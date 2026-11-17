//! Whether an endpoint asks its router for a port mapping (ADR-0064).
//!
//! iroh's portmapper (UPnP, NAT-PMP, PCP) asks the gateway for a public
//! UDP port that forwards to the endpoint's socket and then advertises that
//! address like any other. A peer behind a fully symmetric NAT cannot be
//! punched toward, because its mapping changes with every destination; it
//! can still send first to a mapped address, which is why a daemon asks.
//!
//! Who runs the portmapper: qsh does, not iroh (see [`keep_mapping`]). iroh
//! 1.4 never asks its portmapper for a probe, so the mapping attempt always
//! takes the UPnP branch (SSDP from `0.0.0.0`), which on a host with several
//! interfaces can leave through the wrong NIC and never reach the router,
//! while NAT-PMP and PCP (unicast to the gateway from the default route's
//! address) would have worked. qsh therefore hands iroh `Disabled` and drives
//! a `portmapper::Client` of its own: probe first so PCP and NAT-PMP are
//! preferred, then map the endpoint's IPv4 port, and advertise the mapped
//! address with `add_external_addr`.
//!
//! What is fixed here:
//!
//! - **Only a daemon endpoint maps.** A client endpoint is a short-lived
//!   process with a random key; a mapping for it would be a router entry per
//!   command. iroh's own default is *on* once its `portmapper` feature is
//!   compiled in, so a client says `Disabled` explicitly instead of leaving
//!   the default.
//! - **A daemon maps only when asked** ([`crate::IrohConfig::portmap`]); the
//!   transport's default is off, so a test that builds an `IrohConfig` by
//!   hand never talks to the LAN gateway. `[iroh].portmap` (unset is on)
//!   feeds it for a real daemon.
//! - **A relay-less endpoint never maps.** iroh's net report, which is where
//!   it normally asks for a mapping, is skipped without a relay. But iroh also
//!   hands its IPv4 socket's port to the portmapper when it binds, and the
//!   portmapper starts a mapping on that alone (an SSDP search on the LAN and
//!   a probe of the gateway), relay or not. So qsh passes
//!   `Disabled` when the relay list is empty instead of relying on iroh.
//!
//! The mapped address is advertised as a *configured* address (iroh's own
//! portmapper is off), the same set the reflexive keeper (`reflexive.rs`)
//! edits. The two can name the same socket address (a port-preserving NAT
//! reports the mapped port as the reflexive one), so the keeper never removes
//! the address held in [`MappedAddr`].

use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::PortmapperConfig;

use super::reflexive::Action;

/// How long the first probe of the router's protocols may take before the
/// mapping starts anyway (UPnP search 1 s, PCP and NAT-PMP 0.5 s each).
const PROBE_WAIT: Duration = Duration::from_secs(5);

/// How often the probe repeats. The portmapper trusts a probe for ten
/// minutes; a renewal after that without a fresh probe would fall back to
/// UPnP, so the probe is refreshed well inside that window.
const REPROBE: Duration = Duration::from_secs(5 * 60);

/// How long a released client stays alive after the endpoint is gone, long
/// enough for its service to send the release.
const RELEASE_GRACE: Duration = Duration::from_secs(3);

/// Whether the endpoint being built asks the router for a mapping: a daemon
/// endpoint with at least one relay whose configuration says so.
pub(crate) fn mapping_wanted(daemon: bool, requested: bool, has_relay: bool) -> bool {
    daemon && requested && has_relay
}

/// The portmapper setting handed to iroh's endpoint builder: always
/// `Disabled`. With the `portmapper` feature compiled in the default is
/// `Enabled`, so the value is passed explicitly; the daemon's mapping is
/// qsh's own ([`keep_mapping`]).
pub(crate) fn portmapper_config() -> PortmapperConfig {
    PortmapperConfig::Disabled
}

/// The mapped external address the endpoint currently advertises, shared
/// with the reflexive keeper so that it never removes it.
#[derive(Debug, Clone, Default)]
pub(crate) struct MappedAddr(Arc<Mutex<Option<SocketAddr>>>);

impl MappedAddr {
    fn set(&self, addr: Option<SocketAddr>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = addr;
        }
    }

    /// Whether `addr` is the address the router mapping advertises.
    pub(crate) fn holds(&self, addr: &SocketAddr) -> bool {
        self.0
            .lock()
            .map(|slot| slot.as_ref() == Some(addr))
            .unwrap_or(false)
    }
}

/// Turns the portmapper's external address into endpoint actions.
#[derive(Debug, Default)]
pub(crate) struct Tracker {
    current: Option<SocketAddr>,
}

impl Tracker {
    /// The portmapper now reports `external` (`None`: no mapping). Returns
    /// what to do to the endpoint's configured external addresses.
    pub(crate) fn on_external(&mut self, external: Option<SocketAddrV4>) -> Vec<Action> {
        let next = external.map(SocketAddr::V4);
        if next == self.current {
            return Vec::new();
        }
        let mut actions = Vec::new();
        if let Some(old) = self.current {
            actions.push(Action::Remove(old));
        }
        if let Some(new) = next {
            actions.push(Action::Add(new));
        }
        self.current = next;
        actions
    }

    pub(crate) fn current(&self) -> Option<SocketAddr> {
        self.current
    }
}

/// Releases the mapping when the owning task is aborted: the client lives a
/// moment longer on a detached task so its service can send the release.
struct ReleaseOnDrop(portmapper::Client);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        let client = self.0.clone();
        client.deactivate();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                tokio::time::sleep(RELEASE_GRACE).await;
                drop(client);
            });
        }
    }
}

/// Keep a router mapping for the daemon endpoint `ep` until the task is
/// aborted.
///
/// Probes the router first (iroh's own portmapper never does), because the
/// portmapper prefers PCP, then NAT-PMP, then UPnP only for protocols a probe
/// found, and tries UPnP alone otherwise. UPnP's SSDP search leaves from
/// `0.0.0.0` and can pick the wrong interface on a multi-NIC host; PCP and
/// NAT-PMP go unicast to the gateway from the default route's address.
pub(crate) async fn keep_mapping(ep: iroh::Endpoint, mapped: MappedAddr) {
    let Some(port) = ep
        .bound_sockets()
        .into_iter()
        .find(|a| a.is_ipv4())
        .and_then(|a| std::num::NonZeroU16::new(a.port()))
    else {
        tracing::debug!("iroh: no IPv4 port to map, skipping the router mapping");
        return;
    };
    let client = portmapper::Client::new(portmapper::Config::default());
    let guard = ReleaseOnDrop(client.clone());
    probe(&client, true).await;
    client.update_local_port(port);

    let mut watcher = client.watch_external_address();
    let mut tracker = Tracker::default();
    let mut reprobe = tokio::time::interval(REPROBE);
    reprobe.tick().await;
    loop {
        tokio::select! {
            changed = watcher.changed() => {
                if changed.is_err() {
                    break;
                }
                let external = *watcher.borrow_and_update();
                for action in tracker.on_external(external) {
                    match action {
                        Action::Add(addr) => {
                            tracing::info!(%addr, "iroh: advertising the address the router mapped");
                            mapped.set(Some(addr));
                            ep.add_external_addr(addr).await;
                        }
                        Action::Remove(addr) => {
                            tracing::info!(%addr, "iroh: the router mapping is gone");
                            mapped.set(tracker.current());
                            ep.remove_external_addr(&addr).await;
                        }
                    }
                }
            }
            _ = reprobe.tick() => probe(&client, false).await,
        }
    }
    drop(guard);
}

async fn probe(client: &portmapper::Client, first: bool) {
    match tokio::time::timeout(PROBE_WAIT, client.probe()).await {
        Ok(Ok(Ok(out))) => {
            if first {
                tracing::info!(
                    upnp = out.upnp,
                    pcp = out.pcp,
                    nat_pmp = out.nat_pmp,
                    "iroh: router port-mapping protocols found"
                );
            }
        }
        Ok(Ok(Err(e))) => tracing::debug!("iroh: router probe failed: {e}"),
        Ok(Err(_)) => tracing::debug!("iroh: router probe dropped"),
        Err(_) => tracing::debug!("iroh: router probe timed out"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn v4(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port)
    }

    #[test]
    fn only_a_daemon_that_asks_maps() {
        assert!(mapping_wanted(true, true, true));
        assert!(!mapping_wanted(true, false, true));
        // A client endpoint never maps, whatever the config says.
        assert!(!mapping_wanted(false, true, true));
        assert!(!mapping_wanted(false, false, true));
        // No relay, no mapping.
        assert!(!mapping_wanted(true, true, false));
    }

    #[test]
    fn iroh_never_runs_its_own_portmapper() {
        // Its mapping never probes, so it only ever tries UPnP and a
        // multi-NIC host loses; qsh's own client replaces it.
        assert!(matches!(portmapper_config(), PortmapperConfig::Disabled));
    }

    #[test]
    fn a_new_mapping_is_added_and_a_changed_one_replaces_the_old() {
        let mut t = Tracker::default();
        assert!(t.on_external(None).is_empty());
        assert_eq!(
            t.on_external(Some(v4(4436))),
            vec![Action::Add(SocketAddr::V4(v4(4436)))]
        );
        // The same report again changes nothing.
        assert!(t.on_external(Some(v4(4436))).is_empty());
        assert_eq!(
            t.on_external(Some(v4(5000))),
            vec![
                Action::Remove(SocketAddr::V4(v4(4436))),
                Action::Add(SocketAddr::V4(v4(5000)))
            ]
        );
        assert_eq!(
            t.on_external(None),
            vec![Action::Remove(SocketAddr::V4(v4(5000)))]
        );
        assert_eq!(t.current(), None);
    }

    #[test]
    fn the_keeper_can_ask_whether_an_address_is_the_mapped_one() {
        let m = MappedAddr::default();
        let a = SocketAddr::V4(v4(4436));
        assert!(!m.holds(&a));
        m.set(Some(a));
        assert!(m.holds(&a));
        assert!(!m.holds(&SocketAddr::V4(v4(1))));
        m.set(None);
        assert!(!m.holds(&a));
    }
}
