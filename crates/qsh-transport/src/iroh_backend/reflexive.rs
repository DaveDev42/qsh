//! Keeps a daemon endpoint's public (reflexive) address advertised.
//!
//! iroh learns the public address of an endpoint from QUIC address
//! discovery (QAD): a connection to the relay's QAD port, on which the relay
//! reports the address it saw the packets come from. The set of addresses a
//! peer is told about is rebuilt from every net report, and a report that
//! found no QAD address (the probe timed out) rebuilds it without one.
//!
//! A short-lived client endpoint runs one report and never notices. A daemon
//! endpoint runs one every 20 to 26 seconds for as long as it lives, and on
//! those later runs iroh opens a fresh QAD connection from the socket that
//! already holds one (the first connection's observer is only ever set on an
//! address *change*, so iroh finds nothing to reuse). The public n0 relays
//! answer such a connection only now and then: measured against
//! `aps1-1.relay.n0.iroh.link`, about half of the later probes, and in a
//! capture of a long-running daemon every one of them, time out after 3 s
//! with the relay silent. Each of those reports drops the public address from
//! the daemon's advertised set, so a peer that dials in during the gap is
//! told only the daemon's private addresses, and a network that passes UDP
//! only for flows both sides send into (a corporate firewall) never gets a
//! punch started toward it. The connection stays on the relay.
//!
//! [`Keeper`] holds the last public address a net report proved and keeps
//! it configured on the endpoint (`add_external_addr`) until a later report
//! replaces it or [`GRACE`] passes without a confirmation. The address is
//! advertised alongside what iroh finds on its own, and a fresh report that
//! agrees changes nothing.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::Instant;

/// How long a public address stays advertised without a net report that
/// confirms it. Twice iroh's interval between full reports (five minutes):
/// a full report starts from a clean QAD state and succeeds, so a daemon
/// whose incremental probes all fail still reconfirms well inside this.
/// Long enough to ride out a flaky stretch, short enough that an address
/// from a network the host has left does not outlive it by much (a stale
/// candidate costs a peer a few probes, nothing more).
pub(crate) const GRACE: Duration = Duration::from_secs(10 * 60);

/// What the keeper wants done to the endpoint's configured external
/// addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Advertise this address.
    Add(SocketAddr),
    /// Stop advertising this address.
    Remove(SocketAddr),
}

/// The address pinned for one IP family and when a report last proved it.
#[derive(Debug, Clone, Copy)]
struct Slot {
    addr: SocketAddr,
    confirmed: Instant,
}

/// The state machine behind [`crate::IrohEndpoint`]'s reflexive address
/// keeping. Pure: callers feed it net reports and the clock, and carry out
/// the [`Action`]s it returns.
#[derive(Debug, Default)]
pub(crate) struct Keeper {
    v4: Option<Slot>,
    v6: Option<Slot>,
}

impl Keeper {
    /// A net report finished. `v4` and `v6` are the public addresses it
    /// found, if any.
    ///
    /// A found address is pinned (replacing a different one, which is
    /// removed) and its clock restarts. A report that found none changes
    /// nothing here: it may be the probe that timed out, not a host that
    /// lost its address.
    pub(crate) fn on_report(
        &mut self,
        now: Instant,
        v4: Option<SocketAddr>,
        v6: Option<SocketAddr>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        observe(&mut self.v4, now, v4, &mut actions);
        observe(&mut self.v6, now, v6, &mut actions);
        actions
    }

    /// Drop every pinned address that [`GRACE`] has passed over.
    pub(crate) fn on_tick(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        for slot in [&mut self.v4, &mut self.v6] {
            if let Some(held) = *slot
                && now.saturating_duration_since(held.confirmed) >= GRACE
            {
                actions.push(Action::Remove(held.addr));
                *slot = None;
            }
        }
        actions
    }

    /// When [`Self::on_tick`] next has something to do; `None` with nothing
    /// pinned.
    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        [self.v4, self.v6]
            .into_iter()
            .flatten()
            .map(|slot| slot.confirmed + GRACE)
            .min()
    }

    /// The addresses currently pinned, for logs and tests.
    #[cfg(test)]
    pub(crate) fn pinned(&self) -> Vec<SocketAddr> {
        [self.v4, self.v6]
            .into_iter()
            .flatten()
            .map(|slot| slot.addr)
            .collect()
    }
}

fn observe(
    slot: &mut Option<Slot>,
    now: Instant,
    found: Option<SocketAddr>,
    actions: &mut Vec<Action>,
) {
    let Some(addr) = found else {
        return;
    };
    match slot {
        Some(held) if held.addr == addr => held.confirmed = now,
        _ => {
            if let Some(old) = slot.take() {
                actions.push(Action::Remove(old.addr));
            }
            actions.push(Action::Add(addr));
            *slot = Some(Slot {
                addr,
                confirmed: now,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 7], port))
    }

    /// The failure this module exists for: a report with a public address,
    /// then one whose QAD probe timed out. The address stays.
    #[tokio::test(start_paused = true)]
    async fn a_report_without_an_address_does_not_unpin_it() {
        let mut keeper = Keeper::default();
        let t0 = Instant::now();
        assert_eq!(
            keeper.on_report(t0, Some(v4(5000)), None),
            vec![Action::Add(v4(5000))]
        );
        tokio::time::advance(Duration::from_secs(25)).await;
        assert_eq!(keeper.on_report(Instant::now(), None, None), vec![]);
        assert_eq!(keeper.pinned(), vec![v4(5000)]);
    }

    /// A report that agrees adds and removes nothing, and restarts the
    /// clock.
    #[tokio::test(start_paused = true)]
    async fn a_confirming_report_restarts_the_clock() {
        let mut keeper = Keeper::default();
        let t0 = Instant::now();
        keeper.on_report(t0, Some(v4(5000)), None);
        tokio::time::advance(GRACE - Duration::from_secs(1)).await;
        assert_eq!(
            keeper.on_report(Instant::now(), Some(v4(5000)), None),
            vec![]
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(keeper.on_tick(Instant::now()), vec![]);
        assert_eq!(keeper.pinned(), vec![v4(5000)]);
    }

    /// A different address (the NAT remapped, or the host changed network)
    /// replaces the old one in the same step, old one first.
    #[tokio::test(start_paused = true)]
    async fn a_new_address_replaces_the_old_one() {
        let mut keeper = Keeper::default();
        let t0 = Instant::now();
        keeper.on_report(t0, Some(v4(5000)), None);
        assert_eq!(
            keeper.on_report(t0, Some(v4(5001)), None),
            vec![Action::Remove(v4(5000)), Action::Add(v4(5001))]
        );
        assert_eq!(keeper.pinned(), vec![v4(5001)]);
    }

    /// An address nothing has confirmed for [`GRACE`] is dropped, so a host
    /// that left its network does not advertise it for ever.
    #[tokio::test(start_paused = true)]
    async fn an_unconfirmed_address_expires() {
        let mut keeper = Keeper::default();
        let t0 = Instant::now();
        keeper.on_report(t0, Some(v4(5000)), Some(v6(6000)));
        assert_eq!(keeper.next_expiry(), Some(t0 + GRACE));
        tokio::time::advance(GRACE - Duration::from_secs(1)).await;
        assert_eq!(keeper.on_tick(Instant::now()), vec![]);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            keeper.on_tick(Instant::now()),
            vec![Action::Remove(v4(5000)), Action::Remove(v6(6000))]
        );
        assert_eq!(keeper.next_expiry(), None);
        assert_eq!(keeper.pinned(), vec![]);
    }

    /// The two families are held and expired independently.
    #[tokio::test(start_paused = true)]
    async fn each_family_keeps_its_own_clock() {
        let mut keeper = Keeper::default();
        let t0 = Instant::now();
        keeper.on_report(t0, Some(v4(5000)), Some(v6(6000)));
        tokio::time::advance(GRACE / 2).await;
        keeper.on_report(Instant::now(), Some(v4(5000)), None);
        tokio::time::advance(GRACE / 2).await;
        assert_eq!(
            keeper.on_tick(Instant::now()),
            vec![Action::Remove(v6(6000))]
        );
        assert_eq!(keeper.pinned(), vec![v4(5000)]);
    }
}
