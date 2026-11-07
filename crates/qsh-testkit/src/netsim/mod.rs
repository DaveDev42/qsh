//! `netsim`: a virtual UDP network for real quinn endpoints, with RFC 4787
//! NAT boxes (ADR-0054 decision 22, `docs/design/testing.md` L4).
//!
//! The simulator hands out [`NetSocket`]s. A socket implements quinn's
//! `AsyncUdpSocket`, so `quinn::Endpoint::new_with_abstract_socket` runs the
//! real QUIC state machine (handshake, Retry, path validation,
//! retransmission) on a wire made of this module instead of the OS. No
//! privileges, no loopback, and no platform branch: the same test gives the
//! same result on Linux, macOS and Windows.
//!
//! # Model
//!
//! * [`Net`] is the whole network. [`Net::internet`] is its root [`Realm`],
//!   the public address space.
//! * A [`Realm`] is an address space. Behind each NAT box lies a private
//!   realm; a [`Site`] is one such place a host can live, created by
//!   [`Realm::site`] (a named behaviour, [`NatKind`]), [`Realm::add_nat`]
//!   (any [`NatConfig`]) or [`Realm::add_firewall`]. [`Site::nest`] puts a
//!   box behind a box (a carrier-grade NAT), and [`Site::add_host`] adds a
//!   second host behind the same box.
//! * Delay and loss live on paths. A packet that crosses the public realm
//!   takes the [`PathConfig`] of its (source, destination) public IPs
//!   ([`Net::set_path`], default [`NetConfig::default_path`]). A packet that
//!   stays inside one private realm takes that realm's LAN path
//!   ([`Realm::set_lan`]).
//! * A NAT box follows the RFC 4787 axes: [`Mapping`], [`Filtering`],
//!   [`PortAssignment`], hairpinning and a mapping timeout. The firewall
//!   ([`FirewallConfig`]) is the translation-free case (an IPv6 router).
//!   [`NatHandle::forward`] adds a static port forward (a port opened on the
//!   router).
//!
//! # Time and determinism
//!
//! Delivery is driven by `tokio::time`, so under
//! `#[tokio::test(start_paused = true)]` the network runs on virtual time: a
//! 25 ms path takes exactly 25 ms of test clock and no wall time, and NAT
//! mapping timeouts expire when the test clock passes them. Loss, jitter and
//! random port choices come from one generator seeded by
//! [`NetConfig::seed`]; packets are processed in send order under one lock.
//! With a single-threaded runtime the network side is reproducible
//! bit-for-bit. quinn's own randomness (connection IDs, keys) is not seeded,
//! so QUIC byte contents differ between runs, but what the network does with
//! them does not. A failing test should print [`Net::seed`].
//!
//! # Limits
//!
//! Sockets bind one concrete address; there is no `0.0.0.0` / `[::]`
//! wildcard and no dual-stack socket, so one socket speaks one family. There
//! is no ICMP (a datagram to a closed port or a filtered path vanishes
//! silently), no ECN and no GSO/GRO (one datagram per `try_send`). Packets
//! larger than [`NetConfig::mtu`] are dropped (no fragmentation). NAT
//! mappings are refreshed by outbound packets only.
//!
//! # Example
//!
//! ```no_run
//! # async fn demo() {
//! use qsh_testkit::netsim::{Net, NetConfig, NatKind};
//! let net = Net::new(NetConfig::default());
//! let server = net.internet().site(NatKind::None, "server", "203.0.113.1".parse().unwrap());
//! let home = net.internet().site(NatKind::PortRestricted, "home", "198.51.100.7".parse().unwrap());
//! let s = server.bind(7000).unwrap();
//! let c = home.bind(0).unwrap();
//! c.send_to("203.0.113.1:7000".parse().unwrap(), b"hi");
//! let (from, _) = s.recv_from().await;
//! assert_eq!(from.ip(), "198.51.100.7".parse::<std::net::IpAddr>().unwrap());
//! # }
//! ```

mod nat;
pub mod quic;
mod rng;
mod socket;
mod state;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

pub use nat::{Filtering, FirewallConfig, Mapping, NatConfig, NatKind, PortAssignment};
pub use socket::NetSocket;

use state::{RealmId, Shared};

/// One-way delay, jitter and loss of a path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PathConfig {
    /// Fixed one-way delay.
    pub delay: Duration,
    /// Extra uniformly distributed delay in `[0, jitter)`. Non-zero jitter
    /// can reorder packets.
    pub jitter: Duration,
    /// Independent drop probability per packet, `0.0..=1.0`.
    pub loss: f64,
}

impl PathConfig {
    /// A path with `delay` one way, no jitter, no loss.
    pub fn delay(delay: Duration) -> Self {
        Self {
            delay,
            jitter: Duration::ZERO,
            loss: 0.0,
        }
    }

    /// Returns this path with the loss probability set.
    pub fn with_loss(mut self, loss: f64) -> Self {
        self.loss = loss;
        self
    }

    /// Returns this path with jitter set.
    pub fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }
}

/// Network-wide settings.
#[derive(Clone, Debug)]
pub struct NetConfig {
    /// Seed for loss, jitter and random port assignment.
    pub seed: u64,
    /// The public path between two public IPs without a [`Net::set_path`]
    /// entry. Default 25 ms one way (ADR-0054 decision 27).
    pub default_path: PathConfig,
    /// The default LAN path inside a private realm. Default 1 ms.
    pub lan: PathConfig,
    /// Largest IP packet (payload plus 28 bytes of IPv4 or 48 of IPv6 + UDP
    /// header); larger datagrams are dropped. Default 1500.
    pub mtu: usize,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            default_path: PathConfig::delay(Duration::from_millis(25)),
            lan: PathConfig::delay(Duration::from_millis(1)),
            mtu: 1500,
        }
    }
}

/// Why the network dropped a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    /// The path's random loss.
    Loss,
    /// Larger than the MTU.
    Mtu,
    /// No host owns the destination address.
    NoRoute,
    /// The host exists but nothing is bound to the port.
    NoSocket,
    /// A NAT had no mapping for the destination port.
    NoMapping,
    /// A NAT or firewall filter refused the source.
    Filtered,
    /// A NAT without hairpinning got a packet for its own external address.
    HairpinDisabled,
    /// The receiving socket's queue was full.
    QueueFull,
}

/// Counters since the network was created.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    /// Datagrams handed to the network by sockets.
    pub sent: u64,
    /// Datagrams placed in a receiving socket's queue.
    pub delivered: u64,
    /// Drops by reason.
    pub dropped: BTreeMap<DropReason, u64>,
}

impl NetStats {
    /// Drops for one reason.
    pub fn dropped(&self, reason: DropReason) -> u64 {
        self.dropped.get(&reason).copied().unwrap_or(0)
    }
}

/// A simulated network. Cheap to clone; clones share one network. Must be
/// created inside a tokio runtime (it spawns the delivery task). When the
/// last handle and socket are dropped the task ends.
#[derive(Clone)]
pub struct Net {
    shared: Arc<Shared>,
}

impl fmt::Debug for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Net").field("seed", &self.seed()).finish()
    }
}

impl Net {
    /// Creates an empty network.
    pub fn new(cfg: NetConfig) -> Self {
        Self {
            shared: Shared::new(cfg),
        }
    }

    /// The seed, for failure messages.
    pub fn seed(&self) -> u64 {
        self.shared.lock().cfg.seed
    }

    /// The public realm.
    pub fn internet(&self) -> Realm {
        Realm {
            shared: self.shared.clone(),
            id: 0,
        }
    }

    /// Sets the public path between two public IPs, both directions.
    pub fn set_path(&self, a: IpAddr, b: IpAddr, path: PathConfig) {
        self.shared.lock().set_path(a, b, path, true);
    }

    /// Sets the public path from `from` to `to` only.
    pub fn set_path_one_way(&self, from: IpAddr, to: IpAddr, path: PathConfig) {
        self.shared.lock().set_path(from, to, path, false);
    }

    /// Replaces the default public path.
    pub fn set_default_path(&self, path: PathConfig) {
        self.shared.lock().cfg.default_path = path;
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> NetStats {
        self.shared.lock().stats.clone()
    }
}

/// An address space: the public internet or the inside of one box.
#[derive(Clone)]
pub struct Realm {
    shared: Arc<Shared>,
    id: RealmId,
}

impl fmt::Debug for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Realm").field("name", &self.name()).finish()
    }
}

impl Realm {
    /// The realm's name.
    pub fn name(&self) -> String {
        self.shared.lock().realms[self.id].name.clone()
    }

    /// Replaces the LAN path used between two hosts of this realm.
    pub fn set_lan(&self, path: PathConfig) {
        self.shared.lock().realms[self.id].lan = path;
    }

    /// Binds a socket at `addr` (port 0 picks an ephemeral port from 49152).
    pub fn bind(&self, addr: SocketAddr) -> io::Result<NetSocket> {
        let queue = self.shared.lock().bind(self.id, addr)?;
        Ok(NetSocket::new(self.shared.clone(), self.id, queue))
    }

    /// Puts a host of the named behaviour on this realm. `public_ip` is the
    /// box's external address (for [`NatKind::None`] and
    /// [`NatKind::FirewallV6`], the host's own address).
    pub fn site(&self, kind: NatKind, name: &str, public_ip: IpAddr) -> Site {
        match kind {
            NatKind::None => self.plain_site(name, public_ip),
            NatKind::FirewallV6 => self.add_firewall(name, FirewallConfig::stateful(), public_ip),
            other => self.add_nat(
                name,
                other.nat_config().expect("translating kind"),
                public_ip,
            ),
        }
    }

    fn plain_site(&self, name: &str, ip: IpAddr) -> Site {
        self.shared.lock().realms[self.id].hosts.insert(ip);
        Site {
            realm: self.clone(),
            ip,
            external: ip,
            name: name.to_owned(),
            nat: None,
        }
    }

    /// Puts a NAT box with `cfg` on this realm; the returned site is the
    /// box's inside, with one host address ready.
    pub fn add_nat(&self, name: &str, cfg: NatConfig, external_ip: IpAddr) -> Site {
        let (inner, nat) = self.shared.lock().add_nat(name, self.id, cfg, external_ip);
        let ip = self.shared.lock().alloc_private(inner, external_ip);
        Site {
            realm: Realm {
                shared: self.shared.clone(),
                id: inner,
            },
            ip,
            external: external_ip,
            name: name.to_owned(),
            nat: Some(NatHandle {
                shared: self.shared.clone(),
                nat,
            }),
        }
    }

    /// Puts a translation-free stateful firewall on this realm. Hosts behind
    /// it keep addresses of this realm; `host_ip` is the first.
    pub fn add_firewall(&self, name: &str, cfg: FirewallConfig, host_ip: IpAddr) -> Site {
        let mut st = self.shared.lock();
        let inner = st.add_firewall(name, self.id, cfg);
        st.realms[inner].hosts.insert(host_ip);
        drop(st);
        Site {
            realm: Realm {
                shared: self.shared.clone(),
                id: inner,
            },
            ip: host_ip,
            external: host_ip,
            name: name.to_owned(),
            nat: None,
        }
    }
}

/// A place a host can live: behind a NAT box, behind a firewall, or directly
/// on the network.
#[derive(Clone, Debug)]
pub struct Site {
    realm: Realm,
    ip: IpAddr,
    external: IpAddr,
    name: String,
    nat: Option<NatHandle>,
}

impl Site {
    /// The site's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// This site's host address as the host sees it (private behind a NAT).
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The box's address in its parent realm: the NAT's external IP, or the
    /// host's own address when there is no translation. For a box nested
    /// behind another, this is a private address of the outer box's realm.
    pub fn external_ip(&self) -> IpAddr {
        self.external
    }

    /// The realm this site's hosts live in.
    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    /// The NAT box, if the site is behind one.
    pub fn nat(&self) -> Option<&NatHandle> {
        self.nat.as_ref()
    }

    /// Binds a socket at the site's host address.
    pub fn bind(&self, port: u16) -> io::Result<NetSocket> {
        self.realm.bind(SocketAddr::new(self.ip, port))
    }

    /// Another host behind the same box. Only translating boxes can hand out
    /// private addresses; a plain or firewalled site returns
    /// `ErrorKind::Unsupported` (create another site with its own public
    /// address instead).
    pub fn add_host(&self) -> io::Result<Site> {
        if self.nat.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only a NAT site allocates private host addresses",
            ));
        }
        let ip = self.shared_alloc();
        Ok(Site { ip, ..self.clone() })
    }

    fn shared_alloc(&self) -> IpAddr {
        self.realm
            .shared
            .lock()
            .alloc_private(self.realm.id, self.external)
    }

    /// Puts a box behind this site's box (for example a carrier-grade NAT
    /// in front of a home router). The new box's external address is a
    /// fresh private address of this site's realm. Same restriction as
    /// [`add_host`](Self::add_host).
    pub fn nest(&self, kind: NatKind, name: &str) -> io::Result<Site> {
        if self.nat.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only a NAT site can host a nested box",
            ));
        }
        let outer_ip = self.shared_alloc();
        Ok(self.realm.site(kind, name, outer_ip))
    }
}

/// Control and inspection of one NAT box.
#[derive(Clone)]
pub struct NatHandle {
    shared: Arc<Shared>,
    nat: usize,
}

impl fmt::Debug for NatHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatHandle").field("nat", &self.nat).finish()
    }
}

impl NatHandle {
    /// The box's external IP.
    pub fn external_ip(&self) -> IpAddr {
        self.shared.lock().nats[self.nat].ext_ip
    }

    /// The box's behaviour.
    pub fn config(&self) -> NatConfig {
        self.shared.lock().nats[self.nat].cfg.clone()
    }

    /// Opens `external_port` to `internal` permanently: inbound packets from
    /// anyone reach it, and the inside socket's own packets leave from that
    /// port whatever the mapping rule (a port forward on the router).
    pub fn forward(&self, external_port: u16, internal: SocketAddr) {
        self.shared.lock().nats[self.nat].forward(external_port, internal);
    }

    /// Forgets every dynamic mapping (a router reboot).
    pub fn flush(&self) {
        self.shared.lock().nats[self.nat].flush();
    }

    /// Live dynamic mappings as `(inside, outside)` pairs, sorted.
    pub fn mappings(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.shared.lock().nats[self.nat].mappings(Instant::now())
    }
}
