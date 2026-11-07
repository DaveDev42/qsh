//! NAT and firewall behaviour models (RFC 4787 axes).
//!
//! Pure data and state machines: no I/O, no clock reads. Every method takes
//! `now` from the caller, so [`super::Net`] decides which clock drives them.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::time::Instant;

use super::rng::Rng;

/// How an inside socket's external endpoint depends on the destination
/// (RFC 4787 section 4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    /// One external endpoint per inside socket, whatever the destination (EIM).
    EndpointIndependent,
    /// A new external endpoint per destination IP (ADM).
    AddressDependent,
    /// A new external endpoint per destination IP and port (APDM).
    AddressAndPortDependent,
}

/// Which outside sources may send to an existing mapping (RFC 4787
/// section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filtering {
    /// Anyone (EIF).
    EndpointIndependent,
    /// Only IPs the inside socket has sent to (ADF).
    AddressDependent,
    /// Only IP and port pairs the inside socket has sent to (APDF).
    AddressAndPortDependent,
}

/// How the external port of a new mapping is picked (RFC 4787 section 4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortAssignment {
    /// Reuse the inside port when free, else fall back to sequential.
    Preserve,
    /// Next free port from a counter that starts at 10000.
    Sequential,
    /// A seeded random free port in 1024..=65535.
    Random,
}

/// A NAT box: the RFC 4787 axes plus hairpinning and the idle timeout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatConfig {
    /// Mapping behaviour.
    pub mapping: Mapping,
    /// Filtering behaviour.
    pub filtering: Filtering,
    /// Port assignment.
    pub ports: PortAssignment,
    /// Whether an inside host may reach another inside host through the
    /// NAT's own external address (RFC 4787 section 6). The presets leave
    /// this off, the conservative choice for a consumer router.
    pub hairpin: bool,
    /// Idle time after the last outbound packet before a mapping (and each
    /// filter permission) lapses. Inbound packets do not refresh it
    /// (RFC 4787 REQ-6, outbound refresh only). Default 30 s.
    pub timeout: Duration,
}

impl NatConfig {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    fn preset(mapping: Mapping, filtering: Filtering, ports: PortAssignment) -> Self {
        Self {
            mapping,
            filtering,
            ports,
            hairpin: false,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// EIM, EIF, port preserving.
    pub fn full_cone() -> Self {
        Self::preset(
            Mapping::EndpointIndependent,
            Filtering::EndpointIndependent,
            PortAssignment::Preserve,
        )
    }

    /// EIM, ADF, port preserving.
    pub fn restricted() -> Self {
        Self::preset(
            Mapping::EndpointIndependent,
            Filtering::AddressDependent,
            PortAssignment::Preserve,
        )
    }

    /// EIM, APDF, port preserving.
    pub fn port_restricted() -> Self {
        Self::preset(
            Mapping::EndpointIndependent,
            Filtering::AddressAndPortDependent,
            PortAssignment::Preserve,
        )
    }

    /// APDM, APDF, random ports.
    pub fn symmetric() -> Self {
        Self::preset(
            Mapping::AddressAndPortDependent,
            Filtering::AddressAndPortDependent,
            PortAssignment::Random,
        )
    }

    /// EIM, APDF, random ports (a port-restricted cone that does not keep the
    /// inside port).
    pub fn port_restricted_random() -> Self {
        Self::preset(
            Mapping::EndpointIndependent,
            Filtering::AddressAndPortDependent,
            PortAssignment::Random,
        )
    }

    /// Returns this config with hairpinning set.
    pub fn with_hairpin(mut self, hairpin: bool) -> Self {
        self.hairpin = hairpin;
        self
    }

    /// Returns this config with the mapping timeout set.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns this config with the port assignment set.
    pub fn with_ports(mut self, ports: PortAssignment) -> Self {
        self.ports = ports;
        self
    }
}

/// A stateful firewall without address translation (an IPv6 home router):
/// inside hosts keep their public addresses, inbound packets pass only as the
/// filter allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallConfig {
    /// Filtering behaviour.
    pub filtering: Filtering,
    /// Idle time before a permission lapses. Default 30 s.
    pub timeout: Duration,
}

impl FirewallConfig {
    /// APDF with a 30 s timeout.
    pub fn stateful() -> Self {
        Self {
            filtering: Filtering::AddressAndPortDependent,
            timeout: Duration::from_secs(30),
        }
    }
}

/// The named behaviours of ADR-0054 decision 22.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NatKind {
    /// No box: the host is directly on the network.
    None,
    /// [`NatConfig::full_cone`].
    FullCone,
    /// [`NatConfig::restricted`].
    Restricted,
    /// [`NatConfig::port_restricted`].
    PortRestricted,
    /// [`NatConfig::symmetric`].
    Symmetric,
    /// [`FirewallConfig::stateful`] (IPv6 firewall, no translation).
    FirewallV6,
    /// [`NatConfig::port_restricted_random`].
    PortRestrictedRandom,
}

impl NatKind {
    /// Every kind, in ADR order.
    pub const ALL: [NatKind; 7] = [
        NatKind::None,
        NatKind::FullCone,
        NatKind::Restricted,
        NatKind::PortRestricted,
        NatKind::Symmetric,
        NatKind::FirewallV6,
        NatKind::PortRestrictedRandom,
    ];

    /// The five kinds of the 25-pair matrix (ADR-0054 decision 23).
    pub const MATRIX: [NatKind; 5] = [
        NatKind::None,
        NatKind::FullCone,
        NatKind::Restricted,
        NatKind::PortRestricted,
        NatKind::Symmetric,
    ];

    /// The ADR's preset name.
    pub fn name(self) -> &'static str {
        match self {
            NatKind::None => "none",
            NatKind::FullCone => "full_cone",
            NatKind::Restricted => "restricted",
            NatKind::PortRestricted => "port_restricted",
            NatKind::Symmetric => "symmetric",
            NatKind::FirewallV6 => "firewall_v6",
            NatKind::PortRestrictedRandom => "port_restricted_random",
        }
    }

    /// The translating config, or `None` for `none` and `firewall_v6`.
    pub fn nat_config(self) -> Option<NatConfig> {
        match self {
            NatKind::None | NatKind::FirewallV6 => None,
            NatKind::FullCone => Some(NatConfig::full_cone()),
            NatKind::Restricted => Some(NatConfig::restricted()),
            NatKind::PortRestricted => Some(NatConfig::port_restricted()),
            NatKind::Symmetric => Some(NatConfig::symmetric()),
            NatKind::PortRestrictedRandom => Some(NatConfig::port_restricted_random()),
        }
    }
}

impl fmt::Display for NatKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Remote endpoints an inside socket has sent to, each with the time of the
/// last send.
#[derive(Debug, Default)]
struct Permits {
    ips: HashMap<IpAddr, Instant>,
    addrs: HashMap<SocketAddr, Instant>,
}

impl Permits {
    fn note(&mut self, now: Instant, remote: SocketAddr) {
        self.ips.insert(remote.ip(), now);
        self.addrs.insert(remote, now);
    }

    fn admits(
        &self,
        now: Instant,
        filtering: Filtering,
        timeout: Duration,
        src: SocketAddr,
    ) -> bool {
        let live = |t: Option<&Instant>| t.is_some_and(|t| now < *t + timeout);
        match filtering {
            Filtering::EndpointIndependent => true,
            Filtering::AddressDependent => live(self.ips.get(&src.ip())),
            Filtering::AddressAndPortDependent => live(self.addrs.get(&src)),
        }
    }
}

/// Why a NAT or firewall refused a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    NoMapping,
    Filtered,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum MapKey {
    Any,
    Ip(IpAddr),
    Addr(SocketAddr),
}

#[derive(Debug)]
struct Map {
    internal: SocketAddr,
    key: MapKey,
    ext_port: u16,
    last_out: Instant,
    permits: Permits,
}

/// The state of one NAT box.
#[derive(Debug)]
pub(crate) struct NatState {
    pub(crate) cfg: NatConfig,
    pub(crate) ext_ip: IpAddr,
    /// The realm behind the box.
    pub(crate) inner: usize,
    maps: Vec<Map>,
    forwards: HashMap<u16, SocketAddr>,
    forwards_rev: HashMap<SocketAddr, u16>,
    seq_next: u16,
}

impl NatState {
    pub(crate) fn new(cfg: NatConfig, ext_ip: IpAddr, inner: usize) -> Self {
        Self {
            cfg,
            ext_ip,
            inner,
            maps: Vec::new(),
            forwards: HashMap::new(),
            forwards_rev: HashMap::new(),
            seq_next: 10_000,
        }
    }

    fn purge(&mut self, now: Instant) {
        let timeout = self.cfg.timeout;
        self.maps.retain(|m| now < m.last_out + timeout);
    }

    fn port_free(&self, port: u16, internal: SocketAddr) -> bool {
        port != 0
            && !self.forwards.contains_key(&port)
            && self
                .maps
                .iter()
                .all(|m| m.ext_port != port || m.internal == internal)
    }

    fn allocate(&mut self, internal: SocketAddr, rng: &mut Rng) -> u16 {
        if self.cfg.ports == PortAssignment::Preserve && self.port_free(internal.port(), internal) {
            return internal.port();
        }
        if self.cfg.ports == PortAssignment::Random {
            for _ in 0..4096 {
                let port = 1024 + (rng.next_u64() % (65_536 - 1024)) as u16;
                if self.port_free(port, internal) {
                    return port;
                }
            }
        }
        for _ in 0..=u16::MAX {
            let port = self.seq_next;
            self.seq_next = if port == u16::MAX { 10_000 } else { port + 1 };
            if self.port_free(port, internal) {
                return port;
            }
        }
        // The pool is exhausted; reuse the inside port rather than panic.
        internal.port()
    }

    /// Translates an inside packet `internal -> dst` and returns the external
    /// source endpoint, creating or refreshing the mapping.
    pub(crate) fn outbound(
        &mut self,
        now: Instant,
        internal: SocketAddr,
        dst: SocketAddr,
        rng: &mut Rng,
    ) -> SocketAddr {
        self.purge(now);
        if let Some(port) = self.forwards_rev.get(&internal) {
            return SocketAddr::new(self.ext_ip, *port);
        }
        let key = match self.cfg.mapping {
            Mapping::EndpointIndependent => MapKey::Any,
            Mapping::AddressDependent => MapKey::Ip(dst.ip()),
            Mapping::AddressAndPortDependent => MapKey::Addr(dst),
        };
        let idx = match self
            .maps
            .iter()
            .position(|m| m.internal == internal && m.key == key)
        {
            Some(i) => i,
            None => {
                let ext_port = self.allocate(internal, rng);
                self.maps.push(Map {
                    internal,
                    key,
                    ext_port,
                    last_out: now,
                    permits: Permits::default(),
                });
                self.maps.len() - 1
            }
        };
        let map = &mut self.maps[idx];
        map.last_out = now;
        map.permits.note(now, dst);
        SocketAddr::new(self.ext_ip, map.ext_port)
    }

    /// Translates an outside packet `src -> ext_ip:ext_port` to the inside
    /// endpoint, or says why not.
    pub(crate) fn inbound(
        &mut self,
        now: Instant,
        src: SocketAddr,
        ext_port: u16,
    ) -> Result<SocketAddr, Refusal> {
        self.purge(now);
        if let Some(internal) = self.forwards.get(&ext_port) {
            return Ok(*internal);
        }
        let mut seen = false;
        for m in self.maps.iter().filter(|m| m.ext_port == ext_port) {
            seen = true;
            if m.permits
                .admits(now, self.cfg.filtering, self.cfg.timeout, src)
            {
                return Ok(m.internal);
            }
        }
        Err(if seen {
            Refusal::Filtered
        } else {
            Refusal::NoMapping
        })
    }

    pub(crate) fn forward(&mut self, ext_port: u16, internal: SocketAddr) {
        self.forwards.insert(ext_port, internal);
        self.forwards_rev.insert(internal, ext_port);
    }

    pub(crate) fn flush(&mut self) {
        self.maps.clear();
    }

    /// Live mappings as `(inside, outside)` pairs.
    pub(crate) fn mappings(&mut self, now: Instant) -> Vec<(SocketAddr, SocketAddr)> {
        self.purge(now);
        let mut out: Vec<_> = self
            .maps
            .iter()
            .map(|m| (m.internal, SocketAddr::new(self.ext_ip, m.ext_port)))
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// The state of one stateless-translation firewall.
#[derive(Debug)]
pub(crate) struct FirewallState {
    cfg: FirewallConfig,
    table: HashMap<SocketAddr, Permits>,
}

impl FirewallState {
    pub(crate) fn new(cfg: FirewallConfig) -> Self {
        Self {
            cfg,
            table: HashMap::new(),
        }
    }

    pub(crate) fn note_outbound(&mut self, now: Instant, local: SocketAddr, dst: SocketAddr) {
        self.table.entry(local).or_default().note(now, dst);
    }

    pub(crate) fn admit(&self, now: Instant, local: SocketAddr, src: SocketAddr) -> bool {
        match self.cfg.filtering {
            Filtering::EndpointIndependent => true,
            f => self
                .table
                .get(&local)
                .is_some_and(|p| p.admits(now, f, self.cfg.timeout, src)),
        }
    }
}
