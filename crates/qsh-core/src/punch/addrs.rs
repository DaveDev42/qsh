//! Where this host learns its own source addresses. The route memory keys a
//! pin's rest on them (`route_memory`); qsh's own hole punching, which also
//! read them, was retired (ADR-0068).

use std::net::IpAddr;

/// Where a host learns the addresses it can be reached at. Injected so a
/// simulated network can answer with virtual addresses; production asks the
/// routing table (`trust::invite_address`'s route lookup), which sends
/// nothing.
pub trait LocalAddrs: Send + Sync + 'static {
    /// The source addresses this host would use towards the internet, at
    /// most one per IP family.
    fn observe(&self) -> Vec<IpAddr>;
}

/// The routing-table lookup `qsh trust invite` uses (ADR-0054 decision 8:
/// no interface enumeration, no new dependency).
#[derive(Debug, Clone, Copy, Default)]
pub struct RouteAddrs;

impl LocalAddrs for RouteAddrs {
    fn observe(&self) -> Vec<IpAddr> {
        crate::trust::invite_address::route::observe_source_addresses()
    }
}

/// A fixed answer, for tests.
#[derive(Debug, Clone, Default)]
pub struct FixedAddrs(pub Vec<IpAddr>);

impl LocalAddrs for FixedAddrs {
    fn observe(&self) -> Vec<IpAddr> {
        self.0.clone()
    }
}
