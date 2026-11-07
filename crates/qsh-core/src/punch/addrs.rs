//! Host addresses and the public-or-private call (ADR-0054 decision 8).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use qsh_proto::punch::{MAX_PUNCH_CANDIDATES, valid_punch_candidate};
use qsh_proto::wire::{PunchCandidate, PunchCandidateKind};

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

/// Host candidates for a socket on `port`: the observed IPv4 address and one
/// IPv6 address, the latter only when global unicast (`2000::/3`) or ULA
/// (`fc00::/7`). Every one passes `valid_punch_candidate`.
pub fn host_candidates(observed: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut have_v4 = false;
    let mut have_v6 = false;
    for ip in observed {
        let ip = ip.to_canonical();
        let keep = match ip {
            IpAddr::V4(_) => !std::mem::replace(&mut have_v4, true),
            IpAddr::V6(v6) => {
                (is_global_v6(&v6) || is_ula(&v6)) && !std::mem::replace(&mut have_v6, true)
            }
        };
        if !keep {
            continue;
        }
        let addr = SocketAddr::new(ip, port);
        let valid = match ip {
            IpAddr::V4(v4) => valid_punch_candidate(&v4.octets(), u32::from(port)),
            IpAddr::V6(v6) => valid_punch_candidate(&v6.octets(), u32::from(port)),
        };
        if valid == Some(addr) {
            out.push(addr);
        }
    }
    out.truncate(MAX_PUNCH_CANDIDATES);
    out
}

/// The same list as wire candidates.
pub fn host_candidate_messages(addrs: &[SocketAddr]) -> Vec<PunchCandidate> {
    addrs
        .iter()
        .map(|a| PunchCandidate::from_addr(*a, PunchCandidateKind::Host))
        .collect()
}

fn is_global_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xe000) == 0x2000
}

fn is_ula(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Whether `ip` is an address a stranger on the internet can send to: not
/// private, CGNAT, link-local, loopback, ULA or otherwise special. The
/// rendezvous reports a target address that is not public as
/// `target_reflexive_private` (ADR-0054 decision 8, derived candidate).
pub fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_global_v6(&v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(
        ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        // CGNAT 100.64.0.0/10.
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
        // Documentation ranges are what the simulated networks use as their
        // "public" side, so they count as public here.
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_means_routable_by_a_stranger() {
        for public in [
            "8.8.8.8",
            "203.0.113.7",
            "198.51.100.1",
            "2001:db8::1",
            "2a00::1",
        ] {
            assert!(is_public(ip(public)), "{public}");
        }
        for private in [
            "10.0.0.1",
            "172.16.4.4",
            "192.168.1.9",
            "100.64.0.1",
            "100.127.255.1",
            "169.254.1.1",
            "127.0.0.1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!is_public(ip(private)), "{private}");
        }
    }

    #[test]
    fn host_candidates_take_one_per_family_and_skip_link_local_v6() {
        let observed = [
            ip("192.168.1.5"),
            ip("10.9.9.9"),
            ip("fe80::1"),
            ip("2001:db8::5"),
            ip("fd12::5"),
        ];
        let c = host_candidates(&observed, 6000);
        assert_eq!(
            c,
            vec![
                "192.168.1.5:6000".parse().unwrap(),
                "[2001:db8::5]:6000".parse().unwrap()
            ]
        );
        assert!(host_candidates(&[ip("fe80::1"), ip("127.0.0.1")], 6000).is_empty());
        assert!(host_candidates(&[ip("fd12::5")], 6000).len() == 1);
    }
}
