//! The one OS contact behind `qsh trust invite`'s candidate block: ask the
//! kernel which source address a packet leaving this host would carry.
//!
//! Split out of the parent module for the reason `crate::doctor::probe`'s
//! own doc gives for the same split — detection apart from everything that
//! decides what the detection means, so the deciding half is unit-testable
//! with synthetic inputs, with no real socket, no timing and no flakiness.
//! Unlike that module this file needs no `#[cfg]` at all:
//! `bind`/`connect`/`local_addr` are the same three calls on every
//! platform QSH supports, and the platform differences are only in *which*
//! error a missing route surfaces as, which this file does not classify —
//! it drops the axis either way.
//!
//! Nothing is ever transmitted. `connect(2)` on a datagram socket
//! exchanges no packets; it records a default destination, which means the
//! kernel resolves a route and picks a source address, synchronously and
//! in memory. That is the whole observation. `qsh trust invite` is
//! interactive, so nothing here may wait on the network: there is no
//! transmit call and no receive call and therefore nothing to time out,
//! and the destinations are `SocketAddr` constants rather than strings so
//! no name lookup can happen either. `xtask arch` bans those two method
//! tokens in this file so that stays a property of the code and not of a
//! comment (`docs/design/threat-model.md` §3's `qsh trust invite`
//! entry-point row).
//!
//! The bind-then-connect-then-read order is required, not incidental:
//! reading the local address of a socket bound to an unspecified address
//! is only defined once that socket has been connected.
//!
//! Crate-private on purpose: `crate::ops::Ops::invite_address_advice` is
//! [`observe_source_addresses`]'s only production caller, so deleting that
//! call makes this function dead code and fails `cargo clippy -- -D
//! warnings` on every machine, whatever routes that machine happens to
//! have — the mutation this file's own `mod tests` below does not undo,
//! since a `#[cfg(test)]` call site does not exist in the plain `lib`
//! compilation that lint runs against.
//!
//! [`OBSERVATION_COUNT`] guards a different mutation than deleting the
//! call: *hoisting* it so it still runs, just unconditionally instead of
//! only inside `finish`'s human-mode closure (`crates/qsh-cli/src/
//! main.rs`'s `Command::Trust(TrustCmd::Invite)` arm). That mutation keeps
//! every call site intact, so `dead_code` has nothing to catch; a counter
//! observable from outside this crate does. It cannot be `#[cfg(test)]`
//! itself — the test that reads it lives in `qsh-cli`, a separate crate
//! compiled without `qsh-core`'s own `--cfg test`, so a test-only counter
//! would simply not exist for it to read.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};

/// IPv4 route-query destination: RFC 5737 TEST-NET-1, discard port. A
/// documentation-range address is chosen precisely because it is
/// guaranteed not to be a real host — and since nothing is transmitted,
/// the address only ever functions as an argument to a route lookup.
const V4_DESTINATION: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);

/// IPv6 route-query destination: RFC 3849 documentation prefix, discard
/// port. Same reasoning as [`V4_DESTINATION`].
const V6_DESTINATION: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
    9,
);

/// How many times [`observe_source_addresses`] has run, this process's
/// whole lifetime. `Relaxed`: this exists to be counted, not to
/// synchronize anything else — the machine-mode invariant it pins
/// (`--json`/`--jsonl` never calls it, `docs/CLI.md` §2.2) is checked by
/// comparing two loads around one single-threaded `dispatch` call, not by
/// ordering it against some other memory access.
static OBSERVATION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The source addresses this host's routing table would use, one axis at
/// most each, in IPv4-then-IPv6 order.
///
/// An axis with no route contributes nothing — a host with no default
/// route of that family fails at `connect` with a network-unreachable
/// class error, and that is the ordinary path, not a fault. Every failure
/// is treated the same way for the same reason: this function observes, it
/// does not classify.
pub(crate) fn observe_source_addresses() -> Vec<IpAddr> {
    OBSERVATION_COUNT.fetch_add(1, Ordering::Relaxed);
    [V4_DESTINATION, V6_DESTINATION]
        .into_iter()
        .filter_map(source_address_for)
        .collect()
}

/// How many times [`observe_source_addresses`] has run so far, this
/// process's whole lifetime. Exposed (through
/// [`super::route_query_count`]) so a `qsh-cli` test can drive the real
/// `Command::Trust(TrustCmd::Invite)` dispatch arm in both output modes
/// and assert this does not move under `--json`/`--jsonl` and does move
/// in human mode — the invariant a source-text match alone cannot pin,
/// because hoisting the call out of the human-only closure compiles clean
/// and changes no `dead_code` lint (adversarial review).
pub(crate) fn observation_count() -> usize {
    OBSERVATION_COUNT.load(Ordering::Relaxed)
}

/// One axis: bind an ephemeral socket of the destination's family, connect
/// it (no packet leaves), and read back the local address the kernel
/// chose.
fn source_address_for(destination: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if destination.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(destination).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mutation that swaps `local_addr()` for `peer_addr()` in
    /// [`source_address_for`] compiles clean, keeps every other gate
    /// green, and hands the operator this route query's own RFC
    /// 5737/3849 destination back as if it were this host's address
    /// (adversarial review, reproduced with the mutation applied). This
    /// is the value-pinning half of that guard, run wherever
    /// `V4_DESTINATION`/`V6_DESTINATION` are actually in scope; the
    /// companion in `crates/qsh-cli/tests/init_trust.rs` pins the same
    /// fact end to end, through the CLI's real stdout, on a machine
    /// this crate's tests never reach.
    ///
    /// Vacuously true on a machine with no default route of either
    /// family (`observe_source_addresses` returns an empty vector then)
    /// — not a conditional assertion, since it still runs and still
    /// passes on such a machine; it merely has nothing to check.
    #[test]
    fn observed_addresses_are_never_this_route_querys_own_destination() {
        for ip in observe_source_addresses() {
            assert_ne!(
                ip,
                V4_DESTINATION.ip(),
                "a candidate must never be the RFC 5737 destination itself"
            );
            assert_ne!(
                ip,
                V6_DESTINATION.ip(),
                "a candidate must never be the RFC 3849 destination itself"
            );
        }
    }

    /// [`observation_count`] moves by exactly one per
    /// [`observe_source_addresses`] call — the mechanical fact
    /// `crate::ops::Ops::invite_address_advice`'s machine-mode guard in
    /// `qsh-cli` (`main.rs`'s `trust_invite_json_mode_makes_no_route_
    /// query_while_human_mode_does`) rests on. That test cannot exercise
    /// this function directly (it lives one crate away, without
    /// `qsh-core`'s own `--cfg test`), so this is the one place able to
    /// pin the counter's own arithmetic rather than merely its
    /// reachability from another crate.
    #[test]
    fn observation_count_advances_by_exactly_one_per_call() {
        let before = observation_count();
        observe_source_addresses();
        assert_eq!(observation_count(), before + 1);
        observe_source_addresses();
        assert_eq!(observation_count(), before + 2);
    }
}
