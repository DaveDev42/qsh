//! ADR-0061 decision 4: how the gate judges iroh attempts and keyed peers.
//! No network: peers are built by hand and the clock is the test clock.

use super::*;
use crate::broker::TestClock;
use std::net::{Ipv4Addr, SocketAddr};

fn addr(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

fn keyed(key_byte: u8, path: qsh_transport::PeerPath) -> PeerAddr {
    PeerAddr::Keyed {
        key: qsh_transport::PeerKey([key_byte; qsh_transport::PEER_KEY_LEN]),
        path,
    }
}

fn relay_path() -> qsh_transport::PeerPath {
    qsh_transport::PeerPath::Relay("https://relay.example.test".to_string())
}

fn kind(d: &Decision) -> &'static str {
    match d {
        Decision::Retry => "Retry",
        Decision::Ignore(..) => "Ignore",
        Decision::Refuse(..) => "Refuse",
        Decision::Admit(_) => "Admit",
    }
}

/// A keyed peer is bucketed by its key, whatever path carries it: a relay
/// peer and the same key on a direct path share one bucket, two keys do not,
/// and neither lands in the shared `::/64` bucket a peer without an address
/// used to fall into.
#[test]
fn a_keyed_peer_is_bucketed_by_key_and_not_by_path() {
    let direct = qsh_transport::PeerPath::Direct(addr(Ipv4Addr::new(203, 0, 113, 9), 4433));
    assert_eq!(
        SourceKey::from_peer(&keyed(1, relay_path())),
        SourceKey::from_peer(&keyed(1, direct))
    );
    assert_ne!(
        SourceKey::from_peer(&keyed(1, relay_path())),
        SourceKey::from_peer(&keyed(2, relay_path()))
    );
    assert_ne!(
        SourceKey::from_peer(&keyed(1, relay_path())),
        SourceKey::from_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    );
    // A socket peer is still bucketed by its address.
    assert_eq!(
        SourceKey::from_peer(&PeerAddr::Socket(addr(Ipv4Addr::new(203, 0, 113, 9), 1))),
        SourceKey::from_addr(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
    );
}

/// The post-handshake judgment spends the key's own validated budget: one
/// key over its burst is refused with an audit row naming it, while another
/// key and a socket peer keep their whole budgets.
#[tokio::test]
async fn decide_keyed_limits_each_key_on_its_own() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 10, 5); // validated burst = 10
    let noisy = keyed(7, relay_path());
    for i in 1..=10 {
        assert!(
            gate.decide_keyed(&noisy, gate.now()).is_ok(),
            "attempt {i}/10 is within the burst"
        );
    }
    let records = gate
        .decide_keyed(&noisy, gate.now())
        .expect_err("the 11th is over the key's budget");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].resource, "validated_rate_limited");
    assert_eq!(records[0].action, "connect");
    assert_eq!(records[0].decision, "deny");
    assert_eq!(records[0].peer_addr, noisy.to_string());
    assert_eq!(records[0].peer_path.as_deref(), Some("relay"));
    assert_eq!(
        records[0].relay.as_deref(),
        Some("https://relay.example.test")
    );

    // The same key on a direct path is the same bucket.
    let moved = keyed(
        7,
        qsh_transport::PeerPath::Direct(addr(Ipv4Addr::new(203, 0, 113, 9), 1)),
    );
    assert!(gate.decide_keyed(&moved, gate.now()).is_err());
    // Another key, and a socket peer, are untouched.
    assert!(
        gate.decide_keyed(&keyed(8, relay_path()), gate.now())
            .is_ok()
    );
    let socket = PeerAddr::Socket(addr(Ipv4Addr::new(203, 0, 113, 9), 1));
    assert!(matches!(
        gate.decide(&socket, true, gate.now()),
        Decision::Admit(_)
    ));
}

/// A relay attempt has no source address: it takes a handshake permit from
/// the shared pool or is refused at the cap, and the refusal writes no audit
/// row. A direct attempt at the cap is audited like a QUIC one.
#[tokio::test]
async fn an_iroh_attempt_over_the_cap_is_refused_and_only_a_sourced_one_is_audited() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 1, 100, 100);
    let relay_peer = keyed(3, relay_path());
    let held = match gate.decide_iroh_attempt(&relay_peer, gate.now()) {
        Decision::Admit(permit) => permit,
        other => panic!("expected Admit, got {}", kind(&other)),
    };
    assert_eq!(gate.available_permits(), 0, "the shared pool is spent");
    match gate.decide_iroh_attempt(&relay_peer, gate.now()) {
        Decision::Refuse(RejectReason::AtCapacity, records) => {
            assert!(records.is_empty(), "no source address, no admission row");
        }
        other => panic!("expected Refuse, got {}", kind(&other)),
    }
    let direct_peer = PeerAddr::Socket(addr(Ipv4Addr::new(203, 0, 113, 50), 9));
    match gate.decide_iroh_attempt(&direct_peer, gate.now()) {
        Decision::Refuse(RejectReason::AtCapacity, records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].resource, "at_capacity");
            assert_eq!(records[0].peer_addr, direct_peer.to_string());
        }
        other => panic!("expected Refuse, got {}", kind(&other)),
    }
    drop(held);
    assert!(matches!(
        gate.decide_iroh_attempt(&relay_peer, gate.now()),
        Decision::Admit(_)
    ));
}

/// A direct iroh attempt is rate limited by its source address, and never
/// answered with a Retry (iroh has none).
#[tokio::test]
async fn a_direct_iroh_attempt_is_rate_limited_by_source() {
    let clock = Arc::new(TestClock::new());
    let gate = Gate::new(clock.clone(), 64, 5, 5); // burst = 10 per epoch
    let peer = PeerAddr::Socket(addr(Ipv4Addr::new(203, 0, 113, 60), 9));
    let mut held = Vec::new();
    let mut ignored = 0;
    for _ in 0..30 {
        match gate.decide_iroh_attempt(&peer, gate.now()) {
            Decision::Admit(permit) => held.push(permit),
            Decision::Ignore(RejectReason::RateLimited, _) => ignored += 1,
            other => panic!("unexpected {}", kind(&other)),
        }
    }
    assert_eq!(held.len(), 10, "one epoch's burst");
    assert_eq!(ignored, 20);
}
