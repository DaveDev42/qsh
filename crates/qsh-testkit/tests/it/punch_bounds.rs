//! ADR-0054 DoD 6: every bound of decisions 11, 13 and 14, one row each, in
//! one table test (`punch_bounds`). A row drives the real component against
//! the bound where that is cheap (the pure tables, the wire checks, and
//! netsim endpoints on tokio's paused clock) and fails with the row's name.
//!
//! Rows: 8 candidates, 4 peer-reflexive, 64 datagrams per end, rate 6 per
//! 60 s, 1 in flight, 4 windows, 4 handshakes per offer, 16 punch
//! connections at R, 1 KiB per message.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use qsh_core::punch::schedule::Schedule;
use qsh_core::punch::{
    AttemptLimiter, InitiatorParams, LimitHit, MAX_HANDSHAKES_PER_OFFER, MAX_PEER_REFLEXIVE,
    MAX_PUNCH_CANDIDATES, MAX_PUNCH_DATAGRAMS, PUNCH_INITIAL_RTT, RendezvousState, TargetParams,
    run_initiator, run_target,
};
use qsh_proto::punch::{
    PUNCH_DATAGRAM_LEN, PUNCH_MESSAGE_MAX, PUNCH_RATE, PUNCH_RATE_WINDOW_SECS, PunchDirection,
    PunchMessageError, RENDEZVOUS_MAX_CLIENTS, encode_punch_datagram, punch_tag,
};
use qsh_proto::wire::{
    PunchAnswer, PunchCandidate, PunchCandidateKind, PunchOffer, PunchReply, PunchRequest,
};
use qsh_testkit::make_identity;
use qsh_testkit::netsim::{NatKind, Net, NetConfig, Site};
use qsh_transport::{
    MAX_PUNCH_WINDOWS, Principal, PunchEndpoint, SocketSource, StaticTrust, TransportTuning,
};
use tokio::time::sleep;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn endpoint(
    site: &Site,
    port: u16,
    me: &qsh_testkit::TestIdentity,
    peer: &qsh_testkit::TestIdentity,
) -> PunchEndpoint {
    PunchEndpoint::new(
        SocketSource::Virtual(Arc::new(site.bind_wildcard(port).unwrap())),
        me.local.clone(),
        Arc::new(StaticTrust::empty().with_pin(peer.fingerprint, Principal::Device("peer".into()))),
        TransportTuning::default(),
    )
    .unwrap()
}

fn candidates(n: usize) -> Vec<PunchCandidate> {
    (0..n)
        .map(|i| {
            PunchCandidate::from_addr(
                SocketAddr::new(ip("198.51.100.9"), 4000 + i as u16),
                PunchCandidateKind::Host,
            )
        })
        .collect()
}

fn nowhere(n: u8) -> Vec<SocketAddr> {
    (1..=n)
        .map(|i| format!("192.0.2.{i}:9000").parse().unwrap())
        .collect()
}

/// Decision 11: at most eight candidates in any message.
fn candidates_are_capped_at_eight() {
    assert_eq!(MAX_PUNCH_CANDIDATES, 8);
    let request = |n| PunchRequest {
        attempt_id: vec![1; 16],
        target_fingerprint: vec![2; 32],
        candidates: candidates(n),
    };
    let offer = |n| PunchOffer {
        attempt_id: vec![1; 16],
        initiator_fingerprint: vec![2; 32],
        candidates: candidates(n),
    };
    let answer = |n| PunchAnswer {
        candidates: candidates(n),
    };
    let reply = |n| PunchReply {
        candidates: candidates(n),
        ..PunchReply::default()
    };
    assert_eq!(request(8).validate(), Ok(()));
    assert_eq!(offer(8).validate(), Ok(()));
    assert_eq!(answer(8).validate(), Ok(()));
    assert_eq!(reply(8).validate(), Ok(()));
    let too_many = Err(PunchMessageError::TooManyCandidates);
    assert_eq!(request(9).validate(), too_many);
    assert_eq!(offer(9).validate(), too_many);
    assert_eq!(answer(9).validate(), too_many);
    assert_eq!(reply(9).validate(), too_many);
    // R's side of the same bound is `invalid_candidates_are_dropped_and_too_
    // many_are_refused` (punch_signal).
}

/// Decision 8 and 11: A dials at most four addresses it learns from punch
/// datagrams. Six sources send a correctly tagged datagram; only four of
/// them are ever sent a QUIC Initial.
async fn peer_reflexive_candidates_are_capped_at_four() {
    assert_eq!(MAX_PEER_REFLEXIVE, 4);
    let net = Net::new(NetConfig::default());
    let a_site = net.internet().site(NatKind::None, "a", ip("198.51.100.1"));
    let (ida, idb) = (make_identity(), make_identity());
    let a = endpoint(&a_site, 5000, &ida, &idb);
    let attempt = [4u8; 16];
    let sources: Vec<_> = (0..6u8)
        .map(|i| {
            net.internet()
                .site(NatKind::None, "x", ip(&format!("198.51.100.{}", 20 + i)))
                .bind(7000)
                .unwrap()
        })
        .collect();

    let initiator = tokio::spawn({
        let a = a.clone();
        async move {
            run_initiator(
                &a,
                &InitiatorParams {
                    attempt_id: attempt,
                    expected_peer: idb.fingerprint,
                    candidates: nowhere(1),
                    budget: Duration::from_secs(2),
                },
            )
            .await
        }
    });
    sleep(Duration::from_millis(100)).await;
    let punch = encode_punch_datagram(&punch_tag(&attempt, PunchDirection::BToA));
    for s in &sources {
        s.send_to(SocketAddr::new(a_site.ip(), 5000), &punch);
        sleep(Duration::from_millis(10)).await;
    }
    assert!(initiator.await.unwrap().is_err(), "nobody answers");
    // A QUIC Initial is a long-header packet padded to 1200 bytes; the punch
    // datagram A sends to its one candidate goes elsewhere.
    let dialed = sources
        .iter()
        .filter(|s| {
            std::iter::from_fn(|| s.try_recv_from())
                .any(|(_, d)| d.len() >= 1200 && d[0] & 0x80 != 0)
        })
        .count();
    assert_eq!(dialed, MAX_PEER_REFLEXIVE, "learned addresses dialed");
    a.close(0, b"done");
}

/// Decision 14: 8 candidates times 8 offsets is 64 datagrams of 16 bytes,
/// 1 KiB per end, however many candidates are listed. Both the schedule and
/// a real initiator against twelve listed candidates are held to it; the
/// target end is `a_punch_attempt_sends_at_most_64_datagrams_per_end`
/// (punch_route).
async fn an_end_sends_at_most_sixty_four_datagrams() {
    assert_eq!(MAX_PUNCH_DATAGRAMS, 64);
    assert_eq!(MAX_PUNCH_DATAGRAMS * PUNCH_DATAGRAM_LEN, 1024);
    let mut schedule = Schedule::new(MAX_PUNCH_CANDIDATES);
    assert_eq!(schedule.due(Duration::from_secs(60)).len(), 64);

    let net = Net::new(NetConfig::default());
    let a_site = net
        .internet()
        .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
    let (ida, idb) = (make_identity(), make_identity());
    let a = endpoint(&a_site, 5000, &ida, &idb);
    let result = run_initiator(
        &a,
        &InitiatorParams {
            attempt_id: [3u8; 16],
            expected_peer: idb.fingerprint,
            candidates: nowhere(12),
            budget: Duration::from_secs(5),
        },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(a.stats().punch_sent, 64);
    a.close(0, b"done");
}

/// Decision 11: six attempts per initiator in 60 s, at R and at B.
fn rate_is_six_per_minute() {
    assert_eq!((PUNCH_RATE, PUNCH_RATE_WINDOW_SECS), (6, 60));
    let who = [1u8; 32];
    for single_flight in [true, false] {
        let mut limiter = AttemptLimiter::new(single_flight);
        let t0 = StdInstant::now();
        for i in 0..6u64 {
            let at = t0 + Duration::from_secs(i);
            assert_eq!(limiter.try_begin(&who, at), Ok(()), "attempt {i}");
            limiter.finish(&who);
        }
        let seventh = t0 + Duration::from_secs(10);
        assert_eq!(limiter.try_begin(&who, seventh), Err(LimitHit::Rate));
        // The window slides: the first attempt ages out after 60 s.
        assert_eq!(
            limiter.try_begin(&who, t0 + Duration::from_secs(60)),
            Ok(())
        );
    }
}

/// Decision 11: one attempt in flight per initiator at R, none at B.
fn one_attempt_is_in_flight_per_initiator() {
    let state = RendezvousState::default();
    let who = [7u8; 32];
    let first = state.begin_attempt(who).expect("the first attempt");
    assert!(matches!(state.begin_attempt(who), Err(LimitHit::InFlight)));
    // Another initiator is not in the way.
    let other = state.begin_attempt([8u8; 32]).expect("another initiator");
    drop(other);
    drop(first);
    assert!(state.begin_attempt(who).is_ok(), "free once it ended");

    // B has no such limit: two attempts of one initiator may overlap.
    let mut at_b = AttemptLimiter::new(false);
    let now = StdInstant::now();
    assert_eq!(at_b.try_begin(&who, now), Ok(()));
    assert_eq!(at_b.try_begin(&who, now), Ok(()));
}

/// Decision 11: four windows open on one endpoint at once.
async fn four_windows_are_open_at_most() {
    assert_eq!(MAX_PUNCH_WINDOWS, 4);
    let net = Net::new(NetConfig::default());
    let site = net.internet().site(NatKind::None, "b", ip("198.51.100.2"));
    let (idb, ida) = (make_identity(), make_identity());
    let b = endpoint(&site, 6000, &idb, &ida);
    let held: Vec<_> = (0..4)
        .map(|i| b.open_window().unwrap_or_else(|| panic!("window {i}")))
        .collect();
    assert_eq!(b.open_windows(), 4);
    assert!(b.open_window().is_none(), "a fifth window");
    drop(held);
    assert_eq!(b.open_windows(), 0);
    b.close(0, b"done");
}

/// Decision 14: a window accepts four handshakes per offer. Six dials from
/// a trusted peer reach B inside one window: four finish, two are refused.
async fn four_handshakes_per_offer() {
    assert_eq!(MAX_HANDSHAKES_PER_OFFER, 4);
    let net = Net::new(NetConfig::default());
    let b_site = net.internet().site(NatKind::None, "b", ip("198.51.100.2"));
    let x_site = net.internet().site(NatKind::None, "x", ip("198.51.100.3"));
    let (idb, idx) = (make_identity(), make_identity());
    let b = endpoint(&b_site, 6000, &idb, &idx);
    let x = endpoint(&x_site, 5000, &idx, &idb);

    let target = tokio::spawn({
        let b = b.clone();
        async move {
            let held = Arc::new(std::sync::Mutex::new(Vec::new()));
            let keep = held.clone();
            let report = run_target(
                &b,
                &TargetParams {
                    attempt_id: [5u8; 16],
                    candidates: vec![],
                    window: Duration::from_secs(3),
                },
                move |c| keep.lock().unwrap().push(c),
            )
            .await;
            (report, held)
        }
    });
    sleep(Duration::from_millis(50)).await;
    let addr = SocketAddr::new(b_site.ip(), 6000);
    let mut dials = Vec::new();
    for _ in 0..6 {
        let x = x.clone();
        let fp = idb.fingerprint;
        dials.push(tokio::spawn(async move {
            x.dial(addr, "qsh", PUNCH_INITIAL_RTT, &fp).await
        }));
    }
    let mut stood = 0;
    for d in dials {
        if d.await.unwrap().is_ok() {
            stood += 1;
        }
    }
    let (report, _held) = target.await.unwrap();
    assert_eq!(report.handshakes, 4, "{report:?}");
    assert_eq!(report.connections, 4, "{report:?}");
    assert_eq!(report.refused, 2, "{report:?}");
    assert_eq!(stood, 4, "four dials stand and two are refused");
    b.close(0, b"done");
    x.close(0, b"done");
}

/// Decision 10: sixteen punching connections at R.
fn rendezvous_holds_sixteen_punch_connections() {
    assert_eq!(RENDEZVOUS_MAX_CLIENTS, 16);
    let state = RendezvousState::default();
    let held: Vec<_> = (0..16)
        .map(|i| state.try_client().unwrap_or_else(|| panic!("slot {i}")))
        .collect();
    assert_eq!(state.clients(), 16);
    assert!(state.try_client().is_none(), "a seventeenth connection");
    drop(held);
    assert_eq!(state.clients(), 0);
    assert!(state.try_client().is_some());
}

/// Decision 11: no message encodes to more than 1 KiB. The size check comes
/// before the shape checks, so a request whose `attempt_id` pads it to
/// exactly 1024 bytes fails the shape rule and one byte more fails on size.
fn messages_are_capped_at_one_kib() {
    assert_eq!(PUNCH_MESSAGE_MAX, 1024);
    // tag (1) + two length bytes (n >= 128) + n bytes.
    let padded = |n: usize| PunchRequest {
        attempt_id: vec![0; n],
        ..PunchRequest::default()
    };
    assert_eq!(padded(1021).validate(), Err(PunchMessageError::AttemptId));
    assert_eq!(padded(1022).validate(), Err(PunchMessageError::TooLarge));
    let reply = PunchReply {
        initiator_reflexive: Some(PunchCandidate {
            ip: vec![0; 1100],
            port: 1,
            kind: PunchCandidateKind::Host as i32,
        }),
        ..PunchReply::default()
    };
    assert_eq!(reply.validate(), Err(PunchMessageError::TooLarge));
}

#[tokio::test(start_paused = true)]
async fn punch_bounds() {
    let mut rows: Vec<&str> = Vec::new();
    macro_rules! row {
        ($name:literal, $body:expr) => {{
            $body;
            rows.push($name);
        }};
    }
    row!("8 candidates", candidates_are_capped_at_eight());
    row!(
        "4 peer-reflexive",
        peer_reflexive_candidates_are_capped_at_four().await
    );
    row!(
        "64 datagrams per end",
        an_end_sends_at_most_sixty_four_datagrams().await
    );
    row!("rate 6 per 60 s", rate_is_six_per_minute());
    row!("1 in flight", one_attempt_is_in_flight_per_initiator());
    row!("4 windows", four_windows_are_open_at_most().await);
    row!("4 handshakes per offer", four_handshakes_per_offer().await);
    row!(
        "16 punch connections at R",
        rendezvous_holds_sixteen_punch_connections()
    );
    row!("1 KiB per message", messages_are_capped_at_one_kib());
    assert_eq!(rows.len(), 9, "{rows:?}");
}
