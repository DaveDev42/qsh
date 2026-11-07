//! `PunchEndpoint` over netsim NAT pairs, candidates supplied by hand
//! (ADR-0054 decisions 14, 22, 23; DoD 1 and 7 in their wire-free form).
//!
//! Two real QUIC endpoints on virtual sockets, each behind one of five NAT
//! kinds, a public rendezvous R that only echoes nothing but lets each end
//! learn its server-reflexive address the way a real rendezvous would (a
//! datagram from the endpoint's own socket to R, read at R). The candidates
//! each end hands the other are exactly what R would have relayed: its host
//! address and that reflexive address. No signalling messages exist yet, so
//! B starts 50 ms before A to model the signalling lag (B->R plus R->A at
//! 25 ms a link, decision 14), and A's clock starts at its own t=0.
//!
//! Everything runs on tokio's paused clock, so the times below are exact
//! virtual times and the result is the same on every OS. A failing assertion
//! names the pair and the seed.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use qsh_core::punch::{
    GiveUp, InitiatorParams, MAX_PUNCH_DATAGRAMS, PUNCH_TARGET_WINDOW, PUNCH_WINDOW, TargetParams,
    run_initiator, run_target,
};
use qsh_proto::punch::{AttemptId, PunchDirection, punch_tag};
use qsh_testkit::make_identity;
use qsh_testkit::netsim::{DropReason, NatKind, Net, NetConfig, PathConfig, Site};
use qsh_transport::{
    CLOSE_CODE_NOT_ADOPTED, Connection, ConnectionError, Principal, PunchEndpoint, SocketSource,
    StaticTrust, StreamCode, TransportTuning,
};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};

const KINDS: [NatKind; 5] = [
    NatKind::None,
    NatKind::FullCone,
    NatKind::Restricted,
    NatKind::PortRestricted,
    NatKind::Symmetric,
];

const SEEDS: [u64; 5] = [1, 2, 3, 4, 5];
/// The loss table is cheap, so it runs more seeds than the clean one.
const LOSS_SEEDS: u64 = 30;

/// B starts this long before A: B->R plus R->A at 25 ms a link.
const SIGNAL_LAG: Duration = Duration::from_millis(50);

const R_ADDR: &str = "203.0.113.1:9000";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// ADR-0054 decision 23: the three pairs that cannot open without port
/// prediction (A first, B second).
fn expected_to_fail(a: NatKind, b: NatKind) -> bool {
    matches!(
        (a, b),
        (NatKind::Symmetric, NatKind::PortRestricted)
            | (NatKind::PortRestricted, NatKind::Symmetric)
            | (NatKind::Symmetric, NatKind::Symmetric)
    )
}

fn name(k: NatKind) -> &'static str {
    match k {
        NatKind::None => "none",
        NatKind::FullCone => "full_cone",
        NatKind::Restricted => "restricted",
        NatKind::PortRestricted => "port_restricted",
        NatKind::Symmetric => "symmetric",
        NatKind::FirewallV6 => "firewall_v6",
        NatKind::PortRestrictedRandom => "port_restricted_random",
    }
}

struct Party {
    ep: PunchEndpoint,
    fingerprint: qsh_transport::Fingerprint,
    site: Site,
    port: u16,
}

fn party(
    site: Site,
    port: u16,
    me: &qsh_testkit::TestIdentity,
    peer: &qsh_testkit::TestIdentity,
) -> Party {
    let trust = StaticTrust::empty().with_pin(peer.fingerprint, Principal::Device("peer".into()));
    let socket = site.bind_wildcard(port).unwrap();
    let ep = PunchEndpoint::new(
        SocketSource::Virtual(Arc::new(socket)),
        me.local.clone(),
        Arc::new(trust),
        TransportTuning::default(),
    )
    .unwrap();
    Party {
        ep,
        fingerprint: me.fingerprint,
        site,
        port,
    }
}

impl Party {
    fn host_candidate(&self) -> SocketAddr {
        SocketAddr::new(self.site.ip(), self.port)
    }
}

/// The address R sees for a party: send one datagram from its socket to R.
async fn reflexive(p: &Party, r: &qsh_testkit::netsim::NetSocket) -> SocketAddr {
    let tag = punch_tag(&[0xee; 16], PunchDirection::AToB);
    p.ep.send_punch(R_ADDR.parse().unwrap(), &tag)
        .await
        .unwrap();
    let (from, bytes) = r.recv_from().await;
    assert_eq!(bytes.len(), 16);
    from
}

fn candidates(host: SocketAddr, reflexive: SocketAddr) -> Vec<SocketAddr> {
    if host == reflexive {
        vec![host]
    } else {
        vec![host, reflexive]
    }
}

#[derive(Debug)]
struct Outcome {
    /// Time from A's t=0 to the adopted handshake; `None` when A gave up.
    adopted: Option<Duration>,
    /// When A gave up, measured the same way.
    gave_up: Option<Duration>,
    peer_reflexive: bool,
    losers_closed: usize,
    a_punches: u64,
    b_punches: u64,
    a_quic: u64,
    b_quic: u64,
    b_connections: usize,
    echo_ok: bool,
    b_window_open_after: usize,
    lost: u64,
}

/// Serves one echo on every connection B receives: read "ping", write "pong".
fn echo_on(mut rx: mpsc::UnboundedReceiver<Connection>) -> tokio::task::JoinHandle<usize> {
    tokio::spawn(async move {
        let mut n = 0;
        while let Some(conn) = rx.recv().await {
            n += 1;
            tokio::spawn(async move {
                let Ok((mut tx, mut rx)) = conn.accept_bi().await else {
                    return;
                };
                let mut buf = [0u8; 4];
                if rx.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                    let _ = tx.write_all(b"pong").await;
                    let _ = tx.finish();
                    let _ = conn.closed().await;
                }
            });
        }
        n
    })
}

async fn scenario(a_kind: NatKind, b_kind: NatKind, seed: u64, ab_loss: f64) -> Outcome {
    let net = Net::new(NetConfig {
        seed,
        ..NetConfig::default()
    });
    let r_site = net.internet().site(NatKind::None, "r", ip("203.0.113.1"));
    let r_sock = r_site.bind(9000).unwrap();
    let a_site = net.internet().site(a_kind, "a", ip("198.51.100.1"));
    let b_site = net.internet().site(b_kind, "b", ip("198.51.100.2"));
    net.set_path(
        a_site.external_ip(),
        b_site.external_ip(),
        PathConfig::delay(Duration::from_millis(25)).with_loss(ab_loss),
    );

    let (ida, idb) = (make_identity(), make_identity());
    let a = party(a_site, 5000, &ida, &idb);
    let b = party(b_site, 6000, &idb, &ida);
    let a_refl = reflexive(&a, &r_sock).await;
    let b_refl = reflexive(&b, &r_sock).await;
    let (a_obs, b_obs) = (a.ep.stats(), b.ep.stats());

    let attempt: AttemptId = {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&seed.to_le_bytes());
        id[8] = a_kind as u8;
        id[9] = b_kind as u8;
        id
    };

    // B: server window, punches towards A's candidates.
    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let echo = echo_on(conn_rx);
    let b_task = tokio::spawn({
        let ep = b.ep.clone();
        let params = TargetParams {
            attempt_id: attempt,
            candidates: candidates(a.host_candidate(), a_refl),
            window: PUNCH_TARGET_WINDOW,
        };
        async move {
            run_target(&ep, &params, move |c| {
                let _ = conn_tx.send(c);
            })
            .await
        }
    });

    sleep(SIGNAL_LAG).await;
    let t0 = Instant::now();
    let result = run_initiator(
        &a.ep,
        &InitiatorParams {
            attempt_id: attempt,
            expected_peer: b.fingerprint,
            candidates: candidates(b.host_candidate(), b_refl),
            budget: PUNCH_WINDOW,
        },
    )
    .await;

    let mut out = Outcome {
        adopted: None,
        gave_up: None,
        peer_reflexive: false,
        losers_closed: 0,
        a_punches: 0,
        b_punches: 0,
        a_quic: 0,
        b_quic: 0,
        b_connections: 0,
        echo_ok: false,
        b_window_open_after: 0,
        lost: 0,
    };
    match result {
        Ok(adopted) => {
            out.adopted = Some(adopted.elapsed);
            out.peer_reflexive = adopted.peer_reflexive;
            out.losers_closed = adopted.losers_closed;
            let (mut tx, mut rx) = adopted.connection.open_bi().await.unwrap();
            tx.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            out.echo_ok = timeout(Duration::from_secs(2), rx.read_exact(&mut buf))
                .await
                .is_ok_and(|r| r.is_ok())
                && &buf == b"pong";
            adopted.connection.close(0, b"done");
        }
        Err(GiveUp::Timeout { .. }) => out.gave_up = Some(t0.elapsed()),
        Err(other) => panic!("seed {seed}: {a_kind:?} x {b_kind:?}: {other:?}"),
    }

    let report = b_task.await.unwrap();
    out.b_connections = report.connections;
    out.b_window_open_after = b.ep.open_windows();
    let (a_end, b_end) = (a.ep.stats(), b.ep.stats());
    out.a_punches = a_end.punch_sent - a_obs.punch_sent;
    out.b_punches = b_end.punch_sent - b_obs.punch_sent;
    out.a_quic = a_end.quic_sent;
    out.b_quic = b_end.quic_sent;
    out.lost = net.stats().dropped(DropReason::Loss);
    assert_eq!(report.punches_sent as u64, out.b_punches);
    a.ep.close(0, b"done");
    b.ep.close(0, b"done");
    drop(echo);
    out
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[idx]
}

fn ms(d: Duration) -> u128 {
    d.as_millis()
}

/// DoD 1 without the wire: the 25 pairs, five seeds, 25 ms a link, no loss.
/// The 22 pairs adopt a connection that carries an echo; the 3 give up
/// inside the budget with nothing left behind; time to adoption stays under
/// the ADR's second; no end sends more than 64 punch datagrams.
#[tokio::test(start_paused = true)]
async fn punch_endpoint_nat_matrix_hand_candidates() {
    let mut adopt_times = Vec::new();
    let mut rows = Vec::new();
    for &a in &KINDS {
        for &b in &KINDS {
            let mut pair_times = Vec::new();
            let mut worst_packets = (0, 0);
            let mut learned = 0;
            for &seed in &SEEDS {
                let o = timeout(Duration::from_secs(60), scenario(a, b, seed, 0.0))
                    .await
                    .unwrap_or_else(|_| panic!("seed {seed}: {} x {} hung", name(a), name(b)));
                let who = format!("seed {seed}: {} x {}", name(a), name(b));
                assert_eq!(o.b_window_open_after, 0, "{who}: window still open");
                assert!(o.a_punches <= MAX_PUNCH_DATAGRAMS as u64, "{who}: {o:?}");
                assert!(o.b_punches <= MAX_PUNCH_DATAGRAMS as u64, "{who}: {o:?}");
                worst_packets = (
                    worst_packets.0.max(o.a_punches),
                    worst_packets.1.max(o.b_punches),
                );
                if expected_to_fail(a, b) {
                    let t = o
                        .gave_up
                        .unwrap_or_else(|| panic!("{who}: should give up: {o:?}"));
                    assert!(
                        t <= PUNCH_WINDOW + Duration::from_millis(5),
                        "{who}: gave up at {t:?}"
                    );
                    assert_eq!(o.b_connections, 0, "{who}: B kept a connection");
                } else {
                    let t = o
                        .adopted
                        .unwrap_or_else(|| panic!("{who}: should adopt: {o:?}"));
                    assert!(
                        o.echo_ok,
                        "{who}: no echo over the adopted connection: {o:?}"
                    );
                    assert!(t <= PUNCH_WINDOW, "{who}: adopted at {t:?}");
                    pair_times.push(t);
                    adopt_times.push(t);
                    if o.peer_reflexive {
                        learned += 1;
                    }
                }
            }
            rows.push((a, b, pair_times, worst_packets, learned));
        }
    }

    println!(
        "\nA x B (seeds {SEEDS:?}): adoption ms min/max, A/B punch datagrams, peer-reflexive wins"
    );
    for (a, b, times, (pa, pb), learned) in &rows {
        let verdict = if times.is_empty() {
            "gave up (timeout at 5000 ms)".to_string()
        } else {
            let (lo, hi) = (times.iter().min().unwrap(), times.iter().max().unwrap());
            format!("adopted {}..{} ms", ms(*lo), ms(*hi))
        };
        println!(
            "{:>16} x {:<16} {:<32} A {:>2} B {:>2}  peer-reflexive {}/{}",
            name(*a),
            name(*b),
            verdict,
            pa,
            pb,
            learned,
            SEEDS.len()
        );
    }
    adopt_times.sort();
    let (p50, p95, max) = (
        percentile(&adopt_times, 0.50),
        percentile(&adopt_times, 0.95),
        *adopt_times.last().unwrap(),
    );
    println!(
        "adopted connections: {} (22 pairs x {} seeds), p50 {} ms, p95 {} ms, max {} ms",
        adopt_times.len(),
        SEEDS.len(),
        ms(p50),
        ms(p95),
        ms(max)
    );
    assert_eq!(adopt_times.len(), 22 * SEEDS.len());
    // DoD 1 measures from route start, which also holds the signalling; the
    // punch phase gets the second less four link delays of it.
    assert!(
        p95 <= Duration::from_millis(900),
        "p95 {p95:?} leaves too little of the 1.0 s bound for signalling"
    );
}

/// The same table with 5% loss on the A-B path: every success pair still
/// adopts inside the budget (DoD 1, second half).
#[tokio::test(start_paused = true)]
async fn punch_endpoint_nat_matrix_survives_five_percent_ab_loss() {
    let mut slowest = Duration::ZERO;
    let (mut lost, mut slowed) = (0, 0);
    for &a in &KINDS {
        for &b in &KINDS {
            if expected_to_fail(a, b) {
                continue;
            }
            for seed in 1..=LOSS_SEEDS {
                let o = timeout(Duration::from_secs(60), scenario(a, b, seed, 0.05))
                    .await
                    .unwrap();
                let who = format!("seed {seed}: {} x {} at 5% loss", name(a), name(b));
                let t = o
                    .adopted
                    .unwrap_or_else(|| panic!("{who}: should adopt: {o:?}"));
                assert!(o.echo_ok, "{who}: {o:?}");
                assert!(t <= PUNCH_WINDOW, "{who}: adopted at {t:?}");
                slowest = slowest.max(t);
                lost += o.lost;
                slowed += usize::from(t > Duration::from_millis(125));
            }
        }
    }
    println!(
        "5% A-B loss: {lost} datagrams lost, {slowed} of {} adoptions later than 125 ms, slowest {} ms",
        22 * LOSS_SEEDS as usize,
        ms(slowest)
    );
    assert!(lost > 0, "the loss never applied");
}

/// DoD 7: when several candidates reach the target, exactly one handshake is
/// adopted, every other connection the target holds is closed with `0x1006`
/// within a second, and the target's server side is off by second six.
///
/// "Several candidates reach the target" is built with a target that has two
/// addresses (two sockets with the same identity, as a multihomed host
/// does) at the same distance, so both handshakes finish in the same
/// instant and one has to lose.
#[tokio::test(start_paused = true)]
async fn punch_adopts_one_connection_and_closes_the_others_with_0x1006() {
    let net = Net::new(NetConfig::default());
    let a_site = net.internet().site(NatKind::None, "a", ip("198.51.100.1"));
    let b1_site = net.internet().site(NatKind::None, "b1", ip("198.51.100.2"));
    let b2_site = net.internet().site(NatKind::None, "b2", ip("198.51.100.3"));
    let (ida, idb) = (make_identity(), make_identity());
    let a = party(a_site, 5000, &ida, &idb);
    let b1 = party(b1_site, 6000, &idb, &ida);
    let b2 = party(b2_site, 6000, &idb, &ida);

    let attempt = [9u8; 16];
    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
    let b_start = Instant::now();
    let mut b_tasks = Vec::new();
    for b in [&b1, &b2] {
        let tx = conn_tx.clone();
        let ep = b.ep.clone();
        let params = TargetParams {
            attempt_id: attempt,
            candidates: vec![a.host_candidate()],
            window: PUNCH_TARGET_WINDOW,
        };
        b_tasks.push(tokio::spawn(async move {
            run_target(&ep, &params, move |c| {
                let _ = tx.send(c);
            })
            .await
        }));
    }
    drop(conn_tx);
    sleep(SIGNAL_LAG).await;
    let adopted = run_initiator(
        &a.ep,
        &InitiatorParams {
            attempt_id: attempt,
            expected_peer: b1.fingerprint,
            candidates: vec![b1.host_candidate(), b2.host_candidate()],
            budget: PUNCH_WINDOW,
        },
    )
    .await
    .expect("adopted");

    // The targets' side of the same race: every connection they hold.
    sleep(Duration::from_millis(1000)).await;
    let mut held = Vec::new();
    while let Ok(c) = conn_rx.try_recv() {
        held.push(c);
    }
    assert_eq!(held.len(), 2, "both handshakes finished");
    let mut open = 0;
    for c in &held {
        match c.close_reason() {
            None => open += 1,
            Some(ConnectionError::ApplicationClosed(app)) => {
                assert_eq!(
                    app.error_code,
                    StreamCode::from_u32(CLOSE_CODE_NOT_ADOPTED),
                    "a loser closed with another code"
                );
                assert_eq!(&app.reason[..], b"not adopted");
            }
            Some(other) => panic!("loser closed as {other:?}"),
        }
    }
    assert_eq!(open, 1, "exactly one of the two connections stays");
    assert_eq!(
        adopted.losers_closed, 1,
        "A closed the one it had completed"
    );
    assert!(adopted.connection.close_reason().is_none());

    for t in b_tasks {
        t.await.unwrap();
    }
    assert!(
        b_start.elapsed() <= PUNCH_TARGET_WINDOW + SIGNAL_LAG + Duration::from_millis(1100),
        "windows ran {:?}",
        b_start.elapsed()
    );
    for b in [&b1, &b2] {
        assert_eq!(b.ep.open_windows(), 0, "server side down after the window");
    }
    println!(
        "two reachable candidates: A adopted {} in {} ms and closed {} loser with 0x1006",
        adopted.remote,
        adopted.elapsed.as_millis(),
        adopted.losers_closed
    );
}

/// After the window the target answers nothing: a handshake started late
/// finds no server (decision 7).
#[tokio::test(start_paused = true)]
async fn punch_window_close_stops_new_handshakes_but_keeps_the_connection() {
    let net = Net::new(NetConfig::default());
    let a_site = net.internet().site(NatKind::None, "a", ip("198.51.100.1"));
    let b_site = net.internet().site(NatKind::None, "b", ip("198.51.100.2"));
    let (ida, idb) = (make_identity(), make_identity());
    let a = party(a_site, 5000, &ida, &idb);
    let b = party(b_site, 6000, &idb, &ida);
    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
    let b_task = tokio::spawn({
        let ep = b.ep.clone();
        let params = TargetParams {
            attempt_id: [1; 16],
            candidates: vec![a.host_candidate()],
            window: PUNCH_TARGET_WINDOW,
        };
        async move {
            run_target(&ep, &params, move |c| {
                let _ = conn_tx.send(c);
            })
            .await
        }
    });
    let adopted = run_initiator(
        &a.ep,
        &InitiatorParams {
            attempt_id: [1; 16],
            expected_peer: b.fingerprint,
            candidates: vec![b.host_candidate()],
            budget: PUNCH_WINDOW,
        },
    )
    .await
    .expect("adopted");
    let report = b_task.await.unwrap();
    assert_eq!(b.ep.open_windows(), 0);
    assert_eq!(report.connections, 1);
    let held = conn_rx.recv().await.unwrap();
    assert!(held.close_reason().is_none() && adopted.connection.close_reason().is_none());

    // A second handshake into the closed window gets no answer.
    let late = timeout(
        Duration::from_secs(2),
        a.ep.dial(
            b.host_candidate(),
            "qsh",
            Duration::from_millis(100),
            &b.fingerprint,
        ),
    )
    .await;
    assert!(late.is_err(), "a closed window must not answer a new dial");
}

/// Decision 12/15: a host that passes the trust check but is not the one the
/// attempt is for is never adopted, however fast it answers.
#[tokio::test(start_paused = true)]
async fn punch_never_adopts_a_trusted_stranger() {
    let net = Net::new(NetConfig::default());
    let a_site = net.internet().site(NatKind::None, "a", ip("198.51.100.1"));
    let b_site = net.internet().site(NatKind::None, "b", ip("198.51.100.2"));
    let (ida, idb, idc) = (make_identity(), make_identity(), make_identity());
    // A trusts both B and C; B trusts A.
    let trust = StaticTrust::empty()
        .with_pin(idb.fingerprint, Principal::Device("b".into()))
        .with_pin(idc.fingerprint, Principal::Device("c".into()));
    let a_ep = PunchEndpoint::new(
        SocketSource::Virtual(Arc::new(a_site.bind_wildcard(5000).unwrap())),
        ida.local.clone(),
        Arc::new(trust),
        TransportTuning::default(),
    )
    .unwrap();
    let b = party(b_site, 6000, &idb, &ida);
    let b_task = tokio::spawn({
        let ep = b.ep.clone();
        let params = TargetParams {
            attempt_id: [4; 16],
            candidates: vec![SocketAddr::new(a_site.ip(), 5000)],
            window: PUNCH_TARGET_WINDOW,
        };
        async move { run_target(&ep, &params, |_| {}).await }
    });
    let result = run_initiator(
        &a_ep,
        &InitiatorParams {
            attempt_id: [4; 16],
            expected_peer: idc.fingerprint,
            candidates: vec![b.host_candidate()],
            budget: PUNCH_WINDOW,
        },
    )
    .await;
    match result {
        Err(GiveUp::Timeout { failed_dials }) => {
            assert_eq!(failed_dials.len(), 1, "the one dial ended in a rejection");
            assert!(matches!(
                failed_dials[0].1,
                qsh_transport::DialError::LocalRejected { .. }
            ));
        }
        other => panic!("expected a give-up, got {other:?}"),
    }
    b_task.await.unwrap();
}
