//! L4 chaos-proxy regression gate (`docs/design/testing.md` L4, PLAN M2
//! Step 8). Every test here dials the host through a seeded UDP chaos proxy
//! and asserts an invariant that must hold *despite* the injected faults —
//! never a packet trace, because only the fault decisions are seeded, not the
//! order in which the kernel hands us datagrams.
//!
//! What is proved on top of what M2 already has (Steps 1–4): loss, jitter,
//! reordering and duplication cost nothing but time (QUIC's own recovery does
//! the work); a corrupted datagram is *rejected*, never delivered (the AEAD
//! positive control); a blackhole is ridden out; a `repath()` migrates the
//! connection host-side without disturbing the session; and a `sever()`
//! leaves a re-dial able to reach the same, still-running session inside
//! [`REDIAL_DEADLINE`].
//!
//! Not here (PLAN M2 Step 7/8): resume tokens, `session.attach` replay, the
//! client re-dial loop, the SC4 `kill -9` case. The harness is the point —
//! those scenarios plug into it as `tests/resume_chaos.rs`.
//!
//! **Where the faults themselves are proved.** A counter bumped next to the
//! effect it witnesses is not evidence, so "the fault fired" rests on two
//! things outside this file's assertions: `ChaosStats::is_balanced` (the
//! relay accounting identity — a fault that bumps its counter and relays
//! anyway breaks it) and `tests/chaos_relay.rs`, which watches each fault
//! happen on the wire with no QUIC in the way.
//!
//! Every assertion message carries `h.context()` — seed and addresses, safe
//! to bind once. Counters are read at the assertion via `h.detail()`, never
//! from a snapshot taken before the traffic.

use std::time::Duration;

use qsh_core::client::{ClientError, Session};
use qsh_proto::wire::{self, session_read_event};
use qsh_testkit::chaos::{ChaosPolicy, DelayDist, REDIAL_DEADLINE};
use qsh_testkit::loopback::LoopbackHarness;

/// Wall-clock bound on any single chaotic round trip. Generous (chaos is
/// allowed to cost time) but finite (a hang is a failure, not a slow pass).
const OP_DEADLINE: Duration = Duration::from_secs(30);

/// A payload with no repeating structure a framing bug could hide behind.
fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + i / 251) % 251) as u8).collect()
}

fn open_req(argv: &[&str]) -> wire::SessionOpen {
    wire::SessionOpen {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// A lossy-network policy: everything except corruption, which gets its own
/// test so that a failure there is unambiguous.
fn lossy(seed: u64) -> ChaosPolicy {
    ChaosPolicy::seeded(seed)
        .drop(0.08)
        .delay(DelayDist::uniform(Duration::ZERO, Duration::from_millis(2)))
        .reorder(0.10)
        .duplicate(0.05)
}

/// Read `want` output bytes back with the `(after, ctl_after)` cursor,
/// failing loudly on a replay gap (a gap here would mean the ring evicted
/// bytes, not that the network lost them).
async fn drain(s: &mut Session, id: &str, want: usize, ctx: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(want);
    let mut after = 0u64;
    let mut ctl_after = 0u64;
    while out.len() < want {
        let read = s
            .session_read(wire::SessionRead {
                session_id: id.to_string(),
                after,
                max_bytes: 0,
                wait_ms: 5_000,
                ctl_after,
            })
            .await
            .unwrap_or_else(|err| panic!("session.read failed: {err:?} — {ctx}"));
        after = read.next_after;
        ctl_after = read.next_ctl_after;
        for event in &read.events {
            match &event.body {
                Some(session_read_event::Body::Output(o)) => out.extend_from_slice(&o.data),
                Some(session_read_event::Body::Gap(g)) => {
                    panic!("replay gap at {} — {ctx}", g.available_from)
                }
                _ => {}
            }
        }
    }
    out
}

/// Poll `probe` until it returns `Some`, bounded by a wall-clock deadline.
/// The loop yields rather than sleeping (`testing.md` CI 규율: no `sleep()`).
async fn until<T>(deadline: Duration, ctx: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    tokio::time::timeout(deadline, async {
        loop {
            if let Some(v) = probe() {
                return v;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("condition not reached within {deadline:?} — {ctx}"))
}

/// Control arm: a seeded proxy with no faults enabled is a transparent relay,
/// so the whole L3 spine keeps working through it. If this fails, nothing
/// else in this file means anything.
#[tokio::test(flavor = "multi_thread")]
async fn a_fault_free_proxy_is_transparent() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x0)).await;
    let ctx = h.context();
    assert_ne!(
        h.addr, h.host_addr,
        "the client must dial the proxy — {ctx}"
    );

    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let r = s
        .exec(
            &qsh_core::exec::ExecSpec {
                argv: vec!["sh".into(), "-c".into(), "printf hi; exit 3".into()],
                env: vec![],
                timeout: None,
            },
            None,
        )
        .await
        .unwrap_or_else(|err| panic!("exec: {err:?} — {ctx}"));
    assert_eq!(r.stdout, b"hi", "{ctx}");
    assert_eq!(r.exit_code, 3, "{ctx}");

    let stats = h.chaos().stats();
    assert!(
        stats.to_server > 0 && stats.to_client > 0,
        "{stats:?} — {ctx}"
    );
    assert_eq!(stats.dropped, 0, "{stats:?} — {ctx}");
    assert_eq!(stats.corrupted, 0, "{stats:?} — {ctx}");
    assert_eq!(stats.duplicated, 0, "{stats:?} — {ctx}");
    assert_eq!(stats.delayed, 0, "{stats:?} — {ctx}");
    assert_eq!(stats.reordered, 0, "{stats:?} — {ctx}");
    assert_eq!(stats.blackholed, 0, "{stats:?} — {ctx}");
    assert!(
        stats.is_balanced(),
        "relay accounting broke: {stats:?} — {ctx}"
    );
    s.close();
    h.shutdown().await;
}

/// `exec.run` over a lossy, jittery, reordering, duplicating path returns
/// **byte-identical** stdout and the same exit code. QUIC's retransmission
/// and dedup do the work; qsh contributes nothing but must not get in the
/// way.
#[tokio::test(flavor = "multi_thread")]
async fn exec_is_byte_identical_under_loss_delay_reorder_and_duplication() {
    let h = LoopbackHarness::start_chaotic(lossy(0x0C0F_FEE1)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));

    // 32 KiB in, echoed back out: enough datagrams that an 8% drop rate is a
    // certainty rather than a coin flip.
    let stdin_bytes = payload(32 * 1024);
    let stdin: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(stdin_bytes.clone()));
    let r = tokio::time::timeout(
        OP_DEADLINE,
        s.exec(
            &qsh_core::exec::ExecSpec {
                argv: vec!["cat".into()],
                env: vec![],
                timeout: None,
            },
            Some(stdin),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("exec did not finish — {ctx}"))
    .unwrap_or_else(|err| panic!("exec: {err:?} — {ctx}"));
    assert_eq!(r.exit_code, 0, "{ctx}");
    assert_eq!(r.stdout.len(), stdin_bytes.len(), "{ctx}");
    assert!(
        r.stdout == stdin_bytes,
        "stdout is not byte-identical — {ctx}"
    );

    // The counters say the faults fired; the accounting identity says they
    // *did* something (a fault that bumped and relayed anyway would have sent
    // more datagrams than it accounts for), and quinn's own loss counter is
    // the independent, transport-level witness that datagrams went missing —
    // a loopback path with a transparent relay loses nothing.
    let stats = h.chaos().stats();
    assert!(stats.dropped > 0, "the drop fault never fired — {stats:?}");
    assert!(stats.delayed > 0, "the delay fault never fired — {stats:?}");
    assert!(
        stats.duplicated > 0,
        "the dup fault never fired — {stats:?}"
    );
    assert!(
        stats.reordered > 0,
        "the reorder fault never fired — {stats:?}"
    );
    assert!(
        stats.is_balanced(),
        "relay accounting broke: {stats:?} — {ctx}"
    );
    let client_lost = s.connection().quinn().stats().path.lost_packets;
    let host_lost: u64 = h
        .server_connections()
        .iter()
        .map(|c| c.quinn().stats().path.lost_packets)
        .sum();
    assert!(
        client_lost + host_lost > 0,
        "nothing was ever detected as lost (client {client_lost}, host {host_lost}) — {}",
        h.detail()
    );
    s.close();
    h.shutdown().await;
}

/// The same for the session value ops: open → write → read (cursor) →
/// resize → get → close over a lossy path, with the replayed output
/// byte-identical to what the "child" produced.
#[tokio::test(flavor = "multi_thread")]
async fn session_ops_are_byte_identical_under_loss_delay_reorder_and_duplication() {
    let h = LoopbackHarness::start_chaotic(lossy(0x0C0F_FEE2)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));

    let opened = s
        .session_open(open_req(&["sh"]))
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let id = opened.session_id.clone();
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");

    // 32 KiB fits the harness's 64 KiB replay ring whole, so a gap here
    // would be a bug and not eviction.
    let produced = payload(32 * 1024);
    for chunk in produced.chunks(4096) {
        pipe.write_output(chunk).await.unwrap();
    }
    let drained = tokio::time::timeout(OP_DEADLINE, drain(&mut s, &id, produced.len(), &ctx))
        .await
        .unwrap_or_else(|_| panic!("session.read never caught up — {ctx}"));
    assert!(
        drained == produced,
        "replayed output is not byte-identical ({} of {} bytes) — {ctx}",
        drained.len(),
        produced.len()
    );

    // Input, control and teardown survive the same path.
    let written = s
        .session_write(&id, b"echo hi\n".to_vec())
        .await
        .unwrap_or_else(|err| panic!("session.write: {err:?} — {ctx}"));
    assert_eq!(written, 8, "{ctx}");
    assert_eq!(pipe.read_input(64).await.unwrap(), b"echo hi\n", "{ctx}");
    assert_eq!(s.session_resize(&id, 132, 43).await.unwrap(), (132, 43));
    let info = s.session_get(&id).await.unwrap();
    assert_eq!(info.state, "running", "{ctx}");
    assert_eq!(info.last_sequence, produced.len() as u64, "{ctx}");
    assert_eq!(s.session_list().await.unwrap().len(), 1, "{ctx}");
    let final_seq = s.session_close(&id, Some("TERM".into())).await.unwrap();
    assert_eq!(final_seq, produced.len() as u64, "{ctx}");

    let stats = h.chaos().stats();
    assert!(stats.dropped > 0, "the drop fault never fired — {stats:?}");
    assert!(
        stats.duplicated > 0,
        "the dup fault never fired — {stats:?}"
    );
    assert!(
        stats.is_balanced(),
        "relay accounting broke: {stats:?} — {ctx}"
    );
    s.close();
    h.shutdown().await;
}

/// **AEAD positive control.** Corrupted datagrams must be *rejected* by
/// QUIC — indistinguishable from loss — never authenticated and handed up.
/// If a single tampered byte could reach the application, this test would
/// see it as a mismatch, because the payload is checked byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn corrupted_datagrams_never_reach_application_data() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0xBADF00D).corrupt(0.08)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));

    let opened = s
        .session_open(open_req(&["sh"]))
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let id = opened.session_id.clone();
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    // 32 KiB, well inside the harness's 64 KiB replay ring, so a gap here
    // would be a bug and not eviction.
    let produced = payload(32 * 1024);
    for chunk in produced.chunks(4096) {
        pipe.write_output(chunk).await.unwrap();
    }
    let drained = tokio::time::timeout(OP_DEADLINE, drain(&mut s, &id, produced.len(), &ctx))
        .await
        .unwrap_or_else(|_| panic!("session.read never caught up — {ctx}"));
    assert!(
        drained == produced,
        "corruption reached application data — {ctx}"
    );

    let stats = h.chaos().stats();
    assert!(stats.corrupted > 0, "nothing was corrupted — {stats:?}");
    assert_eq!(stats.dropped, 0, "only corruption was enabled — {stats:?}");
    assert!(
        stats.is_balanced(),
        "relay accounting broke: {stats:?} — {ctx}"
    );

    // The other half of the control: the tampered datagrams did not merely
    // fail to poison the payload, they were *rejected* — the sender saw
    // them as loss. Loss is counted by whichever endpoint sent the packet,
    // so both are consulted.
    let client_lost = s.connection().quinn().stats().path.lost_packets;
    let host_lost: u64 = h
        .server_connections()
        .iter()
        .map(|c| c.quinn().stats().path.lost_packets)
        .sum();
    assert!(
        client_lost + host_lost > 0,
        "corrupted datagrams were not treated as loss (client {client_lost}, host {host_lost}) — {}",
        h.detail()
    );
    s.close();
    h.shutdown().await;
}

/// A blackhole that ends before the idle timeout is ridden out: the op
/// issued while the path is dead completes, correctly, once the path is
/// back. (The blackhole's own duration is the injected fault, not a test
/// `sleep()` — the assertion is a deadline on the op.)
#[tokio::test(flavor = "multi_thread")]
async fn an_in_flight_op_survives_a_blackhole_and_recovery() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x0B14C)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let opened = s
        .session_open(open_req(&["sh"]))
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let id = opened.session_id.clone();
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    let produced = payload(8 * 1024);
    for chunk in produced.chunks(4096) {
        pipe.write_output(chunk).await.unwrap();
    }

    // Path dies for 300 ms — an order of magnitude under the 45 s idle
    // timeout, so recovery must come from PTO retransmission, not from the
    // connection being torn down and rebuilt.
    h.chaos().blackhole(Duration::from_millis(300)).await;
    let drained = tokio::time::timeout(OP_DEADLINE, drain(&mut s, &id, produced.len(), &ctx))
        .await
        .unwrap_or_else(|_| panic!("the op never completed after recovery — {ctx}"));
    assert!(
        drained == produced,
        "output was lost across a blackhole — {ctx}"
    );

    let stats = h.chaos().stats();
    assert!(stats.blackholed > 0, "nothing was blackholed — {stats:?}");
    assert!(
        stats.is_balanced(),
        "relay accounting broke: {stats:?} — {ctx}"
    );
    assert!(s.session_get(&id).await.is_ok(), "connection died — {ctx}");
    s.close();
    h.shutdown().await;
}

/// `repath()` — the harness's stand-in for NAT rebinding / Wi-Fi→LTE — must
/// produce a **connection migration**: the host observes a new peer address
/// on the *same* connection, and the session never notices. quinn does the
/// path validation; this test pins that qsh does not undo it (nothing above
/// the transport may cache the peer address).
#[tokio::test(flavor = "multi_thread")]
async fn repath_migrates_the_connection_and_the_session_continues() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x9EA7)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let opened = s
        .session_open(open_req(&["sh"]))
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let id = opened.session_id.clone();
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    let first = payload(4 * 1024);
    for chunk in first.chunks(4096) {
        pipe.write_output(chunk).await.unwrap();
    }
    let before = drain(&mut s, &id, first.len(), &ctx).await;
    assert!(before == first, "{ctx}");

    // What the host sees right now, and what it must come to see.
    let conn = until(OP_DEADLINE, &ctx, || {
        h.server_connections().first().cloned()
    })
    .await;
    let old_peer = conn.remote_address();
    let old_up = h.chaos().upstream_addr().await.expect("upstream bound");
    assert_eq!(old_peer, old_up, "the host's peer is the proxy — {ctx}");

    let new_up = h.chaos().repath().await.expect("repath");
    assert_ne!(new_up, old_up, "repath must move ports — {ctx}");

    // The session keeps working across the path change, on the same
    // connection (`stable_id` is per-connection, so an equal id after new
    // bytes flowed is migration and not a reconnect).
    let stable_id = conn.stable_id();
    let second = payload(6 * 1024);
    for chunk in second.chunks(4096) {
        pipe.write_output(chunk).await.unwrap();
    }
    let after = tokio::time::timeout(
        OP_DEADLINE,
        drain(&mut s, &id, first.len() + second.len(), &ctx),
    )
    .await
    .unwrap_or_else(|_| panic!("the session stalled after repath — {ctx}"));
    assert!(
        after[..first.len()] == first[..] && after[first.len()..] == second[..],
        "output was lost or duplicated across the migration — {ctx}"
    );
    assert_eq!(
        h.server_connections().len(),
        1,
        "migration must not create a second connection — {ctx}"
    );
    assert_eq!(h.server_connections()[0].stable_id(), stable_id, "{ctx}");

    // …and the host now believes the peer lives at the new address.
    let observed = until(REDIAL_DEADLINE, &ctx, || {
        let peer = conn.remote_address();
        (peer == new_up).then_some(peer)
    })
    .await;
    assert_eq!(observed, new_up, "{ctx}");
    assert_eq!(h.chaos().stats().repaths, 1, "{}", h.detail());
    s.close();
    h.shutdown().await;
}

/// `sever()` — the path dies for good, which is the other recovery route.
/// The old connection can never be recovered (no amount of retransmission
/// reaches the host), a **re-dial** succeeds inside [`REDIAL_DEADLINE`], and
/// the session outlived both. The client-side re-dial loop and `session.
/// attach` replay are PLAN M2 Step 7; what is pinned here is that the
/// harness can express the scenario and that the host end already holds up.
#[tokio::test(flavor = "multi_thread")]
async fn sever_kills_the_path_and_a_redial_finds_the_session_alive() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x5E4E5)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let opened = s
        .session_open(open_req(&["sh"]))
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let id = opened.session_id.clone();
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    let produced = payload(8 * 1024);
    for chunk in produced.chunks(4096) {
        pipe.write_output(chunk).await.unwrap();
    }
    assert!(
        drain(&mut s, &id, produced.len(), &ctx).await == produced,
        "{ctx}"
    );

    h.chaos().sever().await;
    assert_eq!(h.chaos().upstream_addr().await, None, "{ctx}");

    // Nothing can traverse a severed path, so this cannot complete — the
    // deadline is an upper bound on patience, not a race.
    let stalled = tokio::time::timeout(Duration::from_millis(500), s.session_get(&id)).await;
    assert!(
        stalled.is_err(),
        "a severed path answered: {stalled:?} — {ctx}"
    );
    s.close();

    // NOT the L4 recovery criterion — only the scenario. `REDIAL_DEADLINE`
    // is testing.md L4's "path 사망 감지 후 2초 내 재dial + resume", and this
    // test can bound none of the parts that matter: the clock starts where
    // the test chooses, the old session was closed by hand rather than
    // detected as dead, and nothing is resumed. Nothing in M2 Step 8 can do
    // better, because nothing yet notices path death (quinn's idle timeout is
    // 45 s), so this assertion would also pass with a 44-second detector.
    // Step 7 owes the real gate in `resume_chaos.rs`: start the clock at
    // `sever()`, never `close()` by hand, stop it at the first replayed byte
    // after `session.attach`, and assert the old connection was not closed by
    // idle timeout. DoD 4 stays unchecked until then.
    let mut s2 = tokio::time::timeout(REDIAL_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("re-dial did not complete within {REDIAL_DEADLINE:?} — {ctx}"));

    // The session survived the connection (SC5's shape), and its replay
    // buffer still holds every byte from offset 0.
    let info = s2
        .session_get(&id)
        .await
        .unwrap_or_else(|err| panic!("session.get after re-dial: {err:?} — {ctx}"));
    assert_eq!(info.state, "running", "{ctx}");
    let replayed = tokio::time::timeout(OP_DEADLINE, drain(&mut s2, &id, produced.len(), &ctx))
        .await
        .unwrap_or_else(|_| panic!("replay after re-dial stalled — {ctx}"));
    assert!(
        replayed == produced,
        "replay after re-dial is not byte-identical — {ctx}"
    );

    assert_eq!(h.chaos().stats().severs, 1, "{}", h.detail());
    assert_eq!(
        h.server_connections().len(),
        2,
        "the re-dial is a new host connection, not a migration — {}",
        h.detail()
    );
    s2.close();
    h.shutdown().await;
}

/// A dropped client is not a distinguishable one: the proxy refuses the
/// severed source address for good, so a client that keeps retransmitting on
/// the old path gets nowhere while a fresh dial goes through.
#[tokio::test(flavor = "multi_thread")]
async fn a_severed_client_stays_severed() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x51)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    assert!(s.session_list().await.is_ok(), "{ctx}");
    h.chaos().sever().await;

    let before = h.chaos().stats().to_server;
    let err = tokio::time::timeout(Duration::from_millis(300), s.session_list()).await;
    assert!(err.is_err(), "{ctx}");
    let stats = h.chaos().stats();
    assert_eq!(
        stats.to_server, before,
        "not one datagram may cross a severed path — {stats:?}"
    );
    assert!(
        stats.refused > 0,
        "the client kept retransmitting and the proxy refused it — {stats:?}"
    );
    assert!(
        h.chaos().severed_clients().await.len() == 1,
        "{}",
        h.detail()
    );
    s.close();
    h.shutdown().await;
}

/// A chaos harness is still an ordinary harness: the ACL choke point, the
/// audit trail and error mapping are unchanged by what the network did.
#[tokio::test(flavor = "multi_thread")]
async fn errors_and_audit_are_unchanged_by_the_network() {
    let h = LoopbackHarness::start_chaotic(lossy(0xAC10)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let err = s
        .session_get("01K0NOSUCHSESSION")
        .await
        .expect_err("no such session");
    match err {
        ClientError::Remote { code, .. } => {
            assert_eq!(code, qsh_proto::ErrorCode::SessionNotFound, "{ctx}")
        }
        other => panic!("expected a remote error, got {other:?} — {ctx}"),
    }
    let records = h.audit.records();
    assert_eq!(records.len(), 1, "{ctx}");
    assert_eq!(records[0].action, "session.list", "{ctx}");
    assert_eq!(records[0].decision, "allow", "{ctx}");
    // A single tiny op is too few datagrams to *guarantee* an 8 % drop
    // fires, so this test asserts the relay was live and honest rather than
    // that a particular fault fired; the fault counters are pinned by the
    // byte-identity tests above and by `chaos_relay.rs`.
    let stats = h.chaos().stats();
    assert!(
        stats.from_client > 0,
        "nothing crossed the proxy — {stats:?}"
    );
    assert!(
        stats.is_balanced(),
        "relay accounting broke: {stats:?} — {ctx}"
    );
    s.close();
    h.shutdown().await;
}

/// Two live connections through one proxy are relayed independently: a
/// long-poll `session.read` on the first connection still gets its answer
/// while the second connection is chatty. A relay that keyed the return path
/// on "whoever spoke last" would send the host's reply to the wrong client,
/// which drops it as an unknown connection id — a silent stall, not an
/// error.
///
/// This is the shape PLAN M2 Step 7 needs: after a `sever()` the host-side
/// connection stays alive for the full 45 s idle timeout, so a re-dial that
/// attaches (lease steal, or `no_steal` → `SESSION_CONFLICT`) is *two* live
/// connections, and the harness has to be able to relay both.
#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_connections_are_relayed_independently() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x2C0)).await;
    let ctx = h.context();
    let mut first = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let opened = first
        .session_open(open_req(&["sh"]))
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let id = opened.session_id.clone();
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");

    let mut second = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("second negotiate — {ctx}"));
    assert_eq!(h.chaos().flows().await.len(), 2, "{}", h.detail());

    // The first connection parks on a long poll: no output exists yet, so
    // the host cannot answer until one is written.
    let read = tokio::spawn(async move {
        let out = first
            .session_read(wire::SessionRead {
                session_id: id,
                after: 0,
                max_bytes: 0,
                wait_ms: 10_000,
                ctl_after: 0,
            })
            .await;
        (first, out)
    });

    // Meanwhile the second connection does all the talking.
    for _ in 0..8 {
        second
            .session_list()
            .await
            .unwrap_or_else(|err| panic!("session.list on the second connection: {err:?} — {ctx}"));
    }

    let produced = payload(4 * 1024);
    for chunk in produced.chunks(4096) {
        pipe.write_output(chunk).await.unwrap();
    }
    let (mut first, out) = tokio::time::timeout(OP_DEADLINE, read)
        .await
        .unwrap_or_else(|_| panic!("the long poll never returned — {}", h.detail()))
        .expect("read task panicked");
    let out = out.unwrap_or_else(|err| panic!("session.read: {err:?} — {ctx}"));
    let bytes: Vec<u8> = out
        .events
        .iter()
        .filter_map(|e| match &e.body {
            Some(session_read_event::Body::Output(o)) => Some(o.data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(
        produced.starts_with(&bytes) && !bytes.is_empty(),
        "the long poll's answer went to the wrong client ({} bytes) — {}",
        bytes.len(),
        h.detail()
    );

    // Both connections are still usable afterwards.
    assert_eq!(first.session_list().await.unwrap().len(), 1, "{ctx}");
    assert_eq!(second.session_list().await.unwrap().len(), 1, "{ctx}");
    assert_eq!(
        h.server_connections().len(),
        2,
        "two dials, two host connections — {}",
        h.detail()
    );
    first.close();
    second.close();
    h.shutdown().await;
}
