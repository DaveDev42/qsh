//! L4: the **recovery gate** (`docs/design/testing.md` L4, PLAN M2 Step 7,
//! DoD 4). `chaos_proxy.rs` proved the harness can express path death;
//! this file asserts the criterion itself.
//!
//! The criterion is deliberately narrow, because the loose version of it is
//! satisfiable by doing nothing: quinn's idle timeout is 45 s, so a client
//! that simply waits will eventually notice and reconnect, and a test that
//! only checks "it recovered in the end" would pass. So:
//!
//! - the clock starts **immediately before `sever()`**, not at some point
//!   the test picks afterwards;
//! - the old session is never closed by hand — the path dies, nothing else;
//! - the clock stops at the **first replayed byte** on the new connection,
//!   so a re-dial that has not yet produced session output does not count;
//! - and the old connection is checked to have *not* died of idle timeout,
//!   which is what tells "we recovered" from "the transport gave up and we
//!   started over".
//!
//! The bound itself is [`REDIAL_DEADLINE`] — 2 s — and it is enforced by
//! [`recover`], which is the same code path the product uses, not a
//! test-local stopwatch.
//!
//! **What this does not yet measure.** testing.md L4's criterion is "2 s
//! from path-death *detection*", and there is no detector: the probe passed
//! to [`recover`] here is `|| async { false }`, which costs nothing. The
//! measured window is therefore re-dial + attach + first byte, and the
//! detection half of the budget is unrepresented. That is the honest state
//! of the gate — the sever→resume half is green, the detector is the seam
//! Step 9 plugs in.
//! TODO(Step 9): drive this with the real path-death detector and re-check
//! the bound with detection inside the window.

use std::time::Duration;

use qsh_core::client::reconnect::{REDIAL_DEADLINE, Recovered, RecoveryOutcome, recover};
use qsh_core::client::{ClientError, Session};
use qsh_core::telemetry::Recovery;
use qsh_proto::wire::{self, StreamHeader, session_frame};
use qsh_testkit::chaos::ChaosPolicy;
use qsh_testkit::loopback::LoopbackHarness;
use qsh_transport::FramedStream;

/// Wall-clock bound on any single chaotic round trip that is *not* the
/// thing under test. Generous but finite: a hang is a failure.
const OP_DEADLINE: Duration = Duration::from_secs(30);

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Open the `SESSION_DATA` stream for `ticket` on `s`'s connection.
async fn redeem(s: &Session, ticket: Vec<u8>) -> FramedStream {
    let (send, recv) = s.connection().open_bi().await.expect("open_bi");
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::session_data(ticket))
        .await
        .expect("stream header");
    data
}

/// Read output frames until `want` bytes have arrived; returns the bytes
/// and the cumulative offset of the last one.
async fn read_output(data: &mut FramedStream, want: usize) -> (Vec<u8>, u64) {
    let mut bytes = Vec::new();
    let mut last_seq = 0;
    while bytes.len() < want {
        let frame = data
            .recv
            .recv::<wire::SessionFrame>()
            .await
            .expect("frame")
            .expect("stream ended early");
        if let Some(session_frame::Body::Output(o)) = frame.body {
            bytes.extend_from_slice(&o.data);
            last_seq = o.sequence;
        }
    }
    (bytes, last_seq)
}

/// The gate: a severed path is detected, re-dialed and **resumed** — first
/// replayed byte in hand — inside [`REDIAL_DEADLINE`].
#[tokio::test(flavor = "multi_thread")]
async fn a_severed_path_is_redialed_and_resumed_inside_the_deadline() {
    // Sever only. Loss and jitter have their own tests; mixing them in here
    // would make a deadline miss ambiguous.
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x5E4E57)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let opened = s
        .session_open(open_req())
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    let mut data = redeem(&s, opened.ticket.clone()).await;

    let before = b"before the path died\r\n";
    pipe.write_output(before).await.expect("child output");
    let (delivered, last_seq) =
        tokio::time::timeout(OP_DEADLINE, read_output(&mut data, before.len()))
            .await
            .unwrap_or_else(|_| panic!("first output stalled — {ctx}"));
    assert_eq!(delivered, before, "{ctx}");

    // Produced while the path is dying: this is what the resume must
    // replay, and reading its first byte is where the clock stops.
    let after = b"after the path died\r\n";
    pipe.write_output(after).await.expect("child output");

    // The old connection, kept alive on purpose — the client never closes
    // it, so what happens to it is evidence rather than setup.
    let old = s.connection().clone();

    // ---- the measured window starts here ----
    h.chaos().sever().await;
    let session_ref = format!("box/{}", opened.session_id);
    let out = recover(
        &session_ref,
        // No binder: this path is gone for good, so migration is not on the
        // table. Correctness comes from resume alone — which is the point.
        None,
        || async { false },
        || async {
            let mut fresh = h.session().await;
            let attached = fresh
                .attach_request(wire::SessionAttach {
                    session_id: opened.session_id.clone(),
                    resume_token: opened.resume_token.clone(),
                    last_output_seq: last_seq,
                    mode: wire::AttachMode::Rw as i32,
                    no_steal: false,
                })
                .await?;
            let mut stream = redeem(&fresh, attached.ticket.clone()).await;
            // Stop at the first replayed byte: a re-dial that has not
            // produced session output has not recovered anything.
            let (bytes, _) = read_output(&mut stream, 1).await;
            Ok::<_, ClientError>((fresh, attached, stream, bytes))
        },
    )
    .await;
    // ---- and ends here ----

    let (fresh, attached, mut stream, first_byte) = match out.outcome {
        Ok(Recovered::Resumed(parts)) => parts,
        Ok(Recovered::Migrated) => panic!("a severed path cannot migrate — {ctx}"),
        Err(err) => panic!(
            "resume did not complete within {REDIAL_DEADLINE:?}: {err} — {}",
            h.detail()
        ),
    };
    assert_eq!(out.report.recovery, Recovery::Resumed, "{ctx}");
    // `recover` already enforced the bound with a timeout, so the
    // load-bearing assertion is the `panic!` on `Err` above; this one is a
    // consistency check that the *reported* number matches the window that
    // was actually enforced.
    assert!(
        u128::from(out.report.time_to_recovery_ms) <= REDIAL_DEADLINE.as_millis(),
        "the report contradicts the deadline `recover` enforced: {} ms — {ctx}",
        out.report.time_to_recovery_ms
    );
    assert_eq!(out.report.session_ref, session_ref);
    assert_eq!(attached.replay_from, last_seq, "{ctx}");
    assert!(
        !first_byte.is_empty() && after.starts_with(&first_byte),
        "the replay did not continue at the offset that was asked for — {ctx}"
    );

    // The old connection did not time out — it was still perfectly healthy
    // when we recovered. Without this, a 44-second detector riding quinn's
    // idle timeout would satisfy every other assertion here.
    let reason = old.close_reason();
    assert!(
        !matches!(reason, Some(qsh_transport::ConnectionError::TimedOut)),
        "the recovery rode the idle timeout instead of detecting path death: \
         {reason:?} — {ctx}"
    );

    // The rest of the replay is intact behind that first frame.
    let remaining = after.len() - first_byte.len();
    let (rest, _) = tokio::time::timeout(OP_DEADLINE, read_output(&mut stream, remaining))
        .await
        .unwrap_or_else(|_| panic!("the replay stalled after its first frame — {ctx}"));
    let mut stitched = delivered.clone();
    stitched.extend_from_slice(&first_byte);
    stitched.extend_from_slice(&rest);
    let mut reference = before.to_vec();
    reference.extend_from_slice(after);
    assert_eq!(
        stitched, reference,
        "the stitch is not byte-identical — {ctx}"
    );

    let stats = h.chaos().stats();
    assert_eq!(stats.severs, 1, "{}", h.detail());
    assert!(
        stats.is_balanced(),
        "the proxy's accounting identity broke — {}",
        h.detail()
    );
    assert_eq!(
        h.server_connections().len(),
        2,
        "a resume after a sever is a new connection, not a migration — {}",
        h.detail()
    );

    fresh.close();
    s.close();
    h.shutdown().await;
}

/// The other half of the recovery story: when the path merely *moves*, the
/// connection survives it and there is nothing to resume. Classified
/// `migrated`, and the session never learns anything happened.
///
/// This is why migration is only an optimization: the same session, the
/// same code, and a completely different amount of work.
#[tokio::test(flavor = "multi_thread")]
async fn a_repath_survives_as_a_migration_with_nothing_to_resume() {
    let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x9EA77)).await;
    let ctx = h.context();
    let mut s = tokio::time::timeout(OP_DEADLINE, h.session())
        .await
        .unwrap_or_else(|_| panic!("negotiate — {ctx}"));
    let opened = s
        .session_open(open_req())
        .await
        .unwrap_or_else(|err| panic!("session.open: {err:?} — {ctx}"));
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    let mut data = redeem(&s, opened.ticket.clone()).await;

    pipe.write_output(b"before\r\n").await.expect("output");
    let (before, _) = tokio::time::timeout(OP_DEADLINE, read_output(&mut data, 8))
        .await
        .unwrap_or_else(|_| panic!("first output stalled — {ctx}"));
    assert_eq!(before, b"before\r\n", "{ctx}");

    // The host's view of the connection — `stable_id` is per-connection,
    // so an unchanged id after new bytes flowed is migration and not a
    // reconnect.
    let host_conn = h
        .server_connections()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("the host has no connection yet — {ctx}"));
    let stable_id = host_conn.stable_id();
    let old_up = h.chaos().upstream_addr().await.expect("upstream bound");

    let session_ref = format!("box/{}", opened.session_id);
    let new_up = h.chaos().repath().await.expect("repath");
    assert_ne!(new_up, old_up, "repath must move ports — {ctx}");

    // The probe may be called more than once, so the session it round
    // trips on lives behind a shared handle rather than being captured by
    // value.
    let live = tokio::sync::Mutex::new(s);
    let id = opened.session_id.clone();
    let out: RecoveryOutcome<()> = {
        let target = &live;
        let id = &id;
        recover(
            &session_ref,
            None,
            // A real round trip on the existing connection. It is also
            // what *causes* the migration to complete: the host learns the
            // new peer address from a packet arriving on it, so a probe
            // that only listened would wait for a keep-alive.
            move || async move {
                let mut session = target.lock().await;
                tokio::time::timeout(OP_DEADLINE, session.session_get(id))
                    .await
                    .is_ok_and(|r| r.is_ok())
            },
            || async { panic!("a migrated connection must not be re-dialed — {ctx}") },
        )
        .await
    };
    let s = live.into_inner();

    assert!(
        matches!(out.outcome, Ok(Recovered::Migrated)),
        "{:?} — {ctx}",
        out.outcome.map(|_| ())
    );
    assert_eq!(out.report.recovery, Recovery::Migrated, "{ctx}");
    assert!(
        u128::from(out.report.time_to_recovery_ms) <= REDIAL_DEADLINE.as_millis(),
        "a migration took {} ms — {ctx}",
        out.report.time_to_recovery_ms
    );

    // The attach stream it was carrying never noticed: output written
    // after the path moved arrives on the same stream, in sequence.
    pipe.write_output(b"after\r\n").await.expect("output");
    let (after, _) = tokio::time::timeout(OP_DEADLINE, read_output(&mut data, 7))
        .await
        .unwrap_or_else(|_| panic!("the attach stream stalled after the repath — {ctx}"));
    assert_eq!(after, b"after\r\n", "{ctx}");
    assert_eq!(
        h.server_connections().len(),
        1,
        "a migration must not create a second connection — {}",
        h.detail()
    );
    assert_eq!(
        h.server_connections()[0].stable_id(),
        stable_id,
        "the host is talking to a different connection — {}",
        h.detail()
    );

    let stats = h.chaos().stats();
    assert_eq!(stats.repaths, 1, "{}", h.detail());
    assert!(stats.is_balanced(), "{}", h.detail());

    s.close();
    h.shutdown().await;
}

/// The active-migration primitive itself: rebinding the client endpoint to
/// a fresh local socket keeps the connection — and the session on it —
/// alive. Plain loopback, because this is about the local socket moving,
/// not about the path in between.
///
/// Nothing depends on this working (a rebind that fails falls through to
/// resume), which is exactly why it needs its own test: a silent
/// regression here would cost latency, not correctness, and nothing else
/// would notice.
#[tokio::test(flavor = "multi_thread")]
async fn rebinding_the_client_endpoint_keeps_the_connection() {
    use qsh_core::client::reconnect::PathBinder;

    let h = LoopbackHarness::start().await;
    let dialed = h.dial().await;
    let endpoint = dialed.endpoint.clone();
    let conn = dialed.connection.clone();
    let stable_id = conn.stable_id();
    let mut s = Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate");
    let opened = s.session_open(open_req()).await.expect("session.open");
    let (_spec, mut pipe) = h.pipes.take_with_spec().expect("pipe handle");
    let mut data = redeem(&s, opened.ticket.clone()).await;
    pipe.write_output(b"before\r\n").await.expect("output");
    let (_, last_seq) = tokio::time::timeout(OP_DEADLINE, read_output(&mut data, 8))
        .await
        .expect("first output");

    let before_addr = endpoint.local_addr().expect("local addr");
    // Fully qualified: quinn has an inherent `rebind` that takes a socket;
    // the trait's is the one that binds a fresh one, and it is the one the
    // recovery driver calls.
    let after_addr = PathBinder::rebind(&endpoint).expect("rebind to a fresh socket");
    assert_ne!(
        before_addr, after_addr,
        "a rebind must actually move the local socket"
    );

    // The same connection, the same session, across a new local address.
    pipe.write_output(b"after\r\n").await.expect("output");
    let (after, seq) = tokio::time::timeout(OP_DEADLINE, read_output(&mut data, 7))
        .await
        .expect("the session survives the rebind");
    assert_eq!(after, b"after\r\n");
    assert!(seq > last_seq);
    assert_eq!(
        conn.stable_id(),
        stable_id,
        "a rebind is a migration on the same connection, not a new one"
    );
    assert!(
        conn.close_reason().is_none(),
        "the connection did not survive the rebind: {:?}",
        conn.close_reason()
    );

    s.close();
    h.shutdown().await;
}
