//! Quota integration tests (`PLAN.md` M8 Step 3, `docs/adr/0010-resource-
//! quotas.md`): `crate::quota` wired into a *real*, running
//! `Server::run`/reverse-target accept loop over real loopback QUIC —
//! `qsh-core::quota`'s own unit tests and `server::mod`'s inline tests pin
//! the pure logic and the wire-adjacent mapping without a network; these
//! pin the same invariants end to end, against the real accept loop, the
//! real audit sink, and (for two of them) a real already-open session.
//!
//! `crates/qsh-testkit/src/loopback.rs`'s `LoopbackHarness::
//! start_with_quotas` builds the host with a caller-chosen
//! [`QuotaLimits`] instead of `ServeConfig`'s defaults, and also pins a
//! second, distinct client identity (`device:phone`) so the per-principal
//! test can drive two budgets against the one host.

use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::client::{ClientError, Session};
use qsh_core::exec::ExecSpec;
use qsh_core::quota::QuotaLimits;
use qsh_proto::ErrorCode;
use qsh_proto::wire;
use qsh_testkit::loopback::{LoopbackHarness, make_ca, make_identity};
use qsh_transport::{Dialer, FramedStream, Principal, StaticTrust};

/// Mirrors `qsh_core::quota`'s private `AUDIT_AGGREGATION_WINDOW` (10s) —
/// not reachable from here, so restated (the same convention
/// `crates/qsh-testkit/tests/admission.rs` uses for its own copy of the
/// admission module's identical constant).
const AUDIT_AGGREGATION_WINDOW: Duration = Duration::from_secs(10);

/// Same empirical margin `admission.rs`'s on-exit-flush tests use, for the
/// identical reason: rejecting immediately after harness start puts the
/// window's staleness point within milliseconds of the accept loop's
/// periodic flush tick — decided by scheduling jitter, not by anything
/// this test is actually trying to prove. Opening the window comfortably
/// away from a tick boundary makes the on-exit flush the only thing that
/// can produce the summary this test asserts on.
const WINDOW_OPEN_DELAY: Duration = Duration::from_secs(4);

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

fn exec_spec(argv: &[&str]) -> ExecSpec {
    ExecSpec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: vec![],
        timeout: None,
    }
}

/// Unwrap a [`ClientError`] into the peer's `(code, retryable)` — the
/// wire-level shape a `qsh.cli/v1` JSON envelope's `error` object mirrors
/// field for field (`docs/CLI.md` §3).
fn remote(err: ClientError) -> (ErrorCode, bool) {
    match err {
        ClientError::Remote {
            code, retryable, ..
        } => (code, retryable),
        other => panic!("expected a remote error, got {other:?}"),
    }
}

/// I1 (design §4.4) — the global session cap. Past it, `session.open`
/// answers `RESOURCE_EXHAUSTED`/`retryable: true` on the wire (the same
/// shape the CLI's JSON envelope carries verbatim, `docs/CLI.md` §3), the
/// refused attempt creates nothing (`session.list`'s length is
/// unchanged), and — the task's "slot released after close" clause,
/// folded into this same test rather than a separate one, since it is the
/// direct continuation of the same scenario — closing the session frees
/// the slot for exactly one more open before the cap refuses again.
#[tokio::test(flavor = "multi_thread")]
async fn session_open_past_the_quota_answers_resource_exhausted_and_creates_nothing() {
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_sessions: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s = h.session().await;

    let opened = s.session_open(open_req()).await.unwrap();
    let err = s.session_open(open_req()).await.unwrap_err();
    let (code, retryable) = remote(err);
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(
        retryable,
        "RESOURCE_EXHAUSTED must be retryable on the wire"
    );

    let list = s.session_list().await.unwrap();
    assert_eq!(
        list.len(),
        1,
        "the refused open must create nothing — session.list is unchanged"
    );

    // Slot released after close: the next open succeeds...
    s.session_close(&opened.session_id, None).await.unwrap();
    let reopened = s.session_open(open_req()).await.unwrap();
    assert_ne!(reopened.session_id, opened.session_id);

    // ...and refilling the cap refuses the one after that, the same way.
    let err2 = s.session_open(open_req()).await.unwrap_err();
    let (code2, retryable2) = remote(err2);
    assert_eq!(code2, ErrorCode::ResourceExhausted);
    assert!(retryable2);

    h.shutdown().await;
}

/// I3 (design §4.4) — `max_sessions_per_principal` is keyed by principal,
/// not shared: `device:laptop`'s budget is exhausted while the harness's
/// second pinned identity, `device:phone`, opens its own session against
/// the same host unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn two_principals_have_independent_session_budgets() {
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_sessions: 100,
        max_sessions_per_principal: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut laptop = h.session().await;
    let _opened = laptop.session_open(open_req()).await.unwrap();
    let err = laptop.session_open(open_req()).await.unwrap_err();
    let (code, retryable) = remote(err);
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(retryable);

    // `h.second_dial()`, not `h.second_dialer.dial(..)` directly — the
    // harness tracks every endpoint it dials through `second_dial`/`dial`
    // so `h.shutdown()` below can close it; a raw `second_dialer.dial(..)`
    // bypasses that tracking and leaks the endpoint (B11 of the M8 Step 3a
    // conformance sweep — this test showed up as a nextest LEAK).
    let dialed = h.second_dial().await;
    let mut phone = Session::negotiate(dialed.connection, "phone")
        .await
        .expect("negotiate");
    let opened_phone = phone.session_open(open_req()).await.unwrap();
    assert!(!opened_phone.session_id.is_empty());

    h.shutdown().await;
}

/// I7 (design §4.4) — a saturated quota must not starve work already in
/// flight: with the cap already full, the existing session's PTY round
/// trip (write reaches the child, output reaches the peer) still works.
#[tokio::test(flavor = "multi_thread")]
async fn existing_session_echo_survives_a_saturated_quota() {
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_sessions: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s = h.session().await;
    let opened = s.session_open(open_req()).await.unwrap();
    let id = opened.session_id.clone();
    let mut pipe = h.pipes.take().expect("pipe handle for the session");

    let err = s.session_open(open_req()).await.unwrap_err();
    let (code, retryable) = remote(err);
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(retryable);

    pipe.write_output(b"still alive").await.unwrap();
    let read = s
        .session_read(wire::SessionRead {
            session_id: id.clone(),
            after: 0,
            max_bytes: 0,
            wait_ms: 5_000,
            ctl_after: 0,
        })
        .await
        .unwrap();
    let mut bytes = Vec::new();
    for e in &read.events {
        if let Some(wire::session_read_event::Body::Output(o)) = &e.body {
            bytes.extend_from_slice(&o.data);
        }
    }
    assert_eq!(bytes, b"still alive");

    let n = s.session_write(&id, b"ok\n".to_vec()).await.unwrap();
    assert_eq!(n, 3);
    assert_eq!(pipe.read_input(64).await.unwrap(), b"ok\n");

    h.shutdown().await;
}

/// F6 of the M8 Step 3a conformance sweep: `qsh_core::broker`'s own
/// `detached_session_still_holds_quota_until_closed` never performs a real
/// attach or detach — it drops the returned open handle, which changes no
/// broker state, so it only pins half of `docs/CLI.md`'s "attach 중이든
/// detach된 상태든 점유량은 같다" claim. This drives a real wire
/// `session.attach` (a resume-token-bearing stream, protocol.md §10) and a
/// real detach (dropping that stream), end to end, and shows the slot is
/// held throughout both states — only `session.close` frees it.
#[tokio::test(flavor = "multi_thread")]
async fn attach_then_detach_still_holds_the_slot_until_close() {
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_sessions_per_principal: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s = h.session().await;
    let opened = s.session_open(open_req()).await.unwrap();

    // Unattached-but-running: the slot is already held (the property the
    // broker unit test does pin).
    let (code, retryable) = remote(s.session_open(open_req()).await.unwrap_err());
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(retryable);

    // Attach for real: a wire `SessionAttach` with the issued resume
    // token, same shape `attach_loopback.rs`'s tests drive.
    let attached = s
        .attach(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            ..Default::default()
        })
        .await
        .expect("session.attach");

    // Attached: the slot is still held — attaching does not add to the
    // occupancy count (it was already counted), but must not release it
    // either.
    let (code, retryable) = remote(s.session_open(open_req()).await.unwrap_err());
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(retryable);

    // Detach: drop the attached stream with no `session.close`. The CLI.md
    // claim under test is exactly this — detaching a still-running session
    // does not free its quota slot.
    drop(attached);
    let (code, retryable) = remote(s.session_open(open_req()).await.unwrap_err());
    assert_eq!(
        code,
        ErrorCode::ResourceExhausted,
        "detach must not release the quota slot of a still-running session"
    );
    assert!(retryable);

    // Only an explicit close frees it.
    s.session_close(&opened.session_id, None).await.unwrap();
    let reopened = s.session_open(open_req()).await.unwrap();
    assert_ne!(reopened.session_id, opened.session_id);

    h.shutdown().await;
}

/// I9 (design §4.4) — a flood of quota rejections in one window
/// aggregates into exactly one first line plus one summary in the host's
/// audit sink, visible through `LoopbackHarness::audit`, the same
/// first+summary discipline `admission::Gate` uses for handshake
/// rejections.
#[tokio::test(flavor = "multi_thread")]
async fn quota_rejection_audit_is_aggregated() {
    const REJECTIONS: usize = 3;
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_sessions: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s = h.session().await;
    let _opened = s.session_open(open_req()).await.unwrap();

    // See WINDOW_OPEN_DELAY's own doc: a wide gap from loop start before
    // the window even opens, so the periodic flush tick is nowhere near
    // this window's staleness point.
    tokio::time::sleep(WINDOW_OPEN_DELAY).await;

    for _ in 0..REJECTIONS {
        let err = s.session_open(open_req()).await.unwrap_err();
        let (code, _) = remote(err);
        assert_eq!(code, ErrorCode::ResourceExhausted);
    }

    tokio::time::sleep(AUDIT_AGGREGATION_WINDOW + Duration::from_millis(1500)).await;

    let audit = h.audit.clone();
    h.shutdown().await;

    let records = audit.records();
    let first = records
        .iter()
        .find(|r| r.resource == "quota_sessions_host" && r.count.is_none())
        .unwrap_or_else(|| panic!("expected a first quota_sessions_host line, got {records:?}"));
    assert_eq!(first.decision, "deny");
    let summary = records
        .iter()
        .find(|r| r.resource == "quota_sessions_host" && r.count.is_some())
        .unwrap_or_else(|| panic!("expected a quota_sessions_host summary, got {records:?}"));
    assert_eq!(
        summary.count,
        Some((REJECTIONS - 1) as u32),
        "the first rejection was reported immediately; the summary covers the rest"
    );
}

/// B5 (M8 Step 3a fix-3 sweep): pins `Server::run`'s post-loop
/// `quota_housekeeping` call as *the* thing that flushes a window a
/// shutdown catches — the window is pushed past its own staleness bound
/// (so `Quotas::flush_expired` is actually willing to close it —
/// `quota.rs`'s `flush_expired` only ever closes windows already
/// `AUDIT_AGGREGATION_WINDOW` old, shutdown or not: staleness, never
/// wall-clock proximity to shutdown, is what makes a window eligible)
/// but the shutdown fires comfortably *before* the loop's own next
/// periodic tick would have reached it anyway (same `WINDOW_OPEN_DELAY`
/// margin `quota_rejection_audit_is_aggregated` above and the periodic-
/// tick test in `reverse_target_quota` both rely on), and the summary is
/// asserted immediately after `h.shutdown().await` returns — no polling
/// — with the wait bounded well under a second periodic-tick interval.
/// If this post-loop call regressed to a no-op, the summary would never
/// arrive at all (nothing ticks the interval again after `run` returns).
#[tokio::test(flavor = "multi_thread")]
async fn quota_rejection_summary_is_flushed_by_a_shutdown_inside_the_window() {
    const REJECTIONS: usize = 3;
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_sessions: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s = h.session().await;
    let _opened = s.session_open(open_req()).await.unwrap();

    // See `WINDOW_OPEN_DELAY`'s own doc: a wide gap from loop start
    // before the window even opens, so the shutdown below (fired right
    // after the window crosses its own staleness bound) lands well
    // before the loop's *next* periodic tick — only the shutdown path
    // can be what produces the summary this test asserts on.
    tokio::time::sleep(WINDOW_OPEN_DELAY).await;

    for _ in 0..REJECTIONS {
        let err = s.session_open(open_req()).await.unwrap_err();
        let (code, _) = remote(err);
        assert_eq!(code, ErrorCode::ResourceExhausted);
    }

    // Past the window's own staleness bound (opened at ~t0+4, stale at
    // ~t0+14), landing at ~t0+15.5 — well before the next periodic tick
    // at ~t0+20 (same margin `quota_rejection_audit_is_aggregated` uses).
    tokio::time::sleep(AUDIT_AGGREGATION_WINDOW + Duration::from_millis(1500)).await;

    let audit = h.audit.clone();
    h.shutdown().await;

    let records = audit.records();
    let summary = records
        .iter()
        .find(|r| r.resource == "quota_sessions_host" && r.count.is_some())
        .unwrap_or_else(|| panic!("expected a quota_sessions_host summary, got {records:?}"));
    assert_eq!(
        summary.count,
        Some((REJECTIONS - 1) as u32),
        "the first rejection was reported immediately; the summary covers the rest"
    );
}

/// Verdict arbitration item 11①, end to end (the unit-level twin lives in
/// `crates/qsh-core/src/server/mod.rs`'s
/// `saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal`):
/// an unauthorized principal must never learn "the host is at capacity"
/// as a substitute for "you are not allowed here" — ACL runs before the
/// quota check, over a real connection. A CA-issued leaf authenticates
/// fine (the host trusts the CA) but was never pinned, so `AllowAllPinned`
/// denies it outright — regardless of whether the quota it would have hit
/// next is already saturated by someone else.
#[tokio::test(flavor = "multi_thread")]
async fn saturated_quota_still_answers_permission_denied_to_an_unauthorized_principal_end_to_end() {
    let ca = make_ca();
    let allowed = make_identity();
    let denied = ca.issue("qsh://device/mallory");
    let server_trust = StaticTrust::empty()
        .with_pin(allowed.fingerprint, Principal::Device("laptop".into()))
        .with_ca(ca.root_der.clone());
    let h = LoopbackHarness::start_custom_with_quotas(
        Arc::new(AllowAllPinned),
        allowed,
        server_trust,
        QuotaLimits {
            max_sessions: 1,
            ..QuotaLimits::default()
        },
    )
    .await;

    let mut s = h.session().await;
    let _opened = s.session_open(open_req()).await.unwrap();

    let client_trust = StaticTrust::empty().with_pin(
        h.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let dialer = Dialer::new(denied.local.clone(), Arc::new(client_trust));
    let dialed = dialer
        .dial(h.addr, "127.0.0.1")
        .await
        .expect("the CA-issued identity authenticates fine — only its ACL grant is missing");
    let mut mallory = Session::negotiate(dialed.connection, "mallory")
        .await
        .expect("negotiate");
    let err = mallory.session_open(open_req()).await.unwrap_err();
    let (code, _) = remote(err);
    assert_eq!(
        code,
        ErrorCode::PermissionDenied,
        "ACL must run before the quota check, even though the quota is saturated"
    );

    // Nothing was created for the refused attempt — the one allowed
    // session is still the only one.
    let list = s.session_list().await.unwrap();
    assert_eq!(list.len(), 1);

    h.shutdown().await;
}

/// The exec twin of I1: `max_exec_per_principal` end to end. A permit is
/// held from ticket *issue*, not redemption (`crate::quota` module docs,
/// `PLAN.md` M8 Step 3 verification round) — so a single unredeemed
/// `exec.run` ticket alone saturates a cap of 1, and the very next
/// `exec.run` on the same connection is refused before any child is ever
/// spawned.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_past_the_quota_answers_resource_exhausted_end_to_end() {
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_exec_per_principal: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s = h.session().await;

    let started = s.exec_start(&exec_spec(&["cat"])).await.unwrap();
    assert!(!started.ticket.is_empty());

    let err = s.exec_start(&exec_spec(&["true"])).await.unwrap_err();
    let (code, retryable) = remote(err);
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(retryable);

    h.shutdown().await;
}

/// S2 deviation 1 (main-session arbitration): a spawn failure must still
/// release the exec permit end to end — a permit is held from ticket
/// *issue*, not from a successfully spawned child (the test above's own
/// doc), so a leak here would be invisible to any test that only ever
/// spawns real, successful children. `cap = 1`: the first `exec.run`
/// targets a binary that cannot exist (`ENOENT`), which `qsh_core::exec::
/// run_exec::spawn_failure_code` maps to a shell-convention exit code
/// (127) rather than a protocol error — the wire call itself succeeds,
/// carrying a failure *inside* `ExecResult`. If the permit that first
/// `exec.run` held were never released on that path, the second
/// `exec.run` below would be refused `RESOURCE_EXHAUSTED` at a cap of 1.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_against_a_missing_binary_still_releases_the_permit_end_to_end() {
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_exec_per_principal: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s = h.session().await;

    let missing = s
        .exec(&exec_spec(&["/nonexistent/qsh-no-such-binary"]), None)
        .await
        .expect("exec.run completes over the wire even when the child never spawns");
    assert_eq!(
        missing.exit_code, 127,
        "ENOENT must map to the shell-convention \"command not found\" code"
    );

    // The permit the first exec held must already be gone — otherwise
    // this second exec.run, same connection, same principal, cap 1, would
    // be refused RESOURCE_EXHAUSTED.
    let admitted = s.exec(&exec_spec(&["true"]), None).await.unwrap();
    assert_eq!(admitted.exit_code, 0);

    h.shutdown().await;
}

/// The `ExecPermit` must stay alive for as long as the *child* does, not
/// merely until the exec ticket is redeemed. Both end-to-end exec quota
/// tests above saturate the cap with either an unredeemed ticket or an
/// exec that has already finished, so neither observes the window
/// between redemption and child exit — the one window
/// `TicketPurpose::Exec(pending)`'s arm in `server::serve_data_stream` is
/// responsible for. Here a real `cat` child is proven alive by
/// round-tripping a marker byte through its stdin/stdout — deterministic,
/// no sleep — while a second `exec.run` on a *second* connection of the
/// same principal (the budget is per principal, not per connection) must
/// be refused at `max_exec_per_principal = 1`; only after stdin is closed
/// and `cat` exits does a third `exec.run` succeed.
#[cfg(unix)] // real child spawn/exit and `cat` assumed unix-only here
#[tokio::test(flavor = "multi_thread")]
async fn a_running_child_holds_its_exec_permit_until_it_exits() {
    let h = LoopbackHarness::start_with_quotas(QuotaLimits {
        max_exec_per_principal: 1,
        ..QuotaLimits::default()
    })
    .await;
    let mut s1 = h.session().await;
    let mut s2 = h.session().await;

    // Redeem the ticket ourselves (instead of the bundled `Session::exec`)
    // so we control exactly when the child is proven alive, without any
    // sleep-based race.
    let started = s1.exec_start(&exec_spec(&["cat"])).await.unwrap();
    let (send, recv) = s1.connection().open_bi().await.unwrap();
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&wire::StreamHeader::exec_data(started.ticket))
        .await
        .unwrap();

    // Prove the child is actually running — not just an in-flight
    // redemption — by round-tripping a marker through its stdin/stdout;
    // `cat` cannot echo it back until the host has spawned it and hooked
    // up its pipes.
    data.send
        .send(&wire::ExecFrame::stdin(b"marker".to_vec()))
        .await
        .unwrap();
    match data.recv.recv::<wire::ExecFrame>().await.unwrap() {
        Some(wire::ExecFrame {
            body: Some(wire::exec_frame::Body::Stdout(chunk)),
        }) => {
            assert_eq!(chunk.data, b"marker");
        }
        other => panic!("expected the child's stdout echo, got {other:?}"),
    }

    // A live child still holds the only permit — the second connection's
    // exec.run must be refused, same principal, cap 1.
    let err = s2
        .exec_start(&exec_spec(&["true"]))
        .await
        .expect_err("a live child must still hold the only permit");
    let (code, retryable) = remote(err);
    assert_eq!(
        code,
        ErrorCode::ResourceExhausted,
        "the permit is released at child exit, not at ticket redemption"
    );
    assert!(retryable);

    // Close stdin so `cat` sees EOF and exits; drain to `ExecExit` —
    // "await the first exec".
    data.send.send(&wire::ExecFrame::stdin_eof()).await.unwrap();
    let exit = loop {
        match data.recv.recv::<wire::ExecFrame>().await.unwrap() {
            Some(wire::ExecFrame {
                body: Some(wire::exec_frame::Body::ExecExit(exit)),
            }) => break exit,
            Some(_) => continue,
            None => panic!("exec stream ended without ExecExit"),
        }
    };
    assert_eq!(exit.exit_code, 0);

    // The child has exited: the permit is free again, and a third
    // exec.run succeeds.
    let admitted = s2.exec(&exec_spec(&["true"]), None).await.unwrap();
    assert_eq!(admitted.exit_code, 0);

    h.shutdown().await;
}

// ==========================================================================
// I10 (design §4.5) — the reverse **target** arm enforces the identical
// session cap the forward host does. `ReverseHarness`'s own "start_*"
// family builds the *controller* (`Listen`) — it has no sessions of its
// own to quota. The target is a full `Server`, built inside
// `ReverseHarness::run_target_with_config` via the real
// `run_reverse_observed`/`host_runtime` (`crates/qsh-core/src/serve.rs`),
// exactly like `qsh serve`'s forward path — so the quota comes from the
// `Config` passed to `run_target_with_config`, not from a
// `ReverseHarness::start_with_quotas` constructor (there is nothing on
// the controller side for such a constructor to configure; see this
// stage's handoff for why the literal name in the task prompt does not
// fit here). Driven over a real `LOCAL_CONTROL` conduit — the same path a
// local CLI process reaches the target through — not `ReversePairHarness`
// (module docs: that harness hand-builds `Server::new` directly, hardcoding
// `QuotaLimits::default()`, so it could never have caught a regression
// where the reverse target's production wiring forgets to thread
// `[serve]`'s quota keys through `host_runtime` at all).
// ==========================================================================
#[cfg(unix)]
mod reverse_target_quota {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use qsh_core::acl::AllowAllPinned;
    use qsh_core::config::{Config, ServeConfig};
    use qsh_core::localctl::frame::LocalConduit;
    use qsh_core::{Paths, Principal};
    use qsh_proto::ErrorCode;
    use qsh_proto::local::{
        LOCAL_HELLO_VERSION, LocalHello, LocalResponse, LocalStreamKind, local_response,
    };
    use qsh_proto::wire::{self, control_message, response};
    use qsh_testkit::loopback::{TestIdentity, make_identity};
    use qsh_testkit::reverse::{ReverseHarness, wait_for};
    use qsh_transport::StaticTrust;
    use tokio::net::UnixStream;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
        StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
    }

    /// Fresh, throwaway [`Paths`] — only `runtime_dir()` (what
    /// `ReverseHarness::attach_localctl` binds its socket under) matters
    /// here; this is the controller's own localctl scratch space, unrelated
    /// to the target's on-disk trust/acl (`ReverseHarness::run_target_*`
    /// builds those itself).
    fn fresh_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        (dir, paths)
    }

    async fn connect_control(socket_path: &Path, host: &str) -> LocalConduit<UnixStream> {
        let stream = UnixStream::connect(socket_path)
            .await
            .expect("connect localctl socket");
        let mut conduit = LocalConduit::new(stream);
        conduit
            .send(&LocalHello {
                version: LOCAL_HELLO_VERSION,
                kind: LocalStreamKind::LocalControl as i32,
                host: host.to_string(),
                wait_ms: 0,
                known_generation: None,
            })
            .await
            .expect("send LocalHello");
        let ack: LocalResponse = conduit
            .recv()
            .await
            .expect("recv LocalHelloAck")
            .expect("conduit stayed open for the ack");
        match ack.body {
            Some(local_response::Body::HelloAck(_)) => {}
            other => panic!("expected LocalHelloAck, got {other:?}"),
        }
        conduit
    }

    async fn send(
        conduit: &mut LocalConduit<UnixStream>,
        request_id: u64,
        body: control_message::Body,
    ) {
        conduit
            .send(&wire::ControlMessage::new(request_id, body))
            .await
            .expect("send ControlMessage");
    }

    async fn recv(conduit: &mut LocalConduit<UnixStream>) -> wire::ControlMessage {
        conduit
            .recv()
            .await
            .expect("recv ControlMessage")
            .expect("conduit stayed open")
    }

    fn open_session() -> wire::SessionOpen {
        wire::SessionOpen {
            argv: vec!["sh".to_string()],
            env: Default::default(),
            term: String::new(),
            cols: 0,
            rows: 0,
            user: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reverse_target_enforces_the_same_session_quota() {
        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget"))
                .await;
        let (_dir, paths) = fresh_paths();
        let localctl = harness.attach_localctl(&paths).await;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let config = Config {
            serve: ServeConfig {
                max_sessions: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let run_fut = harness.run_target_with_config(
            &target,
            "device-id",
            "controller",
            None,
            &config,
            async {
                let _ = shutdown_rx.await;
            },
        );

        let test_fut = async {
            wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

            let mut ctl = connect_control(&localctl.socket_path, "widget").await;
            send(
                &mut ctl,
                1,
                control_message::Body::SessionOpen(open_session()),
            )
            .await;
            let opened = recv(&mut ctl).await;
            assert!(
                matches!(
                    &opened.body,
                    Some(control_message::Body::Response(wire::Response {
                        body: Some(response::Body::SessionOpened(_)),
                        ..
                    }))
                ),
                "the first open must succeed, got {:?}",
                opened.body
            );

            send(
                &mut ctl,
                2,
                control_message::Body::SessionOpen(open_session()),
            )
            .await;
            let refused = recv(&mut ctl).await;
            match refused.body {
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::Error(err)),
                    ..
                })) => {
                    assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
                    assert!(err.retryable);
                }
                other => panic!("expected a RESOURCE_EXHAUSTED error response, got {other:?}"),
            }

            let _ = shutdown_tx.send(());
        };

        let (result, ()) = tokio::join!(run_fut, test_fut);
        result.expect("run_target_with_config must exit cleanly on shutdown");
        localctl.shutdown().await;
        harness.shutdown().await;
    }

    /// A4/B3 (M8 Step 3a fix round): the reverse target's exec quota is
    /// the identical `[serve]`-config-driven wiring the session quota
    /// above pins — `max_exec_per_principal` must reach `host_runtime`
    /// through the same `QuotaLimits::from_serve` call, not just
    /// `max_sessions`/`max_sessions_per_principal`. One held exec ticket
    /// saturates a cap of 1 (a permit is taken at ticket *issue*, this
    /// file's forward-host `exec_run_past_the_quota_...` test), so the
    /// second `exec.run` over the same `LOCAL_CONTROL` conduit must be
    /// refused before any child ever spawns.
    #[tokio::test(flavor = "multi_thread")]
    async fn reverse_target_enforces_the_same_exec_quota() {
        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget"))
                .await;
        let (_dir, paths) = fresh_paths();
        let localctl = harness.attach_localctl(&paths).await;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let config = Config {
            serve: ServeConfig {
                max_exec_per_principal: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let run_fut = harness.run_target_with_config(
            &target,
            "device-id",
            "controller",
            None,
            &config,
            async {
                let _ = shutdown_rx.await;
            },
        );

        let test_fut = async {
            wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

            let mut ctl = connect_control(&localctl.socket_path, "widget").await;
            send(
                &mut ctl,
                1,
                control_message::Body::ExecStart(wire::ExecStart {
                    argv: vec!["cat".to_string()],
                    env: Default::default(),
                    timeout_ms: 0,
                }),
            )
            .await;
            let started = recv(&mut ctl).await;
            assert!(
                matches!(
                    &started.body,
                    Some(control_message::Body::Response(wire::Response {
                        body: Some(response::Body::ExecStarted(_)),
                        ..
                    }))
                ),
                "the first exec.run must succeed, got {:?}",
                started.body
            );

            send(
                &mut ctl,
                2,
                control_message::Body::ExecStart(wire::ExecStart {
                    argv: vec!["true".to_string()],
                    env: Default::default(),
                    timeout_ms: 0,
                }),
            )
            .await;
            let refused = recv(&mut ctl).await;
            match refused.body {
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::Error(err)),
                    ..
                })) => {
                    assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
                    assert!(err.retryable);
                }
                other => panic!("expected a RESOURCE_EXHAUSTED error response, got {other:?}"),
            }

            let _ = shutdown_tx.send(());
        };

        let (result, ()) = tokio::join!(run_fut, test_fut);
        result.expect("run_target_with_config must exit cleanly on shutdown");
        localctl.shutdown().await;
        harness.shutdown().await;
    }

    /// Proves the periodic quota-flush tick `reverse/target.rs`'s serve
    /// loop now runs (`PLAN.md` M8 Step 3a S2 deviation 2), not just the
    /// lazy on-next-rejection flush `crate::quota::Quotas` also has: a
    /// burst of refusals opens the aggregation window, and — with no
    /// further rejection ever sent — the summary record still lands in
    /// the target's own audit log once the window goes stale. If the tick
    /// regressed to a no-op, this test would hang until `TIMEOUT` (the
    /// summary would never arrive without a later rejection to trigger the
    /// lazy path this scenario deliberately never sends).
    #[tokio::test(flavor = "multi_thread")]
    async fn reverse_target_flushes_the_per_principal_summary_on_the_periodic_tick() {
        use std::path::PathBuf;

        use qsh_core::audit::AuditRecord;

        /// Mirrors the top-level `quota.rs`'s own copy of `qsh_core::
        /// quota`'s private `AUDIT_AGGREGATION_WINDOW` (10s) — restated
        /// here because `mod reverse_target_quota` cannot see the outer
        /// file's `const` (it is not `pub` and modules don't inherit
        /// items from their parent file scope).
        const AUDIT_AGGREGATION_WINDOW: Duration = Duration::from_secs(10);
        const REJECTIONS: usize = 3;
        /// Same tick-boundary reasoning `admission.rs`'s
        /// `admission_on_exit_flush_reports_suppressed_rejections_at_shutdown`
        /// works out in detail: `target.rs`'s `quota_flush` interval is
        /// created the moment this connection's serve loop starts (right
        /// after registration succeeds), and ticks every
        /// `AUDIT_AGGREGATION_WINDOW` after that (`t0`, `t0+10`, `t0+20`,
        /// …). Opening the window at `t0+ε` would put its staleness point
        /// (`t0+ε+10`) a hair past the second tick's own nominal `t0+10`
        /// firing — decided by scheduling jitter, not by anything this
        /// test is trying to prove. Waiting this long after registration
        /// before sending the first rejection opens the window at `t0+4`
        /// instead: the second tick (`t0+10`) sees it only 6s old and
        /// skips it, so only the *third* tick (`t0+20`) can be the one
        /// that flushes it — the thing this test is actually asserting.
        const WINDOW_OPEN_DELAY: Duration = Duration::from_secs(4);

        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget"))
                .await;
        let (_dir, paths) = fresh_paths();
        let localctl = harness.attach_localctl(&paths).await;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (audit_path_tx, audit_path_rx) = tokio::sync::oneshot::channel::<PathBuf>();
        let config = Config {
            serve: ServeConfig {
                max_sessions_per_principal: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let run_fut = harness.run_target_with_config_observing_runtime(
            &target,
            "device-id",
            "controller",
            None,
            &config,
            move |runtime| {
                let _ = audit_path_tx.send(runtime.audit.path().to_path_buf());
            },
            async {
                let _ = shutdown_rx.await;
            },
        );

        let test_fut = async {
            let audit_path = audit_path_rx
                .await
                .expect("run_target hands back the audit path");
            wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

            let mut ctl = connect_control(&localctl.socket_path, "widget").await;
            send(
                &mut ctl,
                1,
                control_message::Body::SessionOpen(open_session()),
            )
            .await;
            let opened = recv(&mut ctl).await;
            assert!(
                matches!(
                    &opened.body,
                    Some(control_message::Body::Response(wire::Response {
                        body: Some(response::Body::SessionOpened(_)),
                        ..
                    }))
                ),
                "the first open must succeed, got {:?}",
                opened.body
            );

            // See `WINDOW_OPEN_DELAY`'s own doc: a wide, non-marginal gap
            // from the serve loop's own start before the window even
            // opens, so the second periodic tick (~t0+10) is nowhere near
            // this window's own staleness point (~t0+14) and only the
            // third tick (~t0+20) can be the one that flushes it.
            tokio::time::sleep(WINDOW_OPEN_DELAY).await;

            for i in 0..REJECTIONS {
                send(
                    &mut ctl,
                    2 + i as u64,
                    control_message::Body::SessionOpen(open_session()),
                )
                .await;
                let refused = recv(&mut ctl).await;
                match refused.body {
                    Some(control_message::Body::Response(wire::Response {
                        body: Some(response::Body::Error(err)),
                        ..
                    })) => {
                        assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
                        assert!(err.retryable);
                    }
                    other => panic!("expected a RESOURCE_EXHAUSTED error response, got {other:?}"),
                }
            }

            // Deliberately no further request from here on — the summary
            // this test asserts on can only reach the sink through the
            // periodic tick, never through a later rejection's lazy flush.
            // Bound generously past the third tick (~t0+20, i.e. ~16s from
            // the window opening at ~t0+4 above) rather than just past
            // staleness (~t0+14): the second tick at ~t0+10 is a genuine
            // no-op here (by design, per `WINDOW_OPEN_DELAY`'s doc), so the
            // wait has to clear it too, not just the staleness point.
            let records = wait_for(2 * AUDIT_AGGREGATION_WINDOW, || {
                let text = std::fs::read_to_string(&audit_path).ok()?;
                let records: Vec<AuditRecord> = text
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
                records
                    .iter()
                    .any(|r| r.resource == "quota_sessions_principal" && r.count.is_some())
                    .then_some(records)
            })
            .await;

            let summary = records
                .iter()
                .find(|r| r.resource == "quota_sessions_principal" && r.count.is_some())
                .unwrap_or_else(|| {
                    panic!("expected a quota_sessions_principal summary, got {records:?}")
                });
            assert_eq!(
                summary.count,
                Some((REJECTIONS - 1) as u32),
                "the first rejection was reported immediately; the summary covers the rest"
            );

            let _ = shutdown_tx.send(());
        };

        let (result, ()) = tokio::join!(run_fut, test_fut);
        result.expect("run_target_with_config_observing_runtime must exit cleanly on shutdown");
        localctl.shutdown().await;
        harness.shutdown().await;
    }

    /// B5 (M8 Step 3a fix-3 sweep): `target.rs`'s serve loop's `_ = &mut
    /// shutdown =>` arm must reach `Server::purge_connection` (and, with
    /// it, `quota_housekeeping`) before it returns, exactly like the
    /// loop's other two exit arms (`watch.dead()`, the `serve_control`
    /// join) already do by falling through past `'serve:`. Same setup as
    /// `reverse_target_flushes_the_per_principal_summary_on_the_periodic_tick`
    /// above, including the same `WINDOW_OPEN_DELAY` margin — the window
    /// must actually be past its own staleness bound before *any* flush
    /// site (tick or shutdown) is willing to close it
    /// (`crate::quota::Quotas::flush_expired` only ever closes windows
    /// already `AUDIT_AGGREGATION_WINDOW` old; shutdown does not force a
    /// fresh window closed early) — but unlike that test, shutdown fires
    /// as soon as the window crosses staleness, comfortably before the
    /// loop's own *next* periodic tick (`quota_flush`, ~t0+20) would have
    /// reached it anyway, so only the shutdown arm's own purge can be
    /// what produces the summary this test asserts on, within its
    /// bounded poll. If that purge call regressed to a no-op (or ran
    /// before `serve_control`'s join, before this connection's
    /// rejections are even recorded), the summary would never arrive —
    /// this loop never reaches its periodic tick again once `shutdown`
    /// resolves.
    #[tokio::test(flavor = "multi_thread")]
    async fn reverse_target_flushes_the_per_principal_summary_when_shutdown_lands_inside_the_window()
     {
        use std::path::PathBuf;

        use qsh_core::audit::AuditRecord;

        /// Mirrors the top-level `quota.rs`'s own copy of `qsh_core::
        /// quota`'s private `AUDIT_AGGREGATION_WINDOW` (10s) — same
        /// reason `reverse_target_flushes_the_per_principal_summary_on_the_periodic_tick`
        /// above restates it (this module cannot see the outer file's
        /// `const`).
        const AUDIT_AGGREGATION_WINDOW: Duration = Duration::from_secs(10);
        const REJECTIONS: usize = 3;
        /// Same reasoning as the periodic-tick test's own
        /// `WINDOW_OPEN_DELAY`: a wide gap from serve-loop start before
        /// the window even opens, so the staleness point this test waits
        /// for (below) lands nowhere near a tick boundary either.
        const WINDOW_OPEN_DELAY: Duration = Duration::from_secs(4);

        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget"))
                .await;
        let (_dir, paths) = fresh_paths();
        let localctl = harness.attach_localctl(&paths).await;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (audit_path_tx, audit_path_rx) = tokio::sync::oneshot::channel::<PathBuf>();
        let config = Config {
            serve: ServeConfig {
                max_sessions_per_principal: Some(1),
                // Near-instant drain (default is 5s): the still-open
                // session from below must not delay `drain()` — and, with
                // it, the shutdown arm's `purge_connection` call this
                // test is actually pinning — long enough to race the
                // bounded poll below against `run_target`'s own on-return
                // cleanup of its scratch `Paths` (which is what actually
                // removes the audit log's directory once this function
                // returns, not anything to do with quota).
                close_grace_ms: Some(10),
                ..Default::default()
            },
            ..Default::default()
        };
        let run_fut = harness.run_target_with_config_observing_runtime(
            &target,
            "device-id",
            "controller",
            None,
            &config,
            move |runtime| {
                let _ = audit_path_tx.send(runtime.audit.path().to_path_buf());
            },
            async {
                let _ = shutdown_rx.await;
            },
        );

        let test_fut = async {
            let audit_path = audit_path_rx
                .await
                .expect("run_target hands back the audit path");
            wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

            let mut ctl = connect_control(&localctl.socket_path, "widget").await;
            send(
                &mut ctl,
                1,
                control_message::Body::SessionOpen(open_session()),
            )
            .await;
            let opened = recv(&mut ctl).await;
            assert!(
                matches!(
                    &opened.body,
                    Some(control_message::Body::Response(wire::Response {
                        body: Some(response::Body::SessionOpened(_)),
                        ..
                    }))
                ),
                "the first open must succeed, got {:?}",
                opened.body
            );

            tokio::time::sleep(WINDOW_OPEN_DELAY).await;

            for i in 0..REJECTIONS {
                send(
                    &mut ctl,
                    2 + i as u64,
                    control_message::Body::SessionOpen(open_session()),
                )
                .await;
                let refused = recv(&mut ctl).await;
                match refused.body {
                    Some(control_message::Body::Response(wire::Response {
                        body: Some(response::Body::Error(err)),
                        ..
                    })) => {
                        assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
                        assert!(err.retryable);
                    }
                    other => panic!("expected a RESOURCE_EXHAUSTED error response, got {other:?}"),
                }
            }

            // Past the window's own staleness bound (opened at ~t0+4,
            // stale at ~t0+14), landing at ~t0+15.5 — well before the
            // next periodic tick at ~t0+20, so shutdown's own purge is
            // the only thing that can produce the summary from here.
            tokio::time::sleep(AUDIT_AGGREGATION_WINDOW + Duration::from_millis(1500)).await;
            let _ = shutdown_tx.send(());

            // Bounded at 3s, not 20s (this loop's own next periodic tick).
            // `close_grace_ms` above keeps `drain()` from delaying
            // `purge_connection`'s own flush by the still-open session's
            // default 5s grace; `ReverseHarness::run_target_via`'s own
            // post-run pause (`crates/qsh-testkit/src/reverse.rs`) is what
            // keeps the write from losing a race against this same
            // future's on-return cleanup of its scratch `Paths`.
            let records = wait_for(Duration::from_secs(3), || {
                let text = std::fs::read_to_string(&audit_path).ok()?;
                let records: Vec<AuditRecord> = text
                    .lines()
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
                records
                    .iter()
                    .any(|r| r.resource == "quota_sessions_principal" && r.count.is_some())
                    .then_some(records)
            })
            .await;

            let summary = records
                .iter()
                .find(|r| r.resource == "quota_sessions_principal" && r.count.is_some())
                .unwrap_or_else(|| {
                    panic!("expected a quota_sessions_principal summary, got {records:?}")
                });
            assert_eq!(
                summary.count,
                Some((REJECTIONS - 1) as u32),
                "the first rejection was reported immediately; the summary covers the rest"
            );
        };

        let (result, ()) = tokio::join!(run_fut, test_fut);
        result.expect("run_target_with_config_observing_runtime must exit cleanly on shutdown");
        localctl.shutdown().await;
        harness.shutdown().await;
    }

    /// A5/B8 (M8 Step 3a fix-3 sweep) — `purge_connection`'s twin to the
    /// shutdown-arm test above: the connection dies (closed outright,
    /// same as `Rig::shutdown`'s `conn.connection.close(..)` in
    /// `reverse_attach.rs`/`reverse_session_ops.rs`) while the host
    /// itself stays up — nothing here ever resolves a `shutdown` future,
    /// so this pins `Server::purge_connection`'s *own*
    /// `quota_housekeeping()` call (added by A9, called unconditionally
    /// today, not the new B5 fallthrough this file's shutdown-lands-
    /// inside-the-window test above pins) directly. Built by hand — the
    /// same `Server`/`Broker`/`MemoryAuditSink` shape
    /// `reverse_attach.rs`'s `Rig` uses — rather than through
    /// `ReverseHarness::run_target_with_config_observing_runtime`,
    /// specifically so the audit sink is in-memory: unlike the on-disk
    /// `RotatingAuditSink` a full target process owns, nothing here ever
    /// tears down a scratch directory out from under the write, so the
    /// bounded poll below only has to win against the flush itself, not
    /// against unrelated cleanup. If `quota_housekeeping()`'s call inside
    /// `purge_connection` regressed to a no-op, this loop's own periodic
    /// tick never runs either (nothing here builds one — this is not
    /// `reverse::target`'s reconnect loop), so the summary would never
    /// arrive at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn reverse_target_purge_connection_flushes_the_summary_when_the_connection_dies_with_the_host_still_up()
     {
        use qsh_core::audit::MemoryAuditSink;
        use qsh_core::broker::{Broker, BrokerConfig, PeerFingerprint, PipeFactory, SystemClock};
        use qsh_core::handshake;
        use qsh_core::server::{ConnCtx, Server};
        use qsh_transport::Dialed;

        const AUDIT_AGGREGATION_WINDOW: Duration = Duration::from_secs(10);
        const REJECTIONS: usize = 3;
        /// Same reasoning as the other two tests' own `WINDOW_OPEN_DELAY`.
        const WINDOW_OPEN_DELAY: Duration = Duration::from_secs(4);

        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget"))
                .await;

        let (dialed, ctl, peer_hello) = harness
            .register(&target, "widget")
            .await
            .expect("target registers with controller");
        let Dialed {
            connection: conn, ..
        } = dialed;
        let ctx = ConnCtx {
            principal: conn.principal().clone(),
            auth_path: conn.auth_path(),
            peer_fingerprint: conn
                .peer_fingerprint()
                .map(|fp| PeerFingerprint::new(*fp.as_bytes())),
            peer_addr: conn.remote_address(),
            conn_id: conn.stable_id(),
            capabilities: handshake::negotiated_capabilities(&peer_hello),
            is_reverse_registration: true,
        };
        let conn_id = ctx.conn_id;

        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(SystemClock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: qsh_core::quota::QuotaLimits {
                    max_sessions_per_principal: 1,
                    ..qsh_core::quota::QuotaLimits::default()
                },
            },
            pipes,
        );
        tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(Arc::new(AllowAllPinned), audit.clone(), broker, "target");

        let serve_task = tokio::spawn({
            let server = server.clone();
            let conn = conn.clone();
            async move {
                let _ = server.clone().serve_control(&conn, ctl, ctx, None).await;
                // The connection is gone one way or another (below, this
                // test closes it outright) — same pairing
                // `reverse_attach.rs`'s `register_reverse` spawned task
                // uses, which is what actually runs the
                // `quota_housekeeping()` call this test pins.
                server.purge_connection(conn_id).await;
            }
        });

        let (_dir, paths) = fresh_paths();
        let localctl = harness.attach_localctl(&paths).await;
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let mut client = connect_control(&localctl.socket_path, "widget").await;
        send(
            &mut client,
            1,
            control_message::Body::SessionOpen(open_session()),
        )
        .await;
        let opened = recv(&mut client).await;
        assert!(
            matches!(
                &opened.body,
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::SessionOpened(_)),
                    ..
                }))
            ),
            "the first open must succeed, got {:?}",
            opened.body
        );

        tokio::time::sleep(WINDOW_OPEN_DELAY).await;

        for i in 0..REJECTIONS {
            send(
                &mut client,
                2 + i as u64,
                control_message::Body::SessionOpen(open_session()),
            )
            .await;
            let refused = recv(&mut client).await;
            match refused.body {
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::Error(err)),
                    ..
                })) => {
                    assert_eq!(err.error_code(), ErrorCode::ResourceExhausted);
                    assert!(err.retryable);
                }
                other => panic!("expected a RESOURCE_EXHAUSTED error response, got {other:?}"),
            }
        }

        // Past the window's own staleness bound, well before any tick
        // this test never builds anyway (module docs above) — closing
        // the connection now is the only thing that can flush it.
        tokio::time::sleep(AUDIT_AGGREGATION_WINDOW + Duration::from_millis(1500)).await;
        conn.close(0, b"client done");

        // Bounded at 3s, not 20s: `MemoryAuditSink` is in-process, so
        // this only has to win against `purge_connection`'s own flush,
        // not against any teardown of on-disk state.
        let records = wait_for(Duration::from_secs(3), || {
            let recs = audit.records();
            recs.iter()
                .any(|r| r.resource == "quota_sessions_principal" && r.count.is_some())
                .then_some(recs)
        })
        .await;

        let summary = records
            .iter()
            .find(|r| r.resource == "quota_sessions_principal" && r.count.is_some())
            .unwrap_or_else(|| {
                panic!("expected a quota_sessions_principal summary, got {records:?}")
            });
        assert_eq!(
            summary.count,
            Some((REJECTIONS - 1) as u32),
            "the first rejection was reported immediately; the summary covers the rest"
        );

        localctl.shutdown().await;
        let _ = serve_task.await;
        harness.shutdown().await;
    }
}
