//! L3 loopback end-to-end for reverse mode (`docs/design/protocol.md` §11,
//! `docs/CLI.md` §6.13, `PLAN.md` M3 Step 3, PR 3b): a real `qsh listen`
//! controller (`qsh_core::reverse::listen::Listen`) accepting real QUIC
//! dial-ins from `qsh reverse` targets, over `qsh_testkit::reverse`'s
//! [`ReverseHarness`].
//!
//! Every negative/deny/conflict-path test asserts the actual reply *frame*
//! the peer received (`HelloError::Remote{code, ..}`), never just a
//! `Result::is_err()` — that is the whole point of the rejection
//! error-frame delivery fix this PR carries (`PLAN.md` Step 3, "거부 error
//! frame의 전달 보장"; `crate::handshake::REJECTION_DRAIN_TIMEOUT`).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use qsh_core::acl::{AllowAllPinned, DenyAll};
use qsh_core::client::{ClientError, ControlIn, Session};
use qsh_core::handshake::{self, HelloError};
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, ControlMessage, control_message, response};
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::reverse::{
    ReverseHarness, forward_hello, reverse_hello, wait_for, wait_for_audit_records,
};
use qsh_transport::{DialError, Dialed, FramedStream, Principal, StaticTrust};

/// Bound on every "this must have already happened" wait in this file. A
/// real in-process QUIC round trip; a few seconds is generous slack, not a
/// budget anyone should ever need in full.
const TIMEOUT: Duration = Duration::from_secs(5);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// [`Result::expect_err`] needs `T: Debug`, and the success type here
/// (`(Dialed, FramedStream, Hello)`) is not — `FramedStream` deliberately
/// isn't (it owns live QUIC stream halves). This is the same shape check
/// without that bound.
fn expect_hello_err(
    result: Result<(Dialed, FramedStream, wire::Hello), HelloError>,
    msg: &str,
) -> HelloError {
    match result {
        Ok(_) => panic!("{msg}"),
        Err(err) => err,
    }
}

fn remote(err: HelloError) -> (ErrorCode, String, bool) {
    match err {
        HelloError::Remote {
            code,
            message,
            retryable,
        } => (code, message, retryable),
        other => panic!("expected a remote error frame, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `qsh::reverse` stderr diagnostic capture (mirrors
// `qsh-cli/tests/attach_recovery.rs`'s `qsh::recovery` capture — a
// process-wide sink, since nextest's per-test process isolation is what
// makes a global subscriber safe here, and the `fingerprint` filter below is
// belt-and-suspenders for a plain non-nextest `cargo test` run where several
// of this file's tests could share one process).
// ---------------------------------------------------------------------------

fn reverse_lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

struct CaptureLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != qsh_core::reverse::listen::TARGET {
            return;
        }
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        if !line.is_empty() {
            reverse_lines()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line);
        }
    }
}

struct MessageOnly<'a>(&'a mut String);

impl tracing::field::Visit for MessageOnly<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

fn capture_reverse_events() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(CaptureLayer)
            .try_init()
            .ok();
    });
}

/// Every captured `qsh::reverse` JSON line whose `fingerprint` field is
/// `fp`, oldest first — the per-test disambiguator (module docs).
fn reverse_events_for(fp: &str) -> Vec<serde_json::Value> {
    reverse_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v["fingerprint"] == fp)
        .collect()
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

/// A pinned target dials, registers under its trust-store alias (never the
/// `offered_name` it sent — name-squatting prevention), and the registry
/// shows it live at generation 0. The controller's `qsh::reverse` stderr
/// diagnostic (`docs/CLI.md` §6.13) reports the same event as a one-line
/// JSON `registered` record.
#[tokio::test(flavor = "multi_thread")]
async fn registers_and_shows_live_with_a_registered_stderr_event() {
    capture_reverse_events();
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    let (dialed, _ctl, peer_hello) = harness
        .register(&target, "attacker-chosen-name")
        .await
        .unwrap_or_else(|err| panic!("registration should succeed: {err:?}"));
    assert!(
        peer_hello.reverse.is_none(),
        "controller's own Hello never registers itself"
    );

    let entry = wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
    assert_eq!(
        entry.name, "widget",
        "trust-store alias wins over offered_name"
    );
    assert_eq!(entry.generation, 0);
    assert_eq!(entry.fingerprint, target.fingerprint.to_string());
    assert_eq!(entry.state, qsh_testkit::reverse::EntryState::Live);
    // Bounded wait, not a bare read: the registry entry (written inside
    // `admit`, before the `Hello` reply is even sent) and the live-
    // connection table (written by `finish_registration`, only *after*
    // `handshake::respond` finishes flushing that reply) are populated by
    // two different points in the server task's sequence, while `register`
    // above only guarantees the *client* has received the reply — nothing
    // orders that against the server task continuing on to
    // `finish_registration`. An unsynchronized read here raced the two
    // (harness race-hygiene review finding).
    wait_for(TIMEOUT, || {
        (harness.listen.live_connections() == 1).then_some(())
    })
    .await;

    let fp = target.fingerprint.to_string();
    let events = wait_for(TIMEOUT, || {
        let v = reverse_events_for(&fp);
        (!v.is_empty()).then_some(v)
    })
    .await;
    assert_eq!(events[0]["event"], "registered");
    assert_eq!(events[0]["host"], "widget");
    assert_eq!(events[0]["generation"], 0);

    drop(dialed);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// negative path ① — forward `qsh serve` receiving `Hello.reverse`
// ---------------------------------------------------------------------------

/// `docs/design/protocol.md` §11 header's symmetric principle makes this an
/// input a forward host can really receive: a peer that sends
/// `Hello.reverse` to an ordinary `qsh serve` host. It answers
/// `UNSUPPORTED` and registers nothing — there is no registry on a forward
/// host at all, so "registers nothing" is really "the connection never
/// reaches `serve_control`".
#[tokio::test(flavor = "multi_thread")]
async fn forward_serve_rejects_hello_reverse() {
    let host = LoopbackHarness::start().await;
    let dialed = host.dial().await;
    let err = match handshake::initiate(&dialed.connection, reverse_hello("anything")).await {
        Ok(_) => panic!("a forward host must refuse Hello.reverse"),
        Err(err) => err,
    };
    let (code, message, _retryable) = remote(err);
    assert_eq!(code, ErrorCode::Unsupported);
    assert!(message.contains("reverse"), "message: {message:?}");
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// negative path ② — `qsh listen` receiving a peer with no `Hello.reverse`
// ---------------------------------------------------------------------------

/// A peer without `Hello.reverse` dialing `qsh listen` is refused
/// `UNSUPPORTED` before the `host.reverse` choke point ever runs — zero
/// resources, zero audit (`docs/design/protocol.md` §11-2: "not an ACL
/// decision").
#[tokio::test(flavor = "multi_thread")]
async fn listen_rejects_a_peer_without_hello_reverse() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    let err = expect_hello_err(
        harness.initiate(&target, forward_hello()).await,
        "qsh listen must refuse a peer with no Hello.reverse",
    );
    let (code, message, _retryable) = remote(err);
    assert_eq!(code, ErrorCode::Unsupported);
    assert!(
        message.contains("reverse registrations"),
        "message: {message:?}"
    );

    assert!(harness.listen.registry().snapshot().is_empty());
    assert_eq!(harness.listen.live_connections(), 0);
    assert!(
        harness.audit.records().is_empty(),
        "absent Hello.reverse is not an ACL decision — zero audit lines"
    );
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// deny path
// ---------------------------------------------------------------------------

/// `DenyAll`: the `host.reverse` choke point denies a fully authenticated,
/// correctly-aliased target. The target receives `PERMISSION_DENIED` as a
/// real remote error frame; the registry stays empty, the controller keeps
/// no connection-table entry for it, and — since a controller has no
/// broker of its own (`docs/design/protocol.md` §11-3) — there is no ticket
/// or session anywhere to have created either. This is the integration
/// counterpart `admit.rs`'s own
/// `deny_all_creates_nothing_and_audits_the_denial` test explicitly leaves
/// owed to this file (its comment names the connection/ticket thirds of
/// this row).
#[tokio::test(flavor = "multi_thread")]
async fn deny_all_creates_no_registry_entry_no_connection_and_no_session() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(DenyAll), false, pin(&target, "widget")).await;

    let err = expect_hello_err(
        harness.register(&target, "").await,
        "DenyAll denies everything",
    );
    let (code, _message, retryable) = remote(err);
    assert_eq!(code, ErrorCode::PermissionDenied);
    assert!(!retryable);

    assert!(
        harness.listen.registry().snapshot().is_empty(),
        "no registry entry"
    );
    assert_eq!(
        harness.listen.live_connections(),
        0,
        "no connection-table entry"
    );

    let records = wait_for_audit_records(&harness.audit, 1, TIMEOUT).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].action, "host.reverse");
    assert_eq!(records[0].decision, "deny");
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// conflict path
// ---------------------------------------------------------------------------

/// Two different fingerprints pinned under the *same* trust-store alias
/// (an operator mistake, or two devices sharing a name) — the second
/// registration is refused `INVALID_ARGUMENT` (no silent overwrite) and the
/// first entry is completely untouched.
#[tokio::test(flavor = "multi_thread")]
async fn conflicting_fingerprint_under_a_live_name_is_invalid_argument() {
    let first = make_identity();
    let second = make_identity();
    let trust = StaticTrust::empty()
        .with_pin(first.fingerprint, Principal::Device("shared".into()))
        .with_pin(second.fingerprint, Principal::Device("shared".into()));
    let harness = ReverseHarness::start_with(Arc::new(AllowAllPinned), false, trust).await;

    let (dialed1, _ctl1, _hello1) = harness.register(&first, "").await.expect("first registers");
    wait_for(TIMEOUT, || harness.listen.registry().get("shared")).await;

    let err = expect_hello_err(
        harness.register(&second, "").await,
        "a different fingerprint under a live name is a conflict",
    );
    let (code, _message, _retryable) = remote(err);
    assert_eq!(code, ErrorCode::InvalidArgument);

    let entry = harness
        .listen
        .registry()
        .get("shared")
        .expect("original entry remains");
    assert_eq!(entry.fingerprint, first.fingerprint.to_string());
    assert_eq!(entry.generation, 0);
    assert_eq!(
        harness.listen.live_connections(),
        1,
        "only the first connection is live"
    );

    drop(dialed1);
    harness.shutdown().await;
}

/// The *same* fingerprint re-dialing under a live name (the NAT-rebind
/// reconnect path) replaces the entry, advances `generation`, and the
/// controller actually closes the superseded connection — not just drops
/// its registry row.
#[tokio::test(flavor = "multi_thread")]
async fn same_fingerprint_redial_replaces_and_closes_the_old_connection() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "shared")).await;

    let (dialed1, _ctl1, _hello1) = harness
        .register(&target, "")
        .await
        .expect("first registers");
    let first_entry = wait_for(TIMEOUT, || harness.listen.registry().get("shared")).await;
    assert_eq!(first_entry.generation, 0);

    let (dialed2, _ctl2, _hello2) = harness
        .register(&target, "")
        .await
        .expect("same fingerprint reconnect replaces");
    let second_entry = wait_for(TIMEOUT, || {
        let e = harness.listen.registry().get("shared")?;
        (e.generation == 1).then_some(e)
    })
    .await;
    assert_eq!(second_entry.fingerprint, target.fingerprint.to_string());
    assert_eq!(
        harness.listen.registry().snapshot().len(),
        1,
        "replaced, not duplicated"
    );

    // The superseded connection is actually torn down, not merely
    // forgotten by the registry — `reverse/listen.rs`'s
    // `CLOSE_CODE_REPLACED` (`0x1003` = 4099, private to that module, so
    // this only checks that *some* application close with that code
    // reached the peer rather than importing the constant).
    let reason = tokio::time::timeout(TIMEOUT, dialed1.connection.closed())
        .await
        .unwrap_or_else(|_| panic!("old connection was not closed within {TIMEOUT:?}"));
    assert!(
        format!("{reason:?}").contains("4099"),
        "expected the replaced-registration close code, got {reason:?}"
    );

    drop(dialed2);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// controller role discipline
// ---------------------------------------------------------------------------

/// Over an established reverse connection the controller is CLIENT role
/// (`docs/design/protocol.md` §11-3): it answers a peer `Ping` but refuses
/// every request-shaped frame with `UNSUPPORTED`, creating nothing. Nothing
/// in Step 3's product code makes a real `qsh reverse` process actually
/// send a request *to* its controller — that is wire-legal but has no
/// producer yet — so this test holds the pen itself, building a
/// [`Session`] straight on the registered connection.
#[tokio::test(flavor = "multi_thread")]
async fn controller_refuses_session_open_but_answers_ping() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    let (dialed, ctl, peer_hello) = harness.register(&target, "").await.expect("registers");
    let mut session = Session::from_control(dialed.connection.clone(), ctl, peer_hello);

    let open = wire::SessionOpen {
        argv: vec!["sh".to_string()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    };
    let err = session
        .session_open(open)
        .await
        .expect_err("the controller must not open a session for the target");
    match err {
        ClientError::Remote { code, .. } => assert_eq!(code, ErrorCode::Unsupported),
        other => panic!("expected a remote UNSUPPORTED, got {other:?}"),
    }
    assert!(
        harness.listen.registry().get("widget").is_some(),
        "the refused SessionOpen must not have touched the registration itself"
    );

    session.send_ping().await.expect("send ping");
    let reply = tokio::time::timeout(TIMEOUT, session.next_control())
        .await
        .expect("pong arrives within the timeout")
        .expect("no stream error");
    assert_eq!(reply, Some(ControlIn::Pong));

    drop(dialed);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// `run_target` — the actual `qsh reverse` entry point end to end
// (`qsh_core::reverse::target::run_reverse`, via `ReverseHarness::run_target`
// — module docs: real on-disk `trust.toml`, real `host_runtime`). Every test
// above drives the wire by hand through `ReverseHarness::initiate`/
// `register`; nothing before this point ever calls `run_target` at all
// (adversarial review finding).
//
// `#[cfg(unix)]` on each test below, not on the file: `run_reverse` itself
// is gated `cfg(not(unix))` to return `ErrorCode::Unsupported` immediately
// on every non-unix target (`reverse/target.rs`'s Windows gate,
// `docs/CLI.md` §6.13) — so on Windows these three would still compile but
// observe the wrong error code/success shape (`Unsupported` instead of the
// specific outcome each test proves). That is exactly the class of failure
// `PLAN.md` M3 Step 3's Windows CI audit calls out, and per-test gating
// (not a whole-file `#![cfg(unix)]`) is the file's own established
// pattern — the rest of this file (registration/deny/conflict/role-
// discipline tests) drives the wire by hand and is genuinely platform
// neutral, exactly like `qsh-testkit/tests/exec_loopback.rs` gates only
// its PTY-signal-specific tests rather than the whole file.
// ---------------------------------------------------------------------------

/// A registration `admit` denies (`DenyAll`) surfaces out of the real
/// `run_reverse` as the same mapped `OpError` the CLI would report and
/// exit `255` on — proving `target.rs`'s
/// `map_client_error(map_hello_error(err))` chain (target.rs:95) actually
/// runs on this path, not just in a hand-built duplex test.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn run_target_maps_a_denied_registration_to_permission_denied() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(DenyAll), false, pin(&target, "widget")).await;

    let err = harness
        .run_target(
            &target,
            "device-id",
            "controller",
            None,
            std::future::pending::<()>(),
        )
        .await
        .expect_err("DenyAll must fail run_reverse");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(harness.listen.registry().snapshot().is_empty());
    harness.shutdown().await;
}

/// The happy path end to end: `run_target` resolves `controller` through a
/// real on-disk `trust.toml` (target.rs:71-72), dials, registers, and
/// serves the connection as a host (`ConnCtx` built at target.rs:106-115)
/// — proven here by the registration actually showing up in the
/// controller's registry — then exits `Ok(())` the moment `shutdown`
/// resolves, without waiting for the connection to die.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn run_target_registers_then_exits_cleanly_on_shutdown() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });
    let watch_fut = async {
        let entry = wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
        assert_eq!(entry.generation, 0);
        let _ = shutdown_tx.send(());
    };
    let (result, ()) = tokio::join!(run_fut, watch_fut);
    assert!(result.is_ok(), "a clean shutdown must exit Ok: {result:?}");

    harness.shutdown().await;
}

/// The connection dying out from under `run_target` — not a shutdown this
/// process asked for — is fatal to the process (`docs/CLI.md` §6.13: no
/// reconnect loop in this step). Forced here the same way a real
/// NAT-rebind reconnect would: a second dial from the identical
/// fingerprint, which the controller answers by replacing the registration
/// and closing the connection `run_target` is holding
/// (`CLOSE_CODE_REPLACED`) — proving `target.rs`'s `serve_control`-ended
/// select arm (target.rs:123-133) actually maps a real connection loss to
/// `ConnectionFailed`, not just a hand-rolled one.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn run_target_reports_connection_failed_when_the_controller_replaces_it() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    let run_fut = harness.run_target(
        &target,
        "device-id",
        "controller",
        None,
        std::future::pending::<()>(),
    );
    let replace_fut = async {
        wait_for(TIMEOUT, || {
            let e = harness.listen.registry().get("widget")?;
            (e.generation == 0).then_some(())
        })
        .await;
        let (dialed2, _ctl2, _hello2) = harness
            .register(&target, "")
            .await
            .expect("same-fingerprint reconnect replaces");
        dialed2
    };

    let (result, _dialed2) = tokio::join!(run_fut, replace_fut);
    let err = result.expect_err("the replaced connection must fail run_reverse");
    assert_eq!(err.code, ErrorCode::ConnectionFailed);

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// L1 matrix row — "reverse dial, untrusted target"
// (`PLAN.md` Step 3 (c): the handshake-matrix table itself
// (`crates/qsh-transport/tests/handshake_matrix.rs`) is deliberately
// transport-only — it cannot depend on `qsh-core`'s `AuditRecord` at all
// (`CLAUDE.md`'s dependency matrix: `qsh-transport` → `qsh-proto` only) —
// so the assertion this row actually needs (a handshake-level deny, never a
// `host.reverse` audit line) lives here instead, the one place both a real
// `Listen` controller and `qsh_core::audit` are available together. This
// test is what discharges PLAN's L1 row — `handshake_matrix.rs` carries a
// matching comment pointing back here, so the deviation is discoverable
// from either file.)
// ---------------------------------------------------------------------------

/// An unpinned/untrusted peer dialing `qsh listen` fails at the mTLS
/// handshake itself, strictly before any `Hello` — let alone a
/// `host.reverse` decision — is ever reached. The controller records this
/// as a connection-level handshake deny (`AuditRecord::handshake_rejected`:
/// `action == "connect"`, `principal == "-"`), never as a `host.reverse`
/// line.
#[tokio::test(flavor = "multi_thread")]
async fn reverse_dial_untrusted_target_fails_handshake_before_registration() {
    let trusted = make_identity();
    let untrusted = make_identity();
    // The controller trusts someone, just never `untrusted`.
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&trusted, "widget")).await;

    // The client's own handshake future can resolve to `Ok` before the
    // server's rejection close frame arrives (the server validates the
    // client's certificate strictly after its own 1-RTT keys are already
    // usable client-side) — so, exactly like
    // `handshake_matrix.rs::expect_remote_rejected`, either the dial fails
    // outright or it completes locally and the rejection only surfaces as
    // a crypto-class connection failure.
    match harness.dial(&untrusted).await {
        Err(DialError::RemoteRejected) => {}
        Ok(dialed) => {
            let err = dialed.connection.closed().await;
            assert!(
                qsh_transport::endpoint::is_crypto_failure(&err),
                "expected a crypto-class connection failure, got {err:?}"
            );
        }
        Err(other) => panic!("expected RemoteRejected (or Ok + crypto failure), got {other:?}"),
    }

    let records = wait_for_audit_records(&harness.audit, 1, TIMEOUT).await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].action, "connect",
        "a handshake deny, not host.reverse"
    );
    assert_eq!(
        records[0].principal, "-",
        "no principal was ever established"
    );
    assert_eq!(records[0].decision, "deny");
    assert!(
        !harness
            .audit
            .records()
            .iter()
            .any(|r| r.action == "host.reverse"),
        "registration is never reached for a peer that fails the handshake"
    );
    assert!(harness.listen.registry().snapshot().is_empty());
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Step 2 debt — raw-wire version mismatch reaches the initiator as a real
// remote error frame
// ---------------------------------------------------------------------------

/// `PLAN.md` Step 2 (c) left this L3-owed: a raw-QUIC initiator that
/// advertises a wire minor version the responder does not support must
/// actually *receive* the responder's `UNSUPPORTED` ("no common wire minor
/// version") as a remote error frame — not merely observe its own local
/// connection failing. Built directly on `qsh_transport::Connection` +
/// `qsh_transport::FramedStream` (the `qsh-proto` frame codec), bypassing
/// `qsh_core::handshake::initiate` entirely, so this genuinely exercises
/// the wire rather than the code path under test exercising itself.
#[tokio::test(flavor = "multi_thread")]
async fn raw_dial_with_unsupported_minor_version_receives_remote_unsupported() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    let dialed = harness.dial(&target).await.expect("mTLS succeeds");
    let (send, recv) = dialed
        .connection
        .open_bi()
        .await
        .expect("open control stream");
    let mut ctl = FramedStream::control(send, recv);
    ctl.send.set_priority(wire::PRIORITY_CONTROL);

    let bad_hello = wire::Hello {
        versions: vec![9_999], // no overlap with `wire::WIRE_MINOR_VERSIONS`
        device_name: "raw-probe".into(),
        capabilities: Vec::new(),
        reverse: Some(wire::ReverseRegistration {
            offered_name: String::new(),
            capabilities: Vec::new(),
        }),
    };
    ctl.send
        .send(&ControlMessage::new(
            0,
            control_message::Body::Hello(bad_hello),
        ))
        .await
        .expect("send raw Hello");

    let reply = tokio::time::timeout(TIMEOUT, ctl.recv.recv::<ControlMessage>())
        .await
        .expect("reply arrives within the timeout")
        .expect("no stream error")
        .expect("stream not closed before a reply");
    match reply.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::Error(e)),
        })) => {
            assert_eq!(e.error_code(), ErrorCode::Unsupported);
            assert_eq!(e.message, "no common wire minor version");
        }
        other => panic!("expected a Response{{Error}} frame, got {other:?}"),
    }

    assert!(harness.listen.registry().snapshot().is_empty());
    harness.shutdown().await;
}
