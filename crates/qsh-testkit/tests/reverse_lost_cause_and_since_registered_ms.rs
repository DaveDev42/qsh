//! End-to-end proof of issue #4 item 6 (`docs/CLI.md` §6.13 bullet at
//! :952): the `cause`/`at`/`since_registered_ms` fields on the reverse
//! mode `qsh::reverse` stderr diagnostic, driving the **real** reconnect
//! loop (`qsh_core::reverse::target::run_reverse` via
//! [`ReverseHarness::run_target_with_config`]/`run_target_through_chaos`)
//! for each cause variant that a real loop can actually reach —
//! `crates/qsh-core/src/reverse/target.rs`'s own unit test module covers
//! the two causes (`resolve`, and the full documented
//! `classify_dial_error`/`classify_hello_error`/
//! `classify_target_connection_loss` vocabulary including `local`) that a
//! real harness either cannot reach at all (no DNS to fail against a real
//! controller) or cannot reach *deterministically* (a local write failure
//! mid-serve).
//!
//! Mirrors `reverse_loopback.rs`'s own `qsh::reverse` stderr capture
//! (module docs there) rather than importing it — each test binary is its
//! own nextest process, so there is nothing to share, and a shared helper
//! crate would be the only alternative to duplicating this ~40 lines.

#![cfg(unix)]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use qsh_core::acl::{AllowAllPinned, DenyAll};
use qsh_core::config::{Config, ReverseConfig};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_testkit::{ChaosPolicy, ChaosProxy, TestIdentity, make_identity};
use qsh_transport::{Principal, StaticTrust};

/// Bound on every "this must have already happened" wait below. Generous
/// slack around a real, event-driven in-process/loopback scenario — never
/// a budget anyone should need in full (`docs/design/testing.md` L2).
const TIMEOUT: Duration = Duration::from_secs(10);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// A config-injected short `[reverse]` backoff, never the 500 ms/30 s
/// production defaults — the scenario's own bound is [`TIMEOUT`].
fn fast_backoff() -> Config {
    Config {
        reverse: ReverseConfig {
            backoff_initial_ms: Some(5),
            backoff_max_ms: Some(20),
            backoff_jitter_pct: Some(0),
            ..Default::default()
        },
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// `qsh::reverse` stderr diagnostic capture (mirrors `reverse_loopback.rs`'s
// own copy verbatim — see module docs on why this isn't shared).
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

/// Every captured `qsh::reverse` JSON line matching `host`/`event` exactly
/// — a target-side `ReconnectEvent`'s `host` is the controller alias this
/// test chose (unique per test, so no cross-test ambiguity even under a
/// plain non-nextest `cargo test` sharing one process).
fn events_by_host_and_kind(host: &str, event: &str) -> Vec<serde_json::Value> {
    reverse_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v["host"] == host && v["event"] == event)
        .collect()
}

/// Wait until the target's own `"registered"` line for `host` has been
/// captured — the target emits it only after `dial_and_register` returned,
/// i.e. after the controller's `Hello` reply actually reached it.
///
/// The controller's registry is not that signal: `Listen::register_connection`
/// (`reverse/listen/registration.rs`) admits into the registry *first* and
/// writes the `Hello` reply *second*, so a test that polls
/// `Listen::registry` and injects its fault the moment the entry appears
/// can land the fault inside that window. A sever there drops the reply on
/// the floor, the target is still parked inside `dial_and_register` with no
/// `PathWatch` running yet, and the `"lost"` line this file asserts on is
/// never emitted for that attempt — the failure surfaces as `retry` with a
/// dial-class cause instead. Observed once on CI (two arm runners, run
/// 35909383603) as a 10 s `wait_for` timeout on the `"lost"` line; never
/// reproduced on a fast host, where the reply lands microseconds after the
/// registry insert. Faults in this file are injected only after this
/// returns.
async fn wait_target_registered(host: &str) {
    wait_for(TIMEOUT, || {
        let v = events_by_host_and_kind(host, "registered");
        (!v.is_empty()).then_some(())
    })
    .await;
}

fn assert_at_is_rfc3339(v: &serde_json::Value) {
    let at = v["at"]
        .as_str()
        .unwrap_or_else(|| panic!("`at` must be a JSON string present on every record: {v}"));
    time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|err| panic!("`at` ({at}) must parse as RFC3339: {err}"));
}

// ---------------------------------------------------------------------------
// `registration_denied` — a real `Hello.reverse` the controller's own
// `host.reverse` choke point rejects, before any registration ever
// happened.
// ---------------------------------------------------------------------------

/// `DenyAll` refuses every registration attempt, so `run_target`'s `retry`
/// line for it never has a registration to report `since_registered_ms`
/// for, and never had a peer connection to name a `fingerprint` for
/// either — both keys must be **absent**, not `null` (issue #4 item 6's
/// own Tests requirement). `at` must be a real, freshly-generated RFC3339
/// timestamp, not a placeholder.
#[tokio::test(flavor = "multi_thread")]
async fn run_target_retry_line_reports_registration_denied_with_no_fingerprint_or_since_registered_ms()
 {
    capture_reverse_events();
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(DenyAll), false, pin(&target, "widget")).await;

    let config = fast_backoff();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target_with_config(
        &target,
        "device-id",
        "controller-cause-denied",
        None,
        &config,
        async {
            let _ = shutdown_rx.await;
        },
    );
    let watch_fut = async {
        let events = wait_for(TIMEOUT, || {
            let v = events_by_host_and_kind("controller-cause-denied", "retry");
            (!v.is_empty()).then_some(v)
        })
        .await;
        // The controller's own `denied` line for the same rejection — its
        // `host` is the target's offered name ("device-id", the
        // `device_id` fallback: no `--offered-name`/`[reverse]
        // .offered_name` set), never the target-side controller alias the
        // `retry` line above is keyed on (issue #4 item 6: this is the
        // real controller-side proof that `listen/tests.rs`'s hand-
        // constructed `RegistrationEvent` literal cannot give).
        let denied = wait_for(TIMEOUT, || {
            let v = events_by_host_and_kind("device-id", "denied");
            (!v.is_empty()).then_some(v)
        })
        .await;
        let _ = shutdown_tx.send(());
        (events, denied)
    };
    let (result, (events, denied)) = tokio::join!(run_fut, watch_fut);
    result.expect("shutdown must resolve run_reverse cleanly even mid-backoff after a denial");

    let first = &events[0];
    assert_eq!(first["cause"], "registration_denied");
    assert!(
        first.get("fingerprint").is_none(),
        "a pre-registration retry line must omit fingerprint entirely, not null: {first}"
    );
    assert!(
        first.get("since_registered_ms").is_none(),
        "a never-registered retry line must omit since_registered_ms entirely, not null: {first}"
    );
    assert_at_is_rfc3339(first);

    let denied = &denied[0];
    assert_eq!(denied["event"], "denied");
    assert_eq!(denied["cause"], "registration_denied");
    assert_at_is_rfc3339(denied);

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// `peer_closed` — the controller explicitly closing an established
// registration (`CLOSE_CODE_REPLACED`, the exact scenario
// `reverse_loopback.rs`'s own
// `run_target_reconnects_and_re_registers_when_the_controller_replaces_it`
// proves reconnects; this test adds the `cause`/`since_registered_ms`
// assertions on top of it).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn run_target_lost_and_retry_lines_report_peer_closed_with_since_registered_ms_present() {
    capture_reverse_events();
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    let config = fast_backoff();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target_with_config(
        &target,
        "device-id",
        "controller-cause-peer",
        None,
        &config,
        async {
            let _ = shutdown_rx.await;
        },
    );
    let force_fut = async {
        // Wait for the real first registration, then dial again under the
        // identical fingerprint — the controller replaces it and closes
        // the connection `run_target` is holding with `CLOSE_CODE_REPLACED`
        // (an explicit application close, `listen/registration.rs`), which
        // is exactly what a peer-initiated close looks like from the
        // target's own `classify_connection_error`.
        wait_for(TIMEOUT, || {
            let e = harness.listen.registry().get("widget")?;
            (e.generation == 0).then_some(())
        })
        .await;
        // Same window as the silent-path test: a replacement that lands
        // before the first target has read its `Hello` reply closes a
        // connection that is not yet "registered" from the target's side,
        // so no `"lost"` line would follow — see `wait_target_registered`.
        wait_target_registered("controller-cause-peer").await;
        let (dialed2, _ctl2, _hello2) = harness
            .register(&target, "")
            .await
            .expect("same-fingerprint reconnect replaces");

        let lost = wait_for(TIMEOUT, || {
            let v = events_by_host_and_kind("controller-cause-peer", "lost");
            (!v.is_empty()).then_some(v)
        })
        .await;
        let retry = wait_for(TIMEOUT, || {
            let v = events_by_host_and_kind("controller-cause-peer", "retry");
            (!v.is_empty()).then_some(v)
        })
        .await;
        let _ = shutdown_tx.send(());
        (dialed2, lost, retry)
    };

    let (result, (_dialed2, lost, retry)) = tokio::join!(run_fut, force_fut);
    result.expect("a clean shutdown must exit Ok even mid-flight after a forced reconnect");

    let lost = &lost[0];
    assert_eq!(lost["event"], "lost");
    assert_eq!(lost["cause"], "peer_closed");
    assert!(
        lost["fingerprint"].is_string(),
        "a `lost` line always names the peer it lost: {lost}"
    );
    let since = lost["since_registered_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("`lost` must carry a numeric since_registered_ms: {lost}"));
    assert_at_is_rfc3339(lost);
    // No controller-side `lost` line for host "widget" here: the old
    // generation's `mark_stale` call is a no-op once the replace already
    // advanced it (`Registry::mark_stale_is_a_no_op_once_a_newer_registration_already_superseded_it`)
    // — `replaced` already documents this death, so `Listen::drive_registered_session`
    // correctly does not emit a second, duplicate diagnostic for the same
    // generation.

    let retry = &retry[0];
    assert_eq!(retry["cause"], "peer_closed");
    assert!(
        retry.get("fingerprint").is_none(),
        "every retry line omits fingerprint, even after a registered loss: {retry}"
    );
    assert_eq!(
        retry["since_registered_ms"].as_u64(),
        Some(since),
        "the paired retry line must carry the same since_registered_ms as its lost line"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// A silent path (no close frame at all) — `path_dead` from the target's
// own `PathWatch`, mirroring `reverse_chaos.rs`'s `sever()` gate.
// ---------------------------------------------------------------------------

/// `docs/design/protocol.md` §11-4's own watchdog also runs on the
/// controller's side of the *same* registered session
/// (`Listen::drive_registered_session`, identical `PathWatchConfig::
/// default()`), so a fully bidirectional silent sever is a genuine race
/// between the two sides' independent ~1 s detection budgets: if the
/// target's own watch wins, it reports `path_dead` directly; if the
/// controller's wins first, it closes the connection with
/// `CLOSE_CODE_PATH_DEAD`, and `classify_connection_error` reads that
/// close code back off the `ApplicationClosed` payload rather than
/// treating every `ApplicationClosed` as a clean peer close — so this
/// side reports `path_dead` too. Both race outcomes converge on the same
/// value; only a close carrying a *different* code (a real clean
/// `peer_closed`) would not.
#[tokio::test(flavor = "multi_thread")]
async fn run_target_lost_and_retry_lines_report_a_silent_path_as_path_dead() {
    capture_reverse_events();
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let chaos = ChaosProxy::start(harness.addr, ChaosPolicy::seeded(0xCA05E))
        .await
        .expect("bind chaos proxy in front of the controller");

    let config = fast_backoff();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target_through_chaos(
        &target,
        "device-id",
        "controller-cause-silent",
        None,
        &config,
        &chaos,
        |_runtime| {},
        async {
            let _ = shutdown_rx.await;
        },
    );
    let scenario = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
        // Not the registry alone — see `wait_target_registered`.
        wait_target_registered("controller-cause-silent").await;
        chaos.sever().await;

        let lost = wait_for(TIMEOUT, || {
            let v = events_by_host_and_kind("controller-cause-silent", "lost");
            (!v.is_empty()).then_some(v)
        })
        .await;
        let retry = wait_for(TIMEOUT, || {
            let v = events_by_host_and_kind("controller-cause-silent", "retry");
            (!v.is_empty()).then_some(v)
        })
        .await;
        // The controller's own `lost` line for the same death — `host` is
        // the registered name ("widget", the pinned alias), not the
        // target-side controller alias the lines above are keyed on. This
        // is the real controller-side proof `listen/tests.rs`'s hand-
        // constructed `RegistrationEvent` literal cannot give (issue #4
        // item 6): whichever side's watchdog wins the race, the
        // controller's own classification converges on `path_dead` too
        // (this test's own module doc), so it is deterministic to assert
        // here, unlike the target-side value in some other scenarios.
        let controller_lost = wait_for(TIMEOUT, || {
            let v = events_by_host_and_kind("widget", "lost");
            (!v.is_empty()).then_some(v)
        })
        .await;
        let _ = shutdown_tx.send(());
        (lost, retry, controller_lost)
    };

    let (result, (lost, retry, controller_lost)) = tokio::join!(run_fut, scenario);
    result.expect("a clean shutdown must exit Ok even mid-flight after a sever");

    let lost = &lost[0];
    assert_eq!(
        lost["cause"], "path_dead",
        "a silent-path loss must classify as path_dead regardless of which \
         side's watchdog closes the connection first: {lost}"
    );
    assert!(lost["since_registered_ms"].as_u64().is_some());
    assert_eq!(retry[0]["cause"], "path_dead");

    let controller_lost = &controller_lost[0];
    assert_eq!(controller_lost["cause"], "path_dead");
    assert!(controller_lost["since_registered_ms"].as_u64().is_some());
    assert_at_is_rfc3339(controller_lost);

    harness.shutdown().await;
}
