//! L4: the reverse-mode chaos gate (`docs/design/testing.md` L4, `PLAN.md`
//! M3 Step 4 (c)/(d)).
//!
//! `reverse_loopback.rs` already proves the reconnect loop survives a
//! *closed* connection (the controller replacing a same-fingerprint
//! registration, `CLOSE_CODE_REPLACED`). This file proves the harder case:
//! a path that goes **silent** — no close frame, nothing — severed by the
//! same [`qsh_testkit::chaos::ChaosProxy`] `resume_chaos.rs` uses for the
//! forward direction, inserted into the target→controller leg only (the
//! controller's own accept loop is unaware of it, exactly like
//! [`qsh_testkit::loopback::LoopbackHarness::start_chaotic`]'s own setup).
//!
//! The invariant under test is SC5's reverse edition (`docs/PRD.md` §15:
//! "client crash가 remote PTY를 죽이지 않음"; `docs/ROADMAP.md`'s SC-number
//! legend) — here it is the *target*'s only connection that dies, not a
//! client, but the same guarantee has to hold: the session (and the real
//! PTY child behind it) the target's broker owns is decoupled from any one
//! connection's lifetime (`docs/design/architecture.md` §3), so it must
//! still be there, under the *same* `session_id`, once the target notices
//! the path is dead and redials.
//!
//! There is no wire-level `session.list` to call here yet — the
//! controller-driven passthrough that would let it dial into the target's
//! broker over the registered connection is M3 Step 5's localctl
//! (`docs/design/protocol.md` §11-3, explicit: "구현은 M3 Step 5다"). So
//! this test reaches the target's broker the only way available today: a
//! handle to the target's own long-lived host runtime, captured once via
//! [`qsh_testkit::reverse::ReverseHarness::run_target_through_chaos`]'s
//! `on_runtime` hook — the same runtime (and the same broker inside it)
//! every reconnect this test forces reuses.
//!
//! `#![cfg(unix)]` gates the whole file, unlike `reverse_loopback.rs`'s
//! per-test gating — that file mixes platform-neutral tests with unix-only
//! ones, so it gates test-by-test; every helper here (`pin`, `fast_backoff`,
//! every import) exists only to feed the one unix-only scenario below, with
//! no platform-neutral content to keep alive, so gating the file is both
//! simpler and the only way to avoid `unused_imports`/`dead_code` on a
//! non-unix build (the exact Windows-leg trap `run_reverse` itself invites:
//! it is gated `cfg(not(unix))` to return `ErrorCode::Unsupported`
//! immediately, so on Windows a real target here would never dial or
//! register at all and the scenario's own `wait_for` deadlines would simply
//! time out — a false failure, not a proof of anything).
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::broker::SessionSpec;
use qsh_core::config::{Config, ReverseConfig};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_testkit::{ChaosPolicy, ChaosProxy, TestIdentity, make_identity};
use qsh_transport::{Principal, StaticTrust};

/// Bound on the whole sever → detect → redial → re-register round trip.
/// `docs/design/protocol.md` §10's default detection budget is ~1 s on a
/// fresh path (`client::pathwatch::PathWatchConfig::default`'s own doc:
/// "250 ms × 3 strikes puts detection at ~1 s") and the injected backoff
/// below is tens of milliseconds, so this is generous slack around a
/// sub-second scenario, not a budget anyone should need in full — a real
/// event (`Registry::get`'s `generation`) is what actually ends the wait,
/// never this deadline on the happy path (`docs/design/testing.md`: no
/// `sleep()`-based synchronization; this is only the bounded backstop).
const TIMEOUT: Duration = Duration::from_secs(10);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// A config-injected (never hardcoded) short `[reverse]` backoff — the
/// scenario's own bound comes from [`TIMEOUT`] above, not from waiting out
/// the 500 ms/30 s production defaults (`PLAN.md` Step 4 (c): "주입된 짧은
/// backoff로 수 초 내 완료").
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

/// The gate: sever the target→controller path, and the target's own
/// reconnect loop redials and re-registers on its own — registry
/// `generation` advances by **exactly** one, never zero (no reconnect
/// happened) and never more than one (a reconnect storm) — while the
/// session the target opened before the sever stays the target broker's
/// same session, under the same `session_id`, the whole way through.
#[tokio::test(flavor = "multi_thread")]
async fn a_severed_path_auto_reregisters_and_the_target_session_survives() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    // Seeded, fault-free control arm: a bare `sever()` is the fault under
    // test — loss/jitter/reorder have their own tests elsewhere
    // (`resume_chaos.rs`), and mixing them in here would make a deadline
    // miss ambiguous about which fault caused it.
    let chaos = ChaosProxy::start(harness.addr, ChaosPolicy::seeded(0x5C5_0DE))
        .await
        .expect("bind chaos proxy in front of the controller");
    let ctx = format!(
        "chaos seed={:#x} front={} controller={}",
        chaos.seed(),
        chaos.addr(),
        harness.addr
    );

    // Bound to a local, not passed as a bare temporary: `run_fut` below
    // holds `&config` across every `.await` point in the reconnect loop, so
    // it must outlive the whole future, not just the call expression that
    // builds it.
    let config = fast_backoff();
    let (runtime_tx, runtime_rx) = tokio::sync::oneshot::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run_fut = harness.run_target_through_chaos(
        &target,
        "device-id",
        "controller",
        None,
        &config,
        &chaos,
        move |runtime| {
            // Fires once, before the first dial (`run_target_through_chaos`'s
            // doc comment) — the same broker instance every reconnect below
            // reuses.
            let _ = runtime_tx.send(runtime.server.clone());
        },
        async {
            let _ = shutdown_rx.await;
        },
    );

    let scenario = async {
        let first = wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
        assert_eq!(first.generation, 0, "initial registration — {ctx}");

        let server = tokio::time::timeout(TIMEOUT, runtime_rx)
            .await
            .unwrap_or_else(|_| panic!("on_runtime hook never fired — {ctx}"))
            .expect("run_target_through_chaos must call on_runtime exactly once");

        // A real, long-lived PTY session, opened directly against the
        // target's own broker (module docs: no wire passthrough exists for
        // this yet). `sleep 30` is comfortably longer than this whole
        // scenario and exits on its own if anything here ever leaked past
        // `harness.shutdown()`.
        let spec = SessionSpec {
            argv: vec!["sleep".to_string(), "30".to_string()],
            cols: 80,
            rows: 24,
            ..Default::default()
        };
        let session_id = server
            .sessions()
            .open(&spec, "reverse-chaos-test")
            .unwrap_or_else(|err| {
                panic!("open a real PTY session on the target — {err:?} — {ctx}")
            });
        let before = server.sessions().list();
        assert!(
            before.iter().any(|s| s.session_id == session_id.as_str()),
            "the freshly opened session must be listed — {ctx}"
        );

        // ---- the measured fault: sever the target→controller leg only ----
        chaos.sever().await;

        wait_for(TIMEOUT, || {
            let e = harness.listen.registry().get("widget")?;
            (e.generation >= 1).then_some(())
        })
        .await;
        let after = harness
            .listen
            .registry()
            .get("widget")
            .unwrap_or_else(|| panic!("still registered after the reconnect — {ctx}"));
        assert_eq!(
            after.generation, 1,
            "generation must advance by exactly one — {ctx}"
        );

        // The same broker, reached again after the reconnect: the exact
        // same session_id is still there, and nothing else was opened or
        // lost — the reconnect never touched the session or its child.
        let still_there = server.sessions().list();
        assert!(
            still_there
                .iter()
                .any(|s| s.session_id == session_id.as_str()),
            "the session must survive the reconnect under the same id — {ctx} \
             before={before:?} after={still_there:?}"
        );
        assert_eq!(
            still_there.len(),
            before.len(),
            "no session must have been created or lost across the reconnect — {ctx}"
        );

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, scenario);
    result.unwrap_or_else(|err| {
        panic!("shutdown must resolve run_target_through_chaos cleanly even after a sever: {err:?} — {ctx}")
    });

    let stats = chaos.stats();
    assert_eq!(stats.severs, 1, "{ctx} stats={stats:?}");
    assert!(stats.is_balanced(), "{ctx} stats={stats:?}");

    harness.shutdown().await;
}
