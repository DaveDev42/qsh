//! `PLAN.md` M3 Step 9 (c): the `qsh-core`-level half of the "exactly
//! once" test — asserts
//! [`qsh_core::reverse::target::run_reverse_observed`]'s `on_unreachable`
//! hook actually fires against a real failed dial, in-process, rather than
//! only inferring it from a real subprocess's stderr
//! (`crates/qsh-cli/tests/reverse_unreachable_diagnostic.rs` is that other
//! half — a real `qsh reverse` child against the same kind of unreachable
//! address, proving the CLI wiring on top of this hook).
//!
//! The "at most once" half of the guarantee is structural, not timing-
//! dependent: `run_reverse_unix` wraps the hook in `Option<F>` and calls
//! it through `Option::take`, so the closure physically cannot run twice
//! no matter how many further retries follow — Rust's ownership rules
//! enforce that, not this test. What still needs a real dial to prove is
//! the "at least once, and the loop survives it" half: that a genuine
//! failed attempt actually reaches the hook and the reconnect loop keeps
//! running (and shuts down cleanly) afterward, instead of the hook being
//! wired to a dead branch.
//!
//! `#![cfg(unix)]`: [`ReverseHarness::run_target_observing_unreachable`]
//! drives the real `#[cfg(unix)]` reconnect loop.

#![cfg(unix)]

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use qsh_core::config::{Config, ReverseConfig};
use qsh_testkit::loopback::make_identity;
use qsh_testkit::reverse::ReverseHarness;

/// Bound on the whole test. Generous: on a sandbox without a fast
/// ICMP-port-unreachable path back from a closed loopback UDP port, a
/// single dial attempt against it runs out the clock on
/// `qsh_transport::endpoint::DEFAULT_DIAL_TIMEOUT` (10s) before
/// `dial_and_register` returns `Err` at all — this bound has to cover at
/// least one full attempt, not assume a fast local refusal.
const TIMEOUT: Duration = Duration::from_secs(20);

/// How often to poll the fire count while waiting for the first failed
/// attempt to reach the hook.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[tokio::test(flavor = "multi_thread")]
async fn on_unreachable_fires_once_on_a_real_failed_dial() {
    let target = make_identity();
    // Only needed for its identity plumbing (`target_paths_at` pins this
    // harness's own controller fingerprint) — the dial below never
    // actually reaches `harness.addr`.
    let harness = ReverseHarness::start().await;

    // A UDP port nothing listens on: bind it to claim a real, otherwise
    // unused loopback port, then drop the socket immediately so nothing
    // answers there.
    let dial_addr = {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a throwaway UDP port");
        socket.local_addr().expect("local addr")
    };

    // Backoff timing barely matters here (a single dial attempt's own
    // timeout dominates it either way) — kept tiny so a retry after the
    // hook fires does not add meaningfully to the test's wall time.
    let fast_backoff = Config {
        reverse: ReverseConfig {
            backoff_initial_ms: Some(5),
            backoff_max_ms: Some(20),
            backoff_jitter_pct: Some(0),
            ..Default::default()
        },
        ..Default::default()
    };

    let fire_count = Arc::new(AtomicUsize::new(0));
    let hook_count = Arc::clone(&fire_count);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target_observing_unreachable(
        &target,
        "device-id",
        "controller-unreachable",
        None,
        &fast_backoff,
        dial_addr,
        move || {
            hook_count.fetch_add(1, Ordering::SeqCst);
        },
        async {
            let _ = shutdown_rx.await;
        },
    );

    // Poll (bounded) for the hook to fire once, then shut down promptly —
    // no fixed sleep guessing how long a dial attempt takes.
    let watch_fut = async {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        while fire_count.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::time::timeout(TIMEOUT, async { tokio::join!(run_fut, watch_fut) })
        .await
        .expect("shutdown must resolve run_reverse within the test bound");
    result.expect("shutdown must resolve run_reverse cleanly against an unreachable controller");

    assert_eq!(
        fire_count.load(Ordering::SeqCst),
        1,
        "on_unreachable must fire exactly once for a real failed dial against an unreachable \
         controller"
    );

    harness.shutdown().await;
}
