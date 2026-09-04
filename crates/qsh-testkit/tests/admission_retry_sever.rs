//! P3-6 재dial 케이던스 (`ARBITRATION-4.md` J6, F1). A client recovering
//! from a dead path re-dials the same host from the same source address,
//! and must never re-dial fast enough for that host's `admission::Gate` to
//! see a burst. The gate's threshold at the shipping default is
//! `handshake_rate_per_source (10) * EPOCH (2 s) = 20` per source per 2 s
//! window (`crates/qsh-core/src/admission.rs`, `Gate::rate_exceeded`).
//!
//! The cadence has two halves, and they are checked in two places because
//! they are reachable from two different places:
//!
//! - **The schedule** — how far apart a recovering attach spaces its
//!   attempts — is `RecoveryConfig::backoff` (0, 200 ms, then 800 ms),
//!   private to `qsh_core::ops`, driven by `recover_attach`, also private.
//!   Neither is reachable from a `qsh-testkit` integration test, and no
//!   forward-route `Ops` harness exists here (`crates/qsh-cli/tests/
//!   attach_recovery.rs`, which does drive a real `Ops` attach, builds its
//!   fleet out of a real `qsh serve` child process and a `Sandbox`, not
//!   out of `LoopbackHarness`). That half is therefore checked as pure
//!   arithmetic, next to the schedule itself, by
//!   `the_recovery_backoff_schedule_stays_far_under_the_admission_burst_limit`
//!   in `crates/qsh-core/src/ops/session.rs` — including the fast-fail
//!   axis, where every attempt fails in microseconds and only the schedule
//!   stands between the loop and the gate. There is no seam here that
//!   would let a `qsh-testkit` test observe that axis through the product
//!   loop, so this file does not carry a fast-fail variant.
//! - **The attempt** — `qsh_core::client::reconnect::recover`, the per-
//!   attempt product entry point that `recover_attach` calls once per
//!   attempt, and the same call `crates/qsh-testkit/tests/resume_chaos.rs`
//!   drives — is reachable, and is what this file exercises: a real
//!   severed path, a real re-dial through the chaos proxy, spaced by the
//!   schedule above.
//!
//! The spacing constants below are a restatement of `RecoveryConfig::
//! backoff`'s, because that function is private; the unit test named above
//! is what fails if the schedule's values ever move, so the restatement
//! cannot quietly drift into asserting something the product does not do.
//!
//! The path is blackholed across the first attempt on purpose. Without it
//! a re-dial after `sever_client` simply succeeds first try (the proxy
//! relays a fresh source port onto a brand-new host connection — see
//! `ChaosProxy::sever`'s own doc), leaving a single timestamp, and one
//! timestamp says nothing about cadence. The blackhole makes attempt 0 run
//! out its `REDIAL_DEADLINE` so the recovery needs at least two attempts
//! and the assertion has a real interval to measure.
//!
//! The zero-`rate_limited`-audit-rows assertion is a safety net rather
//! than the point: the count assertion is what would fail first if the
//! cadence regressed, and the audit rows confirm the host agreed.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use qsh_core::client::ClientError;
use qsh_core::client::reconnect::{REDIAL_DEADLINE, Recovered, recover};
use qsh_testkit::chaos::ChaosPolicy;
use qsh_testkit::loopback::LoopbackHarness;

/// `admission::Gate`'s burst threshold at the shipping default
/// (`handshake_rate_per_source = 10`, `EPOCH = 2 s`, `Gate::rate_exceeded`
/// in `crates/qsh-core/src/admission.rs`). The gate rejects only
/// `estimate > burst_limit`, so a count *of* `BURST_LIMIT` is still
/// admitted — the assertion below checks `<=`, not `<`.
const BURST_LIMIT: usize = 20;

/// The gate's window (`EPOCH`, `crates/qsh-core/src/admission.rs`),
/// restated because it is private to that module.
const EPOCH: Duration = Duration::from_secs(2);

/// `RecoveryConfig::backoff`'s schedule, restated (it is private to
/// `qsh_core::ops`): attempt 0 runs immediately, attempt 1 after 200 ms,
/// every later attempt after 800 ms.
fn backoff(attempt: u32) -> Duration {
    match attempt {
        0 => Duration::ZERO,
        1 => Duration::from_millis(200),
        _ => Duration::from_millis(800),
    }
}

/// `RecoveryConfig::attempts`' shape for this scenario. Three is enough
/// for the blackhole to cost one attempt and still leave two that can
/// succeed, and keeps the worst case inside [`TEST_DEADLINE`].
const ATTEMPTS: u32 = 3;

/// How long the path stays blackholed. Longer than attempt 0's whole
/// `REDIAL_DEADLINE` budget so that attempt fails, and short enough that
/// attempt 1 (at `REDIAL_DEADLINE` + 200 ms ≈ 2.2 s) has the path back
/// well inside its own deadline.
const BLACKHOLE: Duration = Duration::from_millis(2_300);

/// Wall-clock ceiling for the whole test. The scenario costs about 2.6 s
/// (one blackholed attempt, one 200 ms backoff, one fast re-dial) plus
/// harness startup, so 8 s is a hang detector, not a budget being spent.
const TEST_DEADLINE: Duration = Duration::from_secs(8);

/// The largest number of `attempts` timestamps that fall inside any single
/// `window`-wide sliding window — the worst case an admission gate keyed
/// on wall-clock time would ever have seen, checked at every window start
/// an attempt could anchor rather than at fixed-origin buckets.
fn max_in_any_window(attempts: &[Instant], window: Duration) -> usize {
    let mut best = 0usize;
    for (i, &start) in attempts.iter().enumerate() {
        let count = attempts[i..]
            .iter()
            .take_while(|&&t| t.duration_since(start) < window)
            .count();
        best = best.max(count);
    }
    best
}

/// One redial attempt's outcome, for the diagnostic on failure.
struct AttemptLog {
    started: Instant,
    outcome: &'static str,
}

fn diagnostic(attempts: &[AttemptLog], start: Instant, max_window: usize) -> String {
    let mut lines = format!(
        "{} attempts, max-per-{EPOCH:?}-window {max_window} (burst_limit {BURST_LIMIT}, \
         headroom {})\n",
        attempts.len(),
        BURST_LIMIT as isize - max_window as isize,
    );
    for (n, a) in attempts.iter().enumerate() {
        lines.push_str(&format!(
            "  attempt {n} at +{:?}: {}\n",
            a.started.duration_since(start),
            a.outcome
        ));
    }
    lines
}

/// Sever the live path, blackhole it across the first re-dial, then
/// recover on the schedule a recovering attach uses — and count how
/// densely the host's admission gate saw those re-dials arrive.
#[tokio::test(flavor = "multi_thread")]
async fn redial_cadence_after_a_severed_path_stays_under_the_admission_burst_limit() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let h = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0x00B1_AC40)).await;
        let ctx = h.context();

        // Establish one live flow, then sever it — this is the "path died"
        // event the recovery below is reacting to.
        let dialed = h.dial().await;
        let flows = h.chaos().flows().await;
        let (client_addr, _upstream): (SocketAddr, SocketAddr) = *flows
            .first()
            .unwrap_or_else(|| panic!("no live flow to sever — {ctx}"));
        h.chaos().sever_client(client_addr).await;
        drop(dialed);
        let flows_before = h.chaos().flows().await.len();

        // Swallow everything across attempt 0's deadline, so the recovery
        // cannot finish on its first try.
        h.chaos().blackhole(BLACKHOLE).await;

        let session_ref = "box/redial-cadence-blackhole";
        let start = Instant::now();
        let mut log = Vec::new();
        let mut recovered = false;
        for attempt in 0..ATTEMPTS {
            let wait = backoff(attempt);
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            let attempt_start = Instant::now();
            let dialer = &h.dialer;
            let addr = h.addr;
            let out = recover(
                session_ref,
                None,
                REDIAL_DEADLINE,
                || async { false },
                || async move {
                    dialer
                        .dial(addr, "127.0.0.1")
                        .await
                        .map_err(|e| ClientError::Protocol(e.to_string()))
                },
                || 0,
            )
            .await;
            let outcome = match &out.outcome {
                Ok(Recovered::Resumed(_)) => "resumed",
                Ok(Recovered::Migrated) => "migrated",
                Err(_) => "failed",
            };
            log.push(AttemptLog {
                started: attempt_start,
                outcome,
            });
            if out.outcome.is_ok() {
                recovered = true;
                break;
            }
        }

        let timestamps: Vec<Instant> = log.iter().map(|a| a.started).collect();
        let max_window = max_in_any_window(&timestamps, EPOCH);
        let audit_rate_limited: Vec<_> = h
            .audit
            .records()
            .into_iter()
            .filter(|r| r.resource == "rate_limited" || r.resource == "validated_rate_limited")
            .collect();
        // Every re-dial leaves its own source port at the proxy, so the
        // flow table is an observation of the attempts that is independent
        // of the loop's own bookkeeping.
        let flows_after = h.chaos().flows().await.len();
        eprintln!("{}", diagnostic(&log, start, max_window));

        assert!(
            log.len() >= 2,
            "the blackhole did not cost the recovery an attempt, so there is no interval to \
             measure — {ctx}\n{}",
            diagnostic(&log, start, max_window)
        );
        assert!(
            flows_after - flows_before >= 2,
            "the proxy saw {} new source ports, fewer than the {} attempts the loop made — {ctx}",
            flows_after - flows_before,
            log.len()
        );
        assert!(
            recovered,
            "the redial never recovered inside {ATTEMPTS} attempts — {ctx}\n{}",
            diagnostic(&log, start, max_window)
        );
        assert!(
            max_window <= BURST_LIMIT && audit_rate_limited.is_empty(),
            "redial cadence tripped the admission burst limit: max {max_window} attempts in \
             one {EPOCH:?} window (limit {BURST_LIMIT}), {} rate_limited audit rows — {ctx}\n{}",
            audit_rate_limited.len(),
            diagnostic(&log, start, max_window)
        );

        h.shutdown().await;
    })
    .await
    .unwrap_or_else(|_| panic!("test exceeded the {TEST_DEADLINE:?} wall-clock budget"));
}
