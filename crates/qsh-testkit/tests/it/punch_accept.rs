//! ADR-0054 DoD 1 end to end: the 25 NAT pairs through the real client route
//! (`dial_routed`), a real `qsh listen` as R and the real `qsh serve --to` entry
//! as B, signalling included (`punch_route::world`).
//!
//! A's pin of B carries no address, so the route punches at once. The number
//! the p95 bound is about is the `elapsed_ms` of the `adopted` line on the
//! `qsh::punch` log target: route start (R dial, request, answer) to the
//! adopted connection. The `exec` that follows is timed too, only as a
//! sanity bound.
//!
//! The clocks are real (R and B use `std` time), so the links really take
//! 25 ms a hop and five pairs run side by side. The default run
//! is one seed and checks outcomes and budgets. With `QSH_ACCEPTANCE_SLOW`
//! it runs the five seeds of the ADR and asserts the p95 bound, which wants a
//! quiet machine.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use qsh_core::punch::{PUNCH_SIGNAL_BUDGET, PUNCH_WINDOW};
use qsh_proto::ErrorCode;
use qsh_testkit::netsim::NatKind;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::punch_route::{WorldOptions, exec, punched, world};

const KINDS: [NatKind; 5] = [
    NatKind::None,
    NatKind::FullCone,
    NatKind::Restricted,
    NatKind::PortRestricted,
    NatKind::Symmetric,
];

/// DoD 1: the adopted connection stands within a second of the route start.
const P95_BOUND: Duration = Duration::from_millis(1000);

/// ADR-0054 decision 23: the three pairs that cannot open without port
/// prediction.
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

fn slow_gate() -> bool {
    ["QSH_ACCEPTANCE_SLOW", "QSH_ACCEPTANCE_STRICT"]
        .iter()
        .any(|n| {
            std::env::var(n).is_ok_and(|v| {
                let v = v.trim().to_lowercase();
                !(v.is_empty() || v == "0")
            })
        })
}

// ---------------------------------------------------------------------------
// the `adopted` lines of `qsh::punch`
// ---------------------------------------------------------------------------

fn adopted_ms() -> &'static Mutex<Vec<u64>> {
    static LINES: OnceLock<Mutex<Vec<u64>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

struct AdoptedLayer;

struct Message(String);

impl tracing::field::Visit for Message {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AdoptedLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != qsh_core::punch::TARGET {
            return;
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        let Ok(line) = serde_json::from_str::<serde_json::Value>(&message.0) else {
            return;
        };
        if line["punch"] == "adopted"
            && let Some(ms) = line["elapsed_ms"].as_u64()
        {
            adopted_ms()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ms);
        }
    }
}

fn capture_adopted() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(AdoptedLayer)
            .try_init()
            .ok();
    });
}

// ---------------------------------------------------------------------------
// the runs
// ---------------------------------------------------------------------------

/// A pair, a seed and the loss on the A to B path.
type Job = (NatKind, NatKind, u64, f64);

struct Run {
    a: NatKind,
    b: NatKind,
    seed: u64,
    exec_took: Duration,
    outcome: Result<bool, qsh_core::OpError>,
}

impl Run {
    fn who(&self) -> String {
        format!("seed {}: {} x {}", self.seed, name(self.a), name(self.b))
    }
}

async fn run_pair((a, b, seed, loss): Job) -> Run {
    let w = world(WorldOptions {
        a_nat: a,
        b_nat: b,
        direct_listener: false,
        pin_b_address: false,
        seed,
        a_b_loss: loss,
        ..WorldOptions::default()
    })
    .await;
    let started = Instant::now();
    let result = exec(&w.a.ops, "b").await;
    let exec_took = started.elapsed();
    let outcome = result.map(|out| punched(&out));
    w.shutdown().await;
    Run {
        a,
        b,
        seed,
        exec_took,
        outcome,
    }
}

/// Five pairs side by side (the clocks are real, the links only sleep).
async fn run_chunk(jobs: &[Job]) -> Vec<Run> {
    assert!(jobs.len() <= 5);
    let job = |i: usize| jobs.get(i).copied();
    let run = |i: usize| async move {
        match job(i) {
            Some(j) => Some(run_pair(j).await),
            None => None,
        }
    };
    let (r0, r1, r2, r3, r4) = tokio::join!(run(0), run(1), run(2), run(3), run(4));
    [r0, r1, r2, r3, r4].into_iter().flatten().collect()
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let idx = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[idx]
}

/// The 22 pairs run a command over an adopted connection; the 3 give up with
/// `punch.reason = timeout` inside the signalling budget plus the window.
#[tokio::test(flavor = "multi_thread")]
async fn punch_route_nat_matrix() {
    capture_adopted();
    let slow = slow_gate();
    let seeds: Vec<u64> = if slow { vec![1, 2, 3, 4, 5] } else { vec![1] };
    let budget = PUNCH_SIGNAL_BUDGET + PUNCH_WINDOW;

    // With five seeds a chunk is one pair under every seed; with one seed it
    // is one row of the table.
    let mut jobs = Vec::new();
    for &a in &KINDS {
        for &b in &KINDS {
            for &seed in &seeds {
                jobs.push((a, b, seed, 0.0));
            }
        }
    }

    let mut samples: Vec<u64> = Vec::new();
    let (mut succeeded, mut gave_up) = (0, 0);
    for chunk in jobs.chunks(5) {
        adopted_ms()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let runs = run_chunk(chunk).await;
        let mut wins = 0;
        for run in runs {
            let who = run.who();
            if expected_to_fail(run.a, run.b) {
                let err = run
                    .outcome
                    .expect_err(&format!("{who}: should give up, not connect"));
                assert!(
                    matches!(err.code, ErrorCode::ConnectionFailed | ErrorCode::Timeout),
                    "{who}: {err:?}"
                );
                assert_eq!(err.details["punch"]["reason"], "timeout", "{who}: {err:?}");
                assert!(
                    run.exec_took <= budget + Duration::from_millis(1500),
                    "{who}: gave up after {:?}, budget {budget:?}",
                    run.exec_took
                );
                assert!(
                    run.exec_took < qsh_transport::default_dial_timeout(),
                    "{who}: {:?} is past the dial timeout",
                    run.exec_took
                );
                gave_up += 1;
            } else {
                let ok = run
                    .outcome
                    .unwrap_or_else(|err| panic!("{who}: should punch: {err:?}"));
                assert!(ok, "{who}: the command did not run over the punch");
                assert!(
                    run.exec_took < budget,
                    "{who}: took {:?}, past the punch budget",
                    run.exec_took
                );
                println!("{who}: exec {} ms", run.exec_took.as_millis());
                wins += 1;
                succeeded += 1;
            }
        }
        let got = adopted_ms()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(
            got.len(),
            wins,
            "one `adopted` line per punched connection in {chunk:?}"
        );
        samples.extend(got);
    }
    assert_eq!(succeeded, 22 * seeds.len());
    assert_eq!(gave_up, 3 * seeds.len());
    samples.sort_unstable();
    let (p50, p95, max) = (
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        *samples.last().unwrap(),
    );
    println!(
        "route start to adopted over {} punched connections (seeds {seeds:?}): \
         p50 {p50} ms, p95 {p95} ms, max {max} ms",
        samples.len()
    );
    if slow {
        assert!(
            Duration::from_millis(p95) <= P95_BOUND,
            "p95 {p95} ms is past the {P95_BOUND:?} bound (DoD 1)"
        );
    } else {
        eprintln!("p95 bound not asserted without QSH_ACCEPTANCE_SLOW=1");
    }
}

/// DoD 1 tail: the same table with 5% loss on the A to B path (both
/// directions; the signalling links stay clean). Every pair that can open
/// still stands inside the punch budget and runs its command over the
/// adopted connection. The pairs that cannot open are the same three and
/// loss does not change them, so only the 22 run. One seed by default, the
/// five seeds of the ADR with `QSH_ACCEPTANCE_SLOW`.
#[tokio::test(flavor = "multi_thread")]
async fn punch_route_nat_matrix_survives_five_percent_ab_loss() {
    capture_adopted();
    let slow = slow_gate();
    let seeds: Vec<u64> = if slow { vec![1, 2, 3, 4, 5] } else { vec![1] };
    let budget = PUNCH_SIGNAL_BUDGET + PUNCH_WINDOW;
    let mut jobs = Vec::new();
    for &a in &KINDS {
        for &b in &KINDS {
            if expected_to_fail(a, b) {
                continue;
            }
            for &seed in &seeds {
                jobs.push((a, b, seed, 0.05));
            }
        }
    }
    let mut times: Vec<u64> = Vec::new();
    let mut samples: Vec<u64> = Vec::new();
    for chunk in jobs.chunks(5) {
        adopted_ms()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let runs = run_chunk(chunk).await;
        let wins = runs.len();
        for run in runs {
            let who = run.who();
            let ok = run
                .outcome
                .unwrap_or_else(|err| panic!("{who}: should punch under 5% loss: {err:?}"));
            assert!(ok, "{who}: the command did not run over the punch");
            assert!(
                run.exec_took < budget,
                "{who}: took {:?} under loss, past the punch budget {budget:?}",
                run.exec_took
            );
            times.push(run.exec_took.as_millis() as u64);
        }
        let got = adopted_ms()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(got.len(), wins, "one `adopted` line per punched connection");
        samples.extend(got);
    }
    assert_eq!(times.len(), 22 * seeds.len());
    times.sort_unstable();
    samples.sort_unstable();
    println!(
        "5% A-B loss over {} punched connections (seeds {seeds:?}): route start to adopted \
         p50 {} ms, p95 {} ms, max {} ms; exec p95 {} ms, max {} ms (budget {} ms)",
        samples.len(),
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        samples.last().unwrap(),
        percentile(&times, 0.95),
        times.last().unwrap(),
        budget.as_millis()
    );
}
