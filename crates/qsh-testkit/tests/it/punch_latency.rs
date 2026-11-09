//! ADR-0054 DoD 1, the part after adoption: once the punch has adopted a
//! connection, the first `exec` output arrives within a few round trips.
//!
//! `punch_accept` bounds route start to adoption. This file bounds adoption
//! to the end of a one-line `exec` (the `Hello` exchange, the command, its
//! output and exit). Real clocks, links of 25 ms a hop, so the A-B round trip
//! is 50 ms.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use qsh_testkit::netsim::NatKind;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::punch_route::{WorldOptions, exec, punched, world};

/// The wall-clock instant of the latest `adopted` line of `qsh::punch`.
fn adopted_at() -> &'static Mutex<Option<Instant>> {
    static AT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    AT.get_or_init(|| Mutex::new(None))
}

/// The instant B's server logged `exec finished`.
fn exec_finished_at() -> &'static Mutex<Option<Instant>> {
    static AT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    AT.get_or_init(|| Mutex::new(None))
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
        let target = event.metadata().target();
        if target != qsh_core::punch::TARGET {
            if target.starts_with("qsh_core::server") {
                let mut message = Message(String::new());
                event.record(&mut message);
                if message.0.contains("exec finished") {
                    *exec_finished_at().lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(Instant::now());
                }
            }
            return;
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        let Ok(line) = serde_json::from_str::<serde_json::Value>(&message.0) else {
            return;
        };
        if line["punch"] == "adopted" {
            *adopted_at().lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        }
    }
}

fn capture() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(AdoptedLayer)
            .try_init()
            .ok();
    });
}

/// One punched `exec` between A and B, each behind the given NAT: (route
/// start to exec end, adoption to exec end).
async fn one_run(a: NatKind, b: NatKind, seed: u64) -> (Duration, Duration) {
    let w = world(WorldOptions {
        a_nat: a,
        b_nat: b,
        direct_listener: false,
        pin_b_address: false,
        seed,
        ..WorldOptions::default()
    })
    .await;
    *adopted_at().lock().unwrap_or_else(|e| e.into_inner()) = None;
    let started = Instant::now();
    let out = exec(&w.a.ops, "b").await.expect("exec over the punch");
    let finished = Instant::now();
    assert!(punched(&out));
    let adopted = adopted_at()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .expect("an adopted line");
    w.shutdown().await;
    (
        finished.duration_since(started),
        finished.duration_since(adopted),
    )
}

/// The A-B round trip of the world (25 ms a hop).
const RTT: Duration = Duration::from_millis(50);

/// Adoption to the end of the command: the `Hello` and the command are two
/// round trips, the host spawns the process, and the client's endpoint
/// drains for at most `CLOSE_DRAIN_CAP`. Before the cap, the end waited for
/// the closing period of the candidate connections that lost the race (three
/// PTOs from the 100 ms initial guess, 0.9 s), so the same command ended
/// 0.9 s after the adoption with a NAT at B and 0.54 s without one.
fn bound() -> Duration {
    2 * RTT + qsh_transport::CLOSE_DRAIN_CAP + Duration::from_millis(250)
}

/// A punched `exec` is over within [`bound`] of the adoption, whatever the
/// NAT pair: the candidates that lost the race do not hold it up.
#[tokio::test(flavor = "multi_thread")]
async fn a_punched_exec_ends_soon_after_the_adoption() {
    capture();
    let mut worst = Duration::ZERO;
    for (a, b) in [
        (NatKind::PortRestricted, NatKind::PortRestricted),
        (NatKind::None, NatKind::PortRestricted),
        (NatKind::PortRestricted, NatKind::None),
    ] {
        for seed in 1..=2 {
            let (total, after) = one_run(a, b, seed).await;
            eprintln!("{a:?} x {b:?} seed {seed}: total {total:?}, adoption to exec end {after:?}");
            worst = worst.max(after);
            assert!(
                after <= bound(),
                "{a:?} x {b:?} seed {seed}: the exec ended {after:?} after the adoption, over {:?}",
                bound()
            );
        }
    }
    eprintln!("worst adoption to exec end {worst:?}, bound {:?}", bound());
}

/// The cap is for the punch race's losers only. A direct dial keeps the full
/// drain of its connection: the command ends well over `CLOSE_DRAIN_CAP`
/// after the host finished it (the closing period at a 50 ms round trip is
/// about 0.4 s), so a lost final `CONNECTION_CLOSE` is still answered the
/// way it was before hole punching.
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_exec_keeps_the_full_drain() {
    capture();
    let w = world(WorldOptions::default()).await;
    // B's box forwards the direct port, so the direct dial stands alone.
    let b_nat = w.b_site.nat().expect("B is behind a box").clone();
    let inside = std::net::SocketAddr::new(w.b_site.ip(), super::punch_route::B_DIRECT_PORT);
    b_nat.forward(super::punch_route::B_DIRECT_PORT, inside);
    *exec_finished_at().lock().unwrap_or_else(|e| e.into_inner()) = None;
    let out = exec(&w.a.ops, "b").await.expect("direct exec");
    let finished = Instant::now();
    assert!(punched(&out));
    assert_eq!(w.punch_requests(), 0, "the dial was direct");
    let host_done = exec_finished_at()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .expect("the host logged the end of the command");
    let tail = finished.duration_since(host_done);
    eprintln!("direct exec: the client returned {tail:?} after the host finished");
    assert!(
        tail >= qsh_transport::CLOSE_DRAIN_CAP + Duration::from_millis(100),
        "the direct exec returned {tail:?} after the host finished, inside the capped drain"
    );
    w.shutdown().await;
}
