//! ADR-0054 DoD 2: the four scenes of decision 23 that the 25-pair table
//! does not cover, through the real client route (`dial_routed`) with a real
//! `qsh listen` as R and the real `qsh serve --to` entry as B
//! (`punch_route::world`, `Layout`).
//!
//! The clocks are real, so a failing scene takes the punch budget in real
//! seconds. Which candidate won is read from the `kind` and `family` of the
//! `adopted` line on the `qsh::punch` log target (it carries no address).

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use qsh_core::punch::{PUNCH_SIGNAL_BUDGET, PUNCH_WINDOW};
use qsh_proto::ErrorCode;
use qsh_testkit::netsim::{DropReason, NatKind};
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::punch_route::{Layout, World, WorldOptions, exec, punched, world};

// ---------------------------------------------------------------------------
// the `adopted` lines of `qsh::punch`
// ---------------------------------------------------------------------------

fn adopted_lines() -> &'static Mutex<Vec<Value>> {
    static LINES: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();
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
        if let Ok(line) = serde_json::from_str::<Value>(&message.0)
            && line["punch"] == "adopted"
        {
            adopted_lines()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line);
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
    adopted_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// The one `adopted` line of a run.
fn the_adopted_line() -> Value {
    let lines = adopted_lines().lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(lines.len(), 1, "exactly one adopted connection: {lines:?}");
    lines[0].clone()
}

fn scene(layout: Layout, a_nat: NatKind, b_nat: NatKind) -> WorldOptions {
    WorldOptions {
        a_nat,
        b_nat,
        layout,
        direct_listener: false,
        pin_b_address: false,
        ..WorldOptions::default()
    }
}

/// Runs `exec` against B and returns how long it took.
async fn punch_ok(w: &World, who: &str) -> Duration {
    let started = Instant::now();
    let out = exec(&w.a.ops, "b")
        .await
        .unwrap_or_else(|err| panic!("{who}: should punch: {err:?}"));
    let took = started.elapsed();
    assert!(punched(&out), "{who}: the command did not run");
    assert!(
        took < PUNCH_SIGNAL_BUDGET + PUNCH_WINDOW,
        "{who}: took {took:?}"
    );
    took
}

// ---------------------------------------------------------------------------
// (a) one NAT for both
// ---------------------------------------------------------------------------

/// A and B are two hosts behind the same box and the box does not hairpin,
/// so B's outside address is a dead end for A. The host candidate (B's LAN
/// address) is what opens, and the `adopted` line says so.
#[tokio::test(flavor = "multi_thread")]
async fn punch_same_nat_uses_host_candidates() {
    capture_adopted();
    let w = world(scene(
        Layout::SameNat,
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))
    .await;
    assert!(
        !w.a_site.nat().unwrap().config().hairpin,
        "the scene is about a box that does not hairpin"
    );
    let took = punch_ok(&w, "same nat").await;
    let line = the_adopted_line();
    assert_eq!(line["kind"], "host", "{line}");
    assert_eq!(line["family"], "ipv4", "{line}");
    println!(
        "same NAT: host candidate adopted at {} ms, exec {} ms, hairpin drops {}",
        line["elapsed_ms"],
        took.as_millis(),
        w.net.stats().dropped(DropReason::HairpinDisabled)
    );
    w.shutdown().await;
}

// ---------------------------------------------------------------------------
// (b) double NAT
// ---------------------------------------------------------------------------

/// B is behind a home box that is behind a carrier box, both EIM with
/// address-and-port filtering. R sees the carrier box's address; B's punch
/// datagrams open both boxes.
#[tokio::test(flavor = "multi_thread")]
async fn punch_through_double_nat() {
    capture_adopted();
    let w = world(scene(
        Layout::DoubleNat,
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))
    .await;
    let took = punch_ok(&w, "double nat").await;
    let line = the_adopted_line();
    assert_ne!(
        line["kind"], "host",
        "a private address cannot be the way in: {line}"
    );
    println!(
        "double NAT: {} candidate adopted at {} ms, exec {} ms",
        line["kind"],
        line["elapsed_ms"],
        took.as_millis()
    );
    w.shutdown().await;
}

// ---------------------------------------------------------------------------
// (c) IPv6 with stateful firewalls
// ---------------------------------------------------------------------------

/// Nothing but IPv6 and two stateful firewalls with no translation: the
/// addresses are global, the firewalls need the outbound punch to let the
/// peer in.
#[tokio::test(flavor = "multi_thread")]
async fn punch_ipv6_firewalls_only() {
    capture_adopted();
    let w = world(scene(
        Layout::Ipv6Firewalls,
        NatKind::FirewallV6,
        NatKind::FirewallV6,
    ))
    .await;
    assert!(w.a_site.ip().is_ipv6() && w.b_site.ip().is_ipv6() && w.r_site.ip().is_ipv6());
    let took = punch_ok(&w, "ipv6 firewalls").await;
    let line = the_adopted_line();
    assert_eq!(line["family"], "ipv6", "{line}");
    println!(
        "IPv6 firewalls: {} candidate adopted at {} ms, exec {} ms",
        line["kind"],
        line["elapsed_ms"],
        took.as_millis()
    );
    w.shutdown().await;
}

// ---------------------------------------------------------------------------
// (d) R behind B's NAT
// ---------------------------------------------------------------------------

/// R runs on a second host behind B's port-restricted box, with a port
/// forward, and A is outside. B registers over the LAN, so R sees B at a
/// private address; A takes the address it reached R at plus the port R saw,
/// which a port-preserving box keeps.
#[tokio::test(flavor = "multi_thread")]
async fn derived_candidate_reaches_a_target_behind_the_rendezvous_nat() {
    capture_adopted();
    let w = world(scene(
        Layout::RendezvousBehindTarget,
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))
    .await;
    let took = punch_ok(&w, "derived candidate").await;
    let line = the_adopted_line();
    assert_eq!(line["kind"], "reflexive", "the derived candidate: {line}");
    println!(
        "derived candidate adopted at {} ms, exec {} ms",
        line["elapsed_ms"],
        took.as_millis()
    );
    w.shutdown().await;
}

/// The same scene with a box that does not keep the inside port: the derived
/// port is wrong, the pair cannot open, and the punch gives up with
/// `timeout` inside its budget, leaving nothing behind.
#[tokio::test(flavor = "multi_thread")]
async fn derived_candidate_fails_when_the_rendezvous_nat_randomizes_ports() {
    capture_adopted();
    let w = world(scene(
        Layout::RendezvousBehindTarget,
        NatKind::PortRestricted,
        NatKind::PortRestrictedRandom,
    ))
    .await;
    let started = Instant::now();
    let err = exec(&w.a.ops, "b")
        .await
        .expect_err("a wrong derived port cannot connect");
    let took = started.elapsed();
    assert!(
        matches!(err.code, ErrorCode::ConnectionFailed | ErrorCode::Timeout),
        "{err:?}"
    );
    assert_eq!(err.details["punch"]["reason"], "timeout", "{err:?}");
    let budget = PUNCH_SIGNAL_BUDGET + PUNCH_WINDOW;
    assert!(
        took <= budget + Duration::from_millis(1500),
        "gave up after {took:?}, budget {budget:?}"
    );
    assert!(
        adopted_lines()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "no connection was adopted"
    );
    println!("random-port box: gave up after {} ms", took.as_millis());
    w.shutdown().await;
}
