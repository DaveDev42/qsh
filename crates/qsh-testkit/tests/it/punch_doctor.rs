//! `qsh doctor <host>`'s one hole punch, its three codes and `punch` object,
//! and the `qsh::punch` log target (ADR-0054 decision 20, threat model D23),
//! over netsim with a real `qsh listen` as the rendezvous and the real
//! `qsh serve --to` entry as the target.
//!
//! The doctor reaches a pin with no address, so there is no direct probe to
//! send over the real network: the host has no direct path by construction.
//! The log capture is process-wide (one global subscriber), which is why the
//! lines are read per test under nextest, one process each.

use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use qsh_core::punch::{ClientPunch, PunchMode};
use qsh_proto::{DoctorData, DoctorReq};
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use super::punch_route::{WorldOptions, blocking, exec, punched, world};

// ---------------------------------------------------------------------------
// the `qsh::punch` capture
// ---------------------------------------------------------------------------

fn lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

fn capture_punch_lines() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(CaptureLayer)
            .try_init()
            .ok();
    });
}

struct CaptureLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != qsh_core::punch::TARGET {
            return;
        }
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        lines().lock().unwrap_or_else(|e| e.into_inner()).push(line);
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

fn captured() -> Vec<Value> {
    lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not pure JSON: {l:?}: {e}")))
        .collect()
}

fn events() -> Vec<String> {
    captured()
        .iter()
        .map(|v| v["punch"].as_str().expect("punch key").to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

async fn doctor(ops: &qsh_core::Ops, host: &str) -> DoctorData {
    let host = host.to_string();
    blocking(ops, move |ops| {
        ops.doctor(DoctorReq { host: Some(host) }, SystemTime::now())
    })
    .await
    .expect("doctor.run")
}

fn codes(data: &DoctorData) -> Vec<&str> {
    data.findings.iter().map(|f| f.code.as_str()).collect()
}

/// Nothing a doctor report shows may hold an address or a port: the object
/// has no field for one, and the findings name hosts and words only.
fn assert_no_address(data: &DoctorData) {
    let shown = serde_json::to_string(data).unwrap();
    for needle in [
        "198.51.100",
        "203.0.113",
        ":9000",
        ":6000",
        ":4433",
        ":5000",
    ] {
        assert!(!shown.contains(needle), "{needle} in {shown}");
    }
}

/// A host with no direct path gets one punch; it stands, and the report
/// says through whom, with what kind of candidate, and how fast.
#[tokio::test(flavor = "multi_thread")]
async fn doctor_punches_a_pin_without_an_address_and_reports_it() {
    capture_punch_lines();
    let w = world(WorldOptions {
        pin_b_address: false,
        ..WorldOptions::default()
    })
    .await;
    let data = doctor(&w.a.ops, "b").await;
    let punch = data.punch.as_ref().expect("data.punch");
    assert_eq!(punch.outcome, "succeeded", "{data:?}");
    assert_eq!(punch.rendezvous.as_deref(), Some("r"));
    assert_eq!(punch.reason, None);
    assert!(
        matches!(
            punch.candidate_kind.as_deref(),
            Some("host" | "reflexive" | "peer_reflexive")
        ),
        "{punch:?}"
    );
    assert_eq!(punch.family.as_deref(), Some("ipv4"));
    let ms = punch.elapsed_ms.expect("elapsed_ms");
    assert!(ms < 8000, "inside the punch budget: {ms}");

    let found = codes(&data);
    assert!(found.contains(&"punch_succeeded"), "{found:?}");
    assert!(!found.contains(&"punch_failed"), "{found:?}");
    assert!(!found.contains(&"punch_no_rendezvous"), "{found:?}");
    // A rendezvous candidate makes the address-less pin reachable.
    assert!(!found.contains(&"host_pinned_without_address"), "{found:?}");
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "punch_succeeded")
        .unwrap();
    assert_eq!(finding.status, "info");
    assert!(
        finding.detail.contains("rendezvous: r"),
        "{}",
        finding.detail
    );
    assert_no_address(&data);

    // The doctor's connection was closed again: R holds no punching
    // connection and the target no leftover.
    let seen = events();
    for event in ["attempt", "signaled", "adopted", "relayed", "window_opened"] {
        assert!(seen.iter().any(|e| e == event), "{event} in {seen:?}");
    }
    w.shutdown().await;
}

/// The punch fails for a named reason: `punch_failed` is a warning, the
/// reason is the ADR's word, and the report carries no address.
#[tokio::test(flavor = "multi_thread")]
async fn doctor_reports_the_reason_a_punch_failed() {
    capture_punch_lines();
    let w = world(WorldOptions {
        pin_b_address: false,
        register_b: false,
        ..WorldOptions::default()
    })
    .await;
    let data = doctor(&w.a.ops, "b").await;
    let punch = data.punch.as_ref().expect("data.punch");
    assert_eq!(punch.outcome, "failed", "{data:?}");
    assert_eq!(punch.reason.as_deref(), Some("target_not_registered"));
    assert_eq!(punch.rendezvous.as_deref(), Some("r"));
    assert_eq!(punch.candidate_kind, None);
    assert_eq!(punch.family, None);
    assert!(punch.elapsed_ms.is_some());
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "punch_failed")
        .expect("punch_failed");
    assert_eq!(finding.status, "warn");
    assert!(
        finding.detail.contains("reason: target_not_registered"),
        "{}",
        finding.detail
    );
    assert_eq!(data.overall, "warn");
    assert_no_address(&data);
    w.shutdown().await;
}

/// No rendezvous candidate: nothing is tried, and the finding says what to
/// run. The pin without an address is still flagged, as before.
#[tokio::test(flavor = "multi_thread")]
async fn doctor_without_a_rendezvous_says_so() {
    capture_punch_lines();
    let w = world(WorldOptions {
        pin_b_address: false,
        ..WorldOptions::default()
    })
    .await;
    let ops = w.a.ops.clone().with_punch(ClientPunch {
        rendezvous: Vec::new(),
        ..ClientPunch::default()
    });
    let data = doctor(&ops, "b").await;
    let punch = data.punch.as_ref().expect("data.punch");
    assert_eq!(punch.outcome, "no_rendezvous", "{data:?}");
    assert_eq!(punch.reason.as_deref(), Some("no_rendezvous"));
    assert_eq!(punch.rendezvous, None);
    assert_eq!(punch.elapsed_ms, None);
    let found = codes(&data);
    assert!(found.contains(&"punch_no_rendezvous"), "{found:?}");
    assert!(found.contains(&"host_pinned_without_address"), "{found:?}");
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "punch_no_rendezvous")
        .unwrap();
    assert_eq!(finding.status, "info");
    assert!(
        finding
            .remedy
            .as_deref()
            .is_some_and(|r| r.contains("qsh trust rendezvous")),
        "{finding:?}"
    );
    assert!(
        !events().iter().any(|e| e == "attempt"),
        "nothing was tried: {:?}",
        events()
    );
    assert_no_address(&data);
    w.shutdown().await;
}

/// `[punch].mode = off`: no punch, no object, no punch finding.
#[tokio::test(flavor = "multi_thread")]
async fn doctor_with_punching_off_tries_nothing() {
    capture_punch_lines();
    let w = world(WorldOptions {
        pin_b_address: false,
        ..WorldOptions::default()
    })
    .await;
    let ops = w.a.ops.clone().with_punch(ClientPunch {
        mode: PunchMode::Off,
        rendezvous: vec!["r".to_string()],
        ..ClientPunch::default()
    });
    let data = doctor(&ops, "b").await;
    assert_eq!(data.punch, None, "{data:?}");
    let found = codes(&data);
    assert!(
        !found.iter().any(|c| c.starts_with("punch_")),
        "no punch code: {found:?}"
    );
    assert!(events().is_empty(), "{:?}", events());
    w.shutdown().await;
}

// ---------------------------------------------------------------------------
// the log line carries no address (threat model D23)
// ---------------------------------------------------------------------------

/// Keys a `qsh::punch` line may carry. Each holds a count, a duration, or a
/// word; none can hold an address or a port.
const KEYS: &[&str] = &[
    "punch",
    "rendezvous",
    "host_v4",
    "host_v6",
    "reflexive_v4",
    "reflexive_v6",
    "rejected",
    "elapsed_ms",
    "kind",
    "family",
    "tag_rejected",
    "losers_closed",
    "reason",
    "outcome",
    "offered_candidates",
    "answered_candidates",
    "dropped_candidates",
    "answer_candidates",
    "punches_sent",
    "punches_heard",
    "handshakes",
    "connections",
    "refused",
    "failed",
];

/// Captures every `qsh::punch` line of one punch that succeeds and one that
/// fails, through a client, a rendezvous and a target, and asserts none holds
/// an address or a port: each line is one JSON object, its keys are the
/// documented ones, every string is a lowercase word (or `ipv4`/`ipv6`), every number an
/// integer, and the text has no address-shaped run.
#[tokio::test(flavor = "multi_thread")]
async fn qsh_punch_lines_carry_no_address_or_port_on_success_and_failure() {
    capture_punch_lines();

    let won = world(WorldOptions {
        pin_b_address: false,
        ..WorldOptions::default()
    })
    .await;
    let out = exec(&won.a.ops, "b").await.expect("exec over the punch");
    assert!(punched(&out));
    won.shutdown().await;
    let after_success = events();
    for event in ["attempt", "signaled", "adopted", "relayed", "window_opened"] {
        assert!(
            after_success.iter().any(|e| e == event),
            "{event} in {after_success:?}"
        );
    }

    let lost = world(WorldOptions {
        pin_b_address: false,
        register_b: false,
        ..WorldOptions::default()
    })
    .await;
    let err = exec(&lost.a.ops, "b").await.expect_err("no target");
    assert_eq!(err.details["punch"]["reason"], "target_not_registered");
    lost.shutdown().await;
    let all = events();
    assert!(all.iter().any(|e| e == "gave_up"), "{all:?}");

    let raw = lines().lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(!raw.is_empty());
    for line in &raw {
        for needle in ["198.51.100", "203.0.113", "10.", "192.168.", "127.0.0"] {
            assert!(!line.contains(needle), "{needle} in {line}");
        }
        let value: Value = serde_json::from_str(line).expect("pure JSON");
        let object = value.as_object().expect("one object per line");
        for (key, v) in object {
            assert!(KEYS.contains(&key.as_str()), "unexpected key {key}: {line}");
            match v {
                Value::Number(n) => assert!(n.is_u64(), "{key} is a count: {line}"),
                Value::String(s) => assert!(
                    matches!(s.as_str(), "ipv4" | "ipv6")
                        || (!s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
                    "{key} is a word, not an address: {line}"
                ),
                other => panic!("{key} holds {other}: {line}"),
            }
        }
    }
}
