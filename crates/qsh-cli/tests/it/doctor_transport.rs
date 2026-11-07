//! `qsh doctor <host>`'s `transport` object, the `qsh::adapt` line and the
//! two configuration keys behind them (ADR-0052 decisions 14 and 15,
//! `docs/CLI.md` §6.17, §6.23 and §7).
//!
//! The doctor tests dial a real `qsh serve` on loopback. Loopback has a
//! sub-millisecond RTT and no loss, so they pin the shape of the report and
//! the effect of the configuration pins, not particular latencies; the
//! policy table itself is pinned in `qsh-core`'s `adapt::tests`.

use crate::common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Fleet, HOST_ALIAS, Sandbox};
use qsh_core::{Ops, Paths, ScreenAttach, ScreenSync};
use qsh_proto::{EnvVar, SessionAttachReq, SessionOpenReq};
use qsh_testkit::shell::pty_shell;
use serde_json::Value;

use super::attach_recovery::with_deadline;

fn doctor_transport(fleet: &Fleet) -> (Value, Value) {
    let out = fleet.client.qsh(&["doctor", HOST_ALIAS, "--json"]);
    assert!(
        !out.stdout.is_empty(),
        "no envelope; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let env = common::sole_envelope(&out.stdout, &["doctor", HOST_ALIAS]);
    assert_eq!(common::exit_code(&out), 0, "{env}");
    (env["data"]["transport"].clone(), env["data"].clone())
}

fn codes(data: &Value) -> Vec<String> {
    data["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| f["code"].as_str().expect("code").to_string())
        .collect()
}

/// A healthy local `qsh serve` is measured: every documented field is there
/// with the documented type, the probe connection reports no bulk yield (it
/// carries no interactive traffic), and neither `info` finding fires because
/// this build offers both capabilities and loopback carries DATAGRAMs.
#[test]
fn doctor_host_reports_the_transport_object() {
    let fleet = Fleet::start();
    let (transport, data) = doctor_transport(&fleet);
    let t = transport.as_object().expect("data.transport is an object");
    let mut keys: Vec<&str> = t.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "bulk_yield",
            "frame_interval_ms",
            "keep_alive_ms",
            "loss_pct",
            "max_datagram_bytes",
            "min_rtt_ms",
            "nested",
            "prediction",
            "reasons",
            "rtt_ms",
            "rtt_var_ms",
            "screen_sync"
        ]
    );
    assert!(t["rtt_ms"].is_number() && t["rtt_var_ms"].is_number() && t["min_rtt_ms"].is_number());
    assert!(t["loss_pct"].as_f64().expect("loss") >= 0.0);
    assert!(
        t["max_datagram_bytes"]
            .as_u64()
            .expect("loopback DATAGRAM size")
            > 0,
        "{transport}"
    );
    assert_eq!(t["screen_sync"], "datagram", "{transport}");
    assert_eq!(
        t["bulk_yield"], "off",
        "no interactive traffic: {transport}"
    );
    assert_eq!(t["keep_alive_ms"], 15_000);
    assert_eq!(t["nested"], false);
    assert!(
        t["reasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .all(Value::is_string)
    );
    let found = codes(&data);
    assert!(
        !found
            .iter()
            .any(|c| c == "screen_sync_unsupported" || c == "datagram_unavailable"),
        "{found:?}"
    );

    // Human form: the block names the probe's blind spot.
    let human = fleet.client.qsh(&["doctor", HOST_ALIAS]);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("transport:"), "{text}");
    assert!(
        text.contains("this probe carries no interactive traffic, so bulk yield reads off here"),
        "{text}"
    );
}

/// Without a host there is nothing to measure: the field is absent, not null.
#[test]
fn doctor_without_a_host_has_no_transport_field() {
    let sandbox = Sandbox::initialized();
    let (code, env) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert!(env["data"].get("transport").is_none(), "{env}");
}

/// `[transport].adaptive = "off"` pins the knobs: fixed 20 ms frame interval,
/// no prediction, and the `user_override` reason, once.
#[test]
fn doctor_shows_the_adaptive_off_pin() {
    let fleet = Fleet::start();
    let (code, env) = fleet
        .client
        .json(&["config", "set", "transport.adaptive", "off", "--json"]);
    assert_eq!(code, 0, "{env}");
    let (transport, _) = doctor_transport(&fleet);
    assert_eq!(transport["frame_interval_ms"], 20, "{transport}");
    assert_eq!(transport["prediction"], "off");
    assert_eq!(transport["bulk_yield"], "off");
    assert_eq!(transport["keep_alive_ms"], 15_000);
    let reasons: Vec<&str> = transport["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert_eq!(
        reasons.iter().filter(|r| **r == "user_override").count(),
        1,
        "{reasons:?}"
    );
}

/// `[interactive].screen_sync = "off"` makes the report read `screen_sync:
/// off`, the same thing `--screen-sync=off` does to a session.
#[test]
fn doctor_shows_screen_sync_off_from_the_interactive_key() {
    let fleet = Fleet::start();
    let (code, env) =
        fleet
            .client
            .json(&["config", "set", "interactive.screen_sync", "off", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert!(
        env["data"].get("applies_from").is_none(),
        "read per command: {env}"
    );
    let (transport, _) = doctor_transport(&fleet);
    assert_eq!(transport["screen_sync"], "off", "{transport}");
}

/// A bad value never reaches `config.toml`, and one written by hand makes the
/// interactive default fail closed (`CONFIG_ERROR`) instead of guessing.
#[test]
fn the_new_keys_take_only_their_documented_values() {
    let sandbox = Sandbox::initialized();
    for (key, bad) in [
        ("transport.adaptive", "auto"),
        ("transport.adaptive", "true"),
        ("interactive.screen_sync", "sometimes"),
        ("interactive.predict", "sometimes"),
        ("interactive.predict", "on"),
        ("interactive.status_line", "auto"),
        ("interactive.status_line", "true"),
    ] {
        let (code, env) = sandbox.json(&["config", "set", key, bad, "--json"]);
        assert_eq!(code, 255, "{key}={bad}: {env}");
        assert_eq!(env["error"]["code"], "INVALID_ARGUMENT", "{env}");
    }
    let (code, env) = sandbox.json(&["config", "set", "transport.adaptive", "off", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["applies_from"], "next_start");
    let (code, env) = sandbox.json(&["config", "get", "interactive.screen_sync", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["set"], false);
    for (key, value) in [
        ("interactive.predict", "always"),
        ("interactive.status_line", "off"),
    ] {
        let (code, env) = sandbox.json(&["config", "set", key, value, "--json"]);
        assert_eq!(code, 0, "{key}: {env}");
        let (code, env) = sandbox.json(&["config", "get", key, "--json"]);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["data"]["value"], value, "{env}");
    }
}

// ---------------------------------------------------------------------------
// The attach side: the policy report and the `qsh::adapt` line
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

struct CaptureAdapt(Lines);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureAdapt {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != qsh_core::adapt::TARGET {
            return;
        }
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        (self.0).0.lock().expect("not poisoned").push(message.0);
    }
}

fn attach_open_req() -> SessionOpenReq {
    SessionOpenReq {
        host: HOST_ALIAS.to_string(),
        argv: pty_shell(),
        env: vec![EnvVar {
            name: "LANG".into(),
            value: "C".into(),
        }],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
        shell_command: None,
    }
}

/// An interactive screen attach keeps a policy report current and says so on
/// `qsh::adapt` as one pure-JSON line (the first sample counts as a change).
#[test]
fn an_interactive_attach_publishes_the_policy_report_and_the_adapt_line() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let lines = Lines::default();
    let subscriber = tracing_subscriber::registry().with(CaptureAdapt(lines.clone()));
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber in this test");

    let fleet = Fleet::start();
    let ops = Ops::new(Paths::new(
        fleet.client.config_dir(),
        fleet.client.state_dir(),
    ));
    let seen = lines.clone();
    with_deadline("policy report", move || {
        let screen = Some(ScreenAttach {
            mode: ScreenSync::Auto,
            cols: 80,
            rows: 24,
            predict: Default::default(),
            status_line: Default::default(),
        });
        let opened = ops
            .session_open_interactive(attach_open_req(), false, screen)
            .expect("open");
        let stream = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref,
                    no_steal: false,
                },
                &[],
                screen,
            )
            .expect("attach");
        let started = Instant::now();
        let report = loop {
            if let Some(report) = stream.adapt_report() {
                break report;
            }
            assert!(started.elapsed() < Duration::from_secs(10), "no report");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(report.screen_sync, "datagram");
        assert_eq!(report.bulk_yield, "off");
        assert!(report.max_datagram_bytes.is_some());

        let captured = seen.0.lock().expect("not poisoned").clone();
        assert_eq!(
            captured.len(),
            1,
            "one line for the first sample: {captured:?}"
        );
        let line: Value = serde_json::from_str(&captured[0]).expect("pure JSON");
        assert_eq!(line["adapt"], "policy");
        assert_eq!(line["screen_sync"], "datagram");
        assert!(line.get("reasons").is_some());
        stream.close();
    });
}
