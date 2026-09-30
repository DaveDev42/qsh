//! `QSH_PERF_OUT` / `QSH_PERF_INJECT_DELAY_MS` plumbing for the two perf
//! tests. Exercises the harness helpers with explicit
//! paths, so no process environment is mutated.

use qsh_testkit::perf::{append_line, inject_policy, parse_inject_delay_ms};
use serde_json::json;

#[test]
fn perf_out_appends_one_json_line_per_run_and_changes_nothing_when_unset() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("perf-out.jsonl");

    // Unset: no file appears and the call succeeds.
    append_line(None, &json!({"test": "a"})).unwrap();
    assert!(!out.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

    // Set: one line per call, each a whole JSON object, in call order.
    append_line(
        Some(&out),
        &json!({"test": "tunnel_throughput", "throughput_mbps": 512.5}),
    )
    .unwrap();
    append_line(
        Some(&out),
        &json!({"test": "tunnel_echo_under_load", "echo_p95_ms": 1.25}),
    )
    .unwrap();
    let text = std::fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text:?}");
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(first["throughput_mbps"], 512.5);
    assert_eq!(second["echo_p95_ms"], 1.25);

    // The injection knob: only a positive integer turns it on.
    assert_eq!(parse_inject_delay_ms(None), 0);
    assert_eq!(parse_inject_delay_ms(Some("")), 0);
    assert_eq!(parse_inject_delay_ms(Some("abc")), 0);
    assert_eq!(parse_inject_delay_ms(Some("0")), 0);
    assert_eq!(parse_inject_delay_ms(Some(" 40 ")), 40);
    assert!(inject_policy(0).is_none());
    assert!(inject_policy(40).is_some());
}
