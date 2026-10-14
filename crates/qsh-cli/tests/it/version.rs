//! Integration test for the `qsh version` vertical slice: op layer → JSON
//! renderer → exit code, exercised as an actual subprocess.

use std::process::Command;

fn qsh() -> Command {
    Command::new(env!("CARGO_BIN_EXE_qsh"))
}

#[test]
fn version_json_envelope() {
    let output = qsh()
        .args(["version", "--json"])
        .output()
        .expect("failed to run qsh binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid utf-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one JSON line, got: {stdout:?}"
    );

    let value: serde_json::Value =
        serde_json::from_str(lines[0]).expect("stdout line must be valid JSON");
    assert_eq!(value["schema"], "qsh.cli/v1");
    assert_eq!(value["command"], "version.get");
    assert_eq!(value["ok"], true);
    assert!(value["data"]["version"].as_str().is_some());
    assert!(value["request_id"].as_str().is_some());
}

#[test]
fn bad_flag_exits_with_usage_error() {
    let output = qsh()
        .args(["--not-a-real-flag"])
        .output()
        .expect("failed to run qsh binary");

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn json_and_jsonl_together_is_a_usage_error() {
    let output = qsh()
        .args(["--json", "--jsonl", "version"])
        .output()
        .expect("failed to run qsh binary");

    assert_eq!(output.status.code(), Some(2));
}
