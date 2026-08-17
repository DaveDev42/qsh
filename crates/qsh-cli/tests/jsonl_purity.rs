//! JSONL purity (`docs/design/testing.md` L6, `docs/CLI.md` §2.2): run a
//! deliberately noisy command at high verbosity and assert that **every**
//! stdout line is still a complete `qsh.cli/v1` JSON object, with all the
//! diagnostics on stderr where they belong.
//!
//! `exec.run` is a value operation, so "every line" is exactly one line;
//! the point is that verbosity never adds a second one.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{Fleet, HOST_ALIAS, Sandbox, ServeGuard, exit_code};
use serde_json::Value;

/// A command that writes plenty of interleaved stdout and stderr.
const NOISY: &str = "for i in $(seq 1 200); do echo line$i; echo e$i >&2; done";

/// Assert that `stdout` is one or more lines, each a `qsh.cli/v1` object,
/// and return them.
fn parse_stdout_lines(stdout: &[u8], label: &str) -> Vec<Value> {
    let text = std::str::from_utf8(stdout).expect("stdout must be utf-8");
    assert!(!text.is_empty(), "{label}: stdout was empty");
    text.lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap_or_else(|err| {
                panic!("{label}: stdout line is not a complete JSON value: {err}: {line:?}")
            });
            assert!(
                value.is_object(),
                "{label}: every stdout line must be a JSON object, got {line:?}"
            );
            assert_eq!(value["schema"], "qsh.cli/v1", "{label}: {line:?}");
            value
        })
        .collect()
}

#[test]
fn a_noisy_exec_keeps_stdout_pure_json_at_every_verbosity() {
    let fleet = Fleet::start();

    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = fleet
            .client
            .qsh(&["exec", HOST_ALIAS, verbosity, mode, "--", "sh", "-c", NOISY]);

        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(
            lines.len(),
            1,
            "{label}: exec.run is a value operation — one envelope, one line"
        );
        let data = &lines[0]["data"];
        assert_eq!(lines[0]["command"], "exec.run", "{label}");

        // The remote's own noise rode the envelope, not our streams.
        let stdout_bytes = BASE64
            .decode(data["stdout_b64"].as_str().expect("stdout_b64"))
            .expect("stdout_b64 is Base64");
        let stderr_bytes = BASE64
            .decode(data["stderr_b64"].as_str().expect("stderr_b64"))
            .expect("stderr_b64 is Base64");
        assert_eq!(
            String::from_utf8_lossy(&stdout_bytes).lines().count(),
            200,
            "{label}"
        );
        assert_eq!(
            String::from_utf8_lossy(&stderr_bytes).lines().count(),
            200,
            "{label}"
        );

        assert!(
            !output.stderr.is_empty(),
            "{label}: the diagnostics have to be somewhere — stderr was empty"
        );
    }
}

/// `qsh serve` has no envelope at all: stdout stays empty no matter how
/// loud the diagnostics get (`docs/CLI.md` §6.12).
#[test]
fn serve_writes_nothing_to_stdout_even_at_high_verbosity() {
    let host = Sandbox::initialized();
    let mut serve = ServeGuard::start_with(&host, &["-vv"]);
    let output = serve.finish();

    assert!(
        output.stdout.is_empty(),
        "qsh serve wrote to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.has_stderr_line_starting_with("qsh serve: listening on "),
        "stderr: {:#?}",
        output.stderr
    );
}
