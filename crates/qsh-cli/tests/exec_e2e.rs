//! M1's definition of done, exercised as real subprocesses over a real QUIC
//! connection (`docs/ROADMAP.md` M1 "수용 기준", `PLAN.md` Step 7).
//!
//! Each test brings up its own [`Fleet`]: a `qsh serve` host, a client the
//! host pins, and (where needed) a rogue identity the host does *not* pin.
//! Nothing is shared between tests, so the file behaves identically under
//! `cargo test` and `cargo nextest run`.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{AUDIT_KEYS, CLIENT_PRINCIPAL, Fleet, HOST_ALIAS, exit_code, sole_envelope};
use serde_json::Value;

/// DoD 1: `exec … 'echo out; echo err >&2; exit 7'` → exit 7, `ok:true`,
/// the right `stdout_b64`/`stderr_b64`/`remote_exit_code`.
#[test]
fn exec_json_reports_both_streams_and_the_remote_exit_code() {
    let fleet = Fleet::start();

    let (code, value) = fleet.exec_json(&["--", "sh", "-c", "echo out; echo err >&2; exit 7"]);

    assert_eq!(code, 7, "process exit code must be the remote one: {value}");
    assert_eq!(value["command"], "exec.run");
    assert_eq!(value["ok"], true, "{value}");
    let data = &value["data"];
    assert_eq!(data["stdout_b64"], BASE64.encode("out\n"));
    assert_eq!(data["stderr_b64"], BASE64.encode("err\n"));
    assert_eq!(data["remote_exit_code"], 7);
    assert_eq!(data["signal"], Value::Null);
    assert!(data["duration_ms"].is_u64(), "{data}");
}

/// Human mode is a byte-for-byte passthrough: the remote's stdout is ours,
/// the remote's stderr is ours, the exit code is the remote's
/// (`docs/CLI.md` §4, §6.8).
#[test]
fn exec_human_mode_passes_the_streams_through_verbatim() {
    let fleet = Fleet::start();

    let output = fleet.client.qsh(&[
        "exec",
        HOST_ALIAS,
        "--",
        "sh",
        "-c",
        "echo out; echo err >&2; exit 7",
    ]);

    assert_eq!(exit_code(&output), 7);
    assert_eq!(
        output.stdout,
        b"out\n",
        "stdout was {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("err\n"), "stderr was {stderr:?}");
}

/// DoD 2: an untrusted peer gets `AUTH_FAILED` (exit 255), and the host
/// records the rejection as a connection-level deny.
#[test]
fn an_untrusted_peer_is_rejected_and_the_denial_is_audited() {
    let fleet = Fleet::start();
    let rogue = fleet.rogue();

    let (code, value) = rogue.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);

    assert_eq!(code, 255, "{value}");
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["error"]["code"], "AUTH_FAILED", "{value}");
    assert_eq!(value["error"]["retryable"], false, "{value}");
    assert!(
        value["error"]["details"]["category"].as_str().is_some(),
        "AUTH_FAILED must carry a coarse category only: {value}"
    );

    let records = common::wait_for_audit(&fleet.host, "a connect deny", |record| {
        record["action"] == "connect" && record["decision"] == "deny"
    });
    let deny = records
        .iter()
        .find(|r| r["action"] == "connect")
        .expect("connect record");
    assert_eq!(
        deny["principal"], "-",
        "a rejected handshake has no principal"
    );
    assert_eq!(deny["request_id"], "-");
}

/// `docs/CLI.md` §4: a remote `255` becomes process exit `254` so it stays
/// distinguishable from qsh's own failures — but the JSON keeps the truth.
#[test]
fn a_remote_exit_of_255_is_clamped_to_254_but_reported_verbatim() {
    let fleet = Fleet::start();

    let (code, value) = fleet.exec_json(&["--", "sh", "-c", "exit 255"]);

    assert_eq!(code, 254, "{value}");
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(
        value["data"]["remote_exit_code"], 255,
        "the JSON is the source of truth for the real exit code"
    );
}

/// A non-terminal stdin is forwarded to the remote command.
#[test]
fn stdin_is_forwarded_to_the_remote_command() {
    let fleet = Fleet::start();

    let args = ["exec", HOST_ALIAS, "--json", "--", "cat"];
    let output = fleet.client.qsh_with_stdin(&args, b"round trip\n");

    assert_eq!(exit_code(&output), 0);
    let value = sole_envelope(&output.stdout, &args);
    assert_eq!(value["data"]["stdout_b64"], BASE64.encode("round trip\n"));
}

/// `--env NAME=VALUE` reaches the remote process's environment.
#[test]
fn env_flags_reach_the_remote_environment() {
    let fleet = Fleet::start();

    let (code, value) = fleet.exec_json(&[
        "--env",
        "QSH_TEST_ONE=first",
        "--env",
        "QSH_TEST_TWO=second",
        "--",
        "sh",
        "-c",
        "printf '%s/%s' \"$QSH_TEST_ONE\" \"$QSH_TEST_TWO\"",
    ]);

    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["stdout_b64"], BASE64.encode("first/second"));
}

/// `--timeout` gives up long before the remote command would finish
/// (`docs/CLI.md` §9), and reports it as `TIMEOUT`.
#[test]
fn a_timeout_fires_well_before_the_remote_command_finishes() {
    let fleet = Fleet::start();

    let started = std::time::Instant::now();
    let (code, value) = fleet.exec_json(&["--timeout", "300", "--", "sleep", "5"]);
    let elapsed = started.elapsed();

    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "TIMEOUT");
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "a 300 ms timeout took {elapsed:?}"
    );
}

/// DoD 4: `-v` diagnostics go to stderr only; stdout stays a single
/// parsable JSON line (`docs/CLI.md` §2.2).
#[test]
fn verbose_diagnostics_never_reach_stdout() {
    let fleet = Fleet::start();

    let args = ["exec", HOST_ALIAS, "-vv", "--json", "--", "echo", "quiet"];
    let output = fleet.client.qsh(&args);

    assert_eq!(exit_code(&output), 0);
    let value = sole_envelope(&output.stdout, &args);
    assert_eq!(value["command"], "exec.run");
    assert!(
        !output.stderr.is_empty(),
        "-vv must actually produce diagnostics, otherwise this proves nothing"
    );
}

/// `docs/CLI.md` §6.12 and `docs/design/architecture.md` §6: `qsh serve`
/// writes nothing to stdout, announces itself on stderr, and audits every
/// authorization decision with structural fields only.
#[test]
fn serve_keeps_stdout_empty_and_audits_structurally() {
    let mut fleet = Fleet::start();

    let (code, value) = fleet.exec_json(&["--", "true"]);
    assert_eq!(code, 0, "{value}");

    let records = common::wait_for_audit(&fleet.host, "an exec.run allow", |record| {
        record["action"] == "exec.run" && record["decision"] == "allow"
    });
    let allow = records
        .iter()
        .find(|r| r["action"] == "exec.run")
        .expect("exec.run record");
    assert_eq!(allow["principal"], CLIENT_PRINCIPAL);
    assert_eq!(allow["decision"], "allow");
    for record in &records {
        let keys: Vec<&str> = record
            .as_object()
            .expect("audit record is an object")
            .keys()
            .map(String::as_str)
            .collect();
        for key in &keys {
            assert!(
                AUDIT_KEYS.contains(key),
                "audit record carries unexpected key {key:?}: {record}"
            );
        }
    }

    let output = fleet.serve.finish();
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
    assert!(
        output.has_stderr_line_starting_with("qsh serve: identity "),
        "stderr: {:#?}",
        output.stderr
    );
}
