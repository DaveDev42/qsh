//! `PLAN.md` M5 Step 6 (PR 6a): the enforcement flip, exercised against the
//! real `qsh` binary. `crates/qsh-core/src/serve.rs`'s `host_runtime` and
//! `crates/qsh-core/src/reverse/listen.rs`'s controller both now build their
//! `Authorizer` from `acl.toml` (`qsh_core::acl::load_or_deny`) instead of
//! the M1–M4 interim `AllowAllPinned` — these are the owed L2/L3/L5 tests
//! `PLAN.md` (c) lists for that flip, minus (4) the CA-path round trip
//! (`crates/qsh-core/src/acl/load.rs`'s own `load_or_deny_*` tests: no CA
//! issuance harness exists at the real-binary level yet — private CA is M6
//! scope, `crates/qsh-core/src/trust/mod.rs`'s own doc) and (6) the file-
//! mode warning (also `acl/load.rs`, a unix-only `PolicySource::load_path`
//! unit concern, nothing a subprocess-level test would add to).
//!
//! Every test here uses [`common::ServeGuard::start_without_policy`] /
//! [`common::ListenGuard::start_without_policy`] instead of `Fleet`/
//! `start`/`start_with`: those plant a permissive `acl.toml` automatically
//! (`common/mod.rs`'s `plant_allow_all_acl`) so every *other* fixture in
//! this crate keeps behaving the way it did under `AllowAllPinned` — the
//! opposite of what a default-deny test needs.

mod common;

use common::{CLIENT_ALIAS, CLIENT_PRINCIPAL, HOST_ALIAS, Sandbox, ServeGuard};
#[cfg(unix)]
use common::{ListenGuard, ReverseGuard};
#[cfg(unix)]
use common::{hosts_array, wait_for_audit};
use serde_json::Value;

/// The exact, invariant `PERMISSION_DENIED` wording
/// (`qsh_core::acl::PERMISSION_DENIED_MESSAGE`), copied rather than
/// imported for the same reason `reverse_unreachable_diagnostic.rs` copies
/// `doctor::CONTROLLER_UNREACHABLE`'s text: this file's point is to observe
/// what a real subprocess actually put on the wire/into its envelope, not
/// to call into the constant directly (`crates/qsh-core/src/acl/mod.rs`'s
/// own tests already pin the constant itself).
const PERMISSION_DENIED_MESSAGE: &str =
    "peer is not allowed to perform this operation on this host";

/// Owed test (1): a host with no `acl.toml` at all denies a pinned peer's
/// `exec.run` with the uniform message, records exactly one `deny` and no
/// `allow`, and prints the startup diagnostic on stderr exactly once.
/// "Zero child processes" is not independently re-proven here as an OS
/// process-table assertion — `crates/qsh-core/src/server/mod.rs`'s
/// `Server::authorize` call for `Action::ExecRun` gates before anything
/// resembling a spawn (`CLAUDE.md`: "never create a resource before
/// authorization succeeds"); this test's `data`-less error envelope is the
/// observable consequence of that ordering; a real process-table check
/// would only re-verify the interpreter, not this crate's own logic.
#[test]
fn no_acl_toml_denies_exec_run_uniformly_and_prints_the_startup_diagnostic_once() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    let mut serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");
    assert_eq!(
        value["error"]["message"], PERMISSION_DENIED_MESSAGE,
        "{value}"
    );
    assert!(
        value["data"].is_null(),
        "a denied op must carry no data: {value}"
    );

    let records = common::wait_for_audit(&host, "an exec.run deny", |record| {
        record["action"] == "exec.run" && record["decision"] == "deny"
    });
    let exec_records: Vec<&Value> = records
        .iter()
        .filter(|r| r["action"] == "exec.run")
        .collect();
    assert_eq!(
        exec_records.len(),
        1,
        "exactly one exec.run audit line: {records:#?}"
    );
    assert_eq!(
        exec_records[0]["principal"], CLIENT_PRINCIPAL,
        "{records:#?}"
    );
    assert!(
        exec_records[0]["rule"].is_null(),
        "DenyAll never matches a rule: {records:#?}"
    );
    assert!(
        !records.iter().any(|r| r["decision"] == "allow"),
        "nothing should ever have been allowed: {records:#?}"
    );

    let output = serve.finish();
    assert!(
        output.stdout.is_empty(),
        "qsh serve must never write to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let diagnostic_lines: Vec<&String> = output
        .stderr
        .iter()
        .filter(|line| line.contains("no usable acl.toml policy"))
        .collect();
    assert_eq!(
        diagnostic_lines.len(),
        1,
        "the startup diagnostic must print exactly once: {:#?}",
        output.stderr
    );
    assert!(
        diagnostic_lines[0].contains("acl_policy_missing"),
        "{diagnostic_lines:?}"
    );
}

/// Owed test (2): a corrupt `acl.toml` denies exactly like a missing one,
/// its diagnostic names `CONFIG_ERROR`, and stdout stays pure JSON in both
/// `--json` and `--jsonl` mode (`docs/CLI.md` §2.2) — a policy load failure
/// must never leak a byte of it onto the machine-mode stream.
#[test]
fn corrupt_acl_toml_denies_and_stdout_stays_pure_json_in_json_and_jsonl_modes() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    std::fs::write(
        host.config_dir().join("acl.toml"),
        "this is not [ valid toml",
    )
    .expect("write corrupt acl.toml");
    let mut serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    for mode in ["--json", "--jsonl"] {
        let output = client.qsh(&["exec", HOST_ALIAS, mode, "--", "true"]);
        let text = std::str::from_utf8(&output.stdout).expect("stdout must be utf-8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "{mode}: exactly one stdout line, got {text:?}"
        );
        let value: Value = serde_json::from_str(lines[0])
            .unwrap_or_else(|e| panic!("{mode}: stdout line is not JSON: {e}: {lines:?}"));
        assert_eq!(value["schema"], "qsh.cli/v1", "{mode}: {value}");
        assert_eq!(
            value["error"]["code"], "PERMISSION_DENIED",
            "{mode}: {value}"
        );
        assert_eq!(
            value["error"]["message"], PERMISSION_DENIED_MESSAGE,
            "{mode}: {value}"
        );
    }

    let output = serve.finish();
    assert!(
        output.stdout.is_empty(),
        "qsh serve must never write to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let diagnostic_lines: Vec<&String> = output
        .stderr
        .iter()
        .filter(|line| line.contains("no usable acl.toml policy"))
        .collect();
    assert_eq!(
        diagnostic_lines.len(),
        1,
        "exactly once: {:#?}",
        output.stderr
    );
    assert!(
        diagnostic_lines[0].contains("acl_policy_invalid"),
        "{diagnostic_lines:?}"
    );
    assert!(
        output
            .stderr
            .iter()
            .any(|line| line.contains("CONFIG_ERROR")),
        "the diagnostic must name CONFIG_ERROR: {:#?}",
        output.stderr
    );
    // F1 discipline (`acl/load.rs`): the invalid-policy diagnostic must
    // never echo `acl.toml` source content.
    assert!(
        !output
            .stderr
            .iter()
            .any(|line| line.contains("this is not")),
        "the diagnostic must never echo acl.toml content: {:#?}",
        output.stderr
    );
}

/// Owed test (3): a minimal, explicit `acl.toml` that allows exactly
/// `exec.run` lets `exec.run` through and still denies `session.open` — the
/// two audit records show the matching rule index and its absence,
/// respectively.
#[test]
fn minimal_allow_policy_grants_exec_run_and_denies_session_open() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    std::fs::write(
        host.config_dir().join("acl.toml"),
        format!("[[acl]]\nprincipal = \"{CLIENT_PRINCIPAL}\"\nallow = [\"exec.run\"]\n"),
    )
    .expect("write minimal acl.toml");
    // `ServeGuard::start` (not `_without_policy`): `plant_allow_all_acl` is
    // a no-op here since `acl.toml` already exists — this call is the
    // ordinary happy path, deliberately not the bypass, to also prove the
    // "already exists → never clobbered" half of the harness fix.
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let (code, value) = client.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], true, "{value}");

    let (code, value) = client.json(&["session", "open", HOST_ALIAS, "--json"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "PERMISSION_DENIED", "{value}");

    let records = common::wait_for_audit(&host, "a session.open deny", |record| {
        record["action"] == "session.open" && record["decision"] == "deny"
    });
    let exec_allow = records
        .iter()
        .find(|r| r["action"] == "exec.run" && r["decision"] == "allow")
        .unwrap_or_else(|| panic!("no exec.run allow record: {records:#?}"));
    assert_eq!(exec_allow["rule"], 0, "{exec_allow}");
    let session_deny = records
        .iter()
        .find(|r| r["action"] == "session.open" && r["decision"] == "deny")
        .unwrap_or_else(|| panic!("no session.open deny record: {records:#?}"));
    assert!(session_deny["rule"].is_null(), "{session_deny}");
}

/// Owed test (5): the controller side of the flip. `qsh listen` with no
/// `acl.toml` denies every `host.reverse` registration attempt — the
/// target never appears in `host.list`, and the controller's audit log
/// shows only denies, never an allow (`crates/qsh-core/src/reverse/admit.rs`'s
/// `host.reverse` choke point holds through the policy path, not just the
/// old hardcoded one).
#[test]
#[cfg(unix)]
fn listen_without_acl_toml_denies_every_reverse_registration() {
    const TARGET_ALIAS: &str = "denied-target";
    let controller = Sandbox::new();
    let target = Sandbox::new();
    let controller_fp = controller.fingerprint();
    let target_fp = target.fingerprint();
    controller.trust_add(TARGET_ALIAS, None, &target_fp);
    let listen = ListenGuard::start_without_policy(&controller, "127.0.0.1:0");
    target.trust_add("hub", Some(listen.addr()), &controller_fp);
    // Fast, low-jitter backoff so the target retries (and the deny is
    // re-exercised) promptly within this test's bounded wait.
    std::fs::write(
        target.config_dir().join("config.toml"),
        "[reverse]\nbackoff_initial_ms = 10\nbackoff_max_ms = 40\nbackoff_jitter_pct = 0\n",
    )
    .expect("write config.toml");
    let _reverse = ReverseGuard::start(&target, "hub");

    let records = wait_for_audit(&controller, "a host.reverse deny", |record| {
        record["action"] == "host.reverse" && record["decision"] == "deny"
    });
    assert!(
        !records
            .iter()
            .any(|r| r["action"] == "host.reverse" && r["decision"] == "allow"),
        "no reverse registration should ever have been allowed: {records:#?}"
    );

    let hosts = hosts_array(&controller);
    assert!(
        hosts.is_empty(),
        "a denied registration must never appear in host.list: {hosts:?}"
    );

    // F6 (`PLAN.md` M5 Step 6 PR 6a adversarial ④): the controller's own
    // startup diagnostic — deleting the `on_policy_diagnostic` call
    // entirely in `crates/qsh-core/src/reverse/listen.rs`'s `run_listen`
    // still left every test in this file green before this assertion
    // existed (`ListenGuard` discarded stderr outright). Assert it
    // actually printed, exactly once.
    let controller_stderr = listen.stderr_lines();
    let diagnostic_lines: Vec<&String> = controller_stderr
        .iter()
        .filter(|line| line.contains("no usable acl.toml policy"))
        .collect();
    assert_eq!(
        diagnostic_lines.len(),
        1,
        "the controller's startup diagnostic must print exactly once: {:#?}",
        controller_stderr
    );
}
