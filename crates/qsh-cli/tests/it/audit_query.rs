//! L6 CLI: `qsh audit` (`docs/CLI.md` §6.22, ADR-0033 decisions 4-10 and 13)
//! through the real binary.
//!
//! The op and reader are covered in `qsh-core`; what only a spawned `qsh`
//! can show is the output contract (one pure envelope line, human tables
//! that never echo a skipped line), the exit codes, that a query leaves the
//! state directory byte for byte alone, and that one machine reads back the
//! records it wrote as a forward host (`qsh serve`), a reverse listener
//! (`qsh listen`) and a reverse target (`qsh serve --to`) in the same shape.
//! Every test except the route one runs on all three CI legs.

use crate::common;

use common::{Sandbox, exit_code, sole_envelope};
use qsh_core::audit::AuditRecord;
use serde_json::Value;

/// A string that must never reach any output stream: it is planted inside a
/// log line the reader cannot use.
const SECRET: &str = "SECRET-PAYLOAD-must-not-leak";

/// Record `n` of a fixed series: `n` seconds after 2026-10-16T01:00:00Z.
fn record(n: u32, principal: &str, action: &str, resource: &str, decision: &str) -> AuditRecord {
    AuditRecord {
        ts: format!("2026-10-16T01:00:{n:02}Z"),
        request_id: n.to_string(),
        principal: principal.to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        decision: decision.to_string(),
        rule: (decision == "allow").then_some(0),
        auth_path: "pin".to_string(),
        peer_addr: "100.64.0.7:51234".to_string(),
        count: None,
        role: None,
    }
}

/// The fixed series every fixture and filter test reads.
pub(crate) fn series() -> Vec<AuditRecord> {
    let mut with_role = record(4, "device:ci", "session.open", "session", "allow");
    with_role.role = Some("exec".to_string());
    vec![
        record(1, "device:laptop", "exec.run", "exec", "allow"),
        record(
            2,
            "device:laptop",
            "file.write",
            "/srv/builds/app.tar.zst",
            "deny",
        ),
        record(3, "device:phone", "exec.run", "exec", "deny"),
        with_role,
    ]
}

fn log_path(sandbox: &Sandbox) -> std::path::PathBuf {
    sandbox.state_dir().join("audit.log")
}

/// Write `records` as the writer would (one JSON object per line), after an
/// optional unusable line, replacing any log already there.
pub(crate) fn plant(sandbox: &Sandbox, records: &[AuditRecord], unusable_line: Option<&str>) {
    std::fs::create_dir_all(sandbox.state_dir()).expect("create state dir");
    let mut text = String::new();
    for (index, record) in records.iter().enumerate() {
        text.push_str(&serde_json::to_string(record).expect("encode record"));
        text.push('\n');
        if index == 0
            && let Some(line) = unusable_line
        {
            text.push_str(line);
            text.push('\n');
        }
    }
    std::fs::write(log_path(sandbox), text).expect("write audit.log");
}

/// `qsh audit <args> --json`: the exit code and the sole envelope.
fn audit_json(sandbox: &Sandbox, args: &[&str]) -> (i32, Value) {
    let mut argv = vec!["audit"];
    argv.extend_from_slice(args);
    argv.push("--json");
    sandbox.json(&argv)
}

fn request_ids(envelope: &Value) -> Vec<String> {
    envelope["data"]["records"]
        .as_array()
        .expect("data.records")
        .iter()
        .map(|r| r["request_id"].as_str().expect("request_id").to_string())
        .collect()
}

/// A line the reader cannot parse, with a secret inside it.
fn torn_line() -> String {
    format!("{{\"ts\":\"2026-10-16T01:00:00Z\",\"principal\":\"{SECRET}")
}

/// No log yet is an empty answer, not an error: the file is created lazily
/// on the first decision.
#[test]
fn audit_query_on_a_missing_log_is_an_empty_envelope_through_the_binary() {
    let sandbox = Sandbox::initialized();
    let (code, envelope) = audit_json(&sandbox, &[]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(envelope["command"], "audit.query", "{envelope}");
    assert_eq!(envelope["data"]["records"], serde_json::json!([]));
    assert_eq!(envelope["data"]["skipped_lines"], 0);
    assert_eq!(envelope["data"]["oldest_ts"], Value::Null);
    assert_eq!(envelope["data"]["truncated"], false);
    assert!(
        !log_path(&sandbox).exists(),
        "reading a missing log must not create it"
    );

    let human = sandbox.qsh(&["audit"]);
    assert_eq!(exit_code(&human), 0);
    assert_eq!(String::from_utf8_lossy(&human.stdout), "no audit records\n");
}

/// Newest first, AND-combined exact filters, and `oldest_ts` independent of
/// the filters.
#[test]
fn audit_query_orders_newest_first_and_ands_exact_filters_through_the_binary() {
    let sandbox = Sandbox::initialized();
    plant(&sandbox, &series(), None);

    let (code, all) = audit_json(&sandbox, &[]);
    assert_eq!(code, 0, "{all}");
    assert_eq!(request_ids(&all), ["4", "3", "2", "1"]);
    assert_eq!(all["data"]["oldest_ts"], "2026-10-16T01:00:01Z");
    // The `role` key shows only on the record that stored one.
    let records = all["data"]["records"].as_array().unwrap();
    assert_eq!(records[0]["role"], "exec");
    assert!(records[1].get("role").is_none(), "{}", records[1]);
    assert!(records[1].get("count").is_none(), "{}", records[1]);

    let (_, laptop) = audit_json(&sandbox, &["--principal", "device:laptop"]);
    assert_eq!(request_ids(&laptop), ["2", "1"]);
    let (_, denied_laptop) = audit_json(
        &sandbox,
        &["--principal", "device:laptop", "--decision", "deny"],
    );
    assert_eq!(request_ids(&denied_laptop), ["2"]);
    // Exact match, not a prefix or a substring.
    let (_, partial) = audit_json(&sandbox, &["--principal", "device:lap"]);
    assert_eq!(request_ids(&partial), Vec::<String>::new());
    let (_, by_resource) = audit_json(&sandbox, &["--resource", "/srv/builds/app.tar.zst"]);
    assert_eq!(request_ids(&by_resource), ["2"]);
    let (_, by_action) = audit_json(&sandbox, &["--action", "exec.run"]);
    assert_eq!(request_ids(&by_action), ["3", "1"]);
    // `oldest_ts` ignores every filter.
    assert_eq!(by_resource["data"]["oldest_ts"], "2026-10-16T01:00:01Z");

    let (_, window) = audit_json(
        &sandbox,
        &[
            "--since",
            "2026-10-16T01:00:02Z",
            "--until",
            "2026-10-16T01:00:03Z",
        ],
    );
    assert_eq!(request_ids(&window), ["3", "2"]);
    // A relative span counts back from the real clock. Neither record is
    // compared against a clock read here: one is dated far in the past and
    // one far in the future, so `--since 1s` keeps exactly the second.
    let mut old = record(1, "device:laptop", "exec.run", "exec", "allow");
    old.ts = "2000-01-01T00:00:00Z".to_string();
    let mut future = record(2, "device:laptop", "exec.run", "exec", "allow");
    future.ts = "2999-01-01T00:00:00Z".to_string();
    plant(&sandbox, &[old, future], None);
    let (code, recent) = audit_json(&sandbox, &["--since", "1s"]);
    assert_eq!(code, 0, "{recent}");
    assert_eq!(request_ids(&recent), ["2"]);
}

/// `truncated` is true only when `--limit` cut matching records.
#[test]
fn audit_query_limit_truncates_and_reports_it_through_the_binary() {
    let sandbox = Sandbox::initialized();
    plant(&sandbox, &series(), None);

    let (_, cut) = audit_json(&sandbox, &["--limit", "2"]);
    assert_eq!(request_ids(&cut), ["4", "3"]);
    assert_eq!(cut["data"]["truncated"], true);
    let (_, exact) = audit_json(&sandbox, &["--limit", "4"]);
    assert_eq!(exact["data"]["truncated"], false);
    let (_, filtered) = audit_json(&sandbox, &["--limit", "1", "--decision", "allow"]);
    assert_eq!(filtered["data"]["truncated"], true);
}

/// A bad filter value is `INVALID_ARGUMENT` with exit 255 in both machine
/// modes, never a clap usage error (exit 2), and the message has all three
/// parts of the failure-text discipline.
#[test]
fn audit_query_bad_filters_are_invalid_argument_through_the_binary() {
    let sandbox = Sandbox::initialized();
    plant(&sandbox, &series(), None);
    for args in [
        vec!["--limit", "0"],
        vec!["--limit", "1001"],
        vec!["--limit", "4294967295"],
        vec!["--decision", "maybe"],
        vec!["--since", "yesterday"],
        vec!["--since", "5x"],
        vec!["--until", "24h"],
    ] {
        let (code, envelope) = audit_json(&sandbox, &args);
        assert_eq!(code, 255, "{args:?}: {envelope}");
        assert_eq!(envelope["ok"], false, "{args:?}: {envelope}");
        assert_eq!(envelope["command"], "audit.query", "{args:?}");
        assert_eq!(
            envelope["error"]["code"], "INVALID_ARGUMENT",
            "{args:?}: {envelope}"
        );
        let message = envelope["error"]["message"].as_str().unwrap();
        assert!(message.contains("so nothing was read"), "{message}");
        assert!(message.contains("`qsh audit"), "{message}");
    }
    // A value clap cannot even read as a number is a usage error.
    let usage = sandbox.qsh(&["audit", "--limit", "many"]);
    assert_eq!(exit_code(&usage), 2);
}

/// There is no remote form: a host operand is a usage error (exit 2), not a
/// dial (ADR-0033 decision 4).
#[test]
fn audit_query_has_no_remote_form_through_the_binary() {
    let sandbox = Sandbox::initialized();
    let output = sandbox.qsh(&["audit", "somehost"]);
    assert_eq!(exit_code(&output), 2);
    assert!(output.stdout.is_empty());
}

/// A `config.toml` that does not parse is `CONFIG_ERROR`; the reader does
/// not fall back to the default path.
#[test]
fn audit_query_with_an_unparseable_config_is_config_error_through_the_binary() {
    let sandbox = Sandbox::initialized();
    plant(&sandbox, &series(), None);
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        "[audit\nnot toml at all",
    )
    .expect("write config.toml");
    let (code, envelope) = audit_json(&sandbox, &[]);
    assert_eq!(code, 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "CONFIG_ERROR", "{envelope}");
}

/// `[audit].path` moves the log; the query follows it.
#[test]
fn audit_query_follows_the_configured_audit_path_through_the_binary() {
    let sandbox = Sandbox::initialized();
    let moved = sandbox.state_dir().join("moved").join("trail.log");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    plant(&sandbox, &series()[..1], None);
    std::fs::write(
        &moved,
        format!(
            "{}\n",
            serde_json::to_string(&record(9, "device:moved", "exec.run", "exec", "allow")).unwrap()
        ),
    )
    .unwrap();
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        format!("[audit]\npath = {:?}\n", moved.display().to_string()),
    )
    .unwrap();
    let (code, envelope) = audit_json(&sandbox, &[]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(request_ids(&envelope), ["9"]);
}

/// A log the account cannot read is `INTERNAL` naming the path and the error
/// kind, and no line content (ADR-0033 decision 6).
#[cfg(unix)]
#[test]
fn audit_query_unreadable_log_is_internal_with_path_and_kind_only_through_the_binary() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::initialized();
    plant(&sandbox, &series(), Some(&torn_line()));
    let log = log_path(&sandbox);
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&log).is_ok() {
        // Running as root: a mode-000 file still opens, so there is no
        // unreadable log to observe.
        return;
    }
    let (code, envelope) = audit_json(&sandbox, &[]);
    assert_eq!(code, 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INTERNAL", "{envelope}");
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(message.contains(&log.display().to_string()), "{message}");
    assert!(message.contains("permission denied"), "{message}");
    assert!(!message.contains(SECRET), "{message}");
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// `qsh audit` is a read: the log bytes and the state directory's file list
/// are the same after any number of queries, in every output mode.
#[test]
fn audit_query_writes_no_audit_record_through_the_binary() {
    let sandbox = Sandbox::initialized();
    plant(&sandbox, &series(), Some(&torn_line()));
    let list = || {
        let mut names: Vec<String> = std::fs::read_dir(sandbox.state_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let bytes_before = std::fs::read(log_path(&sandbox)).unwrap();
    let files_before = list();

    for args in [
        vec!["audit"],
        vec!["audit", "--json"],
        vec!["audit", "--jsonl"],
        vec!["audit", "--decision", "deny", "--limit", "1", "--json"],
        vec!["audit", "--limit", "0", "--json"],
    ] {
        let _ = sandbox.qsh(&args);
    }

    assert_eq!(std::fs::read(log_path(&sandbox)).unwrap(), bytes_before);
    assert_eq!(
        list(),
        files_before,
        "no record, no lock sidecar, no rotation"
    );
}

/// In both machine modes stdout is exactly one `qsh.cli/v1` line at any
/// verbosity; everything else goes to stderr.
#[test]
fn audit_query_envelope_is_the_only_stdout_line() {
    let sandbox = Sandbox::initialized();
    plant(&sandbox, &series(), Some(&torn_line()));
    for (label, args) in [
        ("--json -vvv", ["audit", "--json", "-vvv"]),
        ("--jsonl -vv", ["audit", "--jsonl", "-vv"]),
    ] {
        let output = sandbox.qsh(&args);
        assert_eq!(exit_code(&output), 0, "{label}");
        let stdout = String::from_utf8(output.stdout.clone()).unwrap();
        assert_eq!(stdout.lines().count(), 1, "{label}: {stdout:?}");
        let envelope = sole_envelope(&output.stdout, &args);
        assert_eq!(envelope["command"], "audit.query", "{label}");
        assert_eq!(envelope["data"]["skipped_lines"], 1, "{label}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(SECRET), "{label}: {stderr}");
    }
    // The failure path keeps the same promise.
    let output = sandbox.qsh(&["audit", "--limit", "0", "--json", "-vvv"]);
    assert_eq!(exit_code(&output), 255);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
}

/// The human table never prints the content of a line it skipped, on either
/// stream; it reports the count and the retention horizon on stderr.
#[test]
fn audit_query_human_mode_never_prints_skipped_line_contents() {
    let sandbox = Sandbox::initialized();
    let mut records = series();
    // A record over the 64 KiB line cap is skipped and counted too.
    records[1].resource = "x".repeat(70 * 1024);
    plant(&sandbox, &records, Some(&torn_line()));

    let output = sandbox.qsh(&["audit"]);
    assert_eq!(exit_code(&output), 0);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(!text.contains(SECRET), "{stream}: {text}");
        assert!(!text.contains("xxxxxxxx"), "{stream} echoed the long line");
    }
    assert!(stdout.starts_with("TS "), "{stdout}");
    assert!(stdout.contains("device:phone"), "{stdout}");
    assert!(
        stderr.contains("skipped 2 unreadable audit log lines"),
        "{stderr}"
    );
    assert!(
        stderr.contains("oldest retained record: 2026-10-16T01:00:01Z"),
        "{stderr}"
    );
    // stdout is the table alone: no summary line leaks into it.
    assert!(!stdout.contains("qsh:"), "{stdout}");

    let cut = sandbox.qsh(&["audit", "--limit", "1"]);
    let cut_stderr = String::from_utf8_lossy(&cut.stderr);
    assert!(cut_stderr.contains("more match"), "{cut_stderr}");
}

// ---------------------------------------------------------------------------
// route equivalence (ADR-0033 decision 13)
// ---------------------------------------------------------------------------

/// The keys an `AuditRecordView` may carry. The first nine are always
/// present.
const VIEW_KEYS: &[&str] = &[
    "ts",
    "request_id",
    "principal",
    "action",
    "resource",
    "decision",
    "rule",
    "auth_path",
    "peer_addr",
    "count",
    "role",
];

/// One machine writes audit records in all three roles (forward host,
/// reverse listener, reverse target), and `qsh audit` on that machine reads
/// all of them back in the same `AuditRecordView` shape, identical to the
/// stored line field for field (nothing enriched).
///
/// 1. `qsh serve`: a client execs on this device.
/// 2. `qsh listen`: a NAT target registers into this device.
/// 3. `qsh serve --to`: this device registers into a controller, which then
///    execs on it through the reverse route.
#[test]
fn audit_query_reads_records_written_by_serve_listen_and_serve_to() {
    use common::{HOST_ALIAS, ListenGuard, ReverseGuard, ServeGuard, hosts_array, poll_until};
    use std::collections::BTreeSet;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(60);

    let device = Sandbox::initialized();
    let device_fp = device.fingerprint();
    let client = Sandbox::initialized();
    let target = Sandbox::initialized();
    let controller = Sandbox::initialized();
    let client_fp = client.fingerprint();
    let target_fp = target.fingerprint();
    let controller_fp = controller.fingerprint();

    // --- Role 1: forward host.
    device.trust_add_with_role("laptop", None, &client_fp, "full");
    let serve = ServeGuard::start(&device);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &device_fp);
    let (code, envelope) = client.json(&common::exec_true_args(HOST_ALIAS));
    assert_eq!(code, 0, "forward host: {envelope}");
    common::wait_for_audit(&device, "the forward host's exec.run allow", |r| {
        r["action"] == "exec.run" && r["principal"] == "device:laptop" && r["decision"] == "allow"
    });
    drop(serve);

    // --- Role 2: reverse listener.
    device.trust_add_with_role("nat-target", None, &target_fp, "reverse");
    let listen = ListenGuard::start(&device);
    target.trust_add("hub", Some(listen.addr()), &device_fp);
    let reverse = ReverseGuard::start_serve_to(&target, "hub");
    poll_until("the target to register into this device", WAIT, || {
        hosts_array(&device)
            .iter()
            .any(|h| h["connection_mode"] == "reverse" && h["state"] == "reachable")
            .then_some(())
    });
    common::wait_for_audit(&device, "the listener's host.reverse allow", |r| {
        r["action"] == "host.reverse"
            && r["principal"] == "device:nat-target"
            && r["decision"] == "allow"
    });
    reverse.shut_down();
    drop(listen);

    // --- Role 3: reverse target.
    controller.trust_add_with_role("dev", None, &device_fp, "reverse");
    let controller_listen = ListenGuard::start(&controller);
    device.trust_add_with_role(
        "hub",
        Some(controller_listen.addr()),
        &controller_fp,
        "full",
    );
    let moved_target = ReverseGuard::start_serve_to(&device, "hub");
    poll_until("this device to register into the controller", WAIT, || {
        hosts_array(&controller)
            .iter()
            .any(|h| h["name"] == "dev" && h["state"] == "reachable")
            .then_some(())
    });
    let (code, envelope) = controller.json(&common::exec_true_args("dev"));
    assert_eq!(code, 0, "reverse target: {envelope}");
    common::wait_for_audit(&device, "the reverse target's exec.run allow", |r| {
        r["action"] == "exec.run" && r["principal"] == "device:hub" && r["decision"] == "allow"
    });
    moved_target.shut_down();

    // --- One query reads all three, newest first, field for field.
    let stored = device.audit_records();
    let (code, envelope) = audit_json(&device, &["--limit", "1000"]);
    assert_eq!(code, 0, "{envelope}");
    let shown = envelope["data"]["records"].as_array().expect("records");
    assert_eq!(envelope["data"]["skipped_lines"], 0, "{envelope}");
    assert_eq!(
        envelope["data"]["oldest_ts"], stored[0]["ts"],
        "oldest_ts is the first stored record"
    );
    let reversed: Vec<&Value> = stored.iter().rev().collect();
    assert_eq!(
        shown.iter().collect::<Vec<_>>(),
        reversed,
        "every stored line shows up, newest first, with no field added or changed"
    );

    // The three roles' records have the same shape and are each found by
    // the filters an operator would use.
    let roles = [
        ("forward host", "device:laptop", "exec.run"),
        ("reverse listener", "device:nat-target", "host.reverse"),
        ("reverse target", "device:hub", "exec.run"),
    ];
    let mut shapes = BTreeSet::new();
    for (role, principal, action) in roles {
        let (code, one) = audit_json(
            &device,
            &[
                "--principal",
                principal,
                "--action",
                action,
                "--decision",
                "allow",
            ],
        );
        assert_eq!(code, 0, "{role}: {one}");
        let records = one["data"]["records"].as_array().unwrap();
        assert!(!records.is_empty(), "{role}: {one}");
        for record in records {
            let keys: BTreeSet<&str> = record
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            for required in &VIEW_KEYS[..9] {
                assert!(
                    keys.contains(required),
                    "{role}: missing {required}: {record}"
                );
            }
            assert!(
                keys.iter().all(|k| VIEW_KEYS.contains(k)),
                "{role}: unexpected key in {record}"
            );
            shapes.insert(
                keys.iter()
                    .filter(|k| **k != "role" && **k != "count")
                    .count(),
            );
        }
    }
    assert_eq!(shapes.len(), 1, "the three roles' records differ in shape");
}
