//! Golden `qsh.cli/v1` fixtures and their schema validation
//! (`docs/design/testing.md` L6, `PLAN.md` Step 7).
//!
//! Three things happen here:
//!
//! 1. **Golden fixtures.** Each `golden_*` test reproduces one real
//!    (command, outcome) with the actual binary, normalizes the volatile
//!    fields away (`qsh_testkit::fixtures::normalize`) and compares the
//!    result to a checked-in file. Fixtures are **append-only**
//!    (`docs/CLI.md` §10): add new ones, never edit or delete an existing
//!    one. Re-run with `QSH_UPDATE_FIXTURES=1` only when adding a fixture.
//! 2. **Schema validation.** `schemars` derives the JSON Schema straight
//!    from the contract types in `qsh-proto`, and every fixture is
//!    validated against it — one source for the envelope shape.
//! 3. **`ErrorCode` reachability.** Every code in `ErrorCode::KNOWN` is
//!    either produced by a fixture or listed in [`DEFERRED`] with the
//!    milestone that will first produce it. The two lists must be
//!    disjoint, so adding a fixture for a code forces removing it here.
//!
//! `qsh schema --json` itself is M7 (`PLAN.md` §3), so the generated
//! schemas stay inside this test.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{Fleet, HOST_ALIAS, Sandbox};
use qsh_proto::{
    ErrorCode, ExecRunData, IdentityInitData, Session, SessionCloseData, SessionListData,
    SessionOpenData, SessionReadData, SessionResizeData, SessionWriteData, TrustAddData,
    TrustListData, TrustRemoveData, VersionData,
};
use qsh_testkit::fixtures;
use schemars::schema_for;
use serde_json::Value;

/// A deterministic, valid fingerprint (32 bytes, standard Base64) so the
/// `trust.*` fixtures never depend on a generated key.
const SAMPLE_FINGERPRINT: &str = "sha256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// Set this to regenerate every fixture this file owns instead of asserting
/// against it.
const UPDATE_ENV: &str = "QSH_UPDATE_FIXTURES";

/// `ErrorCode`s M1 cannot produce yet, each with the milestone that will.
/// Move a code out of this list the moment a fixture covers it — the
/// reachability test asserts the two sets are disjoint.
const DEFERRED: &[(&str, &str)] = &[
    (
        "PERMISSION_DENIED",
        "M5 policy engine (M1 interim policy is allow-all-pinned)",
    ),
    (
        "SESSION_CONFLICT",
        "M2 Step 7: needs two attaches racing for the writer lease",
    ),
    ("RESUME_GAP", "M2 sessions"),
    ("CANCELED", "M2 sessions"),
    ("RESOURCE_EXHAUSTED", "M2 backpressure"),
    ("UNSUPPORTED", "M2 Step 7: attach with a resume token"),
    ("REMOTE_ERROR", "no deterministic producer in M1"),
    ("INTERNAL", "no deterministic producer in M1"),
];

/// Every fixture this milestone owes, so a silently-missing file fails
/// loudly instead of shrinking the covered surface.
const REQUIRED_FIXTURES: &[&str] = &[
    "version.json",
    "identity.init.created.json",
    "identity.init.existing.json",
    "trust.add.json",
    "trust.list.json",
    "trust.remove.json",
    "trust.remove.absent.json",
    "exec.run.json",
    "exec.run.signal.json",
    "error.INVALID_ARGUMENT.json",
    "error.CONFIG_ERROR.json",
    "error.HOST_NOT_FOUND.json",
    "error.CONNECTION_FAILED.json",
    "error.AUTH_FAILED.json",
    "error.TRUST_REQUIRED.json",
    "error.TIMEOUT.json",
    "session.open.json",
    "session.get.json",
    "session.list.json",
    "session.read.json",
    "session.write.json",
    "session.resize.json",
    "session.close.json",
    "error.SESSION_NOT_FOUND.json",
];

// ---------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------

fn updating() -> bool {
    match std::env::var(UPDATE_ENV) {
        Ok(value) => !value.is_empty() && value != "0",
        Err(_) => false,
    }
}

fn fixture_path(name: &str) -> PathBuf {
    fixtures::cli_v1_dir().join(name)
}

/// Compare one freshly-produced envelope to its fixture — or write it, when
/// running with `QSH_UPDATE_FIXTURES=1`.
fn check(name: &str, envelope: Value) {
    let actual = fixtures::normalize(envelope);
    if updating() {
        let path = fixture_path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture dir");
        }
        let mut text = serde_json::to_string_pretty(&actual).expect("encode fixture");
        text.push('\n');
        std::fs::write(&path, text).expect("write fixture");
        eprintln!("regenerated {}", path.display());
        return;
    }
    let expected = fixtures::load_cli_v1(name);
    assert_eq!(
        pretty(&actual),
        pretty(&expected),
        "fixture {name} no longer matches the binary's output.\n\
         Fixtures are append-only: if this is an intentional contract change \
         it needs a new /v2 (docs/CLI.md §10). If you are adding a new \
         fixture, regenerate with {UPDATE_ENV}=1."
    );
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("encode json")
}

/// Fixture-reading tests are meaningless mid-regeneration; skip them then.
fn skip_while_regenerating() -> bool {
    if updating() {
        eprintln!("{UPDATE_ENV} is set: skipping fixture validation");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Golden fixtures produced by real runs
// ---------------------------------------------------------------------------

/// Everything that needs neither a peer nor a network round trip.
#[test]
fn golden_local_fixtures() {
    let sandbox = Sandbox::new();

    let (code, version) = sandbox.json(&["version", "--json"]);
    assert_eq!(code, 0, "{version}");
    check("version.json", version);

    let (code, created) = sandbox.json(&["init", "--json", "--key-store", "file"]);
    assert_eq!(code, 0, "{created}");
    check("identity.init.created.json", created);

    let (code, existing) = sandbox.json(&["init", "--json", "--key-store", "file"]);
    assert_eq!(code, 0, "{existing}");
    check("identity.init.existing.json", existing);

    let (code, added) = sandbox.json(&[
        "trust",
        "add",
        "personal-mac",
        "--address",
        "personal-mac.example.com:4433",
        "--fingerprint",
        SAMPLE_FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 0, "{added}");
    check("trust.add.json", added);

    let (code, listed) = sandbox.json(&["trust", "list", "--json"]);
    assert_eq!(code, 0, "{listed}");
    check("trust.list.json", listed);

    let (code, removed) = sandbox.json(&["trust", "remove", "personal-mac", "--json"]);
    assert_eq!(code, 0, "{removed}");
    check("trust.remove.json", removed);

    let (code, absent) = sandbox.json(&["trust", "remove", "personal-mac", "--json"]);
    assert_eq!(code, 0, "{absent}");
    check("trust.remove.absent.json", absent);

    let (code, invalid) = sandbox.json(&[
        "trust",
        "add",
        "personal-mac",
        "--fingerprint",
        "not-a-fingerprint",
        "--json",
    ]);
    assert_eq!(code, 255, "{invalid}");
    check("error.INVALID_ARGUMENT.json", invalid);

    let (code, missing_host) = sandbox.json(&["exec", "nowhere", "--json", "--", "true"]);
    assert_eq!(code, 255, "{missing_host}");
    check("error.HOST_NOT_FOUND.json", missing_host);

    // A sandbox that never ran `qsh init` has no identity to dial with.
    let uninitialized = Sandbox::new();
    let (code, config_error) = uninitialized.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{config_error}");
    check("error.CONFIG_ERROR.json", config_error);
}

/// The dial-timeout path. Split out because it is the one scenario that
/// costs the full `CONNECTION_FAILED` dial timeout (~10s) — the exit-code
/// matrix uses the instant `:0` variant instead of paying it twice.
#[test]
fn golden_connection_failed_fixture() {
    let sandbox = Sandbox::initialized();
    // Port 9 (discard) with nothing bound: the dial simply gets no answer.
    sandbox.trust_add("unreachable", Some("127.0.0.1:9"), SAMPLE_FINGERPRINT);

    let (code, value) = sandbox.json(&["exec", "unreachable", "--json", "--", "true"]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "CONNECTION_FAILED");
    check("error.CONNECTION_FAILED.json", value);
}

/// Everything that needs a live peer on the other end.
#[test]
fn golden_remote_fixtures() {
    let fleet = Fleet::start();

    let (code, exec) = fleet.exec_json(&["--", "sh", "-c", "echo out; echo err >&2; exit 7"]);
    assert_eq!(code, 7, "{exec}");
    check("exec.run.json", exec);

    // Signal exits are POSIX semantics; the fixture is asserted where a
    // signal can actually happen.
    #[cfg(unix)]
    {
        let (code, killed) = fleet.exec_json(&["--", "sh", "-c", "kill -9 $$"]);
        assert_eq!(code, 137, "{killed}");
        assert_eq!(killed["data"]["signal"], "SIGKILL");
        check("exec.run.signal.json", killed);
    }

    let (code, timeout) = fleet.exec_json(&["--timeout", "300", "--", "sleep", "5"]);
    assert_eq!(code, 255, "{timeout}");
    check("error.TIMEOUT.json", timeout);

    let rogue = fleet.rogue();
    let (code, auth_failed) = rogue.json(&["exec", HOST_ALIAS, "--json", "--", "true"]);
    assert_eq!(code, 255, "{auth_failed}");
    check("error.AUTH_FAILED.json", auth_failed);

    // `trust add` without `--fingerprint` observes the peer instead of
    // prompting, because machine mode never prompts (`docs/CLI.md` §2.1).
    let stranger = Sandbox::initialized();
    let (code, trust_required) = stranger.json(&[
        "trust",
        "add",
        HOST_ALIAS,
        "--address",
        fleet.addr(),
        "--json",
    ]);
    assert_eq!(code, 255, "{trust_required}");
    check("error.TRUST_REQUIRED.json", trust_required);
}

/// The `session.*` value ops against a real `qsh serve` (PTY-backed
/// sessions, M2 Step 4): open → read → write → get → resize → list →
/// close → get (gone). A real PTY's byte stream is not reproducible
/// (prompt text differs per shell and platform), so the asserts here pin
/// invariants — cursor monotonicity and the shape of each envelope — while
/// the fixtures themselves mask payload and offsets.
// Sessions are PTY-backed, so this whole path only exists on POSIX hosts
// (Windows host is P2). The fixtures it writes are checked in and are
// still validated everywhere by the whole-directory contract tests below.
#[cfg(unix)]
#[test]
fn golden_session_fixtures() {
    let fleet = Fleet::start();
    let client = &fleet.client;

    let (code, opened) = client.json(&["session", "open", HOST_ALIAS, "--json", "--", "sh"]);
    assert_eq!(code, 0, "{opened}");
    let session_ref = opened["data"]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string();
    assert!(session_ref.starts_with(&format!("{HOST_ALIAS}/")));
    check("session.open.json", opened);

    // The shell writes its prompt as soon as the PTY is up; a long-poll
    // read from 0 returns it (no lease has been taken yet, so no control
    // events can interleave).
    let (code, read) = client.json(&[
        "session",
        "read",
        &session_ref,
        "--after",
        "0",
        "--wait",
        "5000",
        "--json",
    ]);
    assert_eq!(code, 0, "{read}");
    let events = read["data"]["events"].as_array().expect("events");
    assert!(!events.is_empty(), "{read}");
    assert!(
        events.iter().all(|e| e["type"] == "session.output"),
        "{read}"
    );
    // The reply carries the resume cursor a poller must feed back
    // (`--after`/`--ctl-after`, CLI.md §6.4): it is exactly the last
    // delivered output offset, and reading from 0 must have advanced it.
    let prompt_end = read["data"]["next_after"].as_u64().expect("next_after");
    assert!(prompt_end > 0, "{read}");
    assert_eq!(
        events.last().unwrap()["sequence"].as_u64(),
        Some(prompt_end),
        "{read}"
    );
    assert!(read["data"]["next_ctl_after"].is_u64(), "{read}");
    // One event in the fixture: the pull may split the banner in theory,
    // so keep the fixture to the first event only (shape is what it pins).
    let mut read_fixture = read.clone();
    read_fixture["data"]["events"] = Value::Array(vec![events[0].clone()]);
    check("session.read.json", read_fixture);

    // "hi\n" — the tty echoes it back, and the shell then reacts to it, so
    // the ring grows by *at least* the three bytes written.
    let (code, written) = client.json(&[
        "session",
        "write",
        &session_ref,
        "--data-b64",
        "aGkK",
        "--json",
    ]);
    assert_eq!(code, 0, "{written}");
    assert_eq!(written["data"]["bytes_written"], 3);
    check("session.write.json", written);

    // Bounded poll (no sleeps: each iteration is a real round trip) until
    // the echoed input has landed in the ring and the write's connection
    // has released its lease, so the snapshots below are stable.
    // Wall-clock bounded rather than iteration-bounded so a loaded box
    // does not fail spuriously.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let session = loop {
        let (code, session) = client.json(&["session", "get", &session_ref, "--json"]);
        assert_eq!(code, 0, "{session}");
        let last = session["data"]["last_sequence"]
            .as_u64()
            .expect("last_sequence");
        if last >= prompt_end + 3 && session["data"]["writer"].is_null() {
            break session;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "echoed output never reached the replay ring / lease never released: {session}"
        );
    };
    assert_eq!(session["data"]["state"], "running");
    check("session.get.json", session);

    let (code, resized) = client.json(&[
        "session",
        "resize",
        &session_ref,
        "--cols",
        "120",
        "--rows",
        "40",
        "--json",
    ]);
    assert_eq!(code, 0, "{resized}");
    check("session.resize.json", resized);

    let (code, listed) = client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert_eq!(listed["data"]["sessions"].as_array().map(Vec::len), Some(1));
    check("session.list.json", listed);

    let (code, closed) = client.json(&["session", "close", &session_ref, "--json"]);
    assert_eq!(code, 0, "{closed}");
    // A live shell keeps producing output, so the final offset is only
    // bounded from below by what we have already observed.
    assert!(
        closed["data"]["final_sequence"]
            .as_u64()
            .expect("final_sequence")
            >= prompt_end + 3,
        "{closed}"
    );
    check("session.close.json", closed);

    let (code, gone) = client.json(&["session", "get", &session_ref, "--json"]);
    assert_eq!(code, 255, "{gone}");
    assert_eq!(gone["error"]["code"], "SESSION_NOT_FOUND");
    check("error.SESSION_NOT_FOUND.json", gone);
}

// ---------------------------------------------------------------------------
// Contract checks over the whole fixture directory
// ---------------------------------------------------------------------------

#[test]
fn every_required_fixture_exists() {
    if skip_while_regenerating() {
        return;
    }
    let present: BTreeSet<String> = fixtures::all_cli_v1()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for required in REQUIRED_FIXTURES {
        assert!(
            present.contains(*required),
            "missing fixture {required} (regenerate with {UPDATE_ENV}=1); have {present:?}"
        );
    }
}

#[test]
fn every_fixture_is_a_wellformed_v1_envelope() {
    if skip_while_regenerating() {
        return;
    }
    let known: BTreeSet<&str> = ErrorCode::KNOWN.iter().map(ErrorCode::as_str).collect();
    for (name, fixture) in fixtures::all_cli_v1() {
        assert_eq!(fixture["schema"], "qsh.cli/v1", "{name}");
        assert!(
            fixture["command"].as_str().is_some_and(|c| !c.is_empty()),
            "{name}: missing command"
        );
        assert!(fixture["request_id"].as_str().is_some(), "{name}");
        let ok = fixture["ok"]
            .as_bool()
            .unwrap_or_else(|| panic!("{name}: ok"));
        let has_data = fixture.get("data").is_some();
        let has_error = fixture.get("error").is_some();
        assert_eq!(
            has_data, ok,
            "{name}: `data` is present iff `ok` (docs/CLI.md §3)"
        );
        assert_eq!(has_error, !ok, "{name}: `error` is present iff `!ok`");
        if let Some(error) = fixture.get("error") {
            let code = error["code"].as_str().unwrap_or_else(|| panic!("{name}"));
            assert!(
                known.contains(code),
                "{name}: {code} is not in ErrorCode::KNOWN — error codes come from the \
                 single enum in qsh-proto, never an ad hoc string"
            );
            assert!(error["message"].as_str().is_some(), "{name}");
            assert!(error["retryable"].as_bool().is_some(), "{name}");
        }
    }
}

/// ADR-0007 (결과 절): the resume token is never a property of any JSON
/// contract type (`qsh-proto` pins the schemas) **and never appears in a
/// fixture** — this is the fixture half. Checked structurally on every
/// object key at any depth, and textually so a token smuggled inside a
/// string value would trip it too.
#[test]
fn no_fixture_carries_a_resume_token() {
    if skip_while_regenerating() {
        return;
    }
    fn keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                out.extend(map.keys().cloned());
                map.values().for_each(|c| keys(c, out));
            }
            Value::Array(items) => items.iter().for_each(|c| keys(c, out)),
            _ => {}
        }
    }
    for (name, fixture) in fixtures::all_cli_v1() {
        let mut names = Vec::new();
        keys(&fixture, &mut names);
        assert!(
            !names
                .iter()
                .any(|k| k.contains("resume_token") || k == "token"),
            "{name}: exposes a token field ({names:?}) — ADR-0007"
        );
        let text = serde_json::to_string(&fixture).expect("encode");
        assert!(
            !text.contains("resume_token"),
            "{name}: mentions resume_token"
        );
    }
}

#[test]
fn every_fixture_validates_against_the_envelope_schema() {
    if skip_while_regenerating() {
        return;
    }
    let schema = schema_for!(qsh_proto::CliEnvelope).to_value();
    let validator = jsonschema::validator_for(&schema).expect("envelope schema is valid");
    for (name, fixture) in fixtures::all_cli_v1() {
        if !validator.is_valid(&fixture) {
            let errors: Vec<String> = validator
                .iter_errors(&fixture)
                .map(|e| e.to_string())
                .collect();
            panic!("{name} does not match the CliEnvelope schema: {errors:#?}");
        }
    }
}

#[test]
fn every_fixture_payload_validates_against_its_command_schema() {
    if skip_while_regenerating() {
        return;
    }
    for (name, fixture) in fixtures::all_cli_v1() {
        let Some(data) = fixture.get("data") else {
            continue;
        };
        let command = fixture["command"].as_str().expect("command");
        let schema = data_schema(command)
            .unwrap_or_else(|| panic!("{name}: no data schema registered for command {command}"));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|e| panic!("{command} data schema is invalid: {e}"));
        if !validator.is_valid(data) {
            let errors: Vec<String> = validator.iter_errors(data).map(|e| e.to_string()).collect();
            panic!("{name}: data does not match the {command} schema: {errors:#?}");
        }
    }
}

/// The JSON Schema of the `data` payload of one command, derived from the
/// same `qsh-proto` type the binary serializes.
fn data_schema(command: &str) -> Option<Value> {
    Some(
        match command {
            "version.get" => schema_for!(VersionData),
            "identity.init" => schema_for!(IdentityInitData),
            "trust.add" => schema_for!(TrustAddData),
            "trust.list" => schema_for!(TrustListData),
            "trust.remove" => schema_for!(TrustRemoveData),
            "exec.run" => schema_for!(ExecRunData),
            // M2 session ops (fixtures land with Step 3/5; registered now so
            // the first session fixture validates instead of panicking).
            "session.list" => schema_for!(SessionListData),
            "session.get" => schema_for!(Session),
            "session.open" => schema_for!(SessionOpenData),
            "session.read" => schema_for!(SessionReadData),
            "session.write" => schema_for!(SessionWriteData),
            "session.resize" => schema_for!(SessionResizeData),
            "session.close" => schema_for!(SessionCloseData),
            _ => return None,
        }
        .to_value(),
    )
}

/// `docs/design/testing.md` L6: every `ErrorCode` variant is either covered
/// by a fixture or explicitly deferred to a named milestone. A code that is
/// in neither list is a code nothing can ever produce.
#[test]
fn every_error_code_is_covered_by_a_fixture_or_explicitly_deferred() {
    if skip_while_regenerating() {
        return;
    }
    let known: BTreeSet<String> = ErrorCode::KNOWN
        .iter()
        .map(|code| code.as_str().to_string())
        .collect();
    let covered: BTreeSet<String> = fixtures::all_cli_v1()
        .into_iter()
        .filter_map(|(_, fixture)| {
            fixture
                .get("error")
                .and_then(|e| e["code"].as_str().map(str::to_string))
        })
        .collect();
    let deferred: BTreeSet<String> = DEFERRED
        .iter()
        .map(|(code, _)| (*code).to_string())
        .collect();

    let both: Vec<&String> = covered.intersection(&deferred).collect();
    assert!(
        both.is_empty(),
        "these codes now have a fixture and must be removed from DEFERRED: {both:?}"
    );

    let union: BTreeSet<String> = covered.union(&deferred).cloned().collect();
    let unreachable: Vec<&String> = known.difference(&union).collect();
    assert!(
        unreachable.is_empty(),
        "no fixture and no DEFERRED entry for: {unreachable:?}"
    );
    let stale: Vec<&String> = union.difference(&known).collect();
    assert!(
        stale.is_empty(),
        "these are not ErrorCode::KNOWN codes: {stale:?}"
    );
}

/// Guards the two tests above against passing vacuously: a schemars type
/// that generated a permissive `true` schema would validate anything.
#[test]
fn the_generated_schemas_actually_reject_wrong_shapes() {
    let envelope = schema_for!(qsh_proto::CliEnvelope).to_value();
    let validator = jsonschema::validator_for(&envelope).expect("envelope schema is valid");
    for bad in [
        serde_json::json!({}),
        serde_json::json!({"schema": 1, "request_id": "r", "command": "c", "ok": true}),
        serde_json::json!({"schema": "qsh.cli/v1", "request_id": "r", "command": "c"}),
        serde_json::json!({
            "schema": "qsh.cli/v1", "request_id": "r", "command": "c", "ok": false,
            "error": {"code": "INTERNAL", "message": "m"}
        }),
    ] {
        assert!(
            !validator.is_valid(&bad),
            "the CliEnvelope schema accepted {bad}"
        );
    }

    let exec = data_schema("exec.run").expect("exec.run schema");
    let validator = jsonschema::validator_for(&exec).expect("exec.run schema is valid");
    for bad in [
        serde_json::json!({}),
        serde_json::json!({
            "stdout_b64": "", "stderr_b64": "", "remote_exit_code": "7",
            "signal": null, "duration_ms": 0
        }),
    ] {
        assert!(
            !validator.is_valid(&bad),
            "the ExecRunData schema accepted {bad}"
        );
    }
}
