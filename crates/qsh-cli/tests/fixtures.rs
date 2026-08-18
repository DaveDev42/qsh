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
    ErrorCode, ExecRunData, IdentityInitData, TrustAddData, TrustListData, TrustRemoveData,
    VersionData,
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
    ("SESSION_NOT_FOUND", "M2 sessions"),
    ("SESSION_CONFLICT", "M2 sessions"),
    ("RESUME_GAP", "M2 sessions"),
    ("CANCELED", "M2 sessions"),
    ("RESOURCE_EXHAUSTED", "M2 backpressure"),
    ("UNSUPPORTED", "M2 reserved flags"),
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
