//! Integration tests for the `qsh init` / `qsh trust …` vertical slices:
//! ops layer → JSON renderer → exit code, exercised as real subprocesses.
//!
//! Every test gets its own `QSH_CONFIG_DIR`/`QSH_STATE_DIR`, and always
//! asks for `--key-store file`, so the suite never touches the developer's
//! real config directory or the OS credential store.

use std::path::Path;
use std::process::{Command, Output};

use qsh_core::Fingerprint;
use serde_json::Value;
use tempfile::TempDir;

/// A valid, deterministic fingerprint (SHA-256 of nothing in particular).
const FINGERPRINT: &str = "sha256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

struct Sandbox {
    _dir: TempDir,
    config: std::path::PathBuf,
    state: std::path::PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        Self {
            _dir: dir,
            config,
            state,
        }
    }

    fn qsh(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_qsh"))
            .args(args)
            .env("QSH_CONFIG_DIR", &self.config)
            .env("QSH_STATE_DIR", &self.state)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("QSH_LOG")
            .env_remove("RUST_LOG")
            .output()
            .expect("failed to run qsh")
    }

    /// Run in JSON mode and assert stdout is exactly one JSON line.
    fn json(&self, args: &[&str]) -> (i32, Value) {
        let output = self.qsh(args);
        let stdout = String::from_utf8(output.stdout).expect("stdout must be utf-8");
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one JSON line for {args:?}, got {stdout:?}"
        );
        let value: Value = serde_json::from_str(lines[0])
            .unwrap_or_else(|e| panic!("stdout is not JSON for {args:?}: {e}: {stdout:?}"));
        assert_eq!(value["schema"], "qsh.cli/v1");
        assert!(value["request_id"].as_str().is_some());
        (output.status.code().expect("exit code"), value)
    }

    fn init(&self) -> Value {
        let (code, value) = self.json(&["init", "--json", "--key-store", "file"]);
        assert_eq!(code, 0, "init failed: {value}");
        value
    }
}

fn same_dir(reported: &str, expected: &Path) -> bool {
    let canonical = std::fs::canonicalize(expected).unwrap_or_else(|_| expected.to_path_buf());
    Path::new(reported) == canonical
}

#[test]
fn init_creates_an_identity_then_is_idempotent() {
    let sandbox = Sandbox::new();

    let first = sandbox.init();
    assert_eq!(first["command"], "identity.init");
    assert_eq!(first["ok"], true);
    let data = &first["data"];
    assert_eq!(data["created"], true);
    assert_eq!(data["key_store"], "file");
    assert!(data["device_id"].as_str().unwrap().starts_with("device_"));
    let fingerprint = data["fingerprint"].as_str().unwrap();
    assert!(
        fingerprint.parse::<Fingerprint>().is_ok(),
        "fingerprint {fingerprint} must parse"
    );
    assert!(
        same_dir(data["config_dir"].as_str().unwrap(), &sandbox.config),
        "config_dir was {}",
        data["config_dir"]
    );

    let second = sandbox.init();
    assert_eq!(second["data"]["created"], false);
    assert_eq!(second["data"]["device_id"], data["device_id"]);
    assert_eq!(second["data"]["fingerprint"], data["fingerprint"]);
}

#[test]
fn init_human_mode_writes_no_json_to_stdout() {
    let sandbox = Sandbox::new();
    let output = sandbox.qsh(&["init", "--key-store", "file"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        serde_json::from_str::<Value>(stdout.trim()).is_err(),
        "human mode must not emit JSON: {stdout:?}"
    );
    assert!(stdout.contains("device_id:"), "{stdout:?}");
    assert!(stdout.contains("key_store:   file"), "{stdout:?}");
    assert!(stdout.contains("created"), "{stdout:?}");
}

#[test]
fn verbose_diagnostics_never_pollute_the_json_line() {
    let sandbox = Sandbox::new();
    // `Sandbox::json` already asserts stdout is exactly one JSON line.
    let (code, value) = sandbox.json(&["-vv", "init", "--json", "--key-store", "file"]);
    assert_eq!(code, 0);
    assert_eq!(value["command"], "identity.init");
}

#[test]
fn trust_add_list_remove_are_idempotent() {
    let sandbox = Sandbox::new();
    sandbox.init();

    let (code, added) = sandbox.json(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1:4433",
        "--fingerprint",
        FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 0, "{added}");
    assert_eq!(added["command"], "trust.add");
    assert_eq!(added["data"]["created"], true);
    assert_eq!(added["data"]["peer"]["name"], "peer-a");
    assert_eq!(added["data"]["peer"]["fingerprint"], FINGERPRINT);
    assert_eq!(added["data"]["peer"]["address"], "127.0.0.1:4433");
    assert!(
        added["data"]["peer"]["added_at"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );

    let (code, again) = sandbox.json(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1:9999",
        "--fingerprint",
        FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 0);
    assert_eq!(again["data"]["created"], false);
    assert_eq!(again["data"]["peer"]["address"], "127.0.0.1:4433");

    let (code, listed) = sandbox.json(&["trust", "list", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(listed["command"], "trust.list");
    assert_eq!(listed["data"]["peers"].as_array().unwrap().len(), 1);
    assert_eq!(listed["data"]["peers"][0]["name"], "peer-a");

    let (code, removed) = sandbox.json(&["trust", "remove", "peer-a", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(removed["command"], "trust.remove");
    assert_eq!(
        removed["data"],
        serde_json::json!({"name": "peer-a", "removed": true})
    );

    let (code, removed_again) = sandbox.json(&["trust", "remove", "peer-a", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(removed_again["data"]["removed"], false);

    let (code, empty) = sandbox.json(&["trust", "list", "--json"]);
    assert_eq!(code, 0);
    assert!(empty["data"]["peers"].as_array().unwrap().is_empty());
}

#[test]
fn trust_list_human_mode_renders_a_table() {
    let sandbox = Sandbox::new();
    sandbox.init();

    let empty = sandbox.qsh(&["trust", "list"]);
    assert_eq!(empty.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(empty.stdout).unwrap().trim(),
        "no trusted peers"
    );

    sandbox.qsh(&["trust", "add", "peer-a", "--fingerprint", FINGERPRINT]);
    let listed = sandbox.qsh(&["trust", "list"]);
    let stdout = String::from_utf8(listed.stdout).unwrap();
    assert!(stdout.starts_with("NAME"), "{stdout:?}");
    assert!(stdout.contains("FINGERPRINT"), "{stdout:?}");
    assert!(stdout.contains("peer-a"), "{stdout:?}");
}

#[test]
fn a_malformed_fingerprint_is_an_invalid_argument() {
    let sandbox = Sandbox::new();
    sandbox.init();

    let (code, value) = sandbox.json(&[
        "trust",
        "add",
        "peer-a",
        "--fingerprint",
        "sha256:not-base64!!",
        "--json",
    ]);
    assert_eq!(code, 255);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["retryable"], false);
}

#[test]
fn trust_add_without_address_or_fingerprint_is_an_invalid_argument() {
    let sandbox = Sandbox::new();
    sandbox.init();

    let (code, value) = sandbox.json(&["trust", "add", "peer-a", "--json"]);
    assert_eq!(code, 255);
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--address")
    );
}

#[test]
fn probing_needs_an_identity_and_then_reports_a_connection_failure() {
    let sandbox = Sandbox::new();

    // Port 9 (discard) with nothing bound: no QUIC peer answers.
    let (code, before_init) = sandbox.json(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1:9",
        "--json",
    ]);
    assert_eq!(code, 255);
    assert_eq!(before_init["error"]["code"], "CONFIG_ERROR");
    assert!(
        before_init["error"]["message"]
            .as_str()
            .unwrap()
            .contains("qsh init")
    );

    sandbox.init();

    let (code, after_init) = sandbox.json(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1:9",
        "--json",
    ]);
    assert_eq!(code, 255);
    assert_eq!(after_init["error"]["code"], "CONNECTION_FAILED");
    // Nothing was pinned by a failed probe.
    let (_, listed) = sandbox.json(&["trust", "list", "--json"]);
    assert!(listed["data"]["peers"].as_array().unwrap().is_empty());
}

#[test]
fn json_mode_never_prompts_and_keeps_stdout_pure() {
    let sandbox = Sandbox::new();
    sandbox.init();

    // A non-terminal stdin in human mode must not hang either: it reports
    // the underlying error instead of prompting.
    let output = sandbox.qsh(&["trust", "add", "peer-a", "--address", "127.0.0.1:9"]);
    assert_eq!(output.status.code(), Some(255));
    assert!(
        String::from_utf8(output.stdout).unwrap().is_empty(),
        "human-mode errors belong on stderr"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("qsh:"), "{stderr:?}");
}
