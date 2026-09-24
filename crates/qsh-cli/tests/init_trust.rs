//! Integration tests for the `qsh init` / `qsh trust …` vertical slices:
//! ops layer → JSON renderer → exit code, exercised as real subprocesses.
//!
//! Every test gets its own `QSH_CONFIG_DIR`/`QSH_STATE_DIR`, and always
//! asks for `--key-store file`, so the suite never touches the developer's
//! real config directory or the OS credential store.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

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

    /// Like `qsh`, but feeds `input` on the child's stdin instead of
    /// leaving it inherited — for the `--cert-file -` path.
    fn qsh_with_stdin(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_qsh"))
            .args(args)
            .env("QSH_CONFIG_DIR", &self.config)
            .env("QSH_STATE_DIR", &self.state)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("QSH_LOG")
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh");
        child
            .stdin
            .take()
            .expect("stdin pipe")
            .write_all(input)
            .expect("write stdin");
        child.wait_with_output().expect("wait for qsh")
    }

    /// `json`'s stdin-feeding twin, for `--json`-mode `-` cases.
    fn json_with_stdin(&self, args: &[&str], input: &[u8]) -> (i32, Value) {
        let output = self.qsh_with_stdin(args, input);
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

    /// `qsh identity export --json`'s `data.cert_pem`, for feeding into a
    /// second sandbox's `trust add --cert-file -`.
    fn exported_cert_pem(&self) -> String {
        let (code, exported) = self.json(&["identity", "export", "--json"]);
        assert_eq!(code, 0, "{exported}");
        exported["data"]["cert_pem"]
            .as_str()
            .expect("data.cert_pem")
            .to_string()
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

    // Same name, same fingerprint, same address: a pure no-op (`data.updated:
    // false`) — this is what this test's name promises. A *different*
    // address on an otherwise-identical re-add is a deliberate exception to
    // that idempotency (M7 Step 2 decision B, `docs/CLI.md` §6.11's
    // address-refresh path) and has its own coverage below and in
    // `trust_lifecycle_live.rs`/`fixtures.rs`.
    let (code, again) = sandbox.json(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1:4433",
        "--fingerprint",
        FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 0);
    assert_eq!(again["data"]["created"], false);
    assert_eq!(again["data"]["updated"], false);
    assert_eq!(again["data"]["peer"]["address"], "127.0.0.1:4433");

    // The address-refresh exception itself: same name, same fingerprint, a
    // *different* address updates the pin in place instead of staying a
    // no-op.
    let (code, rebound) = sandbox.json(&[
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
    assert_eq!(rebound["data"]["created"], false);
    assert_eq!(rebound["data"]["updated"], true);
    assert_eq!(rebound["data"]["peer"]["address"], "127.0.0.1:9999");

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

/// `docs/CLI.md` §6.11: human mode always prints exactly one of the two
/// `INVITE_ADDRESS_*` wordings under `accept_command` — a populated
/// heading plus candidates, or the zero-candidate wording — never both,
/// never neither. Which one depends on this test machine's real routing,
/// so the assertion is exclusive-or over the two, not a guess at which
/// branch fires.
#[test]
fn trust_invite_human_mode_prints_exactly_one_of_the_two_address_wordings() {
    use qsh_core::trust::invite_address::{INVITE_ADDRESS_HEADING, INVITE_ADDRESS_NONE};

    let sandbox = Sandbox::new();
    sandbox.init();

    let output = sandbox.qsh(&["trust", "invite"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let heading = stdout.contains(INVITE_ADDRESS_HEADING);
    let none = stdout.contains(INVITE_ADDRESS_NONE);
    assert!(
        heading ^ none,
        "human mode must print exactly one of the two address wordings: {stdout:?}"
    );
    assert!(
        stdout.contains("qsh pair accept <address> "),
        "the `<address>` placeholder survives the candidate block: {stdout:?}"
    );
    // Nothing pins that a printed candidate is *this host's* address
    // rather than the route query's own destination — `source_address_for`
    // reading `peer_addr()` (the RFC 5737/3849 destination) instead of
    // `local_addr()` (this host's kernel-picked source) compiles clean and
    // keeps every other gate green (adversarial review). It is not this
    // host's real address on any machine, so its absence is a
    // machine-independent, unconditional check.
    for destination in ["192.0.2.1", "2001:db8::1"] {
        assert!(
            !stdout.contains(destination),
            "a candidate must never be this route query's own RFC 5737/3849 \
             destination address, which would mean `source_address_for` read the \
             wrong end of the socket: {stdout:?}"
        );
    }
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

/// ADR-0014 결정 5: `trust add --address` with no `:port` pins the default
/// port and notes it exactly once on stderr, never on stdout.
#[test]
fn trust_add_with_a_port_less_address_notes_the_assumed_port_once_and_pins_it() {
    let sandbox = Sandbox::new();
    sandbox.init();

    let output = sandbox.qsh(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1",
        "--fingerprint",
        FINGERPRINT,
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must be exactly one JSON line: {stdout:?}"
    );
    let value: Value = serde_json::from_str(lines[0]).expect("stdout is JSON");
    assert_eq!(value["data"]["peer"]["address"], "127.0.0.1:4433");
    assert_eq!(
        stderr.matches("assuming port 4433").count(),
        1,
        "stderr must note the assumed port exactly once: {stderr:?}"
    );
    assert!(
        !stdout.contains("assuming"),
        "the notice must never reach stdout: {stdout:?}"
    );

    // The `stderr_note!` call in `run_trust_add`
    // fires unconditionally, before the `--json`/human branch is ever
    // looked at (`main.rs`'s `run_trust_add`), so a second, human-mode
    // invocation must see the exact same notice. Deleting that call site
    // must turn *this whole test* red, not just its `--json` half.
    let human_sandbox = Sandbox::new();
    human_sandbox.init();
    let human_output = human_sandbox.qsh(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1",
        "--fingerprint",
        FINGERPRINT,
    ]);
    assert_eq!(human_output.status.code(), Some(0));
    let human_stderr = String::from_utf8(human_output.stderr).unwrap();
    assert_eq!(
        human_stderr.matches("assuming port 4433").count(),
        1,
        "human mode stderr must note the assumed port exactly once: {human_stderr:?}"
    );
}

/// The other half: an address that already names a port notes nothing.
#[test]
fn trust_add_with_a_port_in_the_address_notes_nothing() {
    let sandbox = Sandbox::new();
    sandbox.init();

    let output = sandbox.qsh(&[
        "trust",
        "add",
        "peer-a",
        "--address",
        "127.0.0.1:4433",
        "--fingerprint",
        FINGERPRINT,
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("assuming port"),
        "an address with an explicit port must not be noted: {stderr:?}"
    );
}

/// ADR-0014 결정 5: read paths never note the assumed port, even though
/// they do normalize the address they return (mutation (iii)'s first
/// catcher).
#[test]
fn trust_list_never_notes_an_assumed_port() {
    let sandbox = Sandbox::new();
    sandbox.init();
    std::fs::write(
        sandbox.config.join("trust.toml"),
        format!(
            "[[peer]]\nname = \"peer-a\"\nfingerprint = \"{FINGERPRINT}\"\naddress = \"127.0.0.1\"\nadded_at = \"2026-08-17T00:00:00Z\"\n"
        ),
    )
    .expect("write trust.toml");

    let output = sandbox.qsh(&["trust", "list", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).expect("stdout is JSON");
    assert_eq!(
        value["data"]["peers"][0]["address"], "127.0.0.1:4433",
        "the read path must still normalize"
    );
    assert!(
        !stderr.contains("assuming port"),
        "trust.list must never note an assumed port: {stderr:?}"
    );
}

/// Same guarantee, the other read choke point.
#[test]
fn host_list_never_notes_an_assumed_port() {
    let sandbox = Sandbox::new();
    sandbox.init();
    std::fs::write(
        sandbox.config.join("trust.toml"),
        format!(
            "[[peer]]\nname = \"peer-a\"\nfingerprint = \"{FINGERPRINT}\"\naddress = \"127.0.0.1\"\nadded_at = \"2026-08-17T00:00:00Z\"\n"
        ),
    )
    .expect("write trust.toml");

    let output = sandbox.qsh(&["hosts", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).expect("stdout is JSON");
    assert_eq!(value["data"]["hosts"][0]["address"], "127.0.0.1:4433");
    assert!(
        !stderr.contains("assuming port"),
        "hosts must never note an assumed port: {stderr:?}"
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

// --- ADR-0013: `trust add --cert-file` / `trust add-ca` /
// `identity export` negative table, CLI/exit-code face. Pure-core coverage
// of the same rows lives in `crates/qsh-core/src/ops/tests.rs`; this file
// only re-proves each row's exit code and JSON envelope through a real
// subprocess, plus the `-` (stdin) path that only exists at this layer.

#[test]
fn identity_export_is_a_config_error_before_qsh_init() {
    let sandbox = Sandbox::new();
    let (code, value) = sandbox.json(&["identity", "export", "--json"]);
    assert_eq!(code, 255);
    assert_eq!(value["error"]["code"], "CONFIG_ERROR");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("qsh init"),
        "{value}"
    );
}

#[test]
fn identity_export_refuses_to_clobber_an_existing_out_file() {
    let sandbox = Sandbox::new();
    sandbox.init();
    let out_path = sandbox.config.join("exported.pem");
    std::fs::write(&out_path, "not a cert\n").expect("seed a pre-existing file");

    let (code, value) = sandbox.json(&[
        "identity",
        "export",
        "--out",
        out_path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 255, "{value}");
    assert_ne!(value["error"]["code"], "OK");
    assert_eq!(
        std::fs::read_to_string(&out_path).unwrap(),
        "not a cert\n",
        "a refused clobber must leave the existing file untouched"
    );
}

#[test]
fn trust_add_cert_file_rejects_a_chain_of_two_certificates() {
    let exporter_a = Sandbox::new();
    exporter_a.init();
    let exporter_b = Sandbox::new();
    exporter_b.init();
    let chain = format!(
        "{}{}",
        exporter_a.exported_cert_pem(),
        exporter_b.exported_cert_pem()
    );

    let sandbox = Sandbox::new();
    sandbox.init();
    let (code, value) = sandbox.json_with_stdin(
        &["trust", "add", "peer-a", "--cert-file", "-", "--json"],
        chain.as_bytes(),
    );
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert!(
        !value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("BEGIN"),
        "the error message must never echo input bytes: {value}"
    );
    assert!(value["error"]["details"].is_null(), "{value}");
}

#[test]
fn trust_add_cert_file_rejects_a_bundle_carrying_a_private_key_and_echoes_no_input() {
    let ca_owner = Sandbox::new();
    ca_owner.init();
    let (code, ca_init) = ca_owner.json(&["cert", "init", "--json"]);
    assert_eq!(code, 0, "{ca_init}");
    let ca_pem =
        std::fs::read_to_string(ca_owner.config.join("ca").join("ca.pem")).expect("read ca.pem");
    let ca_key =
        std::fs::read_to_string(ca_owner.config.join("ca").join("ca.key")).expect("read ca.key");
    let bundle = format!("{ca_pem}{ca_key}");

    let sandbox = Sandbox::new();
    sandbox.init();
    let (code, value) = sandbox.json_with_stdin(
        &["trust", "add", "peer-a", "--cert-file", "-", "--json"],
        bundle.as_bytes(),
    );
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert!(
        !value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY"),
        "the error message must never echo input bytes: {value}"
    );
    assert!(value["error"]["details"].is_null(), "{value}");
}

#[test]
fn trust_add_cert_file_is_a_silent_no_op_when_the_name_holds_a_different_fingerprint() {
    let exporter = Sandbox::new();
    exporter.init();
    let cert_pem = exporter.exported_cert_pem();

    let sandbox = Sandbox::new();
    sandbox.init();
    sandbox.qsh(&[
        "trust",
        "add",
        "peer-a",
        "--fingerprint",
        FINGERPRINT,
        "--json",
    ]);

    let (code, value) = sandbox.json_with_stdin(
        &["trust", "add", "peer-a", "--cert-file", "-", "--json"],
        cert_pem.as_bytes(),
    );
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["created"], false);
    assert_eq!(value["data"]["updated"], false);
    assert_eq!(
        value["data"]["peer"]["fingerprint"], FINGERPRINT,
        "a name collision under a different fingerprint is a silent no-op, not a re-bind"
    );

    let (_, listed) = sandbox.json(&["trust", "list", "--json"]);
    assert_eq!(
        listed["data"]["peers"][0]["fingerprint"], FINGERPRINT,
        "the pre-existing pin must be untouched by the no-op re-add"
    );
}

#[test]
fn trust_add_rejects_cert_file_together_with_fingerprint() {
    let exporter = Sandbox::new();
    exporter.init();
    let cert_pem = exporter.exported_cert_pem();

    let sandbox = Sandbox::new();
    sandbox.init();
    let (code, value) = sandbox.json_with_stdin(
        &[
            "trust",
            "add",
            "peer-a",
            "--cert-file",
            "-",
            "--fingerprint",
            FINGERPRINT,
            "--json",
        ],
        cert_pem.as_bytes(),
    );
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
}

/// The conflict must be reported *before* `--cert-file` is ever read
/// (`docs/CLI.md` §6.11): a nonexistent path proves the ordering, since a
/// read-first implementation would instead report the file-read error.
#[test]
fn trust_add_rejects_cert_file_together_with_fingerprint_before_reading_the_path() {
    let sandbox = Sandbox::new();
    sandbox.init();
    let (code, value) = sandbox.json(&[
        "trust",
        "add",
        "peer-a",
        "--cert-file",
        "/no/such/cert.pem",
        "--fingerprint",
        FINGERPRINT,
        "--json",
    ]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("mutually exclusive"),
        "expected the conflict message, not a file-read error: {value}"
    );
}

#[test]
fn trust_add_ca_is_idempotent_for_an_identical_pem() {
    let ca_owner = Sandbox::new();
    ca_owner.init();
    ca_owner.qsh(&["cert", "init", "--json"]);
    let ca_pem =
        std::fs::read_to_string(ca_owner.config.join("ca").join("ca.pem")).expect("read ca.pem");

    let sandbox = Sandbox::new();
    sandbox.init();
    let (code, first) = sandbox.json_with_stdin(
        &[
            "trust",
            "add-ca",
            "foreign-ca",
            "--cert-file",
            "-",
            "--json",
        ],
        ca_pem.as_bytes(),
    );
    assert_eq!(code, 0, "{first}");
    assert_eq!(first["data"]["created"], true);

    let (code, second) = sandbox.json_with_stdin(
        &[
            "trust",
            "add-ca",
            "foreign-ca",
            "--cert-file",
            "-",
            "--json",
        ],
        ca_pem.as_bytes(),
    );
    assert_eq!(code, 0, "{second}");
    assert_eq!(second["data"]["created"], false);
}

#[test]
fn trust_add_ca_rejects_a_second_pem_under_an_existing_name() {
    let ca_owner_a = Sandbox::new();
    ca_owner_a.init();
    ca_owner_a.qsh(&["cert", "init", "--json"]);
    let ca_pem_a = std::fs::read_to_string(ca_owner_a.config.join("ca").join("ca.pem"))
        .expect("read ca.pem a");

    let ca_owner_b = Sandbox::new();
    ca_owner_b.init();
    ca_owner_b.qsh(&["cert", "init", "--json"]);
    let ca_pem_b = std::fs::read_to_string(ca_owner_b.config.join("ca").join("ca.pem"))
        .expect("read ca.pem b");

    let sandbox = Sandbox::new();
    sandbox.init();
    let (code, first) = sandbox.json_with_stdin(
        &[
            "trust",
            "add-ca",
            "foreign-ca",
            "--cert-file",
            "-",
            "--json",
        ],
        ca_pem_a.as_bytes(),
    );
    assert_eq!(code, 0, "{first}");

    let (code, second) = sandbox.json_with_stdin(
        &[
            "trust",
            "add-ca",
            "foreign-ca",
            "--cert-file",
            "-",
            "--json",
        ],
        ca_pem_b.as_bytes(),
    );
    assert_eq!(code, 255, "{second}");
    assert_eq!(second["error"]["code"], "INVALID_ARGUMENT");
}

/// The recovery path `add_ca_append_only`'s own error message and
/// `docs/CLI.md` §6.11 both promise (ADR-0013 결정 5): a name collision
/// is `INVALID_ARGUMENT`, but `trust remove <name>` unpins the CA root
/// so a second, different PEM can then be registered under that name.
#[test]
fn trust_add_ca_collision_is_recoverable_with_trust_remove() {
    let ca_owner_a = Sandbox::new();
    ca_owner_a.init();
    ca_owner_a.qsh(&["cert", "init", "--json"]);
    let ca_pem_a = std::fs::read_to_string(ca_owner_a.config.join("ca").join("ca.pem"))
        .expect("read ca.pem a");

    let ca_owner_b = Sandbox::new();
    ca_owner_b.init();
    ca_owner_b.qsh(&["cert", "init", "--json"]);
    let ca_pem_b = std::fs::read_to_string(ca_owner_b.config.join("ca").join("ca.pem"))
        .expect("read ca.pem b");

    let sandbox = Sandbox::new();
    sandbox.init();
    let (code, first) = sandbox.json_with_stdin(
        &["trust", "add-ca", "x", "--cert-file", "-", "--json"],
        ca_pem_a.as_bytes(),
    );
    assert_eq!(code, 0, "{first}");
    assert_eq!(first["data"]["created"], true);

    let (code, collision) = sandbox.json_with_stdin(
        &["trust", "add-ca", "x", "--cert-file", "-", "--json"],
        ca_pem_b.as_bytes(),
    );
    assert_eq!(code, 255, "{collision}");
    assert_eq!(collision["error"]["code"], "INVALID_ARGUMENT");

    let (code, removed) = sandbox.json(&["trust", "remove", "x", "--json"]);
    assert_eq!(code, 0, "{removed}");
    assert_eq!(
        removed["data"],
        serde_json::json!({"name": "x", "removed": true})
    );

    let (code, second) = sandbox.json_with_stdin(
        &["trust", "add-ca", "x", "--cert-file", "-", "--json"],
        ca_pem_b.as_bytes(),
    );
    assert_eq!(code, 0, "{second}");
    assert_eq!(second["data"]["created"], true);
}
