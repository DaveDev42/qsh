//! `qsh setup` at the CLI boundary (`docs/CLI.md` §6.20, ADR-0024 결과 절,
//! `docs/design/testing.md` L6). What the orchestrator decides per step is
//! pinned in `crates/qsh-core/tests/setup.rs`; this file pins the binary:
//! exit codes, machine-mode discipline, and what reaches stdout/stderr.

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use common::{Sandbox, exit_code, sole_envelope};
use qsh_proto::{SetupRole, SetupStatus, SetupStepId};
use serde_json::Value;

/// A sandbox whose `config.toml` selects the file key store (never the OS
/// keychain from a test) plus `extra` config text.
fn configured(extra: &str) -> Sandbox {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        format!("[identity]\nkey_store = \"file\"\n{extra}"),
    )
    .expect("write config.toml");
    sandbox
}

/// The peer's certificate PEM, from an initialized sandbox.
fn peer_cert_pem() -> String {
    let peer = Sandbox::initialized();
    let (code, exported) = peer.json(&["identity", "export", "--json"]);
    assert_eq!(code, 0, "{exported}");
    exported["data"]["cert_pem"]
        .as_str()
        .expect("cert_pem")
        .to_string()
}

fn write_cert(sandbox: &Sandbox, pem: &str) -> String {
    let path = sandbox.home_dir().join("peer.pem");
    std::fs::write(&path, pem).expect("write peer cert");
    path.to_str().expect("utf8 path").to_string()
}

/// Every file under `root`, relative, with its bytes.
fn files_under(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().display().to_string();
                out.push((rel, std::fs::read(&path).expect("read file")));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn step<'a>(data: &'a Value, id: &str) -> &'a Value {
    data["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("no {id} step in {data}"))
}

/// ADR-0024 decision 7: in machine mode a missing or malformed input is
/// `INVALID_ARGUMENT` before the first step, so nothing is written, and
/// stdout is one envelope line.
#[test]
fn setup_machine_mode_rejects_missing_input_before_any_write() {
    let cases: &[&[&str]] = &[
        &["setup", "--json"],
        &["setup", "host", "--json"],
        &[
            "setup",
            "client",
            "laptop",
            "--address",
            "h.example:4433",
            "--json",
        ],
        &["setup", "client", "--address", "h.example:4433", "--json"],
        &["setup", "listener", "--peer", "macmini", "--json"],
        &["setup", "host", "--to", "macmini", "--json"],
    ];
    for args in cases {
        let sandbox = Sandbox::new();
        let (code, envelope) = sandbox.json(args);
        assert_eq!(code, 255, "{args:?}: {envelope}");
        assert_eq!(envelope["ok"], false, "{args:?}: {envelope}");
        assert_eq!(
            envelope["error"]["code"], "INVALID_ARGUMENT",
            "{args:?}: {envelope}"
        );
        assert_eq!(envelope["command"], "setup.run", "{args:?}: {envelope}");
        assert!(
            files_under(sandbox.config_dir()).is_empty()
                && files_under(sandbox.state_dir()).is_empty(),
            "{args:?} wrote files before rejecting its input"
        );
    }

    // A malformed PEM is rejected up front too, not after `identity`.
    let sandbox = Sandbox::new();
    let bad = write_cert(&sandbox, "not a certificate\n");
    let (code, envelope) = sandbox.json(&[
        "setup",
        "listener",
        "--peer",
        "macmini",
        "--peer-cert",
        &bad,
        "--json",
    ]);
    assert_eq!(code, 255, "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");
    assert!(files_under(sandbox.config_dir()).is_empty());
    assert!(files_under(sandbox.state_dir()).is_empty());
}

/// The sandbox runs `qsh` with stdin closed; a prompt would read end of
/// input and could not proceed, so a run that finishes with exit 255 and an
/// `INVALID_ARGUMENT` envelope shows it never waited on one. `--jsonl`
/// gets the same treatment.
#[test]
fn setup_machine_mode_never_opens_a_prompt() {
    for mode in ["--json", "--jsonl"] {
        let sandbox = configured("");
        let output = sandbox.qsh(&["setup", "client", "--address", "h.example:4433", mode]);
        assert_eq!(exit_code(&output), 255);
        let envelope = sole_envelope(&output.stdout, &["setup", mode]);
        assert_eq!(envelope["error"]["code"], "INVALID_ARGUMENT", "{envelope}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        for prompt in ["role?", "trust-store name", "Enter to check", "[y/N]"] {
            assert!(
                !stderr.contains(prompt),
                "{mode} printed a prompt ({prompt}): {stderr}"
            );
        }
    }
}

/// Human mode without a terminal is the same as machine mode for missing
/// input: `INVALID_ARGUMENT`, exit 255, nothing on stdout, no prompt text.
#[test]
fn setup_human_mode_without_a_tty_treats_missing_input_as_invalid_argument() {
    let sandbox = configured("");
    let output = sandbox.qsh(&["setup", "client", "laptop", "--address", "h.example:4433"]);
    assert_eq!(exit_code(&output), 255);
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("INVALID_ARGUMENT"), "{stderr}");
    assert!(!stderr.contains("[y/N]"), "{stderr}");

    let output = sandbox.qsh(&["setup"]);
    assert_eq!(exit_code(&output), 255);
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("INVALID_ARGUMENT"),
        "no role without a terminal is INVALID_ARGUMENT"
    );
}

/// ADR-0024 decision 2: combinations that make no sense are clap usage
/// errors (exit 2, nothing on stdout).
#[test]
fn setup_usage_conflicts_exit_2() {
    let code = "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab";
    let cases: &[&[&str]] = &[
        // Code and --peer-cert are two pin means.
        &["setup", "client", "laptop", code, "--peer-cert", "p.pem"],
        &[
            "setup",
            "client",
            "laptop",
            "--code-stdin",
            "--peer-cert",
            "p.pem",
        ],
        // Positional code with --code-stdin.
        &["setup", "client", "laptop", code, "--code-stdin"],
        // Flags on a role that does not define them.
        &["setup", "client", "laptop", "--forward"],
        &["setup", "client", "laptop", "--service"],
        &["setup", "listener", "--peer", "m", "--forward"],
        &["setup", "host", "--peer", "m", "--code-stdin"],
        &["setup", "listener", "--to", "m"],
        // --peer and --to name the same slot two ways.
        &["setup", "host", "--peer", "a", "--to", "b"],
        // Unknown role.
        &["setup", "server"],
    ];
    for args in cases {
        for mode in [None, Some("--json")] {
            let mut argv: Vec<&str> = args.to_vec();
            argv.extend(mode);
            let sandbox = Sandbox::new();
            let output = sandbox.qsh(&argv);
            assert_eq!(exit_code(&output), 2, "{argv:?}");
            assert!(output.stdout.is_empty(), "{argv:?} wrote to stdout");
        }
    }
}

/// ADR-0024 decision 9: no key material in any output of any role, and the
/// invite code only inside the host's `invite` step result.
#[test]
fn setup_output_never_carries_key_material() {
    let pem = peer_cert_pem();
    let mut outputs: Vec<(String, String)> = Vec::new();
    let mut key_bodies: Vec<String> = Vec::new();

    let mut record = |label: &str, sandbox: &Sandbox, output: &std::process::Output| {
        outputs.push((
            label.to_string(),
            format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
        let key = sandbox.config_dir().join("identity").join("device.key");
        if let Ok(text) = std::fs::read_to_string(&key) {
            key_bodies.extend(
                text.lines()
                    .filter(|l| !l.starts_with("-----") && l.len() > 16)
                    .map(str::to_string),
            );
        }
    };

    // host: ACL in place so the invite step actually mints a code.
    let host = configured("");
    std::fs::write(
        host.config_dir().join("acl.toml"),
        "[[acl]]\nprincipal = \"device:laptop\"\nallow = [\"exec.run\", \"session.open\", \
         \"session.list\", \"session.attach\", \"session.control\"]\n",
    )
    .expect("write acl.toml");
    let output = host.qsh(&["setup", "host", "--peer", "laptop", "--json"]);
    assert_eq!(exit_code(&output), 0);
    let envelope = sole_envelope(&output.stdout, &["setup", "host"]);
    let invite = step(&envelope["data"], "invite");
    assert_eq!(invite["status"], "done", "{envelope}");
    let invite_code = invite["result"]["code"].as_str().expect("invite code");
    // Everything except the invite step's own result is code-free.
    let mut stripped = envelope.clone();
    for s in stripped["data"]["steps"].as_array_mut().unwrap() {
        if s["id"] == "invite" {
            s["result"] = Value::Null;
        }
    }
    let stripped_text = stripped.to_string();
    assert!(
        !stripped_text.contains(invite_code),
        "the invite code appears outside the invite step result: {stripped_text}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(invite_code), "code on stderr: {stderr}");
    record("host", &host, &output);

    // client, listener and host --to, all by certificate file.
    let client = configured("");
    let path = write_cert(&client, &pem);
    let output = client.qsh(&[
        "setup",
        "client",
        "laptop",
        "--address",
        "h.example:4433",
        "--peer-cert",
        &path,
        "--json",
    ]);
    assert_eq!(exit_code(&output), 0);
    record("client", &client, &output);

    let listener = configured("[listen]\nbind = \"[::]:4433\"\n");
    let path = write_cert(&listener, &pem);
    let output = listener.qsh(&[
        "setup",
        "listener",
        "--peer",
        "macmini",
        "--peer-cert",
        &path,
        "--json",
    ]);
    assert_eq!(exit_code(&output), 0);
    record("listener", &listener, &output);

    let host_to = configured("[serve]\nto = \"macmini\"\n");
    let path = write_cert(&host_to, &pem);
    let output = host_to.qsh(&[
        "setup",
        "host",
        "--to",
        "macmini",
        "--address",
        "m.example:4433",
        "--peer-cert",
        &path,
        "--json",
    ]);
    assert_eq!(exit_code(&output), 0);
    record("host_to", &host_to, &output);

    // An error envelope carries no key material either.
    let broken = configured("");
    let output = broken.qsh(&["setup", "client", "x", "--address", "h:1", "--json"]);
    record("error", &broken, &output);

    assert!(
        !key_bodies.is_empty(),
        "no identity key was created to look for"
    );
    for (label, text) in &outputs {
        assert!(!text.contains("PRIVATE KEY"), "{label} printed a key block");
        for body in &key_bodies {
            assert!(!text.contains(body), "{label} printed key material");
        }
    }
}

/// The step id, status and role names in `docs/CLI.md` §6.20 are the ones
/// the types serialize (the vocabulary-locking discipline of
/// `crates/qsh-core/tests/doctor_docs.rs`): a name added to the enum
/// without the doc, or the reverse, fails here.
#[test]
fn setup_step_vocabulary_matches_cli_md() {
    fn name<T: serde::Serialize>(value: T) -> String {
        serde_json::to_value(value)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }
    // Exhaustive matches keep these lists complete when a variant is added.
    fn all_ids() -> Vec<SetupStepId> {
        use SetupStepId::*;
        let all = vec![
            Identity, ModeConfig, Acl, PinCert, Pair, Invite, Service, Doctor,
        ];
        for id in &all {
            match id {
                Identity | ModeConfig | Acl | PinCert | Pair | Invite | Service | Doctor => {}
            }
        }
        all
    }
    fn all_statuses() -> Vec<SetupStatus> {
        use SetupStatus::*;
        let all = vec![Done, Already, Pending, Blocked, Skipped];
        for s in &all {
            match s {
                Done | Already | Pending | Blocked | Skipped => {}
            }
        }
        all
    }
    fn all_roles() -> Vec<SetupRole> {
        use SetupRole::*;
        let all = vec![Host, HostTo, Client, Listener];
        for r in &all {
            match r {
                Host | HostTo | Client | Listener => {}
            }
        }
        all
    }

    let cli_md = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/CLI.md"))
        .expect("read docs/CLI.md");
    let start = cli_md.find("### 6.20 ").expect("CLI.md has §6.20");
    let rest = &cli_md[start..];
    let end = rest.find("\n## 7.").expect("§6.20 ends before §7");
    let section = &rest[..end];

    // First-cell backtick tokens of the table whose header cell is `header`.
    let table_first_cells = |header: &str| -> BTreeSet<String> {
        let mut lines = section
            .lines()
            .skip_while(|l| !l.starts_with(&format!("| {header} |")));
        assert!(lines.next().is_some(), "no `{header}` table in §6.20");
        lines
            .skip(1)
            .take_while(|l| l.starts_with('|'))
            .filter_map(|l| l.split('|').nth(1))
            .map(|cell| cell.trim().trim_matches('`').to_string())
            .collect()
    };

    let ids: BTreeSet<String> = all_ids().into_iter().map(name).collect();
    assert_eq!(table_first_cells("id"), ids, "step id table drifted");
    let statuses: BTreeSet<String> = all_statuses().into_iter().map(name).collect();
    assert_eq!(
        table_first_cells("status"),
        statuses,
        "status table drifted"
    );
    for role in all_roles().into_iter().map(name) {
        assert!(
            section.contains(&format!("`{role}`")),
            "role `{role}` is not named in §6.20"
        );
    }
}

/// `setup.run` is local only: no wire message carries it (twin of
/// `acl_show_never_appears_as_a_control_message_wire_variant`).
#[test]
fn setup_run_never_appears_as_a_control_message_wire_variant() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../qsh-proto/proto/qsh/wire/v1.proto"
    ))
    .expect("read v1.proto");
    assert!(source.contains("message "), "v1.proto looks empty");
    let lower = source.to_lowercase();
    assert!(
        !lower.contains("setuprun") && !lower.contains("setup_run") && !lower.contains("setup.run"),
        "the wire proto must never gain a setup.run message"
    );
}
