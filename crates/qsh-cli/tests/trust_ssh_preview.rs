//! `qsh trust ssh-preview` (ADR-0026 decision 4): a read-only preview of the
//! pin commands and ACL drafts an `authorized_keys` file would map to.
//!
//! Every test runs the built binary in a temp sandbox with the checked-in
//! golden key; nothing reads the developer's `~/.ssh`.

mod common;
mod ssh_golden;

use common::Sandbox;
use serde_json::Value;
use tempfile::TempDir;

const EXPECTED_ROW: &str = "[[acl]]\nprincipal = \"device:<name>\"\nallow = [\"exec.run\", \"session.open\", \"session.list\", \"session.attach\", \"session.control\"]\n";

fn keys_file(dir: &TempDir, contents: &str) -> String {
    ssh_golden::write(dir.path(), "authorized_keys", contents.as_bytes())
        .display()
        .to_string()
}

fn preview(sandbox: &Sandbox, path: &str) -> Value {
    let (code, value) = sandbox.json(&["trust", "ssh-preview", path, "--json"]);
    assert_eq!(code, 0, "{value}");
    value["data"]["entries"].clone()
}

#[test]
fn trust_ssh_preview_predicts_the_fingerprint_import_ssh_key_produces_for_the_same_key() {
    let preview_box = Sandbox::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys_file(&keys, &format!("{}\n", ssh_golden::GOLDEN_PUB_LINE));
    let entries = preview(&preview_box, &path);
    assert_eq!(entries[0]["status"], "ok");
    assert_eq!(
        entries[0]["ssh_fingerprint"],
        ssh_golden::GOLDEN_SSH_FINGERPRINT
    );

    let importer = Sandbox::new();
    let key = ssh_golden::write(keys.path(), "id_ed25519", &ssh_golden::golden_key_file())
        .display()
        .to_string();
    let (code, value) = importer.json(&[
        "init",
        "--json",
        "--key-store",
        "file",
        "--import-ssh-key",
        &key,
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(entries[0]["qsh_fingerprint"], value["data"]["fingerprint"]);
    assert_eq!(
        entries[0]["ssh_fingerprint"],
        value["data"]["ssh_fingerprint"]
    );
}

#[test]
fn trust_ssh_preview_leaves_trust_toml_and_acl_toml_byte_identical() {
    let sandbox = Sandbox::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys_file(&keys, &format!("{}\n", ssh_golden::GOLDEN_PUB_LINE));
    let trust = b"# operator trust file\n".to_vec();
    let acl = b"# operator acl file\n".to_vec();
    std::fs::write(sandbox.config_dir().join("trust.toml"), &trust).unwrap();
    std::fs::write(sandbox.config_dir().join("acl.toml"), &acl).unwrap();

    preview(&sandbox, &path);
    assert_eq!(
        std::fs::read(sandbox.config_dir().join("trust.toml")).unwrap(),
        trust
    );
    assert_eq!(
        std::fs::read(sandbox.config_dir().join("acl.toml")).unwrap(),
        acl
    );

    // With none present, none is created.
    let bare = Sandbox::new();
    preview(&bare, &path);
    assert!(!bare.config_dir().join("trust.toml").exists());
    assert!(!bare.config_dir().join("acl.toml").exists());
}

#[test]
fn trust_ssh_preview_emits_no_acl_row_for_a_line_with_options() {
    let sandbox = Sandbox::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys_file(
        &keys,
        &format!(
            "command=\"/bin/true\",no-pty {}\n",
            ssh_golden::GOLDEN_PUB_LINE
        ),
    );
    let entries = preview(&sandbox, &path);
    assert_eq!(entries[0]["status"], "restricted_options");
    assert!(entries[0].get("acl_row").is_none(), "{}", entries[0]);
    assert!(entries[0].get("trust_command").is_none(), "{}", entries[0]);
    assert_eq!(
        entries[0]["ssh_fingerprint"],
        ssh_golden::GOLDEN_SSH_FINGERPRINT
    );
}

#[test]
fn trust_ssh_preview_acl_row_is_the_policy_example_row() {
    let sandbox = Sandbox::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys_file(&keys, &format!("{}\n", ssh_golden::GOLDEN_PUB_LINE));
    let entries = preview(&sandbox, &path);
    assert_eq!(entries[0]["acl_row"], EXPECTED_ROW);
    assert_eq!(
        entries[0]["trust_command"],
        format!(
            "qsh trust add <name> --fingerprint {}",
            ssh_golden::golden_qsh_fingerprint()
        )
    );
}

#[test]
fn trust_ssh_preview_placeholder_row_pasted_unedited_matches_no_pinned_principal() {
    let sandbox = Sandbox::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys_file(&keys, &format!("{}\n", ssh_golden::GOLDEN_PUB_LINE));
    sandbox.init();
    let entries = preview(&sandbox, &path);
    let row = entries[0]["acl_row"].as_str().unwrap().to_string();

    sandbox.trust_add("laptop", None, &ssh_golden::golden_qsh_fingerprint());
    let acl_path = sandbox.config_dir().join("acl.toml");
    std::fs::write(&acl_path, &row).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&acl_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let (code, value) = sandbox.json(&[
        "acl",
        "check",
        "--principal",
        "device:laptop",
        "--action",
        "exec.run",
        "--auth-path",
        "pin",
        "--json",
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["decision"], "deny", "{value}");

    let (code, doctor) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{doctor}");
    assert!(
        doctor.to_string().contains("acl_principal_unmatched"),
        "{doctor}"
    );
}

#[test]
fn trust_ssh_preview_reports_already_pinned_as_for_a_known_fingerprint() {
    let sandbox = Sandbox::new();
    sandbox.init();
    sandbox.trust_add("laptop", None, &ssh_golden::golden_qsh_fingerprint());
    let keys = tempfile::tempdir().unwrap();
    let path = keys_file(&keys, &format!("{}\n", ssh_golden::GOLDEN_PUB_LINE));
    let entries = preview(&sandbox, &path);
    assert_eq!(entries[0]["already_pinned_as"], "laptop");
}

#[test]
fn trust_ssh_preview_sanitizes_control_characters_in_comments() {
    let sandbox = Sandbox::new();
    let keys = tempfile::tempdir().unwrap();
    let base = ssh_golden::GOLDEN_PUB_LINE
        .rsplit_once(' ')
        .unwrap()
        .0
        .to_string();
    let path = keys_file(&keys, &format!("{base} evil\x1b[31mred\x07bell\n"));
    let output = sandbox.qsh(&["trust", "ssh-preview", &path, "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\x1b') && !text.contains('\x07'), "{text:?}");
    let human = sandbox.qsh(&["trust", "ssh-preview", &path]);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(!text.contains('\x1b') && !text.contains('\x07'), "{text:?}");
}

#[test]
fn trust_ssh_preview_never_echoes_bytes_of_a_malformed_line() {
    let sandbox = Sandbox::new();
    let keys = tempfile::tempdir().unwrap();
    let marker = "QSHLEAKMARKER0123456789";
    let path = keys_file(
        &keys,
        &format!("ssh-ed25519 {marker} {marker}\n{marker} {marker}\n"),
    );
    let entries = preview(&sandbox, &path);
    assert_eq!(entries[0]["status"], "malformed");
    assert_eq!(entries[1]["status"], "malformed");
    for json in [true, false] {
        let mut args = vec!["-vv", "trust", "ssh-preview", path.as_str()];
        if json {
            args.push("--json");
        }
        let output = sandbox.qsh(&args);
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!all.contains(marker), "input bytes leaked: {all}");
    }
}
