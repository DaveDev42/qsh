//! `qsh doctor`'s device mode through the real binary (ADR-0066,
//! `docs/CLI.md` §6.17, `docs/design/testing.md` L6): a client-only device
//! comes out without an error whether or not an `acl.toml` exists, and
//! `--mode` and `[doctor].mode` override what doctor infers.
//!
//! `qsh_path_shadowed` depends on the `$PATH` of the machine running the
//! test, so findings are compared without it.

use crate::common;

use common::{Sandbox, exit_code};
use serde_json::Value;

fn finding_codes(env: &Value) -> Vec<&str> {
    env["data"]["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| finding["code"].as_str().expect("code"))
        .filter(|code| *code != "qsh_path_shadowed")
        .collect()
}

fn write_acl(sandbox: &Sandbox, text: &str) {
    let acl = sandbox.config_dir().join("acl.toml");
    std::fs::write(&acl, text).expect("write acl.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&acl, std::fs::Permissions::from_mode(0o600))
            .expect("chmod acl.toml");
    }
}

/// An initialized device with one pin of role `none` and an address: a
/// client-only machine as a deployment leaves it.
fn client() -> Sandbox {
    let sandbox = Sandbox::initialized();
    sandbox.trust_add(
        "workstation",
        Some("workstation.example:4433"),
        &qsh_transport::Fingerprint::of_spki_der(b"workstation").to_string(),
    );
    sandbox
}

#[test]
fn a_client_only_device_without_acl_toml_is_not_an_error() {
    let sandbox = client();
    let (code, env) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["mode"], "client", "{env}");
    assert_eq!(env["data"]["mode_basis"], "no_server_signal", "{env}");
    assert_ne!(env["data"]["overall"], "error", "{env}");
    assert_eq!(finding_codes(&env), ["trust_remove_scope"], "{env}");

    // `--fail-on error` is the gate a deployment script uses.
    let gated = sandbox.qsh(&["doctor", "--fail-on", "error"]);
    assert_eq!(exit_code(&gated), 0);
}

#[test]
fn a_client_only_device_with_a_rendered_acl_toml_is_not_an_error() {
    let sandbox = client();
    // A deployment renders one `acl.toml` for every device; none of its rows
    // names this device's pin.
    write_acl(
        &sandbox,
        "[[acl]]\nprincipal = \"device:someone-else\"\nallow = [\"exec.run\"]\n",
    );
    let (code, env) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["mode"], "client", "{env}");
    assert_ne!(env["data"]["overall"], "error", "{env}");
    assert_eq!(finding_codes(&env), ["trust_remove_scope"], "{env}");
}

#[test]
fn the_flag_judges_the_same_device_a_server() {
    let sandbox = client();
    write_acl(
        &sandbox,
        "[[acl]]\nprincipal = \"device:someone-else\"\nallow = [\"exec.run\"]\n",
    );
    let (code, env) = sandbox.json(&["doctor", "--mode", "server", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["mode"], "server", "{env}");
    assert_eq!(env["data"]["mode_basis"], "request", "{env}");
    assert_eq!(env["data"]["overall"], "error", "{env}");
    assert!(
        finding_codes(&env).contains(&"acl_principal_unmatched"),
        "{env}"
    );
}

#[test]
fn the_config_key_judges_the_device_and_the_flag_wins_over_it() {
    let sandbox = client();
    let (code, set) = sandbox.json(&["config", "set", "doctor.mode", "server", "--json"]);
    assert_eq!(code, 0, "{set}");
    let (code, env) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["mode"], "server", "{env}");
    assert_eq!(env["data"]["mode_basis"], "config", "{env}");
    assert!(finding_codes(&env).contains(&"acl_policy_missing"), "{env}");

    let (code, env) = sandbox.json(&["doctor", "--mode", "client", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["mode"], "client", "{env}");
    assert_eq!(env["data"]["mode_basis"], "request", "{env}");
    assert_ne!(env["data"]["overall"], "error", "{env}");
}

#[test]
fn the_human_report_names_the_mode() {
    let sandbox = client();
    let out = sandbox.qsh(&["doctor"]);
    assert_eq!(exit_code(&out), 0);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.lines().any(|l| l == "mode: client (no_server_signal)"),
        "{text}"
    );
}

#[test]
fn an_unknown_mode_is_a_usage_error() {
    let sandbox = client();
    let out = sandbox.qsh(&["doctor", "--mode", "both", "--json"]);
    assert_eq!(exit_code(&out), 2);
    assert!(out.stdout.is_empty());
}
