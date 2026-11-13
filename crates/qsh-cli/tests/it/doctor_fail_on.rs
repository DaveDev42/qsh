//! `qsh doctor --fail-on <warn|error>` (ADR-0027, `docs/CLI.md` §4 and
//! §6.17, `docs/design/testing.md` L6).
//!
//! Three sandboxes give a known severity mix:
//! - `error_box`: initialized, judged a server (`[doctor].mode = "server"`),
//!   no `acl.toml` -> `acl_policy_missing` (error). Without the key doctor
//!   would judge the bare sandbox a client and report nothing (ADR-0066).
//! - `warn_box`: initialized, a valid `acl.toml` and one unknown
//!   `config.toml` key -> `config_unknown_key` (warn), no error.
//! - an uninitialized sandbox, where doctor cannot start.
//!
//! Each precondition is asserted from the report itself, so an
//! environment that adds an unexpected finding fails loudly here instead
//! of silently weakening an exit-code assertion.

use crate::common;

use common::{Sandbox, exit_code, sole_envelope};
use serde_json::Value;

fn error_box() -> Sandbox {
    let sandbox = Sandbox::initialized();
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        "[doctor]\nmode = \"server\"\n",
    )
    .expect("write config.toml");
    let (code, env) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["overall"], "error", "precondition: {env}");
    sandbox
}

fn warn_box() -> Sandbox {
    let sandbox = Sandbox::initialized();
    let acl = sandbox.config_dir().join("acl.toml");
    std::fs::write(
        &acl,
        "[[acl]]\nprincipal = \"device:nobody\"\nallow = [\"exec.run\"]\n",
    )
    .expect("write acl.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&acl, std::fs::Permissions::from_mode(0o600))
            .expect("chmod acl.toml");
    }
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        "definitely_not_a_key = 1\n",
    )
    .expect("write config.toml");
    let (code, env) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["data"]["overall"], "warn", "precondition: {env}");
    sandbox
}

/// The envelope with the per-run `request_id` blanked, so two runs can be
/// compared byte for byte.
fn normalized(stdout: &[u8], args: &[&str]) -> String {
    let mut value = sole_envelope(stdout, args);
    value["request_id"] = Value::Null;
    value.to_string()
}

#[test]
fn doctor_without_fail_on_keeps_exit_zero_and_byte_identical_stdout() {
    let sandbox = error_box();
    let plain = sandbox.qsh(&["doctor", "--json"]);
    assert_eq!(exit_code(&plain), 0);
    // The flag must not change a single stdout byte; `--fail-on error`
    // trips here (exit 1), so equality below proves the render is shared.
    let gated = sandbox.qsh(&["doctor", "--json", "--fail-on", "error"]);
    assert_eq!(exit_code(&gated), 1);
    assert_eq!(
        normalized(&plain.stdout, &["doctor"]),
        normalized(&gated.stdout, &["doctor", "--fail-on"]),
    );
    // Human form: no request_id, so raw bytes compare.
    let plain = sandbox.qsh(&["doctor"]);
    let gated = sandbox.qsh(&["doctor", "--fail-on", "error"]);
    assert_eq!(exit_code(&plain), 0);
    assert_eq!(exit_code(&gated), 1);
    assert_eq!(plain.stdout, gated.stdout);
}

#[test]
fn doctor_fail_on_warn_exits_one_when_a_warn_or_error_finding_exists() {
    for (name, sandbox) in [("warn", warn_box()), ("error", error_box())] {
        for mode in [
            &["doctor", "--fail-on", "warn"][..],
            &["doctor", "--fail-on", "warn", "--json"],
        ] {
            let out = sandbox.qsh(mode);
            assert_eq!(exit_code(&out), 1, "{name} box, {mode:?}");
        }
    }
}

#[test]
fn doctor_fail_on_error_ignores_warn_findings() {
    let sandbox = warn_box();
    for mode in [
        &["doctor", "--fail-on", "error"][..],
        &["doctor", "--fail-on", "error", "--json"],
    ] {
        let out = sandbox.qsh(mode);
        assert_eq!(exit_code(&out), 0, "{mode:?}");
    }
    let tripped = error_box().qsh(&["doctor", "--fail-on", "error"]);
    assert_eq!(exit_code(&tripped), 1);
}

#[test]
fn doctor_fail_on_keeps_the_envelope_ok_true_and_every_finding() {
    let sandbox = error_box();
    let plain = sandbox.qsh(&["doctor", "--json"]);
    let gated = sandbox.qsh(&["doctor", "--json", "--fail-on", "warn"]);
    assert_eq!(exit_code(&gated), 1);
    let env = sole_envelope(&gated.stdout, &["doctor"]);
    assert_eq!(env["ok"], true, "{env}");
    assert!(env.get("error").is_none(), "{env}");
    assert_eq!(env["data"]["overall"], "error");
    let findings = env["data"]["findings"].as_array().expect("findings");
    let plain_env = sole_envelope(&plain.stdout, &["doctor"]);
    assert_eq!(findings, plain_env["data"]["findings"].as_array().unwrap());
    assert!(!findings.is_empty());
}

#[test]
fn doctor_fail_on_rejects_info_and_unknown_severities_with_exit_2() {
    let sandbox = error_box();
    for value in ["info", "ok", "critical", ""] {
        for json in [false, true] {
            let mut args = vec!["doctor", "--fail-on", value];
            if json {
                args.push("--json");
            }
            let out = sandbox.qsh(&args);
            assert_eq!(exit_code(&out), 2, "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}");
        }
    }
}

#[test]
fn doctor_fail_on_does_not_change_the_255_of_a_doctor_that_cannot_start() {
    let sandbox = Sandbox::new();
    for threshold in ["warn", "error"] {
        let (code, env) = sandbox.json(&["doctor", "--json", "--fail-on", threshold]);
        assert_eq!(code, 255, "{env}");
        assert_eq!(env["ok"], false, "{env}");
        assert_eq!(env["error"]["code"], "CONFIG_ERROR", "{env}");
    }
}

/// The findings a freshly initialized client reports are the same on every
/// platform (ADR-0035 decision 17, ADR-0066): doctor judges a device with no
/// server signal a client, so none of the checks that read the service
/// registry, the listener or the ACL policy run. Only `qsh_path_shadowed`
/// depends on the machine (`$PATH`). Every code is one of the shared
/// vocabulary.
#[test]
fn doctor_on_an_initialized_client_reports_the_same_findings_on_every_platform() {
    const MACHINE_DEPENDENT: &[&str] = &["qsh_path_shadowed"];
    let sandbox = Sandbox::initialized();
    let (code, env) = sandbox.json(&["doctor", "--json"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["command"], "doctor.run", "{env}");
    let codes: Vec<&str> = env["data"]["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| finding["code"].as_str().expect("code"))
        .collect();
    for code in &codes {
        assert!(
            qsh_core::doctor::EXPECTED_DOCTOR_CODES.contains(code),
            "{code} is not in the shared vocabulary"
        );
    }
    let client_state: Vec<&str> = codes
        .iter()
        .copied()
        .filter(|code| !MACHINE_DEPENDENT.contains(code))
        .collect();
    assert!(client_state.is_empty(), "{env}");
    assert_ne!(env["data"]["overall"], "error", "{env}");
    assert_eq!(env["data"]["mode"], "client", "{env}");
    assert_eq!(env["data"]["mode_basis"], "no_server_signal", "{env}");
}
