//! The device mode doctor judges (ADR-0066): a client-only device comes out
//! `ok` with or without an `acl.toml`, every server signal flips the verdict,
//! and the request and `[doctor].mode` override the inference. Each test
//! injects the OS and a tempdir home, so none reads this machine's service
//! units.

use qsh_proto::ConfigSetReq;

use super::*;

fn set(ops: &Ops, key: &str, value: &str) {
    ops.config_set(ConfigSetReq {
        key: key.to_string(),
        value: value.to_string(),
    })
    .unwrap();
}

fn pin(ops: &Ops, name: &str, role: Option<&str>) {
    ops.trust_add(TrustAddReq {
        name: name.into(),
        address: Some(format!("{name}.example:4433")),
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(name.as_bytes()).to_string()),
        cert_pem: None,
        role: role.map(str::to_string),
    })
    .unwrap();
}

fn run(ops: &Ops, mode: Option<&str>, env: &DoctorEnvironment<'_>) -> DoctorData {
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    ops.doctor_assemble(
        DoctorReq {
            host: None,
            mode: mode.map(str::to_string),
        },
        unix_seconds(SystemTime::now()),
        &identity,
        &config,
        env,
    )
    .unwrap()
}

/// Doctor on `ops` with a Linux environment whose home is `home`.
fn run_in(ops: &Ops, mode: Option<&str>, home: &Path) -> DoctorData {
    let keystore = crate::identity::MemoryKeyStore::new();
    let env = DoctorEnvironment {
        os: probe::HostOs::Linux,
        home_dir: Some(home),
        username: Some("m28-mode-doctor"),
        ..minimal_env(&keystore)
    };
    run(ops, mode, &env)
}

fn register_unit(home: &Path, mode: &str) {
    let unit = probe::linux_systemd_user_unit_path(home, mode);
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(unit, b"stub").unwrap();
}

/// A device with an identity, a pin with role `none` and no `acl.toml`: what
/// a client-only machine looks like.
fn client_ops() -> (tempfile::TempDir, Ops) {
    let (dir, ops) = temp_ops();
    init_identity(&ops);
    pin(&ops, "laptop", Some("none"));
    (dir, ops)
}

fn acl_codes(data: &DoctorData) -> Vec<&str> {
    codes(&data.findings)
        .into_iter()
        .filter(|code| code.starts_with("acl_"))
        .collect()
}

#[test]
fn a_client_only_device_without_acl_toml_is_ok() {
    let (_guard, ops) = client_ops();
    let home = tempfile::tempdir().unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("client"));
    assert_eq!(data.mode_basis.as_deref(), Some("no_server_signal"));
    assert_eq!(data.overall, "ok", "{:?}", data.findings);
    assert_eq!(codes(&data.findings), ["trust_remove_scope"]);
}

#[test]
fn a_client_only_device_with_an_acl_toml_that_names_none_of_its_pins_is_ok() {
    let (_guard, ops) = client_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
    pin(&ops, "workstation", None);
    let home = tempfile::tempdir().unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("client"));
    assert_eq!(data.overall, "ok", "{:?}", data.findings);
    assert!(acl_codes(&data).is_empty(), "{:?}", data.findings);
}

#[test]
fn a_client_judgment_leaves_out_every_server_only_check() {
    let (_guard, ops) = client_ops();
    add_stub_ca(&ops, "corp-ca");
    let home = tempfile::tempdir().unwrap();
    let keystore = crate::identity::MemoryKeyStore::new();
    let env = DoctorEnvironment {
        os: probe::HostOs::Linux,
        home_dir: Some(home.path()),
        username: Some("m28-mode-doctor"),
        bindv6only_probe: always_v6_only,
        agent_runtime_dir: Some(Path::new("/nonexistent-m28-agent-dir")),
        ..minimal_env(&keystore)
    };
    let data = run(&ops, None, &env);
    assert_eq!(data.mode.as_deref(), Some("client"));
    // The CA with no `acl.toml` row, the missing policy, the missing unit,
    // the IPv6-only bind and the unusable agent directory are each findings
    // on a server and nothing on a client.
    assert_eq!(codes(&data.findings), ["trust_remove_scope"], "{data:?}");

    let server = run(&ops, Some("server"), &env);
    let found = codes(&server.findings);
    for code in [
        "acl_policy_missing",
        "acl_ca_auth_path_missing",
        "service_not_registered",
        "bindv6only_blocks_ipv4",
    ] {
        assert!(found.contains(&code), "{code} missing from {found:?}");
    }
    // `check_agent_dir` only inspects a directory on unix; Windows forwards
    // the agent over a named pipe and never reports this code.
    if cfg!(unix) {
        assert!(
            found.contains(&"agent_dir_unusable"),
            "agent_dir_unusable missing from {found:?}"
        );
    }
}

#[test]
fn a_client_with_an_unparseable_acl_toml_is_told_so_as_a_warning() {
    let (_guard, ops) = client_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), "[[acl]\nthis is not toml").unwrap();
    let home = tempfile::tempdir().unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("client"));
    assert_eq!(acl_codes(&data), ["acl_policy_invalid"]);
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "acl_policy_invalid")
        .unwrap();
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("judged a client"), "{finding:?}");
    assert_eq!(data.overall, "warn");

    // The same file on a server stays the error it always was.
    let server = run_in(&ops, Some("server"), home.path());
    let finding = server
        .findings
        .iter()
        .find(|f| f.code == "acl_policy_invalid")
        .unwrap();
    assert_eq!(finding.status, "error");
}

#[test]
fn a_client_still_gets_the_checks_that_do_not_depend_on_inbound() {
    let (_guard, ops) = client_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (_not_before, not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let keystore = crate::identity::MemoryKeyStore::new();
    let data = ops
        .doctor_assemble(
            DoctorReq {
                host: None,
                mode: None,
            },
            not_after + 86_400,
            &identity.identity,
            &ops.config().unwrap(),
            &minimal_env(&keystore),
        )
        .unwrap();
    assert_eq!(data.mode.as_deref(), Some("client"));
    assert_eq!(data.overall, "error");
    assert!(codes(&data.findings).contains(&"cert_expired"));
}

#[test]
fn a_config_section_for_serving_makes_the_device_a_server() {
    let (_guard, ops) = client_ops();
    set(&ops, "serve.max_sessions", "8");
    let home = tempfile::tempdir().unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("config_section"));
    assert!(codes(&data.findings).contains(&"acl_policy_missing"));
}

#[test]
fn a_registered_service_unit_of_any_run_mode_makes_the_device_a_server() {
    for mode in ["serve", "listen", "reverse"] {
        let (_guard, ops) = client_ops();
        let home = tempfile::tempdir().unwrap();
        register_unit(home.path(), mode);
        let data = run_in(&ops, None, home.path());
        assert_eq!(data.mode.as_deref(), Some("server"), "{mode}");
        assert_eq!(data.mode_basis.as_deref(), Some("service_unit"), "{mode}");
    }
}

#[test]
fn a_serve_record_live_or_left_by_a_crash_makes_the_device_a_server() {
    let (_guard, ops) = client_ops();
    let record = crate::serve::record::ServeRecord::for_current_process(
        "127.0.0.1:4433".parse().unwrap(),
        crate::serve::record::ServeRecordMode::Persistent,
    );
    crate::serve::record::write(ops.paths(), &record).unwrap();
    let home = tempfile::tempdir().unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("daemon"));

    // A record whose process is gone is a serve that crashed: still a server.
    let stale = crate::serve::record::ServeRecord {
        pid: u32::MAX - 1,
        ..record
    };
    crate::serve::record::write(ops.paths(), &stale).unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode_basis.as_deref(), Some("daemon"));
}

/// A `qsh listen` writes no `serve.json`; its localctl endpoint in the
/// runtime directory is what shows it is running.
#[cfg(unix)]
#[test]
fn a_live_localctl_endpoint_makes_the_device_a_server() {
    let (_guard, ops) = client_ops();
    let run_dir = ops.paths().runtime_dir();
    std::fs::create_dir_all(&run_dir).unwrap();
    let home = tempfile::tempdir().unwrap();

    // A leftover endpoint of a process that is gone shows nothing.
    std::fs::write(run_dir.join(format!("{}.sock", u32::MAX - 1)), b"").unwrap();
    assert_eq!(
        run_in(&ops, None, home.path()).mode.as_deref(),
        Some("client")
    );

    std::fs::write(run_dir.join(format!("{}.sock", std::process::id())), b"").unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("daemon"));
}

#[test]
fn a_pin_with_a_role_or_a_live_role_invite_makes_the_device_a_server() {
    let home = tempfile::tempdir().unwrap();

    let (_guard, ops) = client_ops();
    pin(&ops, "teammate", Some("exec"));
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("role_pin"));

    let (_guard, ops) = client_ops();
    ops.trust_invite(qsh_proto::TrustInviteReq {
        as_name: Some("quiet".into()),
        role: Some("none".into()),
    })
    .unwrap();
    assert_eq!(
        run_in(&ops, None, home.path()).mode.as_deref(),
        Some("client"),
        "an invite that pins `none` authorizes nothing"
    );
    ops.trust_invite(qsh_proto::TrustInviteReq {
        as_name: Some("laptop2".into()),
        role: Some("full".into()),
    })
    .unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("role_invite"));
}

#[test]
fn a_server_device_reports_what_it_always_did() {
    let (_guard, ops) = client_ops();
    let home = tempfile::tempdir().unwrap();
    register_unit(home.path(), "serve");
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    // No `acl.toml` on a server: the same error as before ADR-0066.
    assert_eq!(data.overall, "error");
    assert!(codes(&data.findings).contains(&"acl_policy_missing"));
}

#[test]
fn the_request_overrides_the_config_and_the_config_overrides_the_inference() {
    let (_guard, ops) = client_ops();
    let home = tempfile::tempdir().unwrap();
    register_unit(home.path(), "serve");

    // The request beats the state: a unit is registered, the flag says client.
    let data = run_in(&ops, Some("client"), home.path());
    assert_eq!(data.mode.as_deref(), Some("client"));
    assert_eq!(data.mode_basis.as_deref(), Some("request"));
    assert_eq!(data.overall, "ok", "{:?}", data.findings);

    // `[doctor].mode` beats the state.
    set(&ops, "doctor.mode", "client");
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("client"));
    assert_eq!(data.mode_basis.as_deref(), Some("config"));

    // The request beats the config.
    let data = run_in(&ops, Some("server"), home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("request"));

    // `auto` in the request defers to the config, `auto` in the config to
    // the state.
    let data = run_in(&ops, Some("auto"), home.path());
    assert_eq!(data.mode_basis.as_deref(), Some("config"));
    set(&ops, "doctor.mode", "auto");
    let data = run_in(&ops, Some("auto"), home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("service_unit"));
}

#[test]
fn server_in_the_config_makes_a_bare_device_report_the_missing_policy() {
    let (_guard, ops) = client_ops();
    set(&ops, "doctor.mode", "server");
    let home = tempfile::tempdir().unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("config"));
    assert!(codes(&data.findings).contains(&"acl_policy_missing"));
}

#[test]
fn an_unknown_request_mode_is_invalid_argument() {
    let (_guard, ops) = client_ops();
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let keystore = crate::identity::MemoryKeyStore::new();
    let err = ops
        .doctor_assemble(
            DoctorReq {
                host: None,
                mode: Some("both".into()),
            },
            unix_seconds(SystemTime::now()),
            &identity,
            &ops.config().unwrap(),
            &minimal_env(&keystore),
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(!err.retryable);
}

#[test]
fn the_config_key_takes_only_the_three_words() {
    let (_guard, ops) = client_ops();
    for word in ["auto", "client", "server"] {
        set(&ops, "doctor.mode", word);
        assert_eq!(
            ops.config().unwrap().doctor.mode,
            Some(match word {
                "auto" => crate::config::DoctorModeSetting::Auto,
                "client" => crate::config::DoctorModeSetting::Client,
                _ => crate::config::DoctorModeSetting::Server,
            })
        );
    }
    let err = ops
        .config_set(ConfigSetReq {
            key: "doctor.mode".into(),
            value: "both".into(),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

/// `qsh trust allow` grants authorize inbound requests whatever the pin's
/// role is, so a pin that holds some is a server's pin. Without this a
/// device that authorizes only through grants would be judged a client and
/// lose `acl_policy_missing`.
#[test]
fn a_pin_with_grants_and_no_role_makes_the_device_a_server() {
    let (_guard, ops) = client_ops();
    let home = tempfile::tempdir().unwrap();
    assert_eq!(
        run_in(&ops, None, home.path()).mode.as_deref(),
        Some("client")
    );

    ops.trust_allow(qsh_proto::TrustAllowReq {
        name: "laptop".into(),
        actions: vec!["exec.run".into()],
        paths: Vec::new(),
        scope: None,
    })
    .unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("role_pin"));
    assert!(codes(&data.findings).contains(&"acl_policy_missing"));
}

/// An `invites.toml` that exists and does not parse is an unknown, and an
/// unknown reads as a server: the wrong guess in the other direction hides
/// the policy checks.
#[test]
fn an_unreadable_invite_store_reads_as_a_server() {
    let (_guard, ops) = client_ops();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(ops.paths().invites_file(), b"this is = not [valid toml").unwrap();
    let data = run_in(&ops, None, home.path());
    assert_eq!(data.mode.as_deref(), Some("server"));
    assert_eq!(data.mode_basis.as_deref(), Some("role_invite"));
}
