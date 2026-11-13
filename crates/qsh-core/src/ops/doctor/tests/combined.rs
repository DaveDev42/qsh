//! The combined endpoint's doctor rows (ADR-0059 decision 22): the two new
//! codes, the restart notice for a `listen` that hosts sessions, and the
//! two-role policy example. Each test injects the OS and a tempdir home, so
//! none reads this machine's service units.

use qsh_proto::ConfigSetReq;

use super::*;

fn set(ops: &Ops, key: &str, value: &str) {
    ops.config_set(ConfigSetReq {
        key: key.to_string(),
        value: value.to_string(),
    })
    .unwrap();
}

/// A healthy ops whose config makes `qsh listen` combined (or not).
fn ops_with(serve: bool, serve_bind: Option<&str>) -> (tempfile::TempDir, Ops) {
    let (dir, ops) = healthy_ops();
    set(&ops, "listen.serve", if serve { "true" } else { "false" });
    // The mode is `listen` only once `[listen]` has a value, as in a real
    // config; `serve = false` alone is the default and infers `serve`.
    set(&ops, "listen.bind", "127.0.0.1:0");
    if let Some(bind) = serve_bind {
        set(&ops, "serve.bind", bind);
    }
    (dir, ops)
}

fn report(ops: &Ops, env: &DoctorEnvironment<'_>) -> Vec<DoctorFinding> {
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    ops.doctor_assemble(
        DoctorReq {
            host: None,
            mode: None,
        },
        unix_seconds(SystemTime::now()),
        &identity,
        &config,
        env,
    )
    .unwrap()
    .findings
}

fn linux_env<'a>(keystore: &'a dyn KeyStore, home: &'a Path) -> DoctorEnvironment<'a> {
    DoctorEnvironment {
        os: probe::HostOs::Linux,
        home_dir: Some(home),
        username: Some("m27-combined-doctor"),
        ..minimal_env(keystore)
    }
}

fn register_serve_unit(home: &Path) {
    let unit = probe::linux_systemd_user_unit_path(home, "serve");
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(unit, b"stub").unwrap();
}

fn find<'a>(findings: &'a [DoctorFinding], code: &str) -> Option<&'a DoctorFinding> {
    findings.iter().find(|f| f.code == code)
}

#[test]
fn a_serve_bind_is_reported_only_when_the_listen_also_serves() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();

    let (_g, combined) = ops_with(true, Some("127.0.0.1:4433"));
    let findings = report(&combined, &linux_env(&keystore, home.path()));
    let finding = find(&findings, "listen_serve_ignores_serve_bind")
        .unwrap_or_else(|| panic!("missing: {findings:?}"));
    assert_eq!(finding.status, "info");
    assert!(finding.remedy.as_deref().unwrap().contains("[listen].bind"));

    // Combined without a `[serve].bind`: nothing to ignore.
    let (_g, no_bind) = ops_with(true, None);
    let findings = report(&no_bind, &linux_env(&keystore, home.path()));
    assert!(find(&findings, "listen_serve_ignores_serve_bind").is_none());

    // A plain `qsh listen` reads no `[serve].bind` either, and says nothing.
    let (_g, plain) = ops_with(false, Some("127.0.0.1:4433"));
    let findings = report(&plain, &linux_env(&keystore, home.path()));
    assert!(find(&findings, "listen_serve_ignores_serve_bind").is_none());
}

#[test]
fn a_registered_serve_unit_beside_the_combined_listen_warns() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = ops_with(true, None);

    let findings = report(&ops, &linux_env(&keystore, home.path()));
    assert!(
        find(&findings, "serve_unit_beside_listen_serve").is_none(),
        "{findings:?}"
    );

    register_serve_unit(home.path());
    let findings = report(&ops, &linux_env(&keystore, home.path()));
    let finding = find(&findings, "serve_unit_beside_listen_serve")
        .unwrap_or_else(|| panic!("missing: {findings:?}"));
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("serve service unit"), "{finding:?}");

    // The same unit beside a plain `qsh listen` is the two-daemon setup
    // ADR-0059 decision 24 keeps supported.
    let (_g, plain) = ops_with(false, None);
    register_serve_unit(home.path());
    let findings = report(&plain, &linux_env(&keystore, home.path()));
    assert!(find(&findings, "serve_unit_beside_listen_serve").is_none());
}

#[test]
fn the_windows_serve_task_beside_the_combined_listen_warns() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_g, ops) = ops_with(true, None);
    let env = DoctorEnvironment {
        os: probe::HostOs::Windows,
        ..minimal_env(&keystore)
    };
    let findings = report(&ops, &env);
    assert!(find(&findings, "serve_unit_beside_listen_serve").is_none());

    let task = probe::windows_task_definition_path(&ops.paths().config_dir, "serve");
    std::fs::create_dir_all(task.parent().unwrap()).unwrap();
    std::fs::write(task, b"task").unwrap();
    let findings = report(&ops, &env);
    assert!(find(&findings, "serve_unit_beside_listen_serve").is_some());
}

fn write_record(ops: &Ops, pid: u32) {
    crate::serve::record::write(
        ops.paths(),
        &crate::serve::record::ServeRecord {
            pid,
            addr: "127.0.0.1:4433".to_string(),
            mode: crate::serve::record::ServeRecordMode::Persistent,
            started_at: "2026-11-11T00:00:00Z".to_string(),
            iroh: None,
        },
    )
    .unwrap();
}

/// A live `serve.json` is the combined endpoint's own record when its pid has
/// a localctl endpoint, and another `qsh serve` when it has none.
#[cfg(unix)]
#[test]
fn a_live_serve_record_of_another_process_warns_but_the_listens_own_does_not() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = ops_with(true, None);
    // This test process is alive, which is all `live_serve` asks.
    let pid = std::process::id();
    write_record(&ops, pid);

    let findings = report(&ops, &linux_env(&keystore, home.path()));
    let finding = find(&findings, "serve_unit_beside_listen_serve")
        .unwrap_or_else(|| panic!("missing: {findings:?}"));
    assert!(finding.detail.contains("serve.json"), "{finding:?}");

    // The same pid with a localctl socket in the runtime directory is a
    // `qsh listen`, so the record is the combined endpoint's own.
    let run = ops.paths().runtime_dir();
    std::fs::create_dir_all(&run).unwrap();
    let sock = run.join(format!("{pid}.sock"));
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let findings = report(&ops, &linux_env(&keystore, home.path()));
    assert!(
        find(&findings, "serve_unit_beside_listen_serve").is_none(),
        "{findings:?}"
    );
}

#[test]
fn a_dead_serve_record_is_not_a_second_serve() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = ops_with(true, None);
    // Reaped child: its pid is no longer a process.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    child.wait().unwrap();
    write_record(&ops, pid);

    let findings = report(&ops, &linux_env(&keystore, home.path()));
    assert!(
        find(&findings, "serve_unit_beside_listen_serve").is_none(),
        "{findings:?}"
    );
}

/// A `listen` that hosts sessions gets the restart notice a `serve` gets;
/// a plain `listen` does not (it keeps no sessions).
#[test]
fn the_restart_notice_covers_a_listen_that_hosts_sessions() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let unit = probe::linux_systemd_user_unit_path(home.path(), "listen");
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(unit, b"stub").unwrap();

    let (_g, combined) = ops_with(true, None);
    let findings = report(&combined, &linux_env(&keystore, home.path()));
    assert!(
        find(&findings, "service_restart_drops_sessions").is_some(),
        "{findings:?}"
    );

    let (_g, plain) = ops_with(false, None);
    let findings = report(&plain, &linux_env(&keystore, home.path()));
    assert!(
        find(&findings, "service_restart_drops_sessions").is_none(),
        "{findings:?}"
    );
}

/// The combined endpoint reads one `acl.toml` for both roles, so the example
/// of a missing policy shows both rows; a plain `listen` shows its own.
#[test]
fn a_missing_policy_shows_the_example_row_of_both_roles_when_combined() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = ops_with(true, None);
    std::fs::remove_file(ops.paths().acl_file()).unwrap();

    let findings = report(&ops, &linux_env(&keystore, home.path()));
    let finding =
        find(&findings, "acl_policy_missing").unwrap_or_else(|| panic!("missing: {findings:?}"));
    let serve_row = crate::acl::minimal_policy_example(ops.paths(), Role::Serve);
    let listen_row = crate::acl::minimal_policy_example(ops.paths(), Role::Listen);
    assert!(finding.detail.contains(&serve_row), "{}", finding.detail);
    assert!(finding.detail.contains(&listen_row), "{}", finding.detail);

    let (_g, plain) = ops_with(false, None);
    std::fs::remove_file(plain.paths().acl_file()).unwrap();
    let findings = report(&plain, &linux_env(&keystore, home.path()));
    let finding = find(&findings, "acl_policy_missing").unwrap();
    assert!(finding.detail.contains(&listen_row));
    assert!(!finding.detail.contains(&serve_row), "{}", finding.detail);
}

/// The key is a known config key, so `config_unknown_key` stays quiet.
#[test]
fn the_listen_serve_key_is_not_an_unknown_config_key() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = ops_with(true, None);
    let findings = report(&ops, &linux_env(&keystore, home.path()));
    assert!(
        find(&findings, "config_unknown_key").is_none(),
        "{findings:?}"
    );
}
