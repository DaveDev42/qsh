//! `reverse_config_retired` (ADR-0068 decision 4): the leftover keys and
//! units of the retired reverse connection.

use super::*;

fn linux_env<'a>(keystore: &'a dyn KeyStore, home: &'a Path) -> DoctorEnvironment<'a> {
    DoctorEnvironment {
        os: probe::HostOs::Linux,
        home_dir: Some(home),
        username: Some("reverse-retired-doctor"),
        ..minimal_env(keystore)
    }
}

fn findings_for(ops: &Ops, env: &DoctorEnvironment<'_>) -> Vec<DoctorFinding> {
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

fn write_config(ops: &Ops, text: &str) {
    std::fs::write(ops.paths().config_file(), text).unwrap();
}

#[test]
fn a_clean_config_has_no_reverse_config_retired_finding() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = healthy_ops();
    let findings = findings_for(&ops, &linux_env(&keystore, home.path()));
    assert!(
        findings.iter().all(|f| f.code != "reverse_config_retired"),
        "{findings:?}"
    );
}

#[test]
fn leftover_keys_and_units_are_named_in_one_warn_finding() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = healthy_ops();
    write_config(
        &ops,
        "[listen]\nbind = \"127.0.0.1:0\"\n[serve]\nto = \"hub\"\n[reverse]\n\
         backoff_max_ms = 1000\n[recovery]\nreverse_min_dead_after_ms = 5000\n\
         reverse_strikes = 4\n",
    );
    for mode in ["listen", "reverse"] {
        let unit = probe::linux_systemd_user_unit_path(home.path(), mode);
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(unit, b"stub").unwrap();
    }
    let findings = findings_for(&ops, &linux_env(&keystore, home.path()));
    let hits: Vec<_> = findings
        .iter()
        .filter(|f| f.code == "reverse_config_retired")
        .collect();
    assert_eq!(hits.len(), 1, "{findings:?}");
    let finding = hits[0];
    assert_eq!(finding.status, "warn");
    for needle in [
        "[listen]",
        "[serve].to",
        "[reverse]",
        "[recovery].reverse_min_dead_after_ms",
        "[recovery].reverse_strikes",
        "listen service unit",
        "reverse service unit",
    ] {
        assert!(finding.detail.contains(needle), "{needle}: {finding:?}");
    }
    // The retired keys are known keys: no `config_unknown_key` for them.
    assert!(
        findings.iter().all(|f| f.code != "config_unknown_key"),
        "{findings:?}"
    );
}

#[test]
fn the_finding_is_given_to_a_client_device_too() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let (_g, ops) = healthy_ops();
    write_config(&ops, "[serve]\nto = \"hub\"\n");
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    let data = ops
        .doctor_assemble(
            DoctorReq {
                host: None,
                mode: Some("client".to_string()),
            },
            unix_seconds(SystemTime::now()),
            &identity,
            &config,
            &linux_env(&keystore, home.path()),
        )
        .unwrap();
    assert!(
        data.findings
            .iter()
            .any(|f| f.code == "reverse_config_retired" && f.status == "warn"),
        "{:?}",
        data.findings
    );
}
