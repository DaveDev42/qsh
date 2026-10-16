//! The Windows rows of the doctor (ADR-0035 decision 27, ADR-0032 decision
//! 15): the task definition file behind `service_not_registered` and the
//! `service_restart_drops_sessions` notice, and the COM-read principal behind
//! `logon_task_session_scoped` and the Windows half of
//! `keystore_session_bound`. Every test injects `HostOs::Windows` and a
//! fake [`TaskDefinitionReader`], so they run on every build target and
//! start no process.

use std::collections::HashMap;
use std::sync::Mutex;

use super::*;

/// Answers by task name; a name with no entry is "not registered".
struct FakeReader {
    answers: HashMap<String, Result<Option<TaskLogonType>, ()>>,
    queried: Mutex<Vec<String>>,
}

impl FakeReader {
    fn answering(name: &str, answer: Result<Option<TaskLogonType>, ()>) -> Self {
        Self {
            answers: HashMap::from([(name.to_string(), answer)]),
            queried: Mutex::new(Vec::new()),
        }
    }

    fn queried(&self) -> Vec<String> {
        self.queried.lock().unwrap().clone()
    }
}

impl TaskDefinitionReader for FakeReader {
    fn logon_type(&self, task_name: &str) -> Result<Option<TaskLogonType>, OpError> {
        self.queried.lock().unwrap().push(task_name.to_string());
        match self.answers.get(task_name) {
            None => Ok(None),
            Some(Ok(found)) => Ok(*found),
            Some(Err(())) => Err(OpError::new(
                qsh_proto::ErrorCode::Internal,
                "the Task Scheduler could not be read",
            )),
        }
    }
}

fn windows_env<'a>(
    keystore: &'a dyn KeyStore,
    reader: &'a dyn TaskDefinitionReader,
) -> DoctorEnvironment<'a> {
    DoctorEnvironment {
        os: probe::HostOs::Windows,
        task_reader: reader,
        ..minimal_env(keystore)
    }
}

/// Writes the task file of `mode` where `qsh service install` would.
fn seed_task_file(ops: &Ops, mode: &str) {
    let path = probe::windows_task_definition_path(&ops.paths().config_dir, mode);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"task").unwrap();
}

#[test]
fn service_not_registered_reads_the_windows_task_file() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let reader = FakeReader::answering("none", Ok(None));
    let env = windows_env(&keystore, &reader);

    for mode in MODES {
        // No file: the unit is not registered, whatever `$HOME` holds.
        let findings = ops.doctor_service_registration_findings(mode, &env);
        assert_eq!(codes(&findings), ["service_not_registered"], "{mode}");
        assert_eq!(findings[0].status, "info");
        assert!(findings[0].detail.contains(mode));

        // With the file, `service_not_registered` is gone and a serving mode
        // gets the restart notice (a controller has no sessions of its own).
        seed_task_file(&ops, mode);
        let findings = ops.doctor_service_registration_findings(mode, &env);
        assert!(
            !codes(&findings).contains(&"service_not_registered"),
            "{mode}: {findings:?}"
        );
        let expect_restart = mode != "listen";
        assert_eq!(
            codes(&findings).contains(&"service_restart_drops_sessions"),
            expect_restart,
            "{mode}: {findings:?}"
        );
    }
}

#[test]
fn logon_task_session_scoped_fires_for_an_interactive_token_task() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    seed_task_file(&ops, "serve");
    let reader =
        FakeReader::answering(r"\qsh\qsh-serve", Ok(Some(TaskLogonType::InteractiveToken)));
    let env = windows_env(&keystore, &reader);

    let findings = ops.doctor_service_registration_findings("serve", &env);
    let finding = findings
        .iter()
        .find(|f| f.code == "logon_task_session_scoped")
        .unwrap_or_else(|| panic!("logon_task_session_scoped missing: {findings:?}"));
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("serve"), "{finding:?}");
    assert!(
        finding
            .remedy
            .as_deref()
            .is_some_and(|remedy| remedy.contains("docs/deploy/service.md")),
        "{finding:?}"
    );
    assert_eq!(reader.queried(), [r"\qsh\qsh-serve"]);
}

#[test]
fn logon_task_session_scoped_is_silent_for_a_password_task() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    seed_task_file(&ops, "serve");
    for logon in [TaskLogonType::Password, TaskLogonType::Other] {
        let reader = FakeReader::answering(r"\qsh\qsh-serve", Ok(Some(logon)));
        let env = windows_env(&keystore, &reader);
        let findings = ops.doctor_service_registration_findings("serve", &env);
        assert!(
            !codes(&findings).contains(&"logon_task_session_scoped"),
            "{logon:?}: {findings:?}"
        );
        // The read happened; the answer just says nothing is wrong.
        assert_eq!(reader.queried(), [r"\qsh\qsh-serve"]);
    }
}

#[test]
fn logon_task_session_scoped_is_silent_when_the_task_cannot_be_read() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    seed_task_file(&ops, "serve");
    // An unreadable scheduler, and a task that is not registered at all.
    let unreadable = FakeReader::answering(r"\qsh\qsh-serve", Err(()));
    let unregistered = FakeReader::answering("other", Ok(None));
    for reader in [&unreadable, &unregistered] {
        let env = windows_env(&keystore, reader);
        let findings = ops.doctor_service_registration_findings("serve", &env);
        assert!(
            !codes(&findings).contains(&"logon_task_session_scoped"),
            "{findings:?}"
        );
        // The file-based findings are unaffected by the failed read.
        assert!(
            codes(&findings).contains(&"service_restart_drops_sessions"),
            "{findings:?}"
        );
    }
    // The reader of every non-Windows host reads nothing.
    let env = windows_env(&keystore, &UnreadableTaskScheduler);
    let findings = ops.doctor_service_registration_findings("serve", &env);
    assert!(!codes(&findings).contains(&"logon_task_session_scoped"));
}

#[test]
fn logon_task_session_scoped_covers_serve_listen_and_reverse_tasks() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    for mode in MODES {
        seed_task_file(&ops, mode);
        let name = format!("\\qsh\\qsh-{mode}");
        let reader = FakeReader::answering(&name, Ok(Some(TaskLogonType::InteractiveToken)));
        let env = windows_env(&keystore, &reader);
        let findings = ops.doctor_service_registration_findings(mode, &env);
        let finding = findings
            .iter()
            .find(|f| f.code == "logon_task_session_scoped")
            .unwrap_or_else(|| panic!("{mode}: {findings:?}"));
        assert!(
            finding.detail.contains(&format!("mode: {mode}")),
            "{finding:?}"
        );
        // Only the task of the inferred mode is read.
        assert_eq!(reader.queried(), [name], "{mode}");
    }
}

#[test]
fn logon_task_session_scoped_does_not_depend_on_the_task_file() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    // Registered by hand from a file qsh did not write, or whose file was
    // deleted afterwards: the scheduler is what says it is registered.
    let reader =
        FakeReader::answering(r"\qsh\qsh-serve", Ok(Some(TaskLogonType::InteractiveToken)));
    let env = windows_env(&keystore, &reader);
    let findings = ops.doctor_service_registration_findings("serve", &env);
    assert!(
        codes(&findings).contains(&"logon_task_session_scoped"),
        "{findings:?}"
    );
}

#[test]
fn logon_task_session_scoped_is_never_reported_off_windows() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let reader =
        FakeReader::answering(r"\qsh\qsh-serve", Ok(Some(TaskLogonType::InteractiveToken)));
    let home = tempfile::tempdir().unwrap();
    for os in [
        probe::HostOs::Macos,
        probe::HostOs::Linux,
        probe::HostOs::Other,
    ] {
        let env = DoctorEnvironment {
            os,
            home_dir: Some(home.path()),
            ..windows_env(&keystore, &reader)
        };
        let findings = ops.doctor_service_registration_findings("serve", &env);
        assert!(!codes(&findings).contains(&"logon_task_session_scoped"));
    }
    assert!(reader.queried().is_empty(), "{:?}", reader.queried());
}

/// The Windows always-on form is a task registered under a stored-password
/// principal. Whether such a task can read Credential Manager could not be
/// measured without typing the account's password, so a `platform` key store
/// under that task is reported (ADR-0032 decision 15), with the same remedy
/// as on the other platforms.
#[test]
fn keystore_session_bound_fires_for_platform_store_under_a_password_boot_task() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    for mode in MODES {
        seed_task_file(&ops, mode);
        let name = format!("\\qsh\\qsh-{mode}");
        let reader = FakeReader::answering(&name, Ok(Some(TaskLogonType::Password)));
        let env = DoctorEnvironment {
            key_store: KeyStoreKind::Platform,
            ..windows_env(&keystore, &reader)
        };
        let findings = ops.doctor_service_registration_findings(mode, &env);
        let finding = findings
            .iter()
            .find(|f| f.code == "keystore_session_bound")
            .unwrap_or_else(|| panic!("{mode}: keystore_session_bound missing: {findings:?}"));
        assert_eq!(finding.status, "warn");
        assert!(finding.detail.contains(mode), "{finding:?}");
        assert!(
            finding
                .remedy
                .as_deref()
                .is_some_and(|remedy| remedy.contains("qsh identity move-key --to file")),
            "{finding:?}"
        );
        // The same read answers the other Windows finding: a stored-password
        // principal is not logon-scoped.
        assert!(
            !codes(&findings).contains(&"logon_task_session_scoped"),
            "{findings:?}"
        );
        assert_eq!(reader.queried(), [name], "{mode}: one read per run");
    }
    assert!(crate::doctor::EXPECTED_DOCTOR_CODES.contains(&"keystore_session_bound"));
}

/// The finding needs all three: a `platform` key store, a registered task and
/// a stored-password principal.
#[test]
fn keystore_session_bound_is_silent_without_a_password_task_on_a_platform_store() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    seed_task_file(&ops, "serve");
    let name = r"\qsh\qsh-serve";
    let answers = [
        Ok(Some(TaskLogonType::InteractiveToken)),
        Ok(Some(TaskLogonType::Other)),
        Ok(None),
        Err(()),
    ];
    for answer in answers {
        let reader = FakeReader::answering(name, answer);
        let env = DoctorEnvironment {
            key_store: KeyStoreKind::Platform,
            ..windows_env(&keystore, &reader)
        };
        let findings = ops.doctor_service_registration_findings("serve", &env);
        assert!(
            !codes(&findings).contains(&"keystore_session_bound"),
            "{answer:?}: {findings:?}"
        );
    }
    // A file key store has no session-bound dependency, whatever the task.
    let reader = FakeReader::answering(name, Ok(Some(TaskLogonType::Password)));
    let env = DoctorEnvironment {
        key_store: KeyStoreKind::File,
        ..windows_env(&keystore, &reader)
    };
    let findings = ops.doctor_service_registration_findings("serve", &env);
    assert!(
        !codes(&findings).contains(&"keystore_session_bound"),
        "{findings:?}"
    );
    // And a host that reads nothing reports nothing.
    let env = DoctorEnvironment {
        key_store: KeyStoreKind::Platform,
        ..windows_env(&keystore, &UnreadableTaskScheduler)
    };
    let findings = ops.doctor_service_registration_findings("serve", &env);
    assert!(!codes(&findings).contains(&"keystore_session_bound"));
}

/// The Windows half reads the scheduler, so it never fires on another OS even
/// when the reader would say "stored password".
#[test]
fn keystore_session_bound_does_not_read_the_task_scheduler_off_windows() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let reader = FakeReader::answering(r"\qsh\qsh-serve", Ok(Some(TaskLogonType::Password)));
    let home = tempfile::tempdir().unwrap();
    for os in [
        probe::HostOs::Macos,
        probe::HostOs::Linux,
        probe::HostOs::Other,
    ] {
        let env = DoctorEnvironment {
            os,
            home_dir: Some(home.path()),
            key_store: KeyStoreKind::Platform,
            ..windows_env(&keystore, &reader)
        };
        let findings = ops.doctor_service_registration_findings("serve", &env);
        assert!(!codes(&findings).contains(&"keystore_session_bound"));
    }
    assert!(reader.queried().is_empty(), "{:?}", reader.queried());
}

/// ADR-0035 decision 27: the doctor reads the Task Scheduler through COM and
/// the task definition by file existence; no code on its path starts a
/// process, `schtasks` least of all.
#[test]
fn doctor_probe_never_spawns_schtasks() {
    let sources = [
        ("doctor.rs", include_str!("../../../doctor.rs")),
        ("doctor/probe.rs", include_str!("../../../doctor/probe.rs")),
        ("ops/doctor.rs", include_str!("../../doctor.rs")),
        ("ops/service/task.rs", include_str!("../../service/task.rs")),
        (
            "ops/service/task_com.rs",
            include_str!("../../service/task_com.rs"),
        ),
    ];
    for (name, source) in sources {
        let code = source.split("#[cfg(test)]").next().unwrap();
        for line in code.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for needle in [
                "Command::new",
                "process::Command",
                "\"schtasks",
                "tokio::process",
            ] {
                assert!(
                    !line.contains(needle),
                    "{name} starts a process on the doctor path: `{line}`"
                );
            }
        }
    }
}
