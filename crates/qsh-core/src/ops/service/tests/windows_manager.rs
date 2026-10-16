//! The Task Scheduler row of `--activate`, `--deactivate` and `--live`
//! (ADR-0032 decisions 3 to 6, 8, 18; ADR-0035 decisions 27 and 28). Every
//! test but the last runs on every build target: the `schtasks` calls land in
//! a recording runner and the COM reads in a [`FakeScheduler`], so no test
//! starts `schtasks` or touches a real scheduler.

use super::windows_task::{read_task_file, task_host};
use super::*;

fn task_name(mode: &str) -> String {
    format!(r"\qsh\qsh-{mode}")
}

/// The calls a first activation of `mode` makes: register, then start.
fn register_and_run(mode: &str, task_path: &str) -> Vec<String> {
    vec![
        format!(
            r"schtasks /Create /F /TN {} /XML {task_path}",
            task_name(mode)
        ),
        format!(r"schtasks /Run /TN {}", task_name(mode)),
    ]
}

#[test]
fn install_activate_runs_the_documented_argv_on_task_scheduler() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    let data = ops.service_install_with_home(&host, None, true).unwrap();
    assert_eq!(data.manager, "task_scheduler");
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(runner.calls(), register_and_run("serve", &data.path));
    // The file the scheduler is told to register exists by then.
    assert!(read_task_file(Path::new(&data.path)).contains("service run serve"));
    // Every call carries the 30 seconds of decision 8, and none restarts.
    assert!(
        runner
            .deadlines
            .lock()
            .unwrap()
            .iter()
            .all(|deadline| *deadline == MANAGER_CALL_DEADLINE)
    );
    assert!(runner.calls().iter().all(|call| !call.contains("/End")));
}

/// ADR-0032 decision 4: the scheduler keeps the definition inside itself, so
/// the new binary path reaches it only through `/Create /F`. That call is made
/// for a running task too (measured: it leaves the running instance alone),
/// and only `/Run` is skipped.
#[test]
fn windows_activate_updates_the_stored_task_without_running_it_when_already_running() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let scheduler = FakeScheduler::registered(TaskLogonType::InteractiveToken, true);
    let host = host_with_scheduler(Manager::TaskScheduler, &runner, Path::new(""), &scheduler);
    let data = ops.service_install_with_home(&host, None, true).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::AlreadyActive));
    assert_eq!(
        runner.calls(),
        vec![format!(
            r"schtasks /Create /F /TN \qsh\qsh-serve /XML {}",
            data.path
        )]
    );
    // The run state was asked of the scheduler, never of `schtasks`.
    assert!(
        scheduler
            .queried()
            .contains(&r"state \qsh\qsh-serve".to_string())
    );
}

/// ADR-0032 decision 8: an `InteractiveToken` task that cannot start because
/// no interactive session exists makes `/Run` exit non-zero. That is the
/// same `INTERNAL`, and nothing registers the task under another principal
/// or logon type: the only calls are the two documented ones.
#[test]
fn interactive_token_start_failure_is_internal_without_a_fallback_principal() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::with(|argv| {
        if argv.iter().any(|a| a == "/Run") {
            Ok(exit(1, "ERROR: There are no logon sessions available."))
        } else {
            Ok(exit(0, ""))
        }
    });
    let host = task_host(&runner);
    let err = ops
        .service_install_with_home(&host, None, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert_eq!(err.details["step"], "activate");
    assert_eq!(err.details["exit_code"], 1);
    assert!(
        err.message.contains("no logon sessions available"),
        "{}",
        err.message
    );
    assert!(
        err.message.contains("InteractiveToken") && err.message.contains("no other principal"),
        "{}",
        err.message
    );
    let calls = runner.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls[0].starts_with("schtasks /Create /F /TN"), "{calls:?}");
    assert!(calls[1].starts_with("schtasks /Run /TN"), "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|call| !call.contains("/RU") && !call.contains("/RP")),
        "no run-as account or password reaches schtasks: {calls:?}"
    );
    // The file stays, so a repeated install continues from here.
    let path = ops.paths().config_dir.join("service/qsh-serve.task.xml");
    assert!(path.exists());
    assert!(!read_task_file(&path).contains("<LogonType>Password"));
}

#[test]
fn windows_activate_covers_the_error_vocabulary_of_decision_8() {
    let (_dir, ops) = ops_with("");

    let missing = FakeRunner::with(|_| Err(RunError::NotFound));
    let err = ops
        .service_install_with_home(&task_host(&missing), None, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert!(err.message.contains("`schtasks`"), "{}", err.message);
    assert!(
        err.message.contains("docs/deploy/service.md"),
        "{}",
        err.message
    );

    let failing = FakeRunner::with(|argv| {
        if argv.iter().any(|a| a == "/Create") {
            Ok(exit(1, "ERROR: Access is denied."))
        } else {
            Ok(exit(0, ""))
        }
    });
    let err = ops
        .service_install_with_home(&task_host(&failing), None, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert_eq!(err.details["step"], "activate");
    assert_eq!(err.details["exit_code"], 1);
    assert!(err.message.contains("Access is denied"), "{}", err.message);
    // A failed `/Create` is not a start failure: no interactive-session note.
    assert!(!err.message.contains("InteractiveToken"), "{}", err.message);
    assert_eq!(failing.calls().len(), 1, "no /Run after a failed /Create");

    let slow = FakeRunner::with(|_| Err(RunError::TimedOut));
    let err = ops
        .service_install_with_home(&task_host(&slow), None, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
    assert_eq!(err.details["step"], "activate");
}

/// A scheduler that cannot be read ends the step before any `schtasks` call:
/// without the principal qsh cannot tell whether `/Create /F` would replace a
/// person's always-on task.
#[test]
fn windows_flags_stop_without_a_call_when_the_scheduler_cannot_be_read() {
    let (_dir, ops) = ops_with("");
    let scheduler = FakeScheduler::broken();

    let runner = FakeRunner::default();
    let host = host_with_scheduler(Manager::TaskScheduler, &runner, Path::new(""), &scheduler);
    let err = ops
        .service_install_with_home(&host, None, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert_eq!(err.details["step"], "activate");
    assert!(runner.calls().is_empty());
    let path = ops.paths().config_dir.join("service/qsh-serve.task.xml");
    assert!(path.exists(), "the file stays for a repeated install");

    let err = ops
        .service_uninstall_with_home(&host, None, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert_eq!(err.details["step"], "deactivate");
    assert!(runner.calls().is_empty());
    assert!(path.exists(), "a failed release keeps the file");

    let err = ops.service_status_with_home(&host, None, true).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert_eq!(err.details["step"], "live");
    assert!(runner.calls().is_empty());
}

#[test]
fn windows_deactivate_ends_a_running_task_before_deleting_it() {
    let (_dir, ops) = ops_with("");
    let path = windows_manager_seed(&ops);
    let runner = FakeRunner::default();
    let scheduler = FakeScheduler::registered(TaskLogonType::InteractiveToken, true);
    let host = host_with_scheduler(Manager::TaskScheduler, &runner, Path::new(""), &scheduler);
    let data = ops.service_uninstall_with_home(&host, None, true).unwrap();
    assert_eq!(data.deactivation, Some(ServiceDeactivation::Stopped));
    assert!(data.removed);
    assert_eq!(
        runner.calls(),
        vec![
            r"schtasks /Query /TN \qsh\qsh-serve",
            r"schtasks /End /TN \qsh\qsh-serve",
            r"schtasks /Delete /F /TN \qsh\qsh-serve",
        ]
    );
    assert!(!path.exists());
}

#[test]
fn a_failed_windows_deactivate_keeps_the_task_file() {
    let (_dir, ops) = ops_with("");
    let path = windows_manager_seed(&ops);
    let runner = FakeRunner::with(|argv| {
        if argv.iter().any(|a| a == "/Delete") {
            Ok(exit(1, "ERROR: Access is denied."))
        } else {
            Ok(exit(0, ""))
        }
    });
    let host = task_host(&runner);
    let err = ops
        .service_uninstall_with_home(&host, None, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert_eq!(err.details["step"], "deactivate");
    assert_eq!(err.details["exit_code"], 1);
    assert!(path.exists());
}

/// The release is judged by registration, not by whether the task runs: a
/// task that exists but is stopped is deleted all the same, and a task that is
/// not registered is left to the file removal.
#[test]
fn windows_deactivate_is_judged_by_registration_not_by_the_run_state() {
    let (_dir, ops) = ops_with("");
    windows_manager_seed(&ops);
    let runner = FakeRunner::default();
    let scheduler = FakeScheduler::registered(TaskLogonType::Other, false);
    let host = host_with_scheduler(Manager::TaskScheduler, &runner, Path::new(""), &scheduler);
    let data = ops.service_uninstall_with_home(&host, None, true).unwrap();
    assert_eq!(data.deactivation, Some(ServiceDeactivation::Stopped));
    assert_eq!(
        runner.calls(),
        vec![
            r"schtasks /Query /TN \qsh\qsh-serve",
            r"schtasks /Delete /F /TN \qsh\qsh-serve",
        ]
    );
}

/// ADR-0032 decision 18: the always-on form is a task registered with a
/// stored password. `--activate` writes the file and calls nothing, so the
/// person's definition is not replaced by the logon-scoped default.
#[test]
fn windows_activate_and_deactivate_leave_an_always_on_task_untouched() {
    for mode_config in MODE_CONFIGS {
        let (mode, config) = mode_config;
        let (_dir, ops) = ops_with(config);
        let runner = FakeRunner::default();
        let scheduler = FakeScheduler::registered(TaskLogonType::Password, true);
        let host = host_with_scheduler(Manager::TaskScheduler, &runner, Path::new(""), &scheduler);

        let installed = ops.service_install_with_home(&host, None, true).unwrap();
        assert_eq!(installed.mode, mode);
        assert_eq!(
            installed.activation,
            Some(ServiceActivation::AlwaysOnPresent)
        );
        assert!(installed.created, "the file is still written");
        assert!(runner.calls().is_empty(), "{mode}: {:?}", runner.calls());

        let removed = ops.service_uninstall_with_home(&host, None, true).unwrap();
        assert_eq!(
            removed.deactivation,
            Some(ServiceDeactivation::AlwaysOnPresent)
        );
        assert!(removed.removed, "the file is still removed");
        assert!(runner.calls().is_empty(), "{mode}: {:?}", runner.calls());
        // Only the task of the inferred mode was read.
        assert!(
            scheduler
                .queried()
                .iter()
                .all(|query| query.ends_with(&task_name(mode))),
            "{mode}: {:?}",
            scheduler.queried()
        );
    }
}

/// The builders are the documented recipe, built from the closed mode set and
/// the path qsh chose. Nothing a user typed can reach them.
#[test]
fn windows_argv_builders_name_the_task_by_the_closed_mode_set() {
    for mode in ["serve", "listen", "reverse"] {
        let name = task_name(mode);
        assert_eq!(
            schtasks_query_argv(mode),
            ["schtasks", "/Query", "/TN", &name]
        );
        assert_eq!(
            schtasks_create_argv(mode, r"C:\cfg\qsh.task.xml"),
            [
                "schtasks",
                "/Create",
                "/F",
                "/TN",
                &name,
                "/XML",
                r"C:\cfg\qsh.task.xml"
            ]
        );
        assert_eq!(schtasks_run_argv(mode), ["schtasks", "/Run", "/TN", &name]);
        assert_eq!(schtasks_end_argv(mode), ["schtasks", "/End", "/TN", &name]);
        assert_eq!(
            schtasks_delete_argv(mode),
            ["schtasks", "/Delete", "/F", "/TN", &name]
        );
    }
}

/// ADR-0032 decision 10: `schtasks` is started in one place, the default
/// runner, from an argv the builders made. No other code of the backend names
/// a process API or the executable.
#[test]
fn schtasks_is_spawned_only_by_the_default_runner() {
    let others = [
        ("ops/service/mod.rs", include_str!("../mod.rs")),
        ("ops/service/task.rs", include_str!("../task.rs")),
        ("ops/service/task_com.rs", include_str!("../task_com.rs")),
        ("ops/service/run.rs", include_str!("../run.rs")),
    ];
    for (name, source) in others {
        let code = source.split("#[cfg(test)]").next().unwrap();
        for line in code.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for needle in ["Command::new", "process::Command", "\"schtasks"] {
                assert!(
                    !line.contains(needle),
                    "{name} names a process API or schtasks outside the default runner: `{line}`"
                );
            }
        }
    }
    let manager = include_str!("../manager.rs");
    let code = manager.split("#[cfg(test)]").next().unwrap();
    let spawns = code
        .lines()
        .filter(|line| !line.trim_start().starts_with("//") && line.contains("Command::new"))
        .count();
    assert_eq!(spawns, 1, "manager.rs must spawn through one Command::new");
}

/// The real Task Scheduler, read-only (one test, no task is registered): a
/// name that is not registered is not running, `--live` reports
/// `active: false` for it, and the query creates nothing.
#[cfg(windows)]
#[test]
fn status_live_queries_the_real_task_scheduler_for_an_unregistered_task() {
    /// The real COM reads, aimed at a task name that no machine has instead of
    /// the `\qsh\qsh-serve` a developer may have registered.
    struct Absent(String);
    impl TaskStateQuery for Absent {
        fn is_running(&self, _task_name: &str) -> Result<bool, OpError> {
            ComTaskScheduler.is_running(&self.0)
        }
    }

    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let absent = Absent(format!(r"\qsh-test\absent-{unique}"));

    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let mut host = task_host(&runner);
    host.task_state = &absent;
    ops.service_install_with_home(&host, None, false).unwrap();
    let data = ops.service_status_with_home(&host, None, true).unwrap();
    assert!(data.installed);
    assert_eq!(data.active, Some(false));
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    assert_eq!(ComTaskScheduler.logon_type(&absent.0).unwrap(), None);
    assert_eq!(
        ComTaskScheduler.logon_type(r"\qsh-test").unwrap(),
        None,
        "the query created no folder either"
    );
}
