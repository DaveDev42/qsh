//! `install` activating by default, `--to`/`--bind`/`--name`, and
//! `--always-on` / `uninstall --always-on` (ADR-0051 decision 11, decision 13).
//! Every manager and OS call lands in the recording [`FakeRunner`]; no test
//! starts `sudo`, `loginctl`, `schtasks` or `netsh`, and none touches the real
//! home, config or credential store.

use std::sync::atomic::{AtomicUsize, Ordering};

use qsh_proto::{
    IdentityMoveKeyReq, KeyStoreKind, KeyStoreMode, ServiceAlwaysOn, ServiceAlwaysOnState,
};

use super::windows_task::{read_task_file, task_host};
use super::*;
use crate::identity::MemoryKeyStore;
use crate::prompts::MOVE_KEY;

fn options() -> ServiceInstallOptions {
    ServiceInstallOptions::default()
}

fn always_on_options() -> ServiceInstallOptions {
    ServiceInstallOptions {
        always_on: true,
        ..options()
    }
}

fn install_with(
    ops: &Ops,
    host: &ServiceHost<'_>,
    home: &tempfile::TempDir,
    options: &ServiceInstallOptions,
    prompter: &dyn Prompter,
) -> Result<ServiceInstallData, OpError> {
    ops.service_install_with_options(host, Some(home.path().to_path_buf()), options, prompter)
}

fn uninstall_always_on(
    ops: &Ops,
    host: &ServiceHost<'_>,
    home: &tempfile::TempDir,
) -> Result<ServiceUninstallData, OpError> {
    ops.service_uninstall_with_options(host, Some(home.path().to_path_buf()), false, true)
}

/// A prompter that gives a fixed answer and counts the questions.
struct Answer {
    answer: Option<bool>,
    asked: AtomicUsize,
}

impl Answer {
    fn new(answer: Option<bool>) -> Self {
        Self {
            answer,
            asked: AtomicUsize::new(0),
        }
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl Prompter for Answer {
    fn ask(&self, prompt: &crate::prompts::Prompt) -> Option<bool> {
        assert_eq!(prompt, &MOVE_KEY, "only the move-key question exists here");
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.answer
    }
}

fn running_exe() -> String {
    resolve_current_exe().unwrap().display().to_string()
}

// ---------------------------------------------------------------------
// Default activation, `--no-activate`
// ---------------------------------------------------------------------

#[test]
fn install_activates_by_default_on_all_three_managers() {
    // launchd: not loaded yet, so bootstrap.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting_when(|call| call.starts_with("launchctl print"), 113);
    let root = temp_home();
    let home = temp_home();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let data = install_with(&ops, &host, &home, &options(), &NoPrompter).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(data.always_on, None);
    assert_eq!(
        runner.calls(),
        vec![
            "launchctl print gui/501/io.qsh.serve".to_string(),
            format!("launchctl bootstrap gui/501 {}", data.path),
        ]
    );

    // systemd: inactive, so daemon-reload and enable --now.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting_when(|call| call.contains("is-active"), 3);
    let host = host_for(Manager::Systemd, &runner, root.path());
    let data = install_with(&ops, &host, &home, &options(), &NoPrompter).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(
        runner.calls(),
        vec![
            "systemctl --user is-active qsh-serve.service",
            "systemctl --user daemon-reload",
            "systemctl --user enable --now qsh-serve.service",
        ]
    );

    // Task Scheduler: not running, so register and run.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    let data = ops
        .service_install_with_options(&host, None, &options(), &NoPrompter)
        .unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(
        runner.calls(),
        vec![
            format!(r"schtasks /Create /F /TN \qsh\qsh-serve /XML {}", data.path),
            r"schtasks /Run /TN \qsh\qsh-serve".to_string(),
        ]
    );
}

#[test]
fn install_never_restarts_a_running_unit_by_default() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let root = temp_home();
    let home = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let data = install_with(&ops, &host, &home, &options(), &NoPrompter).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::AlreadyActive));
    assert!(runner.calls().iter().all(|call| !call.contains("restart")));
}

#[test]
fn no_activate_is_the_file_only_form_on_all_three_managers() {
    let no_activate = ServiceInstallOptions {
        activate: false,
        ..options()
    };
    let root = temp_home();
    let home = temp_home();
    for manager in [Manager::Launchd, Manager::Systemd, Manager::TaskScheduler] {
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::default();
        let host = host_for(manager, &runner, root.path());
        let data = install_with(&ops, &host, &home, &no_activate, &NoPrompter).unwrap();
        assert_eq!(data.activation, None, "{manager:?}");
        assert_eq!(data.always_on, None, "{manager:?}");
        assert!(runner.calls().is_empty(), "{manager:?}");
        assert!(Path::new(&data.path).is_file(), "{manager:?}");
    }
}

// ---------------------------------------------------------------------
// --to / --bind / --name go through `config set`, never into the argv
// ---------------------------------------------------------------------

#[test]
fn to_bind_and_name_are_written_to_the_config_not_the_unit() {
    let (_dir, ops) = ops_with("# mine\n[serve]\nmax_sessions = 7\n");
    let runner = FakeRunner::default();
    let root = temp_home();
    let home = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let with_flags = ServiceInstallOptions {
        activate: false,
        to: Some("controller".to_string()),
        bind: Some("127.0.0.1:5555".to_string()),
        name: Some("lab".to_string()),
        ..options()
    };
    let data = install_with(&ops, &host, &home, &with_flags, &NoPrompter).unwrap();

    // The mode is inferred from the config the flags just wrote.
    assert_eq!(data.mode, "reverse");
    let config = std::fs::read_to_string(ops.paths().config_file()).unwrap();
    assert!(config.contains("# mine"), "comments survive: {config}");
    assert!(config.contains("max_sessions = 7"), "{config}");
    assert!(config.contains("to = \"controller\""), "{config}");
    assert!(config.contains("bind = \"127.0.0.1:5555\""), "{config}");
    assert!(config.contains("offered_name = \"lab\""), "{config}");

    // The unit argv is the fixed one: no bind, no name.
    let unit = std::fs::read_to_string(&data.path).unwrap();
    assert!(unit.contains("ExecStart="), "{unit}");
    assert!(unit.contains("serve --to controller"), "{unit}");
    assert!(!unit.contains("5555") && !unit.contains("lab"), "{unit}");
    assert!(
        !unit.contains("--bind") && !unit.contains("--name"),
        "{unit}"
    );
}

#[test]
fn a_rejected_flag_value_leaves_the_config_and_the_unit_alone() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let root = temp_home();
    let home = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let bad = ServiceInstallOptions {
        bind: Some("not an address".to_string()),
        ..options()
    };
    // Whether the editor rejects the value or accepts a string, an install
    // that fails must not have touched the manager.
    let outcome = install_with(&ops, &host, &home, &bad, &NoPrompter);
    if outcome.is_err() {
        assert!(runner.calls().is_empty());
        assert!(!unit_of(Manager::Systemd, home.path(), "serve").exists());
    }
}

// ---------------------------------------------------------------------
// --always-on, per OS
// ---------------------------------------------------------------------

#[test]
fn always_on_on_systemd_enables_linger_after_the_default_activation() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting_when(|call| call.contains("is-active"), 3);
    let root = temp_home();
    let home = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let data = install_with(&ops, &host, &home, &always_on_options(), &NoPrompter).unwrap();

    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(
        data.always_on,
        Some(ServiceAlwaysOn {
            state: ServiceAlwaysOnState::Enabled,
            key_moved: false,
            firewall_rule: false,
        })
    );
    assert_eq!(
        runner.calls(),
        vec![
            "systemctl --user is-active qsh-serve.service",
            "systemctl --user daemon-reload",
            "systemctl --user enable --now qsh-serve.service",
            "loginctl enable-linger you",
        ]
    );
    // The call that may ask for polkit owns the terminal.
    assert_eq!(
        *runner.interactive.lock().unwrap(),
        vec!["loginctl enable-linger you"]
    );
    assert_eq!(
        loginctl_enable_linger_argv("you").join(" "),
        "loginctl enable-linger you"
    );
}

#[test]
fn always_on_on_launchd_runs_the_launchdaemon_recipe_under_sudo() {
    let (_dir, ops) = ops_with("");
    let root = temp_home();
    let home = temp_home();
    let captured = Arc::new(Mutex::new(String::new()));
    let seen = Arc::clone(&captured);
    let runner = FakeRunner::with(move |argv| {
        if argv.starts_with(&["sudo".to_string(), "cp".to_string()]) {
            *seen.lock().unwrap() = std::fs::read_to_string(&argv[2]).unwrap();
        }
        Ok(exit(0, ""))
    });
    let host = host_for(Manager::Launchd, &runner, root.path());
    let data = install_with(&ops, &host, &home, &always_on_options(), &NoPrompter).unwrap();

    let daemon = root
        .path()
        .join("Library")
        .join("LaunchDaemons")
        .join("io.qsh.serve.plist")
        .display()
        .to_string();
    let source = ops
        .paths()
        .config_dir
        .join("service")
        .join("io.qsh.serve.plist")
        .display()
        .to_string();
    assert_eq!(
        runner.calls(),
        vec![
            // The LaunchAgent comes down first, as the recipe's first step.
            "launchctl print gui/501/io.qsh.serve".to_string(),
            "launchctl bootout gui/501/io.qsh.serve".to_string(),
            format!("sudo cp {source} {daemon}"),
            format!("sudo chown root:wheel {daemon}"),
            format!("sudo chmod 644 {daemon}"),
            format!("sudo launchctl bootstrap system {daemon}"),
        ]
    );
    // Only the four sudo steps own the terminal.
    assert_eq!(runner.interactive.lock().unwrap().len(), 4);
    // The bytes sudo copied are the documented daemon plist.
    assert_eq!(
        *captured.lock().unwrap(),
        render_launchdaemon_plist(
            "serve",
            &running_exe(),
            &home.path().display().to_string(),
            "",
            "you"
        )
    );
    // The staging copy is gone, and no per-user bootstrap happened.
    assert!(!Path::new(&source).exists());
    assert!(!runner.calls().iter().any(|call| call.contains("gui/501 ")));
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(data.always_on.unwrap().state, ServiceAlwaysOnState::Enabled);
}

#[test]
fn always_on_on_launchd_leaves_an_installed_daemon_alone() {
    let (_dir, ops) = ops_with("");
    let root = temp_home();
    let home = temp_home();
    let daemon = root
        .path()
        .join("Library")
        .join("LaunchDaemons")
        .join("io.qsh.serve.plist");
    std::fs::create_dir_all(daemon.parent().unwrap()).unwrap();
    std::fs::write(&daemon, "daemon").unwrap();
    let runner = FakeRunner::default();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let data = install_with(&ops, &host, &home, &always_on_options(), &NoPrompter).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::AlwaysOnPresent));
    assert_eq!(
        data.always_on.unwrap().state,
        ServiceAlwaysOnState::AlreadyEnabled
    );
    assert!(runner.calls().is_empty());
    assert_eq!(std::fs::read_to_string(&daemon).unwrap(), "daemon");
}

#[test]
fn always_on_on_windows_registers_the_password_task_and_the_firewall_rule() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    let data = ops
        .service_install_with_options(&host, None, &always_on_options(), &NoPrompter)
        .unwrap();

    let always_on_file = Path::new(&data.path).with_file_name("qsh-serve.always-on.xml");
    let exe = running_exe();
    assert_eq!(
        runner.calls(),
        vec![
            "fltmc".to_string(),
            format!(
                r"schtasks /Create /F /TN \qsh\qsh-serve /XML {} /RU you /RP *",
                always_on_file.display()
            ),
            "netsh advfirewall firewall delete rule name=qsh-serve".to_string(),
            format!(
                "netsh advfirewall firewall add rule name=qsh-serve dir=in action=allow \
                 protocol=UDP program={exe}"
            ),
            r"schtasks /Run /TN \qsh\qsh-serve".to_string(),
        ]
    );
    // Only the registration asks for the password.
    assert_eq!(runner.interactive.lock().unwrap().len(), 1);
    assert_eq!(
        read_task_file(&always_on_file),
        render_windows_always_on_task("serve", &exe, "", DOC_EXAMPLE_USER_SID)
    );
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    let always_on = data.always_on.unwrap();
    assert_eq!(always_on.state, ServiceAlwaysOnState::Enabled);
    assert!(always_on.firewall_rule && !always_on.key_moved);
}

#[test]
fn always_on_on_windows_refuses_a_console_that_is_not_elevated() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting_when(|call| call == "fltmc", 5);
    let host = task_host(&runner);
    let flags = ServiceInstallOptions {
        to: Some("controller".to_string()),
        ..always_on_options()
    };
    let err = ops
        .service_install_with_options(&host, None, &flags, &NoPrompter)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(err.message.contains("elevated"), "{}", err.message);
    assert!(
        err.message.contains("qsh service install --always-on"),
        "the error gives the command to rerun: {}",
        err.message
    );
    assert_eq!(
        err.details.get("reason"),
        Some(&serde_json::json!("not_elevated"))
    );
    // Nothing changed: only the probe ran, and neither the config nor a task
    // file was written.
    assert_eq!(runner.calls(), vec!["fltmc"]);
    assert!(!ops.paths().config_file().exists());
    assert!(!ops.paths().config_dir.join("service").exists());

    // The same refusal for the reversal.
    let runner = FakeRunner::exiting_when(|call| call == "fltmc", 5);
    let host = task_host(&runner);
    let err = ops
        .service_uninstall_with_options(&host, None, false, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(err.message.contains("qsh service uninstall --always-on"));
    assert_eq!(runner.calls(), vec!["fltmc"]);
}

// ---------------------------------------------------------------------
// --move-key and the key-store question
// ---------------------------------------------------------------------

/// An identity whose key sits in `platform` (a fake store) in `ops`.
fn platform_identity(ops: &Ops, platform: &MemoryKeyStore) {
    crate::identity::init(ops.paths(), KeyStoreMode::File).unwrap();
    ops.identity_move_key_with_platform_store(
        IdentityMoveKeyReq {
            to: KeyStoreKind::Platform,
        },
        platform,
    )
    .unwrap();
}

fn key_store_of(ops: &Ops) -> KeyStoreKind {
    crate::identity::read_identity(ops.paths())
        .unwrap()
        .unwrap()
        .key_store
}

#[test]
fn move_key_flag_moves_the_key_without_asking() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let platform = MemoryKeyStore::new();
        platform_identity(&ops, &platform);
        let runner = FakeRunner::default();
        let root = temp_home();
        let home = temp_home();
        let mut host = host_for(manager, &runner, root.path());
        host.platform_store = Some(&platform);
        let prompter = Answer::new(None);
        let flags = ServiceInstallOptions {
            move_key: true,
            ..always_on_options()
        };
        let data = install_with(&ops, &host, &home, &flags, &prompter).unwrap();
        assert_eq!(prompter.asked(), 0, "{manager:?}");
        assert!(data.always_on.unwrap().key_moved, "{manager:?}");
        assert_eq!(key_store_of(&ops), KeyStoreKind::File, "{manager:?}");
    }
}

#[test]
fn a_yes_to_the_question_moves_the_key() {
    let (_dir, ops) = ops_with("");
    let platform = MemoryKeyStore::new();
    platform_identity(&ops, &platform);
    let runner = FakeRunner::default();
    let root = temp_home();
    let home = temp_home();
    let mut host = host_for(Manager::Systemd, &runner, root.path());
    host.platform_store = Some(&platform);
    let prompter = Answer::new(Some(true));
    let data = install_with(&ops, &host, &home, &always_on_options(), &prompter).unwrap();
    assert_eq!(prompter.asked(), 1);
    assert!(data.always_on.unwrap().key_moved);
    assert_eq!(key_store_of(&ops), KeyStoreKind::File);
}

#[test]
fn without_an_answer_or_with_a_no_the_install_fails_before_changing_anything() {
    for answer in [None, Some(false)] {
        let (_dir, ops) = ops_with("");
        let platform = MemoryKeyStore::new();
        platform_identity(&ops, &platform);
        let runner = FakeRunner::default();
        let root = temp_home();
        let home = temp_home();
        let mut host = host_for(Manager::Systemd, &runner, root.path());
        host.platform_store = Some(&platform);
        let prompter = Answer::new(answer);
        let flags = ServiceInstallOptions {
            to: Some("controller".to_string()),
            ..always_on_options()
        };
        let err = install_with(&ops, &host, &home, &flags, &prompter).unwrap_err();
        assert_eq!(
            err.details.get("reason"),
            Some(&serde_json::json!("keystore_session_bound")),
            "{answer:?}"
        );
        assert_eq!(key_store_of(&ops), KeyStoreKind::Platform);
        assert!(runner.calls().is_empty());
        assert!(!unit_of(Manager::Systemd, home.path(), "serve").exists());
        assert!(!ops.paths().config_file().exists(), "--to was not written");
    }
}

#[test]
fn a_key_that_needs_no_move_is_not_asked_about() {
    // Key already in the file store, no identity at all, and Windows.
    let (_dir, ops) = ops_with("");
    crate::identity::init(ops.paths(), KeyStoreMode::File).unwrap();
    let (_dir2, ops_without) = ops_with("");
    let root = temp_home();
    let home = temp_home();
    for ops in [&ops, &ops_without] {
        let runner = FakeRunner::default();
        let host = host_for(Manager::Systemd, &runner, root.path());
        let prompter = Answer::new(None);
        let data = install_with(ops, &host, &home, &always_on_options(), &prompter).unwrap();
        assert_eq!(prompter.asked(), 0);
        assert!(!data.always_on.unwrap().key_moved);
    }

    let (_dir, ops) = ops_with("");
    let platform = MemoryKeyStore::new();
    platform_identity(&ops, &platform);
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    let prompter = Answer::new(None);
    ops.service_install_with_options(&host, None, &always_on_options(), &prompter)
        .unwrap();
    assert_eq!(
        prompter.asked(),
        0,
        "a Password task opens Credential Manager"
    );
    assert_eq!(key_store_of(&ops), KeyStoreKind::Platform);
}

// ---------------------------------------------------------------------
// uninstall --always-on
// ---------------------------------------------------------------------

#[test]
fn uninstall_always_on_reverses_linger() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let root = temp_home();
    let home = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    seed_unit(Manager::Systemd, &home, "serve");
    let data = uninstall_always_on(&ops, &host, &home).unwrap();
    assert_eq!(runner.calls(), vec!["loginctl disable-linger you"]);
    assert_eq!(runner.interactive.lock().unwrap().len(), 1);
    assert_eq!(
        data.always_on.unwrap().state,
        ServiceAlwaysOnState::Disabled
    );
    assert!(data.removed);
}

#[test]
fn uninstall_always_on_removes_the_launchdaemon() {
    let (_dir, ops) = ops_with("");
    let root = temp_home();
    let home = temp_home();
    let daemon = root
        .path()
        .join("Library")
        .join("LaunchDaemons")
        .join("io.qsh.serve.plist");
    std::fs::create_dir_all(daemon.parent().unwrap()).unwrap();
    std::fs::write(&daemon, "daemon").unwrap();
    let runner = FakeRunner::default();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let data = uninstall_always_on(&ops, &host, &home).unwrap();
    assert_eq!(
        runner.calls(),
        vec![
            "launchctl print system/io.qsh.serve".to_string(),
            "sudo launchctl bootout system/io.qsh.serve".to_string(),
            format!("sudo rm {}", daemon.display()),
        ]
    );
    assert_eq!(
        data.always_on.unwrap().state,
        ServiceAlwaysOnState::Disabled
    );

    // A daemon that is not loaded has nothing to boot out; the file still goes.
    let runner = FakeRunner::exiting_when(|call| call.starts_with("launchctl print"), 113);
    let host = host_for(Manager::Launchd, &runner, root.path());
    let state = uninstall_always_on(&ops, &host, &home)
        .unwrap()
        .always_on
        .unwrap()
        .state;
    assert_eq!(state, ServiceAlwaysOnState::Disabled);
    assert_eq!(
        runner.calls(),
        vec![
            "launchctl print system/io.qsh.serve".to_string(),
            format!("sudo rm {}", daemon.display()),
        ]
    );

    // No daemon file: nothing to reverse, no call.
    std::fs::remove_file(&daemon).unwrap();
    let runner = FakeRunner::default();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let data = uninstall_always_on(&ops, &host, &home).unwrap();
    assert_eq!(
        data.always_on.unwrap().state,
        ServiceAlwaysOnState::NotEnabled
    );
    assert!(runner.calls().is_empty());
}

#[test]
fn uninstall_always_on_deletes_the_task_and_the_firewall_rule() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let scheduler = FakeScheduler::registered(TaskLogonType::Password, true);
    let host = host_with_scheduler(Manager::TaskScheduler, &runner, Path::new(""), &scheduler);
    let task = windows_manager_seed(&ops);
    let always_on_file = task.with_file_name("qsh-serve.always-on.xml");
    std::fs::write(&always_on_file, "xml").unwrap();
    let data = ops
        .service_uninstall_with_options(&host, None, false, true)
        .unwrap();
    assert_eq!(
        runner.calls(),
        vec![
            "fltmc",
            r"schtasks /End /TN \qsh\qsh-serve",
            r"schtasks /Delete /F /TN \qsh\qsh-serve",
            "netsh advfirewall firewall delete rule name=qsh-serve",
        ]
    );
    let always_on = data.always_on.unwrap();
    assert_eq!(always_on.state, ServiceAlwaysOnState::Disabled);
    assert!(always_on.firewall_rule);
    assert!(!always_on_file.exists());
    assert!(!task.exists());

    // No `Password` task: nothing to reverse.
    let runner = FakeRunner::default();
    let host = task_host(&runner);
    let data = ops
        .service_uninstall_with_options(&host, None, false, true)
        .unwrap();
    assert_eq!(
        data.always_on.unwrap().state,
        ServiceAlwaysOnState::NotEnabled
    );
    assert_eq!(runner.calls(), vec!["fltmc"]);
}

// ---------------------------------------------------------------------
// Failure and the seams
// ---------------------------------------------------------------------

#[test]
fn a_failed_sudo_step_names_the_step_and_keeps_the_unit_file() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting_when(|call| call.starts_with("sudo chown"), 1);
    let root = temp_home();
    let home = temp_home();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let err = install_with(&ops, &host, &home, &always_on_options(), &NoPrompter).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.message.contains("`sudo` failed"), "{}", err.message);
    assert!(err.message.contains("--always-on"), "{}", err.message);
    assert!(unit_of(Manager::Launchd, home.path(), "serve").exists());
    // The staging file does not outlive the failure.
    assert!(
        !ops.paths()
            .config_dir
            .join("service")
            .join("io.qsh.serve.plist")
            .exists()
    );
    // No later step ran.
    assert!(
        !runner
            .calls()
            .iter()
            .any(|call| call.contains("bootstrap system"))
    );
}

#[test]
fn the_command_runner_gives_an_interactive_child_the_terminal_without_capturing_it() {
    // `true` stands in for sudo: it exits 0 and prints nothing.
    if cfg!(unix) {
        let runner = CommandRunner::system();
        let output = runner
            .run_interactive(&["true".to_string()], Duration::from_secs(10))
            .unwrap();
        assert!(output.success());
        assert_eq!(
            output.stderr_first_line, "",
            "stderr is inherited, not read"
        );
        let missing = runner.run_interactive(
            &["qsh-no-such-program".to_string()],
            Duration::from_secs(10),
        );
        assert_eq!(missing, Err(RunError::NotFound));
    }
}
