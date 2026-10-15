use std::sync::Mutex;
use std::time::Duration;

use super::*;
use crate::ops::test_support::temp_ops;

use crate::ops::doctor::infer_run_mode;

// ---------------------------------------------------------------------
// The recording runner. No test in this file ever spawns launchctl,
// systemctl or schtasks (ADR-0032 decision 10): every manager call lands
// here.
// ---------------------------------------------------------------------

type Reply = Box<dyn Fn(&[String]) -> Result<ManagerOutput, RunError> + Send + Sync>;

struct FakeRunner {
    calls: Mutex<Vec<Vec<String>>>,
    deadlines: Mutex<Vec<Duration>>,
    reply: Reply,
}

impl Default for FakeRunner {
    /// Every call exits 0.
    fn default() -> Self {
        Self::with(|_| Ok(exit(0, "")))
    }
}

impl FakeRunner {
    fn with(
        reply: impl Fn(&[String]) -> Result<ManagerOutput, RunError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            deadlines: Mutex::new(Vec::new()),
            reply: Box::new(reply),
        }
    }

    /// Every call exits `code`.
    fn exiting(code: i32) -> Self {
        Self::with(move |_| Ok(exit(code, "")))
    }

    /// Calls exit 0 except the one whose argv joined by spaces satisfies
    /// `pred`, which exits `code`.
    fn exiting_when(pred: impl Fn(&str) -> bool + Send + Sync + 'static, code: i32) -> Self {
        Self::with(move |argv| Ok(exit(if pred(&argv.join(" ")) { code } else { 0 }, "")))
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|argv| argv.join(" "))
            .collect()
    }
}

impl ManagerRunner for FakeRunner {
    fn run(&self, argv: &[String], deadline: Duration) -> Result<ManagerOutput, RunError> {
        self.calls.lock().unwrap().push(argv.to_vec());
        self.deadlines.lock().unwrap().push(deadline);
        (self.reply)(argv)
    }
}

fn exit(code: i32, stderr: &str) -> ManagerOutput {
    ManagerOutput {
        exit_code: Some(code),
        stderr_first_line: stderr.to_string(),
    }
}

fn platform_manager() -> Manager {
    if cfg!(target_os = "macos") {
        Manager::Launchd
    } else {
        Manager::Systemd
    }
}

/// A host for `manager`, uid 501, with `system_root` standing in for `/`.
fn host_for<'a>(manager: Manager, runner: &'a FakeRunner, system_root: &Path) -> ServiceHost<'a> {
    ServiceHost {
        manager,
        runner,
        euid: 501,
        system_root: system_root.to_path_buf(),
        wsl: false,
    }
}

/// The host the pre-activation tests run against: this platform's manager,
/// a root that holds no LaunchDaemon.
fn platform_host(runner: &FakeRunner) -> ServiceHost<'_> {
    host_for(
        platform_manager(),
        runner,
        Path::new("/qsh-test-root-without-launchdaemons"),
    )
}

const BOTH_MANAGERS: [Manager; 2] = [Manager::Launchd, Manager::Systemd];

fn temp_home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn write_config(ops: &Ops, toml: &str) {
    std::fs::create_dir_all(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().config_file(), toml).unwrap();
}

// ---------------------------------------------------------------------
// Pure renderers and path builders — no HOME, no Ops, every platform.
// ---------------------------------------------------------------------

#[test]
fn launchd_plist_renders_the_fleet_semantics_for_each_mode() {
    for mode in ["serve", "listen", "reverse"] {
        let plist = render_launchd_plist(mode, "/exe", "/home/x", "ctrl");
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>\n"));
        assert!(plist.contains("<key>KeepAlive</key>\n  <true/>\n"));
        assert!(plist.contains("<key>ThrottleInterval</key>\n  <integer>15</integer>\n"));
        assert!(plist.contains("<key>ProcessType</key>\n  <string>Background</string>\n"));
        assert!(plist.contains("<key>HOME</key>\n    <string>/home/x</string>\n"));
        assert!(
            plist.contains(
                "<key>PATH</key>\n    <string>/opt/homebrew/bin:/usr/bin:/bin</string>\n"
            )
        );
        assert!(plist.contains(&format!(
            "<string>/home/x/Library/Logs/qsh/{mode}.out.log</string>"
        )));
        assert!(plist.contains(&format!(
            "<string>/home/x/Library/Logs/qsh/{mode}.err.log</string>"
        )));
    }
}

#[test]
fn plist_environment_variables_carry_no_xdg_keys() {
    for mode in ["serve", "listen", "reverse"] {
        let plist = render_launchd_plist(mode, "/exe", "/home/x", "ctrl");
        assert!(
            !plist.contains("XDG_"),
            "EnvironmentVariables must carry only HOME and PATH: {plist}"
        );
    }
}

#[test]
fn systemd_unit_renders_restart_always_for_each_mode() {
    for mode in ["serve", "listen", "reverse"] {
        let unit = render_systemd_unit(mode, "/exe", "ctrl");
        assert!(unit.contains("Restart=always\n"));
        assert!(unit.contains("RestartSec=2\n"));
        assert!(unit.contains("WantedBy=default.target\n"));
    }
}

#[test]
fn plist_escapes_xml_significant_characters_in_the_controller() {
    // `[serve].to`/`[reverse].controller` is a free-form config string —
    // `config_outbound_target` does not restrict its characters — so a
    // value containing `&`, `<` or `>` must not break the plist's XML.
    let plist = render_launchd_plist("reverse", "/exe", "/home/x", "a&b<c>d");
    assert!(
        plist.contains("<string>serve</string>\n    <string>--to</string>\n    <string>a&amp;b&lt;c&gt;d</string>\n"),
        "{plist}"
    );
    assert!(
        !plist.contains("a&b<c>d"),
        "raw value must not appear unescaped: {plist}"
    );
}

#[test]
fn systemd_unit_quotes_a_controller_with_whitespace() {
    let unit = render_systemd_unit("reverse", "/exe", "a controller");
    assert!(
        unit.contains("ExecStart=/exe serve --to \"a controller\"\n"),
        "{unit}"
    );
}

#[test]
fn reverse_mode_units_invoke_serve_to_not_the_hidden_alias() {
    // The file/label token stays `reverse` (`docs/CLI.md` §6.18)...
    let plist = render_launchd_plist("reverse", "/exe", "/home/x", "ctrl-name");
    assert!(plist.contains("<string>io.qsh.reverse</string>"));
    // ...but the argv it launches is `serve --to <controller>`, never the
    // hidden `reverse <controller>` alias.
    assert!(plist.contains(
        "<string>serve</string>\n    <string>--to</string>\n    <string>ctrl-name</string>\n"
    ));
    assert!(!plist.contains("<string>reverse</string>\n"));

    let unit = render_systemd_unit("reverse", "/exe", "ctrl-name");
    assert!(unit.contains("ExecStart=/exe serve --to ctrl-name\n"));
    assert!(unit.contains("Description=qsh serve --to\n"));
}

#[test]
fn unit_arguments_are_fixed() {
    // No `--bind`, no `--name`, no config or verbosity flag ever reaches
    // the argv — exactly the three fixed shapes below, nothing else.
    assert_eq!(mode_argv("serve", "ctrl"), vec!["serve".to_string()]);
    assert_eq!(mode_argv("listen", "ctrl"), vec!["listen".to_string()]);
    assert_eq!(
        mode_argv("reverse", "ctrl"),
        vec!["serve".to_string(), "--to".to_string(), "ctrl".to_string()]
    );
}

#[test]
fn install_path_matches_the_doctor_probe_path_for_every_mode() {
    let home = temp_home();
    for mode in ["serve", "listen", "reverse"] {
        assert_eq!(
            unit_path(Manager::Launchd, home.path(), mode),
            crate::doctor::probe::macos_launchagent_path(home.path(), mode)
        );
        assert_eq!(
            unit_path(Manager::Systemd, home.path(), mode),
            crate::doctor::probe::linux_systemd_user_unit_path(home.path(), mode)
        );
    }
}

#[test]
fn mode_vocabularies_agree() {
    // `infer_run_mode`'s three return values are exactly the tokens the
    // unit paths/renderers key their per-mode behaviour off, and the same
    // three `qsh-cli`'s `SERVE_MODE`/`LISTEN_MODE`/`REVERSE_MODE`
    // constants spell (`"serve"`/`"listen"`/`"reverse"`).
    let mut only_default = Config::default();
    assert_eq!(infer_run_mode(&only_default), "serve");

    let mut only_listen = Config::default();
    only_listen.listen.allow_advertised_names = true;
    assert_eq!(infer_run_mode(&only_listen), "listen");

    only_default.serve.to = Some("ctrl".to_string());
    assert_eq!(infer_run_mode(&only_default), "reverse");
}

// ---------------------------------------------------------------------
// The *_with_home seam — real Ops, an explicit tempdir home, never
// `crate::config::home_dir()`'s real value (module doc).
// ---------------------------------------------------------------------

#[test]
fn mode_inference_covers_the_four_config_shapes() {
    let cases: [(&str, &str); 4] = [
        ("", "serve"),
        ("[listen]\nallow_advertised_names = true\n", "listen"),
        ("[serve]\nto = \"ctrl\"\n", "reverse"),
        ("[reverse]\ncontroller = \"ctrl\"\n", "reverse"),
    ];
    for (toml, expected_mode) in cases {
        let (_dir, ops) = temp_ops();
        let runner = FakeRunner::default();
        let host = platform_host(&runner);
        if !toml.is_empty() {
            write_config(&ops, toml);
        }
        let home = temp_home();
        let data = ops
            .service_status_with_home(&host, Some(home.path().to_path_buf()), false)
            .unwrap();
        assert_eq!(data.mode, expected_mode, "config: {toml:?}");
    }
}

#[test]
fn config_conflict_is_config_error_and_writes_nothing() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    write_config(&ops, "[serve]\nto = \"a\"\n[reverse]\ncontroller = \"b\"\n");
    let home = temp_home();
    let err = ops
        .service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    // The conflict is caught at step 3, strictly before step 5 (home
    // resolution) and step 9 (the write) — nothing was created anywhere
    // under the tempdir home.
    assert!(!home.path().join("Library").exists());
    assert!(!home.path().join(".config").exists());
}

/// `docs/CLI.md` §6.18: all three ops apply the same steps 1-6, so
/// `uninstall` and `status` fail the same `CONFIG_ERROR` as `install`
/// on the `[serve].to`/`[reverse].controller` disagreement — not just the
/// writing op.
#[test]
fn config_conflict_is_config_error_for_uninstall_and_status_too() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    write_config(&ops, "[serve]\nto = \"a\"\n[reverse]\ncontroller = \"b\"\n");

    let home = temp_home();
    let err = ops
        .service_uninstall_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(!home.path().join("Library").exists());
    assert!(!home.path().join(".config").exists());

    let home = temp_home();
    let err = ops
        .service_status_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
}

#[test]
fn config_conflict_with_equal_values_installs_normally() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    write_config(
        &ops,
        "[serve]\nto = \"same\"\n[reverse]\ncontroller = \"same\"\n",
    );
    let home = temp_home();
    let data = ops
        .service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();
    assert_eq!(data.mode, "reverse");
    assert!(data.created);
}

#[test]
fn install_is_idempotent_and_reports_created_only_the_first_time() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    let home = temp_home();
    let first = ops
        .service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();
    assert!(first.created);
    let bytes_first = std::fs::read(&first.path).unwrap();

    let second = ops
        .service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();
    assert!(!second.created);
    let bytes_second = std::fs::read(&second.path).unwrap();
    assert_eq!(bytes_first, bytes_second);
}

/// `docs/CLI.md` §6.18 / `docs/deploy/service.md`: `install` does not own
/// the unit's parent directory (`~/Library/LaunchAgents` holds every other
/// application's agents too), so a pre-existing directory's mode is left
/// exactly as it was — only the unit file itself is written 0600. Pinned
/// here at the `service install` level so the documented behavior cannot
/// silently regress back to tightening a directory qsh does not own.
#[cfg(unix)]
#[test]
fn install_leaves_an_existing_unit_directory_mode_alone() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    let home = temp_home();
    let manager = platform_manager();
    let parent = unit_path(manager, home.path(), "serve")
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

    let data = ops
        .service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();

    let dir_mode = std::fs::metadata(&parent).unwrap().permissions().mode();
    assert_eq!(
        dir_mode & 0o777,
        0o755,
        "a pre-existing unit directory's mode must be left alone"
    );
    let file_mode = std::fs::metadata(&data.path).unwrap().permissions().mode();
    assert_eq!(file_mode & 0o777, 0o600, "the unit file itself is 0600");
}

/// The other half of the create-if-absent contract: when the unit
/// directory does not exist yet, `install` still creates it (and the unit
/// file inside it) rather than failing.
#[test]
fn install_creates_a_missing_unit_directory() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    let home = temp_home();
    let manager = platform_manager();
    let parent = unit_path(manager, home.path(), "serve")
        .parent()
        .unwrap()
        .to_path_buf();
    assert!(!parent.exists());

    let data = ops
        .service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();

    assert!(parent.exists());
    assert!(std::path::Path::new(&data.path).exists());
}

#[test]
fn uninstall_on_an_absent_unit_is_ok_and_reports_removed_false() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    let home = temp_home();
    let data = ops
        .service_uninstall_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();
    assert!(!data.removed);

    // A unit `qsh` did not write is removed all the same (`docs/CLI.md`
    // §6.18) — the contract is the path, not provenance.
    let manager = platform_manager();
    let path = unit_path(manager, home.path(), "serve");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, "hand-authored").unwrap();
    let data = ops
        .service_uninstall_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();
    assert!(data.removed);
    assert!(!path.exists());
}

#[test]
fn status_flips_from_false_to_true_across_install() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    let home = temp_home();
    let before = ops
        .service_status_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();
    assert!(!before.installed);

    ops.service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();

    let after = ops
        .service_status_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap();
    assert!(after.installed);
}

#[test]
fn unsupported_platform_is_reported_before_the_home_directory_is_even_read() {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    // A config.toml `Config::load` would refuse with `CONFIG_ERROR` if
    // step 2 ever ran — on this (unsupported) platform it must not, since
    // step 1's manager check comes first and fails closed on its own.
    std::fs::create_dir_all(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().config_file(), "not valid toml === {{{").unwrap();

    let err = ops.service_install(false).unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert!(err.message.contains("P1"));
}

#[test]
fn install_is_refused_when_the_audit_sink_fails() {
    let (_dir, ops) = temp_ops();
    let runner = FakeRunner::default();
    let host = platform_host(&runner);
    let sink = std::sync::Arc::new(crate::audit::FailingAuditSink::new());
    sink.fail();
    let ops = ops.with_audit_sink(sink.clone());
    let home = temp_home();

    let err = ops
        .service_install_with_home(&host, Some(home.path().to_path_buf()), false)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.retryable);
    assert!(sink.records().is_empty());

    let manager = platform_manager();
    let path = unit_path(manager, home.path(), "serve");
    assert!(
        !path.exists(),
        "no unit may be written when the audit record fails"
    );
}

// ---------------------------------------------------------------------
// Manager calls (ADR-0032) — a recording runner stands in for launchctl
// and systemctl.
// ---------------------------------------------------------------------

/// `[listen]` / `[serve].to` / nothing: the three run modes.
const MODE_CONFIGS: [(&str, &str); 3] = [
    ("serve", ""),
    ("listen", "[listen]\nallow_advertised_names = true\n"),
    ("reverse", "[serve]\nto = \"ctrl\"\n"),
];

fn ops_with(config: &str) -> (tempfile::TempDir, Ops) {
    let (dir, ops) = temp_ops();
    if !config.is_empty() {
        write_config(&ops, config);
    }
    (dir, ops)
}

fn install(
    ops: &Ops,
    host: &ServiceHost<'_>,
    home: &tempfile::TempDir,
    activate: bool,
) -> Result<ServiceInstallData, OpError> {
    ops.service_install_with_home(host, Some(home.path().to_path_buf()), activate)
}

fn uninstall(
    ops: &Ops,
    host: &ServiceHost<'_>,
    home: &tempfile::TempDir,
    deactivate: bool,
) -> Result<ServiceUninstallData, OpError> {
    ops.service_uninstall_with_home(host, Some(home.path().to_path_buf()), deactivate)
}

fn status(
    ops: &Ops,
    host: &ServiceHost<'_>,
    home: &tempfile::TempDir,
    live: bool,
) -> Result<ServiceStatusData, OpError> {
    ops.service_status_with_home(host, Some(home.path().to_path_buf()), live)
}

/// Puts a unit file at `manager`'s path for `mode`, as a previous
/// `install` would have.
fn seed_unit(manager: Manager, home: &tempfile::TempDir, mode: &str) -> PathBuf {
    let path = unit_path(manager, home.path(), mode);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "unit").unwrap();
    path
}

#[test]
fn install_without_activate_never_invokes_the_manager() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::default();
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        let data = install(&ops, &host, &home, false).unwrap();
        assert_eq!(data.activation, None);
        assert!(
            runner.calls().is_empty(),
            "{manager:?}: {:?}",
            runner.calls()
        );
    }
}

#[test]
fn uninstall_without_deactivate_never_invokes_the_manager() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::default();
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        seed_unit(manager, &home, "serve");
        let data = uninstall(&ops, &host, &home, false).unwrap();
        assert!(data.removed);
        assert_eq!(data.deactivation, None);
        assert!(
            runner.calls().is_empty(),
            "{manager:?}: {:?}",
            runner.calls()
        );
    }
}

#[test]
fn status_without_live_never_invokes_the_manager() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::default();
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        seed_unit(manager, &home, "serve");
        let data = status(&ops, &host, &home, false).unwrap();
        assert!(data.installed);
        assert_eq!(data.active, None);
        assert!(
            runner.calls().is_empty(),
            "{manager:?}: {:?}",
            runner.calls()
        );
    }
}

#[test]
fn install_activate_runs_the_documented_argv_on_launchd() {
    let (_dir, ops) = ops_with("");
    // `launchctl print` exits 113 for a label that is not loaded.
    let runner = FakeRunner::exiting_when(|argv| argv.starts_with("launchctl print"), 113);
    let root = temp_home();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let home = temp_home();
    let data = install(&ops, &host, &home, true).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(
        runner.calls(),
        vec![
            "launchctl print gui/501/io.qsh.serve".to_string(),
            format!("launchctl bootstrap gui/501 {}", data.path),
        ]
    );
    assert!(
        std::path::Path::new(&data.path).exists(),
        "the unit file is written before the manager is called"
    );
}

#[test]
fn install_activate_runs_the_documented_argv_on_systemd() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting_when(|argv| argv.contains("is-active"), 3);
    let root = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let home = temp_home();
    let data = install(&ops, &host, &home, true).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::Started));
    assert_eq!(
        runner.calls(),
        vec![
            "systemctl --user is-active qsh-serve.service",
            "systemctl --user daemon-reload",
            "systemctl --user enable --now qsh-serve.service",
        ]
    );
    // The deadline every call carries is the 30 seconds of decision 8.
    assert!(
        runner
            .deadlines
            .lock()
            .unwrap()
            .iter()
            .all(|deadline| *deadline == Duration::from_secs(30))
    );
}

#[test]
fn install_activate_argv_covers_serve_listen_and_reverse_modes() {
    for (mode, config) in MODE_CONFIGS {
        for manager in BOTH_MANAGERS {
            let (_dir, ops) = ops_with(config);
            let runner = FakeRunner::exiting_when(
                |argv| argv.contains("is-active") || argv.starts_with("launchctl print"),
                3,
            );
            let root = temp_home();
            let host = host_for(manager, &runner, root.path());
            let home = temp_home();
            let data = install(&ops, &host, &home, true).unwrap();
            assert_eq!(data.mode, mode);
            let calls = runner.calls();
            let expected = match manager {
                Manager::Launchd => vec![
                    format!("launchctl print gui/501/io.qsh.{mode}"),
                    format!("launchctl bootstrap gui/501 {}", data.path),
                ],
                Manager::Systemd => vec![
                    format!("systemctl --user is-active qsh-{mode}.service"),
                    "systemctl --user daemon-reload".to_string(),
                    format!("systemctl --user enable --now qsh-{mode}.service"),
                ],
            };
            assert_eq!(calls, expected, "{manager:?} {mode}");
            assert!(
                calls.iter().all(|call| !call.contains("restart")),
                "no call restarts a unit: {calls:?}"
            );
        }
    }
}

/// ADR-0032 decision 3: the only values that reach a manager argv are the
/// euid, the unit path and the closed mode set. A controller literal full
/// of whitespace, quotes and `--` stays in the unit file.
#[test]
fn manager_argv_never_contains_user_input() {
    let hostile = "a b\" -- --now \\ 'x'";
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with(&format!(
            "[serve]\nto = \"{}\"\n",
            hostile.replace('\\', "\\\\").replace('"', "\\\"")
        ));
        let runner = FakeRunner::exiting_when(
            |argv| argv.contains("is-active") || argv.starts_with("launchctl print"),
            3,
        );
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        let data = install(&ops, &host, &home, true).unwrap();
        assert_eq!(data.mode, "reverse");
        // The literal really is in the unit file...
        let unit = std::fs::read_to_string(&data.path).unwrap();
        assert!(unit.contains("--now"), "{unit}");
        // ...and in no argv: every call is one of the documented shapes for
        // the `reverse` mode.
        let uid = "501";
        let allowed: Vec<String> = match manager {
            Manager::Launchd => vec![
                launchd_print_argv(uid, "reverse").join(" "),
                launchd_bootstrap_argv(uid, &data.path).join(" "),
                launchd_bootout_argv(uid, "reverse").join(" "),
            ],
            Manager::Systemd => vec![
                systemd_is_active_argv("reverse").join(" "),
                systemd_daemon_reload_argv().join(" "),
                systemd_enable_now_argv("reverse").join(" "),
                systemd_disable_now_argv("reverse").join(" "),
            ],
        };
        for call in runner.calls() {
            assert!(
                allowed.contains(&call),
                "{manager:?}: unexpected argv {call:?}"
            );
        }
        uninstall(&ops, &host, &home, true).unwrap();
        status(&ops, &host, &home, true).unwrap();
        for call in runner.calls() {
            assert!(
                allowed.contains(&call),
                "{manager:?}: unexpected argv {call:?}"
            );
        }
    }
}

#[test]
fn activate_does_not_restart_an_already_active_unit() {
    // launchd: loaded means `bootstrap` is not called at all.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let root = temp_home();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let home = temp_home();
    let data = install(&ops, &host, &home, true).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::AlreadyActive));
    assert_eq!(
        runner.calls(),
        vec!["launchctl print gui/501/io.qsh.serve".to_string()]
    );

    // systemd: active means `enable --now` (which leaves an active unit
    // alone) and never `restart`.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let home = temp_home();
    let data = install(&ops, &host, &home, true).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::AlreadyActive));
    assert_eq!(
        runner.calls(),
        vec![
            "systemctl --user is-active qsh-serve.service",
            "systemctl --user daemon-reload",
            "systemctl --user enable --now qsh-serve.service",
        ]
    );
}

#[test]
fn deactivate_calls_disable_for_a_registered_but_inactive_unit() {
    // systemd: the unit file is the registration. The unit is enabled but
    // stopped (`is-active` would exit 3), and `disable --now` is still
    // called, without asking whether it runs.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting_when(|argv| argv.contains("is-active"), 3);
    let root = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let home = temp_home();
    let path = seed_unit(Manager::Systemd, &home, "serve");
    let data = uninstall(&ops, &host, &home, true).unwrap();
    assert_eq!(data.deactivation, Some(ServiceDeactivation::Stopped));
    assert!(data.removed);
    assert!(!path.exists());
    assert_eq!(
        runner.calls(),
        vec!["systemctl --user disable --now qsh-serve.service"]
    );

    // launchd: registered (`print` exits 0) means `bootout`.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let home = temp_home();
    seed_unit(Manager::Launchd, &home, "serve");
    let data = uninstall(&ops, &host, &home, true).unwrap();
    assert_eq!(data.deactivation, Some(ServiceDeactivation::Stopped));
    assert_eq!(
        runner.calls(),
        vec![
            "launchctl print gui/501/io.qsh.serve",
            "launchctl bootout gui/501/io.qsh.serve",
        ]
    );
}

#[test]
fn deactivate_skips_when_the_unit_is_not_registered() {
    // systemd: no unit file, no call.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let root = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let home = temp_home();
    let data = uninstall(&ops, &host, &home, true).unwrap();
    assert_eq!(data.deactivation, Some(ServiceDeactivation::NotActive));
    assert!(!data.removed);
    assert!(runner.calls().is_empty());

    // launchd: `print` exits non-zero, so only the query ran.
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::exiting(113);
    let host = host_for(Manager::Launchd, &runner, root.path());
    let home = temp_home();
    seed_unit(Manager::Launchd, &home, "serve");
    let data = uninstall(&ops, &host, &home, true).unwrap();
    assert_eq!(data.deactivation, Some(ServiceDeactivation::NotActive));
    assert!(data.removed, "the file is still removed");
    assert_eq!(runner.calls(), vec!["launchctl print gui/501/io.qsh.serve"]);
}

#[test]
fn deactivate_runs_before_the_unit_file_is_removed() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let home = temp_home();
        let path = seed_unit(manager, &home, "serve");
        // Each call records whether the unit file still existed when the
        // manager was asked.
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let runner = {
            let seen = std::sync::Arc::clone(&seen);
            let path = path.clone();
            FakeRunner::with(move |argv| {
                seen.lock().unwrap().push((argv.join(" "), path.exists()));
                Ok(exit(0, ""))
            })
        };
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        uninstall(&ops, &host, &home, true).unwrap();
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(
            seen.iter().all(|(_, existed)| *existed),
            "{manager:?}: the file must exist for every manager call: {seen:?}"
        );
        assert!(!path.exists(), "{manager:?}: and be gone afterwards");
    }
}

#[test]
fn a_failed_deactivate_keeps_the_unit_file() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::with(|argv| {
            let line = argv.join(" ");
            if line.contains("bootout") || line.contains("disable") {
                Ok(exit(5, "Boot-out failed: 5: Input/output error"))
            } else {
                Ok(exit(0, ""))
            }
        });
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        let path = seed_unit(manager, &home, "serve");
        let err = uninstall(&ops, &host, &home, true).unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal, "{manager:?}");
        assert_eq!(err.details["step"], "deactivate");
        assert_eq!(err.details["exit_code"], 5);
        assert!(path.exists(), "{manager:?}: the unit file must stay");
    }
}

#[test]
fn a_failed_activation_keeps_the_written_unit_file() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::with(|argv| {
            let line = argv.join(" ");
            if line.contains("bootstrap") || line.contains("enable") {
                Ok(exit(5, "Bootstrap failed: 5: Input/output error"))
            } else if line.contains("print") || line.contains("is-active") {
                Ok(exit(3, ""))
            } else {
                Ok(exit(0, ""))
            }
        });
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        let err = install(&ops, &host, &home, true).unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal, "{manager:?}");
        assert_eq!(err.details["step"], "activate");
        assert!(
            unit_path(manager, home.path(), "serve").exists(),
            "{manager:?}: the file stays so a repeated install continues"
        );
        if manager == Manager::Launchd {
            assert!(
                err.message.contains("gui/501") && err.message.contains("docs/deploy/service.md"),
                "{}",
                err.message
            );
        }
    }
}

#[test]
fn activate_and_deactivate_leave_a_human_installed_always_on_form_untouched() {
    // macOS: a LaunchDaemon plist for the same mode, put there by a person.
    let root = temp_home();
    let daemon = crate::doctor::probe::macos_launchdaemon_path(root.path(), "serve");
    std::fs::create_dir_all(daemon.parent().unwrap()).unwrap();
    std::fs::write(&daemon, "<plist/>").unwrap();

    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let home = temp_home();
    let data = install(&ops, &host, &home, true).unwrap();
    assert_eq!(data.activation, Some(ServiceActivation::AlwaysOnPresent));
    assert!(data.created, "the per-user unit file is still written");
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());

    // Deactivate with the per-user form loaded: `gui` is released as in
    // decision 5, the daemon is not touched, the file is removed.
    let runner = FakeRunner::default();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let data = uninstall(&ops, &host, &home, true).unwrap();
    assert_eq!(
        data.deactivation,
        Some(ServiceDeactivation::AlwaysOnPresent)
    );
    assert!(data.removed);
    assert_eq!(
        runner.calls(),
        vec![
            "launchctl print gui/501/io.qsh.serve",
            "launchctl bootout gui/501/io.qsh.serve",
        ]
    );

    // And with nothing loaded in `gui`, only the query runs.
    install(
        &ops,
        &host_for(Manager::Launchd, &FakeRunner::default(), root.path()),
        &home,
        true,
    )
    .unwrap();
    let runner = FakeRunner::exiting(113);
    let host = host_for(Manager::Launchd, &runner, root.path());
    let data = uninstall(&ops, &host, &home, true).unwrap();
    assert_eq!(
        data.deactivation,
        Some(ServiceDeactivation::AlwaysOnPresent)
    );
    assert_eq!(runner.calls(), vec!["launchctl print gui/501/io.qsh.serve"]);
    assert!(
        runner.calls().iter().all(|call| !call.contains("system/")),
        "no call names the system domain"
    );

    // No run named the `system` domain, and the always-on plist is never
    // removed.
    assert!(daemon.exists(), "the always-on plist is never removed");
}

#[test]
fn status_live_reports_the_always_on_form_when_present() {
    let root = temp_home();
    let daemon = crate::doctor::probe::macos_launchdaemon_path(root.path(), "serve");
    std::fs::create_dir_all(daemon.parent().unwrap()).unwrap();
    std::fs::write(&daemon, "<plist/>").unwrap();

    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::default();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let home = temp_home();
    seed_unit(Manager::Launchd, &home, "serve");
    // `launchctl print system/…` is not known to answer without root, so
    // the run state of the always-on form is not read: INTERNAL with the
    // command to run by hand (ADR-0032 decision 18, third item).
    let err = status(&ops, &host, &home, true).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert_eq!(err.details["step"], "live");
    assert!(
        err.message
            .contains("sudo launchctl print system/io.qsh.serve"),
        "{}",
        err.message
    );
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
}

#[test]
fn status_live_reads_one_exit_code() {
    for manager in BOTH_MANAGERS {
        let query = match manager {
            Manager::Launchd => "launchctl print gui/501/io.qsh.serve",
            Manager::Systemd => "systemctl --user is-active qsh-serve.service",
        };
        let root = temp_home();

        // Running.
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::default();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        seed_unit(manager, &home, "serve");
        let data = status(&ops, &host, &home, true).unwrap();
        assert_eq!((data.installed, data.active), (true, Some(true)));
        assert_eq!(runner.calls(), vec![query]);

        // Installed but not running.
        let runner = FakeRunner::exiting(3);
        let host = host_for(manager, &runner, root.path());
        let data = status(&ops, &host, &home, true).unwrap();
        assert_eq!((data.installed, data.active), (true, Some(false)));

        // No unit file: false without asking the manager.
        let runner = FakeRunner::default();
        let host = host_for(manager, &runner, root.path());
        let empty_home = temp_home();
        let data = status(&ops, &host, &empty_home, true).unwrap();
        assert_eq!((data.installed, data.active), (false, Some(false)));
        assert!(runner.calls().is_empty());
    }
}

#[test]
fn activate_is_skipped_when_the_unit_write_fails() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let runner = FakeRunner::default();
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        // A directory where the unit file belongs: the write cannot succeed.
        let path = unit_path(manager, home.path(), "serve");
        std::fs::create_dir_all(&path).unwrap();
        install(&ops, &host, &home, true).unwrap_err();
        assert!(
            runner.calls().is_empty(),
            "{manager:?}: {:?}",
            runner.calls()
        );
    }
}

#[test]
fn activate_is_skipped_when_the_audit_sink_fails() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("");
        let sink = std::sync::Arc::new(crate::audit::FailingAuditSink::new());
        sink.fail();
        let ops = ops.with_audit_sink(sink.clone());
        let runner = FakeRunner::default();
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();

        let err = install(&ops, &host, &home, true).unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert!(runner.calls().is_empty(), "{manager:?}");
        assert!(!unit_path(manager, home.path(), "serve").exists());

        // The same holds for a release: the file and the manager are both
        // left alone.
        let path = seed_unit(manager, &home, "serve");
        uninstall(&ops, &host, &home, true).unwrap_err();
        assert!(runner.calls().is_empty(), "{manager:?}");
        assert!(path.exists());
    }
}

#[test]
fn a_missing_manager_binary_is_unsupported_and_a_nonzero_exit_is_internal_with_exit_code() {
    for manager in BOTH_MANAGERS {
        let root = temp_home();
        let (_dir, ops) = ops_with("");

        let runner = FakeRunner::with(|_| Err(RunError::NotFound));
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        let err = install(&ops, &host, &home, true).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unsupported, "{manager:?}");
        assert!(
            err.message.contains("docs/deploy/service.md"),
            "{}",
            err.message
        );

        let runner = FakeRunner::with(|argv| {
            if argv
                .iter()
                .any(|a| a == "daemon-reload" || a == "bootstrap")
            {
                Ok(exit(7, "manager says no"))
            } else {
                Ok(exit(3, ""))
            }
        });
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        let err = install(&ops, &host, &home, true).unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal, "{manager:?}");
        assert_eq!(err.details["step"], "activate");
        assert_eq!(err.details["exit_code"], 7);
        assert!(err.message.contains("manager says no"), "{}", err.message);
    }
}

#[test]
fn a_manager_call_past_the_deadline_is_timeout() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::with(|_| Err(RunError::TimedOut));
    let root = temp_home();
    let host = host_for(Manager::Launchd, &runner, root.path());
    let home = temp_home();
    let err = install(&ops, &host, &home, true).unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
    assert_eq!(err.details["step"], "activate");
    assert_eq!(
        *runner.deadlines.lock().unwrap(),
        vec![MANAGER_CALL_DEADLINE],
        "the op hands the runner the 30 second deadline"
    );
    assert_eq!(MANAGER_CALL_DEADLINE, Duration::from_secs(30));
}

/// The real runner's deadline is measured on an injected clock, so the
/// 30 seconds pass in microseconds.
#[cfg(unix)]
#[test]
fn command_runner_kills_a_call_past_its_deadline_on_an_injected_clock() {
    struct JumpingClock(Mutex<Duration>);
    impl ManagerClock for JumpingClock {
        fn now(&self) -> Duration {
            *self.0.lock().unwrap()
        }
        fn pause(&self) {
            *self.0.lock().unwrap() += Duration::from_secs(10);
        }
    }
    let runner = CommandRunner::with_clock(std::sync::Arc::new(JumpingClock(Mutex::new(
        Duration::ZERO,
    ))));
    // A process that outlives the logical 30 seconds; it is killed, not
    // waited for.
    let argv = vec!["sleep".to_string(), "600".to_string()];
    assert_eq!(
        runner.run(&argv, MANAGER_CALL_DEADLINE),
        Err(RunError::TimedOut)
    );
}

#[cfg(unix)]
#[test]
fn command_runner_reports_exit_code_stderr_first_line_and_not_found() {
    let runner = CommandRunner::system();
    let argv: Vec<String> = ["sh", "-c", "echo first >&2; echo second >&2; exit 3"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let output = runner.run(&argv, MANAGER_CALL_DEADLINE).unwrap();
    assert_eq!(output.exit_code, Some(3));
    assert_eq!(output.stderr_first_line, "first");

    let missing = vec!["qsh-no-such-service-manager".to_string()];
    assert_eq!(
        runner.run(&missing, MANAGER_CALL_DEADLINE),
        Err(RunError::NotFound)
    );
}

#[test]
fn manager_stderr_first_line_is_capped_at_512_bytes() {
    // Two-byte characters, so the cut at 512 lands on a boundary.
    let long = "é".repeat(1000);
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::with(move |argv| {
        if argv
            .iter()
            .any(|a| a == "daemon-reload" || a == "bootstrap")
        {
            Ok(exit(1, &long))
        } else {
            Ok(exit(3, ""))
        }
    });
    let root = temp_home();
    let host = host_for(Manager::Systemd, &runner, root.path());
    let home = temp_home();
    let err = install(&ops, &host, &home, true).unwrap_err();
    let kept = err.message.matches('é').count() * 2;
    assert!(kept > 0 && kept <= MANAGER_STDERR_CAP, "kept {kept} bytes");
    assert_eq!(kept, 512);
}

#[test]
fn wsl_without_systemd_unsupported_message_names_wsl_conf() {
    let (_dir, ops) = ops_with("");
    let runner = FakeRunner::with(|_| Err(RunError::NotFound));
    let root = temp_home();
    let home = temp_home();

    let mut host = host_for(Manager::Systemd, &runner, root.path());
    host.wsl = true;
    let err = install(&ops, &host, &home, true).unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert!(err.message.contains("/etc/wsl.conf"), "{}", err.message);
    assert!(err.message.contains("systemd=true"), "{}", err.message);

    host.wsl = false;
    let err = install(&ops, &host, &home, true).unwrap_err();
    assert!(!err.message.contains("wsl.conf"), "{}", err.message);
    assert!(
        err.message.contains("docs/deploy/service.md"),
        "{}",
        err.message
    );
}

/// ADR-0032 decision 1: the flags are on the command line or nowhere.
/// Neither a `[service]` table in `config.toml` nor the environment turns
/// a flagless call into a manager call.
#[test]
fn activation_flags_cannot_be_defaulted_by_config_or_env() {
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with("[service]\nactivate = true\ndeactivate = true\nlive = true\n");
        let runner = FakeRunner::default();
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        // Whether `Config` ignores or rejects the unknown table, no manager
        // call follows from it.
        let _ = install(&ops, &host, &home, false);
        let _ = status(&ops, &host, &home, false);
        let _ = uninstall(&ops, &host, &home, false);
        assert!(
            runner.calls().is_empty(),
            "{manager:?}: {:?}",
            runner.calls()
        );
    }
    // And the op code reads no environment variable of its own. The one
    // allowed read is the WSL probe, which only changes error wording
    // (ADR-0032 decision 8); any other `env::` read or a `QSH_SERVICE*`
    // name fails here.
    let sources = [include_str!("mod.rs"), include_str!("manager.rs")];
    for source in sources {
        let code = source.split("#[cfg(test)]").next().unwrap();
        assert!(
            !code.contains("QSH_SERVICE"),
            "service code must not read flag defaults from the environment"
        );
        for line in code.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let reads_env = ["env::var", "env::vars", "env::args", "getenv"]
                .iter()
                .any(|needle| line.contains(needle));
            assert!(
                !reads_env || line.contains("WSL_DISTRO_NAME"),
                "service code must not read flag defaults from the environment: `{line}`"
            );
        }
    }
}

/// Windows ends in `UNSUPPORTED` before any flag is looked at; the Task
/// Scheduler backend is later work (ADR-0032 decision 10, ADR-0035
/// decisions 27 and 28).
#[cfg(windows)]
#[test]
fn service_activation_flags_are_unsupported_on_windows_before_m19() {
    let (_dir, ops) = temp_ops();
    std::fs::create_dir_all(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().config_file(), "not valid toml === {{{").unwrap();
    let runner = FakeRunner::default();
    assert_eq!(
        ServiceHost::resolve(&runner).err().map(|err| err.code),
        Some(ErrorCode::Unsupported)
    );
    for err in [
        ops.service_install(true).unwrap_err(),
        ops.service_uninstall(true).unwrap_err(),
        ops.service_status(true).unwrap_err(),
    ] {
        assert_eq!(err.code, ErrorCode::Unsupported);
    }
    assert!(runner.calls().is_empty());
}

/// The stand-in for the Task Scheduler COM state query (ADR-0035 decision
/// 28): the tasks named at construction are running, every other name is
/// not, and each queried name is recorded.
struct FakeTaskState {
    running: Vec<String>,
    queried: Mutex<Vec<String>>,
}

impl TaskStateQuery for FakeTaskState {
    fn is_running(&self, task_name: &str) -> Result<bool, OpError> {
        self.queried.lock().unwrap().push(task_name.to_string());
        Ok(self.running.iter().any(|name| name == task_name))
    }
}

#[test]
fn task_state_query_is_object_safe_and_answers_by_task_name() {
    let fake = FakeTaskState {
        running: vec![r"\qsh\qsh-serve".to_string()],
        queried: Mutex::new(Vec::new()),
    };
    let query: &dyn TaskStateQuery = &fake;
    assert!(query.is_running(r"\qsh\qsh-serve").unwrap());
    assert!(!query.is_running(r"\qsh\qsh-listen").unwrap());
    assert_eq!(
        *fake.queried.lock().unwrap(),
        [r"\qsh\qsh-serve", r"\qsh\qsh-listen"]
    );
}
