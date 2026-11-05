//! `service.*` operations — `qsh service install|uninstall|status`
//! (`docs/CLI.md` §6.18). Writes, removes and reports the launchd (macOS)
//! or systemd (Linux) user unit, or the Task Scheduler task definition
//! (Windows, ADR-0035 decision 27), for this machine's inferred run mode.
//! `UNSUPPORTED` on every other platform, before anything is read or
//! written.
//!
//! Without a flag the ops never touch the service manager. With
//! `--activate`, `--deactivate` or `--live` (ADR-0032 decision 1) they make
//! the calls of the decision 3 table through a [`ManagerRunner`], and read
//! only exit codes. The Task Scheduler row reads two more things through COM
//! instead of through a process: whether the task is running
//! ([`TaskStateQuery`]) and under which principal it is registered
//! ([`TaskDefinitionReader`]), the latter to leave a person's always-on task
//! alone (ADR-0032 decision 18).
//!
//! Every op runs the same strict prefix in the same order, so `status`
//! fails the same way `install`/`uninstall` do on a bad config:
//!
//! 1. the manager, from `cfg!(target_os = …)` alone — no probing for
//!    `systemctl`/`launchctl`, ever;
//! 2. `Config::load`;
//! 3. [`crate::serve::config_outbound_target`], which is itself the sole
//!    judgment point for the `[serve].to`/`[reverse].controller`
//!    disagreement (`CONFIG_ERROR`, ADR-0012 결정 5) and, on success, the
//!    controller literal a `reverse`-mode unit's argv needs;
//! 4. `super::doctor::infer_run_mode` (widened to `pub(crate)` for this
//!    module — never re-derived);
//! 5. `crate::config::home_dir`;
//! 6. the unit path, via the de-`cfg`'d [`crate::doctor::probe`] builders;
//! 7. (install only) resolve the running binary and render the unit text;
//! 8. (install/uninstall only) one fail-closed [`AuditRecord::local_op`];
//! 9. the filesystem mutation (or, for `status`, `path.exists()`);
//! 10. (flags only) the manager calls: `install --activate` after the unit
//!     file is written, `uninstall --deactivate` before it is removed,
//!     `status --live` as the one read (ADR-0032 decisions 2, 5, 6). A
//!     failed audit write or unit write means no manager call, and a failed
//!     release keeps the unit file.
//!
//! **The test seam.** `crate::config::home_dir` wraps
//! `std::env::home_dir()`, which cannot be mocked without an unsafe,
//! repo-wide-banned `std::env::set_var` (edition 2024, data races against
//! concurrent env readers). So the three public `Ops::service_*` methods
//! are the *only* callers of it; every step after "resolve home" lives in
//! a `pub(crate)` `*_with_home` twin parameterized on `home: Option<PathBuf>`
//! and on a `ServiceHost` (the manager, the [`ManagerRunner`], the euid,
//! the root `/Library/LaunchDaemons` hangs under), which `tests.rs` drives
//! with an explicit tempdir and a recording runner. Only `resolve_manager`
//! has a `cfg`; the launchd and systemd rows run on every build target
//! (ADR-0032 decision 10). This is the same "detection reads real state,
//! everything else is a pure function of its inputs" split
//! `crate::doctor::probe`'s own module doc describes — here extended past
//! the unit-text renderers to the whole op, because nothing about
//! `install`/`uninstall`/`status` besides "what is `$HOME`" is actually
//! untestable.

mod always_on;
mod manager;
mod run;
mod task;
#[cfg(windows)]
mod task_com;

pub use always_on::{
    launchdaemon_install_argvs, launchdaemon_remove_argvs, loginctl_disable_linger_argv,
    loginctl_enable_linger_argv, netsh_firewall_add_argv, netsh_firewall_delete_argv,
    render_launchdaemon_plist, schtasks_create_always_on_argv, windows_elevation_probe_argv,
};
pub use run::SERVICE_RUN_MODES;
pub use task::{
    DOC_EXAMPLE_EXE_WINDOWS, DOC_EXAMPLE_USER_SID, TaskDefinitionReader, TaskLogonType,
    UnreadableTaskScheduler, encode_task_file, render_windows_always_on_task, render_windows_task,
};
#[cfg(windows)]
pub use task_com::ComTaskScheduler;

pub use manager::{
    CommandRunner, INTERACTIVE_CALL_DEADLINE, LAUNCHD_SERVICE_NOT_FOUND, MANAGER_CALL_DEADLINE,
    MANAGER_STDERR_CAP, ManagerClock, ManagerOutput, ManagerRunner, RunError, SystemManagerClock,
    TaskStateQuery, launchd_bootout_argv, launchd_bootstrap_argv, launchd_print_argv,
    launchd_print_system_argv, schtasks_create_argv, schtasks_delete_argv, schtasks_end_argv,
    schtasks_query_argv, schtasks_run_argv, systemd_daemon_reload_argv, systemd_disable_now_argv,
    systemd_enable_now_argv, systemd_is_active_argv,
};

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use qsh_proto::{
    ErrorCode, ServiceActivation, ServiceAlwaysOn, ServiceDeactivation, ServiceInstallData,
    ServiceStatusData, ServiceUninstallData,
};

use crate::audit::{AuditRecord, AuditSink, FileAuditSink};
use crate::config::Config;

use qsh_proto::ConfigSetReq;

use crate::prompts::{NoPrompter, Prompter};

use super::{OpError, Operation, Ops, ServiceInstallOp, ServiceUninstallOp};

/// `qsh service install|uninstall|status` (`docs/CLI.md` §6.18) manage
/// user service units for launchd (macOS), systemd (Linux) and the Task
/// Scheduler (Windows) only; unit installation on this platform is P1 and not
/// implemented. Nothing was written. `docs/deploy/service.md` has a
/// hand-written unit for each supported manager.
///
/// One constant for all three ops and every other target
/// (the "P1 예정" convention of `docs/ROADMAP.md` §3's TCP/TLS fallback row).
/// Compiled on every target, quoted verbatim in `docs/CLI.md` §6.18.
pub const SERVICE_UNSUPPORTED_PLATFORM: &str = "`qsh service` manages user service units for launchd (macOS), systemd (Linux) and the Task Scheduler (Windows) only; unit installation on this platform is P1 and not implemented. Nothing was written. `docs/deploy/service.md` has a hand-written unit for each supported manager.";

/// The example binary path `docs/deploy/service.md`'s launchd fences show.
/// Production passes `std::env::current_exe()`; only the doc-contract test
/// (`crates/qsh-core/tests/it/service_docs.rs`) passes this.
pub const DOC_EXAMPLE_EXE_MACOS: &str = "/Users/YOU/.local/bin/qsh";
/// The example `$HOME` `docs/deploy/service.md`'s launchd fences show.
pub const DOC_EXAMPLE_HOME_MACOS: &str = "/Users/YOU";
/// The example binary path `docs/deploy/service.md`'s systemd fences show
/// (absolute — `%h` cannot be produced from `current_exe()`; see
/// `resolve_current_exe`).
pub const DOC_EXAMPLE_EXE_LINUX: &str = "/home/YOU/.local/bin/qsh";
/// The example controller literal every reverse-mode fence shows.
pub const DOC_EXAMPLE_CONTROLLER: &str = "controller";

/// The service manager that owns a unit. Never serialized directly —
/// [`Manager::as_str`] is what lands in `manager` on every `*Data` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Manager {
    Launchd,
    Systemd,
    TaskScheduler,
}

impl Manager {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Manager::Launchd => "launchd",
            Manager::Systemd => "systemd",
            Manager::TaskScheduler => "task_scheduler",
        }
    }
}

/// Step 1 of every op: the manager for this compile target, from
/// `cfg!(target_os = …)` alone. `Err(UNSUPPORTED)` on every other target
/// before anything is read or written — no probing for
/// `systemctl`/`launchctl`/`schtasks`, ever.
fn resolve_manager() -> Result<Manager, OpError> {
    if cfg!(target_os = "macos") {
        Ok(Manager::Launchd)
    } else if cfg!(target_os = "linux") {
        Ok(Manager::Systemd)
    } else if cfg!(windows) {
        Ok(Manager::TaskScheduler)
    } else {
        Err(
            OpError::new(ErrorCode::Unsupported, SERVICE_UNSUPPORTED_PLATFORM)
                .with_retryable(false),
        )
    }
}

/// Step 5: `$HOME` for the manager that places its unit under it. The Task
/// Scheduler definition lives under the config directory instead, so a missing
/// home is no error there and the empty path returned stands for "unused".
fn resolve_home(manager: Manager, home: Option<PathBuf>) -> Result<PathBuf, OpError> {
    match (manager, home) {
        (_, Some(home)) => Ok(home),
        (Manager::TaskScheduler, None) => Ok(PathBuf::new()),
        (_, None) => Err(home_not_found()),
    }
}

/// Step 6: the unit path for `manager`/`mode`, via the de-`cfg`'d
/// `crate::doctor::probe` builders — never a third, hand-rolled join.
fn unit_path(manager: Manager, home: &Path, config_dir: &Path, mode: &str) -> PathBuf {
    match manager {
        Manager::Launchd => crate::doctor::probe::macos_launchagent_path(home, mode),
        Manager::Systemd => crate::doctor::probe::linux_systemd_user_unit_path(home, mode),
        Manager::TaskScheduler => {
            crate::doctor::probe::windows_task_definition_path(config_dir, mode)
        }
    }
}

/// The fixed argv after `<EXE>`, identical for both managers (`docs/CLI.md`
/// §6.18: unit arguments are fixed — never `--bind`, `--name`, config or
/// verbosity flags). `controller` is only consulted for `"reverse"`.
fn mode_argv(mode: &str, controller: &str) -> Vec<String> {
    match mode {
        "listen" => vec!["listen".to_string()],
        "reverse" => vec![
            "serve".to_string(),
            "--to".to_string(),
            controller.to_string(),
        ],
        _ => vec!["serve".to_string()],
    }
}

/// `Description=`/the plist's human label for `mode` — `"qsh serve --to"`
/// for `reverse`, never naming the controller (it would leak an alias into
/// `systemctl list-units` output for no benefit).
fn mode_description(mode: &str) -> &'static str {
    match mode {
        "listen" => "qsh listen",
        "reverse" => "qsh serve --to",
        _ => "qsh serve",
    }
}

/// Escapes the five XML predefined entities (`&`, `<`, `>`, `"`, `'`) so a
/// config-supplied string — the resolved exe path, `$HOME`, or a
/// `[serve].to`/`[reverse].controller` literal, none of which `Config`
/// restricts to XML-safe characters — cannot break a `<string>` element's
/// boundary and produce an unparseable plist.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Wraps `s` in double quotes (escaping `\` and `"`), systemd unit-file
/// style, when it contains whitespace or a quote/backslash of its own —
/// otherwise returns it unchanged, so the common case renders exactly as
/// before. Without this, a `[serve].to`/`[reverse].controller` literal
/// containing whitespace would split `ExecStart=` into extra argv
/// elements.
fn systemd_quote(s: &str) -> String {
    if s.chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            if c == '"' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
        out
    } else {
        s.to_string()
    }
}

/// The launchd plist for `(mode)` at `exe`/`home`, with the fleet
/// semantics `docs/CLI.md` §6.18 documents: `RunAtLoad`, `KeepAlive`,
/// `ThrottleInterval` 15, `ProcessType` Background, an
/// `EnvironmentVariables` carrying exactly `HOME` and `PATH` (no `XDG_*`),
/// and both log paths under `<home>/Library/Logs/qsh/`. `controller` is
/// only used when `mode == "reverse"`. `exe`/`home`/argv are XML-escaped
/// before interpolation (`xml_escape`).
pub fn render_launchd_plist(mode: &str, exe: &str, home: &str, controller: &str) -> String {
    let argv = mode_argv(mode, controller);
    let exe = xml_escape(exe);
    let home = xml_escape(home);
    let mut program_arguments = format!("    <string>{exe}</string>\n");
    for arg in &argv {
        program_arguments.push_str(&format!("    <string>{}</string>\n", xml_escape(arg)));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"
  \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>Label</key>
  <string>io.qsh.{mode}</string>
  <key>ProgramArguments</key>
  <array>
{program_arguments}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>15</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>{home}</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{home}/Library/Logs/qsh/{mode}.out.log</string>
  <key>StandardErrorPath</key>
  <string>{home}/Library/Logs/qsh/{mode}.err.log</string>
</dict>
</plist>
"
    )
}

/// The systemd user unit for `(mode)` at `exe`, `Restart=always`/
/// `RestartSec=2`. `controller` is only used when `mode == "reverse"`.
/// `exe`/argv are quoted (`systemd_quote`) when they contain whitespace
/// or a quote of their own, so `ExecStart=` cannot silently split into
/// extra arguments.
pub fn render_systemd_unit(mode: &str, exe: &str, controller: &str) -> String {
    let argv = mode_argv(mode, controller);
    let mut exec_start = systemd_quote(exe);
    for arg in &argv {
        exec_start.push(' ');
        exec_start.push_str(&systemd_quote(arg));
    }
    let description = mode_description(mode);
    format!(
        "[Unit]
Description={description}

[Service]
ExecStart={exec_start}
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
"
    )
}

/// The running binary's path for a unit's `<EXE>`/`ExecStart`. An
/// already-absolute path (the common case — a Homebrew install runs
/// through a symlink such as `/opt/homebrew/bin/qsh`) is used exactly as
/// `current_exe()` returned it, **not** `canonicalize()`d: resolving the
/// symlink would pin a Cellar path `brew upgrade` replaces out from under
/// a running unit. A relative path (unusual, but possible depending on how
/// the process was invoked) is canonicalized so the unit still gets an
/// absolute `ExecStart`. Failure of either step is `INTERNAL`,
/// non-retryable — nothing is written.
///
/// This "symlink preserved" guarantee is a macOS property of
/// `std::env::current_exe()`, not a cross-platform one: on Linux, `std`
/// implements it as `readlink("/proc/self/exe")`, which the kernel has
/// already fully resolved, so a symlinked Linux install pins the resolved
/// target here regardless. Re-running `qsh service install` after moving
/// or re-pointing the binary is the refresh path on both platforms.
fn resolve_current_exe() -> Result<PathBuf, OpError> {
    let exe = std::env::current_exe().map_err(|_| {
        OpError::new(
            ErrorCode::Internal,
            "the running binary's path could not be determined; nothing was written",
        )
        .with_retryable(false)
    })?;
    if exe.is_absolute() {
        Ok(exe)
    } else {
        exe.canonicalize().map_err(|_| {
            OpError::new(
                ErrorCode::Internal,
                "the running binary's path could not be determined; nothing was written",
            )
            .with_retryable(false)
        })
    }
}

/// `CONFIG_ERROR` for "`crate::config::home_dir()` returned `None`" — the
/// real environment has no resolvable home directory.
fn home_not_found() -> OpError {
    OpError::new(
        ErrorCode::ConfigError,
        "the user's home directory could not be determined ($HOME/USERPROFILE unset); \
         qsh service needs it to place the unit file",
    )
    .with_retryable(false)
}

/// `INTERNAL` for a Task Scheduler `install` that cannot name the current
/// user: the definition's trigger and principal need the SID, and nothing has
/// been written yet.
fn user_sid_unavailable() -> OpError {
    OpError::new(
        ErrorCode::Internal,
        "the current user's SID could not be read, which the task definition needs; \
         nothing was written",
    )
    .with_retryable(false)
}

/// The Task Scheduler reads of this build target: the COM reader on Windows,
/// one that reads nothing elsewhere (where no Task Scheduler row is ever
/// resolved).
#[cfg(windows)]
static PLATFORM_TASK_SCHEDULER: ComTaskScheduler = ComTaskScheduler;
#[cfg(not(windows))]
static PLATFORM_TASK_SCHEDULER: UnreadableTaskScheduler = UnreadableTaskScheduler;

/// Everything a flag-driven manager step needs besides the unit file, so
/// the `*_with_home` twins run the launchd, systemd and Task Scheduler rows
/// on any build target with a recording [`ManagerRunner`] and fake COM reads
/// (ADR-0032 decision 10).
pub(crate) struct ServiceHost<'a> {
    /// The service manager that owns the unit.
    pub(crate) manager: Manager,
    /// Where every manager call goes.
    pub(crate) runner: &'a dyn ManagerRunner,
    /// The effective uid the `gui/<uid>` domain is named after.
    pub(crate) euid: u32,
    /// The root `/Library/LaunchDaemons` hangs under: `/` in production, a
    /// tempdir in tests (the injection `crate::doctor::probe` uses).
    pub(crate) system_root: PathBuf,
    /// Whether this is WSL, which only changes the wording of a missing or
    /// failing `systemctl`.
    pub(crate) wsl: bool,
    /// The string form of the current user's SID, which the Task Scheduler
    /// definition names as its trigger user and principal. `None` on every
    /// platform without one, and when the token could not be read, which
    /// makes a Task Scheduler `install` an `INTERNAL` error before anything is
    /// written.
    pub(crate) user_sid: Option<String>,
    /// Whether a registered task is running (the Task Scheduler row only).
    pub(crate) task_state: &'a dyn TaskStateQuery,
    /// Under which principal a task is registered (the Task Scheduler row
    /// only).
    pub(crate) task_reader: &'a dyn TaskDefinitionReader,
    /// The name the always-on recipes address: `$USER` on Linux and macOS
    /// (`loginctl enable-linger`, the daemon's `UserName`), `DOMAIN\user` on
    /// Windows (`schtasks /RU`). `None` when it could not be read.
    pub(crate) account: Option<String>,
    /// The platform key store standing in for the OS credential store when
    /// `--always-on` moves the key (the seam of
    /// [`Ops::identity_move_key_with_platform_store`]); `None` in production.
    pub(crate) platform_store: Option<&'a dyn crate::identity::KeyStore>,
}

/// The flags of `qsh service install` (`docs/CLI.md` §6.18). `Default` is the
/// flagless command: activate, change nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstallOptions {
    /// Load and start the unit (the default; `--no-activate` clears it).
    pub activate: bool,
    /// `--to`: written to `[serve].to` before the mode is inferred.
    pub to: Option<String>,
    /// `--bind`: written to `[serve].bind`.
    pub bind: Option<String>,
    /// `--name`: written to `[reverse].offered_name`.
    pub name: Option<String>,
    /// `--always-on` (ADR-0051 decision 11).
    pub always_on: bool,
    /// `--move-key`: answers the key-store question with yes.
    pub move_key: bool,
}

impl Default for ServiceInstallOptions {
    fn default() -> Self {
        Self {
            activate: true,
            to: None,
            bind: None,
            name: None,
            always_on: false,
            move_key: false,
        }
    }
}

impl<'a> ServiceHost<'a> {
    /// The first step of every public op: the manager for this build target
    /// (`UNSUPPORTED` elsewhere) plus the real uid, root and WSL state.
    pub(crate) fn resolve(runner: &'a dyn ManagerRunner) -> Result<Self, OpError> {
        Ok(Self {
            manager: resolve_manager()?,
            runner,
            euid: current_euid(),
            system_root: PathBuf::from("/"),
            wsl: running_under_wsl(),
            user_sid: current_user_sid(),
            task_state: &PLATFORM_TASK_SCHEDULER,
            task_reader: &PLATFORM_TASK_SCHEDULER,
            account: current_account(),
            platform_store: None,
        })
    }

    /// Whether the task of `mode` is registered under a stored-password
    /// principal, which is the always-on form a person installed
    /// (ADR-0032 decision 18; `docs/deploy/service.md`, Windows). The
    /// scheduler is asked, not the task file, because the task may have been
    /// registered from a file qsh did not write. A scheduler that cannot be
    /// read ends the step: qsh does not guess whether a replacement would
    /// overwrite that task.
    fn always_on_task_present(&self, step: &'static str, mode: &str) -> Result<bool, OpError> {
        let name = crate::doctor::probe::windows_task_name(mode);
        let logon = self
            .task_reader
            .logon_type(&name)
            .map_err(|err| scheduler_read_error(step, err))?;
        Ok(logon == Some(TaskLogonType::Password))
    }

    /// Whether the task of `mode` is running, from the COM state value
    /// (ADR-0032 decisions 3 and 6).
    fn task_running(&self, step: &'static str, mode: &str) -> Result<bool, OpError> {
        let name = crate::doctor::probe::windows_task_name(mode);
        self.task_state
            .is_running(&name)
            .map_err(|err| scheduler_read_error(step, err))
    }

    /// The human-installed always-on form of `mode` on macOS: a LaunchDaemon
    /// plist (ADR-0032 decisions 13, 18). qsh only looks for the file.
    fn launchdaemon_present(&self, mode: &str) -> bool {
        self.manager == Manager::Launchd
            && crate::doctor::probe::macos_launchdaemon_path(&self.system_root, mode).exists()
    }

    /// One manager call that must run to the end, mapped to the ADR-0032
    /// decision 8 vocabulary when it cannot.
    fn call(&self, step: &'static str, argv: &[String]) -> Result<ManagerOutput, OpError> {
        self.runner
            .run(argv, MANAGER_CALL_DEADLINE)
            .map_err(|err| self.run_error(step, argv, err))
    }

    /// A query whose exit code is the answer: `true` for exit 0, `false` for
    /// any other exit (ADR-0032 decisions 3, 6).
    fn probe(&self, step: &'static str, argv: &[String]) -> Result<bool, OpError> {
        Ok(self.call(step, argv)?.success())
    }

    /// A change that must exit 0.
    fn run_ok(&self, step: &'static str, argv: &[String]) -> Result<(), OpError> {
        let output = self.call(step, argv)?;
        if output.success() {
            Ok(())
        } else {
            Err(self.nonzero_error(step, argv, &output))
        }
    }

    fn program(argv: &[String]) -> &str {
        argv.first().map_or("the service manager", String::as_str)
    }

    fn run_error(&self, step: &'static str, argv: &[String], err: RunError) -> OpError {
        let program = Self::program(argv);
        match err {
            RunError::NotFound => {
                let hint = if self.wsl && self.manager == Manager::Systemd {
                    "under WSL, systemd must run as PID 1: set `systemd=true` under `[boot]` in \
                     /etc/wsl.conf and restart the distro (docs/deploy/service.md, WSL)"
                } else {
                    "docs/deploy/service.md has the recipe to run by hand"
                };
                OpError::new(
                    ErrorCode::Unsupported,
                    format!(
                        "`{program}` was not found, so the unit was not {}; {hint}",
                        step_past(step)
                    ),
                )
                .with_retryable(false)
                .with_details(serde_json::json!({ "step": step }))
            }
            RunError::TimedOut => OpError::new(
                ErrorCode::Timeout,
                format!(
                    "`{program}` did not finish within {} seconds; the call was stopped ({})",
                    MANAGER_CALL_DEADLINE.as_secs(),
                    step_effect(step)
                ),
            )
            .with_details(serde_json::json!({ "step": step })),
            RunError::Io(detail) => OpError::new(
                ErrorCode::Internal,
                format!(
                    "`{program}` could not be run ({detail}); {}",
                    step_effect(step)
                ),
            )
            .with_details(serde_json::json!({ "step": step })),
        }
    }

    fn nonzero_error(
        &self,
        step: &'static str,
        argv: &[String],
        output: &ManagerOutput,
    ) -> OpError {
        let program = Self::program(argv);
        let exit = output.exit_code.map_or_else(
            || "ended by a signal".to_string(),
            |code| format!("exit {code}"),
        );
        let line = manager::cap_bytes(&output.stderr_first_line, MANAGER_STDERR_CAP);
        let mut message = format!("`{program}` failed ({exit})");
        if !line.is_empty() {
            message.push_str(": ");
            message.push_str(line);
        }
        message.push_str("; ");
        message.push_str(step_effect(step));
        match (self.manager, step) {
            (Manager::TaskScheduler, "activate") if argv.get(1).is_some_and(|v| v == "/Run") => {
                message.push_str(
                    ". A task registered with an InteractiveToken principal starts only inside \
                     a logged-on interactive session, which a session reached over ssh alone \
                     does not have; qsh registers it under no other principal. \
                     docs/deploy/service.md (Task Scheduler) has the details",
                );
            }
            (Manager::Launchd, "activate") => message.push_str(&format!(
                ". The `gui/{}` domain exists only inside a logged-in GUI session; \
                 docs/deploy/service.md (launchd) has the details",
                self.euid
            )),
            (Manager::Systemd, _) if self.wsl => message.push_str(
                ". Under WSL, systemd must run as PID 1: set `systemd=true` under `[boot]` in \
                 /etc/wsl.conf (docs/deploy/service.md, WSL)",
            ),
            _ => {}
        }
        OpError::new(ErrorCode::Internal, message)
            .with_details(serde_json::json!({ "step": step, "exit_code": output.exit_code }))
    }

    /// `install --activate`, after the unit file is written (ADR-0032
    /// decisions 2, 4, 18). Never restarts a unit that is already up.
    fn activate(&self, mode: &str, unit_path: &Path) -> Result<ServiceActivation, OpError> {
        let uid = self.euid.to_string();
        match self.manager {
            Manager::Launchd => {
                if self.launchdaemon_present(mode) {
                    return Ok(ServiceActivation::AlwaysOnPresent);
                }
                if self.probe("activate", &launchd_print_argv(&uid, mode))? {
                    return Ok(ServiceActivation::AlreadyActive);
                }
                let unit = unit_path.display().to_string();
                self.run_ok("activate", &launchd_bootstrap_argv(&uid, &unit))?;
                Ok(ServiceActivation::Started)
            }
            Manager::Systemd => {
                let was_active = self.probe("activate", &systemd_is_active_argv(mode))?;
                self.run_ok("activate", &systemd_daemon_reload_argv())?;
                self.run_ok("activate", &systemd_enable_now_argv(mode))?;
                Ok(if was_active {
                    ServiceActivation::AlreadyActive
                } else {
                    ServiceActivation::Started
                })
            }
            Manager::TaskScheduler => {
                // A person's always-on task keeps its definition: `/Create /F`
                // would replace it with the default logon-scoped one.
                if self.always_on_task_present("activate", mode)? {
                    return Ok(ServiceActivation::AlwaysOnPresent);
                }
                // The scheduler keeps the definition inside itself, so the
                // new binary path reaches it only through `/Create /F`, which
                // is called whether or not the task runs. Measured: it leaves
                // a running instance alone, so the path applies at the next
                // start and only `/Run` is skipped.
                let running = self.task_running("activate", mode)?;
                let file = unit_path.display().to_string();
                self.run_ok("activate", &schtasks_create_argv(mode, &file))?;
                if running {
                    return Ok(ServiceActivation::AlreadyActive);
                }
                self.run_ok("activate", &schtasks_run_argv(mode))?;
                Ok(ServiceActivation::Started)
            }
        }
    }

    /// `uninstall --deactivate`, before the unit file is removed (ADR-0032
    /// decisions 5, 18). Judged by registration, not by whether the unit is
    /// running.
    fn deactivate(&self, mode: &str, unit_path: &Path) -> Result<ServiceDeactivation, OpError> {
        let uid = self.euid.to_string();
        match self.manager {
            Manager::Launchd => {
                let always_on = self.launchdaemon_present(mode);
                let registered = self.probe("deactivate", &launchd_print_argv(&uid, mode))?;
                if registered {
                    self.run_ok("deactivate", &launchd_bootout_argv(&uid, mode))?;
                }
                Ok(if always_on {
                    ServiceDeactivation::AlwaysOnPresent
                } else if registered {
                    ServiceDeactivation::Stopped
                } else {
                    ServiceDeactivation::NotActive
                })
            }
            Manager::Systemd => {
                if unit_path.exists() {
                    self.run_ok("deactivate", &systemd_disable_now_argv(mode))?;
                    Ok(ServiceDeactivation::Stopped)
                } else {
                    Ok(ServiceDeactivation::NotActive)
                }
            }
            Manager::TaskScheduler => {
                // The always-on task is the form a person installed, so no
                // `/End` or `/Delete` reaches it; the file is still removed.
                if self.always_on_task_present("deactivate", mode)? {
                    return Ok(ServiceDeactivation::AlwaysOnPresent);
                }
                // Registration decides, not the run state (decision 5): a
                // task that exists but is stopped is still unregistered here.
                if !self.probe("deactivate", &schtasks_query_argv(mode))? {
                    return Ok(ServiceDeactivation::NotActive);
                }
                if self.task_running("deactivate", mode)? {
                    self.run_ok("deactivate", &schtasks_end_argv(mode))?;
                }
                self.run_ok("deactivate", &schtasks_delete_argv(mode))?;
                Ok(ServiceDeactivation::Stopped)
            }
        }
    }

    /// `status --live` (ADR-0032 decisions 6, 14, 18): one exit code. No
    /// manager call when there is no unit file to ask about.
    fn live(&self, mode: &str, installed: bool) -> Result<bool, OpError> {
        let uid = self.euid.to_string();
        match self.manager {
            Manager::Launchd => {
                if self.launchdaemon_present(mode) {
                    // `launchctl print system/…` answers without root
                    // (ADR-0032 decision 18, third item, verified on macOS
                    // 27.0.1): exit 0 is a loaded service, running or not,
                    // so the answer is "loaded", and exit 113 is "not
                    // loaded". Any other status is ambiguous and never reads
                    // as not running.
                    let argv = launchd_print_system_argv(mode);
                    let output = self.call("live", &argv)?;
                    return match output.exit_code {
                        Some(0) => Ok(true),
                        Some(LAUNCHD_SERVICE_NOT_FOUND) => Ok(false),
                        _ => {
                            let command = argv.join(" ");
                            let exit = output.exit_code.map_or_else(
                                || "ended by a signal".to_string(),
                                |code| format!("exit {code}"),
                            );
                            Err(OpError::new(
                                ErrorCode::Internal,
                                format!(
                                    "the always-on LaunchDaemon form of the {mode} unit is \
                                     installed, and `{command}` gave no clear answer ({exit}); \
                                     run `sudo {command}` to check its run state"
                                ),
                            )
                            .with_retryable(false)
                            .with_details(serde_json::json!({
                                "step": "live",
                                "exit_code": output.exit_code
                            })))
                        }
                    };
                }
                if !installed {
                    return Ok(false);
                }
                self.probe("live", &launchd_print_argv(&uid, mode))
            }
            Manager::Systemd => {
                if !installed {
                    return Ok(false);
                }
                self.probe("live", &systemd_is_active_argv(mode))
            }
            Manager::TaskScheduler => {
                // The task name is the same for the default task and the
                // always-on one, so the COM state is the answer for both
                // (ADR-0032 decision 18).
                if !installed {
                    return Ok(false);
                }
                self.task_running("live", mode)
            }
        }
    }
}

/// A failed Task Scheduler COM read, in the vocabulary of decision 8:
/// `INTERNAL` with the step, and what the failure left behind.
fn scheduler_read_error(step: &'static str, err: OpError) -> OpError {
    OpError::new(
        ErrorCode::Internal,
        format!("{}; {}", err.message, step_effect(step)),
    )
    .with_retryable(false)
    .with_details(serde_json::json!({ "step": step }))
}

/// What a failed step leaves, for the tail of an error message.
fn step_effect(step: &str) -> &'static str {
    match step {
        "deactivate" => "the unit file was kept; run `qsh service uninstall --deactivate` again",
        "live" => "the unit's run state was not read",
        "always_on" => {
            "the unit file is written; run `qsh service install --always-on` again \
             (on macOS the per-user unit may be released already)"
        }
        "always_off" => "the unit file was kept; run `qsh service uninstall --always-on` again",
        _ => "the unit file is written; run `qsh service install` again",
    }
}

/// The past participle of a step, for "the unit was not …".
fn step_past(step: &str) -> &'static str {
    match step {
        "deactivate" => "released",
        "live" => "queried",
        "always_on" => "made always-on",
        "always_off" => "made on-demand again",
        _ => "activated",
    }
}

/// This process's effective user id, the `<uid>` of a `gui/<uid>` domain
/// (ADR-0032 decision 3). Windows has no uid; its Task Scheduler row never
/// reads this value.
fn current_euid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid(2)` takes no arguments, touches no memory, and
        // cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// The current user's SID as a string, for the Task Scheduler definition.
/// Windows only; every other platform has none.
fn current_user_sid() -> Option<String> {
    #[cfg(windows)]
    {
        let sid = crate::fsutil::dacl::token_user_sid().ok()?;
        crate::fsutil::dacl::sid_to_string(&sid).ok()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The account the always-on recipes name (`ServiceHost::account`).
fn current_account() -> Option<String> {
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").ok().filter(|v| !v.is_empty())?;
        match std::env::var("USERDOMAIN").ok().filter(|v| !v.is_empty()) {
            Some(domain) => Some(format!("{domain}\\{user}")),
            None => Some(user),
        }
    }
    #[cfg(not(windows))]
    {
        std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("LOGNAME").ok())
            .filter(|v| !v.is_empty())
    }
}

/// Whether this is a WSL distro: only the wording of a `systemctl` failure
/// depends on it (ADR-0032 decision 8).
fn running_under_wsl() -> bool {
    std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .is_ok_and(|release| release.to_ascii_lowercase().contains("microsoft"))
}

impl Ops {
    /// `service.install` — write (or rewrite) the unit (on Windows the task
    /// definition file, UTF-16 under `<config_dir>\service`) for this machine's
    /// inferred run mode, creating its parent directory (and, on macOS,
    /// `~/Library/Logs/qsh`) if absent, via a plain `create_dir_all` — never
    /// changing the mode of a directory that already exists, since qsh does
    /// not own `~/Library/LaunchAgents`/`~/.config/systemd/user` (they hold
    /// every other application's units too) and so has no standing to
    /// re-permission them (documented at `docs/CLI.md` §6.18 and
    /// `docs/deploy/service.md`). The unit file itself is still written
    /// 0600 via `crate::config::write_private_file`. Always re-renders and
    /// rewrites: `created` reports only whether the path was absent
    /// *before* this call, so a repeated `install` is a repair path for a
    /// hand-edited unit rather than a no-op.
    ///
    /// `activate` (the default since ADR-0051 decision 11; `--no-activate`
    /// clears it) additionally asks the service manager to load and start the
    /// unit, as the last step. A unit that is already up is not restarted
    /// (ADR-0032 decision 4), and a human-installed always-on form is left
    /// alone (decision 18).
    ///
    /// `to`, `bind` and `name` are written to `config.toml` through
    /// [`Ops::config_set`] (lock and validation included) before the mode is
    /// inferred; they never reach the unit's argv. `always_on` runs the
    /// recipe of `docs/deploy/service.md` for this OS and, when the key is in
    /// a `platform` store that does not open outside a login session, first
    /// asks `prompter` (or takes `move_key`) whether to move it.
    pub fn service_install(
        &self,
        options: &ServiceInstallOptions,
        prompter: &dyn Prompter,
    ) -> Result<ServiceInstallData, OpError> {
        let runner = CommandRunner::system();
        let host = ServiceHost::resolve(&runner)?;
        self.service_install_with_options(&host, crate::config::home_dir(), options, prompter)
    }

    /// `service.uninstall` — remove the unit for this machine's inferred
    /// run mode. `NotFound` is not an error (`removed: false`, the
    /// `trust.remove` precedent); a unit `qsh` did not write is removed
    /// all the same, since the contract is the path, not provenance.
    ///
    /// `deactivate` (`--deactivate`, ADR-0032 decision 5) first releases the
    /// unit from the service manager when it is registered there, and keeps
    /// the unit file if that fails. Without it a running unit stays up.
    /// `always_on` (`--always-on`, ADR-0051 decision 11) reverses what
    /// `install --always-on` did, before anything else.
    pub fn service_uninstall(
        &self,
        deactivate: bool,
        always_on: bool,
    ) -> Result<ServiceUninstallData, OpError> {
        let runner = CommandRunner::system();
        let host = ServiceHost::resolve(&runner)?;
        self.service_uninstall_with_options(&host, crate::config::home_dir(), deactivate, always_on)
    }

    /// `service.status` — whether the unit for this machine's inferred run
    /// mode exists. Presence only unless `live` (`--live`, ADR-0032 decision
    /// 6) is set, which adds one exit-code read of the service manager.
    pub fn service_status(&self, live: bool) -> Result<ServiceStatusData, OpError> {
        let runner = CommandRunner::system();
        let host = ServiceHost::resolve(&runner)?;
        self.service_status_with_home(&host, crate::config::home_dir(), live)
    }

    /// `qsh setup`'s unit-file step: `install` without a flag, so the
    /// manager is never called (ADR-0032 decision 1).
    pub(crate) fn service_install_for_setup(
        &self,
        home: Option<PathBuf>,
    ) -> Result<ServiceInstallData, OpError> {
        let runner = CommandRunner::system();
        let host = ServiceHost::resolve(&runner)?;
        self.service_install_with_home(&host, home, false)
    }

    /// `qsh setup`'s presence check: `status` without a flag.
    pub(crate) fn service_status_for_setup(
        &self,
        home: Option<PathBuf>,
    ) -> Result<ServiceStatusData, OpError> {
        let runner = CommandRunner::system();
        let host = ServiceHost::resolve(&runner)?;
        self.service_status_with_home(&host, home, false)
    }

    /// The fail-closed audit write shared by `install`/`uninstall`
    /// (`status` writes none — a read has nothing to hold accountable):
    /// one [`AuditRecord::local_op`], `principal` the literal `"-"` (no
    /// peer is involved), `resource` the mode token — not the unit path,
    /// which would carry the home directory and user name into
    /// `audit.log` for no gain. Injected sink if [`Ops::with_audit_sink`]
    /// set one, else a fresh [`FileAuditSink`] on the daemon's own
    /// `audit.log` path, mirroring `trust_rename`'s identical shape. A
    /// failed write is `INTERNAL`/`retryable: true`, and the caller must
    /// not mutate the filesystem afterward. An activation or deactivation
    /// is part of the same op and writes no second record (ADR-0032
    /// decision 9).
    fn record_service_audit(
        &self,
        action: &'static str,
        mode: &str,
        nothing_note: &str,
    ) -> Result<(), OpError> {
        let record = AuditRecord::local_op(action, "-".to_string(), mode.to_string());
        let sink: Arc<dyn AuditSink> = match &self.audit {
            Some(sink) => Arc::clone(sink),
            None => Arc::new(FileAuditSink::new(
                Config::load(&self.paths)?.audit.path(&self.paths),
            )),
        };
        sink.record(&record).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("audit record could not be written; {nothing_note}: {err}"),
            )
            .with_retryable(true)
        })
    }

    /// Steps 2-10 of `service_install`, parameterized on `home` and on the
    /// [`ServiceHost`] so `tests.rs` can drive the whole op — config load,
    /// the two-key conflict, mode inference, path building, rendering, the
    /// fail-closed audit record, the write and the manager calls — against
    /// an explicit tempdir and a recording runner without ever touching
    /// `crate::config::home_dir()`'s real value or a real service manager
    /// (module doc). `home: None` is exactly what a real environment with
    /// no resolvable home directory looks like.
    pub(crate) fn service_install_with_home(
        &self,
        host: &ServiceHost<'_>,
        home: Option<PathBuf>,
        activate: bool,
    ) -> Result<ServiceInstallData, OpError> {
        let options = ServiceInstallOptions {
            activate,
            ..ServiceInstallOptions::default()
        };
        self.service_install_with_options(host, home, &options, &NoPrompter)
    }

    /// [`Self::service_install_with_home`] with every flag of
    /// `qsh service install`.
    pub(crate) fn service_install_with_options(
        &self,
        host: &ServiceHost<'_>,
        home: Option<PathBuf>,
        options: &ServiceInstallOptions,
        prompter: &dyn Prompter,
    ) -> Result<ServiceInstallData, OpError> {
        let manager = host.manager;
        // Everything that can refuse comes before anything is written: a
        // non-elevated Windows console, and a key-store question nobody can
        // answer.
        let mut move_key = false;
        if options.always_on {
            host.require_elevated("install")?;
            move_key = self.decide_key_move(manager, options.move_key, prompter)?;
        }
        for (key, value) in [
            ("serve.to", &options.to),
            ("serve.bind", &options.bind),
            ("reverse.offered_name", &options.name),
        ] {
            if let Some(value) = value {
                self.config_set(ConfigSetReq {
                    key: key.to_string(),
                    value: value.clone(),
                })?;
            }
        }
        let manager = host.manager;
        let config = Config::load(&self.paths)?;
        let controller = crate::serve::config_outbound_target(&config)?;
        let mode = super::doctor::infer_run_mode(&config);
        let home = resolve_home(manager, home)?;
        let exe = resolve_current_exe()?;
        let path = unit_path(manager, &home, &self.paths.config_dir, mode);
        let controller = controller.as_deref().unwrap_or("");
        let bytes = match manager {
            Manager::Launchd => render_launchd_plist(
                mode,
                &exe.display().to_string(),
                &home.display().to_string(),
                controller,
            )
            .into_bytes(),
            Manager::Systemd => {
                render_systemd_unit(mode, &exe.display().to_string(), controller).into_bytes()
            }
            Manager::TaskScheduler => {
                let sid = host.user_sid.as_deref().ok_or_else(user_sid_unavailable)?;
                encode_task_file(&render_windows_task(
                    mode,
                    &exe.display().to_string(),
                    controller,
                    sid,
                ))
            }
        };

        self.record_service_audit(ServiceInstallOp::COMMAND, mode, "no unit was written")?;

        if let Some(parent) = path.parent() {
            if manager == Manager::TaskScheduler {
                // The task definition directory is qsh's own, so it is
                // private; the launchd and systemd directories hold other
                // applications' units too and keep their mode.
                crate::config::ensure_private_dir(parent)?;
            } else {
                std::fs::create_dir_all(parent).map_err(|err| {
                    crate::config::config_io_error(parent, "create directory", &err)
                })?;
            }
        }
        if manager == Manager::Launchd {
            let logs_dir = home.join("Library").join("Logs").join("qsh");
            std::fs::create_dir_all(&logs_dir).map_err(|err| {
                crate::config::config_io_error(&logs_dir, "create directory", &err)
            })?;
        }
        let created = !path.exists();
        crate::config::write_private_file(&path, &bytes)?;

        // The last step, and only on request: a failed write above has
        // already returned, so the manager is never asked to load a unit
        // that was not written (ADR-0032 decision 2).
        let mut activation = None;
        let mut always_on = None;
        if options.always_on {
            // The key moves last before the recipe, so a failure above it
            // leaves the key where it was.
            let key_moved = if move_key {
                self.move_key_to_file(host)?
            } else {
                false
            };
            let plan = always_on::AlwaysOnPlan {
                mode,
                exe: &exe,
                home: &home,
                config_dir: &self.paths.config_dir,
                controller,
                unit_path: &path,
            };
            let outcome = host.enable_always_on(&plan)?;
            activation = Some(outcome.activation);
            always_on = Some(ServiceAlwaysOn {
                state: outcome.state,
                key_moved,
                firewall_rule: outcome.firewall_rule,
            });
        } else if options.activate {
            activation = Some(host.activate(mode, &path)?);
        }

        Ok(ServiceInstallData {
            manager: manager.as_str().to_string(),
            mode: mode.to_string(),
            path: path.display().to_string(),
            created,
            activation,
            always_on,
        })
    }

    /// Steps 2-10 of `service_uninstall` — see
    /// [`Self::service_install_with_home`]'s doc for why `home` and `host`
    /// are parameters here.
    #[cfg(test)]
    pub(crate) fn service_uninstall_with_home(
        &self,
        host: &ServiceHost<'_>,
        home: Option<PathBuf>,
        deactivate: bool,
    ) -> Result<ServiceUninstallData, OpError> {
        self.service_uninstall_with_options(host, home, deactivate, false)
    }

    /// [`Self::service_uninstall_with_home`] with `--always-on` as well.
    pub(crate) fn service_uninstall_with_options(
        &self,
        host: &ServiceHost<'_>,
        home: Option<PathBuf>,
        deactivate: bool,
        always_on: bool,
    ) -> Result<ServiceUninstallData, OpError> {
        if always_on {
            host.require_elevated("uninstall")?;
        }
        let manager = host.manager;
        let config = Config::load(&self.paths)?;
        let _controller = crate::serve::config_outbound_target(&config)?;
        let mode = super::doctor::infer_run_mode(&config);
        let home = resolve_home(manager, home)?;
        let path = unit_path(manager, &home, &self.paths.config_dir, mode);

        self.record_service_audit(ServiceUninstallOp::COMMAND, mode, "no unit was removed")?;

        // Release first, delete second: a unit file removed while the
        // manager still has it registered would leave an orphan that comes
        // back at the next login with the old path (ADR-0032 decision 5). A
        // failed release returns here and keeps the file.
        // The always-on form goes first: on macOS and Windows the per-user
        // release below then sees what is left, not the form it would leave
        // alone.
        let always_off = if always_on {
            let (state, firewall_rule) = host.disable_always_on(mode, &path)?;
            Some(ServiceAlwaysOn {
                state,
                key_moved: false,
                firewall_rule,
            })
        } else {
            None
        };
        let deactivation = if deactivate {
            Some(host.deactivate(mode, &path)?)
        } else {
            None
        };

        let removed = match std::fs::remove_file(&path) {
            Ok(()) => true,
            Err(err) if err.kind() == io::ErrorKind::NotFound => false,
            Err(err) => return Err(crate::config::config_io_error(&path, "remove", &err)),
        };

        Ok(ServiceUninstallData {
            manager: manager.as_str().to_string(),
            mode: mode.to_string(),
            path: path.display().to_string(),
            removed,
            deactivation,
            always_on: always_off,
        })
    }

    /// Steps 2-10 of `service_status` — see
    /// [`Self::service_install_with_home`]'s doc for why `home` and `host`
    /// are parameters here.
    pub(crate) fn service_status_with_home(
        &self,
        host: &ServiceHost<'_>,
        home: Option<PathBuf>,
        live: bool,
    ) -> Result<ServiceStatusData, OpError> {
        let manager = host.manager;
        let config = Config::load(&self.paths)?;
        let _controller = crate::serve::config_outbound_target(&config)?;
        let mode = super::doctor::infer_run_mode(&config);
        let home = resolve_home(manager, home)?;
        let path = unit_path(manager, &home, &self.paths.config_dir, mode);
        let installed = path.exists();
        let active = if live {
            Some(host.live(mode, installed)?)
        } else {
            None
        };

        Ok(ServiceStatusData {
            manager: manager.as_str().to_string(),
            mode: mode.to_string(),
            path: path.display().to_string(),
            installed,
            active,
        })
    }
}

#[cfg(test)]
mod tests;
