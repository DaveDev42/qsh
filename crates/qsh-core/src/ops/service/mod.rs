//! `service.*` operations — `qsh service install|uninstall|status`
//! (`docs/CLI.md` §6.18). Writes, removes and reports the launchd (macOS)
//! or systemd (Linux) user unit for this machine's inferred run mode.
//! `UNSUPPORTED` on every other platform, before anything is read or
//! written.
//!
//! Without a flag the ops never touch the service manager. With
//! `--activate`, `--deactivate` or `--live` (ADR-0032 decision 1) they make
//! the calls of the decision 3 table through a [`ManagerRunner`], and read
//! only exit codes.
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

mod manager;

pub use manager::{
    CommandRunner, MANAGER_CALL_DEADLINE, MANAGER_STDERR_CAP, ManagerClock, ManagerOutput,
    ManagerRunner, RunError, SystemManagerClock, TaskStateQuery, launchd_bootout_argv,
    launchd_bootstrap_argv, launchd_print_argv, launchd_print_system_argv,
    systemd_daemon_reload_argv, systemd_disable_now_argv, systemd_enable_now_argv,
    systemd_is_active_argv,
};

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use qsh_proto::{
    ErrorCode, ServiceActivation, ServiceDeactivation, ServiceInstallData, ServiceStatusData,
    ServiceUninstallData,
};

use crate::audit::{AuditRecord, AuditSink, FileAuditSink};
use crate::config::Config;

use super::{OpError, Operation, Ops, ServiceInstallOp, ServiceUninstallOp};

/// `qsh service install|uninstall|status` (`docs/CLI.md` §6.18) manage
/// user service units for launchd (macOS) and systemd (Linux) only; unit
/// installation on this platform is P1 and not implemented. Nothing was
/// written. `docs/deploy/service.md` has a hand-written unit for each
/// supported manager.
///
/// One constant for all three ops and every non-macOS/Linux target
/// (the "P1 예정" convention of `docs/ROADMAP.md` §3's TCP/TLS fallback row).
/// Compiled on every target, quoted verbatim in `docs/CLI.md` §6.18.
pub const SERVICE_UNSUPPORTED_PLATFORM: &str = "`qsh service` manages user service units for launchd (macOS) and systemd (Linux) only; unit installation on this platform is P1 and not implemented. Nothing was written. `docs/deploy/service.md` has a hand-written unit for each supported manager.";

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
}

impl Manager {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Manager::Launchd => "launchd",
            Manager::Systemd => "systemd",
        }
    }
}

/// Step 1 of every op: the manager for this compile target, from
/// `cfg!(target_os = …)` alone. `Err(UNSUPPORTED)` on every other target
/// (Windows included) before anything is read or written — no probing for
/// `systemctl`/`launchctl`, ever.
fn resolve_manager() -> Result<Manager, OpError> {
    if cfg!(target_os = "macos") {
        Ok(Manager::Launchd)
    } else if cfg!(target_os = "linux") {
        Ok(Manager::Systemd)
    } else {
        Err(
            OpError::new(ErrorCode::Unsupported, SERVICE_UNSUPPORTED_PLATFORM)
                .with_retryable(false),
        )
    }
}

/// Step 6: the unit path for `manager`/`mode`, via the de-`cfg`'d
/// `crate::doctor::probe` builders — never a third, hand-rolled join.
fn unit_path(manager: Manager, home: &Path, mode: &str) -> PathBuf {
    match manager {
        Manager::Launchd => crate::doctor::probe::macos_launchagent_path(home, mode),
        Manager::Systemd => crate::doctor::probe::linux_systemd_user_unit_path(home, mode),
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

/// Everything a flag-driven manager step needs besides the unit file, so
/// the `*_with_home` twins run the launchd and systemd rows on any build
/// target with a recording [`ManagerRunner`] (ADR-0032 decision 10).
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
        })
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
        }
    }

    /// `status --live` (ADR-0032 decisions 6, 14, 18): one exit code. No
    /// manager call when there is no unit file to ask about.
    fn live(&self, mode: &str, installed: bool) -> Result<bool, OpError> {
        let uid = self.euid.to_string();
        match self.manager {
            Manager::Launchd => {
                if self.launchdaemon_present(mode) {
                    // Whether `launchctl print system/…` answers without root
                    // is not verified (ADR-0032 decision 18, third item), and
                    // an exit code from a refused query would read as "not
                    // running". Until that is checked on a Mac, the run state
                    // of the always-on form is the person's to read.
                    let command = launchd_print_system_argv(mode).join(" ");
                    return Err(OpError::new(
                        ErrorCode::Internal,
                        format!(
                            "the always-on LaunchDaemon form of the {mode} unit is installed, and \
                             its run state is not read without root; run `sudo {command}` to check it"
                        ),
                    )
                    .with_retryable(false)
                    .with_details(serde_json::json!({ "step": "live" })));
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
        }
    }
}

/// What a failed step leaves, for the tail of an error message.
fn step_effect(step: &str) -> &'static str {
    match step {
        "deactivate" => "the unit file was kept; run `qsh service uninstall --deactivate` again",
        "live" => "the unit's run state was not read",
        _ => "the unit file is written; run `qsh service install --activate` again",
    }
}

/// The past participle of a step, for "the unit was not …".
fn step_past(step: &str) -> &'static str {
    match step {
        "deactivate" => "released",
        "live" => "queried",
        _ => "activated",
    }
}

/// This process's effective user id, the `<uid>` of a `gui/<uid>` domain
/// (ADR-0032 decision 3). Windows has no uid and ends in `UNSUPPORTED`
/// before this value could matter.
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

/// Whether this is a WSL distro: only the wording of a `systemctl` failure
/// depends on it (ADR-0032 decision 8).
fn running_under_wsl() -> bool {
    std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .is_ok_and(|release| release.to_ascii_lowercase().contains("microsoft"))
}

impl Ops {
    /// `service.install` — write (or rewrite) the unit for this machine's
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
    /// `activate` (`--activate`, ADR-0032 decisions 2 and 4) additionally
    /// asks the service manager to load and start the unit, as the last
    /// step. A unit that is already up is not restarted, and a human-
    /// installed always-on form is left alone (decision 18).
    pub fn service_install(&self, activate: bool) -> Result<ServiceInstallData, OpError> {
        let runner = CommandRunner::system();
        let host = ServiceHost::resolve(&runner)?;
        self.service_install_with_home(&host, crate::config::home_dir(), activate)
    }

    /// `service.uninstall` — remove the unit for this machine's inferred
    /// run mode. `NotFound` is not an error (`removed: false`, the
    /// `trust.remove` precedent); a unit `qsh` did not write is removed
    /// all the same, since the contract is the path, not provenance.
    ///
    /// `deactivate` (`--deactivate`, ADR-0032 decision 5) first releases the
    /// unit from the service manager when it is registered there, and keeps
    /// the unit file if that fails. Without it a running unit stays up.
    pub fn service_uninstall(&self, deactivate: bool) -> Result<ServiceUninstallData, OpError> {
        let runner = CommandRunner::system();
        let host = ServiceHost::resolve(&runner)?;
        self.service_uninstall_with_home(&host, crate::config::home_dir(), deactivate)
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
        let manager = host.manager;
        let config = Config::load(&self.paths)?;
        let controller = crate::serve::config_outbound_target(&config)?;
        let mode = super::doctor::infer_run_mode(&config);
        let home = home.ok_or_else(home_not_found)?;
        let exe = resolve_current_exe()?;
        let path = unit_path(manager, &home, mode);
        let text = match manager {
            Manager::Launchd => render_launchd_plist(
                mode,
                &exe.display().to_string(),
                &home.display().to_string(),
                controller.as_deref().unwrap_or(""),
            ),
            Manager::Systemd => render_systemd_unit(
                mode,
                &exe.display().to_string(),
                controller.as_deref().unwrap_or(""),
            ),
        };

        self.record_service_audit(ServiceInstallOp::COMMAND, mode, "no unit was written")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| crate::config::config_io_error(parent, "create directory", &err))?;
        }
        if manager == Manager::Launchd {
            let logs_dir = home.join("Library").join("Logs").join("qsh");
            std::fs::create_dir_all(&logs_dir).map_err(|err| {
                crate::config::config_io_error(&logs_dir, "create directory", &err)
            })?;
        }
        let created = !path.exists();
        crate::config::write_private_file(&path, text.as_bytes())?;

        // The last step, and only on request: a failed write above has
        // already returned, so the manager is never asked to load a unit
        // that was not written (ADR-0032 decision 2).
        let activation = if activate {
            Some(host.activate(mode, &path)?)
        } else {
            None
        };

        Ok(ServiceInstallData {
            manager: manager.as_str().to_string(),
            mode: mode.to_string(),
            path: path.display().to_string(),
            created,
            activation,
        })
    }

    /// Steps 2-10 of `service_uninstall` — see
    /// [`Self::service_install_with_home`]'s doc for why `home` and `host`
    /// are parameters here.
    pub(crate) fn service_uninstall_with_home(
        &self,
        host: &ServiceHost<'_>,
        home: Option<PathBuf>,
        deactivate: bool,
    ) -> Result<ServiceUninstallData, OpError> {
        let manager = host.manager;
        let config = Config::load(&self.paths)?;
        let _controller = crate::serve::config_outbound_target(&config)?;
        let mode = super::doctor::infer_run_mode(&config);
        let home = home.ok_or_else(home_not_found)?;
        let path = unit_path(manager, &home, mode);

        self.record_service_audit(ServiceUninstallOp::COMMAND, mode, "no unit was removed")?;

        // Release first, delete second: a unit file removed while the
        // manager still has it registered would leave an orphan that comes
        // back at the next login with the old path (ADR-0032 decision 5). A
        // failed release returns here and keeps the file.
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
        let home = home.ok_or_else(home_not_found)?;
        let path = unit_path(manager, &home, mode);
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
