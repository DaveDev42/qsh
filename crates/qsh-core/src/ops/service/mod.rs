//! `service.*` operations — `qsh service install|uninstall|status`
//! (`docs/CLI.md` §6.18). Writes, removes and reports the launchd (macOS)
//! or systemd (Linux) user unit for this machine's inferred run mode.
//! `UNSUPPORTED` on every other platform, before anything is read or
//! written.
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
//! 9. the filesystem mutation (or, for `status`, `path.exists()`).
//!
//! **The test seam.** `crate::config::home_dir` wraps
//! `std::env::home_dir()`, which cannot be mocked without an unsafe,
//! repo-wide-banned `std::env::set_var` (edition 2024, data races against
//! concurrent env readers). So the three public `Ops::service_*` methods
//! are the *only* callers of it; every step after "resolve home" lives in
//! a `pub(crate)` `*_with_home` twin parameterized on `home: Option<PathBuf>`,
//! which `tests.rs` drives with an explicit tempdir. This is the same
//! "detection reads real state, everything else is a pure function of its
//! inputs" split `crate::doctor::probe`'s own module doc describes — here
//! extended past the unit-text renderers to the whole op, because nothing
//! about `install`/`uninstall`/`status` besides "what is `$HOME`" is
//! actually untestable.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use qsh_proto::{ErrorCode, ServiceInstallData, ServiceStatusData, ServiceUninstallData};

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
/// (`docs/ROADMAP.md:153`'s "P1 예정" convention) — `crates/qsh-core/src/
/// reverse/listen.rs`'s `windows_unsupported()` is `#[cfg(not(unix))]`,
/// `pub(super)`-scoped to `reverse`, and has no "P1" in its wording, so it
/// is neither reachable here nor the right text to reuse (recorded finding,
/// `docs/CLI.md` §6.18). Compiled on every target, quoted verbatim there.
pub const SERVICE_UNSUPPORTED_PLATFORM: &str = "`qsh service` manages user service units for launchd (macOS) and systemd (Linux) only; unit installation on this platform is P1 and not implemented. Nothing was written. `docs/deploy/service.md` has a hand-written unit for each supported manager.";

/// The example binary path `docs/deploy/service.md`'s launchd fences show.
/// Production passes `std::env::current_exe()`; only the doc-contract test
/// (`crates/qsh-core/tests/service_docs.rs`) passes this.
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
    fn as_str(self) -> &'static str {
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
    pub fn service_install(&self) -> Result<ServiceInstallData, OpError> {
        self.service_install_with_home(crate::config::home_dir())
    }

    /// `service.uninstall` — remove the unit for this machine's inferred
    /// run mode. `NotFound` is not an error (`removed: false`, the
    /// `trust.remove` precedent); a unit `qsh` did not write is removed
    /// all the same, since the contract is the path, not provenance.
    pub fn service_uninstall(&self) -> Result<ServiceUninstallData, OpError> {
        self.service_uninstall_with_home(crate::config::home_dir())
    }

    /// `service.status` — whether the unit for this machine's inferred run
    /// mode exists. Presence only, never activation: `launchctl print`/
    /// `systemctl --user status` are an explicit non-goal.
    pub fn service_status(&self) -> Result<ServiceStatusData, OpError> {
        self.service_status_with_home(crate::config::home_dir())
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
    /// not mutate the filesystem afterward.
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

    /// Steps 2-9 of `service_install`, parameterized on `home` so
    /// `tests.rs` can drive the whole op — config load, the two-key
    /// conflict, mode inference, path building, rendering, the fail-closed
    /// audit record and the write itself — against an explicit tempdir
    /// without ever touching `crate::config::home_dir()`'s real value
    /// (module doc). `home: None` is exactly what a real environment with
    /// no resolvable home directory looks like.
    pub(crate) fn service_install_with_home(
        &self,
        home: Option<PathBuf>,
    ) -> Result<ServiceInstallData, OpError> {
        let manager = resolve_manager()?;
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

        Ok(ServiceInstallData {
            manager: manager.as_str().to_string(),
            mode: mode.to_string(),
            path: path.display().to_string(),
            created,
        })
    }

    /// Steps 2-9 of `service_uninstall` — see
    /// [`Self::service_install_with_home`]'s doc for why `home` is a
    /// parameter here.
    pub(crate) fn service_uninstall_with_home(
        &self,
        home: Option<PathBuf>,
    ) -> Result<ServiceUninstallData, OpError> {
        let manager = resolve_manager()?;
        let config = Config::load(&self.paths)?;
        let _controller = crate::serve::config_outbound_target(&config)?;
        let mode = super::doctor::infer_run_mode(&config);
        let home = home.ok_or_else(home_not_found)?;
        let path = unit_path(manager, &home, mode);

        self.record_service_audit(ServiceUninstallOp::COMMAND, mode, "no unit was removed")?;

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
        })
    }

    /// Steps 2-9 of `service_status` — see
    /// [`Self::service_install_with_home`]'s doc for why `home` is a
    /// parameter here.
    pub(crate) fn service_status_with_home(
        &self,
        home: Option<PathBuf>,
    ) -> Result<ServiceStatusData, OpError> {
        let manager = resolve_manager()?;
        let config = Config::load(&self.paths)?;
        let _controller = crate::serve::config_outbound_target(&config)?;
        let mode = super::doctor::infer_run_mode(&config);
        let home = home.ok_or_else(home_not_found)?;
        let path = unit_path(manager, &home, mode);
        let installed = path.exists();

        Ok(ServiceStatusData {
            manager: manager.as_str().to_string(),
            mode: mode.to_string(),
            path: path.display().to_string(),
            installed,
        })
    }
}

#[cfg(test)]
mod tests;
