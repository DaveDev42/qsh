//! `service install --always-on` and `service uninstall --always-on`
//! (ADR-0051 decision 11, which revises ADR-0032 decision 16): the
//! documented recipes of `docs/deploy/service.md` for running with nobody
//! logged in, run through the same [`ManagerRunner`] as every other manager
//! call.
//!
//! | Manager | Enable | Disable |
//! |---|---|---|
//! | systemd | `loginctl enable-linger $USER` | `loginctl disable-linger $USER` |
//! | launchd | the LaunchDaemon recipe under `sudo` | `sudo launchctl bootout`, `sudo rm` |
//! | Task Scheduler | the `Password` task, `schtasks /Create … /RU … /RP *`, and the inbound UDP firewall rule | `/End`, `/Delete /F`, the rule removed |
//!
//! The calls that ask the person something (`sudo`, polkit, `schtasks /RP *`)
//! go through [`ManagerRunner::run_interactive`]: the child owns the terminal
//! and qsh never reads a password. Every argv here is built by a function of
//! the closed mode set, a path and an account name, and
//! `crates/qsh-core/tests/it/service_docs.rs` compares them with the recipes
//! in the doc line by line, so the doc and the code cannot drift.

use std::path::Path;

use qsh_proto::{ErrorCode, KeyStoreKind, ServiceActivation, ServiceAlwaysOnState};

use super::manager::{
    INTERACTIVE_CALL_DEADLINE, launchd_bootout_argv, launchd_print_argv, launchd_print_system_argv,
    schtasks_delete_argv, schtasks_end_argv, schtasks_run_argv,
};
use super::*;
use crate::prompts::{self, Prompter};

// ---------------------------------------------------------------------
// argv builders — the recipes of docs/deploy/service.md.
// ---------------------------------------------------------------------

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

/// `loginctl enable-linger <user>`: systemd keeps the user's units running
/// without a session. polkit may ask.
pub fn loginctl_enable_linger_argv(user: &str) -> Vec<String> {
    argv(&["loginctl", "enable-linger", user])
}

/// `loginctl disable-linger <user>`.
pub fn loginctl_disable_linger_argv(user: &str) -> Vec<String> {
    argv(&["loginctl", "disable-linger", user])
}

/// The LaunchDaemon install steps after the LaunchAgent is released, in the
/// order of the recipe: copy the plist `source` to `daemon_path`, give it to
/// root, make it `644`, load it into the `system` domain.
pub fn launchdaemon_install_argvs(source: &str, daemon_path: &str) -> Vec<Vec<String>> {
    vec![
        argv(&["sudo", "cp", source, daemon_path]),
        argv(&["sudo", "chown", "root:wheel", daemon_path]),
        argv(&["sudo", "chmod", "644", daemon_path]),
        argv(&["sudo", "launchctl", "bootstrap", "system", daemon_path]),
    ]
}

/// The LaunchDaemon removal steps, in the order of the recipe.
pub fn launchdaemon_remove_argvs(mode: &str, daemon_path: &str) -> Vec<Vec<String>> {
    vec![
        argv(&[
            "sudo",
            "launchctl",
            "bootout",
            &format!("system/io.qsh.{}", closed_mode(mode)),
        ]),
        argv(&["sudo", "rm", daemon_path]),
    ]
}

/// Registers the always-on `Password` task from `task_file`, naming the
/// account and letting `schtasks` ask for its password (`/RP *`). qsh never
/// reads it.
pub fn schtasks_create_always_on_argv(mode: &str, task_file: &str, account: &str) -> Vec<String> {
    argv(&[
        "schtasks",
        "/Create",
        "/F",
        "/TN",
        &crate::doctor::probe::windows_task_name(closed_mode(mode)),
        "/XML",
        task_file,
        "/RU",
        account,
        "/RP",
        "*",
    ])
}

/// The firewall rule name of `mode`'s executable.
fn firewall_rule_name(mode: &str) -> String {
    format!("name=qsh-{}", closed_mode(mode))
}

/// Allows inbound UDP to the qsh executable at `exe` (needs an elevated
/// console).
pub fn netsh_firewall_add_argv(mode: &str, exe: &str) -> Vec<String> {
    let name = firewall_rule_name(mode);
    let program = format!("program={exe}");
    argv(&[
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &name,
        "dir=in",
        "action=allow",
        "protocol=UDP",
        &program,
    ])
}

/// Removes the rule [`netsh_firewall_add_argv`] made.
pub fn netsh_firewall_delete_argv(mode: &str) -> Vec<String> {
    let name = firewall_rule_name(mode);
    argv(&["netsh", "advfirewall", "firewall", "delete", "rule", &name])
}

/// The elevation probe of a Windows console: `fltmc` lists the filter
/// drivers and needs an elevated token, so an exit code of 0 means elevated.
/// Only the exit code is read.
pub fn windows_elevation_probe_argv() -> Vec<String> {
    argv(&["fltmc"])
}

fn closed_mode(mode: &str) -> &str {
    debug_assert!(
        matches!(mode, "serve" | "listen" | "reverse"),
        "manager argv takes only the closed mode set, got {mode:?}"
    );
    mode
}

/// The bytes the LaunchDaemon recipe puts in
/// `/Library/LaunchDaemons/io.qsh.<mode>.plist`: the LaunchAgent plist of the
/// same mode plus `UserName` (the account) and `GroupName` (`staff`), so the
/// daemon runs as the person and reads their `~/.config/qsh`.
pub fn render_launchdaemon_plist(
    mode: &str,
    exe: &str,
    home: &str,
    controller: &str,
    user: &str,
) -> String {
    let agent = render_launchd_plist(mode, exe, home, controller);
    let label = format!("  <string>io.qsh.{mode}</string>\n");
    let added = format!(
        "{label}  <key>UserName</key>\n  <string>{}</string>\n  <key>GroupName</key>\n  <string>staff</string>\n",
        xml_escape(user)
    );
    agent.replacen(&label, &added, 1)
}

// ---------------------------------------------------------------------
// The steps.
// ---------------------------------------------------------------------

/// What an enabled always-on form did, for the op to put in its data.
pub(super) struct EnableOutcome {
    pub(super) state: ServiceAlwaysOnState,
    pub(super) firewall_rule: bool,
    /// The activation to report. The Linux row reports its own, the others
    /// start the unit as part of the recipe.
    pub(super) activation: ServiceActivation,
}

/// Where the always-on files go and what they contain.
pub(super) struct AlwaysOnPlan<'a> {
    pub(super) mode: &'a str,
    pub(super) exe: &'a Path,
    pub(super) home: &'a Path,
    pub(super) config_dir: &'a Path,
    pub(super) controller: &'a str,
    pub(super) unit_path: &'a Path,
}

impl ServiceHost<'_> {
    /// One call that asks the person something itself, and must exit 0.
    fn interactive_ok(&self, step: &'static str, argv: &[String]) -> Result<(), OpError> {
        let output = self
            .runner
            .run_interactive(argv, INTERACTIVE_CALL_DEADLINE)
            .map_err(|err| self.run_error(step, argv, err))?;
        if output.success() {
            Ok(())
        } else {
            Err(self.nonzero_error(step, argv, &output))
        }
    }

    fn account_or_error(&self) -> Result<&str, OpError> {
        self.account.as_deref().ok_or_else(|| {
            OpError::new(
                ErrorCode::Internal,
                "the current account's name could not be determined ($USER/$USERNAME unset), \
                 which the always-on recipe names; nothing was changed",
            )
            .with_retryable(false)
            .with_details(serde_json::json!({ "step": "always_on" }))
        })
    }

    /// Whether this console is elevated, from the exit code of the probe. A
    /// console that cannot run the probe is not elevated.
    pub(super) fn is_elevated(&self) -> bool {
        self.runner
            .run(&windows_elevation_probe_argv(), MANAGER_CALL_DEADLINE)
            .is_ok_and(|output| output.success())
    }

    /// The Windows refusal of a non-elevated console, before anything is
    /// written. Other managers have no such check.
    pub(super) fn require_elevated(&self, flag: &str) -> Result<(), OpError> {
        if self.manager != Manager::TaskScheduler || self.is_elevated() {
            return Ok(());
        }
        Err(OpError::new(
            ErrorCode::PermissionDenied,
            format!(
                "`--always-on` registers a task that runs with nobody logged on, and a console \
                 that is not elevated cannot do that. Open PowerShell with \"Run as \
                 administrator\" and run `qsh service {} --always-on` again; nothing was changed",
                if flag == "install" {
                    "install"
                } else {
                    "uninstall"
                }
            ),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({ "reason": "not_elevated" })))
    }

    /// `install --always-on`, after the unit file is written.
    pub(super) fn enable_always_on(
        &self,
        plan: &AlwaysOnPlan<'_>,
    ) -> Result<EnableOutcome, OpError> {
        let mode = plan.mode;
        match self.manager {
            Manager::Systemd => {
                let activation = self.activate(mode, plan.unit_path)?;
                let user = self.account_or_error()?;
                self.interactive_ok("always_on", &loginctl_enable_linger_argv(user))?;
                Ok(EnableOutcome {
                    state: ServiceAlwaysOnState::Enabled,
                    firewall_rule: false,
                    activation,
                })
            }
            Manager::Launchd => {
                if self.launchdaemon_present(mode) {
                    return Ok(EnableOutcome {
                        state: ServiceAlwaysOnState::AlreadyEnabled,
                        firewall_rule: false,
                        activation: ServiceActivation::AlwaysOnPresent,
                    });
                }
                let user = self.account_or_error()?;
                let uid = self.euid.to_string();
                // The daemon and the agent share a label and a port: the
                // agent comes down first (the recipe's first step).
                if self.probe("always_on", &launchd_print_argv(&uid, mode))? {
                    self.run_ok("always_on", &launchd_bootout_argv(&uid, mode))?;
                }
                let source_dir = plan.config_dir.join("service");
                crate::config::ensure_private_dir(&source_dir)?;
                let source = source_dir.join(format!("io.qsh.{mode}.plist"));
                let plist = render_launchdaemon_plist(
                    mode,
                    &plan.exe.display().to_string(),
                    &plan.home.display().to_string(),
                    plan.controller,
                    user,
                );
                crate::config::write_private_file(&source, plist.as_bytes())?;
                let daemon = crate::doctor::probe::macos_launchdaemon_path(&self.system_root, mode);
                let result = launchdaemon_install_argvs(
                    &source.display().to_string(),
                    &daemon.display().to_string(),
                )
                .iter()
                .try_for_each(|argv| self.interactive_ok("always_on", argv));
                let _ = std::fs::remove_file(&source);
                result?;
                Ok(EnableOutcome {
                    state: ServiceAlwaysOnState::Enabled,
                    firewall_rule: false,
                    activation: ServiceActivation::Started,
                })
            }
            Manager::TaskScheduler => {
                let account = self.account_or_error()?;
                let sid = self.user_sid.as_deref().ok_or_else(user_sid_unavailable)?;
                let task_file = windows_always_on_path(plan.unit_path, mode);
                let text = render_windows_always_on_task(
                    mode,
                    &plan.exe.display().to_string(),
                    plan.controller,
                    sid,
                );
                crate::config::write_private_file(&task_file, &encode_task_file(&text))?;
                self.interactive_ok(
                    "always_on",
                    &schtasks_create_always_on_argv(
                        mode,
                        &task_file.display().to_string(),
                        account,
                    ),
                )?;
                // A rule left by an earlier run is replaced, not doubled.
                let _ = self.probe("always_on", &netsh_firewall_delete_argv(mode));
                self.run_ok(
                    "always_on",
                    &netsh_firewall_add_argv(mode, &plan.exe.display().to_string()),
                )?;
                let running = self.task_running("always_on", mode)?;
                let activation = if running {
                    ServiceActivation::AlreadyActive
                } else {
                    self.run_ok("always_on", &schtasks_run_argv(mode))?;
                    ServiceActivation::Started
                };
                Ok(EnableOutcome {
                    state: ServiceAlwaysOnState::Enabled,
                    firewall_rule: true,
                    activation,
                })
            }
        }
    }

    /// `uninstall --always-on`: reverses each step of
    /// [`Self::enable_always_on`]. Returns the state and whether a firewall
    /// rule was removed.
    pub(super) fn disable_always_on(
        &self,
        mode: &str,
        unit_path: &Path,
    ) -> Result<(ServiceAlwaysOnState, bool), OpError> {
        match self.manager {
            Manager::Systemd => {
                let user = self.account_or_error()?;
                self.interactive_ok("always_off", &loginctl_disable_linger_argv(user))?;
                Ok((ServiceAlwaysOnState::Disabled, false))
            }
            Manager::Launchd => {
                if !self.launchdaemon_present(mode) {
                    return Ok((ServiceAlwaysOnState::NotEnabled, false));
                }
                let daemon = crate::doctor::probe::macos_launchdaemon_path(&self.system_root, mode)
                    .display()
                    .to_string();
                let loaded = self.probe("always_off", &launchd_print_system_argv(mode))?;
                for (index, argv) in launchdaemon_remove_argvs(mode, &daemon).iter().enumerate() {
                    // The first step unloads; a daemon that is not loaded has
                    // nothing to unload.
                    if index == 0 && !loaded {
                        continue;
                    }
                    self.interactive_ok("always_off", argv)?;
                }
                Ok((ServiceAlwaysOnState::Disabled, false))
            }
            Manager::TaskScheduler => {
                if !self.always_on_task_present("always_off", mode)? {
                    return Ok((ServiceAlwaysOnState::NotEnabled, false));
                }
                if self.task_running("always_off", mode)? {
                    self.run_ok("always_off", &schtasks_end_argv(mode))?;
                }
                self.run_ok("always_off", &schtasks_delete_argv(mode))?;
                let firewall = self
                    .probe("always_off", &netsh_firewall_delete_argv(mode))
                    .unwrap_or(false);
                let _ = std::fs::remove_file(windows_always_on_path(unit_path, mode));
                Ok((ServiceAlwaysOnState::Disabled, firewall))
            }
        }
    }
}

/// `qsh-<mode>.always-on.xml` next to the default task definition file.
pub(super) fn windows_always_on_path(task_path: &Path, mode: &str) -> std::path::PathBuf {
    task_path.with_file_name(format!("qsh-{mode}.always-on.xml"))
}

fn keystore_session_bound_error(declined: bool) -> OpError {
    let how = if declined {
        "the question was answered no"
    } else {
        "the question cannot be asked without a terminal"
    };
    OpError::new(
        ErrorCode::ConfigError,
        format!(
            "the device key is in the OS credential store, which a service started outside a \
             login session cannot be sure to open ({how}); nothing was changed. Run `qsh service \
             install --always-on --move-key` to move it to the key file first, or `qsh identity \
             move-key --to file`"
        ),
    )
    .with_retryable(false)
    .with_details(serde_json::json!({ "reason": "keystore_session_bound" }))
}

impl Ops {
    /// Whether `install --always-on` has to move the key first, and whether
    /// the person agrees (ADR-0051 decisions 11 and 13). `Ok(false)` when
    /// the key does not need to move. An unanswerable or declined question
    /// is the `keystore_session_bound` error, before anything is changed.
    pub(super) fn decide_key_move(
        &self,
        manager: Manager,
        move_key_flag: bool,
        prompter: &dyn Prompter,
    ) -> Result<bool, OpError> {
        if manager == Manager::TaskScheduler {
            // A `Password` task opens Credential Manager without a session
            // (docs/deploy/service.md, measured), so the key stays.
            return Ok(false);
        }
        let on_platform = crate::identity::read_identity(&self.paths)?
            .is_some_and(|identity| identity.key_store == KeyStoreKind::Platform);
        if !on_platform {
            return Ok(false);
        }
        if move_key_flag {
            return Ok(true);
        }
        match prompter.ask(&prompts::MOVE_KEY) {
            Some(true) => Ok(true),
            Some(false) => Err(keystore_session_bound_error(true)),
            None => Err(keystore_session_bound_error(false)),
        }
    }

    /// The key move itself: the existing `identity.move_key` op.
    pub(super) fn move_key_to_file(&self, host: &ServiceHost<'_>) -> Result<bool, OpError> {
        let req = qsh_proto::IdentityMoveKeyReq {
            to: KeyStoreKind::File,
        };
        let data = match host.platform_store {
            Some(store) => self.identity_move_key_with_platform_store(req, store)?,
            None => self.identity_move_key(req)?,
        };
        Ok(data.moved)
    }
}
