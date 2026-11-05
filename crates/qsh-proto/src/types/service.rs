//! `service.*` data types (`docs/CLI.md` §6.18).
//!
//! None of the three ops takes a request body — mode is inferred from
//! `config.toml`, not requested — so there are no `*Req` types here,
//! mirroring `Ops::version()`/`Ops::trust_list()`. The three explicit
//! flags (`--activate`, `--deactivate`, `--live`, ADR-0032 decision 1) are
//! arguments to the `Ops` methods, not wire fields, and each adds one
//! optional field below (decision 7): absent when the flag is not given, so
//! a flagless call is byte-identical to the pre-flag envelope.

use super::*;

/// What `qsh service install --activate` did with the service manager
/// (ADR-0032 decisions 4, 7, 18). Closed list; additions only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceActivation {
    /// The manager was asked to load and start the unit.
    Started,
    /// The unit was already loaded and running. It is never restarted, so a
    /// changed binary path takes effect at the next restart.
    AlreadyActive,
    /// A human-installed always-on form of the same mode exists (macOS
    /// LaunchDaemon). Only the unit file was written; the manager was not
    /// called.
    AlwaysOnPresent,
}

/// What `qsh service uninstall --deactivate` did with the service manager
/// (ADR-0032 decisions 5, 7, 18). Closed list; additions only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceDeactivation {
    /// The unit was registered and the manager was asked to release it
    /// before the unit file was removed.
    Stopped,
    /// The unit was not registered with the manager; no release call was
    /// made.
    NotActive,
    /// A human-installed always-on form of the same mode exists. Only the
    /// per-user form was released; the always-on form is left to its own
    /// release recipe.
    AlwaysOnPresent,
}

/// What `--always-on` (install) or `--always-on` (uninstall) did
/// (ADR-0051 decision 11). Closed list; additions only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAlwaysOnState {
    /// The OS procedure ran: `loginctl enable-linger`, the LaunchDaemon
    /// recipe under `sudo`, or the `Password` task registration.
    Enabled,
    /// A LaunchDaemon of the same mode was already installed, so nothing
    /// ran (macOS only).
    AlreadyEnabled,
    /// `uninstall --always-on` reversed the procedure.
    Disabled,
    /// `uninstall --always-on` found no always-on form to reverse.
    NotEnabled,
}

/// The `always_on` field of `service.install` and `service.uninstall`
/// (ADR-0051 decision 11, `docs/CLI.md` §6.18). Absent unless the flag was
/// given. Additive (`docs/CLI.md` §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceAlwaysOn {
    /// What the flag did.
    pub state: ServiceAlwaysOnState,
    /// `true` when `install --always-on` first moved the device key from the
    /// `platform` store to the key file (`--move-key` or the answer to the
    /// question).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub key_moved: bool,
    /// `true` when the inbound UDP firewall rule of the qsh executable was
    /// created (install) or removed (uninstall). Windows only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub firewall_rule: bool,
}

/// Data payload of `service.install`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceInstallData {
    /// The service manager that owns this unit: `"launchd"` (macOS) or
    /// `"systemd"` (Linux). Never `"none"` — when no manager applies the
    /// op fails `UNSUPPORTED` instead of returning `data`.
    pub manager: String,
    /// The inferred run mode: `"serve"`, `"listen"` or `"reverse"`
    /// (`docs/CLI.md` §6.17's `config_serve_to_conflict` precedence).
    pub mode: String,
    /// The unit file path that was written.
    pub path: String,
    /// `true` if the path was absent before this call; `false` if it
    /// already existed and was rewritten in place (idempotent — the
    /// bytes are the same either way).
    pub created: bool,
    /// What the activation did with the service manager (ADR-0032 decisions
    /// 2, 4, 18). Present by default since ADR-0051 decision 11; absent only
    /// with `--no-activate`. Additive (`docs/CLI.md` §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<ServiceActivation>,
    /// What `--always-on` did (ADR-0051 decision 11). Absent unless the flag
    /// was given. Additive (`docs/CLI.md` §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_on: Option<ServiceAlwaysOn>,
}

/// Data payload of `service.uninstall`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceUninstallData {
    /// See [`ServiceInstallData::manager`].
    pub manager: String,
    /// See [`ServiceInstallData::mode`].
    pub mode: String,
    /// The unit file path that was removed (or would have been).
    pub path: String,
    /// `true` if a unit was removed; `false` if none existed (idempotent
    /// — the `trust.remove` precedent). A unit `qsh` did not write is
    /// removed all the same: the contract is the path, not provenance.
    pub removed: bool,
    /// What `--deactivate` did with the service manager (ADR-0032 decisions
    /// 5, 18). Absent unless the flag was given. Additive (`docs/CLI.md`
    /// §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivation: Option<ServiceDeactivation>,
    /// What `--always-on` reversed (ADR-0051 decision 11). Absent unless the
    /// flag was given. Additive (`docs/CLI.md` §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_on: Option<ServiceAlwaysOn>,
}

/// Data payload of `service.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceStatusData {
    /// See [`ServiceInstallData::manager`].
    pub manager: String,
    /// See [`ServiceInstallData::mode`].
    pub mode: String,
    /// The unit file path that was checked.
    pub path: String,
    /// `true` if the unit file exists. Presence only, never activation:
    /// `launchctl print` / `systemctl --user status` are an explicit
    /// non-goal (`docs/CLI.md` §6.18).
    pub installed: bool,
    /// Whether the unit is running, read from one exit code of the service
    /// manager (ADR-0032 decision 6). Present only with `--live`; `false`
    /// without calling the manager when the unit file is absent. Additive
    /// (`docs/CLI.md` §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}
