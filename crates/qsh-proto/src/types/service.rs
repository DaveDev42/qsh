//! `service.*` data types (`docs/CLI.md` §6.18).
//!
//! None of the three ops takes an argument — mode is inferred from
//! `config.toml`, not requested — so there are no `*Req` types here,
//! mirroring `Ops::version()`/`Ops::trust_list()`.

use super::*;

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
}
