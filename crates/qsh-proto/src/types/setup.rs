//! `setup.run` request and data types (`docs/CLI.md` §6.20, ADR-0024).
//!
//! `qsh setup` is a local orchestrator over existing operations, so these
//! types describe a plan and its steps, not a new capability. The step id
//! and status vocabularies are closed lists: additions are allowed, removals
//! and renames are not (`docs/CLI.md` §10).

use super::*;

/// Which of the four `qsh setup` roles a run sets up (ADR-0024 결정 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetupRole {
    /// `qsh setup host --peer <name>`: this machine runs `qsh serve`.
    Host,
    /// `qsh setup host --to <alias> --address <addr>`: this machine runs
    /// `qsh serve --to <alias>`.
    HostTo,
    /// `qsh setup client <name> --address <addr>`: this machine connects
    /// with `qsh <name>`.
    Client,
    /// `qsh setup listener --peer <name>`: this machine runs `qsh listen`.
    Listener,
}

/// The id of one `qsh setup` step (ADR-0024 결정 8). Closed list; additions
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetupStepId {
    /// Create this device's identity (`identity.init`).
    Identity,
    /// Check that `config.toml` selects the run mode the role needs.
    ModeConfig,
    /// Check that `acl.toml` allows the intended actions. Read-only.
    Acl,
    /// Pin the peer from a certificate file (`trust.add` with `cert_pem`).
    PinCert,
    /// Pin the peer by redeeming an invite code (`trust.accept`).
    Pair,
    /// Mint an invite that assigns the peer's name (`trust.invite`).
    Invite,
    /// Write the service unit file (`service.install`).
    Service,
    /// Run the diagnostics (`doctor.run`).
    Doctor,
}

/// The state of one `qsh setup` step (ADR-0024 결정 8). Closed list;
/// additions only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    /// Executed by this run, or satisfied as of this run.
    Done,
    /// Already satisfied; nothing was executed.
    Already,
    /// A person has something left to do (`detail` says what), or the step
    /// has not run yet in a plan.
    Pending,
    /// Not run because an earlier step is `pending`.
    Blocked,
    /// Excluded by a flag, or unsupported on this platform.
    Skipped,
}

/// Request for `setup.run` (`qsh setup`, `docs/CLI.md` §6.20).
///
/// Every field is an input the CLI collected from flags, standard input or
/// a prompt; the operation itself never prompts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SetupRunReq {
    /// The role to set up.
    pub role: SetupRole,
    /// The pin name: `--peer` for `host` and `listener`, `--to` for
    /// `host_to`, the positional name for `client`. It is also the
    /// `device:<name>` principal of the `[[acl]]` rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `host:port` to record on the pin (`host_to`, `client`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// PEM text of the peer's certificate (`--peer-cert`). Mutually
    /// exclusive with `code`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_cert_pem: Option<String>,
    /// A one-time invite code (`client` only). Mutually exclusive with
    /// `peer_cert_pem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Also require `forward.local` in the `[[acl]]` rows (`host` and
    /// `host_to` only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forward: bool,
    /// Also write the service unit file.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub service: bool,
}

/// One step of a `qsh setup` run (ADR-0024 결정 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SetupStep {
    /// Which step this is.
    pub id: SetupStepId,
    /// Where the step stands.
    pub status: SetupStatus,
    /// The standalone command that does the same thing, so a person or a
    /// provisioning script can follow the step without `qsh setup`.
    pub command: String,
    /// What is left for a person to do, or a note about what was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The `data` of the operation this step called, verbatim. `invite`
    /// carries the `trust.invite` data (the invite code); `acl` carries one
    /// `acl.check` data per checked action, in action order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

/// Data payload of `setup.run` (ADR-0024 결정 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SetupRunData {
    /// The role that ran.
    pub role: SetupRole,
    /// `true` when no step is `pending` or `blocked` and the doctor's
    /// `overall` is not `"error"`: `qsh setup` has nothing left to do on this
    /// machine. For `host` it does not mean the peer connected.
    pub complete: bool,
    /// The steps, in run order.
    pub steps: Vec<SetupStep>,
    /// The `[[acl]]` rows to put in `acl.toml`, as text. Present when the
    /// role has an `acl` step. `qsh setup` never writes `acl.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_rows: Option<String>,
    /// Commands a person runs after this run, in order.
    pub next: Vec<String>,
}
