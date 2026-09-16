//! `doctor.run` request and data types (`docs/CLI.md` §6.17).

use super::*;

// ---------------------------------------------------------------------------
// doctor.run (`docs/CLI.md` §6.17, M7 Step 6). A **local** operation, same
// discipline as `acl.check` above — it inspects this host's own config,
// identity, and network reachability and is never dispatched to a remote
// peer.
// ---------------------------------------------------------------------------

/// Request for `doctor.run` (`qsh doctor`, `docs/CLI.md` §6.17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorReq {
    /// Pinned host to include connectivity diagnostics for, in addition to
    /// the configured `reverse.controller` target; omit to check only the
    /// controller (when configured) and this host's own local state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Data payload of `doctor.run` (`docs/CLI.md` §6.17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorData {
    /// `"ok"` when every finding is informational or absent; `"warn"` when
    /// the worst finding is `"warn"`; `"error"` when at least one finding
    /// is `"error"`. Never itself `"info"` — `"ok"` is the empty/all-info
    /// case (`PLAN.md` M7 §4.1 #6: `"ok"` only ever appears here, never on
    /// an individual [`DoctorFinding::status`]).
    pub overall: String,
    /// One entry per diagnostic that fired. Empty when nothing did.
    pub findings: Vec<DoctorFinding>,
}

/// One diagnostic result within `doctor.run`'s [`DoctorData::findings`]
/// (`docs/CLI.md` §6.17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorFinding {
    /// Stable diagnostic code, e.g. `"controller_unreachable"` — the
    /// vocabulary `docs/CLI.md` §6.17 documents in full
    /// (`qsh_core::doctor::EXPECTED_DOCTOR_CODES`).
    pub code: String,
    /// `"warn"` | `"error"` | `"info"` — never `"ok"` (that value is
    /// reserved for [`DoctorData::overall`] alone).
    pub status: String,
    /// Human-readable explanation of what was checked and what was found.
    pub detail: String,
    /// Actionable next step, when the diagnostic has one specific enough to
    /// state; `None` for a purely informational finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}
