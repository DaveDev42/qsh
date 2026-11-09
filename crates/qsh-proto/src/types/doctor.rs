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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorData {
    /// `"ok"` when every finding is informational or absent; `"warn"` when
    /// the worst finding is `"warn"`; `"error"` when at least one finding
    /// is `"error"`. Never itself `"info"` — `"ok"` is the empty/all-info
    /// case (`PLAN.md` M7 §4.1 #6: `"ok"` only ever appears here, never on
    /// an individual [`DoctorFinding::status`]).
    pub overall: String,
    /// One entry per diagnostic that fired. Empty when nothing did.
    pub findings: Vec<DoctorFinding>,
    /// What a short measurement connection to `DoctorReq.host` saw and what
    /// the adaptive policy would do with it (ADR-0052 decision 14). Absent
    /// when no host was named or the measurement connection did not come up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<DoctorTransport>,
    /// What the one hole punch `qsh doctor <host>` tried found, when the host
    /// has no direct path (ADR-0054 decision 20). Absent when no host was
    /// named, the direct path exists, or punching is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub punch: Option<DoctorPunch>,
}

/// The `punch` object of [`DoctorData`] (`docs/CLI.md` §6.17, ADR-0054
/// decision 20). Names and words only: no field can carry an IP address or a
/// port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorPunch {
    /// The rendezvous peer's pin name on this device. Absent when none was
    /// usable (`outcome` is `"no_rendezvous"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,
    /// `"succeeded"`, `"failed"` or `"no_rendezvous"`.
    pub outcome: String,
    /// Why the punch ended without a connection: one of the closed words of
    /// `details.punch.reason` (`docs/CLI.md` §6.1). Absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Kind of the adopted candidate: `"host"`, `"reflexive"` or
    /// `"peer_reflexive"`. Present on success only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_kind: Option<String>,
    /// Address family of the adopted candidate: `"ipv4"` or `"ipv6"`. Present
    /// on success only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Milliseconds from the start of the attempt to the adopted handshake,
    /// or to giving up. Absent when no attempt ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

/// The `transport` object of [`DoctorData`] (`docs/CLI.md` §6.17, ADR-0052
/// decision 14). Statistics and knob values only: nothing in it can carry
/// PTY content or key material.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorTransport {
    /// Smoothed round-trip time of the measurement connection, in
    /// milliseconds.
    pub rtt_ms: f64,
    /// Round-trip time variation, in milliseconds.
    pub rtt_var_ms: f64,
    /// Smallest round-trip time seen, in milliseconds.
    pub min_rtt_ms: f64,
    /// Packet loss over the measurement, in percent.
    pub loss_pct: f64,
    /// Largest DATAGRAM payload the path carries, in bytes; `null` when the
    /// path carries none.
    pub max_datagram_bytes: Option<u64>,
    /// Screen-update carrier: `"datagram"`, `"stream"` or `"off"`.
    pub screen_sync: String,
    /// Minimum time between screen updates, in milliseconds.
    pub frame_interval_ms: u64,
    /// Knob (a): `"off"` or `"yield"`. A measurement connection carries no
    /// interactive traffic, so this reads `"off"` there.
    pub bulk_yield: String,
    /// Knob (d): `"off"`, `"display"` or `"underline"`.
    pub prediction: String,
    /// Keep-alive interval, in milliseconds.
    pub keep_alive_ms: u64,
    /// The connection rides inside a jump or proxy.
    pub nested: bool,
    /// Why the knobs have these values. An open vocabulary; the starting set
    /// is in `docs/CLI.md` §6.17.
    pub reasons: Vec<String>,
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
