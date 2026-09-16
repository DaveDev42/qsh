//! `acl.check` and `capabilities` request and data types (`docs/CLI.md` §6.15).

use super::*;

// ---------------------------------------------------------------------------
// acl.check (`docs/CLI.md` §6.15, M5 Step 1 — contract only: no evaluator or
// loader exists yet, `PLAN.md` M5 Step 1 (a). This is a **local**
// operation — it evaluates this host's own `acl.toml` against the given
// inputs and is never dispatched to a remote peer (`docs/CLI.md` §2.5's
// "인가 불요" row, ROADMAP M5 감사 개정 ③: a remote-visible policy query
// would itself be a capability-enumeration oracle).
// ---------------------------------------------------------------------------

/// Request for `acl.check` (`qsh acl check`, `docs/CLI.md` §6.15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AclCheckReq {
    /// Principal string to evaluate — `device:<name>` | `user:<name>` |
    /// `fp:sha256:<base64>` (`docs/PRD.md` §9).
    pub principal: String,
    /// Dotted action string, one of the 11 PRD §9 actions
    /// (`qsh_core::acl::Action::as_str`).
    pub action: String,
    /// Resource identifier the action would target (e.g. a session id, a
    /// `host:port`); `None` when the action carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Auth path to assume the principal authenticated over — open string,
    /// same discipline as [`Host::connection_mode`] (`docs/CLI.md` §10).
    /// `None` = the policy's own default (`"pin"`, `PLAN.md` M5 §4.1 #2)
    /// applies, matching what an unqualified `acl.toml` row means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_path: Option<String>,
    /// Principal that owns `resource`, so `scope = "owned"` rows can be
    /// evaluated too (`docs/CLI.md` §6.15, `PLAN.md` M5 §4.2's `--owner`
    /// decision — additive, M5 Step 7). `None` evaluates `resource` as
    /// unowned, the only behavior before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Auth path [`Self::owner`] authenticated over — same open-string,
    /// default-on-omission discipline as [`Self::auth_path`], and
    /// meaningless without [`Self::owner`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_auth_path: Option<String>,
}

/// Data payload of `acl.check` (`docs/CLI.md` §6.15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AclCheckData {
    /// Echoes [`AclCheckReq::principal`].
    pub principal: String,
    /// Echoes [`AclCheckReq::action`].
    pub action: String,
    /// Echoes [`AclCheckReq::resource`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Echoes [`AclCheckReq::auth_path`] as actually evaluated (the
    /// defaulted value when the request omitted it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_path: Option<String>,
    /// Open string: `"allow"` | `"deny"` (`qsh_core::acl::Decision::as_str`,
    /// same open-string discipline as [`Host::connection_mode`]).
    pub decision: String,
    /// Index of the matching policy rule; `None` when no rule matched
    /// (always true for a `"deny"` decision) or when no policy is loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<u32>,
    /// Which policy file this decision was evaluated against.
    pub policy: AclPolicyRef,
    /// Echoes [`AclCheckReq::owner`] (M5 Step 7, additive). Never the
    /// folded `opener_key` string — always the unfolded principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Echoes [`AclCheckReq::owner_auth_path`] as actually evaluated (the
    /// defaulted value when `owner` was given but this was omitted);
    /// `None` whenever [`Self::owner`] itself is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_auth_path: Option<String>,
}

/// Which `acl.toml` an `acl.check` decision was evaluated against
/// (`docs/CLI.md` §6.15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AclPolicyRef {
    /// Absolute path to the policy file, whether or not it loaded.
    pub path: String,
    /// Number of rules the loaded policy has; `0` when `loaded` is `false`.
    pub rules: u32,
    /// `false` when `acl.toml` is missing or failed to parse — every
    /// decision is `"deny"` in that state (`PLAN.md` M5 §4.1 #1), and this
    /// is how an operator distinguishes "denied by a rule" from "denied
    /// because there is no policy at all".
    pub loaded: bool,
}

/// Request for `capabilities.get` (`docs/CLI.md` §6.10, `qsh capabilities
/// [host]`). No `host`: this build's own advertised capability set. With a
/// `host`: the capabilities negotiated with that pinned peer's `Hello`
/// (`docs/design/protocol.md` §9) — the same intersection every value op's
/// own connection already computes, not a separate wire request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitiesReq {
    /// Pinned host to dial and negotiate with; omit for the local/static
    /// form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Data payload of `capabilities.get` (`docs/CLI.md` §6.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitiesData {
    /// Capability strings, unprocessed (`PLAN.md` M7 §4.1 #2): this
    /// build's own `Hello.capabilities` advertisement when [`Self::host`]
    /// is absent, or the negotiated intersection with that peer when it is
    /// present.
    pub capabilities: Vec<String>,
    /// The host this reflects the *negotiated* set for. Absent for the
    /// local/static form — never present with a value that was not
    /// actually dialed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}
