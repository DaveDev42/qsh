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
    /// The remote path a file action would target (`qsh acl check --path`,
    /// ADR-0029 결정 19): required for `file.read`/`file.write` and refused
    /// for every other action. Shape rules are the file ops' (absolute,
    /// `~`, `~/…` or home-relative; no NUL, UTF-8, at most 4096 bytes).
    /// Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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
    /// The trust role the decision was evaluated with (ADR-0045 결정 10):
    /// the `role` key of this machine's pin named by a `device:<name>`
    /// principal, evaluated with the pin's own fingerprint. A pin without a
    /// `role` key is evaluated as `"none"`. Omitted when the principal is not
    /// a `device:` name, the auth path is `"ca"`, no pin has that name, or
    /// `trust.toml` could not be parsed (enforcement grants no role then).
    /// Open string, same discipline as [`Self::decision`]. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// What an `"allow"` rests on (ADR-0045 결정 10): `"role"` | `"acl"`.
    /// When a role and a row would both allow, the basis is `"role"`
    /// (ADR-0045 결정 4). Present only for an allow. Open string. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    /// Echoes [`AclCheckReq::path`] as given (ADR-0029 결정 19). Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The request path after the host's normalization (ADR-0029 결정 6-2),
    /// present only when normalization ran and succeeded. It runs only when
    /// the principal has some ground for the file action (a role that grants
    /// it, or a row granting it with `paths`), exactly as enforcement does,
    /// so a principal with no file grant never makes the query touch the
    /// filesystem. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_path: Option<String>,
}

/// Which `acl.toml` an `acl.check` decision was evaluated against
/// (`docs/CLI.md` §6.15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AclPolicyRef {
    /// Absolute path to the policy file, whether or not it loaded.
    pub path: String,
    /// Number of rules the loaded policy has; `0` when `loaded` is `false`.
    pub rules: u32,
    /// `false` when `acl.toml` is missing or failed to parse. Whether every
    /// decision is `"deny"` then depends on [`Self::state`]: an `"invalid"`
    /// file denies everything, trust roles included, while a `"missing"`
    /// file is a policy with no rows and trust roles still grant
    /// (ADR-0045 결정 6).
    pub loaded: bool,
    /// Why `loaded` is what it is (ADR-0045 결정 10): `"loaded"` |
    /// `"missing"` (no file) | `"invalid"` (unreadable or unparseable; every
    /// decision is `"deny"`, role grants included). Open string. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// ---------------------------------------------------------------------------
// acl.show (`docs/CLI.md` §6.19, ADR-0025). Local like `acl.check`: it reads
// this host's own `acl.toml` and is never dispatched to a remote peer (a
// remote-visible policy summary would be a capability-enumeration oracle,
// and a set-valued one is a more efficient oracle than `acl.check`'s single
// triple). The data carries structure only; the "unowned-resource ceiling"
// and "restart required" notices are prose the human renderer prints and
// `docs/CLI.md` §6.19 states as contract sentences, so this type never
// freezes their wording into `qsh.cli/v1`.
// ---------------------------------------------------------------------------

/// Request for `acl.show` (`qsh acl show`, `docs/CLI.md` §6.19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AclShowReq {
    /// Principal string to summarize — `device:<name>` | `user:<name>` |
    /// `fp:sha256:<base64>` (`docs/PRD.md` §9).
    pub principal: String,
    /// Auth path to assume the principal authenticated over — open string,
    /// same discipline as [`AclCheckReq::auth_path`]. `None` evaluates as
    /// `"pin"` and sets [`AclShowData::auth_path_defaulted`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_path: Option<String>,
}

/// One `[[acl]]` row that matches the requested principal and auth path
/// (`docs/CLI.md` §6.19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AclMatchingRule {
    /// The row's array index in `acl.toml`, the same value
    /// [`AclCheckData::rule`] carries.
    pub index: u32,
    /// The row's `allow` patterns exactly as written (`"exec.run"`,
    /// `"forward.*"`).
    pub allow: Vec<String>,
    /// The row's `auth_path` (`"pin"` when the file omitted it).
    pub auth_path: String,
    /// The row's `scope`: open string, `"owned"` | `"any"`.
    pub scope: String,
    /// The row's `paths` entries exactly as written (ADR-0029 결정 19).
    /// Omitted for a row without the key, which grants no file access.
    /// Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// True when the row names a file action but has no `paths`, so it
    /// grants no file access (ADR-0029 결정 19). Computed by the host so a
    /// renderer holds no ACL logic. Omitted when false. Additive.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub file_paths_missing: bool,
}

/// Data payload of `acl.show` (`docs/CLI.md` §6.19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AclShowData {
    /// Echoes [`AclShowReq::principal`].
    pub principal: String,
    /// The auth path actually evaluated (`"pin"` when the request omitted
    /// it).
    pub auth_path: String,
    /// `true` when the request omitted `auth_path` and `"pin"` was filled
    /// in (ADR-0025 decision 5).
    pub auth_path_defaulted: bool,
    /// Which policy file this summary was computed from. `loaded: false`
    /// (missing, unparseable, or unreadable file) means empty results.
    pub policy: AclPolicyRef,
    /// Rows matching the principal and auth path, in file order.
    pub matching_rules: Vec<AclMatchingRule>,
    /// Actions the principal may take on an unowned resource, in vocabulary
    /// order: the union of what its trust role grants and what the matching
    /// rows grant (ADR-0045 결정 11). A ceiling for owned resources. Never
    /// contains the always-denied actions. A file action is in it when the
    /// role grants it or some matching row grants it together with `paths`
    /// (ADR-0029 결정 19); which paths open is what
    /// [`AclMatchingRule::paths`] and `acl check --path` answer.
    pub effective_actions: Vec<String>,
    /// The principal's pin role, resolved exactly as
    /// [`AclCheckData::role`] (ADR-0045 결정 11). Omitted in the same cases.
    /// Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The actions that role grants, in the order of the role table
    /// (ADR-0045 결정 2), always-denied actions the table lists included.
    /// Present exactly when [`Self::role`] is. A role's grants are refused
    /// wholesale when `policy.state` is `"invalid"`, and
    /// [`Self::effective_actions`] is what is left after every gate.
    /// Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_actions: Option<Vec<String>>,
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
