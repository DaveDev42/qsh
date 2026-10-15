//! `audit.query` request and data types (ADR-0033 결정 4~9).
//!
//! These are the contract halves of the read-only audit query. The query
//! itself is a **local** operation: it reads this machine's own audit log
//! and is never dispatched to a remote peer (ADR-0033 결정 4), so nothing
//! here has a wire counterpart. The user-facing surface (`qsh audit`,
//! `docs/CLI.md`) lands on top of these types.

use super::*;

/// Request for `audit.query` (ADR-0033 결정 5). Every filter is optional;
/// string filters match exactly and combine with AND.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryReq {
    /// Lower bound on a record's `ts` (inclusive): an RFC 3339 timestamp or
    /// a relative `N[smhd]` span counted back from the query's clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Upper bound on a record's `ts` (inclusive), RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// Exact match on [`AuditRecordView::principal`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Exact match on [`AuditRecordView::action`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Exact match on [`AuditRecordView::resource`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// `"allow"` or `"deny"`; anything else is `INVALID_ARGUMENT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Most records to return, newest first. Default 100, at most 1000;
    /// above that is `INVALID_ARGUMENT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One audit record as `audit.query` shows it (ADR-0033 결정 8): the
/// structural fields `qsh_core::audit::AuditRecord` stores, moved over
/// field for field with no enrichment (no reverse lookup, no alias
/// resolution). There is no field that could carry a payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuditRecordView {
    /// RFC 3339 UTC timestamp of the decision.
    pub ts: String,
    /// The wire `request_id` of the decided request as a string, or `"-"`
    /// for a connection-level decision.
    pub request_id: String,
    /// The authenticated principal, or `"-"` when none was established.
    pub principal: String,
    /// ACL action, or `"connect"` for a connection-level record.
    pub action: String,
    /// Structural resource identifier the action targeted.
    pub resource: String,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    /// Index of the matching policy rule; `null` when no rule decided it.
    pub rule: Option<u32>,
    /// How the peer authenticated (`"pin"`, `"ca"`, `"pairing"`, `"local"`,
    /// or `"-"`); an open string.
    pub auth_path: String,
    /// Peer socket address at decision time, or `"-"`.
    pub peer_addr: String,
    /// How many further rejections a windowed summary record collapses;
    /// present only on such a record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// The trust role behind the record (ADR-0045 결정 16); present only
    /// when the stored record carries the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// Data payload of `audit.query` (ADR-0033 결정 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuditQueryData {
    /// Matching records, newest first, at most the request's `limit`.
    pub records: Vec<AuditRecordView>,
    /// Lines that could not be used (torn, unparseable or over the line
    /// cap), counted over every file read. Their content is never echoed.
    pub skipped_lines: u64,
    /// The `ts` of the oldest record in every file read, independent of the
    /// filters: the retention horizon of this host. `null` when no record
    /// was read.
    pub oldest_ts: Option<String>,
    /// `true` only when `limit` cut off records that matched the filters.
    pub truncated: bool,
}
