//! `session.*` request and data types (`docs/CLI.md` §6.2–§6.7).

use super::*;

// ---------------------------------------------------------------------------
// session.* (`docs/CLI.md` §6.2–§6.7)
// ---------------------------------------------------------------------------

/// Request for `session.list` (`qsh sessions [host]`, `docs/CLI.md` §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct SessionListReq {
    /// Host alias to list; `None` = every configured host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Data payload of `session.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionListData {
    /// Sessions visible under the caller's `session.list` ACL scope.
    pub sessions: Vec<Session>,
    /// Hosts that could not be asked when `qsh sessions` fans out over
    /// every pinned host (`docs/CLI.md` §6.2). Absent/empty when every host
    /// answered, and always empty for a single-host request (that is a
    /// plain error). Additive (`qsh.cli/v1`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreachable: Vec<UnreachableHost>,
}

/// One host `session.list` could not reach — its alias plus the error it
/// would have produced on its own (`docs/CLI.md` §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UnreachableHost {
    /// Host alias.
    pub host: String,
    /// `ErrorCode` string of the failure (`CONNECTION_FAILED`, `TIMEOUT`, ...).
    pub code: String,
    /// Human-readable explanation. Automation must not parse this.
    pub message: String,
}

/// Request for `session.get` (`docs/CLI.md` §6.2). The data payload is a
/// [`Session`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionGetReq {
    /// Opaque session handle as returned by `session.open`/`session.list`.
    pub session_ref: String,
}

/// Request for `session.open` (`docs/CLI.md` §6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionOpenReq {
    /// Host alias.
    pub host: String,
    /// Program and arguments (`--` argv), passed verbatim — no shell
    /// re-interpretation. Empty = the remote account's login shell.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Extra environment variables layered over the remote login-shell
    /// environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// `TERM` to export in the session; `None` = remote default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    /// Initial terminal width; `None` = remote default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u32>,
    /// Initial terminal height; `None` = remote default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u32>,
    /// The `user` half of `qsh user@host` — a hint checked against the
    /// remote serve account's login name (`docs/CLI.md` §7); never an
    /// identity (the principal always comes from the certificate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Data payload of a successful `session.open` (`docs/CLI.md` §6.3).
///
/// Deliberately has no `resume_token`: the token lives only in the client
/// state file and is never surfaced in any output mode (ADR-0007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionOpenData {
    /// Opaque session handle for every later `session.*` call.
    pub session_ref: String,
    /// Cumulative output offset at creation — `0` for a fresh session.
    pub initial_sequence: u64,
}

/// Request for the stream operation `session.attach` (`docs/CLI.md` §7.1).
/// The resume token is looked up by `Ops` from the client state file, never
/// supplied by the caller (ADR-0007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionAttachReq {
    /// Opaque session handle.
    pub session_ref: String,
    /// Fail with `SESSION_CONFLICT` instead of stealing a live writer lease
    /// (`docs/design/protocol.md` §10). Default: steal.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_steal: bool,
}

/// Request for `session.read` (`docs/CLI.md` §6.4; the same cursor-pull
/// shape a long-running external process's, e.g. an agent tool, long-poll
/// caller would send).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionReadReq {
    /// Opaque session handle.
    pub session_ref: String,
    /// Cumulative output byte offset already received (`--after`); the
    /// reply starts right after it.
    #[serde(default)]
    pub after_sequence: u64,
    /// Long-poll wait for new output in milliseconds (`--wait`); `None` =
    /// return immediately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// Maximum output payload bytes in one reply (`--limit-bytes`); `None`
    /// = server default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<u64>,
    /// Control-entry cursor (`--ctl-after`): the `next_ctl_after` of the
    /// previous reply, `0` (the default) for a fresh read. Control events
    /// (`session.exit`/`writer_changed`/`closed`) carry the offset they were
    /// appended at and do **not** advance it, so `after_sequence` alone
    /// cannot express "I already have the control event positioned at N";
    /// a poller that does not echo this back sees such an event again on
    /// every pull (`docs/CLI.md` §6.4). Additive (`qsh.cli/v1`), so it is
    /// omitted entirely when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctl_after: Option<u64>,
}

/// Data payload of a single (non-`--follow`) `session.read`: the events
/// received for this pull, in total order (`docs/CLI.md` §6.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SessionReadData {
    /// Opaque session handle the events belong to.
    pub session_ref: String,
    /// `qsh.event/v1` events (`session.output`/`gap`/`exit`/
    /// `writer_changed`/`closed`); may be empty when `wait_ms` elapsed.
    pub events: Vec<crate::event::SessionEvent>,
    /// Cursor to resume from: pass back as `after_sequence`. Equal to the
    /// request's `after_sequence` plus the output bytes delivered (or the
    /// replay buffer's `available_from` after a gap). Additive
    /// (`qsh.cli/v1`).
    #[serde(default)]
    pub next_after: u64,
    /// Control-entry half of the resume cursor: pass back as `ctl_after`.
    /// Additive (`qsh.cli/v1`).
    #[serde(default)]
    pub next_ctl_after: u64,
}

/// Request for `session.write` (`docs/CLI.md` §6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionWriteReq {
    /// Opaque session handle.
    pub session_ref: String,
    /// Bytes to inject as terminal input, standard Base64 (`--data-b64`, or
    /// raw stdin encoded by the CLI for `--stdin`).
    pub data_b64: String,
}

/// Data payload of `session.write`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionWriteData {
    /// Opaque session handle.
    pub session_ref: String,
    /// Number of input bytes accepted by the host.
    pub bytes_written: u64,
}

/// Request for `session.resize` (`docs/CLI.md` §6.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionResizeReq {
    /// Opaque session handle.
    pub session_ref: String,
    /// New terminal width.
    pub cols: u32,
    /// New terminal height.
    pub rows: u32,
}

/// Data payload of `session.resize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionResizeData {
    /// Opaque session handle.
    pub session_ref: String,
    /// Applied terminal width.
    pub cols: u32,
    /// Applied terminal height.
    pub rows: u32,
}

/// Request for `session.close` (`docs/CLI.md` §6.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionCloseReq {
    /// Opaque session handle.
    pub session_ref: String,
    /// First signal of the HUP → TERM → KILL escalation, canonical
    /// `SIGTERM` form (`--signal`, one of HUP|INT|QUIT|TERM|USR1|USR2|KILL);
    /// `None` = default (SIGHUP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// Data payload of `session.close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionCloseData {
    /// Opaque session handle that was closed.
    pub session_ref: String,
    /// Cumulative output byte offset at removal.
    pub final_sequence: u64,
}
