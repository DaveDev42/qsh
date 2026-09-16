//! JSON contract types shared by the CLI, the ops layer and any long-running
//! external process (e.g. an agent tool) integrating over `qsh.cli/v1`.
//! These mirror `docs/CLI.md` field-for-field; when the two disagree,
//! `docs/CLI.md` is the source of truth and this file is wrong.
//!
//! Every `*Req`/`*Data` type derives `JsonSchema` (schemars) so the same
//! Rust definition drives the CLI envelope and golden-fixture validation —
//! one source (`docs/design/architecture.md` §2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ErrorCode;

/// The `schema` value stamped on every `qsh.cli/v1` envelope.
pub const CLI_SCHEMA_V1: &str = "qsh.cli/v1";

/// The `qsh.cli/v1` response envelope (`docs/CLI.md` §3). One per
/// non-streaming command, exactly one line on stdout in `--json` mode.
///
/// `data` is left as an untyped value here because its shape depends on
/// `command`; the per-command `*Data` types in this module are the typed
/// halves and carry their own schemas.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CliEnvelope {
    /// Always [`CLI_SCHEMA_V1`].
    pub schema: String,
    /// ULID assigned per invocation (correlates logs, audit and output).
    pub request_id: String,
    /// Dotted operation name, e.g. `exec.run` (`docs/CLI.md` §2.4).
    pub command: String,
    /// `true` with `data`, `false` with `error`.
    pub ok: bool,
    /// Present iff `ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Present iff `!ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CliError>,
}

/// The `error` object of a failed envelope (`docs/CLI.md` §3.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CliError {
    /// One of [`ErrorCode`] (unknown codes pass through as strings).
    pub code: ErrorCode,
    /// Human-readable, single-line message. Never carries secrets.
    pub message: String,
    /// Whether the same call may succeed if simply retried.
    pub retryable: bool,
    /// Code-specific structured details, or `null`.
    #[serde(default)]
    pub details: serde_json::Value,
}

/// Data payload of a `version.get` response (`docs/CLI.md` §3.1 envelope,
/// `data` field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VersionData {
    /// The `qsh` binary's own version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Wire/CLI schema identifiers this build understands, e.g.
    /// `"qsh.cli/v1"`, `"qsh.event/v1"`.
    pub schemas: Vec<String>,
    /// Build identifiers this binary was compiled with, when the build
    /// environment provided any (`docs/ROADMAP.md` M7 감사 개정 ③, additive).
    /// Entirely absent — not a present-but-empty object — when nothing was
    /// injected at compile time: a local `cargo build` typically has none,
    /// CI supplies one (`PLAN.md` M7 §4.1 #1). Never fabricated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildInfo>,
}

/// Build identifiers embedded in the binary at compile time
/// (`VersionData::build`). Currently just `commit`; more fields (e.g. a
/// build date) can join later without a `/v2` — every field here is its own
/// additive promise, same as `VersionData.build` itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BuildInfo {
    /// Commit id injected via `option_env!("QSH_BUILD_COMMIT")` at compile
    /// time (no `vergen`-style build script — `PLAN.md` M7 §4.1 #1). Only
    /// present when that environment variable was set for the build that
    /// produced this binary.
    pub commit: String,
}

/// A host entry as returned by `qsh hosts` / `qsh host get`
/// (`docs/CLI.md` §5, "Host").
///
/// Placeholder no longer describes this type: M3 Step 1 is the first thing
/// to fix its value vocabulary (below), even though no op emits it and no
/// fixture exists for it *yet* (both land in Step 5) — so this is the
/// *first definition* of these fields' meaning, not a documented-meaning
/// change that would require `/v2` (`docs/CLI.md` §10). Actual production
/// (`host.list`/`host.get`) lands with the M3 reverse registry and `qsh
/// listen`/`qsh reverse` steps later in this milestone; `source`/`user`
/// (below) are the M7 Step 3 host *directory* (`hosts.toml`) addition,
/// additive-optional on top of this same type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Host {
    /// Local alias for this host.
    pub name: String,
    /// `host:port` this client dials (forward hosts) or last observed from
    /// (reverse hosts).
    pub address: String,
    /// `"forward"` or `"reverse"`.
    pub connection_mode: String,
    /// Reachability, open string set (`docs/CLI.md` §10): `"reachable"` |
    /// `"stale"` | `"unknown"`. A forward host is never probed for
    /// reachability in M3, so it always reports `"unknown"` — an
    /// unconfirmed host is never reported as `"reachable"`. A live reverse
    /// registration (the controller is actively holding an authenticated
    /// connection to it) is `"reachable"`; a registration whose connection
    /// died is `"stale"` for the controller's retention window
    /// (`docs/design/protocol.md` §11-4) before it is dropped.
    pub state: String,
    /// The peer's SPKI SHA-256 fingerprint, `sha256:BASE64`
    /// (`docs/design/architecture.md` §5) — the value pinned in the trust
    /// store for a forward host, or the value the daemon TLS-verified for a
    /// reverse host. Never `Hello.device_name` or any other wire display
    /// name (`docs/design/protocol.md` §3: identity is never taken from
    /// wire data), e.g. `"sha256:BASE64FINGERPRINT"`. This is the identity
    /// *pinned to this name* — trust.toml's answer to "who is this name
    /// supposed to be" — never an observation of who currently answers at
    /// `address` (`PLAN.md` Step 3 (a)-추기 ②): a forward host's `address`
    /// can come from `hosts.toml`, which supplies no identity of its own,
    /// so `device_id` always still names the trust.toml-pinned peer that
    /// TLS must verify at that address, whichever directory the address
    /// came from.
    pub device_id: String,
    /// Additive, `PLAN.md` M7 Step 3 — for a `"forward"` host, which
    /// directory's *address* was actually used (`PLAN.md` Step 3 (a)-추기
    /// ②; not merely which directory(s) name the host): `"hosts"` when
    /// `hosts.toml` set a non-empty address for this name and it differs
    /// from (or is the only address for) trust.toml's pin; `"trust"` when
    /// `hosts.toml` has no entry, or its address is empty, so trust.toml's
    /// pinned address is the one actually used; `"both"` only when both
    /// sides set the *same* address. `None` for a `"reverse"` host (reverse
    /// registration is never `hosts.toml`-sourced), and `None` for a
    /// `"forward"` host whenever the whole `hosts.toml` directory has zero
    /// entries — a deployment that never adopted it sees the identical
    /// pre-M7-Step-3 shape (`docs/CLI.md` §5). Security note: write access
    /// to `hosts.toml` is the power to redirect a name to a different
    /// already-pinned peer (mTLS still blocks an unpinned address) — such a
    /// redirect is exactly what `source: "hosts"` (address differs from
    /// trust.toml's pin, or trust.toml has no pin at all) reveals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Additive, `PLAN.md` M7 Step 3 — `hosts.toml`'s `user` hint for this
    /// name, if it set one. Never an identity or an account selector, only
    /// ever the same `SessionOpen.user` assertion hint `docs/CLI.md` §7
    /// already documents; `None` when `hosts.toml` has no entry (or no
    /// `user`) for this name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Request for `host.list` (`qsh hosts`, `docs/CLI.md` §6.1). No filters in
/// M3 — every configured forward host plus every currently-registered
/// reverse host is returned in one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct HostListReq {}

/// Data payload of `host.list`: configured forward hosts and
/// currently-registered reverse hosts, together (`docs/CLI.md` §6.1:
/// trust-store-pinned forward hosts plus the resident daemon's live reverse
/// registrations, merged into one list; `host.list` never dials, and the
/// same name can appear as two entries — one per `connection_mode`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostListData {
    /// Every host visible to this caller, forward and reverse together.
    pub hosts: Vec<Host>,
}

/// Request for `host.get` (`docs/CLI.md` §6.1). The data payload is a
/// [`Host`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostGetReq {
    /// Host alias.
    pub name: String,
}

/// A session entry as returned by `qsh sessions` / `qsh session get`
/// (`docs/CLI.md` §5, "Session").
///
/// This is the JSON DTO: the wire `SessionInfo` carries
/// `session_id/state/writer/created_at/last_sequence` only, and the client
/// `Ops` layer adds `session_ref`/`host` from its local alias knowledge
/// (ADR-0007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Session {
    /// Opaque handle (`<host-alias>/<session_id>`, assembled by `Ops`);
    /// callers must not construct or parse this themselves.
    pub session_ref: String,
    /// Host alias this session lives on.
    pub host: String,
    /// Opaque, URL-safe session identifier issued by the host (ULID).
    pub session_id: String,
    /// Session lifecycle state — open string set: `"running"`, `"exited"`,
    /// ... (`docs/CLI.md` §10).
    pub state: String,
    /// Principal string of the current writer-lease holder
    /// (`device:…`/`user:…`/`fp:…`), or `null` when no connection holds the
    /// lease.
    pub writer: Option<String>,
    /// RFC 3339 UTC timestamp of session creation.
    pub created_at: String,
    /// Cumulative output byte offset produced by this session so far
    /// (`docs/CLI.md` §2.3); pass straight to `session read --after`.
    pub last_sequence: u64,
}

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

// ---------------------------------------------------------------------------
// exec.run (`docs/CLI.md` §6.8)
// ---------------------------------------------------------------------------

/// Request for `exec.run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecRunReq {
    /// Host name. Until the hosts.toml directory lands (M7) this is resolved
    /// through the trust store's pinned peers (name → address).
    pub host: String,
    /// Program and arguments, passed to the remote verbatim (no shell
    /// re-interpretation).
    pub argv: Vec<String>,
    /// Extra environment variables layered over the remote environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// Whole-operation timeout in milliseconds (`docs/CLI.md` §9). `None`
    /// means no timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// One `NAME=value` environment entry for [`ExecRunReq::env`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvVar {
    /// Variable name.
    pub name: String,
    /// Variable value.
    pub value: String,
}

/// Data payload of a successful `exec.run` (`docs/CLI.md` §6.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecRunData {
    /// Remote stdout, standard Base64.
    pub stdout_b64: String,
    /// Remote stderr, standard Base64.
    pub stderr_b64: String,
    /// The remote process's real exit code (`0..=255`). This is the source
    /// of truth; the process exit code of `qsh exec` clamps 255 → 254
    /// (`docs/CLI.md` §4). When the process was killed by a signal this is
    /// `128 + signo` and [`signal`](Self::signal) names it.
    pub remote_exit_code: i32,
    /// Terminating signal name (e.g. `"SIGKILL"`), or `null`.
    pub signal: Option<String>,
    /// Wall-clock duration of the remote execution in milliseconds.
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// identity.init (`docs/CLI.md` §6.11)
// ---------------------------------------------------------------------------

/// Which private-key store `qsh init` was asked to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyStoreMode {
    /// Prefer the OS credential store, fall back to a 0600 file when it is
    /// unavailable (headless Linux). The default.
    #[default]
    Auto,
    /// OS credential store only; fail if unavailable.
    Platform,
    /// 0600 file under the config directory only.
    File,
}

impl KeyStoreMode {
    /// Lowercase name as used in `config.toml` and `--key-store`.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyStoreMode::Auto => "auto",
            KeyStoreMode::Platform => "platform",
            KeyStoreMode::File => "file",
        }
    }
}

impl std::str::FromStr for KeyStoreMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(KeyStoreMode::Auto),
            "platform" => Ok(KeyStoreMode::Platform),
            "file" => Ok(KeyStoreMode::File),
            other => Err(format!(
                "invalid key store mode {other:?} (expected auto, platform or file)"
            )),
        }
    }
}

/// The store that actually holds the private key. Unlike [`KeyStoreMode`],
/// this is never `auto` — `qsh init` always reports the concrete choice
/// (`docs/CLI.md` §6.11: "어느 쪽이 사용됐는지는 항상 결과에 명시한다").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KeyStoreKind {
    /// OS credential store (macOS Keychain, Linux Secret Service).
    Platform,
    /// `identity/device.key`, mode 0600.
    File,
}

impl KeyStoreKind {
    /// Lowercase name as reported in `identity.init` data.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyStoreKind::Platform => "platform",
            KeyStoreKind::File => "file",
        }
    }
}

/// Request for `identity.init`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct IdentityInitReq {
    /// Key store selection. `None` = use `config.toml` `[identity].key_store`
    /// or `auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_store: Option<KeyStoreMode>,
}

/// Data payload of `identity.init` (`docs/CLI.md` §6.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityInitData {
    /// Stable device identifier, `device_<ULID>`.
    pub device_id: String,
    /// SPKI SHA-256 fingerprint of the device certificate, `sha256:BASE64`.
    pub fingerprint: String,
    /// The store actually holding the private key.
    pub key_store: KeyStoreKind,
    /// Absolute config directory the identity lives in.
    pub config_dir: String,
    /// `true` if this call created the identity, `false` if it already
    /// existed (idempotent).
    pub created: bool,
}

// ---------------------------------------------------------------------------
// trust.* (`docs/CLI.md` §6.11)
// ---------------------------------------------------------------------------

/// A pinned peer — the unified object used by `trust.add`/`list`/`remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPeer {
    /// Local alias for the peer (also the `device:<name>` principal it
    /// authenticates as).
    pub name: String,
    /// SPKI SHA-256 fingerprint, `sha256:BASE64`.
    pub fingerprint: String,
    /// `host:port` used to dial this peer. Empty when the pin exists only to
    /// authorize the peer as a *client* (no dial address).
    pub address: String,
    /// RFC 3339 UTC timestamp of when the pin was added.
    pub added_at: String,
}

/// Request for `trust.add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAddReq {
    /// Peer alias.
    pub name: String,
    /// `host:port`. Optional for client-only pins; required when
    /// `fingerprint` is absent (needed to observe it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// `sha256:BASE64`. When present the peer is pinned without connecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Data payload of `trust.add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAddData {
    /// The (new, pre-existing, or address-updated) pin.
    pub peer: TrustPeer,
    /// `true` if a new pin was written; `false` if `name` was already
    /// pinned (idempotent).
    pub created: bool,
    /// `true` if `name` was already pinned under the *same* fingerprint and
    /// this call changed its stored `address` in place (`docs/CLI.md`
    /// §6.11's address-refresh path, `PLAN.md` M7 Step 2 decision B —
    /// e.g. the host's reachable address changed and the operator re-ran
    /// `trust add` with the same identity and a new `--address`). `false`
    /// (never `true`) alongside `created: true` — a brand-new pin has
    /// nothing to update — and also `false` when `name` already existed
    /// but nothing about it changed: same address, or a *different*
    /// fingerprint (a fingerprint mismatch is never applied — re-binding an
    /// identity is a deliberate `remove` then `add`, never a side effect of
    /// a repeated `trust add`). Additive (`docs/CLI.md` §10): absent on any
    /// envelope produced before M7 Step 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<bool>,
}

/// Data payload of `trust.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustListData {
    /// All pinned peers, in store order.
    pub peers: Vec<TrustPeer>,
}

/// Data payload of `trust.remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustRemoveData {
    /// The name that was asked to be removed.
    pub name: String,
    /// `true` if a pin was removed; `false` if none existed (idempotent).
    pub removed: bool,
}

/// Request for `trust.invite` (ADR-0002, M7 Step 4). No fields today — kept
/// as a struct for symmetry with every other typed request, so a future
/// optional parameter (e.g. a non-default TTL) is additive, not a new op.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustInviteReq {}

/// Data payload of `trust.invite`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustInviteData {
    /// The one-time invite code, Crockford Base32, lowercase, hyphenated
    /// 4-char groups (`xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx`). Carries no
    /// address — give it to the other device's operator out of band
    /// alongside a reachable `host:port` for *this* device.
    pub code: String,
    /// RFC 3339 UTC expiry — creation time plus a 10-minute TTL
    /// (`docs/CLI.md` §6.11).
    pub expires_at: String,
    /// The complete command line for the other device to run, with `code`
    /// already filled in and `<address>` left as a literal placeholder this
    /// host cannot know on its own (its externally reachable address is a
    /// deployment fact, not something `trust.invite` observes — the same
    /// reason `HOST_NOT_FOUND`'s own remedy text uses a placeholder
    /// address). Human-mode output prints this verbatim; the operator
    /// substitutes a real `host:port` before sending it to the other party.
    pub accept_command: String,
}

// ---------------------------------------------------------------------------
// cert.* (`docs/adr/0008-private-ca-cert-issuance.md`, `docs/CLI.md` §6.x)
// ---------------------------------------------------------------------------

/// Request for `cert.init`. No fields today — kept as a struct for
/// symmetry with every other typed request (same rationale as
/// [`TrustInviteReq`]), so a future optional parameter is additive, not a
/// new op.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertInitReq {}

/// Data payload of `cert.init` — create the local private CA root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertInitData {
    /// SPKI SHA-256 fingerprint of the CA root certificate,
    /// `sha256:BASE64`.
    pub fingerprint: String,
    /// Absolute config directory the CA root lives under (`<config_dir>/ca`,
    /// ADR-0008 §4) — same field name as `identity.init`'s `config_dir`.
    pub config_dir: String,
    /// `true` if this call created the CA root; `false` if one already
    /// existed (idempotent).
    pub created: bool,
}

/// Request for `cert.issue`. No fields today: `qsh cert issue` always
/// promotes *this* device's own identity (ADR-0008 §5 — remote/headless
/// provisioning is P1), so there is nothing to parametrize yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertIssueReq {}

/// The `trust.toml [[ca]]` registration half of `cert.issue`'s result —
/// the same created/updated shape as [`TrustAddData`] (ADR-0008 §6 결과:
/// "trust.toml \[\[ca\]\] 등재는... trust add(Step 2) 선례를 따른다"). Never
/// carries the raw PEM: only the CA's own fingerprint, so this payload
/// stays golden-fixture-stable across regenerations (a fresh CA's PEM
/// bytes differ every run; its trust-entry shape does not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CaRegistration {
    /// The `trust.toml [[ca]]` entry name this call registered under.
    pub name: String,
    /// SPKI SHA-256 fingerprint of the registered CA root.
    pub fingerprint: String,
    /// `true` if this call wrote a new `[[ca]]` entry.
    pub created: bool,
    /// `true` if an existing entry's `cert_pem` was overwritten in place
    /// (only reachable by re-initializing the local CA under the same
    /// name — `qsh_core::trust::TrustStore::add_ca`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<bool>,
}

/// Data payload of `cert.issue` — CA-sign the local device identity and
/// register the CA root in `trust.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertIssueData {
    /// The device this certificate authenticates as
    /// (`qsh://device/<device_id>` SAN) — always this device's existing
    /// `device_id`; the SAN body never changes, only its signer (ADR-0008
    /// §2).
    pub device_id: String,
    /// SPKI SHA-256 fingerprint of the (freshly issued, or already
    /// CA-issued) device certificate.
    pub fingerprint: String,
    /// `true` if this call (re-)signed `identity/device.pem`; `false` if
    /// it was already CA-issued by this exact local CA — re-running `qsh
    /// cert issue` is idempotent and never silently rotates the leaf
    /// (ADR-0008 §6 결과: rotation is out of scope for M7).
    pub issued: bool,
    /// The `trust.toml [[ca]]` registration this call ensured.
    pub ca: CaRegistration,
}

/// Request for `trust.accept` (ADR-0002, M7 Step 4): dial `address` and
/// redeem `code` against the invite it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAcceptReq {
    /// `host:port` to dial — the invite-issuing device's reachable address,
    /// supplied out of band (the code itself never carries one).
    pub address: String,
    /// The invite code as displayed by `trust.invite` (case-insensitive,
    /// hyphens ignored).
    pub code: String,
}

/// Data payload of `trust.accept`. Same shape as [`TrustAddData`] — a
/// successful pairing exchange ends, from this device's perspective, in
/// exactly the same local pin `trust.add` would have written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAcceptData {
    /// The peer pinned as a result of this pairing exchange.
    pub peer: TrustPeer,
    /// `true` if this wrote a new pin.
    pub created: bool,
    /// `true` if an existing pin's address was updated in place. See
    /// [`TrustAddData::updated`] for the exact semantics (identical here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<bool>,
}

// ---------------------------------------------------------------------------
// tunnel.* (`docs/CLI.md` §6.9, M4)
// ---------------------------------------------------------------------------

/// A tunnel entry as returned by `tunnel.open`/`tunnels`/`tunnel.close`
/// (`docs/CLI.md` §6.9, "Tunnel").
///
/// This is the JSON DTO: the wire `RemoteForwardOpen`/`RemoteForwardOpened`
/// and the localctl `LocalTunnel` carry `tunnel_id`/`mode`/`bind`/
/// `forward_to`/`actual_port` only, and the client `Ops` layer adds `host`
/// from its own local alias knowledge — the same pattern `Session.host`
/// uses over the wire `SessionInfo` (ADR-0007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Tunnel {
    /// Opaque handle for `tunnel.close` / filtering `tunnels`.
    pub tunnel_id: String,
    /// Open string set: `"local"` (`-L`) or `"remote"` (`-R`) — same
    /// open-string discipline as `Host.connection_mode` (`docs/CLI.md`
    /// §10).
    pub mode: String,
    /// The `[bind:]listen_port` half of the forward spec, as bound.
    pub bind: String,
    /// The `host:host_port` half of the forward spec — the dial target, in
    /// the canonical form [`crate::wire::format_host_port`] produces (an
    /// IPv6 literal is bracketed: `"[::1]:5432"`).
    pub forward_to: String,
    /// The port actually bound — the kernel-assigned one for a `0`
    /// request, and the requested one when it was granted as asked
    /// (`docs/CLI.md` §6.9's `Tunnel` example carries it for a fixed-port
    /// forward). Optional because a tunnel that is not bound yet has no
    /// port to report; a producer that knows the bound port always fills
    /// it, so a reader never has to fall back to splitting `bind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_port: Option<u32>,
    /// Host alias this tunnel is on (`Ops`-filled; never present on the
    /// wire — ADR-0007, same rule as `Session.host`).
    pub host: String,
}

/// Request for `tunnel.open` (`docs/CLI.md` §6.9, `-L`/`-R`). `mode`
/// selects the direction (`"local"` for `-L`, `"remote"` for `-R` —
/// `wire::ForwardDirection`'s JSON mirror); `bind`/`listen_port`/
/// `forward_host`/`forward_port` are the already-parsed halves of the
/// `[bind:]listen_port:host:host_port` spec (`wire::parse_forward_spec`
/// parses the raw CLI string into these before a request is built — this
/// type never carries the unparsed string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelOpenReq {
    /// Host alias.
    pub host: String,
    /// `"local"` or `"remote"`.
    pub mode: String,
    /// The `[bind:]` prefix, when present; `None` = caller-side default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// The `listen_port` component.
    pub listen_port: u32,
    /// The `host` component of the forward spec (the dial target host —
    /// distinct from this request's own `host` field, which is the QSH
    /// peer).
    pub forward_host: String,
    /// The `host_port` component of the forward spec.
    pub forward_port: u32,
}

/// Data payload of a successful `tunnel.open`: the opened tunnel, exactly
/// the shape `tunnels`/`tunnel.close` also return — same "the data payload
/// is a [`Tunnel`]" pattern `HostGetReq`/`SessionGetReq` already use for
/// their respective single-entity gets.
pub type TunnelOpenData = Tunnel;

/// Request for `tunnel.list` (`qsh tunnels`, `docs/CLI.md` §6.9). No
/// filters — every tunnel visible under the caller's ownership is
/// returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct TunnelListReq {}

/// Data payload of `tunnel.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelListData {
    /// Every tunnel visible to this caller.
    pub tunnels: Vec<Tunnel>,
}

/// Request for `tunnel.close` (`docs/CLI.md` §6.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelCloseReq {
    /// Opaque tunnel handle.
    pub tunnel_id: String,
}

/// Data payload of `tunnel.close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelCloseData {
    /// Opaque tunnel handle that was asked to be closed.
    pub tunnel_id: String,
    /// `true` if a tunnel was closed; `false` if none existed with that id
    /// (idempotent, same pattern as `TrustRemoveData::removed`).
    pub closed: bool,
}

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

/// Data payload of `schema.get` (`docs/CLI.md` §6.10). Serves exactly the
/// JSON Schemas `crates/qsh-cli/tests/fixtures.rs` generates for golden
/// fixture validation — one source (`docs/design/testing.md` L6),
/// `qsh_proto::schema` is where both sides read them from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaData {
    /// Wire/CLI schema identifiers this build understands — same list as
    /// [`VersionData::schemas`].
    pub schemas: Vec<String>,
    /// JSON Schema (schemars, draft 2020-12) of the `qsh.cli/v1` envelope
    /// itself ([`CliEnvelope`]).
    pub envelope: serde_json::Value,
    /// JSON Schema of each command's `data` payload, keyed by dotted
    /// operation name (`docs/CLI.md` §2.4).
    pub commands: std::collections::BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests;
