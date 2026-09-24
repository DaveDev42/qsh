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

mod acl;
mod cert;
mod doctor;
mod exec;
mod identity;
mod service;
mod session;
mod trust;
mod tunnel;

pub use acl::*;
pub use cert::*;
pub use doctor::*;
pub use exec::*;
pub use identity::*;
pub use service::*;
pub use session::*;
pub use trust::*;
pub use tunnel::*;

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
    /// Additive, issue #4 item 4 — RFC 3339 UTC instant the registry
    /// observed this reverse registration's connection die (the same
    /// wall-clock stamp `qsh.local.v1`'s `LocalHost.lost_at` carries from
    /// `Registry::mark_stale`). Present only for a `"reverse"` host whose
    /// `state` is `"stale"`; absent (key omitted, never `null`) for every
    /// other state and for every `"forward"` host — a forward host is
    /// never probed at all (`state` doc above), so it has no connection
    /// loss to time-stamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_at: Option<String>,
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
