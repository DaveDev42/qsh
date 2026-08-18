//! JSON contract types shared by the CLI, the ops layer and (eventually) the
//! MCP adapter. These mirror `docs/CLI.md` field-for-field; when the two
//! disagree, `docs/CLI.md` is the source of truth and this file is wrong.
//!
//! Every `*Req`/`*Data` type derives `JsonSchema` (schemars) so the same
//! Rust definition drives the CLI envelope, golden-fixture validation and
//! (from M6) MCP tool schemas — one source (`docs/design/architecture.md` §2).

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
}

/// A host entry as returned by `qsh hosts` / `qsh host get`
/// (`docs/CLI.md` §5, "Host").
///
/// Placeholder: field shape only, not yet produced or consumed by any op
/// (host directory lands in M7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Host {
    /// Local alias for this host.
    pub name: String,
    /// `host:port` this client dials (forward hosts) or last observed from
    /// (reverse hosts).
    pub address: String,
    /// `"forward"` or `"reverse"`.
    pub connection_mode: String,
    /// Last known reachability state, e.g. `"reachable"`.
    pub state: String,
    /// Stable per-device identifier the peer presented, e.g.
    /// `"device_01K0EXAMPLE"`.
    pub device_id: String,
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

/// Request for `session.read` (`docs/CLI.md` §6.4; same field names as the
/// MCP `read_session` tool, §8.3).
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
    /// The (new or pre-existing) pin.
    pub peer: TrustPeer,
    /// `true` if a new pin was written; `false` if `name` was already
    /// pinned (idempotent — the existing entry is returned unchanged).
    pub created: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_data_round_trips() {
        let data = VersionData {
            version: "0.1.0".to_string(),
            schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: VersionData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn exec_run_data_matches_documented_shape() {
        let data = ExecRunData {
            stdout_b64: "RGFyd2luCg==".into(),
            stderr_b64: String::new(),
            remote_exit_code: 0,
            signal: None,
            duration_ms: 18,
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "stdout_b64": "RGFyd2luCg==",
                "stderr_b64": "",
                "remote_exit_code": 0,
                "signal": null,
                "duration_ms": 18
            })
        );
    }

    #[test]
    fn identity_init_data_matches_documented_shape() {
        let data = IdentityInitData {
            device_id: "device_01K0EXAMPLE".into(),
            fingerprint: "sha256:BASE64FINGERPRINT".into(),
            key_store: KeyStoreKind::Platform,
            config_dir: "/Users/dave/.config/qsh".into(),
            created: true,
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["key_store"], "platform");
        assert_eq!(json["created"], true);
        assert_eq!(json["fingerprint"], "sha256:BASE64FINGERPRINT");
        let back: IdentityInitData = serde_json::from_value(json).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn key_store_mode_parses_lowercase_only() {
        assert_eq!("auto".parse::<KeyStoreMode>().unwrap(), KeyStoreMode::Auto);
        assert_eq!("file".parse::<KeyStoreMode>().unwrap(), KeyStoreMode::File);
        assert_eq!(
            "platform".parse::<KeyStoreMode>().unwrap(),
            KeyStoreMode::Platform
        );
        assert!("Keychain".parse::<KeyStoreMode>().is_err());
        assert_eq!(
            serde_json::to_string(&KeyStoreMode::Auto).unwrap(),
            "\"auto\""
        );
    }

    #[test]
    fn trust_types_match_documented_shape() {
        let peer = TrustPeer {
            name: "personal-mac".into(),
            fingerprint: "sha256:BASE64FINGERPRINT".into(),
            address: "personal-mac.example.com:4433".into(),
            added_at: "2026-08-17T00:00:00Z".into(),
        };
        let add = TrustAddData {
            peer: peer.clone(),
            created: true,
        };
        let json = serde_json::to_value(&add).unwrap();
        assert_eq!(json["peer"]["name"], "personal-mac");
        assert_eq!(json["peer"]["added_at"], "2026-08-17T00:00:00Z");
        assert_eq!(json["created"], true);

        let list = TrustListData { peers: vec![peer] };
        assert_eq!(
            serde_json::to_value(&list).unwrap()["peers"][0]["name"],
            "personal-mac"
        );

        let rm = TrustRemoveData {
            name: "personal-mac".into(),
            removed: false,
        };
        assert_eq!(
            serde_json::to_value(&rm).unwrap(),
            serde_json::json!({"name": "personal-mac", "removed": false})
        );
    }

    #[test]
    fn exec_run_req_omits_empty_optionals() {
        let req = ExecRunReq {
            host: "h".into(),
            argv: vec!["true".into()],
            env: vec![],
            timeout_ms: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json, serde_json::json!({"host": "h", "argv": ["true"]}));
        let back: ExecRunReq = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn contract_types_have_json_schemas() {
        // Smoke: schema generation must not panic for any contract type.
        let _ = schemars::schema_for!(VersionData);
        let _ = schemars::schema_for!(ExecRunReq);
        let _ = schemars::schema_for!(ExecRunData);
        let _ = schemars::schema_for!(IdentityInitData);
        let _ = schemars::schema_for!(TrustAddReq);
        let _ = schemars::schema_for!(TrustAddData);
        let _ = schemars::schema_for!(TrustListData);
        let _ = schemars::schema_for!(TrustRemoveData);
        for schema in session_schemas() {
            // Every session contract type is an object schema with at least
            // one property (none of them is a bare alias or an empty struct).
            assert_eq!(schema["type"], "object", "{schema}");
            assert!(
                schema["properties"]
                    .as_object()
                    .is_some_and(|p| !p.is_empty()),
                "{schema}"
            );
        }
    }

    fn session_schemas() -> Vec<serde_json::Value> {
        vec![
            schemars::schema_for!(Session).to_value(),
            schemars::schema_for!(SessionListReq).to_value(),
            schemars::schema_for!(SessionListData).to_value(),
            schemars::schema_for!(UnreachableHost).to_value(),
            schemars::schema_for!(SessionGetReq).to_value(),
            schemars::schema_for!(SessionOpenReq).to_value(),
            schemars::schema_for!(SessionOpenData).to_value(),
            schemars::schema_for!(SessionAttachReq).to_value(),
            schemars::schema_for!(SessionReadReq).to_value(),
            schemars::schema_for!(SessionReadData).to_value(),
            schemars::schema_for!(SessionWriteReq).to_value(),
            schemars::schema_for!(SessionWriteData).to_value(),
            schemars::schema_for!(SessionResizeReq).to_value(),
            schemars::schema_for!(SessionResizeData).to_value(),
            schemars::schema_for!(SessionCloseReq).to_value(),
            schemars::schema_for!(SessionCloseData).to_value(),
        ]
    }

    /// ADR-0007: the resume token is never a property of any JSON contract
    /// type (checked structurally on every `properties` map, at any depth).
    #[test]
    fn no_session_contract_type_exposes_resume_token() {
        fn property_names(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(map) => {
                    if let Some(serde_json::Value::Object(props)) = map.get("properties") {
                        out.extend(props.keys().cloned());
                    }
                    for child in map.values() {
                        property_names(child, out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for child in items {
                        property_names(child, out);
                    }
                }
                _ => {}
            }
        }
        for schema in session_schemas() {
            let mut names = Vec::new();
            property_names(&schema, &mut names);
            assert!(!names.is_empty());
            for n in &names {
                let lower = n.to_ascii_lowercase();
                assert!(
                    !lower.contains("token"),
                    "credential-looking property {n:?} in a JSON contract schema"
                );
            }
        }
    }

    #[test]
    fn session_matches_documented_shape() {
        let s = Session {
            session_ref: "personal-mac/01K0SESSION".into(),
            host: "personal-mac".into(),
            session_id: "01K0SESSION".into(),
            state: "running".into(),
            writer: Some("device:hermes".into()),
            created_at: "2026-08-17T00:00:00Z".into(),
            last_sequence: 42,
        };
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            serde_json::json!({
                "session_ref": "personal-mac/01K0SESSION",
                "host": "personal-mac",
                "session_id": "01K0SESSION",
                "state": "running",
                "writer": "device:hermes",
                "created_at": "2026-08-17T00:00:00Z",
                "last_sequence": 42
            })
        );
        // `writer` is nullable from day one (CLI.md §5).
        let json = serde_json::json!({
            "session_ref": "personal-mac/01K0SESSION",
            "host": "personal-mac",
            "session_id": "01K0SESSION",
            "state": "exited",
            "writer": null,
            "created_at": "2026-08-17T00:00:00Z",
            "last_sequence": 180
        });
        let back: Session = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back.writer, None);
        assert_eq!(serde_json::to_value(&back).unwrap(), json);
    }

    #[test]
    fn session_open_data_matches_documented_shape() {
        let d = SessionOpenData {
            session_ref: "personal-mac/01K0SESSION".into(),
            initial_sequence: 0,
        };
        assert_eq!(
            serde_json::to_value(&d).unwrap(),
            serde_json::json!({
                "session_ref": "personal-mac/01K0SESSION",
                "initial_sequence": 0
            })
        );
    }

    #[test]
    fn session_read_req_matches_mcp_read_session_shape() {
        // CLI.md §8.3: {session_ref, after_sequence, wait_ms, limit_bytes}.
        let json = serde_json::json!({
            "session_ref": "personal-mac/01K0SESSION",
            "after_sequence": 42,
            "wait_ms": 30000,
            "limit_bytes": 65536
        });
        let req: SessionReadReq = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(req.after_sequence, 42);
        assert_eq!(req.wait_ms, Some(30000));
        assert_eq!(req.limit_bytes, Some(65536));
        assert_eq!(serde_json::to_value(&req).unwrap(), json);

        // Optionals default.
        let minimal: SessionReadReq =
            serde_json::from_value(serde_json::json!({"session_ref": "h/x"})).unwrap();
        assert_eq!(minimal.after_sequence, 0);
        assert_eq!(minimal.wait_ms, None);
        assert_eq!(minimal.limit_bytes, None);
        assert_eq!(minimal.ctl_after, None);

        // `ctl_after` is additive: absent from the §8.3 shape above, and
        // round-trips when a poller echoes the previous reply's cursor.
        let with_cursor: SessionReadReq = serde_json::from_value(serde_json::json!({
            "session_ref": "h/x",
            "after_sequence": 42,
            "ctl_after": 7
        }))
        .unwrap();
        assert_eq!(with_cursor.ctl_after, Some(7));
        assert_eq!(
            serde_json::to_value(&with_cursor).unwrap(),
            serde_json::json!({
                "session_ref": "h/x",
                "after_sequence": 42,
                "ctl_after": 7
            })
        );
    }

    #[test]
    fn session_read_data_carries_events_in_order() {
        use crate::event::{EVENT_SCHEMA, SessionEvent};
        let d = SessionReadData {
            session_ref: "personal-mac/01K0SESSION".into(),
            next_after: 180,
            next_ctl_after: 3,
            events: vec![
                SessionEvent::Output {
                    schema: EVENT_SCHEMA.into(),
                    session_ref: "personal-mac/01K0SESSION".into(),
                    sequence: 49,
                    data_b64: "SGVsbG8NCg==".into(),
                },
                SessionEvent::Exit {
                    schema: EVENT_SCHEMA.into(),
                    session_ref: "personal-mac/01K0SESSION".into(),
                    sequence: 49,
                    exit_code: Some(0),
                    signal: None,
                },
            ],
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["events"][0]["type"], "session.output");
        assert_eq!(json["events"][1]["type"], "session.exit");
        let back: SessionReadData = serde_json::from_value(json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn session_reqs_omit_empty_optionals() {
        let open = SessionOpenReq {
            host: "h".into(),
            argv: vec![],
            env: vec![],
            term: None,
            cols: None,
            rows: None,
            user: None,
        };
        assert_eq!(
            serde_json::to_value(&open).unwrap(),
            serde_json::json!({"host": "h"})
        );
        let attach = SessionAttachReq {
            session_ref: "h/x".into(),
            no_steal: false,
        };
        assert_eq!(
            serde_json::to_value(&attach).unwrap(),
            serde_json::json!({"session_ref": "h/x"})
        );
        let close = SessionCloseReq {
            session_ref: "h/x".into(),
            signal: None,
        };
        assert_eq!(
            serde_json::to_value(&close).unwrap(),
            serde_json::json!({"session_ref": "h/x"})
        );
        let list: SessionListReq = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(list.host, None);
    }
}
