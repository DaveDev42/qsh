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

/// A session entry as returned by `qsh session get` / `qsh session open`
/// (`docs/CLI.md` §5, "Session").
///
/// Placeholder: field shape only, not yet produced or consumed by any op
/// (sessions land in M2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Session {
    /// Opaque handle combining host and session id; callers must not
    /// construct this themselves.
    pub session_ref: String,
    /// Host alias this session lives on.
    pub host: String,
    /// ULID session identifier.
    pub session_id: String,
    /// Session lifecycle state, e.g. `"running"`.
    pub state: String,
    /// `device_id` of the principal currently holding the writer lease.
    pub writer: String,
    /// RFC 3339 timestamp of session creation.
    pub created_at: String,
    /// Highest byte-offset sequence produced by this session so far.
    pub last_sequence: u64,
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
    }
}
