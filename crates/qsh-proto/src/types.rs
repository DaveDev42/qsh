//! JSON contract types shared by the CLI, the ops layer and (eventually) the
//! MCP adapter. These mirror `docs/CLI.md` field-for-field; when the two
//! disagree, `docs/CLI.md` is the source of truth and this file is wrong.

use serde::{Deserialize, Serialize};

/// Data payload of a `version.get` response (`docs/CLI.md` §3.1 envelope,
/// `data` field). This is the one contract type actually produced by code
/// in this milestone (`qsh version --json`); the rest of this module is
/// placeholder shape only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// Placeholder: field shape only, not yet produced or consumed by any op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// Placeholder: field shape only, not yet produced or consumed by any op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}
