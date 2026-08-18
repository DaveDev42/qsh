//! Structured audit log (`docs/design/architecture.md` §6): one JSONL line
//! per authorization decision at `$XDG_STATE_HOME/qsh/audit.log`.
//!
//! [`AuditRecord`] has **no field** that could carry argv, PTY bytes, stdin
//! or key material — "payload is never logged" is a property of the type,
//! not a discipline. Adding such a field is a design change (opt-in
//! `audit.log_argv` is the only sanctioned exception, and it is not in M1).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::acl::{Action, Decision};
use crate::config::now_rfc3339;

/// One audit line. Fields are exactly those listed in architecture.md §6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC 3339 UTC timestamp of the decision.
    pub ts: String,
    /// The wire `request_id` of the request being decided (as a string so
    /// it stays opaque), or `"-"` for connection-level decisions.
    pub request_id: String,
    /// The connection's authenticated principal (`device:<name>`, …).
    pub principal: String,
    /// ACL action (`exec.run`, …).
    pub action: String,
    /// Resource identifier the action targeted.
    pub resource: String,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    /// Index of the matching policy rule (M5+); `null` under the interim
    /// allow-all-pinned policy.
    pub rule: Option<u32>,
    /// Peer socket address at decision time.
    pub peer_addr: String,
}

impl AuditRecord {
    /// Build a record for a decision made now.
    pub fn now(
        request_id: u64,
        principal: &qsh_transport::Principal,
        action: Action,
        resource: &str,
        decision: Decision,
        peer_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: request_id.to_string(),
            principal: principal.to_string(),
            action: action.as_str().to_string(),
            resource: resource.to_string(),
            decision: decision.as_str().to_string(),
            rule: None,
            peer_addr: peer_addr.to_string(),
        }
    }
}

impl AuditRecord {
    /// A connection-level deny: the peer never got past the TLS handshake
    /// (no client cert, unpinned, expired…). There is no principal — the
    /// whole point is that none could be established — so `principal` is
    /// `"-"`, `action` is `"connect"` and `resource` is the coarse
    /// rejection category (never a detailed reason).
    pub fn handshake_rejected(peer_addr: std::net::SocketAddr, category: &str) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: "-".to_string(),
            principal: "-".to_string(),
            action: "connect".to_string(),
            resource: category.to_string(),
            decision: Decision::Deny.as_str().to_string(),
            rule: None,
            peer_addr: peer_addr.to_string(),
        }
    }
}

/// Where audit lines go. Implementations must never block the caller for
/// long and must never panic on I/O errors (audit failure is logged, not
/// fatal — refusing service because the audit disk is full is a separate
/// policy decision that M1 does not make).
pub trait AuditSink: Send + Sync + 'static {
    /// Append one record.
    fn record(&self, record: &AuditRecord);
}

/// Append-only JSONL file sink. Creates the parent directory (0700) and the
/// file (0600) on first use.
#[derive(Debug)]
pub struct FileAuditSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileAuditSink {
    /// Sink writing to `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// The log path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append(&self, line: &str) -> std::io::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, record: &AuditRecord) {
        let line = match serde_json::to_string(record) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(%err, "audit: failed to encode record");
                return;
            }
        };
        if let Err(err) = self.append(&line) {
            tracing::error!(%err, path = %self.path.display(), "audit: failed to append");
        }
    }
}

/// In-memory sink for tests.
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemoryAuditSink {
    /// Empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of everything recorded so far.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Drop everything recorded so far (tests: isolate one phase).
    pub fn clear(&self) {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, record: &AuditRecord) {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record.clone());
    }
}

/// A sink that drops everything (for contexts where audit is not
/// configured, e.g. client-only processes).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _record: &AuditRecord) {}
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_transport::Principal;

    fn sample() -> AuditRecord {
        AuditRecord::now(
            7,
            &Principal::Device("laptop".into()),
            Action::ExecRun,
            "exec",
            Decision::Allow,
            "127.0.0.1:4433".parse().unwrap(),
        )
    }

    #[test]
    fn record_has_only_structural_fields() {
        // Type-level guarantee, checked by enumerating the JSON keys: no
        // argv / payload / key field can appear.
        let value = serde_json::to_value(sample()).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "action",
                "decision",
                "peer_addr",
                "principal",
                "request_id",
                "resource",
                "rule",
                "ts"
            ]
        );
        assert_eq!(value["principal"], "device:laptop");
        assert_eq!(value["action"], "exec.run");
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["request_id"], "7");
        assert!(value["rule"].is_null());
    }

    #[test]
    fn file_sink_appends_jsonl_with_private_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("audit.log");
        let sink = FileAuditSink::new(&path);
        sink.record(&sample());
        sink.record(&sample());
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let back: AuditRecord = serde_json::from_str(line).unwrap();
            assert_eq!(back.decision, "allow");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let dmode = fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700);
        }
    }

    #[test]
    fn now_rfc3339_has_second_precision_and_z_suffix() {
        let ts = now_rfc3339();
        assert!(ts.ends_with('Z'), "{ts}");
        assert_eq!(ts.len(), "2026-08-17T00:00:00Z".len(), "{ts}");
    }
}
