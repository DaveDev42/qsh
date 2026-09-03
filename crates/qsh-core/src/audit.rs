//! Structured audit log (`docs/design/architecture.md` §6): one JSONL line
//! per authorization decision at `$XDG_STATE_HOME/qsh/audit.log`.
//!
//! [`AuditRecord`] has **no field** that could carry argv, PTY bytes, stdin
//! or key material — "payload is never logged" is a property of the type,
//! not a discipline. Adding such a field is a design change (opt-in
//! `audit.log_argv` is the only sanctioned exception, and it is not in M1).
//!
//! **Fail-closed (`PLAN.md` M5 Step 3).** [`AuditSink::record`] returns a
//! [`Result`]: a caller that cannot durably record a decision must not
//! treat it as allowed. The production sink is [`writer::RotatingAuditSink`]
//! — a bounded-queue, rotating, degraded-latching writer thread — and the
//! four authorization choke points (`server::Server::authorize`/
//! `authorize_stream`/`authorize_session_control`, `reverse::admit::admit`)
//! all turn a `record` failure into a denial regardless of what the policy
//! verdict itself was. The one sanctioned exception is
//! [`AuditRecord::handshake_rejected`]: that path is already rejecting the
//! connection, so a failed enqueue there gets a diagnostic, never a changed
//! outcome (there is nothing left to fail closed *toward*).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_transport::{AuthPath, Principal};
use serde::{Deserialize, Serialize};

use crate::acl::{Action, Decision};
use crate::config::now_rfc3339;
use crate::quota::QuotaKind;

pub mod writer;

pub use writer::RotatingAuditSink;

/// `PLAN.md` M5 Step 3, F2: how long [`wait_for_sole_owner`] gives a
/// straggling `Arc` clone to drop before giving up. Generous enough for a
/// detached per-connection task to finish unwinding, finite enough to
/// never meaningfully delay process shutdown.
pub const AUDIT_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

/// Bounded, best-effort wait for `arc` to become the sole owner of its
/// value before the caller drops its own clone (`PLAN.md` M5 Step 3, F2).
///
/// `RotatingAuditSink::drop`'s final bounded flush of whatever is still
/// `pending` only runs once every clone is gone — but neither
/// `server::Server::run`'s nor `reverse::listen::Listen::run`'s accept
/// loops track (let alone join) the per-connection tasks they
/// `tokio::spawn` (`docs/design/architecture.md` §3: only the broker's own
/// sessions are drained), so a task still mid-unwind can hold its own
/// `Arc<dyn AuditSink>` clone alive for a little while after `run(..)`
/// itself returns. This gives such a straggler up to `grace` to drop its
/// clone before the caller (`serve::run_serve`/`reverse::listen::
/// run_listen_unix`) drops its own — best effort, not a guarantee: gives
/// up and returns anyway past the deadline, because shutdown must never
/// hang on one wedged task. Whichever clone turns out to be the last one,
/// `RotatingAuditSink::drop` still performs its own final flush.
pub async fn wait_for_sole_owner<T: ?Sized>(arc: &Arc<T>, grace: Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    while Arc::strong_count(arc) > 1 {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Why [`AuditSink::record`] could not accept a record. Exactly two shapes
/// (`PLAN.md` M5 Step 3): the writer's bounded queue is at capacity, or the
/// writer is latched degraded after a fatal write failure (disk full,
/// read-only filesystem, …). Either way the record is not durable, so a
/// caller gating a privileged operation on it must deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// The bounded writer queue had no room for this record (backpressure).
    #[error("audit queue is full")]
    QueueFull,
    /// The writer is degraded: its most recent write failed and no
    /// subsequent write has yet succeeded.
    #[error("audit writer is degraded (a previous write failed)")]
    Degraded,
}

/// `"pin"` / `"ca"` / `"pairing"` — the open string [`AuditRecord::auth_path`]
/// and `acl.toml`'s own `auth_path` key share (`docs/PRD.md` §9).
/// `"pairing"` (ADR-0002, M7 Step 4) never appears in an ordinary ACL
/// decision — a pairing connection never reaches the ACL choke point at all
/// (`crate::server::Server::serve_pairing_connection`'s own doc) — it only
/// ever labels the pairing exchange's own audit record.
fn auth_path_str(auth_path: AuthPath) -> &'static str {
    match auth_path {
        AuthPath::Pin => "pin",
        AuthPath::Ca => "ca",
        AuthPath::Pairing => "pairing",
    }
}

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
    /// How the peer authenticated: `"pin"` or `"ca"` (`docs/design/
    /// architecture.md` §6), or `"-"` when no principal was established at
    /// all ([`AuditRecord::handshake_rejected`]). Structural, like every
    /// other field — a `Principal` alone cannot tell a pin from a CA leaf
    /// asserting the same name, so this is what lets an investigation tell
    /// them apart after the fact.
    pub auth_path: String,
    /// Peer socket address at decision time.
    pub peer_addr: String,
    /// How many *additional* rejections a windowed summary record
    /// collapses (`PLAN.md` M8 Step 2, ADR-0009) — `None` (and omitted
    /// from the JSONL line entirely, `skip_serializing_if`) on every
    /// ordinary record, including the first rejection of a new admission
    /// aggregation window. `Some(n)` only on
    /// [`AuditRecord::handshake_rejected_summary`]'s own output: one line
    /// per `(category, 10s window)` standing in for `n` further
    /// rejections that window already suppressed, so a flood produces
    /// `O(categories / window)` audit lines instead of one per forged
    /// packet. Additive — `qsh.cli/v1`/`qsh.event/v1` never carry
    /// `AuditRecord` directly, but this still follows the same
    /// never-remove-never-repurpose discipline (`CLAUDE.md`) as every
    /// other field here, and old readers ignore a key they don't know.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count: Option<u32>,
}

impl AuditRecord {
    /// Build a record for a decision made now. `rule` is the matching
    /// policy rule's index (`Verdict::rule`, M5+) — `None` under the
    /// interim allow-all-pinned policy, or when the decision didn't come
    /// from a rule match at all (an always-deny gate, an ownership
    /// refusal, a credential failure — anything upstream or downstream of
    /// `Authorizer::check` itself).
    ///
    /// Eight positional arguments (over clippy's default seven): every one
    /// of them is a distinct structural field this record carries by
    /// contract (`docs/design/architecture.md` §6's field list, byte for
    /// byte) — a builder would only spread the same eight names across
    /// more call-site lines, not reduce what a caller has to get right.
    #[allow(clippy::too_many_arguments)]
    pub fn now(
        request_id: u64,
        principal: &qsh_transport::Principal,
        auth_path: AuthPath,
        action: Action,
        resource: &str,
        decision: Decision,
        rule: Option<u32>,
        peer_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: request_id.to_string(),
            principal: principal.to_string(),
            action: action.as_str().to_string(),
            resource: resource.to_string(),
            decision: decision.as_str().to_string(),
            rule,
            auth_path: auth_path_str(auth_path).to_string(),
            peer_addr: peer_addr.to_string(),
            count: None,
        }
    }
}

impl AuditRecord {
    /// A connection-level authorization decision: allow *or* deny, but
    /// never a reply to a specific control-stream request, so `request_id`
    /// is `"-"` (the field doc above reserves that value for exactly this
    /// case, and [`AuditRecord::handshake_rejected`] already honors the
    /// same convention) rather than a numeric id — indistinguishable
    /// otherwise from a peer-chosen wire request `0`.
    pub fn connection_level(
        principal: &qsh_transport::Principal,
        auth_path: AuthPath,
        action: Action,
        resource: &str,
        decision: Decision,
        rule: Option<u32>,
        peer_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: "-".to_string(),
            principal: principal.to_string(),
            action: action.as_str().to_string(),
            resource: resource.to_string(),
            decision: decision.as_str().to_string(),
            rule,
            auth_path: auth_path_str(auth_path).to_string(),
            peer_addr: peer_addr.to_string(),
            count: None,
        }
    }

    /// A connection-level deny: the peer never got past the TLS handshake
    /// (no client cert, unpinned, expired…). There is no principal — the
    /// whole point is that none could be established — so `principal` and
    /// `auth_path` are both `"-"`, `action` is `"connect"` and `resource` is
    /// the coarse rejection category (never a detailed reason).
    pub fn handshake_rejected(peer_addr: std::net::SocketAddr, category: &str) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: "-".to_string(),
            principal: "-".to_string(),
            action: "connect".to_string(),
            resource: category.to_string(),
            decision: Decision::Deny.as_str().to_string(),
            rule: None,
            auth_path: "-".to_string(),
            peer_addr: peer_addr.to_string(),
            count: None,
        }
    }

    /// The windowed-summary half of [`AuditRecord::handshake_rejected`]'s
    /// aggregation (`PLAN.md` M8 Step 2, ADR-0009, `crate::admission::Gate`):
    /// one record per `(category, 10s window)`, standing in for `count`
    /// further rejections in that same category and window that were
    /// suppressed rather than each getting their own line. `peer_addr` is
    /// always `"-"` — under a spoofed-source flood, recording each
    /// suppressed rejection's (attacker-controlled, likely forged) address
    /// would be worthless and unbounded; the *first* rejection of the
    /// window already recorded a real observed address via
    /// `handshake_rejected` itself.
    pub fn handshake_rejected_summary(category: &str, count: u32) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: "-".to_string(),
            principal: "-".to_string(),
            action: "connect".to_string(),
            resource: category.to_string(),
            decision: Decision::Deny.as_str().to_string(),
            rule: None,
            auth_path: "-".to_string(),
            peer_addr: "-".to_string(),
            count: Some(count),
        }
    }

    /// A resource-quota rejection (`crate::quota`, `PLAN.md` M8 Step 3,
    /// `docs/adr/0010-resource-quotas.md`) — the peer was already
    /// authorized (this fires strictly after the ACL choke point, never
    /// before: an unauthorized principal must see `PERMISSION_DENIED`,
    /// not a quota oracle), so unlike [`AuditRecord::handshake_rejected`]
    /// there is a real `principal` to record. `action` is `kind.action()` —
    /// `"session.open"` or `"exec.run"`, the same word `docs/CLI.md`'s audit
    /// section names for a quota-reject record, never the bare `"quota"`
    /// placeholder. `resource` carries `kind.category()` — the same
    /// `quota_*` vocabulary [`crate::quota::QuotaKind::category`]
    /// documents — mirroring how [`AuditRecord::handshake_rejected`] stuffs
    /// its category into `resource`. `request_id` and `auth_path` are the
    /// caller's own live values (threaded through `crate::quota::Quotas::
    /// record_rejection` from the same control-stream request that hit the
    /// quota), so the ACL `allow` line and this `deny` line for one request
    /// share a `request_id` and are not left to guesswork (verdict ruling
    /// 11①). `peer_addr` alone stays `"-"`: `crate::quota::Quotas` is
    /// leaf-most and connection-agnostic (architecture.md §1) and does not
    /// have it to hand. Structural fields only — never payload.
    pub fn quota_rejected(
        kind: QuotaKind,
        principal: &str,
        request_id: u64,
        auth_path: AuthPath,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: request_id.to_string(),
            principal: principal.to_string(),
            action: kind.action().to_string(),
            resource: kind.category().to_string(),
            decision: Decision::Deny.as_str().to_string(),
            rule: None,
            auth_path: auth_path_str(auth_path).to_string(),
            peer_addr: "-".to_string(),
            count: None,
        }
    }

    /// The windowed-summary half of [`AuditRecord::quota_rejected`]'s
    /// aggregation (`crate::quota::Quotas`, same `AUDIT_AGGREGATION_
    /// WINDOW`/first-record-then-summary shape as [`AuditRecord::
    /// handshake_rejected_summary`]): one record per `(category, 10s
    /// window)`, standing in for `count` further rejections in that same
    /// category and window that were suppressed rather than each getting
    /// their own line. Callers pass `"-"` for `principal` — a window can
    /// suppress rejections from more than one principal, and the first
    /// rejection of the window already recorded a real one via
    /// [`AuditRecord::quota_rejected`] — but the parameter is left open
    /// rather than hardcoded so a caller with a single dominant principal
    /// for the window is free to name it.
    pub fn quota_rejected_summary(kind: QuotaKind, principal: &str, count: u32) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: "-".to_string(),
            principal: principal.to_string(),
            action: kind.action().to_string(),
            resource: kind.category().to_string(),
            decision: Decision::Deny.as_str().to_string(),
            rule: None,
            auth_path: "-".to_string(),
            peer_addr: "-".to_string(),
            count: Some(count),
        }
    }

    /// A pairing exchange's outcome (ADR-0002, M7 Step 4,
    /// `crate::server::Server::serve_pairing_connection`). Pairing has no
    /// authorization surface at all (`docs/CLI.md` §2.5's
    /// `NoAuthorizationSurface` classification — a pairing connection never
    /// reaches the ACL choke point), so this sidesteps [`Action`]/rule the
    /// same way [`AuditRecord::handshake_rejected`] does. `resource` is a
    /// coarse, structural-only label — the peer's self-reported device name
    /// on success, or a failure category (`"no-match"`, `"expired"`, …) on
    /// failure — **never** the invite code, the proof bytes or the exported
    /// keying material (architecture.md §6: never log key material).
    pub fn pairing(peer_addr: std::net::SocketAddr, decision: Decision, resource: &str) -> Self {
        Self {
            ts: now_rfc3339(),
            request_id: "-".to_string(),
            principal: Principal::Pairing.to_string(),
            action: "pairing".to_string(),
            resource: resource.to_string(),
            decision: decision.as_str().to_string(),
            rule: None,
            auth_path: auth_path_str(AuthPath::Pairing).to_string(),
            peer_addr: peer_addr.to_string(),
            count: None,
        }
    }
}

/// Write whatever [`crate::admission::Gate::decide`] (a rejection) or
/// [`crate::admission::Gate::flush_expired`] (a bounded-latency summary
/// flush) handed back — 0, 1, or 2 records — logging the same
/// `tracing::warn!` diagnostic the record itself carries and recording it
/// through `audit`, warning (not failing the caller) if the write itself
/// fails.
///
/// **The single definition** of this contract (`PLAN.md` M8 Step 2
/// verification round, P1-1): `crate::server::Server::admit` and
/// `crate::reverse::listen::Listen::admit` — the two internet-exposed
/// accept loops — both call this instead of each keeping its own copy.
/// Before the fix, the two copies were independently mutable: an
/// adversarial mutation could delete one arm's audit-write entirely and
/// nothing detected it (the other loop's tests, and the other loop's
/// copy, were unaffected). Same fail-open-on-audit-failure exception as
/// every other rejection path in this crate: the connection is already
/// being rejected, so a failed enqueue changes only the diagnostic, never
/// the outcome. The `tracing::warn!` follows the same suppression as the
/// audit record itself — driven by the same (possibly empty) `records`
/// list — so a throttled flood cannot flood stderr either.
pub(crate) fn write_admission_audit(audit: &dyn AuditSink, records: &[AuditRecord]) {
    for record in records {
        if record.count.is_some() {
            tracing::warn!(
                category = %record.resource,
                count = record.count,
                "admission rejections aggregated in this window"
            );
        } else {
            tracing::warn!(
                peer = %record.peer_addr,
                category = %record.resource,
                "connection rejected by admission control"
            );
        }
        if let Err(audit_err) = audit.record(record) {
            tracing::warn!(%audit_err, "failed to record admission rejection");
        }
    }
}

/// [`write_admission_audit`]'s sibling for resource-quota rejections
/// ([`AuditRecord::quota_rejected`]/[`AuditRecord::quota_rejected_summary`],
/// `PLAN.md` M8 Step 3): same sink, same fail-open-on-audit-failure
/// exception (the request is already being refused, so a failed enqueue
/// changes only the diagnostic), same suppression-driven `tracing::warn!`
/// volume — but its own wording, because a quota rejection is neither a
/// connection rejection nor an admission decision, and an operator
/// grepping the log must not read it as one. A quota record has a real
/// `principal` and no `peer_addr` (`crate::quota` is
/// connection-agnostic), so that is what the line carries.
pub(crate) fn write_quota_audit(audit: &dyn AuditSink, records: &[AuditRecord]) {
    for record in records {
        if record.count.is_some() {
            tracing::warn!(
                category = %record.resource,
                count = record.count,
                "quota rejections aggregated in this window"
            );
        } else {
            tracing::warn!(
                principal = %record.principal,
                category = %record.resource,
                "request refused by a resource quota"
            );
        }
        if let Err(audit_err) = audit.record(record) {
            tracing::warn!(%audit_err, "failed to record quota rejection");
        }
    }
}

/// Where audit lines go. Implementations must never block the caller for
/// long and must never panic on I/O errors. A failure is not logged and
/// swallowed: it is returned, and every privileged-operation choke point
/// treats it as a denial (`PLAN.md` M5 Step 3 — this is the audit
/// fail-closed policy `docs/design/architecture.md` §6 documents).
pub trait AuditSink: Send + Sync + 'static {
    /// Append one record. `Err` means the record is not durable — the
    /// caller must not proceed as though the decision it describes was
    /// recorded.
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

/// Append-only JSONL file sink: opens the file fresh on every call (no
/// handle held across appends), so it has no rotation/retention and no
/// backpressure of its own — every write is its own attempt, with no
/// "queue full" failure mode. Still fail-closed: a write failure is
/// reported as [`AuditError::Degraded`], never silently dropped. Every
/// production choke point uses [`RotatingAuditSink`] instead (`qsh serve`/
/// `qsh reverse` via `serve::host_runtime`, and `qsh listen`'s controller
/// as of `PLAN.md` M5 Step 3 F7) — this stays as the simplest-possible
/// sink for callers that just want one, mainly this crate's own tests.
/// Creates the parent directory (0700) and the file (0600) on first use.
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
        // F3: payload and the trailing newline as ONE buffer, ONE
        // `write_all` — two separate calls (as this used to be) leave a
        // window where the payload lands but the newline doesn't, which
        // would torn-merge with whatever the next call appends.
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        file.write_all(&buf)
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let line = match serde_json::to_string(record) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(target: "qsh::audit", %err, "audit: failed to encode record");
                return Err(AuditError::Degraded);
            }
        };
        if let Err(err) = self.append(&line) {
            tracing::error!(
                target: "qsh::audit",
                %err,
                path = %self.path.display(),
                "audit: failed to append; denying the operation this record was for"
            );
            return Err(AuditError::Degraded);
        }
        Ok(())
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
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record.clone());
        Ok(())
    }
}

/// A sink that drops everything (for contexts where audit is not
/// configured, e.g. client-only processes).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Deterministic test double that fails every `record()` call on demand
/// (`PLAN.md` M5 Step 3's disk-full fail-closed tests) — an ENOSPC-class
/// failure without touching a real filesystem or the bounded-queue/writer
/// machinery [`RotatingAuditSink`] actually uses. `#[cfg(test)]` and
/// `pub(crate)`: it is a correctness fixture, never a production sink, but
/// is shared across this crate's own test modules (`server::mod::tests`,
/// `reverse::admit::tests`), which see it because `cfg(test)` is set for
/// the whole crate under `cargo test`.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct FailingAuditSink {
    failing: std::sync::atomic::AtomicBool,
    records: Mutex<Vec<AuditRecord>>,
}

#[cfg(test)]
impl FailingAuditSink {
    /// A sink that accepts every record until [`Self::fail`] is called.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Start failing every subsequent `record()` call.
    pub(crate) fn fail(&self) {
        self.failing
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Stop failing — later `record()` calls succeed again. The latch is
    /// not permanent (`PLAN.md` M5 §4.2's "다음 성공적 쓰기" recovery rule);
    /// this is the test-side equivalent of that recovery.
    pub(crate) fn clear(&self) {
        self.failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Everything actually recorded (i.e. every call made while not
    /// failing).
    pub(crate) fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
impl AuditSink for FailingAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AuditError::Degraded);
        }
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record.clone());
        Ok(())
    }
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
            AuthPath::Pin,
            Action::ExecRun,
            "exec",
            Decision::Allow,
            None,
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
                "auth_path",
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
        assert_eq!(value["auth_path"], "pin");
        assert!(value["rule"].is_null());
    }

    #[test]
    fn file_sink_appends_jsonl_with_private_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("audit.log");
        let sink = FileAuditSink::new(&path);
        sink.record(&sample()).unwrap();
        sink.record(&sample()).unwrap();
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

    /// `FileAuditSink` is fail-closed too, not just `RotatingAuditSink`
    /// (`PLAN.md` M5 Step 3): a write it cannot perform is `Err`, never a
    /// swallowed `tracing::error!` with the call site none the wiser. Kept
    /// as the simplest-possible sink for callers that want one (tests)
    /// even though `reverse::listen`'s controller itself moved onto
    /// `RotatingAuditSink` (F7). A directory at the log path makes
    /// `OpenOptions::open` fail deterministically (EISDIR), no real
    /// disk-full condition required.
    #[test]
    fn file_sink_returns_err_when_the_path_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        fs::create_dir(&path).unwrap();
        let sink = FileAuditSink::new(&path);
        assert_eq!(sink.record(&sample()), Err(AuditError::Degraded));
    }

    #[test]
    fn now_rfc3339_has_second_precision_and_z_suffix() {
        let ts = now_rfc3339();
        assert!(ts.ends_with('Z'), "{ts}");
        assert_eq!(ts.len(), "2026-08-17T00:00:00Z".len(), "{ts}");
    }

    // ---- F2: wait_for_sole_owner ---------------------------------------

    #[tokio::test]
    async fn wait_for_sole_owner_returns_immediately_when_already_sole_owner() {
        let arc = Arc::new(NullAuditSink);
        // No other clone exists: the loop's own condition is false on the
        // very first check, so this returns without ever sleeping.
        wait_for_sole_owner(&arc, Duration::from_secs(10)).await;
    }

    #[tokio::test]
    async fn wait_for_sole_owner_gives_up_after_grace_when_a_clone_is_still_held() {
        let arc = Arc::new(NullAuditSink);
        let _still_held = arc.clone();
        let grace = Duration::from_millis(30);
        let start = std::time::Instant::now();
        wait_for_sole_owner(&arc, grace).await;
        assert!(
            start.elapsed() >= grace,
            "must wait out the full grace period while a clone is held"
        );
        assert_eq!(
            Arc::strong_count(&arc),
            2,
            "gives up rather than blocking forever"
        );
    }
}
