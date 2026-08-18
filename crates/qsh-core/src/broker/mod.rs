//! Session broker: the subsystem that decouples session lifetime from the
//! transport connection (`docs/design/architecture.md` §3, ADR-0003).
//!
//! This module is the [`SessionBackend`] seam. It is **pure of transport**:
//! nothing under `broker/` names a `qsh_transport` type, so a future
//! out-of-process supervisor (ADR-0003, P1) can implement the same trait
//! over a UDS without touching the broker's callers. `xtask arch` enforces
//! the no-`qsh_transport`-import rule at module granularity (the crate-level
//! matrix cannot see intra-crate imports).
//!
//! What lives here:
//!
//! - a single-lock [`Broker`] registry (`SessionId → SessionHandle`),
//! - the [`SessionActor`] per session (see [`session`]),
//! - the [`ReplayRing`] behind [`ReplayStore`] (see [`ring`], ADR-0004),
//! - the writer [`lease`] rules,
//! - an injected [`Clock`] (see [`clock`]) for every time decision, and
//! - the resume-TTL reaper ([`Broker::reap_once`]).
//!
//! Step 2 wires only the non-PTY [`PipeSource`]; the PTY source and the
//! server/`Ops` wiring land in later steps.

pub mod clock;
pub mod lease;
pub mod ring;
pub mod session;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::ServeConfig;

pub use clock::{Clock, SystemClock, TestClock};
pub use lease::{ConnectionId, LeaseHolder, TakeOutcome, WriterLease};
pub use ring::{
    CloseReason, ControlEvent, Cursor, ReadError, ReadOut, ReplayEvent, ReplayRing, ReplayStore,
};
pub use session::{
    AttachGuard, PipeHandle, PipeSource, SessionActor, SessionConfig, SessionHandle, SessionInfo,
    SessionSource, SessionSpec, SessionState, SourceControl, SourceExit, SpawnedSource, WriteError,
};

/// How often the resume-TTL reaper wakes (`docs/design/architecture.md` §3:
/// "TTL reaper task (30s tick)").
pub const REAPER_TICK: Duration = Duration::from_secs(30);

/// Opaque session identifier. A Crockford base32 ULID string; the broker
/// treats it as an opaque, URL-safe token and never parses it (ADR-0007:
/// the client `Ops` assembles `session_ref`, the host only knows the id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub String);

impl SessionId {
    /// Mint a fresh id.
    pub fn generate() -> Self {
        SessionId(ulid::Ulid::new().to_string())
    }

    /// Borrow the string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a broker call failed. Each variant maps to an existing
/// [`qsh_proto::ErrorCode`] (Step 3 does the mapping at the dispatch edge);
/// the broker does not depend on the CLI envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// No session with that id (→ `SESSION_NOT_FOUND`).
    #[error("session not found")]
    NotFound,
    /// The writer lease is held by someone else and `no_steal` was set
    /// (→ `SESSION_CONFLICT`).
    #[error("session writer lease is held by another connection")]
    Conflict,
    /// The session's writer connection is not the caller's (→
    /// `SESSION_CONFLICT`).
    #[error("connection does not hold the writer lease")]
    NotWriter,
    /// The session already exited/closed (→ `SESSION_CONFLICT`).
    #[error("session is no longer running")]
    NotRunning,
    /// Launching the source failed (→ `INTERNAL`).
    #[error("failed to start session: {0}")]
    Spawn(String),
    /// The session actor is gone (→ `INTERNAL`).
    #[error("session actor stopped")]
    Gone,
}

/// Effective, validated broker settings resolved from `[serve]`
/// (`docs/PRD.md` §13: 8 MiB replay, 24 h TTL; CLI.md §6.7 5 s grace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerConfig {
    /// Per-session replay ring byte budget (`[serve].replay_bytes`).
    pub replay_bytes: usize,
    /// Resume TTL for unattached sessions (`[serve].resume_ttl`).
    pub resume_ttl: Duration,
    /// Per-step grace in the close signal escalation
    /// (`[serve].close_grace_ms`).
    pub close_grace: Duration,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            replay_bytes: ServeConfig::DEFAULT_REPLAY_BYTES,
            resume_ttl: Duration::from_secs(ServeConfig::DEFAULT_RESUME_TTL_SECS),
            close_grace: Duration::from_millis(ServeConfig::DEFAULT_CLOSE_GRACE_MS),
        }
    }
}

impl BrokerConfig {
    /// Resolve from a parsed `[serve]` section, applying the documented
    /// defaults for any unset field.
    pub fn from_serve(serve: &ServeConfig) -> Self {
        Self {
            replay_bytes: serve.replay_bytes(),
            resume_ttl: serve.resume_ttl(),
            close_grace: serve.close_grace(),
        }
    }
}

/// The in-process session broker.
///
/// The registry is a single mutex (architecture.md §3: "단일 lock, 저경합");
/// per-session concurrency lives in each [`SessionActor`]'s inbox, so the
/// registry lock is only held to look a handle up or insert/remove one.
pub struct Broker {
    registry: Mutex<HashMap<SessionId, SessionHandle>>,
    clock: Arc<dyn Clock>,
    config: BrokerConfig,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("sessions", &self.session_count())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Broker {
    /// Build a broker with the given clock and config.
    pub fn new(clock: Arc<dyn Clock>, config: BrokerConfig) -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(HashMap::new()),
            clock,
            config,
        })
    }

    /// The clock every session shares.
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// Resolved config.
    pub fn config(&self) -> BrokerConfig {
        self.config
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, SessionHandle>> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now_rfc3339(&self) -> String {
        let secs = self
            .clock
            .wall_now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        OffsetDateTime::from_unix_timestamp(secs as i64)
            .ok()
            .and_then(|t| t.format(&Rfc3339).ok())
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
    }

    /// Look a session up by id.
    pub fn get(&self, id: &SessionId) -> Result<SessionHandle, BrokerError> {
        self.lock().get(id).cloned().ok_or(BrokerError::NotFound)
    }

    /// A snapshot of every session (`session.list`).
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut infos: Vec<SessionInfo> = self.lock().values().map(|h| h.info()).collect();
        infos.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        infos
    }

    /// Open a session, spawn its actor task, and register it. Returns the
    /// new session's handle (its id is [`SessionHandle::id`]).
    ///
    /// The caller is responsible for having authorized this first (Step 3
    /// puts the ACL check ahead of `open` — never create a resource before
    /// authorization succeeds, `CLAUDE.md` security defaults).
    pub fn open(
        &self,
        spec: &SessionSpec,
        source: Box<dyn SessionSource>,
    ) -> Result<SessionHandle, BrokerError> {
        let id = SessionId::generate();
        let created_at = self.now_rfc3339();
        let (handle, actor) = SessionActor::create(
            id.0.clone(),
            created_at,
            Arc::clone(&self.clock),
            spec,
            source,
            SessionConfig {
                replay_bytes: self.config.replay_bytes,
                ..SessionConfig::default()
            },
        )
        .map_err(|e| BrokerError::Spawn(e.to_string()))?;
        tokio::spawn(actor.run());
        self.lock().insert(id, handle.clone());
        Ok(handle)
    }

    /// Remove and close a session, appending `session.closed{reason}`.
    /// A missing session is [`BrokerError::NotFound`].
    pub async fn close(
        &self,
        id: &SessionId,
        reason: CloseReason,
        signal: Option<String>,
    ) -> Result<(), BrokerError> {
        let handle = self.lock().remove(id).ok_or(BrokerError::NotFound)?;
        handle.close(reason, signal).await;
        Ok(())
    }

    /// Release any writer lease held by `conn` across every session
    /// (connection death). The sessions and their children survive
    /// (architecture.md §3 rule c).
    pub async fn release_connection(&self, conn: ConnectionId) {
        let handles: Vec<SessionHandle> = self.lock().values().cloned().collect();
        for handle in handles {
            handle.release_connection(conn).await;
        }
    }

    /// One reaper pass: close every unattached session that is past its
    /// resume TTL. Called on each [`REAPER_TICK`] by [`Broker::run_reaper`]
    /// and directly by tests (with an advanced [`TestClock`]). Returns the
    /// ids it reaped.
    pub async fn reap_once(&self) -> Vec<SessionId> {
        let now = self.clock.now();
        let ttl = self.config.resume_ttl;
        // Decide under the registry lock, then act without holding it.
        let doomed: Vec<(SessionId, SessionHandle, CloseReason)> = {
            let registry = self.lock();
            registry
                .iter()
                .filter_map(|(id, handle)| {
                    handle
                        .ttl_reap_reason(now, ttl)
                        .map(|reason| (id.clone(), handle.clone(), reason))
                })
                .collect()
        };
        let mut reaped = Vec::new();
        for (id, handle, reason) in doomed {
            // Re-check membership: a concurrent close may have won.
            if self.lock().remove(&id).is_some() {
                handle.close(reason, None).await;
                reaped.push(id);
            }
        }
        reaped
    }

    /// Run the reaper loop until `self` is dropped. Spawn this on a task.
    /// Uses the injected clock, so `tokio::time::pause()`/`TestClock` drive
    /// it deterministically (no wall-clock `sleep`).
    pub async fn run_reaper(self: Arc<Self>) {
        loop {
            self.clock.sleep(REAPER_TICK).await;
            self.reap_once().await;
        }
    }
}

/// The transport-free session seam (ADR-0003). A future out-of-process
/// supervisor implements the same trait over IPC; the broker's callers
/// (server dispatch, `Ops`) name only this.
///
/// It deliberately traffics in broker-local types ([`SessionId`],
/// [`SessionInfo`], [`Cursor`], [`ReadOut`]) — never a `qsh_transport` type —
/// so the abstraction can cross a process boundary later.
pub trait SessionBackend: Send + Sync {
    /// Open a new session from `spec`, returning its id.
    fn open(
        &self,
        spec: &SessionSpec,
        source: Box<dyn SessionSource>,
    ) -> Result<SessionId, BrokerError>;

    /// Snapshot one session.
    fn get(&self, id: &SessionId) -> Result<SessionInfo, BrokerError>;

    /// Snapshot every session.
    fn list(&self) -> Vec<SessionInfo>;

    /// Read from `cursor` (the cursor-pull primitive). `wait` bounds how
    /// long to block for new data.
    fn pull(
        &self,
        id: &SessionId,
        cursor: Cursor,
        max_bytes: usize,
        wait: Duration,
    ) -> impl std::future::Future<Output = Result<ReadOut, BrokerError>> + Send;

    /// Write client input; requires `conn` to hold the writer lease.
    fn write(
        &self,
        id: &SessionId,
        conn: ConnectionId,
        data: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), BrokerError>> + Send;

    /// Apply a window-size change.
    fn resize(
        &self,
        id: &SessionId,
        cols: u16,
        rows: u16,
    ) -> impl std::future::Future<Output = Result<(), BrokerError>> + Send;

    /// Try to take the writer lease.
    fn take_lease(
        &self,
        id: &SessionId,
        principal: String,
        conn: ConnectionId,
        no_steal: bool,
    ) -> impl std::future::Future<Output = Result<TakeOutcome, BrokerError>> + Send;

    /// Close a session.
    fn close(
        &self,
        id: &SessionId,
        reason: CloseReason,
        signal: Option<String>,
    ) -> impl std::future::Future<Output = Result<(), BrokerError>> + Send;
}

impl SessionBackend for Broker {
    fn open(
        &self,
        spec: &SessionSpec,
        source: Box<dyn SessionSource>,
    ) -> Result<SessionId, BrokerError> {
        Ok(SessionId(
            Broker::open(self, spec, source)?.id().to_string(),
        ))
    }

    fn get(&self, id: &SessionId) -> Result<SessionInfo, BrokerError> {
        Ok(Broker::get(self, id)?.info())
    }

    fn list(&self) -> Vec<SessionInfo> {
        Broker::list(self)
    }

    async fn pull(
        &self,
        id: &SessionId,
        cursor: Cursor,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<ReadOut, BrokerError> {
        let handle = Broker::get(self, id)?;
        handle
            .pull(cursor, max_bytes, wait, self.clock.as_ref())
            .await
            .map_err(|e| match e {
                ReadError::CursorBeyondEnd { .. } => BrokerError::NotFound,
            })
    }

    async fn write(
        &self,
        id: &SessionId,
        conn: ConnectionId,
        data: Vec<u8>,
    ) -> Result<(), BrokerError> {
        let handle = Broker::get(self, id)?;
        handle.write(conn, data).await.map_err(map_write_error)
    }

    async fn resize(&self, id: &SessionId, cols: u16, rows: u16) -> Result<(), BrokerError> {
        let handle = Broker::get(self, id)?;
        handle.resize(cols, rows).await.map_err(map_write_error)
    }

    async fn take_lease(
        &self,
        id: &SessionId,
        principal: String,
        conn: ConnectionId,
        no_steal: bool,
    ) -> Result<TakeOutcome, BrokerError> {
        let handle = Broker::get(self, id)?;
        handle
            .take_lease(principal, conn, no_steal)
            .await
            .map_err(map_write_error)
    }

    async fn close(
        &self,
        id: &SessionId,
        reason: CloseReason,
        signal: Option<String>,
    ) -> Result<(), BrokerError> {
        Broker::close(self, id, reason, signal).await
    }
}

fn map_write_error(err: WriteError) -> BrokerError {
    match err {
        WriteError::NotWriter => BrokerError::NotWriter,
        WriteError::NotRunning => BrokerError::NotRunning,
        WriteError::Io(_) => BrokerError::Gone,
        WriteError::Gone => BrokerError::Gone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_broker(ttl: Duration) -> (Arc<Broker>, TestClock) {
        let clock = TestClock::new();
        let broker = Broker::new(
            Arc::new(clock.clone()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: ttl,
                close_grace: Duration::from_millis(5000),
            },
        );
        (broker, clock)
    }

    fn open_pipe(broker: &Broker) -> (SessionHandle, PipeHandle) {
        let (source, pipe) = PipeSource::new(64 * 1024);
        let handle = broker
            .open(&SessionSpec::default(), Box::new(source))
            .unwrap();
        (handle, pipe)
    }

    #[tokio::test]
    async fn open_get_list_close_roundtrip() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (h1, _p1) = open_pipe(&broker);
        let (h2, _p2) = open_pipe(&broker);
        assert_eq!(broker.session_count(), 2);

        let id1 = SessionId(h1.id().to_string());
        let info = broker.get(&id1).unwrap().info();
        assert_eq!(info.session_id, h1.id());
        assert_eq!(info.state, SessionState::Running);

        let list = broker.list();
        assert_eq!(list.len(), 2);

        broker.close(&id1, CloseReason::Closed, None).await.unwrap();
        assert_eq!(broker.session_count(), 1);
        assert!(matches!(broker.get(&id1), Err(BrokerError::NotFound)));
        // h2 still there.
        assert!(broker.get(&SessionId(h2.id().to_string())).is_ok());
    }

    #[tokio::test]
    async fn reaper_leaves_attached_sessions_and_reaps_unattached_running_ones() {
        let ttl = Duration::from_secs(60);
        let (broker, clock) = test_broker(ttl);
        let (attached, _pa) = open_pipe(&broker);
        let (_idle, _pi) = open_pipe(&broker);
        let _guard = attached.attach_guard();

        // Not yet past TTL.
        clock.advance(ttl - Duration::from_secs(1));
        assert!(broker.reap_once().await.is_empty());

        // Past TTL: the idle one is reaped as TtlExpired (still running),
        // the attached one survives.
        clock.advance(Duration::from_secs(2));
        let reaped = broker.reap_once().await;
        assert_eq!(reaped.len(), 1);
        assert_eq!(broker.session_count(), 1);
        assert!(broker.get(&SessionId(attached.id().to_string())).is_ok());
    }

    #[tokio::test]
    async fn reaper_reason_is_exit_for_an_already_exited_child() {
        let ttl = Duration::from_secs(60);
        let (broker, clock) = test_broker(ttl);
        let (handle, mut pipe) = open_pipe(&broker);
        pipe.exit(SourceExit {
            exit_code: Some(0),
            signal: None,
        });
        // Let the actor observe EOF + exit and flip to Exited.
        for _ in 0..10 {
            tokio::task::yield_now().await;
            if handle.state() == SessionState::Exited {
                break;
            }
        }
        assert_eq!(handle.state(), SessionState::Exited);

        // The exited session's TTL runs from the exit instant.
        clock.advance(ttl + Duration::from_secs(1));
        let now = clock.now();
        assert_eq!(
            handle.ttl_reap_reason(now, ttl),
            Some(CloseReason::Exit),
            "an exited child reaps as Exit, not TtlExpired"
        );
        let reaped = broker.reap_once().await;
        assert_eq!(reaped.len(), 1);
    }

    #[tokio::test]
    async fn detach_restarts_the_ttl_clock() {
        let ttl = Duration::from_secs(60);
        let (broker, clock) = test_broker(ttl);
        let (handle, _pipe) = open_pipe(&broker);
        {
            let _guard = handle.attach_guard();
            clock.advance(Duration::from_secs(120)); // long attach
            assert!(broker.reap_once().await.is_empty());
        } // detach here; TTL restarts from now
        assert!(broker.reap_once().await.is_empty());
        clock.advance(ttl + Duration::from_secs(1));
        assert_eq!(broker.reap_once().await.len(), 1);
    }

    #[tokio::test]
    async fn release_connection_drops_leases_everywhere_but_keeps_sessions() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (h1, _p1) = open_pipe(&broker);
        let (h2, _p2) = open_pipe(&broker);
        let conn = ConnectionId(7);
        h1.take_lease("device:a", conn, false).await.unwrap();
        h2.take_lease("device:a", conn, false).await.unwrap();
        assert_eq!(h1.info().writer.as_deref(), Some("device:a"));

        broker.release_connection(conn).await;
        assert_eq!(h1.info().writer, None);
        assert_eq!(h2.info().writer, None);
        assert_eq!(broker.session_count(), 2, "sessions survive lease loss");
    }

    #[tokio::test]
    async fn backend_write_maps_lease_errors() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (handle, _pipe) = open_pipe(&broker);
        let id = SessionId(handle.id().to_string());
        // No lease.
        assert_eq!(
            SessionBackend::write(broker.as_ref(), &id, ConnectionId(1), b"x".to_vec()).await,
            Err(BrokerError::NotWriter)
        );
        // Take + write via the backend trait.
        SessionBackend::take_lease(
            broker.as_ref(),
            &id,
            "device:a".into(),
            ConnectionId(1),
            false,
        )
        .await
        .unwrap();
        SessionBackend::write(broker.as_ref(), &id, ConnectionId(1), b"ok".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn no_steal_conflict_surfaces_through_the_backend() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (handle, _pipe) = open_pipe(&broker);
        let id = SessionId(handle.id().to_string());
        handle
            .take_lease("device:a", ConnectionId(1), false)
            .await
            .unwrap();
        let outcome = SessionBackend::take_lease(
            broker.as_ref(),
            &id,
            "device:b".into(),
            ConnectionId(2),
            true,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, TakeOutcome::Conflict { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn run_reaper_uses_the_injected_clock() {
        // A SystemClock reaper under tokio pause: advancing tokio time
        // fires the tick without any real sleep.
        let clock = SystemClock;
        let broker = Broker::new(
            Arc::new(clock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(10),
                close_grace: Duration::from_millis(5000),
            },
        );
        let (source, _pipe) = PipeSource::new(64 * 1024);
        broker
            .open(&SessionSpec::default(), Box::new(source))
            .unwrap();
        let reaper = tokio::spawn(Arc::clone(&broker).run_reaper());

        // Past TTL + a reaper tick.
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::time::advance(REAPER_TICK).await;
        // Give the reaper task a turn.
        for _ in 0..20 {
            tokio::task::yield_now().await;
            if broker.session_count() == 0 {
                break;
            }
        }
        assert_eq!(broker.session_count(), 0);
        reaper.abort();
    }
}
