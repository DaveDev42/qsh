//! Session broker: the subsystem that decouples session lifetime from the
//! transport connection (`docs/design/architecture.md` §3, ADR-0003).
//!
//! This module is the [`SessionBackend`] seam. It is **pure of transport**:
//! nothing under `broker/` names a `qsh_transport` type (nor the crate-root
//! re-exports of one), so a future out-of-process supervisor (ADR-0003, P1)
//! can implement the same trait over a UDS without touching the broker's
//! callers. `xtask arch` enforces the ban at module granularity (the
//! crate-level matrix cannot see intra-crate imports).
//!
//! What lives here:
//!
//! - a single-lock [`Broker`] registry (`SessionId → SessionHandle`),
//! - the [`SessionActor`] per session (see [`session`]),
//! - the [`ReplayRing`] behind [`ReplayStore`] (see [`ring`], ADR-0004),
//! - the writer [`lease`] rules,
//! - the closed [`Signal`] set (see [`signal`], CLI.md §6.7),
//! - an injected [`Clock`] (see [`clock`]) for every time decision, and
//! - the resume-TTL reaper ([`Broker::reap_once`]).
//!
//! Step 2 wires only the non-PTY [`PipeSource`]; the PTY source and the
//! server/`Ops` wiring land in later steps.

pub mod clock;
pub mod lease;
pub mod resume;
pub mod ring;
pub mod session;
pub mod signal;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use crate::config::ServeConfig;

pub use clock::{BoxFuture, Clock, SystemClock, TestClock};
pub use lease::{ConnectionId, LeaseHolder, TakeOutcome, WriterLease};
pub use resume::{
    PEER_FINGERPRINT_LEN, PeerFingerprint, RESUME_TOKEN_LEN, ResumeDenied, ResumeRegistry,
    ResumeToken, TokenHash,
};
pub use ring::{
    CloseReason, ControlEvent, Cursor, ReadError, ReadOut, ReplayEvent, ReplayRing, ReplayStore,
};
pub use session::{
    AttachGuard, AttachToken, FIRST_INPUT_STREAM, InputStreamId, PipeHandle, PipeSource,
    SessionActor, SessionConfig, SessionHandle, SessionInfo, SessionSource, SessionSpec,
    SessionState, SourceControl, SourceExit, SpawnedSource, WriteError,
};
pub use signal::Signal;

/// How often the resume-TTL reaper wakes (`docs/design/architecture.md` §3:
/// "TTL reaper task (30s tick)").
pub const REAPER_TICK: Duration = Duration::from_secs(30);

/// How long a closed session stays readable after its `session.closed`
/// entry was appended, so a follower whose next pull is in flight (network
/// RTT, a long-poll turnaround) still receives `session.closed` as the last
/// event (CLI.md §6.4) instead of `SESSION_NOT_FOUND`. `get`/`list`/`write`/
/// `close` treat the session as gone immediately; only `pull` sees it.
pub const CLOSED_RETENTION: Duration = Duration::from_secs(60);

/// Opaque session identifier. A Crockford base32 ULID string; the broker
/// treats it as an opaque, URL-safe token and never parses it (ADR-0007:
/// the client `Ops` assembles `session_ref`, the host only knows the id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub String);

impl SessionId {
    /// Mint a fresh id stamped with `now` (from the injected clock, so the
    /// broker has no time source of its own — `docs/design/testing.md` L2).
    pub fn generate_at(now: SystemTime) -> Self {
        SessionId(ulid::Ulid::from_datetime(now).to_string())
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
    /// No live session with that id (→ `SESSION_NOT_FOUND`).
    #[error("session not found")]
    NotFound,
    /// A caller-supplied argument is out of range — e.g. a `--after N`
    /// beyond the end of the stream (→ `INVALID_ARGUMENT`). Never means the
    /// session is gone.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The writer lease is held by another principal and `no_steal` was
    /// set (→ `SESSION_CONFLICT`).
    #[error("session writer lease is held by another principal")]
    Conflict,
    /// The session's writer connection is not the caller's (→
    /// `SESSION_CONFLICT`).
    #[error("connection does not hold the writer lease")]
    NotWriter,
    /// The session already exited/closed (→ `SESSION_CONFLICT`).
    #[error("session is no longer running")]
    NotRunning,
    /// The child is not draining input and the bounded input queue is full
    /// (→ `RESOURCE_EXHAUSTED`).
    #[error("session input queue is full")]
    Backpressure,
    /// The source refuses the request as a matter of policy/platform, not
    /// failure: no PTY backend on this host, or a `user` hint naming anyone
    /// but the serve account (`io::ErrorKind::Unsupported`; → `UNSUPPORTED`,
    /// CLI.md §7). Nothing was spawned.
    #[error("{0}")]
    Unsupported(String),
    /// Launching the source failed (→ `INTERNAL`).
    #[error("failed to start session: {0}")]
    Spawn(String),
    /// I/O against the session's source failed (→ `INTERNAL`).
    #[error("session source i/o failed: {0}")]
    Io(String),
    /// The session actor is gone (→ `INTERNAL`).
    #[error("session actor stopped")]
    Gone,
    /// Lost the race against [`Broker::close_all`]: the caller's
    /// `session.open` reached the registry lock after draining had already
    /// been committed (→ `RESOURCE_EXHAUSTED`). Nothing was spawned — the
    /// same outcome `require_not_draining`'s ordinary, earlier check gives,
    /// just for the narrow window that check alone cannot close.
    #[error("qsh serve is shutting down: refusing new sessions")]
    Draining,
}

/// Factory/spawn `io::Error` → [`BrokerError`]: `Unsupported` is a policy
/// answer (`UNSUPPORTED`), everything else is an `INTERNAL` spawn failure.
fn spawn_error(e: std::io::Error) -> BrokerError {
    if e.kind() == std::io::ErrorKind::Unsupported {
        BrokerError::Unsupported(e.to_string())
    } else {
        BrokerError::Spawn(e.to_string())
    }
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

/// Builds the byte producer for a new session. The broker owns the factory
/// so [`SessionBackend::open`] takes only a serialisable [`SessionSpec`] —
/// an out-of-process implementation builds its PTY on its own side of the
/// boundary. Step 4 supplies the PTY factory; tests supply [`PipeSource`]s.
pub trait SourceFactory: Send + Sync + 'static {
    /// Create the source for `spec` (not yet spawned).
    fn create(&self, spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>>;
}

impl<F> SourceFactory for F
where
    F: Fn(&SessionSpec) -> io::Result<Box<dyn SessionSource>> + Send + Sync + 'static,
{
    fn create(&self, spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>> {
        self(spec)
    }
}

/// A [`SourceFactory`] handing out cooperative [`PipeSource`]s and queueing
/// their test-side [`PipeHandle`]s (with the [`SessionSpec`] each was
/// opened with) for the caller to pick up in open order. This is how the
/// loopback harness (and the broker's own tests) drive session output/exit
/// without a PTY, and assert what reached the source.
#[derive(Default)]
pub struct PipeFactory {
    buffer: usize,
    ignored: Vec<Signal>,
    handles: Mutex<std::collections::VecDeque<(SessionSpec, PipeHandle)>>,
}

impl PipeFactory {
    /// Factory whose pipes buffer `buffer` bytes each way.
    pub fn new(buffer: usize) -> Self {
        Self::with_ignored_signals(buffer, &[])
    }

    /// Like [`PipeFactory::new`], but every source it creates ignores the
    /// listed signals ([`PipeSource::with_ignored_signals`]) — a "child"
    /// that survives HUP, to exercise the close escalation end to end.
    pub fn with_ignored_signals(buffer: usize, ignored: &[Signal]) -> Self {
        Self {
            buffer,
            ignored: ignored.to_vec(),
            handles: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// The handle of the oldest session opened through this factory that
    /// nobody has taken yet.
    pub fn take(&self) -> Option<PipeHandle> {
        self.take_with_spec().map(|(_, handle)| handle)
    }

    /// Like [`PipeFactory::take`], also returning the exact [`SessionSpec`]
    /// the broker handed to `create` — how tests assert that `argv`/`env`/
    /// `term`/window size survived the wire unchanged.
    pub fn take_with_spec(&self) -> Option<(SessionSpec, PipeHandle)> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// Number of handles waiting to be taken.
    pub fn pending(&self) -> usize {
        self.handles.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl std::fmt::Debug for PipeFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeFactory")
            .field("buffer", &self.buffer)
            .field("pending", &self.pending())
            .finish()
    }
}

impl SourceFactory for PipeFactory {
    fn create(&self, spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>> {
        let (source, handle) = PipeSource::with_ignored_signals(self.buffer.max(1), &self.ignored);
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back((spec.clone(), handle));
        Ok(Box::new(source))
    }
}

/// The headless stand-in `qsh serve` uses until the PTY source lands (PLAN
/// M2 Step 4): every session is a [`PipeSource`] whose "child" prints
/// [`ECHO_BANNER`] once, then echoes each input byte back as output, and
/// exits on the first fatal signal. Zero PTY code, but the whole
/// `session.*` control path — ACL, tickets, ring, lease, close escalation —
/// runs for real against it.
#[derive(Debug, Default, Clone, Copy)]
pub struct EchoPipeFactory;

/// What an [`EchoPipeFactory`] session prints first, so a human (or a
/// golden fixture) can tell it is talking to the stand-in.
pub const ECHO_BANNER: &[u8] = b"qsh: headless echo session\r\n";

impl SourceFactory for EchoPipeFactory {
    fn create(&self, _spec: &SessionSpec) -> io::Result<Box<dyn SessionSource>> {
        let (source, mut handle) = PipeSource::new(ECHO_PIPE_BUFFER);
        tokio::spawn(async move {
            if handle.write_output(ECHO_BANNER).await.is_err() {
                return;
            }
            loop {
                match handle.read_input(ECHO_PIPE_BUFFER).await {
                    Ok(data) if !data.is_empty() => {
                        if handle.write_output(&data).await.is_err() {
                            break;
                        }
                    }
                    // EOF: the actor dropped its input end (session closed).
                    _ => break,
                }
            }
        });
        Ok(Box::new(source))
    }
}

/// Buffer size of each [`EchoPipeFactory`] pipe.
const ECHO_PIPE_BUFFER: usize = 64 * 1024;

/// The in-process session broker.
///
/// The registry is a single mutex (architecture.md §3: "단일 lock, 저경합");
/// per-session concurrency lives in each [`SessionActor`]'s inbox, so the
/// registry lock is only held to look a handle up or insert/remove one.
/// Closed sessions linger in the registry (invisible to everything but
/// `pull`) for [`CLOSED_RETENTION`] so late followers can drain
/// `session.closed`; the reaper drops them afterwards.
pub struct Broker {
    registry: Mutex<HashMap<SessionId, SessionHandle>>,
    /// Set once, by [`Broker::close_all`], and never cleared. Only ever
    /// read or written while `registry`'s lock is held (`open_with`'s and
    /// `close_all`'s own comments) — that is what makes "admission is
    /// closed" and "the live-session snapshot was taken" a single atomic
    /// event, so a `session.open` racing a SIGTERM drain either loses
    /// before spawning anything or is guaranteed to land in the snapshot.
    /// A plain `bool` would do; `AtomicBool` only so reading it doesn't
    /// need `&mut`.
    draining: AtomicBool,
    clock: Arc<dyn Clock>,
    config: BrokerConfig,
    factory: Arc<dyn SourceFactory>,
    /// Resume credentials, keyed by session id (protocol.md §10). Lives
    /// beside the registry because its entries die exactly when a session
    /// does: the reaper and `close` both forget through it, so a closed
    /// session's `session.attach` is indistinguishable from one naming an
    /// id that never existed.
    resume: ResumeRegistry,
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
    /// Build a broker with the given clock, config and source factory.
    pub fn new(
        clock: Arc<dyn Clock>,
        config: BrokerConfig,
        factory: Arc<dyn SourceFactory>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(HashMap::new()),
            draining: AtomicBool::new(false),
            resume: ResumeRegistry::new(Arc::clone(&clock)),
            clock,
            config,
            factory,
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

    /// Number of live (not closed) sessions.
    pub fn session_count(&self) -> usize {
        self.lock()
            .values()
            .filter(|h| h.closed_at().is_none())
            .count()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, SessionHandle>> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now_rfc3339(&self) -> String {
        crate::config::rfc3339_of(self.clock.wall_now())
    }

    /// Look a live session up by id. A closed session is
    /// [`BrokerError::NotFound`] (CLI.md §6.4: after `session.closed`,
    /// `get`/`write`/`resize`/`close` are `SESSION_NOT_FOUND`).
    pub fn get(&self, id: &SessionId) -> Result<SessionHandle, BrokerError> {
        self.lock()
            .get(id)
            .filter(|h| h.closed_at().is_none())
            .cloned()
            .ok_or(BrokerError::NotFound)
    }

    /// Look a session up for reading: like [`Broker::get`] but a closed
    /// session still within [`CLOSED_RETENTION`] is returned so a follower
    /// can drain its trailing `session.closed`.
    pub fn get_for_read(&self, id: &SessionId) -> Result<SessionHandle, BrokerError> {
        self.lock().get(id).cloned().ok_or(BrokerError::NotFound)
    }

    /// A snapshot of every live session (`session.list`).
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut infos: Vec<SessionInfo> = self
            .lock()
            .values()
            .filter(|h| h.closed_at().is_none())
            .map(|h| h.info())
            .collect();
        infos.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        infos
    }

    /// Open a session from `spec` using the broker's [`SourceFactory`],
    /// spawn its actor task, and register it. Returns the new session's
    /// handle (its id is [`SessionHandle::id`]).
    ///
    /// The caller is responsible for having authorized this first (Step 3
    /// puts the ACL check ahead of `open` — never create a resource before
    /// authorization succeeds, `CLAUDE.md` security defaults).
    pub fn open(&self, spec: &SessionSpec) -> Result<SessionHandle, BrokerError> {
        let source = self.factory.create(spec).map_err(spawn_error)?;
        self.open_with(spec, source)
    }

    /// [`Broker::open`] with an explicit source (tests; Step 4 PTY wiring
    /// that already holds one). Same authorization precondition.
    pub fn open_with(
        &self,
        spec: &SessionSpec,
        source: Box<dyn SessionSource>,
    ) -> Result<SessionHandle, BrokerError> {
        // Held from the draining check through the registry insert below,
        // spanning `SessionActor::create` (which spawns the real child —
        // synchronous, no `.await`, so this never holds the lock across a
        // suspend point). This is what closes the race against
        // `Broker::close_all`'s own snapshot, which takes the same lock to
        // set `draining` and read the registry together: with both sides
        // serialized on one lock, a `session.open` either observes
        // `draining` before spawning anything (and refuses, orphaning
        // nothing) or completes its insert strictly before `close_all`
        // takes its snapshot (and is included in it) — there is no window
        // where the caller believes it opened a session `close_all` never
        // saw. `require_not_draining`'s check in `server/mod.rs` is the
        // cheap fast path for the ordinary case; this is the backstop for
        // the race that check alone cannot close.
        let mut registry = self.lock();
        if self.draining.load(Ordering::Acquire) {
            return Err(BrokerError::Draining);
        }
        let id = SessionId::generate_at(self.clock.wall_now());
        let created_at = self.now_rfc3339();
        let (handle, actor) = SessionActor::create(
            id.0.clone(),
            created_at,
            Arc::clone(&self.clock),
            spec,
            source,
            SessionConfig {
                replay_bytes: self.config.replay_bytes,
                close_grace: self.config.close_grace,
                ..SessionConfig::default()
            },
        )
        .map_err(spawn_error)?;
        tokio::spawn(actor.run());
        registry.insert(id, handle.clone());
        Ok(handle)
    }

    /// Close a session: signal its child (escalating per CLI.md §6.7 on
    /// the injected clock; no signal at all if it already exited), then
    /// append `session.closed{reason}` as its last entry. Resolves once the
    /// entry is in the ring and returns the final cumulative output offset
    /// (the `sequence` stamped on that `session.closed` entry — CLI.md §6.7
    /// `final_sequence`, which includes whatever the child emitted while
    /// dying). The session stays readable for [`CLOSED_RETENTION`] and is
    /// otherwise gone at once. A missing or already-closed session is
    /// [`BrokerError::NotFound`]; a close racing another close joins it.
    pub async fn close(
        &self,
        id: &SessionId,
        reason: CloseReason,
        signal: Option<Signal>,
    ) -> Result<u64, BrokerError> {
        let handle = self.get(id)?;
        handle.close(reason, signal).await;
        // The session is gone, so its resume credential must be too: a
        // later `session.attach` presenting it has to look exactly like one
        // naming an id that never existed (CLI.md §6.4, protocol.md §10-2).
        self.resume.forget(id);
        Ok(handle.info().last_sequence)
    }

    /// Close every live session through the same procedure as
    /// [`Broker::close`] — signal escalation, `session.closed{reason}`
    /// emission, resume-credential forgetting — concurrently, so the host's
    /// SIGTERM drain (`docs/CLI.md` §6.12, ADR-0003) does not take N times
    /// as long as one session's close for N sessions. Mirrors
    /// [`Broker::reap_once`]'s `doomed` loop, which the same escalation-time
    /// argument already applies to.
    ///
    /// Also flips [`Broker::draining`](Broker) — under the same registry
    /// lock this snapshot is taken with — so `session.open` is refused from
    /// this call forward with no gap `open_with`'s own comment doesn't
    /// already cover. Idempotent and safe to call again afterwards (a
    /// second pass's snapshot is empty, a cheap no-op); the caller is still
    /// responsible for having stopped admitting `session.attach`, which is
    /// not gated at this layer.
    pub async fn close_all(&self, reason: CloseReason) {
        let handles: Vec<(SessionId, SessionHandle)> = {
            let registry = self.lock();
            self.draining.store(true, Ordering::Release);
            registry
                .iter()
                .filter(|(_, h)| h.closed_at().is_none())
                .map(|(id, h)| (id.clone(), h.clone()))
                .collect()
        };
        let mut joins = tokio::task::JoinSet::new();
        for (id, handle) in handles {
            joins.spawn(async move {
                handle.close(reason, None).await;
                id
            });
        }
        while let Some(res) = joins.join_next().await {
            if let Ok(id) = res {
                self.resume.forget(&id);
            }
        }
    }

    /// Release any writer lease held by `conn` across every session
    /// (connection death). The sessions and their children survive
    /// (architecture.md §3 rule c).
    pub async fn release_connection(&self, conn: ConnectionId) {
        let handles: Vec<SessionHandle> = self
            .lock()
            .values()
            .filter(|h| h.closed_at().is_none())
            .cloned()
            .collect();
        for handle in handles {
            handle.release_connection(conn).await;
        }
    }

    /// One reaper pass: close every unattached session that is past its
    /// resume TTL, and drop closed sessions whose [`CLOSED_RETENTION`] has
    /// elapsed. Called on each [`REAPER_TICK`] by [`Broker::run_reaper`]
    /// and directly by tests (with an advanced [`TestClock`]). Returns the
    /// ids it closed.
    pub async fn reap_once(&self) -> Vec<SessionId> {
        let now = self.clock.now();
        let ttl = self.config.resume_ttl;
        // Decide under the registry lock, then act without holding it.
        let mut deadlines: HashMap<SessionId, Instant> = HashMap::new();
        let (doomed, expired): (Vec<(SessionId, SessionHandle, CloseReason)>, Vec<SessionId>) = {
            let registry = self.lock();
            for (id, handle) in registry.iter() {
                deadlines.insert(id.clone(), handle.resume_deadline(now, ttl));
            }
            let doomed = registry
                .iter()
                .filter_map(|(id, handle)| {
                    handle
                        .ttl_reap_reason(now, ttl)
                        .map(|reason| (id.clone(), handle.clone(), reason))
                })
                .collect();
            let expired = registry
                .iter()
                .filter(|(_, handle)| {
                    handle
                        .closed_at()
                        .is_some_and(|at| now.saturating_duration_since(at) >= CLOSED_RETENTION)
                })
                .map(|(id, _)| id.clone())
                .collect();
            (doomed, expired)
        };
        {
            let mut registry = self.lock();
            for id in expired {
                registry.remove(&id);
            }
        }
        // Re-anchor every live session's credential to that session's own
        // deadline, and drop the credentials whose session is gone and
        // whose TTL lapsed on its own. Without the re-anchoring a session
        // attached for longer than `resume_ttl` would keep running with an
        // expired credential and be orphaned by the next disconnect.
        self.resume.sync_expiry(&deadlines);
        // Close concurrently: each close may take up to three grace periods
        // of escalation, and one stubborn child must not delay the rest.
        // `close` is idempotent and joins a concurrent close, so a race with
        // an explicit close is harmless.
        let mut joins = tokio::task::JoinSet::new();
        for (id, handle, reason) in doomed {
            joins.spawn(async move {
                handle.close(reason, None).await;
                id
            });
        }
        let mut reaped = Vec::new();
        while let Some(res) = joins.join_next().await {
            if let Ok(id) = res {
                self.resume.forget(&id);
                reaped.push(id);
            }
        }
        reaped.sort();
        reaped
    }

    /// Run the reaper loop until the broker is dropped (it holds only a
    /// [`Weak`] reference, so it does not keep the broker alive). Spawn
    /// this on a task. Uses the injected clock, so
    /// `tokio::time::pause()`/`TestClock` drive it deterministically (no
    /// wall-clock `sleep`).
    pub async fn run_reaper(this: Weak<Self>) {
        loop {
            let Some(broker) = this.upgrade() else {
                return;
            };
            let clock = broker.clock();
            drop(broker);
            clock.sleep(REAPER_TICK).await;
            let Some(broker) = this.upgrade() else {
                return;
            };
            broker.reap_once().await;
        }
    }
}

/// The transport-free session seam (ADR-0003). A future out-of-process
/// supervisor implements the same trait over IPC; the broker's callers
/// (server dispatch, `Ops`) name only this.
///
/// It deliberately traffics in broker-local, serialisable types
/// ([`SessionId`], [`SessionSpec`], [`SessionInfo`], [`Cursor`],
/// [`ReadOut`], [`Signal`]) — never a `qsh_transport` type and never an
/// in-process object like a source — so the abstraction can cross a
/// process boundary later. Methods return [`BoxFuture`]s so the trait is
/// object-safe: callers hold an `Arc<dyn SessionBackend>` and the in-process
/// [`Broker`] can be swapped for an IPC client at runtime.
pub trait SessionBackend: Send + Sync {
    /// Open a new session from `spec`, returning its id. The caller has
    /// already authorized the request.
    fn open(&self, spec: &SessionSpec) -> Result<SessionId, BrokerError>;

    /// Snapshot one live session.
    fn get(&self, id: &SessionId) -> Result<SessionInfo, BrokerError>;

    /// Snapshot every live session.
    fn list(&self) -> Vec<SessionInfo>;

    /// Register one live attachment on `id`, suspending its resume TTL for
    /// as long as the returned token is alive; dropping the token detaches
    /// (architecture.md §3: the TTL runs on *unattached* sessions).
    ///
    /// The token is an opaque local RAII handle, never a value that crosses
    /// the seam: an out-of-process supervisor returns its own type whose
    /// `Drop` sends the detach over IPC. The caller has already authorized
    /// the attach.
    fn attach(&self, id: &SessionId) -> Result<Box<dyn AttachToken>, BrokerError>;

    /// Read from `cursor` (the cursor-pull primitive). `wait` bounds how
    /// long to block for new data. A cursor beyond the end of the stream is
    /// [`BrokerError::InvalidArgument`], not `NotFound`. Works on a closed
    /// session for [`CLOSED_RETENTION`] so `session.closed` can be drained.
    fn pull(
        &self,
        id: &SessionId,
        cursor: Cursor,
        max_bytes: usize,
        wait: Duration,
    ) -> BoxFuture<'_, Result<ReadOut, BrokerError>>;

    /// Write client input; requires `conn` to hold the writer lease.
    fn write(
        &self,
        id: &SessionId,
        conn: ConnectionId,
        data: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), BrokerError>>;

    /// Write client input carrying its cumulative offset (`input_seq` is
    /// the offset *after* the chunk). The session trims what it already
    /// applied and resolves to its applied offset — the value the peer is
    /// acked with. This is the exactly-once half of protocol.md §10-5: a
    /// reattach may retransmit its un-acked tail freely.
    fn write_at(
        &self,
        id: &SessionId,
        conn: ConnectionId,
        stream: InputStreamId,
        data: Vec<u8>,
        input_seq: u64,
    ) -> BoxFuture<'_, Result<u64, BrokerError>>;

    /// Reserve the id this attach's input axis will have, without creating
    /// it — so the id can be named to a credential rotation that has not
    /// decided yet, and a rotation that loses its race costs no axis slot.
    fn reserve_input_stream(&self, id: &SessionId) -> Result<InputStreamId, BrokerError>;

    /// Create the axis [`reserve_input_stream`](Self::reserve_input_stream)
    /// handed out, forked from `from` (the axis the resume credential
    /// names) and seeded with that axis's applied offset. `None` starts a
    /// client with no history at zero. Returns that starting offset.
    fn seed_input_stream(
        &self,
        id: &SessionId,
        stream: InputStreamId,
        from: Option<InputStreamId>,
    ) -> Result<u64, BrokerError>;

    /// Apply a window-size change.
    fn resize(
        &self,
        id: &SessionId,
        cols: u16,
        rows: u16,
    ) -> BoxFuture<'_, Result<(), BrokerError>>;

    /// Whether a `no_steal` take would conflict right now: another
    /// principal holds a live lease.
    ///
    /// A read-only probe, so a decision that is not final yet (an attach
    /// whose credential rotation can still lose a race) can answer
    /// `SESSION_CONFLICT` without moving the lease. The binding take stays
    /// where the stream is actually opened.
    fn lease_conflict(&self, id: &SessionId, principal: &str) -> bool;

    /// Try to take the writer lease.
    fn take_lease(
        &self,
        id: &SessionId,
        principal: String,
        conn: ConnectionId,
        no_steal: bool,
    ) -> BoxFuture<'_, Result<TakeOutcome, BrokerError>>;

    /// Close a session (see [`Broker::close`]); resolves to the final
    /// output offset. `signal` overrides the first escalation step; the
    /// dispatch edge parses it with [`Signal::parse`] and answers
    /// `INVALID_ARGUMENT` itself.
    fn close(
        &self,
        id: &SessionId,
        reason: CloseReason,
        signal: Option<Signal>,
    ) -> BoxFuture<'_, Result<u64, BrokerError>>;

    /// A connection died: release every writer lease it held. Sessions and
    /// their children survive (architecture.md §3 rule c).
    fn release_connection(&self, conn: ConnectionId) -> BoxFuture<'_, ()>;

    /// Close every live session at once, through the same procedure
    /// [`close`](Self::close) uses for one — the host's SIGTERM drain
    /// (`docs/CLI.md` §6.12, ADR-0003). The caller must already have
    /// stopped admitting new `session.open`/`session.attach`, or a session
    /// created concurrently is not covered.
    fn drain(&self, reason: CloseReason) -> BoxFuture<'_, ()>;

    /// The resume TTL an unattached session lives for (`[serve].resume_ttl`)
    /// — what the host reports as `SessionOpened.expires_at`.
    fn resume_ttl(&self) -> Duration;

    /// Mint the session's first resume credential, bound to `peer`
    /// (protocol.md §10). Called once, by `session.open`, **after**
    /// authorization; the plaintext is handed to the opening client and
    /// never stored.
    fn issue_resume(&self, id: &SessionId, peer: PeerFingerprint) -> ResumeToken;

    /// Check a presented credential without consuming it. This is the
    /// *first* gate of a reattach (protocol.md §10-2): it runs before the
    /// ACL call, and its single failure mode is non-distinguishing. On
    /// success it answers with the input axis the credential's lineage
    /// last used, which the redemption forks from.
    fn verify_resume(
        &self,
        id: &SessionId,
        presented: &[u8],
        peer: PeerFingerprint,
    ) -> Result<InputStreamId, ResumeDenied>;

    /// Honour a verified redemption: invalidate the presented credential
    /// and mint its successor, recording `input_stream` as the lineage's
    /// axis. Called **only** once the token check, the identity check and
    /// the ACL check have all passed.
    fn rotate_resume(
        &self,
        id: &SessionId,
        presented: &[u8],
        peer: PeerFingerprint,
        input_stream: InputStreamId,
    ) -> Result<ResumeToken, ResumeDenied>;
}

impl SessionBackend for Broker {
    fn open(&self, spec: &SessionSpec) -> Result<SessionId, BrokerError> {
        Ok(SessionId(Broker::open(self, spec)?.id().to_string()))
    }

    fn get(&self, id: &SessionId) -> Result<SessionInfo, BrokerError> {
        Ok(Broker::get(self, id)?.info())
    }

    fn list(&self) -> Vec<SessionInfo> {
        Broker::list(self)
    }

    fn attach(&self, id: &SessionId) -> Result<Box<dyn AttachToken>, BrokerError> {
        Ok(Box::new(Broker::get(self, id)?.attach_guard()))
    }

    fn pull(
        &self,
        id: &SessionId,
        cursor: Cursor,
        max_bytes: usize,
        wait: Duration,
    ) -> BoxFuture<'_, Result<ReadOut, BrokerError>> {
        let handle = self.get_for_read(id);
        Box::pin(async move {
            handle?
                .pull(cursor, max_bytes, wait, self.clock.as_ref())
                .await
                .map_err(|e| match e {
                    ReadError::CursorBeyondEnd { after, end } => BrokerError::InvalidArgument(
                        format!("cursor offset {after} is beyond the end of the stream ({end})"),
                    ),
                })
        })
    }

    fn write(
        &self,
        id: &SessionId,
        conn: ConnectionId,
        data: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), BrokerError>> {
        let handle = Broker::get(self, id);
        Box::pin(async move { handle?.write(conn, data).await.map_err(map_write_error) })
    }

    fn write_at(
        &self,
        id: &SessionId,
        conn: ConnectionId,
        stream: InputStreamId,
        data: Vec<u8>,
        input_seq: u64,
    ) -> BoxFuture<'_, Result<u64, BrokerError>> {
        let handle = Broker::get(self, id);
        Box::pin(async move {
            handle?
                .write_at(conn, data, Some((stream, input_seq)))
                .await
                .map_err(map_write_error)
        })
    }

    fn reserve_input_stream(&self, id: &SessionId) -> Result<InputStreamId, BrokerError> {
        Ok(Broker::get(self, id)?.reserve_input_stream())
    }

    fn seed_input_stream(
        &self,
        id: &SessionId,
        stream: InputStreamId,
        from: Option<InputStreamId>,
    ) -> Result<u64, BrokerError> {
        Ok(Broker::get(self, id)?.seed_input_stream(stream, from))
    }

    fn resize(
        &self,
        id: &SessionId,
        cols: u16,
        rows: u16,
    ) -> BoxFuture<'_, Result<(), BrokerError>> {
        let handle = Broker::get(self, id);
        Box::pin(async move { handle?.resize(cols, rows).await.map_err(map_write_error) })
    }

    fn lease_conflict(&self, id: &SessionId, principal: &str) -> bool {
        Broker::get(self, id).is_ok_and(|h| h.lease_conflict(principal))
    }

    fn take_lease(
        &self,
        id: &SessionId,
        principal: String,
        conn: ConnectionId,
        no_steal: bool,
    ) -> BoxFuture<'_, Result<TakeOutcome, BrokerError>> {
        let handle = Broker::get(self, id);
        Box::pin(async move {
            handle?
                .take_lease(principal, conn, no_steal)
                .await
                .map_err(map_write_error)
        })
    }

    fn close(
        &self,
        id: &SessionId,
        reason: CloseReason,
        signal: Option<Signal>,
    ) -> BoxFuture<'_, Result<u64, BrokerError>> {
        let id = id.clone();
        Box::pin(async move { Broker::close(self, &id, reason, signal).await })
    }

    fn release_connection(&self, conn: ConnectionId) -> BoxFuture<'_, ()> {
        Box::pin(Broker::release_connection(self, conn))
    }

    fn drain(&self, reason: CloseReason) -> BoxFuture<'_, ()> {
        Box::pin(Broker::close_all(self, reason))
    }

    fn resume_ttl(&self) -> Duration {
        self.config.resume_ttl
    }

    fn issue_resume(&self, id: &SessionId, peer: PeerFingerprint) -> ResumeToken {
        self.resume.issue(id, peer, self.config.resume_ttl)
    }

    fn verify_resume(
        &self,
        id: &SessionId,
        presented: &[u8],
        peer: PeerFingerprint,
    ) -> Result<InputStreamId, ResumeDenied> {
        self.resume.verify(id, presented, peer)
    }

    fn rotate_resume(
        &self,
        id: &SessionId,
        presented: &[u8],
        peer: PeerFingerprint,
        input_stream: InputStreamId,
    ) -> Result<ResumeToken, ResumeDenied> {
        self.resume
            .rotate(id, presented, peer, self.config.resume_ttl, input_stream)
    }
}

fn map_write_error(err: WriteError) -> BrokerError {
    match err {
        WriteError::NotWriter => BrokerError::NotWriter,
        WriteError::NotRunning => BrokerError::NotRunning,
        WriteError::Backpressure => BrokerError::Backpressure,
        // A peer that skipped input bytes is a protocol fault, not a
        // caller mistake the CLI can surface; the stream pump turns it into
        // a reset. `INVALID_ARGUMENT` is the closest control-stream code.
        err @ WriteError::InputGap { .. } => BrokerError::InvalidArgument(err.to_string()),
        WriteError::Io(e) => BrokerError::Io(e),
        WriteError::Gone => BrokerError::Gone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail instead of hanging when something is broken. Real time only
    /// elapses on failure.
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .expect("timed out")
    }

    fn test_broker(ttl: Duration) -> (Arc<Broker>, TestClock) {
        let clock = TestClock::new();
        let broker = Broker::new(
            Arc::new(clock.clone()),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: ttl,
                close_grace: Duration::from_millis(5000),
            },
            Arc::new(PipeFactory::new(64 * 1024)),
        );
        (broker, clock)
    }

    fn open_pipe(broker: &Broker) -> (SessionHandle, PipeHandle) {
        let (source, pipe) = PipeSource::new(64 * 1024);
        let handle = broker
            .open_with(&SessionSpec::default(), Box::new(source))
            .unwrap();
        (handle, pipe)
    }

    fn sid(h: &SessionHandle) -> SessionId {
        SessionId(h.id().to_string())
    }

    async fn wait_exited(handle: &SessionHandle, clock: &TestClock) {
        let mut cursor = Cursor::from_offset(0);
        loop {
            let out = within(handle.pull(cursor, 1024, Duration::from_secs(30), clock))
                .await
                .unwrap();
            cursor = out.next;
            if handle.state() == SessionState::Exited {
                return;
            }
        }
    }

    #[tokio::test]
    async fn open_get_list_close_roundtrip() {
        let (broker, clock) = test_broker(Duration::from_secs(3600));
        let (h1, _p1) = open_pipe(&broker);
        let (h2, _p2) = open_pipe(&broker);
        assert_eq!(broker.session_count(), 2);

        let id1 = sid(&h1);
        let info = broker.get(&id1).unwrap().info();
        assert_eq!(info.session_id, h1.id());
        assert_eq!(info.state, SessionState::Running);

        let list = broker.list();
        assert_eq!(list.len(), 2);

        within(broker.close(&id1, CloseReason::Closed, None))
            .await
            .unwrap();
        assert_eq!(broker.session_count(), 1);
        assert!(matches!(broker.get(&id1), Err(BrokerError::NotFound)));
        assert_eq!(broker.list().len(), 1);
        // A second close is NotFound (CLI.md §6.4), not a hang or a panic.
        assert_eq!(
            broker.close(&id1, CloseReason::Closed, None).await,
            Err(BrokerError::NotFound)
        );
        // But the closed session is still readable: `session.closed` is the
        // last event a follower sees.
        let out = within(SessionBackend::pull(
            broker.as_ref(),
            &id1,
            Cursor::from_offset(0),
            1024,
            Duration::ZERO,
        ))
        .await
        .unwrap();
        assert!(matches!(
            out.events.last(),
            Some(ReplayEvent::Control {
                event: ControlEvent::Closed {
                    reason: CloseReason::Closed
                },
                ..
            })
        ));
        // …until the retention window passes and the reaper drops it.
        clock.advance(CLOSED_RETENTION);
        broker.reap_once().await;
        assert!(matches!(
            SessionBackend::pull(
                broker.as_ref(),
                &id1,
                Cursor::from_offset(0),
                1024,
                Duration::ZERO
            )
            .await,
            Err(BrokerError::NotFound)
        ));
        // h2 still there.
        assert!(broker.get(&sid(&h2)).is_ok());
    }

    #[tokio::test]
    async fn backend_open_uses_the_source_factory_and_is_object_safe() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let backend: Arc<dyn SessionBackend> = broker.clone();
        let id = backend.open(&SessionSpec::default()).unwrap();
        assert_eq!(backend.get(&id).unwrap().state, SessionState::Running);
        assert_eq!(backend.list().len(), 1);
        within(backend.close(&id, CloseReason::Closed, None))
            .await
            .unwrap();
        assert!(matches!(backend.get(&id), Err(BrokerError::NotFound)));
    }

    #[tokio::test]
    async fn reaper_leaves_attached_sessions_and_reaps_unattached_running_ones() {
        let ttl = Duration::from_secs(60);
        let (broker, clock) = test_broker(ttl);
        let (attached, _pa) = open_pipe(&broker);
        let (_idle, pi) = open_pipe(&broker);
        let _guard = attached.attach_guard();

        // Not yet past TTL.
        clock.advance(ttl - Duration::from_secs(1));
        assert!(broker.reap_once().await.is_empty());

        // Past TTL: the idle one is reaped as TtlExpired (still running, so
        // it is signalled), the attached one survives.
        clock.advance(Duration::from_secs(2));
        let reaped = within(broker.reap_once()).await;
        assert_eq!(reaped.len(), 1);
        assert_eq!(pi.signals(), vec![Signal::Hup]);
        assert_eq!(broker.session_count(), 1);
        assert!(broker.get(&sid(&attached)).is_ok());
    }

    #[tokio::test]
    async fn reaper_reason_is_exit_for_an_already_exited_child_and_sends_no_signal() {
        let ttl = Duration::from_secs(60);
        let (broker, clock) = test_broker(ttl);
        let (handle, mut pipe) = open_pipe(&broker);
        pipe.exit(SourceExit {
            exit_code: Some(0),
            signal: None,
        });
        wait_exited(&handle, &clock).await;

        // The exited session's TTL runs from the exit instant.
        clock.advance(ttl + Duration::from_secs(1));
        let now = clock.now();
        assert_eq!(
            handle.ttl_reap_reason(now, ttl),
            Some(CloseReason::Exit),
            "an exited child reaps as Exit, not TtlExpired"
        );
        let reaped = within(broker.reap_once()).await;
        assert_eq!(reaped.len(), 1);
        assert!(
            pipe.signals().is_empty(),
            "an exited session is never signalled (CLI.md §6.7)"
        );
        let out = handle
            .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
            .await
            .unwrap();
        assert!(matches!(
            out.events.last(),
            Some(ReplayEvent::Control {
                event: ControlEvent::Closed {
                    reason: CloseReason::Exit
                },
                ..
            })
        ));
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
        assert_eq!(within(broker.reap_once()).await.len(), 1);
    }

    /// A credential must live exactly as long as the session it resumes.
    ///
    /// The session's own TTL does not run while it is attached — that is
    /// the product's premise, a shell worked in all day — so anchoring the
    /// credential to its issue instant instead would leave a healthy
    /// session with an expired credential and orphan it on the next
    /// disconnect (PRD §13). The reaper re-anchors on every pass.
    #[tokio::test]
    async fn an_attached_session_keeps_its_credential_past_the_ttl() {
        let ttl = Duration::from_secs(60);
        let (broker, clock) = test_broker(ttl);
        let (handle, _pipe) = open_pipe(&broker);
        let id = sid(&handle);
        let peer = PeerFingerprint::new([3u8; PEER_FINGERPRINT_LEN]);
        let token = SessionBackend::issue_resume(&*broker, &id, peer);

        {
            let _guard = handle.attach_guard();
            // Ten times the credential's nominal life, worked in the whole
            // time. Nothing reaps, and the credential still verifies.
            for _ in 0..10 {
                clock.advance(ttl);
                assert!(within(broker.reap_once()).await.is_empty());
            }
            assert!(
                SessionBackend::verify_resume(&*broker, &id, token.expose(), peer).is_ok(),
                "a session alive past its TTL must still be resumable"
            );
        }

        // Detached, the credential lapses with the session, not before it.
        clock.advance(ttl / 2);
        assert!(within(broker.reap_once()).await.is_empty());
        assert!(SessionBackend::verify_resume(&*broker, &id, token.expose(), peer).is_ok());
        clock.advance(ttl);
        assert_eq!(within(broker.reap_once()).await.len(), 1);
        assert_eq!(
            SessionBackend::verify_resume(&*broker, &id, token.expose(), peer),
            Err(ResumeDenied),
            "a reaped session's credential is forgotten with it"
        );
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

        within(broker.release_connection(conn)).await;
        assert_eq!(h1.info().writer, None);
        assert_eq!(h2.info().writer, None);
        assert_eq!(broker.session_count(), 2, "sessions survive lease loss");
    }

    /// `close_all` is `close`, applied to every live session at once: same
    /// `session.closed` emission, same resume-credential forgetting,
    /// nothing left running afterwards.
    #[tokio::test]
    async fn close_all_closes_every_live_session_and_forgets_its_credential() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (h1, _p1) = open_pipe(&broker);
        let (h2, _p2) = open_pipe(&broker);
        let id1 = sid(&h1);
        let id2 = sid(&h2);
        let peer = PeerFingerprint::new([9u8; PEER_FINGERPRINT_LEN]);
        let token1 = SessionBackend::issue_resume(&*broker, &id1, peer);
        assert_eq!(broker.session_count(), 2);

        within(broker.close_all(CloseReason::Closed)).await;

        assert_eq!(broker.session_count(), 0);
        assert!(matches!(broker.get(&id1), Err(BrokerError::NotFound)));
        assert!(matches!(broker.get(&id2), Err(BrokerError::NotFound)));
        assert_eq!(
            SessionBackend::verify_resume(&*broker, &id1, token1.expose(), peer),
            Err(ResumeDenied),
            "a session closed by drain forgets its credential exactly like an explicit close"
        );
        let out = within(SessionBackend::pull(
            broker.as_ref(),
            &id1,
            Cursor::from_offset(0),
            1024,
            Duration::ZERO,
        ))
        .await
        .unwrap();
        assert!(matches!(
            out.events.last(),
            Some(ReplayEvent::Control {
                event: ControlEvent::Closed {
                    reason: CloseReason::Closed
                },
                ..
            })
        ));
        // Idempotent: a second pass finds nothing left to close.
        within(broker.close_all(CloseReason::Closed)).await;
    }

    /// The [`SessionBackend`] seam a future out-of-process supervisor would
    /// implement, exercised the same way `Server::drain` calls it.
    #[tokio::test]
    async fn backend_drain_closes_every_session_via_the_trait_object() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let backend: Arc<dyn SessionBackend> = broker.clone();
        let id = backend.open(&SessionSpec::default()).unwrap();
        assert_eq!(backend.list().len(), 1);

        within(backend.drain(CloseReason::Closed)).await;

        assert!(backend.list().is_empty());
        assert!(matches!(backend.get(&id), Err(BrokerError::NotFound)));
    }

    #[tokio::test]
    async fn backend_write_maps_lease_errors() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (handle, _pipe) = open_pipe(&broker);
        let id = sid(&handle);
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
        within(SessionBackend::write(
            broker.as_ref(),
            &id,
            ConnectionId(1),
            b"ok".to_vec(),
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn no_steal_conflict_surfaces_through_the_backend() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (handle, _pipe) = open_pipe(&broker);
        let id = sid(&handle);
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

    #[tokio::test]
    async fn pull_beyond_end_is_invalid_argument_not_not_found() {
        let (broker, _clock) = test_broker(Duration::from_secs(3600));
        let (handle, _pipe) = open_pipe(&broker);
        let id = sid(&handle);
        let err = SessionBackend::pull(
            broker.as_ref(),
            &id,
            Cursor::from_offset(999),
            16,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, BrokerError::InvalidArgument(_)), "{err:?}");
        // The session is, of course, still there.
        assert!(broker.get(&id).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn run_reaper_uses_the_injected_clock_and_stops_with_the_broker() {
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
            Arc::new(PipeFactory::new(64 * 1024)),
        );
        let (source, _pipe) = PipeSource::new(64 * 1024);
        broker
            .open_with(&SessionSpec::default(), Box::new(source))
            .unwrap();
        let reaper = tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));

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
        // Dropping the broker ends the reaper on its next wake (Weak).
        drop(broker);
        tokio::time::advance(REAPER_TICK).await;
        within(reaper).await.unwrap();
    }
}
