//! Per-session actor and the [`SessionSource`] seam
//! (`docs/design/architecture.md` §3 "SessionActor").
//!
//! One [`SessionActor`] runs per session as its own tokio task. It owns the
//! byte producer ([`SessionSource`]) and drives a single loop that:
//!
//! - pumps source output into the [`ReplayRing`] — the **only** place
//!   cumulative offsets are assigned — and wakes readers,
//! - serves the mpsc inbox ([`Command`]): `Write` / `Resize` / `Signal` /
//!   `TakeLease` / `ReleaseConnection` / `Attach` / `Detach` / `Close`,
//! - observes child exit, drains the remaining output, then appends the
//!   `session.exit` control entry (output-before-exit ordering,
//!   `docs/design/testing.md` L5).
//!
//! Reads do **not** go through the inbox or the lease: the ring lives behind
//! a mutex in [`SessionShared`] and [`SessionHandle::pull`] reads it directly
//! (architecture.md §3 "reads need no lease"; the pump never blocks on a
//! consumer). The producer is only ever a PTY (Step 4) or, here, a
//! [`PipeSource`] for headless tests — no PTY code in this step.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc, oneshot};

use super::clock::{BoxFuture, Clock};
use super::lease::{ConnectionId, TakeOutcome, WriterLease};
use super::ring::{
    Cursor, RING_CHUNK_MAX, ReadError, ReadOut, ReplayRing, ReplayStore,
    {CloseReason, ControlEvent},
};

/// What to launch. For [`PipeSource`] this is metadata only; the PTY source
/// (Step 4) consumes it fully.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSpec {
    /// Program + args. Empty ⇒ login shell (host decides).
    pub argv: Vec<String>,
    /// Extra environment.
    pub env: Vec<(String, String)>,
    /// `TERM` value.
    pub term: Option<String>,
    /// Initial window size (cols, rows).
    pub cols: u16,
    /// Initial window size rows.
    pub rows: u16,
    /// `user@` hint (validated by the host, not here — CLI.md §7).
    pub user: Option<String>,
}

/// How a source's child ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceExit {
    /// Exit code, or `None` if terminated by signal.
    pub exit_code: Option<i32>,
    /// Terminating signal (`SIGTERM` form), if any.
    pub signal: Option<String>,
}

/// The output/input/exit trio a spawned source hands back.
pub struct SpawnedSource {
    /// Bytes the child produced (PTY master read side / pipe).
    pub output: Box<dyn AsyncRead + Send + Unpin>,
    /// Where client input goes (PTY master write side / pipe).
    pub input: Box<dyn AsyncWrite + Send + Unpin>,
    /// Resize / signal control.
    pub control: Box<dyn SourceControl>,
    /// Resolves when the child exits. Owned (not `&mut self`) so it can be
    /// selected on across the actor loop without borrow gymnastics.
    pub wait: BoxFuture<'static, SourceExit>,
}

/// Out-of-band control over a running source.
pub trait SourceControl: Send {
    /// Apply a window-size change (`TIOCSWINSZ` for PTY; no-op for a pipe).
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;
    /// Deliver a signal to the child's process group (`killpg` for PTY;
    /// recorded but inert for a pipe). `signal` is in `SIGTERM` form.
    fn signal(&mut self, signal: &str) -> io::Result<()>;
}

/// The byte producer behind a session. In-process only in P0.
pub trait SessionSource: Send + 'static {
    /// Launch and hand back the I/O trio. Called once, by the actor.
    fn spawn(self: Box<Self>, spec: &SessionSpec) -> io::Result<SpawnedSource>;
}

/// Lifecycle state (CLI.md §5 `Session.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Child is running.
    Running,
    /// Child exited; session retained for late readers until TTL.
    Exited,
}

impl SessionState {
    /// The CLI string form.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::Running => "running",
            SessionState::Exited => "exited",
        }
    }
}

/// A point-in-time snapshot of a session for `session.get` / `session.list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Opaque session id (ULID). `session_ref`/`host` are assembled by the
    /// client `Ops` (ADR-0007) and are not present here.
    pub session_id: String,
    /// Lifecycle state.
    pub state: SessionState,
    /// Writer-lease holder principal, or `None`.
    pub writer: Option<String>,
    /// Wall-clock creation time (RFC 3339, whole seconds).
    pub created_at: String,
    /// Highest cumulative output offset so far.
    pub last_sequence: u64,
}

/// Mutable session metadata published to readers (`session.list`/`get` and
/// `writer_changed` broadcasts). The actor is the only writer; readers take
/// the lock briefly.
#[derive(Debug)]
struct Meta {
    state: SessionState,
    lease: WriterLease,
    /// Number of live attachments. TTL only runs while this is zero.
    attached: usize,
    /// Monotonic instant the TTL is measured from when `attached == 0`:
    /// creation, last detach, or exit.
    ttl_base: Instant,
    /// `true` once a `Closed` control has been appended (idempotent close).
    closed: bool,
}

/// State shared between the actor and every [`SessionHandle`] clone.
pub struct SessionShared {
    id: String,
    created_at: String,
    clock: Arc<dyn Clock>,
    ring: Mutex<Box<dyn ReplayStore>>,
    /// Bumped on every ring append so `pull(..., wait)` can sleep until
    /// there is something new.
    notify: Notify,
    meta: Mutex<Meta>,
}

impl std::fmt::Debug for SessionShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionShared")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl SessionShared {
    fn note_append(&self) {
        self.notify.notify_waiters();
    }
}

/// Cheap, cloneable handle to a session. Held by the registry and by every
/// consumer. Dropping all handles lets the actor's inbox close.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    shared: Arc<SessionShared>,
    inbox: mpsc::Sender<Command>,
}

/// Inbox messages (architecture.md §3 "mpsc 인박스").
enum Command {
    Write {
        conn: ConnectionId,
        data: Vec<u8>,
        resp: oneshot::Sender<Result<(), WriteError>>,
    },
    Resize {
        cols: u16,
        rows: u16,
        resp: oneshot::Sender<io::Result<()>>,
    },
    Signal {
        signal: String,
        resp: oneshot::Sender<io::Result<()>>,
    },
    TakeLease {
        principal: String,
        conn: ConnectionId,
        no_steal: bool,
        resp: oneshot::Sender<TakeOutcome>,
    },
    ReleaseConnection {
        conn: ConnectionId,
        resp: oneshot::Sender<()>,
    },
    Close {
        reason: CloseReason,
        signal: Option<String>,
        resp: oneshot::Sender<()>,
    },
}

/// Why a write was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// The writing connection does not hold the lease.
    #[error("connection does not hold the writer lease")]
    NotWriter,
    /// The session has already exited or closed; input is discarded.
    #[error("session is no longer running")]
    NotRunning,
    /// Writing to the source failed.
    #[error("write to session source failed: {0}")]
    Io(String),
    /// The actor is gone.
    #[error("session actor stopped")]
    Gone,
}

impl SessionHandle {
    /// The opaque session id.
    pub fn id(&self) -> &str {
        &self.shared.id
    }

    /// A point-in-time snapshot.
    pub fn info(&self) -> SessionInfo {
        let meta = self.shared.meta.lock().unwrap_or_else(|e| e.into_inner());
        let last_sequence = self
            .shared
            .ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .end();
        SessionInfo {
            session_id: self.shared.id.clone(),
            state: meta.state,
            writer: meta.lease.holder().map(|h| h.principal.clone()),
            created_at: self.shared.created_at.clone(),
            last_sequence,
        }
    }

    /// Read from `cursor`, returning at most `max_bytes` of output plus any
    /// control entries due, in stream order. If nothing is ready and
    /// `wait` is non-zero, sleep on `clock` until there is something or the
    /// deadline passes (the cursor-pull primitive — architecture.md §3;
    /// the same call backs `session read --wait`, `--follow` and MCP
    /// long-poll). Never needs the lease.
    pub async fn pull(
        &self,
        cursor: Cursor,
        max_bytes: usize,
        wait: Duration,
        clock: &dyn Clock,
    ) -> Result<ReadOut, ReadError> {
        let deadline = clock.now() + wait;
        loop {
            // Register for wakeups *before* reading. `Notified` only becomes
            // a registered waiter once polled; `enable()` registers it now
            // so an append that lands between this read and the await below
            // still wakes us (otherwise `notify_waiters()` finds no waiter
            // and the wakeup is lost — a `pull(wait=∞)` would hang forever).
            let notified = self.shared.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let out = {
                let ring = self.shared.ring.lock().unwrap_or_else(|e| e.into_inner());
                ring.read(cursor, max_bytes)?
            };
            if !out.events.is_empty() || wait.is_zero() {
                return Ok(out);
            }
            let now = clock.now();
            if now >= deadline {
                return Ok(out);
            }
            tokio::select! {
                _ = notified => {}
                _ = clock.sleep_until(deadline) => {
                    // Final non-blocking read so a same-instant append is
                    // not dropped on the deadline.
                    let ring = self.shared.ring.lock().unwrap_or_else(|e| e.into_inner());
                    return ring.read(cursor, max_bytes);
                }
            }
        }
    }

    /// Write client input. Requires `conn` to hold the writer lease.
    pub async fn write(&self, conn: ConnectionId, data: Vec<u8>) -> Result<(), WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::Write { conn, data, resp })
            .await
            .map_err(|_| WriteError::Gone)?;
        rx.await.map_err(|_| WriteError::Gone)?
    }

    /// Apply a window-size change.
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<(), WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::Resize { cols, rows, resp })
            .await
            .map_err(|_| WriteError::Gone)?;
        rx.await
            .map_err(|_| WriteError::Gone)?
            .map_err(|e| WriteError::Io(e.to_string()))
    }

    /// Deliver a signal to the child's process group.
    pub async fn signal(&self, signal: impl Into<String>) -> Result<(), WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::Signal {
                signal: signal.into(),
                resp,
            })
            .await
            .map_err(|_| WriteError::Gone)?;
        rx.await
            .map_err(|_| WriteError::Gone)?
            .map_err(|e| WriteError::Io(e.to_string()))
    }

    /// Try to take the writer lease. See [`WriterLease::take`].
    pub async fn take_lease(
        &self,
        principal: impl Into<String>,
        conn: ConnectionId,
        no_steal: bool,
    ) -> Result<TakeOutcome, WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::TakeLease {
                principal: principal.into(),
                conn,
                no_steal,
                resp,
            })
            .await
            .map_err(|_| WriteError::Gone)?;
        rx.await.map_err(|_| WriteError::Gone)
    }

    /// Release any lease held by `conn` (connection death), awaiting the
    /// actor's acknowledgement so the release is observable on return. If
    /// the actor is already gone there is nothing to release.
    pub async fn release_connection(&self, conn: ConnectionId) {
        let (resp, rx) = oneshot::channel();
        if self
            .inbox
            .send(Command::ReleaseConnection { conn, resp })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
    }

    /// Mark one new attachment (suspends the TTL). Returns a guard that
    /// detaches on drop.
    pub fn attach_guard(&self) -> AttachGuard {
        {
            let mut meta = self.shared.meta.lock().unwrap_or_else(|e| e.into_inner());
            meta.attached += 1;
        }
        AttachGuard {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Terminate the session's child and remove it, appending
    /// `session.closed{reason}`. Idempotent.
    pub async fn close(&self, reason: CloseReason, signal: Option<String>) {
        let (resp, rx) = oneshot::channel();
        if self
            .inbox
            .send(Command::Close {
                reason,
                signal,
                resp,
            })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
    }

    /// If this session is unattached and past its resume TTL, the reason it
    /// should be reaped (`Exit` for an already-exited child, `TtlExpired`
    /// for a still-running one). `now`/`ttl` come from the broker's clock
    /// and `[serve].resume_ttl`. Returns `None` while attached or already
    /// closed.
    pub fn ttl_reap_reason(&self, now: Instant, ttl: Duration) -> Option<CloseReason> {
        let meta = self.shared.meta.lock().unwrap_or_else(|e| e.into_inner());
        if meta.attached > 0 || meta.closed {
            return None;
        }
        if now.saturating_duration_since(meta.ttl_base) < ttl {
            return None;
        }
        Some(match meta.state {
            SessionState::Exited => CloseReason::Exit,
            SessionState::Running => CloseReason::TtlExpired,
        })
    }

    /// Current lifecycle state.
    pub fn state(&self) -> SessionState {
        self.shared
            .meta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state
    }

    #[cfg(test)]
    fn end_offset(&self) -> u64 {
        self.shared
            .ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .end()
    }
}

/// RAII attachment counter. While at least one is alive the resume TTL is
/// suspended (architecture.md §3: TTL runs on unattached sessions).
#[derive(Debug)]
pub struct AttachGuard {
    shared: Arc<SessionShared>,
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        let now = self.shared.clock.now();
        let mut meta = self.shared.meta.lock().unwrap_or_else(|e| e.into_inner());
        meta.attached = meta.attached.saturating_sub(1);
        if meta.attached == 0 {
            // Restart the TTL from the moment the last consumer left.
            meta.ttl_base = now;
        }
    }
}

/// The per-session task.
pub struct SessionActor {
    shared: Arc<SessionShared>,
    inbox: mpsc::Receiver<Command>,
    lease_conn: Option<ConnectionId>,
    spawned: SpawnedSource,
}

/// Configuration a session is created with.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Replay ring byte budget.
    pub replay_bytes: usize,
    /// Inbox depth.
    pub inbox_capacity: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            replay_bytes: 8 * 1024 * 1024,
            inbox_capacity: 256,
        }
    }
}

impl SessionActor {
    /// Create a session: spawn the source, build shared state, and return
    /// the handle plus the actor future to spawn.
    ///
    /// `id` is the opaque session id; `created_at` is the RFC 3339 stamp.
    pub fn create(
        id: String,
        created_at: String,
        clock: Arc<dyn Clock>,
        spec: &SessionSpec,
        source: Box<dyn SessionSource>,
        config: SessionConfig,
    ) -> io::Result<(SessionHandle, SessionActor)> {
        let spawned = source.spawn(spec)?;
        let ring: Box<dyn ReplayStore> = Box::new(ReplayRing::new(config.replay_bytes));
        let ttl_base = clock.now();
        let shared = Arc::new(SessionShared {
            id,
            created_at,
            clock,
            ring: Mutex::new(ring),
            notify: Notify::new(),
            meta: Mutex::new(Meta {
                state: SessionState::Running,
                lease: WriterLease::new(),
                attached: 0,
                ttl_base,
                closed: false,
            }),
        });
        let (tx, rx) = mpsc::channel(config.inbox_capacity);
        let handle = SessionHandle {
            shared: Arc::clone(&shared),
            inbox: tx,
        };
        let actor = SessionActor {
            shared,
            inbox: rx,
            lease_conn: None,
            spawned,
        };
        Ok((handle, actor))
    }

    /// Drive the session to completion. Spawn this on a tokio task.
    pub async fn run(self) {
        let SessionActor {
            shared,
            mut inbox,
            mut lease_conn,
            spawned,
        } = self;
        let SpawnedSource {
            mut output,
            mut input,
            mut control,
            wait,
        } = spawned;
        tokio::pin!(wait);

        let mut buf = vec![0u8; RING_CHUNK_MAX];
        let mut output_done = false;
        let mut exiting = false;
        let mut pending_exit: Option<SourceExit> = None;
        let mut exit_appended = false;

        loop {
            // Once the child has exited *and* its output is drained, append
            // the exit control entry exactly once (output-before-exit).
            if exiting && output_done && !exit_appended {
                exit_appended = true;
                let exit = pending_exit.clone().unwrap_or_default();
                shared.push_control(ControlEvent::Exit {
                    exit_code: exit.exit_code,
                    signal: exit.signal,
                });
                shared.set_state_exited();
            }

            tokio::select! {
                cmd = inbox.recv() => {
                    match cmd {
                        Some(cmd) => {
                            if handle_command(&shared, &mut control, &mut input, &mut lease_conn, cmd)
                                .await
                            {
                                return; // Close handled; session is gone.
                            }
                        }
                        None => return, // all handles dropped
                    }
                }
                r = output.read(&mut buf), if !output_done => {
                    match r {
                        Ok(0) | Err(_) => output_done = true,
                        Ok(n) => shared.push_output(&buf[..n]),
                    }
                }
                status = &mut wait, if !exiting => {
                    pending_exit = Some(status);
                    exiting = true;
                    // Keep reading until the source's output hits EOF so no
                    // trailing bytes land after `session.exit`.
                }
            }
        }
    }
}

impl SessionShared {
    fn push_output(&self, data: &[u8]) {
        {
            let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
            ring.push(data);
        }
        self.note_append();
    }

    fn push_control(&self, event: ControlEvent) {
        {
            let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
            ring.push_control(event);
        }
        self.note_append();
    }

    fn set_state_exited(&self) {
        let now = self.clock.now();
        let mut meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
        meta.state = SessionState::Exited;
        // Restart the TTL from the exit moment (only relevant while
        // unattached; the reaper reads `ttl_base`).
        meta.ttl_base = now;
    }
}

/// Handle one inbox command. Returns `true` when the session is now closed
/// and the actor should stop.
async fn handle_command(
    shared: &SessionShared,
    control: &mut Box<dyn SourceControl>,
    input: &mut Box<dyn AsyncWrite + Send + Unpin>,
    lease_conn: &mut Option<ConnectionId>,
    cmd: Command,
) -> bool {
    match cmd {
        Command::Write { conn, data, resp } => {
            let result = do_write(shared, input, conn, data).await;
            let _ = resp.send(result);
            false
        }
        Command::Resize { cols, rows, resp } => {
            let _ = resp.send(control.resize(cols, rows));
            false
        }
        Command::Signal { signal, resp } => {
            let _ = resp.send(control.signal(&signal));
            false
        }
        Command::TakeLease {
            principal,
            conn,
            no_steal,
            resp,
        } => {
            let outcome = {
                let mut meta = shared.meta.lock().unwrap_or_else(|e| e.into_inner());
                meta.lease.take(&principal, conn, no_steal)
            };
            if let TakeOutcome::Acquired { changed: true, .. } = &outcome {
                *lease_conn = Some(conn);
                shared.push_control(ControlEvent::WriterChanged {
                    writer: Some(principal.clone()),
                });
            }
            let _ = resp.send(outcome);
            false
        }
        Command::ReleaseConnection { conn, resp } => {
            let released = {
                let mut meta = shared.meta.lock().unwrap_or_else(|e| e.into_inner());
                meta.lease.release_connection(conn)
            };
            if released.is_some() {
                if *lease_conn == Some(conn) {
                    *lease_conn = None;
                }
                shared.push_control(ControlEvent::WriterChanged { writer: None });
            }
            let _ = resp.send(());
            false
        }
        Command::Close {
            reason,
            signal,
            resp,
        } => {
            do_close(shared, control, reason, signal);
            let _ = resp.send(());
            true
        }
    }
}

async fn do_write(
    shared: &SessionShared,
    input: &mut Box<dyn AsyncWrite + Send + Unpin>,
    conn: ConnectionId,
    data: Vec<u8>,
) -> Result<(), WriteError> {
    {
        let meta = shared.meta.lock().unwrap_or_else(|e| e.into_inner());
        if meta.state != SessionState::Running {
            return Err(WriteError::NotRunning);
        }
        if !meta.lease.is_held_by(conn) {
            return Err(WriteError::NotWriter);
        }
    }
    input
        .write_all(&data)
        .await
        .map_err(|e| WriteError::Io(e.to_string()))?;
    input
        .flush()
        .await
        .map_err(|e| WriteError::Io(e.to_string()))
}

fn do_close(
    shared: &SessionShared,
    control: &mut Box<dyn SourceControl>,
    reason: CloseReason,
    signal: Option<String>,
) {
    // Signal the child (best-effort; inert for a pipe). Full HUP→TERM→KILL
    // escalation with `close_grace` belongs to the PTY source (Step 4) and
    // the broker reaper; here we deliver one signal and mark the session
    // closed so late readers still drain output + the
    // `session.exit`/`session.closed` controls.
    {
        let already_closed = shared.meta.lock().unwrap_or_else(|e| e.into_inner()).closed;
        if already_closed {
            return;
        }
        let sig = signal.unwrap_or_else(|| "SIGHUP".to_string());
        let _ = control.signal(&sig);
    }
    {
        let mut meta = shared.meta.lock().unwrap_or_else(|e| e.into_inner());
        if meta.closed {
            return;
        }
        meta.closed = true;
    }
    shared.push_control(ControlEvent::Closed { reason });
}

// ---------------------------------------------------------------------------
// PipeSource — the non-PTY, in-memory source for headless tests (Step 2).
// ---------------------------------------------------------------------------

/// An in-memory [`SessionSource`] backed by tokio pipes. The producer side
/// is driven by tests through a [`PipeHandle`]: write "child output", read
/// "client input", and trigger exit. No PTY, no process — pure logic.
pub struct PipeSource {
    to_actor: tokio::io::DuplexStream,
    from_actor: tokio::io::DuplexStream,
    exit_rx: oneshot::Receiver<SourceExit>,
    signals: Arc<Mutex<Vec<String>>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
}

/// Test-side control of a [`PipeSource`].
pub struct PipeHandle {
    /// Write here to feed session output into the ring.
    output: tokio::io::DuplexStream,
    /// Read here to observe client input the actor forwarded.
    input: tokio::io::DuplexStream,
    exit_tx: Option<oneshot::Sender<SourceExit>>,
    signals: Arc<Mutex<Vec<String>>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
}

impl PipeSource {
    /// Build a source + its test handle. `buffer` bounds each in-memory
    /// pipe.
    pub fn new(buffer: usize) -> (PipeSource, PipeHandle) {
        let (to_actor, output) = tokio::io::duplex(buffer);
        let (from_actor, input) = tokio::io::duplex(buffer);
        let (exit_tx, exit_rx) = oneshot::channel();
        let signals = Arc::new(Mutex::new(Vec::new()));
        let resizes = Arc::new(Mutex::new(Vec::new()));
        (
            PipeSource {
                to_actor,
                from_actor,
                exit_rx,
                signals: Arc::clone(&signals),
                resizes: Arc::clone(&resizes),
            },
            PipeHandle {
                output,
                input,
                exit_tx: Some(exit_tx),
                signals,
                resizes,
            },
        )
    }
}

impl SessionSource for PipeSource {
    fn spawn(self: Box<Self>, _spec: &SessionSpec) -> io::Result<SpawnedSource> {
        let PipeSource {
            to_actor,
            from_actor,
            exit_rx,
            signals,
            resizes,
        } = *self;
        Ok(SpawnedSource {
            output: Box::new(to_actor),
            input: Box::new(from_actor),
            control: Box::new(PipeControl { signals, resizes }),
            wait: Box::pin(async move { exit_rx.await.unwrap_or_default() }),
        })
    }
}

struct PipeControl {
    signals: Arc<Mutex<Vec<String>>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
}

impl SourceControl for PipeControl {
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.resizes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((cols, rows));
        Ok(())
    }

    fn signal(&mut self, signal: &str) -> io::Result<()> {
        self.signals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(signal.to_string());
        Ok(())
    }
}

impl PipeHandle {
    /// Feed `data` as child output. It flows into the ring on the actor's
    /// next read.
    pub async fn write_output(&mut self, data: &[u8]) -> io::Result<()> {
        self.output.write_all(data).await?;
        self.output.flush().await
    }

    /// Read whatever client input the actor has forwarded so far (up to
    /// `max`). Resolves once at least one byte is available or the input
    /// side closed.
    pub async fn read_input(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; max];
        let n = self.input.read(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Signals the actor delivered to the source, in order.
    pub fn signals(&self) -> Vec<String> {
        self.signals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Resizes the actor applied, in order.
    pub fn resizes(&self) -> Vec<(u16, u16)> {
        self.resizes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// End the child with `exit`, closing the output pipe so the actor sees
    /// EOF and appends `session.exit` after draining.
    pub fn exit(&mut self, exit: SourceExit) {
        // Drop the output writer → EOF for the actor's reader.
        let (dead, _) = tokio::io::duplex(1);
        let _ = std::mem::replace(&mut self.output, dead);
        if let Some(tx) = self.exit_tx.take() {
            let _ = tx.send(exit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::clock::TestClock;
    use crate::broker::ring::ReplayEvent;

    const A: ConnectionId = ConnectionId(1);
    const B: ConnectionId = ConnectionId(2);

    fn spawn_session() -> (SessionHandle, PipeHandle) {
        let (source, pipe) = PipeSource::new(64 * 1024);
        let (handle, actor) = SessionActor::create(
            "01TESTSESSION".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            Arc::new(TestClock::new()),
            &SessionSpec::default(),
            Box::new(source),
            SessionConfig::default(),
        )
        .unwrap();
        tokio::spawn(actor.run());
        (handle, pipe)
    }

    fn collect_output(out: &ReadOut) -> Vec<u8> {
        let mut v = Vec::new();
        for e in &out.events {
            if let ReplayEvent::Output { data, .. } = e {
                v.extend_from_slice(data);
            }
        }
        v
    }

    #[tokio::test]
    async fn output_flows_into_the_ring_and_pull_returns_it() {
        let clock = TestClock::new();
        let (handle, mut pipe) = spawn_session();
        pipe.write_output(b"hello\r\n").await.unwrap();
        // Wait (bounded) for the actor to ingest.
        let out = handle
            .pull(
                Cursor::from_offset(0),
                1024,
                Duration::from_secs(30),
                &clock,
            )
            .await
            .unwrap();
        assert_eq!(collect_output(&out), b"hello\r\n");
        assert_eq!(out.next.after, 7);
    }

    #[tokio::test]
    async fn write_requires_the_lease_and_reaches_the_source() {
        let (handle, mut pipe) = spawn_session();
        // No lease yet.
        assert_eq!(
            handle.write(A, b"x".to_vec()).await,
            Err(WriteError::NotWriter)
        );
        // Take it, then write.
        assert!(matches!(
            handle.take_lease("device:a", A, false).await.unwrap(),
            TakeOutcome::Acquired { changed: true, .. }
        ));
        handle.write(A, b"ls\n".to_vec()).await.unwrap();
        let got = pipe.read_input(16).await.unwrap();
        assert_eq!(got, b"ls\n");
        // A different connection cannot write.
        assert_eq!(
            handle.write(B, b"y".to_vec()).await,
            Err(WriteError::NotWriter)
        );
    }

    #[tokio::test]
    async fn steal_emits_writer_changed_control_in_order() {
        let clock = TestClock::new();
        let (handle, mut pipe) = spawn_session();
        pipe.write_output(b"aa").await.unwrap();
        handle.take_lease("device:a", A, false).await.unwrap();
        // Give the actor room to ingest the output and the lease.
        let _ = handle
            .pull(Cursor::from_offset(0), 1024, Duration::from_secs(5), &clock)
            .await
            .unwrap();
        // Steal from B.
        handle.take_lease("device:b", B, false).await.unwrap();
        // no_steal against the live holder now conflicts.
        assert!(matches!(
            handle.take_lease("device:a", A, true).await.unwrap(),
            TakeOutcome::Conflict { .. }
        ));
        let out = handle
            .pull(Cursor::from_offset(0), 1024, Duration::from_secs(5), &clock)
            .await
            .unwrap();
        let writers: Vec<Option<String>> = out
            .events
            .iter()
            .filter_map(|e| match e {
                ReplayEvent::Control {
                    event: ControlEvent::WriterChanged { writer },
                    ..
                } => Some(writer.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            writers,
            vec![Some("device:a".to_string()), Some("device:b".to_string())]
        );
        assert_eq!(handle.info().writer.as_deref(), Some("device:b"));
    }

    #[tokio::test]
    async fn lease_auto_releases_on_connection_death() {
        let (handle, _pipe) = spawn_session();
        handle.take_lease("device:a", A, false).await.unwrap();
        assert_eq!(handle.info().writer.as_deref(), Some("device:a"));
        handle.release_connection(A).await;
        // Round-trip a cheap command to be sure the release was applied.
        let _ = handle.resize(80, 24).await;
        assert_eq!(handle.info().writer, None);
        // Now writes fail again.
        assert_eq!(
            handle.write(A, b"x".to_vec()).await,
            Err(WriteError::NotWriter)
        );
    }

    #[tokio::test]
    async fn exit_control_is_appended_after_all_output() {
        let clock = TestClock::new();
        let (handle, mut pipe) = spawn_session();
        pipe.write_output(b"line1\r\n").await.unwrap();
        pipe.write_output(b"line2\r\n").await.unwrap();
        pipe.exit(SourceExit {
            exit_code: Some(0),
            signal: None,
        });
        // Wait (bounded, no sleep) for the actor to drain output and flip to
        // Exited, so the non-blocking drain below sees the whole stream.
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if handle.state() == SessionState::Exited {
                break;
            }
        }
        assert_eq!(handle.state(), SessionState::Exited);
        // Drain everything non-blocking (wait = ZERO): an empty read means
        // the end, not "block for more".
        let mut cursor = Cursor::from_offset(0);
        let mut bytes = Vec::new();
        let mut saw_exit_after = None;
        loop {
            let out = handle
                .pull(cursor, 1024, Duration::ZERO, &clock)
                .await
                .unwrap();
            if out.events.is_empty() {
                break;
            }
            for e in &out.events {
                match e {
                    ReplayEvent::Output { data, .. } => bytes.extend_from_slice(data),
                    ReplayEvent::Control {
                        sequence,
                        event: ControlEvent::Exit { exit_code, .. },
                        ..
                    } => {
                        assert_eq!(*exit_code, Some(0));
                        saw_exit_after = Some(*sequence);
                    }
                    _ => {}
                }
            }
            cursor = out.next;
        }
        assert_eq!(bytes, b"line1\r\nline2\r\n");
        assert_eq!(saw_exit_after, Some(bytes.len() as u64));
        assert_eq!(handle.info().state, SessionState::Exited);
    }

    #[tokio::test]
    async fn resize_and_signal_reach_the_source() {
        let (handle, pipe) = spawn_session();
        handle.resize(120, 40).await.unwrap();
        handle.signal("SIGWINCH").await.unwrap();
        assert_eq!(pipe.resizes(), vec![(120, 40)]);
        assert_eq!(pipe.signals(), vec!["SIGWINCH".to_string()]);
    }

    #[tokio::test]
    async fn close_appends_closed_control_and_stops_the_actor() {
        let clock = TestClock::new();
        let (handle, _pipe) = spawn_session();
        handle.close(CloseReason::Closed, None).await;
        let out = handle
            .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
            .await
            .unwrap();
        assert!(out.events.iter().any(|e| matches!(
            e,
            ReplayEvent::Control {
                event: ControlEvent::Closed {
                    reason: CloseReason::Closed
                },
                ..
            }
        )));
        // Actor stopped: further writes report it is gone.
        assert_eq!(handle.write(A, b"x".to_vec()).await, Err(WriteError::Gone));
    }

    #[tokio::test]
    async fn pull_wait_blocks_until_output_then_returns() {
        let clock = TestClock::new();
        let (handle, mut pipe) = spawn_session();
        let reader = {
            let handle = handle.clone();
            let clock = clock.clone();
            tokio::spawn(async move {
                handle
                    .pull(
                        Cursor::from_offset(0),
                        1024,
                        Duration::from_secs(60),
                        &clock,
                    )
                    .await
                    .map(|o| collect_output(&o))
            })
        };
        // Nothing yet: the reader is parked.
        tokio::task::yield_now().await;
        assert!(!reader.is_finished());
        pipe.write_output(b"late\r\n").await.unwrap();
        assert_eq!(reader.await.unwrap().unwrap(), b"late\r\n");
    }

    #[tokio::test(start_paused = true)]
    async fn pull_wait_times_out_via_the_clock_without_sleeping() {
        let clock = TestClock::new();
        let (handle, _pipe) = spawn_session();
        let reader = {
            let handle = handle.clone();
            let clock = clock.clone();
            tokio::spawn(async move {
                handle
                    .pull(
                        Cursor::from_offset(0),
                        1024,
                        Duration::from_secs(30),
                        &clock,
                    )
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(!reader.is_finished());
        // Advance the injected clock past the deadline; no real time passes.
        clock.advance(Duration::from_secs(30));
        let out = reader.await.unwrap().unwrap();
        assert!(out.events.is_empty());
    }

    #[tokio::test]
    async fn per_session_memory_is_bounded_by_the_ring_budget() {
        let (source, mut pipe) = PipeSource::new(1024 * 1024);
        let (handle, actor) = SessionActor::create(
            "01BOUNDED".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            Arc::new(TestClock::new()),
            &SessionSpec::default(),
            Box::new(source),
            SessionConfig {
                replay_bytes: 4096,
                inbox_capacity: 16,
            },
        )
        .unwrap();
        tokio::spawn(actor.run());
        let clock = TestClock::new();
        // Push far more than the budget.
        for _ in 0..50 {
            pipe.write_output(&[b'z'; 4096]).await.unwrap();
            // Drain via pull so the actor keeps ingesting.
            let _ = handle
                .pull(handle.end_offset().into(), 0, Duration::ZERO, &clock)
                .await;
        }
        // Let the actor catch up.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        // Whatever end offset we reached, the retained bytes never exceed
        // the budget plus one in-flight chunk.
        let out = handle
            .pull(Cursor::from_offset(0), usize::MAX, Duration::ZERO, &clock)
            .await
            .unwrap();
        let retained: usize = out
            .events
            .iter()
            .map(|e| match e {
                ReplayEvent::Output { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        assert!(
            retained <= 4096 + RING_CHUNK_MAX,
            "retained {retained} exceeds ring budget"
        );
    }
}
