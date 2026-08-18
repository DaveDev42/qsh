//! Per-session actor and the [`SessionSource`] seam
//! (`docs/design/architecture.md` §3 "SessionActor").
//!
//! One [`SessionActor`] runs per session. It owns the byte producer
//! ([`SessionSource`]) and splits its work over three tasks so that no
//! side can stall another:
//!
//! - the **output pump** (architecture.md §3 `pty_reader task`): reads the
//!   source's output into the [`ReplayRing`] — the **only** place
//!   cumulative offsets are assigned — and wakes readers. It is never
//!   blocked by a consumer (reads are cursor pulls on the ring) nor by
//!   client input (writes run elsewhere).
//! - the **input writer**: drains a bounded queue of client input into the
//!   source. A child that stops reading its input back-pressures this
//!   queue only; when it is full, further writes fail fast with
//!   [`WriteError::Backpressure`] (→ `RESOURCE_EXHAUSTED`) instead of
//!   parking anything.
//! - the **actor loop**: serves the mpsc inbox ([`Command`]: `Write` /
//!   `Resize` / `Signal` / `TakeLease` / `ReleaseConnection` / `Close`),
//!   observes child exit, appends the `session.exit` control entry once the
//!   output is drained (output-before-exit ordering,
//!   `docs/design/testing.md` L5), and drives the close escalation
//!   (CLI.md §6.7: first signal → `close_grace` → `SIGTERM` → `close_grace`
//!   → `SIGKILL` → `close_grace` → forced cleanup; an `exited` session is
//!   never signalled) on the injected [`Clock`].
//!
//! Reads do **not** go through the inbox or the lease: the ring lives behind
//! a mutex in [`SessionShared`] and [`SessionHandle::pull`] reads it directly
//! (architecture.md §3 "reads need no lease"). The producer is only ever a
//! PTY (Step 4) or, here, a [`PipeSource`] for headless tests — no PTY code
//! in this step.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};

use super::clock::{BoxFuture, Clock};
use super::lease::{ConnectionId, TakeOutcome, WriterLease};
use super::ring::{
    Cursor, RING_CHUNK_MAX, ReadError, ReadOut, ReplayRing, ReplayStore,
    {CloseReason, ControlEvent},
};
use super::signal::Signal;

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
    /// recorded for a pipe). Only ever called with a [`Signal`] from the
    /// documented set, and never on an `exited` session.
    fn signal(&mut self, signal: Signal) -> io::Result<()>;
}

/// The byte producer behind a session. In-process only in P0.
pub trait SessionSource: Send + 'static {
    /// Launch and hand back the I/O trio. Called once, by the actor, on
    /// the caller's task (synchronously — the production PTY source does
    /// `openpty` + `fork`/`exec` here, milliseconds, not I/O waits; callers
    /// on a latency-sensitive task may wrap `Broker::open` in
    /// `spawn_blocking`). Must be called from within a tokio runtime.
    /// An `io::ErrorKind::Unsupported` error means "refused, nothing
    /// spawned" (→ `UNSUPPORTED`), any other error → `INTERNAL`.
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
    /// `true` from the moment a close was accepted (escalation may still be
    /// running). Rejects input and stops the TTL reaper from closing twice.
    closing: bool,
    /// Set once the `Closed` control has been appended (the session is
    /// gone; only late readers draining the ring remain).
    closed_at: Option<Instant>,
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

    fn meta(&self) -> std::sync::MutexGuard<'_, Meta> {
        self.meta.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ring(&self) -> std::sync::MutexGuard<'_, Box<dyn ReplayStore>> {
        self.ring.lock().unwrap_or_else(|e| e.into_inner())
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
        signal: Signal,
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
        signal: Option<Signal>,
        resp: oneshot::Sender<()>,
    },
}

/// Why a write was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// The writing connection does not hold the lease.
    #[error("connection does not hold the writer lease")]
    NotWriter,
    /// The session has already exited or is closing; input is discarded.
    #[error("session is no longer running")]
    NotRunning,
    /// The child is not draining its input and the bounded input queue is
    /// full (→ `RESOURCE_EXHAUSTED`, CLI.md §3.3). Retry later.
    #[error("session input queue is full")]
    Backpressure,
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
        let meta = self.shared.meta();
        let last_sequence = self.shared.ring().end();
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
    /// long-poll). Never needs the lease. Works on a closed session too,
    /// so a follower can drain the trailing `session.closed`.
    ///
    /// `wait` is caller-supplied; an absurdly large value is clamped
    /// rather than allowed to overflow the clock (a panic here would be
    /// remotely triggerable).
    pub async fn pull(
        &self,
        cursor: Cursor,
        max_bytes: usize,
        wait: Duration,
        clock: &dyn Clock,
    ) -> Result<ReadOut, ReadError> {
        let now = clock.now();
        let deadline = now.checked_add(wait).unwrap_or_else(|| now + MAX_PULL_WAIT);
        loop {
            // Register for wakeups *before* reading. `Notified` only becomes
            // a registered waiter once polled; `enable()` registers it now
            // so an append that lands between this read and the await below
            // still wakes us (otherwise `notify_waiters()` finds no waiter
            // and the wakeup is lost — a `pull(wait=∞)` would hang forever).
            let notified = self.shared.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let out = self.shared.ring().read(cursor, max_bytes)?;
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
                    return self.shared.ring().read(cursor, max_bytes);
                }
            }
        }
    }

    /// Write client input. Requires `conn` to hold the writer lease.
    /// Resolves once the bytes have been written to the source (or fails
    /// fast with [`WriteError::Backpressure`] if the input queue is full).
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

    /// Deliver a signal to the child's process group. Refused on an
    /// `exited`/closing session (nothing to signal; a reused pgid must not
    /// be hit — CLI.md §6.7).
    pub async fn signal(&self, signal: Signal) -> Result<(), WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::Signal { signal, resp })
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
        self.shared.meta().attached += 1;
        AttachGuard {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Terminate the session's child (escalating on the clock) and mark it
    /// closed, appending `session.closed{reason}` as the last entry.
    /// Resolves once the `Closed` entry is in the ring. Idempotent and safe
    /// to call concurrently: every caller resolves on the same close.
    ///
    /// Crate-private: [`super::Broker::close`] is the only removal path so
    /// the registry never holds a session it does not know is closed.
    pub(crate) async fn close(&self, reason: CloseReason, signal: Option<Signal>) {
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
    /// and `[serve].resume_ttl`. Returns `None` while attached or once a
    /// close has been accepted.
    pub fn ttl_reap_reason(&self, now: Instant, ttl: Duration) -> Option<CloseReason> {
        let meta = self.shared.meta();
        if meta.attached > 0 || meta.closing {
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
        self.shared.meta().state
    }

    /// Whether a close has been accepted (escalation may still be running).
    pub fn is_closing(&self) -> bool {
        self.shared.meta().closing
    }

    /// The instant the `Closed` entry was appended, once it has been.
    pub fn closed_at(&self) -> Option<Instant> {
        self.shared.meta().closed_at
    }

    #[cfg(test)]
    fn end_offset(&self) -> u64 {
        self.shared.ring().end()
    }
}

/// Clamp for `pull(..., wait)` when `now + wait` would overflow the clock.
const MAX_PULL_WAIT: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Opaque RAII token handed out by [`super::SessionBackend::attach`]:
/// while it is alive the session counts as attached and its resume TTL is
/// suspended; dropping it detaches. In-process this is an
/// [`AttachGuard`]; an out-of-process supervisor supplies its own type
/// whose `Drop` sends the detach over IPC, which is why the seam names a
/// trait object rather than the concrete guard.
pub trait AttachToken: Send + Sync + std::fmt::Debug {}

/// RAII attachment counter. While at least one is alive the resume TTL is
/// suspended (architecture.md §3: TTL runs on unattached sessions).
#[derive(Debug)]
pub struct AttachGuard {
    shared: Arc<SessionShared>,
}

impl AttachToken for AttachGuard {}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        let now = self.shared.clock.now();
        let mut meta = self.shared.meta();
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
    spawned: SpawnedSource,
    config: SessionConfig,
}

/// Configuration a session is created with.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Replay ring byte budget.
    pub replay_bytes: usize,
    /// Inbox depth.
    pub inbox_capacity: usize,
    /// Depth of the client-input queue in front of the source; when full,
    /// writes fail with [`WriteError::Backpressure`].
    pub input_queue: usize,
    /// Per-step grace of the close escalation (`[serve].close_grace_ms`).
    pub close_grace: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            replay_bytes: 8 * 1024 * 1024,
            inbox_capacity: 256,
            input_queue: 64,
            close_grace: Duration::from_millis(5000),
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
                closing: false,
                closed_at: None,
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
            spawned,
            config,
        };
        Ok((handle, actor))
    }

    /// Drive the session to completion. Spawn this on a tokio task.
    pub async fn run(self) {
        let SessionActor {
            shared,
            mut inbox,
            spawned,
            config,
        } = self;
        let SpawnedSource {
            mut output,
            mut input,
            control,
            wait,
        } = spawned;
        tokio::pin!(wait);

        // Output pump: source → ring. Its own task, so it is never behind a
        // blocked input write or a slow command.
        let (eof_tx, eof_rx) = oneshot::channel::<()>();
        let pump = {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut buf = vec![0u8; RING_CHUNK_MAX];
                loop {
                    match output.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => shared.push_output(&buf[..n]),
                    }
                }
                let _ = eof_tx.send(());
            })
        };
        tokio::pin!(eof_rx);

        // Input writer: bounded queue → source. A child that stops reading
        // stalls only this task; the queue bound turns into
        // `WriteError::Backpressure` for callers.
        let (in_tx, mut in_rx) = mpsc::channel::<InputChunk>(config.input_queue.max(1));
        let writer = tokio::spawn(async move {
            while let Some((data, resp)) = in_rx.recv().await {
                let result = async {
                    input.write_all(&data).await?;
                    input.flush().await
                }
                .await
                .map_err(|e| WriteError::Io(e.to_string()));
                let _ = resp.send(result);
            }
        });

        let mut state = ActorState {
            shared: Arc::clone(&shared),
            control,
            in_tx,
            lease_conn: None,
            close_grace: config.close_grace,
            exiting: false,
            output_done: false,
            exit_appended: false,
            pending_exit: None,
            closing: None,
        };

        loop {
            // Once the child has exited *and* its output is drained, append
            // the exit control entry exactly once (output-before-exit).
            if state.exiting && state.output_done && !state.exit_appended {
                state.exit_appended = true;
                let exit = state.pending_exit.take().unwrap_or_default();
                shared.push_control(ControlEvent::Exit {
                    exit_code: exit.exit_code,
                    signal: exit.signal,
                });
                shared.set_state_exited();
            }
            // A close finishes as soon as the child is gone and drained, or
            // when the escalation has run out of steps.
            if let Some(closing) = &state.closing
                && (state.exit_appended || closing.forced)
            {
                break;
            }

            tokio::select! {
                cmd = inbox.recv() => {
                    match cmd {
                        Some(cmd) => state.handle_command(cmd),
                        None => break, // every handle dropped: nobody can reach us
                    }
                }
                _ = &mut eof_rx, if !state.output_done => {
                    state.output_done = true;
                }
                status = &mut wait, if !state.exiting => {
                    state.pending_exit = Some(status);
                    state.exiting = true;
                    // Keep pumping until the source's output hits EOF so no
                    // trailing bytes land after `session.exit`.
                }
                _ = state.closing_timer(), if state.closing.is_some() => {
                    state.escalate();
                }
            }
        }

        // Finalise: stop the I/O tasks (drops the source ends), then append
        // `Closed` as the very last entry and answer every closer.
        pump.abort();
        writer.abort();
        let reason = state
            .closing
            .as_ref()
            .map(|c| c.reason)
            .unwrap_or(CloseReason::Closed);
        let responders = state
            .closing
            .take()
            .map(|c| c.responders)
            .unwrap_or_default();
        shared.mark_closed(reason);
        for resp in responders {
            let _ = resp.send(());
        }
    }
}

type InputChunk = (Vec<u8>, oneshot::Sender<Result<(), WriteError>>);

/// An in-progress close (CLI.md §6.7 escalation).
struct Closing {
    reason: CloseReason,
    responders: Vec<oneshot::Sender<()>>,
    /// Next escalation step, or `None` once `SIGKILL` has been sent (the
    /// step after that is forced cleanup).
    next: Option<Signal>,
    /// Sleep until the next step; recreated on every step.
    timer: BoxFuture<'static, ()>,
    /// The escalation ran out (KILL + grace elapsed with no exit): finish
    /// without waiting for the child.
    forced: bool,
}

/// The actor loop's mutable state, kept together so `select!` arms can call
/// methods on it.
struct ActorState {
    shared: Arc<SessionShared>,
    control: Box<dyn SourceControl>,
    in_tx: mpsc::Sender<InputChunk>,
    lease_conn: Option<ConnectionId>,
    close_grace: Duration,
    exiting: bool,
    output_done: bool,
    exit_appended: bool,
    pending_exit: Option<SourceExit>,
    closing: Option<Closing>,
}

impl ActorState {
    /// The current escalation timer. Only polled while `closing.is_some()`;
    /// pending forever otherwise (never actually reached because of the
    /// `select!` guard).
    fn closing_timer(&mut self) -> impl std::future::Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx| match &mut self.closing {
            Some(c) => c.timer.as_mut().poll(cx),
            None => Poll::Pending,
        })
    }

    fn sleep_owned(&self, dur: Duration) -> BoxFuture<'static, ()> {
        let clock = Arc::clone(&self.shared.clock);
        Box::pin(async move { clock.sleep(dur).await })
    }

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Write { conn, data, resp } => {
                // On refusal `resp` was answered inside; nothing else to do.
                self.enqueue_write(conn, data, resp);
            }
            Command::Resize { cols, rows, resp } => {
                let _ = resp.send(self.control.resize(cols, rows));
            }
            Command::Signal { signal, resp } => {
                // `exiting` (child reaped, output still draining) is treated
                // like `exited`: the pgid may already be reused (CLI.md
                // §6.7), same rule as `begin_close`.
                let running = {
                    let meta = self.shared.meta();
                    meta.state == SessionState::Running && !meta.closing
                } && !self.exiting;
                let _ = resp.send(if running {
                    self.control.signal(signal)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "session is not running",
                    ))
                });
            }
            Command::TakeLease {
                principal,
                conn,
                no_steal,
                resp,
            } => {
                let outcome = self.shared.meta().lease.take(&principal, conn, no_steal);
                if let TakeOutcome::Acquired { changed: true, .. } = &outcome {
                    self.lease_conn = Some(conn);
                    self.shared.push_control(ControlEvent::WriterChanged {
                        writer: Some(principal.clone()),
                    });
                }
                let _ = resp.send(outcome);
            }
            Command::ReleaseConnection { conn, resp } => {
                let released = self.shared.meta().lease.release_connection(conn);
                if released.is_some() {
                    if self.lease_conn == Some(conn) {
                        self.lease_conn = None;
                    }
                    self.shared
                        .push_control(ControlEvent::WriterChanged { writer: None });
                }
                let _ = resp.send(());
            }
            Command::Close {
                reason,
                signal,
                resp,
            } => self.begin_close(reason, signal, resp),
        }
    }

    /// Validate and hand a write to the input writer without blocking the
    /// actor. On refusal the caller's `resp` is answered with the error;
    /// on success the writer task answers it once the bytes are written.
    fn enqueue_write(
        &mut self,
        conn: ConnectionId,
        data: Vec<u8>,
        resp: oneshot::Sender<Result<(), WriteError>>,
    ) {
        let refusal = {
            let meta = self.shared.meta();
            if meta.state != SessionState::Running || meta.closing {
                Some(WriteError::NotRunning)
            } else if !meta.lease.is_held_by(conn) {
                Some(WriteError::NotWriter)
            } else {
                None
            }
        };
        if let Some(err) = refusal {
            let _ = resp.send(Err(err));
            return;
        }
        match self.in_tx.try_send((data, resp)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full((_, resp))) => {
                let _ = resp.send(Err(WriteError::Backpressure));
            }
            Err(mpsc::error::TrySendError::Closed((_, resp))) => {
                let _ = resp.send(Err(WriteError::Gone));
            }
        }
    }

    /// Accept a close. An `exited` session gets **no signal** (CLI.md §6.7:
    /// a reused pgid must never be hit) and finishes at once; a running one
    /// gets `signal` (default `SIGHUP`) and the escalation timer starts.
    /// A second close while one is in flight just joins it.
    fn begin_close(
        &mut self,
        reason: CloseReason,
        signal: Option<Signal>,
        resp: oneshot::Sender<()>,
    ) {
        if let Some(closing) = &mut self.closing {
            closing.responders.push(resp);
            return;
        }
        // `exiting` covers the window where the child has already been
        // reaped but its output is still draining: the pgid may already be
        // reused, so it is treated exactly like `exited` here.
        let exited = {
            let mut meta = self.shared.meta();
            meta.closing = true;
            meta.state == SessionState::Exited
        } || self.exiting;
        let (next, timer) = if exited {
            // Nothing to signal; finish once the drain completes (or after
            // one grace if it never does).
            (None, self.sleep_owned(self.close_grace))
        } else {
            let first = signal.unwrap_or(Signal::Hup);
            let _ = self.control.signal(first);
            let next = match first {
                Signal::Kill => None,
                Signal::Term => Some(Signal::Kill),
                _ => Some(Signal::Term),
            };
            (next, self.sleep_owned(self.close_grace))
        };
        self.closing = Some(Closing {
            reason,
            responders: vec![resp],
            next,
            timer,
            forced: false,
        });
    }

    /// One escalation step: the timer fired and the child is still there.
    fn escalate(&mut self) {
        let grace = self.close_grace;
        let timer = self.sleep_owned(grace);
        let Some(closing) = &mut self.closing else {
            return;
        };
        match closing.next.take() {
            Some(sig) => {
                let _ = self.control.signal(sig);
                closing.next = match sig {
                    Signal::Kill => None,
                    _ => Some(Signal::Kill),
                };
                closing.timer = timer;
            }
            None => {
                // KILL (or an exited-at-close session) + grace elapsed:
                // finish regardless.
                closing.forced = true;
            }
        }
    }
}

impl SessionShared {
    fn push_output(&self, data: &[u8]) {
        self.ring().push(data);
        self.note_append();
    }

    fn push_control(&self, event: ControlEvent) {
        self.ring().push_control(event);
        self.note_append();
    }

    fn set_state_exited(&self) {
        let now = self.clock.now();
        let mut meta = self.meta();
        meta.state = SessionState::Exited;
        // Restart the TTL from the exit moment (only relevant while
        // unattached; the reaper reads `ttl_base`).
        meta.ttl_base = now;
    }

    fn mark_closed(&self, reason: CloseReason) {
        let now = self.clock.now();
        {
            let mut meta = self.meta();
            meta.closing = true;
            meta.closed_at = Some(now);
        }
        self.push_control(ControlEvent::Closed { reason });
    }
}

// ---------------------------------------------------------------------------
// PipeSource — the non-PTY, in-memory source for headless tests (Step 2).
// ---------------------------------------------------------------------------

/// An in-memory [`SessionSource`] backed by tokio pipes. The producer side
/// is driven by tests through a [`PipeHandle`]: write "child output", read
/// "client input", and trigger exit. No PTY, no process — pure logic.
///
/// It behaves like a cooperative child: a fatal signal (`HUP`/`INT`/`QUIT`/
/// `TERM`/`KILL`) ends it with `SourceExit{signal}` and EOF on its output,
/// unless the signal was listed in [`PipeSource::with_ignored_signals`]
/// (to exercise the close escalation).
pub struct PipeSource {
    to_actor: tokio::io::DuplexStream,
    from_actor: tokio::io::DuplexStream,
    exit_rx: oneshot::Receiver<SourceExit>,
    exit_tx: SharedExitTx,
    signals: Arc<Mutex<Vec<Signal>>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    ignored: Vec<Signal>,
}

type SharedExitTx = Arc<Mutex<Option<oneshot::Sender<SourceExit>>>>;

/// Test-side control of a [`PipeSource`].
pub struct PipeHandle {
    /// Write here to feed session output into the ring.
    output: tokio::io::DuplexStream,
    /// Read here to observe client input the actor forwarded.
    input: tokio::io::DuplexStream,
    exit_tx: SharedExitTx,
    signals: Arc<Mutex<Vec<Signal>>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
}

impl PipeSource {
    /// Build a source + its test handle. `buffer` bounds each in-memory
    /// pipe.
    pub fn new(buffer: usize) -> (PipeSource, PipeHandle) {
        Self::with_ignored_signals(buffer, &[])
    }

    /// Like [`PipeSource::new`], but the listed signals are recorded and
    /// otherwise ignored (the child "survives" them).
    pub fn with_ignored_signals(buffer: usize, ignored: &[Signal]) -> (PipeSource, PipeHandle) {
        let (to_actor, output) = tokio::io::duplex(buffer);
        let (from_actor, input) = tokio::io::duplex(buffer);
        let (exit_tx, exit_rx) = oneshot::channel();
        let exit_tx: SharedExitTx = Arc::new(Mutex::new(Some(exit_tx)));
        let signals = Arc::new(Mutex::new(Vec::new()));
        let resizes = Arc::new(Mutex::new(Vec::new()));
        (
            PipeSource {
                to_actor,
                from_actor,
                exit_rx,
                exit_tx: Arc::clone(&exit_tx),
                signals: Arc::clone(&signals),
                resizes: Arc::clone(&resizes),
                ignored: ignored.to_vec(),
            },
            PipeHandle {
                output,
                input,
                exit_tx,
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
            exit_tx,
            signals,
            resizes,
            ignored,
        } = *self;
        let (dead_tx, dead_rx) = oneshot::channel();
        Ok(SpawnedSource {
            output: Box::new(PipeOutput {
                inner: to_actor,
                dead_rx,
                dead: false,
            }),
            input: Box::new(from_actor),
            control: Box::new(PipeControl {
                signals,
                resizes,
                ignored,
                exit_tx,
                dead_tx: Some(dead_tx),
            }),
            wait: Box::pin(async move { exit_rx.await.unwrap_or_default() }),
        })
    }
}

/// The pipe's output side: reads through to the duplex until it is drained
/// *and* the child is dead, then EOF (like a PTY master after the child
/// exits and its slave fds close).
struct PipeOutput {
    inner: tokio::io::DuplexStream,
    dead_rx: oneshot::Receiver<()>,
    dead: bool,
}

impl AsyncRead for PipeOutput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => {
                if !self.dead && Pin::new(&mut self.dead_rx).poll(cx).is_ready() {
                    self.dead = true;
                }
                if self.dead {
                    Poll::Ready(Ok(())) // EOF: nothing filled
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

struct PipeControl {
    signals: Arc<Mutex<Vec<Signal>>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    ignored: Vec<Signal>,
    exit_tx: SharedExitTx,
    dead_tx: Option<oneshot::Sender<()>>,
}

impl SourceControl for PipeControl {
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.resizes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((cols, rows));
        Ok(())
    }

    fn signal(&mut self, signal: Signal) -> io::Result<()> {
        self.signals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(signal);
        let fatal = matches!(
            signal,
            Signal::Hup | Signal::Int | Signal::Quit | Signal::Term | Signal::Kill
        );
        if fatal && !self.ignored.contains(&signal) {
            if let Some(tx) = self
                .exit_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                let _ = tx.send(SourceExit {
                    exit_code: None,
                    signal: Some(signal.as_str().to_string()),
                });
            }
            if let Some(tx) = self.dead_tx.take() {
                let _ = tx.send(());
            }
        }
        Ok(())
    }
}

impl PipeHandle {
    /// Feed `data` as child output. It flows into the ring on the pump's
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
    pub fn signals(&self) -> Vec<Signal> {
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
        if let Some(tx) = self
            .exit_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
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

    /// Fail instead of hanging when the actor is broken. Real time only
    /// elapses on failure.
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .expect("timed out: actor stalled")
    }

    fn spawn_with(source: PipeSource, clock: &TestClock, config: SessionConfig) -> SessionHandle {
        let (handle, actor) = SessionActor::create(
            "01TESTSESSION".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            Arc::new(clock.clone()),
            &SessionSpec::default(),
            Box::new(source),
            config,
        )
        .unwrap();
        tokio::spawn(actor.run());
        handle
    }

    fn spawn_session() -> (SessionHandle, PipeHandle, TestClock) {
        let clock = TestClock::new();
        let (source, pipe) = PipeSource::new(64 * 1024);
        let handle = spawn_with(source, &clock, SessionConfig::default());
        (handle, pipe, clock)
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

    fn controls(out: &ReadOut) -> Vec<ControlEvent> {
        out.events
            .iter()
            .filter_map(|e| match e {
                ReplayEvent::Control { event, .. } => Some(event.clone()),
                _ => None,
            })
            .collect()
    }

    /// Pull until the predicate holds on the accumulated events (bounded by
    /// the injected clock, never by real sleep).
    async fn drain_until(
        handle: &SessionHandle,
        clock: &TestClock,
        mut done: impl FnMut(&[ReplayEvent]) -> bool,
    ) -> Vec<ReplayEvent> {
        let mut cursor = Cursor::from_offset(0);
        let mut all = Vec::new();
        loop {
            let out = within(handle.pull(cursor, 1024, Duration::from_secs(30), clock))
                .await
                .unwrap();
            cursor = out.next;
            all.extend(out.events);
            if done(&all) {
                return all;
            }
        }
    }

    #[tokio::test]
    async fn output_flows_into_the_ring_and_pull_returns_it() {
        let (handle, mut pipe, clock) = spawn_session();
        pipe.write_output(b"hello\r\n").await.unwrap();
        let out = within(handle.pull(
            Cursor::from_offset(0),
            1024,
            Duration::from_secs(30),
            &clock,
        ))
        .await
        .unwrap();
        assert_eq!(collect_output(&out), b"hello\r\n");
        assert_eq!(out.next.after, 7);
    }

    #[tokio::test]
    async fn write_requires_the_lease_and_reaches_the_source() {
        let (handle, mut pipe, _clock) = spawn_session();
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
        within(handle.write(A, b"ls\n".to_vec())).await.unwrap();
        let got = within(pipe.read_input(16)).await.unwrap();
        assert_eq!(got, b"ls\n");
        // A different connection cannot write.
        assert_eq!(
            handle.write(B, b"y".to_vec()).await,
            Err(WriteError::NotWriter)
        );
    }

    #[tokio::test]
    async fn blocked_input_write_never_stalls_the_pump_or_close() {
        // 8-byte pipes; the "child" never reads its input. A 4 KiB write
        // parks the input writer only: output still flows into the ring,
        // and close still completes.
        let clock = TestClock::new();
        let (source, mut pipe) = PipeSource::new(8);
        let handle = spawn_with(source, &clock, SessionConfig::default());
        handle.take_lease("device:a", A, false).await.unwrap();
        let blocked = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.write(A, vec![b'x'; 4096]).await })
        };
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished(), "the write is parked on the child");

        // The pump is alive: 5 bytes of output land in the ring.
        // (8-byte pipe: write in one go so the test itself does not block.)
        pipe.write_output(b"hello").await.unwrap();
        let events = drain_until(&handle, &clock, |all| {
            all.iter().any(|e| matches!(e, ReplayEvent::Output { .. }))
        })
        .await;
        let bytes: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                ReplayEvent::Output { data, .. } => Some(data.to_vec()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(bytes, b"hello");

        // The inbox is alive: a resize round-trips.
        within(handle.resize(80, 24)).await.unwrap();

        // Close completes (cooperative pipe dies on SIGHUP) even though the
        // input writer is still parked.
        within(handle.close(CloseReason::Closed, None)).await;
        assert!(handle.closed_at().is_some());
        // The parked write is torn down with the session.
        let r = within(blocked).await.unwrap();
        assert!(
            matches!(r, Err(WriteError::Gone) | Err(WriteError::Io(_))),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn full_input_queue_fails_fast_with_backpressure() {
        let clock = TestClock::new();
        let (source, _pipe) = PipeSource::new(8);
        let handle = spawn_with(
            source,
            &clock,
            SessionConfig {
                input_queue: 1,
                ..SessionConfig::default()
            },
        );
        handle.take_lease("device:a", A, false).await.unwrap();
        // First write parks in the writer task; second sits in the
        // (depth-1) queue; third is refused immediately.
        let mut parked = Vec::new();
        for _ in 0..2 {
            let h = handle.clone();
            parked.push(tokio::spawn(
                async move { h.write(A, vec![b'x'; 64]).await },
            ));
            tokio::task::yield_now().await;
        }
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            within(handle.write(A, vec![b'y'; 8])).await,
            Err(WriteError::Backpressure)
        );
        // Nothing else was affected: a resize still round-trips.
        within(handle.resize(1, 1)).await.unwrap();
        for p in parked {
            p.abort();
        }
    }

    #[tokio::test]
    async fn steal_emits_writer_changed_control_in_order() {
        let (handle, mut pipe, clock) = spawn_session();
        pipe.write_output(b"aa").await.unwrap();
        handle.take_lease("device:a", A, false).await.unwrap();
        // Steal from B.
        handle.take_lease("device:b", B, false).await.unwrap();
        // no_steal against a live holder of another principal conflicts.
        assert!(matches!(
            handle.take_lease("device:a", A, true).await.unwrap(),
            TakeOutcome::Conflict { .. }
        ));
        let events = drain_until(&handle, &clock, |all| {
            all.iter()
                .filter(|e| matches!(e, ReplayEvent::Control { .. }))
                .count()
                >= 2
        })
        .await;
        let writers: Vec<Option<String>> = events
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
        let (handle, _pipe, _clock) = spawn_session();
        handle.take_lease("device:a", A, false).await.unwrap();
        assert_eq!(handle.info().writer.as_deref(), Some("device:a"));
        within(handle.release_connection(A)).await;
        assert_eq!(handle.info().writer, None);
        // Now writes fail again.
        assert_eq!(
            handle.write(A, b"x".to_vec()).await,
            Err(WriteError::NotWriter)
        );
    }

    #[tokio::test]
    async fn exit_control_is_appended_after_all_output() {
        let (handle, mut pipe, clock) = spawn_session();
        pipe.write_output(b"line1\r\n").await.unwrap();
        pipe.write_output(b"line2\r\n").await.unwrap();
        pipe.exit(SourceExit {
            exit_code: Some(0),
            signal: None,
        });
        // Pull (on the injected clock, no sleep) until the exit control
        // arrives; everything before it must be the whole output.
        let events = drain_until(&handle, &clock, |all| {
            all.iter().any(|e| {
                matches!(
                    e,
                    ReplayEvent::Control {
                        event: ControlEvent::Exit { .. },
                        ..
                    }
                )
            })
        })
        .await;
        let mut bytes = Vec::new();
        let mut saw_exit_after = None;
        for e in &events {
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
        assert_eq!(bytes, b"line1\r\nline2\r\n");
        assert_eq!(saw_exit_after, Some(bytes.len() as u64));
        assert_eq!(handle.info().state, SessionState::Exited);
    }

    #[tokio::test]
    async fn resize_and_signal_reach_the_source() {
        let (handle, pipe, _clock) = spawn_session();
        within(handle.resize(120, 40)).await.unwrap();
        within(handle.signal(Signal::Usr1)).await.unwrap();
        assert_eq!(pipe.resizes(), vec![(120, 40)]);
        assert_eq!(pipe.signals(), vec![Signal::Usr1]);
        assert_eq!(handle.state(), SessionState::Running);
    }

    #[tokio::test]
    async fn close_signals_hup_appends_exit_then_closed_and_stops_the_actor() {
        let (handle, pipe, clock) = spawn_session();
        within(handle.close(CloseReason::Closed, None)).await;
        assert_eq!(pipe.signals(), vec![Signal::Hup]);
        let out = handle
            .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
            .await
            .unwrap();
        // The cooperative child died on HUP: exit(signal) then closed, in
        // that order, closed last.
        let ctls = controls(&out);
        assert_eq!(ctls.len(), 2, "{ctls:?}");
        assert!(matches!(
            &ctls[0],
            ControlEvent::Exit { exit_code: None, signal: Some(s) } if s == "SIGHUP"
        ));
        assert_eq!(
            ctls[1],
            ControlEvent::Closed {
                reason: CloseReason::Closed
            }
        );
        assert!(handle.closed_at().is_some());
        // Actor stopped: further writes report it is gone.
        assert_eq!(handle.write(A, b"x".to_vec()).await, Err(WriteError::Gone));
        // A closed session is still readable (late followers drain it).
        let again = handle
            .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
            .await
            .unwrap();
        assert_eq!(controls(&again).len(), 2);
    }

    #[tokio::test]
    async fn close_of_an_exited_session_sends_no_signal() {
        let (handle, mut pipe, clock) = spawn_session();
        pipe.exit(SourceExit {
            exit_code: Some(3),
            signal: None,
        });
        drain_until(&handle, &clock, |all| {
            all.iter().any(|e| {
                matches!(
                    e,
                    ReplayEvent::Control {
                        event: ControlEvent::Exit { .. },
                        ..
                    }
                )
            })
        })
        .await;
        assert_eq!(handle.state(), SessionState::Exited);
        within(handle.close(CloseReason::Closed, Some(Signal::Term))).await;
        assert!(
            pipe.signals().is_empty(),
            "an exited session must never be signalled (CLI.md §6.7): {:?}",
            pipe.signals()
        );
        let out = handle
            .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
            .await
            .unwrap();
        assert_eq!(
            controls(&out).last(),
            Some(&ControlEvent::Closed {
                reason: CloseReason::Closed
            })
        );
    }

    #[tokio::test]
    async fn close_escalates_hup_term_kill_on_the_injected_clock() {
        let clock = TestClock::new();
        let grace = Duration::from_secs(5);
        let (source, pipe) =
            PipeSource::with_ignored_signals(64 * 1024, &[Signal::Hup, Signal::Term]);
        let handle = spawn_with(
            source,
            &clock,
            SessionConfig {
                close_grace: grace,
                ..SessionConfig::default()
            },
        );
        let closer = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.close(CloseReason::TtlExpired, None).await })
        };
        // Step 1: HUP immediately.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(pipe.signals(), vec![Signal::Hup]);
        assert!(!closer.is_finished());
        // Not yet: one tick short of the grace.
        clock.advance(grace - Duration::from_millis(1));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(pipe.signals(), vec![Signal::Hup]);
        // Step 2: TERM after the grace.
        clock.advance(Duration::from_millis(1));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(pipe.signals(), vec![Signal::Hup, Signal::Term]);
        assert!(!closer.is_finished());
        // Step 3: KILL after another grace; the child dies, close completes.
        clock.advance(grace);
        within(closer).await.unwrap();
        assert_eq!(
            pipe.signals(),
            vec![Signal::Hup, Signal::Term, Signal::Kill]
        );
        let out = handle
            .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
            .await
            .unwrap();
        let ctls = controls(&out);
        assert!(matches!(
            &ctls[0],
            ControlEvent::Exit { signal: Some(s), .. } if s == "SIGKILL"
        ));
        assert_eq!(
            ctls[1],
            ControlEvent::Closed {
                reason: CloseReason::TtlExpired
            }
        );
    }

    #[tokio::test]
    async fn close_with_kill_skips_escalation() {
        let (handle, pipe, _clock) = spawn_session();
        within(handle.close(CloseReason::Closed, Some(Signal::Kill))).await;
        assert_eq!(pipe.signals(), vec![Signal::Kill]);
    }

    #[tokio::test]
    async fn close_of_an_unkillable_child_finishes_after_kill_plus_grace() {
        // Nothing kills it (D-state analogue): HUP, TERM, KILL, then a last
        // grace, then forced cleanup — the close never hangs forever and no
        // synthetic exit is invented.
        let clock = TestClock::new();
        let grace = Duration::from_secs(1);
        let (source, pipe) = PipeSource::with_ignored_signals(64 * 1024, &Signal::ALL);
        let handle = spawn_with(
            source,
            &clock,
            SessionConfig {
                close_grace: grace,
                ..SessionConfig::default()
            },
        );
        let closer = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.close(CloseReason::Closed, None).await })
        };
        for step in 0..3 {
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert!(!closer.is_finished(), "finished early at step {step}");
            clock.advance(grace);
        }
        within(closer).await.unwrap();
        assert_eq!(
            pipe.signals(),
            vec![Signal::Hup, Signal::Term, Signal::Kill]
        );
        let out = handle
            .pull(Cursor::from_offset(0), 1024, Duration::ZERO, &clock)
            .await
            .unwrap();
        assert_eq!(
            controls(&out),
            vec![ControlEvent::Closed {
                reason: CloseReason::Closed
            }]
        );
    }

    #[tokio::test]
    async fn concurrent_closes_all_resolve_on_the_same_close() {
        let (handle, pipe, _clock) = spawn_session();
        let a = {
            let h = handle.clone();
            tokio::spawn(async move { h.close(CloseReason::Closed, None).await })
        };
        let b = {
            let h = handle.clone();
            tokio::spawn(async move { h.close(CloseReason::TtlExpired, Some(Signal::Kill)).await })
        };
        within(a).await.unwrap();
        within(b).await.unwrap();
        // Only the first close's signal was sent; one Closed entry.
        assert_eq!(pipe.signals(), vec![Signal::Hup]);
        let out = handle
            .pull(
                Cursor::from_offset(0),
                1024,
                Duration::ZERO,
                &TestClock::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            controls(&out)
                .iter()
                .filter(|c| matches!(c, ControlEvent::Closed { .. }))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn pull_wait_blocks_until_output_then_returns() {
        let (handle, mut pipe, clock) = spawn_session();
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
        assert_eq!(within(reader).await.unwrap().unwrap(), b"late\r\n");
    }

    #[tokio::test(start_paused = true)]
    async fn pull_wait_times_out_via_the_clock_without_sleeping() {
        let (handle, _pipe, clock) = spawn_session();
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
        let out = within(reader).await.unwrap().unwrap();
        assert!(out.events.is_empty());
    }

    #[tokio::test]
    async fn pull_with_a_huge_wait_does_not_panic() {
        let (handle, mut pipe, clock) = spawn_session();
        // A caller-supplied `--wait` far beyond what an Instant can hold
        // must clamp, not overflow.
        let reader = {
            let handle = handle.clone();
            let clock = clock.clone();
            tokio::spawn(async move {
                handle
                    .pull(Cursor::from_offset(0), 16, Duration::MAX, &clock)
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(!reader.is_finished());
        pipe.write_output(b"ok").await.unwrap();
        let out = within(reader).await.unwrap().unwrap();
        assert_eq!(collect_output(&out), b"ok");
    }

    #[tokio::test]
    async fn per_session_memory_is_bounded_by_the_ring_budget() {
        // The worst producer for a ring: one byte per read, far past the
        // budget. Bytes retained stay within the budget and — because small
        // pushes coalesce — the entry count (the per-entry overhead) stays
        // within budget / chunk as well, so the session's memory is
        // ring budget + O(1), not O(bytes ever produced). Consumers are
        // just cursors: N of them add no per-byte cost.
        let clock = TestClock::new();
        let budget = 4096;
        let (source, mut pipe) = PipeSource::new(1);
        let handle = spawn_with(
            source,
            &clock,
            SessionConfig {
                replay_bytes: budget,
                ..SessionConfig::default()
            },
        );
        let total = 8 * budget;
        for i in 0..total {
            pipe.write_output(&[(i % 251) as u8]).await.unwrap();
        }
        // Wait (injected clock, no sleep) until the pump has ingested
        // everything: pull at the current end until the end reaches total.
        while handle.end_offset() < total as u64 {
            let cursor = Cursor::from_offset(handle.end_offset());
            within(handle.pull(cursor, 1, Duration::from_secs(30), &clock))
                .await
                .unwrap();
        }
        let (retained, entries, ring_budget, piece) = {
            let ring = handle.shared.ring();
            (
                ring.retained(),
                ring.entry_count(),
                ring.budget(),
                ring.chunk_max(),
            )
        };
        assert_eq!(ring_budget, budget);
        assert!(retained <= budget, "retained {retained} > budget {budget}");
        assert!(
            entries <= budget / piece + 1,
            "entries {entries} exceed budget/chunk ({})",
            budget / piece
        );
        // A rough per-entry overhead proxy: even charging 64 B per entry the
        // whole ring is within 2× the budget.
        assert!(retained + entries * 64 <= 2 * budget);
        // Multiple consumers are cursors only: reading from many offsets
        // returns bounded data and allocates nothing in the session.
        for after in [0u64, 100, 4000, handle.end_offset() - 1] {
            let out = handle
                .pull(
                    Cursor::from_offset(after),
                    usize::MAX,
                    Duration::ZERO,
                    &clock,
                )
                .await
                .unwrap();
            assert!(collect_output(&out).len() <= budget);
        }
    }
}
