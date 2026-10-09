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
//! - the **actor loop**: serves the mpsc inbox (`Command`: `Write` /
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

use std::collections::BTreeMap;
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
    /// The identity that opened this session — `crate::acl::opener_key`'s
    /// output (`session.open`'s authenticated `(principal, auth_path)`, not
    /// `ctx.principal.to_string()` alone: see that function's doc for why).
    /// Never surfaced in `session.get`/`list` JSON (`session_info_to_wire`
    /// does not map it) — internal to the `session.control` ownership check
    /// (`docs/history/m3-plan.md` Step 3.5 PR②, PRD §6, M5 Step 5). `Broker::open`/
    /// `open_with` (as opposed to `open_as`, which is what `SessionBackend::
    /// open` — the only production path — always calls) leave this
    /// `String::new()`: no `opener_key` output is ever empty, so a session
    /// created that way is refused by the ownership check for every
    /// principal, permanently.
    /// That is fine for a test double that never drives `session.write`/
    /// `resize` through the wire dispatcher, but is a footgun for any
    /// other caller — prefer `open_as`.
    pub opener: String,
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
    /// Highest cumulative input byte offset applied, **per logical input
    /// stream** (protocol.md §8/§10-5).
    ///
    /// One axis per stream rather than one per session: a resumed attach is
    /// forked from its predecessor's offset ([`SessionHandle::fork_input_stream`]),
    /// so retransmission of an un-acked tail is still exactly-once, while a
    /// peer that has been demoted to read-only — or any other attach living
    /// alongside this one — can no longer move the cursor the live writer
    /// deduplicates against. Bounded by [`MAX_INPUT_AXES`].
    applied_input: BTreeMap<InputStreamId, u64>,
    /// Source of fresh [`InputStreamId`]s for this session.
    next_input_stream: u64,
    /// `true` from the moment a close was accepted (escalation may still be
    /// running). Rejects input and stops the TTL reaper from closing twice.
    closing: bool,
    /// Set once the `Closed` control has been appended (the session is
    /// gone; only late readers draining the ring remain).
    closed_at: Option<Instant>,
}

/// The four facts the TTL rules read, detached from the actor so the same
/// rule serves the reaper ([`SessionHandle::ttl_reap_reason`],
/// [`SessionHandle::resume_deadline`]) and the `broker_ops` fuzz harness
/// (`crates/qsh-core/tests/support/broker_ops_harness.rs`), which has no
/// actor to ask and drives these four fields directly against a model.
#[derive(Debug, Clone, Copy)]
pub struct TtlWindow {
    /// Number of live attachments. TTL only runs while this is zero.
    pub attached: usize,
    /// `true` from the moment a close was accepted.
    pub closing: bool,
    /// Lifecycle state (decides `Exit` vs `TtlExpired`).
    pub state: SessionState,
    /// Monotonic instant the TTL is measured from when `attached == 0`.
    pub ttl_base: Instant,
}

impl TtlWindow {
    /// See [`SessionHandle::ttl_reap_reason`].
    pub fn reap_reason(&self, now: Instant, ttl: Duration) -> Option<CloseReason> {
        if self.attached > 0 || self.closing {
            return None;
        }
        if now.saturating_duration_since(self.ttl_base) < ttl {
            return None;
        }
        Some(match self.state {
            SessionState::Exited => CloseReason::Exit,
            SessionState::Running => CloseReason::TtlExpired,
        })
    }

    /// See [`SessionHandle::resume_deadline`].
    pub fn deadline(&self, now: Instant, ttl: Duration) -> Instant {
        if self.attached > 0 {
            now + ttl
        } else {
            self.ttl_base + ttl
        }
    }
}

/// State shared between the actor and every [`SessionHandle`] clone.
pub struct SessionShared {
    id: String,
    created_at: String,
    /// The owner key recorded at open ([`SessionInfo::opener`]) — set once
    /// at creation, never mutated (`docs/history/m3-plan.md` Step 3.5 PR②).
    opener: String,
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

/// Identifies one logical client input stream on a session.
///
/// Minted by the host, one per attach: `session.open` gets the session's
/// first, and every `session.attach` gets a fresh one *forked* from the
/// axis its resume credential names, inheriting that axis's applied offset
/// (protocol.md §10-5 — that is what makes the dedup cursor survive a
/// reattach instead of restarting per attach, without two live attaches
/// sharing one axis). Opaque to the peer: it rides on the ticket, never on
/// the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InputStreamId(pub u64);

/// The input stream `session.open`'s own ticket carries — the session's
/// first, and the one a resume lineage forks from until it forks again.
pub const FIRST_INPUT_STREAM: InputStreamId = InputStreamId(1);

/// How many input axes a session remembers.
///
/// Every attach forks a fresh axis, so without a bound a long-lived session
/// that reconnects all day would grow one entry per recovery. Only the most
/// recent axes can still have a live peer numbering against them (an attach
/// this many generations old lost its lease long ago), so the oldest are
/// dropped when a new one is minted.
const MAX_INPUT_AXES: usize = 32;

/// Hold the axis map to [`MAX_INPUT_AXES`], dropping the oldest ids first.
///
/// Ids are minted monotonically, so `BTreeMap` order is age order and the
/// axis just created is always the largest key — it can never prune itself.
fn prune_input_axes(meta: &mut Meta) {
    while meta.applied_input.len() > MAX_INPUT_AXES {
        let oldest = *meta
            .applied_input
            .keys()
            .next()
            .expect("non-empty: len is above the bound");
        meta.applied_input.remove(&oldest);
    }
}

/// Inbox messages (architecture.md §3 "mpsc 인박스").
enum Command {
    Write {
        conn: ConnectionId,
        data: Vec<u8>,
        /// The numbered input stream this chunk belongs to and the
        /// cumulative offset *after* it. `None` for the `session.write`
        /// value op, which has no cursor of its own: it injects out of band
        /// and deliberately does not move any stream's axis.
        input_seq: Option<(InputStreamId, u64)>,
        resp: oneshot::Sender<Result<u64, WriteError>>,
    },
    Resize {
        cols: u16,
        rows: u16,
        resp: oneshot::Sender<io::Result<()>>,
    },
    /// The `SESSION_DATA` stream's resize, unlike [`Command::Resize`],
    /// requires `conn` to hold the writer lease — the same bound `Input`
    /// on that stream already has (`docs/history/m3-plan.md` Step 3.5 PR② follow-up: a
    /// demoted attach must not still be able to mutate the live PTY).
    ResizeAt {
        conn: ConnectionId,
        cols: u16,
        rows: u16,
        resp: oneshot::Sender<Result<(), WriteError>>,
    },
    Signal {
        signal: Signal,
        resp: oneshot::Sender<io::Result<()>>,
    },
    TakeLease {
        principal: String,
        /// Comparison identity — `lease::LeaseHolder::conn`'s own doc.
        conn: ConnectionId,
        /// Release-on-death connection — `lease::LeaseHolder::physical`'s
        /// own doc. Equal to `conn` for every caller except
        /// [`SessionHandle::take_lease_owned`].
        physical: ConnectionId,
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
    /// The chunk starts past what the session has applied: the peer
    /// skipped input bytes the host never received. Accepting would lose
    /// them silently, which PRD §8 forbids — this is a protocol fault, not
    /// a retryable condition.
    #[error("input starts at {start} but only {applied} bytes were applied")]
    InputGap {
        /// Cumulative offset the rejected chunk starts at.
        start: u64,
        /// Cumulative offset the session had applied.
        applied: u64,
    },
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

    /// The owner key recorded when this session was opened
    /// ([`SessionInfo::opener`] — `docs/history/m3-plan.md` Step 3.5 PR②'s
    /// `session.control` ownership check).
    pub fn opener(&self) -> &str {
        &self.shared.opener
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
            opener: self.shared.opener.clone(),
        }
    }

    /// Read from `cursor`, returning at most `max_bytes` of output plus any
    /// control entries due, in stream order. If nothing is ready and
    /// `wait` is non-zero, sleep on `clock` until there is something or the
    /// deadline passes (the cursor-pull primitive — architecture.md §3;
    /// the same call backs `session read --wait`, `--follow` and a
    /// long-running external process's (e.g. an agent tool) long-poll).
    /// Never needs the lease. Works on a closed session too,
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
        self.write_at(conn, data, None).await.map(|_| ())
    }

    /// Write client input carrying its cumulative offset (`input_seq` is
    /// the offset *after* the chunk, protocol.md §8). The session trims
    /// whatever it already applied and answers with its applied offset, so
    /// a reattach may retransmit freely: input is neither lost nor applied
    /// twice (protocol.md §10-5). `None` appends without a cursor.
    pub async fn write_at(
        &self,
        conn: ConnectionId,
        data: Vec<u8>,
        input_seq: Option<(InputStreamId, u64)>,
    ) -> Result<u64, WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::Write {
                conn,
                data,
                input_seq,
                resp,
            })
            .await
            .map_err(|_| WriteError::Gone)?;
        rx.await.map_err(|_| WriteError::Gone)?
    }

    /// Reserve the id of the input axis one attach *will* use, without
    /// creating it.
    ///
    /// Split from [`seed_input_stream`](Self::seed_input_stream) so an
    /// attach can name its axis to the credential rotation before the
    /// rotation has decided. A redemption that loses that race then burns
    /// nothing but a counter value: no map slot is taken, so a lost race
    /// cannot evict a live peer's axis from the `MAX_INPUT_AXES` window.
    ///
    /// A **fresh** id every time, never the predecessor's, is what keeps
    /// the previous attach — which may still be connected and typing after
    /// being demoted to read-only — off the axis this one deduplicates
    /// against.
    pub fn reserve_input_stream(&self) -> InputStreamId {
        let mut meta = self.shared.meta();
        let id = InputStreamId(meta.next_input_stream);
        meta.next_input_stream += 1;
        id
    }

    /// Create the axis [`reserve_input_stream`](Self::reserve_input_stream)
    /// handed out, and say where it starts.
    ///
    /// `from` is the axis this attach continues — the predecessor recorded
    /// on the resume credential — and the new axis is seeded with exactly
    /// what that one had applied, so the client's un-acked tail is still
    /// deduplicated to exactly-once (protocol.md §10-5). `None` is a client
    /// with no history: it starts at zero and deduplicates against nobody.
    pub fn seed_input_stream(&self, id: InputStreamId, from: Option<InputStreamId>) -> u64 {
        let mut meta = self.shared.meta();
        let start = from
            .and_then(|prev| meta.applied_input.get(&prev).copied())
            .unwrap_or(0);
        meta.applied_input.insert(id, start);
        prune_input_axes(&mut meta);
        start
    }

    /// [`reserve_input_stream`](Self::reserve_input_stream) followed by
    /// [`seed_input_stream`](Self::seed_input_stream) — the whole fork, for
    /// callers with no rotation to interleave.
    #[cfg(test)]
    pub fn fork_input_stream(&self, from: Option<InputStreamId>) -> (InputStreamId, u64) {
        let id = self.reserve_input_stream();
        let start = self.seed_input_stream(id, from);
        (id, start)
    }

    /// How far `stream` has been applied (tests and diagnostics).
    pub fn applied_input(&self, stream: InputStreamId) -> Option<u64> {
        self.shared.meta().applied_input.get(&stream).copied()
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

    /// [`resize`](Self::resize), refused with [`WriteError::NotWriter`]
    /// unless `conn` holds the writer lease. The `SESSION_DATA` stream's
    /// `Resize` frame uses this, not `resize` — a peer whose `Input` is
    /// already being discarded as read-only (lease stolen by a steal-back
    /// reattach) must not keep mutating the live PTY's window size either.
    pub async fn resize_at(
        &self,
        conn: ConnectionId,
        cols: u16,
        rows: u16,
    ) -> Result<(), WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::ResizeAt {
                conn,
                cols,
                rows,
                resp,
            })
            .await
            .map_err(|_| WriteError::Gone)?;
        rx.await.map_err(|_| WriteError::Gone)?
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

    /// Whether a `no_steal` take would conflict: a **different** principal
    /// holds a live lease (architecture.md §3 rule b — the same principal
    /// on another connection is the same writer moving devices).
    ///
    /// A read-only snapshot, not a decision: the binding take still goes
    /// through the actor. It exists so a caller whose own decision is not
    /// final yet can refuse without mutating anything.
    pub fn lease_conflict(&self, principal: &str) -> bool {
        self.shared
            .meta()
            .lease
            .holder()
            .is_some_and(|h| h.principal != principal)
    }

    /// Try to take the writer lease. See [`WriterLease::take`]. Identity
    /// and release-on-death connection are the same value (`conn`) here —
    /// see [`Self::take_lease_owned`] for the reverse-route case where a
    /// finer identity than the physical connection is needed.
    pub async fn take_lease(
        &self,
        principal: impl Into<String>,
        conn: ConnectionId,
        no_steal: bool,
    ) -> Result<TakeOutcome, WriteError> {
        self.take_lease_owned(principal, conn, conn, no_steal).await
    }

    /// [`Self::take_lease`], with the comparison identity (`owner`) and the
    /// release-on-death connection (`physical`) given separately. See
    /// [`WriterLease::take_owned`]'s doc for why the two can differ (a
    /// reverse-route `SESSION_DATA` stream's `owner` is derived from its
    /// single-use ticket, never from the daemon's shared registration
    /// connection).
    pub async fn take_lease_owned(
        &self,
        principal: impl Into<String>,
        owner: ConnectionId,
        physical: ConnectionId,
        no_steal: bool,
    ) -> Result<TakeOutcome, WriteError> {
        let (resp, rx) = oneshot::channel();
        self.inbox
            .send(Command::TakeLease {
                principal: principal.into(),
                conn: owner,
                physical,
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
        self.ttl_window().reap_reason(now, ttl)
    }

    /// When this session stops being resumable, on the broker's clock.
    ///
    /// While attached the TTL does not run at all (architecture.md §3), so
    /// the answer is `now + ttl`: the session cannot be reaped before then
    /// whatever happens next. Unattached it is `ttl` past the last detach
    /// (or the exit, or creation) — the same instant [`ttl_reap_reason`]
    /// fires on. The resume credential is anchored to this, so a credential
    /// never expires under a session that is still alive.
    ///
    /// [`ttl_reap_reason`]: Self::ttl_reap_reason
    pub fn resume_deadline(&self, now: Instant, ttl: Duration) -> Instant {
        self.ttl_window().deadline(now, ttl)
    }

    /// The four facts [`TtlWindow`]'s rules read, snapshotted from this
    /// session's `Meta` under one lock acquisition.
    fn ttl_window(&self) -> TtlWindow {
        let meta = self.shared.meta();
        TtlWindow {
            attached: meta.attached,
            closing: meta.closing,
            state: meta.state,
            ttl_base: meta.ttl_base,
        }
    }

    /// Current lifecycle state.
    pub fn state(&self) -> SessionState {
        self.shared.meta().state
    }

    /// Whether at least one consumer is attached right now. `false` is the
    /// "detached" state the resume TTL runs in.
    pub fn is_attached(&self) -> bool {
        self.shared.meta().attached > 0
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
    /// `id` is the opaque session id; `created_at` is the RFC 3339 stamp;
    /// `opener` is the opaque owner key recorded for this session
    /// ([`SessionInfo::opener`] — `docs/history/m3-plan.md` Step 3.5 PR②).
    pub fn create(
        id: String,
        created_at: String,
        opener: String,
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
            opener,
            clock,
            ring: Mutex::new(ring),
            notify: Notify::new(),
            meta: Mutex::new(Meta {
                state: SessionState::Running,
                lease: WriterLease::new(),
                attached: 0,
                ttl_base,
                applied_input: BTreeMap::from([(FIRST_INPUT_STREAM, 0)]),
                next_input_stream: FIRST_INPUT_STREAM.0 + 1,
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
            while let Some((data, applied, resp)) = in_rx.recv().await {
                let result = async {
                    input.write_all(&data).await?;
                    input.flush().await
                }
                .await
                .map(|()| applied)
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

type InputChunk = (Vec<u8>, u64, oneshot::Sender<Result<u64, WriteError>>);

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
            Command::Write {
                conn,
                data,
                input_seq,
                resp,
            } => {
                // On refusal `resp` was answered inside; nothing else to do.
                self.enqueue_write(conn, data, input_seq, resp);
            }
            Command::Resize { cols, rows, resp } => {
                let _ = resp.send(self.control.resize(cols, rows));
            }
            Command::ResizeAt {
                conn,
                cols,
                rows,
                resp,
            } => {
                let result = if !self.shared.meta().lease.is_held_by(conn) {
                    Err(WriteError::NotWriter)
                } else {
                    self.control
                        .resize(cols, rows)
                        .map_err(|e| WriteError::Io(e.to_string()))
                };
                let _ = resp.send(result);
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
                physical,
                no_steal,
                resp,
            } => {
                let outcome = self
                    .shared
                    .meta()
                    .lease
                    .take_owned(&principal, conn, physical, no_steal);
                if let TakeOutcome::Acquired { changed: true, .. } = &outcome {
                    // Tracks the *physical* connection, consistent with
                    // `ReleaseConnection` below (also physical-keyed) —
                    // never the finer `conn`/owner identity.
                    self.lease_conn = Some(physical);
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
    /// Admit one input chunk: state + lease, then the session's input
    /// cursor, then the bounded queue.
    ///
    /// The cursor arithmetic happens **here**, inside the actor, because
    /// the actor is what serialises writes: the order chunks are enqueued
    /// is the order the child sees them, so trimming an already-applied
    /// prefix under the same serialisation is what makes a reattach's
    /// retransmission exactly-once (protocol.md §10-5). Doing it in the
    /// stream pump instead would make it per-attach, and a reattach would
    /// replay input the child already ran.
    fn enqueue_write(
        &mut self,
        conn: ConnectionId,
        data: Vec<u8>,
        input_seq: Option<(InputStreamId, u64)>,
        resp: oneshot::Sender<Result<u64, WriteError>>,
    ) {
        // The axis this chunk is numbered on. A stream nobody minted (or one
        // pruned generations ago) starts from zero rather than borrowing
        // another client's offset.
        let axis = input_seq.map(|(stream, _)| stream);
        let admit = {
            let meta = self.shared.meta();
            if meta.state != SessionState::Running || meta.closing {
                Err(WriteError::NotRunning)
            } else if !meta.lease.is_held_by(conn) {
                Err(WriteError::NotWriter)
            } else {
                Ok(axis
                    .and_then(|stream| meta.applied_input.get(&stream).copied())
                    .unwrap_or(0))
            }
        };
        let applied = match admit {
            Ok(applied) => applied,
            Err(err) => {
                // A refused numbered chunk still moves **its own** axis: the
                // bytes are deliberately dropped (a demoted read-only
                // attach, protocol.md §10 "read-only로 강등"), and the peer
                // must not resend them when its lease returns. Touching only
                // its own axis is what keeps that advance from poisoning the
                // live writer's — a peer holding no lease has no effect on
                // any state but its own.
                if let Some((stream, seq)) = input_seq {
                    let mut meta = self.shared.meta();
                    let slot = meta.applied_input.entry(stream).or_insert(0);
                    *slot = (*slot).max(seq);
                    // This path can create an axis too (a peer numbering
                    // against an axis already pruned out), so it owes the
                    // same bound a fork does — otherwise the map sits above
                    // MAX_INPUT_AXES until the next attach.
                    prune_input_axes(&mut meta);
                }
                let _ = resp.send(Err(err));
                return;
            }
        };
        let (data, next) = match input_seq {
            // The value op has no cursor: it injects out of band and must
            // not move any stream's axis, or the attached writer's next
            // chunk would look like a retransmission and be dropped.
            None => (data, applied),
            Some((_, seq)) => {
                let Some(start) = seq.checked_sub(data.len() as u64) else {
                    let _ = resp.send(Err(WriteError::InputGap {
                        start: seq,
                        applied,
                    }));
                    return;
                };
                if start > applied {
                    // Bytes we never saw would be skipped; accepting would
                    // lose them silently, which PRD §8 forbids.
                    let _ = resp.send(Err(WriteError::InputGap { start, applied }));
                    return;
                }
                let skip = (applied - start) as usize;
                if skip >= data.len() {
                    // Entirely a retransmission of what the child already
                    // ran: acknowledge it again and apply nothing.
                    let _ = resp.send(Ok(applied));
                    return;
                }
                (data[skip..].to_vec(), seq)
            }
        };
        match self.in_tx.try_send((data, next, resp)) {
            Ok(()) => {
                if let Some(stream) = axis {
                    self.shared.meta().applied_input.insert(stream, next);
                }
            }
            Err(mpsc::error::TrySendError::Full((_, _, resp))) => {
                let _ = resp.send(Err(WriteError::Backpressure));
            }
            Err(mpsc::error::TrySendError::Closed((_, _, resp))) => {
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
mod tests;
