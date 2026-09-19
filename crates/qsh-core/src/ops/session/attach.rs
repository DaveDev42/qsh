//! The `session.attach` stream op: [`SessionAttachOp`], [`SessionAttachStream`], and the [`AttachHandle`] a frontend drives it through.

use super::*;

/// The `session.attach` operation — the only stream op.
pub struct SessionAttachOp;
impl Operation for SessionAttachOp {
    const COMMAND: &'static str = "session.attach";
}

/// What a frontend sends into a live attach.
pub(super) enum AttachCommand {
    /// Session input, split into wire chunks by the writer.
    Input(Vec<u8>),
    /// A window-size change.
    Resize {
        /// New column count.
        cols: u16,
        /// New row count.
        rows: u16,
    },
    /// Finish the send half and report back once the host has acknowledged
    /// applying everything written before it. Travels the same ordered
    /// queue as the input so a detach cannot overtake the bytes typed just
    /// before it (`docs/CLI.md` §7).
    Detach(std::sync::mpsc::SyncSender<DetachFlush>),
}

/// What a detach could establish about the input queued ahead of it.
///
/// A detach closes the connection, and a QUIC close throws away anything
/// the peer has not taken, so "did the shell get it?" has to be answered
/// *before* the close rather than assumed after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachFlush {
    /// The host acknowledged applying every byte written before the detach:
    /// a command typed immediately ahead of `~d` reached the child.
    Applied,
    /// The bound elapsed with bytes still unacknowledged, so they may never
    /// have reached the child. The caller has to say so — silently dropped
    /// input is what `docs/PRD.md` §8 forbids.
    Unconfirmed,
}

/// A live attach: a blocking `qsh.event/v1` event stream out, an
/// input/resize channel in. See [`Ops::session_attach`].
///
/// The connection, its runtime and the driver task are owned here, so
/// dropping this ends the attach.
pub struct SessionAttachStream {
    /// **Declared first on purpose**: fields drop in declaration order, so
    /// this marks the attach deliberately over and stops the driver before
    /// the connection underneath it goes away. Without it, dropping a
    /// stream without calling [`close`](Self::close) closes the connection
    /// with `finished` still false, and the driver reads its own teardown
    /// as a path death and starts re-dialing.
    pub(super) stop: AttachStop,
    /// The `-L` local forwards opened on this attach, if any
    /// ([`Self::open_local_forwards`]). Declared **before** `conn`
    /// deliberately: each handle's drop aborts its accept loop on `conn`'s
    /// runtime, so they must go while that runtime is still there. That
    /// ordering is also the whole `-L` teardown story — the listeners die
    /// with the attach, no daemon and no close RPC (`PLAN.md` M4 §4.1 #1).
    pub(super) forwards: Vec<crate::tunnel::LocalForwardHandle>,
    /// The `-D` dynamic (SOCKS5) forwards opened on this attach, if any
    /// ([`Self::open_dynamic_forwards`], ADR-0019 decision 11). Declared
    /// **before** `conn` for the same reason `forwards` is: each handle's
    /// drop aborts its accept loop on `conn`'s runtime.
    pub(super) dynamic_forwards: Vec<crate::tunnel::DynamicForwardHandle>,
    /// The `-R` remote forwards opened on this attach, if any — one shared
    /// [`crate::tunnel::remote::RemoteForwardAcceptor`] for every `-R` spec
    /// on this attach (`PLAN.md` M4 Step 4): a single `TCP_ACCEPTED`
    /// dispatcher per connection is not an optimization, it is the only
    /// correct shape once more than one `-R` shares a connection (that
    /// type's own doc explains why two independent accept loops would
    /// misroute each other's streams). Declared **before** `conn` for the
    /// same reason `forwards` is: its accept task runs on `conn`'s runtime.
    /// Set by [`Ops::session_attach`] itself, not by a method on this
    /// type — see that method's own doc for why the `RemoteForwardOpen`
    /// round trips cannot wait until after this value exists.
    ///
    /// Never read again after this: it is held purely for its `Drop`
    /// (aborts the `TCP_ACCEPTED` dispatcher task, same one-drop teardown
    /// `forwards`'s handles use) — `rustc`'s `dead_code` lint cannot see a
    /// field kept alive only for its destructor, hence the `allow` below.
    #[allow(dead_code)]
    pub(super) remote_acceptor: Option<crate::tunnel::remote::RemoteForwardAcceptor>,
    /// The `qsh.cli/v1` [`Tunnel`](qsh_proto::Tunnel) DTO for each `-R`
    /// spec [`Ops::session_attach`] already opened, waiting for
    /// [`Self::take_remote_forward_tunnels`] to hand them to the frontend
    /// to render — the same information `-L`'s [`Self::open_local_forwards`]
    /// returns directly, split out here only because `-R`'s RPCs cannot
    /// run this late (this struct's own doc on `remote_acceptor`).
    pub(super) remote_tunnels: Vec<qsh_proto::Tunnel>,
    /// The capabilities negotiated at handshake time, captured **before**
    /// [`Ops::session_attach`] calls `conn.take_session()` to hand the
    /// session to the background driver. [`Connected::capabilities`]
    /// itself reads `&[]` once its `session` has been taken (that method's
    /// own doc), which is unconditionally true of `conn` by the time this
    /// struct exists — so [`Self::open_dynamic_forwards`]'s `dial-filter.v1`
    /// gate reads this field, never `self.conn.capabilities()`, or it would
    /// refuse every attach's `-D`, negotiated or not (the bug this field
    /// fixes: found by `dynamic_forward.rs`'s
    /// `interactive_dash_d_opens_listener_beside_session` failing against a
    /// live peer that plainly does advertise `dial-filter.v1`).
    pub(super) capabilities: Vec<String>,
    pub(super) conn: Connected,
    /// See [`SessionReader::store`].
    pub(super) store: ResumeStore,
    pub(super) events: tokio::sync::mpsc::Receiver<Result<SessionEvent, OpError>>,
    pub(super) commands: tokio::sync::mpsc::Sender<AttachCommand>,
    pub(super) session_ref: String,
    pub(super) replay_from: u64,
    pub(super) writer_lease: bool,
    /// When to push the stored entry's expiry forward; `None` when the
    /// host's window did not parse and there is nothing to schedule from.
    pub(super) renewal: Option<RenewalSchedule>,
    pub(super) expires_at: String,
    /// What [`Self::handle`] hands each [`AttachHandle`] — computed once
    /// at `session_attach` and kept here rather than re-derived from
    /// `conn` on every call, because the reverse route's half
    /// (`attached.kill`) only ever exists for the instant right after
    /// `open_attach_stream` returns (`crate::ops::session::RecoveryLink`'s
    /// own doc).
    pub(super) link: RecoveryLink,
}

/// Ends an attach the same way whether it was closed or merely dropped:
/// mark it deliberately over, then stop the driver. See
/// [`SessionAttachStream::stop`].
pub(super) struct AttachStop {
    /// Shared with the driver: set once this attach is deliberately over,
    /// so a connection the frontend closed is never recovered from.
    pub(super) finished: Arc<std::sync::atomic::AtomicBool>,
    /// See [`AttachHandle::detaching`].
    pub(super) detaching: Arc<std::sync::Mutex<()>>,
    pub(super) driver: tokio::task::JoinHandle<()>,
}

impl Drop for AttachStop {
    fn drop(&mut self) {
        // A `~d` runs on the frontend's input thread while the thread that
        // owns the stream is still in `next_event`, so the two race: the
        // detach is announced before it has flushed, and the owner can
        // reach this teardown while the driver is still writing the bytes
        // typed just before the escape. Aborting there loses them for
        // good. The gate makes the teardown wait out a detach that is
        // already in flight — which is bounded by
        // [`DETACH_FLUSH_GRACE`], not by the host.
        let _flushing = lock(&self.detaching);
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        self.driver.abort();
    }
}

/// When a live attach owes its stored resume entry a fresh `expires_at`.
///
/// Split out as a pure schedule with an injected `now` for one reason: the
/// bug it replaces was not in the arithmetic but in what drove it. Renewal
/// used to happen only as a side effect of an event arriving, so an attach
/// that produced no output — the all-day-idle shell the resume feature
/// exists to protect — never renewed, and the client-side "drop an entry
/// whose `expires_at` has passed" rule then deleted a credential the host
/// would still have honoured. A schedule that can be asked "how long until
/// the next one is due?" is what lets the waiting loop wake for the
/// renewal instead of for an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RenewalSchedule {
    ttl: std::time::Duration,
    due: std::time::Instant,
}

impl RenewalSchedule {
    /// Renew every half-window: at the default 24 h TTL that is one small
    /// disk write every twelve hours, and it leaves a full half-window of
    /// slack for a renewal that fails.
    pub(super) fn new(ttl: std::time::Duration, now: std::time::Instant) -> Self {
        Self {
            ttl,
            due: now + Self::period(ttl),
        }
    }

    fn period(ttl: std::time::Duration) -> std::time::Duration {
        // Never zero: a degenerate TTL must not turn the waiting loop into
        // a spin.
        (ttl / 2).max(std::time::Duration::from_millis(1))
    }

    /// The window the host granted, which is also what a renewal writes.
    pub(super) fn ttl(&self) -> std::time::Duration {
        self.ttl
    }

    /// How long until the next renewal is due — what the event wait is
    /// bounded by, so a silent attach still wakes up in time.
    pub(super) fn due_in(&self, now: std::time::Instant) -> std::time::Duration {
        self.due.saturating_duration_since(now)
    }

    /// Claim a due renewal and arm the next one. `false` if it is not due
    /// yet, so the caller does not write the file on every wakeup.
    pub(super) fn take_if_due(&mut self, now: std::time::Instant) -> bool {
        if now < self.due {
            return false;
        }
        self.due = now + Self::period(self.ttl);
        true
    }
}

impl SessionAttachStream {
    /// Bind and start this attach's `-L` local forwards (`PLAN.md` M4
    /// Step 3; `docs/CLI.md` §7 "`-L`/`-R`은 이 대화형 form의 companion
    /// flag이지 별도 명령이 아니다").
    ///
    /// The forwards ride **this attach's** connection and are owned by
    /// this stream, so they live exactly as long as the interactive
    /// session and die with it — the foreground holder model (§4.1 #1),
    /// with no daemon and no orphaned bound port. Nothing here is
    /// authorized locally: each forwarded TCP connection is authorized by
    /// the peer, inline at stream open, before the peer dials anything
    /// (`docs/design/protocol.md` §7).
    ///
    /// Binding is all-or-nothing: a spec that fails drops every listener
    /// this call already bound, so a partially-established `-L` set never
    /// survives into the session. Call it **before** the frontend takes
    /// the terminal — a bind failure is an ordinary typed error, and the
    /// caller should report it rather than half-start a session.
    ///
    /// Returns the [`qsh_proto::Tunnel`] DTO of each forward, in `specs`
    /// order, for
    /// the frontend to render.
    pub fn open_local_forwards(
        &mut self,
        specs: &[qsh_proto::wire::ForwardSpec],
    ) -> Result<Vec<qsh_proto::Tunnel>, OpError> {
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        let host = parse_session_ref(&self.session_ref)?.host;
        // A `-L` needs a raw QUIC stream of its own; the reverse route has
        // no connection here to open one on (`Connected::connection`).
        // Fail closed rather than pretend (`PLAN.md` M4 Step 5).
        let Some(connection) = self.conn.connection() else {
            return Err(OpError::new(
                ErrorCode::Unsupported,
                "local forwards over a reverse connection are not implemented yet",
            ));
        };
        let started = {
            let runtime = self.conn.runtime();
            let mut started = Vec::with_capacity(specs.len());
            for spec in specs {
                // On `Err` the loop returns, dropping every handle in
                // `started` — each drop closes its listener.
                let handle = runtime
                    .block_on(crate::tunnel::LocalForwardHandle::start(
                        spec,
                        connection.clone(),
                    ))
                    .map_err(crate::ops::tunnel::map_local_forward_error)?;
                started.push(handle);
            }
            started
        };
        let tunnels = started.iter().map(|f| f.tunnel(&host)).collect();
        self.forwards.extend(started);
        Ok(tunnels)
    }

    /// Bind and start this attach's `-D` dynamic (SOCKS5) forwards
    /// (ADR-0019 decision 11) — the interactive twin of
    /// [`Ops::tunnel_dynamic`](crate::ops::Ops::tunnel_dynamic), shaped
    /// like [`Self::open_local_forwards`]: rides this attach's own
    /// connection, refuses a reverse route (ADR-0019 decisions 3, 10) and
    /// the peer's missing `dial-filter.v1` capability (ADR-0019 decision
    /// 3, no fallback) before binding anything, and is all-or-nothing —
    /// a spec that fails drops every listener this call already bound.
    ///
    /// Returns the [`qsh_proto::DynamicTunnel`] DTO of each forward, in
    /// `specs` order, for the frontend to render.
    pub fn open_dynamic_forwards(
        &mut self,
        specs: &[qsh_proto::wire::DynamicSpec],
    ) -> Result<Vec<qsh_proto::DynamicTunnel>, OpError> {
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        let host = parse_session_ref(&self.session_ref)?.host;
        // Same reverse-route refusal `open_local_forwards` applies, before
        // any resource exists (ADR-0019 decisions 3, 10 — `-D` is
        // forward-route only at this landing). This is a backstop, not
        // the primary gate: `tui::run` (the only caller that can reach a
        // reverse route interactively) already calls
        // `Ops::check_dynamic_route` *before* `session.open`, so a
        // reverse-routed host is refused before a session — let alone a
        // listener — ever exists. This check stays so `open_dynamic_forwards`
        // is still safe to call from anywhere without relying on a caller
        // to have checked first.
        let Some(connection) = self.conn.connection() else {
            return Err(crate::ops::tunnel::dynamic_forward_reverse_unsupported_interactive());
        };
        // ADR-0019 decision 3: no fallback if the peer never advertised
        // the capability this dial policy depends on — refused here,
        // before any listener binds, exactly like `Ops::tunnel_dynamic`'s
        // own gate. Shares the actual predicate with that gate through
        // `require_dial_filter_capability`, not a second independently
        // re-derived `if`.
        crate::ops::tunnel::require_dial_filter_capability(&self.capabilities)?;
        let started = {
            let runtime = self.conn.runtime();
            let mut started = Vec::with_capacity(specs.len());
            for spec in specs {
                // On `Err` the loop returns, dropping every handle in
                // `started` — each drop closes its listener.
                let handle = runtime
                    .block_on(crate::tunnel::DynamicForwardHandle::start(
                        spec.bind.as_deref(),
                        spec.listen_port,
                        connection.clone(),
                    ))
                    .map_err(crate::ops::tunnel::map_local_forward_error)?;
                started.push(handle);
            }
            started
        };
        let tunnels = started.iter().map(|f| f.dynamic_tunnel(&host)).collect();
        self.dynamic_forwards.extend(started);
        Ok(tunnels)
    }

    /// This attach's `-R` remote forward [`Tunnel`](qsh_proto::Tunnel)
    /// DTOs, for the frontend to render — one per spec, in the order
    /// passed to [`Ops::session_attach`], which is where the actual
    /// `RemoteForwardOpen` round trips already happened (this method's own
    /// struct field doc, `SessionAttachStream::remote_acceptor`, says
    /// why they cannot happen here instead). Takes the vec, so a second
    /// call sees nothing left — there is exactly one batch to hand over,
    /// same as `-L`'s single [`Self::open_local_forwards`] call.
    pub fn take_remote_forward_tunnels(&mut self) -> Vec<qsh_proto::Tunnel> {
        std::mem::take(&mut self.remote_tunnels)
    }

    /// The session being attached.
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }

    /// Cumulative output offset replay started from.
    pub fn replay_from(&self) -> u64 {
        self.replay_from
    }

    /// Whether this attach holds the writer lease.
    pub fn writer_lease(&self) -> bool {
        self.writer_lease
    }

    /// When the session's resume window ends (RFC 3339), as the host
    /// reported it when this attach was **first** established.
    ///
    /// A snapshot, not a live value: a resume underneath this stream gets a
    /// fresh `expires_at` from the host and writes it straight to the
    /// stored credential (`reattach`), which is the copy that decides
    /// whether a later attach can resume. This one is not re-read, because
    /// the TTL the host grants is a constant of its configuration; if that
    /// ever stops being true, the driver has to publish the new window back
    /// here and into `RenewalSchedule::ttl` together.
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    /// Block until the next event. `None` once the stream has ended — the
    /// child exited, the session closed, or the connection went away.
    ///
    /// Call from a plain thread, never from inside an async runtime: like
    /// every other `Ops` entry point this is the blocking face of the
    /// driver that owns the connection.
    pub fn next_event(&mut self) -> Option<Result<SessionEvent, OpError>> {
        loop {
            self.renew_credential();
            // The wait is bounded by the next renewal, never by the next
            // event: a shell nobody is typing into can go a whole day
            // without producing a byte, and that is precisely the session
            // whose credential must not be allowed to go stale.
            let event = match self.renewal.map(|r| r.due_in(std::time::Instant::now())) {
                Some(wait) => {
                    let runtime = self.conn.runtime();
                    let events = &mut self.events;
                    // The timer is created *inside* `block_on`: `timeout`
                    // arms its sleep eagerly, and there is no reactor on
                    // this thread until the runtime is entered.
                    match runtime
                        .block_on(async { tokio::time::timeout(wait, events.recv()).await })
                    {
                        Ok(Some(event)) => event,
                        Ok(None) => return None,
                        // The renewal came due first. Round the loop, write
                        // it, and go back to waiting.
                        Err(_) => continue,
                    }
                }
                None => self.events.blocking_recv()?,
            };
            if let Ok(event) = &event {
                forget_if_closed(&self.store, &self.session_ref, event);
            }
            return Some(event);
        }
    }

    /// Keep the stored credential's expiry ahead of the clock while this
    /// attach is alive. Runs at most once per half-window (a disk write
    /// every twelve hours at the default TTL), and a failure is not fatal:
    /// the host is the authority, and the worst case is the stale stamp
    /// this is trying to avoid.
    fn renew_credential(&mut self) {
        let Some(schedule) = self.renewal.as_mut() else {
            return;
        };
        if !schedule.take_if_due(std::time::Instant::now()) {
            return;
        }
        let ttl = schedule.ttl();
        if let Err(err) = self.store.renew(&self.session_ref, ttl) {
            tracing::debug!(session_ref = %self.session_ref, %err, "resume entry renewal failed");
        }
    }

    /// Queue session input; the driver writes it in order. Blocks only
    /// while the driver's bounded queue is full — that backpressure is
    /// what keeps a fast producer from growing the queue without limit.
    pub fn write(&self, data: Vec<u8>) -> Result<(), OpError> {
        self.handle().write(data)
    }

    /// Queue a window-size change. Same backpressure as [`write`](Self::write).
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), OpError> {
        self.handle().resize(cols, rows)
    }

    /// A cloneable handle on the input side of this attach.
    ///
    /// [`next_event`](Self::next_event) blocks the thread that owns the
    /// stream, so anything that has to reach the session while output is
    /// flowing — a terminal's input pump, a `SIGWINCH` watcher, a detach
    /// key — runs on another thread and needs its own handle. The stream
    /// stays the sole owner of the event side.
    pub fn handle(&self) -> AttachHandle {
        AttachHandle {
            commands: self.commands.clone(),
            link: self.link.clone(),
            finished: self.stop.finished.clone(),
            detaching: self.stop.detaching.clone(),
        }
    }

    /// Stop the attach and close the connection.
    pub fn close(self) {
        // Destructured rather than dropped whole so the ordering is
        // explicit: `stop` marks the attach finished and aborts the driver
        // *before* `close` drains and tears down the connection, which is
        // the same order the drop glue produces.
        let Self { stop, conn, .. } = self;
        drop(stop);
        conn.close();
    }
}

/// The input side of a live attach: cloneable, `Send`, and usable from any
/// thread — session input, window-size changes, and a detach that leaves
/// the session running. See [`SessionAttachStream::handle`].
#[derive(Clone)]
pub struct AttachHandle {
    commands: tokio::sync::mpsc::Sender<AttachCommand>,
    link: RecoveryLink,
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// Held for as long as a detach is flushing, so the thread that owns
    /// the stream cannot tear the driver down mid-flush. See
    /// [`AttachStop::drop`].
    detaching: Arc<std::sync::Mutex<()>>,
}

impl std::fmt::Debug for AttachHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachHandle").finish_non_exhaustive()
    }
}

impl AttachHandle {
    /// Queue session input; the driver writes it in order. Blocks only
    /// while the driver's bounded queue is full.
    ///
    /// Call from a plain thread, never from inside an async runtime — the
    /// same rule every blocking `Ops` entry point follows.
    pub fn write(&self, data: Vec<u8>) -> Result<(), OpError> {
        self.commands
            .blocking_send(AttachCommand::Input(data))
            .map_err(|_| attach_gone())
    }

    /// Queue session input without ever blocking. `Ok(false)` means the
    /// driver's queue was full and the bytes were **not** taken — the
    /// caller has to say so rather than pretend they were sent.
    ///
    /// For callers that must stay responsive under backpressure: the host
    /// parks its own input reader when its frame queue fills, so a
    /// blocking [`write`](Self::write) can park indefinitely.
    pub fn try_write(&self, data: Vec<u8>) -> Result<bool, OpError> {
        match self.commands.try_send(AttachCommand::Input(data)) {
            Ok(()) => Ok(true),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(attach_gone()),
        }
    }

    /// Queue a window-size change. Same backpressure as [`write`](Self::write).
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), OpError> {
        self.commands
            .blocking_send(AttachCommand::Resize { cols, rows })
            .map_err(|_| attach_gone())
    }

    /// Queue a window-size change without ever blocking; see
    /// [`try_write`](Self::try_write). A dropped resize is self-healing —
    /// the next `SIGWINCH` sends the current size again.
    pub fn try_resize(&self, cols: u16, rows: u16) -> Result<bool, OpError> {
        match self.commands.try_send(AttachCommand::Resize { cols, rows }) {
            Ok(()) => Ok(true),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(attach_gone()),
        }
    }

    /// Detach: end this client's attach **without touching the session**
    /// (`docs/CLI.md` §7 — a session outlives its client by design).
    ///
    /// Closing the QUIC connection is what makes a detach prompt and
    /// complete: the host purges the connection, releases the writer lease
    /// it held and keeps the session running, and the
    /// [`next_event`](SessionAttachStream::next_event) blocking the owning
    /// thread returns. Idempotent, and callable from any thread — closing
    /// a connection needs no runtime.
    ///
    /// The answer says whether the input typed ahead of the detach is known
    /// to have reached the child; a caller that gets
    /// [`DetachFlush::Unconfirmed`] owes the user a word about it.
    pub fn detach(&self) -> DetachFlush {
        // Held across the whole detach: the thread that owns the stream is
        // free to tear the attach down the moment it notices, and the
        // teardown aborts the very driver this flush is waiting on.
        let _flushing = lock(&self.detaching);
        // Marked deliberate *first*: closing the connection is
        // indistinguishable, from the driver's side, from the path dying,
        // and a detach that raced the flag would be answered with a
        // re-dial and a resume of the session the user just left.
        self.finished
            .store(true, std::sync::atomic::Ordering::Release);
        // Ordering next: hand the driver a detach marker down the same
        // queue as the input, so everything already typed is written — and
        // acknowledged by the host — before the connection goes away. A
        // QUIC close discards unsent stream data, and a host that has not
        // read a frame yet loses it with the stream, so only the host's own
        // `InputAck` can say the bytes made it (protocol.md §10-5).
        //
        // Bounded on both sides. A full queue (the host stopped reading)
        // means the bytes were never going to land anyway, and a driver
        // parked on flow control never answers; neither may keep the user
        // attached, so the close happens regardless — and says so.
        let (ack, flushed) = std::sync::mpsc::sync_channel(1);
        let outcome = if self.commands.try_send(AttachCommand::Detach(ack)).is_ok() {
            flushed
                .recv_timeout(DETACH_FLUSH_GRACE)
                .unwrap_or(DetachFlush::Unconfirmed)
        } else {
            DetachFlush::Unconfirmed
        };
        // Forward: closing the connection is what makes `next_event`
        // return and the host release the writer lease (this doc's own
        // opening paragraph). Reverse: there is no connection this attach
        // owns alone to close (`RecoveryLink`'s own doc) — the hard-stop
        // is this attach's own `LOCAL_STREAM` conduit going away locally,
        // which needs no cooperation from the daemon or the peer either.
        match &self.link {
            RecoveryLink::Forward(link) => link.connection().close(0, b"detach"),
            RecoveryLink::Reverse(kill) => kill.kill(),
        }
        outcome
    }

    /// Whether a detach is flushing **right now** — the state the
    /// teardown gate in [`SessionAttachStream::close`] waits out.
    ///
    /// A snapshot, with one asymmetry that makes it useful: `false` can be
    /// stale the instant it returns (a detach may begin right after), but
    /// `true` means the detach currently holding the gate keeps it until
    /// that detach completes — so a teardown started while this reports
    /// `true` is guaranteed to wait the flush out. An owner that knows a
    /// detach was *requested* on another thread cannot get the same
    /// guarantee from the request alone: thread start order says nothing
    /// about who reaches the gate first.
    pub fn is_detaching(&self) -> bool {
        match self.detaching.try_lock() {
            Ok(_guard) => false,
            Err(std::sync::TryLockError::WouldBlock) => true,
            // Poisoned: the flushing thread panicked, so whatever detach
            // held the gate is over — nothing left to wait out.
            Err(std::sync::TryLockError::Poisoned(_)) => false,
        }
    }
}

fn attach_gone() -> OpError {
    OpError::new(ErrorCode::ConnectionFailed, "the attach stream has ended")
}
