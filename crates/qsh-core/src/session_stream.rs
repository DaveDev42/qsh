//! Host side of the `SESSION_DATA` stream — one bidirectional QUIC stream
//! per attach (`docs/design/protocol.md` §7 "Session data" row, §9
//! `SessionFrame`, §12).
//!
//! The stream is opened by the attaching peer, identified by its
//! `StreamHeader{SESSION_DATA, ticket}`, and admitted by the dispatch edge
//! only after the ticket issued by an authorized `session.open` /
//! `session.attach` was redeemed — nothing here re-decides policy.
//!
//! Three concurrent parts, so neither direction can stall the other:
//!
//! - the **output pump**: a cursor pull loop on the broker's replay ring —
//!   the same [`SessionBackend::pull`] primitive `session read --wait` and
//!   `--follow` use — turning [`ReplayEvent`]s into `Output`/`Gap`/`Exit`
//!   frames. The ring is the decoupler (protocol.md §12): a slow consumer
//!   only falls behind its own cursor and is resynchronised with a `Gap`;
//!   it can never block the session's source reader.
//! - the **input loop**: `Input`/`Resize` frames from the peer. `Input`
//!   carries the cumulative input offset *after* its chunk, so the host
//!   discards (or trims) whatever it already applied and answers
//!   `InputAck{acked_input_seq}` — lossless and duplicate-free
//!   (protocol.md §10-5). Losing the writer lease demotes this attach to
//!   read-only rather than ending it: input is dropped on the floor while
//!   another peer drives, still acked so the peer's stream stays
//!   contiguous, and writing resumes by itself on a steal-back.
//! - the **frame writer**: sole owner of the send half, fed by both of the
//!   above through a bounded queue.
//!
//! **Screen sync** (ADR-0052, `docs/design/protocol.md` §18). When the ticket
//! says the attach runs screen sync, the output pump is replaced by the
//! `screen_pump`: it never sends `Output`, it sends `ScreenUpdate` parts
//! built from the session's host emulator. The ring is still pulled, but only
//! as the wake-up and for the control entries (`Exit`, `Closed`, ...), which
//! stay in order behind the last screen. The stream carrier's base is the
//! last state *sent* (ordered, reliable stream), new updates wait while more
//! than `SEND_DEPTH_CAP_BYTES` of screen data sit unwritten, and then one
//! update to the newest state replaces everything skipped meanwhile. The
//! input pump learns the client's `ScreenAck`s: state 0 is a request for the
//! full screen.
//!
//! Everything is torn down when the QUIC connection dies, so a wedged child
//! (a session write parked on a full PTY input buffer) can never keep the
//! stream — or its [`AttachToken`], which suspends the session's resume TTL
//! — alive past the connection.
//!
//! This module lives outside `broker/` on purpose: it is the only part of
//! the session path that names `qsh-transport` types, and `xtask arch`
//! bans those under `crates/qsh-core/src/broker/`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use prost::Message as _;
use qsh_proto::datagram::{ChannelId, DatagramFrame, DatagramKind};
use qsh_proto::screen::MAX_DATAGRAM_PARTS;
use qsh_proto::wire::{
    self, ControlMessage, ScreenEcho, SessionFrame, TtyEcho, control_message, session_frame,
};
use qsh_transport::{Connection, FramedRecv, FramedSend, FramedStream, StreamError};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, mpsc};

use crate::adapt::{Carrier, CarrierRunner, FIXED_FRAME_INTERVAL, KeepAliveMemory, User};
use crate::datagram::{DatagramHub, DatagramRx, SendFailure, part_budget};
use crate::input_times::InputTimes;

use crate::broker::{
    AttachToken, BrokerError, ConnectionId, ControlEvent, Cursor, InputStreamId, ReplayEvent,
    SessionBackend, SessionId,
};
use crate::tunnel::splice::SEND_DEPTH_CAP_BYTES;

/// Payload budget of one output pull: four wire chunks. Enough to keep the
/// stream busy without building a reply the writer cannot drain.
pub const SESSION_STREAM_PULL_BYTES: usize = 4 * wire::SESSION_CHUNK_MAX;

/// How long one output pull parks waiting for new bytes before looping.
/// Only sets how often the pump re-enters the ring — the pull wakes
/// immediately on an append.
pub const SESSION_STREAM_PULL_WAIT: Duration = Duration::from_secs(30);

/// How long [`output_pump`] waits for `Closed` after `Exit`, once, before
/// giving up. An explicit `session.close`/SIGTERM drain on a still-running
/// session appends both as one actor operation (`begin_close`/
/// `mark_closed`) and they almost always land in the very next `pull()`
/// batch together — this covers the rare case they do not. A **child that
/// exits on its own** is different: no caller closed it, so `Closed` only
/// ever comes from the TTL reaper, which will not run at all while this
/// pump's attach token is held (`Broker::ttl_reap_reason`) — waiting
/// indefinitely there would hold the token, and the reaper, hostage
/// forever. `docs/CLI.md` §6.4 agrees for the sibling `--follow` consumer
/// of the same ring: it ends the moment it sees `session.exit` and does not
/// wait for the reaper's later `session.closed{reason:"exit"}` either.
const EXIT_CLOSED_GRACE: Duration = Duration::from_secs(2);

/// Depth of the queue between the two pumps and the single frame writer.
pub const SESSION_STREAM_QUEUE: usize = 64;

/// Why a `SESSION_DATA` stream ended.
#[derive(Debug, Error)]
pub enum SessionStreamError {
    /// Stream I/O failed (peer reset, connection lost, oversize frame).
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// The peer sent a frame that violates the session-data grammar.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The broker refused an operation the stream depends on.
    #[error(transparent)]
    Backend(#[from] BrokerError),
    /// The connection went away while the stream was running.
    #[error("connection closed")]
    PeerGone,
}

impl SessionStreamError {
    /// Whether this is just the peer going away rather than a host fault —
    /// the dispatch edge logs those at debug, not warn.
    pub fn is_peer_gone(&self) -> bool {
        matches!(
            self,
            SessionStreamError::PeerGone
                | SessionStreamError::Stream(StreamError::Read(_) | StreamError::Write(_))
        )
    }
}

/// Everything one `SESSION_DATA` stream needs, assembled by the dispatch
/// edge (which has already authorized it).
pub struct SessionStream {
    /// The broker seam.
    pub sessions: Arc<dyn SessionBackend>,
    /// The session this stream is attached to.
    pub session_id: SessionId,
    /// Connection identity, for the writer-lease check on inbound `Input`.
    pub conn: ConnectionId,
    /// Where output replay starts (`SessionAttach.last_output_seq`; `0` for
    /// a stream redeemed straight off `session.open`).
    pub cursor: Cursor,
    /// The logical input stream this attach continues (protocol.md §10-5).
    /// A resumed attach carries the id it left, so the session's dedup
    /// cursor still applies to it; anything else carries a fresh id.
    pub input_stream: InputStreamId,
    /// Cumulative input offset the peer was told to resume its own counter
    /// from (`SessionAttached.input_seq`) — the first ack it can expect.
    pub input_from: u64,
    /// Funnel to the connection's control-stream writer for the
    /// asynchronous `SessionEvent`s an attached peer is owed
    /// (protocol.md §9). For an *attached* peer this is the only carrier
    /// of `writer_changed`/`closed` — neither has a `SessionFrame` — so a
    /// full queue parks the pump instead of dropping the event (PRD §8:
    /// never lose silently). The queue is drained by the connection loop,
    /// which never parks on a session.
    pub events: Option<mpsc::Sender<ControlMessage>>,
    /// Run screen sync on this stream (the ticket carried a non-empty
    /// `screen_channel`, ADR-0052 decision 9): the host sends
    /// `ScreenUpdate` and no `Output`. `false` is the byte path.
    pub screen: bool,
    /// The datagram carrier for this screen-sync attach (ADR-0052 decisions
    /// 6 to 9): set when `datagram.v1` was negotiated on a forward
    /// connection. The carrier stays unused until the client has sent a
    /// datagram on the channel, which tells the host it reads them.
    pub datagram: Option<DatagramParams>,
    /// What the keep-alive policy needs from the host (ADR-0052 decision
    /// 13).
    pub keep_alive: KeepAliveParams,
    /// Send `ScreenEcho` on this screen-sync attach: both sides advertised
    /// `screen-echo.v1` (ADR-0053 decision 3).
    pub screen_echo: bool,
}

/// What the dispatch edge hands a screen-sync attach for knob (e), the
/// keep-alive interval (ADR-0052 decisions 12 (e) and 13).
#[derive(Clone, Default)]
pub struct KeepAliveParams {
    /// `[transport].keep_alive_ms` when the operator wrote the key: the
    /// interval is pinned and the policy sends no `Ping`.
    pub pinned: Option<Duration>,
    /// Test hook ([`crate::server::Server::inject_nat_rebind`]): idle
    /// milliseconds of a NAT rebind to report once, `0` for none.
    pub rebind_hook: Arc<AtomicU64>,
    /// Policy `Ping`s written, for tests and `qsh::adapt` debugging
    /// ([`crate::server::Server::keep_alive_pings`]).
    pub pings: Arc<AtomicU64>,
    /// Shortened intervals this process remembers per peer, and the key of
    /// this attach's peer (decision 12 (e)).
    pub memory: Arc<KeepAliveMemory>,
    pub peer: String,
}

/// What the dispatch edge hands a screen-sync attach for its datagram
/// carrier.
#[derive(Clone)]
pub struct DatagramParams {
    /// The channel id issued as `screen_channel` for this attach.
    pub channel: ChannelId,
    /// Test hook ([`crate::server::Server::blackhole_datagrams`]): datagram
    /// sends are accepted and silently dropped, as a path that eats
    /// datagrams would.
    pub blackhole: Arc<AtomicBool>,
}

/// What the input side of a screen-sync stream tells the screen pump.
struct ScreenSync {
    /// The client asked for the full screen (`ScreenAck{0}`).
    resync: AtomicBool,
    /// Newest state number the client acked, on either carrier. A request
    /// for the full screen resets it to 0.
    acked: AtomicU64,
    /// The client has sent a datagram on this attach's channel: it reads
    /// them, and the path carries them at least towards the host.
    datagram_seen: AtomicBool,
    /// When the host wrote the input of this attach (ADR-0053 decision 3).
    times: std::sync::Mutex<InputTimes>,
    /// Wakes the pump for a new input write: the `ScreenEcho` timer moved.
    input_poke: Notify,
    /// Wakes the pump for a resync request or a window-size change, neither
    /// of which moves the ring.
    poke: Notify,
}

impl ScreenSync {
    fn new(input_from: u64) -> Self {
        Self {
            resync: AtomicBool::new(false),
            acked: AtomicU64::new(0),
            datagram_seen: AtomicBool::new(false),
            times: std::sync::Mutex::new(InputTimes::new(input_from)),
            input_poke: Notify::new(),
            poke: Notify::new(),
        }
    }

    /// The session accepted input up to cumulative offset `end`.
    fn note_input(&self, end: u64, now: Instant) {
        self.times
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(end, now);
        self.input_poke.notify_one();
    }

    /// A `ScreenAck` from either carrier.
    fn on_ack(&self, state_num: u64) {
        if state_num == 0 {
            self.acked.store(0, Ordering::Release);
            self.resync.store(true, Ordering::Release);
            self.poke.notify_one();
        } else {
            self.acked.fetch_max(state_num, Ordering::AcqRel);
        }
    }
}

/// Input offset the host has applied on one attach's axis, shared by the
/// stream loop and the datagram copy path. The lock is held across the
/// session write so a copy and its stream twin never interleave.
type InputAxis = Arc<Mutex<u64>>;

/// Screen bytes queued for the writer and not written yet: the stream
/// carrier's "send queue" (ADR-0052 decision 6).
#[derive(Default)]
struct SendDepth {
    bytes: AtomicUsize,
    drained: Notify,
}

impl SendDepth {
    fn has_room(&self) -> bool {
        (self.bytes.load(Ordering::Acquire) as u64) <= SEND_DEPTH_CAP_BYTES
    }

    fn add(&self, n: usize) {
        self.bytes.fetch_add(n, Ordering::AcqRel);
    }

    fn sub(&self, n: usize) {
        self.bytes.fetch_sub(n, Ordering::AcqRel);
        self.drained.notify_one();
    }
}

impl SessionStream {
    /// Drive the stream to completion. On return the send half has been
    /// finished (or dropped, on error).
    pub async fn run(
        self,
        stream: FramedStream,
        connection: &Connection,
    ) -> Result<(), SessionStreamError> {
        tokio::select! {
            result = self.run_inner(stream, connection.clone()) => result,
            // A parked `sessions.write` (child not draining its PTY input)
            // must never outlive the connection: the attach token below
            // suspends the session's resume TTL, so a stuck pump would keep
            // an orphaned session alive for ever.
            _ = connection.closed() => Err(SessionStreamError::PeerGone),
        }
    }

    async fn run_inner(
        self,
        stream: FramedStream,
        connection: Connection,
    ) -> Result<(), SessionStreamError> {
        let SessionStream {
            sessions,
            session_id,
            conn,
            cursor,
            input_stream,
            input_from,
            events,
            screen,
            datagram,
            keep_alive,
            screen_echo,
        } = self;

        // While this token lives the session counts as attached and its
        // resume TTL is suspended (architecture.md §3). Taken only after
        // the ticket was redeemed, i.e. after authorization.
        let attached: Box<dyn AttachToken> = sessions.attach(&session_id)?;

        let (mut send, recv) = stream.split();
        // protocol.md §12 band: below the control stream (200), above bulk.
        send.set_priority(wire::PRIORITY_SESSION_DATA);

        let (frames_tx, frames_rx) = mpsc::channel::<SessionFrame>(SESSION_STREAM_QUEUE);
        let depth = Arc::new(SendDepth::default());
        let sync = screen.then(|| Arc::new(ScreenSync::new(input_from)));
        let mut writer = AbortOnDrop(tokio::spawn({
            let depth = Arc::clone(&depth);
            async move {
                let result = write_frames(&mut send, frames_rx, &depth).await;
                let _ = send.finish();
                result
            }
        }));

        let axis: InputAxis = Arc::new(Mutex::new(input_from));
        // The datagram channel is registered before the pumps start, so a
        // datagram that races the stream open is not counted as unknown.
        let carrier = match (&sync, datagram) {
            (Some(_), Some(params)) => {
                let hub = DatagramHub::of(&connection);
                let rx = hub.register(params.channel);
                Some((hub, rx, params))
            }
            _ => None,
        };
        let (dg_tx, dg_task) = match carrier {
            Some((hub, rx, params)) => {
                let sync = sync.clone().expect("carrier implies screen sync");
                let task = AbortOnDrop(tokio::spawn(datagram_pump(
                    rx,
                    Arc::clone(&sync),
                    Arc::clone(&sessions),
                    session_id.clone(),
                    conn,
                    input_stream,
                    Arc::clone(&axis),
                    frames_tx.clone(),
                )));
                (
                    Some(DatagramTx {
                        hub,
                        channel: params.channel,
                        blackhole: params.blackhole,
                    }),
                    Some(task),
                )
            }
            None => (None, None),
        };

        let mut output = AbortOnDrop(match &sync {
            Some(sync) => tokio::spawn(screen_pump(
                Arc::clone(&sessions),
                session_id.clone(),
                cursor,
                frames_tx.clone(),
                events,
                Arc::clone(sync),
                depth,
                connection.clone(),
                dg_tx,
                keep_alive,
                screen_echo,
            )),
            None => tokio::spawn(output_pump(
                Arc::clone(&sessions),
                session_id.clone(),
                cursor,
                frames_tx.clone(),
                events,
            )),
        });

        // Set once `writer` ends on its own — the peer sent `STOP_SENDING`
        // (`write_frames`'s own `send.stopped()` race) or a write failed —
        // so the trailing cleanup below knows not to poll that already-
        // completed `JoinHandle` a second time (`AbortOnDrop`'s `.0` is a
        // plain `tokio::task::JoinHandle`, and polling one again past
        // completion is not something this code relies on being safe).
        let mut writer_done = false;
        let result = {
            let input = input_pump(
                sessions,
                session_id,
                conn,
                input_stream,
                Arc::clone(&axis),
                recv,
                frames_tx,
                sync.clone(),
                // Keys are the interactive traffic bulk yields to
                // (ADR-0052 decision 12 (a)); the governor lives as long as
                // this attach does.
                crate::adapt::BulkGovernor::for_connection(&connection),
            );
            tokio::pin!(input);
            tokio::select! {
                r = &mut input => match r {
                    // The peer finished its send half — but it is still
                    // owed its output, so the stream lives until the
                    // output pump is done. (Losing the writer lease does
                    // *not* land here: that only demotes the attach to
                    // read-only, it keeps reading input.) *Or* until the
                    // write side notices nobody is listening any more —
                    // see the `writer` arm below, which is exactly as
                    // valid a reason to stop here as `output` finishing:
                    // an idle session's `output_pump` can sit forever with
                    // nothing new to pull, and would otherwise never learn
                    // that the peer detached with no more output ever
                    // coming (the localctl `LOCAL_STREAM` splice's own
                    // cross-leg cancellation is exactly what triggers
                    // this on the reverse route).
                    Ok(()) => tokio::select! {
                        r = &mut output.0 => r.unwrap_or(Ok(())),
                        r = &mut writer.0 => {
                            writer_done = true;
                            r.unwrap_or(Ok(())).map_err(SessionStreamError::from)
                        }
                    },
                    Err(err) => Err(err),
                },
                // `Exit`/`Closed`: the last frame has been queued.
                r = &mut output.0 => r.unwrap_or(Ok(())),
                // See the comment on the nested arm above — the write
                // side can end first too, most commonly on the reverse
                // route where a detached peer's data conduit is gone
                // long before `input`/`output` would otherwise notice.
                r = &mut writer.0 => {
                    writer_done = true;
                    r.unwrap_or(Ok(())).map_err(SessionStreamError::from)
                }
            }
        };
        // Every sender is dropped by now, so the writer drains the queue,
        // FINs the stream and returns — unless it already ended on its
        // own above, in which case awaiting it again would poll an
        // already-completed `JoinHandle`.
        drop(output);
        drop(dg_task);
        if !writer_done {
            let _ = (&mut writer.0).await;
        }
        drop(attached);
        if let Some(sync) = &sync {
            tracing::debug!(
                acked = sync.acked.load(Ordering::Acquire),
                "screen-sync data stream ended"
            );
        }
        result
    }
}

/// A spawned task that is aborted if its owner is dropped — so the whole
/// stream disappears when [`SessionStream::run`] loses the race against
/// `Connection::closed()`.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The single owner of the send half.
///
/// Races draining `frames` against [`FramedSend::stopped`] — which
/// resolves only when the peer sends `STOP_SENDING` (or the stream/
/// connection is already gone), never merely on an ordinary ack of bytes
/// already written (`quinn`'s own `send_stream_stopped`: `Ok(None)` for an
/// already-closed stream, `Ok(Some(code))` for a real `STOP_SENDING`,
/// otherwise it keeps waiting). A peer that will never read another byte
/// here — most commonly a reverse-route localctl `LOCAL_STREAM` conduit
/// whose CLI end already detached (`localctl::daemon`'s cross-leg
/// cancellation resets the corresponding `RecvStream`, which the QUIC
/// layer turns into `STOP_SENDING` on this end) — is exactly as good a
/// reason to stop as the queue itself ending, and unlike a *forward*
/// attach's own connection loss, nothing else here would ever notice on
/// an idle session otherwise: `output_pump` can sit forever finding no
/// new bytes to pull, and would hold this stream's `AttachToken` (and the
/// TTL suspension it implies) open indefinitely on the peer's behalf.
async fn write_frames(
    send: &mut FramedSend,
    mut frames: mpsc::Receiver<SessionFrame>,
    depth: &SendDepth,
) -> Result<(), StreamError> {
    loop {
        tokio::select! {
            frame = frames.recv() => {
                match frame {
                    Some(frame) => {
                        // Screen parts count toward the stream carrier's
                        // depth from the moment they are queued until the
                        // transport has taken them.
                        let screen_len = match &frame.body {
                            Some(session_frame::Body::ScreenUpdate(u)) => Some(u.data.len()),
                            _ => None,
                        };
                        let result = send.send(&frame).await;
                        if let Some(n) = screen_len {
                            depth.sub(n);
                        }
                        result?;
                    }
                    None => return Ok(()),
                }
            }
            () = send.stopped() => return Ok(()),
        }
    }
}

/// Cursor pull loop: replay ring → `Output`/`Gap`/`Exit` frames.
async fn output_pump(
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    mut cursor: Cursor,
    frames: mpsc::Sender<SessionFrame>,
    events: Option<mpsc::Sender<ControlMessage>>,
) -> Result<(), SessionStreamError> {
    // Set once `Exit` has been seen with no `Closed` in the same batch —
    // gives exactly one more, short-waited pull a chance to catch a
    // `Closed` that landed a moment later, then gives up regardless
    // ([`EXIT_CLOSED_GRACE`]'s docs: the ordinary self-exit case has no
    // `Closed` coming at all while this pump holds the attach token).
    let mut exit_grace_used = false;
    loop {
        let wait = if exit_grace_used {
            EXIT_CLOSED_GRACE
        } else {
            SESSION_STREAM_PULL_WAIT
        };
        let out = match sessions
            .pull(&id, cursor, SESSION_STREAM_PULL_BYTES, wait)
            .await
        {
            Ok(out) => out,
            // The session left the registry (past `CLOSED_RETENTION`):
            // nothing more to stream.
            Err(BrokerError::NotFound) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        cursor = out.next;
        let mut exited_this_batch = false;
        for event in out.events {
            match event {
                ReplayEvent::Output { sequence, data } => {
                    // The ring's chunks are already ≤ SESSION_CHUNK_MAX;
                    // re-splitting is defensive, never lossy, and keeps
                    // every `sequence` the exact cumulative end offset.
                    let mut offset = sequence - data.len() as u64;
                    for chunk in data.chunks(wire::SESSION_CHUNK_MAX) {
                        offset += chunk.len() as u64;
                        send_frame(&frames, SessionFrame::output(offset, chunk.to_vec())).await?;
                    }
                }
                ReplayEvent::Gap {
                    requested_after,
                    available_from,
                } => {
                    send_frame(&frames, SessionFrame::gap(requested_after, available_from)).await?;
                }
                ReplayEvent::Control {
                    sequence, event, ..
                } => {
                    notify(&events, &id, sequence, &event).await?;
                    match event {
                        ControlEvent::Exit { exit_code, signal } => {
                            // The wire `exit_code` is not optional: a
                            // signal-terminated child reports -1 plus its
                            // signal name (CLI.md §6.4).
                            send_frame(
                                &frames,
                                SessionFrame::exit(sequence, exit_code.unwrap_or(-1), signal),
                            )
                            .await?;
                            // Not terminal on its own: an explicit
                            // `session.close` (or the SIGTERM drain) on a
                            // still-*running* session appends `Exit` then
                            // `Closed` as one actor operation
                            // (`broker::session`'s `begin_close`/
                            // `mark_closed`) — almost always landing in this
                            // very `pull()` batch together. Returning here
                            // would silently drop the `Closed` `notify` a
                            // couple of loop iterations away, leaving an
                            // attached consumer never told the session is
                            // gone (an L5 real-process test, not this
                            // module's own unit tests, is what caught it —
                            // see `serve_sigterm_drain.rs`). `EXIT_CLOSED_GRACE`
                            // below covers that, bounded — a child that
                            // exited on its own with nobody having called
                            // `session.close` has no `Closed` coming while
                            // this pump holds the attach token, so waiting
                            // past the grace is a self-deadlock, not a fix.
                            exited_this_batch = true;
                        }
                        // Always the last ring entry; nothing follows it.
                        ControlEvent::Closed { .. } => return Ok(()),
                        // Not representable as a `SessionFrame`; it went out
                        // on the control stream in `notify` above.
                        ControlEvent::WriterChanged { .. } => {}
                    }
                }
            }
        }
        if exited_this_batch {
            exit_grace_used = true;
        } else if exit_grace_used {
            // The grace pull came back with no `Closed` (and no fresh
            // `Exit`, which cannot recur): nobody is going to close this
            // session while we keep waiting. Give up rather than hold the
            // attach token — and the TTL reaper it blocks — forever.
            return Ok(());
        }
    }
}

/// How long after a datagram update goes out, unacked, the pump sends the
/// newest state again: a lost datagram is never retransmitted, but the
/// client must still converge when output stops.
const DATAGRAM_RESEND_RTTS: u32 = 2;

/// The send half of the datagram carrier on the host.
struct DatagramTx {
    hub: Arc<DatagramHub>,
    channel: ChannelId,
    blackhole: Arc<AtomicBool>,
}

/// Where a `try_send` left things.
enum Sent {
    /// Nothing more to send now.
    Done,
    /// The stream's send queue is full; wait for it to drain.
    Blocked,
    /// A datagram update went out too recently; try again at this time.
    Paced(Instant),
}

/// Everything the screen pump knows about how updates reach the client
/// (ADR-0052 decision 6): which base each carrier diffs from, which datagram
/// updates are still unacked, and what `adapt` currently says.
struct ScreenSender {
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    frames: mpsc::Sender<SessionFrame>,
    depth: Arc<SendDepth>,
    sync: Arc<ScreenSync>,
    conn: Connection,
    dg: Option<DatagramTx>,
    runner: CarrierRunner,
    /// Newest state sent on the stream. The stream is ordered and reliable,
    /// so the next stream update diffs from it.
    last_sent_stream: u64,
    /// The client asked for the full screen and has not got one yet.
    force_full: bool,
    /// Datagram updates not yet covered by an ack: state number and send time.
    inflight: VecDeque<(u64, Instant)>,
    last_dg_at: Option<Instant>,
    /// Send `ScreenEcho` (both sides advertised `screen-echo.v1`).
    echo_on: bool,
    /// The last `ScreenEcho` sent, to skip repeats.
    last_echo: Option<(u64, u64, TtyEcho)>,
    /// State number of the update `try_send` just put on a carrier.
    just_sent: Option<u64>,
}

impl ScreenSender {
    fn datagram_usable(&self) -> bool {
        self.dg.is_some()
            && self.sync.datagram_seen.load(Ordering::Acquire)
            && self.conn.max_datagram_size().is_some()
    }

    /// Drop what the client has acknowledged and run the policy.
    fn tick(&mut self, now: Instant) {
        let acked = self.sync.acked.load(Ordering::Acquire);
        if acked == 0 {
            self.inflight.clear();
        }
        while self.inflight.front().is_some_and(|(n, _)| *n <= acked) {
            self.inflight.pop_front();
        }
        let usable = self.datagram_usable();
        let unacked = self.inflight.front().map(|(_, t)| now.duration_since(*t));
        let tick = self.runner.tick(now, self.conn.stats(), usable, unacked);
        if tick.retest_started {
            // The re-test starts a fresh unacked clock.
            self.inflight.clear();
        }
        if tick.carrier_changed {
            tracing::debug!(
                target: "qsh::adapt",
                carrier = ?self.runner.knobs().carrier,
                "screen carrier changed"
            );
        }
    }

    /// Feed the policy what knob (e) reads: where the peer's packets come
    /// from (a change after an idle spell is a NAT rebind).
    fn observe_path(&mut self, params: &KeepAliveParams) {
        self.runner.observe_peer(self.conn.remote_address());
        let injected = params.rebind_hook.swap(0, Ordering::AcqRel);
        if injected != 0 {
            self.runner
                .inject_nat_rebind(Duration::from_millis(injected));
        }
    }

    /// Apply knob (e), the keep-alive interval (ADR-0052 decision 13): when
    /// the policy has shortened the interval below quinn's own 15 s and the
    /// user left the key unset, write a control-stream `Ping` whenever one
    /// is due. The write never waits: a full control queue skips the ping,
    /// and the next wake-up tries again.
    fn send_keep_alive(
        &mut self,
        now: Instant,
        events: &Option<mpsc::Sender<ControlMessage>>,
        params: &KeepAliveParams,
    ) {
        let Some(tx) = events else { return };
        if !self.runner.ping_due(now) {
            return;
        }
        let ping = ControlMessage::new(0, control_message::Body::Ping(wire::Ping {}));
        if tx.try_send(ping).is_ok() {
            self.runner.ping_sent(now);
            params.pings.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                target: "qsh::adapt",
                interval_ms = self.runner.knobs().keep_alive.as_millis() as u64,
                "keep-alive ping"
            );
        }
    }

    /// When the pump must look again even if nothing arrives: the resend of
    /// a datagram update that is still unacked.
    fn resend_deadline(&self) -> Option<Instant> {
        let (_, sent) = self.inflight.back()?;
        let rtt = self.conn.stats().rtt.max(crate::adapt::RTT_FLOOR);
        Some(*sent + rtt * DATAGRAM_RESEND_RTTS + FIXED_FRAME_INTERVAL)
    }

    /// Send the update that takes the client to the newest state, on the
    /// carrier the policy picks. `force_stream` is for the final screen
    /// before `Exit`: it must be on the ordered stream, ahead of the event,
    /// whatever the queue holds.
    async fn try_send(
        &mut self,
        now: Instant,
        force_stream: bool,
    ) -> Result<Sent, SessionStreamError> {
        let acked = self.sync.acked.load(Ordering::Acquire);
        if !force_stream
            && self.datagram_usable()
            && self.runner.knobs().carrier == Carrier::Datagram
        {
            if let Some(at) = self.last_dg_at {
                let next = at + FIXED_FRAME_INTERVAL;
                if now < next {
                    return Ok(Sent::Paced(next));
                }
            }
            let base = if self.force_full { 0 } else { acked };
            let Some(update) = self.sessions.screen_update_since(&self.id, base) else {
                return Ok(Sent::Done);
            };
            let encoded = update.encode();
            if encoded.len() > qsh_proto::screen::MAX_UPDATE_BYTES {
                return Err(SessionStreamError::Protocol(
                    "screen update is larger than the update cap".into(),
                ));
            }
            let budget = self.conn.max_datagram_size().and_then(part_budget);
            if let Some(budget) = budget {
                let parts = wire::ScreenUpdate::parts_sized(update.new_num, &encoded, budget);
                let count = parts.len() as u32;
                if count <= MAX_DATAGRAM_PARTS
                    && self.runner.carrier_for_update(count) == Carrier::Datagram
                    && self.send_datagram_parts(&parts)?
                {
                    self.inflight.push_back((update.new_num, now));
                    self.last_dg_at = Some(now);
                    self.just_sent = Some(update.new_num);
                    if update.base_num == 0 {
                        self.force_full = false;
                    }
                    return Ok(Sent::Done);
                }
            }
            // Too big for datagrams, or the transport refused: the stream
            // twin carries this update.
        }
        if !force_stream && !self.depth.has_room() {
            return Ok(Sent::Blocked);
        }
        let base = if self.force_full {
            0
        } else {
            acked.max(self.last_sent_stream)
        };
        let Some(update) = self.sessions.screen_update_since(&self.id, base) else {
            return Ok(Sent::Done);
        };
        let encoded = update.encode();
        if encoded.len() > qsh_proto::screen::MAX_UPDATE_BYTES {
            return Err(SessionStreamError::Protocol(
                "screen update is larger than the update cap".into(),
            ));
        }
        for part in wire::ScreenUpdate::parts_of(update.new_num, &encoded) {
            self.depth.add(part.data.len());
            send_frame(&self.frames, SessionFrame::screen_update(part)).await?;
        }
        self.last_sent_stream = update.new_num;
        self.just_sent = Some(update.new_num);
        if update.base_num == 0 {
            self.force_full = false;
        }
        Ok(Sent::Done)
    }

    /// Send a `ScreenEcho` (ADR-0053 decision 3) when it says something new.
    /// `after_update` is the state number of the update just sent (case a);
    /// `None` is the timer case (b), which reads the current state and sends
    /// only if the input offset or the tty state moved. The stream always
    /// carries it; a live datagram carrier gets it first. Values equal to the
    /// last one sent are skipped. The frame holds offsets and a tty flag
    /// only, never PTY content.
    async fn send_echo(
        &mut self,
        now: Instant,
        after_update: Option<u64>,
    ) -> Result<(), SessionStreamError> {
        if !self.echo_on {
            return Ok(());
        }
        let input_seq = self
            .sync
            .times
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .settle(now);
        let tty = self.sessions.tty_echo(&self.id);
        let state_num = match after_update {
            Some(n) => n,
            None => {
                let unchanged = match self.last_echo {
                    Some((_, seq, t)) => seq == input_seq && t == tty,
                    None => input_seq == 0 && tty == TtyEcho::Unknown,
                };
                if unchanged {
                    return Ok(());
                }
                match self.sessions.screen_state_num(&self.id) {
                    Some(n) => n,
                    None => return Ok(()),
                }
            }
        };
        let value = (state_num, input_seq, tty);
        if self.last_echo == Some(value) {
            return Ok(());
        }
        self.last_echo = Some(value);
        let echo = ScreenEcho {
            state_num,
            input_seq,
            tty: tty as i32,
        };
        if self.datagram_usable()
            && let Some(dg) = &self.dg
            && !dg.blackhole.load(Ordering::Relaxed)
        {
            // Best effort: the stream copy below is the certain one.
            let _ = dg.hub.send(&DatagramFrame {
                channel: dg.channel,
                kind: DatagramKind::ScreenEcho,
                payload: echo.encode_to_vec(),
            });
        }
        send_frame(&self.frames, SessionFrame::screen_echo(echo)).await
    }

    /// Send the lines that scrolled off since the last call (ADR-0052
    /// decision 10) as `ScreenHistory` frames on the stream, oldest first,
    /// the `skipped` count last. History only goes out when the update queue
    /// has room (`force` is for the flush before `Exit`); when the sender is
    /// behind, the host emulator keeps collecting up to its row and byte cap
    /// and counts the rest, so the client gets one `skipped` line instead of
    /// a late flood. Never on a datagram, never logged: the lines are PTY
    /// content.
    async fn send_history(&mut self, force: bool) -> Result<(), SessionStreamError> {
        if !force && !self.depth.has_room() {
            return Ok(());
        }
        let Some(batch) = self.sessions.screen_take_history(&self.id) else {
            return Ok(());
        };
        let (frames, _) = wire::ScreenHistory::batches(&batch.lines, batch.skipped);
        for h in frames {
            send_frame(&self.frames, SessionFrame::screen_history(h)).await?;
        }
        Ok(())
    }

    /// Send every part as a datagram. `Ok(false)` means the transport
    /// cannot carry it and the caller uses the stream.
    fn send_datagram_parts(
        &self,
        parts: &[wire::ScreenUpdate],
    ) -> Result<bool, SessionStreamError> {
        let Some(dg) = &self.dg else {
            return Ok(false);
        };
        for part in parts {
            let frame = DatagramFrame {
                channel: dg.channel,
                kind: DatagramKind::ScreenUpdate,
                payload: part.encode_to_vec(),
            };
            if dg.blackhole.load(Ordering::Relaxed) {
                continue;
            }
            match dg.hub.send(&frame) {
                Ok(()) => {}
                Err(SendFailure::Unavailable) => return Ok(false),
                Err(SendFailure::Closed) => return Err(SessionStreamError::PeerGone),
            }
        }
        Ok(true)
    }
}

/// Screen-sync counterpart of [`output_pump`] (ADR-0052 decisions 6 and 11).
///
/// The first thing sent is the full screen (`base_num` 0) on the stream.
/// After that an update is built whenever the ring moved. On the stream it
/// is the difference from the last state sent, held back while the send
/// queue is deep; on the datagram carrier, once the client has shown it
/// reads datagrams and `adapt` allows it, it is the difference from the last
/// state the client acked, at most one per frame interval, and resent when no
/// ack comes. Either way every screen in between is skipped. Control entries
/// are forwarded as the byte path does, after a last update on the stream so
/// the client's screen is current when it sees `Exit`.
#[allow(clippy::too_many_arguments)]
async fn screen_pump(
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    mut cursor: Cursor,
    frames: mpsc::Sender<SessionFrame>,
    events: Option<mpsc::Sender<ControlMessage>>,
    sync: Arc<ScreenSync>,
    depth: Arc<SendDepth>,
    conn: Connection,
    dg: Option<DatagramTx>,
    keep_alive: KeepAliveParams,
    screen_echo: bool,
) -> Result<(), SessionStreamError> {
    let mut sender = ScreenSender {
        sessions: Arc::clone(&sessions),
        id: id.clone(),
        frames: frames.clone(),
        depth: Arc::clone(&depth),
        sync: Arc::clone(&sync),
        conn,
        dg,
        runner: CarrierRunner::new(
            Instant::now(),
            User {
                keep_alive: keep_alive.pinned,
                ..User::from_process()
            },
        ),
        last_sent_stream: 0,
        force_full: false,
        inflight: VecDeque::new(),
        last_dg_at: None,
        echo_on: screen_echo,
        last_echo: None,
        just_sent: None,
    };
    if let Some(remembered) = keep_alive.memory.get(&keep_alive.peer) {
        sender.runner.seed_keep_alive(remembered);
    }
    let mut dirty = true;
    let mut exit_grace_used = false;
    loop {
        let now = Instant::now();
        if sync.resync.swap(false, Ordering::AcqRel) {
            sender.force_full = true;
            sender.last_sent_stream = 0;
            dirty = true;
        }
        sender.observe_path(&keep_alive);
        sender.tick(now);
        if keep_alive.pinned.is_none() {
            keep_alive
                .memory
                .remember(&keep_alive.peer, sender.runner.knobs().keep_alive);
        }
        sender.send_keep_alive(now, &events, &keep_alive);
        let mut wake = sender.runner.next_ping_at().filter(|at| *at > now);
        if let Some(at) = sender.resend_deadline() {
            if at <= now {
                dirty = true;
            } else {
                wake = Some(at);
            }
        }
        if dirty {
            match sender.try_send(now, false).await? {
                Sent::Done => dirty = false,
                Sent::Blocked => {}
                Sent::Paced(at) => wake = Some(wake.map_or(at, |w| w.min(at))),
            }
        }
        if let Some(n) = sender.just_sent.take() {
            sender.send_echo(now, Some(n)).await?;
        } else if !dirty {
            sender.send_echo(now, None).await?;
        }
        if !dirty {
            sender.send_history(false).await?;
        }
        if sender.echo_on {
            let due = sync
                .times
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .next_due();
            if let Some(at) = due {
                // Already due means the next pass settles it; look again soon.
                let at = at.max(now + Duration::from_millis(1));
                wake = Some(wake.map_or(at, |w| w.min(at)));
            }
        }
        let mut wait = if exit_grace_used {
            EXIT_CLOSED_GRACE
        } else {
            // The policy looks at the connection about once a second: the
            // idle time before a NAT rebind is measured at these wake-ups.
            SESSION_STREAM_PULL_WAIT.min(crate::adapt::TICK)
        };
        if let Some(at) = wake {
            wait = wait.min(at.saturating_duration_since(Instant::now()));
        }
        let out = tokio::select! {
            r = sessions.pull(&id, cursor, SESSION_STREAM_PULL_BYTES, wait) => match r {
                Ok(out) => out,
                Err(BrokerError::NotFound) => return Ok(()),
                Err(err) => return Err(err.into()),
            },
            // A resync request or a resize: nothing new in the ring, but the
            // screen has to be looked at again.
            () = sync.poke.notified() => {
                dirty = true;
                continue;
            }
            // New input was written: the echo timer moved.
            () = sync.input_poke.notified() => continue,
            // The writer took screen data: a gated update may go now.
            () = depth.drained.notified(), if dirty => continue,
        };
        cursor = out.next;
        let mut exited_this_batch = false;
        for event in out.events {
            match event {
                // The bytes are the byte path's business; here they only
                // mean the screen may have changed.
                ReplayEvent::Output { .. } | ReplayEvent::Gap { .. } => dirty = true,
                ReplayEvent::Control {
                    sequence, event, ..
                } => {
                    // The client must see the final screen before the event
                    // that ends the session, whatever the queue holds.
                    sender.try_send(Instant::now(), true).await?;
                    if let Some(n) = sender.just_sent.take() {
                        sender.send_echo(Instant::now(), Some(n)).await?;
                    }
                    sender.send_history(true).await?;
                    dirty = false;
                    notify(&events, &id, sequence, &event).await?;
                    match event {
                        ControlEvent::Exit { exit_code, signal } => {
                            send_frame(
                                &frames,
                                SessionFrame::exit(sequence, exit_code.unwrap_or(-1), signal),
                            )
                            .await?;
                            exited_this_batch = true;
                        }
                        ControlEvent::Closed { .. } => return Ok(()),
                        ControlEvent::WriterChanged { .. } => {}
                    }
                }
            }
        }
        if exited_this_batch {
            exit_grace_used = true;
        } else if exit_grace_used {
            return Ok(());
        }
    }
}

/// What the client sends by datagram on a screen-sync attach (ADR-0052
/// decisions 6 and 8): acks of the state it holds, and a copy of each
/// `Input` chunk. The channel is created by the host and registered before
/// the stream runs, so everything arriving here belongs to this attach.
#[allow(clippy::too_many_arguments)]
async fn datagram_pump(
    mut rx: DatagramRx,
    sync: Arc<ScreenSync>,
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    conn: ConnectionId,
    stream: InputStreamId,
    axis: InputAxis,
    frames: mpsc::Sender<SessionFrame>,
) {
    while let Some(frame) = rx.recv().await {
        // The first datagram tells the pump the carrier may be used.
        if !sync.datagram_seen.swap(true, Ordering::AcqRel) {
            sync.poke.notify_one();
        }
        match frame.kind {
            DatagramKind::ScreenAck => {
                if let Ok(ack) = wire::ScreenAck::decode(frame.payload.as_slice()) {
                    sync.on_ack(ack.state_num);
                }
            }
            DatagramKind::Input => {
                let Ok(input) = wire::Input::decode(frame.payload.as_slice()) else {
                    continue;
                };
                if SessionFrame::input(input.input_seq, input.data.clone())
                    .validate()
                    .is_err()
                {
                    continue;
                }
                let applied = apply_input_copy(&sessions, &id, conn, stream, &axis, input).await;
                if let Some(now) = applied {
                    sync.note_input(now, Instant::now());
                }
                if let Some(now) = applied
                    && send_frame(&frames, SessionFrame::input_ack(now))
                        .await
                        .is_err()
                {
                    return;
                }
            }
            // The host sends updates; a client sending one is a slip.
            DatagramKind::ScreenUpdate | DatagramKind::ScreenEcho => {}
            // Kind 14 names a jump channel, which lives in the jump table and
            // never in a screen attach's channel map (ADR-0056 decision 3);
            // one arriving here is dropped like any unknown channel.
            DatagramKind::JumpPacket => {}
        }
    }
}

/// Apply a datagram copy of an `Input` chunk, and only if its first byte is
/// exactly the next one this attach's axis expects (protocol.md §10-5, §18.9).
/// A copy that starts earlier is a duplicate of bytes already applied; one
/// that starts later would skip bytes whose stream copy has not arrived. Both
/// are dropped, and the stream copy, which is authoritative, does the work
/// (and is de-duplicated by the same axis). Returns the new offset when the
/// copy was applied.
async fn apply_input_copy(
    sessions: &Arc<dyn SessionBackend>,
    id: &SessionId,
    conn: ConnectionId,
    stream: InputStreamId,
    axis: &InputAxis,
    input: wire::Input,
) -> Option<u64> {
    let start = input.input_seq.checked_sub(input.data.len() as u64)?;
    let mut applied = axis.lock().await;
    if start != *applied || input.data.is_empty() {
        return None;
    }
    match sessions
        .write_at(id, conn, stream, input.data, input.input_seq)
        .await
    {
        Ok(now) => {
            *applied = now;
            Some(now)
        }
        // Not the writer, session gone, or anything else: the stream copy
        // decides what to do about it.
        Err(_) => None,
    }
}

/// `Input`/`Resize` from the peer, with the input dedup + ack of
/// protocol.md §10-5.
#[allow(clippy::too_many_arguments)]
async fn input_pump(
    sessions: Arc<dyn SessionBackend>,
    id: SessionId,
    conn: ConnectionId,
    stream: InputStreamId,
    axis: InputAxis,
    mut recv: FramedRecv,
    frames: mpsc::Sender<SessionFrame>,
    sync: Option<Arc<ScreenSync>>,
    governor: Arc<crate::adapt::BulkGovernor>,
) -> Result<(), SessionStreamError> {
    // The dedup cursor lives in the **session** (protocol.md §10-5), not
    // here: `SessionBackend::write_at` trims whatever the child already ran
    // under the actor's own serialisation. A reattach that retransmits its
    // un-acked tail therefore cannot make the child see a byte twice, and a
    // stealing peer — told where the axis stands in
    // `SessionAttached.input_seq` — cannot have its input mistaken for a
    // replay. The shared value is only the last ack we sent; the datagram
    // copy path (`apply_input_copy`) reads and moves it under the same lock.
    loop {
        let Some(frame) = recv.recv::<SessionFrame>().await? else {
            return Ok(()); // peer finished its half cleanly
        };
        // A peer not running our encoder is bounded only by the frame cap.
        frame
            .validate()
            .map_err(|e| SessionStreamError::Protocol(e.to_string()))?;
        match frame.body {
            Some(session_frame::Body::Input(input)) => {
                // An empty `Input` is a client's heartbeat (a repeat that
                // is acknowledged again below), not a keystroke.
                if !input.data.is_empty() {
                    governor.note_interactive();
                }
                let len = input.data.len() as u64;
                let mut applied_guard = axis.lock().await;
                let mut applied = *applied_guard;
                let Some(start) = input.input_seq.checked_sub(len) else {
                    return Err(SessionStreamError::Protocol(format!(
                        "Input.input_seq {} is smaller than its own chunk",
                        input.input_seq
                    )));
                };
                if start > applied {
                    // The peer skipped input bytes we never saw. Accepting
                    // would lose them silently, which PRD §8 forbids. (The
                    // session re-checks this against its own cursor; this
                    // catches it one round trip earlier.)
                    return Err(SessionStreamError::Protocol(format!(
                        "Input starts at {start} but only {applied} bytes were applied"
                    )));
                }
                match sessions
                    .write_at(&id, conn, stream, input.data.clone(), input.input_seq)
                    .await
                {
                    Ok(now) => applied = now,
                    Err(BrokerError::InvalidArgument(why)) => {
                        return Err(SessionStreamError::Protocol(why));
                    }
                    // The lease was stolen (this attach is read-only
                    // now — protocol.md §10 "read-only로 강등된다") or
                    // the child is gone. Neither ends the attach: the
                    // peer is still owed its output and its `Exit`, and
                    // a steal-back must resume writing without a
                    // reattach. Discard the bytes but keep the offset
                    // moving, so the peer's stream stays contiguous and
                    // its ack is never left dangling, and try again on
                    // the next frame.
                    Err(
                        BrokerError::NotRunning | BrokerError::NotWriter | BrokerError::NotFound,
                    ) => applied = applied.max(input.input_seq),
                    Err(err) => return Err(err.into()),
                }
                if applied > *applied_guard
                    && let Some(sync) = &sync
                {
                    sync.note_input(applied, Instant::now());
                }
                *applied_guard = applied;
                drop(applied_guard);
                // Re-ack a duplicate too: the peer is waiting for it.
                send_frame(&frames, SessionFrame::input_ack(applied)).await?;
            }
            Some(session_frame::Body::Resize(resize)) => {
                let (Ok(cols), Ok(rows)) = (u16::try_from(resize.cols), u16::try_from(resize.rows))
                else {
                    return Err(SessionStreamError::Protocol(
                        "Resize cols/rows must fit in 16 bits".into(),
                    ));
                };
                // `resize_at`, not `resize`: this attach may have been
                // demoted to read-only by a steal-back on another
                // connection (protocol.md §10), same as `Input` above —
                // a stale attach must not keep SIGWINCH-ing the live PTY
                // out from under the connection that actually holds it.
                match sessions.resize_at(&id, conn, cols, rows).await {
                    Ok(())
                    | Err(
                        BrokerError::NotRunning | BrokerError::NotFound | BrokerError::NotWriter,
                    ) => {}
                    Err(err) => return Err(err.into()),
                }
                // The new size changes the screen without any output.
                if let Some(sync) = &sync {
                    sync.poke.notify_one();
                }
            }
            // The client's report of the newest state it applied. Only a
            // screen-sync stream takes one; on a byte path stream it is a
            // slip like any other host-to-client frame.
            Some(session_frame::Body::ScreenAck(ack)) => {
                if let Some(sync) = &sync {
                    sync.on_ack(ack.state_num);
                }
            }
            // Host → client frames coming back from a client are a slip,
            // not an attack surface; ignore them like a stray Pong.
            Some(_) | None => {}
        }
    }
}

/// Queue one frame for the writer. A closed queue means the writer is gone.
async fn send_frame(
    frames: &mpsc::Sender<SessionFrame>,
    frame: SessionFrame,
) -> Result<(), SessionStreamError> {
    frames
        .send(frame)
        .await
        .map_err(|_| SessionStreamError::PeerGone)
}

/// Mirror a ring control entry onto the control stream as an asynchronous
/// `SessionEvent` (protocol.md §9). `writer_changed` and `closed` have no
/// `SessionFrame` form, so for an attached peer this is their only door —
/// it waits for room rather than dropping them.
async fn notify(
    events: &Option<mpsc::Sender<ControlMessage>>,
    id: &SessionId,
    sequence: u64,
    event: &ControlEvent,
) -> Result<(), SessionStreamError> {
    let Some(tx) = events else { return Ok(()) };
    let body = match event {
        ControlEvent::Exit { exit_code, signal } => wire::SessionEvent::exited(
            id.as_str(),
            wire::Exit {
                final_seq: sequence,
                exit_code: exit_code.unwrap_or(-1),
                signal: signal.clone(),
            },
        ),
        ControlEvent::WriterChanged { writer } => {
            wire::SessionEvent::writer_changed(id.as_str(), writer.clone(), sequence)
        }
        ControlEvent::Closed { reason } => {
            wire::SessionEvent::closed(id.as_str(), reason.as_str(), sequence)
        }
    };
    tx.send(ControlMessage::new(
        0,
        control_message::Body::SessionEvent(body),
    ))
    .await
    .map_err(|_| SessionStreamError::PeerGone)
}
