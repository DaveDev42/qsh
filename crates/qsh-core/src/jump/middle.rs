//! The intermediate peer of a jump chain (ADR-0056 decisions 3, 4, 7, 8 and
//! 9; `docs/design/protocol.md` §21.3).
//!
//! `qsh_core::server`'s `JUMP` handler does the admission in decision 7's
//! order (shape, `forward.jump`, bounds, resolution, host-local filter, a
//! `connect`ed UDP socket) and then hands the socket and the stream to
//! [`run`]. Nothing in this module creates a resource before that handler has
//! authorized the request.
//!
//! [`run`] is one task per channel. It moves packets between the stream
//! carrier and the datagram carrier of the outer connection on one side and
//! the UDP socket on the other:
//!
//! * **client to target.** Stream frames ([`JumpStreamDecoder`]) and kind 14
//!   datagrams go out of the socket through the QUIC gate ([`Gate`]). Until
//!   the target answers like QUIC, only Initial-shaped packets pass, at most
//!   [`JUMP_PREGATE_PACKETS`] of them and [`JUMP_PREGATE_BYTES`] bytes.
//! * **target to client.** A packet is dropped until it opens the gate.
//!   After that the carrier is chosen per packet from this peer's own view
//!   ([`choose_carrier`]): a datagram when both sides advertise `datagram.v1`
//!   and the outer connection has room for a minimum-size inner packet,
//!   otherwise the stream, whose queue is bounded by [`JUMP_STREAM_QUEUE`].
//!   A packet that does not fit a datagram is dropped and counted, never
//!   sent on the stream instead (decision 4).
//! * **end.** A channel ends when the stream ends or resets, the outer
//!   connection closes, [`JUMP_IDLE`] passes without a forwarded packet in
//!   either direction, the gate stays shut for [`JUMP_GATE_TIMEOUT`], or the
//!   socket reports a refusal (`ECONNREFUSED`; `WSAECONNRESET` on Windows,
//!   whose `SIO_UDP_CONNRESET` this code never turns off). The stream is
//!   reset with `0x2007` for every abnormal end, so the client sees "not a
//!   clean end" at once (decision 8).
//!
//! The only things read from a packet are the clear-text QUIC long-header
//! fields (`qsh_proto::jump`). Logs, counters and the audit carry counts and
//! closed words, never an address, a channel, a connection ID or a byte.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_proto::datagram::{ChannelId, DatagramFrame, DatagramKind};
use qsh_proto::jump::{
    JUMP_CHANNEL_LEN, JUMP_PACKET_MAX, JUMP_PACKET_MIN, JUMP_PREGATE_BYTES, JUMP_PREGATE_PACKETS,
    JUMP_STREAM_QUEUE, JumpStreamDecoder, answers_gate, encode_packet, is_v1_initial_shaped,
    read_long_header,
};
use qsh_transport::{RecvStream, SendStream, StreamCode};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::datagram::{DatagramRx, SendFailure};

use super::TARGET;

/// Jump channels one connection may hold at once (ADR-0056 decision 9).
pub const MAX_JUMP_CHANNELS_PER_CONN: usize = 16;
/// A channel with no forwarded packet in either direction for this long
/// closes. It is longer than the inner connection's 45 s idle timeout, so J
/// never ends a live inner connection first.
pub const JUMP_IDLE: Duration = Duration::from_secs(60);
/// How long the QUIC gate waits for the target to answer like QUIC.
pub const JUMP_GATE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the one name resolution may take (decision 7 step 4).
pub const JUMP_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Stream reset code for every abnormal end of a channel. The same internal
/// code the tunnel splice uses; the peer only reads "not a clean end".
const RESET_CODE_ABORT: u32 = 0x2007;
/// Stream reset code for a framing violation (`BAD_HEADER`).
const RESET_CODE_BAD_FRAME: u32 = 0x2001;
/// Bytes of the jump datagram header (channel and kind).
const DATAGRAM_HEADER: usize = DatagramFrame::HEADER_LEN;

/// The knobs of an intermediate peer. Production uses [`Default`]; the
/// fields exist so a test can shorten a timer or turn off the host-local
/// filter, which would otherwise make a loopback target unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JumpOptions {
    /// [`JUMP_IDLE`].
    pub idle: Duration,
    /// [`JUMP_GATE_TIMEOUT`].
    pub gate_timeout: Duration,
    /// [`JUMP_RESOLVE_TIMEOUT`].
    pub resolve_timeout: Duration,
    /// [`MAX_JUMP_CHANNELS_PER_CONN`].
    pub max_channels_per_conn: usize,
    /// Test hook: do not filter host-local targets. Production never sets
    /// it (decision 7 step 5 is always on).
    pub allow_host_local: bool,
}

impl Default for JumpOptions {
    fn default() -> Self {
        Self {
            idle: JUMP_IDLE,
            gate_timeout: JUMP_GATE_TIMEOUT,
            resolve_timeout: JUMP_RESOLVE_TIMEOUT,
            max_channels_per_conn: MAX_JUMP_CHANNELS_PER_CONN,
            allow_host_local: false,
        }
    }
}

/// Why a channel ended. The words are the ones decision 19 logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// No forwarded packet for [`JumpOptions::idle`].
    Idle,
    /// The client finished or reset the stream, or the stream died.
    StreamEnd,
    /// The outer connection closed.
    ConnectionClosed,
    /// The target's socket reported a refusal.
    Unreachable,
    /// The gate stayed shut for [`JumpOptions::gate_timeout`].
    GateTimeout,
    /// The stream carrier's length prefix was invalid.
    BadFrame,
    /// The socket failed in a way that is not a refusal.
    SocketError,
}

impl CloseReason {
    /// The closed word logged for this reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::StreamEnd => "stream_end",
            Self::ConnectionClosed => "connection_closed",
            Self::Unreachable => "unreachable",
            Self::GateTimeout => "gate_timeout",
            Self::BadFrame => "bad_frame",
            Self::SocketError => "socket_error",
        }
    }
}

/// Counters of one host's jump channels, for tests and diagnostics. Counts
/// only: nothing here can hold a packet, an address or a channel value.
#[derive(Debug, Default)]
pub struct JumpStats {
    /// Channels that reached `ConnectResult{ok}`.
    pub opened: AtomicU64,
    /// Channels that ended.
    pub closed: AtomicU64,
    /// Packets sent from the client toward the target.
    pub to_target_packets: AtomicU64,
    /// Bytes sent from the client toward the target.
    pub to_target_bytes: AtomicU64,
    /// Of those, packets that arrived as datagrams.
    pub to_target_datagrams: AtomicU64,
    /// Packets sent from the target toward the client.
    pub to_client_packets: AtomicU64,
    /// Bytes sent from the target toward the client.
    pub to_client_bytes: AtomicU64,
    /// Of those, packets that went out as datagrams.
    pub to_client_datagrams: AtomicU64,
    /// Client packets the gate refused (not Initial-shaped, or over the
    /// pregate caps) and target packets that did not open it.
    pub gate_dropped: AtomicU64,
    /// Packets too large for a carrier (a datagram that did not fit, a
    /// packet over [`JUMP_PACKET_MAX`]).
    pub oversize_dropped: AtomicU64,
    /// Packets dropped because the stream queue was full.
    pub queue_dropped: AtomicU64,
    /// Datagrams the outer connection would not take.
    pub datagram_unavailable: AtomicU64,
    /// Sends the socket failed for a reason that is not a refusal.
    pub send_failed: AtomicU64,
    /// Channels in the table that are past admission (the number the
    /// on-demand idle exit counts).
    live: AtomicUsize,
    reasons: Mutex<Vec<CloseReason>>,
}

impl JumpStats {
    /// Live channels, past admission.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// The reasons channels ended, in order.
    pub fn close_reasons(&self) -> Vec<CloseReason> {
        self.reasons
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

// ----------------------------------------------------------------------
// the channel table
// ----------------------------------------------------------------------

/// The `jump_channel`s of every connection of one host and how many of them
/// are past admission. The first is the "already in use" check (shape,
/// before the ACL), the second the bound of decision 9 and the number the
/// on-demand idle exit counts.
#[derive(Debug, Default)]
pub struct JumpTable {
    inner: Mutex<TableInner>,
}

#[derive(Debug, Default)]
struct TableInner {
    claimed: HashSet<(usize, [u8; JUMP_CHANNEL_LEN])>,
    live: HashMap<usize, usize>,
}

impl JumpTable {
    /// A new, empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim `channel` on connection `conn`. `None` when this connection
    /// already uses the value. The claim holds until the guard drops.
    pub fn claim(
        self: &Arc<Self>,
        conn: usize,
        channel: [u8; JUMP_CHANNEL_LEN],
        stats: &Arc<JumpStats>,
    ) -> Option<ChannelGuard> {
        let inserted = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .claimed
            .insert((conn, channel));
        inserted.then(|| ChannelGuard {
            table: Arc::clone(self),
            stats: Arc::clone(stats),
            conn,
            channel,
            live: false,
            opened: false,
            reason: None,
        })
    }

    /// Channels past admission, over every connection.
    pub fn live_channels(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .live
            .values()
            .sum()
    }
}

/// A claimed `jump_channel`. Dropping it releases the claim and, once
/// [`reserve`](Self::reserve) succeeded, the live slot.
#[derive(Debug)]
pub struct ChannelGuard {
    table: Arc<JumpTable>,
    stats: Arc<JumpStats>,
    conn: usize,
    channel: [u8; JUMP_CHANNEL_LEN],
    live: bool,
    opened: bool,
    reason: Option<CloseReason>,
}

impl ChannelGuard {
    /// The channel reached `ConnectResult{ok}`. From here the guard counts
    /// the channel as closed when it drops, however the task ended (the
    /// connection driver aborts a stream task when its connection closes).
    pub fn mark_open(&mut self) {
        if !self.opened {
            self.opened = true;
            self.stats.opened.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Why the channel ended, when the relay knows. Without it a dropped
    /// guard records [`CloseReason::ConnectionClosed`].
    pub fn set_reason(&mut self, reason: CloseReason) {
        self.reason = Some(reason);
    }

    /// Take one of the connection's live slots. `false` when it already
    /// holds `max`.
    pub fn reserve(&mut self, max: usize) -> bool {
        if self.live {
            return true;
        }
        let mut inner = self.table.inner.lock().unwrap_or_else(|e| e.into_inner());
        let held = inner.live.get(&self.conn).copied().unwrap_or(0);
        if held >= max {
            return false;
        }
        inner.live.insert(self.conn, held + 1);
        self.live = true;
        self.stats.live.fetch_add(1, Ordering::Relaxed);
        true
    }
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        if self.opened {
            self.stats.closed.fetch_add(1, Ordering::Relaxed);
            self.stats
                .reasons
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(self.reason.unwrap_or(CloseReason::ConnectionClosed));
        }
        let mut inner = self.table.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.claimed.remove(&(self.conn, self.channel));
        if self.live {
            if let Some(held) = inner.live.get_mut(&self.conn) {
                *held -= 1;
                if *held == 0 {
                    inner.live.remove(&self.conn);
                }
            }
            self.stats.live.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ----------------------------------------------------------------------
// the QUIC gate
// ----------------------------------------------------------------------

/// The QUIC gate of decision 8, as a state machine over packets.
#[derive(Debug)]
pub struct Gate {
    open: bool,
    scids: Vec<Vec<u8>>,
    packets: usize,
    bytes: usize,
    max_packets: usize,
    max_bytes: usize,
}

impl Default for Gate {
    fn default() -> Self {
        Self::with_limits(JUMP_PREGATE_PACKETS, JUMP_PREGATE_BYTES)
    }
}

impl Gate {
    /// A shut gate with the pregate limits of decision 8.
    pub fn new() -> Self {
        Self::default()
    }

    /// A shut gate with other limits (tests).
    pub fn with_limits(max_packets: usize, max_bytes: usize) -> Self {
        Self {
            open: false,
            scids: Vec::new(),
            packets: 0,
            bytes: 0,
            max_packets,
            max_bytes,
        }
    }

    /// Whether the target has answered like QUIC.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Whether a packet from the client may go to the target. Before the
    /// gate opens that means Initial-shaped and within the pregate caps; the
    /// packet's SCID is remembered for [`admit_target`](Self::admit_target).
    pub fn admit_client(&mut self, packet: &[u8]) -> bool {
        if self.open {
            return !packet.is_empty();
        }
        if !is_v1_initial_shaped(packet) {
            return false;
        }
        if self.packets >= self.max_packets || self.bytes + packet.len() > self.max_bytes {
            return false;
        }
        let Some(header) = read_long_header(packet) else {
            return false;
        };
        self.packets += 1;
        self.bytes += packet.len();
        if !self.scids.iter().any(|s| s.as_slice() == header.scid) {
            self.scids.push(header.scid.to_vec());
        }
        true
    }

    /// Whether a packet from the target may go to the client. The first one
    /// that answers a remembered SCID with a long header opens the gate and
    /// passes; everything before that is dropped.
    pub fn admit_target(&mut self, packet: &[u8]) -> bool {
        if self.open {
            return !packet.is_empty();
        }
        if self.scids.iter().any(|scid| answers_gate(packet, scid)) {
            self.open = true;
            return true;
        }
        false
    }
}

// ----------------------------------------------------------------------
// carrier choice
// ----------------------------------------------------------------------

/// The carrier J sends target-to-client packets on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// One kind 14 datagram per packet.
    Datagram,
    /// Length-prefixed frames on the `JUMP` stream.
    Stream,
}

/// Decision 4's static rule: a datagram when both sides advertise
/// `datagram.v1` and the outer connection's `max_datagram_size()` holds a
/// minimum-size inner packet and the 17-byte jump header; the stream
/// otherwise. This peer's silence fallback (4 x srtt without a datagram
/// back, retried every 30 s) is a later step.
pub fn choose_carrier(both_datagram: bool, max_datagram_size: Option<usize>) -> Carrier {
    match max_datagram_size {
        Some(room) if both_datagram && room >= JUMP_PACKET_MIN + DATAGRAM_HEADER => {
            Carrier::Datagram
        }
        _ => Carrier::Stream,
    }
}

// ----------------------------------------------------------------------
// the stream queue and its writer
// ----------------------------------------------------------------------

/// The bounded queue in front of the stream carrier's writer. A packet that
/// would take it over `limit` unsent bytes is refused, because a queue only
/// hides loss from the inner congestion controller as delay.
#[derive(Debug)]
pub struct StreamQueue {
    queued: Arc<AtomicUsize>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    limit: usize,
}

impl StreamQueue {
    /// A queue and the receiver its writer drains. Call
    /// [`QueueRx::sent`] after each write so the bytes leave the count.
    pub fn new(limit: usize) -> (Self, QueueRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        (
            Self {
                queued: Arc::clone(&queued),
                tx,
                limit,
            },
            QueueRx { rx, queued },
        )
    }

    /// Queue one encoded frame. `false` when it would exceed the limit (the
    /// caller drops and counts) or the writer is gone.
    pub fn push(&self, frame: Vec<u8>) -> bool {
        if self.queued.load(Ordering::Acquire) + frame.len() > self.limit {
            return false;
        }
        self.queued.fetch_add(frame.len(), Ordering::AcqRel);
        self.tx.send(frame).is_ok()
    }

    /// Bytes queued and not yet written.
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }
}

/// The writer's end of a [`StreamQueue`].
#[derive(Debug)]
pub struct QueueRx {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

impl QueueRx {
    /// The next frame.
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// `len` bytes of a frame left the queue.
    pub fn sent(&self, len: usize) {
        self.queued.fetch_sub(len, Ordering::AcqRel);
    }
}

fn code(raw: u32) -> StreamCode {
    StreamCode::from_u32(raw)
}

/// Writes queued frames to the stream. `close` tells it how to end: `Some`
/// resets with that code at once (queued bytes are discarded), anything else
/// finishes.
async fn write_loop(
    mut send: SendStream,
    mut queue: QueueRx,
    mut close: oneshot::Receiver<Option<u32>>,
) {
    loop {
        tokio::select! {
            biased;
            how = &mut close => {
                end_send(&mut send, how.ok().flatten());
                return;
            }
            next = queue.next() => {
                let Some(frame) = next else {
                    let _ = send.finish();
                    return;
                };
                let len = frame.len();
                tokio::select! {
                    biased;
                    how = &mut close => {
                        end_send(&mut send, how.ok().flatten());
                        return;
                    }
                    written = send.write_all(&frame) => {
                        queue.sent(len);
                        if written.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

fn end_send(send: &mut SendStream, how: Option<u32>) {
    match how {
        Some(raw) => {
            let _ = send.reset(code(raw));
        }
        None => {
            let _ = send.finish();
        }
    }
}

// ----------------------------------------------------------------------
// the relay
// ----------------------------------------------------------------------

/// Everything [`run`] needs, handed over after admission.
pub struct Relay {
    /// The `connect`ed UDP socket toward the target.
    pub socket: UdpSocket,
    /// The `JUMP` stream's send half (raw: framing ended with the
    /// `ConnectResult`).
    pub send: SendStream,
    /// The stream's receive half.
    pub recv: RecvStream,
    /// Bytes the client pipelined behind its header.
    pub residue: Vec<u8>,
    /// Kind 14 datagrams for this channel.
    pub datagrams: DatagramRx,
    /// Whether both sides advertise `datagram.v1`.
    pub both_datagram: bool,
    /// The timers.
    pub options: JumpOptions,
    /// The host's counters.
    pub stats: Arc<JumpStats>,
    /// Holds the channel claim and the live slot until the relay ends.
    pub guard: ChannelGuard,
}

/// Whether a socket error is the target's refusal (Linux `ECONNREFUSED`,
/// Windows `WSAECONNRESET`) or an ICMP "unreachable".
fn is_refusal(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

struct State {
    socket: UdpSocket,
    gate: Gate,
    queue: StreamQueue,
    datagrams: DatagramRx,
    channel: ChannelId,
    both_datagram: bool,
    stats: Arc<JumpStats>,
    last_forward: Instant,
    packets: u64,
    bytes: u64,
}

impl State {
    /// A packet from the client, from either carrier.
    async fn relay_client(&mut self, packet: &[u8], via_datagram: bool) -> Result<(), CloseReason> {
        if packet.is_empty() || packet.len() > JUMP_PACKET_MAX {
            self.stats.oversize_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if !self.gate.admit_client(packet) {
            self.stats.gate_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        match self.socket.send(packet).await {
            Ok(_) => {
                self.stats.to_target_packets.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .to_target_bytes
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                if via_datagram {
                    self.stats
                        .to_target_datagrams
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.last_forward = Instant::now();
                self.packets += 1;
                self.bytes += packet.len() as u64;
                Ok(())
            }
            Err(err) if is_refusal(&err) => Err(CloseReason::Unreachable),
            Err(_) => {
                self.stats.send_failed.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    /// A packet from the target.
    fn relay_target(&mut self, packet: &[u8]) -> Result<(), CloseReason> {
        if packet.is_empty() || packet.len() > JUMP_PACKET_MAX {
            self.stats.oversize_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let was_open = self.gate.is_open();
        if !self.gate.admit_target(packet) {
            self.stats.gate_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if !was_open {
            tracing::debug!(target: TARGET, event = "gate_opened");
        }
        let room = self.datagrams.hub().max_datagram_size();
        let sent = match choose_carrier(self.both_datagram, room) {
            Carrier::Datagram => {
                let room = room.unwrap_or(0);
                if DATAGRAM_HEADER + packet.len() > room {
                    // Not sent on the stream instead: the inner PLPMTUD
                    // learns the room from the loss (decision 4).
                    self.stats.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                let frame = DatagramFrame {
                    channel: self.channel,
                    kind: DatagramKind::JumpPacket,
                    payload: packet.to_vec(),
                };
                match self.datagrams.hub().send(&frame) {
                    Ok(()) => {
                        self.stats
                            .to_client_datagrams
                            .fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Err(SendFailure::Closed) => return Err(CloseReason::ConnectionClosed),
                    Err(SendFailure::Unavailable) => {
                        self.stats
                            .datagram_unavailable
                            .fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
            }
            Carrier::Stream => {
                let Some(frame) = encode_packet(packet) else {
                    self.stats.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                };
                if self.queue.push(frame) {
                    true
                } else {
                    self.stats.queue_dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        };
        if sent {
            self.stats.to_client_packets.fetch_add(1, Ordering::Relaxed);
            self.stats
                .to_client_bytes
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            self.last_forward = Instant::now();
            self.packets += 1;
            self.bytes += packet.len() as u64;
        }
        Ok(())
    }
}

/// Run one channel until it ends and return why. The stream is already past
/// `ConnectResult{ok}`.
pub async fn run(relay: Relay) -> CloseReason {
    let Relay {
        socket,
        send,
        mut recv,
        residue,
        datagrams,
        both_datagram,
        options,
        stats,
        mut guard,
    } = relay;
    let channel = datagrams.channel();
    let (queue, queue_rx) = StreamQueue::new(JUMP_STREAM_QUEUE);
    let (close_tx, close_rx) = oneshot::channel();
    let mut writer = tokio::spawn(write_loop(send, queue_rx, close_rx));
    let mut writer_done = false;
    let started = Instant::now();
    let mut state = State {
        socket,
        gate: Gate::new(),
        queue,
        datagrams,
        channel,
        both_datagram,
        stats: Arc::clone(&stats),
        last_forward: started,
        packets: 0,
        bytes: 0,
    };
    guard.mark_open();
    tracing::debug!(target: TARGET, event = "channel_opened");

    let mut decoder = JumpStreamDecoder::new();
    decoder.push(&residue);
    let mut read_buf = vec![0u8; 16 * 1024];
    // One byte over the largest packet tells an oversize datagram from a
    // full-size one without reading the rest.
    let mut socket_buf = vec![0u8; JUMP_PACKET_MAX + 1];
    let gate_deadline = started + options.gate_timeout;

    let reason = 'channel: loop {
        loop {
            match decoder.next_packet() {
                Ok(Some(packet)) => {
                    if let Err(reason) = state.relay_client(&packet, false).await {
                        break 'channel reason;
                    }
                }
                Ok(None) => break,
                Err(_) => break 'channel CloseReason::BadFrame,
            }
        }
        let idle_deadline = state.last_forward + options.idle;
        let (deadline, on_deadline) = if state.gate.is_open() || idle_deadline < gate_deadline {
            (idle_deadline, CloseReason::Idle)
        } else {
            (gate_deadline, CloseReason::GateTimeout)
        };
        tokio::select! {
            read = recv.read(&mut read_buf) => match read {
                Ok(Some(n)) => decoder.push(&read_buf[..n]),
                Ok(None) | Err(_) => break CloseReason::StreamEnd,
            },
            frame = state.datagrams.recv() => match frame {
                Some(frame) if frame.kind == DatagramKind::JumpPacket => {
                    if let Err(reason) = state.relay_client(&frame.payload, true).await {
                        break reason;
                    }
                }
                Some(_) => {}
                None => break CloseReason::ConnectionClosed,
            },
            received = state.socket.recv(&mut socket_buf) => match received {
                Ok(n) => {
                    if let Err(reason) = state.relay_target(&socket_buf[..n]) {
                        break reason;
                    }
                }
                Err(err) if is_refusal(&err) => break CloseReason::Unreachable,
                Err(_) => break CloseReason::SocketError,
            },
            _ = &mut writer => {
                writer_done = true;
                break CloseReason::StreamEnd;
            }
            () = tokio::time::sleep_until(deadline) => break on_deadline,
        }
    };

    let (send_how, stop_how) = match reason {
        CloseReason::StreamEnd | CloseReason::ConnectionClosed => (None, None),
        CloseReason::BadFrame => (Some(RESET_CODE_BAD_FRAME), Some(RESET_CODE_BAD_FRAME)),
        _ => (Some(RESET_CODE_ABORT), Some(RESET_CODE_ABORT)),
    };
    let _ = close_tx.send(send_how);
    if let Some(raw) = stop_how {
        let _ = recv.stop(code(raw));
    }
    if !writer_done {
        // The reset is one poll away; the timeout only covers a runtime
        // that is shutting down.
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut writer).await;
        writer.abort();
    }
    guard.set_reason(reason);
    tracing::debug!(
        target: TARGET,
        event = "channel_closed",
        reason = reason.as_str(),
        packets = state.packets,
        bytes = state.bytes,
        queue_dropped = stats.queue_dropped.load(Ordering::Relaxed),
        oversize_dropped = stats.oversize_dropped.load(Ordering::Relaxed),
    );
    drop(guard);
    reason
}

#[cfg(test)]
mod tests;
