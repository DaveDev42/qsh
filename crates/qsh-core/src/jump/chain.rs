//! The client side of a jump chain (ADR-0056 decisions 4 to 6, 10 to 13 and
//! 15; MTU numbers from ADR-0057).
//!
//! [`dial_chain`] takes the connection to the first peer (the caller got it
//! the ordinary way, punching included) and walks the rest of the chain:
//!
//! 1. negotiate with the peer reached so far and check it advertises
//!    `jump.v1`;
//! 2. open a `JUMP` stream on its connection with a fresh CSPRNG channel and
//!    the next peer's pin address, as written (this side never resolves it),
//!    and wait for `ConnectResult`;
//! 3. run a [`PacketPipe`] over the channel (the pump) and dial the next
//!    peer over it with [`Dialer::dial_over_pipe`], accepting that peer's
//!    pinned fingerprint and nothing else (decision 10);
//! 4. repeat from the connection that just stood.
//!
//! The last connection is returned as [`ChainConn`] and is an ordinary qsh
//! connection: a session, an exec, a tunnel or a copy runs on it unchanged.
//! Every connection and pump the chain holds below it is kept alive by a
//! supervisor task that ends them together once the last connection closes,
//! and closes the last connection when any layer under it dies (decision 16:
//! the chain is one unit).
//!
//! Each failure is a [`JumpFailure`]: which step, and which of the nine
//! stages. Nothing is created on the end target before its pin matched, so a
//! mismatch leaves no session or command there.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::datagram::{ChannelId, DatagramFrame, DatagramKind};
use qsh_proto::jump::{
    JUMP_CHANNEL_LEN, JUMP_PACKET_MAX, JUMP_STREAM_QUEUE, JumpStreamDecoder, encode_packet,
};
use qsh_proto::wire::{
    CAP_DATAGRAM_V1, CAP_JUMP_V1, ConnectResult, PRIORITY_SESSION_DATA, StreamHeader, StreamKind,
};
use qsh_transport::{
    Connection, DialError, Dialer, Endpoint, Fingerprint, FramedRecv, FramedSend, PacketPipe,
    PipePeer, Principal, StaticTrust,
};
use rand::Rng as _;
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

use super::TARGET;
use super::carrier::{Carrier, DATAGRAM_HEADER, SilenceFallback, choose_carrier};
use super::middle::{ChanRx, ChanTx, StreamQueue, write_loop};
use super::report::{JumpFailure, Stage};
use crate::client::Session;
use crate::datagram::{DatagramHub, DatagramRx, SendFailure};
use crate::ops::OpError;
use crate::punch::PunchPlan;

/// Intermediate peers a chain may have (ADR-0056 decision 11). The end
/// target is not counted.
pub const MAX_JUMP_HOPS: usize = 4;

/// Bytes one jump layer takes off the room of the connection that carries
/// it: the 17-byte jump datagram header plus the 38 bytes QUIC adds to a
/// datagram of the carrying connection (ADR-0057 decision 1). The code reads
/// the live `max_datagram_size()`; this is the table's number.
pub const LAYER_COST: usize = DATAGRAM_HEADER + 38;

/// How often a pump re-reads the outer connection's room when no packet
/// forces it (so the packet limit follows PLPMTUD on an idle channel).
const LIMIT_REFRESH: Duration = Duration::from_millis(250);

/// How long a teardown waits for each layer's closing handshake to leave.
const CLOSE_GRACE: Duration = Duration::from_millis(300);

/// How long the supervisor keeps the layers up for the end connection's
/// closing handshake: its closing period is three PTOs, which can be seconds
/// on a path that just lost packets. Under the transport's
/// `NESTED_IDLE_CAP`, which bounds the caller's own wait.
const END_DRAIN: Duration = Duration::from_secs(2);

/// Depth of a pipe's two queues, in packets.
const PIPE_DEPTH: usize = 256;

/// A peer of the chain as the client's trust store has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopPin {
    /// The pin name.
    pub name: String,
    /// `host:port`, sent to the previous peer as it is.
    pub address: String,
    /// The one fingerprint the peer may present.
    pub fingerprint: Fingerprint,
}

/// A validated chain: the intermediate peers in order and the end target.
#[derive(Clone)]
pub struct JumpPlan {
    /// One to [`MAX_JUMP_HOPS`] intermediate peers.
    pub hops: Vec<HopPin>,
    /// The end target.
    pub end: HopPin,
    /// The punch plan for the first peer's ordinary route (decision 13).
    pub first_punch: Option<Arc<PunchPlan>>,
    /// The device name the client presents in `Hello` to every peer.
    pub device_name: String,
    /// Set when the first hop is a registered host reached only through the
    /// local `qsh listen` daemon (ADR-0056 decision 14).
    pub first_reverse: Option<ReverseHop>,
}

/// The first hop of a chain when it registered reverse on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseHop {
    /// The host alias to ask the daemon for (`LocalHello.host`).
    pub host: String,
    /// The daemon's localctl socket.
    pub socket: std::path::PathBuf,
}

impl std::fmt::Debug for JumpPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JumpPlan")
            .field("hops", &self.hops)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

impl JumpPlan {
    /// Checks the shape rules of decision 11 before anything is dialed.
    /// `INVALID_ARGUMENT` for no hop, more than [`MAX_JUMP_HOPS`], the same
    /// pin twice (by name or by fingerprint), or the end target among the
    /// hops.
    pub fn new(
        hops: Vec<HopPin>,
        end: HopPin,
        first_punch: Option<Arc<PunchPlan>>,
        device_name: String,
    ) -> Result<Self, OpError> {
        let names: Vec<&str> = hops.iter().map(|h| h.name.as_str()).collect();
        check_shape(&names, &end.name)?;
        for (i, hop) in hops.iter().enumerate() {
            let same = |other: &HopPin| other.fingerprint == hop.fingerprint;
            if hops[..i].iter().any(same) || same(&end) {
                return Err(invalid("a jump chain names the same peer twice"));
            }
        }
        Ok(Self {
            hops,
            end,
            first_punch,
            device_name,
            first_reverse: None,
        })
    }

    /// The first hop is reached through the local daemon's registration
    /// instead of by a dial of its own (decision 14).
    #[must_use]
    pub fn with_reverse_first(mut self, route: ReverseHop) -> Self {
        self.first_reverse = Some(route);
        self
    }

    /// Intermediate peers plus the end target.
    pub fn hop_count(&self) -> usize {
        self.hops.len() + 1
    }

    /// The step at 0-based `index`: an intermediate peer or the end.
    pub fn step(&self, index: usize) -> &HopPin {
        self.hops.get(index).unwrap_or(&self.end)
    }
}

fn invalid(message: &str) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}

/// The name-level shape rules, usable before any pin is looked up: at least
/// one hop, at most [`MAX_JUMP_HOPS`], no name twice, the end not among the
/// hops.
pub fn check_shape(hops: &[&str], end: &str) -> Result<(), OpError> {
    if hops.is_empty() {
        return Err(invalid("a jump chain needs at least one hop"));
    }
    if hops.len() > MAX_JUMP_HOPS {
        return Err(invalid(&format!(
            "a jump chain has at most {MAX_JUMP_HOPS} hops before the target; {} were given",
            hops.len()
        )));
    }
    for (i, hop) in hops.iter().enumerate() {
        if hops[..i].contains(hop) {
            return Err(invalid(&format!("{hop:?} appears twice in the jump chain")));
        }
        if *hop == end {
            return Err(invalid(&format!(
                "the target {end:?} is also one of its jump hops"
            )));
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// the budget
// ----------------------------------------------------------------------

/// The longest inner packet a datagram carrier holds when the carrying
/// connection's `max_datagram_size()` is `room`.
pub fn datagram_packet_limit(room: usize) -> usize {
    room.saturating_sub(DATAGRAM_HEADER).min(JUMP_PACKET_MAX)
}

/// What the carrier choice makes of a link whose UDP payload is
/// `link_payload` bytes, layer by layer (ADR-0057 decision 2). The first
/// entry is the first hop; each entry is the carrier and the packet limit
/// of that channel's pipe. `hops` entries are returned, assuming the
/// connection that carries a channel can discover a path MTU as large as
/// its own pipe allows.
pub fn budget(link_payload: usize, hops: usize) -> Vec<(Carrier, usize)> {
    let mut out = Vec::new();
    // The outer connection's PLPMTUD stops at `JUMP_PACKET_MAX`.
    let mut mtu = link_payload.min(JUMP_PACKET_MAX);
    for _ in 0..hops {
        let room = mtu.saturating_sub(38);
        let carrier = choose_carrier(true, Some(room));
        let limit = match carrier {
            Carrier::Datagram => datagram_packet_limit(room),
            Carrier::Stream => JUMP_PACKET_MAX,
        };
        out.push((carrier, limit));
        mtu = limit;
    }
    out
}

// ----------------------------------------------------------------------
// counters
// ----------------------------------------------------------------------

/// Counters of one channel of the chain, for tests and `qsh doctor`. Counts
/// only.
#[derive(Debug, Default)]
pub struct ChannelInfo {
    carrier: AtomicU8,
    packet_limit: AtomicUsize,
    /// Packets sent to the previous peer as datagrams.
    pub datagrams_out: AtomicU64,
    /// Packets sent to the previous peer on the stream.
    pub stream_out: AtomicU64,
    /// Packets that came back as datagrams.
    pub datagrams_in: AtomicU64,
    /// Packets that came back on the stream.
    pub stream_in: AtomicU64,
    /// Outgoing packets that did not fit a datagram and were dropped.
    pub oversize_dropped: AtomicU64,
    /// Outgoing packets dropped because the stream queue was full.
    pub queue_dropped: AtomicU64,
    /// Datagrams the outer connection would not take.
    pub datagram_unavailable: AtomicU64,
    /// Times the carrier changed.
    pub switches: AtomicU64,
    /// Times the silence rule moved the channel to the stream.
    pub silence_fallbacks: AtomicU64,
}

impl ChannelInfo {
    /// The carrier of the last packet sent.
    pub fn carrier(&self) -> Carrier {
        if self.carrier.load(Ordering::Relaxed) == 1 {
            Carrier::Datagram
        } else {
            Carrier::Stream
        }
    }

    /// The pipe's packet limit as last set.
    pub fn packet_limit(&self) -> usize {
        self.packet_limit.load(Ordering::Relaxed)
    }
}

/// What a built chain exposes about itself.
#[derive(Debug, Default)]
pub struct ChainInfo {
    /// One entry per channel, in chain order: entry 0 carries the
    /// connection to the second step.
    pub channels: Vec<Arc<ChannelInfo>>,
}

// ----------------------------------------------------------------------
// the pump
// ----------------------------------------------------------------------

/// Why a pump ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpEnd {
    /// The chain stopped it, or the pipe's inner endpoint is gone.
    Stopped,
    /// The `JUMP` stream ended or was reset: the previous peer closed the
    /// channel (a refused target, the idle timer, a bad frame).
    StreamEnded,
    /// The outer connection closed.
    ConnectionClosed,
}

struct PumpHandle {
    stop: Option<oneshot::Sender<()>>,
    ended: watch::Receiver<Option<PumpEnd>>,
    task: JoinHandle<()>,
}

impl PumpHandle {
    /// Resolves when the pump ended, and why.
    async fn ended(&mut self) -> PumpEnd {
        loop {
            if let Some(end) = *self.ended.borrow_and_update() {
                return end;
            }
            if self.ended.changed().await.is_err() {
                return PumpEnd::Stopped;
            }
        }
    }

    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

struct PumpArgs {
    /// The connection that carries the channel; `None` when the first hop
    /// is reached through the local daemon (a stream-only conduit,
    /// ADR-0056 decision 14).
    outer: Option<Connection>,
    id: [u8; JUMP_CHANNEL_LEN],
    send: ChanTx,
    recv: ChanRx,
    residue: Vec<u8>,
    datagrams: Option<DatagramRx>,
    peer: PipePeer,
    both_datagram: bool,
    info: Arc<ChannelInfo>,
}

fn spawn_pump(args: PumpArgs) -> PumpHandle {
    let (stop_tx, stop_rx) = oneshot::channel();
    let (ended_tx, ended_rx) = watch::channel(None);
    let task = tokio::spawn(async move {
        pump(args, stop_rx, ended_tx).await;
    });
    PumpHandle {
        stop: Some(stop_tx),
        ended: ended_rx,
        task,
    }
}

/// Moves the packets of the inner connection (the pipe's [`PipePeer`]) over
/// the channel until it ends.
async fn pump(
    args: PumpArgs,
    mut stop: oneshot::Receiver<()>,
    ended: watch::Sender<Option<PumpEnd>>,
) {
    let PumpArgs {
        outer,
        id,
        send,
        mut recv,
        residue,
        mut datagrams,
        mut peer,
        both_datagram,
        info,
    } = args;
    let hub = datagrams.as_ref().map(|d| Arc::clone(d.hub()));
    let channel = ChannelId(id);
    let (queue, queue_rx) = StreamQueue::new(JUMP_STREAM_QUEUE);
    let (close_tx, close_rx) = oneshot::channel();
    let mut writer = tokio::spawn(write_loop(send, queue_rx, close_rx));
    let mut writer_done = false;
    let mut silence = SilenceFallback::new();
    let mut decoder = JumpStreamDecoder::new();
    decoder.push(&residue);
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut refresh = tokio::time::interval(LIMIT_REFRESH);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last: Option<Carrier> = None;

    // The first limit is the room's until a packet or the refresh reads it
    // again, so a packet is never held to a stale datagram budget.
    let room = hub.as_ref().and_then(|h| h.max_datagram_size());
    apply_limit(&peer, &info, choose_carrier(both_datagram, room), room);

    let end = 'pump: loop {
        loop {
            match decoder.next_packet() {
                Ok(Some(packet)) => {
                    info.stream_in.fetch_add(1, Ordering::Relaxed);
                    peer.send(packet);
                }
                Ok(None) => break,
                Err(_) => break 'pump PumpEnd::StreamEnded,
            }
        }
        tokio::select! {
            biased;
            _ = &mut stop => break PumpEnd::Stopped,
            packet = peer.recv() => {
                let Some(packet) = packet else { break PumpEnd::Stopped };
                let room = hub.as_ref().and_then(|h| h.max_datagram_size());
                let rule = choose_carrier(both_datagram, room);
                let rtt = hub.as_ref().map_or(Duration::ZERO, |h| h.rtt());
                let carrier = silence.choose(rule, std::time::Instant::now(), rtt);
                if silence.fell_back() && last == Some(Carrier::Datagram) {
                    info.silence_fallbacks.fetch_add(1, Ordering::Relaxed);
                }
                note_carrier(&info, &mut last, carrier);
                // The pipe holds packets to the limit of the carrier in use.
                apply_limit(&peer, &info, carrier, room);
                match carrier {
                    Carrier::Datagram => {
                        let room = room.unwrap_or(0);
                        if DATAGRAM_HEADER + packet.len() > room {
                            info.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let frame = DatagramFrame {
                            channel,
                            kind: DatagramKind::JumpPacket,
                            payload: packet,
                        };
                        let sent = match &hub {
                            Some(hub) => hub.send(&frame),
                            None => Err(SendFailure::Unavailable),
                        };
                        match sent {
                            Ok(()) => {
                                silence.sent_datagram(std::time::Instant::now());
                                info.datagrams_out.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(SendFailure::Closed) => break PumpEnd::ConnectionClosed,
                            Err(SendFailure::Unavailable) => {
                                info.datagram_unavailable.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Carrier::Stream => {
                        let Some(frame) = encode_packet(&packet) else {
                            info.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        if queue.push(frame) {
                            info.stream_out.fetch_add(1, Ordering::Relaxed);
                        } else {
                            info.queue_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            frame = next_datagram(&mut datagrams) => match frame {
                Some(frame) if frame.kind == DatagramKind::JumpPacket => {
                    silence.received_datagram();
                    info.datagrams_in.fetch_add(1, Ordering::Relaxed);
                    peer.send(frame.payload);
                }
                Some(_) => {}
                None => break PumpEnd::ConnectionClosed,
            },
            read = recv.read(&mut read_buf) => match read {
                Ok(Some(n)) => decoder.push(&read_buf[..n]),
                Ok(None) | Err(_) => break PumpEnd::StreamEnded,
            },
            _ = &mut writer => {
                writer_done = true;
                break PumpEnd::StreamEnded;
            }
            _ = refresh.tick() => {
                let room = hub.as_ref().and_then(|h| h.max_datagram_size());
                let rule = choose_carrier(both_datagram, room);
                let carrier = if silence.fell_back() { Carrier::Stream } else { rule };
                apply_limit(&peer, &info, carrier, room);
            }
            () = outer_closed(&outer) => break PumpEnd::ConnectionClosed,
        }
    };

    // Said before anything is torn down: the pipe closes with this task, and
    // whoever sees the inner endpoint fail must find the reason already
    // here.
    let _ = ended.send(Some(end));
    // The stream is reset on every end the pump decides, so the previous
    // peer drops the channel at once; a clean end finishes it.
    let how = match end {
        PumpEnd::Stopped => None,
        _ => Some(0x2007),
    };
    let _ = close_tx.send(how);
    if how.is_some() {
        recv.stop(0x2007);
    }
    if !writer_done {
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut writer).await;
        writer.abort();
    }
    tracing::debug!(
        target: TARGET,
        event = "channel_closed",
        side = "client",
        datagrams_out = info.datagrams_out.load(Ordering::Relaxed),
        stream_out = info.stream_out.load(Ordering::Relaxed),
    );
}

/// The next datagram of a channel; never, for a channel with no datagram
/// carrier.
async fn next_datagram(datagrams: &mut Option<DatagramRx>) -> Option<DatagramFrame> {
    match datagrams {
        Some(d) => d.recv().await,
        None => std::future::pending().await,
    }
}

/// Resolves when the outer connection closes; never, without one.
async fn outer_closed(outer: &Option<Connection>) {
    match outer {
        Some(conn) => {
            let _ = conn.closed().await;
        }
        None => std::future::pending().await,
    }
}

/// Holds the pipe to the packet size of the carrier in use.
fn apply_limit(peer: &PipePeer, info: &ChannelInfo, carrier: Carrier, room: Option<usize>) {
    let limit = match carrier {
        Carrier::Datagram => datagram_packet_limit(room.unwrap_or(0)),
        Carrier::Stream => JUMP_PACKET_MAX,
    };
    peer.set_packet_limit(limit);
    info.packet_limit.store(limit, Ordering::Relaxed);
}

fn note_carrier(info: &ChannelInfo, last: &mut Option<Carrier>, now: Carrier) {
    info.carrier.store(
        match now {
            Carrier::Datagram => 1,
            Carrier::Stream => 0,
        },
        Ordering::Relaxed,
    );
    if let Some(before) = *last
        && before != now
    {
        info.switches.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            target: TARGET,
            event = "carrier_changed",
            from = before.as_str(),
            to = now.as_str(),
        );
    }
    *last = Some(now);
}

// ----------------------------------------------------------------------
// the walk
// ----------------------------------------------------------------------

/// The connection a chain ends in and what it exposes.
pub struct ChainConn {
    /// The connection to the end target. Closing it ends the chain.
    pub connection: Connection,
    /// The endpoint that carries it (a pipe endpoint).
    pub endpoint: Endpoint,
    /// Counters of every channel.
    pub info: Arc<ChainInfo>,
}

impl std::fmt::Debug for ChainConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainConn").finish_non_exhaustive()
    }
}

/// One connection of the chain below the end, with what keeps it useful.
struct Layer {
    /// `None` for the first hop of a chain reached through the local
    /// daemon: that hop has no connection of this process.
    connection: Option<Connection>,
    endpoint: Option<Endpoint>,
    /// The negotiated control stream. Dropped last.
    session: Option<Session>,
    /// The pump of the channel this connection carries toward the next
    /// step.
    pump: Option<PumpHandle>,
}

fn failure(plan: &JumpPlan, index: usize, stage: Stage) -> JumpFailure {
    JumpFailure {
        hop: index + 1,
        hops: plan.hop_count(),
        name: plan.step(index).name.clone(),
        stage,
    }
}

fn split_target(address: &str) -> Option<(String, u16)> {
    let (host, port) = crate::trust::split_port(address)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().ok()?;
    (!host.is_empty() && port != 0).then(|| (host.to_string(), port))
}

/// The stage and plain message for a refused `JUMP`, from the previous
/// peer's `ConnectResult`.
fn refusal(result: &ConnectResult) -> (Stage, String) {
    let code: Option<ErrorCode> = result.code.parse().ok();
    let stage = match code {
        Some(ErrorCode::PermissionDenied) => Stage::Denied,
        Some(ErrorCode::ResourceExhausted) => Stage::Limit,
        Some(ErrorCode::Unsupported) => Stage::Unsupported,
        _ => Stage::Resolve,
    };
    let message = match stage {
        Stage::Denied => "the previous hop does not allow this jump".to_string(),
        Stage::Limit => format!("the previous hop is at a limit: {}", result.message),
        Stage::Unsupported => "the previous hop does not support jumping".to_string(),
        _ => format!("the previous hop could not reach it: {}", result.message),
    };
    (stage, message)
}

/// Walks the chain. `first` is the connection to the first intermediate
/// peer and the endpoint that carries it; `deadline` bounds every later
/// step (decision 6: one dial time for the whole chain).
///
/// On failure everything created so far is closed. On success a supervisor
/// owns the layers; see the module documentation.
pub async fn dial_chain(
    plan: &JumpPlan,
    dialer: &Dialer,
    first: (Connection, Endpoint),
    deadline: Instant,
) -> Result<ChainConn, OpError> {
    dial_chain_from(plan, dialer, FirstHop::Direct(first.0, first.1), deadline).await
}

/// [`dial_chain`] for a plan whose first hop is reached through the local
/// daemon's registration ([`JumpPlan::first_reverse`], decision 14): the
/// daemon opens the first `JUMP` channel on the registered connection and
/// there is no connection of this process to the first hop at all.
pub async fn dial_chain_via_daemon(
    plan: &JumpPlan,
    dialer: &Dialer,
    deadline: Instant,
) -> Result<ChainConn, OpError> {
    dial_chain_from(plan, dialer, FirstHop::Daemon, deadline).await
}

/// How the first peer of a chain is reached.
#[allow(clippy::large_enum_variant)]
enum FirstHop {
    Direct(Connection, Endpoint),
    Daemon,
}

async fn dial_chain_from(
    plan: &JumpPlan,
    dialer: &Dialer,
    first: FirstHop,
    deadline: Instant,
) -> Result<ChainConn, OpError> {
    let mut layers = LayerGuard(Vec::with_capacity(plan.hop_count()));
    let mut infos: Vec<Arc<ChannelInfo>> = Vec::new();
    match walk(plan, dialer, first, deadline, &mut layers.0, &mut infos).await {
        Ok((connection, endpoint)) => {
            let info = Arc::new(ChainInfo { channels: infos });
            supervise(
                std::mem::take(&mut layers.0),
                connection.clone(),
                endpoint.clone(),
            );
            tracing::debug!(
                target: TARGET,
                event = "chain_up",
                hops = plan.hop_count(),
            );
            Ok(ChainConn {
                connection,
                endpoint,
                info,
            })
        }
        Err(op) => {
            tracing::debug!(
                target: TARGET,
                event = "chain_failed",
                stage = op.details["jump"]["stage"].as_str().unwrap_or("-"),
            );
            teardown(std::mem::take(&mut layers.0)).await;
            Err(op)
        }
    }
}

/// Owns the layers while the chain is being walked. A walk that is dropped
/// half way (a recovery attempt that ran out of time) must not leave its
/// connections and pumps behind: recovery rebuilds the chain from the
/// start and the old layers are not reused (decision 16).
struct LayerGuard(Vec<Layer>);

impl Drop for LayerGuard {
    fn drop(&mut self) {
        let layers = std::mem::take(&mut self.0);
        if layers.is_empty() {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(teardown(layers));
        }
    }
}

async fn walk(
    plan: &JumpPlan,
    dialer: &Dialer,
    first: FirstHop,
    deadline: Instant,
    layers: &mut Vec<Layer>,
    infos: &mut Vec<Arc<ChannelInfo>>,
) -> Result<(Connection, Endpoint), OpError> {
    let hops = plan.hop_count();

    // Step 1: the first peer. The ordinary route accepts any pinned peer,
    // so the pin of this step is checked here. Through the daemon there is
    // no connection of this process: the pin is checked against the
    // registration before the first channel is asked for.
    if let FirstHop::Direct(conn, endpoint) = first {
        if conn.peer_fingerprint() != Some(plan.step(0).fingerprint) {
            conn.close(0, b"pin mismatch");
            return Err(failure(plan, 0, Stage::Auth)
                .into_op("the peer's certificate is not the one pinned for it", None));
        }
        let session = negotiate(plan, 0, &conn, deadline, Stage::Dial).await;
        let session = match session {
            Ok(s) => s,
            Err(op) => {
                conn.close(0, b"hello failed");
                return Err(op);
            }
        };
        layers.push(Layer {
            connection: Some(conn),
            endpoint: Some(endpoint),
            session: Some(session),
            pump: None,
        });
    }

    for index in 1..hops {
        let step = plan.step(index);
        // What carries this step's channel: the previous peer's connection,
        // or the local daemon for a first hop that registered reverse.
        let (outer, both_datagram) = match layers.last() {
            Some(Layer {
                connection: Some(conn),
                session,
                ..
            }) => {
                let caps = session
                    .as_ref()
                    .map(|s| s.capabilities.clone())
                    .unwrap_or_default();
                if !caps.iter().any(|c| c == CAP_JUMP_V1) {
                    return Err(failure(plan, index, Stage::Unsupported)
                        .into_op("the previous hop does not support jumping", None));
                }
                (
                    Some(conn.clone()),
                    caps.iter().any(|c| c == CAP_DATAGRAM_V1),
                )
            }
            _ => (None, false),
        };
        let Some((host, port)) = split_target(&step.address) else {
            return Err(failure(plan, index, Stage::Address)
                .into_op("the pinned address is not host:port", None));
        };

        // The channel: client-chosen, from the CSPRNG.
        let mut id = [0u8; JUMP_CHANNEL_LEN];
        rand::rng().fill_bytes(&mut id);
        let header = StreamHeader {
            kind: StreamKind::Jump as i32,
            ticket: id.to_vec(),
            host,
            port: u32::from(port),
            deny_host_local: false,
        };
        let (datagrams, opened) = match &outer {
            Some(outer) => {
                let hub = DatagramHub::of(outer);
                let datagrams = hub.register(ChannelId(id));
                let opened = tokio::time::timeout_at(deadline, open_channel(outer, &header)).await;
                (Some(datagrams), opened)
            }
            None => {
                let opened =
                    tokio::time::timeout_at(deadline, open_channel_via_daemon(plan, &header)).await;
                (None, opened)
            }
        };
        let (send, recv, residue) = match opened {
            Err(_) => {
                return Err(failure(plan, index, Stage::Handshake)
                    .into_op("the previous hop did not answer in time", None));
            }
            Ok(Err(OpenError::Refused(result))) => {
                let (stage, message) = refusal(&result);
                return Err(failure(plan, index, stage).into_op(message, None));
            }
            Ok(Err(OpenError::Transport(message))) => {
                return Err(failure(plan, index, Stage::Unreachable).into_op(message, None));
            }
            Ok(Err(OpenError::FirstHop(stage, message, route))) => {
                return Err(failure(plan, 0, stage).into_op(message, route));
            }
            Ok(Ok(opened)) => opened,
        };

        // The pipe, and the pump that carries it over the channel.
        let (pipe, peer) = PacketPipe::new(PIPE_DEPTH);
        let info = Arc::new(ChannelInfo::default());
        infos.push(Arc::clone(&info));
        let mut pump = spawn_pump(PumpArgs {
            outer,
            id,
            send,
            recv,
            residue,
            datagrams,
            peer,
            both_datagram,
            info,
        });

        // The inner connection accepts exactly the step's pinned fingerprint.
        let evaluator = Arc::new(
            StaticTrust::empty().with_pin(step.fingerprint, Principal::Device(step.name.clone())),
        );
        let remaining = deadline.saturating_duration_since(Instant::now());
        let pinned = dialer.with_evaluator(evaluator).with_timeout(remaining);
        let outcome = tokio::select! {
            biased;
            dialed = pinned.dial_over_pipe(pipe, "qsh") => Ok(dialed),
            end = pump.ended() => Err(end),
        };
        match layers.last_mut() {
            Some(layer) if layer.connection.is_some() => layer.pump = Some(pump),
            // The first hop is the daemon's: the pump has no layer of a
            // connection to hang on, so it gets one of its own.
            _ => layers.push(Layer {
                connection: None,
                endpoint: None,
                session: None,
                pump: Some(pump),
            }),
        }
        // A channel the previous peer closed under the handshake is the
        // report, whatever error the inner endpoint gave when its pipe
        // closed: nothing answered at the target (ICMP refusal, the gate's
        // timeout) and nothing will.
        let closed_under_us = |layers: &[Layer]| {
            layers
                .last()
                .and_then(|l| l.pump.as_ref())
                .and_then(|p| *p.ended.borrow())
                .filter(|end| *end != PumpEnd::Stopped)
        };
        let unreachable = |end: PumpEnd| {
            let reason = match end {
                PumpEnd::ConnectionClosed => "the previous hop closed the connection",
                _ => "the previous hop closed the channel; nothing answered at the target",
            };
            failure(plan, index, Stage::Unreachable).into_op(reason, None)
        };
        let dialed = match outcome {
            Ok(Ok(dialed)) => dialed,
            Ok(Err(err)) => {
                return Err(match closed_under_us(layers) {
                    Some(end) => unreachable(end),
                    None => inner_dial_failure(plan, index, err),
                });
            }
            Err(end) => return Err(unreachable(end)),
        };
        let inner = dialed.connection;
        // Migration happens at the first hop only (decision 16): this
        // endpoint's rebind moves the socket of the layer under it. A first
        // hop reached through the daemon has no socket of this process, so
        // there is nothing to move.
        let parent_endpoint = layers.last().and_then(|l| l.endpoint.clone());
        let inner_endpoint = match parent_endpoint {
            Some(parent) => dialed.endpoint.rebinding_via(parent),
            None => dialed.endpoint,
        };

        if index + 1 == hops {
            return Ok((inner, inner_endpoint));
        }
        // An intermediate peer: negotiate, then it is the next layer.
        let session = match negotiate(plan, index, &inner, deadline, Stage::Handshake).await {
            Ok(s) => s,
            Err(op) => {
                inner.close(0, b"hello failed");
                layers.push(Layer {
                    connection: Some(inner),
                    endpoint: Some(inner_endpoint),
                    session: None,
                    pump: None,
                });
                return Err(op);
            }
        };
        layers.push(Layer {
            connection: Some(inner),
            endpoint: Some(inner_endpoint),
            session: Some(session),
            pump: None,
        });
    }
    unreachable!("a chain has at least the end target after its first peer")
}

fn inner_dial_failure(plan: &JumpPlan, index: usize, err: DialError) -> OpError {
    let (stage, message) = match err {
        DialError::LocalRejected { .. } => (
            Stage::Auth,
            "the peer's certificate is not the one pinned for it".to_string(),
        ),
        DialError::RemoteRejected => (
            Stage::Auth,
            "the peer rejected this device's certificate".to_string(),
        ),
        DialError::Timeout(t) => (
            Stage::Handshake,
            format!("no answer from the target within {t:?}"),
        ),
        other => (Stage::Handshake, format!("the handshake failed: {other}")),
    };
    failure(plan, index, stage).into_op(message, None)
}

/// `Hello` with the peer reached at step `index`. A failure is `stage` (the
/// first peer's is `dial`: it is an ordinary connection that failed).
async fn negotiate(
    plan: &JumpPlan,
    index: usize,
    conn: &Connection,
    deadline: Instant,
    stage: Stage,
) -> Result<Session, OpError> {
    let negotiated = tokio::time::timeout_at(
        deadline,
        Session::negotiate(conn.clone(), &plan.device_name),
    )
    .await;
    match negotiated {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(err)) => {
            let route = crate::ops::exec::map_client_error(err);
            let message = route.message.clone();
            let keep = (stage == Stage::Dial).then_some(route);
            Err(failure(plan, index, stage).into_op(message, keep))
        }
        Err(_) => Err(failure(plan, index, Stage::Handshake)
            .into_op("the peer did not answer the handshake in time", None)),
    }
}

enum OpenError {
    Refused(ConnectResult),
    Transport(String),
    /// The first hop, reached through the local daemon, failed before any
    /// channel: its stage, the words, and the route's own error when there
    /// is one.
    FirstHop(Stage, String, Option<OpError>),
}

/// Opens the `JUMP` stream and reads `ConnectResult`. The stream comes back
/// raw: after an `ok` result only length-prefixed packets follow.
async fn open_channel(
    outer: &Connection,
    header: &StreamHeader,
) -> Result<(ChanTx, ChanRx, Vec<u8>), OpenError> {
    let transport =
        |what: &str, e: &dyn std::fmt::Display| OpenError::Transport(format!("{what}: {e}"));
    let (send, recv) = outer
        .open_bi()
        .await
        .map_err(|e| transport("cannot open a jump channel", &e))?;
    let mut send = FramedSend::data(send);
    send.set_priority(PRIORITY_SESSION_DATA);
    send.send(header)
        .await
        .map_err(|e| transport("cannot send the jump request", &e))?;
    let mut recv = FramedRecv::data(recv);
    let result: ConnectResult = recv
        .recv()
        .await
        .map_err(|e| transport("cannot read the jump answer", &e))?
        .ok_or_else(|| OpenError::Transport("the jump channel closed without an answer".into()))?;
    if !result.ok {
        return Err(OpenError::Refused(result));
    }
    let (recv, residue) = recv.into_raw();
    Ok((send.into_raw().into(), recv.into(), residue))
}

/// The same exchange as [`open_channel`] for a first hop that registered
/// reverse on this machine: the `LOCAL_STREAM` conduit to the daemon stands
/// in for the connection, and the daemon opens the `JUMP` stream on the
/// registered connection (decision 14). The registration is checked against
/// the first hop's pin before the header leaves, and the answer is the
/// host's `ConnectResult`, verbatim, or the daemon's own refusal.
async fn open_channel_via_daemon(
    plan: &JumpPlan,
    header: &StreamHeader,
) -> Result<(ChanTx, ChanRx, Vec<u8>), OpenError> {
    use crate::localctl::client::{ExpectedPeer, StreamOpenError, open_stream_expecting};
    let route = plan
        .first_reverse
        .as_ref()
        .expect("a chain through the daemon has its route");
    let expect = ExpectedPeer {
        fingerprint: plan.step(0).fingerprint.to_string(),
        generation: None,
    };
    let mut handshake =
        match open_stream_expecting(&route.socket, &route.host, header, &expect).await {
            Ok(handshake) => handshake,
            Err(StreamOpenError::PeerChanged) => {
                return Err(OpenError::FirstHop(
                    Stage::Auth,
                    "the registered peer is not the one pinned for it".to_string(),
                    None,
                ));
            }
            Err(StreamOpenError::Op(op)) => {
                return Err(OpenError::FirstHop(
                    Stage::Dial,
                    op.message.clone(),
                    Some(op),
                ));
            }
        };
    let result: ConnectResult = match handshake.recv.recv().await {
        Ok(Some(result)) => result,
        Ok(None) => {
            return Err(OpenError::Transport(
                "the local daemon closed the jump channel without an answer".to_string(),
            ));
        }
        Err(op) => {
            return Err(OpenError::Transport(format!(
                "cannot read the jump answer: {}",
                op.message
            )));
        }
    };
    if !result.ok {
        return Err(OpenError::Refused(result));
    }
    let (recv, residue) = handshake.recv.into_raw();
    let send = handshake.send.into_raw();
    Ok((
        ChanTx::Raw(Box::new(send)),
        ChanRx::Raw(Box::new(recv)),
        residue,
    ))
}

// ----------------------------------------------------------------------
// the supervisor
// ----------------------------------------------------------------------

/// Keeps the layers alive for the end connection's life and ends them
/// together.
fn supervise(mut layers: Vec<Layer>, end: Connection, end_endpoint: Endpoint) {
    tokio::spawn(async move {
        let mut watch = JoinSet::new();
        for (index, layer) in layers.iter().enumerate() {
            let Some(conn) = layer.connection.clone() else {
                continue;
            };
            watch.spawn(async move {
                let reason = conn.closed().await;
                format!("connection {index} closed: {reason}")
            });
        }
        for (index, layer) in layers.iter_mut().enumerate() {
            if let Some(pump) = &mut layer.pump {
                let mut ended = pump.ended.clone();
                watch.spawn(async move {
                    loop {
                        if let Some(end) = *ended.borrow_and_update() {
                            return format!("pump {index} ended: {end:?}");
                        }
                        if ended.changed().await.is_err() {
                            return format!("pump {index} dropped");
                        }
                    }
                });
            }
        }
        let end_closed = {
            let end = end.clone();
            async move {
                let _ = end.closed().await;
            }
        };
        tokio::select! {
            () = end_closed => {}
            down = watch.join_next() => {
                // A layer under the end connection died: the chain is one
                // unit, so the end connection goes with it.
                tracing::debug!(
                    target: TARGET,
                    event = "layer_down",
                    why = down.and_then(Result::ok).unwrap_or_default(),
                );
                end.close(0, b"jump chain down");
            }
        }
        // The end connection's closing handshake leaves through the pumps,
        // so they stay up until it has.
        end_endpoint.wait_idle_for(END_DRAIN).await;
        teardown(layers).await;
    });
}

/// Closes the layers from the innermost out, stopping each pump after the
/// connection it carried has said goodbye.
async fn teardown(mut layers: Vec<Layer>) {
    while let Some(mut layer) = layers.pop() {
        if let Some(connection) = &layer.connection {
            connection.close(0, b"jump chain done");
        }
        if let Some(endpoint) = &layer.endpoint {
            endpoint.wait_idle_for(CLOSE_GRACE).await;
        }
        // The pump of the channel this layer carried has nothing left to
        // move.
        if let Some(pump) = &mut layer.pump {
            pump.stop();
            let _ = tokio::time::timeout(CLOSE_GRACE, &mut pump.task).await;
        }
        drop(layer.session.take());
    }
}
