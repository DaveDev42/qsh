//! The `qsh listen` daemon's carrier translation for a jump chain whose
//! first hop reached this machine by reverse registration (ADR-0056
//! decision 14, `docs/design/protocol.md` §21.7).
//!
//! The CLI cannot open a QUIC stream on a registered connection: the daemon
//! holds it. So the CLI asks over `LOCAL_STREAM` and the daemon opens the
//! `JUMP` stream on the registered connection, then [`run`] moves the inner
//! QUIC packets between the two legs:
//!
//! * **CLI leg.** The conduit is a local socket on this machine, lossless,
//!   so it always carries the stream framing (`u16` length and packet).
//! * **Registered leg.** Each packet toward the registered host takes the
//!   carrier [`choose_carrier`] and [`SilenceFallback`] pick from the
//!   registered connection's own view; packets from the host arrive as kind
//!   14 datagrams or on the `JUMP` stream and are written to the CLI leg as
//!   stream frames.
//!
//! The daemon reads nothing but the length prefix. It does not decrypt, and
//! it is no authorization point: the registered host decides `forward.jump`
//! (decision 7), exactly as an intermediate peer reached directly does. What
//! the daemon does bound is its own resources: [`MAX_JUMP_CHANNELS_PER_HUB`]
//! channels per registered host, a channel value claimed once, frames of
//! 1 to [`qsh_proto::jump::JUMP_PACKET_MAX`] bytes, [`JUMP_STREAM_QUEUE`] unsent bytes per
//! leg, and a datagram that does not fit is dropped and counted, never sent
//! on the stream instead (decision 4).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use qsh_proto::datagram::{ChannelId, DatagramFrame, DatagramKind};
use qsh_proto::jump::{JUMP_STREAM_QUEUE, JumpStreamDecoder, encode_packet};
use qsh_transport::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

use super::TARGET;
use super::carrier::{Carrier, DATAGRAM_HEADER, SilenceFallback, choose_carrier};
use super::middle::{ChanRx, ChanTx, StreamQueue, write_loop};
use crate::datagram::{DatagramHub, DatagramRx, SendFailure};

/// Jump channels the daemon carries at once for one registered host
/// (ADR-0056 decision 14).
pub const MAX_JUMP_CHANNELS_PER_HUB: usize = 32;

/// How long the daemon waits for the registered host's `ConnectResult`. The
/// host resolves the target name within 5 s (decision 7); the CLI's own dial
/// time is 10 s.
pub const JUMP_OPEN_TIMEOUT: Duration = Duration::from_secs(12);

/// Stream reset code for every abnormal end toward the registered host.
const RESET_CODE_ABORT: u32 = 0x2007;
/// Stream reset code for a framing violation (`BAD_HEADER`).
const RESET_CODE_BAD_FRAME: u32 = 0x2001;

/// Counters of the jump channels one registered host's hub has carried.
/// Counts only: nothing here can hold a packet, an address or a channel.
#[derive(Debug, Default)]
pub struct RelayStats {
    /// Channels that reached `ConnectResult{ok}`.
    pub opened: AtomicU64,
    /// Channels that ended.
    pub closed: AtomicU64,
    /// Packets sent to the registered host as datagrams.
    pub to_host_datagrams: AtomicU64,
    /// Packets sent to the registered host on the `JUMP` stream.
    pub to_host_stream: AtomicU64,
    /// Packets from the registered host that arrived as datagrams.
    pub from_host_datagrams: AtomicU64,
    /// Packets from the registered host that arrived on the stream.
    pub from_host_stream: AtomicU64,
    /// Packets written to the CLI leg.
    pub to_cli: AtomicU64,
    /// Datagrams that did not fit the registered connection's room.
    pub oversize_dropped: AtomicU64,
    /// Packets dropped because a leg's stream queue was full.
    pub queue_dropped: AtomicU64,
    /// Datagrams the registered connection would not take.
    pub datagram_unavailable: AtomicU64,
    /// Times the silence rule moved a channel to the stream.
    pub silence_fallbacks: AtomicU64,
}

/// Why a channel ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// The CLI closed its end of the conduit (or died).
    CliGone,
    /// The registered host finished or reset the `JUMP` stream.
    HostEnded,
    /// The registered connection closed.
    ConnectionClosed,
    /// The CLI sent a length prefix of 0 or over [`qsh_proto::jump::JUMP_PACKET_MAX`].
    BadFrameFromCli,
    /// The registered host sent one.
    BadFrameFromHost,
}

impl RelayEnd {
    /// The closed word logged for this end.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CliGone => "cli_gone",
            Self::HostEnded => "host_ended",
            Self::ConnectionClosed => "connection_closed",
            Self::BadFrameFromCli => "bad_frame_cli",
            Self::BadFrameFromHost => "bad_frame_host",
        }
    }
}

/// Everything [`run`] needs, handed over after the registered host answered
/// `ConnectResult{ok}`.
pub struct Relay {
    /// The registered connection.
    pub conn: Connection,
    /// The `JUMP` stream's send half on the registered connection.
    pub send: SendStream,
    /// The stream's receive half.
    pub recv: RecvStream,
    /// Bytes the host pipelined behind its `ConnectResult`.
    pub host_residue: Vec<u8>,
    /// The CLI leg's read half (raw phase).
    pub cli_read: Box<dyn AsyncRead + Send + Unpin>,
    /// Bytes the CLI sent that were read ahead of the raw phase.
    pub cli_residue: Vec<u8>,
    /// The CLI leg's write half (raw phase).
    pub cli_write: Box<dyn AsyncWrite + Send + Unpin>,
    /// Kind 14 datagrams for this channel from the registered connection.
    pub datagrams: DatagramRx,
    /// Whether the registered host advertises `datagram.v1` (this side
    /// always does).
    pub both_datagram: bool,
    /// The hub's counters.
    pub stats: Arc<RelayStats>,
}

struct State {
    hub: Arc<DatagramHub>,
    channel: ChannelId,
    both_datagram: bool,
    silence: SilenceFallback,
    host_queue: StreamQueue,
    cli_queue: StreamQueue,
    stats: Arc<RelayStats>,
}

impl State {
    /// A packet from the CLI, toward the registered host.
    fn send_to_host(&mut self, packet: Vec<u8>) -> Result<(), RelayEnd> {
        let room = self.hub.max_datagram_size();
        let rule = choose_carrier(self.both_datagram, room);
        let carrier = self
            .silence
            .choose(rule, std::time::Instant::now(), self.hub.rtt());
        match carrier {
            Carrier::Datagram => {
                if DATAGRAM_HEADER + packet.len() > room.unwrap_or(0) {
                    // Not sent on the stream instead: the inner PLPMTUD
                    // learns the room from the loss (decision 4).
                    self.stats.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                let frame = DatagramFrame {
                    channel: self.channel,
                    kind: DatagramKind::JumpPacket,
                    payload: packet,
                };
                match self.hub.send(&frame) {
                    Ok(()) => {
                        self.silence.sent_datagram(std::time::Instant::now());
                        self.stats.to_host_datagrams.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(SendFailure::Closed) => return Err(RelayEnd::ConnectionClosed),
                    Err(SendFailure::Unavailable) => {
                        self.stats
                            .datagram_unavailable
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Carrier::Stream => {
                let Some(frame) = encode_packet(&packet) else {
                    self.stats.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                };
                if self.host_queue.push(frame) {
                    self.stats.to_host_stream.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.queue_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }

    /// A packet from the registered host, toward the CLI.
    fn send_to_cli(&mut self, packet: &[u8]) {
        let Some(frame) = encode_packet(packet) else {
            self.stats.oversize_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if self.cli_queue.push(frame) {
            self.stats.to_cli.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.queue_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Runs one channel until it ends and returns why. The `JUMP` stream is
/// already past `ConnectResult{ok}` and the CLI has been given it.
pub async fn run(relay: Relay) -> RelayEnd {
    let Relay {
        conn,
        send,
        recv,
        host_residue,
        cli_read,
        cli_residue,
        cli_write,
        datagrams,
        both_datagram,
        stats,
    } = relay;
    let hub = Arc::clone(datagrams.hub());
    let channel = datagrams.channel();
    let mut datagrams = datagrams;
    let (host_queue, host_queue_rx) = StreamQueue::new(JUMP_STREAM_QUEUE);
    let (cli_queue, cli_queue_rx) = StreamQueue::new(JUMP_STREAM_QUEUE);
    let (host_close_tx, host_close_rx) = oneshot::channel();
    let (_cli_close_tx, cli_close_rx) = oneshot::channel();
    let mut host_writer =
        tokio::spawn(write_loop(ChanTx::Quic(send), host_queue_rx, host_close_rx));
    let mut cli_writer = tokio::spawn(write_loop(
        ChanTx::Raw(cli_write),
        cli_queue_rx,
        cli_close_rx,
    ));
    let mut host_writer_done = false;
    let mut cli_writer_done = false;
    let mut recv = ChanRx::Quic(recv);
    let mut cli_read = ChanRx::Raw(cli_read);
    let mut state = State {
        hub,
        channel,
        both_datagram,
        silence: SilenceFallback::new(),
        host_queue,
        cli_queue,
        stats: Arc::clone(&stats),
    };
    stats.opened.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(target: TARGET, event = "channel_opened", side = "daemon");

    let mut cli_decoder = JumpStreamDecoder::new();
    cli_decoder.push(&cli_residue);
    let mut host_decoder = JumpStreamDecoder::new();
    host_decoder.push(&host_residue);
    let mut cli_buf = vec![0u8; 16 * 1024];
    let mut host_buf = vec![0u8; 16 * 1024];

    let end = 'relay: loop {
        loop {
            match cli_decoder.next_packet() {
                Ok(Some(packet)) => {
                    if let Err(end) = state.send_to_host(packet) {
                        break 'relay end;
                    }
                }
                Ok(None) => break,
                Err(_) => break 'relay RelayEnd::BadFrameFromCli,
            }
        }
        loop {
            match host_decoder.next_packet() {
                Ok(Some(packet)) => {
                    stats.from_host_stream.fetch_add(1, Ordering::Relaxed);
                    state.send_to_cli(&packet);
                }
                Ok(None) => break,
                Err(_) => break 'relay RelayEnd::BadFrameFromHost,
            }
        }
        tokio::select! {
            read = cli_read.read(&mut cli_buf) => match read {
                Ok(Some(n)) => cli_decoder.push(&cli_buf[..n]),
                Ok(None) | Err(_) => break RelayEnd::CliGone,
            },
            read = recv.read(&mut host_buf) => match read {
                Ok(Some(n)) => host_decoder.push(&host_buf[..n]),
                Ok(None) | Err(_) => break RelayEnd::HostEnded,
            },
            frame = datagrams.recv() => match frame {
                Some(frame) if frame.kind == DatagramKind::JumpPacket => {
                    state.silence.received_datagram();
                    stats.from_host_datagrams.fetch_add(1, Ordering::Relaxed);
                    state.send_to_cli(&frame.payload);
                }
                Some(_) => {}
                None => break RelayEnd::ConnectionClosed,
            },
            _ = &mut host_writer => {
                host_writer_done = true;
                break RelayEnd::HostEnded;
            }
            _ = &mut cli_writer => {
                cli_writer_done = true;
                break RelayEnd::CliGone;
            }
            _ = conn.closed() => break RelayEnd::ConnectionClosed,
        }
    };

    if state.silence.fell_back() {
        stats.silence_fallbacks.fetch_add(1, Ordering::Relaxed);
    }
    // The registered host: a clean end finishes the stream, anything else
    // resets it so the host drops the channel at once.
    let (host_how, host_stop) = match end {
        RelayEnd::CliGone | RelayEnd::ConnectionClosed => (None, None),
        RelayEnd::BadFrameFromCli | RelayEnd::BadFrameFromHost => {
            (Some(RESET_CODE_BAD_FRAME), Some(RESET_CODE_BAD_FRAME))
        }
        RelayEnd::HostEnded => (Some(RESET_CODE_ABORT), None),
    };
    let _ = host_close_tx.send(host_how);
    recv.stop(host_stop.unwrap_or(RESET_CODE_ABORT));
    // The CLI: whatever is queued still goes out, then the leg half-closes
    // and the CLI reads an end of stream.
    let State {
        cli_queue,
        host_queue,
        ..
    } = state;
    drop(cli_queue);
    drop(host_queue);
    // `cli_close_tx` stays alive until the writer is done: dropping it would
    // end the writer before it drained the queue.
    if !cli_writer_done {
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut cli_writer).await;
        cli_writer.abort();
    }
    if !host_writer_done {
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut host_writer).await;
        host_writer.abort();
    }
    stats.closed.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        target: TARGET,
        event = "channel_closed",
        side = "daemon",
        reason = end.as_str(),
    );
    end
}
