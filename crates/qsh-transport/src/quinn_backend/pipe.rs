//! [`PacketPipe`]: an in-memory datagram socket for a QUIC endpoint, and the
//! [`Dialer::dial_over_pipe`](crate::endpoint::Dialer::dial_over_pipe) that runs a
//! client-only endpoint on it (ADR-0056 decisions 2, 4, 5 and 6; MTU numbers
//! from ADR-0057).
//!
//! A jump hop carries the packets of an *inner* QUIC connection inside an
//! *outer* one. The inner endpoint therefore has no UDP socket: it sends and
//! receives through a pair of bounded queues. [`PacketPipe::new`] makes both
//! ends. The [`PacketPipe`] goes to `dial_over_pipe` and becomes quinn's
//! socket; the [`PipePeer`] stays with the jump code, which moves each packet
//! it reads from [`PipePeer::recv`] onto the outer connection and hands each
//! packet that arrives from there to [`PipePeer::send`]. `PipePeer` names no
//! quinn type, so `qsh-core` can hold it.
//!
//! What the socket promises quinn, each of which the 2026-11-09 probe
//! (ADR-0056 revision history) found to be load-bearing:
//!
//! * `may_fragment()` is `false`. With `true` quinn switches PLPMTUD off and
//!   the inner connection stays at its initial MTU.
//! * `max_transmit_segments()` is 1: no GSO, one packet per `try_send`.
//! * A packet longer than the current limit (see [`PipePeer::set_packet_limit`])
//!   is dropped without an error, as a real link drops what exceeds its MTU.
//!   `try_send` returning `Ok` is what lets PLPMTUD learn the limit from the
//!   loss of its probes.
//! * Both queues are bounded. A full queue drops the new packet and counts
//!   it; nothing blocks, because a blocked inner endpoint would turn queueing
//!   into hidden delay that the inner congestion controller cannot see.
//!
//! Addresses: the pipe has no real peer, but quinn needs a [`SocketAddr`] for
//! the remote and for its own local side. They are the fixed documentation
//! addresses [`PIPE_REMOTE_ADDR`] (RFC 5737 `192.0.2.1:9`) and
//! [`PIPE_LOCAL_ADDR`] (`192.0.2.2:9`). Nothing is ever sent to them; they
//! only name the path inside quinn and show up in the inner connection's
//! `remote_address()`.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

/// Smallest packet a QUIC endpoint may send: the QUIC floor (ADR-0056
/// decision 5). The inner connection's `initial_mtu` and `min_mtu`.
pub const JUMP_PACKET_MIN: u16 = qsh_proto::jump::JUMP_PACKET_MIN as u16;

/// Largest packet the pipe carries: the PLPMTUD upper bound of the inner
/// connection (ADR-0056 decision 5) and the default packet limit.
/// Both constants are `qsh_proto::jump`'s, narrowed to quinn's `u16`.
pub const JUMP_PACKET_MAX: u16 = qsh_proto::jump::JUMP_PACKET_MAX as u16;

/// The remote address quinn sees for the pipe (RFC 5737 TEST-NET-1).
pub const PIPE_REMOTE_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);

/// The local address quinn sees for the pipe (RFC 5737 TEST-NET-1).
pub const PIPE_LOCAL_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 9);

/// Counters of one pipe, read through [`PipePeer::stats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeStats {
    /// Packets the inner endpoint sent that were queued for the peer.
    pub out_queued: u64,
    /// Outgoing packets dropped because the outgoing queue was full.
    pub out_dropped_full: u64,
    /// Outgoing packets dropped for being longer than the packet limit.
    pub out_dropped_oversize: u64,
    /// Packets handed to the inner endpoint through [`PipePeer::send`].
    pub in_queued: u64,
    /// Incoming packets dropped because the incoming queue was full or the
    /// inner endpoint is gone.
    pub in_dropped_full: u64,
    /// Incoming packets dropped for being longer than the packet limit.
    pub in_dropped_oversize: u64,
}

struct Shared {
    limit: AtomicUsize,
    out_queued: AtomicU64,
    out_dropped_full: AtomicU64,
    out_dropped_oversize: AtomicU64,
    in_queued: AtomicU64,
    in_dropped_full: AtomicU64,
    in_dropped_oversize: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The inner endpoint's side of a pipe. Pass it to
/// [`Dialer::dial_over_pipe`](crate::endpoint::Dialer::dial_over_pipe); it becomes the
/// endpoint's socket.
pub struct PacketPipe {
    socket: Arc<PipeSocket>,
}

impl std::fmt::Debug for PacketPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketPipe").finish_non_exhaustive()
    }
}

/// The jump code's side of a pipe: the packets the inner endpoint sends come
/// out of [`Self::recv`], and packets for it go in through [`Self::send`].
pub struct PipePeer {
    to_inner: mpsc::Sender<Vec<u8>>,
    from_inner: mpsc::Receiver<Vec<u8>>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for PipePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipePeer")
            .field("limit", &self.packet_limit())
            .finish_non_exhaustive()
    }
}

impl PacketPipe {
    /// Makes a pipe whose two queues hold `depth` packets each (at least 1).
    /// The packet limit starts at [`JUMP_PACKET_MAX`].
    pub fn new(depth: usize) -> (PacketPipe, PipePeer) {
        let depth = depth.max(1);
        let (to_inner, inner_rx) = mpsc::channel(depth);
        let (inner_tx, from_inner) = mpsc::channel(depth);
        let shared = Arc::new(Shared {
            limit: AtomicUsize::new(usize::from(JUMP_PACKET_MAX)),
            out_queued: AtomicU64::new(0),
            out_dropped_full: AtomicU64::new(0),
            out_dropped_oversize: AtomicU64::new(0),
            in_queued: AtomicU64::new(0),
            in_dropped_full: AtomicU64::new(0),
            in_dropped_oversize: AtomicU64::new(0),
        });
        let socket = Arc::new(PipeSocket {
            tx: inner_tx,
            rx: Mutex::new(inner_rx),
            shared: shared.clone(),
        });
        (
            PacketPipe { socket },
            PipePeer {
                to_inner,
                from_inner,
                shared,
            },
        )
    }

    pub(crate) fn into_socket(self) -> Arc<dyn AsyncUdpSocket> {
        self.socket
    }
}

impl PipePeer {
    /// The next packet the inner endpoint sent. `None` once the inner
    /// endpoint is gone and the queue is drained.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_inner.recv().await
    }

    /// The next packet already queued, without waiting; `None` when the
    /// queue is empty (or closed). Lets the pump drain a burst per wakeup.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.from_inner.try_recv().ok()
    }

    /// Hands `packet` to the inner endpoint. Returns `false` if it was
    /// dropped (queue full, longer than the limit, or the inner endpoint is
    /// gone); drops are counted in [`Self::stats`]. Never blocks.
    pub fn send(&self, packet: Vec<u8>) -> bool {
        if packet.len() > self.packet_limit() {
            self.shared
                .in_dropped_oversize
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        match self.to_inner.try_send(packet) {
            Ok(()) => {
                self.shared.in_queued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.shared.in_dropped_full.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// The longest packet the pipe carries in either direction.
    pub fn packet_limit(&self) -> usize {
        self.shared.limit.load(Ordering::Relaxed)
    }

    /// Sets the packet limit, which the carrier (the outer connection's
    /// datagram size, or [`JUMP_PACKET_MAX`] for the stream carrier) decides.
    /// Longer outgoing packets are dropped silently so PLPMTUD finds the limit
    /// by loss. Takes effect for the next packet.
    pub fn set_packet_limit(&self, limit: usize) {
        self.shared.limit.store(limit, Ordering::Relaxed);
    }

    /// The pipe's counters.
    pub fn stats(&self) -> PipeStats {
        let s = &self.shared;
        PipeStats {
            out_queued: s.out_queued.load(Ordering::Relaxed),
            out_dropped_full: s.out_dropped_full.load(Ordering::Relaxed),
            out_dropped_oversize: s.out_dropped_oversize.load(Ordering::Relaxed),
            in_queued: s.in_queued.load(Ordering::Relaxed),
            in_dropped_full: s.in_dropped_full.load(Ordering::Relaxed),
            in_dropped_oversize: s.in_dropped_oversize.load(Ordering::Relaxed),
        }
    }
}

/// The quinn socket. Never blocks: `try_send` drops what does not fit.
struct PipeSocket {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for PipeSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeSocket").finish_non_exhaustive()
    }
}

/// Always writable: `try_send` never returns `WouldBlock`.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for PipeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let s = &self.shared;
        if transmit.contents.len() > s.limit.load(Ordering::Relaxed) {
            s.out_dropped_oversize.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        match self.tx.try_send(transmit.contents.to_vec()) {
            Ok(()) => s.out_queued.fetch_add(1, Ordering::Relaxed),
            Err(_) => s.out_dropped_full.fetch_add(1, Ordering::Relaxed),
        };
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = lock(&self.rx);
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let packet = if n == 0 {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(p)) => p,
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match rx.try_recv() {
                    Ok(p) => p,
                    Err(_) => break,
                }
            };
            let len = packet.len().min(bufs[n].len());
            bufs[n][..len].copy_from_slice(&packet[..len]);
            meta[n] = RecvMeta {
                addr: PIPE_REMOTE_ADDR,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(PIPE_LOCAL_ADDR)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
