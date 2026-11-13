//! The iroh backend: [`MuxConn`], [`SendHalf`] and [`RecvHalf`] over an iroh
//! connection (noq underneath, a quinn fork).
//!
//! Streams are QUIC streams, so the stream halves are thin wrappers like the
//! QUIC backend's. What differs is the connection: it may run over a direct
//! UDP path, a relay path or both (multipath), and its peer is a bare
//! Ed25519 key, not a certificate.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use iroh::TransportAddr;
use iroh::endpoint as ie;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::endpoint::EndpointHandle;
use super::errors::{
    closed_stream, code_of, conn_err, datagram_err, export_err, read_err, read_exact_err,
    read_to_end_err, stopped_err, varint_of, write_err,
};
use super::key::fingerprint_of_key;
use crate::endpoint::ConnStats;
use crate::error::{
    ClosedStream, ConnectionError, DatagramError, ExportError, ReadError, ReadExactError,
    ReadToEndError, StoppedError, StreamCode, WriteError,
};
use crate::identity::Fingerprint;
use crate::mux::{MuxConn, RecvHalf, SendHalf, TransportCaps, TransportKind};
use crate::peer_addr::{PeerAddr, PeerKey, PeerPath};

/// An iroh connection plus what the transport-neutral wrapper needs.
///
/// A cheap handle: iroh's connection carries its path-tracking state inline,
/// and holding it by value would inflate every
/// [`Connection`](crate::Connection) (and the `qsh-core` types that hold one,
/// which sit close to clippy's size lints) even when it runs over QUIC.
#[derive(Clone, Debug)]
pub(crate) struct IrohConn {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    conn: ie::Connection,
    /// Keeps the endpoint (its sockets and relay connection) alive for as
    /// long as any clone of the connection is, like a QUIC `Dialed` keeps
    /// its endpoint, and closes it gracefully when the last one goes.
    endpoint: Arc<EndpointHandle>,
    /// The peer's qsh fingerprint, computed from its identity key.
    peer: Fingerprint,
    /// The peer's qsh identity key. For a server it is its endpoint id; for
    /// a client it is the key proven in-band, not the random endpoint id.
    key: PeerKey,
    /// The smallest round trip seen on the current kind of path (noq keeps
    /// no minimum of its own). See [`MinRtt`].
    min_rtt: Mutex<MinRtt>,
}

/// A running minimum of the sampled round trip, reset whenever the selected
/// path switches between direct and relay: the floor of a 15 ms direct path
/// says nothing about a 250 ms relay path, and the bulk governor reads
/// `srtt - min_rtt` as queueing delay, so a stale floor would read a
/// relay-path switch as a standing queue.
#[derive(Debug, Default)]
struct MinRtt {
    relay: bool,
    min: Option<Duration>,
}

impl MinRtt {
    fn observe(&mut self, relay: bool, rtt: Duration) -> Duration {
        if self.relay != relay {
            *self = Self { relay, min: None };
        }
        if !rtt.is_zero() {
            self.min = Some(self.min.map_or(rtt, |m| m.min(rtt)));
        }
        self.min.unwrap_or(Duration::ZERO)
    }
}

impl IrohConn {
    pub(crate) fn new(
        conn: ie::Connection,
        endpoint: Arc<EndpointHandle>,
        peer_key: [u8; 32],
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                conn,
                endpoint,
                peer: fingerprint_of_key(&peer_key),
                key: PeerKey(peer_key),
                min_rtt: Mutex::new(MinRtt::default()),
            }),
        }
    }

    /// The peer's qsh fingerprint.
    pub(crate) fn peer(&self) -> Fingerprint {
        self.shared.peer
    }

    fn conn(&self) -> &ie::Connection {
        &self.shared.conn
    }

    /// Whether the selected path is a relay path (or none is selected yet).
    #[allow(dead_code)] // Read by the route layer in a later step.
    pub(crate) fn on_relay(&self) -> bool {
        !self
            .conn()
            .paths()
            .iter()
            .any(|p| p.is_selected() && p.is_ip())
    }
}

/// The path the connection uses now: the selected one, else any path it
/// still has (a path is selected as soon as data flows, so the fallback only
/// covers the instant around a switch). A connection with no path at all is
/// closing and reports an empty relay URL.
fn current_path(conn: &ie::Connection) -> PeerPath {
    let paths = conn.paths();
    let path = paths
        .iter()
        .find(|p| p.is_selected())
        .or_else(|| paths.iter().next());
    match path.map(|p| p.remote_addr().clone()) {
        Some(TransportAddr::Ip(addr)) => PeerPath::Direct(addr),
        Some(TransportAddr::Relay(url)) => PeerPath::Relay(url.to_string()),
        _ => PeerPath::Relay(String::new()),
    }
}

#[derive(Debug)]
pub(crate) struct IrohSend(pub(crate) ie::SendStream);

#[derive(Debug)]
pub(crate) struct IrohRecv(pub(crate) ie::RecvStream);

impl MuxConn for IrohConn {
    type Send = IrohSend;
    type Recv = IrohRecv;

    fn kind(&self) -> TransportKind {
        TransportKind::Iroh
    }

    fn caps(&self) -> TransportCaps {
        TransportCaps {
            // Multipath moves a connection between direct and relay paths
            // without a new handshake.
            migration: true,
            send_priority: true,
            // iroh exposes no pre-handshake `Incoming` control to the
            // caller's admission gate that matches the QUIC listener's
            // (ADR-0061 decision 4: admission is judged after the handshake).
            retry_validation: false,
            stateless_reset: false,
        }
    }

    async fn open_bi(&self) -> Result<(IrohSend, IrohRecv), ConnectionError> {
        let (send, recv) = self.conn().open_bi().await.map_err(conn_err)?;
        Ok((IrohSend(send), IrohRecv(recv)))
    }

    async fn accept_bi(&self) -> Result<(IrohSend, IrohRecv), ConnectionError> {
        let (send, recv) = self.conn().accept_bi().await.map_err(conn_err)?;
        Ok((IrohSend(send), IrohRecv(recv)))
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.conn().close(ie::VarInt::from_u32(code), reason);
        self.shared.endpoint.note_closed(self.conn());
    }

    async fn closed(&self) -> ConnectionError {
        conn_err(self.conn().closed().await)
    }

    fn close_reason(&self) -> Option<ConnectionError> {
        self.conn().close_reason().map(conn_err)
    }

    fn remote_address(&self) -> PeerAddr {
        PeerAddr::Keyed {
            key: self.shared.key,
            path: current_path(&self.shared.conn),
        }
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn().max_datagram_size()
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), DatagramError> {
        self.conn().send_datagram(data).map_err(datagram_err)
    }

    async fn read_datagram(&self) -> Result<Bytes, ConnectionError> {
        self.conn().read_datagram().await.map_err(conn_err)
    }

    fn stats(&self) -> ConnStats {
        let total = self.conn().stats();
        let paths = self.conn().paths();
        // Per-path numbers (rtt, cwnd, mtu) come from the path data is sent
        // on; the counters are connection-wide sums.
        let selected = paths.iter().find(|p| p.is_selected());
        let on_relay = !selected.as_ref().is_some_and(|p| p.is_ip());
        let selected = selected.map(|p| p.stats());
        let (rtt, cwnd, congestion_events, mtu) = selected
            .map(|s| (s.rtt, s.cwnd, s.congestion_events, s.current_mtu))
            .unwrap_or((Duration::ZERO, 0, 0, 0));
        // noq keeps no per-path minimum, so one is kept here from the samples
        // `stats()` is polled with; zero is the documented "no sample" value.
        let min_rtt = self
            .shared
            .min_rtt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .observe(on_relay, rtt);
        ConnStats {
            rtt,
            min_rtt,
            cwnd,
            congestion_events,
            lost_bytes: total.lost_bytes,
            sent_packets: total.sent_packets,
            path_mtu: mtu,
            tx_datagram_frames: total.frame_tx.datagram,
            rx_datagram_frames: total.frame_rx.datagram,
            rx_frames: fold_frames_rx(&total.frame_rx),
            peer_blocked_events: total.frame_rx.data_blocked,
            peer_stream_blocked_events: total.frame_rx.stream_data_blocked,
            rx_raw_datagrams: Some(total.udp_rx.datagrams),
            lost_packets: Some(total.lost_packets),
        }
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportError> {
        self.conn()
            .export_keying_material(output, label, context)
            .map_err(export_err)
    }
}

impl SendHalf for IrohSend {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        self.0.write(buf).await.map_err(write_err)
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        self.0.write_all(buf).await.map_err(write_err)
    }

    fn finish(&mut self) -> Result<(), ClosedStream> {
        self.0.finish().map_err(closed_stream)
    }

    fn reset(&mut self, code: StreamCode) -> Result<(), ClosedStream> {
        self.0.reset(varint_of(code)).map_err(closed_stream)
    }

    fn set_priority(&self, priority: i32) -> Result<(), ClosedStream> {
        self.0.set_priority(priority).map_err(closed_stream)
    }

    fn priority(&self) -> Result<i32, ClosedStream> {
        self.0.priority().map_err(closed_stream)
    }

    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<StreamCode>, StoppedError>> + Send + Sync + 'static
    {
        let fut = self.0.stopped();
        async move { fut.await.map(|code| code.map(code_of)).map_err(stopped_err) }
    }
}

impl RecvHalf for IrohRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        self.0.read(buf).await.map_err(read_err)
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        self.0.read_exact(buf).await.map_err(read_exact_err)
    }

    async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        self.0
            .read_to_end(size_limit)
            .await
            .map_err(read_to_end_err)
    }

    fn stop(&mut self, code: StreamCode) -> Result<(), ClosedStream> {
        self.0.stop(varint_of(code)).map_err(closed_stream)
    }
}

impl AsyncWrite for IrohSend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

impl AsyncRead for IrohRecv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

/// Sum of every received frame counter noq keeps. `FrameStats` is
/// `#[non_exhaustive]`, so a frame type a future noq adds is not caught by
/// the compiler: re-check this list on an iroh upgrade. The conformance
/// suite pins that ordinary stream traffic moves the sum.
fn fold_frames_rx(f: &ie::FrameStats) -> u64 {
    [
        f.acks,
        f.path_acks,
        f.ack_frequency,
        f.crypto,
        f.connection_close,
        f.data_blocked,
        f.datagram,
        u64::from(f.handshake_done),
        f.immediate_ack,
        f.max_data,
        f.max_stream_data,
        f.max_streams_bidi,
        f.max_streams_uni,
        f.new_connection_id,
        f.path_new_connection_id,
        f.new_token,
        f.path_challenge,
        f.path_response,
        f.ping,
        f.reset_stream,
        f.retire_connection_id,
        f.path_retire_connection_id,
        f.stream_data_blocked,
        f.streams_blocked_bidi,
        f.streams_blocked_uni,
        f.stop_sending,
        f.stream,
        f.observed_addr,
        f.path_abandon,
        f.path_status_available,
        f.path_status_backup,
        f.max_path_id,
        f.paths_blocked,
        f.path_cids_blocked,
        f.add_address,
        f.reach_out,
        f.remove_address,
    ]
    .into_iter()
    .fold(0u64, u64::saturating_add)
}
