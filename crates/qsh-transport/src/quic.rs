//! The QUIC backend: [`MuxConn`], [`SendHalf`] and [`RecvHalf`] over quinn.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::endpoint::ConnStats;
use crate::error::{
    ClosedStream, ConnectionError, ExportError, ReadError, ReadExactError, ReadToEndError,
    StoppedError, StreamCode, WriteError,
};
use crate::mux::{MuxConn, RecvHalf, SendHalf, TransportCaps, TransportKind};

/// A quinn connection.
#[derive(Clone, Debug)]
pub(crate) struct QuicConn(pub(crate) quinn::Connection);

#[derive(Debug)]
pub(crate) struct QuicSend(pub(crate) quinn::SendStream);

#[derive(Debug)]
pub(crate) struct QuicRecv(pub(crate) quinn::RecvStream);

impl MuxConn for QuicConn {
    type Send = QuicSend;
    type Recv = QuicRecv;

    fn kind(&self) -> TransportKind {
        TransportKind::Quic
    }

    fn caps(&self) -> TransportCaps {
        TransportCaps {
            migration: true,
            send_priority: true,
            retry_validation: true,
            stateless_reset: true,
        }
    }

    async fn open_bi(&self) -> Result<(QuicSend, QuicRecv), ConnectionError> {
        let (send, recv) = self.0.open_bi().await?;
        Ok((QuicSend(send), QuicRecv(recv)))
    }

    async fn accept_bi(&self) -> Result<(QuicSend, QuicRecv), ConnectionError> {
        let (send, recv) = self.0.accept_bi().await?;
        Ok((QuicSend(send), QuicRecv(recv)))
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.0.close(quinn::VarInt::from_u32(code), reason);
    }

    async fn closed(&self) -> ConnectionError {
        self.0.closed().await.into()
    }

    fn close_reason(&self) -> Option<ConnectionError> {
        self.0.close_reason().map(ConnectionError::from)
    }

    fn remote_address(&self) -> SocketAddr {
        self.0.remote_address()
    }

    fn stats(&self) -> ConnStats {
        let stats = self.0.stats();
        ConnStats {
            rtt: stats.path.rtt,
            rx_frames: fold_frames_rx(&stats.frame_rx),
            peer_blocked_events: stats.frame_rx.data_blocked,
            peer_stream_blocked_events: stats.frame_rx.stream_data_blocked,
            rx_raw_datagrams: Some(stats.udp_rx.datagrams),
            lost_packets: Some(stats.path.lost_packets),
        }
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportError> {
        Ok(self.0.export_keying_material(output, label, context)?)
    }
}

impl SendHalf for QuicSend {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        Ok(self.0.write(buf).await?)
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        Ok(self.0.write_all(buf).await?)
    }

    fn finish(&mut self) -> Result<(), ClosedStream> {
        Ok(self.0.finish()?)
    }

    fn reset(&mut self, code: StreamCode) -> Result<(), ClosedStream> {
        Ok(self.0.reset(code.to_varint())?)
    }

    fn set_priority(&self, priority: i32) -> Result<(), ClosedStream> {
        Ok(self.0.set_priority(priority)?)
    }

    fn priority(&self) -> Result<i32, ClosedStream> {
        Ok(self.0.priority()?)
    }

    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<StreamCode>, StoppedError>> + Send + Sync + 'static
    {
        let fut = self.0.stopped();
        async move {
            fut.await
                .map(|code| code.map(StreamCode::from))
                .map_err(StoppedError::from)
        }
    }
}

impl RecvHalf for QuicRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        Ok(self.0.read(buf).await?)
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        Ok(self.0.read_exact(buf).await?)
    }

    async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        Ok(self.0.read_to_end(size_limit).await?)
    }

    fn stop(&mut self, code: StreamCode) -> Result<(), ClosedStream> {
        Ok(self.0.stop(code.to_varint())?)
    }
}

impl AsyncWrite for QuicSend {
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

impl AsyncRead for QuicRecv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

/// Sum of every received frame counter quinn keeps.
///
/// Every field is listed explicitly. `FrameStats` is `#[non_exhaustive]`, so
/// a frame type a future quinn adds is not caught by the compiler:
/// re-check this list on a quinn upgrade. The loopback test
/// `rx_frames_moves_on_authenticated_stream_frames` pins that ordinary
/// stream traffic moves the sum.
fn fold_frames_rx(f: &quinn::FrameStats) -> u64 {
    [
        f.acks,
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
        f.new_token,
        f.path_challenge,
        f.path_response,
        f.ping,
        f.reset_stream,
        f.retire_connection_id,
        f.stream_data_blocked,
        f.streams_blocked_bidi,
        f.streams_blocked_uni,
        f.stop_sending,
        f.stream,
    ]
    .into_iter()
    .fold(0u64, u64::saturating_add)
}
