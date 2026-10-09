//! Transport-neutral byte streams (`docs/adr/0028-tcp-tls-fallback.md`
//! decision 0).
//!
//! [`SendStream`] and [`RecvStream`] are what [`Connection::open_bi`] and
//! [`Connection::accept_bi`] hand out. Each is a closed enum over the
//! backends (today only QUIC), so a TCP backend lands as one more variant
//! without a generic parameter or a vtable on the splice hot path.
//!
//! The drop semantics are quinn's, and callers rely on them (the tunnel
//! splice guard, the denial teardown in `docs/design/protocol.md` §7):
//!
//! - dropping a [`SendStream`] that was neither finished nor reset is a
//!   clean [`finish`](SendStream::finish);
//! - dropping a [`RecvStream`] before end-of-stream is a
//!   [`stop`](RecvStream::stop) with code 0.
//!
//! [`Connection::open_bi`]: crate::Connection::open_bi
//! [`Connection::accept_bi`]: crate::Connection::accept_bi

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{
    ClosedStream, ReadError, ReadExactError, ReadToEndError, StoppedError, StreamCode, WriteError,
};
use crate::mux::{RecvHalf, SendHalf};
use crate::quic::{QuicRecv, QuicSend};

#[derive(Debug)]
enum SendBackend {
    Quic(QuicSend),
}

#[derive(Debug)]
enum RecvBackend {
    Quic(QuicRecv),
}

/// The sending half of a bidirectional stream.
#[derive(Debug)]
pub struct SendStream {
    inner: SendBackend,
}

impl SendStream {
    pub(crate) fn from_quic(stream: QuicSend) -> Self {
        Self {
            inner: SendBackend::Quic(stream),
        }
    }

    /// Write some of `buf`, returning how many bytes were accepted.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        match &mut self.inner {
            SendBackend::Quic(s) => s.write(buf).await,
        }
    }

    /// Write all of `buf`.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        match &mut self.inner {
            SendBackend::Quic(s) => s.write_all(buf).await,
        }
    }

    /// Signal end-of-stream to the peer (half-close). A second call errors
    /// with [`ClosedStream`].
    pub fn finish(&mut self) -> Result<(), ClosedStream> {
        match &mut self.inner {
            SendBackend::Quic(s) => s.finish(),
        }
    }

    /// Abruptly end the stream with an application code, discarding any data
    /// not yet delivered.
    pub fn reset(&mut self, code: StreamCode) -> Result<(), ClosedStream> {
        match &mut self.inner {
            SendBackend::Quic(s) => s.reset(code),
        }
    }

    /// Set the send priority hint (higher is sent first;
    /// `docs/design/protocol.md` §12).
    pub fn set_priority(&self, priority: i32) -> Result<(), ClosedStream> {
        match &self.inner {
            SendBackend::Quic(s) => s.set_priority(priority),
        }
    }

    /// The priority most recently set. `Err` only once the stream has
    /// closed.
    pub fn priority(&self) -> Result<i32, ClosedStream> {
        match &self.inner {
            SendBackend::Quic(s) => s.priority(),
        }
    }

    /// Resolves when the peer has acknowledged every byte written so far
    /// (`Ok(None)`), or stopped the stream (`Ok(Some(code))`). The future
    /// owns what it needs, so it may outlive the borrow of `self`.
    pub fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<StreamCode>, StoppedError>> + Send + Sync + 'static
    {
        match &self.inner {
            SendBackend::Quic(s) => s.stopped(),
        }
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            SendBackend::Quic(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            SendBackend::Quic(s) => AsyncWrite::poll_flush(Pin::new(s), cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            SendBackend::Quic(s) => AsyncWrite::poll_shutdown(Pin::new(s), cx),
        }
    }
}

/// The receiving half of a bidirectional stream.
#[derive(Debug)]
pub struct RecvStream {
    inner: RecvBackend,
}

impl RecvStream {
    pub(crate) fn from_quic(stream: QuicRecv) -> Self {
        Self {
            inner: RecvBackend::Quic(stream),
        }
    }

    /// Read contiguous data into `buf`. `Ok(None)` is a clean end-of-stream.
    /// Cancel-safe.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        match &mut self.inner {
            RecvBackend::Quic(s) => s.read(buf).await,
        }
    }

    /// Fill `buf` exactly. Not cancel-safe.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadExactError> {
        match &mut self.inner {
            RecvBackend::Quic(s) => s.read_exact(buf).await,
        }
    }

    /// Read to end-of-stream, failing with [`ReadToEndError::TooLong`] past
    /// `size_limit` bytes. Not cancel-safe.
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>, ReadToEndError> {
        match &mut self.inner {
            RecvBackend::Quic(s) => s.read_to_end(size_limit).await,
        }
    }

    /// Stop accepting data: discard what is unread and tell the peer to stop
    /// sending.
    pub fn stop(&mut self, code: StreamCode) -> Result<(), ClosedStream> {
        match &mut self.inner {
            RecvBackend::Quic(s) => s.stop(code),
        }
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            RecvBackend::Quic(s) => AsyncRead::poll_read(Pin::new(s), cx, buf),
        }
    }
}
