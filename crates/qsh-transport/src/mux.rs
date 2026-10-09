//! The contract every transport backend implements
//! (`docs/adr/0028-tcp-tls-fallback.md` decision 0).
//!
//! [`Connection`](crate::Connection), [`SendStream`](crate::SendStream) and
//! [`RecvStream`](crate::RecvStream) are closed enums over the backends, and
//! each enum's variant payload implements one of the traits below. The
//! traits are private on purpose: they exist so that adding a backend with a
//! missing method fails to compile, and so that `tests/conformance.rs` has
//! one behavior list to hold every backend to. They are not a seam for
//! mocking a transport (`docs/design/testing.md` L4), and no `dyn` or
//! generic parameter reaches `qsh-core`: dispatch is a `match` over a
//! closed set, which keeps the splice hot path free of a vtable.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::endpoint::ConnStats;
use crate::error::{
    ClosedStream, ConnectionError, ExportError, ReadError, ReadExactError, ReadToEndError,
    StoppedError, StreamCode, WriteError,
};

/// Which transport a connection runs over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// QUIC over UDP.
    Quic,
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quic => f.write_str("quic"),
        }
    }
}

/// What a transport can and cannot do, for callers that degrade rather than
/// fail (`docs/design/protocol.md` §12 priorities, connection migration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCaps {
    /// The connection survives a change of the local path (QUIC connection
    /// migration, `Endpoint::rebind_ephemeral`).
    pub migration: bool,
    /// [`SendStream::set_priority`](crate::SendStream::set_priority) changes
    /// what is sent first.
    pub send_priority: bool,
    /// The listener can validate a peer's source address before spending
    /// handshake state on it (QUIC Retry).
    pub retry_validation: bool,
    /// A restarted peer can tell us it lost the connection without a full
    /// timeout (QUIC stateless reset).
    pub stateless_reset: bool,
}

/// A bidirectional-stream connection.
///
/// `open_bi`/`accept_bi` are cancel-safe: a dropped future opens or accepts
/// nothing, and `accept_bi` is used inside `tokio::select!` by the server
/// loop, the remote-forward acceptor and the registration loop.
pub(crate) trait MuxConn: Clone + Send + Sync + 'static {
    type Send: SendHalf;
    type Recv: RecvHalf;

    fn kind(&self) -> TransportKind;
    fn caps(&self) -> TransportCaps;

    /// Open a stream, waiting for a slot while the peer's concurrent-stream
    /// limit (`MAX_CONCURRENT_BIDI_STREAMS`) is reached.
    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::Send, Self::Recv), ConnectionError>> + Send;
    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::Send, Self::Recv), ConnectionError>> + Send;

    /// Idempotent.
    fn close(&self, code: u32, reason: &[u8]);
    /// Resolves for a local close and for a peer close alike.
    fn closed(&self) -> impl Future<Output = ConnectionError> + Send;
    fn close_reason(&self) -> Option<ConnectionError>;

    fn remote_address(&self) -> SocketAddr;
    fn stats(&self) -> ConnStats;
    /// RFC 5705 exporter over the connection's TLS session
    /// (`docs/design/protocol.md` §15).
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportError>;
}

/// The sending half of a stream. Dropping one that was neither finished nor
/// reset is a clean [`finish`](Self::finish) (the tunnel splice guard relies
/// on it).
pub(crate) trait SendHalf: AsyncWrite + Unpin + Send {
    fn write(&mut self, buf: &[u8]) -> impl Future<Output = Result<usize, WriteError>> + Send;
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), WriteError>> + Send;
    /// Half-close. A second call is [`ClosedStream`].
    fn finish(&mut self) -> Result<(), ClosedStream>;
    /// Discard unsent data and tell the peer why.
    fn reset(&mut self, code: StreamCode) -> Result<(), ClosedStream>;
    /// Higher is sent first (`docs/design/protocol.md` §12).
    fn set_priority(&self, priority: i32) -> Result<(), ClosedStream>;
    fn priority(&self) -> Result<i32, ClosedStream>;
    /// The future owns what it needs, so it outlives the borrow of `self`.
    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<StreamCode>, StoppedError>> + Send + Sync + 'static;
}

/// The receiving half of a stream. Dropping one before end-of-stream is a
/// [`stop`](Self::stop) with code 0.
pub(crate) trait RecvHalf: AsyncRead + Unpin + Send {
    /// `Ok(None)` is a clean end-of-stream. Cancel-safe.
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, ReadError>> + Send;
    fn read_exact(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(), ReadExactError>> + Send;
    fn read_to_end(
        &mut self,
        size_limit: usize,
    ) -> impl Future<Output = Result<Vec<u8>, ReadToEndError>> + Send;
    /// Discard what is unread and tell the peer to stop sending.
    fn stop(&mut self, code: StreamCode) -> Result<(), ClosedStream>;
}
