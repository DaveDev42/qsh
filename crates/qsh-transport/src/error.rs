//! Transport-neutral error and code types.
//!
//! `qsh-transport`'s public surface names no quinn type
//! (`docs/adr/0043-no-tcp-fallback.md` decision 3): the errors a caller can
//! match are owned here, and each backend converts its own errors into them
//! inside its module (`quinn_backend::error` for the QUIC backend,
//! ADR-0061 decision 7). This module names no backend's error type.
//!
//! Two properties are load-bearing:
//!
//! - **`Display` is byte-identical to quinn's.** The strings flow into CLI
//!   messages (`connection lost: {err}`, `handshake failed: {err}`), so the
//!   `display_matches_quinn_*` tests (in `quinn_backend::error`) pin every variant against quinn's own
//!   rendering.
//! - **Variant names mirror quinn's** where a caller already matches them
//!   (`ConnectionError::{ApplicationClosed, LocallyClosed, TimedOut, Reset}`,
//!   `ReadError::{Reset, ConnectionLost}`, `WriteError::{Stopped,
//!   ConnectionLost}`), so moving a match to this module is a path change.
//!
//! What the callers classify on is exposed as methods
//! ([`ConnectionError::is_crypto_failure`] and friends) rather than as the
//! QUIC transport-error code arithmetic they used to repeat.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

/// An application-defined stream or connection error code (a stream reset,
/// a stop-sending, a connection close).
///
/// Every code this repository sends is a `u32` (`RESET_CODE_*`,
/// `CLOSE_CODE_*`), but a peer can put any value on the wire, so the type
/// holds the full 62-bit range a QUIC varint can carry and
/// [`from_u32`](Self::from_u32) is the only constructor callers need.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamCode(u64);

impl StreamCode {
    /// The code for a `u32` application constant.
    pub const fn from_u32(code: u32) -> Self {
        Self(code as u64)
    }

    /// The code for a raw QUIC varint value a backend received.
    pub(crate) const fn from_raw(code: u64) -> Self {
        Self(code)
    }

    /// The code as a `u64` (a peer-sent code can exceed `u32::MAX`).
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// The code as a `u32`, `None` if a peer sent something larger.
    pub fn as_u32(self) -> Option<u32> {
        u32::try_from(self.0).ok()
    }

    /// A code from a raw wire value (a backend building one from its own
    /// error types; callers use [`from_u32`](Self::from_u32)).
    pub(crate) const fn from_u64(code: u64) -> Self {
        Self(code)
    }
}

impl From<u32> for StreamCode {
    fn from(code: u32) -> Self {
        Self::from_u32(code)
    }
}

impl From<StreamCode> for u64 {
    fn from(code: StreamCode) -> Self {
        code.0
    }
}

/// Renders as the bare decimal number, like quinn's `VarInt`.
impl fmt::Display for StreamCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The peer's explicit `close(code, reason)` (QUIC `APPLICATION_CLOSE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationClose {
    /// Application-specific reason code.
    pub error_code: StreamCode,
    /// Human-readable reason for the close.
    pub reason: Bytes,
}

impl fmt::Display for ApplicationClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reason.is_empty() {
            self.error_code.fmt(f)
        } else {
            f.write_str(&String::from_utf8_lossy(&self.reason))?;
            f.write_str(" (code ")?;
            self.error_code.fmt(f)?;
            f.write_str(")")
        }
    }
}

/// Why a connection ended or never came up.
///
/// The classification the rest of the workspace needs is on the methods
/// ([`is_crypto_failure`](Self::is_crypto_failure),
/// [`is_refused`](Self::is_refused),
/// [`is_idle_timeout`](Self::is_idle_timeout),
/// [`is_peer_reset`](Self::is_peer_reset),
/// [`application_code`](Self::application_code)). The variants that carry
/// `text` hold the transport's own rendering so [`Display`](fmt::Display)
/// stays identical to what the QUIC stack printed before this type existed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionError {
    /// The peer does not implement a version this side supports.
    VersionMismatch,
    /// The peer closed the connection with an application code.
    ApplicationClosed(ApplicationClose),
    /// The peer is unable to continue the connection, usually after a
    /// restart (QUIC stateless reset).
    Reset,
    /// Communication lapsed for longer than the idle timeout.
    TimedOut,
    /// This side closed the connection.
    LocallyClosed,
    /// The connection could not be created: not enough connection-id space.
    CidsExhausted,
    /// The handshake failed with a TLS alert (QUIC transport code
    /// `0x100..=0x1ff`).
    Crypto {
        /// The TLS alert number.
        alert: u8,
        /// The transport's rendering of the failure.
        text: Arc<str>,
    },
    /// The peer's admission gate refused the attempt outright (QUIC
    /// `CONNECTION_CLOSE(CONNECTION_REFUSED)`).
    Refused {
        /// The transport's rendering of the failure.
        text: Arc<str>,
    },
    /// A dial had nowhere to go: no relay (disabled) and no direct address.
    /// Typed so the relay diagnostic does not classify by message text.
    NoRoute,
    /// Any other transport-level failure.
    Other(Arc<str>),
}

impl ConnectionError {
    /// A peer-reported TLS alert failure with no reason phrase, rendered the
    /// way the QUIC stack renders a received `CONNECTION_CLOSE` carrying that
    /// alert.
    pub fn crypto(alert: u8) -> Self {
        Self::Crypto {
            alert,
            text: format!("aborted by peer: the cryptographic handshake failed: error {alert}")
                .into(),
        }
    }

    /// The handshake was aborted with a TLS alert (by the peer or by us).
    pub fn is_crypto_failure(&self) -> bool {
        matches!(self, Self::Crypto { .. })
    }

    /// The dial had no route at all: the relay is disabled and the peer has
    /// no direct address, so nothing was attempted.
    pub fn is_no_route(&self) -> bool {
        matches!(self, Self::NoRoute)
    }

    /// The peer refused the attempt outright (`CONNECTION_REFUSED`), as
    /// `Incoming::refuse` produces on the far end. Deliberately narrower
    /// than a crypto failure: the two never overlap.
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }

    /// The connection died of the idle timeout, not of anything either side
    /// said.
    pub fn is_idle_timeout(&self) -> bool {
        matches!(self, Self::TimedOut)
    }

    /// The peer dropped a connection it no longer holds (a stateless
    /// reset).
    pub fn is_peer_reset(&self) -> bool {
        matches!(self, Self::Reset)
    }

    /// The peer closed the connection explicitly, with any application code
    /// (including one past `u32`, which [`application_code`](Self::application_code)
    /// cannot represent).
    pub fn is_application_closed(&self) -> bool {
        matches!(self, Self::ApplicationClosed(_))
    }

    /// The application code of the peer's explicit close, if that is how the
    /// connection ended. Codes past `u32` (only a foreign peer sends them)
    /// read as `None`.
    pub fn application_code(&self) -> Option<u32> {
        match self {
            Self::ApplicationClosed(close) => close.error_code.as_u32(),
            _ => None,
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch => f.write_str("peer doesn't implement any supported version"),
            Self::ApplicationClosed(close) => write!(f, "closed by peer: {close}"),
            Self::Reset => f.write_str("reset by peer"),
            Self::TimedOut => f.write_str("timed out"),
            Self::LocallyClosed => f.write_str("closed"),
            Self::CidsExhausted => f.write_str("CIDs exhausted"),
            Self::NoRoute => {
                f.write_str("no route to the peer: relay disabled and no direct address")
            }
            Self::Crypto { text, .. } | Self::Refused { text } | Self::Other(text) => {
                f.write_str(text)
            }
        }
    }
}

impl std::error::Error for ConnectionError {}

/// The same `io::ErrorKind` mapping quinn applies to its connection error.
impl From<ConnectionError> for std::io::Error {
    fn from(err: ConnectionError) -> Self {
        use std::io::ErrorKind;
        let kind = match &err {
            ConnectionError::TimedOut => ErrorKind::TimedOut,
            ConnectionError::Reset => ErrorKind::ConnectionReset,
            ConnectionError::ApplicationClosed(_)
            | ConnectionError::Crypto { .. }
            | ConnectionError::Refused { .. } => ErrorKind::ConnectionAborted,
            // quinn maps a peer `ConnectionClosed` to `ConnectionAborted` and a
            // locally detected `TransportError` to `Other`; both land in
            // `Other` here, which no caller distinguishes.
            _ => ErrorKind::Other,
        };
        Self::new(kind, err)
    }
}

/// A stream operation on a stream that is already finished, reset, stopped
/// or was never open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Error)]
#[error("closed stream")]
pub struct ClosedStream;

/// A failed read from a stream.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ReadError {
    /// The peer abandoned transmitting data on this stream.
    #[error("stream reset by peer: error {0}")]
    Reset(StreamCode),
    /// The connection was lost.
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream has already been stopped, finished, or reset.
    #[error("closed stream")]
    ClosedStream,
    /// An ordered read followed an unordered read.
    #[error("ordered read after unordered read")]
    IllegalOrderedRead,
    /// A 0-RTT stream the server rejected (qsh never opens one).
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

/// The same `io::ErrorKind` mapping quinn applies, so an `io::Error` built
/// from a stream failure classifies identically before and after the
/// neutral types.
impl From<ReadError> for std::io::Error {
    fn from(err: ReadError) -> Self {
        use std::io::ErrorKind;
        let kind = match &err {
            ReadError::Reset(_) | ReadError::ZeroRttRejected => ErrorKind::ConnectionReset,
            ReadError::ConnectionLost(_) | ReadError::ClosedStream => ErrorKind::NotConnected,
            ReadError::IllegalOrderedRead => ErrorKind::InvalidInput,
        };
        Self::new(kind, err)
    }
}

/// A failed [`RecvStream::read_exact`](crate::RecvStream::read_exact).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ReadExactError {
    /// The stream finished before all bytes were read.
    #[error("stream finished early ({0} bytes read)")]
    FinishedEarly(usize),
    /// A read error occurred.
    #[error(transparent)]
    ReadError(#[from] ReadError),
}

/// A failed [`RecvStream::read_to_end`](crate::RecvStream::read_to_end).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ReadToEndError {
    /// An error occurred during reading.
    #[error("read error: {0}")]
    Read(#[from] ReadError),
    /// The stream is larger than the caller-supplied limit.
    #[error("stream too long")]
    TooLong,
}

/// A failed write to a stream.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum WriteError {
    /// The peer is no longer accepting data on this stream.
    #[error("sending stopped by peer: error {0}")]
    Stopped(StreamCode),
    /// The connection was lost.
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// The stream has already been finished or reset.
    #[error("closed stream")]
    ClosedStream,
    /// A 0-RTT stream the server rejected (qsh never opens one).
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

impl From<ClosedStream> for WriteError {
    fn from(_: ClosedStream) -> Self {
        Self::ClosedStream
    }
}

/// The same `io::ErrorKind` mapping quinn applies (see
/// [`ReadError`]'s conversion).
impl From<WriteError> for std::io::Error {
    fn from(err: WriteError) -> Self {
        use std::io::ErrorKind;
        let kind = match &err {
            WriteError::Stopped(_) | WriteError::ZeroRttRejected => ErrorKind::ConnectionReset,
            WriteError::ConnectionLost(_) | WriteError::ClosedStream => ErrorKind::NotConnected,
        };
        Self::new(kind, err)
    }
}

/// A failure while waiting for the peer to stop a send stream.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum StoppedError {
    /// The connection was lost.
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// A 0-RTT stream the server rejected (qsh never opens one).
    #[error("0-RTT rejected")]
    ZeroRttRejected,
}

/// A dial that failed before any packet was sent.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ConnectError {
    /// The endpoint can no longer create new connections.
    #[error("endpoint stopping")]
    EndpointStopping,
    /// Not enough connection-id space is available.
    #[error("CIDs exhausted")]
    CidsExhausted,
    /// The given server name was malformed.
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
    /// The remote address was unusable (port 0, wrong address family).
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(SocketAddr),
    /// No default client configuration was set up.
    #[error("no default client config")]
    NoDefaultClientConfig,
    /// The local endpoint does not support the version the client
    /// configuration asks for.
    #[error("unsupported QUIC version")]
    UnsupportedVersion,
}

/// The TLS keying-material exporter refused the request (the requested
/// output was too long).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("keying material export failed")]
pub struct ExportError;

/// A failed datagram send (`Connection::send_datagram`).
///
/// Datagrams are an optional carrier (`docs/adr/0052-m22-screen-state-sync-and-adaptive-transport.md`
/// decision 7): every caller must have a stream path for the same message, so
/// the first three variants are "use the stream instead", not failures of the
/// session.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DatagramError {
    /// The peer did not advertise datagram support.
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled on this side.
    #[error("datagram support disabled")]
    Disabled,
    /// The payload exceeds `Connection::max_datagram_size` (path MTU minus
    /// overhead, or the peer's advertised limit).
    #[error("datagram too large")]
    TooLarge,
    /// The connection was lost.
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
}
