//! Transport-neutral error and code types.
//!
//! `qsh-transport`'s public surface names no quinn type
//! (`docs/adr/0043-no-tcp-fallback.md` decision 3): the errors a caller can
//! match are owned here, and the QUIC backend converts quinn's into them with
//! the `From` impls below.
//!
//! Two properties are load-bearing:
//!
//! - **`Display` is byte-identical to quinn's.** The strings flow into CLI
//!   messages (`connection lost: {err}`, `handshake failed: {err}`), so the
//!   `display_matches_quinn_*` tests pin every variant against quinn's own
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

/// Lowest QUIC transport error code that encodes a TLS alert (RFC 9001
/// §4.8: `0x100 + alert`).
const CRYPTO_CODE_MIN: u64 = 0x100;
/// Highest QUIC transport error code that encodes a TLS alert.
const CRYPTO_CODE_MAX: u64 = 0x1ff;
/// QUIC `CONNECTION_REFUSED` (RFC 9000 §20.1).
const CONNECTION_REFUSED_CODE: u64 = 0x2;

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

    /// The code as a `u64` (a peer-sent code can exceed `u32::MAX`).
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// The code as a `u32`, `None` if a peer sent something larger.
    pub fn as_u32(self) -> Option<u32> {
        u32::try_from(self.0).ok()
    }

    /// quinn's varint for this code. A value past the varint range (not
    /// constructible from `u32`) clamps to the maximum.
    pub(crate) fn to_varint(self) -> quinn::VarInt {
        quinn::VarInt::from_u64(self.0).unwrap_or(quinn::VarInt::MAX)
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

impl From<quinn::VarInt> for StreamCode {
    fn from(code: quinn::VarInt) -> Self {
        Self(code.into_inner())
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

impl From<quinn::ApplicationClose> for ApplicationClose {
    fn from(close: quinn::ApplicationClose) -> Self {
        Self {
            error_code: close.error_code.into(),
            reason: close.reason,
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
            Self::Crypto { text, .. } | Self::Refused { text } | Self::Other(text) => {
                f.write_str(text)
            }
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<quinn::ConnectionError> for ConnectionError {
    fn from(err: quinn::ConnectionError) -> Self {
        match err {
            quinn::ConnectionError::VersionMismatch => Self::VersionMismatch,
            quinn::ConnectionError::ApplicationClosed(close) => {
                Self::ApplicationClosed(close.into())
            }
            quinn::ConnectionError::Reset => Self::Reset,
            quinn::ConnectionError::TimedOut => Self::TimedOut,
            quinn::ConnectionError::LocallyClosed => Self::LocallyClosed,
            quinn::ConnectionError::CidsExhausted => Self::CidsExhausted,
            // We detected the violation ourselves. Only the crypto class is
            // told apart; the code is never `CONNECTION_REFUSED` here (that
            // is a peer-sent close).
            quinn::ConnectionError::TransportError(te) => {
                let text: Arc<str> = te.to_string().into();
                match crypto_alert(te.code.into()) {
                    Some(alert) => Self::Crypto { alert, text },
                    None => Self::Other(text),
                }
            }
            // The peer's QUIC stack aborted the connection.
            quinn::ConnectionError::ConnectionClosed(cc) => {
                let raw: u64 = cc.error_code.into();
                let text: Arc<str> = format!("aborted by peer: {cc}").into();
                if let Some(alert) = crypto_alert(raw) {
                    Self::Crypto { alert, text }
                } else if raw == CONNECTION_REFUSED_CODE {
                    Self::Refused { text }
                } else {
                    Self::Other(text)
                }
            }
        }
    }
}

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

/// The TLS alert a QUIC transport code encodes, if it is in the crypto band.
fn crypto_alert(code: u64) -> Option<u8> {
    (CRYPTO_CODE_MIN..=CRYPTO_CODE_MAX)
        .contains(&code)
        .then_some((code & 0xff) as u8)
}

/// A stream operation on a stream that is already finished, reset, stopped
/// or was never open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Error)]
#[error("closed stream")]
pub struct ClosedStream;

impl From<quinn::ClosedStream> for ClosedStream {
    fn from(_: quinn::ClosedStream) -> Self {
        Self
    }
}

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

impl From<quinn::ReadError> for ReadError {
    fn from(err: quinn::ReadError) -> Self {
        match err {
            quinn::ReadError::Reset(code) => Self::Reset(code.into()),
            quinn::ReadError::ConnectionLost(e) => Self::ConnectionLost(e.into()),
            quinn::ReadError::ClosedStream => Self::ClosedStream,
            quinn::ReadError::IllegalOrderedRead => Self::IllegalOrderedRead,
            quinn::ReadError::ZeroRttRejected => Self::ZeroRttRejected,
        }
    }
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

impl From<quinn::ReadExactError> for ReadExactError {
    fn from(err: quinn::ReadExactError) -> Self {
        match err {
            quinn::ReadExactError::FinishedEarly(n) => Self::FinishedEarly(n),
            quinn::ReadExactError::ReadError(e) => Self::ReadError(e.into()),
        }
    }
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

impl From<quinn::ReadToEndError> for ReadToEndError {
    fn from(err: quinn::ReadToEndError) -> Self {
        match err {
            quinn::ReadToEndError::Read(e) => Self::Read(e.into()),
            quinn::ReadToEndError::TooLong => Self::TooLong,
        }
    }
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

impl From<quinn::WriteError> for WriteError {
    fn from(err: quinn::WriteError) -> Self {
        match err {
            quinn::WriteError::Stopped(code) => Self::Stopped(code.into()),
            quinn::WriteError::ConnectionLost(e) => Self::ConnectionLost(e.into()),
            quinn::WriteError::ClosedStream => Self::ClosedStream,
            quinn::WriteError::ZeroRttRejected => Self::ZeroRttRejected,
        }
    }
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

impl From<quinn::StoppedError> for StoppedError {
    fn from(err: quinn::StoppedError) -> Self {
        match err {
            quinn::StoppedError::ConnectionLost(e) => Self::ConnectionLost(e.into()),
            quinn::StoppedError::ZeroRttRejected => Self::ZeroRttRejected,
        }
    }
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

impl From<quinn::ConnectError> for ConnectError {
    fn from(err: quinn::ConnectError) -> Self {
        match err {
            quinn::ConnectError::EndpointStopping => Self::EndpointStopping,
            quinn::ConnectError::CidsExhausted => Self::CidsExhausted,
            quinn::ConnectError::InvalidServerName(name) => Self::InvalidServerName(name),
            quinn::ConnectError::InvalidRemoteAddress(addr) => Self::InvalidRemoteAddress(addr),
            quinn::ConnectError::NoDefaultClientConfig => Self::NoDefaultClientConfig,
            quinn::ConnectError::UnsupportedVersion => Self::UnsupportedVersion,
        }
    }
}

/// The TLS keying-material exporter refused the request (the requested
/// output was too long).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("keying material export failed")]
pub struct ExportError;

impl From<quinn::crypto::ExportKeyingMaterialError> for ExportError {
    fn from(_: quinn::crypto::ExportKeyingMaterialError) -> Self {
        Self
    }
}

#[cfg(test)]
mod tests;
