//! quinn's errors, converted into the neutral ones in [`crate::error`]
//! (ADR-0061 decision 7: each backend maps its own errors in its own
//! module; `ErrorCode` and the doctor codes only ever see the neutral
//! types).
//!
//! Every `Display` here is pinned byte for byte against quinn's own
//! rendering by `tests.rs`, and the `io::ErrorKind` mappings the neutral
//! types apply match what quinn applies to its errors.

use std::sync::Arc;

use crate::error::{
    ApplicationClose, ClosedStream, ConnectError, ConnectionError, DatagramError, ExportError,
    ReadError, ReadExactError, ReadToEndError, StoppedError, StreamCode, WriteError,
};

/// quinn's varint for `code`. A value past the varint range (not
/// constructible from `u32`) clamps to the maximum.
pub(crate) fn varint(code: StreamCode) -> quinn::VarInt {
    quinn::VarInt::from_u64(code.into_inner()).unwrap_or(quinn::VarInt::MAX)
}

/// Lowest QUIC transport error code that encodes a TLS alert (RFC 9001
/// §4.8: `0x100 + alert`).
const CRYPTO_CODE_MIN: u64 = 0x100;
/// Highest QUIC transport error code that encodes a TLS alert.
const CRYPTO_CODE_MAX: u64 = 0x1ff;
/// QUIC `CONNECTION_REFUSED` (RFC 9000 §20.1).
const CONNECTION_REFUSED_CODE: u64 = 0x2;

impl From<quinn::VarInt> for StreamCode {
    fn from(code: quinn::VarInt) -> Self {
        Self::from_u64(code.into_inner())
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

impl From<quinn::ClosedStream> for ClosedStream {
    fn from(_: quinn::ClosedStream) -> Self {
        Self
    }
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

impl From<quinn::ReadExactError> for ReadExactError {
    fn from(err: quinn::ReadExactError) -> Self {
        match err {
            quinn::ReadExactError::FinishedEarly(n) => Self::FinishedEarly(n),
            quinn::ReadExactError::ReadError(e) => Self::ReadError(e.into()),
        }
    }
}

impl From<quinn::ReadToEndError> for ReadToEndError {
    fn from(err: quinn::ReadToEndError) -> Self {
        match err {
            quinn::ReadToEndError::Read(e) => Self::Read(e.into()),
            quinn::ReadToEndError::TooLong => Self::TooLong,
        }
    }
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

impl From<quinn::StoppedError> for StoppedError {
    fn from(err: quinn::StoppedError) -> Self {
        match err {
            quinn::StoppedError::ConnectionLost(e) => Self::ConnectionLost(e.into()),
            quinn::StoppedError::ZeroRttRejected => Self::ZeroRttRejected,
        }
    }
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

impl From<quinn::crypto::ExportKeyingMaterialError> for ExportError {
    fn from(_: quinn::crypto::ExportKeyingMaterialError) -> Self {
        Self
    }
}

impl From<quinn::SendDatagramError> for DatagramError {
    fn from(err: quinn::SendDatagramError) -> Self {
        match err {
            quinn::SendDatagramError::UnsupportedByPeer => Self::UnsupportedByPeer,
            quinn::SendDatagramError::Disabled => Self::Disabled,
            quinn::SendDatagramError::TooLarge => Self::TooLarge,
            quinn::SendDatagramError::ConnectionLost(e) => Self::ConnectionLost(e.into()),
        }
    }
}

/// The TLS alert a QUIC transport code encodes, if it is in the crypto band.
fn crypto_alert(code: u64) -> Option<u8> {
    (CRYPTO_CODE_MIN..=CRYPTO_CODE_MAX)
        .contains(&code)
        .then_some((code & 0xff) as u8)
}

#[cfg(test)]
mod tests;
