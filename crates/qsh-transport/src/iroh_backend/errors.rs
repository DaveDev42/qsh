//! iroh (noq) error types into the transport-neutral ones
//! (ADR-0061 decision 7: each backend converts its own errors, and only the
//! neutral types leave the backend).
//!
//! noq is a fork of quinn and keeps its error shapes, so the mapping mirrors
//! the QUIC backend's `From` impls in `error.rs`. They are free functions and
//! not `From` impls so that this module is the only place that names noq's
//! types.

use std::error::Error as StdError;
use std::sync::Arc;

use iroh::endpoint as ie;

use crate::endpoint::CLOSE_CODE_UNVERIFIED_PEER;
use crate::error::{
    ApplicationClose, ClosedStream, ConnectionError, DatagramError, ExportError, ReadError,
    ReadExactError, ReadToEndError, StoppedError, StreamCode, WriteError,
};

/// Lowest QUIC transport error code that encodes a TLS alert (RFC 9001 4.8).
const CRYPTO_CODE_MIN: u64 = 0x100;
/// Highest QUIC transport error code that encodes a TLS alert.
const CRYPTO_CODE_MAX: u64 = 0x1ff;
/// TLS alert `unknown_ca` (RFC 8446 6.2): how the QUIC backend's verifier
/// reports a peer that is neither pinned nor under a trusted CA.
const ALERT_UNKNOWN_CA: u8 = 48;
/// QUIC `CONNECTION_REFUSED` (RFC 9000 20.1).
const CONNECTION_REFUSED_CODE: u64 = 0x2;

fn crypto_alert(code: u64) -> Option<u8> {
    (CRYPTO_CODE_MIN..=CRYPTO_CODE_MAX)
        .contains(&code)
        .then_some((code & 0xff) as u8)
}

pub(super) fn code_of(code: ie::VarInt) -> StreamCode {
    StreamCode::from_raw(code.into_inner())
}

pub(super) fn varint_of(code: StreamCode) -> ie::VarInt {
    ie::VarInt::from_u64(code.into_inner()).unwrap_or(ie::VarInt::MAX)
}

pub(super) fn conn_err(err: ie::ConnectionError) -> ConnectionError {
    match err {
        ie::ConnectionError::VersionMismatch => ConnectionError::VersionMismatch,
        // The refusal of an unpinned peer comes after the handshake here,
        // where the QUIC backend's verifier refuses inside it with a TLS
        // alert. Report the same neutral classification (a crypto failure,
        // `unknown_ca`, what an untrusted certificate becomes there), so
        // the callers that turn that into "the server rejected this
        // device" need no iroh case.
        ie::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == u64::from(CLOSE_CODE_UNVERIFIED_PEER) =>
        {
            ConnectionError::crypto(ALERT_UNKNOWN_CA)
        }
        ie::ConnectionError::ApplicationClosed(close) => {
            ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: code_of(close.error_code),
                reason: close.reason,
            })
        }
        ie::ConnectionError::Reset => ConnectionError::Reset,
        ie::ConnectionError::TimedOut => ConnectionError::TimedOut,
        ie::ConnectionError::LocallyClosed => ConnectionError::LocallyClosed,
        ie::ConnectionError::CidsExhausted => ConnectionError::CidsExhausted,
        ie::ConnectionError::TransportError(te) => {
            let text: Arc<str> = te.to_string().into();
            let raw: u64 = te.code.into();
            match crypto_alert(raw) {
                Some(alert) => ConnectionError::Crypto { alert, text },
                None => ConnectionError::Other(text),
            }
        }
        ie::ConnectionError::ConnectionClosed(cc) => {
            let raw: u64 = cc.error_code.into();
            let text: Arc<str> = format!("aborted by peer: {cc}").into();
            if let Some(alert) = crypto_alert(raw) {
                ConnectionError::Crypto { alert, text }
            } else if raw == CONNECTION_REFUSED_CODE {
                ConnectionError::Refused { text }
            } else {
                ConnectionError::Other(text)
            }
        }
    }
}

pub(super) fn closed_stream(_: ie::ClosedStream) -> ClosedStream {
    ClosedStream
}

pub(super) fn read_err(err: ie::ReadError) -> ReadError {
    match err {
        ie::ReadError::Reset(code) => ReadError::Reset(code_of(code)),
        ie::ReadError::ConnectionLost(e) => ReadError::ConnectionLost(conn_err(e)),
        ie::ReadError::ClosedStream => ReadError::ClosedStream,
        ie::ReadError::ZeroRttRejected => ReadError::ZeroRttRejected,
    }
}

pub(super) fn read_exact_err(err: ie::ReadExactError) -> ReadExactError {
    match err {
        ie::ReadExactError::FinishedEarly(n) => ReadExactError::FinishedEarly(n),
        ie::ReadExactError::ReadError(e) => ReadExactError::ReadError(read_err(e)),
    }
}

pub(super) fn read_to_end_err(err: ie::ReadToEndError) -> ReadToEndError {
    match err {
        ie::ReadToEndError::Read(e) => ReadToEndError::Read(read_err(e)),
        ie::ReadToEndError::TooLong => ReadToEndError::TooLong,
    }
}

pub(super) fn write_err(err: ie::WriteError) -> WriteError {
    match err {
        ie::WriteError::Stopped(code) => WriteError::Stopped(code_of(code)),
        ie::WriteError::ConnectionLost(e) => WriteError::ConnectionLost(conn_err(e)),
        ie::WriteError::ClosedStream => WriteError::ClosedStream,
        ie::WriteError::ZeroRttRejected => WriteError::ZeroRttRejected,
    }
}

pub(super) fn stopped_err(err: ie::StoppedError) -> StoppedError {
    match err {
        ie::StoppedError::ConnectionLost(e) => StoppedError::ConnectionLost(conn_err(e)),
        ie::StoppedError::ZeroRttRejected => StoppedError::ZeroRttRejected,
    }
}

pub(super) fn datagram_err(err: ie::SendDatagramError) -> DatagramError {
    match err {
        ie::SendDatagramError::UnsupportedByPeer => DatagramError::UnsupportedByPeer,
        ie::SendDatagramError::Disabled => DatagramError::Disabled,
        ie::SendDatagramError::TooLarge => DatagramError::TooLarge,
        ie::SendDatagramError::ConnectionLost(e) => DatagramError::ConnectionLost(conn_err(e)),
    }
}

pub(super) fn export_err(_: ie::ExportKeyingMaterialError) -> ExportError {
    ExportError
}

/// An error and its `source()` chain as one line. iroh's own errors print
/// only their outermost message, which on its own ("Unable to connect to
/// remote") hides the cause.
pub(super) fn chain(err: &dyn StdError) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !out.ends_with(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}
