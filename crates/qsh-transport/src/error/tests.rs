use super::*;

use bytes::Bytes;

fn code(raw: u64) -> quinn::TransportErrorCode {
    // `TransportErrorCode` has no public raw constructor except through
    // `crypto`/the named constants; build the codes the tests need.
    match raw {
        0x2 => quinn::TransportErrorCode::CONNECTION_REFUSED,
        0x0a => quinn::TransportErrorCode::PROTOCOL_VIOLATION,
        0x100..=0x1ff => quinn::TransportErrorCode::crypto((raw & 0xff) as u8),
        other => panic!("test has no constructor for transport code {other:#x}"),
    }
}

fn closed(raw: u64, reason: &str) -> quinn::ConnectionError {
    quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
        error_code: code(raw),
        frame_type: None,
        reason: Bytes::copy_from_slice(reason.as_bytes()),
    })
}

fn local(raw: u64, reason: &str) -> quinn::ConnectionError {
    quinn::ConnectionError::TransportError(quinn_proto::TransportError {
        code: code(raw),
        frame: None,
        reason: reason.to_owned(),
    })
}

fn app_closed(raw: u32, reason: &str) -> quinn::ConnectionError {
    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
        error_code: quinn::VarInt::from_u32(raw),
        reason: Bytes::copy_from_slice(reason.as_bytes()),
    })
}

/// Every quinn `ConnectionError` shape the neutral type is built from.
fn every_quinn_connection_error() -> Vec<quinn::ConnectionError> {
    vec![
        quinn::ConnectionError::VersionMismatch,
        quinn::ConnectionError::Reset,
        quinn::ConnectionError::TimedOut,
        quinn::ConnectionError::LocallyClosed,
        quinn::ConnectionError::CidsExhausted,
        app_closed(0, ""),
        app_closed(0x1004, ""),
        app_closed(7, "going away"),
        app_closed(7, "not \u{fffd} utf8 \u{e9}"),
        closed(0x2, ""),
        closed(0x2, "at capacity"),
        closed(0x0a, ""),
        closed(0x0a, "bad frame"),
        closed(0x100, ""),
        closed(0x12a, "alert"),
        closed(0x1ff, ""),
        local(0x0a, ""),
        local(0x0a, "stream limit"),
        local(0x12a, "invalid peer certificate"),
        local(0x2, "refused locally"),
    ]
}

/// The neutral `Display` is the string the CLI has always printed
/// (`connection lost: {err}`, `handshake failed: {err}`), for every variant.
#[test]
fn display_matches_quinn_for_every_connection_error() {
    for quinn_err in every_quinn_connection_error() {
        let expected = quinn_err.to_string();
        let neutral = ConnectionError::from(quinn_err.clone());
        assert_eq!(neutral.to_string(), expected, "from {quinn_err:?}");
    }
}

#[test]
fn display_matches_quinn_for_every_stream_error() {
    let mut reads = vec![
        quinn::ReadError::ClosedStream,
        quinn::ReadError::IllegalOrderedRead,
        quinn::ReadError::ZeroRttRejected,
        quinn::ReadError::Reset(quinn::VarInt::from_u32(0x2001)),
        quinn::ReadError::Reset(quinn::VarInt::from_u64((1 << 40) + 5).unwrap()),
    ];
    let mut writes = vec![
        quinn::WriteError::ClosedStream,
        quinn::WriteError::ZeroRttRejected,
        quinn::WriteError::Stopped(quinn::VarInt::from_u32(0)),
        quinn::WriteError::Stopped(quinn::VarInt::from_u32(0x2001)),
    ];
    for e in every_quinn_connection_error() {
        reads.push(quinn::ReadError::ConnectionLost(e.clone()));
        writes.push(quinn::WriteError::ConnectionLost(e));
    }
    for quinn_err in reads {
        let neutral = ReadError::from(quinn_err.clone());
        assert_eq!(neutral.to_string(), quinn_err.to_string(), "{quinn_err:?}");
        let (a, b) = (
            std::io::Error::from(neutral),
            std::io::Error::from(quinn_err.clone()),
        );
        assert_eq!(a.kind(), b.kind(), "io kind for {quinn_err:?}");
        assert_eq!(a.to_string(), b.to_string(), "io text for {quinn_err:?}");
    }
    for quinn_err in writes {
        let neutral = WriteError::from(quinn_err.clone());
        assert_eq!(neutral.to_string(), quinn_err.to_string(), "{quinn_err:?}");
        let (a, b) = (
            std::io::Error::from(neutral),
            std::io::Error::from(quinn_err.clone()),
        );
        assert_eq!(a.kind(), b.kind(), "io kind for {quinn_err:?}");
        assert_eq!(a.to_string(), b.to_string(), "io text for {quinn_err:?}");
    }
    let stopped = [
        quinn::StoppedError::ZeroRttRejected,
        quinn::StoppedError::ConnectionLost(quinn::ConnectionError::Reset),
    ];
    for quinn_err in stopped {
        assert_eq!(
            StoppedError::from(quinn_err.clone()).to_string(),
            quinn_err.to_string()
        );
    }
    assert_eq!(
        ClosedStream::from(quinn::ClosedStream::default()).to_string(),
        quinn::ClosedStream::default().to_string()
    );
}

#[test]
fn display_matches_quinn_for_every_connect_error() {
    let all = [
        quinn::ConnectError::EndpointStopping,
        quinn::ConnectError::CidsExhausted,
        quinn::ConnectError::InvalidServerName("bad name".into()),
        quinn::ConnectError::InvalidRemoteAddress("127.0.0.1:0".parse().unwrap()),
        quinn::ConnectError::NoDefaultClientConfig,
        quinn::ConnectError::UnsupportedVersion,
    ];
    for quinn_err in all {
        assert_eq!(
            ConnectError::from(quinn_err.clone()).to_string(),
            quinn_err.to_string(),
            "{quinn_err:?}"
        );
    }
}

/// The classification predicates replace the old free functions on
/// `quinn::ConnectionError` (`is_crypto_failure`, `is_connection_refused`):
/// they agree with them over the whole `0x100..=0x1ff` band's edges and
/// `CONNECTION_REFUSED = 0x2`, for a locally detected `TransportError` and a
/// peer `ConnectionClosed` alike.
#[test]
fn crypto_and_refused_classification_agrees_with_the_quinn_rules() {
    fn old_is_crypto(err: &quinn::ConnectionError) -> bool {
        let in_band = |raw: u64| (0x100..=0x1ff).contains(&raw);
        match err {
            quinn::ConnectionError::TransportError(te) => in_band(te.code.into()),
            quinn::ConnectionError::ConnectionClosed(cc) => in_band(cc.error_code.into()),
            _ => false,
        }
    }
    fn old_is_refused(err: &quinn::ConnectionError) -> bool {
        match err {
            quinn::ConnectionError::ConnectionClosed(cc) => u64::from(cc.error_code) == 0x2,
            _ => false,
        }
    }
    for quinn_err in every_quinn_connection_error() {
        let neutral = ConnectionError::from(quinn_err.clone());
        assert_eq!(
            neutral.is_crypto_failure(),
            old_is_crypto(&quinn_err),
            "crypto: {quinn_err:?}"
        );
        assert_eq!(
            neutral.is_refused(),
            old_is_refused(&quinn_err),
            "refused: {quinn_err:?}"
        );
        assert!(
            !(neutral.is_crypto_failure() && neutral.is_refused()),
            "the two classes never overlap: {quinn_err:?}"
        );
    }
    // The band's edges: 0x100 and 0x1ff are crypto, and the alert survives.
    for (raw, alert) in [(0x100u64, 0u8), (0x1ff, 0xff), (0x12a, 42)] {
        let neutral = ConnectionError::from(closed(raw, ""));
        assert!(matches!(
            neutral,
            ConnectionError::Crypto { alert: a, .. } if a == alert
        ));
    }
    // A local `TransportError` with the refused code is not "refused": only a
    // peer-sent close is.
    assert!(!ConnectionError::from(local(0x2, "")).is_refused());
}

#[test]
fn the_crypto_constructor_renders_like_a_received_crypto_close() {
    let expected = quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
        error_code: quinn::TransportErrorCode::crypto(42),
        frame_type: None,
        reason: Bytes::new(),
    });
    let built = ConnectionError::crypto(42);
    assert_eq!(built.to_string(), expected.to_string());
    assert_eq!(built, ConnectionError::from(expected));
    assert!(built.is_crypto_failure());
}

#[test]
fn idle_timeout_peer_reset_and_application_code_classify_the_matching_variants() {
    assert!(ConnectionError::TimedOut.is_idle_timeout());
    assert!(!ConnectionError::Reset.is_idle_timeout());
    assert!(ConnectionError::Reset.is_peer_reset());
    assert!(!ConnectionError::LocallyClosed.is_peer_reset());
    assert_eq!(
        ConnectionError::from(app_closed(0x1004, "")).application_code(),
        Some(0x1004)
    );
    assert_eq!(ConnectionError::TimedOut.application_code(), None);
    assert_eq!(ConnectionError::crypto(1).application_code(), None);
    // A foreign peer can send a code past u32; it is carried, not truncated.
    let big = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
        error_code: quinn::VarInt::from_u64(1 << 40).unwrap(),
        reason: Bytes::new(),
    });
    let neutral = ConnectionError::from(big);
    assert_eq!(neutral.application_code(), None);
    assert!(matches!(
        neutral,
        ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. })
            if u64::from(error_code) == 1 << 40
    ));
}

#[test]
fn stream_code_round_trips_u32_and_renders_as_a_decimal() {
    let c = StreamCode::from_u32(0x2001);
    assert_eq!(u64::from(c), 0x2001);
    assert_eq!(c.as_u32(), Some(0x2001));
    assert_eq!(c.to_string(), 0x2001u64.to_string());
    assert_eq!(
        StreamCode::from(quinn::VarInt::from_u32(9)),
        StreamCode::from_u32(9)
    );
    assert_eq!(StreamCode::from(u32::MAX).as_u32(), Some(u32::MAX));
}
