use super::*;

/// Mutation coverage for `classify_client_error`'s own three-way split
/// (issue #4 item 6): a real `ClientError` of each documented shape
/// classifies as the one `classify_client_error`'s doc comment claims.
#[test]
fn classify_client_error_maps_the_documented_vocabulary() {
    // `Connection(ApplicationClosed)` with an ordinary close code (not
    // `CLOSE_CODE_PATH_DEAD`) — a real, clean peer close.
    let closed = ClientError::Connection(qsh_transport::ConnectionError::ApplicationClosed(
        qsh_transport::ApplicationClose {
            error_code: qsh_transport::StreamCode::from_u32(0),
            reason: bytes::Bytes::new(),
        },
    ));
    assert_eq!(
        classify_client_error(&closed),
        crate::reverse::ReconnectCause::PeerClosed
    );

    // `Connection(TimedOut)` — quinn's own idle-timeout expiry on an
    // otherwise-silent path. Its own cause, `idle_timeout`, not `path_dead`
    // (ADR-0022 결정 5·6).
    let timed_out = ClientError::Connection(qsh_transport::ConnectionError::TimedOut);
    assert_eq!(
        classify_client_error(&timed_out),
        crate::reverse::ReconnectCause::IdleTimeout
    );

    // Everything else — a peer-sent wire `Error` reply, here — is
    // `local`: none of it is a peer-initiated clean close or a
    // PathWatch-class idle judgment.
    let remote = ClientError::Remote {
        code: qsh_proto::ErrorCode::PermissionDenied,
        message: "denied".to_string(),
        retryable: false,
    };
    assert_eq!(
        classify_client_error(&remote),
        crate::reverse::ReconnectCause::Local
    );
}
