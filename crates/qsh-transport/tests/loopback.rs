//! L3: in-process loopback QUIC (`docs/design/testing.md` L3) — two quinn
//! endpoints on 127.0.0.1:0, real TLS, no subprocess.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::frame::{CONTROL_FRAME_MAX, DATA_FRAME_MAX, FrameError};
use qsh_proto::wire::{
    ControlMessage, EXEC_CHUNK_MAX, Error as WireError, ExecFrame, ExecStart, ExecStarted, Hello,
    Ping, Pong, Response, StreamHeader, StreamKind, WireEncodeError, control_message, response,
};
use qsh_transport::endpoint::{KEEP_ALIVE_INTERVAL, MAX_IDLE_TIMEOUT};
use qsh_transport::{
    CertificateDer, Connection, DialError, Dialer, Fingerprint, FramedRecv, FramedSend,
    FramedStream, Listener, LocalIdentity, Principal, RejectReason, StaticTrust, StreamError,
};

fn make_identity() -> (LocalIdentity, Fingerprint) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let fp = Fingerprint::of_cert_der(&der).unwrap();
    (
        LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: key.serialize_der(),
        },
        fp,
    )
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[tokio::test]
async fn pinned_peers_handshake_and_exchange_hello() {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();

    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("box".into()));

    let listener = Listener::bind(loopback(), server_id, Arc::new(server_trust)).unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = listener.accept().await.expect("one connection");
        let conn = incoming.accept().await.expect("handshake");
        assert_eq!(conn.principal(), &Principal::Device("laptop".into()));
        let (send, recv) = conn.accept_bi().await.unwrap();
        let mut ctl = FramedStream::control(send, recv);
        let hello: ControlMessage = ctl.recv.recv().await.unwrap().expect("hello");
        assert!(matches!(
            hello.body,
            Some(control_message::Body::Hello(Hello { ref device_name, .. })) if device_name == "client"
        ));
        ctl.send
            .send(&ControlMessage::new(
                0,
                control_message::Body::Hello(Hello {
                    versions: vec![0],
                    device_name: "server".into(),
                    capabilities: vec!["exec".into()],
                    reverse: None,
                }),
            ))
            .await
            .unwrap();
        // Keep the connection alive until the client is done.
        let _ = ctl.recv.recv::<ControlMessage>().await;
    });

    let dialer = Dialer::new(client_id, Arc::new(client_trust));
    let dialed = dialer.dial(addr, "127.0.0.1").await.expect("dial");
    assert_eq!(
        dialed.connection.principal(),
        &Principal::Device("box".into())
    );

    let (send, recv) = dialed.connection.open_bi().await.unwrap();
    let mut ctl = FramedStream::control(send, recv);
    ctl.send
        .send(&ControlMessage::new(
            0,
            control_message::Body::Hello(Hello {
                versions: vec![0],
                device_name: "client".into(),
                capabilities: vec!["exec".into()],
                reverse: None,
            }),
        ))
        .await
        .unwrap();
    let hello: ControlMessage = ctl.recv.recv().await.unwrap().expect("server hello");
    assert!(matches!(
        hello.body,
        Some(control_message::Body::Hello(Hello { ref device_name, .. })) if device_name == "server"
    ));
    ctl.send.finish().unwrap();
    dialed.connection.close(0, b"done");
    server.await.unwrap();
}

#[tokio::test]
async fn unpinned_server_is_rejected_locally_with_observed_fingerprint() {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
    let listener = Listener::bind(loopback(), server_id, Arc::new(server_trust)).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        if let Some(incoming) = listener.accept().await {
            let _ = incoming.accept().await;
        }
    });

    let dialer = Dialer::new(client_id, Arc::new(StaticTrust::empty()));
    let err = dialer.dial(addr, "127.0.0.1").await.unwrap_err();
    match err {
        DialError::LocalRejected { reason, observed } => {
            assert_eq!(reason, RejectReason::Untrusted);
            assert_eq!(observed, Some(server_fp));
        }
        other => panic!("expected LocalRejected, got {other:?}"),
    }
    server.abort();
}

#[tokio::test]
async fn unpinned_client_is_rejected_by_server() {
    let (server_id, server_fp) = make_identity();
    let (client_id, _client_fp) = make_identity();
    // Server trusts nobody.
    let listener = Listener::bind(loopback(), server_id, Arc::new(StaticTrust::empty())).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        incoming.accept().await
    });

    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("box".into()));
    let dialer = Dialer::new(client_id, Arc::new(client_trust));
    let result = dialer.dial(addr, "127.0.0.1").await;
    // Depending on timing the client either sees the rejection during the
    // handshake, or the handshake "completes" locally and the failure
    // surfaces on first stream use. Either way: no application data flows.
    let remote_rejected = match result {
        Err(DialError::RemoteRejected) => true,
        Ok(dialed) => {
            let err = dialed.connection.closed().await;
            qsh_transport::endpoint::is_crypto_failure(&err)
        }
        Err(other) => panic!("unexpected error {other:?}"),
    };
    assert!(remote_rejected, "server must reject the unpinned client");
    let server_result = server.await.unwrap();
    assert!(server_result.is_err(), "server accept must fail");
}

// ---------------------------------------------------------------------
// Framed stream I/O over an already-authenticated connection: control
// message / StreamHeader / ExecFrame roundtrips, truncation, oversize
// rejection, and keep-alive configuration.
// ---------------------------------------------------------------------

/// Binds a listener, dials it with a peer pinned both ways, and returns
/// both ends of the now fully-handshaken connection. The tests below only
/// care about framed I/O over an already-authenticated connection, not the
/// handshake itself (covered above and in `handshake_matrix.rs`).
async fn connect_pinned_pair() -> (qsh_transport::Dialed, Connection, quinn::Endpoint) {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("box".into()));

    let listener = Listener::bind(loopback(), server_id, Arc::new(server_trust)).unwrap();
    let addr = listener.local_addr().unwrap();
    // Keep a handle to the server endpoint alive for the caller: dropping
    // the *last* `quinn::Endpoint` clone force-closes every connection it
    // ever accepted (`ApplicationClose{code:0}`), which would otherwise
    // happen the instant the short-lived accept task below returns.
    let server_endpoint = listener.endpoint().clone();
    let server = tokio::spawn(async move {
        let incoming = listener.accept().await.expect("one connection");
        incoming.accept().await.expect("handshake")
    });

    let dialer = Dialer::new(client_id, Arc::new(client_trust));
    let dialed = dialer.dial(addr, "127.0.0.1").await.expect("dial");
    let server_conn = server.await.unwrap();
    (dialed, server_conn, server_endpoint)
}

#[tokio::test]
async fn data_stream_framed_roundtrip_many_messages_and_clean_eof() {
    let (dialed, server_conn, _server_endpoint) = connect_pinned_pair().await;

    let controls = vec![
        ControlMessage::new(
            1,
            control_message::Body::Hello(Hello {
                versions: vec![0],
                device_name: "roundtrip-client".into(),
                capabilities: vec!["exec".into()],
                reverse: None,
            }),
        ),
        ControlMessage::new(0, control_message::Body::Ping(Ping {})),
        ControlMessage::new(0, control_message::Body::Pong(Pong {})),
        ControlMessage::new(
            2,
            control_message::Body::ExecStart(ExecStart {
                argv: vec!["sh".into(), "-c".into(), "true".into()],
                env: Default::default(),
                timeout_ms: 1000,
            }),
        ),
        ControlMessage::new(
            2,
            control_message::Body::Response(Response {
                body: Some(response::Body::ExecStarted(ExecStarted {
                    exec_id: "e1".into(),
                    ticket: vec![9, 9, 9],
                })),
            }),
        ),
        ControlMessage::error(3, WireError::from_code(ErrorCode::AuthFailed, "nope")),
    ];
    // The first frame on a real EXEC_DATA stream, plus a maximal (16 KiB)
    // stdout chunk among a mix of the other ExecFrame variants.
    let header = StreamHeader::exec_data(vec![1, 2, 3, 4]);
    let frames = vec![
        ExecFrame::stdin(b"hello".to_vec()),
        ExecFrame::stdin_eof(),
        ExecFrame::stdout(vec![0xAB; EXEC_CHUNK_MAX]),
        ExecFrame::stderr(b"warn".to_vec()),
        ExecFrame::exec_exit(7, None),
    ];

    let expect_controls = controls.clone();
    let expect_header = header.clone();
    let expect_frames = frames.clone();
    let server = tokio::spawn(async move {
        let (send, recv) = server_conn.accept_bi().await.unwrap();
        let mut data = FramedStream::data(send, recv);

        let mut received_controls = Vec::new();
        for _ in 0..expect_controls.len() {
            received_controls.push(
                data.recv
                    .recv::<ControlMessage>()
                    .await
                    .unwrap()
                    .expect("control message"),
            );
        }
        assert_eq!(received_controls, expect_controls);

        let received_header: StreamHeader = data.recv.recv().await.unwrap().expect("stream header");
        assert_eq!(received_header, expect_header);
        assert_eq!(received_header.stream_kind(), Some(StreamKind::ExecData));

        let mut received_frames = Vec::new();
        while let Some(f) = data.recv.recv::<ExecFrame>().await.unwrap() {
            received_frames.push(f);
        }
        assert_eq!(received_frames, expect_frames);
    });

    let (send, recv) = dialed.connection.open_bi().await.unwrap();
    let mut data = FramedStream::data(send, recv);
    for m in &controls {
        data.send.send(m).await.unwrap();
    }
    data.send.send(&header).await.unwrap();
    for f in &frames {
        data.send.send(f).await.unwrap();
    }
    // FIN lands exactly at a frame boundary: the receiver's next `recv()`
    // must be a clean `Ok(None)`, not `Truncated`.
    data.send.finish().unwrap();

    server.await.unwrap();
    dialed.connection.close(0, b"data roundtrip done");
}

#[tokio::test]
async fn truncated_frame_mid_payload_is_reported() {
    let (dialed, server_conn, _server_endpoint) = connect_pinned_pair().await;

    let server = tokio::spawn(async move {
        let (_send, recv) = server_conn.accept_bi().await.unwrap();
        let mut framed = FramedRecv::data(recv);
        framed.recv::<ExecFrame>().await
    });

    let (mut send, _recv) = dialed.connection.open_bi().await.unwrap();
    // Declares a 10-byte payload but only ever writes 4 bytes of it, then
    // FINs — a clean stream end in the middle of a frame.
    let mut wire = 10u32.to_be_bytes().to_vec();
    wire.extend_from_slice(&[1, 2, 3, 4]);
    send.write_all(&wire).await.unwrap();
    send.finish().unwrap();

    match server.await.unwrap() {
        Err(StreamError::Truncated { buffered }) => assert_eq!(buffered, 8),
        other => panic!("expected Truncated, got {other:?}"),
    }
    dialed.connection.close(0, b"truncation case done");
}

#[tokio::test]
async fn oversize_data_frame_header_rejected_without_reading_payload() {
    let (dialed, server_conn, _server_endpoint) = connect_pinned_pair().await;

    let server = tokio::spawn(async move {
        let (_send, recv) = server_conn.accept_bi().await.unwrap();
        let mut framed = FramedRecv::data(recv);
        framed.recv::<ExecFrame>().await
    });

    let (mut send, _recv) = dialed.connection.open_bi().await.unwrap();
    // Only the 4-byte header is ever sent: if the receiver allocated a
    // buffer sized by the declared (huge) length before checking the cap,
    // this would OOM instead of erroring.
    send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    send.finish().unwrap();

    match server.await.unwrap() {
        Err(StreamError::Frame(FrameError::Oversize { len, max })) => {
            assert_eq!(len, u32::MAX);
            assert_eq!(max, DATA_FRAME_MAX);
        }
        other => panic!("expected Frame(Oversize), got {other:?}"),
    }
    dialed.connection.close(0, b"oversize case done");
}

#[tokio::test]
async fn oversize_control_frame_rejected_and_encode_refuses_to_send_over_cap() {
    let (dialed, server_conn, _server_endpoint) = connect_pinned_pair().await;

    let server = tokio::spawn(async move {
        let (_send, recv) = server_conn.accept_bi().await.unwrap();
        let mut framed = FramedRecv::control(recv);
        framed.recv::<ControlMessage>().await
    });

    let (mut send, _recv) = dialed.connection.open_bi().await.unwrap();
    let huge_len = (CONTROL_FRAME_MAX + 1) as u32;
    send.write_all(&huge_len.to_be_bytes()).await.unwrap();
    send.finish().unwrap();

    match server.await.unwrap() {
        Err(StreamError::Frame(FrameError::Oversize { len, max })) => {
            assert_eq!(len, huge_len);
            assert_eq!(max, CONTROL_FRAME_MAX);
        }
        other => panic!("expected Frame(Oversize), got {other:?}"),
    }

    // The sending side refuses to even attempt an over-cap message: encoding
    // fails before any bytes reach the wire (a second, never-written-to
    // stream — nothing above depends on the peer reading from it).
    let (send2, _recv2) = dialed.connection.open_bi().await.unwrap();
    let mut framed_send = FramedSend::control(send2);
    let huge = ControlMessage::new(
        99,
        control_message::Body::ExecStart(ExecStart {
            argv: vec!["x".repeat(CONTROL_FRAME_MAX + 1024)],
            env: Default::default(),
            timeout_ms: 0,
        }),
    );
    match framed_send.send(&huge).await {
        Err(StreamError::Encode(WireEncodeError::TooLarge { len, max })) => {
            assert!(len > CONTROL_FRAME_MAX);
            assert_eq!(max, CONTROL_FRAME_MAX);
        }
        other => panic!("expected Encode(TooLarge), got {other:?}"),
    }

    dialed.connection.close(0, b"encode-refuses case done");
}

#[tokio::test]
async fn keep_alive_and_idle_timeout_are_configured_and_ping_pong_roundtrips() {
    assert_eq!(KEEP_ALIVE_INTERVAL, Duration::from_secs(15));
    assert_eq!(MAX_IDLE_TIMEOUT, Duration::from_secs(45));

    // 0-RTT is never used: `client_tls_config` sets `enable_early_data =
    // false` and disables resumption entirely, and `server_tls_config` sets
    // `max_early_data_size = 0` and installs `NoServerSessionStorage`. This
    // makes 0-RTT structurally unreachable rather than merely unused —
    // there is no client/server API surface left to assert against (no
    // `into_0rtt()` is ever called, no ticket is ever issued to call it
    // with), so the functional check below (a full round trip over the
    // resulting connection) is the closest observable proxy: it only works
    // because the handshake completed as ordinary 1-RTT.
    let (dialed, server_conn, _server_endpoint) = connect_pinned_pair().await;

    let server = tokio::spawn(async move {
        let (send, recv) = server_conn.accept_bi().await.unwrap();
        let mut ctl = FramedStream::control(send, recv);
        let ping: ControlMessage = ctl.recv.recv().await.unwrap().expect("ping");
        assert!(matches!(
            ping.body,
            Some(control_message::Body::Ping(Ping {}))
        ));
        ctl.send
            .send(&ControlMessage::new(
                ping.request_id,
                control_message::Body::Pong(Pong {}),
            ))
            .await
            .unwrap();
        // Keep the connection (and this task's `Connection` handle) alive
        // until the client is done: dropping the last `Connection` handle
        // on either side implicitly closes it (quinn's
        // `ConnectionRef::drop`), which would otherwise race the client's
        // read of the pong above.
        let _ = ctl.recv.recv::<ControlMessage>().await;
    });

    let (send, recv) = dialed.connection.open_bi().await.unwrap();
    let mut ctl = FramedStream::control(send, recv);
    ctl.send
        .send(&ControlMessage::new(
            7,
            control_message::Body::Ping(Ping {}),
        ))
        .await
        .unwrap();
    let pong: ControlMessage = ctl.recv.recv().await.unwrap().expect("pong");
    assert!(matches!(
        pong.body,
        Some(control_message::Body::Pong(Pong {}))
    ));
    assert_eq!(pong.request_id, 7);

    ctl.send.finish().unwrap();
    dialed.connection.close(0, b"keep-alive case done");
    server.await.unwrap();
}
