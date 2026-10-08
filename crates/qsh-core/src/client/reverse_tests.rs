use qsh_proto::local::{LocalHello, LocalHelloAck, LocalResponse, LocalStreamKind, local_response};
use tokio::net::UnixListener;

use super::*;
use crate::localctl::frame::LocalConduit;

/// A `from_local_control` [`Session`]'s [`Session::open_attach_stream`]
/// dials a **fresh** `LOCAL_STREAM` conduit to the exact same daemon
/// socket and host its `LOCAL_CONTROL` handshake came from
/// (`Self::local`'s own doc) — proven end to end against a fake daemon
/// that serves both conduit kinds, one after the other, on the same
/// socket path.
#[tokio::test]
async fn open_attach_stream_on_a_reverse_session_reaches_the_same_daemon_socket_and_host() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("reverse-attach.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        // First conduit: LOCAL_CONTROL, exactly what
        // `dial_reverse`/`open_control` produce.
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let hello: LocalHello = control.recv().await.unwrap().unwrap();
        assert_eq!(hello.kind, LocalStreamKind::LocalControl as i32);
        assert_eq!(hello.host, "phone");
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();

        // Second conduit, same socket path: LOCAL_STREAM, opened by
        // `open_attach_stream` — proves it is a fresh conduit to the
        // *same* daemon/host rather than reusing the control conduit
        // or dialing somewhere else.
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let hello: LocalHello = data.recv().await.unwrap().unwrap();
        assert_eq!(hello.kind, LocalStreamKind::LocalStream as i32);
        assert_eq!(hello.host, "phone");
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
                generation: 1,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        let header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        assert_eq!(header.stream_kind(), Some(wire::StreamKind::SessionData));
        header.ticket
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let mut session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );

    let attached = session
        .open_attach_stream(wire::SessionAttached {
            ticket: vec![7, 7, 7],
            new_resume_token: Vec::new(),
            replay_from: 0,
            writer_lease: true,
            expires_at: String::new(),
            input_seq: 0,
        })
        .await
        .unwrap();
    // A live `LOCAL_STREAM` conduit, not the forward route's
    // synchronous no-op — `DataKillSwitch::kill`'s own doc.
    attached.kill.kill();

    let seen_ticket = daemon.await.unwrap();
    assert_eq!(seen_ticket, vec![7, 7, 7]);
}

fn exec_spec() -> ExecSpec {
    ExecSpec {
        argv: vec!["true".to_string()],
        env: Vec::new(),
        timeout: None,
    }
}

/// Issue #5's own regression: a `from_local_control` `Session`
/// (the reverse route) opens `exec`'s `EXEC_DATA` stream on the *same*
/// daemon socket and host its `LOCAL_CONTROL` handshake came from —
/// [`Session::exec`]'s counterpart to
/// [`open_attach_stream_on_a_reverse_session_reaches_the_same_daemon_socket_and_host`]
/// above, proving `EXEC_DATA` now goes through the same generalized
/// [`Session::open_data_link`] `SESSION_DATA` already used, rather than
/// [`Session::exec`]'s old `require_connection()`-guarded QUIC-only
/// path (which failed every reverse-linked `Session` with
/// `ClientError::Unsupported` before issue #5's daemon `EXEC_DATA`
/// relay, `crate::localctl::daemon::local_stream_relay_kind`).
#[tokio::test]
async fn open_data_link_for_exec_data_on_a_reverse_session_opens_its_stream_on_the_same_daemon_socket_and_host()
 {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("reverse-exec.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        // First conduit: LOCAL_CONTROL, exactly what
        // `dial_reverse`/`open_control` produce.
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let hello: LocalHello = control.recv().await.unwrap().unwrap();
        assert_eq!(hello.kind, LocalStreamKind::LocalControl as i32);
        assert_eq!(hello.host, "phone");
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:1111111111111111111111111111111111111111111"
                        .to_string(),
                    generation: 1,
                    capabilities: vec![wire::CAP_EXEC.to_string()],
                })),
            })
            .await
            .unwrap();

        // The control phase of `exec`: an `ExecStart` request over the
        // same conduit, answered with an `ExecStarted` ticket — exactly
        // what `crate::localctl::mux::classify`'s own
        // `MessageKind::Request` already relayed before issue #5, which
        // changes nothing about this control leg (only `EXEC_DATA`'s
        // data leg below is new).
        let req: ControlMessage = control.recv().await.unwrap().unwrap();
        let request_id = req.request_id;
        assert!(matches!(
            req.body,
            Some(control_message::Body::ExecStart(_))
        ));
        control
            .send(&ControlMessage::new(
                request_id,
                control_message::Body::Response(wire::Response {
                    body: Some(response::Body::ExecStarted(ExecStarted {
                        exec_id: "e1".to_string(),
                        ticket: vec![9, 9, 9],
                    })),
                }),
            ))
            .await
            .unwrap();

        // Second conduit, same socket: LOCAL_STREAM carrying an
        // EXEC_DATA header — proves a fresh conduit to the *same*
        // daemon/host, not the control conduit reused or a QUIC
        // `open_bi()` this `Session` has no connection to make.
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let hello: LocalHello = data.recv().await.unwrap().unwrap();
        assert_eq!(hello.kind, LocalStreamKind::LocalStream as i32);
        assert_eq!(hello.host, "phone");
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:1111111111111111111111111111111111111111111".to_string(),
                generation: 1,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        let header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        assert_eq!(header.stream_kind(), Some(wire::StreamKind::ExecData));
        // `EXEC_DATA` gets an explicit ack before the splice
        // (`daemon::LocalStreamRelay::OpenBidiAndSplice`'s
        // `ack_before_splice` doc) — unlike `SESSION_DATA`, which stays
        // silent on success.
        data.send(&LocalResponse {
            body: Some(local_response::Body::ClaimGranted(
                qsh_proto::local::LocalClaimGranted {},
            )),
        })
        .await
        .unwrap();
        header.ticket
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let mut session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );

    let started = session.exec_start(&exec_spec()).await.unwrap();
    assert_eq!(started.ticket, vec![9, 9, 9]);
    let (_send, _recv, kill) = session
        .open_data_link(
            &StreamHeader::exec_data(started.ticket),
            wire::PRIORITY_EXEC_DATA,
        )
        .await
        .unwrap();
    // A live `LOCAL_STREAM` conduit, not the forward route's
    // synchronous no-op — `DataKillSwitch::kill`'s own doc.
    kill.kill();

    let seen_ticket = daemon.await.unwrap();
    assert_eq!(seen_ticket, vec![9, 9, 9]);
}

/// The same stale-route check [`open_attach_stream`](Session::open_attach_stream)
/// already inherits (`Session::open_local_data_link`'s own doc) applies
/// to `exec` too, now that both go through the same
/// [`Session::open_data_link`]: if the registration's `(peer_fingerprint,
/// generation)` the `LOCAL_STREAM` conduit's own ack reports disagrees
/// with what this `Session`'s `LOCAL_CONTROL` handshake recorded, the
/// data phase fails closed with a retryable `HOST_NOT_FOUND` rather
/// than redeeming the ticket against whatever now answers that name.
#[tokio::test]
async fn open_data_link_for_exec_data_on_a_reverse_session_fails_closed_when_the_registration_generation_changed()
 {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("reverse-exec-stale.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let _hello: LocalHello = control.recv().await.unwrap().unwrap();
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:2222222222222222222222222222222222222222222"
                        .to_string(),
                    generation: 1,
                    capabilities: vec![wire::CAP_EXEC.to_string()],
                })),
            })
            .await
            .unwrap();

        let req: ControlMessage = control.recv().await.unwrap().unwrap();
        let request_id = req.request_id;
        control
            .send(&ControlMessage::new(
                request_id,
                control_message::Body::Response(wire::Response {
                    body: Some(response::Body::ExecStarted(ExecStarted {
                        exec_id: "e1".to_string(),
                        ticket: vec![5, 5, 5],
                    })),
                }),
            ))
            .await
            .unwrap();

        // Second conduit, same socket and host — but its own ack
        // reports a *different* generation: the registration changed
        // (died and came back, or was superseded) between the two
        // handshakes.
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let _hello: LocalHello = data.recv().await.unwrap().unwrap();
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:2222222222222222222222222222222222222222222".to_string(),
                generation: 2,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        // `open_stream_over_inner` sends the header unconditionally
        // right after the ack, before this `Session`'s own stale-route
        // comparison ever runs (`crate::localctl::client`'s own doc) —
        // read it so this daemon task ends cleanly rather than racing
        // this connection's drop.
        let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        // `EXEC_DATA` always gets this ack before `open_stream_over_inner`
        // returns (`ack_before_splice`'s own doc) — sent here so the
        // client's stale-route check, which runs only after that
        // handshake completes, is what actually rejects this call, not
        // an unrelated handshake timeout.
        data.send(&LocalResponse {
            body: Some(local_response::Body::ClaimGranted(
                qsh_proto::local::LocalClaimGranted {},
            )),
        })
        .await
        .unwrap();
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let mut session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );

    let started = session.exec_start(&exec_spec()).await.unwrap();
    // Not `.unwrap_err()`: the `Ok` side holds `DataSend`/`DataRecv`,
    // which (like `localctl::client`'s own raw `UnixStream` halves)
    // has no `Debug` impl, so this matches instead.
    match session
        .open_data_link(
            &StreamHeader::exec_data(started.ticket),
            wire::PRIORITY_EXEC_DATA,
        )
        .await
    {
        Ok(_) => panic!("a changed registration generation must fail closed, not redeem"),
        Err(ClientError::Remote {
            code, retryable, ..
        }) => {
            assert_eq!(code, ErrorCode::HostNotFound);
            assert!(retryable, "a stale route must be retryable");
        }
        Err(other) => panic!("expected ClientError::Remote{{HostNotFound}}, got {other:?}"),
    }

    daemon.await.unwrap();
}

/// Issue #5's `pump_stdin` regression: a reverse `exec` whose command keeps
/// writing output *after* the local `stdin` has already reached EOF
/// must still succeed — `stdin` EOF has no stream-close meaning
/// (`pump_stdin`'s own doc): it sends exactly one application-level
/// `ExecFrame::StdinEof`, over the same `DataSend` the stdin pump task
/// keeps alive until `exec` itself returns, never
/// `finish()`/`shutdown()`s the underlying conduit. The fake daemon
/// here is the adversarial case that regresses if that stopped being
/// true: it deliberately answers the client's `Stdin`/`StdinEof`
/// frames with more `Stdout` *after* `StdinEof`, then only later sends
/// `ExecExit` — if anything on the client tore the conduit down (or
/// stopped reading) once its own `StdinEof` went out, this output
/// would never arrive and `exec` would hang or end early instead of
/// collecting it. Right after draining `StdinEof`, the fake daemon
/// also probes with a short-timeout read of its own: collecting the
/// output alone would not catch a regression where `exec` finishes its
/// `send` half but the daemon still relays `Stdout`/`ExecExit`
/// regardless (a read half, not a write half, is what carries that
/// output back) — the probe pins that the client's send half is still
/// open, not just that the output arrives.
#[tokio::test]
async fn exec_on_a_reverse_session_still_collects_output_sent_after_stdin_eof() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("reverse-exec-after-eof.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let _hello: LocalHello = control.recv().await.unwrap().unwrap();
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:3333333333333333333333333333333333333333333"
                        .to_string(),
                    generation: 1,
                    capabilities: vec![wire::CAP_EXEC.to_string()],
                })),
            })
            .await
            .unwrap();

        let req: ControlMessage = control.recv().await.unwrap().unwrap();
        let request_id = req.request_id;
        control
            .send(&ControlMessage::new(
                request_id,
                control_message::Body::Response(wire::Response {
                    body: Some(response::Body::ExecStarted(ExecStarted {
                        exec_id: "e1".to_string(),
                        ticket: vec![7, 7, 7],
                    })),
                }),
            ))
            .await
            .unwrap();

        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let _hello: LocalHello = data.recv().await.unwrap().unwrap();
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:3333333333333333333333333333333333333333333".to_string(),
                generation: 1,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        // `EXEC_DATA`'s own ack before the splice.
        data.send(&LocalResponse {
            body: Some(local_response::Body::ClaimGranted(
                qsh_proto::local::LocalClaimGranted {},
            )),
        })
        .await
        .unwrap();

        // Drain the client's stdin frames up through StdinEof.
        loop {
            let frame: ExecFrame = data.recv().await.unwrap().unwrap();
            if matches!(frame.body, Some(exec_frame::Body::StdinEof(_))) {
                break;
            }
        }

        // `pump_stdin`'s own doc: `StdinEof` is the one and only
        // stdin-end signal on the wire, and nothing on the normal path
        // ever half-closes `send` itself to mean the same thing. If
        // `exec` finished/shut down its `DataSend` right after
        // `StdinEof` went out, this conduit would already be at a
        // clean end from the daemon's side — a short-timeout read here
        // would see that immediately instead of timing out with
        // nothing more incoming.
        match tokio::time::timeout(Duration::from_millis(200), data.recv::<ExecFrame>()).await {
            Err(_elapsed) => {} // still open, nothing more incoming — expected
            Ok(Ok(None)) => panic!(
                "the client's LOCAL_STREAM send half closed right after StdinEof; \
                 pump_stdin must never half-close it on the normal path"
            ),
            Ok(Ok(Some(frame))) => panic!("unexpected extra frame from the client: {frame:?}"),
            Ok(Err(err)) => panic!("conduit error while probing for an early close: {err:?}"),
        }

        // Only now, after StdinEof, does more output arrive — the
        // exact ordering the client must not give up on.
        data.send(&ExecFrame::stdout(b"after eof".to_vec()))
            .await
            .unwrap();
        data.send(&ExecFrame::exec_exit(0, None)).await.unwrap();
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let mut session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );

    let stdin: Box<dyn AsyncRead + Send + Unpin> = Box::new(std::io::Cursor::new(b"hi".to_vec()));
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        session.exec(&exec_spec(), Some(stdin), None),
    )
    .await
    .expect("must not hang once StdinEof has gone out")
    .unwrap();
    assert_eq!(result.stdout, b"after eof");
    assert_eq!(result.exit_code, 0);

    daemon.await.unwrap();
}

/// A pre-issue-#5 `qsh listen` daemon rejects
/// `EXEC_DATA` on `LOCAL_STREAM` with a bare `INVALID_ARGUMENT` (its
/// `serve_stream` never heard of the kind) — the fake daemon here
/// answers exactly that, over a real `open_stream` handshake, and the
/// mapped [`ClientError`] must name the stale `qsh listen` daemon
/// rather than repeat the daemon's generic shape-check text verbatim,
/// so an operator sees the fix (restart/upgrade this machine's `qsh
/// listen`), not just the symptom. Must not hang either way.
#[tokio::test]
async fn exec_data_rejected_by_an_old_daemon_names_the_stale_qsh_listen() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("reverse-exec-old-daemon.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        // First conduit: LOCAL_CONTROL — what the test's own
        // `open_control` call below needs to build a `Session` at all.
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let _hello: LocalHello = control.recv().await.unwrap().unwrap();
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:3333333333333333333333333333333333333333333"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();

        // Second conduit: LOCAL_STREAM carrying the EXEC_DATA header —
        // this is the one an old daemon rejects.
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let _hello: LocalHello = data.recv().await.unwrap().unwrap();
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:3333333333333333333333333333333333333333333".to_string(),
                generation: 1,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        // The pre-issue-#5 `serve_stream`'s own literal refusal text
        // (`crate::localctl::daemon`, before `local_stream_relay_kind`
        // existed) — never inspected structurally by the mapping this
        // test pins, only by code + header kind.
        data.send(&LocalResponse {
            body: Some(local_response::Body::Error(
                qsh_proto::local::LocalError::from_code(
                    ErrorCode::InvalidArgument,
                    "LOCAL_STREAM's first frame must be a SESSION_DATA, TCP_CONNECT, or \
                     TCP_ACCEPTED StreamHeader",
                ),
            )),
        })
        .await
        .unwrap();
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        session.open_data_link(
            &StreamHeader::exec_data(vec![1, 2, 3]),
            wire::PRIORITY_EXEC_DATA,
        ),
    )
    .await
    .expect("an old daemon's rejection must be answered promptly, never hang");

    match result {
        Ok(_) => panic!("an old daemon's INVALID_ARGUMENT must not be read as success"),
        Err(ClientError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::InvalidArgument);
            assert!(
                message.contains("qsh listen") && message.contains("restart"),
                "message must name the stale `qsh listen` daemon and its fix: {message}"
            );
        }
        Err(other) => panic!("expected ClientError::Remote{{InvalidArgument}}, got {other:?}"),
    }

    daemon.await.unwrap();
}

/// `AttachHandle::detach` on the reverse route ends the attach's own
/// `LOCAL_STREAM` conduit synchronously — no connection, no runtime,
/// no cooperation from the daemon needed (`DataKillSwitch::kill`'s own
/// doc). Killing it must be a clean, typed end of conduit on the
/// reader's side, never a panic or a hang.
#[tokio::test]
async fn killing_a_reverse_attachs_data_conduit_ends_the_reader_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("reverse-kill.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let daemon = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut control = LocalConduit::new(stream);
        let _hello: LocalHello = control.recv().await.unwrap().unwrap();
        control
            .send(&LocalResponse {
                body: Some(local_response::Body::HelloAck(LocalHelloAck {
                    host: "phone".to_string(),
                    peer_fingerprint: "sha256:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        .to_string(),
                    generation: 1,
                    capabilities: Vec::new(),
                })),
            })
            .await
            .unwrap();

        let (stream, _addr) = listener.accept().await.unwrap();
        let mut data = LocalConduit::new(stream);
        let _hello: LocalHello = data.recv().await.unwrap().unwrap();
        data.send(&LocalResponse {
            body: Some(local_response::Body::HelloAck(LocalHelloAck {
                host: "phone".to_string(),
                peer_fingerprint: "sha256:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string(),
                generation: 1,
                capabilities: Vec::new(),
            })),
        })
        .await
        .unwrap();
        let _header: wire::StreamHeader = data.recv().await.unwrap().unwrap();
        // Never write, never close from this side — the reader on the
        // other end must unblock from `kill()` alone.
        std::future::pending::<()>().await
    });

    let handshake = crate::localctl::client::open_control(&sock, "phone", 0, None)
        .await
        .unwrap();
    let mut session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        sock.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );
    let attached = session
        .open_attach_stream(wire::SessionAttached {
            ticket: vec![1],
            new_resume_token: Vec::new(),
            replay_from: 0,
            writer_lease: true,
            expires_at: String::new(),
            input_seq: 0,
        })
        .await
        .unwrap();
    let kill = attached.kill.clone();
    let (_writer, mut reader) = attached.split();

    kill.kill();
    let end = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("kill() must unblock the reader promptly, not hang");
    assert!(
        end.unwrap().is_none(),
        "a killed conduit must end cleanly, not error"
    );

    daemon.abort();
}
