//! Transport conformance suite (`docs/adr/0028-tcp-tls-fallback.md`
//! decision 0): the behavior every `qsh-transport` backend must show through
//! the public [`Connection`] / [`SendStream`] / [`RecvStream`] facades.
//!
//! The behaviors are written once, in [`transport_conformance!`], and
//! instantiated per backend with a function that yields a connected pair.
//! Today that is QUIC only; a second backend adds one more line at the
//! bottom and inherits the whole list. This is a conformance list and not a
//! mock: both ends are real connections over real sockets
//! (`docs/design/testing.md` L4).
//!
//! Callers depend on these behaviors, and each test names the one it pins:
//! the tunnel splice guard relies on drop-is-FIN, the denial teardown in
//! `docs/design/protocol.md` §7 relies on stop and reset codes being
//! visible, and the server loops rely on `accept_bi` being cancel-safe.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use qsh_transport::endpoint::MAX_CONCURRENT_BIDI_STREAMS;
use qsh_transport::{
    CertificateDer, Connection, ConnectionError, Dialer, Fingerprint, Listener, LocalIdentity,
    Principal, ReadError, ReadToEndError, StaticTrust, StreamCode, TransportKind, WriteError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long a behavior may take before the test calls it a hang.
const DEADLINE: Duration = Duration::from_secs(10);
/// How long "nothing happens" is observed for.
const QUIET: Duration = Duration::from_millis(200);

/// A connected pair plus whatever must outlive it (listener, endpoint).
struct Pair {
    client: Connection,
    server: Connection,
    _keep: Box<dyn Any + Send>,
}

fn make_identity() -> (LocalIdentity, Fingerprint) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let fp = Fingerprint::of_cert_der(&der).unwrap();
    (
        LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        },
        fp,
    )
}

/// Two pinned peers over loopback QUIC.
async fn quic_pair() -> Pair {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("client".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("server".into()));
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_id,
        Arc::new(server_trust),
    )
    .unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let incoming = listener.accept().await.expect("one connection");
        let conn = incoming.accept().await.expect("server handshake");
        (listener, conn)
    });
    let dialer = Dialer::new(client_id, Arc::new(client_trust));
    let dialed = dialer.dial(addr, "127.0.0.1").await.expect("dial");
    let (listener, server) = accept.await.unwrap();
    Pair {
        client: dialed.connection.clone(),
        server,
        _keep: Box::new((listener, dialed)),
    }
}

async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, fut)
        .await
        .expect("behavior did not complete in time")
}

macro_rules! transport_conformance {
    ($backend:ident, $pair:ident, $kind:expr) => {
        mod $backend {
            use super::*;

            #[tokio::test]
            async fn reports_its_transport_kind_and_a_stable_id() {
                let p = $pair().await;
                assert_eq!(p.client.transport_kind(), $kind);
                assert_eq!(p.server.transport_kind(), $kind);
                assert_eq!(p.client.stable_id(), p.client.clone().stable_id());
                assert_ne!(p.client.stable_id(), p.server.stable_id());
            }

            /// `finish` is a half-close: the peer reads to end-of-stream and
            /// can still answer on the other direction.
            #[tokio::test]
            async fn finish_is_a_half_close() {
                let p = $pair().await;
                let (mut c_send, mut c_recv) = within(p.client.open_bi()).await.unwrap();
                c_send.write_all(b"ping").await.unwrap();
                c_send.finish().unwrap();
                assert!(c_send.finish().is_err(), "a second finish is ClosedStream");

                let (mut s_send, mut s_recv) = within(p.server.accept_bi()).await.unwrap();
                assert_eq!(within(s_recv.read_to_end(16)).await.unwrap(), b"ping");
                s_send.write_all(b"pong").await.unwrap();
                s_send.finish().unwrap();
                assert_eq!(within(c_recv.read_to_end(16)).await.unwrap(), b"pong");
            }

            /// Dropping a `SendStream` that was neither finished nor reset is
            /// a clean FIN (the tunnel `SpliceGuard` relies on it).
            #[tokio::test]
            async fn dropping_a_send_half_is_a_clean_fin() {
                let p = $pair().await;
                let (mut c_send, _c_recv) = within(p.client.open_bi()).await.unwrap();
                c_send.write_all(b"x").await.unwrap();
                drop(c_send);

                let (_s_send, mut s_recv) = within(p.server.accept_bi()).await.unwrap();
                assert_eq!(within(s_recv.read_to_end(16)).await.unwrap(), b"x");
                let mut buf = [0u8; 4];
                assert_eq!(within(s_recv.read(&mut buf)).await.unwrap(), None);
            }

            /// Dropping a `RecvStream` before end-of-stream is a stop with
            /// code 0, which the writer sees as `WriteError::Stopped(0)`.
            #[tokio::test]
            async fn dropping_a_recv_half_stops_the_writer_with_code_zero() {
                let p = $pair().await;
                let (mut c_send, _c_recv) = within(p.client.open_bi()).await.unwrap();
                c_send.write_all(b"x").await.unwrap();
                let (_s_send, s_recv) = within(p.server.accept_bi()).await.unwrap();
                drop(s_recv);

                let err = within(async {
                    loop {
                        if let Err(err) = c_send.write_all(&[0u8; 1024]).await {
                            break err;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await;
                assert_eq!(err, WriteError::Stopped(StreamCode::from_u32(0)));
            }

            /// A stop code is the writer's `Stopped(code)`, and the same code
            /// resolves `stopped()` (the denial teardown in
            /// `docs/design/protocol.md` §7 depends on both).
            #[tokio::test]
            async fn a_stop_code_is_visible_to_the_writer() {
                let p = $pair().await;
                let (mut c_send, _c_recv) = within(p.client.open_bi()).await.unwrap();
                c_send.write_all(b"x").await.unwrap();
                let stopped = c_send.stopped();
                let (_s_send, mut s_recv) = within(p.server.accept_bi()).await.unwrap();
                s_recv.stop(StreamCode::from_u32(7)).unwrap();

                assert_eq!(
                    within(stopped).await.unwrap(),
                    Some(StreamCode::from_u32(7))
                );
                let err = within(async {
                    loop {
                        if let Err(err) = c_send.write_all(&[0u8; 1024]).await {
                            break err;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await;
                assert_eq!(err, WriteError::Stopped(StreamCode::from_u32(7)));
            }

            /// `reset` discards unsent data and its code is the reader's
            /// `Reset(code)`: the reader never sees a clean end-of-stream.
            #[tokio::test]
            async fn a_reset_discards_unsent_data_and_its_code_is_visible_to_the_reader() {
                let p = $pair().await;
                let (mut c_send, _c_recv) = within(p.client.open_bi()).await.unwrap();
                // Far more than one stream window, so some of it is unsent.
                let big = vec![0xa5u8; 16 * 1024 * 1024];
                let accepted = within(c_send.write(&big)).await.unwrap();
                assert!(
                    accepted < big.len(),
                    "the whole payload cannot be in flight"
                );
                c_send.reset(StreamCode::from_u32(9)).unwrap();
                assert!(
                    c_send.finish().is_err(),
                    "a reset stream cannot be finished"
                );

                let (_s_send, mut s_recv) = within(p.server.accept_bi()).await.unwrap();
                match within(s_recv.read_to_end(usize::MAX)).await {
                    Err(ReadToEndError::Read(ReadError::Reset(code))) => {
                        assert_eq!(code, StreamCode::from_u32(9));
                    }
                    other => panic!("expected a reset, got {other:?}"),
                }
            }

            /// The send priority hint is accepted and read back.
            #[tokio::test]
            async fn a_priority_hint_is_accepted() {
                let p = $pair().await;
                let (c_send, _c_recv) = within(p.client.open_bi()).await.unwrap();
                assert!(p.client.caps().send_priority);
                c_send.set_priority(200).unwrap();
                assert_eq!(c_send.priority().unwrap(), 200);
                c_send.set_priority(-3).unwrap();
                assert_eq!(c_send.priority().unwrap(), -3);
            }

            /// `accept_bi` is used inside `tokio::select!`; a dropped future
            /// must not lose a stream (server loop, remote-forward acceptor,
            /// registration loop).
            #[tokio::test]
            async fn accept_bi_is_cancel_safe() {
                let p = $pair().await;
                let client = p.client.clone();
                let opener = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    let mut held = Vec::new();
                    for i in 0u8..3 {
                        let (mut send, recv) = client.open_bi().await.unwrap();
                        send.write_all(&[i]).await.unwrap();
                        held.push((send, recv));
                    }
                    held
                });

                let mut got = Vec::new();
                within(async {
                    while got.len() < 3 {
                        match tokio::time::timeout(Duration::from_millis(1), p.server.accept_bi())
                            .await
                        {
                            Ok(Ok(pair)) => got.push(pair),
                            Ok(Err(err)) => panic!("accept_bi failed: {err}"),
                            Err(_) => {} // cancelled; must not have consumed a stream
                        }
                    }
                })
                .await;
                let mut firsts = Vec::new();
                for (_send, recv) in &mut got {
                    let mut byte = [0u8; 1];
                    recv.read_exact(&mut byte).await.unwrap();
                    firsts.push(byte[0]);
                }
                firsts.sort_unstable();
                assert_eq!(firsts, [0, 1, 2]);
                drop(opener.await.unwrap());
            }

            /// A pending `accept_bi` fails with the peer's close code when
            /// the peer closes.
            #[tokio::test]
            async fn a_peer_close_fails_a_pending_accept_with_its_code() {
                let p = $pair().await;
                let server = p.server.clone();
                let pending = tokio::spawn(async move { server.accept_bi().await });
                tokio::time::sleep(Duration::from_millis(20)).await;
                p.client.close(7, b"bye");
                let err = within(pending).await.unwrap().unwrap_err();
                assert_eq!(err.application_code(), Some(7));
            }

            /// `close` is idempotent (the first code wins), `closed()`
            /// resolves for the local and the peer side, and a clean close
            /// reaches the peer as `ApplicationClosed(code)`.
            #[tokio::test]
            async fn close_is_idempotent_and_closed_resolves_on_both_sides() {
                let p = $pair().await;
                assert!(p.client.close_reason().is_none());
                p.client.close(42, b"bye");
                p.client.close(43, b"again");

                let peer_view = within(p.server.closed()).await;
                assert_eq!(peer_view.application_code(), Some(42));
                assert!(peer_view.is_application_closed());
                assert_eq!(
                    within(p.client.closed()).await,
                    ConnectionError::LocallyClosed
                );
                assert!(p.client.close_reason().is_some());
                assert!(p.server.close_reason().is_some());
            }

            /// With every stream slot taken, `open_bi` waits for one rather
            /// than failing, a cancelled wait opens nothing, and finishing a
            /// stream on both sides frees its slot.
            #[tokio::test]
            async fn a_full_stream_table_makes_open_bi_wait_for_a_slot() {
                let p = $pair().await;
                let n = MAX_CONCURRENT_BIDI_STREAMS as usize;
                let mut client_side = Vec::with_capacity(n);
                let mut server_side = Vec::with_capacity(n);
                within(async {
                    for _ in 0..n {
                        let (mut send, recv) = p.client.open_bi().await.unwrap();
                        send.write_all(b"x").await.unwrap();
                        client_side.push((send, recv));
                    }
                    for _ in 0..n {
                        server_side.push(p.server.accept_bi().await.unwrap());
                    }
                })
                .await;

                assert!(
                    tokio::time::timeout(QUIET, p.client.open_bi())
                        .await
                        .is_err(),
                    "open_bi must wait while {n} streams are open"
                );

                // Finish a quarter of the table in both directions. A backend
                // may hand slots back in batches (QUIC announces a new limit
                // once an eighth of the window has been freed), so one
                // finished stream is not enough to promise a free slot.
                for _ in 0..n / 4 {
                    let (mut c_send, mut c_recv) = client_side.swap_remove(0);
                    let (mut s_send, mut s_recv) = server_side.swap_remove(0);
                    c_send.finish().unwrap();
                    s_send.finish().unwrap();
                    within(s_recv.read_to_end(16)).await.unwrap();
                    within(c_recv.read_to_end(16)).await.unwrap();
                    // Both ends are done with the stream: drop the handles so
                    // the transport can retire it.
                    drop((c_send, c_recv, s_send, s_recv));
                }

                let (mut send, _recv) = within(p.client.open_bi()).await.unwrap();
                send.write_all(b"y").await.unwrap();
                let (_s_send, mut s_recv) = within(p.server.accept_bi()).await.unwrap();
                let mut byte = [0u8; 1];
                s_recv.read_exact(&mut byte).await.unwrap();
                assert_eq!(&byte, b"y");
                assert!(
                    tokio::time::timeout(QUIET, p.server.accept_bi())
                        .await
                        .is_err(),
                    "the cancelled open_bi must not have produced a stream"
                );
            }
        }
    };
}

transport_conformance!(quic, quic_pair, TransportKind::Quic);

/// `AsyncRead`/`AsyncWrite` on the facades reach the same stream the
/// inherent methods do (the splice and the PTY pump use the trait form).
#[tokio::test]
async fn the_async_io_form_agrees_with_the_inherent_form() {
    let p = quic_pair().await;
    let (mut c_send, mut c_recv) = within(p.client.open_bi()).await.unwrap();
    AsyncWriteExt::write_all(&mut c_send, b"via-trait")
        .await
        .unwrap();
    AsyncWriteExt::shutdown(&mut c_send).await.unwrap();
    let (mut s_send, mut s_recv) = within(p.server.accept_bi()).await.unwrap();
    let mut got = Vec::new();
    within(AsyncReadExt::read_to_end(&mut s_recv, &mut got))
        .await
        .unwrap();
    assert_eq!(got, b"via-trait");
    s_send.write_all(b"back").await.unwrap();
    s_send.finish().unwrap();
    assert_eq!(within(c_recv.read_to_end(16)).await.unwrap(), b"back");
}
