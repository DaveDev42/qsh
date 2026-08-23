//! L3 — the `LOCAL_CONTROL` relay end to end (`PLAN.md` M3 Step 6,
//! `docs/design/protocol.md` §11-3's "다중화 규칙"): a real
//! [`qsh_testkit::reverse::ReverseHarness`] target, a real
//! `crate::localctl::daemon::LocalctlDaemon` bound via
//! [`ReverseHarness::attach_localctl`], and one or more raw `LOCAL_CONTROL`
//! conduits driven directly at the `qsh.local.v1`/`qsh.wire.v1` frame level
//! (no `Ops`/CLI layer — that routing seam is a different stage's work;
//! this file only proves the daemon's own multiplex-and-relay state
//! machine, `crate::reverse::listen::ControlHub` +
//! `crate::localctl::mux::ControlMux`).
//!
//! `#![cfg(unix)]`: localctl (UDS) and `ReverseHarness::attach_localctl`
//! are both unix-only (`qsh_core::localctl` compiles out on Windows,
//! `docs/CLI.md` §6.13) — same gating `host_list_reverse.rs` uses for the
//! same reason.

#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::localctl::frame::LocalConduit;
use qsh_core::{Paths, Principal};
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalHello, LocalResponse, LocalStreamKind, local_response,
};
use qsh_proto::wire::{self, control_message, response};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_transport::StaticTrust;
use tokio::net::UnixStream;

/// Bound on every "this must have already happened" wait in this file —
/// same order of magnitude as `reverse_loopback.rs`'s own `TIMEOUT`.
const TIMEOUT: Duration = Duration::from_secs(5);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// Fresh, throwaway [`Paths`] — this file never touches `trust.toml`
/// (no `Ops`, module docs), so only `runtime_dir()` (what
/// [`ReverseHarness::attach_localctl`] binds its socket under) matters.
fn fresh_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, paths)
}

/// Connect a fresh `LOCAL_CONTROL` conduit for `host` and consume its
/// `LocalHelloAck` — the raw handshake every real caller (a future `Ops`
/// link, this file's own tests) performs identically.
async fn connect_control(socket_path: &Path, host: &str) -> LocalConduit<UnixStream> {
    let stream = UnixStream::connect(socket_path)
        .await
        .expect("connect localctl socket");
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalControl as i32,
            host: host.to_string(),
            wait_ms: 0,
        })
        .await
        .expect("send LocalHello");
    let ack: LocalResponse = conduit
        .recv()
        .await
        .expect("recv LocalHelloAck")
        .expect("conduit stayed open for the ack");
    match ack.body {
        Some(local_response::Body::HelloAck(_)) => {}
        other => panic!("expected LocalHelloAck, got {other:?}"),
    }
    conduit
}

async fn send(
    conduit: &mut LocalConduit<UnixStream>,
    request_id: u64,
    body: control_message::Body,
) {
    conduit
        .send(&wire::ControlMessage::new(request_id, body))
        .await
        .expect("send ControlMessage");
}

async fn recv(conduit: &mut LocalConduit<UnixStream>) -> wire::ControlMessage {
    conduit
        .recv()
        .await
        .expect("recv ControlMessage")
        .expect("conduit stayed open")
}

fn open_sh() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".to_string()],
        env: Default::default(),
        term: String::new(),
        cols: 0,
        rows: 0,
        user: None,
    }
}

/// Two independent `LOCAL_CONTROL` conduits for the same host, each
/// minting the identical `peer_request_id` (`docs/design/protocol.md`
/// §11-3: "여러 CLI 프로세스가 같은 QUIC connection을 공유하므로 채번 공간이
/// 겹칠 수 있다") — the daemon must remap each onto its own
/// `daemon_request_id` and route the reply back to the conduit that asked,
/// never crossing them.
#[tokio::test(flavor = "multi_thread")]
async fn two_conduits_with_the_same_peer_request_id_each_get_their_own_reply() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let mut a = connect_control(&localctl.socket_path, "widget").await;
        let mut b = connect_control(&localctl.socket_path, "widget").await;

        // Deliberately different request *shapes* under the same
        // peer_request_id, not just different conduits sending the
        // byte-identical body: two `SessionList` replies are
        // indistinguishable from each other, so a daemon bug that swapped
        // `ra`/`rb` between conduits would leave every assertion on the
        // original version of this test passing (adversarial review
        // finding). `SessionListResult` vs. `SessionOpened` are different
        // `Response` variants — a crossed reply fails the `matches!` below
        // outright rather than silently passing.
        send(
            &mut a,
            7,
            control_message::Body::SessionList(wire::SessionList {}),
        )
        .await;
        send(&mut b, 7, control_message::Body::SessionOpen(open_sh())).await;

        let ra = recv(&mut a).await;
        let rb = recv(&mut b).await;

        assert_eq!(
            ra.request_id, 7,
            "conduit a's own peer_request_id must come back unchanged"
        );
        assert_eq!(
            rb.request_id, 7,
            "conduit b's own peer_request_id must come back unchanged"
        );
        assert!(
            matches!(
                &ra.body,
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::SessionListResult(_)),
                    ..
                }))
            ),
            "conduit a must get its own SessionListResult, got {:?} \
             (a SessionOpened here would mean b's reply crossed to a)",
            ra.body
        );
        assert!(
            matches!(
                &rb.body,
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::SessionOpened(_)),
                    ..
                }))
            ),
            "conduit b must get its own SessionOpened, got {:?} \
             (a SessionListResult here would mean a's reply crossed to b)",
            rb.body
        );

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// A `Ping` on a `LOCAL_CONTROL` conduit is answered locally with a `Pong`
/// — never forwarded onto the reverse QUIC connection
/// (`docs/design/protocol.md` §11-3: "liveness는 연결을 실제로 쥔 데몬의
/// 몫"). Proven black-box (the conduit gets a bare `Pong`, not a
/// `Response`, for the exact `request_id` it sent) plus a same-conduit
/// follow-up `session.list` to show the conduit — and the multiplexer's
/// request table underneath it — is unaffected; `crate::localctl::mux`'s
/// own `ping_classifies_separately_from_every_request_body` unit test is
/// the direct proof that `classify` pulls `Ping` out before
/// `ControlMux::map_outbound` is ever called, so nothing here duplicates
/// that at the pure-state-machine level.
#[tokio::test(flavor = "multi_thread")]
async fn ping_on_a_conduit_is_answered_locally_with_pong() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
        let mut conduit = connect_control(&localctl.socket_path, "widget").await;

        send(&mut conduit, 42, control_message::Body::Ping(wire::Ping {})).await;
        let reply = recv(&mut conduit).await;
        assert_eq!(reply.request_id, 42);
        assert!(
            matches!(reply.body, Some(control_message::Body::Pong(_))),
            "expected a bare Pong, got {:?}",
            reply.body
        );

        send(
            &mut conduit,
            1,
            control_message::Body::SessionList(wire::SessionList {}),
        )
        .await;
        let list_reply = recv(&mut conduit).await;
        assert_eq!(list_reply.request_id, 1);
        assert!(
            matches!(
                list_reply.body,
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::SessionListResult(_)),
                    ..
                }))
            ),
            "the conduit must still work normally after a Ping, got {:?}",
            list_reply.body
        );

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// A conduit dying with a request genuinely in flight (a long-poll
/// `session.read` the target has nothing to answer yet) leaves the
/// multiplexer's table for it empty — `ControlHub::unregister_conduit`'s
/// contract (`docs/design/protocol.md` §11-3: "conduit이 죽으면... 대응
/// QUIC 스트림 쪽 작업을 reset/취소"), observed through
/// [`qsh_core::reverse::listen::Listen::control_hub`]'s
/// `total_in_flight` diagnostic rather than a private `ConduitId`.
#[tokio::test(flavor = "multi_thread")]
async fn a_dying_conduits_in_flight_entry_is_fully_removed() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
        let hub = harness
            .listen
            .control_hub("widget")
            .expect("a live registration must have a hub");
        assert_eq!(hub.total_in_flight(), 0);

        let mut dying = connect_control(&localctl.socket_path, "widget").await;

        send(&mut dying, 1, control_message::Body::SessionOpen(open_sh())).await;
        let opened = recv(&mut dying).await;
        let session_id = match opened.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::SessionOpened(o)),
                ..
            })) => o.session_id,
            other => panic!("expected SessionOpened, got {other:?}"),
        };

        // Drain whatever the freshly-opened shell has already written (its
        // prompt) and learn the current output cursor, so the long-poll
        // below has genuinely nothing to answer and stays in flight rather
        // than being satisfied the instant it arrives. A read anchored at
        // `after: 0` returns immediately whenever any output already
        // exists — the initial prompt does — which raced the in-flight
        // assertion into a flake (the read round-tripped before the 2 ms
        // poll ever observed it outstanding, consistently on faster CI
        // runners). This drain is bounded, not a fixed sleep.
        send(
            &mut dying,
            2,
            control_message::Body::SessionRead(wire::SessionRead {
                session_id: session_id.clone(),
                after: 0,
                max_bytes: 0,
                wait_ms: 200,
                ctl_after: 0,
            }),
        )
        .await;
        let next_after = match recv(&mut dying).await.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::SessionReadResult(result)),
                ..
            })) => result.next_after,
            other => panic!("expected a SessionReadResult draining initial output, got {other:?}"),
        };

        // Now a long-poll starting *past* everything the session has
        // produced so far: an idle shell writes nothing more, so this is
        // genuinely in flight on this conduit until the conduit dies —
        // fire-and-forget, deliberately never read.
        send(
            &mut dying,
            3,
            control_message::Body::SessionRead(wire::SessionRead {
                session_id,
                after: next_after,
                max_bytes: 0,
                wait_ms: 5_000,
                ctl_after: 0,
            }),
        )
        .await;

        wait_for(TIMEOUT, || (hub.total_in_flight() >= 1).then_some(())).await;

        drop(dying); // the conduit dies mid-request

        wait_for(TIMEOUT, || (hub.total_in_flight() == 0).then_some(())).await;

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// The reverse QUIC connection dying (here: `run_target`'s own clean
/// shutdown, which closes it — `target.rs`'s `conn.close(0, b"shutdown")`)
/// ends every `LOCAL_CONTROL` conduit of that host together, each with a
/// clean EOF on its UDS stream — `ControlHub::mark_dead`'s
/// `ConduitInbound::HostDead` teardown
/// (`docs/design/protocol.md` §11-3: "그 host의 모든 conduit이 명확한
/// typed error로 함께 끝난다").
#[tokio::test(flavor = "multi_thread")]
async fn severing_the_quic_connection_ends_every_conduit_of_that_host() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let mut a = connect_control(&localctl.socket_path, "widget").await;
        let mut b = connect_control(&localctl.socket_path, "widget").await;

        let _ = shutdown_tx.send(());

        for (who, conduit) in [("a", &mut a), ("b", &mut b)] {
            let result = tokio::time::timeout(TIMEOUT, conduit.recv::<wire::ControlMessage>())
                .await
                .unwrap_or_else(|_| panic!("conduit {who} must close within the timeout"));
            assert!(
                matches!(result, Ok(None) | Err(_)),
                "conduit {who} must end with EOF/error once the host dies, got {result:?}"
            );
        }
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}
