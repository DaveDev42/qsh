//! L3 — the `LOCAL_STREAM` splice end to end (`PLAN.md` M3 Step 7,
//! `docs/design/protocol.md` §11-3): a real
//! [`qsh_testkit::reverse::ReverseHarness`] target, a real
//! `crate::localctl::daemon::LocalctlDaemon` bound via
//! [`ReverseHarness::attach_localctl`], one raw `LOCAL_CONTROL` conduit to
//! mint tickets exactly as `local_control_reverse.rs` does, and one or more
//! raw `LOCAL_STREAM` conduits driven directly at the `qsh.local.v1`/
//! `qsh.wire.v1` frame level (no `Ops`/CLI layer — same division of labor
//! `local_control_reverse.rs`'s own module docs draw).
//!
//! What this file proves, concretely:
//!
//! - a `SESSION_DATA` ticket minted by a real `session.open` over
//!   `LOCAL_CONTROL`, redeemed on a fresh `LOCAL_STREAM` conduit, actually
//!   reaches a real PTY on the target — an `Input` frame containing `echo
//!   <marker>` comes back out as `Output` containing `<marker>`, proving
//!   the daemon's raw byte splice preserves `qsh.wire.v1` framing exactly
//!   (`crate::localctl::daemon::LocalctlDaemon::serve_stream`'s own doc:
//!   "never parses a `SessionFrame`");
//! - once the session exits, the spliced stream carries the `Exit` frame
//!   through and then ends cleanly — the target-initiated half of HARD
//!   RULES' "QUIC FIN/reset -> UDS shutdown" propagated all the way to the
//!   client's own conduit read, not just to the daemon's log;
//! - a ticket nobody issued is the target's own rejection (`RESET_CODE_BAD_HEADER`,
//!   `crate::server::mod`'s `handle_data_stream`), relayed through the
//!   splice as an unhurried, bounded end of conduit — never a hang. The
//!   daemon itself never inspects `ticket` at all (module docs' "grants no
//!   new authority"): this is proof that a *forged* ticket is rejected
//!   *somewhere* downstream, promptly, not proof of exactly where.
//!
//! What this file deliberately does **not** attempt: proving that closing
//! the client's own `LOCAL_STREAM` conduit *alone* ends the target's data
//! stream. `crate::session_stream`'s pre-existing (M2) `run_inner` already
//! documents why that doesn't hold for an idle PTY on its own — "The peer
//! finished its send half — but it is still owed its output, so the stream
//! lives until the output pump is done" — and the writer lease itself is
//! released only at whole-connection teardown
//! (`crate::server::Server::purge_connection`), not at a single spliced
//! stream's end, since every `LOCAL_STREAM` conduit for a host shares that
//! host's one reverse connection. That coincidence has always been masked
//! for a forward attach (one dedicated connection per attach); Step 7 does
//! not change it, and this file does not claim otherwise. What *is* proven
//! here — the target-initiated direction, via a real session exit — is the
//! honest, hang-free version of "the stream ends and the client's conduit
//! sees it."
//!
//! `#![cfg(unix)]`: localctl (UDS) and `ReverseHarness::attach_localctl`
//! are both unix-only (`qsh_core::localctl` compiles out on Windows,
//! `docs/CLI.md` §6.13) — same gating `local_control_reverse.rs` uses for
//! the same reason.

#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::localctl::frame::LocalConduit;
use qsh_core::server::TICKET_LEN;
use qsh_core::{Paths, Principal};
use qsh_proto::ErrorCode;
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalHello, LocalResponse, LocalStreamKind, local_response,
};
use qsh_proto::wire::{self, control_message, response, session_frame};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_transport::StaticTrust;
use tokio::net::UnixStream;

/// Bound on every "this must have already happened" wait in this file —
/// generous relative to `local_control_reverse.rs`'s own `TIMEOUT` since a
/// real fork/exec PTY and two relay hops (UDS + QUIC) are involved, not a
/// pure in-memory relay.
const TIMEOUT: Duration = Duration::from_secs(15);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// Fresh, throwaway [`Paths`] — this file never touches `trust.toml` (no
/// `Ops`, module docs), so only `runtime_dir()` (what
/// [`ReverseHarness::attach_localctl`] binds its socket under) matters.
fn fresh_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, paths)
}

/// Connect a fresh `LOCAL_CONTROL` conduit for `host` and consume its
/// `LocalHelloAck` — identical to `local_control_reverse.rs`'s own helper
/// of the same name (each test binary is its own crate; there is no shared
/// support module for these small wire-level helpers to live in).
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
            known_generation: None,
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

/// Connect a fresh `LOCAL_STREAM` conduit for `host` and consume its
/// `LocalHelloAck` — [`connect_control`]'s twin, `kind` is the only
/// difference (`crate::localctl::daemon`'s module docs: both conduit kinds
/// answer the identical ack shape).
async fn connect_stream(socket_path: &Path, host: &str) -> LocalConduit<UnixStream> {
    let stream = UnixStream::connect(socket_path)
        .await
        .expect("connect localctl socket");
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalStream as i32,
            host: host.to_string(),
            wait_ms: 0,
            known_generation: None,
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

async fn send_control(
    conduit: &mut LocalConduit<UnixStream>,
    request_id: u64,
    body: control_message::Body,
) {
    conduit
        .send(&wire::ControlMessage::new(request_id, body))
        .await
        .expect("send ControlMessage");
}

/// Read the next `ControlMessage` off `ctl`, skipping over any spontaneous
/// `SessionEvent` (`request_id = 0`, host → attached client) that lands
/// interleaved with a request/response — the `LOCAL_STREAM` conduit
/// redeeming its ticket on the very next line broadcasts exactly one of
/// these (`WriterChanged`) to every registered `LOCAL_CONTROL` conduit on
/// this host, `ctl` included, regardless of ordering relative to whatever
/// request `ctl` itself has in flight (`crate::localctl::mux`'s own
/// `writer_changed_broadcasts_to_every_registered_conduit_including_non_subscribers`).
async fn recv_control_response(conduit: &mut LocalConduit<UnixStream>) -> wire::ControlMessage {
    loop {
        let msg: wire::ControlMessage = conduit
            .recv()
            .await
            .expect("recv ControlMessage")
            .expect("conduit stayed open");
        if matches!(msg.body, Some(control_message::Body::SessionEvent(_))) {
            continue;
        }
        return msg;
    }
}

/// A real interactive shell, sized for canonical-mode PTY echo — the same
/// shape `attach_loopback.rs`'s own `open_req()` uses, so typed input is
/// actually echoed back through `Output` the way a real terminal would.
fn open_sh() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".to_string()],
        term: "xterm-256color".to_string(),
        cols: 80,
        rows: 24,
        ..Default::default()
    }
}

async fn open_session(ctl: &mut LocalConduit<UnixStream>, request_id: u64) -> wire::SessionOpened {
    send_control(
        ctl,
        request_id,
        control_message::Body::SessionOpen(open_sh()),
    )
    .await;
    let reply = recv_control_response(ctl).await;
    assert_eq!(reply.request_id, request_id);
    match reply.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::SessionOpened(opened)),
            ..
        })) => opened,
        other => panic!("expected SessionOpened, got {other:?}"),
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Read `SessionFrame`s off `data` until `marker` has appeared somewhere in
/// the accumulated `Output` bytes, bounded by [`TIMEOUT`].
async fn read_until_output_contains(data: &mut LocalConduit<UnixStream>, marker: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let frame: wire::SessionFrame = data
                .recv()
                .await
                .expect("recv SessionFrame")
                .expect("stream ended before the marker arrived");
            if let Some(session_frame::Body::Output(o)) = frame.body {
                bytes.extend_from_slice(&o.data);
                if contains_subslice(&bytes, marker) {
                    return;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("marker {marker:?} did not arrive within {TIMEOUT:?}; got {bytes:?}")
    });
    bytes
}

/// The milestone's central L3 proof: a `SESSION_DATA` ticket minted by a
/// real `session.open` over `LOCAL_CONTROL`, redeemed on a fresh
/// `LOCAL_STREAM` conduit, splices through the daemon to a real PTY and
/// back — `Input` reaches the shell, its `Output` (echo + the command's own
/// stdout) reaches the client untouched — and once the session is closed,
/// the `Exit` frame and the stream's own clean end both make it back
/// through the same splice (module docs' "does not attempt" section
/// explains why this is the direction proven, not client-initiated
/// closure).
#[tokio::test(flavor = "multi_thread")]
async fn local_stream_splices_session_data_to_a_real_pty_and_relays_exit_cleanly() {
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

        let mut ctl = connect_control(&localctl.socket_path, "widget").await;
        let opened = open_session(&mut ctl, 1).await;

        let mut data = connect_stream(&localctl.socket_path, "widget").await;
        data.send(&wire::StreamHeader::session_data(opened.ticket.clone()))
            .await
            .expect("send StreamHeader");

        let marker = b"QSHPTYMARK";
        let input = b"echo QSHPTYMARK\n".to_vec();
        data.send(&wire::SessionFrame::input(input.len() as u64, input))
            .await
            .expect("send Input");

        let seen = read_until_output_contains(&mut data, marker).await;
        assert!(
            contains_subslice(&seen, marker),
            "the echoed command's output must reach the client through the splice: {seen:?}"
        );

        // Kill the session so the target's own output pump converges on
        // its own — see this file's module docs for why this, not a
        // client-initiated close, is the direction proven here.
        send_control(
            &mut ctl,
            2,
            control_message::Body::SessionClose(wire::SessionClose {
                session_id: opened.session_id.clone(),
                signal: None,
            }),
        )
        .await;
        let closed = recv_control_response(&mut ctl).await;
        assert!(
            matches!(
                closed.body,
                Some(control_message::Body::Response(wire::Response {
                    body: Some(response::Body::SessionClosed(_)),
                    ..
                }))
            ),
            "expected SessionClosed, got {:?}",
            closed.body
        );

        // The data stream — spliced through the daemon's `LOCAL_STREAM`
        // conduit exactly like every byte before it — must see the
        // session's `Exit` frame: the daemon's own splice never
        // distinguishes it from any other byte, so this also re-proves the
        // splice preserves ordering and framing all the way to the end.
        let saw_exit = tokio::time::timeout(TIMEOUT, async {
            loop {
                match data
                    .recv::<wire::SessionFrame>()
                    .await
                    .expect("recv SessionFrame")
                {
                    Some(frame) if matches!(frame.body, Some(session_frame::Body::Exit(_))) => {
                        return true;
                    }
                    Some(_) => continue,
                    None => return false,
                }
            }
        })
        .await
        .expect("Exit or a clean end arrives within the deadline");
        assert!(
            saw_exit,
            "the Exit frame must reach the client before the stream ends"
        );

        // Past `Exit` the target has nothing more to send — the daemon's
        // QUIC->UDS leg relays that FIN as a clean end of this conduit,
        // exactly like `LocalConduit::recv`'s own "clean end of conduit"
        // contract (HARD RULES: "QUIC FIN/reset -> UDS shutdown").
        let after_exit = tokio::time::timeout(TIMEOUT, data.recv::<wire::SessionFrame>())
            .await
            .expect("the conduit ends promptly once the target has nothing more to send")
            .expect("a clean end, not a framing error");
        assert!(
            after_exit.is_none(),
            "expected the conduit to end cleanly after Exit, got another frame: {after_exit:?}"
        );

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// HARD RULES: "the daemon never redeems or inspects the ticket — the
/// TARGET does (ticket misuse is the target's reset, relayed as-is)". A
/// ticket nobody ever issued must be rejected promptly — never treated as
/// redeemable, never a hang — even though the daemon itself does nothing
/// special to detect it (`crate::localctl::daemon::LocalctlDaemon::serve_stream`'s
/// own doc: it forwards the header verbatim and only ever becomes a raw
/// pump after that).
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_ticket_on_local_stream_is_rejected_promptly_never_a_hang() {
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

        let mut data = connect_stream(&localctl.socket_path, "widget").await;
        // Never minted by anything on the target — `redeem_ticket` cannot
        // possibly find it in its table.
        let forged_ticket = vec![0xAAu8; TICKET_LEN];
        data.send(&wire::StreamHeader::session_data(forged_ticket))
            .await
            .expect("send StreamHeader");

        let outcome = tokio::time::timeout(TIMEOUT, data.recv::<wire::SessionFrame>())
            .await
            .expect("a forged ticket must be rejected promptly, never hang");
        match outcome {
            // `pump_quic_to_uds`'s frame-boundary sentinel byte (daemon.rs)
            // turns exactly this case — a target reset with nothing
            // written yet, i.e. a "looks clean" boundary — into a forced
            // mid-frame conduit error on the client's decoder, never a
            // clean `Ok(None)`: link death (including a rejected ticket)
            // must surface as a typed error, never as an indistinguishable
            // normal end (`docs/CLI.md` §6.13's "명확한 typed error").
            Err(_conduit_error) => {}
            Ok(None) => {
                panic!(
                    "a forged ticket's rejection must surface as a typed error, not a clean \
                     end indistinguishable from the session exiting normally"
                )
            }
            Ok(Some(frame)) => {
                panic!("a forged ticket must never be answered as if it redeemed: {frame:?}")
            }
        }

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// A `LOCAL_STREAM` conduit's first post-ack frame must be a `SESSION_DATA`
/// `StreamHeader` (HARD RULES: "a non-`SESSION_DATA` or missing header ->
/// `LocalError` `INVALID_ARGUMENT`, nothing opened on QUIC") — the real,
/// end-to-end version of `crate::localctl::daemon`'s own unit test
/// `only_a_session_data_header_passes_the_local_stream_shape_check`, which
/// only exercises `is_session_data_header` as a pure function against a
/// synthetic `StreamHeader` and proves nothing about the real conduit path
/// (adversarial review finding: mutating away the guard in `serve_stream`
/// leaves every existing test green). This drives the actual daemon.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_session_data_header_on_local_stream_is_invalid_argument_nothing_opened_on_quic() {
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

        let mut data = connect_stream(&localctl.socket_path, "widget").await;
        // `EXEC_DATA`, not `SESSION_DATA` — the one shape `LOCAL_STREAM`
        // must refuse before ever touching QUIC.
        data.send(&wire::StreamHeader::exec_data(vec![0xBBu8; TICKET_LEN]))
            .await
            .expect("send StreamHeader");

        let response: LocalResponse = tokio::time::timeout(TIMEOUT, data.recv())
            .await
            .expect("must answer promptly, never hang")
            .expect("conduit stays open long enough to answer")
            .expect("daemon must answer on this same framed conduit, not go raw");
        match response.body {
            Some(local_response::Body::Error(err)) => {
                assert_eq!(
                    err.error_code(),
                    ErrorCode::InvalidArgument,
                    "wrong error code: {err:?}"
                );
            }
            other => panic!("expected a LocalError{{INVALID_ARGUMENT}}, got {other:?}"),
        }

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}
