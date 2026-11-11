//! The combined `listen` + `serve` endpoint (ADR-0059), registration branch
//! and shared parts: a `Server` in front of a `Listen` on one address, built
//! on one authorizer, one audit sink, one admission gate and one quota
//! tracker (`qsh_testkit::combined::CombinedHarness`).
//!
//! Covered here (decisions 4, 6, 8, 9, 12 and DoD 27.1's registration rows,
//! 27.5, 27.6, 27.7): which branch a connection takes at `Hello`, that a
//! registered connection never reaches the host's dispatch, the quota order
//! of each branch (R3 forward, A2/B5 registration), the single connection
//! pool, and the single policy snapshot and audit sink. Decision 5's punch
//! rows (the first request that is not a `Ping` decides, `[punch].mode = off`
//! never switches) and the limits a switched connection keeps are here too;
//! the netsim half of the punch branch is in `combined_punch.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use qsh_core::acl::{AllowAllPinned, Authorizer, DenyAll, Role};
use qsh_core::audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink};
use qsh_core::client::{ClientError, Session};
use qsh_core::config::{Config, Paths};
use qsh_core::handshake::HelloError;
use qsh_core::quota::QuotaLimits;
use qsh_core::reverse::listen::Listen;
use qsh_core::serve::SharedParts;
use qsh_core::server::Server;
use qsh_core::trust::SharedTrustStore;
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, ControlMessage, control_message};
use qsh_testkit::combined::CombinedHarness;
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{forward_hello, wait_for, wait_for_audit_records};
use qsh_transport::{Dialed, FramedStream, Principal, ReadError, StaticTrust, StreamError};

pub(super) const TIMEOUT: Duration = Duration::from_secs(5);

/// The reset code a controller ends a peer-opened stream with when its
/// header is not one the registered connection carries (`server::
/// RESET_CODE_BAD_HEADER`).
const RESET_BAD_HEADER: u64 = 0x2001;

pub(super) fn pins(peers: &[(&TestIdentity, &str)]) -> StaticTrust {
    peers
        .iter()
        .fold(StaticTrust::empty(), |trust, (id, name)| {
            trust.with_pin(id.fingerprint, Principal::Device((*name).to_string()))
        })
}

pub(super) fn remote(err: HelloError) -> (ErrorCode, String, bool) {
    match err {
        HelloError::Remote {
            code,
            message,
            retryable,
        } => (code, message, retryable),
        other => panic!("expected a remote error frame, got {other:?}"),
    }
}

/// `Result::expect_err` needs `Debug` on the success type, and the
/// `FramedStream` in it is deliberately not.
fn expect_err<T>(result: Result<T, HelloError>, msg: &str) -> HelloError {
    match result {
        Ok(_) => panic!("{msg}"),
        Err(err) => err,
    }
}

pub(super) fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        env: Default::default(),
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// Keep a registered test connection answering the controller's liveness
/// `Ping`s so its watchdog does not judge the idle test connection dead.
pub(super) fn keepalive(mut ctl: FramedStream) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(Some(msg)) = ctl.recv.recv::<ControlMessage>().await {
            if let Some(control_message::Body::Ping(_)) = msg.body
                && ctl
                    .send
                    .send(&ControlMessage::new(
                        msg.request_id,
                        control_message::Body::Pong(wire::Pong {}),
                    ))
                    .await
                    .is_err()
            {
                return;
            }
        }
    })
}

pub(super) fn limits(max_connections: usize, per_principal: usize) -> QuotaLimits {
    QuotaLimits {
        max_connections,
        max_connections_per_principal: per_principal,
        ..QuotaLimits::default()
    }
}

/// A forward `session.open` on an established forward connection.
async fn open_session(
    dialed: &Dialed,
    ctl: FramedStream,
    hello: wire::Hello,
) -> Result<wire::SessionOpened, ClientError> {
    let mut session = Session::from_control(dialed.connection.clone(), ctl, hello);
    session.session_open(open_req()).await
}

/// A `PunchRequest` for a target nobody registered: well formed, so the
/// rendezvous answers it with a refusal reply (`TARGET_NOT_REGISTERED`)
/// rather than an error.
pub(super) fn punch_request() -> wire::PunchRequest {
    wire::PunchRequest {
        attempt_id: vec![7u8; 16],
        target_fingerprint: vec![9u8; 32],
        candidates: vec![wire::PunchCandidate::from_addr(
            "198.51.100.7:5000".parse().expect("addr"),
            wire::PunchCandidateKind::Host,
        )],
    }
}

/// Send one control message and read the reply to it.
pub(super) async fn ask(
    ctl: &mut FramedStream,
    id: u64,
    body: control_message::Body,
) -> ControlMessage {
    ctl.send
        .send(&ControlMessage::new(id, body))
        .await
        .expect("send the request");
    tokio::time::timeout(TIMEOUT, ctl.recv.recv::<ControlMessage>())
        .await
        .expect("a reply arrives")
        .expect("no stream error")
        .expect("the control stream stays open until the reply")
}

/// What a reply is, for a table row: the error code, or the refusal of a
/// `PunchReply`.
#[derive(Debug, PartialEq)]
pub(super) enum Reply {
    Error(String),
    PunchRefusal(i32),
    Other,
}

pub(super) fn classify(msg: ControlMessage) -> Reply {
    match msg.body {
        Some(control_message::Body::Response(wire::Response { body: Some(body) })) => match body {
            wire::response::Body::Error(e) => Reply::Error(e.code),
            wire::response::Body::PunchReply(r) => Reply::PunchRefusal(r.refusal),
            _ => Reply::Other,
        },
        _ => Reply::Other,
    }
}

/// The error a `PunchRequest` draws as the host's own reply and as a
/// rendezvous' connection error, by message, so a row tells them apart.
async fn punch_reply_message(ctl: &mut FramedStream, id: u64) -> (Reply, String) {
    let msg = ask(
        ctl,
        id,
        control_message::Body::PunchRequest(punch_request()),
    )
    .await;
    let message = match &msg.body {
        Some(control_message::Body::Response(wire::Response {
            body: Some(wire::response::Body::Error(e)),
        })) => e.message.clone(),
        _ => String::new(),
    };
    (classify(msg), message)
}

const NOT_SERVED: &str = "hole-punching requests are not served by this peer";
const PUNCH_ONLY: &str = "a hole-punching connection answers one PunchRequest and Ping";

// ---------------------------------------------------------------------------
// DoD 27.1 registration rows: the branch is decided by the peer's `Hello`.
// ---------------------------------------------------------------------------

/// Decision 4's table, rows that start at `Hello`: `reverse` present goes to
/// the registration choke point (`host.reverse`) and, admitted, to the
/// controller; `reverse` absent is a forward connection whose requests the
/// host judges one by one. Each row also pins which `Hello` reply the peer
/// got (decision 3): the controller's for a registration, the host's for a
/// forward peer.
#[tokio::test(flavor = "multi_thread")]
async fn combined_dispatch_table() {
    #[derive(Debug, PartialEq)]
    enum Branch {
        Registered,
        RegistrationDenied,
        Forward,
    }

    for (label, authorizer, reverse, expect) in [
        (
            "reverse + host.reverse allowed",
            Arc::new(AllowAllPinned) as Arc<dyn Authorizer>,
            true,
            Branch::Registered,
        ),
        (
            "reverse + host.reverse denied",
            Arc::new(DenyAll) as Arc<dyn Authorizer>,
            true,
            Branch::RegistrationDenied,
        ),
        (
            "no reverse, session.open allowed",
            Arc::new(AllowAllPinned) as Arc<dyn Authorizer>,
            false,
            Branch::Forward,
        ),
    ] {
        let peer = make_identity();
        let h =
            CombinedHarness::start(authorizer, pins(&[(&peer, "widget")]), limits(512, 32)).await;

        let got = if reverse {
            match h.register(&peer, "").await {
                Ok((dialed, ctl, peer_hello)) => {
                    let _keep = keepalive(ctl);
                    assert_eq!(peer_hello.device_name, "box", "{label}");
                    assert!(peer_hello.reverse.is_none(), "{label}");
                    wait_for(TIMEOUT, || (h.listen.live_connections() == 1).then_some(())).await;
                    assert!(h.listen.registry().get("widget").is_some(), "{label}");
                    assert_eq!(h.broker.live_counts().live, 0, "{label}: no session");
                    drop(dialed);
                    Branch::Registered
                }
                Err(err) => {
                    let (code, _message, retryable) = remote(err);
                    assert_eq!(code, ErrorCode::PermissionDenied, "{label}");
                    assert!(!retryable, "{label}");
                    assert!(h.listen.registry().snapshot().is_empty(), "{label}");
                    assert_eq!(h.listen.live_connections(), 0, "{label}");
                    Branch::RegistrationDenied
                }
            }
        } else {
            let (dialed, ctl, peer_hello) = h.forward(&peer).await.expect("forward hello");
            assert_eq!(peer_hello, h.server.local_hello(None), "{label}");
            open_session(&dialed, ctl, peer_hello)
                .await
                .expect("a forward peer opens a session");
            assert_eq!(h.broker.live_counts().live, 1, "{label}");
            assert!(h.listen.registry().snapshot().is_empty(), "{label}");
            assert_eq!(h.listen.live_connections(), 0, "{label}");
            Branch::Forward
        };
        assert_eq!(got, expect, "{label}");
        h.shutdown().await;
    }

    punch_rows().await;
}

/// Decision 4 and 5, the rows that start at the first request: a `Hello`
/// without `reverse` is a forward connection until its first request that is
/// not a `Ping`, and only a `PunchRequest` there switches it to a punching
/// connection. A request of any other kind, or a data stream the peer opens,
/// settles it as a forward connection, and a `PunchRequest` that comes later
/// is the host's `UNSUPPORTED`. `[punch].mode = off` and a peer without
/// `punch.v1` never switch.
async fn punch_rows() {
    #[derive(Clone, Copy, Debug)]
    enum First {
        /// `Ping` (not counted), then the `PunchRequest`.
        PingThenPunch,
        /// The `PunchRequest` itself.
        Punch,
        SessionOpen,
        /// An `ExecStart` that the host refuses for its shape: still a request.
        ExecStart,
        RendezvousQuery,
        /// A `TCP_CONNECT` stream opened with no request before it.
        TcpConnectStream,
        /// A `JUMP` stream opened with no request before it.
        JumpStream,
    }

    struct Row {
        label: &'static str,
        first: First,
        mode_off: bool,
        peer_has_punch: bool,
        /// Whether the connection ends up a punching one.
        switches: bool,
    }

    let rows = [
        Row {
            label: "Ping then PunchRequest",
            first: First::PingThenPunch,
            mode_off: false,
            peer_has_punch: true,
            switches: true,
        },
        Row {
            label: "PunchRequest first",
            first: First::Punch,
            mode_off: false,
            peer_has_punch: true,
            switches: true,
        },
        Row {
            label: "SessionOpen first",
            first: First::SessionOpen,
            mode_off: false,
            peer_has_punch: true,
            switches: false,
        },
        Row {
            label: "ExecStart first",
            first: First::ExecStart,
            mode_off: false,
            peer_has_punch: true,
            switches: false,
        },
        Row {
            label: "RendezvousQuery first",
            first: First::RendezvousQuery,
            mode_off: false,
            peer_has_punch: true,
            switches: false,
        },
        Row {
            label: "TCP_CONNECT stream first",
            first: First::TcpConnectStream,
            mode_off: false,
            peer_has_punch: true,
            switches: false,
        },
        Row {
            label: "JUMP stream first",
            first: First::JumpStream,
            mode_off: false,
            peer_has_punch: true,
            switches: false,
        },
        Row {
            label: "[punch].mode = off",
            first: First::Punch,
            mode_off: true,
            peer_has_punch: true,
            switches: false,
        },
        Row {
            label: "peer without punch.v1",
            first: First::Punch,
            mode_off: false,
            peer_has_punch: false,
            switches: false,
        },
    ];

    for row in rows {
        let label = row.label;
        let peer = make_identity();
        let h = CombinedHarness::start(
            Arc::new(AllowAllPinned),
            pins(&[(&peer, "widget")]),
            limits(512, 32),
        )
        .await;
        h.listen.set_punch_enabled(!row.mode_off);
        let mut hello = forward_hello();
        if !row.peer_has_punch {
            hello.capabilities.retain(|c| c != wire::CAP_PUNCH_V1);
        }
        let (dialed, mut ctl, _) = h
            .initiate(&peer, hello)
            .await
            .unwrap_or_else(|err| panic!("{label}: hello: {err:?}"));

        let mut next_id = 1u64;
        let mut id = || {
            next_id += 1;
            next_id
        };
        // The request or stream that decides the connection (when it is not
        // the `PunchRequest` itself), and the `PunchRequest` that follows.
        match row.first {
            First::PingThenPunch => {
                let pong = ask(&mut ctl, id(), control_message::Body::Ping(wire::Ping {})).await;
                assert!(
                    matches!(pong.body, Some(control_message::Body::Pong(_))),
                    "{label}: a Ping is answered by either role"
                );
                assert_eq!(
                    h.listen.punch_connections(),
                    0,
                    "{label}: Ping decides nothing"
                );
            }
            First::Punch => {}
            First::SessionOpen => {
                let reply = ask(
                    &mut ctl,
                    id(),
                    control_message::Body::SessionOpen(open_req()),
                )
                .await;
                assert!(matches!(classify(reply), Reply::Other), "{label}");
            }
            First::ExecStart => {
                let reply = ask(
                    &mut ctl,
                    id(),
                    control_message::Body::ExecStart(wire::ExecStart::default()),
                )
                .await;
                assert!(
                    matches!(classify(reply), Reply::Error(_)),
                    "{label}: the host refuses an empty command"
                );
            }
            First::RendezvousQuery => {
                let reply = ask(
                    &mut ctl,
                    id(),
                    control_message::Body::RendezvousQuery(wire::RendezvousQuery {}),
                )
                .await;
                assert_eq!(
                    classify(reply),
                    Reply::Error("UNSUPPORTED".into()),
                    "{label}"
                );
            }
            First::TcpConnectStream | First::JumpStream => {
                let header = if matches!(row.first, First::TcpConnectStream) {
                    wire::StreamHeader {
                        kind: wire::StreamKind::TcpConnect as i32,
                        ticket: Vec::new(),
                        host: "127.0.0.1".into(),
                        port: 1,
                        deny_host_local: false,
                    }
                } else {
                    wire::StreamHeader::jump([3u8; 16], "127.0.0.1".into(), 1)
                };
                let (send, recv) = dialed.connection.open_bi().await.expect("open a stream");
                let mut data = FramedStream::data(send, recv);
                data.send.send(&header).await.expect("send the header");
                // The host has taken the stream once it answers or ends it.
                let _ = tokio::time::timeout(TIMEOUT, data.recv.recv::<wire::SessionFrame>())
                    .await
                    .expect("the host settles the stream");
            }
        }

        let (reply, message) = punch_reply_message(&mut ctl, id()).await;
        if row.switches {
            assert_eq!(
                reply,
                Reply::PunchRefusal(wire::PunchRefusal::TargetNotRegistered as i32),
                "{label}: the rendezvous answers it"
            );
            assert_eq!(h.listen.punch_connections(), 1, "{label}");
            let records = wait_for_audit_records(&h.audit, 1, TIMEOUT).await;
            assert!(
                records
                    .iter()
                    .any(|r| r.action == "host.punch" && r.decision == "allow"),
                "{label}: judged as host.punch: {records:?}"
            );
            // A switched connection answers Ping and nothing else.
            let (reply, message) = {
                let msg = ask(
                    &mut ctl,
                    id(),
                    control_message::Body::SessionOpen(open_req()),
                )
                .await;
                match classify(msg) {
                    Reply::Error(code) => (Reply::Error(code), PUNCH_ONLY.to_string()),
                    other => (other, String::new()),
                }
            };
            assert_eq!(reply, Reply::Error("UNSUPPORTED".into()), "{label}");
            assert_eq!(message, PUNCH_ONLY, "{label}");
            assert_eq!(h.broker.live_counts().live, 0, "{label}: no session");
        } else {
            assert_eq!(reply, Reply::Error("UNSUPPORTED".into()), "{label}");
            assert_eq!(message, NOT_SERVED, "{label}: the host's own answer");
            assert_eq!(h.listen.punch_connections(), 0, "{label}");
            assert!(
                h.audit.records().iter().all(|r| r.action != "host.punch"),
                "{label}: no punch decision was made"
            );
        }
        drop(dialed);
        h.shutdown().await;
    }
}

/// Decision 7 and DoD 27.7: a listen without `serve` and a standalone serve
/// refuse each other's peer exactly as before, and the combined endpoint
/// answers each peer with the `Hello` the standalone role would have sent.
#[tokio::test(flavor = "multi_thread")]
async fn listen_without_serve_hello_is_unchanged() {
    use qsh_testkit::loopback::LoopbackHarness;
    use qsh_testkit::reverse::{ReverseHarness, reverse_hello};

    // Standalone host: `Hello.reverse` is refused, and a plain `Hello` is
    // answered with the host's own.
    let host = LoopbackHarness::start().await;
    let dialed = host.dial().await;
    let err = expect_hello(
        qsh_core::handshake::initiate(&dialed.connection, reverse_hello("x")).await,
        "a standalone host refuses Hello.reverse",
    );
    let (code, message, _) = remote(err);
    assert_eq!(code, ErrorCode::Unsupported);
    assert_eq!(message, "this host does not accept reverse registrations");
    let host_hello = {
        let dialed = host.dial().await;
        let (_ctl, hello) = qsh_core::handshake::initiate(&dialed.connection, forward_hello())
            .await
            .expect("standalone forward hello");
        hello
    };
    host.shutdown().await;

    // Standalone listen: a peer with no `Hello.reverse` (and no `punch.v1`,
    // which would make it a punching connection) is refused, a registering
    // peer is answered with the controller's `Hello`.
    let target = make_identity();
    let listen = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pins(&[(&target, "widget")]),
    )
    .await;
    let mut no_punch = forward_hello();
    no_punch.capabilities.retain(|c| c != wire::CAP_PUNCH_V1);
    let (code, message, _) = remote(expect_err(
        listen.initiate(&target, no_punch).await,
        "a standalone listen refuses a peer with no Hello.reverse",
    ));
    assert_eq!(code, ErrorCode::Unsupported);
    assert_eq!(message, "this endpoint only accepts reverse registrations");
    assert!(
        listen.audit.records().is_empty(),
        "the refusal is not an ACL decision: no audit line"
    );
    let (_d, _ctl, listen_hello) = listen
        .register(&target, "")
        .await
        .expect("standalone registration");
    listen.shutdown().await;

    // Combined: the same two replies, byte for byte, from one address (the
    // device name is the harnesses' only difference).
    let peer = make_identity();
    let h = CombinedHarness::start(
        Arc::new(AllowAllPinned),
        pins(&[(&peer, "widget")]),
        limits(512, 32),
    )
    .await;
    let (_d, _ctl, forward_reply) = h.forward(&peer).await.expect("combined forward");
    assert_eq!(
        wire::Hello {
            device_name: host_hello.device_name.clone(),
            ..forward_reply
        },
        host_hello,
        "a forward peer gets the host's Hello"
    );
    let (_d2, ctl, registration_reply) = h.register(&peer, "").await.expect("combined register");
    let _keep = keepalive(ctl);
    assert_eq!(
        wire::Hello {
            device_name: listen_hello.device_name.clone(),
            ..registration_reply
        },
        listen_hello,
        "a registering peer gets the controller's Hello"
    );
    h.shutdown().await;
}

fn expect_hello(result: Result<(FramedStream, wire::Hello), HelloError>, msg: &str) -> HelloError {
    match result {
        Ok(_) => panic!("{msg}"),
        Err(err) => err,
    }
}

// ---------------------------------------------------------------------------
// Decision 6: a registered connection never reaches the host's dispatch.
// ---------------------------------------------------------------------------

/// The registered target's connection is a client-role connection of the
/// controller. A shell on the combined host needs a forward connection of its
/// own: request-shaped frames on the registered control stream are refused
/// `UNSUPPORTED` and a data stream the peer opens is reset, with no session,
/// ticket or audit record of the host's side created (threat model A25).
#[tokio::test(flavor = "multi_thread")]
async fn a_registered_connection_never_reaches_forward_dispatch() {
    let target = make_identity();
    let h = CombinedHarness::start(
        Arc::new(AllowAllPinned),
        pins(&[(&target, "widget")]),
        limits(512, 32),
    )
    .await;
    let (dialed, ctl, peer_hello) = h.register(&target, "").await.expect("registers");
    let mut session = Session::from_control(dialed.connection.clone(), ctl, peer_hello);

    // A control-stream request: refused, nothing created.
    let err = session
        .session_open(open_req())
        .await
        .expect_err("a registered connection must not open a session on the host");
    match err {
        ClientError::Remote { code, .. } => assert_eq!(code, ErrorCode::Unsupported),
        other => panic!("expected a remote UNSUPPORTED, got {other:?}"),
    }

    // A data stream of a kind the host serves: reset.
    let (send, recv) = session
        .connection()
        .open_bi()
        .await
        .expect("open a stream on the registered connection");
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&wire::StreamHeader::session_data(vec![0u8; 16]))
        .await
        .expect("send the header");
    match tokio::time::timeout(TIMEOUT, data.recv.recv::<wire::SessionFrame>())
        .await
        .expect("the controller ends the stream")
    {
        Err(StreamError::Read(ReadError::Reset(code))) => {
            assert_eq!(code.into_inner(), RESET_BAD_HEADER)
        }
        other => panic!("expected the stream to be reset, got {other:?}"),
    }

    assert_eq!(h.broker.live_counts().live, 0, "no session was created");
    assert_eq!(h.server.pending_tickets(), 0, "no ticket was minted");
    assert!(
        h.listen.registry().get("widget").is_some(),
        "the refused requests left the registration alone"
    );
    let records = h.audit.records();
    assert!(
        records.iter().all(|r| r.action == "host.reverse"),
        "only the registration was ever judged: {records:?}"
    );
    drop(dialed);
    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// Decision 9: quota order per branch.
// ---------------------------------------------------------------------------

/// A2/B5: a registration is judged by the ACL first and by the connection
/// quota after. At capacity a peer the registry would deny still gets
/// `PERMISSION_DENIED`, so it learns nothing about saturation; an allowed
/// registration gets `RESOURCE_EXHAUSTED` (retryable) and leaves no registry
/// entry behind.
#[tokio::test(flavor = "multi_thread")]
async fn combined_registration_checks_acl_before_quota() {
    for (label, authorizer, expected) in [
        (
            "denied registration at capacity",
            Arc::new(DenyAll) as Arc<dyn Authorizer>,
            (ErrorCode::PermissionDenied, false),
        ),
        (
            "allowed registration at capacity",
            Arc::new(AllowAllPinned) as Arc<dyn Authorizer>,
            (ErrorCode::ResourceExhausted, true),
        ),
    ] {
        let holder = make_identity();
        let registrant = make_identity();
        let h = CombinedHarness::start(
            authorizer,
            pins(&[(&holder, "holder"), (&registrant, "widget")]),
            limits(1, 32),
        )
        .await;
        // One forward connection fills the endpoint's one slot.
        let (_held, _held_ctl, _hello) = h.forward(&holder).await.expect("holder connects");
        assert_eq!(h.quotas.total_connections_in_use(), 1, "{label}");

        let (code, _message, retryable) = remote(expect_err(
            h.register(&registrant, "").await,
            "the registration must be refused",
        ));
        assert_eq!((code, retryable), expected, "{label}");
        assert!(
            h.listen.registry().snapshot().is_empty(),
            "{label}: an admitted-then-refused registration is rolled back"
        );
        assert_eq!(h.listen.live_connections(), 0, "{label}");
        h.shutdown().await;
    }
}

/// R3: a forward peer is told about a full pool before its `Hello` is looked
/// at, `RESOURCE_EXHAUSTED` and retryable, whatever it is allowed to do. The
/// same fact reaches a pinned peer without `host.reverse` that way; D27 keeps
/// it as a residual risk.
#[tokio::test(flavor = "multi_thread")]
async fn combined_forward_reports_quota_before_hello() {
    let holder = make_identity();
    let late = make_identity();
    let h = CombinedHarness::start(
        Arc::new(DenyAll),
        pins(&[(&holder, "holder"), (&late, "late")]),
        limits(1, 32),
    )
    .await;
    let (_held, _held_ctl, _hello) = h.forward(&holder).await.expect("holder connects");

    let (code, _message, retryable) = remote(expect_err(
        h.forward(&late).await,
        "the pool is full: the forward peer is refused at Hello",
    ));
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(retryable);
    h.shutdown().await;
}

/// DoD 27.6: one pool. A registration and a forward connection count against
/// the same `max_connections`, and a freed slot is usable by either role.
#[tokio::test(flavor = "multi_thread")]
async fn combined_endpoint_shares_one_connection_pool() {
    let target = make_identity();
    let client = make_identity();
    let late_client = make_identity();
    let late_target = make_identity();
    let h = CombinedHarness::start(
        Arc::new(AllowAllPinned),
        pins(&[
            (&target, "widget"),
            (&client, "laptop"),
            (&late_client, "tablet"),
            (&late_target, "gadget"),
        ]),
        limits(2, 32),
    )
    .await;

    let (reg, reg_ctl, _) = h.register(&target, "").await.expect("registers");
    let _keep = keepalive(reg_ctl);
    let (_fwd, _fwd_ctl, _) = h.forward(&client).await.expect("forward connects");
    assert_eq!(h.quotas.total_connections_in_use(), 2);

    // Full: both roles are refused alike.
    let (code, _, retryable) = remote(expect_err(
        h.forward(&late_client).await,
        "a third connection is refused",
    ));
    assert_eq!((code, retryable), (ErrorCode::ResourceExhausted, true));
    let (code, _, retryable) = remote(expect_err(
        h.register(&late_target, "").await,
        "a second registration is refused",
    ));
    assert_eq!((code, retryable), (ErrorCode::ResourceExhausted, true));

    // The registration ends: its slot frees up for a forward peer.
    reg.connection.close(0u32, b"done");
    wait_for(TIMEOUT, || {
        (h.quotas.total_connections_in_use() == 1).then_some(())
    })
    .await;
    h.forward(&late_client)
        .await
        .expect("the freed slot is usable by the other role");
    h.shutdown().await;
}

/// C29: one principal's flood of forward connections stops at its own
/// per-principal cap and leaves room in the shared pool for a registration.
#[tokio::test(flavor = "multi_thread")]
async fn forward_flood_from_one_principal_leaves_room_for_registration() {
    let flooder = make_identity();
    let target = make_identity();
    let h = CombinedHarness::start(
        Arc::new(AllowAllPinned),
        pins(&[(&flooder, "flooder"), (&target, "widget")]),
        limits(10, 3),
    )
    .await;

    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(h.forward(&flooder).await.expect("within the principal cap"));
    }
    let (code, _, retryable) = remote(expect_err(
        h.forward(&flooder).await,
        "the fourth connection of one principal is refused",
    ));
    assert_eq!((code, retryable), (ErrorCode::ResourceExhausted, true));

    let (_reg, reg_ctl, _) = h
        .register(&target, "")
        .await
        .expect("a different principal still registers");
    let _keep = keepalive(reg_ctl);
    assert!(h.listen.registry().get("widget").is_some());
    drop(held);
    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// Decision 5: a connection that switched to the punching role keeps the
// rendezvous limits of ADR-0054 decision 10 (2).
// ---------------------------------------------------------------------------

/// C30: the connection quota is held from the start, the 16-connection permit
/// is taken at the switch, an answered punching connection closes three
/// seconds later, and everything but `Ping` on it is `UNSUPPORTED`. The
/// sixteen permits are not the forward pool: a forward client still gets a
/// session while they are all taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_combined_punch_connection_keeps_the_rendezvous_limits() {
    use qsh_core::punch::RENDEZVOUS_IDLE;

    const CAP: usize = qsh_proto::punch::RENDEZVOUS_MAX_CLIENTS;
    // One initiator may have a single attempt in flight and six a minute, so
    // sixteen punching connections need sixteen initiators.
    let punchers: Vec<TestIdentity> = (0..=CAP).map(|_| make_identity()).collect();
    let names: Vec<String> = (0..=CAP).map(|i| format!("p{i}")).collect();
    let forwarder = make_identity();
    let mut peers: Vec<(&TestIdentity, &str)> = punchers
        .iter()
        .zip(names.iter())
        .map(|(id, n)| (id, n.as_str()))
        .collect();
    peers.push((&forwarder, "fwd"));
    let h = CombinedHarness::start(Arc::new(AllowAllPinned), pins(&peers), limits(512, 32)).await;

    let mut held = Vec::new();
    let mut answered_at = Vec::new();
    for id in &punchers[..CAP] {
        let (dialed, mut ctl, _) = h.forward(id).await.expect("forward hello");
        let (reply, _) = punch_reply_message(&mut ctl, 1).await;
        assert_eq!(
            reply,
            Reply::PunchRefusal(wire::PunchRefusal::TargetNotRegistered as i32)
        );
        answered_at.push(tokio::time::Instant::now());
        held.push((dialed, ctl));
    }
    assert_eq!(h.listen.punch_connections(), CAP);
    assert_eq!(
        h.quotas.total_connections_in_use(),
        CAP,
        "a punching connection holds its connection quota from the start"
    );

    // The seventeenth is refused at the switch: retryable, then closed.
    let (dialed17, mut ctl17, _) = h.forward(&punchers[CAP]).await.expect("forward hello");
    let (reply, message) = punch_reply_message(&mut ctl17, 1).await;
    assert_eq!(reply, Reply::Error("RESOURCE_EXHAUSTED".into()));
    assert_eq!(message, "too many hole-punching connections");
    tokio::time::timeout(TIMEOUT, dialed17.connection.closed())
        .await
        .expect("the refused connection is closed");
    assert_eq!(h.listen.punch_connections(), CAP, "the cap held");

    // Not the forward pool: a forward client opens a session meanwhile.
    let (dialed, ctl, hello) = h.forward(&forwarder).await.expect("forward hello");
    open_session(&dialed, ctl, hello)
        .await
        .expect("a forward client is served while the punch permits are all taken");

    // One request and `Ping` only: a second `PunchRequest` and any other
    // request draw `UNSUPPORTED`; `Ping` is answered.
    {
        let (_, ctl) = &mut held[0];
        let (reply, message) = punch_reply_message(ctl, 2).await;
        assert_eq!(reply, Reply::Error("UNSUPPORTED".into()));
        assert_eq!(message, PUNCH_ONLY);
        let pong = ask(ctl, 3, control_message::Body::Ping(wire::Ping {})).await;
        assert!(matches!(pong.body, Some(control_message::Body::Pong(_))));
    }

    // Three seconds after its answer each one is closed, and the permits and
    // the connection quota come back.
    for (i, (dialed, _)) in held.iter().enumerate() {
        tokio::time::timeout(RENDEZVOUS_IDLE + TIMEOUT, dialed.connection.closed())
            .await
            .expect("an answered punching connection is closed");
        assert!(
            answered_at[i].elapsed() >= RENDEZVOUS_IDLE - Duration::from_millis(200),
            "connection {i} lived {:?}, less than the rendezvous window",
            answered_at[i].elapsed()
        );
    }
    wait_for(TIMEOUT, || {
        (h.listen.punch_connections() == 0).then_some(())
    })
    .await;
    wait_for(TIMEOUT, || {
        (h.quotas.total_connections_in_use() <= 1).then_some(())
    })
    .await;
    let (_d, mut ctl, _) = h.forward(&punchers[CAP]).await.expect("forward hello");
    let (reply, _) = punch_reply_message(&mut ctl, 1).await;
    assert_eq!(
        reply,
        Reply::PunchRefusal(wire::PunchRefusal::TargetNotRegistered as i32),
        "a freed permit is usable again"
    );
    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// Decision 19: the order of a shutdown.
// ---------------------------------------------------------------------------

/// SIGTERM's order on the endpoint (the part of it `Server::run` owns):
/// accept stops, the registered connections close with the endpoint's own
/// code, only then the sessions drain, and the endpoint closes last. The
/// session child here ignores `SIGHUP` and `SIGTERM`, so the drain takes the
/// close escalation's time: a target that sees its registration close while
/// the session is still alive saw the registrations go first. Done the other
/// way round, the session would be gone by then.
#[tokio::test(flavor = "multi_thread")]
async fn combined_shutdown_closes_registrations_before_the_drain() {
    use qsh_core::broker::{PipeFactory, Signal};

    let target = make_identity();
    let client = make_identity();
    let pipes = Arc::new(PipeFactory::with_ignored_signals(
        64 * 1024,
        &[Signal::Hup, Signal::Term],
    ));
    let h = CombinedHarness::start_with_pipes(
        Arc::new(AllowAllPinned),
        pins(&[(&target, "widget"), (&client, "laptop")]),
        limits(512, 32),
        pipes,
    )
    .await;
    let (reg, reg_ctl, _) = h.register(&target, "").await.expect("registers");
    let _keep = keepalive(reg_ctl);
    let (dialed, ctl, hello) = h.forward(&client).await.expect("forward hello");
    open_session(&dialed, ctl, hello)
        .await
        .expect("a forward peer opens a session");
    assert_eq!(h.broker.live_counts().live, 1);

    let broker = h.broker.clone();
    let stopping = tokio::spawn(h.shutdown());

    let closed = tokio::time::timeout(TIMEOUT, reg.connection.closed())
        .await
        .expect("the registration is closed by the shutdown");
    let live_then = broker.live_counts().live;
    match closed {
        qsh_transport::ConnectionError::ApplicationClosed(app) => {
            assert_eq!(app.error_code.into_inner(), 0, "the endpoint's own code");
            assert_eq!(&app.reason[..], b"shutdown");
        }
        other => panic!("expected the endpoint's close, got {other:?}"),
    }
    assert_eq!(
        live_then, 1,
        "the registration closed while the session was still alive: registrations go first"
    );

    tokio::time::timeout(TIMEOUT, stopping)
        .await
        .expect("the endpoint stops")
        .expect("no panic");
    assert_eq!(broker.live_counts().live, 0, "the drain closed the session");
}

// ---------------------------------------------------------------------------
// Decision 8: one policy snapshot, one audit sink, fail closed everywhere.
// ---------------------------------------------------------------------------

/// A sandbox whose `trust.toml` pins `peers` with the `full` role and whose
/// `acl.toml` is absent, valid or garbage.
struct Sandbox {
    _dir: tempfile::TempDir,
    paths: Paths,
}

enum Acl {
    Absent,
    Garbage,
}

impl Sandbox {
    fn new(peers: &[(&TestIdentity, &str)], acl: Acl) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        let mut trust = String::new();
        for (id, name) in peers {
            trust.push_str(&format!(
                "[[peer]]\nname = \"{name}\"\nfingerprint = \"{}\"\naddress = \"\"\n\
                 added_at = \"2026-10-14T00:00:00Z\"\nrole = \"full\"\n\n",
                id.fingerprint
            ));
        }
        std::fs::write(paths.trust_file(), trust).expect("write trust.toml");
        if let Acl::Garbage = acl {
            qsh_core::config::write_private_file(&paths.acl_file(), b"[[acl]\nnot toml")
                .expect("write acl.toml");
        }
        Self { _dir: dir, paths }
    }

    fn parts(&self) -> SharedParts {
        let trust = SharedTrustStore::open(self.paths.trust_file()).expect("open trust.toml");
        SharedParts::load(&self.paths, &Config::default(), trust, Role::Serve)
    }
}

/// B53: the policy is loaded once for the whole endpoint. Both roles judge
/// against that one snapshot, a later change to `acl.toml` reaches neither
/// (no hot reload), and a `Listen` built on other parts is refused by
/// `Server::set_listen`.
#[tokio::test(flavor = "multi_thread")]
async fn combined_endpoint_loads_acl_once_and_writes_one_audit_sink() {
    let peer = make_identity();
    let sandbox = Sandbox::new(&[(&peer, "laptop")], Acl::Absent);
    let host = make_identity();
    let h = CombinedHarness::start_with_parts(sandbox.parts(), host).await;

    // `acl.toml` becomes garbage after the start: neither branch notices.
    qsh_core::config::write_private_file(&sandbox.paths.acl_file(), b"[[acl]\nnot toml")
        .expect("write acl.toml");

    let (dialed, ctl, hello) = h.forward(&peer).await.expect("forward hello");
    open_session(&dialed, ctl, hello)
        .await
        .expect("the forward branch still judges against the start-time snapshot");
    let (_reg, reg_ctl, _) = h
        .register(&peer, "")
        .await
        .expect("the registration branch judges against the same snapshot");
    let _keep = keepalive(reg_ctl);

    // Parts that are not shared are refused (and the server stays as it was).
    let stranger = Listen::new(
        qsh_core::reverse::registry::Registry::new(Arc::new(qsh_core::broker::SystemClock), false),
        Arc::new(AllowAllPinned),
        Arc::new(MemoryAuditSink::new()),
        "box",
        Arc::new(qsh_core::broker::SystemClock),
        Duration::from_secs(120),
    );
    let fresh = Server::new(
        Arc::new(AllowAllPinned),
        Arc::new(MemoryAuditSink::new()),
        h.broker.clone(),
        "box",
    );
    let err = fresh
        .set_listen(stranger)
        .expect_err("a listen on other parts must be refused");
    assert_eq!(err.code, ErrorCode::Internal);
    h.shutdown().await;

    // One sink: a registration and a forward request land in the same one.
    let peer = make_identity();
    let h = CombinedHarness::start(
        Arc::new(DenyAll),
        pins(&[(&peer, "laptop")]),
        limits(512, 32),
    )
    .await;
    let (dialed, ctl, hello) = h.forward(&peer).await.expect("forward hello");
    open_session(&dialed, ctl, hello).await.expect_err("denied");
    expect_err(h.register(&peer, "").await, "denied");
    let records = wait_for_audit_records(&h.audit, 2, TIMEOUT).await;
    let mut actions: Vec<_> = records.iter().map(|r| r.action.as_str()).collect();
    actions.sort_unstable();
    assert_eq!(actions, ["host.reverse", "session.open"], "{records:?}");
    assert!(records.iter().all(|r| r.decision == "deny"), "{records:?}");
    h.shutdown().await;
}

/// B53 and ADR-0045 decision 6: an `acl.toml` that does not parse denies
/// every request of every peer, role holders included, on both branches.
#[tokio::test(flavor = "multi_thread")]
async fn combined_unparseable_acl_denies_every_path() {
    let peer = make_identity();
    let sandbox = Sandbox::new(&[(&peer, "laptop")], Acl::Garbage);
    let parts = sandbox.parts();
    assert!(
        parts.policy_diagnostic.is_some(),
        "the start-up diagnostic names the unusable policy"
    );
    let h = CombinedHarness::start_with_parts(parts, make_identity()).await;

    let (code, _, _) = remote(expect_err(
        h.register(&peer, "").await,
        "registration is denied",
    ));
    assert_eq!(code, ErrorCode::PermissionDenied);
    assert!(h.listen.registry().snapshot().is_empty());

    let (dialed, ctl, hello) = h.forward(&peer).await.expect("forward hello");
    match open_session(&dialed, ctl, hello).await {
        Err(ClientError::Remote { code, .. }) => assert_eq!(code, ErrorCode::PermissionDenied),
        other => panic!("expected PERMISSION_DENIED, got {other:?}"),
    }
    assert_eq!(h.broker.live_counts().live, 0);

    // The punch branch: the same policy, the same denial. The refusal is
    // final, so the connection closes and its permit comes back.
    let (dialed, mut ctl, _) = h.forward(&peer).await.expect("forward hello");
    let (reply, _) = punch_reply_message(&mut ctl, 1).await;
    assert_eq!(reply, Reply::Error("PERMISSION_DENIED".into()));
    tokio::time::timeout(TIMEOUT, dialed.connection.closed())
        .await
        .expect("a denied punching connection is closed");
    wait_for(TIMEOUT, || {
        (h.listen.punch_connections() == 0).then_some(())
    })
    .await;
    h.shutdown().await;
}

/// An audit sink that can be told to fail.
struct ToggleSink {
    inner: MemoryAuditSink,
    failing: AtomicBool,
}

impl AuditSink for ToggleSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(AuditError::Degraded);
        }
        self.inner.record(record)
    }
}

/// B53 and the fail-closed audit rule: with the one sink failing, nothing is
/// created on either branch. The decision itself is denied because it cannot
/// be recorded.
#[tokio::test(flavor = "multi_thread")]
async fn combined_audit_failure_fails_closed_on_every_path() {
    let peer = make_identity();
    let sink = Arc::new(ToggleSink {
        inner: MemoryAuditSink::new(),
        failing: AtomicBool::new(false),
    });
    let h = CombinedHarness::start_with_sink(
        Arc::new(AllowAllPinned),
        pins(&[(&peer, "laptop")]),
        limits(512, 32),
        sink.clone(),
    )
    .await;
    let (dialed, ctl, hello) = h.forward(&peer).await.expect("forward hello");
    let mut session = Session::from_control(dialed.connection.clone(), ctl, hello);

    sink.failing.store(true, Ordering::SeqCst);

    let err = session
        .session_open(open_req())
        .await
        .expect_err("a forward request that cannot be audited is denied");
    match err {
        ClientError::Remote { code, .. } => assert_eq!(code, ErrorCode::PermissionDenied),
        other => panic!("expected PERMISSION_DENIED, got {other:?}"),
    }
    assert_eq!(h.broker.live_counts().live, 0);

    let (code, _, _) = remote(expect_err(
        h.register(&peer, "").await,
        "a registration that cannot be audited is denied",
    ));
    assert_eq!(code, ErrorCode::PermissionDenied);
    assert!(h.listen.registry().snapshot().is_empty());
    assert_eq!(h.listen.live_connections(), 0);

    // The punch branch: judged as `host.punch`, which cannot be recorded, so
    // it is denied and nothing is relayed.
    let (dialed, mut ctl, _) = h.forward(&peer).await.expect("forward hello");
    let (reply, _) = punch_reply_message(&mut ctl, 1).await;
    assert_eq!(reply, Reply::Error("PERMISSION_DENIED".into()));
    tokio::time::timeout(TIMEOUT, dialed.connection.closed())
        .await
        .expect("a denied punching connection is closed");

    // The latch is not permanent: the next successful write recovers.
    sink.failing.store(false, Ordering::SeqCst);
    let (_reg, reg_ctl, _) = h
        .register(&peer, "")
        .await
        .expect("registers again once the sink recovers");
    let _keep = keepalive(reg_ctl);
    h.shutdown().await;
}
