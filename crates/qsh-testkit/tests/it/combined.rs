//! The combined `listen` + `serve` endpoint (ADR-0059), registration branch
//! and shared parts: a `Server` in front of a `Listen` on one address, built
//! on one authorizer, one audit sink, one admission gate and one quota
//! tracker (`qsh_testkit::combined::CombinedHarness`).
//!
//! Covered here (decisions 4, 6, 8, 9, 12 and DoD 27.1's registration rows,
//! 27.5, 27.6, 27.7): which branch a connection takes at `Hello`, that a
//! registered connection never reaches the host's dispatch, the quota order
//! of each branch (R3 forward, A2/B5 registration), the single connection
//! pool, and the single policy snapshot and audit sink. The punch branch and
//! the lifecycle belong to later steps.

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

const TIMEOUT: Duration = Duration::from_secs(5);

/// The reset code a controller ends a peer-opened stream with when its
/// header is not one the registered connection carries (`server::
/// RESET_CODE_BAD_HEADER`).
const RESET_BAD_HEADER: u64 = 0x2001;

fn pins(peers: &[(&TestIdentity, &str)]) -> StaticTrust {
    peers
        .iter()
        .fold(StaticTrust::empty(), |trust, (id, name)| {
            trust.with_pin(id.fingerprint, Principal::Device((*name).to_string()))
        })
}

fn remote(err: HelloError) -> (ErrorCode, String, bool) {
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

fn open_req() -> wire::SessionOpen {
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
fn keepalive(mut ctl: FramedStream) -> tokio::task::JoinHandle<()> {
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

fn limits(max_connections: usize, per_principal: usize) -> QuotaLimits {
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

    // The latch is not permanent: the next successful write recovers.
    sink.failing.store(false, Ordering::SeqCst);
    let (_reg, reg_ctl, _) = h
        .register(&peer, "")
        .await
        .expect("registers again once the sink recovers");
    let _keep = keepalive(reg_ctl);
    h.shutdown().await;
}
