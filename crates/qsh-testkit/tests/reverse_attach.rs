//! L3 — `session.attach` driven for real over the `LOCAL_STREAM` splice
//! (`PLAN.md` M3 Step 7, DoD 1): a real target (in-process broker,
//! `qsh_testkit::reverse::ReverseHarness` controller, a real localctl
//! daemon attached to it) and a real [`Ops`] on the "laptop" side —
//! `reverse_session_ops.rs`'s own three-actor shape, extended past the
//! value ops to the one **stream** op, `Ops::session_attach`, which that
//! file's module docs name as exactly what Step 7 owes.
//!
//! Every scenario below is a plain, deterministic `fn`, run inside
//! [`blocking`] off the `#[tokio::test]` worker (the same division of
//! labor `attach_ops.rs`'s own `with_deadline` draws — `Ops`'s blocking
//! API and a pipe-backed [`PipeHandle`] both need a thread that is not
//! itself a tokio worker), driven against a pipe-backed [`Rig`] rather
//! than a real PTY (`attach_loopback.rs`'s own convention) so output is
//! byte-exact and nothing here depends on shell/terminal timing.
//!
//! **Route-shared scenarios** (`burst_scenario`, `steal_scenario`,
//! `detach_reattach_scenario`) run once against `"fwdhost"` — a direct
//! forward dial, [`Rig`]'s own listener — and once against `"revhost"` —
//! the reverse registration relayed through the real localctl daemon —
//! proving `Ops::session_attach`'s route split (M3 Step 7's "session_attach
//! becomes route-aware via `Ops::connect`") is invisible to the stream
//! op's own behavior, the identical property `reverse_session_ops.rs`
//! already proved for the seven value ops.
//!
//! **Reverse-only scenarios** (`input ack/dedup`, `two local conduits`)
//! are driven at the raw `qsh.local.v1`/`qsh.wire.v1` frame level, the way
//! `local_stream_reverse.rs`/`local_control_reverse.rs` already do, because
//! what they prove — the daemon's byte-transparent `LOCAL_STREAM` splice,
//! and its `ControlMux` multiplexing several local conduits onto one
//! relayed control stream — has no forward-route analogue at all: a
//! forward attach has no local daemon in the loop to begin with. The wire
//! *protocol's* dedup rule is already proven over both routes, at the raw
//! frame level, by `attach_loopback.rs`'s own
//! `replayed_input_is_discarded_and_re_acked_exactly_once`; what is new
//! here is proving the **daemon's splice** relays that property
//! byte-for-byte rather than reinventing the wire-level proof.
//!
//! **Why the steal/no_steal scenario injects its "foreign" lease holder
//! directly on the broker** rather than dialing a second, genuinely
//! distinct connection: on the reverse route every local CLI reaches the
//! target over the *one* physical QUIC connection the registration
//! opened (`ConnCtx.conn_id` is `conn.stable_id()`, fixed for the whole
//! registration's life) — the same structural fact
//! `qsh_testkit::reverse::ReversePairHarness`'s own module doc calls
//! "structurally single-peer, by construction — not a harness
//! limitation." `broker::lease::WriterLease::take` keys a lease strictly
//! by `ConnectionId`, so two attaches relayed through the same daemon
//! registration are, from the broker's point of view, the same connection
//! re-acquiring its own lease — never a conflict, steal or no. This file
//! does not fight that; it proves the thing that *is* true on this leg
//! (a plain reattach never conflicts with itself) and reaches the genuine
//! cross-connection conflict the same deterministic way
//! `resume_loopback.rs`'s own
//! `no_steal_conflicts_with_a_foreign_lease_and_spends_no_credential` does:
//! by calling `SessionHandle::take_lease` on the broker directly, which
//! that test's own doc establishes is "the broker's own take_lease [that]
//! does not gate on identity" — a legitimate way to place a foreign
//! holder without inventing a topology the product does not build.
//!
//! `#![cfg(unix)]`: localctl (UDS) is unix-only, same gating as every
//! other localctl testkit file.

#![cfg(unix)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use qsh_core::acl::{AllowAllPinned, Authorizer};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{
    Broker, BrokerConfig, ConnectionId, PeerFingerprint, PipeFactory, SessionId, SystemClock,
};
use qsh_core::handshake;
use qsh_core::localctl::frame::LocalConduit;
use qsh_core::server::{ConnCtx, Server};
use qsh_core::{DetachFlush, Fingerprint, OpError, Ops, Paths, Principal, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalHello, LocalResponse, LocalStreamKind, local_response,
};
use qsh_proto::wire::{self, control_message, response, session_frame};
use qsh_proto::{
    EnvVar, ErrorCode, IdentityInitReq, KeyStoreMode, SessionAttachReq, SessionCloseReq,
    SessionGetReq, SessionOpenReq,
};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_transport::{Dialed, Listener, StaticTrust};
use tokio::net::UnixStream;

/// Bound on every "this must already have happened" harness wait — same
/// order of magnitude as every other reverse testkit file's own `TIMEOUT`.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on one scenario closure run through [`blocking`]. `PLAN.md`'s own
/// ceiling for this stage's tests ("each test < 20s"); generous slack
/// under it since nothing here is a real PTY/shell round trip.
const DEADLINE: Duration = Duration::from_secs(15);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// Run a blocking scenario off the calling `#[tokio::test]` worker —
/// `Ops`'s own blocking API and a pipe-backed [`qsh_core::broker::PipeHandle`]'s
/// async methods (driven from inside the closure through a throwaway
/// `tokio::runtime::Runtime`, never nested with *this* function's own
/// `spawn_blocking`) both need a thread that is not itself a tokio worker
/// — `reverse_session_ops.rs`'s own `blocking` helper draws the identical
/// line for plain `Ops` calls; this is its scenario-closure twin.
///
/// Bounded by [`DEADLINE`]: a `spawn_blocking` task cannot be cancelled
/// once running, so a timeout here still lets the *test* fail promptly
/// rather than hang the suite, even though the underlying thread runs to
/// completion in the background regardless.
async fn blocking<T: Send + 'static>(
    what: &'static str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    tokio::time::timeout(DEADLINE, tokio::task::spawn_blocking(f))
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish within {DEADLINE:?}"))
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()))
}

/// A fresh [`Ops`] with a file-mode device identity already initialized
/// and its `runtime_dir()` ready for [`ReverseHarness::attach_localctl`]
/// to bind a socket under — identical to `reverse_session_ops.rs`'s own
/// `fresh_ops`.
async fn fresh_ops() -> (tempfile::TempDir, Ops, Fingerprint) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    let data = blocking("identity.init", {
        let ops = ops.clone();
        move || {
            ops.identity_init(IdentityInitReq {
                key_store: Some(KeyStoreMode::File),
            })
        }
    })
    .await
    .expect("identity.init");
    let fingerprint = data
        .fingerprint
        .parse::<Fingerprint>()
        .expect("parse this device's own fingerprint");
    (dir, ops, fingerprint)
}

/// A hand-built target: a real pipe-backed [`Broker`]/[`Server`], reachable
/// both as a direct forward listener (`"fwdhost"`) and, once
/// [`Self::register_reverse`] is called, as a live reverse registration
/// (`"revhost"`) relayed through a [`ReverseHarness`]'s localctl daemon —
/// the same shape `reverse_session_ops.rs`'s own `TargetRig` builds, with
/// one addition: `pipes` is kept so a scenario can grab the exact
/// [`qsh_core::broker::PipeHandle`] for whatever session it just opened
/// (`attach_loopback.rs`'s own convention), instead of driving a real
/// shell for byte-exact assertions.
struct Rig {
    server: Arc<Server>,
    broker: Arc<Broker>,
    pipes: Arc<PipeFactory>,
    forward_identity: TestIdentity,
    forward_addr: SocketAddr,
    forward_task: tokio::task::JoinHandle<()>,
    forward_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    reverse_conn: Option<Dialed>,
    reverse_task: Option<tokio::task::JoinHandle<()>>,
}

impl Rig {
    async fn start(authorizer: Arc<dyn Authorizer>, cli_fingerprint: Fingerprint) -> Self {
        let forward_identity = make_identity();
        let server_trust =
            StaticTrust::empty().with_pin(cli_fingerprint, Principal::Device("cli".to_string()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            forward_identity.local.clone(),
            Arc::new(server_trust),
        )
        .expect("bind target forward listener");
        let forward_addr = listener.local_addr().expect("local addr");

        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(SystemClock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
            },
            pipes.clone(),
        );
        tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(authorizer, audit, broker.clone(), "target");

        let (tx, rx) = tokio::sync::oneshot::channel();
        let forward_task = tokio::spawn(server.clone().run(listener, async move {
            let _ = rx.await;
        }));

        Self {
            server,
            broker,
            pipes,
            forward_identity,
            forward_addr,
            forward_task,
            forward_shutdown: Some(tx),
            reverse_conn: None,
            reverse_task: None,
        }
    }

    async fn register_reverse(
        &mut self,
        harness: &ReverseHarness,
        reverse_identity: &TestIdentity,
        offered_name: &str,
    ) {
        let (dialed, ctl, peer_hello) = harness
            .register(reverse_identity, offered_name)
            .await
            .expect("target registers with controller");
        let conn = dialed.connection.clone();
        let ctx = ConnCtx {
            principal: conn.principal().clone(),
            auth_path: conn.auth_path(),
            peer_fingerprint: conn
                .peer_fingerprint()
                .map(|fp| PeerFingerprint::new(*fp.as_bytes())),
            peer_addr: conn.remote_address(),
            conn_id: conn.stable_id(),
            capabilities: handshake::negotiated_capabilities(&peer_hello),
        };
        let server = self.server.clone();
        let conn_id = ctx.conn_id;
        let task = tokio::spawn(async move {
            let _ = server.clone().serve_control(&conn, ctl, ctx, None).await;
            server.purge_connection(conn_id).await;
        });
        self.reverse_conn = Some(dialed);
        self.reverse_task = Some(task);
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.forward_shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.forward_task.await;
        if let Some(conn) = self.reverse_conn.take() {
            conn.connection.close(0, b"test done");
        }
        if let Some(task) = self.reverse_task.take() {
            let _ = task.await;
        }
    }
}

/// Everything one scenario needs, built once per `#[tokio::test]` and
/// shared across its forward/reverse call sites — `reverse_session_ops.rs`'s
/// own per-test setup shape, factored out here since every scenario in
/// this file repeats it identically.
struct Fixture {
    _ops_dir: tempfile::TempDir,
    ops: Ops,
    rig: Rig,
    harness: ReverseHarness,
    localctl: qsh_testkit::reverse::LocalctlHandle,
}

async fn setup(authorizer: Arc<dyn Authorizer>) -> Fixture {
    let (ops_dir, ops, cli_fp) = fresh_ops().await;
    let mut rig = Rig::start(authorizer.clone(), cli_fp).await;

    blocking("trust.add fwdhost", {
        let ops = ops.clone();
        let addr = rig.forward_addr.to_string();
        let fp = rig.forward_identity.fingerprint.to_string();
        move || {
            ops.trust_add(qsh_proto::TrustAddReq {
                name: "fwdhost".into(),
                address: Some(addr),
                fingerprint: Some(fp),
            })
        }
    })
    .await
    .expect("trust.add fwdhost");

    let reverse_identity = make_identity();
    let harness =
        ReverseHarness::start_with(authorizer, false, pin(&reverse_identity, "revhost")).await;
    rig.register_reverse(&harness, &reverse_identity, "laptop-offered-name")
        .await;
    wait_for(TIMEOUT, || harness.listen.registry().get("revhost")).await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    Fixture {
        _ops_dir: ops_dir,
        ops,
        rig,
        harness,
        localctl,
    }
}

impl Fixture {
    async fn teardown(self) {
        self.localctl.shutdown().await;
        self.harness.shutdown().await;
        self.rig.shutdown().await;
    }
}

fn open_req(host: &str) -> SessionOpenReq {
    SessionOpenReq {
        host: host.to_string(),
        argv: vec!["sh".to_string()],
        env: vec![EnvVar {
            name: "QSH_TEST".into(),
            value: "1".into(),
        }],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
    }
}

fn attach(ops: &Ops, session_ref: &str, no_steal: bool) -> Result<SessionAttachStream, OpError> {
    ops.session_attach(SessionAttachReq {
        session_ref: session_ref.to_string(),
        no_steal,
    })
}

fn decode_b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .expect("session output is Base64")
}

fn bare_session_id(session_ref: &str) -> String {
    session_ref
        .rsplit_once('/')
        .expect("session_ref is host/session_id")
        .1
        .to_string()
}

// ===========================================================================
// Scenario 1 — output ordering + sequence monotonicity across a burst.
// ===========================================================================

/// A single write bigger than one wire chunk arrives whole, in order, with
/// `sequence` the exact cumulative end offset of each chunk — the same
/// property `attach_loopback.rs`'s own
/// `attach_stream_delivers_output_in_order_with_monotonic_sequences`
/// proves at the raw frame level, reproved here through the production
/// `Ops::session_attach` surface and (on the reverse call site) the
/// `LOCAL_STREAM` splice.
fn burst_scenario(ops: &Ops, host: &str, pipes: &PipeFactory) {
    let rt = tokio::runtime::Runtime::new().expect("throwaway runtime");
    let opened = ops.session_open(open_req(host)).expect("session.open");
    let mut pipe = pipes
        .take()
        .expect("pipe handle for the session just opened");
    let mut stream = attach(ops, &opened.session_ref, false).expect("session.attach");
    assert!(
        stream.writer_lease(),
        "the first attach with nothing else held gets the lease"
    );

    // More than one wire chunk, deterministic and content-agnostic (a
    // recognisable pattern, so a reorder or a duplicate is visible).
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    rt.block_on(pipe.write_output(&payload))
        .expect("write_output");

    let mut got = Vec::with_capacity(payload.len());
    let mut sequences = Vec::new();
    while got.len() < payload.len() {
        match stream
            .next_event()
            .expect("the stream must not end before every byte arrives")
            .expect("attach event")
        {
            SessionEvent::Output {
                sequence, data_b64, ..
            } => {
                got.extend_from_slice(&decode_b64(&data_b64));
                sequences.push(sequence);
            }
            // Attaching for the first time takes the writer lease
            // (`changed: true`), which broadcasts a `WriterChanged` to
            // every attach on the session — including this one, the very
            // one that caused it. Nothing else this scenario cares about.
            SessionEvent::WriterChanged { .. } => {}
            other => panic!("unexpected event before output completed: {other:?}"),
        }
    }
    assert_eq!(got, payload, "bytes arrive in order, none lost or doubled");
    assert!(
        sequences.windows(2).all(|w| w[0] < w[1]),
        "sequences must be strictly increasing: {sequences:?}"
    );
    assert_eq!(
        sequences.last().copied(),
        Some(payload.len() as u64),
        "the last sequence is the cumulative total"
    );
    let chunk_max = wire::SESSION_CHUNK_MAX as u64;
    assert!(
        sequences[0] <= chunk_max && sequences.windows(2).all(|w| w[1] - w[0] <= chunk_max),
        "no chunk exceeds SESSION_CHUNK_MAX: {sequences:?}"
    );

    stream.close();
    ops.session_close(SessionCloseReq {
        session_ref: opened.session_ref,
        signal: None,
    })
    .expect("session.close");
}

#[tokio::test(flavor = "multi_thread")]
async fn output_ordering_and_monotonic_sequences_across_a_burst() {
    let fx = setup(Arc::new(AllowAllPinned)).await;
    let pipes = fx.rig.pipes.clone();

    blocking("burst forward", {
        let ops = fx.ops.clone();
        let pipes = pipes.clone();
        move || burst_scenario(&ops, "fwdhost", &pipes)
    })
    .await;
    blocking("burst reverse", {
        let ops = fx.ops.clone();
        move || burst_scenario(&ops, "revhost", &pipes)
    })
    .await;

    fx.teardown().await;
}

// ===========================================================================
// Scenario 2 — second attach: default steal takes the lease; `no_steal`
// against a foreign holder is SESSION_CONFLICT.
// ===========================================================================

/// See this file's module docs for why the "foreign" holder is planted
/// directly on the broker rather than dialed as a second connection.
///
/// Planted on a session nothing has attached to yet, deliberately: the
/// control-message probe `attach_request` performs is not the same event
/// as the binding `take_lease` `open_attach_stream`'s own data-stream
/// redemption performs a moment later (`resume_loopback.rs`'s own doc:
/// "The binding take happens where the data stream opens"), so an attach
/// left alive here would still be racing its own redemption against this
/// injection. Planting on a session with no attach in flight at all removes
/// that race outright rather than trying to out-wait it.
fn steal_scenario(ops: &Ops, host: &str, broker: &Broker) {
    let opened = ops.session_open(open_req(host)).expect("session.open");
    let session_id = SessionId(bare_session_id(&opened.session_ref));
    let rt = tokio::runtime::Runtime::new().expect("throwaway runtime");
    rt.block_on(broker.get(&session_id).expect("session exists").take_lease(
        "device:out-of-band-thief",
        ConnectionId(u64::MAX),
        false,
    ))
    .expect("the broker's own take_lease does not gate on identity");

    let conflict = match attach(ops, &opened.session_ref, true) {
        Err(err) => err,
        Ok(_) => panic!("no_steal must refuse a lease a different principal holds"),
    };
    assert_eq!(conflict.code, ErrorCode::SessionConflict, "{conflict:?}");

    let second =
        attach(ops, &opened.session_ref, false).expect("default steal takes the lease back");
    assert!(
        second.writer_lease(),
        "a stealing attach is granted the lease"
    );

    second.close();
    ops.session_close(SessionCloseReq {
        session_ref: opened.session_ref,
        signal: None,
    })
    .expect("session.close");
}

#[tokio::test(flavor = "multi_thread")]
async fn second_attach_steals_by_default_and_no_steal_conflicts_with_a_foreign_lease() {
    let fx = setup(Arc::new(AllowAllPinned)).await;
    let broker = fx.rig.broker.clone();

    blocking("steal forward", {
        let ops = fx.ops.clone();
        let broker = broker.clone();
        move || steal_scenario(&ops, "fwdhost", &broker)
    })
    .await;
    blocking("steal reverse", {
        let ops = fx.ops.clone();
        move || steal_scenario(&ops, "revhost", &broker)
    })
    .await;

    fx.teardown().await;
}

// ===========================================================================
// Scenario 3 — detach leaves the session running; a reattach replays the
// retained ring from its cursor.
// ===========================================================================

fn detach_reattach_scenario(ops: &Ops, host: &str, pipes: &PipeFactory) {
    let rt = tokio::runtime::Runtime::new().expect("throwaway runtime");
    let opened = ops.session_open(open_req(host)).expect("session.open");
    let mut pipe = pipes.take().expect("pipe handle");
    let mut stream = attach(ops, &opened.session_ref, false).expect("attach");

    let marker = b"pre-detach";
    rt.block_on(pipe.write_output(marker))
        .expect("write_output");
    let mut got = Vec::new();
    while got.len() < marker.len() {
        match stream.next_event().expect("event before EOF").expect("ok") {
            SessionEvent::Output { data_b64, .. } => got.extend_from_slice(&decode_b64(&data_b64)),
            SessionEvent::WriterChanged { .. } => {}
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert_eq!(got, marker);

    let handle = stream.handle();
    let flush = handle.detach();
    assert_eq!(
        flush,
        DetachFlush::Applied,
        "nothing was typed ahead of the detach, so it has nothing to wait for"
    );
    while let Some(event) = stream.next_event() {
        assert!(
            !matches!(event, Ok(SessionEvent::Exit { .. })),
            "detach must not end the session"
        );
    }
    stream.close();

    let info = ops
        .session_get(SessionGetReq {
            session_ref: opened.session_ref.clone(),
        })
        .expect("session.get after detach");
    assert_eq!(info.state, "running", "detach must not end the session");

    let mut second = attach(ops, &opened.session_ref, false).expect("re-attach");
    assert_eq!(
        second.replay_from(),
        0,
        "a plain re-attach replays the whole retained ring from 0, not a live resume cursor"
    );
    let mut replayed = Vec::new();
    while replayed.len() < marker.len() {
        match second.next_event().expect("event before EOF").expect("ok") {
            SessionEvent::Output { data_b64, .. } => {
                replayed.extend_from_slice(&decode_b64(&data_b64))
            }
            SessionEvent::WriterChanged { .. } => {}
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert_eq!(
        replayed, marker,
        "the re-attach's replay cursor serves the pre-detach bytes again"
    );

    second.close();
    ops.session_close(SessionCloseReq {
        session_ref: opened.session_ref,
        signal: None,
    })
    .expect("session.close");
}

#[tokio::test(flavor = "multi_thread")]
async fn detaching_leaves_the_session_running_and_a_reattach_replays_the_retained_ring() {
    let fx = setup(Arc::new(AllowAllPinned)).await;
    let pipes = fx.rig.pipes.clone();

    blocking("detach/reattach forward", {
        let ops = fx.ops.clone();
        let pipes = pipes.clone();
        move || detach_reattach_scenario(&ops, "fwdhost", &pipes)
    })
    .await;
    blocking("detach/reattach reverse", {
        let ops = fx.ops.clone();
        move || detach_reattach_scenario(&ops, "revhost", &pipes)
    })
    .await;

    fx.teardown().await;
}

// ===========================================================================
// Raw `qsh.local.v1`/`qsh.wire.v1` frame-level helpers, reverse-only (no
// forward-route analogue: a forward attach never touches a local daemon).
// Same shapes `local_control_reverse.rs`/`local_stream_reverse.rs` already
// use — each test binary is its own crate, so there is no shared support
// module for these to live in.
// ===========================================================================

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

/// Read the next `ControlMessage`, skipping any spontaneous `SessionEvent`
/// interleaved with a reply.
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

/// Read the next `ControlMessage` and require it to be exactly one
/// `SessionEvent::WriterChanged` broadcast — used where the broadcast
/// itself, not a reply, is the thing under test.
async fn assert_writer_changed(conduit: &mut LocalConduit<UnixStream>) {
    let msg: wire::ControlMessage = tokio::time::timeout(TIMEOUT, conduit.recv())
        .await
        .expect("a writer_changed broadcast arrives within the deadline")
        .expect("recv ControlMessage")
        .expect("conduit stayed open");
    assert!(
        matches!(
            msg.body,
            Some(control_message::Body::SessionEvent(wire::SessionEvent {
                body: Some(wire::session_event::Body::WriterChanged(_)),
                ..
            }))
        ),
        "expected a writer_changed broadcast, got {:?}",
        msg.body
    );
}

fn open_sh() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".to_string()],
        term: "xterm-256color".to_string(),
        cols: 80,
        rows: 24,
        ..Default::default()
    }
}

async fn open_session_raw(
    ctl: &mut LocalConduit<UnixStream>,
    request_id: u64,
) -> wire::SessionOpened {
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

/// Read `SessionFrame`s off `data` until the next `InputAck`, returning its
/// offset.
async fn next_ack(data: &mut LocalConduit<UnixStream>) -> u64 {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let frame: wire::SessionFrame = data
                .recv()
                .await
                .expect("recv SessionFrame")
                .expect("stream ended early");
            if let Some(session_frame::Body::InputAck(a)) = frame.body {
                return a.acked_input_seq;
            }
        }
    })
    .await
    .expect("an ack arrives within the deadline")
}

/// Read exactly `want` bytes of child input off a pipe-backed session.
async fn read_child_input(pipe: &mut qsh_core::broker::PipeHandle, want: usize) -> Vec<u8> {
    tokio::time::timeout(TIMEOUT, async {
        let mut got = Vec::new();
        while got.len() < want {
            let chunk = pipe.read_input(want - got.len()).await.unwrap();
            assert!(!chunk.is_empty(), "the child's input side closed early");
            got.extend_from_slice(&chunk);
        }
        got
    })
    .await
    .expect("the child receives the input within the deadline")
}

// ===========================================================================
// Scenario 4 (reverse-only) — a resend of an already-acked input offset,
// spliced through a real `LOCAL_STREAM` conduit, is never applied twice.
// ===========================================================================

/// The wire-level dedup rule is already proven over both routes, at the
/// raw frame level, by `attach_loopback.rs`'s own
/// `replayed_input_is_discarded_and_re_acked_exactly_once`. What is new
/// here — and has no forward analogue, since a forward attach never
/// touches a local daemon — is that the daemon's `LOCAL_STREAM` byte
/// splice preserves the property exactly: it never parses a `SessionFrame`
/// (`LocalctlDaemon::serve_stream`'s own doc), so this is proof the wire
/// framing survives the splice untouched, not a second proof of the dedup
/// rule itself.
#[tokio::test(flavor = "multi_thread")]
async fn resend_of_an_already_acked_input_seq_through_the_local_stream_splice_is_not_applied_twice()
{
    let fx = setup(Arc::new(AllowAllPinned)).await;

    let mut ctl = connect_control(&fx.localctl.socket_path, "revhost").await;
    let opened = open_session_raw(&mut ctl, 1).await;
    let mut pipe = fx.rig.pipes.take().expect("pipe handle");
    let mut data = connect_stream(&fx.localctl.socket_path, "revhost").await;
    data.send(&wire::StreamHeader::session_data(opened.ticket.clone()))
        .await
        .expect("send StreamHeader");

    data.send(&wire::SessionFrame::input(5, b"hello".to_vec()))
        .await
        .expect("send Input");
    assert_eq!(next_ack(&mut data).await, 5);
    assert_eq!(read_child_input(&mut pipe, 5).await, b"hello");

    // The exact same frame again: applied once, acked again — never a
    // second "hello" reaching the child.
    data.send(&wire::SessionFrame::input(5, b"hello".to_vec()))
        .await
        .expect("send Input (resend)");
    assert_eq!(
        next_ack(&mut data).await,
        5,
        "the resend's ack is repeated, not advanced"
    );

    // A fresh, distinguishable input arrives next with nothing in between
    // — if the resend had been applied, the child would see "hello" a
    // second time ahead of this.
    data.send(&wire::SessionFrame::input(10, b"BYE!!".to_vec()))
        .await
        .expect("send Input");
    assert_eq!(next_ack(&mut data).await, 10);
    assert_eq!(
        read_child_input(&mut pipe, 5).await,
        b"BYE!!",
        "only the bytes past the applied offset ever reach the child"
    );

    fx.teardown().await;
}

// ===========================================================================
// Scenario 5 (reverse-only) — two local conduits sharing one reverse
// registration: request/reply isolation while `SESSION_DATA` is live, and
// the writer_changed broadcast reaches every registered control conduit.
// ===========================================================================

/// "Two CLIs attached at once", read literally for the reverse route: two
/// independent `LOCAL_CONTROL` conduits (what two separate `qsh` processes
/// on the same laptop would each open) sharing the one relayed control
/// stream `ControlHub::send_request` multiplexes onto the target's single
/// reverse connection, proven while a real `LOCAL_STREAM` attach is
/// simultaneously live — the combination `local_control_reverse.rs`'s own
/// `two_conduits_with_the_same_peer_request_id_each_get_their_own_reply`
/// does not yet exercise, since that file predates `LOCAL_STREAM` entirely.
#[tokio::test(flavor = "multi_thread")]
async fn two_local_control_conduits_isolate_replies_and_both_see_the_writer_changed_broadcast() {
    let fx = setup(Arc::new(AllowAllPinned)).await;

    let mut ctl_a = connect_control(&fx.localctl.socket_path, "revhost").await;
    let mut ctl_b = connect_control(&fx.localctl.socket_path, "revhost").await;
    let opened = open_session_raw(&mut ctl_a, 1).await;

    // Redeeming the session's own data ticket acquires the writer lease
    // for the first time (nobody held it before) — a `changed: true` take,
    // which broadcasts to every registered `LOCAL_CONTROL` conduit for
    // this host, `ctl_b` included even though it never touched the
    // session at all.
    let mut data = connect_stream(&fx.localctl.socket_path, "revhost").await;
    data.send(&wire::StreamHeader::session_data(opened.ticket.clone()))
        .await
        .expect("send StreamHeader");
    assert_writer_changed(&mut ctl_a).await;
    assert_writer_changed(&mut ctl_b).await;

    // Request/reply isolation: both conduits pipeline the identical
    // peer `request_id` for *different* request shapes (so a crossed
    // reply fails outright rather than silently passing —
    // `local_control_reverse.rs`'s own review finding), while the
    // `LOCAL_STREAM` conduit above is live and unread.
    send_control(
        &mut ctl_a,
        42,
        control_message::Body::SessionList(wire::SessionList {}),
    )
    .await;
    send_control(
        &mut ctl_b,
        42,
        control_message::Body::SessionGet(wire::SessionGet {
            session_id: opened.session_id.clone(),
        }),
    )
    .await;
    let ra = recv_control_response(&mut ctl_a).await;
    let rb = recv_control_response(&mut ctl_b).await;
    assert_eq!(
        ra.request_id, 42,
        "conduit a's own request_id comes back unchanged"
    );
    assert_eq!(
        rb.request_id, 42,
        "conduit b's own request_id comes back unchanged"
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
         (a SessionInfo here would mean b's reply crossed to a)",
        ra.body
    );
    assert!(
        matches!(
            &rb.body,
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::SessionInfo(_)),
                ..
            }))
        ),
        "conduit b must get its own SessionInfo, got {:?} \
         (a SessionListResult here would mean a's reply crossed to b)",
        rb.body
    );

    fx.teardown().await;
}
