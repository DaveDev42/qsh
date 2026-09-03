//! L3 — headless `session.*` value ops driven through real [`Ops`], over
//! both routes `Ops::connect` can now take (`PLAN.md` M3 Step 6): a real
//! target (owning the session broker), a real `qsh listen` controller
//! (`qsh_testkit::reverse::ReverseHarness`) with a real localctl daemon
//! attached, and a real `Ops` instance in-process on the "laptop" side of
//! that daemon — the exact three-actor shape `docs/design/protocol.md`
//! §11-3 describes, driven end to end rather than at the raw frame level
//! (`local_control_reverse.rs` already owns that layer).
//!
//! Unlike `session_loopback.rs`'s `HostedPair` (which proves role-axis
//! independence for a raw `client::Session` handed to it directly), every
//! scenario here goes through [`Ops`] itself, so it also exercises
//! `Ops::resolve_route`/`Ops::connect`'s routing choice and
//! `Connected::peer_fingerprint`'s reverse-leg behavior — the part of
//! Step 6 that is new.
//!
//! What this file deliberately does **not** attempt: `session.attach`
//! over the reverse route. `Ops::session_attach` still resolves its peer
//! via `Ops::resolve_peer`/`Ops::connect_target` unconditionally
//! (`ops/session.rs`'s own doc on `Ops::connect`: "`session.attach`'s own
//! `connect_target` call stays forward-only (M3 Step 7 adds its reverse
//! leg)"), and the writer-lease ticket a real attach mints is only
//! redeemed by opening a second QUIC stream (`Session::open_attach_stream`)
//! — a data-plane primitive `ControlLink::Local` has no relay for yet
//! (Step 7's `LOCAL_STREAM` conduit kind). So the writer-lease invariant
//! below is proven the way it actually *can* be in this step: structurally,
//! by observing that a dead `LOCAL_CONTROL` conduit never reaches
//! `Server::purge_connection` (only the shared reverse QUIC connection the
//! daemon owns can do that) — the mechanism the M3 Step 6 invariant text
//! names — rather than by driving a full attach/steal round trip over
//! reverse, which has no producer to drive yet.
//!
//! `#![cfg(unix)]`: localctl (UDS) is unix-only, same gating as every
//! other localctl testkit file.

#![cfg(unix)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use qsh_core::acl::{AllowAllPinned, Authorizer, DenyAll};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, BrokerConfig, PeerFingerprint, PipeFactory, SystemClock};
use qsh_core::handshake;
use qsh_core::resume::{NoToken, ResumeStore};
use qsh_core::server::{ConnCtx, Server};
use qsh_core::{Fingerprint, Ops, Paths, Principal};
use qsh_proto::{
    EnvVar, ErrorCode, IdentityInitReq, KeyStoreMode, SessionCloseReq, SessionGetReq,
    SessionListReq, SessionOpenReq, SessionReadReq, SessionResizeReq, SessionWriteReq, TrustAddReq,
};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_transport::{Dialed, Listener, StaticTrust};

/// Bound on every "this must already have happened" wait — same order of
/// magnitude as every other reverse testkit file's own `TIMEOUT`.
const TIMEOUT: Duration = Duration::from_secs(5);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// Run a blocking [`Ops`] call (every `Ops` session method builds its own
/// runtime internally — `ops/session.rs`'s own doc on why) off the
/// calling `#[tokio::test]` worker thread, exactly like
/// `host_list_reverse.rs`'s own `host_list`/`host_get`/`resolve_route`
/// helpers.
async fn blocking<T: Send + 'static>(ops: &Ops, f: impl FnOnce(&Ops) -> T + Send + 'static) -> T {
    let ops = ops.clone();
    tokio::task::spawn_blocking(move || f(&ops))
        .await
        .expect("spawn_blocking join")
}

/// A fresh [`Ops`] with a file-mode device identity already initialized
/// (needed for the forward leg's own dial) and its `runtime_dir()` ready
/// for [`ReverseHarness::attach_localctl`] to bind a socket under.
/// Returns the identity's own fingerprint too, since [`TargetRig::start`]
/// needs to pin it before `Ops` can dial in over the forward leg.
async fn fresh_ops() -> (tempfile::TempDir, Ops, Fingerprint) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    let data = blocking(&ops, |ops| {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
    })
    .await
    .expect("identity.init");
    let fingerprint = data
        .fingerprint
        .parse::<Fingerprint>()
        .expect("parse this device's own fingerprint");
    (dir, ops, fingerprint)
}

/// A hand-built host: a real broker (pipe-backed, deterministic — no PTY
/// code, `session_loopback.rs`'s own convention) reachable *both* as a
/// direct forward listener and, once [`Self::register_reverse`] is
/// called, as a live reverse registration on a [`ReverseHarness`]
/// controller — the same [`Server`]/[`Broker`] instance either way, so a
/// session opened over one route is visible over the other.
struct TargetRig {
    server: Arc<Server>,
    broker: Arc<Broker>,
    /// This rig's own transport identity for the forward listener — kept
    /// so a caller can pin its fingerprint into an `Ops` trust.toml
    /// (`TrustAddReq` has no "probe and pin" primitive; it demands the
    /// fingerprint up front, `docs/CLI.md`'s deliberate fail-closed
    /// design).
    forward_identity: TestIdentity,
    forward_addr: SocketAddr,
    forward_task: tokio::task::JoinHandle<()>,
    forward_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// Kept alive for as long as a reverse registration should live —
    /// [`Dialed`]'s own doc: dropping the endpoint does not close the
    /// connection, but the whole value must outlive the registration.
    reverse_conn: Option<Dialed>,
    reverse_task: Option<tokio::task::JoinHandle<()>>,
}

impl TargetRig {
    /// `authorizer` governs every session op this rig's `Server` answers,
    /// on *both* routes — the "unauthorized principal" test swaps in
    /// [`DenyAll`], everything else uses [`AllowAllPinned`] (the interim
    /// M1-M4 posture). `cli_fingerprint` is pinned as the only identity
    /// allowed to dial the forward listener directly.
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
                quota_limits: qsh_core::quota::QuotaLimits::default(),
            },
            pipes,
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
            forward_identity,
            forward_addr,
            forward_task,
            forward_shutdown: Some(tx),
            reverse_conn: None,
            reverse_task: None,
        }
    }

    /// Register this rig's shared broker/server with `harness` as a
    /// reverse target under `reverse_identity`'s pin, offering
    /// `offered_name` (the controller alias is whatever `harness`'s own
    /// inbound trust pins that fingerprint to — `host_list_reverse.rs`'s
    /// own note: never the offered name). Spawns the real
    /// `Server::serve_control` on the registered connection, so session
    /// ops relayed through the controller's `LOCAL_CONTROL` conduits hit
    /// this rig's *same* broker the forward listener does.
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
            // A real registration via `ReverseHarness::register` (this
            // fn's own doc) — every local CLI process the controller
            // relays for shares this one connection
            // (`ConnCtx::is_reverse_registration`'s own doc).
            is_reverse_registration: true,
        };
        let server = self.server.clone();
        let conn_id = ctx.conn_id;
        let task = tokio::spawn(async move {
            let _ = server.clone().serve_control(&conn, ctl, ctx, None).await;
            server.purge_connection(conn_id, ()).await;
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

/// `session.open -> get -> list -> read -> write -> resize -> close`, the
/// full owed L3 chain, driven at `host` through `ops` — identical body run
/// against both the forward and the reverse alias of the same target
/// (`PLAN.md` M3 Step 6 (c): "정방향과 같은 시나리오 함수"). Returns the
/// bare session id (host-alias-independent) so a caller can look the same
/// session up under a *different* alias afterward.
async fn full_lifecycle_open_get_list_read_write_resize_close(ops: &Ops, host: &str) -> String {
    let host_s = host.to_string();
    let opened = blocking(ops, {
        let host_s = host_s.clone();
        move |ops| ops.session_open(open_req(&host_s))
    })
    .await
    .unwrap_or_else(|err| panic!("session.open on {host}: {err:?}"));
    let session_ref = opened.session_ref.clone();
    assert!(!session_ref.is_empty());
    assert_eq!(opened.initial_sequence, 0);

    let got = blocking(ops, {
        let r = session_ref.clone();
        move |ops| ops.session_get(SessionGetReq { session_ref: r })
    })
    .await
    .unwrap_or_else(|err| panic!("session.get on {host}: {err:?}"));
    assert_eq!(got.session_ref, session_ref);
    assert_eq!(got.host, host);

    let listed = blocking(ops, {
        let h = host_s.clone();
        move |ops| ops.session_list(SessionListReq { host: Some(h) })
    })
    .await
    .unwrap_or_else(|err| panic!("session.list on {host}: {err:?}"));
    assert!(
        listed.sessions.iter().any(|s| s.session_ref == session_ref),
        "session.list on {host} did not contain the just-opened session: {listed:?}"
    );

    let write_data = base64::engine::general_purpose::STANDARD.encode(b"echo hi\n");
    let wrote = blocking(ops, {
        let r = session_ref.clone();
        move |ops| {
            ops.session_write(SessionWriteReq {
                session_ref: r,
                data_b64: write_data,
            })
        }
    })
    .await
    .unwrap_or_else(|err| panic!("session.write on {host}: {err:?}"));
    assert_eq!(wrote.session_ref, session_ref);

    let _read = blocking(ops, {
        let r = session_ref.clone();
        move |ops| {
            ops.session_read(SessionReadReq {
                session_ref: r,
                after_sequence: 0,
                wait_ms: None,
                limit_bytes: None,
                ctl_after: None,
            })
        }
    })
    .await
    .unwrap_or_else(|err| panic!("session.read on {host}: {err:?}"));

    let resized = blocking(ops, {
        let r = session_ref.clone();
        move |ops| {
            ops.session_resize(SessionResizeReq {
                session_ref: r,
                cols: 100,
                rows: 40,
            })
        }
    })
    .await
    .unwrap_or_else(|err| panic!("session.resize on {host}: {err:?}"));
    assert_eq!(resized.cols, 100);
    assert_eq!(resized.rows, 40);

    let closed = blocking(ops, {
        let r = session_ref.clone();
        move |ops| {
            ops.session_close(SessionCloseReq {
                session_ref: r,
                signal: None,
            })
        }
    })
    .await
    .unwrap_or_else(|err| panic!("session.close on {host}: {err:?}"));
    assert_eq!(closed.session_ref, session_ref);

    session_ref
        .rsplit_once('/')
        .expect("session_ref is host/session_id")
        .1
        .to_string()
}

/// The milestone's central L3 proof: the identical `session.*` chain,
/// through the identical `Ops`, succeeds whether `Ops::resolve_route`
/// picks the forward pin or the live reverse registration — the routing
/// split is invisible to the six value ops' bodies (`PLAN.md` M3 Step 6:
/// "결과: session_open/get/list/read/write/resize/close의 본문은 한 줄도
/// 바뀌지 않는다").
#[tokio::test(flavor = "multi_thread")]
async fn session_lifecycle_succeeds_over_both_forward_and_reverse_routes() {
    let (_ops_dir, ops, cli_fp) = fresh_ops().await;
    let mut rig = TargetRig::start(Arc::new(AllowAllPinned), cli_fp).await;

    blocking(&ops, {
        let addr = rig.forward_addr.to_string();
        let fp = rig.forward_identity.fingerprint.to_string();
        move |ops| {
            ops.trust_add(TrustAddReq {
                name: "fwdhost".into(),
                address: Some(addr),
                fingerprint: Some(fp),
            })
        }
    })
    .await
    .expect("trust.add fwdhost");

    let reverse_identity = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&reverse_identity, "revhost"),
    )
    .await;
    rig.register_reverse(&harness, &reverse_identity, "laptop-offered-name")
        .await;
    wait_for(TIMEOUT, || harness.listen.registry().get("revhost")).await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let fwd_id = full_lifecycle_open_get_list_read_write_resize_close(&ops, "fwdhost").await;
    let rev_id = full_lifecycle_open_get_list_read_write_resize_close(&ops, "revhost").await;
    assert_ne!(
        fwd_id, rev_id,
        "forward and reverse runs must each open their own session"
    );

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// `PLAN.md` M3 Step 6's most important security test: a reverse
/// registration grants *reachability*, never *authority* — the target
/// alone decides, against the controller's own authenticated principal
/// (`docs/design/protocol.md` §11-3, this file's HARD RULES). A `Server`
/// under [`DenyAll`] refuses `session.open` relayed over the reverse
/// route with `PERMISSION_DENIED`, and no session is created on the
/// target's broker as a side effect of the attempt
/// (`docs/security defaults`: never create a resource before
/// authorization succeeds).
#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_principal_session_open_over_reverse_is_permission_denied() {
    let (_ops_dir, ops, cli_fp) = fresh_ops().await;
    // `DenyAll`: every `Authorizer::check` call denies, regardless of
    // principal or auth path — the target's own ACL choke point, the one
    // `localctl` grants no authority around.
    let mut rig = TargetRig::start(Arc::new(DenyAll), cli_fp).await;

    let reverse_identity = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&reverse_identity, "denied-host"),
    )
    .await;
    rig.register_reverse(&harness, &reverse_identity, "laptop")
        .await;
    wait_for(TIMEOUT, || harness.listen.registry().get("denied-host")).await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    assert_eq!(
        rig.broker.session_count(),
        0,
        "no session exists before the denied attempt"
    );

    let err = blocking(&ops, |ops| ops.session_open(open_req("denied-host")))
        .await
        .expect_err("an unauthorized principal's session.open must be refused");
    assert_eq!(err.code, ErrorCode::PermissionDenied, "{err:?}");

    assert_eq!(
        rig.broker.session_count(),
        0,
        "a denied session.open must never create a session as a side effect"
    );

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// The input side of ADR-0007's presentation condition on the reverse
/// leg: the resume credential `session.open` stores is bound to
/// `Connected::peer_fingerprint()` — which, for the reverse route, is
/// exactly `LocalHelloAck.peer_fingerprint` (the daemon's own TLS-verified
/// SPKI for *that* registration), never re-derived by this process (which
/// holds no QUIC connection to the peer at all on this leg) — and that
/// `ResumeStore` itself fails closed on any other peer string.
///
/// **What this test does NOT cover** (naming it explicitly so nobody reads
/// it as more than it is): the *output* side — `Ops::session_attach`'s own
/// `let Some(peer) = conn.peer_fingerprint() else { … PeerMismatch }`
/// gate (`ops/session.rs`) that decides whether a token is presented at
/// all. `session_attach` resolves forward-only today
/// (`Ops::resolve_peer`/`connect_target`) — a reverse-only host fails at
/// `HOST_NOT_FOUND` before that gate is ever reached — so this file
/// cannot drive that path end to end over reverse until Step 7 adds
/// reverse attach. Until then, this pins only "the ack's fingerprint
/// reaches the store, and the store refuses a mismatched key"; it does
/// not mechanically prove the reverse leg cannot present a token to the
/// wrong peer. Step 7 owes the companion test through `session_attach`
/// itself.
#[tokio::test(flavor = "multi_thread")]
async fn resume_store_on_the_reverse_leg_is_seeded_from_the_acks_peer_fingerprint_and_fails_closed_on_mismatch()
 {
    let (_ops_dir, ops, cli_fp) = fresh_ops().await;
    let mut rig = TargetRig::start(Arc::new(AllowAllPinned), cli_fp).await;

    let reverse_identity = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&reverse_identity, "revhost"),
    )
    .await;
    rig.register_reverse(&harness, &reverse_identity, "laptop")
        .await;
    wait_for(TIMEOUT, || harness.listen.registry().get("revhost")).await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let opened = blocking(&ops, |ops| ops.session_open(open_req("revhost")))
        .await
        .expect("session.open over reverse");
    let session_ref = opened.session_ref.clone();

    let store = ResumeStore::new(ops.paths());
    let entry = store
        .get(&session_ref)
        .expect("session.open over reverse must store a resume entry");
    assert_eq!(
        entry.peer_spki_sha256,
        reverse_identity.fingerprint.to_string(),
        "the stored peer must be exactly the target's own SPKI, as the daemon's \
         LocalHelloAck reported it for this registration — never re-derived"
    );

    // Match: the real, correct peer redeems successfully.
    let redeemed = store
        .take_for(&session_ref, &reverse_identity.fingerprint.to_string())
        .expect("the correct peer must redeem the stored token");
    assert_eq!(redeemed.expose().len(), 32);

    // Re-seed (the successful `take_for` above consumed the entry) and
    // prove the mismatch path: any other peer string is refused locally,
    // fails closed, `peer_mismatch` — the exact `Ops::session_attach`
    // path this file cannot drive end to end over reverse yet (module
    // docs), tested directly against the same `ResumeStore` a real attach
    // would use.
    let opened2 = blocking(&ops, |ops| ops.session_open(open_req("revhost")))
        .await
        .expect("second session.open over reverse");
    let session_ref2 = opened2.session_ref.clone();
    let wrong_peer = "sha256:0000000000000000000000000000000000000000000=";
    let mismatch = store
        .take_for(&session_ref2, wrong_peer)
        .expect_err("a mismatched peer must never redeem the stored token");
    assert_eq!(mismatch, NoToken::PeerMismatch);
    let as_error = mismatch.into_error(&session_ref2);
    assert_eq!(as_error.code, ErrorCode::SessionNotFound);
    assert_eq!(
        as_error.details.get("reason").and_then(|v| v.as_str()),
        Some("peer_mismatch")
    );
    // `ResumeStore::take_for`'s own doc: a peer mismatch discards the
    // entry outright (an alias re-pinned to another device must not keep
    // offering a credential that device cannot hold) — so the *next*
    // lookup, even by the correct peer, now finds nothing rather than
    // silently succeeding. No token was ever sent to reach this state.
    let gone = store
        .take_for(&session_ref2, &reverse_identity.fingerprint.to_string())
        .expect_err("a mismatched lookup must discard the entry, not just refuse it");
    assert_eq!(gone, NoToken::Missing);

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// Lifecycle: killing the resident daemon (this machine's localctl relay,
/// not the target) mid-session leaves the CLI with a clear typed error on
/// its very next call — the reverse route simply stops resolving, since
/// the discovery step this device's own `Ops::resolve_route` performs is
/// itself a localctl round trip — while the target's own broker, whose
/// connection to the controller was never touched, keeps the session
/// alive. Proven over a *different* alias that only ever routes forward
/// (`docs/CLI.md` §6.13: a reverse-routed session is not tied to any one
/// alias, only to the target's own broker), never by asking the dead
/// route again.
#[tokio::test(flavor = "multi_thread")]
async fn killing_the_daemon_mid_session_gives_the_cli_a_clear_error_while_the_target_survives() {
    let (_ops_dir, ops, cli_fp) = fresh_ops().await;
    let mut rig = TargetRig::start(Arc::new(AllowAllPinned), cli_fp).await;

    // A forward pin under a *different* alias to the same target, purely
    // so this test can later prove liveness without going anywhere near
    // the now-dead daemon.
    blocking(&ops, {
        let addr = rig.forward_addr.to_string();
        let fp = rig.forward_identity.fingerprint.to_string();
        move |ops| {
            ops.trust_add(TrustAddReq {
                name: "fwdhost".into(),
                address: Some(addr),
                fingerprint: Some(fp),
            })
        }
    })
    .await
    .expect("trust.add fwdhost");

    let reverse_identity = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&reverse_identity, "revhost"),
    )
    .await;
    rig.register_reverse(&harness, &reverse_identity, "laptop")
        .await;
    wait_for(TIMEOUT, || harness.listen.registry().get("revhost")).await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let opened = blocking(&ops, |ops| ops.session_open(open_req("revhost")))
        .await
        .expect("session.open over reverse, daemon alive");
    let session_id = opened
        .session_ref
        .rsplit_once('/')
        .expect("session_ref is host/session_id")
        .1
        .to_string();

    // Kill *only* the localctl UDS daemon — the controller's own QUIC
    // registry and the target's registered connection are untouched.
    localctl.shutdown().await;

    let err = blocking(&ops, {
        let session_id = session_id.clone();
        move |ops| {
            ops.session_get(SessionGetReq {
                session_ref: format!("revhost/{session_id}"),
            })
        }
    })
    .await
    .expect_err("the very next reverse-routed call must fail once the daemon is dead");
    assert!(
        matches!(
            err.code,
            ErrorCode::HostNotFound | ErrorCode::ConnectionFailed | ErrorCode::Internal
        ),
        "expected a clear typed routing/connection error, got {err:?}"
    );

    // The target's own session is still running — proven over the
    // forward alias, never by retrying the now-dead reverse route.
    let listed = blocking(&ops, |ops| {
        ops.session_list(SessionListReq {
            host: Some("fwdhost".into()),
        })
    })
    .await
    .expect("session.list over the forward route, unaffected by the dead daemon");
    assert!(
        listed.sessions.iter().any(|s| s.session_id == session_id),
        "the target's session must still be running after only the daemon died: {listed:?}"
    );

    harness.shutdown().await;
    rig.shutdown().await;
}
