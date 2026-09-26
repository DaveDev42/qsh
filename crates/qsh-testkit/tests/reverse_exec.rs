//! L3 — `Ops::exec_run` driven end to end over a real reverse registration
//! (issue #5): the same three-actor shape `reverse_session_ops.rs` already
//! proves for the six `session.*` value ops (a real target `Server`, a
//! real `qsh listen` controller — `qsh_testkit::reverse::ReverseHarness` —
//! with its localctl daemon attached, and a real `Ops` instance dialing/
//! relaying through it), driven here for `exec.run` instead.
//!
//! What is already proven elsewhere and is **not** re-proven here:
//! - the raw `EXEC_DATA` relay itself, at the wire level, including the
//!   UDS-EOF -> QUIC reset rule, the ack-before-splice shape, and a client
//!   that abandons its conduit still kills a silent remote command
//!   (`local_stream_reverse.rs`);
//! - `Session::exec`'s own reverse-route behavior: the same daemon socket
//!   and host as `LOCAL_CONTROL`, fail-closed on a stale registration
//!   generation, still collects output sent after `StdinEof`, and the
//!   old-daemon `INVALID_ARGUMENT` -> named-cause message mapping
//!   (`crates/qsh-core/src/client/mod.rs`'s `reverse_tests`);
//! - `CONFIG_ERROR`-before-routing, the `not_in_trust_store`/
//!   `pinned_without_address`/`user@`-prefix message split, and the
//!   two-live-daemon `INVALID_ARGUMENT` exec inherits unchanged — all pure
//!   decisions, unit tested directly against `Ops::resolve_exec_route`/
//!   `host::resolve_route` (`crates/qsh-core/src/ops/exec.rs`'s own `mod
//!   tests`, `crates/qsh-core/src/ops/host/tests.rs`).
//!
//! This file's own job is the one thing none of those prove: that
//! `Ops::exec_run` itself — routing, dial-or-relay, and result assembly,
//! through the same public API a real `qsh exec` calls — behaves
//! correctly end to end once a live reverse registration is involved.
//!
//! One deliberate gap: `Ops::exec_run`'s public `ExecStdin` is only
//! `Closed`/`Inherit` (this process's own stdin) — there is no seam to
//! hand it a synthetic reader the way `Session::exec` itself takes one.
//! Streaming a chosen stdin payload through the reverse route is already
//! proven at that lower layer
//! (`exec_on_a_reverse_session_still_collects_output_sent_after_stdin_eof`,
//! `client/mod.rs`); every scenario here uses `ExecStdin::Closed` and
//! still exercises the real `StdinEof` frame it sends.
//!
//! `#![cfg(unix)]`: localctl (UDS) is unix-only, same gating every other
//! localctl testkit file uses.

#![cfg(unix)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::{AllowAllPinned, Authorizer, DenyAll};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, BrokerConfig, PeerFingerprint, PipeFactory, SystemClock};
use qsh_core::client::EXEC_OUTPUT_MAX;
use qsh_core::handshake;
use qsh_core::server::{ConnCtx, Server};
use qsh_core::{ExecStdin, Ops, Paths, Principal};
use qsh_proto::{ErrorCode, ExecRunReq, IdentityInitReq, KeyStoreMode, TrustAddReq};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::ReverseHarness;
use qsh_transport::{Dialed, StaticTrust};

/// Bound on every "this must have already happened" wait in this file —
/// generous relative to a pure in-memory relay: a real reverse
/// registration, a real localctl round trip and, for several scenarios, a
/// real forked child.
const TIMEOUT: Duration = Duration::from_secs(20);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// A throwaway address nothing ever answers on — bind a real UDP port,
/// then drop the socket, exactly like `ops/exec.rs`'s own
/// `exec_async_tries_every_resolved_address_not_only_the_first`.
fn dead_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a throwaway UDP port");
    socket.local_addr().expect("local addr")
}

/// Run a blocking [`Ops`] call off the calling `#[tokio::test]` worker
/// thread — every `Ops` session/exec method builds its own runtime
/// internally, exactly like `reverse_session_ops.rs`'s own helper of the
/// same name.
async fn blocking<T: Send + 'static>(ops: &Ops, f: impl FnOnce(&Ops) -> T + Send + 'static) -> T {
    let ops = ops.clone();
    tokio::task::spawn_blocking(move || f(&ops))
        .await
        .expect("spawn_blocking join")
}

/// A fresh [`Ops`] with a file-mode device identity already initialized
/// (exec.run's own `CONFIG_ERROR` guard, `ops/exec.rs`'s own doc) and its
/// `runtime_dir()` ready for [`ReverseHarness::attach_localctl`] to bind a
/// socket under.
async fn fresh_ops() -> (tempfile::TempDir, Ops) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    blocking(&ops, |ops| {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        })
    })
    .await
    .expect("identity.init");
    (dir, ops)
}

async fn trust_add(ops: &Ops, name: &str, address: Option<SocketAddr>, fingerprint: &TestIdentity) {
    let name = name.to_string();
    let address = address.map(|a| a.to_string());
    let fp = fingerprint.fingerprint.to_string();
    blocking(ops, move |ops| {
        ops.trust_add(TrustAddReq {
            name,
            address,
            fingerprint: Some(fp),
            cert_pem: None,
        })
    })
    .await
    .unwrap_or_else(|err| panic!("trust.add: {err:?}"));
}

fn exec_req(host: &str, argv: &[&str]) -> ExecRunReq {
    ExecRunReq {
        host: host.to_string(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: vec![],
        timeout_ms: Some(5_000),
    }
}

async fn wait_for_pid(marker: &Path) -> u32 {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let Ok(contents) = std::fs::read_to_string(marker)
                && let Ok(pid) = contents.trim().parse::<u32>()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the child must record its own pid within the deadline")
}

async fn wait_for_pid_gone(pid: u32) {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let alive = tokio::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .await
                .expect("run kill -0")
                .success();
            if !alive {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("pid {pid} must be gone within {TIMEOUT:?}"));
}

/// Poll `ops.host_list()` until `name`'s reverse entry reports `state`
/// (`"reachable"` or `"stale"`) — the same daemon-observed state
/// `crates/qsh-cli/tests/fixtures.rs`'s `golden_reverse_stale_fixtures`
/// polls for through the real CLI, here read straight off [`Ops`].
async fn wait_for_reverse_state(ops: &Ops, name: &str, state: &str) {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let listed = blocking(ops, |ops| ops.host_list())
                .await
                .expect("host.list");
            if listed
                .hosts
                .iter()
                .any(|h| h.name == name && h.connection_mode == "reverse" && h.state == state)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{name} did not reach reverse state {state:?} within the deadline"));
}

/// A hand-built target: a real [`Server`] (its own broker/audit, exactly
/// like `reverse_session_ops.rs`'s own `TargetRig`, minus the forward
/// listener that file's session-op scenarios need and this file's
/// routing-only scenarios do not) registered with a [`ReverseHarness`]
/// controller as a live reverse target. `authorizer` governs every
/// `exec.run` this rig answers.
struct ExecTargetRig {
    server: Arc<Server>,
    audit: Arc<MemoryAuditSink>,
    reverse_conn: Option<Dialed>,
    reverse_task: Option<tokio::task::JoinHandle<()>>,
}

impl ExecTargetRig {
    async fn start(authorizer: Arc<dyn Authorizer>) -> Self {
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
        let server = Server::new(authorizer, audit.clone(), broker, "target");
        Self {
            server,
            audit,
            reverse_conn: None,
            reverse_task: None,
        }
    }

    /// Register with `harness` under whatever alias its own inbound trust
    /// pins `reverse_identity`'s fingerprint to (never `offered_name`
    /// itself — `ReverseHarness::register`'s own doc), and spawn the real
    /// `Server::serve_control` on the registered connection so `exec.run`
    /// relayed through the controller's `LOCAL_CONTROL`/`LOCAL_STREAM`
    /// conduits hits this rig's real `Server`.
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

    /// End only the reverse connection — for the stale-registration test,
    /// which needs the controller's own registry to notice the connection
    /// died and flip the entry to `"stale"`, never a dial attempt.
    async fn sever_reverse(&mut self) {
        if let Some(conn) = self.reverse_conn.take() {
            conn.connection.close(0, b"test severs the reverse leg");
        }
        if let Some(task) = self.reverse_task.take() {
            let _ = task.await;
        }
    }

    async fn shutdown(mut self) {
        self.sever_reverse().await;
    }
}

/// The 09-26 reproduction from issue #5 itself: a forward pin whose
/// address is dead (the target's NAT mapping moved on) alongside a live
/// reverse registration under the *same* alias. `exec.run` must pick the
/// live reverse registration — `Ops::resolve_host_route`'s routing
/// priority, never the dead pin — and so must succeed promptly, not spend
/// the dial's own connection-attempt budget on an address nothing answers.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_prefers_a_live_reverse_registration_over_a_dead_forward_pin() {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(AllowAllPinned)).await;
    let target_identity = make_identity();

    trust_add(&ops, "revhost", Some(dead_addr()), &target_identity).await;

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "revhost"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("revhost").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let out = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, |ops| {
            ops.exec_run(exec_req("revhost", &["true"]), ExecStdin::Closed)
        }),
    )
    .await
    .expect("must not fall through to the dead forward pin's own dial timeout")
    .expect("exec.run must prefer the live reverse registration");
    assert_eq!(out.data.remote_exit_code, 0);

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// The 09-25 reproduction: a trust-store pin with a fingerprint but no
/// address (`qsh trust add --fingerprint ... `, no `--address`) and a live
/// reverse registration under that same alias. `exec.run` must reach it
/// over reverse — there is no forward address to have fallen back to.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_reaches_a_reverse_only_host_pinned_without_address() {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(AllowAllPinned)).await;
    let target_identity = make_identity();

    trust_add(&ops, "revhost2", None, &target_identity).await;

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "revhost2"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("revhost2").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let out = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, |ops| {
            ops.exec_run(exec_req("revhost2", &["true"]), ExecStdin::Closed)
        }),
    )
    .await
    .expect("must not hang")
    .expect("exec.run must reach a reverse-only host pinned without an address");
    assert_eq!(out.data.remote_exit_code, 0);

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// POSIX signal semantics survive the whole `Ops::exec_run` round trip
/// over reverse, not just `Session::exec` directly (`exec_loopback.rs`'s
/// own `exec_signal_exit_and_timeout_kill_report_sigkill` proves the
/// forward-route/client-level version of this).
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_over_reverse_reports_exit_code_and_signal() {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(AllowAllPinned)).await;
    let target_identity = make_identity();

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "sig-host"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("sig-host").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let out = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, |ops| {
            ops.exec_run(
                exec_req("sig-host", &["sh", "-c", "kill -9 $$"]),
                ExecStdin::Closed,
            )
        }),
    )
    .await
    .expect("must not hang")
    .expect("exec.run over reverse");
    assert_eq!(out.data.remote_exit_code, 137);
    assert_eq!(out.data.signal.as_deref(), Some("SIGKILL"));

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// Pins the end-to-end result of the `--timeout` deadline
/// `exec_async_reverse` races against `dial_reverse`/`Session::exec` over
/// reverse: a `TIMEOUT` error plus the remote command actually dying —
/// exactly like the forward route's `connection.close()` achieves. This
/// test does not isolate *which* mechanism kills the process (the host's
/// own `run_exec` timeout fires here regardless of the data-conduit kill
/// switch); `exec_client_drop_over_reverse_kills_a_silent_remote_command`
/// is the one that pins the `DataKillSwitch`/UDS-EOF→reset rule this issue
/// adds on its own.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_over_reverse_timeout_kills_the_remote_command() {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(AllowAllPinned)).await;
    let target_identity = make_identity();

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "timeout-host"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("timeout-host").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let marker_dir = tempfile::tempdir().expect("tempdir");
    let marker = marker_dir.path().join("pid");
    let script = format!("echo $$ > {} ; exec sleep 60", marker.display());
    let mut req = exec_req("timeout-host", &["sh", "-c", &script]);
    req.timeout_ms = Some(300);

    let err = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, move |ops| ops.exec_run(req, ExecStdin::Closed)),
    )
    .await
    .expect("must not hang")
    .expect_err("a timeout must surface as an error, not a truncated success");
    assert_eq!(err.code, ErrorCode::Timeout);

    let pid = wait_for_pid(&marker).await;
    wait_for_pid_gone(pid).await;

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// Pins the end-to-end result of `exec.run`'s output cap (`EXEC_OUTPUT_MAX`,
/// `client/mod.rs`) over reverse: exceeding it must fail closed with
/// `RESOURCE_EXHAUSTED` (never a silently truncated "success") and the
/// remote command must actually die rather than being left as a
/// still-writing orphan. This test does not isolate `Session::exec`'s
/// `recv_half.abort` as the mechanism — the daemon's own
/// `quic_recv.stop(PEER_GONE)` on UDS EOF (`crate::localctl::daemon`)
/// already makes the host's writer fail on its own;
/// `exec_client_drop_over_reverse_kills_a_silent_remote_command` is the one
/// that isolates the kill-switch/reset rule.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_over_reverse_output_cap_is_resource_exhausted_and_kills_the_command() {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(AllowAllPinned)).await;
    let target_identity = make_identity();

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "cap-host"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("cap-host").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let marker_dir = tempfile::tempdir().expect("tempdir");
    let marker = marker_dir.path().join("pid");
    // `yes` writes fast and forever — well past `EXEC_OUTPUT_MAX` long
    // before this test's own `TIMEOUT` — so the cap, not the child
    // finishing on its own, is what ends this exec.
    let script = format!("echo $$ > {} ; exec yes 0123456789abcdef", marker.display());
    let mut req = exec_req("cap-host", &["sh", "-c", &script]);
    req.timeout_ms = None;

    let err = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, move |ops| ops.exec_run(req, ExecStdin::Closed)),
    )
    .await
    .expect("must not hang")
    .expect_err("output over the cap must fail, not succeed with truncated output");
    assert_eq!(err.code, ErrorCode::ResourceExhausted);
    assert_eq!(
        err.details["limit_bytes"],
        serde_json::json!(EXEC_OUTPUT_MAX)
    );

    let pid = wait_for_pid(&marker).await;
    wait_for_pid_gone(pid).await;

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// `docs/design/protocol.md` §11-3's own HARD RULE, for `exec.run`
/// specifically: a reverse registration grants reachability, never
/// authority. A target `Server` under [`DenyAll`] refuses `exec.run`
/// relayed over the reverse route with `PERMISSION_DENIED`, creating
/// nothing — no ticket ever issued — as a side effect of the attempt
/// (`CLAUDE.md`: never create a resource before authorization succeeds).
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_over_reverse_is_denied_by_the_target_acl_and_creates_nothing() {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(DenyAll)).await;
    let target_identity = make_identity();

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "denied-host"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("denied-host").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let err = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, |ops| {
            ops.exec_run(exec_req("denied-host", &["true"]), ExecStdin::Closed)
        }),
    )
    .await
    .expect("must not hang")
    .expect_err("a denied principal's exec.run must be refused");
    assert_eq!(err.code, ErrorCode::PermissionDenied);

    assert_eq!(
        rig.server.pending_tickets(),
        0,
        "a denied exec.run must never create a ticket as a side effect"
    );
    let records = rig.audit.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].action, "exec.run");
    assert_eq!(records[0].decision, "deny");

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// An allowed `exec.run` relayed over reverse writes exactly one audit
/// record on the target, and it carries the controller's own principal —
/// `Principal::Device("controller")`, the pin `ReverseHarness::dialer_for`
/// gives the connection the target itself dialed to register — never the
/// target's own identity or `Principal::Device("laptop")`'s CLI-side
/// convention from the forward tests.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_over_reverse_allowed_writes_exactly_one_allow_audit_record_with_the_controller_principal()
 {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(AllowAllPinned)).await;
    let target_identity = make_identity();

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "audited-host"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("audited-host").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let out = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, |ops| {
            ops.exec_run(exec_req("audited-host", &["true"]), ExecStdin::Closed)
        }),
    )
    .await
    .expect("must not hang")
    .expect("an allowed exec.run over reverse must succeed");
    assert_eq!(out.data.remote_exit_code, 0);

    let records = rig.audit.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].action, "exec.run");
    assert_eq!(records[0].decision, "allow");
    assert_eq!(records[0].principal, "device:controller");

    localctl.shutdown().await;
    harness.shutdown().await;
    rig.shutdown().await;
}

/// issue #4 items 4/3a's stale-registration rule, for `exec.run`
/// specifically: once the reverse leg dies and the controller's own
/// registry has noticed (`state == "stale"`), `exec.run` must answer a
/// retryable `HOST_NOT_FOUND` naming the stale registration — decided by
/// `Ops::resolve_host_route`'s routing alone, never by attempting a dial
/// or a relay that could only ever fail some other way.
#[tokio::test(flavor = "multi_thread")]
async fn exec_run_with_only_a_stale_registration_is_retryable_host_not_found() {
    let (_ops_dir, ops) = fresh_ops().await;
    let mut rig = ExecTargetRig::start(Arc::new(AllowAllPinned)).await;
    let target_identity = make_identity();

    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target_identity, "stale-host"),
    )
    .await;
    rig.register_reverse(&harness, &target_identity, "laptop")
        .await;
    harness.wait_control_hub("stale-host").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    // Reachable first, proving this is a routing decision, not a dial
    // that merely never had a chance to succeed in the first place.
    wait_for_reverse_state(&ops, "stale-host", "reachable").await;
    tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, |ops| {
            ops.exec_run(exec_req("stale-host", &["true"]), ExecStdin::Closed)
        }),
    )
    .await
    .expect("must not hang")
    .expect("must succeed once, live, before the registration goes stale");

    rig.sever_reverse().await;
    wait_for_reverse_state(&ops, "stale-host", "stale").await;

    let err = tokio::time::timeout(
        TIMEOUT,
        blocking(&ops, |ops| {
            ops.exec_run(exec_req("stale-host", &["true"]), ExecStdin::Closed)
        }),
    )
    .await
    .expect("must not hang")
    .expect_err("a stale-only registration must be HOST_NOT_FOUND, not a dial attempt");
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(err.retryable);
    assert_eq!(
        err.details["reason"],
        serde_json::json!("reverse_registration_stale")
    );

    localctl.shutdown().await;
    harness.shutdown().await;
}
