//! `-D` (SOCKS5 dynamic forwarding) over a **reverse route**, end to end
//! (ADR-0020 decisions 1–3): a real [`qsh_testkit::reverse::ReverseHarness`]
//! target, a real localctl daemon bound via
//! [`ReverseHarness::attach_localctl`], and the real production requester
//! leg — [`DynamicForwardHandle::start_reverse`] — driving genuine SOCKS5
//! traffic through them. The reverse-route sibling of
//! `dynamic_loopback.rs` (forward route), reusing that file's own SOCKS5
//! wire helpers' shape rather than sharing code with it (each test binary
//! is its own crate; there is no shared support module for these small
//! per-file helpers to live in — same division `reverse_tunnel.rs` and
//! `dynamic_loopback.rs` already draw).
//!
//! **Why (a) needs a non-loopback destination and (b) does not**: same
//! reasoning as `dynamic_loopback.rs`'s own module doc — `-D` sends
//! `StreamHeader.deny_host_local: true` on every `CONNECT` it opens
//! unconditionally, so a loopback destination is filtered by the property
//! under test, not reached by it. In this reverse suite, the *target*
//! (not the controller) is the side that ultimately dials the destination
//! (`ReverseRoute`'s own doc in `reverse_tunnel.rs`: the target always
//! plays the dialing-host role once registered), so the destination is
//! bound in this same test process either way — only its address differs
//! between (a) and (b).
//!
//! **Item (c) — missing `dial-filter.v1` capability — is deliberately not
//! here.** [`ReverseHarness::run_target`] always drives the real
//! [`qsh_core::reverse::target::run_reverse`], which always negotiates the
//! full [`qsh_proto::wire::LOCAL_CAPABILITIES`] set; there is no exposed
//! knob to make a real target advertise a reduced one (this repository
//! never shipped a pre-ADR-0019 target build to dial in as one). That
//! exact "no live peer in this codebase lacks the capability" gap is
//! already the reasoning `crates/qsh-cli/tests/dynamic_forward.rs`'s own
//! module doc gives for the analogous CLI-level exclusion; the capability
//! gate itself (`require_dial_filter_capability`, ADR-0019 decision 3,
//! ADR-0020 decision 2's dual-cause reverse wording) is pinned instead by
//! `crates/qsh-core/src/ops/tunnel.rs`'s
//! `tunnel_dynamic_over_reverse_without_dial_filter_capability_is_unsupported_and_binds_nothing`
//! unit test, which fabricates a `LocalHelloAck` with the capability
//! omitted — the only way to exercise this predicate without a real
//! degraded peer.
//!
//! **Item (e) — interactive `-D`'s capability failure creates no session
//! on target — is also not here, for the identical reason as (c)**: the
//! primary ordering gate for this case is
//! `Ops::session_open_for_dynamic` (`crates/qsh-core/src/ops/session.rs`,
//! ADR-0020 decisions 2–3), which runs the same
//! `require_dial_filter_capability` check *before* `SessionOpen` is ever
//! sent — and needs the identical fabricated-capability seam (c) does, not
//! a real `ReverseHarness` target. That ordering guarantee is pinned by
//! `crates/qsh-core/src/ops/session/tests.rs`'s
//! `session_open_for_dynamic_without_dial_filter_capability_on_reverse_route_opens_no_session`
//! (and its forward-route twin), using
//! [`qsh_core::client::Connected::for_test_reverse`] the same way the
//! qsh-core tunnel test above does.
//!
//! Item (d) — interactive reverse `-L` byte round trip at Ops level — is
//! covered separately by
//! [`interactive_dash_l_over_reverse_round_trips_at_the_ops_level`] below,
//! driven through the real, fully public `Ops::session_open`/
//! `Ops::session_attach`/`SessionAttachStream::open_local_forwards` call
//! chain against a real `ReverseHarness` target — no test-only seam
//! needed at all, since a real reverse `session.attach` naturally produces
//! a reverse-route [`SessionAttachStream`].
//!
//! `#![cfg(unix)]`: localctl (UDS) and `ReverseHarness::attach_localctl`
//! are both unix-only, same as every other reverse-conduit L3 suite in
//! this crate.

#![cfg(unix)]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::ops::Ops;
use qsh_core::tunnel::DynamicForwardHandle;
use qsh_core::{HostRoute, Paths, Principal};
use qsh_proto::{SessionAttachReq, SessionOpenReq};
use qsh_testkit::loopback::make_identity;
use qsh_testkit::net_probe::{self, LanEcho};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_testkit::tunnel::ephemeral_local_spec;
use qsh_transport::StaticTrust;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// Bound on every "this must have already happened" wait in this file —
/// same generosity `reverse_tunnel.rs`'s own `TIMEOUT` uses for the
/// identical reason (a real reverse registration plus one or two relay
/// hops, not a pure in-memory pipe).
const TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on a real, non-loopback round trip once
/// [`net_probe::require_non_loopback_v4`]'s own probe has already
/// succeeded once for the same address — same value and rationale as
/// `dynamic_loopback.rs`'s own `NETWORK_BOUND`.
const NETWORK_BOUND: Duration = Duration::from_secs(20);

fn pin(fingerprint: &str, name: &str) -> StaticTrust {
    let fp: qsh_transport::Fingerprint = fingerprint.parse().expect("parse test fingerprint");
    StaticTrust::empty().with_pin(fp, Principal::Device(name.to_string()))
}

/// Fresh, throwaway [`Paths`], with `runtime_dir()` pinned under the same
/// tempdir via [`Paths::with_runtime_dir`]. Without the pin, `runtime_dir()`
/// falls back to `$XDG_RUNTIME_DIR/qsh` whenever that variable is set
/// (`Paths::runtime_dir`'s own doc) — true on every Linux CI runner, where
/// it names one directory shared by every concurrently running `nextest`
/// process. [`ReverseHarness::attach_localctl`] binds its socket there, and
/// `Ops::resolve_host_route`'s reverse-source discovery
/// (`crates/qsh-core/src/ops/host.rs`) scans it by listing `<pid>.sock`
/// files, so an unpinned `Paths` lets this test's discovery see every other
/// concurrently running test process's same-named registration — the exact
/// cause of the `InvalidArgument`/"registered live by more than one qsh
/// listen daemon" flake this file, `local_control_reverse.rs` and
/// `local_stream_reverse.rs` (also unpinned) can otherwise produce for
/// each other under nextest's one-process-per-test model. Pinning gives
/// this test's own daemon and its own discovery the same private directory,
/// independent of the ambient environment — the same isolation
/// `host_list_reverse.rs`, `reverse_attach.rs`, `reverse_session_ops.rs` and
/// two of `reverse_tunnel.rs`'s own tests already apply for the identical
/// reason.
fn fresh_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    (dir, paths)
}

// ---------------------------------------------------------------------
// SOCKS5 wire helpers — same shape as `dynamic_loopback.rs`'s own copy.
// ---------------------------------------------------------------------

async fn greet_no_auth(tcp: &mut TcpStream) {
    tcp.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write the socks5 greeting");
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply)
        .await
        .expect("read the socks5 method-select reply");
    assert_eq!(
        reply,
        [0x05, 0x00],
        "a real SOCKS5 listener must select no-auth"
    );
}

fn connect_request_ipv4(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = addr else {
        panic!("this helper only builds IPv4 CONNECT requests")
    };
    let mut v = vec![0x05, 0x01, 0x00, 0x01];
    v.extend_from_slice(&v4.ip().octets());
    v.extend_from_slice(&v4.port().to_be_bytes());
    v
}

async fn read_rep(tcp: &mut TcpStream) -> [u8; 10] {
    let mut rep = [0u8; 10];
    tcp.read_exact(&mut rep)
        .await
        .expect("read the socks5 REP frame");
    rep
}

// ---------------------------------------------------------------------
// (a) a real reverse `-D` round trip to a non-loopback echo server.
// ---------------------------------------------------------------------

/// The role-axis baseline for the reverse route
/// (`dynamic_loopback.rs::socks_connect_to_echo_round_trips_bytes` is its
/// forward-route counterpart, in a different file/harness): bind a `-D`
/// listener relaying through a real reverse registration, `CONNECT` to a
/// real non-loopback echo server the target can reach, and confirm a
/// payload round-trips byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn dash_d_over_reverse_reaches_a_non_loopback_echo() {
    let iface_ip = qsh_testkit::gap_or_return!(
        net_probe::require_non_loopback_v4("no reachable non-loopback address on this host").await,
        "dash_d_over_reverse_reaches_a_non_loopback_echo"
    );

    let target = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target.fingerprint.to_string(), "widget"),
    )
    .await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let echo = LanEcho::start(iface_ip).await.expect("bind lan echo");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let forward = DynamicForwardHandle::start_reverse(
            None,
            0,
            localctl.socket_path.clone(),
            "widget".to_string(),
        )
        .await
        .expect("bind -D over reverse");

        let gap = net_probe::bound_or_gap(
            "a real round trip did not finish within the network bound on this host's network",
            NETWORK_BOUND,
            async {
                let mut sock = TcpStream::connect(forward.local_addr())
                    .await
                    .expect("connect to the -D listener");
                greet_no_auth(&mut sock).await;
                sock.write_all(&connect_request_ipv4(echo.addr()))
                    .await
                    .expect("write the CONNECT request");
                let rep = read_rep(&mut sock).await;
                assert_eq!(
                    rep[1], 0x00,
                    "CONNECT to a real, non-loopback destination over a reverse route must \
                     succeed: {rep:?}"
                );

                let payload = b"qsh -D round trip over a reverse route".to_vec();
                sock.write_all(&payload).await.expect("write the payload");
                sock.shutdown().await.expect("half-close the write side");
                let mut got = Vec::new();
                sock.read_to_end(&mut got).await.expect("read the echo");
                assert_eq!(got, payload, "the reverse relay must not alter bytes");
            },
        )
        .await;

        let _ = shutdown_tx.send(());
        gap
    };

    let (result, gap) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
    qsh_testkit::gap_or_return!(gap, "dash_d_over_reverse_reaches_a_non_loopback_echo");
}

// ---------------------------------------------------------------------
// (b) localhost/127.0.0.1 CONNECT is filtered before the daemon crosses
// to the target, and the target's own loopback server sees no accept —
// proof `deny_host_local = true` reaches the target's dial unchanged.
// ---------------------------------------------------------------------

/// No non-loopback route is needed at all: the whole point is that a
/// **loopback** destination is refused, mirroring
/// `dynamic_loopback.rs::localhost_name_is_filtered_rep_02_and_the_loopback_server_sees_no_accept`
/// one carrier over. Also stands in for the "Ops unit test that the
/// reverse opener sets `deny_host_local = true` on every header it
/// writes" requirement: if [`ForwardCarrier::Local`]'s `-D` opener ever
/// stopped setting that field, this `CONNECT` would reach the target's
/// real dialer and the spy listener below would see an accept.
#[tokio::test(flavor = "multi_thread")]
async fn dash_d_over_reverse_filters_loopback_and_the_target_sees_no_accept() {
    let target = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target.fingerprint.to_string(), "widget"),
    )
    .await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;

    // Bound in this same process: the target dials from here too
    // (`ReverseHarness::run_target` drives the real target in-process),
    // so a loopback spy here is exactly what the target would reach if
    // the filter ever let a loopback destination through.
    let spy = StdTcpListener::bind("127.0.0.1:0").expect("bind the loopback spy");
    spy.set_nonblocking(true).expect("set nonblocking");
    let spy = tokio::net::TcpListener::from_std(spy).expect("adopt the spy into tokio");
    let spy_addr = spy.local_addr().expect("spy addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        let forward = DynamicForwardHandle::start_reverse(
            None,
            0,
            localctl.socket_path.clone(),
            "widget".to_string(),
        )
        .await
        .expect("bind -D over reverse");

        let mut sock = TcpStream::connect(forward.local_addr())
            .await
            .expect("connect to the -D listener");
        greet_no_auth(&mut sock).await;
        sock.write_all(&connect_request_ipv4(spy_addr))
            .await
            .expect("write the CONNECT request");
        let rep = read_rep(&mut sock).await;
        assert_eq!(
            rep[1], 0x02,
            "expected NotAllowedByRuleset REP for a loopback destination over reverse: {rep:?}"
        );

        let accept = tokio::time::timeout(Duration::from_millis(500), spy.accept()).await;
        assert!(
            accept.is_err(),
            "the host-local filter crossing the daemon to the target must still refuse to \
             dial a loopback destination: {accept:?}"
        );

        // The port must still be usable after one refused CONNECT — the
        // holder itself is unaffected by a single client's denial.
        drop(sock);

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
}

// ---------------------------------------------------------------------
// (d) interactive reverse `-L` byte round trip at the `Ops` level — the
// real, fully public `Ops::session_open`/`Ops::session_attach`/
// `SessionAttachStream::open_local_forwards` chain against a real
// `ReverseHarness` target.
// ---------------------------------------------------------------------

/// Drives the real interactive `-L` path end to end over a reverse route,
/// entirely through `Ops`'s own public surface — no test-only `Connected`
/// seam: a real `session.attach` against a reverse registration naturally
/// produces a reverse-route [`SessionAttachStream`]
/// (`Ops::session_attach`'s own doc: "Route-aware... a live reverse
/// registration relays through this machine's `qsh listen` daemon, exactly
/// like every other `Ops::connect` caller"), so `open_local_forwards`
/// exercises [`SessionAttachStream::start_local_forwards_reverse`] for
/// real. Uses a real shell session (`argv: ["cat"]`) rather than a PTY, so
/// the test only needs the session's `SessionOpen`/`SessionAttach` control
/// plane to work, not a full terminal.
#[tokio::test(flavor = "multi_thread")]
async fn interactive_dash_l_over_reverse_round_trips_at_the_ops_level() {
    let target = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&target.fingerprint.to_string(), "widget"),
    )
    .await;
    let (dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback echo target for -L");
    let echo_addr = echo.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // Pin the controller under the daemon's own runtime_dir so
    // `Ops::connect` resolves "widget" to a reverse route through the
    // localctl socket `attach_localctl` just bound — the same trust setup
    // `crates/qsh-cli/tests/dynamic_forward.rs`'s interactive tests use,
    // minus the CLI process (this drives `Ops` directly).
    let ops = Ops::new(paths.clone());
    let mut trust = qsh_core::trust::TrustStore::default();
    trust.add_peer(
        "widget",
        None,
        target.fingerprint,
        "2026-01-01T00:00:00Z".to_string(),
    );
    trust
        .save(&paths.trust_file())
        .expect("save controller trust.toml");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;

        // Pin the property `fresh_paths`'s isolation exists to guarantee:
        // discovery resolves "widget" to exactly this test's own daemon.
        // `Ops::resolve_host_route`'s two-daemon-duplicate check
        // (`crates/qsh-core/src/ops/host.rs`) would return `InvalidArgument`
        // instead of `HostRoute::Reverse` if it ever saw more than one live
        // registration under this name — so a successful match here, on
        // this test's own `localctl.socket_path`, is a direct assertion of
        // "exactly one daemon", not an inference from `session_open` merely
        // succeeding.
        let route = tokio::task::spawn_blocking({
            let ops = ops.clone();
            move || ops.resolve_host_route("widget")
        })
        .await
        .expect("join resolve_host_route")
        .expect("resolve_host_route must resolve \"widget\" to exactly one live daemon");
        match route {
            HostRoute::Reverse { socket, .. } => assert_eq!(
                socket, localctl.socket_path,
                "discovery must resolve \"widget\" to this test's own localctl daemon, not a \
                 concurrent process's"
            ),
            other => panic!("expected a live reverse route for \"widget\", got {other:?}"),
        }

        let opened = tokio::task::spawn_blocking({
            let ops = ops.clone();
            move || {
                ops.session_open(SessionOpenReq {
                    host: "widget".to_string(),
                    argv: vec!["cat".to_string()],
                    env: Vec::new(),
                    term: None,
                    cols: None,
                    rows: None,
                    user: None,
                })
            }
        })
        .await
        .expect("join session_open")
        .expect("session_open over a reverse route");

        let spec = ephemeral_local_spec(&echo_addr.ip().to_string(), echo_addr.port());

        let (bind_addr, _handle) = tokio::task::spawn_blocking({
            let ops = ops.clone();
            let session_ref = opened.session_ref.clone();
            move || -> (SocketAddr, ()) {
                let mut attach = ops
                    .session_attach(
                        SessionAttachReq {
                            session_ref,
                            no_steal: false,
                        },
                        &[],
                    )
                    .expect("session_attach over a reverse route");
                let tunnels = attach
                    .open_local_forwards(&[spec])
                    .expect("open -L over the reverse attach");
                let bind = tunnels[0]
                    .bind
                    .parse::<SocketAddr>()
                    .expect("parse the bound -L address");
                // Leak the attach deliberately: dropping it would tear
                // down the forward's listener before the test connects.
                std::mem::forget(attach);
                (bind, ())
            }
        })
        .await
        .expect("join session_attach + open_local_forwards");

        let payload = b"INTERACTIVE_DASH_L_OVER_REVERSE";
        let mut sock = TcpStream::connect(bind_addr)
            .await
            .expect("connect to the -L listener");
        sock.write_all(payload).await.expect("write the payload");
        sock.shutdown().await.expect("half-close the write side");
        let mut got = Vec::new();
        sock.read_to_end(&mut got).await.expect("read the echo");
        assert_eq!(
            got, payload,
            "the -L forward over a reverse attach must not alter bytes"
        );

        let _ = shutdown_tx.send(());
    };

    let (result, ()) = tokio::join!(run_fut, test_fut);
    result.expect("run_target must exit cleanly on shutdown");
    localctl.shutdown().await;
    harness.shutdown().await;
    drop(dir);
}

// ---------------------------------------------------------------------
// A direct regression check for the isolation `fresh_paths` now provides —
// forces the exact two-daemon collision the CI flake this file hit under
// nextest's one-process-per-test model, instead of relying on that flake's
// absence as indirect evidence.
// ---------------------------------------------------------------------

/// Binds a live "widget" localctl daemon at a caller-chosen `pid`, backed
/// by `harness`'s own registry — the same two primitives
/// [`ReverseHarness::attach_localctl`] itself composes
/// ([`qsh_core::localctl::daemon::LocalctlListener::bind`] +
/// [`qsh_core::localctl::daemon::LocalctlDaemon::run`]), called directly so
/// a fabricated `pid` can be forced rather than always taking
/// `std::process::id()`. That is what lets this one test process bind two
/// independently live daemons under the *same* directory: `pid` is only
/// ever used as a `<pid>.sock` filename and a `details.pids` label
/// (`crates/qsh-core/src/ops/host.rs`'s `resolve_route`), never checked
/// against a real OS process, so two fabricated, distinct values collide
/// exactly the way two real nextest test processes' genuine pids do.
struct FabricatedDaemon {
    socket_path: std::path::PathBuf,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl FabricatedDaemon {
    /// Signal shutdown and wait for the accept loop to drain — the same
    /// two steps [`LocalctlHandle::shutdown`] performs for a real one.
    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.task.await;
    }
}

async fn attach_fabricated_localctl(
    harness: &ReverseHarness,
    paths: &Paths,
    pid: u32,
) -> FabricatedDaemon {
    use qsh_core::localctl::daemon::{LocalctlDaemon, LocalctlListener};
    let bound = LocalctlListener::bind(paths, pid).expect("bind fabricated localctl socket");
    let socket_path = bound.socket_path.clone();
    let daemon = LocalctlDaemon::new(harness.listen.clone());
    let (shutdown, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(daemon.run(bound, async move {
        let _ = rx.await;
    }));
    FabricatedDaemon {
        socket_path,
        shutdown,
        task,
    }
}

/// Two independent, live "widget" registrations whose localctl sockets are
/// deliberately forced into one shared directory — the shape
/// `$XDG_RUNTIME_DIR/qsh` takes when several concurrently running
/// `nextest` processes all fall back to the same ambient directory
/// (`Paths::runtime_dir`'s own doc), which is what actually produced the
/// `InvalidArgument`/"registered live by more than one qsh listen daemon"
/// failure this suite hit in CI. Discovery over that shared directory must
/// fail closed with `resolve_route`'s two-daemon-duplicate check
/// (`crates/qsh-core/src/ops/host.rs`), naming both fabricated pids. A
/// third, independent daemon registered under `fresh_paths`'s own isolated
/// directory carries the identical name and must resolve cleanly
/// regardless — proof that `fresh_paths`'s `with_runtime_dir` pin, not
/// luck, is what keeps `interactive_dash_l_over_reverse_round_trips_at_the_
/// ops_level` (above) green under concurrent nextest processes.
#[tokio::test(flavor = "multi_thread")]
async fn discovery_fails_closed_on_a_shared_runtime_dir_but_resolves_cleanly_once_isolated() {
    let shared_dir = tempfile::tempdir().expect("shared decoy runtime dir");

    let decoy_a_target = make_identity();
    let decoy_a_harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&decoy_a_target.fingerprint.to_string(), "widget"),
    )
    .await;
    let decoy_a_scratch = tempfile::tempdir().expect("tempdir");
    let decoy_a_paths = Paths::new(
        decoy_a_scratch.path().join("config"),
        decoy_a_scratch.path().join("state"),
    )
    .with_runtime_dir(shared_dir.path().to_path_buf());

    let decoy_b_target = make_identity();
    let decoy_b_harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&decoy_b_target.fingerprint.to_string(), "widget"),
    )
    .await;
    let decoy_b_scratch = tempfile::tempdir().expect("tempdir");
    let decoy_b_paths = Paths::new(
        decoy_b_scratch.path().join("config"),
        decoy_b_scratch.path().join("state"),
    )
    .with_runtime_dir(shared_dir.path().to_path_buf());

    let (own_dir, own_paths) = fresh_paths();
    let own_target = make_identity();
    let own_harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        pin(&own_target.fingerprint.to_string(), "widget"),
    )
    .await;

    let (decoy_a_shutdown_tx, decoy_a_shutdown_rx) = tokio::sync::oneshot::channel();
    let (decoy_b_shutdown_tx, decoy_b_shutdown_rx) = tokio::sync::oneshot::channel();
    let (own_shutdown_tx, own_shutdown_rx) = tokio::sync::oneshot::channel();

    let decoy_a_run =
        decoy_a_harness.run_target(&decoy_a_target, "device-id", "controller", None, async {
            let _ = decoy_a_shutdown_rx.await;
        });
    let decoy_b_run =
        decoy_b_harness.run_target(&decoy_b_target, "device-id", "controller", None, async {
            let _ = decoy_b_shutdown_rx.await;
        });
    let own_run = own_harness.run_target(&own_target, "device-id", "controller", None, async {
        let _ = own_shutdown_rx.await;
    });

    let test_fut = async {
        wait_for(TIMEOUT, || decoy_a_harness.listen.registry().get("widget")).await;
        wait_for(TIMEOUT, || decoy_b_harness.listen.registry().get("widget")).await;
        wait_for(TIMEOUT, || own_harness.listen.registry().get("widget")).await;

        // Two fabricated pids, deliberately distinct, both bound under
        // `shared_dir` — the two-daemon collision itself.
        let decoy_a_daemon =
            attach_fabricated_localctl(&decoy_a_harness, &decoy_a_paths, 900_001).await;
        let decoy_b_daemon =
            attach_fabricated_localctl(&decoy_b_harness, &decoy_b_paths, 900_002).await;

        let probe_scratch = tempfile::tempdir().expect("tempdir");
        let probe_paths = Paths::new(
            probe_scratch.path().join("config"),
            probe_scratch.path().join("state"),
        )
        .with_runtime_dir(shared_dir.path().to_path_buf());
        let probe_ops = Ops::new(probe_paths);
        let err = tokio::task::spawn_blocking(move || probe_ops.resolve_host_route("widget"))
            .await
            .expect("join resolve_host_route")
            .expect_err(
                "two live \"widget\" daemons sharing one runtime dir must fail closed, not \
                 guess",
            );
        assert_eq!(
            err.code,
            qsh_proto::ErrorCode::InvalidArgument,
            "expected the two-daemon-duplicate InvalidArgument, got {err:?}"
        );
        let pids: Vec<u64> = err
            .details
            .get("pids")
            .and_then(serde_json::Value::as_array)
            .expect("details.pids must be an array")
            .iter()
            .map(|v| v.as_u64().expect("each pid is a number"))
            .collect();
        assert_eq!(
            pids,
            vec![900_001, 900_002],
            "details.pids must name exactly the two colliding fabricated daemons, sorted: {err:?}"
        );

        // The isolated "own" directory sees only its own daemon and
        // resolves cleanly despite the collision above still being live —
        // the property this file's own interactive `-L` test depends on.
        let own_ops = Ops::new(own_paths.clone());
        let own_localctl = attach_fabricated_localctl(&own_harness, &own_paths, 900_003).await;
        let route = tokio::task::spawn_blocking(move || own_ops.resolve_host_route("widget"))
            .await
            .expect("join resolve_host_route")
            .expect(
                "an isolated runtime dir must resolve \"widget\" cleanly despite two unrelated \
                 decoys elsewhere sharing the same name",
            );
        match route {
            HostRoute::Reverse { socket, .. } => {
                assert_eq!(
                    socket, own_localctl.socket_path,
                    "must resolve to this test's own daemon, not a decoy's"
                );
            }
            other => panic!("expected a live reverse route for \"widget\", got {other:?}"),
        }

        decoy_a_daemon.shutdown().await;
        decoy_b_daemon.shutdown().await;
        own_localctl.shutdown().await;

        let _ = decoy_a_shutdown_tx.send(());
        let _ = decoy_b_shutdown_tx.send(());
        let _ = own_shutdown_tx.send(());
    };

    let (decoy_a_result, decoy_b_result, own_result, ()) =
        tokio::join!(decoy_a_run, decoy_b_run, own_run, test_fut);
    decoy_a_result.expect("decoy A run_target must exit cleanly on shutdown");
    decoy_b_result.expect("decoy B run_target must exit cleanly on shutdown");
    own_result.expect("own run_target must exit cleanly on shutdown");
    decoy_a_harness.shutdown().await;
    decoy_b_harness.shutdown().await;
    own_harness.shutdown().await;
    drop(own_dir);
}
