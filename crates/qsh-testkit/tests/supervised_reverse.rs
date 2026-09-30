//! `--supervise` on the reverse route, `-L` and `-D` (ADR-0023 decisions 2,
//! 4, 7-1, 9, 12 and 22), against a real [`ReverseHarness`] target, a real
//! localctl daemon and the product `Ops::tunnel_open`/`Ops::tunnel_dynamic`.
//!
//! What the tests wait on is what a person would see: the round trip through
//! the forward listener and the `qsh::tunnel::supervise` lines, which a
//! process-wide capture layer collects (one test per process under nextest,
//! so the global subscriber is the test's own).
//!
//! The per-accept identity check (decision 7-5) cannot be reached through a
//! real daemon: a registration that changes ends the `LOCAL_CONTROL` conduit
//! first, which the supervisor reads as a loss before any accept can see the
//! new identity. Its tests script the daemon instead and live next to the
//! supervisor, in `crates/qsh-core/src/ops/tunnel/supervise/tests.rs`.

#![cfg(unix)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use qsh_core::acl::AllowAllPinned;
use qsh_core::reverse::registry::EntryState;
use qsh_core::{Ops, Paths, Principal};
use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq, TunnelDynamicReq, TunnelOpenReq};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{LocalctlHandle, ReverseHarness, wait_for};
use qsh_testkit::tunnel::{EchoServer, TunnelHarness};
use qsh_transport::StaticTrust;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;

/// Bound on every "this must have happened" wait: a real registration, a
/// redial and a few relay hops, not a budget anything should need in full.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The supervise budget handed to every tunnel. Long enough that only the
/// scenario, never the budget, ends a tunnel.
const SUPERVISE_MS: u32 = 120_000;

// ---- the supervise lines ------------------------------------------------

fn captured() -> &'static Mutex<Vec<serde_json::Value>> {
    static LINES: OnceLock<Mutex<Vec<serde_json::Value>>> = OnceLock::new();
    LINES.get_or_init(Default::default)
}

struct Capture;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        if let Ok(line) = serde_json::from_str::<serde_json::Value>(&message.0) {
            captured()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line);
        }
    }
}

/// Filtered to the supervise target: an unfiltered global subscriber makes
/// every quinn `trace!` on every thread pay for a registry lookup.
fn init_capture() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(
            Capture.with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target(qsh_core::tunnel::supervise::TARGET, tracing::Level::INFO),
            ),
        ),
    )
    .expect("no other global tracing subscriber in this test process");
}

fn lines_of(kind: &str) -> Vec<serde_json::Value> {
    captured()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|line| line["supervise"] == kind)
        .cloned()
        .collect()
}

async fn wait_line(kind: &str) -> serde_json::Value {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(line) = lines_of(kind).into_iter().next() {
            return line;
        }
        assert!(
            Instant::now() < deadline,
            "no `{kind}` line within {TIMEOUT:?}; saw {:?}",
            captured().lock().unwrap_or_else(|e| e.into_inner())
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---- fixtures -------------------------------------------------------------

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind to pick a free port")
        .local_addr()
        .expect("picked port")
        .port()
}

struct Rig {
    harness: ReverseHarness,
    ops: Ops,
    paths: Paths,
    localctl: LocalctlHandle,
    echo: EchoServer,
    _dir: tempfile::TempDir,
}

/// A controller that keeps a dead registration for `retention` (the default
/// 120 s when `None`), a localctl daemon, and a client `Ops` whose own
/// `trust.toml` is empty.
async fn rig(target: &TestIdentity, retention: Option<Duration>) -> Rig {
    let trust = pin(target, "widget");
    let harness = match retention {
        None => ReverseHarness::start_with(Arc::new(AllowAllPinned), false, trust).await,
        Some(retention) => {
            ReverseHarness::start_with_stale_retention_and_sweep_tick(
                Arc::new(AllowAllPinned),
                false,
                trust,
                retention,
                Duration::from_millis(100),
            )
            .await
        }
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    qsh_core::TrustStore::default()
        .save(&paths.trust_file())
        .expect("save empty trust.toml");
    let ops = Ops::new(paths.clone());
    let localctl = harness.attach_localctl(&paths).await;
    let echo = EchoServer::start().await.expect("bind echo server");
    Rig {
        harness,
        ops,
        paths,
        localctl,
        echo,
        _dir: dir,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Local,
    Dynamic,
    /// `-R`: the listener is on the target, and the tunnel is known to the
    /// daemon by the `forward_id` the target's server issued.
    Remote,
}

/// A supervised tunnel held on its own thread until stopped.
struct Running {
    tunnel_id: String,
    bind: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<Option<qsh_core::OpError>>,
}

impl Running {
    async fn stop(mut self) -> Option<qsh_core::OpError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.done.await.expect("the hold task joins")
    }
}

async fn open(ops: &Ops, kind: Kind, echo_port: u16) -> Running {
    let ops = ops.clone();
    let (opened_tx, opened_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let done = tokio::task::spawn_blocking(move || {
        let held = match kind {
            Kind::Local | Kind::Remote => ops
                .tunnel_open(TunnelOpenReq {
                    host: "widget".to_string(),
                    mode: if kind == Kind::Remote {
                        "remote"
                    } else {
                        "local"
                    }
                    .to_string(),
                    bind: None,
                    listen_port: u32::from(free_port()),
                    forward_host: "127.0.0.1".to_string(),
                    forward_port: u32::from(echo_port),
                    wait_ms: None,
                    supervise_ms: Some(SUPERVISE_MS),
                    accept_hold_ms: None,
                })
                .map(|hold| {
                    let tunnel = hold.tunnel();
                    (tunnel.tunnel_id.clone(), tunnel.bind.clone(), hold)
                }),
            Kind::Dynamic => ops
                .tunnel_dynamic(TunnelDynamicReq {
                    host: "widget".to_string(),
                    bind: None,
                    listen_port: u32::from(free_port()),
                    supervise_ms: Some(SUPERVISE_MS),
                    accept_hold_ms: None,
                })
                .map(|hold| {
                    let tunnel = hold.dynamic_tunnel();
                    (tunnel.tunnel_id.clone(), tunnel.bind.clone(), hold)
                }),
        };
        match held {
            Ok((tunnel_id, bind, hold)) => {
                let _ = opened_tx.send(Ok((tunnel_id, bind)));
                hold.hold_until(async move {
                    let _ = stop_rx.await;
                })
            }
            Err(err) => {
                let _ = opened_tx.send(Err(err));
                None
            }
        }
    });
    let (tunnel_id, bind) = opened_rx
        .await
        .expect("the open reported")
        .expect("the supervised open over reverse succeeds");
    Running {
        tunnel_id,
        bind: bind.parse().expect("bind is a socket address"),
        stop: Some(stop_tx),
        done,
    }
}

/// One attempt to use the tunnel: an echo round trip for `-L`; for `-D`, a
/// CONNECT to a loopback destination, which the peer's host-local filter
/// must answer with REP 0x02 (a disconnected listener answers 0x01).
async fn probe_once(kind: Kind, bind: SocketAddr, spy: Option<SocketAddr>) -> bool {
    match kind {
        Kind::Local | Kind::Remote => {
            let payload = b"through the supervised reverse tunnel".to_vec();
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(3),
                    TunnelHarness::round_trip(bind, payload.clone())
                )
                .await,
                Ok(Ok(got)) if got == payload
            )
        }
        Kind::Dynamic => {
            let spy = spy.expect("a -D probe needs a loopback destination");
            tokio::time::timeout(Duration::from_secs(3), async {
                let mut sock = TcpStream::connect(bind).await.ok()?;
                sock.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
                let mut method = [0u8; 2];
                sock.read_exact(&mut method).await.ok()?;
                let SocketAddr::V4(spy) = spy else {
                    return None;
                };
                let mut request = vec![0x05, 0x01, 0x00, 0x01];
                request.extend_from_slice(&spy.ip().octets());
                request.extend_from_slice(&spy.port().to_be_bytes());
                sock.write_all(&request).await.ok()?;
                let mut reply = [0u8; 10];
                sock.read_exact(&mut reply).await.ok()?;
                Some(reply[1] == 0x02)
            })
            .await
            .ok()
            .flatten()
            .unwrap_or(false)
        }
    }
}

async fn probe_within(kind: Kind, bind: SocketAddr, spy: Option<SocketAddr>, what: &str) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if probe_once(kind, bind, spy).await {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: no answer in {TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// What the target's registration does while the tunnel is open.
#[derive(Clone, Copy, PartialEq)]
enum Gap {
    /// It comes back while the old entry is still stale.
    Stale,
    /// It comes back after the controller swept the entry.
    Swept,
}

/// Register, open a supervised tunnel, prove it carries traffic, end the
/// registration, bring it back per `gap`, and wait until the tunnel carries
/// traffic again. Returns the stopped tunnel's id.
async fn lose_and_regain(rig: &Rig, target: &TestIdentity, kind: Kind, gap: Gap) -> String {
    lose_and_regain_then(rig, target, kind, gap, |running| async move { running }).await
}

/// [`lose_and_regain`] that hands the tunnel, carrying traffic again, to
/// `then` before it is stopped.
async fn lose_and_regain_then<F, Fut>(
    rig: &Rig,
    target: &TestIdentity,
    kind: Kind,
    gap: Gap,
    then: F,
) -> String
where
    F: FnOnce(Running) -> Fut,
    Fut: std::future::Future<Output = Running>,
{
    let spy_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the loopback spy");
    let spy = spy_listener.local_addr().expect("spy addr");
    let (s1_tx, s1_rx) = oneshot::channel::<()>();
    let (s2_tx, s2_rx) = oneshot::channel::<()>();
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    let targets = async {
        rig.harness
            .run_target(target, "device-id", "controller", None, async {
                let _ = s1_rx.await;
            })
            .await
            .expect("the first registration ends cleanly");
        let _ = gate_rx.await;
        rig.harness
            .run_target(target, "device-id", "controller", None, async {
                let _ = s2_rx.await;
            })
            .await
            .expect("the second registration ends cleanly");
    };
    let scenario = async {
        rig.harness.wait_control_hub("widget").await;
        let running = open(&rig.ops, kind, rig.echo.port()).await;
        probe_within(kind, running.bind, Some(spy), "before the loss").await;

        let _ = s1_tx.send(());
        wait_line("lost").await;
        if gap == Gap::Swept {
            wait_for(TIMEOUT, || {
                rig.harness
                    .listen
                    .registry()
                    .get("widget")
                    .is_none()
                    .then_some(())
            })
            .await;
            // The name is on no daemon now: the supervisor keeps asking.
            wait_for(TIMEOUT, || {
                lines_of("retry")
                    .into_iter()
                    .find(|line| line["code"] == "HOST_NOT_FOUND")
            })
            .await;
        }
        let _ = gate_tx.send(());
        wait_line("reestablished").await;
        probe_within(kind, running.bind, Some(spy), "after the re-registration").await;
        if kind == Kind::Dynamic {
            // The filter's refusal is per destination, not a change of the
            // peer's policy: the tunnel must outlive it.
            assert!(probe_once(kind, running.bind, Some(spy)).await);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(
                !running.done.is_finished(),
                "a host-local filter refusal ended the supervised tunnel"
            );
        }
        let running = then(running).await;
        let tunnel_id = running.tunnel_id.clone();
        let ended = running.stop().await;
        assert!(
            ended.is_none(),
            "a deliberate stop is not an error: {ended:?}"
        );
        let _ = s2_tx.send(());
        tunnel_id
    };
    let ((), tunnel_id) = tokio::join!(targets, scenario);
    drop(spy_listener);
    tunnel_id
}

// ---- tests ------------------------------------------------------------------

/// Decision 4 and 7-1: the target's connection drops and it registers again
/// under the same name; the tunnel's listener never went away and carries
/// traffic over the new registration.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_local_reestablishes_after_the_target_reregisters() {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, None).await;
    lose_and_regain(&rig, &target, Kind::Local, Gap::Stale).await;

    let lost = &lines_of("lost")[0];
    assert_eq!(lost["route"], "reverse");
    assert_eq!(lost["host"], "widget");
    let back = &lines_of("reestablished")[0];
    assert!(
        back["generation"].as_u64().unwrap_or(0) >= 1,
        "the new registration is a later generation: {back}"
    );

    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

/// Decision 7-1, daemon restart: the tunnel's daemon goes away and another
/// one, on another socket, takes the name. The generation of the first is
/// not sent to the second, whose generations start over; sending it would
/// make the new daemon wait for a generation it will never reach.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_local_reestablishes_after_a_listen_daemon_restart() {
    init_capture();
    let target = make_identity();
    let Rig {
        harness: first,
        ops,
        paths,
        localctl: first_localctl,
        echo,
        _dir,
    } = rig(&target, None).await;
    let second =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;

    // Stage one: the first daemon, the tunnel, and the daemon's death. The
    // daemon stops answering before the registration goes (a dropped handle
    // closes its socket), so the supervisor's first look finds no daemon
    // at all instead of parking in a daemon that is on its way out.
    let (s1_tx, s1_rx) = oneshot::channel::<()>();
    let stage_one = first.run_target(&target, "device-id", "controller", None, async {
        let _ = s1_rx.await;
    });
    let mut first_localctl = Some(first_localctl);
    let opened = async {
        first.wait_control_hub("widget").await;
        let running = open(&ops, Kind::Local, echo.port()).await;
        probe_within(Kind::Local, running.bind, None, "before the restart").await;
        drop(first_localctl.take());
        let _ = s1_tx.send(());
        wait_line("lost").await;
        running
    };
    let (result, running) = tokio::join!(stage_one, opened);
    result.expect("the first registration ends cleanly");
    first.shutdown().await;

    // A second daemon binds another socket (the pid of a process that is
    // alive, because discovery unlinks the socket of a dead one) and the
    // target registers with it.
    let second_localctl = second
        .attach_localctl_as(&paths, std::os::unix::process::parent_id())
        .await;
    let (s2_tx, s2_rx) = oneshot::channel::<()>();
    let stage_two = second.run_target(&target, "device-id", "controller", None, async {
        let _ = s2_rx.await;
    });
    let regained = async {
        second.wait_control_hub("widget").await;
        wait_line("reestablished").await;
        probe_within(Kind::Local, running.bind, None, "after the restart").await;
        assert!(running.stop().await.is_none());
        let _ = s2_tx.send(());
    };
    let (result, ()) = tokio::join!(stage_two, regained);
    result.expect("the second registration ends cleanly");

    second_localctl.shutdown().await;
    second.shutdown().await;
}

/// Decision 9 and 7-1, the long gap: the controller sweeps the dead entry
/// after `stale_retention`, so for a while the name is on no daemon at all.
/// The supervisor keeps asking (`HOST_NOT_FOUND` is retried; the budget is
/// not cut down to `stale_retention`) and the tunnel comes back when the
/// target does.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_local_reestablishes_after_a_gap_longer_than_stale_retention() {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, Some(Duration::from_secs(1))).await;
    lose_and_regain(&rig, &target, Kind::Local, Gap::Swept).await;

    let retries = lines_of("retry");
    assert!(
        retries.iter().any(|line| line["code"] == "HOST_NOT_FOUND"),
        "the swept name is retried, not fatal: {retries:?}"
    );
    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

/// Decision 22: a forward pin of the same name is never a candidate while
/// the supervisor looks for the registration again. The pin points at a UDP
/// socket that counts datagrams, so one dial (a QUIC Initial) would show.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_route_local_never_dials_a_forward_pin_while_the_registration_is_stale_or_swept()
 {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, Some(Duration::from_secs(1))).await;

    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the blackhole");
    let blackhole_addr = blackhole.local_addr().expect("blackhole addr");
    let datagrams = Arc::new(AtomicUsize::new(0));
    let counter = datagrams.clone();
    let counting = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while blackhole.recv_from(&mut buf).await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let ops = rig.ops.clone();
    tokio::task::spawn_blocking(move || {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
            ..Default::default()
        })
        .expect("client identity");
        ops.trust_add(TrustAddReq {
            name: "widget".into(),
            address: Some(blackhole_addr.to_string()),
            fingerprint: Some(
                qsh_transport::Fingerprint::of_spki_der(b"a forward pin").to_string(),
            ),
            cert_pem: None,
        })
        .expect("pin the name to a blackhole address");
    })
    .await
    .expect("pin task joins");

    lose_and_regain(&rig, &target, Kind::Local, Gap::Swept).await;

    assert_eq!(
        datagrams.load(Ordering::SeqCst),
        0,
        "the supervisor dialed the forward pin"
    );
    counting.abort();
    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

/// Decision 4 with `-D`: the same loss and recovery, and the peer's
/// host-local filter still answers (REP 0x02 for a loopback destination,
/// which also shows the new carrier carried the request to the peer).
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_dynamic_reestablishes_and_keeps_the_host_local_filter() {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, None).await;
    lose_and_regain(&rig, &target, Kind::Dynamic, Gap::Stale).await;

    let back = &lines_of("reestablished")[0];
    assert_eq!(back["mode"], "dynamic");
    assert_eq!(back["route"], "reverse");
    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

/// Decision 2: `--wait` on a supervised open is still capped to this
/// machine's `stale_retention`, so it returns the retryable stale error
/// instead of riding past the sweep into the non-retryable "not configured"
/// one. Same shape as `tunnel_open_wait_is_capped_by_stale_retention_and_never_outlives_the_sweep`.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_with_wait_still_caps_the_initial_wait_to_stale_retention() {
    let target = make_identity();
    let harness = ReverseHarness::start_with_stale_retention_and_sweep_tick(
        Arc::new(AllowAllPinned),
        false,
        pin(&target, "widget"),
        Duration::from_secs(3),
        Duration::from_millis(100),
    )
    .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    qsh_core::TrustStore::default()
        .save(&paths.trust_file())
        .expect("save empty trust.toml");
    std::fs::write(
        paths.config_file(),
        "[reverse]\nbackoff_initial_ms = 1\nbackoff_max_ms = 1\n\n[listen]\nstale_retention = 1\n",
    )
    .expect("write config.toml with a short stale_retention");
    let ops = Ops::new(paths);
    let localctl = harness.attach_localctl(ops.paths()).await;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
        let _ = shutdown_rx.await;
    });
    let register_then_end = async {
        harness.wait_control_hub("widget").await;
        let _ = shutdown_tx.send(());
    };
    let (result, ()) = tokio::join!(run_fut, register_then_end);
    result.expect("run_target must exit cleanly on shutdown");
    wait_for(TIMEOUT, || {
        let entry = harness.listen.registry().get("widget")?;
        (entry.state == EntryState::Stale).then_some(())
    })
    .await;

    let ops_call = ops.clone();
    let started = Instant::now();
    let outcome = tokio::task::spawn_blocking(move || {
        ops_call.tunnel_open(TunnelOpenReq {
            host: "widget".to_string(),
            mode: "local".to_string(),
            bind: None,
            listen_port: u32::from(free_port()),
            forward_host: "127.0.0.1".to_string(),
            forward_port: 1,
            wait_ms: Some(5_000),
            supervise_ms: Some(SUPERVISE_MS),
            accept_hold_ms: None,
        })
    })
    .await
    .expect("spawn_blocking join");
    let elapsed = started.elapsed();

    let err = match outcome {
        Ok(_) => panic!("must still be stale: nothing registered \"widget\" again"),
        Err(err) => err,
    };
    assert_eq!(err.code, qsh_proto::ErrorCode::HostNotFound, "{err:?}");
    assert!(
        err.retryable,
        "the 1s cap must return before the real 3s sweep: {err:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(2),
        "the 1s config cap, not the 5s request, governs the wait: {elapsed:?}"
    );

    localctl.shutdown().await;
    harness.shutdown().await;
}

/// Decision 12 and 23: every line of a reverse-route tunnel carries the
/// route and the host alias, the first key is `supervise`, and the
/// `generation` on `reestablished` is the one the controller registered.
#[tokio::test(flavor = "multi_thread")]
async fn supervise_lines_on_reverse_route_carry_host_and_a_generation_that_matches_the_registered_line()
 {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, None).await;
    let tunnel_id = lose_and_regain(&rig, &target, Kind::Local, Gap::Stale).await;

    let registered = rig
        .harness
        .listen
        .registry()
        .get("widget")
        .expect("the entry is still held, stale");
    for kind in ["lost", "reestablished"] {
        let line = &lines_of(kind)[0];
        assert_eq!(line["route"], "reverse", "{line}");
        assert_eq!(line["host"], "widget", "{line}");
        assert_eq!(line["tunnel_id"], tunnel_id.as_str(), "{line}");
        assert_eq!(line["mode"], "local", "{line}");
        assert!(
            line["at"].as_str().is_some_and(|at| at.ends_with('Z')),
            "{line}"
        );
    }
    assert_eq!(
        lines_of("reestablished")[0]["generation"].as_u64(),
        Some(registered.generation),
        "the line names the generation the controller registered"
    );
    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

// ---- -R (decisions 7-1, 7-4, 13 and 14) -----------------------------------

/// [`Ops::tunnel_list`] off the calling thread (it builds its own runtime).
async fn tunnel_list(ops: &Ops) -> qsh_proto::TunnelListData {
    let ops = ops.clone();
    tokio::task::spawn_blocking(move || ops.tunnel_list(qsh_proto::TunnelListReq {}))
        .await
        .expect("spawn_blocking join")
        .expect("tunnel.list")
}

/// [`Ops::tunnel_close`] off the calling thread.
async fn tunnel_close(ops: &Ops, tunnel_id: &str) -> qsh_proto::TunnelCloseData {
    let ops = ops.clone();
    let tunnel_id = tunnel_id.to_string();
    tokio::task::spawn_blocking(move || ops.tunnel_close(qsh_proto::TunnelCloseReq { tunnel_id }))
        .await
        .expect("spawn_blocking join")
        .expect("tunnel.close")
}

/// Decision 7-1 with 7-4: the target registers again, the supervisor asks
/// the daemon again, closes the old forward and opens the same bind on the
/// new registration. The port the tunnel carries traffic on is the one it
/// had, and no operator close is read into the loss.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_remote_reissues_after_the_target_reregisters() {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, None).await;
    lose_and_regain(&rig, &target, Kind::Remote, Gap::Stale).await;

    let back = &lines_of("reestablished")[0];
    assert_eq!(back["route"], "reverse");
    assert_eq!(back["mode"], "remote");
    assert!(back["previous_tunnel_id"].is_string(), "{back}");
    assert!(lines_of("closed").is_empty(), "{:?}", lines_of("closed"));

    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

/// Decision 13: after a re-issue the tunnel has a new `forward_id`; the
/// `reestablished` line names both, `qsh tunnels` shows the new one, and
/// closing by the first one is the ordinary `closed: false`.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_remote_reestablished_line_carries_a_new_tunnel_id_and_previous_tunnel_id_and_qsh_tunnels_shows_the_new_one()
 {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, None).await;
    let ops = rig.ops.clone();
    let seen = Arc::new(Mutex::new(None));
    let seen_in = Arc::clone(&seen);
    let first = lose_and_regain_then(
        &rig,
        &target,
        Kind::Remote,
        Gap::Stale,
        |running| async move {
            let back = lines_of("reestablished")[0].clone();
            let listed = tunnel_list(&ops).await;
            let mut ids: Vec<String> = listed.tunnels.iter().map(|t| t.tunnel_id.clone()).collect();
            ids.sort();
            let stale_close = tunnel_close(&ops, &running.tunnel_id).await;
            *seen_in.lock().unwrap() = Some((back, ids, stale_close));
            running
        },
    )
    .await;

    let (back, ids, stale_close) = seen.lock().unwrap().take().expect("the inspection ran");
    let new_id = back["tunnel_id"].as_str().expect("tunnel_id").to_string();
    assert_eq!(back["previous_tunnel_id"], first.as_str(), "{back}");
    assert_ne!(new_id, first);
    assert_eq!(ids, vec![new_id], "`qsh tunnels` lists only the new id");
    assert!(
        !stale_close.closed,
        "the first id no longer names anything: {stale_close:?}"
    );

    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

/// Decision 14: `qsh tunnel close` on the daemon removes the forward while
/// the registration stays. The claim loop's prompt answer plus the daemon's
/// lists read as an operator close: one `closed` line, exit `0`, nothing
/// re-opened.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_remote_closed_by_qsh_tunnel_close_emits_closed_and_exits_zero_without_reopening()
 {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, None).await;
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let targets = rig
        .harness
        .run_target(&target, "device-id", "controller", None, async {
            let _ = stop_rx.await;
        });
    let scenario = async {
        rig.harness.wait_control_hub("widget").await;
        let running = open(&rig.ops, Kind::Remote, rig.echo.port()).await;
        probe_within(Kind::Remote, running.bind, None, "before the close").await;

        let closed = tunnel_close(&rig.ops, &running.tunnel_id).await;
        assert!(closed.closed, "{closed:?}");
        let line = wait_line("closed").await;
        assert_eq!(line["route"], "reverse");
        assert_eq!(line["mode"], "remote");
        let ended = tokio::time::timeout(TIMEOUT, running.done)
            .await
            .expect("the tunnel ends on its own")
            .expect("the hold task joins");
        assert!(ended.is_none(), "an operator close exits 0: {ended:?}");
        assert!(lines_of("lost").is_empty(), "{:?}", lines_of("lost"));
        assert!(lines_of("reestablished").is_empty());
        assert!(tunnel_list(&rig.ops).await.tunnels.is_empty());
        let _ = stop_tx.send(());
    };
    let (result, ()) = tokio::join!(targets, scenario);
    result.expect("the registration ends cleanly");

    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}

/// Decision 14, the other reading: a registration that went away, even for
/// long enough to be swept, is a loss. The claim loop answers promptly in
/// both cases, so the daemon's lists decide, and no `closed` line appears.
#[tokio::test(flavor = "multi_thread")]
async fn supervised_reverse_remote_registration_loss_is_not_read_as_an_operator_close() {
    init_capture();
    let target = make_identity();
    let rig = rig(&target, Some(Duration::from_secs(1))).await;
    lose_and_regain(&rig, &target, Kind::Remote, Gap::Swept).await;

    assert!(lines_of("closed").is_empty(), "{:?}", lines_of("closed"));
    assert!(!lines_of("lost").is_empty());
    assert!(!lines_of("reestablished").is_empty());

    rig.localctl.shutdown().await;
    rig.harness.shutdown().await;
}
