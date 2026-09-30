//! The supervisor against a scripted peer (ADR-0023 decision 7-3).
//!
//! `qsh-testkit`, which has the live-host harness, cannot be a dev-dependency
//! of this crate, and every real `qsh serve` advertises `dial-filter.v1`
//! unconditionally. A peer that stopped offering it after a restart is
//! therefore scripted here: a listener that runs the real responder half of
//! the `Hello` exchange and counts the streams the client opens on it.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, ControlMessage, Hello, control_message};
use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq, TunnelDynamicReq};
use qsh_transport::{Connection, Listener};

use crate::config::Paths;
use crate::ops::Ops;
use crate::tunnel::testutil::{AlwaysPairingOpen, self_signed};

/// A listener that answers every connection's `Hello`, offering
/// `dial-filter.v1` only while `strip` is `false`, and reports each accepted
/// connection.
struct ScriptedPeer {
    addr: std::net::SocketAddr,
    fingerprint: String,
    strip: Arc<AtomicBool>,
    /// While set, liveness `Ping`s on the control stream go unanswered.
    mute: Arc<AtomicBool>,
    /// While set, an incoming connection's handshake is not completed, so a
    /// dial to this peer stays in flight.
    stall: Arc<AtomicBool>,
    /// Connection attempts that reached the listener, handshake done or not.
    incoming: Arc<AtomicUsize>,
    /// Streams the client opened after the handshake, across connections.
    requests: Arc<AtomicUsize>,
    /// What the peer says to `RemoteForwardOpen` and `RemoteForwardClose`.
    #[cfg_attr(not(unix), allow(dead_code))]
    rfwd: Arc<RfwdScript>,
    accepted: tokio::sync::mpsc::UnboundedReceiver<Connection>,
}

/// The scripted peer's side of `-R`: what it was asked and how it answers.
#[derive(Default)]
struct RfwdScript {
    /// Every `RemoteForwardOpen`, in order.
    opens: std::sync::Mutex<Vec<wire::RemoteForwardOpen>>,
    /// For each entry of `opens`, the ordinal of the connection it arrived
    /// on. Each supervise attempt dials a new connection, so this attributes
    /// an open to its attempt without reading a count against a moving clock.
    open_conns: std::sync::Mutex<Vec<usize>>,
    /// Every `RemoteForwardClose.forward_id`, in order.
    closes: std::sync::Mutex<Vec<String>>,
    /// The next this-many opens that ask for a concrete port fail with
    /// `CONNECTION_FAILED`, as a bind that races a listener still closing.
    bind_failures: AtomicUsize,
    /// While set, an open that asks for a concrete port is refused
    /// `PERMISSION_DENIED` (a policy that allows only port zero).
    deny_concrete_port: AtomicBool,
    /// Forward ids issued so far.
    issued: AtomicUsize,
}

impl RfwdScript {
    fn answer(&self, conn: usize, id: u64, body: &control_message::Body) -> Option<ControlMessage> {
        use wire::response;
        match body {
            control_message::Body::RfwdOpen(open) => {
                self.open_conns.lock().unwrap().push(conn);
                self.opens.lock().unwrap().push(open.clone());
                let refuse = |code, what: &str| {
                    Some(ControlMessage::error(
                        id,
                        wire::Error::from_code(code, what),
                    ))
                };
                // The very first open is the tunnel's own; the switches
                // below only concern what comes after a loss.
                let first = self.issued.load(Ordering::SeqCst) == 0;
                if !first && open.bind_port != 0 && self.deny_concrete_port.load(Ordering::SeqCst) {
                    return refuse(ErrorCode::PermissionDenied, "policy");
                }
                if !first
                    && open.bind_port != 0
                    && self
                        .bind_failures
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                {
                    return refuse(ErrorCode::ConnectionFailed, "address in use");
                }
                let n = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
                Some(ControlMessage::response(
                    id,
                    response::Body::RfwdOpened(wire::RemoteForwardOpened {
                        forward_id: format!("fwd-{n}"),
                        // The first answer is a port the peer chose, not the one
                        // asked for, like a request for an ephemeral port.
                        actual_port: if first { 43_210 } else { open.bind_port },
                    }),
                ))
            }
            control_message::Body::RfwdClose(close) => {
                self.closes.lock().unwrap().push(close.forward_id.clone());
                // Only the latest id is live on this peer; any other is
                // what a peer that lost its registrations says.
                let live = format!("fwd-{}", self.issued.load(Ordering::SeqCst));
                if close.forward_id == live {
                    Some(ControlMessage::new(
                        id,
                        control_message::Body::Response(wire::Response { body: None }),
                    ))
                } else {
                    Some(ControlMessage::error(
                        id,
                        wire::Error::from_code(ErrorCode::InvalidArgument, "no such forward_id"),
                    ))
                }
            }
            _ => None,
        }
    }
}

async fn scripted_peer() -> ScriptedPeer {
    let (identity, fingerprint) = self_signed();
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        identity,
        Arc::new(AlwaysPairingOpen),
    )
    .expect("bind the scripted peer");
    let addr = listener.local_addr().unwrap();
    let strip = Arc::new(AtomicBool::new(false));
    let mute = Arc::new(AtomicBool::new(false));
    let stall = Arc::new(AtomicBool::new(false));
    let incoming_count = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let rfwd = Arc::new(RfwdScript::default());
    let (tx, accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn({
        let strip = Arc::clone(&strip);
        let mute = Arc::clone(&mute);
        let stall = Arc::clone(&stall);
        let incoming_count = Arc::clone(&incoming_count);
        let requests = Arc::clone(&requests);
        let rfwd = Arc::clone(&rfwd);
        async move {
            while let Some(incoming) = listener.accept().await {
                let conn_ordinal = incoming_count.fetch_add(1, Ordering::SeqCst);
                while stall.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let Ok(conn) = incoming.accept().await else {
                    continue;
                };
                let offer_dial_filter = !strip.load(Ordering::SeqCst);
                let requests = Arc::clone(&requests);
                let mute = Arc::clone(&mute);
                let rfwd = Arc::clone(&rfwd);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let hello = move |_peer: &Hello| {
                        Ok(Hello {
                            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
                            device_name: "scripted".to_string(),
                            capabilities: wire::LOCAL_CAPABILITIES
                                .iter()
                                .filter(|cap| {
                                    offer_dial_filter || **cap != wire::CAP_DIAL_FILTER_V1
                                })
                                .map(|cap| cap.to_string())
                                .collect(),
                            reverse: None,
                        })
                    };
                    let Ok((mut ctl, _)) = crate::handshake::respond(&conn, hello).await else {
                        return;
                    };
                    tokio::spawn(async move {
                        while let Ok(Some(msg)) = ctl.recv.recv::<ControlMessage>().await {
                            let reply = match &msg.body {
                                Some(control_message::Body::Ping(_))
                                    if !mute.load(Ordering::SeqCst) =>
                                {
                                    Some(ControlMessage::new(
                                        msg.request_id,
                                        control_message::Body::Pong(wire::Pong {}),
                                    ))
                                }
                                Some(body) => rfwd.answer(conn_ordinal, msg.request_id, body),
                                None => None,
                            };
                            if let Some(reply) = reply
                                && ctl.send.send(&reply).await.is_err()
                            {
                                return;
                            }
                        }
                    });
                    let _ = tx.send(conn.clone());
                    // Any stream after the control stream is a request.
                    while conn.accept_bi().await.is_ok() {
                        requests.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        }
    });
    ScriptedPeer {
        addr,
        fingerprint: fingerprint.to_string(),
        strip,
        mute,
        stall,
        incoming: incoming_count,
        requests,
        rfwd,
        accepted,
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn supervised_dynamic_redial_to_a_peer_without_dial_filter_ends_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let ops = Ops::new(Paths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ));
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();

    let peer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut peer = peer_runtime.block_on(scripted_peer());
    ops.trust_add(TrustAddReq {
        name: "box".into(),
        address: Some(peer.addr.to_string()),
        fingerprint: Some(peer.fingerprint.clone()),
        cert_pem: None,
    })
    .unwrap();

    let hold = ops
        .tunnel_dynamic(TunnelDynamicReq {
            host: "box".into(),
            bind: None,
            listen_port: u32::from(free_port()),
            supervise_ms: Some(30_000),
            accept_hold_ms: None,
        })
        .expect("the first open sees dial-filter.v1 and binds");

    // From now on the peer no longer offers the capability, and the first
    // connection goes away.
    peer.strip.store(true, Ordering::SeqCst);
    let first = peer_runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), peer.accepted.recv()).await
        })
        .expect("the first connection was accepted")
        .expect("the channel is open");
    first.close(0, b"restart");

    let err = hold.hold();
    assert_eq!(err.code, ErrorCode::Unsupported, "{err:?}");
    assert_eq!(
        peer.requests.load(Ordering::SeqCst),
        0,
        "no request may reach a peer that lacks the capability"
    );
}

/// The process wall clock plus a hand-moved offset, plugged into the
/// process-wide wake detector the supervisor subscribes to.
struct FakeClock(std::sync::atomic::AtomicU64);

impl crate::client::wake::WallClock for FakeClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now() + Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}

/// `(when, "supervise" kind, cause)` of every supervise line, in order.
type Seen = Vec<(std::time::Instant, String, Option<String>)>;

/// Every supervise line, whole.
fn full_lines() -> &'static std::sync::Mutex<Vec<serde_json::Value>> {
    static LINES: std::sync::OnceLock<std::sync::Mutex<Vec<serde_json::Value>>> =
        std::sync::OnceLock::new();
    LINES.get_or_init(Default::default)
}

#[cfg(unix)]
fn lines_of(kind: &str) -> Vec<serde_json::Value> {
    full_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|line| line["supervise"] == kind)
        .cloned()
        .collect()
}

fn seen() -> &'static std::sync::Mutex<Seen> {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<Seen>> = std::sync::OnceLock::new();
    SEEN.get_or_init(Default::default)
}

struct TimedCapture;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TimedCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != crate::tunnel::supervise::TARGET {
            return;
        }
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
            full_lines()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line.clone());
            seen().lock().unwrap_or_else(|e| e.into_inner()).push((
                std::time::Instant::now(),
                line["supervise"].as_str().unwrap_or_default().to_string(),
                line["cause"].as_str().map(str::to_string),
            ));
        }
    }
}

fn lost_lines() -> Vec<(std::time::Instant, Option<String>)> {
    seen()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|(_, kind, _)| kind == "lost")
        .map(|(at, _, cause)| (*at, cause.clone()))
        .collect()
}

/// ADR-0023 decision 17 end to end: a wake resets the supervisor's idea of
/// the path, so a connection that went dead while the machine slept is
/// declared lost within about two seconds of waking instead of after the
/// idle probe interval (set to 60 s here, so only the wake can explain it).
#[test]
fn supervised_forward_carrier_is_declared_lost_within_two_seconds_of_an_injected_wake() {
    use crate::client::pathwatch::PathWatchConfig;
    use crate::client::wake::{WakeDetector, install_process_detector_for_test};
    use crate::ops::session::RecoveryConfig;
    use tracing_subscriber::layer::SubscriberExt as _;

    let clock = Arc::new(FakeClock(std::sync::atomic::AtomicU64::new(0)));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    // The detector's tick task belongs to whichever runtime subscribes
    // first: the supervisor's own. Nothing is subscribed yet.
    install_process_detector_for_test(WakeDetector::new(clock.clone()));
    // Filtered to the supervise target: an unfiltered global subscriber
    // makes every quinn `trace!` on every thread pay for a registry
    // lookup, which starves the handshake under load.
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(
            <TimedCapture as tracing_subscriber::Layer<_>>::with_filter(
                TimedCapture,
                tracing_subscriber::filter::Targets::new()
                    .with_target(crate::tunnel::supervise::TARGET, tracing::Level::INFO),
            ),
        ),
    )
    .expect("no other global tracing subscriber in this test process");

    let dir = tempfile::tempdir().unwrap();
    let ops = Ops::new(Paths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ))
    .with_recovery(RecoveryConfig {
        watch: PathWatchConfig {
            // Active for 5 s after any traffic (a wake counts), then a 60 s
            // idle cadence: without the wake, the first probe after the
            // tunnel goes quiet would come a minute later.
            active_window: Duration::from_secs(5),
            idle_probe_interval: Duration::from_secs(60),
            ..PathWatchConfig::default()
        },
        migration: false,
        ..RecoveryConfig::default()
    });
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();

    let peer = runtime.block_on(scripted_peer());
    ops.trust_add(TrustAddReq {
        name: "box".into(),
        address: Some(peer.addr.to_string()),
        fingerprint: Some(peer.fingerprint.clone()),
        cert_pem: None,
    })
    .unwrap();
    let hold = ops
        .tunnel_dynamic(TunnelDynamicReq {
            host: "box".into(),
            bind: None,
            listen_port: u32::from(free_port()),
            supervise_ms: Some(60_000),
            accept_hold_ms: None,
        })
        .expect("open the supervised tunnel");

    // Let the open's own traffic age out of the active window, so the
    // watchdog is on its idle cadence when the path dies.
    std::thread::sleep(Duration::from_secs(6));
    // The path "dies" while nobody is probing: the peer stops answering.
    peer.mute.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        lost_lines().is_empty(),
        "nothing but a wake may make the supervisor look at the path: {:?}",
        seen().lock().unwrap()
    );

    // The machine "wakes": the wall clock jumps ten seconds ahead of the
    // monotonic one.
    clock.0.fetch_add(10_000, Ordering::SeqCst);
    let woke = std::time::Instant::now();
    let limit = woke + Duration::from_secs(10);
    let lost = loop {
        if let Some(first) = lost_lines().into_iter().next() {
            break first;
        }
        assert!(
            std::time::Instant::now() < limit,
            "no `lost` within 10 s of the wake: {:?}",
            seen().lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let delay = lost.0.saturating_duration_since(woke);
    eprintln!("measured: `lost` {delay:?} after the injected wake");
    assert!(lost.0 >= woke, "`lost` came before the wake");
    assert!(delay <= Duration::from_secs(10), "took {delay:?}");
    assert_eq!(lost.1.as_deref(), Some("path_dead"));
    drop(hold);
}

// The capture helpers it reads the supervise lines with are unix-only.
#[cfg(unix)]
mod remote;

// ---- --accept-hold (ADR-0023 decision 19) ------------------------------

/// Everything an accept-hold test needs: a supervised `-D` tunnel over a
/// scripted peer that can be told to stall its next handshake, running in
/// its own thread until `stop` is sent.
struct HeldTunnel {
    peer: ScriptedPeer,
    peer_runtime: tokio::runtime::Runtime,
    port: u16,
    first: Connection,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    runner: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Drop for HeldTunnel {
    fn drop(&mut self) {
        self.peer.stall.store(false, Ordering::SeqCst);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(runner) = self.runner.take() {
            let _ = runner.join();
        }
    }
}

fn held_tunnel(accept_hold_ms: u32) -> HeldTunnel {
    let dir = tempfile::tempdir().unwrap();
    let ops = Ops::new(Paths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ));
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    let peer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut peer = peer_runtime.block_on(scripted_peer());
    ops.trust_add(TrustAddReq {
        name: "box".into(),
        address: Some(peer.addr.to_string()),
        fingerprint: Some(peer.fingerprint.clone()),
        cert_pem: None,
    })
    .unwrap();
    let port = free_port();
    let hold = ops
        .tunnel_dynamic(TunnelDynamicReq {
            host: "box".into(),
            bind: None,
            listen_port: u32::from(port),
            supervise_ms: Some(60_000),
            accept_hold_ms: Some(accept_hold_ms),
        })
        .expect("the first open binds");
    let first = peer_runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), peer.accepted.recv()).await
        })
        .expect("the first connection was accepted")
        .expect("the channel is open");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let runner = std::thread::spawn(move || {
        let _ = hold.hold_until(async move {
            let _ = stopped.await;
        });
    });
    HeldTunnel {
        peer,
        peer_runtime,
        port,
        first,
        stop: Some(stop),
        runner: Some(runner),
        _dir: dir,
    }
}

/// A SOCKS5 client that has greeted and sent a `CONNECT`, and is now
/// waiting for the reply.
fn socks_connect(port: u16) -> std::net::TcpStream {
    use std::io::{Read, Write};
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("the listener is bound");
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    tcp.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut select = [0u8; 2];
    tcp.read_exact(&mut select).unwrap();
    assert_eq!(select, [0x05, 0x00]);
    let host = b"example.test";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&80u16.to_be_bytes());
    tcp.write_all(&request).unwrap();
    tcp
}

fn wait_for(mut cond: impl FnMut() -> bool, what: &str) {
    for _ in 0..1_500 {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("never happened: {what}");
}

/// Lose the first connection and wait until the supervisor's redial is at the
/// peer's door (stalled there), which is when its hold window is open.
fn lose_first_and_wait_for_the_redial(tunnel: &HeldTunnel) {
    let before = tunnel.peer.incoming.load(Ordering::SeqCst);
    tunnel.peer.stall.store(true, Ordering::SeqCst);
    tunnel.first.close(0, b"restart");
    wait_for(
        || tunnel.peer.incoming.load(Ordering::SeqCst) > before,
        "the redial reaching the peer",
    );
}

/// A `CONNECT` that arrives while the redial is in flight is kept, sends
/// nothing, and goes out on the new connection once the peer has answered.
/// The wall-clock sleep only gives the listener time to take the `CONNECT`
/// into its hold; the window is 2 s and the stall is released well inside it.
#[test]
fn accept_hold_a_connect_during_a_redial_rides_the_new_connection() {
    let tunnel = held_tunnel(2_000);
    lose_first_and_wait_for_the_redial(&tunnel);
    let _tcp = socks_connect(tunnel.port);
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        tunnel.peer.requests.load(Ordering::SeqCst),
        0,
        "nothing is sent while the redial is in flight"
    );
    tunnel.peer.stall.store(false, Ordering::SeqCst);
    wait_for(
        || tunnel.peer.requests.load(Ordering::SeqCst) == 1,
        "the held CONNECT reaching the new connection",
    );
}

/// The same connection, with the peer stalled past the window, is answered
/// `REP 0x01` and never sent anywhere, not even on the connection that comes
/// up afterwards.
#[test]
fn accept_hold_a_connect_outlasting_the_window_gets_rep_01_and_no_stream() {
    use std::io::Read;
    let mut tunnel = held_tunnel(300);
    lose_first_and_wait_for_the_redial(&tunnel);
    let started = std::time::Instant::now();
    let mut tcp = socks_connect(tunnel.port);
    let mut rep = [0u8; 10];
    tcp.read_exact(&mut rep).unwrap();
    assert_eq!(rep[1], 0x01);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(tunnel.peer.requests.load(Ordering::SeqCst), 0);

    tunnel.peer.stall.store(false, Ordering::SeqCst);
    let second = tunnel
        .peer_runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), tunnel.peer.accepted.recv()).await
        })
        .expect("the tunnel re-established")
        .expect("the channel is open");
    // Its control stream is up; had the expired CONNECT been kept, it would
    // be a request by now.
    assert_eq!(tunnel.peer.requests.load(Ordering::SeqCst), 0);
    drop(second);
}

// ---- the reverse route against a scripted daemon (ADR-0023 decisions 7-2, 7-5, 12) ----
//
// A real daemon ends the `LOCAL_CONTROL` conduit the moment a registration
// changes, and the supervisor reads that as a loss before any accept can see
// the new identity. The per-accept check and the wake line are therefore
// driven against a daemon that does exactly what the test scripts.

#[cfg(unix)]
const FP_A: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
#[cfg(unix)]
const FP_B: &str = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

#[cfg(unix)]
/// A localctl daemon that answers `LocalHostList`, `LOCAL_CONTROL` and
/// `LOCAL_STREAM` from switches the test flips.
struct ScriptedDaemon {
    runtime: tokio::runtime::Runtime,
    /// The fingerprint a `LOCAL_CONTROL` ack and the host list report.
    control_fingerprint: Arc<std::sync::Mutex<String>>,
    /// The fingerprint a `LOCAL_STREAM` ack reports.
    stream_fingerprint: Arc<std::sync::Mutex<String>>,
    /// When unset, the host list is empty and `LOCAL_CONTROL` is refused
    /// `HOST_NOT_FOUND`, as for a name no daemon holds.
    registered: Arc<AtomicBool>,
    /// `LOCAL_STREAM` conduits opened, and the `StreamHeader`s that reached
    /// the daemon on them.
    stream_opens: Arc<AtomicUsize>,
    stream_headers: Arc<AtomicUsize>,
    /// Bumped to close every live `LOCAL_CONTROL` conduit.
    drop_controls: tokio::sync::watch::Sender<u64>,
}

#[cfg(unix)]
impl ScriptedDaemon {
    fn start(runtime_dir: &std::path::Path) -> Self {
        use crate::localctl::frame::LocalConduit;
        use qsh_proto::local::{
            LocalAdminRequest, LocalError, LocalHello, LocalHelloAck, LocalHost,
            LocalHostListResult, LocalResponse, LocalStreamKind, local_admin_request,
            local_response,
        };

        std::fs::create_dir_all(runtime_dir).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let control_fingerprint = Arc::new(std::sync::Mutex::new(FP_A.to_string()));
        let stream_fingerprint = Arc::new(std::sync::Mutex::new(FP_A.to_string()));
        let registered = Arc::new(AtomicBool::new(true));
        let stream_opens = Arc::new(AtomicUsize::new(0));
        let stream_headers = Arc::new(AtomicUsize::new(0));
        let (drop_controls, _) = tokio::sync::watch::channel(0u64);
        let socket = runtime_dir.join(format!("{}.sock", std::process::id()));
        let listener = {
            let _guard = runtime.enter();
            let std_listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            std_listener.set_nonblocking(true).unwrap();
            tokio::net::UnixListener::from_std(std_listener).unwrap()
        };
        let daemon = Self {
            runtime,
            control_fingerprint: Arc::clone(&control_fingerprint),
            stream_fingerprint: Arc::clone(&stream_fingerprint),
            registered: Arc::clone(&registered),
            stream_opens: Arc::clone(&stream_opens),
            stream_headers: Arc::clone(&stream_headers),
            drop_controls: drop_controls.clone(),
        };
        daemon.runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let control_fingerprint = Arc::clone(&control_fingerprint);
                let stream_fingerprint = Arc::clone(&stream_fingerprint);
                let registered = Arc::clone(&registered);
                let stream_opens = Arc::clone(&stream_opens);
                let stream_headers = Arc::clone(&stream_headers);
                let mut dropped = drop_controls.subscribe();
                tokio::spawn(async move {
                    let mut conduit = LocalConduit::new(stream);
                    let Ok(Some(hello)) = conduit.recv::<LocalHello>().await else {
                        return;
                    };
                    let ack = |fingerprint: &Arc<std::sync::Mutex<String>>| LocalResponse {
                        body: Some(local_response::Body::HelloAck(LocalHelloAck {
                            host: hello.host.clone(),
                            peer_fingerprint: fingerprint.lock().unwrap().clone(),
                            generation: 1,
                            capabilities: vec![wire::CAP_DIAL_FILTER_V1.to_string()],
                        })),
                    };
                    let not_found = || LocalResponse {
                        body: Some(local_response::Body::Error(LocalError {
                            code: "HOST_NOT_FOUND".to_string(),
                            message: "not registered".to_string(),
                        })),
                    };
                    match hello.kind {
                        k if k == LocalStreamKind::LocalAdmin as i32 => {
                            let Ok(Some(LocalAdminRequest {
                                body: Some(local_admin_request::Body::HostList(_)),
                            })) = conduit.recv::<LocalAdminRequest>().await
                            else {
                                return;
                            };
                            let hosts = if registered.load(Ordering::SeqCst) {
                                vec![LocalHost {
                                    name: "phone".to_string(),
                                    address: "203.0.113.5:51820".to_string(),
                                    state: "reachable".to_string(),
                                    fingerprint: control_fingerprint.lock().unwrap().clone(),
                                    capabilities: vec![wire::CAP_DIAL_FILTER_V1.to_string()],
                                    generation: 1,
                                    registered_at: "2026-09-30T00:00:00Z".to_string(),
                                    lost_at: None,
                                }]
                            } else {
                                Vec::new()
                            };
                            let _ = conduit
                                .send(&LocalResponse {
                                    body: Some(local_response::Body::HostListResult(
                                        LocalHostListResult { hosts },
                                    )),
                                })
                                .await;
                        }
                        k if k == LocalStreamKind::LocalControl as i32 => {
                            if !registered.load(Ordering::SeqCst) {
                                let _ = conduit.send(&not_found()).await;
                                return;
                            }
                            if conduit.send(&ack(&control_fingerprint)).await.is_err() {
                                return;
                            }
                            // Hold the conduit until the test drops it.
                            let _ = dropped.changed().await;
                        }
                        k if k == LocalStreamKind::LocalStream as i32 => {
                            stream_opens.fetch_add(1, Ordering::SeqCst);
                            if conduit.send(&ack(&stream_fingerprint)).await.is_err() {
                                return;
                            }
                            if let Ok(Ok(Some(_))) = tokio::time::timeout(
                                Duration::from_millis(500),
                                conduit.recv_payload(),
                            )
                            .await
                            {
                                stream_headers.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        _ => {}
                    }
                });
            }
        });
        daemon
    }

    fn drop_control_conduits(&self) {
        self.drop_controls.send_modify(|n| *n += 1);
    }
}

#[cfg(unix)]
fn reverse_ops(dir: &std::path::Path) -> Ops {
    let ops = Ops::new(
        Paths::new(dir.join("config"), dir.join("state")).with_runtime_dir(dir.join("run")),
    );
    crate::trust::TrustStore::default()
        .save(&ops.paths().trust_file())
        .unwrap();
    ops
}

#[cfg(unix)]
fn open_reverse_local(ops: &Ops) -> crate::ops::TunnelHold {
    ops.tunnel_open(qsh_proto::TunnelOpenReq {
        host: "phone".to_string(),
        mode: "local".to_string(),
        bind: None,
        listen_port: u32::from(free_port()),
        forward_host: "127.0.0.1".to_string(),
        forward_port: 9,
        wait_ms: None,
        supervise_ms: Some(60_000),
        accept_hold_ms: None,
    })
    .expect("the supervised open over the scripted daemon")
}

#[cfg(unix)]
fn capture_supervise_lines() {
    use tracing_subscriber::layer::SubscriberExt as _;
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(
            <TimedCapture as tracing_subscriber::Layer<_>>::with_filter(
                TimedCapture,
                tracing_subscriber::filter::Targets::new()
                    .with_target(crate::tunnel::supervise::TARGET, tracing::Level::INFO),
            ),
        ),
    )
    .expect("no other global tracing subscriber in this test process");
}

#[cfg(unix)]
/// Decisions 6, 7-2 and 7-5. The registration behind the host name changes
/// to another device while the tunnel's `LOCAL_CONTROL` conduit is still
/// open. The next accept's `LocalHelloAck` names the other device, so the
/// `StreamHeader` is never sent; the supervisor then asks again, sees the
/// other fingerprint on the control leg too, and ends the tunnel with
/// `AUTH_FAILED`.
#[test]
fn supervised_reverse_local_sends_no_byte_to_a_device_that_reregistered_under_the_same_name_with_another_fingerprint()
 {
    capture_supervise_lines();
    let dir = tempfile::tempdir().unwrap();
    let ops = reverse_ops(dir.path());
    let daemon = ScriptedDaemon::start(&ops.paths().runtime_dir());
    let hold = open_reverse_local(&ops);
    let bind: std::net::SocketAddr = hold.tunnel().bind.parse().unwrap();
    let (ended_tx, ended_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = ended_tx.send(hold.hold());
    });

    // Another device takes the name: new connections see it from now on,
    // and so does the next time the supervisor asks.
    *daemon.stream_fingerprint.lock().unwrap() = FP_B.to_string();
    *daemon.control_fingerprint.lock().unwrap() = FP_B.to_string();
    let _client = std::net::TcpStream::connect(bind).expect("the listener is bound");

    let err = ended_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the supervisor ends the tunnel");
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert!(
        daemon.stream_opens.load(Ordering::SeqCst) >= 1,
        "the accept must have reached the daemon's ack for the check to be tested"
    );
    assert_eq!(
        daemon.stream_headers.load(Ordering::SeqCst),
        0,
        "no StreamHeader may reach a registration other than the confirmed one"
    );
    let gave_up = lines_of("gave_up");
    assert_eq!(gave_up.len(), 1, "{gave_up:?}");
    assert_eq!(gave_up[0]["code"], "AUTH_FAILED");
    assert_eq!(gave_up[0]["route"], "reverse");
    assert_eq!(gave_up[0]["host"], "phone");
}

#[cfg(unix)]
/// Decision 17 and 12 on the reverse route: a wake during the outage is
/// logged with the time slept, and the outage the next `reestablished`
/// reports does not include that time.
#[test]
fn supervise_wake_line_reports_slept_ms_and_outage_ms_excludes_it() {
    use crate::client::wake::{WakeDetector, install_process_detector_for_test};

    let clock = Arc::new(FakeClock(std::sync::atomic::AtomicU64::new(0)));
    install_process_detector_for_test(WakeDetector::new(clock.clone()));
    capture_supervise_lines();
    let dir = tempfile::tempdir().unwrap();
    let ops = reverse_ops(dir.path());
    let daemon = ScriptedDaemon::start(&ops.paths().runtime_dir());
    let hold = open_reverse_local(&ops);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let runner = std::thread::spawn(move || {
        let _ = hold.hold_until(async move {
            let _ = stopped.await;
        });
    });

    // The registration goes; the supervisor starts asking and getting
    // `HOST_NOT_FOUND`.
    daemon.registered.store(false, Ordering::SeqCst);
    daemon.drop_control_conduits();
    wait_for(|| !lines_of("lost").is_empty(), "the `lost` line");
    wait_for(|| !lines_of("retry").is_empty(), "a retry");

    // The machine sleeps ten seconds (the wall clock jumps, the monotonic
    // one does not) and wakes; then the registration is back.
    clock.0.fetch_add(10_000, Ordering::SeqCst);
    wait_for(|| !lines_of("wake").is_empty(), "the `wake` line");
    daemon.registered.store(true, Ordering::SeqCst);
    wait_for(
        || !lines_of("reestablished").is_empty(),
        "the `reestablished` line",
    );

    let wake = &lines_of("wake")[0];
    assert_eq!(wake["route"], "reverse");
    assert_eq!(wake["host"], "phone");
    let slept = wake["slept_ms"].as_u64().expect("slept_ms");
    assert!(
        (9_000..=11_000).contains(&slept),
        "slept_ms {slept} should be about the injected ten seconds"
    );
    let outage = lines_of("reestablished")[0]["outage_ms"]
        .as_u64()
        .expect("outage_ms");
    assert!(
        outage < slept,
        "outage_ms {outage} must not include the {slept} ms slept"
    );
    let _ = stop.send(());
    runner.join().unwrap();
}
