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
    accepted: tokio::sync::mpsc::UnboundedReceiver<Connection>,
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
    let (tx, accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn({
        let strip = Arc::clone(&strip);
        let mute = Arc::clone(&mute);
        let stall = Arc::clone(&stall);
        let incoming_count = Arc::clone(&incoming_count);
        let requests = Arc::clone(&requests);
        async move {
            while let Some(incoming) = listener.accept().await {
                incoming_count.fetch_add(1, Ordering::SeqCst);
                while stall.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let Ok(conn) = incoming.accept().await else {
                    continue;
                };
                let offer_dial_filter = !strip.load(Ordering::SeqCst);
                let requests = Arc::clone(&requests);
                let mute = Arc::clone(&mute);
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
                            if !matches!(msg.body, Some(control_message::Body::Ping(_)))
                                || mute.load(Ordering::SeqCst)
                            {
                                continue;
                            }
                            let pong = ControlMessage::new(
                                msg.request_id,
                                control_message::Body::Pong(wire::Pong {}),
                            );
                            if ctl.send.send(&pong).await.is_err() {
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
