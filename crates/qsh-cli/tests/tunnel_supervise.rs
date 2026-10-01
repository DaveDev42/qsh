//! `--supervise` for forward `-L` and `-D`, driven through the product path
//! (ADR-0023, `docs/CLI.md` §6.14, `docs/design/testing.md` L4).
//!
//! A real `qsh serve` sits behind a [`ChaosProxy`] and the client is pinned
//! to the proxy, so a test can kill the path (`sever`), stall it
//! (`blackhole`) or replace the peer behind it (kill the `serve` child and
//! start another one on the same address). Every test opens the tunnel with
//! [`Ops::tunnel_open`] / [`Ops::tunnel_dynamic`] in this process and reads
//! the supervisor's own diagnostic lines (target `qsh::tunnel::supervise`)
//! off a tracing layer, so "the tunnel was re-established" is an observed
//! event and never a sleep.
//!
//! Migration is off in every scenario here. The proxy models a dead path by
//! blacklisting the client's source address, and a rebind escapes that by
//! definition; what these tests own is the re-dial path.

#![cfg(unix)]

mod common;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use common::{CLIENT_ALIAS, HOST_ALIAS, Sandbox, ServeGuard, poll_until};
use nix::sys::signal::Signal;
use qsh_core::{Ops, Paths, RecoveryConfig};
use qsh_proto::{ErrorCode, TunnelDynamicReq, TunnelOpenReq};
use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy};
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// How long a scenario may wait for the supervisor to reach a state. A
/// hang is a failure; nothing is expected to take anywhere near this.
const WAIT: Duration = Duration::from_secs(60);

/// The disconnection budget the tunnels here are opened with. Large enough
/// that nothing but a test's own choice ends a tunnel.
const BUDGET_MS: u32 = 120_000;

// ---------------------------------------------------------------------------
// supervise telemetry capture
// ---------------------------------------------------------------------------

fn captured() -> &'static Mutex<Vec<Value>> {
    static LINES: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

fn capture_supervise_lines() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(CaptureLayer)
            .try_init()
            .ok();
    });
}

struct CaptureLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != qsh_core::tunnel::supervise::TARGET {
            return;
        }
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        if let Ok(value) = serde_json::from_str::<Value>(&line) {
            captured()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(value);
        }
    }
}

struct MessageOnly<'a>(&'a mut String);

impl tracing::field::Visit for MessageOnly<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

/// The captured lines of one tunnel with `supervise == kind`, in order.
fn lines_of(tunnel_id: &str, kind: &str) -> Vec<Value> {
    captured()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|line| line["tunnel_id"] == tunnel_id && line["supervise"] == kind)
        .cloned()
        .collect()
}

/// Wait until the tunnel has emitted at least `count` lines of `kind`.
fn wait_for(tunnel_id: &str, kind: &str, count: usize) -> Vec<Value> {
    poll_until(&format!("{count} `{kind}` line(s)"), WAIT, || {
        let lines = lines_of(tunnel_id, kind);
        (lines.len() >= count).then_some(lines)
    })
}

// ---------------------------------------------------------------------------
// the rig
// ---------------------------------------------------------------------------

struct Rig {
    host: Sandbox,
    client: Sandbox,
    serve: Option<ServeGuard>,
    /// The address the host bound; a restart binds it again.
    addr: String,
    proxy: Arc<ChaosProxy>,
    /// Drives the proxy.
    runtime: tokio::runtime::Runtime,
}

impl Rig {
    fn start() -> Self {
        capture_supervise_lines();
        let host = Sandbox::new();
        let client = Sandbox::new();
        let host_fingerprint = host.fingerprint();
        let client_fingerprint = client.fingerprint();
        host.trust_add(CLIENT_ALIAS, None, &client_fingerprint);
        let serve = ServeGuard::start_at(&host, &common::steady_bind());
        let addr = serve.addr().to_string();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("proxy runtime");
        let server: SocketAddr = addr.parse().expect("serve address");
        let proxy = Arc::new(
            runtime
                .block_on(ChaosProxy::start(server, ChaosPolicy::seeded(0x5EED_0023)))
                .expect("chaos proxy"),
        );
        client.trust_add(
            HOST_ALIAS,
            Some(&proxy.addr().to_string()),
            &host_fingerprint,
        );
        Self {
            host,
            client,
            serve: Some(serve),
            addr,
            proxy,
            runtime,
        }
    }

    fn ops(&self) -> Ops {
        Ops::new(Paths::new(
            self.client.config_dir().to_path_buf(),
            self.client.state_dir().to_path_buf(),
        ))
        .with_recovery(RecoveryConfig {
            migration: false,
            ..RecoveryConfig::default()
        })
    }

    /// Kill the path underneath every live connection.
    fn sever(&self) {
        self.runtime.block_on(self.proxy.sever());
    }

    fn blackhole(&self, dur: Duration) {
        self.runtime.block_on(self.proxy.blackhole(dur));
    }

    /// SIGKILL the host: nothing tells the client, and the address stops
    /// answering.
    fn kill_serve(&mut self) {
        if let Some(mut serve) = self.serve.take() {
            serve.signal(Signal::SIGKILL);
            serve
                .wait_timeout(Duration::from_secs(10))
                .expect("the killed serve exits");
        }
    }

    /// SIGTERM the host and wait for it to exit. A clean exit drops its
    /// audit sink, and the sink's `Drop` joins the writer thread once it has
    /// written every record already queued.
    fn stop_serve(&mut self) {
        if let Some(mut serve) = self.serve.take() {
            serve.signal(Signal::SIGTERM);
            serve
                .wait_timeout(Duration::from_secs(20))
                .expect("the host exits on SIGTERM");
        }
    }

    /// Bring the same host (same identity, same policy) back on the address
    /// it had.
    fn restart_serve(&mut self) {
        self.serve = Some(ServeGuard::start_at(&self.host, &self.addr));
    }
}

fn start_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the echo server");
    let port = listener.local_addr().expect("echo address").port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().expect("clone the echo socket");
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
            });
        }
    });
    port
}

/// A port nothing listens on, released back to the kernel; the request
/// wants a concrete one.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

fn local_req(forward_port: u16, supervise_ms: u32) -> TunnelOpenReq {
    TunnelOpenReq {
        host: HOST_ALIAS.to_string(),
        mode: "local".to_string(),
        bind: None,
        listen_port: u32::from(free_port()),
        forward_host: "127.0.0.1".to_string(),
        forward_port: u32::from(forward_port),
        wait_ms: None,
        supervise_ms: (supervise_ms != 0).then_some(supervise_ms),
        accept_hold_ms: None,
    }
}

fn dynamic_req(supervise_ms: u32) -> TunnelDynamicReq {
    TunnelDynamicReq {
        host: HOST_ALIAS.to_string(),
        bind: None,
        listen_port: u32::from(free_port()),
        supervise_ms: (supervise_ms != 0).then_some(supervise_ms),
        accept_hold_ms: None,
    }
}

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the tunnel port");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    stream
}

/// One echo round trip through a fresh connection to `port`.
fn round_trip(port: u16, payload: &[u8]) {
    let mut stream = connect(port);
    exchange(&mut stream, payload);
}

fn exchange(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).expect("write through the tunnel");
    let mut back = vec![0u8; payload.len()];
    stream
        .read_exact(&mut back)
        .expect("read the echo back through the tunnel");
    assert_eq!(back, payload);
}

/// Whether a connect to `port` is refused right now.
fn refused(port: u16) -> bool {
    match TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(1),
    ) {
        Ok(_) => false,
        Err(err) => err.kind() == std::io::ErrorKind::ConnectionRefused,
    }
}

// ---------------------------------------------------------------------------
// -L
// ---------------------------------------------------------------------------

#[test]
fn supervised_local_keeps_its_port_and_tunnel_id_across_two_reestablishments() {
    let rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(local_req(echo, BUDGET_MS))
        .expect("open the supervised tunnel");
    let id = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.expect("bound port")).unwrap();
    round_trip(port, b"before");

    for round in 1..=2 {
        rig.sever();
        wait_for(&id, "reestablished", round);
        round_trip(port, format!("after-{round}").as_bytes());
    }

    // The same tunnel throughout: two losses, two re-establishments, and the
    // listener never moved.
    assert_eq!(lines_of(&id, "lost").len(), 2);
    assert_eq!(hold.tunnel().tunnel_id, id);
    assert_eq!(hold.tunnel().actual_port, Some(u32::from(port)));
    let reestablished = lines_of(&id, "reestablished");
    assert_eq!(reestablished.len(), 2);
    for line in reestablished {
        assert_eq!(line["mode"], "local");
        assert_eq!(line["route"], "forward");
        assert!(line["outage_ms"].is_u64(), "{line}");
    }
    hold.close();
}

#[test]
fn supervised_local_splice_survives_a_short_blackhole_and_new_accepts_ride_the_new_connection() {
    let rig = Rig::start();
    let echo = start_echo();
    let ops = rig.ops();

    // The default-mode tunnel: a stall shorter than the death detector is
    // ridden out by the connection itself.
    let plain = ops
        .tunnel_open(local_req(echo, 0))
        .expect("open the default-mode tunnel");
    let plain_port = u16::try_from(plain.tunnel().actual_port.unwrap()).unwrap();
    let mut plain_splice = connect(plain_port);
    exchange(&mut plain_splice, b"plain-1");

    // The supervised tunnel: the same, and it does not declare the carrier
    // lost for it.
    let hold = ops
        .tunnel_open(local_req(echo, BUDGET_MS))
        .expect("open the supervised tunnel");
    let id = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.unwrap()).unwrap();
    let mut splice = connect(port);
    exchange(&mut splice, b"super-1");

    rig.blackhole(Duration::from_millis(400));
    exchange(&mut plain_splice, b"plain-2");
    exchange(&mut splice, b"super-2");
    assert!(
        lines_of(&id, "lost").is_empty(),
        "a stall shorter than the detector must not lose the carrier: {:?}",
        lines_of(&id, "lost")
    );
    // New accepts after the stall ride the same, still live connection.
    round_trip(plain_port, b"plain-3");
    round_trip(port, b"super-3");

    // Then the path really dies: the supervised tunnel takes new accepts on
    // the new connection.
    rig.sever();
    wait_for(&id, "reestablished", 1);
    round_trip(port, b"super-4");
    drop(splice);
    drop(plain_splice);
    hold.close();
    plain.close();
}

#[test]
fn supervised_local_accept_during_disconnect_gets_rst_once_the_carrier_is_disconnected() {
    let mut rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(local_req(echo, BUDGET_MS))
        .expect("open the supervised tunnel");
    let id = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.unwrap()).unwrap();
    round_trip(port, b"warm");

    rig.kill_serve();
    wait_for(&id, "lost", 1);

    // The carrier is Disconnected from the instant `lost` is emitted: the
    // connection is accepted by the kernel and reset at once, never queued.
    // The RST can reach this side before `connect` itself returns: the
    // handshake completes in the kernel, the holder accepts and resets, and
    // a client thread that has not been scheduled yet gets ECONNRESET from
    // `connect` (observed on macOS under a loaded nextest run). That is the
    // same reset, so it is checked the same way as one seen by `read`.
    let outcome = TcpStream::connect(("127.0.0.1", port)).and_then(|mut stream| {
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        stream.read(&mut buf)
    });
    match outcome {
        Err(err) => assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionReset,
            "expected an RST, got {err}"
        ),
        Ok(n) => panic!("expected an RST while disconnected, read {n} byte(s)"),
    }
    // The listener stayed bound throughout.
    assert!(!refused(port), "the listener must stay bound");
    assert!(
        lines_of(&id, "reestablished").is_empty(),
        "nothing brought the peer back"
    );
    hold.close();
}

#[test]
fn supervised_forward_initial_open_failure_is_not_retried() {
    let mut rig = Rig::start();
    let echo = start_echo();
    rig.kill_serve();
    let started = Instant::now();
    let err = match rig.ops().tunnel_open(local_req(echo, BUDGET_MS)) {
        Ok(_) => panic!("opening against a dead peer must fail"),
        Err(err) => err,
    };
    assert_eq!(err.code, ErrorCode::ConnectionFailed, "{err:?}");
    // The first open is the caller's answer, not the supervisor's retry: it
    // fails inside one dial deadline instead of spending the budget.
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the initial open was retried for {:?}",
        started.elapsed()
    );
    let any = captured()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|line| line["supervise"] == "retry" || line["supervise"] == "lost");
    assert!(!any, "no supervise line for a tunnel that never opened");
}

// ---------------------------------------------------------------------------
// -D
// ---------------------------------------------------------------------------

/// A SOCKS5 `CONNECT` to `127.0.0.1:1`, up to the reply's first two bytes.
fn socks_connect_reply(port: u16) -> [u8; 2] {
    let mut stream = connect(port);
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x01])
        .unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).unwrap();
    reply
}

#[test]
fn supervised_dynamic_connect_during_disconnect_gets_rep_01() {
    let mut rig = Rig::start();
    let hold = rig
        .ops()
        .tunnel_dynamic(dynamic_req(BUDGET_MS))
        .expect("open the supervised -D tunnel");
    let id = hold.dynamic_tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.dynamic_tunnel().actual_port.unwrap()).unwrap();

    rig.kill_serve();
    wait_for(&id, "lost", 1);
    // General failure, immediately, and no tunnel stream was attempted.
    assert_eq!(socks_connect_reply(port), [0x05, 0x01]);
    assert!(!refused(port), "the SOCKS listener must stay bound");
    hold.close();
}

// ---------------------------------------------------------------------------
// what the peer behind the address may become
// ---------------------------------------------------------------------------

/// A second, different host: its own identity, pinned by the client (so the
/// TLS layer accepts it) and trusting the client.
fn impostor(rig: &Rig) -> Sandbox {
    let other = Sandbox::new();
    let other_fingerprint = other.fingerprint();
    other.trust_add(CLIENT_ALIAS, None, &rig.client.fingerprint());
    rig.client.trust_add("other", None, &other_fingerprint);
    other
}

#[test]
fn supervised_forward_redial_to_a_different_fingerprint_ends_with_auth_failed_and_sends_no_request()
{
    let mut rig = Rig::start();
    let echo = start_echo();
    let other = impostor(&rig);
    let hold = rig
        .ops()
        .tunnel_open(local_req(echo, BUDGET_MS))
        .expect("open the supervised tunnel");
    let id = hold.tunnel().tunnel_id.clone();
    round_trip(
        u16::try_from(hold.tunnel().actual_port.unwrap()).unwrap(),
        b"warm",
    );

    rig.kill_serve();
    let _other_serve = ServeGuard::start_at(&other, &rig.addr);
    let err = hold.hold();
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert_eq!(lines_of(&id, "gave_up").len(), 1);
    assert_eq!(
        lines_of(&id, "reestablished").len(),
        0,
        "a different peer must never become the carrier"
    );
    // The impostor was dialed and dropped; nothing was ever sent to it.
    assert!(
        other.audit_records().is_empty(),
        "the different peer saw a request: {:?}",
        other.audit_records()
    );
}

/// The host's `action` denies, once they are all on disk. The host queues
/// an audit record before it answers, and a writer thread appends it later
/// (the module doc of `qsh-core`'s `audit::writer`), so the denial can
/// reach the client before its line is in the file. Wait for the first
/// deny line, then stop the host so its writer drains whatever else is
/// queued, and only then count: a retry storm still shows up as more than
/// one.
fn settled_denies(rig: &mut Rig, action: &str) -> Vec<Value> {
    let is_deny = |record: &Value| record["action"] == action && record["decision"] == "deny";
    poll_until("the host's audit deny line", WAIT, || {
        rig.host.audit_records().iter().any(is_deny).then_some(())
    });
    rig.stop_serve();
    rig.host
        .audit_records()
        .into_iter()
        .filter(|record| is_deny(record))
        .collect()
}

/// Rewrite the host's `acl.toml` without `forward.local` and restart the
/// host on its address.
fn restart_without_forward_local(rig: &mut Rig) {
    rig.kill_serve();
    let acl = rig.host.config_dir().join("acl.toml");
    std::fs::remove_file(&acl).expect("remove the planted acl");
    std::fs::write(
        &acl,
        format!(
            "[[acl]]\nprincipal = \"device:{CLIENT_ALIAS}\"\nallow = [\"exec.run\", \
             \"session.open\", \"session.list\", \"session.attach\", \"session.control\"]\n"
        ),
    )
    .expect("write the narrowed acl");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&acl, std::fs::Permissions::from_mode(0o600));
    }
    rig.restart_serve();
}

#[test]
fn supervised_forward_peer_restarted_without_forward_local_ends_permission_denied_with_one_audit_deny()
 {
    let mut rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(local_req(echo, BUDGET_MS))
        .expect("open the supervised tunnel");
    let id = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.unwrap()).unwrap();
    round_trip(port, b"warm");

    restart_without_forward_local(&mut rig);
    // Once the tunnel is back on the new peer, one local connection makes
    // the peer answer the first request with a denial.
    let poker = {
        let id = id.clone();
        thread::spawn(move || {
            wait_for(&id, "reestablished", 1);
            let mut stream = connect(port);
            let _ = stream.write_all(b"knock");
            let mut buf = [0u8; 8];
            let _ = stream.read(&mut buf);
        })
    };
    let err = hold.hold();
    poker.join().expect("poker thread");
    assert_eq!(err.code, ErrorCode::PermissionDenied, "{err:?}");
    let denies = settled_denies(&mut rig, "forward.local");
    assert_eq!(denies.len(), 1, "one deny, no retry storm: {denies:?}");
}

/// `qsh trust remove` on the host, run against the host's own config: the
/// host re-reads `trust.toml` on every handshake, so no restart is needed.
fn host_trust_remove_client(rig: &Rig) {
    let (code, value) = rig.host.json(&["trust", "remove", CLIENT_ALIAS, "--json"]);
    assert_eq!(code, 0, "trust remove failed: {value}");
}

fn forward_local_records(rig: &Rig) -> usize {
    rig.host
        .audit_records()
        .iter()
        .filter(|record| record["action"] == "forward.local")
        .count()
}

/// ADR-0023 decision 8 and `docs/CLI.md` §6.9: a removal applies from the
/// peer's next handshake, so a re-establishment after it is rejected at the
/// handshake. The supervisor keeps retrying inside its budget, never gets a
/// carrier, and gives up.
#[test]
fn supervised_forward_peer_that_trust_removed_the_client_rejects_the_reestablishment_handshake() {
    let rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(local_req(echo, 4_000))
        .expect("open the supervised tunnel");
    let id = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.unwrap()).unwrap();
    round_trip(port, b"warm");
    // The audit record lands after the relay; wait for it so the count below
    // is a settled baseline, not a race with the writer.
    let served_before = poll_until("the warm-up's audit record", WAIT, || {
        let n = forward_local_records(&rig);
        (n >= 1).then_some(n)
    });

    host_trust_remove_client(&rig);
    rig.sever();
    let err = hold.hold();

    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert_eq!(lines_of(&id, "gave_up").len(), 1);
    assert_eq!(
        lines_of(&id, "reestablished").len(),
        0,
        "a removed peer must never get a carrier back"
    );
    assert_eq!(
        forward_local_records(&rig),
        served_before,
        "the host never authorized a request on the rejected connection"
    );
}

/// The other half of the same fact (`docs/CLI.md` §6.9, §6.14, README Known
/// limitations): removal does not touch a connection that is already up, so
/// a supervised tunnel on it keeps relaying and never declares a loss.
#[test]
fn supervised_forward_tunnel_on_a_live_connection_keeps_running_after_trust_remove() {
    let rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(local_req(echo, BUDGET_MS))
        .expect("open the supervised tunnel");
    let id = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.unwrap()).unwrap();
    round_trip(port, b"warm");

    host_trust_remove_client(&rig);
    // Fresh TCP connections keep riding the connection that was negotiated
    // before the removal.
    round_trip(port, b"after the removal");
    round_trip(port, b"and again");

    assert!(
        lines_of(&id, "lost").is_empty(),
        "trust remove must not look like a lost carrier: {:?}",
        lines_of(&id, "lost")
    );
    hold.close();
}

// ---------------------------------------------------------------------------
// -R (decisions 7-4, 8, 13)
// ---------------------------------------------------------------------------

fn remote_req(forward_port: u16, supervise_ms: u32) -> TunnelOpenReq {
    TunnelOpenReq {
        mode: "remote".to_string(),
        ..local_req(forward_port, supervise_ms)
    }
}

/// The `reestablished` line whose `previous_tunnel_id` is `previous`. A
/// `-R` tunnel's lines are keyed by the id the peer currently knows it by
/// (decision 13), so the line after a re-issue carries the new one.
fn reestablished_after(previous: &str) -> Value {
    poll_until("the `reestablished` line", WAIT, || {
        captured()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|line| {
                line["supervise"] == "reestablished" && line["previous_tunnel_id"] == previous
            })
            .cloned()
    })
}

#[test]
fn supervised_forward_remote_reissues_before_the_peer_idle_timeout_and_regains_the_same_port() {
    let rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(remote_req(echo, BUDGET_MS))
        .expect("open the supervised -R tunnel");
    let first = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.expect("bound port")).unwrap();
    round_trip(port, b"before");

    // The path dies under the connection; the peer has not noticed yet, so
    // its listener still holds the port when the new connection asks.
    rig.sever();
    let line = reestablished_after(&first);
    round_trip(port, b"after");

    assert_eq!(line["mode"], "remote");
    assert_eq!(line["route"], "forward");
    assert_ne!(line["tunnel_id"], first.as_str(), "{line}");
    // The envelope the holder printed keeps the first id.
    assert_eq!(hold.tunnel().tunnel_id, first);
    assert_eq!(hold.tunnel().actual_port, Some(u32::from(port)));
    hold.close();
}

#[test]
fn supervised_remote_ends_when_another_principal_took_the_port_during_the_outage() {
    let mut rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(remote_req(echo, BUDGET_MS))
        .expect("open the supervised -R tunnel");
    let first = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.expect("bound port")).unwrap();
    round_trip(port, b"before");

    // The host goes away, which frees the port, and someone else binds it
    // before the host comes back.
    rig.kill_serve();
    wait_for(&first, "lost", 1);
    let squatter = TcpListener::bind(("127.0.0.1", port)).expect("the port is free again");
    rig.restart_serve();

    let err = hold.hold();
    drop(squatter);
    assert_eq!(err.code, ErrorCode::ConnectionFailed, "{err:?}");
    assert!(
        captured()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|line| line["supervise"] == "gave_up" && line["tunnel_id"] == first.as_str()),
        "the supervisor reports that it gave up"
    );
}

/// Rewrite the host's `acl.toml` without `forward.remote` and restart the
/// host on its address.
fn restart_without_forward_remote(rig: &mut Rig) {
    rig.kill_serve();
    let acl = rig.host.config_dir().join("acl.toml");
    std::fs::remove_file(&acl).expect("remove the planted acl");
    std::fs::write(
        &acl,
        format!(
            "[[acl]]\nprincipal = \"device:{CLIENT_ALIAS}\"\nallow = [\"exec.run\", \
             \"session.open\", \"session.list\", \"session.attach\", \"session.control\", \
             \"forward.local\"]\n"
        ),
    )
    .expect("write the narrowed acl");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&acl, std::fs::Permissions::from_mode(0o600));
    }
    rig.restart_serve();
}

/// The `forward.remote` twin of the `forward.local` test above: the
/// reissue goes through the peer's ordinary choke point on the new
/// connection, so a peer that restarted with a narrower policy refuses it,
/// the tunnel ends with `PERMISSION_DENIED`, and the peer's audit log holds
/// the deny. No retry storm either.
#[test]
fn supervised_remote_peer_restarted_without_forward_remote_ends_permission_denied_with_one_audit_deny()
 {
    let mut rig = Rig::start();
    let echo = start_echo();
    let hold = rig
        .ops()
        .tunnel_open(remote_req(echo, BUDGET_MS))
        .expect("open the supervised -R tunnel");
    let first = hold.tunnel().tunnel_id.clone();
    let port = u16::try_from(hold.tunnel().actual_port.expect("bound port")).unwrap();
    round_trip(port, b"warm");

    restart_without_forward_remote(&mut rig);
    let err = hold.hold();

    assert_eq!(err.code, ErrorCode::PermissionDenied, "{err:?}");
    let gave_up: Vec<Value> = captured()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|line| line["supervise"] == "gave_up" && line["tunnel_id"] == first.as_str())
        .cloned()
        .collect();
    assert_eq!(gave_up.len(), 1, "{gave_up:?}");
    assert_eq!(gave_up[0]["code"], "PERMISSION_DENIED");
    let denies = settled_denies(&mut rig, "forward.remote");
    assert_eq!(denies.len(), 1, "one deny, no retry storm: {denies:?}");
}
