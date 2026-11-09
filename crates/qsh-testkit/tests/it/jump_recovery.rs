//! Recovery, migration and `--supervise` through a jump chain (ADR-0056
//! decision 16; DoD 25.9).
//!
//! The chain is one unit. Every party is real and talks over real loopback
//! UDP; the cuts are a [`ChaosProxy`] in front of a hop:
//!
//! ```text
//!   C ==QUIC== [proxy A] == J ==UDP== [proxy B] == T
//! ```
//!
//! The client pins `j` at proxy A's address, so cutting A is cutting the C-J
//! link. J gets T's address from the client's pin (the `JUMP` request names
//! it), so pinning `t` at proxy B's address puts B on J's UDP path to T.
//!
//! Every test asserts an invariant (the bytes the PTY's side received are
//! exactly the bytes typed, once each), not a packet trace.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use qsh_core::client::Session;
use qsh_core::jump::{HopPin, JumpPlan};
use qsh_core::{Ops, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{SessionAttachReq, SessionOpenReq, TunnelOpenReq};
use qsh_testkit::chaos::{ChaosPolicy, ChaosProxy};
use qsh_testkit::net_probe::free_port;
use qsh_testkit::tunnel::EchoServer;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use super::jump_chain::{Direct, Net, blocking, close, loopback_options};

/// A hang is a failure, not a flake.
const SCENARIO_LIMIT: Duration = Duration::from_secs(120);

/// How long the cut lasts (DoD 25.9).
const CUT: Duration = Duration::from_secs(5);

// ----------------------------------------------------------------------
// recovery telemetry
// ----------------------------------------------------------------------

fn recovery_lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

fn capture_recovery_records() {
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
        if event.metadata().target() != qsh_core::telemetry::TARGET {
            return;
        }
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        if !line.is_empty() {
            recovery_lines()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line);
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

/// The `recovery` word of every record of `session_ref`, in order.
fn records_for(session_ref: &str) -> Vec<String> {
    recovery_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            (value["session_ref"].as_str() == Some(session_ref))
                .then(|| value["recovery"].as_str().unwrap_or_default().to_string())
        })
        .collect()
}

// ----------------------------------------------------------------------
// the rig
// ----------------------------------------------------------------------

/// Which link of `C - J - T` is cut.
#[derive(Clone, Copy, Debug)]
enum Cut {
    /// C to J: the first hop's connection.
    ClientToJ,
    /// J to T: the middle peer's UDP socket toward the target.
    JToTarget,
}

/// A client, `j` and `t`, with a chaos proxy on the link `cut` names.
struct Rig {
    net: Net,
    proxy: Arc<ChaosProxy>,
}

impl Rig {
    async fn start(cut: Cut, seed: u64) -> Self {
        let net = Net::start_unpinned(&["j", "t"], |_| "*", loopback_options()).await;
        let (j, t) = (net.host("j"), net.host("t"));
        let proxy = match cut {
            Cut::ClientToJ => ChaosProxy::start(j.h.addr, ChaosPolicy::seeded(seed)).await,
            Cut::JToTarget => ChaosProxy::start(t.h.addr, ChaosPolicy::seeded(seed)).await,
        }
        .expect("chaos proxy");
        let (j_addr, t_addr) = match cut {
            Cut::ClientToJ => (proxy.addr(), t.h.addr),
            Cut::JToTarget => (j.h.addr, proxy.addr()),
        };
        net.pin(
            "j",
            Some(j_addr.to_string()),
            j.h.server_identity.fingerprint,
        )
        .await;
        net.pin(
            "t",
            Some(t_addr.to_string()),
            t.h.server_identity.fingerprint,
        )
        .await;
        Self {
            net,
            proxy: Arc::new(proxy),
        }
    }

    fn ops(&self) -> Ops {
        self.net.via(&["j"])
    }

    async fn shutdown(self) {
        self.net.shutdown().await;
    }
}

fn open_and_attach(ops: &Ops) -> (String, SessionAttachStream) {
    let opened = ops
        .session_open(SessionOpenReq {
            host: "t".into(),
            argv: vec!["sh".into()],
            env: vec![],
            term: Some("xterm-256color".into()),
            cols: Some(80),
            rows: Some(24),
            user: None,
            shell_command: None,
        })
        .expect("session.open through the chain");
    let stream = ops
        .session_attach(
            SessionAttachReq {
                session_ref: opened.session_ref.clone(),
                no_steal: false,
            },
            &[],
        )
        .expect("session.attach through the chain");
    (opened.session_ref, stream)
}

/// Lines typed, and lines the host prints, in the scenario below.
const LINES: usize = 90;
/// Pause between two lines. 90 lines span about 9 s: the cut lands inside
/// and recovery has traffic on both sides of it.
const LINE_GAP: Duration = Duration::from_millis(100);
/// When the cut begins, from the first line.
const CUT_AT: Duration = Duration::from_secs(2);

fn input_line(i: usize) -> String {
    format!("in-{i:04}\n")
}

fn output_line(i: usize) -> String {
    format!("out-{i:04}\r\n")
}

/// A PTY session through the chain while `proxy` is cut for [`CUT`]: the
/// chain is rebuilt, the same session resumes, and every line typed reaches
/// the host once, in order, while every line the host printed reaches the
/// client once, in order (L4).
async fn session_survives_a_cut(cut: Cut, seed: u64) {
    capture_recovery_records();
    let rig = Rig::start(cut, seed).await;
    let ctx = rig.proxy.context();
    let ops = rig.ops();

    let (session_ref, stream) = blocking({
        let ops = ops.clone();
        move || open_and_attach(&ops)
    })
    .await;
    let mut host = rig.net.host("t").h.pipes.take().expect("the host's side");

    let handle = stream.handle();
    let mut stream = stream;
    let started = Instant::now();

    // The host side: print the numbered lines, collect what arrives.
    let host_task = tokio::spawn(async move {
        let mut got = Vec::new();
        let want: usize = (0..LINES).map(|i| input_line(i).len()).sum();
        let mut next_out = 0usize;
        let mut next_at = Instant::now();
        let end = Instant::now() + SCENARIO_LIMIT;
        while got.len() < want && Instant::now() < end {
            if next_out < LINES && Instant::now() >= next_at {
                host.write_output(output_line(next_out).as_bytes())
                    .await
                    .expect("output");
                next_out += 1;
                next_at += LINE_GAP;
            }
            if let Ok(Ok(chunk)) =
                tokio::time::timeout(Duration::from_millis(20), host.read_input(4096)).await
            {
                got.extend_from_slice(&chunk);
            }
        }
        while next_out < LINES {
            host.write_output(output_line(next_out).as_bytes())
                .await
                .expect("output");
            next_out += 1;
        }
        got
    });

    // The typist: one thread, one line per gap.
    let typist = std::thread::spawn({
        let handle = handle.clone();
        move || {
            for i in 0..LINES {
                handle
                    .write(input_line(i).into_bytes())
                    .expect("queue the input");
                std::thread::sleep(LINE_GAP);
            }
        }
    });

    // The cut, in the middle of it.
    let cutter = {
        let proxy = Arc::clone(&rig.proxy);
        tokio::spawn(async move {
            tokio::time::sleep(CUT_AT).await;
            proxy.blackhole(CUT).await;
        })
    };

    // The reader: output until the last line is in. The stream stays open
    // until the typist has finished, so no queued line meets a closed attach.
    let last = output_line(LINES - 1);
    let j_stats = Arc::clone(rig.net.host("j").h.server.jump_stats());
    let (output, stream) = blocking(move || {
        let mut seen = Vec::new();
        let deadline = Instant::now() + SCENARIO_LIMIT;
        while Instant::now() < deadline {
            let Some(event) = stream.next_event() else {
                break;
            };
            match event.unwrap_or_else(|err| panic!("the attach failed: {err}")) {
                SessionEvent::Output { data_b64, .. } => {
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(data_b64.as_bytes())
                        .expect("session output is Base64");
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen).contains(&last) {
                        break;
                    }
                }
                SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => break,
                _ => {}
            }
        }
        (seen, stream)
    })
    .await;
    blocking(move || typist.join().expect("typist")).await;
    cutter.await.expect("cutter");
    let elapsed = started.elapsed();

    let got = tokio::time::timeout(Duration::from_secs(30), host_task)
        .await
        .unwrap_or_else(|_| panic!("the host never got every line — {ctx}"))
        .expect("host task");

    // The old chain is gone, not kept beside the new one: J carries the new
    // chain's channel only (decision 16).
    let live = blocking(move || {
        let settle = Instant::now() + Duration::from_secs(10);
        while j_stats.live() > 1 && Instant::now() < settle {
            std::thread::sleep(Duration::from_millis(50));
        }
        let live = j_stats.live();
        stream.close();
        live
    })
    .await;
    assert!(live <= 1, "J still carries {live} channels — {ctx}");
    let want_in: String = (0..LINES).map(input_line).collect();
    let want_out: String = (0..LINES).map(output_line).collect();
    assert_eq!(
        String::from_utf8_lossy(&got),
        want_in,
        "input must arrive once and in order — {ctx}"
    );
    assert_eq!(
        String::from_utf8_lossy(&output),
        want_out,
        "output must arrive once and in order — {ctx}"
    );
    let records = records_for(&session_ref);
    eprintln!("{cut:?}: {records:?}, whole run {elapsed:?}");
    assert!(
        records.iter().any(|r| r == "resumed"),
        "the chain was rebuilt and the session resumed: {records:?} — {ctx}"
    );
    // The chain was rebuilt: the middle peer carried a second channel.
    let opened = rig
        .net
        .host("j")
        .h
        .server
        .jump_stats()
        .opened
        .load(Ordering::Relaxed);
    assert!(opened >= 3, "J opened {opened} channels — {ctx}");
    rig.shutdown().await;
}

/// DoD 25.9: the C-J link is cut for 5 s, recovery rebuilds the chain and
/// resumes the same session, and the input is lossless and duplicate-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_through_a_jump_resumes_after_the_hop_link_dies() {
    session_survives_a_cut(Cut::ClientToJ, 0x4A55_0001).await;
}

/// A cut on the middle peer's UDP to the target recovers the same way: the
/// inner connection dies on its path, the end connection's watch declares
/// it dead, and the chain is rebuilt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_through_a_jump_resumes_after_the_target_link_dies() {
    session_survives_a_cut(Cut::JToTarget, 0x4A55_0002).await;
}

// ----------------------------------------------------------------------
// migration
// ----------------------------------------------------------------------

/// DoD 25.9: rebinding C's socket migrates the first hop and the inner
/// connection does not notice. Same end connection, no second channel, the
/// middle peer's socket toward the target unchanged (the target sees the
/// same peer address before and after).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outer_migration_is_invisible_to_the_inner_connection() {
    let d = Direct::start(&["j", "t"]).await;
    // A proxy on each link, to see who talks to whom: A on C-J, B on J-T.
    let (j, t) = (d.host("j"), d.host("t"));
    let a = ChaosProxy::start(j.h.addr, ChaosPolicy::seeded(0x4A55_0010))
        .await
        .expect("proxy A");
    let b = ChaosProxy::start(t.h.addr, ChaosPolicy::seeded(0x4A55_0011))
        .await
        .expect("proxy B");
    let at = |host: &super::jump_chain::Host, addr: std::net::SocketAddr| HopPin {
        name: host.name.clone(),
        address: addr.to_string(),
        fingerprint: host.h.server_identity.fingerprint,
    };
    let plan = JumpPlan::new(
        vec![at(j, a.addr())],
        at(t, b.addr()),
        None,
        "laptop".into(),
    )
    .expect("a plan");
    let chain = d.dial(&plan, Duration::from_secs(10)).await.expect("chain");
    let mut session = Session::negotiate(chain.connection.clone(), "laptop")
        .await
        .expect("hello with the end");
    session.session_list().await.expect("a round trip");

    let a_before = a.flows().await;
    let b_before = b.flows().await;
    assert_eq!(a_before.len(), 1, "{a_before:?}");
    assert_eq!(b_before.len(), 1, "{b_before:?}");
    let id_before = chain.connection.stable_id();

    // The end endpoint's rebind moves the first hop's socket.
    let new_local = chain
        .endpoint
        .rebind_ephemeral()
        .expect("the chain's endpoint rebinds through the first hop");
    eprintln!("first hop rebound to {new_local}");

    // The end connection works over it, and the first hop now arrives from
    // a second client address.
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        session.session_list().await.expect("the chain still works");
        let now = a.flows().await;
        if now.len() == 2 {
            break;
        }
        assert!(Instant::now() < end, "the first hop never moved: {now:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(chain.connection.close_reason().is_none());
    assert_eq!(chain.connection.stable_id(), id_before);
    // J's socket toward the target is the same one: B has its one flow,
    // from the same address, and J opened no second channel.
    assert_eq!(b.flows().await, b_before, "the target saw a change");
    assert_eq!(
        j.h.server.jump_stats().opened.load(Ordering::Relaxed),
        1,
        "no second channel: the inner connection was not rebuilt"
    );
    session.session_list().await.expect("still alive");
    drop(session);
    close(chain).await;
    d.shutdown().await;
}

/// The endpoint of a chain with a middle hop moves the outermost socket too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nested_endpoint_never_binds_a_socket_of_its_own() {
    let d = Direct::start(&["a", "b", "t"]).await;
    let plan = d.plan(&["a", "b", "t"]);
    let chain = d.dial(&plan, Duration::from_secs(15)).await.expect("chain");
    assert!(chain.endpoint.is_nested());
    let mut session = Session::negotiate(chain.connection.clone(), "laptop")
        .await
        .expect("hello with the end");
    chain
        .endpoint
        .rebind_ephemeral()
        .expect("through two layers to the first hop");
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        match session.session_list().await {
            Ok(_) => break,
            Err(err) if Instant::now() > end => panic!("the chain died after a rebind: {err:?}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    drop(session);
    close(chain).await;
    d.shutdown().await;
}

// ----------------------------------------------------------------------
// --supervise
// ----------------------------------------------------------------------

fn echo_once(port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Write as _};
    use std::net::{Shutdown, SocketAddr, TcpStream};
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(payload)?;
    stream.shutdown(Shutdown::Write)?;
    let mut got = Vec::new();
    stream.read_to_end(&mut got)?;
    Ok(got)
}

/// A `--supervise` `-L` tunnel through a chain whose C-J link is cut: once
/// the link is back the supervisor's redial has rebuilt the chain and a
/// round trip goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_supervised_tunnel_through_a_chain_survives_a_cut() {
    supervised_tunnel_survives(Cut::ClientToJ, false, 0x4A55_0003).await;
}

/// The same with the middle peer's UDP to the target cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_supervised_tunnel_through_a_chain_survives_a_cut_behind_the_hop() {
    supervised_tunnel_survives(Cut::JToTarget, false, 0x4A55_0004).await;
}

/// The C-J path is cut for good, but C's address can change: the death
/// verdict's migration step rebinds the first hop's socket (decision 16, tier
/// 1) and the very same chain carries the tunnel on, without a second
/// `JUMP`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_supervised_tunnel_migrates_at_the_first_hop_and_keeps_its_chain() {
    supervised_tunnel_survives(Cut::ClientToJ, true, 0x4A55_0005).await;
}

async fn supervised_tunnel_survives(cut: Cut, sever: bool, seed: u64) {
    let rig = Rig::start(cut, seed).await;
    let ctx = rig.proxy.context();
    let ops = rig.ops();
    let echo = EchoServer::start().await.expect("echo server");
    let echo_port = echo.port();
    let listen_port = free_port();
    let cut_started = Arc::new(AtomicBool::new(false));
    let proxy = Arc::clone(&rig.proxy);
    let flag = cut_started.clone();
    let ctx_in = ctx.clone();
    let recovered_after = blocking(move || {
        let ctx = ctx_in;
        let hold = ops
            .tunnel_open(TunnelOpenReq {
                host: "t".into(),
                mode: "local".into(),
                bind: None,
                listen_port: u32::from(listen_port),
                forward_host: "127.0.0.1".into(),
                forward_port: u32::from(echo_port),
                wait_ms: None,
                supervise_ms: Some(300_000),
                accept_hold_ms: None,
            })
            .expect("open the supervised -L tunnel through the chain");
        let payload = vec![0x5au8; 64 * 1024];
        assert_eq!(
            echo_once(listen_port, &payload).expect("a round trip before the cut"),
            payload
        );

        // The cut: a runtime-free thread asks the proxy through a tiny
        // runtime of its own.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let started = Instant::now();
        if sever {
            rt.block_on(proxy.sever());
        } else {
            rt.block_on(proxy.blackhole(CUT));
        }
        flag.store(true, Ordering::SeqCst);
        let deadline = started + Duration::from_secs(60);
        loop {
            match echo_once(listen_port, &payload) {
                Ok(got) if got == payload => break,
                Ok(_) | Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(250));
                }
                Ok(got) => panic!("a short echo ({} bytes) — {ctx}", got.len()),
                Err(err) => panic!("no round trip within 60 s of the cut: {err} — {ctx}"),
            }
        }
        let after = started.elapsed();
        hold.close();
        after
    })
    .await;
    assert!(cut_started.load(Ordering::SeqCst));
    eprintln!("first round trip after the cut: {recovered_after:?}");
    // A chain was built again: the middle peer carried more than the first.
    let opened = rig
        .net
        .host("j")
        .h
        .server
        .jump_stats()
        .opened
        .load(Ordering::Relaxed);
    if sever {
        assert_eq!(opened, 1, "the chain was rebuilt, not migrated — {ctx}");
    } else {
        assert!(opened >= 2, "J opened {opened} channels — {ctx}");
    }
    rig.shutdown().await;
}
