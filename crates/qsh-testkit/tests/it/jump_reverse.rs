//! L3 for a jump chain whose first hop is a reverse registration on this
//! machine (ADR-0056 decision 14, DoD 25.10): the first hop is a real
//! `qsh serve --to` host registered with a real `qsh listen` daemon, the end
//! target is a loopback host reached by J's real UDP socket, and the CLI
//! (`Ops` with `with_jump`) reaches J only through the daemon.
//!
//! ```text
//!   CLI ==LOCAL_STREAM (stream carrier)== daemon ==registered QUIC== J --UDP-- T
//! ```
//!
//! - `jump_first_hop_over_the_reverse_route`: a session, an exec and a `-L`
//!   tunnel end on T, and the registered-connection leg ends up on the
//!   datagram carrier in both directions.
//! - `a_reverse_first_hop_with_another_fingerprint_opens_nothing`: the
//!   registration is checked against the pin before the header leaves.
//! - the daemon's own bounds and cleanup, driven by hand over
//!   `LOCAL_STREAM`: a channel value claimed once, the 32 channels per host,
//!   a frame of 0 or over 1452 bytes, a CLI that goes away, a host without
//!   `jump.v1`.
//!
//! The authorization of `forward.jump` is J's, as for a directly reached
//! intermediate peer; the daemon test of that rule is that the daemon never
//! decides it (the CLI's header reaches J unchanged, `jump_stats().opened`).

use std::future::Future;
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use qsh_core::acl::AllowAllPinned;
use qsh_core::config::{Config, Paths};
use qsh_core::jump::{CloseReason, JumpOptions};
use qsh_core::localctl::frame::LocalConduit;
use qsh_core::reverse::listen::ControlHub;
use qsh_core::server::Server;
use qsh_core::{ExecStdin, Fingerprint, OpError, Ops};
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalHello, LocalResponse, LocalStreamKind, local_response,
};
use qsh_proto::wire::{self, ConnectResult, StreamKind};
use qsh_proto::{
    ErrorCode, ExecRunReq, IdentityInitReq, KeyStoreMode, SessionOpenReq, SessionReadReq,
    SessionWriteReq, TrustAddReq, TunnelOpenReq,
};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_testkit::net_probe::free_port;
use qsh_testkit::reverse::{
    DataStream, LocalStream, ReverseHarness, connect_localctl, into_data_conduit, reverse_hello,
    wait_for,
};
use qsh_testkit::tunnel::EchoServer;
use qsh_transport::{Principal, StaticTrust};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const TIMEOUT: Duration = Duration::from_secs(30);
const SCENARIO_LIMIT: Duration = Duration::from_secs(120);

fn rel() -> Ordering {
    Ordering::Relaxed
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::time::timeout(SCENARIO_LIMIT, tokio::task::spawn_blocking(f)).await {
        Ok(joined) => joined.expect("blocking task"),
        Err(_) => panic!("a blocking step did not finish within {SCENARIO_LIMIT:?}"),
    }
}

/// Options for J: it reaches T on loopback, so the host-local filter is
/// off; `max_channels_per_conn` is raised by the tests that fill the
/// daemon's 32 before J's own 16.
fn j_options(max_channels_per_conn: usize) -> JumpOptions {
    JumpOptions {
        allow_host_local: true,
        max_channels_per_conn,
        ..JumpOptions::default()
    }
}

/// What a scenario sees.
struct Ctx {
    _dir: tempfile::TempDir,
    ops: Ops,
    socket: PathBuf,
    hub: Arc<ControlHub>,
    j: Arc<Server>,
    t: LoopbackHarness,
}

/// Which fingerprint the client pins J under.
#[derive(Clone, Copy)]
enum JPin {
    Real,
    Wrong,
}

/// A controller with a `qsh listen` daemon, J registered with it as `jrev`,
/// T on loopback, and a client `Ops` that pins both. `body` gets the
/// context and hands it back for the teardown.
async fn scenario<F, Fut>(options: JumpOptions, j_pin: JPin, body: F)
where
    F: FnOnce(Ctx) -> Fut,
    Fut: Future<Output = Ctx>,
{
    let target = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        StaticTrust::empty().with_pin(target.fingerprint, Principal::Device("jrev".into())),
    )
    .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    let init = blocking({
        let ops = ops.clone();
        move || {
            ops.identity_init(IdentityInitReq {
                key_store: Some(KeyStoreMode::File),
                ..Default::default()
            })
        }
    })
    .await
    .expect("identity.init");
    let client: Fingerprint = init.fingerprint.parse().expect("fingerprint");
    let localctl = harness.attach_localctl(ops.paths()).await;

    let t = LoopbackHarness::start_custom(
        Arc::new(AllowAllPinned),
        make_identity(),
        StaticTrust::empty().with_pin(client, Principal::Device("laptop".into())),
    )
    .await;
    pin(
        &ops,
        "t",
        Some(t.addr.to_string()),
        t.server_identity.fingerprint,
    )
    .await;
    let j_fingerprint = match j_pin {
        JPin::Real => target.fingerprint,
        JPin::Wrong => make_identity().fingerprint,
    };
    // J has no address in the client's pin: the daemon holds its connection.
    pin(&ops, "jrev", None, j_fingerprint).await;

    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let config = Config::default();
    let run = harness.run_target_with_config_observing_runtime(
        &target,
        "device-id",
        "controller",
        None,
        &config,
        move |runtime| {
            let _ = server_tx.send(runtime.server.clone());
        },
        async {
            let _ = shutdown_rx.await;
        },
    );
    let scene = async {
        let hub = harness.wait_control_hub("jrev").await;
        let j = wait_for(TIMEOUT, || server_rx.try_recv().ok()).await;
        j.set_jump_options(options);
        let ctx = Ctx {
            _dir: dir,
            ops,
            socket: localctl.socket_path.clone(),
            hub,
            j,
            t,
        };
        let ctx = tokio::time::timeout(SCENARIO_LIMIT, body(ctx))
            .await
            .expect("the scenario finished");
        ctx.t.shutdown().await;
        let _ = shutdown_tx.send(());
    };
    let (result, ()) = tokio::join!(run, scene);
    result.expect("run_target exits cleanly");
    localctl.shutdown().await;
    harness.shutdown().await;
}

async fn pin(ops: &Ops, name: &str, address: Option<String>, fingerprint: Fingerprint) {
    let (ops, name) = (ops.clone(), name.to_string());
    blocking(move || {
        ops.trust_add(TrustAddReq {
            name,
            address,
            fingerprint: Some(fingerprint.to_string()),
            cert_pem: None,
            role: None,
        })
    })
    .await
    .expect("trust.add");
}

fn echo_argv(text: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["sh".into(), "-c".into(), format!("echo {text}")]
    }
    #[cfg(windows)]
    {
        vec!["cmd".into(), "/c".into(), format!("echo {text}")]
    }
}

async fn exec(
    ops: &Ops,
    host: &str,
    argv: Vec<String>,
) -> Result<qsh_core::ExecRunOutput, OpError> {
    let (ops, host) = (ops.clone(), host.to_string());
    blocking(move || {
        ops.exec_run(
            ExecRunReq {
                host,
                argv,
                env: vec![],
                timeout_ms: Some(30_000),
            },
            ExecStdin::Closed,
        )
    })
    .await
}

/// One round trip through a `-L` listener: write `payload`, half-close, read
/// the echo to the end.
fn echo_through(listen_port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], listen_port)),
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let data = payload.to_vec();
    let writing = std::thread::spawn(move || {
        writer.write_all(&data)?;
        writer.shutdown(Shutdown::Write)
    });
    let mut got = Vec::new();
    stream.read_to_end(&mut got)?;
    writing.join().expect("writer thread")?;
    Ok(got)
}

// ----------------------------------------------------------------------
// DoD 25.10
// ----------------------------------------------------------------------

/// A session and an exec through a chain whose first hop is a reverse
/// registration run on T, and the leg between the daemon and the registered
/// host takes the datagram carrier in both directions once the registered
/// connection's room opens (decision 4 applied to the daemon's own outer
/// connection).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_first_hop_over_the_reverse_route() {
    scenario(j_options(16), JPin::Real, |ctx| async move {
        let ops = ctx.ops.clone().with_jump(vec!["jrev".into()]);

        // exec
        let out = exec(&ops, "t", echo_argv("exec-rev"))
            .await
            .expect("exec through the registered first hop");
        assert_eq!(out.data.remote_exit_code, 0);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("exec-rev"),
            "{:?}",
            String::from_utf8_lossy(&out.stdout)
        );

        // a PTY session: T's side is the test's pipe.
        let opened = {
            let (ops, host) = (ops.clone(), "t".to_string());
            blocking(move || {
                ops.session_open(SessionOpenReq {
                    host,
                    argv: vec!["sh".into()],
                    env: vec![],
                    term: Some("xterm-256color".into()),
                    cols: Some(80),
                    rows: Some(24),
                    user: None,
                    shell_command: None,
                })
            })
            .await
            .expect("session.open through the registered first hop")
        };
        let mut pipe = ctx.t.pipes.take().expect("T's side of the session");
        pipe.write_output(b"hello-rev").await.expect("output");
        let read = {
            let (ops, session_ref) = (ops.clone(), opened.session_ref.clone());
            blocking(move || {
                ops.session_read(SessionReadReq {
                    session_ref,
                    after_sequence: 0,
                    wait_ms: Some(10_000),
                    limit_bytes: None,
                    ctl_after: None,
                })
            })
            .await
            .expect("session.read")
        };
        assert_eq!(String::from_utf8_lossy(&read.output), "hello-rev");
        {
            use base64::Engine as _;
            let (ops, session_ref) = (ops.clone(), opened.session_ref.clone());
            let b64 = base64::engine::general_purpose::STANDARD.encode(b"typed-rev");
            blocking(move || {
                ops.session_write(SessionWriteReq {
                    session_ref,
                    data_b64: b64,
                })
            })
            .await
            .expect("session.write");
            let got = pipe.read_input(64).await.expect("input");
            assert_eq!(got, b"typed-rev");
        }

        // -L to an echo server on T's machine, repeated until the daemon's
        // leg has used datagrams both ways: the registered connection starts
        // at the 1200-byte MTU, whose room cannot hold a minimum-size inner
        // packet, and PLPMTUD opens it under this traffic.
        let echo = EchoServer::start().await.expect("echo server");
        let echo_port = echo.port();
        let listen_port = free_port();
        let payload: Vec<u8> = (0..400 * 1024).map(|i| (i % 251) as u8).collect();
        let started = Instant::now();
        let hold = {
            let (ops, host) = (ops.clone(), "t".to_string());
            blocking(move || {
                ops.tunnel_open(TunnelOpenReq {
                    host,
                    mode: "local".into(),
                    bind: None,
                    listen_port: u32::from(listen_port),
                    forward_host: "127.0.0.1".into(),
                    forward_port: u32::from(echo_port),
                    wait_ms: None,
                    supervise_ms: None,
                    accept_hold_ms: None,
                })
            })
            .await
            .expect("open the -L tunnel through the registered first hop")
        };
        loop {
            let expected = payload.clone();
            let sent = payload.clone();
            let got = blocking(move || echo_through(listen_port, &sent))
                .await
                .expect("a round trip through -L");
            assert!(got == expected, "the echo came back different");
            let daemon = ctx.hub.jump_stats();
            let j = ctx.j.jump_stats();
            if daemon.to_host_datagrams.load(rel()) > 0
                && daemon.from_host_datagrams.load(rel()) > 0
                && j.to_target_datagrams.load(rel()) > 0
                && j.to_client_datagrams.load(rel()) > 0
            {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the registered leg never took the datagram carrier: daemon sent {} / got {}, \
                 J got {} / sent {}",
                daemon.to_host_datagrams.load(rel()),
                daemon.from_host_datagrams.load(rel()),
                j.to_target_datagrams.load(rel()),
                j.to_client_datagrams.load(rel()),
            );
        }
        blocking(move || hold.close()).await;

        // The CLI leg carried frames, and the daemon's counters add up to
        // channels that all ended.
        let daemon = ctx.hub.jump_stats();
        assert!(daemon.to_cli.load(rel()) > 0);
        assert!(daemon.opened.load(rel()) >= 3, "exec, session and tunnel");
        assert!(ctx.j.jump_stats().opened.load(rel()) >= 3);
        ctx
    })
    .await;
}

/// The registration behind the first hop is compared with its pin before the
/// `JUMP` request leaves: a different fingerprint is `AUTH_FAILED` naming
/// hop 1, and neither the daemon nor J opens anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reverse_first_hop_with_another_fingerprint_opens_nothing() {
    scenario(j_options(16), JPin::Wrong, |ctx| async move {
        let ops = ctx.ops.clone().with_jump(vec!["jrev".into()]);
        let err = exec(&ops, "t", echo_argv("never"))
            .await
            .expect_err("the pin does not match the registration");
        assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
        assert_eq!(err.details["jump"]["stage"], "auth", "{err:?}");
        assert_eq!(err.details["jump"]["hop"], 1, "{err:?}");
        assert_eq!(ctx.hub.jump_stats().opened.load(rel()), 0);
        assert_eq!(ctx.j.jump_stats().opened.load(rel()), 0);
        assert_eq!(ctx.hub.jump_channels_in_use(), 0);
        ctx
    })
    .await;
}

// ----------------------------------------------------------------------
// the daemon's bounds and cleanup, by hand over LOCAL_STREAM
// ----------------------------------------------------------------------

async fn connect_stream(socket: &Path, host: &str) -> LocalConduit<LocalStream> {
    let stream = connect_localctl(socket).await.expect("connect localctl");
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalStream as i32,
            host: host.to_string(),
            wait_ms: 0,
            known_generation: None,
        })
        .await
        .expect("send LocalHello");
    let ack: LocalResponse = conduit
        .recv()
        .await
        .expect("recv LocalHelloAck")
        .expect("the conduit stayed open");
    assert!(
        matches!(ack.body, Some(local_response::Body::HelloAck(_))),
        "{ack:?}"
    );
    conduit
}

/// An open `JUMP` channel as a CLI process would hold it: the answer and the
/// raw conduit behind it.
struct Channel {
    result: ConnectResult,
    raw: DataStream,
}

fn jump_header(channel: &[u8], port: u16) -> wire::StreamHeader {
    wire::StreamHeader {
        kind: StreamKind::Jump as i32,
        ticket: channel.to_vec(),
        host: "127.0.0.1".into(),
        port: u32::from(port),
        deny_host_local: false,
    }
}

async fn open_channel(socket: &Path, host: &str, header: &wire::StreamHeader) -> Channel {
    let mut conduit = connect_stream(socket, host).await;
    conduit.send(header).await.expect("send the JUMP header");
    let mut data = into_data_conduit(conduit);
    let result: ConnectResult = tokio::time::timeout(TIMEOUT, data.recv())
        .await
        .expect("the daemon answers")
        .expect("a framed ConnectResult")
        .expect("the conduit stayed open for the answer");
    let (raw, residue) = data.into_raw();
    assert!(residue.is_empty());
    Channel { result, raw }
}

fn channel_id(n: u8) -> [u8; 16] {
    [n; 16]
}

/// An endpoint that is not listening: J only needs a socket to `connect`.
fn quiet_port() -> u16 {
    free_port()
}

/// The channel value is the daemon's table key, so it is claimed once, and a
/// value that is not 16 bytes never reaches the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_claims_a_jump_channel_once_and_refuses_a_malformed_one() {
    scenario(j_options(16), JPin::Real, |ctx| async move {
        let port = quiet_port();
        let bad = open_channel(&ctx.socket, "jrev", &jump_header(&[7u8; 5], port)).await;
        assert!(!bad.result.ok);
        assert_eq!(bad.result.code, ErrorCode::InvalidArgument.as_str());
        assert_eq!(
            ctx.j.jump_stats().opened.load(rel()),
            0,
            "nothing reached J"
        );
        assert_eq!(ctx.hub.jump_channels_in_use(), 0);

        let first = open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(1), port)).await;
        assert!(first.result.ok, "{:?}", first.result);
        assert_eq!(ctx.hub.jump_channels_in_use(), 1);
        let again = open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(1), port)).await;
        assert!(!again.result.ok);
        assert_eq!(again.result.code, ErrorCode::InvalidArgument.as_str());
        assert_eq!(
            ctx.j.jump_stats().opened.load(rel()),
            1,
            "the duplicate never left the daemon"
        );

        // The value is free again once its channel ends.
        drop(first);
        wait_for(TIMEOUT, || {
            (ctx.hub.jump_channels_in_use() == 0).then_some(())
        })
        .await;
        let reused = open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(1), port)).await;
        assert!(reused.result.ok, "{:?}", reused.result);
        drop(reused);
        drop(again);
        ctx
    })
    .await;
}

/// The daemon carries 32 channels per registered host (decision 14); the
/// 33rd is `RESOURCE_EXHAUSTED` from the daemon before anything is opened
/// toward the host, and a slot freed by a closed channel is usable again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_carries_at_most_32_jump_channels_per_registered_host() {
    scenario(j_options(64), JPin::Real, |ctx| async move {
        let port = quiet_port();
        let mut open = Vec::new();
        for n in 1..=32u8 {
            let channel =
                open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(n), port)).await;
            assert!(channel.result.ok, "channel {n}: {:?}", channel.result);
            open.push(channel);
        }
        assert_eq!(ctx.hub.jump_channels_in_use(), 32);
        assert_eq!(ctx.j.jump_stats().opened.load(rel()), 32);

        let over = open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(33), port)).await;
        assert!(!over.result.ok);
        assert_eq!(over.result.code, ErrorCode::ResourceExhausted.as_str());
        assert_eq!(
            ctx.j.jump_stats().opened.load(rel()),
            32,
            "the refusal came from the daemon"
        );

        drop(open.pop());
        wait_for(TIMEOUT, || {
            (ctx.hub.jump_channels_in_use() == 31).then_some(())
        })
        .await;
        let fits = open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(33), port)).await;
        assert!(fits.result.ok, "{:?}", fits.result);
        drop(fits);
        drop(open);
        wait_for(TIMEOUT, || {
            (ctx.hub.jump_channels_in_use() == 0).then_some(())
        })
        .await;
        ctx
    })
    .await;
}

/// A CLI-leg frame of length 0 or over 1452 ends the channel: the daemon
/// resets the stream toward the host, closes the conduit, and frees its slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_frame_from_the_cli_ends_the_channel_and_frees_its_slot() {
    scenario(j_options(16), JPin::Real, |ctx| async move {
        let port = quiet_port();
        for (n, length) in [(1u8, 0u16), (2, 1453), (3, u16::MAX)] {
            let mut channel =
                open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(n), port)).await;
            assert!(channel.result.ok);
            channel
                .raw
                .write_all(&length.to_be_bytes())
                .await
                .expect("write the length prefix");
            // The conduit ends: the daemon read the prefix and gave up.
            let mut rest = Vec::new();
            let read = tokio::time::timeout(TIMEOUT, channel.raw.read_to_end(&mut rest))
                .await
                .expect("the daemon closes the conduit");
            assert!(
                read.is_ok() && rest.is_empty(),
                "length {length}: {read:?} {rest:?}"
            );
            wait_for(TIMEOUT, || {
                (ctx.hub.jump_channels_in_use() == 0 && ctx.j.jump_stats().live() == 0)
                    .then_some(())
            })
            .await;
        }
        let closed = ctx.j.jump_stats().close_reasons();
        assert_eq!(closed.len(), 3, "{closed:?}");
        assert!(
            closed.iter().all(|r| *r == CloseReason::StreamEnd),
            "J saw the stream die: {closed:?}"
        );
        ctx
    })
    .await;
}

/// A CLI that goes away (its process dies, the conduit closes) takes its
/// channel with it on both sides: the host's socket and slot, the daemon's
/// slot and datagram registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_cleans_up_when_the_cli_goes_away() {
    scenario(j_options(16), JPin::Real, |ctx| async move {
        let port = quiet_port();
        let channels: Vec<Channel> = {
            let mut v = Vec::new();
            for n in 1..=4u8 {
                v.push(open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(n), port)).await);
            }
            v
        };
        assert!(channels.iter().all(|c| c.result.ok));
        assert_eq!(ctx.hub.jump_channels_in_use(), 4);
        assert_eq!(ctx.j.jump_stats().live(), 4);

        drop(channels);

        wait_for(TIMEOUT, || {
            (ctx.hub.jump_channels_in_use() == 0 && ctx.j.jump_stats().live() == 0).then_some(())
        })
        .await;
        let closed = ctx.j.jump_stats().close_reasons();
        assert_eq!(closed.len(), 4, "{closed:?}");
        assert!(closed.iter().all(|r| *r == CloseReason::StreamEnd));
        assert_eq!(ctx.hub.jump_stats().closed.load(rel()), 4);
        // And the daemon's datagram table forgot the channels: the values
        // are claimable again.
        let again = open_channel(&ctx.socket, "jrev", &jump_header(&channel_id(1), port)).await;
        assert!(again.result.ok);
        drop(again);
        ctx
    })
    .await;
}

/// A refusal of J (here: a role without `forward.jump` is not set up, so
/// the refusal is the target-name shape check) comes back to the CLI as J
/// wrote it, and the daemon holds nothing afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_of_the_host_reaches_the_cli_verbatim_and_frees_the_slot() {
    scenario(j_options(16), JPin::Real, |ctx| async move {
        let mut header = jump_header(&channel_id(9), 1);
        header.host = "bad host\u{7}name".into();
        let refused = open_channel(&ctx.socket, "jrev", &header).await;
        assert!(!refused.result.ok);
        assert_eq!(refused.result.code, ErrorCode::InvalidArgument.as_str());
        assert_eq!(ctx.j.jump_stats().opened.load(rel()), 0);
        drop(refused);
        wait_for(TIMEOUT, || {
            (ctx.hub.jump_channels_in_use() == 0).then_some(())
        })
        .await;
        ctx
    })
    .await;
}

/// A registered host that never advertised `jump.v1` gets no `JUMP` stream:
/// the daemon answers `UNSUPPORTED` itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registered_host_without_jump_v1_gets_no_jump_stream() {
    let target = make_identity();
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        StaticTrust::empty().with_pin(target.fingerprint, Principal::Device("old".into())),
    )
    .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let localctl = harness.attach_localctl(&paths).await;
    let mut hello = reverse_hello("old");
    hello.capabilities.retain(|c| c != wire::CAP_JUMP_V1);
    let (_dialed, _ctl, _peer) = harness
        .initiate(&target, hello)
        .await
        .expect("registration without jump.v1");
    harness.wait_control_hub("old").await;

    let refused = open_channel(
        &localctl.socket_path,
        "old",
        &jump_header(&channel_id(1), 9),
    )
    .await;
    assert!(!refused.result.ok);
    assert_eq!(refused.result.code, ErrorCode::Unsupported.as_str());
    drop(refused);
    localctl.shutdown().await;
    harness.shutdown().await;
}
