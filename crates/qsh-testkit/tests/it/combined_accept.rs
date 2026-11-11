//! L3 acceptance for the combined endpoint (ADR-0059 DoD 27.3): one `qsh
//! listen --serve` shaped endpoint on real loopback UDP, with a reverse
//! target registered on it, serves a second machine's forward features on the
//! same port while the first machine's localctl carries the reverse route to
//! the target, all at the same time.
//!
//! ```text
//!   laptop (Ops) --QUIC--> box (CombinedHarness) <--QUIC-- widget (qsh serve --to)
//!       |   |                  ^   |
//!       |   +-- localctl ------+   +--UDP--> far (-J target)
//!       +------ -J box ----------------------^
//! ```
//!
//! Every party is real and talks over real loopback UDP. The endpoint is the
//! harness the other `combined_*` files use (a `Server` in front, a `Listen`
//! attached, one set of shared parts); its localctl daemon is the production
//! one, bound over the endpoint's own `Listen`. The forward sessions of `box`
//! are the broker's pipe-backed ones (no PTY), the reverse target `widget` is
//! the production `run_reverse_observed` with a real PTY.

use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::agent::{AgentEndpoint, ClientAgent};
use qsh_core::config::{AuditConfig, Config, Paths};
use qsh_core::quota::QuotaLimits;
use qsh_core::reverse::target::run_reverse_observed;
use qsh_core::{CancelToken, ExecStdin, Fingerprint, Ops, SilentObserver};
use qsh_proto::{
    FileCopyReq, IdentityInitReq, KeyStoreMode, SessionCloseReq, SessionOpenReq, SessionReadReq,
    SessionWriteReq, TrustAddReq, TunnelDynamicReq, TunnelOpenReq,
};
use qsh_testkit::agent_probe::{self, hex};
use qsh_testkit::combined::CombinedHarness;
use qsh_testkit::fake_agent::{FakeAgent, FakeIdentity, identities_answer};
use qsh_testkit::loopback::make_identity;
use qsh_testkit::net_probe::{self, Gap, LanEcho, free_port};
use qsh_testkit::reverse::{loaded_identity, wait_for};
use qsh_testkit::tunnel::{EchoServer, echo_exchange};
use qsh_transport::{Principal, StaticTrust};

use super::jump_chain::{
    blocking, blocking_named, echo_argv, echo_through, every_feature_with, exec, loopback_options,
    shutdown as shutdown_hosts, start_hosts, stdout_of,
};

/// A client machine: its `Ops` (with a private runtime directory, so its
/// localctl discovery sees only this test's daemon) and its fingerprint.
pub(super) struct Client {
    _dir: tempfile::TempDir,
    pub(super) paths: Paths,
    pub(super) ops: Ops,
    pub(super) fp: Fingerprint,
}

pub(super) async fn client() -> Client {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(
        dir.path().join("client/config"),
        dir.path().join("client/state"),
    )
    .with_runtime_dir(dir.path().join("client/run"));
    let ops = Ops::new(paths.clone());
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
    let fp: Fingerprint = init.fingerprint.parse().expect("fingerprint");
    Client {
        _dir: dir,
        paths,
        ops,
        fp,
    }
}

pub(super) async fn pin(ops: &Ops, name: &str, address: String, fingerprint: Fingerprint) {
    let ops = ops.clone();
    let name = name.to_string();
    blocking(move || {
        ops.trust_add(TrustAddReq {
            name,
            address: Some(address),
            fingerprint: Some(fingerprint.to_string()),
            cert_pem: None,
            role: None,
        })
    })
    .await
    .expect("trust.add");
}

/// The target machine's own config: it pins the endpoint as `ctl` with role
/// `full`, so the endpoint's requests are authorized by the role.
pub(super) fn target_paths(
    dir: &std::path::Path,
    endpoint: std::net::SocketAddr,
    fp: Fingerprint,
) -> Paths {
    let paths = Paths::new(dir.join("target/config"), dir.join("target/state"));
    std::fs::create_dir_all(&paths.config_dir).expect("target config dir");
    std::fs::write(
        paths.trust_file(),
        format!(
            "[[peer]]\nname = \"ctl\"\nfingerprint = \"{fp}\"\naddress = \"{endpoint}\"\n\
             added_at = \"2026-11-11T00:00:00Z\"\nrole = \"full\"\n"
        ),
    )
    .expect("write target trust.toml");
    paths
}

// ----------------------------------------------------------------------
// the features of the second machine, on the endpoint's forward side
// ----------------------------------------------------------------------

/// `qsh -t box 'cmd'`: the command string reaches the host as a shell
/// request, not as an argv.
async fn t_command(ops: &Ops, h: &CombinedHarness) {
    let opened = {
        let ops = ops.clone();
        blocking_named("session.open with a shell command", move || {
            ops.session_open(SessionOpenReq {
                host: "box".into(),
                argv: vec![],
                env: vec![],
                term: Some("xterm-256color".into()),
                cols: Some(80),
                rows: Some(24),
                user: None,
                shell_command: Some("echo t-command".into()),
            })
        })
        .await
        .expect("session.open -t")
    };
    let (spec, _pipe) = h
        .pipes
        .take_with_spec()
        .expect("the host made the session of the -t command");
    assert!(spec.argv.is_empty(), "{spec:?}");
    assert_eq!(
        spec.shell,
        Some(qsh_core::shell::ShellRequest::Command(
            "echo t-command".into()
        ))
    );
    let ops = ops.clone();
    blocking(move || {
        ops.session_close(SessionCloseReq {
            session_ref: opened.session_ref,
            signal: None,
        })
    })
    .await
    .expect("session.close");
}

/// `-R`: a connection to the port the endpoint bound comes back out of the
/// laptop's echo server.
async fn remote_forward(ops: &Ops) {
    let echo = EchoServer::start().await.expect("echo server");
    let echo_port = echo.port();
    let bound_port = free_port();
    let ops = ops.clone();
    let got = blocking_named("-R tunnel and echo", move || {
        let hold = ops
            .tunnel_open(TunnelOpenReq {
                host: "box".into(),
                mode: "remote".into(),
                bind: None,
                listen_port: u32::from(bound_port),
                forward_host: "127.0.0.1".into(),
                forward_port: u32::from(echo_port),
                wait_ms: None,
                supervise_ms: None,
                accept_hold_ms: None,
            })
            .expect("open the -R tunnel");
        let port = hold
            .tunnel()
            .actual_port
            .expect("the endpoint reports the port it bound");
        let payload: Vec<u8> = (0..96 * 1024).map(|i| (i % 249) as u8).collect();
        let got = echo_through(u16::try_from(port).expect("port"), &payload)
            .expect("a round trip through -R");
        hold.close();
        (payload, got)
    })
    .await;
    assert!(got.0 == got.1, "the -R echo came back different");
}

/// `-D`: a SOCKS5 CONNECT to a non-loopback destination (the listener always
/// asks the host to refuse host-local ones). The step needs such an address;
/// off CI a machine without one skips it, on CI that is a failure.
async fn dynamic_forward(ops: &Ops) {
    let ip = match net_probe::require_non_loopback_v4("no usable non-loopback address").await {
        Gap::Ready(ip) => ip,
        Gap::Skip(reason) => {
            eprintln!("skipping the -D step: {reason}");
            return;
        }
        Gap::Fail(reason) => panic!("the -D step: {reason}"),
    };
    let lan = LanEcho::start(ip).await.expect("bind a lan echo");
    let dest = lan.addr();
    let socks_port = free_port();
    let ops = ops.clone();
    let got = blocking_named("-D tunnel and echo", move || {
        use std::io::{Read, Write};
        let hold = ops
            .tunnel_dynamic(TunnelDynamicReq {
                host: "box".into(),
                bind: None,
                listen_port: u32::from(socks_port),
                supervise_ms: None,
                accept_hold_ms: None,
            })
            .expect("open the -D listener");
        let port = hold
            .dynamic_tunnel()
            .actual_port
            .unwrap_or(u32::from(socks_port));
        let mut sock = std::net::TcpStream::connect(("127.0.0.1", u16::try_from(port).unwrap()))
            .expect("connect to the -D listener");
        sock.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        sock.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0u8; 2];
        sock.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);
        let std::net::SocketAddr::V4(v4) = dest else {
            panic!("an IPv4 destination")
        };
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&v4.ip().octets());
        request.extend_from_slice(&v4.port().to_be_bytes());
        sock.write_all(&request).unwrap();
        let mut reply = [0u8; 10];
        sock.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0x00, "CONNECT through -D: {reply:?}");
        let payload = b"-D through the combined endpoint".to_vec();
        let got = echo_exchange(sock, &payload, Duration::from_secs(20)).expect("the echo");
        hold.close();
        (payload, got)
    })
    .await;
    assert_eq!(got.0, got.1, "the -D echo came back different");
}

/// `-A`: a program on the endpoint's machine lists the keys of the laptop's
/// agent through the forwarded socket.
async fn agent_forward(ops: &Ops) {
    let key = FakeIdentity::new(b"combined-key".to_vec(), "comment-never-logged");
    let fake = FakeAgent::start(vec![key.clone()])
        .await
        .expect("fake agent");
    let agent = ClientAgent::new(AgentEndpoint::resolve(Some(fake.endpoint()), &|_| None));
    let ops = ops.clone().with_client_agent(agent);
    let argv = agent_probe::call_argv(&["11".to_string()]);
    let out = blocking_named("-A exec", move || {
        ops.exec_run(
            qsh_proto::ExecRunReq {
                host: "box".into(),
                argv,
                env: vec![],
                timeout_ms: Some(30_000),
            },
            ExecStdin::Closed,
        )
    })
    .await
    .expect("exec -A");
    assert_eq!(out.data.remote_exit_code, 0);
    let lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(
        lines,
        vec![hex(&identities_answer(std::slice::from_ref(&key))[4..])]
    );
    assert_eq!(
        fake.received_kinds(),
        vec![11],
        "the list reached the agent"
    );
}

/// Everything the second machine does on the endpoint as a host.
async fn forward_features(ops: &Ops, h: &CombinedHarness) {
    t_command(ops, h).await;
    // exec, a PTY session, -L and a cp, on the end connection.
    every_feature_with(ops, "box", &h.pipes, "forward").await;
    remote_forward(ops).await;
    dynamic_forward(ops).await;
    agent_forward(ops).await;
}

// ----------------------------------------------------------------------
// the features of the first machine's localctl, on the reverse route
// ----------------------------------------------------------------------

/// A session, an exec and a cp on `widget`, which only the registration
/// reaches. The target has a real PTY.
async fn reverse_features(ops: &Ops) {
    // exec
    let out = exec(ops, "widget", echo_argv("exec-reverse"))
        .await
        .expect("exec over the reverse route");
    assert_eq!(out.data.remote_exit_code, 0);
    assert!(
        stdout_of(&out).contains("exec-reverse"),
        "{}",
        stdout_of(&out)
    );

    // a PTY session: what the shell prints reaches the laptop
    let opened = {
        let ops = ops.clone();
        blocking_named("session.open over the reverse route", move || {
            ops.session_open(SessionOpenReq {
                host: "widget".into(),
                argv: vec![],
                env: vec![],
                term: Some("xterm-256color".into()),
                cols: Some(80),
                rows: Some(24),
                user: None,
                shell_command: None,
            })
        })
        .await
        .expect("session.open over the reverse route")
    };
    let session_ref = opened.session_ref.clone();
    {
        use base64::Engine as _;
        let ops = ops.clone();
        let session_ref = session_ref.clone();
        let line = if cfg!(windows) {
            "echo reverse-session\r\n"
        } else {
            "echo reverse-$((20+22))\n"
        };
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(line.as_bytes());
        blocking_named("session.write over the reverse route", move || {
            ops.session_write(SessionWriteReq {
                session_ref,
                data_b64,
            })
        })
        .await
        .expect("session.write over the reverse route");
    }
    let needle = if cfg!(windows) {
        "reverse-session"
    } else {
        "reverse-42"
    };
    let mut seen = Vec::new();
    let mut after = 0u64;
    let mut ctl_after = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !String::from_utf8_lossy(&seen).contains(needle) {
        assert!(
            std::time::Instant::now() < deadline,
            "the shell's output never reached the laptop: {:?}",
            String::from_utf8_lossy(&seen)
        );
        let ops = ops.clone();
        let session_ref = session_ref.clone();
        let read = blocking_named("session.read over the reverse route", move || {
            ops.session_read(SessionReadReq {
                session_ref,
                after_sequence: after,
                wait_ms: Some(2_000),
                limit_bytes: None,
                ctl_after,
            })
        })
        .await
        .expect("session.read over the reverse route");
        seen.extend_from_slice(&read.output);
        after = read.data.next_after;
        ctl_after = Some(read.data.next_ctl_after);
    }
    {
        let ops = ops.clone();
        blocking(move || {
            ops.session_close(SessionCloseReq {
                session_ref,
                signal: None,
            })
        })
        .await
        .expect("session.close over the reverse route");
    }

    // qsh cp, both ways, and the BLAKE3 of the file survives
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.bin");
    let there = dir.path().join("there.bin");
    let back = dir.path().join("back.bin");
    let bytes: Vec<u8> = (0..400 * 1024).map(|i| (i % 247) as u8).collect();
    std::fs::write(&source, &bytes).expect("write the source");
    for (from, to) in [
        (
            source.to_string_lossy().into_owned(),
            format!("[widget]:{}", there.display()),
        ),
        (
            format!("[widget]:{}", there.display()),
            back.to_string_lossy().into_owned(),
        ),
    ] {
        let ops = ops.clone();
        let data = blocking_named("cp over the reverse route", move || {
            ops.file_copy(
                FileCopyReq {
                    sources: vec![from],
                    destination: to,
                    recursive: false,
                    preserve: false,
                    no_clobber: false,
                },
                Arc::new(SilentObserver),
                &CancelToken::new(),
            )
        })
        .await
        .unwrap_or_else(|err| panic!("cp over the reverse route: {err:?}"));
        assert_eq!(data.files, 1, "{data:?}");
    }
    let want = blake3::hash(&bytes);
    assert_eq!(blake3::hash(&std::fs::read(&there).expect("the put")), want);
    assert_eq!(blake3::hash(&std::fs::read(&back).expect("the get")), want);
}

// ----------------------------------------------------------------------
// the test
// ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn combined_endpoint_serves_registration_and_forward_at_once() {
    let c = client().await;
    let widget = make_identity();
    let dir = tempfile::tempdir().expect("tempdir");

    // `far` is only reachable through the endpoint: the `-J` target.
    let far = start_hosts(&["far"], c.fp, |_| "*", loopback_options()).await;

    // The endpoint: both roles on one socket, one set of parts.
    let trust = StaticTrust::empty()
        .with_pin(c.fp, Principal::Device("laptop".into()))
        .with_pin(widget.fingerprint, Principal::Device("widget".into()));
    let h = CombinedHarness::start(Arc::new(AllowAllPinned), trust, QuotaLimits::default()).await;
    // Every `-J` target of the tests is on loopback.
    h.server.set_jump_options(loopback_options());
    let host_paths = Paths::new(dir.path().join("box/config"), dir.path().join("box/state"));
    h.server
        .set_file_host(host_paths.clone(), AuditConfig::default());
    h.server.set_agent_runtime_dir(dir.path().join("box/run"));

    pin(&c.ops, "box", h.addr.to_string(), h.host.fingerprint).await;
    pin(
        &c.ops,
        "far",
        far[0].h.addr.to_string(),
        far[0].h.server_identity.fingerprint,
    )
    .await;

    // The endpoint's localctl daemon, over the same `Listen`, in the
    // laptop's runtime directory: the reverse route of `widget`.
    let localctl = {
        use qsh_core::localctl::daemon::{LocalctlDaemon, LocalctlListener};
        let bound = LocalctlListener::bind(&c.paths, std::process::id()).expect("bind localctl");
        let daemon = LocalctlDaemon::new(h.listen.clone());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = rx.await;
        }));
        (tx, task)
    };

    // The reverse target registers on the endpoint's port.
    let t_paths = target_paths(dir.path(), h.addr, h.host.fingerprint);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let target_config = Config::default();
    let run_target = run_reverse_observed(
        &t_paths,
        &target_config,
        loaded_identity(&widget, "widget-device"),
        "ctl",
        Some("widget"),
        |_runtime| {},
        || {},
        async move {
            let _ = stop_rx.await;
        },
    );

    let test = async {
        wait_for(Duration::from_secs(30), || h.listen.control_hub("widget")).await;

        // All three at the same time: the forward features of the laptop on
        // `box`, the same features on `far` through `box` as the hop, and
        // the reverse route to `widget` through the localctl daemon.
        let through_box = c.ops.clone().with_jump(vec!["box".to_string()]);
        let all = async {
            tokio::join!(
                forward_features(&c.ops, &h),
                every_feature_with(&through_box, "far", &far[0].h.pipes, "jump"),
                reverse_features(&c.ops),
            )
        };
        tokio::time::timeout(Duration::from_secs(240), all)
            .await
            .expect("the three feature sets did not finish in time");

        // The target kept its registration through all of it, and the
        // endpoint's one audit sink holds the records of every branch.
        assert!(
            h.listen.control_hub("widget").is_some(),
            "the registration survived the forward traffic"
        );
        let records = h.audit.records();
        let has = |action: &str, principal: &str| {
            records.iter().any(|r| {
                r.action == action && r.decision == "allow" && r.principal.contains(principal)
            })
        };
        assert!(has("host.reverse", "widget"), "registration: {records:#?}");
        for action in [
            "session.open",
            "exec.run",
            "forward.local",
            "forward.remote",
            "forward.agent",
            "forward.jump",
            "file.write",
        ] {
            assert!(has(action, "laptop"), "{action}: {records:#?}");
        }
        // `far` saw the laptop itself, not the hop.
        assert!(
            far[0]
                .h
                .audit
                .records()
                .iter()
                .any(|r| r.principal.contains("laptop")),
            "the target of the chain audits the client"
        );
        let _ = stop_tx.send(());
    };

    let (target_result, ()) = tokio::join!(run_target, test);
    target_result.expect("the reverse target exits cleanly on shutdown");
    let (stop_localctl, task) = localctl;
    let _ = stop_localctl.send(());
    let _ = task.await;
    h.shutdown().await;
    shutdown_hosts(far).await;
}
