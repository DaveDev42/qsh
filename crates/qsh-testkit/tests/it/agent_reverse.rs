//! L3 for agent forwarding over the reverse route (ADR-0055 decision 14, DoD
//! 23.3): the target (`qsh serve --to`) is the host, the CLI on the
//! controller is the client, and the `qsh listen` daemon between them only
//! relays. The daemon holds the `agent_channel -> conduit` table and the
//! claim seat; the CLI process connects to its own agent and filters.
//!
//! - `agent_forward_over_the_reverse_route`: a real target host, a real
//!   daemon and a real `Ops` with a `FakeAgent`; a program on the host lists
//!   and signs through `$SSH_AUTH_SOCK`.
//! - `a_reverse_agent_stream_reaches_only_the_cli_that_registered_its_channel`
//!   (decision 22 B47): two CLIs on one daemon, a claimant that knows the
//!   channel but not the seat, a channel nobody registered.
//! - `a_reverse_reattach_registers_its_channel_again`: the same attach, after
//!   the registration is lost and comes back, signs again.
//!
//! The in-process hub rules (seat, cap, sweep) are unit tests in
//! `qsh_core::reverse::listen::agent_hub_tests`.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::acl::AllowAllPinned;
use qsh_core::agent::{AgentEndpoint, ClientAgent};
use qsh_core::localctl::frame::LocalConduit;
use qsh_core::{Paths, Principal};
use qsh_proto::agent::{SSH2_AGENTC_REQUEST_IDENTITIES, encode_message};
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalHello, LocalResponse, LocalStreamKind, local_response,
};
use qsh_proto::wire::{self, control_message};
use qsh_testkit::fake_agent::{FakeAgent, FakeIdentity, identities_answer};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{LocalStream, ReverseHarness, connect_localctl};
use qsh_transport::{Connection, FramedSend, RecvStream, SendStream, StaticTrust};

const TIMEOUT: Duration = Duration::from_secs(20);
const WAIT: Duration = Duration::from_secs(5);

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

fn fresh_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, paths)
}

fn key(name: &str) -> FakeIdentity {
    FakeIdentity::new(
        format!("blob-{name}").into_bytes(),
        format!("comment-{name}"),
    )
}

fn client_agent(fake: &FakeAgent) -> Arc<ClientAgent> {
    ClientAgent::new(AgentEndpoint::resolve(Some(fake.endpoint()), &|_| None))
}

/// A `LOCAL_CONTROL` conduit for `host`, past its `LocalHelloAck`.
async fn connect_control(socket_path: &Path, host: &str) -> LocalConduit<LocalStream> {
    let stream = connect_localctl(socket_path)
        .await
        .expect("connect localctl socket");
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalControl as i32,
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
        .expect("conduit stayed open for the ack");
    assert!(matches!(ack.body, Some(local_response::Body::HelloAck(_))));
    conduit
}

/// A `LOCAL_STREAM` conduit for `host`, past its `LocalHelloAck`, the next
/// frame being the wire `StreamHeader`.
async fn connect_stream(socket_path: &Path, host: &str, wait_ms: u32) -> LocalConduit<LocalStream> {
    let stream = connect_localctl(socket_path)
        .await
        .expect("connect localctl socket");
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalStream as i32,
            host: host.to_string(),
            wait_ms,
            known_generation: None,
        })
        .await
        .expect("send LocalHello");
    let ack: LocalResponse = conduit
        .recv()
        .await
        .expect("recv LocalHelloAck")
        .expect("conduit stayed open for the ack");
    assert!(matches!(ack.body, Some(local_response::Body::HelloAck(_))));
    conduit
}

/// The request a CLI sends when it runs `qsh exec -A` or attaches with `-A`:
/// the channel rides in the request itself.
fn exec_start(channel: &[u8]) -> control_message::Body {
    control_message::Body::ExecStart(wire::ExecStart {
        argv: vec!["true".into()],
        agent_channel: channel.to_vec(),
        ..Default::default()
    })
}

/// Read what the controller relays to the (raw) target until `want` requests
/// that carry an `agent_channel` have arrived; by then the hub has entered
/// them (it does so as a request leaves).
async fn wait_for_agent_requests(ctl: &mut qsh_transport::FramedStream, want: usize) {
    let mut seen = 0;
    let deadline = Instant::now() + TIMEOUT;
    while seen < want {
        let left = deadline.saturating_duration_since(Instant::now());
        let msg = tokio::time::timeout(left, ctl.recv.recv::<wire::ControlMessage>())
            .await
            .expect("the controller relays the request")
            .expect("control stream")
            .expect("control stream open");
        let channel_len = match msg.body {
            Some(control_message::Body::ExecStart(r)) => r.agent_channel.len(),
            Some(control_message::Body::SessionAttach(r)) => r.agent_channel.len(),
            _ => 0,
        };
        if channel_len == wire::AGENT_CHANNEL_LEN {
            seen += 1;
        }
    }
}

// ---- the raw target's side of an AGENT stream -----------------------------

async fn open_agent_stream(host: &Connection, channel: &[u8]) -> (SendStream, RecvStream) {
    let (send, recv) = host.open_bi().await.expect("open_bi");
    let mut framed = FramedSend::data(send);
    framed
        .send(&wire::StreamHeader {
            kind: wire::StreamKind::Agent as i32,
            ticket: channel.to_vec(),
            ..Default::default()
        })
        .await
        .expect("stream header");
    (framed.into_raw(), recv)
}

async fn read_message(recv: &mut RecvStream) -> Option<Vec<u8>> {
    tokio::time::timeout(WAIT, async {
        let mut head = [0u8; 4];
        recv.read_exact(&mut head).await.ok()?;
        let len = u32::from_be_bytes(head) as usize;
        let mut body = vec![0u8; len];
        recv.read_exact(&mut body).await.ok()?;
        let mut all = head.to_vec();
        all.extend_from_slice(&body);
        Some(all)
    })
    .await
    .expect("an answer or a close within the deadline")
}

/// One request, one answer; `None` when the stream ended or was reset.
async fn exchange(send: &mut SendStream, recv: &mut RecvStream, request: &[u8]) -> Option<Vec<u8>> {
    send.write_all(request).await.ok()?;
    read_message(recv).await
}

fn list_request() -> Vec<u8> {
    encode_message(SSH2_AGENTC_REQUEST_IDENTITIES, &[]).unwrap()
}

// ---- B47 ------------------------------------------------------------------

/// ADR-0055 decision 22 B47 (`a_reverse_agent_channel_is_claimed_only_by_its_conduit`
/// is the hub rule, this is the wire): the host opens `AGENT` streams on the
/// registered connection. Two CLIs share the daemon; each stream goes to the
/// CLI whose request carried its channel and to nobody else.
#[tokio::test(flavor = "multi_thread")]
async fn a_reverse_agent_stream_reaches_only_the_cli_that_registered_its_channel() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let socket = localctl.socket_path.clone();
    let (dialed, mut ctl, _hello) = harness
        .register(&target, "widget")
        .await
        .expect("the raw target registers");
    harness.wait_control_hub("widget").await;
    let host_conn = dialed.connection.clone();

    // Two CLI processes, each with its own agent.
    let fake_a = FakeAgent::start(vec![key("a")]).await.unwrap();
    let fake_b = FakeAgent::start(vec![key("b")]).await.unwrap();
    let (cli_a, cli_b) = (client_agent(&fake_a), client_agent(&fake_b));
    let (channel_a, channel_b) = (cli_a.register(), cli_b.register());
    channel_a.serve_over_daemon(socket.clone(), "widget".to_string());
    channel_b.serve_over_daemon(socket.clone(), "widget".to_string());
    let mut control_a = connect_control(&socket, "widget").await;
    let mut control_b = connect_control(&socket, "widget").await;
    control_a
        .send(&wire::ControlMessage::new(
            1,
            exec_start(&channel_a.bytes()),
        ))
        .await
        .unwrap();
    control_b
        .send(&wire::ControlMessage::new(
            1,
            exec_start(&channel_b.bytes()),
        ))
        .await
        .unwrap();
    wait_for_agent_requests(&mut ctl, 2).await;

    // Each channel's stream reaches its own CLI's agent.
    let (mut send, mut recv) = open_agent_stream(&host_conn, &channel_a.bytes()).await;
    let reply = exchange(&mut send, &mut recv, &list_request()).await;
    assert_eq!(reply, Some(identities_answer(&[key("a")])));
    assert_eq!(
        fake_a.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES]
    );
    assert!(fake_b.received_kinds().is_empty());

    let (mut send, mut recv) = open_agent_stream(&host_conn, &channel_b.bytes()).await;
    let reply = exchange(&mut send, &mut recv, &list_request()).await;
    assert_eq!(reply, Some(identities_answer(&[key("b")])));
    assert_eq!(
        fake_a.received_kinds().len(),
        1,
        "a saw only its own stream"
    );
    assert_eq!(fake_b.received_kinds().len(), 1);

    // A third process of the same uid that learned channel A's value claims
    // it with a token of its own. The seat is A's: it is told there is
    // nothing for it, at once, and takes nothing.
    let started = Instant::now();
    let mut thief = connect_stream(&socket, "widget", 4_000).await;
    let mut ticket = channel_a.bytes();
    ticket.extend_from_slice(b"not-the-seated-token");
    thief
        .send(&wire::StreamHeader {
            kind: wire::StreamKind::Agent as i32,
            ticket,
            ..Default::default()
        })
        .await
        .unwrap();
    let answer: LocalResponse = tokio::time::timeout(WAIT, thief.recv())
        .await
        .expect("the claim is answered")
        .expect("framed answer")
        .expect("conduit open");
    match answer.body {
        Some(local_response::Body::Error(err)) => {
            assert_eq!(err.error_code(), qsh_proto::ErrorCode::Timeout)
        }
        other => panic!("expected a framed Timeout, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a claim against someone else's seat must not park"
    );

    // Channel A is still served by A after the attempt, and B never sees A's
    // traffic.
    let (mut send, mut recv) = open_agent_stream(&host_conn, &channel_a.bytes()).await;
    let reply = exchange(&mut send, &mut recv, &list_request()).await;
    assert_eq!(reply, Some(identities_answer(&[key("a")])));
    assert_eq!(fake_a.received_kinds().len(), 2);
    assert_eq!(fake_b.received_kinds().len(), 1);

    // A channel no CLI registered, and one of the wrong length, are reset
    // before any agent is reached.
    let (mut send, mut recv) = open_agent_stream(&host_conn, &[0xEE; 16]).await;
    assert_eq!(exchange(&mut send, &mut recv, &list_request()).await, None);
    let (mut send, mut recv) = open_agent_stream(&host_conn, &[0xEE; 15]).await;
    assert_eq!(exchange(&mut send, &mut recv, &list_request()).await, None);
    assert_eq!(fake_a.received_kinds().len(), 2);
    assert_eq!(fake_b.received_kinds().len(), 1);

    drop((channel_a, channel_b));
    localctl.shutdown().await;
    harness.shutdown().await;
}

/// ADR-0055 decision 10 on the wire: the daemon holds 32 `AGENT` streams per
/// hub. With a CLI registered but its agent never answering, the 33rd stream
/// is reset and the first 32 are not.
#[tokio::test(flavor = "multi_thread")]
async fn the_33rd_reverse_agent_stream_is_reset() {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "widget")).await;
    let (_dir, paths) = fresh_paths();
    let localctl = harness.attach_localctl(&paths).await;
    let socket = localctl.socket_path.clone();
    let (dialed, mut ctl, _hello) = harness
        .register(&target, "widget")
        .await
        .expect("the raw target registers");
    harness.wait_control_hub("widget").await;
    let host_conn = dialed.connection.clone();

    // A registration with no claim loop: nothing drains the queue, so every
    // stream keeps its slot.
    let channel = [0x5c; wire::AGENT_CHANNEL_LEN];
    let mut control = connect_control(&socket, "widget").await;
    control
        .send(&wire::ControlMessage::new(1, exec_start(&channel)))
        .await
        .unwrap();
    wait_for_agent_requests(&mut ctl, 1).await;

    // 33 streams at once. The accept loop takes them concurrently, so which
    // one is refused is not fixed; exactly one is, and it is reset at once
    // while the other 32 wait in the queue for a claimant.
    let mut probes = tokio::task::JoinSet::new();
    for _ in 0..33 {
        let (send, mut recv) = open_agent_stream(&host_conn, &channel).await;
        probes.spawn(async move {
            let _keep_open = send;
            let mut buf = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(1500), recv.read(&mut buf)).await {
                Ok(Err(_)) => true,
                Ok(Ok(_)) => panic!("a queued agent stream received bytes with no claimant"),
                Err(_elapsed) => false,
            }
        });
    }
    let mut refused = 0;
    while let Some(done) = probes.join_next().await {
        if done.expect("probe task") {
            refused += 1;
        }
    }
    assert_eq!(refused, 1, "exactly the stream over the cap is reset");

    localctl.shutdown().await;
    harness.shutdown().await;
}

// ---- probe-driven end to end ----------------------------------------------

mod end_to_end {
    use super::*;

    use base64::Engine as _;
    use qsh_core::{ExecStdin, Fingerprint, Ops, RecoveryConfig, SessionAttachStream};
    use qsh_proto::event::SessionEvent;
    use qsh_proto::{EnvVar, ExecRunReq, IdentityInitReq, KeyStoreMode};
    use qsh_proto::{SessionAttachReq, SessionOpenReq};
    use qsh_testkit::agent_probe::{self, hex};
    use qsh_testkit::fake_agent::sign_response;
    use qsh_testkit::{ChaosPolicy, ChaosProxy};

    /// The messages the program on the host sends: list, then sign `blob-a`
    /// over `data-to-sign`. The probe prints both answers as hex.
    fn program_messages() -> Vec<String> {
        vec![
            "11".into(),
            agent_probe::sign_arg(b"blob-a", b"data-to-sign"),
        ]
    }

    async fn blocking<T: Send + 'static>(
        ops: &Ops,
        f: impl FnOnce(&Ops) -> T + Send + 'static,
    ) -> T {
        let ops = ops.clone();
        tokio::task::spawn_blocking(move || f(&ops))
            .await
            .expect("spawn_blocking join")
    }

    async fn fresh_ops() -> (tempfile::TempDir, Ops, Fingerprint) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
            .with_runtime_dir(dir.path().join("run"));
        let ops = Ops::new(paths);
        let data = blocking(&ops, |ops| {
            ops.identity_init(IdentityInitReq {
                key_store: Some(KeyStoreMode::File),
                ..Default::default()
            })
        })
        .await
        .expect("identity.init");
        let fingerprint = data
            .fingerprint
            .parse::<Fingerprint>()
            .expect("fingerprint");
        (dir, ops, fingerprint)
    }

    /// DoD 23.3: a program on the host, run by `qsh exec -A` through the
    /// daemon, lists and signs through the forwarded socket, and the answers
    /// are the CLI-side agent's.
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_forward_over_the_reverse_route() {
        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "revhost"))
                .await;
        let (_ops_dir, ops, _fp) = fresh_ops().await;
        let localctl = harness.attach_localctl(ops.paths()).await;
        let fake = FakeAgent::start(vec![key("a")]).await.unwrap();
        let ops = ops.with_client_agent(client_agent(&fake));

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run_fut = harness.run_target(&target, "device-id", "controller", None, async {
            let _ = shutdown_rx.await;
        });
        let test_fut = async {
            harness.wait_control_hub("revhost").await;
            let out = tokio::time::timeout(
                TIMEOUT,
                blocking(&ops, |ops| {
                    ops.exec_run(
                        ExecRunReq {
                            host: "revhost".into(),
                            argv: agent_probe::call_argv(&program_messages()),
                            env: vec![],
                            timeout_ms: Some(15_000),
                        },
                        ExecStdin::Closed,
                    )
                }),
            )
            .await
            .expect("exec.run finishes")
            .expect("exec.run over the reverse route");
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            assert_eq!(out.data.agent.as_deref(), Some("forwarded"), "{stdout}");
            assert_eq!(out.data.remote_exit_code, 0, "the program failed: {stdout}");
            let lines: Vec<&str> = stdout.lines().collect();
            assert_eq!(lines.len(), 2, "{stdout}");
            assert_eq!(lines[0], hex(&identities_answer(&[key("a")])[4..]));
            assert_eq!(
                lines[1],
                hex(&sign_response(b"blob-a", b"data-to-sign")[4..])
            );
            assert_eq!(fake.received_kinds(), vec![11, 13]);
            let _ = shutdown_tx.send(());
        };
        let (result, ()) = tokio::join!(run_fut, test_fut);
        result.expect("run_target exits cleanly");
        localctl.shutdown().await;
        harness.shutdown().await;
    }

    /// One identity request through the session's socket, printed with a tag
    /// the typed line itself does not contain (the probe builds `AGENT<n>:`).
    fn shell_list(n: u32) -> String {
        agent_probe::shell_tagged_call(&n.to_string(), &["11".to_string()])
    }

    /// The shell a session runs, and the line ending that submits a command
    /// typed into it.
    #[cfg(unix)]
    const SHELL: &[&str] = &["sh"];
    #[cfg(unix)]
    const EOL: &str = "\n";
    #[cfg(windows)]
    const SHELL: &[&str] = &["cmd.exe", "/q"];
    #[cfg(windows)]
    const EOL: &str = "\r\n";

    fn read_until(stream: &mut SessionAttachStream, seen: &mut String, needle: &str) {
        while let Some(event) = stream.next_event() {
            match event.unwrap_or_else(|err| panic!("attach stream failed: {err}")) {
                SessionEvent::Output { data_b64, .. } => {
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(data_b64.as_bytes())
                        .expect("session output is Base64");
                    seen.push_str(&String::from_utf8_lossy(&data));
                    if seen.contains(needle) {
                        return;
                    }
                }
                SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => {
                    panic!("the session ended before {needle:?}; saw {seen:?}")
                }
                _ => {}
            }
        }
        panic!("the attach stream ended before {needle:?}; saw {seen:?}");
    }

    /// DoD 23.3 with ADR-0055 decision 9: an `-A` attach on the reverse route
    /// lists through the session's socket, the registration is cut and comes
    /// back, and the same attach (the recovery sends the same channel in its
    /// `SessionAttach`) lists again. The claim loop outlives the first
    /// registration; the new hub enters the channel from the recovery's
    /// request.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reverse_reattach_registers_its_channel_again() {
        let target = make_identity();
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, "revhost"))
                .await;
        let chaos = ChaosProxy::start(harness.addr, ChaosPolicy::seeded(0xA6E_2E7))
            .await
            .expect("bind chaos proxy in front of the controller");
        let config = qsh_core::config::Config {
            reverse: qsh_core::config::ReverseConfig {
                backoff_initial_ms: Some(5),
                backoff_max_ms: Some(20),
                backoff_jitter_pct: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run_fut = harness.run_target_through_chaos(
            &target,
            "device-id",
            "controller",
            None,
            &config,
            &chaos,
            |_runtime| {},
            async {
                let _ = shutdown_rx.await;
            },
        );

        let scenario = async {
            let first = qsh_testkit::reverse::wait_for(TIMEOUT, || {
                harness.listen.registry().get("revhost")
            })
            .await;
            let baseline = first.generation;
            harness.wait_control_hub("revhost").await;

            let (_ops_dir, ops, _fp) = fresh_ops().await;
            let localctl = harness.attach_localctl(ops.paths()).await;
            let fake = FakeAgent::start(vec![key("a")]).await.unwrap();
            let ops = ops
                .with_client_agent(client_agent(&fake))
                .with_recovery(RecoveryConfig {
                    migration: false,
                    ..RecoveryConfig::default()
                });

            let (sever_tx, sever_rx) = tokio::sync::oneshot::channel::<()>();
            let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
            let answer = hex(&identities_answer(&[key("a")])[4..]);
            let handle = tokio::task::spawn_blocking(move || {
                // Opened and attached with `-A`: the open makes the socket,
                // the attach backs it.
                let session_ref = ops
                    .session_open(SessionOpenReq {
                        host: "revhost".into(),
                        argv: SHELL.iter().map(|a| (*a).to_string()).collect(),
                        env: vec![
                            EnvVar {
                                name: "LANG".into(),
                                value: "C".into(),
                            },
                            EnvVar {
                                name: "PS1".into(),
                                value: String::new(),
                            },
                        ],
                        term: Some("xterm-256color".into()),
                        cols: Some(80),
                        rows: Some(24),
                        user: None,
                        shell_command: None,
                    })
                    .expect("session.open")
                    .session_ref;
                let mut stream = ops
                    .session_attach(
                        SessionAttachReq {
                            session_ref: session_ref.clone(),
                            no_steal: false,
                        },
                        &[],
                    )
                    .expect("session.attach");
                assert_eq!(stream.agent_outcome(), Some("forwarded"));
                let mut seen = String::new();
                stream
                    .write(format!("{}{EOL}", shell_list(1)).into_bytes())
                    .expect("write");
                read_until(&mut stream, &mut seen, &format!("AGENT1:{answer}"));

                sever_tx.send(()).ok();
                done_rx.recv().expect("the async side severed the path");

                // Typed into a session whose path is already dead; it runs
                // after the recovery, and the socket has its backing again.
                stream
                    .write(format!("{}{EOL}", shell_list(2)).into_bytes())
                    .expect("write");
                read_until(&mut stream, &mut seen, &format!("AGENT2:{answer}"));
                stream.close();
            });

            sever_rx.await.expect("the first listing came back");
            chaos.sever().await;
            done_tx.send(()).ok();
            tokio::time::timeout(Duration::from_secs(90), handle)
                .await
                .expect("the scenario finishes")
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));

            let after = qsh_testkit::reverse::wait_for(TIMEOUT, || {
                let e = harness.listen.registry().get("revhost")?;
                (e.generation > baseline).then_some(e)
            })
            .await;
            assert!(after.generation > baseline);
            assert_eq!(fake.received_kinds(), vec![11, 11]);

            localctl.shutdown().await;
            let _ = shutdown_tx.send(());
        };
        let ((), result) = tokio::join!(scenario, run_fut);
        result.expect("run_target exits cleanly after a sever");
        harness.shutdown().await;
    }
}
