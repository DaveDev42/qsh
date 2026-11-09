//! L3/L4 end to end for agent forwarding (ADR-0055 DoD 23.1, 23.4, 23.5):
//! a real client [`Ops`] with forwarding on, pointed at a [`FakeAgent`] it was
//! given explicitly (never the process `SSH_AUTH_SOCK`), against a real host.
//!
//! The host is a [`LoopbackHarness`] whose authorizer comes from a sandbox
//! `trust.toml` that pins the `Ops` identity with role `full`. The program on
//! the host is a small `python3` script (the test skips with a message when
//! `python3` is missing) or, where only a connect matters, the test itself.
//! A session in this harness is pipe-backed, so there the program is started
//! by the test with `SSH_AUTH_SOCK` set to the socket the host made.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::acl::{Authorizer, Role, load_or_deny};
use qsh_core::agent::{AgentEndpoint, ClientAgent};
use qsh_core::config::Paths;
use qsh_core::trust::SharedTrustStore;
use qsh_core::{ExecRunOutput, ExecStdin, Fingerprint, Ops, RecoveryConfig, SessionAttachStream};
use qsh_proto::agent::{
    FAILURE_REPLY, SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST, encode_message,
};
use qsh_proto::{
    ExecRunReq, IdentityInitReq, KeyStoreMode, SessionAttachReq, SessionOpenReq, TrustAddReq,
};
use qsh_testkit::chaos::{ChaosPolicy, DelayDist};
use qsh_testkit::fake_agent::{
    FakeAgent, FakeIdentity, identities_answer, sign_request_body, sign_response,
};
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_transport::{Principal, StaticTrust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::punch_route::{WorldOptions, world};

const CHALLENGE: &[u8] = b"challenge-bytes";

/// A key a fake agent lists, named by `blob`.
fn key(blob: &str) -> FakeIdentity {
    FakeIdentity::new(blob.as_bytes().to_vec(), "comment-never-logged")
}

/// The program on the host: connect to `$SSH_AUTH_SOCK` and send, one after
/// the other on one connection, a list (11), a sign (13, request body in
/// `argv[1]` as hex) and a remove-all (19). Prints each reply (without the
/// length prefix) as a hex line.
const PROGRAM: &str = r#"
import os, socket, struct, sys
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ["SSH_AUTH_SOCK"])
def rd(n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SystemExit(3)
        b += c
    return b
def call(msg):
    s.sendall(struct.pack(">I", len(msg)) + msg)
    (n,) = struct.unpack(">I", rd(4))
    print(rd(n).hex(), flush=True)
call(bytes([11]))
call(bytes([13]) + bytes.fromhex(sys.argv[1]))
call(bytes([19]))
"#;

fn have_python() -> bool {
    let found = std::process::Command::new("python3")
        .arg("-c")
        .arg("import socket")
        .status()
        .is_ok_and(|s| s.success());
    if !found {
        eprintln!("skipping: python3 is not available to act as the program on the host");
    }
    found
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What `PROGRAM` must print for an agent that lists `key`: the list answer,
/// the signature, and the `FAILURE` the client gave the remove-all itself.
fn expected_lines(key: &FakeIdentity) -> Vec<String> {
    vec![
        hex(&identities_answer(std::slice::from_ref(key))[4..]),
        hex(&sign_response(&key.blob, CHALLENGE)[4..]),
        hex(&FAILURE_REPLY[4..]),
    ]
}

fn sign_body_hex(key: &FakeIdentity) -> String {
    hex(&sign_request_body(&key.blob, CHALLENGE, 0))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("blocking task")
}

fn client_agent(fake: &FakeAgent) -> Arc<ClientAgent> {
    ClientAgent::new(AgentEndpoint::resolve(Some(fake.endpoint()), &|_| None))
}

/// A real `Ops` and the host it is pinned to.
struct Rig {
    _dir: tempfile::TempDir,
    /// The client with no agent; derive agent-forwarding ones from it. All
    /// share one identity and one resume-token store.
    ops: Ops,
    h: LoopbackHarness,
    runtime: PathBuf,
}

impl Rig {
    async fn start(chaos: Option<ChaosPolicy>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(
            dir.path().join("client/config"),
            dir.path().join("client/state"),
        )
        .with_runtime_dir(dir.path().join("client/run"));
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
        let fp: Fingerprint = init.fingerprint.parse().expect("fingerprint");

        let host_paths = Paths::new(
            dir.path().join("host/config"),
            dir.path().join("host/state"),
        );
        std::fs::create_dir_all(&host_paths.config_dir).expect("host config dir");
        std::fs::write(
            host_paths.trust_file(),
            format!(
                "[[peer]]\nname = \"laptop\"\nfingerprint = \"{fp}\"\naddress = \"\"\n\
                 added_at = \"2026-11-09T00:00:00Z\"\nrole = \"full\"\n"
            ),
        )
        .expect("write trust.toml");
        let trust = SharedTrustStore::open(host_paths.trust_file()).expect("open trust.toml");
        let (authorizer, _diag): (Arc<dyn Authorizer>, _) =
            load_or_deny(&host_paths, Role::Serve, trust);
        let host_trust = StaticTrust::empty().with_pin(fp, Principal::Device("laptop".into()));
        let h = match chaos {
            None => LoopbackHarness::start_custom(authorizer, make_identity(), host_trust).await,
            Some(policy) => {
                LoopbackHarness::start_chaotic_custom(
                    authorizer,
                    make_identity(),
                    host_trust,
                    policy,
                )
                .await
            }
        };
        let runtime = dir.path().join("host/run");
        h.server.set_agent_runtime_dir(runtime.clone());

        let address = h.addr.to_string();
        let host_fp = h.server_identity.fingerprint.to_string();
        blocking({
            let ops = ops.clone();
            move || {
                ops.trust_add(TrustAddReq {
                    name: "box".into(),
                    address: Some(address),
                    fingerprint: Some(host_fp),
                    cert_pem: None,
                    role: None,
                })
            }
        })
        .await
        .expect("trust.add");
        Self {
            _dir: dir,
            ops,
            h,
            runtime,
        }
    }

    fn with_agent(&self, fake: &FakeAgent) -> Ops {
        self.ops.clone().with_client_agent(client_agent(fake))
    }

    fn sockets(&self) -> Vec<PathBuf> {
        match std::fs::read_dir(self.runtime.join("agent")) {
            Ok(entries) => entries.filter_map(Result::ok).map(|e| e.path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn the_socket(&self) -> PathBuf {
        let sockets = self.sockets();
        assert_eq!(sockets.len(), 1, "exactly one agent socket: {sockets:?}");
        sockets.into_iter().next().unwrap()
    }
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn exec_req(host: &str, argv: Vec<String>) -> ExecRunReq {
    ExecRunReq {
        host: host.into(),
        argv,
        env: vec![],
        timeout_ms: Some(30_000),
    }
}

fn program_argv(key: &FakeIdentity) -> Vec<String> {
    vec![
        "python3".into(),
        "-c".into(),
        PROGRAM.into(),
        sign_body_hex(key),
    ]
}

fn lines(out: &ExecRunOutput) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// Run `PROGRAM` the way a shell in the session would: `SSH_AUTH_SOCK` set to
/// `sock`.
async fn run_program(sock: &Path, key: &FakeIdentity) -> Vec<String> {
    let sock = sock.to_path_buf();
    let body = sign_body_hex(key);
    blocking(move || {
        let out = std::process::Command::new("python3")
            .args(["-c", PROGRAM, &body])
            .env("SSH_AUTH_SOCK", &sock)
            .output()
            .expect("run python3");
        assert!(out.status.success(), "the program failed: {:?}", out.status);
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    })
    .await
}

fn open_shell(ops: &Ops, host: &str) -> String {
    ops.session_open(SessionOpenReq {
        host: host.into(),
        argv: vec!["sh".into()],
        env: vec![],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
        shell_command: None,
    })
    .expect("session.open")
    .session_ref
}

fn attach(ops: &Ops, session_ref: &str) -> SessionAttachStream {
    ops.session_attach(
        SessionAttachReq {
            session_ref: session_ref.to_string(),
            no_steal: false,
        },
        &[],
    )
    .expect("session.attach")
}

// ---- raw client of the host's socket, for connect-only checks -------------

/// Connect to `sock`, send `request` and read one whole reply. `None` when the
/// connection is refused or closed before a reply.
async fn exchange(sock: &Path, request: &[u8]) -> Option<Vec<u8>> {
    let mut stream = tokio::net::UnixStream::connect(sock).await.ok()?;
    stream.write_all(request).await.ok()?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.ok()?;
    let mut message = len.to_vec();
    message.extend_from_slice(&body);
    Some(message)
}

fn list_request() -> Vec<u8> {
    encode_message(SSH2_AGENTC_REQUEST_IDENTITIES, &[]).unwrap()
}

fn sign_request(key: &FakeIdentity) -> Vec<u8> {
    encode_message(
        SSH2_AGENTC_SIGN_REQUEST,
        &sign_request_body(&key.blob, CHALLENGE, 0),
    )
    .unwrap()
}

async fn list(sock: &Path) -> Option<Vec<u8>> {
    exchange(sock, &list_request()).await
}

// ---- DoD 23.1 --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn agent_forward_loopback_lists_and_signs() {
    if !have_python() {
        return;
    }
    let rig = Rig::start(None).await;

    // `-A` exec: the program lists, signs, and its remove-all never reaches
    // the agent.
    let k = key("exec-key");
    let fake = FakeAgent::start(vec![k.clone()]).await.unwrap();
    let ops = rig.with_agent(&fake);
    let argv = program_argv(&k);
    let out = blocking(move || ops.exec_run(exec_req("box", argv), ExecStdin::Closed))
        .await
        .expect("exec.run");
    assert_eq!(out.data.remote_exit_code, 0, "{:?}", lines(&out));
    assert_eq!(lines(&out), expected_lines(&k));
    assert_eq!(
        fake.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST],
        "the remove-all (19) stopped at the client"
    );
    wait_until("the exec socket is removed", || rig.sockets().is_empty()).await;

    // `-A` session: the attach that holds the lease backs the socket.
    let k = key("session-key");
    let fake = FakeAgent::start(vec![k.clone()]).await.unwrap();
    let ops = rig.with_agent(&fake);
    let stream = blocking(move || {
        let session_ref = open_shell(&ops, "box");
        attach(&ops, &session_ref)
    })
    .await;
    let sock = rig.the_socket();
    assert_eq!(run_program(&sock, &k).await, expected_lines(&k));
    assert_eq!(
        fake.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST]
    );
    drop(stream);
    rig.h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_forward_over_a_punched_connection() {
    if !have_python() {
        return;
    }
    let w = world(WorldOptions {
        direct_listener: false,
        pin_b_address: false,
        ..WorldOptions::default()
    })
    .await;
    // B's runtime directory, as `world` set it up.
    let runtime = w._dir.path().join("run");

    let k = key("punched-key");
    let fake = FakeAgent::start(vec![k.clone()]).await.unwrap();
    let ops = w.a.ops.clone().with_client_agent(client_agent(&fake));
    let argv = program_argv(&k);
    let out = blocking(move || ops.exec_run(exec_req("b", argv), ExecStdin::Closed))
        .await
        .expect("exec over the punch");
    assert_eq!(out.data.remote_exit_code, 0, "{:?}", lines(&out));
    assert_eq!(lines(&out), expected_lines(&k));
    assert_eq!(
        fake.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST]
    );
    assert_eq!(w.punch_requests(), 1, "the connection came from a punch");

    // The same flow in a session, with the test connecting to the socket the
    // host announced.
    let k2 = key("punched-session-key");
    let fake2 = FakeAgent::start(vec![k2.clone()]).await.unwrap();
    let ops2 = w.a.ops.clone().with_client_agent(client_agent(&fake2));
    let stream = blocking(move || {
        let session_ref = open_shell(&ops2, "b");
        attach(&ops2, &session_ref)
    })
    .await;
    let dir = runtime.join("agent");
    wait_until("the session socket", || {
        std::fs::read_dir(&dir).is_ok_and(|d| d.count() == 1)
    })
    .await;
    let sock = std::fs::read_dir(&dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(run_program(&sock, &k2).await, expected_lines(&k2));
    assert_eq!(
        fake2.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST]
    );
    drop(stream);
    w.shutdown().await;
}

// ---- DoD 23.5 --------------------------------------------------------------

/// Decision 9 (a): the socket follows the writer lease. `-A` attach A backs
/// it with A's agent; a later attach without `-A` leaves it unbacked and its
/// connections close at once; a third attach with `-A` and another agent
/// moves signing to that agent.
#[tokio::test(flavor = "multi_thread")]
async fn agent_backing_follows_the_writer_attach() {
    let rig = Rig::start(None).await;
    let (ka, kb) = (key("key-of-a"), key("key-of-b"));
    let fake_a = FakeAgent::start(vec![ka.clone()]).await.unwrap();
    let fake_b = FakeAgent::start(vec![kb.clone()]).await.unwrap();
    let (ops_a, ops_b) = (rig.with_agent(&fake_a), rig.with_agent(&fake_b));
    let plain = rig.ops.clone();

    let (session_ref, attach_a) = blocking(move || {
        let session_ref = open_shell(&ops_a, "box");
        let stream = attach(&ops_a, &session_ref);
        (session_ref, stream)
    })
    .await;
    let sock = rig.the_socket();

    // A holds the lease with `-A`.
    assert_eq!(
        list(&sock).await,
        Some(identities_answer(std::slice::from_ref(&ka)))
    );
    assert_eq!(
        exchange(&sock, &sign_request(&ka)).await,
        Some(sign_response(&ka.blob, CHALLENGE))
    );

    // The lease moves to an attach without `-A`: nothing backs the socket.
    let attach_plain = blocking({
        let session_ref = session_ref.clone();
        move || attach(&plain, &session_ref)
    })
    .await;
    let started = Instant::now();
    assert_eq!(list(&sock).await, None, "no `-A` writer, no agent");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(fake_b.connections(), 0);

    // Another `-A` attach takes the lease: signing goes to its agent.
    let attach_b = blocking(move || attach(&ops_b, &session_ref)).await;
    assert_eq!(
        list(&sock).await,
        Some(identities_answer(std::slice::from_ref(&kb)))
    );
    assert_eq!(
        exchange(&sock, &sign_request(&kb)).await,
        Some(sign_response(&kb.blob, CHALLENGE))
    );
    assert_eq!(
        fake_a.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST],
        "A's agent heard nothing after it lost the lease"
    );
    assert_eq!(
        fake_b.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST]
    );
    drop((attach_a, attach_plain, attach_b));
    rig.h.shutdown().await;
}

/// DoD 23.5 and G12: while the path is cut a local connection to the socket
/// is closed rather than left to wait, and once the attach has resumed the
/// next request is signed again.
#[tokio::test(flavor = "multi_thread")]
async fn agent_requests_during_a_blackout_fail_fast_and_work_after_resume() {
    let rig = Rig::start(Some(ChaosPolicy::seeded(0xA6E2_5B1A))).await;
    let ctx = rig.h.context();
    let k = key("resume-key");
    let fake = FakeAgent::start(vec![k.clone()]).await.unwrap();
    let ops = rig.with_agent(&fake).with_recovery(RecoveryConfig {
        migration: false,
        ..RecoveryConfig::default()
    });
    let stream = blocking(move || {
        let session_ref = open_shell(&ops, "box");
        attach(&ops, &session_ref)
    })
    .await;
    let sock = rig.the_socket();
    assert_eq!(
        list(&sock).await,
        Some(identities_answer(std::slice::from_ref(&k))),
        "{ctx}"
    );

    // The path dies. The client re-dials by itself.
    rig.h.chaos().sever().await;

    // Every local connection from here to the resume is closed, not held:
    // the first one while the host finds out the backing is gone, the rest
    // at once.
    let mut failed = 0usize;
    let mut slowest_after_first = Duration::ZERO;
    let deadline = Instant::now() + Duration::from_secs(40);
    let signed = loop {
        assert!(
            Instant::now() < deadline,
            "no signature after the resume — {ctx}"
        );
        let started = Instant::now();
        let attempt = tokio::time::timeout(Duration::from_secs(10), list(&sock))
            .await
            .unwrap_or_else(|_| panic!("a local connection was held during the cut — {ctx}"));
        let took = started.elapsed();
        match attempt {
            Some(answer) => {
                assert_eq!(answer, identities_answer(std::slice::from_ref(&k)), "{ctx}");
                break exchange(&sock, &sign_request(&k)).await;
            }
            None => {
                if failed > 0 {
                    slowest_after_first = slowest_after_first.max(took);
                }
                failed += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    assert!(failed > 0, "the cut was never seen by the socket — {ctx}");
    assert!(
        slowest_after_first < Duration::from_millis(100),
        "a connection during the cut took {slowest_after_first:?} to close — {ctx}"
    );
    assert_eq!(
        signed,
        Some(sign_response(&k.blob, CHALLENGE)),
        "signing works after the resume — {ctx}"
    );
    assert_eq!(
        fake.received_kinds(),
        vec![
            SSH2_AGENTC_REQUEST_IDENTITIES,
            SSH2_AGENTC_REQUEST_IDENTITIES,
            SSH2_AGENTC_SIGN_REQUEST
        ],
        "nothing reached the agent while the path was cut — {ctx}"
    );
    drop(stream);
    rig.h.shutdown().await;
}

/// A healthy path adds no round trip of its own: the liveness probe runs
/// beside the real stream, so a list request over a path with a fixed 50 ms
/// one-way delay costs about one round trip (100 ms), not two.
#[tokio::test(flavor = "multi_thread")]
async fn a_healthy_path_adds_no_round_trip_to_an_agent_request() {
    let policy =
        ChaosPolicy::seeded(0xA6E2_D31A).delay(DelayDist::fixed(Duration::from_millis(50)));
    let rig = Rig::start(Some(policy)).await;
    let ctx = rig.h.context();
    let k = key("delayed-key");
    let fake = FakeAgent::start(vec![k.clone()]).await.unwrap();
    let ops = rig.with_agent(&fake);
    let stream = blocking(move || {
        let session_ref = open_shell(&ops, "box");
        attach(&ops, &session_ref)
    })
    .await;
    let sock = rig.the_socket();

    for round in 0..3 {
        let started = Instant::now();
        let answer = list(&sock).await;
        let took = started.elapsed();
        assert_eq!(
            answer,
            Some(identities_answer(std::slice::from_ref(&k))),
            "{ctx}"
        );
        assert!(
            took < Duration::from_millis(170),
            "round {round}: a list took {took:?} over a 100 ms round trip, \
             more than one round trip plus slack — {ctx}"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    drop(stream);
    rig.h.shutdown().await;
}
