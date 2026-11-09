//! L3 loopback for the host side of agent forwarding (ADR-0055 decisions 5 to
//! 10, 16, 17; DoD 23.1 host half, 23.4, 23.7).
//!
//! The host here is the real one: a [`LoopbackHarness`] whose authorizer is
//! built from a sandbox `trust.toml`/`acl.toml` and whose [`Server`] has a
//! temporary runtime directory for agent sockets. The client is a test: it
//! sends `agent_channel` through the `Session` entry points the wire step
//! added, accepts the host's `AGENT` streams itself and bridges each one to a
//! [`FakeAgent`]. The program on the host is a small `python3` script (or the
//! test itself, connecting to the socket the host announced), and the test
//! skips with a message when `python3` is missing.
//!
//! The dispatcher that does this in the real client, the local agent connect
//! and the filter are the client step's; nothing here depends on them.
//!
//! [`Server`]: qsh_core::server::Server

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_core::acl::{Authorizer, Role, load_or_deny};
use qsh_core::audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink};
use qsh_core::broker::SourceExit;
use qsh_core::client::ClientError;
use qsh_core::config::Paths;
use qsh_core::exec::ExecSpec;
use qsh_core::trust::SharedTrustStore;
use qsh_proto::ErrorCode;
use qsh_proto::agent::SSH2_AGENTC_REQUEST_IDENTITIES;
use qsh_proto::wire::{self, AgentGrant, ExecFrame, StreamHeader, StreamKind};
use qsh_testkit::fake_agent::{FakeAgent, FakeIdentity, identities_answer};
use qsh_testkit::loopback::{LoopbackHarness, TestIdentity, make_identity};
use qsh_testkit::pair::HostedPair;
use qsh_transport::{Connection, FramedStream, Principal, StaticTrust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

const CHANNEL: [u8; wire::AGENT_CHANNEL_LEN] = [0xa5; wire::AGENT_CHANNEL_LEN];
const OTHER_CHANNEL: [u8; wire::AGENT_CHANNEL_LEN] = [0x5a; wire::AGENT_CHANNEL_LEN];

/// A sandbox config dir (`trust.toml`, optional `acl.toml`) plus a runtime
/// directory the host makes agent sockets in.
struct Env {
    _dir: tempfile::TempDir,
    paths: Paths,
    runtime: PathBuf,
    trust: Arc<SharedTrustStore>,
    client: TestIdentity,
}

impl Env {
    /// The harness client is pinned as `laptop` with `role_line` (e.g.
    /// `role = "full"\n`) and the host reads `acl` as `acl.toml` when given.
    fn new(role_line: &str, acl: Option<&str>) -> Self {
        let client = make_identity();
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::write(
            paths.trust_file(),
            format!(
                "[[peer]]\nname = \"laptop\"\nfingerprint = \"{}\"\naddress = \"\"\n\
                 added_at = \"2026-11-09T00:00:00Z\"\n{role_line}\n",
                client.fingerprint
            ),
        )
        .expect("write trust.toml");
        if let Some(text) = acl {
            let path = paths.acl_file();
            std::fs::write(&path, text).expect("write acl.toml");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod acl.toml");
        }
        let trust = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
        let runtime = dir.path().join("run");
        Self {
            _dir: dir,
            paths,
            runtime,
            trust,
            client,
        }
    }

    fn authorizer(&self) -> Arc<dyn Authorizer> {
        let (authorizer, _diagnostic) =
            load_or_deny(&self.paths, Role::Serve, Arc::clone(&self.trust));
        authorizer
    }

    fn host_trust(&self) -> StaticTrust {
        StaticTrust::empty().with_pin(
            self.client.fingerprint,
            Principal::Device("laptop".to_string()),
        )
    }

    async fn start(&self) -> LoopbackHarness {
        let h = LoopbackHarness::start_custom(
            self.authorizer(),
            self.client.clone(),
            self.host_trust(),
        )
        .await;
        h.server.set_agent_runtime_dir(self.runtime.clone());
        h
    }

    /// The names in `<runtime>/agent/`; empty when the directory is absent.
    fn sockets(&self) -> Vec<String> {
        agent_entries(&self.runtime)
    }
}

fn agent_entries(runtime: &Path) -> Vec<String> {
    match std::fs::read_dir(runtime.join("agent")) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn open_req(agent_channel: &[u8]) -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        agent_channel: agent_channel.to_vec(),
        ..Default::default()
    }
}

fn exec_spec(argv: &[&str]) -> ExecSpec {
    ExecSpec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: vec![],
        timeout: None,
        shell: None,
        agent_sock: None,
    }
}

fn fake_identities() -> Vec<FakeIdentity> {
    vec![FakeIdentity::new(
        b"blob-one".to_vec(),
        "secret-comment-one",
    )]
}

/// What the client does with the host's `AGENT` streams: accept each one on
/// `conn`, check its header names `channel`, and copy bytes to and from a new
/// connection to `agent`. Counts the streams it served.
struct ClientAgent {
    served: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl ClientAgent {
    fn start(conn: Connection, channel: Vec<u8>, agent: Arc<FakeAgent>) -> Self {
        let served = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&served);
        let task = tokio::spawn(async move {
            while let Ok((send, recv)) = conn.accept_bi().await {
                let agent = Arc::clone(&agent);
                let channel = channel.clone();
                let count = Arc::clone(&count);
                tokio::spawn(async move {
                    let mut framed = FramedStream::data(send, recv);
                    let Ok(Some(header)) = framed.recv.recv::<StreamHeader>().await else {
                        return;
                    };
                    if header.stream_kind() != Some(StreamKind::Agent) || header.ticket != channel {
                        return;
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let Ok(local) = agent.connect().await else {
                        return;
                    };
                    let (mut local_read, mut local_write) = tokio::io::split(local);
                    let mut send = framed.send.into_raw();
                    let (mut recv, residue) = framed.recv.into_raw();
                    let down = async {
                        let _ = local_write.write_all(&residue).await;
                        let _ = tokio::io::copy(&mut recv, &mut local_write).await;
                        let _ = local_write.shutdown().await;
                    };
                    let up = async {
                        let _ = tokio::io::copy(&mut local_read, &mut send).await;
                        let _ = send.shutdown().await;
                    };
                    tokio::join!(down, up);
                });
            }
        });
        Self { served, task }
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

impl Drop for ClientAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The program on the host, as the test itself: connect to `sock`, send
/// `REQUEST_IDENTITIES` and read one whole reply. `None` when the connection
/// is refused or closed before a reply.
async fn request_identities(sock: &Path) -> Option<Vec<u8>> {
    let mut stream = tokio::net::UnixStream::connect(sock).await.ok()?;
    stream
        .write_all(&[0, 0, 0, 1, SSH2_AGENTC_REQUEST_IDENTITIES])
        .await
        .ok()?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.ok()?;
    let mut message = len.to_vec();
    message.extend_from_slice(&body);
    Some(message)
}

/// Whether a program connecting to `sock` is closed at once (no reply, no
/// hang).
async fn is_closed_at_once(sock: &Path) -> bool {
    tokio::time::timeout(Duration::from_secs(5), request_identities(sock))
        .await
        .expect("a socket with no backing must close the connection, not hold it")
        .is_none()
}

fn the_one_socket(env: &Env) -> PathBuf {
    let entries = env.sockets();
    assert_eq!(entries.len(), 1, "exactly one agent socket: {entries:?}");
    env.runtime.join("agent").join(&entries[0])
}

// ---- exec ---------------------------------------------------------------

const PROGRAM: &str = r#"
import os, socket, struct
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ["SSH_AUTH_SOCK"])
s.sendall(struct.pack(">IB", 1, 11))
def rd(n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SystemExit(3)
        b += c
    return b
(n,) = struct.unpack(">I", rd(4))
print(rd(n).hex())
"#;

/// Run `argv` as an exec on `s`, returning stdout and the exit code.
async fn run_exec(
    s: &mut qsh_core::client::Session,
    spec: &ExecSpec,
    channel: &[u8],
) -> (AgentGrant, String, i32) {
    let started = s
        .exec_start_with_agent(spec, channel.to_vec())
        .await
        .unwrap();
    let grant = AgentGrant::try_from(started.agent).unwrap();
    let (send, recv) = s.connection().open_bi().await.unwrap();
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::exec_data(started.ticket))
        .await
        .unwrap();
    let mut stdout = Vec::new();
    let code = loop {
        match data.recv.recv::<ExecFrame>().await.unwrap() {
            Some(ExecFrame {
                body: Some(wire::exec_frame::Body::Stdout(chunk)),
            }) => stdout.extend_from_slice(&chunk.data),
            Some(ExecFrame {
                body: Some(wire::exec_frame::Body::ExecExit(exit)),
            }) => break exit.exit_code,
            Some(_) => {}
            None => panic!("exec stream ended without ExecExit"),
        }
    };
    (grant, String::from_utf8_lossy(&stdout).into_owned(), code)
}

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

#[tokio::test(flavor = "multi_thread")]
async fn an_exec_program_lists_identities_through_the_forwarded_socket() {
    if !have_python() {
        return;
    }
    let env = Env::new("role = \"full\"\n", None);
    let h = env.start().await;
    let fake = Arc::new(FakeAgent::start(fake_identities()).await.unwrap());
    let mut s = h.session().await;
    let client = ClientAgent::start(s.connection().clone(), CHANNEL.to_vec(), Arc::clone(&fake));

    let (grant, stdout, code) =
        run_exec(&mut s, &exec_spec(&["python3", "-c", PROGRAM]), &CHANNEL).await;
    assert_eq!(grant, AgentGrant::Forwarded);
    assert_eq!(code, 0, "the program failed: {stdout}");
    let expected = identities_answer(&fake_identities());
    let hex: String = expected[4..].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(stdout.trim(), hex);
    assert_eq!(client.served(), 1);
    assert_eq!(fake.received_kinds(), vec![SSH2_AGENTC_REQUEST_IDENTITIES]);

    // The exec is over: its socket is gone with it.
    wait_until("the exec socket is removed", || env.sockets().is_empty()).await;
    s.close();
    h.shutdown().await;
}

/// ADR-0055 decision 6: the host pins `SSH_AUTH_SOCK`. A value the client
/// sends is dropped, with an agent and without one.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_auth_sock_is_pinned_by_the_host() {
    let env = Env::new("role = \"full\"\n", None);
    let h = env.start().await;
    let mut s = h.session().await;
    let show = ["sh", "-c", "printf %s \"${SSH_AUTH_SOCK-unset}\""];

    // No agent: the client's value never reaches the child.
    let mut spec = exec_spec(&show);
    spec.env = vec![("SSH_AUTH_SOCK".into(), "/tmp/evil.sock".into())];
    let (grant, stdout, _) = run_exec(&mut s, &spec, &[]).await;
    assert_eq!(grant, AgentGrant::Unspecified);
    assert_eq!(stdout, "unset");

    // With an agent: the host's own socket, whatever the client sent.
    let (grant, stdout, _) = run_exec(&mut s, &spec, &CHANNEL).await;
    assert_eq!(grant, AgentGrant::Forwarded);
    assert!(
        stdout.starts_with(env.runtime.join("agent").to_str().unwrap())
            && stdout.ends_with(".sock"),
        "SSH_AUTH_SOCK was {stdout:?}"
    );
    s.close();
    h.shutdown().await;
}

// ---- session ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_session_socket_is_private_pinned_in_the_spec_and_bridged() {
    let env = Env::new("role = \"full\"\n", None);
    let h = env.start().await;
    let fake = Arc::new(FakeAgent::start(fake_identities()).await.unwrap());
    let mut s = h.session().await;
    let client = ClientAgent::start(s.connection().clone(), CHANNEL.to_vec(), Arc::clone(&fake));

    let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Forwarded as i32);
    assert!(!opened.ticket.is_empty());
    let (spec, _pipe) = h.pipes().take_with_spec().expect("the session exists");

    let sock = the_one_socket(&env);
    assert_eq!(
        spec.agent_sock.as_deref(),
        sock.to_str(),
        "SSH_AUTH_SOCK is the host's socket"
    );
    // 0700 directory, 0600 socket (decision 6).
    let dir_mode = std::fs::metadata(env.runtime.join("agent"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o700);
    let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(sock_mode & 0o777, 0o600);

    let reply = request_identities(&sock).await.expect("a reply");
    assert_eq!(reply, identities_answer(&fake_identities()));
    assert_eq!(client.served(), 1);
    s.close();
    h.shutdown().await;
}

/// DoD 23.4: the session's socket goes when the session ends, whichever way
/// it ends.
#[tokio::test(flavor = "multi_thread")]
async fn agent_socket_is_removed_when_the_session_ends() {
    let env = Env::new("role = \"full\"\n", None);
    let h = env.start().await;
    let fake = Arc::new(FakeAgent::start(fake_identities()).await.unwrap());
    let mut s = h.session().await;
    let _client = ClientAgent::start(s.connection().clone(), CHANNEL.to_vec(), Arc::clone(&fake));

    // `session close`.
    let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
    let (_spec, _pipe) = h.pipes().take_with_spec().unwrap();
    let sock = the_one_socket(&env);
    assert!(request_identities(&sock).await.is_some());
    s.session_close(&opened.session_id, None).await.unwrap();
    wait_until("the closed session's socket is removed", || {
        env.sockets().is_empty()
    })
    .await;
    assert!(!sock.exists());

    // The child exits by itself.
    let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Forwarded as i32);
    let (_spec, mut pipe) = h.pipes().take_with_spec().unwrap();
    assert_eq!(env.sockets().len(), 1);
    pipe.exit(SourceExit {
        exit_code: Some(0),
        signal: None,
    });
    wait_until("the exited session's socket is removed", || {
        env.sockets().is_empty()
    })
    .await;
    s.close();
    h.shutdown().await;
}

/// The socket outlives nothing the host drops: shutting the host down while a
/// session is alive removes it too.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_host_removes_its_session_sockets() {
    let env = Env::new("role = \"full\"\n", None);
    let h = env.start().await;
    let mut s = h.session().await;
    let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Forwarded as i32);
    let _pipe = h.pipes().take().unwrap();
    assert_eq!(env.sockets().len(), 1);
    s.close();
    h.shutdown().await;
    drop(_pipe);
    wait_until("the host's sockets are removed", || {
        env.sockets().is_empty()
    })
    .await;
}

/// Decision 9: with nothing backing the socket, a local connection is closed
/// at once. Here the connection that backed it is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_socket_with_no_backing_closes_connections_at_once() {
    let env = Env::new("role = \"full\"\n", None);
    let h = env.start().await;
    let fake = Arc::new(FakeAgent::start(fake_identities()).await.unwrap());
    let mut s = h.session().await;
    let _client = ClientAgent::start(s.connection().clone(), CHANNEL.to_vec(), Arc::clone(&fake));
    let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Forwarded as i32);
    let (_spec, _pipe) = h.pipes().take_with_spec().unwrap();
    let sock = the_one_socket(&env);
    assert!(request_identities(&sock).await.is_some());

    // The backing connection goes away; the session and its socket stay.
    s.connection().close(0, b"gone");
    // Backing is cleared when the host notices the close.
    let mut closed = false;
    for _ in 0..200 {
        if tokio::time::timeout(Duration::from_millis(500), request_identities(&sock))
            .await
            .is_ok_and(|r| r.is_none())
        {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(closed, "a connection to an unbacked socket must be closed");
    assert!(
        sock.exists(),
        "the socket belongs to the session, not to the connection"
    );
    assert!(is_closed_at_once(&sock).await);
    h.shutdown().await;
}

/// Decision 9, as far as open and attach need it: the attach that took the
/// writer lease and asked for `-A` backs the socket; a later attach without
/// `-A` leaves it unbacked; a session opened without `-A` answers `NO_SOCKET`.
#[tokio::test(flavor = "multi_thread")]
async fn the_attach_that_holds_the_lease_backs_the_session_socket() {
    let env = Env::new("role = \"full\"\n", None);
    let h = env.start().await;
    let fake_a = Arc::new(FakeAgent::start(fake_identities()).await.unwrap());
    let fake_b = Arc::new(FakeAgent::start(fake_identities()).await.unwrap());

    let mut a = h.session().await;
    let client_a = ClientAgent::start(
        a.connection().clone(),
        CHANNEL.to_vec(),
        Arc::clone(&fake_a),
    );
    let opened = a.session_open(open_req(&CHANNEL)).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Forwarded as i32);
    let (_spec, _pipe) = h.pipes().take_with_spec().unwrap();
    let sock = the_one_socket(&env);
    assert!(request_identities(&sock).await.is_some());
    assert_eq!((client_a.served(), fake_a.connections()), (1, 1));

    // A second device attaches with `-A` and its own channel.
    let mut b = h.session().await;
    let client_b = ClientAgent::start(
        b.connection().clone(),
        OTHER_CHANNEL.to_vec(),
        Arc::clone(&fake_b),
    );
    let attach = |token: Vec<u8>, channel: &[u8]| wire::SessionAttach {
        session_id: opened.session_id.clone(),
        resume_token: token,
        mode: wire::AttachMode::Rw as i32,
        agent_channel: channel.to_vec(),
        ..Default::default()
    };
    let attached = b
        .attach_request(attach(opened.resume_token.clone(), &OTHER_CHANNEL))
        .await
        .unwrap();
    assert_eq!(attached.agent, AgentGrant::Forwarded as i32);
    assert!(request_identities(&sock).await.is_some());
    assert_eq!(
        (client_a.served(), client_b.served(), fake_b.connections()),
        (1, 1, 1),
        "the new stream went to the attach that holds the lease"
    );

    // A third attach without `-A` takes the lease and backs nothing.
    let mut c = h.session().await;
    let attached = c
        .attach_request(attach(attached.new_resume_token.clone(), &[]))
        .await
        .unwrap();
    assert_eq!(attached.agent, AgentGrant::Unspecified as i32);
    assert!(is_closed_at_once(&sock).await);

    // A session opened without `-A` has no socket, and `-A` later makes none.
    let plain = c.session_open(open_req(&[])).await.unwrap();
    assert_eq!(plain.agent, AgentGrant::Unspecified as i32);
    let _plain_pipe = h.pipes().take().unwrap();
    let attached = c
        .attach_request(wire::SessionAttach {
            session_id: plain.session_id.clone(),
            resume_token: plain.resume_token.clone(),
            mode: wire::AttachMode::Rw as i32,
            agent_channel: CHANNEL.to_vec(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(attached.agent, AgentGrant::NoSocket as i32);
    assert_eq!(
        env.sockets().len(),
        1,
        "still only the first session's socket"
    );
    a.close();
    b.close();
    c.close();
    h.shutdown().await;
}

// ---- authorization (decisions 16 and 17) --------------------------------

/// Rows that let a role without `forward.agent` open sessions and execs at
/// all, so the only thing in question is the agent.
const OPEN_ROWS: &str = "[[acl]]\nprincipal = \"device:laptop\"\n\
                         allow = [\"session.open\", \"session.attach\", \"exec.run\"]\n";

fn forward_agent_records(h: &LoopbackHarness) -> Vec<AuditRecord> {
    h.audit
        .records()
        .into_iter()
        .filter(|r| r.action == "forward.agent")
        .collect()
}

/// DoD 23.7: a role without `forward.agent` (and a pin with no role) gets
/// `DENIED`, no socket, and the session and the exec still open.
#[tokio::test(flavor = "multi_thread")]
async fn agent_request_without_forward_agent_creates_no_socket() {
    for role_line in [
        "role = \"tunnel\"\n",
        "role = \"read-only\"\n",
        "role = \"reverse\"\n",
        "role = \"none\"\n",
        "",
    ] {
        let env = Env::new(role_line, Some(OPEN_ROWS));
        let h = env.start().await;
        let mut s = h.session().await;
        let label = if role_line.is_empty() {
            "no role"
        } else {
            role_line.trim()
        };

        let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
        assert_eq!(opened.agent, AgentGrant::Denied as i32, "{label}");
        assert!(
            !opened.session_id.is_empty() && !opened.ticket.is_empty(),
            "{label}"
        );
        let (spec, _pipe) = h.pipes().take_with_spec().expect("the session opened");
        assert_eq!(spec.agent_sock, None, "{label}: no SSH_AUTH_SOCK");

        let started = s
            .exec_start_with_agent(&exec_spec(&["true"]), CHANNEL.to_vec())
            .await
            .unwrap();
        assert_eq!(started.agent, AgentGrant::Denied as i32, "{label}");
        assert!(!started.ticket.is_empty(), "{label}");

        let attached = s
            .attach_request(wire::SessionAttach {
                session_id: opened.session_id.clone(),
                resume_token: opened.resume_token.clone(),
                mode: wire::AttachMode::Rw as i32,
                agent_channel: CHANNEL.to_vec(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(attached.agent, AgentGrant::Denied as i32, "{label}");

        assert!(env.sockets().is_empty(), "{label}: no socket was made");
        let records = forward_agent_records(&h);
        let resources: Vec<&str> = records.iter().map(|r| r.resource.as_str()).collect();
        assert_eq!(
            resources,
            ["session.open", "exec.run", "session.attach"],
            "{label}"
        );
        for record in &records {
            assert_eq!(record.decision, "deny", "{label}");
            assert_eq!(record.principal, "device:laptop");
            let line = serde_json::to_string(record).unwrap();
            assert!(
                !line.contains(".sock") && !line.contains("a5a5"),
                "{label}: {line}"
            );
        }
        s.close();
        h.shutdown().await;
    }
}

/// `full` and `exec` do grant it, and it is audited as an allow.
#[tokio::test(flavor = "multi_thread")]
async fn full_and_exec_roles_get_a_socket_and_an_allow_record() {
    for role in ["full", "exec"] {
        let env = Env::new(&format!("role = \"{role}\"\n"), None);
        let h = env.start().await;
        let mut s = h.session().await;
        let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
        assert_eq!(opened.agent, AgentGrant::Forwarded as i32, "{role}");
        let _pipe = h.pipes().take().unwrap();
        assert_eq!(env.sockets().len(), 1, "{role}");
        let records = forward_agent_records(&h);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, "allow");
        assert_eq!(records[0].role.as_deref(), Some(role));
        s.close();
        h.shutdown().await;
    }
}

/// `trust allow <peer> forward.agent` on a pin that cannot open a session
/// still makes no socket: the request is refused before the agent is asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_forward_agent_grant_does_not_open_a_session_by_itself() {
    let env = Env::new("role = \"tunnel\"\ngrants = [\"forward.agent\"]\n", None);
    let h = env.start().await;
    let mut s = h.session().await;
    let err = s.session_open(open_req(&CHANNEL)).await.unwrap_err();
    assert!(
        matches!(
            err,
            ClientError::Remote {
                code: ErrorCode::PermissionDenied,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(h.pipes().take().is_none());
    assert!(env.sockets().is_empty());
    assert!(
        forward_agent_records(&h).is_empty(),
        "forward.agent is not decided for a request that was refused"
    );
    s.close();
    h.shutdown().await;
}

/// An audit sink that refuses `forward.agent` records and keeps the rest.
struct RefuseAgentAudit {
    inner: Arc<MemoryAuditSink>,
    refused: Mutex<usize>,
}

impl AuditSink for RefuseAgentAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if record.action == "forward.agent" {
            *self.refused.lock().unwrap() += 1;
            return Err(AuditError::Degraded);
        }
        self.inner.record(record)
    }
}

/// DoD 23.7: an allow that could not be recorded makes no socket and answers
/// `UNAVAILABLE`; the session and the exec still open.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_audit_write_leaves_no_socket_and_answers_unavailable() {
    let env = Env::new("role = \"full\"\n", None);
    let sink = Arc::new(RefuseAgentAudit {
        inner: Arc::new(MemoryAuditSink::new()),
        refused: Mutex::new(0),
    });
    let h = LoopbackHarness::start_custom_with_audit_sink(
        env.authorizer(),
        env.client.clone(),
        env.host_trust(),
        sink.clone(),
    )
    .await;
    h.server.set_agent_runtime_dir(env.runtime.clone());
    let mut s = h.session().await;

    let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Unavailable as i32);
    let (spec, _pipe) = h.pipes().take_with_spec().expect("the session opened");
    assert_eq!(spec.agent_sock, None);
    let started = s
        .exec_start_with_agent(&exec_spec(&["true"]), CHANNEL.to_vec())
        .await
        .unwrap();
    assert_eq!(started.agent, AgentGrant::Unavailable as i32);
    assert!(env.sockets().is_empty());
    assert_eq!(*sink.refused.lock().unwrap(), 2, "one attempt per request");
    s.close();
    h.shutdown().await;
}

/// A host that was never told where to make sockets cannot make one.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_a_runtime_directory_answers_unavailable() {
    let env = Env::new("role = \"full\"\n", None);
    let h =
        LoopbackHarness::start_custom(env.authorizer(), env.client.clone(), env.host_trust()).await;
    let mut s = h.session().await;
    let opened = s.session_open(open_req(&CHANNEL)).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Unavailable as i32);
    assert!(h.pipes().take().is_some(), "the session still opened");
    s.close();
    h.shutdown().await;
}
