//! L3 acceptance for the relay endpoint of `qsh serve` and `qsh listen
//! --serve` (ADR-0061 decisions 2, 3, 4 and 6): the production runtimes
//! (`run_serve_with_iroh`, `run_listen_serve_with_iroh`) given an
//! `IrohServe` that homes on an in-process relay, and a client that dials
//! them by key with `qsh_transport::IrohEndpoint`.
//!
//! Everything stays on loopback. The relay is the in-process test relay
//! (`qsh_transport::test_relay`), whose self-signed certificate the host is
//! told to trust; no test contacts a public relay, binds UDP 4433, 4434 or
//! 443, or touches the real `~/.config/qsh`. Every runtime lives in a
//! sandbox of its own.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_core::client::Session;
use qsh_core::config::{Config, Paths};
use qsh_core::exec::ExecSpec;
use qsh_core::identity;
use qsh_core::iroh_serve::IrohServe;
use qsh_core::serve::record::{self, ServeRecord};
use qsh_core::server::Server;
use qsh_core::trust::TrustStore;
use qsh_proto::KeyStoreMode;
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::wait_for;
use qsh_transport::test_relay::TestRelay;
use qsh_transport::{
    Connection, DialError, Fingerprint, IrohEndpoint, IrohPeer, Principal, StaticTrust,
};
use serde_json::Value;

const TIMEOUT: Duration = Duration::from_secs(30);

/// Which production runtime the sandbox runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Runtime {
    /// `qsh serve`.
    Serve,
    /// `qsh listen --serve`.
    ListenServe,
}

/// A running host in a sandbox, reachable over an in-process relay.
struct Host {
    _dir: tempfile::TempDir,
    paths: Paths,
    relay: TestRelay,
    host_fp: Fingerprint,
    /// The host's Ed25519 public key, the key a client dials.
    host_key: [u8; 32],
    /// The host's `Server`; only the `qsh serve` runtime hands one out.
    server: Option<Arc<Server>>,
    /// `serve.json` as it was when the address was announced.
    record_at_bind: Option<ServeRecord>,
    task: tokio::task::JoinHandle<Result<(), qsh_core::ops::OpError>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

/// How the host's endpoint is configured.
enum Iroh {
    /// Off.
    None,
    /// On, homing on the sandbox's own test relay.
    OnTestRelay,
    /// On, homing on this URL.
    Url(String),
}

/// The `allow` line of an ACL row: everything a test here asks of a peer.
const ALLOW: &str = "allow = [\"exec.run\", \"session.open\", \"session.list\", \
    \"session.attach\", \"session.control\"]";

impl Host {
    async fn start(runtime: Runtime, iroh: Iroh, pinned: &[&TestIdentity]) -> Self {
        Self::start_with(runtime, iroh, pinned, |_| {}).await
    }

    async fn start_with(
        runtime: Runtime,
        iroh: Iroh,
        pinned: &[&TestIdentity],
        tune: impl FnOnce(&mut Config),
    ) -> Self {
        qsh_testkit::env_check::ensure_loopback_udp();
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
            .with_runtime_dir(dir.path().join("run"));
        identity::init(&paths, KeyStoreMode::File).expect("identity.init");
        let loaded = identity::load(&paths).expect("load").expect("an identity");
        let host_fp = loaded.identity.fingerprint;
        let host_key = loaded.local.iroh_public_key().expect("an Ed25519 identity");

        let mut trust = TrustStore::default();
        // The first pin is `laptop`, the next `laptop2`, and so on (a name is
        // pinned once), each allowed what the tests here ask of it.
        let mut acl = String::new();
        for (index, peer) in pinned.iter().enumerate() {
            let name = if index == 0 {
                "laptop".to_string()
            } else {
                format!("laptop{}", index + 1)
            };
            trust.add_peer(
                &name,
                None,
                peer.fingerprint,
                "2026-01-01T00:00:00Z".to_string(),
            );
            acl.push_str(&format!(
                "[[acl]]\nprincipal = \"device:{name}\"\n{ALLOW}\n"
            ));
        }
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        trust.save(&paths.trust_file()).expect("save trust.toml");
        qsh_core::config::write_private_file(&paths.acl_file(), acl.as_bytes()).expect("acl.toml");

        let relay = TestRelay::spawn().await;
        let serve = match iroh {
            Iroh::None => None,
            Iroh::OnTestRelay => {
                let mut serve = IrohServe::new(relay.url.clone(), 0);
                serve.relay_roots = vec![relay.cert.clone()];
                Some(serve)
            }
            Iroh::Url(url) => {
                let mut serve = IrohServe::new(url, 0);
                serve.relay_roots = vec![relay.cert.clone()];
                Some(serve)
            }
        };

        let mut config = Config::default();
        config.listen.serve = runtime == Runtime::ListenServe;
        tune(&mut config);

        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server: Arc<Mutex<Option<Arc<Server>>>> = Arc::new(Mutex::new(None));
        let task = {
            let paths = paths.clone();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let record_paths = paths.clone();
                let on_bound = move |addr: SocketAddr| {
                    let _ = bound_tx.send((addr, record::read(&record_paths)));
                };
                let shutdown = async move {
                    let _ = stop_rx.await;
                };
                match runtime {
                    Runtime::Serve => {
                        qsh_core::serve::run_serve_with_iroh(
                            &paths,
                            &config,
                            loaded,
                            "127.0.0.1:0".parse().expect("addr"),
                            None,
                            serve,
                            on_bound,
                            move |runtime| {
                                *server.lock().unwrap_or_else(|e| e.into_inner()) =
                                    Some(Arc::clone(&runtime.server));
                            },
                            |_| {},
                            shutdown,
                        )
                        .await
                    }
                    Runtime::ListenServe => {
                        qsh_core::reverse::listen::run_listen_serve_with_iroh(
                            &paths,
                            &config,
                            loaded,
                            Some("127.0.0.1:0"),
                            serve,
                            on_bound,
                            |_| {},
                            |_| {},
                            shutdown,
                        )
                        .await
                    }
                }
            })
        };
        let (_addr, record_at_bind) = match tokio::time::timeout(TIMEOUT, bound_rx).await {
            Ok(Ok(bound)) => bound,
            _ => panic!("the runtime ended without binding: {:?}", task.await),
        };
        let server = server.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Self {
            _dir: dir,
            paths,
            relay,
            host_fp,
            host_key,
            server,
            record_at_bind,
            task,
            stop: Some(stop_tx),
        }
    }

    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(TIMEOUT, &mut self.task)
            .await
            .expect("the runtime stops")
            .expect("no panic")
            .expect("a clean stop");
    }

    /// Every record in the host's audit log so far, oldest first.
    fn audit(&self) -> Vec<Value> {
        let Ok(text) = std::fs::read_to_string(self.paths.audit_log()) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    async fn audit_record(&self, what: &str, f: impl Fn(&Value) -> bool) -> Value {
        let found = tokio::time::timeout(
            TIMEOUT,
            wait_for(TIMEOUT, || self.audit().into_iter().find(&f)),
        )
        .await;
        match found {
            Ok(record) => record,
            Err(_) => panic!("no audit record: {what}; log: {:?}", self.audit()),
        }
    }
}

/// A client with its own iroh endpoint, homed on the same test relay and
/// pinning the host, with no direct address for it.
struct Client {
    id: TestIdentity,
    endpoint: IrohEndpoint,
}

impl Client {
    async fn new(host: &Host, id: TestIdentity) -> Self {
        let trust = StaticTrust::empty().with_pin(host.host_fp, Principal::Device("box".into()));
        let endpoint = IrohEndpoint::bind(&id.local, Arc::new(trust), host.relay.config())
            .await
            .expect("bind the client endpoint")
            .with_timeout(Duration::from_secs(5));
        Self { id, endpoint }
    }

    /// Dial the host by its key, over the relay only. The host's endpoint may
    /// not have reached the relay yet, so a dial that fails is retried.
    async fn dial(&self, host: &Host) -> Result<Connection, DialError> {
        let peer = IrohPeer::new(host.host_key);
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            match self.endpoint.dial(&peer).await {
                Err(DialError::Timeout(_) | DialError::Failed(_))
                    if tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                other => return other,
            }
        }
    }
}

/// The path keys of a keyed peer's record. The connection starts on the relay
/// and iroh may move it to a direct loopback path at any moment, so either is
/// right; what is fixed is that `relay` is there exactly when the path is the
/// relay, and then names only scheme, host and port.
fn assert_keyed_path(record: &Value) {
    match record["peer_path"].as_str() {
        Some("relay") => {
            let relay = record["relay"].as_str().expect("relay accompanies relay");
            assert!(relay.starts_with("https://127.0.0.1:"), "{record}");
            assert!(!relay.contains("/relay"), "{record}");
        }
        Some("direct") => assert!(record.get("relay").is_none(), "{record}"),
        other => panic!("peer_path {other:?} in {record}"),
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

fn open_req() -> qsh_proto::wire::SessionOpen {
    qsh_proto::wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// A client with a pinned key runs `exec` and opens a session through `qsh
/// serve` over the relay, and the audit records name it as an iroh peer on a
/// relay path. `serve.json` records the endpoint, and SIGTERM's shutdown
/// closes the connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_iroh_client_runs_exec_and_a_session_through_serve() {
    let client_id = make_identity();
    let mut host = Host::start(Runtime::Serve, Iroh::OnTestRelay, &[&client_id]).await;
    let client = Client::new(&host, client_id).await;

    // serve.json names the endpoint (docs/CLI.md 6.12).
    let record = host.record_at_bind.clone().expect("serve.json at bind");
    let iroh = record.iroh.expect("serve.json has an iroh object");
    assert_eq!(iroh.endpoint_id, host.host_fp.to_string());
    assert!(
        iroh.relay.starts_with("https://127.0.0.1:"),
        "{}",
        iroh.relay
    );

    let conn = client.dial(&host).await.expect("dial by key");
    let mut session = Session::negotiate(conn.clone(), "laptop")
        .await
        .expect("hello over the relay");
    let ran = tokio::time::timeout(
        TIMEOUT,
        session.exec(&exec_spec(&["sh", "-c", "echo hi; exit 3"]), None, None),
    )
    .await
    .expect("exec finishes")
    .expect("exec");
    assert_eq!(ran.stdout, b"hi\n");
    assert_eq!(ran.exit_code, 3);

    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open over the relay");
    let listed = session.session_list().await.expect("session.list");
    assert!(
        listed.iter().any(|s| s.session_id == opened.session_id),
        "{listed:?}"
    );

    // The record of the exec: an iroh peer on a relay path, the relay named
    // by scheme and host only.
    let fp = client.id.fingerprint;
    let exec = host
        .audit_record("the exec.run allow record", |r| {
            r["action"] == "exec.run" && r["decision"] == "allow"
        })
        .await;
    assert_eq!(exec["peer_addr"], format!("iroh:{fp}"), "{exec}");
    assert_keyed_path(&exec);
    assert_eq!(exec["principal"], "device:laptop", "{exec}");
    assert_eq!(exec["auth_path"], "pin", "{exec}");

    // The shutdown drain closes the relay connection too.
    host.stop().await;
    tokio::time::timeout(TIMEOUT, conn.closed())
        .await
        .expect("the connection ends when the host shuts down");
    client.endpoint.close().await;
}

/// A key the host does not pin gets no further than the handshake: no
/// session, no ticket, no connection slot, and one `connect` deny record
/// naming the iroh peer.
#[tokio::test(flavor = "multi_thread")]
async fn an_unpinned_iroh_key_is_refused_and_creates_nothing() {
    let pinned = make_identity();
    let mut host = Host::start(Runtime::Serve, Iroh::OnTestRelay, &[&pinned]).await;
    // The client has a key the host never pinned; it pins the host, so its
    // own dial check passes and the refusal is the host's.
    let client = Client::new(&host, make_identity()).await;
    let conn = client.dial(&host).await.expect("the handshake completes");
    let negotiated = Session::negotiate(conn, "laptop").await;
    assert!(negotiated.is_err(), "an unpinned key must not get a Hello");

    let fp = client.id.fingerprint;
    let denied = host
        .audit_record("the handshake rejection", |r| {
            r["action"] == "connect" && r["decision"] == "deny"
        })
        .await;
    assert_eq!(denied["resource"], "untrusted", "{denied}");
    assert_eq!(denied["peer_addr"], format!("iroh:{fp}"), "{denied}");
    assert_keyed_path(&denied);
    assert_eq!(denied["principal"], "-", "{denied}");

    let server = host.server.clone().expect("the serve runtime's server");
    let activity = server.activity();
    assert_eq!(activity.sessions, 0);
    assert_eq!(activity.connections, 0);
    assert_eq!(server.pending_tickets(), 0);
    // Nothing past the handshake was decided for it.
    assert!(
        host.audit()
            .iter()
            .all(|r| r["action"] == "connect" && r["decision"] == "deny"),
        "{:?}",
        host.audit()
    );
    host.stop().await;
    client.endpoint.close().await;
}

/// `qsh listen --serve` accepts a forward connection on its iroh endpoint and
/// serves it as the forward host it also is.
#[tokio::test(flavor = "multi_thread")]
async fn listen_serve_accepts_an_iroh_forward_connection() {
    let client_id = make_identity();
    let mut host = Host::start(Runtime::ListenServe, Iroh::OnTestRelay, &[&client_id]).await;
    let client = Client::new(&host, client_id).await;

    let record = host.record_at_bind.clone().expect("serve.json at bind");
    assert_eq!(
        record.iroh.expect("an iroh object").endpoint_id,
        host.host_fp.to_string()
    );

    let conn = client.dial(&host).await.expect("dial by key");
    let mut session = Session::negotiate(conn, "laptop")
        .await
        .expect("hello over the relay");
    let ran = tokio::time::timeout(
        TIMEOUT,
        session.exec(&exec_spec(&["sh", "-c", "printf %s combined"]), None, None),
    )
    .await
    .expect("exec finishes")
    .expect("exec");
    assert_eq!(ran.stdout, b"combined");
    assert_eq!(ran.exit_code, 0);

    let exec = host
        .audit_record("the exec.run record", |r| r["action"] == "exec.run")
        .await;
    assert_eq!(
        exec["peer_addr"],
        format!("iroh:{}", client.id.fingerprint),
        "{exec}"
    );
    assert_keyed_path(&exec);
    drop(session);
    host.stop().await;
    client.endpoint.close().await;
}

/// The per-key bucket: with `validated_rate_per_source = 1` a key may
/// connect twice in an epoch (a burst of `rate * 2`) and its third
/// connection is closed before anything is served on it, with one audit
/// row naming the key. A second key is not affected by the first one's
/// budget.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_over_its_budget_is_refused_after_the_handshake() {
    let noisy = make_identity();
    let quiet = make_identity();
    let mut host = Host::start_with(
        Runtime::Serve,
        Iroh::OnTestRelay,
        &[&noisy, &quiet],
        |config| config.serve.validated_rate_per_source = Some(1),
    )
    .await;
    let noisy = Client::new(&host, noisy).await;

    let mut sessions = Vec::new();
    for _ in 0..2 {
        let conn = noisy.dial(&host).await.expect("dial");
        sessions.push(Session::negotiate(conn, "laptop").await.expect("hello"));
    }
    let third = noisy.dial(&host).await.expect("the handshake completes");
    assert!(
        Session::negotiate(third, "laptop").await.is_err(),
        "the third connection of the epoch is over the key's budget"
    );
    let denied = host
        .audit_record("the keyed rejection", |r| {
            r["action"] == "connect" && r["resource"] == "validated_rate_limited"
        })
        .await;
    assert_eq!(
        denied["peer_addr"],
        format!("iroh:{}", noisy.id.fingerprint),
        "{denied}"
    );
    assert_keyed_path(&denied);

    // Another key has its own bucket.
    let quiet = Client::new(&host, quiet).await;
    let conn = quiet.dial(&host).await.expect("dial");
    Session::negotiate(conn, "laptop")
        .await
        .expect("a different key is not limited by the first one's budget");

    drop(sessions);
    host.stop().await;
    noisy.endpoint.close().await;
    quiet.endpoint.close().await;
}

/// No `IrohServe`, no endpoint: the host has none, its `serve.json` has no
/// `iroh` object, and an endpoint that is asked for does reach for the relay
/// it is given (the control for the quiet case: the relay here is a TCP
/// listener that counts the connections made to it).
#[tokio::test(flavor = "multi_thread")]
async fn without_an_iroh_serve_there_is_no_endpoint_and_no_relay_contact() {
    // The control: a host given a relay URL reaches for it.
    let decoy = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the decoy");
    let decoy_url = format!("https://{}", decoy.local_addr().expect("addr"));
    let contacts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&contacts);
    let accepter = tokio::spawn(async move {
        loop {
            if decoy.accept().await.is_ok() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });
    let mut asked = Host::start(Runtime::Serve, Iroh::Url(decoy_url), &[]).await;
    assert!(
        asked
            .server
            .as_ref()
            .expect("server")
            .iroh_endpoint()
            .is_some()
    );
    wait_for(TIMEOUT, || {
        (contacts.load(std::sync::atomic::Ordering::SeqCst) > 0).then_some(())
    })
    .await;
    asked.stop().await;
    accepter.abort();

    // The quiet case: no `IrohServe`.
    let mut quiet = Host::start(Runtime::Serve, Iroh::None, &[]).await;
    assert!(
        quiet
            .server
            .as_ref()
            .expect("server")
            .iroh_endpoint()
            .is_none()
    );
    let record = quiet.record_at_bind.clone().expect("serve.json at bind");
    assert!(record.iroh.is_none());
    let raw = std::fs::read_to_string(quiet.paths.serve_record_file()).expect("serve.json");
    assert!(!raw.contains("iroh"), "{raw}");
    quiet.stop().await;
}
