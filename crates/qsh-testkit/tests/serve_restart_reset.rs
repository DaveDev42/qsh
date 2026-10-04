//! L3: a restarted `qsh serve` resets the clients it forgot, and they learn
//! it in one round trip (`docs/adr/0036-stateless-reset-key.md`,
//! `docs/design/reexec-estimate.md` §3 H1b, `docs/design/protocol.md` §10
//! "Path 사망 감지").
//!
//! The host here is wired exactly like `qsh serve`'s listener:
//! [`qsh_core::reset_key::bind_listener`] over a real config directory, so
//! the key file, the 0600 mode and the transport injection are the
//! production ones. It runs on a runtime of its own; a "restart" drops that
//! runtime, which drops every task unpolled and so, like `SIGKILL`, sends no
//! `CONNECTION_CLOSE`. A second host then takes the same UDP port.
//!
//! What a client must see, and what it must not:
//!
//! * with the key file kept, the first packet the client sends after the
//!   restart is answered with a stateless reset, the connection ends with
//!   `ConnectionError::Reset`, and that happens inside `REDIAL_DEADLINE`
//!   (2 s), far under the 45 s idle timeout;
//! * the session is still gone: a resume attempt on the new host fails with
//!   the existing `AUTH_FAILED` (`docs/CLI.md` §6.3, §6.4), the same answer a
//!   never-existing session gets (`docs/design/protocol.md` §10, the
//!   non-distinguishing rule);
//! * with the key file deleted before the restart, no reset arrives and
//!   detection is left to path watch.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use qsh_core::acl::AllowAllPinned;
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, BrokerConfig, PipeFactory, SystemClock};
use qsh_core::client::reconnect::REDIAL_DEADLINE;
use qsh_core::client::{ClientError, Session};
use qsh_core::config::Paths;
use qsh_core::server::Server;
use qsh_proto::ErrorCode;
use qsh_proto::wire;
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_transport::endpoint::MAX_IDLE_TIMEOUT;
use qsh_transport::{ConnectionError, Dialer, Principal, StaticTrust};

/// One `qsh serve`-shaped host on its own runtime and thread.
struct Host {
    addr: SocketAddr,
    crash: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
    diagnostic: Option<String>,
}

impl Host {
    fn start(
        paths: &Paths,
        bind: SocketAddr,
        server: &TestIdentity,
        client: &TestIdentity,
    ) -> Self {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (crash, crash_rx) = mpsc::channel::<()>();
        let paths = paths.clone();
        let identity = server.local.clone();
        let client_fp = client.fingerprint;
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let _guard = rt.enter();
            let trust =
                StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
            let (listener, diagnostic) = qsh_core::reset_key::bind_listener(
                &paths,
                bind,
                identity,
                Arc::new(trust),
                qsh_transport::TransportTuning::default(),
            )
            .expect("bind the host listener");
            ready_tx
                .send((listener.local_addr().unwrap(), diagnostic))
                .unwrap();
            let broker = Broker::new(
                Arc::new(SystemClock),
                BrokerConfig {
                    replay_bytes: 64 * 1024,
                    resume_ttl: Duration::from_secs(3600),
                    close_grace: Duration::from_millis(100),
                    quota_limits: Default::default(),
                },
                Arc::new(PipeFactory::new(64 * 1024)),
            );
            tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
            let gate = qsh_core::admission::Gate::new(
                Arc::new(SystemClock),
                qsh_core::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
                qsh_core::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
                qsh_core::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
            );
            let server = Server::with_admission(
                Arc::new(AllowAllPinned),
                Arc::new(MemoryAuditSink::new()),
                broker,
                "box",
                gate,
            );
            tokio::spawn(server.run(listener, std::future::pending::<()>()));
            let _ = crash_rx.recv();
            drop(_guard);
            drop(rt);
        });
        let (addr, diagnostic) = ready_rx.recv().expect("the host came up");
        Self {
            addr,
            crash,
            thread,
            diagnostic,
        }
    }

    /// Kill the host without a goodbye and return the port it held.
    fn crash(self) -> SocketAddr {
        self.crash.send(()).unwrap();
        self.thread.join().unwrap();
        self.addr
    }
}

struct World {
    _dir: tempfile::TempDir,
    paths: Paths,
    server: TestIdentity,
    client: TestIdentity,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        std::fs::create_dir_all(dir.path().join("config")).unwrap();
        Self {
            _dir: dir,
            paths,
            server: make_identity(),
            client: make_identity(),
        }
    }

    fn key_file(&self) -> PathBuf {
        self.paths.stateless_reset_key_file()
    }

    fn dialer(&self) -> Dialer {
        let trust =
            StaticTrust::empty().with_pin(self.server.fingerprint, Principal::Device("box".into()));
        Dialer::new(self.client.local.clone(), Arc::new(trust))
    }

    fn start_host(&self, bind: SocketAddr) -> Host {
        Host::start(&self.paths, bind, &self.server, &self.client)
    }
}

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// An attached client: the session, its resume credential, the live data
/// stream and the endpoint keeping the connection's socket open.
struct Attached {
    session: Session,
    session_id: String,
    resume_token: Vec<u8>,
    _data: qsh_transport::FramedStream,
    _endpoint: qsh_transport::Endpoint,
}

async fn attach_client(world: &World, addr: SocketAddr) -> Attached {
    let dialed = world
        .dialer()
        .dial(addr, "127.0.0.1")
        .await
        .expect("dial the host");
    let endpoint = dialed.endpoint.clone();
    let mut session = Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate");
    let opened = session
        .session_open(open_req())
        .await
        .expect("session.open");
    let (send, recv) = session.connection().open_bi().await.expect("open_bi");
    let mut data = qsh_transport::FramedStream::data(send, recv);
    data.send
        .send(&wire::StreamHeader::session_data(opened.ticket))
        .await
        .expect("stream header");
    Attached {
        session,
        session_id: opened.session_id,
        resume_token: opened.resume_token,
        _data: data,
        _endpoint: endpoint,
    }
}

/// The first packet after the restart, then how long the connection took
/// to end (`None` when it was still open after `window`).
async fn first_packet_then_wait(
    attached: &Attached,
    window: Duration,
) -> Option<(Duration, ConnectionError)> {
    let started = Instant::now();
    let (mut send, _recv) = attached
        .session
        .connection()
        .quinn()
        .open_bi()
        .await
        .expect("open_bi on the doomed connection");
    let _ = send.write_all(b"first packet after the restart").await;
    tokio::time::timeout(window, attached.session.connection().closed())
        .await
        .ok()
        .map(|err| (started.elapsed(), err))
}

#[tokio::test]
async fn restarted_serve_resets_an_attached_client_within_the_redial_deadline_and_reports_the_session_lost()
 {
    let world = World::new();
    let host = world.start_host("127.0.0.1:0".parse().unwrap());
    assert!(host.diagnostic.is_none(), "{:?}", host.diagnostic);
    let key_before = std::fs::read(world.key_file()).expect("the key file was created");
    let attached = attach_client(&world, host.addr).await;

    let addr = host.crash();
    let restarted = world.start_host(addr);
    assert!(restarted.diagnostic.is_none(), "{:?}", restarted.diagnostic);
    assert_eq!(
        std::fs::read(world.key_file()).unwrap(),
        key_before,
        "the restart reuses the key"
    );

    let (elapsed, err) = first_packet_then_wait(&attached, REDIAL_DEADLINE)
        .await
        .expect("a stateless reset ends the connection inside REDIAL_DEADLINE");
    assert!(
        matches!(err, ConnectionError::Reset),
        "expected a stateless reset, got {err:?}"
    );
    assert!(
        elapsed < REDIAL_DEADLINE && elapsed < MAX_IDLE_TIMEOUT / 10,
        "detection took {elapsed:?}"
    );

    // The session is gone with the old process: the resume attempt fails
    // with the existing attach failure code, and says exactly what a
    // session that never existed says.
    let dialed = world
        .dialer()
        .dial(addr, "127.0.0.1")
        .await
        .expect("redial the restarted host");
    let _endpoint = dialed.endpoint.clone();
    let mut redialed = Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate");
    let attach = |session_id: String, resume_token: Vec<u8>| wire::SessionAttach {
        session_id,
        resume_token,
        last_output_seq: 0,
        mode: wire::AttachMode::Rw as i32,
        no_steal: false,
    };
    let lost = redialed
        .attach(attach(
            attached.session_id.clone(),
            attached.resume_token.clone(),
        ))
        .await
        .err()
        .expect("the old session does not exist on the new host");
    let never = redialed
        .attach(attach("01NEVEREXISTED".into(), vec![9; 32]))
        .await
        .err()
        .expect("a session that never existed is refused");
    let (
        ClientError::Remote {
            code: lost_code,
            message: lost_message,
            ..
        },
        ClientError::Remote {
            code: never_code,
            message: never_message,
            ..
        },
    ) = (&lost, &never)
    else {
        panic!("expected two remote errors, got {lost:?} and {never:?}");
    };
    assert_eq!(*lost_code, ErrorCode::AuthFailed);
    assert_eq!((lost_code, lost_message), (never_code, never_message));

    restarted.crash();
}

#[tokio::test]
async fn a_serve_restarted_with_a_new_key_leaves_detection_to_path_watch() {
    let world = World::new();
    let host = world.start_host("127.0.0.1:0".parse().unwrap());
    let key_before = std::fs::read(world.key_file()).expect("the key file was created");
    let attached = attach_client(&world, host.addr).await;

    let addr = host.crash();
    std::fs::remove_file(world.key_file()).unwrap();
    let restarted = world.start_host(addr);
    assert_ne!(
        std::fs::read(world.key_file()).unwrap(),
        key_before,
        "deleting the file yields a new key"
    );

    // No reset can be recognised: the connection stays open for at least
    // as long as the positive case needed to close it, plus a margin. It is
    // path watch (`protocol.md` §10), not QUIC, that declares it dead.
    let outcome =
        first_packet_then_wait(&attached, REDIAL_DEADLINE + Duration::from_millis(500)).await;
    assert!(
        outcome.is_none(),
        "a reset from another key must be ignored, got {outcome:?}"
    );
    restarted.crash();
}
