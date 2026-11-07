//! The hole-punching signalling path end to end over netsim (ADR-0054
//! decisions 6, 10, 11, 12, 14; `docs/design/protocol.md` §19).
//!
//! A (the initiator), R (a `qsh listen`) and B (the real `qsh serve --to`
//! entry, `run_reverse_on`) each sit on their own virtual site, A and B behind
//! port-restricted NAT boxes. A dials R, sends a `PunchRequest`, R relays a
//! `PunchOffer` over B's registration connection, B opens its window and
//! answers, R answers A, and A runs the punching schedule against what it was
//! given and then speaks the ordinary protocol over the adopted connection.
//!
//! The real `host_runtime` runs on B, so the tests use the real clock.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use qsh_core::acl::{Action, AllowAllPinned, Authorizer, Requester, ResourceRef, Verdict};
use qsh_core::audit::{AuditRecord, MemoryAuditSink};
use qsh_core::broker::SystemClock;
use qsh_core::client::Session;
use qsh_core::config::{Config, Paths};
use qsh_core::exec::ExecSpec;
use qsh_core::handshake;
use qsh_core::punch::{FixedAddrs, InitiatorParams, PUNCH_WINDOW, RENDEZVOUS_IDLE, run_initiator};
use qsh_core::reverse::listen::Listen;
use qsh_core::reverse::registry::Registry;
use qsh_core::reverse::target::{ReverseOptions, run_reverse_on};
use qsh_core::shell::ShellRequest;
use qsh_core::trust::{TrustRole, TrustStore};
use qsh_proto::wire::{
    self, ControlMessage, PunchCandidate, PunchCandidateKind, PunchRefusal, PunchRequest,
    RendezvousQuery, control_message, response,
};
use qsh_testkit::make_identity;
use qsh_testkit::netsim::{NatKind, Net, NetConfig, PathConfig, Site};
use qsh_testkit::reverse::{forward_hello, loaded_identity, wait_for};
use qsh_transport::{
    Connection, Fingerprint, FramedStream, Listener, Principal, PunchEndpoint, SocketSource,
    StaticTrust, TransportTuning,
};
use tokio::sync::oneshot;

const R_ADDR: &str = "203.0.113.1:9000";
const A_PORT: u16 = 5000;
const B_PORT: u16 = 6000;
const TIMEOUT: Duration = Duration::from_secs(20);

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// R's authorizer: everything a pinned peer may do, except `host.punch`
/// while `deny_punch` is set.
struct RAuth {
    deny_punch: Arc<AtomicBool>,
}

impl Authorizer for RAuth {
    fn check(
        &self,
        requester: &Requester<'_>,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict {
        if action == Action::HostPunch && self.deny_punch.load(Ordering::Relaxed) {
            return Verdict::DENY;
        }
        AllowAllPinned.check(requester, action, resource)
    }
}

struct Rig {
    c: PunchEndpoint,
    r_listen: Arc<Listen>,
    r_audit: Arc<MemoryAuditSink>,
    r_fp: Fingerprint,
    deny_punch: Arc<AtomicBool>,
    a: PunchEndpoint,
    a_site: Site,
    a_fp: Fingerprint,
    b_fp: Fingerprint,
    b_server: Arc<qsh_core::server::Server>,
    b_audit_path: std::path::PathBuf,
    b_shutdown: Option<oneshot::Sender<()>>,
    b_task: Option<tokio::task::JoinHandle<()>>,
    r_shutdown: Option<oneshot::Sender<()>>,
    r_task: tokio::task::JoinHandle<()>,
    _net: Net,
    _dir: tempfile::TempDir,
}

struct RigOptions {
    /// B's role for A; `None` pins A with `TrustRole::None` (identity only).
    b_role_for_a: TrustRole,
    /// Whether B registers with R at all.
    register_b: bool,
    /// R's authorizer; `None` is the `RAuth` of the rig.
    r_authorizer: Option<Arc<dyn Authorizer>>,
    /// B's NAT. An unfiltered B lets a third party reach the open window.
    b_nat: NatKind,
}

impl Default for RigOptions {
    fn default() -> Self {
        Self {
            b_role_for_a: TrustRole::Full,
            register_b: true,
            r_authorizer: None,
            b_nat: NatKind::PortRestricted,
        }
    }
}

async fn rig(opts: RigOptions) -> Rig {
    let net = Net::new(NetConfig {
        seed: 7,
        ..NetConfig::default()
    });
    let r_site = net.internet().site(NatKind::None, "r", ip("203.0.113.1"));
    let a_site = net
        .internet()
        .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
    let b_site = net.internet().site(opts.b_nat, "b", ip("198.51.100.2"));
    let c_site = net.internet().site(NatKind::None, "c", ip("198.51.100.3"));
    net.set_path(
        a_site.external_ip(),
        b_site.external_ip(),
        PathConfig::delay(Duration::from_millis(25)),
    );

    let (r_id, a_id, b_id, c_id) = (
        make_identity(),
        make_identity(),
        make_identity(),
        make_identity(),
    );

    // R: a `qsh listen` on the virtual network.
    let r_trust = StaticTrust::empty()
        .with_pin(a_id.fingerprint, Principal::Device("a".into()))
        .with_pin(b_id.fingerprint, Principal::Device("b".into()));
    let r_listener = Listener::bind_virtual(
        Arc::new(r_site.bind_wildcard(9000).unwrap()),
        r_id.local.clone(),
        Arc::new(r_trust),
        TransportTuning::default(),
    )
    .unwrap();
    let r_audit = Arc::new(MemoryAuditSink::new());
    let deny_punch = Arc::new(AtomicBool::new(false));
    let clock: Arc<dyn qsh_core::broker::Clock> = Arc::new(SystemClock);
    let r_listen = Listen::new(
        Registry::new(clock.clone(), false),
        opts.r_authorizer.clone().unwrap_or_else(|| {
            Arc::new(RAuth {
                deny_punch: deny_punch.clone(),
            })
        }),
        r_audit.clone(),
        "controller-device",
        clock,
        Duration::from_secs(120),
    );
    let (r_tx, r_rx) = oneshot::channel::<()>();
    let r_task = tokio::spawn(r_listen.clone().run(r_listener, async move {
        let _ = r_rx.await;
    }));

    // B: the real `qsh serve --to r` entry on the virtual network.
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    let mut trust = TrustStore::default();
    trust.add_peer(
        "r",
        Some(R_ADDR.to_string()),
        r_id.fingerprint,
        "2026-01-01T00:00:00Z".to_string(),
    );
    trust.add_peer_with_role(
        "a",
        None,
        a_id.fingerprint,
        "2026-01-01T00:00:00Z".to_string(),
        opts.b_role_for_a,
    );
    // A third peer B knows and trusts at the TLS layer, never the initiator.
    trust.add_peer_with_role(
        "c",
        None,
        c_id.fingerprint,
        "2026-01-01T00:00:00Z".to_string(),
        TrustRole::Full,
    );
    trust.save(&paths.trust_file()).unwrap();
    qsh_core::config::write_private_file(
        &paths.acl_file(),
        b"[[acl]]\nprincipal = \"device:r\"\nallow = [\"host.reverse\"]\n",
    )
    .unwrap();

    let (server_tx, server_rx) = std::sync::mpsc::channel();
    let (b_tx, b_rx) = oneshot::channel::<()>();
    let b_socket = b_site.bind_wildcard(B_PORT).unwrap();
    let b_local = b_site.ip();
    let b_task = opts.register_b.then(|| {
        let b_identity = loaded_identity(&b_id, "b");
        let paths = paths.clone();
        tokio::spawn(async move {
            let options = ReverseOptions {
                socket: SocketSource::Virtual(Arc::new(b_socket)),
                local_addrs: Arc::new(FixedAddrs(vec![b_local])),
                ..ReverseOptions::default()
            };
            let _ = run_reverse_on(
                &paths,
                &Config::default(),
                b_identity,
                "r",
                None,
                options,
                move |runtime| {
                    let _ = server_tx
                        .send((runtime.server.clone(), runtime.audit.path().to_path_buf()));
                },
                || {},
                async move {
                    let _ = b_rx.await;
                },
            )
            .await;
        })
    });

    let (b_server, b_audit_path) = if opts.register_b {
        let (server, path) = wait_for(TIMEOUT, || server_rx.try_recv().ok()).await;
        // Registered: R holds a live hub for B, and B knows its controller.
        let target = server.punch_target().expect("punch target").clone();
        let r_fp = r_id.fingerprint;
        wait_for(TIMEOUT, || {
            target
                .rendezvous_fingerprints()
                .contains(r_fp.as_bytes())
                .then_some(())
        })
        .await;
        wait_for(TIMEOUT, || r_listen.hubs_snapshot().first().map(|_| ())).await;
        (server, path)
    } else {
        // No B process: a server stub nothing talks to.
        let id = make_identity();
        let _ = id;
        (
            qsh_core::server::Server::new(
                Arc::new(qsh_core::acl::DenyAll),
                Arc::new(MemoryAuditSink::new()),
                qsh_core::broker::Broker::new(
                    Arc::new(SystemClock),
                    qsh_core::broker::BrokerConfig {
                        replay_bytes: 1024,
                        resume_ttl: Duration::from_secs(1),
                        close_grace: Duration::from_millis(10),
                        quota_limits: qsh_core::quota::QuotaLimits::default(),
                    },
                    Arc::new(qsh_core::broker::PipeFactory::new(1024)),
                ),
                "unused",
            ),
            dir.path().join("none.jsonl"),
        )
    };

    // A: a punching endpoint behind its NAT, trusting R and B.
    let a_trust = StaticTrust::empty()
        .with_pin(r_id.fingerprint, Principal::Device("r".into()))
        .with_pin(b_id.fingerprint, Principal::Device("b".into()));
    let a = PunchEndpoint::new(
        SocketSource::Virtual(Arc::new(a_site.bind_wildcard(A_PORT).unwrap())),
        a_id.local.clone(),
        Arc::new(a_trust),
        TransportTuning::default(),
    )
    .unwrap();

    let c_trust = StaticTrust::empty().with_pin(b_id.fingerprint, Principal::Device("b".into()));
    let c = PunchEndpoint::new(
        SocketSource::Virtual(Arc::new(c_site.bind_wildcard(7000).unwrap())),
        c_id.local.clone(),
        Arc::new(c_trust),
        TransportTuning::default(),
    )
    .unwrap();

    Rig {
        c,
        r_listen,
        r_audit,
        r_fp: r_id.fingerprint,
        deny_punch,
        a,
        a_fp: a_id.fingerprint,
        a_site,
        b_fp: b_id.fingerprint,
        b_server,
        b_audit_path,
        b_shutdown: Some(b_tx),
        b_task,
        r_shutdown: Some(r_tx),
        r_task,
        _net: net,
        _dir: dir,
    }
}

impl Rig {
    /// A new connection from A to R, past the `Hello` exchange.
    async fn dial_r(&self) -> (Connection, FramedStream) {
        let conn = self
            .a
            .dial(
                R_ADDR.parse().unwrap(),
                "qsh",
                Duration::from_millis(100),
                &self.r_fp,
            )
            .await
            .expect("A dials R");
        let (ctl, _peer) = handshake::initiate(&conn, forward_hello())
            .await
            .expect("R accepts the punching connection");
        (conn, ctl)
    }

    fn a_host(&self) -> SocketAddr {
        SocketAddr::new(self.a_site.ip(), A_PORT)
    }

    fn request(&self, attempt: [u8; 16], target: &Fingerprint) -> PunchRequest {
        PunchRequest {
            attempt_id: attempt.to_vec(),
            target_fingerprint: target.as_bytes().to_vec(),
            candidates: vec![PunchCandidate::from_addr(
                self.a_host(),
                PunchCandidateKind::Host,
            )],
        }
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.b_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.b_task.take() {
            let _ = tokio::time::timeout(TIMEOUT, task).await;
        }
        self.a.close(0, b"done");
        self.c.close(0, b"done");
        if let Some(tx) = self.r_shutdown.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(TIMEOUT, &mut self.r_task).await;
    }
}

async fn ask(ctl: &mut FramedStream, id: u64, body: control_message::Body) -> ControlMessage {
    ctl.send.send(&ControlMessage::new(id, body)).await.unwrap();
    tokio::time::timeout(TIMEOUT, ctl.recv.recv::<ControlMessage>())
        .await
        .expect("a reply arrives")
        .expect("no stream error")
        .expect("the stream stays open until the reply")
}

fn reply_body(msg: ControlMessage) -> response::Body {
    match msg.body {
        Some(control_message::Body::Response(wire::Response { body: Some(b) })) => b,
        other => panic!("expected a response, got {other:?}"),
    }
}

fn error_code(msg: ControlMessage) -> String {
    match reply_body(msg) {
        response::Body::Error(e) => e.code,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn punch_records(records: &[AuditRecord]) -> Vec<&AuditRecord> {
    records
        .iter()
        .filter(|r| r.action == "host.punch")
        .collect()
}

fn b_punch_lines(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("host.punch"))
        .map(str::to_string)
        .collect()
}

fn shell(command: &str) -> ExecSpec {
    ExecSpec {
        argv: vec![],
        env: vec![],
        timeout: None,
        shell: Some(ShellRequest::Command(command.into())),
    }
}

fn attempt(n: u8) -> [u8; 16] {
    [n; 16]
}

/// The whole path: signal, punch, adopted connection, exec over it. Also the
/// audit and log shape: three `host.punch` decisions' worth of structure and
/// no address anywhere.
#[tokio::test(flavor = "multi_thread")]
async fn punch_signal_then_punch_then_adopted_connection_runs_exec() {
    let rig = rig(RigOptions::default()).await;
    let (conn, mut ctl) = rig.dial_r().await;

    let req = rig.request(attempt(1), &rig.b_fp);
    let msg = ask(&mut ctl, 1, control_message::Body::PunchRequest(req)).await;
    let reply = match reply_body(msg) {
        response::Body::PunchReply(r) => r,
        other => panic!("expected a PunchReply, got {other:?}"),
    };
    assert_eq!(reply.refusal, PunchRefusal::None as i32);
    assert!(
        reply.candidates.len() >= 2,
        "B's host and reflexive addresses: {:?}",
        reply.candidates
    );
    assert!(
        reply.initiator_reflexive.is_some(),
        "R tells A the address it saw"
    );
    assert!(!reply.target_reflexive_private);
    assert!(
        reply
            .candidates
            .iter()
            .any(|c| c.kind == PunchCandidateKind::Reflexive as i32),
        "the reflexive of B is among them"
    );

    let candidates: Vec<SocketAddr> = reply
        .candidates
        .iter()
        .filter_map(PunchCandidate::socket_addr)
        .collect();
    let adopted = run_initiator(
        &rig.a,
        &InitiatorParams {
            attempt_id: attempt(1),
            expected_peer: rig.b_fp,
            candidates,
            budget: PUNCH_WINDOW,
        },
    )
    .await
    .expect("the punch opens a connection");

    // R's job is over; the punching connection goes away by itself.
    conn.close(0, b"done");

    let mut session = Session::negotiate(adopted.connection.clone(), "a")
        .await
        .expect("the host negotiates over the adopted connection");
    let out = tokio::time::timeout(TIMEOUT, session.exec(&shell("echo punched"), None, None))
        .await
        .expect("exec returns")
        .expect("exec runs");
    assert_eq!(out.exit_code, 0);
    assert!(String::from_utf8_lossy(&out.stdout).contains("punched"));

    // `RendezvousQuery` over the adopted connection: B names R.
    session
        .send_control_message(&ControlMessage::new(
            77,
            control_message::Body::RendezvousQuery(RendezvousQuery {}),
        ))
        .await
        .unwrap();
    let list = loop {
        let msg = tokio::time::timeout(TIMEOUT, session.next_control_message())
            .await
            .expect("the list arrives")
            .unwrap()
            .expect("the connection stays open");
        if msg.request_id == 77 {
            break reply_body(msg);
        }
    };
    match list {
        response::Body::RendezvousList(l) => {
            assert_eq!(l.fingerprints, vec![rig.r_fp.as_bytes().to_vec()]);
        }
        other => panic!("expected a RendezvousList, got {other:?}"),
    }
    adopted.connection.close(0, b"done");

    // The window closes after the schedule; nothing stays open.
    let target = rig.b_server.punch_target().unwrap().clone();
    wait_for(TIMEOUT, || (target.open_windows() == 0).then_some(())).await;
    wait_for(TIMEOUT, || {
        (rig.r_listen.punch_connections() == 0).then_some(())
    })
    .await;

    // Audit: R recorded `punch.request`, B recorded `punch.offer`, and no
    // record or log line holds an address.
    let r_records = rig.r_audit.records();
    let requests: Vec<_> = r_records
        .iter()
        .filter(|r| r.resource == "punch.request")
        .collect();
    assert_eq!(requests.len(), 1, "{r_records:?}");
    assert_eq!(requests[0].decision, "allow");
    assert_eq!(requests[0].action, "host.punch");
    assert_eq!(requests[0].peer_addr, "-");
    assert_eq!(requests[0].principal, "device:a");
    wait_for(TIMEOUT, || {
        let lines = b_punch_lines(&rig.b_audit_path);
        lines
            .iter()
            .any(|l| l.contains("punch.offer"))
            .then_some(())
    })
    .await;
    for needle in ["198.51.100", "203.0.113", "10.", ":5000", ":6000", ":9000"] {
        for r in punch_records(&r_records) {
            assert!(
                !format!("{r:?}").contains(needle),
                "R audit record holds {needle}: {r:?}"
            );
        }
        for l in b_punch_lines(&rig.b_audit_path) {
            assert!(!l.contains(needle), "B audit line holds {needle}: {l}");
        }
    }

    rig.shutdown().await;
}

/// R without `host.punch` for A: the request is refused with the uniform
/// denial, B never hears of it, and R has no state left.
#[tokio::test(flavor = "multi_thread")]
async fn a_punch_request_without_host_punch_reaches_no_target() {
    let rig = rig(RigOptions::default()).await;
    rig.deny_punch.store(true, Ordering::Relaxed);
    let (_conn, mut ctl) = rig.dial_r().await;

    let msg = ask(
        &mut ctl,
        1,
        control_message::Body::PunchRequest(rig.request(attempt(2), &rig.b_fp)),
    )
    .await;
    assert_eq!(error_code(msg), "PERMISSION_DENIED");

    let records = rig.r_audit.records();
    let punch = punch_records(&records);
    assert_eq!(punch.len(), 1, "{records:?}");
    assert_eq!(punch[0].decision, "deny");
    assert_eq!(punch[0].resource, "punch.request");

    // B got nothing: no window, no datagram, no offer record.
    let target = rig.b_server.punch_target().unwrap();
    assert_eq!(target.open_windows(), 0);
    assert_eq!(target.endpoint().stats().punch_sent, 0);
    assert!(b_punch_lines(&rig.b_audit_path).is_empty());

    rig.shutdown().await;
}

/// B does not grant `host.punch` to A: R relays, B refuses before any window,
/// and A is told `TARGET_DENIED`, nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn a_punch_offer_for_an_unauthorized_initiator_opens_no_window() {
    let rig = rig(RigOptions {
        b_role_for_a: TrustRole::None,
        ..RigOptions::default()
    })
    .await;
    let (_conn, mut ctl) = rig.dial_r().await;

    let msg = ask(
        &mut ctl,
        1,
        control_message::Body::PunchRequest(rig.request(attempt(3), &rig.b_fp)),
    )
    .await;
    match reply_body(msg) {
        response::Body::PunchReply(r) => {
            assert_eq!(r.refusal, PunchRefusal::TargetDenied as i32);
            assert!(r.candidates.is_empty());
        }
        other => panic!("expected a refusing PunchReply, got {other:?}"),
    }

    let target = rig.b_server.punch_target().unwrap();
    assert_eq!(target.open_windows(), 0);
    assert_eq!(target.endpoint().stats().punch_sent, 0);
    wait_for(TIMEOUT, || {
        b_punch_lines(&rig.b_audit_path)
            .iter()
            .any(|l| l.contains("punch.offer") && l.contains("deny"))
            .then_some(())
    })
    .await;

    rig.shutdown().await;
}

/// A target nobody registered: `TARGET_NOT_REGISTERED`, no state.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_for_an_unregistered_target_is_refused() {
    let rig = rig(RigOptions {
        register_b: false,
        ..RigOptions::default()
    })
    .await;
    let (_conn, mut ctl) = rig.dial_r().await;

    let msg = ask(
        &mut ctl,
        1,
        control_message::Body::PunchRequest(rig.request(attempt(4), &rig.b_fp)),
    )
    .await;
    match reply_body(msg) {
        response::Body::PunchReply(r) => {
            assert_eq!(r.refusal, PunchRefusal::TargetNotRegistered as i32);
        }
        other => panic!("expected a refusing PunchReply, got {other:?}"),
    }
    assert!(rig.r_listen.hubs_snapshot().is_empty());
    rig.shutdown().await;
}

/// Seven attempts of one initiator in a minute: the seventh is refused with
/// `RESOURCE_EXHAUSTED` at R, before it looks for a registration.
#[tokio::test(flavor = "multi_thread")]
async fn rendezvous_rate_limits_an_initiator() {
    let rig = rig(RigOptions {
        register_b: false,
        ..RigOptions::default()
    })
    .await;
    for n in 0..6u8 {
        let (_conn, mut ctl) = rig.dial_r().await;
        let msg = ask(
            &mut ctl,
            1,
            control_message::Body::PunchRequest(rig.request(attempt(10 + n), &rig.b_fp)),
        )
        .await;
        match reply_body(msg) {
            response::Body::PunchReply(r) => {
                assert_eq!(
                    r.refusal,
                    PunchRefusal::TargetNotRegistered as i32,
                    "try {n}"
                );
            }
            other => panic!("try {n}: {other:?}"),
        }
    }
    let (_conn, mut ctl) = rig.dial_r().await;
    let msg = ask(
        &mut ctl,
        1,
        control_message::Body::PunchRequest(rig.request(attempt(99), &rig.b_fp)),
    )
    .await;
    assert_eq!(error_code(msg), "RESOURCE_EXHAUSTED");
    rig.shutdown().await;
}

/// Candidates that fail the validator are dropped and counted; a request with
/// nothing but such candidates still reaches B (the reflexive R adds makes
/// the offer usable), while one with more than eight is an error.
#[tokio::test(flavor = "multi_thread")]
async fn invalid_candidates_are_dropped_and_too_many_are_refused() {
    let rig = rig(RigOptions {
        register_b: false,
        ..RigOptions::default()
    })
    .await;

    let (_c1, mut ctl) = rig.dial_r().await;
    let mut req = rig.request(attempt(20), &rig.b_fp);
    req.candidates = (0..9)
        .map(|i| {
            PunchCandidate::from_addr(
                SocketAddr::new(ip("198.51.100.9"), 4000 + i),
                PunchCandidateKind::Host,
            )
        })
        .collect();
    let msg = ask(&mut ctl, 1, control_message::Body::PunchRequest(req)).await;
    assert_eq!(error_code(msg), "INVALID_ARGUMENT");

    // Loopback, multicast and a zero port: all dropped, the request goes on
    // (here to "target not registered").
    let (_c2, mut ctl) = rig.dial_r().await;
    let mut req = rig.request(attempt(21), &rig.b_fp);
    req.candidates = vec![
        PunchCandidate {
            ip: vec![127, 0, 0, 1],
            port: 4000,
            kind: PunchCandidateKind::Host as i32,
        },
        PunchCandidate {
            ip: vec![224, 0, 0, 1],
            port: 4000,
            kind: PunchCandidateKind::Host as i32,
        },
        PunchCandidate {
            ip: vec![198, 51, 100, 1],
            port: 0,
            kind: PunchCandidateKind::Host as i32,
        },
    ];
    let msg = ask(&mut ctl, 1, control_message::Body::PunchRequest(req)).await;
    match reply_body(msg) {
        response::Body::PunchReply(r) => {
            assert_eq!(r.refusal, PunchRefusal::TargetNotRegistered as i32);
        }
        other => panic!("{other:?}"),
    }
    rig.shutdown().await;
}

/// A punching connection answers `Ping` and one request, nothing else, and
/// an idle one is closed after `RENDEZVOUS_IDLE`.
#[tokio::test(flavor = "multi_thread")]
async fn a_punching_connection_serves_ping_and_one_request_then_idles_out() {
    let rig = rig(RigOptions {
        register_b: false,
        ..RigOptions::default()
    })
    .await;
    let (conn, mut ctl) = rig.dial_r().await;

    let pong = ask(&mut ctl, 1, control_message::Body::Ping(wire::Ping {})).await;
    assert!(matches!(pong.body, Some(control_message::Body::Pong(_))));

    // Anything else is answered `UNSUPPORTED` and the connection stays.
    let msg = ask(
        &mut ctl,
        2,
        control_message::Body::RendezvousQuery(RendezvousQuery {}),
    )
    .await;
    assert_eq!(error_code(msg), "UNSUPPORTED");
    assert_eq!(rig.r_listen.punch_connections(), 1);

    let started = tokio::time::Instant::now();
    tokio::time::timeout(RENDEZVOUS_IDLE + Duration::from_secs(5), conn.closed())
        .await
        .expect("an idle punching connection is closed");
    assert!(started.elapsed() >= RENDEZVOUS_IDLE - Duration::from_millis(200));
    wait_for(TIMEOUT, || {
        (rig.r_listen.punch_connections() == 0).then_some(())
    })
    .await;
    rig.shutdown().await;
}

/// Two requests of one initiator at once: both are answered (a reply or
/// `RESOURCE_EXHAUSTED`), and no more windows open than attempts made.
#[tokio::test(flavor = "multi_thread")]
async fn only_one_attempt_is_in_flight_per_initiator() {
    let rig = rig(RigOptions::default()).await;
    // Hold B's answer back by occupying the attempt slot: two requests on two
    // connections at once, the second sees the first still in flight or, if
    // the first already finished, a normal reply. Either way no second
    // window is open at the end.
    let (_c1, mut ctl1) = rig.dial_r().await;
    let (_c2, mut ctl2) = rig.dial_r().await;
    let m1 = ControlMessage::new(
        1,
        control_message::Body::PunchRequest(rig.request(attempt(30), &rig.b_fp)),
    );
    let m2 = ControlMessage::new(
        1,
        control_message::Body::PunchRequest(rig.request(attempt(31), &rig.b_fp)),
    );
    let first = ctl1.send.send(&m1);
    let second = ctl2.send.send(&m2);
    first.await.unwrap();
    second.await.unwrap();
    let (m1, m2) = tokio::join!(
        ctl1.recv.recv::<ControlMessage>(),
        ctl2.recv.recv::<ControlMessage>()
    );
    let kinds: Vec<String> = [m1, m2]
        .into_iter()
        .map(|m| {
            let m = m.unwrap().unwrap();
            match reply_body(m) {
                response::Body::PunchReply(_) => "reply".to_string(),
                response::Body::Error(e) => e.code,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    assert!(
        kinds.iter().filter(|k| *k == "reply").count() >= 1,
        "{kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .all(|k| k == "reply" || k == "RESOURCE_EXHAUSTED"),
        "{kinds:?}"
    );
    let target = rig.b_server.punch_target().unwrap().clone();
    assert!(target.open_windows() <= 2);
    rig.shutdown().await;
}

/// For the deny-seam sweep (`acl_uniformity`): a `PunchRequest` sent to a
/// rendezvous whose authorizer is `authorizer`. Returns R's audit sink, the
/// error A got and A's fingerprint.
pub(crate) async fn drive_punch_request(
    authorizer: Arc<dyn Authorizer>,
) -> (Arc<MemoryAuditSink>, wire::Error, Fingerprint) {
    let rig = rig(RigOptions {
        register_b: false,
        r_authorizer: Some(authorizer),
        ..RigOptions::default()
    })
    .await;
    let (_conn, mut ctl) = rig.dial_r().await;
    let msg = ask(
        &mut ctl,
        1,
        control_message::Body::PunchRequest(rig.request(attempt(50), &rig.b_fp)),
    )
    .await;
    let err = match reply_body(msg) {
        response::Body::Error(e) => e,
        other => panic!("expected an error, got {other:?}"),
    };
    let (audit, a_fp) = (rig.r_audit.clone(), rig.a_fp);
    rig.shutdown().await;
    (audit, err, a_fp)
}

/// An unfiltered B with a window open for A: a third peer that B trusts at the
/// TLS layer completes a handshake and is closed with `0x1001`, serves
/// nothing, and A still gets its connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_punch_window_serves_only_the_initiator() {
    let rig = rig(RigOptions {
        b_nat: NatKind::None,
        ..RigOptions::default()
    })
    .await;
    let (_conn, mut ctl) = rig.dial_r().await;
    let msg = ask(
        &mut ctl,
        1,
        control_message::Body::PunchRequest(rig.request(attempt(60), &rig.b_fp)),
    )
    .await;
    let reply = match reply_body(msg) {
        response::Body::PunchReply(r) => r,
        other => panic!("expected a PunchReply, got {other:?}"),
    };
    let candidates: Vec<SocketAddr> = reply
        .candidates
        .iter()
        .filter_map(PunchCandidate::socket_addr)
        .collect();
    let target = rig.b_server.punch_target().unwrap().clone();
    assert_eq!(target.open_windows(), 1);

    // C reaches B's window: B's TLS layer trusts C, the window does not.
    let mut closed_with = None;
    for addr in &candidates {
        let Ok(conn) = rig
            .c
            .dial(*addr, "qsh", Duration::from_millis(100), &rig.b_fp)
            .await
        else {
            continue;
        };
        let reason = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("B closes a peer its window does not serve");
        closed_with = Some(reason);
        break;
    }
    match closed_with.expect("C reached B's window on one candidate") {
        qsh_transport::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code.into_inner(),
                u64::from(qsh_transport::endpoint::CLOSE_CODE_UNVERIFIED_PEER)
            );
        }
        other => panic!("expected an application close, got {other:?}"),
    }

    // A, the initiator, is still served.
    let adopted = run_initiator(
        &rig.a,
        &InitiatorParams {
            attempt_id: attempt(60),
            expected_peer: rig.b_fp,
            candidates,
            budget: PUNCH_WINDOW,
        },
    )
    .await
    .expect("the initiator's punch opens a connection");
    adopted.connection.close(0, b"done");
    rig.shutdown().await;
}
