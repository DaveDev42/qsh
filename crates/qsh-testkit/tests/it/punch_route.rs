//! The client route of a hole punch end to end, over netsim (ADR-0054
//! decisions 4, 16, 17; DoD 3 and 4): `Ops::exec_run` against a host that
//! sits behind a NAT, with a real `qsh listen` as the rendezvous and the real
//! `qsh serve --to` entry as the target.
//!
//! The clocks are real (the target's services use `std` time), so the budgets
//! below are real seconds. A failing assertion names the row.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use qsh_core::acl::{Action, AllowAllPinned, Authorizer, Requester, ResourceRef, Verdict};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::SystemClock;
use qsh_core::config::{Config, Paths};
use qsh_core::handshake;
use qsh_core::punch::{
    ClientPunch, FixedAddrs, GiveUpReason, PUNCH_HEAD_START, PunchMode, SocketFactory,
};
use qsh_core::reverse::listen::Listen;
use qsh_core::reverse::registry::Registry;
use qsh_core::reverse::target::{ReverseOptions, run_reverse_on};
use qsh_core::trust::{TrustRole, TrustStore};
use qsh_core::{ExecRunOutput, ExecStdin, Fingerprint, OpError, Ops, SharedTrustStore};
use qsh_proto::wire::{
    self, ControlMessage, Hello, PunchCandidate, PunchCandidateKind, PunchRefusal, PunchReply,
    control_message, response,
};
use qsh_proto::{ErrorCode, ExecRunReq, IdentityInitReq, KeyStoreMode, TrustAddReq};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::netsim::{NatKind, Net, NetConfig, PathConfig, Site};
use qsh_testkit::reverse::{loaded_identity, wait_for};
use qsh_transport::{
    Listener, Principal, SocketSource, StaticTrust, TransportTuning, TrustEvaluator,
};
use tokio::sync::oneshot;

const R_ADDR: &str = "203.0.113.1:9000";
const B_PORT: u16 = 6000;
pub(super) const B_DIRECT_PORT: u16 = 4433;
const TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(super) async fn blocking<T: Send + 'static>(
    ops: &Ops,
    f: impl FnOnce(&Ops) -> T + Send + 'static,
) -> T {
    let ops = ops.clone();
    tokio::task::spawn_blocking(move || f(&ops))
        .await
        .expect("spawn_blocking join")
}

/// `echo punched`, spelled for the platform's shell.
fn echo_argv() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["sh".into(), "-c".into(), "echo punched".into()]
    }
    #[cfg(windows)]
    {
        vec!["cmd".into(), "/c".into(), "echo punched".into()]
    }
}

/// A: the client's `Ops` with its own identity and punch settings.
pub(super) struct Client {
    pub(super) _dir: tempfile::TempDir,
    pub(super) ops: Ops,
    pub(super) fp: Fingerprint,
    /// The punch settings `ops` was built with, so a test can derive a
    /// variant (another flag) that keeps the virtual sockets.
    pub(super) env: ClientPunch,
}

/// Builds the client on `site`. `rendezvous` are the pin names to punch
/// through; each new endpoint takes the next port of the site.
async fn client(site: &Site, rendezvous: &[&str]) -> Client {
    client_with(site, rendezvous, PUNCH_HEAD_START, false).await
}

async fn client_with(
    site: &Site,
    rendezvous: &[&str],
    head_start: Duration,
    learn_hints: bool,
) -> Client {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    let init = blocking(&ops, |ops| {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
            ..Default::default()
        })
    })
    .await
    .expect("identity.init");
    let fp: Fingerprint = init.fingerprint.parse().expect("fingerprint");
    let next = Arc::new(AtomicU16::new(5000));
    let socket_site = site.clone();
    let factory: SocketFactory = Arc::new(move || {
        let port = next.fetch_add(1, Ordering::SeqCst);
        SocketSource::Virtual(Arc::new(socket_site.bind_wildcard(port).unwrap()))
    });
    let env = ClientPunch {
        mode: PunchMode::Auto,
        rendezvous: rendezvous.iter().map(|s| (*s).to_string()).collect(),
        learn_hints,
        head_start,
        local_addrs: Arc::new(FixedAddrs(vec![site.ip()])),
        socket: Some(factory),
    };
    let ops = ops.with_punch(env.clone());
    Client {
        _dir: dir,
        ops,
        fp,
        env,
    }
}

pub(super) async fn pin(ops: &Ops, name: &str, address: Option<String>, fingerprint: &Fingerprint) {
    let name = name.to_string();
    let fp = fingerprint.to_string();
    blocking(ops, move |ops| {
        ops.trust_add(TrustAddReq {
            name,
            address,
            fingerprint: Some(fp),
            cert_pem: None,
            role: None,
        })
    })
    .await
    .unwrap_or_else(|err| panic!("trust.add: {err:?}"));
}

pub(super) async fn exec(ops: &Ops, host: &str) -> Result<ExecRunOutput, OpError> {
    let host = host.to_string();
    blocking(ops, move |ops| {
        ops.exec_run(
            ExecRunReq {
                host,
                argv: echo_argv(),
                env: vec![],
                timeout_ms: Some(30_000),
            },
            ExecStdin::Closed,
        )
    })
    .await
}

pub(super) fn punched(out: &ExecRunOutput) -> bool {
    out.data.remote_exit_code == 0 && String::from_utf8_lossy(&out.stdout).contains("punched")
}

/// R's authorizer: every pinned peer may do everything.
struct AllowAll;

impl Authorizer for AllowAll {
    fn check(&self, r: &Requester<'_>, a: Action, res: ResourceRef<'_>) -> Verdict {
        AllowAllPinned.check(r, a, res)
    }
}

pub(super) struct WorldOptions {
    pub(super) b_nat: NatKind,
    /// A listener on B's site for the direct dial.
    pub(super) direct_listener: bool,
    /// Whether B registers with R.
    pub(super) register_b: bool,
    /// Whether A's pin of B carries B's address (`B_DIRECT_PORT`).
    pub(super) pin_b_address: bool,
    /// One-way delay between A's and B's outside addresses.
    pub(super) a_b_delay: Duration,
    /// How long the direct dial runs alone.
    pub(super) head_start: Duration,
    /// A's NAT. A random-port box gives a flushed mapping a new outside port.
    pub(super) a_nat: NatKind,
    /// A's recovery settings; the defaults when unset.
    pub(super) recovery: Option<qsh_core::RecoveryConfig>,
    /// `--rendezvous r` on every command. Off leaves the rendezvous to the
    /// pin's hints.
    pub(super) flag_rendezvous: bool,
    /// A asks hosts for rendezvous hints, as the `qsh` binary does.
    pub(super) learn_hints: bool,
    /// The netsim seed (random NAT ports, loss).
    pub(super) seed: u64,
}

impl Default for WorldOptions {
    fn default() -> Self {
        Self {
            b_nat: NatKind::PortRestricted,
            direct_listener: true,
            register_b: true,
            pin_b_address: true,
            a_b_delay: Duration::from_millis(25),
            head_start: PUNCH_HEAD_START,
            a_nat: NatKind::PortRestricted,
            recovery: None,
            flag_rendezvous: true,
            learn_hints: false,
            seed: 7,
        }
    }
}

/// A behind a NAT, R on the public network running a real `Listen`, B behind
/// `b_nat` registered with R and, when asked, also listening for direct dials.
pub(super) struct World {
    pub(super) a: Client,
    pub(super) r_listen: Arc<Listen>,
    pub(super) r_audit: Arc<MemoryAuditSink>,
    pub(super) b_server: Option<Arc<qsh_core::server::Server>>,
    pub(super) b_shutdown: Option<oneshot::Sender<()>>,
    pub(super) b_task: Option<tokio::task::JoinHandle<()>>,
    pub(super) direct_shutdown: Option<oneshot::Sender<()>>,
    pub(super) r_shutdown: Option<oneshot::Sender<()>>,
    pub(super) r_task: tokio::task::JoinHandle<()>,
    pub(super) net: Net,
    pub(super) a_site: Site,
    pub(super) b_site: Site,
    pub(super) r_site: Site,
    pub(super) _dir: tempfile::TempDir,
}

pub(super) async fn world(opts: WorldOptions) -> World {
    let net = Net::new(NetConfig {
        seed: opts.seed,
        ..NetConfig::default()
    });
    let r_site = net.internet().site(NatKind::None, "r", ip("203.0.113.1"));
    let a_site = net.internet().site(opts.a_nat, "a", ip("198.51.100.1"));
    let b_site = net.internet().site(opts.b_nat, "b", ip("198.51.100.2"));
    net.set_path(
        a_site.external_ip(),
        b_site.external_ip(),
        PathConfig::delay(opts.a_b_delay),
    );

    let flagged: &[&str] = if opts.flag_rendezvous { &["r"] } else { &[] };
    let mut a = client_with(&a_site, flagged, opts.head_start, opts.learn_hints).await;
    if let Some(recovery) = opts.recovery {
        a.ops = a.ops.with_recovery(recovery);
    }
    let (r_id, b_id) = (make_identity(), make_identity());

    // R: a real `qsh listen` on the virtual network.
    let r_trust = StaticTrust::empty()
        .with_pin(a.fp, Principal::Device("a".into()))
        .with_pin(b_id.fingerprint, Principal::Device("b".into()));
    let r_listener = Listener::bind_virtual(
        Arc::new(r_site.bind_wildcard(9000).unwrap()),
        r_id.local.clone(),
        Arc::new(r_trust),
        TransportTuning::default(),
    )
    .unwrap();
    let r_audit = Arc::new(MemoryAuditSink::new());
    let clock: Arc<dyn qsh_core::broker::Clock> = Arc::new(SystemClock);
    let r_listen = Listen::new(
        Registry::new(clock.clone(), false),
        Arc::new(AllowAll),
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
        a.fp,
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
                    let _ = server_tx.send(runtime.server.clone());
                },
                || {},
                async move {
                    let _ = b_rx.await;
                },
            )
            .await;
        })
    });
    let mut b_server = None;
    let mut direct_shutdown = None;
    if opts.register_b {
        let server = wait_for(TIMEOUT, || server_rx.try_recv().ok()).await;
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
        if opts.direct_listener {
            let evaluator: Arc<dyn TrustEvaluator> =
                SharedTrustStore::open(paths.trust_file()).unwrap();
            let listener = Listener::bind_virtual(
                Arc::new(b_site.bind_wildcard(B_DIRECT_PORT).unwrap()),
                b_id.local.clone(),
                evaluator,
                TransportTuning::default(),
            )
            .unwrap();
            let (tx, rx) = oneshot::channel::<()>();
            tokio::spawn(server.clone().run(listener, async move {
                let _ = rx.await;
            }));
            direct_shutdown = Some(tx);
        }
        b_server = Some(server);
    }

    pin(&a.ops, "r", Some(R_ADDR.to_string()), &r_id.fingerprint).await;
    let b_address = opts
        .pin_b_address
        .then(|| SocketAddr::new(b_site.external_ip(), B_DIRECT_PORT).to_string());
    pin(&a.ops, "b", b_address, &b_id.fingerprint).await;

    World {
        a,
        r_listen,
        r_audit,
        b_server,
        b_shutdown: Some(b_tx),
        b_task,
        direct_shutdown,
        r_shutdown: Some(r_tx),
        r_task,
        net,
        a_site,
        b_site,
        r_site,
        _dir: dir,
    }
}

impl World {
    pub(super) fn punch_requests(&self) -> usize {
        self.r_audit
            .records()
            .iter()
            .filter(|r| r.resource == "punch.request")
            .count()
    }

    pub(super) async fn shutdown(mut self) {
        if let Some(tx) = self.direct_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.b_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.b_task.take() {
            let _ = tokio::time::timeout(TIMEOUT, task).await;
        }
        if let Some(tx) = self.r_shutdown.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(TIMEOUT, &mut self.r_task).await;
    }
}

/// An open path: the direct dial stands within the head start, and the
/// rendezvous hears nothing (DoD 3, `a_direct_dial_that_succeeds_sends_nothing_to_the_rendezvous`).
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_dial_that_succeeds_sends_nothing_to_the_rendezvous() {
    let w = world(WorldOptions {
        b_nat: NatKind::None,
        ..WorldOptions::default()
    })
    .await;
    let started = Instant::now();
    let out = exec(&w.a.ops, "b")
        .await
        .expect("exec over the direct dial");
    let took = started.elapsed();
    assert!(punched(&out));
    assert!(
        took < PUNCH_HEAD_START,
        "the direct dial stands before the head start passes: {took:?}"
    );
    assert_eq!(w.punch_requests(), 0, "no PunchRequest was sent");
    assert_eq!(w.r_listen.punch_connections(), 0, "no punching connection");
    w.shutdown().await;
}

/// Direct path blocked by B's NAT: the punch starts at the head start and
/// its connection runs the command.
#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_direct_path_starts_the_punch_at_one_second_and_it_wins() {
    let w = world(WorldOptions::default()).await;
    let started = Instant::now();
    let out = exec(&w.a.ops, "b").await.expect("exec over the punch");
    let took = started.elapsed();
    assert!(punched(&out));
    assert!(
        took >= PUNCH_HEAD_START,
        "the punch does not start before the head start: {took:?}"
    );
    assert!(
        took < qsh_transport::default_dial_timeout(),
        "and finishes inside the dial timeout: {took:?}"
    );
    assert_eq!(w.punch_requests(), 1);
    w.shutdown().await;
}

/// A pin with no address punches at once: with a head start longer than the
/// whole command could take, it still finishes, and the rendezvous heard it.
#[tokio::test(flavor = "multi_thread")]
async fn a_pin_without_an_address_punches_immediately() {
    let head_start = Duration::from_secs(8);
    let w = world(WorldOptions {
        pin_b_address: false,
        head_start,
        ..WorldOptions::default()
    })
    .await;
    let started = Instant::now();
    let out = exec(&w.a.ops, "b").await.expect("exec over the punch");
    let took = started.elapsed();
    assert!(punched(&out));
    assert!(
        took < head_start,
        "no head start without a direct dial: {took:?}"
    );
    assert_eq!(w.punch_requests(), 1);
    w.shutdown().await;
}

/// A slow direct path stands while the punch is running: the direct
/// connection is used and the punch leaves nothing open.
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_dial_that_stands_while_the_punch_runs_wins_and_leaves_nothing_open() {
    let w = world(WorldOptions {
        b_nat: NatKind::None,
        a_b_delay: Duration::from_millis(400),
        ..WorldOptions::default()
    })
    .await;
    let out = exec(&w.a.ops, "b").await.expect("exec");
    assert!(punched(&out));
    assert_eq!(
        w.punch_requests(),
        1,
        "the punch had started when the direct dial stood"
    );
    let target = w.b_server.as_ref().unwrap().punch_target().unwrap().clone();
    wait_for(Duration::from_secs(10), || {
        (target.open_windows() == 0).then_some(())
    })
    .await;
    wait_for(Duration::from_secs(10), || {
        (w.r_listen.punch_connections() == 0).then_some(())
    })
    .await;
    w.shutdown().await;
}

/// A script for a rendezvous that is not the real `Listen`: it answers the
/// way a given failure looks on the wire.
#[derive(Clone)]
enum Script {
    /// The `Hello` is refused with `UNSUPPORTED` (no hole punching here).
    HelloUnsupported,
    /// The request is answered with this wire error.
    Error(ErrorCode),
    /// The request is answered with this refusal.
    Refusal(PunchRefusal),
    /// The request is answered with these target candidates.
    Reply(Vec<SocketAddr>),
    /// The request is never answered.
    Silent,
}

fn hello() -> Hello {
    Hello {
        versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
        device_name: "fake-r".into(),
        capabilities: wire::LOCAL_CAPABILITIES
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        reverse: None,
    }
}

/// Serves `script` on `site:port`. `requests` counts the `PunchRequest`s.
fn fake_r(
    site: &Site,
    port: u16,
    id: &TestIdentity,
    trust: StaticTrust,
    script: Script,
    requests: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    let listener = Listener::bind_virtual(
        Arc::new(site.bind_wildcard(port).unwrap()),
        id.local.clone(),
        Arc::new(trust),
        TransportTuning::default(),
    )
    .unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = listener.accept().await {
            if incoming.may_retry() {
                let _ = incoming.retry();
                continue;
            }
            let script = script.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.accept().await else {
                    return;
                };
                if matches!(script, Script::HelloUnsupported) {
                    let _ = handshake::respond(&conn, |_| {
                        Err(wire::Error::new(
                            ErrorCode::Unsupported,
                            "no hole punching here",
                            false,
                        ))
                    })
                    .await;
                    return;
                }
                let Ok((mut ctl, _)) = handshake::respond(&conn, |_| Ok(hello())).await else {
                    return;
                };
                let Ok(Some(msg)) = ctl.recv.recv::<ControlMessage>().await else {
                    return;
                };
                let Some(control_message::Body::PunchRequest(_)) = msg.body else {
                    return;
                };
                requests.fetch_add(1, Ordering::SeqCst);
                let id = msg.request_id;
                let reply = |candidates: Vec<PunchCandidate>, refusal: PunchRefusal| {
                    ControlMessage::response(
                        id,
                        response::Body::PunchReply(PunchReply {
                            candidates,
                            initiator_reflexive: None,
                            target_reflexive_private: false,
                            refusal: refusal as i32,
                        }),
                    )
                };
                let answer = match script {
                    Script::HelloUnsupported => return,
                    Script::Silent => {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        return;
                    }
                    Script::Error(code) => {
                        ControlMessage::error(id, wire::Error::new(code, "refused", false))
                    }
                    Script::Refusal(r) => reply(vec![], r),
                    Script::Reply(addrs) => reply(
                        addrs
                            .iter()
                            .map(|a| PunchCandidate::from_addr(*a, PunchCandidateKind::Host))
                            .collect(),
                        PunchRefusal::None,
                    ),
                };
                let _ = ctl.send.send(&answer).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    })
}

/// Accepts connections on `site:port` and holds them: a pinned peer that is
/// not the target.
fn bystander(site: &Site, port: u16, id: &TestIdentity, trust: StaticTrust) {
    let listener = Listener::bind_virtual(
        Arc::new(site.bind_wildcard(port).unwrap()),
        id.local.clone(),
        Arc::new(trust),
        TransportTuning::default(),
    )
    .unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = listener.accept().await {
            if incoming.may_retry() {
                let _ = incoming.retry();
                continue;
            }
            if let Ok(conn) = incoming.accept().await {
                held.push(conn);
            }
        }
    });
}

/// One row of the give-up table: a state of the world and the reason the
/// punch must report.
struct Row {
    reason: GiveUpReason,
    /// `None`: nothing listens at R.
    script: Option<Script>,
    /// Pin names handed to `--rendezvous`.
    rendezvous: &'static [&'static str],
    /// Whether A's pin of B has an address (a dead one).
    b_has_address: bool,
    /// The rendezvous name the error must carry.
    named: &'static str,
}

const BLACKHOLE: &str = "198.51.100.200:4433";

async fn run_row(row: Row, extra_candidate: Option<&'static str>) -> (GiveUpReason, OpError) {
    let net = Net::new(NetConfig {
        seed: 11,
        ..NetConfig::default()
    });
    let r_site = net.internet().site(NatKind::None, "r", ip("203.0.113.1"));
    let a_site = net
        .internet()
        .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
    let c_site = net.internet().site(NatKind::None, "c", ip("198.51.100.3"));
    let a = client(&a_site, row.rendezvous).await;
    let (r_id, b_id, c_id) = (make_identity(), make_identity(), make_identity());

    let requests = Arc::new(AtomicUsize::new(0));
    let mut candidates = Vec::new();
    if let Some(script) = row.script.clone() {
        let script = match (script, extra_candidate) {
            (Script::Reply(_), Some(_)) => {
                bystander(
                    &c_site,
                    7000,
                    &c_id,
                    StaticTrust::empty().with_pin(a.fp, Principal::Device("a".into())),
                );
                candidates.push("198.51.100.3:7000".parse().unwrap());
                Script::Reply(candidates.clone())
            }
            (other, _) => other,
        };
        let trust = StaticTrust::empty().with_pin(a.fp, Principal::Device("a".into()));
        drop(fake_r(
            &r_site,
            9000,
            &r_id,
            trust,
            script,
            requests.clone(),
        ));
    }
    pin(&a.ops, "r", Some(R_ADDR.to_string()), &r_id.fingerprint).await;
    pin(&a.ops, "c", None, &c_id.fingerprint).await;
    let b_address = row.b_has_address.then(|| BLACKHOLE.to_string());
    pin(&a.ops, "b", b_address, &b_id.fingerprint).await;
    if row.reason == GiveUpReason::NoRendezvous {
        // A hint that names a peer which is no longer pinned.
        let ghost = make_identity();
        pin(
            &a.ops,
            "ghost",
            Some(BLACKHOLE.to_string()),
            &ghost.fingerprint,
        )
        .await;
        blocking(&a.ops, |ops| {
            ops.trust_set_rendezvous(qsh_proto::TrustSetRendezvousReq {
                name: "b".into(),
                rendezvous: vec!["ghost".into()],
                clear: false,
            })
        })
        .await
        .expect("trust.set_rendezvous");
        blocking(&a.ops, |ops| ops.trust_remove("ghost"))
            .await
            .expect("trust.remove");
    }

    let err = exec(&a.ops, "b")
        .await
        .expect_err(&format!("{:?} must fail", row.reason));
    assert_eq!(
        err.code,
        ErrorCode::ConnectionFailed,
        "{:?}: {err:?}",
        row.reason
    );
    let punch = &err.details["punch"];
    assert_eq!(
        punch["reason"],
        row.reason.as_str(),
        "{:?}: {err:?}",
        row.reason
    );
    assert_eq!(punch["rendezvous"], row.named, "{:?}: {err:?}", row.reason);
    assert!(
        err.message.ends_with(&format!(
            "; hole punching via {} failed: {}",
            row.named,
            row.reason.as_str()
        )),
        "{:?}: {}",
        row.reason,
        err.message
    );
    // No address anywhere in what the user sees.
    let shown = format!("{}{}", err.message, err.details);
    for needle in [
        "203.0.113",
        "198.51.100.1:",
        "198.51.100.3",
        ":9000",
        ":7000",
    ] {
        assert!(!shown.contains(needle), "{:?}: {shown}", row.reason);
    }
    (row.reason, err)
}

/// DoD 4: every reason of decision 17 is provoked and reported as
/// `details.punch.reason`, with the pin name of the rendezvous and no
/// address. The rows run side by side, each in a world of its own. The
/// dial timeout is 4 s so the slow rows (the 3 s signalling budget, the
/// window) end inside it.
#[tokio::test(flavor = "multi_thread")]
async fn punch_give_up_reasons() {
    qsh_transport::set_default_dial_timeout(Duration::from_secs(4));
    let blackhole: SocketAddr = "198.51.100.201:9".parse().unwrap();
    let rows: Vec<(Row, Option<&'static str>)> = vec![
        (
            Row {
                reason: GiveUpReason::NoRendezvous,
                script: None,
                rendezvous: &[],
                b_has_address: true,
                named: "-",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::RendezvousUnreachable,
                script: None,
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::RendezvousUnsupported,
                script: Some(Script::HelloUnsupported),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::RendezvousDenied,
                script: Some(Script::Error(ErrorCode::PermissionDenied)),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::TargetNotRegistered,
                script: Some(Script::Refusal(PunchRefusal::TargetNotRegistered)),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::TargetUnsupported,
                script: Some(Script::Refusal(PunchRefusal::TargetUnsupported)),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::TargetDenied,
                script: Some(Script::Refusal(PunchRefusal::TargetDenied)),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::RateLimited,
                script: Some(Script::Error(ErrorCode::ResourceExhausted)),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::RateLimited,
                script: Some(Script::Refusal(PunchRefusal::TargetBusy)),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::NoCandidatePair,
                script: Some(Script::Reply(vec![])),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::PeerMismatch,
                script: Some(Script::Reply(vec![])),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            Some("bystander"),
        ),
        (
            Row {
                reason: GiveUpReason::Timeout,
                script: Some(Script::Reply(vec![blackhole])),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::Timeout,
                script: Some(Script::Refusal(PunchRefusal::TargetTimeout)),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
        (
            Row {
                reason: GiveUpReason::Timeout,
                script: Some(Script::Silent),
                rendezvous: &["r"],
                b_has_address: false,
                named: "r",
            },
            None,
        ),
    ];

    let mut set = tokio::task::JoinSet::new();
    for (row, extra) in rows {
        set.spawn(run_row(row, extra));
    }
    let mut seen = Vec::new();
    while let Some(done) = set.join_next().await {
        let (reason, _) = done.expect("row task");
        seen.push(reason);
    }
    for reason in GiveUpReason::ALL {
        assert!(seen.contains(&reason), "no row provoked {reason}");
    }
    assert_eq!(GiveUpReason::ALL.len(), 11);
}

/// A rendezvous that never answers, and a direct path that is blackholed:
/// the whole command still ends inside the dial timeout (DoD 3,
/// `punch_never_extends_the_dial_past_its_timeout`).
#[tokio::test(flavor = "multi_thread")]
async fn punch_never_extends_the_dial_past_its_timeout() {
    let dial_timeout = qsh_transport::default_dial_timeout();
    let (elapsed, err) = silent_rendezvous_run().await;
    assert!(
        elapsed >= dial_timeout.saturating_sub(Duration::from_millis(300)),
        "the direct dial runs to its own timeout: {elapsed:?}"
    );
    assert!(
        elapsed <= dial_timeout + Duration::from_millis(1500),
        "punching adds nothing to the dial timeout {dial_timeout:?}: {elapsed:?}"
    );
    assert_eq!(err.code, ErrorCode::ConnectionFailed);
    assert_eq!(err.details["punch"]["reason"], "timeout");
}

/// `-o ConnectTimeout=3` cuts the whole route, the punch included, to 3 s.
#[tokio::test(flavor = "multi_thread")]
async fn connect_timeout_bounds_the_race() {
    qsh_transport::set_default_dial_timeout(Duration::from_secs(3));
    let (elapsed, err) = silent_rendezvous_run().await;
    assert!(
        elapsed <= Duration::from_millis(4500),
        "ConnectTimeout=3 ends the route in about 3 s: {elapsed:?}"
    );
    assert_eq!(err.code, ErrorCode::ConnectionFailed);
    assert_eq!(err.details["punch"]["reason"], "timeout");
}

async fn silent_rendezvous_run() -> (Duration, OpError) {
    let net = Net::new(NetConfig {
        seed: 3,
        ..NetConfig::default()
    });
    let r_site = net.internet().site(NatKind::None, "r", ip("203.0.113.1"));
    let a_site = net
        .internet()
        .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
    let a = client(&a_site, &["r"]).await;
    let (r_id, b_id) = (make_identity(), make_identity());
    let requests = Arc::new(AtomicUsize::new(0));
    let task = fake_r(
        &r_site,
        9000,
        &r_id,
        StaticTrust::empty().with_pin(a.fp, Principal::Device("a".into())),
        Script::Silent,
        requests.clone(),
    );
    pin(&a.ops, "r", Some(R_ADDR.to_string()), &r_id.fingerprint).await;
    pin(&a.ops, "b", Some(BLACKHOLE.to_string()), &b_id.fingerprint).await;
    let started = Instant::now();
    let err = exec(&a.ops, "b").await.expect_err("nothing answers");
    let elapsed = started.elapsed();
    assert_eq!(requests.load(Ordering::SeqCst), 1, "the punch did start");
    task.abort();
    (elapsed, err)
}

/// `--no-punch` (mode off) and a host with no rendezvous: no request leaves
/// and the error is the direct dial's, unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_rendezvous_or_with_punching_off_the_error_is_the_direct_dials() {
    qsh_transport::set_default_dial_timeout(Duration::from_secs(2));
    for mode_off in [false, true] {
        let net = Net::new(NetConfig {
            seed: 5,
            ..NetConfig::default()
        });
        let r_site = net.internet().site(NatKind::None, "r", ip("203.0.113.1"));
        let a_site = net
            .internet()
            .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
        // Off: the rendezvous is named but punching is off. On: none named.
        let a = client(&a_site, if mode_off { &["r"] } else { &[] }).await;
        let ops = if mode_off {
            a.ops.clone().with_punch(ClientPunch {
                mode: PunchMode::Off,
                rendezvous: vec!["r".into()],
                local_addrs: Arc::new(FixedAddrs(vec![a_site.ip()])),
                ..ClientPunch::default()
            })
        } else {
            a.ops.clone()
        };
        let a = Client {
            _dir: a._dir,
            ops,
            fp: a.fp,
            env: a.env,
        };
        let (r_id, b_id) = (make_identity(), make_identity());
        let requests = Arc::new(AtomicUsize::new(0));
        let task = fake_r(
            &r_site,
            9000,
            &r_id,
            StaticTrust::empty().with_pin(a.fp, Principal::Device("a".into())),
            Script::Silent,
            requests.clone(),
        );
        pin(&a.ops, "r", Some(R_ADDR.to_string()), &r_id.fingerprint).await;
        pin(&a.ops, "b", Some(BLACKHOLE.to_string()), &b_id.fingerprint).await;
        let err = exec(&a.ops, "b").await.expect_err("nothing answers");
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
        assert!(err.details.get("punch").is_none(), "{err:?}");
        assert!(!err.message.contains("hole punching"), "{err:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 0, "no PunchRequest left");
        task.abort();
    }
}

/// A pin with no address and no usable rendezvous keeps the old
/// `HOST_NOT_FOUND`.
#[tokio::test(flavor = "multi_thread")]
async fn a_pin_without_an_address_and_without_a_rendezvous_is_still_host_not_found() {
    let net = Net::new(NetConfig::default());
    let a_site = net
        .internet()
        .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
    let a = client(&a_site, &["ghost"]).await;
    pin(&a.ops, "b", None, &make_identity().fingerprint).await;
    let err = exec(&a.ops, "b").await.expect_err("no route");
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

/// A live reverse registration is the first route: the command goes through
/// the local `qsh listen` daemon, and the rendezvous (a socket that would
/// show any datagram) hears nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_reverse_registration_is_chosen_before_any_punch() {
    use qsh_core::broker::{Broker, BrokerConfig, PeerFingerprint, PipeFactory};
    use qsh_core::server::{ConnCtx, Server};
    use qsh_testkit::reverse::ReverseHarness;

    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    blocking(&ops, |ops| {
        ops.identity_init(IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
            ..Default::default()
        })
    })
    .await
    .expect("identity.init");
    let ops = ops.with_punch(ClientPunch {
        rendezvous: vec!["r".into()],
        ..ClientPunch::default()
    });

    // The rendezvous: a plain UDP socket that records anything sent to it.
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    watch.set_nonblocking(true).unwrap();
    let r_id = make_identity();
    pin(
        &ops,
        "r",
        Some(watch.local_addr().unwrap().to_string()),
        &r_id.fingerprint,
    )
    .await;

    // The target: a real server registered with a real listen daemon.
    let target_identity = make_identity();
    pin(&ops, "revhost", None, &target_identity.fingerprint).await;
    let broker = Broker::new(
        Arc::new(SystemClock),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(100),
            quota_limits: qsh_core::quota::QuotaLimits::default(),
        },
        Arc::new(PipeFactory::new(64 * 1024)),
    );
    tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
    let server = Server::new(
        Arc::new(AllowAllPinned),
        Arc::new(MemoryAuditSink::new()),
        broker,
        "target",
    );
    let harness = ReverseHarness::start_with(
        Arc::new(AllowAllPinned),
        false,
        StaticTrust::empty().with_pin(
            target_identity.fingerprint,
            Principal::Device("revhost".into()),
        ),
    )
    .await;
    let (dialed, ctl, peer_hello) = harness
        .register(&target_identity, "laptop")
        .await
        .expect("target registers with controller");
    let conn = dialed.connection.clone();
    let ctx = ConnCtx {
        principal: conn.principal().clone(),
        auth_path: conn.auth_path(),
        peer_fingerprint: conn
            .peer_fingerprint()
            .map(|fp| PeerFingerprint::new(*fp.as_bytes())),
        peer_addr: conn.remote_address(),
        conn_id: conn.stable_id(),
        capabilities: handshake::negotiated_capabilities(&peer_hello),
        is_reverse_registration: true,
    };
    let serving = server.clone();
    let serve = tokio::spawn(async move {
        let _ = serving.serve_control(&conn, ctl, ctx, None).await;
    });
    harness.wait_control_hub("revhost").await;
    let localctl = harness.attach_localctl(ops.paths()).await;

    let out = tokio::time::timeout(TIMEOUT, exec(&ops, "revhost"))
        .await
        .expect("must not wait for a punch")
        .expect("exec over the reverse registration");
    assert_eq!(out.data.remote_exit_code, 0);
    let mut buf = [0u8; 64];
    assert!(
        watch.recv_from(&mut buf).is_err(),
        "the rendezvous heard nothing"
    );

    localctl.shutdown().await;
    harness.shutdown().await;
    dialed.connection.close(0, b"done");
    let _ = serve.await;
}

/// DoD 7 / threat model C24: one attempt sends at most 64 punch datagrams
/// per end (eight candidates, eight offsets), 1 KiB, whatever the candidates
/// are. Both ends are driven against eight candidates that lead nowhere.
#[tokio::test(flavor = "multi_thread")]
async fn a_punch_attempt_sends_at_most_64_datagrams_per_end() {
    use qsh_core::punch::{
        InitiatorParams, MAX_PUNCH_DATAGRAMS, TargetParams, run_initiator, run_target,
    };
    use qsh_proto::punch::PUNCH_DATAGRAM_LEN;

    let net = Net::new(NetConfig::default());
    let a_site = net
        .internet()
        .site(NatKind::PortRestricted, "a", ip("198.51.100.1"));
    let b_site = net
        .internet()
        .site(NatKind::PortRestricted, "b", ip("198.51.100.2"));
    let (a_id, b_id) = (make_identity(), make_identity());
    let endpoint = |site: &Site, id: &TestIdentity, port: u16, peer: &TestIdentity| {
        qsh_transport::PunchEndpoint::new(
            SocketSource::Virtual(Arc::new(site.bind_wildcard(port).unwrap())),
            id.local.clone(),
            Arc::new(
                StaticTrust::empty().with_pin(peer.fingerprint, Principal::Device("peer".into())),
            ),
            TransportTuning::default(),
        )
        .unwrap()
    };
    let a = endpoint(&a_site, &a_id, 5000, &b_id);
    let b = endpoint(&b_site, &b_id, 6000, &a_id);
    let nowhere: Vec<SocketAddr> = (1..=12u8)
        .map(|n| format!("192.0.2.{n}:9000").parse().unwrap())
        .collect();
    let attempt = [3u8; 16];

    let b_run = tokio::spawn({
        let b = b.clone();
        let candidates = nowhere.clone();
        async move {
            run_target(
                &b,
                &TargetParams {
                    attempt_id: attempt,
                    candidates,
                    window: Duration::from_secs(5),
                },
                |_| {},
            )
            .await
        }
    });
    let gave_up = run_initiator(
        &a,
        &InitiatorParams {
            attempt_id: attempt,
            expected_peer: b_id.fingerprint,
            candidates: nowhere,
            budget: Duration::from_secs(5),
        },
    )
    .await
    .expect_err("nothing answers");
    let report = b_run.await.unwrap();
    let _ = gave_up;

    // Twelve candidates were offered; eight were used, at eight offsets.
    assert_eq!(MAX_PUNCH_DATAGRAMS, 64);
    assert_eq!(a.stats().punch_sent, 64, "end A");
    assert_eq!(report.punches_sent, 64, "end B");
    assert_eq!(
        64 * PUNCH_DATAGRAM_LEN,
        1024,
        "sixty-four 16-byte datagrams are 1 KiB"
    );
    a.close(0, b"done");
    b.close(0, b"done");
}
