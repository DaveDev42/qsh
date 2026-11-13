//! The client side of the iroh relay route (ADR-0061, `docs/CLI.md` §6.1),
//! through the real `Ops` and an in-process relay.
//!
//! The server side is the test's own: a real `Server` handed the connections
//! an `IrohEndpoint` accepts, since `qsh serve` does not bring up an iroh
//! endpoint yet. The relay is an `iroh-relay` server on `127.0.0.1` with a
//! self-signed certificate that only the client under test is told to trust
//! (`Ops::with_iroh_relay_roots`); nothing here reaches a public relay, binds
//! UDP 4433, 4434 or 443, or reads `~/.config/qsh`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use iroh_relay::server::testing::self_signed_tls_certs_and_config;
use iroh_relay::server::{
    AllowAll, CertConfig, RelayConfig as RelayServerConfig, Server as RelayServer, ServerConfig,
    TlsConfig,
};
use qsh_core::punch::{ClientPunch, LocalAddrs};
use qsh_core::route_memory::RouteClock;
use qsh_core::{ExecStdin, OpError, Ops};
use qsh_proto::{ConfigSetReq, ErrorCode, ExecRunReq, TrustAddCaReq, TrustAddReq, TrustSetIrohReq};
use qsh_transport::{
    CertificateDer, IrohConfig, IrohEndpoint, IrohRelay, IrohRelayTrust, Principal, StaticTrust,
};

use super::jump_chain::{Net, blocking, echo_argv, exec, loopback_options, stdout_of};

/// A relay server running in this process.
struct TestRelay {
    url: String,
    cert: CertificateDer,
    _server: RelayServer,
}

impl TestRelay {
    async fn spawn() -> Self {
        let (certs, server_config) = self_signed_tls_certs_and_config();
        let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.tls = Some(TlsConfig::new(
            (Ipv4Addr::LOCALHOST, 0),
            CertConfig::Manual { server_config },
        ));
        relay.key_cache_capacity = Some(1024);
        relay.access = Arc::new(AllowAll);
        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        let server = RelayServer::spawn(config).await.expect("spawn test relay");
        Self {
            url: format!("https://{}", server.https_addr().expect("https bound")),
            cert: CertificateDer::from(certs[0].to_vec()),
            _server: server,
        }
    }

    /// The host side: homed on this relay, trusting its certificate, bound to
    /// loopback only.
    fn host_config(&self) -> IrohConfig {
        IrohConfig {
            relay: IrohRelay::Url(self.url.clone()),
            relay_trust: IrohRelayTrust::OnlyRoots(vec![self.cert.clone()]),
            bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
            proxy_from_env: false,
        }
    }
}

/// Something that counts the TCP connections made to it and never answers: a
/// relay URL no endpoint can get through, which shows whether one tried.
struct CountingPort {
    url: String,
    count: Arc<AtomicUsize>,
}

impl CountingPort {
    async fn bind() -> Self {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind counting port");
        let url = format!("https://{}", listener.local_addr().expect("addr"));
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                seen.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });
        Self { url, count }
    }

    fn contacts(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The route memory's clock, moved by the test.
struct TestClock(AtomicU64);

impl TestClock {
    fn advance(&self, by: Duration) {
        self.0
            .fetch_add(u64::try_from(by.as_millis()).unwrap(), Ordering::SeqCst);
    }
}

impl RouteClock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The addresses this client sends from, which are its "network" for the
/// route memory; the test moves it to another network.
struct TestAddrs(Mutex<Vec<std::net::IpAddr>>);

impl TestAddrs {
    fn set(&self, ip: &str) {
        *self.0.lock().unwrap() = vec![ip.parse().unwrap()];
    }
}

impl LocalAddrs for TestAddrs {
    fn observe(&self) -> Vec<std::net::IpAddr> {
        self.0.lock().unwrap().clone()
    }
}

/// A UDP port that takes every packet and never answers, and counts them.
struct Blackhole {
    addr: std::net::SocketAddr,
    packets: Arc<AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Blackhole {
    fn bind() -> Self {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind blackhole");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("read timeout");
        let addr = socket.local_addr().expect("addr");
        let packets = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, done) = (packets.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !done.load(Ordering::SeqCst) {
                if socket.recv_from(&mut buf).is_ok() {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        Self {
            addr,
            packets,
            stop,
        }
    }

    fn packets(&self) -> usize {
        self.packets.load(Ordering::SeqCst)
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// A host `far` that accepts over an iroh endpoint, and the client `Ops` that
/// trusts the test relay.
struct Rig {
    net: Net,
    relay: TestRelay,
    ops: Ops,
    clock: Arc<TestClock>,
    addrs: Arc<TestAddrs>,
    /// The host's iroh public key, 64 hex characters.
    key: String,
    _endpoint: IrohEndpoint,
}

impl Rig {
    /// `trusts_client`: whether the host pins the client. When it does not,
    /// the host closes every iroh connection after the handshake.
    async fn start(trusts_client: bool) -> Self {
        let net = Net::start_unpinned(&["far"], |_| "*", loopback_options()).await;
        let relay = TestRelay::spawn().await;
        let host = net.host("far");
        let trust = if trusts_client {
            StaticTrust::empty().with_pin(net.fp, Principal::Device("laptop".into()))
        } else {
            StaticTrust::empty()
        };
        let endpoint = IrohEndpoint::bind(
            &host.h.server_identity.local,
            Arc::new(trust),
            relay.host_config(),
        )
        .await
        .expect("bind the host's iroh endpoint");
        assert_eq!(
            endpoint.fingerprint(),
            host.h.server_identity.fingerprint,
            "the iroh endpoint is the host's qsh identity"
        );
        tokio::time::timeout(Duration::from_secs(10), endpoint.online())
            .await
            .expect("the host reaches the test relay");
        let accepting = endpoint.clone();
        let server = host.h.server.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                let server = server.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.accept().await {
                        server.serve_connection(conn).await;
                    }
                });
            }
        });
        let clock = Arc::new(TestClock(AtomicU64::new(1_800_000_000_000)));
        let addrs = Arc::new(TestAddrs(Mutex::new(Vec::new())));
        addrs.set("192.0.2.10");
        let ops = net
            .ops
            .clone()
            .with_iroh_relay_roots(vec![relay.cert.clone()])
            .with_route_clock(clock.clone())
            .with_punch(ClientPunch {
                local_addrs: addrs.clone(),
                ..ClientPunch::default()
            });
        Self {
            key: hex(&endpoint.public_key()),
            net,
            relay,
            ops,
            clock,
            addrs,
            _endpoint: endpoint,
        }
    }

    /// Pin the host as `name` (at `address`, or with none) with the iroh route
    /// on, homed on `relay_url`.
    async fn pin_iroh(&self, name: &str, address: Option<String>, relay_url: &str) {
        let fingerprint = self.net.host("far").h.server_identity.fingerprint;
        self.net.pin(name, address, fingerprint).await;
        self.set_iroh(name, Some(relay_url), Some(&self.key))
            .await
            .expect("trust.set_iroh");
    }

    async fn set_iroh(
        &self,
        name: &str,
        relay: Option<&str>,
        key: Option<&str>,
    ) -> Result<qsh_proto::TrustSetIrohData, OpError> {
        let ops = self.ops.clone();
        let req = TrustSetIrohReq {
            name: name.into(),
            relay: relay.map(str::to_string),
            key: key.map(str::to_string),
            off: false,
        };
        blocking(move || ops.trust_set_iroh(req)).await
    }

    async fn config_set(&self, key: &str, value: &str) {
        let ops = self.ops.clone();
        let req = ConfigSetReq {
            key: key.into(),
            value: value.into(),
        };
        blocking(move || ops.config_set(req))
            .await
            .expect("config.set");
    }

    fn allowed_on_host(&self) -> usize {
        self.net
            .host("far")
            .h
            .audit
            .records()
            .iter()
            .filter(|r| r.decision == "allow")
            .count()
    }
}

/// `exec` with its own time limit, for a command that is meant to fail.
async fn exec_within(
    ops: &Ops,
    host: &str,
    limit: Duration,
) -> Result<qsh_core::ExecRunOutput, OpError> {
    let ops = ops.clone();
    let req = ExecRunReq {
        host: host.into(),
        argv: echo_argv("never"),
        env: vec![],
        timeout_ms: Some(u64::try_from(limit.as_millis()).unwrap()),
    };
    blocking(move || ops.exec_run(req, ExecStdin::Closed)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_address_less_iroh_pin_runs_exec_through_the_relay() {
    let rig = Rig::start(true).await;
    rig.pin_iroh("far", None, &rig.relay.url).await;

    let started = Instant::now();
    let out = exec(&rig.ops, "far", echo_argv("via-iroh"))
        .await
        .expect("exec over the iroh route");
    assert_eq!(stdout_of(&out).trim(), "via-iroh");
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "an address-less pin dials iroh at once, not after a head start: {:?}",
        started.elapsed()
    );
    assert_eq!(rig.allowed_on_host(), 1, "the host allowed the exec once");
    rig.net.shutdown().await;
}

/// Two commands of one machine at the same time, the long-lived tunnel holder
/// and an interactive `exec` of the field report: each dials with its own
/// client endpoint, so the second does not displace the first's relay home
/// connection, and the host sees the machine's one qsh identity on both.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_commands_of_one_identity_both_finish_over_iroh() {
    let rig = Rig::start(true).await;
    rig.pin_iroh("far", None, &rig.relay.url).await;

    let first = {
        let ops = rig.ops.clone();
        tokio::spawn(async move {
            exec(&ops, "far", echo_argv("first; sleep 3; echo first-done")).await
        })
    };
    // The first command is connected and running when the second dials.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let second = exec(&rig.ops, "far", echo_argv("second"))
        .await
        .expect("the second command while the first is running");
    assert_eq!(stdout_of(&second).trim(), "second");

    let first = first
        .await
        .expect("the first command's task")
        .expect("the first command survives the second");
    assert_eq!(stdout_of(&first).trim(), "first\nfirst-done");
    assert_eq!(rig.allowed_on_host(), 2, "the host allowed both execs");
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn iroh_starts_after_the_head_start_when_the_direct_dial_never_answers() {
    let rig = Rig::start(true).await;
    // A UDP port that takes every packet and never answers: the direct dial
    // hangs until its timeout.
    let blackhole = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind blackhole");
    rig.config_set("iroh.head_start_ms", "400").await;
    rig.pin_iroh(
        "far",
        Some(blackhole.local_addr().unwrap().to_string()),
        &rig.relay.url,
    )
    .await;

    let started = Instant::now();
    let out = exec(&rig.ops, "far", echo_argv("raced"))
        .await
        .expect("iroh wins the race against the blackholed direct dial");
    let took = started.elapsed();
    assert_eq!(stdout_of(&out).trim(), "raced");
    assert!(
        took >= Duration::from_millis(400),
        "iroh waits for its head start while the direct dial is still trying: {took:?}"
    );
    assert!(
        took < Duration::from_secs(8),
        "iroh wins inside the 10 s dial timeout, long before the direct dial gives up: {took:?}"
    );
    drop(blackhole);
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_dial_that_stands_never_contacts_the_relay() {
    let rig = Rig::start(true).await;
    let watched = CountingPort::bind().await;
    let addr = rig.net.host("far").h.addr.to_string();
    rig.pin_iroh("far", Some(addr), &watched.url).await;

    let out = exec(&rig.ops, "far", echo_argv("direct"))
        .await
        .expect("exec over the direct route");
    assert_eq!(stdout_of(&out).trim(), "direct");
    // Give a wrongly started iroh dial time to show itself.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        watched.contacts(),
        0,
        "the direct dial stood inside the head start, so the relay was never contacted"
    );
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_disabled_route_contacts_no_relay_and_keeps_the_old_errors() {
    let rig = Rig::start(true).await;
    let watched = CountingPort::bind().await;
    rig.pin_iroh("far", None, &watched.url).await;
    // A pin that never asked for the route, with the same key on file.
    let fingerprint = rig.net.host("far").h.server_identity.fingerprint;
    rig.net.pin("plain", None, fingerprint).await;
    rig.set_iroh("plain", None, Some(&rig.key))
        .await
        .expect("record the key")
        .peer
        .routes
        .first()
        .expect("trust.set_iroh turns the route on");
    let ops = rig.ops.clone();
    blocking(move || {
        ops.trust_set_iroh(TrustSetIrohReq {
            name: "plain".into(),
            relay: None,
            key: None,
            off: true,
        })
    })
    .await
    .expect("route off");

    // No `routes`: the address-less pin is the same "not found" as before.
    let err = exec_within(&rig.ops, "plain", Duration::from_secs(5))
        .await
        .expect_err("a pin without routes and without an address");
    assert_eq!(err.code, ErrorCode::HostNotFound, "{err:?}");

    // `--no-iroh`.
    let err = exec_within(
        &rig.ops.clone().with_no_iroh(true),
        "far",
        Duration::from_secs(5),
    )
    .await
    .expect_err("--no-iroh");
    assert_eq!(err.code, ErrorCode::HostNotFound, "{err:?}");

    // `[iroh].mode = "off"`.
    rig.config_set("iroh.mode", "off").await;
    let err = exec_within(&rig.ops, "far", Duration::from_secs(5))
        .await
        .expect_err("[iroh].mode = off");
    assert_eq!(err.code, ErrorCode::HostNotFound, "{err:?}");

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(watched.contacts(), 0, "no relay was contacted");

    // The control: with the route on, the same pin does reach for its relay.
    rig.config_set("iroh.mode", "auto").await;
    let err = exec_within(&rig.ops, "far", Duration::from_secs(4))
        .await
        .expect_err("a relay that never answers");
    assert!(
        matches!(err.code, ErrorCode::Timeout | ErrorCode::ConnectionFailed),
        "{err:?}"
    );
    assert!(watched.contacts() >= 1, "the route on contacts its relay");
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_does_not_trust_the_client_is_auth_failed() {
    let rig = Rig::start(false).await;
    rig.pin_iroh("far", None, &rig.relay.url).await;

    let err = exec(&rig.ops, "far", echo_argv("refused"))
        .await
        .expect_err("the host refuses an unpinned client");
    assert_eq!(err.code, ErrorCode::AuthFailed, "{err:?}");
    assert!(!err.retryable, "{err:?}");
    assert_eq!(rig.allowed_on_host(), 0, "nothing ran on the host");
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_is_not_the_pins_is_a_config_error_on_every_command() {
    let rig = Rig::start(true).await;
    rig.pin_iroh("far", None, &rig.relay.url).await;

    // `qsh trust iroh --key` refuses a key of another fingerprint.
    let other = "08".repeat(32);
    let err = rig
        .set_iroh("far", None, Some(&other))
        .await
        .expect_err("the key's fingerprint is not the pin's");
    assert_eq!(err.code, ErrorCode::InvalidArgument, "{err:?}");

    // A `trust.toml` that holds such a key anyway makes the whole file a
    // CONFIG_ERROR, and no route is built from it.
    let path = rig.ops.paths().trust_file();
    let text = std::fs::read_to_string(&path).expect("read trust.toml");
    let edited = text.replace(&rig.key, &other);
    assert_ne!(text, edited, "the key is in trust.toml");
    std::fs::write(&path, edited).expect("write trust.toml");
    let err = exec(&rig.ops, "far", echo_argv("never"))
        .await
        .expect_err("a pin whose key contradicts its fingerprint");
    assert_eq!(err.code, ErrorCode::ConfigError, "{err:?}");
    assert_eq!(rig.allowed_on_host(), 0);
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_iroh_section_is_a_config_error_for_a_pin_that_uses_the_route() {
    let rig = Rig::start(true).await;
    rig.pin_iroh("far", None, &rig.relay.url).await;
    // `config set` refuses the value, so write the file the way a hand edit
    // would.
    let path = rig.ops.paths().config_file();
    std::fs::write(&path, "[iroh]\nrelay_url = \"http://relay.example\"\n").expect("write config");

    let err = exec(&rig.ops, "far", echo_argv("never"))
        .await
        .expect_err("[iroh].relay_url is not https");
    assert_eq!(err.code, ErrorCode::ConfigError, "{err:?}");
    // `--no-iroh` does not need the section to be valid.
    let err = exec_within(
        &rig.ops.clone().with_no_iroh(true),
        "far",
        Duration::from_secs(5),
    )
    .await
    .expect_err("no route is left for an address-less pin");
    assert_eq!(err.code, ErrorCode::HostNotFound, "{err:?}");
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_jump_chain_cannot_open_an_iroh_only_hop_and_a_private_ca_cannot_take_the_route() {
    let rig = Rig::start(true).await;
    rig.pin_iroh("far", None, &rig.relay.url).await;
    let fingerprint = rig.net.host("far").h.server_identity.fingerprint;
    rig.net
        .pin("gate", Some("127.0.0.1:9".into()), fingerprint)
        .await;

    // `-J gate` to a target that only iroh could reach.
    let via = rig.ops.clone().with_jump(vec!["gate".to_string()]);
    let err = exec_within(&via, "far", Duration::from_secs(5))
        .await
        .expect_err("a chain does not open its target over iroh");
    assert_eq!(err.code, ErrorCode::Unsupported, "{err:?}");
    assert_eq!(err.details["iroh"]["reason"], "jump_unsupported", "{err:?}");
    assert_eq!(err.details["jump"]["stage"], "unsupported", "{err:?}");

    // The same pin as an iroh-only first hop.
    let via = rig.ops.clone().with_jump(vec!["far".to_string()]);
    let err = exec_within(&via, "gate", Duration::from_secs(5))
        .await
        .expect_err("a chain does not open a hop over iroh");
    assert_eq!(err.code, ErrorCode::Unsupported, "{err:?}");
    assert_eq!(err.details["iroh"]["reason"], "jump_unsupported", "{err:?}");

    // A private CA root has no key to dial.
    let ca = qsh_testkit::loopback::make_ca();
    let pem = pem_of(ca.root_der.as_ref());
    let ops = rig.ops.clone();
    blocking(move || {
        ops.trust_add_ca(TrustAddCaReq {
            name: "root".into(),
            cert_pem: pem,
        })
    })
    .await
    .expect("trust.add_ca");
    let err = rig
        .set_iroh("root", None, None)
        .await
        .expect_err("a CA root takes no iroh route");
    assert_eq!(err.code, ErrorCode::Unsupported, "{err:?}");
    assert_eq!(
        err.details["iroh"]["reason"], "private_ca_unsupported",
        "{err:?}"
    );
    rig.net.shutdown().await;
}

/// The `key` of the pin `name` in `trust.toml`, if it has one.
fn pin_key(ops: &Ops, name: &str) -> Option<String> {
    let store = qsh_core::trust::TrustStore::load(&ops.paths().trust_file()).expect("trust.toml");
    store.find(name).and_then(|p| p.key.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_connection_teaches_the_pin_its_key_and_never_overwrites_it() {
    let rig = Rig::start(true).await;
    let addr = rig.net.host("far").h.addr.to_string();
    let fingerprint = rig.net.host("far").h.server_identity.fingerprint;
    rig.net.pin("far", Some(addr), fingerprint).await;
    assert_eq!(pin_key(&rig.ops, "far"), None, "a fresh pin has no key");

    let out = exec(&rig.ops, "far", echo_argv("direct"))
        .await
        .expect("direct exec");
    assert_eq!(stdout_of(&out).trim(), "direct");
    // The write happens off the dial path; wait for it.
    let mut learned = None;
    for _ in 0..50 {
        learned = pin_key(&rig.ops, "far");
        if learned.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(learned.as_deref(), Some(rig.key.as_str()));

    // The pin now dials by key: `trust iroh` with no `--key` suffices.
    let set = rig
        .set_iroh("far", Some(&rig.relay.url), None)
        .await
        .expect("trust.set_iroh without a key");
    assert_eq!(set.peer.key.as_deref(), Some(rig.key.as_str()));
    // Another key is refused rather than replacing it.
    let other = "08".repeat(32);
    let err = rig
        .set_iroh("far", None, Some(&other))
        .await
        .expect_err("a key of another fingerprint");
    assert_eq!(err.code, ErrorCode::InvalidArgument, "{err:?}");
    assert_eq!(pin_key(&rig.ops, "far").as_deref(), Some(rig.key.as_str()));
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trust_add_with_a_certificate_records_the_key() {
    let rig = Rig::start(true).await;
    let pem = pem_of(&rig.net.host("far").h.server_identity.cert_der);
    let ops = rig.ops.clone();
    let added = blocking(move || {
        ops.trust_add(TrustAddReq {
            name: "from-cert".into(),
            address: None,
            fingerprint: None,
            cert_pem: Some(pem),
            role: None,
        })
    })
    .await
    .expect("trust add --cert-file");
    assert_eq!(added.peer.key.as_deref(), Some(rig.key.as_str()));
    assert_eq!(
        pin_key(&rig.ops, "from-cert").as_deref(),
        Some(rig.key.as_str())
    );

    // A fingerprint alone knows no key.
    let fingerprint = rig.net.host("far").h.server_identity.fingerprint;
    let ops = rig.ops.clone();
    let added = blocking(move || {
        ops.trust_add(TrustAddReq {
            name: "from-fp".into(),
            address: None,
            fingerprint: Some(fingerprint.to_string()),
            cert_pem: None,
            role: None,
        })
    })
    .await
    .expect("trust add --fingerprint");
    assert_eq!(added.peer.key, None);
    rig.net.shutdown().await;
}

fn pem_of(der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// The time `exec` takes against a pin, and whether it ran.
async fn timed_exec(ops: &Ops, host: &str, word: &str) -> Duration {
    let started = Instant::now();
    let out = exec(ops, host, echo_argv(word))
        .await
        .expect("exec over the relay route");
    assert_eq!(stdout_of(&out).trim(), word);
    started.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_dial_skips_the_blackholed_direct_route_and_starts_iroh_at_once() {
    let rig = Rig::start(true).await;
    let blackhole = Blackhole::bind();
    rig.config_set("iroh.head_start_ms", "1500").await;
    rig.pin_iroh("far", Some(blackhole.addr.to_string()), &rig.relay.url)
        .await;

    // The first dial waits out the head start while the direct dial hangs.
    let first = timed_exec(&rig.ops, "far", "first").await;
    assert!(first >= Duration::from_millis(1500), "{first:?}");
    let knocks = blackhole.packets();
    assert!(knocks > 0, "the first dial tried the direct route");

    // The second one remembers: iroh at once, the blackhole is left alone.
    let second = timed_exec(&rig.ops, "far", "second").await;
    assert!(
        second < Duration::from_millis(1400),
        "no head start the second time: {second:?}"
    );
    assert_eq!(
        blackhole.packets(),
        knocks,
        "the direct route is not tried while it rests"
    );
    assert!(rig.ops.paths().route_cache_file().exists());
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rest_that_has_ended_tries_the_blocked_route_once_beside_iroh() {
    let rig = Rig::start(true).await;
    let blackhole = Blackhole::bind();
    rig.config_set("iroh.head_start_ms", "1500").await;
    rig.pin_iroh("far", Some(blackhole.addr.to_string()), &rig.relay.url)
        .await;
    timed_exec(&rig.ops, "far", "first").await;
    let mut knocks = blackhole.packets();
    assert!(knocks > 0);

    // Nine minutes: still resting.
    rig.clock.advance(Duration::from_secs(9 * 60));
    timed_exec(&rig.ops, "far", "resting").await;
    assert_eq!(blackhole.packets(), knocks);

    // Ten: one look at the blocked route, beside iroh, so no waiting.
    rig.clock.advance(Duration::from_secs(60));
    let retry = timed_exec(&rig.ops, "far", "retry").await;
    assert!(retry < Duration::from_millis(1400), "{retry:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        blackhole.packets() > knocks,
        "the rest ended, the route was tried"
    );
    knocks = blackhole.packets();

    // It lost again, so the next rest is twenty minutes.
    rig.clock.advance(Duration::from_secs(19 * 60));
    timed_exec(&rig.ops, "far", "twenty").await;
    assert_eq!(
        blackhole.packets(),
        knocks,
        "twenty minutes have not passed"
    );
    rig.clock.advance(Duration::from_secs(60));
    timed_exec(&rig.ops, "far", "twenty-one").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(blackhole.packets() > knocks, "the doubled rest ended");
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twelve_dials_in_twelve_minutes_knock_on_the_blocked_route_twice() {
    let rig = Rig::start(true).await;
    let blackhole = Blackhole::bind();
    rig.config_set("iroh.head_start_ms", "300").await;
    rig.pin_iroh("far", Some(blackhole.addr.to_string()), &rig.relay.url)
        .await;
    let mut dials_that_knocked = Vec::new();
    for n in 0..12 {
        let before = blackhole.packets();
        timed_exec(&rig.ops, "far", &format!("dial-{n}")).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        if blackhole.packets() > before {
            dials_that_knocked.push(n);
        }
        rig.clock.advance(Duration::from_secs(60));
    }
    assert_eq!(
        dials_that_knocked,
        [0, 10],
        "the first dial and the first one after the ten-minute rest"
    );
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_of_network_forgets_the_rest_and_the_head_start_returns() {
    let rig = Rig::start(true).await;
    let blackhole = Blackhole::bind();
    rig.config_set("iroh.head_start_ms", "1200").await;
    rig.pin_iroh("far", Some(blackhole.addr.to_string()), &rig.relay.url)
        .await;
    timed_exec(&rig.ops, "far", "first").await;
    let second = timed_exec(&rig.ops, "far", "second").await;
    assert!(second < Duration::from_millis(1100), "{second:?}");
    let knocks = blackhole.packets();

    rig.addrs.set("198.51.100.20");
    let third = timed_exec(&rig.ops, "far", "third").await;
    assert!(
        third >= Duration::from_millis(1200),
        "a new network gets the usual head start again: {third:?}"
    );
    assert!(
        blackhole.packets() > knocks,
        "and the direct route is tried again"
    );
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_route_that_stands_ends_the_rest() {
    let rig = Rig::start(true).await;
    let blackhole = Blackhole::bind();
    rig.config_set("iroh.head_start_ms", "300").await;
    rig.pin_iroh("far", Some(blackhole.addr.to_string()), &rig.relay.url)
        .await;
    timed_exec(&rig.ops, "far", "first").await;
    // The address now works: after the rest the direct dial wins the race.
    let real = rig.net.host("far").h.addr.to_string();
    let fingerprint = rig.net.host("far").h.server_identity.fingerprint;
    rig.net.pin("far", Some(real), fingerprint).await;
    rig.clock.advance(Duration::from_secs(10 * 60));
    timed_exec(&rig.ops, "far", "direct").await;
    // No rest is left: the next dial runs the usual order, and a direct dial
    // that stands inside the head start never contacts the relay.
    let watched = CountingPort::bind().await;
    rig.set_iroh("far", Some(&watched.url), None)
        .await
        .expect("a relay that nobody answers");
    timed_exec(&rig.ops, "far", "again").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(watched.contacts(), 0);
    rig.net.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_memory_is_not_used_without_the_route_and_a_broken_file_is_ignored() {
    let rig = Rig::start(true).await;
    let blackhole = Blackhole::bind();
    rig.config_set("iroh.head_start_ms", "300").await;
    rig.pin_iroh("far", Some(blackhole.addr.to_string()), &rig.relay.url)
        .await;
    timed_exec(&rig.ops, "far", "first").await;

    // `--no-iroh` neither reads nor writes the memory, and a pin without
    // routes has none.
    let path = rig.ops.paths().route_cache_file();
    let before = std::fs::read(&path).expect("the memory was written");
    let err = exec_within(
        &rig.ops.clone().with_no_iroh(true),
        "far",
        Duration::from_secs(2),
    )
    .await
    .expect_err("the blackholed address alone");
    assert!(
        matches!(err.code, ErrorCode::Timeout | ErrorCode::ConnectionFailed),
        "{err:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);

    // A broken file is an empty memory: the head start is back, and the
    // file is written again.
    std::fs::write(&path, b"{ not json").unwrap();
    rig.config_set("iroh.head_start_ms", "900").await;
    let took = timed_exec(&rig.ops, "far", "after-corruption").await;
    assert!(took >= Duration::from_millis(900), "{took:?}");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"pins\""), "{text}");
    rig.net.shutdown().await;
}
