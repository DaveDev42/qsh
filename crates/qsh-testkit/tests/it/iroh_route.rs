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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use iroh_relay::server::testing::self_signed_tls_certs_and_config;
use iroh_relay::server::{
    AllowAll, CertConfig, RelayConfig as RelayServerConfig, Server as RelayServer, ServerConfig,
    TlsConfig,
};
use qsh_core::{ExecStdin, OpError, Ops};
use qsh_proto::{ConfigSetReq, ErrorCode, ExecRunReq, TrustAddCaReq, TrustSetIrohReq};
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

/// A host `far` that accepts over an iroh endpoint, and the client `Ops` that
/// trusts the test relay.
struct Rig {
    net: Net,
    relay: TestRelay,
    ops: Ops,
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
        let ops = net
            .ops
            .clone()
            .with_iroh_relay_roots(vec![relay.cert.clone()]);
        Self {
            key: hex(&endpoint.public_key()),
            net,
            relay,
            ops,
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
