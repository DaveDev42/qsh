//! In-process loopback harness: server + client identities, mutual pins,
//! a running [`Server`] and a [`Dialer`] ready to connect to it.
//!
//! [`LoopbackHarness::start_chaotic`] is the L4 variant: identical host, but
//! the dialer is pointed at a [`ChaosProxy`](crate::chaos::ChaosProxy) that
//! relays to it under a seeded fault policy (`docs/design/testing.md` L4).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use qsh_core::acl::{AllowAllPinned, Authorizer};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, BrokerConfig, PipeFactory, SystemClock};
use qsh_core::client::Session;
use qsh_core::server::Server;
use qsh_proto::wire::{self, Hello};
use qsh_transport::{
    CertificateDer, Connection, Dialed, Dialer, Fingerprint, FramedStream, Listener, LocalIdentity,
    Principal, StaticTrust,
};

use crate::chaos::{ChaosPolicy, ChaosProxy};
use crate::pair::HostedPair;

/// A freshly generated self-signed Ed25519 device identity.
#[derive(Clone)]
pub struct TestIdentity {
    /// Cert chain + PKCS#8 key.
    pub local: LocalIdentity,
    /// SPKI fingerprint of the cert.
    pub fingerprint: Fingerprint,
    /// DER of the cert (for pinning / CA tests).
    pub cert_der: Vec<u8>,
}

/// Generate a valid (10-year) self-signed Ed25519 identity.
pub fn make_identity() -> TestIdentity {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    let cert = params.self_signed(&key).expect("self-sign");
    let der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = Fingerprint::of_cert_der(&der).expect("fingerprint");
    TestIdentity {
        local: LocalIdentity {
            cert_chain: vec![der.clone()],
            key_pkcs8_der: key.serialize_der(),
        },
        fingerprint,
        cert_der: der.to_vec(),
    }
}

/// A private CA for tests: a self-signed root that can sign leaves.
pub struct TestCa {
    key: rcgen::KeyPair,
    params: rcgen::CertificateParams,
    /// DER of the CA root (for `StaticTrust::with_ca`).
    pub root_der: CertificateDer<'static>,
}

/// Generate a private CA root.
pub fn make_ca() -> TestCa {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("self-sign CA");
    TestCa {
        key,
        params,
        root_der: CertificateDer::from(cert.der().to_vec()),
    }
}

impl TestCa {
    /// Issue a leaf under this CA carrying `san_uri` (e.g.
    /// `qsh://device/laptop`) as its SAN URI.
    pub fn issue(&self, san_uri: &str) -> TestIdentity {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(san_uri).expect("ia5 uri"),
        )];
        let issuer = rcgen::Issuer::new(self.params.clone(), &self.key);
        let cert = params.signed_by(&key, &issuer).expect("sign leaf");
        let der = CertificateDer::from(cert.der().to_vec());
        let fingerprint = Fingerprint::of_cert_der(&der).expect("fingerprint");
        TestIdentity {
            local: LocalIdentity {
                cert_chain: vec![der.clone()],
                key_pkcs8_der: key.serialize_der(),
            },
            fingerprint,
            cert_der: der.to_vec(),
        }
    }
}

/// A running in-process host plus a client that it trusts.
pub struct LoopbackHarness {
    /// The host.
    pub server: Arc<Server>,
    /// Every audit record the host produced.
    pub audit: Arc<MemoryAuditSink>,
    /// The host's session broker (pipe-backed sources, real clock).
    pub broker: Arc<Broker>,
    /// Hands out the [`qsh_core::broker::PipeHandle`] of every session the
    /// host opened, in open order — the test's side of the "child".
    pub pipes: Arc<PipeFactory>,
    /// The address the client dials: the host itself, or — for a harness
    /// started with [`LoopbackHarness::start_chaotic`] — the chaos proxy in
    /// front of it.
    pub addr: SocketAddr,
    /// The host's own bound address (never the proxy's).
    pub host_addr: SocketAddr,
    /// The chaos proxy the client dials through, if any.
    pub chaos: Option<Arc<ChaosProxy>>,
    /// A dialer whose identity the host pins as `device:laptop`; it pins the
    /// host as `device:box`.
    pub dialer: Dialer,
    /// The client identity (to build alternative dialers).
    pub client: TestIdentity,
    /// The server identity.
    pub server_identity: TestIdentity,
    /// A second client identity the host also pins, as `device:phone` —
    /// only set by [`Self::start_with_quotas`], for per-principal quota
    /// tests (`crates/qsh-testkit/tests/quota.rs`) that need two distinct
    /// principals against the one host. `None` for every other
    /// constructor.
    pub second_client: Option<TestIdentity>,
    /// A dialer built for [`Self::second_client`] — pins the same host,
    /// under the same `device:box` principal `dialer` uses. `None` unless
    /// `second_client` is set.
    pub second_dialer: Option<Dialer>,
    conns: Arc<Mutex<Vec<Connection>>>,
    /// Every client-side [`quinn::Endpoint`] a harness dial method
    /// (`Self::dial`, `Self::second_dial`) has created. `Dialer::dial`
    /// mints a brand-new endpoint per call (`qsh_transport::endpoint::
    /// Dialer::dial_inner`) and hands it back inside `Dialed` for the
    /// caller to keep; nothing about the client `Connection` itself closes
    /// it. Before this field existed, every dial's endpoint was simply
    /// dropped at the end of whatever scope built it — harmless for a
    /// connection torn down promptly, but `two_principals_have_
    /// independent_session_budgets` (`crates/qsh-testkit/tests/quota.rs`)
    /// holds its second-principal connection open across the whole test
    /// body, and nextest flagged the resulting undriven endpoint as a
    /// LEAK. `Self::shutdown` closes every endpoint stashed here.
    client_endpoints: Arc<Mutex<Vec<quinn::Endpoint>>>,
    task: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl LoopbackHarness {
    /// Start a host with the interim allow-all-pinned policy.
    pub async fn start() -> Self {
        Self::start_with(Arc::new(AllowAllPinned)).await
    }

    /// Start a host with a custom policy. The host pins the client as
    /// `device:laptop`.
    pub async fn start_with(authorizer: Arc<dyn Authorizer>) -> Self {
        let client = make_identity();
        let server_trust =
            StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
        Self::start_custom(authorizer, client, server_trust).await
    }

    /// Start a host with a custom policy, a caller-provided client identity
    /// and a caller-provided host trust store (which decides how — pin or
    /// CA — the host authenticates that client). The client always pins the
    /// host as `device:box`.
    pub async fn start_custom(
        authorizer: Arc<dyn Authorizer>,
        client: TestIdentity,
        server_trust: StaticTrust,
    ) -> Self {
        Self::start_inner(authorizer, client, server_trust, None, None, None).await
    }

    /// [`Self::start_custom`] plus an explicit
    /// [`qsh_core::quota::QuotaLimits`] — for a quota test that also needs
    /// [`Self::start_custom`]'s caller-built `server_trust` (e.g. a
    /// CA-pinned, ACL-denied second peer alongside the quota-saturating
    /// pinned one, `crates/qsh-testkit/tests/quota.rs`'s ACL→quota
    /// order-pin test). [`Self::start_with_quotas`] covers the common
    /// single-identity case.
    pub async fn start_custom_with_quotas(
        authorizer: Arc<dyn Authorizer>,
        client: TestIdentity,
        server_trust: StaticTrust,
        limits: qsh_core::quota::QuotaLimits,
    ) -> Self {
        Self::start_inner(authorizer, client, server_trust, None, None, Some(limits)).await
    }

    /// [`Self::start`], but with an explicit
    /// `(max_concurrent_handshakes, handshake_rate_per_source,
    /// validated_rate_per_source)` `crate::admission::Gate` instead of
    /// `crate::config::ServeConfig`'s defaults (`PLAN.md` M8 Step 2, P2-3
    /// wiring added Step 3) — the admission integration tests
    /// (`crates/qsh-testkit/tests/admission.rs`) use a small cap so they
    /// don't need hundreds of real connections to reach it.
    pub async fn start_with_admission(
        max_concurrent_handshakes: usize,
        handshake_rate_per_source: u32,
        validated_rate_per_source: u32,
    ) -> Self {
        let client = make_identity();
        let server_trust =
            StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
        Self::start_inner(
            Arc::new(AllowAllPinned),
            client,
            server_trust,
            None,
            Some((
                max_concurrent_handshakes,
                handshake_rate_per_source,
                validated_rate_per_source,
            )),
            None,
        )
        .await
    }

    /// [`Self::start`], but with an explicit
    /// [`qsh_core::quota::QuotaLimits`] instead of
    /// `crate::config::ServeConfig`'s defaults (`PLAN.md` M8 Step 3) — for
    /// quota integration tests (`crates/qsh-testkit/tests/quota.rs`). The
    /// host also pins a second, distinct client identity under
    /// `device:phone` ([`Self::second_client`]/[`Self::second_dialer`]) so
    /// a per-principal test can drive two budgets against the one host
    /// without standing up a second harness — pinning happens once at
    /// bind time (`qsh_transport::StaticTrust` has no runtime add-a-pin
    /// path), so this is the only place a second principal can be
    /// introduced, not something a test can bolt onto [`Self::start`]
    /// afterward.
    pub async fn start_with_quotas(limits: qsh_core::quota::QuotaLimits) -> Self {
        let client = make_identity();
        let second_client = make_identity();
        let server_trust = StaticTrust::empty()
            .with_pin(client.fingerprint, Principal::Device("laptop".into()))
            .with_pin(second_client.fingerprint, Principal::Device("phone".into()));
        let mut harness = Self::start_inner(
            Arc::new(AllowAllPinned),
            client,
            server_trust,
            None,
            None,
            Some(limits),
        )
        .await;
        let client_trust = StaticTrust::empty().with_pin(
            harness.server_identity.fingerprint,
            Principal::Device("box".into()),
        );
        harness.second_dialer = Some(Dialer::new(
            second_client.local.clone(),
            Arc::new(client_trust),
        ));
        harness.second_client = Some(second_client);
        harness
    }

    /// [`Self::start_with_admission`] and [`Self::start_with_quotas`]
    /// combined (`ARBITRATION-4.md` J4, `start_inner` already takes
    /// both) — for a test that needs quota limits pinned down tight
    /// while the *admission* axis (handshake concurrency, per-source
    /// rate limits) is opened wide so it never becomes the bottleneck
    /// being measured (`crates/qsh-testkit/tests/quota.rs`'s
    /// connection-/session-flood-vs-existing-session-echo tests). Single
    /// pinned client identity — no [`Self::second_client`]/
    /// [`Self::second_dialer`], same as [`Self::start_custom_with_quotas`].
    pub async fn start_with_admission_and_quotas(
        max_concurrent_handshakes: usize,
        handshake_rate_per_source: u32,
        validated_rate_per_source: u32,
        limits: qsh_core::quota::QuotaLimits,
    ) -> Self {
        let client = make_identity();
        let server_trust =
            StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
        Self::start_inner(
            Arc::new(AllowAllPinned),
            client,
            server_trust,
            None,
            Some((
                max_concurrent_handshakes,
                handshake_rate_per_source,
                validated_rate_per_source,
            )),
            Some(limits),
        )
        .await
    }

    /// Start a host the client reaches only through a seeded chaos proxy
    /// (`docs/design/testing.md` L4). [`addr`](Self::addr) becomes the
    /// proxy's front address, so `dial()`/`session()` and everything built on
    /// them traverse the faults with no further changes.
    pub async fn start_chaotic(policy: ChaosPolicy) -> Self {
        Self::start_chaotic_with(Arc::new(AllowAllPinned), policy).await
    }

    /// [`start_chaotic`](Self::start_chaotic) with a custom policy engine.
    pub async fn start_chaotic_with(authorizer: Arc<dyn Authorizer>, policy: ChaosPolicy) -> Self {
        let client = make_identity();
        let server_trust =
            StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into()));
        Self::start_inner(authorizer, client, server_trust, Some(policy), None, None).await
    }

    async fn start_inner(
        authorizer: Arc<dyn Authorizer>,
        client: TestIdentity,
        server_trust: StaticTrust,
        chaos: Option<ChaosPolicy>,
        admission: Option<(usize, u32, u32)>,
        quota_limits: Option<qsh_core::quota::QuotaLimits>,
    ) -> Self {
        let server_identity = make_identity();
        let client_trust = StaticTrust::empty()
            .with_pin(server_identity.fingerprint, Principal::Device("box".into()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            server_identity.local.clone(),
            Arc::new(server_trust),
        )
        .expect("bind loopback");
        let host_addr = listener.local_addr().expect("local addr");
        let audit = Arc::new(MemoryAuditSink::new());
        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(SystemClock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: std::time::Duration::from_secs(3600),
                close_grace: std::time::Duration::from_millis(100),
                quota_limits: quota_limits.unwrap_or_default(),
            },
            pipes.clone(),
        );
        tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
        let (max_concurrent_handshakes, handshake_rate_per_source, validated_rate_per_source) =
            admission.unwrap_or((
                qsh_core::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
                qsh_core::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
                qsh_core::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
            ));
        let gate = qsh_core::admission::Gate::new(
            Arc::new(SystemClock),
            max_concurrent_handshakes,
            handshake_rate_per_source,
            validated_rate_per_source,
        );
        let server = match quota_limits {
            Some(limits) => {
                let quotas = qsh_core::quota::Quotas::new(limits, Arc::new(SystemClock));
                Server::with_admission_and_quotas(
                    authorizer,
                    audit.clone(),
                    broker.clone(),
                    "box",
                    gate,
                    quotas,
                )
            }
            None => Server::with_admission(authorizer, audit.clone(), broker.clone(), "box", gate),
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let conns: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let (addr, chaos, task) = match chaos {
            None => {
                let task = tokio::spawn(server.clone().run(listener, async move {
                    let _ = rx.await;
                }));
                (host_addr, None, task)
            }
            Some(policy) => {
                let proxy = Arc::new(
                    ChaosProxy::start(host_addr, policy)
                        .await
                        .expect("bind chaos proxy"),
                );
                let task = tokio::spawn(accept_observed(
                    server.clone(),
                    listener,
                    conns.clone(),
                    async move {
                        let _ = rx.await;
                    },
                ));
                (proxy.addr(), Some(proxy), task)
            }
        };
        Self {
            server,
            audit,
            broker,
            pipes,
            addr,
            host_addr,
            chaos,
            dialer: Dialer::new(client.local.clone(), Arc::new(client_trust)),
            client,
            server_identity,
            second_client: None,
            second_dialer: None,
            conns,
            client_endpoints: Arc::new(Mutex::new(Vec::new())),
            task,
            shutdown: Some(tx),
        }
    }

    /// The chaos proxy in front of the host. Panics unless the harness was
    /// started with [`start_chaotic`](Self::start_chaotic).
    pub fn chaos(&self) -> &ChaosProxy {
        self.chaos
            .as_deref()
            .expect("harness was not started with start_chaotic")
    }

    /// The one-line context every chaos assertion message must carry — it
    /// prints the seed (`docs/design/testing.md`, CI 규율). It is immutable,
    /// so binding it once at the top of a test is safe; for the proxy's
    /// counters use [`detail`](Self::detail) *at* the assertion.
    pub fn context(&self) -> String {
        match &self.chaos {
            Some(proxy) => proxy.context(),
            None => format!("loopback host={}", self.host_addr),
        }
    }

    /// [`context`](Self::context) plus a freshly read [`ChaosStats`]
    /// (`qsh_testkit::chaos::ChaosStats`). Call it at the assertion site.
    pub fn detail(&self) -> String {
        match &self.chaos {
            Some(proxy) => proxy.detail(),
            None => format!("loopback host={}", self.host_addr),
        }
    }

    /// Every connection the host has accepted, in accept order. Only
    /// populated for a [`start_chaotic`](Self::start_chaotic) harness — it is
    /// how a test observes the **host-side** peer address, which is what
    /// connection migration changes.
    ///
    /// Connections are retained for the harness's lifetime (a test needs the
    /// closed ones too, e.g. to sum `lost_packets` after a re-dial), so a
    /// test that dials in a long loop holds every quinn connection state it
    /// created. That is fine at the handful of dials L4 scenarios need.
    pub fn server_connections(&self) -> Vec<Connection> {
        self.conns.lock().expect("conns lock").clone()
    }

    /// Dial the host with the trusted client identity. Under chaos a
    /// handshake killed by `drop`/`corrupt` surfaces here, so the panic
    /// carries the seed (`docs/design/testing.md` L4: 실패 메시지에 seed를
    /// 출력한다).
    pub async fn dial(&self) -> Dialed {
        self.dial_via(&self.dialer).await
    }

    /// [`Self::dial`], but through [`Self::second_dialer`] — the second
    /// pinned principal ([`Self::second_client`], `device:phone`) a
    /// `start_with_quotas` harness sets up. Panics unless the harness was
    /// started with [`start_with_quotas`](Self::start_with_quotas).
    ///
    /// Goes through the same [`Self::dial_via`] tracking `Self::dial`
    /// does, so its endpoint is closed by `Self::shutdown` too — calling
    /// `self.second_dialer.dial(..)` directly instead would bypass that
    /// tracking and leak the endpoint, exactly the failure this method
    /// exists to prevent.
    pub async fn second_dial(&self) -> Dialed {
        let dialer = self
            .second_dialer
            .as_ref()
            .expect("harness was not started with start_with_quotas");
        self.dial_via(dialer).await
    }

    /// Shared by [`Self::dial`]/[`Self::second_dial`]: dial through
    /// `dialer` and stash a clone of the resulting endpoint in
    /// [`Self::client_endpoints`] before handing the [`Dialed`] back, so
    /// `Self::shutdown` can close it even though the caller only ever
    /// touches `dialed.connection`. `quinn::Endpoint` is a cheap `Clone` —
    /// an `Arc`-backed handle onto the same underlying endpoint state, not
    /// a second endpoint — so closing the stashed clone closes the one the
    /// caller holds too.
    async fn dial_via(&self, dialer: &Dialer) -> Dialed {
        let dialed = dialer
            .dial(self.addr, "127.0.0.1")
            .await
            .unwrap_or_else(|err| panic!("dial {}: {err:?} — {}", self.addr, self.detail()));
        self.client_endpoints
            .lock()
            .expect("client_endpoints lock")
            .push(dialed.endpoint.clone());
        dialed
    }

    /// Dial and negotiate `Hello`.
    pub async fn session(&self) -> Session {
        let dialed = self.dial().await;
        Session::negotiate(dialed.connection, "laptop")
            .await
            .unwrap_or_else(|err| panic!("negotiate: {err:?} — {}", self.detail()))
    }

    /// [`Self::session`] without the [`Session`] wrapper: dial, run
    /// [`qsh_core::handshake::initiate`] with the ordinary "laptop" `Hello`,
    /// and hand back the raw [`Connection`]/[`FramedStream`] — for tests
    /// that pipeline `wire::ControlMessage`s directly instead of going
    /// through the typed client API (`attach_loopback.rs`'s wedged-child/
    /// backlog/pipelining scenarios; [`HostedPair::raw_session`]'s doc).
    pub async fn raw_session(&self) -> (Connection, FramedStream) {
        let dialed = self.dial().await;
        let local_hello = Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: "laptop".to_string(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            reverse: None,
        };
        let (ctl, _peer_hello) = qsh_core::handshake::initiate(&dialed.connection, local_hello)
            .await
            .unwrap_or_else(|err| panic!("raw negotiate: {err:?} — {}", self.detail()));
        (dialed.connection, ctl)
    }

    /// Stop the host and, for a non-chaotic harness, wait for it to drain.
    ///
    /// **A chaotic harness does not drain.** Its accept loop skips
    /// `wait_idle()` and never joins the per-connection tasks, because a
    /// severed or blackholed connection would hold teardown hostage for the
    /// full 45 s idle timeout. After `shutdown()` returns, connections
    /// started through the proxy may still be live — do not build an fd-count
    /// or zombie-check assertion on top of it.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;

        // Close every client endpoint `Self::dial`/`Self::second_dial`
        // created (`Self::client_endpoints`'s doc) — dropping a
        // `quinn::Endpoint` alone does not promptly close it, and an
        // endpoint left running past the harness's own shutdown is what
        // nextest flags as a LEAK. Bounded so a connection `wait_idle`
        // cannot hang the whole test on a peer that never acks the close.
        let endpoints =
            std::mem::take(&mut *self.client_endpoints.lock().expect("client_endpoints lock"));
        for endpoint in endpoints {
            endpoint.close(0u32.into(), b"");
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.wait_idle()).await;
        }
    }
}

/// The chaos harness's accept loop. The per-connection work — handshake,
/// rejection audit, `serve_connection` — is [`Server::accept_and_serve`],
/// the same code [`Server::run`] uses, so nothing about accepting is
/// duplicated here. Only the loop differs, in exactly the two ways L4 needs:
///
/// 1. it keeps a clone of every accepted [`Connection`], so a test can watch
///    the **host-side** peer address change across a `repath()`;
/// 2. it does not `wait_idle()` on shutdown. Under chaos a connection can be
///    unreachable (severed, blackholed) and would hold teardown hostage until
///    the 45 s idle timeout.
async fn accept_observed(
    server: Arc<Server>,
    listener: Listener,
    conns: Arc<Mutex<Vec<Connection>>>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            incoming = listener.accept() => {
                let Some(incoming) = incoming else { break };
                let server = server.clone();
                let conns = conns.clone();
                tokio::spawn(async move {
                    server
                        .accept_and_serve(incoming, |conn| {
                            conns.lock().expect("conns lock").push(conn.clone());
                        })
                        .await;
                });
            }
        }
    }
    listener.close(0, b"shutdown");
}

impl Drop for LoopbackHarness {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

impl HostedPair for LoopbackHarness {
    fn server(&self) -> &Arc<Server> {
        &self.server
    }

    fn broker(&self) -> &Arc<Broker> {
        &self.broker
    }

    fn pipes(&self) -> &Arc<PipeFactory> {
        &self.pipes
    }

    fn audit(&self) -> &Arc<MemoryAuditSink> {
        &self.audit
    }

    async fn session(&self) -> Session {
        LoopbackHarness::session(self).await
    }

    async fn raw_session(&self) -> (Connection, FramedStream) {
        LoopbackHarness::raw_session(self).await
    }

    async fn shutdown(self) {
        LoopbackHarness::shutdown(self).await
    }
}
