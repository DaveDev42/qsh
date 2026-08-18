//! In-process loopback harness: server + client identities, mutual pins,
//! a running [`Server`] and a [`Dialer`] ready to connect to it.

use std::net::SocketAddr;
use std::sync::Arc;

use qsh_core::acl::{AllowAllPinned, Authorizer};
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, BrokerConfig, PipeFactory, SystemClock};
use qsh_core::client::Session;
use qsh_core::server::Server;
use qsh_transport::{
    CertificateDer, Dialed, Dialer, Fingerprint, Listener, LocalIdentity, Principal, StaticTrust,
};

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
    /// The host's bound address.
    pub addr: SocketAddr,
    /// A dialer whose identity the host pins as `device:laptop`; it pins the
    /// host as `device:box`.
    pub dialer: Dialer,
    /// The client identity (to build alternative dialers).
    pub client: TestIdentity,
    /// The server identity.
    pub server_identity: TestIdentity,
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
        let server_identity = make_identity();
        let client_trust = StaticTrust::empty()
            .with_pin(server_identity.fingerprint, Principal::Device("box".into()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            server_identity.local.clone(),
            Arc::new(server_trust),
        )
        .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let audit = Arc::new(MemoryAuditSink::new());
        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(SystemClock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: std::time::Duration::from_secs(3600),
                close_grace: std::time::Duration::from_millis(100),
            },
            pipes.clone(),
        );
        tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
        let server = Server::new(authorizer, audit.clone(), broker.clone(), "box");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.clone().run(listener, async move {
            let _ = rx.await;
        }));
        Self {
            server,
            audit,
            broker,
            pipes,
            addr,
            dialer: Dialer::new(client.local.clone(), Arc::new(client_trust)),
            client,
            server_identity,
            task,
            shutdown: Some(tx),
        }
    }

    /// Dial the host with the trusted client identity.
    pub async fn dial(&self) -> Dialed {
        self.dialer
            .dial(self.addr, "127.0.0.1")
            .await
            .expect("dial loopback host")
    }

    /// Dial and negotiate `Hello`.
    pub async fn session(&self) -> Session {
        let dialed = self.dial().await;
        Session::negotiate(dialed.connection, "laptop")
            .await
            .expect("negotiate")
    }

    /// Stop the host and wait for it to drain.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for LoopbackHarness {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}
