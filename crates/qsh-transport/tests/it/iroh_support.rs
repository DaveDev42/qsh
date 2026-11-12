//! Shared setup for the iroh backend tests: an in-process relay server and
//! helpers that bring up connected pairs.
//!
//! Nothing here touches the network beyond loopback. The relay is spawned in
//! this process on `127.0.0.1` with a fresh self-signed certificate, and the
//! endpoints that use it are told to trust exactly that certificate.

use std::net::Ipv4Addr;
use std::sync::Arc;

use iroh_relay::server::testing::self_signed_tls_certs_and_config;
use iroh_relay::server::{
    AllowAll, CertConfig, RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig,
};
use qsh_transport::{
    CertificateDer, Connection, Fingerprint, IrohConfig, IrohEndpoint, IrohPeer, IrohRelay,
    IrohRelayTrust, LocalIdentity, Principal, StaticTrust,
};

/// A relay server running in this process.
pub struct TestRelay {
    /// `https://127.0.0.1:<port>`.
    pub url: String,
    /// The relay's self-signed certificate.
    pub cert: CertificateDer,
    _server: Server,
}

impl TestRelay {
    pub async fn spawn() -> Self {
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
        let server = Server::spawn(config).await.expect("spawn test relay");
        let url = format!("https://{}", server.https_addr().expect("https bound"));
        Self {
            url,
            cert: CertificateDer::from(certs[0].to_vec()),
            _server: server,
        }
    }

    /// The relay's HTTPS socket address.
    pub fn addr(&self) -> std::net::SocketAddr {
        self.url
            .trim_start_matches("https://")
            .parse()
            .expect("the test relay url is a socket address")
    }

    /// An endpoint config that homes on this relay and trusts its
    /// certificate, bound to loopback only.
    pub fn config(&self) -> IrohConfig {
        IrohConfig {
            relay: IrohRelay::Url(self.url.clone()),
            relay_trust: IrohRelayTrust::OnlyRoots(vec![self.cert.clone()]),
            bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
            proxy_from_env: false,
        }
    }
}

/// An Ed25519 qsh identity and its fingerprint.
pub fn make_identity() -> (LocalIdentity, Fingerprint) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let fp = Fingerprint::of_cert_der(&der).unwrap();
    (
        LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        },
        fp,
    )
}

/// Loopback-only config with the relay off: peers reach each other by
/// direct address.
pub fn direct_config() -> IrohConfig {
    IrohConfig {
        relay: IrohRelay::Disabled,
        relay_trust: IrohRelayTrust::System,
        bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
        proxy_from_env: false,
    }
}

/// How a test pair reaches each other.
#[derive(Clone, Copy)]
pub enum Route {
    /// Relay disabled, direct loopback address.
    Direct,
    /// Both home on the test relay; the dialer is given the relay URL only.
    Relay,
}

#[allow(dead_code)] // Not every test reads every field.
pub struct IrohPair {
    pub client: Connection,
    pub server: Connection,
    pub client_ep: IrohEndpoint,
    pub server_ep: IrohEndpoint,
    pub client_fp: Fingerprint,
    pub server_fp: Fingerprint,
    /// Keeps the relay (if any) running.
    pub _relay: Option<TestRelay>,
}

/// Two pinned peers: the server pins the client as `device:client`, the
/// client pins the server as `device:server` (the names the conformance
/// suite expects).
pub async fn iroh_pair(route: Route) -> IrohPair {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("client".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("server".into()));

    let relay = match route {
        Route::Direct => None,
        Route::Relay => Some(TestRelay::spawn().await),
    };
    let config = |relay: &Option<TestRelay>| match relay {
        Some(r) => r.config(),
        None => direct_config(),
    };
    let server_ep = IrohEndpoint::bind(&server_id, Arc::new(server_trust), config(&relay))
        .await
        .expect("bind server endpoint");
    let client_ep = IrohEndpoint::bind(&client_id, Arc::new(client_trust), config(&relay))
        .await
        .expect("bind client endpoint");

    let mut peer = IrohPeer::new(server_ep.public_key());
    if matches!(route, Route::Direct) {
        peer.direct_addrs = server_ep.bound_sockets();
    }

    let accept = {
        let server_ep = server_ep.clone();
        tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("one attempt");
            incoming.accept().await.expect("server handshake")
        })
    };
    let client = client_ep.dial(&peer).await.expect("dial");
    let server = accept.await.unwrap();
    IrohPair {
        client,
        server,
        client_ep,
        server_ep,
        client_fp,
        server_fp,
        _relay: relay,
    }
}
