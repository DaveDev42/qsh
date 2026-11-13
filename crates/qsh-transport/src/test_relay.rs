//! An iroh relay server that runs in the test process (`test-support`
//! feature only), for sibling crates' tests of the iroh route.
//!
//! The relay listens on `127.0.0.1` with a fresh self-signed certificate;
//! endpoints that use it are told to trust exactly that certificate
//! ([`TestRelay::config`]). Nothing here reaches a network beyond loopback
//! and no test using it contacts a public relay.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use iroh_relay::server::testing::self_signed_tls_certs_and_config;
use iroh_relay::server::{
    AllowAll, CertConfig, RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig,
};

use crate::identity::CertificateDer;
use crate::iroh_backend::{IrohConfig, IrohRelay, IrohRelayTrust};

/// A relay server running in this process.
pub struct TestRelay {
    /// `https://127.0.0.1:<port>`.
    pub url: String,
    /// The relay's self-signed certificate.
    pub cert: CertificateDer,
    server: Option<Server>,
}

impl TestRelay {
    /// Start a relay on an ephemeral loopback port.
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
            server: Some(server),
        }
    }

    /// The relay's HTTPS socket address.
    pub fn addr(&self) -> SocketAddr {
        self.url
            .trim_start_matches("https://")
            .parse()
            .expect("the test relay url is a socket address")
    }

    /// Stop the relay: its listener closes and every client connection to it
    /// drops, so a dial to its URL is refused from now on. Stopping twice is
    /// harmless.
    pub async fn kill(&mut self) {
        if let Some(server) = self.server.take() {
            let _ = server.shutdown().await;
        }
    }

    /// An endpoint config that homes on the best of `relays` and trusts all
    /// of their certificates, bound to loopback only.
    pub fn candidates_config(relays: &[&TestRelay]) -> IrohConfig {
        IrohConfig {
            relay: IrohRelay::Urls(relays.iter().map(|r| r.url.clone()).collect()),
            relay_trust: IrohRelayTrust::OnlyRoots(relays.iter().map(|r| r.cert.clone()).collect()),
            bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
            proxy_from_env: false,
            portmap: false,
            relay_quic_port: None,
        }
    }

    /// An endpoint config that homes on this relay and trusts its
    /// certificate, bound to loopback only.
    pub fn config(&self) -> IrohConfig {
        IrohConfig {
            relay: IrohRelay::Url(self.url.clone()),
            relay_trust: IrohRelayTrust::OnlyRoots(vec![self.cert.clone()]),
            bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
            proxy_from_env: false,
            portmap: false,
            relay_quic_port: None,
        }
    }
}
