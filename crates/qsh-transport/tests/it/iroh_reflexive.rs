//! A daemon endpoint keeps advertising its public address through a net
//! report whose address-discovery probe failed.
//!
//! The scene is the one found on a real machine: a long-lived `qsh serve`
//! whose periodic net reports often time out (the public relay does not
//! answer the new QUIC address discovery connection iroh opens on every
//! later run), so the address set it tells a dialing peer lacked the public
//! address for much of its life. Here the relay's address discovery service
//! sits behind a small UDP forwarder that plays the NAT: the relay sees the
//! forwarder's address, never the endpoint's own, so the "public" address
//! the endpoint learns differs from every address it is bound on. Switching
//! the forwarder off makes the next probe time out.
//!
//! Loopback only; no test contacts a public relay.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iroh_relay::server::testing::self_signed_tls_certs_and_config;
use iroh_relay::server::{
    AllowAll, CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server, ServerConfig,
    TlsConfig,
};
use qsh_transport::{
    CertificateDer, IrohConfig, IrohEndpoint, IrohRelay, IrohRelayTrust, StaticTrust,
};
use tokio::net::UdpSocket;

use crate::iroh_support::make_identity;

const DEADLINE: Duration = Duration::from_secs(20);

/// An in-process relay that also serves QUIC address discovery.
struct QadRelay {
    url: String,
    cert: CertificateDer,
    quic: SocketAddr,
    _server: Server,
}

impl QadRelay {
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
        config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));
        let server = Server::spawn(config).await.expect("spawn test relay");
        Self {
            url: format!("https://{}", server.https_addr().expect("https bound")),
            cert: CertificateDer::from(certs[0].to_vec()),
            quic: server.quic_addr().expect("quic bound"),
            _server: server,
        }
    }
}

/// A stand-in NAT for one client: forwards the client's datagrams to `to`
/// from its own upstream socket, so `to` sees `upstream` as the sender, and
/// forwards the answers back. `blocked` drops both directions.
struct Nat {
    front: SocketAddr,
    upstream: SocketAddr,
    blocked: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Nat {
    async fn spawn(to: SocketAddr) -> Self {
        let front = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (front_addr, upstream_addr) =
            (front.local_addr().unwrap(), upstream.local_addr().unwrap());
        let blocked = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let blocked = Arc::clone(&blocked);
            async move {
                let mut client = None;
                let (mut a, mut b) = (vec![0u8; 65535], vec![0u8; 65535]);
                loop {
                    tokio::select! {
                        got = front.recv_from(&mut a) => {
                            let Ok((n, from)) = got else { return };
                            client = Some(from);
                            if !blocked.load(Ordering::Relaxed) {
                                let _ = upstream.send_to(&a[..n], to).await;
                            }
                        }
                        got = upstream.recv_from(&mut b) => {
                            let Ok((n, _)) = got else { return };
                            if let (false, Some(client)) = (blocked.load(Ordering::Relaxed), client) {
                                let _ = front.send_to(&b[..n], client).await;
                            }
                        }
                    }
                }
            }
        });
        Self {
            front: front_addr,
            upstream: upstream_addr,
            blocked,
            task,
        }
    }

    fn block(&self) {
        self.blocked.store(true, Ordering::Relaxed);
    }
}

impl Drop for Nat {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Poll until the endpoint advertises `addr`.
async fn advertises(ep: &IrohEndpoint, addr: SocketAddr) -> bool {
    tokio::time::timeout(DEADLINE, async {
        while !ep.advertised_addrs().contains(&addr) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok()
}

/// The regression test. Before the keeper, the second assertion failed: the
/// report whose probe timed out rebuilt the endpoint's address set without
/// the public address.
#[tokio::test]
async fn a_failed_address_discovery_probe_does_not_unadvertise_the_public_address() {
    let relay = QadRelay::spawn().await;
    let nat = Nat::spawn(relay.quic).await;
    let (id, _fp) = make_identity();
    let ep = IrohEndpoint::bind(
        &id,
        Arc::new(StaticTrust::empty()),
        IrohConfig {
            relay: IrohRelay::Url(relay.url.clone()),
            relay_trust: IrohRelayTrust::OnlyRoots(vec![relay.cert.clone()]),
            bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
            proxy_from_env: false,
            portmap: false,
            relay_quic_port: Some(nat.front.port()),
        },
    )
    .await
    .expect("bind daemon endpoint");

    // The relay saw the forwarder, not the endpoint: that address is what a
    // peer behind another NAT has to be told.
    let public = nat.upstream;
    assert!(
        !ep.bound_sockets().contains(&public),
        "the public address must differ from the bound ones"
    );
    assert!(
        advertises(&ep, public).await,
        "the endpoint never advertised its public address {public}; it advertises {:?}",
        ep.advertised_addrs()
    );

    // The next probe gets no answer.
    nat.block();
    ep.refresh_net_report().await;
    assert!(
        ep.next_report_without_public_v4(DEADLINE).await,
        "the blocked probe should end in a report without a public address"
    );
    // Let the report reach the endpoint's address set.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        ep.advertised_addrs().contains(&public),
        "the public address was dropped by a failed probe: {:?}",
        ep.advertised_addrs()
    );
    ep.close().await;
}
