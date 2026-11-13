//! A connection that starts on the relay moves to a direct path (protocol
//! 22.9). The dial completes over the relay, the two endpoints exchange their
//! addresses over it and open a direct path beside it, and the connection
//! reports the direct one. A guard on the endpoint's transport settings: a
//! setting that kept the connection on the relay (a path-selection bias, a
//! disabled address publication, a closed direct socket) fails it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_transport::{IrohEndpoint, IrohPeer, PeerAddr, PeerPath, Principal, StaticTrust};

use crate::iroh_support::{TestRelay, make_identity};

#[tokio::test]
async fn a_relay_dial_moves_to_a_direct_path() {
    let relay = TestRelay::spawn().await;
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("client".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("server".into()));
    let server = IrohEndpoint::bind(&server_id, Arc::new(server_trust), relay.config())
        .await
        .expect("bind the daemon");
    let client_ep = IrohEndpoint::bind_client(&client_id, Arc::new(client_trust), relay.config())
        .await
        .expect("bind the client");
    let peer = IrohPeer::new(server.public_key());

    let accepting = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.expect("incoming").accept().await })
    };
    let client = client_ep.dial(&peer).await.expect("dial by key");
    let _accepted = accepting.await.expect("no panic").expect("accepted");

    let started = Instant::now();
    let direct = loop {
        let addr = client.remote_address();
        if matches!(
            addr,
            PeerAddr::Keyed {
                path: PeerPath::Direct(_),
                ..
            }
        ) {
            break addr;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the connection stayed on {addr:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    drop(direct);
}
