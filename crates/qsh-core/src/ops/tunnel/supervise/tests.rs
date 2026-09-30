//! The supervisor against a scripted peer (ADR-0023 decision 7-3).
//!
//! `qsh-testkit`, which has the live-host harness, cannot be a dev-dependency
//! of this crate, and every real `qsh serve` advertises `dial-filter.v1`
//! unconditionally. A peer that stopped offering it after a restart is
//! therefore scripted here: a listener that runs the real responder half of
//! the `Hello` exchange and counts the streams the client opens on it.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, Hello};
use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq, TunnelDynamicReq};
use qsh_transport::{Connection, Listener};

use crate::config::Paths;
use crate::ops::Ops;
use crate::tunnel::testutil::{AlwaysPairingOpen, self_signed};

/// A listener that answers every connection's `Hello`, offering
/// `dial-filter.v1` only while `strip` is `false`, and reports each accepted
/// connection.
struct ScriptedPeer {
    addr: std::net::SocketAddr,
    fingerprint: String,
    strip: Arc<AtomicBool>,
    /// Streams the client opened after the handshake, across connections.
    requests: Arc<AtomicUsize>,
    accepted: tokio::sync::mpsc::UnboundedReceiver<Connection>,
}

async fn scripted_peer() -> ScriptedPeer {
    let (identity, fingerprint) = self_signed();
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        identity,
        Arc::new(AlwaysPairingOpen),
    )
    .expect("bind the scripted peer");
    let addr = listener.local_addr().unwrap();
    let strip = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let (tx, accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn({
        let strip = Arc::clone(&strip);
        let requests = Arc::clone(&requests);
        async move {
            while let Some(incoming) = listener.accept().await {
                let Ok(conn) = incoming.accept().await else {
                    continue;
                };
                let offer_dial_filter = !strip.load(Ordering::SeqCst);
                let requests = Arc::clone(&requests);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let hello = move |_peer: &Hello| {
                        Ok(Hello {
                            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
                            device_name: "scripted".to_string(),
                            capabilities: wire::LOCAL_CAPABILITIES
                                .iter()
                                .filter(|cap| {
                                    offer_dial_filter || **cap != wire::CAP_DIAL_FILTER_V1
                                })
                                .map(|cap| cap.to_string())
                                .collect(),
                            reverse: None,
                        })
                    };
                    let Ok((_ctl, _)) = crate::handshake::respond(&conn, hello).await else {
                        return;
                    };
                    let _ = tx.send(conn.clone());
                    // Any stream after the control stream is a request.
                    while conn.accept_bi().await.is_ok() {
                        requests.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        }
    });
    ScriptedPeer {
        addr,
        fingerprint: fingerprint.to_string(),
        strip,
        requests,
        accepted,
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn supervised_dynamic_redial_to_a_peer_without_dial_filter_ends_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let ops = Ops::new(Paths::new(
        dir.path().join("config"),
        dir.path().join("state"),
    ));
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();

    let peer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut peer = peer_runtime.block_on(scripted_peer());
    ops.trust_add(TrustAddReq {
        name: "box".into(),
        address: Some(peer.addr.to_string()),
        fingerprint: Some(peer.fingerprint.clone()),
        cert_pem: None,
    })
    .unwrap();

    let hold = ops
        .tunnel_dynamic(TunnelDynamicReq {
            host: "box".into(),
            bind: None,
            listen_port: u32::from(free_port()),
            supervise_ms: Some(30_000),
            accept_hold_ms: None,
        })
        .expect("the first open sees dial-filter.v1 and binds");

    // From now on the peer no longer offers the capability, and the first
    // connection goes away.
    peer.strip.store(true, Ordering::SeqCst);
    let first = peer_runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), peer.accepted.recv()).await
        })
        .expect("the first connection was accepted")
        .expect("the channel is open");
    first.close(0, b"restart");

    let err = hold.hold();
    assert_eq!(err.code, ErrorCode::Unsupported, "{err:?}");
    assert_eq!(
        peer.requests.load(Ordering::SeqCst),
        0,
        "no request may reach a peer that lacks the capability"
    );
}
