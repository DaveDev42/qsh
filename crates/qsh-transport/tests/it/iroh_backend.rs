//! The iroh backend beyond the shared conformance list (ADR-0061
//! decisions 3, 4, 11, 12): identity and fingerprint, the pin check on both
//! ends, the refusal codes, reverification, the pairing fallback, and relay
//! TLS verification.
//!
//! Everything runs on loopback against an in-process relay server; no test
//! contacts a public relay.

use std::sync::Arc;
use std::time::Duration;

use qsh_transport::{
    AcceptError, AuthPath, Connection, DialError, IrohConfig, IrohEndpoint, IrohPeer, IrohRelay,
    IrohRelayTrust, PeerAddr, PeerKey, PeerPath, Principal, RejectReason, StaticTrust,
    TransportKind, fingerprint_of_ed25519_key,
};

use crate::iroh_support::{Route, TestRelay, direct_config, iroh_pair, make_identity};

const DEADLINE: Duration = Duration::from_secs(15);

async fn bind(
    identity: &qsh_transport::LocalIdentity,
    trust: StaticTrust,
    config: IrohConfig,
) -> IrohEndpoint {
    IrohEndpoint::bind(identity, Arc::new(trust), config)
        .await
        .expect("bind")
}

/// The qsh identity key is the iroh key: the endpoint's id fingerprints to
/// the same value the certificate path computes, so `trust.toml` pins that
/// name the identity apply unchanged.
#[tokio::test]
async fn the_endpoint_fingerprint_is_the_identity_fingerprint() {
    let (id, fp) = make_identity();
    let ep = bind(&id, StaticTrust::empty(), direct_config()).await;
    assert_eq!(ep.fingerprint(), fp);
    assert_eq!(ep.public_key(), id.iroh_public_key().unwrap());
    assert_eq!(fingerprint_of_ed25519_key(&ep.public_key()), fp);
    assert_eq!(IrohPeer::new(ep.public_key()).fingerprint(), fp);
}

/// Each end's `peer_fingerprint` is the other's identity fingerprint, and
/// the connection reports the iroh transport.
#[tokio::test]
async fn peers_see_each_others_identity_fingerprint() {
    let p = iroh_pair(Route::Direct).await;
    assert_eq!(p.client.peer_fingerprint(), Some(p.server_fp));
    assert_eq!(p.server.peer_fingerprint(), Some(p.client_fp));
    assert_eq!(p.client.transport_kind(), TransportKind::Iroh);
    assert_eq!(p.client.auth_path(), AuthPath::Pin);
    assert_eq!(p.server.auth_path(), AuthPath::Pin);
}

/// A dial whose target key is not in the client's trust store is refused
/// locally, with the observed fingerprint, the same way the QUIC backend
/// refuses an unpinned server (`DialError::LocalRejected`).
#[tokio::test]
async fn a_server_key_the_client_does_not_pin_is_rejected_locally() {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let (_other_id, other_fp) = make_identity();
    // The client pins some other key, not the server's.
    let client_trust = StaticTrust::empty().with_pin(other_fp, Principal::Device("other".into()));
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("client".into()));
    let server_ep = bind(&server_id, server_trust, direct_config()).await;
    let client_ep = bind(&client_id, client_trust, direct_config()).await;
    let mut peer = IrohPeer::new(server_ep.public_key());
    peer.direct_addrs = server_ep.bound_sockets();
    let err = tokio::time::timeout(DEADLINE, client_ep.dial(&peer))
        .await
        .unwrap()
        .unwrap_err();
    match err {
        DialError::LocalRejected { reason, observed } => {
            assert_eq!(reason, RejectReason::Untrusted);
            assert_eq!(observed, Some(server_fp));
        }
        other => panic!("expected LocalRejected, got {other:?}"),
    }
    // The key is judged before any packet leaves: the server never sees an
    // attempt, not even one that is closed right after the handshake.
    assert!(
        tokio::time::timeout(Duration::from_secs(1), server_ep.accept())
            .await
            .is_err(),
        "an unpinned key must cause no handshake"
    );
}

/// A client whose key the server does not pin is refused by the server with
/// `AcceptError::Unverified`; no `Connection` is produced and the client
/// sees the connection closed with the unverified-peer code.
#[tokio::test]
async fn a_client_key_the_server_does_not_pin_is_rejected_by_the_server() {
    let (server_id, server_fp) = make_identity();
    let (client_id, _client_fp) = make_identity();
    let (_other_id, other_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pin(other_fp, Principal::Device("other".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("server".into()));
    let server_ep = bind(&server_id, server_trust, direct_config()).await;
    let client_ep = bind(&client_id, client_trust, direct_config()).await;
    let accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move {
            let incoming = ep.accept().await.unwrap();
            incoming.accept().await
        })
    };

    let mut peer = IrohPeer::new(server_ep.public_key());
    peer.direct_addrs = server_ep.bound_sockets();
    // The handshake itself completes on the client; the refusal arrives as
    // a close right after.
    let conn = tokio::time::timeout(DEADLINE, client_ep.dial(&peer))
        .await
        .unwrap()
        .expect("the client's own check passes");

    let accepted = tokio::time::timeout(DEADLINE, accept)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            accepted,
            Err(AcceptError::Unverified(RejectReason::Untrusted))
        ),
        "server must refuse an unpinned client, got {accepted:?}"
    );
    // The client sees the refusal as the QUIC backend's verifier reports
    // it: a crypto-class failure, which is what `qsh-core` turns into
    // "the server rejected this device" (`AUTH_FAILED`).
    let closed = tokio::time::timeout(DEADLINE, conn.closed()).await.unwrap();
    assert!(
        qsh_transport::endpoint::is_crypto_failure(&closed) && closed.is_crypto_failure(),
        "expected a crypto-class failure, got {closed:?}"
    );
    assert!(!closed.is_refused());
}

/// The iroh twin of `handshake_matrix.rs`'s remote-rejection pair: a server
/// that does not pin the client rejects it (`AcceptError::Unverified`), and
/// the client sees that as `RemoteRejected` or as a connection that dies
/// with a crypto-class error, on `closed()` and on the first stream
/// operation alike. A server that pins the client admits it, and the client
/// does not.
#[tokio::test]
async fn an_unpinned_client_is_remote_rejected_like_over_quic() {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("server".into()));
    let ok = unpinned_client_outcome(
        &server_id,
        StaticTrust::empty().with_pin(client_fp, Principal::Device("client".into())),
        &client_id,
        client_trust.clone(),
    )
    .await;
    assert_eq!(ok.server, Ok(Principal::Device("client".into())));
    assert!(ok.client_failure.is_none(), "{:?}", ok.client_failure);

    let (_other_id, other_fp) = make_identity();
    let rejected = unpinned_client_outcome(
        &server_id,
        StaticTrust::empty().with_pin(other_fp, Principal::Device("other".into())),
        &client_id,
        client_trust,
    )
    .await;
    assert_eq!(rejected.server, Err(RejectReason::Untrusted));
    let failure = rejected.client_failure.expect("the client must be refused");
    assert!(
        qsh_transport::endpoint::is_crypto_failure(&failure),
        "expected a crypto-class failure, got {failure:?}"
    );
}

struct UnpinnedClientOutcome {
    /// The server's verdict: the admitted principal or the reject reason.
    server: Result<Principal, RejectReason>,
    /// How the client's connection failed, `None` when it stayed up.
    client_failure: Option<qsh_transport::ConnectionError>,
}

async fn unpinned_client_outcome(
    server_id: &qsh_transport::LocalIdentity,
    server_trust: StaticTrust,
    client_id: &qsh_transport::LocalIdentity,
    client_trust: StaticTrust,
) -> UnpinnedClientOutcome {
    let server_ep = bind(server_id, server_trust, direct_config()).await;
    let client_ep = bind(client_id, client_trust, direct_config()).await;
    let accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move {
            let incoming = ep.accept().await.unwrap();
            match incoming.accept().await {
                Ok(conn) => {
                    let principal = conn.principal().clone();
                    // Hold the connection open until the client is done.
                    tokio::time::timeout(Duration::from_secs(3), conn.closed())
                        .await
                        .ok();
                    Ok(principal)
                }
                Err(AcceptError::Unverified(reason)) => Err(reason),
                Err(other) => panic!("unexpected accept error {other:?}"),
            }
        })
    };
    let mut peer = IrohPeer::new(server_ep.public_key());
    peer.direct_addrs = server_ep.bound_sockets();
    let dialed = tokio::time::timeout(DEADLINE, client_ep.dial(&peer))
        .await
        .unwrap();
    let client_failure = match dialed {
        Err(DialError::RemoteRejected) => Some(qsh_transport::ConnectionError::crypto(48)),
        Err(other) => panic!("expected RemoteRejected or an established dial, got {other:?}"),
        Ok(conn) => client_connection_failure(&conn).await,
    };
    if client_failure.is_none() {
        client_ep.close().await;
    }
    let server = tokio::time::timeout(DEADLINE, accept)
        .await
        .unwrap()
        .unwrap();
    UnpinnedClientOutcome {
        server,
        client_failure,
    }
}

/// `None` when the connection is still up after a stream round trip is
/// attempted, else the error the first operation or `closed()` reports.
async fn client_connection_failure(conn: &Connection) -> Option<qsh_transport::ConnectionError> {
    // Whichever comes first, the close or a failing stream open, must carry
    // the crypto-class classification.
    let attempt = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(b"x").await.ok();
        send.finish().ok();
        match recv.read_to_end(8).await {
            Ok(_) => Ok(()),
            Err(qsh_transport::ReadToEndError::Read(qsh_transport::ReadError::ConnectionLost(
                e,
            ))) => Err(e),
            Err(_) => Ok(()),
        }
    };
    match tokio::time::timeout(Duration::from_secs(2), attempt).await {
        Ok(Err(e)) => Some(e),
        Ok(Ok(())) | Err(_) => tokio::time::timeout(Duration::from_millis(500), conn.closed())
            .await
            .ok(),
    }
}

/// Dialing a key that the address does not hold fails the handshake: the
/// server at the address cannot prove the key, so the dial never yields a
/// connection to a different peer (ADR-0060's name binding, structurally).
#[tokio::test]
async fn a_server_that_does_not_hold_the_dialed_key_is_not_reached() {
    let (server_id, server_fp) = make_identity();
    let (client_id, client_fp) = make_identity();
    let (ghost_id, ghost_fp) = make_identity();
    // The client pins both the real server and the key it will (wrongly)
    // expect at that address.
    let client_trust = StaticTrust::empty()
        .with_pin(server_fp, Principal::Device("server".into()))
        .with_pin(ghost_fp, Principal::Device("ghost".into()));
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("client".into()));
    let server_ep = bind(&server_id, server_trust, direct_config()).await;
    let client_ep = bind(&client_id, client_trust, direct_config())
        .await
        .with_timeout(Duration::from_secs(5));
    let _accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move {
            ep.accept()
                .await
                .unwrap()
                .accept()
                .await
                .map(|c| c.stable_id())
        })
    };

    let mut peer = IrohPeer::new(
        // A valid key that is not the server's.
        bind(&ghost_id, StaticTrust::empty(), direct_config())
            .await
            .public_key(),
    );
    peer.direct_addrs = server_ep.bound_sockets();
    let result = client_ep.dial(&peer).await;
    // A TLS failure while connecting is the dialed key not being proven: a
    // local rejection of the target, not the server rejecting this client.
    assert!(
        matches!(
            result,
            Err(DialError::LocalRejected {
                reason: RejectReason::Untrusted,
                observed: None,
            })
        ),
        "must not connect to a peer that does not hold the dialed key: {result:?}"
    );
}

/// `reverify` re-judges the peer by key, and a withdrawn pin makes it
/// `Untrusted` (the trust watch relies on this, ADR-0031).
#[tokio::test]
async fn reverify_follows_the_trust_store() {
    let p = iroh_pair(Route::Direct).await;
    let same = StaticTrust::empty().with_pin(p.server_fp, Principal::Device("server".into()));
    let verified = p.client.reverify(&same).unwrap();
    assert_eq!(verified.principal, Principal::Device("server".into()));
    assert_eq!(verified.auth_path, AuthPath::Pin);
    assert_eq!(
        p.client.reverify(&StaticTrust::empty()).unwrap_err(),
        RejectReason::Untrusted
    );
}

/// With a pairing window open, an unpinned client is admitted as
/// `Principal::Pairing`, exactly as the certificate path does.
#[tokio::test]
async fn an_open_pairing_window_admits_an_unpinned_client_as_pairing() {
    let (server_id, server_fp) = make_identity();
    let (client_id, _client_fp) = make_identity();
    let server_trust = StaticTrust::empty().with_pairing_open(true);
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("server".into()));
    let server_ep = bind(&server_id, server_trust, direct_config()).await;
    let client_ep = bind(&client_id, client_trust, direct_config()).await;
    let accept = {
        let ep = server_ep.clone();
        tokio::spawn(async move { ep.accept().await.unwrap().accept().await })
    };
    let mut peer = IrohPeer::new(server_ep.public_key());
    peer.direct_addrs = server_ep.bound_sockets();
    let _client = tokio::time::timeout(DEADLINE, client_ep.dial(&peer))
        .await
        .unwrap()
        .unwrap();
    let server = accept.await.unwrap().unwrap();
    assert_eq!(server.principal(), &Principal::Pairing);
    assert_eq!(server.auth_path(), AuthPath::Pairing);
}

/// With no relay and no direct address there is nowhere to dial; the dial
/// fails at once instead of waiting out a timeout.
#[tokio::test]
async fn a_dial_with_no_route_fails_immediately() {
    let (id, _fp) = make_identity();
    let (peer_id, peer_fp) = make_identity();
    let trust = StaticTrust::empty().with_pin(peer_fp, Principal::Device("peer".into()));
    let ep = bind(&id, trust, direct_config()).await;
    let peer_ep = bind(&peer_id, StaticTrust::empty(), direct_config()).await;
    let err = tokio::time::timeout(
        Duration::from_secs(2),
        ep.dial(&IrohPeer::new(peer_ep.public_key())),
    )
    .await
    .expect("no timeout wait")
    .unwrap_err();
    // The relay diagnostic keys off this variant, not off the message text.
    assert!(
        matches!(&err, DialError::Failed(inner) if inner.is_no_route()),
        "{err:?}"
    );
}

/// A key that is not an Ed25519 key cannot name an iroh endpoint.
#[tokio::test]
async fn a_non_ed25519_identity_cannot_bind() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let id = qsh_transport::LocalIdentity {
        cert_chain: vec![qsh_transport::CertificateDer::from(cert.der().to_vec())],
        key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
    };
    let err = IrohEndpoint::bind(&id, Arc::new(StaticTrust::empty()), direct_config())
        .await
        .unwrap_err();
    assert!(matches!(err, qsh_transport::SetupError::Iroh(_)), "{err:?}");
}

/// The relay's certificate is verified (ADR-0061 decision 12). An endpoint
/// that trusts only the OS store does not trust the test relay's private
/// certificate and never gets online; the same endpoint with that
/// certificate added to the OS store's roots does.
#[tokio::test]
async fn the_relay_certificate_is_verified_against_the_trust_store() {
    let relay = TestRelay::spawn().await;
    let (id, _fp) = make_identity();

    let distrusting = IrohConfig {
        relay: IrohRelay::Url(relay.url.clone()),
        relay_trust: IrohRelayTrust::System,
        bind: vec![(std::net::Ipv4Addr::LOCALHOST, 0).into()],
        proxy_from_env: false,
    };
    let ep = bind(&id, StaticTrust::empty(), distrusting).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(3), ep.online())
            .await
            .is_err(),
        "an untrusted relay certificate must not be accepted"
    );
    // Not just "never online": the certificate itself fails verification
    // against the trust anchors the endpoint uses, with the unknown-issuer
    // verdict.
    let reason = ep
        .probe_relay_tls(relay.addr())
        .await
        .expect_err("a private relay certificate must not verify against the OS store");
    // The verdict's wording is the platform verifier's: rustls-webpki says
    // `UnknownIssuer` on Linux and Windows, while macOS Security.framework
    // reports the chain as "not trusted" (errSecNotTrusted, -67843).
    assert!(
        reason.contains("UnknownIssuer") || reason.contains("is not trusted"),
        "expected an untrusted-issuer verdict, got: {reason}"
    );
    ep.close().await;

    let trusting = IrohConfig {
        relay: IrohRelay::Url(relay.url.clone()),
        relay_trust: IrohRelayTrust::SystemWithRoots(vec![relay.cert.clone()]),
        bind: vec![(std::net::Ipv4Addr::LOCALHOST, 0).into()],
        proxy_from_env: false,
    };
    let ep = bind(&id, StaticTrust::empty(), trusting).await;
    tokio::time::timeout(DEADLINE, ep.online())
        .await
        .expect("a relay whose root is trusted comes online");
    ep.probe_relay_tls(relay.addr())
        .await
        .expect("the added root verifies the relay certificate");
    ep.close().await;
}

/// A relay-only dial: the dialer knows the server's key and the relay URL
/// and nothing else (no direct address), as an `iroh` route would.
#[tokio::test]
async fn a_relay_only_dial_reaches_a_server_known_by_key() {
    let p = iroh_pair(Route::Relay).await;
    let (mut send, mut recv) = tokio::time::timeout(DEADLINE, p.client.open_bi())
        .await
        .unwrap()
        .unwrap();
    send.write_all(b"over-relay").await.unwrap();
    send.finish().unwrap();
    let (mut s_send, mut s_recv) = tokio::time::timeout(DEADLINE, p.server.accept_bi())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s_recv.read_to_end(64).await.unwrap(), b"over-relay");
    s_send.write_all(b"ok").await.unwrap();
    s_send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"ok");
}

/// A connection reports the peer by key and the path in use, and renders
/// as `iroh:<fingerprint>` on either path (`docs/CLI.md` §6.22).
#[tokio::test]
async fn remote_address_names_the_peer_key_and_the_path() {
    let p = iroh_pair(Route::Direct).await;
    let expect_display = format!("iroh:{}", p.server_fp);
    let seen = p.client.remote_address();
    assert_eq!(seen.to_string(), expect_display);
    assert_eq!(seen.key(), Some(&PeerKey(p.server_ep.public_key())));
    match &seen {
        PeerAddr::Keyed {
            path: PeerPath::Direct(addr),
            ..
        } => assert!(
            p.server_ep
                .bound_sockets()
                .iter()
                .any(|s| s.port() == addr.port())
        ),
        other => panic!("expected a direct keyed path, got {other:?}"),
    }
    assert_eq!(
        p.server.remote_address().to_string(),
        format!("iroh:{}", p.client_fp)
    );

    let r = iroh_pair(Route::Relay).await;
    // Right after the handshake the connection may still be on the relay;
    // either way the key is the peer's and the text does not change.
    let seen = r.client.remote_address();
    assert_eq!(seen.to_string(), format!("iroh:{}", r.server_fp));
    assert_eq!(seen.key(), Some(&PeerKey(r.server_ep.public_key())));
    assert!(
        matches!(
            seen,
            PeerAddr::Keyed {
                path: PeerPath::Relay(_) | PeerPath::Direct(_),
                ..
            }
        ),
        "{seen:?}"
    );
}
