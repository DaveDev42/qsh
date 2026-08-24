//! Test-only scaffolding shared by this module tree's tests: a
//! same-process, mutually-pinned forward-route QUIC connection pair.
//!
//! Hand-rolled here rather than reached for from `qsh-testkit`, because
//! `qsh-testkit` depends on `qsh-core` and never the reverse
//! (`docs/design/architecture.md` §1's dependency matrix), so this crate's
//! own unit tests cannot use that harness.

use std::sync::Arc;

use qsh_transport::{
    CertificateDer, Connection, Dialer, Fingerprint, Listener, LocalIdentity, Principal,
    StaticTrust,
};

/// A fresh self-signed identity plus its SPKI fingerprint.
pub(crate) fn self_signed() -> (LocalIdentity, Fingerprint) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    let cert = params.self_signed(&key).expect("self-sign");
    let der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = Fingerprint::of_cert_der(&der).expect("fingerprint");
    (
        LocalIdentity {
            cert_chain: vec![der],
            key_pkcs8_der: key.serialize_der(),
        },
        fingerprint,
    )
}

/// `(client, server)` ends of one live, mutually-pinned QUIC connection on
/// loopback. Port 0 bind (`docs/design/testing.md`'s CI rule).
pub(crate) async fn loopback_pair() -> (Connection, Connection) {
    let (client_id, client_fp) = self_signed();
    let (server_id, server_fp) = self_signed();
    let server_trust = StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
    let client_trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("box".into()));

    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_id,
        Arc::new(server_trust),
    )
    .unwrap();
    let addr = listener.local_addr().unwrap();
    let dialer = Dialer::new(client_id, Arc::new(client_trust));
    let (server, client) = tokio::join!(
        async { listener.accept().await.unwrap().accept().await.unwrap() },
        async { dialer.dial(addr, "127.0.0.1").await.unwrap().connection },
    );
    (client, server)
}
