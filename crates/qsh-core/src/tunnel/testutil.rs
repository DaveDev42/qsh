//! Test-only scaffolding shared by this module tree's tests: a
//! same-process, mutually-pinned forward-route QUIC connection pair.
//!
//! Hand-rolled here rather than reached for from `qsh-testkit`, because
//! `qsh-testkit` depends on `qsh-core` and never the reverse
//! (`docs/design/architecture.md` §1's dependency matrix), so this crate's
//! own unit tests cannot use that harness.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::tunnel::remote::{BindHostResolver, LookupFuture};
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

/// A [`BindHostResolver`] that answers from a script and counts how
/// many times it was asked. The count is the point: it is what turns
/// "the address bound is the address validated" into an assertion
/// instead of a comment. A resolver whose answers *change* between
/// calls is exactly the peer-controlled DNS zone
/// `crate::tunnel::remote::resolve_loopback_bind_addr`'s own doc describes.
pub(crate) struct ScriptedResolver {
    answers: Mutex<std::collections::VecDeque<Vec<SocketAddr>>>,
    calls: std::sync::atomic::AtomicUsize,
}

impl ScriptedResolver {
    /// `answers[n]` is what the `n`-th lookup gets; a lookup past the
    /// end of the script reuses the last answer (so a caller that
    /// resolves once cannot accidentally "pass" by running out).
    pub(crate) fn new(answers: Vec<Vec<SocketAddr>>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl BindHostResolver for ScriptedResolver {
    fn lookup<'a>(&'a self, _host: &'a str, _port: u16) -> LookupFuture<'a> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        let answer = if answers.len() > 1 {
            answers.pop_front().unwrap_or_default()
        } else {
            answers.front().cloned().unwrap_or_default()
        };
        Box::pin(async move { Ok(answer) })
    }
}

pub(crate) fn addr(s: &str) -> SocketAddr {
    s.parse().expect("test address literal")
}
