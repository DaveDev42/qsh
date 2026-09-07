//! A raw, anonymous QUIC client bound to a caller-chosen loopback source
//! address — for driving traffic at admission's `Gate::decide`
//! (`crates/qsh-core/src/admission.rs`), which runs at the QUIC accept/Retry
//! layer strictly before any qsh TLS identity is checked. That layer needs
//! no real device identity or server-pin verification to exercise, only a
//! source address `qsh_transport::Dialer::dial` has no seam to choose
//! (it always binds `0.0.0.0`).
//!
//! Moved here from `crates/qsh-cli/tests/adversarial_load.rs` (`BRIEF-4c.md`
//! §4.1/J3, 4c adversarial review finding B13): `qsh-cli` already carries
//! `qsh-testkit` as a dev-dependency, and this crate already depends on
//! `quinn` as a real (non-dev) dependency, so adding `rustls` here avoids
//! `qsh-cli` needing its own `quinn`/`rustls` dev-dependencies just for this
//! one scenario.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// Anonymous TLS client config: skips server certificate verification
/// entirely and presents no client certificate. Safe here specifically
/// because admission's `Gate::decide` runs before qsh's own TLS identity
/// check ever sees this traffic — there is nothing this client needs to
/// prove, and it never carries real session data.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn raw_client_config() -> quinn::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .expect("rustls config is valid for QUIC");
    quinn::ClientConfig::new(Arc::new(quic))
}

/// A raw client `quinn::Endpoint` bound to `ip:0` — `None` if the bind
/// itself fails (a caller expecting several source addresses to bind should
/// tolerate some failing rather than treat any single one as fatal).
pub fn raw_source_endpoint(ip: Ipv4Addr) -> Option<quinn::Endpoint> {
    let socket = qsh_transport::bind_tuned_udp_socket(SocketAddr::new(ip.into(), 0), true).ok()?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .ok()?;
    endpoint.set_default_client_config(raw_client_config());
    Some(endpoint)
}
