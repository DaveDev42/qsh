//! Real quinn endpoints on a [`NetSocket`], for tests that
//! only need a QUIC connection and not qsh's identity layer.
//!
//! The server presents a fresh self-signed certificate and the client skips
//! certificate verification, the same stand-in `raw_quic` uses. Both speak
//! qsh's ALPN. The runtime is quinn's tokio runtime, so a test that wants
//! virtual time runs under `#[tokio::test(start_paused = true)]`.

use std::io;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::NetSocket;

/// The TLS name clients dial.
pub const SERVER_NAME: &str = "netsim.test";

#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// The client half of a QUIC configuration (no server certificate check).
pub fn client_config() -> io::Result<quinn::ClientConfig> {
    let provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(tls).map_err(other)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

/// A server configuration with a fresh self-signed certificate.
pub fn server_config() -> io::Result<quinn::ServerConfig> {
    let certified =
        rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).map_err(other)?;
    let cert = certified.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(other)?;
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(tls).map_err(other)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

/// A quinn endpoint on `socket` that accepts connections and can also dial
/// (the same shape the hole-punching target needs).
pub fn server_endpoint(socket: NetSocket) -> io::Result<quinn::Endpoint> {
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config()?),
        Arc::new(socket),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}

/// A dial-only quinn endpoint on `socket`.
pub fn client_endpoint(socket: NetSocket) -> io::Result<quinn::Endpoint> {
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        Arc::new(socket),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}
