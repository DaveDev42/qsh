//! quinn and rustls configuration: TLS, transport parameters, the server's
//! admission bounds and the endpoint config (stateless reset and CID keys).
//! The numbers live in `endpoint` (they are the neutral tuning contract);
//! this module is where they reach quinn.

use std::sync::Arc;

use quinn::crypto::rustls::QuicServerConfig;

use crate::endpoint::{
    CONNECTION_RECEIVE_WINDOW, DATAGRAM_RECEIVE_BUFFER_SIZE, DATAGRAM_SEND_BUFFER_SIZE,
    INCOMING_BUFFER_SIZE, INCOMING_BUFFER_SIZE_TOTAL, LocalIdentity, MAX_CONCURRENT_BIDI_STREAMS,
    MAX_IDLE_TIMEOUT, MAX_INCOMING, RESET_KEY_LEN, SetupError, TUNNEL_STREAM_RECEIVE_WINDOW,
    TransportTuning,
};
use crate::tls::QshPeerVerifier;

/// The congestion controller factory every qsh connection uses: BBR
/// (`docs/design/protocol.md` §12). Its own function so a unit test can build
/// a controller from it, because `quinn::TransportConfig` does not print the
/// factory in `Debug`.
/// `identity`'s chain in rustls' certificate type (the neutral type is
/// converted here, at the backend boundary).
fn tls_chain(identity: &LocalIdentity) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    identity
        .cert_chain
        .iter()
        .map(|c| rustls::pki_types::CertificateDer::from(c.to_vec()))
        .collect()
}

/// `identity`'s private key in rustls' type.
fn identity_key(identity: &LocalIdentity) -> rustls::pki_types::PrivateKeyDer<'static> {
    rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        identity.key_pkcs8_der.to_vec(),
    ))
}

pub(crate) fn congestion_controller_factory() -> Arc<quinn::congestion::BbrConfig> {
    Arc::new(quinn::congestion::BbrConfig::default())
}

pub(crate) fn transport_config(tuning: TransportTuning) -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.keep_alive_interval(Some(tuning.keep_alive));
    tc.max_idle_timeout(Some(
        MAX_IDLE_TIMEOUT
            .try_into()
            .expect("45s fits in a QUIC idle timeout VarInt"),
    ));
    tc.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    // Tunnel/backpressure config (`docs/design/protocol.md` §12,
    // M4 plan Step 2 (2473c88)) — priority (queue order, applied per-stream at
    // the call site: `qsh_transport::control::FramedSend::set_priority`,
    // `qsh_proto::wire::PRIORITY_TUNNEL`) plus these three connection-level
    // knobs (queue depth), so a saturated tunnel cannot starve PTY chunks
    // buffered behind it:
    tc.congestion_controller_factory(congestion_controller_factory());
    tc.send_fairness(true);
    // QUIC DATAGRAM, enabled as an optional carrier (ADR-0052 decision 7).
    // Quinn's defaults (1.25 MB receive, 1 MiB send) are pinned down here so
    // the memory bound is ours; a unit test reads these constants.
    tc.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_SIZE));
    tc.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER_SIZE);
    tc.stream_receive_window(quinn::VarInt::from_u32(TUNNEL_STREAM_RECEIVE_WINDOW));
    // `docs/ROADMAP.md` M8 DoD 2 ("세션당 buffer ≤ 8 MB") — see
    // `CONNECTION_RECEIVE_WINDOW`'s own doc for the derivation. Never set
    // before M8 Step 2, so this connection-wide ceiling was quinn's own
    // `VarInt::MAX` (unbounded) the whole time `stream_receive_window`
    // above was already finite per-stream.
    tc.receive_window(
        quinn::VarInt::try_from(CONNECTION_RECEIVE_WINDOW).expect("8 MiB fits in a QUIC VarInt"),
    );
    tc
}

/// The `Debug` rendering of the `quinn::TransportConfig` that `tuning`
/// produces. A test seam: `quinn::TransportConfig` has no public getters,
/// so a caller in another crate (the `[transport].keep_alive_ms` tests in
/// `qsh-core`) can only observe what reached quinn through its `Debug`
/// output, exactly as this module's own tests do.
#[doc(hidden)]
pub fn transport_config_debug(tuning: TransportTuning) -> String {
    format!("{:?}", transport_config(tuning))
}

pub(crate) fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

pub(crate) fn client_tls_config(
    identity: &LocalIdentity,
    verifier: Arc<QshPeerVerifier>,
) -> Result<rustls::ClientConfig, SetupError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(tls_chain(identity), identity_key(identity))?;
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    // No 0-RTT, no session resumption (`protocol.md` §2).
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    // Never put the dialed hostname on the wire: the server verifies by
    // pin and ignores SNI, so it would only leak the name to on-path
    // observers (`docs/adr/0040-ech-policy.md` decision 2). rustls still
    // takes a `ServerName` for verification plumbing.
    tls.enable_sni = false;
    Ok(tls)
}

pub(crate) fn server_tls_config(
    identity: &LocalIdentity,
    verifier: Arc<QshPeerVerifier>,
) -> Result<rustls::ServerConfig, SetupError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(tls_chain(identity), identity_key(identity))?;
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    // No early data, no tickets: every connection re-runs full mutual
    // authentication (`protocol.md` §2).
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(tls)
}

/// Build the `quinn::ServerConfig` [`Listener::bind_inner`] hands to
/// `quinn::Endpoint::new` — TLS, the given `transport`, and the L0
/// admission bounds ([`MAX_INCOMING`]/[`INCOMING_BUFFER_SIZE`]/
/// [`INCOMING_BUFFER_SIZE_TOTAL`], M8 plan Step 2 (52639fc), `docs/adr/0009-
/// admission-defenses.md`) — never set before M8, so these sat at quinn's
/// own defaults (65536 / 10 MiB / 100 MiB, `quinn-proto` `config/mod.rs`).
/// This is L0 of the L0-L5 admission ordering: the cheap shed quinn
/// applies *before* deriving Initial keys or handing us an `Incoming` at
/// all — `admission::Gate` (qsh-core) is L2-L3, one layer above, and only
/// ever sees what gets past this.
///
/// **The single construction site** (M8 plan Step 2 (52639fc) verification
/// round, P2-1): before this existed, the test that pinned these three
/// bounds (`tests::server_config_sets_admission_bounds`) rebuilt its own
/// copy of this same sequence of calls and asserted against *that* copy —
/// tautological, since deleting the setters from `bind_inner` alone
/// (leaving the test's copy untouched) left the test green. `bind_inner`
/// and the test now both call this one function, so there is exactly one
/// place the three bounds can be set, and the test asserts on the actual
/// production construction path.
pub(crate) fn server_config(
    identity: &LocalIdentity,
    verifier: Arc<QshPeerVerifier>,
    transport: quinn::TransportConfig,
) -> Result<quinn::ServerConfig, SetupError> {
    let tls = server_tls_config(identity, verifier)?;
    let quic = QuicServerConfig::try_from(tls).map_err(|e| SetupError::Quic(e.to_string()))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server_config.transport_config(Arc::new(transport));
    server_config
        .max_incoming(MAX_INCOMING)
        .incoming_buffer_size(INCOMING_BUFFER_SIZE)
        .incoming_buffer_size_total(INCOMING_BUFFER_SIZE_TOTAL);
    Ok(server_config)
}

/// The server endpoint's `quinn::EndpointConfig`: quinn's own default
/// (a fresh random HMAC key per process) when `reset_key` is `None`, else
/// the given key, so a restarted process derives the same stateless reset
/// token for a connection ID the previous process issued (RFC 9000 §10.3,
/// `docs/design/reexec-estimate.md` §3 H1b). The only construction site of
/// a server `EndpointConfig`; the client endpoint and the testkit's raw
/// quinn path keep `default()`.
///
/// The connection ID generator is keyed from the same secret. quinn drops a
/// short-header packet whose destination ID its generator cannot validate
/// *before* it considers a stateless reset, and the default generator draws
/// a fresh key per process, so a restarted endpoint would silently discard
/// every packet of a connection it issued IDs for and the reset key alone
/// would change nothing. The generator key is a domain-separated HMAC
/// output, so it reveals nothing about the reset key.
pub(crate) fn server_endpoint_config(
    reset_key: Option<&[u8; RESET_KEY_LEN]>,
) -> quinn::EndpointConfig {
    let Some(key) = reset_key else {
        return quinn::EndpointConfig::default();
    };
    let hmac_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let tag = aws_lc_rs::hmac::sign(&hmac_key, CID_KEY_LABEL);
    let mut cid_key = [0u8; 8];
    cid_key.copy_from_slice(&tag.as_ref()[..8]);
    let cid_key = u64::from_le_bytes(cid_key);
    let mut config = quinn::EndpointConfig::new(Arc::new(hmac_key));
    config.cid_generator(move || {
        Box::new(quinn_proto::HashedConnectionIdGenerator::from_key(cid_key))
    });
    config
}

/// Domain separation label for the connection ID generator key derived in
/// [`server_endpoint_config`].
pub(crate) const CID_KEY_LABEL: &[u8] = b"qsh stateless reset: connection id generator key v1";
