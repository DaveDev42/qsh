//! quinn endpoint construction (`docs/design/protocol.md` §2, §4):
//! ALPN `qsh/1`, TLS 1.3 only, keep-alive 15 s / idle 45 s, **no 0-RTT**,
//! **no session tickets** (long-lived connections; a resumed handshake must
//! never skip client-certificate verification), mutual authentication via
//! [`QshPeerVerifier`] on both sides.
//!
//! [`Dialer`] and [`Listener`] are the only two ways to obtain a
//! [`Connection`]; a `Connection` always carries the peer's verified
//! [`Principal`], computed from the certificate chain — never from wire data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;

use crate::identity::{Fingerprint, Principal};
use crate::tls::{AuthPath, Observation, PeerRole, QshPeerVerifier, RejectReason, TrustEvaluator};

/// Application-level keep-alive interval (`protocol.md` §2).
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Max idle timeout before the connection is considered dead (`protocol.md` §2).
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Default bound on how long a dial may take before it is reported as
/// `CONNECTION_FAILED` (much shorter than the idle timeout — a dial that
/// gets no response should fail fast).
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// QUIC application close code sent when the peer's principal cannot be
/// re-derived after the handshake (should be unreachable — the verifier
/// already ran — but fail closed).
pub const CLOSE_CODE_UNVERIFIED_PEER: u32 = 0x1001;
/// QUIC application close code for a protocol violation on the control
/// stream (bad Hello, oversize frame, unknown stream header…).
pub const CLOSE_CODE_PROTOCOL: u32 = 0x1002;

/// The local device's cert chain and private key (PKCS#8 DER).
#[derive(Clone)]
pub struct LocalIdentity {
    /// Leaf first. Self-signed device certs are a chain of one.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// PKCS#8 DER private key.
    pub key_pkcs8_der: Vec<u8>,
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never Debug-print key material.
        f.debug_struct("LocalIdentity")
            .field("cert_chain_len", &self.cert_chain.len())
            .finish_non_exhaustive()
    }
}

impl LocalIdentity {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()))
    }
}

/// Errors building endpoints.
#[derive(Debug, Error)]
pub enum SetupError {
    /// rustls rejected the configuration (bad key/cert…).
    #[error("tls config: {0}")]
    Tls(#[from] rustls::Error),
    /// quinn rejected the rustls config (e.g. missing TLS 1.3).
    #[error("quic crypto config: {0}")]
    Quic(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    /// Socket bind failed.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The address we tried to bind.
        addr: SocketAddr,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
}

/// Errors from a dial attempt, already classified for the ops layer.
#[derive(Debug, Error)]
pub enum DialError {
    /// Endpoint construction failed.
    #[error(transparent)]
    Setup(#[from] SetupError),
    /// The address/server name was unusable.
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// **We** rejected the peer's certificate (client-side verifier).
    #[error("peer certificate rejected locally ({reason:?})")]
    LocalRejected {
        /// Coarse reason.
        reason: RejectReason,
        /// The peer's SPKI fingerprint, if its cert parsed. This is what a
        /// `TRUST_REQUIRED` error reports as `observed_fingerprint`.
        observed: Option<Fingerprint>,
    },
    /// The **peer** rejected our certificate (or the handshake otherwise
    /// failed cryptographically): the remote side sent a TLS alert /
    /// crypto-class CONNECTION_CLOSE.
    #[error("peer rejected our certificate")]
    RemoteRejected,
    /// The dial did not complete within the timeout.
    #[error("dial timed out after {0:?}")]
    Timeout(Duration),
    /// Any other connection failure (unreachable, reset, idle…).
    #[error("connection failed: {0}")]
    Failed(#[from] quinn::ConnectionError),
}

/// Errors accepting an inbound connection.
#[derive(Debug, Error)]
pub enum AcceptError {
    /// The handshake failed (typically: client cert rejected by the
    /// verifier, or no client cert at all).
    #[error("handshake failed: {0}")]
    Handshake(#[from] quinn::ConnectionError),
    /// Handshake completed but the peer principal could not be derived —
    /// the connection was closed. Should not happen (the verifier ran).
    #[error("peer principal could not be derived ({0:?}); connection closed")]
    Unverified(RejectReason),
    /// The endpoint is shutting down.
    #[error("endpoint closed")]
    Closed,
}

fn transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    tc.max_idle_timeout(Some(
        MAX_IDLE_TIMEOUT
            .try_into()
            .expect("45s fits in a QUIC idle timeout VarInt"),
    ));
    tc
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn client_tls_config(
    identity: &LocalIdentity,
    verifier: Arc<QshPeerVerifier>,
) -> Result<rustls::ClientConfig, SetupError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(identity.cert_chain.clone(), identity.key())?;
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    // No 0-RTT, no session resumption (`protocol.md` §2).
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(tls)
}

fn server_tls_config(
    identity: &LocalIdentity,
    verifier: Arc<QshPeerVerifier>,
) -> Result<rustls::ServerConfig, SetupError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.cert_chain.clone(), identity.key())?;
    tls.alpn_protocols = vec![qsh_proto::wire::ALPN.to_vec()];
    // No early data, no tickets: every connection re-runs full mutual
    // authentication (`protocol.md` §2).
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(tls)
}

/// A verified QUIC connection: quinn's connection plus the peer's
/// certificate-derived principal.
#[derive(Clone, Debug)]
pub struct Connection {
    inner: quinn::Connection,
    principal: Principal,
    auth_path: AuthPath,
}

impl Connection {
    /// The peer's authenticated principal (the ACL input).
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// How the peer was authenticated (pin vs. CA) — the other ACL input.
    pub fn auth_path(&self) -> AuthPath {
        self.auth_path
    }

    /// Peer socket address (may change over the connection's life via
    /// migration; this is the current one).
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Stable id for logs/audit (`quinn::Connection::stable_id`).
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError> {
        self.inner.open_bi().await
    }

    /// Accept the next peer-initiated bidirectional stream.
    pub async fn accept_bi(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError> {
        self.inner.accept_bi().await
    }

    /// Close with an application error code and reason. Idempotent.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(quinn::VarInt::from_u32(code), reason);
    }

    /// Resolves when the connection is closed (by either side).
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.inner.closed().await
    }

    /// If the connection is already closed, why.
    pub fn close_reason(&self) -> Option<quinn::ConnectionError> {
        self.inner.close_reason()
    }

    /// The underlying quinn connection, for transport-level features not
    /// wrapped here (rebind, stats). Not for identity — use
    /// [`principal`](Self::principal).
    pub fn quinn(&self) -> &quinn::Connection {
        &self.inner
    }
}

fn peer_chain(conn: &quinn::Connection) -> Vec<CertificateDer<'static>> {
    conn.peer_identity()
        .and_then(|any| any.downcast::<Vec<CertificateDer<'static>>>().ok())
        .map(|b| *b)
        .unwrap_or_default()
}

/// Client-side factory: dials servers with our identity, verifying them
/// through `evaluator`.
pub struct Dialer {
    identity: LocalIdentity,
    evaluator: Arc<dyn TrustEvaluator>,
    timeout: Duration,
}

impl Dialer {
    /// Create a dialer.
    pub fn new(identity: LocalIdentity, evaluator: Arc<dyn TrustEvaluator>) -> Self {
        Self {
            identity,
            evaluator,
            timeout: DEFAULT_DIAL_TIMEOUT,
        }
    }

    /// Override the dial timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Dial `addr`, presenting `server_name` as SNI (informational only —
    /// the verifier ignores it). Returns the connection with the server's
    /// principal attached, plus the endpoint (which must outlive the
    /// connection).
    pub async fn dial(&self, addr: SocketAddr, server_name: &str) -> Result<Dialed, DialError> {
        let verifier = Arc::new(QshPeerVerifier::new(self.evaluator.clone()));
        let tls = client_tls_config(&self.identity, verifier.clone())?;
        let quic = QuicClientConfig::try_from(tls).map_err(SetupError::from)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
        client_config.transport_config(Arc::new(transport_config()));

        // Bind in the remote's address family so we never rely on
        // dual-stack sockets.
        let bind: SocketAddr = match addr.ip() {
            IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|source| SetupError::Bind { addr: bind, source })?;
        endpoint.set_default_client_config(client_config);

        let connecting = endpoint.connect(addr, server_name)?;
        let result = tokio::time::timeout(self.timeout, connecting).await;
        let conn = match result {
            Err(_) => return Err(DialError::Timeout(self.timeout)),
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => return Err(classify_dial_failure(err, verifier.last_observation())),
        };

        let chain = peer_chain(&conn);
        let verified = match verifier.verify_peer(&chain, PeerRole::Server) {
            Ok(v) => v,
            Err(reason) => {
                conn.close(
                    quinn::VarInt::from_u32(CLOSE_CODE_UNVERIFIED_PEER),
                    b"unverified peer",
                );
                return Err(DialError::LocalRejected {
                    reason,
                    observed: chain.first().and_then(|c| Fingerprint::of_cert_der(c).ok()),
                });
            }
        };
        Ok(Dialed {
            connection: Connection {
                inner: conn,
                principal: verified.principal,
                auth_path: verified.auth_path,
            },
            endpoint,
            verifier,
        })
    }
}

/// A successful dial: connection + the endpoint keeping it alive + the
/// verifier (for its observation).
#[derive(Debug)]
pub struct Dialed {
    /// The verified connection.
    pub connection: Connection,
    /// The client endpoint. Dropping it does **not** immediately close the
    /// connection, but callers should keep it for the connection's life and
    /// call [`quinn::Endpoint::wait_idle`] on shutdown for a clean close.
    pub endpoint: quinn::Endpoint,
    /// The per-dial verifier.
    pub verifier: Arc<QshPeerVerifier>,
}

impl Dialed {
    /// What the verifier saw for the server's certificate.
    pub fn observation(&self) -> Option<Observation> {
        self.verifier.last_observation()
    }
}

/// Map a failed handshake to a [`DialError`], using the verifier's
/// observation to tell "we rejected them" from "they rejected us".
fn classify_dial_failure(err: quinn::ConnectionError, obs: Option<Observation>) -> DialError {
    if let Some(Observation {
        fingerprint,
        outcome: Err(reason),
    }) = obs
    {
        return DialError::LocalRejected {
            reason,
            observed: fingerprint,
        };
    }
    if is_crypto_failure(&err) {
        return DialError::RemoteRejected;
    }
    DialError::Failed(err)
}

/// Whether a connection error is a TLS/crypto-class failure — i.e. the peer
/// (or we) aborted the handshake with a TLS alert. QUIC encodes TLS alerts
/// as transport error codes `0x100 + alert` (RFC 9001 §4.8).
pub fn is_crypto_failure(err: &quinn::ConnectionError) -> bool {
    match err {
        quinn::ConnectionError::TransportError(te) => is_crypto_code(te.code),
        quinn::ConnectionError::ConnectionClosed(cc) => is_crypto_code(cc.error_code),
        _ => false,
    }
}

fn is_crypto_code(code: quinn::TransportErrorCode) -> bool {
    let raw: u64 = code.into();
    (0x100..=0x1ff).contains(&raw)
}

/// Server-side listener: accepts inbound connections, verifying clients
/// through `evaluator`.
pub struct Listener {
    endpoint: quinn::Endpoint,
    verifier: Arc<QshPeerVerifier>,
}

impl Listener {
    /// Bind a server endpoint on `bind`.
    pub fn bind(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
    ) -> Result<Self, SetupError> {
        let verifier = Arc::new(QshPeerVerifier::new(evaluator));
        let tls = server_tls_config(&identity, verifier.clone())?;
        let quic = QuicServerConfig::try_from(tls)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
        server_config.transport_config(Arc::new(transport_config()));
        let endpoint = quinn::Endpoint::server(server_config, bind)
            .map_err(|source| SetupError::Bind { addr: bind, source })?;
        Ok(Self { endpoint, verifier })
    }

    /// The actual bound address (useful with port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Wait for the next inbound connection attempt. `None` when the
    /// endpoint has been closed.
    pub async fn accept(&self) -> Option<Incoming> {
        let incoming = self.endpoint.accept().await?;
        Some(Incoming {
            incoming,
            verifier: self.verifier.clone(),
        })
    }

    /// Begin a graceful shutdown: refuse new connections and close existing
    /// ones with `code`.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.endpoint.close(quinn::VarInt::from_u32(code), reason);
    }

    /// The underlying endpoint (e.g. for `wait_idle`).
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }
}

/// An inbound connection attempt whose handshake has not completed yet.
pub struct Incoming {
    incoming: quinn::Incoming,
    verifier: Arc<QshPeerVerifier>,
}

impl Incoming {
    /// Peer address of the attempt (before authentication — for logs only).
    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }

    /// Run the handshake. Fails if the client presented no/untrusted cert
    /// (the verifier rejected it) — nothing above the transport ever sees
    /// such a peer.
    pub async fn accept(self) -> Result<Connection, AcceptError> {
        let conn = self.incoming.await?;
        let chain = peer_chain(&conn);
        match self.verifier.verify_peer(&chain, PeerRole::Client) {
            Ok(verified) => Ok(Connection {
                inner: conn,
                principal: verified.principal,
                auth_path: verified.auth_path,
            }),
            Err(reason) => {
                conn.close(
                    quinn::VarInt::from_u32(CLOSE_CODE_UNVERIFIED_PEER),
                    b"unverified peer",
                );
                Err(AcceptError::Unverified(reason))
            }
        }
    }
}
