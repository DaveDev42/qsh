//! quinn endpoint construction (`docs/design/protocol.md` §2, §4):
//! ALPN `qsh/1`, TLS 1.3 only, keep-alive 15 s / idle 45 s, **no 0-RTT**,
//! **no session tickets** (long-lived connections; a resumed handshake must
//! never skip client-certificate verification), mutual authentication via
//! [`QshPeerVerifier`] on both sides.
//!
//! [`Dialer`] and [`Listener`] are the only two ways to obtain a
//! [`Connection`]; a `Connection` always carries the peer's verified
//! [`Principal`], computed from the certificate chain — never from wire data.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use socket2::{Domain, Protocol, Socket, Type};
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

/// Peer-advertised cap on concurrently open bidirectional streams per
/// connection, set explicitly rather than left at quinn's own default
/// (100 as of quinn-proto 0.11) — one registration connection
/// (`qsh reverse`) carries a persistent `LOCAL_CONTROL` relay stream plus
/// one QUIC bidi stream per live `LOCAL_STREAM` attach splice
/// (`qsh-core::localctl::daemon`'s `serve_stream`), and that daemon's own
/// `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS` pool cap (256) must always bite
/// *before* this transport-level limit does — otherwise `open_bi` parks
/// against the peer's own cap instead of answering the daemon's clean,
/// bounded `ErrorCode::ResourceExhausted`. Set comfortably above that pool
/// (headroom for the control stream and a few forward-route attaches on
/// the same connection).
pub const MAX_CONCURRENT_BIDI_STREAMS: u32 = 1024;

/// Connection-wide per-stream receive window (`docs/design/protocol.md`
/// §12's bufferbloat defense (a)), sized for tunnel throughput (`protocol.md`
/// §12's sanctioned 2–4 MB tunnel band). **Quinn 0.11 limitation, not a
/// design choice:** `quinn_proto::TransportConfig` only exposes a single
/// connection-wide [`quinn::TransportConfig::stream_receive_window`] —
/// there is no per-stream-*kind* asymmetric window (PTY ~256 KiB vs.
/// tunnel ~2-4 MiB, as `PLAN.md` M4 Step 2 and `protocol.md` §12
/// originally drafted it). Every stream on the connection — PTY session
/// data, exec, the replay ring's own stream, and tunnel/file — gets this
/// same window; PTY protection instead comes from
/// [`qsh_proto::wire::PRIORITY_TUNNEL`] (queue *order*, §12's priority
/// band) plus a send-side depth cap in `qsh_core::tunnel`'s splice path
/// (`SEND_DEPTH_CAP_BYTES`, queue *depth* at the application layer,
/// `docs/design/protocol.md` §12's final note on where the asymmetry
/// actually lives). M4 Step 7 needed both: the priority band alone left
/// DoD 4 (saturated-tunnel-vs-PTY-echo p95) at p95=30.579ms against a
/// <10ms bar; the depth cap is what closed the gap (see
/// `SEND_DEPTH_CAP_BYTES`'s own doc for the measured before/after). If a
/// future quinn release adds a per-stream-type window, prefer it over
/// this connection-wide value and update this doc.
///
/// **Why 2 MiB, not larger or smaller.** The window is a hard ceiling on
/// single-stream throughput over a real (non-loopback) path: at most
/// `window / RTT` bytes/sec can be in flight unacked on one stream, so a
/// window sized for a fast LAN starves a WAN tunnel and a window sized
/// for a slow WAN wastes memory on a fast link. §12's 2–4 MB band is
/// chosen against a representative broadband/mobile RTT (~50 ms): 2 MiB /
/// 50 ms ≈ 42 MB/s, comfortably above what a single forwarded TCP
/// connection needs. M4 Step 7's saturated-tunnel-vs-PTY-echo perf gate
/// (`crates/qsh-testkit/tests/tunnel_echo_under_load.rs` and
/// `tunnel_throughput.rs`) first tried the low end of that reasoning —
/// 128 KiB — and rejected it: 128 KiB / 50 ms ≈ 2.6 MB/s, a throughput
/// ceiling *every* stream on the connection now shares, PTY/exec/replay
/// included, not just tunnel/file. The loopback ratio gate (DoD 3) cannot
/// see this regression — both its raw-quinn baseline and its tunnel leg
/// share the one connection-wide window either way — which is exactly why
/// this constant needs a floor assertion in code (see this module's
/// tests), not just a passing perf number. 2 MiB is the value that
/// landed: inside §12's sanctioned band, and above quinn's own default
/// `STREAM_RWND` (1,250,000 bytes) rather than below it.
pub const TUNNEL_STREAM_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;

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
    tc.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    // Tunnel/backpressure config (`docs/design/protocol.md` §12,
    // `PLAN.md` M4 Step 2) — priority (queue order, applied per-stream at
    // the call site: `qsh_transport::control::FramedSend::set_priority`,
    // `qsh_proto::wire::PRIORITY_TUNNEL`) plus these three connection-level
    // knobs (queue depth), so a saturated tunnel cannot starve PTY chunks
    // buffered behind it:
    tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    tc.send_fairness(true);
    tc.stream_receive_window(quinn::VarInt::from_u32(TUNNEL_STREAM_RECEIVE_WINDOW));
    tc
}

/// Descending candidate ladder for the UDP socket buffer tuning below.
/// Deliberately **decoupled** from [`TUNNEL_STREAM_RECEIVE_WINDOW`]: the
/// window is a QUIC-level flow-control ceiling tuned against the M4 perf
/// DoDs (and, per that constant's own doc, may need to come *down* to
/// protect PTY latency), while this ladder is a queue-*depth* floor one
/// layer below it (the OS socket) that must never shrink — a socket
/// buffer smaller than whatever window is in effect would itself become
/// the bottleneck a bufferbloat-sensitive stream queues behind, defeating
/// the point regardless of which window value wins. Kept independent
/// (and always ≥ the current window) rather than derived from it, so a
/// future window change can never accidentally shrink this.
const SOCKET_BUFFER_LADDER_BYTES: [usize; 4] = [
    8 * 1024 * 1024,
    4 * 1024 * 1024,
    2 * 1024 * 1024,
    1024 * 1024,
];

/// Try each rung of [`SOCKET_BUFFER_LADDER_BYTES`], largest first, keeping
/// the first rung whose OS-granted result beats what the OS already had
/// before this function touched it (`get`/`set` are `recv_buffer_size`/
/// `set_recv_buffer_size` or the `send_*` pair). **Never reduces the
/// buffer:** a candidate at or below the already-granted default is
/// skipped outright (never handed to `set`), and a rung whose `set`
/// either fails or is silently clamped back down to (or below) the
/// default is undone by re-asserting the default before the next
/// (smaller) rung is tried — so a clamped-low attempt can never leave the
/// socket worse off than it started, and this function is safe to call
/// even on a platform whose default already exceeds every rung.
///
/// **Why independently sized ladders per direction, not one shared call.**
/// macOS grants a default `SO_RCVBUF` of ~768 KiB but a default
/// `SO_SNDBUF` of only ~9 KiB — the two directions differ by two orders
/// of magnitude on the same platform, so a single fixed request applied
/// to both (this file's previous approach: a flat 128 KiB for both) was a
/// measured **6x reduction** of macOS's own recv default, the opposite of
/// what `docs/design/testing.md`'s CI 규율 ("GHA macOS runner는 UDP 소켓
/// 버퍼 기본값이 작다") exists to guard against. Sizing each direction
/// from its own read-back default, independently, is what keeps a
/// well-provisioned platform's default from ever being *reduced* by this
/// tuning.
fn tune_socket_buffer(
    socket: &Socket,
    get: impl Fn(&Socket) -> io::Result<usize>,
    set: impl Fn(&Socket, usize) -> io::Result<()>,
) {
    let Ok(default) = get(socket) else {
        // Can't read the baseline back — nothing safe to compare against,
        // so leave the socket untouched rather than risk a reduction.
        return;
    };
    for candidate in SOCKET_BUFFER_LADDER_BYTES {
        if candidate <= default {
            // Never call `set` with a value at or below the read-back
            // default — either it would be a no-op or, on a platform that
            // honors requests literally instead of clamping them up, a
            // reduction.
            continue;
        }
        if set(socket, candidate).is_err() {
            continue;
        }
        match get(socket) {
            Ok(granted) if granted > default => return,
            _ => {
                // Didn't stick, or the OS granted something at/below the
                // default — restore before trying a smaller rung.
                let _ = set(socket, default);
            }
        }
    }
}

/// Bind a UDP socket at `addr` with [`tune_socket_buffer`] applied
/// independently to each direction, in place of
/// `quinn::Endpoint::client`/`::server`'s own internal bind (which offers
/// no way to ask for a bigger buffer). `dual_stack_v6` mirrors
/// `quinn::Endpoint::client`'s own best-effort `IPV6_V6ONLY` handling for
/// a wildcard v6 bind — `Listener::bind` never asked for this (its
/// `Endpoint::server` precedent didn't either), so only
/// [`Dialer::dial`]'s replacement passes `true`. Also used by
/// `qsh_core::client::reconnect`'s migration rebind (`PathBinder`), so a
/// post-migration socket keeps the same tuning and dual-stack behavior
/// the original dial got.
///
/// Every step here is best-effort except the bind itself: a platform that
/// refuses (or silently caps) the buffer request keeps its own default,
/// which only degrades *how fast* a loopback benchmark can measure, never
/// correctness (`crates/qsh-testkit/tests/tunnel_throughput.rs`'s own
/// module doc walks through why the M4 DoD 3 ratio gate is tolerant of
/// this either way).
pub fn bind_tuned_udp_socket(
    addr: SocketAddr,
    dual_stack_v6: bool,
) -> io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if dual_stack_v6 && addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    tune_socket_buffer(
        &socket,
        Socket::recv_buffer_size,
        Socket::set_recv_buffer_size,
    );
    tune_socket_buffer(
        &socket,
        Socket::send_buffer_size,
        Socket::set_send_buffer_size,
    );
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
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
    peer_fingerprint: Option<Fingerprint>,
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

    /// SPKI SHA-256 fingerprint of the peer's verified leaf certificate.
    ///
    /// `None` only if the leaf failed to re-parse after the verifier
    /// already accepted it (not reachable in practice). This is the value
    /// a resume credential is bound to (`docs/design/protocol.md` §10: the
    /// host stores `peer_spki_sha256` beside the token hash), and it is
    /// **not** an ACL input — authorization runs on
    /// [`principal`](Self::principal).
    pub fn peer_fingerprint(&self) -> Option<Fingerprint> {
        self.peer_fingerprint
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

    /// RFC 5705 TLS exporter — the channel-binding primitive pairing uses
    /// to derive its proof (ADR-0002, `docs/design/protocol.md` §15): both
    /// peers independently compute the same value from their shared TLS
    /// session, so a proof relayed by a MITM terminating two separate TLS
    /// sessions never verifies on the leg it didn't originate on.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), quinn::crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
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
        self.dial_inner(addr, server_name, transport_config()).await
    }

    /// Test/benchmark-only escape hatch: identical to [`Self::dial`] —
    /// same TLS/identity plumbing, same socket tuning — except the
    /// `TransportConfig` is quinn's own stock `TransportConfig::default()`
    /// instead of qsh's tuned `transport_config()` (no BBR override, no
    /// `send_fairness`, no widened `stream_receive_window`). Exists for
    /// the M4 DoD 3 throughput gate
    /// (`crates/qsh-testkit/tests/tunnel_throughput.rs`), which needs an
    /// *untuned* quinn baseline to compare qsh's tuning against — without
    /// this, the gate's raw-quinn leg would share `transport_config()`
    /// with the tunnel leg, and the ratio would only ever measure
    /// `qsh-core`'s splice overhead, never whether the transport tuning
    /// itself helps.
    pub async fn dial_stock_transport(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Dialed, DialError> {
        self.dial_inner(addr, server_name, quinn::TransportConfig::default())
            .await
    }

    async fn dial_inner(
        &self,
        addr: SocketAddr,
        server_name: &str,
        transport: quinn::TransportConfig,
    ) -> Result<Dialed, DialError> {
        let verifier = Arc::new(QshPeerVerifier::new(self.evaluator.clone()));
        let tls = client_tls_config(&self.identity, verifier.clone())?;
        let quic = QuicClientConfig::try_from(tls).map_err(SetupError::from)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
        client_config.transport_config(Arc::new(transport));

        // Bind in the remote's address family so we never rely on
        // dual-stack sockets.
        let bind: SocketAddr = match addr.ip() {
            IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = bind_tuned_udp_socket(bind, true)
            .map_err(|source| SetupError::Bind { addr: bind, source })?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
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
                peer_fingerprint: chain.first().and_then(|c| Fingerprint::of_cert_der(c).ok()),
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
        Self::bind_inner(bind, identity, evaluator, transport_config())
    }

    /// Test/benchmark-only escape hatch — see
    /// [`Dialer::dial_stock_transport`]'s own doc. Identical to
    /// [`Self::bind`] except the `TransportConfig` is quinn's stock
    /// `TransportConfig::default()`.
    pub fn bind_stock_transport(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
    ) -> Result<Self, SetupError> {
        Self::bind_inner(bind, identity, evaluator, quinn::TransportConfig::default())
    }

    fn bind_inner(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        transport: quinn::TransportConfig,
    ) -> Result<Self, SetupError> {
        let verifier = Arc::new(QshPeerVerifier::new(evaluator));
        let tls = server_tls_config(&identity, verifier.clone())?;
        let quic = QuicServerConfig::try_from(tls)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
        server_config.transport_config(Arc::new(transport));
        let socket = bind_tuned_udp_socket(bind, false)
            .map_err(|source| SetupError::Bind { addr: bind, source })?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
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
                peer_fingerprint: chain.first().and_then(|c| Fingerprint::of_cert_der(c).ok()),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// (b) `send_fairness` and the tunnel-sized `stream_receive_window`
    /// are actually set on the `TransportConfig` every dial/listen builds
    /// (`docs/design/protocol.md` §12, `PLAN.md` M4 Step 2) —
    /// `TransportConfig`'s congestion controller has no public getter
    /// (quinn-proto stores it as `Arc<dyn ControllerFactory>`, `Debug`
    /// explicitly excludes it — see [`TUNNEL_STREAM_RECEIVE_WINDOW`]'s own
    /// doc), so the BBR selection itself is asserted indirectly: every
    /// existing forward/reverse loopback test in this workspace dials and
    /// listens through this exact `transport_config()`, so a
    /// `congestion_controller_factory` call that panicked or silently
    /// no-op'd would already show up there.
    #[test]
    fn transport_config_sets_send_fairness_and_tunnel_receive_window() {
        let tc = transport_config();
        let debug = format!("{tc:?}");
        assert!(
            debug.contains("send_fairness: true"),
            "expected send_fairness: true in {debug:?}"
        );
        assert!(
            debug.contains(&format!(
                "stream_receive_window: {TUNNEL_STREAM_RECEIVE_WINDOW}"
            )),
            "expected stream_receive_window: {TUNNEL_STREAM_RECEIVE_WINDOW} in {debug:?}"
        );
    }

    /// M4 Step 7's loud regression guard for
    /// [`TUNNEL_STREAM_RECEIVE_WINDOW`]: the DoD 3 loopback throughput
    /// ratio gate (`crates/qsh-testkit/tests/tunnel_throughput.rs`)
    /// structurally *cannot* catch a window regression — even with a
    /// stock-quinn baseline (`Dialer::dial_stock_transport`), a loopback
    /// path's near-zero RTT means almost any window value clears the
    /// ratio floor; window strangling only shows up over a real RTT. So
    /// this constant needs a plain floor assertion here instead: quinn
    /// 0.11's own default `stream_receive_window`
    /// (`quinn_proto::TransportConfig::default()`, i.e. `STREAM_RWND`) is
    /// 1,250,000 bytes, and this constant must never regress *below*
    /// quinn's own untuned default — doing so would mean qsh's "tuning"
    /// made every stream's flow-control window worse than doing nothing.
    #[test]
    fn tunnel_stream_receive_window_never_regresses_below_quinns_own_default() {
        const QUINN_DEFAULT_STREAM_RWND: u32 = 1_250_000;
        // `black_box` on both sides: without it, this is a comparison of
        // two `const`s and clippy's `assertions_on_constants` (correctly)
        // flags a constant-folded assertion as pointless. The whole point
        // here *is* that both are compile-time constants — the assertion
        // still needs to run so a future edit to either one is caught.
        assert!(
            std::hint::black_box(TUNNEL_STREAM_RECEIVE_WINDOW)
                >= std::hint::black_box(QUINN_DEFAULT_STREAM_RWND),
            "TUNNEL_STREAM_RECEIVE_WINDOW ({TUNNEL_STREAM_RECEIVE_WINDOW}) must stay at or \
             above quinn's own default STREAM_RWND ({QUINN_DEFAULT_STREAM_RWND}) — the DoD 3 \
             loopback ratio gate cannot see a window regression (both its baseline and tunnel \
             legs run over ~0 RTT, where almost any window clears the ratio floor), so this \
             floor is the only thing standing between a bad edit and a silently strangled \
             stream on a real (non-loopback) path"
        );
    }
}
