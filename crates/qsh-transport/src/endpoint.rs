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

/// Connection-wide flow-control ceiling (`quinn::TransportConfig::
/// receive_window`) — the total unacked data quinn will let a peer have
/// buffered across *every* stream on one connection combined. Never set
/// before M8 Step 2 (`PLAN.md` M8 Step 2, ROADMAP.md's admission audit
/// sentence), so it sat at quinn's own default `VarInt::MAX` — no ceiling
/// at all, one connection free to hold arbitrarily much unacked data in
/// memory regardless of how many streams it opens.
///
/// **Derivation.** The natural ceiling is "per-stream window × how many
/// streams could plausibly all be at that window at once":
/// [`TUNNEL_STREAM_RECEIVE_WINDOW`] (2 MiB) × [`MAX_CONCURRENT_BIDI_STREAMS`]
/// (1024) = 2 GiB — but `docs/ROADMAP.md` M8 DoD 2 fixes an independent,
/// tighter ceiling directly: **"세션당 buffer ≤ 8 MB"**. The two numbers
/// answer different questions (one is "what could every stream want at
/// once", the other is "what a session is allowed to cost"), so this
/// value is the *smaller* of the two rather than their product — in
/// practice always the 8 MiB DoD ceiling, since the per-stream-window ×
/// stream-count product so vastly exceeds it that no realistic
/// configuration of either constant alone would ever make the product the
/// binding term. A future change to either constant that *did* cross that
/// threshold would silently stop mattering here too — hence `min`, not a
/// bare constant, so the relationship stays visible in code rather than
/// only in this comment.
pub const CONNECTION_RECEIVE_WINDOW: u64 = const_min(
    TUNNEL_STREAM_RECEIVE_WINDOW as u64 * MAX_CONCURRENT_BIDI_STREAMS as u64,
    8 * 1024 * 1024,
);

const fn const_min(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

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
    /// The peer's `admission::Gate` refused us outright: we were already
    /// address-validated but lost the race for a handshake permit
    /// (`PLAN.md` M8 Step 2, `docs/adr/0009-admission-defenses.md`) —
    /// `qsh_transport::Incoming::refuse` on the far end sends exactly one
    /// Initial-scoped `CONNECTION_CLOSE(CONNECTION_REFUSED = 0x2)`. Maps
    /// to the *same* `ErrorCode::ConnectionFailed`/`retryable: true` as
    /// [`DialError::Failed`] (`qsh.cli/v1` is unchanged by this variant
    /// existing) — this only buys a human message that names what
    /// actually happened instead of quinn's raw `closed by peer: 2 ()`.
    #[error(
        "host refused the connection (at capacity or rate-limiting new connections); retry shortly"
    )]
    Refused,
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

/// Cap on `quinn::ServerConfig::max_incoming` — how many inbound connection
/// attempts quinn is willing to hold as an unaccepted `Incoming` (a slab
/// slot plus derived Initial keys already spent) before it starts
/// *ignoring* further Initials without deriving keys at all (`quinn-proto`
/// `endpoint.rs`'s own comment: "deriving initial keys per Initial just to
/// reply with CONNECTION_REFUSED would starve packet processing"). This is
/// L0 of the L0-L5 admission ordering (`docs/adr/0009-admission-
/// defenses.md`) — the backstop *below* `admission::Gate`'s own
/// `max_concurrent_handshakes` (qsh-core `ServeConfig`, default 64), not a
/// replacement for it. Sized as generous headroom above that default
/// (64x) rather than tightened to match it 1:1: `admission::Gate`'s accept
/// loop drains one `Incoming` per iteration with an in-memory decision, so
/// under ordinary load this quinn-level queue should almost never hold
/// more than a handful at once — this cap only bites during a burst faster
/// than the loop can drain synchronously (many Initials landing in one
/// UDP `recv` batch), where quinn's own default (65536) would instead let
/// slab/key-derivation cost scale with attacker-controlled burst size.
/// Deliberately a fixed constant, not derived from the configurable
/// `ServeConfig` value: `qsh-transport` has no config dependency (arch
/// matrix, `CLAUDE.md`) and must not gain one just for this.
pub const MAX_INCOMING: usize = 4096;

/// Per-`Incoming` cap on `quinn::ServerConfig::incoming_buffer_size` —
/// bytes quinn will keep buffering for *one* unaccepted connection attempt
/// (every datagram after the first Initial that created the `Incoming`,
/// e.g. retransmissions) before dropping further ones instead. Never set
/// before M8 Step 2, so it sat at quinn's own default (10 MiB) — the
/// design arbitration's own instruction was explicit: measure before
/// picking a number, never guess blind (`PLAN.md` M8 Step 2's design
/// judgment table, row `incoming_buffer_size(_total)`).
///
/// **Measured**, not guessed: `measure_incoming_buffered_bytes_during_delayed_accept`
/// (this module's own test) drives a real loopback mTLS handshake through
/// a byte-counting relay while deliberately holding the server's
/// `Incoming` unaccepted for 4 seconds — long past quinn's own ~1 s
/// initial PTO, so the run captures actual client retransmissions, not
/// just the founding Initial (which predates the `Incoming` and is never
/// counted against this cap). A single well-behaved `qsh` client
/// retransmitting its own Initial on loss-recovery timers produced
/// **4,800 bytes** (4 × 1,200-byte Initial retransmissions, measured
/// 2026-09-02) of such follow-up traffic in that window on this machine
/// (Apple M1, macOS, loopback — re-run the test and update this number if
/// a platform/quinn-version change moves it materially). Set at 64 KiB:
/// **~13.6x** that measurement, while still a **160x reduction** from
/// quinn's 10 MiB default.
///
/// That ~13.6x is headroom against **starving a legitimate handshake**,
/// not an adversarial safety margin (`PLAN.md` M8 Step 2 verification
/// round, H1/H2 — the earlier wording conflated the two). What actually
/// bounds an *attacker's* per-`Incoming` buffering is the constant
/// itself, full stop, regardless of the measured number: quinn silently
/// drops any follow-up datagram once this cap is hit
/// (`INCOMING_BUFFER_SIZE_TOTAL`'s own doc comment cites the exact
/// vendored-source line). The measurement instead answers a different
/// question — does a *real* client's own retransmission traffic fit
/// comfortably under this cap while `admission::Gate::decide` runs? — and
/// the risk the arbitration flagged (a real handshake starved while the
/// gate "deliberates") cannot occur in practice anyway, since `decide` is
/// a synchronous, in-memory decision with no `.await` between quinn
/// handing us the `Incoming` and the accept loop calling
/// `retry`/`refuse`/`ignore`/`accept` on it — the 4 s delay this
/// measurement used is already several orders of magnitude more
/// conservative than production ever pays.
pub const INCOMING_BUFFER_SIZE: u64 = 64 * 1024;

/// Cap on `quinn::ServerConfig::incoming_buffer_size_total` — the sum of
/// [`INCOMING_BUFFER_SIZE`] across *every* unaccepted `Incoming` at once,
/// so no single attacker source pushing many simultaneous half-open
/// attempts (bounded individually by [`MAX_INCOMING`]) can multiply
/// [`INCOMING_BUFFER_SIZE`] into an unbounded aggregate.
///
/// **Set explicitly to 16 MiB** (`INCOMING_BUFFER_SIZE × 256`), not
/// derived from [`MAX_INCOMING`] (`PLAN.md` M8 Step 2 verification round,
/// P2-2). The original `const_min(INCOMING_BUFFER_SIZE * MAX_INCOMING,
/// 100 MiB)` — 64 KiB × 4096 = 256 MiB, clamped to quinn's own prior
/// default of 100 MiB — always evaluated to exactly that 100 MiB default,
/// which is a no-op: this field was never actually tightened by M8 Step
/// 2, only [`MAX_INCOMING`] and [`INCOMING_BUFFER_SIZE`] were. 100 MiB of
/// attacker-influenceable half-open buffer cannot sit next to
/// `docs/ROADMAP.md` M8 DoD 2's ≤30 MB idle-listener soak bound. 16 MiB —
/// 256× [`INCOMING_BUFFER_SIZE`] — keeps headroom for `MAX_INCOMING`
/// simultaneous attempts each using a meaningful fraction of their own
/// per-`Incoming` cap (a scenario `admission::Gate` draining the accept
/// loop makes unlikely in practice, so this rarely binds), while landing
/// on the same order of magnitude as the DoD 2 bound rather than 3⅓×
/// above it.
///
/// **What happens when this cap (or [`INCOMING_BUFFER_SIZE`]) is
/// exceeded**, read from the vendored `quinn-proto-0.11.16` source
/// (`~/.cargo/registry/src/*/quinn-proto-0.11.16/src/endpoint.rs:218-227`,
/// `handle_first_packet`'s `RouteDatagramTo::Incoming` arm): quinn checks
/// `incoming_buffer.total_bytes + datagram_len <= incoming_buffer_size`
/// **and** `all_incoming_buffers_total_bytes + datagram_len <=
/// incoming_buffer_size_total` before pushing a follow-up datagram onto
/// an already-created `Incoming`'s buffer; if either check fails the
/// datagram is silently dropped (not buffered, no error surfaced, no
/// `Incoming` torn down) and the function returns `None`. So exceeding
/// either cap costs quinn nothing beyond the datagram it just discarded —
/// the existing `Incoming` and everything already buffered for it are
/// unaffected, and a well-behaved client's retransmission simply gets
/// dropped and retried on the client's own loss-recovery timer (the same
/// outcome ordinary packet loss produces).
pub const INCOMING_BUFFER_SIZE_TOTAL: u64 = INCOMING_BUFFER_SIZE * 256;

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

/// Build the `quinn::ServerConfig` [`Listener::bind_inner`] hands to
/// `quinn::Endpoint::new` — TLS, the given `transport`, and the L0
/// admission bounds ([`MAX_INCOMING`]/[`INCOMING_BUFFER_SIZE`]/
/// [`INCOMING_BUFFER_SIZE_TOTAL`], `PLAN.md` M8 Step 2, `docs/adr/0009-
/// admission-defenses.md`) — never set before M8, so these sat at quinn's
/// own defaults (65536 / 10 MiB / 100 MiB, `quinn-proto` `config/mod.rs`).
/// This is L0 of the L0-L5 admission ordering: the cheap shed quinn
/// applies *before* deriving Initial keys or handing us an `Incoming` at
/// all — `admission::Gate` (qsh-core) is L2-L3, one layer above, and only
/// ever sees what gets past this.
///
/// **The single construction site** (`PLAN.md` M8 Step 2 verification
/// round, P2-1): before this existed, the test that pinned these three
/// bounds (`tests::server_config_sets_admission_bounds`) rebuilt its own
/// copy of this same sequence of calls and asserted against *that* copy —
/// tautological, since deleting the setters from `bind_inner` alone
/// (leaving the test's copy untouched) left the test green. `bind_inner`
/// and the test now both call this one function, so there is exactly one
/// place the three bounds can be set, and the test asserts on the actual
/// production construction path.
fn server_config(
    identity: &LocalIdentity,
    verifier: Arc<QshPeerVerifier>,
    transport: quinn::TransportConfig,
) -> Result<quinn::ServerConfig, SetupError> {
    let tls = server_tls_config(identity, verifier)?;
    let quic = QuicServerConfig::try_from(tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server_config.transport_config(Arc::new(transport));
    server_config
        .max_incoming(MAX_INCOMING)
        .incoming_buffer_size(INCOMING_BUFFER_SIZE)
        .incoming_buffer_size_total(INCOMING_BUFFER_SIZE_TOTAL);
    Ok(server_config)
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
    if is_connection_refused(&err) {
        return DialError::Refused;
    }
    DialError::Failed(err)
}

/// Whether a connection error is exactly quinn's own `CONNECTION_REFUSED`
/// (transport error code `0x2`, RFC 9000 §20.1) closing an
/// Initial-scoped connection — the signature `qsh_transport::Incoming::
/// refuse` produces on the peer's side (`PLAN.md` M8 Step 2). Deliberately
/// narrower than [`is_crypto_failure`]'s whole `0x100..=0x1ff` band: `0x2`
/// sits well outside that range, so the two checks never overlap.
fn is_connection_refused(err: &quinn::ConnectionError) -> bool {
    match err {
        quinn::ConnectionError::ConnectionClosed(cc) => {
            let raw: u64 = cc.error_code.into();
            raw == 0x2
        }
        _ => false,
    }
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
        let server_config = server_config(&identity, verifier.clone(), transport)?;
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

    /// Whether the sender of this attempt's Initial has already proved it
    /// can receive traffic at [`remote_address`](Self::remote_address) —
    /// i.e. this is the second Initial of a Retry round trip, carrying a
    /// token quinn has checked against this exact address (`PLAN.md` M8
    /// Step 2, `docs/adr/0009-admission-defenses.md`). `admission::Gate`'s
    /// address-validation decision reads this: `false` ⇒ unconditionally
    /// [`retry`](Self::retry) (never [`accept`](Self::accept) an
    /// unvalidated peer straight through — that is exactly the
    /// state-before-authorization gap M8's audit found), `true` ⇒ governed
    /// by the concurrency cap alone.
    pub fn remote_address_validated(&self) -> bool {
        self.incoming.remote_address_validated()
    }

    /// Whether responding with a Retry is legal for this attempt. Per
    /// quinn's own contract, `!remote_address_validated()` guarantees this
    /// is `true` (the converse does not hold) — so the gate's ordinary
    /// path never needs to check it before calling
    /// [`retry`](Self::retry); it exists for [`retry`]'s own `Err` case
    /// and for tests pinning that contract.
    pub fn may_retry(&self) -> bool {
        self.incoming.may_retry()
    }

    /// Respond with a Retry packet, forcing the peer to prove it owns
    /// `remote_address()` with a second, token-bearing Initial. Frees the
    /// slab slot and any datagrams already buffered for this attempt
    /// (quinn's `clean_up_incoming`) — a spoofed source that never returns
    /// leaves no state behind. Errors with `self` re-wrapped when
    /// [`may_retry`](Self::may_retry) is `false` (retrying an
    /// already-validated `Incoming`), mirroring quinn's own
    /// `RetryError::into_incoming` so a caller that mis-orders its checks
    /// gets its `Incoming` back rather than losing it.
    ///
    /// `Self` in the `Err` arm is the shape the task's own spec (`PLAN.md`
    /// M8 Step 2) and quinn's own `Incoming::retry`/`RetryError` API both
    /// call for — accepted deliberately over boxing it away: this is a
    /// cold, per-*attempt* error path (never hot-path, never per-byte),
    /// so the extra stack bytes on the rare `Err` cost nothing that
    /// matters.
    #[allow(clippy::result_large_err)]
    pub fn retry(self) -> Result<(), Self> {
        let Self { incoming, verifier } = self;
        match incoming.retry() {
            Ok(()) => Ok(()),
            Err(err) => Err(Self {
                incoming: err.into_incoming(),
                verifier,
            }),
        }
    }

    /// Refuse the attempt outright: quinn sends one Initial-scoped
    /// `CONNECTION_CLOSE(CONNECTION_REFUSED)` datagram — smaller than the
    /// Initial that triggered it, so no amplification — and frees the slab
    /// slot. For an already address-validated peer that lost a race for a
    /// capacity permit: a real client deserves a fast, distinguishable
    /// failure rather than silence (`admission::Gate`'s own doc).
    pub fn refuse(self) {
        self.incoming.refuse();
    }

    /// Drop the attempt with **no packet sent at all**. For an unvalidated,
    /// rate-limited source — never answer bytes to a spoofable address
    /// already judged abusive. **This is not the same as letting an
    /// `Incoming` fall out of scope**: quinn's own `Drop` impl treats a
    /// bare drop as an implicit [`refuse`](Self::refuse) (one packet sent).
    /// Every rejection path in this codebase must call `retry`/`refuse`/
    /// `ignore` explicitly — "silence" is a chosen method, never an
    /// oversight.
    pub fn ignore(self) {
        self.incoming.ignore();
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
    use crate::tls::StaticTrust;

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

    /// `PLAN.md` M8 Step 2 — pins [`CONNECTION_RECEIVE_WINDOW`] onto the
    /// `TransportConfig` every dial/listen builds, the same way (b) above
    /// pins `stream_receive_window`, **and** (verification round P3-2)
    /// that the applied value stays within `docs/ROADMAP.md` M8 DoD 2's
    /// "세션당 buffer ≤ 8 MB". A previously separate test,
    /// `connection_receive_window_never_exceeds_the_roadmap_dod_bound`,
    /// asserted only `min(CONNECTION_RECEIVE_WINDOW, 8 MiB) ≤ 8 MiB` —
    /// true by construction of the constant's own definition regardless
    /// of what `transport_config()` actually applies, so it could never
    /// fail no matter what value landed on the real `TransportConfig`
    /// (confirmed: it stayed green even when a mutation made
    /// `receive_window(VarInt::MAX)` land on the config instead). Folding
    /// the DoD bound into *this* test — which does inspect the applied
    /// value — makes it a real pin instead of a second, tautological one.
    #[test]
    fn transport_config_sets_connection_receive_window() {
        const DOD2_SESSION_BUFFER_CEILING: u64 = 8 * 1024 * 1024;
        let tc = transport_config();
        let debug = format!("{tc:?}");
        assert!(
            debug.contains(&format!("receive_window: {CONNECTION_RECEIVE_WINDOW}")),
            "expected receive_window: {CONNECTION_RECEIVE_WINDOW} in {debug:?}"
        );
        // `black_box` on both sides (same reason as
        // `tunnel_stream_receive_window_never_regresses_below_quinns_own_default`
        // above): both operands are compile-time constants, so without it
        // clippy's `assertions_on_constants` (correctly) flags this as a
        // constant-folded assertion — but the assertion still needs to
        // run so a future edit to either constant is caught, and the
        // `debug.contains(...)` assertion just above is what makes this
        // *not* the tautology `connection_receive_window_never_exceeds_
        // the_roadmap_dod_bound` was (P3-2): that test only ever compared
        // the constant against itself, never against what
        // `transport_config()` actually applied.
        assert!(
            std::hint::black_box(CONNECTION_RECEIVE_WINDOW)
                <= std::hint::black_box(DOD2_SESSION_BUFFER_CEILING),
            "CONNECTION_RECEIVE_WINDOW ({CONNECTION_RECEIVE_WINDOW}), the value actually \
             applied to TransportConfig above, must never exceed ROADMAP.md M8 DoD 2's \
             ≤8 MB per-session buffer bound ({DOD2_SESSION_BUFFER_CEILING})"
        );
    }

    /// `PLAN.md` M8 Step 2 — [`MAX_INCOMING`]/[`INCOMING_BUFFER_SIZE`]/
    /// [`INCOMING_BUFFER_SIZE_TOTAL`] are actually applied to the
    /// `ServerConfig` `Listener::bind` builds, not left at quinn's own
    /// defaults. `ServerConfig`'s `Debug` prints these three fields
    /// (`quinn-proto` `config/mod.rs`'s own `impl Debug`), so — like (b)
    /// above for `TransportConfig` — this is a debug-string assertion
    /// rather than a public getter (none exists).
    ///
    /// Calls the *production* `server_config(..)` (verification round
    /// P2-1) rather than rebuilding its own copy of the three setter
    /// calls: before this, the test's own copy meant deleting the setters
    /// from `bind_inner` alone left this test green — asserting against
    /// what the test itself had just constructed, not against what
    /// `Listener::bind` actually produces.
    #[test]
    fn server_config_sets_admission_bounds() {
        let identity = test_identity();
        let verifier = Arc::new(QshPeerVerifier::new(Arc::new(StaticTrust::empty())));
        let built = server_config(&identity, verifier, transport_config()).expect("server config");
        let debug = format!("{built:?}");
        assert!(
            debug.contains(&format!("max_incoming: {MAX_INCOMING}")),
            "expected max_incoming: {MAX_INCOMING} in {debug:?}"
        );
        assert!(
            debug.contains(&format!("incoming_buffer_size: {INCOMING_BUFFER_SIZE}")),
            "expected incoming_buffer_size: {INCOMING_BUFFER_SIZE} in {debug:?}"
        );
        assert!(
            debug.contains(&format!(
                "incoming_buffer_size_total: {INCOMING_BUFFER_SIZE_TOTAL}"
            )),
            "expected incoming_buffer_size_total: {INCOMING_BUFFER_SIZE_TOTAL} in {debug:?}"
        );

        // Mutation-testing round 4, N7: the debug-string assertions above
        // compare each const against a `format!` of *itself*, so a
        // mutation to the const's own decided value (e.g.
        // `INCOMING_BUFFER_SIZE_TOTAL` bumped from 16 MiB to 100 MiB)
        // sails through them unnoticed — both sides of the comparison
        // move together. Pin the three ADR-0009 decided numbers against
        // hardcoded literals instead. `black_box` on both sides (same
        // reason as `CONNECTION_RECEIVE_WINDOW`'s check above): without
        // it, clippy flags a comparison of two compile-time constants as
        // dead code. `INCOMING_BUFFER_SIZE_TOTAL` in particular must stay
        // well under ROADMAP.md M8 DoD 2's ≤30 MB idle-listener bound —
        // changing any of these three is a deliberate ADR-level decision,
        // never a drive-by.
        assert_eq!(
            std::hint::black_box(INCOMING_BUFFER_SIZE_TOTAL),
            std::hint::black_box(16 * 1024 * 1024),
            "ADR-0009's decided INCOMING_BUFFER_SIZE_TOTAL is 16 MiB"
        );
        assert_eq!(
            std::hint::black_box(INCOMING_BUFFER_SIZE),
            std::hint::black_box(64 * 1024),
            "ADR-0009's decided INCOMING_BUFFER_SIZE is 64 KiB"
        );
        assert_eq!(
            std::hint::black_box(MAX_INCOMING),
            std::hint::black_box(4096),
            "ADR-0009's decided MAX_INCOMING is 4096"
        );
    }

    fn test_identity() -> LocalIdentity {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let cert = params.self_signed(&key).unwrap();
        LocalIdentity {
            cert_chain: vec![CertificateDer::from(cert.der().to_vec())],
            key_pkcs8_der: key.serialize_der(),
        }
    }

    /// A trust store that pins nothing and trusts no CA — same role as
    /// `crates/qsh-transport/tests/loopback.rs`'s `make_identity`, but
    /// this module cannot import from an integration test file, so it
    /// gets its own tiny copy.
    fn test_pair() -> ((LocalIdentity, Fingerprint), (LocalIdentity, Fingerprint)) {
        fn one() -> (LocalIdentity, Fingerprint) {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            let cert = params.self_signed(&key).unwrap();
            let der = CertificateDer::from(cert.der().to_vec());
            let fp = Fingerprint::of_cert_der(&der).unwrap();
            (
                LocalIdentity {
                    cert_chain: vec![der],
                    key_pkcs8_der: key.serialize_der(),
                },
                fp,
            )
        }
        (one(), one())
    }

    /// `PLAN.md` M8 Step 2 design §8 — the first `Incoming` a real
    /// `Dialer` produces has never proven it owns its source address:
    /// `remote_address_validated()` is `false` and `may_retry()` is
    /// `true`. Pins the predicate `admission::Gate::decide` reads.
    #[tokio::test]
    async fn fresh_incoming_is_unvalidated() {
        let ((server_id, _), (_, client_fp)) = test_pair();
        let server_trust =
            StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_id,
            Arc::new(server_trust),
        )
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let ((client_id, _), _) = test_pair();
        let dial_task = tokio::spawn(async move {
            let dialer = Dialer::new(client_id, Arc::new(StaticTrust::empty()));
            // The client trusts nothing, so this dial never completes —
            // it exists only to put a real Initial on the wire. Dropped
            // (aborted) once the assertion below is done with it.
            let _ = dialer.dial(addr, "127.0.0.1").await;
        });
        let incoming = listener.accept().await.expect("one attempt");
        assert!(!incoming.remote_address_validated());
        assert!(incoming.may_retry());
        incoming.ignore();
        dial_task.abort();
    }

    /// `PLAN.md` M8 Step 2 design §8 — retrying the first `Incoming` of a
    /// dial forces a *second* Initial bearing quinn's Retry token; that
    /// second `Incoming` is address-validated, and completes a real mTLS
    /// handshake against qsh's own `Dialer`/`Listener`. Pins ① end to end:
    /// address validation costs exactly one extra `Incoming` and does not
    /// break qsh's own client.
    #[tokio::test]
    async fn retry_forces_a_validated_second_incoming() {
        let ((server_id, server_fp), (client_id, client_fp)) = test_pair();
        let server_trust =
            StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_id,
            Arc::new(server_trust),
        )
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let client_trust =
            StaticTrust::empty().with_pin(server_fp, Principal::Device("box".into()));
        let dialer = Dialer::new(client_id, Arc::new(client_trust));
        let dial_task = tokio::spawn(async move { dialer.dial(addr, "127.0.0.1").await });

        let first = listener.accept().await.expect("first attempt");
        assert!(!first.remote_address_validated());
        first
            .retry()
            .unwrap_or_else(|_| panic!("retry a fresh Incoming"));

        let second = listener.accept().await.expect("retried attempt");
        assert!(second.remote_address_validated());
        let conn = second.accept().await.expect("handshake completes");
        assert_eq!(conn.principal(), &Principal::Device("laptop".into()));

        let dialed = dial_task.await.unwrap().expect("dial completes");
        assert_eq!(
            dialed.connection.principal(),
            &Principal::Device("box".into())
        );
    }

    /// `PLAN.md` M8 Step 2 design §8 — `retry()` on an already
    /// address-validated `Incoming` errs (quinn's own contract) rather
    /// than silently retrying forever. Pins that `admission::Gate` can
    /// trust `retry()`'s `Err` to mean "this attempt is validated", not a
    /// transient failure to paper over with another retry.
    #[tokio::test]
    async fn retry_on_validated_incoming_errs() {
        let ((server_id, _), (client_id, client_fp)) = test_pair();
        let server_trust =
            StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_id,
            Arc::new(server_trust),
        )
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let dialer = Dialer::new(client_id, Arc::new(StaticTrust::empty()));
        let dial_task = tokio::spawn(async move {
            let _ = dialer.dial(addr, "127.0.0.1").await;
        });

        let first = listener.accept().await.expect("first attempt");
        first
            .retry()
            .unwrap_or_else(|_| panic!("retry a fresh Incoming"));
        let second = listener.accept().await.expect("retried attempt");
        assert!(second.remote_address_validated());
        assert!(
            !second.may_retry(),
            "an already-validated Incoming must not claim it may retry"
        );
        match second.retry() {
            Ok(()) => panic!("retry() on a validated Incoming must err"),
            Err(returned) => {
                // The `Incoming` comes back usable — clean it up rather
                // than leaking it.
                returned.ignore();
            }
        }
        dial_task.abort();
    }

    /// `PLAN.md` M8 Step 2, design §3's risk #3 ("`incoming_buffer_size`
    /// tightened blind"): measures how many bytes quinn actually buffers
    /// for one unaccepted `Incoming` while a real client's dial sits
    /// waiting, so [`INCOMING_BUFFER_SIZE`] is set from a number, not a
    /// guess.
    ///
    /// **Method.** A tiny UDP relay (plain `tokio::net::UdpSocket` — this
    /// crate cannot depend on `qsh-testkit`'s `ChaosProxy`, arch matrix)
    /// sits between a real `Dialer` and a real `Listener`, tallying every
    /// byte it forwards client→server. The server calls `listener.accept()`
    /// once (consuming the founding Initial — the one that creates the
    /// `Incoming`, never counted against `incoming_buffer_size` itself)
    /// and then *deliberately does not* call `.accept()`/`retry()`/
    /// `refuse()`/`ignore()` on the `Incoming` it gets back for 4 seconds
    /// — comfortably past quinn's own ~1 s initial PTO, so the window
    /// captures real client retransmissions, not just the founding
    /// packet. The relay's forwarded-byte counter is sampled right after
    /// `accept()` returns (baseline) and again after the 4 s delay; the
    /// difference is every byte quinn's `incoming_buffer_size` accounting
    /// had to hold for this one attempt.
    ///
    /// **This is a conservative upper bound, not an exact reading**: quinn
    /// does not expose the buffered-byte counter itself (`quinn-proto`
    /// `endpoint.rs`'s `IncomingBuffer::total_bytes` is private), so this
    /// measures wire bytes reaching the server instead — every one of
    /// which is a datagram quinn's accounting would have added to that
    /// counter (nothing else is multiplexed onto this relay), so the two
    /// numbers coincide unless quinn itself dropped a datagram for being
    /// malformed or duplicate, which would only make quinn's true number
    /// *smaller* than what this test reports.
    #[tokio::test(flavor = "multi_thread")]
    async fn measure_incoming_buffered_bytes_during_delayed_accept() {
        let ((server_id, _), (client_id, client_fp)) = test_pair();
        let server_trust =
            StaticTrust::empty().with_pin(client_fp, Principal::Device("laptop".into()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_id,
            Arc::new(server_trust),
        )
        .unwrap();
        let real_server_addr = listener.local_addr().unwrap();

        // The relay: client dials `relay_client_side`'s address; every
        // datagram it receives there is forwarded to `real_server_addr`
        // via `relay_server_side`, and vice versa for replies.
        let relay_client_side = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_client_side.local_addr().unwrap();
        let relay_server_side = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarded_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let relay_task = {
            let forwarded_bytes = forwarded_bytes.clone();
            tokio::spawn(async move {
                let mut from_client = [0u8; 2048];
                let mut from_server = [0u8; 2048];
                let mut client_addr: Option<SocketAddr> = None;
                loop {
                    tokio::select! {
                        r = relay_client_side.recv_from(&mut from_client) => {
                            let Ok((n, from)) = r else { break };
                            client_addr = Some(from);
                            forwarded_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::SeqCst);
                            let _ = relay_server_side.send_to(&from_client[..n], real_server_addr).await;
                        }
                        r = relay_server_side.recv_from(&mut from_server) => {
                            let Ok((n, _)) = r else { break };
                            if let Some(to) = client_addr {
                                let _ = relay_client_side.send_to(&from_server[..n], to).await;
                            }
                        }
                    }
                }
            })
        };

        let dialer = Dialer::new(client_id, Arc::new(StaticTrust::empty()))
            // Long enough to outlast this test's own 4 s delay — the
            // dial is expected to keep retrying, not time out early.
            .with_timeout(Duration::from_secs(20));
        let dial_task = tokio::spawn(async move {
            let _ = dialer.dial(relay_addr, "127.0.0.1").await;
        });

        let incoming = listener.accept().await.expect("founding Initial arrives");
        let baseline = forwarded_bytes.load(std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(4)).await;
        let after = forwarded_bytes.load(std::sync::atomic::Ordering::SeqCst);
        let measured = after - baseline;

        eprintln!(
            "measure_incoming_buffered_bytes_during_delayed_accept: {measured} bytes buffered \
             for one Incoming over a 4s deliberate accept delay (INCOMING_BUFFER_SIZE = \
             {INCOMING_BUFFER_SIZE}, {}x measured)",
            INCOMING_BUFFER_SIZE.checked_div(measured).unwrap_or(0)
        );
        // `PLAN.md` M8 Step 2 verification round, H1/H2: this used to
        // assert `measured * 8 <= INCOMING_BUFFER_SIZE` — an ≥8x headroom
        // check against the *specific* measured number, which is real-time
        // dependent (PTO retransmission count in a fixed 4 s window) and
        // was measured with only 1.7x headroom to that exact threshold on
        // this machine, not the 13x the constant's doc comment otherwise
        // implies (4,800 measured vs 8,192 = INCOMING_BUFFER_SIZE / 8).
        // What this setting actually defends is narrower and doesn't need
        // that fragile a number: a legitimate, well-behaved handshake must
        // never be starved of buffering room while `admission::Gate`
        // "deliberates" (the arbitration's own framing) — i.e. some
        // non-zero amount of real follow-up traffic got through and stayed
        // under the cap. `measured` bounded above by `INCOMING_BUFFER_SIZE`
        // is what that actually requires; a specific multiple of a
        // wall-clock-dependent measurement is not.
        assert!(
            measured > 0 && measured <= INCOMING_BUFFER_SIZE,
            "expected 0 < measured <= INCOMING_BUFFER_SIZE ({INCOMING_BUFFER_SIZE}) — a \
             legitimate handshake's real follow-up traffic ({measured} bytes over a 4s delay) \
             must never be starved by this cap"
        );

        incoming.ignore();
        dial_task.abort();
        relay_task.abort();
    }
}
