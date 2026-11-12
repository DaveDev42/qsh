//! Endpoint construction (`docs/design/protocol.md` §2, §4), backend-neutral;
//! the QUIC work itself is in `quinn_backend::endpoint`:
//! ALPN `qsh/1`, TLS 1.3 only, keep-alive 15 s / idle 45 s, **no 0-RTT**,
//! **no session tickets** (long-lived connections; a resumed handshake must
//! never skip client-certificate verification), mutual authentication via
//! [`QshPeerVerifier`] on both sides.
//!
//! [`Dialer`] and [`Listener`] are the only two ways to obtain a
//! [`Connection`]; a `Connection` always carries the peer's verified
//! [`Principal`], computed from the certificate chain — never from wire data.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::error::{ConnectError, ConnectionError, DatagramError, ExportError};
use crate::identity::{CertificateDer, Fingerprint, Principal};
use crate::iroh_backend::{IrohConn, IrohEndpoint};
use crate::mux::{MuxConn, TransportCaps, TransportKind};
use crate::peer_addr::PeerAddr;
pub use crate::quinn_backend::config::transport_config_debug;
use crate::quinn_backend::conn::{QuicConn, peer_chain};
use crate::quinn_backend::endpoint::{QuicEndpoint, QuicIncoming, TransportProfile, VirtualSocket};
pub use crate::quinn_backend::socket::bind_tuned_udp_socket;
use crate::stream::{RecvStream, SendStream};
use crate::tls::{
    AuthPath, Observation, PeerRole, QshPeerVerifier, RejectReason, TrustEvaluator, VerifiedPeer,
    reverify_chain,
};

/// How long a command waits for its endpoint to drain after it closed its
/// connection when a hole-punching race left closed candidates on it
/// ([`Endpoint::wait_idle_for`]). A direct dial keeps the full
/// [`Endpoint::wait_idle`].
pub const CLOSE_DRAIN_CAP: Duration = Duration::from_millis(200);

/// Application-level keep-alive interval (`protocol.md` §2). The default
/// of [`TransportTuning`]; `[transport].keep_alive_ms` in `config.toml`
/// replaces it (`docs/adr/0021-transport-liveness-knobs.md` decision 1).
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Max idle timeout before the connection is considered dead (`protocol.md` §2).
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Default bound on how long a dial may take before it is reported as
/// `CONNECTION_FAILED` (much shorter than the idle timeout — a dial that
/// gets no response should fail fast).
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Process-wide replacement for [`DEFAULT_DIAL_TIMEOUT`] in milliseconds
/// (`0` = none set). The ssh-form client sets it once from `-o
/// ConnectTimeout` (ADR-0051 decision 7), so every [`Dialer`] the process
/// builds afterwards uses it without each call site carrying the value.
static DIAL_TIMEOUT_OVERRIDE_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Replace the dial timeout every later [`Dialer::new`] starts with.
/// Meant to be called once, at process start, by a client frontend.
pub fn set_default_dial_timeout(timeout: Duration) {
    let ms = u64::try_from(timeout.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    DIAL_TIMEOUT_OVERRIDE_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// The dial timeout a [`Dialer`] built now starts with: [`DEFAULT_DIAL_TIMEOUT`],
/// or the `-o ConnectTimeout` override ([`set_default_dial_timeout`]). The hole
/// punching route bounds its race with a direct dial by this value.
pub fn default_dial_timeout() -> Duration {
    match DIAL_TIMEOUT_OVERRIDE_MS.load(std::sync::atomic::Ordering::Relaxed) {
        0 => DEFAULT_DIAL_TIMEOUT,
        ms => Duration::from_millis(ms),
    }
}

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
/// tunnel ~2-4 MiB, as M4 plan Step 2 (2473c88) and `protocol.md` §12
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
/// (`crates/qsh-testkit/tests/it/tunnel_echo_under_load.rs` and
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
///
/// **Not the only defense against PTY starvation any more.** A tunnel
/// stream whose local consumer never reads holds up to this much of
/// [`CONNECTION_RECEIVE_WINDOW`], so four of them used to hold all of it
/// and stop the same connection's PTY output
/// (`crates/qsh-testkit/tests/it/tunnel_stalled_streams.rs`). The ratio of the
/// two windows now sets a limit instead of being the defense:
/// `qsh_core::tunnel::stall` stops the oldest stalled tunnel streams once
/// more than `CONNECTION_RECEIVE_WINDOW / TUNNEL_STREAM_RECEIVE_WINDOW - 1`
/// are stalled on one connection (ADR-0037). Changing either constant moves
/// that limit with it.
pub const TUNNEL_STREAM_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;

/// Connection-wide flow-control ceiling (`quinn::TransportConfig::
/// receive_window`) — the total unacked data quinn will let a peer have
/// buffered across *every* stream on one connection combined. Never set
/// before M8 Step 2 (M8 plan Step 2 (52639fc), ROADMAP.md's admission audit
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
///
/// The window relation alone does not keep a starved connection's PTY
/// flowing: unread bytes on stalled tunnel streams count against this
/// window too, and [`TUNNEL_STREAM_RECEIVE_WINDOW`]'s doc names the
/// `qsh-core` stall limit (ADR-0037) that now does.
pub const CONNECTION_RECEIVE_WINDOW: u64 = const_min(
    TUNNEL_STREAM_RECEIVE_WINDOW as u64 * MAX_CONCURRENT_BIDI_STREAMS as u64,
    8 * 1024 * 1024,
);

const fn const_min(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

/// `quinn::TransportConfig::datagram_receive_buffer_size`: how many bytes of
/// received QUIC DATAGRAM payload may sit unread before quinn drops the
/// oldest. Also the `max_datagram_frame_size` transport parameter we
/// advertise, so it caps the largest datagram a peer may send us.
///
/// Datagrams are an optional carrier for screen diffs and input copies
/// (ADR-0052 decision 7), each at most one path MTU (about 1.2 KB), and a
/// stale diff is worth less than the newest one.
///
/// A jump hop (ADR-0056) puts a whole inner QUIC connection on the datagram
/// carrier, and an inner sender emits bursts of tens of packets at once. At
/// 64 KiB (about fifty MTU-sized datagrams) each burst overflowed the buffer
/// and quinn evicted the oldest, which the inner connection read as loss: a
/// one-hop bulk upload resent about 25% of its packets and moved 0.42 of the
/// direct throughput. 512 KiB absorbs the bursts (about 3% resent, 0.7 of
/// direct). It is a ceiling, not an allocation: a reader that stalls costs at
/// most this much per connection, well under quinn's default of 1.25 MB (M8
/// DoD 2: session buffer <= 8 MB).
pub const DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 512 * 1024;

/// `quinn::TransportConfig::datagram_send_buffer_size`: bytes of outgoing
/// datagram payload queued before quinn drops the oldest to make room. Same
/// reasoning as [`DATAGRAM_RECEIVE_BUFFER_SIZE`], including the jump bursts;
/// for a sender, dropping the oldest is the right policy because the next diff
/// supersedes it.
pub const DATAGRAM_SEND_BUFFER_SIZE: usize = 512 * 1024;

/// QUIC application close code sent when the peer's principal cannot be
/// re-derived after the handshake (should be unreachable — the verifier
/// already ran — but fail closed).
pub const CLOSE_CODE_UNVERIFIED_PEER: u32 = 0x1001;
/// QUIC application close code for a protocol violation on the control
/// stream (bad Hello, oversize frame, unknown stream header…).
pub const CLOSE_CODE_PROTOCOL: u32 = 0x1002;
/// QUIC application close code for a connection closed because the local
/// trust store no longer vouches for it: the peer was un-pinned, its CA was
/// removed, or the role grants it was admitted with shrank (ADR-0031
/// decision 7). The value sits in the band `docs/design/protocol.md` §16.3
/// leaves outside the freeze; a peer never branches on it (§7).
pub const CLOSE_CODE_TRUST_WITHDRAWN: u32 = 0x1005;
/// The fixed reason phrase sent with [`CLOSE_CODE_TRUST_WITHDRAWN`]. It names
/// no principal and no cause; the audit record carries the coarse category.
pub const TRUST_WITHDRAWN_REASON: &[u8] = b"trust withdrawn";

/// Application close code of a connection that finished its handshake in a
/// hole-punching attempt but lost the race to another one
/// (`docs/adr/0054-m24-hole-punching.md` decision 15). Internal until the
/// `punch.v1` step documents it in `docs/design/protocol.md` §16.3.
pub const CLOSE_CODE_NOT_ADOPTED: u32 = 0x1006;

/// The close reason that goes with [`CLOSE_CODE_NOT_ADOPTED`].
pub const NOT_ADOPTED_REASON: &[u8] = b"not adopted";

/// The local device's cert chain and private key (PKCS#8 DER).
#[derive(Clone)]
pub struct LocalIdentity {
    /// Leaf first. Self-signed device certs are a chain of one.
    pub cert_chain: Vec<CertificateDer>,
    /// PKCS#8 DER private key. `Zeroizing` covers the resident copy this
    /// struct owns; `key()` below draws one further copy out of it via
    /// `.to_vec()` (not `.clone()` — the result is a plain `Vec<u8>`,
    /// already outside `Zeroizing` from the moment it exists) and hands
    /// that `Vec` to `PrivatePkcs8KeyDer::from`, which takes ownership of
    /// it rather than copying it again. That one non-`Zeroizing` copy is
    /// *not* zeroized on drop once it belongs to rustls/quinn —
    /// `rustls-pki-types` 1.15.1 implements `zeroize::Zeroize` on
    /// `PrivatePkcs8KeyDer` for callers who opt in, but has no `Drop` impl
    /// that calls it, so the copy handed to rustls/quinn is out of this
    /// type's control.
    pub key_pkcs8_der: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never Debug-print key material.
        f.debug_struct("LocalIdentity")
            .field("cert_chain_len", &self.cert_chain.len())
            .finish_non_exhaustive()
    }
}

/// Errors building endpoints.
#[derive(Debug, Error)]
pub enum SetupError {
    /// rustls rejected the configuration (bad key/cert…).
    #[error("tls config: {0}")]
    Tls(#[from] rustls::Error),
    /// The QUIC stack rejected the rustls config (e.g. no usable initial
    /// cipher suite); the stack's own description.
    #[error("quic crypto config: {0}")]
    Quic(String),
    /// Socket bind failed.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The address we tried to bind.
        addr: SocketAddr,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// The iroh endpoint could not be set up (the identity is not an
    /// Ed25519 key, an address or URL did not parse, the bind failed).
    #[error("iroh endpoint: {0}")]
    Iroh(String),
}

/// Errors from a dial attempt, already classified for the ops layer.
#[derive(Debug, Error)]
pub enum DialError {
    /// Endpoint construction failed.
    #[error(transparent)]
    Setup(#[from] SetupError),
    /// The address/server name was unusable.
    #[error("connect: {0}")]
    Connect(#[from] ConnectError),
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
    /// (M8 plan Step 2 (52639fc), `docs/adr/0009-admission-defenses.md`) —
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
    Failed(#[from] ConnectionError),
}

/// Errors accepting an inbound connection.
#[derive(Debug, Error)]
pub enum AcceptError {
    /// The handshake failed (typically: client cert rejected by the
    /// verifier, or no client cert at all).
    #[error("handshake failed: {0}")]
    Handshake(#[from] ConnectionError),
    /// Handshake completed but the peer principal could not be derived —
    /// the connection was closed. Should not happen (the verifier ran).
    #[error("peer principal could not be derived ({0:?}); connection closed")]
    Unverified(RejectReason),
    /// The endpoint is shutting down.
    #[error("endpoint closed")]
    Closed,
}

/// The one connection-level knob an operator may turn: how often an idle
/// connection sends a keep-alive (`docs/adr/0021-transport-liveness-knobs.md`
/// decision 1). [`MAX_IDLE_TIMEOUT`] stays fixed (decision 2). This crate
/// knows nothing about `config.toml`; `qsh-core` validates the configured
/// value and passes it in. `Default` is [`KEEP_ALIVE_INTERVAL`], so a caller
/// that never names a tuning keeps today's behavior byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTuning {
    /// Keep-alive interval applied to every connection built from this
    /// tuning.
    pub keep_alive: Duration,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            keep_alive: KEEP_ALIVE_INTERVAL,
        }
    }
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
/// picking a number, never guess blind (M8 plan Step 2 (52639fc)'s design
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
/// not an adversarial safety margin (M8 plan Step 2 (52639fc) verification
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
/// derived from [`MAX_INCOMING`] (M8 plan Step 2 (52639fc) verification round,
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
/// (`~/.cargo/registry/src/*/quinn-proto-0.11.16/src/endpoint.rs`,
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

/// A verified QUIC connection: quinn's connection plus the peer's
/// certificate-derived principal.
#[derive(Clone, Debug)]
pub struct Connection {
    inner: ConnBackend,
    /// Process-global id minted when the connection is wrapped
    /// ([`Connection::stable_id`]).
    id: usize,
    principal: Principal,
    auth_path: AuthPath,
    peer_fingerprint: Option<Fingerprint>,
    /// The peer's certificate chain (DER, leaf first) from the handshake,
    /// kept so [`Connection::reverify`] can re-run the verifier later
    /// (ADR-0031 decision 4). A few KB per connection; shared by clones.
    peer_chain: Arc<[CertificateDer]>,
    /// Which side of the handshake the peer was, for the chain verifier's
    /// key-usage check.
    peer_role: PeerRole,
    /// The code of the close **this side** performed first, if it did. The
    /// transport reports a local close as plain "locally closed" with no
    /// code, so this record is the only way
    /// [`Connection::closed_by_trust_withdrawal`] can tell this side's own
    /// withdrawal from any other local close. Shared by clones.
    local_close: Arc<Mutex<LocalClose>>,
}

/// What this side's own [`Connection::close`] calls tell about how the
/// connection ended (ADR-0031 decision 7's trust-withdrawal classification).
///
/// The transport cannot answer "who closed first" afterwards: on any local
/// `close` it overwrites the connection's error with "locally closed", even
/// when the peer's close (or a timeout) had already ended the connection and
/// the local call changed nothing on the wire. So the answer has to be
/// sampled **before** the first local close, under the lock that serializes
/// local closes, and kept:
///
/// - the connection had no close reason: this side's close is the one that
///   ended it, and its `code` is recorded;
/// - it already had one (the peer's close, an idle timeout): that `prior`
///   reason is the end of the connection, and the later local close, which
///   the transport turns into "locally closed", must not hide it. A peer's
///   `0x1005` therefore stays a withdrawal even after this side's own
///   shutdown close runs over it.
///
/// The one gap left is the transport's own: a peer close processed between
/// the sample and the close call is invisible, and the connection is then
/// recorded as closed by this side. That reading is the right one for the
/// consumer, since this side did decide to close it, and the transport
/// itself reports "locally closed" in that case too.
#[derive(Debug, Default)]
struct LocalClose {
    /// The code of the close this side performed on an open connection.
    code: Option<u32>,
    /// The reason the connection already had when this side first closed it.
    prior: Option<ConnectionError>,
}

impl LocalClose {
    /// Account for one `close(code)` call; `before` is the connection's
    /// close reason read just ahead of it. Only the first call counts.
    fn record(&mut self, code: u32, before: Option<ConnectionError>) {
        if self.code.is_some() || self.prior.is_some() {
            return;
        }
        match before {
            None => self.code = Some(code),
            Some(reason) => self.prior = Some(reason),
        }
    }

    /// Whether the connection ended with [`CLOSE_CODE_TRUST_WITHDRAWN`],
    /// judged from what was recorded, or from `live` (the transport's
    /// current reason) when no local close happened.
    fn is_trust_withdrawal(&self, live: Option<ConnectionError>) -> bool {
        if let Some(code) = self.code {
            return code == CLOSE_CODE_TRUST_WITHDRAWN;
        }
        match self.prior.clone().or(live) {
            Some(ConnectionError::ApplicationClosed(close)) => {
                close.error_code.into_inner() == u64::from(CLOSE_CODE_TRUST_WITHDRAWN)
            }
            _ => false,
        }
    }
}

/// The transports a [`Connection`] can run over. Every method that touches
/// the wire goes through the [`MuxConn`] contract, so a backend that lacks
/// one fails to compile.
#[derive(Clone, Debug)]
enum ConnBackend {
    Quic(QuicConn),
    Iroh(IrohConn),
}

#[cfg(test)]
impl Connection {
    /// The QUIC backend's connection, for this crate's own backend unit
    /// tests (see `quinn_backend::conn`'s `quic_for_test`). Compiled only
    /// under `cfg(test)`.
    pub(crate) fn quic_conn(&self) -> &QuicConn {
        match &self.inner {
            ConnBackend::Quic(c) => c,
            ConnBackend::Iroh(_) => panic!("quic_conn on an iroh connection"),
        }
    }
}

impl Connection {
    /// Wrap a handshaken QUIC connection whose peer the verifier accepted.
    fn from_quic(
        conn: QuicConn,
        chain: &[CertificateDer],
        role: PeerRole,
        verified: VerifiedPeer,
    ) -> Self {
        Self {
            peer_fingerprint: chain.first().and_then(|c| Fingerprint::of_cert_der(c).ok()),
            peer_chain: chain.into(),
            peer_role: role,
            local_close: Arc::new(Mutex::new(LocalClose::default())),
            inner: ConnBackend::Quic(conn),
            id: next_connection_id(),
            principal: verified.principal,
            auth_path: verified.auth_path,
        }
    }

    /// Wrap an iroh connection whose peer key the trust store accepted.
    /// There is no certificate chain; the peer is its key.
    pub(crate) fn from_iroh(conn: IrohConn, role: PeerRole, verified: VerifiedPeer) -> Self {
        Self {
            peer_fingerprint: Some(conn.peer()),
            peer_chain: Arc::from(Vec::new()),
            peer_role: role,
            local_close: Arc::new(Mutex::new(LocalClose::default())),
            inner: ConnBackend::Iroh(conn),
            id: next_connection_id(),
            principal: verified.principal,
            auth_path: verified.auth_path,
        }
    }

    /// Which transport the connection runs over.
    pub fn transport_kind(&self) -> TransportKind {
        match &self.inner {
            ConnBackend::Quic(c) => c.kind(),
            ConnBackend::Iroh(c) => c.kind(),
        }
    }

    /// What the connection's transport can do.
    pub fn caps(&self) -> TransportCaps {
        match &self.inner {
            ConnBackend::Quic(c) => c.caps(),
            ConnBackend::Iroh(c) => c.caps(),
        }
    }

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

    /// Re-run the handshake's verification over the peer chain kept from
    /// the handshake, against `evaluator`'s current view of the trust
    /// store (ADR-0031 decision 4).
    ///
    /// This is the same `verify_peer` core the handshake used, so validity
    /// window, pin lookup, CA chain and the pairing fallback are judged by
    /// the handshake's own rules. A connection whose kept chain is empty or
    /// whose leaf no longer parses cannot be judged and is rejected
    /// (decision 5: undecidable means untrusted).
    pub fn reverify(&self, evaluator: &dyn TrustEvaluator) -> Result<VerifiedPeer, RejectReason> {
        // An iroh peer has no certificate chain, only a key: re-judge it by
        // pin (and the pairing window), as the handshake did.
        if let ConnBackend::Iroh(c) = &self.inner {
            return crate::iroh_backend::verify_iroh_peer(evaluator, &c.peer());
        }
        reverify_chain(evaluator, &self.peer_chain, self.peer_role)
    }

    /// Close because the trust store no longer vouches for this connection:
    /// [`close`](Self::close) with [`CLOSE_CODE_TRUST_WITHDRAWN`] and the
    /// fixed [`TRUST_WITHDRAWN_REASON`] (ADR-0031 decision 7). Idempotent.
    pub fn close_trust_withdrawn(&self) {
        self.close(CLOSE_CODE_TRUST_WITHDRAWN, TRUST_WITHDRAWN_REASON);
    }

    /// Whether this connection ended with [`CLOSE_CODE_TRUST_WITHDRAWN`],
    /// whether this side sent it
    /// ([`close_trust_withdrawn`](Self::close_trust_withdrawn)) or the peer
    /// did. `false` while the
    /// connection is open and for every other close.
    pub fn closed_by_trust_withdrawal(&self) -> bool {
        let local = self.local_close.lock().unwrap_or_else(|e| e.into_inner());
        local.is_trust_withdrawal(self.close_reason())
    }

    /// A copy of this connection that has forgotten the peer chain kept from
    /// the handshake, standing in for a connection the trust watch cannot
    /// judge ([`Connection::reverify`] rejects it, ADR-0031 decision 5).
    /// The copy shares the live transport connection with `self`.
    ///
    /// A test seam, compiled only for this crate's tests and under the
    /// `test-support` feature: no production path loses the chain. It is not
    /// in a test module because the connection-watch tests sit in another
    /// crate and cannot reach the private field.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_peer_chain_dropped(&self) -> Connection {
        let mut copy = self.clone();
        copy.peer_chain = Arc::from(Vec::new());
        copy
    }

    /// Peer socket address (may change over the connection's life via
    /// migration; this is the current one).
    pub fn remote_address(&self) -> PeerAddr {
        match &self.inner {
            ConnBackend::Quic(c) => c.remote_address(),
            ConnBackend::Iroh(c) => c.remote_address(),
        }
    }

    /// Id for logs, audit and the per-connection registries (quota, lease,
    /// stall ledger, traffic hooks).
    ///
    /// Process-global and monotonic, minted when the connection is wrapped
    /// (`docs/adr/0043-no-tcp-fallback.md` decision 3), so two connections
    /// of one process never share an id even when they come from different
    /// listeners or transports and an id is never reused after its
    /// connection closes. (quinn's own `stable_id` is a per-endpoint slab
    /// index: it repeats across endpoints and is recycled.) Only meaningful
    /// as an opaque key; two reads of the same connection (or a clone) agree.
    pub fn stable_id(&self) -> usize {
        self.id
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        match &self.inner {
            ConnBackend::Quic(c) => {
                let (send, recv) = c.open_bi().await?;
                Ok((SendStream::from_quic(send), RecvStream::from_quic(recv)))
            }
            ConnBackend::Iroh(c) => {
                let (send, recv) = c.open_bi().await?;
                Ok((SendStream::from_iroh(send), RecvStream::from_iroh(recv)))
            }
        }
    }

    /// Accept the next peer-initiated bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        match &self.inner {
            ConnBackend::Quic(c) => {
                let (send, recv) = c.accept_bi().await?;
                Ok((SendStream::from_quic(send), RecvStream::from_quic(recv)))
            }
            ConnBackend::Iroh(c) => {
                let (send, recv) = c.accept_bi().await?;
                Ok((SendStream::from_iroh(send), RecvStream::from_iroh(recv)))
            }
        }
    }

    /// The largest payload [`send_datagram`](Self::send_datagram) accepts at
    /// this moment (path MTU minus overhead, bounded by the peer's advertised
    /// limit). `None` when datagrams cannot be used on this connection. The
    /// value can change when path MTU discovery or a migration moves the MTU,
    /// so read it per send, not once.
    pub fn max_datagram_size(&self) -> Option<usize> {
        match &self.inner {
            ConnBackend::Quic(c) => c.max_datagram_size(),
            ConnBackend::Iroh(c) => c.max_datagram_size(),
        }
    }

    /// Send one unreliable, unordered datagram. Never waits: when the send
    /// buffer ([`DATAGRAM_SEND_BUFFER_SIZE`]) is full the oldest queued
    /// datagram is dropped. Delivery is not confirmed. Datagrams are an
    /// optional carrier (ADR-0052 decision 7): a message sent this way also
    /// has a stream path, so a caller falls back to the stream on
    /// [`DatagramError::UnsupportedByPeer`] or [`DatagramError::TooLarge`].
    pub fn send_datagram(&self, data: Bytes) -> Result<(), DatagramError> {
        match &self.inner {
            ConnBackend::Quic(c) => c.send_datagram(data),
            ConnBackend::Iroh(c) => c.send_datagram(data),
        }
    }

    /// Receive the next datagram. Cancel-safe. Resolves with the connection
    /// error once the connection closes.
    pub async fn read_datagram(&self) -> Result<Bytes, ConnectionError> {
        match &self.inner {
            ConnBackend::Quic(c) => c.read_datagram().await,
            ConnBackend::Iroh(c) => c.read_datagram().await,
        }
    }

    /// Close with an application error code and reason. Idempotent.
    ///
    /// Local closes go through one lock, and the first one records what the
    /// connection looked like just before it (`LocalClose`), because the
    /// transport overwrites the close reason of an already-closed connection
    /// with "locally closed".
    pub fn close(&self, code: u32, reason: &[u8]) {
        let mut local = self.local_close.lock().unwrap_or_else(|e| e.into_inner());
        local.record(code, self.close_reason());
        match &self.inner {
            ConnBackend::Quic(c) => c.close(code, reason),
            ConnBackend::Iroh(c) => c.close(code, reason),
        }
    }

    /// Resolves when the connection is closed (by either side).
    pub async fn closed(&self) -> ConnectionError {
        match &self.inner {
            ConnBackend::Quic(c) => c.closed().await,
            ConnBackend::Iroh(c) => c.closed().await,
        }
    }

    /// If the connection is already closed, why.
    pub fn close_reason(&self) -> Option<ConnectionError> {
        match &self.inner {
            ConnBackend::Quic(c) => c.close_reason(),
            ConnBackend::Iroh(c) => c.close_reason(),
        }
    }

    /// Convenience for [`ConnStats::rx_frames`].
    pub fn rx_frames(&self) -> u64 {
        self.stats().rx_frames
    }

    /// The connection's current latency estimate (the QUIC path RTT).
    pub fn rtt(&self) -> Duration {
        self.stats().rtt
    }

    /// A snapshot of the connection's transport counters. See [`ConnStats`]
    /// for what each field proves and what it does not.
    pub fn stats(&self) -> ConnStats {
        match &self.inner {
            ConnBackend::Quic(c) => c.stats(),
            ConnBackend::Iroh(c) => c.stats(),
        }
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
    ) -> Result<(), ExportError> {
        match &self.inner {
            ConnBackend::Quic(c) => c.export_keying_material(output, label, context),
            ConnBackend::Iroh(c) => c.export_keying_material(output, label, context),
        }
    }
}

/// Source of [`Connection::stable_id`].
fn next_connection_id() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// How long [`Endpoint::wait_idle`] waits on an endpoint that runs over a
/// pipe inside another connection.
pub const NESTED_IDLE_CAP: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
enum EndpointBackend {
    Quic(QuicEndpoint),
    /// An iroh endpoint (ADR-0061): dialed by key, carried over a relay or a
    /// direct path.
    Iroh(IrohEndpoint),
}

/// The local socket a connection runs over: what a [`Dialed`] hands back and
/// [`Listener::endpoint`] exposes.
///
/// A cheap `Clone` handle. It exposes only what callers do with an endpoint
/// (read its address, wait for its connections to drain, move it to a fresh
/// local path); the transport behind it is a closed enum, so another backend
/// is one more variant (`docs/adr/0043-no-tcp-fallback.md` decision 3).
#[derive(Clone, Debug)]
pub struct Endpoint {
    inner: EndpointBackend,
    rebind: Rebind,
}

/// What [`Endpoint::rebind_ephemeral`] does for this endpoint.
#[derive(Clone, Debug, Default)]
enum Rebind {
    /// Bind a fresh socket under the endpoint (a UDP endpoint).
    #[default]
    Own,
    /// The endpoint runs over a pipe inside another connection (a jump
    /// hop, ADR-0056 decision 16): its path is the outer endpoint's, so
    /// moving that one is the whole migration. The inner connection is not
    /// touched.
    Via(Arc<Endpoint>),
    /// A pipe endpoint with no outer one to move.
    Unsupported,
}

impl Endpoint {
    pub(crate) fn from_quic(endpoint: QuicEndpoint) -> Self {
        Self {
            inner: EndpointBackend::Quic(endpoint),
            rebind: Rebind::Own,
        }
    }

    /// The endpoint of an iroh connection, kept for the connection's life
    /// (ADR-0061). It has no single local address and cannot be rebound by
    /// qsh: iroh moves its own paths.
    pub fn from_iroh(endpoint: IrohEndpoint) -> Self {
        Self {
            inner: EndpointBackend::Iroh(endpoint),
            rebind: Rebind::Unsupported,
        }
    }

    /// This endpoint with no socket of its own to move: it runs over a pipe
    /// and nothing outside a chain may rebind it.
    pub(crate) fn without_rebind(mut self) -> Self {
        self.rebind = Rebind::Unsupported;
        self
    }

    /// Makes [`Self::rebind_ephemeral`] move `outer` instead of this
    /// endpoint's own socket. For the endpoint of a connection that runs
    /// inside `outer`'s (a jump chain, ADR-0056 decision 16): migration
    /// happens at the outermost connection and the inner ones ride on it.
    #[must_use]
    pub fn rebinding_via(mut self, outer: Endpoint) -> Self {
        self.rebind = Rebind::Via(Arc::new(outer));
        self
    }

    /// Whether the endpoint runs over a pipe inside another connection (the
    /// end of a jump chain) rather than over a socket of its own.
    pub fn is_nested(&self) -> bool {
        !matches!(self.rebind, Rebind::Own)
    }

    /// The local address the endpoint is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.inner {
            EndpointBackend::Quic(e) => e.local_addr(),
            EndpointBackend::Iroh(e) => e.bound_sockets().into_iter().next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the iroh endpoint has no socket",
                )
            }),
        }
    }

    /// Resolves once every connection on the endpoint has fully closed and
    /// drained. Call it after closing connections for a clean shutdown.
    ///
    /// An endpoint on a pipe (the end of a jump chain) waits at most
    /// [`NESTED_IDLE_CAP`]: its pipe is closed when the chain is torn down,
    /// and quinn's endpoint task ends with the socket, after which no
    /// closing connection is ever reported drained.
    pub async fn wait_idle(&self) {
        if self.is_nested() {
            self.wait_idle_for(NESTED_IDLE_CAP).await;
            return;
        }
        self.wait_idle_inner().await;
    }

    /// [`Self::wait_idle`] for at most `cap`: the wait that ends a command.
    ///
    /// `CONNECTION_CLOSE` leaves as soon as a connection is closed; what
    /// `wait_idle` keeps waiting for is the closing period (three PTOs) of
    /// every connection the endpoint ever closed. A connection that never
    /// finished its handshake (a hole-punching candidate that lost the race)
    /// has no RTT sample and counts that period from its initial guess, which
    /// is about 0.9 s at `PUNCH_INITIAL_RTT`; waiting for it made a punched
    /// `exec` return 0.5 to 0.9 s after its output. Only a punched command
    /// uses this; a direct dial waits out its connection's full drain.
    pub async fn wait_idle_for(&self, cap: Duration) {
        let _ = tokio::time::timeout(cap, self.wait_idle_inner()).await;
    }

    async fn wait_idle_inner(&self) {
        match &self.inner {
            EndpointBackend::Quic(e) => e.wait_idle().await,
            // iroh waits for the close frames to be acknowledged inside
            // `close`; connections are closed by their holders first.
            EndpointBackend::Iroh(e) => e.close().await,
        }
    }

    /// Close every connection on the endpoint with an application code and
    /// refuse new ones. Idempotent.
    pub fn close(&self, code: u32, reason: &[u8]) {
        match &self.inner {
            EndpointBackend::Quic(e) => e.close(code, reason),
            EndpointBackend::Iroh(e) => {
                // iroh closes asynchronously; without a runtime the endpoint
                // closes when its last handle drops.
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let e = e.clone();
                    runtime.spawn(async move { e.close().await });
                }
            }
        }
    }

    /// Move the endpoint to a fresh local path so the peer sees a new
    /// source: a new socket of the same address family, unspecified address,
    /// ephemeral port. Returns the new local address.
    ///
    /// The point is a new local path, and letting the OS pick is what makes
    /// this work when the old interface is already gone. The socket comes
    /// from [`bind_tuned_udp_socket`] (not a plain `UdpSocket::bind`) so a
    /// post-migration socket keeps the same OS buffer tuning and
    /// dual-stack-v6 handling (`true`, mirroring [`Dialer::dial`]) the
    /// original dial got; a bare bind would silently reset the connection to
    /// whatever the OS grants by default. A backend with no migration
    /// would return [`io::ErrorKind::Unsupported`].
    pub fn rebind_ephemeral(&self) -> io::Result<SocketAddr> {
        match &self.rebind {
            Rebind::Own => {}
            Rebind::Via(outer) => return outer.rebind_ephemeral(),
            Rebind::Unsupported => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "an endpoint on a packet pipe has no socket to move",
                ));
            }
        }
        match &self.inner {
            EndpointBackend::Quic(e) => e.rebind_ephemeral(),
            EndpointBackend::Iroh(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "an iroh endpoint moves its own paths",
            )),
        }
    }
}

/// Transport counters of one connection ([`Connection::stats`]).
///
/// What the callers read, and why each is here rather than a backend type:
/// the path watchdog (`rtt`, `rx_frames`, `rx_raw_datagrams`), the tunnel
/// stall ledger (`peer_blocked_events`, ADR-0037), and the chaos tests
/// (`lost_packets`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// Current best estimate of the connection's round-trip time.
    pub rtt: Duration,
    /// How many frames this connection has received **and authenticated**,
    /// summed over every frame type the backend counts. Monotonic; the value
    /// means nothing on its own, only its movement does.
    ///
    /// This is the path-liveness signal `qsh-core`'s watchdog reads
    /// (`docs/design/protocol.md` §10): a counter that moved proves the
    /// peer's packets are reaching us whether or not any application
    /// message got through, which a `Pong` queued behind loss recovery on
    /// the ordered control stream cannot. Deliberately **not** the raw
    /// datagram counter: that one is counted before decryption, so an
    /// on-path injector who knows the connection id could keep a dead path
    /// looking alive until the idle timeout with junk datagrams. This one
    /// is recorded only after a packet has been decrypted and authenticated
    /// (`docs/design/threat-model.md` §4).
    pub rx_frames: u64,
    /// How many times the peer told us it is blocked on connection-level
    /// flow control (QUIC `DATA_BLOCKED`). The tunnel stall ledger's
    /// "peer destination stopped reading" signal (ADR-0037).
    pub peer_blocked_events: u64,
    /// How many times the peer told us a single stream is blocked on
    /// stream-level flow control (QUIC `STREAM_DATA_BLOCKED`).
    pub peer_stream_blocked_events: u64,
    /// Datagrams received on the socket, counted before decryption. Only a
    /// **hint** (anyone who knows the connection id can forge them), and
    /// `None` for a backend with no datagram layer.
    pub rx_raw_datagrams: Option<u64>,
    /// Packets this side detected as lost; `None` for a backend that does
    /// not track it.
    pub lost_packets: Option<u64>,
    /// Smallest RTT seen on the path, ignoring ack delay. Zero before the
    /// first sample.
    pub min_rtt: Duration,
    /// Current congestion window in bytes (BBR's, as quinn reports it).
    pub cwnd: u64,
    /// Congestion events the controller has handled.
    pub congestion_events: u64,
    /// Bytes this side detected as lost.
    pub lost_bytes: u64,
    /// Packets sent on the path.
    pub sent_packets: u64,
    /// Largest UDP payload the path currently supports (path MTU).
    pub path_mtu: u16,
    /// QUIC DATAGRAM frames sent (ADR-0052 decision 7).
    pub tx_datagram_frames: u64,
    /// QUIC DATAGRAM frames received **and authenticated**.
    pub rx_datagram_frames: u64,
}

/// Client-side factory: dials servers with our identity, verifying them
/// through `evaluator`.
pub struct Dialer {
    pub(crate) identity: LocalIdentity,
    pub(crate) evaluator: Arc<dyn TrustEvaluator>,
    pub(crate) timeout: Duration,
    pub(crate) tuning: TransportTuning,
}

impl Dialer {
    /// Create a dialer.
    pub fn new(identity: LocalIdentity, evaluator: Arc<dyn TrustEvaluator>) -> Self {
        Self {
            identity,
            evaluator,
            timeout: default_dial_timeout(),
            tuning: TransportTuning::default(),
        }
    }

    /// A dialer with this one's identity, timeout and tuning that verifies
    /// peers through `evaluator` instead. A jump chain uses it to accept
    /// exactly one fingerprint for the hop it is dialing (ADR-0056 decision
    /// 10) while the first hop keeps the ordinary trust store.
    #[must_use]
    pub fn with_evaluator(&self, evaluator: Arc<dyn TrustEvaluator>) -> Self {
        Self {
            identity: self.identity.clone(),
            evaluator,
            timeout: self.timeout,
            tuning: self.tuning,
        }
    }

    /// A dialer with this one's identity, timeout and tuning that accepts
    /// only the peer `binding` names (ADR-0060): the pin's exact key, or a
    /// CA-issued leaf. The evaluator it narrows is this dialer's own.
    #[must_use]
    pub fn bound_to(&self, binding: crate::tls::PeerBinding) -> Self {
        self.with_evaluator(Arc::new(crate::tls::BoundTrust::new(
            self.evaluator.clone(),
            binding,
        )))
    }

    /// Apply a [`TransportTuning`] to every connection this dialer makes.
    /// [`Self::new`] keeps the compiled default.
    #[must_use]
    pub fn with_tuning(mut self, tuning: TransportTuning) -> Self {
        self.tuning = tuning;
        self
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
        self.dial_quic(addr, server_name, TransportProfile::Tuned(self.tuning))
            .await
    }

    /// Test/benchmark-only escape hatch: identical to [`Self::dial`] —
    /// same TLS/identity plumbing, same socket tuning — except the
    /// `TransportConfig` is quinn's own stock `TransportConfig::default()`
    /// instead of qsh's tuned `transport_config()` (no BBR override, no
    /// `send_fairness`, no widened `stream_receive_window`). Exists for
    /// the M4 DoD 3 throughput gate
    /// (`crates/qsh-testkit/tests/it/tunnel_throughput.rs`), which needs an
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
        self.dial_quic(addr, server_name, TransportProfile::Stock)
            .await
    }

    /// Dial over a [`PacketPipe`] instead of a UDP socket: the inner
    /// connection of a jump hop (ADR-0056 decisions 2, 5 and 6). Same TLS,
    /// pin verification, dial timeout and transport config as [`Self::dial`],
    /// except that the endpoint is client-only, `initial_mtu` and `min_mtu`
    /// are [`JUMP_PACKET_MIN`] and PLPMTUD stops at [`JUMP_PACKET_MAX`].
    /// The connection's remote address is [`PIPE_REMOTE_ADDR`].
    pub async fn dial_over_pipe(
        &self,
        pipe: PacketPipe,
        server_name: &str,
    ) -> Result<Dialed, DialError> {
        self.dial_quic_over_pipe(pipe, server_name).await
    }
}

/// The part of a dial after the handshake: run the pin/CA check on the
/// server's chain and wrap the connection. Shared by [`Dialer`] and
/// [`PunchEndpoint::dial`].
pub(crate) fn finish_dial(
    conn: QuicConn,
    verifier: &QshPeerVerifier,
) -> Result<Connection, DialError> {
    let chain = peer_chain(&conn);
    match verifier.verify_peer(&chain, PeerRole::Server) {
        Ok(verified) => Ok(Connection::from_quic(
            conn,
            &chain,
            PeerRole::Server,
            verified,
        )),
        Err(reason) => {
            conn.close(CLOSE_CODE_UNVERIFIED_PEER, b"unverified peer");
            Err(DialError::LocalRejected {
                reason,
                observed: chain.first().and_then(|c| Fingerprint::of_cert_der(c).ok()),
            })
        }
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
    /// call [`Endpoint::wait_idle`] on shutdown for a clean close.
    pub endpoint: Endpoint,
    /// The per-dial verifier.
    pub verifier: Arc<QshPeerVerifier>,
}

impl Dialed {
    /// What the verifier saw for the server's certificate.
    pub fn observation(&self) -> Option<Observation> {
        self.verifier.last_observation()
    }
}

/// Whether a connection error is a TLS/crypto-class failure — i.e. the peer
/// (or we) aborted the handshake with a TLS alert. A free-function spelling
/// of [`ConnectionError::is_crypto_failure`], kept for the classifiers that
/// take it as a function value.
pub fn is_crypto_failure(err: &ConnectionError) -> bool {
    err.is_crypto_failure()
}

/// Server-side listener: accepts inbound connections, verifying clients
/// through `evaluator`.
pub struct Listener {
    pub(crate) endpoint: QuicEndpoint,
    pub(crate) verifier: Arc<QshPeerVerifier>,
}

/// Length in bytes of the stateless reset key
/// [`Listener::bind_with_reset_key`] takes (`docs/adr/0036-stateless-reset-key.md`
/// decision 2).
pub const RESET_KEY_LEN: usize = 32;

impl Listener {
    /// Bind a server endpoint on `bind`. The stateless reset key is
    /// quinn's per-process random one; production callers use
    /// [`Self::bind_with_reset_key`].
    pub fn bind(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
    ) -> Result<Self, SetupError> {
        Self::bind_quic(
            bind,
            identity,
            evaluator,
            TransportProfile::Tuned(TransportTuning::default()),
            None,
        )
    }

    /// [`Self::bind`] with the stateless reset key injected
    /// (`docs/adr/0036-stateless-reset-key.md`). This crate knows nothing
    /// of where the key lives; `qsh-core` reads or creates it and passes
    /// the bytes here. `tuning` is applied to every accepted connection.
    pub fn bind_with_reset_key(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        reset_key: &[u8; RESET_KEY_LEN],
        tuning: TransportTuning,
    ) -> Result<Self, SetupError> {
        Self::bind_quic(
            bind,
            identity,
            evaluator,
            TransportProfile::Tuned(tuning),
            Some(reset_key),
        )
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
        Self::bind_quic(bind, identity, evaluator, TransportProfile::Stock, None)
    }

    /// A listener on a caller-supplied (simulated) UDP socket, with the
    /// same server configuration [`Self::bind_with_reset_key`] builds. For
    /// `qsh_testkit::netsim`, where the rendezvous of a hole-punch test runs
    /// on a virtual network. Not part of the stable surface, the same
    /// escape-hatch status as [`SocketSource::Virtual`].
    #[doc(hidden)]
    pub fn bind_virtual(
        socket: Arc<VirtualSocket>,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        tuning: TransportTuning,
    ) -> Result<Self, SetupError> {
        Self::bind_quic_virtual(socket, identity, evaluator, tuning)
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
        self.endpoint.close(code, reason);
    }

    /// A handle on the listener's endpoint (e.g. for `wait_idle`, or to keep
    /// the socket alive past the listener).
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::from_quic(self.endpoint.clone())
    }
}

/// An inbound connection attempt whose handshake has not completed yet.
pub struct Incoming {
    pub(crate) incoming: QuicIncoming,
    pub(crate) verifier: Arc<QshPeerVerifier>,
}

impl Incoming {
    /// Peer address of the attempt (before authentication — for logs only).
    pub fn remote_address(&self) -> PeerAddr {
        PeerAddr::Socket(self.incoming.remote_address())
    }

    /// Whether the sender of this attempt's Initial has already proved it
    /// can receive traffic at [`remote_address`](Self::remote_address) —
    /// i.e. this is the second Initial of a Retry round trip, carrying a
    /// token quinn has checked against this exact address (the M8 plan (52639fc)
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
    /// [`retry`](Self::retry); it exists for [`retry`](Self::retry)'s own `Err` case
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
    /// `Self` in the `Err` arm is the shape the task's own spec (the M8 plan (52639fc)
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
            Err(incoming) => Err(Self { incoming, verifier }),
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
        let conn = self.incoming.handshake().await?;
        let chain = peer_chain(&conn);
        match self.verifier.verify_peer(&chain, PeerRole::Client) {
            Ok(verified) => Ok(Connection::from_quic(
                conn,
                &chain,
                PeerRole::Client,
                verified,
            )),
            Err(reason) => {
                conn.close(CLOSE_CODE_UNVERIFIED_PEER, b"unverified peer");
                Err(AcceptError::Unverified(reason))
            }
        }
    }
}

pub use crate::quinn_backend::pipe::{
    JUMP_PACKET_MAX, JUMP_PACKET_MIN, PIPE_LOCAL_ADDR, PIPE_REMOTE_ADDR, PacketPipe, PipePeer,
    PipeStats,
};
pub use crate::quinn_backend::punch::{
    MAX_PUNCH_WINDOWS, PunchArrival, PunchEndpoint, PunchInbox, PunchStats, PunchWindow,
    SocketSource,
};

#[cfg(test)]
mod tests;
