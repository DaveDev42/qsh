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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::error::{ConnectError, ConnectionError, ExportError};
use crate::identity::{Fingerprint, Principal};
use crate::mux::{MuxConn, TransportCaps, TransportKind};
use crate::quic::QuicConn;
use crate::stream::{RecvStream, SendStream};
use crate::tls::{
    AuthPath, Observation, PeerRole, QshPeerVerifier, RejectReason, TrustEvaluator, VerifiedPeer,
};

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
///
/// **Not the only defense against PTY starvation any more.** A tunnel
/// stream whose local consumer never reads holds up to this much of
/// [`CONNECTION_RECEIVE_WINDOW`], so four of them used to hold all of it
/// and stop the same connection's PTY output
/// (`crates/qsh-testkit/tests/tunnel_stalled_streams.rs`). The ratio of the
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

impl LocalIdentity {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.to_vec()))
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

fn transport_config(tuning: TransportTuning) -> quinn::TransportConfig {
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

/// The `Debug` rendering of the `quinn::TransportConfig` that `tuning`
/// produces. A test seam: `quinn::TransportConfig` has no public getters,
/// so a caller in another crate (the `[transport].keep_alive_ms` tests in
/// `qsh-core`) can only observe what reached quinn through its `Debug`
/// output, exactly as this module's own tests do.
#[doc(hidden)]
pub fn transport_config_debug(tuning: TransportTuning) -> String {
    format!("{:?}", transport_config(tuning))
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

/// Bind a UDP socket at `addr` with `tune_socket_buffer` applied
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
    // Never put the dialed hostname on the wire: the server verifies by
    // pin and ignores SNI, so it would only leak the name to on-path
    // observers (`docs/adr/0040-ech-policy.md` decision 2). rustls still
    // takes a `ServerName` for verification plumbing.
    tls.enable_sni = false;
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
fn server_config(
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
}

/// The transports a [`Connection`] can run over. Every method that touches
/// the wire goes through the [`MuxConn`] contract, so a backend that lacks
/// one fails to compile.
#[derive(Clone, Debug)]
enum ConnBackend {
    Quic(QuicConn),
}

impl Connection {
    /// Wrap a handshaken quinn connection whose peer the verifier accepted.
    fn from_quic(
        conn: quinn::Connection,
        chain: &[CertificateDer<'static>],
        verified: VerifiedPeer,
    ) -> Self {
        Self {
            peer_fingerprint: chain.first().and_then(|c| Fingerprint::of_cert_der(c).ok()),
            inner: ConnBackend::Quic(QuicConn(conn)),
            id: next_connection_id(),
            principal: verified.principal,
            auth_path: verified.auth_path,
        }
    }

    /// Which transport the connection runs over.
    pub fn transport_kind(&self) -> TransportKind {
        match &self.inner {
            ConnBackend::Quic(c) => c.kind(),
        }
    }

    /// What the connection's transport can do.
    pub fn caps(&self) -> TransportCaps {
        match &self.inner {
            ConnBackend::Quic(c) => c.caps(),
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

    /// Peer socket address (may change over the connection's life via
    /// migration; this is the current one).
    pub fn remote_address(&self) -> SocketAddr {
        match &self.inner {
            ConnBackend::Quic(c) => c.remote_address(),
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
        }
    }

    /// Accept the next peer-initiated bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        match &self.inner {
            ConnBackend::Quic(c) => {
                let (send, recv) = c.accept_bi().await?;
                Ok((SendStream::from_quic(send), RecvStream::from_quic(recv)))
            }
        }
    }

    /// Close with an application error code and reason. Idempotent.
    pub fn close(&self, code: u32, reason: &[u8]) {
        match &self.inner {
            ConnBackend::Quic(c) => c.close(code, reason),
        }
    }

    /// Resolves when the connection is closed (by either side).
    pub async fn closed(&self) -> ConnectionError {
        match &self.inner {
            ConnBackend::Quic(c) => c.closed().await,
        }
    }

    /// If the connection is already closed, why.
    pub fn close_reason(&self) -> Option<ConnectionError> {
        match &self.inner {
            ConnBackend::Quic(c) => c.close_reason(),
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
        }
    }

    /// The underlying quinn connection: a QUIC-backend escape hatch for
    /// `qsh-transport`'s own backend tests (handshake data, keep-alive ping
    /// counters). Not part of the supported surface — `qsh-core` and
    /// `qsh-cli` must go through the neutral methods on this type, and
    /// `cargo xtask arch` bars them from naming quinn at all.
    #[doc(hidden)]
    pub fn quinn(&self) -> &quinn::Connection {
        match &self.inner {
            ConnBackend::Quic(c) => &c.0,
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
        }
    }
}

/// Source of [`Connection::stable_id`].
fn next_connection_id() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Debug)]
enum EndpointBackend {
    Quic(quinn::Endpoint),
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
}

impl Endpoint {
    pub(crate) fn from_quic(endpoint: quinn::Endpoint) -> Self {
        Self {
            inner: EndpointBackend::Quic(endpoint),
        }
    }

    /// The local address the endpoint is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.inner {
            EndpointBackend::Quic(e) => e.local_addr(),
        }
    }

    /// Resolves once every connection on the endpoint has fully closed and
    /// drained. Call it after closing connections for a clean shutdown.
    pub async fn wait_idle(&self) {
        match &self.inner {
            EndpointBackend::Quic(e) => e.wait_idle().await,
        }
    }

    /// Close every connection on the endpoint with an application code and
    /// refuse new ones. Idempotent.
    pub fn close(&self, code: u32, reason: &[u8]) {
        match &self.inner {
            EndpointBackend::Quic(e) => e.close(quinn::VarInt::from_u32(code), reason),
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
        match &self.inner {
            EndpointBackend::Quic(e) => {
                let bind: SocketAddr = match e.local_addr()? {
                    SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
                    SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
                };
                let socket = bind_tuned_udp_socket(bind, true)?;
                e.rebind(socket)?;
                e.local_addr()
            }
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
    tuning: TransportTuning,
}

impl Dialer {
    /// Create a dialer.
    pub fn new(identity: LocalIdentity, evaluator: Arc<dyn TrustEvaluator>) -> Self {
        Self {
            identity,
            evaluator,
            timeout: DEFAULT_DIAL_TIMEOUT,
            tuning: TransportTuning::default(),
        }
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
        self.dial_inner(addr, server_name, transport_config(self.tuning))
            .await
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
        let quic = QuicClientConfig::try_from(tls).map_err(|e| SetupError::Quic(e.to_string()))?;
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

        let connecting = endpoint
            .connect(addr, server_name)
            .map_err(ConnectError::from)?;
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
            connection: Connection::from_quic(conn, &chain, verified),
            endpoint: Endpoint::from_quic(endpoint),
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

/// Map a failed handshake to a [`DialError`], using the verifier's
/// observation to tell "we rejected them" from "they rejected us".
fn classify_dial_failure(err: quinn::ConnectionError, obs: Option<Observation>) -> DialError {
    let err = ConnectionError::from(err);
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
    if err.is_crypto_failure() {
        return DialError::RemoteRejected;
    }
    if err.is_refused() {
        return DialError::Refused;
    }
    DialError::Failed(err)
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
    endpoint: quinn::Endpoint,
    verifier: Arc<QshPeerVerifier>,
}

/// Length in bytes of the stateless reset key
/// [`Listener::bind_with_reset_key`] takes (`docs/adr/0036-stateless-reset-key.md`
/// decision 2).
pub const RESET_KEY_LEN: usize = 32;

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
fn server_endpoint_config(reset_key: Option<&[u8; RESET_KEY_LEN]>) -> quinn::EndpointConfig {
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
const CID_KEY_LABEL: &[u8] = b"qsh stateless reset: connection id generator key v1";

impl Listener {
    /// Bind a server endpoint on `bind`. The stateless reset key is
    /// quinn's per-process random one; production callers use
    /// [`Self::bind_with_reset_key`].
    pub fn bind(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
    ) -> Result<Self, SetupError> {
        Self::bind_inner(
            bind,
            identity,
            evaluator,
            transport_config(TransportTuning::default()),
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
        Self::bind_inner(
            bind,
            identity,
            evaluator,
            transport_config(tuning),
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
        Self::bind_inner(
            bind,
            identity,
            evaluator,
            quinn::TransportConfig::default(),
            None,
        )
    }

    fn bind_inner(
        bind: SocketAddr,
        identity: LocalIdentity,
        evaluator: Arc<dyn TrustEvaluator>,
        transport: quinn::TransportConfig,
        reset_key: Option<&[u8; RESET_KEY_LEN]>,
    ) -> Result<Self, SetupError> {
        let verifier = Arc::new(QshPeerVerifier::new(evaluator));
        let server_config = server_config(&identity, verifier.clone(), transport)?;
        let socket = bind_tuned_udp_socket(bind, false)
            .map_err(|source| SetupError::Bind { addr: bind, source })?;
        let endpoint = quinn::Endpoint::new(
            server_endpoint_config(reset_key),
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

    /// A handle on the listener's endpoint (e.g. for `wait_idle`, or to keep
    /// the socket alive past the listener).
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::from_quic(self.endpoint.clone())
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
        let conn = self.incoming.await.map_err(ConnectionError::from)?;
        let chain = peer_chain(&conn);
        match self.verifier.verify_peer(&chain, PeerRole::Client) {
            Ok(verified) => Ok(Connection::from_quic(conn, &chain, verified)),
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
mod tests;
