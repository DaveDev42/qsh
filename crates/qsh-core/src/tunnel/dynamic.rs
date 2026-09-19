//! The requester side of `-D`, SOCKS5 dynamic port forwarding (ADR-0019
//! decisions 7, 8, 9).
//!
//! A [`DynamicForward`] owns one loopback TCP listener. Every connection
//! accepted on it speaks SOCKS5 to this process (the sans-IO codec in
//! [`qsh_proto::socks5`] does the parsing/encoding); once its `CONNECT`
//! request is fully read, the destination it names becomes a
//! `StreamHeader{TCP_CONNECT, deny_host_local: true}` on the peer, exactly
//! the same wire shape [`crate::tunnel::local`] uses for `-L` — [`open_tunnel`]
//! and [`splice_opened`] are shared with it verbatim:
//!
//! ```text
//! local TCP conn ──▶ SOCKS5 greeting/request ──▶ (this module, local only)
//!                 ◀── method-select / no REP yet ──
//!                                  │
//!                                  ▼ open_tunnel(deny_host_local: true)
//!                              StreamHeader{TCP_CONNECT} ──▶ peer
//!                                  ◀── ConnectResult{ok} ──
//!                                  │
//!                 ◀── REP (only after ConnectResult) ──
//!                 ◀────────── raw bytes, both ways ─────────▶
//! ```
//!
//! Unlike `-L`, the destination is chosen by whatever is speaking SOCKS5
//! through this listener — a browser via `curl --socks5-hostname`, most
//! sharply — not by the operator. ADR-0019's threat model is that content
//! behind the proxy could steer a resolve-time rebind at the *peer's*
//! loopback or cloud-metadata addresses; [`DialPolicy::deny_host_local`]
//! (always `true` here) is what the peer checks for that, and this module
//! adds its own, purely defensive, resource limits so a single loopback
//! listener cannot itself become a denial-of-service vector against the
//! peer's fail-closed audit writer or its `max_tunnel_streams_per_principal`
//! quota (ADR-0019 decision 9):
//!
//! - a **handshake-slot** semaphore ([`HANDSHAKE_SLOTS`]) bounds how many
//!   connections may be mid-handshake (reading the SOCKS greeting/request) at
//!   once; over the bound, a connection is closed immediately, before a byte
//!   is read from it;
//! - an **established-connection cap** ([`MAX_ESTABLISHED_CONNECTIONS`])
//!   bounds how many `CONNECT`s may be open at once, below the peer's own
//!   default per-principal stream quota; over the cap, the connection gets
//!   `REP 0x01` and no tunnel stream is opened;
//! - a **token bucket** ([`RATE_PER_SEC`]/[`RATE_BURST`]) bounds the rate of
//!   new `CONNECT`s. A browser opens dozens of connections for one page load,
//!   so an over-rate `CONNECT` is not refused outright — it *waits* for a
//!   token, but never past its own connection's absolute handshake deadline
//!   ([`HANDSHAKE_DEADLINE`]); only a wait that would cross that deadline
//!   ends in `REP 0x01` with no stream.
//!
//! Every connection also owes the peer a `deny_host_local: true` header no
//! matter how it got here, and an absolute [`HANDSHAKE_DEADLINE`] covering
//! its greeting *and* request together — a client that never finishes
//! speaking SOCKS5 (or never speaks it at all) is dropped, not parked
//! forever holding a handshake slot.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::socks5::{self, Rep};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant as TokioInstant;

use crate::tunnel::dial::DialPolicy;
use crate::tunnel::local::{
    ACCEPT_BACKOFF, AcceptDisposition, ForwardCarrier, ForwardConnError, LocalForwardError,
    accept_disposition, loopback_bind_addr, open_tunnel, splice_opened,
};

/// How many connections may be mid-handshake (greeting/request not yet
/// fully read) at once, across one `-D` listener (ADR-0019 decision 9).
/// Acquired with [`Semaphore::try_acquire_owned`] — a connection that finds
/// no slot is closed immediately, before it is read from at all.
pub(crate) const HANDSHAKE_SLOTS: usize = 64;

/// How many `CONNECT`s may be open at once, across one `-D` listener
/// (ADR-0019 decision 9) — below the peer's own default
/// `max_tunnel_streams_per_principal` (256), so this cap is always the one
/// that answers first. Over it, a `CONNECT` gets `REP 0x01` and no tunnel
/// stream is opened.
pub(crate) const MAX_ESTABLISHED_CONNECTIONS: usize = 128;

/// Token-bucket steady rate: new `CONNECT`s per second (ADR-0019 decision
/// 9).
pub(crate) const RATE_PER_SEC: f64 = 50.0;

/// Token-bucket burst capacity (ADR-0019 decision 9).
pub(crate) const RATE_BURST: f64 = 100.0;

/// Absolute deadline covering one connection's SOCKS5 greeting *and*
/// request together (ADR-0019 decision 9): "handshake 기한은 greeting과
/// request를 합쳐 절대 10초다. 읽을 때마다 기한이 늘어나지 않는다." The same
/// deadline also bounds how long an over-rate `CONNECT` waits for a token
/// (ADR-0019 decision 9's amendment) — there is only ever one deadline per
/// connection.
pub(crate) const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// A token bucket for the `CONNECT` rate limit, virtual-clock-based
/// ([`tokio::time::Instant`]) so it advances correctly under
/// `tokio::time::pause` in tests, exactly the way the deadline it is bounded
/// by does.
struct TokenBucket {
    rate_per_sec: f64,
    burst: f64,
    state: Mutex<TokenBucketState>,
}

struct TokenBucketState {
    tokens: f64,
    last_refill: TokioInstant,
}

impl TokenBucket {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            rate_per_sec,
            burst,
            state: Mutex::new(TokenBucketState {
                tokens: burst,
                last_refill: TokioInstant::now(),
            }),
        }
    }

    fn refill_locked(&self, state: &mut TokenBucketState) {
        let now = TokioInstant::now();
        let elapsed = now
            .saturating_duration_since(state.last_refill)
            .as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.rate_per_sec).min(self.burst);
        state.last_refill = now;
    }

    /// Take one token now, if one is available.
    fn try_take(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.refill_locked(&mut state);
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// How long until at least one token is available, `Duration::ZERO` if
    /// one already is.
    fn time_until_token(&self) -> Duration {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.refill_locked(&mut state);
        if state.tokens >= 1.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((1.0 - state.tokens) / self.rate_per_sec)
        }
    }

    /// Wait for one token, but never past `deadline` (ADR-0019 decision 9's
    /// amendment: "그 기한 안에 토큰이 생기지 않을 때만 스트림 없이 REP
    /// 0x01을 받는다"). `true` if a token was acquired, `false` if
    /// `deadline` passed first.
    async fn acquire_before(&self, deadline: TokioInstant) -> bool {
        loop {
            if self.try_take() {
                return true;
            }
            let now = TokioInstant::now();
            if now >= deadline {
                return false;
            }
            let wait = self.time_until_token().min(deadline - now);
            if wait.is_zero() {
                // Another waiter raced us to the refilled token; yield once
                // and try again rather than spin.
                tokio::task::yield_now().await;
                continue;
            }
            tokio::time::sleep(wait).await;
        }
    }
}

/// The three shared, listener-wide limits (ADR-0019 decision 9), plus the
/// live established-connection count they gate.
struct DynamicLimits {
    handshake_slots: Arc<Semaphore>,
    max_established: usize,
    established: Arc<AtomicUsize>,
    rate: TokenBucket,
    /// [`HANDSHAKE_DEADLINE`] in production; test-only override
    /// ([`DynamicLimits::new`]) so the rate-limit-vs-deadline boundary can be
    /// exercised in milliseconds of real time instead of the full 10 s.
    handshake_deadline: Duration,
}

impl DynamicLimits {
    fn production() -> Self {
        Self::new(
            HANDSHAKE_SLOTS,
            MAX_ESTABLISHED_CONNECTIONS,
            RATE_PER_SEC,
            RATE_BURST,
            HANDSHAKE_DEADLINE,
        )
    }

    fn new(
        handshake_slots: usize,
        max_established: usize,
        rate_per_sec: f64,
        burst: f64,
        handshake_deadline: Duration,
    ) -> Self {
        Self {
            handshake_slots: Arc::new(Semaphore::new(handshake_slots)),
            max_established,
            established: Arc::new(AtomicUsize::new(0)),
            rate: TokenBucket::new(rate_per_sec, burst),
            handshake_deadline,
        }
    }

    /// Reserve one of [`Self::max_established`] slots, held for the whole
    /// life of one `CONNECT` (from just after its request is parsed until
    /// its splice ends). `None` if the cap is already reached.
    fn reserve_connection_slot(&self) -> Option<ConnectionSlot> {
        let mut current = self.established.load(Ordering::SeqCst);
        loop {
            if current >= self.max_established {
                return None;
            }
            match self.established.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(ConnectionSlot {
                        established: Arc::clone(&self.established),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// RAII release of one [`DynamicLimits::reserve_connection_slot`] reservation.
struct ConnectionSlot {
    established: Arc<AtomicUsize>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.established.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A bound, running `-D` listener: one loopback TCP listener speaking SOCKS5
/// to whatever connects to it.
///
/// Mirrors [`crate::tunnel::local::LocalForward`]'s split between "bind"
/// (learn the real port before accepting) and "run" (the accept loop) —
/// same reason: `-D 0` (or `[bind:]0`) needs the OS-chosen port back before
/// the loop starts.
pub(crate) struct DynamicForward {
    listener: TcpListener,
    local_addr: SocketAddr,
    limits: Arc<DynamicLimits>,
}

impl DynamicForward {
    /// Bind the loopback listener for `-D [bind:]port` with production
    /// limits (ADR-0019 decision 9). Never creates anything but the
    /// listener itself — no tunnel stream exists until a SOCKS client
    /// completes a `CONNECT` (this module's own doc).
    pub(crate) async fn bind(
        bind: Option<&str>,
        listen_port: u16,
    ) -> Result<Self, LocalForwardError> {
        Self::bind_with_limits(bind, listen_port, DynamicLimits::production()).await
    }

    /// [`Self::bind`] with test-scale limits, so a unit test can exercise
    /// the handshake-slot/connection-cap/rate-limit boundaries without
    /// opening 64, 128 or 100 real connections.
    #[cfg(test)]
    async fn bind_for_test(
        bind: Option<&str>,
        listen_port: u16,
        handshake_slots: usize,
        max_established: usize,
        rate_per_sec: f64,
        burst: f64,
    ) -> Result<Self, LocalForwardError> {
        Self::bind_for_test_with_deadline(
            bind,
            listen_port,
            handshake_slots,
            max_established,
            rate_per_sec,
            burst,
            HANDSHAKE_DEADLINE,
        )
        .await
    }

    /// [`Self::bind_for_test`], additionally overriding the absolute
    /// handshake deadline — the one knob a rate-limit-vs-deadline test needs
    /// that the others do not, so it stays a separate constructor rather than
    /// a seventh parameter every other test call site would have to spell
    /// out.
    #[cfg(test)]
    async fn bind_for_test_with_deadline(
        bind: Option<&str>,
        listen_port: u16,
        handshake_slots: usize,
        max_established: usize,
        rate_per_sec: f64,
        burst: f64,
        handshake_deadline: Duration,
    ) -> Result<Self, LocalForwardError> {
        Self::bind_with_limits(
            bind,
            listen_port,
            DynamicLimits::new(
                handshake_slots,
                max_established,
                rate_per_sec,
                burst,
                handshake_deadline,
            ),
        )
        .await
    }

    async fn bind_with_limits(
        bind: Option<&str>,
        listen_port: u16,
        limits: DynamicLimits,
    ) -> Result<Self, LocalForwardError> {
        // ADR-0019 decision 9: "bind는 loopback 전용이다" — the exact same
        // rule `-L` enforces, reused rather than re-implemented, with `-D`
        // named in its own refusal text (`loopback_bind_addr`'s own doc).
        let addr = loopback_bind_addr(bind, listen_port, "-D")?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| LocalForwardError::Listen { addr, source })?;
        let local_addr = listener
            .local_addr()
            .map_err(|source| LocalForwardError::Listen { addr, source })?;
        Ok(Self {
            listener,
            local_addr,
            limits: Arc::new(limits),
        })
    }

    /// The address actually bound — with a `0` listen port, the one the
    /// kernel picked.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// A cheap handle to this listener's shared limits — test-only, taken
    /// before [`Self::run`] consumes `self`, so a test can still poll e.g.
    /// `available_permits()` on the handshake-slot semaphore to synchronize
    /// "N connections are mid-handshake" without a race on wall-clock timing.
    #[cfg(test)]
    fn limits_handle(&self) -> Arc<DynamicLimits> {
        Arc::clone(&self.limits)
    }

    /// Accept forever, running each connection's SOCKS5 handshake and, past
    /// it, splicing it onto its own tunnel stream — the `-D` analogue of
    /// [`crate::tunnel::local::LocalForward::run`], reusing its exact accept-
    /// error discipline ([`accept_disposition`]) so one bad `accept()` can
    /// no more take a `-D` listener down than it can a `-L` one.
    pub(crate) async fn run(self, carrier: Arc<ForwardCarrier>) -> io::Error {
        let mut tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (tcp, _peer) = match accepted {
                        Ok(pair) => pair,
                        Err(err) => match accept_disposition(&err) {
                            AcceptDisposition::Retry => {
                                tracing::debug!(%err, "qsh::tunnel::dynamic: transient accept error");
                                continue;
                            }
                            AcceptDisposition::Backoff => {
                                // Structural only — no destination exists
                                // yet at this point, so there is nothing
                                // for this module's own "destination at
                                // debug only" rule to protect here.
                                tracing::warn!(
                                    %err,
                                    backoff_ms = ACCEPT_BACKOFF.as_millis() as u64,
                                    "qsh::tunnel::dynamic: accept deferred, out of resources"
                                );
                                tokio::time::sleep(ACCEPT_BACKOFF).await;
                                continue;
                            }
                            AcceptDisposition::Fatal => return err,
                        },
                    };
                    let carrier = Arc::clone(&carrier);
                    let limits = Arc::clone(&self.limits);
                    tasks.spawn(async move {
                        handle_connection(tcp, carrier, limits).await;
                    });
                }
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(err) = joined
                        && err.is_panic()
                    {
                        tracing::warn!(%err, "qsh::tunnel::dynamic: connection task panicked");
                    }
                }
            }
        }
    }
}

/// A bound, running `-D` listener plus the task serving it, owned by the
/// caller (`Ops`/`SessionAttachStream`) for the tunnel's whole lifetime.
///
/// Mirrors [`crate::tunnel::local::LocalForwardHandle`]: `start` binds and
/// spawns in one step, `Drop` aborts the accept task (which owns the
/// listener and every in-flight connection task via its own `JoinSet`, so
/// aborting it is a complete teardown — [`LocalForwardHandle`]'s own doc).
///
/// [`LocalForwardHandle`]: crate::tunnel::local::LocalForwardHandle
#[derive(Debug)]
pub struct DynamicForwardHandle {
    tunnel_id: String,
    bind: SocketAddr,
    task: tokio::task::JoinHandle<io::Error>,
}

impl DynamicForwardHandle {
    /// Bind `[bind:]listen_port`'s loopback listener and start serving it
    /// over `connection` (ADR-0019 decision 11).
    ///
    /// Must be called from inside a tokio runtime — same requirement as
    /// [`LocalForwardHandle::start`]. The listener exists only after this
    /// returns `Ok`: a refused bind (non-loopback, port in use) creates
    /// nothing, and no tunnel stream is opened until a SOCKS client
    /// completes a `CONNECT` (this module's own doc).
    ///
    /// [`LocalForwardHandle::start`]: crate::tunnel::local::LocalForwardHandle::start
    pub async fn start(
        bind: Option<&str>,
        listen_port: u16,
        connection: qsh_transport::Connection,
    ) -> Result<Self, LocalForwardError> {
        let forward = DynamicForward::bind(bind, listen_port).await?;
        let bind_addr = forward.local_addr();
        let carrier = Arc::new(ForwardCarrier::Quic(connection));
        Ok(Self {
            tunnel_id: ulid::Ulid::new().to_string(),
            bind: bind_addr,
            task: tokio::spawn(forward.run(carrier)),
        })
    }

    /// The address actually bound — with a `0` listen port, the one the
    /// kernel picked.
    pub fn local_addr(&self) -> SocketAddr {
        self.bind
    }

    /// This forward as the `qsh.cli/v1` [`qsh_proto::DynamicTunnel`] DTO
    /// (ADR-0019 decision 11). `host` is the peer alias, which only the
    /// `Ops` layer knows — same `Ops`-filled-alias rule
    /// [`LocalForwardHandle::tunnel`] follows (ADR-0007).
    ///
    /// [`LocalForwardHandle::tunnel`]: crate::tunnel::local::LocalForwardHandle::tunnel
    pub fn dynamic_tunnel(&self, host: &str) -> qsh_proto::DynamicTunnel {
        qsh_proto::DynamicTunnel {
            tunnel_id: self.tunnel_id.clone(),
            mode: "dynamic".to_string(),
            bind: self.bind.to_string(),
            actual_port: Some(u32::from(self.bind.port())),
            protocol: "socks5".to_string(),
            dial_policy: "deny_host_local".to_string(),
            host: host.to_string(),
        }
    }

    /// Wait for the forward's listener to fail fatally.
    ///
    /// Only a *listener* error resolves this — one broken `CONNECT`ed
    /// connection never does — so in practice a holder parks here until the
    /// process ends or the handle is dropped (same discipline as
    /// [`LocalForwardHandle::wait`]).
    ///
    /// [`LocalForwardHandle::wait`]: crate::tunnel::local::LocalForwardHandle::wait
    pub async fn wait(&mut self) -> io::Error {
        match (&mut self.task).await {
            Ok(err) => err,
            Err(err) => io::Error::other(format!("dynamic forward task ended: {err}")),
        }
    }
}

impl Drop for DynamicForwardHandle {
    fn drop(&mut self) {
        // The listener and every in-flight connection task live inside the
        // aborted future (`DynamicForward::run`'s own `JoinSet`), so this is
        // the whole teardown — same reasoning as `LocalForwardHandle::drop`.
        self.task.abort();
    }
}

/// Why [`read_greeting`]/[`read_request`] gave up without a `REP` to send —
/// the client either never spoke SOCKS5 at all, or the absolute
/// [`HANDSHAKE_DEADLINE`] passed (or the connection closed) before a
/// complete message arrived. Both are "close, write nothing, open nothing"
/// (ADR-0019 decision 7's own "silent close" rule, extended by decision 9 to
/// cover the deadline).
enum HandshakeGiveUp {
    /// The first byte was not `0x05`.
    NotSocks5,
    /// The deadline passed, or the peer closed the connection, before a
    /// complete message arrived.
    DeadlineOrClosed,
}

/// Read exactly `buf.len()` bytes off `tcp`, bounded by the single absolute
/// `deadline` covering the whole handshake (ADR-0019 decision 9: "읽을 때마다
/// 기한이 늘어나지 않는다" — `deadline` is a value the caller computed once
/// and passes through unchanged, never recomputed here). `None` on a
/// timeout, an EOF, or an I/O error — all of which the caller treats
/// identically (module doc).
///
/// Reads in a loop rather than a single `read`, because a slow/adversarial
/// client can split even a 4-byte header across multiple TCP segments —
/// but every iteration re-measures time against the same `deadline`, so the
/// bound is on the whole read, not on any one `read()` call.
async fn read_exact_before(
    tcp: &mut TcpStream,
    buf: &mut [u8],
    deadline: TokioInstant,
) -> Option<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, tcp.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(n)) => filled += n,
            Ok(Err(_)) => return None,
            Err(_elapsed) => return None,
        }
    }
    Some(())
}

/// Read one SOCKS5 greeting off `tcp`: `VER(1) NMETHODS(1) METHODS(0..=255)`
/// (ADR-0019 decision 7). Reads exactly the fixed 2-byte header, then
/// exactly the `NMETHODS` method bytes it names — never touches a byte
/// belonging to the request that follows, so nothing is ever carried
/// forward between the greeting and request reads (decision 7: "고정
/// 헤더를 읽은 뒤 ... 나머지 길이만큼만 정확히 읽는다").
async fn read_greeting(
    tcp: &mut TcpStream,
    deadline: TokioInstant,
) -> Result<socks5::Greeting, HandshakeGiveUp> {
    let mut ver = [0u8; 1];
    read_exact_before(tcp, &mut ver, deadline)
        .await
        .ok_or(HandshakeGiveUp::DeadlineOrClosed)?;
    // A single `VER` byte is already enough for `parse_greeting` to reject
    // a non-`0x05` first byte (module doc's "silent close" rule) without
    // reading anything more from a client that never spoke SOCKS5 at all.
    match socks5::parse_greeting(&ver) {
        Err(socks5::GreetingError::Invalid) => return Err(HandshakeGiveUp::NotSocks5),
        Err(socks5::GreetingError::Incomplete) => {}
        Ok(_) => unreachable!("one byte can never complete a greeting"),
    }

    let mut nmethods = [0u8; 1];
    read_exact_before(tcp, &mut nmethods, deadline)
        .await
        .ok_or(HandshakeGiveUp::DeadlineOrClosed)?;

    let mut full = Vec::with_capacity(2 + nmethods[0] as usize);
    full.push(ver[0]);
    full.push(nmethods[0]);
    let mut methods = vec![0u8; nmethods[0] as usize];
    if !methods.is_empty() {
        read_exact_before(tcp, &mut methods, deadline)
            .await
            .ok_or(HandshakeGiveUp::DeadlineOrClosed)?;
    }
    full.extend_from_slice(&methods);

    match socks5::parse_greeting(&full) {
        Ok(parsed) => Ok(parsed.value),
        Err(_) => unreachable!("a full-length greeting always parses"),
    }
}

/// [`read_greeting`]'s outcome once a request has been read far enough to
/// classify: either a fully valid [`socks5::Request`], or a `REP` the driver
/// already owes the client (unsupported `CMD`/`ATYP`, a shape violation) —
/// see [`socks5::RequestError::Rejected`].
enum RequestOutcome {
    Parsed(socks5::Request),
    Rejected(Rep),
}

/// [`read_greeting`]'s sibling for the `CONNECT` request:
/// `VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(..) DST.PORT(2)` (ADR-0019
/// decision 7). Reads exactly the fixed 4-byte header, then exactly the
/// length `ATYP` determines — IPv4 (`0x01`): 4 address bytes + 2 port
/// bytes; IPv6 (`0x04`): 16 + 2; domain (`0x03`): a 1-byte length prefix,
/// then that many bytes + 2 — never more. Any bytes the client already
/// wrote past the request (its first pipelined payload segment) are
/// therefore never pulled into this buffer at all: they stay in the
/// socket's own receive buffer for [`splice_opened`] to read in its normal
/// course, exactly decision 7's "요청 뒤에 이어 온 바이트는 버리지 않고
/// splice로 넘어간다".
///
/// Unlike a greeting, a request has no "not SOCKS5 at all" outcome of its
/// own (that was already settled by the greeting) — only "classified" or
/// "gave up before a full request arrived", so the error type here is a
/// bare unit rather than [`HandshakeGiveUp`].
async fn read_request(tcp: &mut TcpStream, deadline: TokioInstant) -> Result<RequestOutcome, ()> {
    let mut buf = [0u8; 4];
    read_exact_before(tcp, &mut buf, deadline).await.ok_or(())?;
    let atyp = buf[3];
    let mut buf = buf.to_vec();
    match atyp {
        // IPv4 (ADR-0019 decision 7): 4 address bytes + 2 port bytes.
        0x01 => {
            let mut rest = [0u8; 4 + 2];
            read_exact_before(tcp, &mut rest, deadline)
                .await
                .ok_or(())?;
            buf.extend_from_slice(&rest);
        }
        // IPv6: 16 address bytes + 2 port bytes.
        0x04 => {
            let mut rest = [0u8; 16 + 2];
            read_exact_before(tcp, &mut rest, deadline)
                .await
                .ok_or(())?;
            buf.extend_from_slice(&rest);
        }
        // Domain: a 1-byte length prefix, then that many bytes + 2 port
        // bytes — the one `ATYP` whose remaining length is itself carried
        // in the stream rather than fixed.
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_before(tcp, &mut len, deadline).await.ok_or(())?;
            buf.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            read_exact_before(tcp, &mut rest, deadline)
                .await
                .ok_or(())?;
            buf.extend_from_slice(&rest);
        }
        // Any other ATYP is classified from the 4-byte header alone
        // (`socks5::parse_request`'s `Rep::AddressTypeNotSupported`) — no
        // further bytes are needed or read.
        _ => {}
    }
    match socks5::parse_request(&buf) {
        Ok(parsed) => Ok(RequestOutcome::Parsed(parsed.value)),
        Err(socks5::RequestError::Rejected(rep)) => Ok(RequestOutcome::Rejected(rep)),
        Err(socks5::RequestError::Incomplete) => {
            unreachable!("the driver reads exactly the ATYP-determined length before reparsing")
        }
    }
}

/// Discard whatever the peer has already sent but this driver never read
/// (e.g. the domain-and-payload tail of a single write the exact-length
/// reads above deliberately left in the socket's own receive buffer, on a
/// path that turns out not to splice it through after all). Closing a
/// socket with unread bytes still sitting in the kernel's receive buffer
/// resets the connection (`RST`) instead of closing it in the ordinary way
/// (`FIN`) — regardless of `SO_LINGER` — which on a path that just wrote a
/// `REP` is exactly the race decision 8's "no RST after a REP" rule
/// forbids (the RST can destroy the not-yet-delivered `REP`), and on a
/// silent-close path (module doc) would surprise a local client expecting
/// a plain closed connection rather than a reset one.
///
/// Non-blocking and best-effort: never awaits, so it can never itself hang
/// past the handshake deadline, and a client that keeps on sending is
/// bounded by a fixed number of iterations rather than drained forever.
fn drain_pending(tcp: &TcpStream) {
    let mut scratch = [0u8; 4096];
    for _ in 0..64 {
        match tcp.try_read(&mut scratch) {
            Ok(0) => return,
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

/// Write `rep`, half-close the write direction, drain any unread input
/// (`drain_pending`'s own doc), then close normally — never `abort_local`'s
/// `SO_LINGER 0` RST, which would destroy the `REP` this function just
/// queued (ADR-0019 decision 8: "실패 REP 뒤에는 `shutdown(Write)` 후 보통
/// close를 한다ᅠ... `SO_LINGER 0`(RST)은 아직 보내지 않은 REP를 없앨 수 있으므로
/// 이 경로에서는 쓰지 않는다"). The write and the shutdown are best-effort —
/// a client that is already gone is not this function's problem to report.
async fn send_rep_and_close(mut tcp: TcpStream, rep: Rep) {
    let _ = tcp.write_all(&socks5::encode_reply(rep)).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp).await;
    drain_pending(&tcp);
}

/// Map a failed [`open_tunnel`] to the `REP` ADR-0019 decision 8's table
/// assigns it. [`ForwardConnError::Refused`] carries the peer's
/// [`ErrorCode`] as sanitized text ([`ForwardConnError::Refused`]'s own
/// doc); `ErrorCode::from_str` is total (unrecognized text becomes
/// [`ErrorCode::Unknown`], never an `Err`), so re-parsing it here is exact
/// for a well-behaved peer and a safe `REP 0x01` fallback for anything else.
/// Every other variant is a *local* failure (stream would not open, no
/// `ConnectResult` arrived, the carrier could not surrender a raw pipe) —
/// decision 8's "로컬" row, `REP 0x01`.
fn rep_for_forward_conn_error(err: &ForwardConnError) -> Rep {
    match err {
        ForwardConnError::Refused { code, .. } => {
            let error_code: ErrorCode = code
                .parse()
                .unwrap_or_else(|never: std::convert::Infallible| match never {});
            Rep::from_error_code(&error_code)
        }
        ForwardConnError::Link(_)
        | ForwardConnError::NoConnectResult
        | ForwardConnError::CarrierNotRaw => Rep::GeneralFailure,
        ForwardConnError::Splice(_) => Rep::GeneralFailure,
    }
}

/// One accepted TCP connection's whole life on a `-D` listener: negotiate
/// SOCKS5, open a tunnel stream for whatever it asked to `CONNECT` to, and
/// either splice or answer a `REP` and close (module doc's sequence
/// diagram).
///
/// Never fatal to the listener — [`DynamicForward::run`]'s own doc — every
/// path through this function returns normally, logging at most (debug: the
/// destination; warn: nothing from here, since nothing here is a resource
/// shortage the operator needs to see, unlike `accept()` itself).
async fn handle_connection(
    mut tcp: TcpStream,
    carrier: Arc<ForwardCarrier>,
    limits: Arc<DynamicLimits>,
) {
    // ADR-0019 decision 9: no slot -> close immediately, write nothing,
    // open nothing.
    let Ok(_handshake_permit) = Arc::clone(&limits.handshake_slots).try_acquire_owned() else {
        return;
    };

    let deadline = TokioInstant::now() + limits.handshake_deadline;
    let greeting = match read_greeting(&mut tcp, deadline).await {
        Ok(greeting) => greeting,
        Err(HandshakeGiveUp::NotSocks5) => {
            tracing::debug!("qsh::tunnel::dynamic: first byte was not SOCKS5; closing");
            // `read_greeting` only ever reads one byte before classifying
            // this — drain whatever else the client already sent so the
            // close below is an ordinary FIN, not an RST (`drain_pending`'s
            // own doc).
            drain_pending(&tcp);
            return;
        }
        Err(HandshakeGiveUp::DeadlineOrClosed) => {
            tracing::debug!("qsh::tunnel::dynamic: handshake deadline reached before a greeting");
            drain_pending(&tcp);
            return;
        }
    };

    let select = socks5::encode_method_select(&greeting);
    if tcp.write_all(&select).await.is_err() {
        return;
    }
    if select[1] != 0x00 {
        // No acceptable method (ADR-0019 decision 7: `05 FF`) — close, no
        // request is ever read.
        drain_pending(&tcp);
        return;
    }

    let outcome = match read_request(&mut tcp, deadline).await {
        Ok(outcome) => outcome,
        Err(()) => {
            tracing::debug!("qsh::tunnel::dynamic: handshake deadline reached before a request");
            drain_pending(&tcp);
            return;
        }
    };
    let request = match outcome {
        RequestOutcome::Rejected(rep) => {
            send_rep_and_close(tcp, rep).await;
            return;
        }
        RequestOutcome::Parsed(request) => request,
    };
    // Any bytes the client already wrote past the request (its first
    // pipelined payload segment) were never read into a driver buffer
    // (`read_request`'s own doc) — they are still sitting in `tcp`'s own
    // receive buffer, and `splice_opened` below will read and forward them
    // in its ordinary course, in order, once the tunnel is spliced.

    // The handshake proper is over; free the slot for the next connection
    // before doing anything that can wait (the connection cap, the rate
    // limit, the dial itself).
    drop(_handshake_permit);

    let Some(_connection_slot) = limits.reserve_connection_slot() else {
        send_rep_and_close(tcp, Rep::GeneralFailure).await;
        return;
    };

    if !limits.rate.acquire_before(deadline).await {
        send_rep_and_close(tcp, Rep::GeneralFailure).await;
        return;
    }

    // Structural only: host/port at debug, never above it (module doc,
    // ADR-0019 decision 12).
    tracing::debug!(
        host = %request.host,
        port = request.port,
        "qsh::tunnel::dynamic: CONNECT"
    );

    let policy = DialPolicy {
        deny_host_local: true,
    };
    match open_tunnel(&carrier, &request.host, request.port, policy).await {
        Ok(opened) => {
            if tcp
                .write_all(&socks5::encode_reply(Rep::Succeeded))
                .await
                .is_err()
            {
                return;
            }
            if let Err(err) = splice_opened(tcp, opened).await {
                tracing::debug!(%err, "qsh::tunnel::dynamic: spliced connection ended");
            }
        }
        Err(err) => {
            let rep = rep_for_forward_conn_error(&err);
            send_rep_and_close(tcp, rep).await;
        }
    }
}

#[cfg(test)]
mod tests;
