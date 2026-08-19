//! L4 network fault injection: an in-process UDP chaos proxy
//! (`docs/design/testing.md` L4, PLAN M2 Step 8).
//!
//! ```text
//! client (quinn Endpoint) ──▶ front socket ──▶ upstream socket ──▶ host
//!                          ◀──             ◀──
//! ```
//!
//! One tokio task owns the front socket and one upstream socket **per client
//! address** (a "flow"). The client dials [`ChaosProxy::addr`] instead of the
//! host; every datagram in either direction is run through a seeded
//! [`ChaosPolicy`] before it is relayed. Nothing about the host or the client
//! changes — this is the real QUIC stack on both ends, which is the whole
//! point: connection migration is a property of real path validation, so a
//! transport mock would only be testing the mock (`testing.md` L4, "대안 대비
//! 선택 근거").
//!
//! **Faults.** Per-datagram, seeded: [`ChaosPolicy::drop`],
//! [`ChaosPolicy::delay`], [`ChaosPolicy::reorder`],
//! [`ChaosPolicy::duplicate`], [`ChaosPolicy::corrupt`] (the AEAD positive
//! control — a corrupted packet must be *rejected* by QUIC, never handed to
//! the application). Live, out-of-band: [`ChaosProxy::blackhole`] +
//! [`ChaosProxy::recover`], [`ChaosProxy::repath`] (rebind the upstream
//! socket so the host sees a new peer address — what NAT rebinding and a
//! Wi-Fi→LTE switch look like from the host's side) and
//! [`ChaosProxy::sever`] (cut the path for good, forcing a re-dial).
//!
//! **Determinism.** All fault decisions come from a [`ChaosPolicy::seeded`]
//! PRNG threaded through the proxy task — never from wall-clock time or a
//! thread-local RNG. The decision *sequence* is therefore a pure function of
//! the seed and of the order datagrams arrive in; the OS decides the latter,
//! so a chaos test must assert an invariant ("byte-identical output"), not a
//! packet trace. Every failure message must print [`ChaosProxy::context`],
//! which carries the seed (`testing.md`, "CI 규율": chaos는 seeded, 실패 시
//! seed를 단언 메시지에 출력).
//!
//! **Counters are not self-certifying.** [`ChaosStats`] exists so a test can
//! say "the fault fired", but a counter incremented next to the effect it
//! witnesses proves nothing on its own. Two things keep it honest:
//! [`ChaosStats::is_balanced`] ties the fault counters to the counters bumped
//! at the actual `send_to` syscall (a fault that bumps without acting breaks
//! the identity), and `tests/chaos_relay.rs` observes each fault directly on
//! the wire, with no QUIC in the way.
//!
//! The only timers here are the injected delays themselves. Tests must stay
//! event- or deadline-driven; they must never `sleep()` to "let things
//! settle".

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// Receive buffer per direction. One QUIC datagram never approaches this,
/// but a generous bound keeps the proxy from ever being the reason a test
/// sees truncation.
pub const DATAGRAM_BUF: usize = 64 * 1024;

/// How long a datagram held back by [`ChaosPolicy::reorder`] waits for a
/// successor to jump ahead of it before it is released anyway. Bounds the
/// damage of reordering the *last* datagram of a burst.
pub const REORDER_HOLD: Duration = Duration::from_millis(10);

/// Cap on datagrams simultaneously waiting out a [`ChaosPolicy::delay`].
/// Far above anything a test produces; it exists so a pathological policy
/// grows a counted `undeliverable` instead of unbounded memory.
pub const MAX_PENDING: usize = 4_096;

/// The pass/fail bound for recovery after a [`ChaosProxy::sever`]: path
/// death detection → re-dial → resume must fit inside this.
/// `docs/design/testing.md` L4 fixes it: "idle timeout이 뒤늦게 터져서
/// 복구되는 것은 통과가 아니다 — path 사망 감지 후 **2초 내 재dial +
/// resume**".
///
/// **Where the real gate lives.** The client-side detector
/// (`qsh_core::client::pathwatch`) and the resume half both landed in M2
/// Step 7, and the criterion is enforced end to end by
/// `qsh-cli/tests/attach_recovery.rs`: it severs the path under a live
/// `Ops::session_attach` stream and asserts the driver's own
/// `qsh::recovery` record carries `time_to_recovery_ms <= 2000` — the clock
/// starts at path death, the test never closes or re-attaches the session
/// by hand, and the whole scenario is bounded far inside quinn's 45 s idle
/// timeout so "it eventually timed out" cannot pass. `tests/chaos_proxy.rs`
/// and `tests/resume_chaos.rs` use this constant to bound re-dials the
/// *test* initiates — the scenario, not the criterion.
pub const REDIAL_DEADLINE: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// seeded PRNG
// ---------------------------------------------------------------------------

/// SplitMix64. Deliberately hand-rolled rather than pulled from `rand`:
/// `StdRng`'s output is explicitly *not* stable across releases, and a chaos
/// seed that changes meaning on a dependency bump is not a seed.
#[derive(Debug, Clone)]
struct ChaosRng(u64);

impl ChaosRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        // 53 significant bits, the most an f64 can hold exactly.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// `true` with probability `p`. A disabled fault (`p <= 0`) draws
    /// nothing, so enabling one fault does not shift another's stream.
    fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        if p >= 1.0 {
            return true;
        }
        self.unit() < p
    }

    /// Uniform in `[0, n)`.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

/// How long a delayed datagram is held.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DelayDist {
    /// No added latency (the default).
    #[default]
    None,
    /// Always the same delay.
    Fixed(Duration),
    /// Uniform in `[min, max]` — jitter, which is what actually exercises
    /// ack/reordering logic.
    Uniform {
        /// Lower bound, inclusive.
        min: Duration,
        /// Upper bound, inclusive.
        max: Duration,
    },
}

impl DelayDist {
    /// A constant delay.
    pub fn fixed(d: Duration) -> Self {
        Self::Fixed(d)
    }

    /// Uniform jitter in `[min, max]`. `max` is clamped up to `min`.
    pub fn uniform(min: Duration, max: Duration) -> Self {
        Self::Uniform {
            min,
            max: max.max(min),
        }
    }

    fn draw(&self, rng: &mut ChaosRng) -> Duration {
        match *self {
            Self::None => Duration::ZERO,
            Self::Fixed(d) => d,
            Self::Uniform { min, max } => {
                let span = max.saturating_sub(min);
                min + Duration::from_nanos(rng.below(span.as_nanos() as u64 + 1))
            }
        }
    }
}

/// The seeded fault profile applied to every relayed datagram.
///
/// Built fluently from [`ChaosPolicy::seeded`]:
///
/// ```
/// use std::time::Duration;
/// use qsh_testkit::chaos::{ChaosPolicy, DelayDist};
///
/// let policy = ChaosPolicy::seeded(0xC0FFEE)
///     .drop(0.05)
///     .delay(DelayDist::uniform(Duration::ZERO, Duration::from_millis(3)))
///     .reorder(0.10)
///     .duplicate(0.05);
/// assert_eq!(policy.seed(), 0xC0FFEE);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ChaosPolicy {
    seed: u64,
    drop_p: f64,
    corrupt_p: f64,
    duplicate_p: f64,
    reorder_p: f64,
    delay: DelayDist,
}

impl ChaosPolicy {
    /// A fault-free policy with a fixed seed. Every fault is opt-in, so a
    /// bare `seeded(n)` proxy is a pure relay — useful as the control arm of
    /// a chaos test.
    pub fn seeded(seed: u64) -> Self {
        Self {
            seed,
            drop_p: 0.0,
            corrupt_p: 0.0,
            duplicate_p: 0.0,
            reorder_p: 0.0,
            delay: DelayDist::None,
        }
    }

    /// The seed. Print it in every failure message.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Drop a datagram with probability `p`.
    #[must_use]
    pub fn drop(mut self, p: f64) -> Self {
        self.drop_p = p;
        self
    }

    /// Delay every datagram by a draw from `dist`.
    #[must_use]
    pub fn delay(mut self, dist: DelayDist) -> Self {
        self.delay = dist;
        self
    }

    /// With probability `p`, hold a datagram back so the *next* one in the
    /// same direction overtakes it (see [`REORDER_HOLD`]).
    #[must_use]
    pub fn reorder(mut self, p: f64) -> Self {
        self.reorder_p = p;
        self
    }

    /// With probability `p`, relay a datagram twice.
    #[must_use]
    pub fn duplicate(mut self, p: f64) -> Self {
        self.duplicate_p = p;
        self
    }

    /// With probability `p`, flip a bit in the AEAD tag of a datagram's last
    /// QUIC packet before relaying it. **Positive control:** QUIC must
    /// reject that packet (it is indistinguishable from loss); a corrupted
    /// byte must never reach application data.
    #[must_use]
    pub fn corrupt(mut self, p: f64) -> Self {
        self.corrupt_p = p;
        self
    }
}

// ---------------------------------------------------------------------------
// counters
// ---------------------------------------------------------------------------

/// A snapshot of what the proxy has done so far.
///
/// The snapshot is taken at a quiescent point of the relay task (it is
/// published after each datagram is fully disposed of), so
/// [`is_balanced`](Self::is_balanced) is an exact identity and not a race.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChaosStats {
    /// Datagrams accepted from a client.
    pub from_client: u64,
    /// Datagrams accepted from the host.
    pub from_server: u64,
    /// Datagrams actually sent on to the host.
    pub to_server: u64,
    /// Datagrams actually sent on to a client.
    pub to_client: u64,
    /// Datagrams discarded by [`ChaosPolicy::drop`].
    pub dropped: u64,
    /// Datagrams refused before they were ever accepted, because their flow
    /// had been [`ChaosProxy::sever`]ed (either direction).
    pub refused: u64,
    /// Accepted datagrams that could not be handed to a socket: no live flow
    /// for that client, a `send_to` error, or [`MAX_PENDING`] overflow.
    pub undeliverable: u64,
    /// Datagrams whose AEAD tag was tampered with.
    pub corrupted: u64,
    /// Datagrams relayed twice (counted once per extra copy).
    pub duplicated: u64,
    /// Datagrams held back by [`ChaosPolicy::delay`].
    pub delayed: u64,
    /// Datagrams that were actually overtaken by a successor — the swap
    /// happened, not merely that one was parked.
    pub reordered: u64,
    /// Datagrams swallowed at egress while the path was blackholed.
    pub blackholed: u64,
    /// Datagrams still waiting out a delay or a reorder hold.
    pub inflight: u64,
    /// Completed [`ChaosProxy::repath`] calls.
    pub repaths: u64,
    /// Completed [`ChaosProxy::sever`] calls.
    pub severs: u64,
}

impl ChaosStats {
    /// The relay accounting identity: every accepted datagram is dropped,
    /// blackholed, undeliverable, still staged, or sent — with one extra
    /// send per duplicated datagram.
    ///
    /// This is what makes the fault counters worth asserting on. A fault
    /// that bumps its counter and then relays anyway (a refactor that
    /// short-circuits the pipeline, an inverted `if`) sends more datagrams
    /// than it accounts for, and this identity fails immediately.
    pub fn is_balanced(&self) -> bool {
        let sent = i128::from(self.to_server)
            + i128::from(self.to_client)
            + i128::from(self.undeliverable)
            + i128::from(self.inflight);
        let expected = i128::from(self.from_client) + i128::from(self.from_server)
            - i128::from(self.dropped)
            - i128::from(self.blackholed)
            + i128::from(self.duplicated);
        sent == expected
    }
}

// ---------------------------------------------------------------------------
// proxy handle
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Command {
    Repath(Option<SocketAddr>, oneshot::Sender<io::Result<SocketAddr>>),
    Sever(Option<SocketAddr>, oneshot::Sender<()>),
    Blackhole(Duration, oneshot::Sender<()>),
    Recover(oneshot::Sender<()>),
    Flows(oneshot::Sender<Vec<(SocketAddr, SocketAddr)>>),
    Blocked(oneshot::Sender<Vec<SocketAddr>>),
}

/// A running chaos proxy. Dial [`ChaosProxy::addr`]; the proxy relays to the
/// host it was started for. Dropping it stops the relay.
///
/// The proxy multiplexes any number of client addresses: each gets its own
/// upstream socket, so the host's replies come back to the client that
/// earned them. Two live connections through one proxy — which is what a
/// lease-steal or a re-dial-before-teardown test needs — are relayed
/// independently.
#[derive(Debug)]
pub struct ChaosProxy {
    addr: SocketAddr,
    server: SocketAddr,
    seed: u64,
    stats: Arc<Mutex<ChaosStats>>,
    cmd: mpsc::UnboundedSender<Command>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ChaosProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ChaosProxy {
    /// Bind a front socket on loopback (port 0) and start relaying to
    /// `server` under `policy`.
    pub async fn start(server: SocketAddr, policy: ChaosPolicy) -> io::Result<Self> {
        let front = Arc::new(UdpSocket::bind(loopback_wildcard(server)).await?);
        let addr = local_addr(&front, server)?;
        let stats = Arc::new(Mutex::new(ChaosStats::default()));
        let (tx, rx) = mpsc::unbounded_channel();
        let (up_tx, up_rx) = mpsc::unbounded_channel();
        let runner = Runner {
            front,
            server,
            flows: HashMap::new(),
            up_tx,
            blocked: HashSet::new(),
            policy,
            rng: ChaosRng::new(policy.seed),
            stats: ChaosStats::default(),
            shared: stats.clone(),
            pending: BinaryHeap::new(),
            held: HashMap::new(),
            blackhole_until: None,
            seq: 0,
        };
        let task = tokio::spawn(runner.run(rx, up_rx));
        Ok(Self {
            addr,
            server,
            seed: policy.seed,
            stats,
            cmd: tx,
            task,
        })
    }

    /// The address the client dials.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The host address the proxy relays to.
    pub fn server_addr(&self) -> SocketAddr {
        self.server
    }

    /// The policy seed. Reproduce a failure with `ChaosPolicy::seeded(seed)`.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// What the proxy has done so far.
    pub fn stats(&self) -> ChaosStats {
        *self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The one-line context every chaos assertion message must carry. It is
    /// **immutable** — seed and addresses only — so a test may bind it once
    /// and interpolate it anywhere without printing stale counters. For the
    /// counters use [`detail`](Self::detail), which reads them fresh.
    pub fn context(&self) -> String {
        format!(
            "chaos seed={:#x} front={} host={}",
            self.seed, self.addr, self.server
        )
    }

    /// [`context`](Self::context) plus a fresh [`ChaosStats`]. Call it *at*
    /// the assertion, never before the traffic it describes.
    pub fn detail(&self) -> String {
        format!("{} stats={:?}", self.context(), self.stats())
    }

    /// Every live flow as `(client address, upstream address)`, in no
    /// particular order.
    pub async fn flows(&self) -> Vec<(SocketAddr, SocketAddr)> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Flows(tx)).is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Every client address [`sever`](Self::sever) has blacklisted, in no
    /// particular order.
    pub async fn severed_clients(&self) -> Vec<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Blocked(tx)).is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// The proxy's current *upstream* address — the peer address the host
    /// sees — when there is exactly one live flow. `None` after a
    /// [`sever`](Self::sever) and before the next dial, and `None` when
    /// several clients are live (ask [`flows`](Self::flows) instead).
    pub async fn upstream_addr(&self) -> Option<SocketAddr> {
        let flows = self.flows().await;
        match flows.as_slice() {
            [(_, up)] => Some(*up),
            _ => None,
        }
    }

    /// Rebind the sole flow's upstream socket to a fresh port: the host
    /// suddenly sees the same QUIC connection arriving from a new peer
    /// address, exactly as a NAT rebinding or a Wi-Fi→LTE switch looks to
    /// it. Returns the new upstream address. The client is not told and does
    /// not care — that is the point.
    ///
    /// Fails if there is not exactly one live flow; use
    /// [`repath_client`](Self::repath_client) then.
    pub async fn repath(&self) -> io::Result<SocketAddr> {
        self.repath_inner(None).await
    }

    /// [`repath`](Self::repath) for one named client flow.
    pub async fn repath_client(&self, client: SocketAddr) -> io::Result<SocketAddr> {
        self.repath_inner(Some(client)).await
    }

    async fn repath_inner(&self, client: Option<SocketAddr>) -> io::Result<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::Repath(client, tx))
            .map_err(|_| io::Error::other("chaos proxy is gone"))?;
        rx.await
            .map_err(|_| io::Error::other("chaos proxy is gone"))?
    }

    /// Cut every live path for good: close the upstream sockets and
    /// blacklist the client addresses, so the in-flight connections can
    /// never be recovered by any amount of retransmission. The front address
    /// stays bound, so a **re-dial** (a fresh client endpoint, hence a fresh
    /// source port) is relayed normally onto a brand-new host connection.
    /// This is the harness half of the "재dial + resume" recovery path; the
    /// client re-dial loop itself is PLAN M2 Step 7.
    ///
    /// There is deliberately no `unsever`. The blacklist is keyed by socket
    /// address and never expires, so in the (rare) event that the OS hands a
    /// later `Endpoint` the severed ephemeral port, that dial is blackholed
    /// too and surfaces as a dial timeout. A test that re-dials in a loop
    /// should assert the new source address is not in
    /// [`severed_clients`](Self::severed_clients).
    pub async fn sever(&self) {
        self.sever_inner(None).await;
    }

    /// [`sever`](Self::sever) for one named client flow, leaving the others
    /// live.
    pub async fn sever_client(&self, client: SocketAddr) {
        self.sever_inner(Some(client)).await;
    }

    async fn sever_inner(&self, client: Option<SocketAddr>) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Sever(client, tx)).is_ok() {
            let _ = rx.await;
        }
    }

    /// Swallow every datagram, both ways, for `dur` — then relay again. The
    /// path is not torn down: the connection is expected to ride it out on
    /// PTO/keep-alive. The check is at egress, so datagrams already staged
    /// by [`ChaosPolicy::delay`] or [`ChaosPolicy::reorder`] are swallowed
    /// too.
    pub async fn blackhole(&self, dur: Duration) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Blackhole(dur, tx)).is_ok() {
            let _ = rx.await;
        }
    }

    /// End a [`blackhole`](Self::blackhole) early.
    pub async fn recover(&self) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Recover(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

fn loopback_wildcard(peer: SocketAddr) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(_) => (Ipv4Addr::LOCALHOST, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::LOCALHOST, 0).into(),
    }
}

fn local_addr(sock: &UdpSocket, peer: SocketAddr) -> io::Result<SocketAddr> {
    let mut addr = sock.local_addr()?;
    // Bound to a loopback literal, so this is already the reachable address;
    // normalise the (impossible here, but cheap to guard) wildcard case.
    if addr.ip().is_unspecified() {
        addr.set_ip(loopback_wildcard(peer).ip());
    }
    Ok(addr)
}

// ---------------------------------------------------------------------------
// the relay task
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Dir {
    ToServer,
    ToClient,
}

/// A datagram waiting out its injected delay.
#[derive(Debug)]
struct Scheduled {
    at: Instant,
    seq: u64,
    client: SocketAddr,
    dir: Dir,
    data: Vec<u8>,
}

impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.seq == other.seq
    }
}
impl Eq for Scheduled {}
impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> Ordering {
        self.at.cmp(&other.at).then(self.seq.cmp(&other.seq))
    }
}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A datagram held back so its successor can overtake it.
#[derive(Debug)]
struct Held {
    data: Vec<u8>,
    until: Instant,
}

/// One client's relay path: the upstream socket the host sees, plus the task
/// draining it.
#[derive(Debug)]
struct Flow {
    up: Arc<UdpSocket>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A datagram the host sent, tagged with the flow it arrived on.
#[derive(Debug)]
struct Inbound {
    client: SocketAddr,
    peer: SocketAddr,
    data: Vec<u8>,
}

/// Consecutive `recv_from` errors a flow tolerates before giving up. On
/// Windows a UDP socket reports ICMP port-unreachable as `WSAECONNRESET` on
/// the *next* receive, which is transient and must not kill the flow; a
/// permanently broken socket must not spin either.
const FLOW_ERROR_BUDGET: u32 = 64;

fn spawn_flow(
    client: SocketAddr,
    sock: Arc<UdpSocket>,
    tx: mpsc::UnboundedSender<Inbound>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; DATAGRAM_BUF];
        let mut errors = 0u32;
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    errors = 0;
                    let inbound = Inbound {
                        client,
                        peer,
                        data: buf[..n].to_vec(),
                    };
                    if tx.send(inbound).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    errors += 1;
                    if errors >= FLOW_ERROR_BUDGET {
                        break;
                    }
                }
            }
        }
    })
}

struct Runner {
    front: Arc<UdpSocket>,
    server: SocketAddr,
    flows: HashMap<SocketAddr, Flow>,
    up_tx: mpsc::UnboundedSender<Inbound>,
    blocked: HashSet<SocketAddr>,
    policy: ChaosPolicy,
    rng: ChaosRng,
    stats: ChaosStats,
    shared: Arc<Mutex<ChaosStats>>,
    pending: BinaryHeap<Reverse<Scheduled>>,
    held: HashMap<(SocketAddr, Dir), Held>,
    blackhole_until: Option<Instant>,
    seq: u64,
}

impl Runner {
    async fn run(
        mut self,
        mut cmds: mpsc::UnboundedReceiver<Command>,
        mut up_rx: mpsc::UnboundedReceiver<Inbound>,
    ) {
        let mut from_client = vec![0u8; DATAGRAM_BUF];
        loop {
            let front = self.front.clone();
            let deadline = self.next_deadline();
            // Deliberately not `biased`: a biased select would poll the
            // front socket before the upstream one every time, so a chatty
            // client could starve the host→client direction. Command
            // ordering does not need bias — every mutator awaits its own
            // reply, so `sever().await` returning still means the command
            // has been applied.
            tokio::select! {
                cmd = cmds.recv() => {
                    match cmd {
                        Some(cmd) => self.command(cmd).await,
                        // Every handle is gone; nothing can observe us.
                        None => break,
                    }
                }
                () = sleep_until(deadline) => self.on_timer().await,
                res = front.recv_from(&mut from_client) => {
                    if let Ok((n, peer)) = res {
                        self.on_client(peer, &from_client[..n]).await;
                    }
                }
                inbound = up_rx.recv() => {
                    if let Some(inbound) = inbound {
                        self.on_server(inbound).await;
                    }
                }
            }
            self.publish();
        }
    }

    /// Publish a coherent snapshot. Called only between datagrams, so a
    /// reader never sees a half-disposed one and
    /// [`ChaosStats::is_balanced`] is exact.
    fn publish(&mut self) {
        self.stats.inflight = (self.pending.len() + self.held.len()) as u64;
        *self.shared.lock().unwrap_or_else(|e| e.into_inner()) = self.stats;
    }

    fn next_deadline(&self) -> Option<Instant> {
        let mut next = self.pending.peek().map(|Reverse(s)| s.at);
        for h in self.held.values() {
            next = Some(next.map_or(h.until, |n| n.min(h.until)));
        }
        if let Some(until) = self.blackhole_until {
            next = Some(next.map_or(until, |n| n.min(until)));
        }
        next
    }

    /// Resolve a command's optional client argument to a live flow.
    fn resolve(&self, client: Option<SocketAddr>) -> Option<SocketAddr> {
        match client {
            Some(c) => self.flows.contains_key(&c).then_some(c),
            None => match self.flows.keys().collect::<Vec<_>>().as_slice() {
                [only] => Some(**only),
                _ => None,
            },
        }
    }

    async fn command(&mut self, cmd: Command) {
        match cmd {
            Command::Repath(client, reply) => {
                let result = match self.resolve(client) {
                    None => Err(io::Error::other(
                        "repath needs exactly one live flow (or a client address)",
                    )),
                    Some(client) => match UdpSocket::bind(loopback_wildcard(self.server)).await {
                        Err(err) => Err(err),
                        Ok(sock) => {
                            let sock = Arc::new(sock);
                            let addr = local_addr(&sock, self.server);
                            let task = spawn_flow(client, sock.clone(), self.up_tx.clone());
                            // Replacing the flow drops the old socket and
                            // aborts its task: the host *must* migrate, it
                            // cannot keep using the old path.
                            self.flows.insert(client, Flow { up: sock, task });
                            self.stats.repaths += 1;
                            addr
                        }
                    },
                };
                let _ = reply.send(result);
            }
            Command::Sever(client, reply) => {
                let targets: Vec<SocketAddr> = match client {
                    Some(c) => vec![c],
                    None => self.flows.keys().copied().collect(),
                };
                for client in targets {
                    self.blocked.insert(client);
                    self.flows.remove(&client);
                    // Datagrams already staged for this flow (waiting out a
                    // delay or parked for a reorder) were counted on
                    // arrival and can never be sent now. Count them as
                    // undeliverable, or `inflight` would simply shrink and
                    // `ChaosStats::is_balanced` — the identity that keeps
                    // every other counter honest — would go false after a
                    // sever.
                    let before = self.pending.len() + self.held.len();
                    self.pending = self
                        .pending
                        .drain()
                        .filter(|Reverse(s)| s.client != client)
                        .collect();
                    self.held.retain(|(c, _), _| *c != client);
                    let purged = before - (self.pending.len() + self.held.len());
                    self.stats.undeliverable += purged as u64;
                }
                self.stats.severs += 1;
                let _ = reply.send(());
            }
            Command::Blackhole(dur, reply) => {
                self.blackhole_until = Some(Instant::now() + dur);
                let _ = reply.send(());
            }
            Command::Recover(reply) => {
                self.blackhole_until = None;
                let _ = reply.send(());
            }
            Command::Flows(reply) => {
                let flows = self
                    .flows
                    .iter()
                    .filter_map(|(client, flow)| {
                        local_addr(&flow.up, self.server)
                            .ok()
                            .map(|up| (*client, up))
                    })
                    .collect();
                let _ = reply.send(flows);
            }
            Command::Blocked(reply) => {
                let _ = reply.send(self.blocked.iter().copied().collect());
            }
        }
    }

    async fn on_timer(&mut self) {
        let now = Instant::now();
        while let Some(Reverse(next)) = self.pending.peek() {
            if next.at > now {
                break;
            }
            let Some(Reverse(item)) = self.pending.pop() else {
                break;
            };
            self.send(item.client, item.dir, &item.data).await;
        }
        // A hold that expires without a successor was never overtaken, so it
        // is released unchanged and `reordered` is not bumped.
        let expired: Vec<(SocketAddr, Dir)> = self
            .held
            .iter()
            .filter(|(_, h)| h.until <= now)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            if let Some(h) = self.held.remove(&key) {
                self.send(key.0, key.1, &h.data).await;
            }
        }
        if matches!(self.blackhole_until, Some(until) if until <= now) {
            self.blackhole_until = None;
        }
    }

    async fn on_client(&mut self, peer: SocketAddr, data: &[u8]) {
        if self.blocked.contains(&peer) {
            // Severed path: this client no longer exists as far as the host
            // is concerned. A re-dial arrives from a different source port.
            self.stats.refused += 1;
            return;
        }
        if !self.flows.contains_key(&peer) {
            let Ok(sock) = UdpSocket::bind(loopback_wildcard(self.server)).await else {
                // Never accepted, so nothing to account for.
                return;
            };
            let sock = Arc::new(sock);
            let task = spawn_flow(peer, sock.clone(), self.up_tx.clone());
            self.flows.insert(peer, Flow { up: sock, task });
        }
        self.stats.from_client += 1;
        self.inject(peer, Dir::ToServer, data).await;
    }

    async fn on_server(&mut self, inbound: Inbound) {
        if inbound.peer != self.server {
            return;
        }
        if !self.flows.contains_key(&inbound.client) {
            // The flow was severed (or repathed) while this datagram was in
            // the channel: it has nowhere to go.
            self.stats.refused += 1;
            return;
        }
        self.stats.from_server += 1;
        self.inject(inbound.client, Dir::ToClient, &inbound.data)
            .await;
    }

    /// The fault pipeline: drop → corrupt → duplicate → reorder → delay.
    /// (Blackholing is at egress, in [`Runner::send`], so datagrams already
    /// staged when the blackhole opens are swallowed too.)
    async fn inject(&mut self, client: SocketAddr, dir: Dir, data: &[u8]) {
        if self.rng.chance(self.policy.drop_p) {
            self.stats.dropped += 1;
            return;
        }
        let mut buf = data.to_vec();
        if self.rng.chance(self.policy.corrupt_p) {
            corrupt(&mut buf, &mut self.rng);
            self.stats.corrupted += 1;
        }
        if self.rng.chance(self.policy.duplicate_p) {
            self.stats.duplicated += 1;
            // The extra copy skips the reorder stage: two byte-identical
            // copies swapping places is not an observable reordering, and
            // counting it as one would make `reordered` a lie.
            self.schedule(client, dir, buf.clone()).await;
        }
        self.stage(client, dir, buf).await;
    }

    /// Reorder stage. A held datagram is released *after* the one that
    /// overtook it, and both bypass the delay stage so that the swap is
    /// guaranteed rather than probabilistic.
    async fn stage(&mut self, client: SocketAddr, dir: Dir, data: Vec<u8>) {
        if let Some(held) = self.held.remove(&(client, dir)) {
            self.stats.reordered += 1;
            self.send(client, dir, &data).await;
            self.send(client, dir, &held.data).await;
            return;
        }
        if self.rng.chance(self.policy.reorder_p) {
            self.held.insert(
                (client, dir),
                Held {
                    data,
                    until: Instant::now() + REORDER_HOLD,
                },
            );
            return;
        }
        self.schedule(client, dir, data).await;
    }

    async fn schedule(&mut self, client: SocketAddr, dir: Dir, data: Vec<u8>) {
        let delay = self.policy.delay.draw(&mut self.rng);
        if delay.is_zero() {
            self.send(client, dir, &data).await;
            return;
        }
        if self.pending.len() >= MAX_PENDING {
            self.stats.undeliverable += 1;
            return;
        }
        self.stats.delayed += 1;
        self.seq += 1;
        self.pending.push(Reverse(Scheduled {
            at: Instant::now() + delay,
            seq: self.seq,
            client,
            dir,
            data,
        }));
    }

    async fn send(&mut self, client: SocketAddr, dir: Dir, data: &[u8]) {
        if let Some(until) = self.blackhole_until {
            if Instant::now() < until {
                self.stats.blackholed += 1;
                return;
            }
            self.blackhole_until = None;
        }
        let sent = match dir {
            Dir::ToServer => match self.flows.get(&client) {
                Some(flow) => flow.up.send_to(data, self.server).await.is_ok(),
                None => false,
            },
            Dir::ToClient => self.front.send_to(data, client).await.is_ok(),
        };
        match (sent, dir) {
            (true, Dir::ToServer) => self.stats.to_server += 1,
            (true, Dir::ToClient) => self.stats.to_client += 1,
            (false, _) => self.stats.undeliverable += 1,
        }
    }
}

/// Flip one bit inside the AEAD tag of the datagram's **last** QUIC packet
/// (its last 16 bytes). Targeting the tag rather than the header means the
/// packet is well-formed all the way to *authentication* and is then
/// rejected there — which is the property under test.
///
/// Note the "last packet" precision: a datagram may coalesce several QUIC
/// packets (an Initial + a Handshake, typically), and the earlier ones stay
/// intact and are still processed. That is enough for the control — the
/// tampered packet is never authenticated — but it is not "the whole
/// datagram is discarded". Short datagrams (there are none in QUIC after the
/// handshake) fall back to any byte.
fn corrupt(buf: &mut [u8], rng: &mut ChaosRng) {
    if buf.is_empty() {
        return;
    }
    const TAG: usize = 16;
    let start = buf.len().saturating_sub(TAG);
    let idx = start + rng.below((buf.len() - start) as u64) as usize;
    let bit = rng.below(8) as u32;
    buf[idx] ^= 1u8 << bit;
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prng_is_reproducible_and_independent_of_wall_clock() {
        let mut r1 = ChaosRng::new(0xDEAD_BEEF);
        let mut r2 = ChaosRng::new(0xDEAD_BEEF);
        let s1: Vec<u64> = (0..64).map(|_| r1.next_u64()).collect();
        let s2: Vec<u64> = (0..64).map(|_| r2.next_u64()).collect();
        assert_eq!(s1, s2, "same seed, same stream");
        assert!(s1.windows(2).all(|w| w[0] != w[1]), "not a constant");
    }

    #[test]
    fn disabled_faults_do_not_consume_the_stream() {
        let mut rng = ChaosRng::new(1);
        // p == 0 draws nothing: the next real draw is the same as if the
        // disabled fault were not in the pipeline at all.
        assert!(!rng.chance(0.0));
        assert!(!rng.chance(-1.0));
        let after_zero = rng.next_u64();
        let mut fresh = ChaosRng::new(1);
        assert_eq!(after_zero, fresh.next_u64());
        assert!(fresh.chance(1.0), "p >= 1 is unconditional");
    }

    #[test]
    fn chance_tracks_the_requested_probability() {
        let mut rng = ChaosRng::new(0x5EED);
        let hits = (0..10_000).filter(|_| rng.chance(0.25)).count();
        assert!((2_200..2_800).contains(&hits), "{hits} of 10000 at p=0.25");
    }

    #[test]
    fn delay_draws_stay_inside_the_distribution() {
        let mut rng = ChaosRng::new(9);
        let dist = DelayDist::uniform(Duration::from_millis(1), Duration::from_millis(5));
        for _ in 0..1_000 {
            let d = dist.draw(&mut rng);
            assert!(
                d >= Duration::from_millis(1) && d <= Duration::from_millis(5),
                "{d:?}"
            );
        }
        assert_eq!(
            DelayDist::fixed(Duration::from_millis(2)).draw(&mut rng),
            Duration::from_millis(2)
        );
        assert!(DelayDist::None.draw(&mut rng).is_zero());
        // A backwards range is clamped, not a panic.
        let flipped = DelayDist::uniform(Duration::from_millis(5), Duration::from_millis(1));
        assert_eq!(flipped.draw(&mut rng), Duration::from_millis(5));
    }

    #[test]
    fn corruption_lands_in_the_aead_tag_and_changes_exactly_one_bit() {
        let mut rng = ChaosRng::new(42);
        for _ in 0..200 {
            let original = vec![0xA5u8; 1200];
            let mut tampered = original.clone();
            corrupt(&mut tampered, &mut rng);
            let differing: Vec<usize> = (0..original.len())
                .filter(|i| original[*i] != tampered[*i])
                .collect();
            assert_eq!(differing.len(), 1);
            assert!(
                differing[0] >= original.len() - 16,
                "corruption must hit the tag, hit {}",
                differing[0]
            );
            assert_eq!(
                (original[differing[0]] ^ tampered[differing[0]]).count_ones(),
                1
            );
        }
        // Degenerate inputs do not panic.
        corrupt(&mut [], &mut rng);
        let mut tiny = [7u8];
        corrupt(&mut tiny, &mut rng);
        assert_ne!(tiny[0], 7);
    }

    #[test]
    fn scheduled_datagrams_order_by_time_then_arrival() {
        let base = Instant::now();
        let client: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        let mk = |ms: u64, seq: u64| Scheduled {
            at: base + Duration::from_millis(ms),
            seq,
            client,
            dir: Dir::ToServer,
            data: vec![],
        };
        let mut heap = BinaryHeap::new();
        heap.push(Reverse(mk(10, 1)));
        heap.push(Reverse(mk(5, 2)));
        heap.push(Reverse(mk(5, 3)));
        let order: Vec<u64> = std::iter::from_fn(|| heap.pop().map(|Reverse(s)| s.seq)).collect();
        assert_eq!(order, vec![2, 3, 1]);
    }

    #[test]
    fn the_accounting_identity_catches_a_fault_that_only_bumps_its_counter() {
        // Ten datagrams in, two dropped, one duplicated, one blackholed:
        // seven sends plus the extra copy.
        let honest = ChaosStats {
            from_client: 10,
            to_server: 8,
            dropped: 2,
            duplicated: 1,
            blackholed: 1,
            ..Default::default()
        };
        assert!(honest.is_balanced(), "{honest:?}");
        // A `drop` that bumps the counter and relays anyway.
        let liar = ChaosStats {
            to_server: 10,
            ..honest
        };
        assert!(!liar.is_balanced(), "{liar:?}");
        // A staged datagram is accounted for while it waits.
        let staged = ChaosStats {
            to_server: 6,
            inflight: 2,
            ..honest
        };
        assert!(staged.is_balanced(), "{staged:?}");
    }
}
