//! L4 network fault injection: an in-process UDP chaos proxy
//! (`docs/design/testing.md` L4, PLAN M2 Step 8).
//!
//! ```text
//! client (quinn Endpoint) ──▶ front socket ──▶ upstream socket ──▶ host
//!                          ◀──             ◀──
//! ```
//!
//! One tokio task owns both sockets. The client dials [`ChaosProxy::addr`]
//! instead of the host; every datagram in either direction is run through a
//! seeded [`ChaosPolicy`] before it is relayed. Nothing about the host or the
//! client changes — this is the real QUIC stack on both ends, which is the
//! whole point: connection migration is a property of real path validation,
//! so a transport mock would only be testing the mock (`testing.md` L4,
//! "대안 대비 선택 근거").
//!
//! **Faults.** Per-datagram, seeded: [`ChaosPolicy::drop`],
//! [`ChaosPolicy::delay`], [`ChaosPolicy::reorder`],
//! [`ChaosPolicy::duplicate`], [`ChaosPolicy::corrupt`] (the AEAD positive
//! control — a corrupted datagram must be *rejected* by QUIC, never handed to
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
//! The only timers here are the injected delays themselves. Tests must stay
//! event- or deadline-driven; they must never `sleep()` to "let things
//! settle".

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
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

/// The pass/fail bound for recovery after a [`ChaosProxy::sever`]: path
/// death → re-dial (+ resume, once PLAN M2 Step 7 lands) must complete
/// inside this. `docs/design/testing.md` L4 fixes it: "idle timeout이 뒤늦게
/// 터져서 복구되는 것은 통과가 아니다 — path 사망 감지 후 **2초 내 재dial +
/// resume**". It lives here, as a constant used by assertions, so that the
/// criterion is code and not a comment.
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

    /// With probability `p`, flip a bit in a datagram's AEAD tag before
    /// relaying it. **Positive control:** QUIC must reject the datagram
    /// (it is indistinguishable from loss); a corrupted byte must never
    /// reach application data.
    #[must_use]
    pub fn corrupt(mut self, p: f64) -> Self {
        self.corrupt_p = p;
        self
    }
}

// ---------------------------------------------------------------------------
// counters
// ---------------------------------------------------------------------------

/// A snapshot of what the proxy has done so far. Chaos tests assert on these
/// so that a fault which silently failed to fire cannot make a test vacuous.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChaosStats {
    /// Datagrams received from the client.
    pub from_client: u64,
    /// Datagrams received from the host.
    pub from_server: u64,
    /// Datagrams actually sent on to the host.
    pub to_server: u64,
    /// Datagrams actually sent on to the client.
    pub to_client: u64,
    /// Datagrams discarded by [`ChaosPolicy::drop`], or because the sender
    /// had been [`ChaosProxy::sever`]ed.
    pub dropped: u64,
    /// Datagrams whose AEAD tag was tampered with.
    pub corrupted: u64,
    /// Datagrams relayed twice.
    pub duplicated: u64,
    /// Datagrams held back by [`ChaosPolicy::delay`].
    pub delayed: u64,
    /// Datagrams overtaken by their successor.
    pub reordered: u64,
    /// Datagrams swallowed while the path was blackholed.
    pub blackholed: u64,
    /// Completed [`ChaosProxy::repath`] calls.
    pub repaths: u64,
    /// Completed [`ChaosProxy::sever`] calls.
    pub severs: u64,
}

#[derive(Debug, Default)]
struct Counters {
    from_client: AtomicU64,
    from_server: AtomicU64,
    to_server: AtomicU64,
    to_client: AtomicU64,
    dropped: AtomicU64,
    corrupted: AtomicU64,
    duplicated: AtomicU64,
    delayed: AtomicU64,
    reordered: AtomicU64,
    blackholed: AtomicU64,
    repaths: AtomicU64,
    severs: AtomicU64,
}

impl Counters {
    fn bump(field: &AtomicU64) {
        field.fetch_add(1, AtomicOrdering::Relaxed);
    }

    fn snapshot(&self) -> ChaosStats {
        let get = |f: &AtomicU64| f.load(AtomicOrdering::Relaxed);
        ChaosStats {
            from_client: get(&self.from_client),
            from_server: get(&self.from_server),
            to_server: get(&self.to_server),
            to_client: get(&self.to_client),
            dropped: get(&self.dropped),
            corrupted: get(&self.corrupted),
            duplicated: get(&self.duplicated),
            delayed: get(&self.delayed),
            reordered: get(&self.reordered),
            blackholed: get(&self.blackholed),
            repaths: get(&self.repaths),
            severs: get(&self.severs),
        }
    }
}

// ---------------------------------------------------------------------------
// proxy handle
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Command {
    Repath(oneshot::Sender<io::Result<SocketAddr>>),
    Sever(oneshot::Sender<()>),
    Blackhole(Duration, oneshot::Sender<()>),
    Recover(oneshot::Sender<()>),
    Upstream(oneshot::Sender<Option<SocketAddr>>),
}

/// A running chaos proxy. Dial [`ChaosProxy::addr`]; the proxy relays to the
/// host it was started for. Dropping it stops the relay.
#[derive(Debug)]
pub struct ChaosProxy {
    addr: SocketAddr,
    server: SocketAddr,
    seed: u64,
    counters: Arc<Counters>,
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
        let counters = Arc::new(Counters::default());
        let (tx, rx) = mpsc::unbounded_channel();
        let runner = Runner {
            front,
            server,
            up: None,
            client: None,
            blocked: HashSet::new(),
            policy,
            rng: ChaosRng::new(policy.seed),
            counters: counters.clone(),
            pending: BinaryHeap::new(),
            held: [None, None],
            blackhole_until: None,
            seq: 0,
        };
        let task = tokio::spawn(runner.run(rx));
        Ok(Self {
            addr,
            server,
            seed: policy.seed,
            counters,
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
        self.counters.snapshot()
    }

    /// The one-line context every chaos assertion message must carry.
    pub fn context(&self) -> String {
        format!(
            "chaos seed={:#x} front={} host={} stats={:?}",
            self.seed,
            self.addr,
            self.server,
            self.stats()
        )
    }

    /// The proxy's current *upstream* address — the peer address the host
    /// sees. `None` after a [`sever`](Self::sever) and before the next dial.
    pub async fn upstream_addr(&self) -> Option<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Command::Upstream(tx)).ok()?;
        rx.await.ok().flatten()
    }

    /// Rebind the upstream socket to a fresh port: the host suddenly sees
    /// the same QUIC connection arriving from a new peer address, exactly as
    /// a NAT rebinding or a Wi-Fi→LTE switch looks to it. Returns the new
    /// upstream address. The client is not told and does not care — that is
    /// the point.
    pub async fn repath(&self) -> io::Result<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::Repath(tx))
            .map_err(|_| io::Error::other("chaos proxy is gone"))?;
        rx.await
            .map_err(|_| io::Error::other("chaos proxy is gone"))?
    }

    /// Cut the path for good: close the upstream socket and blacklist the
    /// current client address, so the in-flight connection can never be
    /// recovered by any amount of retransmission. The front address stays
    /// bound, so a **re-dial** (a fresh client endpoint, hence a fresh source
    /// port) is relayed normally onto a brand-new host connection. This is
    /// the harness half of the "재dial + resume" recovery path; the client
    /// re-dial loop itself is PLAN M2 Step 7.
    pub async fn sever(&self) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Sever(tx)).is_ok() {
            let _ = rx.await;
        }
    }

    /// Swallow every datagram, both ways, for `dur` — then relay again. The
    /// path is not torn down: the connection is expected to ride it out on
    /// PTO/keep-alive.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    ToServer,
    ToClient,
}

impl Dir {
    fn idx(self) -> usize {
        match self {
            Self::ToServer => 0,
            Self::ToClient => 1,
        }
    }
}

/// A datagram waiting out its injected delay.
#[derive(Debug)]
struct Scheduled {
    at: Instant,
    seq: u64,
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

struct Runner {
    front: Arc<UdpSocket>,
    server: SocketAddr,
    up: Option<Arc<UdpSocket>>,
    client: Option<SocketAddr>,
    blocked: HashSet<SocketAddr>,
    policy: ChaosPolicy,
    rng: ChaosRng,
    counters: Arc<Counters>,
    pending: BinaryHeap<Reverse<Scheduled>>,
    held: [Option<Held>; 2],
    blackhole_until: Option<Instant>,
    seq: u64,
}

impl Runner {
    async fn run(mut self, mut cmds: mpsc::UnboundedReceiver<Command>) {
        let mut from_client = vec![0u8; DATAGRAM_BUF];
        let mut from_server = vec![0u8; DATAGRAM_BUF];
        loop {
            let front = self.front.clone();
            let up = self.up.clone();
            let deadline = self.next_deadline();
            tokio::select! {
                biased;
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
                res = recv_from(up.as_deref(), &mut from_server) => {
                    if let Some(Ok((n, peer))) = res {
                        self.on_server(peer, &from_server[..n]).await;
                    }
                }
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        let mut next = self.pending.peek().map(|Reverse(s)| s.at);
        for h in self.held.iter().flatten() {
            next = Some(next.map_or(h.until, |n| n.min(h.until)));
        }
        if let Some(until) = self.blackhole_until {
            next = Some(next.map_or(until, |n| n.min(until)));
        }
        next
    }

    async fn command(&mut self, cmd: Command) {
        match cmd {
            Command::Repath(reply) => {
                let bound = UdpSocket::bind(loopback_wildcard(self.server)).await;
                let result = match bound {
                    Ok(sock) => {
                        let addr = local_addr(&sock, self.server);
                        // The old socket is closed here: the host *must*
                        // migrate, it cannot keep using the old path.
                        self.up = Some(Arc::new(sock));
                        Counters::bump(&self.counters.repaths);
                        addr
                    }
                    Err(err) => Err(err),
                };
                let _ = reply.send(result);
            }
            Command::Sever(reply) => {
                if let Some(client) = self.client.take() {
                    self.blocked.insert(client);
                }
                self.up = None;
                self.pending.clear();
                self.held = [None, None];
                Counters::bump(&self.counters.severs);
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
            Command::Upstream(reply) => {
                let addr = self
                    .up
                    .as_ref()
                    .and_then(|s| local_addr(s, self.server).ok());
                let _ = reply.send(addr);
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
            self.send(item.dir, &item.data).await;
        }
        for dir in [Dir::ToServer, Dir::ToClient] {
            let expired = matches!(&self.held[dir.idx()], Some(h) if h.until <= now);
            if expired && let Some(h) = self.held[dir.idx()].take() {
                self.send(dir, &h.data).await;
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
            Counters::bump(&self.counters.dropped);
            return;
        }
        if self.client != Some(peer) {
            self.client = Some(peer);
        }
        if self.up.is_none() {
            match UdpSocket::bind(loopback_wildcard(self.server)).await {
                Ok(sock) => self.up = Some(Arc::new(sock)),
                Err(_) => return,
            }
        }
        Counters::bump(&self.counters.from_client);
        self.inject(Dir::ToServer, data).await;
    }

    async fn on_server(&mut self, peer: SocketAddr, data: &[u8]) {
        if peer != self.server {
            return;
        }
        Counters::bump(&self.counters.from_server);
        self.inject(Dir::ToClient, data).await;
    }

    /// The fault pipeline: blackhole → drop → corrupt → duplicate → reorder
    /// → delay.
    async fn inject(&mut self, dir: Dir, data: &[u8]) {
        if let Some(until) = self.blackhole_until {
            if Instant::now() < until {
                Counters::bump(&self.counters.blackholed);
                return;
            }
            self.blackhole_until = None;
        }
        if self.rng.chance(self.policy.drop_p) {
            Counters::bump(&self.counters.dropped);
            return;
        }
        let mut buf = data.to_vec();
        if self.rng.chance(self.policy.corrupt_p) {
            corrupt(&mut buf, &mut self.rng);
            Counters::bump(&self.counters.corrupted);
        }
        let twice = self.rng.chance(self.policy.duplicate_p);
        if twice {
            Counters::bump(&self.counters.duplicated);
            self.stage(dir, buf.clone()).await;
        }
        self.stage(dir, buf).await;
    }

    /// Reorder stage. A held datagram is released *after* the one that
    /// overtook it, and both bypass the delay stage so that the swap is
    /// guaranteed rather than probabilistic.
    async fn stage(&mut self, dir: Dir, data: Vec<u8>) {
        if let Some(held) = self.held[dir.idx()].take() {
            self.send(dir, &data).await;
            self.send(dir, &held.data).await;
            return;
        }
        if self.rng.chance(self.policy.reorder_p) {
            Counters::bump(&self.counters.reordered);
            self.held[dir.idx()] = Some(Held {
                data,
                until: Instant::now() + REORDER_HOLD,
            });
            return;
        }
        self.schedule(dir, data).await;
    }

    async fn schedule(&mut self, dir: Dir, data: Vec<u8>) {
        let delay = self.policy.delay.draw(&mut self.rng);
        if delay.is_zero() {
            self.send(dir, &data).await;
            return;
        }
        Counters::bump(&self.counters.delayed);
        self.seq += 1;
        self.pending.push(Reverse(Scheduled {
            at: Instant::now() + delay,
            seq: self.seq,
            dir,
            data,
        }));
    }

    async fn send(&self, dir: Dir, data: &[u8]) {
        match dir {
            Dir::ToServer => {
                if let Some(up) = &self.up
                    && up.send_to(data, self.server).await.is_ok()
                {
                    Counters::bump(&self.counters.to_server);
                }
            }
            Dir::ToClient => {
                if let Some(client) = self.client
                    && self.front.send_to(data, client).await.is_ok()
                {
                    Counters::bump(&self.counters.to_client);
                }
            }
        }
    }
}

/// Flip one bit inside the datagram's AEAD tag (the last 16 bytes of a QUIC
/// packet). Targeting the tag rather than the header means the packet is
/// well-formed all the way to *authentication* and is then rejected there —
/// which is the property under test. Short datagrams (there are none in QUIC
/// after the handshake) fall back to any byte.
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

async fn recv_from(
    sock: Option<&UdpSocket>,
    buf: &mut [u8],
) -> Option<io::Result<(usize, SocketAddr)>> {
    match sock {
        Some(sock) => Some(sock.recv_from(buf).await),
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prng_is_reproducible_and_independent_of_wall_clock() {
        let a: Vec<u64> = (0..8).map(|_| ChaosRng::new(7).next_u64()).collect();
        assert!(a.iter().all(|v| *v == a[0]), "same seed, same first draw");
        let mut r1 = ChaosRng::new(0xDEAD_BEEF);
        let mut r2 = ChaosRng::new(0xDEAD_BEEF);
        let s1: Vec<u64> = (0..64).map(|_| r1.next_u64()).collect();
        let s2: Vec<u64> = (0..64).map(|_| r2.next_u64()).collect();
        assert_eq!(s1, s2);
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
        let mk = |ms: u64, seq: u64| Scheduled {
            at: base + Duration::from_millis(ms),
            seq,
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
}
