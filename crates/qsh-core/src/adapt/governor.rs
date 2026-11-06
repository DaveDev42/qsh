//! The per-connection bulk governor (ADR-0052 decision 12 (a)): the object
//! every bulk sender on one QUIC connection asks before it writes, so that a
//! tunnel, a file transfer or a relay yields to the PTY traffic that shares
//! the connection's bottleneck.
//!
//! It owns one [`BulkBudget`] and feeds it the way the policy says: the mode
//! comes from [`decide`] (`interactive` and `bulk` seen recently, and the
//! user's `adaptive` pin), the steering from the connection's smoothed RTT
//! against its minimum (`queue_delay`). Interactive streams never call
//! [`BulkGovernor::pace`]; they only report themselves with
//! [`BulkGovernor::note_interactive`], so they are never throttled.
//!
//! [`GovernorCore`] is the state machine with injected time and statistics;
//! [`BulkGovernor`] binds it to a [`Connection`] and tokio's timers. One
//! governor exists per connection and per side: the registry hands the same
//! `Arc` to every holder, keyed by `stable_id` like the stall ledger's
//! (`crate::tunnel::stall`), and forgets it when the last holder is gone.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use qsh_transport::{ConnStats, Connection};

use super::{BulkBudget, BulkYield, Knobs, Observed, RTT_FLOOR, User, decide};

/// Key input or a screen update counts as interactive for this long
/// (decision 12, `interactive`: "최근 2초").
pub const INTERACTIVE_WINDOW: Duration = Duration::from_secs(2);
/// Bulk bytes counted as moving for this long (decision 12, `bulk`: "최근
/// 1초").
pub const BULK_WINDOW: Duration = Duration::from_secs(1);
/// Open number: how often the governor re-reads the connection statistics
/// and re-runs the policy. The steering itself moves at most once per srtt;
/// this only bounds the cost of asking.
pub const EVALUATE_PERIOD: Duration = Duration::from_millis(20);
/// Open number: the longest a sender sleeps on an empty bucket before it
/// looks again, so that a mode change (the user stopped typing) releases a
/// parked sender within this time instead of at the end of a long wait.
pub const MAX_PARK: Duration = Duration::from_millis(50);

/// Open number: width of one delivery-rate bucket.
const RATE_BUCKET: Duration = Duration::from_millis(250);
/// Open number: the delivery rate is the bytes of this many consecutive
/// buckets per second, so one bursty bucket does not stand for a rate.
const RATE_SPAN: u64 = 4;
/// Open number: how far back the peak delivery rate looks.
const RATE_MEMORY: Duration = Duration::from_secs(60);
/// Open number: the bandwidth estimate is capped at this many percent of the
/// peak delivery rate. `cwnd / srtt` alone ran at 10 to 20 times the link
/// whenever BBR's window grew past the pipe, and a budget that grows by a
/// share of that overshoots the queue by a whole pipe on every rise.
const PEAK_HEADROOM_PERCENT: u64 = 125;

/// Open number: while the budget is limiting, a sender hands the transport
/// this many bytes at a time, each one paid for before it is written. quinn
/// sends what it is handed in one burst at line speed; a burst longer than the
/// bottleneck's queue is dropped at its tail, which a 64 KiB write into a
/// 20 ms queue at 20 Mbit/s (50 KB) always was.
pub const PACE_GRANULE: usize = 16 * 1024;

static PROCESS_ADAPTIVE: AtomicBool = AtomicBool::new(true);

/// Set what `[transport].adaptive` pins for governors created from now on
/// (`false` is `"off"`: no yielding). The configuration step calls this at
/// startup, once, before any connection exists; the default is `true`.
pub fn set_process_adaptive(adaptive: bool) {
    PROCESS_ADAPTIVE.store(adaptive, Ordering::Relaxed);
}

/// The pin [`set_process_adaptive`] last set.
pub fn process_adaptive() -> bool {
    PROCESS_ADAPTIVE.load(Ordering::Relaxed)
}

/// What a sender must do next to put the rest of its bytes on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pace {
    /// The whole amount is paid for; write.
    Go,
    /// Some of it is still owed; look again after this long.
    Wait(Duration),
}

/// The state machine behind [`BulkGovernor`]: no clock, no connection.
#[derive(Clone, Debug)]
pub struct GovernorCore {
    budget: BulkBudget,
    knobs: Knobs,
    user: User,
    last_interactive: Option<Duration>,
    last_bulk: Option<Duration>,
    last_evaluated: Option<Duration>,
    /// Bytes granted per [`RATE_BUCKET`], by bucket index.
    delivered: VecDeque<(u64, u64)>,
    /// `lost_packets` as of the last evaluation.
    lost_seen: Option<u64>,
}

impl GovernorCore {
    /// A governor that is not limiting yet.
    pub fn new(now: Duration, user: User) -> Self {
        Self {
            budget: BulkBudget::new(now),
            knobs: Knobs::default(),
            user,
            last_interactive: None,
            last_bulk: None,
            last_evaluated: None,
            delivered: VecDeque::new(),
            lost_seen: None,
        }
    }

    fn bucket_of(now: Duration) -> u64 {
        (now.as_nanos() / RATE_BUCKET.as_nanos()) as u64
    }

    fn record(&mut self, now: Duration, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let idx = Self::bucket_of(now);
        match self.delivered.back_mut() {
            Some((i, b)) if *i == idx => *b += bytes,
            _ => self.delivered.push_back((idx, bytes)),
        }
        let oldest =
            idx.saturating_sub(RATE_MEMORY.as_nanos() as u64 / RATE_BUCKET.as_nanos() as u64);
        while self.delivered.front().is_some_and(|(i, _)| *i < oldest) {
            self.delivered.pop_front();
        }
    }

    /// The most bytes per second the senders got out over any
    /// [`RATE_SPAN`] complete buckets in the last [`RATE_MEMORY`]. While a
    /// saturating sender is held back only by the pipe, this is the pipe.
    fn peak_rate(&self, now: Duration) -> Option<u64> {
        let current = Self::bucket_of(now);
        let (mut best, mut sum, mut lo) = (0u64, 0u64, 0usize);
        for hi in 0..self.delivered.len() {
            let (end, bytes) = self.delivered[hi];
            if end >= current {
                break;
            }
            sum += bytes;
            while self.delivered[lo].0 + RATE_SPAN <= end {
                sum -= self.delivered[lo].1;
                lo += 1;
            }
            best = best.max(sum);
        }
        let span = RATE_BUCKET.as_secs_f64() * RATE_SPAN as f64;
        (best > 0).then(|| (best as f64 / span) as u64)
    }

    /// Interactive traffic (a key, a screen update) moved at `now`.
    pub fn note_interactive(&mut self, now: Duration) {
        self.last_interactive = Some(now);
    }

    /// Whether the statistics are stale enough to read again.
    pub fn due(&self, now: Duration) -> bool {
        self.last_evaluated
            .is_none_or(|t| now.saturating_sub(t) >= EVALUATE_PERIOD)
    }

    /// Feed one statistics snapshot: run the policy for the mode, then one
    /// steering step.
    pub fn evaluate(&mut self, now: Duration, stats: &ConnStats) {
        self.last_evaluated = Some(now);
        let within = |last: Option<Duration>, window: Duration| {
            last.is_some_and(|t| now.saturating_sub(t) <= window)
        };
        let mut observed = Observed {
            interactive: within(self.last_interactive, INTERACTIVE_WINDOW),
            bulk: within(self.last_bulk, BULK_WINDOW),
            user: self.user,
            ..Observed::default()
        }
        .with_path_stats(stats, stats, Duration::ZERO);
        if let Some(peak) = self.peak_rate(now) {
            let cap = peak / 100 * PEAK_HEADROOM_PERCENT;
            observed.est_bandwidth = Some(cap);
        }
        self.knobs = decide(&observed, &self.knobs);
        self.budget
            .set_mode(now, self.knobs.bulk_yield, observed.est_bandwidth);
        if let Some(lost) = stats.lost_packets {
            if self.lost_seen.is_some_and(|seen| lost > seen) {
                self.budget.note_loss();
            }
            self.lost_seen = Some(lost);
        }
        // The same RTT floor as the carrier rule: a loopback srtt of 0.1 ms
        // would let the steering run ten thousand times a second.
        self.budget
            .steer(now, observed.queue_delay(), stats.rtt.max(RTT_FLOOR));
    }

    /// A sender wants to write `*remaining` bytes. Takes what the bucket
    /// has, lowers `*remaining` by it and says whether to write or wait.
    pub fn pace(&mut self, now: Duration, remaining: &mut u64) -> Pace {
        self.last_bulk = Some(now);
        if self.budget.rate().is_none() {
            let all = std::mem::take(remaining);
            self.record(now, all);
            return Pace::Go;
        }
        let granted = self.budget.grant(now, *remaining);
        self.record(now, granted);
        *remaining -= granted;
        if *remaining == 0 {
            return Pace::Go;
        }
        Pace::Wait(
            self.budget
                .wait_for(now, *remaining)
                .clamp(Duration::from_millis(1), MAX_PARK),
        )
    }

    /// `(interactive, bulk)` as of `now`.
    pub fn activity(&self, now: Duration) -> (bool, bool) {
        let within = |last: Option<Duration>, window: Duration| {
            last.is_some_and(|t| now.saturating_sub(t) <= window)
        };
        (
            within(self.last_interactive, INTERACTIVE_WINDOW),
            within(self.last_bulk, BULK_WINDOW),
        )
    }

    /// The knob (a) the last [`Self::evaluate`] decided.
    pub fn bulk_yield(&self) -> BulkYield {
        self.knobs.bulk_yield
    }

    /// Current budget rate in bytes per second, `None` while not limiting.
    pub fn rate(&self) -> Option<u64> {
        self.budget.rate()
    }
}

/// Bulk governor of one connection, shared by everything on it.
pub struct BulkGovernor {
    conn: Connection,
    epoch: Instant,
    core: Mutex<GovernorCore>,
}

type Registry = Mutex<HashMap<usize, Weak<BulkGovernor>>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl BulkGovernor {
    /// The governor of `conn`, created on first use. Keyed by `stable_id`;
    /// a live governor holds `conn`, so the id cannot be reused by another
    /// connection while the entry upgrades.
    pub fn for_connection(conn: &Connection) -> Arc<BulkGovernor> {
        let mut registry = lock(registry());
        registry.retain(|_, governor| governor.strong_count() > 0);
        if let Some(governor) = registry.get(&conn.stable_id()).and_then(Weak::upgrade) {
            return governor;
        }
        let governor = Arc::new(Self::new(conn.clone(), process_adaptive()));
        registry.insert(conn.stable_id(), Arc::downgrade(&governor));
        governor
    }

    /// A governor outside the registry, with an explicit `adaptive` pin.
    pub fn new(conn: Connection, adaptive: bool) -> Self {
        Self {
            conn,
            epoch: Instant::now(),
            core: Mutex::new(GovernorCore::new(
                Duration::ZERO,
                User {
                    adaptive,
                    ..User::default()
                },
            )),
        }
    }

    /// Interactive traffic moved: a key arrived or went out, a screen update
    /// was sent. Cheap; never waits.
    pub fn note_interactive(&self) {
        lock(&self.core).note_interactive(self.epoch.elapsed());
    }

    /// Wait until `bytes` of bulk may go out. Returns at once while the
    /// budget is not limiting.
    pub async fn pace(&self, bytes: usize) {
        let mut remaining = bytes as u64;
        loop {
            let wait = {
                let now = self.epoch.elapsed();
                let mut core = lock(&self.core);
                if core.due(now) {
                    let stats = self.conn.stats();
                    core.evaluate(now, &stats);
                }
                match core.pace(now, &mut remaining) {
                    Pace::Go => return,
                    Pace::Wait(d) => d,
                }
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// How much of a `len`-byte write to hand the transport next: all of it
    /// while the budget is not limiting, [`PACE_GRANULE`] while it is.
    pub fn granule(&self, len: usize) -> usize {
        if lock(&self.core).rate().is_some() {
            len.min(PACE_GRANULE)
        } else {
            len
        }
    }

    /// Whether key input moved within [`INTERACTIVE_WINDOW`] and bulk bytes
    /// within [`BULK_WINDOW`]: the two traffic inputs of the policy.
    pub fn activity(&self) -> (bool, bool) {
        lock(&self.core).activity(self.epoch.elapsed())
    }

    /// Current budget rate, for tests and diagnostics.
    pub fn rate(&self) -> Option<u64> {
        lock(&self.core).rate()
    }
}
