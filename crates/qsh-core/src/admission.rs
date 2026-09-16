//! Connection admission control (`PLAN.md` M8 Step 2,
//! `docs/adr/0009-admission-defenses.md`, extended `PLAN.md` M8 Step 3
//! P2-3): the L2-L3 layer of the L0-L5 admission ordering, sitting
//! between quinn's own cheap pre-app shed (`qsh_transport::endpoint`'s
//! `MAX_INCOMING`/`INCOMING_BUFFER_SIZE`, L0) and the TLS handshake (L4).
//! Shared by both internet-exposed accept loops —
//! `crate::server::Server::run` and `crate::reverse::listen::Listen::run`.
//!
//! [`Gate`] answers one question, [`Gate::decide`]: for this `Incoming`,
//! at this moment, is the attempt address-validated and, if so, is there
//! capacity to run its handshake? The answer is a [`Decision`] the accept
//! loop maps onto `qsh_transport::Incoming::retry`/`refuse`/`ignore`/
//! `accept` — `decide` itself never touches the network, a QUIC type, or
//! an audit sink: it only reads/updates in-memory state (a semaphore, two
//! independent count-min sketches — one per rate-limit axis, unvalidated
//! and validated — and three rejection-aggregation windows, one per
//! [`RejectReason`]) and returns what happened, including any
//! [`crate::audit::AuditRecord`]s the call site should write. That split
//! is deliberate: every invariant this module owns (the cap bites, both
//! rate limits bite and recover independently, IPv6 keys by /64, neither
//! table can grow) is testable without a network, a clock that runs in
//! real time, or a fake [`crate::audit::AuditSink`].

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::audit::AuditRecord;
use crate::broker::Clock;

/// Count-min sketch dimensions (`PLAN.md` M8 Step 2 design judgment table,
/// row "source rate limit"): 4 independently-hashed rows × 1024 columns,
/// so an attacker who can observe (or brute-force) one row's hash seed
/// still needs to collide all 4 simultaneously to manufacture a false
/// throttle against a chosen victim key. Fixed, not derived from config —
/// the whole point is a table whose footprint never depends on how many
/// distinct sources an attacker forges (see
/// `gate_table_is_constant_size_under_forged_cardinality`).
const SKETCH_ROWS: usize = 4;
/// See [`SKETCH_ROWS`]. 4 rows × 1024 columns × 2 generations ×
/// `size_of::<AtomicU32>()` (4 bytes) = 32 KiB total, matching the design
/// arbitration's own number.
const SKETCH_COLS: usize = 1024;

/// Sliding-window epoch length for the per-source rate limiter (`PLAN.md`
/// M8 Step 2 verification round, F2/item 4). **2 s, not 1 s.** With a 1 s
/// epoch and a `rate × 2` threshold, a *sustained* source at `rate × 2`
/// events/s never accumulates more than `burst_limit` in either the
/// current or the blended-previous epoch, so it sails through forever —
/// exactly the "10/s 기본, burst 2배" contract `docs/CLI.md` §6.12
/// documents gets silently doubled into an unbounded-sustained 20/s pass.
/// A 2 s epoch with threshold `rate × EPOCH.as_secs()` fixes the units: a
/// *sustained* source at `rate`/s accumulates ~`rate × 2` per epoch,
/// landing it right at the threshold (never over), while a source that
/// front-loads its whole epoch's budget into a fraction of a second still
/// gets the same numeric burst headroom before the second attempt in the
/// blended window trips `estimate > burst_limit`. Not configurable —
/// `[serve].handshake_rate_per_source` sets the *sustained budget per
/// second*, not the epoch length.
const EPOCH: Duration = Duration::from_secs(2);

/// How long an admission-rejection audit window stays open before its
/// suppressed count is flushed as a summary record and a new window
/// starts (`PLAN.md` M8 Step 2 §5, ADR-0009). 10 s, matching the design's
/// own "창(10초)당 category별 1행 + 요약 1행" contract (also documented
/// verbatim in `docs/CLI.md` §6.12).
///
/// Flushed two ways (`PLAN.md` M8 Step 2 verification round, P1-3/F1):
/// lazily, the next time a rejection in the same category arrives after
/// the window has run past this bound (see `Gate::record_rejection`'s
/// doc), *and* on a bounded schedule — both `crate::server::Server::run`
/// and `crate::reverse::listen::Listen::run` tick
/// [`Gate::flush_expired`] every `AUDIT_AGGREGATION_WINDOW` off a
/// `tokio::time::interval` in their accept-loop `select!`, plus once more
/// when the loop exits. So a flood's last (possibly partial) window's
/// summary is never delayed past one more tick after the flood stops —
/// not "possibly never", as it was when only the lazy path existed.
///
/// `pub`, not `pub(crate)`: `crates/qsh-cli/tests/adversarial_load.rs`
/// (scenario 12a) reads this across the crate boundary instead of
/// carrying its own hardcoded copy of the window length (`PLAN.md` M8
/// Step 5 (b-0)). Widening visibility here is not a contract change —
/// nothing outside this crate is meant to *depend* on the value, only
/// this one integration test computing bounds from the real number
/// instead of drifting from it.
pub const AUDIT_AGGREGATION_WINDOW: Duration = Duration::from_secs(10);

/// Why one admission attempt was rejected — also the vocabulary
/// [`crate::audit::AuditRecord::handshake_rejected`]'s `category` uses for
/// this module's three rejection kinds (`docs/CLI.md` §6.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The per-source sliding-window rate limit was exceeded by an
    /// address-*unvalidated* attempt.
    RateLimited,
    /// The address-validated attempt lost the race for a handshake
    /// permit — [`Gate`]'s concurrency cap is exhausted.
    AtCapacity,
    /// The per-source sliding-window rate limit was exceeded by an
    /// address-*validated* attempt (holder of a completed Retry round
    /// trip) — `PLAN.md` M8 Step 3 P2-3, `docs/adr/0009-admission-
    /// defenses.md`'s 한계 section. Keyed by the same validated peer
    /// address, but tracked in its own `Sketch` so a spoofed
    /// unvalidated flood can never collide with (and steal budget from)
    /// a real validated source.
    ValidatedRateLimited,
}

impl RejectReason {
    /// Every variant, in the same order as [`Gate`]'s `windows` array —
    /// `reason as usize` indexes into it, so this order and the enum's
    /// declaration order must stay in lockstep. Used by
    /// [`Gate::flush_expired`] and by `crates/qsh-core/tests/
    /// admission_docs.rs`'s doc-drift check.
    pub const ALL: &'static [RejectReason] = &[
        RejectReason::RateLimited,
        RejectReason::AtCapacity,
        RejectReason::ValidatedRateLimited,
    ];

    /// The audit/log category word (`docs/CLI.md` §6.12: `"rate_limited"`
    /// / `"at_capacity"` / `"validated_rate_limited"`).
    pub fn category(self) -> &'static str {
        match self {
            RejectReason::RateLimited => "rate_limited",
            RejectReason::AtCapacity => "at_capacity",
            RejectReason::ValidatedRateLimited => "validated_rate_limited",
        }
    }
}

/// The outcome of [`Gate::decide`]. The accept loop maps each variant onto
/// exactly one `qsh_transport::Incoming` method — see this module's own
/// doc for why the mapping is the caller's job, not `decide`'s.
pub enum Decision {
    /// Unvalidated, under the per-source rate limit: force a Retry round
    /// trip. **Never audited** — a Retry is a protocol challenge, not a
    /// denial (auditing it is the audit-flood vector this whole module
    /// exists to close).
    Retry,
    /// Unvalidated, over the per-source rate limit: the caller must
    /// `ignore()` the attempt (no packet sent to an address already
    /// judged abusive). The [`Vec<AuditRecord>`] is what the call site
    /// should hand to its [`crate::audit::AuditSink`] — empty when this
    /// rejection landed inside an aggregation window that already
    /// recorded its first occurrence (`Gate`'s module doc, §5
    /// aggregation), otherwise one or two records (a closed prior
    /// window's summary, then this window's own first-occurrence record).
    Ignore(RejectReason, Vec<AuditRecord>),
    /// Validated, but rejected before/instead of a handshake permit: over
    /// its own per-source rate limit (`RejectReason::ValidatedRateLimited`,
    /// P2-3 — never touches the semaphore) or at the concurrency cap
    /// (`RejectReason::AtCapacity`). Either way the caller must `refuse()`
    /// the attempt. Same aggregation contract as [`Decision::Ignore`].
    Refuse(RejectReason, Vec<AuditRecord>),
    /// Validated, under the cap: admitted. The permit must be held until
    /// the handshake (`Incoming::accept()`) resolves — success or
    /// failure — and dropped **before** the connection is served, so a
    /// handshake slot never outlives the handshake itself.
    Admit(OwnedSemaphorePermit),
}

/// Lock-free per-branch tally of every [`Decision`] [`Gate::decide`] has
/// ever returned, since `Gate::new` — a soak-observability counter
/// (M8 Step 5a), not an enforcement mechanism. `Ignore` is deliberately
/// **not** promoted past `tracing::trace!` for the individual event (a
/// spoofed-source flood can hit it thousands of times a second), so this
/// snapshot is the only cheap way an accept-loop heartbeat or a soak
/// harness can see how much of that traffic there was without paying for
/// per-event tracing at a visible level.
#[derive(Debug, Default)]
struct DecisionCounters {
    retry: AtomicU64,
    ignore: AtomicU64,
    refuse: AtomicU64,
    admit: AtomicU64,
}

/// A point-in-time snapshot of `DecisionCounters` — what
/// [`Gate::counters`] returns. Plain `u64`s (not atomics): once read out,
/// this is a moment's tally, not a live handle.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionCounters {
    pub retry: u64,
    pub ignore: u64,
    pub refuse: u64,
    pub admit: u64,
}

/// One row of the count-min sketch: its own independently-seeded hasher
/// (`std::collections::hash_map::RandomState`, freshly generated per row
/// at [`Gate::new`] — deliberately *not* one shared hasher reused across
/// rows) plus two generations of fixed-length atomic counters. Per-row
/// seeding is the point: an attacker who somehow learned one row's
/// mapping still cannot precompute a source that collides with a
/// legitimate victim in all 4 rows at once (design judgment table's
/// "추가 요구: 행별 독립 시드 해시").
struct SketchRow {
    hasher: RandomState,
    /// `gens[e % 2]` is the generation currently accumulating epoch `e`'s
    /// counts. Backed by `Vec`, not a fixed array, purely because
    /// `[AtomicU32; 1024]` has no ergonomic all-zero const constructor —
    /// the length is fixed at construction and never changes again (see
    /// [`Gate::sketch_storage_pointers`] and
    /// `gate_table_is_constant_size_under_forged_cardinality`, which pins
    /// exactly that).
    gens: [Vec<AtomicU32>; 2],
}

impl SketchRow {
    fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            gens: [
                (0..SKETCH_COLS).map(|_| AtomicU32::new(0)).collect(),
                (0..SKETCH_COLS).map(|_| AtomicU32::new(0)).collect(),
            ],
        }
    }

    fn column(&self, key: &SourceKey) -> usize {
        (self.hasher.hash_one(key) as usize) % SKETCH_COLS
    }
}

/// The admission key a source's traffic is bucketed under (`PLAN.md` M8
/// Step 2 design judgment table): the full address for IPv4 (a /32 is
/// exactly one `Ipv4Addr`), the top 64 bits for IPv6 (a /64 — privacy
/// extensions rotate the low 64 bits for one legitimate host, so keying
/// any narrower lets a single host looking like many hosts evade the
/// limiter, and any wider lets one attacker holding a /64 look like
/// unboundedly many). IPv4 and IPv6 never collide with each other: the
/// discriminant is part of what gets hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SourceKey {
    V4(u32),
    V6(u64),
}

impl SourceKey {
    fn from_addr(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => SourceKey::V4(u32::from(v4)),
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                let prefix64 = ((seg[0] as u64) << 48)
                    | ((seg[1] as u64) << 32)
                    | ((seg[2] as u64) << 16)
                    | (seg[3] as u64);
                SourceKey::V6(prefix64)
            }
        }
    }
}

/// Which epoch's counters are "current" right now, and the machinery to
/// advance that pointer. A `Mutex`, not lock-free: transitions happen at
/// most once per [`EPOCH`] (2 s) system-wide, so contention here is
/// negligible — only the per-request counter *increments* need to stay
/// lock-free, and those go straight to the `AtomicU32`s without taking
/// this lock.
struct EpochState {
    index: u64,
}

struct Sketch {
    rows: [SketchRow; SKETCH_ROWS],
    epoch: Mutex<EpochState>,
}

impl Sketch {
    fn new() -> Self {
        Self {
            rows: [
                SketchRow::new(),
                SketchRow::new(),
                SketchRow::new(),
                SketchRow::new(),
            ],
            epoch: Mutex::new(EpochState { index: 0 }),
        }
    }

    /// Advance the shared epoch pointer to `target`, clearing whichever
    /// generation slot(s) are now stale. A gap of exactly one epoch only
    /// needs the newly-current slot cleared (the previously-current slot
    /// correctly becomes "previous"); a gap greater than one (the gate
    /// sat idle for over a second) means *both* slots are stale history
    /// with no relationship to `target`'s neighborhood, so both are
    /// cleared. A `target` at or behind the current index is a no-op —
    /// either this call observed the epoch it already knew about, or lost
    /// a race with a concurrent advance to a later epoch, and the later
    /// epoch's clearing already covers what this call would have done.
    fn advance_to(&self, target: u64) {
        let mut state = self.epoch.lock().unwrap_or_else(|e| e.into_inner());
        if target <= state.index {
            return;
        }
        let gap = target - state.index;
        for row in &self.rows {
            if gap == 1 {
                let cur = (target % 2) as usize;
                for counter in &row.gens[cur] {
                    counter.store(0, Ordering::Relaxed);
                }
            } else {
                for generation in &row.gens {
                    for counter in generation {
                        counter.store(0, Ordering::Relaxed);
                    }
                }
            }
        }
        state.index = target;
    }

    /// Record one event for `key` at `epoch_index`/`fraction_into_epoch`
    /// (`fraction_into_epoch` in `[0, 1)`: how far into the current epoch
    /// `now` falls) and return the sketch's current rate estimate for
    /// `key` — the minimum across all 4 rows (`min-of-counters`, the
    /// standard count-min-sketch read, which is what bounds the effect of
    /// any single row's hash collisions). The estimate blends this
    /// epoch's count so far with the *previous* epoch's count weighted by
    /// how much of the previous epoch's "reach" has not yet been
    /// superseded (`1 - fraction_into_epoch`) — the standard sliding-
    /// window-counter approximation, chosen (design judgment table) over
    /// a hard per-epoch reset specifically so a source is never handed a
    /// fresh full budget the instant a wall-clock second ticks over.
    fn record_and_estimate(
        &self,
        key: &SourceKey,
        epoch_index: u64,
        fraction_into_epoch: f64,
    ) -> u32 {
        self.advance_to(epoch_index);
        let cur = (epoch_index % 2) as usize;
        let prev = 1 - cur;
        let mut estimate = u32::MAX;
        for row in &self.rows {
            let col = row.column(key);
            let new_current = row.gens[cur][col].fetch_add(1, Ordering::Relaxed) + 1;
            let previous = row.gens[prev][col].load(Ordering::Relaxed);
            let weighted_previous = (previous as f64 * (1.0 - fraction_into_epoch)) as u32;
            estimate = estimate.min(new_current.saturating_add(weighted_previous));
        }
        estimate
    }

    /// Raw pointers to every generation's backing storage, in a stable
    /// order — see [`Gate::sketch_storage_pointers`]'s doc for what this
    /// is for.
    #[cfg(test)]
    fn storage_pointers(&self) -> Vec<*const AtomicU32> {
        self.rows
            .iter()
            .flat_map(|row| row.gens.iter().map(|generation| generation.as_ptr()))
            .collect()
    }
}

/// Rejection-audit aggregation state for one [`RejectReason`] category
/// (`PLAN.md` M8 Step 2 §5, ADR-0009): the first rejection in a 10 s
/// window is reported immediately (with its real, observed `peer_addr` —
/// a stray denial must not be delayed waiting for a window to close);
/// every further rejection in that same window only increments
/// `suppressed`; the count is turned into a summary record either the
/// next time a rejection in this category arrives after the window has
/// run past [`AUDIT_AGGREGATION_WINDOW`] (lazy flush — see
/// [`Gate::record_rejection`]'s doc), or the next time
/// [`Gate::flush_expired`] is polled after that same bound — whichever
/// comes first.
#[derive(Default)]
pub(crate) struct WindowState {
    pub(crate) start: Option<Instant>,
    pub(crate) suppressed: u32,
}

/// `start` and `suppressed` live behind **one** lock (verification round
/// P3-4): the previous shape (`Mutex<Option<Instant>>` next to a separate
/// `AtomicU32`) let a concurrent [`Gate::flush_expired`] `swap` the
/// counter to 0 in the gap between [`Gate::record_rejection`] dropping the
/// window-start guard and then bumping the atomic — landing that
/// increment in the *next* window instead of the one it was counted
/// against. A single `Mutex<WindowState>` makes "read start, maybe bump
/// suppressed, maybe reset both" one atomic critical section, so that
/// interleaving cannot happen. No `.await` is ever held across the lock.
#[derive(Default)]
pub(crate) struct AuditWindow {
    pub(crate) state: Mutex<WindowState>,
}

/// The admission decision-maker: a handshake concurrency permit pool plus
/// a per-source rate limiter, both driven by an injected
/// [`crate::broker::Clock`] so every invariant here is testable without
/// real wall-clock time. See the module doc for the [`Gate::decide`]/
/// audit-sink split.
pub struct Gate {
    clock: Arc<dyn Clock>,
    /// Reference point [`Gate::new`] captured `clock.now()` at — the
    /// sketch's epoch index is `now.duration_since(origin).as_secs()`.
    /// `Instant` has no meaningful cross-process absolute value, so each
    /// `Gate` anchors its own axis rather than assuming one.
    origin: Instant,
    handshake_permits: Arc<Semaphore>,
    rate_per_source: u32,
    sketch: Sketch,
    /// P2-3 (`PLAN.md` M8 Step 3, design §2.7): a **second**, independent
    /// fixed-size sketch keyed by the same validated peer address, so a
    /// spoofed unvalidated flood can never collide with (and steal
    /// budget from) a real validated source's counters.
    validated_sketch: Sketch,
    validated_rate_per_source: u32,
    windows: [AuditWindow; 3],
    /// Soak observability (M8 Step 5a) — see [`DecisionCounters`].
    decision_counters: DecisionCounters,
}

impl Gate {
    /// Build a gate. `max_concurrent_handshakes`/`rate_per_source`/
    /// `validated_rate_per_source` are already-defaulted, already-nonzero
    /// values (`crate::config::ServeConfig::max_concurrent_handshakes`/
    /// `handshake_rate_per_source`/`validated_rate_per_source` — `0` in
    /// config means "use the default", never "unlimited", and that
    /// degradation happens before this constructor is ever called).
    pub fn new(
        clock: Arc<dyn Clock>,
        max_concurrent_handshakes: usize,
        rate_per_source: u32,
        validated_rate_per_source: u32,
    ) -> Self {
        let origin = clock.now();
        Self {
            clock,
            origin,
            handshake_permits: Arc::new(Semaphore::new(max_concurrent_handshakes)),
            rate_per_source,
            sketch: Sketch::new(),
            validated_sketch: Sketch::new(),
            validated_rate_per_source,
            windows: [
                AuditWindow::default(),
                AuditWindow::default(),
                AuditWindow::default(),
            ],
            decision_counters: DecisionCounters::default(),
        }
    }

    /// Snapshot the running tally of every [`Decision`] branch
    /// [`Gate::decide`] has returned since construction (M8 Step 5a) —
    /// for the accept-loop heartbeat and soak harnesses, not for
    /// enforcement decisions.
    pub fn counters(&self) -> AdmissionCounters {
        AdmissionCounters {
            retry: self.decision_counters.retry.load(Ordering::Relaxed),
            ignore: self.decision_counters.ignore.load(Ordering::Relaxed),
            refuse: self.decision_counters.refuse.load(Ordering::Relaxed),
            admit: self.decision_counters.admit.load(Ordering::Relaxed),
        }
    }

    /// The gate's own clock, for a caller that needs `now` to pass to
    /// [`Gate::decide`] (production accept loops) without duplicating
    /// which clock that is.
    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    /// The number of handshake permits currently available — diagnostic/
    /// test use only (e.g. asserting a permit was actually released).
    pub fn available_permits(&self) -> usize {
        self.handshake_permits.available_permits()
    }

    /// Decide what to do with one `Incoming`, given whether quinn has
    /// already validated its source address and the current time. Pure
    /// with respect to I/O — no network call, no audit write — but not
    /// pure with respect to `self`: it advances the rate-limit sketch's
    /// epoch and counters, and (on a rejection) the aggregation window's
    /// state, exactly the state a real accept loop needs updated whether
    /// or not it acts on the `Decision` synchronously.
    ///
    /// **Ordering this method encodes** (`docs/adr/0009-admission-
    /// defenses.md`'s L2-L3, extended by design §2.7 for P2-3): an
    /// unvalidated attempt is checked against its rate limit *before*
    /// anything capacity-related, so a spoofed source that will be
    /// `Ignore`d never touches the handshake semaphore at all. A
    /// validated attempt is checked against its *own* (separately
    /// sketched, separately configured) rate limit before it ever
    /// competes for a permit — the same "rate limit ahead of the
    /// semaphore" ordering ADR-0009 established, just extended to the
    /// axis that ADR-0009's 한계 section left open. `RejectReason::
    /// ValidatedRateLimited` never touches `handshake_permits`.
    pub fn decide(&self, peer: SocketAddr, validated: bool, now: Instant) -> Decision {
        if !validated {
            if self.rate_exceeded(&self.sketch, self.rate_per_source, peer, now) {
                let records = self.record_rejection(RejectReason::RateLimited, peer, now);
                self.decision_counters
                    .ignore
                    .fetch_add(1, Ordering::Relaxed);
                // Deliberately `trace!`, not `debug!`/`info!`: a spoofed
                // source under flood hits this branch thousands of times
                // a second (module doc, §5 aggregation) — the aggregated
                // `AuditRecord`s above are the visible signal, this is
                // only for someone who turned tracing all the way up.
                // No payload/key material, address only.
                tracing::trace!(
                    target: "qsh_core::admission",
                    peer = %peer,
                    reason = ?RejectReason::RateLimited,
                    "admission decision: ignore"
                );
                return Decision::Ignore(RejectReason::RateLimited, records);
            }
            self.decision_counters.retry.fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::admission",
                peer = %peer,
                "admission decision: retry"
            );
            return Decision::Retry;
        }
        if self.rate_exceeded(
            &self.validated_sketch,
            self.validated_rate_per_source,
            peer,
            now,
        ) {
            let records = self.record_rejection(RejectReason::ValidatedRateLimited, peer, now);
            self.decision_counters
                .refuse
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::admission",
                peer = %peer,
                reason = ?RejectReason::ValidatedRateLimited,
                "admission decision: refuse"
            );
            return Decision::Refuse(RejectReason::ValidatedRateLimited, records);
        }
        match self.handshake_permits.clone().try_acquire_owned() {
            Ok(permit) => {
                self.decision_counters.admit.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    target: "qsh_core::admission",
                    peer = %peer,
                    "admission decision: admit"
                );
                Decision::Admit(permit)
            }
            Err(_) => {
                let records = self.record_rejection(RejectReason::AtCapacity, peer, now);
                self.decision_counters
                    .refuse
                    .fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    target: "qsh_core::admission",
                    peer = %peer,
                    reason = ?RejectReason::AtCapacity,
                    "admission decision: refuse"
                );
                Decision::Refuse(RejectReason::AtCapacity, records)
            }
        }
    }

    /// Record one event for `peer` in `sketch` and report whether that
    /// source is now over `rate`'s per-epoch budget — the shared body
    /// behind both the unvalidated and the validated rate checks in
    /// [`Gate::decide`]; only which `sketch`/`rate` pair is passed in
    /// differs between the two axes. See [`Sketch::record_and_estimate`]
    /// for the epoch/burst math this wraps.
    fn rate_exceeded(&self, sketch: &Sketch, rate: u32, peer: SocketAddr, now: Instant) -> bool {
        let key = SourceKey::from_addr(peer.ip());
        let elapsed = now.saturating_duration_since(self.origin);
        let epoch_len = EPOCH.as_secs_f64();
        let epoch_position = elapsed.as_secs_f64() / epoch_len;
        let epoch_index = epoch_position as u64;
        let fraction_into_epoch = epoch_position - epoch_index as f64;
        let estimate = sketch.record_and_estimate(&key, epoch_index, fraction_into_epoch);
        // The per-epoch budget for a *sustained* `rate`/s source
        // (verification round F2, extended unchanged to the validated
        // axis by design §2.7): over one `EPOCH`-long window a sustained
        // source accumulates `rate × EPOCH.as_secs()` events, so that
        // product — not a separate burst multiplier — is both the
        // sustained ceiling and the instantaneous-burst allowance within
        // a single epoch.
        let burst_limit = rate.saturating_mul(EPOCH.as_secs() as u32);
        estimate > burst_limit
    }

    /// The §5 aggregation itself. **Lazy flush**: a window's summary is
    /// only produced here the next time a rejection in the *same
    /// category* arrives after the window has run past
    /// [`AUDIT_AGGREGATION_WINDOW`] — this method alone never forces a
    /// flush the instant 10 s elapses with nothing left to report. That
    /// half of the contract is deliberate: the aggregation exists to
    /// bound audit *volume under sustained load*, and a category that
    /// stops producing rejections has nothing left to warn about here.
    /// The *other* half — a flood that stops still gets its last window's
    /// summary within one more tick, even with no further rejection to
    /// trigger this path — is [`Gate::flush_expired`]'s job, called on a
    /// schedule by the accept loop, not this method's.
    fn record_rejection(
        &self,
        reason: RejectReason,
        peer: SocketAddr,
        now: Instant,
    ) -> Vec<AuditRecord> {
        let window = &self.windows[reason as usize];
        let mut guard = window.state.lock().unwrap_or_else(|e| e.into_inner());
        let window_is_fresh = match guard.start {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= AUDIT_AGGREGATION_WINDOW,
        };
        if !window_is_fresh {
            // Same critical section as the freshness check above — no gap
            // a concurrent `flush_expired` could land its `swap` inside
            // (verification round P3-4, this struct's own doc).
            guard.suppressed = guard.suppressed.saturating_add(1);
            return Vec::new();
        }
        let prior_suppressed = guard.suppressed;
        guard.suppressed = 0;
        guard.start = Some(now);
        drop(guard);
        let mut records = Vec::with_capacity(2);
        if prior_suppressed > 0 {
            records.push(AuditRecord::handshake_rejected_summary(
                reason.category(),
                prior_suppressed,
            ));
        }
        records.push(AuditRecord::handshake_rejected(peer, reason.category()));
        records
    }

    /// Force-close every category window whose `start` is at least
    /// [`AUDIT_AGGREGATION_WINDOW`] old, emitting a
    /// [`AuditRecord::handshake_rejected_summary`] for any that suppressed
    /// at least one rejection (`PLAN.md` M8 Step 2 verification round,
    /// P1-3/F1). The accept loop calls this once per tick of a
    /// `tokio::time::interval(AUDIT_AGGREGATION_WINDOW)` in its `select!`
    /// (plus once more on shutdown) so a category's last window closes on
    /// a bounded schedule even when the flood that filled it has already
    /// stopped and nothing will ever call `Gate::record_rejection`
    /// again to flush it lazily. A window with no `start` (never opened)
    /// or one still inside the aggregation window is left untouched — the
    /// *next* rejection (if any) is still the one that opens/continues it,
    /// exactly as before this method existed.
    pub fn flush_expired(&self, now: Instant) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        for (window, reason) in self.windows.iter().zip(RejectReason::ALL.iter().copied()) {
            let mut guard = window.state.lock().unwrap_or_else(|e| e.into_inner());
            let Some(start) = guard.start else { continue };
            if now.saturating_duration_since(start) < AUDIT_AGGREGATION_WINDOW {
                continue;
            }
            let suppressed = guard.suppressed;
            guard.start = None;
            guard.suppressed = 0;
            drop(guard);
            if suppressed > 0 {
                records.push(AuditRecord::handshake_rejected_summary(
                    reason.category(),
                    suppressed,
                ));
            }
        }
        records
    }

    /// Raw storage-pointer identity of the unvalidated-axis sketch's
    /// backing arrays — the measurable proxy
    /// [`gate_table_is_constant_size_under_forged_cardinality`] uses to
    /// demonstrate the table cannot grow: a `Vec`'s data pointer only
    /// ever changes when it reallocates, and nothing in [`Sketch`] ever
    /// calls `push`/`resize`/`reserve` on `gens` after [`SketchRow::new`]
    /// allocates it once at construction — every operation past that
    /// point indexes into the fixed length. If the pointers returned here
    /// are bit-identical before and after driving [`Gate::decide`] with
    /// 10⁵ distinct synthetic sources, the table's footprint provably did
    /// not move, let alone grow.
    #[cfg(test)]
    fn sketch_storage_pointers(&self) -> Vec<*const AtomicU32> {
        self.sketch.storage_pointers()
    }

    /// [`Gate::sketch_storage_pointers`]'s twin for the **validated**-axis
    /// sketch (P2-3, design §2.7 U17) — the second, independent fixed-size
    /// table [`Gate::decide`]'s validated branch drives.
    #[cfg(test)]
    fn validated_sketch_storage_pointers(&self) -> Vec<*const AtomicU32> {
        self.validated_sketch.storage_pointers()
    }
}

#[cfg(test)]
mod tests;
