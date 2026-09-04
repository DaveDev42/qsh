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
use std::sync::atomic::{AtomicU32, Ordering};
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
/// the window has run past this bound (see [`Gate::record_rejection`]'s
/// doc), *and* on a bounded schedule — both `crate::server::Server::run`
/// and `crate::reverse::listen::Listen::run` tick
/// [`Gate::flush_expired`] every `AUDIT_AGGREGATION_WINDOW` off a
/// `tokio::time::interval` in their accept-loop `select!`, plus once more
/// when the loop exits. So a flood's last (possibly partial) window's
/// summary is never delayed past one more tick after the flood stops —
/// not "possibly never", as it was when only the lazy path existed.
pub(crate) const AUDIT_AGGREGATION_WINDOW: Duration = Duration::from_secs(10);

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
    /// address, but tracked in its own [`Sketch`] so a spoofed
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

#[cfg(test)]
impl AuditWindow {
    /// Whether this window is still open (`state.start.is_some()`) —
    /// test-only, so a pin can assert the window a `flush_expired` just
    /// closed is *actually* closed (`start` reset to `None`) rather than
    /// merely re-stamped with a fresh `start` that happens to also pass a
    /// "was it reported" assertion (`crate::quota`'s twin of this module's
    /// own `flush_expired`/`WindowState` shape shares this helper).
    pub(crate) fn is_open(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .start
            .is_some()
    }
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
                return Decision::Ignore(RejectReason::RateLimited, records);
            }
            return Decision::Retry;
        }
        if self.rate_exceeded(
            &self.validated_sketch,
            self.validated_rate_per_source,
            peer,
            now,
        ) {
            let records = self.record_rejection(RejectReason::ValidatedRateLimited, peer, now);
            return Decision::Refuse(RejectReason::ValidatedRateLimited, records);
        }
        match self.handshake_permits.clone().try_acquire_owned() {
            Ok(permit) => Decision::Admit(permit),
            Err(_) => {
                let records = self.record_rejection(RejectReason::AtCapacity, peer, now);
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
    /// stopped and nothing will ever call [`Gate::record_rejection`]
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
mod tests {
    use super::*;
    use crate::broker::TestClock;
    use std::net::Ipv4Addr;

    fn addr(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// `Decision` has no `Debug` impl (`Decision::Admit` holds an
    /// `OwnedSemaphorePermit`, which doesn't implement it either) — this
    /// is the panic-message-only stand-in the newer tests below use
    /// instead of `{other:?}`.
    fn decision_kind(d: &Decision) -> &'static str {
        match d {
            Decision::Retry => "Retry",
            Decision::Ignore(..) => "Ignore",
            Decision::Refuse(..) => "Refuse",
            Decision::Admit(_) => "Admit",
        }
    }

    /// `PLAN.md` M8 Step 2 design §8 — the concurrency cap: the first
    /// `max_concurrent_handshakes` validated attempts are all `Admit`ted,
    /// and the next one is `Refuse`d with an `AtCapacity` audit record
    /// while every earlier permit is still held.
    #[tokio::test]
    async fn gate_admits_then_refuses_at_cap() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 2, 10, 10);
        let peer = addr(v4(203, 0, 113, 1), 1);

        let permit1 = match gate.decide(peer, true, gate.now()) {
            Decision::Admit(p) => p,
            _ => panic!("expected Admit"),
        };
        let permit2 = match gate.decide(peer, true, gate.now()) {
            Decision::Admit(p) => p,
            _ => panic!("expected Admit"),
        };
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::AtCapacity, records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].resource, "at_capacity");
                assert_eq!(records[0].peer_addr, peer.to_string());
                assert!(
                    records[0].count.is_none(),
                    "first rejection carries no count"
                );
            }
            _ => panic!("expected Refuse(AtCapacity)"),
        }
        drop((permit1, permit2));
    }

    /// `PLAN.md` M8 Step 2 design §8 — dropping the permit returned by
    /// `Admit` (standing in for the handshake resolving, `Decision::Admit`'s
    /// own doc) frees the slot for a later attempt.
    #[tokio::test]
    async fn gate_releases_permit_on_handshake_completion() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 1, 10, 10);
        let peer = addr(v4(203, 0, 113, 2), 1);

        let permit = match gate.decide(peer, true, gate.now()) {
            Decision::Admit(p) => p,
            _ => panic!("expected Admit"),
        };
        assert_eq!(gate.available_permits(), 0);
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(..) => {}
            _ => panic!("expected Refuse while the permit is held"),
        }
        drop(permit); // the handshake "resolved"
        assert_eq!(gate.available_permits(), 1);
        match gate.decide(peer, true, gate.now()) {
            Decision::Admit(_) => {}
            _ => panic!("expected Admit once the permit was released"),
        }
    }

    /// `PLAN.md` M8 Step 2 design §8 — an unvalidated source under the
    /// rate limit is always `Retry`d (never audited); once it exceeds
    /// `rate_per_source * 2` (burst) within one epoch it is `Ignore`d
    /// with a `RateLimited` record, and advancing the clock past the next
    /// epoch boundary lets it through again.
    #[tokio::test]
    async fn gate_throttles_per_source_and_recovers_next_window() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 5, 10); // burst = 10
        let peer = addr(v4(198, 51, 100, 7), 4242);

        let mut retried = 0;
        let mut ignored = 0;
        for _ in 0..10 {
            match gate.decide(peer, false, gate.now()) {
                Decision::Retry => retried += 1,
                Decision::Ignore(RejectReason::RateLimited, _) => ignored += 1,
                _ => panic!("unvalidated attempt must be Retry or Ignore"),
            }
        }
        assert_eq!(retried, 10, "all 10 attempts are within burst=10");
        assert_eq!(ignored, 0);

        match gate.decide(peer, false, gate.now()) {
            Decision::Ignore(RejectReason::RateLimited, records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].resource, "rate_limited");
            }
            _ => panic!("the 11th attempt in one epoch must be throttled"),
        }

        // Cross two full epoch boundaries so both generations are clear
        // of this source's history (the sliding-window blend still
        // weights the immediately-prior epoch otherwise).
        clock.advance(EPOCH * 2);
        match gate.decide(peer, false, gate.now()) {
            Decision::Retry => {}
            _ => panic!("expected recovery after the window passed"),
        }
    }

    /// `PLAN.md` M8 Step 2 design §8 — two IPv6 addresses sharing a /64
    /// share a rate-limit bucket; a different /64 does not.
    #[tokio::test]
    async fn gate_keys_ipv6_by_64_prefix() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 2, 10); // burst = 4

        let same_prefix_a = addr(IpAddr::V6("2001:db8:1234:5678::1".parse().unwrap()), 1);
        let same_prefix_b = addr(
            IpAddr::V6("2001:db8:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap()),
            2,
        );
        let different_prefix = addr(IpAddr::V6("2001:db8:1234:9999::1".parse().unwrap()), 3);

        // Exhaust the shared /64's burst using both addresses.
        for _ in 0..4 {
            assert!(matches!(
                gate.decide(same_prefix_a, false, gate.now()),
                Decision::Retry
            ));
        }
        // The *second* address in the same /64 is already over budget —
        // proof the two share one bucket, not two.
        assert!(matches!(
            gate.decide(same_prefix_b, false, gate.now()),
            Decision::Ignore(RejectReason::RateLimited, _)
        ));
        // A genuinely different /64 has its own, untouched budget.
        assert!(matches!(
            gate.decide(different_prefix, false, gate.now()),
            Decision::Retry
        ));
    }

    /// `PLAN.md` M8 Step 2 design §8 — the sketch's backing storage
    /// cannot grow no matter how many distinct (forged) source addresses
    /// pass through `decide`. Proxy: pointer identity of the sketch's
    /// backing `Vec`s (see `Gate::sketch_storage_pointers`'s doc for why
    /// that is a valid, measurable stand-in for "no allocation growth")
    /// stays bit-for-bit identical before and after 10⁵ distinct
    /// synthetic sources — the forged cardinality this test drives.
    #[tokio::test]
    async fn gate_table_is_constant_size_under_forged_cardinality() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 10, 10);
        let before = gate.sketch_storage_pointers();

        const FORGED_SOURCES: u32 = 100_000;
        for i in 0..FORGED_SOURCES {
            let ip = v4((i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8);
            let peer = addr(ip, 1);
            // Ignore the outcome — the point is that `decide` never
            // panics and never needs to allocate to accommodate a source
            // it has never seen before.
            let _ = gate.decide(peer, false, gate.now());
        }

        let after = gate.sketch_storage_pointers();
        assert_eq!(
            before, after,
            "the sketch's backing storage must never reallocate, regardless of source cardinality"
        );
    }

    /// `PLAN.md` M8 Step 2 design §8 — false-positive rate under a flood
    /// of forged sources. **Forged cardinality tested at: 5,000** distinct
    /// spoofed sources, each firing once within the same epoch (expected
    /// load ≈ 5000/1024 ≈ 4.9 events per column per row) — chosen as a
    /// flood dense enough to load the sketch meaningfully while the
    /// legitimate traffic below stays well under `burst_limit`; asserts
    /// under 1% of 1,000 independent legitimate low-rate sources are
    /// incorrectly throttled by hash collisions with the forged flood.
    #[tokio::test]
    async fn gate_false_positive_rate_under_flood() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 10, 10); // burst = 20
        let now = gate.now();

        const FORGED_SOURCES: u32 = 5_000;
        for i in 0..FORGED_SOURCES {
            // Offset well clear of the legitimate range below.
            let ip = v4(10, (i >> 16) as u8, (i >> 8) as u8, i as u8);
            let _ = gate.decide(addr(ip, 1), false, now);
        }

        const LEGITIMATE_SOURCES: u32 = 1_000;
        const LEGITIMATE_REQUESTS_PER_SOURCE: u32 = 5; // well under burst=20
        let mut throttled = 0u32;
        for i in 0..LEGITIMATE_SOURCES {
            // 203.0.0.0/8 range, distinct from the 10.0.0.0/8 forged range
            // above — plenty of distinct /32s for 1,000 legitimate
            // sources.
            let ip = v4(203, (i >> 16) as u8, (i >> 8) as u8, i as u8);
            let peer = addr(ip, 1);
            let mut this_source_throttled = false;
            for _ in 0..LEGITIMATE_REQUESTS_PER_SOURCE {
                if matches!(
                    gate.decide(peer, false, now),
                    Decision::Ignore(RejectReason::RateLimited, _)
                ) {
                    this_source_throttled = true;
                }
            }
            if this_source_throttled {
                throttled += 1;
            }
        }

        let fp_rate = throttled as f64 / LEGITIMATE_SOURCES as f64;
        assert!(
            fp_rate < 0.01,
            "false-positive rate {fp_rate:.4} ({throttled}/{LEGITIMATE_SOURCES}) must stay \
             under 1% at {FORGED_SOURCES} forged sources"
        );
    }

    /// `M8 Step 4` (`ARBITRATION-4.md` J4): the time axis
    /// `gate_table_is_constant_size_under_forged_cardinality` doesn't
    /// cover — a sustained unvalidated (spoofable) flood that keeps
    /// firing across many [`EPOCH`] generation rollovers must still
    /// never grow the sketch's backing storage and must never touch the
    /// handshake permit pool, no matter how many generations have
    /// rotated through the sliding-window blend
    /// ([`Gate::rate_exceeded`]'s epoch/fraction math).
    #[tokio::test]
    async fn gate_state_and_permits_survive_generation_rollovers_under_sustained_forged_flood() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 8, 10, 10);
        let before_pointers = gate.sketch_storage_pointers();
        let before_permits = gate.available_permits();

        const GENERATIONS: u32 = 50;
        const SOURCES_PER_GENERATION: u32 = 200;
        for generation in 0..GENERATIONS {
            for i in 0..SOURCES_PER_GENERATION {
                // A fresh forged /32 every attempt, reused across
                // generations by (generation, i) so the flood is both
                // wide (cardinality) and sustained (keeps firing across
                // rollovers) rather than a one-shot burst.
                let ip = v4(10, (generation % 256) as u8, (i >> 8) as u8, i as u8);
                let peer = addr(ip, 1);
                // Unvalidated: outcome doesn't matter here — the
                // invariant is what it never does (grow storage, touch
                // the permit pool), which
                // `unvalidated_peer_never_touches_the_permit_pool_even_at_cap_zero`
                // already pins per-call; this test pins it across time.
                let _ = gate.decide(peer, false, gate.now());
            }
            clock.advance(EPOCH);
        }

        let after_pointers = gate.sketch_storage_pointers();
        assert_eq!(
            before_pointers, after_pointers,
            "the sketch's backing storage must never reallocate across EPOCH generation \
             rollovers, regardless of sustained forged-source cardinality"
        );
        assert_eq!(
            gate.available_permits(),
            before_permits,
            "a sustained unvalidated flood must never consume a handshake permit, across any \
             number of EPOCH generation rollovers"
        );

        // `ARBITRATION-4.md` M8 Step 4 fixer round F2 (A-P2-2): the two
        // asserts above are both time-invariant regardless of whether
        // `Sketch::advance_to` ever actually rolls a generation over —
        // storage never reallocates and an unvalidated decide never
        // touches the permit pool either way (P2-2's mutation experiment:
        // gutting `advance_to` to a no-op `return;` still passes both).
        // What's missing is a load-bearing check *of the rollover itself*
        // — that generations are really rotating, not just that nothing
        // visibly breaks if they don't. Two more, on the still-forged
        // `gate`/`clock` above:
        //
        // (a) a single legitimate source amid the flood is never a false
        // positive — sketch saturation from 50 generations × 200 forged
        // sources/generation must not spill onto an honest source's own
        // estimate.
        let honest = addr(v4(192, 168, 0, 7), 1);
        assert!(
            matches!(gate.decide(honest, false, gate.now()), Decision::Retry),
            "a legitimate source amid a sustained forged flood spanning many EPOCH rollovers \
             must not be falsely throttled"
        );

        // (b) a single *sustained* source, pushed past `burst_limit` (=
        // `rate_per_source * EPOCH.as_secs()` = 10 * 2 = 20, this gate's
        // own `rate_exceeded` doc) within one generation, is throttled —
        // and two EPOCH rollovers later the same source is admitted
        // again, which only happens if `advance_to` actually resets its
        // counters rather than merely leaving old ones in place forever.
        let noisy = addr(v4(203, 0, 113, 9), 1);
        for i in 1..=20 {
            match gate.decide(noisy, false, gate.now()) {
                Decision::Retry => {}
                other => panic!(
                    "burst attempt {i}/20 within one epoch must be Retry, got {}",
                    decision_kind(&other)
                ),
            }
        }
        assert!(
            matches!(
                gate.decide(noisy, false, gate.now()),
                Decision::Ignore(RejectReason::RateLimited, _)
            ),
            "the 21st attempt within one epoch must be throttled once burst_limit=20 is exceeded"
        );
        clock.advance(EPOCH);
        clock.advance(EPOCH);
        assert!(
            matches!(gate.decide(noisy, false, gate.now()), Decision::Retry),
            "two EPOCH rollovers after being throttled, the same source must be admitted again \
             — proof the rollover actually resets its counters, not just that nothing crashes \
             if it doesn't"
        );
    }

    /// `PLAN.md` M8 Step 2 verification round, P1-2: pins the L2-before-L3
    /// ordering `Gate::decide`'s own doc claims — an *unvalidated* peer is
    /// never charged against the handshake-concurrency semaphore, even
    /// with the cap already exhausted (`max_concurrent_handshakes = 0`
    /// here, the extreme case). Under mutation M4 (acquire the permit
    /// before the validated check), this becomes `Refuse`, not `Retry`,
    /// and reflects a `CONNECTION_REFUSED` at a spoofable address instead
    /// of silently retrying it — the adversarial report's own finding.
    #[tokio::test]
    async fn unvalidated_peer_never_touches_the_permit_pool_even_at_cap_zero() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 0, 10, 10);
        let peer = addr(v4(198, 51, 100, 20), 1);

        let before = gate.available_permits();
        assert_eq!(before, 0, "cap=0 starts with zero permits, not unlimited");

        match gate.decide(peer, false, gate.now()) {
            Decision::Retry => {}
            other => panic!(
                "an unvalidated peer at cap=0 must still be Retry (never Refuse) — the \
                 rate limit, not the semaphore, is what an unvalidated attempt can ever \
                 fail against; got {}",
                decision_kind(&other)
            ),
        }
        assert_eq!(
            gate.available_permits(),
            before,
            "an unvalidated Retry must never touch the permit pool"
        );

        // A validated peer at the same cap=0 is the contrasting case:
        // Refuse, from the semaphore, not the rate limiter.
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::AtCapacity, _) => {}
            other => panic!(
                "a validated peer at cap=0 must be Refuse(AtCapacity), got {}",
                decision_kind(&other)
            ),
        }
        assert_eq!(gate.available_permits(), 0);
    }

    /// `PLAN.md` M8 Step 2 verification round, P1-3/F1: pins
    /// [`Gate::flush_expired`] without any real wall-clock wait —
    /// `Gate` is clock-injected precisely so this doesn't need one.
    /// Reject `n` times (all suppressed after the first), advance the
    /// clock past [`AUDIT_AGGREGATION_WINDOW`], flush: exactly one
    /// summary record with `count == Some(n - 1)` and `peer_addr == "-"`.
    /// A second flush with nothing new to report yields nothing — the
    /// window was already closed by the first flush, not left open to
    /// double-report.
    #[tokio::test]
    async fn gate_flush_expired_emits_exactly_one_summary_after_the_window_closes() {
        let clock = Arc::new(TestClock::new());
        // cap=0: every attempt is a deterministic AtCapacity rejection —
        // no rate-limit interaction to account for.
        let gate = Gate::new(clock.clone(), 0, 10, 10);
        let peer = addr(v4(198, 51, 100, 21), 1);

        const REJECTIONS: usize = 7;
        for _ in 0..REJECTIONS {
            match gate.decide(peer, true, gate.now()) {
                Decision::Refuse(RejectReason::AtCapacity, _) => {}
                other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
            }
        }

        // Nothing to flush yet — the window is still open.
        assert!(
            gate.flush_expired(gate.now()).is_empty(),
            "flush_expired must not fire before the window has run past \
             AUDIT_AGGREGATION_WINDOW"
        );

        clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
        let flushed = gate.flush_expired(gate.now());
        assert_eq!(
            flushed.len(),
            1,
            "expected exactly one summary record, got {flushed:?}"
        );
        assert_eq!(flushed[0].resource, "at_capacity");
        assert_eq!(
            flushed[0].count,
            Some((REJECTIONS - 1) as u32),
            "the first rejection was reported immediately (not suppressed); the summary \
             covers only the remaining {} suppressed ones",
            REJECTIONS - 1
        );
        assert_eq!(
            flushed[0].peer_addr, "-",
            "the summary row never carries an observed address"
        );

        // The window is now closed — a second flush at the same instant
        // (or later, with no new rejection in between) reports nothing.
        assert!(
            gate.flush_expired(gate.now()).is_empty(),
            "a closed window with nothing new since must not re-emit a summary"
        );
    }

    /// `PLAN.md` M8 Step 2 verification round, F2/item 4: pins the
    /// corrected rate semantics with a `TestClock` and wide margins —
    /// `rate_per_source = 10` ⇒ `burst_limit = 10 * EPOCH.as_secs() = 20`.
    ///
    /// - Sustained 5/s (well under the 10/s budget) for 6 s: never
    ///   throttled.
    /// - A burst of 20 fired back-to-back within one epoch (a fresh
    ///   source, so the blended-previous-epoch term is 0): every one of
    ///   the 20 is `Retry`; the 21st is `Ignore`.
    /// - Sustained 15/s (over the 10/s budget): throttled before the
    ///   first epoch (2 s) even completes.
    #[tokio::test]
    async fn gate_rate_limit_bounds_sustained_rate_not_just_instantaneous_burst() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 10, 10); // burst_limit = 20
        let five_per_sec = addr(v4(198, 51, 100, 22), 1);
        let burst_peer = addr(v4(198, 51, 100, 23), 1);
        let fifteen_per_sec = addr(v4(198, 51, 100, 24), 1);

        // Sustained 5/s (200 ms apart) for 6 s = 30 attempts, all Retry.
        for tick in 0..30 {
            match gate.decide(five_per_sec, false, gate.now()) {
                Decision::Retry => {}
                other => panic!(
                    "sustained 5/s (well under the 10/s budget) must never be throttled — \
                     tick {tick} got {}",
                    decision_kind(&other)
                ),
            }
            clock.advance(Duration::from_millis(200));
        }

        // 20 back-to-back attempts from a fresh source, same instant: all
        // Retry (estimate climbs 1..=20, burst_limit is 20, `>` not `>=`).
        for i in 1..=20 {
            match gate.decide(burst_peer, false, gate.now()) {
                Decision::Retry => {}
                other => panic!(
                    "burst attempt {i}/20 within one epoch must be Retry, got {}",
                    decision_kind(&other)
                ),
            }
        }
        match gate.decide(burst_peer, false, gate.now()) {
            Decision::Ignore(RejectReason::RateLimited, _) => {}
            other => panic!(
                "the 21st attempt within one epoch must be Ignore, got {}",
                decision_kind(&other)
            ),
        }

        // Sustained 15/s (≈66.7 ms apart): must be ignored before the
        // first 2 s epoch completes.
        let mut ignored_before_2s = false;
        let mut elapsed = Duration::ZERO;
        while elapsed < Duration::from_secs(2) {
            if matches!(
                gate.decide(fifteen_per_sec, false, gate.now()),
                Decision::Ignore(RejectReason::RateLimited, _)
            ) {
                ignored_before_2s = true;
                break;
            }
            clock.advance(Duration::from_millis(67));
            elapsed += Duration::from_millis(67);
        }
        assert!(
            ignored_before_2s,
            "sustained 15/s (over the 10/s budget) must be throttled before t = 2s"
        );
    }

    /// Mutation-testing round 4, N10 + X2: pins that both flush paths —
    /// `record_rejection`'s lazy flush *and* `flush_expired`'s scheduled
    /// flush — reset `guard.suppressed = 0` when they close a window, not
    /// just report its count. A mutant that drops either reset leaks the
    /// closed window's count into the *next* window's tally, so that
    /// window's own (correctly small) suppressed count gets over-reported
    /// later. This also pins X2 — `record_rejection`'s own lazy-flush
    /// summary push (distinct from `flush_expired`'s) — since the first
    /// assertion block only passes if that push still runs.
    ///
    /// Sequence: window 1 gets 3 rejections (1 first row + 2 suppressed);
    /// advancing past the window and rejecting again closes window 1
    /// lazily, returning exactly `[summary(count=Some(2)), first_row]`.
    /// Window 2 then gets 2 more rejections (both suppressed, no records).
    /// Advancing past the window and calling `flush_expired` must report
    /// `count == Some(2)` — a leaked counter from window 1 would report
    /// `4`. Finally, a fresh window's first rejection carries no summary
    /// at all — nothing was suppressed in it yet.
    #[tokio::test]
    async fn gate_record_rejection_and_flush_expired_both_reset_suppressed_not_just_report_it() {
        let clock = Arc::new(TestClock::new());
        // cap=0: every validated attempt is a deterministic AtCapacity
        // rejection.
        let gate = Gate::new(clock.clone(), 0, 10, 10);
        let peer = addr(v4(198, 51, 100, 30), 1);

        // Window 1: 3 rejections — 1 first-occurrence row + 2 suppressed.
        for _ in 0..3 {
            match gate.decide(peer, true, gate.now()) {
                Decision::Refuse(RejectReason::AtCapacity, _) => {}
                other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
            }
        }

        clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));

        // This rejection opens window 2 and, in the same call, lazily
        // closes window 1 (`record_rejection`'s doc) — exactly
        // [summary(count=Some(2)), first_row_of_window_2].
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::AtCapacity, records) => {
                assert_eq!(
                    records.len(),
                    2,
                    "expected [summary, first_row] closing window 1, got {records:?}"
                );
                assert_eq!(records[0].resource, "at_capacity");
                assert_eq!(
                    records[0].count,
                    Some(2),
                    "window 1 suppressed exactly 2 of its 3 rejections"
                );
                assert_eq!(
                    records[0].peer_addr, "-",
                    "the summary row never carries an observed address"
                );
                assert!(
                    records[1].count.is_none(),
                    "window 2's own first row carries no count"
                );
                assert_eq!(records[1].peer_addr, peer.to_string());
            }
            other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
        }

        // Window 2: 2 more rejections, both suppressed — no records
        // returned for either (same-window suppression never reports
        // synchronously).
        for _ in 0..2 {
            match gate.decide(peer, true, gate.now()) {
                Decision::Refuse(RejectReason::AtCapacity, records) => {
                    assert!(
                        records.is_empty(),
                        "a suppressed rejection inside an open window must carry no \
                         records, got {records:?}"
                    );
                }
                other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
            }
        }

        clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));

        // `flush_expired` closes window 2. If either flush path failed to
        // reset `suppressed`, this would report 4 (2 leaked from window 1
        // plus window 2's own 2), not window 2's real count of 2.
        let flushed = gate.flush_expired(gate.now());
        assert_eq!(
            flushed.len(),
            1,
            "expected exactly one summary closing window 2, got {flushed:?}"
        );
        assert_eq!(flushed[0].resource, "at_capacity");
        assert_eq!(
            flushed[0].count,
            Some(2),
            "window 2 suppressed exactly 2 — a leaked counter from window 1 would \
             report 4 instead"
        );
        assert_eq!(
            flushed[0].peer_addr, "-",
            "the summary row never carries an observed address"
        );

        // A fresh window (3) opens on the next rejection with nothing
        // carried over from window 2, which `flush_expired` already
        // closed above — its first row must come alone, no summary.
        clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::AtCapacity, records) => {
                assert_eq!(
                    records.len(),
                    1,
                    "a fresh window's first rejection must carry only its own first-row \
                     record, no leftover summary from window 2: {records:?}"
                );
                assert!(
                    records[0].count.is_none(),
                    "the fresh window's first row carries no count"
                );
                assert_eq!(records[0].peer_addr, peer.to_string());
            }
            other => panic!("expected Refuse(AtCapacity), got {}", decision_kind(&other)),
        }
    }

    /// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U15) — the validated-axis
    /// rate limiter sits *ahead* of the handshake semaphore, exactly the
    /// `AtCapacity` axis's own ordering: an attempt that loses only to
    /// its own rate budget must never dent `available_permits()`.
    #[tokio::test]
    async fn validated_rate_limit_rejects_without_taking_a_permit() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 10, 5); // validated burst = 10
        let peer = addr(v4(203, 0, 113, 40), 1);

        let mut held_permits = Vec::new();
        for i in 1..=10 {
            match gate.decide(peer, true, gate.now()) {
                Decision::Admit(p) => held_permits.push(p),
                other => panic!(
                    "attempt {i}/10 within the validated burst must be Admit, got {}",
                    decision_kind(&other)
                ),
            }
        }
        let permits_before = gate.available_permits();

        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::ValidatedRateLimited, records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].resource, "validated_rate_limited");
                assert_eq!(records[0].peer_addr, peer.to_string());
                assert!(
                    records[0].count.is_none(),
                    "first rejection carries no count"
                );
            }
            other => panic!(
                "the 11th validated attempt within one epoch must be \
                 Refuse(ValidatedRateLimited), got {}",
                decision_kind(&other)
            ),
        }
        assert_eq!(
            gate.available_permits(),
            permits_before,
            "a validated-rate rejection must never touch the handshake permit pool"
        );
        drop(held_permits);
    }

    /// `validated_rate_limit_rejects_without_taking_a_permit` only compares
    /// `available_permits()` *before* and *after* the call, which cannot
    /// tell "never acquired" apart from "acquired, then released on the
    /// way out" — this one watches the pool *during* a validated-rate
    /// flood: with `validated_rate_per_source = 0` every validated attempt
    /// is a rate-axis rejection, so the single handshake permit must read
    /// `1` at every instant a concurrent reader samples it. Capped at a
    /// fixed iteration count (well under the adversarial source's
    /// 2,000,000) so it runs in well under a second.
    #[test]
    fn validated_rate_rejection_never_dips_the_permit_pool_even_transiently() {
        const SAMPLES: usize = 200_000;

        let clock = Arc::new(TestClock::new());
        let gate = Arc::new(Gate::new(clock.clone(), 1, 10, 0));
        let peer = addr(v4(198, 51, 100, 77), 1);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let flood_gate = Arc::clone(&gate);
        let flood_stop = Arc::clone(&stop);
        let flooder = std::thread::spawn(move || {
            while !flood_stop.load(Ordering::Relaxed) {
                let now = flood_gate.now();
                match flood_gate.decide(peer, true, now) {
                    Decision::Refuse(RejectReason::ValidatedRateLimited, _) => {}
                    other => panic!(
                        "every validated attempt at rate 0 must be \
                         ValidatedRateLimited, got {}",
                        decision_kind(&other)
                    ),
                }
            }
        });

        let mut dips = 0usize;
        for _ in 0..SAMPLES {
            if gate.available_permits() != 1 {
                dips += 1;
            }
        }
        stop.store(true, Ordering::Relaxed);
        flooder.join().unwrap();
        assert_eq!(
            dips, 0,
            "a validated-rate rejection must never take a handshake permit, \
             not even transiently"
        );
    }

    /// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U16), both directions: the
    /// two axes are tracked in genuinely independent `Sketch`es, so a
    /// flood on one axis from a given address never spends the other
    /// axis's budget for that same address.
    #[tokio::test]
    async fn unvalidated_flood_does_not_consume_a_validated_sources_budget() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 5, 5); // both bursts = 10
        let peer = addr(v4(203, 0, 113, 41), 1);

        // Flood the unvalidated axis well past its own burst from this
        // address — the validated axis must not notice.
        for _ in 0..15 {
            let _ = gate.decide(peer, false, gate.now());
        }
        match gate.decide(peer, true, gate.now()) {
            Decision::Admit(_) => {}
            other => panic!(
                "a validated attempt from an address that only flooded the unvalidated \
                 axis must still be Admit, got {}",
                decision_kind(&other)
            ),
        }

        // And the reverse: flood a fresh address's validated axis past
        // its own burst — the unvalidated axis for that same address
        // must still see a clean slate.
        let other_peer = addr(v4(203, 0, 113, 43), 1);
        for _ in 0..15 {
            let _ = gate.decide(other_peer, true, gate.now());
        }
        match gate.decide(other_peer, false, gate.now()) {
            Decision::Retry => {}
            other => panic!(
                "an unvalidated attempt from an address that only flooded the validated \
                 axis must still be Retry, got {}",
                decision_kind(&other)
            ),
        }
    }

    /// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U17) — the validated-axis
    /// sketch's twin of `gate_table_is_constant_size_under_forged_cardinality`:
    /// its backing storage must never reallocate regardless of how many
    /// distinct validated addresses an attacker forges.
    #[tokio::test]
    async fn validated_rate_state_is_constant_size_under_forged_cardinality() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 10, 10);
        let before = gate.validated_sketch_storage_pointers();

        const FORGED_SOURCES: u32 = 100_000;
        for i in 0..FORGED_SOURCES {
            let ip = v4((i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8);
            let peer = addr(ip, 1);
            let _ = gate.decide(peer, true, gate.now());
        }

        let after = gate.validated_sketch_storage_pointers();
        assert_eq!(
            before, after,
            "the validated-axis sketch's backing storage must never reallocate, \
             regardless of source cardinality"
        );
    }

    /// `PLAN.md` M8 Step 3 P2-3 (design §4.3, U18) — pins the documented
    /// default (`[serve].validated_rate_per_source = 10`, `docs/CLI.md`
    /// §6.12): a sustained validated source at exactly the burst ceiling
    /// (20 within one epoch, same `rate × EPOCH.as_secs()` formula as the
    /// unvalidated axis) always passes, and the 21st trips
    /// `ValidatedRateLimited`.
    #[tokio::test]
    async fn validated_rate_threshold_matches_the_documented_sustained_rate() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(
            clock.clone(),
            64,
            10,
            crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
        );
        let peer = addr(v4(203, 0, 113, 42), 1);
        let mut held_permits = Vec::new();

        for i in 1..=20 {
            match gate.decide(peer, true, gate.now()) {
                Decision::Admit(p) => held_permits.push(p),
                other => panic!(
                    "attempt {i}/20 at the documented default validated rate must be \
                     Admit, got {}",
                    decision_kind(&other)
                ),
            }
        }
        match gate.decide(peer, true, gate.now()) {
            Decision::Refuse(RejectReason::ValidatedRateLimited, _) => {}
            other => panic!(
                "the 21st validated attempt at the documented default (10/s, burst 20) \
                 must be ValidatedRateLimited, got {}",
                decision_kind(&other)
            ),
        }
        drop(held_permits);
    }

    /// `PLAN.md` M8 Step 3, verdict ruling 10's U18 twin (F3 of the M8
    /// Step 3a conformance sweep — `validated_rate_threshold_matches_
    /// the_documented_sustained_rate` above proves only the validated
    /// axis, at a single instant; the ADR-0010 draft cited it as the
    /// two-axis cadence pin, which it is not). One source dials at a
    /// truly *sustained* 10/s — one dial every `EPOCH / RATE` (100 ms),
    /// not `RATE * EPOCH.as_secs()` (20) dials bursted at each epoch
    /// boundary — across several epochs, each dial driving *both* axes
    /// the way a real client does: `decide(peer, false, …)` (Initial,
    /// always `Retry` below the unvalidated ceiling) followed by
    /// `decide(peer, true, …)` (post-Retry-roundtrip, `Admit` below the
    /// validated ceiling, permit dropped immediately — a completed
    /// handshake, not a held one).
    ///
    /// The even spacing matters, not just the total: [`Sketch::
    /// record_and_estimate`]'s two-generation estimator weights the
    /// *previous* epoch's count by `1 - fraction_into_epoch`, so 20
    /// events bursted at one epoch's very start followed by 20 more
    /// bursted at the very next epoch's start would double-count (the new
    /// epoch's first event already sees the full, undecayed previous
    /// count) — correctly rejecting a burst that only *looks* like two
    /// separate epochs' worth of budget, but not what "sustained 10/s"
    /// means. Spreading the same total count evenly is what a genuinely
    /// paced dialer looks like, and neither axis may ever reject it — a
    /// coupling regression between the two independently-sketched axes,
    /// or an off-by-one in the sliding-window math, would show up here
    /// even though it passes U18 (which never calls `TestClock::advance`
    /// at all).
    #[tokio::test]
    async fn one_source_dialing_at_a_sustained_rate_passes_both_axes_across_epochs() {
        let clock = Arc::new(TestClock::new());
        let gate = Gate::new(clock.clone(), 64, 10, 10);
        let peer = addr(v4(203, 0, 113, 44), 1);

        const RATE_PER_SEC: u32 = 10;
        const EPOCHS: u32 = 4;
        let dial_interval = EPOCH / RATE_PER_SEC;
        let total_dials = RATE_PER_SEC * EPOCHS * (EPOCH.as_secs() as u32);

        for dial in 1..=total_dials {
            match gate.decide(peer, false, gate.now()) {
                Decision::Retry => {}
                other => panic!(
                    "dial {dial}/{total_dials}: the unvalidated axis of a sustained \
                     10/s dialer must stay Retry, got {}",
                    decision_kind(&other)
                ),
            }
            match gate.decide(peer, true, gate.now()) {
                Decision::Admit(permit) => drop(permit),
                other => panic!(
                    "dial {dial}/{total_dials}: the validated axis of a sustained \
                     10/s dialer must stay Admit, got {}",
                    decision_kind(&other)
                ),
            }
            clock.advance(dial_interval);
        }
    }

    /// `PLAN.md` M8 Step 3 P2-3 — the `ValidatedRateLimited` category's
    /// audit shares the exact first-row-then-summary aggregation contract
    /// every other `RejectReason` already has
    /// (`gate_flush_expired_emits_exactly_one_summary_after_the_window_closes`'s
    /// twin), pinned independently for the new category and window slot.
    #[tokio::test]
    async fn validated_rate_limited_rejections_aggregate_into_first_row_then_summary() {
        let clock = Arc::new(TestClock::new());
        // validated_rate_per_source = 0: burst = 0, so every validated
        // attempt is a deterministic ValidatedRateLimited rejection —
        // same pattern the existing cap=0 AtCapacity tests use, just on
        // the rate axis instead of the semaphore.
        let gate = Gate::new(clock.clone(), 64, 10, 0);
        let peer = addr(v4(198, 51, 100, 50), 1);

        const REJECTIONS: usize = 5;
        for i in 0..REJECTIONS {
            match gate.decide(peer, true, gate.now()) {
                Decision::Refuse(RejectReason::ValidatedRateLimited, records) => {
                    if i == 0 {
                        assert_eq!(records.len(), 1, "the first rejection carries its own row");
                        assert_eq!(records[0].resource, "validated_rate_limited");
                        assert_eq!(records[0].peer_addr, peer.to_string());
                        assert!(records[0].count.is_none());
                    } else {
                        assert!(
                            records.is_empty(),
                            "further rejections in the same window are suppressed, not \
                             re-reported: {records:?}"
                        );
                    }
                }
                other => panic!(
                    "expected Refuse(ValidatedRateLimited), got {}",
                    decision_kind(&other)
                ),
            }
        }

        assert!(
            gate.flush_expired(gate.now()).is_empty(),
            "flush_expired must not fire before the window has run past \
             AUDIT_AGGREGATION_WINDOW"
        );

        clock.advance(AUDIT_AGGREGATION_WINDOW + Duration::from_secs(1));
        let flushed = gate.flush_expired(gate.now());
        assert_eq!(
            flushed.len(),
            1,
            "expected exactly one summary record, got {flushed:?}"
        );
        assert_eq!(flushed[0].resource, "validated_rate_limited");
        assert_eq!(flushed[0].count, Some((REJECTIONS - 1) as u32));
        assert_eq!(
            flushed[0].peer_addr, "-",
            "the summary row never carries an observed address"
        );
    }
}
