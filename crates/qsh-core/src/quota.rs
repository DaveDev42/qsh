//! Resource quotas (`PLAN.md` M8 Step 3, `docs/adr/0010-resource-quotas.md`).
//!
//! Everything here enforces a *post-authorization* limit — the ACL choke
//! point has already run by the time any caller reaches this module
//! (`CLAUDE.md` security defaults: never create a resource before
//! authorization succeeds). An unauthorized principal must always see
//! `PERMISSION_DENIED`, never a quota rejection — that would be an oracle
//! on how saturated the host currently is. Quota rejections are
//! `RESOURCE_EXHAUSTED`, always `retryable: true` (the defining property of
//! a quota, as opposed to a policy denial: the resource comes back).
//!
//! **Lock discipline (verdict arbitration item 8, mirroring `crate::
//! admission::Gate`'s `WindowState`).** [`Quotas`]'s mutex (and each
//! [`crate::admission::AuditWindow`]'s) is always the **leaf-most** lock
//! taken: nothing else is ever locked while it is held, it is never held
//! across an `.await`, and it is never held while a session or child
//! handle is dropped (a `Drop` impl that runs arbitrary destructor code
//! under this lock is exactly the shape that turns a lock-order mistake
//! elsewhere into a deadlock nobody can see in a diff). A caller that must
//! drop a collection of entries after releasing a quota permit collects
//! them into a `Vec` first and drops that outside any guard.
//!
//! Session counting is deliberately **not** done here — `crate::broker::
//! Broker` derives its live-session count from its own registry (no
//! separate counter — see that module's doc), so a session slot can never
//! leak the way a hand-maintained counter's decrement-site sprawl invites.
//! This module owns the audit aggregation windows for *every*
//! [`QuotaKind`], including the broker-enforced ones, so a rejection's
//! audit trail is centralized in one place regardless of which module
//! holds the counter that produced it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use crate::admission::{AUDIT_AGGREGATION_WINDOW, AuditWindow};
use crate::audit::AuditRecord;
use crate::broker::Clock;
use crate::config::ServeConfig;

/// Which resource axis a quota rejection came from. Also the vocabulary
/// [`QuotaKind::category`] hands to [`AuditRecord::quota_rejected`]/
/// [`AuditRecord::quota_rejected_summary`] (`docs/CLI.md` audit section,
/// mirroring `crate::admission::RejectReason::category`).
///
/// Declaration order matches [`Quotas`]'s internal `windows` array — each
/// variant's `as usize` is that array's index (same trick `crate::
/// admission::Gate` uses for its two `RejectReason`s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    /// The global live-session cap (`[serve].max_sessions`) —
    /// enforced by `crate::broker::Broker`, not this module.
    Sessions,
    /// The per-principal live-session cap
    /// (`[serve].max_sessions_per_principal`) — enforced by
    /// `crate::broker::Broker`, not this module.
    SessionsPerPrincipal,
    /// The per-principal concurrent-`exec.run` cap
    /// (`[serve].max_exec_per_principal`) — enforced by
    /// [`Quotas::reserve_exec`].
    ExecPerPrincipal,
}

impl QuotaKind {
    /// Every variant, in the same order as [`Quotas`]'s internal window
    /// array — a fixed, non-growing list (Step 2's "a growing structure
    /// is the surface" principle applies here too, `docs/adr/0009-
    /// admission-defenses.md`).
    pub const ALL: &'static [QuotaKind] = &[
        QuotaKind::Sessions,
        QuotaKind::SessionsPerPrincipal,
        QuotaKind::ExecPerPrincipal,
    ];

    /// The audit/log category word — the exact `quota_*` vocabulary
    /// `docs/adr/0010-resource-quotas.md` §2.4 settles on.
    pub fn category(self) -> &'static str {
        match self {
            QuotaKind::Sessions => "quota_sessions_host",
            QuotaKind::SessionsPerPrincipal => "quota_sessions_principal",
            QuotaKind::ExecPerPrincipal => "quota_exec_principal",
        }
    }

    /// The ACL action word this kind's rejection is *for* — `docs/CLI.md`'s
    /// audit prose states the `action` field on a quota-reject record is
    /// `"session.open"` (either session axis) or `"exec.run"`
    /// (`ExecPerPrincipal`), matching `crate::acl::Action::SessionOpen`/
    /// `ExecRun::as_str()` byte for byte without pulling an `acl` dependency
    /// into this leaf-most module — see [`crate::audit::AuditRecord::
    /// quota_rejected`], which is the sole caller.
    pub fn action(self) -> &'static str {
        match self {
            QuotaKind::Sessions | QuotaKind::SessionsPerPrincipal => "session.open",
            QuotaKind::ExecPerPrincipal => "exec.run",
        }
    }

    /// The wire-facing rejection string `crate::broker::BrokerError::
    /// QuotaExceeded` displays (`docs/CLI.md` §6.12, `docs/adr/
    /// 0010-resource-quotas.md` §5).
    ///
    /// Uniform *per resource type*, not per variant: both session-axis
    /// kinds (`Sessions`, the host-wide cap, and `SessionsPerPrincipal`,
    /// the per-principal cap) share one string, distinct only from the
    /// exec-axis string. Which axis actually rejected the request is
    /// carried solely by the audit record's `resource` field
    /// ([`QuotaKind::category`]) — a client parsing this message alone
    /// cannot and is not meant to distinguish host-wide from
    /// per-principal within the same resource type.
    pub fn wire_message(self) -> &'static str {
        match self {
            QuotaKind::Sessions | QuotaKind::SessionsPerPrincipal => "session quota exceeded",
            QuotaKind::ExecPerPrincipal => "exec quota exceeded",
        }
    }
}

/// Effective, already-defaulted quota values resolved from `[serve]`
/// (mirrors `crate::broker::BrokerConfig::from_serve`'s shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    /// Global cap on live sessions (`[serve].max_sessions`).
    pub max_sessions: usize,
    /// Per-principal cap on live sessions
    /// (`[serve].max_sessions_per_principal`).
    pub max_sessions_per_principal: usize,
    /// Per-principal cap on concurrently running `exec.run` children
    /// (`[serve].max_exec_per_principal`).
    pub max_exec_per_principal: usize,
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            max_sessions: ServeConfig::DEFAULT_MAX_SESSIONS,
            max_sessions_per_principal: ServeConfig::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL,
            max_exec_per_principal: ServeConfig::DEFAULT_MAX_EXEC_PER_PRINCIPAL,
        }
    }
}

impl QuotaLimits {
    /// Resolve from a parsed `[serve]` section, applying the documented
    /// defaults (`0`/unset ⇒ default, never "unlimited") for any unset
    /// field.
    pub fn from_serve(serve: &ServeConfig) -> Self {
        Self {
            max_sessions: serve.max_sessions(),
            max_sessions_per_principal: serve.max_sessions_per_principal(),
            max_exec_per_principal: serve.max_exec_per_principal(),
        }
    }
}

/// Mutable state behind [`Quotas`]'s single leaf-most lock.
#[derive(Default)]
struct QuotaState {
    /// Live (unreleased) `exec.run` reservations, keyed by the same
    /// `opener_key` string `crate::broker::Broker` keys sessions by. An
    /// entry is removed the instant its count reaches zero — cardinality
    /// is bounded by the number of distinct principals currently holding
    /// at least one reservation, which is itself bounded by `Σ
    /// max_exec_per_principal` (the same "no entry without a live
    /// resource" invariant `docs/adr/0010-resource-quotas.md` §2.1
    /// states for the tunnel/connection maps 3b adds).
    exec_in_use: HashMap<String, usize>,
}

/// The quota decision-maker for the resource axes this module directly
/// enforces (today: `exec.run` concurrency), plus the shared audit
/// aggregation windows for every [`QuotaKind`] regardless of which module
/// enforces it. Constructed as an `Arc` so [`Quotas::reserve_exec`]'s
/// returned [`ExecPermit`] can release its reservation from an arbitrary
/// `'static` task without borrowing back into whatever owns the `Quotas`
/// itself (a [`Weak`] back-reference, upgraded on `Drop` — if the whole
/// `Quotas` has already been torn down, there is nothing left to
/// decrement into, so the permit's `Drop` is simply a no-op rather than a
/// panic).
pub struct Quotas {
    limits: QuotaLimits,
    clock: Arc<dyn Clock>,
    self_weak: Weak<Quotas>,
    state: Mutex<QuotaState>,
    windows: [AuditWindow; QuotaKind::ALL.len()],
}

impl std::fmt::Debug for Quotas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Quotas")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Quotas {
    /// Build a quota tracker with the given limits, driven by an injected
    /// [`Clock`] so every invariant here is testable without real
    /// wall-clock time (same discipline as `crate::admission::Gate::new`).
    pub fn new(limits: QuotaLimits, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            limits,
            clock,
            self_weak: weak.clone(),
            state: Mutex::new(QuotaState::default()),
            windows: Default::default(),
        })
    }

    /// The quotas' own clock, for a caller that needs `now` to pass to
    /// [`Quotas::record_rejection`]/[`Quotas::flush_expired`] without
    /// duplicating which clock that is (mirrors `crate::admission::
    /// Gate::now`).
    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QuotaState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve one `exec.run` slot for `principal_key`, or refuse with
    /// [`QuotaKind::ExecPerPrincipal`] if that principal is already at
    /// [`QuotaLimits::max_exec_per_principal`]. The counter tracks *live*
    /// (unredeemed-ticket) children only — a released [`ExecPermit`]
    /// (child reaped) frees the slot immediately, so a principal that
    /// keeps redeeming and reaping tickets never accumulates an unbounded
    /// backlog the way `crate::server`'s pending-ticket budget alone
    /// would allow (verdict arbitration item 5). An expired, never-
    /// redeemed ticket is not this immediate — its `ExecPermit` is
    /// released only by the next sweep of `crate::server`'s ticket map
    /// (any ticket-issuing request, a connection purge, or
    /// `Server::quota_housekeeping`'s periodic tick), not the instant it
    /// expires.
    pub fn reserve_exec(&self, principal_key: &str) -> Result<ExecPermit, QuotaKind> {
        let mut state = self.lock();
        // Read-only check first (F9 of the M8 Step 3a conformance sweep):
        // `entry(..).or_insert(0)` ahead of the cap test would plant a
        // zero-valued map entry for a *refused* principal too, breaking
        // this module's own "no entry without a live resource" invariant
        // (this struct's doc comment) the moment `max_exec_per_principal`
        // is `0` — unreachable from parsed config (`0` degrades to the
        // default there) but reachable from any hand-built `QuotaLimits`,
        // which is exactly how tests (and 3b) construct one.
        let current = state.exec_in_use.get(principal_key).copied().unwrap_or(0);
        if current >= self.limits.max_exec_per_principal {
            return Err(QuotaKind::ExecPerPrincipal);
        }
        *state
            .exec_in_use
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
        Ok(ExecPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
        })
    }

    /// Current live `exec.run` reservation count for `principal_key` —
    /// test/diagnostic use only.
    pub fn exec_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .exec_in_use
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct principals with a map entry in `exec_in_use` —
    /// test-only, distinct from [`Quotas::exec_in_use`] itself: that
    /// method's `unwrap_or(0)` cannot tell "no entry" apart from "entry
    /// present holding `0`", which is exactly the distinction the F9
    /// no-entry-without-a-live-resource invariant (this struct's own
    /// doc comment) needs a test to pin.
    #[cfg(test)]
    fn exec_in_use_principal_count(&self) -> usize {
        self.lock().exec_in_use.len()
    }

    /// Record one rejection of `kind` against `principal`, returning the
    /// [`AuditRecord`]s the caller should hand to its
    /// [`crate::audit::AuditSink`] — first-occurrence-then-summary
    /// aggregation, same [`AUDIT_AGGREGATION_WINDOW`] (10 s), same
    /// single-lock-per-window shape, and now (main-session arbitration
    /// round, S1 deviation 2 overturned) the exact same up-to-two-record
    /// return shape as `crate::admission::Gate::record_rejection`: a
    /// *stale* window (one that ran past the aggregation bound with
    /// nothing to close it) closes with its own summary record *and* the
    /// triggering rejection still gets its own fresh first-line record —
    /// never one at the other's expense. The single-`Option` version this
    /// replaced could lose an isolated rejection's own line entirely when
    /// it happened to be the one that reopened a stale window (that
    /// version's own doc comment named the trade); a single unattributed
    /// probe against an otherwise-idle category is exactly the audit line
    /// an investigation most needs, so this module now costs the same one
    /// extra `Vec` slot `Gate::record_rejection` already pays for the same
    /// guarantee.
    ///
    /// `request_id`/`auth_path` are the calling request's own — passed
    /// through untouched to the immediate (non-summary) record so the ACL
    /// `allow` line and this `deny` line for the *same* request share a
    /// `request_id` and can be correlated (verdict ruling 11①). A summary
    /// record spans many requests, so it keeps the pre-existing `"-"`
    /// convention regardless of what is passed here.
    pub fn record_rejection(
        &self,
        kind: QuotaKind,
        principal: &str,
        now: Instant,
        request_id: u64,
        auth_path: qsh_transport::AuthPath,
    ) -> Vec<AuditRecord> {
        let window = &self.windows[kind as usize];
        let mut guard = window.state.lock().unwrap_or_else(|e| e.into_inner());
        let window_is_fresh = match guard.start {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= AUDIT_AGGREGATION_WINDOW,
        };
        if !window_is_fresh {
            // Same critical section as the freshness check above — no gap
            // a concurrent `flush_expired` could land its close inside
            // (mirrors `Gate::record_rejection`'s own identical note).
            guard.suppressed = guard.suppressed.saturating_add(1);
            return Vec::new();
        }
        let prior_suppressed = guard.suppressed;
        guard.suppressed = 0;
        guard.start = Some(now);
        drop(guard);
        let mut records = Vec::with_capacity(2);
        if prior_suppressed > 0 {
            records.push(AuditRecord::quota_rejected_summary(
                kind,
                "-",
                prior_suppressed,
            ));
        }
        records.push(AuditRecord::quota_rejected(
            kind, principal, request_id, auth_path,
        ));
        records
    }

    /// Force-close every category window whose `start` is at least
    /// [`AUDIT_AGGREGATION_WINDOW`] old, emitting a
    /// [`AuditRecord::quota_rejected_summary`] for any that suppressed at
    /// least one rejection — mirrors `crate::admission::Gate::
    /// flush_expired` exactly (same rationale: a flood that has already
    /// stopped still gets its last window's summary within one more
    /// tick, even with nothing left to trigger the lazy path in
    /// [`Quotas::record_rejection`]).
    pub fn flush_expired(&self, now: Instant) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        for (window, kind) in self.windows.iter().zip(QuotaKind::ALL.iter().copied()) {
            let mut guard = window.state.lock().unwrap_or_else(|e| e.into_inner());
            let Some(start) = guard.start else {
                continue;
            };
            if now.saturating_duration_since(start) < AUDIT_AGGREGATION_WINDOW {
                continue;
            }
            let suppressed = guard.suppressed;
            guard.start = None;
            guard.suppressed = 0;
            drop(guard);
            if suppressed > 0 {
                records.push(AuditRecord::quota_rejected_summary(kind, "-", suppressed));
            }
        }
        records
    }
}

/// RAII `exec.run` concurrency reservation ([`Quotas::reserve_exec`]).
/// `Drop` decrements the principal's in-use count (removing the map entry
/// entirely once it reaches zero, so the map's cardinality never exceeds
/// the number of principals currently holding a live reservation) — this
/// runs on every exit path (normal completion, early `?` return, task
/// abort's unwind), so a slot can never leak the way a hand-maintained
/// counter's scattered decrement sites invite (`crate::broker`'s own
/// registry-derived-count rationale, restated here for the same reason).
#[derive(Debug)]
pub struct ExecPermit {
    quotas: Weak<Quotas>,
    principal_key: String,
}

impl Drop for ExecPermit {
    fn drop(&mut self) {
        // B4 (M8 Step 3a fix-3 sweep): the mechanical half of ADR-0010
        // §9's "collect under the guard, drop outside" rule — an
        // `ExecPermit` (this struct) is what a `Ticket` carries, so its
        // `Drop` is exactly the thing that must never run while a
        // higher-level lock (`crate::server::Server`'s tickets map) is
        // still held. `lock_order::violations()` never panics inside a
        // `Drop` impl (a panicking `Drop` during unwind aborts the
        // process) — it only records the violation for a test's own
        // assertion to fail on.
        #[cfg(test)]
        if lock_order::DEPTH.with(|d| d.get()) > 0 {
            lock_order::VIOLATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        let Some(quotas) = self.quotas.upgrade() else {
            return;
        };
        let mut state = quotas.lock();
        if let Some(count) = state.exec_in_use.get_mut(&self.principal_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.exec_in_use.remove(&self.principal_key);
            }
        }
    }
}

/// `cfg(test)`-only lock-order tripwire (M8 Step 3a fix-3 sweep, B4):
/// mechanically enforces ADR-0010 §9's "collect under the guard, drop
/// outside" rule instead of leaving it to convention and code review
/// alone. `crate::server::Server` routes every `self.tickets.lock()`
/// acquisition through one helper (`lock_tickets`) whose returned guard
/// holds a [`NonLeafGuard`] for as long as the tickets map is locked;
/// [`ExecPermit`]'s own `Drop` (above) checks [`DEPTH`] and records a
/// violation in [`VIOLATIONS`] if it runs while some `NonLeafGuard` is
/// still alive on this thread — an `ExecPermit` dropped while a
/// higher-level lock is held is precisely the ordering ADR-0010 §9
/// forbids (its own `Drop` takes the *leaf-most* quota lock, safe to run
/// underneath another lock, never while one is still held).
///
/// [`VIOLATIONS`] is process-global, not per-test: `cargo nextest` runs
/// one test per process, so a nonzero count read back within a single
/// test's own assertion is never cross-test noise.
#[cfg(test)]
pub(crate) mod lock_order {
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;

    thread_local! {
        pub(super) static DEPTH: Cell<u32> = const { Cell::new(0) };
    }

    pub(super) static VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

    /// Held for the lifetime of a non-leaf lock scope (today: just
    /// `crate::server::Server`'s tickets map, via its `TicketsGuard`).
    /// The constructor increments [`DEPTH`]; `Drop` decrements it — so a
    /// thread nesting two non-leaf scopes (not that any do today) is
    /// still tracked correctly by depth, not a boolean.
    pub(crate) struct NonLeafGuard;

    impl NonLeafGuard {
        pub(crate) fn new() -> Self {
            DEPTH.with(|d| d.set(d.get() + 1));
            Self
        }
    }

    impl Drop for NonLeafGuard {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
        }
    }

    /// Read back by a test after exercising every sweep site once.
    pub(crate) fn violations() -> usize {
        VIOLATIONS.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::TestClock;

    fn quotas_with(max_exec_per_principal: usize) -> Arc<Quotas> {
        Quotas::new(
            QuotaLimits {
                max_exec_per_principal,
                ..QuotaLimits::default()
            },
            Arc::new(TestClock::new()),
        )
    }

    #[test]
    fn reserve_exec_refuses_past_the_cap_and_release_frees_the_slot() {
        let quotas = quotas_with(2);
        let p1 = quotas.reserve_exec("device:a").unwrap();
        let p2 = quotas.reserve_exec("device:a").unwrap();
        assert_eq!(quotas.exec_in_use("device:a"), 2);
        assert_eq!(
            quotas.reserve_exec("device:a").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );

        drop(p1);
        assert_eq!(quotas.exec_in_use("device:a"), 1);
        let p3 = quotas.reserve_exec("device:a").unwrap();
        assert_eq!(quotas.exec_in_use("device:a"), 2);

        drop(p2);
        drop(p3);
        assert_eq!(quotas.exec_in_use("device:a"), 0);
    }

    /// Adversary finding A8: `exec_in_use`'s comparison against
    /// `max_exec_per_principal` used to cast the limit down to `u32`,
    /// truncating any limit above `u32::MAX` back into a small (even
    /// zero) effective cap. `exec_in_use` is `usize` now, so a limit this
    /// large must still admit the very first reservation.
    #[test]
    fn reserve_exec_is_not_truncated_by_a_limit_above_u32_max() {
        let quotas = quotas_with(1usize << 32);
        assert!(quotas.reserve_exec("device:a").is_ok());
    }

    #[test]
    fn exec_quota_is_isolated_per_principal() {
        let quotas = quotas_with(1);
        let _a = quotas.reserve_exec("device:a").unwrap();
        // A's cap is full, but B is a distinct key and still admits.
        let _b = quotas.reserve_exec("device:b").unwrap();
        assert_eq!(quotas.exec_in_use("device:a"), 1);
        assert_eq!(quotas.exec_in_use("device:b"), 1);
        assert_eq!(
            quotas.reserve_exec("device:a").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
        assert_eq!(
            quotas.reserve_exec("device:b").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
    }

    /// F9 of the M8 Step 3a conformance sweep: `reserve_exec` must test
    /// the cap *before* touching `exec_in_use`'s map, not
    /// `entry(..).or_insert(0)` ahead of the check. With
    /// `max_exec_per_principal == 0` (unreachable through parsed config,
    /// where `0` degrades to the default — `QuotaLimits::from_serve` — but
    /// directly reachable through a hand-built `QuotaLimits` the way this
    /// test, and 3b's tunnel/connection quotas, construct one) every
    /// refused reservation must leave the map exactly as it found it: no
    /// zero-valued entry surviving under the refused principal's key.
    #[test]
    fn reserve_exec_leaves_no_entry_behind_when_the_cap_is_zero() {
        let quotas = quotas_with(0);
        assert_eq!(
            quotas.reserve_exec("device:a").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
        assert_eq!(quotas.exec_in_use("device:a"), 0);
        assert_eq!(
            quotas.exec_in_use_principal_count(),
            0,
            "a refused reservation against a zero cap must not plant a \
             zero-valued map entry — the module's own \"no entry without \
             a live resource\" invariant"
        );

        // A second, distinct principal against the same zero cap: same
        // refusal, same empty map afterward.
        assert_eq!(
            quotas.reserve_exec("device:b").unwrap_err(),
            QuotaKind::ExecPerPrincipal
        );
        assert_eq!(quotas.exec_in_use_principal_count(), 0);
    }

    #[test]
    fn quota_audit_reports_first_then_summary() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();

        // First rejection in a fresh window: an immediate, real record.
        let first_batch = quotas.record_rejection(
            QuotaKind::ExecPerPrincipal,
            "device:a",
            t0,
            1,
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(
            first_batch.len(),
            1,
            "just the fresh window's own first line"
        );
        let first = &first_batch[0];
        assert_eq!(first.principal, "device:a");
        assert_eq!(first.resource, QuotaKind::ExecPerPrincipal.category());
        assert_eq!(first.count, None);

        // Two more within the same window: suppressed, no record yet.
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::ExecPerPrincipal,
                    "device:a",
                    t0 + std::time::Duration::from_secs(1),
                    1,
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::ExecPerPrincipal,
                    "device:a",
                    t0 + std::time::Duration::from_secs(2),
                    1,
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );

        // Flushing before the window has aged out reports nothing.
        assert!(
            quotas
                .flush_expired(t0 + std::time::Duration::from_secs(3))
                .is_empty()
        );

        // Once the window has aged past AUDIT_AGGREGATION_WINDOW, flush
        // closes it with a summary counting the two suppressed rejections.
        let flushed =
            quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].principal, "-");
        assert_eq!(flushed[0].count, Some(2));
        assert_eq!(flushed[0].resource, QuotaKind::ExecPerPrincipal.category());
    }

    /// `record_rejection` indexes `Quotas`'s internal `windows` array by
    /// `kind as usize` (this module's `windows: [AuditWindow;
    /// QuotaKind::ALL.len()]` field), while `flush_expired` walks
    /// `windows` zipped in lockstep with `QuotaKind::ALL`'s own iteration
    /// order — the two only agree with each other if `ALL`'s declared
    /// order exactly matches each variant's discriminant.
    #[test]
    fn quota_kind_all_is_declared_in_discriminant_order() {
        for (i, k) in QuotaKind::ALL.iter().enumerate() {
            assert_eq!(*k as usize, i);
        }
    }

    /// Twin of the discriminant-order pin above, exercised through the
    /// actual read/write path rather than the raw enum values: a window
    /// `record_rejection` opens for `kind` (via `kind as usize`) must be
    /// the exact same slot `flush_expired`'s `windows.iter().zip(ALL)`
    /// later reports back out *as* `kind` — reordering `QuotaKind::ALL`
    /// relative to declaration order would make `flush_expired` attribute
    /// one category's suppressed rejections to a different one.
    #[test]
    fn flush_expired_summary_names_the_correct_kind_for_every_category() {
        for &kind in QuotaKind::ALL {
            let quotas = quotas_with(1);
            let clock = TestClock::new();
            let t0 = clock.now();
            let sec = std::time::Duration::from_secs(1);

            let first =
                quotas.record_rejection(kind, "device:a", t0, 1, qsh_transport::AuthPath::Ca);
            assert_eq!(first.len(), 1, "kind {kind:?}: first line");
            assert!(
                quotas
                    .record_rejection(kind, "device:a", t0 + sec, 1, qsh_transport::AuthPath::Ca)
                    .is_empty(),
                "kind {kind:?}: second rejection suppressed"
            );

            let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
            assert_eq!(flushed.len(), 1, "kind {kind:?}: summary");
            assert_eq!(
                flushed[0].resource,
                kind.category(),
                "kind {kind:?}: summary named the wrong category"
            );
        }
    }

    #[test]
    fn quota_flush_expired_closes_a_window_with_no_further_rejections() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();

        let first = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:a",
            t0,
            1,
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(first.len(), 1, "first rejection reported");
        // Nothing else ever calls record_rejection again for this
        // category — the flood already stopped. The periodic tick must
        // still close the window on its own.
        let flushed =
            quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1));
        // No further rejections were suppressed, so there is nothing to
        // summarize — but the window itself must be closed (a second
        // flush at the same instant reports nothing new either).
        assert!(flushed.is_empty());
        // Directly on the window's own state, not merely inferred from
        // "nothing was reported": an empty `flushed` is also what a bug
        // that re-stamped `guard.start = Some(start)` instead of clearing
        // it to `None` would produce, since that bug leaves nothing new
        // to summarize either. `AuditWindow::is_open` reads `start`
        // itself, so it fails the way that bug should.
        assert!(
            !quotas.windows[QuotaKind::Sessions as usize].is_open(),
            "flush_expired must actually close the window (guard.start = \
             None), not just decline to report anything"
        );
        assert!(
            quotas
                .flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1))
                .is_empty()
        );

        // A rejection after the close starts a brand new window and is
        // reported immediately, proving the old one did not linger open.
        let reopened = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:b",
            t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(2),
            2,
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(
            reopened.len(),
            1,
            "closed window reopens on the next rejection"
        );
        assert_eq!(reopened[0].principal, "device:b");
        assert_eq!(reopened[0].count, None);
    }

    /// The quota module's twin of
    /// `crate::admission::tests::gate_record_rejection_and_flush_expired_
    /// both_reset_suppressed_not_just_report_it`, which `Quotas` never got
    /// when it copied `Gate::flush_expired`'s shape. `flush_expired` must
    /// *consume* the suppressed count it reports, not merely read it —
    /// otherwise the next rejection to reopen that category's window
    /// re-emits a phantom summary for suppressions that were already
    /// summarized one window ago.
    #[test]
    fn quota_flush_expired_resets_suppressed_not_just_reports_it() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();
        let sec = std::time::Duration::from_secs(1);

        assert_eq!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    "device:a",
                    t0,
                    1,
                    qsh_transport::AuthPath::Ca
                )
                .len(),
            1
        );
        for n in 1..=2u64 {
            assert!(
                quotas
                    .record_rejection(
                        QuotaKind::Sessions,
                        "device:a",
                        t0 + sec * (n as u32),
                        1,
                        qsh_transport::AuthPath::Ca,
                    )
                    .is_empty()
            );
        }

        let flushed = quotas.flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + sec);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].count, Some(2));

        // A later, isolated rejection opens a brand new window: it owes
        // exactly one fresh first line and nothing else. A second summary
        // here would be re-reporting the two suppressions the flush above
        // already accounted for.
        let later = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:b",
            t0 + AUDIT_AGGREGATION_WINDOW + sec * 2,
            7,
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(
            later.len(),
            1,
            "flush_expired must consume the suppressed count it reported — \
             got a phantom second summary: {later:?}"
        );
        assert_eq!(later[0].principal, "device:b");
        assert!(later[0].count.is_none());
    }

    /// Main-session arbitration round, item 4 (S1 deviation 2 overturned):
    /// the stale-reopen branch must return *both* the closing window's
    /// summary and the triggering rejection's own first line, mirroring
    /// `crate::admission::Gate::record_rejection` exactly — not the single
    /// `Option` the M8 Step 3a S1 stage had shipped, which could only ever
    /// return one of the two.
    #[test]
    fn quota_rejection_reopens_a_stale_window_with_both_its_summary_and_a_fresh_first_line() {
        let quotas = quotas_with(1);
        let clock = TestClock::new();
        let t0 = clock.now();

        // Three rejections in one window: one immediate first line, two
        // suppressed.
        let first = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:a",
            t0,
            1,
            qsh_transport::AuthPath::Ca,
        );
        assert_eq!(first.len(), 1);
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    "device:a",
                    t0 + std::time::Duration::from_secs(1),
                    1,
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );
        assert!(
            quotas
                .record_rejection(
                    QuotaKind::Sessions,
                    "device:a",
                    t0 + std::time::Duration::from_secs(2),
                    1,
                    qsh_transport::AuthPath::Ca,
                )
                .is_empty()
        );

        // Advance past the window with nothing to close it (no
        // `flush_expired` tick), then one more rejection: this call alone
        // must close the stale window (summary, 2 suppressed) *and* report
        // its own fresh first line — never one at the other's expense.
        let stale_reopen = quotas.record_rejection(
            QuotaKind::Sessions,
            "device:b",
            t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1),
            9,
            qsh_transport::AuthPath::Pin,
        );
        assert_eq!(
            stale_reopen.len(),
            2,
            "the closing summary and the reopening rejection's own line, \
             both — got {stale_reopen:?}"
        );
        assert_eq!(stale_reopen[0].principal, "-");
        assert_eq!(stale_reopen[0].count, Some(2));
        assert_eq!(stale_reopen[0].resource, QuotaKind::Sessions.category());
        assert_eq!(stale_reopen[1].principal, "device:b");
        assert_eq!(stale_reopen[1].count, None);
        assert_eq!(stale_reopen[1].request_id, "9");
        assert_eq!(stale_reopen[1].auth_path, "pin");

        // The window this rejection just opened is fresh — a flush at the
        // same instant reports nothing new for it.
        assert!(
            quotas
                .flush_expired(t0 + AUDIT_AGGREGATION_WINDOW + std::time::Duration::from_secs(1))
                .is_empty()
        );
    }
}
