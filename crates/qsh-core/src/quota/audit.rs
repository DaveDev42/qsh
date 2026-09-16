//! Rejection audit windows: [`Quotas::record_rejection`] and [`Quotas::flush_expired`].

use super::*;

impl Quotas {
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
    /// convention regardless of what is passed here. `request_id` is
    /// `Option<u64>` (M8 Step 3b ruling R9): a control request (session,
    /// exec, `RemoteForwardOpen`) has a real one to pass as `Some`; a data
    /// stream (tunnel dial) or a connection-axis rejection (S4) has none,
    /// and passes `None` rather than the ambiguous sentinel `0` — the same
    /// "no id" shape `authorize_stream`'s connection-level callers already
    /// use. [`AuditRecord::quota_rejected`] writes `None` as the audit
    /// string `"-"`.
    ///
    /// `peer_addr` (M8 Step 3b ruling R4, reversing the 3a "this module has
    /// no address to hand" note) is likewise the caller's own live value —
    /// this module stays connection-agnostic (`architecture.md` §1): it
    /// only carries the address through to [`AuditRecord::quota_rejected`]
    /// as an opaque value, never inspects or validates it. Every caller
    /// today (session/exec axes) passes its `ConnCtx::peer_addr`; the
    /// summary record still hardcodes `"-"` — one aggregation window can
    /// span many peers.
    ///
    /// **Window key (R2 설계 검토 (a-2)/(a-3)):** the window this call
    /// opens or bumps is keyed on `(kind, principal)`, not `kind` alone —
    /// `CategoryWindows::per_principal` holds one `WindowState` per
    /// principal currently within its own aggregation window, so one
    /// principal's flood can never suppress a *different* principal's
    /// first rejection into a summary line. Once a category already has
    /// [`MAX_AUDIT_WINDOW_PRINCIPALS`] live principal windows, a rejection
    /// from any further new principal falls into that category's single
    /// `overflow` window instead of growing the map — its own first line
    /// still carries the rejected principal's real name (only the later
    /// *summary* line for that shared window is audited under `"-"`, see
    /// [`Quotas::flush_expired`]). `"-"` is itself a reserved sentinel
    /// (R2 review B, B1) and is routed straight to `overflow` regardless
    /// of the map's current size, so no caller — today or in the future —
    /// can accidentally open a normal `per_principal` window whose
    /// summary would then be indistinguishable from an actual overflow
    /// summary. This call only ever touches its own
    /// key's window; it never inspects or closes another principal's
    /// still-open window in the same category, so the critical section
    /// stays O(1) regardless of how many other principals are currently
    /// being tracked (the deliberate trade documented on
    /// `CategoryWindows`/[`Quotas::flush_expired`]: a window that has
    /// gone stale but has not yet been swept can occupy a map slot for up
    /// to one more housekeeping tick before a *new* principal beyond the
    /// cap is pushed to overflow — an audit-attribution quality question,
    /// never a cap-enforcement one).
    pub fn record_rejection(
        &self,
        kind: QuotaKind,
        principal: &str,
        peer_addr: std::net::SocketAddr,
        now: Instant,
        request_id: Option<u64>,
        auth_path: qsh_transport::AuthPath,
    ) -> Vec<AuditRecord> {
        // Counted on every call, independent of the
        // window-suppression decision below — suppression governs whether
        // *this* call also emits its own audit line, not whether it
        // happened at all.
        self.rejections[kind as usize].fetch_add(1, Ordering::Relaxed);
        let mut cat = self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // `is_overflow` records which window this rejection landed in so
        // the summary line built after the lock is dropped below can pick
        // the right principal string ("-" for overflow, the window's own
        // owner otherwise) without holding the lock while formatting it.
        //
        // R2 review B (B1): `"-"` is reserved for the overflow summary and
        // must never become a `per_principal` key in its own right — a
        // caller that (today or in the future) audits a pre-identity axis
        // under the same sentinel admission already uses for it
        // (`docs/CLI.md` §6.12's admission-reject `principal: "-"`) would
        // otherwise open a normal, indistinguishable window under that
        // string, and its summary line would then be byte-for-byte
        // identical to an actual overflow summary. Routing it to
        // `overflow` up front makes that invariant a type fact instead of
        // a convention every future caller has to already know.
        let (state, is_overflow) = if principal == "-" {
            (&mut cat.overflow, true)
        } else if let Some(state) = cat.per_principal.get_mut(principal) {
            (state, false)
        } else if cat.per_principal.len() >= MAX_AUDIT_WINDOW_PRINCIPALS {
            (&mut cat.overflow, true)
        } else {
            (
                cat.per_principal.entry(principal.to_string()).or_default(),
                false,
            )
        };
        let window_is_fresh = match state.start {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= AUDIT_AGGREGATION_WINDOW,
        };
        if !window_is_fresh {
            // Same critical section as the freshness check above — no gap
            // a concurrent `flush_expired` could land its close inside
            // (mirrors `Gate::record_rejection`'s own identical note).
            state.suppressed = state.suppressed.saturating_add(1);
            return Vec::new();
        }
        let prior_suppressed = state.suppressed;
        state.suppressed = 0;
        state.start = Some(now);
        drop(cat);
        let mut records = Vec::with_capacity(2);
        if prior_suppressed > 0 {
            records.push(AuditRecord::quota_rejected_summary(
                kind,
                if is_overflow { "-" } else { principal },
                prior_suppressed,
            ));
        }
        records.push(AuditRecord::quota_rejected(
            kind, principal, peer_addr, request_id, auth_path,
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
    ///
    /// A closed principal window's entry is *deleted* from
    /// `CategoryWindows::per_principal`, not reset in place — this is
    /// what keeps the map's cardinality bounded by
    /// [`MAX_AUDIT_WINDOW_PRINCIPALS`] rather than growing by one for
    /// every distinct principal ever rejected over the process's
    /// lifetime. The only thing dropped under the category lock is a
    /// `String` (the deleted key) — not a session or child-process
    /// handle — so this stays within the module's own "collect under the
    /// guard, drop outside" lock discipline (top-of-file doc). The
    /// `overflow` slot is a fixed field, never deleted, only closed
    /// (`start = None`) the same way a principal window used to be.
    ///
    /// One consequence worth naming: with up to
    /// [`MAX_AUDIT_WINDOW_PRINCIPALS`] principal windows live per
    /// category, a single tick's return can carry up to
    /// `QuotaKind::ALL.len() × (MAX_AUDIT_WINDOW_PRINCIPALS + 1)` summary
    /// records (650 today) instead of the old at-most-10. `crate::audit::
    /// write_quota_audit`'s sink write can return `AuditError::QueueFull`
    /// under that burst; that path does not latch the sink `degraded` (only
    /// a hard write failure does, `crate::audit::writer::RotatingAuditSink
    /// ::record`), and the caller already treats a failed quota-audit
    /// enqueue as fail-open (the request itself is already being refused,
    /// so a lost *summary* line only degrades the diagnostic, not any
    /// enforcement decision).
    ///
    /// **R2 review A (F1): this burst is not free of effect on other
    /// traffic, and the previous wording here overstated that it was.**
    /// `write_quota_audit` shares one `AuditSink` — and one bounded queue —
    /// with `Server::authorize`/`authorize_stream`'s own enqueues, and
    /// *those* choke points are where the actual `docs/CLI.md` §6.12
    /// fail-closed rule lives: an allow verdict whose own audit enqueue
    /// fails is denied (`server/mod.rs`'s `verdict.is_allow() &&
    /// recorded.is_ok()` / `!verdict.is_allow() || recorded.is_err()`
    /// shape). A 650-record burst landing in the same queue at the same
    /// instant as a legitimate request's own enqueue can push that
    /// request's enqueue into `QueueFull` too, and the fail-closed rule
    /// then denies a request that was never itself over any quota — an
    /// availability cost, not a fail-closed *violation* (no allow ever
    /// reaches a peer without a durable record; the queue-full request is
    /// simply refused instead). The default `[audit].queue_depth` (1024)
    /// leaves headroom over the 650-record ceiling; the test
    /// `flush_expired_worst_case_burst_fits_under_the_default_audit_queue_
    /// depth` below pins that relationship so a future `QuotaKind::ALL`
    /// growth (or a cap increase) that closes the gap fails loudly instead
    /// of silently. An operator who lowers `[audit].queue_depth` below the
    /// per-tick ceiling trades that headroom away themselves.
    ///
    /// **R2 review B (B5):** the same row-count increase (2 → up to 130
    /// per category per window, before this change) also shortens how
    /// long a deny record actually survives on disk under a
    /// principal-rotating flood. `[audit].max_bytes × (retain + 1)` still
    /// bounds the audit directory's total *volume* (`docs/CLI.md` §6.12),
    /// but a flood that fills the same volume with more rows pushes older
    /// deny records past `[audit].retain`'s rotation boundary sooner —
    /// this is ordinary rotation working as designed, not a new bound
    /// violation, but it means "audit flood does not grow the log" is no
    /// longer the same claim as "audit flood does not shorten retention".
    pub fn flush_expired(&self, now: Instant) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        for (window, kind) in self.windows.iter().zip(QuotaKind::ALL.iter().copied()) {
            let mut closed: Vec<(String, u32)> = Vec::new();
            let mut overflow_suppressed = None;
            {
                let mut cat = window.lock().unwrap_or_else(|e| e.into_inner());
                cat.per_principal.retain(|principal, state| {
                    let Some(start) = state.start else {
                        return false;
                    };
                    if now.saturating_duration_since(start) < AUDIT_AGGREGATION_WINDOW {
                        return true;
                    }
                    closed.push((principal.clone(), state.suppressed));
                    false
                });
                if let Some(start) = cat.overflow.start
                    && now.saturating_duration_since(start) >= AUDIT_AGGREGATION_WINDOW
                {
                    overflow_suppressed = Some(cat.overflow.suppressed);
                    cat.overflow.start = None;
                    cat.overflow.suppressed = 0;
                }
            }
            for (principal, suppressed) in closed {
                if suppressed > 0 {
                    records.push(AuditRecord::quota_rejected_summary(
                        kind, &principal, suppressed,
                    ));
                }
            }
            if let Some(suppressed) = overflow_suppressed
                && suppressed > 0
            {
                records.push(AuditRecord::quota_rejected_summary(kind, "-", suppressed));
            }
        }
        records
    }

    /// Test-only accessors replacing the direct `windows[..].is_open()`
    /// field access the pre-Step-5 single-window-per-category shape used
    /// — `CategoryWindows`'s two fields are private so the invariants in
    /// its own doc comment (map cardinality, overflow separation) cannot
    /// be violated from outside this module even in tests.
    #[cfg(test)]
    pub(super) fn audit_window_is_open(&self, kind: QuotaKind, principal: &str) -> bool {
        // A deleted entry (`flush_expired`) reads as closed — deletion
        // *is* closure in this design, not merely "closure implies
        // deletion eventually".
        self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .per_principal
            .get(principal)
            .is_some_and(|state| state.start.is_some())
    }

    #[cfg(test)]
    pub(super) fn audit_window_principal_count(&self, kind: QuotaKind) -> usize {
        self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .per_principal
            .len()
    }

    #[cfg(test)]
    pub(super) fn audit_overflow_window_is_open(&self, kind: QuotaKind) -> bool {
        self.windows[kind as usize]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .overflow
            .start
            .is_some()
    }
}
