//! `exec.run` concurrency quota: [`Quotas::reserve_exec`] and its counters.

use super::*;

impl Quotas {
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
        // Read-only checks first (F9 of the M8 Step 3a conformance sweep):
        // `entry(..).or_insert(0)` ahead of either cap test would plant a
        // zero-valued map entry for a *refused* principal too, breaking
        // this module's own "no entry without a live resource" invariant
        // (this struct's doc comment) the moment a cap is `0` —
        // unreachable from parsed config (`0` degrades to the default
        // there) but reachable from any hand-built `QuotaLimits`, which is
        // exactly how tests (and 3b) construct one.
        //
        // Host axis first, then per-principal (M8 Step 3b, `QuotaLimits::
        // max_exec`): the host-wide count is derived as `Σ
        // exec_in_use.values()` — no separate counter, so it can never
        // drift from the per-principal counts that back it (this module's
        // own no-hand-maintained-counter discipline, restated for this
        // axis).
        let host_in_use: usize = state.exec_in_use.values().sum();
        if host_in_use >= self.limits.max_exec {
            return Err(QuotaKind::ExecHost);
        }
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
    pub(super) fn exec_in_use_principal_count(&self) -> usize {
        self.lock().exec_in_use.len()
    }
}
