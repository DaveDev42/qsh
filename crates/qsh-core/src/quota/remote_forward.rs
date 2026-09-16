//! Remote-forward quota per principal: [`Quotas::reserve_remote_forward`].

use super::*;

impl Quotas {
    /// Reserve one live remote-forward listener for `principal_key`
    /// (`[serve].max_remote_forwards_per_principal`, M8 Step 3b). `Err(
    /// QuotaKind::RemoteForwardsPerPrincipal)` if the principal is already
    /// at its cap — read-only check first, same F9 discipline as
    /// [`Quotas::reserve_exec`]/[`Quotas::reserve_tunnel_stream`] (a `0`
    /// cap must never plant a zero-valued entry for a refused principal).
    pub fn reserve_remote_forward(
        &self,
        principal_key: &str,
    ) -> Result<RemoteForwardPermit, QuotaKind> {
        let mut state = self.lock();
        let count = state
            .remote_forwards_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0);
        if count >= self.limits.max_remote_forwards_per_principal {
            return Err(QuotaKind::RemoteForwardsPerPrincipal);
        }
        *state
            .remote_forwards_per_principal
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
        Ok(RemoteForwardPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
        })
    }

    /// Current live remote-forward reservation count for `principal_key`
    /// — test/diagnostic use only. `pub`, not `#[cfg(test)]`, matching
    /// [`Quotas::exec_in_use`]'s own visibility, since `crate::server`'s
    /// own test module (a different module in the same crate) needs it
    /// too.
    pub fn remote_forwards_per_principal_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .remote_forwards_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct principals with a map entry in
    /// `remote_forwards_per_principal` — test-only, same "entry present
    /// holding `0`" distinction `exec_in_use_principal_count` exists for.
    #[cfg(test)]
    pub(super) fn remote_forwards_per_principal_entry_count(&self) -> usize {
        self.lock().remote_forwards_per_principal.len()
    }
}
