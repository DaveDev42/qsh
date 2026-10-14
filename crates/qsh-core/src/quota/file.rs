//! File-transfer concurrency quota: [`Quotas::reserve_file_transfer`]
//! (ADR-0029 decision 12).

use super::*;

impl Quotas {
    /// Reserve one `file.read`/`file.write` transfer slot for
    /// `principal_key`, or refuse with the axis that is full: the host-wide
    /// axis ([`QuotaKind::FilesHost`], `[serve].max_file_transfers`) first,
    /// then the principal's ([`QuotaKind::FilesPerPrincipal`]) -- the same
    /// order and the same read-only-checks-first discipline as
    /// [`Quotas::reserve_exec`] (a `0` cap must never plant a zero-valued
    /// entry for a refused principal). The host count is derived as `Σ
    /// files_in_use.values()`, no separate counter.
    ///
    /// The caller holds the returned [`FilePermit`] on the ticket, so the
    /// slot is released when the transfer ends or the ticket expires.
    /// `file.list` and `file.mkdir` leave no resource behind and never come
    /// here.
    pub fn reserve_file_transfer(&self, principal_key: &str) -> Result<FilePermit, QuotaKind> {
        let mut state = self.lock();
        let host_in_use: usize = state.files_in_use.values().sum();
        if host_in_use >= self.limits.max_file_transfers {
            return Err(QuotaKind::FilesHost);
        }
        let current = state.files_in_use.get(principal_key).copied().unwrap_or(0);
        if current >= self.limits.max_file_transfers_per_principal {
            return Err(QuotaKind::FilesPerPrincipal);
        }
        *state
            .files_in_use
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
        Ok(FilePermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
        })
    }

    /// Current live file-transfer reservation count for `principal_key` --
    /// test/diagnostic use only.
    pub fn files_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .files_in_use
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Live file-transfer reservations across every principal (the derived
    /// host axis) -- test/diagnostic use only.
    pub fn files_in_use_total(&self) -> usize {
        self.lock().files_in_use.values().sum()
    }

    /// Number of principals with a `files_in_use` entry -- test-only, the
    /// "entry present holding `0`" distinction.
    #[cfg(test)]
    pub(super) fn files_in_use_entry_count(&self) -> usize {
        self.lock().files_in_use.len()
    }
}
