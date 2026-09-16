//! Connection quotas, per principal and in total: [`Quotas::reserve_connection`].

use super::*;

impl Quotas {
    /// Reserve one live connection slot for `principal_key` (an
    /// [`crate::acl::opener_key`] string, same as every other per-
    /// principal axis in this module), or refuse with
    /// [`QuotaKind::Connections`] (host/accept-arm-wide,
    /// `[serve].max_connections`) or [`QuotaKind::ConnectionsPerPrincipal`]
    /// (`[serve].max_connections_per_principal`) if either axis is already
    /// at its cap.
    ///
    /// Host axis first, then per-principal — same order as
    /// [`Quotas::reserve_exec`] (host → principal, M8 Step 3b ruling R3),
    /// derived as `Σ connections_per_principal.values()` rather than a
    /// separate counter, same discipline as `reserve_exec`'s
    /// `ExecHost`. Read-only checks first, same F9 discipline as every
    /// other `reserve_*` here (a `0` cap must never plant a zero-valued
    /// entry for a refused principal).
    ///
    /// Called from the *outer* frame of a connection's accept path
    /// (`crate::server::Server::serve_connection`,
    /// `crate::reverse::listen::Listen::accept_and_register_permitted`) —
    /// before the inner `Hello` exchange even runs, so a peer that never
    /// sends `Hello` at all is still counted (ruling R3).
    pub fn reserve_connection(&self, principal_key: &str) -> Result<ConnectionPermit, QuotaKind> {
        let mut state = self.lock();
        let host_in_use: usize = state.connections_per_principal.values().sum();
        if host_in_use >= self.limits.max_connections {
            self.connection_counters
                .connection_refused
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::quota",
                kind = ?QuotaKind::Connections,
                "quota decision: refuse"
            );
            return Err(QuotaKind::Connections);
        }
        let current = state
            .connections_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0);
        if current >= self.limits.max_connections_per_principal {
            self.connection_counters
                .connection_refused
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::quota",
                kind = ?QuotaKind::ConnectionsPerPrincipal,
                "quota decision: refuse"
            );
            return Err(QuotaKind::ConnectionsPerPrincipal);
        }
        *state
            .connections_per_principal
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        drop(state);
        self.connection_counters
            .connection_reserved
            .fetch_add(1, Ordering::Relaxed);
        tracing::trace!(target: "qsh_core::quota", "quota decision: reserve connection");
        Ok(ConnectionPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
        })
    }

    /// Current live connection reservation count for `principal_key` —
    /// `pub`, not `#[cfg(test)]`, matching [`Quotas::
    /// remote_forwards_per_principal_in_use`]'s own visibility: both
    /// `crate::server` and `crate::reverse::listen`'s test modules need
    /// it.
    pub fn connections_per_principal_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .connections_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Total live connection reservations across every principal — the
    /// same `Σ connections_per_principal.values()` [`Quotas::
    /// reserve_connection`]'s own host-axis check already computes
    /// (M8 Step 5a: the accept-loop heartbeat's `live_conns` field).
    pub fn total_connections_in_use(&self) -> usize {
        self.lock().connections_per_principal.values().sum()
    }

    /// Number of distinct principals with a map entry in
    /// `connections_per_principal` — test-only, same "entry present
    /// holding `0`" distinction `exec_in_use_principal_count` exists for.
    #[cfg(test)]
    pub(super) fn connections_per_principal_entry_count(&self) -> usize {
        self.lock().connections_per_principal.len()
    }
}
