//! Tunnel-stream quotas, per principal and per forward: [`Quotas::reserve_tunnel_stream`].

use super::*;

impl Quotas {
    /// Reserve one tunnel (`-L`) stream slot for `principal_key` dialing
    /// `resource` (`host:port`, [`qsh_proto::wire::format_host_port`]'s
    /// canonical form — the same string
    /// `crate::server::Server::authorize_and_dial_tunnel` uses as its ACL
    /// resource), or refuse with [`QuotaKind::TunnelStreamsPerPrincipal`]
    /// / [`QuotaKind::TunnelStreamsPerForward`] if either axis is already
    /// at its cap.
    ///
    /// Principal axis checked first, forward axis second — broader before
    /// narrower, same direction as [`Quotas::reserve_exec`]'s
    /// host-before-principal order: every forward-axis count is a subset
    /// of its principal's total, so a caller already at the broader cap
    /// learns *that* reason rather than the narrower one. Read-only
    /// checks first, same F9 discipline as `reserve_exec` (a `0` cap must
    /// never plant a zero-valued entry for a refused principal).
    pub fn reserve_tunnel_stream(
        &self,
        principal_key: &str,
        resource: &str,
    ) -> Result<TunnelStreamPermit, QuotaKind> {
        let mut state = self.lock();
        let principal_count = state
            .tunnel_streams_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0);
        if principal_count >= self.limits.max_tunnel_streams_per_principal {
            return Err(QuotaKind::TunnelStreamsPerPrincipal);
        }
        let forward_key = (principal_key.to_string(), resource.to_string());
        let forward_count = state
            .tunnel_streams_per_forward
            .get(&forward_key)
            .copied()
            .unwrap_or(0);
        if forward_count >= self.limits.max_tunnel_streams_per_forward {
            return Err(QuotaKind::TunnelStreamsPerForward);
        }
        *state
            .tunnel_streams_per_principal
            .entry(principal_key.to_string())
            .or_insert(0) += 1;
        *state
            .tunnel_streams_per_forward
            .entry(forward_key)
            .or_insert(0) += 1;
        drop(state);
        Ok(TunnelStreamPermit {
            quotas: self.self_weak.clone(),
            principal_key: principal_key.to_string(),
            resource: resource.to_string(),
        })
    }

    /// Current live tunnel-stream reservation count for `principal_key`
    /// across every destination — test/diagnostic use only.
    ///
    /// `pub(crate)`, not module-private: `tunnel::remote`'s own
    /// principal-axis test observes this axis the same way the
    /// forward-axis tests observe theirs.
    #[cfg(test)]
    pub(crate) fn tunnel_streams_per_principal_in_use(&self, principal_key: &str) -> usize {
        self.lock()
            .tunnel_streams_per_principal
            .get(principal_key)
            .copied()
            .unwrap_or(0)
    }

    /// Current live tunnel-stream reservation count for
    /// `(principal_key, resource)` — test-only observation, the forward-axis
    /// twin of [`Quotas::tunnel_streams_per_principal_in_use`].
    ///
    /// `#[cfg(test)]` rather than `pub` (M8 Step 4b): the `-R` accept-permit
    /// e2e in `qsh-testkit` observes the permit through the refused TCP
    /// accept and the audit row, so no caller outside this crate exists.
    /// Widen to `pub` (as [`Quotas::pairing_connections_in_use`] is) only
    /// when one appears. No logic beyond the lookup; not part of the permit
    /// decision itself.
    #[cfg(test)]
    pub(crate) fn tunnel_streams_per_forward_in_use(
        &self,
        principal_key: &str,
        resource: &str,
    ) -> usize {
        self.lock()
            .tunnel_streams_per_forward
            .get(&(principal_key.to_string(), resource.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Number of distinct principals with a map entry in
    /// `tunnel_streams_per_principal` — test-only, same "entry present
    /// holding `0`" distinction `exec_in_use_principal_count` exists for.
    #[cfg(test)]
    pub(super) fn tunnel_streams_per_principal_entry_count(&self) -> usize {
        self.lock().tunnel_streams_per_principal.len()
    }

    /// Number of distinct `(principal, destination)` pairs with a map
    /// entry in `tunnel_streams_per_forward` — test-only, same purpose as
    /// [`Quotas::tunnel_streams_per_principal_entry_count`] for the
    /// narrower axis.
    #[cfg(test)]
    pub(super) fn tunnel_streams_per_forward_entry_count(&self) -> usize {
        self.lock().tunnel_streams_per_forward.len()
    }
}
