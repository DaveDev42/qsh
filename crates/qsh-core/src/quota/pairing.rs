//! Pairing-connection quota: [`Quotas::reserve_pairing_connection`].

use super::*;

impl Quotas {
    /// Reserve one of the fixed [`MAX_CONCURRENT_PAIRING_CONNECTIONS`]
    /// slots for a pre-identity (`Principal::Pairing`) connection, or
    /// refuse with [`QuotaKind::PairingConnections`]. Not configurable
    /// (M8 Step 3b ruling R2) and not keyed by principal — a pairing
    /// connection has none yet.
    pub fn reserve_pairing_connection(&self) -> Result<PairingConnectionPermit, QuotaKind> {
        let mut state = self.lock();
        if state.pairing_connections_in_use >= MAX_CONCURRENT_PAIRING_CONNECTIONS {
            self.connection_counters
                .pairing_refused
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(
                target: "qsh_core::quota",
                kind = ?QuotaKind::PairingConnections,
                "quota decision: refuse"
            );
            return Err(QuotaKind::PairingConnections);
        }
        state.pairing_connections_in_use += 1;
        drop(state);
        self.connection_counters
            .pairing_reserved
            .fetch_add(1, Ordering::Relaxed);
        tracing::trace!(target: "qsh_core::quota", "quota decision: reserve pairing connection");
        Ok(PairingConnectionPermit {
            quotas: self.self_weak.clone(),
        })
    }

    /// Current live pairing-connection reservation count — test/
    /// diagnostic use only.
    pub fn pairing_connections_in_use(&self) -> usize {
        self.lock().pairing_connections_in_use
    }
}
