//! End R's state: what a `qsh listen` keeps to relay `PunchRequest`s
//! (ADR-0054 decisions 6, 10, 11). The relay itself is `Listen`'s
//! (`reverse::listen`, it owns the registrations); this is the part that
//! needs no connection: the on/off switch, the cap on punching connections
//! and the per-initiator attempt table.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use qsh_proto::punch::RENDEZVOUS_MAX_CLIENTS;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::limits::{AttemptLimiter, LimitHit};

/// How long a punching connection may sit without a request, and how long it
/// may linger after the answer (ADR-0054 decision 10).
pub const RENDEZVOUS_IDLE: Duration = Duration::from_secs(3);

/// How long R waits for B's `PunchAnswer` (ADR-0054 decision 10,
/// `PUNCH_ANSWER_TIMEOUT`).
pub const PUNCH_ANSWER_TIMEOUT: Duration = Duration::from_millis(1500);

/// The rendezvous' shared state.
pub struct RendezvousState {
    enabled: AtomicBool,
    clients: Arc<Semaphore>,
    limiter: Mutex<AttemptLimiter>,
}

impl Default for RendezvousState {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            clients: Arc::new(Semaphore::new(RENDEZVOUS_MAX_CLIENTS)),
            limiter: Mutex::new(AttemptLimiter::new(true)),
        }
    }
}

impl std::fmt::Debug for RendezvousState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RendezvousState")
            .field("enabled", &self.enabled())
            .field("clients", &self.clients())
            .finish()
    }
}

/// An attempt's slot in the table; dropping it ends the attempt.
pub struct AttemptSlot<'a> {
    state: &'a RendezvousState,
    initiator: [u8; 32],
}

impl Drop for AttemptSlot<'_> {
    fn drop(&mut self) {
        self.state.table().finish(&self.initiator);
    }
}

impl RendezvousState {
    /// `[punch].mode = "off"` turns relaying off.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// Whether this listener relays.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Punching connections open now.
    pub fn clients(&self) -> usize {
        RENDEZVOUS_MAX_CLIENTS - self.clients.available_permits()
    }

    /// A slot for one more punching connection, or `None` at the cap.
    pub fn try_client(&self) -> Option<OwnedSemaphorePermit> {
        self.clients.clone().try_acquire_owned().ok()
    }

    fn table(&self) -> MutexGuard<'_, AttemptLimiter> {
        self.limiter.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts an attempt of `initiator`: one in flight and `PUNCH_RATE` per
    /// window. The slot frees the in-flight mark when dropped.
    pub fn begin_attempt(&self, initiator: [u8; 32]) -> Result<AttemptSlot<'_>, LimitHit> {
        self.table().try_begin(&initiator, Instant::now())?;
        Ok(AttemptSlot {
            state: self,
            initiator,
        })
    }
}
