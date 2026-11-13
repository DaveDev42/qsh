//! The route memory of the forward dial (ADR-0061 decision 1,
//! `docs/CLI.md` §6.1 "route 기억").
//!
//! A direct dial and a punch to a pin that also has the iroh relay route
//! cost the user a head start every time when the network in front of them
//! drops those packets. This device therefore remembers, per pin, that the
//! iroh route won while the direct dial and the punch had not stood, and the
//! next dial starts iroh at once and leaves them out. Four rules:
//!
//! 1. A pin whose last dial was won by iroh while the direct dial and the
//!    punch were not standing is in a rest: dials start iroh with no head
//!    start and do not start them. If iroh fails before the dial's time is
//!    up, they start then, as a fallback, and a win by them ends the rest.
//! 2. A rest ends after 10 minutes, doubling with every consecutive time
//!    iroh won again, up to one hour. The first dial after it runs them
//!    beside iroh (no head start), so the user waits no longer than before.
//!    A win by the direct dial or the punch removes the memory of the pin.
//! 3. The memory is kept for one network. When the set of source addresses
//!    this device would use towards the internet (the routing-table lookup
//!    the punch also uses, [`LocalAddrs`]) changes, which covers an address
//!    change and a default-route change, every pin is forgotten.
//! 4. A recovery or `--supervise` re-dial asks the same memory, so a string
//!    of re-dials does not knock on a blocked route more often than rule 2.
//!
//! The memory is a file, `route-cache.json` in the state directory. It is
//! internal state and not a contract: a file that cannot be read or does not
//! parse is an empty memory and is written over, and a write that fails is
//! ignored. It holds a hash of the network, the pins' fingerprints and
//! timestamps, and no address.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::punch::LocalAddrs;

/// The first rest after the iroh route won over a route that did not stand.
pub const FIRST_REST: Duration = Duration::from_secs(10 * 60);

/// The longest rest.
pub const MAX_REST: Duration = Duration::from_secs(60 * 60);

/// The most pins the file remembers; the ones whose rest ends first go.
const MAX_PINS: usize = 256;

/// The longest the file may be before it is treated as corrupt.
const MAX_FILE_BYTES: u64 = 256 * 1024;

const VERSION: u32 = 1;

/// Where the memory reads the time from. Production uses the wall clock (the
/// file outlives a process); a test sets its own.
pub trait RouteClock: Send + Sync + 'static {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRouteClock;

impl RouteClock for SystemRouteClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// How a dial treats the direct dial and the punch (rule 1 and 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stance {
    /// Nothing is remembered: the usual order, iroh after its head start.
    Normal,
    /// The pin is in a rest: iroh at once, the others only as a fallback.
    Skip,
    /// A rest has ended: the others run beside iroh, iroh at once.
    Retry,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct PinMemory {
    /// How many times in a row iroh won over a route that did not stand.
    failures: u32,
    /// When the rest began, in milliseconds since the epoch; it lasts
    /// [`rest_after`]`(failures)`.
    since_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct State {
    version: u32,
    /// A hash of the network the memory belongs to.
    network: String,
    /// By the pin's fingerprint.
    pins: BTreeMap<String, PinMemory>,
}

/// The memory of one pin, over the shared file.
#[derive(Clone)]
pub struct RouteMemory {
    path: Arc<PathBuf>,
    pin: Arc<str>,
    clock: Arc<dyn RouteClock>,
    addrs: Arc<dyn LocalAddrs>,
}

impl std::fmt::Debug for RouteMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteMemory")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// The rest after `failures` consecutive wins of iroh over a route that did
/// not stand: 10 minutes, doubling, one hour at most.
pub fn rest_after(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(8);
    FIRST_REST.saturating_mul(1u32 << doublings).min(MAX_REST)
}

/// A hash of the addresses this device sends from towards the internet. An
/// empty observation (offline) has no signature: it neither matches nor
/// forgets anything.
fn network_signature(observed: &[std::net::IpAddr]) -> Option<String> {
    if observed.is_empty() {
        return None;
    }
    let mut lines: Vec<String> = observed
        .iter()
        .map(|ip| ip.to_canonical().to_string())
        .collect();
    lines.sort();
    lines.dedup();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"qsh route memory network v1\n");
    for line in &lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    Some(hasher.finalize().to_hex().to_string())
}

impl RouteMemory {
    /// The memory of the pin with fingerprint `pin`, in the file at `path`.
    pub fn new(
        path: PathBuf,
        pin: impl Into<Arc<str>>,
        clock: Arc<dyn RouteClock>,
        addrs: Arc<dyn LocalAddrs>,
    ) -> Self {
        Self {
            path: Arc::new(path),
            pin: pin.into(),
            clock,
            addrs,
        }
    }

    fn read(&self) -> State {
        let Ok(meta) = std::fs::metadata(&*self.path) else {
            return State::default();
        };
        if meta.len() > MAX_FILE_BYTES {
            return State::default();
        }
        std::fs::read(&*self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<State>(&bytes).ok())
            .filter(|s| s.version == VERSION)
            .unwrap_or_default()
    }

    fn write(&self, state: &State) {
        let Ok(bytes) = serde_json::to_vec(state) else {
            return;
        };
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // A failed write is a memory that did not take; nothing depends on it.
        let _ = crate::fsutil::write_atomically(&self.path, &bytes, false);
    }

    /// The state with the network rule applied: when this device's network
    /// is not the one the file was written for, the pins are dropped.
    /// Returns whether the state changed and must be written.
    fn sync_network(&self, state: &mut State) -> bool {
        let Some(now) = network_signature(&self.addrs.observe()) else {
            return false;
        };
        if state.network == now {
            return false;
        }
        state.network = now;
        state.pins.clear();
        state.version = VERSION;
        true
    }

    /// How the next dial treats the direct dial and the punch.
    pub fn stance(&self) -> Stance {
        let mut state = self.read();
        if self.sync_network(&mut state) {
            self.write(&state);
        }
        match state.pins.get(&*self.pin) {
            None => Stance::Normal,
            Some(memory) => {
                let now = self.clock.now_ms();
                let end = memory
                    .since_ms
                    .saturating_add(duration_ms(rest_after(memory.failures)));
                // A clock that went back before the rest began cannot be
                // measured against it: the dial retries the others, beside
                // iroh, which costs the user nothing.
                if now >= memory.since_ms && now < end {
                    Stance::Skip
                } else {
                    Stance::Retry
                }
            }
        }
    }

    /// The direct dial or the punch won: whatever was remembered about the
    /// pin is gone.
    pub fn note_other_won(&self) {
        let mut state = self.read();
        let mut changed = self.sync_network(&mut state);
        changed |= state.pins.remove(&*self.pin).is_some();
        if changed {
            self.write(&state);
        }
    }

    /// The iroh route won. `other_ran` is whether the direct dial and the
    /// punch ran in that dial without standing; when they did not run (the
    /// pin was resting) the rest is left as it is.
    pub fn note_iroh_won(&self, other_ran: bool) {
        let mut state = self.read();
        let mut changed = self.sync_network(&mut state);
        if other_ran {
            let now = self.clock.now_ms();
            let failures = state
                .pins
                .get(&*self.pin)
                .map_or(0, |m| m.failures)
                .saturating_add(1);
            state.pins.insert(
                self.pin.to_string(),
                PinMemory {
                    failures,
                    since_ms: now,
                },
            );
            if state.pins.len() > MAX_PINS {
                let mut by_rest: Vec<(u64, String)> = state
                    .pins
                    .iter()
                    .map(|(k, v)| {
                        let end = v
                            .since_ms
                            .saturating_add(duration_ms(rest_after(v.failures)));
                        (end, k.clone())
                    })
                    .collect();
                by_rest.sort();
                let drop = state.pins.len() - MAX_PINS;
                for (_, key) in by_rest.into_iter().take(drop) {
                    state.pins.remove(&key);
                }
            }
            changed = true;
        }
        if changed {
            state.version = VERSION;
            self.write(&state);
        }
    }
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
