//! Noticing that the machine slept (ADR-0023 decision 17).
//!
//! quinn cannot tell "the laptop lid was closed for ten minutes" from "the
//! path is slow": on macOS and Linux the monotonic clock (`Instant`, and so
//! every tokio timer) stops while the machine sleeps, but the wall clock
//! (`SystemTime`) keeps counting. So once per [`WAKE_TICK`] the detector
//! reads both, and when the wall clock advanced by at least [`WAKE_SKEW`]
//! more than the monotonic clock did, the difference is time the process
//! spent asleep. Consumers ([`super::pathwatch::watch_path`], and later the
//! supervise and target backoffs) treat that as "everything you knew about
//! the path is stale, look again now".
//!
//! **Only forward wall-clock jumps count.** A wall clock that moves backwards
//! (an NTP step, a manual change) is never a wake. Each tick compares only
//! the two steps since the *previous* tick and then re-baselines, so a slow
//! NTP slew (at most a few hundred ppm) never accumulates into a false
//! positive, and a backward step cannot leave a stale baseline that makes a
//! later ordinary tick look like a jump. A forward NTP step of three seconds
//! or more is indistinguishable from a short sleep and is accepted as a
//! false positive: it costs a few probes and a backoff restart.
//!
//! **One detector per process.** The first [`subscribe`] starts a single
//! one-second timer task; it stops on its own when the last subscriber is
//! gone, so an idle process pays nothing and no packet is ever sent. The
//! task is tied to whichever runtime started it, so a subscriber arriving
//! after that runtime is gone (test binaries build many) restarts it.
//!
//! Windows: whether `Instant` stops during sleep there is unverified
//! (ROADMAP M19). If it does not, the two clocks never diverge, the detector
//! never fires, and behaviour is exactly what it was before it existed.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tokio::time::Instant;

/// How often the wall and monotonic clocks are compared.
pub const WAKE_TICK: Duration = Duration::from_secs(1);

/// How far the wall clock must outrun the monotonic clock, within one tick,
/// to count as a wake.
pub const WAKE_SKEW: Duration = Duration::from_secs(3);

/// The wall-clock source. Injected so tests can move it by hand; product
/// code uses [`SystemWallClock`].
pub trait WallClock: Send + Sync + 'static {
    /// The current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// [`SystemTime::now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// What subscribers observe. `seq` counts wakes since the detector started
/// (0 means none yet); `slept_ms` is the skew of the latest one.
///
/// Carried by a `watch` channel, so a subscriber that was busy when a wake
/// fired still sees it on its next `changed()`. Two wakes inside one busy
/// spell coalesce into the latest value, and `seq` shows how many there were.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WakeEvent {
    /// Wake counter.
    pub seq: u64,
    /// Milliseconds the wall clock outran the monotonic clock on the latest
    /// wake.
    pub slept_ms: u64,
}

/// The pure comparison: two clock readings per tick in, a verdict out.
#[derive(Debug, Clone, Copy)]
pub struct WakeSense {
    last_wall: SystemTime,
    last_mono: Instant,
}

impl WakeSense {
    /// Baseline both clocks.
    pub fn new(wall: SystemTime, mono: Instant) -> Self {
        Self {
            last_wall: wall,
            last_mono: mono,
        }
    }

    /// Compare one tick. Returns the slept duration when this tick is a
    /// wake. Always re-baselines, whatever the outcome.
    pub fn tick(&mut self, wall: SystemTime, mono: Instant) -> Option<Duration> {
        let mono_step = mono.saturating_duration_since(self.last_mono);
        // `Err` means the wall clock went backwards: never a wake.
        let wall_step = wall.duration_since(self.last_wall);
        self.last_wall = wall;
        self.last_mono = mono;
        let skew = wall_step.ok()?.checked_sub(mono_step)?;
        (skew >= WAKE_SKEW).then_some(skew)
    }
}

struct Shared {
    tx: watch::Sender<WakeEvent>,
    clock: Arc<dyn WallClock>,
    /// The running tick task, if any. The task clears this itself (under the
    /// lock) when it finds no subscriber left, so `subscribe` can never
    /// hand out a receiver to a task that is about to exit.
    task: Mutex<Option<tokio::task::AbortHandle>>,
}

/// A wake detector. The process-wide one is reached through [`subscribe`];
/// tests build their own around a fake [`WallClock`].
#[derive(Clone)]
pub struct WakeDetector {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for WakeDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeDetector").finish_non_exhaustive()
    }
}

impl WakeDetector {
    /// A detector over `clock`. Nothing runs until the first subscription.
    pub fn new(clock: Arc<dyn WallClock>) -> Self {
        Self {
            shared: Arc::new(Shared {
                tx: watch::Sender::new(WakeEvent::default()),
                clock,
                task: Mutex::new(None),
            }),
        }
    }

    /// Subscribe to wakes, starting the tick task if it is not running. The
    /// receiver treats the current value as already seen, so only wakes
    /// after this call are delivered. Must be called inside a tokio runtime.
    pub fn subscribe(&self) -> watch::Receiver<WakeEvent> {
        let mut task = self
            .shared
            .task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The receiver exists before the exit check below can run, so a
        // task that decides to stop under this same lock sees it.
        let rx = self.shared.tx.subscribe();
        if task.as_ref().is_none_or(|h| h.is_finished()) {
            // Baseline synchronously: a jump between `subscribe` returning
            // and the task's first poll must not be swallowed into it.
            let sense = WakeSense::new(self.shared.clock.now(), Instant::now());
            let shared = Arc::clone(&self.shared);
            *task = Some(tokio::spawn(run(shared, sense)).abort_handle());
        }
        rx
    }
}

async fn run(shared: Arc<Shared>, mut sense: WakeSense) {
    loop {
        tokio::time::sleep(WAKE_TICK).await;
        {
            let mut task = shared
                .task
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if shared.tx.receiver_count() == 0 {
                *task = None;
                return;
            }
        }
        if let Some(slept) = sense.tick(shared.clock.now(), Instant::now()) {
            shared.tx.send_modify(|e| {
                e.seq += 1;
                e.slept_ms = u64::try_from(slept.as_millis()).unwrap_or(u64::MAX);
            });
        }
    }
}

/// A detector a test plugs into the process-wide [`subscribe`], so code that
/// subscribes on its own (the tunnel supervisor) sees a wake the test
/// injects by moving a fake [`WallClock`]. Nextest gives each test its own
/// process, so a set-once slot is enough.
#[cfg(test)]
static TEST_DETECTOR: OnceLock<WakeDetector> = OnceLock::new();

/// Route the process-wide [`subscribe`] to `detector` for the rest of this
/// test process.
#[cfg(test)]
pub(crate) fn install_process_detector_for_test(detector: WakeDetector) {
    assert!(
        TEST_DETECTOR.set(detector).is_ok(),
        "a test detector is already installed in this process"
    );
}

/// Subscribe to the process-wide detector.
pub fn subscribe() -> watch::Receiver<WakeEvent> {
    #[cfg(test)]
    if let Some(detector) = TEST_DETECTOR.get() {
        return detector.subscribe();
    }
    static GLOBAL: OnceLock<WakeDetector> = OnceLock::new();
    GLOBAL
        .get_or_init(|| WakeDetector::new(Arc::new(SystemWallClock)))
        .subscribe()
}

#[cfg(test)]
mod tests;
