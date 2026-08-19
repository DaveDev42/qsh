//! Noticing that the path under a live attach has died — fast enough to be
//! worth noticing (`docs/design/protocol.md` §2, `docs/design/testing.md`
//! L4).
//!
//! This is the half of the recovery story that has no QUIC answer. quinn
//! surfaces a connection that was *closed* ([`Connection::closed`]) and a
//! connection that has been silent for its whole idle timeout — 45 s
//! (`protocol.md` §2). Neither describes the case the product exists for: a
//! laptop that changed networks, whose packets now go nowhere while the
//! connection state on both ends is perfectly healthy. Waiting out the idle
//! timeout is explicitly *not* a pass (`testing.md` L4), so the client has
//! to ask the question itself.
//!
//! **The question is a `Ping`.** The control stream already carries one
//! (`protocol.md` §9) and every host answers it, so a probe costs a few
//! bytes and needs no protocol change. What counts as an answer is
//! deliberately loose: *any* inbound traffic — a `Pong`, a `SessionEvent`,
//! a frame of session output — proves the path carries packets. A session
//! that is busy printing therefore never probes at all.
//!
//! **Two cadences, because a shell is idle most of its life.** Probing four
//! times a second forever would wake a sleeping laptop's radio to learn
//! something nobody is waiting to hear. So the fast cadence runs only while
//! the attach is *active* (bytes moved, or the user typed, inside
//! [`PathWatchConfig::active_window`]); outside it the probe drops to a
//! slow beat that still finds a dead path long before the idle timeout
//! would. The moment the user touches the keyboard the attach is active
//! again, so the case that matters — "I came back to my terminal" — is
//! always measured at the fast cadence.
//!
//! **The deadline scales with the path.** A fixed timeout is either too
//! tight for a satellite link or too loose for a LAN, so death is declared
//! at `max(min_dead_after, rtt × rtt_multiple)` using quinn's smoothed RTT
//! — the closest thing to the "PTO 실패" `protocol.md` §2 names. A false
//! positive costs a re-dial and a replay, never correctness; that asymmetry
//! is why the defaults lean towards declaring death rather than waiting.
//!
//! **A stalled consumer is not a dead path.** If the frontend stops
//! draining events, the pumps park on a full queue and stop reading — which
//! looks exactly like silence. Callers wrap those awaits in
//! [`PathWatch::stalled`] so the watchdog refuses to judge a window it
//! cannot see into, rather than guessing.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// How the watchdog behaves. Every field is a knob a slow or lossy link may
/// want to move; the defaults are what the M2 gate is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathWatchConfig {
    /// Probe cadence while the attach is active. Also the watchdog's tick.
    pub probe_interval: Duration,
    /// Probe cadence once the attach has been quiet for
    /// [`active_window`](Self::active_window).
    pub idle_probe_interval: Duration,
    /// How long after the last byte (either way) an attach counts as
    /// active.
    pub active_window: Duration,
    /// Floor on the silence that declares a path dead, whatever the RTT.
    pub min_dead_after: Duration,
    /// Multiple of the smoothed RTT that raises that floor on a slow path.
    pub rtt_multiple: u32,
    /// Unanswered probes required before silence can be called death. More
    /// than one, so a single lost datagram is not a verdict.
    pub strikes: u32,
}

impl Default for PathWatchConfig {
    fn default() -> Self {
        Self {
            // 250 ms × 3 strikes puts detection at ~1 s on a fast path:
            // comfortably inside the 2 s the recovery itself is allowed
            // (`reconnect::REDIAL_DEADLINE`) and two orders of magnitude
            // away from the 45 s idle timeout that must never be the
            // mechanism.
            probe_interval: Duration::from_millis(250),
            idle_probe_interval: Duration::from_secs(5),
            active_window: Duration::from_secs(15),
            min_dead_after: Duration::from_secs(1),
            rtt_multiple: 8,
            strikes: 3,
        }
    }
}

impl PathWatchConfig {
    /// The silence that means death on a path with this smoothed RTT.
    fn dead_after(&self, rtt: Duration) -> Duration {
        self.min_dead_after
            .max(rtt.saturating_mul(self.rtt_multiple))
    }
}

/// What the watchdog decided on one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing to do.
    Healthy,
    /// Send a liveness `Ping`.
    Probe,
    /// The path is dead; recover.
    Dead,
}

/// The watchdog's bookkeeping, as a pure state machine over an injected
/// clock.
///
/// Separated from the task that drives it so the policy — when to probe,
/// when to give up — is testable without a socket, a timer or a sleep.
#[derive(Debug, Clone, Copy)]
pub struct PathState {
    last_inbound: Instant,
    last_activity: Instant,
    last_probe: Option<Instant>,
    unanswered: u32,
}

impl PathState {
    /// A path that has just proven itself (an attach starts here: the
    /// `SessionAttached` response is inbound traffic).
    pub fn new(now: Instant) -> Self {
        Self {
            last_inbound: now,
            last_activity: now,
            last_probe: None,
            unanswered: 0,
        }
    }

    /// Something arrived from the host. Any traffic answers every
    /// outstanding probe: the question was "does this path carry packets".
    pub fn observe_inbound(&mut self, now: Instant) {
        self.last_inbound = now;
        self.last_activity = now;
        self.unanswered = 0;
    }

    /// The client did something a user would expect an answer to — typed,
    /// resized. Does not prove the path works, but does mean somebody is
    /// waiting, so the fast cadence applies.
    pub fn observe_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Probes sent since the last inbound byte.
    pub fn unanswered(&self) -> u32 {
        self.unanswered
    }

    /// Decide one tick, recording a probe if it orders one.
    pub fn verdict(&mut self, now: Instant, rtt: Duration, cfg: &PathWatchConfig) -> Verdict {
        let silence = now.saturating_duration_since(self.last_inbound);
        // Death needs both: enough unanswered probes that this is not one
        // lost datagram, and enough silence that it is not a slow path.
        if self.unanswered >= cfg.strikes && silence >= cfg.dead_after(rtt) {
            return Verdict::Dead;
        }
        let cadence = if now.saturating_duration_since(self.last_activity) <= cfg.active_window {
            cfg.probe_interval
        } else {
            cfg.idle_probe_interval
        };
        let since_probe = self
            .last_probe
            .map_or(Duration::MAX, |at| now.saturating_duration_since(at));
        if silence >= cadence && since_probe >= cadence {
            self.last_probe = Some(now);
            self.unanswered += 1;
            return Verdict::Probe;
        }
        Verdict::Healthy
    }
}

/// A shared handle on one attach's liveness: the pumps report traffic into
/// it, the watchdog reads it, and anything waiting on a dead path awaits
/// [`PathWatch::dead`].
#[derive(Debug, Clone)]
pub struct PathWatch {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    cfg: PathWatchConfig,
    state: std::sync::Mutex<PathState>,
    dead: AtomicBool,
    /// How many pumps are currently parked on a full event queue. While
    /// this is non-zero the watchdog cannot see inbound traffic, so it
    /// refuses to judge.
    stalls: AtomicUsize,
    notify: tokio::sync::Notify,
    /// Woken every time inbound traffic is reported, so a migration probe
    /// can wait for "anything at all" without polling.
    inbound: tokio::sync::Notify,
}

impl PathWatch {
    /// Start watching, with the path assumed live as of now.
    pub fn new(cfg: PathWatchConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                cfg,
                state: std::sync::Mutex::new(PathState::new(Instant::now())),
                dead: AtomicBool::new(false),
                stalls: AtomicUsize::new(0),
                notify: tokio::sync::Notify::new(),
                inbound: tokio::sync::Notify::new(),
            }),
        }
    }

    /// The configuration this watch runs on.
    pub fn config(&self) -> &PathWatchConfig {
        &self.inner.cfg
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PathState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Report traffic from the host.
    pub fn inbound(&self) {
        self.state().observe_inbound(Instant::now());
        self.inner.inbound.notify_waiters();
    }

    /// Resolve on the next inbound traffic reported *after* this is
    /// awaited. Used by the migration probe, whose question is "did
    /// anything come back", not "did this particular frame come back".
    pub async fn next_inbound(&self) {
        self.inner.inbound.notified().await;
    }

    /// Report local activity (input, resize) — somebody is waiting.
    pub fn activity(&self) {
        self.state().observe_activity(Instant::now());
    }

    /// Decide one tick against `rtt`.
    pub fn verdict(&self, rtt: Duration) -> Verdict {
        // A pump parked on a full queue is not reading, so silence proves
        // nothing. Treat the window as live and start the clock again from
        // here, rather than banking strikes the path never earned.
        if self.inner.stalls.load(Ordering::Acquire) > 0 {
            self.inbound();
            return Verdict::Healthy;
        }
        let cfg = self.inner.cfg;
        self.state().verdict(Instant::now(), rtt, &cfg)
    }

    /// Mark the path dead and wake everything waiting on it. Idempotent.
    pub fn declare_dead(&self) {
        if !self.inner.dead.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    /// Whether the path has been declared dead.
    pub fn is_dead(&self) -> bool {
        self.inner.dead.load(Ordering::Acquire)
    }

    /// Un-declare a death that turned out to be survivable: the connection
    /// migrated, so the same streams keep working and the same watch keeps
    /// watching. The state is reset rather than kept, because the strikes
    /// that produced the verdict were earned on a path that no longer
    /// exists.
    pub fn revive(&self) {
        *self.state() = PathState::new(Instant::now());
        self.inner.dead.store(false, Ordering::Release);
    }

    /// Resolve once the path is dead. Never resolves for a healthy path,
    /// so it is safe as a `select!` arm.
    pub async fn dead(&self) {
        loop {
            // Register before the check: a `declare_dead` racing us in
            // between must not be missed.
            let notified = self.inner.notify.notified();
            if self.is_dead() {
                return;
            }
            notified.await;
            if self.is_dead() {
                return;
            }
        }
    }

    /// Guard the caller's await against being mistaken for a dead path.
    /// While any guard is alive the watchdog declares nothing.
    pub fn stalled(&self) -> StallGuard {
        self.inner.stalls.fetch_add(1, Ordering::AcqRel);
        StallGuard {
            watch: self.clone(),
        }
    }
}

/// See [`PathWatch::stalled`].
#[derive(Debug)]
pub struct StallGuard {
    watch: PathWatch,
}

impl Drop for StallGuard {
    fn drop(&mut self) {
        self.watch.inner.stalls.fetch_sub(1, Ordering::AcqRel);
        // The window we could not see into is over; start measuring from
        // now rather than from whenever the last byte happened to land.
        self.watch.inbound();
    }
}

/// Drive one attach's watchdog until the path dies or the attach ends.
///
/// `probes` wakes the task that owns the control stream, which is the only
/// place a `Ping` can be written from.
pub async fn watch_path(
    conn: qsh_transport::Connection,
    watch: PathWatch,
    probes: std::sync::Arc<tokio::sync::Notify>,
) {
    let period = watch.config().probe_interval;
    let mut ticker = tokio::time::interval_at(Instant::now() + period, period);
    // A watchdog that fell behind wants the *next* tick, not a burst of
    // catch-up ticks each banking a strike.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            // The unambiguous case: QUIC itself gave up, or the peer
            // closed. No probing needed, and no reason to wait for a tick.
            _ = conn.closed() => {
                tracing::debug!("attach connection closed; path is dead");
                watch.declare_dead();
                return;
            }
            _ = ticker.tick() => {}
        }
        let rtt = conn.quinn().stats().path.rtt;
        match watch.verdict(rtt) {
            Verdict::Healthy => {}
            // `notify_one` keeps a permit if the control pump is busy, so
            // a probe asked for while it was writing still goes out — and
            // several asked for in a row collapse into one, which is what
            // an unanswered path deserves.
            Verdict::Probe => probes.notify_one(),
            Verdict::Dead => {
                tracing::debug!(
                    rtt_ms = rtt.as_millis() as u64,
                    "no answer from the host; declaring the path dead"
                );
                watch.declare_dead();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PathWatchConfig {
        PathWatchConfig::default()
    }

    const LAN: Duration = Duration::from_millis(1);

    #[test]
    fn a_talking_host_is_never_probed() {
        let cfg = cfg();
        let t0 = Instant::now();
        let mut state = PathState::new(t0);
        // Output every 100 ms: never silent for a whole probe interval.
        for step in 1..40u32 {
            let now = t0 + Duration::from_millis(100) * step;
            state.observe_inbound(now);
            assert_eq!(state.verdict(now, LAN, &cfg), Verdict::Healthy);
        }
        assert_eq!(state.unanswered(), 0);
    }

    #[test]
    fn silence_earns_probes_and_then_a_verdict() {
        let cfg = cfg();
        let t0 = Instant::now();
        let mut state = PathState::new(t0);
        let at = |ms: u64| t0 + Duration::from_millis(ms);

        assert_eq!(state.verdict(at(100), LAN, &cfg), Verdict::Healthy);
        assert_eq!(state.verdict(at(250), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.verdict(at(400), LAN, &cfg), Verdict::Healthy);
        assert_eq!(state.verdict(at(500), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.verdict(at(750), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.unanswered(), 3);
        // Three strikes, but the silence floor is not reached yet.
        assert_eq!(state.verdict(at(999), LAN, &cfg), Verdict::Healthy);
        assert_eq!(state.verdict(at(1_000), LAN, &cfg), Verdict::Dead);
    }

    /// The whole point of the exercise: detection lands far inside the 2 s
    /// the recovery itself is allowed, and nowhere near the 45 s idle
    /// timeout that must never be the mechanism.
    #[test]
    fn detection_is_far_inside_the_recovery_budget() {
        let cfg = cfg();
        let t0 = Instant::now();
        let mut state = PathState::new(t0);
        let mut declared = None;
        for ms in 1..=45_000u64 {
            let now = t0 + Duration::from_millis(ms);
            if state.verdict(now, LAN, &cfg) == Verdict::Dead {
                declared = Some(ms);
                break;
            }
        }
        let ms = declared.expect("a silent path must be declared dead");
        assert!(
            ms <= 1_500,
            "detection took {ms} ms; the 2 s recovery budget starts *after* this"
        );
        assert!(
            ms < 45_000,
            "detection must not be quinn's idle timeout in disguise"
        );
    }

    /// A single lost datagram on an otherwise live path must not be a
    /// verdict: the answer that arrives clears the strikes.
    #[test]
    fn one_answer_clears_the_strikes() {
        let cfg = cfg();
        let t0 = Instant::now();
        let mut state = PathState::new(t0);
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        assert_eq!(state.verdict(at(250), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.verdict(at(500), LAN, &cfg), Verdict::Probe);
        state.observe_inbound(at(600));
        assert_eq!(state.unanswered(), 0);
        assert_eq!(state.verdict(at(1_200), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.verdict(at(1_300), LAN, &cfg), Verdict::Healthy);
    }

    /// A slow path is judged on its own RTT, not on a number picked for a
    /// LAN: eight round trips of silence, not one second.
    #[test]
    fn a_slow_path_gets_a_deadline_of_its_own() {
        let cfg = cfg();
        let rtt = Duration::from_millis(400); // 8 × 400 ms = 3.2 s
        let t0 = Instant::now();
        let mut state = PathState::new(t0);
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        for ms in [250, 500, 750, 1_000, 1_250] {
            state.verdict(at(ms), rtt, &cfg);
        }
        assert!(state.unanswered() >= cfg.strikes);
        assert_ne!(
            state.verdict(at(2_000), rtt, &cfg),
            Verdict::Dead,
            "a 400 ms path is not dead after 2 s of silence"
        );
        assert_eq!(state.verdict(at(3_200), rtt, &cfg), Verdict::Dead);
    }

    /// An attach nobody is using drops to the slow cadence — and typing
    /// puts it straight back on the fast one, because that is the moment a
    /// user starts caring.
    #[test]
    fn an_idle_attach_probes_slowly_until_the_user_types() {
        let cfg = cfg();
        let t0 = Instant::now();
        let mut state = PathState::new(t0);
        let at = |secs: u64| t0 + Duration::from_secs(secs);

        // Past the active window: probes are 5 s apart, not 250 ms, and no
        // amount of slow probing declares death — the silence floor is met
        // but the strikes only accrue one per 5 s.
        assert_eq!(state.verdict(at(16), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.verdict(at(18), LAN, &cfg), Verdict::Healthy);
        assert_eq!(state.verdict(at(20), LAN, &cfg), Verdict::Healthy);
        assert_eq!(state.verdict(at(21), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.verdict(at(23), LAN, &cfg), Verdict::Healthy);

        // The user types: the cadence is fast again, so the verdict lands a
        // quarter-second later rather than five seconds later. The strikes
        // banked while idle still count — the path was already suspect.
        state.observe_activity(at(26));
        assert_eq!(state.verdict(at(26), LAN, &cfg), Verdict::Probe);
        assert_eq!(state.unanswered(), cfg.strikes);
        assert_eq!(
            state.verdict(at(26) + cfg.probe_interval, LAN, &cfg),
            Verdict::Dead
        );
    }

    #[tokio::test]
    async fn a_stalled_consumer_is_not_a_dead_path() {
        let watch = PathWatch::new(cfg());
        let guard = watch.stalled();
        // However long the frontend parks us, no strike is banked: the
        // watchdog cannot see inbound traffic it is not reading.
        for _ in 0..100 {
            assert_eq!(watch.verdict(LAN), Verdict::Healthy);
        }
        assert!(!watch.is_dead());
        drop(guard);
        assert_eq!(watch.verdict(LAN), Verdict::Healthy);
    }

    #[tokio::test]
    async fn death_is_observable_before_and_after_it_is_declared() {
        let watch = PathWatch::new(cfg());
        let waiting = watch.clone();
        let task = tokio::spawn(async move { waiting.dead().await });
        watch.declare_dead();
        assert!(watch.is_dead());
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("a declared death must wake its waiters")
            .expect("join");
        // Already dead: resolves immediately, and stays idempotent.
        watch.declare_dead();
        tokio::time::timeout(Duration::from_secs(5), watch.dead())
            .await
            .expect("an already-dead path resolves at once");
    }

    #[tokio::test(start_paused = true)]
    async fn a_healthy_path_never_resolves_dead() {
        let watch = PathWatch::new(cfg());
        assert!(
            tokio::time::timeout(Duration::from_secs(600), watch.dead())
                .await
                .is_err(),
            "a path nobody declared dead must not resolve"
        );
    }
}
