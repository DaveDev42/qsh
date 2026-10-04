//! Noticing that the path under a live attach has died — fast enough to be
//! worth noticing (`docs/design/protocol.md` §2, `docs/design/testing.md`
//! L4).
//!
//! This is the half of the recovery story that has no QUIC answer. quinn
//! surfaces a connection that was *closed* (`Connection::closed`) and a
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
//! that is busy printing therefore never probes at all. That includes
//! traffic the control stream never sees: the watchdog also reads the
//! connection's UDP receive counter ([`ProbeSource::rx_datagrams`]) each
//! tick, so a `Pong` held up in ordered loss recovery on a lossy link does
//! not outvote datagrams that are visibly arriving.
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

/// What the watchdog measured at the tick it ruled [`Verdict::Dead`]: the
/// smoothed RTT it scaled the deadline by and how long the path had been
/// silent. Diagnostic only; [`Verdict`] itself stays payload-free.
///
/// `silence` is counted from the last liveness evidence of any kind: a
/// control or session message, or the tick at which the watchdog saw the
/// connection's UDP receive counter advance ([`ProbeSource::rx_datagrams`]),
/// whichever is later. The counter is only sampled per tick, so the figure is
/// tick-granular and can understate the real silence by at most one cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadVerdict {
    /// Smoothed RTT at the verdict.
    pub srtt: Duration,
    /// Time since the watchdog last saw the path carry anything.
    pub silence: Duration,
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
    /// Set by a wake: the next verdict probes at once, whatever the silence
    /// so far, instead of waiting out a cadence beat.
    probe_now: bool,
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
            probe_now: false,
        }
    }

    /// Something arrived from the host. Any traffic answers every
    /// outstanding probe: the question was "does this path carry packets".
    ///
    /// Deliberately **not** activity. A `Pong` is the watchdog talking to
    /// itself, and counting it would hold the attach inside
    /// [`PathWatchConfig::active_window`] forever — the fast cadence would
    /// keep answering itself and the slow one would never be reached on
    /// any path that is actually alive, which is exactly backwards.
    pub fn observe_inbound(&mut self, now: Instant) {
        self.last_inbound = now;
        self.unanswered = 0;
    }

    /// Session traffic arrived — output, an event, a `Ping` the host sent
    /// of its own accord. Proves the path *and* means the session is in
    /// use, so the fast cadence applies.
    pub fn observe_traffic(&mut self, now: Instant) {
        self.observe_inbound(now);
        self.last_activity = now;
    }

    /// The client did something a user would expect an answer to — typed,
    /// resized. Does not prove the path works, but does mean somebody is
    /// waiting, so the fast cadence applies.
    pub fn observe_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// The machine slept and woke (`super::wake`, ADR-0023 decision 17).
    /// Everything known about the path is stale, so this counts as activity
    /// (somebody is about to look, hence the fast cadence) and orders a
    /// probe on the very next verdict.
    ///
    /// The silence clock is left alone on purpose: it is measured on the
    /// monotonic clock from the last inbound byte before the sleep, so the
    /// strikes and `dead_after` that follow are not shortened or lengthened
    /// by how long the machine slept.
    pub fn observe_wake(&mut self, now: Instant) {
        self.last_activity = now;
        self.probe_now = true;
    }

    /// How long the path has been silent as of `now`: the time since the
    /// last liveness evidence: an inbound message, or a tick that saw the
    /// UDP receive counter move.
    pub fn silence(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_inbound)
    }

    /// Probes sent since the last inbound byte.
    pub fn unanswered(&self) -> u32 {
        self.unanswered
    }

    /// Whether nobody has been waiting on this attach for a whole
    /// [`PathWatchConfig::active_window`].
    pub fn is_idle(&self, now: Instant, cfg: &PathWatchConfig) -> bool {
        now.saturating_duration_since(self.last_activity) > cfg.active_window
    }

    /// How often this attach should be probing right now — which is also
    /// how long the watchdog task may sleep before deciding again.
    pub fn cadence(&self, now: Instant, cfg: &PathWatchConfig) -> Duration {
        if self.is_idle(now, cfg) {
            cfg.idle_probe_interval
        } else {
            cfg.probe_interval
        }
    }

    /// Decide one tick, recording a probe if it orders one.
    pub fn verdict(&mut self, now: Instant, rtt: Duration, cfg: &PathWatchConfig) -> Verdict {
        let silence = now.saturating_duration_since(self.last_inbound);
        // Death needs both: enough unanswered probes that this is not one
        // lost datagram, and enough silence that it is not a slow path.
        if self.unanswered >= cfg.strikes && silence >= cfg.dead_after(rtt) {
            return Verdict::Dead;
        }
        let cadence = self.cadence(now, cfg);
        let since_probe = self
            .last_probe
            .map_or(Duration::MAX, |at| now.saturating_duration_since(at));
        if std::mem::take(&mut self.probe_now) || (silence >= cadence && since_probe >= cadence) {
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
    /// What the watchdog measured when it ruled the path dead; `None` until
    /// then, and again after [`PathWatch::revive`]. Stays `None` when the
    /// death was declared some other way (`declare_dead` on a closed
    /// connection), which is how a caller tells its own ruling apart.
    dead_verdict: std::sync::Mutex<Option<DeadVerdict>>,
    /// How many pumps are currently parked on a full event queue. While
    /// this is non-zero the watchdog cannot see inbound traffic, so it
    /// refuses to judge.
    stalls: AtomicUsize,
    notify: tokio::sync::Notify,
    /// Bumped every time inbound traffic is reported, so a migration probe
    /// can wait for "anything at all" without polling.
    ///
    /// A `watch` channel rather than a `Notify`: a notification edge is
    /// only delivered to a waiter that has already registered, and the
    /// migration probe necessarily asks its question *before* it starts
    /// waiting for the answer. `subscribe()` snapshots the counter, so an
    /// answer that lands in that window is still seen and a live
    /// connection is not written off as unmigratable.
    inbound: tokio::sync::watch::Sender<u64>,
    /// Woken when the cadence changes under a sleeping watchdog, so
    /// "somebody came back to their terminal" is measured fast rather than
    /// after the rest of an idle-length beat.
    wake: tokio::sync::Notify,
}

impl PathWatch {
    /// Start watching, with the path assumed live as of now.
    pub fn new(cfg: PathWatchConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                cfg,
                state: std::sync::Mutex::new(PathState::new(Instant::now())),
                dead: AtomicBool::new(false),
                dead_verdict: std::sync::Mutex::new(None),
                stalls: AtomicUsize::new(0),
                notify: tokio::sync::Notify::new(),
                inbound: tokio::sync::watch::Sender::new(0),
                wake: tokio::sync::Notify::new(),
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

    /// Report bare liveness from the host — a `Pong`, and nothing else.
    /// Proves the path carries packets; says nothing about anybody
    /// waiting, so it does not move the cadence.
    pub fn inbound(&self) {
        self.state().observe_inbound(Instant::now());
        self.bump_inbound();
    }

    /// Report session traffic from the host: output, an event, a host
    /// `Ping`. Liveness *and* activity.
    pub fn traffic(&self) {
        self.observe(|state, now| state.observe_traffic(now));
        self.bump_inbound();
    }

    fn bump_inbound(&self) {
        self.inner.inbound.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// A snapshot of the inbound counter that resolves on the *next* report
    /// after it is taken. Used by the migration probe, whose question is
    /// "did anything come back", not "did this particular frame come back".
    pub fn inbound_signal(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.inbound.subscribe()
    }

    /// Reset the silence clock without reporting traffic.
    ///
    /// Used where the *absence* of a signal proves nothing rather than
    /// where a signal arrived: a window the watchdog could not see into.
    /// Deliberately does not bump the inbound counter — a migration probe
    /// waiting for an answer must not read the watchdog's own unblocking
    /// as one.
    fn restart_silence_clock(&self) {
        self.state().observe_inbound(Instant::now());
    }

    /// The connection's UDP receive counter advanced. Liveness only: not
    /// activity (it would pin the fast cadence, as a `Pong` would), and it
    /// does not bump the inbound signal, because a migration probe asks
    /// whether the *host answered*, not whether the transport ACKed
    /// something.
    fn datagrams_moved(&self) {
        self.state().observe_inbound(Instant::now());
    }

    /// Report local activity (input, resize, an accepted local connection)
    /// — somebody is waiting.
    pub fn activity(&self) {
        self.observe(|state, now| state.observe_activity(now));
    }

    /// Report that the machine woke from sleep. See
    /// [`PathState::observe_wake`]. [`watch_path`] calls this itself when
    /// the process wake detector fires and judges immediately afterwards.
    pub fn wake(&self) {
        // Not through `observe`: the caller judges right away, so waking a
        // sleeping watchdog through the cadence-change `Notify` as well
        // would only leave a stale permit behind.
        self.state().observe_wake(Instant::now());
    }

    /// Apply one observation, waking a watchdog that is sleeping out an
    /// idle-length beat if this is what put the attach back in use.
    fn observe(&self, f: impl FnOnce(&mut PathState, Instant)) {
        let now = Instant::now();
        let cfg = self.inner.cfg;
        let was_idle = {
            let mut state = self.state();
            let was_idle = state.is_idle(now, &cfg);
            f(&mut state, now);
            was_idle
        };
        // Only on the transition: on a busy attach the beat is already
        // fast, and waking the watchdog per keystroke would be a lot of
        // noise for a cadence that does not change.
        if was_idle {
            self.inner.wake.notify_one();
        }
    }

    /// The beat this attach is on right now.
    pub fn cadence(&self) -> Duration {
        let cfg = self.inner.cfg;
        self.state().cadence(Instant::now(), &cfg)
    }

    /// Resolve when something changed the cadence under a sleeping
    /// watchdog. Safe as a `select!` arm: a missed wake only costs the
    /// rest of one beat.
    pub async fn woken(&self) {
        self.inner.wake.notified().await;
    }

    /// Decide one tick against `rtt`.
    pub fn verdict(&self, rtt: Duration) -> Verdict {
        // A pump parked on a full queue is not reading, so silence proves
        // nothing. Treat the window as live and start the clock again from
        // here, rather than banking strikes the path never earned.
        if self.inner.stalls.load(Ordering::Acquire) > 0 {
            self.restart_silence_clock();
            return Verdict::Healthy;
        }
        let cfg = self.inner.cfg;
        let now = Instant::now();
        let mut state = self.state();
        let verdict = state.verdict(now, rtt, &cfg);
        if verdict == Verdict::Dead {
            let silence = state.silence(now);
            drop(state);
            *self.dead_verdict_slot() = Some(DeadVerdict { srtt: rtt, silence });
        }
        verdict
    }

    fn dead_verdict_slot(&self) -> std::sync::MutexGuard<'_, Option<DeadVerdict>> {
        self.inner
            .dead_verdict
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// What this watch's own watchdog measured when it ruled the path dead,
    /// or `None` if it never did (the path was never declared dead, or
    /// something else declared it: a closed connection, a caller of
    /// [`declare_dead`](Self::declare_dead)).
    pub fn dead_verdict(&self) -> Option<DeadVerdict> {
        *self.dead_verdict_slot()
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
        *self.dead_verdict_slot() = None;
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
        self.watch.restart_silence_clock();
    }
}

/// What [`watch_path`] needs from the connection carrying probes: an
/// unambiguous "this is gone" signal, and the RTT that scales the death
/// deadline (`PathWatchConfig::dead_after`). Nothing about *sending* a
/// probe lives here — deliberately: on both roles, writing to the control
/// stream is owned by a single task for cancel-safety reasons (see
/// `ops/session.rs`'s `pump_attach_control` doc comment on why
/// `Session::next_event` is unsafe to call from a `select!` arm that can be
/// cancelled), so `watch_path` only ever *asks* for a probe (the `probes`
/// `Notify` parameter below) and never writes one itself.
///
/// This is the seam M3 Step 4 exists to add: until now the only
/// implementation was the client attach's own `qsh_transport::Connection`
/// (below), because `PathWatch`/`watch_path` were wired only into
/// `ops/session.rs`'s attach/recovery driver. The host role's own
/// connection handle (`server::ConnCtx`'s `conn_id` aside, the host holds a
/// plain `qsh_transport::Connection` too — `reverse/target.rs`'s
/// `run_reverse` and `server::Server::serve_connection` both do) satisfies
/// this trait through the exact same blanket impl: closed-ness and RTT are
/// role-agnostic properties of the transport connection, not of who is
/// dialing whom. What *is* new for the host role is the other half of the
/// loop — who answers `Verdict::Probe` by actually writing a `Ping` and
/// correlating the `Pong` — and that lives in `server::ControlPinger`
/// (`server/mod.rs`), not here: the judgment policy in this module is
/// unchanged.
pub trait ProbeSource: Send + Sync + 'static {
    /// Resolves when the underlying connection is unambiguously gone —
    /// QUIC close, reset, or (in the limit) the 45 s idle timeout. No
    /// probing is useful past this point.
    fn closed(&self) -> impl std::future::Future<Output = ()> + Send;

    /// Current smoothed RTT, used to scale `PathWatchConfig::dead_after`.
    fn rtt(&self) -> Duration;

    /// Total UDP datagrams received on this connection so far. Any advance
    /// proves the path carries packets towards us, even when the control
    /// stream is stuck in ordered loss recovery (a lost `Pong` waits for a
    /// retransmit, which on a lossy link can outlast the death budget while
    /// datagrams keep arriving). [`watch_path`] counts an advance as
    /// inbound traffic; a counter that stops moving leaves the verdict
    /// schedule untouched. A source with no such counter must return a
    /// constant, which falls back to control-stream liveness alone.
    fn rx_datagrams(&self) -> u64;
}

impl ProbeSource for qsh_transport::Connection {
    async fn closed(&self) {
        // The specific `quinn::ConnectionError` is diagnostic-only here —
        // `watch_path`'s caller learns "dead", not "why", the same way a
        // silence-based verdict never learns why either.
        let _ = qsh_transport::Connection::closed(self).await;
    }

    fn rtt(&self) -> Duration {
        self.quinn().stats().path.rtt
    }

    fn rx_datagrams(&self) -> u64 {
        self.quinn().stats().udp_rx.datagrams
    }
}

/// Drive one attach's watchdog until the path dies or the attach ends.
///
/// `probes` wakes the task that owns the control stream, which is the only
/// place a `Ping` can be written from. `source` is generic over
/// [`ProbeSource`] so the same judgment policy drives either role's
/// connection — see that trait's doc comment.
pub async fn watch_path<S: ProbeSource>(
    source: S,
    watch: PathWatch,
    probes: std::sync::Arc<tokio::sync::Notify>,
) {
    watch_path_with_wake(source, watch, probes, super::wake::subscribe()).await;
}

/// [`watch_path`] with the wake signal supplied, so a test can inject one
/// without touching the process-wide detector.
///
/// A wake is judged at once rather than after the next beat: the watchdog
/// records it (activity plus an immediate probe, `PathState::observe_wake`)
/// and falls straight through to the verdict. With no answer, three probes at
/// the fast cadence and `dead_after(rtt)` of silence later the path is
/// declared dead: `WAKE_TICK + dead_after(rtt)` after the machine woke at the
/// outside (ADR-0023 decision 17).
pub(crate) async fn watch_path_with_wake<S: ProbeSource>(
    source: S,
    watch: PathWatch,
    probes: std::sync::Arc<tokio::sync::Notify>,
    mut wake_rx: tokio::sync::watch::Receiver<super::wake::WakeEvent>,
) {
    let mut wake_closed = false;
    let mut last_rx = source.rx_datagrams();
    loop {
        // Re-read every round rather than arming a fixed ticker: the beat
        // *is* the power budget, and an attach nobody is using must not
        // wake this task four times a second to learn something nobody is
        // waiting to hear.
        let period = watch.cadence();
        tokio::select! {
            // The unambiguous case: QUIC itself gave up, or the peer
            // closed. No probing needed, and no reason to wait for a tick.
            () = source.closed() => {
                tracing::debug!("attach connection closed; path is dead");
                watch.declare_dead();
                return;
            }
            // The attach went from idle to in-use while we were sleeping
            // out a five-second beat. Re-time rather than finish it: "I
            // came back to my terminal" is the case that has to be
            // measured at the fast cadence.
            () = watch.woken() => continue,
            () = tokio::time::sleep(period) => {}
            // The machine slept. `changed()` is cancel-safe and the
            // receiver keeps the value, so a wake that lands while the
            // verdict below is running is seen on the next round.
            woke = async {
                if wake_closed {
                    std::future::pending().await
                } else {
                    wake_rx.changed().await
                }
            } => {
                if woke.is_err() {
                    // Detector gone (only possible with an injected
                    // sender): nothing more will ever arrive, so stop
                    // polling it rather than spin.
                    wake_closed = true;
                    continue;
                }
                tracing::debug!(
                    slept_ms = wake_rx.borrow_and_update().slept_ms,
                    "machine woke from sleep; judging the path now"
                );
                watch.wake();
            }
        }
        // Any datagram since the last tick proves the path carries packets,
        // whether or not a control-stream reply made it through ordered
        // recovery. Read before judging so a moving counter never banks a
        // strike.
        let rx = source.rx_datagrams();
        if rx != last_rx {
            last_rx = rx;
            watch.datagrams_moved();
        }
        let rtt = source.rtt();
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
mod tests;
