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
//! that is busy printing therefore never probes at all.
//!
//! **An authenticated QUIC frame is an answer too.** A `Pong` rides the
//! ordered control stream, so loss recovery on that one stream can hold it
//! back while the peer's packets keep arriving (issue #10). The watchdog
//! therefore also reads [`ProbeSource::rx_frames`] each tick and treats a
//! counter that moved as inbound traffic. The counter is quinn's
//! post-decryption frame count, so only a peer that can encrypt moves it.
//!
//! **A raw datagram is a hint, not an answer.** The connection's UDP
//! receive counter ([`ProbeSource::rx_datagrams`]) counts packets before
//! decryption, and anyone who knows the connection ID can forge those. It
//! therefore never declares the path alive. When the death verdict is due
//! and datagrams arrived recently without any authenticated frame, the
//! watchdog grants **one** grace extension of
//! [`PathWatchConfig::datagram_grace`] per dead-timer cycle; if no
//! authenticated frame shows up inside it the path is dead. A spoofer can
//! thus delay detection by that one grace and no more, and an authenticated
//! frame restarts the cycle.
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
//! A reverse registration is the exception, because its loss ends every
//! tunnel carried on it with no replay; it gets
//! [`PathWatchConfig::reverse_default`] on both ends.
//!
//! **A starved watchdog is not a dead path either.** The watch measures the
//! path with its own timer, so a process that was not scheduled (a host at
//! load 50, a debugger, a `SIGSTOP`) reads its own absence as the path's
//! silence. [`PathState::observe_tick`] compares each tick's actual gap with
//! the beat it slept; a tick that fired a whole [`PathWatchConfig::probe_interval`]
//! or more late discounts that lateness from the silence and cannot rule the
//! path dead on that tick (ADR-0042 decision 1). This is the sibling of the
//! wake detector (`super::wake`): that one fires when the monotonic clock
//! *stopped* (the wall clock outran it), this one when the monotonic clock
//! ran and the process did not.
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
    /// The default for a reverse registration connection, on both ends of
    /// it: the target's `qsh serve --to` watch and the controller's
    /// `qsh listen` watch (ADR-0041).
    ///
    /// The probe cadence and strike count are [`Default::default`]'s; only
    /// the silence floor moves, from 1 s to 4.25 s. An interactive attach
    /// wants a dead path called within its 2 s redial budget. A registration
    /// has no one waiting on it, and each loss drops every reverse tunnel
    /// carried on it with no replay, so it is worth riding out the 2 to 4 s
    /// uplink bursts a lossy Wi-Fi hop produces (the longest measured in
    /// issue #10 was 3.6 s; the watchdog samples per tick, so it can see
    /// up to one cadence more). `P×S+D` is then exactly 5 s, the
    /// `REVERSE_DETECTION_CEILING_MS` that `config::RecoverySection`
    /// enforces on every `[recovery]` override.
    pub fn reverse_default() -> Self {
        Self {
            min_dead_after: Duration::from_millis(4_250),
            ..Self::default()
        }
    }

    /// How late a watchdog tick must fire before the lateness is blamed on
    /// this process rather than the path (ADR-0042 decision 1): one probe
    /// interval, the unit a strike is counted in. Derived rather than a
    /// field so the struct, and the byte-identical `Debug` output the
    /// `[recovery]` knobs promise, do not change.
    fn self_delay_threshold(&self) -> Duration {
        self.probe_interval
    }

    /// The one extension granted when the dead-path timer expires while raw
    /// UDP datagrams were still arriving but no authenticated frame did
    /// ([`ProbeSource::rx_datagrams`]): `probe_interval × strikes`, one
    /// whole round of probes (750 ms by default, on the reverse default too).
    /// Once per dead-timer cycle, and only an authenticated frame starts a
    /// new cycle, so it is also the most a forger can delay a verdict.
    /// Derived rather than a field, like [`Self::self_delay_threshold`], so
    /// the `Debug` output the `[recovery]` knobs promise does not change.
    pub fn datagram_grace(&self) -> Duration {
        self.probe_interval.saturating_mul(self.strikes)
    }

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
/// `silence` is counted from the last authenticated liveness evidence: a
/// control or session message, or an authenticated QUIC frame counted by the
/// transport ([`ProbeSource::rx_frames`], stamped at the previous tick),
/// whichever is later. Raw datagrams ([`ProbeSource::rx_datagrams`]) do not
/// reset it, so it includes any grace that was granted. The counter is only
/// sampled per tick, so the figure is tick-granular.
/// Time a late tick showed this process was not running is discounted from it
/// ([`PathState::observe_tick`]), so it is the silence the watch actually
/// observed, not wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadVerdict {
    /// Smoothed RTT at the verdict.
    pub srtt: Duration,
    /// Time since the watchdog last saw the path carry anything, less any
    /// time it was itself too late to see.
    pub silence: Duration,
    /// How late the watchdog's latest-running tick was, at its worst, since
    /// it last saw the path carry anything: the gap between two consecutive
    /// ticks less the beat the watchdog slept (`gap - expected`), so the
    /// cadence itself (250 ms active, 5 s idle) never shows. A healthy
    /// process reads a few milliseconds or zero, on either cadence; a figure
    /// of seconds says this process was starved while the verdict's silence
    /// built up. Surfaces as `tick_gap_ms` on the diagnostic line.
    pub tick_gap: Duration,
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
    /// Greatest tick lateness (gap less the beat slept) seen since the last
    /// liveness evidence.
    max_tick_gap: Duration,
    /// How late the tick about to be judged fired, when it fired a whole
    /// [`PathWatchConfig::probe_interval`] or more late. The verdict takes
    /// it once: a path cannot be ruled dead on a tick unless its silence
    /// also clears `dead_after` by this much, because whatever arrived
    /// while this process was not running is still waiting to be read.
    pending_margin: Duration,
    /// When a raw UDP datagram last arrived without being credited as an
    /// authenticated frame. Cleared by any authenticated evidence.
    last_datagram: Option<Instant>,
    /// When this dead-timer cycle's one grace extension began. Set once the
    /// verdict was due with a fresh datagram hint; cleared by any
    /// authenticated evidence, which is what starts a new cycle.
    grace_started: Option<Instant>,
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
            max_tick_gap: Duration::ZERO,
            pending_margin: Duration::ZERO,
            last_datagram: None,
            grace_started: None,
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
        self.new_cycle();
        // The tick lateness in a verdict describes the silence it ruled on,
        // so it starts over with every piece of evidence.
        self.max_tick_gap = Duration::ZERO;
    }

    /// The transport saw authenticated frames arrive from the peer at some
    /// instant no later than `at`. Liveness only: it moves the silence clock
    /// forward (never backward) and answers every outstanding probe, and it
    /// is **not** activity, for the same reason [`observe_inbound`](Self::observe_inbound) is not.
    ///
    /// `at` is a lower bound on when the frames arrived, so the silence it
    /// leaves behind can only be overstated, never understated.
    pub fn observe_inbound_since(&mut self, at: Instant) {
        self.last_inbound = self.last_inbound.max(at);
        self.unanswered = 0;
        self.new_cycle();
    }

    /// Authenticated evidence ends the dead-timer cycle: the datagram hint
    /// and any grace already spent belong to the silence that just ended.
    fn new_cycle(&mut self) {
        self.last_datagram = None;
        self.grace_started = None;
    }

    /// A raw UDP datagram arrived at `at` and no authenticated frame came
    /// with it. A **hint** only: it does not touch the silence clock or the
    /// strikes, so it cannot answer a probe or keep a path alive. It only
    /// makes the death verdict eligible for the one grace extension
    /// ([`Self::verdict`]).
    pub fn observe_datagram(&mut self, at: Instant) {
        self.last_datagram = Some(self.last_datagram.map_or(at, |prev| prev.max(at)));
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

    /// One watchdog tick fired `gap` after the previous one, having slept
    /// `expected`. Returns how late it was when that was a self-delay.
    ///
    /// A tick that fires a whole [`PathWatchConfig::probe_interval`] or more
    /// late means this process, not the path, was away: the host was
    /// starved, or the runtime did not get to the timer. Silence counted
    /// over that stretch says nothing about the path, so the lateness is
    /// moved off the silence clock (`last_inbound` shifts forward by it,
    /// never past `now`) and this tick may not rule the path dead unless
    /// the silence clears `dead_after` by that lateness as well
    /// ([`Self::verdict`]); the next on-time tick judges as usual, by which
    /// time the datagrams that queued up while this process was away have
    /// been read. The lateness of every tick, whether or not it clears the
    /// threshold, feeds [`DeadVerdict::tick_gap`]; the raw gap does not,
    /// because on the idle cadence a healthy gap is the 5 s beat itself.
    ///
    /// `probe_interval` is the threshold because it is the unit of a strike:
    /// a tick that late has lost a whole probe slot, so the strike count is
    /// already distorted by as much as one strike. Anything shorter only
    /// inflates the silence by less than the tick granularity it already
    /// has. Silence the clock did not run through (a sleeping machine) is
    /// the wake detector's, not this one's.
    ///
    /// Lateness is discounted, not forgiven: a path that really is dead is
    /// still ruled dead once the *observed* silence reaches `dead_after`,
    /// so a host that is starved on every tick delays the verdict in
    /// proportion instead of disabling it.
    pub fn observe_tick(
        &mut self,
        now: Instant,
        gap: Duration,
        expected: Duration,
        cfg: &PathWatchConfig,
    ) -> Option<Duration> {
        let late = gap.saturating_sub(expected);
        self.max_tick_gap = self.max_tick_gap.max(late);
        if late < cfg.self_delay_threshold() {
            return None;
        }
        self.last_inbound = self
            .last_inbound
            .checked_add(late)
            .map_or(now, |shifted| shifted.min(now));
        self.pending_margin = late;
        Some(late)
    }

    /// The greatest tick lateness since the last liveness evidence.
    pub fn max_tick_gap(&self) -> Duration {
        self.max_tick_gap
    }

    /// How long the path has been silent as of `now`: the time since the
    /// last authenticated liveness evidence: an inbound message, or
    /// authenticated frames the transport counted.
    pub fn silence(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_inbound)
    }

    /// Forget the margin a late tick banked for its own verdict
    /// ([`Self::observe_tick`]).
    fn discard_pending_margin(&mut self) {
        self.pending_margin = Duration::ZERO;
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
        // A tick that fired late rules only on silence that also clears the
        // lateness ([`Self::observe_tick`]); taken here so it covers exactly
        // this tick.
        let margin = std::mem::take(&mut self.pending_margin);
        // Death needs both: enough unanswered probes that this is not one
        // lost datagram, and enough silence that it is not a slow path.
        if self.unanswered >= cfg.strikes && silence >= cfg.dead_after(rtt).saturating_add(margin) {
            // Raw datagrams are a hint, never proof: they buy one bounded
            // grace per cycle, and only while they are recent. Once the
            // grace is spent the verdict stands until an authenticated
            // frame arrives, however many datagrams keep coming.
            let grace = cfg.datagram_grace();
            let hinted = self
                .last_datagram
                .is_some_and(|at| now.saturating_duration_since(at) <= grace);
            match self.grace_started {
                Some(started) if now.saturating_duration_since(started) >= grace => {
                    return Verdict::Dead;
                }
                Some(_) => {}
                None if hinted => self.grace_started = Some(now),
                None => return Verdict::Dead,
            }
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

    /// Report that the transport received authenticated frames from the
    /// peer at some instant no later than `at` (see
    /// [`PathState::observe_inbound_since`]). Liveness only.
    ///
    /// Unlike [`inbound`](Self::inbound) this does not bump the inbound
    /// counter: the migration probe waits for an application-level answer
    /// ([`inbound_signal`](Self::inbound_signal)), and the transport's own
    /// ACKs must not read as one.
    pub(crate) fn transport_inbound(&self, at: Instant) {
        self.state().observe_inbound_since(at);
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
        let mut state = self.state();
        state.observe_inbound(Instant::now());
        // A margin banked by a late tick belongs to the verdict that tick
        // was about to give. Whoever restarts the clock has just made that
        // verdict moot, and a stale margin would defer a later real death
        // by one tick.
        state.discard_pending_margin();
    }

    /// The connection's UDP receive counter advanced, with no authenticated
    /// frame to show for it. A hint for the bounded grace
    /// ([`PathState::observe_datagram`]), not liveness: it neither answers
    /// probes nor moves the silence clock, and it does not bump the inbound
    /// signal.
    fn datagrams_seen(&self, at: Instant) {
        self.state().observe_datagram(at);
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

    /// One watchdog tick fired `gap` after the previous one, having slept
    /// `expected`. See [`PathState::observe_tick`]; returns the lateness
    /// when it was discounted.
    fn ticked(&self, gap: Duration, expected: Duration) -> Option<Duration> {
        let cfg = self.inner.cfg;
        self.state()
            .observe_tick(Instant::now(), gap, expected, &cfg)
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
            let tick_gap = state.max_tick_gap();
            drop(state);
            *self.dead_verdict_slot() = Some(DeadVerdict {
                srtt: rtt,
                silence,
                tick_gap,
            });
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

    /// A monotonic count of authenticated QUIC frames received from the
    /// peer; only its *movement* is read. When it moves between two ticks
    /// the path carried the peer's packets and the peer can encrypt: this is
    /// the signal that declares the path alive, whether or not a `Pong`
    /// made it through the ordered control stream
    /// (`docs/design/protocol.md` §10).
    ///
    /// The default is a constant, which never moves: a source that cannot
    /// say relies on control-stream traffic alone.
    fn rx_frames(&self) -> u64 {
        0
    }

    /// Total UDP datagrams received on this connection so far, counted
    /// before decryption. Only a **hint**: anyone who knows the connection
    /// ID can forge datagrams, so an advance here never proves liveness. It
    /// only earns the dead-path timer one bounded grace extension per cycle
    /// ([`PathWatchConfig::datagram_grace`]) when no authenticated frame
    /// arrived, so a `Pong` and ACKs held up by loss recovery on a lossy
    /// link are not ruled dead while packets are visibly landing, and a
    /// spoofer can postpone the verdict by that bounded amount at most.
    ///
    /// The default is a constant, which never moves.
    fn rx_datagrams(&self) -> u64 {
        0
    }
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

    fn rx_frames(&self) -> u64 {
        qsh_transport::Connection::rx_frames(self)
    }

    fn rx_datagrams(&self) -> u64 {
        self.quinn().stats().udp_rx.datagrams
    }
}

/// Turns movement of [`ProbeSource::rx_frames`] into liveness and movement
/// of [`ProbeSource::rx_datagrams`] into the grace hint.
///
/// A `Pong` rides the ordered control stream, so one packet lost on a busy
/// connection holds every later control message behind loss recovery even
/// while the peer's datagrams keep arriving (issue #10: a reverse
/// registration carrying tunnel data was declared `path_dead` with packets
/// still landing every 100-300 ms). The frame counter moves for any frame,
/// on any stream or none, so it answers the watchdog's real question (does
/// this path carry packets from the peer) without waiting behind that queue.
///
/// **The stamp is the previous sample, never now.** Frames counted between
/// two samples arrived after the earlier sample was taken, so the earlier
/// instant is a safe lower bound on their arrival. Stamping with the current
/// tick instead would credit the path with up to one tick of liveness it may
/// not have had and stretch the time a blackout takes to be noticed.
///
/// And the stamp is refreshed on **every** sample, whether or not the
/// counter moved. A stamp left over from the last time it moved would make a
/// path that was merely quiet for a while look as if it had been silent for
/// that whole while, and with the strikes reset by the movement the death
/// verdict could arrive before `min_dead_after` of real silence.
struct RxLiveness {
    frames: u64,
    datagrams: u64,
    sampled_at: Instant,
}

impl RxLiveness {
    fn new<S: ProbeSource>(source: &S) -> Self {
        // Time first, counters second: a frame counted by this read may have
        // landed after the timestamp, which only makes the next stamp older.
        let sampled_at = Instant::now();
        Self {
            frames: source.rx_frames(),
            datagrams: source.rx_datagrams(),
            sampled_at,
        }
    }

    fn sample<S: ProbeSource>(&mut self, source: &S, watch: &PathWatch) {
        let sampled_at = Instant::now();
        let frames = source.rx_frames();
        let datagrams = source.rx_datagrams();
        if frames != self.frames {
            // Authenticated: this alone is liveness.
            watch.transport_inbound(self.sampled_at);
        }
        if datagrams != self.datagrams {
            // Unauthenticated: a hint for the grace, nothing more.
            watch.datagrams_seen(sampled_at);
        }
        self.frames = frames;
        self.datagrams = datagrams;
        self.sampled_at = sampled_at;
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
    let mut rx = RxLiveness::new(&source);
    loop {
        // Re-read every round rather than arming a fixed ticker: the beat
        // *is* the power budget, and an attach nobody is using must not
        // wake this task four times a second to learn something nobody is
        // waiting to hear.
        let period = watch.cadence();
        let slept_from = Instant::now();
        // Only the timer arm is a tick whose gap means anything: the other
        // arms re-time or end the round.
        let mut timer_fired = false;
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
            () = watch.woken() => {
                rx.sample(&source, &watch);
                continue;
            }
            () = tokio::time::sleep(period) => timer_fired = true,
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
                    rx.sample(&source, &watch);
                    continue;
                }
                tracing::debug!(
                    slept_ms = wake_rx.borrow_and_update().slept_ms,
                    "machine woke from sleep; judging the path now"
                );
                watch.wake();
            }
        }
        // A tick that fired much later than the beat it slept means this
        // process was away, not the path: discount the lateness before
        // anything is judged (`PathState::observe_tick`, ADR-0042).
        if timer_fired {
            let gap = slept_from.elapsed();
            if let Some(late) = watch.ticked(gap, period) {
                tracing::debug!(
                    late_ms = late.as_millis() as u64,
                    "watchdog tick fired late; discounting the delay from the silence"
                );
            }
        }
        // Before the verdict, so frames that arrived since the last tick
        // answer outstanding probes first.
        rx.sample(&source, &watch);
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
