use super::super::wake::{WAKE_TICK, WakeEvent};
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

/// The regression the two-cadence design existed only on paper
/// without: a *healthy* idle path — one where the host answers every
/// probe — has to fall to the slow beat. The obvious version of
/// "inbound traffic means the attach is in use" made every answer
/// re-arm the active window, so a live silent session probed four
/// times a second for as long as it was open.
#[test]
fn a_healthy_idle_path_falls_to_the_slow_cadence() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = PathState::new(t0);
    let mut probes_in_the_last_minute = 0u32;
    // A live host: every probe is answered a millisecond later.
    for ms in 1..=60_000u64 {
        let now = t0 + Duration::from_millis(ms);
        match state.verdict(now, LAN, &cfg) {
            Verdict::Probe => {
                probes_in_the_last_minute += 1;
                state.observe_inbound(now + Duration::from_millis(1));
            }
            Verdict::Dead => panic!("an answered path must never be declared dead"),
            Verdict::Healthy => {}
        }
    }
    assert_eq!(
        state.cadence(t0 + Duration::from_secs(60), &cfg),
        cfg.idle_probe_interval,
        "a `Pong` is the watchdog answering itself; it must not count as somebody waiting"
    );
    // 15 s of fast cadence, then 45 s of slow: ~60 + ~9, nowhere near
    // the ~240 a permanently-active window would produce.
    assert!(
        probes_in_the_last_minute < 100,
        "an idle-but-live attach probed {probes_in_the_last_minute} times in a minute"
    );
    // …and a keystroke puts it straight back on the fast beat.
    let back = t0 + Duration::from_secs(60);
    state.observe_activity(back);
    assert_eq!(state.cadence(back, &cfg), cfg.probe_interval);
}

/// Session traffic *is* activity, so a session that is printing stays
/// on the fast cadence — that is the one the user is watching.
#[test]
fn session_traffic_keeps_the_fast_cadence() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = PathState::new(t0);
    let at = t0 + Duration::from_secs(30);
    state.observe_traffic(at);
    assert_eq!(state.cadence(at, &cfg), cfg.probe_interval);
}

#[tokio::test]
async fn a_migration_probe_cannot_miss_the_answer_it_asked_for() {
    let watch = PathWatch::new(cfg());
    // Subscribed *before* the question, which is the whole point: the
    // answer below lands before anything awaits, and must still be
    // seen.
    let mut signal = watch.inbound_signal();
    watch.inbound();
    tokio::time::timeout(Duration::from_secs(5), signal.changed())
        .await
        .expect("an answer that beat the waiter must not be lost")
        .expect("the sender outlives the receiver");
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

/// A stub that never closes and reports a fixed RTT — stands in for
/// whatever a host-role prober will wrap ([`server::ControlPinger`]'s
/// module doc, M3 Step 4). Exists to prove [`watch_path`] is generic
/// over [`ProbeSource`] in fact, not just in the trait's shape: a type
/// with no `qsh_transport::Connection` inside it can still drive the
/// exact same watchdog policy.
#[derive(Clone)]
struct NeverCloses;

impl ProbeSource for NeverCloses {
    async fn closed(&self) {
        std::future::pending::<()>().await
    }

    fn rtt(&self) -> Duration {
        LAN
    }

    fn rx_datagrams(&self) -> u64 {
        0
    }
}

/// A stub whose receive counters are driven by the test. `frames` models
/// authenticated QUIC frames (what a live peer produces), `datagrams` raw
/// UDP datagrams (what a forger can produce too).
#[derive(Clone, Default)]
struct CountingSource {
    frames: Arc<std::sync::atomic::AtomicU64>,
    datagrams: Arc<std::sync::atomic::AtomicU64>,
}

impl CountingSource {
    fn frame(&self) {
        self.frames.fetch_add(1, Ordering::Relaxed);
        // A real frame arrives inside a datagram.
        self.datagrams.fetch_add(1, Ordering::Relaxed);
    }

    fn forged_datagram(&self) {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
    }
}

impl ProbeSource for CountingSource {
    async fn closed(&self) {
        std::future::pending::<()>().await
    }

    fn rtt(&self) -> Duration {
        LAN
    }

    fn rx_frames(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }

    fn rx_datagrams(&self) -> u64 {
        self.datagrams.load(Ordering::Relaxed)
    }
}

// Liveness is an authenticated frame; a raw datagram is only a hint that
// buys one bounded grace (`docs/design/protocol.md` §10, threat-model G7).
// The timing-sensitive tests share the `datagram_liveness_` prefix so one
// filterset selects them for the load repeat in `scripts/stress/run.sh`.

#[tokio::test(start_paused = true)]
async fn datagram_liveness_moving_frames_keep_the_path_alive_without_control_replies() {
    let watch = PathWatch::new(cfg());
    let source = CountingSource::default();
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source.clone(), watch.clone(), probes));
    // Ten times the death budget, with an authenticated frame every 100 ms
    // and no control reply at all.
    for _ in 0..100 {
        source.frame();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!watch.is_dead(), "frames are arriving; path is alive");
    }
    // Real death detection is unchanged: the frames stop, the verdict
    // follows on the usual schedule (`dead_after` plus a probe beat).
    let stopped = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("frozen counters must still end in a verdict");
    let took = stopped.elapsed();
    assert!(
        took <= watch.config().dead_after(LAN) + watch.config().probe_interval * 2,
        "{took:?}"
    );
    watchdog.await.expect("watchdog returns once it declares");
}

#[tokio::test(start_paused = true)]
async fn datagram_liveness_frames_are_not_activity_so_the_idle_cadence_is_still_reached() {
    let cfg = cfg();
    let watch = PathWatch::new(cfg);
    let source = CountingSource::default();
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source.clone(), watch.clone(), probes));
    // Frames keep arriving (the transport's own ACKs, say) for well past the
    // active window, and nobody types or prints anything.
    for _ in 0..400 {
        source.frame();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!watch.is_dead());
    assert!(
        watch.state().is_idle(Instant::now(), &cfg),
        "a moving frame counter must not pin the fast cadence"
    );
    watchdog.abort();
}

/// (iii) No traffic at all: dead at the normal timeout, no grace.
#[tokio::test(start_paused = true)]
async fn datagram_liveness_no_traffic_is_dead_on_the_existing_schedule() {
    let watch = PathWatch::new(cfg());
    let source = CountingSource::default();
    source.frames.store(7, Ordering::Relaxed);
    source.datagrams.store(42, Ordering::Relaxed);
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source, watch.clone(), probes));
    let start = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("frozen counters with no replies must be declared dead");
    let took = start.elapsed();
    // Same bound `silence_earns_probes_and_then_a_verdict` pins for
    // `PathState`: three strikes at the fast cadence, 1 s floor.
    assert!(took >= watch.config().dead_after(LAN), "{took:?}");
    assert!(
        took <= watch.config().dead_after(LAN) + watch.config().probe_interval,
        "{took:?}"
    );
    watchdog.await.expect("watchdog returns once it declares");
}

/// (ii) Datagrams with no authenticated frame never keep a path alive: the
/// verdict is held back by the grace and then stands, however many
/// datagrams keep coming.
#[tokio::test(start_paused = true)]
async fn datagram_liveness_datagrams_alone_earn_one_bounded_grace_then_the_path_is_dead() {
    let cfg = cfg();
    let watch = PathWatch::new(cfg);
    let source = CountingSource::default();
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source.clone(), watch.clone(), probes));
    let start = Instant::now();
    let mut dead_at = None;
    // A forged datagram every 50 ms, far past any bound.
    for _ in 0..200 {
        source.forged_datagram();
        tokio::time::sleep(Duration::from_millis(50)).await;
        if dead_at.is_none() && watch.is_dead() {
            dead_at = Some(start.elapsed());
        }
    }
    let dead_at = dead_at.expect("datagrams alone must not keep the path alive indefinitely");
    // Held past the normal timeout (the grace was granted) ...
    assert!(
        dead_at > cfg.dead_after(LAN) + cfg.probe_interval,
        "dead after {dead_at:?}: no grace was granted"
    );
    // ... but by no more than the bounded grace plus a tick of slack.
    assert!(
        dead_at <= cfg.dead_after(LAN) + cfg.datagram_grace() + cfg.probe_interval * 2,
        "dead after {dead_at:?}: the grace was not bounded"
    );
    watchdog.await.expect("watchdog returns once it declares");
}

/// An authenticated frame inside the grace is liveness: the path lives and
/// a later outage gets a fresh cycle.
#[tokio::test(start_paused = true)]
async fn datagram_liveness_a_frame_inside_the_grace_revives_the_path() {
    let cfg = cfg();
    let watch = PathWatch::new(cfg);
    let source = CountingSource::default();
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source.clone(), watch.clone(), probes));
    // Datagrams only, through the normal timeout and into the grace.
    let until = cfg.dead_after(LAN) + cfg.probe_interval * 2;
    let mut waited = Duration::ZERO;
    while waited < until {
        source.forged_datagram();
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    }
    assert!(!watch.is_dead(), "still inside the grace");
    // The peer proves itself.
    source.frame();
    // Less than the new cycle's own dead_after: the frame bought a fresh
    // cycle, not immunity.
    for _ in 0..16 {
        source.forged_datagram();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!watch.is_dead(), "a frame arrived inside the grace");
    }
    watchdog.abort();
}

#[test]
fn a_datagram_hint_grants_exactly_one_grace_per_cycle() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = state_one_tick_from_death(t0);
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    let grace = cfg.datagram_grace();
    assert_eq!(grace, Duration::from_millis(750));

    // The verdict is due at 1 s with a datagram seen just before: grace.
    state.observe_datagram(at(990));
    assert_ne!(state.verdict(at(1_000), LAN, &cfg), Verdict::Dead);
    // Datagrams keep coming; the grace does not move.
    state.observe_datagram(at(1_500));
    assert_ne!(state.verdict(at(1_500), LAN, &cfg), Verdict::Dead);
    assert_ne!(state.verdict(at(1_749), LAN, &cfg), Verdict::Dead);
    state.observe_datagram(at(1_750));
    assert_eq!(state.verdict(at(1_750), LAN, &cfg), Verdict::Dead);
    // A datagram cannot touch silence or strikes.
    assert!(state.unanswered() >= cfg.strikes);
    assert!(state.silence(at(1_750)) >= Duration::from_millis(1_750));

    // An authenticated frame starts a new cycle with a new grace.
    state.observe_inbound_since(at(1_800));
    assert_eq!(state.unanswered(), 0);
    let mut dead = None;
    for ms in (1_800..8_000).step_by(50) {
        state.observe_datagram(at(ms));
        if state.verdict(at(ms), LAN, &cfg) == Verdict::Dead {
            dead = Some(ms - 1_800);
            break;
        }
    }
    let took = Duration::from_millis(dead.expect("the second cycle also ends dead"));
    assert!(
        took >= cfg.dead_after(LAN) + grace - cfg.probe_interval,
        "{took:?}"
    );
    assert!(
        took <= cfg.dead_after(LAN) + grace + cfg.probe_interval * 2,
        "{took:?}"
    );
}

#[test]
fn a_stale_datagram_hint_grants_no_grace() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = state_one_tick_from_death(t0);
    // The only datagram came at t0; by the 1 s verdict it is older than the
    // 750 ms grace window, so it is not evidence of anything current.
    state.observe_datagram(t0);
    let now = t0 + Duration::from_millis(1_000);
    assert_eq!(state.verdict(now, LAN, &cfg), Verdict::Dead);
}

#[tokio::test(start_paused = true)]
async fn watch_path_is_generic_over_the_probe_source() {
    let watch = PathWatch::new(cfg());
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(NeverCloses, watch.clone(), probes));
    // No answer ever arrives, so silence alone must reach a verdict —
    // exactly the policy `silence_earns_probes_and_then_a_verdict`
    // already covers for `PathState` directly; this proves the same
    // outcome survives going through the generic `watch_path` task.
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("an unanswered stub path must be declared dead");
    watchdog
        .await
        .expect("watch_path must return once it declares death");
}

// ADR-0023 decision 4 and 17: a wake is activity and an immediate probe.

#[test]
fn path_state_probes_at_once_and_uses_the_fast_cadence_after_a_wake() {
    let cfg = cfg();
    let t0 = Instant::now();
    // An attach nobody has touched for half a minute whose last inbound
    // byte is only 100 ms old: on the idle cadence, and not silent enough
    // to earn a probe for another few seconds.
    let idle_state = || {
        let mut state = PathState::new(t0);
        state.observe_inbound(t0 + Duration::from_millis(29_900));
        state
    };
    let woke_at = t0 + Duration::from_secs(30);
    let mut control = idle_state();
    assert!(control.is_idle(woke_at, &cfg));
    assert_eq!(control.verdict(woke_at, LAN, &cfg), Verdict::Healthy);

    let mut state = idle_state();
    state.observe_wake(woke_at);
    assert!(!state.is_idle(woke_at, &cfg), "a wake is activity");
    assert_eq!(state.cadence(woke_at, &cfg), cfg.probe_interval);
    // The first judgment after the wake is a probe, without waiting out any
    // beat and without the silence being long enough by itself.
    assert_eq!(state.verdict(woke_at, LAN, &cfg), Verdict::Probe);
    assert_eq!(state.unanswered(), 1);

    // Then the fast cadence carries it to a verdict: 250 ms per step, three
    // strikes and `dead_after` (1 s) of silence.
    let mut now = woke_at;
    let mut steps = 0;
    loop {
        now += cfg.probe_interval;
        steps += 1;
        match state.verdict(now, LAN, &cfg) {
            Verdict::Dead => break,
            Verdict::Probe => {}
            Verdict::Healthy => panic!("a silent path on the fast cadence must keep probing"),
        }
        assert!(steps < 10, "no verdict after {steps} fast beats");
    }
    let took = now - woke_at;
    assert!(
        took <= WAKE_TICK + cfg.dead_after(LAN),
        "declared dead {took:?} after the wake"
    );
    assert!(took < cfg.idle_probe_interval);
}

#[test]
fn path_state_treats_a_local_accept_as_activity() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = PathState::new(t0);
    // Two idle-cadence probes deep into silence.
    let mut now = t0 + Duration::from_secs(60);
    while state.unanswered() < 2 {
        now += cfg.idle_probe_interval;
        state.verdict(now, LAN, &cfg);
    }
    assert!(state.is_idle(now, &cfg));
    assert_eq!(state.cadence(now, &cfg), cfg.idle_probe_interval);
    let unanswered = state.unanswered();

    // A local connection is accepted: somebody is waiting for an answer.
    // That is activity (fast cadence) but proves nothing about the path, so
    // the strikes already earned are kept.
    state.observe_activity(now);
    assert!(!state.is_idle(now, &cfg));
    assert_eq!(state.cadence(now, &cfg), cfg.probe_interval);
    assert_eq!(state.unanswered(), unanswered);
}

type WakeTx = tokio::sync::watch::Sender<WakeEvent>;

/// A machine that slept while the attach idled on the slow cadence: at
/// virtual t = 30 s the watch has 30 s of silence and the watchdog is
/// halfway through a five-second beat.
async fn idle_watch_with_running_watchdog() -> (
    PathWatch,
    Arc<tokio::sync::Notify>,
    WakeTx,
    tokio::task::JoinHandle<()>,
) {
    let watch = PathWatch::new(cfg());
    tokio::time::advance(Duration::from_secs(30)).await;
    let probes = Arc::new(tokio::sync::Notify::new());
    let (tx, rx) = tokio::sync::watch::channel(WakeEvent::default());
    let watchdog = tokio::spawn(watch_path_with_wake(
        NeverCloses,
        watch.clone(),
        probes.clone(),
        rx,
    ));
    // Let the watchdog reach its sleep before anyone moves the clock.
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    (watch, probes, tx, watchdog)
}

fn inject_wake(tx: &WakeTx) {
    tx.send_modify(|e| {
        e.seq += 1;
        e.slept_ms = 600_000;
    });
}

#[tokio::test(start_paused = true)]
async fn path_watch_declares_dead_within_wake_tick_plus_dead_after_of_a_wake() {
    let (watch, _probes, tx, watchdog) = idle_watch_with_running_watchdog().await;
    let bound = WAKE_TICK + watch.config().dead_after(LAN);

    // Without a wake the slow beat has not come round yet.
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(!watch.is_dead(), "nothing may be declared before the wake");

    inject_wake(&tx);
    let woke_at = Instant::now();
    tokio::time::timeout(Duration::from_secs(60), watch.dead())
        .await
        .expect("a silent path must be declared dead after a wake");
    let took = woke_at.elapsed();
    assert!(
        took <= bound,
        "declared dead {took:?} after the wake; the bound is {bound:?}"
    );
    // Contrast: on the slow beat alone this takes three five-second probes.
    assert!(took < watch.config().idle_probe_interval, "{took:?}");
    watchdog.await.expect("watchdog returns once it declares");
}

#[tokio::test(start_paused = true)]
async fn path_watch_probes_at_once_on_a_wake_even_on_the_slow_cadence() {
    let (_watch, probes, tx, watchdog) = idle_watch_with_running_watchdog().await;
    inject_wake(&tx);
    let woke_at = Instant::now();
    tokio::time::timeout(Duration::from_secs(60), probes.notified())
        .await
        .expect("the wake must order a probe");
    let took = woke_at.elapsed();
    assert!(
        took < cfg().probe_interval,
        "the probe came {took:?} after the wake, not at once"
    );
    watchdog.abort();
}

#[tokio::test(start_paused = true)]
async fn a_closed_wake_channel_does_not_spin_or_kill_the_watchdog() {
    let (watch, _probes, tx, watchdog) = idle_watch_with_running_watchdog().await;
    drop(tx);
    // The path still gets judged on its own beats.
    tokio::time::timeout(Duration::from_secs(60), watch.dead())
        .await
        .expect("silence alone must still reach a verdict");
    watchdog.await.expect("watchdog returns once it declares");
}

// Issue #10 request 3: the measurements behind a death verdict.

#[tokio::test(start_paused = true)]
async fn dead_verdict_records_the_rtt_and_silence_it_ruled_on() {
    let cfg = cfg();
    let watch = PathWatch::new(cfg);
    assert_eq!(watch.dead_verdict(), None, "nothing ruled yet");
    let (_tx, rx) = tokio::sync::watch::channel(WakeEvent::default());
    let task = tokio::spawn(watch_path_with_wake(
        NeverCloses,
        watch.clone(),
        Arc::new(tokio::sync::Notify::new()),
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("a silent path must be declared dead");
    task.await.expect("the watchdog returns once it declares");

    let verdict = watch
        .dead_verdict()
        .expect("the watchdog ruled, so it must have left its measurements");
    assert_eq!(verdict.srtt, LAN);
    assert!(
        verdict.silence >= cfg.min_dead_after,
        "ruled dead on {:?} of silence, inside the {:?} floor",
        verdict.silence,
        cfg.min_dead_after
    );
    assert!(
        verdict.silence <= cfg.min_dead_after + cfg.probe_interval,
        "silence {:?} overshoots the floor by more than one tick",
        verdict.silence
    );
}

#[tokio::test(start_paused = true)]
async fn a_death_declared_from_outside_leaves_no_verdict() {
    let watch = PathWatch::new(cfg());
    watch.declare_dead();
    assert!(watch.is_dead());
    assert_eq!(
        watch.dead_verdict(),
        None,
        "a closed connection is not this watchdog's ruling"
    );
}

#[tokio::test(start_paused = true)]
async fn revive_clears_the_dead_verdict() {
    let watch = PathWatch::new(cfg());
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Enough probes to earn a verdict: tick the policy by hand.
    let mut ruled = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if watch.verdict(LAN) == Verdict::Dead {
            ruled = true;
            break;
        }
    }
    assert!(ruled);
    assert!(watch.dead_verdict().is_some());
    watch.declare_dead();
    watch.revive();
    assert_eq!(watch.dead_verdict(), None);
    assert!(!watch.is_dead());
}

// Issue #11 request 2 (ADR-0042 decision 1): a watchdog that was itself
// starved must not read its own absence as the path's silence.

/// Three unanswered probes and 750 ms of silence on the default schedule:
/// one tick short of a verdict.
fn state_one_tick_from_death(t0: Instant) -> PathState {
    let cfg = cfg();
    let mut state = PathState::new(t0);
    for ms in [250, 500, 750] {
        let now = t0 + Duration::from_millis(ms);
        assert_eq!(state.verdict(now, LAN, &cfg), Verdict::Probe);
    }
    assert_eq!(state.unanswered(), 3);
    state
}

#[test]
fn a_tick_less_than_a_probe_interval_late_is_not_a_self_delay() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = state_one_tick_from_death(t0);
    let now = t0 + Duration::from_millis(1_000);
    // 249 ms late with a 250 ms probe interval: ordinary scheduling noise.
    let gap = cfg.probe_interval + cfg.probe_interval - Duration::from_millis(1);
    assert_eq!(state.observe_tick(now, gap, cfg.probe_interval, &cfg), None);
    assert_eq!(
        state.silence(now),
        Duration::from_secs(1),
        "silence untouched"
    );
    assert_eq!(
        state.verdict(now, LAN, &cfg),
        Verdict::Dead,
        "noise below the threshold must not delay a real verdict"
    );
}

#[test]
fn a_tick_a_whole_probe_interval_late_is_a_self_delay() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = state_one_tick_from_death(t0);
    let now = t0 + Duration::from_millis(1_000);
    let gap = cfg.probe_interval * 2;
    assert_eq!(
        state.observe_tick(now, gap, cfg.probe_interval, &cfg),
        Some(cfg.probe_interval),
        "exactly one probe interval late is the threshold"
    );
}

#[test]
fn a_late_tick_discounts_the_delay_and_cannot_rule_the_path_dead_on_itself() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = state_one_tick_from_death(t0);
    // The process was away for ten seconds: the next tick fires at 10.75 s
    // having slept a 250 ms beat since 750 ms.
    let now = t0 + Duration::from_millis(10_750);
    let late = state.observe_tick(now, Duration::from_secs(10), cfg.probe_interval, &cfg);
    assert_eq!(late, Some(Duration::from_millis(9_750)));
    assert_eq!(
        state.silence(now),
        Duration::from_secs(1),
        "only the silence this process was awake for counts"
    );
    // Three strikes and a full second of (observed) silence, and still no
    // verdict: whatever arrived while we were away has not been read yet.
    assert_eq!(state.verdict(now, LAN, &cfg), Verdict::Probe);
    // The next tick is on time and nothing came: now it is a verdict.
    let next = now + cfg.probe_interval;
    assert_eq!(
        state.observe_tick(next, cfg.probe_interval, cfg.probe_interval, &cfg),
        None
    );
    assert_eq!(state.verdict(next, LAN, &cfg), Verdict::Dead);
}

#[test]
fn evidence_read_after_a_late_tick_keeps_the_path_alive() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = state_one_tick_from_death(t0);
    let now = t0 + Duration::from_millis(10_750);
    state.observe_tick(now, Duration::from_secs(10), cfg.probe_interval, &cfg);
    assert_eq!(state.verdict(now, LAN, &cfg), Verdict::Probe);
    // The queued-up answer is read between the two ticks.
    state.observe_inbound(now + Duration::from_millis(10));
    assert_eq!(state.unanswered(), 0);
    let next = now + cfg.probe_interval;
    state.observe_tick(next, cfg.probe_interval, cfg.probe_interval, &cfg);
    assert_ne!(state.verdict(next, LAN, &cfg), Verdict::Dead);
}

#[test]
fn the_discounted_silence_never_runs_ahead_of_now() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = PathState::new(t0);
    // Evidence arrived just before the late tick: shifting by the whole
    // lateness would put the silence clock in the future.
    let now = t0 + Duration::from_secs(10);
    state.observe_inbound(now - Duration::from_millis(5));
    state.observe_tick(now, Duration::from_secs(10), cfg.probe_interval, &cfg);
    assert_eq!(state.silence(now), Duration::ZERO);
}

#[test]
fn the_tick_gap_is_the_greatest_lateness_since_the_last_evidence() {
    let cfg = cfg();
    let t0 = Instant::now();
    let mut state = PathState::new(t0);
    let beat = cfg.probe_interval;
    let mut now = t0;
    // On time, three beats' worth of gap for one beat slept, and a few
    // milliseconds of noise: the figure is the worst lateness, not the gap.
    for gap in [beat, beat * 3, beat + Duration::from_millis(7)] {
        now += gap;
        state.observe_tick(now, gap, beat, &cfg);
    }
    assert_eq!(state.max_tick_gap(), beat * 2);
    // Evidence ends the window the figure describes.
    state.observe_inbound(now);
    assert_eq!(state.max_tick_gap(), Duration::ZERO);
}

/// Let the watchdog task run whatever the clock just released.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// A watchdog that has sent its third probe: silent for 750 ms, so one tick
/// from a verdict on the default schedule.
async fn running_watchdog_one_tick_from_death() -> (PathWatch, WakeTx, tokio::task::JoinHandle<()>)
{
    let watch = PathWatch::new(cfg());
    let (tx, rx) = tokio::sync::watch::channel(WakeEvent::default());
    let watchdog = tokio::spawn(watch_path_with_wake(
        NeverCloses,
        watch.clone(),
        Arc::new(tokio::sync::Notify::new()),
        rx,
    ));
    settle().await;
    for _ in 0..3 {
        tokio::time::advance(Duration::from_millis(250)).await;
        settle().await;
    }
    assert!(!watch.is_dead());
    (watch, tx, watchdog)
}

#[tokio::test(start_paused = true)]
async fn a_watchdog_that_was_starved_does_not_declare_the_path_dead_when_it_resumes() {
    let (watch, _tx, watchdog) = running_watchdog_one_tick_from_death().await;
    // The process is away for ten seconds; the timer fires the moment it
    // is scheduled again. Before ADR-0042 this tick read ten seconds of
    // silence and three strikes as a dead path.
    tokio::time::advance(Duration::from_secs(10)).await;
    settle().await;
    assert!(!watch.is_dead(), "the tick that resumed us may not rule");
    // What the host sent meanwhile is read before the next tick.
    watch.inbound();
    for _ in 0..3 {
        tokio::time::advance(Duration::from_millis(250)).await;
        settle().await;
        assert!(!watch.is_dead(), "the answer proves the path");
        watch.inbound();
    }
    watchdog.abort();
}

#[tokio::test(start_paused = true)]
async fn a_path_that_stays_silent_after_a_stall_is_still_declared_dead() {
    let (watch, _tx, watchdog) = running_watchdog_one_tick_from_death().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    settle().await;
    assert!(!watch.is_dead());
    let resumed = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("a path that stays silent is dead one on-time tick later");
    assert!(
        resumed.elapsed() <= cfg().probe_interval * 2,
        "{:?}",
        resumed.elapsed()
    );
    let verdict = watch.dead_verdict().expect("the watchdog ruled");
    assert_eq!(
        verdict.tick_gap,
        Duration::from_millis(9_750),
        "the diagnostic names the stall (ten seconds for a 250 ms beat)"
    );
    assert!(
        verdict.silence < Duration::from_secs(2),
        "silence counts what the watch observed, not the ten seconds it was away: {:?}",
        verdict.silence
    );
    watchdog.await.expect("watchdog returns once it declares");
}

#[tokio::test(start_paused = true)]
async fn a_watchdog_that_is_late_on_every_tick_still_reaches_a_verdict() {
    let watch = PathWatch::new(cfg());
    let (_tx, rx) = tokio::sync::watch::channel(WakeEvent::default());
    let watchdog = tokio::spawn(watch_path_with_wake(
        NeverCloses,
        watch.clone(),
        Arc::new(tokio::sync::Notify::new()),
        rx,
    ));
    settle().await;
    // Every beat of 250 ms takes 550 ms: 300 ms late each time, over the
    // threshold. On time this path would be dead on the fourth tick.
    let mut rounds = 0;
    while !watch.is_dead() {
        rounds += 1;
        assert!(
            rounds <= 10,
            "a watch starved on every tick must still converge"
        );
        tokio::time::advance(Duration::from_millis(550)).await;
        settle().await;
        if rounds < 5 {
            assert!(
                !watch.is_dead(),
                "round {rounds}: still inside the discount"
            );
        }
    }
    assert!(
        rounds >= 5,
        "the discount delayed the verdict ({rounds} rounds)"
    );
    watchdog.await.expect("watchdog returns once it declares");
}

#[tokio::test(start_paused = true)]
async fn an_on_time_watchdog_records_no_lateness_as_its_tick_gap() {
    let watch = PathWatch::new(cfg());
    let (_tx, rx) = tokio::sync::watch::channel(WakeEvent::default());
    let task = tokio::spawn(watch_path_with_wake(
        NeverCloses,
        watch.clone(),
        Arc::new(tokio::sync::Notify::new()),
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("a silent path must be declared dead");
    task.await.expect("the watchdog returns once it declares");
    assert_eq!(watch.dead_verdict().unwrap().tick_gap, Duration::ZERO);
}

/// On the idle cadence a healthy gap is the 5 s beat itself. The diagnostic
/// must not read that as starvation: it reports lateness, and an on-time
/// idle tick has none.
#[tokio::test(start_paused = true)]
async fn an_idle_watch_on_time_records_no_lateness_though_its_gaps_are_five_seconds() {
    let cfg = PathWatchConfig {
        // Nothing the idle probes can answer, so the path dies on schedule.
        min_dead_after: Duration::from_secs(1),
        active_window: Duration::ZERO,
        ..cfg()
    };
    let watch = PathWatch::new(cfg);
    let (_tx, rx) = tokio::sync::watch::channel(WakeEvent::default());
    let task = tokio::spawn(watch_path_with_wake(
        NeverCloses,
        watch.clone(),
        Arc::new(tokio::sync::Notify::new()),
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(60), watch.dead())
        .await
        .expect("a silent idle path must be declared dead");
    task.await.expect("the watchdog returns once it declares");
    let verdict = watch.dead_verdict().expect("the watchdog ruled");
    assert!(
        verdict.silence >= cfg.idle_probe_interval,
        "the test ran on the idle beat: {:?}",
        verdict.silence
    );
    assert_eq!(verdict.tick_gap, Duration::ZERO, "{verdict:?}");
}

/// A pump parked on a full queue makes the verdict Healthy without judging.
/// The margin a late tick banked for that verdict goes with it: left behind
/// it would be charged to the next verdict that can rule, deferring a real
/// death by a tick.
///
/// With the shipped strike counts (`S >= 2`) the next verdict after a stall
/// is always a probe, which spends the stale margin harmlessly; `strikes: 0`
/// makes the very next verdict death-eligible so the leftover is observable.
#[tokio::test(start_paused = true)]
async fn a_stalled_verdict_does_not_leave_a_stale_margin_behind() {
    let cfg = PathWatchConfig {
        strikes: 0,
        ..cfg()
    };
    let watch = PathWatch::new(cfg);
    let guard = watch.stalled();
    assert_eq!(
        watch.ticked(Duration::from_secs(10), cfg.probe_interval),
        Some(Duration::from_millis(9_750))
    );
    assert_eq!(watch.verdict(LAN), Verdict::Healthy, "stalled: no judgment");
    drop(guard);
    // The stall is over and the path is silent from here. A 9.75 s leftover
    // margin would put this verdict out of reach.
    tokio::time::advance(cfg.min_dead_after).await;
    assert_eq!(
        watch.verdict(LAN),
        Verdict::Dead,
        "a real death is not deferred by a margin nobody used"
    );
}
