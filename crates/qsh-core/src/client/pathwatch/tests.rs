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

/// A stub whose receive counter is driven by the test, to model datagrams
/// arriving while no control-stream reply does.
#[derive(Clone, Default)]
struct CountingSource(Arc<std::sync::atomic::AtomicU64>);

impl ProbeSource for CountingSource {
    async fn closed(&self) {
        std::future::pending::<()>().await
    }

    fn rtt(&self) -> Duration {
        LAN
    }

    fn rx_datagrams(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[tokio::test(start_paused = true)]
async fn a_moving_datagram_counter_keeps_the_path_alive_without_control_replies() {
    let watch = PathWatch::new(cfg());
    let source = CountingSource::default();
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source.clone(), watch.clone(), probes));
    // Ten times the death budget, with a datagram every 100 ms and no
    // control reply at all.
    for _ in 0..100 {
        source.0.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!watch.is_dead(), "datagrams are arriving; path is alive");
    }
    // Real death detection is unchanged: the counter stops, the verdict
    // follows on the usual schedule (`dead_after` plus a probe beat).
    let stopped = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("a frozen counter must still end in a verdict");
    let took = stopped.elapsed();
    assert!(
        took <= watch.config().dead_after(LAN) + watch.config().probe_interval * 2,
        "{took:?}"
    );
    watchdog.await.expect("watchdog returns once it declares");
}

#[tokio::test(start_paused = true)]
async fn datagram_liveness_is_not_activity_so_the_idle_cadence_is_still_reached() {
    let cfg = cfg();
    let watch = PathWatch::new(cfg);
    let source = CountingSource::default();
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source.clone(), watch.clone(), probes));
    // Datagrams keep arriving (the transport's own ACKs, say) for well past
    // the active window, and nobody types or prints anything.
    for _ in 0..400 {
        source.0.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!watch.is_dead());
    assert!(
        watch.state().is_idle(Instant::now(), &cfg),
        "a moving datagram counter must not pin the fast cadence"
    );
    watchdog.abort();
}

#[tokio::test(start_paused = true)]
async fn a_frozen_datagram_counter_without_replies_is_dead_on_the_existing_schedule() {
    let watch = PathWatch::new(cfg());
    let source = CountingSource::default();
    source.0.store(42, Ordering::Relaxed);
    let probes = Arc::new(tokio::sync::Notify::new());
    let watchdog = tokio::spawn(watch_path(source, watch.clone(), probes));
    let start = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), watch.dead())
        .await
        .expect("a frozen counter with no replies must be declared dead");
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
