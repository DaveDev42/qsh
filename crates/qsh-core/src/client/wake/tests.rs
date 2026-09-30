use std::sync::atomic::{AtomicI64, Ordering};
use std::time::UNIX_EPOCH;

use super::*;

/// A wall clock that follows tokio's (possibly paused) monotonic clock and
/// can additionally be jumped by hand, like a machine that slept.
struct FakeWall {
    base: Instant,
    shift_ms: AtomicI64,
}

impl FakeWall {
    const ORIGIN_MS: i64 = 1_800_000_000_000;

    fn new() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            shift_ms: AtomicI64::new(0),
        })
    }

    fn shift(&self, ms: i64) {
        self.shift_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl WallClock for FakeWall {
    fn now(&self) -> SystemTime {
        let elapsed = i64::try_from(self.base.elapsed().as_millis()).expect("small");
        at(Self::ORIGIN_MS + elapsed + self.shift_ms.load(Ordering::SeqCst))
    }
}

fn at(ms: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).expect("positive test time"))
}

fn sense() -> (WakeSense, SystemTime, Instant) {
    let wall = at(FakeWall::ORIGIN_MS);
    let mono = Instant::now();
    (WakeSense::new(wall, mono), wall, mono)
}

#[test]
fn wake_detector_reports_a_wall_clock_jump_the_monotonic_clock_did_not_see() {
    let (mut sense, wall, mono) = sense();
    // The machine slept for a minute: the wall clock counted it, the
    // monotonic clock did not.
    let slept = sense.tick(wall + Duration::from_secs(60), mono);
    assert_eq!(slept.map(|d| d.as_millis()), Some(60_000));
}

#[test]
fn wake_detector_ignores_divergence_below_three_seconds() {
    let (mut sense, wall, mono) = sense();
    // 2.999 s of skew: an NTP correction or a stalled scheduler, not a wake.
    assert_eq!(sense.tick(wall + Duration::from_millis(2_999), mono), None);
    // Exactly the threshold is a wake (the ADR says "3 seconds or more").
    let (mut sense, wall, mono) = self::sense();
    assert_eq!(
        sense.tick(wall + WAKE_SKEW, mono),
        Some(WAKE_SKEW),
        "the boundary itself is a wake"
    );
    // An ordinary tick, both clocks agreeing, is nothing.
    let (mut sense, wall, mono) = self::sense();
    assert_eq!(sense.tick(wall + WAKE_TICK, mono + WAKE_TICK), None);
}

#[test]
fn wake_detector_ignores_a_backward_wall_clock_step() {
    let (mut sense, wall, mono) = sense();
    // The wall clock jumped back an hour while a second of monotonic time
    // passed. Never a wake, however large the step.
    let back = wall - Duration::from_secs(3600);
    assert_eq!(sense.tick(back, mono + WAKE_TICK), None);
    // The baseline moved with it: the next ordinary tick is not read as a
    // jump against the pre-step wall time.
    assert_eq!(
        sense.tick(back + WAKE_TICK, mono + 2 * WAKE_TICK),
        None,
        "a backward step must not leave a stale baseline behind"
    );
    // And a real wake after the step is still found.
    let slept = sense.tick(
        back + WAKE_TICK + Duration::from_secs(30),
        mono + 2 * WAKE_TICK,
    );
    assert_eq!(slept, Some(Duration::from_secs(30)));
}

#[test]
fn wake_detector_does_not_accumulate_a_slow_slew_into_a_wake() {
    let (mut sense, mut wall, mut mono) = sense();
    // 500 ppm, the most an NTP slew applies: 0.5 ms per tick. A thousand
    // ticks put the wall clock 500 ms ahead of the monotonic one, far below
    // the threshold, and every single tick is compared on its own step.
    for _ in 0..10_000 {
        wall += WAKE_TICK + Duration::from_micros(500);
        mono += WAKE_TICK;
        assert_eq!(sense.tick(wall, mono), None);
    }
}

#[test]
fn a_wall_clock_behind_the_monotonic_step_is_not_a_wake() {
    let (mut sense, wall, mono) = sense();
    // Wall advanced less than monotonic: the checked subtraction is the
    // guard, not a panic or a wrap to a huge duration.
    assert_eq!(
        sense.tick(wall + Duration::from_millis(10), mono + WAKE_TICK),
        None
    );
}

#[tokio::test(start_paused = true)]
async fn wake_detector_task_publishes_a_wake_with_its_slept_time() {
    let clock = FakeWall::new();
    let det = WakeDetector::new(clock.clone());
    let mut rx = det.subscribe();
    assert_eq!(*rx.borrow_and_update(), WakeEvent::default());
    // Sixty seconds of sleep land inside the next tick, on top of that
    // tick's own second.
    clock.shift(60_000);
    tokio::time::timeout(Duration::from_secs(10), rx.changed())
        .await
        .expect("the detector must publish the wake")
        .expect("the sender lives as long as the detector");
    let ev = *rx.borrow_and_update();
    assert_eq!(ev.seq, 1);
    assert_eq!(ev.slept_ms, 60_000);
}

#[tokio::test(start_paused = true)]
async fn wake_detector_delivers_every_wake_to_a_subscriber_that_was_busy() {
    let clock = FakeWall::new();
    let det = WakeDetector::new(clock.clone());
    let mut busy = det.subscribe();
    let mut waiting = det.subscribe();

    clock.shift(10_000);
    // `waiting` awaits, so it sees the wake as it happens.
    tokio::time::timeout(Duration::from_secs(10), waiting.changed())
        .await
        .expect("wake reaches an awaiting subscriber")
        .expect("open");
    assert_eq!(waiting.borrow_and_update().seq, 1);

    // `busy` never awaited: the wake is still there for it, not consumed
    // by the first subscriber and not lost like a `Notify` edge would be.
    assert!(busy.has_changed().expect("open"));
    let ev = *busy.borrow_and_update();
    assert_eq!(
        ev,
        WakeEvent {
            seq: 1,
            slept_ms: 10_000
        }
    );

    // Two more wakes while `busy` is away: it comes back to the latest
    // value, and `seq` shows that none was skipped over silently.
    for expected in [2, 3] {
        clock.shift(20_000);
        tokio::time::timeout(Duration::from_secs(10), waiting.changed())
            .await
            .expect("wake")
            .expect("open");
        assert_eq!(waiting.borrow_and_update().seq, expected);
    }
    assert!(busy.has_changed().expect("open"));
    assert_eq!(busy.borrow_and_update().seq, 3);
}

#[tokio::test(start_paused = true)]
async fn wake_detector_stops_with_its_last_subscriber_and_restarts_on_the_next() {
    let clock = FakeWall::new();
    let det = WakeDetector::new(clock.clone());
    let rx = det.subscribe();
    drop(rx);
    // Let the task notice there is nobody left and retire itself.
    let handle = det
        .shared
        .task
        .lock()
        .expect("task slot lock")
        .clone()
        .expect("the task was started");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !handle.is_finished() {
            tokio::task::yield_now().await;
            tokio::time::advance(WAKE_TICK).await;
        }
    })
    .await
    .expect("the task must exit once nobody listens");

    // A new subscriber gets a working detector again.
    let mut rx = det.subscribe();
    clock.shift(5_000);
    tokio::time::timeout(Duration::from_secs(10), rx.changed())
        .await
        .expect("the restarted detector must publish")
        .expect("open");
    assert_eq!(rx.borrow_and_update().slept_ms, 5_000);
}

#[tokio::test(start_paused = true)]
async fn wake_detector_ignores_a_backward_step_end_to_end() {
    let clock = FakeWall::new();
    let det = WakeDetector::new(clock.clone());
    let mut rx = det.subscribe();
    clock.shift(-3_600_000);
    // Give the detector plenty of ticks: none may publish.
    let quiet = tokio::time::timeout(Duration::from_secs(10), rx.changed()).await;
    assert!(quiet.is_err(), "a backward step must never publish a wake");
    assert_eq!(rx.borrow().seq, 0);
}
