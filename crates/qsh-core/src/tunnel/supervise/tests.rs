//! Supervisor decision logic under a paused clock and seeded RNGs
//! (ADR-0023 decisions 9, 10, 18).

use std::time::Duration;

use proptest::prelude::*;
use qsh_proto::ErrorCode;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::watch;
use tokio::time::Instant;

use super::backoff::{Backoff, FAST_CAP, FAST_WINDOW, INITIAL, MAX, Pacer, Waited};
use super::budget::{Budget, STABLE_AFTER};
use super::classify::{Disposition, Source, classify};
use crate::client::wake::WakeEvent;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// An RNG that always draws the top of a range, so a step's delay equals its
/// ceiling and a test can state exact waits without depending on a seed.
struct MaxRng;

impl rand::RngCore for MaxRng {
    fn next_u32(&mut self) -> u32 {
        u32::MAX
    }
    fn next_u64(&mut self) -> u64 {
        u64::MAX
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        dst.fill(0xff);
    }
}

fn seeded(seed: u64) -> Backoff<StdRng> {
    Backoff::new(StdRng::seed_from_u64(seed))
}

/// Step until `n` ceilings are collected, advancing the clock by each step's
/// ceiling (the longest gap the draw allows) so the window arithmetic is
/// exact whatever the jitter.
fn ceilings<R: rand::RngCore>(b: &mut Backoff<R>, now: &mut Instant, n: usize) -> Vec<Duration> {
    (0..n)
        .map(|_| {
            let step = b.next_step(*now);
            assert!(step.delay <= step.ceiling);
            *now += step.ceiling;
            step.ceiling
        })
        .collect()
}

// -- decision 10 and 18: backoff ---------------------------------------------

#[test]
fn supervise_backoff_caps_at_two_seconds_inside_the_fast_window_then_doubles_to_thirty() {
    let t0 = Instant::now();
    let mut now = t0;
    let mut b = seeded(7);
    b.lost(now);

    // 500, 1000, then pinned at 2000 for as long as the window is open.
    let mut seen = Vec::new();
    while now < t0 + FAST_WINDOW {
        let step = b.next_step(now);
        seen.push(step.ceiling);
        now += step.ceiling;
    }
    assert_eq!(seen[..3], [ms(500), ms(1000), ms(2000)]);
    assert!(
        seen[2..].iter().all(|c| *c == FAST_CAP),
        "inside the window the ceiling never leaves the fast cap: {seen:?}"
    );

    // The window has closed: doubling resumes from where it was.
    assert!(!b.in_fast_window(now));
    let after = ceilings(&mut b, &mut now, 6);
    assert_eq!(
        after,
        [ms(4000), ms(8000), ms(16000), MAX, MAX, MAX],
        "after the window: double from 2 s and stop at 30 s"
    );
}

#[test]
fn supervise_backoff_restarts_and_reopens_the_fast_window_on_wake() {
    let t0 = Instant::now();
    let mut now = t0;
    let mut b = seeded(11);
    b.lost(now);
    // Run well past the window, up to the 30 s ceiling.
    now += FAST_WINDOW + secs(1);
    assert_eq!(
        ceilings(&mut b, &mut now, 6),
        [INITIAL, ms(1000), ms(2000), ms(4000), ms(8000), ms(16000)]
            .iter()
            .map(|c| (*c).min(MAX))
            .collect::<Vec<_>>()
    );
    assert_eq!(ceilings(&mut b, &mut now, 1), [MAX]);

    // The machine woke: back to the start, fast window open again.
    b.wake(now);
    assert!(b.in_fast_window(now));
    let woke_at = now;
    let mut seen = vec![];
    while now < woke_at + FAST_WINDOW {
        seen.push(ceilings(&mut b, &mut now, 1)[0]);
    }
    assert_eq!(seen[..3], [ms(500), ms(1000), ms(2000)]);
    assert!(seen[2..].iter().all(|c| *c == FAST_CAP), "{seen:?}");
    assert!(!b.in_fast_window(now));
}

#[test]
fn supervise_backoff_closes_the_fast_window_on_refused() {
    let t0 = Instant::now();
    let mut now = t0;
    let mut b = seeded(3);
    b.lost(now);
    assert_eq!(ceilings(&mut b, &mut now, 2), [ms(500), ms(1000)]);
    assert!(b.in_fast_window(now));

    // The peer refused the attempt for load: stop knocking every two seconds.
    b.refused();
    assert!(!b.in_fast_window(now));
    assert_eq!(
        ceilings(&mut b, &mut now, 3),
        [ms(2000), ms(4000), ms(8000)],
        "a closed window lets the sequence run past the fast cap"
    );

    // The next loss reopens it.
    b.lost(now);
    assert!(b.in_fast_window(now));
    assert_eq!(ceilings(&mut b, &mut now, 1), [FAST_CAP]);
}

#[test]
fn supervise_backoff_reset_starts_the_sequence_over_without_touching_the_window() {
    let t0 = Instant::now();
    let mut now = t0;
    let mut b = seeded(5);
    b.lost(now);
    ceilings(&mut b, &mut now, 3);
    b.reset();
    assert!(b.in_fast_window(now));
    assert_eq!(ceilings(&mut b, &mut now, 1), [INITIAL]);
}

#[tokio::test(start_paused = true)]
async fn supervise_backoff_wake_cuts_a_pending_wait_but_not_an_attempt_in_flight() {
    let (tx, rx) = watch::channel(WakeEvent::default());
    let mut backoff = Backoff::new(MaxRng);
    backoff.lost(Instant::now());
    let mut pacer = Pacer::new(backoff, rx);
    // Advance the sequence so the pending wait is long (2 s ceiling, MaxRng
    // draws all of it).
    for _ in 0..3 {
        assert!(matches!(pacer.wait().await, Waited::Elapsed(_)));
    }

    // 1. A wake during a pending wait cuts it.
    let started = Instant::now();
    let waiter = tokio::spawn(async move {
        let outcome = pacer.wait().await;
        (pacer, outcome)
    });
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(!waiter.is_finished(), "the 2 s wait must still be pending");
    tx.send_modify(|e| {
        e.seq += 1;
        e.slept_ms = 90_000;
    });
    let (mut pacer, outcome) = waiter.await.expect("waiter");
    assert_eq!(
        outcome,
        Waited::Woken(WakeEvent {
            seq: 1,
            slept_ms: 90_000
        })
    );
    assert!(
        started.elapsed() < FAST_CAP,
        "the wake must not wait out the delay: {:?}",
        started.elapsed()
    );

    // The sequence restarted and the window reopened.
    let Waited::Elapsed(step) = pacer.wait().await else {
        panic!("no wake is pending");
    };
    assert_eq!(step.ceiling, INITIAL);

    // 2. A wake during an attempt does not cut the attempt. The attempt is
    //    the caller's own future; the wake is remembered and served by the
    //    very next wait, which returns without sleeping.
    let attempt_started = Instant::now();
    let attempt = async {
        tokio::time::sleep(secs(3)).await;
        "connected"
    };
    let inject = async {
        tokio::time::sleep(secs(1)).await;
        tx.send_modify(|e| {
            e.seq += 1;
            e.slept_ms = 5_000;
        });
    };
    let (result, ()) = tokio::join!(attempt, inject);
    assert_eq!(result, "connected");
    assert_eq!(
        attempt_started.elapsed(),
        secs(3),
        "the attempt ran to its end"
    );
    let before_wait = Instant::now();
    assert!(matches!(pacer.wait().await, Waited::Woken(e) if e.seq == 2));
    assert_eq!(before_wait.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn supervise_backoff_serves_out_its_wait_when_the_wake_channel_is_gone() {
    let (tx, rx) = watch::channel(WakeEvent::default());
    let mut pacer = Pacer::new(Backoff::new(MaxRng), rx);
    drop(tx);
    let started = Instant::now();
    let Waited::Elapsed(step) = pacer.wait().await else {
        panic!("a closed channel is not a wake");
    };
    assert_eq!(step.delay, INITIAL);
    assert_eq!(started.elapsed(), INITIAL);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn supervise_backoff_never_exceeds_thirty_seconds_and_never_exceeds_two_inside_a_window(
        seed in any::<u64>(),
        ops in proptest::collection::vec((0u8..5, 0u64..90_000), 1..200),
    ) {
        let mut now = Instant::now();
        let mut b = seeded(seed);
        for (op, advance_ms) in ops {
            now += ms(advance_ms);
            match op {
                0 => b.lost(now),
                1 => b.wake(now),
                2 => b.refused(),
                3 => b.reset(),
                _ => {}
            }
            let in_window = b.in_fast_window(now);
            let step = b.next_step(now);
            prop_assert!(step.ceiling <= MAX, "over 30 s: {step:?}");
            prop_assert!(step.delay <= step.ceiling);
            if in_window {
                prop_assert!(step.ceiling <= FAST_CAP, "over 2 s inside the window: {step:?}");
            }
        }
    }
}

// -- decision 10: budget -----------------------------------------------------

#[test]
fn supervise_budget_counts_only_disconnected_time_and_carries_over_inside_the_thirty_second_stability_window()
 {
    let t0 = Instant::now();
    // `--supervise 5000`, connected for a long while before the loss.
    let mut budget = Budget::new(ms(5000), t0);
    let lost_at = t0 + secs(100);
    assert!(budget.lost(lost_at), "a long-lived carrier refills");
    assert_eq!(budget.remaining(lost_at + secs(3)), ms(2000));

    // Re-established after 3 s down; the 100 s of life before did not count.
    let up_at = lost_at + secs(3);
    budget.reestablished(up_at);
    assert_eq!(
        budget.remaining(up_at + secs(19)),
        ms(2000),
        "up time is free"
    );

    // Dies again 20 s later: same outage, 2 s left.
    let lost_again = up_at + secs(20);
    assert!(!budget.lost(lost_again), "20 s alive is not stable");
    assert_eq!(budget.remaining(lost_again), ms(2000));
    assert!(!budget.exhausted(lost_again + ms(1999)));
    assert!(budget.exhausted(lost_again + ms(2000)));
}

#[test]
fn supervise_budget_refills_after_thirty_seconds_alive() {
    let t0 = Instant::now();
    let mut budget = Budget::new(ms(5000), t0);
    budget.lost(t0);
    budget.reestablished(t0 + secs(4));
    assert_eq!(budget.remaining(t0 + secs(4)), ms(1000));

    // One millisecond short of stable: still the same outage.
    let almost = t0 + secs(4) + STABLE_AFTER - ms(1);
    assert!(!budget.lost(almost));
    assert_eq!(budget.remaining(almost), ms(1000));
    budget.reestablished(almost);

    // Exactly stable: the outage is over and the budget is whole again.
    let stable = almost + STABLE_AFTER;
    assert!(budget.lost(stable), "30 s alive ends the outage");
    assert_eq!(budget.remaining(stable), ms(5000));
}

#[test]
fn supervise_budget_excludes_slept_time_and_still_attempts_once_after_a_wake_longer_than_the_budget()
 {
    let t0 = Instant::now();
    let mut budget = Budget::new(ms(5000), t0);
    budget.lost(t0);
    // 3 s disconnected, then the machine sleeps for ten minutes. The
    // monotonic clock stopped for that whole time, so the next reading is
    // still 3 s (plus the tick that noticed) after the loss.
    let after_sleep = t0 + secs(3) + ms(500);
    assert_eq!(
        budget.remaining(after_sleep),
        ms(1500),
        "sleep is not charged"
    );
    assert!(!budget.exhausted(after_sleep));

    // Now the reverse case: the budget ran out just before sleeping.
    let out = t0 + secs(6);
    assert!(budget.exhausted(out));
    budget.note_wake();
    assert!(!budget.exhausted(out), "a wake grants one more attempt");
    budget.note_attempt();
    assert!(budget.exhausted(out), "and exactly one");

    // A re-established carrier drops any unused allowance.
    budget.note_wake();
    budget.reestablished(out);
    budget.lost(out + secs(60));
    assert!(!budget.exhausted(out + secs(60)));
}

// -- decision 9: classification ----------------------------------------------

const SOURCES: [Source; 5] = [
    Source::LocalDial,
    Source::LocalDaemon,
    Source::SupervisorCheck,
    Source::Peer,
    Source::LocalListener,
];

/// The decision-9 table written as data, independently of `classify`'s
/// `match`: the codes each source retries. Peer answers are handled apart
/// because they follow `retryable`.
fn retried_codes(source: Source) -> &'static [ErrorCode] {
    match source {
        Source::LocalDial => &[ErrorCode::ConnectionFailed],
        Source::LocalDaemon => &[
            ErrorCode::HostNotFound,
            ErrorCode::Timeout,
            ErrorCode::ConnectionFailed,
        ],
        _ => &[],
    }
}

#[test]
fn supervise_error_classification_covers_every_source_and_error_code() {
    let mut codes: Vec<ErrorCode> = ErrorCode::KNOWN.to_vec();
    codes.push(ErrorCode::Unknown("SOMETHING_NEW".into()));
    codes.push(ErrorCode::Unknown(String::new()));

    for source in SOURCES {
        for code in &codes {
            for retryable in [true, false] {
                let expected = match source {
                    Source::Peer => {
                        let never = matches!(
                            code,
                            ErrorCode::PermissionDenied
                                | ErrorCode::AuthFailed
                                | ErrorCode::TrustRequired
                                | ErrorCode::Unknown(_)
                        );
                        if retryable && !never {
                            Disposition::Retry
                        } else {
                            Disposition::Stop
                        }
                    }
                    other if retried_codes(other).contains(code) => Disposition::Retry,
                    _ => Disposition::Stop,
                };
                assert_eq!(
                    classify(source, code, retryable),
                    expected,
                    "{source:?} / {code:?} / retryable={retryable}"
                );
            }
        }
    }
}

#[test]
fn supervise_error_classification_matches_the_adr_examples() {
    use Disposition::{Retry, Stop};
    // Both HOST_NOT_FOUND shapes (stale inside the window, swept after it).
    assert_eq!(
        classify(Source::LocalDaemon, &ErrorCode::HostNotFound, true),
        Retry
    );
    assert_eq!(
        classify(Source::LocalDaemon, &ErrorCode::HostNotFound, false),
        Retry
    );
    // Quota is retried, a bind failure is not.
    assert_eq!(
        classify(Source::Peer, &ErrorCode::ResourceExhausted, true),
        Retry
    );
    assert_eq!(
        classify(Source::Peer, &ErrorCode::ConnectionFailed, false),
        Stop
    );
    // A denial is never repeated, even if the peer called it retryable.
    assert_eq!(
        classify(Source::Peer, &ErrorCode::PermissionDenied, true),
        Stop
    );
    // Failing open after `trust remove` is the thing to avoid.
    assert_eq!(
        classify(Source::LocalDial, &ErrorCode::AuthFailed, true),
        Stop
    );
    // The supervisor's own fingerprint and capability checks end the tunnel.
    assert_eq!(
        classify(Source::SupervisorCheck, &ErrorCode::AuthFailed, true),
        Stop
    );
    assert_eq!(
        classify(Source::SupervisorCheck, &ErrorCode::Unsupported, true),
        Stop
    );
}
