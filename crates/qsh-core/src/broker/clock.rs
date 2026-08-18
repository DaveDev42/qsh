//! Injectable time source for the broker (`docs/design/testing.md` L2:
//! "주입 가능한 clock을 M2 설계 시점부터").
//!
//! Every time-dependent decision the broker makes — resume TTL expiry, the
//! close escalation grace, `pull(..., wait)` deadlines, `created_at`
//! stamps — goes through a [`Clock`]. Production uses [`SystemClock`]
//! (tokio's clock, so `tokio::time::pause()` still works end to end); tests
//! and the M8 stateful fuzzer drive a [`TestClock`] by hand with
//! [`TestClock::advance`]. Nothing under `broker/` calls
//! `Instant::now()`/`sleep()` directly.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Notify;

/// A boxed, sendable future — the return type of [`Clock::sleep_until`],
/// kept object-safe so the broker can hold an `Arc<dyn Clock>`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Monotonic + wall clock the broker reads time from.
pub trait Clock: Send + Sync + 'static {
    /// Current monotonic instant. Only ever compared with other instants
    /// from the same clock.
    fn now(&self) -> Instant;

    /// Current wall-clock time (for `created_at`/`expires_at` stamps).
    fn wall_now(&self) -> SystemTime;

    /// Resolve once [`Clock::now`] is at or past `deadline`.
    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'_, ()>;

    /// Resolve after `dur` has elapsed on this clock.
    fn sleep(&self, dur: Duration) -> BoxFuture<'_, ()> {
        self.sleep_until(self.now() + dur)
    }
}

/// The real clock, backed by tokio's timer (so `tokio::time::pause()` and
/// `advance()` steer it in tests that prefer that route).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'_, ()> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline,
        )))
    }
}

/// A manually advanced clock. Time only moves when [`TestClock::advance`]
/// (or [`TestClock::set`]) is called; sleepers wake exactly then — no real
/// time passes and nothing polls.
#[derive(Debug, Clone)]
pub struct TestClock {
    inner: Arc<TestClockInner>,
}

#[derive(Debug)]
struct TestClockInner {
    /// Reference point for the monotonic axis. Never read as "real time";
    /// it only lets us hand out `std::time::Instant` values.
    epoch: Instant,
    /// Wall time corresponding to `epoch`.
    wall_epoch: SystemTime,
    elapsed: Mutex<Duration>,
    tick: Notify,
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TestClock {
    /// Wall time at the clock's zero: 2026-01-01T00:00:00Z as seconds since
    /// the Unix epoch (arbitrary but stable, so stamps in tests are
    /// predictable).
    pub const WALL_START_UNIX_SECS: u64 = 1_767_225_600;

    /// A clock frozen at its own zero.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TestClockInner {
                epoch: Instant::now(),
                wall_epoch: SystemTime::UNIX_EPOCH
                    + Duration::from_secs(Self::WALL_START_UNIX_SECS),
                elapsed: Mutex::new(Duration::ZERO),
                tick: Notify::new(),
            }),
        }
    }

    /// Move the clock forward by `dur`, waking every sleeper whose deadline
    /// is now due.
    pub fn advance(&self, dur: Duration) {
        {
            let mut elapsed = self.inner.elapsed.lock().unwrap_or_else(|e| e.into_inner());
            *elapsed = elapsed.saturating_add(dur);
        }
        self.inner.tick.notify_waiters();
    }

    /// Set the elapsed time since the clock's zero (never goes backwards).
    pub fn set(&self, elapsed_since_zero: Duration) {
        {
            let mut elapsed = self.inner.elapsed.lock().unwrap_or_else(|e| e.into_inner());
            if elapsed_since_zero > *elapsed {
                *elapsed = elapsed_since_zero;
            }
        }
        self.inner.tick.notify_waiters();
    }

    /// Time elapsed since the clock's zero.
    pub fn elapsed(&self) -> Duration {
        *self.inner.elapsed.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.inner.epoch + self.elapsed()
    }

    fn wall_now(&self) -> SystemTime {
        self.inner.wall_epoch + self.elapsed()
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            loop {
                // Register interest *before* checking, so an `advance` that
                // races between the check and the await is not missed.
                // `enable()` makes the waiter live at this point rather than
                // only on first poll.
                let tick = self.inner.tick.notified();
                tokio::pin!(tick);
                tick.as_mut().enable();
                if self.now() >= deadline {
                    return;
                }
                tick.await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clock_only_moves_when_advanced() {
        let clock = TestClock::new();
        let t0 = clock.now();
        assert_eq!(clock.now(), t0);
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now(), t0 + Duration::from_secs(5));
        assert_eq!(
            clock.wall_now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(TestClock::WALL_START_UNIX_SECS + 5)
        );
    }

    #[tokio::test]
    async fn sleepers_wake_exactly_on_advance() {
        let clock = TestClock::new();
        // Capture an absolute deadline *now* (elapsed 0) so the wake point
        // does not depend on when the spawned task is first polled.
        let deadline = clock.now() + Duration::from_secs(10);
        let sleeper = {
            let clock = clock.clone();
            tokio::spawn(async move {
                clock.sleep_until(deadline).await;
                clock.elapsed()
            })
        };
        // Not enough: the sleeper stays pending.
        clock.advance(Duration::from_secs(9));
        tokio::task::yield_now().await;
        assert!(!sleeper.is_finished());
        clock.advance(Duration::from_secs(1));
        assert_eq!(sleeper.await.unwrap(), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn set_never_goes_backwards() {
        let clock = TestClock::new();
        clock.set(Duration::from_secs(3));
        clock.set(Duration::from_secs(1));
        assert_eq!(clock.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn system_clock_follows_tokio_pause() {
        let clock = SystemClock;
        let t0 = clock.now();
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(clock.now() - t0, Duration::from_secs(60));
        let deadline = clock.now() + Duration::from_millis(500);
        // Auto-advance under `start_paused` resolves this without waiting.
        clock.sleep_until(deadline).await;
        assert!(clock.now() >= deadline);
    }
}
