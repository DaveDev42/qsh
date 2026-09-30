//! Retry spacing (ADR-0023 decisions 10 and 18).
//!
//! The first attempt after a loss is immediate and is not this module's
//! business. Every later gap comes from [`Backoff::next_step`]: the
//! *ceiling* starts at [`INITIAL`] and doubles up to [`MAX`], and the actual
//! delay is drawn uniformly from `0..=ceiling` (full jitter) so a fleet of
//! tunnels that lost the same peer does not retry in lockstep.
//!
//! **The fast window.** Waiting 30 s to retry is right for a peer that is
//! down, and wrong for a laptop that just came back on a new network. So a
//! loss, and a wake from sleep, each open a [`FAST_WINDOW`] of 60 s during
//! which the ceiling never exceeds [`FAST_CAP`] (2 s). The window is not a
//! separate schedule: the ceiling sequence itself is clamped while the
//! window is open, so when it closes the doubling simply resumes from where
//! it was (2 s, 4 s, ... 30 s) instead of jumping.
//!
//! A wake restarts the sequence at [`INITIAL`] and reopens the window; an
//! attempt that ended in `refused` (admission control, ADR-0009) closes the
//! window at once, because a peer that is refusing for load must not be
//! knocked on every two seconds.
//!
//! Time is always passed in as a [`tokio::time::Instant`], so a paused
//! tokio clock drives the window exactly.

use std::time::Duration;

use rand::Rng;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::client::wake::WakeEvent;

/// First ceiling of the sequence.
pub(crate) const INITIAL: Duration = Duration::from_millis(500);
/// Ceiling the sequence stops doubling at.
pub(crate) const MAX: Duration = Duration::from_millis(30_000);
/// How long a loss or a wake keeps the fast cap in force.
pub(crate) const FAST_WINDOW: Duration = Duration::from_secs(60);
/// Ceiling inside the fast window.
pub(crate) const FAST_CAP: Duration = Duration::from_millis(2_000);

/// One planned gap: the ceiling it was drawn under and the delay itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Step {
    /// Upper bound of the draw. Observable so tests (and the `retry`
    /// diagnostic) can state the schedule without depending on the RNG.
    pub(crate) ceiling: Duration,
    /// The jittered delay, `0..=ceiling`.
    pub(crate) delay: Duration,
}

/// The gap schedule. Generic over the RNG like the target role's backoff.
#[derive(Debug)]
pub(crate) struct Backoff<R> {
    /// The un-jittered ceiling of the last step; `None` at the start of a
    /// sequence.
    ceiling: Option<Duration>,
    /// Until when the fast cap applies, if a window is open.
    window_until: Option<Instant>,
    rng: R,
}

impl<R: rand::RngCore> Backoff<R> {
    pub(crate) fn new(rng: R) -> Self {
        Self {
            ceiling: None,
            window_until: None,
            rng,
        }
    }

    /// A loss was detected: open (or extend) the fast window. Does not
    /// touch the sequence position; the caller calls [`reset`](Self::reset)
    /// when the previous loss is known to be over.
    pub(crate) fn lost(&mut self, now: Instant) {
        self.window_until = Some(now + FAST_WINDOW);
    }

    /// The machine woke: restart the sequence at [`INITIAL`] and reopen
    /// the fast window.
    pub(crate) fn wake(&mut self, now: Instant) {
        self.ceiling = None;
        self.window_until = Some(now + FAST_WINDOW);
    }

    /// An attempt ended in `refused`: close the window now. The next loss
    /// or wake reopens it.
    pub(crate) fn refused(&mut self) {
        self.window_until = None;
    }

    /// The previous loss is over (the carrier lived long enough): the next
    /// loss starts the sequence from [`INITIAL`].
    pub(crate) fn reset(&mut self) {
        self.ceiling = None;
    }

    /// Whether the fast window is open at `now`.
    pub(crate) fn in_fast_window(&self, now: Instant) -> bool {
        self.window_until.is_some_and(|until| now < until)
    }

    /// Plan the gap before the next attempt.
    pub(crate) fn next_step(&mut self, now: Instant) -> Step {
        let cap = if self.in_fast_window(now) {
            FAST_CAP
        } else {
            MAX
        };
        let ceiling = match self.ceiling {
            None => INITIAL,
            Some(prev) => prev.saturating_mul(2),
        }
        .min(cap);
        self.ceiling = Some(ceiling);
        let ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        let delay = Duration::from_millis(self.rng.random_range(0..=ms));
        Step { ceiling, delay }
    }
}

/// What ended a wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
    /// The planned delay elapsed.
    Elapsed(Step),
    /// A wake cut the wait short (or arrived while the previous attempt was
    /// still running); the sequence was restarted and the caller should
    /// attempt at once.
    Woken(WakeEvent),
}

/// A [`Backoff`] joined to the wake signal (ADR-0023 decision 10).
///
/// A wake cuts a pending *wait*, never an *attempt* in flight: the caller
/// runs its attempt without involving this type, so nothing here can abort
/// it. A wake that lands during the attempt is remembered by the receiver
/// and applied at the next [`wait`](Self::wait), which then returns at once.
pub(crate) struct Pacer<R> {
    backoff: Backoff<R>,
    wake: watch::Receiver<WakeEvent>,
}

impl<R: rand::RngCore> Pacer<R> {
    /// `wake` should be a fresh subscription (its current value counts as
    /// already seen).
    pub(crate) fn new(backoff: Backoff<R>, mut wake: watch::Receiver<WakeEvent>) -> Self {
        wake.mark_unchanged();
        Self { backoff, wake }
    }

    /// Wait out the gap after a failed attempt.
    pub(crate) async fn wait(&mut self) -> Waited {
        let now = Instant::now();
        // A wake that arrived while the attempt was running.
        if self.wake.has_changed().unwrap_or(false) {
            return self.woken(now);
        }
        let step = self.backoff.next_step(now);
        let sleep = tokio::time::sleep(step.delay);
        tokio::pin!(sleep);
        tokio::select! {
            () = &mut sleep => {}
            changed = self.wake.changed() => {
                if changed.is_ok() {
                    return self.woken(Instant::now());
                }
                // The detector is gone (only an injected sender can be):
                // no wake will ever cut this wait, so serve it out.
                sleep.await;
            }
        }
        Waited::Elapsed(step)
    }

    fn woken(&mut self, now: Instant) -> Waited {
        let event = *self.wake.borrow_and_update();
        self.backoff.wake(now);
        Waited::Woken(event)
    }
}
