//! The disconnection budget (ADR-0023 decision 10).
//!
//! `--supervise <ms>` is how long a tunnel may spend *disconnected* per
//! outage, not how long it may run. The ledger counts only the time spent in
//! the "disconnected" state, on the monotonic clock. That clock stops while
//! the machine sleeps (macOS, Linux; ADR-0023 decision 17), so time asleep is
//! never charged, and the budget takes no `slept_ms` input: subtracting it
//! from a clock that already excluded it would hand time back twice.
//!
//! **What ends an outage.** A re-established carrier has to live
//! [`STABLE_AFTER`] (30 s) before the loss counts as over and the budget
//! refills. A carrier that dies sooner is the same outage: the time already
//! spent stays spent (so a flapping path cannot reset its way to an endless
//! retry) and the caller keeps its backoff position as well.
//!
//! **One attempt per wake.** A budget that ran out just before the machine
//! slept must not turn a wake into an immediate `gave_up`: waking is the
//! moment the network most likely came back. [`Budget::note_wake`] grants
//! one attempt past exhaustion, consumed by [`Budget::note_attempt`].

use std::time::Duration;

use tokio::time::Instant;

/// How long a re-established carrier must live before the outage that
/// preceded it is considered over.
pub(crate) const STABLE_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
enum State {
    /// Connected since this instant.
    Up(Instant),
    /// Disconnected since this instant.
    Down(Instant),
}

/// The ledger.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    total: Duration,
    /// Disconnected time already charged in the current outage.
    spent: Duration,
    state: State,
    /// One attempt is allowed past exhaustion (a wake arrived).
    grace: bool,
}

impl Budget {
    /// A connected tunnel with `total` disconnection time available.
    pub(crate) fn new(total: Duration, now: Instant) -> Self {
        Self {
            total,
            spent: Duration::ZERO,
            state: State::Up(now),
            grace: false,
        }
    }

    /// The carrier was declared lost. Returns whether the previous outage
    /// had ended (the carrier lived [`STABLE_AFTER`]), in which case the
    /// budget is full again and the caller should also reset its backoff
    /// position. A no-op if already disconnected.
    pub(crate) fn lost(&mut self, now: Instant) -> bool {
        let State::Up(since) = self.state else {
            return false;
        };
        let refilled = now.saturating_duration_since(since) >= STABLE_AFTER;
        if refilled {
            self.spent = Duration::ZERO;
        }
        self.state = State::Down(now);
        refilled
    }

    /// A carrier was re-established: charge the outage's disconnected time.
    pub(crate) fn reestablished(&mut self, now: Instant) {
        if let State::Down(since) = self.state {
            self.spent = self
                .spent
                .saturating_add(now.saturating_duration_since(since));
        }
        self.state = State::Up(now);
        self.grace = false;
    }

    /// Disconnected time still available at `now`.
    pub(crate) fn remaining(&self, now: Instant) -> Duration {
        let running = match self.state {
            State::Down(since) => now.saturating_duration_since(since),
            State::Up(_) => Duration::ZERO,
        };
        self.total
            .saturating_sub(self.spent.saturating_add(running))
    }

    /// Whether the supervisor must give up rather than plan another
    /// attempt.
    pub(crate) fn exhausted(&self, now: Instant) -> bool {
        !self.grace && self.remaining(now).is_zero()
    }

    /// The machine woke: allow one more attempt even if the budget is spent.
    pub(crate) fn note_wake(&mut self) {
        self.grace = true;
    }

    /// An attempt started: the wake allowance, if any, is used up.
    pub(crate) fn note_attempt(&mut self) {
        self.grace = false;
    }
}
