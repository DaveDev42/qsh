//! The per-initiator attempt limits of the rendezvous (R) and the target (B)
//! (ADR-0054 decision 11): `PUNCH_RATE` attempts per `PUNCH_RATE_WINDOW_SECS`
//! and, at R, one attempt in flight. A pure table keyed by the initiator's
//! fingerprint; the caller passes `now`.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use qsh_proto::punch::{PUNCH_RATE, PUNCH_RATE_WINDOW_SECS};

/// Initiators remembered at once. Only authorized peers reach the table, so
/// the bound is a backstop; past it the oldest idle entries are dropped.
const MAX_TRACKED_INITIATORS: usize = 1024;

/// Why an attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitHit {
    /// This initiator already has an attempt in flight (R only).
    InFlight,
    /// This initiator started `PUNCH_RATE` attempts in the last window.
    Rate,
}

#[derive(Debug, Default)]
struct Entry {
    recent: VecDeque<Instant>,
    in_flight: bool,
}

/// Attempt counters per initiator fingerprint.
#[derive(Debug)]
pub struct AttemptLimiter {
    single_flight: bool,
    window: Duration,
    rate: usize,
    entries: HashMap<[u8; 32], Entry>,
}

impl AttemptLimiter {
    /// The limiter with ADR-0054's numbers. `single_flight` is the rendezvous'
    /// "one attempt in flight per initiator".
    pub fn new(single_flight: bool) -> Self {
        Self {
            single_flight,
            window: Duration::from_secs(PUNCH_RATE_WINDOW_SECS),
            rate: PUNCH_RATE,
            entries: HashMap::new(),
        }
    }

    /// Counts a new attempt of `initiator` at `now`, or says which limit is
    /// hit (and counts nothing). With `single_flight`, a successful call must
    /// be followed by [`Self::finish`].
    pub fn try_begin(&mut self, initiator: &[u8; 32], now: Instant) -> Result<(), LimitHit> {
        if self.entries.len() >= MAX_TRACKED_INITIATORS && !self.entries.contains_key(initiator) {
            self.prune(now);
        }
        let window = self.window;
        let entry = self.entries.entry(*initiator).or_default();
        while entry
            .recent
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= window)
        {
            entry.recent.pop_front();
        }
        if self.single_flight && entry.in_flight {
            return Err(LimitHit::InFlight);
        }
        if entry.recent.len() >= self.rate {
            return Err(LimitHit::Rate);
        }
        entry.recent.push_back(now);
        entry.in_flight = self.single_flight;
        Ok(())
    }

    /// Ends the in-flight attempt of `initiator`.
    pub fn finish(&mut self, initiator: &[u8; 32]) {
        if let Some(entry) = self.entries.get_mut(initiator) {
            entry.in_flight = false;
        }
    }

    fn prune(&mut self, now: Instant) {
        let window = self.window;
        self.entries.retain(|_, e| {
            e.in_flight
                || e.recent
                    .back()
                    .is_some_and(|t| now.saturating_duration_since(*t) < window)
        });
        // Still full of busy entries: forget the least recently active ones.
        while self.entries.len() >= MAX_TRACKED_INITIATORS {
            let oldest = self
                .entries
                .iter()
                .filter(|(_, e)| !e.in_flight)
                .min_by_key(|(_, e)| e.recent.back().copied())
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.entries.remove(&k);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];

    #[test]
    fn the_seventh_attempt_in_a_window_is_refused_and_the_window_slides() {
        let mut l = AttemptLimiter::new(false);
        let t0 = Instant::now();
        for i in 0..PUNCH_RATE {
            assert_eq!(l.try_begin(&A, t0 + Duration::from_secs(i as u64)), Ok(()));
        }
        assert_eq!(
            l.try_begin(&A, t0 + Duration::from_secs(10)),
            Err(LimitHit::Rate)
        );
        // Another initiator is unaffected.
        assert_eq!(l.try_begin(&B, t0 + Duration::from_secs(10)), Ok(()));
        // The first attempt leaves the window 60 s after it started.
        assert_eq!(l.try_begin(&A, t0 + Duration::from_secs(60)), Ok(()));
        assert_eq!(
            l.try_begin(&A, t0 + Duration::from_secs(60)),
            Err(LimitHit::Rate)
        );
    }

    #[test]
    fn a_second_attempt_in_flight_is_refused_until_the_first_finishes() {
        let mut l = AttemptLimiter::new(true);
        let t0 = Instant::now();
        assert_eq!(l.try_begin(&A, t0), Ok(()));
        assert_eq!(l.try_begin(&A, t0), Err(LimitHit::InFlight));
        assert_eq!(l.try_begin(&B, t0), Ok(()));
        l.finish(&A);
        assert_eq!(l.try_begin(&A, t0), Ok(()));
    }

    #[test]
    fn a_refused_attempt_counts_for_nothing() {
        let mut l = AttemptLimiter::new(true);
        let t0 = Instant::now();
        assert_eq!(l.try_begin(&A, t0), Ok(()));
        for _ in 0..20 {
            assert_eq!(l.try_begin(&A, t0), Err(LimitHit::InFlight));
        }
        l.finish(&A);
        // One counted attempt so far, not twenty-one.
        for _ in 1..PUNCH_RATE {
            assert_eq!(l.try_begin(&A, t0), Ok(()));
            l.finish(&A);
        }
        assert_eq!(l.try_begin(&A, t0), Err(LimitHit::Rate));
    }

    #[test]
    fn the_table_stays_bounded() {
        let mut l = AttemptLimiter::new(false);
        let t0 = Instant::now();
        for i in 0..(MAX_TRACKED_INITIATORS * 2) {
            let mut fp = [0u8; 32];
            fp[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert_eq!(
                l.try_begin(&fp, t0 + Duration::from_millis(i as u64)),
                Ok(())
            );
        }
        assert!(l.entries.len() <= MAX_TRACKED_INITIATORS);
    }
}
