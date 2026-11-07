//! The host's input write-time table for `ScreenEcho` (ADR-0053 decision 3,
//! `docs/design/protocol.md` §18.12).
//!
//! `ScreenEcho.input_seq` claims that every input byte below it was written
//! to the PTY at least [`ECHO_GRACE`] before the screen state it names, so
//! the client can tell "the application had its chance to echo" from "the
//! echo has not come yet". The host therefore remembers when each input
//! chunk was written. The table holds only offsets and times, never bytes.
//! It takes the clock as an argument, so tests drive it with made-up
//! instants.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long after a write the host assumes the application and the kernel
/// have echoed it. Starting value of ADR-0053 decision 3, confirmed on three
/// OSes by the decision 16 tests and recorded in the ADR revision history.
pub const ECHO_GRACE: Duration = Duration::from_millis(50);

/// Most (end offset, write time) entries one attach keeps; past it the two
/// oldest merge (ADR-0053 decision 3).
pub const MAX_INPUT_TIMES: usize = 64;

/// Input offsets of one attach's axis with the time each was written.
#[derive(Debug, Clone)]
pub struct InputTimes {
    /// Every byte below this offset has already been claimed as written at
    /// least [`ECHO_GRACE`] ago. Starts at the offset the attach resumed at.
    settled: u64,
    /// Chunks written and not yet old enough: end offset and write time,
    /// ascending in both.
    pending: VecDeque<(u64, Instant)>,
}

impl InputTimes {
    /// A table for an attach whose input axis already stands at `from`.
    pub fn new(from: u64) -> Self {
        Self {
            settled: from,
            pending: VecDeque::new(),
        }
    }

    /// The host wrote input up to cumulative offset `end` at `now`. An
    /// offset that does not move past the newest one (a duplicate) is
    /// ignored.
    pub fn record(&mut self, end: u64, now: Instant) {
        let newest = self.pending.back().map_or(self.settled, |(e, _)| *e);
        if end <= newest {
            return;
        }
        if self.pending.len() == MAX_INPUT_TIMES {
            // Merge the two oldest: the later time and the later offset, so
            // the claim only ever gets more conservative.
            let (_, first_at) = self.pending.pop_front().expect("full");
            if let Some(second) = self.pending.front_mut() {
                second.1 = second.1.max(first_at);
            }
        }
        self.pending.push_back((end, now));
    }

    /// The offset below which every byte was written at least
    /// [`ECHO_GRACE`] before `now`. Never goes backwards.
    pub fn settle(&mut self, now: Instant) -> u64 {
        while let Some((end, at)) = self.pending.front().copied() {
            if now.saturating_duration_since(at) < ECHO_GRACE {
                break;
            }
            self.settled = end;
            self.pending.pop_front();
        }
        self.settled
    }

    /// When the next entry becomes old enough, for the timer that sends a
    /// `ScreenEcho` although the screen did not change.
    pub fn next_due(&self) -> Option<Instant> {
        self.pending.front().map(|(_, at)| *at + ECHO_GRACE)
    }

    /// Entries not yet settled.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no entry waits.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(base: Instant, n: u64) -> Instant {
        base + Duration::from_millis(n)
    }

    #[test]
    fn a_chunk_settles_only_after_the_echo_grace() {
        let t0 = Instant::now();
        let mut t = InputTimes::new(10);
        assert_eq!(t.settle(t0), 10);
        t.record(12, t0);
        t.record(15, ms(t0, 30));
        assert_eq!(t.next_due(), Some(ms(t0, 50)));
        assert_eq!(t.settle(ms(t0, 49)), 10);
        assert_eq!(t.settle(ms(t0, 50)), 12);
        assert_eq!(t.next_due(), Some(ms(t0, 80)));
        assert_eq!(t.settle(ms(t0, 79)), 12);
        assert_eq!(t.settle(ms(t0, 500)), 15);
        assert!(t.is_empty());
        assert_eq!(t.next_due(), None);
    }

    #[test]
    fn a_duplicate_or_older_offset_changes_nothing() {
        let t0 = Instant::now();
        let mut t = InputTimes::new(0);
        t.record(5, t0);
        t.record(5, ms(t0, 40));
        t.record(3, ms(t0, 40));
        assert_eq!(t.len(), 1);
        assert_eq!(t.settle(ms(t0, 50)), 5);
        t.record(5, ms(t0, 60));
        assert!(t.is_empty());
    }

    #[test]
    fn the_table_is_bounded_and_merging_keeps_the_later_time() {
        let t0 = Instant::now();
        let mut t = InputTimes::new(0);
        for i in 0..(MAX_INPUT_TIMES as u64 * 3) {
            t.record(i + 1, ms(t0, i));
            assert!(t.len() <= MAX_INPUT_TIMES);
        }
        // The merged front entry never claims a byte earlier than its own
        // write: at the instant the newest is due, everything is settled.
        let last = MAX_INPUT_TIMES as u64 * 3;
        assert_eq!(t.settle(ms(t0, last - 1 + 50)), last);
    }

    #[test]
    fn settling_never_claims_a_byte_written_inside_the_grace() {
        let t0 = Instant::now();
        let mut t = InputTimes::new(0);
        for i in 0..200u64 {
            t.record(i + 1, ms(t0, i * 10));
        }
        for probe in [0u64, 17, 333, 1000, 1999, 2500] {
            let now = ms(t0, probe);
            let claimed = t.clone().settle(now);
            for byte in 0..claimed {
                // Byte `byte` was written at 10 * byte ms at the latest of
                // its chunk; merging may only delay, never advance.
                assert!(now.duration_since(ms(t0, byte * 10)) >= ECHO_GRACE);
            }
        }
    }
}
