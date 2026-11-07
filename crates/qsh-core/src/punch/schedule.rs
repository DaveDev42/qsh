//! The punch send schedule (ADR-0054 decision 14) as a state machine with no
//! clock and no I/O: the caller says how much time has passed and gets the
//! candidates that are due.

use std::time::Duration;

use super::PUNCH_OFFSETS_MS;

/// Which candidates are due for a punch datagram, by elapsed time since t=0.
///
/// Every candidate gets one datagram at each of [`PUNCH_OFFSETS_MS`]. Rounds
/// are never repeated and never skipped: a late caller gets all the rounds it
/// missed at once.
#[derive(Clone, Debug)]
pub struct Schedule {
    candidates: usize,
    /// Index into [`PUNCH_OFFSETS_MS`] of the next round.
    round: usize,
}

impl Schedule {
    /// A schedule for `candidates` destinations.
    pub fn new(candidates: usize) -> Self {
        Self {
            candidates,
            round: 0,
        }
    }

    /// The destinations (candidate indexes) to send to, round by round, for
    /// every round whose offset is at or before `elapsed`.
    pub fn due(&mut self, elapsed: Duration) -> Vec<usize> {
        let mut out = Vec::new();
        while let Some(offset) = self.next_at() {
            if offset > elapsed {
                break;
            }
            out.extend(0..self.candidates);
            self.round += 1;
        }
        out
    }

    /// When the next round is due, or `None` after the last.
    pub fn next_at(&self) -> Option<Duration> {
        PUNCH_OFFSETS_MS
            .get(self.round)
            .map(|ms| Duration::from_millis(*ms))
    }

    /// Datagrams handed out so far.
    pub fn sent(&self) -> usize {
        self.round * self.candidates
    }

    /// Datagrams the whole schedule hands out.
    pub fn total(&self) -> usize {
        PUNCH_OFFSETS_MS.len() * self.candidates
    }
}
