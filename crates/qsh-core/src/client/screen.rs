//! Client side of screen state sync (ADR-0052 decisions 5, 6 and 11,
//! `docs/design/protocol.md` §18): the screen the host described.
//!
//! [`ClientScreen`] takes the `ScreenUpdate` parts a data stream or the
//! datagram carrier delivers, puts them together, applies the update to the
//! screen it holds and checks the result against the update's `state_hash`.
//! It decides what to tell the host: the state number it now holds, or 0 to
//! ask for the full screen when it cannot continue (hash mismatch, a base it
//! does not have, an update it cannot apply). It does no I/O; the caller
//! sends the acknowledgement ([`ScreenOutcome::ack`]) with
//! [`super::Attached::send_screen_ack`] and draws [`ClientScreen::state`]
//! however it likes. The real `qsh` renderer is a later step.
//!
//! The screen keeps the last [`RETAINED_STATES`] states it applied. A
//! datagram update diffs from the last state *acked*, which can be older
//! than the newest the client holds when an ack was lost; any retained state
//! is a valid base.

use std::collections::VecDeque;

use qsh_proto::screen::{DatagramReassembler, Effect, Reassembler, ScreenState, ScreenUpdate};
use qsh_proto::wire;

use super::ClientError;

/// States kept as possible bases (ADR-0052 decision 5).
pub const RETAINED_STATES: usize = 8;

/// What one [`ClientScreen::on_part`] call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenOutcome {
    /// The part belongs to an update that is not complete yet.
    Partial,
    /// An update was applied and its hash matched.
    Applied {
        /// The state the client now holds.
        new_num: u64,
        /// Output offset the state reflects.
        output_seq: u64,
        /// Effects (title, bell, clipboard, hyperlink) that happened up to
        /// this state, in order.
        effects: Vec<Effect>,
    },
    /// The client cannot continue from what it holds and has dropped it.
    /// The caller sends `ScreenAck{0}`; until the full screen arrives the
    /// updates still in flight are ignored.
    Resync(ResyncReason),
    /// An update that cannot apply because a full screen was requested and
    /// has not arrived yet.
    Ignored,
    /// An update that is not newer than the state held (it crossed a newer
    /// one on the other carrier) or whose base the client no longer retains
    /// (a datagram update after a lost ack). It is dropped and the held
    /// state is acked again so the host diffs from it.
    Stale {
        /// The state the client holds; 0 when it holds none.
        held: u64,
    },
}

impl ScreenOutcome {
    /// The `ScreenAck.state_num` to send for this outcome, if any: the new
    /// state after an applied update, 0 after a resync, the held state after
    /// a stale one.
    pub fn ack(&self) -> Option<u64> {
        match self {
            ScreenOutcome::Applied { new_num, .. } => Some(*new_num),
            ScreenOutcome::Resync(_) => Some(0),
            ScreenOutcome::Stale { held } if *held != 0 => Some(*held),
            ScreenOutcome::Stale { .. } | ScreenOutcome::Partial | ScreenOutcome::Ignored => None,
        }
    }
}

/// Why the client asks for the full screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncReason {
    /// The applied screen's hash differs from the update's `state_hash`.
    HashMismatch,
    /// The update's base is not the state the client holds.
    BaseMismatch,
    /// The diff does not apply (out-of-range row, bad size, ...).
    BadDiff,
}

/// The carrier an update came on: it decides what a base the client does not
/// retain means. On the stream the host diffs from what it sent, so a miss
/// is a fault and asks for the full screen; a datagram update diffs from
/// the last ack, so a miss is just an old ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Stream,
    Datagram,
}

/// The screen a screen-sync attach has built so far.
#[derive(Debug, Default)]
pub struct ClientScreen {
    /// Applied states, oldest first; the last one is the screen held.
    history: VecDeque<(u64, ScreenState)>,
    output_seq: u64,
    parts: Reassembler,
    datagram_parts: DatagramReassembler,
    awaiting_full: bool,
    applied: u64,
    resyncs: u64,
    datagram_dropped: u64,
}

impl ClientScreen {
    /// An empty client screen: it holds no state, so the first update the
    /// host sends (base 0) builds it.
    pub fn new() -> Self {
        Self::default()
    }

    /// The screen, once the first update has been applied.
    pub fn state(&self) -> Option<&ScreenState> {
        self.history.back().map(|(_, s)| s)
    }

    /// The `state_num` of the screen held; 0 before the first update.
    pub fn num(&self) -> u64 {
        self.history.back().map_or(0, |(n, _)| *n)
    }

    /// Output offset the screen held reflects.
    pub fn output_seq(&self) -> u64 {
        self.output_seq
    }

    /// `state_hash` of the screen held.
    pub fn hash(&self) -> Option<[u8; qsh_proto::screen::HASH_LEN]> {
        self.state().map(ScreenState::hash)
    }

    /// Updates applied so far.
    pub fn applied_updates(&self) -> u64 {
        self.applied
    }

    /// Full-screen requests made so far.
    pub fn resyncs(&self) -> u64 {
        self.resyncs
    }

    /// Datagram parts or updates dropped as malformed.
    pub fn datagram_dropped(&self) -> u64 {
        self.datagram_dropped
    }

    /// Feed one `ScreenUpdate` part from the data stream. An `Err` is a
    /// host that broke the part grammar or sent bytes that do not decode;
    /// the attach should be treated as failed.
    pub fn on_part(&mut self, part: &wire::ScreenUpdate) -> Result<ScreenOutcome, ClientError> {
        let complete = self
            .parts
            .push(part.new_num, part.part, part.parts, &part.data)
            .map_err(|e| ClientError::Protocol(format!("ScreenUpdate part: {e}")))?;
        let Some(bytes) = complete else {
            return Ok(ScreenOutcome::Partial);
        };
        let update = ScreenUpdate::decode(&bytes)
            .map_err(|e| ClientError::Protocol(format!("ScreenUpdate: {e}")))?;
        Ok(self.apply(&update))
    }

    /// Feed one `ScreenUpdate` part from a datagram. Parts may arrive in any
    /// order, twice, or never; the update applies when all of its parts have
    /// arrived. A datagram that does not parse is counted and dropped, never
    /// fatal: the stream carries the same information.
    pub fn on_datagram_part(&mut self, part: &wire::ScreenUpdate) -> ScreenOutcome {
        match self
            .datagram_parts
            .push(part.new_num, part.part, part.parts, &part.data)
        {
            Ok(None) => ScreenOutcome::Partial,
            Ok(Some(bytes)) => match ScreenUpdate::decode(&bytes) {
                Ok(update) => self.apply_via(&update, Via::Datagram),
                Err(_) => {
                    self.datagram_dropped += 1;
                    ScreenOutcome::Partial
                }
            },
            Err(_) => {
                self.datagram_dropped += 1;
                ScreenOutcome::Partial
            }
        }
    }

    /// Apply a whole decoded stream update.
    pub fn apply(&mut self, update: &ScreenUpdate) -> ScreenOutcome {
        self.apply_via(update, Via::Stream)
    }

    fn apply_via(&mut self, update: &ScreenUpdate, via: Via) -> ScreenOutcome {
        if self.awaiting_full && update.base_num != 0 {
            return ScreenOutcome::Ignored;
        }
        // Not newer than what is held: it crossed a newer update on the
        // other carrier. Applying it would move the screen backwards. A
        // full screen (base 0) is self-contained, so one for the state
        // already held is applied again, and only an older one is dropped.
        let held = self.num();
        if held != 0 && (update.new_num < held || (update.base_num != 0 && update.new_num == held))
        {
            return ScreenOutcome::Stale { held };
        }
        let base = if update.base_num == 0 {
            match ScreenState::blank(update.diff.rows, update.diff.cols) {
                Ok(blank) => blank,
                Err(_) => return self.resync(ResyncReason::BadDiff),
            }
        } else {
            match self.history.iter().find(|(n, _)| *n == update.base_num) {
                Some((_, state)) => state.clone(),
                None if via == Via::Datagram => {
                    return ScreenOutcome::Stale { held: self.num() };
                }
                None => return self.resync(ResyncReason::BaseMismatch),
            }
        };
        match update.apply(&base) {
            Ok(state) => {
                self.history.push_back((update.new_num, state));
                while self.history.len() > RETAINED_STATES {
                    self.history.pop_front();
                }
                self.output_seq = update.output_seq;
                self.awaiting_full = false;
                self.applied += 1;
                ScreenOutcome::Applied {
                    new_num: update.new_num,
                    output_seq: update.output_seq,
                    effects: update.effects.clone(),
                }
            }
            Err(qsh_proto::screen::ApplyError::HashMismatch) => {
                self.resync(ResyncReason::HashMismatch)
            }
            Err(_) => self.resync(ResyncReason::BadDiff),
        }
    }

    fn resync(&mut self, reason: ResyncReason) -> ScreenOutcome {
        self.history.clear();
        self.awaiting_full = true;
        self.resyncs += 1;
        ScreenOutcome::Resync(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_proto::screen::{Cell, ScreenDiff};

    impl ClientScreen {
        fn apply_datagram_for_test(&mut self, update: &ScreenUpdate) -> ScreenOutcome {
            self.apply_via(update, Via::Datagram)
        }
    }

    fn state_with(text: &str) -> ScreenState {
        let mut s = ScreenState::blank(2, 4).unwrap();
        s.grid[0].cells[0] = Cell {
            text: text.into(),
            ..Cell::default()
        };
        s
    }

    fn update(base: &ScreenState, base_num: u64, new: &ScreenState, new_num: u64) -> ScreenUpdate {
        ScreenUpdate {
            base_num,
            new_num,
            output_seq: 0,
            diff: ScreenDiff::between(base, new).unwrap(),
            effects: Vec::new(),
            state_hash: new.hash(),
        }
    }

    #[test]
    fn a_hash_mismatch_drops_the_screen_and_asks_for_base_zero() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let a = state_with("a");
        let b = state_with("b");
        let mut c = ClientScreen::new();
        let first = c.apply(&update(&blank, 0, &a, 1));
        assert_eq!(first.ack(), Some(1));
        assert_eq!(c.hash(), Some(a.hash()));

        let mut bad = update(&a, 1, &b, 2);
        bad.state_hash = [0xff; 8];
        let out = c.apply(&bad);
        assert_eq!(out, ScreenOutcome::Resync(ResyncReason::HashMismatch));
        assert_eq!(out.ack(), Some(0));
        assert!(c.state().is_none() && c.num() == 0);

        // Updates still in flight are ignored until the full screen lands.
        let c3 = state_with("c");
        assert_eq!(c.apply(&update(&b, 2, &c3, 3)), ScreenOutcome::Ignored);
        let full = c.apply(&update(&blank, 0, &c3, 3));
        assert_eq!(full.ack(), Some(3));
        assert_eq!(c.hash(), Some(c3.hash()));
        assert_eq!(c.resyncs(), 1);
    }

    #[test]
    fn a_base_the_client_does_not_hold_asks_for_base_zero() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let a = state_with("a");
        let b = state_with("b");
        let mut c = ClientScreen::new();
        c.apply(&update(&blank, 0, &a, 1));
        let out = c.apply(&update(&a, 5, &b, 6));
        assert_eq!(out, ScreenOutcome::Resync(ResyncReason::BaseMismatch));
    }

    #[test]
    fn parts_of_an_update_are_reassembled_in_order() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let a = state_with("a");
        let bytes = update(&blank, 0, &a, 1).encode();
        let mut c = ClientScreen::new();
        let parts = wire::ScreenUpdate::parts_of(1, &bytes);
        let mut last = ScreenOutcome::Partial;
        for p in &parts {
            last = c.on_part(p).unwrap();
        }
        assert_eq!(last.ack(), Some(1));
        // A middle part with nothing before it is a protocol fault.
        let mut c = ClientScreen::new();
        let orphan = wire::ScreenUpdate {
            new_num: 1,
            part: 1,
            parts: 2,
            data: vec![0],
        };
        assert!(c.on_part(&orphan).is_err());
    }

    #[test]
    fn datagram_parts_apply_out_of_order_once_all_have_arrived() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let a = state_with("a");
        let bytes = update(&blank, 0, &a, 1).encode();
        let parts = wire::ScreenUpdate::parts_sized(1, &bytes, 8);
        assert!(
            parts.len() >= 3,
            "{} parts of {} bytes",
            parts.len(),
            bytes.len()
        );
        let mut c = ClientScreen::new();
        for p in parts[1..].iter().rev() {
            assert_eq!(c.on_datagram_part(p), ScreenOutcome::Partial);
            // A duplicate of a part changes nothing.
            assert_eq!(c.on_datagram_part(p), ScreenOutcome::Partial);
        }
        assert!(c.state().is_none(), "one part short, nothing applied");
        let last = c.on_datagram_part(&parts[0]);
        assert_eq!(last.ack(), Some(1));
        assert_eq!(c.hash(), Some(a.hash()));
    }

    #[test]
    fn a_datagram_update_diffs_from_any_retained_state() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let (a, b, d) = (state_with("a"), state_with("b"), state_with("d"));
        let mut c = ClientScreen::new();
        c.apply(&update(&blank, 0, &a, 1));
        c.apply(&update(&a, 1, &b, 2));
        // The host never saw the ack of state 2 and still diffs from 1.
        let out = c.apply_datagram_for_test(&update(&a, 1, &d, 3));
        assert_eq!(out.ack(), Some(3));
        assert_eq!(c.hash(), Some(d.hash()));
    }

    #[test]
    fn a_datagram_whose_base_is_gone_reacks_instead_of_resyncing() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let a = state_with("a");
        let b = state_with("b");
        let mut c = ClientScreen::new();
        c.apply(&update(&blank, 0, &a, 1));
        let out = c.apply_datagram_for_test(&update(&b, 9, &a, 10));
        assert_eq!(out, ScreenOutcome::Stale { held: 1 });
        assert_eq!(out.ack(), Some(1), "the host is told what we hold");
        assert_eq!(c.resyncs(), 0);
        assert_eq!(c.num(), 1);
    }

    #[test]
    fn an_update_that_crossed_a_newer_one_is_dropped_and_the_held_state_reacked() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let (a, b, d) = (state_with("a"), state_with("b"), state_with("d"));
        let mut c = ClientScreen::new();
        c.apply(&update(&blank, 0, &a, 1));
        c.apply(&update(&a, 1, &d, 3));
        let out = c.apply(&update(&a, 1, &b, 2));
        assert_eq!(out, ScreenOutcome::Stale { held: 3 });
        assert_eq!(c.hash(), Some(d.hash()), "the screen did not go backwards");
        // The same state as a full screen is applied again: it is what a
        // client that asked for one is owed.
        let full = c.apply(&update(&blank, 0, &d, 3));
        assert_eq!(full.ack(), Some(3));
    }

    #[test]
    fn only_eight_states_are_kept_as_bases() {
        let blank = ScreenState::blank(2, 4).unwrap();
        let mut c = ClientScreen::new();
        let mut prev = blank.clone();
        let mut prev_num = 0;
        for n in 1..=(RETAINED_STATES as u64 + 2) {
            let next = state_with(&format!("{}", n % 10));
            assert!(c.apply(&update(&prev, prev_num, &next, n)).ack().is_some());
            prev = next;
            prev_num = n;
        }
        let newest = prev_num + 1;
        let target = state_with("z");
        // State 1 fell out of the window; 3 is still in it.
        assert!(matches!(
            c.apply_datagram_for_test(&update(&state_with("1"), 1, &target, newest)),
            ScreenOutcome::Stale { .. }
        ));
        assert!(matches!(
            c.apply_datagram_for_test(&update(&state_with("3"), 3, &target, newest)),
            ScreenOutcome::Applied { .. }
        ));
    }
}
