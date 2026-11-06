//! Client side of screen state sync (ADR-0052 decisions 5, 6 and 11,
//! `docs/design/protocol.md` §18): the screen the host described.
//!
//! [`ClientScreen`] takes the `ScreenUpdate` parts a data stream delivers,
//! puts them together, applies the update to the screen it holds and checks
//! the result against the update's `state_hash`. It decides what to tell the
//! host: the state number it now holds, or 0 to ask for the full screen when
//! it cannot continue (hash mismatch, a base it does not have, an update it
//! cannot apply). It does no I/O; the caller sends the acknowledgement
//! ([`ScreenOutcome::ack`]) with [`super::Attached::send_screen_ack`] and
//! draws [`ClientScreen::state`] however it likes. The real `qsh` renderer
//! is a later step.

use qsh_proto::screen::{Effect, Reassembler, ScreenState, ScreenUpdate};
use qsh_proto::wire;

use super::ClientError;

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
}

impl ScreenOutcome {
    /// The `ScreenAck.state_num` to send for this outcome, if any: the new
    /// state after an applied update, 0 after a resync.
    pub fn ack(&self) -> Option<u64> {
        match self {
            ScreenOutcome::Applied { new_num, .. } => Some(*new_num),
            ScreenOutcome::Resync(_) => Some(0),
            ScreenOutcome::Partial | ScreenOutcome::Ignored => None,
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

/// The screen a screen-sync attach has built so far.
#[derive(Debug, Default)]
pub struct ClientScreen {
    state: Option<ScreenState>,
    num: u64,
    output_seq: u64,
    parts: Reassembler,
    awaiting_full: bool,
    applied: u64,
    resyncs: u64,
}

impl ClientScreen {
    /// An empty client screen: it holds no state, so the first update the
    /// host sends (base 0) builds it.
    pub fn new() -> Self {
        Self::default()
    }

    /// The screen, once the first update has been applied.
    pub fn state(&self) -> Option<&ScreenState> {
        self.state.as_ref()
    }

    /// The `state_num` of the screen held; 0 before the first update.
    pub fn num(&self) -> u64 {
        self.num
    }

    /// Output offset the screen held reflects.
    pub fn output_seq(&self) -> u64 {
        self.output_seq
    }

    /// `state_hash` of the screen held.
    pub fn hash(&self) -> Option<[u8; qsh_proto::screen::HASH_LEN]> {
        self.state.as_ref().map(ScreenState::hash)
    }

    /// Updates applied so far.
    pub fn applied_updates(&self) -> u64 {
        self.applied
    }

    /// Full-screen requests made so far.
    pub fn resyncs(&self) -> u64 {
        self.resyncs
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

    /// Apply a whole decoded update.
    pub fn apply(&mut self, update: &ScreenUpdate) -> ScreenOutcome {
        if self.awaiting_full && update.base_num != 0 {
            return ScreenOutcome::Ignored;
        }
        if update.base_num != 0 && update.base_num != self.num {
            return self.resync(ResyncReason::BaseMismatch);
        }
        let base = if update.base_num == 0 {
            match ScreenState::blank(update.diff.rows, update.diff.cols) {
                Ok(blank) => blank,
                Err(_) => return self.resync(ResyncReason::BadDiff),
            }
        } else {
            match &self.state {
                Some(state) => state.clone(),
                None => return self.resync(ResyncReason::BaseMismatch),
            }
        };
        match update.apply(&base) {
            Ok(state) => {
                self.state = Some(state);
                self.num = update.new_num;
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
        self.state = None;
        self.num = 0;
        self.awaiting_full = true;
        self.resyncs += 1;
        ScreenOutcome::Resync(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_proto::screen::{Cell, ScreenDiff};

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
}
