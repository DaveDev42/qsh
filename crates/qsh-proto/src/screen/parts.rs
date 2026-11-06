//! Splitting an encoded [`super::ScreenUpdate`] into parts and putting the
//! parts back together (ADR-0052 decision 6, `docs/design/protocol.md` §18.4).
//!
//! The stream carrier delivers parts in order, so the reassembler is strict:
//! a part is accepted only if it is the next one of the update being built,
//! or part 0 of a newer update (which drops a half-built older one). The
//! total is bounded by [`super::MAX_UPDATE_BYTES`] before anything is
//! buffered beyond it.

use super::MAX_UPDATE_BYTES;

/// Largest payload of one part, bytes. Equal to the session chunk cap so a
/// part always fits a `SessionFrame` under `DATA_FRAME_MAX`.
pub const PART_MAX: usize = 16 * 1024;

/// Most parts one update may have: `MAX_UPDATE_BYTES / PART_MAX`.
pub const MAX_PARTS: u32 = (MAX_UPDATE_BYTES / PART_MAX) as u32;

/// Why a part is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PartError {
    /// `parts` is 0 or over [`MAX_PARTS`], or `part >= parts`.
    #[error("part numbering is out of range")]
    Numbering,
    /// A part is longer than [`PART_MAX`], or the parts add up past the
    /// update cap.
    #[error("part is too large")]
    TooLarge,
    /// The part does not continue the update being built: a middle part
    /// with nothing before it, a repeat, or a change of `parts`.
    #[error("part does not continue the update being built")]
    OutOfOrder,
}

/// Cut `encoded` into [`PART_MAX`]-sized slices. Always at least one slice,
/// so an (impossible) empty encoding still yields one empty part.
pub fn split(encoded: &[u8]) -> Vec<&[u8]> {
    if encoded.is_empty() {
        return vec![encoded];
    }
    encoded.chunks(PART_MAX).collect()
}

/// Rebuilds one update at a time from its in-order parts.
#[derive(Debug, Default)]
pub struct Reassembler {
    new_num: u64,
    parts: u32,
    next: u32,
    buf: Vec<u8>,
}

impl Reassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes buffered for an unfinished update.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Offer one part. `Ok(Some(bytes))` is a complete update, `Ok(None)`
    /// means more parts are needed. An error leaves the reassembler empty.
    pub fn push(
        &mut self,
        new_num: u64,
        part: u32,
        parts: u32,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, PartError> {
        let result = self.push_inner(new_num, part, parts, data);
        if result.is_err() {
            self.reset();
        }
        result
    }

    fn push_inner(
        &mut self,
        new_num: u64,
        part: u32,
        parts: u32,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, PartError> {
        if parts == 0 || parts > MAX_PARTS || part >= parts {
            return Err(PartError::Numbering);
        }
        if data.len() > PART_MAX {
            return Err(PartError::TooLarge);
        }
        if part == 0 {
            self.reset();
            self.new_num = new_num;
            self.parts = parts;
        } else if self.parts == 0
            || new_num != self.new_num
            || parts != self.parts
            || part != self.next
        {
            return Err(PartError::OutOfOrder);
        }
        if self.buf.len() + data.len() > MAX_UPDATE_BYTES {
            return Err(PartError::TooLarge);
        }
        self.buf.extend_from_slice(data);
        self.next = part + 1;
        if self.next == self.parts {
            let done = std::mem::take(&mut self.buf);
            self.reset();
            Ok(Some(done))
        } else {
            Ok(None)
        }
    }

    fn reset(&mut self) {
        self.new_num = 0;
        self.parts = 0;
        self.next = 0;
        self.buf.clear();
    }
}

/// Most parts a datagram update may have. A datagram part is about one
/// path MTU, so this bounds an update at roughly 76 KB; a bigger one goes
/// over the stream (ADR-0052 decision 6, `docs/design/protocol.md` §18.9).
pub const MAX_DATAGRAM_PARTS: u32 = 64;

/// Cut `encoded` into slices of at most `max_part` bytes (at least one).
pub fn split_sized(encoded: &[u8], max_part: usize) -> Vec<&[u8]> {
    if encoded.is_empty() {
        return vec![encoded];
    }
    encoded.chunks(max_part.max(1)).collect()
}

/// Rebuilds one datagram update from parts that may arrive in any order,
/// twice or not at all (ADR-0052 decision 6): the state with the highest
/// `new_num` seen wins, and an update completes only when every part of it
/// is present. Memory is bounded by [`MAX_UPDATE_BYTES`] and
/// [`MAX_DATAGRAM_PARTS`].
#[derive(Debug, Default)]
pub struct DatagramReassembler {
    new_num: u64,
    /// Highest state completed; older states are dropped. The same state is
    /// not: the host sends it again as a full screen when the client asks.
    done: u64,
    parts: u32,
    got: u32,
    slots: Vec<Option<Vec<u8>>>,
    bytes: usize,
}

impl DatagramReassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes buffered for an unfinished update.
    pub fn buffered(&self) -> usize {
        self.bytes
    }

    /// Offer one part. `Ok(Some(bytes))` is a complete update. A part of a
    /// state older than the one being built is dropped (`Ok(None)`); a newer
    /// state replaces the half-built one.
    pub fn push(
        &mut self,
        new_num: u64,
        part: u32,
        parts: u32,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, PartError> {
        if parts == 0 || parts > MAX_DATAGRAM_PARTS || part >= parts {
            return Err(PartError::Numbering);
        }
        if data.len() > PART_MAX {
            return Err(PartError::TooLarge);
        }
        if new_num < self.done || (self.parts != 0 && new_num < self.new_num) {
            return Ok(None);
        }
        if self.parts == 0 || new_num > self.new_num {
            self.reset();
            self.new_num = new_num;
            self.parts = parts;
            self.slots = vec![None; parts as usize];
        } else if parts != self.parts {
            self.reset();
            return Err(PartError::OutOfOrder);
        }
        let slot = &mut self.slots[part as usize];
        if slot.is_some() {
            return Ok(None);
        }
        if self.bytes + data.len() > MAX_UPDATE_BYTES {
            self.reset();
            return Err(PartError::TooLarge);
        }
        self.bytes += data.len();
        *slot = Some(data.to_vec());
        self.got += 1;
        if self.got == self.parts {
            let done: Vec<u8> = self.slots.drain(..).flatten().flatten().collect();
            self.reset();
            self.done = new_num;
            Ok(Some(done))
        } else {
            Ok(None)
        }
    }

    fn reset(&mut self) {
        self.parts = 0;
        self.got = 0;
        self.slots.clear();
        self.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_then_push_gives_the_bytes_back() {
        let data: Vec<u8> = (0..PART_MAX * 2 + 5).map(|i| (i % 253) as u8).collect();
        let slices = split(&data);
        assert_eq!(slices.len(), 3);
        let mut r = Reassembler::new();
        let mut out = None;
        for (i, s) in slices.iter().enumerate() {
            out = r.push(7, i as u32, 3, s).unwrap();
        }
        assert_eq!(out.unwrap(), data);
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn disorder_and_bad_numbering_are_refused() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(1, 0, 0, &[]), Err(PartError::Numbering));
        assert_eq!(r.push(1, 2, 2, &[]), Err(PartError::Numbering));
        assert_eq!(r.push(1, 1, 2, &[1]), Err(PartError::OutOfOrder));
        assert_eq!(r.push(1, 0, 3, &[1]), Ok(None));
        assert_eq!(r.push(1, 2, 3, &[1]), Err(PartError::OutOfOrder));
        assert_eq!(
            r.push(1, 0, 2, &vec![0; PART_MAX + 1]),
            Err(PartError::TooLarge)
        );
    }

    #[test]
    fn a_newer_update_replaces_a_half_built_one() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(1, 0, 2, &[1]), Ok(None));
        assert_eq!(r.push(2, 0, 1, &[9]), Ok(Some(vec![9])));
    }

    #[test]
    fn datagram_parts_complete_in_any_order_and_survive_duplicates() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let slices = split_sized(&data, 1000);
        assert_eq!(slices.len(), 3);
        let mut r = DatagramReassembler::new();
        assert_eq!(r.push(4, 2, 3, slices[2]), Ok(None));
        assert_eq!(r.push(4, 0, 3, slices[0]), Ok(None));
        assert_eq!(r.push(4, 0, 3, slices[0]), Ok(None));
        assert_eq!(r.push(4, 1, 3, slices[1]), Ok(Some(data)));
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn a_newer_datagram_state_drops_the_older_one_and_late_parts() {
        let mut r = DatagramReassembler::new();
        assert_eq!(r.push(1, 0, 2, &[1]), Ok(None));
        assert_eq!(r.push(2, 0, 2, &[2]), Ok(None));
        // A late part of state 1 changes nothing.
        assert_eq!(r.push(1, 1, 2, &[1]), Ok(None));
        assert_eq!(r.push(2, 1, 2, &[3]), Ok(Some(vec![2, 3])));
        assert_eq!(
            r.push(1, 0, 1, &[9]),
            Ok(None),
            "an older state is not rebuilt"
        );
        assert_eq!(
            r.push(2, 0, 1, &[9]),
            Ok(Some(vec![9])),
            "the same state again is a full screen the client asked for"
        );
        assert_eq!(r.push(3, 0, 1, &[9]), Ok(Some(vec![9])));
    }

    #[test]
    fn datagram_part_numbering_is_bounded() {
        let mut r = DatagramReassembler::new();
        assert_eq!(r.push(1, 0, 0, &[]), Err(PartError::Numbering));
        assert_eq!(
            r.push(1, 0, MAX_DATAGRAM_PARTS + 1, &[]),
            Err(PartError::Numbering)
        );
        assert_eq!(r.push(1, 3, 3, &[]), Err(PartError::Numbering));
        assert_eq!(r.push(1, 0, 2, &[1]), Ok(None));
        assert_eq!(r.push(1, 1, 3, &[1]), Err(PartError::OutOfOrder));
    }
}
