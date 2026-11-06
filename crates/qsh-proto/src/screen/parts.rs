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
}
