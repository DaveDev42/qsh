//! Length-prefixed framing: `u32` big-endian length + payload.
//!
//! This is the framing used on every QSH byte stream (control stream and
//! per-attach/exec/tunnel streams alike, see the architecture note in
//! `docs/adr/`). It is deliberately tiny and allocation-disciplined: the
//! declared length is checked against a hard cap *before* any buffer sized
//! by that length is allocated, so a peer cannot make us allocate gigabytes
//! by lying in a 4-byte header.

use thiserror::Error;

/// Maximum payload size for a control-stream frame (256 KiB).
pub const CONTROL_FRAME_MAX: usize = 256 * 1024;

/// Maximum payload size for a data/tunnel-stream frame (64 KiB).
pub const DATA_FRAME_MAX: usize = 64 * 1024;

/// Length of the frame header: one big-endian `u32`.
const HEADER_LEN: usize = 4;

/// Errors produced while encoding or decoding frames.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    /// The declared frame length exceeds the decoder's configured cap.
    /// Produced *before* any payload-sized buffer is allocated.
    #[error("frame length {len} exceeds max {max}")]
    Oversize {
        /// The length the peer declared, as read off the wire.
        len: u32,
        /// The cap this decoder enforces.
        max: usize,
    },
    /// A payload was too large to represent in the `u32` length prefix.
    #[error("payload length does not fit in a u32 frame length")]
    PayloadTooLarge,
}

/// Encode `payload` as a single length-prefixed frame: 4-byte big-endian
/// length followed by the payload bytes.
///
/// Returns [`FrameError::PayloadTooLarge`] if `payload.len()` does not fit
/// in a `u32`. Callers are expected to additionally respect
/// [`CONTROL_FRAME_MAX`]/[`DATA_FRAME_MAX`] for the stream they're writing;
/// this function does not itself enforce those caps so it can be reused for
/// both.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| FrameError::PayloadTooLarge)?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Incremental frame decoder over a byte stream that may arrive in
/// arbitrarily small chunks.
///
/// Usage: [`push`](FrameDecoder::push) bytes as they arrive, then call
/// [`next_frame`](FrameDecoder::next_frame) in a loop until it returns
/// `Ok(None)` (need more bytes) to drain every complete frame currently
/// buffered.
pub struct FrameDecoder {
    buf: Vec<u8>,
    max_frame_len: usize,
}

impl FrameDecoder {
    /// Create a decoder that rejects any frame whose declared length
    /// exceeds `max_frame_len` (use [`CONTROL_FRAME_MAX`] or
    /// [`DATA_FRAME_MAX`]).
    pub fn new(max_frame_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_frame_len,
        }
    }

    /// Feed newly-received bytes into the decoder. Does not itself attempt
    /// to decode; call [`next_frame`](Self::next_frame) afterwards.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Number of bytes buffered but not yet returned as a frame. Non-zero
    /// at end-of-stream means the peer truncated a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Drain and return whatever bytes are currently buffered but not yet
    /// resolved into a complete frame, leaving the decoder empty.
    ///
    /// Exists for the one place a QSH byte stream deliberately switches
    /// from this length-prefixed framing to raw byte-level use partway
    /// through: localctl's `LOCAL_STREAM` conduit reads exactly one
    /// [`wire::StreamHeader`]-shaped frame and then becomes a raw QUIC
    /// splice (`docs/design/protocol.md` §11-3) — a single `read()` off
    /// the socket routinely returns more bytes than just that header
    /// frame, and this hands back whatever of the next frame it already
    /// swallowed so the caller can feed it into the splice instead of
    /// silently dropping it.
    ///
    /// [`wire::StreamHeader`]: crate::wire::StreamHeader
    pub fn take_remaining(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Try to decode one complete frame from the buffered bytes.
    ///
    /// - `Ok(None)`: not enough bytes buffered yet for a full frame.
    /// - `Ok(Some(payload))`: one frame was decoded and removed from the
    ///   internal buffer.
    /// - `Err(_)`: the declared length exceeds this decoder's cap. This is
    ///   detected from the 4-byte header alone, before any payload-sized
    ///   buffer is allocated. Once returned, the stream should be treated
    ///   as unrecoverable (the caller should close the connection) since
    ///   framing sync cannot be trusted past an oversize header.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let len_bytes = [self.buf[0], self.buf[1], self.buf[2], self.buf[3]];
        let len = u32::from_be_bytes(len_bytes);
        let len_usize = len as usize;
        if len_usize > self.max_frame_len {
            return Err(FrameError::Oversize {
                len,
                max: self.max_frame_len,
            });
        }

        let total = HEADER_LEN + len_usize;
        if self.buf.len() < total {
            return Ok(None);
        }

        let payload = self.buf[HEADER_LEN..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encode_decode() {
        let payload = b"hello qsh".to_vec();
        let wire = encode_frame(&payload).unwrap();

        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        assert_eq!(dec.next_frame().unwrap(), Some(payload));
        assert_eq!(dec.next_frame().unwrap(), None);
    }

    #[test]
    fn split_across_feeds() {
        let wire = encode_frame(b"split me").unwrap();
        let (first, second) = wire.split_at(wire.len() / 2);

        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(first);
        assert_eq!(dec.next_frame().unwrap(), None, "partial frame must wait");

        dec.push(second);
        assert_eq!(dec.next_frame().unwrap(), Some(b"split me".to_vec()));
    }

    #[test]
    fn one_byte_feeds() {
        let wire = encode_frame(b"trickle").unwrap();
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);

        for (i, byte) in wire.iter().enumerate() {
            dec.push(std::slice::from_ref(byte));
            let is_last = i + 1 == wire.len();
            let result = dec.next_frame().unwrap();
            if is_last {
                assert_eq!(result, Some(b"trickle".to_vec()));
            } else {
                assert_eq!(result, None, "should not decode before last byte");
            }
        }
    }

    #[test]
    fn take_remaining_drains_bytes_past_the_last_complete_frame() {
        let mut wire = encode_frame(b"header").unwrap();
        wire.extend_from_slice(b"leftover raw bytes");

        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        assert_eq!(dec.next_frame().unwrap(), Some(b"header".to_vec()));

        let remaining = dec.take_remaining();
        assert_eq!(remaining, b"leftover raw bytes".to_vec());
        // Draining leaves nothing behind for a later frame to
        // half-assemble from.
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn take_remaining_on_an_empty_decoder_is_an_empty_vec() {
        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        assert_eq!(dec.take_remaining(), Vec::<u8>::new());
    }

    #[test]
    fn oversize_rejected_without_allocation() {
        let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
        // Only the 4-byte header is ever pushed: if the decoder tried to
        // allocate a buffer sized by the (huge) declared length before
        // checking the cap, this would OOM instead of erroring.
        let huge_len: u32 = u32::MAX;
        dec.push(&huge_len.to_be_bytes());

        let err = dec.next_frame().unwrap_err();
        assert_eq!(
            err,
            FrameError::Oversize {
                len: huge_len,
                max: DATA_FRAME_MAX,
            }
        );
    }

    #[test]
    fn oversize_just_above_cap_is_rejected() {
        let mut dec = FrameDecoder::new(DATA_FRAME_MAX);
        let len = (DATA_FRAME_MAX + 1) as u32;
        dec.push(&len.to_be_bytes());
        assert!(dec.next_frame().is_err());
    }

    #[test]
    fn empty_frame_roundtrips() {
        let wire = encode_frame(b"").unwrap();
        assert_eq!(wire, vec![0, 0, 0, 0]);

        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        assert_eq!(dec.next_frame().unwrap(), Some(Vec::new()));
    }

    #[test]
    fn multiple_frames_in_one_push() {
        let mut wire = encode_frame(b"one").unwrap();
        wire.extend(encode_frame(b"two").unwrap());

        let mut dec = FrameDecoder::new(CONTROL_FRAME_MAX);
        dec.push(&wire);
        assert_eq!(dec.next_frame().unwrap(), Some(b"one".to_vec()));
        assert_eq!(dec.next_frame().unwrap(), Some(b"two".to_vec()));
        assert_eq!(dec.next_frame().unwrap(), None);
    }
}
