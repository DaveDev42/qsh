//! Fuzzes `qsh_proto::frame::FrameDecoder` — the length-prefixed framing
//! every QSH byte stream runs attacker bytes through first.
//!
//! Models a peer that trickles bytes in arbitrary splits and a caller that
//! interleaves `push`/`next_frame`/`take_remaining` in arbitrary order and
//! arity (matching how `take_remaining` is used mid-stream on the localctl
//! conduit, `docs/design/protocol.md` §11-3). Invariants checked:
//! - never panics
//! - never allocates a payload-sized buffer before the cap check
//!   (implicit: an oversize length with no payload bytes following must
//!   return promptly, not hang/OOM)
//! - `buffered()` bookkeeping never goes negative/inconsistent
//! - bytes are conserved: nothing pushed is ever lost across a mix of
//!   `next_frame` drains and a final `take_remaining`

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::frame::{CONTROL_FRAME_MAX, DATA_FRAME_MAX, FrameDecoder};

#[derive(Debug, arbitrary::Arbitrary)]
enum Op<'a> {
    Push(&'a [u8]),
    NextFrame,
    TakeRemaining,
    Buffered,
}

#[derive(Debug, arbitrary::Arbitrary)]
struct Input<'a> {
    use_data_cap: bool,
    ops: Vec<Op<'a>>,
}

fuzz_target!(|input: Input| {
    let max = if input.use_data_cap {
        DATA_FRAME_MAX
    } else {
        CONTROL_FRAME_MAX
    };
    let mut dec = FrameDecoder::new(max);
    let mut pushed_total: u64 = 0;
    let mut drained_total: u64 = 0;

    for op in input.ops.iter().take(4096) {
        match op {
            Op::Push(bytes) => {
                pushed_total += bytes.len() as u64;
                dec.push(bytes);
            }
            Op::NextFrame => match dec.next_frame() {
                Ok(Some(payload)) => {
                    drained_total += 4 + payload.len() as u64;
                }
                Ok(None) => {}
                Err(_) => {
                    // Oversize header: framing is now unrecoverable per the
                    // doc contract. Stop driving this decoder further, same
                    // as a real caller closing the connection.
                    return;
                }
            },
            Op::TakeRemaining => {
                let remaining = dec.take_remaining();
                drained_total += remaining.len() as u64;
                assert_eq!(dec.buffered(), 0, "take_remaining must empty the buffer");
            }
            Op::Buffered => {
                let _ = dec.buffered();
            }
        }
    }

    // Whatever is left buffered plus what we've already accounted for must
    // equal what we pushed -- no silent byte loss or duplication.
    let leftover = dec.buffered() as u64;
    assert_eq!(
        drained_total + leftover,
        pushed_total,
        "byte accounting mismatch"
    );
});
