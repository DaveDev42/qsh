//! Fuzzes `decode_msg::<FileFrame>` — every frame on a FILE_DATA stream
//! (`data`/`end`/`result` oneof, ADR-0029 decision 9), a data-stream path
//! independent of `decode_control`/`ControlMessage` with its own frame cap
//! (`DATA_FRAME_MAX`), its own chunk cap (`FILE_CHUNK_MAX`) and its own
//! encode helper. The chunk check is chained after decode, as the FILE_DATA
//! pump will call it on every received frame.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{FileFrame, WireEncodeError, decode_msg, encode_file_frame};

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = decode_msg::<FileFrame>(data) else {
        return;
    };
    // A frame the receiver accepts must never be refused by the sender-side
    // chunk cap; only the whole-frame size can refuse it.
    if frame.validate().is_ok() {
        match encode_file_frame(&frame) {
            Ok(_) | Err(WireEncodeError::TooLarge { .. }) => {}
            Err(other) => panic!("a validated FileFrame failed to encode: {other:?}"),
        }
    } else {
        assert!(matches!(
            encode_file_frame(&frame),
            Err(WireEncodeError::ChunkTooLarge(_))
        ));
    }
});
