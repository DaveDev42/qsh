//! Fuzzes `decode_msg::<SessionFrame>` — every frame on a SESSION_DATA
//! stream (Output/Input/InputAck/Gap/Resize/Exit oneof), which the module
//! docs say the SESSION_DATA pump calls on every decoded frame. Chains
//! `SessionFrame::validate()` right after decode, since a successful decode
//! with a hostile Output/Input chunk over `SESSION_CHUNK_MAX` is exactly
//! the case `validate` exists to catch (decode+validate together, not as
//! two separate stages, since a peer not running our encoder is bounded
//! only by the frame cap, not the chunk cap).

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{SessionFrame, decode_msg};

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = decode_msg::<SessionFrame>(data) {
        let _ = frame.validate();
    }
});
