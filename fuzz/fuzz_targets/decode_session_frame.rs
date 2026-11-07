//! Fuzzes `decode_msg::<SessionFrame>` — every frame on a SESSION_DATA
//! stream (Output/Input/InputAck/Gap/Resize/Exit/ScreenUpdate/ScreenAck/ScreenHistory/ScreenEcho oneof), which the module
//! docs say the SESSION_DATA pump calls on every decoded frame. Chains
//! `SessionFrame::validate()` right after decode, since a successful decode
//! with a hostile Output/Input chunk over `SESSION_CHUNK_MAX` is exactly
//! the case `validate` exists to catch (decode+validate together, not as
//! two separate stages, since a peer not running our encoder is bounded
//! only by the frame cap, not the chunk cap).

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{SessionFrame, decode_msg, session_frame};

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = decode_msg::<SessionFrame>(data) {
        let _ = frame.validate();
        // ADR-0053: `ScreenEcho` reads its tty value and checks its offset
        // against any bound without panicking.
        if let Some(session_frame::Body::ScreenEcho(echo)) = &frame.body {
            let _ = echo.tty_echo();
            let _ = echo.validate_against_sent(0);
            let _ = echo.validate_against_sent(u64::MAX);
        }
    }
});
