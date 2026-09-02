//! Fuzzes `decode_msg::<ControlMessage>` — the top-level decode entry point
//! for the QSH control stream (crates/qsh-core/src/handshake.rs and
//! qsh-core/src/server/mod.rs feed peer bytes straight into this after
//! `FrameDecoder::next_frame` succeeds). `ControlMessage` is the root oneof
//! (Hello, SessionOpen/Attach/List/Get/Resize/Close/Read/Write, ExecStart,
//! RfwdOpen/Close, Ping/Pong, SessionEvent, PairingProof/Accepted,
//! Response{SessionOpened/Attached/..., Error}), so this one target
//! transitively covers the whole control-plane grammar.
//!
//! Chains the post-decode invariants the wire module documents as
//! receiver-side checks a host must run, since a peer not running our
//! encoder is bounded only by the frame cap:
//! - `SessionWrite::validate()` / `SessionReadResult::validate()` (the
//!   ChunkTooLarge choke point, `check_chunk`)
//! - `SessionAttach::attach_mode()` / `wants_write()` (arbitrary `mode: i32`
//!   through `AttachMode::try_from`)
//! - `Error::error_code()` (arbitrary `code: String` through
//!   `ErrorCode::from_str`, documented infallible)
//!
//! None of these may panic on any decoded value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{ControlMessage, Response, control_message, decode_msg, response};

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = decode_msg::<ControlMessage>(data) else {
        return;
    };

    match &msg.body {
        Some(control_message::Body::SessionWrite(w)) => {
            let _ = w.validate();
        }
        Some(control_message::Body::SessionAttach(a)) => {
            let _ = a.attach_mode();
            let _ = a.wants_write();
        }
        Some(control_message::Body::Response(Response { body })) => match body {
            Some(response::Body::SessionReadResult(r)) => {
                let _ = r.validate();
            }
            Some(response::Body::Error(e)) => {
                let _ = e.error_code();
            }
            _ => {}
        },
        _ => {}
    }
});
