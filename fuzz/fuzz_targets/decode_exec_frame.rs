//! Fuzzes `decode_msg::<ExecFrame>` — every frame on an EXEC_DATA stream
//! (Stdout/Stderr/Stdin/StdinEof/ExecExit oneof), a data-stream path
//! independent of `decode_control`/`ControlMessage` with its own frame cap
//! (`DATA_FRAME_MAX`) and its own encode/decode helpers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{ExecFrame, decode_msg};

fuzz_target!(|data: &[u8]| {
    let _ = decode_msg::<ExecFrame>(data);
});
