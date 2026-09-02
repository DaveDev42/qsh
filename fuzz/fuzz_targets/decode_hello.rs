//! Fuzzes `decode_msg::<Hello>` directly. `Hello` is the very first message
//! decoded from a peer during the handshake, before any authentication of
//! the *application layer* is complete (identity is bound to the cert, but
//! this is still the earliest attacker-controlled parse in the protocol) —
//! narrower target than `decode_control` so libFuzzer's coverage-guided
//! mutation isn't diluted across the whole oneof.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{Hello, decode_msg};

fuzz_target!(|data: &[u8]| {
    let _ = decode_msg::<Hello>(data);
});
