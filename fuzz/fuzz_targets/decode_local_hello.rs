//! Fuzzes `local::decode_local::<LocalHello>` — the first message decoded
//! on the localctl conduit (a CLI process talking to the resident `qsh
//! listen` daemon over a Unix domain socket, `docs/design/protocol.md`
//! §11-3). Separate package (`qsh.local.v1`) from the wire (`qsh.wire.v1`)
//! grammar fuzzed by the `decode_*` targets above, sharing only the frame
//! layer -- worth its own target and corpus.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::local::{LocalHello, decode_local};

fuzz_target!(|data: &[u8]| {
    let _ = decode_local::<LocalHello>(data);
});
