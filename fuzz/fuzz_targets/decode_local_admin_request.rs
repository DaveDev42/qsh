//! Fuzzes `local::decode_local::<LocalAdminRequest>` — the second frame of
//! a `LOCAL_ADMIN` conduit exchange (`LocalHostList` / `LocalTunnelList` /
//! `LocalTunnelClose` oneof envelope). Distinct grammar/entry point from
//! `LocalHello` (different point in the conduit's message sequence), so a
//! separate target rather than folded into `decode_local_hello`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::local::{LocalAdminRequest, decode_local};

fuzz_target!(|data: &[u8]| {
    let _ = decode_local::<LocalAdminRequest>(data);
});
