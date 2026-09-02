//! Fuzzes `decode_msg::<StreamHeader>` — the first message decoded on every
//! newly-opened QUIC stream (kind, ticket, host, port), before the stream
//! is even dispatched to a handler; an earlier attack surface than
//! SessionFrame/ExecFrame. Chains `StreamHeader::stream_kind()`, which
//! converts the peer-supplied `kind: i32` (arbitrary — prost keeps unknown
//! enum values in the raw i32) through `StreamKind::try_from`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{StreamHeader, decode_msg};

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = decode_msg::<StreamHeader>(data) {
        let _ = header.stream_kind();
    }
});
