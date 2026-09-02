//! Fuzzes `decode_msg::<ConnectResult>` — the reply a `-L` local-forward
//! dial reads back off a fresh `TCP_CONNECT` QUIC stream from whatever host
//! the client dialed (`crates/qsh-core/src/tunnel/local.rs`,
//! `forward_connection`), before any splice happens. Unlike the other
//! top-level `decode_msg::<T>` targets this one has no ticket/ACL gate in
//! front of it — `TCP_CONNECT` is the sole stream kind that carries no
//! ticket (§7), so this is reached straight off the wire.
//!
//! Chains what `forward_connection` does with the decoded value on the
//! `!result.ok` path: both `code` and `message` are peer-authored free text
//! fed to `sanitize_peer_text` before landing in `ForwardConnError::Refused`
//! and potentially a raw-mode terminal. `code` is never parsed through
//! `ErrorCode::from_str` on this path — it stays a display string — so this
//! target does not chain that.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{ConnectResult, decode_msg, sanitize_peer_text};

fuzz_target!(|data: &[u8]| {
    if let Ok(result) = decode_msg::<ConnectResult>(data) {
        let _ = sanitize_peer_text(&result.code);
        let _ = sanitize_peer_text(&result.message);
    }
});
