//! Fuzzes `qsh_proto::openssh` — the hand-written OpenSSH key parsers behind
//! `qsh init --import-ssh-key` and the `authorized_keys` trust preview
//! (ADR-0026). Local-file input like `parse_forward_spec`, included in
//! qsh-proto's sans-IO parser surface for the same reason (ADR-0001,
//! `docs/design/protocol.md` §13).
//!
//! The first byte picks the layer, so one corpus covers all three:
//!
//! - `0`: `decode_pem_envelope` (armor strip + base64);
//! - `1`: `parse_openssh_key_body` (binary `openssh-key-v1`);
//! - `2`: `parse_authorized_keys` (line classifier).
//!
//! Invariants: no panic (libFuzzer treats any panic as a crash); every
//! accepted key's public wire blob is well formed; `parse_authorized_keys`
//! yields at most one entry per input line with strictly increasing 1-based
//! line numbers inside the input; an armored input the envelope accepts
//! never yields a body larger than the input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::openssh::{self, AuthorizedKeysEntry};

fuzz_target!(|data: &[u8]| {
    let Some((&layer, rest)) = data.split_first() else {
        return;
    };
    match layer % 3 {
        0 => {
            if let Ok(body) = openssh::decode_pem_envelope(rest) {
                assert!(body.len() <= rest.len());
                let _ = openssh::parse_openssh_key_body(&body);
            }
        }
        1 => {
            if let Ok(key) = openssh::parse_openssh_key_body(rest) {
                let blob = key.public_wire_blob();
                assert_eq!(&blob[blob.len() - 32..], key.public_key());
            }
        }
        _ => {
            let lines = openssh::parse_authorized_keys(rest);
            let max_line = rest.split(|b| *b == b'\n').count();
            let mut prev = 0;
            for l in &lines {
                assert!(l.line > prev && l.line <= max_line);
                prev = l.line;
                if let AuthorizedKeysEntry::OtherKeyType { key_type, .. } = l.entry {
                    assert!(!key_type.is_empty());
                }
            }
        }
    }
});
