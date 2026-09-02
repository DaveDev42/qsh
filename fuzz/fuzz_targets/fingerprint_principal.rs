//! Fuzzes `qsh_transport::identity::{Fingerprint, Principal}::from_str`.
//!
//! `Fingerprint::from_str` (`sha256:<base64>`) is reached from an on-disk
//! file (`trust.toml` via `qsh-core`'s `parsed_pins()`) and from CLI/user
//! text via `Ops::trust_add`; it does manual byte-offset slicing on a
//! caller-controlled prefix match plus a base64-decode-then-length-check,
//! a decode/bounds-shaped target. `Principal::from_str`
//! (`device:<name>` | `user:<name>` | `fp:sha256:<base64>` | `pairing`) is
//! reached from `qsh acl check --principal` and composes
//! `Fingerprint::from_str` for its `fp:` branch — one target with a
//! selector byte covers both since they are the same crate's string
//! grammar family and `Principal` calls straight into `Fingerprint`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_transport::identity::{Fingerprint, Principal};
use std::str::FromStr;

fuzz_target!(|input: (bool, String)| {
    let (fingerprint_only, text) = input;
    if fingerprint_only {
        let _ = Fingerprint::from_str(&text);
    } else {
        let _ = Principal::from_str(&text);
    }
});
