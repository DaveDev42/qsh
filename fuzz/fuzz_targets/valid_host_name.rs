//! Fuzzes `wire::valid_host_name` — the shape check on a peer-offered
//! reverse-target name (`Hello.reverse.offered_name`) run *before* it can
//! become an ACL resource or audit field. Coverage-guided mutation off a
//! valid-charset corpus should find boundary bugs around the 64-byte cap
//! interacting with multi-byte UTF-8 (`.len()` in bytes vs. displayed
//! width diverging) that a byte-count-only regex seed corpus wouldn't
//! surface on its own.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::valid_host_name;

fuzz_target!(|name: String| {
    let _ = valid_host_name(&name);
});
