//! Fuzzes `wire::sanitize_peer_text` — strips/replaces ANSI/OSC-hostile
//! control characters from any free-form peer-authored string the local
//! side will display (ConnectResult.code/message, and elsewhere any peer
//! prose shown on a terminal in raw mode). Feeds arbitrary UTF-8 (via
//! `arbitrary`'s `String` impl, which only ever yields valid UTF-8 -- the
//! type this function actually takes) and asserts:
//! - never panics
//! - no raw C0/C1 control byte survives in the output (the documented
//!   invariant of the function)

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::sanitize_peer_text;

fuzz_target!(|text: String| {
    let out = sanitize_peer_text(&text);
    for ch in out.chars() {
        assert!(
            !ch.is_control() || ch == '\t',
            "sanitize_peer_text left a control character {ch:?} in the output"
        );
    }
    assert_eq!(
        out.chars().count(),
        text.chars().count(),
        "sanitize_peer_text must replace, never drop or merge, characters"
    );
});
