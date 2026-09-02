//! Fuzzes `pairing::parse_invite_code` — decodes a hand-typed/pasted
//! Crockford Base32 invite code (case-fold, `-`-stripping, `i`/`l`/`o`
//! remap, `u` outright rejected) back into the raw pairing secret.
//! Reached from `Ops::trust_accept` (`qsh trust accept`) with
//! CLI/MCP-caller-controlled text, and has already been hardened once for
//! an unbounded-length DoS (its own comments reference this) -- a good
//! regression-fuzz target. `input.chars()` iterates full Unicode, not just
//! the Crockford alphabet, so this also transitively exercises the private
//! per-char `decode_symbol` predicate over the full `char` domain.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::pairing::parse_invite_code;

fuzz_target!(|input: String| {
    let _ = parse_invite_code(&input);
});
