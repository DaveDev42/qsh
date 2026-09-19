//! Fuzzes `qsh_proto::socks5::parse_greeting` and `::parse_request` — the
//! SOCKS5 sans-IO codec `-D` (dynamic port forwarding) drives against its
//! loopback listener (ADR-0019). Local-CLI-adjacent input (bytes a SOCKS5
//! client sends to that listener, not a `qsh`-to-`qsh` wire message —
//! `docs/design/protocol.md` §16.3 lists this codec outside the wire
//! freeze), included in qsh-proto's sans-IO parser surface for the same
//! reason `parse_forward_spec` is (that target's own doc comment,
//! `docs/design/protocol.md` §13).
//!
//! Invariants checked on every input, against both parsers independently:
//!
//! - no panic (guaranteed simply by running to completion — libFuzzer
//!   treats any panic as a crash);
//! - `consumed <= input.len()` on a successful parse;
//! - the property the module's whole "distinguish Incomplete from
//!   Invalid/Rejected" contract rests on: every strict prefix of a message
//!   that parses successfully is itself `Incomplete`, never
//!   `Invalid`/`Rejected` — checked by re-parsing every shorter prefix of
//!   the exact bytes a successful parse consumed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::socks5::{self, GreetingError, RequestError};

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = socks5::parse_greeting(data) {
        assert!(parsed.consumed <= data.len());
        for len in 0..parsed.consumed {
            assert_eq!(
                socks5::parse_greeting(&data[..len]),
                Err(GreetingError::Incomplete),
                "strict prefix (len {len}) of a valid greeting must be Incomplete"
            );
        }
    }

    if let Ok(parsed) = socks5::parse_request(data) {
        assert!(parsed.consumed <= data.len());
        for len in 0..parsed.consumed {
            assert_eq!(
                socks5::parse_request(&data[..len]),
                Err(RequestError::Incomplete),
                "strict prefix (len {len}) of a valid request must be Incomplete"
            );
        }
    }
});
