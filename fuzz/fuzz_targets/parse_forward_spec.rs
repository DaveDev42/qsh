//! Fuzzes `wire::parse_forward_spec` — the `-L`/`-R` forward-spec grammar
//! parser (`[bind:]listen_port:host:host_port`), including IPv6-bracket
//! tokenizing, port-range checks, and ASCII host-charset validation.
//! Local-CLI-origin rather than peer/network-origin text, but it lives in
//! qsh-proto's sans-IO parser surface next to the other wire-contract
//! parsers, so it gets the same treatment.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::parse_forward_spec;

fuzz_target!(|spec: String| {
    let _ = parse_forward_spec(&spec);
});
