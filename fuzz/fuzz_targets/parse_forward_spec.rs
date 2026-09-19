//! Fuzzes `wire::parse_forward_spec` and `wire::parse_dynamic_spec` — the
//! `-L`/`-R`/`-D` forward-spec grammar parsers (`[bind:]listen_port:host:host_port`
//! and `[bind:]listen_port` respectively), including IPv6-bracket
//! tokenizing, port-range checks, and ASCII host-charset validation. Both
//! share the same `tokenize_forward_spec` tokenizer (ADR-0019 decision 11),
//! so the same input is fed to both parsers here rather than splitting into
//! a second fuzz target. Local-CLI-origin rather than peer/network-origin
//! text, but it lives in qsh-proto's sans-IO parser surface next to the
//! other wire-contract parsers, so it gets the same treatment.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::{parse_dynamic_spec, parse_forward_spec};

fuzz_target!(|spec: String| {
    let _ = parse_forward_spec(&spec);
    let _ = parse_dynamic_spec(&spec);
});
