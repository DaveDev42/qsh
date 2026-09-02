//! Fuzzes `serde_json::from_value`/`from_slice` into every `qsh_proto`
//! request type the MCP adapter deserializes an external client's tool-call
//! `arguments` into (`crates/qsh-cli/src/mcp/mod.rs`, `run_tool`'s
//! `serde_json::from_value(Value::Object(arguments))`, one call site shared
//! by every tool). CLAUDE.md names the JSON contract types (`qsh-proto`) as
//! fuzz surface; this is the untrusted-JSON-in edge of that surface — MCP
//! `arguments` come straight from whatever client is talking to `qsh mcp`
//! over stdio, no ACL gate in front of the deserialize itself.
//!
//! Covers exactly the request types `run_tool` is invoked with in
//! `mcp/mod.rs` as of this writing (verified against the call sites, not
//! the tool list): `HostListReq`, `HostGetReq`, `SessionListReq`,
//! `SessionGetReq`, `SessionOpenReq`, `SessionReadReq`, `SessionWriteReq`,
//! `SessionResizeReq`, `SessionCloseReq`, `ExecRunReq`, `TunnelOpenReq`,
//! `TunnelCloseReq`. (`SessionAttachReq` exists in `qsh-proto::types` but
//! `mcp/mod.rs` does not currently route any tool through it — nothing to
//! select here until it does.)
//!
//! First byte of the input selects the type (mod the list length, same
//! selector-byte shape `fingerprint_principal` uses for its own two-way
//! split); the rest is handed to `serde_json::from_slice` unmodified so the
//! corpus can carry real JSON bytes with a one-byte prefix.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::types::{
    ExecRunReq, HostGetReq, HostListReq, SessionCloseReq, SessionGetReq, SessionListReq,
    SessionOpenReq, SessionReadReq, SessionResizeReq, SessionWriteReq, TunnelCloseReq,
    TunnelOpenReq,
};

const VARIANT_COUNT: u8 = 12;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % VARIANT_COUNT {
        0 => {
            let _ = serde_json::from_slice::<HostListReq>(rest);
        }
        1 => {
            let _ = serde_json::from_slice::<HostGetReq>(rest);
        }
        2 => {
            let _ = serde_json::from_slice::<SessionListReq>(rest);
        }
        3 => {
            let _ = serde_json::from_slice::<SessionGetReq>(rest);
        }
        4 => {
            let _ = serde_json::from_slice::<SessionOpenReq>(rest);
        }
        5 => {
            let _ = serde_json::from_slice::<SessionReadReq>(rest);
        }
        6 => {
            let _ = serde_json::from_slice::<SessionWriteReq>(rest);
        }
        7 => {
            let _ = serde_json::from_slice::<SessionResizeReq>(rest);
        }
        8 => {
            let _ = serde_json::from_slice::<SessionCloseReq>(rest);
        }
        9 => {
            let _ = serde_json::from_slice::<ExecRunReq>(rest);
        }
        10 => {
            let _ = serde_json::from_slice::<TunnelOpenReq>(rest);
        }
        11 => {
            let _ = serde_json::from_slice::<TunnelCloseReq>(rest);
        }
        _ => unreachable!("selector % VARIANT_COUNT is < VARIANT_COUNT"),
    }
});
