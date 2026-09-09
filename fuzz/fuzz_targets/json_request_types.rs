//! Fuzzes `serde_json::from_slice` into `qsh_proto::types::*Req` — the
//! request types an agent hands in as the `--json` argument payload on
//! `qsh`'s JSON CLI surface (ADR-0011: agent integration is JSON CLI and
//! exec stdio, not a built-in MCP adapter). CLAUDE.md names the JSON
//! contract types (`qsh-proto`) as fuzz surface; this is the
//! untrusted-JSON-in edge of that surface.
//!
//! Covers 12 of the request types in `qsh_proto::types`: `HostListReq`,
//! `HostGetReq`, `SessionListReq`, `SessionGetReq`, `SessionOpenReq`,
//! `SessionReadReq`, `SessionWriteReq`, `SessionResizeReq`,
//! `SessionCloseReq`, `ExecRunReq`, `TunnelOpenReq`, `TunnelCloseReq`.
//! (`SessionAttachReq` also exists in `qsh-proto::types` but is not
//! selected here — nothing in this list routes through it.)
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
