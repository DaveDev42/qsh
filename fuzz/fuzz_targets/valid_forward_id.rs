//! Fuzzes `wire::valid_forward_id` — the shape check on an opaque
//! host-issued token a peer echoes back
//! (`RemoteForwardOpened.forward_id`/`RemoteForwardClose.forward_id`/
//! `StreamHeader.ticket`) before it is re-trusted. Distinct alphabet and
//! length rule from `valid_host_name`, so a distinct target rather than
//! folded together.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::wire::valid_forward_id;

fuzz_target!(|id: String| {
    let _ = valid_forward_id(&id);
});
