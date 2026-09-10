//! Stateful fuzz target for the broker's core data structures — the
//! `ReplayRing`/`WriterLease`/`ResumeRegistry`/`TtlWindow` combination that
//! backs every attached session. Unlike the other 16 targets in this
//! directory (each a single decoder call on one input), this target
//! replays a *sequence* of ops against a model and asserts the broker's
//! real state matches the model's prediction after every op — the harness
//! doing the decoding, modeling, and assertion lives in
//! `crates/qsh-core/tests/support/broker_ops_harness.rs` and is included
//! here by path so the same file also runs as a plain nextest binary
//! (`crates/qsh-core/tests/broker_ops_corpus.rs`, seed replay) with no
//! divergence between what the fuzzer explores and what CI replays.
//!
//! Ops reach real production call sites, not synthetic shortcuts:
//! `DropConnection` drives `release_connection` the same order
//! `server/mod.rs:2321` uses on a dying QUIC connection; `Attach`/`Detach`
//! model the attach-token lifetime `session_stream.rs:167` takes out around
//! a live pump; `Reap` drives `sync_expiry` the way `broker/mod.rs:870`'s
//! reaper sweep does, then adds a `purge_expired` call production never
//! makes so credential expiry is judged on the spot. See the
//! harness's module doc for the op table, the model, and the full oracle
//! list (sequence/control-id, gap/byte-identity, memory bounds, lease
//! transitions, resume verify/rotate, TTL/reap).
//!
//! Deliberately out of scope: `signal.rs`'s control-byte parser is not
//! exercised here — `decode_control` (this directory) already fuzzes it in
//! isolation, and this harness's `AppendControl` op writes `CloseReason`/
//! writer-changed values directly into the ring rather than through that
//! wire decoder, so a wire-format regression there would not surface as a
//! `broker_ops` failure. The ACL default-deny axis is out of scope too —
//! that belongs to `acl/policy.rs`'s proptests, which reach a different
//! part of the broker than the ring/lease/resume/TTL state this target
//! covers.
#![no_main]

#[path = "../../crates/qsh-core/tests/support/broker_ops_harness.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
