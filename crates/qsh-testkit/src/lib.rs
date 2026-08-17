//! `qsh-testkit`: shared test harness helpers (`docs/design/testing.md`).
//!
//! - [`loopback`]: in-process loopback QUIC harness (L3) — a real
//!   `qsh_core::server::Server` behind a `Listener` on `127.0.0.1:0`, plus a
//!   `Dialer` whose identity the server pins. No subprocess, no sleeps.
//! - [`fixtures`]: golden-fixture loader for `crates/qsh-cli/tests/fixtures`
//!   (L6).
//!
//! This crate may depend on any workspace crate. Chaos proxy (L4) lands in M2.

pub mod fixtures;
pub mod loopback;

pub use loopback::{LoopbackHarness, TestIdentity, make_identity};
