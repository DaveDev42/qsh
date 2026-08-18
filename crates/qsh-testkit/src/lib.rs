//! `qsh-testkit`: shared test harness helpers (`docs/design/testing.md`).
//!
//! - [`loopback`]: in-process loopback QUIC harness (L3) — a real
//!   `qsh_core::server::Server` behind a `Listener` on `127.0.0.1:0`, plus a
//!   `Dialer` whose identity the server pins. No subprocess, no sleeps.
//! - [`chaos`]: in-process UDP chaos proxy (L4) — a seeded fault injector
//!   the loopback harness can dial through, so loss, reordering, corruption,
//!   blackholes, NAT rebinding (`repath`) and path death (`sever`) are
//!   ordinary PR regression tests instead of a manual campaign.
//! - [`fixtures`]: golden-fixture loader for `crates/qsh-cli/tests/fixtures`
//!   (L6).
//!
//! This crate may depend on any workspace crate.

pub mod chaos;
pub mod fixtures;
pub mod loopback;

pub use chaos::{ChaosPolicy, ChaosProxy, ChaosStats, DelayDist};
pub use loopback::{LoopbackHarness, TestIdentity, make_identity};
