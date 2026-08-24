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
//! - [`reverse`]: in-process reverse-mode harness (L3) — a `qsh listen`
//!   controller plus the raw dial primitives to play a `qsh reverse`
//!   target's wire role, and [`reverse::ReversePairHarness`], the
//!   role-swapped counterpart of [`loopback::LoopbackHarness`] used to
//!   prove role-axis independence (`PLAN.md` M3 Step 3, PR 3b).
//! - [`pair`]: [`pair::HostedPair`], the trait that lets one scenario body
//!   run unmodified against both harnesses above.
//! - [`tunnel`]: in-process loopback **tunnel** harness (L3) — a
//!   [`loopback::LoopbackHarness`] host plus a client `-L` listener plus a
//!   local echo destination, so a forwarded byte's whole path is one
//!   process (`PLAN.md` M4 Step 3).
//!
//! This crate may depend on any workspace crate.

pub mod chaos;
pub mod fixtures;
pub mod loopback;
pub mod pair;
pub mod reverse;
pub mod tunnel;

pub use chaos::{ChaosPolicy, ChaosProxy, ChaosStats, DelayDist};
pub use loopback::{LoopbackHarness, TestIdentity, make_identity};
pub use pair::HostedPair;
pub use tunnel::{EchoServer, TunnelHarness};
