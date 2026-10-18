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
//!   prove role-axis independence (M3 plan Step 3 (2473c88), PR 3b).
//! - [`pair`]: [`pair::HostedPair`], the trait that lets one scenario body
//!   run unmodified against both harnesses above.
//! - [`tunnel`]: in-process loopback **tunnel** harness (L3) — a
//!   [`loopback::LoopbackHarness`] host plus a client `-L` listener plus a
//!   local echo destination, so a forwarded byte's whole path is one
//!   process (M4 plan Step 3 (2473c88)).
//! - [`procstat`]: `/proc`-based RSS/fd readers and the poll-until-stable
//!   convergence helper T2's `adversarial_load.rs` and M8 Step 5's
//!   `soak.rs` both need (docs/campaigns/m8-soak.md §4, moved from
//!   `crates/qsh-cli/tests/it/common/mod.rs`).
//! - [`env_check`]: one-shot loopback-UDP self-check the QUIC harness
//!   constructors run first, so a host firewall that drops loopback UDP
//!   fails with one clear message instead of 10 s timeouts.
//! - [`net_probe`]: non-loopback IPv4 route/hairpin discovery plus the
//!   CI-aware skip-or-fail [`net_probe::Gap`] policy, shared by any suite
//!   that needs a real off-loopback destination (`-D`'s
//!   `crates/qsh-testkit/tests/it/dynamic_loopback.rs` and its reverse-route
//!   twin).
//!
//! - [`echo_host`]: [`echo_host::EchoHost`], a host whose sessions are the
//!   broker's headless echo, reachable forward or as a reverse target, for
//!   driving the real client where the host has no PTY.
//! - [`fake_ssh`]: [`fake_ssh::FakeSsh`], a private directory holding a copy
//!   of the `qsh-fake-ssh` executable this crate builds, which records its
//!   argv and plays the system `ssh` of the SSH bootstrap tests (ADR-0044)
//!   with no sshd and no OpenSSH configuration.
//! - [`shell`]: the interactive shell and the stdin-copying program a
//!   platform-neutral test runs on the host it drives.
//! - [`testbin`]: finds a helper executable this crate builds
//!   (`qsh-fake-ssh`, `qsh-console-probe`) from a test.
//!
//! - [`signal_probe`]: the constants and lookup for `qsh-signal-probe`, a
//!   Windows console program that reports which event a session signal
//!   turned into through its exit code (ADR-0035 decision 22).
//!
//! - `freeze` (Windows only): suspends every thread of a process, the
//!   counterpart of `SIGSTOP`, so a test can make a peer go silent without
//!   ending it.
//! - `conpty` (Windows only): a ConPTY harness that runs a program in a
//!   pseudo-console and reads what it printed.
//!
//! `src/bin/qsh-console-probe/` is the Windows console probe the ConPTY
//! harness runs; it drives `qsh-cli`'s console layer
//! (`docs/design/testing.md`).
//!
//! This crate may depend on any workspace crate.

pub mod chaos;
#[cfg(windows)]
pub mod conpty;
pub mod echo_host;
pub mod env_check;
pub mod fake_ssh;
pub mod fixtures;
#[cfg(windows)]
pub mod freeze;
pub mod loopback;
pub mod net_probe;
pub mod pair;
pub mod pairing;
pub mod perf;
pub mod procstat;
pub mod raw_quic;
pub mod reverse;
pub mod shell;
pub mod signal_probe;
pub mod testbin;
pub mod tunnel;

pub use chaos::{ChaosPolicy, ChaosProxy, ChaosStats, DelayDist};
pub use loopback::{LoopbackHarness, TestIdentity, make_identity};
pub use pair::HostedPair;
pub use pairing::PairingHarness;
pub use tunnel::{EchoServer, TunnelHarness};
