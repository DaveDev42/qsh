//! `localctl` — the local-socket transport that agent forwarding binds its
//! per-session listener on: a Unix domain socket on unix, a named pipe on
//! Windows ([`transport`]; `docs/design/architecture.md` §7, ADR-0035
//! decision 14, ADR-0055).
//!
//! The module used to hold the IPC a CLI process spoke to its own resident
//! `qsh listen` daemon (`qsh.local.v1`). ADR-0068 retired the daemon, the
//! protocol and its client; only the transport stays, because agent
//! forwarding reuses its trust model:
//!
//! - unix: the socket node is mode 0600, and the accepting side rejects a
//!   peer whose euid is not its own (`SO_PEERCRED` on Linux, `getpeereid` on
//!   macOS) before it reads a byte;
//! - Windows: every pipe instance carries a protected, owner-only DACL,
//!   remote clients are rejected, and each side compares the peer process's
//!   user SID with its own before the first byte.
//!
//! [`chunked`] is the length-prefixed chunk framing the Windows pipe applies
//! to a raw byte phase, because a byte-mode pipe cannot half-close. It is
//! platform-neutral so every OS compiles and tests it.
//!
//! Nothing in this tree may name `qsh_transport`, `quinn` or `rustls`; the
//! file-scoped bans in `xtask/src/arch.rs` enforce that for the two platform
//! files.

pub mod chunked;
pub mod transport;
