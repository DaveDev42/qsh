//! The OS half of localctl: the local stream agent forwarding listens on and
//! how the accepting side decides who may talk to it (ADR-0035 decision 14,
//! `docs/design/architecture.md` §1 and §7).
//!
//! | platform | endpoint | [`LocalStream`] | who may connect |
//! |---|---|---|---|
//! | unix | a socket node | `tokio::net::UnixStream` | the node is 0600, and the accepting side compares the peer's euid with its own before reading |
//! | Windows | `\\.\pipe\...` | a named pipe client or server end | every instance carries a protected, owner-only DACL, remote clients are rejected, and each side compares the peer process's user SID with its own before the first byte |
//!
//! The two files `unix` and `windows` hold the platform code and are the
//! only places in `localctl` that name a socket or pipe API. They must never
//! name `qsh_transport`, `quinn` or `rustls` (`xtask/src/arch.rs`).

// ADR-0068 retired the daemon and its conduit, so the Windows half keeps
// listener, enumeration and raw-phase helpers no caller uses. They go with
// the next Windows-capable edit, not here, because that half cannot be
// compiled by every contributor.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
#[allow(dead_code)]
pub(crate) mod windows;

#[cfg(unix)]
pub use unix::LocalStream;
#[cfg(all(unix, test))]
pub(crate) use unix::peer_is_authorized;
#[cfg(unix)]
pub(crate) use unix::{authorized_peer, bind_with_narrow_umask};

#[cfg(windows)]
#[allow(unused_imports)]
pub(crate) use windows::{
    Listener, OwnedReadHalf, OwnedWriteHalf, RawReader, RawWriter, bind, candidate_endpoints,
    forget_refused_endpoint, raw_bytes, raw_reader, raw_writer, remove_endpoint, shutdown_both,
    shutdown_write, split, wait_for_hangup,
};
#[cfg(windows)]
pub use windows::{LocalStream, connect};
