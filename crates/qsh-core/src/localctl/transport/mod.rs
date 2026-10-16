//! The OS half of localctl: how a CLI process reaches this machine's
//! resident `qsh listen` daemon and how the daemon decides who may talk to
//! it (ADR-0035 decision 14, `docs/design/architecture.md` §1 and §7).
//!
//! Everything above this module — [`super::frame`], [`super::client`], the
//! `qsh.local.v1` message set — speaks to a [`LocalStream`] and nothing else.
//! The platform decides what that is:
//!
//! | platform | endpoint | [`LocalStream`] | who may connect |
//! |---|---|---|---|
//! | unix | `<runtime_dir>/<pid>.sock` | `tokio::net::UnixStream` | the socket is 0600 in a 0700 directory, and the daemon compares the peer's euid with its own before reading a frame |
//! | Windows | `\\.\pipe\qsh-<scope>-<pid>` | a named pipe client or server end | every instance carries a protected, owner-only DACL, remote clients are rejected, and each side compares the peer process's user SID with its own before the first frame |
//!
//! The two files `unix` and `windows` hold the platform code and are the
//! only places in `localctl` that name a socket or pipe API. Like
//! `frame.rs` and `client.rs` they must never name `qsh_transport`, `quinn`
//! or `rustls` (`xtask/src/arch.rs`).
//!
//! The functions re-exported here are the whole surface the platform-neutral
//! code uses:
//!
//! - `connect` opens an endpoint. On Windows it also checks, before
//!   returning the stream, that the server end runs as the same user, so
//!   nothing is ever written to another user's pipe.
//! - `candidate_endpoints` lists the endpoints of this machine's daemons,
//!   pid-ascending.
//! - `shutdown_write` and `shutdown_both` end the write direction, or
//!   both, of a stream that several owners share.
//! - `forget_refused_endpoint` is the unix stale-socket cleanup; a pipe
//!   cannot outlive its process, so it does nothing on Windows.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(unix)]
pub use unix::LocalStream;
#[cfg(unix)]
pub(crate) use unix::{
    authorized_peer, bind_with_narrow_umask, candidate_endpoints, connect, forget_refused_endpoint,
    shutdown_both, shutdown_write, tighten_socket_mode,
};
#[cfg(all(unix, test))]
pub(crate) use unix::{peer_is_authorized, process_is_verifiably_dead};

#[cfg(windows)]
pub use windows::LocalStream;
#[cfg(windows)]
pub(crate) use windows::{candidate_endpoints, connect, forget_refused_endpoint, shutdown_write};
