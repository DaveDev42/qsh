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
//!   both, of a stream that several owners share. `shutdown_write` is for
//!   the raw byte phase only.
//! - `forget_refused_endpoint` is the unix stale-socket cleanup; a pipe
//!   cannot outlive its process, so it does nothing on Windows.
//! - `bind` and `Listener::accept` are the daemon's side: `bind` claims the
//!   endpoint (a socket in a private directory, or the first instance of a
//!   pipe name) and `accept` hands over each connection together with the
//!   verdict of the credential check, so the daemon never reads a frame from
//!   a peer that failed it. `remove_endpoint` deletes a socket node once the
//!   daemon stops; a pipe goes away by itself.
//! - `split`, `OwnedReadHalf` and `OwnedWriteHalf` give a relay independent
//!   halves of a conduit. `wait_for_hangup` resolves when the peer has closed
//!   both directions.
//! - `raw_reader`, `raw_writer`, `raw_bytes`, `RawReader` and `RawWriter` are
//!   how a conduit's raw byte phase (after the framed `qsh.local.v1`
//!   messages) touches the stream. A socket half-closes, so the bytes go
//!   through as they are. A byte-mode pipe cannot, so on Windows the raw
//!   phase carries its bytes as chunks (a 4-byte big-endian length and that
//!   many bytes, a zero length ending the writer's direction;
//!   `crate::localctl::chunked`). Every relay of raw bytes goes through
//!   these, so a shut-down write half reaches the peer as an end-of-stream
//!   while it can still answer, on every platform.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(unix)]
pub use unix::LocalStream;
#[cfg(unix)]
pub(crate) use unix::{
    Listener, OwnedReadHalf, OwnedWriteHalf, RawReader, RawWriter, bind, candidate_endpoints,
    connect, forget_refused_endpoint, raw_bytes, raw_reader, raw_writer, remove_endpoint,
    shutdown_both, shutdown_write, split, wait_for_hangup,
};
#[cfg(all(unix, test))]
pub(crate) use unix::{
    authorized_peer, bind_with_narrow_umask, peer_is_authorized, process_is_verifiably_dead,
};

#[cfg(windows)]
pub use windows::LocalStream;
#[cfg(windows)]
pub(crate) use windows::{
    Listener, OwnedReadHalf, OwnedWriteHalf, RawReader, RawWriter, bind, candidate_endpoints,
    connect, forget_refused_endpoint, raw_bytes, raw_reader, raw_writer, remove_endpoint,
    shutdown_both, shutdown_write, split, wait_for_hangup,
};
