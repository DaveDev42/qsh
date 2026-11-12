//! The QUIC backend: everything in `qsh-transport` that names quinn or
//! rustls (ADR-0061 decisions 5 and 7). The neutral types in `endpoint`,
//! `stream` and `error` dispatch to it; nothing outside this tree
//! converts a quinn error, builds a quinn config or implements a backend
//! trait for a quinn type.
//!
//! - [`conn`]: `MuxConn`, `SendHalf` and `RecvHalf` over a quinn connection.
//! - [`config`]: TLS, transport and server configuration for quinn.
//! - [`endpoint`]: the quinn endpoints behind `Dialer`, `Listener`,
//!   `Incoming` and `Endpoint`.
//! - [`error`]: quinn error to neutral error conversions.
//! - [`pipe`]: the in-memory packet pipe a jump hop's inner connection runs
//!   over (ADR-0056).
//! - [`punch`]: the hole-punching endpoint on one punch-aware UDP socket
//!   (ADR-0054).
//! - [`socket`]: tuned, dual-stack UDP sockets.

pub(crate) mod config;
pub(crate) mod conn;
pub(crate) mod endpoint;
pub(crate) mod error;
pub(crate) mod pipe;
pub(crate) mod punch;
pub(crate) mod socket;
