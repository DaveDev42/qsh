//! `qsh-core`: all business logic, exposed as a typed operation layer.
//!
//! [`ops::Ops`] is the single API every frontend (`qsh-cli`'s human/JSON
//! renderers today; the MCP adapter from M6) calls through — see
//! `docs/CLI.md` §11. This crate depends only on `qsh-proto` for now; the
//! `qsh-transport` dependency lands once dispatch/ACL/broker code that
//! actually needs a connection is implemented.

pub mod ops;

pub use ops::{OpError, Operation, Ops, VersionOp};
