//! `qsh-proto`: the sans-IO contract layer shared by every other QSH crate.
//!
//! This crate has no async runtime and no I/O of its own. It owns:
//!
//! - [`frame`]: the length-prefixed framing used on every QSH byte stream.
//! - [`error`]: [`error::ErrorCode`], the vocabulary shared by the wire
//!   protocol and the `qsh.cli/v1` JSON envelope.
//! - [`types`]: JSON contract types (`docs/CLI.md` §5).
//! - [`event`]: `qsh.event/v1` session events (`docs/CLI.md` §6.4).
//!
//! Because this crate parses untrusted input from the network, it is the
//! designated fuzzing surface for the project (see the PRD's fuzzing
//! section) and depends on nothing beyond `serde`/`serde_json`/`thiserror`.

pub mod error;
pub mod event;
pub mod frame;
pub mod types;

pub use error::ErrorCode;
pub use event::SessionEvent;
pub use types::{Host, Session, VersionData};
