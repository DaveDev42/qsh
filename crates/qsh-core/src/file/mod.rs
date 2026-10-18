//! Remote file operations (`docs/adr/0029-file-copy.md`).
//!
//! - [`guard`]: the path judgement every remote file op shares (shape check
//!   and home resolution, normalization, the protected state set, the
//!   open-handle recheck primitives). A pure module that the op dispatch
//!   (`Server::handle_file_op`) composes in the order decision 8 fixes.
//! - `host`: the filesystem steps behind the decisions, pure functions over
//!   open directory handles (list a page, make a directory, stat by name, the
//!   write side's temp file and placement). The unix steps are `*at` calls;
//!   the Windows ones are `local`'s handle-and-path equivalents.
//! - `local`: the steps a `qsh cp` client takes on its own machine, one
//!   interface over the unix `*at` calls and the Windows handle-and-path
//!   equivalents (ADR-0035 decision 26). [`stat`] holds the types both share.
//! - [`operand`]: the scp operand grammar of `qsh cp` (pure).
//! - `xfer`: the blocking pieces of a `FILE_DATA` transfer the host and the
//!   client share (temp file guard, disk writer, commit).

pub mod guard;
pub mod host;
#[cfg(any(unix, windows))]
pub(crate) mod local;
pub mod operand;
pub mod stat;
#[cfg(any(unix, windows))]
pub(crate) mod xfer;
