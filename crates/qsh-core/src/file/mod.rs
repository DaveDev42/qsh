//! Remote file operations (`docs/adr/0029-file-copy.md`).
//!
//! - [`guard`]: the path judgement every remote file op shares (shape check
//!   and home resolution, normalization, the protected state set, the
//!   open-handle recheck primitives). A pure module that the op dispatch
//!   (`Server::handle_file_op`) composes in the order decision 8 fixes.
//! - `host` (unix only): the filesystem steps behind the decisions, pure
//!   functions over open directory fds (list a page, make a directory, stat
//!   by name).
//! - [`operand`]: the scp operand grammar of `qsh cp` (pure).
//! - `xfer` (unix only): the blocking pieces of a `FILE_DATA` transfer the host
//!   and the client share (temp file guard, disk writer, commit).

pub mod guard;
#[cfg(unix)]
pub mod host;
pub mod operand;
#[cfg(unix)]
pub(crate) mod xfer;
