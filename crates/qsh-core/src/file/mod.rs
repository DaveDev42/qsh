//! Remote file operations (`docs/adr/0029-file-copy.md`).
//!
//! - [`guard`]: the path judgement every remote file op shares (shape check
//!   and home resolution, normalization, the protected state set, the
//!   open-handle recheck primitives). A pure module that no authorization
//!   path calls yet; the op dispatch lands on top of it later in M15.

pub mod guard;
