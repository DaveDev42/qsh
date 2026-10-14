//! The single integration-test binary of `qsh-transport`: every former `tests/<name>.rs` is
//! a module here, so the workspace links one test executable per crate instead of
//! one per file. Run one former file with `-E 'test(/^<name>::/)'`.

mod conformance;
mod handshake_matrix;
mod loopback;
mod reset_key;
