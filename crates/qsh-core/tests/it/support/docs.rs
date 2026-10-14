//! `repo_root()` and `read_doc()`, shared by the doc-drift and source-scan
//! integration tests. Each consumer pulls this file in with
//! `#[path = "support/docs.rs"] mod docs;`, the same way
//! `broker_ops_corpus.rs` includes `broker_ops_harness.rs`.
#![allow(dead_code)]

use std::path::PathBuf;

/// The repo root, reached from `CARGO_MANIFEST_DIR` (`crates/qsh-core`) the
/// same way every other doc-reading integration test in this workspace
/// does.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Read a repo-relative file (README.md, docs/CLI.md, a source file) to a
/// string, panicking with the path when it is missing.
pub fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}
