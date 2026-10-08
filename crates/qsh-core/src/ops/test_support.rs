//! Test-only helpers shared by the `ops` test modules and `setup`.

use super::Ops;
use crate::config::Paths;

/// An `Ops` rooted in a fresh temp dir (`config/` and `state/` beneath it).
/// The returned `TempDir` must outlive the `Ops`.
pub(crate) fn temp_ops() -> (tempfile::TempDir, Ops) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, Ops::new(paths))
}
