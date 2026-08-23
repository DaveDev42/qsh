//! Doc-prose == code-constant anti-drift gate for
//! [`qsh_core::doctor::CONTROLLER_UNREACHABLE`] (`PLAN.md` M3 Step 9 (c)).
//!
//! `README.md`, `docs/CLI.md`, and `docs/PRD.md` each quote this
//! diagnostic's `message`/`remedy` verbatim rather than paraphrasing it —
//! the whole point of a single source of truth is that the docs and the
//! constant cannot silently drift apart. This test is the mechanical
//! enforcement of that, the same discipline `docs/design/testing.md` L6
//! already applies to fixtures: a byte-for-byte substring check, not a
//! loose keyword match, so a wording edit in one place that is not
//! mirrored in the other three fails CI instead of shipping quietly.
//!
//! Deliberately has no `#[cfg(unix)]` anywhere — the diagnostic is pure
//! data (`doctor.rs`'s own module docs) and every doc file it must appear
//! in is plain text, so this runs on the Windows CI leg too
//! (`PLAN.md` M3 Step 9 (d)).

use std::path::PathBuf;

use qsh_core::CONTROLLER_UNREACHABLE;

/// The repo root, reached from `CARGO_MANIFEST_DIR`
/// (`crates/qsh-core`) the same way every other doc-reading integration
/// test in this workspace does.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn readme_quotes_the_controller_unreachable_diagnostic_verbatim() {
    let readme = read_doc("README.md");
    assert!(
        readme.contains(CONTROLLER_UNREACHABLE.message),
        "README.md must quote CONTROLLER_UNREACHABLE.message verbatim"
    );
    assert!(
        readme.contains(CONTROLLER_UNREACHABLE.remedy),
        "README.md must quote CONTROLLER_UNREACHABLE.remedy verbatim"
    );
}

#[test]
fn cli_md_quotes_the_controller_unreachable_diagnostic_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        cli_md.contains(CONTROLLER_UNREACHABLE.message),
        "docs/CLI.md §6.13 must quote CONTROLLER_UNREACHABLE.message verbatim"
    );
    assert!(
        cli_md.contains(CONTROLLER_UNREACHABLE.remedy),
        "docs/CLI.md §6.13 must quote CONTROLLER_UNREACHABLE.remedy verbatim"
    );
}

#[test]
fn prd_md_quotes_the_controller_unreachable_diagnostic_verbatim() {
    let prd_md = read_doc("docs/PRD.md");
    assert!(
        prd_md.contains(CONTROLLER_UNREACHABLE.message),
        "docs/PRD.md §6 must quote CONTROLLER_UNREACHABLE.message verbatim"
    );
    assert!(
        prd_md.contains(CONTROLLER_UNREACHABLE.remedy),
        "docs/PRD.md §6 must quote CONTROLLER_UNREACHABLE.remedy verbatim"
    );
}
