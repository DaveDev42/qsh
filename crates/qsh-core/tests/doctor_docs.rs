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
use qsh_core::doctor::{CERT_EXPIRING_SOON, TRUST_REMOVE_SCOPE};

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

// -----------------------------------------------------------------------
// M7 Step 6 doctor diagnostics (verify round P2-5, `PLAN.md` M7 §4.1
// L98's completeness gate). Only the two new-in-M7 diagnostics
// `docs/CLI.md` §6.17's own JSON example already quotes verbatim
// (`TRUST_REMOVE_SCOPE` and `CERT_EXPIRING_SOON`) get a drift gate here —
// the other seven new codes are only described in §6.17's table as a
// paraphrase, not quoted verbatim anywhere in the docs today, so asserting
// verbatim substring containment for them would fail against current
// (accurate, just not verbatim) prose rather than catch real drift.
// README.md is deliberately excluded (main-session decision, `PLAN.md`
// M7 Step 6 verify-round note): its "Known limitations" section
// paraphrases these two rather than quoting them.
// -----------------------------------------------------------------------

#[test]
fn cli_md_quotes_the_trust_remove_scope_diagnostic_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        cli_md.contains(TRUST_REMOVE_SCOPE.message),
        "docs/CLI.md §6.17 must quote TRUST_REMOVE_SCOPE.message verbatim"
    );
    assert!(
        cli_md.contains(TRUST_REMOVE_SCOPE.remedy),
        "docs/CLI.md §6.17 must quote TRUST_REMOVE_SCOPE.remedy verbatim"
    );
}

#[test]
fn cli_md_quotes_the_cert_expiring_soon_diagnostic_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        cli_md.contains(CERT_EXPIRING_SOON.message),
        "docs/CLI.md §6.17 must quote CERT_EXPIRING_SOON.message verbatim"
    );
    assert!(
        cli_md.contains(CERT_EXPIRING_SOON.remedy),
        "docs/CLI.md §6.17 must quote CERT_EXPIRING_SOON.remedy verbatim"
    );
}

/// The stable half of a diagnostic is its `code`, not its prose: `code` is
/// what operators grep for and what a future `--fail-on` would select on,
/// and `EXPECTED_DOCTOR_CODES` freezes the set. So while only the two
/// diagnostics above are pinned word-for-word, every code in the frozen
/// set must at least be *named* in `docs/CLI.md` — adding a fourteenth
/// code without documenting it, or renaming one out from under §6.17,
/// fails here instead of shipping an undocumented finding.
#[test]
fn cli_md_names_every_frozen_doctor_code() {
    let cli_md = read_doc("docs/CLI.md");
    let undocumented: Vec<&str> = qsh_core::doctor::EXPECTED_DOCTOR_CODES
        .iter()
        .copied()
        .filter(|code| !cli_md.contains(code))
        .collect();
    assert!(
        undocumented.is_empty(),
        "docs/CLI.md §6.17 must name every frozen doctor code; missing: {undocumented:?}"
    );
}
