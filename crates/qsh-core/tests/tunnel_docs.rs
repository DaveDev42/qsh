//! Doc-prose == code-constant anti-drift gate for M4 tunnel wording
//! (`PLAN.md` M4 Step 8 (c), L6 — the same discipline `doctor_docs.rs`
//! already applies to `qsh_core::doctor::CONTROLLER_UNREACHABLE`,
//! `PLAN.md` M3 Step 9 (c)).
//!
//! Two tunnel-facing refusal messages are quoted verbatim in `README.md`
//! and `docs/CLI.md` §6.9 rather than paraphrased:
//!
//! - [`qsh_core::ops::tunnel::DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE`] — the
//!   `-D` P0 `UNSUPPORTED` stub's message ("P1 feature").
//! - [`qsh_core::tunnel::REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE`] — a
//!   non-loopback `-R` bind's `INVALID_ARGUMENT` refusal.
//!
//! This is a byte-for-byte substring check, not a loose keyword match, so
//! a wording edit in one place that is not mirrored in the other fails CI
//! instead of shipping quietly — a wording edit on the code side that is
//! not mirrored in the docs fails just the same, since both directions
//! are the same `.contains()` assertion.
//!
//! Deliberately has no `#[cfg(unix)]` anywhere — both constants are pure
//! data and every doc file this test reads is plain text, so this runs on
//! the Windows CI leg too (`PLAN.md` M3 Step 9 (d)'s precedent).

use std::path::PathBuf;

use qsh_core::ops::tunnel::DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE;
use qsh_core::tunnel::REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE;

/// The repo root, reached from `CARGO_MANIFEST_DIR` (`crates/qsh-core`)
/// the same way `doctor_docs.rs`'s own helper does.
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
fn readme_quotes_the_dynamic_forward_unsupported_message_verbatim() {
    let readme = read_doc("README.md");
    assert!(
        readme.contains(DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE),
        "README.md must quote DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE verbatim"
    );
}

#[test]
fn cli_md_quotes_the_dynamic_forward_unsupported_message_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        cli_md.contains(DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE),
        "docs/CLI.md §6.9 must quote DYNAMIC_FORWARD_UNSUPPORTED_MESSAGE verbatim"
    );
}

#[test]
fn readme_quotes_the_remote_forward_loopback_only_message_verbatim() {
    let readme = read_doc("README.md");
    assert!(
        readme.contains(REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE),
        "README.md must quote REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE verbatim"
    );
}

#[test]
fn cli_md_quotes_the_remote_forward_loopback_only_message_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        cli_md.contains(REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE),
        "docs/CLI.md §6.9 must quote REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE verbatim"
    );
}
