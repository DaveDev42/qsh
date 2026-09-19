//! Doc-prose == code-constant anti-drift gate for tunnel wording
//! (`PLAN.md` M4 Step 8 (c), L6 — the same discipline `doctor_docs.rs`
//! already applies to `qsh_core::doctor::CONTROLLER_UNREACHABLE`,
//! `PLAN.md` M3 Step 9 (c)).
//!
//! Two tunnel-facing wordings are quoted verbatim in `README.md` and
//! `docs/CLI.md` §6.9 rather than paraphrased:
//!
//! - [`qsh_core::ops::tunnel::DYNAMIC_FORWARD_ACL_NOTE`] — the security
//!   fact `-D` is not a new grant, `forward.local` reused, and
//!   `forward.socks` is never consulted (ADR-0019 decision 14). This
//!   replaces the P0 stub's own refusal wording once `-D` was implemented
//!   — see this file's `git log` for the four tests that pinned the old
//!   stub's message/guidance constants before ADR-0019 landed.
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

use qsh_core::ops::tunnel::DYNAMIC_FORWARD_ACL_NOTE;
use qsh_core::tunnel::REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE;

#[path = "support/docs.rs"]
mod docs;
use docs::read_doc;

/// Slice `doc` from `heading` (matched verbatim) up to, but not including,
/// the next line starting with `#` at any level. Copied from
/// `acl_docs.rs`'s `heading_section_slice` (integration test binaries
/// cannot share code across files without a `#[path]` module) — see that
/// file for the full F5 rationale. The four pre-existing tests below stay
/// on the whole-file `.contains` frame unedited; only the section-scoped
/// `docs/CLI.md` §6.9 tests below (`docs/design/testing.md` L6) use this
/// helper.
fn heading_section_slice<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc
        .find(heading)
        .unwrap_or_else(|| panic!("doc must have a {heading:?} heading"));
    let rest = &doc[start..];
    let end = rest[heading.len()..]
        .find("\n#")
        .map(|i| i + heading.len())
        .unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn readme_quotes_the_dynamic_forward_acl_note_verbatim() {
    let readme = read_doc("README.md");
    assert!(
        readme.contains(DYNAMIC_FORWARD_ACL_NOTE),
        "README.md must quote DYNAMIC_FORWARD_ACL_NOTE verbatim"
    );
}

#[test]
fn cli_md_section_6_9_quotes_the_dynamic_forward_acl_note_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.9 Tunnel");
    assert!(
        section.contains(DYNAMIC_FORWARD_ACL_NOTE),
        "docs/CLI.md §6.9 itself (not merely somewhere in the file) must quote \
         DYNAMIC_FORWARD_ACL_NOTE verbatim"
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

// ---------------------------------------------------------------------
// REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE again, section-scoped rather than
// whole-file. Unrelated to `-D`/DYNAMIC_FORWARD_ACL_NOTE — left exactly as
// it was before ADR-0019.
// ---------------------------------------------------------------------

#[test]
fn cli_md_section_6_9_quotes_the_remote_forward_loopback_only_message_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.9 Tunnel");
    assert!(
        section.contains(REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE),
        "docs/CLI.md §6.9 itself (not merely somewhere in the file) must quote \
         REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE verbatim"
    );
}

#[test]
fn readme_port_forwards_quotes_the_remote_forward_loopback_only_message_verbatim() {
    let readme = read_doc("README.md");
    let section = heading_section_slice(&readme, "### Port forwards");
    assert!(
        section.contains(REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE),
        "README.md's Port forwards section itself must quote \
         REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE verbatim"
    );
}
