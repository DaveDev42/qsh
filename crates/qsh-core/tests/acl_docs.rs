//! Doc-prose == code-vocabulary anti-drift gate for `Action::ALL`
//! (`PLAN.md` M5 Step 1 (c), L6 — the same discipline `tunnel_docs.rs`/
//! `doctor_docs.rs` already apply to wording constants).
//!
//! `docs/PRD.md` §9 is the **binding** action vocabulary (`CLAUDE.md`
//! "docs/PRD.md and docs/CLI.md are the binding contract" — PRD wins if
//! anything else ever disagrees). This test extracts every `action.name`
//! token PRD §9 lists and asserts it is exactly the set
//! [`qsh_core::acl::Action::ALL`] produces via `as_str()` — neither side may
//! drift from the other silently. A wording/vocabulary edit on either side
//! that is not mirrored on the other fails CI instead of shipping quietly.
//!
//! Deliberately has no `#[cfg(unix)]` anywhere — both sides are pure data
//! (an enum's `as_str()` and a markdown file), so this runs on the Windows
//! CI leg too (`PLAN.md` M3 Step 9 (d)'s precedent).

use std::collections::BTreeSet;
use std::path::PathBuf;

use qsh_core::acl::Action;

/// The repo root, reached from `CARGO_MANIFEST_DIR` (`crates/qsh-core`) the
/// same way every other doc-reading integration test in this workspace
/// does.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// Every `` `word.word` `` inline-code token inside PRD §9 ("## 9. 보안과
/// ACL" up to the next `## ` heading) — dotted, lowercase, `[a-z_]+\.[a-z_]+`
/// only, which is exactly the shape of an ACL action string and excludes
/// unrelated backtick spans elsewhere in the doc (principal examples like
/// `` `user:dave` `` have no `.`, so they never match).
///
/// Splitting on `` ` `` alternates outside/inside-backtick text (odd split
/// index = inside); the one fenced ```` ```toml ```` block in this section
/// contributes an even number of backticks (3 open + 3 close), so parity
/// across it is preserved and every real inline span on either side is
/// still picked out correctly — the fenced block's own body lands in an
/// "inside" slot too, but it is thrown out by the shape filter below (it is
/// not just lowercase ASCII either side of its first `.`).
fn prd_section_9_actions() -> BTreeSet<String> {
    let prd = read_doc("docs/PRD.md");
    let start = prd
        .find("## 9. 보안과 ACL")
        .expect("docs/PRD.md must have a '## 9. 보안과 ACL' heading");
    let rest = &prd[start..];
    let end = rest[3..].find("\n## ").map(|i| i + 3).unwrap_or(rest.len());
    let section = &rest[..end];

    section
        .split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, token)| token)
        .filter(|token| is_dotted_action_shape(token))
        .map(|token| token.to_string())
        .collect()
}

fn is_dotted_action_shape(token: &str) -> bool {
    let Some((head, tail)) = token.split_once('.') else {
        return false;
    };
    let is_lower_alpha = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase());
    is_lower_alpha(head) && is_lower_alpha(tail)
}

#[test]
fn prd_section_9_lists_at_least_the_eleven_actions() {
    // Sanity check on the extractor itself before trusting the equality
    // test below: PRD §9's prose repeats some action names outside the
    // bullet list (e.g. `session.control` in the paragraph right after),
    // so this is a superset check, not a count check.
    let prd_actions = prd_section_9_actions();
    assert_eq!(
        prd_actions.len(),
        11,
        "docs/PRD.md §9 must name exactly 11 distinct dotted action tokens \
         in backticks, found {prd_actions:?}"
    );
}

#[test]
fn action_all_matches_prd_section_9_exactly() {
    let prd_actions = prd_section_9_actions();
    let code_actions: BTreeSet<String> =
        Action::ALL.iter().map(|a| a.as_str().to_string()).collect();
    assert_eq!(
        code_actions, prd_actions,
        "Action::ALL and docs/PRD.md §9's action list have drifted apart — \
         PRD.md is binding (CLAUDE.md); conform the code, not the doc \
         (unless PRD.md itself needs a proposed ADR, per CLAUDE.md)"
    );
}
