//! Doc-prose == code-vocabulary anti-drift gate for `Action::ALL`
//! (M5 plan Step 1 (c) (2473c88), L6 — the same discipline `tunnel_docs.rs`/
//! `doctor_docs.rs` already apply to wording constants), plus the same
//! discipline applied to `PERMISSION_DENIED_MESSAGE` (M5 plan Step 4 (2473c88)
//! (c)).
//!
//! `docs/PRD.md` §9 is the **binding** action vocabulary (`CLAUDE.md`
//! "docs/PRD.md and docs/CLI.md are the binding contract" — PRD wins if
//! anything else ever disagrees). This test extracts every `action.name`
//! token PRD §9 lists and asserts it is exactly the set
//! [`qsh_core::acl::Action::ALL`] produces via `as_str()` — neither side may
//! drift from the other silently. A wording/vocabulary edit on either side
//! that is not mirrored on the other fails CI instead of shipping quietly.
//!
//! [`qsh_core::acl::PERMISSION_DENIED_MESSAGE`] is quoted verbatim in
//! `docs/CLI.md` §3.2's example envelope and in `docs/design/
//! architecture.md` §6's own prose — a byte-for-byte substring check in
//! the `tunnel_docs.rs`/`doctor_docs.rs` mould, not a loose keyword match.
//! Both checks are scoped to the specific section (§3.2 / §6), sliced from
//! its heading to the next `#`-heading, not the whole file: a whole-file
//! `.contains` would still pass if the constant only showed up somewhere
//! unrelated (a stray HTML comment, a different section entirely) while
//! the section that is actually supposed to quote it drifted (F5, M5 Step
//! 4 adversarial review).
//!
//! Deliberately has no `#[cfg(unix)]` anywhere — both sides are pure data
//! (an enum's `as_str()`, a `&str` constant, and markdown files), so this
//! runs on the Windows CI leg too (M3 plan Step 9 (d) (2473c88)'s precedent).

use std::collections::BTreeSet;

use qsh_core::acl::{
    ACL_POLICY_INVALID_CODE, ACL_POLICY_MISSING_CODE, ACL_STARTUP_CHECK_HINT,
    ACL_STARTUP_DENIED_CLAUSE, ACL_STARTUP_HEADLINE, ACL_STARTUP_NO_AUTOGEN, Action,
    PERMISSION_DENIED_MESSAGE, ROLE_GRANTS,
};

#[path = "support/docs.rs"]
mod docs;
use docs::read_doc;

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

/// Slice `doc` from `heading` (matched verbatim, e.g. `"### 3.2 실패"`) up
/// to — but not including — the next line starting with `#` at any level,
/// generalizing [`prd_section_9_actions`]'s own "to the next heading"
/// trick so a doc-quoting check can assert a constant appears *inside* the
/// one section it claims to, not merely somewhere in the file (F5, M5
/// Step 4 adversarial review — a whole-file `.contains` would still pass
/// if the constant showed up anywhere else, e.g. a stray comment near an
/// unrelated section, while the section that is actually supposed to
/// quote it silently drifted). Skipping `heading.len()` bytes before
/// searching for `"\n#"` is what stops this from immediately matching the
/// heading's own leading `#`; it is always a valid UTF-8 boundary because
/// `heading` was located by an exact substring match at `start`.
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

#[test]
fn cli_md_quotes_the_permission_denied_message_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 3.2 실패");
    assert!(
        section.contains(PERMISSION_DENIED_MESSAGE),
        "docs/CLI.md §3.2 itself (not merely somewhere in the file) must quote \
         PERMISSION_DENIED_MESSAGE verbatim"
    );
}

/// F5's second gate (M5 Step 4 adversarial review): the same
/// section-scoped check for `docs/design/architecture.md` §6, which quotes
/// the constant in its own "거부 문면 균일성" bullet.
#[test]
fn architecture_md_quotes_the_permission_denied_message_verbatim() {
    let architecture_md = read_doc("docs/design/architecture.md");
    let section = heading_section_slice(&architecture_md, "## 6. ACL 엔진과 audit");
    assert!(
        section.contains(PERMISSION_DENIED_MESSAGE),
        "docs/design/architecture.md §6 itself (not merely somewhere in the file) \
         must quote PERMISSION_DENIED_MESSAGE verbatim"
    );
}

// ---------------------------------------------------------------------
// F4 (M5 plan Step 6 (2473c88) PR 6a adversarial ②): the L6 doc-consistency
// gate the migration story (1) owed and never got — `doctor_docs.rs`'s
// `CONTROLLER_UNREACHABLE` precedent, applied to
// `qsh_core::acl::StartupDiagnostic::render`'s fixed wording. `render()`
// composes its output FROM these consts (`crates/qsh-core/src/acl/
// load.rs`) rather than inlining the literal text, so there is exactly
// one place the wording can drift from — and this gate is what stops that
// drift from reaching README.md/docs/CLI.md silently. A whole-file
// `.contains` (not section-scoped) mirrors `doctor_docs.rs` itself, which
// this gate is explicitly modeled on.
// ---------------------------------------------------------------------

#[test]
fn readme_quotes_the_acl_startup_diagnostic_wording_verbatim() {
    let readme = read_doc("README.md");
    for fragment in [
        ACL_STARTUP_HEADLINE,
        ACL_STARTUP_DENIED_CLAUSE,
        ACL_STARTUP_NO_AUTOGEN,
        ACL_STARTUP_CHECK_HINT,
        ACL_POLICY_MISSING_CODE,
        ACL_POLICY_INVALID_CODE,
    ] {
        assert!(
            readme.contains(fragment),
            "README.md's security posture section must quote {fragment:?} verbatim \
             (StartupDiagnostic::render's fixed wording)"
        );
    }
}

#[test]
fn cli_md_quotes_the_acl_startup_diagnostic_wording_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    for fragment in [
        ACL_STARTUP_HEADLINE,
        ACL_STARTUP_DENIED_CLAUSE,
        ACL_STARTUP_NO_AUTOGEN,
        ACL_STARTUP_CHECK_HINT,
        ACL_POLICY_MISSING_CODE,
        ACL_POLICY_INVALID_CODE,
    ] {
        assert!(
            cli_md.contains(fragment),
            "docs/CLI.md §6.12 must quote {fragment:?} verbatim \
             (StartupDiagnostic::render's fixed wording)"
        );
    }
}

// ---------------------------------------------------------------------
// ADR-0045 결정 2: the role-to-action table has one code copy
// (`ROLE_GRANTS`) and two doc copies (`docs/CLI.md` §6.11, `docs/PRD.md`
// §9). Both doc tables use the header `| role | 주는 action | 소유 축 |`;
// each row is `| `role` | `a`, `b` | scope |` with `없음` for an empty
// action set. Section-scoped, like the checks above.
// ---------------------------------------------------------------------

type RoleRow = (String, Vec<String>, String);

/// The rows of the role table inside `section`, in document order.
fn role_table_rows(section: &str) -> Vec<RoleRow> {
    let mut lines = section.lines();
    lines
        .by_ref()
        .find(|line| line.trim() == "| role | 주는 action | 소유 축 |")
        .expect("the section must contain the role table header");
    lines.next().expect("separator row after the header");
    lines
        .take_while(|line| line.starts_with('|'))
        .map(|line| {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            assert_eq!(cells.len(), 3, "role table row {line:?}");
            let unquote = |s: &str| s.trim_matches('`').to_string();
            let actions = if cells[1] == "없음" {
                Vec::new()
            } else {
                cells[1].split(',').map(|a| unquote(a.trim())).collect()
            };
            (unquote(cells[0]), actions, cells[2].to_string())
        })
        .collect()
}

fn role_rows_from_code() -> Vec<RoleRow> {
    ROLE_GRANTS
        .iter()
        .map(|grant| {
            (
                grant.role.as_str().to_string(),
                grant
                    .actions
                    .iter()
                    .map(|a| a.as_str().to_string())
                    .collect(),
                grant.scope.as_str().to_string(),
            )
        })
        .collect()
}

#[test]
fn role_action_table_matches_docs() {
    let code = role_rows_from_code();
    assert_eq!(code.len(), 6, "ADR-0045 결정 2 fixes six roles");

    let cli_md = read_doc("docs/CLI.md");
    let cli_section = heading_section_slice(&cli_md, "### 6.11 Identity와 trust");
    assert_eq!(
        role_table_rows(cli_section),
        code,
        "docs/CLI.md §6.11's role table and ROLE_GRANTS have drifted apart"
    );

    let prd = read_doc("docs/PRD.md");
    let prd_section = heading_section_slice(&prd, "## 9. 보안과 ACL");
    assert_eq!(
        role_table_rows(prd_section),
        code,
        "docs/PRD.md §9's role table and ROLE_GRANTS have drifted apart"
    );
}

/// No role grants `forward.socks`, and `none` grants nothing: the two rows
/// ADR-0045 결정 2 states in prose, checked against the code table so a
/// hand edit of `ROLE_GRANTS` cannot widen either silently.
#[test]
fn role_table_never_grants_forward_socks_and_none_grants_nothing() {
    for (role, actions, _) in role_rows_from_code() {
        assert!(
            !actions.iter().any(|a| a == "forward.socks"),
            "{role} grants forward.socks"
        );
        if role == "none" {
            assert!(actions.is_empty());
        }
    }
}
