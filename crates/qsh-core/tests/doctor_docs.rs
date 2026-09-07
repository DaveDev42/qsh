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

/// M8 Step 4c (`BRIEF-4c.md` §5.4/§7 Q7, `ARBITRATION-4.md` "4c 구현 판정"
/// Q7): the test above pins that every frozen *code* is named somewhere in
/// `docs/CLI.md`, but nothing pinned the loose *count prose* — "진단 코드
/// N종" at `docs/CLI.md:752` and "N종 진단 코드" at `:1030` — against
/// `EXPECTED_DOCTOR_CODES.len()`. That drift actually happened once
/// already: M8 Step 4b added a 14th code (`config_unknown_key`) and the
/// table grew to 14 rows, but both prose mentions of the count stayed at
/// "13종" because `cli_md_names_every_frozen_doctor_code` only checks
/// that each code is *present*, not that the doc's own headline count
/// agrees with the code set's length. This test reads the digit run
/// immediately adjacent to each of those two exact phrases and requires
/// it to equal `EXPECTED_DOCTOR_CODES.len()`.
#[test]
fn cli_md_prose_doctor_code_count_matches_expected_len() {
    let cli_md = read_doc("docs/CLI.md");
    let expected = qsh_core::doctor::EXPECTED_DOCTOR_CODES.len();

    let counts = doctor_code_counts_named_in_prose(&cli_md);
    // 4c adversarial review B7: `!counts.is_empty()` alone lets either
    // site silently drop out of `counts` (rather than fail) the moment its
    // exact phrasing changes — `doctor_code_counts_named_in_prose`'s
    // patterns only match, they never flag a near-miss. A rewrite of
    // §6.11's "진단 코드 N종" that keeps a number nearby but breaks the
    // literal adjacency (B7's experiment: "진단 코드는 13종") drops that
    // site from `counts` instead of asserting on it, so the loop below
    // would silently check only the surviving site and still pass. Pinning
    // `counts.len() == 2` requires *both* of §6.11's and §6.17's known
    // phrasings to still be found before the per-site check even runs.
    assert_eq!(
        counts.len(),
        2,
        "expected exactly 2 doctor-code-count phrasings in docs/CLI.md \
         (§6.11's \"진단 코드 N종\" and §6.17's \"N종 진단 코드\"), found {} — \
         one of the two sites' exact phrasing changed and silently stopped \
         being checked: {counts:?}",
        counts.len()
    );
    for (idx, n) in &counts {
        assert_eq!(
            *n, expected,
            "docs/CLI.md names the doctor code count as {n} at byte offset \
             {idx}, but EXPECTED_DOCTOR_CODES.len() == {expected} — the \
             prose count and the frozen code set have drifted apart"
        );
    }
}

/// Reads the digit run adjacent to each of `docs/CLI.md`'s two exact
/// count-prose phrasings and returns `(byte offset of the "종", parsed
/// number)` for every match found. Deliberately anchored to the two
/// literal adjacency patterns this doc actually uses — "진단 코드 N종"
/// (§6.11, digits immediately follow a space after "코드") and "N종 진단
/// 코드" (§6.17's table headline, digits immediately precede "종") —
/// rather than a loose "any digit run near '진단 코드'" scan: this file's
/// own §6.12 prose separately says things like "재사용 5종·신설 9종" in
/// the same paragraph as a "N종 진단 코드" headline, and a window-based
/// scan picks up 5/9 as false positives from that neighboring sentence.
fn doctor_code_counts_named_in_prose(doc: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();

    // Pattern A: "진단 코드 " followed immediately by a digit run then "종"
    // (`docs/CLI.md:752`: "...진단 코드 14종·envelope...").
    const PREFIX: &str = "진단 코드 ";
    let mut search_from = 0;
    while let Some(rel_idx) = doc[search_from..].find(PREFIX) {
        let after_prefix = search_from + rel_idx + PREFIX.len();
        search_from = after_prefix;
        let digits: String = doc[after_prefix..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if digits.is_empty() {
            continue;
        }
        let jong_idx = after_prefix + digits.len();
        if doc[jong_idx..].starts_with("종") {
            let n: usize = digits.parse().expect("digit-only string must parse");
            out.push((jong_idx, n));
        }
    }

    // Pattern B: a digit run immediately followed by "종 진단 코드"
    // (`docs/CLI.md:1030`: "**14종 진단 코드** (...)").
    const SUFFIX: &str = "종 진단 코드";
    search_from = 0;
    while let Some(rel_idx) = doc[search_from..].find(SUFFIX) {
        let jong_idx = search_from + rel_idx;
        search_from = jong_idx + SUFFIX.len();
        let digits: String = doc[..jong_idx]
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if digits.is_empty() {
            continue;
        }
        let n: usize = digits.parse().expect("digit-only string must parse");
        out.push((jong_idx, n));
    }
    out
}
