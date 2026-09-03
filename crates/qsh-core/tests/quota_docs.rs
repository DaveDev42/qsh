//! Doc-prose == code-constant anti-drift gate for `qsh_core::quota`'s
//! vocabulary (`PLAN.md` M8 Step 3, `docs/adr/0010-resource-quotas.md`) —
//! `crates/qsh-core/tests/admission_docs.rs`'s pattern, restated for the
//! quota module: before this, nothing cross-checked `docs/CLI.md` §6.12's
//! quota prose (the category strings, the config key names, their
//! defaults) against the actual `qsh_core::quota::QuotaKind::category()`/
//! `qsh_core::config::ServeConfig`/`qsh_core::quota::QuotaLimits`
//! constants it describes. A rename or a cap change on either side would
//! have left the doc silently stale.
//!
//! Every assertion below reads the real constant/function rather than a
//! literal, so a rename breaks this test instead of leaving a doc wrong.
//! `QuotaKind::ALL` is iterated rather than named one variant at a time so
//! a *new* `QuotaKind` (a future tunnel/connection quota, `PLAN.md` M8
//! Step 3's commit-split 3b) is caught by this test the moment it lands
//! in `ALL`, before anyone remembers to hand-write a new assertion for
//! it.

use std::path::PathBuf;

use qsh_core::config::ServeConfig;
use qsh_core::quota::{QuotaKind, QuotaLimits};

/// The repo root, reached from `CARGO_MANIFEST_DIR` (`crates/qsh-core`)
/// the same way every other doc-reading integration test in this
/// workspace does.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// The first decimal number appearing after `key`'s own occurrence in
/// `doc`, within a short window — `docs/CLI.md`/`docs/design/
/// architecture.md`'s shared "`key`(기본 N)" / "key(기본 N, ...)"
/// convention (quoted-backtick style differs between the two docs, so
/// this matches on the bare `기본` marker rather than any particular
/// surrounding punctuation). Scoped to a window right after the key's own
/// occurrence, not the whole (very long, many-numbered) config-map line —
/// so a cap change on a *different* key elsewhere on the same line can
/// never be mistaken for this one's default. Panics with the offending
/// text on any mismatch, so a doc that stops naming a key — or drifts far
/// enough from its default that this heuristic can no longer find it —
/// fails loudly instead of silently agreeing with anything.
fn doc_default_after(doc: &str, key: &str) -> u64 {
    let key_idx = find_key_as_its_own_identifier(doc, key).unwrap_or_else(|| {
        panic!("doc never names \"{key}\" as its own identifier (not as a prefix of a longer one)")
    });
    // Char-based, not byte-based: `doc` is Korean UTF-8, and a fixed byte
    // offset from `key_idx` can land inside a multi-byte character.
    let window: String = doc[key_idx..].chars().take(200).collect();
    let marker_idx = window
        .find("기본")
        .unwrap_or_else(|| panic!("no \"기본 N\" found near \"{key}\": {window:?}"));
    let after = &window[marker_idx + "기본".len()..];
    let digits: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("no number found after \"기본\" near \"{key}\": {after:?}"))
}

/// Finds `key` in `doc`, skipping any hit whose next character is still
/// part of the same identifier (`_` or alphanumeric) — otherwise
/// `"max_sessions"` matches inside `"max_sessions_per_principal"` and
/// `doc_default_after` reads the wrong config key's default.
fn find_key_as_its_own_identifier(doc: &str, key: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(rel_idx) = doc[search_from..].find(key) {
        let idx = search_from + rel_idx;
        let boundary_ok = match doc[idx + key.len()..].chars().next() {
            Some(c) => c != '_' && !c.is_alphanumeric(),
            None => true,
        };
        if boundary_ok {
            return Some(idx);
        }
        search_from = idx + key.len();
    }
    None
}

/// D1: every `QuotaKind::ALL` category string is named in both docs.
#[test]
fn cli_md_and_architecture_md_name_every_quota_reject_category() {
    let cli_md = read_doc("docs/CLI.md");
    let architecture_md = read_doc("docs/design/architecture.md");

    assert!(
        QuotaKind::ALL.len() >= 3,
        "QuotaKind::ALL collapsed to fewer than the three M8 Step 3 kinds \
         (sessions/per-principal-sessions/per-principal-exec) — {:?}",
        QuotaKind::ALL
    );

    for kind in QuotaKind::ALL {
        let category = kind.category();
        assert!(
            cli_md.contains(category),
            "docs/CLI.md §6.12 must name the \"{category}\" category word \
             ({kind:?}::category())"
        );
        assert!(
            architecture_md.contains(category),
            "docs/design/architecture.md must name the \"{category}\" category word \
             ({kind:?}::category())"
        );
    }
}

/// D1b: every `QuotaKind::ALL` variant's `action()` word — the exact
/// string `crate::audit::AuditRecord::quota_rejected`/
/// `quota_rejected_summary` now write into a quota-reject record's
/// `action` field — is named by `docs/CLI.md` §6.12's audit sentence.
/// Catches drift the other direction from D1: a category string alone
/// (D1) does not pin which `action` word goes with it, and F1 of the M8
/// Step 3a conformance sweep found `action` hardcoded to the placeholder
/// `"quota"` in code while this exact sentence already named
/// `"session.open"`/`"exec.run"` — this test is the drift gate D1 was
/// missing.
#[test]
fn cli_md_names_every_quota_reject_action() {
    let cli_md = read_doc("docs/CLI.md");

    // Scope the search to §6.12's own text — the section between its
    // heading and the next `### 6.13` heading — rather than the whole
    // file. `"session.open"`/`"exec.run"` both also appear in unrelated
    // JSON examples elsewhere in CLI.md (§6.3's session-open request,
    // §6.8's exec-run request), so a whole-file `.contains` would still
    // pass even if §6.12's own quota-reject sentence were deleted.
    const SECTION_HEADING: &str = "### 6.12 장기 실행 모드: `qsh serve`";
    const NEXT_HEADING: &str = "### 6.13 장기 실행 모드: `qsh listen` / `qsh reverse`";
    let start = cli_md
        .find(SECTION_HEADING)
        .unwrap_or_else(|| panic!("docs/CLI.md must contain the heading {SECTION_HEADING:?}"));
    let end = cli_md[start..]
        .find(NEXT_HEADING)
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("docs/CLI.md must contain the heading {NEXT_HEADING:?}"));
    let section = &cli_md[start..end];

    let actions: std::collections::BTreeSet<&'static str> =
        QuotaKind::ALL.iter().map(|kind| kind.action()).collect();
    assert_eq!(
        actions,
        std::collections::BTreeSet::from(["session.open", "exec.run"]),
        "QuotaKind::action() vocabulary changed — update the assertion \
         (and docs/CLI.md §6.12's action sentence) deliberately, not by \
         drift: {actions:?}"
    );
    for action in &actions {
        assert!(
            section.contains(&format!("\"{action}\"")),
            "docs/CLI.md §6.12 must name the \"{action}\" action word \
             a quota-reject audit record now carries (QuotaKind::action())"
        );
    }
}

/// D2 + D3: every new `[serve]` quota key is named in both docs, and each
/// doc's quoted default matches `QuotaLimits::default()` — parsed out of
/// the doc's own text, not compared against a second hand-typed literal
/// this test could just as easily drift from.
///
/// `validated_rate_per_source` (P2-3) is *not* repeated here — it is
/// `admission_docs.rs`'s own key, already covered by
/// `validated_rate_per_source_is_documented_in_cli_md_and_architecture_md`
/// there; duplicating that assertion in this file would just be a second
/// place for the same fact to go stale.
#[test]
fn cli_md_and_architecture_md_name_every_quota_config_key_and_its_default() {
    let cli_md = read_doc("docs/CLI.md");
    let architecture_md = read_doc("docs/design/architecture.md");
    let defaults = QuotaLimits::default();

    let keys: &[(&str, u64)] = &[
        ("max_sessions", defaults.max_sessions as u64),
        (
            "max_sessions_per_principal",
            defaults.max_sessions_per_principal as u64,
        ),
        (
            "max_exec_per_principal",
            defaults.max_exec_per_principal as u64,
        ),
    ];

    for (key, default) in keys {
        assert!(
            cli_md.contains(key),
            "docs/CLI.md §6.12 must name the [serve].{key} config key"
        );
        assert_eq!(
            doc_default_after(&cli_md, key),
            *default,
            "docs/CLI.md §6.12's quoted default for {key} must match \
             QuotaLimits::default() ({default})"
        );

        assert!(
            architecture_md.contains(key),
            "docs/design/architecture.md's config map must name the [serve].{key} config key"
        );
        assert_eq!(
            doc_default_after(&architecture_md, key),
            *default,
            "docs/design/architecture.md's quoted default for {key} must match \
             QuotaLimits::default() ({default})"
        );
    }

    // Cross-check against `ServeConfig`'s own constants too — `QuotaLimits::
    // default()` is defined in terms of them (`crates/qsh-core/src/
    // quota.rs`), so this is redundant *unless* that definition ever
    // drifts from them, which would be its own bug this incidentally
    // catches.
    assert_eq!(defaults.max_sessions, ServeConfig::DEFAULT_MAX_SESSIONS);
    assert_eq!(
        defaults.max_sessions_per_principal,
        ServeConfig::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL
    );
    assert_eq!(
        defaults.max_exec_per_principal,
        ServeConfig::DEFAULT_MAX_EXEC_PER_PRINCIPAL
    );
}
