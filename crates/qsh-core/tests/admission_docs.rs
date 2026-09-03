//! Doc-prose == code-constant anti-drift gate for `qsh_core::admission`'s
//! vocabulary (`PLAN.md` M8 Step 2 verification round, H3; extended M8
//! Step 3 verdict arbitration item 11④ to `RejectReason::ALL` and to
//! `docs/design/architecture.md`): before this, nothing cross-checked
//! `docs/CLI.md` §6.12's admission prose — the category strings, the
//! config key names, their defaults — against the actual
//! `qsh_core::admission::RejectReason::category()`/
//! `qsh_core::config::ServeConfig` constants it describes, unlike the
//! established `doctor_docs.rs`/`acl_docs.rs`/`tunnel_docs.rs` pattern
//! this file follows (`read_doc` helper included). A rename on either
//! side would have left the doc silently stale.
//!
//! Every assertion below reads the real constant/function rather than a
//! literal, so a rename breaks this test instead of leaving a doc wrong.
//! `RejectReason::ALL` is iterated rather than named one variant at a
//! time so a *new* `RejectReason` (like `ValidatedRateLimited`, added
//! M8 Step 3 P2-3) is caught by this test the moment it lands in `ALL`,
//! before anyone remembers to hand-write a new assertion for it.

use std::path::PathBuf;

use qsh_core::admission::RejectReason;
use qsh_core::config::ServeConfig;

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

/// The first decimal number appearing after `key`'s own occurrence in
/// `doc`, within a short window — mirrors `crates/qsh-core/tests/
/// quota_docs.rs`'s helper of the same name and same "`key`(기본 N)"
/// convention, restated here rather than shared across integration test
/// binaries. Scoped to a window right after `key`, not a bare
/// `doc.contains(&default.to_string())` (F8 of the M8 Step 3a
/// conformance sweep): a bare `contains` on the *number itself* passes as
/// long as that digit sequence appears anywhere in the file for any
/// reason — CLI.md's admission bullet, for instance, also says "창(10초)
/// 당" a few words after `validated_rate_per_source`'s own default, so a
/// doc default that drifted to any value would still find *some* stray
/// "10" and pass silently. Panics with the offending text on any
/// mismatch, so a doc that stops naming a key — or drifts far enough that
/// this heuristic can no longer find it — fails loudly instead of
/// silently agreeing with anything.
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

#[test]
fn every_admission_rejection_category_is_named_in_cli_md_and_architecture_md() {
    let cli_md = read_doc("docs/CLI.md");
    let architecture_md = read_doc("docs/design/architecture.md");

    for reason in RejectReason::ALL {
        let category = reason.category();
        assert!(
            cli_md.contains(category),
            "docs/CLI.md §6.12 must name the \"{category}\" category word \
             ({reason:?}::category())"
        );
        assert!(
            architecture_md.contains(category),
            "docs/design/architecture.md must name the \"{category}\" category word \
             ({reason:?}::category())"
        );
    }
}

#[test]
fn cli_md_names_every_admission_config_key_and_its_default() {
    let cli_md = read_doc("docs/CLI.md");

    assert!(
        cli_md.contains("max_concurrent_handshakes"),
        "docs/CLI.md §6.12 must name the [serve].max_concurrent_handshakes config key"
    );
    assert_eq!(
        doc_default_after(&cli_md, "max_concurrent_handshakes"),
        ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES as u64,
        "docs/CLI.md §6.12's quoted max_concurrent_handshakes default has drifted \
         from ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES"
    );

    assert!(
        cli_md.contains("handshake_rate_per_source"),
        "docs/CLI.md §6.12 must name the [serve].handshake_rate_per_source config key"
    );
    assert_eq!(
        doc_default_after(&cli_md, "handshake_rate_per_source"),
        ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE as u64,
        "docs/CLI.md §6.12's quoted handshake_rate_per_source default has drifted \
         from ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE"
    );
}

/// `PLAN.md` M8 Step 3 P2-3, verdict arbitration item 11④: the new
/// validated-axis config key must be documented in *both* `docs/CLI.md`
/// and `docs/design/architecture.md`, not just one — the two docs drifted
/// apart is exactly the failure mode this whole file exists to catch.
#[test]
fn validated_rate_per_source_is_documented_in_cli_md_and_architecture_md() {
    let cli_md = read_doc("docs/CLI.md");
    let architecture_md = read_doc("docs/design/architecture.md");

    assert!(
        cli_md.contains("validated_rate_per_source"),
        "docs/CLI.md §6.12 must name the [serve].validated_rate_per_source config key"
    );
    assert_eq!(
        doc_default_after(&cli_md, "validated_rate_per_source"),
        ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE as u64,
        "docs/CLI.md §6.12's quoted validated_rate_per_source default has drifted \
         from ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE"
    );

    assert!(
        architecture_md.contains("validated_rate_per_source"),
        "docs/design/architecture.md's config map must name the \
         [serve].validated_rate_per_source config key"
    );
    assert_eq!(
        doc_default_after(&architecture_md, "validated_rate_per_source"),
        ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE as u64,
        "docs/design/architecture.md's quoted validated_rate_per_source default has \
         drifted from ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE"
    );
}
