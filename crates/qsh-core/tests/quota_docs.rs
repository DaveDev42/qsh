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
        std::collections::BTreeSet::from([
            "session.open",
            "exec.run",
            "forward.local",
            "forward.remote",
            "connect",
        ]),
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
        ("max_exec", defaults.max_exec as u64),
        (
            "max_tunnel_streams_per_principal",
            defaults.max_tunnel_streams_per_principal as u64,
        ),
        (
            "max_tunnel_streams_per_forward",
            defaults.max_tunnel_streams_per_forward as u64,
        ),
        (
            "max_remote_forwards_per_principal",
            defaults.max_remote_forwards_per_principal as u64,
        ),
        (
            "max_connections_per_principal",
            defaults.max_connections_per_principal as u64,
        ),
        ("max_connections", defaults.max_connections as u64),
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

/// D4: `docs/design/protocol.md` used to say the tunnel-stream and
/// remote-forward-listener axes hit **no** cap at all (M4/M5's
/// deliberately-left-open gap, `docs/ROADMAP.md` M8 감사 개정 ③) — M8
/// Step 3b closed both, so the doc must no longer claim otherwise. This
/// only catches the literal old sentence reappearing (e.g. a careless
/// revert); it does not re-derive the gap's closure from the quota
/// module the way D1-D3 do, because protocol.md's prose has no single
/// constant to read back.
#[test]
fn protocol_md_no_longer_declares_the_tunnel_gaps_unbounded() {
    let protocol_md = read_doc("docs/design/protocol.md");

    assert!(
        !protocol_md.contains("어떤 상한에도 걸리지 않는다"),
        "docs/design/protocol.md must not claim the remote-forward-listener \
         count hits no cap — M8 Step 3b closed that gap with \
         max_remote_forwards_per_principal"
    );
    assert!(
        protocol_md.contains("max_tunnel_streams_per_principal")
            && protocol_md.contains("max_tunnel_streams_per_forward"),
        "docs/design/protocol.md's concurrency-limit section must name the \
         M8 Step 3b tunnel-stream quota keys, not just the transport-level \
         MAX_CONCURRENT_BIDI_STREAMS ceiling"
    );
    assert!(
        protocol_md.contains("max_remote_forwards_per_principal"),
        "docs/design/protocol.md's remote-forward-listener section must \
         name the M8 Step 3b max_remote_forwards_per_principal quota key"
    );
}

/// Every M8 Step 3b `QuotaKind` category is named in `docs/CLI.md` §6.12
/// (D1 already asserts this for `QuotaKind::ALL` as a whole, iterated —
/// this pins the *new* 3b-specific set by name so a doc edit that drops
/// one of them, even while leaving the pre-3b three intact, is caught by
/// its own literal instead of only by the generic loop), and the two new
/// wire-facing reset/close codes (`RESET_CODE_RESOURCE_EXHAUSTED` =
/// `0x200D`, `CLOSE_CODE_RESOURCE_EXHAUSTED` = `0x1003`,
/// `crates/qsh-core/src/server/mod.rs`) are registered in
/// `docs/design/protocol.md`'s prose.
#[test]
fn cli_md_names_every_3b_quota_category_and_protocol_md_names_the_new_wire_codes() {
    let cli_md = read_doc("docs/CLI.md");
    let protocol_md = read_doc("docs/design/protocol.md");

    for category in [
        "quota_exec_host",
        "quota_tunnels_principal",
        "quota_tunnels_forward",
        "quota_remote_forwards_principal",
        "quota_connections_principal",
        "quota_connections_host",
        "quota_connections_pairing",
    ] {
        assert!(
            cli_md.contains(category),
            "docs/CLI.md §6.12 must name the M8 Step 3b \"{category}\" category word"
        );
    }

    assert!(
        protocol_md.contains("0x200D"),
        "docs/design/protocol.md must register RESET_CODE_RESOURCE_EXHAUSTED (0x200D)"
    );
    assert!(
        protocol_md.contains("0x1003"),
        "docs/design/protocol.md must register CLOSE_CODE_RESOURCE_EXHAUSTED (0x1003)"
    );
}

/// M8 Step 3b arbitration B6: the tunnel axis's refusal is a
/// `wire::ConnectResult{ok,code,message}`, which has no `retryable`
/// field — only `wire::Error` does. `docs/CLI.md` §6.12's sentence
/// listing which axes come back as `RESOURCE_EXHAUSTED(retryable: true)`
/// must not include the tunnel axis (터널) in that list.
#[test]
fn cli_md_does_not_claim_the_tunnel_axis_carries_retryable() {
    let cli_md = read_doc("docs/CLI.md");
    // Scoped to the §6.12 quota sentence specifically (`docs/CLI.md`
    // also says "retryable: true" once elsewhere, for `--timeout`'s
    // unrelated `TIMEOUT` code) via the exact phrase that sentence uses.
    let marker = "`RESOURCE_EXHAUSTED`(`retryable: true`)";
    let idx = cli_md
        .find(marker)
        .unwrap_or_else(|| panic!("docs/CLI.md §6.12 must still say \"{marker}\" somewhere"));
    // The sentence is delimited by the nearest '.' on each side (Korean
    // prose here uses ASCII periods as sentence stops, same convention
    // the rest of this file's window-based readers rely on).
    let before = &cli_md[..idx];
    let sentence_start = before.rfind('.').map(|i| i + 1).unwrap_or(0);
    let after = &cli_md[idx..];
    let sentence_end = idx
        + after
            .find('.')
            .unwrap_or_else(|| panic!("no sentence end found after \"{marker}\""));
    let sentence = &cli_md[sentence_start..=sentence_end];
    assert!(
        !sentence.contains("터널"),
        "the \"retryable: true\" sentence must not claim the tunnel axis — \
         ConnectResult has no retryable field: {sentence:?}"
    );
}
