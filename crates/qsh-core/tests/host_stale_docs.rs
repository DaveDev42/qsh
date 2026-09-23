//! Doc-prose == code-constant anti-drift gate for the stale-registration
//! retryable `HOST_NOT_FOUND` branch (issue #4 items 4/3a,
//! `docs/design/testing.md` L6 — the same discipline `doctor_docs.rs`/
//! `tunnel_docs.rs` already apply elsewhere in this crate).
//!
//! Two `docs/CLI.md` spots must stay in sync with the code they describe:
//!
//! - §3.2 must carry the new sentence establishing `retryable` as a
//!   per-response value (never derived from `code` alone) — the general
//!   rule the stale branch below is the worked example of.
//! - §6.1 must carry a row naming the stale branch's `details.reason`
//!   value, [`qsh_core::ops::host::STALE_REGISTRATION_REASON`], so the
//!   constant and its documentation can never drift apart silently.

#[path = "support/docs.rs"]
mod docs;
use docs::read_doc;

/// Slice `doc` from `heading` (matched verbatim) up to, but not
/// including, the next line starting with `#` at any level — copied from
/// `tunnel_docs.rs`'s identical helper (integration test binaries cannot
/// share code across files without a `#[path]` module).
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
fn cli_md_section_3_2_states_retryable_is_a_per_response_value() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 3.2 실패");
    assert!(
        section.contains("`retryable`은 응답마다 값이 붙는 필드다"),
        "docs/CLI.md §3.2 must state that `retryable` is a per-response \
         value, not derived from `code` alone: {section:?}"
    );
    assert!(
        section.contains("ErrorCode::default_retryable()"),
        "§3.2's new sentence must name the default automation must not \
         substitute for reading the field"
    );
}

#[test]
fn cli_md_section_6_1_names_the_stale_registration_reason() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.1 Host 조회");
    let marker = format!(
        "`reason: \"{}\"`",
        qsh_core::ops::host::STALE_REGISTRATION_REASON
    );
    assert!(
        section.contains(&marker),
        "docs/CLI.md §6.1 must name the stale branch's details.reason \
         value ({marker:?}) verbatim, matching \
         qsh_core::ops::host::STALE_REGISTRATION_REASON: {section:?}"
    );
    assert!(
        section.contains("retryable: true"),
        "§6.1's stale-branch row must say the branch is retryable"
    );
    assert!(
        section.contains("lost_ago_ms"),
        "§6.1's stale-branch row must name the lost_ago_ms details field"
    );
    assert!(
        section.contains("retry_after_ms"),
        "§6.1's stale-branch row must name the retry_after_ms details field"
    );
    assert!(
        section.contains("`lost_at`"),
        "§6.1's stale-branch row must name the lost_at field on the Host \
         it is reported against"
    );
}

#[test]
fn cli_md_section_6_12_qualifies_the_connect_result_fallback_as_that_frame_only() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### 6.12 장기 실행 모드: `qsh serve`");
    assert!(
        section.contains("이 프레임 하나만의 fallback이다"),
        "docs/CLI.md §6.12's ConnectResult paragraph must qualify \
         deriving retryable from `code` as that frame's own fallback, not \
         the general `qsh.cli/v1` rule stated in §3.2: {section:?}"
    );
}

#[test]
fn cli_md_section_5_documents_host_lost_at() {
    let cli_md = read_doc("docs/CLI.md");
    let section = heading_section_slice(&cli_md, "### Host");
    assert!(
        section.contains("`lost_at`"),
        "docs/CLI.md §5's Host type description must document `lost_at`: \
         {section:?}"
    );
    assert!(
        section.contains("additive-optional"),
        "§5's `lost_at` paragraph must state it is additive-optional \
         (§10), the same discipline `source`/`user` already follow"
    );
}
