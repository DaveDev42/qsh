use super::{format_trust_pin_line, render_doctor_lines, sanitize};
use qsh_proto::{DoctorData, DoctorFinding, TrustPeer};

#[test]
fn sanitize_strips_escapes_and_newlines_but_keeps_tabs() {
    assert_eq!(sanitize("plain text"), "plain text");
    assert_eq!(
        sanitize("a\u{1b}[31mred\u{1b}[0m\nfake line\ttab"),
        "a\u{FFFD}[31mred\u{FFFD}[0m\u{FFFD}fake line\ttab"
    );
}

/// The invariant every fixed-width table renderer in this module
/// (`print_trust_list`, `print_hosts`, `print_tunnels`, `print_session_
/// list`) depends on without re-checking it: `sanitize` maps each
/// control character to exactly one U+FFFD, one char in for one char
/// out, so a column width computed from the *raw* field (as all of the
/// above do — `docs/design/architecture.md`'s crate-boundary style,
/// cheaper than sanitizing twice) never drifts from the width of the
/// *sanitized* text actually written into that column. If `sanitize`
/// ever stopped being 1:1 (collapsing a multi-char escape sequence to
/// one replacement char, say), every such table would silently
/// misalign instead of failing loudly — this test is what fails
/// loudly instead.
#[test]
fn sanitize_preserves_char_count_for_control_character_input() {
    let s = "a\u{1b}[31mb\u{0}c\td\re\nf";
    assert_eq!(
        sanitize(s).chars().count(),
        s.chars().count(),
        "sanitize must map each control char to exactly one U+FFFD"
    );
}

/// Fix A1: a peer-controlled `TrustPeer.name` containing a terminal
/// escape sequence and a bare `\r` must not be able to overwrite or
/// hide the fingerprint printed right after it on the same line — the
/// exact threat `print_trust_accept`'s one-line `{name} ({fingerprint})`
/// shape creates for the value pairing tells the operator to compare
/// out of band (`docs/CLI.md` §6.11).
#[test]
fn format_trust_pin_line_sanitizes_the_name_and_keeps_the_fingerprint_intact() {
    let peer = TrustPeer {
        name: "evil\u{1b}[Kname\r".to_string(),
        fingerprint: "sha256:REALFINGERPRINT".to_string(),
        address: String::new(),
        added_at: "2026-08-31T00:00:00Z".to_string(),
    };

    let line = format_trust_pin_line("pinned", &peer);

    assert_eq!(
        line,
        "pinned evil\u{FFFD}[Kname\u{FFFD} (sha256:REALFINGERPRINT)"
    );
    assert!(
        line.ends_with("(sha256:REALFINGERPRINT)"),
        "the fingerprint must remain intact and fully visible on the line: {line:?}"
    );
}

/// The address branch, and a positive control on the field a legitimate
/// peer's own device id always is (alphanumerics, underscores — no
/// control characters): nothing is altered.
#[test]
fn format_trust_pin_line_leaves_an_ordinary_name_untouched() {
    let peer = TrustPeer {
        name: "device_01K0EXAMPLE".to_string(),
        fingerprint: "sha256:REALFINGERPRINT".to_string(),
        address: "198.51.100.7:4433".to_string(),
        added_at: "2026-08-31T00:00:00Z".to_string(),
    };

    let line = format_trust_pin_line("pinned", &peer);

    assert_eq!(
        line,
        "pinned device_01K0EXAMPLE (sha256:REALFINGERPRINT) [198.51.100.7:4433]"
    );
}

/// P3-6 (verify round): a multiline `detail` (the shape
/// `acl_policy_missing`/`acl_policy_invalid` findings carry, from
/// `crate::acl::StartupDiagnostic::render`) must render one line per
/// input line, indented, each independently escape-sanitized — not
/// flattened into a single U+FFFD-mangled line the way running
/// `sanitize` over the whole string before splitting used to.
#[test]
fn render_doctor_lines_splits_multiline_detail_and_sanitizes_each_line_independently() {
    let data = DoctorData {
        overall: "error".to_string(),
        findings: vec![DoctorFinding {
            code: "acl_policy_missing".to_string(),
            status: "error".to_string(),
            detail: "line one\nline two\u{1b}[31mred\u{1b}[0m\nline three".to_string(),
            remedy: Some("do the thing".to_string()),
        }],
    };

    let lines = render_doctor_lines(&data);
    assert_eq!(
        lines,
        vec![
            "overall: error".to_string(),
            "1 finding(s):".to_string(),
            "  [error] acl_policy_missing: line one".to_string(),
            "      line two\u{FFFD}[31mred\u{FFFD}[0m".to_string(),
            "      line three".to_string(),
            "    remedy: do the thing".to_string(),
        ]
    );
}
