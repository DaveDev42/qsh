//! Pins two invariants of the one-line status header in `docs/CLI.md`
//! (`PLAN.md` M13 (j)). The header is a hand-written change log, so a typo
//! in a cited section number or a newer version written behind an older one
//! would otherwise ship unnoticed. Both tests read the document only; no
//! code constant is involved, and there is no `#[cfg(unix)]`, so the tests
//! run on every CI leg.

#[path = "support/docs.rs"]
mod docs;
use docs::read_doc;

/// The status header: the line that starts with `**상태:**`.
fn status_header(cli_md: &str) -> &str {
    cli_md
        .lines()
        .find(|line| line.starts_with("**상태:**"))
        .expect("docs/CLI.md must keep its `**상태:**` header line")
}

/// Every `§N` or `§N.M` cited in `text`, in order of appearance. A trailing
/// `.` that is not followed by a digit belongs to the sentence, not the
/// number.
fn cited_sections(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find('§') {
        rest = &rest[pos + '§'.len_utf8()..];
        let bytes = rest.as_bytes();
        let mut end = 0;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end == 0 {
            continue;
        }
        if end + 1 < bytes.len() && bytes[end] == b'.' && bytes[end + 1].is_ascii_digit() {
            end += 1;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
        }
        out.push(rest[..end].to_string());
        rest = &rest[end..];
    }
    out
}

/// The numbers of the `## N.` and `### N.M` headings in the document.
fn numbered_headings(cli_md: &str) -> Vec<String> {
    cli_md
        .lines()
        .filter_map(|line| {
            let title = line
                .strip_prefix("### ")
                .or_else(|| line.strip_prefix("## "))?;
            let number: String = title
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let number = number.trim_end_matches('.');
            (!number.is_empty()).then(|| number.to_string())
        })
        .collect()
}

/// The `N` of every `v0.N` token in `text`, in order of appearance. A token
/// only counts when the `v` does not continue a longer word.
fn minor_versions(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("v0.") {
        let preceded_by_word = rest[..pos]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric());
        rest = &rest[pos + 3..];
        if preceded_by_word {
            continue;
        }
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse() {
            out.push(n);
        }
    }
    out
}

#[test]
fn cli_md_status_header_cites_only_sections_that_exist() {
    let cli_md = read_doc("docs/CLI.md");
    let headings = numbered_headings(&cli_md);
    assert!(
        headings.iter().any(|h| h == "6.17"),
        "heading scan found no `### 6.17`; the scan is broken: {headings:?}"
    );
    let cited = cited_sections(status_header(&cli_md));
    assert!(
        cited.len() >= 10,
        "the status header cites at least ten sections; the scan found {cited:?}"
    );
    let missing: Vec<&String> = cited.iter().filter(|s| !headings.contains(s)).collect();
    assert!(
        missing.is_empty(),
        "docs/CLI.md status header cites sections with no heading: {missing:?}"
    );
}

#[test]
fn cli_md_status_header_leads_with_its_newest_version() {
    let cli_md = read_doc("docs/CLI.md");
    let header = status_header(&cli_md);
    let lead = header
        .strip_prefix("**상태:** Draft ")
        .expect("the header must open with `**상태:** Draft v0.N`");
    let lead_version = minor_versions(lead)
        .first()
        .copied()
        .expect("the header must open with `Draft v0.N`");
    assert!(
        lead.starts_with(&format!("v0.{lead_version}")),
        "the first token after `Draft` must be the version: {lead:.40}"
    );
    let versions = minor_versions(header);
    assert!(
        versions.len() >= 5,
        "the header chains its older versions; the scan found {versions:?}"
    );
    let newest = versions.iter().copied().max().unwrap();
    assert_eq!(
        lead_version, newest,
        "the status header leads with v0.{lead_version} but mentions v0.{newest}; \
         the newest version goes first"
    );
}

#[test]
fn status_header_scanners_behave_on_small_inputs() {
    assert_eq!(
        cited_sections("§6.12와 §6.13. §2.4·§6.11, §10 끝. §x §"),
        ["6.12", "6.13", "2.4", "6.11", "10"]
    );
    assert_eq!(
        minor_versions("Draft v0.18 (a); v0.9 qsh.cli/v1 rev0.3"),
        [18, 9]
    );
    let doc = "## 2. 공통\n### 2.4 Operation\n### Host\n## 10. Compat\n";
    assert_eq!(numbered_headings(doc), ["2", "2.4", "10"]);
}
