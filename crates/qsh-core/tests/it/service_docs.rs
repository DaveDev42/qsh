//! Doc-prose == code-constant anti-drift gate for `qsh service` (ROADMAP
//! M9 (g), `docs/CLI.md` §6.18, `docs/deploy/service.md`).
//!
//! `docs/deploy/service.md` is no longer a set of hand-typed illustrative
//! examples — every fence on it is exactly what `qsh service install`
//! writes, rendered through the same [`render_launchd_plist`]/
//! [`render_systemd_unit`] functions production calls, fed the same
//! `DOC_EXAMPLE_*` constants the doc's prose uses. This is the byte-for-byte
//! enforcement of that: a fence edited without regenerating it, or a
//! renderer changed without updating the doc, fails here instead of
//! shipping quietly (the same discipline `doctor_docs.rs` already applies
//! to `CONTROLLER_UNREACHABLE`).
//!
//! Deliberately has no `#[cfg(unix)]`/`#[cfg(target_os = ...)]` anywhere —
//! the renderers are plain functions of their string arguments and every
//! doc file is plain text, so this runs on the Windows CI leg too
//! (mirrors why `crate::doctor::probe`'s path builders lost their own
//! `#[cfg]`: they are `pub fn`, not `#[cfg]`-gated, in
//! `crates/qsh-core/src/doctor/probe.rs`).

use qsh_core::doctor::SERVICE_NOT_REGISTERED;
use qsh_core::{
    DOC_EXAMPLE_CONTROLLER, DOC_EXAMPLE_EXE_LINUX, DOC_EXAMPLE_EXE_MACOS, DOC_EXAMPLE_HOME_MACOS,
    SERVICE_UNSUPPORTED_PLATFORM, launchd_bootout_argv, launchd_bootstrap_argv, launchd_print_argv,
    render_launchd_plist, render_systemd_unit, systemd_daemon_reload_argv,
    systemd_disable_now_argv, systemd_enable_now_argv, systemd_is_active_argv,
};

use crate::docs;
use docs::read_doc;

/// Find the fence immediately following `path_marker` (a unique substring
/// identifying which of the three modes' fences this is, e.g. the unit
/// path line that precedes it) and return its body, requiring the fence to
/// open with ` ```{lang}\n` and close with a bare ` ``` ` line.
fn fence_after(doc: &str, path_marker: &str, lang: &str) -> String {
    let marker_at = doc
        .find(path_marker)
        .unwrap_or_else(|| panic!("docs/deploy/service.md must contain {path_marker:?}"));
    let after = &doc[marker_at..];
    let open = format!("```{lang}\n");
    let fence_open = after
        .find(&open)
        .unwrap_or_else(|| panic!("no {open:?} fence found after {path_marker:?}"));
    let body_start = fence_open + open.len();
    let body_end = after[body_start..]
        .find("```")
        .map(|i| body_start + i)
        .unwrap_or_else(|| panic!("fence after {path_marker:?} never closes"));
    after[body_start..body_end].to_string()
}

/// Count every fenced block opened with ` ```{lang}\n` in the whole doc —
/// the "assert the number of fences found" guard `doctor_docs.rs`'s
/// `counts.len() == 2` pattern models: a parser that only matches never
/// flags a near-miss (a fence silently dropped or renamed), so this must
/// run before the per-fence loop below trusts what it found.
fn count_fences(doc: &str, lang: &str) -> usize {
    let open = format!("```{lang}\n");
    doc.matches(&open).count()
}

/// Same as [`count_fences`], but only for ` ```ini` fences whose body
/// contains `needle` — this page has a fourth, unrelated ```ini fence
/// (`/etc/wsl.conf`'s `[boot]` block), and every systemd *unit* fence this
/// test cares about has a `[Service]` section that block does not.
fn count_ini_fences_containing(doc: &str, needle: &str) -> usize {
    let open = "```ini\n";
    let mut count = 0;
    let mut rest = doc;
    while let Some(start) = rest.find(open) {
        let body_start = start + open.len();
        let after = &rest[body_start..];
        let Some(end) = after.find("```") else {
            break;
        };
        if after[..end].contains(needle) {
            count += 1;
        }
        rest = &after[end..];
    }
    count
}

#[test]
fn service_md_declares_exactly_six_unit_fences() {
    let service_md = read_doc("docs/deploy/service.md");
    assert_eq!(
        count_fences(&service_md, "xml"),
        3,
        "docs/deploy/service.md must have exactly 3 ```xml launchd plist fences (serve/listen/reverse)"
    );
    assert_eq!(
        count_ini_fences_containing(&service_md, "[Service]"),
        3,
        "docs/deploy/service.md must have exactly 3 ```ini systemd unit fences (serve/listen/reverse)"
    );
}

#[test]
fn service_md_launchd_fences_match_the_generated_plists() {
    let service_md = read_doc("docs/deploy/service.md");
    for (mode, marker) in [
        ("serve", "`~/Library/LaunchAgents/io.qsh.serve.plist`:"),
        ("listen", "`~/Library/LaunchAgents/io.qsh.listen.plist`:"),
        ("reverse", "`~/Library/LaunchAgents/io.qsh.reverse.plist`"),
    ] {
        let fence = fence_after(&service_md, marker, "xml");
        let generated = render_launchd_plist(
            mode,
            DOC_EXAMPLE_EXE_MACOS,
            DOC_EXAMPLE_HOME_MACOS,
            DOC_EXAMPLE_CONTROLLER,
        );
        assert_eq!(
            fence, generated,
            "docs/deploy/service.md's {mode} launchd fence must equal render_launchd_plist({mode}, ...) byte for byte"
        );
    }
}

#[test]
fn service_md_systemd_fences_match_the_generated_units() {
    let service_md = read_doc("docs/deploy/service.md");
    for (mode, marker) in [
        ("serve", "`~/.config/systemd/user/qsh-serve.service`:"),
        ("listen", "`~/.config/systemd/user/qsh-listen.service`:"),
        ("reverse", "`~/.config/systemd/user/qsh-reverse.service`"),
    ] {
        let fence = fence_after(&service_md, marker, "ini");
        let generated = render_systemd_unit(mode, DOC_EXAMPLE_EXE_LINUX, DOC_EXAMPLE_CONTROLLER);
        assert_eq!(
            fence, generated,
            "docs/deploy/service.md's {mode} systemd fence must equal render_systemd_unit({mode}, ...) byte for byte"
        );
    }
}

#[test]
fn service_md_no_longer_promises_a_future_installer() {
    let service_md = read_doc("docs/deploy/service.md");
    assert!(
        !service_md.contains("is planned for M9"),
        "docs/deploy/service.md must no longer describe `qsh service install` as a future feature"
    );
}

#[test]
fn cli_md_quotes_the_service_unsupported_message_verbatim() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        cli_md.contains(SERVICE_UNSUPPORTED_PLATFORM),
        "docs/CLI.md §6.18 must quote SERVICE_UNSUPPORTED_PLATFORM verbatim"
    );
}

#[test]
fn service_not_registered_remedy_no_longer_says_the_installer_is_missing() {
    assert!(
        !SERVICE_NOT_REGISTERED.remedy.contains("does not exist yet"),
        "SERVICE_NOT_REGISTERED.remedy must not claim `qsh service install` does not exist"
    );
    assert!(
        SERVICE_NOT_REGISTERED
            .remedy
            .contains("qsh service install"),
        "SERVICE_NOT_REGISTERED.remedy must point at `qsh service install`"
    );
}

#[test]
fn cli_md_service_not_registered_row_points_at_the_installer() {
    let cli_md = read_doc("docs/CLI.md");
    assert!(
        !cli_md.contains("`qsh service install`은 아직 없으므로"),
        "docs/CLI.md §6.17's service_not_registered row must not claim the installer is missing"
    );
}

/// Every trimmed line inside a ` ```bash` fence of the doc.
fn bash_fence_lines(doc: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut inside = false;
    for line in doc.lines() {
        if line.starts_with("```bash") {
            inside = true;
        } else if line.starts_with("```") {
            inside = false;
        } else if inside {
            lines.push(line.trim().to_string());
        }
    }
    lines
}

/// ADR-0032 decision 11: the activation, query and release recipes in
/// `docs/deploy/service.md` are the argv `qsh service --activate`,
/// `--deactivate` and `--live` run. The builders take the recipe's own
/// placeholders (`$UID` for the uid, the example unit path) so the text
/// compared is the text a person types. Nothing here runs a manager.
/// The Task Scheduler recipes join this check with the Windows backend.
#[test]
fn service_md_activation_recipes_match_the_argv_builders() {
    let service_md = read_doc("docs/deploy/service.md");
    let recipes = bash_fence_lines(&service_md);
    assert!(
        recipes.iter().any(|line| line.starts_with("launchctl ")),
        "the bash fence scan found no launchctl recipe: {recipes:?}"
    );

    let uid = "$UID";
    let agent = "~/Library/LaunchAgents/io.qsh.serve.plist";
    let expected: Vec<(&str, Vec<String>)> = vec![
        ("launchd query", launchd_print_argv(uid, "serve")),
        ("launchd activate", launchd_bootstrap_argv(uid, agent)),
        ("launchd release", launchd_bootout_argv(uid, "serve")),
        ("systemd query", systemd_is_active_argv("serve")),
        ("systemd reload", systemd_daemon_reload_argv()),
        ("systemd activate", systemd_enable_now_argv("serve")),
        ("systemd release", systemd_disable_now_argv("serve")),
    ];
    // Each recipe line is present, and the lines of one manager appear in
    // the order the ops run them: the query before the activation, the
    // activation before the release, and `daemon-reload` before
    // `enable --now`.
    let mut positions: Vec<(&str, usize)> = Vec::new();
    for (what, argv) in &expected {
        let line = argv.join(" ");
        let position = recipes.iter().position(|recipe| *recipe == line);
        let Some(position) = position else {
            panic!("docs/deploy/service.md has no `{line}` line ({what}) in a bash fence");
        };
        positions.push((what, position));
    }
    for manager in ["launchd", "systemd"] {
        let ordered: Vec<(&str, usize)> = positions
            .iter()
            .copied()
            .filter(|(what, _)| what.starts_with(manager))
            .collect();
        assert!(
            ordered.windows(2).all(|pair| pair[0].1 < pair[1].1),
            "the {manager} recipe lines are out of order: {ordered:?}"
        );
    }
    let position_of = |what: &str| {
        positions
            .iter()
            .find(|(name, _)| *name == what)
            .map(|(_, position)| *position)
            .unwrap()
    };
    assert!(position_of("systemd reload") < position_of("systemd activate"));
    assert!(position_of("launchd query") < position_of("launchd activate"));

    // Every manager line in a bash fence is either one of the argv above or
    // a read-only line the ops do not run, so a new activation step cannot
    // enter the doc without entering the builders.
    let expected_lines: Vec<String> = expected.iter().map(|(_, argv)| argv.join(" ")).collect();
    let documented_only = ["systemctl --user status qsh-serve.service"];
    for line in &recipes {
        let is_manager_line = line.starts_with("launchctl ") || line.starts_with("systemctl ");
        assert!(
            !is_manager_line
                || expected_lines.contains(line)
                || documented_only.contains(&line.as_str()),
            "docs/deploy/service.md has a manager line the argv builders do not produce: `{line}`"
        );
    }
    // The doc names no restart as a step: the ops never run one
    // (ADR-0032 decision 4).
    assert!(
        !recipes
            .iter()
            .any(|line| line.starts_with("systemctl --user restart")
                || line.starts_with("launchctl kickstart")),
        "the recipes must not restart a unit"
    );
}
