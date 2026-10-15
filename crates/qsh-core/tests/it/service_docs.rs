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
    launchd_print_system_argv, render_launchd_plist, render_systemd_unit,
    systemd_daemon_reload_argv, systemd_disable_now_argv, systemd_enable_now_argv,
    systemd_is_active_argv,
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

/// The single top-level entry of a plist after `<key>{key}</key>`: the one
/// line for a scalar (`<string>`, `<true/>`), or every line through the
/// matching close for an `<array>` or `<dict>`. The plists on this page indent
/// their top-level keys by two spaces, which is what closes a container.
fn plist_entry(plist: &str, key: &str) -> String {
    let lines: Vec<&str> = plist.lines().collect();
    let marker = format!("  <key>{key}</key>");
    let at = lines
        .iter()
        .position(|line| *line == marker)
        .unwrap_or_else(|| panic!("plist has no top-level `{key}` key:\n{plist}"));
    let first = lines[at + 1];
    let close = match first.trim() {
        "<array>" => Some("  </array>"),
        "<dict>" => Some("  </dict>"),
        _ => None,
    };
    match close {
        None => first.to_string(),
        Some(close) => {
            let end = lines[at + 1..]
                .iter()
                .position(|line| *line == close)
                .unwrap_or_else(|| panic!("`{key}` never closes"));
            lines[at + 1..=at + 1 + end].join("\n")
        }
    }
}

/// ADR-0032 decision 13: the LaunchDaemon recipe in `docs/deploy/service.md`
/// is the LaunchAgent plist of the same mode plus `UserName`, `GroupName`
/// and a `HOME`. The fence is not rendered by qsh, so the comparison is not
/// byte for byte: the keys that decide what runs (`Label`,
/// `ProgramArguments`, `RunAtLoad`, `KeepAlive`, the two log paths) must equal
/// what the LaunchAgent renderer emits, and the additions must be there.
/// Nothing here runs `launchctl` or reads `/Library`.
#[test]
fn service_md_launchdaemon_recipe_matches_the_agent_program_arguments() {
    let service_md = read_doc("docs/deploy/service.md");
    let daemon = fence_after(
        &service_md,
        "`/Library/LaunchDaemons/io.qsh.serve.plist`:",
        "plist",
    );
    let agent = render_launchd_plist(
        "serve",
        DOC_EXAMPLE_EXE_MACOS,
        DOC_EXAMPLE_HOME_MACOS,
        DOC_EXAMPLE_CONTROLLER,
    );

    for key in [
        "Label",
        "ProgramArguments",
        "RunAtLoad",
        "KeepAlive",
        "StandardOutPath",
        "StandardErrorPath",
    ] {
        assert_eq!(
            plist_entry(&daemon, key),
            plist_entry(&agent, key),
            "the LaunchDaemon fence's `{key}` must equal the LaunchAgent renderer's"
        );
    }

    // `UserName` is the account the example home belongs to, and the daemon
    // gets no `HOME` of its own, so the recipe has to carry it.
    let user = DOC_EXAMPLE_HOME_MACOS
        .rsplit('/')
        .next()
        .expect("example home has a last component");
    assert_eq!(
        plist_entry(&daemon, "UserName"),
        format!("  <string>{user}</string>")
    );
    assert_eq!(
        plist_entry(&daemon, "GroupName"),
        "  <string>staff</string>"
    );
    let environment = plist_entry(&daemon, "EnvironmentVariables");
    assert!(
        environment.contains(&format!(
            "<key>HOME</key>\n    <string>{DOC_EXAMPLE_HOME_MACOS}</string>"
        )),
        "the LaunchDaemon fence must set HOME:\n{environment}"
    );
    assert!(
        !agent.contains("<key>UserName</key>") && !agent.contains("<key>GroupName</key>"),
        "the LaunchAgent renderer must not emit the daemon-only keys"
    );
}

/// ADR-0032 decisions 12, 13 and 16: the install, check and removal steps the
/// LaunchDaemon recipe gives, in the order a person runs them. They are the
/// human's commands: qsh runs none of them.
#[test]
fn service_md_launchdaemon_install_steps_are_in_order() {
    let service_md = read_doc("docs/deploy/service.md");
    let recipes = bash_fence_lines(&service_md);
    let daemon = "/Library/LaunchDaemons/io.qsh.serve.plist";
    let install = [
        "qsh service uninstall --deactivate".to_string(),
        format!("sudo cp io.qsh.serve.plist {daemon}"),
        format!("sudo chown root:wheel {daemon}"),
        format!("sudo chmod 644 {daemon}"),
        format!("sudo launchctl bootstrap system {daemon}"),
    ];
    let positions: Vec<usize> = install
        .iter()
        .map(|line| {
            recipes
                .iter()
                .position(|recipe| recipe == line)
                .unwrap_or_else(|| panic!("docs/deploy/service.md has no `{line}` line"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "the LaunchDaemon install steps are out of order: {positions:?}"
    );
    for line in [
        "sudo launchctl bootout system/io.qsh.serve".to_string(),
        format!("sudo rm {daemon}"),
        "sudo launchctl print system/io.qsh.serve".to_string(),
    ] {
        assert!(
            recipes.contains(&line),
            "docs/deploy/service.md has no `{line}` line"
        );
    }
    // The check line is the same query `status --live` would run as root.
    assert_eq!(
        launchd_print_system_argv("serve").join(" "),
        "launchctl print system/io.qsh.serve"
    );
}

/// ADR-0032 decision 15: both always-on recipes (linger and the LaunchDaemon)
/// tell a `platform` key store holder to move the key first, and the page
/// names the command the doctor finding recommends.
#[test]
fn service_md_always_on_recipes_point_at_move_key() {
    let service_md = read_doc("docs/deploy/service.md");
    let flattened = service_md.replace("\n", " ").replace("  ", " ");
    assert_eq!(
        flattened.matches("qsh identity move-key --to file").count(),
        2,
        "the launchd and the linger recipe each carry one move-key line"
    );
    assert!(
        qsh_core::doctor::KEYSTORE_SESSION_BOUND
            .remedy
            .contains("qsh identity move-key --to file")
    );
}
