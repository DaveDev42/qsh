//! `[listen].serve = true` does not change the service (ADR-0059 decision
//! 21): the mode is still inferred as `listen`, the unit is the `listen`
//! unit, and its bytes and argv are the ones a plain `[listen]` config gets.
//! Which of the two a process is comes from `config.toml` at start.

use super::*;

const COMBINED: &str = "[listen]\nserve = true\n";
const PLAIN_LISTEN: &str = "[listen]\nallow_advertised_names = true\n";

/// The mode and the unit text of an install under `config`, with the
/// tempdir home (which the launchd plist embeds) replaced by `<home>`.
fn installed_unit(manager: Manager, config: &str) -> (String, String) {
    let (_dir, ops) = ops_with(config);
    let runner = FakeRunner::default();
    let root = temp_home();
    let host = host_for(manager, &runner, root.path());
    let home = temp_home();
    let data = install(&ops, &host, &home, false).unwrap();
    let text = String::from_utf8(std::fs::read(&data.path).unwrap()).unwrap();
    (
        data.mode,
        text.replace(&home.path().display().to_string(), "<home>"),
    )
}

#[test]
fn service_unit_for_combined_mode_is_the_listen_unit() {
    // The key alone makes `[listen]` present, so the mode is `listen`, and it
    // beats the outbound keys exactly as any `[listen]` value does.
    let mut combined = Config::default();
    combined.listen.serve = true;
    assert_eq!(infer_run_mode(&combined), "listen");
    combined.serve.to = Some("ctrl".to_string());
    assert_eq!(infer_run_mode(&combined), "listen");

    for manager in BOTH_MANAGERS {
        let (mode, text) = installed_unit(manager, COMBINED);
        assert_eq!(mode, "listen", "{manager:?}");
        let (plain_mode, plain_text) = installed_unit(manager, PLAIN_LISTEN);
        assert_eq!(plain_mode, "listen");
        // The same unit: the argv is fixed per mode (threat model E10) and
        // carries no `--serve`.
        assert_eq!(text, plain_text, "{manager:?}");
        assert!(!text.contains("--serve"), "{text}");
    }
    assert_eq!(mode_argv("listen", ""), vec!["listen".to_string()]);

    // Status and uninstall find the same unit.
    for manager in BOTH_MANAGERS {
        let (_dir, ops) = ops_with(COMBINED);
        let runner = FakeRunner::default();
        let root = temp_home();
        let host = host_for(manager, &runner, root.path());
        let home = temp_home();
        let installed = install(&ops, &host, &home, false).unwrap();
        let shown = status(&ops, &host, &home, false).unwrap();
        assert_eq!(
            (shown.mode.as_str(), &shown.path),
            ("listen", &installed.path)
        );
        let removed = uninstall(&ops, &host, &home, false).unwrap();
        assert!(removed.removed);
        assert_eq!(removed.path, installed.path);
    }
}
