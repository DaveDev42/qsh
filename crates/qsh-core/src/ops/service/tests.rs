use super::*;

use crate::config::Paths;
use crate::ops::doctor::infer_run_mode;

fn temp_ops() -> (tempfile::TempDir, Ops) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, Ops::new(paths))
}

fn temp_home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn write_config(ops: &Ops, toml: &str) {
    std::fs::create_dir_all(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().config_file(), toml).unwrap();
}

// ---------------------------------------------------------------------
// Pure renderers and path builders — no HOME, no Ops, every platform.
// ---------------------------------------------------------------------

#[test]
fn launchd_plist_renders_the_fleet_semantics_for_each_mode() {
    for mode in ["serve", "listen", "reverse"] {
        let plist = render_launchd_plist(mode, "/exe", "/home/x", "ctrl");
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>\n"));
        assert!(plist.contains("<key>KeepAlive</key>\n  <true/>\n"));
        assert!(plist.contains("<key>ThrottleInterval</key>\n  <integer>15</integer>\n"));
        assert!(plist.contains("<key>ProcessType</key>\n  <string>Background</string>\n"));
        assert!(plist.contains("<key>HOME</key>\n    <string>/home/x</string>\n"));
        assert!(
            plist.contains(
                "<key>PATH</key>\n    <string>/opt/homebrew/bin:/usr/bin:/bin</string>\n"
            )
        );
        assert!(plist.contains(&format!(
            "<string>/home/x/Library/Logs/qsh/{mode}.out.log</string>"
        )));
        assert!(plist.contains(&format!(
            "<string>/home/x/Library/Logs/qsh/{mode}.err.log</string>"
        )));
    }
}

#[test]
fn plist_environment_variables_carry_no_xdg_keys() {
    for mode in ["serve", "listen", "reverse"] {
        let plist = render_launchd_plist(mode, "/exe", "/home/x", "ctrl");
        assert!(
            !plist.contains("XDG_"),
            "EnvironmentVariables must carry only HOME and PATH: {plist}"
        );
    }
}

#[test]
fn systemd_unit_renders_restart_always_for_each_mode() {
    for mode in ["serve", "listen", "reverse"] {
        let unit = render_systemd_unit(mode, "/exe", "ctrl");
        assert!(unit.contains("Restart=always\n"));
        assert!(unit.contains("RestartSec=2\n"));
        assert!(unit.contains("WantedBy=default.target\n"));
    }
}

#[test]
fn plist_escapes_xml_significant_characters_in_the_controller() {
    // `[serve].to`/`[reverse].controller` is a free-form config string —
    // `config_outbound_target` does not restrict its characters — so a
    // value containing `&`, `<` or `>` must not break the plist's XML.
    let plist = render_launchd_plist("reverse", "/exe", "/home/x", "a&b<c>d");
    assert!(
        plist.contains("<string>serve</string>\n    <string>--to</string>\n    <string>a&amp;b&lt;c&gt;d</string>\n"),
        "{plist}"
    );
    assert!(
        !plist.contains("a&b<c>d"),
        "raw value must not appear unescaped: {plist}"
    );
}

#[test]
fn systemd_unit_quotes_a_controller_with_whitespace() {
    let unit = render_systemd_unit("reverse", "/exe", "a controller");
    assert!(
        unit.contains("ExecStart=/exe serve --to \"a controller\"\n"),
        "{unit}"
    );
}

#[test]
fn reverse_mode_units_invoke_serve_to_not_the_hidden_alias() {
    // The file/label token stays `reverse` (`docs/CLI.md` §6.18)...
    let plist = render_launchd_plist("reverse", "/exe", "/home/x", "ctrl-name");
    assert!(plist.contains("<string>io.qsh.reverse</string>"));
    // ...but the argv it launches is `serve --to <controller>`, never the
    // hidden `reverse <controller>` alias.
    assert!(plist.contains(
        "<string>serve</string>\n    <string>--to</string>\n    <string>ctrl-name</string>\n"
    ));
    assert!(!plist.contains("<string>reverse</string>\n"));

    let unit = render_systemd_unit("reverse", "/exe", "ctrl-name");
    assert!(unit.contains("ExecStart=/exe serve --to ctrl-name\n"));
    assert!(unit.contains("Description=qsh serve --to\n"));
}

#[test]
fn unit_arguments_are_fixed() {
    // No `--bind`, no `--name`, no config or verbosity flag ever reaches
    // the argv — exactly the three fixed shapes below, nothing else.
    assert_eq!(mode_argv("serve", "ctrl"), vec!["serve".to_string()]);
    assert_eq!(mode_argv("listen", "ctrl"), vec!["listen".to_string()]);
    assert_eq!(
        mode_argv("reverse", "ctrl"),
        vec!["serve".to_string(), "--to".to_string(), "ctrl".to_string()]
    );
}

#[test]
fn install_path_matches_the_doctor_probe_path_for_every_mode() {
    let home = temp_home();
    for mode in ["serve", "listen", "reverse"] {
        assert_eq!(
            unit_path(Manager::Launchd, home.path(), mode),
            crate::doctor::probe::macos_launchagent_path(home.path(), mode)
        );
        assert_eq!(
            unit_path(Manager::Systemd, home.path(), mode),
            crate::doctor::probe::linux_systemd_user_unit_path(home.path(), mode)
        );
    }
}

#[test]
fn mode_vocabularies_agree() {
    // `infer_run_mode`'s three return values are exactly the tokens the
    // unit paths/renderers key their per-mode behaviour off, and the same
    // three `qsh-cli`'s `SERVE_MODE`/`LISTEN_MODE`/`REVERSE_MODE`
    // constants spell (`"serve"`/`"listen"`/`"reverse"`).
    let mut only_default = Config::default();
    assert_eq!(infer_run_mode(&only_default), "serve");

    let mut only_listen = Config::default();
    only_listen.listen.allow_advertised_names = true;
    assert_eq!(infer_run_mode(&only_listen), "listen");

    only_default.serve.to = Some("ctrl".to_string());
    assert_eq!(infer_run_mode(&only_default), "reverse");
}

// ---------------------------------------------------------------------
// The *_with_home seam — real Ops, an explicit tempdir home, never
// `crate::config::home_dir()`'s real value (module doc).
// ---------------------------------------------------------------------

#[test]
fn mode_inference_covers_the_four_config_shapes() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let cases: [(&str, &str); 4] = [
        ("", "serve"),
        ("[listen]\nallow_advertised_names = true\n", "listen"),
        ("[serve]\nto = \"ctrl\"\n", "reverse"),
        ("[reverse]\ncontroller = \"ctrl\"\n", "reverse"),
    ];
    for (toml, expected_mode) in cases {
        let (_dir, ops) = temp_ops();
        if !toml.is_empty() {
            write_config(&ops, toml);
        }
        let home = temp_home();
        let data = ops
            .service_status_with_home(Some(home.path().to_path_buf()))
            .unwrap();
        assert_eq!(data.mode, expected_mode, "config: {toml:?}");
    }
}

#[test]
fn config_conflict_is_config_error_and_writes_nothing() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    write_config(&ops, "[serve]\nto = \"a\"\n[reverse]\ncontroller = \"b\"\n");
    let home = temp_home();
    let err = ops
        .service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    // The conflict is caught at step 3, strictly before step 5 (home
    // resolution) and step 9 (the write) — nothing was created anywhere
    // under the tempdir home.
    assert!(!home.path().join("Library").exists());
    assert!(!home.path().join(".config").exists());
}

/// `docs/CLI.md` §6.18: all three ops apply the same steps 1-6, so
/// `uninstall` and `status` fail the same `CONFIG_ERROR` as `install`
/// on the `[serve].to`/`[reverse].controller` disagreement — not just the
/// writing op.
#[test]
fn config_conflict_is_config_error_for_uninstall_and_status_too() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    write_config(&ops, "[serve]\nto = \"a\"\n[reverse]\ncontroller = \"b\"\n");

    let home = temp_home();
    let err = ops
        .service_uninstall_with_home(Some(home.path().to_path_buf()))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(!home.path().join("Library").exists());
    assert!(!home.path().join(".config").exists());

    let home = temp_home();
    let err = ops
        .service_status_with_home(Some(home.path().to_path_buf()))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
}

#[test]
fn config_conflict_with_equal_values_installs_normally() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    write_config(
        &ops,
        "[serve]\nto = \"same\"\n[reverse]\ncontroller = \"same\"\n",
    );
    let home = temp_home();
    let data = ops
        .service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap();
    assert_eq!(data.mode, "reverse");
    assert!(data.created);
}

#[test]
fn install_is_idempotent_and_reports_created_only_the_first_time() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    let home = temp_home();
    let first = ops
        .service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap();
    assert!(first.created);
    let bytes_first = std::fs::read(&first.path).unwrap();

    let second = ops
        .service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap();
    assert!(!second.created);
    let bytes_second = std::fs::read(&second.path).unwrap();
    assert_eq!(bytes_first, bytes_second);
}

/// `docs/CLI.md` §6.18 / `docs/deploy/service.md`: `install` does not own
/// the unit's parent directory (`~/Library/LaunchAgents` holds every other
/// application's agents too), so a pre-existing directory's mode is left
/// exactly as it was — only the unit file itself is written 0600. Pinned
/// here at the `service install` level so the documented behavior cannot
/// silently regress back to tightening a directory qsh does not own.
#[cfg(unix)]
#[test]
fn install_leaves_an_existing_unit_directory_mode_alone() {
    use std::os::unix::fs::PermissionsExt as _;

    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    let home = temp_home();
    let manager = if cfg!(target_os = "macos") {
        Manager::Launchd
    } else {
        Manager::Systemd
    };
    let parent = unit_path(manager, home.path(), "serve")
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

    let data = ops
        .service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap();

    let dir_mode = std::fs::metadata(&parent).unwrap().permissions().mode();
    assert_eq!(
        dir_mode & 0o777,
        0o755,
        "a pre-existing unit directory's mode must be left alone"
    );
    let file_mode = std::fs::metadata(&data.path).unwrap().permissions().mode();
    assert_eq!(file_mode & 0o777, 0o600, "the unit file itself is 0600");
}

/// The other half of the create-if-absent contract: when the unit
/// directory does not exist yet, `install` still creates it (and the unit
/// file inside it) rather than failing.
#[test]
fn install_creates_a_missing_unit_directory() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    let home = temp_home();
    let manager = if cfg!(target_os = "macos") {
        Manager::Launchd
    } else {
        Manager::Systemd
    };
    let parent = unit_path(manager, home.path(), "serve")
        .parent()
        .unwrap()
        .to_path_buf();
    assert!(!parent.exists());

    let data = ops
        .service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap();

    assert!(parent.exists());
    assert!(std::path::Path::new(&data.path).exists());
}

#[test]
fn uninstall_on_an_absent_unit_is_ok_and_reports_removed_false() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    let home = temp_home();
    let data = ops
        .service_uninstall_with_home(Some(home.path().to_path_buf()))
        .unwrap();
    assert!(!data.removed);

    // A unit `qsh` did not write is removed all the same (`docs/CLI.md`
    // §6.18) — the contract is the path, not provenance.
    let manager = if cfg!(target_os = "macos") {
        Manager::Launchd
    } else {
        Manager::Systemd
    };
    let path = unit_path(manager, home.path(), "serve");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, "hand-authored").unwrap();
    let data = ops
        .service_uninstall_with_home(Some(home.path().to_path_buf()))
        .unwrap();
    assert!(data.removed);
    assert!(!path.exists());
}

#[test]
fn status_flips_from_false_to_true_across_install() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    let home = temp_home();
    let before = ops
        .service_status_with_home(Some(home.path().to_path_buf()))
        .unwrap();
    assert!(!before.installed);

    ops.service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap();

    let after = ops
        .service_status_with_home(Some(home.path().to_path_buf()))
        .unwrap();
    assert!(after.installed);
}

#[test]
fn unsupported_platform_is_reported_before_the_home_directory_is_even_read() {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    // A config.toml `Config::load` would refuse with `CONFIG_ERROR` if
    // step 2 ever ran — on this (unsupported) platform it must not, since
    // step 1's manager check comes first and fails closed on its own.
    std::fs::create_dir_all(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().config_file(), "not valid toml === {{{").unwrap();

    let err = ops.service_install_with_home(None).unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert!(err.message.contains("P1"));
}

#[test]
fn install_is_refused_when_the_audit_sink_fails() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let (_dir, ops) = temp_ops();
    let sink = std::sync::Arc::new(crate::audit::FailingAuditSink::new());
    sink.fail();
    let ops = ops.with_audit_sink(sink.clone());
    let home = temp_home();

    let err = ops
        .service_install_with_home(Some(home.path().to_path_buf()))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.retryable);
    assert!(sink.records().is_empty());

    let manager = if cfg!(target_os = "macos") {
        Manager::Launchd
    } else {
        Manager::Systemd
    };
    let path = unit_path(manager, home.path(), "serve");
    assert!(
        !path.exists(),
        "no unit may be written when the audit record fails"
    );
}
