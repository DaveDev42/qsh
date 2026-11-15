use super::*;

fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<PathBuf> + use<> {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    move |key| {
        owned
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| PathBuf::from(v))
    }
}

#[test]
fn explicit_override_wins_over_xdg_and_home() {
    let paths = Paths::from_lookup(
        lookup(&[
            ("QSH_CONFIG_DIR", "/explicit/config"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("XDG_STATE_HOME", "/xdgstate"),
        ]),
        Some(PathBuf::from("/home/dave")),
    )
    .unwrap();
    assert_eq!(paths.config_dir, PathBuf::from("/explicit/config"));
    assert_eq!(paths.state_dir, PathBuf::from("/xdgstate/qsh"));
}

#[test]
fn home_is_the_last_resort() {
    let paths = Paths::from_lookup(lookup(&[]), Some(PathBuf::from("/home/dave"))).unwrap();
    assert_eq!(paths.config_dir, PathBuf::from("/home/dave/.config/qsh"));
    assert_eq!(
        paths.state_dir,
        PathBuf::from("/home/dave/.local/state/qsh")
    );
}

#[test]
fn missing_home_is_a_config_error() {
    let err = Paths::from_lookup(lookup(&[]), None).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(!err.retryable);
}

#[test]
fn derived_paths_hang_off_the_two_roots() {
    let paths = Paths::new("/c", "/s");
    assert_eq!(paths.config_file(), PathBuf::from("/c/config.toml"));
    assert_eq!(paths.trust_file(), PathBuf::from("/c/trust.toml"));
    assert_eq!(paths.hosts_file(), PathBuf::from("/c/hosts.toml"));
    assert_eq!(paths.identity_dir(), PathBuf::from("/c/identity"));
    assert_eq!(paths.audit_log(), PathBuf::from("/s/audit.log"));
}

#[test]
fn runtime_dir_prefers_xdg_runtime_dir_over_the_state_dir_fallback() {
    // architecture.md §7: `$XDG_RUNTIME_DIR/qsh` — no `$QSH_RUNTIME_DIR`
    // override exists in the documented contract (unlike config/state).
    let paths = Paths::new("/c", "/s");
    let dir = paths.runtime_dir_from(lookup(&[("XDG_RUNTIME_DIR", "/run/user/1000")]));
    assert_eq!(dir, PathBuf::from("/run/user/1000/qsh"));
}

#[test]
fn runtime_dir_falls_back_to_state_dir_run_when_xdg_runtime_dir_is_unset_or_empty() {
    let paths = Paths::new("/c", "/s");
    assert_eq!(paths.runtime_dir_from(lookup(&[])), PathBuf::from("/s/run"));
    // An explicitly empty value is treated the same as unset (same
    // discipline `Paths::from_lookup`'s `resolve` closure applies).
    assert_eq!(
        paths.runtime_dir_from(lookup(&[("XDG_RUNTIME_DIR", "")])),
        PathBuf::from("/s/run")
    );
}

#[test]
fn localctl_socket_is_pid_dot_sock_under_the_runtime_dir() {
    // Deliberately does not exercise the env-reading `runtime_dir()`
    // (adversarial review finding: doing so made this test's outcome
    // depend on whatever `$XDG_RUNTIME_DIR` the process happened to
    // inherit — reproducibly failing under `cargo nextest
    // run --workspace` on any Linux/WSL2 systemd-logind session). Pin
    // the join logic through the deterministic override instead —
    // `runtime_dir_prefers_xdg_runtime_dir_over_the_state_dir_fallback`
    // and `runtime_dir_falls_back_to_state_dir_run_when_xdg_runtime_dir_is_unset_or_empty`
    // already cover the env-precedence rule via the pure
    // `runtime_dir_from` function.
    let paths = Paths::new("/c", "/s").with_runtime_dir("/s/run");
    assert_eq!(
        paths.localctl_socket(4242),
        PathBuf::from("/s/run/4242.sock")
    );
}

#[test]
fn with_runtime_dir_overrides_both_env_and_the_state_dir_fallback() {
    // The override must win even when `$XDG_RUNTIME_DIR` is also
    // present in the lookup closure — it is a stronger, test-only
    // pin, not merely another fallback tier.
    let paths = Paths::new("/c", "/s").with_runtime_dir("/tmp/sandboxed/run");
    assert_eq!(paths.runtime_dir(), PathBuf::from("/tmp/sandboxed/run"));
    assert_eq!(
        paths.localctl_socket(4242),
        PathBuf::from("/tmp/sandboxed/run/4242.sock")
    );
}

#[test]
fn missing_config_file_is_default() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    let config = Config::load(&paths).unwrap();
    assert_eq!(config, Config::default());
    assert!(config.identity.key_store.is_none());
}

#[test]
fn config_file_is_parsed_and_unknown_keys_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    std::fs::write(
        paths.config_file(),
        "[identity]\nkey_store = \"file\"\n\n[serve]\nbind = \"127.0.0.1:4433\"\n\n\
         [future]\nsomething = 1\n",
    )
    .unwrap();
    let config = Config::load(&paths).unwrap();
    assert_eq!(config.identity.key_store, Some(KeyStoreMode::File));
    assert_eq!(config.serve.bind.as_deref(), Some("127.0.0.1:4433"));
}

#[test]
fn serve_broker_keys_use_the_documented_names_and_defaults() {
    // architecture.md §7 / M9 plan Step 2 (b9a621b): `[serve] replay_bytes ·
    // resume_ttl · close_grace_ms`. Unknown keys are ignored, so a
    // misnamed key would silently fall back to the default — pin the
    // documented spellings.
    let serve: ServeConfig =
        toml::from_str("replay_bytes = 1024\nresume_ttl = 60\nclose_grace_ms = 250\n").unwrap();
    assert_eq!(serve.replay_bytes(), 1024);
    assert_eq!(serve.resume_ttl(), std::time::Duration::from_secs(60));
    assert_eq!(serve.close_grace(), std::time::Duration::from_millis(250));
    // The `_secs` spelling is an accepted alias.
    let alias: ServeConfig = toml::from_str("resume_ttl_secs = 5\n").unwrap();
    assert_eq!(alias.resume_ttl(), std::time::Duration::from_secs(5));
    // Defaults: 8 MiB, 24 h, 5 s; replay_bytes = 0 degrades to default.
    let empty: ServeConfig = toml::from_str("replay_bytes = 0\n").unwrap();
    assert_eq!(empty.replay_bytes(), 8 * 1024 * 1024);
    assert_eq!(
        empty.resume_ttl(),
        std::time::Duration::from_secs(24 * 3600)
    );
    assert_eq!(empty.close_grace(), std::time::Duration::from_millis(5000));
}

#[test]
fn admission_keys_use_the_documented_names_and_defaults() {
    // architecture.md §7 / CLI.md §6.12, M8 plan Step 2 (52639fc):
    // `[serve] max_concurrent_handshakes(64) · handshake_rate_per_source(10)`.
    let serve: ServeConfig =
        toml::from_str("max_concurrent_handshakes = 8\nhandshake_rate_per_source = 3\n").unwrap();
    assert_eq!(serve.max_concurrent_handshakes(), 8);
    assert_eq!(serve.handshake_rate_per_source(), 3);

    // Defaults: 64 / 10; `0` degrades to the default rather than
    // meaning "unlimited" — this defense has no off switch.
    let empty: ServeConfig =
        toml::from_str("max_concurrent_handshakes = 0\nhandshake_rate_per_source = 0\n").unwrap();
    assert_eq!(empty.max_concurrent_handshakes(), 64);
    assert_eq!(empty.handshake_rate_per_source(), 10);

    let absent = ServeConfig::default();
    assert_eq!(absent.max_concurrent_handshakes(), 64);
    assert_eq!(absent.handshake_rate_per_source(), 10);
}

#[test]
fn quota_keys_use_the_documented_names_and_defaults() {
    // `crate::quota`, M8 plan Step 3 (52639fc), docs/adr/0010-resource-
    // quotas.md: `[serve] max_sessions(256) ·
    // max_sessions_per_principal(32) · max_exec_per_principal(32) ·
    // validated_rate_per_source(10)`.
    let serve: ServeConfig = toml::from_str(
        "max_sessions = 10\n\
         max_sessions_per_principal = 4\n\
         max_exec_per_principal = 5\n\
         validated_rate_per_source = 7\n",
    )
    .unwrap();
    assert_eq!(serve.max_sessions(), 10);
    assert_eq!(serve.max_sessions_per_principal(), 4);
    assert_eq!(serve.max_exec_per_principal(), 5);
    assert_eq!(serve.validated_rate_per_source(), 7);

    // Defaults: 256 / 32 / 32 / 10; `0` degrades to the default
    // rather than meaning "unlimited" — this defense has no off
    // switch.
    let zero: ServeConfig = toml::from_str(
        "max_sessions = 0\n\
         max_sessions_per_principal = 0\n\
         max_exec_per_principal = 0\n\
         validated_rate_per_source = 0\n",
    )
    .unwrap();
    assert_eq!(zero.max_sessions(), 256);
    assert_eq!(zero.max_sessions_per_principal(), 32);
    assert_eq!(zero.max_exec_per_principal(), 32);
    assert_eq!(zero.validated_rate_per_source(), 10);

    let absent = ServeConfig::default();
    assert_eq!(absent.max_sessions(), 256);
    assert_eq!(absent.max_sessions_per_principal(), 32);
    assert_eq!(absent.max_exec_per_principal(), 32);
    assert_eq!(absent.validated_rate_per_source(), 10);
}

#[test]
fn audit_keys_use_the_documented_names_and_defaults() {
    // architecture.md §7 / §6, M5 plan Step 1 (2473c88): `[audit] path ·
    // max_bytes(64 MiB) · retain(5) · queue_depth(1024)`, and no
    // `fail_closed` knob — that is fixed policy, not configurable.
    let audit: AuditConfig = toml::from_str(
        "path = \"/custom/audit.log\"\nmax_bytes = 1048576\nretain = 3\nqueue_depth = 64\n",
    )
    .unwrap();
    let paths = Paths::new("/c", "/s");
    assert_eq!(audit.path(&paths), PathBuf::from("/custom/audit.log"));
    assert_eq!(audit.max_bytes(), 1_048_576);
    assert_eq!(audit.retain(), 3);
    assert_eq!(audit.queue_depth(), 64);

    // Defaults: absent ⇒ Paths::audit_log() / 64 MiB / 5 / 1024.
    let empty = AuditConfig::default();
    assert_eq!(empty.path, None);
    assert_eq!(empty.path(&paths), paths.audit_log());
    assert_eq!(empty.max_bytes(), 64 * 1024 * 1024);
    assert_eq!(empty.retain(), 5);
    assert_eq!(empty.queue_depth(), 1024);
    assert_eq!(AuditConfig::DEFAULT_MAX_BYTES, 64 * 1024 * 1024);
    assert_eq!(AuditConfig::DEFAULT_RETAIN, 5);
    assert_eq!(AuditConfig::DEFAULT_QUEUE_DEPTH, 1024);

    // `0` degrades to the default, same discipline as
    // `ServeConfig::replay_bytes`.
    let zeroed = AuditConfig {
        max_bytes: Some(0),
        queue_depth: Some(0),
        ..Default::default()
    };
    assert_eq!(zeroed.max_bytes(), 64 * 1024 * 1024);
    assert_eq!(zeroed.queue_depth(), 1024);
}

#[test]
fn audit_config_is_absent_by_default_and_ignores_unknown_keys() {
    // A `config.toml` with no `[audit]` section at all parses to
    // `AuditConfig::default()` (docs/CLI.md §2.3 unknown-field
    // tolerance's mirror image: an absent *known* section is not an
    // error either), and an unrecognized key inside `[audit]` is
    // ignored rather than failing the parse — same idiom
    // `config_file_is_parsed_and_unknown_keys_ignored` already checks
    // for `[future]`.
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    std::fs::write(paths.config_file(), "[identity]\nkey_store = \"file\"\n").unwrap();
    let config = Config::load(&paths).unwrap();
    assert_eq!(config.audit, AuditConfig::default());

    std::fs::write(
        paths.config_file(),
        "[audit]\nmax_bytes = 2048\nunknown_future_key = \"x\"\n",
    )
    .unwrap();
    let config = Config::load(&paths).unwrap();
    assert_eq!(config.audit.max_bytes(), 2048);
    assert_eq!(config.audit.retain(), AuditConfig::DEFAULT_RETAIN);
}

#[test]
fn listen_and_reverse_keys_use_the_documented_names_and_defaults() {
    // architecture.md §7 / CLI.md §6.13 / M9 plan Step 3 (b9a621b) PR 3a:
    // `[listen] bind · allow_advertised_names` and `[reverse]
    // controller · offered_name`. Pin the documented spellings and the
    // `allow_advertised_names = false` default (name-squatting
    // prevention wins unless explicitly opted into).
    let listen: ListenConfig =
        toml::from_str("bind = \"[::]:5000\"\nallow_advertised_names = true\n").unwrap();
    assert_eq!(listen.bind.as_deref(), Some("[::]:5000"));
    assert!(listen.allow_advertised_names);

    let listen_default = ListenConfig::default();
    assert_eq!(listen_default.bind, None);
    assert!(!listen_default.allow_advertised_names);

    let reverse: ReverseConfig =
        toml::from_str("controller = \"personal-mac\"\noffered_name = \"phone\"\n").unwrap();
    assert_eq!(reverse.controller.as_deref(), Some("personal-mac"));
    assert_eq!(reverse.offered_name.as_deref(), Some("phone"));

    let reverse_default = ReverseConfig::default();
    assert_eq!(reverse_default.controller, None);
    assert_eq!(reverse_default.offered_name, None);
}

#[test]
fn transport_keep_alive_ms_outside_1000_to_20000_is_config_error_without_clamping() {
    // ADR-0021 decision 1: 1000..=20000, out of range is a startup error,
    // never a clamp (the same shape as `ReverseConfig::backoff`).
    for bad in [0, 999, 20_001, u64::MAX] {
        let transport = TransportConfig {
            keep_alive_ms: Some(bad),
            adaptive: None,
        };
        let err = transport.keep_alive().unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError, "{bad}");
        assert!(!err.retryable, "{bad}");
        assert!(
            err.message.contains(&format!(
                "[transport].keep_alive_ms ({bad}) must be within 1000..=20000"
            )),
            "{}",
            err.message
        );
        // The same value fails the whole-config validation too, which is
        // what every daemon runs at startup.
        let config = Config {
            transport,
            ..Config::default()
        };
        assert_eq!(config.liveness().unwrap_err().code, ErrorCode::ConfigError);
    }
    for ok in [1_000, 5_000, 20_000] {
        let transport = TransportConfig {
            keep_alive_ms: Some(ok),
            adaptive: None,
        };
        assert_eq!(
            transport.keep_alive().unwrap(),
            std::time::Duration::from_millis(ok)
        );
    }
}

#[test]
fn absent_transport_section_keeps_the_fifteen_second_keep_alive() {
    use qsh_transport::TransportTuning;
    use qsh_transport::endpoint::{KEEP_ALIVE_INTERVAL, transport_config_debug};

    let config: Config = toml::from_str("").unwrap();
    assert_eq!(config.transport, TransportConfig::default());
    let liveness = config.liveness().unwrap();
    assert_eq!(liveness.keep_alive, std::time::Duration::from_secs(15));
    assert_eq!(liveness.keep_alive, KEEP_ALIVE_INTERVAL);
    assert_eq!(liveness.tuning(), TransportTuning::default());

    // The quinn config built from an absent section is byte-identical to
    // the one built before the section existed (the compiled default), and
    // an empty `[transport]` table changes nothing either.
    let before = transport_config_debug(TransportTuning::default());
    assert_eq!(transport_config_debug(liveness.tuning()), before);
    assert!(
        before.contains("keep_alive_interval: Some(15s)"),
        "{before}"
    );
    let empty_table: Config = toml::from_str("[transport]\n").unwrap();
    assert_eq!(
        transport_config_debug(empty_table.liveness().unwrap().tuning()),
        before
    );
}

#[test]
fn keep_alive_ms_reaches_the_quinn_transport_config() {
    use qsh_transport::endpoint::{KEEP_ALIVE_INTERVAL, MAX_IDLE_TIMEOUT, transport_config_debug};

    let config: Config = toml::from_str("[transport]\nkeep_alive_ms = 5000\n").unwrap();
    let tuning = config.liveness().unwrap().tuning();
    assert_eq!(tuning.keep_alive, std::time::Duration::from_secs(5));
    let tuned = transport_config_debug(tuning);
    assert!(tuned.contains("keep_alive_interval: Some(5s)"), "{tuned}");
    // Only the keep-alive moved: the idle timeout stays the fixed 45 s
    // (ADR-0021 decision 2) and every other field renders as before.
    assert!(tuned.contains("max_idle_timeout: Some(45000)"), "{tuned}");
    assert_eq!(MAX_IDLE_TIMEOUT, std::time::Duration::from_secs(45));
    let default = transport_config_debug(qsh_transport::TransportTuning {
        keep_alive: KEEP_ALIVE_INTERVAL,
    });
    assert_eq!(
        tuned.replace(
            "keep_alive_interval: Some(5s)",
            "keep_alive_interval: Some(15s)"
        ),
        default
    );
}

fn recovery(probe: Option<u64>, dead: Option<u64>, strikes: Option<u32>) -> RecoverySection {
    RecoverySection {
        probe_interval_ms: probe,
        min_dead_after_ms: dead,
        strikes,
        ..RecoverySection::default()
    }
}

#[test]
fn recovery_keys_use_the_documented_names_and_defaults() {
    use std::time::Duration;

    let config: Config = toml::from_str(
        "[recovery]\nprobe_interval_ms = 100\nmin_dead_after_ms = 800\nstrikes = 4\n",
    )
    .unwrap();
    assert_eq!(config.recovery, recovery(Some(100), Some(800), Some(4)));
    let watch = config.liveness().unwrap().watch;
    assert_eq!(watch.probe_interval, Duration::from_millis(100));
    assert_eq!(watch.min_dead_after, Duration::from_millis(800));
    assert_eq!(watch.strikes, 4);
    // The three closed knobs keep their defaults.
    let defaults = PathWatchConfig::default();
    assert_eq!(watch.idle_probe_interval, defaults.idle_probe_interval);
    assert_eq!(watch.active_window, defaults.active_window);
    assert_eq!(watch.rtt_multiple, defaults.rtt_multiple);
    // A key left out falls back to its own default, not to a zero.
    let partial: Config = toml::from_str("[recovery]\nstrikes = 2\n").unwrap();
    let watch = partial.liveness().unwrap().watch;
    assert_eq!(watch.probe_interval, defaults.probe_interval);
    assert_eq!(watch.min_dead_after, defaults.min_dead_after);
    assert_eq!(watch.strikes, 2);
}

#[test]
fn recovery_values_beyond_the_detection_budget_bound_are_config_error() {
    // P*S+D <= 2000, S >= 2, 50 <= P <= D (ADR-0021 decision 4), and an
    // out-of-range value is a startup error, never a clamp.
    let bad = [
        // 2001 in total: 250*3 + 1251.
        recovery(None, Some(1_251), None),
        // One strike is not a verdict.
        recovery(None, None, Some(1)),
        recovery(None, None, Some(0)),
        // Below the tick floor.
        recovery(Some(49), Some(1_000), Some(3)),
        recovery(Some(0), None, None),
        // The probe cadence slower than the silence floor.
        recovery(Some(600), Some(500), Some(2)),
        // Each product that would wrap or blow the ceiling.
        recovery(Some(u64::MAX), Some(u64::MAX), Some(u32::MAX)),
        recovery(Some(667), Some(700), Some(2)),
        recovery(None, None, Some(40)),
    ];
    for section in bad {
        let err = section.path_watch().unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError, "{section:?}");
        assert!(!err.retryable, "{section:?}");
        assert!(err.message.contains("[recovery]"), "{}", err.message);
        let config = Config {
            recovery: section.clone(),
            ..Config::default()
        };
        assert_eq!(
            config.liveness().unwrap_err().code,
            ErrorCode::ConfigError,
            "{section:?}"
        );
    }
    // Exactly 2000 passes, at the edges the bound implies.
    for ok in [
        recovery(Some(250), Some(1_250), Some(3)),
        recovery(Some(50), Some(1_900), Some(2)),
        recovery(Some(666), Some(668), Some(2)),
        recovery(Some(50), Some(50), Some(39)),
        recovery(Some(250), Some(1_000), Some(3)),
    ] {
        let watch = ok.path_watch().unwrap();
        let budget = watch.probe_interval * watch.strikes + watch.min_dead_after;
        assert!(
            budget <= std::time::Duration::from_millis(RECOVERY_DETECTION_CEILING_MS),
            "{ok:?}"
        );
    }
}

#[test]
fn absent_recovery_section_keeps_todays_path_watch_config_byte_identically() {
    let defaults = format!("{:?}", PathWatchConfig::default());
    let absent: Config = toml::from_str("").unwrap();
    assert_eq!(absent.recovery, RecoverySection::default());
    assert_eq!(format!("{:?}", absent.liveness().unwrap().watch), defaults);
    // An empty `[recovery]` table changes nothing either.
    let empty: Config = toml::from_str("[recovery]\n").unwrap();
    assert_eq!(format!("{:?}", empty.liveness().unwrap().watch), defaults);
    // What an attach runs with when nothing overrides it.
    assert_eq!(
        format!("{:?}", crate::ops::RecoveryConfig::default().watch),
        defaults
    );
    // The numbers the defaults must keep (ADR-0021 decision 4).
    let watch = absent.liveness().unwrap().watch;
    assert_eq!(watch.probe_interval, std::time::Duration::from_millis(250));
    assert_eq!(watch.min_dead_after, std::time::Duration::from_secs(1));
    assert_eq!(watch.strikes, 3);
}

#[test]
fn recovery_section_reaches_attach_and_supervised_path_watch() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    std::fs::create_dir_all(&paths.config_dir).unwrap();
    std::fs::write(
        paths.config_file(),
        "[recovery]\nprobe_interval_ms = 100\nmin_dead_after_ms = 600\nstrikes = 5\n",
    )
    .unwrap();
    let ops = crate::ops::Ops::new(paths);
    let liveness = ops.liveness().unwrap();
    let expected = ops.config().unwrap().recovery.path_watch().unwrap();
    assert_eq!(liveness.watch, expected);
    assert_ne!(liveness.watch, PathWatchConfig::default());

    // Attach and supervised tunnels: `effective_recovery` feeds
    // `AttachContext.recovery` and `Supervision.recovery`.
    let recovery = ops.effective_recovery(&liveness);
    assert_eq!(recovery.watch, expected);
    assert_eq!(
        crate::ops::RecoveryConfig {
            watch: PathWatchConfig::default(),
            ..recovery
        },
        crate::ops::RecoveryConfig::default()
    );
}

#[test]
fn config_file_parses_listen_and_reverse_sections() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    std::fs::write(
        paths.config_file(),
        "[listen]\nbind = \"127.0.0.1:5000\"\nallow_advertised_names = true\n\n\
         [reverse]\ncontroller = \"personal-mac\"\noffered_name = \"phone\"\n",
    )
    .unwrap();
    let config = Config::load(&paths).unwrap();
    assert_eq!(config.listen.bind.as_deref(), Some("127.0.0.1:5000"));
    assert!(config.listen.allow_advertised_names);
    assert_eq!(config.reverse.controller.as_deref(), Some("personal-mac"));
    assert_eq!(config.reverse.offered_name.as_deref(), Some("phone"));
}

#[test]
fn malformed_config_file_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    std::fs::write(paths.config_file(), "[identity\nkey_store =").unwrap();
    let err = Config::load(&paths).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(!err.retryable);
    assert!(
        err.message.contains("config.toml"),
        "message: {}",
        err.message
    );
}

#[test]
fn now_rfc3339_has_second_granularity_and_z_suffix() {
    let now = now_rfc3339();
    assert!(now.ends_with('Z'), "{now}");
    assert_eq!(now.len(), "2026-08-17T00:00:00Z".len(), "{now}");
    assert!(OffsetDateTime::parse(&now, &Rfc3339).is_ok(), "{now}");
}

#[cfg(unix)]
#[test]
fn private_dir_and_file_modes() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a/b");
    ensure_private_dir(&nested).unwrap();
    let mode = std::fs::metadata(&nested).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);

    // Idempotent, and tightens an already-loose directory.
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
    ensure_private_dir(&nested).unwrap();
    let mode = std::fs::metadata(&nested).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);

    let file = nested.join("secret");
    write_private_file(&file, b"hello").unwrap();
    let mode = std::fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(std::fs::read(&file).unwrap(), b"hello");

    // Overwriting keeps 0600 and leaves no temp file behind.
    write_private_file(&file, b"world").unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"world");
    let leftovers: Vec<_> = std::fs::read_dir(&nested)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp file left behind");
}

// ---------------------------------------------------------------------
// `[ssh]` (ADR-0044 decisions 2, 4, 9)
// ---------------------------------------------------------------------

fn load_text(text: &str) -> Result<Config, OpError> {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path(), dir.path());
    std::fs::write(paths.config_file(), text).unwrap();
    Config::load(&paths)
}

#[test]
fn ssh_section_defaults_are_auto_ssh_and_qsh() {
    let config = Config::default();
    assert_eq!(config.ssh.bootstrap_mode(), SshBootstrapMode::Auto);
    assert_eq!(config.ssh.program().unwrap(), SshConfig::DEFAULT_PROGRAM);
    assert_eq!(
        SshConfig::DEFAULT_PROGRAM,
        if cfg!(windows) { "ssh.exe" } else { "ssh" }
    );
    assert_eq!(config.ssh.remote_qsh().unwrap(), "qsh");
}

#[test]
fn ssh_section_reads_the_three_keys() {
    let config = load_text(
        "[ssh]\nbootstrap = \"off\"\nprogram = \"/opt/openssh/bin/ssh\"\n\
         remote_qsh = \"/usr/local/bin/qsh\"\n",
    )
    .unwrap();
    assert_eq!(config.ssh.bootstrap_mode(), SshBootstrapMode::Off);
    assert_eq!(config.ssh.program().unwrap(), "/opt/openssh/bin/ssh");
    assert_eq!(config.ssh.remote_qsh().unwrap(), "/usr/local/bin/qsh");
    let auto = load_text("[ssh]\nbootstrap = \"auto\"\n").unwrap();
    assert_eq!(auto.ssh.bootstrap_mode(), SshBootstrapMode::Auto);
}

#[test]
fn ssh_config_bootstrap_value_outside_auto_off_is_a_config_error() {
    for bad in ["\"on\"", "\"Auto\"", "\"\"", "true", "1", "\"always\""] {
        let err = load_text(&format!("[ssh]\nbootstrap = {bad}\n")).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError, "{bad}");
        assert!(!err.retryable, "{bad}");
    }
}

#[test]
fn ssh_config_blank_program_or_remote_qsh_is_a_config_error() {
    let config = load_text("[ssh]\nprogram = \"  \"\nremote_qsh = \"\"\n").unwrap();
    let program = config.ssh.program().unwrap_err();
    assert_eq!(program.code, ErrorCode::ConfigError);
    assert!(program.message.contains("[ssh].program"));
    let remote = config.ssh.remote_qsh().unwrap_err();
    assert_eq!(remote.code, ErrorCode::ConfigError);
    assert!(remote.message.contains("[ssh].remote_qsh"));
}
