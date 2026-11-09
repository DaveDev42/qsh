use std::collections::BTreeSet;

use qsh_proto::{ConfigGetReq, ConfigListReq, ConfigSetReq, ConfigUnsetReq};

use super::*;
use crate::config::{
    AuditConfig, IdentityConfig, ListenConfig, RecoverySection, ReverseConfig, ServeConfig,
    SshBootstrapMode, SshConfig, TransportConfig,
};
use crate::config_edit::{KEYS, KeyType};
use crate::ops::ScreenSync;
use crate::ops::test_support::temp_ops;

fn set(ops: &Ops, key: &str, value: &str) -> Result<qsh_proto::ConfigSetData, OpError> {
    ops.config_set(ConfigSetReq {
        key: key.into(),
        value: value.into(),
    })
}

fn write_config(ops: &Ops, text: &str) {
    let path = ops.paths.config_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn read_config(ops: &Ops) -> String {
    std::fs::read_to_string(ops.paths.config_file()).unwrap()
}

const COMMENTED: &str = "\
# my qsh config
[serve]
# where to listen
bind = \"[::]:4433\" # default port
max_sessions = 10

[transport]
keep_alive_ms = 15000

# trailing note
";

#[test]
fn set_keeps_comments_and_order() {
    let (_g, ops) = temp_ops();
    write_config(&ops, COMMENTED);

    let data = set(&ops, "serve.bind", "[::]:60001").unwrap();
    assert!(data.changed);
    assert_eq!(data.previous, Some("[::]:4433".into()));
    assert_eq!(data.applies_from.as_deref(), Some("next_start"));
    set(&ops, "ssh.program", "/usr/bin/ssh").unwrap();
    set(&ops, "serve.close_grace_ms", "2000").unwrap();

    let text = read_config(&ops);
    assert!(
        text.starts_with("# my qsh config\n[serve]\n# where to listen\n"),
        "{text}"
    );
    assert!(
        text.contains("bind = \"[::]:60001\" # default port\n"),
        "{text}"
    );
    assert!(text.contains("# trailing note"), "{text}");
    let order: Vec<usize> = [
        "bind =",
        "max_sessions =",
        "close_grace_ms =",
        "[transport]",
        "[ssh]",
    ]
    .iter()
    .map(|needle| {
        text.find(needle)
            .unwrap_or_else(|| panic!("{needle} in {text}"))
    })
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
    let config = Config::load(&ops.paths).unwrap();
    assert_eq!(config.serve.bind.as_deref(), Some("[::]:60001"));
    assert_eq!(config.serve.max_sessions, Some(10));
}

#[test]
fn setting_the_same_value_writes_nothing() {
    let (_g, ops) = temp_ops();
    write_config(&ops, COMMENTED);
    let before = std::fs::metadata(ops.paths.config_file())
        .unwrap()
        .modified()
        .unwrap();
    let data = set(&ops, "serve.max_sessions", "10").unwrap();
    assert!(!data.changed);
    assert_eq!(data.applies_from, None);
    assert_eq!(read_config(&ops), COMMENTED);
    assert_eq!(
        std::fs::metadata(ops.paths.config_file())
            .unwrap()
            .modified()
            .unwrap(),
        before
    );
}

#[test]
fn invalid_values_are_rejected_and_the_file_is_unchanged() {
    let (_g, ops) = temp_ops();
    write_config(&ops, COMMENTED);
    let cases = [
        ("transport.keep_alive_ms", "50", ErrorCode::ConfigError),
        ("transport.keep_alive_ms", "99999", ErrorCode::ConfigError),
        ("recovery.strikes", "1", ErrorCode::ConfigError),
        ("recovery.probe_interval_ms", "900", ErrorCode::ConfigError),
        ("listen.stale_retention", "10", ErrorCode::ConfigError),
        ("ssh.program", "  ", ErrorCode::ConfigError),
        (
            "transport.keep_alive_ms",
            "soon",
            ErrorCode::InvalidArgument,
        ),
        ("transport.keep_alive_ms", "-5", ErrorCode::InvalidArgument),
        (
            "listen.allow_advertised_names",
            "yes",
            ErrorCode::InvalidArgument,
        ),
        ("ssh.bootstrap", "sometimes", ErrorCode::InvalidArgument),
        ("identity.key_store", "vault", ErrorCode::InvalidArgument),
        (
            "reverse.backoff_jitter_pct",
            "300",
            ErrorCode::InvalidArgument,
        ),
    ];
    for (key, value, code) in cases {
        let err = set(&ops, key, value).unwrap_err();
        assert_eq!(err.code, code, "{key}={value}: {}", err.message);
        assert!(!err.retryable, "{key}={value}");
        assert_eq!(
            read_config(&ops),
            COMMENTED,
            "{key}={value} changed the file"
        );
    }
}

#[test]
fn a_rejected_set_does_not_create_the_file() {
    let (_g, ops) = temp_ops();
    set(&ops, "transport.keep_alive_ms", "5").unwrap_err();
    assert!(!ops.paths.config_file().exists());
}

#[test]
fn unknown_keys_are_rejected_everywhere() {
    let (_g, ops) = temp_ops();
    write_config(&ops, COMMENTED);
    for key in [
        "serve.bnid",
        "serve",
        "bind",
        "nosuch.key",
        "serve.bind.x",
        "Serve.bind",
    ] {
        assert_eq!(
            set(&ops, key, "1").unwrap_err().code,
            ErrorCode::InvalidArgument,
            "{key}"
        );
        assert_eq!(
            ops.config_get(ConfigGetReq { key: key.into() })
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument,
            "{key}"
        );
        assert_eq!(
            ops.config_unset(ConfigUnsetReq { key: key.into() })
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument,
            "{key}"
        );
    }
    assert_eq!(read_config(&ops), COMMENTED);
}

#[test]
fn get_list_and_unset() {
    let (_g, ops) = temp_ops();
    write_config(&ops, COMMENTED);

    let got = ops
        .config_get(ConfigGetReq {
            key: "serve.max_sessions".into(),
        })
        .unwrap();
    assert!(got.set);
    assert_eq!(got.value, Some(10.into()));
    let unset = ops
        .config_get(ConfigGetReq {
            key: "serve.max_exec".into(),
        })
        .unwrap();
    assert!(!unset.set);
    assert_eq!(unset.value, None);
    let ssh = ops
        .config_get(ConfigGetReq {
            key: "ssh.program".into(),
        })
        .unwrap();
    assert_eq!(ssh.applies_from, None, "ssh.* is read per command");

    let listed = ops.config_list(ConfigListReq::default()).unwrap();
    let keys: Vec<_> = listed.entries.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "serve.bind",
            "serve.max_sessions",
            "transport.keep_alive_ms"
        ]
    );
    let all = ops.config_list(ConfigListReq { all: true }).unwrap();
    assert_eq!(all.entries.len(), KEYS.len());

    let removed = ops
        .config_unset(ConfigUnsetReq {
            key: "transport.keep_alive_ms".into(),
        })
        .unwrap();
    assert!(removed.changed);
    assert_eq!(removed.previous, Some(15000.into()));
    assert_eq!(removed.applies_from.as_deref(), Some("next_start"));
    let text = read_config(&ops);
    assert!(
        !text.contains("keep_alive_ms") && !text.contains("[transport]"),
        "{text}"
    );
    assert!(
        text.contains("# trailing note") && text.contains("# default port"),
        "{text}"
    );

    let again = ops
        .config_unset(ConfigUnsetReq {
            key: "transport.keep_alive_ms".into(),
        })
        .unwrap();
    assert!(!again.changed);
    assert_eq!(again.previous, None);
}

#[test]
fn unset_can_repair_an_invalid_file_but_set_cannot_hide_it() {
    let (_g, ops) = temp_ops();
    write_config(
        &ops,
        "[transport]\nkeep_alive_ms = 5\n[serve]\nmax_sessions = 3\n",
    );
    // The file already violates the range; setting another key keeps it invalid.
    assert_eq!(
        set(&ops, "serve.max_sessions", "4").unwrap_err().code,
        ErrorCode::ConfigError
    );
    // Removing the offending key makes the result valid.
    ops.config_unset(ConfigUnsetReq {
        key: "transport.keep_alive_ms".into(),
    })
    .unwrap();
    Config::load(&ops.paths).unwrap().validate().unwrap();
}

#[test]
fn an_unparseable_file_is_a_config_error_and_stays_put() {
    let (_g, ops) = temp_ops();
    write_config(&ops, "[serve\nbind = ");
    assert_eq!(
        set(&ops, "serve.bind", "x").unwrap_err().code,
        ErrorCode::ConfigError
    );
    assert_eq!(
        ops.config_get(ConfigGetReq {
            key: "serve.bind".into()
        })
        .unwrap_err()
        .code,
        ErrorCode::ConfigError
    );
    assert_eq!(read_config(&ops), "[serve\nbind = ");
}

#[test]
fn the_legacy_alias_is_read_and_replaced() {
    let (_g, ops) = temp_ops();
    write_config(&ops, "[serve]\nresume_ttl_secs = 60\n");
    let got = ops
        .config_get(ConfigGetReq {
            key: "serve.resume_ttl".into(),
        })
        .unwrap();
    assert_eq!(got.value, Some(60.into()));
    let data = set(&ops, "serve.resume_ttl", "120").unwrap();
    assert_eq!(data.previous, Some(60.into()));
    let text = read_config(&ops);
    assert!(
        text.contains("resume_ttl = 120") && !text.contains("resume_ttl_secs"),
        "{text}"
    );
}

#[test]
fn concurrent_writers_serialize() {
    let (_g, ops) = temp_ops();
    write_config(&ops, COMMENTED);
    let paths = ops.paths.clone();
    let keys: Vec<&str> = KEYS
        .iter()
        .filter(|k| k.section == "serve" && k.ty == KeyType::Int)
        .map(|k| k.key)
        .collect();
    assert!(keys.len() >= 12);
    std::thread::scope(|scope| {
        for (n, key) in keys.iter().enumerate() {
            let paths = paths.clone();
            scope.spawn(move || {
                let ops = Ops::new(paths);
                set(&ops, &format!("serve.{key}"), &(100 + n).to_string()).unwrap();
            });
        }
    });
    let text = read_config(&ops);
    for (n, key) in keys.iter().enumerate() {
        let expected = format!("{key} = {}", 100 + n);
        // `max_sessions` started as 10 and is rewritten like the rest.
        assert!(text.contains(&expected), "lost write {expected}:\n{text}");
    }
    assert!(
        text.contains("# my qsh config") && text.contains("# trailing note"),
        "{text}"
    );
}

fn leaf_paths(prefix: &str, value: &toml::Value, out: &mut BTreeSet<String>) {
    match value {
        toml::Value::Table(table) => {
            for (name, inner) in table {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                leaf_paths(&path, inner, out);
            }
        }
        _ => {
            out.insert(prefix.to_string());
        }
    }
}

/// A `Config` with every field spelled out. The literals deliberately omit
/// `..Default::default()`: a new `Config` field stops this test compiling
/// until it is added here and, through the assertion below, to
/// [`KEYS`], so `qsh config set` can write it (ADR-0051 결정 10).
fn every_field_populated() -> Config {
    Config {
        serve: ServeConfig {
            bind: Some(String::new()),
            to: Some(String::new()),
            replay_bytes: Some(1),
            resume_ttl: Some(1),
            close_grace_ms: Some(1),
            max_concurrent_handshakes: Some(1),
            handshake_rate_per_source: Some(1),
            max_sessions: Some(1),
            max_sessions_per_principal: Some(1),
            max_exec_per_principal: Some(1),
            validated_rate_per_source: Some(1),
            max_exec: Some(1),
            max_tunnel_streams_per_principal: Some(1),
            max_tunnel_streams_per_forward: Some(1),
            max_remote_forwards_per_principal: Some(1),
            max_connections_per_principal: Some(1),
            max_connections: Some(1),
            max_file_transfers_per_principal: Some(1),
            max_file_transfers: Some(1),
            on_demand_idle_ms: Some(1),
        },
        identity: IdentityConfig {
            key_store: Some(qsh_proto::KeyStoreMode::Auto),
        },
        listen: ListenConfig {
            bind: Some(String::new()),
            allow_advertised_names: true,
            stale_retention: Some(1),
        },
        reverse: ReverseConfig {
            controller: Some(String::new()),
            offered_name: Some(String::new()),
            backoff_initial_ms: Some(1),
            backoff_max_ms: Some(1),
            backoff_jitter_pct: Some(1),
        },
        audit: AuditConfig {
            path: Some(String::new()),
            max_bytes: Some(1),
            retain: Some(1),
            queue_depth: Some(1),
        },
        transport: TransportConfig {
            keep_alive_ms: Some(1),
            adaptive: Some(crate::config::AdaptiveMode::On),
        },
        recovery: RecoverySection {
            probe_interval_ms: Some(1),
            min_dead_after_ms: Some(1),
            strikes: Some(1),
            reverse_min_dead_after_ms: Some(1),
            reverse_strikes: Some(1),
        },
        ssh: SshConfig {
            bootstrap: Some(SshBootstrapMode::Auto),
            program: Some(String::new()),
            remote_qsh: Some(String::new()),
        },
        interactive: crate::config::InteractiveConfig {
            screen_sync: Some(crate::ops::ScreenSync::Auto),
            predict: Some(crate::ops::Predict::Auto),
            status_line: Some(crate::ops::StatusLine::On),
        },
        punch: crate::config::PunchConfig {
            mode: Some(crate::punch::PunchMode::Auto),
        },
    }
}

/// A value that is valid for `path` together with every other sample.
fn sample(path: &str, key: &crate::config_edit::ConfigKey) -> String {
    match path {
        "transport.keep_alive_ms" => "15000".into(),
        "transport.adaptive" => "off".into(),
        "interactive.screen_sync" => "on".into(),
        "interactive.predict" => "always".into(),
        "interactive.status_line" => "off".into(),
        "recovery.probe_interval_ms" => "250".into(),
        "recovery.min_dead_after_ms" => "1000".into(),
        "recovery.strikes" => "3".into(),
        "recovery.reverse_min_dead_after_ms" => "4250".into(),
        "recovery.reverse_strikes" => "3".into(),
        "listen.stale_retention" => "300".into(),
        "reverse.backoff_initial_ms" => "500".into(),
        "reverse.backoff_max_ms" => "30000".into(),
        "reverse.backoff_jitter_pct" => "20".into(),
        _ => match key.ty {
            KeyType::Str if !key.choices.is_empty() => key.choices[0].into(),
            KeyType::Str => "value".into(),
            KeyType::Int => "100".into(),
            KeyType::Bool => "true".into(),
        },
    }
}

#[test]
fn every_config_key_is_settable() {
    // Config -> registry: the fields `Config` has are exactly the keys the
    // registry lists.
    let full = toml::Value::try_from(every_field_populated()).unwrap();
    let mut config_keys = BTreeSet::new();
    leaf_paths("", &full, &mut config_keys);
    let registry: BTreeSet<String> = KEYS.iter().map(|k| k.path()).collect();
    assert_eq!(
        config_keys, registry,
        "a `Config` field has no `config_edit::KEYS` row (or the reverse): every key must be \
         settable with `qsh config set`"
    );

    // Registry -> Config: every row sets through the op and lands in the
    // field of the same name.
    let (_g, ops) = temp_ops();
    for key in KEYS {
        let path = key.path();
        let data = set(&ops, &path, &sample(&path, key))
            .unwrap_or_else(|err| panic!("{path}: {}", err.message));
        assert!(data.changed, "{path}");
        assert_eq!(data.applies_from.is_some(), key.startup_only, "{path}");
    }
    let loaded = Config::load(&ops.paths).unwrap();
    loaded.validate().unwrap();
    let mut loaded_keys = BTreeSet::new();
    leaf_paths(
        "",
        &toml::Value::try_from(loaded).unwrap(),
        &mut loaded_keys,
    );
    assert_eq!(loaded_keys, registry);
    let listed = ops.config_list(ConfigListReq::default()).unwrap();
    assert_eq!(listed.entries.len(), KEYS.len());
    assert!(listed.entries.iter().all(|e| e.set));

    // And every row unsets again.
    for key in KEYS {
        ops.config_unset(ConfigUnsetReq { key: key.path() })
            .unwrap();
    }
    assert_eq!(Config::load(&ops.paths).unwrap(), Config::default());
}

/// ADR-0051 DoD 4: what `config set` writes is what `doctor` reads. Every
/// key written through the op is a known key, so `doctor` reports no
/// `config_unknown_key`, while a typo added by hand to the same file still is.
#[test]
fn doctor_reports_no_config_unknown_key_for_anything_config_set_wrote() {
    let (_g, ops) = temp_ops();
    ops.identity_init(qsh_proto::IdentityInitReq {
        key_store: Some(qsh_proto::KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    for key in KEYS {
        let path = key.path();
        set(&ops, &path, &sample(&path, key))
            .unwrap_or_else(|err| panic!("{path}: {}", err.message));
    }
    // `doctor` opens the audit path to see that it is writable; the sample
    // `value` is relative and would land in the working directory.
    let audit = _g.path().join("audit-probe.log");
    set(&ops, "audit.path", &audit.display().to_string()).unwrap();
    let unknown = |ops: &Ops| {
        ops.doctor(
            qsh_proto::DoctorReq { host: None },
            std::time::SystemTime::now(),
        )
        .unwrap()
        .findings
        .into_iter()
        .filter(|f| f.code == "config_unknown_key")
        .collect::<Vec<_>>()
    };
    assert!(unknown(&ops).is_empty(), "{:?}", unknown(&ops));

    let mut text = read_config(&ops);
    text.push_str("\n[servr]\nbind = \"x\"\n");
    write_config(&ops, &text);
    let found = unknown(&ops);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].detail.contains("servr.bind"), "{found:?}");
}

/// ADR-0052 decision 15: `--screen-sync` beats `[interactive].screen_sync`,
/// which beats `auto`; a `config.toml` that does not parse fails closed.
#[test]
fn screen_sync_mode_is_flag_then_key_then_auto() {
    let (_g, ops) = temp_ops();
    assert_eq!(ops.screen_sync_mode(None).unwrap(), ScreenSync::Auto);
    assert_eq!(
        ops.screen_sync_mode(Some(ScreenSync::On)).unwrap(),
        ScreenSync::On
    );

    set(&ops, "interactive.screen_sync", "off").unwrap();
    assert_eq!(ops.screen_sync_mode(None).unwrap(), ScreenSync::Off);
    assert_eq!(
        ops.screen_sync_mode(Some(ScreenSync::On)).unwrap(),
        ScreenSync::On,
        "the flag wins over the key"
    );
    assert_eq!(
        ops.screen_sync_mode(Some(ScreenSync::Auto)).unwrap(),
        ScreenSync::Auto,
        "an explicit auto is still the flag"
    );

    set(&ops, "interactive.screen_sync", "on").unwrap();
    assert_eq!(ops.screen_sync_mode(None).unwrap(), ScreenSync::On);

    // A value the enum does not know is a load error, never a silent auto.
    std::fs::write(
        ops.paths().config_file(),
        "[interactive]\nscreen_sync = \"sometimes\"\n",
    )
    .unwrap();
    let err = ops.screen_sync_mode(None).unwrap_err();
    assert_eq!(err.code, qsh_proto::ErrorCode::ConfigError);
    assert_eq!(
        ops.screen_sync_mode(Some(ScreenSync::Off)).unwrap(),
        ScreenSync::Off,
        "a flag needs no config at all"
    );
}

/// ADR-0052 decision 15: `[transport].adaptive = "off"` reaches the process
/// pin the bulk governor and the carrier policy read, and a key that is not
/// written leaves the pin alone. (nextest runs each test in its own process,
/// so the process-wide pin does not leak into other tests.)
#[test]
fn transport_adaptive_pins_the_process() {
    use crate::adapt::{User, process_adaptive};

    let (_g, ops) = temp_ops();
    assert!(process_adaptive(), "adaptive is on by default");
    ops.pin_process_transport();
    assert!(process_adaptive(), "no key, no change");

    set(&ops, "transport.adaptive", "on").unwrap();
    ops.pin_process_transport();
    assert!(process_adaptive());
    assert!(User::from_process().adaptive);

    set(&ops, "transport.adaptive", "off").unwrap();
    ops.pin_process_transport();
    assert!(!process_adaptive());
    let user = User::from_process();
    assert!(!user.adaptive, "the carrier runner's pin follows the key");
    assert_eq!(user.keep_alive, None);

    // The liveness read every daemon and attach does pins it the same way.
    crate::adapt::set_process_adaptive(true);
    ops.config().unwrap().liveness().unwrap().pin_process();
    assert!(!process_adaptive());
    crate::adapt::set_process_adaptive(true);
}

/// ADR-0053 decisions 10 and 11: `--predict` and `--status-line` beat their
/// `[interactive]` keys, which beat `auto` and `on`; an unreadable value
/// fails closed, and `interactive_options` agrees with the single-flag
/// resolvers.
#[test]
fn predict_and_status_line_are_flag_then_key_then_default() {
    use crate::ops::{InteractiveOptions, Predict, StatusLine};

    let (_g, ops) = temp_ops();
    assert_eq!(ops.predict_mode(None).unwrap(), Predict::Auto);
    assert_eq!(ops.status_line_mode(None).unwrap(), StatusLine::On);
    assert_eq!(
        ops.interactive_options(None, None, None).unwrap(),
        InteractiveOptions::default()
    );

    set(&ops, "interactive.predict", "never").unwrap();
    set(&ops, "interactive.status_line", "off").unwrap();
    assert_eq!(ops.predict_mode(None).unwrap(), Predict::Never);
    assert_eq!(ops.status_line_mode(None).unwrap(), StatusLine::Off);
    assert_eq!(
        ops.predict_mode(Some(Predict::Always)).unwrap(),
        Predict::Always,
        "the flag wins over the key"
    );
    assert_eq!(
        ops.predict_mode(Some(Predict::Auto)).unwrap(),
        Predict::Auto,
        "an explicit auto is still the flag"
    );
    assert_eq!(
        ops.status_line_mode(Some(StatusLine::On)).unwrap(),
        StatusLine::On
    );

    let merged = ops
        .interactive_options(Some(ScreenSync::On), None, Some(StatusLine::On))
        .unwrap();
    assert_eq!(
        merged,
        InteractiveOptions {
            screen_sync: ScreenSync::On,
            predict: Predict::Never,
            status_line: StatusLine::On,
        }
    );

    // Values outside the closed sets are refused by `config set`.
    assert!(set(&ops, "interactive.predict", "sometimes").is_err());
    assert!(set(&ops, "interactive.predict", "on").is_err());
    assert!(set(&ops, "interactive.status_line", "auto").is_err());

    // A hand-written bad value is a load error, never a silent default.
    std::fs::write(
        ops.paths().config_file(),
        "[interactive]\npredict = \"sometimes\"\nstatus_line = \"on\"\n",
    )
    .unwrap();
    assert_eq!(
        ops.predict_mode(None).unwrap_err().code,
        qsh_proto::ErrorCode::ConfigError
    );
    assert_eq!(
        ops.interactive_options(None, None, None).unwrap_err().code,
        qsh_proto::ErrorCode::ConfigError
    );
    assert_eq!(
        ops.predict_mode(Some(Predict::Never)).unwrap(),
        Predict::Never,
        "a flag needs no config at all"
    );
}

/// ADR-0054 decision 19: `[punch].mode` is `auto` unless set to `off`, the
/// flag wins, a value outside the set is refused by `config set` and is a
/// load error when written by hand, and the key is read at start by the
/// daemons (`applies_from`).
#[test]
fn punch_mode_is_a_validated_key() {
    use crate::punch::{ClientPunch, PunchMode};
    let (_g, ops) = temp_ops();
    assert_eq!(ops.punch_mode().unwrap(), PunchMode::Auto);

    let data = set(&ops, "punch.mode", "off").unwrap();
    assert_eq!(data.applies_from.as_deref(), Some("next_start"));
    assert_eq!(ops.punch_mode().unwrap(), PunchMode::Off);
    set(&ops, "punch.mode", "auto").unwrap();
    assert_eq!(ops.punch_mode().unwrap(), PunchMode::Auto);

    assert!(set(&ops, "punch.mode", "sometimes").is_err());
    assert!(set(&ops, "punch.mode", "on").is_err());

    // `--no-punch` wins over the key.
    set(&ops, "punch.mode", "auto").unwrap();
    let flagged = ops.clone().with_punch(ClientPunch {
        mode: PunchMode::Off,
        ..ClientPunch::default()
    });
    assert_eq!(flagged.punch_mode().unwrap(), PunchMode::Off);

    std::fs::write(ops.paths().config_file(), "[punch]\nmode = \"sometimes\"\n").unwrap();
    assert_eq!(
        ops.punch_mode().unwrap_err().code,
        qsh_proto::ErrorCode::ConfigError
    );
}
