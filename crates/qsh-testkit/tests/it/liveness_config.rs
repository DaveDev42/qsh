//! ADR-0021 decisions 1 and 4: `[transport]` and `[recovery]` are validated
//! by every daemon at startup, whatever its role, before any socket is
//! bound or connection dialed. An out-of-range value is `CONFIG_ERROR`
//! (non-retryable), never a clamp.
//!
//! The daemon entry point is handed a config whose `[transport]` is out of
//! range (or whose `[recovery]` breaks the detection budget, attach or
//! reverse registration) and a shutdown future that never resolves: a
//! daemon that skipped the validation would bind and wait, so the test's own
//! timeout is what catches it. (`qsh listen` and `qsh reverse` retired with
//! ADR-0068.)

use std::net::SocketAddr;
use std::time::Duration;

use qsh_core::config::{Config, Paths, RecoverySection, TransportConfig};
use qsh_core::serve::run_serve;
use qsh_proto::ErrorCode;
use qsh_testkit::loopback::{loaded_identity, make_identity};

const TIMEOUT: Duration = Duration::from_secs(10);

fn bad_recovery(label: &'static str, recovery: RecoverySection) -> (&'static str, Config) {
    (
        label,
        Config {
            recovery,
            ..Config::default()
        },
    )
}

fn bad_configs() -> Vec<(&'static str, Config)> {
    vec![
        (
            "keep_alive_ms = 999",
            Config {
                transport: TransportConfig {
                    keep_alive_ms: Some(999),
                    adaptive: None,
                },
                ..Config::default()
            },
        ),
        bad_recovery(
            "min_dead_after_ms = 1251 (P*S+D = 2001)",
            RecoverySection {
                min_dead_after_ms: Some(1_251),
                ..RecoverySection::default()
            },
        ),
        bad_recovery(
            "strikes = 1",
            RecoverySection {
                strikes: Some(1),
                ..RecoverySection::default()
            },
        ),
        bad_recovery(
            "reverse_min_dead_after_ms = 4251 (P*S+D = 5001)",
            RecoverySection {
                reverse_min_dead_after_ms: Some(4_251),
                ..RecoverySection::default()
            },
        ),
        bad_recovery(
            "reverse_strikes = 1",
            RecoverySection {
                reverse_strikes: Some(1),
                ..RecoverySection::default()
            },
        ),
        bad_recovery(
            "probe_interval_ms = 49",
            RecoverySection {
                probe_interval_ms: Some(49),
                ..RecoverySection::default()
            },
        ),
    ]
}

fn temp_paths(dir: &tempfile::TempDir) -> Paths {
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    std::fs::create_dir_all(&paths.config_dir).unwrap();
    paths
}

#[tokio::test(flavor = "multi_thread")]
async fn every_daemon_fails_closed_on_an_out_of_range_liveness_value_before_binding() {
    for (label, mut config) in bad_configs() {
        // ADR-0063: a daemon brings its iroh endpoint up unless told not to,
        // and these tests must never reach a public relay.
        config.iroh.enable = Some(false);
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(&dir);
        let identity = make_identity();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let serve = tokio::time::timeout(
            TIMEOUT,
            run_serve(
                &paths,
                &config,
                loaded_identity(&identity, "host"),
                bind,
                |_| panic!("{label}: qsh serve must not bind"),
                |_| {},
                |_| {},
                std::future::pending::<()>(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: qsh serve started instead of failing"));
        let err = serve.expect_err("qsh serve must fail closed");
        assert_eq!(err.code, ErrorCode::ConfigError, "{label}: serve");
        assert!(!err.retryable, "{label}: serve");
    }
}
