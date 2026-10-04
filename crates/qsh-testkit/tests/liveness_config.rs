//! ADR-0021 decisions 1 and 4: `[transport]` and `[recovery]` are validated
//! by every daemon at startup, whatever its role, before any socket is
//! bound or connection dialed. An out-of-range value is `CONFIG_ERROR`
//! (non-retryable), never a clamp.
//!
//! Each daemon entry point is handed a config whose `[transport]` is out of
//! range and a shutdown future that never resolves: a daemon that skipped
//! the validation would bind and wait, so the test's own timeout is what
//! catches it.

#![cfg(unix)]

use std::net::SocketAddr;
use std::time::Duration;

use qsh_core::config::{Config, Paths, TransportConfig};
use qsh_core::reverse::listen::run_listen;
use qsh_core::reverse::target::run_reverse;
use qsh_core::serve::run_serve;
use qsh_proto::ErrorCode;
use qsh_testkit::loopback::make_identity;
use qsh_testkit::reverse::loaded_identity;

const TIMEOUT: Duration = Duration::from_secs(10);

fn bad_configs() -> Vec<(&'static str, Config)> {
    vec![(
        "keep_alive_ms = 999",
        Config {
            transport: TransportConfig {
                keep_alive_ms: Some(999),
            },
            ..Config::default()
        },
    )]
}

fn temp_paths(dir: &tempfile::TempDir) -> Paths {
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    std::fs::create_dir_all(&paths.config_dir).unwrap();
    paths
}

#[tokio::test(flavor = "multi_thread")]
async fn every_daemon_fails_closed_on_an_out_of_range_liveness_value_before_binding() {
    for (label, config) in bad_configs() {
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

        let listen = tokio::time::timeout(
            TIMEOUT,
            run_listen(
                &paths,
                &config,
                loaded_identity(&identity, "controller"),
                Some("127.0.0.1:0"),
                |_| panic!("{label}: qsh listen must not bind"),
                |_| {},
                std::future::pending::<()>(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: qsh listen started instead of failing"));
        let err = listen.expect_err("qsh listen must fail closed");
        assert_eq!(err.code, ErrorCode::ConfigError, "{label}: listen");
        assert!(!err.retryable, "{label}: listen");

        let reverse = tokio::time::timeout(
            TIMEOUT,
            run_reverse(
                &paths,
                &config,
                loaded_identity(&identity, "target"),
                "controller.invalid:4433",
                None,
                std::future::pending::<()>(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: qsh reverse started instead of failing"));
        let err = reverse.expect_err("qsh reverse must fail closed");
        assert_eq!(err.code, ErrorCode::ConfigError, "{label}: reverse");
        assert!(!err.retryable, "{label}: reverse");
    }
}
