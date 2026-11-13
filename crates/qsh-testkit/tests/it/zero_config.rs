//! Two devices with no `config.toml`, no `acl.toml` and pins that are nothing
//! but a `name`, a `key` and a `role` (ADR-0063), reaching each other through
//! an in-process relay.
//!
//! The host runs the production `qsh serve` runtime (`run_serve_with_iroh`),
//! handed the endpoint settings a default config produces except for the relay
//! URL and its trust, which the test must replace to stay off the public
//! relays. The client is a real `Ops` with the same two seams. Everything stays
//! on loopback: no test here contacts a public relay, binds UDP 4433, 4434 or
//! 443, or touches the real `~/.config/qsh`.

use std::time::Duration;

use qsh_core::config::{Config, Paths};
use qsh_core::identity;
use qsh_core::iroh_serve::iroh_serve_from_config;
use qsh_core::iroh_settings::DEFAULT_RELAY_URLS;
use qsh_core::{ExecStdin, Ops};
use qsh_proto::{ExecRunReq, KeyStoreMode};
use qsh_transport::test_relay::TestRelay;

use super::jump_chain::{blocking, echo_argv, stdout_of};

const TIMEOUT: Duration = Duration::from_secs(30);

fn hex(key: &[u8; 32]) -> String {
    qsh_core::trust::iroh_pin::key_to_hex(key)
}

/// A device's paths in a sandbox, its identity initialised.
fn device(dir: &tempfile::TempDir, name: &str) -> (Paths, identity::LoadedIdentity, [u8; 32]) {
    let paths = Paths::new(
        dir.path().join(name).join("config"),
        dir.path().join(name).join("state"),
    )
    .with_runtime_dir(dir.path().join(name).join("run"));
    std::fs::create_dir_all(&paths.config_dir).expect("config dir");
    identity::init(&paths, KeyStoreMode::File).expect("identity.init");
    let loaded = identity::load(&paths).expect("load").expect("an identity");
    let key = loaded.local.iroh_public_key().expect("an Ed25519 identity");
    (paths, loaded, key)
}

fn exec_request(host: &str, text: &str) -> ExecRunReq {
    ExecRunReq {
        host: host.into(),
        argv: echo_argv(text),
        env: vec![],
        timeout_ms: Some(20_000),
    }
}

#[test]
fn a_default_config_brings_the_endpoint_up_on_the_public_relays() {
    let serve = iroh_serve_from_config(&Config::default())
        .expect("an unset [iroh].enable is on (ADR-0063)");
    assert_eq!(serve.relay_urls, DEFAULT_RELAY_URLS);
    assert!(serve.proxy_from_env);
}

#[test]
fn an_explicit_enable_false_brings_no_endpoint_up() {
    let mut config = Config::default();
    config.iroh.enable = Some(false);
    assert!(iroh_serve_from_config(&config).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_with_key_only_pins_and_no_config_reach_each_other() {
    qsh_testkit::env_check::ensure_loopback_udp();
    let dir = tempfile::tempdir().expect("tempdir");
    let relay = TestRelay::spawn().await;
    let (host_paths, host_identity, host_key) = device(&dir, "host");
    let (client_paths, _client_identity, client_key) = device(&dir, "client");

    // The whole configuration of each device: one pin of the other.
    std::fs::write(
        host_paths.trust_file(),
        format!(
            "[[peer]]\nname = \"client\"\nkey = \"{}\"\nrole = \"exec\"\n",
            hex(&client_key)
        ),
    )
    .expect("host trust.toml");
    std::fs::write(
        client_paths.trust_file(),
        format!("[[peer]]\nname = \"host\"\nkey = \"{}\"\n", hex(&host_key)),
    )
    .expect("client trust.toml");
    for paths in [&host_paths, &client_paths] {
        assert!(!paths.config_file().exists(), "no config.toml");
        assert!(!paths.acl_file().exists(), "no acl.toml");
    }

    // The host's endpoint is what a default config asks for, homed on the
    // test relay instead of the public ones.
    let mut serve = iroh_serve_from_config(&Config::default()).expect("on by default");
    serve.relay_urls = vec![relay.url.clone()];
    serve.relay_roots = vec![relay.cert.clone()];

    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let host_task = {
        let paths = host_paths.clone();
        tokio::spawn(async move {
            qsh_core::serve::run_serve_with_iroh(
                &paths,
                &Config::default(),
                host_identity,
                "127.0.0.1:0".parse().expect("addr"),
                None,
                Some(serve),
                move |addr| {
                    let _ = bound_tx.send(addr);
                },
                |_| {},
                |_| {},
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        })
    };
    tokio::time::timeout(TIMEOUT, bound_rx)
        .await
        .expect("the host binds")
        .expect("the host reports its address");

    let ops = Ops::new(client_paths.clone())
        .with_iroh_relay_roots(vec![relay.cert.clone()])
        .with_iroh_relay_urls(vec![relay.url.clone()]);

    // The pin has no address, so the relay is the only way, and it is the
    // default route of a pin with a key.
    let out = {
        let ops = ops.clone();
        blocking(move || ops.exec_run(exec_request("host", "zero-config"), ExecStdin::Closed))
            .await
            .expect("exec over the relay with no config")
    };
    assert_eq!(stdout_of(&out).trim(), "zero-config");

    // Neither device wrote a config file or an ACL, and the client's pin was
    // not rewritten into a longer form.
    for paths in [&host_paths, &client_paths] {
        assert!(!paths.config_file().exists());
        assert!(!paths.acl_file().exists());
    }
    let pin = std::fs::read_to_string(client_paths.trust_file()).expect("client trust.toml");
    assert!(!pin.contains("fingerprint"), "{pin}");
    assert!(!pin.contains("routes"), "{pin}");

    let _ = stop_tx.send(());
    tokio::time::timeout(TIMEOUT, host_task)
        .await
        .expect("the host stops")
        .expect("no panic")
        .expect("a clean stop");
}

/// ADR-0061 decision 2, kept by ADR-0063: a config that turns the endpoint off
/// brings none up. The runtime reads `[iroh]` itself here (`run_serve_with`),
/// so a daemon that ignored `enable = false` would reach for the public relays
/// and record an `iroh` object in `serve.json`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_enable_false_keeps_the_daemon_off_every_relay() {
    qsh_testkit::env_check::ensure_loopback_udp();
    let dir = tempfile::tempdir().expect("tempdir");
    let (paths, loaded, _key) = device(&dir, "host");
    let mut config = Config::default();
    config.iroh.enable = Some(false);

    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let (runtime_tx, runtime_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let task = {
        let paths = paths.clone();
        tokio::spawn(async move {
            qsh_core::serve::run_serve_with(
                &paths,
                &config,
                loaded,
                "127.0.0.1:0".parse().expect("addr"),
                None,
                move |addr| {
                    let _ = bound_tx.send(addr);
                },
                move |runtime| {
                    let _ = runtime_tx.send(runtime.server.iroh_endpoint().is_some());
                },
                |_| {},
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        })
    };
    tokio::time::timeout(TIMEOUT, bound_rx)
        .await
        .expect("the host binds")
        .expect("the host reports its address");
    let has_endpoint = runtime_rx.await.expect("the runtime is handed out");
    assert!(!has_endpoint, "enable = false brings no endpoint up");
    let raw = std::fs::read_to_string(paths.serve_record_file()).expect("serve.json");
    assert!(!raw.contains("iroh"), "{raw}");

    let _ = stop_tx.send(());
    tokio::time::timeout(TIMEOUT, task)
        .await
        .expect("the host stops")
        .expect("no panic")
        .expect("a clean stop");
}

#[test]
fn no_iroh_keeps_a_daemons_own_endpoint_down_and_nothing_else_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (paths, _loaded, _key) = device(&dir, "host");
    let plain = Ops::new(paths.clone()).daemon_config().expect("config");
    assert_eq!(plain.iroh.enable, None, "the file's config, untouched");
    let flagged = Ops::new(paths)
        .with_no_iroh(true)
        .daemon_config()
        .expect("config");
    assert_eq!(flagged.iroh.enable, Some(false));
    assert_eq!(
        flagged.iroh.mode, None,
        "`serve --to` still follows [iroh].mode"
    );
}
