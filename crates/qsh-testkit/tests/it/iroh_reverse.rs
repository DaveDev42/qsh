//! L3 acceptance for `qsh serve --to` over the iroh relay (ADR-0061, `docs/CLI.md`
//! §6.13): the production runtimes `run_listen_with_iroh` (the controller) and
//! `run_reverse_on` (the target) given an in-process relay, and a client `Ops`
//! that execs through the controller's local daemon.
//!
//! The target pins the controller with no address, so the relay is the only
//! route it has. Everything stays on loopback: the relay is the in-process test
//! relay, which both daemons are told to trust; no test contacts a public relay,
//! binds UDP 4433, 4434 or 443, or touches the real `~/.config/qsh`.

#![cfg(unix)]

use std::net::SocketAddr;
use std::time::Duration;

use qsh_core::config::{Config, Paths};
use qsh_core::iroh_serve::IrohServe;
use qsh_core::reverse::target::{ReverseOptions, run_reverse_on};
use qsh_core::trust::TrustStore;
use qsh_core::{ExecStdin, Ops};
use qsh_proto::{ExecRunReq, IdentityInitReq, KeyStoreMode, TrustAddReq, TrustSetIrohReq};
use qsh_testkit::loopback::{TestIdentity, make_identity};
use qsh_testkit::reverse::{loaded_identity, wait_for};
use qsh_transport::test_relay::TestRelay;
use serde_json::Value;

const TIMEOUT: Duration = Duration::from_secs(30);

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("join")
}

fn sandbox() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    std::fs::create_dir_all(&paths.config_dir).expect("config dir");
    (dir, paths)
}

/// A running `qsh listen` with its relay endpoint on `relay`.
struct Controller {
    _dir: tempfile::TempDir,
    paths: Paths,
    id: TestIdentity,
    task: tokio::task::JoinHandle<Result<(), qsh_core::ops::OpError>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Controller {
    /// A controller that pins `target` as `b` and lets it register.
    async fn start(relay: &TestRelay, target: &TestIdentity) -> Self {
        Self::start_with_acl(
            relay,
            target,
            b"[[acl]]\nprincipal = \"device:b\"\nallow = [\"host.reverse\"]\n",
        )
        .await
    }

    /// A controller that pins `target` as `b` under the given `acl.toml`.
    async fn start_with_acl(relay: &TestRelay, target: &TestIdentity, acl: &[u8]) -> Self {
        qsh_testkit::env_check::ensure_loopback_udp();
        let (dir, paths) = sandbox();
        let id = make_identity();
        let mut trust = TrustStore::default();
        trust.add_peer(
            "b",
            None,
            target.fingerprint,
            "2026-01-01T00:00:00Z".to_string(),
        );
        trust.save(&paths.trust_file()).expect("trust.toml");
        qsh_core::config::write_private_file(&paths.acl_file(), acl).expect("acl.toml");

        let mut serve = IrohServe::new(relay.url.clone(), 0);
        serve.relay_roots = vec![relay.cert.clone()];
        let loaded = loaded_identity(&id, "controller");
        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = {
            let paths = paths.clone();
            tokio::spawn(async move {
                qsh_core::reverse::listen::run_listen_with_iroh(
                    &paths,
                    &Config::default(),
                    loaded,
                    Some("127.0.0.1:0"),
                    Some(serve),
                    move |addr| {
                        let _ = bound_tx.send(addr);
                    },
                    |_| {},
                    async move {
                        let _ = stop_rx.await;
                    },
                )
                .await
            })
        };
        match tokio::time::timeout(TIMEOUT, bound_rx).await {
            Ok(Ok(_)) => {}
            _ => panic!("the controller ended without binding: {:?}", task.await),
        }
        Self {
            _dir: dir,
            paths,
            id,
            task,
            stop: Some(stop_tx),
        }
    }

    fn audit(&self) -> Vec<Value> {
        let Ok(text) = std::fs::read_to_string(self.paths.audit_log()) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(TIMEOUT, &mut self.task)
            .await
            .expect("the controller stops")
            .expect("no panic")
            .expect("a clean stop");
    }
}

/// A running `qsh serve --to` whose only route to the controller is the relay.
struct Target {
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<Result<(), qsh_core::ops::OpError>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Target {
    async fn start(
        relay: &TestRelay,
        id: &TestIdentity,
        controller: &Controller,
        controller_key: &str,
        address: Option<String>,
    ) -> Self {
        Self::start_with_file_key(relay, id, controller, controller_key, address, None).await
    }

    /// [`Self::start`] with the pin's `key` line then edited by hand to
    /// `file_key`, which `trust.set_iroh` would have refused.
    async fn start_with_file_key(
        relay: &TestRelay,
        id: &TestIdentity,
        controller: &Controller,
        controller_key: &str,
        address: Option<String>,
        file_key: Option<&str>,
    ) -> Self {
        let (dir, paths) = sandbox();
        let ops = Ops::new(paths.clone());
        let name = "ctl".to_string();
        let fingerprint = controller.id.fingerprint.to_string();
        let relay_url = relay.url.clone();
        let key = controller_key.to_string();
        blocking(move || {
            ops.trust_add(TrustAddReq {
                name: name.clone(),
                address: address.clone(),
                fingerprint: Some(fingerprint),
                cert_pem: None,
                role: None,
            })
            .expect("trust.add");
            ops.trust_set_iroh(TrustSetIrohReq {
                name,
                relay: Some(relay_url),
                key: Some(key),
                off: false,
            })
            .expect("trust.set_iroh");
        })
        .await;
        qsh_core::config::write_private_file(
            &paths.acl_file(),
            b"[[acl]]\nprincipal = \"device:ctl\"\nallow = [\"exec.run\"]\n",
        )
        .expect("acl.toml");
        if let Some(file_key) = file_key {
            let text = std::fs::read_to_string(paths.trust_file()).expect("trust.toml");
            assert!(text.contains(controller_key), "{text}");
            let edited = text.replace(controller_key, file_key);
            qsh_core::config::write_private_file(&paths.trust_file(), edited.as_bytes())
                .expect("edited trust.toml");
        }

        let loaded = loaded_identity(id, "b");
        let roots = vec![relay.cert.clone()];
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            run_reverse_on(
                &paths,
                &Config::default(),
                loaded,
                "ctl",
                None,
                ReverseOptions {
                    iroh_relay_roots: roots,
                    ..ReverseOptions::default()
                },
                |_| {},
                || {},
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });
        Self {
            _dir: dir,
            task,
            stop: Some(stop_tx),
        }
    }

    /// End the target whatever it is doing; its result does not matter to a
    /// test that expects it never to register.
    async fn abort(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }

    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(TIMEOUT, &mut self.task)
            .await
            .expect("the target stops")
            .expect("no panic")
            .expect("a clean stop");
    }
}

/// A client whose daemon socket is the controller's: it pins `b` with no
/// address, so the only way to reach it is the controller's registration.
async fn client_of(controller: &Controller, target: &TestIdentity) -> (tempfile::TempDir, Ops) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(controller.paths.runtime_dir());
    let ops = Ops::new(paths);
    let fingerprint = target.fingerprint.to_string();
    let ops_for = ops.clone();
    blocking(move || {
        ops_for
            .identity_init(IdentityInitReq {
                key_store: Some(KeyStoreMode::File),
                ..Default::default()
            })
            .expect("identity.init");
        ops_for
            .trust_add(TrustAddReq {
                name: "b".into(),
                address: None,
                fingerprint: Some(fingerprint),
                cert_pem: None,
                role: None,
            })
            .expect("trust.add");
    })
    .await;
    (dir, ops)
}

async fn wait_reachable(ops: &Ops) {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let ops = ops.clone();
            let listed = blocking(move || ops.host_list()).await.expect("host.list");
            if listed
                .hosts
                .iter()
                .any(|h| h.name == "b" && h.connection_mode == "reverse" && h.state == "reachable")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the target registers with the controller over the relay");
}

/// A target that knows the controller only by key registers over the relay,
/// the controller admits it as an iroh peer, and a client's `exec` through the
/// controller reaches the target.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_registers_over_the_relay_and_exec_runs_through_the_controller() {
    let relay = TestRelay::spawn().await;
    let target_id = make_identity();
    let mut controller = Controller::start(&relay, &target_id).await;
    let controller_key = hex(&controller.id.local.iroh_public_key().expect("ed25519"));
    let mut target = Target::start(&relay, &target_id, &controller, &controller_key, None).await;

    let (_dir, ops) = client_of(&controller, &target_id).await;
    wait_reachable(&ops).await;

    let out = tokio::time::timeout(
        TIMEOUT,
        blocking({
            let ops = ops.clone();
            move || {
                ops.exec_run(
                    ExecRunReq {
                        host: "b".into(),
                        argv: vec!["sh".into(), "-c".into(), "exit 7".into()],
                        env: vec![],
                        timeout_ms: Some(10_000),
                    },
                    ExecStdin::Closed,
                )
            }
        }),
    )
    .await
    .expect("exec returns")
    .expect("exec through the controller reaches the registered target");
    assert_eq!(out.data.remote_exit_code, 7);
    assert_registered_over_the_relay(&controller, &target_id).await;

    target.stop().await;
    controller.stop().await;
}

/// A controller pin whose address answers nothing falls back to the relay: the
/// direct dial fails at once, the relay starts without waiting out the head
/// start, and the registration is admitted over it.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_controller_address_falls_back_to_the_relay() {
    let relay = TestRelay::spawn().await;
    let target_id = make_identity();
    let mut controller = Controller::start(&relay, &target_id).await;
    let controller_key = hex(&controller.id.local.iroh_public_key().expect("ed25519"));
    // A UDP port nothing listens on: bound and dropped.
    let dead = {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket.local_addr().expect("addr").to_string()
    };
    let mut target =
        Target::start(&relay, &target_id, &controller, &controller_key, Some(dead)).await;

    let (_dir, ops) = client_of(&controller, &target_id).await;
    wait_reachable(&ops).await;
    assert_registered_over_the_relay(&controller, &target_id).await;

    target.stop().await;
    controller.stop().await;
}

/// A registrant the controller's ACL does not grant `host.reverse` is refused
/// over the relay like over UDP: the audit log has the denial, no registration
/// is admitted, and the client never sees `b` as reachable.
#[tokio::test(flavor = "multi_thread")]
async fn a_registrant_without_the_reverse_role_is_refused_over_the_relay() {
    let relay = TestRelay::spawn().await;
    let target_id = make_identity();
    let mut controller = Controller::start_with_acl(
        &relay,
        &target_id,
        b"[[acl]]\nprincipal = \"device:b\"\nallow = [\"exec.run\"]\n",
    )
    .await;
    let controller_key = hex(&controller.id.local.iroh_public_key().expect("ed25519"));
    let mut target = Target::start(&relay, &target_id, &controller, &controller_key, None).await;

    let denied = wait_for(TIMEOUT, || {
        controller
            .audit()
            .into_iter()
            .find(|r| r["action"] == "host.reverse" && r["decision"] == "deny")
    })
    .await;
    assert_eq!(
        denied["peer_addr"],
        format!("iroh:{}", target_id.fingerprint),
        "{denied}"
    );
    assert!(
        !controller
            .audit()
            .iter()
            .any(|r| r["action"] == "host.reverse" && r["decision"] == "allow"),
        "{:?}",
        controller.audit()
    );
    let (_dir, ops) = client_of(&controller, &target_id).await;
    let listed = blocking(move || ops.host_list()).await.expect("host.list");
    assert!(
        !listed
            .hosts
            .iter()
            .any(|h| h.name == "b" && h.connection_mode == "reverse" && h.state == "reachable"),
        "{listed:?}"
    );

    target.abort().await;
    controller.stop().await;
}

/// A pin whose `key` was edited to another controller's key is not dialed:
/// the key must hash to the pinned fingerprint (ADR-0060 name binding), so
/// the other controller, which would admit this target, sees nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_pin_whose_key_is_not_the_pinned_fingerprints_is_never_dialed() {
    let relay = TestRelay::spawn().await;
    let target_id = make_identity();
    let mut real = Controller::start(&relay, &target_id).await;
    let mut impostor = Controller::start(&relay, &target_id).await;
    let real_key = hex(&real.id.local.iroh_public_key().expect("ed25519"));
    let impostor_key = hex(&impostor.id.local.iroh_public_key().expect("ed25519"));
    assert_ne!(real_key, impostor_key);
    let mut target = Target::start_with_file_key(
        &relay,
        &target_id,
        &real,
        &real_key,
        None,
        Some(&impostor_key),
    )
    .await;

    // Long enough for several registration attempts if any were made.
    tokio::time::sleep(Duration::from_secs(4)).await;
    for controller in [&real, &impostor] {
        let seen: Vec<_> = controller
            .audit()
            .into_iter()
            .filter(|r| r["action"] == "host.reverse")
            .collect();
        assert!(seen.is_empty(), "{seen:?}");
    }

    target.abort().await;
    real.stop().await;
    impostor.stop().await;
}

/// The controller's audit log has the registration as an iroh peer: it was
/// admitted over the relay endpoint, not the UDP listener.
async fn assert_registered_over_the_relay(controller: &Controller, target_id: &TestIdentity) {
    // The controller saw an iroh peer: the registration was admitted over the
    // relay endpoint, not the UDP listener.
    let admitted = wait_for(TIMEOUT, || {
        controller
            .audit()
            .into_iter()
            .find(|r| r["action"] == "host.reverse" && r["decision"] == "allow")
    })
    .await;
    assert_eq!(
        admitted["peer_addr"],
        format!("iroh:{}", target_id.fingerprint),
        "{admitted}"
    );
}
