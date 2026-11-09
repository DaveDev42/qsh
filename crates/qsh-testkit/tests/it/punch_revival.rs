//! ADR-0054 DoD 4, last sentence: when the punch fails, the SSH-bootstrap
//! pin's serve revival still follows, as it did before hole punching.
//!
//! The pin of B is marked as the SSH bootstrap wrote it and carries B's
//! address, on which nothing listens. B is not registered with R, so the
//! punch gives up (`target_not_registered`) and the direct dial fails with
//! the error the command would have had without punching. The revival then
//! runs `ssh` (the fake of `qsh_testkit::fake_ssh`, which records its calls)
//! and prints its notice; the command still fails with the dial error, now
//! carrying `details.punch`.

use std::sync::{Arc, Mutex};

use qsh_core::trust::PIN_SOURCE_SSH_BOOTSTRAP;
use qsh_core::{SshRevival, TrustStore};
use qsh_proto::ErrorCode;
use qsh_testkit::fake_ssh::FakeSsh;
use qsh_testkit::netsim::NatKind;

use super::punch_route::{WorldOptions, exec, world};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_punch_is_followed_by_the_ssh_serve_revival() {
    let w = world(WorldOptions {
        register_b: false,
        direct_listener: false,
        b_nat: NatKind::None,
        ..WorldOptions::default()
    })
    .await;

    // The pin of B is the one `qsh pair ssh` wrote.
    let config_dir = w.a._dir.path().join("config");
    let trust_file = config_dir.join("trust.toml");
    let mut store = TrustStore::load(&trust_file).expect("trust.toml");
    assert!(store.mark_source("b", PIN_SOURCE_SSH_BOOTSTRAP));
    store.save(&trust_file).expect("save trust.toml");

    // `ssh` is the fake: it answers nothing useful, so the revival fails,
    // but every call it makes is recorded.
    let fake = FakeSsh::new();
    std::fs::write(
        config_dir.join("config.toml"),
        format!("[ssh]\nprogram = '{}'\n", fake.program().display()),
    )
    .expect("config.toml");
    let notices = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = notices.clone();
    let ops = w.a.ops.clone().with_ssh_revival(SshRevival {
        machine_mode: true,
        user: None,
        ssh: Default::default(),
        notice: Arc::new(move |line: &str| sink.lock().unwrap().push(line.to_string())),
    });

    let err = exec(&ops, "b")
        .await
        .expect_err("nothing answers, so the command fails");

    // The punch ran and failed...
    assert_eq!(w.punch_requests(), 1, "the route asked R to punch");
    assert_eq!(
        err.details["punch"]["reason"], "target_not_registered",
        "{err:?}"
    );
    assert!(
        matches!(err.code, ErrorCode::ConnectionFailed | ErrorCode::Timeout),
        "{err:?}"
    );
    // ...and the revival followed it.
    let notices = notices.lock().unwrap().clone();
    assert!(
        notices
            .iter()
            .any(|n| n.contains("starting its serve over ssh")),
        "the revival announced itself: {notices:?}"
    );
    assert!(
        !fake.calls().is_empty(),
        "the revival ran ssh after the punch gave up"
    );
    w.shutdown().await;
}
