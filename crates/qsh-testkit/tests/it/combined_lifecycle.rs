//! The runtime of the combined `listen` + `serve` endpoint (ADR-0059
//! decisions 16, 17 and 19), run the way `qsh listen` with `[listen].serve =
//! true` runs it: `qsh_core::reverse::listen::run_listen_serve` on a sandbox
//! of its own, in-process, with a shutdown the test pulls.
//!
//! The assembly of the shared parts and the branches of the accept loop are
//! in `combined.rs`; here is what the runtime adds around them: the pairing
//! window of a forward host, the `serve.json` record, and the files that
//! must be gone when the process is.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use qsh_core::config::{Config, Paths};
use qsh_core::identity;
use qsh_core::serve::record::{self, ServeRecord, ServeRecordMode};
use qsh_core::trust::TrustStore;
use qsh_core::trust::pairing::{InviteStore, generate_secret};
use qsh_proto::KeyStoreMode;
use qsh_proto::pairing::INVITE_SECRET_LEN;
use qsh_testkit::loopback::make_identity;
use qsh_testkit::pairing::pairing_dialer;

const TIMEOUT: Duration = Duration::from_secs(20);

/// A running combined runtime on `127.0.0.1:0` in a sandbox.
struct Runtime {
    _dir: tempfile::TempDir,
    paths: Paths,
    addr: SocketAddr,
    /// `serve.json` as the runtime found it when it announced the address.
    record_at_bind: Option<ServeRecord>,
    /// The notices the forward host side handed to the caller.
    notices: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<Result<(), qsh_core::ops::OpError>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Runtime {
    async fn start() -> Self {
        qsh_testkit::env_check::ensure_loopback_udp();
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
            .with_runtime_dir(dir.path().join("run"));
        identity::init(&paths, KeyStoreMode::File).expect("identity.init");
        let loaded = identity::load(&paths).expect("load").expect("an identity");
        let mut config = Config::default();
        config.listen.serve = true;

        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let notices = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let paths = paths.clone();
            let notices = Arc::clone(&notices);
            tokio::spawn(async move {
                let record_paths = paths.clone();
                qsh_core::reverse::listen::run_listen_serve(
                    &paths,
                    &config,
                    loaded,
                    Some("127.0.0.1:0"),
                    move |addr| {
                        let _ = bound_tx.send((addr, record::read(&record_paths)));
                    },
                    |_| {},
                    move |notice| {
                        notices
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(notice.to_string());
                    },
                    async move {
                        let _ = stop_rx.await;
                    },
                )
                .await
            })
        };
        let (addr, record_at_bind) = match tokio::time::timeout(TIMEOUT, bound_rx).await {
            Ok(Ok(bound)) => bound,
            _ => panic!(
                "the combined runtime ended without binding: {:?}",
                task.await
            ),
        };
        Self {
            _dir: dir,
            paths,
            addr,
            record_at_bind,
            notices,
            task,
            stop: Some(stop_tx),
        }
    }

    /// Ask it to stop and wait for it to return.
    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(TIMEOUT, &mut self.task)
            .await
            .expect("the runtime stops")
            .expect("no panic")
            .expect("a clean stop");
    }

    /// A fresh invite on this runtime's on-disk store, the way `qsh pair
    /// invite` writes one.
    fn invite(&self) -> [u8; INVITE_SECRET_LEN] {
        let secret = generate_secret();
        let path = self.paths.invites_file();
        let mut store = InviteStore::load(&path).expect("load invites");
        store.add(secret.as_slice(), SystemTime::now(), None);
        store.save(&path).expect("save invites");
        *secret
    }
}

/// Decision 16: the combined endpoint is a forward host, so its pairing
/// window works the way a standalone `qsh serve`'s does. An initiator with no
/// pin dials with an invite, redeems it over the same socket, and is pinned
/// by this endpoint under the name it gave.
#[tokio::test(flavor = "multi_thread")]
async fn pair_invite_redeems_on_a_combined_endpoint() {
    let mut rt = Runtime::start().await;
    let secret = rt.invite();
    let laptop = make_identity();

    let dialed = pairing_dialer(laptop.local.clone())
        .dial(rt.addr, "127.0.0.1")
        .await
        .expect("a pairing dial reaches the combined endpoint");
    let success = qsh_core::pairing::accept(&dialed.connection, "laptop", &secret)
        .await
        .expect("the invite is redeemed");
    assert!(!success.pinned_name.is_empty());
    dialed.connection.close(0, b"done");

    let trust = TrustStore::load(&rt.paths.trust_file()).expect("trust.toml");
    let pinned = trust.find("laptop").expect("laptop is pinned");
    assert_eq!(pinned.fingerprint, laptop.fingerprint.to_string());

    // The invite was consumed: the same secret from another initiator is
    // refused, so the window stays one-shot there too.
    let other = make_identity();
    let dialed = pairing_dialer(other.local)
        .dial(rt.addr, "127.0.0.1")
        .await
        .expect("dial");
    let again = qsh_core::pairing::accept(&dialed.connection, "other", &secret).await;
    assert!(again.is_err(), "a redeemed invite redeems once");
    assert!(
        TrustStore::load(&rt.paths.trust_file())
            .expect("trust.toml")
            .find("other")
            .is_none()
    );
    rt.stop().await;
}

/// Decision 17: the runtime publishes `serve.json` with the address it
/// really bound, as a persistent serve, before it announces that address,
/// and removes it, with the local control socket, when it ends. That record
/// is what lets the SSH bootstrap find this endpoint instead of starting an
/// on-demand serve beside it.
#[tokio::test(flavor = "multi_thread")]
async fn combined_runtime_publishes_serve_json_and_cleans_up_on_shutdown() {
    let mut rt = Runtime::start().await;
    let record = rt
        .record_at_bind
        .clone()
        .expect("serve.json exists when the address is announced");
    assert_eq!(record.pid, std::process::id());
    assert_eq!(record.mode, ServeRecordMode::Persistent);
    assert_eq!(record.socket_addr(), Some(rt.addr));
    assert_eq!(
        record::live_serve(&rt.paths).map(|r| r.pid),
        Some(std::process::id())
    );
    assert!(
        rt.notices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "nothing to report yet"
    );

    // The local control socket of the listen side is there while it runs.
    let socket = |paths: &Paths| {
        std::fs::read_dir(paths.runtime_dir())
            .map(|dir| {
                dir.filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sock"))
                    .count()
            })
            .unwrap_or(0)
    };
    #[cfg(unix)]
    assert_eq!(socket(&rt.paths), 1, "the localctl socket is bound");

    rt.stop().await;
    assert!(
        record::read(&rt.paths).is_none(),
        "a clean exit removes serve.json"
    );
    assert_eq!(socket(&rt.paths), 0, "the localctl socket is cleaned up");
}
