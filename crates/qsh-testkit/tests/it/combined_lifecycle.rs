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
    /// The identity fingerprint a peer must pin to dial this runtime.
    host_fp: qsh_transport::Fingerprint,
    /// The startup diagnostics (an unusable `acl.toml`, say).
    diagnostics: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<Result<(), qsh_core::ops::OpError>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Runtime {
    async fn start() -> Self {
        Self::start_with(|_, _| {}).await
    }

    /// [`Self::start`] after `setup` has had its say about the files under
    /// the sandbox's `paths` (a `trust.toml`, an `acl.toml`) and the
    /// `config` the runtime is started with.
    async fn start_with(setup: impl FnOnce(&Paths, &mut Config)) -> Self {
        qsh_testkit::env_check::ensure_loopback_udp();
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
            .with_runtime_dir(dir.path().join("run"));
        identity::init(&paths, KeyStoreMode::File).expect("identity.init");
        let loaded = identity::load(&paths).expect("load").expect("an identity");
        let host_fp = loaded.identity.fingerprint;
        let mut config = Config::default();
        config.listen.serve = true;
        setup(&paths, &mut config);
        let diagnostics = Arc::new(Mutex::new(Vec::new()));

        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let notices = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let paths = paths.clone();
            let notices = Arc::clone(&notices);
            let diagnostics = Arc::clone(&diagnostics);
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
                    move |text| {
                        diagnostics
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(text.to_string());
                    },
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
            host_fp,
            diagnostics,
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

// ---------------------------------------------------------------------------
// The production assembly: roles, policy, trust watch, punch switch
// ---------------------------------------------------------------------------
//
// `combined.rs` and `combined_roles.rs` hand-wire a `Server` and a `Listen`
// from the same parts. The tests below start the production entry
// (`run_listen_serve`) on a sandbox with a real `trust.toml` and no
// `acl.toml` (or a broken one), so everything `run_listen_impl` adds on top
// of the parts is in play: `set_punch_enabled`, `set_path_watch`,
// `set_trust_watch`, the pairing window, the notice sink and `serve.json`.

use qsh_core::acl::PERMISSION_DENIED_MESSAGE;
use qsh_core::client::{ClientError, Session};
use qsh_core::exec::ExecSpec;
use qsh_core::handshake::{self, HelloError};
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, control_message};
use qsh_testkit::loopback::TestIdentity;
use qsh_testkit::reverse::{forward_hello, reverse_hello};
use qsh_transport::{Dialed, Dialer, FramedStream, Principal, StaticTrust};

use super::combined::{Reply, ask, classify, keepalive, open_req, punch_request};

/// Pins `(name, identity, role)` as a `trust.toml`.
fn trust_toml(pins: &[(&str, &TestIdentity, &str)]) -> String {
    pins.iter()
        .map(|(name, id, role)| {
            format!(
                "[[peer]]\nname = \"{name}\"\nfingerprint = \"{}\"\naddress = \"\"\n\
                 added_at = \"2026-11-11T00:00:00Z\"\nrole = \"{role}\"\n\n",
                id.fingerprint
            )
        })
        .collect()
}

impl Runtime {
    /// Dial the runtime as `peer`, trusting only the runtime's identity.
    async fn dial(&self, peer: &TestIdentity) -> Dialed {
        let trust =
            StaticTrust::empty().with_pin(self.host_fp, Principal::Device("box".to_string()));
        Dialer::new(peer.local.clone(), std::sync::Arc::new(trust))
            .dial(self.addr, "127.0.0.1")
            .await
            .expect("dial the combined runtime")
    }

    /// A forward connection: the `Hello` has no `reverse`.
    async fn forward(&self, peer: &TestIdentity) -> (Dialed, FramedStream, wire::Hello) {
        let dialed = self.dial(peer).await;
        let (ctl, hello) = handshake::initiate(&dialed.connection, forward_hello())
            .await
            .expect("forward hello");
        (dialed, ctl, hello)
    }

    /// A registration under `name`; the error frame when it is refused.
    async fn register(
        &self,
        peer: &TestIdentity,
        name: &str,
    ) -> Result<(Dialed, FramedStream), HelloError> {
        let dialed = self.dial(peer).await;
        let (ctl, _) = handshake::initiate(&dialed.connection, reverse_hello(name)).await?;
        Ok((dialed, ctl))
    }

    /// Replace `trust.toml` the way `qsh trust remove` does (write a sibling,
    /// rename it over).
    fn replace_trust(&self, text: &str) {
        let path = self.paths.trust_file();
        let tmp = path.with_extension("toml.new");
        std::fs::write(&tmp, text).expect("write the new trust.toml");
        std::fs::rename(&tmp, &path).expect("replace trust.toml");
    }
}

/// `true` when the request was authorized (it succeeded or failed past the
/// gate), `false` for the uniform denial.
fn allowed<T>(result: Result<T, ClientError>) -> bool {
    match result {
        Ok(_) => true,
        Err(ClientError::Remote {
            code: ErrorCode::PermissionDenied,
            message,
            ..
        }) => {
            assert_eq!(message, PERMISSION_DENIED_MESSAGE, "uniform denial");
            false
        }
        Err(ClientError::Remote { .. }) => true,
        Err(other) => panic!("neither an allow nor a denial: {other:?}"),
    }
}

fn exec_true() -> ExecSpec {
    ExecSpec {
        argv: vec!["true".into()],
        env: vec![],
        timeout: None,
        shell: None,
        agent_sock: None,
    }
}

async fn punch(ctl: &mut FramedStream) -> Reply {
    classify(ask(ctl, 2, control_message::Body::PunchRequest(punch_request())).await)
}

/// DoD 27.5 on the production assembly: a real `trust.toml` with a `full`, a
/// `reverse` and a `none` pin and no `acl.toml`. The `reverse` pin registers
/// and is punch-capable but is `PERMISSION_DENIED` for `session.open` and
/// `exec`; the `full` pin gets registration, forward actions and a punching
/// connection; the `none` pin gets nothing. Removing the `reverse` pin from
/// `trust.toml` withdraws its registration within the trust watch's poll
/// tick, which only the production assembly (`set_trust_watch`) arranges.
#[tokio::test(flavor = "multi_thread")]
async fn production_runtime_judges_pin_roles_on_all_three_branches() {
    let full = make_identity();
    let reverse = make_identity();
    let none = make_identity();
    let text = trust_toml(&[
        ("p-full", &full, "full"),
        ("p-reverse", &reverse, "reverse"),
        ("p-none", &none, "none"),
    ]);
    let mut rt = Runtime::start_with(|paths, _| {
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::write(paths.trust_file(), &text).expect("write trust.toml");
    })
    .await;
    assert!(
        !rt.paths.acl_file().exists(),
        "no acl.toml: the pins' roles are the whole policy"
    );

    // --- the `reverse` pin ------------------------------------------------
    let (reg_conn, reg_ctl) = rt
        .register(&reverse, "rev-target")
        .await
        .expect("a reverse pin registers");
    let _keep = keepalive(reg_ctl);
    let (dialed, ctl, hello) = rt.forward(&reverse).await;
    let mut s = Session::from_control(dialed.connection.clone(), ctl, hello);
    assert!(
        !allowed(s.session_open(open_req()).await),
        "a reverse pin gets no shell on the forward branch"
    );
    assert!(
        !allowed(s.exec_start(&exec_true()).await),
        "a reverse pin gets no exec"
    );
    let (d2, mut ctl2, _) = rt.forward(&reverse).await;
    assert_eq!(
        punch(&mut ctl2).await,
        Reply::PunchRefusal(wire::PunchRefusal::TargetNotRegistered as i32),
        "a reverse pin may use the rendezvous (host.punch)"
    );

    // --- the `full` pin ---------------------------------------------------
    let (full_reg, full_ctl) = rt
        .register(&full, "full-target")
        .await
        .expect("a full pin registers too (host.reverse)");
    let _keep_full = keepalive(full_ctl);
    let (fd, fctl, fhello) = rt.forward(&full).await;
    let mut fs = Session::from_control(fd.connection.clone(), fctl, fhello);
    assert!(allowed(fs.exec_start(&exec_true()).await), "full: exec");
    #[cfg(unix)]
    assert!(
        fs.session_open(open_req()).await.is_ok(),
        "full: session.open on the production host"
    );
    let (fd2, mut fctl2, _) = rt.forward(&full).await;
    assert_eq!(
        punch(&mut fctl2).await,
        Reply::PunchRefusal(wire::PunchRefusal::TargetNotRegistered as i32)
    );

    // --- the `none` pin ---------------------------------------------------
    match rt.register(&none, "none-target").await {
        Err(HelloError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied);
            assert_eq!(message, PERMISSION_DENIED_MESSAGE);
        }
        other => panic!("a none pin must not register: {:?}", other.map(|_| ())),
    }
    let (nd, nctl, nhello) = rt.forward(&none).await;
    let mut ns = Session::from_control(nd.connection.clone(), nctl, nhello);
    assert!(!allowed(ns.session_open(open_req()).await), "none: shell");
    let (nd2, mut nctl2, _) = rt.forward(&none).await;
    assert_eq!(
        punch(&mut nctl2).await,
        Reply::Error("PERMISSION_DENIED".into()),
        "none: no rendezvous"
    );

    // --- trust watch ------------------------------------------------------
    // Both registrations are still up before the edit.
    assert!(reg_conn.connection.close_reason().is_none());
    assert!(full_reg.connection.close_reason().is_none());
    rt.replace_trust(&trust_toml(&[
        ("p-full", &full, "full"),
        ("p-none", &none, "none"),
    ]));
    tokio::time::timeout(Duration::from_secs(8), reg_conn.connection.closed())
        .await
        .expect("the removed pin's registration is closed by the trust watch");
    assert!(
        reg_conn.connection.closed_by_trust_withdrawal(),
        "closed with the trust-withdrawn code: {:?}",
        reg_conn.connection.close_reason()
    );
    // Its forward connection goes the same way, and a new dial is refused at
    // the handshake: the pin is gone.
    tokio::time::timeout(Duration::from_secs(8), dialed.connection.closed())
        .await
        .expect("the removed pin's forward connection is closed too");
    let redial = Dialer::new(
        reverse.local.clone(),
        std::sync::Arc::new(
            StaticTrust::empty().with_pin(rt.host_fp, Principal::Device("box".to_string())),
        ),
    )
    .dial(rt.addr, "127.0.0.1")
    .await;
    assert!(
        match redial {
            Err(_) => true,
            Ok(d) => handshake::initiate(&d.connection, forward_hello())
                .await
                .is_err(),
        },
        "a withdrawn pin cannot start a new connection"
    );
    // The pins that stay are untouched.
    assert!(full_reg.connection.close_reason().is_none());
    assert!(fd.connection.close_reason().is_none());
    drop((d2, fd2, nd2));
    rt.stop().await;
}

/// An `acl.toml` that does not parse denies every request from every peer,
/// roles included (CLAUDE.md "Security defaults"): on the production
/// assembly the combined endpoint refuses the registration, the punch and the
/// forward request of a `full` pin, and the startup diagnostic says why.
#[tokio::test(flavor = "multi_thread")]
async fn production_runtime_with_an_unparseable_acl_denies_all_three_branches() {
    let full = make_identity();
    let text = trust_toml(&[("p-full", &full, "full")]);
    let mut rt = Runtime::start_with(|paths, _| {
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::write(paths.trust_file(), &text).expect("write trust.toml");
        std::fs::write(paths.acl_file(), "this is [not toml").expect("write acl.toml");
    })
    .await;
    assert!(
        !rt.diagnostics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "the broken policy is reported at startup"
    );

    match rt.register(&full, "full-target").await {
        Err(HelloError::Remote { code, message, .. }) => {
            assert_eq!(code, ErrorCode::PermissionDenied);
            assert_eq!(message, PERMISSION_DENIED_MESSAGE);
        }
        other => panic!("registration must be denied: {:?}", other.map(|_| ())),
    }
    let (_pd, mut pctl, _) = rt.forward(&full).await;
    assert_eq!(
        punch(&mut pctl).await,
        Reply::Error("PERMISSION_DENIED".into())
    );
    let (fd, fctl, fhello) = rt.forward(&full).await;
    let mut fs = Session::from_control(fd.connection.clone(), fctl, fhello);
    assert!(!allowed(fs.exec_start(&exec_true()).await), "forward exec");
    assert!(!allowed(fs.session_open(open_req()).await), "forward shell");
    rt.stop().await;
}

/// `[punch].mode = "off"` is read by the production assembly
/// (`set_punch_enabled`) and by the host's own dispatch: the first-request
/// intercept is off, so a `PunchRequest` is the host's `UNSUPPORTED` for a
/// `full` pin, while the same runtime with the default mode answers it as a
/// rendezvous.
#[tokio::test(flavor = "multi_thread")]
async fn production_runtime_punch_mode_off_turns_the_intercept_off() {
    for off in [false, true] {
        let full = make_identity();
        let text = trust_toml(&[("p-full", &full, "full")]);
        let mut rt = Runtime::start_with(|paths, config| {
            std::fs::create_dir_all(&paths.config_dir).expect("config dir");
            std::fs::write(paths.trust_file(), &text).expect("write trust.toml");
            if off {
                config.punch.mode = Some(qsh_core::punch::PunchMode::Off);
            }
        })
        .await;
        let (_d, mut ctl, _) = rt.forward(&full).await;
        let reply = punch(&mut ctl).await;
        if off {
            assert_eq!(reply, Reply::Error("UNSUPPORTED".into()), "mode off");
        } else {
            assert_eq!(
                reply,
                Reply::PunchRefusal(wire::PunchRefusal::TargetNotRegistered as i32),
                "mode auto"
            );
        }
        rt.stop().await;
    }
}

/// Decision 15: the forward sessions' agent sockets live under
/// `<runtime>/agent/` and the local control socket is `<runtime>/<pid>.sock`.
/// One combined process holds both in one runtime directory without a clash,
/// and both are gone after the clean stop.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn agent_sockets_and_the_localctl_socket_coexist_in_one_runtime_dir() {
    let full = make_identity();
    let text = trust_toml(&[("p-full", &full, "full")]);
    let mut rt = Runtime::start_with(|paths, _| {
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::write(paths.trust_file(), &text).expect("write trust.toml");
    })
    .await;
    let run = rt.paths.runtime_dir().to_path_buf();
    let ctl_sock = run.join(format!("{}.sock", std::process::id()));
    assert!(ctl_sock.exists(), "the localctl socket is bound");

    let (d, ctl, hello) = rt.forward(&full).await;
    let mut s = Session::from_control(d.connection.clone(), ctl, hello);
    let mut req = open_req();
    req.agent_channel = vec![0xa5; wire::AGENT_CHANNEL_LEN];
    let opened = s.session_open(req).await.expect("session.open with agent");
    assert_eq!(opened.agent, wire::AgentGrant::Forwarded as i32);

    let agent_dir = run.join("agent");
    let agent_socks: Vec<_> = std::fs::read_dir(&agent_dir)
        .expect("the agent directory exists")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    assert_eq!(agent_socks.len(), 1, "one agent socket: {agent_socks:?}");
    assert_ne!(agent_socks[0], ctl_sock);
    assert!(
        agent_socks[0].starts_with(&agent_dir) && ctl_sock.parent() == Some(run.as_path()),
        "the two live at different levels of one runtime dir"
    );
    assert!(ctl_sock.exists(), "the localctl socket is still there");

    s.close();
    rt.stop().await;
    assert!(!ctl_sock.exists(), "the localctl socket is cleaned up");
}
