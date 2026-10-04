//! In-crate reverse-mode harness for the two `idle_timeout` integration
//! tests (`docs/design/testing.md` L4): a real controller
//! ([`Listen::run`]), a real target ([`run_reverse_observed`]) and a small
//! UDP relay between them that can be cut on demand.
//!
//! `qsh-testkit::reverse::ReverseHarness` is the usual way to run both ends
//! in one process, but `qsh-testkit` depends on `qsh-core`, so pulling it in
//! as a dev-dependency would link `qsh-core` twice and the `#[cfg(test)]`
//! injections in this crate (`super::path_watch_config`,
//! `Listen::set_test_path_watch`) would never reach that copy. Hence this
//! separate, deliberately small harness.
//!
//! A cut relay swallows every datagram in both directions, so the two QUIC
//! endpoints see pure silence: no close frame, no ICMP. With both
//! `PathWatch` floors raised above the 45 s idle timeout
//! ([`slow_path_watch`]) quinn's `TimedOut` is what ends the connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use qsh_proto::KeyStoreKind;
use qsh_transport::{CertificateDer, Fingerprint, Listener, LocalIdentity, Principal, StaticTrust};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, oneshot, watch};
use tokio::task::JoinHandle;

use crate::acl::AllowAllPinned;
use crate::audit::MemoryAuditSink;
use crate::broker::{Clock, SystemClock};
use crate::client::pathwatch::PathWatchConfig;
use crate::client::wake::WakeEvent;
use crate::config::{Config, Paths, ReverseConfig};
use crate::identity::{Identity, LoadedIdentity};
use crate::reverse::listen::{Listen, STALE_SWEEP_TICK, TARGET};
use crate::reverse::registry::Registry;
use crate::reverse::target::run_reverse_observed;
use crate::trust::TrustStore;

/// The environment switch that gates the ~50 s wall-clock tests
/// (`docs/design/testing.md` L4), the same one `reverse_blackout` uses.
pub(super) fn slow_tests_enabled() -> bool {
    std::env::var_os("QSH_ACCEPTANCE_SLOW").is_some_and(|v| !v.is_empty() && v != "0")
}

/// `min_dead_after` well past quinn's 45 s idle timeout, so `PathWatch`
/// cannot declare the silent path dead first.
pub(super) fn slow_path_watch() -> PathWatchConfig {
    PathWatchConfig {
        min_dead_after: Duration::from_secs(120),
        ..PathWatchConfig::default()
    }
}

/// Upper bound on any single "this must happen" wait: the 45 s idle timeout
/// plus generous slack. Never a budget the scenario should need in full.
pub(super) const WAIT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// `qsh::reverse` diagnostic capture.
// ---------------------------------------------------------------------------

fn captured() -> &'static Mutex<Vec<serde_json::Value>> {
    static LINES: OnceLock<Mutex<Vec<serde_json::Value>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

static CAPTURED_SIGNAL: Notify = Notify::const_new();

struct CaptureLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != TARGET {
            return;
        }
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            captured()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(value);
            CAPTURED_SIGNAL.notify_waiters();
        }
    }
}

struct MessageOnly<'a>(&'a mut String);

impl tracing::field::Visit for MessageOnly<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

/// Install the capture layer as the process-global subscriber (once).
pub(super) fn capture_reverse_events() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::registry()
            .with(CaptureLayer)
            .try_init()
            .ok();
    });
}

/// Every captured `qsh::reverse` line with this `host` and `event`, oldest
/// first. Callers use a `host` unique to their test, so tests sharing a
/// process (plain `cargo test`) cannot see each other's lines.
pub(super) fn lines(host: &str, event: &str) -> Vec<serde_json::Value> {
    captured()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|v| v["host"] == host && v["event"] == event)
        .cloned()
        .collect()
}

/// Wait, event-driven and bounded by [`WAIT`], until a captured line for
/// `host`/`event` exists, and return the first one.
pub(super) async fn wait_for_line(host: &str, event: &str) -> serde_json::Value {
    tokio::time::timeout(WAIT, async {
        loop {
            // Register before the check so a line landing in between is
            // not missed.
            let notified = CAPTURED_SIGNAL.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(line) = lines(host, event).into_iter().next() {
                return line;
            }
            notified.await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no `{event}` line for `{host}` within {WAIT:?}"))
}

/// Like [`wait_for_line`], but waits until at least `n` lines exist for
/// `host`/`event` and returns the `n`th (1-based), bounded by `within`.
pub(super) async fn wait_for_nth_line(
    host: &str,
    event: &str,
    n: usize,
    within: Duration,
) -> serde_json::Value {
    tokio::time::timeout(within, async {
        loop {
            let notified = CAPTURED_SIGNAL.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(line) = lines(host, event).into_iter().nth(n - 1) {
                return line;
            }
            notified.await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {n}th `{event}` line for `{host}` within {within:?}"))
}

// ---------------------------------------------------------------------------
// UDP relay with a cut switch.
// ---------------------------------------------------------------------------

/// A UDP relay in front of the controller. While not cut it forwards every
/// datagram both ways; once [`Self::cut`], it drops everything.
pub(crate) struct UdpRelay {
    /// The relay's own address: what a client dials instead of `upstream`.
    pub(crate) addr: SocketAddr,
    cut: Arc<AtomicBool>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl UdpRelay {
    pub(crate) async fn start(upstream: SocketAddr) -> Self {
        let front = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind relay socket"),
        );
        let addr = front.local_addr().expect("relay addr");
        let cut = Arc::new(AtomicBool::new(false));
        let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let main = tokio::spawn({
            let cut = cut.clone();
            let tasks = tasks.clone();
            async move {
                // One upstream socket per client source address, so the
                // controller sees a stable peer per target connection and a
                // re-dial from a fresh source port gets a fresh leg.
                let mut legs: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
                let mut buf = vec![0u8; 65_536];
                loop {
                    let Ok((n, src)) = front.recv_from(&mut buf).await else {
                        return;
                    };
                    if cut.load(Ordering::SeqCst) {
                        continue;
                    }
                    let leg = match legs.get(&src) {
                        Some(leg) => leg.clone(),
                        None => {
                            let leg = Arc::new(
                                UdpSocket::bind("127.0.0.1:0")
                                    .await
                                    .expect("bind relay leg"),
                            );
                            leg.connect(upstream).await.expect("connect relay leg");
                            let back = tokio::spawn({
                                let leg = leg.clone();
                                let front = front.clone();
                                let cut = cut.clone();
                                async move {
                                    let mut buf = vec![0u8; 65_536];
                                    while let Ok(n) = leg.recv(&mut buf).await {
                                        if !cut.load(Ordering::SeqCst) {
                                            let _ = front.send_to(&buf[..n], src).await;
                                        }
                                    }
                                }
                            });
                            tasks.lock().unwrap_or_else(|e| e.into_inner()).push(back);
                            legs.insert(src, leg.clone());
                            leg
                        }
                    };
                    let _ = leg.send(&buf[..n]).await;
                }
            }
        });
        tasks.lock().unwrap_or_else(|e| e.into_inner()).push(main);
        Self { addr, cut, tasks }
    }

    /// Drop every datagram from now on, in both directions.
    pub(crate) fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
    }

    /// Forward again after a [`Self::cut`].
    pub(super) fn restore(&self) {
        self.cut.store(false, Ordering::SeqCst);
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        for task in self.tasks.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Identities.
// ---------------------------------------------------------------------------

struct TestIdentity {
    local: LocalIdentity,
    fingerprint: Fingerprint,
    cert_der: Vec<u8>,
}

fn make_identity() -> TestIdentity {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    let cert = params.self_signed(&key).expect("self-sign");
    let der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = Fingerprint::of_cert_der(&der).expect("fingerprint");
    TestIdentity {
        local: LocalIdentity {
            cert_chain: vec![der.clone()],
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        },
        fingerprint,
        cert_der: der.to_vec(),
    }
}

fn loaded_identity(test: &TestIdentity, device_id: &str) -> LoadedIdentity {
    LoadedIdentity {
        identity: Identity {
            device_id: device_id.to_string(),
            fingerprint: test.fingerprint,
            key_store: KeyStoreKind::File,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            cert_der: test.cert_der.clone(),
            issued_by_ca: None,
        },
        local: test.local.clone(),
    }
}

// ---------------------------------------------------------------------------
// The rig.
// ---------------------------------------------------------------------------

/// The target-side knobs [`Rig::start_with`] varies. [`Default`] is what
/// [`Rig::start`] uses: a short backoff and the raised `PathWatch` floor.
pub(super) struct TargetOptions {
    /// `[reverse].backoff_initial_ms`.
    pub(super) backoff_initial_ms: u64,
    /// `[reverse].backoff_max_ms`.
    pub(super) backoff_max_ms: u64,
    /// The target's `PathWatch` config.
    pub(super) path_watch: PathWatchConfig,
    /// The controller's `PathWatch` config for every registration it
    /// drives ([`Listen::set_test_path_watch`]).
    pub(super) controller_path_watch: PathWatchConfig,
}

impl Default for TargetOptions {
    fn default() -> Self {
        Self {
            backoff_initial_ms: 50,
            backoff_max_ms: 200,
            path_watch: slow_path_watch(),
            controller_path_watch: slow_path_watch(),
        }
    }
}

/// A controller and a target wired through a cuttable [`UdpRelay`].
pub(super) struct Rig {
    /// Injects wakes into the target's reconnect loop.
    wake_tx: watch::Sender<WakeEvent>,
    relay: UdpRelay,
    controller_shutdown: Option<oneshot::Sender<()>>,
    target_shutdown: Option<oneshot::Sender<()>>,
    controller_task: JoinHandle<()>,
    target_task: JoinHandle<()>,
    _sweeper: JoinHandle<()>,
    /// Keeps the controller alive for the rig's lifetime.
    _listen: Arc<Listen>,
}

impl Rig {
    /// Start the controller, then a target that registers with it as
    /// `target_name`, dialing through the relay under the trust-store alias
    /// `controller_alias`. Both `PathWatch` floors are raised
    /// ([`slow_path_watch`]). The target's own `qsh::reverse` lines carry
    /// `host = controller_alias`; the controller's carry
    /// `host = target_name`.
    pub(super) async fn start(controller_alias: &str, target_name: &str) -> Self {
        Self::start_with(controller_alias, target_name, TargetOptions::default()).await
    }

    /// [`Self::start`] with caller-chosen target knobs. The target listens
    /// to this rig's injected wake signal ([`Self::inject_wake`]) instead of
    /// the process-wide detector.
    pub(super) async fn start_with(
        controller_alias: &str,
        target_name: &str,
        options: TargetOptions,
    ) -> Self {
        capture_reverse_events();
        let controller = make_identity();
        let target = make_identity();

        // Controller.
        let trust = StaticTrust::empty().with_pin(
            target.fingerprint,
            Principal::Device(target_name.to_string()),
        );
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            controller.local.clone(),
            Arc::new(trust),
        )
        .expect("bind controller");
        let controller_addr = listener.local_addr().expect("controller addr");
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let listen = Listen::new_with_sweep_tick(
            Registry::new(clock.clone(), false),
            Arc::new(AllowAllPinned),
            Arc::new(MemoryAuditSink::new()),
            "controller-device",
            clock,
            Duration::from_secs(120),
            STALE_SWEEP_TICK,
        );
        listen.set_test_path_watch(options.controller_path_watch);
        let sweeper = tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));
        let (controller_shutdown, controller_rx) = oneshot::channel::<()>();
        let controller_task = tokio::spawn(listen.clone().run(listener, async move {
            let _ = controller_rx.await;
        }));

        // Relay in front of the controller.
        let relay = UdpRelay::start(controller_addr).await;

        // Target: an on-disk config dir pinning the controller (through the
        // relay) under `controller_alias`, exactly like the production
        // path.
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        let mut trust_store = TrustStore::default();
        trust_store.add_peer(
            controller_alias,
            Some(relay.addr.to_string()),
            controller.fingerprint,
            "2026-01-01T00:00:00Z".to_string(),
        );
        trust_store
            .save(&paths.trust_file())
            .expect("save target trust.toml");
        std::fs::write(
            paths.acl_file(),
            format!(
                "[[acl]]\nprincipal = \"device:{controller_alias}\"\nallow = [\"exec.run\", \
                 \"session.open\", \"session.list\", \"session.attach\", \"session.control\", \
                 \"host.reverse\", \"forward.local\", \"forward.remote\"]\n"
            ),
        )
        .expect("write target acl.toml");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(paths.acl_file(), std::fs::Permissions::from_mode(0o600))
                .expect("chmod target acl.toml");
        }
        // A short backoff keeps the post-loss `retry` prompt; the scenario's
        // own bound is [`WAIT`].
        let config = Config {
            reverse: ReverseConfig {
                backoff_initial_ms: Some(options.backoff_initial_ms),
                backoff_max_ms: Some(options.backoff_max_ms),
                backoff_jitter_pct: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        let identity = loaded_identity(&target, "target-device");
        let controller_alias = controller_alias.to_string();
        let target_name = target_name.to_string();
        let (target_shutdown, target_rx) = oneshot::channel::<()>();
        let (wake_tx, wake_rx) = watch::channel(WakeEvent::default());
        let target_task = tokio::spawn(crate::reverse::TEST_PATH_WATCH_CONFIG.scope(
            options.path_watch,
            crate::reverse::TEST_WAKE.scope(wake_rx, async move {
                // `dir` lives as long as the target runs.
                let _dir = dir;
                let _ = run_reverse_observed(
                    &paths,
                    &config,
                    identity,
                    &controller_alias,
                    Some(&target_name),
                    |_runtime| {},
                    || {},
                    async move {
                        let _ = target_rx.await;
                    },
                )
                .await;
            }),
        ));

        Self {
            wake_tx,
            relay,
            controller_shutdown: Some(controller_shutdown),
            target_shutdown: Some(target_shutdown),
            controller_task,
            target_task,
            _sweeper: sweeper,
            _listen: listen,
        }
    }

    /// Stall (`true`) or resume (`false`) the controller's control loop
    /// ([`Listen::set_test_control_stall`]) while its QUIC connection keeps
    /// running.
    pub(super) fn stall_controller_control(&self, stalled: bool) {
        self._listen.set_test_control_stall(stalled);
    }

    /// Cut the relay: from now on both ends see only silence.
    pub(super) fn cut(&self) {
        self.relay.cut();
    }

    /// Undo [`Self::cut`]: datagrams flow again.
    pub(super) fn restore(&self) {
        self.relay.restore();
    }

    /// Tell the target's reconnect loop the machine just woke from
    /// `slept_ms` of sleep.
    pub(super) fn inject_wake(&self, slept_ms: u64) {
        self.wake_tx.send_modify(|event| {
            event.seq += 1;
            event.slept_ms = slept_ms;
        });
    }

    /// Stop the target, then the controller, and wait for both.
    pub(super) async fn shutdown(mut self) {
        if let Some(tx) = self.target_shutdown.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), &mut self.target_task).await;
        if let Some(tx) = self.controller_shutdown.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), &mut self.controller_task).await;
        self._sweeper.abort();
    }
}
