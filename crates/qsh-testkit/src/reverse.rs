//! In-process reverse-mode harness (`docs/design/testing.md` L3, `PLAN.md`
//! Step 3, PR 3b): a `qsh listen` controller plus the raw dial primitives a
//! test needs to play the `qsh reverse` target's wire role.
//!
//! [`ReverseHarness`] builds the controller the same way
//! [`qsh_core::reverse::listen::run_listen`] does — bind, trust, registry,
//! [`Listen::new`] — except it keeps the `Arc<Listen>` handle `run_listen`
//! itself never returns (it blocks forever inside its own accept loop). A
//! test needs that handle: `Listen::registry`/`Listen::live_connections`
//! are how `reverse/listen.rs`'s own module docs say a test should observe
//! registration state, instead of scraping stderr. This mirrors
//! [`crate::loopback::LoopbackHarness`], which for the identical reason
//! builds `Server::new(..)` directly rather than calling `serve::run_serve`.
//!
//! Two ways to play the target side of a connection:
//!
//! - [`ReverseHarness::initiate`]/[`ReverseHarness::register`] — dial +
//!   [`qsh_core::handshake::initiate`] with a caller-built `Hello`, handing
//!   back the raw [`Connection`]/[`FramedStream`] so a test can read the
//!   *actual* reply frame (never just an `Err`) and keep driving the
//!   connection afterward. Every negative/deny/conflict-path assertion in
//!   `reverse_loopback.rs` is built on this — it is what proves a rejection
//!   arrived as a real error frame the peer received, not a bare connection
//!   close (`PLAN.md` M3 Step 3, "거부 error frame의 전달 보장"). It is also
//!   the only way to exercise the "controller role discipline" scenarios:
//!   nothing in Step 3's product code ever makes a real `qsh reverse`
//!   process send a request *to* its controller (that is wire-legal per
//!   `docs/design/protocol.md` §11 header but has no producer yet), so a
//!   test has to hold the pen itself.
//! - [`ReverseHarness::run_target`] — the real
//!   [`qsh_core::reverse::target::run_reverse`], for scenarios that want
//!   the genuine CLI-facing entry point end to end (real on-disk
//!   `trust.toml`, real `host_runtime`).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_core::acl::{AllowAllPinned, Authorizer};
use qsh_core::audit::{AuditRecord, MemoryAuditSink};
use qsh_core::broker::{Broker, BrokerConfig, PeerFingerprint, PipeFactory, SystemClock};
use qsh_core::client::Session;
use qsh_core::config::{Config, Paths};
use qsh_core::handshake::{self, HelloError};
use qsh_core::identity::{Identity, LoadedIdentity};
use qsh_core::ops::OpError;
pub use qsh_core::reverse::listen::Listen;
use qsh_core::reverse::registry::Registry;
pub use qsh_core::reverse::registry::{EntryState, ReverseEntry};
use qsh_core::reverse::target::run_reverse_observed;
pub use qsh_core::serve::HostRuntime;
use qsh_core::server::{ConnCtx, Server};
use qsh_core::trust::TrustStore;
use qsh_proto::KeyStoreKind;
use qsh_proto::wire::{self, Hello};
use qsh_transport::{
    Connection, DialError, Dialed, Dialer, FramedStream, Listener, Principal, StaticTrust,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::chaos::ChaosProxy;
use crate::loopback::{TestIdentity, make_identity};
use crate::pair::HostedPair;

/// A `qsh listen` controller bound on `127.0.0.1:0` — see module docs for
/// why this is built by hand rather than by calling
/// [`qsh_core::reverse::listen::run_listen`].
pub struct ReverseHarness {
    /// The controller itself — `registry()`/`live_connections()` are how a
    /// test observes registration state without scraping stderr.
    pub listen: Arc<Listen>,
    /// The controller's bound address — what a target dials.
    pub addr: SocketAddr,
    /// Every audit record the controller produced.
    pub audit: Arc<MemoryAuditSink>,
    /// The controller's own identity. Its SPKI fingerprint is what a
    /// target's trust store must pin to reach this controller at all.
    pub controller: TestIdentity,
    task: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl ReverseHarness {
    /// A controller with the interim allow-all-pinned policy,
    /// `allow_advertised_names = false`, and an empty inbound trust store —
    /// a test adds whichever target identities it needs via
    /// [`Self::start_with`] instead.
    pub async fn start() -> Self {
        Self::start_with(Arc::new(AllowAllPinned), false, StaticTrust::empty()).await
    }

    /// A controller with a caller-chosen policy, `allow_advertised_names`
    /// setting, and inbound trust store — the target identities this
    /// controller authenticates at the QUIC layer. This is also what feeds
    /// the registry's trust-store-alias resolution: `reverse::admit::admit`
    /// derives the alias from exactly this same `(AuthPath::Pin,
    /// Principal::Device(name))` pin, so pinning `target` here under
    /// `"widget"` is what makes `"widget"` the name a registration
    /// resolves to.
    pub async fn start_with(
        authorizer: Arc<dyn Authorizer>,
        allow_advertised_names: bool,
        trust: StaticTrust,
    ) -> Self {
        // `docs/design/protocol.md` §11-4's documented default
        // (`ListenConfig::DEFAULT_STALE_RETENTION_SECS`) — most callers
        // don't care about stale-retention *timing*; a test that does uses
        // [`Self::start_with_stale_retention`] instead.
        Self::start_with_stale_retention(
            authorizer,
            allow_advertised_names,
            trust,
            Duration::from_secs(120),
        )
        .await
    }

    /// [`Self::start_with`] with a caller-chosen `[listen].stale_retention`
    /// — for a test that actually wants to observe
    /// [`Registry::sweep_expired`]'s removal firing (`docs/design/testing.md`
    /// L4), rather than treating a live-vs-stale registration as a
    /// same-process-forever detail. Also spawns
    /// [`Listen::run_stale_sweeper`], exactly like production's
    /// `run_listen_unix` does — without this, a harness registration could
    /// transition to [`EntryState::Stale`] but nothing would ever sweep it,
    /// no matter how long a test waited (adversarial review finding: the
    /// harness never wired the sweeper at all).
    pub async fn start_with_stale_retention(
        authorizer: Arc<dyn Authorizer>,
        allow_advertised_names: bool,
        trust: StaticTrust,
        stale_retention: Duration,
    ) -> Self {
        Self::start_with_stale_retention_and_sweep_tick(
            authorizer,
            allow_advertised_names,
            trust,
            stale_retention,
            qsh_core::reverse::listen::STALE_SWEEP_TICK,
        )
        .await
    }

    /// [`Self::start_with_stale_retention`] with a caller-chosen sweeper
    /// tick — for an L4 test that wants to actually observe
    /// [`Listen::run_stale_sweeper`] fire without paying
    /// `STALE_SWEEP_TICK`'s real 5 s wall-clock cost per tick
    /// (adversarial review finding: the only integration coverage of the
    /// sweeper previously had no way to inject a faster tick and so paid
    /// that cost on every run).
    pub async fn start_with_stale_retention_and_sweep_tick(
        authorizer: Arc<dyn Authorizer>,
        allow_advertised_names: bool,
        trust: StaticTrust,
        stale_retention: Duration,
        sweep_tick: Duration,
    ) -> Self {
        let controller = make_identity();
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            controller.local.clone(),
            Arc::new(trust),
        )
        .expect("bind controller");
        let addr = listener.local_addr().expect("local addr");
        let audit = Arc::new(MemoryAuditSink::new());
        let clock: Arc<dyn qsh_core::broker::Clock> = Arc::new(SystemClock);
        let registry = Registry::new(clock.clone(), allow_advertised_names);
        let listen = Listen::new_with_sweep_tick(
            registry,
            authorizer,
            audit.clone(),
            "controller-device",
            clock,
            stale_retention,
            sweep_tick,
        );
        tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(listen.clone().run(listener, async move {
            let _ = rx.await;
        }));
        Self {
            listen,
            addr,
            audit,
            controller,
            task,
            shutdown: Some(tx),
        }
    }

    /// [`Self::start`], but with an explicit
    /// `(max_concurrent_handshakes, handshake_rate_per_source)`
    /// `qsh_core::admission::Gate` instead of `crate::config::ServeConfig`'s
    /// defaults (`PLAN.md` M8 Step 2 verification round, P1-1) — mirrors
    /// `crate::loopback::LoopbackHarness::start_with_admission` for the
    /// `Listen` arm. Before this existed, nothing could drive `Listen::run`'s
    /// real accept loop at a small enough cap/rate to reach admission's
    /// rejection paths without hundreds of real connections, which is why
    /// that whole arm shipped with zero admission integration coverage
    /// (the adversarial verification round's own finding — a mutation that
    /// deleted `Listen::admit`'s gate check entirely passed 1151/1151).
    pub async fn start_with_admission(
        max_concurrent_handshakes: usize,
        handshake_rate_per_source: u32,
        validated_rate_per_source: u32,
    ) -> Self {
        let controller = make_identity();
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            controller.local.clone(),
            Arc::new(StaticTrust::empty()),
        )
        .expect("bind controller");
        let addr = listener.local_addr().expect("local addr");
        let audit = Arc::new(MemoryAuditSink::new());
        let clock: Arc<dyn qsh_core::broker::Clock> = Arc::new(SystemClock);
        let registry = Registry::new(clock.clone(), false);
        let admission = qsh_core::admission::Gate::new(
            clock.clone(),
            max_concurrent_handshakes,
            handshake_rate_per_source,
            validated_rate_per_source,
        );
        let listen = Listen::with_admission(
            registry,
            Arc::new(AllowAllPinned),
            audit.clone(),
            "controller-device",
            clock,
            Duration::from_secs(120),
            admission,
        );
        tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(listen.clone().run(listener, async move {
            let _ = rx.await;
        }));
        Self {
            listen,
            addr,
            audit,
            controller,
            task,
            shutdown: Some(tx),
        }
    }

    /// [`Self::start_with`] plus an explicit
    /// [`qsh_core::quota::QuotaLimits`] instead of `crate::config::
    /// ServeConfig`'s defaults (M8 Step 3b ruling R6) — mirrors
    /// `crate::loopback::LoopbackHarness::start_with_quotas` for the
    /// `Listen` arm's own connection-cap integration test
    /// (`crates/qsh-testkit/tests/quota.rs`, I12): this controller keeps
    /// its own [`crate::quota::Quotas`] instance, entirely independent of
    /// `crate::server::Server`'s, even when both run in the same process
    /// (ruling R6 — arm-scoped, not process-scoped).
    pub async fn start_with_quotas(
        authorizer: Arc<dyn Authorizer>,
        allow_advertised_names: bool,
        trust: StaticTrust,
        limits: qsh_core::quota::QuotaLimits,
    ) -> Self {
        let controller = make_identity();
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            controller.local.clone(),
            Arc::new(trust),
        )
        .expect("bind controller");
        let addr = listener.local_addr().expect("local addr");
        let audit = Arc::new(MemoryAuditSink::new());
        let clock: Arc<dyn qsh_core::broker::Clock> = Arc::new(SystemClock);
        let registry = Registry::new(clock.clone(), allow_advertised_names);
        let admission = qsh_core::admission::Gate::new(
            clock.clone(),
            qsh_core::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
            qsh_core::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
            qsh_core::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
        );
        let quotas = qsh_core::quota::Quotas::new(limits, clock.clone());
        let listen = Listen::with_admission_and_quotas(
            registry,
            authorizer,
            audit.clone(),
            "controller-device",
            clock,
            Duration::from_secs(120),
            qsh_core::reverse::listen::STALE_SWEEP_TICK,
            admission,
            quotas,
        );
        tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(listen.clone().run(listener, async move {
            let _ = rx.await;
        }));
        Self {
            listen,
            addr,
            audit,
            controller,
            task,
            shutdown: Some(tx),
        }
    }

    /// A `Dialer` for `target`, trusting only this controller — the same
    /// one-directional pin shape [`crate::loopback::LoopbackHarness`] uses
    /// for its own `dialer` field.
    pub fn dialer_for(&self, target: &TestIdentity) -> Dialer {
        let trust = StaticTrust::empty().with_pin(
            self.controller.fingerprint,
            Principal::Device("controller".into()),
        );
        Dialer::new(target.local.clone(), Arc::new(trust))
    }

    /// Dial the controller as `target`. Unlike [`Self::initiate`], this
    /// does not panic on a rejected dial — the L1 matrix case (an
    /// untrusted target whose mTLS handshake never reaches `Hello`) needs
    /// the raw [`DialError`].
    pub async fn dial(&self, target: &TestIdentity) -> Result<Dialed, DialError> {
        self.dialer_for(target).dial(self.addr, "127.0.0.1").await
    }

    /// Dial the controller as `target` and run the raw initiator half of
    /// the `Hello` exchange with a caller-built `Hello` — the primitive
    /// every raw registration/negative-path test in `reverse_loopback.rs`
    /// is built from.
    ///
    /// `Err(HelloError::Remote{..})` is a real error frame the controller
    /// wrote and [`handshake::respond`]'s bounded drain already flushed —
    /// never a bare connection close (`PLAN.md` M3 Step 3, "거부 error
    /// frame의 전달 보장"). The returned [`Dialed`] must be kept alive for
    /// as long as the connection is used (its `endpoint` docs).
    pub async fn initiate(
        &self,
        target: &TestIdentity,
        hello: Hello,
    ) -> Result<(Dialed, FramedStream, Hello), HelloError> {
        let dialed = self
            .dial(target)
            .await
            .unwrap_or_else(|err| panic!("dial controller {}: {err:?}", self.addr));
        let (ctl, peer_hello) = handshake::initiate(&dialed.connection, hello).await?;
        Ok((dialed, ctl, peer_hello))
    }

    /// [`Self::initiate`] with the ordinary `Hello.reverse` a `qsh reverse`
    /// process sends: full `WIRE_MINOR_VERSIONS`/`LOCAL_CAPABILITIES`, empty
    /// `ReverseRegistration.capabilities` (`v1.proto`: empty means "same as
    /// `Hello.capabilities`").
    pub async fn register(
        &self,
        target: &TestIdentity,
        offered_name: &str,
    ) -> Result<(Dialed, FramedStream, Hello), HelloError> {
        self.initiate(target, reverse_hello(offered_name)).await
    }

    /// Build the temp [`Paths`] + on-disk `trust.toml` (pinning
    /// `dial_addr` — this controller's own bound address for
    /// [`Self::run_target_with_config`], or a [`ChaosProxy`]'s front
    /// address for [`Self::run_target_through_chaos`] — under
    /// `controller_alias`, so the target believes it is talking straight to
    /// `controller_alias` either way) a real [`run_reverse_observed`]
    /// invocation needs.
    fn target_paths_at(
        &self,
        controller_alias: &str,
        dial_addr: SocketAddr,
    ) -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        let mut trust = TrustStore::default();
        trust.add_peer(
            controller_alias,
            Some(dial_addr.to_string()),
            self.controller.fingerprint,
            "2026-01-01T00:00:00Z".to_string(),
        );
        trust
            .save(&paths.trust_file())
            .expect("save target trust.toml");
        // `PLAN.md` M5 Step 6: `run_reverse_observed` runs the *real*
        // `host_runtime`/`load_or_deny` production wiring, not a stub
        // authorizer — unlike this harness's controller side (`start_with`
        // takes `Arc<dyn Authorizer>` directly), the target side default-
        // denies without an `acl.toml` of its own next to the `trust.toml`
        // just written above. Grant the controller principal the same
        // full non-always-denied vocabulary the pre-M5 `AllowAllPinned`
        // gave every pinned peer, so every existing scenario built on this
        // harness keeps behaving the way it did before the flip.
        std::fs::write(
            paths.acl_file(),
            format!(
                "[[acl]]\nprincipal = \"device:{controller_alias}\"\nallow = [\"exec.run\", \
                 \"session.open\", \"session.list\", \"session.attach\", \"session.control\", \
                 \"host.reverse\", \"forward.local\", \"forward.remote\"]\n"
            ),
        )
        .expect("write target acl.toml");
        // F8 (`PLAN.md` M5 Step 6 PR 6a adversarial ④): `fs::write`
        // inherits the process umask — a group-writable planted
        // `acl.toml` would spuriously trip the F7 group-/world-writable
        // warning on any runner whose umask leaves the group-write bit
        // set. Pin it to owner-only explicitly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(paths.acl_file(), std::fs::Permissions::from_mode(0o600));
        }
        (dir, paths)
    }

    /// Run the real [`qsh_core::reverse::target::run_reverse`] as `target`,
    /// pinning this controller under `controller_alias` in a fresh on-disk
    /// trust store, with `Config::default()`'s backoff (`docs/design/
    /// protocol.md` §11-4). Blocks until `shutdown` resolves — `run_reverse`
    /// itself never returns on a dead/rejected connection any more (M3 Step
    /// 4: registration is the target's only reachability path, so it is
    /// never abandoned) — a caller spawns this and drives it with its own
    /// shutdown channel, the same shape [`Self::start_with`] uses for the
    /// controller.
    pub async fn run_target(
        &self,
        target: &TestIdentity,
        device_id: &str,
        controller_alias: &str,
        offered_name: Option<&str>,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), OpError> {
        self.run_target_with_config(
            target,
            device_id,
            controller_alias,
            offered_name,
            &Config::default(),
            shutdown,
        )
        .await
    }

    /// [`Self::run_target`] with a caller-chosen [`Config`] — the reconnect
    /// tests want a short `[reverse]` backoff so a bounded `TIMEOUT` can
    /// actually observe more than one retry without the suite slowing down
    /// (`docs/design/testing.md`'s "no `sleep()`-based synchronization"
    /// still holds: the *shape* of the wait stays event-driven `wait_for`,
    /// this only makes the events themselves arrive sooner).
    pub async fn run_target_with_config(
        &self,
        target: &TestIdentity,
        device_id: &str,
        controller_alias: &str,
        offered_name: Option<&str>,
        config: &Config,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), OpError> {
        self.run_target_via(
            target,
            device_id,
            controller_alias,
            offered_name,
            config,
            self.addr,
            |_runtime| {},
            || {},
            shutdown,
        )
        .await
    }

    /// [`Self::run_target_with_config`], plus a hook exposing the target's
    /// own [`HostRuntime`] before the first dial — for a caller that needs
    /// to read something off the target's real runtime that no wire
    /// response surfaces (e.g. `HostRuntime::audit`'s
    /// `RotatingAuditSink::path`, to assert on the target's own on-disk
    /// audit log directly). Mirrors [`Self::run_target_through_chaos`]'s
    /// `on_runtime` hook, minus the chaos proxy in front.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_target_with_config_observing_runtime(
        &self,
        target: &TestIdentity,
        device_id: &str,
        controller_alias: &str,
        offered_name: Option<&str>,
        config: &Config,
        on_runtime: impl FnOnce(&HostRuntime),
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), OpError> {
        self.run_target_via(
            target,
            device_id,
            controller_alias,
            offered_name,
            config,
            self.addr,
            on_runtime,
            || {},
            shutdown,
        )
        .await
    }

    /// [`Self::run_target_with_config`], plus a hook that fires at most
    /// once, the first time an attempt to reach `controller_alias` fails —
    /// the same `on_unreachable` [`run_reverse_observed`] exposes, wired
    /// through so a test can assert `qsh-core`'s once-only guard directly
    /// (`PLAN.md` M3 Step 9's "exactly once" test) without spawning a real
    /// `qsh reverse` process.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_target_observing_unreachable(
        &self,
        target: &TestIdentity,
        device_id: &str,
        controller_alias: &str,
        offered_name: Option<&str>,
        config: &Config,
        dial_addr: SocketAddr,
        on_unreachable: impl FnOnce(),
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), OpError> {
        self.run_target_via(
            target,
            device_id,
            controller_alias,
            offered_name,
            config,
            dial_addr,
            |_runtime| {},
            on_unreachable,
            shutdown,
        )
        .await
    }

    /// [`Self::run_target_with_config`], but dialed through `chaos`
    /// (`docs/design/testing.md` L4) instead of this controller directly —
    /// the target's on-disk trust.toml pins `chaos.addr()`, so the resolved
    /// dial goes target → chaos → controller. A test builds `chaos` in
    /// front of this harness itself (`ChaosProxy::start(harness.addr,
    /// policy)`, mirroring [`crate::loopback::LoopbackHarness::
    /// start_chaotic`]'s own setup) and can then `sever()`/`repath()`/etc.
    /// the target→controller leg while the target keeps believing it is
    /// talking straight to `controller_alias`; a re-dial after `sever()`
    /// arrives from a fresh source port, so it is relayed onto a brand-new
    /// connection exactly like a real NAT-rebind reconnect (`ChaosProxy::
    /// sever`'s own docs).
    ///
    /// `on_runtime` fires once, synchronously, with the target's own
    /// long-lived host runtime — the *same* broker instance every
    /// reconnect this call makes reuses (`run_reverse_observed`'s doc
    /// comment) — so a caller can stash `runtime.server.clone()` and query
    /// its broker directly across a `sever()`, proving a session survives
    /// the reconnect without needing a wire-level `session.list` the
    /// controller side cannot issue yet (`docs/design/protocol.md` §11-3:
    /// that passthrough is M3 Step 5's localctl, not this step's).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_target_through_chaos(
        &self,
        target: &TestIdentity,
        device_id: &str,
        controller_alias: &str,
        offered_name: Option<&str>,
        config: &Config,
        chaos: &ChaosProxy,
        on_runtime: impl FnOnce(&HostRuntime),
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), OpError> {
        self.run_target_via(
            target,
            device_id,
            controller_alias,
            offered_name,
            config,
            chaos.addr(),
            on_runtime,
            || {},
            shutdown,
        )
        .await
    }

    /// The building block [`Self::run_target_with_config`],
    /// [`Self::run_target_observing_unreachable`] and
    /// [`Self::run_target_through_chaos`] share: build a target trust.toml
    /// pinning `dial_addr` under `controller_alias`, then run the real
    /// [`run_reverse_observed`].
    #[allow(clippy::too_many_arguments)]
    async fn run_target_via(
        &self,
        target: &TestIdentity,
        device_id: &str,
        controller_alias: &str,
        offered_name: Option<&str>,
        config: &Config,
        dial_addr: SocketAddr,
        on_runtime: impl FnOnce(&HostRuntime),
        on_unreachable: impl FnOnce(),
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), OpError> {
        let (_dir, paths) = self.target_paths_at(controller_alias, dial_addr);
        let identity = loaded_identity(target, device_id);
        let result = run_reverse_observed(
            &paths,
            config,
            identity,
            controller_alias,
            offered_name,
            on_runtime,
            on_unreachable,
            shutdown,
        )
        .await;
        // M8 Step 3a fix-3 sweep (B5): the target's own audit sink
        // (`HostRuntime::audit`'s `RotatingAuditSink`, per this fn's own
        // `on_runtime` doc) writes through a real background OS thread —
        // `record()` only `try_send`s into its channel, with no
        // synchronization point that would otherwise guarantee a write
        // enqueued right before shutdown (e.g. by a `purge_connection`-
        // triggered quota-audit flush) actually reaches disk before this
        // function returns and `_dir` drops, deleting the scratch
        // directory `on_runtime`'s caller may still want to read from.
        // A short, deliberate pause here — after the run, before the
        // drop — is what makes that read reliable instead of racing a
        // background thread against `tempfile::TempDir`'s own cleanup.
        tokio::time::sleep(Duration::from_millis(300)).await;
        result
    }

    /// Bind and run a localctl UDS admin daemon on top of this harness's
    /// own [`Listen`] — the same [`LocalctlListener::bind`] +
    /// [`LocalctlDaemon::run`] wiring `reverse/listen.rs`'s
    /// `run_listen_unix` does, except [`ReverseHarness`] is built by hand
    /// rather than through [`crate::reverse::listen::run_listen`] (module
    /// docs), so nothing attaches a localctl socket unless a caller asks
    /// for one here. `PLAN.md` M3 Step 5 (c)'s owed L3 proof — `qsh
    /// hosts`/`host.get` merging forward + live reverse into one array,
    /// then flipping to `"stale"` once the connection dies — needs a real
    /// socket [`qsh_core::localctl::client::admin_host_list_all`] can
    /// discover; `paths.runtime_dir()` is where it is bound (`<pid>.sock`,
    /// `std::process::id()` — this test process genuinely is alive for as
    /// long as the daemon runs, exactly like a real `qsh listen` process),
    /// and a caller's own `Ops` must read from that same directory for the
    /// two to ever meet.
    #[cfg(unix)]
    pub async fn attach_localctl(&self, paths: &Paths) -> LocalctlHandle {
        use qsh_core::localctl::daemon::{LocalctlDaemon, LocalctlListener};
        let pid = std::process::id();
        let bound = LocalctlListener::bind(paths, pid).expect("bind localctl socket");
        let socket_path = bound.socket_path.clone();
        let daemon = LocalctlDaemon::new(self.listen.clone());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(daemon.run(bound, async move {
            let _ = rx.await;
        }));
        LocalctlHandle {
            socket_path,
            task,
            shutdown: Some(tx),
        }
    }

    /// Stop the controller and wait for it to drain.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}

/// The localctl daemon [`ReverseHarness::attach_localctl`] binds — kept
/// separate from [`ReverseHarness`] itself so the many
/// `reverse_loopback.rs`/`reverse_chaos.rs` scenarios that never touch
/// localctl at all pay nothing for it (no socket, no extra task).
#[cfg(unix)]
pub struct LocalctlHandle {
    /// The bound socket's absolute path (`<runtime_dir>/<pid>.sock`) — the
    /// same path a caller's own `Paths::runtime_dir()` must resolve to for
    /// `admin_host_list_all` to ever find this daemon.
    pub socket_path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(unix)]
impl LocalctlHandle {
    /// Stop the daemon's accept loop and wait for it to drain. Does not
    /// unlink the socket file itself — same division of labor
    /// `run_listen_unix` draws between the daemon task and its caller's own
    /// cleanup, and a test's tempdir is removed wholesale on drop anyway.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}

#[cfg(unix)]
impl Drop for LocalctlHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

impl Drop for ReverseHarness {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

/// The `Hello` a `qsh reverse` target sends: full negotiation fields plus
/// `Hello.reverse` with empty `capabilities` (`v1.proto`: "same as
/// `Hello.capabilities`").
pub fn reverse_hello(offered_name: &str) -> Hello {
    Hello {
        versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
        device_name: "target".to_string(),
        capabilities: wire::LOCAL_CAPABILITIES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        reverse: Some(wire::ReverseRegistration {
            offered_name: offered_name.to_string(),
            capabilities: Vec::new(),
        }),
    }
}

/// A `Hello` with **no** `Hello.reverse` — an ordinary forward peer's
/// negotiation. Used to probe `qsh listen`'s "absent registration" refusal
/// and, dialed at a forward host instead, has no bearing there at all
/// (that is the point of the *other* negative path, which uses
/// [`reverse_hello`] against a forward [`crate::loopback::LoopbackHarness`]
/// host).
pub fn forward_hello() -> Hello {
    Hello {
        versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
        device_name: "peer".to_string(),
        capabilities: wire::LOCAL_CAPABILITIES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        reverse: None,
    }
}

/// Build a [`LoadedIdentity`] straight from a [`TestIdentity`], bypassing
/// `identity::init`/a key store entirely — [`run_reverse`] only needs the
/// shape, and every field it is built from ([`Identity::device_id`]/
/// `fingerprint`/`cert_der`, [`LoadedIdentity::local`]) is already sitting
/// in `test` from [`crate::loopback::make_identity`].
pub fn loaded_identity(test: &TestIdentity, device_id: &str) -> LoadedIdentity {
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

/// Poll `f` until it returns `Some`, or panic after `timeout`. A bounded,
/// event-driven substitute for a fixed `sleep()`
/// (`docs/design/testing.md`: "sleep() 전면 금지") for the handful of
/// registration/audit-visibility assertions in this harness that have no
/// dedicated notification channel to await instead — a real
/// [`ReverseHarness::run_target`] registers on a task this caller does not
/// otherwise synchronize with, so its effect on [`Listen::registry`] or
/// [`ReverseHarness::audit`] has to be observed by polling.
pub async fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(v) = f() {
                return v;
            }
            // A poll interval inside a `tokio::time::timeout`-bounded loop,
            // not the unconditioned fixed delay `docs/design/testing.md`
            // bans — same distinction `qsh-cli/tests/common/mod.rs`'s
            // `wait_for_audit` draws for its own deadline-bounded poll.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("condition not observed within {timeout:?}"))
}

/// [`wait_for`] specialized to "at least `n` audit records exist yet".
pub async fn wait_for_audit_records(
    audit: &MemoryAuditSink,
    n: usize,
    timeout: Duration,
) -> Vec<AuditRecord> {
    wait_for(timeout, || {
        let records = audit.records();
        (records.len() >= n).then_some(records)
    })
    .await
}

// ==========================================================================
// ReversePairHarness — the role-swapped counterpart of
// `crate::loopback::LoopbackHarness`, for the mechanical proof of
// role-axis independence (`PLAN.md` M3 Step 3 PR 3b: "기존
// session_loopback·attach_loopback·resume_loopback 시나리오를 정방향/역방향
// dial 두 방향으로 파라미터화").
// ==========================================================================

/// A connected pair with the dial direction reversed relative to
/// [`crate::loopback::LoopbackHarness`]: the party that *dials* — playing
/// "target" — owns the broker/pipes/audit/[`Server`] and serves requests;
/// the party that *accepts* — playing "controller" — drives them with a
/// client-role [`Session`]. Same shape [`Listen::finish_registration`]
/// builds in the real product (`reverse/listen.rs`'s module docs: a
/// successful registration "makes this connection CLIENT role"), reused
/// here without going through [`Listen`]/[`Registry`] at all.
///
/// **Deliberately bypasses admission.** This is not a second
/// registration-path harness — [`ReverseHarness`] above already owns that
/// (name resolution, conflicts, `host.reverse`, the negative paths). Here
/// the target dials straight in with a plain `Hello` (`reverse: None`) and
/// the controller's responder accepts unconditionally: the only thing under
/// test through this type is that `qsh_core`'s session/attach/resume `Ops`
/// code, driven from the CLIENT-role side of a connection the HOST-role
/// side happened to dial, behaves identically to the forward direction.
///
/// **Structurally single-peer, by construction — not a harness
/// limitation.** A forward host ([`crate::loopback::LoopbackHarness`]) is a
/// [`Listener`]: any number of distinct principals can dial in, which is
/// exactly what `resume_loopback.rs`'s three credential-theft/no-steal
/// scenarios need (an "owner" and a "thief"/"other" device reaching the
/// *same* host). A reverse target has no listener at all — its one and
/// only peer, for the lifetime of the process, is the controller it dialed
/// to register with (`docs/CLI.md` §6.13, `reverse/target.rs`'s module
/// docs). There is consequently no reverse-mode way to get a second,
/// distinct principal to the same target-host's broker without inventing a
/// topology Step 3 does not build (two simultaneous registrations from one
/// target); that is *why*, not just *that*, those three scenarios stay
/// forward-only in `resume_loopback.rs` (named exclusions there, with this
/// paragraph cited).
/// Bound on [`ReversePairHarness::connect`]'s wait for the controller's
/// accept loop to enqueue a dialed connection. Same order of magnitude as
/// `reverse_loopback.rs`'s own `TIMEOUT` — a real in-process QUIC round
/// trip; generous slack, not a budget anyone should need in full. Without
/// this, a broken accept loop turns one bad connection into an unbounded
/// `.recv().await` that burns the entire CI job timeout instead of failing
/// just this one test (harness race-hygiene review finding).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ReversePairHarness {
    /// The target's host-role dispatcher.
    pub server: Arc<Server>,
    /// The target's session broker.
    pub broker: Arc<Broker>,
    /// The target's pipe-backed session sources.
    pub pipes: Arc<PipeFactory>,
    /// Every audit record the target produced.
    pub audit: Arc<MemoryAuditSink>,
    controller_addr: SocketAddr,
    /// The target's dialer, trusting only the controller.
    dialer: Dialer,
    /// Controller-side `(Connection, ctl, peer_hello)` triples, one per
    /// connection the accept loop finished negotiating, in accept order.
    /// [`AsyncMutex`] (not [`Mutex`]) because [`Self::connect`] holds the
    /// guard across the `.recv().await`.
    accepted: AsyncMutex<mpsc::UnboundedReceiver<(Connection, FramedStream, Hello)>>,
    /// The target-side `serve_control` task per connection — nothing reads
    /// these back; they exist so [`Drop`] can abort them instead of leaking
    /// tasks past a test that never spent every session it opened.
    target_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    accept_task: tokio::task::JoinHandle<()>,
    accept_shutdown: Option<oneshot::Sender<()>>,
}

impl ReversePairHarness {
    /// A pair with the interim allow-all-pinned policy.
    pub async fn start() -> Self {
        Self::start_with(Arc::new(AllowAllPinned)).await
    }

    /// A pair with a caller-chosen policy on the target's [`Server`] — the
    /// ACL the controller (client role) is checked against, symmetric with
    /// [`crate::loopback::LoopbackHarness::start_with`].
    pub async fn start_with(authorizer: Arc<dyn Authorizer>) -> Self {
        let target = make_identity();
        let controller = make_identity();

        // The controller's listener pins the target — only the target may
        // ever dial in.
        let controller_trust =
            StaticTrust::empty().with_pin(target.fingerprint, Principal::Device("target".into()));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            controller.local.clone(),
            Arc::new(controller_trust),
        )
        .expect("bind controller");
        let controller_addr = listener.local_addr().expect("local addr");

        // The target's dialer pins the controller right back — a target
        // never registers with an unpinned controller. Pinned as
        // `device:laptop`, matching `LoopbackHarness`'s forward-direction
        // client pin: the shared `session_loopback.rs`/`attach_loopback.rs`/
        // `resume_loopback.rs` scenario bodies assert the audited/writer
        // principal by this exact literal in both directions — the point
        // being that the *same* string appears regardless of which side
        // dialed, not that the name "controller" would somehow be wrong.
        let target_trust = StaticTrust::empty()
            .with_pin(controller.fingerprint, Principal::Device("laptop".into()));
        let dialer = Dialer::new(target.local.clone(), Arc::new(target_trust));

        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(SystemClock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: qsh_core::quota::QuotaLimits::default(),
            },
            pipes.clone(),
        );
        tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
        let audit = Arc::new(MemoryAuditSink::new());
        let server = Server::new(authorizer, audit.clone(), broker.clone(), "target");

        let (tx, rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let controller_hello = Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: "controller".to_string(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            reverse: None,
        };
        let accept_task = tokio::spawn(controller_accept_loop(
            listener,
            tx,
            controller_hello,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        Self {
            server,
            broker,
            pipes,
            audit,
            controller_addr,
            dialer,
            accepted: AsyncMutex::new(rx),
            target_tasks: Mutex::new(Vec::new()),
            accept_task,
            accept_shutdown: Some(shutdown_tx),
        }
    }

    /// Dial the controller as the target, negotiate as the *host* role
    /// (`handshake::initiate` — the target is the transport dialer, same as
    /// a real `qsh reverse`), spawn the target's dispatch loop on the
    /// result, and hand back the *controller's* accepted counterpart —
    /// the client-role `(Connection, ctl, peer_hello)` a caller wraps into
    /// [`Session::from_control`] or drives raw.
    async fn connect(&self) -> (Connection, FramedStream, Hello) {
        let dialed = self
            .dialer
            .dial(self.controller_addr, "127.0.0.1")
            .await
            .unwrap_or_else(|err| {
                panic!("target dials controller {}: {err:?}", self.controller_addr)
            });
        let target_hello = Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: "target".to_string(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            reverse: None,
        };
        let (ctl, controller_hello) = handshake::initiate(&dialed.connection, target_hello)
            .await
            .unwrap_or_else(|err| panic!("target negotiates with controller: {err:?}"));

        let conn = dialed.connection.clone();
        let ctx = ConnCtx {
            principal: conn.principal().clone(),
            auth_path: conn.auth_path(),
            peer_fingerprint: conn
                .peer_fingerprint()
                .map(|fp| PeerFingerprint::new(*fp.as_bytes())),
            peer_addr: conn.remote_address(),
            conn_id: conn.stable_id(),
            capabilities: handshake::negotiated_capabilities(&controller_hello),
            // Deliberately `false`: this harness dials a *fresh* physical
            // connection per `Self::session` call (this fn's own doc) — it
            // is a role-axis-independence proof, not a stand-in for a real
            // `qsh listen` daemon multiplexing many local CLI processes
            // over *one* connection, so it must not be mistaken for one
            // (`ConnCtx::is_reverse_registration`'s own doc — a real
            // registration is `qsh-testkit/tests/reverse_attach.rs`'s and
            // `reverse_session_ops.rs`'s `register_reverse`, built off
            // `ReverseHarness::register` against the real registry).
            is_reverse_registration: false,
        };
        let server = self.server.clone();
        let conn_id = ctx.conn_id;
        let handle = tokio::spawn(async move {
            // Errors end up here whenever the caller closes the connection
            // — ordinary teardown, nothing to report. Unlike a real `qsh
            // reverse` process (which exits the moment its one connection
            // dies, so nothing needs cleaning up — `reverse/target.rs`'s
            // module docs), this harness's `Server`/broker outlive any one
            // connection (`Self::session` is called repeatedly against the
            // same pair), so it has to do the cleanup `Server::
            // serve_connection` would have done for a forward host:
            // `serve_control` alone never releases writer leases or drops
            // pending tickets on its own.
            // `None`: this harness does not exercise the target's Step 4
            // liveness probing — it is a role-axis-independence proof for
            // ordinary dispatch, not a reconnect-loop test.
            let _ = server.clone().serve_control(&conn, ctl, ctx, None).await;
            server.purge_connection(conn_id, ()).await;
        });
        self.target_tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(handle);
        // `dialed` (and its endpoint) is dropped here — the same convention
        // `LoopbackHarness::session`/`raw_session` already rely on
        // (`Dialed::endpoint`'s own docs: dropping it does not close the
        // connection).

        let mut accepted = self.accepted.lock().await;
        tokio::time::timeout(CONNECT_TIMEOUT, accepted.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "controller accept loop did not enqueue the target's \
                     connection within {CONNECT_TIMEOUT:?}"
                )
            })
            .expect("the controller accepted the target's connection")
    }

    /// The client-role (controller) [`Session`] driving ops against this
    /// pair's target-host — [`HostedPair::session`]'s reverse
    /// implementation.
    pub async fn session(&self) -> Session {
        let (conn, ctl, peer_hello) = self.connect().await;
        Session::from_control(conn, ctl, peer_hello)
    }

    /// [`Self::session`] without the [`Session`] wrapper —
    /// [`HostedPair::raw_session`]'s reverse implementation.
    pub async fn raw_session(&self) -> (Connection, FramedStream) {
        let (conn, ctl, _peer_hello) = self.connect().await;
        (conn, ctl)
    }

    /// Stop the controller's accept loop and wait for it to drain. Target
    /// tasks (one `serve_control` per connection) are not joined here — a
    /// caller has already ended every session/connection it opened by the
    /// time it calls this, the same way `LoopbackHarness::shutdown` does
    /// not join per-connection work either; [`Drop`] aborts any stragglers.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.accept_shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.accept_task).await;
    }
}

impl Drop for ReversePairHarness {
    fn drop(&mut self) {
        if let Some(tx) = self.accept_shutdown.take() {
            let _ = tx.send(());
        }
        self.accept_task.abort();
        for handle in self
            .target_tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            handle.abort();
        }
    }
}

/// The controller's accept loop: for every inbound connection (the target
/// dialing in), run the app-level `Hello` exchange as *responder* — client
/// role — with a fixed, unconditional `local_hello`, then publish the
/// negotiated triple on `tx`. Deliberately has no admission/registry logic
/// at all (module docs on [`ReversePairHarness`]) — the one thing this loop
/// decides is "accept every peer this listener's trust store already
/// verified at the TLS layer".
async fn controller_accept_loop(
    listener: Listener,
    tx: mpsc::UnboundedSender<(Connection, FramedStream, Hello)>,
    local_hello: Hello,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            incoming = listener.accept() => {
                let Some(incoming) = incoming else { break };
                let tx = tx.clone();
                let local_hello = local_hello.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.accept().await else {
                        return;
                    };
                    let Ok((ctl, peer_hello)) =
                        handshake::respond(&conn, |_peer_hello| Ok(local_hello.clone())).await
                    else {
                        return;
                    };
                    let _ = tx.send((conn, ctl, peer_hello));
                });
            }
        }
    }
    listener.close(0, b"shutdown");
    listener.endpoint().wait_idle().await;
}

impl HostedPair for ReversePairHarness {
    fn server(&self) -> &Arc<Server> {
        &self.server
    }

    fn broker(&self) -> &Arc<Broker> {
        &self.broker
    }

    fn pipes(&self) -> &Arc<PipeFactory> {
        &self.pipes
    }

    fn audit(&self) -> &Arc<MemoryAuditSink> {
        &self.audit
    }

    async fn session(&self) -> Session {
        ReversePairHarness::session(self).await
    }

    async fn raw_session(&self) -> (Connection, FramedStream) {
        ReversePairHarness::raw_session(self).await
    }

    async fn shutdown(self) {
        ReversePairHarness::shutdown(self).await
    }
}
