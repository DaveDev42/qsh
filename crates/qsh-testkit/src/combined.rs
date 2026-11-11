//! In-process harness for the combined `listen` + `serve` endpoint
//! (ADR-0059, `docs/design/testing.md` L3): one UDP socket, one
//! [`Server`] in front and a [`Listen`] controller behind it, built on the
//! same authorizer, audit sink, admission gate and quota tracker.
//!
//! [`CombinedHarness`] assembles what the production runtime assembles
//! (`qsh_core::serve::SharedParts`, [`Server::set_listen`]) except that it
//! keeps the `Arc<Server>` and `Arc<Listen>` handles, the way
//! [`crate::loopback::LoopbackHarness`] and [`crate::reverse::ReverseHarness`]
//! do, so a test observes the broker, the registry and the audit sink
//! directly. The sessions are the broker's pipe-backed ones (no PTY).
//!
//! A test plays either peer role over the same address with
//! [`CombinedHarness::forward`] (a `Hello` with no `reverse`) and
//! [`CombinedHarness::register`] (a `Hello` that registers a name).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_core::acl::Authorizer;
use qsh_core::admission::Gate;
use qsh_core::audit::{AuditSink, MemoryAuditSink};
use qsh_core::broker::{Broker, BrokerConfig, Clock, PipeFactory, SystemClock};
use qsh_core::handshake::{self, HelloError};
use qsh_core::quota::{QuotaLimits, Quotas};
use qsh_core::reverse::listen::{Listen, STALE_SWEEP_TICK};
use qsh_core::reverse::registry::Registry;
use qsh_core::serve::SharedParts;
use qsh_core::server::Server;
use qsh_proto::wire::Hello;
use qsh_transport::{
    DialError, Dialed, Dialer, Endpoint, FramedStream, Listener, Principal, StaticTrust,
    TrustEvaluator,
};

use crate::loopback::{TestIdentity, make_identity};
use crate::reverse::{forward_hello, reverse_hello};

/// The two roles of a combined endpoint, assembled the way the production
/// runtime does: a [`Server`] in front, a [`Listen`] attached to it, both
/// built on the one `authorizer`, `sink`, `gate` and `quotas` given.
pub struct Roles {
    /// The front of the endpoint.
    pub server: Arc<Server>,
    /// The controller attached to it.
    pub listen: Arc<Listen>,
    /// The server's session broker (pipe-backed sources, real clock).
    pub broker: Arc<Broker>,
    /// The test's side of every session child.
    pub pipes: Arc<PipeFactory>,
}

/// Build [`Roles`] without binding anything, so a test can run
/// `roles.server.clone().run(listener, ..)` on a listener of its own (a
/// netsim one, for instance). Spawns the broker's reaper and the listen
/// controller's stale sweeper, as the real runtime does.
pub fn build_roles(
    authorizer: Arc<dyn Authorizer>,
    sink: Arc<dyn AuditSink>,
    gate: Arc<Gate>,
    quotas: Arc<Quotas>,
    limits: QuotaLimits,
) -> Roles {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let pipes = Arc::new(PipeFactory::new(64 * 1024));
    let broker = Broker::new(
        clock.clone(),
        BrokerConfig {
            replay_bytes: 64 * 1024,
            resume_ttl: Duration::from_secs(3600),
            close_grace: Duration::from_millis(100),
            quota_limits: limits,
        },
        pipes.clone(),
    );
    tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));

    let listen = Listen::with_admission_and_quotas(
        Registry::new(clock.clone(), false),
        authorizer.clone(),
        sink.clone(),
        "box",
        clock,
        Duration::from_secs(120),
        STALE_SWEEP_TICK,
        gate.clone(),
        quotas.clone(),
    );
    tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));
    let server =
        Server::with_admission_and_quotas(authorizer, sink, broker.clone(), "box", gate, quotas);
    server
        .set_listen(listen.clone())
        .expect("the roles are built on one set of parts");
    Roles {
        server,
        listen,
        broker,
        pipes,
    }
}

/// A combined endpoint on `127.0.0.1:0`; see the module docs.
pub struct CombinedHarness {
    /// The front of the endpoint: the host that serves the forward roles.
    pub server: Arc<Server>,
    /// The controller behind it: the registry and the registered connections.
    pub listen: Arc<Listen>,
    /// Every audit record the endpoint produced, when it was built with the
    /// in-memory sink (the constructors other than
    /// [`Self::start_with_parts`] and [`Self::start_with_sink`]).
    pub audit: Arc<MemoryAuditSink>,
    /// The host's session broker (pipe-backed sources, real clock).
    pub broker: Arc<Broker>,
    /// The test's side of every session child, in open order.
    pub pipes: Arc<PipeFactory>,
    /// The shared admission gate both roles were built on.
    pub gate: Arc<Gate>,
    /// The shared quota tracker both roles were built on.
    pub quotas: Arc<Quotas>,
    /// The bound address both roles are reached at.
    pub addr: SocketAddr,
    /// The endpoint's identity; a peer must pin its fingerprint.
    pub host: TestIdentity,
    client_endpoints: Arc<Mutex<Vec<Endpoint>>>,
    task: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl CombinedHarness {
    /// An endpoint with a caller-chosen policy, the peers it authenticates
    /// and quota limits, writing to the in-memory [`Self::audit`].
    pub async fn start(
        authorizer: Arc<dyn Authorizer>,
        trust: StaticTrust,
        limits: QuotaLimits,
    ) -> Self {
        let audit = Arc::new(MemoryAuditSink::new());
        Self::assemble(
            make_identity(),
            Arc::new(trust),
            authorizer,
            audit.clone(),
            audit,
            limits,
            None,
        )
        .await
    }

    /// [`Self::start`] writing to `sink` instead — for a test that makes the
    /// audit write fail. [`Self::audit`] stays empty.
    pub async fn start_with_sink(
        authorizer: Arc<dyn Authorizer>,
        trust: StaticTrust,
        limits: QuotaLimits,
        sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self::assemble(
            make_identity(),
            Arc::new(trust),
            authorizer,
            sink,
            Arc::new(MemoryAuditSink::new()),
            limits,
            None,
        )
        .await
    }

    /// An endpoint built on production [`SharedParts`] (the on-disk
    /// `acl.toml` policy, the rotating audit sink, the `[serve]` admission
    /// and quota values), with `host` as its identity. The trust the
    /// listener verifies peers against is `parts.trust`.
    pub async fn start_with_parts(parts: SharedParts, host: TestIdentity) -> Self {
        let SharedParts {
            trust,
            audit,
            authorizer,
            admission,
            quotas,
            ..
        } = parts;
        Self::assemble(
            host,
            trust,
            authorizer,
            audit,
            Arc::new(MemoryAuditSink::new()),
            QuotaLimits::default(),
            Some((admission, quotas)),
        )
        .await
    }

    async fn assemble(
        host: TestIdentity,
        trust: Arc<dyn TrustEvaluator>,
        authorizer: Arc<dyn Authorizer>,
        sink: Arc<dyn AuditSink>,
        memory: Arc<MemoryAuditSink>,
        limits: QuotaLimits,
        shared: Option<(Arc<Gate>, Arc<Quotas>)>,
    ) -> Self {
        crate::env_check::ensure_loopback_udp();
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            host.local.clone(),
            trust,
        )
        .expect("bind combined endpoint");
        let addr = listener.local_addr().expect("local addr");

        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let (gate, quotas) = shared.unwrap_or_else(|| {
            (
                Arc::new(Gate::new(
                    clock.clone(),
                    qsh_core::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
                    qsh_core::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
                    qsh_core::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
                )),
                Quotas::new(limits, clock.clone()),
            )
        });

        let Roles {
            server,
            listen,
            broker,
            pipes,
        } = build_roles(authorizer, sink, gate.clone(), quotas.clone(), limits);

        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.clone().run(listener, async move {
            let _ = rx.await;
        }));
        Self {
            server,
            listen,
            audit: memory,
            broker,
            pipes,
            gate,
            quotas,
            addr,
            host,
            client_endpoints: Arc::new(Mutex::new(Vec::new())),
            task,
            shutdown: Some(tx),
        }
    }

    /// A [`Dialer`] for `peer` that trusts only this endpoint.
    pub fn dialer_for(&self, peer: &TestIdentity) -> Dialer {
        let trust =
            StaticTrust::empty().with_pin(self.host.fingerprint, Principal::Device("box".into()));
        Dialer::new(peer.local.clone(), Arc::new(trust))
    }

    /// Dial the endpoint as `peer`. The client endpoint is closed by
    /// [`Self::shutdown`], so a test need not keep it alive for that.
    pub async fn dial(&self, peer: &TestIdentity) -> Result<Dialed, DialError> {
        let dialed = self.dialer_for(peer).dial(self.addr, "127.0.0.1").await?;
        self.client_endpoints
            .lock()
            .expect("client_endpoints lock")
            .push(dialed.endpoint.clone());
        Ok(dialed)
    }

    /// Dial as `peer` and run the initiator half of the `Hello` exchange with
    /// a caller-built `Hello`. `Err(HelloError::Remote{..})` is the real
    /// error frame the endpoint wrote.
    pub async fn initiate(
        &self,
        peer: &TestIdentity,
        hello: Hello,
    ) -> Result<(Dialed, FramedStream, Hello), HelloError> {
        let dialed = self
            .dial(peer)
            .await
            .unwrap_or_else(|err| panic!("dial combined endpoint {}: {err:?}", self.addr));
        let (ctl, peer_hello) = handshake::initiate(&dialed.connection, hello).await?;
        Ok((dialed, ctl, peer_hello))
    }

    /// Play the forward client role: a `Hello` with no `reverse`.
    pub async fn forward(
        &self,
        peer: &TestIdentity,
    ) -> Result<(Dialed, FramedStream, Hello), HelloError> {
        self.initiate(peer, forward_hello()).await
    }

    /// Play the reverse target role: a `Hello` that registers a name.
    pub async fn register(
        &self,
        peer: &TestIdentity,
        offered_name: &str,
    ) -> Result<(Dialed, FramedStream, Hello), HelloError> {
        self.initiate(peer, reverse_hello(offered_name)).await
    }

    /// Stop the endpoint, wait for it to drain and close every client
    /// endpoint a dial created.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
        let endpoints =
            std::mem::take(&mut *self.client_endpoints.lock().expect("client_endpoints lock"));
        for endpoint in endpoints {
            endpoint.close(0u32, b"");
            let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
        }
    }
}
