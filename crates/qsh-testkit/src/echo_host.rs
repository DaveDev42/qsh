//! A host whose sessions are the broker's headless echo (`EchoPipeFactory`),
//! for tests that drive the real `qsh` client against a host whose sessions
//! are deterministic and need no console.
//!
//! The interactive client's console tests on Windows want a host whose output
//! is exactly what it was sent, not a ConPTY's rendering of it. [`EchoHost`]
//! stands in for the host behind a real client: it runs the same [`Server`]
//! and [`Broker`] a `qsh serve` runs, with the echo factory as the session
//! source, and reaches the client over a QUIC listener
//! ([`EchoHost::serve_forward`]) on `127.0.0.1:0` that pins the client's
//! fingerprint.
//!
//! Only the session source differs from production. The wire, the handshake,
//! the ACL choke point and the broker's detach and resume are the real ones.
//!
//! The host owns a small tokio runtime, so a synchronous test (the CLI
//! integration tests are) can hold one without an async context.

use std::net::SocketAddr;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, BrokerConfig, EchoPipeFactory, LiveCounts, SystemClock};
use qsh_core::server::Server;
use qsh_transport::{Fingerprint, Listener, Principal, StaticTrust};

use crate::loopback::{TestIdentity, make_identity};

/// A host with echo sessions. See the module docs.
pub struct EchoHost {
    /// Declared first so the runtime outlives nothing that borrows it.
    runtime: Option<tokio::runtime::Runtime>,
    server: Arc<Server>,
    broker: Arc<Broker>,
    identity: TestIdentity,
    stop: Option<tokio::sync::watch::Sender<bool>>,
}

impl EchoHost {
    /// A host with a fresh identity and no route yet.
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build the echo host's runtime");
        let identity = make_identity();
        let (server, broker) = {
            let _guard = runtime.enter();
            let broker = Broker::new(
                Arc::new(SystemClock),
                BrokerConfig {
                    replay_bytes: 64 * 1024,
                    resume_ttl: Duration::from_secs(3600),
                    close_grace: Duration::from_millis(100),
                    quota_limits: qsh_core::quota::QuotaLimits::default(),
                },
                Arc::new(EchoPipeFactory),
            );
            tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
            let server = Server::new(
                Arc::new(AllowAllPinned),
                Arc::new(MemoryAuditSink::new()),
                broker.clone(),
                "echo-host",
            );
            (server, broker)
        };
        let (stop, _) = tokio::sync::watch::channel(false);
        Self {
            runtime: Some(runtime),
            server,
            broker,
            identity,
            stop: Some(stop),
        }
    }

    /// The host's fingerprint, in the spelling `qsh trust add --fingerprint`
    /// takes.
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint.to_string()
    }

    /// Make this host behave as a build that predates `caps`
    /// ([`Server::hide_capabilities`]); call before the first client dials.
    pub fn hide_capabilities(&self, caps: &[&str]) {
        self.server.hide_capabilities(caps);
    }

    /// Sessions the host holds right now, and how many have no attached
    /// client.
    pub fn live_counts(&self) -> LiveCounts {
        self.broker.live_counts()
    }

    fn runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime.as_ref().expect("the runtime lives until drop")
    }

    /// Listen on `127.0.0.1:0` for a client with `client_fingerprint`, and
    /// return the address it dials.
    pub fn serve_forward(&self, client_fingerprint: &str) -> SocketAddr {
        let client = Fingerprint::from_str(client_fingerprint)
            .unwrap_or_else(|e| panic!("{client_fingerprint:?} is not a fingerprint: {e:?}"));
        let trust = StaticTrust::empty().with_pin(client, Principal::Device("laptop".into()));
        let _guard = self.runtime().enter();
        crate::env_check::ensure_loopback_udp();
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            self.identity.local.clone(),
            Arc::new(trust),
        )
        .expect("bind the echo host's listener");
        let addr = listener.local_addr().expect("listener address");
        let server = self.server.clone();
        let mut stop = self.stop.as_ref().expect("not dropped").subscribe();
        tokio::spawn(async move {
            server
                .run(listener, async move {
                    let _ = stop.wait_for(|stopped| *stopped).await;
                })
                .await;
        });
        addr
    }
}

impl Default for EchoHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EchoHost {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
    }
}
