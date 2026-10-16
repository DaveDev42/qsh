//! A host whose sessions are the broker's headless echo (`EchoPipeFactory`),
//! for tests that drive the real `qsh` client against a host that has no PTY.
//!
//! A Windows host answers `UNSUPPORTED` to PTY sessions until the Windows host
//! role lands, so the interactive client cannot be driven against a real
//! `qsh serve` there. [`EchoHost`] stands in for the host behind a real
//! client: it runs the same [`Server`] and [`Broker`] a `qsh serve` runs, with
//! the echo factory as the session source, and reaches the client over either
//! route.
//!
//! - [`EchoHost::serve_forward`]: a QUIC listener on `127.0.0.1:0` that pins
//!   the client's fingerprint, for a client that dials it.
//! - [`EchoHost::register`]: the host dials a real `qsh listen` daemon and
//!   registers as a reverse target, so the client reaches it through the
//!   daemon's local socket or pipe.
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
use qsh_core::broker::{
    Broker, BrokerConfig, EchoPipeFactory, LiveCounts, PeerFingerprint, SystemClock,
};
use qsh_core::handshake;
use qsh_core::server::{ConnCtx, Server};
use qsh_transport::{Dialer, Fingerprint, Listener, Principal, StaticTrust};

use crate::loopback::{TestIdentity, make_identity};
use crate::reverse::reverse_hello;

/// How long [`EchoHost::register`] waits for the daemon to take the
/// registration before it panics.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(30);

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

    /// Dial the `qsh listen` daemon at `controller_addr` (which presents
    /// `controller_fingerprint`), register as the reverse target named
    /// `offered_name`, and serve that connection. Returns once the daemon has
    /// accepted the registration.
    pub fn register(
        &self,
        controller_addr: &str,
        controller_fingerprint: &str,
        offered_name: &str,
    ) {
        let controller = Fingerprint::from_str(controller_fingerprint)
            .unwrap_or_else(|e| panic!("{controller_fingerprint:?} is not a fingerprint: {e:?}"));
        let addr: SocketAddr = controller_addr
            .parse()
            .unwrap_or_else(|e| panic!("{controller_addr:?} is not an address: {e}"));
        let trust = StaticTrust::empty().with_pin(controller, Principal::Device("hub".into()));
        let dialer = Dialer::new(self.identity.local.clone(), Arc::new(trust));
        let server = self.server.clone();
        let name = offered_name.to_string();
        let mut stop = self.stop.as_ref().expect("not dropped").subscribe();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        self.runtime().spawn(async move {
            let dialed = dialer
                .dial(addr, "127.0.0.1")
                .await
                .unwrap_or_else(|e| panic!("the echo target dials the controller {addr}: {e:?}"));
            let (ctl, controller_hello) =
                handshake::initiate(&dialed.connection, reverse_hello(&name))
                    .await
                    .unwrap_or_else(|e| panic!("the controller refused the registration: {e:?}"));
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
                is_reverse_registration: true,
            };
            let conn_id = ctx.conn_id;
            let _ = ready_tx.send(());
            tokio::select! {
                _ = server.clone().serve_control(&conn, ctl, ctx, None) => {}
                _ = stop.wait_for(|stopped| *stopped) => {}
            }
            server.purge_connection(conn_id, ()).await;
            // The endpoint must outlive the connection (`Dialed::endpoint`).
            drop(dialed);
        });
        ready_rx
            .recv_timeout(REGISTER_TIMEOUT)
            .unwrap_or_else(|_| panic!("the controller did not take the registration"));
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
