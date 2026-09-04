//! In-process pairing harness (L3): a real, on-disk-backed `qsh serve`-
//! shaped host with pairing wired in — the same `Server::set_pairing`/
//! `SharedTrustStore::attach_pairing` shape `crate::serve::run_serve` wires
//! in production — plus the `AcceptAnyForPairing` dialer pairing's real
//! clients use (report §B3: pairing's authentication is possession of the
//! secret, not the TLS identity).
//!
//! Promoted from `crates/qsh-testkit/tests/pairing_loopback.rs`'s private
//! `PairingHost` (`PLAN.md` M8 Step 4, ARBITRATION-4.md J11) so a second
//! test file can share it without duplicating the wiring.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use qsh_core::acl::AllowAllPinned;
use qsh_core::admission::Gate;
use qsh_core::audit::MemoryAuditSink;
use qsh_core::broker::{Broker, BrokerConfig, PipeFactory, SystemClock};
use qsh_core::config::ServeConfig;
use qsh_core::pairing::AcceptAnyForPairing;
use qsh_core::quota::{QuotaLimits, Quotas};
use qsh_core::server::Server;
use qsh_core::trust::pairing::{InviteStore, generate_secret};
use qsh_core::trust::{SharedInviteStore, SharedTrustStore, TrustStore};
use qsh_proto::pairing::INVITE_SECRET_LEN;
use qsh_transport::{Dialed, Dialer, Listener, LocalIdentity, TrustEvaluator};

use crate::loopback::make_identity;
use crate::reverse::wait_for;

/// A real, on-disk-backed `qsh serve`-shaped host with pairing wired in —
/// the same `Server::set_pairing`/`SharedTrustStore::attach_pairing` shape
/// `crate::serve::run_serve` wires in production.
pub struct PairingHarness {
    pub addr: SocketAddr,
    trust_path: PathBuf,
    invites_path: PathBuf,
    /// The host's own `MemoryAuditSink` — exposed (unlike the original
    /// private `PairingHost`, which dropped its `Arc` after handing it to
    /// `Server::new`) so quota-rejection tests can read the audit trail a
    /// refused pairing connection leaves behind.
    pub audit: Arc<MemoryAuditSink>,
    /// The host's own quota tracker — held (rather than left inside
    /// `Server`, whose `quotas` field is private) so
    /// `open_pending_pairing_connections` can poll
    /// `Quotas::pairing_connections_in_use` for a deterministic "the host
    /// has actually reserved these slots" signal instead of a fixed sleep.
    quotas: Arc<Quotas>,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PairingHarness {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let trust_path = dir.path().join("trust.toml");
        let invites_path = dir.path().join("invites.toml");

        let host_identity = make_identity();
        let trust = SharedTrustStore::open(&trust_path).expect("open trust");
        let invites = SharedInviteStore::open(&invites_path).expect("open invites");
        trust.attach_pairing(Arc::clone(&invites));

        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            host_identity.local.clone(),
            Arc::clone(&trust) as Arc<dyn TrustEvaluator>,
        )
        .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        let audit = Arc::new(MemoryAuditSink::new());
        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(SystemClock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: qsh_core::quota::QuotaLimits::default(),
            },
            pipes,
        );
        tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
        // Same admission gate `Server::new` builds internally
        // (`ServeConfig::DEFAULT_*`) — this harness only needs a handle on
        // `Quotas`, not a different admission posture, so it reconstructs
        // `Server::new`'s defaults explicitly via `with_admission_and_quotas`
        // rather than changing pairing test semantics.
        let admission = Gate::new(
            Arc::new(SystemClock),
            ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
            ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
            ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
        );
        let quotas = Quotas::new(QuotaLimits::default(), Arc::new(SystemClock));
        let server = Server::with_admission_and_quotas(
            Arc::new(AllowAllPinned),
            Arc::clone(&audit) as _,
            broker,
            "host",
            admission,
            Arc::clone(&quotas),
        );
        server.set_pairing(Arc::clone(&trust), Arc::clone(&invites));

        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.clone().run(listener, async move {
            let _ = rx.await;
        }));

        Self {
            addr,
            trust_path,
            invites_path,
            audit,
            quotas,
            _dir: dir,
            task,
            shutdown: Some(tx),
        }
    }

    /// Mint a fresh invite directly against this host's on-disk store
    /// (mirrors `Ops::trust_invite` without going through the `Ops` layer,
    /// so these tests stay focused on the wire exchange and
    /// `Server::serve_pairing_connection`, not the CLI-facing op).
    pub fn invite_at(&self, created_at: SystemTime) -> [u8; INVITE_SECRET_LEN] {
        let secret = generate_secret();
        let mut store = InviteStore::load(&self.invites_path).expect("load invites");
        store.add(secret.as_slice(), created_at);
        store.save(&self.invites_path).expect("save invites");
        *secret
    }

    pub fn invite(&self) -> [u8; INVITE_SECRET_LEN] {
        self.invite_at(SystemTime::now())
    }

    pub fn trust_snapshot(&self) -> TrustStore {
        TrustStore::load(&self.trust_path).expect("load trust")
    }

    /// Dial `n` pairing connections against this host and hold them open
    /// without ever exchanging a single pairing-protocol frame — each one
    /// occupies one `Quotas::reserve_pairing_connection` slot (M8 Step 3b
    /// ruling R2, `crates/qsh-core/src/server/mod.rs`'s `serve_connection`
    /// pairing arm) for as long as the returned `Dialed` handles stay
    /// alive: the slot is reserved at connection-accept time, before any
    /// stream is even opened, let alone a `PairingProof` sent.
    ///
    /// `Server::quotas` is private, so `qsh-testkit` callers can't reach
    /// it through `Server` itself — in-crate `qsh-core` tests can reserve
    /// a slot directly against `rig.quotas` without a live connection
    /// behind it, but from outside the crate this is the only way to
    /// drive the pairing cap to exhaustion: real QUIC connections, real
    /// `Principal::Pairing` authentication, real permits.
    pub async fn open_pending_pairing_connections(&self, n: usize) -> Vec<Dialed> {
        // `TrustEvaluator::pairing_open()` (`SharedTrustStore`'s own,
        // backed by `SharedInviteStore::pairing_open`) must answer `true`
        // for the TLS handshake to admit an unknown-cert peer as
        // `Principal::Pairing` at all — otherwise rustls rejects the
        // client cert outright (`UnknownIssuer`) before the connection
        // ever reaches `Server::serve_connection`'s pairing arm. A single
        // live, unredeemed invite is enough: none of these connections
        // ever sends a `PairingProof`, so it is never consumed.
        let _live_invite = self.invite();
        let mut conns = Vec::with_capacity(n);
        for _ in 0..n {
            let identity = make_identity();
            let dialed = pairing_dialer(identity.local)
                .dial(self.addr, "127.0.0.1")
                .await
                .expect("dial pending pairing connection");
            conns.push(dialed);
        }
        // The host's own accept loop spawns `serve_connection` (and, in
        // it, reserves the pairing permit) asynchronously to our own
        // `dial()` returning — poll the harness's own `Quotas` handle
        // until it has actually observed all `n` reservations instead of
        // guessing at a fixed delay, so a scheduling delay under load
        // can't read as a quota bug (or a fast host mask a genuine one).
        let quotas = Arc::clone(&self.quotas);
        wait_for(Duration::from_secs(5), move || {
            (quotas.pairing_connections_in_use() == n).then_some(())
        })
        .await;
        eprintln!(
            "open_pending_pairing_connections: observed {n} pairing slots in use at {:?}",
            std::time::Instant::now()
        );
        conns
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}

/// A dialer that accepts any certificate the dialed address presents — the
/// same evaluator `qsh trust accept` dials with (report §B3): pairing's
/// real authentication is possession of the secret, not the TLS identity.
pub fn pairing_dialer(local: LocalIdentity) -> Dialer {
    Dialer::new(local, Arc::new(AcceptAnyForPairing))
}
