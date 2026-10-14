//! ADR-0031 결정 2~8: the per-connection trust watch, end to end over real
//! QUIC connections.
//!
//! **What is real.** A [`Host`] is built the way `qsh serve` builds its
//! listener: one [`SharedTrustStore`] over an on-disk `trust.toml` is both the
//! TLS verifier's evaluator and the store the server's connection watch reads
//! ([`Server::set_trust_watch`]), and the authorizer comes from
//! [`load_or_deny`] over the same files, so a `trust.toml` edit reaches the
//! handshake, the role stage and the watch through the one store. The tests
//! edit the file the way `qsh trust remove`, `set-role` and `rename` do
//! (atomic replace), and the watch notices through the process's one 1-second
//! poll task. `qsh listen` and `qsh serve --to` get their own scenarios
//! at the end: the registration connection of [`ReverseHarness`] and the real
//! `run_reverse` loop of [`ReverseHarness::run_target_with_config_observing_runtime`].
//!
//! **How a close is read.** The client side of the connection sees the
//! host's close: `Connection::closed` resolves and
//! `Connection::closed_by_trust_withdrawal` reads close code `0x1005` with
//! the fixed reason `trust withdrawn` (ADR-0031 결정 7). The host's audit
//! line (결정 8) is read from the host's sink.
//!
//! **The 2-second contract.** Every "closes" assertion here waits up to
//! [`CLOSE_BOUND`], generous for a loaded runner. The contract itself, one
//! poll tick, is pinned on the clock by
//! `trust_withdrawal_closes_within_one_poll_tick_under_paused_time`, and the
//! real binary's version by `an_established_connection_is_closed_within_two_seconds_of_trust_remove`
//! in `crates/qsh-cli/tests/it/trust_lifecycle_live.rs`. "Stays open"
//! assertions wait [`STAY_WINDOW`], two poll ticks after the edit.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use qsh_core::acl::{Authorizer, PERMISSION_DENIED_MESSAGE, Role, load_or_deny};
use qsh_core::audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink};
use qsh_core::broker::{Broker, BrokerConfig, PipeFactory, SystemClock};
use qsh_core::client::{ClientError, Session};
use qsh_core::config::Paths;
use qsh_core::quota::{QuotaLimits, Quotas};
use qsh_core::server::Server;
use qsh_core::trust::{SharedTrustStore, TRUST_POLL_INTERVAL};
use qsh_proto::ErrorCode;
use qsh_proto::wire;
use qsh_testkit::loopback::{TestCa, TestIdentity, make_ca, make_identity};
use qsh_transport::{
    Connection, ConnectionError, Dialer, Fingerprint, Listener, Principal, StaticTrust,
    TrustEvaluator,
};

/// How long a close may take on a loaded runner before the test fails.
const CLOSE_BOUND: Duration = Duration::from_secs(8);

/// How long a connection that must stay open is watched: two poll ticks and
/// some slack, so a wrongly-closing watch has had its chance twice.
const STAY_WINDOW: Duration = Duration::from_millis(2500);

// ---------------------------------------------------------------------------
// trust.toml
// ---------------------------------------------------------------------------

fn pin(name: &str, fingerprint: &Fingerprint, role: Option<&str>) -> String {
    let role = role.map_or(String::new(), |r| format!("role = \"{r}\"\n"));
    format!(
        "[[peer]]\nname = \"{name}\"\nfingerprint = \"{fingerprint}\"\naddress = \"\"\n\
         added_at = \"2026-10-15T00:00:00Z\"\n{role}\n"
    )
}

fn ca_block(name: &str, ca: &TestCa) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(ca.root_der.as_ref());
    let wrapped: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ascii"))
        .collect();
    format!(
        "[[ca]]\nname = \"{name}\"\ncert_pem = '''-----BEGIN CERTIFICATE-----\n{}\n\
         -----END CERTIFICATE-----\n'''\n\n",
        wrapped.join("\n")
    )
}

/// A config dir with a `trust.toml`, the store opened over it, and the paths
/// `load_or_deny` reads.
struct Env {
    _dir: tempfile::TempDir,
    paths: Paths,
    store: Arc<SharedTrustStore>,
}

impl Env {
    fn new(trust_text: &str) -> Self {
        Self::with_acl(trust_text, None)
    }

    fn with_acl(trust_text: &str, acl: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        std::fs::create_dir_all(&paths.config_dir).expect("config dir");
        std::fs::write(paths.trust_file(), trust_text).expect("write trust.toml");
        if let Some(acl) = acl {
            let path = paths.acl_file();
            std::fs::write(&path, acl).expect("write acl.toml");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod acl.toml");
            }
        }
        let store = SharedTrustStore::open(paths.trust_file()).expect("open trust.toml");
        Self {
            _dir: dir,
            paths,
            store,
        }
    }

    fn trust_path(&self) -> PathBuf {
        self.paths.trust_file()
    }

    /// Replace `trust.toml` the way `qsh trust ...` does: a temp file in the
    /// same directory, renamed over it.
    fn rewrite(&self, text: &str) {
        let path = self.trust_path();
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).expect("write temp trust.toml");
        std::fs::rename(&tmp, &path).expect("replace trust.toml");
    }

    fn delete(&self) {
        std::fs::remove_file(self.trust_path()).expect("delete trust.toml");
    }

    fn authorizer(&self) -> Arc<dyn Authorizer> {
        let (authorizer, _diagnostic) =
            load_or_deny(&self.paths, Role::Serve, Arc::clone(&self.store));
        authorizer
    }
}

// ---------------------------------------------------------------------------
// The host and its clients
// ---------------------------------------------------------------------------

/// A memory audit sink whose writes can be made to fail, the shape of a
/// fail-closed writer with a full disk.
#[derive(Default)]
struct ToggleAudit {
    inner: MemoryAuditSink,
    failing: AtomicBool,
    /// The (tokio) instant of the first withdrawal record: the watch writes
    /// it right after the close, so it dates the judgment on a paused clock.
    first_withdrawal: std::sync::Mutex<Option<tokio::time::Instant>>,
}

impl AuditSink for ToggleAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(AuditError::Degraded);
        }
        if record.resource == "trust_withdrawn" || record.resource == "grants_reduced" {
            self.first_withdrawal
                .lock()
                .expect("stamp lock")
                .get_or_insert_with(tokio::time::Instant::now);
        }
        self.inner.record(record)
    }
}

impl ToggleAudit {
    fn records(&self) -> Vec<AuditRecord> {
        self.inner.records()
    }

    /// The connection-level records the watch wrote, as `(resource,
    /// principal, auth_path)`.
    fn withdrawals(&self) -> Vec<AuditRecord> {
        self.records()
            .into_iter()
            .filter(|r| {
                r.action == "connect"
                    && (r.resource == "trust_withdrawn" || r.resource == "grants_reduced")
            })
            .collect()
    }
}

struct Host {
    addr: SocketAddr,
    identity: TestIdentity,
    audit: Arc<ToggleAudit>,
    broker: Arc<Broker>,
    server: Arc<Server>,
    task: tokio::task::JoinHandle<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Host {
    async fn start(env: &Env) -> Self {
        Self::start_with(env, None).await
    }

    async fn start_with(env: &Env, limits: Option<QuotaLimits>) -> Self {
        qsh_testkit::env_check::ensure_loopback_udp();
        let identity = make_identity();
        let evaluator: Arc<dyn TrustEvaluator> = env.store.clone();
        let listener = Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            identity.local.clone(),
            evaluator,
        )
        .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let audit = Arc::new(ToggleAudit::default());
        let pipes = Arc::new(PipeFactory::new(64 * 1024));
        let broker = Broker::new(
            Arc::new(SystemClock),
            BrokerConfig {
                replay_bytes: 64 * 1024,
                resume_ttl: Duration::from_secs(3600),
                close_grace: Duration::from_millis(100),
                quota_limits: QuotaLimits::default(),
            },
            pipes,
        );
        tokio::spawn(Broker::run_reaper(Arc::downgrade(&broker)));
        let server = match limits {
            None => Server::new(env.authorizer(), audit.clone(), broker.clone(), "box"),
            Some(limits) => {
                // A test of many connections from one source must not meet
                // the handshake gate it is not about.
                let gate = qsh_core::admission::Gate::new(
                    Arc::new(SystemClock),
                    4096,
                    1_000_000,
                    1_000_000,
                );
                Server::with_admission_and_quotas(
                    env.authorizer(),
                    audit.clone(),
                    broker.clone(),
                    "box",
                    gate,
                    Quotas::new(limits, Arc::new(SystemClock)),
                )
            }
        };
        server.set_trust_watch(Arc::clone(&env.store));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.clone().run(listener, async move {
            let _ = rx.await;
        }));
        Self {
            addr,
            identity,
            audit,
            broker,
            server,
            task,
            shutdown: Some(tx),
        }
    }

    /// Dial as `client`, which the host's trust store must vouch for.
    async fn dial(&self, client: &TestIdentity) -> Result<Session, String> {
        let trust = StaticTrust::empty().with_pin(
            self.identity.fingerprint,
            Principal::Device("box".to_string()),
        );
        let dialer = Dialer::new(client.local.clone(), Arc::new(trust));
        let dialed = dialer
            .dial(self.addr, "127.0.0.1")
            .await
            .map_err(|err| format!("dial: {err:?}"))?;
        Session::negotiate(dialed.connection, "desktop")
            .await
            .map_err(|err| format!("negotiate: {err:?}"))
    }

    /// Dial as `client` and run the `Hello` exchange by hand, returning the
    /// raw control stream: a peer the test can make stop reading.
    async fn dial_raw(&self, client: &TestIdentity) -> (Connection, qsh_transport::FramedStream) {
        let trust = StaticTrust::empty().with_pin(
            self.identity.fingerprint,
            Principal::Device("box".to_string()),
        );
        let dialer = Dialer::new(client.local.clone(), Arc::new(trust));
        let dialed = dialer
            .dial(self.addr, "127.0.0.1")
            .await
            .expect("the host trusts this client");
        let hello = wire::Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: "desktop".to_string(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            reverse: None,
        };
        let (ctl, _peer_hello) = qsh_core::handshake::initiate(&dialed.connection, hello)
            .await
            .expect("hello");
        (dialed.connection, ctl)
    }

    async fn session(&self, client: &TestIdentity) -> Session {
        self.dial(client)
            .await
            .expect("the host trusts this client")
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
        let _ = (&self.server, &self.broker);
    }
}

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        env: Default::default(),
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

/// `session.list` is granted by `full`, `exec` and `read-only`. `Ok` is an
/// allow and a uniform `PERMISSION_DENIED` a denial; anything else (a closed
/// connection included) fails the test.
async fn can_list(session: &mut Session) -> bool {
    match session.session_list().await {
        Ok(_) => true,
        Err(ClientError::Remote {
            code: ErrorCode::PermissionDenied,
            message,
            ..
        }) => {
            assert_eq!(message, PERMISSION_DENIED_MESSAGE);
            false
        }
        Err(other) => panic!("neither an allow nor a uniform denial: {other:?}"),
    }
}

/// Wait until `session.list` is `want`, polling; the request path reads the
/// store, so this follows the state of the file without a fixed sleep.
async fn wait_can_list(session: &mut Session, want: bool) {
    let deadline = tokio::time::Instant::now() + CLOSE_BOUND;
    loop {
        if can_list(session).await == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "session.list never became {want}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The connection is closed by the host's trust watch: code `0x1005`, the
/// fixed reason, seen from the peer.
async fn assert_withdrawn(conn: &Connection) {
    wait_closed(conn).await;
    assert_withdrawn_close(conn);
}

/// [`assert_withdrawn`] for a peer that keeps sending into the connection
/// after the host closed it (the stopped-reading flood tests).
///
/// QUIC sends CONNECTION_CLOSE once and does not retransmit it; the closing
/// side answers later packets with it only while it is still draining
/// (about three PTOs). Under CPU starvation the host's connection can
/// finish draining before the flooding peer observes the close, and the
/// host endpoint then answers the peer's next packet with a stateless reset,
/// which the peer reports as `ConnectionError::Reset`. ADR-0031 decision 7
/// says a peer cannot rely on the code; the security property is the close
/// itself, and the caller asserts that the host recorded the withdrawal.
/// So a reset is accepted here, and any other close must carry the code.
async fn assert_withdrawn_or_reset(conn: &Connection) {
    wait_closed(conn).await;
    if matches!(conn.close_reason(), Some(ConnectionError::Reset)) {
        return;
    }
    assert_withdrawn_close(conn);
}

async fn wait_closed(conn: &Connection) {
    tokio::time::timeout(CLOSE_BOUND, conn.closed())
        .await
        .unwrap_or_else(|_| panic!("the connection was not closed within {CLOSE_BOUND:?}"));
}

fn assert_withdrawn_close(conn: &Connection) {
    assert!(
        conn.closed_by_trust_withdrawal(),
        "closed, but not with the trust-withdrawn code: {:?}",
        conn.close_reason()
    );
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(close)) => {
            assert_eq!(&close.reason[..], b"trust withdrawn", "the fixed reason");
        }
        other => panic!("expected an application close, got {other:?}"),
    }
}

async fn assert_stays_open(conn: &Connection) {
    assert!(
        tokio::time::timeout(STAY_WINDOW, conn.closed())
            .await
            .is_err(),
        "the connection was closed: {:?}",
        conn.close_reason()
    );
}

/// Wait for the host's withdrawal record with this `resource` and return it.
async fn withdrawal_record(audit: &ToggleAudit, resource: &str) -> AuditRecord {
    let deadline = tokio::time::Instant::now() + CLOSE_BOUND;
    loop {
        if let Some(record) = audit
            .withdrawals()
            .into_iter()
            .find(|r| r.resource == resource)
        {
            return record;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no `{resource}` audit record: {:?}",
            audit.records()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// ADR-0031 결정 8: the shape of the record, whichever reason.
fn assert_connection_deny(record: &AuditRecord, principal: &str, auth_path: &str) {
    assert_eq!(record.action, "connect", "{record:?}");
    assert_eq!(record.decision, "deny", "{record:?}");
    assert_eq!(record.request_id, "-", "{record:?}");
    assert_eq!(record.principal, principal, "{record:?}");
    assert_eq!(record.auth_path, auth_path, "{record:?}");
    assert!(record.rule.is_none(), "{record:?}");
    assert!(record.role.is_none(), "no role key: {record:?}");
}

// ---------------------------------------------------------------------------
// qsh serve: the inbound connection
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn serve_inbound_connection_closes_on_trust_remove() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    assert!(can_list(&mut session).await);
    let conn = session.connection().clone();

    env.rewrite("");

    assert_withdrawn(&conn).await;
    let record = withdrawal_record(&host.audit, "trust_withdrawn").await;
    assert_connection_deny(&record, "device:laptop", "pin");
    assert_eq!(host.audit.withdrawals().len(), 1, "one line per connection");
    host.stop().await;
}

/// ADR-0031 결정 3: the watch runs in a task of its own, so a withdrawn peer
/// that stops reading the control stream cannot delay the close. Its
/// `session.list` replies (twenty sessions, about 2 KiB each) fill the
/// stream's 2 MiB window, which blocks the serving loop in a flow-controlled
/// send; the close must not wait for that loop.
#[tokio::test(flavor = "multi_thread")]
async fn serve_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let host = Host::start(&env).await;
    let mut opener = host.session(&client).await;
    for _ in 0..20 {
        opener.session_open(open_req()).await.expect("session.open");
    }

    let (conn, mut ctl) = host.dial_raw(&client).await;
    // Never read `ctl.recv`; keep it alive so the stream is not reset.
    let flood = tokio::spawn(async move {
        for id in 1..=6000u64 {
            let msg = wire::ControlMessage::new(
                id,
                wire::control_message::Body::SessionList(wire::SessionList {}),
            );
            if ctl.send.send(&msg).await.is_err() {
                break;
            }
        }
        std::future::pending::<()>().await;
        drop(ctl);
    });
    // Let the host fill the window and block in its send.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        conn.close_reason().is_none(),
        "still trusted, still open: {:?}",
        conn.close_reason()
    );

    env.rewrite("");

    assert_withdrawn_or_reset(&conn).await;
    let record = withdrawal_record(&host.audit, "trust_withdrawn").await;
    assert_connection_deny(&record, "device:laptop", "pin");
    flood.abort();
    host.stop().await;
}

/// 결정 6: the close comes first. A host whose audit writer fails closed
/// (the record cannot be written) still drops the withdrawn connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_audit_writer_does_not_keep_a_withdrawn_connection_open() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let host = Host::start(&env).await;
    let session = host.session(&client).await;
    let conn = session.connection().clone();
    host.audit.failing.store(true, Ordering::SeqCst);

    env.rewrite("");

    assert_withdrawn(&conn).await;
    assert!(
        host.audit.withdrawals().is_empty(),
        "nothing could be written"
    );
    host.stop().await;
}

/// ADR-0031 결정 3 and the "2 seconds" of 결정 9, on the clock: with tokio's
/// time paused after the connection is up, a `trust.toml` edit closes the
/// connection within one poll tick of virtual time. The poll task is the
/// only timer that has to fire, so the bound does not depend on the
/// speed of the machine.
#[tokio::test(flavor = "current_thread")]
async fn trust_withdrawal_closes_within_one_poll_tick_under_paused_time() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    assert!(can_list(&mut session).await);
    let conn = session.connection().clone();

    tokio::time::pause();
    env.rewrite("");
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(2), conn.closed())
        .await
        .expect("closed within 2 seconds of virtual time");
    assert!(conn.closed_by_trust_withdrawal());
    // The judgment itself is what the contract bounds: the host closes and
    // audits in one step, so the audit stamp dates the close. (The peer's
    // observation adds only the QUIC close packet's flight.)
    let judged = host
        .audit
        .first_withdrawal
        .lock()
        .expect("stamp lock")
        .expect("the withdrawal was audited");
    let elapsed = judged.duration_since(started);
    // Tokio rounds a deadline up to its 1 ms timer resolution, so a tick that
    // began just before the edit lands up to 1 ms past the interval.
    assert!(
        elapsed <= TRUST_POLL_INTERVAL + Duration::from_millis(1),
        "judged {elapsed:?} after the edit, more than one poll tick ({TRUST_POLL_INTERVAL:?})"
    );
    tokio::time::resume();
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pin_and_ca_path_connections_each_close_on_trust_remove() {
    let ca = make_ca();
    let pinned = make_identity();
    let via_ca = ca.issue("qsh://user/ops");
    let full_text = format!(
        "{}{}",
        pin("laptop", &pinned.fingerprint, Some("full")),
        ca_block("corp", &ca)
    );
    let env = Env::new(&full_text);
    let host = Host::start(&env).await;
    let mut pin_session = host.session(&pinned).await;
    let ca_session = host.session(&via_ca).await;
    assert!(can_list(&mut pin_session).await);
    let (pin_conn, ca_conn) = (
        pin_session.connection().clone(),
        ca_session.connection().clone(),
    );

    // Removing the pin closes the pin-path connection and spares the other.
    env.rewrite(&ca_block("corp", &ca));
    assert_withdrawn(&pin_conn).await;
    assert!(ca_conn.close_reason().is_none());
    let record = withdrawal_record(&host.audit, "trust_withdrawn").await;
    assert_connection_deny(&record, "device:laptop", "pin");

    // Removing the CA then closes the CA-path connection.
    env.rewrite("");
    assert_withdrawn(&ca_conn).await;
    let records = host.audit.withdrawals();
    let ca_record = records
        .iter()
        .find(|r| r.auth_path == "ca")
        .unwrap_or_else(|| panic!("no record for the CA path: {records:?}"));
    assert_connection_deny(ca_record, "user:ops", "ca");
    ca_session.close();
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_ca_closes_ca_path_connections_and_spares_pin_path_ones() {
    let ca = make_ca();
    let pinned = make_identity();
    let via_ca = ca.issue("qsh://user/ops");
    let pin_only = pin("laptop", &pinned.fingerprint, Some("full"));
    let env = Env::new(&format!("{pin_only}{}", ca_block("corp", &ca)));
    let host = Host::start(&env).await;
    let mut pin_session = host.session(&pinned).await;
    let ca_session = host.session(&via_ca).await;
    assert!(can_list(&mut pin_session).await);
    let (pin_conn, ca_conn) = (
        pin_session.connection().clone(),
        ca_session.connection().clone(),
    );

    env.rewrite(&pin_only);

    assert_withdrawn(&ca_conn).await;
    assert_stays_open(&pin_conn).await;
    assert!(can_list(&mut pin_session).await, "the pin keeps its role");
    pin_session.close();
    host.stop().await;
}

/// The pin is removed while a CA that vouches for the same leaf stays:
/// `reverify` still accepts the certificate, but through the CA, which is a
/// different trust basis than the connection was admitted on (결정 5, the
/// `auth_path` bullet).
#[tokio::test(flavor = "multi_thread")]
async fn pin_removed_but_ca_still_accepts_closes_on_auth_path_change() {
    let ca = make_ca();
    let leaf = ca.issue("qsh://device/laptop");
    let env = Env::new(&format!(
        "{}{}",
        pin("laptop", &leaf.fingerprint, Some("full")),
        ca_block("corp", &ca)
    ));
    let host = Host::start(&env).await;
    let mut session = host.session(&leaf).await;
    assert!(can_list(&mut session).await);
    let conn = session.connection().clone();

    env.rewrite(&ca_block("corp", &ca));

    assert_withdrawn(&conn).await;
    let record = withdrawal_record(&host.audit, "trust_withdrawn").await;
    assert_connection_deny(&record, "device:laptop", "pin");
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_trust_toml_closes_every_connection() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("exec")));
    let host = Host::start(&env).await;
    let first = host.session(&client).await;
    let second = host.session(&client).await;
    let (a, b) = (first.connection().clone(), second.connection().clone());

    env.delete();

    assert_withdrawn(&a).await;
    assert_withdrawn(&b).await;
    let deadline = tokio::time::Instant::now() + CLOSE_BOUND;
    while host.audit.withdrawals().len() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "two records expected"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    host.stop().await;
}

// ---------------------------------------------------------------------------
// qsh serve: roles (ADR-0031 결정 5, last two bullets)
// ---------------------------------------------------------------------------

/// Run `(from, to)` role changes in parallel, each on its own host, and
/// return for each whether the connection was closed (with `grants_reduced`
/// asserted) or stayed open.
async fn role_change(from: &'static str, to: &'static str, expect_closed: bool) {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some(from)));
    let host = Host::start(&env).await;
    let session = host.session(&client).await;
    let conn = session.connection().clone();

    env.rewrite(&pin("laptop", &client.fingerprint, Some(to)));

    if expect_closed {
        assert_withdrawn(&conn).await;
        let record = withdrawal_record(&host.audit, "grants_reduced").await;
        assert_connection_deny(&record, "device:laptop", "pin");
        assert!(
            host.audit
                .withdrawals()
                .iter()
                .all(|r| r.resource != "trust_withdrawn"),
            "{from} -> {to} keeps the credential, so it is not a trust withdrawal"
        );
    } else {
        assert_stays_open(&conn).await;
        assert!(host.audit.withdrawals().is_empty(), "{from} -> {to}");
    }
    host.stop().await;
}

async fn run_role_changes(cases: &[(&'static str, &'static str)], expect_closed: bool) {
    let mut tasks = Vec::new();
    for &(from, to) in cases {
        tasks.push(tokio::spawn(role_change(from, to, expect_closed)));
    }
    for (task, case) in tasks.into_iter().zip(cases) {
        task.await
            .unwrap_or_else(|err| panic!("{} -> {}: {err}", case.0, case.1));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn set_role_narrowing_closes_with_grants_reduced() {
    run_role_changes(
        &[
            // `any` becomes `owned` for the shared forwards, and the other
            // actions go (결정 5: `any` covers `owned`, not the reverse).
            ("full", "tunnel"),
            ("full", "exec"),
            ("full", "read-only"),
            ("full", "none"),
            ("exec", "read-only"),
            ("exec", "none"),
            ("read-only", "none"),
            ("tunnel", "none"),
            ("exec", "tunnel"),
        ],
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn set_role_widening_does_not_close() {
    run_role_changes(
        &[
            ("none", "exec"),
            ("read-only", "exec"),
            ("exec", "full"),
            ("tunnel", "full"),
            ("exec", "exec"),
            ("reverse", "full"),
        ],
        false,
    )
    .await;
}

/// 결정 5's replacement rule: a widening moves the recorded set, so the
/// narrowing that follows is measured against the widened record. `exec` to
/// `full` and back is a reduction, although the connection was admitted with
/// `exec`.
#[tokio::test(flavor = "multi_thread")]
async fn widen_then_narrow_closes_against_the_widened_record() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("exec")));
    let host = Host::start(&env).await;
    let session = host.session(&client).await;
    let conn = session.connection().clone();

    env.rewrite(&pin("laptop", &client.fingerprint, Some("full")));
    // Wait for the watch to have recorded the widened set: two poll ticks.
    assert_stays_open(&conn).await;
    env.rewrite(&pin("laptop", &client.fingerprint, Some("exec")));

    assert_withdrawn(&conn).await;
    withdrawal_record(&host.audit, "grants_reduced").await;
    host.stop().await;
}

/// 결정 5's last bullet: a rename moves the role to a new name, and the
/// connection looks its role up under the name it was admitted with. A pin
/// with a role loses it (closed, `grants_reduced`); a pin without one had
/// nothing to lose.
#[tokio::test(flavor = "multi_thread")]
async fn rename_of_a_role_pin_closes_and_rename_of_a_roleless_pin_does_not() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let host = Host::start(&env).await;
    let session = host.session(&client).await;
    let conn = session.connection().clone();
    env.rewrite(&pin("desk", &client.fingerprint, Some("full")));
    assert_withdrawn(&conn).await;
    let record = withdrawal_record(&host.audit, "grants_reduced").await;
    assert_connection_deny(&record, "device:laptop", "pin");
    host.stop().await;

    let env = Env::new(&pin("laptop", &client.fingerprint, None));
    let host = Host::start(&env).await;
    let session = host.session(&client).await;
    let conn = session.connection().clone();
    env.rewrite(&pin("desk", &client.fingerprint, None));
    assert_stays_open(&conn).await;
    assert!(host.audit.withdrawals().is_empty());
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn alias_reorder_does_not_close() {
    let client = make_identity();
    let other = make_identity();
    let laptop = pin("laptop", &client.fingerprint, Some("full"));
    let phone = pin("phone", &other.fingerprint, Some("exec"));
    let env = Env::new(&format!("{laptop}{phone}"));
    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    let conn = session.connection().clone();

    env.rewrite(&format!("{phone}{laptop}"));

    assert_stays_open(&conn).await;
    assert!(can_list(&mut session).await);
    assert!(host.audit.withdrawals().is_empty());
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unrelated_trust_changes_do_not_close_a_connection() {
    let client = make_identity();
    let other = make_identity();
    let ca = make_ca();
    let mine = pin("laptop", &client.fingerprint, Some("exec"));
    let env = Env::new(&mine);
    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    let conn = session.connection().clone();

    let steps = [
        format!("{mine}{}", pin("phone", &other.fingerprint, Some("full"))),
        format!("{mine}{}", pin("phone", &other.fingerprint, Some("none"))),
        format!(
            "{mine}{}{}",
            pin("phone", &other.fingerprint, Some("none")),
            ca_block("corp", &ca)
        ),
        format!("{mine}{}", ca_block("corp", &ca)),
        mine.clone(),
    ];
    for step in &steps {
        env.rewrite(step);
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    assert_stays_open(&conn).await;
    assert!(can_list(&mut session).await, "my own role is untouched");
    assert!(host.audit.withdrawals().is_empty());
    host.stop().await;
}

/// ADR-0031 결정 5 and the result section: a connection authorized by an
/// `acl.toml` row alone keeps going while its pin stays, whatever the pin's
/// role does, and is closed when the pin goes.
#[tokio::test(flavor = "multi_thread")]
async fn acl_row_only_connection_survives_while_its_pin_remains() {
    let client = make_identity();
    let acl = "[[acl]]\nprincipal = \"device:laptop\"\nallow = [\"session.list\"]\n";
    let env = Env::with_acl(&pin("laptop", &client.fingerprint, None), Some(acl));
    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    let conn = session.connection().clone();
    assert!(can_list(&mut session).await, "the row grants session.list");

    // A role that grants nothing, then a wider one: neither reduces the
    // (empty) set the connection was admitted with.
    env.rewrite(&pin("laptop", &client.fingerprint, Some("none")));
    assert_stays_open(&conn).await;
    assert!(can_list(&mut session).await, "still granted by the row");
    env.rewrite(&pin("laptop", &client.fingerprint, Some("full")));
    assert_stays_open(&conn).await;
    assert!(can_list(&mut session).await);

    env.rewrite("");
    assert_withdrawn(&conn).await;
    withdrawal_record(&host.audit, "trust_withdrawn").await;
    host.stop().await;
}

// ---------------------------------------------------------------------------
// qsh serve: a trust.toml that cannot be used (결정 6)
// ---------------------------------------------------------------------------

const GARBAGE: &str = "[[peer]\nthis is not toml";

/// 결정 6: a `trust.toml` that does not parse closes nothing, but the role
/// stage stops granting (ADR-0045 결정 4). Fixing the file clears it, and
/// the comparison that was owed runs at once against the recorded set: a
/// role lowered while the file was broken closes the connection after the
/// repair.
#[tokio::test(flavor = "multi_thread")]
async fn unparseable_trust_toml_keeps_connections_but_suspends_role_requests() {
    let client = make_identity();
    let good = pin("laptop", &client.fingerprint, Some("full"));
    let env = Env::new(&good);
    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    let conn = session.connection().clone();
    assert!(can_list(&mut session).await);

    env.rewrite(GARBAGE);
    wait_can_list(&mut session, false).await;
    assert_stays_open(&conn).await;
    assert!(!can_list(&mut session).await, "roles stay suspended");

    // The same good text again: the generation moves and the role grants
    // are back, the connection never closed.
    env.rewrite(&good);
    wait_can_list(&mut session, true).await;
    assert_stays_open(&conn).await;
    assert!(host.audit.withdrawals().is_empty());

    // Broken again, and repaired with a lower role: the repair finds the
    // reduction.
    env.rewrite(GARBAGE);
    wait_can_list(&mut session, false).await;
    env.rewrite(&pin("laptop", &client.fingerprint, Some("none")));
    assert_withdrawn(&conn).await;
    withdrawal_record(&host.audit, "grants_reduced").await;
    host.stop().await;
}

/// Unix permissions can make `trust.toml` unreadable without changing a
/// byte of it. The suspension that causes ends without a generation change,
/// so the watch must ask again on the poll cadence instead of waiting for a
/// notification that never comes. Skipped where a mode does not stop the
/// reader (root).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_trust_toml_defers_the_comparison_until_it_can_be_read() {
    use std::os::unix::fs::PermissionsExt;

    fn set_mode(path: &std::path::Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("chmod trust.toml");
    }

    let client = make_identity();
    let good = pin("laptop", &client.fingerprint, Some("full"));
    let env = Env::new(&good);
    let path = env.trust_path();
    set_mode(&path, 0o000);
    if std::fs::File::open(&path).is_ok() {
        eprintln!("skipped: file modes do not stop this reader");
        set_mode(&path, 0o600);
        return;
    }
    set_mode(&path, 0o600);

    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    let conn = session.connection().clone();
    assert!(can_list(&mut session).await);

    // Unreadable, identical bytes: roles suspend, nothing closes.
    set_mode(&path, 0o000);
    wait_can_list(&mut session, false).await;
    assert_stays_open(&conn).await;

    // Readable again with the same bytes: the grants return and the
    // connection was never touched.
    set_mode(&path, 0o600);
    wait_can_list(&mut session, true).await;
    assert_stays_open(&conn).await;
    assert!(host.audit.withdrawals().is_empty());

    // A second connection is admitted while the file is unreadable, so its
    // watch starts without a baseline. The repair is silent (no new
    // generation); the watch adopts the set it then sees, and a later
    // reduction is measured against it.
    set_mode(&path, 0o000);
    wait_can_list(&mut session, false).await;
    let second = host.session(&client).await;
    let second_conn = second.connection().clone();
    set_mode(&path, 0o600);
    wait_can_list(&mut session, true).await;
    // Two poll ticks: the deferred comparison has adopted `full`.
    assert_stays_open(&second_conn).await;

    env.rewrite(&pin("laptop", &client.fingerprint, Some("none")));
    assert_withdrawn(&second_conn).await;
    assert_withdrawn(&conn).await;
    assert_eq!(
        host.audit
            .withdrawals()
            .iter()
            .filter(|r| r.resource == "grants_reduced")
            .count(),
        2
    );
    host.stop().await;
}

// ---------------------------------------------------------------------------
// qsh serve: after the close (결정 7)
// ---------------------------------------------------------------------------

/// A closed connection detaches its sessions and does not end them. A peer
/// that is still trusted dials again and sees them with the reduced grants.
#[tokio::test(flavor = "multi_thread")]
async fn closed_connection_sessions_detach_and_a_still_trusted_peer_resumes_with_reduced_grants() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let host = Host::start(&env).await;
    let mut session = host.session(&client).await;
    session
        .session_open(open_req())
        .await
        .expect("session.open");
    assert_eq!(host.broker.session_count(), 1);
    let conn = session.connection().clone();

    env.rewrite(&pin("laptop", &client.fingerprint, Some("read-only")));
    assert_withdrawn(&conn).await;

    assert_eq!(
        host.broker.session_count(),
        1,
        "the close detaches the session, it does not end it"
    );
    let mut again = host.session(&client).await;
    let listed = again.session_list().await.expect("read-only may list");
    assert_eq!(listed.len(), 1, "the session is still there: {listed:?}");
    match again.session_open(open_req()).await {
        Err(ClientError::Remote {
            code: ErrorCode::PermissionDenied,
            ..
        }) => {}
        other => panic!("the reduced role must not open sessions: {other:?}"),
    }
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_peer_cannot_handshake_again() {
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let host = Host::start(&env).await;
    let session = host.session(&client).await;
    let conn = session.connection().clone();

    env.rewrite("");
    assert_withdrawn(&conn).await;

    assert!(
        host.dial(&client).await.is_err(),
        "a peer whose trust was withdrawn must not get back in"
    );
    host.stop().await;
}

// ---------------------------------------------------------------------------
// Measurement: one change, many connections
// ---------------------------------------------------------------------------

/// One trust change closes every connection the host holds, in well under
/// the two seconds the contract promises. The count defaults to 96 so the
/// test is cheap in the gate; `QSH_M16_CONNECTIONS` raises it for the
/// measurement near the host's connection cap (512). Each connection costs
/// one judgment (a certificate re-verification and a table lookup), and they
/// all run on the one generation change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_change_closes_many_connections_within_two_seconds() {
    let count: usize = std::env::var("QSH_M16_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(96);
    let client = make_identity();
    let env = Env::new(&pin("laptop", &client.fingerprint, Some("full")));
    let limits = QuotaLimits {
        max_connections_per_principal: count + 8,
        max_connections: count + 8,
        ..QuotaLimits::default()
    };
    let host = Arc::new(Host::start_with(&env, Some(limits)).await);

    let mut dials = tokio::task::JoinSet::new();
    for _ in 0..count {
        let host = Arc::clone(&host);
        let client = client.clone();
        dials.spawn(async move { host.session(&client).await });
    }
    let mut sessions = Vec::with_capacity(count);
    while let Some(joined) = dials.join_next().await {
        sessions.push(joined.expect("dial task"));
    }
    let conns: Vec<Connection> = sessions.iter().map(|s| s.connection().clone()).collect();
    // Let every watch finish its first judgment so the change below is the
    // only thing left to notice.
    tokio::time::sleep(Duration::from_millis(500)).await;

    env.rewrite("");
    let started = std::time::Instant::now();
    for conn in &conns {
        tokio::time::timeout(CLOSE_BOUND, conn.closed())
            .await
            .expect("every connection is closed");
    }
    let elapsed = started.elapsed();
    let deadline = tokio::time::Instant::now() + CLOSE_BOUND;
    while host.audit.withdrawals().len() < count {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} of {count} audit records",
            host.audit.withdrawals().len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let audited = started.elapsed();
    let by_reason: BTreeMap<String, usize> =
        host.audit
            .withdrawals()
            .iter()
            .fold(BTreeMap::new(), |mut acc, r| {
                *acc.entry(r.resource.clone()).or_default() += 1;
                acc
            });
    eprintln!(
        "m16 measurement: {count} connections closed {elapsed:?} after the edit, \
         {count} audit lines {audited:?} after it, {by_reason:?}"
    );
    assert!(
        conns.iter().all(|c| c.closed_by_trust_withdrawal()),
        "every close carries the trust-withdrawn code"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "{count} connections took {elapsed:?} to close after one change"
    );
    assert_eq!(by_reason.get("trust_withdrawn").copied(), Some(count));
    drop(sessions);
    if let Ok(host) = Arc::try_unwrap(host) {
        host.stop().await;
    }
}

// ---------------------------------------------------------------------------
// qsh listen: the registration connection (결정 2, 7)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod listen {
    use super::*;
    use qsh_core::acl::AllowAllPinned;
    use qsh_testkit::reverse::{EntryState, ReverseHarness, wait_for};

    const TIMEOUT: Duration = Duration::from_secs(10);

    fn controller_pin(target: &TestIdentity) -> StaticTrust {
        StaticTrust::empty().with_pin(target.fingerprint, Principal::Device("widget".to_string()))
    }

    /// A controller whose connection watch reads `env`, and a target that
    /// has registered as `widget`.
    async fn registered(
        env: &Env,
        target: &TestIdentity,
    ) -> (
        ReverseHarness,
        qsh_transport::Dialed,
        qsh_transport::FramedStream,
    ) {
        let harness =
            ReverseHarness::start_with(Arc::new(AllowAllPinned), false, controller_pin(target))
                .await;
        harness.listen.set_trust_watch(Arc::clone(&env.store));
        let (dialed, ctl, _hello) = harness
            .register(target, "widget")
            .await
            .unwrap_or_else(|err| panic!("registration refused: {err:?}"));
        wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
        (harness, dialed, ctl)
    }

    async fn withdrawn_record(harness: &ReverseHarness, resource: &str) -> AuditRecord {
        wait_for(TIMEOUT, || {
            harness
                .audit
                .records()
                .into_iter()
                .find(|r| r.action == "connect" && r.resource == resource)
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn listen_registration_closes_on_trust_remove() {
        let target = make_identity();
        let env = Env::new(&pin("widget", &target.fingerprint, Some("reverse")));
        let (harness, dialed, _ctl) = registered(&env, &target).await;

        env.rewrite("");

        assert_withdrawn(&dialed.connection).await;
        let record = withdrawn_record(&harness, "trust_withdrawn").await;
        assert_connection_deny(&record, "device:widget", "pin");
        wait_for(TIMEOUT, || {
            harness
                .listen
                .registry()
                .get("widget")
                .filter(|entry| entry.state == EntryState::Stale)
        })
        .await;
        harness.shutdown().await;
    }

    /// ADR-0031 결정 3: the registration's watch runs in its own task. The
    /// target stops reading the control stream while flooding request-shaped
    /// messages, each answered with an `UNSUPPORTED` error the controller's
    /// loop awaits a send for; once the window is full that loop is blocked,
    /// and the close must not wait for it.
    #[tokio::test(flavor = "multi_thread")]
    async fn listen_closes_a_withdrawn_peer_that_stopped_reading_the_control_stream() {
        let target = make_identity();
        let env = Env::new(&pin("widget", &target.fingerprint, Some("reverse")));
        let (harness, dialed, mut ctl) = registered(&env, &target).await;

        let flood = tokio::spawn(async move {
            for id in 1..=200_000u64 {
                let msg = qsh_proto::wire::ControlMessage::new(
                    id,
                    qsh_proto::wire::control_message::Body::SessionList(
                        qsh_proto::wire::SessionList {},
                    ),
                );
                if ctl.send.send(&msg).await.is_err() {
                    break;
                }
            }
            std::future::pending::<()>().await;
            drop(ctl);
        });
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(dialed.connection.close_reason().is_none());

        env.rewrite("");

        assert_withdrawn_or_reset(&dialed.connection).await;
        let record = withdrawn_record(&harness, "trust_withdrawn").await;
        assert_connection_deny(&record, "device:widget", "pin");
        flood.abort();
        harness.shutdown().await;
    }

    /// The registration only exercises `host.reverse`, so that is the one
    /// grant compared: the target pin's role falling from `reverse` to
    /// `none` closes it as `grants_reduced`.
    #[tokio::test(flavor = "multi_thread")]
    async fn listen_registration_closes_with_grants_reduced_when_target_role_drops_to_none() {
        let target = make_identity();
        let env = Env::new(&pin("widget", &target.fingerprint, Some("reverse")));
        let (harness, dialed, _ctl) = registered(&env, &target).await;

        env.rewrite(&pin("widget", &target.fingerprint, Some("none")));

        assert_withdrawn(&dialed.connection).await;
        let record = withdrawn_record(&harness, "grants_reduced").await;
        assert_connection_deny(&record, "device:widget", "pin");
        wait_for(TIMEOUT, || {
            harness
                .listen
                .registry()
                .get("widget")
                .filter(|entry| entry.state == EntryState::Stale)
        })
        .await;
        harness.shutdown().await;
    }

    /// A role that still grants `host.reverse` does not touch the
    /// registration: the same role, a wider one, and `full` falling to
    /// `reverse` (which loses everything a registration never uses, and
    /// changes the ownership axis of an action that has none).
    #[tokio::test(flavor = "multi_thread")]
    async fn listen_registration_survives_a_same_or_wider_target_role() {
        let target = make_identity();
        let env = Env::new(&pin("widget", &target.fingerprint, Some("reverse")));
        let (harness, dialed, _ctl) = registered(&env, &target).await;

        for role in ["reverse", "full", "reverse", "full", "reverse"] {
            env.rewrite(&pin("widget", &target.fingerprint, Some(role)));
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }

        assert_stays_open(&dialed.connection).await;
        assert!(harness.listen.registry().get("widget").is_some());
        assert!(
            harness
                .audit
                .records()
                .iter()
                .all(|r| r.resource != "trust_withdrawn" && r.resource != "grants_reduced")
        );
        harness.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// qsh serve --to: the outbound connection (결정 7)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod serve_to {
    use super::*;
    use qsh_core::acl::AllowAllPinned;
    use qsh_core::config::{Config, ReverseConfig};
    use qsh_testkit::reverse::{EntryState, ReverseHarness, wait_for};

    const TIMEOUT: Duration = Duration::from_secs(20);

    /// The real `run_reverse` loop dials a controller it pins in its own
    /// `trust.toml`. Removing that pin makes the target's watch close the
    /// connection it dialed (the target serves requests on it), audit it in
    /// its own log, and then the redial meets its own verifier's refusal.
    #[tokio::test(flavor = "multi_thread")]
    async fn serve_to_outbound_connection_closes_on_trust_remove() {
        let target = make_identity();
        let harness = ReverseHarness::start_with(
            Arc::new(AllowAllPinned),
            false,
            StaticTrust::empty()
                .with_pin(target.fingerprint, Principal::Device("widget".to_string())),
        )
        .await;
        let config = Config {
            reverse: ReverseConfig {
                backoff_initial_ms: Some(50),
                backoff_max_ms: Some(200),
                backoff_jitter_pct: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (path_tx, path_rx) = tokio::sync::oneshot::channel::<PathBuf>();
        let run = harness.run_target_with_config_observing_runtime(
            &target,
            "device-id",
            "ctrl",
            None,
            &config,
            move |runtime| {
                let _ = path_tx.send(runtime.audit.path().to_path_buf());
            },
            async {
                let _ = shutdown_rx.await;
            },
        );
        let drive = async {
            // The target's audit log is `<tmp>/state/audit.log` and its
            // `trust.toml` `<tmp>/config/trust.toml` (`target_paths_at`).
            let audit_log = path_rx.await.expect("the runtime hook ran");
            let root = audit_log
                .parent()
                .and_then(std::path::Path::parent)
                .expect("temp root")
                .to_path_buf();
            let trust = root.join("config").join("trust.toml");
            let before = std::fs::read_to_string(&trust).expect("target trust.toml");
            assert!(before.contains("ctrl"), "the target pins the controller");
            wait_for(TIMEOUT, || harness.listen.registry().get("widget")).await;
            // The controller's end of the connection the target dialed.
            let (controller_side, _hub) =
                wait_for(TIMEOUT, || harness.listen.connection_for("widget")).await;

            // `qsh trust remove ctrl` on the target: an atomic replace.
            let tmp = trust.with_extension("toml.tmp");
            std::fs::write(&tmp, "").expect("write empty trust.toml");
            std::fs::rename(&tmp, &trust).expect("replace trust.toml");

            // The controller sees the target's close with the trust-withdrawn
            // code `0x1005` and the fixed reason (결정 7).
            // Read through `closed_by_trust_withdrawal`, not the raw reason:
            // the controller's own teardown closes the handle again, and the
            // transport overwrites the reason of a closed connection with
            // "locally closed" (`Connection::close`'s doc).
            tokio::time::timeout(CLOSE_BOUND, controller_side.closed())
                .await
                .expect("the controller side is closed");
            assert!(
                controller_side.closed_by_trust_withdrawal(),
                "the controller observed a close other than 0x1005"
            );
            // The registration goes stale (it is not removed until the
            // retention passes).
            wait_for(TIMEOUT, || {
                harness
                    .listen
                    .registry()
                    .get("widget")
                    .filter(|entry| entry.state == EntryState::Stale)
            })
            .await;
            // The target audited the close on its own log (결정 8).
            wait_for(TIMEOUT, || {
                let text = std::fs::read_to_string(&audit_log).ok()?;
                text.lines()
                    .filter_map(|line| serde_json::from_str::<AuditRecord>(line).ok())
                    .find(|r| r.action == "connect" && r.resource == "trust_withdrawn")
            })
            .await;
            // The pin is gone for the target's own verifier too: the redial
            // is refused and the registration does not come back live.
            tokio::time::sleep(Duration::from_millis(2000)).await;
            let entry = harness
                .listen
                .registry()
                .get("widget")
                .expect("stale entry");
            assert_eq!(entry.state, EntryState::Stale, "no live re-registration");
            let _ = shutdown_tx.send(());
        };
        let (result, ()) =
            tokio::time::timeout(Duration::from_secs(60), async { tokio::join!(run, drive) })
                .await
                .expect("the scenario finishes");
        result.expect("run_reverse stops cleanly on shutdown");
        harness.shutdown().await;
    }
}
