//! `qsh listen` — the reverse-mode controller (`docs/CLI.md` §6.13,
//! `docs/design/protocol.md` §11-2, `PLAN.md` Step 3, PR 3b). Symmetric in
//! shape with `serve.rs`'s `run_serve`: bind resolution
//! (`--bind` > `[listen].bind` > [`crate::serve::DEFAULT_BIND`]), an
//! `on_bound` callback, and a `shutdown` future the accept loop selects on.
//!
//! Per accepted connection this runs [`crate::handshake::respond`] with the
//! controller's own `Hello` (`reverse: None` — the controller never
//! registers itself). The peer's `Hello.reverse` decides what happens
//! next:
//!
//! - **absent** — `UNSUPPORTED` ("this endpoint only accepts reverse
//!   registrations"), zero resources, zero audit (not an ACL decision).
//! - **present** — [`super::admit::admit`] decides, exactly as PR 3a wired
//!   it: shape → name resolution → the `host.reverse` choke point → insert.
//!   A denial answers with the *opaque* `OpError` `admit` already produced
//!   (never enriched here). A success makes this connection CLIENT role
//!   ([`crate::client::Session::from_control`]) and this file — never
//!   [`super::registry::Registry`] — owns the live connection, keyed by
//!   `(name, generation)` (module docs on [`Listen`]).
//!
//! Every rejection error frame this module writes rides the same bounded
//! drain [`crate::handshake::respond`] already applies
//! (`crate::handshake::REJECTION_DRAIN_TIMEOUT`) before the caller closes
//! the connection — nothing here re-implements that ordering.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, Hello};
use qsh_transport::{AcceptError, Connection, FramedStream, Incoming, Listener};

// The next four imports are consumed only by the unix entry point (and
// this module's tests) — on the Windows lib build nothing constructs a
// controller, so ungated they would trip `unused_imports` under the
// Windows leg's `clippy -D warnings` (same gating as `tui/mod.rs`).
#[cfg(any(unix, test))]
use crate::acl::AllowAllPinned;
use crate::acl::Authorizer;
#[cfg(unix)]
use crate::audit::FileAuditSink;
use crate::audit::{AuditRecord, AuditSink};
#[cfg(unix)]
use crate::broker::SystemClock;
use crate::client::{ControlIn, Session};
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
use crate::ops::OpError;
#[cfg(unix)]
use crate::trust::SharedTrustStore;

use super::admit::{AdmitRequest, admit};
use super::registry::{self, RegisterOutcome, Registry};

/// Close code for the connection a NAT-rebind reconnect displaces
/// (`docs/design/protocol.md` §11-2's "same-fingerprint replace"). Local to
/// this module — the meaning is registration-specific, not a transport
/// concern, so it does not belong in `qsh-transport`
/// (`docs/design/architecture.md` §1).
const CLOSE_CODE_REPLACED: u32 = 0x1003;

/// Resolve the bind address: CLI flag > `config.toml` `[listen].bind` >
/// [`crate::serve::DEFAULT_BIND`] — the same default `qsh serve` uses
/// (`docs/CLI.md` §6.13: running both roles on one host needs an explicit
/// `--bind`). Accepts `ip:port` or `host:port` (first resolution).
pub fn resolve_bind(flag: Option<&str>, config: &Config) -> Result<SocketAddr, OpError> {
    let spec = flag
        .map(str::to_owned)
        .or_else(|| config.listen.bind.clone())
        .unwrap_or_else(|| crate::serve::DEFAULT_BIND.to_string());
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(addr);
    }
    spec.to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| {
            OpError::new(
                ErrorCode::InvalidArgument,
                format!("invalid bind address {spec:?} (expected ip:port or host:port)"),
            )
        })
}

/// Run the controller until `shutdown` resolves.
///
/// `identity` must already be loaded synchronously before entering the
/// runtime, exactly like [`crate::serve::run_serve`]. `on_bound` receives
/// the actual bound address once the listener is up.
pub async fn run_listen(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    bind_flag: Option<&str>,
    on_bound: impl FnOnce(SocketAddr),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    // Twin cfg blocks as alternative tail expressions — the exact shape
    // `pty::factory` established; a `return` here instead would trip
    // clippy's `needless_return` on the Windows leg (probed empirically).
    #[cfg(not(unix))]
    {
        let _ = (paths, config, identity, bind_flag, on_bound, shutdown);
        Err(windows_unsupported())
    }
    #[cfg(unix)]
    {
        run_listen_unix(paths, config, identity, bind_flag, on_bound, shutdown).await
    }
}

/// `docs/CLI.md` §6.13: `qsh listen`/`qsh reverse` create no resources on
/// Windows and answer `UNSUPPORTED` + exit `255` — localctl (UDS) and the
/// host role (PTY, `crate::pty`) are both `cfg(unix)`, so there is nothing
/// for either to actually do there. Shared by [`run_listen`] and
/// [`super::target::run_reverse`] so the message and code stay identical.
#[cfg(not(unix))]
pub(super) fn windows_unsupported() -> OpError {
    OpError::new(
        ErrorCode::Unsupported,
        "reverse mode is not supported on this platform (localctl and the PTY host role are unix-only)",
    )
}

#[cfg(unix)]
async fn run_listen_unix(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    bind_flag: Option<&str>,
    on_bound: impl FnOnce(SocketAddr),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    let bind = resolve_bind(bind_flag, config)?;
    let trust = SharedTrustStore::open(paths.trust_file())?;
    let listener = Listener::bind(bind, identity.local, trust).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("cannot listen on {bind}: {err}"),
        )
    })?;
    let actual = listener.local_addr().map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot read bound address: {err}"),
        )
    })?;
    on_bound(actual);

    let audit = Arc::new(FileAuditSink::new(paths.audit_log()));
    let registry = Registry::new(Arc::new(SystemClock), config.listen.allow_advertised_names);
    let listen = Listen::new(
        registry,
        Arc::new(AllowAllPinned),
        audit,
        identity.identity.device_id.clone(),
    );
    tracing::info!(
        device_id = %identity.identity.device_id,
        fingerprint = %identity.identity.fingerprint,
        %actual,
        "qsh listen listening"
    );
    listen.run(listener, shutdown).await;
    Ok(())
}

/// The controller: registry + policy + audit + the live-connection table
/// `Registry` deliberately does not hold (module docs, `PLAN.md` Step 3
/// (b): "살아 있는 `client::Session`은 registry가 아니라
/// `reverse/listen.rs`의 연결 표가 소유한다").
///
/// One `Listen` is built per `qsh listen` process ([`run_listen`]) and
/// shared across every accepted connection, symmetric with `serve.rs`'s
/// [`crate::serve::HostRuntime`]. Exposes [`Listen::registry`] so a test
/// harness can observe registrations by name without scraping stderr.
pub struct Listen {
    registry: Registry,
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<dyn AuditSink>,
    device_name: String,
    /// Live registered connections, keyed by `(name, generation)` — never
    /// in [`Registry`] (module docs).
    conns: Mutex<HashMap<(String, u64), Connection>>,
}

impl std::fmt::Debug for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listen")
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl Listen {
    /// Build a controller with the given registry, policy and audit sink.
    pub fn new(
        registry: Registry,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            authorizer,
            audit,
            device_name: device_name.into(),
            conns: Mutex::new(HashMap::new()),
        })
    }

    /// The reverse-registration table — read-only from outside this
    /// module; a test harness uses this instead of scraping stderr.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Number of live connections this controller currently holds
    /// (tests/diagnostics).
    pub fn live_connections(&self) -> usize {
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// The `Hello` this controller sends on every connection —
    /// `reverse: None` always: the controller registers nothing of its own
    /// (module docs).
    fn local_hello(&self) -> Hello {
        Hello {
            versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
            device_name: self.device_name.clone(),
            capabilities: wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            reverse: None,
        }
    }

    // ------------------------------------------------------------------
    // accept loop
    // ------------------------------------------------------------------

    /// Accept loop. Runs until `shutdown` resolves or the listener closes,
    /// then closes the endpoint and waits for it to drain — same shape as
    /// [`crate::server::Server::run`].
    pub async fn run(
        self: Arc<Self>,
        listener: Listener,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                incoming = listener.accept() => {
                    let Some(incoming) = incoming else { break };
                    let this = self.clone();
                    tokio::spawn(async move { this.accept_and_register(incoming).await });
                }
            }
        }
        listener.close(0, b"shutdown");
        listener.endpoint().wait_idle().await;
    }

    /// Accept one inbound connection and run the registration handshake on
    /// it. Mirrors [`crate::server::Server::accept_and_serve`]'s
    /// verify-then-audit shape for a rejected TLS handshake.
    async fn accept_and_register(self: Arc<Self>, incoming: Incoming) {
        let peer = incoming.remote_address();
        match incoming.accept().await {
            Ok(conn) => self.register_connection(conn).await,
            Err(err) => {
                let category = match &err {
                    AcceptError::Unverified(reason) => format!("{reason:?}").to_lowercase(),
                    _ => "handshake".to_string(),
                };
                self.audit
                    .record(&AuditRecord::handshake_rejected(peer, &category));
                tracing::warn!(%peer, %err, "connection rejected");
            }
        }
    }

    /// Run the `Hello` exchange as responder and, on a successful
    /// registration, hand the connection off to
    /// [`Listen::finish_registration`]. Every rejection path already wrote
    /// (and [`crate::handshake::respond`] already drained) its error frame
    /// before returning here — this only has to close.
    async fn register_connection(self: Arc<Self>, conn: Connection) {
        // `Mutex`, not `RefCell`: this reference is captured by the
        // `make_local_hello` closure `handshake::respond` holds across an
        // `.await` inside a `tokio::spawn`ed task, so it must be `Sync`
        // (`RefCell` is not — the borrow-check failure is the compiler
        // catching exactly that). Never actually contended: the closure
        // runs synchronously, once, before `respond` returns.
        let outcome_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
        let result = crate::handshake::respond(&conn, |peer_hello| {
            self.decide_registration(&conn, peer_hello, &outcome_cell)
        })
        .await;

        let (ctl, peer_hello) = match result {
            Ok(pair) => pair,
            Err(_err) => {
                // `decide_registration` may already have run `admit` and
                // stashed a `RegisterOutcome` here — reachable when the
                // `Hello` reply itself failed to send after admission
                // succeeded (`handshake::respond_on`'s `io.send_hello(..)`,
                // after the callback returns `Ok`). Left alone, that would
                // leave a `Live` registry entry with no connection behind
                // it, forever (`PLAN.md` M3 Step 3 review). Roll it back —
                // undoing exactly what `admit` did, nothing more.
                if let Some(outcome) = outcome_cell.into_inner().unwrap_or_else(|e| e.into_inner())
                {
                    self.registry.rollback(
                        &outcome.entry.name,
                        outcome.entry.generation,
                        outcome.replaced_entry,
                    );
                }
                conn.close(
                    qsh_transport::endpoint::CLOSE_CODE_PROTOCOL,
                    b"registration refused",
                );
                return;
            }
        };
        let Some(outcome) = outcome_cell.into_inner().unwrap_or_else(|e| e.into_inner()) else {
            // Defensive: `decide_registration` always populates this on
            // every `Ok` it returns.
            conn.close(
                qsh_transport::endpoint::CLOSE_CODE_PROTOCOL,
                b"internal error",
            );
            return;
        };
        self.finish_registration(conn, ctl, peer_hello, outcome)
            .await;
    }

    /// The synchronous decision `crate::handshake::respond`'s
    /// `make_local_hello` callback needs: absent `Hello.reverse` is
    /// `UNSUPPORTED` (not an ACL decision — zero resources, zero audit);
    /// present is [`super::admit::admit`], verbatim, with its `Ok` stashed
    /// into `outcome_cell` for [`Listen::register_connection`] to pick up
    /// once the whole `Hello` exchange (this reply included) has actually
    /// gone out.
    fn decide_registration(
        &self,
        conn: &Connection,
        peer_hello: &Hello,
        outcome_cell: &Mutex<Option<RegisterOutcome>>,
    ) -> Result<Hello, wire::Error> {
        let Some(reg) = peer_hello.reverse.as_ref() else {
            tracing::warn!(
                peer = %conn.remote_address(),
                "peer connected to qsh listen without Hello.reverse"
            );
            return Err(wire::Error::new(
                ErrorCode::Unsupported,
                "this endpoint only accepts reverse registrations",
                false,
            ));
        };

        let Some(fingerprint) = conn.peer_fingerprint() else {
            // Not reachable in practice (`Connection::peer_fingerprint`'s
            // own docs: only `None` if a verified leaf failed to
            // re-parse) — fail closed rather than register an entry with
            // nothing to bind a fingerprint to.
            return Err(wire::Error::new(
                ErrorCode::PermissionDenied,
                registry::host_reverse_denied().message,
                false,
            ));
        };
        // `ReverseRegistration.capabilities` empty means "same as
        // Hello.capabilities" (`v1.proto`'s field doc) — the negotiated
        // intersection this connection's general `Hello` already settled.
        let capabilities = if reg.capabilities.is_empty() {
            crate::handshake::negotiated_capabilities(peer_hello)
        } else {
            reg.capabilities.clone()
        };

        let req = AdmitRequest {
            principal: conn.principal(),
            auth_path: conn.auth_path(),
            fingerprint,
            address: conn.remote_address(),
            offered_name: &reg.offered_name,
            capabilities,
        };

        match admit(
            &self.registry,
            self.authorizer.as_ref(),
            self.audit.as_ref(),
            req,
        ) {
            Ok(outcome) => {
                RegistrationEvent {
                    event: if outcome.replaced_generation.is_some() {
                        "replaced"
                    } else {
                        "registered"
                    },
                    host: &outcome.entry.name,
                    fingerprint: &outcome.entry.fingerprint,
                    generation: Some(outcome.entry.generation),
                }
                .emit();
                *outcome_cell.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
                Ok(self.local_hello())
            }
            Err(err) => {
                RegistrationEvent {
                    event: "denied",
                    host: diag_host(&reg.offered_name),
                    fingerprint: &fingerprint.to_string(),
                    generation: None,
                }
                .emit();
                Err(wire::Error::new(err.code, err.message, err.retryable))
            }
        }
    }

    /// Publish the registered connection into [`Listen::conns`], close any
    /// connection it replaced (NAT-rebind reconnect — insert the new entry
    /// *before* closing the old one, so the name is never briefly
    /// unroutable), then drive the connection as CLIENT role until it
    /// dies.
    async fn finish_registration(
        self: Arc<Self>,
        conn: Connection,
        ctl: FramedStream,
        peer_hello: Hello,
        outcome: RegisterOutcome,
    ) {
        let name = outcome.entry.name.clone();
        let fingerprint = outcome.entry.fingerprint.clone();
        let generation = outcome.entry.generation;

        // KNOWN RACE, deferred to Step 4 (`PLAN.md` M3 Step 3 review — LOW,
        // deliberately not fixed here): `Registry::admit` (called from
        // `decide_registration`, before this method runs) is atomic per
        // call, but the *this* table below is only populated later, after
        // `handshake::respond` has finished flushing the `Hello` reply —
        // so two concurrent same-fingerprint registrations can have their
        // `admit()` calls ordered A-then-B (generation 0→1→2) while their
        // `finish_registration` continuations run B-then-A. B's `remove`
        // below then finds nothing at generation 1 (A has not inserted it
        // yet) and closes nothing; A's unconditional `insert` afterward
        // publishes generation 1's connection into `conns` with no
        // registry entry pointing at it any more — a live connection the
        // table now leaks forever (never closed, never removed) instead of
        // the intended "replace closes the superseded connection"
        // guarantee this method's own doc comment promises. Acceptable for
        // Step 3: nothing in this step's product code ever fires two
        // concurrent registrations from one target — a real `qsh reverse`
        // holds exactly one connection and registers once
        // (`reverse/target.rs`'s module docs); only Step 4's reconnect
        // loop, which can legitimately race a stale connection's death
        // against a fresh re-dial, exercises the controller-side replace
        // path enough to hit this. Step 4 MUST close that window (e.g. by
        // moving the `conns` publish inside the same critical section
        // `admit()` already holds, or by re-checking the table under lock
        // before trusting `replaced_generation`).
        {
            let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
            conns.insert((name.clone(), generation), conn.clone());
        }
        if let Some(replaced_generation) = outcome.replaced_generation {
            let old = self
                .conns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&(name.clone(), replaced_generation));
            if let Some(old_conn) = old {
                // `Connection::close` is idempotent — safe even if the old
                // connection is already mid-close on its own (e.g. the
                // peer hung up right as it reconnected).
                old_conn.close(CLOSE_CODE_REPLACED, b"replaced by a newer registration");
            }
        }

        let session = Session::from_control(conn, ctl, peer_hello);
        self.drive_registered_session(session, name, fingerprint, generation)
            .await;
    }

    /// The controller is CLIENT role on a registered connection
    /// (`docs/design/protocol.md` §11-3: registration grants reachability,
    /// never authority) — it never opens sessions, so the only things to
    /// do here are answer a peer `Ping` and refuse every request-shaped
    /// frame with `UNSUPPORTED`, creating nothing either way. Runs until
    /// the connection ends, then removes this generation's table entry —
    /// unless a newer registration already did (the `remove` returning
    /// `None` is exactly that: [`Listen::finish_registration`] already
    /// emitted `"replaced"` for it, so this must not also emit `"lost"`).
    async fn drive_registered_session(
        self: Arc<Self>,
        mut session: Session,
        name: String,
        fingerprint: String,
        generation: u64,
    ) {
        loop {
            match session.next_control().await {
                Ok(Some(ControlIn::Ping { request_id })) => {
                    if session.send_pong(request_id).await.is_err() {
                        break;
                    }
                }
                Ok(Some(ControlIn::Request { request_id })) => {
                    if session.reject_unsupported(request_id).await.is_err() {
                        break;
                    }
                }
                // The controller has nothing to react to on either of
                // these — it opened nothing, so no `SessionEvent` is ever
                // its own, and it never sends a `Ping` of its own on this
                // connection (Step 4 adds that liveness driver).
                Ok(Some(ControlIn::Event(_))) | Ok(Some(ControlIn::Pong)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        let still_live = self
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(name.clone(), generation))
            .is_some();
        if still_live {
            RegistrationEvent {
                event: "lost",
                host: &name,
                fingerprint: &fingerprint,
                generation: Some(generation),
            }
            .emit();
        }
    }
}

/// How much of a peer-controlled `offered_name` the `denied` diagnostic
/// ever echoes. This runs before [`registry::Registry::resolve_name`]'s own
/// shape check (`wire::valid_host_name`, `<=64` bytes) has necessarily
/// rejected it — a peer can send an arbitrarily large `offered_name` and
/// have it reach this stderr line on its way to being refused, so the
/// diagnostic bounds it itself rather than trusting a check it runs ahead
/// of (adversarial review finding).
const OFFERED_NAME_DIAG_MAX_CHARS: usize = 128;

/// The `host` field for a `"denied"` [`RegistrationEvent`]: `"-"` for
/// empty, otherwise `offered_name` truncated (on a `char` boundary) to
/// [`OFFERED_NAME_DIAG_MAX_CHARS`].
fn diag_host(offered_name: &str) -> &str {
    if offered_name.is_empty() {
        return "-";
    }
    match offered_name.char_indices().nth(OFFERED_NAME_DIAG_MAX_CHARS) {
        Some((cut, _)) => &offered_name[..cut],
        None => offered_name,
    }
}

/// The tracing target every `qsh listen` registration diagnostic carries
/// (`docs/CLI.md` §6.13: "structured diagnostic … one-line JSON … no
/// payload/token fields"). Mirrors [`crate::telemetry::TARGET`]'s
/// contract — the message *is* the JSON.
pub const TARGET: &str = "qsh::reverse";

/// One `registered`/`denied`/`replaced`/`lost` line
/// (`docs/design/protocol.md` §11-2/§11-4's vocabulary — `expired`/`retry`
/// are Step 4). Fields are exactly `event`/`host`/`fingerprint`/
/// `generation`: no payload, no token, matching the audit record's own
/// structural-only discipline (`docs/design/architecture.md` §6).
struct RegistrationEvent<'a> {
    event: &'static str,
    host: &'a str,
    fingerprint: &'a str,
    /// Absent when nothing was ever assigned one (`"denied"` before a name
    /// resolved far enough to reach [`Registry::admit`]).
    generation: Option<u64>,
}

impl RegistrationEvent<'_> {
    /// Compact JSON, no trailing newline, keys in a fixed order — same
    /// discipline as [`crate::telemetry::RecoveryReport::to_json_line`].
    fn to_json_line(&self) -> String {
        let host = serde_json::Value::String(self.host.to_string());
        let fingerprint = serde_json::Value::String(self.fingerprint.to_string());
        match self.generation {
            Some(generation) => format!(
                r#"{{"event":"{}","host":{host},"fingerprint":{fingerprint},"generation":{generation}}}"#,
                self.event,
            ),
            None => format!(
                r#"{{"event":"{}","host":{host},"fingerprint":{fingerprint}}}"#,
                self.event,
            ),
        }
    }

    /// Emit the record on [`TARGET`] at `INFO`. The typed fields ride
    /// along for a structural tracing consumer; the message is the exact
    /// JSON line a stderr-reading campaign script parses whole.
    fn emit(&self) {
        tracing::info!(
            target: TARGET,
            event = self.event,
            host = self.host,
            fingerprint = self.fingerprint,
            generation = self.generation,
            "{}",
            self.to_json_line()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_precedence_flag_then_config_then_default() {
        let mut config = Config::default();
        assert_eq!(
            resolve_bind(None, &config).unwrap(),
            crate::serve::DEFAULT_BIND.parse::<SocketAddr>().unwrap()
        );
        config.listen.bind = Some("127.0.0.1:5001".into());
        assert_eq!(
            resolve_bind(None, &config).unwrap(),
            "127.0.0.1:5001".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind(Some("127.0.0.1:6001"), &config).unwrap(),
            "127.0.0.1:6001".parse::<SocketAddr>().unwrap()
        );
        let err = resolve_bind(Some("not an address"), &config).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn diag_host_bounds_an_oversized_offered_name() {
        assert_eq!(diag_host(""), "-");
        assert_eq!(diag_host("widget"), "widget");
        let huge = "a".repeat(10_000);
        let bounded = diag_host(&huge);
        assert_eq!(bounded.chars().count(), OFFERED_NAME_DIAG_MAX_CHARS);
    }

    #[test]
    fn registration_event_json_line_has_the_documented_field_set() {
        let with_generation = RegistrationEvent {
            event: "registered",
            host: "personal-mac",
            fingerprint: "sha256:abc",
            generation: Some(0),
        }
        .to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&with_generation).unwrap();
        assert_eq!(parsed["event"], "registered");
        assert_eq!(parsed["host"], "personal-mac");
        assert_eq!(parsed["fingerprint"], "sha256:abc");
        assert_eq!(parsed["generation"], 0);

        let without_generation = RegistrationEvent {
            event: "denied",
            host: "-",
            fingerprint: "sha256:abc",
            generation: None,
        }
        .to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&without_generation).unwrap();
        assert_eq!(parsed["event"], "denied");
        assert!(parsed.get("generation").is_none());
    }

    #[tokio::test]
    async fn listen_wires_device_name_and_starts_with_no_live_connections() {
        let registry = Registry::new(Arc::new(crate::broker::TestClock::new()), false);
        let listen = Listen::new(
            registry,
            Arc::new(AllowAllPinned),
            Arc::new(crate::audit::NullAuditSink),
            "hermes",
        );
        assert_eq!(listen.local_hello().device_name, "hermes");
        assert!(listen.local_hello().reverse.is_none());
        assert_eq!(listen.live_connections(), 0);
        assert!(listen.registry().snapshot().is_empty());
    }

    /// `docs/CLI.md` §6.13's Windows gate, mechanically: `run_listen`
    /// refuses on every non-unix target before it ever touches its
    /// arguments (module docs on [`windows_unsupported`]), so the
    /// identity/paths/config below are throwaway. This is the positive
    /// Windows-leg assertion `PLAN.md` Step 3 (d) owes ("Windows leg의
    /// nextest green … 나머지가 컴파일·통과") — a real `#[tokio::test]` that
    /// runs and passes on the Windows CI leg, not just an absence of a
    /// compile error there.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn run_listen_is_unsupported_on_non_unix() {
        let identity = LoadedIdentity {
            identity: crate::identity::Identity {
                device_id: "device".into(),
                fingerprint: qsh_transport::Fingerprint::of_spki_der(&[]),
                key_store: qsh_proto::KeyStoreKind::File,
                created_at: "2026-01-01T00:00:00Z".into(),
                cert_der: Vec::new(),
            },
            local: qsh_transport::LocalIdentity {
                cert_chain: Vec::new(),
                key_pkcs8_der: Vec::new(),
            },
        };
        let paths = Paths::new("unused-config", "unused-state");
        let err = run_listen(
            &paths,
            &Config::default(),
            identity,
            None,
            |_addr| {},
            std::future::pending::<()>(),
        )
        .await
        .expect_err("non-unix must refuse to run");
        assert_eq!(err.code, ErrorCode::Unsupported);
    }
}
