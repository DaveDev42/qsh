//! The typed operation layer: the single API surface the CLI, `--json`
//! renderer and (from M6) the MCP adapter all call through. See
//! `docs/CLI.md` §11 — frontends must not reimplement business logic, they
//! only translate an [`Ops`] call into their own presentation.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use qsh_proto::{
    BuildInfo, ErrorCode, IdentityInitData, IdentityInitReq, KeyStoreMode, SchemaData,
    TrustAcceptData, TrustAcceptReq, TrustAddData, TrustAddReq, TrustInviteData, TrustInviteReq,
    TrustListData, TrustRemoveData, VersionData,
};
use qsh_transport::{DialError, Dialer, Fingerprint, StaticTrust};

use crate::config::{Config, Paths, now_rfc3339};
use crate::hosts::HostsFile;
use crate::identity::LoadedIdentity;
use crate::trust::{SharedTrustStore, TrustStore};

pub mod acl;
pub mod cert;
pub mod doctor;
pub mod exec;
pub mod host;
pub mod session;
pub mod tunnel;

pub use acl::AclCheckOp;
pub use cert::{CertInitOp, CertIssueOp};
pub use doctor::DoctorOp;
pub use exec::{ExecRunOp, ExecRunOutput, ExecStdin};
pub use host::{HostGetOp, HostListOp, HostRoute};
pub use session::{
    AttachHandle, DetachFlush, RecoveryConfig, SESSION_WRITE_MAX, SessionAttachOp,
    SessionAttachStream, SessionCloseOp, SessionGetOp, SessionListOp, SessionOpenOp, SessionReadOp,
    SessionReadOutput, SessionReader, SessionRef, SessionResizeOp, SessionWriteOp,
    make_session_ref, parse_session_ref,
};
pub use tunnel::{
    TunnelCloseOp, TunnelHold, TunnelListOp, TunnelOpenOp, dynamic_forward_unsupported,
    parse_local_forwards, parse_remote_forwards,
};

/// Everything a remote call needs to reach a pinned host: our identity,
/// the trust evaluator, and where to dial.
pub(crate) struct PeerTarget {
    /// This device's identity and private key.
    pub identity: LoadedIdentity,
    /// The trust store as the transport's evaluator.
    pub trust: Arc<SharedTrustStore>,
    /// `host:port` recorded for the peer.
    pub address: String,
    /// SNI value for the dial (see [`server_name_for`]).
    pub server_name: String,
}

/// Where `Ops::connect`/`connect_target` (`crate::ops::session`) actually
/// reach `host` through — the dial-time counterpart of
/// [`host::HostRoute`], resolved by [`Ops::resolve_route`] (`PLAN.md` M3
/// Step 6). `HostRoute` is what `host.get`/the human renderer *display*;
/// `PeerRoute` is what a connection is actually built over, carrying the
/// identity/trust material `HostRoute` deliberately does not (routing and
/// display share one decision, `host::resolve_route`, but only one of
/// their two callers ever needs a private key in hand).
pub(crate) enum PeerRoute {
    /// Dial the peer directly over QUIC (forward route).
    Forward(PeerTarget),
    /// Relay through this machine's resident `qsh listen` daemon (reverse
    /// route).
    Reverse(LocalRoute),
}

/// Everything a reverse dial needs: which daemon (by its localctl socket)
/// and which of its registered hosts (by the alias name `LocalHello.host`
/// carries) to ask for.
///
/// Deliberately **not** carrying the fingerprint [`host::HostRoute::Reverse`]
/// observed at resolution time — [`crate::ops::session::Connected::peer_fingerprint`]
/// (the ADR-0007 presentation-condition input) must be the value *this*
/// connection's own `LocalHelloAck` reports, not a possibly-stale one read
/// moments earlier during routing (`docs/design/protocol.md` §11-3, `PLAN.md`
/// M3 Step 6's "Connected::peer_fingerprint() on the reverse leg returns
/// LocalHelloAck.peer_fingerprint" rule).
pub(crate) struct LocalRoute {
    /// The host alias to ask the daemon for (`LocalHello.host`).
    // Only ever read by `ops/session.rs`'s `dial_reverse`, `#[cfg(unix)]`
    // (localctl/UDS is unix-only) — `resolve_route` below still
    // *constructs* a `LocalRoute` on every platform (it mirrors
    // `HostRoute::Reverse` unconditionally), so the fields are genuinely
    // unread, not unconstructed, on Windows.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub host: String,
    /// The daemon's localctl socket path.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub socket: std::path::PathBuf,
}

/// How long the `trust.add` fingerprint probe waits for a handshake before
/// reporting `CONNECTION_FAILED`. Deliberately shorter than the transport's
/// default dial timeout: this dial is expected to fail (we trust nothing),
/// so it must not hold a human or a test hostage.
const PROBE_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Marker trait for a single typed operation.
///
/// `COMMAND` is the dotted-form command name used as the `command` field in
/// the `qsh.cli/v1` envelope and as the audit/ACL join key (e.g.
/// `"version.get"`, `"session.open"`).
pub trait Operation {
    /// Dotted-form command name, e.g. `"version.get"`.
    const COMMAND: &'static str;
}

/// Error type returned by every operation. Carries everything the
/// `qsh.cli/v1` error envelope needs (`docs/CLI.md` §3.2) plus a structured
/// `details` payload for automation.
#[derive(Debug, Clone, PartialEq)]
pub struct OpError {
    /// Shared error vocabulary code.
    pub code: ErrorCode,
    /// Human-readable explanation. Automation must not parse this.
    pub message: String,
    /// Whether retrying the same request might succeed.
    pub retryable: bool,
    /// Structured, machine-readable detail payload. `Value::Null` when
    /// there is nothing to add beyond `code`/`message`.
    pub details: serde_json::Value,
}

impl OpError {
    /// Construct an [`OpError`] with `retryable` defaulted from
    /// [`ErrorCode::default_retryable`] and empty `details`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let retryable = code.default_retryable();
        Self {
            code,
            message: message.into(),
            retryable,
            details: serde_json::Value::Null,
        }
    }

    /// Override the default retryability.
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Attach a structured `details` payload.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl From<ErrorCode> for OpError {
    /// Build an [`OpError`] whose message is just the code's own display
    /// string. Callers that have a better message should use
    /// [`OpError::new`] instead; this exists for quick propagation of a
    /// bare code (e.g. from a lower layer that only has the code).
    fn from(code: ErrorCode) -> Self {
        let message = code.to_string();
        OpError::new(code, message)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for OpError {}

/// The `version.get` operation.
pub struct VersionOp;

impl Operation for VersionOp {
    const COMMAND: &'static str = "version.get";
}

/// The `schema.get` operation.
pub struct SchemaOp;

impl Operation for SchemaOp {
    const COMMAND: &'static str = "schema.get";
}

/// The `capabilities.get` operation.
pub struct CapabilitiesOp;

impl Operation for CapabilitiesOp {
    const COMMAND: &'static str = "capabilities.get";
}

/// The `identity.init` operation (`qsh init`).
pub struct IdentityInitOp;

impl Operation for IdentityInitOp {
    const COMMAND: &'static str = "identity.init";
}

/// The `trust.add` operation.
pub struct TrustAddOp;

impl Operation for TrustAddOp {
    const COMMAND: &'static str = "trust.add";
}

/// The `trust.invite` operation (ADR-0002, `PLAN.md` M7 Step 4).
pub struct TrustInviteOp;

impl Operation for TrustInviteOp {
    const COMMAND: &'static str = "trust.invite";
}

/// The `trust.accept` operation (ADR-0002, `PLAN.md` M7 Step 4).
pub struct TrustAcceptOp;

impl Operation for TrustAcceptOp {
    const COMMAND: &'static str = "trust.accept";
}

/// The `trust.list` operation.
pub struct TrustListOp;

impl Operation for TrustListOp {
    const COMMAND: &'static str = "trust.list";
}

/// The `trust.remove` operation.
pub struct TrustRemoveOp;

impl Operation for TrustRemoveOp {
    const COMMAND: &'static str = "trust.remove";
}

/// Façade over every typed operation. This is the *only* entry point
/// frontends (`qsh-cli`'s human/JSON renderers, and later the MCP adapter)
/// are allowed to call into `qsh-core` through.
///
/// One `Ops` is bound to one pair of config/state directories, so a test —
/// or a `QSH_CONFIG_DIR` override — redirects the whole tree at once.
#[derive(Debug, Clone)]
pub struct Ops {
    paths: Paths,
    recovery: session::RecoveryConfig,
    /// Every tunnel this process is holding via [`Ops::tunnel_open_and_hold`]
    /// (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2) — `Arc`-backed so every
    /// clone of this `Ops` shares the same table (`tunnel::TunnelHoldRegistry`'s
    /// own doc).
    tunnel_holds: tunnel::TunnelHoldRegistry,
    /// The Tokio runtime [`session::Connected::connect_target`]/
    /// [`session::Connected::connect_reverse`] dial and block on, shared
    /// across every clone of this `Ops` and every pull on it instead of
    /// built-and-torn-down per call (`PLAN.md` M7 Step 7-2 ①: a single
    /// abandoned pull used to cost 11 threads — a whole `num_cpus`-sized
    /// `Builder::new_multi_thread()` plus a `lookup_host` blocking thread —
    /// on top of its own QUIC endpoint/socket; measured 11.05
    /// threads/5.00 fds per in-flight pull before this change).
    ///
    /// **Lazy by construction**: nothing builds this until the first
    /// `connect*` call reaches [`Self::connect_runtime`], so a purely local
    /// op (`qsh version`, `qsh trust list`, …) never pays for it. `Arc<
    /// OnceLock<Arc<SharedRuntime>>>`, not a bare `OnceLock`, for two
    /// reasons — the outer `Arc` lets every `Ops::clone()` share the one
    /// cell (a `static OnceLock` was considered and rejected: it would
    /// outlive `Ops` and break test isolation, since `qsh-testkit` builds
    /// and drops many `Ops` instances with different `Paths` per test), and
    /// the inner `Arc<SharedRuntime>` lets a [`session::Connected`] hold an
    /// owned handle that outlives the `&Ops` borrow which created it — a
    /// bare `&Runtime` borrowed from the cell could not be stored across
    /// `connect_target`'s return. [`SharedRuntime`] (rather than a bare
    /// `Runtime`) is what makes the last such `Arc` safe to drop from
    /// literally anywhere — see its own doc.
    ///
    /// Never reused for the `qsh mcp` server's own long-lived runtime
    /// ([`crate`]'s caller wires that up separately in `qsh-cli`): sharing
    /// one runtime's blocking-thread pool between "the server accepting MCP
    /// requests" and "every in-flight pull's blocking work" was measured to
    /// deadlock around ~256 concurrent pulls, because each pull both
    /// occupies a blocking-pool thread (the caller's `spawn_blocking`) and
    /// then asks the *same* pool for another one (`tokio::net::lookup_host`)
    /// — two independent runtimes keep the two demands on separate pools.
    connect_runtime: Arc<OnceLock<Arc<SharedRuntime>>>,
}

/// A [`tokio::runtime::Runtime`] whose `Drop` never blocks.
///
/// The plain `Runtime::drop` waits for every worker thread to park before
/// returning, and that wait **panics** — "Cannot drop a runtime in a
/// context where blocking is not allowed" — if it happens to run on a
/// thread that is, at that moment, itself executing inside some async
/// task (any runtime's, not necessarily this one's). [`Ops::connect_runtime`]
/// is shared and reference-counted, so its very last `Arc` can be dropped
/// almost anywhere — in particular, `qsh-testkit`'s loopback fixtures build
/// an `Ops` inside a `#[tokio::test]` and drop it at the end of that same
/// async test function, which is exactly such a context (found by this
/// step's own nextest run: `qsh-testkit::reverse_attach
/// detaching_leaves_the_session_running_and_a_reattach_replays_the_retained_ring`
/// failed with precisely that panic before this wrapper existed). Wrapping
/// every shared handle in this type instead and routing its `Drop` through
/// [`tokio::runtime::Runtime::shutdown_background`] — documented by tokio
/// itself as the non-blocking teardown, safe to call from inside another
/// runtime — fixes it generally, for every current and future caller,
/// rather than special-casing the one call site the test happened to
/// exercise.
#[derive(Debug)]
pub(crate) struct SharedRuntime(Option<tokio::runtime::Runtime>);

impl std::ops::Deref for SharedRuntime {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &tokio::runtime::Runtime {
        self.0.as_ref().expect("runtime is only taken by Drop")
    }
}

impl Drop for SharedRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

impl Ops {
    /// Bind operations to explicit directories.
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            recovery: session::RecoveryConfig::default(),
            tunnel_holds: tunnel::new_tunnel_hold_registry(),
            connect_runtime: Arc::new(OnceLock::new()),
        }
    }

    /// The shared dial runtime, building it on first use.
    ///
    /// `std::sync::OnceLock::get_or_try_init` is still unstable (tracking
    /// issue 109737), so a fallible build cannot use `get_or_init`
    /// directly; this hand-rolls the same double-checked shape:
    /// [`OnceLock::get`] first (the fast, already-built path every pull
    /// after the first takes), and only on a miss does it build a runtime
    /// and race [`OnceLock::set`] to install it. Losing that race is
    /// harmless — the loser's freshly built, never-used runtime is simply
    /// dropped, which [`SharedRuntime`]'s own `Drop` makes safe regardless
    /// of which context that drop happens to run in.
    pub(crate) fn connect_runtime(&self) -> Result<Arc<SharedRuntime>, OpError> {
        if let Some(runtime) = self.connect_runtime.get() {
            return Ok(Arc::clone(runtime));
        }
        let built = Arc::new(SharedRuntime(Some(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|err| OpError::new(ErrorCode::Internal, format!("runtime: {err}")))?,
        )));
        match self.connect_runtime.set(Arc::clone(&built)) {
            Ok(()) => Ok(built),
            Err(_) => Ok(Arc::clone(
                self.connect_runtime
                    .get()
                    .expect("just set by the winning thread"),
            )),
        }
    }

    /// Override how a live attach survives a dead path
    /// ([`session::RecoveryConfig`]).
    ///
    /// The defaults are what the product ships and what the M2 recovery
    /// gate measures; this exists so a caller can turn a half of it off —
    /// which is also how "nothing depends on migration succeeding"
    /// (`docs/design/protocol.md` §2) is demonstrated rather than asserted.
    #[must_use]
    pub fn with_recovery(mut self, recovery: session::RecoveryConfig) -> Self {
        self.recovery = recovery;
        self
    }

    /// Bind operations to the directories resolved from the environment
    /// ([`Paths::from_env`]).
    pub fn from_env() -> Result<Self, OpError> {
        Ok(Self::new(Paths::from_env()?))
    }

    /// The config/state directories these operations act on.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Load `config.toml` (missing = defaults).
    pub fn config(&self) -> Result<Config, OpError> {
        Config::load(&self.paths)
    }

    /// Report this build's version and the wire/CLI schemas it understands.
    ///
    /// `build.commit` (`docs/ROADMAP.md` M7 감사 개정 ③) is whatever
    /// `option_env!("QSH_BUILD_COMMIT")` captured when this binary was
    /// *compiled* — not read from the environment at call time — so a
    /// local build with no such variable set reports no `build` field at
    /// all rather than a fabricated or empty one (`PLAN.md` M7 §4.1 #1).
    pub fn version(&self) -> Result<VersionData, OpError> {
        Ok(VersionData {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
            build: option_env!("QSH_BUILD_COMMIT").map(|commit| BuildInfo {
                commit: commit.to_string(),
            }),
        })
    }

    /// `schema.get` (`docs/CLI.md` §6.10) — the JSON Schema of the
    /// `qsh.cli/v1` envelope and every command's `data` payload, generated
    /// straight from `qsh_proto::schema`: the exact same function
    /// `crates/qsh-cli/tests/fixtures.rs` validates every golden fixture
    /// against (`docs/design/testing.md` L6), so this and the fixture
    /// validator cannot drift apart.
    pub fn schema(&self) -> Result<SchemaData, OpError> {
        let commands = qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS
            .iter()
            .map(|&command| {
                let schema = qsh_proto::schema::cli_v1_data_schema(command).unwrap_or_else(|| {
                    panic!(
                        "CLI_V1_SCHEMA_COMMANDS names {command:?} with no cli_v1_data_schema arm"
                    )
                });
                (command.to_string(), schema.to_value())
            })
            .collect();
        Ok(SchemaData {
            schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
            envelope: qsh_proto::schema::cli_v1_envelope_schema().to_value(),
            commands,
        })
    }

    // -----------------------------------------------------------------
    // identity
    // -----------------------------------------------------------------

    /// `identity.init` — create this device's identity if it does not exist
    /// (idempotent: an existing identity comes back with `created: false`).
    ///
    /// Key-store selection: the request wins over `config.toml`
    /// `[identity].key_store`, which wins over `auto`.
    pub fn identity_init(&self, req: IdentityInitReq) -> Result<IdentityInitData, OpError> {
        let mode = match req.key_store {
            Some(mode) => mode,
            None => self
                .config()?
                .identity
                .key_store
                .unwrap_or(KeyStoreMode::Auto),
        };
        crate::identity::init(&self.paths, mode)
    }

    /// This device's identity plus its private key, or `None` before
    /// `qsh init`.
    ///
    /// **Runtime caveat:** with a platform key store this blocks on the OS
    /// credential store — call it outside a tokio runtime, or from
    /// `spawn_blocking` (see [`crate::identity::load`]).
    pub fn load_identity(&self) -> Result<Option<LoadedIdentity>, OpError> {
        crate::identity::load(&self.paths)
    }

    /// The shared, reload-on-change trust store to inject into the
    /// transport as a [`qsh_transport::TrustEvaluator`].
    pub fn open_trust(&self) -> Result<Arc<SharedTrustStore>, OpError> {
        SharedTrustStore::open(self.paths.trust_file())
    }

    // -----------------------------------------------------------------
    // trust
    // -----------------------------------------------------------------

    /// `trust.add` — pin a peer.
    ///
    /// With `--fingerprint` the peer is pinned **without connecting**
    /// (provisioning-friendly, `docs/CLI.md` §6.11). Without one, the peer
    /// is dialed once to observe its fingerprint and the result is always a
    /// `TRUST_REQUIRED` error carrying `details.observed_fingerprint` and
    /// `details.address`: the caller (human prompt or automation) verifies
    /// that value out of band and re-calls with `--fingerprint`. Nothing is
    /// ever pinned on the strength of what the network said.
    ///
    /// Re-adding an already-pinned name is idempotent, with one deliberate
    /// exception (`PLAN.md` M7 Step 2 decision B, `TrustStore::add_peer`'s
    /// own doc): the *same* fingerprint with a *different* `--address`
    /// overwrites the stored address in place (`data.updated: true`,
    /// `data.created` stays `false`) instead of being a no-op — the M6
    /// mobility campaign's backlog item. A *different* fingerprint is still
    /// a hard no-op on the whole entry; re-binding an identity is `trust
    /// remove` then `trust add`, never a side effect of a repeated call.
    pub fn trust_add(&self, req: TrustAddReq) -> Result<TrustAddData, OpError> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "peer name must not be empty",
            ));
        }

        let fingerprint = match req.fingerprint.as_deref() {
            Some(text) => text
                .parse::<Fingerprint>()
                .map_err(|err| OpError::new(ErrorCode::InvalidArgument, err.to_string()))?,
            None => {
                let Some(address) = req.address.as_deref() else {
                    return Err(OpError::new(
                        ErrorCode::InvalidArgument,
                        "--address is required to observe a fingerprint",
                    ));
                };
                let observed = self.probe_fingerprint(address)?;
                return Err(OpError::new(
                    ErrorCode::TrustRequired,
                    format!(
                        "peer {address} is not trusted; verify the fingerprint and re-run with \
                         --fingerprint"
                    ),
                )
                .with_retryable(false)
                .with_details(serde_json::json!({
                    "observed_fingerprint": observed.to_string(),
                    "address": address,
                })));
            }
        };

        let path = self.paths.trust_file();
        // Whole load→mutate→save under lock, not just the write — a
        // concurrent `qsh serve` pairing response or another CLI process
        // racing this same read-modify-write must not have its change
        // silently discarded (`TrustStore::lock`'s own doc, `PLAN.md` M7
        // Step 7-1).
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let (peer, created, updated) =
            store.add_peer(name, req.address, fingerprint, now_rfc3339());
        if created || updated {
            store.save(&path)?;
        }
        Ok(TrustAddData {
            peer,
            created,
            updated: (!created).then_some(updated),
        })
    }

    /// `trust.list` — every pinned peer, in store order.
    pub fn trust_list(&self) -> Result<TrustListData, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        Ok(TrustListData {
            peers: store.peers().to_vec(),
        })
    }

    /// `trust.remove` — unpin a peer. Removing an unknown name is not an
    /// error (`removed: false`, idempotent).
    pub fn trust_remove(&self, name: &str) -> Result<TrustRemoveData, OpError> {
        let path = self.paths.trust_file();
        // See `trust_add`'s identical comment — whole cycle under lock.
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let removed = store.remove(name);
        if removed {
            store.save(&path)?;
        }
        Ok(TrustRemoveData {
            name: name.to_string(),
            removed,
        })
    }

    /// `trust.invite` — mint a one-time pairing invite (ADR-0002, `PLAN.md`
    /// M7 Step 4).
    ///
    /// The raw secret exists only for the lifetime of this call: it is
    /// generated, hashed into `invites.toml` (never the raw bytes —
    /// `crate::trust::pairing`'s own module doc), rendered as the Crockford
    /// Base32 display code, and zeroized on drop before this returns. `qsh
    /// serve`'s own `SharedInviteStore` picks up the freshly written invite
    /// on its very next check, without a restart (Step 2's content-based
    /// reload, invariant #6). `accept_command` is the exact command line to
    /// hand the other party — the code alone carries no address (`PLAN.md`
    /// M7 §4.1 #7), so this is the only place that pairing is complete.
    pub fn trust_invite(&self, _req: TrustInviteReq) -> Result<TrustInviteData, OpError> {
        let secret = crate::trust::pairing::generate_secret();
        let now = std::time::SystemTime::now();
        let path = self.paths.invites_file();
        // Whole load→mutate→save under lock, not just the write — closes
        // report F-9's residual lost-update window against a concurrent
        // `qsh serve` redeeming a different invite at the same time
        // (`InviteStore::lock`'s own doc, `PLAN.md` M7 Step 7-1).
        let _lock = crate::trust::pairing::InviteStore::lock(&path)?;
        let mut store = crate::trust::pairing::InviteStore::load(&path)?;
        store.prune(now);
        let (_created_at, expires_at) = store.add(secret.as_slice(), now);
        store.save(&path)?;

        let code = qsh_proto::pairing::encode_invite_code(&secret);
        Ok(TrustInviteData {
            accept_command: format!("qsh trust accept <address> {code}"),
            code,
            expires_at,
        })
    }

    /// `trust.accept <address> <code>` — complete a pairing exchange with
    /// `qsh trust invite`'s counterpart (ADR-0002, `PLAN.md` M7 Step 4).
    ///
    /// Dials `address` with a trust evaluator that accepts *any*
    /// certificate ([`crate::pairing::AcceptAnyForPairing`], report §B3) —
    /// pairing's real authentication is possession of `code`'s secret,
    /// proven over a TLS-exporter-bound channel
    /// ([`crate::pairing::accept`]), never the TLS identity presented. Only
    /// once the responder's own proof has verified (never on the strength
    /// of a reply merely arriving — report §B13) is the responder pinned,
    /// using this connection's own observed fingerprint, via the same
    /// [`TrustStore::add_peer`] path `qsh trust add` uses. A name collision
    /// here (the responder's self-reported name already pinned locally
    /// under a *different* fingerprint) fails loudly with `SESSION_CONFLICT`
    /// — unlike `trust add`'s own established silent no-op on the same
    /// underlying case (`TrustStore::add_peer`'s own doc; left untouched).
    ///
    /// **Runtime caveat:** loads the identity synchronously — call it
    /// outside a tokio runtime (see [`Self::load_identity`]).
    pub fn trust_accept(&self, req: TrustAcceptReq) -> Result<TrustAcceptData, OpError> {
        let secret = qsh_proto::pairing::parse_invite_code(&req.code).map_err(|err| {
            OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
        })?;

        let Some(loaded) = self.load_identity()? else {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "no device identity in {}; run qsh init first",
                    self.paths.config_dir.display()
                ),
            )
            .with_retryable(false));
        };
        let device_name = loaded.identity.device_id.clone();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("failed to start an async runtime: {err}"),
                )
                .with_retryable(false)
            })?;

        let dialer = Dialer::new(loaded.local, Arc::new(crate::pairing::AcceptAnyForPairing));
        let server_name = server_name_for(&req.address);
        let dial_address = req.address.clone();

        let outcome = runtime.block_on(async move {
            let socket = resolve_one(&dial_address).await?;
            let dialed = dialer
                .dial(socket, &server_name)
                .await
                .map_err(|err| classify_pairing_dial_failure(err, &dial_address))?;
            let success = crate::pairing::accept(&dialed.connection, &device_name, &secret)
                .await
                .map_err(classify_pairing_exchange_failure)?;
            let observed_fp = dialed.connection.peer_fingerprint().ok_or_else(|| {
                OpError::new(
                    ErrorCode::Internal,
                    "paired connection reported no peer certificate fingerprint",
                )
                .with_retryable(false)
            })?;
            dialed.connection.close(0, b"paired");
            Ok::<_, OpError>((success, observed_fp))
        });
        runtime.shutdown_timeout(Duration::from_millis(200));
        let (success, observed_fp) = outcome?;

        let path = self.paths.trust_file();
        // See `trust_add`'s identical comment — whole cycle under lock.
        // Acquired only now, after the network dial above has already
        // completed: the critical section stays a small local file
        // rewrite, never a network wait.
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        // Report F-6: pin with the address this exchange just dialed
        // successfully (`req.address`, the same meaning `trust add
        // --address` gives it) rather than `None` — otherwise `qsh exec
        // <peer>` right after a successful pairing would come back
        // `HOST_NOT_FOUND` (§6.1/§6.8: an address-less pin is never a
        // dial-address candidate), directly undercutting ADR-0002's SC1
        // (5-minute pairing to first connection).
        let (peer, created, updated) = store.add_peer(
            success.peer_device_name.clone(),
            Some(req.address.clone()),
            observed_fp,
            now_rfc3339(),
        );
        if !created && !updated && peer.fingerprint != observed_fp.to_string() {
            return Err(OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "paired with {}, but {:?} is already pinned locally under a different \
                     identity; rename or remove the conflicting entry and retry",
                    req.address, success.peer_device_name
                ),
            )
            .with_retryable(false));
        }
        if created || updated {
            store.save(&path)?;
        }
        Ok(TrustAcceptData {
            peer,
            created,
            updated: (!created).then_some(updated),
        })
    }

    /// Resolve `host` to a dial target: loads the identity (`CONFIG_ERROR`
    /// before `qsh init`) and resolves an address via `hosts.toml`
    /// layered over the trust store's pinned peers (`PLAN.md` M7 Step 3,
    /// §4.1 #4 — `hosts.toml` first, trust-store pin as fallback;
    /// `HOST_NOT_FOUND` when neither source has one). Identity/trust is
    /// still decided solely by the trust store: this only changes where
    /// the *address* comes from.
    ///
    /// **Runtime caveat:** loads the identity synchronously — call it
    /// outside a tokio runtime (see [`Ops::load_identity`]).
    pub(crate) fn resolve_peer(&self, host: &str) -> Result<PeerTarget, OpError> {
        let identity = self.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
        })?;
        let trust = self.open_trust()?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let (address, server_name) = resolve_peer_address(&trust.snapshot(), &hosts, host)?;
        Ok(PeerTarget {
            identity,
            trust,
            address,
            server_name,
        })
    }

    /// Resolve `host` to a [`PeerRoute`] — the routing decision
    /// [`Self::resolve_host_route`] already makes (live reverse
    /// registration beats a forward pin), turned into what
    /// `Ops::connect`/`connect_target` (`crate::ops::session`) need to
    /// actually build a connection over either link (`PLAN.md` M3 Step 6).
    ///
    /// **Sync, and not callable from inside a running Tokio runtime** —
    /// same caveat as [`Self::resolve_peer`] (identity loads synchronously
    /// on the forward branch, which a platform key store will not hand
    /// over from inside one) and [`Self::resolve_host_route`] (whose own
    /// doc this delegates to). Called from `Ops::connect`/`connect_target`
    /// *before* either builds its own runtime for the dial — sequential,
    /// not nested, runtimes: [`Self::resolve_host_route`]'s throwaway
    /// probe runtime is built and torn down here, before the dial's own
    /// multi-thread runtime exists.
    pub(crate) fn resolve_route(&self, host: &str) -> Result<PeerRoute, OpError> {
        match self.resolve_host_route(host)? {
            HostRoute::Forward { .. } => Ok(PeerRoute::Forward(self.resolve_peer(host)?)),
            HostRoute::Reverse { socket, .. } => Ok(PeerRoute::Reverse(LocalRoute {
                host: host.to_string(),
                socket,
            })),
        }
    }

    /// Dial `address` once with an empty trust store and report the
    /// fingerprint the peer presented.
    ///
    /// Because nothing is trusted, the handshake always ends in a local
    /// rejection — the observation is the *point* of the dial, and no
    /// usable connection is ever established. Used by `trust.add` and by
    /// the CLI's interactive pin prompt.
    pub fn probe_fingerprint(&self, address: &str) -> Result<Fingerprint, OpError> {
        // Load the identity *before* entering the runtime: a platform key
        // store blocks on the OS credential service.
        let Some(loaded) = self.load_identity()? else {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "no device identity in {}; run qsh init first",
                    self.paths.config_dir.display()
                ),
            )
            .with_retryable(false));
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("failed to start an async runtime: {err}"),
                )
                .with_retryable(false)
            })?;

        let dialer = Dialer::new(loaded.local, Arc::new(StaticTrust::empty()))
            .with_timeout(PROBE_DIAL_TIMEOUT);
        let server_name = server_name_for(address);

        runtime.block_on(async move {
            let socket = resolve_one(address).await?;
            match dialer.dial(socket, &server_name).await {
                // Unreachable in practice (an empty trust store rejects
                // every peer), but never leave a connection open.
                Ok(dialed) => {
                    let observed = dialed.observation().and_then(|o| o.fingerprint);
                    dialed.connection.close(0, b"probe");
                    observed.ok_or_else(|| {
                        OpError::new(
                            ErrorCode::Internal,
                            "peer accepted by an empty trust store".to_string(),
                        )
                        .with_retryable(false)
                    })
                }
                // The expected outcome: our (empty) trust store rejected
                // the peer, and the verifier recorded what it presented.
                Err(DialError::LocalRejected {
                    observed: Some(fingerprint),
                    ..
                }) => Ok(fingerprint),
                Err(err) => Err(classify_probe_failure(err, address)),
            }
        })
    }
}

/// Resolve `host:port` to its first socket address. `pub(crate)` — Step 3's
/// `qsh reverse` (`crate::reverse::target::run_reverse`) reuses this exact
/// resolution instead of a second copy of it, for the same reason
/// [`resolve_peer_address`] just below is split out.
pub(crate) async fn resolve_one(address: &str) -> Result<SocketAddr, OpError> {
    let mut addrs = tokio::net::lookup_host(address).await.map_err(|err| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            format!("failed to resolve {address}: {err}"),
        )
    })?;
    addrs.next().ok_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            format!("{address} resolved to no addresses"),
        )
    })
}

/// The `(address, server_name)` half of [`Ops::resolve_peer`] that touches
/// no identity — split out so a caller that already holds its own
/// [`LoadedIdentity`] can reuse the trust-store/`hosts.toml` lookup without
/// a second synchronous identity load of its own. `qsh reverse` (`PLAN.md`
/// M3 Step 3, `crate::reverse::target::run_reverse`/`dial_and_register`) is
/// that caller: it loads identity once, outside any runtime, ahead of a
/// reconnect loop that must not reopen the keystore per dial
/// (`docs/design/protocol.md` §11-4), so it cannot go through
/// [`Ops::resolve_peer`] itself (which always loads identity synchronously
/// — safe only when called before a runtime exists, per that method's own
/// doc).
///
/// Address resolution: `hosts.toml` layered over `trust`'s pinned peers,
/// via [`host::resolve_forward`] — the exact same decision
/// [`Ops::host_list`]/[`Ops::resolve_host_route`] make (`PLAN.md` M7 Step
/// 3, §4.1 #4). Identity/trust is unaffected: the fingerprint a dial
/// actually presents is still verified solely against `trust` at the TLS
/// layer ([`qsh_transport::TrustEvaluator::lookup_pin`] is fingerprint-
/// keyed across the whole store, not scoped to `host`) — `hosts.toml`
/// supplying an address for a name with no trust peer, or a different
/// address than trust's own pin, never changes *who* is allowed to answer.
pub(crate) fn resolve_peer_address(
    trust: &TrustStore,
    hosts: &HostsFile,
    host: &str,
) -> Result<(String, String), OpError> {
    let hosts_has_any = !hosts.entries().is_empty();
    // Message text is a frozen golden fixture
    // (`crates/qsh-cli/tests/fixtures/cli-v1/error.HOST_NOT_FOUND.json`,
    // via `qsh exec nowhere`) — kept byte-identical to the pre-M7-Step-3
    // wording even though the remedy it names (`qsh trust add`) is now
    // only one of two ways to fix this (the other being a `hosts.toml`
    // entry); fixtures are append-only, this is not an editable one.
    let entry = host::resolve_forward(trust.find(host), hosts.find(host), hosts_has_any)
        .ok_or_else(|| {
            OpError::new(
                ErrorCode::HostNotFound,
                format!(
                    "host {host:?} is not in the trust store; pin it with `qsh trust add {host} \
                     --address <host:port> --fingerprint sha256:...`"
                ),
            )
        })?;
    let server_name = server_name_for(&entry.address);
    Ok((entry.address, server_name))
}

/// SNI value for a dial. The verifier ignores it entirely
/// (`docs/design/protocol.md` §3), so this only needs to be a name rustls
/// will accept; the host part of the address is the most useful one for
/// packet captures.
fn server_name_for(address: &str) -> String {
    let host = match address.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => address,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        "qsh".to_string()
    } else {
        host.to_string()
    }
}

/// Turn a failed probe dial into the error the ops layer promises.
///
/// A *local* rejection with an observed fingerprint is the success case for
/// a probe and is handled by the caller; everything else is a genuine
/// failure. `AUTH_FAILED` details carry only a category — never a reason
/// that could leak trust-store contents (`docs/CLI.md` §6.11).
fn classify_probe_failure(err: DialError, address: &str) -> OpError {
    match err {
        DialError::LocalRejected {
            observed: Some(fingerprint),
            ..
        } => OpError::new(
            ErrorCode::TrustRequired,
            format!("peer {address} is not trusted"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({
            "observed_fingerprint": fingerprint.to_string(),
            "address": address,
        })),
        DialError::LocalRejected { observed: None, .. } => OpError::new(
            ErrorCode::AuthFailed,
            format!("could not read {address}'s certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "unverifiable_certificate"})),
        DialError::RemoteRejected => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address} rejected this device's certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "remote_rejected"})),
        DialError::Timeout(after) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} after {after:?}"),
        ),
        DialError::Connect(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot dial {address}: {err}"),
        ),
        DialError::Failed(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection to {address} failed: {err}"),
        ),
        DialError::Setup(err) => OpError::new(
            ErrorCode::Internal,
            format!("failed to build a client endpoint: {err}"),
        )
        .with_retryable(false),
    }
}

/// `trust.accept`'s own dial-failure classifier: unlike
/// [`classify_probe_failure`], the dialer here is
/// [`crate::pairing::AcceptAnyForPairing`] (accepts *any* fingerprint), so
/// a [`DialError::LocalRejected`] can only mean the peer's certificate
/// itself was structurally invalid (malformed, outside its validity
/// window — `qsh_transport::tls::verify_core`'s unconditional checks, which
/// run before any trust-evaluator branch), never "untrusted" — there is no
/// `observed_fingerprint` detail worth reporting since nothing was ever
/// evaluated against a fingerprint at all.
fn classify_pairing_dial_failure(err: DialError, address: &str) -> OpError {
    match err {
        DialError::LocalRejected { .. } => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address}'s certificate could not be verified"),
        )
        .with_retryable(false),
        DialError::RemoteRejected => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address} rejected this device's certificate"),
        )
        .with_retryable(false),
        DialError::Timeout(after) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} after {after:?}"),
        ),
        DialError::Connect(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot dial {address}: {err}"),
        ),
        DialError::Failed(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection to {address} failed: {err}"),
        ),
        DialError::Setup(err) => OpError::new(
            ErrorCode::Internal,
            format!("failed to build a client endpoint: {err}"),
        )
        .with_retryable(false),
    }
}

/// Turn a failed [`crate::pairing::accept`] exchange into the `OpError`
/// `trust.accept` reports. `Remote { code, .. }` is the common case — the
/// responder already picked one of `AUTH_FAILED`/`TRUST_REQUIRED`/
/// `SESSION_CONFLICT`/`INTERNAL` via its own `PairingError::as_wire_error`
/// (report §B7) and this just carries that verdict through unchanged. The
/// `NoMatch`/`Expired`/`AlreadyConsumed`/`PinCollision` arms are the
/// responder's own local-matching outcomes and are never constructed by
/// [`crate::pairing::accept`] itself (only by `respond`) — present here
/// only so the match stays exhaustive, matching this codebase's existing
/// style for structurally-unreachable-but-required arms.
fn classify_pairing_exchange_failure(err: crate::pairing::PairingError) -> OpError {
    use crate::pairing::PairingError as E;
    match err {
        E::Remote {
            code,
            message,
            retryable,
        } => OpError::new(code, message).with_retryable(retryable),
        E::NoMatch => OpError::new(ErrorCode::AuthFailed, err.to_string()).with_retryable(false),
        E::Expired => OpError::new(ErrorCode::TrustRequired, err.to_string()).with_retryable(false),
        E::AlreadyConsumed | E::PinCollision => {
            OpError::new(ErrorCode::SessionConflict, err.to_string()).with_retryable(false)
        }
        E::InvalidDeviceName { .. } => {
            OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
        }
        E::ResponderProofMismatch => {
            OpError::new(ErrorCode::AuthFailed, err.to_string()).with_retryable(false)
        }
        E::Timeout => OpError::new(ErrorCode::Timeout, err.to_string()),
        E::ClosedEarly | E::UnexpectedMessage | E::Stream(_) | E::Connection(_) => {
            OpError::new(ErrorCode::ConnectionFailed, err.to_string())
        }
        E::ExporterUnavailable => {
            OpError::new(ErrorCode::Internal, err.to_string()).with_retryable(false)
        }
        E::Store(op_err) => op_err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_proto::KeyStoreKind;

    fn temp_ops() -> (tempfile::TempDir, Ops) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        (dir, Ops::new(paths))
    }

    fn file_mode() -> IdentityInitReq {
        IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        }
    }

    #[test]
    fn version_reports_schemas_and_own_version() {
        let (_guard, ops) = temp_ops();
        let data = ops.version().unwrap();
        assert_eq!(data.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(data.schemas, vec!["qsh.cli/v1", "qsh.event/v1"]);
    }

    /// `PLAN.md` M7 Step 7-2 ①: the shared dial runtime must be **lazy** —
    /// nothing may build it until a `connect*` call actually reaches
    /// [`Ops::connect_runtime`], or a purely local command (`qsh version`,
    /// tested here) would pay for a `num_cpus`-sized `multi_thread`
    /// runtime it never uses. Reaches into the private `connect_runtime`
    /// `OnceLock` directly (this test module is `super`'s own, not an
    /// external caller) rather than inferring laziness indirectly, so a
    /// regression that starts eagerly building the runtime in `Ops::new`
    /// is caught here rather than only showing up as a thread-count
    /// regression under load.
    #[test]
    fn connect_runtime_is_lazy_until_first_connect_call() {
        let (_guard, ops) = temp_ops();
        assert!(
            ops.connect_runtime.get().is_none(),
            "Ops::new must not build the shared dial runtime eagerly"
        );
        // A local-only op — no host, no dial — must still leave it unbuilt.
        ops.version().unwrap();
        assert!(
            ops.connect_runtime.get().is_none(),
            "a local-only op (version.get) must not build the shared dial runtime"
        );
        // `qsh trust list` by name — the field doc on `Ops::connect_runtime`
        // points at it explicitly as a local-only op that must not force
        // the runtime into existence.
        ops.trust_list().unwrap();
        assert!(
            ops.connect_runtime.get().is_none(),
            "a local-only op (trust.list) must not build the shared dial runtime"
        );
        // The schema surface is local-only too (no host, no dial).
        ops.schema().unwrap();
        assert!(
            ops.connect_runtime.get().is_none(),
            "a local-only op (schema.get) must not build the shared dial runtime"
        );
    }

    /// The other half of `PLAN.md` M7 Step 7-2 ①: once built, the runtime
    /// is **shared** — every `connect_runtime()` call on the same `Ops`
    /// (and on every clone of it, since `Ops::clone` only bumps the outer
    /// `Arc`'s refcount) returns a handle to the exact same
    /// `tokio::runtime::Runtime`, not a fresh one per call. `Arc::ptr_eq`
    /// is the direct claim — same allocation, not merely
    /// equal-by-value — which is what makes a pull's per-call `Builder::
    /// new_multi_thread()` (the 11-threads-per-pull cost this step
    /// removes) actually go away.
    #[test]
    fn connect_runtime_is_the_same_instance_across_calls_and_clones() {
        let (_guard, ops) = temp_ops();
        let first = ops.connect_runtime().unwrap();
        let second = ops.connect_runtime().unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "two connect_runtime() calls on the same Ops must share one Runtime"
        );

        let cloned = ops.clone();
        let third = cloned.connect_runtime().unwrap();
        assert!(
            Arc::ptr_eq(&first, &third),
            "Ops::clone must not fork a second dial runtime"
        );

        // The other direction: a wholly independent `Ops` (its own
        // `Paths`, not a clone of the first) must NOT share the first's
        // runtime. The field doc on `Ops::connect_runtime` explicitly
        // rejects a `static OnceLock` for this reason — it "would outlive
        // `Ops` and break test isolation" — so this pins that rejection
        // both ways: same `Ops`/clones share one instance (above), a
        // second `Ops` gets its own.
        let (_other_guard, other_ops) = temp_ops();
        let other = other_ops.connect_runtime().unwrap();
        assert!(
            !Arc::ptr_eq(&first, &other),
            "two independent Ops instances must not share one dial runtime \
             (a static OnceLock would fail this)"
        );
    }

    /// Regression pin for the failure this step's own nextest run caught:
    /// `qsh-testkit::reverse_attach
    /// detaching_leaves_the_session_running_and_a_reattach_replays_the_retained_ring`
    /// panicked with "Cannot drop a runtime in a context where blocking is
    /// not allowed" the first time `Ops`'s shared runtime shipped as a bare
    /// `Arc<tokio::runtime::Runtime>`. Root cause: `connect_runtime` is
    /// reference-counted and shared, so its very last `Arc` can be dropped
    /// almost anywhere — that fixture builds an `Ops` inside a
    /// `#[tokio::test]` and drops it before the async test function
    /// returns, and the plain `Runtime::drop` blocks (panicking if that
    /// block happens on a thread already executing inside *any* async
    /// task). [`SharedRuntime`] fixes this generally by routing its `Drop`
    /// through `Runtime::shutdown_background` instead. This test
    /// reproduces the minimal shape directly, without going through a full
    /// loopback fixture: populate the shared-runtime cell, then drop the
    /// `Ops` that owns it from inside a *different*, already-running
    /// runtime. Passing (not panicking) is the assertion.
    #[test]
    fn dropping_ops_with_a_live_shared_runtime_from_inside_another_runtime_does_not_panic() {
        let (_guard, ops) = temp_ops();
        ops.connect_runtime()
            .expect("build the shared runtime so there is something to drop");

        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build the outer async context this test drops `ops` from");
        outer.block_on(async move {
            // `ops` (and with it, `connect_runtime`'s last `Arc<SharedRuntime>`)
            // drops here, on a thread `outer` currently has executing this
            // async block — exactly the context the plain `Runtime::drop`
            // cannot tolerate.
            drop(ops);
        });
    }

    #[test]
    fn op_error_from_code_defaults_retryable() {
        let err = OpError::from(ErrorCode::Timeout);
        assert!(err.retryable);
        assert_eq!(err.code, ErrorCode::Timeout);
    }

    #[test]
    fn operation_commands_are_dotted_form() {
        assert_eq!(VersionOp::COMMAND, "version.get");
        assert_eq!(IdentityInitOp::COMMAND, "identity.init");
        assert_eq!(TrustAddOp::COMMAND, "trust.add");
        assert_eq!(TrustListOp::COMMAND, "trust.list");
        assert_eq!(TrustRemoveOp::COMMAND, "trust.remove");
    }

    #[test]
    fn identity_init_is_idempotent() {
        let (_guard, ops) = temp_ops();
        let first = ops.identity_init(file_mode()).unwrap();
        assert!(first.created);
        let second = ops.identity_init(file_mode()).unwrap();
        assert!(!second.created);
        assert_eq!(second.device_id, first.device_id);
    }

    #[test]
    fn identity_init_takes_the_key_store_from_config_when_unset() {
        let (_guard, ops) = temp_ops();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(
            ops.paths().config_file(),
            "[identity]\nkey_store = \"file\"\n",
        )
        .unwrap();
        let data = ops
            .identity_init(IdentityInitReq { key_store: None })
            .unwrap();
        assert_eq!(data.key_store, KeyStoreKind::File);
    }

    #[test]
    fn trust_add_list_remove_round_trip() {
        let (_guard, ops) = temp_ops();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();

        let added = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("mac.example:4433".into()),
                fingerprint: Some(fingerprint.clone()),
            })
            .unwrap();
        assert!(added.created);
        assert_eq!(added.updated, None, "nothing to update on a fresh pin");
        assert_eq!(added.peer.fingerprint, fingerprint);

        // Same fingerprint, same address: a pure no-op.
        let again = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("mac.example:4433".into()),
                fingerprint: Some(fingerprint.clone()),
            })
            .unwrap();
        assert!(!again.created);
        assert_eq!(again.updated, Some(false));
        assert_eq!(again.peer, added.peer);

        let listed = ops.trust_list().unwrap();
        assert_eq!(listed.peers, vec![added.peer.clone()]);

        let removed = ops.trust_remove("mac").unwrap();
        assert!(removed.removed);
        assert_eq!(removed.name, "mac");
        let removed_again = ops.trust_remove("mac").unwrap();
        assert!(!removed_again.removed);
        assert!(ops.trust_list().unwrap().peers.is_empty());
    }

    /// M7 Step 2 decision B: the same identity re-pinned at a new address
    /// updates the stored address in place instead of being a silent
    /// no-op (`docs/CLI.md` §6.11) — the M6 mobility campaign backlog item.
    #[test]
    fn trust_add_updates_the_address_of_an_identity_it_already_knows() {
        let (_guard, ops) = temp_ops();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();

        let added = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("old.example:4433".into()),
                fingerprint: Some(fingerprint.clone()),
            })
            .unwrap();
        assert!(added.created);

        let moved = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("new.example:5555".into()),
                fingerprint: Some(fingerprint.clone()),
            })
            .unwrap();
        assert!(!moved.created, "identity already pinned — never re-created");
        assert_eq!(moved.updated, Some(true));
        assert_eq!(moved.peer.address, "new.example:5555");
        assert_eq!(moved.peer.fingerprint, fingerprint);
        assert_eq!(
            moved.peer.added_at, added.peer.added_at,
            "added_at tracks the identity's first pin, not the address move"
        );

        let listed = ops.trust_list().unwrap();
        assert_eq!(listed.peers, vec![moved.peer], "no duplicate entry");
    }

    /// Regression for `PLAN.md` M7 Step 7-1 검증 라운드 A2: `crate::trust`'s
    /// own concurrency regressions (`concurrent_full_rmw_cycles_do_not_lose_each_others_peers`
    /// et al.) call `TrustStore::lock`/`load`/`save` directly from test
    /// threads and never go through `Ops::trust_add` — so a future edit
    /// that silently dropped the `TrustStore::lock(&path)?` line at the
    /// real call site (`Ops::trust_add`, this file) would leave the whole
    /// suite green. This drives that actual call site instead: 8 threads,
    /// each its own `Ops` bound to the same config directory (a fresh
    /// `Ops` per thread rather than a shared clone, so the wiring under
    /// test is the file lock, not any in-process synchronization `Ops`
    /// might incidentally provide), concurrently `trust_add`ing a distinct
    /// peer. All 8 must survive.
    #[test]
    fn concurrent_trust_add_through_ops_does_not_lose_a_peer() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));

        let mut threads = Vec::new();
        for i in 0..8u8 {
            let ops = Ops::new(paths.clone());
            let fingerprint = qsh_transport::Fingerprint::of_spki_der(&[i; 4]).to_string();
            threads.push(std::thread::spawn(move || {
                ops.trust_add(TrustAddReq {
                    name: format!("peer-{i}"),
                    address: None,
                    fingerprint: Some(fingerprint),
                })
                .unwrap();
            }));
        }
        for t in threads {
            t.join().expect("writer");
        }

        let listed = Ops::new(paths).trust_list().unwrap();
        assert_eq!(
            listed.peers.len(),
            8,
            "a concurrent Ops::trust_add lost a peer — the lock wired into the real call \
             site isn't doing its job"
        );
    }

    /// Fix A2 (initiator side), at the layer that actually writes
    /// `trust.toml`: `Ops::trust_accept` must reject a responder's
    /// `PairingAccepted.device_name` containing a control character with
    /// `INVALID_ARGUMENT` *before* ever touching the local trust store —
    /// even when the responder's own proof genuinely verifies (a rogue or
    /// misconfigured responder that really does know the invite secret
    /// must still not get pinned under an escape-sequence name). Proven
    /// against the store itself (`trust.toml` is never even created), not
    /// just the returned error — mirroring
    /// `qsh-testkit/tests/pairing_loopback.rs`'s responder-side sibling of
    /// this test. The rogue responder here hand-crafts its own wire reply
    /// (rather than going through `crate::server::Server`) so it can send
    /// a genuinely verifying proof alongside a bad device name — something
    /// a real, unmodified `qsh serve` never does, but a modified or
    /// compromised one could, and the wire format itself does not forbid.
    #[test]
    fn trust_accept_rejects_a_control_character_responder_device_name_and_leaves_trust_toml_untouched()
     {
        use qsh_proto::pairing::{INVITE_SECRET_LEN, encode_invite_code};
        use qsh_proto::wire::{self, ControlMessage, control_message};
        use qsh_transport::{FramedStream, Listener};

        let (dir, ops) = temp_ops();
        ops.identity_init(file_mode()).unwrap();

        let secret = [0x33u8; INVITE_SECRET_LEN];
        let code = encode_invite_code(&secret);

        let (rogue_identity, _rogue_fp) = crate::tunnel::testutil::self_signed();
        // `Listener::bind` itself needs an active Tokio reactor (quinn
        // registers the socket against `Handle::current()` at bind time),
        // and this test function is a plain synchronous `#[test]` with none
        // running on its own thread — so the listener is built inside the
        // rogue thread's own runtime via `block_on`, then both the runtime
        // and the already-bound listener move into the spawned thread
        // together, keeping every later async call on the same reactor.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt.block_on(async {
            Listener::bind(
                "127.0.0.1:0".parse().unwrap(),
                rogue_identity,
                Arc::new(StaticTrust::empty().with_pairing_open(true)),
            )
            .unwrap()
        });
        let addr = listener.local_addr().unwrap();

        let rogue = std::thread::spawn(move || {
            rt.block_on(async move {
                let incoming = listener.accept().await.unwrap();
                let conn = incoming.accept().await.unwrap();
                let (send, recv) = conn.accept_bi().await.unwrap();
                let mut ctl = FramedStream::control(send, recv);
                let _proof: ControlMessage = ctl.recv.recv().await.unwrap().unwrap();

                // A genuinely verifying proof — computed the same way
                // `crate::pairing::respond` would — so the initiator has no
                // reason to reject on that basis; only the device name is
                // bad here.
                let mut ekm = [0u8; 32];
                conn.export_keying_material(&mut ekm, crate::pairing::EXPORTER_LABEL, &[])
                    .expect("export keying material");
                let (_client_proof, server_proof) =
                    crate::trust::pairing::proofs_from_secret(&secret, &ekm);

                ctl.send
                    .send(&ControlMessage::new(
                        0,
                        control_message::Body::PairingAccepted(wire::PairingAccepted {
                            device_name: "host\u{1b}[2Kname".to_string(),
                            proof: server_proof.to_vec(),
                        }),
                    ))
                    .await
                    .expect("send PairingAccepted with a bad device name");
                if ctl.send.finish().is_ok() {
                    let _ = tokio::time::timeout(Duration::from_secs(2), ctl.send.stopped()).await;
                }
            });
        });

        let err = ops
            .trust_accept(TrustAcceptReq {
                address: addr.to_string(),
                code,
            })
            .expect_err("a control-character responder device name must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        rogue.join().expect("rogue responder thread");

        assert!(
            !dir.path().join("config").join("trust.toml").exists(),
            "the initiator's trust store must be untouched when the responder's \
             device name is rejected"
        );
    }

    /// Same regression, `Ops::trust_remove`'s call site instead of
    /// `trust_add`'s: 8 peers are pre-seeded, then 8 threads each their own
    /// `Ops` on the same config directory concurrently `trust_remove` a
    /// distinct one. All 8 removals must land — a lost one would mean a
    /// peer that was supposed to be unpinned came back because a stale,
    /// concurrently-loaded snapshot overwrote the file that already
    /// reflected its removal.
    #[test]
    fn concurrent_trust_remove_through_ops_does_not_lose_a_removal() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));

        let seed = Ops::new(paths.clone());
        for i in 0..8u8 {
            let fingerprint = qsh_transport::Fingerprint::of_spki_der(&[i; 4]).to_string();
            seed.trust_add(TrustAddReq {
                name: format!("peer-{i}"),
                address: None,
                fingerprint: Some(fingerprint),
            })
            .unwrap();
        }
        assert_eq!(seed.trust_list().unwrap().peers.len(), 8, "seed setup");

        let mut threads = Vec::new();
        for i in 0..8u8 {
            let ops = Ops::new(paths.clone());
            threads.push(std::thread::spawn(move || {
                let removed = ops.trust_remove(&format!("peer-{i}")).unwrap();
                assert!(removed.removed, "peer-{i} was not found to remove");
            }));
        }
        for t in threads {
            t.join().expect("remover");
        }

        let listed = Ops::new(paths).trust_list().unwrap();
        assert!(
            listed.peers.is_empty(),
            "a concurrent Ops::trust_remove lost a removal (peers left: {:?}) — the lock \
             wired into the real call site isn't doing its job",
            listed.peers.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
    }

    /// M7 Step 2 decision B, the guardrail half: a *different* fingerprint
    /// under an already-pinned name changes nothing at all — identity
    /// rebind stays a deliberate `trust remove` + `trust add`, never a
    /// side effect of a repeated call (`docs/CLI.md` §6.11's existing
    /// idempotence contract, preserved).
    #[test]
    fn trust_add_rejects_a_different_fingerprint_for_an_already_pinned_name() {
        let (_guard, ops) = temp_ops();
        let first_fp = qsh_transport::Fingerprint::of_spki_der(b"first").to_string();
        let second_fp = qsh_transport::Fingerprint::of_spki_der(b"second").to_string();

        let added = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("mac.example:4433".into()),
                fingerprint: Some(first_fp.clone()),
            })
            .unwrap();
        assert!(added.created);

        let rejected = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("attacker.example:1".into()),
                fingerprint: Some(second_fp),
            })
            .unwrap();
        assert!(!rejected.created);
        assert_eq!(rejected.updated, Some(false));
        assert_eq!(
            rejected.peer, added.peer,
            "a fingerprint mismatch must not touch the existing pin at all"
        );

        let listed = ops.trust_list().unwrap();
        assert_eq!(listed.peers, vec![added.peer]);
    }

    #[test]
    fn trust_add_rejects_bad_input() {
        let (_guard, ops) = temp_ops();

        let err = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: None,
                fingerprint: Some("not-a-fingerprint".into()),
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let err = ops
            .trust_add(TrustAddReq {
                name: "  ".into(),
                address: None,
                fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"x").to_string()),
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let err = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: None,
                fingerprint: None,
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(err.message.contains("--address"), "{err}");
    }

    #[test]
    fn probing_without_an_identity_asks_for_init_first() {
        let (_guard, ops) = temp_ops();
        let err = ops.probe_fingerprint("127.0.0.1:9").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(err.message.contains("qsh init"), "{err}");
    }

    #[test]
    fn open_trust_serves_pins_as_device_principals() {
        let (_guard, ops) = temp_ops();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer");
        ops.trust_add(TrustAddReq {
            name: "mac".into(),
            address: None,
            fingerprint: Some(fingerprint.to_string()),
        })
        .unwrap();

        let evaluator = ops.open_trust().unwrap();
        assert_eq!(
            qsh_transport::TrustEvaluator::lookup_pin(evaluator.as_ref(), &fingerprint),
            Some(qsh_transport::Principal::Device("mac".into()))
        );
    }

    #[test]
    fn server_name_strips_the_port_and_brackets() {
        assert_eq!(server_name_for("example.com:4433"), "example.com");
        assert_eq!(server_name_for("127.0.0.1:4433"), "127.0.0.1");
        assert_eq!(server_name_for("[::1]:4433"), "::1");
        assert_eq!(server_name_for("example.com"), "example.com");
        assert_eq!(server_name_for(":4433"), "qsh");
    }

    // ---- `Ops::resolve_route` — `PeerRoute` selection (`PLAN.md` M3
    // Step 6) ----
    //
    // `resolve_route` is a thin `HostRoute` -> `PeerRoute` mapping over
    // the same routing decision `resolve_host_route`/
    // `resolve_host_route_async` already make and already test
    // exhaustively at the `HostRoute` level (`crate::ops::host`'s own
    // test module). What these add is proof the *mapping* itself is
    // right: a forward `HostRoute` becomes a fully resolved `PeerTarget`
    // (identity loaded, address/server_name carried through
    // `resolve_peer`), a reverse `HostRoute` becomes the `LocalRoute`
    // `Ops::connect_reverse` actually dials with (host alias + that
    // daemon's own socket, nothing else), and not-found/duplicate stay
    // plain error propagation through the mapping.
    //
    // `resolve_route` is sync — same identity-load constraint as
    // `resolve_peer` — so on the reverse/duplicate cases below the fake
    // `LOCAL_ADMIN` daemon has to live on its own OS thread with its own
    // runtime (mirroring a real `qsh listen` process), never on the
    // test's own thread: calling `resolve_route` from inside a runtime
    // that already exists is exactly the "cannot start a runtime from
    // within a runtime" hazard `resolve_host_route`'s own doc flags.

    fn resolve_route_ops(dir: &std::path::Path) -> Ops {
        let paths =
            Paths::new(dir.join("config"), dir.join("state")).with_runtime_dir(dir.join("run"));
        Ops::new(paths)
    }

    #[test]
    fn resolve_route_not_found_is_host_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let ops = resolve_route_ops(dir.path());

        let err = match ops.resolve_route("nowhere") {
            Err(err) => err,
            Ok(_) => panic!("expected an error for an unknown host"),
        };
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    #[test]
    fn resolve_route_forward_resolves_a_peer_target_with_the_pinned_address() {
        let dir = tempfile::tempdir().unwrap();
        let ops = resolve_route_ops(dir.path());
        ops.identity_init(file_mode()).unwrap();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();
        ops.trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("mac.example.com:4433".into()),
            fingerprint: Some(fingerprint),
        })
        .unwrap();

        match ops.resolve_route("mac").unwrap() {
            PeerRoute::Forward(target) => {
                assert_eq!(target.address, "mac.example.com:4433");
                assert_eq!(target.server_name, "mac.example.com");
            }
            PeerRoute::Reverse(_) => panic!("expected a forward route"),
        }
    }

    #[cfg(unix)]
    fn sample_local_host(name: &str) -> qsh_proto::local::LocalHost {
        qsh_proto::local::LocalHost {
            name: name.to_string(),
            address: "203.0.113.5:51820".to_string(),
            state: "reachable".to_string(),
            fingerprint: qsh_transport::Fingerprint::of_spki_der(b"reverse-peer").to_string(),
            capabilities: vec!["pty".to_string()],
            generation: 1,
            registered_at: "2026-08-22T00:00:00Z".to_string(),
        }
    }

    /// Bind a one-shot fake `LOCAL_ADMIN` daemon at `<pid>.sock` under
    /// `runtime_dir`, answering exactly one `LocalHostList` with `hosts`,
    /// on its own OS thread with its own runtime — see this section's own
    /// header for why it cannot share the test's thread/runtime.
    #[cfg(unix)]
    fn spawn_fake_admin_daemon_thread(
        runtime_dir: &std::path::Path,
        pid: u32,
        hosts: Vec<qsh_proto::local::LocalHost>,
    ) -> std::thread::JoinHandle<()> {
        std::fs::create_dir_all(runtime_dir).unwrap();
        let sock = runtime_dir.join(format!("{pid}.sock"));
        // Bind synchronously, on the caller's thread, before handing off:
        // `resolve_route` must never race the socket file into existence.
        let std_listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std_listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
                let (stream, _addr) = listener.accept().await.unwrap();
                let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
                let _hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
                let _req: qsh_proto::local::LocalHostList = conduit.recv().await.unwrap().unwrap();
                conduit
                    .send(&qsh_proto::local::LocalResponse {
                        body: Some(qsh_proto::local::local_response::Body::HostListResult(
                            qsh_proto::local::LocalHostListResult { hosts },
                        )),
                    })
                    .await
                    .unwrap();
            });
        })
    }

    #[test]
    #[cfg(unix)]
    fn resolve_route_reverse_returns_the_local_route_to_the_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let ops = resolve_route_ops(dir.path());
        let runtime_dir = ops.paths().runtime_dir();
        let daemon =
            spawn_fake_admin_daemon_thread(&runtime_dir, 100, vec![sample_local_host("phone")]);

        match ops.resolve_route("phone").unwrap() {
            PeerRoute::Reverse(route) => {
                assert_eq!(route.host, "phone");
                assert_eq!(route.socket, runtime_dir.join("100.sock"));
            }
            PeerRoute::Forward(_) => panic!("expected a reverse route"),
        }
        daemon.join().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn resolve_route_reverse_prefers_the_live_daemon_over_a_forward_pin() {
        let dir = tempfile::tempdir().unwrap();
        let ops = resolve_route_ops(dir.path());
        ops.identity_init(file_mode()).unwrap();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"forward-pin").to_string();
        ops.trust_add(TrustAddReq {
            name: "phone".into(),
            address: Some("stale.example.com:4433".into()),
            fingerprint: Some(fingerprint),
        })
        .unwrap();
        let runtime_dir = ops.paths().runtime_dir();
        let daemon =
            spawn_fake_admin_daemon_thread(&runtime_dir, 100, vec![sample_local_host("phone")]);

        match ops.resolve_route("phone").unwrap() {
            PeerRoute::Reverse(route) => assert_eq!(route.host, "phone"),
            PeerRoute::Forward(_) => {
                panic!("a live reverse registration must beat a forward pin")
            }
        }
        daemon.join().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn resolve_route_duplicate_live_daemons_is_invalid_argument() {
        let dir = tempfile::tempdir().unwrap();
        let ops = resolve_route_ops(dir.path());
        let runtime_dir = ops.paths().runtime_dir();
        let a = spawn_fake_admin_daemon_thread(&runtime_dir, 100, vec![sample_local_host("dup")]);
        let b = spawn_fake_admin_daemon_thread(&runtime_dir, 101, vec![sample_local_host("dup")]);

        let err = match ops.resolve_route("dup") {
            Err(err) => err,
            Ok(_) => panic!("expected an error for two live daemons holding the same name"),
        };
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        a.join().unwrap();
        b.join().unwrap();
    }
}
