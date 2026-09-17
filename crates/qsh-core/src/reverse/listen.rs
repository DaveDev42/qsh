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
//!
//! `run_listen_unix` also binds this process's `localctl` UDS admin
//! socket (`crate::localctl::daemon`, `PLAN.md` M3 Step 5 (a)) alongside
//! the QUIC listener and runs its accept loop for as long as
//! [`Listen::run`]'s does, unlinking the socket immediately after — on a
//! clean shutdown and on the QUIC listener dying on its own alike, so the
//! socket file never outlives this process.

use std::collections::HashMap;
#[cfg(unix)]
use std::collections::{HashSet, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, Hello};
use qsh_transport::{AcceptError, Connection, FramedStream, Incoming, Listener};
#[cfg(unix)]
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc;
#[cfg(unix)]
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

// The next four imports are consumed only by the unix entry point (and
// this module's tests) — on the Windows lib build nothing constructs a
// controller, so ungated they would trip `unused_imports` under the
// Windows leg's `clippy -D warnings` (same gating as `tui/mod.rs`).
// `AllowAllPinned` itself is test-only now (M5 Step 6): production builds
// its `Authorizer` from `acl::load_or_deny` below, never this interim
// stand-in — the test module's `test_listen`/`test_listen_with_clock`
// helpers are the only remaining callers.
#[cfg(test)]
use crate::acl::AllowAllPinned;
use crate::acl::Authorizer;
#[cfg(unix)]
use crate::audit::RotatingAuditSink;
use crate::audit::{AuditRecord, AuditSink};
use crate::broker::Clock;
#[cfg(unix)]
use crate::broker::SessionId;
#[cfg(any(unix, test))]
use crate::broker::SystemClock;
use crate::client::Session;
use crate::client::pathwatch::{PathWatch, PathWatchConfig, watch_path};
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
#[cfg(unix)]
use crate::localctl::daemon::{LocalctlDaemon, LocalctlListener};
#[cfg(unix)]
use crate::localctl::mux::{ConduitId, ControlMux, Exhausted};
use crate::ops::OpError;
#[cfg(unix)]
use crate::trust::SharedTrustStore;

use super::admit::{AdmitRequest, admit};
use super::registry::{self, RegisterOutcome, Registry};

mod conn_table;
mod hub;
mod registration;

use conn_table::{ConnTable, Published, rollback_target};
#[cfg(unix)]
use hub::{
    RESET_CODE_TUNNEL_HUB_EXHAUSTED, RESET_CODE_TUNNEL_UNKNOWN_FORWARD,
    TUNNEL_ARRIVAL_SWEEP_INTERVAL,
};

#[cfg(unix)]
pub use hub::{ConduitInbound, ControlHub, HubSendError};
#[cfg(unix)]
pub(crate) use hub::{TunnelCloseTarget, tunnel_close_target};

/// How often [`Listen::run_stale_sweeper`] checks the registry for stale
/// entries whose `[listen].stale_retention` has elapsed
/// (`docs/design/protocol.md` §11-4). Mirrors [`crate::broker::REAPER_TICK`]'s
/// exact shape — a periodic driver calling a pure, clock-checked sweep — at
/// a tighter interval, proportionate to the much shorter default retention
/// (120 s here vs. the broker's 24 h default TTL).
pub const STALE_SWEEP_TICK: Duration = Duration::from_secs(5);

/// Poll interval for [`Listen::control_hub_wait`]/[`Listen::connection_for_wait`]
/// — Step 8's reverse recovery waiting for a new-generation registration.
/// `PLAN.md` M3 Step 8 (b) sanctions a bounded poll as an acceptable
/// substitute for a per-name wakeup, and this is the interval the daemon-
/// side `wait_ms`/`LOCAL_WAIT_MAX` (60 s) window is checked against —
/// small enough that a re-registration a few hundred milliseconds into a
/// re-dial's backoff is still noticed promptly, large enough that a full
/// `wait_ms` window of waiting never becomes a hot loop.
// Consumed only by `control_hub_wait`/`connection_for_wait`, both `#[cfg(unix)]`
// (localctl is a Unix-domain socket) — dead, not absent, on Windows.
#[cfg_attr(not(unix), allow(dead_code))]
const HUB_WAIT_POLL: Duration = Duration::from_millis(75);

/// Close code for the connection a NAT-rebind reconnect displaces
/// (`docs/design/protocol.md` §11-2's "same-fingerprint replace"). Local to
/// this module — the meaning is registration-specific, not a transport
/// concern, so it does not belong in `qsh-transport`
/// (`docs/design/architecture.md` §1).
const CLOSE_CODE_REPLACED: u32 = 0x1003;

/// Close code `drive_registered_session` uses when its own [`watch_path`]
/// declares this connection's path dead — the controller-side twin of
/// `reverse::target`'s identical `CLOSE_CODE_PATH_DEAD` (same value, same
/// meaning, duplicated rather than shared for the same reason
/// `CLOSE_CODE_REPLACED` above is local to this module: registration
/// semantics, not a transport concern). Without an explicit close here, a
/// silently-severed path leaves the QUIC connection object technically
/// alive — nothing tells quinn to give up on it — so any stream still
/// reading on it (in particular a `LOCAL_STREAM` splice pump relaying this
/// host's session data, `M3 Step 7`) blocks until quinn's own
/// unconfigurable `max_idle_timeout` (`docs/design/protocol.md` §10, 45 s)
/// finally kills it. That is exactly the "late idle-timeout" recovery
/// Step 8 (i) criterion ⑤ forbids: `mark_hub_dead`/`ConnTable::remove_if`
/// below already stop *new* `LOCAL_CONTROL` work promptly, but do nothing
/// for streams already open on the connection object itself — only
/// closing the connection does that (`reverse::target`'s own identical
/// `watch.dead()` arm makes the same argument for `serve_control`'s
/// blocking read).
const CLOSE_CODE_PATH_DEAD: u32 = 0x1004;

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
/// the actual bound address and fires immediately before the accept loop
/// starts, not as soon as the listener is up, for the reason given on
/// [`crate::serve::run_serve`]. `on_policy_diagnostic` fires at most once,
/// before `on_bound` and therefore before the accept loop starts admitting
/// registrations, and only when `acl.toml` did not produce a usable
/// policy — with the already-rendered
/// [`crate::acl::StartupDiagnostic::render`] text (`PLAN.md` M5 Step 6);
/// `qsh-cli` prints it verbatim and holds no ACL logic of its own.
pub async fn run_listen(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    bind_flag: Option<&str>,
    on_bound: impl FnOnce(SocketAddr),
    on_policy_diagnostic: impl FnOnce(&str),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    // Twin cfg blocks as alternative tail expressions — the exact shape
    // `pty::factory` established; a `return` here instead would trip
    // clippy's `needless_return` on the Windows leg (probed empirically).
    #[cfg(not(unix))]
    {
        let _ = (
            paths,
            config,
            identity,
            bind_flag,
            on_bound,
            on_policy_diagnostic,
            shutdown,
        );
        Err(windows_unsupported())
    }
    #[cfg(unix)]
    {
        run_listen_unix(
            paths,
            config,
            identity,
            bind_flag,
            on_bound,
            on_policy_diagnostic,
            shutdown,
        )
        .await
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
    on_policy_diagnostic: impl FnOnce(&str),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    let bind = resolve_bind(bind_flag, config)?;
    // Validated before any resource (socket, registry, sweeper task)
    // exists — a nonsensical `[listen].stale_retention`/`[reverse].backoff_max_ms`
    // combination must fail closed at startup, not surface later as a
    // half-initialized controller.
    let stale_retention = config.stale_retention()?;

    // localctl (`PLAN.md` M3 Step 5 (a)): bind this process's UDS admin
    // socket before the QUIC listener, so a runtime directory whose
    // permissions this process cannot pin to 0700 fails the whole startup
    // closed rather than leaving a QUIC listener half-serving with no
    // local control surface behind it.
    let pid = std::process::id();
    let localctl_bound = LocalctlListener::bind(paths, pid)?;
    let localctl_socket_path = localctl_bound.socket_path.clone();

    // From here on, every fallible step must unlink `localctl_socket_path`
    // before returning its error — the socket already exists on disk once
    // `LocalctlListener::bind` above succeeded, and nothing past this point
    // has taken ownership of cleaning it up the way the accept-loop tail
    // below does. Without this, a `qsh listen` that fails to come up at all
    // (bad trust store, port already in use, …) would leave a `<pid>.sock`
    // behind that nothing will ever unlink — `PLAN.md` M3 Step 5 (a)'s "the
    // socket must not outlive the process" on every exit path, not only the
    // clean-shutdown one the accept loop's own tail covers.
    let trust = SharedTrustStore::open(paths.trust_file()).inspect_err(|_| {
        let _ = std::fs::remove_file(&localctl_socket_path);
    })?;
    let listener = Listener::bind(bind, identity.local, trust).map_err(|err| {
        let _ = std::fs::remove_file(&localctl_socket_path);
        crate::serve::bind_setup_error(&bind, err)
    })?;
    let actual = listener.local_addr().map_err(|err| {
        let _ = std::fs::remove_file(&localctl_socket_path);
        OpError::new(
            ErrorCode::Internal,
            format!("cannot read bound address: {err}"),
        )
    })?;
    // F7 (`PLAN.md` M5 Step 3 arbitration): the controller shares the same
    // config-driven `RotatingAuditSink` construction `serve.rs`'s
    // `host_runtime` uses — `[audit]`'s `path`/`max_bytes`/`retain`/
    // `queue_depth` all apply here too, rather than `FileAuditSink`'s
    // fixed, unrotated `paths.audit_log()`. `qsh listen` and `qsh serve`/
    // `qsh reverse` (`crate::serve::host_runtime`) default to the exact
    // same path, which is safe now that F6 gives `RotatingAuditSink`
    // multi-writer rotation locking.
    let audit = Arc::new(RotatingAuditSink::spawn(
        config.audit.path(paths),
        config.audit.max_bytes(),
        config.audit.retain(),
        config.audit.queue_depth(),
    ));
    // Kept past `Listen::new` (which takes ownership of a clone below) so
    // the shutdown tail can wait on it directly — see the F2 comment near
    // `listen.run(..)`.
    let audit_for_shutdown = audit.clone();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let registry = Registry::new(clock.clone(), config.listen.allow_advertised_names);
    // `PLAN.md` M5 Step 6: the controller's `host.reverse` choke point
    // (`super::admit::admit`) is gated by the same `acl.toml`-backed
    // policy `crate::serve::host_runtime` builds for `qsh serve`/`qsh
    // reverse` — `load_or_deny` falls back to `DenyAll` (never
    // `AllowAllPinned`) plus a diagnostic on anything short of a clean
    // load. Read independently of `trust` above (already moved into
    // `Listener::bind`): `load_or_deny` opens `paths.trust_file()` itself
    // to fill the diagnostic's example policy with this machine's actual
    // pins.
    let (authorizer, policy_diagnostic) = crate::acl::load_or_deny(paths);
    if let Some(diag) = &policy_diagnostic {
        on_policy_diagnostic(&diag.render());
    }
    // `[listen]` has no admission keys of its own — it inherits
    // `[serve].max_concurrent_handshakes`/`handshake_rate_per_source`
    // (`PLAN.md` M8 Step 2 design arbitration, `docs/CLI.md` §6.12).
    let admission = crate::admission::Gate::new(
        clock.clone(),
        config.serve.max_concurrent_handshakes(),
        config.serve.handshake_rate_per_source(),
        config.serve.validated_rate_per_source(),
    );
    // `[listen]` has no quota keys of its own either — same inheritance
    // as `admission` just above (M8 Step 3b ruling R6: this controller's
    // connection cap is its own accept arm, but the *values* it enforces
    // still come from the operator's `[serve]` section).
    let quotas = crate::quota::Quotas::new(
        crate::quota::QuotaLimits::from_serve(&config.serve),
        clock.clone(),
    );
    let listen = Listen::with_admission_and_quotas(
        registry,
        authorizer,
        audit,
        identity.identity.device_id.clone(),
        clock,
        stale_retention,
        STALE_SWEEP_TICK,
        admission,
        quotas,
    );
    tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));
    tracing::info!(
        device_id = %identity.identity.device_id,
        fingerprint = %identity.identity.fingerprint,
        %actual,
        socket = %localctl_socket_path.display(),
        "qsh listen listening"
    );

    // The localctl daemon reads only through `Listen::registry` — never
    // `Listen`'s live connection table — so it shares no lock with the
    // Step 4 probe driver/sweeper, which only ever touch `conns`
    // (`reverse/listen.rs` module docs: the two are separate locks, never
    // held together by any caller). Its accept loop's lifetime is tied to
    // the QUIC accept loop's below, not to a second, independent read of
    // `shutdown`: whichever way `listen.run` below ends — a clean
    // shutdown, or the QUIC endpoint dying on its own — the localctl loop
    // is told to stop and the socket is unlinked immediately after, so it
    // can never outlive this process on any exit path, including SIGTERM
    // (`run_listen`'s caller drives `shutdown` from `shutdown_signal()`).
    let (localctl_shutdown_tx, localctl_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let localctl_daemon = LocalctlDaemon::new(listen.clone());
    let localctl_task = tokio::spawn(localctl_daemon.run(localctl_bound, async move {
        let _ = localctl_shutdown_rx.await;
    }));

    // Announced here, not right after `local_addr()` above, for the reason
    // spelled out at the matching call in `crate::serve::run_serve` — the
    // stderr line is what external scripts synchronize on, so it must not
    // be readable before the accept loop is armed. The window this closes
    // is wider here than in `run_serve`: everything between the bind and
    // this point includes two blocking file reads (the audit sink's
    // rotation setup and `acl::load_or_deny`, which opens `acl.toml` and
    // `trust.toml`), so on a slow or loaded disk the old placement left a
    // real, disk-latency-bounded gap rather than a scheduling-only one.
    on_bound(actual);

    listen.run(listener, shutdown).await;

    let _ = localctl_shutdown_tx.send(());
    if let Err(join_err) = localctl_task.await {
        tracing::warn!(%join_err, "localctl daemon task panicked");
    }
    let _ = std::fs::remove_file(&localctl_socket_path);

    // F2 (`PLAN.md` M5 Step 3): `Listen::run` detaches each accepted
    // connection's task the same way `server::Server::run` does — a
    // straggler can still hold its own `Arc<Listen>` clone (and thus,
    // through it, `Listen::audit`) for a moment after `run` returns. By
    // this point `listen.run(..)` has already consumed this function's own
    // `Arc<Listen>` and `localctl_task.await` has joined the only other
    // clone this function itself handed out, so `audit_for_shutdown` is
    // the one reference left to wait out — best effort, not a guarantee,
    // see `wait_for_sole_owner`'s docs.
    crate::audit::wait_for_sole_owner(&audit_for_shutdown, crate::audit::AUDIT_SHUTDOWN_GRACE)
        .await;

    Ok(())
}

#[cfg(all(test, unix))]
mod control_hub_tests;

#[cfg(test)]
mod conn_table_tests;

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
    /// Live registered connections, keyed by name — never in [`Registry`]
    /// (module docs). See [`ConnTable`]'s own docs for why `name` alone,
    /// not `(name, generation)`.
    conns: ConnTable<Connection>,
    /// The `LOCAL_CONTROL` relay for each live registration, keyed by
    /// `name` exactly like [`Self::conns`] — a *separate* table
    /// (`M3 Step 6`), not a field alongside `Connection` in `conns`
    /// itself, purely so this whole table (and its type, [`ControlHub`])
    /// can be `#[cfg(unix)]`-only without splitting `conns`'s type across
    /// platforms (localctl has no meaning on Windows — this file's own
    /// module docs on `crate::localctl`). Published/removed in lock-step
    /// with `conns` by [`Self::finish_registration`]/
    /// [`Self::drive_registered_session`], via the same generation-guarded
    /// [`ConnTable::publish`]/[`ConnTable::remove_if`] `conns` uses — two
    /// separate lock acquisitions, not one joint publish, so there is a
    /// vanishingly small window where a losing generation's hub is
    /// briefly visible before its own teardown catches up; harmless and
    /// self-healing (the conduit that raced into it sees the hub die
    /// immediately after, the same as any other host-death path) rather
    /// than worth a joint lock over.
    #[cfg(unix)]
    hubs: ConnTable<Arc<ControlHub>>,
    /// The same clock [`Registry`] was built with — [`Listen::run_stale_sweeper`]
    /// needs it too (to pace its own tick), so it is threaded through here
    /// rather than exposed off [`Registry`] just for that.
    clock: Arc<dyn Clock>,
    /// Defaulted and validated `[listen].stale_retention`
    /// (`docs/design/protocol.md` §11-4, [`crate::config::ListenConfig::stale_retention`]).
    stale_retention: Duration,
    /// How often [`Listen::run_stale_sweeper`] wakes to check for
    /// retention-expired entries. [`STALE_SWEEP_TICK`] in production;
    /// injectable so an L3/L4 test that actually wants to observe a sweep
    /// fire does not have to pay `STALE_SWEEP_TICK`'s real wall-clock cost
    /// to do it (`Listen::new`'s doc comment).
    sweep_tick: Duration,
    /// L2-L3 of the L0-L5 admission ordering (`PLAN.md` M8 Step 2,
    /// `docs/adr/0009-admission-defenses.md`) — same type, same ordering,
    /// as `crate::server::Server`'s own field; consulted by [`Self::run`]
    /// before an `Incoming` reaches [`Self::accept_and_register`].
    admission: crate::admission::Gate,
    /// M8 Step 3b ruling R6: `[serve].max_connections`/
    /// `max_connections_per_principal` is enforced **per accept arm**,
    /// not per process — this controller is its own arm, independent of
    /// `crate::server::Server`'s, with its own [`crate::quota::Quotas`]
    /// instance (same type, same reservation call
    /// [`crate::quota::Quotas::reserve_connection`], same host→principal
    /// order) even when both run in the same `qsh listen` process.
    quotas: Arc<crate::quota::Quotas>,
}

impl std::fmt::Debug for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listen")
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl Listen {
    /// Build a controller with the given registry, policy, audit sink, and
    /// stale-eviction parameters. `clock` should be the same clock `registry`
    /// was built with (`Listen::clock`'s doc comment) — production callers
    /// share one `Arc<dyn Clock>` between the two constructions exactly the
    /// way `run_listen_unix` does. [`Self::new`] paces
    /// [`Self::run_stale_sweeper`] at the production [`STALE_SWEEP_TICK`]; a
    /// test that actually wants to observe a sweep fire without paying that
    /// real wall-clock cost uses [`Self::new_with_sweep_tick`] instead
    /// (`sweep_tick`'s own doc comment). Its admission
    /// gate (`PLAN.md` M8 Step 2) defaults to
    /// `crate::config::ServeConfig`'s own defaults on `clock` — production
    /// (`run_listen_unix`) instead builds one from the operator's actual
    /// `[serve]` values (`[listen]` has no admission keys of its own — the
    /// design arbitration's own call: inherit `[serve]`) via
    /// [`Self::with_admission`].
    pub fn new(
        registry: Registry,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
        clock: Arc<dyn Clock>,
        stale_retention: Duration,
    ) -> Arc<Self> {
        Self::new_with_sweep_tick(
            registry,
            authorizer,
            audit,
            device_name,
            clock,
            stale_retention,
            STALE_SWEEP_TICK,
        )
    }

    /// [`Self::new`] with a caller-chosen sweep tick — the injection point
    /// `sweep_tick`'s doc comment promises.
    pub fn new_with_sweep_tick(
        registry: Registry,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
        clock: Arc<dyn Clock>,
        stale_retention: Duration,
        sweep_tick: Duration,
    ) -> Arc<Self> {
        let admission = crate::admission::Gate::new(
            clock.clone(),
            crate::config::ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
            crate::config::ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
            crate::config::ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE,
        );
        Self::with_admission_and_sweep_tick(
            registry,
            authorizer,
            audit,
            device_name,
            clock,
            stale_retention,
            sweep_tick,
            admission,
        )
    }

    /// [`Self::new`] plus an explicit [`crate::admission::Gate`] —
    /// `run_listen_unix` uses this to build the gate from the operator's
    /// actual `[serve].max_concurrent_handshakes`/`handshake_rate_per_source`
    /// (`[listen]` inherits `[serve]`'s admission values, design
    /// arbitration) instead of the hardcoded defaults [`Self::new`] uses.
    pub fn with_admission(
        registry: Registry,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
        clock: Arc<dyn Clock>,
        stale_retention: Duration,
        admission: crate::admission::Gate,
    ) -> Arc<Self> {
        Self::with_admission_and_sweep_tick(
            registry,
            authorizer,
            audit,
            device_name,
            clock,
            stale_retention,
            STALE_SWEEP_TICK,
            admission,
        )
    }

    /// [`Self::with_admission`] with a caller-chosen sweep tick — same
    /// injection point as [`Self::new_with_sweep_tick`].
    #[allow(clippy::too_many_arguments)]
    pub fn with_admission_and_sweep_tick(
        registry: Registry,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
        clock: Arc<dyn Clock>,
        stale_retention: Duration,
        sweep_tick: Duration,
        admission: crate::admission::Gate,
    ) -> Arc<Self> {
        let quotas = crate::quota::Quotas::new(crate::quota::QuotaLimits::default(), clock.clone());
        Self::with_admission_and_quotas(
            registry,
            authorizer,
            audit,
            device_name,
            clock,
            stale_retention,
            sweep_tick,
            admission,
            quotas,
        )
    }

    /// [`Self::with_admission_and_sweep_tick`] plus an explicit
    /// [`crate::quota::Quotas`] — `run_listen_unix` uses this to build
    /// the tracker from the operator's actual `[serve].max_connections`/
    /// `max_connections_per_principal` the same way `[listen]` already
    /// inherits `[serve]`'s admission values (`Self::with_admission`'s own
    /// doc comment), rather than [`crate::quota::QuotaLimits::default`].
    /// M8 Step 3b ruling R6: this controller's `Quotas` is entirely its
    /// own — a separate accept arm from `crate::server::Server`'s, never
    /// shared, even when both run in the same process.
    #[allow(clippy::too_many_arguments)]
    pub fn with_admission_and_quotas(
        registry: Registry,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
        clock: Arc<dyn Clock>,
        stale_retention: Duration,
        sweep_tick: Duration,
        admission: crate::admission::Gate,
        quotas: Arc<crate::quota::Quotas>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            authorizer,
            audit,
            device_name: device_name.into(),
            conns: ConnTable::new(),
            #[cfg(unix)]
            hubs: ConnTable::new(),
            clock,
            stale_retention,
            sweep_tick,
            admission,
            quotas,
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
        self.conns.len()
    }

    /// The `LOCAL_CONTROL` relay for `name`'s *current* live registration,
    /// if it has one — `crate::localctl::daemon`'s `LOCAL_CONTROL` serve
    /// path looks this up once, right after reading `LocalHello`, and
    /// answers `HOST_NOT_FOUND` on `None` (stale and unknown are
    /// indistinguishable here on purpose: this table only ever holds a
    /// genuinely live hub, [`Self::registry`] is what still knows a name
    /// existed at all).
    #[cfg(unix)]
    pub fn control_hub(&self, name: &str) -> Option<Arc<ControlHub>> {
        self.hubs.get(name)
    }

    /// Every currently-registered host's `(name, hub)`, live or not —
    /// `crate::localctl::daemon`'s `LOCAL_ADMIN` handling for
    /// `LocalTunnelList`/admin `tunnel.close` (`PLAN.md` M4 Step 5 PR
    /// 5b), which — unlike [`Self::control_hub`] — has no single host
    /// name to look up: `qsh tunnels`/`qsh tunnel close <id>` name no
    /// host at all (`docs/CLI.md` §6.9's own usage examples), so this
    /// controller must consider every live registration it holds, the
    /// same shape [`Self::registry`]'s own `snapshot` gives `LocalHostList`.
    #[cfg(unix)]
    pub fn hubs_snapshot(&self) -> Vec<(String, Arc<ControlHub>)> {
        self.hubs.snapshot()
    }

    /// The live QUIC [`Connection`] and [`ControlHub`] for `name`'s
    /// *current* live registration, generation-matched to each other —
    /// `crate::localctl::daemon`'s `LOCAL_STREAM` serve path needs both:
    /// the hub for `LocalHelloAck`'s fields, the connection to open the
    /// spliced data stream on (`PLAN.md` M3 Step 7).
    ///
    /// Looking each up independently (a `control_hub` call plus a
    /// separate `conns` lookup) could momentarily pair a hub from one
    /// generation with a connection from a different one during the
    /// narrow window `Self::hubs`'s own doc comment describes; this
    /// method instead fixes the hub's generation first and requires the
    /// connection to still be published under exactly that generation,
    /// `None` otherwise — the same "stale and unknown are
    /// indistinguishable" contract [`Self::control_hub`] already
    /// documents, extended to cover the pair. Two separate lock
    /// acquisitions (`ConnTable::get`/`get_matching` each take and
    /// release their own), never held across an `.await` — both return
    /// owned clones.
    #[cfg(unix)]
    pub fn connection_for(&self, name: &str) -> Option<(Connection, Arc<ControlHub>)> {
        let hub = self.hubs.get(name)?;
        let conn = self.conns.get_matching(name, hub.generation)?;
        Some((conn, hub))
    }

    /// [`Self::control_hub`], but willing to wait: Step 8's reverse
    /// recovery (`docs/design/protocol.md` §11-4's "controller 측 attach
    /// driver... registry에서 그 host의 새 generation 등록을 기다렸다가").
    ///
    /// `known_generation` is the caller's `LocalHello.known_generation`
    /// (`qsh/local/v1.proto`'s own doc on that field): `None` accepts any
    /// live hub immediately, exactly like [`Self::control_hub`] — every
    /// pre-Step-8 caller (a first `LOCAL_CONTROL`/`LOCAL_STREAM` open,
    /// `wait_ms = 0`) takes this branch and observes no behavior change.
    /// `Some(g)` requires a hub whose generation is strictly greater than
    /// `g` — a hub still sitting at exactly `g` is the very registration
    /// whose connection `LocalReconnect` watched die, and handing it back
    /// would silently resume the caller onto a dead connection instead of
    /// the live one it is waiting for (this method's whole job).
    ///
    /// Polls `Self::hubs` on `Self::clock` (so `TestClock` drives this
    /// deterministically in tests, `docs/design/testing.md` L2) at
    /// `HUB_WAIT_POLL` — a plain `ConnTable` has no per-name wakeup to
    /// block on instead (this method's own module has no `Notify` keyed by
    /// registration name), and `PLAN.md` M3 Step 8 (b) sanctions a bounded
    /// poll as an acceptable substitute for exactly this reason. Gives up
    /// and returns `None` the moment either `deadline` elapses *or* the
    /// name is no longer known to [`Self::registry`] at all (evicted by
    /// [`Registry::sweep_expired`] — no later poll within `deadline` could
    /// ever find a satisfying hub once the name itself is gone, so this
    /// stops waiting on it rather than spinning uselessly to the deadline;
    /// `docs/design/protocol.md` §11-4's `stale_retention` is what actually
    /// bounds that case in practice, this check is just not wasting the
    /// caller's remaining budget once it has already fired).
    #[cfg(unix)]
    pub async fn control_hub_wait(
        &self,
        name: &str,
        known_generation: Option<u64>,
        deadline: Duration,
    ) -> Option<Arc<ControlHub>> {
        let satisfies = |hub: &Arc<ControlHub>| match known_generation {
            Some(seen) => hub.generation > seen,
            None => true,
        };
        let start = self.clock.now();
        loop {
            if let Some(hub) = self.hubs.get(name) {
                if satisfies(&hub) {
                    return Some(hub);
                }
            } else if self.registry.get(name).is_none() {
                // Never registered, or already swept — no poll between now
                // and `deadline` can change that.
                return None;
            }
            let elapsed = self.clock.now().saturating_duration_since(start);
            if elapsed >= deadline {
                return None;
            }
            self.clock
                .sleep(HUB_WAIT_POLL.min(deadline - elapsed))
                .await;
        }
    }

    /// [`Self::connection_for`], but waiting exactly the way
    /// [`Self::control_hub_wait`] does — the `LOCAL_STREAM` sibling Step
    /// 8's `LocalReconnect` needs after its `LOCAL_CONTROL` wait already
    /// landed on the new generation (`crate::localctl::daemon::serve_stream`'s
    /// call site).
    ///
    /// Generation-matches the connection to *the hub this call itself
    /// returned* (never re-resolves `known_generation` against `conns`
    /// directly) — the same reasoning [`Self::connection_for`]'s own doc
    /// gives for why hub and connection must come from one fixed
    /// generation, not two independent lookups.
    #[cfg(unix)]
    pub async fn connection_for_wait(
        &self,
        name: &str,
        known_generation: Option<u64>,
        deadline: Duration,
    ) -> Option<(Connection, Arc<ControlHub>)> {
        let hub = self
            .control_hub_wait(name, known_generation, deadline)
            .await?;
        let conn = self.conns.get_matching(name, hub.generation)?;
        Some((conn, hub))
    }

    /// Sweep stale, retention-expired registry entries until this
    /// controller is dropped (`this` holds only a [`std::sync::Weak`], the
    /// same shape [`crate::broker::Broker::run_reaper`] uses). Spawn this
    /// on a task alongside [`Listen::run`]. Uses `Listen::clock`, so
    /// `tokio::time::pause()`/`TestClock` drive it deterministically — see
    /// [`Registry::sweep_expired`] for the pure logic this only paces.
    pub async fn run_stale_sweeper(this: std::sync::Weak<Self>) {
        loop {
            let Some(listen) = this.upgrade() else {
                return;
            };
            let clock = listen.clock.clone();
            let sweep_tick = listen.sweep_tick;
            drop(listen);
            clock.sleep(sweep_tick).await;
            let Some(listen) = this.upgrade() else {
                return;
            };
            for entry in listen.registry.sweep_expired(listen.stale_retention) {
                RegistrationEvent {
                    event: "expired",
                    host: &entry.name,
                    fingerprint: &entry.fingerprint,
                    generation: Some(entry.generation),
                }
                .emit();
            }
        }
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
        // See `crate::server::Server::run`'s identical branch for the full
        // rationale (`PLAN.md` M8 Step 2 verification round, P1-3/F1):
        // bounded-latency admission-audit flush, same window, same
        // `MissedTickBehavior`.
        let mut audit_flush = tokio::time::interval(crate::admission::AUDIT_AGGREGATION_WINDOW);
        audit_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                incoming = listener.accept() => {
                    let Some(incoming) = incoming else { break };
                    self.clone().admit(incoming);
                }
                _ = audit_flush.tick() => {
                    let records = self.admission.flush_expired(self.admission.now());
                    crate::audit::write_admission_audit(self.audit.as_ref(), &records);
                    // M8 Step 3b S5: this controller owns its own
                    // `Quotas` (ruling R6 — the `Listen` accept arm's
                    // connection cap is independent of `qsh serve`'s), so
                    // its rejection-audit windows need the same
                    // bounded-latency flush `Server::run`'s identical tick
                    // gives `quota_housekeeping` — otherwise a burst of
                    // refused registrations here would open a first-record
                    // window that never closes into a summary until the
                    // next rejection happens to land, which may be never.
                    let quota_records = self.quotas.flush_expired(self.quotas.now());
                    crate::audit::write_quota_audit(self.audit.as_ref(), &quota_records);
                }
            }
        }
        let records = self.admission.flush_expired(self.admission.now());
        crate::audit::write_admission_audit(self.audit.as_ref(), &records);
        let quota_records = self.quotas.flush_expired(self.quotas.now());
        crate::audit::write_quota_audit(self.audit.as_ref(), &quota_records);
        listener.close(0, b"shutdown");
        listener.endpoint().wait_idle().await;
    }

    /// L2-L4 of the L0-L5 admission ordering — mirrors
    /// `crate::server::Server::admit` exactly (same `Gate` type, same
    /// `Decision` mapping); see that method's doc for the full rationale.
    fn admit(self: Arc<Self>, incoming: Incoming) {
        let peer = incoming.remote_address();
        let validated = incoming.remote_address_validated();
        let now = self.admission.now();
        match self.admission.decide(peer, validated, now) {
            crate::admission::Decision::Retry => {
                if let Err(returned) = incoming.retry() {
                    returned.ignore();
                }
            }
            crate::admission::Decision::Ignore(_, records) => {
                crate::audit::write_admission_audit(self.audit.as_ref(), &records);
                incoming.ignore();
            }
            crate::admission::Decision::Refuse(_, records) => {
                crate::audit::write_admission_audit(self.audit.as_ref(), &records);
                incoming.refuse();
            }
            crate::admission::Decision::Admit(permit) => {
                tokio::spawn(async move {
                    self.accept_and_register_permitted(incoming, Some(permit))
                        .await;
                });
            }
        }
    }
}

/// Aborts the task it holds when dropped — including when the task that
/// *owns* it is itself aborted, since tokio's cancellation drops a task's
/// locals at its next poll point. Same shape and same purpose as
/// `crate::session_stream`'s and `crate::ops::session`'s own guards of
/// this name; kept local rather than shared because it is three lines and
/// each copy states the lifetime it guards
/// ([`Listen::run_tunnel_accept_loop`]'s sweeper, here).
#[cfg(unix)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

#[cfg(unix)]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// [`Listen::drive_registered_session`]'s `select!` arm for its hub's
/// outbound-relay channel — a receiver that may not exist at all (no hub
/// for this generation, or this build has no `ControlHub` at all —
/// [`Listen::take_hub_outbound_receiver`]'s `#[cfg(not(unix))]` twin
/// always returns `None`) resolves to a future that never completes, so
/// that `select!` branch simply never fires rather than the whole loop
/// needing a second, platform-conditional shape
/// (`tokio::select!` has no per-branch `#[cfg]`, unlike `futures::select!`).
async fn recv_outbound(
    rx: &mut Option<mpsc::UnboundedReceiver<(u64, wire::control_message::Body)>>,
) -> Option<(u64, wire::control_message::Body)> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
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

/// One `registered`/`denied`/`replaced`/`lost`/`expired` line
/// (`docs/design/protocol.md` §11-2/§11-4's vocabulary — `retry` is
/// `reverse/target.rs`'s own `ReconnectEvent`, the target's side of the
/// same tracing target, never emitted here). Fields are exactly
/// `event`/`host`/`fingerprint`/`generation`: no payload, no token,
/// matching the audit record's own structural-only discipline
/// (`docs/design/architecture.md` §6). Built with `serde_json`, never
/// hand-formatted (`docs/CLI.md` §6.13) — the same shape
/// `reverse/target.rs`'s `ReconnectEvent` already uses.
#[derive(serde::Serialize)]
struct RegistrationEvent<'a> {
    event: &'static str,
    host: &'a str,
    fingerprint: &'a str,
    /// Absent when nothing was ever assigned one (`"denied"` before a name
    /// resolved far enough to reach [`Registry::admit`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
}

impl RegistrationEvent<'_> {
    /// Emit the record on [`TARGET`] at `INFO`. The typed fields ride
    /// along for a structural tracing consumer; the message is the exact
    /// JSON line a stderr-reading campaign script parses whole.
    fn emit(&self) {
        let line = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        tracing::info!(
            target: TARGET,
            event = self.event,
            host = self.host,
            fingerprint = self.fingerprint,
            generation = self.generation,
            "{}",
            line
        );
    }
}

#[cfg(test)]
mod tests;
