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
/// the actual bound address once the listener is up. `on_policy_diagnostic`
/// fires at most once, after `on_bound` and before the accept loop starts
/// admitting registrations, and only when `acl.toml` did not produce a
/// usable policy — with the already-rendered
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
        OpError::new(
            ErrorCode::ConfigError,
            format!("cannot listen on {bind}: {err}"),
        )
    })?;
    let actual = listener.local_addr().map_err(|err| {
        let _ = std::fs::remove_file(&localctl_socket_path);
        OpError::new(
            ErrorCode::Internal,
            format!("cannot read bound address: {err}"),
        )
    })?;
    on_bound(actual);

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

/// The live-connection table [`Listen::finish_registration`] publishes into
/// and [`Listen::drive_registered_session`] retires from — keyed by `name`
/// alone, generation carried in the value, generic over `T` so the
/// race-freedom argument below is unit-testable without a real
/// [`Connection`] (this module's tests use a small mock).
///
/// **`PLAN.md` M3 Step 4 (4) — the Step 3 race debt this fixes.** The old
/// shape keyed `conns` by `(name, generation)` and published a new
/// connection with a separate insert-then-remove sequence: insert
/// `(name, new_generation)`, then — if [`Registry::admit`]'s
/// `replaced_generation` said so — remove `(name, old_generation)` and
/// close what came back. Two concurrent same-fingerprint registrations
/// whose `admit()` calls land in one order but whose `finish_registration`
/// continuations resume in the *other* order could each publish under a
/// distinct `(name, generation)` key with no relationship enforced between
/// them — the second continuation's `remove` could find nothing (the first
/// hadn't inserted yet) and close nothing, leaving that generation's
/// connection permanently unreferenced: never the table's current entry,
/// never closed by anyone.
///
/// Keying by `name` alone removes the two-step gap entirely: publishing is
/// one `HashMap::insert`, so whichever call actually lands second
/// necessarily sees what the first one left behind, in the same critical
/// section it installs its own value in. [`ConnTable::publish`]'s
/// generation guard is what makes that safe to rely on regardless of
/// *which* call happens to run second — see its own doc comment for the
/// two-registration replay this was built against.
struct ConnTable<T> {
    inner: Mutex<HashMap<String, (u64, T)>>,
}

/// What a caller of [`ConnTable::publish`] must do with the result.
enum Published<T> {
    /// This call's value is now `name`'s occupant. `Some` is whatever it
    /// replaced — the caller closes that (never its own value).
    Installed(Option<T>),
    /// A `generation` at least as new was already published under `name`
    /// before this call ran, so this call's value never became the
    /// occupant. The caller must close *its own* value instead — nothing
    /// else references it, so leaving it open would leak exactly the
    /// connection [`ConnTable`]'s own doc comment describes.
    Superseded(T),
}

impl<T> ConnTable<T> {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u64, T)>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Publish `(generation, value)` under `name` — installing it only if
    /// `generation` is strictly newer than whatever is currently there (or
    /// nothing is). One `HashMap::insert` under this table's own lock: no
    /// read-then-write gap for a second concurrent caller to land inside
    /// ([`ConnTable`]'s own doc comment).
    ///
    /// **Replay of the race this fixes**, both possible continuation
    /// orders, starting from a pre-existing occupant at generation `0` and
    /// two concurrent same-fingerprint registrations whose `admit()` calls
    /// (elsewhere, strictly ordered by [`Registry`]'s own lock) produced
    /// generations `1` then `2`:
    ///
    /// - Continuations run in `admit()` order (`1` then `2`): `1` finds `0`
    ///   installs, hands back `0` to close. `2` finds `1`, installs, hands
    ///   back `1` to close. Final occupant: `2`. Closed: `0`, `1`.
    /// - Continuations run in the *other* order (`2` then `1`, the bug
    ///   scenario): `2` finds `0`, installs, hands back `0` to close. `1`
    ///   finds `2` — not newer than its own `1` — so it does **not**
    ///   install; it gets its own value back as [`Published::Superseded`]
    ///   and must close *that*. Final occupant: `2`. Closed: `0`, `1`.
    ///
    /// Both orders converge on the same end state — the highest generation
    /// open, every other value closed exactly once, nothing leaked.
    fn publish(&self, name: String, generation: u64, value: T) -> Published<T> {
        let mut table = self.lock();
        match table.get(&name) {
            Some((existing, _)) if *existing >= generation => Published::Superseded(value),
            _ => Published::Installed(table.insert(name, (generation, value)).map(|(_, v)| v)),
        }
    }

    /// Remove `name`'s entry iff it is still exactly `generation` — the
    /// same "only touch what I still believe is mine" guard
    /// [`Registry::mark_stale`]/[`Registry::rollback`] apply registry-side.
    /// Returns whether it was removed: `false` means a newer registration
    /// already superseded this one (which already got its own `"replaced"`
    /// event — the caller must not also treat this as a fresh loss).
    fn remove_if(&self, name: &str, generation: u64) -> bool {
        let mut table = self.lock();
        let matches = matches!(table.get(name), Some((g, _)) if *g == generation);
        if matches {
            table.remove(name);
        }
        matches
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    /// The generation currently published under `name`, if any. A
    /// non-mutating peek — used only to check whether a connection is
    /// still actually the live occupant before restoring metadata that
    /// describes it (see [`rollback_target`]).
    fn occupant_generation(&self, name: &str) -> Option<u64> {
        self.lock().get(name).map(|(g, _)| *g)
    }
}

impl<T: Clone> ConnTable<T> {
    /// `name`'s current occupant, whatever generation it happens to be —
    /// [`Listen::control_hub`]'s lookup: a caller outside this file that
    /// just wants "the live one, if any" rather than a specific
    /// generation (see [`Self::get_matching`] for that).
    #[cfg_attr(not(unix), allow(dead_code))]
    fn get(&self, name: &str) -> Option<T> {
        self.lock().get(name).map(|(_, v)| v.clone())
    }

    /// `name`'s current occupant iff it is still exactly `generation` — a
    /// non-mutating peek, the read-side counterpart to
    /// [`ConnTable::remove_if`]'s generation guard. `M3 Step 6`'s
    /// [`Listen::hubs`] table uses this to hand `daemon.rs` a
    /// [`ControlHub`] only when it is genuinely still that host's live
    /// one, never a generation a newer registration has already
    /// superseded.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn get_matching(&self, name: &str, generation: u64) -> Option<T> {
        match self.lock().get(name) {
            Some((g, v)) if *g == generation => Some(v.clone()),
            _ => None,
        }
    }

    /// Every current occupant, by name — [`Listen::hubs_snapshot`]'s own
    /// use (`PLAN.md` M4 Step 5 PR 5b's `LocalTunnelList`/admin
    /// `tunnel.close`): unlike [`Self::get`]/[`Self::get_matching`], which
    /// answer "the one host I already know the name of", these two admin
    /// requests carry no host at all and must consider every live
    /// registration this controller currently holds, the same "no host
    /// named, consider everything live" shape [`Registry::snapshot`]
    /// already has for [`LocalHostList`](qsh_proto::local::LocalHostList).
    #[cfg_attr(not(unix), allow(dead_code))]
    fn snapshot(&self) -> Vec<(String, T)> {
        self.lock()
            .iter()
            .map(|(name, (_, v))| (name.clone(), v.clone()))
            .collect()
    }
}

/// Decide what [`Registry::rollback`] should actually restore.
/// [`RegisterOutcome::replaced_entry`] is a *snapshot* taken at `admit()`
/// time — by the time a failed `Hello` reply triggers a rollback
/// (`Listen::register_connection`'s error branch), the connection that
/// snapshot describes may have already died on its own and removed itself
/// from `conns` (its watchdog declared the path dead and
/// [`Listen::drive_registered_session`] ran `conns.remove_if`), or a
/// further registration may have replaced it again. Restoring the
/// snapshot verbatim in either case would put a `Live` registry row back
/// with no connection behind it — and nothing would ever mark it stale,
/// since `mark_stale` needs a drive loop to call it, and that loop already
/// exited (adversarial review finding: "a permanent phantom host").
///
/// So the snapshot is only trustworthy while `conns` still shows it as
/// `name`'s current occupant — otherwise the rollback must free the name,
/// exactly like a rollback of a *fresh* (non-replacing) registration
/// already does for `replaced: None`.
fn rollback_target<T>(
    conns: &ConnTable<T>,
    name: &str,
    replaced: Option<registry::ReverseEntry>,
) -> Option<registry::ReverseEntry> {
    replaced.filter(|prev| conns.occupant_generation(name) == Some(prev.generation))
}

// --------------------------------------------------------------------
// LOCAL_CONTROL relay hub (`PLAN.md` M3 Step 6, `docs/design/protocol.md`
// §11-3's "다중화 규칙" — `crates/qsh-core/src/localctl/mux.rs`, Stage A1,
// is the pure state machine this wires up). `#[cfg(unix)]` throughout:
// localctl has no meaning on Windows (this file's own module docs on
// `crate::localctl`) — same discipline as the `LocalctlDaemon`/
// `LocalctlListener` import above, just a level lower.
// --------------------------------------------------------------------

/// How many undelivered [`ConduitInbound`] messages one conduit's inbox
/// holds before it is treated as dead. Generous relative to
/// `crate::localctl::mux::MAX_INFLIGHT_PER_CONDUIT` (64 in-flight
/// requests, each worth at most one `Response`) so a merely-bursty reader
/// is never mistaken for a stuck one, while still bounding this hub's
/// memory against a conduit that stops reading altogether
/// ([`ControlHub::deliver_response`]/[`ControlHub::deliver_event`]'s doc
/// comments).
#[cfg(unix)]
const CONDUIT_INBOX_CAPACITY: usize = 256;

/// Upper bound on `SessionRead`/`SessionClose` long-polls this hub relays
/// concurrently — **across every conduit of this host combined**, not
/// per-conduit. The target enforces its own
/// [`crate::server::MAX_INFLIGHT_REQUESTS_PER_CONN`] (64) on the one QUIC
/// connection every conduit of this host shares; a per-conduit cap of the
/// same 64 magnitude (`crate::localctl::mux::MAX_INFLIGHT_PER_CONDUIT`)
/// does *not* bound the shared resource at all — one conduit alone,
/// legally within its own cap, can hold all 64 of the target's long-poll
/// permits and starve `session read --wait`/`session close` for every
/// other conduit of the same host for up to
/// [`crate::server::SESSION_READ_MAX_WAIT`] (adversarial review finding,
/// reproduced against this exact cap arithmetic). This hub-wide cap is
/// set well under the target's own budget so no combination of conduits —
/// however many, whichever ones die — can approach it. It does not (and,
/// without a wire-level per-request cancel message the current protocol
/// has no way to) recover an already-in-flight long-poll's target-side
/// permit the instant its issuing conduit dies; it bounds how much of the
/// shared budget can ever be held at once in the first place, which is
/// the actual DoS surface the finding demonstrated.
#[cfg(unix)]
const MAX_INFLIGHT_LONG_POLL_PER_HUB: usize = 16;

/// Upper bound on tunnel data streams this hub carries **at once** —
/// every `TCP_CONNECT` splice `crate::localctl::daemon::LocalctlDaemon::serve_stream`
/// opens on this hub's connection, plus every `TCP_ACCEPTED` stream the
/// target opens back (accepted by [`Listen::run_tunnel_accept_loop`]),
/// summed across every `LOCAL_STREAM` conduit of every CLI process
/// attached to this host — modelled directly on
/// [`MAX_INFLIGHT_LONG_POLL_PER_HUB`]'s own reasoning (`PLAN.md` M4 Step
/// 5 (a)): the tunnels of every CLI process on this host share the one
/// physical reverse connection's `MAX_CONCURRENT_BIDI_STREAMS` budget
/// (`crates/qsh-transport/src/endpoint.rs`), so a per-conduit cap alone
/// cannot stop one greedy `-L`/`-R` from starving every other conduit of
/// this host — including its own `LOCAL_CONTROL` request/response traffic
/// and every other conduit's session/exec data streams, all riding the
/// same connection. 64 is chosen the same way
/// `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS` was (`localctl/daemon.rs`'s own
/// doc): comfortably under the transport's per-connection stream ceiling
/// (1024, `docs/design/protocol.md`'s own "동시성 상한" note on
/// `TCP_CONNECT`), generous enough that ordinary use (a handful of `-L`/
/// `-R` forwards, each carrying a handful of concurrent connections)
/// never comes close, and small enough that no combination of conduits on
/// this host can approach the transport's own limit and start starving
/// `LOCAL_CONTROL`/`SESSION_DATA` traffic that shares the connection.
/// Held for the *whole* life of a tunnel stream — from the moment this
/// hub commits to it (`open_bi` about to run, or a `TCP_ACCEPTED` stream
/// just accepted and queued for its claimant) until the splice ends — not
/// just its handshake, because an unclaimed backlog of accepted-but-not-
/// yet-spliced connections is exactly as much of a held QUIC stream as an
/// active one ([`TunnelArrival`]'s own doc).
#[cfg(unix)]
const MAX_TUNNEL_STREAMS_PER_HUB: usize = 64;

/// Upper bound on concurrently *parked* `TCP_ACCEPTED` claims per hub —
/// [`ControlHub::claim_permits`]'s own doc on the distinct resource this
/// bounds (a `serve_tcp_accepted` wait, not a relayed stream) and the
/// finding it closes. Deliberately smaller than [`MAX_TUNNEL_STREAMS_PER_HUB`]:
/// a legitimate `-R` claim loop keeps at most a small, fixed number of
/// claims outstanding at once per registered forward (`crate::tunnel::
/// remote::claim_remote_forward_reverse`'s own doc: one persistent claim
/// per `forward_id`, immediately re-armed), so this only needs headroom
/// for several forwards on one host, not for the whole relayed-stream
/// budget — and it must stay well under the daemon-wide
/// `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS` (256) so a single host at its
/// own cap can never come close to exhausting that pool for every other
/// host.
#[cfg(unix)]
const MAX_PARKED_CLAIMS_PER_HUB: usize = 32;

/// The share of [`MAX_PARKED_CLAIMS_PER_HUB`] any **one** owning conduit
/// (in practice: one CLI process's `LOCAL_CONTROL` conduit, the one that
/// opened the `forward_id`s being claimed) may hold parked at once —
/// `MAX_PARKED_CLAIMS_PER_HUB / 4`, so no single conduit can ever take
/// more than a quarter of this hub's pool and at least four conduits'
/// claim loops always coexist at *full* share, with any number coexisting
/// at ordinary use.
///
/// **Why a share is needed at all, on top of the hub ceiling**
/// (adversarial review finding): the ceiling alone bounds an *attack* but
/// not ordinary operation, because the steady state of a healthy `-R` is
/// to sit holding a permit. `crate::tunnel::remote::claim_remote_forward_reverse`
/// keeps exactly one long-poll parked per registered `forward_id` and
/// re-arms it the instant it returns (its own doc), so a CLI running
/// `MAX_PARKED_CLAIMS_PER_HUB` reverse forwards would hold *every* permit
/// on this host essentially forever and every other CLI's `-R` claim
/// would be refused for as long as it kept them — normal operation
/// starving normal operation, which no cap alone can answer. The pool has
/// to be divided, not merely bounded.
///
/// 8 is the quarter share rather than a smaller one because it is the
/// same "generous for real use, far under the shared budget" reasoning
/// [`MAX_PARKED_CLAIMS_PER_HUB`] itself is sized by, one level down: one
/// parked claim per registered `forward_id` means a share of 8 covers a
/// single CLI running eight concurrent reverse forwards against one host,
/// already well past ordinary use, while still leaving three quarters of
/// the hub for everyone else.
#[cfg(unix)]
const MAX_PARKED_CLAIMS_PER_CONDUIT: usize = MAX_PARKED_CLAIMS_PER_HUB / 4;

#[cfg(unix)]
const _: () = assert!(
    MAX_PARKED_CLAIMS_PER_HUB.is_multiple_of(MAX_PARKED_CLAIMS_PER_CONDUIT)
        && MAX_PARKED_CLAIMS_PER_HUB / MAX_PARKED_CLAIMS_PER_CONDUIT >= 4,
    "the per-conduit share must divide the hub pool into at least four full shares, or one \
     conduit at its own share could still deny the hub to everyone else"
);

/// Reset code for a `TCP_ACCEPTED` stream this hub will not carry:
/// malformed shape, or a `forward_id` this hub never registered (already
/// closed, never opened, or — the ordinary race
/// [`crate::tunnel::remote`]'s own `RemoteForwardAcceptor` doc already
/// describes for the direct-connect leg — opened but not yet registered
/// here). Distinct from [`RESET_CODE_TUNNEL_HUB_EXHAUSTED`] so a target
/// inspecting the QUIC error code can tell the two apart, though neither
/// is a documented wire contract (`crate::tunnel::splice`'s own doc on
/// why these codes are internal, like `crate::localctl::daemon`'s
/// `0x2005`/`0x2006` and `crate::tunnel::remote`'s `0x2008`/`0x2009`).
#[cfg(unix)]
const RESET_CODE_TUNNEL_UNKNOWN_FORWARD: u32 = 0x200A;

/// How long a `TCP_ACCEPTED` arrival may sit in [`HubState::tunnel_queue`]
/// unclaimed before [`ControlHub::sweep_expired_arrivals`] resets it and
/// gives its [`MAX_TUNNEL_STREAMS_PER_HUB`] permit back.
///
/// **Why queued arrivals need a life at all** (adversarial review
/// finding): a queued arrival pins one hub tunnel permit *and* one live
/// QUIC bidi stream ([`TunnelArrival`]'s own doc on why the permit is
/// held for the queued time too), and until this existed a queue drained
/// only on a successful claim, on [`ControlHub::unregister_conduit`], or
/// on an owner-checked close — so a claimant that was merely slow, or
/// starved, or simply never came back left its backlog holding hub
/// capacity indefinitely, and that backlog is charged against
/// [`MAX_TUNNEL_STREAMS_PER_HUB`], i.e. against *every other* CLI's
/// tunnels on this host, not just its own.
///
/// 30 s is chosen to be orders of magnitude above the drain rate a
/// healthy claimant actually achieves and still far below any budget an
/// unhealthy one can hold this hub for. A registered `-R`'s claim loop
/// keeps one long-poll parked at all times and re-arms it immediately
/// (`crate::tunnel::remote::claim_remote_forward_reverse`), so an
/// ordinary arrival is claimed in well under a millisecond, and even a
/// full [`MAX_TUNNEL_STREAMS_PER_HUB`] backlog whose every claim is being
/// refused and retried on `crate::tunnel::remote`'s
/// `REVERSE_CLAIM_RETRY_BACKOFF` (200 ms) drains in ~13 s — inside this
/// budget, so contention slows a claimant down without costing it its
/// connections.
#[cfg(unix)]
const MAX_QUEUED_TUNNEL_ARRIVAL_AGE: Duration = Duration::from_secs(30);

/// How often [`Listen::run_tunnel_arrival_sweeper`] wakes to enforce
/// [`MAX_QUEUED_TUNNEL_ARRIVAL_AGE`] — the reason an arrival's real worst
/// case is that age plus one interval rather than exactly that age. Small
/// relative to the age (so the overshoot is a rounding error, not a
/// second budget) and coarse in absolute terms (so a hub with an empty
/// queue — the overwhelmingly common case — costs one uncontended lock
/// acquisition every few seconds and nothing else).
#[cfg(unix)]
const TUNNEL_ARRIVAL_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Reset code for a queued `TCP_ACCEPTED` stream that reached
/// [`MAX_QUEUED_TUNNEL_ARRIVAL_AGE`] with nobody having claimed it.
/// Distinct from [`RESET_CODE_TUNNEL_UNKNOWN_FORWARD`] (the id was real
/// and still registered — the *claimant* never came) and from
/// [`RESET_CODE_TUNNEL_HUB_EXHAUSTED`] (this one was admitted, and held
/// capacity for its whole life), so a target correlating QUIC error codes
/// can tell "nobody was listening for you" from "you were refused at the
/// door". Like its siblings it is internal, not a wire contract
/// (`crate::tunnel::splice`'s own doc).
#[cfg(unix)]
const RESET_CODE_TUNNEL_CLAIM_EXPIRED: u32 = 0x200C;

/// Reset code for a `TCP_ACCEPTED` stream that named a real, still-
/// registered `forward_id` but arrived while this hub was already at
/// [`MAX_TUNNEL_STREAMS_PER_HUB`] — refused before it is ever queued for
/// a claimant, so the cap is exact rather than advisory (`ErrorCode::
/// ResourceExhausted`'s CLI-facing edition of the same refusal is what
/// `crate::localctl::daemon`'s `TCP_CONNECT` leg answers when it hits
/// this same semaphore).
#[cfg(unix)]
const RESET_CODE_TUNNEL_HUB_EXHAUSTED: u32 = 0x200B;

/// One `TCP_ACCEPTED` stream the target opened for a `forward_id` this
/// hub still recognizes, queued for whichever `LOCAL_STREAM` conduit
/// claims that exact `forward_id` next
/// ([`ControlHub::deliver_tcp_accepted`]/[`ControlHub::claim_tcp_accepted`]).
///
/// Carries the [`MAX_TUNNEL_STREAMS_PER_HUB`] permit this stream
/// consumed the moment it was accepted — not acquired again at claim
/// time — so the cap counts a queued-but-unclaimed backlog exactly the
/// same as an actively splicing stream (both hold one of this
/// connection's real QUIC bidi stream slots); dropping a [`TunnelArrival`]
/// that was never claimed (a conduit died first, or the whole hub did)
/// releases the permit automatically along with the streams themselves.
#[cfg(unix)]
pub(crate) struct TunnelArrival {
    send: SendStream,
    recv: RecvStream,
    /// Bytes the target had already pipelined past its own `StreamHeader`
    /// frame by the time [`Listen::run_tunnel_accept_loop`] read the
    /// header off `recv` — `qsh_transport::FramedRecv::into_raw`'s own
    /// doc on why these must lead whatever the claimant's splice
    /// subsequently reads from `recv` directly, not be dropped or
    /// reordered behind it. A `TCP_ACCEPTED` stream carries no
    /// handshake past its header (`v1.proto`'s own comment: "it *is* the
    /// accepted leg"), so the target may already be mid-transfer by the
    /// time this arrival is even queued, let alone claimed.
    residue: Vec<u8>,
    /// When [`ControlHub::deliver_tcp_accepted`] queued this arrival —
    /// the only input [`ControlHub::sweep_expired_arrivals`] needs, and
    /// the reason a queue is drained strictly from its front: arrivals
    /// are pushed in `Instant::now()` order onto the back of a `VecDeque`,
    /// so a queue is always sorted oldest-first and the first
    /// non-expired entry ends the scan.
    queued_at: Instant,
    _permit: OwnedSemaphorePermit,
}

#[cfg(unix)]
impl TunnelArrival {
    /// Reset both halves with `code` rather than letting them drop bare —
    /// a bare `SendStream`/`RecvStream` drop finishes/stops *cleanly*
    /// (quinn's own `Drop`), which would tell the target this accepted
    /// connection ended normally when in fact nobody on the controller
    /// side ever spliced it to anything (`crate::tunnel::splice`'s module
    /// doc: "a truncated transfer that looks like a clean EOF is data
    /// loss the application cannot detect" — the same discipline applies
    /// to a stream that never started, not just one that was cut off
    /// mid-transfer).
    fn reset(mut self, code: u32) {
        let _ = self.send.reset(quinn::VarInt::from_u32(code));
        let _ = self.recv.stop(quinn::VarInt::from_u32(code));
    }

    /// Unpack for the claimant to splice — **including** the permit
    /// ([`MAX_TUNNEL_STREAMS_PER_HUB`]'s own doc: this stream stays
    /// counted against the cap for its whole life, splice included, not
    /// just its time in [`HubState::tunnel_queue`]). The caller must hold
    /// the returned permit alive for as long as it drives the splice and
    /// drop it only once that is done.
    fn into_parts(self) -> (SendStream, RecvStream, Vec<u8>, OwnedSemaphorePermit) {
        (self.send, self.recv, self.residue, self._permit)
    }
}

/// Whether a `ControlMessage` body a conduit is relaying is one of the
/// target's long-poll-classified requests (mirrors
/// `crate::server::is_long_poll`, which this module may not import —
/// `qsh-core::server` is the target-side module and this is the
/// controller-side relay; the classification itself is a wire-contract
/// fact, not shared state, so duplicating the two-arm match here is
/// simpler and safer than reaching across that boundary).
#[cfg(unix)]
fn is_long_poll_body(body: &wire::control_message::Body) -> bool {
    matches!(
        body,
        wire::control_message::Body::SessionRead(_) | wire::control_message::Body::SessionClose(_)
    )
}

/// One delivery `crate::localctl::daemon`'s `LOCAL_CONTROL` conduit-serve
/// loop reads from its inbox and turns into exactly one outbound
/// `qsh.wire.v1.ControlMessage` back to the CLI process.
#[cfg(unix)]
pub enum ConduitInbound {
    /// A correlated reply — `peer_request_id` is already restored
    /// (`ControlMux::map_inbound`), so the conduit only has to wrap it in
    /// a `ControlMessage` and write it.
    Response {
        peer_request_id: u64,
        body: wire::Response,
    },
    /// An asynchronous `SessionEvent` this conduit is owed
    /// (`request_id = 0` on the wire).
    Event(wire::SessionEvent),
    /// This host's reverse QUIC connection died (or was replaced by a
    /// newer registration) — the conduit closes its UDS stream, which is
    /// what gives the CLI-side `Session` on the other end the same
    /// `ClientError::Protocol("peer closed control stream mid-request")`
    /// a genuinely dead QUIC control stream would (`Session::request`'s
    /// own EOF handling) — a real typed error, not a silent hang.
    HostDead,
}

/// Why [`ControlHub::send_request`] could not forward a conduit's request.
#[cfg(unix)]
#[derive(Debug)]
pub enum HubSendError {
    /// `conduit` already has `crate::localctl::mux::MAX_INFLIGHT_PER_CONDUIT`
    /// requests outstanding — the caller answers this one `RESOURCE_EXHAUSTED`
    /// locally, on the same conduit only (`ControlMux::map_outbound`'s own
    /// contract: nothing was allocated or sent).
    Exhausted,
    /// This host's driver (`Listen::drive_registered_session`) has
    /// already exited — there is nobody left to send onto the QUIC
    /// connection. The caller treats this exactly like a mid-flight host
    /// death: the conduit is about to receive (or may already have
    /// received) [`ConduitInbound::HostDead`].
    HostDead,
    /// This conduit asked to close a `forward_id` that belongs to a
    /// *different* conduit on this hub (adversarial-review hole 3).
    /// Nothing was allocated and nothing was sent — the request never
    /// reaches the target, which could not have distinguished the two
    /// conduits itself. The caller answers `PERMISSION_DENIED` on this
    /// conduit alone.
    NotOwner,
}

/// The one claim token that may ever claim a given `forward_id`'s
/// `TCP_ACCEPTED` arrivals — deliberately a type, not a bare `Vec<u8>`,
/// because the invariant it carries is what an adversarial review found
/// missing twice in a row: an *empty* seat used to match any same-uid
/// claimant that presented an empty token, i.e. a capability that
/// silently degraded to "anyone" while the surrounding code still read as
/// though it were protected.
///
/// The inner field is private to this module, so the only way to build a
/// seat anywhere in this crate is [`ClaimSeat::seat`], and the only way
/// to test one is [`ClaimSeat::admits`] — a future edit cannot construct
/// a claimable-but-empty seat, and cannot compare tokens by hand and get
/// the empty case wrong, because it has no access to the bytes at all.
#[cfg(unix)]
mod claim_seat {
    /// See the module-level type doc above the `mod` keyword.
    #[derive(Clone, Debug)]
    pub(super) struct ClaimSeat {
        /// Invariant, enforced by [`ClaimSeat::seat`] being the only
        /// constructor and this field being private: `Some(t)` implies
        /// `!t.is_empty()`. `None` means *permanently unclaimable* — a
        /// registration whose originating `RemoteForwardOpen` carried no
        /// claim token at all. Unclaimable is a terminal state: nothing
        /// re-seats it later (the hub cannot mint one itself — there is
        /// no wire round trip that could ever echo a hub-minted token
        /// back to the requester, so a minted token would lock the
        /// rightful owner out just as hard), so such a registration
        /// exists only to keep its `forward_id` reserved and sweepable,
        /// never to hand a stream to anyone.
        token: Option<Vec<u8>>,
    }

    impl ClaimSeat {
        /// Seat exactly the bytes the originating `RemoteForwardOpen`
        /// carried. Empty in, permanently unclaimable out — an absent or
        /// empty capability is a refusal, never a pass.
        pub(super) fn seat(token: Vec<u8>) -> Self {
            if token.is_empty() {
                Self { token: None }
            } else {
                Self { token: Some(token) }
            }
        }

        /// Whether `presented` may claim this seat. Fails closed on both
        /// halves of the empty case: an unclaimable seat admits nothing,
        /// and an empty presented token is refused even against a seat
        /// that holds real bytes (belt and braces — a non-empty seat can
        /// never equal an empty slice anyway, but this is the line a
        /// future edit is most likely to loosen).
        pub(super) fn admits(&self, presented: &[u8]) -> bool {
            match &self.token {
                Some(seated) => !presented.is_empty() && seated.as_slice() == presented,
                None => false,
            }
        }

        /// Whether this registration can ever hand a stream to anyone —
        /// `false` for the permanently-unclaimable seat above.
        /// [`super::ControlHub::deliver_tcp_accepted`] refuses to *queue*
        /// for an unclaimable registration at all, so an arrival for one
        /// is reset immediately instead of occupying a hub tunnel permit
        /// and a live QUIC stream until the owning conduit happens to die.
        pub(super) fn is_claimable(&self) -> bool {
            self.token.is_some()
        }
    }
}

#[cfg(unix)]
use claim_seat::ClaimSeat;

/// One live `forward_id` registration: the conduit that owns it and the
/// single [`ClaimSeat`] that may ever take its arrivals, as **one entry**
/// rather than two parallel maps (adversarial-review finding: two maps
/// keyed by the same string can diverge, and every path that mutated only
/// one of them was a hole — the close arm that removed both without an
/// owner check, and the claim path that re-checked ownership against the
/// *owner* map while the *token* map was the one that mattered). Inserted
/// and removed as a unit, so "registered" and "has a seat" are the same
/// fact and no edit can separate them.
#[cfg(unix)]
#[derive(Debug)]
struct ForwardRegistration {
    /// The `LOCAL_CONTROL` conduit whose `RemoteForwardOpen` minted this
    /// `forward_id` — the only conduit that may close it
    /// ([`ControlHub::send_request`]'s `RfwdClose` arm and
    /// [`ControlHub::deliver_response`]'s close arm both check it) and
    /// the one whose death sweeps it ([`ControlHub::unregister_conduit`]).
    owner: ConduitId,
    seat: ClaimSeat,
    /// Structural facts about this forward — never payload, exactly the
    /// kind of record `Server::authorize_and_bind_remote_forward`'s own
    /// audit line keeps host-side — kept so `LocalTunnelList`
    /// (`PLAN.md` M4 Step 5 PR 5b) has something to build a
    /// [`qsh_proto::local::LocalTunnel`] from: the Step 4 residual
    /// `PLAN.md` §4 records ("audit 기록이 '요청한 주소'지 '실제로 bind한
    /// 주소'가 아니다... `qsh tunnels`가 bind된 주소를 사용자에게 보여주기
    /// 시작하는 지점이라 같은 정보가 어차피 필요하다") lands here.
    meta: ForwardMeta,
}

/// The structural half of [`ForwardRegistration`] — everything
/// `LocalTunnelList` reports about one forward, and nothing else: no
/// payload byte has ever passed through this type.
#[cfg(unix)]
#[derive(Debug, Clone)]
struct ForwardMeta {
    /// Always `"remote"`: only `-R`'s host-bound listener ever registers a
    /// `forward_id` in [`HubState::forwards`] at all — `-L over reverse`'s
    /// per-connection `TCP_CONNECT`s carry no `forward_id` and never touch
    /// this table (`HubState::forwards`'s own doc; `docs/CLI.md` §6.9's
    /// `Tunnel.mode` vocabulary). Kept as an explicit field, not a literal
    /// at the `LocalTunnel` call site, so nothing there has to re-derive
    /// this claim.
    mode: &'static str,
    /// The address actually bound on this hub's own host machine —
    /// `bind_host` (defaulted to `127.0.0.1` exactly the way
    /// `crate::ops::tunnel::remote_tunnel_dto`'s client-side DTO already
    /// does, for the same reason: an unspecified request bind means
    /// loopback) joined with `RemoteForwardOpened.actual_port`, the
    /// kernel-assigned port when `bind_port` was `0`. This is the address
    /// that exists, not the one the request asked for.
    bind: String,
    /// The same bound port `bind` already carries, kept as a bare `u32`
    /// too so `LocalTunnel.actual_port` (`qsh/local/v1.proto`) never has
    /// to re-parse it back out of the formatted `bind` string — the two
    /// are always constructed together from the one
    /// `RemoteForwardOpened.actual_port` value.
    actual_port: u32,
    /// Where the requester (the controller CLI, on either route) dials
    /// each `TCP_ACCEPTED` — `RemoteForwardOpen.forward_host`:
    /// `forward_port` verbatim.
    forward_to: String,
}

/// [`ControlHub::list_forwards`]'s per-forward answer — a plain, owned
/// copy of [`ForwardMeta`] plus the `forward_id` key it was stored under,
/// so `crate::localctl::daemon`'s `LocalTunnelList` handling
/// (`PLAN.md` M4 Step 5 PR 5b) has a named type to map into
/// [`qsh_proto::local::LocalTunnel`] rather than an anonymous tuple.
///
/// **F3 residual, still open (`PLAN.md` M4 §4).** A forward past this
/// hub's per-conduit parked-claim share (`MAX_PARKED_CLAIMS_PER_CONDUIT`,
/// `docs/design/protocol.md` §11-3's "이 pool은 나뉘어 있다" paragraph) —
/// the "9th forward" scenario — registers exactly like a healthy one:
/// `RemoteForwardOpen` still succeeds, [`Self::list_forwards`] still
/// reports it, and none of the five fields below distinguish it from a
/// forward whose claim loop actually holds a permit and is parked
/// waiting. `qsh tunnels` therefore does **not** close this observability
/// gap — a starved forward still looks, from this listing alone,
/// identical to a working one; the only signal today remains the daemon's
/// own `tracing::warn!` when a claim is refused for lack of a permit. This
/// type has no room for a claim/liveness field without a wire change
/// (`qsh/local/v1.proto`'s `LocalTunnel` would need a new field), so
/// closing this gap for real is left to M5's quota work, per `PLAN.md`'s
/// own framing — this comment is that "still open, not silently dropped"
/// record, not a fix.
#[cfg(unix)]
pub(crate) struct ForwardSummary {
    pub(crate) forward_id: String,
    pub(crate) mode: &'static str,
    pub(crate) bind: String,
    pub(crate) actual_port: u32,
    pub(crate) forward_to: String,
}

/// The address half of an in-flight `RemoteForwardOpen`, captured by
/// [`ControlHub::send_request`] alongside its claim token — see
/// [`HubState::pending_rfwd_opens`]'s own doc for why the two are one
/// entry rather than two maps.
#[cfg(unix)]
#[derive(Debug, Default)]
struct PendingRfwdOpen {
    claim_token: Vec<u8>,
    bind_host: String,
    forward_host: String,
    forward_port: u32,
}

/// This hub's parked-claim pool: the [`MAX_PARKED_CLAIMS_PER_HUB`]
/// ceiling and the [`MAX_PARKED_CLAIMS_PER_CONDUIT`] share enforced
/// **together**, in one non-blocking `try_acquire`, under a small mutex
/// of its own (never `HubState`'s — see [`ControlHub::claim_permits`]).
/// A plain `Semaphore` cannot express the share, and the share is what
/// keeps one CLI's perfectly ordinary steady state from denying `-R` to
/// every other CLI on this host ([`MAX_PARKED_CLAIMS_PER_CONDUIT`]'s own
/// doc).
///
/// **This accounting is fairness, never authorization.** The `owner` it
/// keys on is read out of [`HubState::forwards`] read-only and is
/// advisory: a permit means "you may park", never "you may be delivered
/// to". The single place a claimant's right to an arrival is decided
/// stays [`HubState::admits_claim`], evaluated under the same lock
/// acquisition that pops the arrival, on every wake, against the current
/// seat ([`ControlHub::claim_tcp_accepted`]'s own doc) — nothing here
/// participates in that decision, and a permit granted against a stale,
/// absent or someone else's owner buys nothing but a wait that
/// `admits_claim` then refuses.
///
/// That is also why keying the share on the *owning* conduit is safe
/// rather than a lever a hostile same-uid conduit could pull on someone
/// else's share: parking for any length of time requires passing
/// `admits_claim`, i.e. presenting the seated claim token. A claim with
/// the wrong token is refused on `claim_tcp_accepted`'s first iteration,
/// before it ever awaits, and its permit is released immediately — so it
/// can occupy another conduit's share only for the microseconds that
/// refusal takes, never durably.
#[cfg(unix)]
#[derive(Default)]
struct ClaimPoolState {
    /// Permits outstanding across every bucket — the hub-wide ceiling's
    /// own accounting, kept as a running count rather than summed from
    /// `per_owner` so the ceiling can never drift from the shares.
    total: usize,
    /// `owner -> permits outstanding`. `None` is the bucket for a claim
    /// whose `forward_id` resolved to no live registration at the moment
    /// its permit was taken; such a claim is refused by `admits_claim`
    /// without ever awaiting, but it gets a bucket of its own — bounded
    /// by the same share — rather than a free pass, so the one window in
    /// which it could park (the id becoming registered, to a token the
    /// claimant somehow already holds, between the permit and the claim)
    /// is bounded exactly like every other. Entries are removed when they
    /// hit zero, so this map is never larger than the ceiling.
    per_owner: HashMap<Option<ConduitId>, usize>,
}

#[cfg(unix)]
#[derive(Default)]
struct ClaimPool {
    slots: Mutex<ClaimPoolState>,
}

#[cfg(unix)]
impl ClaimPool {
    /// One permit for `owner`, or `None` when either the hub ceiling or
    /// `owner`'s own share is already spent. Never blocks and never
    /// queues — the same "fail the next one immediately" discipline
    /// [`ControlHub::try_acquire_tunnel_permit`]'s doc states, now with
    /// two reasons to fail that are deliberately indistinguishable to the
    /// caller (both answer the one `ErrorCode::ResourceExhausted` the
    /// hub-wide refusal already answered, so this adds no new observable
    /// class).
    fn try_acquire(self: &Arc<Self>, owner: Option<ConduitId>) -> Option<ClaimPermit> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        if slots.total >= MAX_PARKED_CLAIMS_PER_HUB {
            return None;
        }
        let held = slots.per_owner.get(&owner).copied().unwrap_or(0);
        if held >= MAX_PARKED_CLAIMS_PER_CONDUIT {
            return None;
        }
        // Only ever inserted on the granting path, so a refused acquire
        // leaves no entry behind for an owner that holds nothing.
        slots.per_owner.insert(owner, held + 1);
        slots.total += 1;
        Some(ClaimPermit {
            pool: self.clone(),
            owner,
        })
    }

    /// Give one permit back. Every [`ClaimPermit`] was minted by
    /// [`Self::try_acquire`] (its fields are private, so there is no
    /// other way to build one), which means the bucket being released
    /// always exists and `total` always counts it — the `saturating_sub`
    /// and the `if let` are belt and braces against a future edit, not
    /// live cases.
    fn release(&self, owner: Option<ConduitId>) {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots.total = slots.total.saturating_sub(1);
        if let Some(held) = slots.per_owner.get_mut(&owner) {
            *held -= 1;
            if *held == 0 {
                slots.per_owner.remove(&owner);
            }
        }
    }

    #[cfg(test)]
    fn held_total(&self) -> usize {
        self.slots.lock().unwrap_or_else(|e| e.into_inner()).total
    }
}

/// One parked claim's slot in [`ClaimPool`] — released on drop, exactly
/// like the [`OwnedSemaphorePermit`] it replaces, so
/// `crate::localctl::daemon`'s `serve_tcp_accepted` keeps its existing
/// discipline of dropping it explicitly the instant the parked wait ends
/// (its own comment on why the live splice must be bounded by
/// [`MAX_TUNNEL_STREAMS_PER_HUB`] instead).
#[cfg(unix)]
pub(crate) struct ClaimPermit {
    pool: Arc<ClaimPool>,
    owner: Option<ConduitId>,
}

#[cfg(unix)]
impl Drop for ClaimPermit {
    fn drop(&mut self) {
        self.pool.release(self.owner);
    }
}

#[cfg(unix)]
struct HubState {
    mux: ControlMux,
    next_conduit_id: u64,
    inboxes: HashMap<ConduitId, mpsc::Sender<ConduitInbound>>,
    /// `daemon_request_id -> session_id` for an in-flight `SessionAttach`
    /// only — a `SessionAttach` request already names the session it
    /// wants to subscribe to (unlike `SessionOpen`, whose session id is
    /// born in the *response*), so [`ControlHub::send_request`] records it
    /// here and [`ControlHub::deliver_response`] consumes it once the
    /// matching `Response` (success or not) arrives. Entries a conduit's
    /// death orphans are swept by [`ControlHub::unregister_conduit`].
    pending_attach_subscriptions: HashMap<u64, SessionId>,
    /// `daemon_request_id`s of currently in-flight long-poll-classified
    /// requests (`SessionRead`/`SessionClose`), across every conduit of
    /// this hub combined — the accounting [`MAX_INFLIGHT_LONG_POLL_PER_HUB`]
    /// enforces. A subset of `mux`'s own `inflight` keys; kept as a
    /// separate `HashSet` because `ControlMux` is transport/kind-agnostic
    /// by design (its own module docs) and must not learn what a
    /// `wire::control_message::Body` is.
    long_poll_ids: HashSet<u64>,
    /// `forward_id -> its one [`ForwardRegistration`]` — the
    /// safety-critical table `PLAN.md` M4 Step 5 (a) names: the *only*
    /// place a `forward_id` is ever attributed to a conduit, populated by
    /// [`ControlHub::deliver_response`] the moment (not later) the
    /// matching `RemoteForwardOpened` comes back, and swept in full by
    /// [`ControlHub::unregister_conduit`] the moment that conduit dies —
    /// the same "every insert has exactly one removal" discipline
    /// `ControlMux`'s own module doc states for its table, extended to
    /// this one. A `forward_id` absent here is unregistered (never
    /// opened, already closed, or its owner already dead) and every
    /// tunnel-relay path treats that identically:
    /// [`ControlHub::deliver_tcp_accepted`] refuses to queue a stream for
    /// it, and a `LOCAL_STREAM` claim for it is refused before it can
    /// wait.
    ///
    /// **Owner and claim seat are one entry, never two maps**
    /// (adversarial-review holes 1 and 3): the conduit that owns a
    /// `forward_id` and the one token that may claim it are inserted,
    /// checked and removed together, under this hub's single `state`
    /// mutex, so there is no window in which one exists without the
    /// other and no path that can mutate one while reasoning about the
    /// other. Ownership decides *who may close* (both
    /// [`ControlHub::send_request`]'s `RfwdClose` arm and
    /// [`ControlHub::deliver_response`]'s close arm compare against it);
    /// the seat decides *who may be delivered to*
    /// ([`ControlHub::claim_tcp_accepted`], re-checked on every wake).
    forwards: HashMap<String, ForwardRegistration>,
    /// `daemon_request_id -> (claim_token, requested address/target)` for
    /// an in-flight `RemoteForwardOpen` only — captured by
    /// [`ControlHub::send_request`] from the request body itself
    /// (`wire::RemoteForwardOpen`'s own fields) and consumed by
    /// [`ControlHub::deliver_response`] the instant the matching
    /// `RemoteForwardOpened` registers a *new* `forward_id`, mirroring
    /// `pending_attach_subscriptions`/`pending_rfwd_closes` exactly. A
    /// conduit's death before the reply arrives orphans its entry here
    /// exactly the way it orphans a pending attach subscription — left
    /// alone; nothing here holds a resource that needs releasing.
    ///
    /// **One entry, not two maps** (the same discipline
    /// [`HubState::forwards`]'s own doc states for owner/seat): the claim
    /// token and the request's address fields are both facts about the
    /// same in-flight `RemoteForwardOpen`, read together by the same
    /// registration arm in [`ControlHub::deliver_response`]
    /// (`PLAN.md` M4 Step 5 PR 5b — [`ForwardRegistration::meta`] is
    /// built from the address half, [`ClaimSeat::seat`] from the token
    /// half) — splitting them across two maps would reopen exactly the
    /// divergence hazard that doc warns about, just for a second pair of
    /// fields.
    pending_rfwd_opens: HashMap<u64, PendingRfwdOpen>,
    /// `daemon_request_id -> forward_id` for an in-flight `RemoteForwardClose`
    /// only — mirrors `pending_attach_subscriptions` exactly (a
    /// `RemoteForwardClose` request already names the forward it is
    /// closing; the response is a bare success with no payload of its
    /// own, `v1.proto`'s own comment on the message, so this is the only
    /// way [`ControlHub::deliver_response`] can tell *which* `forward_id`
    /// a bare-success `Response` is closing). Consumed there once the
    /// matching `Response` arrives, success or not; a conduit's death
    /// orphans an entry here exactly the way it orphans a pending attach
    /// subscription — left alone, since nothing here holds a resource
    /// that needs releasing (the *forward's* resource is
    /// `forwards`/`tunnel_queue`, released by
    /// [`ControlHub::unregister_conduit`] regardless of whether a close
    /// was ever in flight).
    pending_rfwd_closes: HashMap<u64, String>,
    /// `forward_id -> TCP_ACCEPTED streams already accepted and waiting
    /// for a `LOCAL_STREAM` conduit to claim them`
    /// ([`ControlHub::deliver_tcp_accepted`]/[`ControlHub::claim_tcp_accepted`]).
    /// An entry only ever exists for a `forward_id` also present in
    /// `forwards` — [`ControlHub::unregister_conduit`] removes both
    /// together, in the same locked section, so there is no window where
    /// one outlives the other.
    tunnel_queue: HashMap<String, VecDeque<TunnelArrival>>,
    /// Set once, by [`ControlHub::mark_dead`], and never cleared —
    /// [`ControlHub::register_conduit`] checks it under the same lock it
    /// registers under, so a conduit that resolves this hub via
    /// [`Listen::control_hub`] and then registers *after* `mark_dead` has
    /// already run (a real window: `crate::localctl::daemon`'s
    /// `serve_control` awaits a UDS write — the `LocalHelloAck` — between
    /// the two) is told immediately instead of being handed a live-looking
    /// hub whose drive loop is already gone and hanging forever with no
    /// timeout on this leg (adversarial review finding).
    dead: bool,
}

#[cfg(unix)]
impl HubState {
    /// **The one place a presented claim token is ever compared against a
    /// seat** (adversarial-review hole 1: the previous shape validated the
    /// token once, at entry to [`ControlHub::claim_tcp_accepted`], and
    /// then re-checked something *else* — mere registration — inside the
    /// wait loop, after popping the arrival. A registration re-seated
    /// while a claimant was parked therefore handed the new owner's
    /// arrival to the old claimant: a textbook check-then-use, sitting on
    /// this PR's central security invariant).
    ///
    /// Callers must call this under the same lock acquisition that
    /// performs the handover, and must not pop anything from
    /// [`Self::tunnel_queue`] before it returns `true` — the guarantee
    /// this function exists to provide is that a token is validated
    /// against the *current* seat at the instant an arrival changes
    /// hands, not at some earlier instant that a concurrent re-seat can
    /// invalidate.
    ///
    /// Fails closed on every ambiguity: an unregistered `forward_id`, a
    /// registration whose seat is permanently unclaimable
    /// ([`ClaimSeat`]'s own doc), and an empty presented token all return
    /// `false`, indistinguishable from one another.
    fn admits_claim(&self, forward_id: &str, presented: &[u8]) -> bool {
        self.forwards
            .get(forward_id)
            .is_some_and(|registration| registration.seat.admits(presented))
    }

    /// Whether `conduit` is the conduit that opened `forward_id` — the
    /// check every teardown path owes (adversarial-review hole 3: the
    /// close arm tore down `forward_id` for whichever conduit's
    /// `RemoteForwardClose` happened to be answered, never comparing
    /// against the conduit `ControlMux::map_inbound` had just resolved,
    /// so any conduit could delete another conduit's registration and
    /// reset its queued arrivals). `false` for an unregistered id too, so
    /// a non-owner's close is indistinguishable from a close for an id
    /// this hub never knew.
    fn is_forward_owner(&self, forward_id: &str, conduit: ConduitId) -> bool {
        self.forwards
            .get(forward_id)
            .is_some_and(|registration| registration.owner == conduit)
    }
}

/// The `LOCAL_CONTROL` relay for one registered host's live reverse
/// connection — what `Listen::drive_registered_session` (the sole
/// owner/driver of that connection's [`Session`]) and
/// `crate::localctl::daemon`'s conduit-serve loop (one per attached CLI
/// process, `N` per host) share: `N` conduits in, one physical QUIC
/// control stream out, `crate::localctl::mux::ControlMux` (Stage A1) kept
/// apart from any I/O behind [`Mutex`] so neither side ever holds it
/// across an await.
///
/// **Ownership/lock model** (module docs, `PLAN.md` M3 Step 6 deliverable
/// 1): a conduit task registers itself, then only ever calls
/// [`Self::send_request`]/[`Self::unregister_conduit`] — synchronous,
/// non-blocking calls under this hub's own `state` mutex, never the
/// [`Registry`] lock and never `Listen::conns`'s. The drive loop is the
/// *only* task that ever reads `Self::take_outbound_receiver`'s channel
/// or writes to the QUIC control stream (`Session::send_control_message`),
/// so two conduits' requests can never interleave on the wire regardless
/// of how many conduits send concurrently — every send this hub relays is
/// queued (an unbounded channel: this hub never blocks a conduit's own
/// request-handling loop waiting for the drive loop to catch up) and the
/// drive loop drains and sends them one at a time, in the order conduits
/// handed them over. This is a *different* lock than `Listen::hubs`/
/// `Listen::conns` (`ConnTable`'s own `Mutex`) and than
/// [`super::registry::Registry`]'s — none of the three is ever held while
/// awaiting another, so there is no lock-order hazard against the
/// registry, the Step 4 probe driver, or the stale sweeper (all of which
/// already only ever touch the registry's own lock).
#[cfg(unix)]
pub struct ControlHub {
    host: String,
    peer_fingerprint: String,
    generation: u64,
    capabilities: Vec<String>,
    state: Mutex<HubState>,
    outbound_tx: mpsc::UnboundedSender<(u64, wire::control_message::Body)>,
    /// Taken exactly once, by the same task that just published this hub
    /// ([`Listen::finish_registration`] → [`Listen::drive_registered_session`],
    /// one hub per registration generation) — see
    /// [`Self::take_outbound_receiver`].
    outbound_rx: Mutex<Option<mpsc::UnboundedReceiver<(u64, wire::control_message::Body)>>>,
    /// [`MAX_TUNNEL_STREAMS_PER_HUB`] permits — a plain `Semaphore`, not
    /// folded into `state`'s `Mutex`, because acquiring one races real
    /// I/O (`open_bi` on the `TCP_CONNECT` leg) that must never run while
    /// holding `state`'s lock (`Self`'s own module doc: nothing here ever
    /// holds `state` across an `.await`).
    tunnel_permits: Arc<Semaphore>,
    /// The parked-claim pool — [`MAX_PARKED_CLAIMS_PER_HUB`] permits
    /// hub-wide, of which any one owning conduit may hold at most
    /// [`MAX_PARKED_CLAIMS_PER_CONDUIT`] ([`ClaimPool`]) — held only
    /// while a `LOCAL_STREAM` `TCP_ACCEPTED` claim is parked inside
    /// [`Self::claim_tcp_accepted`]'s wait (`crate::localctl::daemon`'s
    /// `serve_tcp_accepted` acquires one *before* calling it and drops it
    /// the instant the call returns, granted or not). A separate
    /// `Semaphore` from `tunnel_permits`: that one bounds *relayed tunnel
    /// bytes* (a `TCP_CONNECT`/`TCP_ACCEPTED` stream actually carrying, or
    /// about to carry, a splice); this one bounds *parked waits*, a
    /// distinct resource — the daemon-wide
    /// `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS` permit `serve_authorized_conduit`
    /// already acquired for this conduit is held for the parked call's
    /// *entire* budget (up to `LOCAL_WAIT_MAX`) whether or not anything
    /// ever arrives, so with no per-hub bound of its own one CLI opening
    /// many long-`wait_ms` claims against one host could alone exhaust
    /// that daemon-wide pool and starve every other CLI and every other
    /// host's `SESSION_DATA`/`TCP_CONNECT` conduits too (adversarial
    /// review finding). Sized independently of `tunnel_permits` on
    /// purpose — a parked wait holds no QUIC resource at all, so there is
    /// no reason the two caps need to match. Not a `Semaphore`, because a
    /// semaphore can express the ceiling but not the per-conduit share,
    /// and the share is the half that keeps *ordinary* use (one parked
    /// claim per registered `-R`, re-armed forever) from starving every
    /// other CLI on this host — [`MAX_PARKED_CLAIMS_PER_CONDUIT`]'s own
    /// doc.
    claim_permits: Arc<ClaimPool>,
    /// Broadcasts every [`ControlHub::deliver_tcp_accepted`] call — and
    /// every [`ControlHub::unregister_conduit`] sweep, which removes
    /// registrations out from under whoever is parked on them (finding
    /// F2, in that method) — to every [`ControlHub::claim_tcp_accepted`]
    /// currently waiting; each waiter
    /// re-checks only its own `forward_id`'s queue on wake
    /// ([`Self::claim_tcp_accepted`]'s own doc explains why a shared,
    /// rather than per-`forward_id`, `Notify` is both correct and
    /// sufficient at this scale).
    tunnel_notify: Notify,
}

#[cfg(unix)]
impl ControlHub {
    fn new(
        host: String,
        peer_fingerprint: String,
        generation: u64,
        capabilities: Vec<String>,
    ) -> Arc<Self> {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            host,
            peer_fingerprint,
            generation,
            capabilities,
            state: Mutex::new(HubState {
                mux: ControlMux::new(),
                next_conduit_id: 0,
                inboxes: HashMap::new(),
                pending_attach_subscriptions: HashMap::new(),
                long_poll_ids: HashSet::new(),
                forwards: HashMap::new(),
                pending_rfwd_opens: HashMap::new(),
                pending_rfwd_closes: HashMap::new(),
                tunnel_queue: HashMap::new(),
                dead: false,
            }),
            outbound_tx,
            outbound_rx: Mutex::new(Some(outbound_rx)),
            tunnel_permits: Arc::new(Semaphore::new(MAX_TUNNEL_STREAMS_PER_HUB)),
            claim_permits: Arc::new(ClaimPool::default()),
            tunnel_notify: Notify::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HubState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The `LocalHelloAck` fields for this host's current registration —
    /// `crate::localctl::daemon`'s `LOCAL_CONTROL` serve path builds the
    /// ack directly from this (`host`, `peer_fingerprint`, `generation`,
    /// `capabilities`).
    pub fn ack_fields(&self) -> (String, String, u64, Vec<String>) {
        (
            self.host.clone(),
            self.peer_fingerprint.clone(),
            self.generation,
            self.capabilities.clone(),
        )
    }

    /// Total requests in flight across every registered conduit of this
    /// host (diagnostic only — `crates/qsh-testkit`'s Step 6 coverage uses
    /// this to prove a dead conduit's entries are fully gone from the
    /// multiplexer's table without needing to know its private
    /// [`ConduitId`]; mirrors [`Listen::live_connections`]'s existing
    /// diagnostic-`pub fn` shape).
    pub fn total_in_flight(&self) -> usize {
        let state = self.lock();
        state
            .mux
            .conduit_ids()
            .into_iter()
            .map(|id| state.mux.in_flight_count(id))
            .sum()
    }

    /// [`Listen::drive_registered_session`] takes this exactly once, right
    /// after [`Listen::finish_registration`] publishes this hub — the
    /// sole receiver for every [`Self::send_request`] this hub ever
    /// relays. A second call (there should never be one — one hub is
    /// driven by exactly one task for its entire life) gets `None` rather
    /// than a panic, so a future bug here fails as "conduits on this host
    /// get `HostSendError::HostDead`" instead of taking the process down.
    fn take_outbound_receiver(
        &self,
    ) -> Option<mpsc::UnboundedReceiver<(u64, wire::control_message::Body)>> {
        self.outbound_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// Register a new `LOCAL_CONTROL` conduit — mints a [`ConduitId`],
    /// registers it with the multiplexer, and returns the bounded inbox
    /// `crate::localctl::daemon` reads [`ConduitInbound`] deliveries from
    /// (`Self`'s own doc comment on inbox capacity/slow-reader handling).
    pub fn register_conduit(&self) -> (ConduitId, mpsc::Receiver<ConduitInbound>) {
        let (tx, rx) = mpsc::channel(CONDUIT_INBOX_CAPACITY);
        let mut state = self.lock();
        let id = ConduitId(state.next_conduit_id);
        state.next_conduit_id += 1;
        state.mux.register_conduit(id);
        state.inboxes.insert(id, tx.clone());
        let already_dead = state.dead;
        drop(state);
        if already_dead {
            // See `HubState::dead`'s doc: this hub was marked dead before
            // this conduit got here. The caller's own `select!` loop reads
            // exactly this inbox next, so it learns the host is gone on
            // its very first poll rather than hanging with no timeout.
            let _ = tx.try_send(ConduitInbound::HostDead);
        }
        (id, rx)
    }

    /// Tear down `conduit`: removes everything it owns from the
    /// multiplexer (in-flight requests, event subscriptions —
    /// `ControlMux::unregister_conduit`'s own contract), drops its inbox
    /// sender, and — `PLAN.md` M4 Step 5 (a)'s misdelivery-prevention
    /// requirement — removes **every** `forward_id` this conduit owns
    /// from `HubState::forwards` and resets every `TCP_ACCEPTED`
    /// stream still queued for one of them in `HubState::tunnel_queue`
    /// (`RESET_CODE_TUNNEL_UNKNOWN_FORWARD`: from this instant those ids
    /// are exactly as unregistered as one that never existed, so a
    /// straggling `TCP_ACCEPTED` for one that arrives moments later is
    /// rejected by `Self::deliver_tcp_accepted` the ordinary way — no
    /// separate bookkeeping needed there). No leaked registry entry, no
    /// leaked QUIC stream, and no entry ever outlives the conduit that
    /// owns it. Idempotent — safe to call from both the conduit's own EOF
    /// path and a concurrent host-death sweep racing it (a conduit with
    /// no forwards removes nothing extra).
    pub fn unregister_conduit(&self, conduit: ConduitId) {
        let mut state = self.lock();
        let dropped_ids = state.mux.unregister_conduit(conduit);
        state.inboxes.remove(&conduit);
        for daemon_request_id in dropped_ids {
            state
                .pending_attach_subscriptions
                .remove(&daemon_request_id);
            // Deliberately NOT removed from `state.long_poll_ids` here: a
            // long-poll already dispatched to the target still occupies
            // its real permit (`crate::server::MAX_INFLIGHT_REQUESTS_PER_CONN`)
            // whether or not the conduit that asked for it is still
            // around to hear the answer — there is no wire-level cancel
            // to reclaim it early (`MAX_INFLIGHT_LONG_POLL_PER_HUB`'s
            // doc). Releasing it here instead of when the `Response`
            // actually arrives (`Self::deliver_response`) would let a
            // burst of short-lived dying conduits re-open the hub-wide
            // budget far faster than the target's own permits actually
            // free up, defeating the cap's entire purpose.
        }
        let orphaned_forward_ids: Vec<String> = state
            .forwards
            .iter()
            .filter(|(_, registration)| registration.owner == conduit)
            .map(|(forward_id, _)| forward_id.clone())
            .collect();
        let mut orphaned_arrivals = Vec::new();
        for forward_id in &orphaned_forward_ids {
            // One entry, so owner and claim seat leave together — there
            // is no second map that could keep a stale seat alive for a
            // `forward_id` string a later registration reuses
            // (`HubState::forwards`'s own doc).
            state.forwards.remove(forward_id);
            if let Some(queue) = state.tunnel_queue.remove(forward_id) {
                orphaned_arrivals.extend(queue);
            }
        }
        drop(state);
        // **Finding F2 — wake whoever was parked on what this sweep just
        // removed.** `claim_tcp_accepted` re-validates `admits_claim` on
        // every wake (its own doc), but `tunnel_notify` is the only thing
        // that ever wakes it and until now only `deliver_tcp_accepted`
        // rang it. A daemon task parked on a forward removed here would
        // therefore sit out the rest of its wait budget (up to
        // `qsh_proto::local::LOCAL_WAIT_MAX`) holding a `ClaimPool` permit
        // in a bucket keyed by a `ConduitId` that is never reissued — the
        // hub-wide pool shrinking with no live conduit holding anything,
        // repeatable until the pool is empty. Woken, such a claimant finds
        // no registration, `admits_claim` refuses, it returns `None` and
        // its `ClaimPermit` releases on drop, returning capacity to both
        // its bucket and the hub total (`ClaimPool::release`). Rung
        // unconditionally: `notify_waiters` wakes claimants on other
        // conduits' forwards too, which costs them one re-check under the
        // lock before they park again.
        self.tunnel_notify.notify_waiters();
        for arrival in orphaned_arrivals {
            arrival.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
        }
    }

    /// Forward `conduit`'s request (`peer_request_id`, `body`) onto this
    /// host's live QUIC control stream under a fresh, daemon-chosen
    /// `request_id` (`docs/design/protocol.md` §11-3's "request_id
    /// 재매핑") — never touching the connection at all when `conduit` is
    /// already at cap ([`HubSendError::Exhausted`], per
    /// `ControlMux::map_outbound`'s own contract: nothing allocated or
    /// sent) or when this host's driver has already exited
    /// ([`HubSendError::HostDead`]).
    pub fn send_request(
        &self,
        conduit: ConduitId,
        peer_request_id: u64,
        mut body: wire::control_message::Body,
    ) -> Result<(), HubSendError> {
        let mut state = self.lock();
        let is_long_poll = is_long_poll_body(&body);
        // Hub-wide, across every conduit — checked *before* allocating a
        // `daemon_request_id` at all, so a conduit refused here never
        // touches `mux`'s own per-conduit cap or the connection
        // (`MAX_INFLIGHT_LONG_POLL_PER_HUB`'s doc: this is what actually
        // keeps any one conduit — or any combination of them — from
        // exhausting the target's shared per-connection long-poll budget,
        // which the per-conduit cap alone cannot do).
        if is_long_poll && state.long_poll_ids.len() >= MAX_INFLIGHT_LONG_POLL_PER_HUB {
            return Err(HubSendError::Exhausted);
        }
        // **Adversarial-review hole 3, the outbound half.** A
        // `RemoteForwardClose` naming a `forward_id` this hub has
        // registered to a *different* conduit is refused here, before a
        // `daemon_request_id` is minted and before anything reaches the
        // shared QUIC connection: the daemon is the only component in the
        // system that can tell one CLI's conduit from another's (the
        // target sees a single connection and cannot), so if the relay
        // forwarded it the target would dutifully close another CLI's
        // forward and there would be nothing left for the inbound half to
        // protect. An id this hub does not know is *not* refused — it may
        // be a close racing its own `RemoteForwardOpened`, and the target
        // is the right place to answer for an id nobody here holds.
        //
        // **F7 residual (`PLAN.md` M4 §4).** `HubSendError::NotOwner` vs.
        // "unknown id, forwarded anyway" is, in principle, a `forward_id`
        // existence oracle for a same-uid caller that has to *guess* a
        // `forward_id` it does not already hold — flagged informational
        // pre-5b because `forward_id` is a 128-bit ULID, so guessing one
        // is infeasible regardless. PR 5b's own `LocalTunnelList`
        // ([`Self::list_forwards`]) makes this concern moot rather than
        // worse: any same-uid caller who could mount this oracle already
        // has a strictly more direct route to the same fact — ask the
        // daemon for the list and read every live `forward_id` off it
        // outright, no guessing or `NotOwner`/timing inference required.
        // Nothing here needed to change; this comment is the "reviewed
        // and still acceptable" record `PLAN.md` asked for.
        if let wire::control_message::Body::RfwdClose(close) = &body
            && state.forwards.contains_key(&close.forward_id)
            && !state.is_forward_owner(&close.forward_id, conduit)
        {
            return Err(HubSendError::NotOwner);
        }
        let daemon_request_id = state
            .mux
            .map_outbound(conduit, peer_request_id)
            .map_err(|Exhausted| HubSendError::Exhausted)?;
        if is_long_poll {
            state.long_poll_ids.insert(daemon_request_id);
        }
        if let wire::control_message::Body::SessionAttach(attach) = &body {
            state
                .pending_attach_subscriptions
                .insert(daemon_request_id, SessionId(attach.session_id.clone()));
        }
        if let wire::control_message::Body::RfwdClose(close) = &body {
            // Mirrors the `SessionAttach` case just above — see
            // `HubState::pending_rfwd_closes`'s own doc for why this is
            // the only way `deliver_response` can attribute a bare-
            // success `Response` to the `forward_id` it is closing.
            state
                .pending_rfwd_closes
                .insert(daemon_request_id, close.forward_id.clone());
        }
        if let wire::control_message::Body::RfwdOpen(open) = &mut body {
            // Finding A fix: captured here, under the same lock that just
            // allocated `daemon_request_id`, so `deliver_response` can
            // seat it atomically alongside the registration the instant
            // the matching `RemoteForwardOpened` comes back —
            // `HubState::pending_rfwd_opens`'s own doc.
            //
            // **Finding 5 fix — `mem::take`, not `.clone()`.** `claim_token`
            // is a purely requester-local capability
            // (`wire::RemoteForwardOpen::claim_token`'s own doc: the
            // target never inspects or compares it) that exists solely so
            // *this* seat can be minted; it has no business reaching the
            // peer at all. `LOCAL_CONTROL` has no message shape of its
            // own to carry it on instead — this conduit relays the
            // *exact* `qsh.wire.v1.ControlMessage`/`Response` pair that
            // crosses the QUIC control stream verbatim
            // (`qsh/local/v1.proto`'s own header, `LocalctlDaemon::
            // serve_control`'s `conduit.recv::<wire::ControlMessage>()`
            // at `localctl/daemon.rs`), so taking it here — rather than
            // leaving it in `open` for `.clone()` to copy and the real
            // send below to carry unmodified — is what actually keeps it
            // off the wire: `body` below, the exact value
            // [`Listen::drive_registered_session`]'s `recv_outbound` arm
            // serializes onto the live QUIC connection to the peer, no
            // longer has it once this line runs, regardless of what the
            // requesting CLI process originally sent on its local
            // conduit. See `claim_token`'s own field doc in
            // `qsh/wire/v1.proto` for why the field is not removed from
            // the message outright.
            let claim_token = std::mem::take(&mut open.claim_token);
            state.pending_rfwd_opens.insert(
                daemon_request_id,
                PendingRfwdOpen {
                    claim_token,
                    bind_host: open.bind_host.clone(),
                    forward_host: open.forward_host.clone(),
                    forward_port: open.forward_port,
                },
            );
        }
        drop(state);
        self.outbound_tx
            .send((daemon_request_id, body))
            .map_err(|_| HubSendError::HostDead)
    }

    /// The drive loop's sole entry point for a `Response` arriving on this
    /// host's control stream (`Listen::drive_registered_session`).
    /// Resolves `daemon_request_id` back to the conduit that asked for it
    /// — an unknown id (its conduit already died and had its entries
    /// cleared by [`Self::unregister_conduit`]) is simply dropped, per
    /// `ControlMux::map_inbound`'s own contract, with no exception for a
    /// `SessionOpened` body: session lifetime is decoupled from connection
    /// (or conduit) lifetime by design (`docs/PRD.md`'s core premise), and
    /// the reverse relay must not diverge from that on the forward route.
    /// A CLI that dies between `session.open` and receiving
    /// `SessionOpened` on the forward path leaves a live session on the
    /// target — discoverable via `session.list`, closable via
    /// `session.close` — and never "invisible" or leaked. A dead conduit
    /// here is the same situation: the target already created the
    /// session, it stays alive exactly as it would on the forward route,
    /// and the relay must not originate a `session.close` under the
    /// controller principal that nobody asked for — the relay carries no
    /// business logic of its own and the target would audit that close
    /// against a request that never happened. On a successful
    /// `session.open`/`session.attach`, this establishes that conduit's
    /// event subscription for the (new or named) session
    /// (`docs/design/protocol.md` §11-3's "구독은 그 conduit이
    /// session.open/session.attach 응답을 받은 시점에 성립").
    pub fn deliver_response(&self, daemon_request_id: u64, resp: wire::Response) {
        let mut state = self.lock();
        // Released here, unconditionally — whether or not the id still
        // resolves to a live conduit below — because this is the point
        // where the target's own long-poll permit for it is actually
        // freed (`MAX_INFLIGHT_LONG_POLL_PER_HUB`'s doc explains why this
        // must not happen any earlier, e.g. on conduit death).
        state.long_poll_ids.remove(&daemon_request_id);
        let pending_session_id = state
            .pending_attach_subscriptions
            .remove(&daemon_request_id);
        let pending_rfwd_close = state.pending_rfwd_closes.remove(&daemon_request_id);
        let pending_rfwd_open = state.pending_rfwd_opens.remove(&daemon_request_id);
        let Some((conduit, peer_request_id)) = state.mux.map_inbound(daemon_request_id) else {
            drop(state);
            // The conduit that asked for this died before the reply
            // arrived (`ControlMux::unregister_conduit` already cleared
            // its table entry) — dropped, unconditionally, including a
            // `SessionOpened` body (see this method's own doc comment for
            // why that is correct, not a leak). It already swept
            // `forwards`/`tunnel_queue` for this conduit too, so
            // there is nothing left here to register or remove either.
            return;
        };
        let subscribe_to = match &resp.body {
            Some(wire::response::Body::SessionOpened(opened)) => {
                Some(SessionId(opened.session_id.clone()))
            }
            Some(wire::response::Body::SessionAttached(_)) => pending_session_id,
            _ => None,
        };
        if let Some(session_id) = subscribe_to {
            state.mux.subscribe(conduit, session_id);
        }
        // Tunnel forward-id registry bookkeeping (`PLAN.md` M4 Step 5
        // (a)): registration happens *here*, under the same lock that
        // just resolved `conduit` from `daemon_request_id`, the instant
        // the target's `RemoteForwardOpened` answers the request this
        // conduit issued — never later, and never attributed to any
        // conduit but the one `map_inbound` just proved issued it. A
        // malformed `forward_id` is never seated (peer-ingress shape
        // discipline, `qsh_proto::wire::valid_forward_id`) — the relay
        // does not trust the target to always hand back a well-shaped id
        // it never itself asked for. A `RemoteForwardClose` succeeding
        // (bare `None` body, matched via `pending_rfwd_close`) is the
        // mirror-image teardown, queued arrivals included.
        //
        // **Duplicate `forward_id` is rejected, never adopted**
        // (adversarial review finding): `forward_id` is target-minted
        // (`ulid::Ulid::new()`, `Server::handle_rfwd_open`) and
        // practically unique, but this relay must not *trust* that — a
        // second `RemoteForwardOpened` naming an id already present in
        // `forwards` would otherwise silently move ownership to
        // whichever conduit's request happened to be answered second,
        // handing a different conduit's live registration (and, unclaimed
        // queued arrivals with it) to a conduit that never opened it. The
        // first registration owns the id until it is explicitly closed;
        // every later `RemoteForwardOpened` for the same id is logged and
        // dropped on the floor — not inserted, and not an error reported
        // to anyone, since the *requesting* conduit for this duplicate
        // reply already has its own distinct, valid registration recorded
        // moments earlier under this same `daemon_request_id`'s own first
        // answer; only a target minting the same id twice (a bug or an
        // adversarial target) reaches this branch at all.
        let mut closed_arrivals = Vec::new();
        match &resp.body {
            // **Finding F5 — an answer only counts against the request it
            // answers.** The arms below used to register a `forward_id` on
            // the strength of an `RfwdOpened` *body* alone, with nothing
            // establishing that the request being answered was a
            // `RemoteForwardOpen` at all. A target answering some
            // unrelated request of this conduit's (a `SessionRead`, say)
            // with `RfwdOpened { forward_id: Z }` therefore squatted Z: it
            // was seated under whichever conduit made that unrelated
            // request and — having no pending token to seat — seated
            // permanently unclaimable, so the conduit that later
            // legitimately opened Z fell into the duplicate-rejection arm
            // below and was left holding a forward that never registered
            // and could never be claimed. Silent, and exactly the
            // misdelivery-class failure this registry exists to prevent.
            //
            // `pending_rfwd_open` is `Some` for precisely the ids whose
            // outbound body was an `RfwdOpen`: `send_request` inserts into
            // `pending_rfwd_opens` on that arm and nowhere else, and it
            // inserts the `mem::take`n token even when that token is
            // empty — so a legitimate open that carried none is
            // `Some(PendingRfwdOpen { claim_token: empty, .. })`, still
            // reaches the seating arm below, and is still seated
            // permanently unclaimable by `ClaimSeat::seat` (the
            // empty-means-unclaimable path is unchanged). `None` means
            // the target answered something that was never an open:
            // nothing is registered, and the id stays free for whoever
            // legitimately opens it later.
            Some(wire::response::Body::RfwdOpened(_)) if pending_rfwd_open.is_none() => {
                // The `forward_id` is deliberately not logged here: on
                // this path it is unvalidated peer text (the arms below
                // reach `wire::valid_forward_id` only once this one has
                // been passed), while `daemon_request_id` is daemon-minted
                // and safe.
                tracing::warn!(
                    daemon_request_id,
                    "qsh::tunnel: RemoteForwardOpened answering a request that was not a \
                     RemoteForwardOpen; registering nothing"
                );
            }
            Some(wire::response::Body::RfwdOpened(opened))
                if wire::valid_forward_id(&opened.forward_id)
                    && !state.forwards.contains_key(&opened.forward_id) =>
            {
                // **Ownership fix (adversarial-review findings A and 2):**
                // owner and claim seat are seated *atomically*, as one
                // entry, in the same critical section that resolved
                // `conduit` from `daemon_request_id` — never lazily on
                // whichever `claim_tcp_accepted` call happens to arrive
                // first, and never as two independently-mutable maps. The
                // token seated is exactly what `pending_rfwd_open`
                // above took out of `pending_rfwd_opens` — the bytes
                // *this conduit's own request* carried in
                // `RemoteForwardOpen.claim_token`
                // (`RemoteForwardAcceptor::spawn_reverse` mints it,
                // `RemoteForwardAcceptor::claim_token`'s doc requires the
                // caller send it before calling `register`) — never a
                // value invented here: minting a *different* token at
                // this point would seat a secret the requester can never
                // learn (there is no wire round trip that echoes it back)
                // and would lock every future claim out, itself included.
                //
                // **An absent or empty token is a refusal, not a
                // wildcard** (hole 2): a request that carried none
                // (`ops::tunnel::remote_forward_open_from_spec`'s empty
                // placeholder is the live example) used to seat an
                // *empty* token, and an empty seat matched any same-uid
                // claimant presenting an empty token — a capability that
                // silently meant "anyone". `ClaimSeat::seat` maps empty
                // to the permanently-unclaimable seat instead: the
                // `forward_id` is still recorded (so it stays attributed
                // to this conduit, is swept when it dies, cannot be
                // adopted by a duplicate `RemoteForwardOpened`, and is
                // still closable by its owner) but no claim for it can
                // ever succeed and `deliver_tcp_accepted` refuses to
                // queue anything for it at all.
                let pending = pending_rfwd_open.unwrap_or_default();
                let seat = ClaimSeat::seat(pending.claim_token);
                if !seat.is_claimable() {
                    tracing::warn!(
                        forward_id = %opened.forward_id,
                        "qsh::tunnel: RemoteForwardOpened for a request that carried no claim \
                         token; registering it as permanently unclaimable"
                    );
                }
                // Structural snapshot for `LocalTunnelList` (`PLAN.md` M4
                // Step 5 PR 5b, `ForwardMeta`'s own doc): `bind` is the
                // address that actually exists — the request's
                // `bind_host` (defaulted to loopback, same rule the
                // requester-side DTO applies) joined with the *bound*
                // port `RemoteForwardOpened.actual_port` reports, never
                // the raw requested `bind_port`.
                let bind_host = if pending.bind_host.is_empty() {
                    "127.0.0.1".to_string()
                } else {
                    pending.bind_host
                };
                // `opened.actual_port` is peer-supplied and not validated
                // to fit a real port range before this point. Clamp once
                // and reuse that single `u16` for both `bind`'s port and
                // `meta.actual_port` below — never clamp one and leave
                // the other raw (adversarial-review finding: those two
                // fields disagreeing breaks `docs/CLI.md` §6.9's own
                // stated invariant that a reader never has to re-derive
                // one from the other).
                let actual_port_u16 = u16::try_from(opened.actual_port).unwrap_or(u16::MAX);
                let bind = wire::format_host_port(&bind_host, actual_port_u16);
                let forward_to = wire::format_host_port(
                    &pending.forward_host,
                    u16::try_from(pending.forward_port).unwrap_or(u16::MAX),
                );
                state.forwards.insert(
                    opened.forward_id.clone(),
                    ForwardRegistration {
                        owner: conduit,
                        seat,
                        meta: ForwardMeta {
                            mode: "remote",
                            bind,
                            actual_port: u32::from(actual_port_u16),
                            forward_to,
                        },
                    },
                );
            }
            Some(wire::response::Body::RfwdOpened(opened))
                if wire::valid_forward_id(&opened.forward_id) =>
            {
                tracing::warn!(
                    forward_id = %opened.forward_id,
                    "qsh::tunnel: duplicate RemoteForwardOpened for an already-registered \
                     forward_id; keeping the first registration, ignoring this one"
                );
            }
            None if pending_rfwd_close.is_some() => {
                let forward_id = pending_rfwd_close.as_deref().unwrap_or_default();
                // **Adversarial-review hole 3, the inbound half.** The
                // sibling `RfwdOpened` arm above is careful never to move
                // a registration to a conduit that did not open it; this
                // arm must be exactly as careful about *removing* one. A
                // successful `RemoteForwardClose` tears down
                // `forward_id`'s registration and resets every arrival
                // still queued for it — so answering it without comparing
                // the closing conduit against the registered owner let
                // any conduit delete another conduit's forward and kill
                // its in-flight streams. `send_request` already refuses to
                // relay such a close at all, so reaching here means the
                // registration changed hands (or appeared) between the
                // request going out and its answer coming back: still a
                // non-owner, still refused. A close from a non-owner
                // changes nothing and is indistinguishable from a close
                // for an id this hub never knew — both fall through
                // having mutated no state, and the `Response` itself is
                // still delivered to the conduit that asked, verbatim.
                if state.is_forward_owner(forward_id, conduit) {
                    state.forwards.remove(forward_id);
                    if let Some(queue) = state.tunnel_queue.remove(forward_id) {
                        closed_arrivals.extend(queue);
                    }
                } else {
                    tracing::warn!(
                        forward_id = %forward_id,
                        "qsh::tunnel: RemoteForwardClose answered for a forward_id this conduit \
                         does not own; registry left untouched"
                    );
                }
            }
            _ => {}
        }
        let inbox = state.inboxes.get(&conduit).cloned();
        drop(state);
        for arrival in closed_arrivals {
            arrival.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
        }
        let Some(inbox) = inbox else {
            return;
        };
        if inbox
            .try_send(ConduitInbound::Response {
                peer_request_id,
                body: resp,
            })
            .is_err()
        {
            // The conduit's own reader is stuck or gone — same "treat a
            // full inbox as a dead conduit" discipline this hub's own doc
            // comment on `CONDUIT_INBOX_CAPACITY` describes.
            self.unregister_conduit(conduit);
        }
    }

    /// The drive loop's sole entry point for an asynchronous
    /// `SessionEvent` (`request_id = 0`) arriving on this host's control
    /// stream — fans it out to `ControlMux::route_event`'s targets (every
    /// subscriber, or every registered conduit for `session.writer_changed`,
    /// `docs/CLI.md` §6.4's broadcast contract).
    pub fn deliver_event(&self, event: wire::SessionEvent) {
        let state = self.lock();
        let targets = state.mux.route_event(&event);
        let mut dead = Vec::new();
        for conduit in targets {
            let delivered = state
                .inboxes
                .get(&conduit)
                .map(|inbox| inbox.try_send(ConduitInbound::Event(event.clone())).is_ok());
            if delivered != Some(true) {
                dead.push(conduit);
            }
        }
        drop(state);
        for conduit in dead {
            self.unregister_conduit(conduit);
        }
    }

    /// Every conduit of this host ends together
    /// (`docs/design/protocol.md` §11-3's "역방향 QUIC 연결 자체가 죽으면 그
    /// host의 모든 conduit이 명확한 typed error로 함께 끝난다") — called once,
    /// when `Listen::drive_registered_session`'s select loop exits for
    /// any reason (probe-declared death, a read error, or this generation
    /// being replaced by a newer one). Every live conduit gets one
    /// best-effort [`ConduitInbound::HostDead`] and is then unregistered;
    /// a conduit whose inbox is already full still gets unregistered (and
    /// so still loses its UDS connection once its own send/recv next
    /// fails), just without the explicit courtesy message.
    pub fn mark_dead(&self) {
        // `dead` is set in the same lock acquisition as the snapshot, so
        // any `register_conduit` that acquires the lock afterward is
        // guaranteed to observe it (`HubState::dead`'s doc) — this is
        // exactly what closes the window a conduit racing this call could
        // otherwise fall into.
        let conduits = {
            let mut state = self.lock();
            state.dead = true;
            state.mux.conduit_ids()
        };
        for conduit in conduits {
            if let Some(inbox) = self.lock().inboxes.get(&conduit).cloned() {
                let _ = inbox.try_send(ConduitInbound::HostDead);
            }
            self.unregister_conduit(conduit);
        }
    }

    // ----------------------------------------------------------------
    // Tunnel relay (`PLAN.md` M4 Step 5, PR 5a). Both directions the
    // `LOCAL_STREAM` conduit carries (`docs/design/protocol.md` §11-3):
    // `TCP_CONNECT` (`crate::localctl::daemon::LocalctlDaemon::serve_stream`
    // opens the QUIC bidi itself, so it only needs a permit from
    // [`Self::try_acquire_tunnel_permit`]) and `TCP_ACCEPTED` (the target
    // opens the QUIC bidi; [`Listen::run_tunnel_accept_loop`] accepts it
    // and hands it to [`Self::deliver_tcp_accepted`], `serve_stream`'s
    // `TCP_ACCEPTED` arm claims it via [`Self::claim_tcp_accepted`]).
    // ----------------------------------------------------------------

    /// Acquire one of this hub's [`MAX_TUNNEL_STREAMS_PER_HUB`] permits,
    /// or `None` at the cap — the caller's cue to answer
    /// `ErrorCode::ResourceExhausted` (`TCP_CONNECT`, before `open_bi` —
    /// `crate::localctl::daemon`) or reset the stream with
    /// [`RESET_CODE_TUNNEL_HUB_EXHAUSTED`] (`TCP_ACCEPTED`, before it is
    /// ever queued — [`Self::deliver_tcp_accepted`]'s call site) rather
    /// than commit the resource. Never blocks: `try_acquire`, not
    /// `acquire` — a hub at its cap must fail the *next* stream
    /// immediately, not queue callers behind whichever ones happen to
    /// finish first.
    pub(crate) fn try_acquire_tunnel_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.tunnel_permits.clone().try_acquire_owned().ok()
    }

    /// Acquire one parked-claim permit for `forward_id`'s owning conduit,
    /// or `None` when either this hub's [`MAX_PARKED_CLAIMS_PER_HUB`]
    /// ceiling or that owner's own [`MAX_PARKED_CLAIMS_PER_CONDUIT`]
    /// share is spent — the caller's cue to answer
    /// `ErrorCode::ResourceExhausted` *before* ever calling
    /// [`Self::claim_tcp_accepted`], the same "fail the next one
    /// immediately, never queue behind it" discipline
    /// [`Self::try_acquire_tunnel_permit`]'s own doc states, applied to
    /// the distinct resource [`ControlHub::claim_permits`]'s doc
    /// describes.
    ///
    /// The owner is resolved read-only, in its own lock acquisition that
    /// ends before the pool's is taken (the two are never nested, so
    /// there is no lock-order hazard against anything else that touches
    /// `state`), and is **fairness accounting only** — [`ClaimPool`]'s
    /// own doc on why nothing here is or can become an authorization
    /// decision. An unregistered `forward_id` resolves to `None`, its own
    /// bucket, and is then refused by [`HubState::admits_claim`] inside
    /// the claim itself exactly as before: this call never distinguishes
    /// "no such forward" from "nothing arrived" for the caller, and does
    /// not change which claims succeed — only how many may wait at once.
    pub(crate) fn try_acquire_claim_permit(&self, forward_id: &str) -> Option<ClaimPermit> {
        let owner = self
            .lock()
            .forwards
            .get(forward_id)
            .map(|registration| registration.owner);
        self.claim_permits.try_acquire(owner)
    }

    /// Only for tests: whether `forward_id` currently resolves to a live
    /// registration, and to which conduit — the adversarial cross-conduit
    /// coverage this table exists for (`PLAN.md` M4 Step 5 (a)) needs to
    /// assert on ownership directly, not just on observable splice
    /// behavior.
    #[cfg(test)]
    fn forward_owner(&self, forward_id: &str) -> Option<ConduitId> {
        self.lock()
            .forwards
            .get(forward_id)
            .map(|registration| registration.owner)
    }

    /// Only for tests: whether `forward_id` is registered *and* holds a
    /// seat that can ever admit a claimant — the direct assertion hole 2
    /// owes (`ClaimSeat`'s own doc): a registration is either claimable
    /// with a real token or permanently unclaimable, never "claimable by
    /// anyone presenting nothing".
    #[cfg(test)]
    fn forward_is_claimable(&self, forward_id: &str) -> bool {
        self.lock()
            .forwards
            .get(forward_id)
            .is_some_and(|registration| registration.seat.is_claimable())
    }

    /// Only for tests: the total number of live `forward_id` registrations
    /// this hub currently holds, across every conduit — the precise
    /// "the registry is empty afterwards, not just that the happy path
    /// still works" assertion a conduit-death sweep owes (`PLAN.md` M4
    /// Step 5 (a)): checking each id individually proves only that the
    /// ids a test happened to think of are gone, never that nothing else
    /// was left behind.
    #[cfg(test)]
    fn forward_registry_len(&self) -> usize {
        self.lock().forwards.len()
    }

    /// Only for tests: seat a `forward_id -> conduit` registration
    /// directly, without driving a whole `RemoteForwardOpen`/`Opened`
    /// round trip through [`Self::send_request`]/[`Self::deliver_response`]
    /// — the tunnel-relay unit coverage this hub owes
    /// (`docs/design/testing.md` L2) drives [`Self::deliver_tcp_accepted`]/
    /// [`Self::claim_tcp_accepted`] directly and only needs a registered
    /// id to exist first, not the control-message plumbing that would
    /// normally produce one.
    #[cfg(test)]
    fn register_forward_for_test(&self, forward_id: &str, owner: ConduitId) -> Vec<u8> {
        let token = ulid::Ulid::new().to_string().into_bytes();
        let mut state = self.lock();
        state.forwards.insert(
            forward_id.to_string(),
            ForwardRegistration {
                owner,
                seat: ClaimSeat::seat(token.clone()),
                meta: ForwardMeta {
                    mode: "remote",
                    bind: "127.0.0.1:0".to_string(),
                    actual_port: 0,
                    forward_to: "localhost:0".to_string(),
                },
            },
        );
        token
    }

    /// Every forward this hub currently holds, as one [`ForwardSummary`]
    /// each — `crate::localctl::daemon`'s `LocalTunnelList`
    /// handling (`PLAN.md` M4 Step 5 PR 5b) maps each into a
    /// [`qsh_proto::local::LocalTunnel`], filling `host` itself from the
    /// name this hub is registered under (the same "this table's own key
    /// is the alias" fact `to_local_host` already relies on for
    /// `LocalHost.name`). Read-only — a snapshot, exactly like
    /// [`Registry::snapshot`], never a lock held across anything else.
    pub(crate) fn list_forwards(&self) -> Vec<ForwardSummary> {
        self.lock()
            .forwards
            .iter()
            .map(|(forward_id, registration)| ForwardSummary {
                forward_id: forward_id.clone(),
                mode: registration.meta.mode,
                bind: registration.meta.bind.clone(),
                actual_port: registration.meta.actual_port,
                forward_to: registration.meta.forward_to.clone(),
            })
            .collect()
    }

    /// Close `forward_id` on this hub's **own authority** — the daemon's
    /// `LOCAL_ADMIN` `tunnel.close` handling (`PLAN.md` M4 Step 5 PR 5b),
    /// deliberately a *different* path from [`Self::send_request`]'s
    /// `RfwdClose` relay, which is owner-conduit-gated
    /// (`docs/design/protocol.md` §11-3's "close도 소유 conduit만 할 수
    /// 있다"). That gate exists to stop one **data**-plane conduit from
    /// tearing down another's live registration/in-flight splices — it
    /// says nothing about who may *ask the daemon itself* to close a
    /// forward, and `docs/CLI.md` §2.5's "해당 tunnel의 소유 peer이면 허용"
    /// is a peer-identity statement: every same-uid local process
    /// authenticates to this daemon as the one controller principal that
    /// opened the reverse connection in the first place (`localctl`'s own
    /// same-uid accept check is that trust boundary,
    /// `docs/design/architecture.md` §7), so a *second* CLI process
    /// asking to close a forward the *first* one opened is still the
    /// owning peer asking — `qsh tunnel close <id>` (a brand-new process,
    /// `docs/CLI.md` §6.9's own usage example has no `--host`) could never
    /// work for a daemon-held forward otherwise. This method therefore
    /// acts with the daemon's own authority rather than pretending to be
    /// the opening conduit: it removes the registration and resets every
    /// queued arrival **first** (so no other conduit can be handed
    /// anything for `forward_id` from the instant this call is made,
    /// strictly *strengthening* the misdelivery invariant rather than
    /// weakening it), then best-effort notifies the target with
    /// `RemoteForwardClose` on a bare, uncorrelated `daemon_request_id`
    /// ([`ControlMux::next_bare_request_id`]'s own doc) — nothing here
    /// waits for or depends on that notification landing.
    ///
    /// `false` when `forward_id` names nothing this hub currently holds
    /// (never registered, already closed, or its owning conduit already
    /// dead) — no resource touched, nothing sent, matching every other
    /// `tunnel.close`-on-an-unknown-id outcome (`qsh_proto::TunnelCloseData::closed`'s
    /// own doc: idempotent, not an error).
    pub(crate) fn admin_close_forward(&self, forward_id: &str) -> bool {
        let (found, arrivals, daemon_request_id) = {
            let mut state = self.lock();
            if !state.forwards.contains_key(forward_id) {
                return false;
            }
            state.forwards.remove(forward_id);
            let arrivals = state.tunnel_queue.remove(forward_id).unwrap_or_default();
            let daemon_request_id = state.mux.next_bare_request_id();
            (true, arrivals, daemon_request_id)
        };
        debug_assert!(found);
        // Same wake as `unregister_conduit`'s own sweep — a claimant
        // parked on exactly this `forward_id` must not sit out its whole
        // wait budget holding a `ClaimPool` permit for a registration
        // this call just removed (`unregister_conduit`'s F2 doc).
        self.tunnel_notify.notify_waiters();
        for arrival in arrivals {
            arrival.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
        }
        let _ = self.outbound_tx.send((
            daemon_request_id,
            wire::control_message::Body::RfwdClose(wire::RemoteForwardClose {
                forward_id: forward_id.to_string(),
            }),
        ));
        true
    }

    /// Queue a `TCP_ACCEPTED` stream the target just opened for
    /// `forward_id`, for whichever `LOCAL_STREAM` conduit claims it next
    /// (`Self::claim_tcp_accepted`). `permit` is the
    /// [`Self::try_acquire_tunnel_permit`] the caller already acquired —
    /// threaded in rather than acquired here so the caller can reset the
    /// stream with [`RESET_CODE_TUNNEL_HUB_EXHAUSTED`] *before* ever
    /// reaching this call when none was available, never after ([`Self`]'s
    /// own module doc on why the cap must be exact).
    ///
    /// **The one invariant this whole relay exists to hold**
    /// (`PLAN.md` M4 Step 5 (a)): a `forward_id` this hub does not
    /// currently recognize as registered — never opened, already closed,
    /// or its owning conduit already dead — is refused here,
    /// unconditionally, before the stream is queued for anyone. There is
    /// no path from an unrecognized id to a splice, and no path for one
    /// `forward_id`'s arrival to reach a different `forward_id`'s
    /// claimant: every lookup and every insert in this method is keyed by
    /// the exact string the caller passed, never a position, an order, or
    /// a count.
    ///
    /// `Err` means `forward_id` names no currently-registered forward on
    /// this hub — the caller gets its
    /// `send`/`recv`/`permit` back, still unpacked in the returned
    /// [`TunnelArrival`], specifically so it can [`TunnelArrival::reset`]
    /// them with a real error code — this method itself must never be the
    /// place a rejected stream's ownership silently ends, since a bare
    /// drop here would finish/stop the streams *cleanly* rather than
    /// reset them ([`TunnelArrival::reset`]'s own doc on why that
    /// distinction matters).
    pub(crate) fn deliver_tcp_accepted(
        &self,
        forward_id: &str,
        send: SendStream,
        recv: RecvStream,
        residue: Vec<u8>,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), TunnelArrival> {
        let arrival = TunnelArrival {
            send,
            recv,
            residue,
            queued_at: Instant::now(),
            _permit: permit,
        };
        let mut state = self.lock();
        // Registered *and* claimable — a permanently-unclaimable
        // registration ([`ClaimSeat`]'s own doc) is refused here exactly
        // like an unknown id, so an arrival for one is reset immediately
        // instead of occupying a hub tunnel permit and a live QUIC stream
        // in a queue nobody can ever legitimately drain.
        if !state
            .forwards
            .get(forward_id)
            .is_some_and(|registration| registration.seat.is_claimable())
        {
            return Err(arrival);
        }
        state
            .tunnel_queue
            .entry(forward_id.to_string())
            .or_default()
            .push_back(arrival);
        drop(state);
        self.tunnel_notify.notify_waiters();
        Ok(())
    }

    /// Wait up to `wait` for a `TCP_ACCEPTED` stream queued for
    /// `forward_id` — a stream already sitting in
    /// [`HubState::tunnel_queue`] is returned immediately; otherwise this
    /// waits for [`Self::deliver_tcp_accepted`] to notify.
    ///
    /// **Ownership, not just existence** (adversarial review finding: two
    /// lenses independently caught that ownership gated *delivery* but
    /// this method checked only that `forward_id` was registered to
    /// *someone*, so any same-uid conduit that merely knew a live
    /// `forward_id` could claim another CLI's arrivals — precisely the
    /// cross-conduit misdelivery this whole relay exists to prevent).
    /// `claim_token` is the caller's half of the binding
    /// [`ForwardRegistration`]'s seat describes: the token is seated once,
    /// atomically, when [`Self::deliver_response`] registers the
    /// `forward_id` — never by a claimant — and every claim attempt,
    /// including the rightful owner's own next one and the adversarial
    /// case of a different conduit presenting a different token, is
    /// checked against exactly that seated value by
    /// [`HubState::admits_claim`] **under the same lock acquisition that
    /// would hand the arrival over, on every wake** (hole 1: validating
    /// once at entry and then popping first and re-checking something
    /// else afterwards let a registration re-seated during a parked wait
    /// deliver the new owner's arrival to the old claimant). A mismatch
    /// returns `None`, indistinguishable from an unregistered id (the
    /// caller has no more use for telling the two apart than it already
    /// has for "unregistered" vs "timed out", this method's own next
    /// paragraph). `crate::localctl::daemon`'s
    /// `serve_tcp_accepted` derives `claim_token` from the same
    /// `forward_id\0token` ticket it parses `forward_id` out of, minted
    /// once per [`crate::tunnel::remote::RemoteForwardAcceptor`] instance
    /// and reused for every claim attempt that instance makes, so a
    /// legitimate claim loop's own repeat attempts always present the
    /// same bytes.
    ///
    /// Returns `None` when `forward_id` is not currently registered at
    /// all, when it is registered but to a seat these bytes do not match
    /// (including a registration re-seated mid-wait, and a
    /// permanently-unclaimable one — re-checked on every wake, not just
    /// the first, since the owning conduit can die or be replaced while
    /// this call is waiting: `Self::unregister_conduit`'s sweep), and when the
    /// wait simply times out — the caller cannot and need not tell the
    /// two apart (`crate::localctl::daemon`'s `TCP_ACCEPTED` arm answers
    /// the same `ErrorCode::Timeout` either way, matching every other
    /// `LOCAL_STREAM`/`LOCAL_CONTROL` bounded wait in this file).
    ///
    /// Uses [`Notify::notified`]'s documented `enable()` pattern (create
    /// the notification future and register it as a waiter *before*
    /// re-checking the queue) rather than a bare check-then-`.await` —
    /// `notify_waiters` (unlike `notify_one`) wakes only futures that are
    /// already registered at the moment it runs, so checking first and
    /// registering second would lose a delivery that lands in between.
    pub(crate) async fn claim_tcp_accepted(
        &self,
        forward_id: &str,
        claim_token: &[u8],
        wait: Duration,
    ) -> Option<(SendStream, RecvStream, Vec<u8>, OwnedSemaphorePermit)> {
        let wait_for_arrival = async {
            loop {
                let notified = self.tunnel_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let mut state = self.lock();
                    // **Hole 1 fix — the invariant, not an extra check.**
                    // The presented token is validated against the
                    // *current* seat under the same lock acquisition that
                    // hands an arrival over, on every wake rather than
                    // once at entry, and *before* the queue is touched:
                    // an arrival never leaves `tunnel_queue` until this
                    // has returned `true`, so there is no pop-then-check
                    // window in which a re-seated registration's arrival
                    // can be handed to the previous seat's claimant. This
                    // subsumes the entry-time check the previous shape
                    // did separately (the first iteration runs before any
                    // await, so a mismatched or unregistered id is still
                    // refused immediately, not after waiting out `wait`),
                    // and it subsumes the old "is it still registered"
                    // re-check too, since an unregistered id has no seat
                    // and therefore admits nobody.
                    if !state.admits_claim(forward_id, claim_token) {
                        return None;
                    }
                    if let Some(queue) = state.tunnel_queue.get_mut(forward_id)
                        && let Some(arrival) = queue.pop_front()
                    {
                        return Some(arrival.into_parts());
                    }
                }
                notified.await;
            }
        };
        tokio::time::timeout(wait, wait_for_arrival)
            .await
            .unwrap_or(None)
    }

    /// Reset every queued `TCP_ACCEPTED` arrival that has sat unclaimed
    /// for [`MAX_QUEUED_TUNNEL_ARRIVAL_AGE`], returning how many were
    /// expired — [`Listen::run_tunnel_arrival_sweeper`] drives this on
    /// [`TUNNEL_ARRIVAL_SWEEP_INTERVAL`] for as long as this hub's
    /// connection lives.
    ///
    /// **What it releases.** Both halves of what a queued arrival pins:
    /// the [`MAX_TUNNEL_STREAMS_PER_HUB`] permit it has held since it was
    /// accepted (dropped with the [`TunnelArrival`], so the slot returns
    /// to the pool every other CLI on this host draws from) and the live
    /// QUIC bidi stream itself.
    ///
    /// **Visibly, never silently.** Each expiry is a
    /// [`TunnelArrival::reset`] with [`RESET_CODE_TUNNEL_CLAIM_EXPIRED`]
    /// plus one `warn`, never a bare drop — a bare drop finishes/stops
    /// the stream *cleanly*, telling the target this accepted connection
    /// ended normally when in fact nobody ever spliced it
    /// ([`TunnelArrival::reset`]'s own doc), which is exactly the
    /// undetectable data loss `crate::tunnel::splice`'s module doc
    /// forbids. The log names the `forward_id` and the age only: an id is
    /// `[A-Za-z0-9_-]{1,64}` by construction here (it matched a live
    /// registration to have been queued at all) and payload is never
    /// parsed, let alone logged, on this path — the same purity
    /// `PLAN.md` M4 Step 5 (a) states for the whole relay.
    ///
    /// **What it does not touch.** Only [`HubState::tunnel_queue`]
    /// entries, and only their expired *front* elements. The
    /// `forward_id`'s [`ForwardRegistration`] — its owner and its seat —
    /// is left exactly as it was: an idle `-R` whose backlog aged out is
    /// still a live, claimable forward, and the next arrival for it is
    /// queued normally. Emptied queues are removed, which preserves
    /// [`HubState::forwards`]'s invariant that a `tunnel_queue` entry
    /// only ever exists for a registered id (it only ever removes).
    pub(crate) fn sweep_expired_arrivals(&self) -> usize {
        let now = Instant::now();
        let mut expired: Vec<(String, TunnelArrival)> = Vec::new();
        {
            let mut state = self.lock();
            state.tunnel_queue.retain(|forward_id, queue| {
                while queue.front().is_some_and(|arrival| {
                    now.saturating_duration_since(arrival.queued_at)
                        >= MAX_QUEUED_TUNNEL_ARRIVAL_AGE
                }) {
                    let arrival = queue
                        .pop_front()
                        .expect("the front was just observed to exist");
                    expired.push((forward_id.clone(), arrival));
                }
                !queue.is_empty()
            });
        }
        let count = expired.len();
        for (forward_id, arrival) in expired {
            let age = now.saturating_duration_since(arrival.queued_at);
            tracing::warn!(
                forward_id,
                age_ms = age.as_millis() as u64,
                "qsh::reverse: queued TCP_ACCEPTED went unclaimed past its budget; resetting it \
                 and returning its hub tunnel permit"
            );
            arrival.reset(RESET_CODE_TUNNEL_CLAIM_EXPIRED);
        }
        count
    }

    /// Only for tests: how many permits this hub's tunnel-stream pool
    /// currently has free — the direct assertion the expiry path owes
    /// (`PLAN.md` M4 Step 5 (a)'s hub cap): proving an expired arrival
    /// released its permit needs the pool's own count, not merely that
    /// some later acquire happened to succeed.
    #[cfg(test)]
    fn tunnel_permits_available(&self) -> usize {
        self.tunnel_permits.available_permits()
    }

    /// Only for tests: how many arrivals are queued for `forward_id`.
    #[cfg(test)]
    fn queued_arrival_count(&self, forward_id: &str) -> usize {
        self.lock()
            .tunnel_queue
            .get(forward_id)
            .map_or(0, |queue| queue.len())
    }

    /// Only for tests: how many parked-claim permits are outstanding
    /// across every bucket of this hub's [`ClaimPool`].
    #[cfg(test)]
    fn parked_claims_held(&self) -> usize {
        self.claim_permits.held_total()
    }

    /// Only for tests: pretend every queued arrival was queued `by`
    /// earlier than it was, so the *real* [`Self::sweep_expired_arrivals`]
    /// and the *real* [`MAX_QUEUED_TUNNEL_ARRIVAL_AGE`] can be exercised
    /// deterministically — rather than either sleeping out a 30 s budget
    /// or pausing tokio's clock underneath a live quinn connection, whose
    /// own idle/loss timers would then fire inside the jump and tear the
    /// stream down for an unrelated reason, hiding the very reset this
    /// coverage exists to observe.
    #[cfg(test)]
    fn backdate_queued_arrivals_for_test(&self, by: Duration) {
        let mut state = self.lock();
        for queue in state.tunnel_queue.values_mut() {
            for arrival in queue.iter_mut() {
                arrival.queued_at = arrival
                    .queued_at
                    .checked_sub(by)
                    .expect("test backdating must stay within the monotonic clock's range");
            }
        }
    }
}

/// [`tunnel_close_target`]'s result: which hub (if any, and if
/// unambiguous) `crate::localctl::daemon::LocalctlDaemon::serve_admin_tunnel_close`
/// should act on. Hand-implements [`std::fmt::Debug`] (below) rather than
/// deriving it — [`ControlHub`] itself is not `Debug` (it holds live
/// sockets/tasks, and this whole relay's own discipline is never to log
/// its state as a blob — every log site names specific structural fields
/// instead), so `One`'s variant just prints its host-agnostic shape.
#[cfg(unix)]
pub(crate) enum TunnelCloseTarget<'a> {
    /// No registered host's hub currently holds `tunnel_id`.
    None,
    /// Exactly one hub holds it — the ordinary, unambiguous case.
    One(&'a Arc<ControlHub>),
    /// `tunnel_id` matched a live forward on more than one registered
    /// host's hub at once — carries the match count for the caller's
    /// structural warning log, never the hosts or the id's holder.
    Ambiguous(usize),
}

#[cfg(unix)]
impl std::fmt::Debug for TunnelCloseTarget<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelCloseTarget::None => write!(f, "TunnelCloseTarget::None"),
            TunnelCloseTarget::One(_) => write!(f, "TunnelCloseTarget::One(..)"),
            TunnelCloseTarget::Ambiguous(n) => write!(f, "TunnelCloseTarget::Ambiguous({n})"),
        }
    }
}

/// Pure decision function behind
/// `LocalctlDaemon::serve_admin_tunnel_close` (`PLAN.md` M4 Step 5 PR
/// 5b, `qsh tunnel close <id>`) — factored out here, next to
/// [`ControlHub::list_forwards`]/[`ControlHub::admin_close_forward`], so
/// it can be unit-tested with this module's own `test_hub`/
/// `register_forward_for_test` seams rather than a real
/// `LocalConduit`/UDS round trip.
///
/// **Ambiguity is refused, not resolved by picking one (adversarial-
/// review finding).** `tunnel_id` is `forward_id`, which is target-minted
/// (this module's own §11-3 doc: shape-checked by
/// [`wire::valid_forward_id`] only, never guaranteed unique *across*
/// hosts — only within one hub's own table, `Self::deliver_response`'s
/// "같은 forward_id가 두 번째로 도착하면" paragraph). `LocalTunnelClose`
/// has no `host` to disambiguate with (unlike `LocalTunnel.host` on the
/// listing side), so if the id names a live forward on **more than one**
/// registered host's hub at once, there is no principled way to pick the
/// intended one from this call alone. Scanning with `Iterator::any` and
/// taking the first match over a `HashMap`'s nondeterministic iteration
/// order would silently close whichever hub happened to be checked first
/// — a real, if narrow, "closes the wrong host's tunnel" failure mode a
/// colliding id (accidental, or a non-ULID-minting peer) could trigger.
/// Refusing instead follows this codebase's own default (`CLAUDE.md`:
/// "Fail closed on any ambiguous auth/ACL state").
#[cfg(unix)]
pub(crate) fn tunnel_close_target<'a>(
    hubs: &'a [(String, Arc<ControlHub>)],
    tunnel_id: &str,
) -> TunnelCloseTarget<'a> {
    let mut matches = hubs.iter().filter(|(_, hub)| {
        hub.list_forwards()
            .iter()
            .any(|forward| forward.forward_id == tunnel_id)
    });
    match (matches.next(), matches.next()) {
        (None, _) => TunnelCloseTarget::None,
        (Some((_, hub)), None) => TunnelCloseTarget::One(hub),
        (Some(_), Some(_)) => TunnelCloseTarget::Ambiguous(2 + matches.count()),
    }
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

    /// Accept one inbound connection and run the registration handshake on
    /// it. Mirrors [`crate::server::Server::accept_and_serve`]'s
    /// verify-then-audit shape for a rejected TLS handshake. Reached only
    /// through [`Self::admit`], holding the handshake permit
    /// [`Self::admission`] handed out.
    /// M8 Step 3b (rulings R3/R6): this controller's own connection-count
    /// quota is reserved here — this is its outer role, exactly like
    /// `crate::server::Server::serve_connection` is for the `qsh serve`
    /// accept arm (same host→principal order, same [`crate::quota::
    /// Quotas::reserve_connection`] call) — before [`Self::register_connection`]
    /// (and the `Hello` exchange inside it) ever runs, and released only
    /// after this whole registered session has fully torn down
    /// (`Self::drive_registered_session`'s own `conns.remove_if`, deep
    /// inside the `register_connection(...).await` below — this task's
    /// own `.await` does not return until that has already run). `Listen`
    /// never sees `Principal::Pairing` (pairing is a `qsh serve`-only
    /// concept), so there is only ever this one axis to check, unlike
    /// `Server::serve_connection`'s pairing/regular split.
    async fn accept_and_register_permitted(
        self: Arc<Self>,
        incoming: Incoming,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let peer = incoming.remote_address();
        let result = incoming.accept().await;
        drop(permit);
        match result {
            Ok(conn) => {
                let opener = crate::acl::opener_key(conn.principal(), conn.auth_path());
                let (quota_permit, refused) = match self.quotas.reserve_connection(&opener) {
                    Ok(permit) => (Some(permit), None),
                    Err(kind) => {
                        let records = self.quotas.record_rejection(
                            kind,
                            &opener,
                            peer,
                            self.quotas.now(),
                            None,
                            conn.auth_path(),
                        );
                        crate::audit::write_quota_audit(self.audit.as_ref(), &records);
                        (None, Some(kind))
                    }
                };
                // B3 (type-pinned, M8 Step 3b arbitration): `quota_permit`
                // moves into `register_connection` by value rather than
                // being dropped here — the same "the callee holds it and
                // releases it last" shape `Server::serve_connection`'s two
                // arms now use for their own connection permits. A
                // trailing `drop(quota_permit)` here would compile fine
                // and release the slot before the registered session is
                // actually torn down; moving it in makes that ordering a
                // type error instead of a text convention.
                self.register_connection(conn, quota_permit, refused).await;
            }
            Err(err) => {
                let category = match &err {
                    AcceptError::Unverified(reason) => format!("{reason:?}").to_lowercase(),
                    _ => "handshake".to_string(),
                };
                // Already rejecting the connection outright: a failure to
                // record it doesn't change the outcome, only the
                // diagnostic — same exception as
                // `server::Server::accept_and_serve`.
                if let Err(audit_err) = self
                    .audit
                    .record(&AuditRecord::handshake_rejected(peer, &category))
                {
                    tracing::warn!(%peer, %audit_err, "failed to record handshake rejection");
                }
                tracing::warn!(%peer, %err, "connection rejected");
            }
        }
    }

    /// Run the `Hello` exchange as responder and, on a successful
    /// registration, hand the connection off to
    /// [`Listen::finish_registration`]. Every rejection path already wrote
    /// (and [`crate::handshake::respond`] already drained) its error frame
    /// before returning here — this only has to close.
    ///
    /// M8 Step 3b arbitration B3: `quota_permit` is owned here, not
    /// borrowed or dropped by the caller — released only at the very end
    /// of this function (see the `drop(quota_permit)` there), after the
    /// whole registered session this permit was reserved for has already
    /// run to completion. [`Listen::accept_and_register_permitted`]'s own
    /// doc comment already named the shape this enforces: the slot stays
    /// held for as long as the connection is live.
    async fn register_connection(
        self: Arc<Self>,
        conn: Connection,
        quota_permit: Option<crate::quota::ConnectionPermit>,
        refused: Option<crate::quota::QuotaKind>,
    ) {
        // `Mutex`, not `RefCell`: this reference is captured by the
        // `make_local_hello` closure `handshake::respond` holds across an
        // `.await` inside a `tokio::spawn`ed task, so it must be `Sync`
        // (`RefCell` is not — the borrow-check failure is the compiler
        // catching exactly that). Never actually contended: the closure
        // runs synchronously, once, before `respond` returns.
        let outcome_cell: Mutex<Option<RegisterOutcome>> = Mutex::new(None);
        let result = crate::handshake::respond(&conn, |peer_hello| {
            self.decide_registration(&conn, peer_hello, &outcome_cell, refused)
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
                    // `rollback_target` drops `replaced_entry` back to
                    // `None` if the connection it describes is no longer
                    // `conns`'s live occupant for this name — see its own
                    // doc comment.
                    let replaced =
                        rollback_target(&self.conns, &outcome.entry.name, outcome.replaced_entry);
                    self.registry
                        .rollback(&outcome.entry.name, outcome.entry.generation, replaced);
                }
                conn.close(
                    qsh_transport::endpoint::CLOSE_CODE_PROTOCOL,
                    b"registration refused",
                );
                drop(quota_permit);
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
            drop(quota_permit);
            return;
        };
        self.finish_registration(conn, ctl, peer_hello, outcome)
            .await;
        drop(quota_permit);
    }

    /// The synchronous decision `crate::handshake::respond`'s
    /// `make_local_hello` callback needs: absent `Hello.reverse` is
    /// `UNSUPPORTED` (not an ACL decision — zero resources, zero audit);
    /// present is [`super::admit::admit`], verbatim, with its `Ok` stashed
    /// into `outcome_cell` for [`Listen::register_connection`] to pick up
    /// once the whole `Hello` exchange (this reply included) has actually
    /// gone out.
    ///
    /// M8 Step 3b arbitration (A2/B5, overturning R3 for this arm): the
    /// connection-count `refused` check is consulted only *after*
    /// [`admit`] — this arm's `host.reverse` ACL choke point — has run,
    /// never before it. Checking it first (R3's original placement, still
    /// correct for `crate::server::Server::serve_connection_inner`'s
    /// per-op ACL, which has no handshake-time "would this Hello even be
    /// authorized" concept) made a peer this registry would deny anyway
    /// able to fingerprint the controller's saturation: the exact same
    /// denied `Hello` got `PERMISSION_DENIED` while idle and
    /// `RESOURCE_EXHAUSTED(retryable)` once the connection cap filled —
    /// one bit of "is the host full right now" leaking to principals with
    /// zero authorization (`crate::quota` module doc, `adr-0010-draft.md`
    /// §6: unauthorized principals must never see a quota-shaped answer).
    /// `admit`'s own doc guarantees "every early return leaves the
    /// registry exactly as it was", so an ACL deny here costs nothing to
    /// unwind; an ACL *allow* that this method then discards for quota
    /// reasons does insert into the registry (`admit`'s step 4) and must
    /// be rolled back explicitly below — the same `rollback_target` +
    /// `Registry::rollback` pair `Listen::register_connection`'s own
    /// failed-`Hello`-reply path already uses for the identical shape
    /// (an admitted entry with nothing to drive it).
    fn decide_registration(
        &self,
        conn: &Connection,
        peer_hello: &Hello,
        outcome_cell: &Mutex<Option<RegisterOutcome>>,
        refused: Option<crate::quota::QuotaKind>,
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
                // A2/B5: the ACL choke point above just allowed this
                // registration — only now is it safe to also apply the
                // connection-count refusal decided before this callback
                // ever ran. `refused` is ignored entirely on the `Err`
                // arm below: an ACL-denied peer must never learn whether
                // the controller happens to be at capacity.
                if let Some(kind) = refused {
                    let replaced =
                        rollback_target(&self.conns, &outcome.entry.name, outcome.replaced_entry);
                    self.registry
                        .rollback(&outcome.entry.name, outcome.entry.generation, replaced);
                    return Err(wire::Error::new(
                        ErrorCode::ResourceExhausted,
                        kind.wire_message(),
                        true,
                    ));
                }
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

    /// Publish the registered connection into [`Listen::conns`], close
    /// whatever it replaced, then drive the connection as CLIENT role until
    /// it dies. Race-free regardless of what order two concurrent
    /// same-fingerprint registrations' calls to this method happen to run
    /// in — [`ConnTable::publish`]'s doc comment (`PLAN.md` M3 Step 4 (4),
    /// fixing the KNOWN RACE PR 3b left here — see git blame for that
    /// comment's history).
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
        #[cfg(unix)]
        let capabilities = outcome.entry.capabilities.clone();

        match self.conns.publish(name.clone(), generation, conn.clone()) {
            Published::Installed(Some(old_conn)) => {
                // `Connection::close` is idempotent — safe even if the old
                // connection is already mid-close on its own (e.g. the
                // peer hung up right as it reconnected).
                old_conn.close(CLOSE_CODE_REPLACED, b"replaced by a newer registration");
            }
            Published::Installed(None) => {}
            Published::Superseded(_) => {
                // A newer generation already published under `name` before
                // this call ran (`ConnTable::publish`'s doc comment) — this
                // connection lost the race and must never be driven as
                // this name's live connection. Closing it here, rather
                // than leaving it to be discovered later, is what keeps it
                // from leaking: nothing else references it.
                conn.close(CLOSE_CODE_REPLACED, b"superseded by a newer registration");
                return;
            }
        }

        // `Listen::hubs`'s own doc comment: a second, separately-locked
        // publish under the same generation guard — `Published::Superseded`
        // here (this generation's hub itself losing a race after `conns`
        // already won one) is left unhandled on purpose, nothing to do
        // either way; the hub is simply dropped unpublished.
        #[cfg(unix)]
        {
            let hub = ControlHub::new(name.clone(), fingerprint.clone(), generation, capabilities);
            if let Published::Installed(Some(old_hub)) =
                self.hubs.publish(name.clone(), generation, hub)
            {
                old_hub.mark_dead();
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
    /// frame with `UNSUPPORTED`, creating nothing either way.
    ///
    /// **Step 4: the controller's own liveness watch.** This is the small
    /// probe driver `PLAN.md` M3 Step 4 (b) calls for — reusing
    /// [`PathWatchConfig`]'s judgment policy unchanged, watching this
    /// connection through Stage A's role-agnostic `ProbeSource` blanket
    /// impl on [`Connection`]. Shaped exactly like `ops/session.rs`'s
    /// `pump_attach_control`: [`watch_path`] runs as its own task and only
    /// ever *asks* for a probe via `probes`, this loop is the sole writer
    /// on `session`'s control stream (`Session::send_ping`/`send_pong`), a
    /// `Pong` is bare liveness (`PathWatch::inbound`) while everything else
    /// inbound is liveness *and* activity (`PathWatch::traffic`). When
    /// [`PathWatch::dead`] fires, the loop exits exactly like a read error
    /// would.
    ///
    /// On exit, this generation's [`Listen::conns`] entry is removed —
    /// unless a newer registration already replaced it
    /// ([`ConnTable::remove_if`] returning `false` is exactly that:
    /// [`Listen::finish_registration`] already emitted `"replaced"` for it,
    /// so this must not also emit `"lost"`) — and, only when it was still
    /// this generation's entry, [`Registry::mark_stale`] transitions the
    /// registry entry and a `"lost"` diagnostic is emitted. Actual removal
    /// after `[listen].stale_retention` is [`Listen::run_stale_sweeper`]'s
    /// job, not this method's.
    async fn drive_registered_session(
        self: Arc<Self>,
        mut session: Session,
        name: String,
        fingerprint: String,
        generation: u64,
    ) {
        let watch = PathWatch::new(PathWatchConfig::default());
        let probes = Arc::new(tokio::sync::Notify::new());
        let watchdog = tokio::spawn(watch_path(
            session.connection().clone(),
            watch.clone(),
            probes.clone(),
        ));
        // `PLAN.md` M4 Step 5 (a): the only kind of peer-initiated bidi
        // stream this connection legitimately carries is a `TCP_ACCEPTED`
        // the target opens for a `-R` this hub's own conduits registered
        // (module docs' kind table for every stream `serve_stream`
        // itself opens instead). Its own task, exactly like `watchdog` —
        // see [`Self::spawn_tunnel_accept_loop`]'s doc for the unix/
        // non-unix split.
        let tunnel_accept_task =
            self.spawn_tunnel_accept_loop(session.connection().clone(), &name, generation);

        // `M3 Step 6`: this loop is the one and only reader/writer of
        // `session`'s control stream (this method's own long-standing
        // contract), so it is also the natural sole relay point for every
        // `LOCAL_CONTROL` conduit of this host. `tokio::select!` has no
        // per-branch `#[cfg]` (unlike `futures::select!`), so rather than
        // duplicate this whole loop behind a platform split, every
        // `ControlHub`-touching step below goes through a same-signature
        // `#[cfg(unix)]`/`#[cfg(not(unix))]` twin method
        // (`Self::take_hub_outbound_receiver`/`Self::deliver_hub_response`/
        // `Self::deliver_hub_event`/`Self::mark_hub_dead`/
        // `Self::remove_hub_if`) — a no-op returning the same shape on a
        // non-unix build, where `ControlHub` does not exist at all — so
        // this method's own body stays platform-agnostic end to end.
        let mut outbound_rx = self.take_hub_outbound_receiver(&name, generation);

        loop {
            tokio::select! {
                biased;
                () = watch.dead() => {
                    // `CLOSE_CODE_PATH_DEAD`'s own doc: without this, a
                    // `LOCAL_STREAM` splice pump still reading on this
                    // connection blocks until quinn's 45 s idle timeout,
                    // not this watchdog's own detection budget.
                    session.connection().close(CLOSE_CODE_PATH_DEAD, b"path unresponsive");
                    break;
                }
                () = probes.notified() => {
                    if session.send_ping().await.is_err() {
                        break;
                    }
                }
                outbound = recv_outbound(&mut outbound_rx) => {
                    let Some((daemon_request_id, body)) = outbound else {
                        // Either there was no hub at all (`outbound_rx` was
                        // already `None`, so this can only be reached from
                        // the other arm below), or the hub's `outbound_tx`
                        // was just dropped — a *closed* `mpsc::UnboundedReceiver`
                        // resolves `recv().await` to `Ready(None)`
                        // immediately and forever, not `Pending`, so
                        // leaving `outbound_rx` as `Some(_)` here would
                        // make this `biased` branch win every iteration
                        // and spin at 100% CPU without ever reaching the
                        // `next_control_message()` arm below (adversarial
                        // review finding). Setting it to `None` switches
                        // `recv_outbound` to the `pending()` arm instead,
                        // so this branch truly never produces work again.
                        outbound_rx = None;
                        continue;
                    };
                    let msg = wire::ControlMessage::new(daemon_request_id, body);
                    if session.send_control_message(&msg).await.is_err() {
                        break;
                    }
                }
                message = session.next_control_message() => {
                    let msg = match message {
                        Ok(Some(msg)) => msg,
                        Ok(None) | Err(_) => break,
                    };
                    let request_id = msg.request_id;
                    match msg.body {
                        // The answer to our own liveness probe — proof the
                        // path carries packets, nothing more (mirrors
                        // `pump_attach_control`'s identical comment: counting
                        // this as activity would keep the watchdog inside the
                        // active window forever).
                        Some(wire::control_message::Body::Pong(_)) => watch.inbound(),
                        // Symmetric probing (Step 4): with a `PathWatch`
                        // driving *both* ends of a registered connection,
                        // every `Ping` reaching this arm is the target's
                        // own probe loop (`server::drive_probes`) asking
                        // the same liveness question this side is asking
                        // it — never real session traffic. Counting it as
                        // activity (`PathWatch::traffic`) would re-arm
                        // `active_window` on every reply and pin this
                        // watch to the fast cadence forever — the same
                        // failure mode `PathState::observe_inbound`'s doc
                        // comment already names for an inbound `Pong`,
                        // just from the other message direction. Bare
                        // liveness only.
                        Some(wire::control_message::Body::Ping(_)) => {
                            watch.inbound();
                            if session.send_pong(request_id).await.is_err() {
                                break;
                            }
                        }
                        // `M3 Step 6`: a correlated reply to something
                        // `ControlHub::send_request` forwarded on behalf of
                        // a `LOCAL_CONTROL` conduit — never anything this
                        // driver itself asked for (it only ever sends
                        // `Ping`, which gets a `Pong`, not a `Response`).
                        Some(wire::control_message::Body::Response(resp)) => {
                            watch.traffic();
                            self.deliver_hub_response(&name, generation, request_id, resp);
                        }
                        // `M3 Step 6`: an asynchronous `SessionEvent`
                        // (`request_id = 0`) owed to whichever conduits
                        // subscribed — fanned out via the hub, never this
                        // driver's own business (it opens nothing).
                        Some(wire::control_message::Body::SessionEvent(event)) => {
                            watch.traffic();
                            self.deliver_hub_event(&name, generation, event);
                        }
                        // Everything else the oneof can carry is
                        // request-shaped (`Hello`, every `session_*`/
                        // `exec_start`, or an unknown/reserved number
                        // decoding to `body: None`) — the controller
                        // itself never serves one; refuse rather than
                        // drop, exactly the zero-resource `UNSUPPORTED`
                        // contract `docs/design/protocol.md` §11-3
                        // documents.
                        _ => {
                            watch.traffic();
                            if session.reject_unsupported(request_id).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        watchdog.abort();
        if let Some(task) = tunnel_accept_task {
            task.abort();
        }

        self.mark_hub_dead(&name, generation);

        let still_live = self.conns.remove_if(&name, generation);
        self.remove_hub_if(&name, generation);
        if still_live && self.registry.mark_stale(&name, generation).is_some() {
            RegistrationEvent {
                event: "lost",
                host: &name,
                fingerprint: &fingerprint,
                generation: Some(generation),
            }
            .emit();
        }
    }

    // ------------------------------------------------------------------
    // `ControlHub` access for `Listen::drive_registered_session` — one
    // same-signature `#[cfg(unix)]`/`#[cfg(not(unix))]` pair per step, so
    // that method's own body needs no `#[cfg]` at all (this section's own
    // doc comment there). Every method here takes `(name, generation)`
    // rather than a cached `hub: Option<Arc<ControlHub>>`, trading one
    // extra `ConnTable` lookup per control message (never a hot path —
    // bounded by real CLI activity, not wire throughput) for a
    // `drive_registered_session` body that compiles identically on both
    // platforms.
    // ------------------------------------------------------------------

    /// Take this generation's hub's outbound-relay receiver, if it has a
    /// hub at all (`Listen::hubs`'s own doc comment on the tiny window
    /// where it might not). Called once, before the select loop starts.
    #[cfg(unix)]
    fn take_hub_outbound_receiver(
        &self,
        name: &str,
        generation: u64,
    ) -> Option<mpsc::UnboundedReceiver<(u64, wire::control_message::Body)>> {
        self.hubs
            .get_matching(name, generation)
            .and_then(|hub| hub.take_outbound_receiver())
    }

    #[cfg(not(unix))]
    fn take_hub_outbound_receiver(
        &self,
        _name: &str,
        _generation: u64,
    ) -> Option<mpsc::UnboundedReceiver<(u64, wire::control_message::Body)>> {
        None
    }

    /// Route one correlated `Response` through this generation's hub, if
    /// it still has one — see [`ControlHub::deliver_response`].
    #[cfg(unix)]
    fn deliver_hub_response(
        &self,
        name: &str,
        generation: u64,
        request_id: u64,
        resp: wire::Response,
    ) {
        if let Some(hub) = self.hubs.get_matching(name, generation) {
            hub.deliver_response(request_id, resp);
        }
    }

    #[cfg(not(unix))]
    fn deliver_hub_response(
        &self,
        _name: &str,
        _generation: u64,
        _request_id: u64,
        _resp: wire::Response,
    ) {
    }

    /// Fan one asynchronous `SessionEvent` out through this generation's
    /// hub, if it still has one — see [`ControlHub::deliver_event`].
    #[cfg(unix)]
    fn deliver_hub_event(&self, name: &str, generation: u64, event: wire::SessionEvent) {
        if let Some(hub) = self.hubs.get_matching(name, generation) {
            hub.deliver_event(event);
        }
    }

    #[cfg(not(unix))]
    fn deliver_hub_event(&self, _name: &str, _generation: u64, _event: wire::SessionEvent) {}

    /// End every conduit of this generation's hub together, if it still
    /// has one — see [`ControlHub::mark_dead`]. Called once, right after
    /// the select loop exits, before [`Self::conns`]/[`Self::hubs`] are
    /// cleaned up (so a conduit racing a lookup in between still finds a
    /// hub, just one already mid-teardown, rather than none at all).
    #[cfg(unix)]
    fn mark_hub_dead(&self, name: &str, generation: u64) {
        if let Some(hub) = self.hubs.get_matching(name, generation) {
            hub.mark_dead();
        }
    }

    #[cfg(not(unix))]
    fn mark_hub_dead(&self, _name: &str, _generation: u64) {}

    /// [`ConnTable::remove_if`] on [`Self::hubs`] — the hub-table
    /// counterpart to the `self.conns.remove_if(&name, generation)` this
    /// runs alongside.
    #[cfg(unix)]
    fn remove_hub_if(&self, name: &str, generation: u64) {
        let _ = self.hubs.remove_if(name, generation);
    }

    #[cfg(not(unix))]
    fn remove_hub_if(&self, _name: &str, _generation: u64) {}

    /// Spawn [`Self::run_tunnel_accept_loop`] for this generation's hub,
    /// if it still has one (the same tiny window [`Self::hubs`]'s own doc
    /// comment describes) — `None` here just means no `TCP_ACCEPTED`
    /// stream can ever be delivered for this generation, not a startup
    /// failure worth surfacing; a `-R` opened through it would simply
    /// have nowhere to register a `forward_id` either.
    #[cfg(unix)]
    fn spawn_tunnel_accept_loop(
        &self,
        conn: Connection,
        name: &str,
        generation: u64,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let hub = self.hubs.get_matching(name, generation)?;
        Some(tokio::spawn(Listen::run_tunnel_accept_loop(conn, hub)))
    }

    #[cfg(not(unix))]
    fn spawn_tunnel_accept_loop(
        &self,
        _conn: Connection,
        _name: &str,
        _generation: u64,
    ) -> Option<tokio::task::JoinHandle<()>> {
        None
    }

    /// Accept every peer-initiated bidi stream on `conn` for as long as
    /// it lives — on a registered reverse connection that is, exactly,
    /// every `TCP_ACCEPTED` stream the target opens for one of this
    /// hub's registered `forward_id`s (`PLAN.md` M4 Step 5 (a),
    /// `docs/design/protocol.md` §11-3's "-R(remote forward)이 역방향 위에서
    /// 도는 경로"). Ends on its own — no cancellation token needed — the
    /// moment `accept_bi` reports the connection is gone; the caller
    /// (`Self::drive_registered_session`) also aborts this task's handle
    /// explicitly the moment its own loop exits, so a connection that
    /// dies by some path other than `accept_bi` noticing (e.g. this
    /// generation replaced by a newer one, `CLOSE_CODE_REPLACED`) does
    /// not leave this loop parked on a connection nothing else is using.
    ///
    /// Each accepted stream is handled on its own spawned task
    /// ([`Self::handle_tcp_accepted_stream`]) so one slow/adversarial
    /// header never blocks the next `accept_bi` — the same reasoning
    /// [`crate::tunnel::remote::dispatch_remote_forwards`]'s doc gives for
    /// the direct-connect leg's mirror-image accept loop.
    #[cfg(unix)]
    async fn run_tunnel_accept_loop(conn: Connection, hub: Arc<ControlHub>) {
        // The queued-arrival sweeper lives exactly as long as this loop
        // does — its own task rather than a `select!` arm here, so
        // nothing can make `accept_bi`'s future be dropped mid-poll, and
        // guarded by [`AbortOnDrop`] rather than joined, because this
        // loop is normally ended by the caller's `.abort()` and an
        // aborted task's locals are dropped at its next poll point (which
        // is what runs the guard). Same lifetime, same connection: a hub
        // whose connection is gone has already had every queue drained by
        // `ControlHub::mark_dead`'s per-conduit sweep, so there is
        // nothing left for a sweeper to do past this point.
        let _sweeper = AbortOnDrop(tokio::spawn(Listen::run_tunnel_arrival_sweeper(
            hub.clone(),
        )));
        loop {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    tokio::spawn(Listen::handle_tcp_accepted_stream(send, recv, hub.clone()));
                }
                Err(_) => return,
            }
        }
    }

    /// Enforce [`MAX_QUEUED_TUNNEL_ARRIVAL_AGE`] on this hub's queued
    /// `TCP_ACCEPTED` arrivals every [`TUNNEL_ARRIVAL_SWEEP_INTERVAL`]
    /// ([`ControlHub::sweep_expired_arrivals`]'s own doc on why a queued
    /// arrival needs a bounded life at all). Never ends on its own —
    /// [`Self::run_tunnel_accept_loop`]'s `AbortOnDrop` guard ends it,
    /// whether that loop returned or was aborted.
    ///
    /// `MissedTickBehavior::Delay`: if the runtime is busy enough that a
    /// tick is missed, the next sweep should be one interval *later*, not
    /// a burst of catch-up sweeps that each take this hub's lock for
    /// nothing.
    #[cfg(unix)]
    async fn run_tunnel_arrival_sweeper(hub: Arc<ControlHub>) {
        let mut ticker = tokio::time::interval(TUNNEL_ARRIVAL_SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            hub.sweep_expired_arrivals();
        }
    }

    /// One accepted stream's whole life on this leg: read its
    /// `StreamHeader` (bounded by `crate::server::HEADER_TIMEOUT`, the
    /// same bound the direct-connect requester leg uses for the identical
    /// read), require `TCP_ACCEPTED` and a shape-valid `forward_id`
    /// ticket (`qsh_proto::wire::valid_forward_id` — checked **before**
    /// the registry lookup, `PLAN.md` M4 Step 5 (a)), take a
    /// [`MAX_TUNNEL_STREAMS_PER_HUB`] permit, then hand it to
    /// [`ControlHub::deliver_tcp_accepted`]. Every rejection path resets
    /// the stream and touches nothing else — no permit taken for a
    /// malformed header, no queue entry for an unregistered id, no partial
    /// pipe ever started (`PLAN.md` M4 Step 5 (a)'s explicit requirement).
    ///
    /// Never logs the ticket's bytes on a rejection, only its length — the
    /// same `qsh_proto::wire::sanitize_peer_text` discipline
    /// `crate::tunnel::remote::handle_accepted_stream`'s identical check
    /// documents, and for the identical reason: past `valid_forward_id`
    /// the string is `[A-Za-z0-9_-]{1,64}` by construction and safe to
    /// log as-is, but a string that *failed* the check is arbitrary
    /// peer-controlled text.
    #[cfg(unix)]
    async fn handle_tcp_accepted_stream(send: SendStream, recv: RecvStream, hub: Arc<ControlHub>) {
        let mut stream = qsh_transport::FramedStream::data(send, recv);
        let header: wire::StreamHeader = match tokio::time::timeout(
            crate::server::HEADER_TIMEOUT,
            stream.recv.recv::<wire::StreamHeader>(),
        )
        .await
        {
            Ok(Ok(Some(h))) => h,
            _ => {
                stream.send.reset(crate::server::RESET_CODE_BAD_HEADER);
                stream.recv.stop(crate::server::RESET_CODE_BAD_HEADER);
                return;
            }
        };
        if header.stream_kind() != Some(wire::StreamKind::TcpAccepted) {
            tracing::debug!(
                kind = header.kind,
                "qsh::reverse: unexpected peer-opened stream kind on a registered connection"
            );
            stream.send.reset(crate::server::RESET_CODE_BAD_HEADER);
            stream.recv.stop(crate::server::RESET_CODE_BAD_HEADER);
            return;
        }
        let forward_id = match String::from_utf8(header.ticket.clone()) {
            Ok(id) if wire::valid_forward_id(&id) => id,
            _ => {
                tracing::warn!(
                    ticket_len = header.ticket.len(),
                    "qsh::reverse: TCP_ACCEPTED with a malformed forward_id ticket"
                );
                stream.send.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
                stream.recv.stop(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
                return;
            }
        };
        let Some(permit) = hub.try_acquire_tunnel_permit() else {
            tracing::warn!(
                forward_id,
                "qsh::reverse: this hub's tunnel-stream cap is exhausted; rejecting TCP_ACCEPTED"
            );
            stream.send.reset(RESET_CODE_TUNNEL_HUB_EXHAUSTED);
            stream.recv.stop(RESET_CODE_TUNNEL_HUB_EXHAUSTED);
            return;
        };

        // Past this point the stream is a raw byte pipe — same residue
        // handoff `crate::tunnel::remote::handle_accepted_stream`'s
        // identical `TCP_ACCEPTED` leg documents. `residue` cannot be
        // written anywhere yet: nobody has claimed this `forward_id` —
        // possibly nobody ever will — so it travels inside the queued
        // [`TunnelArrival`] instead of being flushed here.
        let (send_half, recv_half) = stream.split();
        let raw_send = send_half.into_raw();
        let (raw_recv, residue) = recv_half.into_raw();
        if let Err(rejected) =
            hub.deliver_tcp_accepted(&forward_id, raw_send, raw_recv, residue, permit)
        {
            // `deliver_tcp_accepted` never inserted anything and handed
            // the streams straight back, still owning their permit — this
            // is the ordinary, expected race
            // `crate::tunnel::remote::RESET_CODE_UNKNOWN_FORWARD`'s own
            // doc describes for the direct-connect leg's mirror-image
            // case (a `TCP_ACCEPTED` outrunning the control round trip
            // that would have registered it, or simply arriving after the
            // forward was already closed) — not necessarily a hostile
            // one, but rejected identically either way: reset, nothing
            // spliced, permit released.
            tracing::warn!(
                forward_id,
                "qsh::reverse: TCP_ACCEPTED for an unregistered forward_id"
            );
            rejected.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
        }
        // `Ok(())`: queued in `hub`'s `tunnel_queue`, owning its permit,
        // for `ControlHub::claim_tcp_accepted` to hand to a `LOCAL_STREAM`
        // conduit — nothing further to do on this task.
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
