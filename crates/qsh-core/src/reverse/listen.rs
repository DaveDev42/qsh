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
//! [`run_listen_unix`] also binds this process's `localctl` UDS admin
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
#[cfg(any(unix, test))]
use crate::acl::AllowAllPinned;
use crate::acl::Authorizer;
#[cfg(unix)]
use crate::audit::FileAuditSink;
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

    let audit = Arc::new(FileAuditSink::new(paths.audit_log()));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let registry = Registry::new(clock.clone(), config.listen.allow_advertised_names);
    let listen = Listen::new(
        registry,
        Arc::new(AllowAllPinned),
        audit,
        identity.identity.device_id.clone(),
        clock,
        stale_retention,
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
/// [`crate::localctl::mux::MAX_INFLIGHT_PER_CONDUIT`] (64 in-flight
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
    /// `conduit` already has [`crate::localctl::mux::MAX_INFLIGHT_PER_CONDUIT`]
    /// requests outstanding — the caller answers this one `RESOURCE_EXHAUSTED`
    /// locally, on the same conduit only (`ControlMux::map_outbound`'s own
    /// contract: nothing was allocated or sent).
    Exhausted,
    /// This host's driver ([`Listen::drive_registered_session`]) has
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
    /// `daemon_request_id -> claim_token` for an in-flight `RemoteForwardOpen`
    /// only — captured by [`ControlHub::send_request`] from the request
    /// body itself (`wire::RemoteForwardOpen::claim_token`) and consumed
    /// by [`ControlHub::deliver_response`] the instant the matching
    /// `RemoteForwardOpened` registers a *new* `forward_id`, mirroring
    /// `pending_attach_subscriptions`/`pending_rfwd_closes` exactly. A
    /// conduit's death before the reply arrives orphans its entry here
    /// exactly the way it orphans a pending attach subscription — left
    /// alone; nothing here holds a resource that needs releasing.
    pending_rfwd_open_claim_tokens: HashMap<u64, Vec<u8>>,
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
/// connection — what [`Listen::drive_registered_session`] (the sole
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
/// [`Registry`] lock and never [`Listen::conns`]'s. The drive loop is the
/// *only* task that ever reads [`Self::take_outbound_receiver`]'s channel
/// or writes to the QUIC control stream (`Session::send_control_message`),
/// so two conduits' requests can never interleave on the wire regardless
/// of how many conduits send concurrently — every send this hub relays is
/// queued (an unbounded channel: this hub never blocks a conduit's own
/// request-handling loop waiting for the drive loop to catch up) and the
/// drive loop drains and sends them one at a time, in the order conduits
/// handed them over. This is a *different* lock than [`Listen::hubs`]/
/// [`Listen::conns`] (`ConnTable`'s own `Mutex`) and than
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
                pending_rfwd_open_claim_tokens: HashMap::new(),
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
    /// from [`HubState::forwards`] and resets every `TCP_ACCEPTED`
    /// stream still queued for one of them in [`HubState::tunnel_queue`]
    /// (`RESET_CODE_TUNNEL_UNKNOWN_FORWARD`: from this instant those ids
    /// are exactly as unregistered as one that never existed, so a
    /// straggling `TCP_ACCEPTED` for one that arrives moments later is
    /// rejected by [`Self::deliver_tcp_accepted`] the ordinary way — no
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
            // `HubState::pending_rfwd_open_claim_tokens`'s own doc.
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
            state
                .pending_rfwd_open_claim_tokens
                .insert(daemon_request_id, claim_token);
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
        let pending_claim_token = state
            .pending_rfwd_open_claim_tokens
            .remove(&daemon_request_id);
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
            // `pending_claim_token` is `Some` for precisely the ids whose
            // outbound body was an `RfwdOpen`: `send_request` inserts into
            // `pending_rfwd_open_claim_tokens` on that arm and nowhere
            // else, and it inserts the `mem::take`n token even when that
            // token is empty — so a legitimate open that carried none is
            // `Some(empty)`, still reaches the seating arm below, and is
            // still seated permanently unclaimable by `ClaimSeat::seat`
            // (the empty-means-unclaimable path is unchanged). `None`
            // means the target answered something that was never an open:
            // nothing is registered, and the id stays free for whoever
            // legitimately opens it later.
            Some(wire::response::Body::RfwdOpened(_)) if pending_claim_token.is_none() => {
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
                // token seated is exactly what `pending_claim_token`
                // above took out of `pending_rfwd_open_claim_tokens` —
                // the bytes *this conduit's own request* carried in
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
                let seat = ClaimSeat::seat(pending_claim_token.unwrap_or_default());
                if !seat.is_claimable() {
                    tracing::warn!(
                        forward_id = %opened.forward_id,
                        "qsh::tunnel: RemoteForwardOpened for a request that carried no claim \
                         token; registering it as permanently unclaimable"
                    );
                }
                state.forwards.insert(
                    opened.forward_id.clone(),
                    ForwardRegistration {
                        owner: conduit,
                        seat,
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
    /// when [`Listen::drive_registered_session`]'s select loop exits for
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
            },
        );
        token
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

#[cfg(all(test, unix))]
mod control_hub_tests {
    use super::*;

    fn hub() -> Arc<ControlHub> {
        ControlHub::new("widget".into(), "sha256:deadbeef".into(), 1, Vec::new())
    }

    fn read_body(after: u64) -> wire::control_message::Body {
        wire::control_message::Body::SessionRead(wire::SessionRead {
            session_id: "s1".into(),
            after,
            max_bytes: 0,
            wait_ms: 30_000,
            ctl_after: 0,
        })
    }

    fn list_body() -> wire::control_message::Body {
        wire::control_message::Body::SessionList(wire::SessionList {})
    }

    fn opened_response(session_id: &str) -> wire::Response {
        wire::Response {
            body: Some(wire::response::Body::SessionOpened(wire::SessionOpened {
                session_id: session_id.to_string(),
                resume_token: Vec::new(),
                ticket: Vec::new(),
                initial_seq: 0,
                expires_at: String::new(),
            })),
        }
    }

    /// The BLOCKER this cap exists to close (adversarial review finding):
    /// a per-conduit cap of the same magnitude as the target's shared
    /// per-connection long-poll budget does not bound the shared
    /// resource at all — one conduit, entirely within its own allowance,
    /// can occupy the whole thing. Proven directly against
    /// `ControlHub::send_request`: conduit A alone hits the *hub-wide*
    /// cap well below its own per-conduit cap, and — the actual
    /// cross-conduit denial — a completely different conduit B is
    /// refused a long-poll it never asked much of, while a non-long-poll
    /// request from B still goes through (the cap is scoped to
    /// `SessionRead`/`SessionClose` only).
    #[test]
    fn long_poll_cap_is_hub_wide_not_per_conduit() {
        let hub = hub();
        let (a, _rx_a) = hub.register_conduit();
        let (b, _rx_b) = hub.register_conduit();

        for i in 0..MAX_INFLIGHT_LONG_POLL_PER_HUB as u64 {
            hub.send_request(a, i, read_body(i))
                .expect("under the hub-wide cap");
        }
        const _: () = assert!(
            MAX_INFLIGHT_LONG_POLL_PER_HUB < crate::localctl::mux::MAX_INFLIGHT_PER_CONDUIT,
            "the whole point of this cap is to bind tighter than the per-conduit one"
        );
        assert!(
            matches!(
                hub.send_request(a, 9999, read_body(9999)),
                Err(HubSendError::Exhausted)
            ),
            "conduit a is still far under its own per-conduit cap, but the hub-wide \
             long-poll budget is spent"
        );

        // The actual DoS this finding demonstrated: a *different* conduit
        // that has sent nothing at all is refused too, because the shared
        // budget — not either conduit's own allowance — is what is
        // spent.
        assert!(
            matches!(
                hub.send_request(b, 0, read_body(0)),
                Err(HubSendError::Exhausted)
            ),
            "conduit b must be denied a long-poll while the hub-wide budget is \
             saturated, even though b itself sent nothing"
        );

        // Only long-poll-classified requests are bounded by this cap — a
        // plain request from the otherwise-blocked conduit still goes
        // through untouched.
        assert!(
            hub.send_request(b, 1, list_body()).is_ok(),
            "a non-long-poll request must never be refused by the long-poll cap"
        );
    }

    /// A dying conduit must not hand its share of the hub-wide long-poll
    /// budget back early — the target-side permit it occupied is not
    /// actually freed just because nobody is listening for the answer any
    /// more (`MAX_INFLIGHT_LONG_POLL_PER_HUB`'s doc: there is no
    /// wire-level cancel). The budget is only released when the `Response`
    /// actually arrives, however late.
    #[tokio::test]
    async fn conduit_death_does_not_free_the_long_poll_budget_but_the_late_response_does() {
        let hub = hub();
        let (a, _rx_a) = hub.register_conduit();
        let (b, _rx_b) = hub.register_conduit();

        for i in 0..MAX_INFLIGHT_LONG_POLL_PER_HUB as u64 {
            hub.send_request(a, i, read_body(i)).unwrap();
        }
        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");
        let mut sent_ids = Vec::new();
        for _ in 0..MAX_INFLIGHT_LONG_POLL_PER_HUB {
            let (daemon_request_id, _) = outbound.recv().await.expect("queued send");
            sent_ids.push(daemon_request_id);
        }

        hub.unregister_conduit(a);
        assert!(
            matches!(
                hub.send_request(b, 0, read_body(0)),
                Err(HubSendError::Exhausted)
            ),
            "a's death alone must not free target-side long-poll capacity nobody \
             actually reclaimed"
        );

        // The (late) `Response` for one of a's now-orphaned long-polls
        // arrives — this is what actually frees its slot.
        hub.deliver_response(
            sent_ids[0],
            wire::Response {
                body: Some(wire::response::Body::SessionReadResult(
                    wire::SessionReadResult {
                        events: Vec::new(),
                        next_after: 0,
                        next_ctl_after: 0,
                    },
                )),
            },
        );
        assert!(
            hub.send_request(b, 1, read_body(1)).is_ok(),
            "once the target's own reply actually arrives, the hub-wide budget \
             must be released"
        );
    }

    fn rfwd_open_body() -> wire::control_message::Body {
        wire::control_message::Body::RfwdOpen(wire::RemoteForwardOpen::default())
    }

    fn rfwd_opened_response(forward_id: &str) -> wire::Response {
        wire::Response {
            body: Some(wire::response::Body::RfwdOpened(
                wire::RemoteForwardOpened {
                    forward_id: forward_id.to_string(),
                    actual_port: 0,
                },
            )),
        }
    }

    /// **Finding: a duplicate `forward_id` must not silently transfer
    /// ownership.** `forward_id` is target-minted (`ulid::Ulid::new()`)
    /// and practically unique, but this relay must not trust that: a
    /// second `RemoteForwardOpened` naming an id already registered to
    /// conduit A, answering a *different* request conduit B issued, must
    /// leave A as the owner — never silently hand B the registration (and
    /// with it, any arrival already queued for it).
    #[tokio::test]
    async fn a_duplicate_forward_id_does_not_transfer_ownership_to_a_later_registrant() {
        let hub = hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");

        hub.send_request(conduit_a, 0, rfwd_open_body()).unwrap();
        let (daemon_request_id_a, _) = outbound.recv().await.expect("queued send");
        hub.send_request(conduit_b, 0, rfwd_open_body()).unwrap();
        let (daemon_request_id_b, _) = outbound.recv().await.expect("queued send");

        hub.deliver_response(daemon_request_id_a, rfwd_opened_response("fid-dup"));
        assert_eq!(
            hub.forward_owner("fid-dup"),
            Some(conduit_a),
            "conduit_a's registration must seat first"
        );

        // The target (bug, or adversary) answers conduit_b's own,
        // separate request with the *same* forward_id conduit_a already
        // holds. Mutation-check target: deleting this rejection and
        // letting the `insert` run unconditionally again is exactly what
        // would make this test fail.
        hub.deliver_response(daemon_request_id_b, rfwd_opened_response("fid-dup"));
        assert_eq!(
            hub.forward_owner("fid-dup"),
            Some(conduit_a),
            "a duplicate forward_id must never move ownership away from its first registrant"
        );
    }

    /// The reverse relay's late-response rule, symmetric with the forward
    /// route: session lifetime is decoupled from connection lifetime
    /// (`docs/PRD.md`'s core premise). On the forward route, a CLI that
    /// dies between sending `session.open` and receiving `SessionOpened`
    /// leaves a live session on the target — discoverable via
    /// `session.list`, closable via `session.close` — never leaked or
    /// invisible. A late `Response` for a `daemon_request_id` whose
    /// conduit already died must behave identically here: dropped, full
    /// stop. The relay must not originate a `session.close` on its own
    /// initiative — it carries no business logic, and the target would
    /// audit a close nobody requested under the controller principal.
    #[tokio::test]
    async fn a_late_response_for_a_dead_conduit_is_dropped_and_sends_nothing() {
        let hub = hub();
        let (a, _rx_a) = hub.register_conduit();
        hub.send_request(
            a,
            0,
            wire::control_message::Body::SessionOpen(wire::SessionOpen {
                argv: vec!["sh".into()],
                env: Default::default(),
                term: String::new(),
                cols: 0,
                rows: 0,
                user: None,
            }),
        )
        .unwrap();

        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");
        let (open_id, _) = outbound.recv().await.expect("the queued session.open");

        // The conduit dies before the reply arrives — its own mux table
        // entry (and, were this a long-poll body, its `long_poll_ids`
        // membership) is already gone.
        hub.unregister_conduit(a);
        assert_eq!(
            hub.total_in_flight(),
            0,
            "the dead conduit's entry must already be gone from the mux table"
        );

        // The reply arrives late — nobody is registered to receive it any
        // more.
        hub.deliver_response(open_id, opened_response("orphan-session-1"));

        // Dropped, not compensated: nothing goes out on the outbound
        // channel — no compensating `session.close`, nothing at all.
        let outcome = tokio::time::timeout(Duration::from_millis(50), outbound.recv()).await;
        assert!(
            outcome.is_err(),
            "a late response for a dead conduit must send nothing on the outbound \
             channel, got {outcome:?}"
        );

        // Still nothing under `open_id` in the mux table after the late
        // delivery.
        assert_eq!(hub.total_in_flight(), 0);
    }

    /// `HubState::dead` closes the race a conduit can otherwise fall into:
    /// resolving this hub, then registering *after* `mark_dead` already
    /// ran (the real window `crate::localctl::daemon::serve_control` has
    /// — an await for the `LocalHelloAck` write sits between the two).
    /// Without the sticky flag such a conduit would be handed a
    /// live-looking hub and hang forever; with it, the very first thing
    /// its inbox receives is `HostDead`.
    #[tokio::test]
    async fn registering_after_mark_dead_delivers_host_dead_immediately() {
        let hub = hub();
        hub.mark_dead();

        let (_conduit, mut inbox) = hub.register_conduit();
        assert!(
            matches!(inbox.recv().await, Some(ConduitInbound::HostDead)),
            "a conduit registering after the hub is already dead must be told \
             immediately, not left to hang"
        );
    }
}

#[cfg(test)]
mod conn_table_tests {
    use super::*;

    /// A cheap stand-in for [`Connection`] — an id plus a shared log of
    /// which ids got "closed" — so [`ConnTable::publish`]'s race-freedom
    /// claim is testable without a real QUIC connection ([`ConnTable`] is
    /// generic exactly so this is possible).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockConn(u32);

    fn close(log: &Mutex<Vec<u32>>, conn: MockConn) {
        log.lock().unwrap_or_else(|e| e.into_inner()).push(conn.0);
    }

    /// Both possible continuation orders described in [`ConnTable::publish`]'s
    /// own doc comment converge on the same end state. `order` selects which
    /// of the two concurrent registrations' `finish_registration` calls
    /// reaches `publish` first — the whole point being that it must not
    /// matter which one does.
    fn replay(publish_gen2_first: bool) -> (u32, Vec<u32>) {
        let table = ConnTable::new();
        let log = Mutex::new(Vec::new());
        // Pre-existing occupant at generation 0 — the connection a fresh
        // reconnect (generation 1) is about to replace.
        match table.publish("name".to_string(), 0, MockConn(0)) {
            Published::Installed(None) => {}
            other => panic!("first publish must install cleanly: {other:?}"),
        }

        let call = |generation: u64, id: u32| match table.publish(
            "name".to_string(),
            generation,
            MockConn(id),
        ) {
            Published::Installed(old) => {
                if let Some(old) = old {
                    close(&log, old);
                }
            }
            Published::Superseded(mine) => close(&log, mine),
        };

        if publish_gen2_first {
            call(2, 2);
            call(1, 1);
        } else {
            call(1, 1);
            call(2, 2);
        }

        let occupant = table.lock().get("name").map(|(g, _)| *g).unwrap();
        let mut closed = log.into_inner().unwrap_or_else(|e| e.into_inner());
        closed.sort_unstable();
        (occupant as u32, closed)
    }

    impl std::fmt::Debug for Published<MockConn> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Published::Installed(old) => write!(f, "Installed({old:?})"),
                Published::Superseded(v) => write!(f, "Superseded({v:?})"),
            }
        }
    }

    #[test]
    fn admit_order_continuation_order_ends_with_the_newest_generation_open() {
        let (occupant, closed) = replay(false);
        assert_eq!(occupant, 2, "the newest generation must be the occupant");
        assert_eq!(closed, vec![0, 1], "everything else closed exactly once");
    }

    #[test]
    fn reversed_continuation_order_still_ends_with_the_newest_generation_open() {
        // This is the exact scenario `PLAN.md` M3 Step 4 (4) names: the
        // higher-generation registration's `finish_registration` reaches
        // `publish` first. The old `(name, generation)`-keyed table leaked
        // generation 1's connection here; this table must not.
        let (occupant, closed) = replay(true);
        assert_eq!(occupant, 2, "the newest generation must be the occupant");
        assert_eq!(
            closed,
            vec![0, 1],
            "generation 1's own connection must close itself, not leak"
        );
    }

    #[test]
    fn remove_if_only_removes_a_matching_generation() {
        let table: ConnTable<MockConn> = ConnTable::new();
        table.publish("name".to_string(), 0, MockConn(0));
        assert!(
            !table.remove_if("name", 1),
            "generation mismatch must not remove"
        );
        assert_eq!(table.len(), 1);
        assert!(table.remove_if("name", 0), "matching generation removes");
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn remove_if_on_an_unknown_name_is_a_no_op() {
        let table: ConnTable<MockConn> = ConnTable::new();
        assert!(!table.remove_if("nobody-home", 0));
    }

    fn sample_entry(generation: u64) -> registry::ReverseEntry {
        registry::ReverseEntry {
            name: "name".to_string(),
            fingerprint: "sha256:abc".to_string(),
            principal: "device:target".to_string(),
            address: "127.0.0.1:0".parse().unwrap(),
            capabilities: Vec::new(),
            registered_at: "2026-01-01T00:00:00Z".to_string(),
            generation,
            state: registry::EntryState::Live,
            stale_since: None,
        }
    }

    // `rollback_target` — the fix for the adversarial-review "permanent
    // phantom host" finding (`Listen::register_connection`'s rollback
    // branch): a `RegisterOutcome::replaced_entry` snapshot must only be
    // restored while `conns` still backs it with a live connection.

    #[test]
    fn rollback_target_keeps_the_snapshot_while_its_connection_is_still_the_occupant() {
        let table = ConnTable::new();
        table.publish("name".to_string(), 0, MockConn(0));
        let prev = sample_entry(0);
        assert_eq!(
            rollback_target(&table, "name", Some(prev.clone())),
            Some(prev),
            "the connection it describes is still live — safe to restore"
        );
    }

    #[test]
    fn rollback_target_drops_the_snapshot_once_its_connection_already_exited() {
        // Nothing published under `name`: the connection this snapshot
        // describes already ran its own `remove_if` and removed itself —
        // e.g. its watchdog declared the path dead in the window between
        // the admission this snapshot came from and the rollback.
        let table: ConnTable<MockConn> = ConnTable::new();
        let prev = sample_entry(0);
        assert_eq!(
            rollback_target(&table, "name", Some(prev)),
            None,
            "restoring a Live entry with no connection behind it must never happen"
        );
    }

    #[test]
    fn rollback_target_drops_the_snapshot_once_a_further_generation_replaced_it() {
        let table = ConnTable::new();
        table.publish("name".to_string(), 2, MockConn(2));
        let prev = sample_entry(0);
        assert_eq!(
            rollback_target(&table, "name", Some(prev)),
            None,
            "generation 2 is the real occupant now — generation 0 must not come back"
        );
    }

    #[test]
    fn rollback_target_passes_a_fresh_registrations_none_through_unchanged() {
        let table: ConnTable<MockConn> = ConnTable::new();
        assert_eq!(rollback_target(&table, "name", None), None);
    }
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
    /// ([`sweep_tick`](Self::sweep_tick)'s own doc comment).
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
    /// [`sweep_tick`](Self::sweep_tick)'s doc comment promises.
    pub fn new_with_sweep_tick(
        registry: Registry,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        device_name: impl Into<String>,
        clock: Arc<dyn Clock>,
        stale_retention: Duration,
        sweep_tick: Duration,
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

    /// The live QUIC [`Connection`] and [`ControlHub`] for `name`'s
    /// *current* live registration, generation-matched to each other —
    /// `crate::localctl::daemon`'s `LOCAL_STREAM` serve path needs both:
    /// the hub for `LocalHelloAck`'s fields, the connection to open the
    /// spliced data stream on (`PLAN.md` M3 Step 7).
    ///
    /// Looking each up independently (a `control_hub` call plus a
    /// separate `conns` lookup) could momentarily pair a hub from one
    /// generation with a connection from a different one during the
    /// narrow window [`Self::hubs`]'s own doc comment describes; this
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
    /// Polls [`Self::hubs`] on [`Self::clock`] (so `TestClock` drives this
    /// deterministically in tests, `docs/design/testing.md` L2) at
    /// [`HUB_WAIT_POLL`] — a plain [`ConnTable`] has no per-name wakeup to
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
    /// on a task alongside [`Listen::run`]. Uses [`Listen::clock`], so
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
        let with_generation = serde_json::to_string(&RegistrationEvent {
            event: "registered",
            host: "personal-mac",
            fingerprint: "sha256:abc",
            generation: Some(0),
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&with_generation).unwrap();
        assert_eq!(parsed["event"], "registered");
        assert_eq!(parsed["host"], "personal-mac");
        assert_eq!(parsed["fingerprint"], "sha256:abc");
        assert_eq!(parsed["generation"], 0);

        let without_generation = serde_json::to_string(&RegistrationEvent {
            event: "denied",
            host: "-",
            fingerprint: "sha256:abc",
            generation: None,
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&without_generation).unwrap();
        assert_eq!(parsed["event"], "denied");
        assert!(parsed.get("generation").is_none());
    }

    #[test]
    fn registration_event_json_line_covers_the_expired_event() {
        // Step 4 addition: `Listen::run_stale_sweeper` emits this on the
        // same tracing target/shape as every other `RegistrationEvent`.
        let line = serde_json::to_string(&RegistrationEvent {
            event: "expired",
            host: "personal-mac",
            fingerprint: "sha256:abc",
            generation: Some(3),
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["event"], "expired");
        assert_eq!(parsed["generation"], 3);
    }

    fn test_listen() -> Arc<Listen> {
        let registry = Registry::new(Arc::new(SystemClock), false);
        Listen::new(
            registry,
            Arc::new(AllowAllPinned),
            Arc::new(crate::audit::NullAuditSink),
            "hermes",
            Arc::new(SystemClock),
            Duration::from_secs(120),
        )
    }

    /// [`test_listen`], but on an injectable [`crate::broker::TestClock`]
    /// shared between the registry and `Listen` itself — the same sharing
    /// [`Listen::new`]'s own doc requires of every caller — so
    /// [`Listen::control_hub_wait`]'s poll loop advances only when a test
    /// calls [`crate::broker::TestClock::advance`], never on real wall
    /// time (`docs/design/testing.md` L2, `PLAN.md` M3 Step 8 (c)).
    #[cfg(unix)]
    fn test_listen_with_clock(clock: Arc<crate::broker::TestClock>) -> Arc<Listen> {
        let registry = Registry::new(clock.clone(), false);
        Listen::new(
            registry,
            Arc::new(AllowAllPinned),
            Arc::new(crate::audit::NullAuditSink),
            "hermes",
            clock,
            Duration::from_secs(120),
        )
    }

    /// Registers `name` in `listen`'s registry (so
    /// [`Listen::control_hub_wait`] does not take its "name unknown, stop
    /// waiting" exit early) and returns the `generation` the registry
    /// assigned — the first admission under a fresh name, always `0`
    /// ([`ConnTable`]'s own doc: "starting from a pre-existing occupant at
    /// generation `0`").
    #[cfg(unix)]
    fn admit(listen: &Listen, name: &str) -> u64 {
        listen
            .registry()
            .admit(
                name.to_string(),
                registry::AdmittedEntry {
                    fingerprint: "sha256:test",
                    principal: "device:test",
                    address: "127.0.0.1:4433".parse().unwrap(),
                    capabilities: vec![],
                },
            )
            .expect("registers")
            .entry
            .generation
    }

    /// Publishes a bare [`ControlHub`] at `generation` under `name` —
    /// exactly what [`Listen::finish_registration`] does after a real
    /// `LOCAL_CONTROL` registration handshake, minus the handshake itself
    /// (`PLAN.md` M3 Step 8 (c)'s unit tests exercise
    /// [`Listen::control_hub_wait`] directly, not the daemon frame loop
    /// around it — that path is covered at L3 by
    /// `crates/qsh-testkit/tests/local_control_reverse.rs`).
    #[cfg(unix)]
    fn publish_hub(listen: &Listen, name: &str, generation: u64) -> Arc<ControlHub> {
        let hub = ControlHub::new(
            name.to_string(),
            "sha256:test".to_string(),
            generation,
            vec![],
        );
        listen
            .hubs
            .publish(name.to_string(), generation, hub.clone());
        hub
    }

    /// **L2 — old generation never satisfies the wait.**
    ///
    /// `PLAN.md` M3 Step 8 (c): "옛 `generation`의 등록으로는 진행하지 않음".
    /// A hub is live under `name`, but still sitting at exactly the
    /// generation [`LocalReconnect`] already rode to death — the dead
    /// registration the recovery exists to wait *past*, not settle for.
    /// [`Listen::control_hub_wait`] must not resolve on it: it stays
    /// pending across several of its own poll ticks, and once the
    /// deadline elapses with nothing newer ever registering, it gives up
    /// with `None` — the same outcome
    /// `crate::localctl::daemon`'s `LOCAL_CONTROL` serve path turns into
    /// `ErrorCode::HostNotFound` (daemon.rs's own doc on this call site).
    #[cfg(unix)]
    #[tokio::test]
    async fn control_hub_wait_does_not_resolve_on_a_registration_still_at_the_known_generation() {
        let clock = Arc::new(crate::broker::TestClock::new());
        let listen = test_listen_with_clock(clock.clone());
        let known_generation = admit(&listen, "widget");
        publish_hub(&listen, "widget", known_generation);

        let deadline = Duration::from_millis(500);
        let waiter = {
            let listen = listen.clone();
            tokio::spawn(async move {
                listen
                    .control_hub_wait("widget", Some(known_generation), deadline)
                    .await
            })
        };

        // Several poll ticks' worth of clock movement, still short of the
        // deadline: the still-at-`known_generation` hub must not have
        // resolved the wait.
        for _ in 0..3 {
            clock.advance(HUB_WAIT_POLL);
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        }
        assert!(
            !waiter.is_finished(),
            "a hub still at the known generation must not satisfy the wait"
        );

        // Past the deadline, with nothing newer ever having registered.
        clock.advance(deadline);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let outcome = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("control_hub_wait must give up once its deadline elapses")
            .expect("the wait task did not panic");
        assert!(
            outcome.is_none(),
            "an old-generation-only registration must time out to None, not resolve"
        );
    }

    /// **L2 — a within-window newer generation resolves the wait.**
    ///
    /// `PLAN.md` M3 Step 8 (c): "새 generation 등록을 기다렸다가... 대기하고".
    /// The same scenario as the previous test, except a strictly newer
    /// generation registers before the deadline — [`LocalReconnect`]'s own
    /// production path, driven here without a real target re-dial or a
    /// real daemon frame loop (`docs/design/protocol.md` §11-4's mapping
    /// paragraph: "controller의 attach driver는 새 세대 등록을 기다린다").
    #[cfg(unix)]
    #[tokio::test]
    async fn control_hub_wait_resolves_once_a_strictly_newer_generation_registers() {
        let clock = Arc::new(crate::broker::TestClock::new());
        let listen = test_listen_with_clock(clock.clone());
        let known_generation = admit(&listen, "widget");
        publish_hub(&listen, "widget", known_generation);

        let deadline = Duration::from_secs(5);
        let waiter = {
            let listen = listen.clone();
            tokio::spawn(async move {
                listen
                    .control_hub_wait("widget", Some(known_generation), deadline)
                    .await
            })
        };

        // Let the wait take its first poll and go to sleep on the
        // still-stale hub, well short of the deadline.
        clock.advance(HUB_WAIT_POLL);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!waiter.is_finished(), "must still be waiting");

        // The target's own re-dial lands as a new registration generation.
        let new_generation = known_generation + 1;
        let published = publish_hub(&listen, "widget", new_generation);

        // One more poll tick wakes the loop onto the fresh hub.
        clock.advance(HUB_WAIT_POLL);
        let hub = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("control_hub_wait must resolve once a newer generation is live")
            .expect("the wait task did not panic")
            .expect("a strictly newer generation must satisfy the wait");
        assert_eq!(
            hub.generation, new_generation,
            "the resolved hub must be the newer generation, not the old one"
        );
        assert!(
            Arc::ptr_eq(&hub, &published),
            "must be the same hub instance published"
        );
    }

    /// **L2 — window-exceeded with no registration at all times out.**
    ///
    /// `PLAN.md` M3 Step 8 (b): "창이 지나면 `HOST_NOT_FOUND`". No hub is
    /// ever published under `name` (the target never re-dials within the
    /// window) — [`Listen::control_hub_wait`] keeps polling, because the
    /// registry still knows the name (it went stale, not gone), and gives
    /// up at exactly its deadline rather than early or late.
    #[cfg(unix)]
    #[tokio::test]
    async fn control_hub_wait_times_out_when_nothing_ever_registers() {
        let clock = Arc::new(crate::broker::TestClock::new());
        let listen = test_listen_with_clock(clock.clone());
        // Registered (so the registry-gone early exit does not fire), but
        // no `ControlHub` is ever published — the registration went stale
        // and nothing re-dialed.
        admit(&listen, "widget");

        let deadline = Duration::from_millis(300);
        let waiter = {
            let listen = listen.clone();
            tokio::spawn(async move { listen.control_hub_wait("widget", None, deadline).await })
        };

        for _ in 0..2 {
            clock.advance(HUB_WAIT_POLL);
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        }
        assert!(!waiter.is_finished(), "must still be within the deadline");

        clock.advance(deadline);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let outcome = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("control_hub_wait must give up once its deadline elapses")
            .expect("the wait task did not panic");
        assert!(
            outcome.is_none(),
            "no registration within the window must time out to None (daemon maps this to \
             HostNotFound, `crate::localctl::daemon`'s LOCAL_CONTROL serve path)"
        );
    }

    #[tokio::test]
    async fn listen_wires_device_name_and_starts_with_no_live_connections() {
        let listen = test_listen();
        assert_eq!(listen.local_hello().device_name, "hermes");
        assert!(listen.local_hello().reverse.is_none());
        assert_eq!(listen.live_connections(), 0);
        assert!(listen.registry().snapshot().is_empty());
    }

    /// `Listen::run_stale_sweeper` — `docs/design/testing.md` L2, no real
    /// `sleep()` — removes a stale, retention-expired entry and stops on
    /// its own once the last `Arc<Listen>` drops. Both the registry's
    /// retention clock and the sweeper's own tick pacing are
    /// [`SystemClock`], which is `tokio::time::pause()`-steerable
    /// (`broker::clock`'s module docs) — the exact shape
    /// `broker::run_reaper_uses_the_injected_clock_and_stops_with_the_broker`
    /// already establishes for the sibling reaper.
    #[tokio::test(start_paused = true)]
    async fn run_stale_sweeper_removes_a_retention_expired_entry() {
        let listen = test_listen();
        let outcome = listen
            .registry()
            .admit(
                "widget".to_string(),
                registry::AdmittedEntry {
                    fingerprint: "sha256:a",
                    principal: "device:widget",
                    address: "127.0.0.1:4433".parse().unwrap(),
                    capabilities: vec![],
                },
            )
            .expect("registers");
        listen
            .registry()
            .mark_stale("widget", outcome.entry.generation)
            .expect("goes stale");

        let sweeper = tokio::spawn(Listen::run_stale_sweeper(Arc::downgrade(&listen)));

        // Retention (120s) hasn't elapsed yet — still present, across
        // several of the sweeper's own ticks.
        tokio::time::advance(Duration::from_secs(60)).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(listen.registry().get("widget").is_some(), "not due yet");

        // Past retention, and past at least one more of the sweeper's own
        // ticks.
        tokio::time::advance(Duration::from_secs(61) + STALE_SWEEP_TICK).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
            if listen.registry().get("widget").is_none() {
                break;
            }
        }
        assert!(listen.registry().get("widget").is_none(), "swept away");

        drop(listen);
        tokio::time::advance(STALE_SWEEP_TICK).await;
        tokio::time::timeout(Duration::from_secs(5), sweeper)
            .await
            .expect("sweeper must stop once the last Arc<Listen> drops")
            .unwrap();
    }

    /// `PLAN.md` M3 Step 5 (a): the localctl socket this process bound must
    /// not outlive it. Drives the real `run_listen`/`run_listen_unix` end
    /// to end — a genuine on-disk identity via `identity::init`/
    /// `identity::load` (`File` key-store mode, so nothing touches an OS
    /// credential store) — rather than constructing `Listen` directly the
    /// way `qsh_testkit::reverse::ReverseHarness` does, because this test
    /// is specifically about `run_listen_unix`'s own composition of the
    /// localctl accept loop with the QUIC one's drain, which `ReverseHarness`
    /// does not build at all (it calls `Listen::new`/`Listen::run` straight,
    /// never `run_listen`/`LocalctlListener`).
    #[cfg(unix)]
    #[tokio::test]
    async fn run_listen_unix_unlinks_its_localctl_socket_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        // `.with_runtime_dir` pins the localctl socket inside this test's
        // own tempdir, independent of `$XDG_RUNTIME_DIR` — otherwise this
        // and the sibling test below both bind at
        // `$XDG_RUNTIME_DIR/qsh/<this-process's-pid>.sock` (both tests
        // share one process pid under plain `cargo test`), racing each
        // other's bind/unlink and leaking into the real runtime directory
        // (adversarial review finding).
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
            .with_runtime_dir(dir.path().join("run"));
        crate::identity::init(&paths, qsh_proto::KeyStoreMode::File).expect("identity::init");
        let identity = crate::identity::load(&paths)
            .expect("identity::load")
            .expect("identity was just created");

        let socket_path = paths.localctl_socket(std::process::id());

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel::<()>();
        let run_paths = paths.clone();
        let task = tokio::spawn(async move {
            run_listen(
                &run_paths,
                &Config::default(),
                identity,
                Some("127.0.0.1:0"),
                move |_addr| {
                    let _ = bound_tx.send(());
                },
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        bound_rx.await.expect("qsh listen bound");
        assert!(
            socket_path.exists(),
            "localctl socket must exist once the daemon is up"
        );

        let _ = shutdown_tx.send(());
        task.await
            .expect("run_listen task did not panic")
            .expect("run_listen exits cleanly on shutdown");

        assert!(
            !socket_path.exists(),
            "localctl socket must be unlinked once shutdown has drained"
        );
    }

    /// `PLAN.md` M3 Step 5 (a): "unlinks the socket on every exit path", not
    /// only the clean-shutdown one the previous test covers. Corrupts
    /// `trust.toml` so `SharedTrustStore::open` — the first fallible step
    /// *after* `LocalctlListener::bind` already created the socket file —
    /// fails startup outright; the socket must still not be left behind.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_listen_unix_unlinks_its_localctl_socket_when_startup_fails_after_binding_it() {
        let dir = tempfile::tempdir().unwrap();
        // See the sibling test above for why `.with_runtime_dir` is
        // required here rather than optional.
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
            .with_runtime_dir(dir.path().join("run"));
        crate::identity::init(&paths, qsh_proto::KeyStoreMode::File).expect("identity::init");
        let identity = crate::identity::load(&paths)
            .expect("identity::load")
            .expect("identity was just created");

        // Written after `identity::init` (which creates `config_dir`) so
        // this lands exactly where `Paths::trust_file` looks — malformed
        // TOML, not a missing file, since a missing trust file is a normal
        // empty store (`TrustStore::load`), not a startup failure.
        std::fs::write(paths.trust_file(), b"this is not valid toml [[[").unwrap();

        let socket_path = paths.localctl_socket(std::process::id());
        assert!(
            !socket_path.exists(),
            "nothing has bound this pid's socket yet"
        );

        let err = run_listen(
            &paths,
            &Config::default(),
            identity,
            Some("127.0.0.1:0"),
            |_addr| panic!("must fail before the QUIC listener ever reports bound"),
            std::future::pending::<()>(),
        )
        .await
        .expect_err("a corrupt trust store must fail startup");
        assert_eq!(err.code, ErrorCode::ConfigError);

        assert!(
            !socket_path.exists(),
            "the localctl socket bound before the failing step must not survive it"
        );
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

    // ------------------------------------------------------------------
    // Tunnel relay registry (`PLAN.md` M4 Step 5, PR 5a). `PLAN.md`'s own
    // framing: "the central risk of this PR is silent misdelivery" — a
    // `forward_id` resolving to the wrong conduit's splice is a security
    // incident, not a bug. These tests exercise
    // [`ControlHub::deliver_tcp_accepted`]/[`ControlHub::claim_tcp_accepted`]/
    // [`ControlHub::unregister_conduit`] and [`Listen::handle_tcp_accepted_stream`]
    // directly — the full wire-level round trip through a real reverse
    // connection and daemon `LOCAL_STREAM` conduit is
    // `crates/qsh-testkit/tests/reverse_tunnel.rs`'s job (L3), not this
    // crate's unit tests (the same split `local_stream_at_the_stream_pools_cap_...`
    // above already draws for `LOCAL_STREAM`'s own cap).
    // ------------------------------------------------------------------

    #[cfg(unix)]
    fn test_hub() -> Arc<ControlHub> {
        ControlHub::new("widget".into(), "sha256:test".into(), 1, Vec::new())
    }

    /// A `TCP_ACCEPTED` naming a `forward_id` this hub never registered —
    /// never opened, already closed, or its owner already dead — must be
    /// refused by [`ControlHub::deliver_tcp_accepted`] itself, before
    /// anything is queued: `PLAN.md`'s "an unknown ... forward_id causes
    /// a stream reset and nothing else". The rejected [`TunnelArrival`]
    /// comes straight back to the caller (never silently dropped —
    /// [`ControlHub::deliver_tcp_accepted`]'s own doc on why a bare drop
    /// here would be wrong), and the registry gained no trace of the
    /// unknown id.
    #[cfg(unix)]
    #[tokio::test]
    async fn deliver_tcp_accepted_refuses_an_unregistered_forward_id_and_queues_nothing() {
        let hub = test_hub();
        let (client, _server) = crate::tunnel::testutil::loopback_pair().await;
        let (send, recv) = client.open_bi().await.unwrap();
        let permit = hub
            .try_acquire_tunnel_permit()
            .expect("a fresh hub is under its cap");

        let rejected = hub
            .deliver_tcp_accepted("never-registered", send, recv, Vec::new(), permit)
            .expect_err("an unregistered forward_id must never be queued");
        assert!(hub.forward_owner("never-registered").is_none());

        // The caller (here, standing in for `handle_tcp_accepted_stream`'s
        // own rejection path) is responsible for resetting it — prove the
        // handles really did come back usable, not consumed.
        rejected.reset(0x9999);
    }

    /// **The central proof this whole registry exists for**
    /// (`PLAN.md` M4 Step 5 (a)): a `forward_id` registered by one conduit
    /// never resolves to a different conduit's claim, even when a real
    /// arrival is sitting in the hub's queue for the *other* id at the
    /// exact moment of the claim. Two conduits, two distinct
    /// `forward_id`s, one arrival delivered only for the first — the
    /// second conduit's claim on its own id must see nothing, and the
    /// first conduit's claim on its own id must see exactly the arrival
    /// it registered.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_forward_id_never_resolves_to_a_different_conduits_registration() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit_a);
        let token_b = hub.register_forward_for_test("fid-b", conduit_b);

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send, target_recv) = client.open_bi().await.unwrap();
        // A QUIC peer only learns a stream exists once a frame referencing
        // it actually arrives — `accept_bi` below would otherwise block
        // forever waiting on a stream the client never told it about.
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        drop(target_send);
        drop(target_recv);
        let permit = hub.try_acquire_tunnel_permit().unwrap();
        assert!(
            hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
                .is_ok(),
            "fid-a is registered to conduit_a, so this must be accepted"
        );

        // conduit_b's own id must not see conduit_a's arrival, however
        // briefly it waits.
        let claimed_by_b = hub
            .claim_tcp_accepted("fid-b", &token_b, Duration::from_millis(50))
            .await;
        assert!(
            claimed_by_b.is_none(),
            "fid-b must never resolve to fid-a's queued arrival"
        );

        // fid-a's own claim still succeeds — proving the arrival really
        // was queued, just never reachable under the wrong id.
        let claimed_by_a = hub
            .claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(50))
            .await;
        assert!(
            claimed_by_a.is_some(),
            "fid-a's own claim must still see the arrival it registered"
        );
    }

    /// **The adversarial byte-level edition of the proof above**
    /// (`PLAN.md` M4 Step 5 (a)'s own framing: misdelivery here is "a
    /// security incident, not a bug"). Two conduits, two `forward_id`s,
    /// two independent target connections, both queued and both claimed
    /// *concurrently* — and then every leg carries a payload that names
    /// its own `forward_id` in the clear, in both directions at once. If
    /// a single byte of fid-a's traffic ever reached fid-b's claimed
    /// stream (or vice versa), the marker comparisons below catch it
    /// directly — a leak here is detectable, not merely improbable.
    #[cfg(unix)]
    #[tokio::test]
    async fn distinguishable_payloads_never_cross_between_two_conduits_claimed_forwards() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit_a);
        let token_b = hub.register_forward_for_test("fid-b", conduit_b);

        // Two independent loopback QUIC pairs — separate connections, so
        // there is no shared transport-level state between "target a" and
        // "target b" beyond the hub itself.
        let (client_a, server_a) = crate::tunnel::testutil::loopback_pair().await;
        let (client_b, server_b) = crate::tunnel::testutil::loopback_pair().await;

        async fn open_target(client: &Connection) -> (SendStream, RecvStream) {
            let (mut send, recv) = client.open_bi().await.unwrap();
            // A QUIC peer only learns a stream exists once a frame
            // referencing it actually arrives.
            send.write_all(b"x").await.unwrap();
            (send, recv)
        }

        let (mut target_send_a, mut target_recv_a) = open_target(&client_a).await;
        let (mut target_send_b, mut target_recv_b) = open_target(&client_b).await;
        let (daemon_send_a, daemon_recv_a) = server_a.accept_bi().await.unwrap();
        let (daemon_send_b, daemon_recv_b) = server_b.accept_bi().await.unwrap();

        let permit_a = hub.try_acquire_tunnel_permit().unwrap();
        let permit_b = hub.try_acquire_tunnel_permit().unwrap();
        hub.deliver_tcp_accepted("fid-a", daemon_send_a, daemon_recv_a, Vec::new(), permit_a)
            .unwrap_or_else(|_| panic!("fid-a is registered"));
        hub.deliver_tcp_accepted("fid-b", daemon_send_b, daemon_recv_b, Vec::new(), permit_b)
            .unwrap_or_else(|_| panic!("fid-b is registered"));

        // Claim both concurrently — interleaved, not sequential — so a
        // bug that only shows up under a race (a shared cursor, a
        // single-slot cache instead of a genuine per-id queue) has a
        // chance to fire.
        let (claimed_a, claimed_b) = tokio::join!(
            hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_secs(5)),
            hub.claim_tcp_accepted("fid-b", &token_b, Duration::from_secs(5)),
        );
        let (mut daemon_send_a, mut daemon_recv_a, _, _permit_a) =
            claimed_a.expect("fid-a's own arrival must be claimable");
        let (mut daemon_send_b, mut daemon_recv_b, _, _permit_b) =
            claimed_b.expect("fid-b's own arrival must be claimable");

        // Drain `open_target`'s single sentinel byte off each claimed
        // stream before the real payload exchange below — it exists only
        // to make `accept_bi` observe the stream, and is not part of
        // either marker.
        let mut sentinel = [0u8; 1];
        daemon_recv_a.read_exact(&mut sentinel).await.unwrap();
        daemon_recv_b.read_exact(&mut sentinel).await.unwrap();

        const MARKER_A: &[u8] = b"PAYLOAD-BELONGS-TO-FID-A-ONLY";
        const MARKER_B: &[u8] = b"PAYLOAD-BELONGS-TO-FID-B-ONLY";

        // Both directions, both ids, fully interleaved.
        let (w1, w2, w3, w4) = tokio::join!(
            target_send_a.write_all(MARKER_A),
            target_send_b.write_all(MARKER_B),
            daemon_send_a.write_all(MARKER_A),
            daemon_send_b.write_all(MARKER_B),
        );
        w1.unwrap();
        w2.unwrap();
        w3.unwrap();
        w4.unwrap();

        let mut buf_daemon_a = vec![0u8; MARKER_A.len()];
        let mut buf_daemon_b = vec![0u8; MARKER_B.len()];
        let mut buf_target_a = vec![0u8; MARKER_A.len()];
        let mut buf_target_b = vec![0u8; MARKER_B.len()];
        let (r1, r2, r3, r4) = tokio::join!(
            daemon_recv_a.read_exact(&mut buf_daemon_a),
            daemon_recv_b.read_exact(&mut buf_daemon_b),
            target_recv_a.read_exact(&mut buf_target_a),
            target_recv_b.read_exact(&mut buf_target_b),
        );
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
        r4.unwrap();

        assert_eq!(
            buf_daemon_a, MARKER_A,
            "fid-a's claimed stream must see exactly fid-a's payload, never fid-b's"
        );
        assert_eq!(
            buf_daemon_b, MARKER_B,
            "fid-b's claimed stream must see exactly fid-b's payload, never fid-a's"
        );
        assert_eq!(
            buf_target_a, MARKER_A,
            "fid-a's target must see exactly its own daemon-side reply"
        );
        assert_eq!(
            buf_target_b, MARKER_B,
            "fid-b's target must see exactly its own daemon-side reply"
        );
    }

    /// **The other half of "one conduit registers, the other tries to
    /// claim"**: even the *legitimate* claimant's own two racing attempts
    /// for the same `forward_id` (the same [`crate::tunnel::remote::
    /// RemoteForwardAcceptor`] instance, hence the same claim token —
    /// ownership alone, `Self::claim_tcp_accepted`'s own doc, does not
    /// serialize concurrent attempts by the id's rightful owner) must
    /// never both win: a single queued arrival is handed to exactly one
    /// claimant, never duplicated to two racing callers — duplicating it
    /// would itself be a byte leak, the same payload spliced into two
    /// different processes.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_single_queued_arrival_is_won_by_exactly_one_of_two_racing_claimants() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit_a);

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send, _target_recv) = client.open_bi().await.unwrap();
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        let permit = hub.try_acquire_tunnel_permit().unwrap();
        hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
            .unwrap_or_else(|_| panic!("fid-a is registered"));

        // Two concurrent claimants for the *same* id, presenting the
        // *same* (real, registered) claim token — modeling the legitimate
        // owner's own two racing attempts, not an adversarial conduit
        // (that case has its own dedicated test below).
        let (first, second) = tokio::join!(
            hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(200)),
            hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(200)),
        );
        let winners = [first.is_some(), second.is_some()];
        assert_eq!(
            winners.iter().filter(|w| **w).count(),
            1,
            "exactly one of two racing claimants must win the single queued arrival, got {winners:?}"
        );
    }

    /// **The BLOCKER this ownership check exists to close** (adversarial
    /// review finding, rated the most important of the batch: "claiming
    /// does not check ownership"). The registry already gated
    /// *delivery* — `deliver_tcp_accepted` refuses an id it never
    /// registered — but before this test's own fix, nothing gated
    /// *claiming*: `claim_tcp_accepted` only checked that `forward_id`
    /// resolved to *some* registration, not that the caller was the one
    /// who held it. Conduit B here knows conduit A's `forward_id` — the
    /// adversarial premise the finding names verbatim — and presents its
    /// own, different claim token. It must be refused outright, without
    /// ever seeing the queue, and conduit A's own subsequent claim (its
    /// *first*, seating its token as this id's owner) must still succeed
    /// untouched by B's attempt.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_conduit_that_only_knows_another_conduits_forward_id_cannot_claim_it() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (_conduit_b, _rx_b) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit_a);

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send, _target_recv) = client.open_bi().await.unwrap();
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        let permit = hub.try_acquire_tunnel_permit().unwrap();
        hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
            .unwrap_or_else(|_| panic!("fid-a is registered to conduit_a"));

        // Conduit B never registered "fid-a" and holds no token for it —
        // it merely *knows the string* (leaked, guessed, or otherwise
        // obtained out of band) and tries to claim it with a token of its
        // own choosing (necessarily different from the real, hub-minted
        // `token_a`, which B never learned).
        let stolen = hub
            .claim_tcp_accepted("fid-a", b"conduit-b-token", Duration::from_millis(100))
            .await;
        assert!(
            stolen.is_none(),
            "a conduit that never registered fid-a must never claim its arrival, no matter what \
             token it presents"
        );

        // The real owner's own claim, presenting the token registration
        // actually seated, must be entirely unaffected by B's attempt
        // above.
        let claimed_by_owner = hub
            .claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(100))
            .await;
        assert!(
            claimed_by_owner.is_some(),
            "fid-a's real registrant must still be able to claim its own arrival after an \
             adversarial attempt"
        );
    }

    /// [`ControlHub::claim_tcp_accepted`]'s ownership check, mutation-checked:
    /// with the `Some(existing) if existing.as_slice() == claim_token`
    /// guard weakened to accept any token once one is merely present, the
    /// adversarial test above must fail. This test pins the *shape* of
    /// the check a second, independent way: the claim token that matters
    /// is the one [`ControlHub::register_forward_for_test`] (standing in
    /// for [`ControlHub::deliver_response`]'s own registration arm) seats
    /// *atomically at registration* — never one a claimant supplies and
    /// has accepted merely for being first, which is exactly the race
    /// finding A closed. A mismatched token is refused immediately,
    /// before any wait, and the id itself stays registered.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_token_not_seated_at_registration_is_refused_and_the_real_one_still_works() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit_a);

        // A token nobody ever registered — not even a first, unclaimed
        // attempt at seating one, since registration (not claiming) is
        // now the only place a token is ever seated. Given a generous
        // budget, it must still be refused *fast*, proving the denial
        // happens at the ownership check itself, before any wait, rather
        // than as a timeout that would also (for the wrong reason)
        // satisfy a bare `is_none` assertion.
        let started = std::time::Instant::now();
        let mismatched = hub
            .claim_tcp_accepted("fid-a", b"wrong-token", Duration::from_secs(5))
            .await;
        assert!(
            mismatched.is_none(),
            "a token that does not match the one seated at registration must be refused"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a token mismatch must be rejected immediately, not after waiting out the full \
             5s budget"
        );
        assert!(
            hub.forward_owner("fid-a").is_some(),
            "a claim-token mismatch must not deregister the forward_id itself"
        );

        // No arrival was ever queued, so even the *real* token times out
        // rather than errors — proving the mismatch above was rejected
        // for being the wrong token, not because fid-a itself had become
        // unclaimable for some other reason.
        let real_token_result = hub
            .claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(20))
            .await;
        assert!(
            real_token_result.is_none(),
            "no arrival was ever queued, so even the real token's claim must time out, not error"
        );
    }

    /// [`ControlHub::unregister_conduit`]'s tunnel-registry sweep
    /// (`PLAN.md` M4 Step 5 (a)): every `forward_id` the dying conduit
    /// owned is removed and every `TCP_ACCEPTED` stream still queued for
    /// one of them is reset — but a *different* conduit's own
    /// registration is untouched by that same call.
    #[cfg(unix)]
    #[tokio::test]
    async fn unregister_conduit_sweeps_its_own_forwards_and_resets_queued_streams_but_spares_others()
     {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        hub.register_forward_for_test("fid-a", conduit_a);
        hub.register_forward_for_test("fid-b", conduit_b);

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send, mut target_recv) = client.open_bi().await.unwrap();
        // See the sibling test above for why `accept_bi` needs this first.
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        let permit = hub.try_acquire_tunnel_permit().unwrap();
        assert!(
            hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
                .is_ok(),
            "fid-a is registered"
        );

        hub.unregister_conduit(conduit_a);

        assert!(
            hub.forward_owner("fid-a").is_none(),
            "conduit_a's forward_id must be swept the instant it dies"
        );
        assert_eq!(
            hub.forward_owner("fid-b"),
            Some(conduit_b),
            "a sibling conduit's own registration must survive conduit_a's teardown"
        );

        // The queued stream for fid-a must have been reset, not silently
        // dropped clean — a bare drop finishes/stops a QUIC stream
        // cleanly (`TunnelArrival::reset`'s own doc), which would tell
        // whoever opened it "this ended normally" about a forward that in
        // fact was torn down out from under it.
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
            .await
            .expect("the reset must be observed promptly, not hang");
        match read {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(
                    code,
                    quinn::VarInt::from_u32(RESET_CODE_TUNNEL_UNKNOWN_FORWARD),
                    "a swept forward's queued stream must reset with the documented code"
                );
            }
            other => panic!("expected a stream reset, got {other:?}"),
        }
    }

    /// The stronger form of the sweep proof above: a conduit that owns
    /// *several* `forward_id`s (not just one) loses every one of them the
    /// instant it dies, and the registry is verifiably left with zero
    /// trace of it — not merely "the two ids this test happened to check
    /// are gone" (`PLAN.md` M4 Step 5 (a): "conduit death removes every
    /// forward_id it owned"). [`ControlHub::forward_registry_len`] is
    /// the precise, exhaustive assertion; per-id [`ControlHub::forward_owner`]
    /// checks alone could pass even if the sweep leaked some other id
    /// nobody thought to check.
    #[cfg(unix)]
    #[tokio::test]
    async fn unregister_conduit_leaves_zero_trace_of_a_conduit_that_owned_several_forwards() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        hub.register_forward_for_test("fid-a1", conduit_a);
        hub.register_forward_for_test("fid-a2", conduit_a);
        hub.register_forward_for_test("fid-a3", conduit_a);
        hub.register_forward_for_test("fid-b", conduit_b);
        assert_eq!(hub.forward_registry_len(), 4);

        // Queue a real arrival for two of conduit_a's three ids, so the
        // sweep's reset behavior is proven for more than a single
        // straggler.
        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let mut queued_targets = Vec::new();
        for fid in ["fid-a1", "fid-a2"] {
            let (mut target_send, target_recv) = client.open_bi().await.unwrap();
            target_send.write_all(b"x").await.unwrap();
            let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
            let permit = hub.try_acquire_tunnel_permit().unwrap();
            hub.deliver_tcp_accepted(fid, daemon_send, daemon_recv, Vec::new(), permit)
                .unwrap_or_else(|_| panic!("{fid} is registered"));
            queued_targets.push(target_recv);
        }

        hub.unregister_conduit(conduit_a);

        // Precise, not spot-checked: the registry holds exactly
        // conduit_b's one surviving id, nothing else.
        assert_eq!(
            hub.forward_registry_len(),
            1,
            "every one of conduit_a's forward_ids must be gone, leaving only conduit_b's"
        );
        for fid in ["fid-a1", "fid-a2", "fid-a3"] {
            assert!(hub.forward_owner(fid).is_none(), "{fid} must be swept");
        }
        assert_eq!(
            hub.forward_owner("fid-b"),
            Some(conduit_b),
            "a sibling conduit's own registration must survive conduit_a's teardown"
        );

        // Both queued arrivals — not just the first — were reset, never
        // left to drop clean.
        for mut target_recv in queued_targets {
            let mut buf = [0u8; 8];
            let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
                .await
                .expect("the reset must be observed promptly, not hang");
            match read {
                Err(quinn::ReadError::Reset(code)) => {
                    assert_eq!(
                        code,
                        quinn::VarInt::from_u32(RESET_CODE_TUNNEL_UNKNOWN_FORWARD),
                        "every swept forward's queued stream must reset with the documented code"
                    );
                }
                other => panic!("expected a stream reset, got {other:?}"),
            }
        }
    }

    /// [`MAX_TUNNEL_STREAMS_PER_HUB`] is exact, not advisory
    /// (`PLAN.md` M4 Step 5 (a)'s hub cap): the `(cap+1)`th
    /// [`ControlHub::try_acquire_tunnel_permit`] call is refused while
    /// every permit up to the cap is still held, and releasing one frees
    /// exactly one slot back.
    #[cfg(unix)]
    #[tokio::test]
    async fn tunnel_permit_cap_is_exact_not_advisory() {
        let hub = test_hub();
        let mut held = Vec::new();
        for _ in 0..MAX_TUNNEL_STREAMS_PER_HUB {
            held.push(
                hub.try_acquire_tunnel_permit()
                    .expect("every permit up to the cap must be grantable"),
            );
        }
        assert!(
            hub.try_acquire_tunnel_permit().is_none(),
            "the (cap+1)th tunnel stream must be refused, not silently admitted"
        );

        held.pop();
        assert!(
            hub.try_acquire_tunnel_permit().is_some(),
            "releasing one held permit must free exactly one slot"
        );
    }

    /// The cap must refuse only the stream that overflows it — it must
    /// never corrupt or block delivery for streams already admitted, and
    /// once a slot frees, a *different* conduit's registered forward must
    /// be able to use it immediately (`PLAN.md` M4 Step 5 (a): exceeding
    /// the cap "does not wedge the hub for other conduits").
    #[cfg(unix)]
    #[tokio::test]
    async fn exceeding_the_hub_cap_refuses_the_new_stream_without_wedging_the_hub_for_others() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit_a);
        let token_b = hub.register_forward_for_test("fid-b", conduit_b);

        // Fill the cap to one below the limit with permits standing in
        // for other conduits' already-admitted tunnel streams.
        let mut held: Vec<_> = (0..MAX_TUNNEL_STREAMS_PER_HUB - 1)
            .map(|_| hub.try_acquire_tunnel_permit().unwrap())
            .collect();

        // fid-a takes the one remaining slot and is delivered normally —
        // proving a near-full cap does not itself disturb an admission
        // that still fits.
        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send_a, _target_recv_a) = client.open_bi().await.unwrap();
        target_send_a.write_all(b"x").await.unwrap();
        let (daemon_send_a, daemon_recv_a) = server.accept_bi().await.unwrap();
        let permit_a = hub
            .try_acquire_tunnel_permit()
            .expect("the last free slot must still be grantable");
        hub.deliver_tcp_accepted("fid-a", daemon_send_a, daemon_recv_a, Vec::new(), permit_a)
            .unwrap_or_else(|_| panic!("fid-a fits exactly at the cap"));

        // The hub is now saturated. A new stream must be refused —
        // observably, deterministically — rather than hang or wedge the
        // whole hub.
        assert!(
            hub.try_acquire_tunnel_permit().is_none(),
            "the hub is saturated; a new permit must be refused, not granted"
        );

        // fid-a's already-admitted arrival is unaffected by the refusal
        // above — still claimable, proving the cap rejection is scoped to
        // the one overflowing attempt, not a hub-wide stall.
        let claimed_a = hub
            .claim_tcp_accepted("fid-a", &token_a, Duration::from_secs(5))
            .await;
        assert!(
            claimed_a.is_some(),
            "an already-admitted stream must not be disturbed by a sibling's cap refusal"
        );

        // Free exactly one of the "other conduits'" held permits — fid-b
        // must now succeed, proving the hub recovers rather than staying
        // wedged once any capacity returns.
        held.pop();
        let (mut target_send_b, target_recv_b) = client.open_bi().await.unwrap();
        target_send_b.write_all(b"x").await.unwrap();
        let (daemon_send_b, daemon_recv_b) = server.accept_bi().await.unwrap();
        let permit_b = hub
            .try_acquire_tunnel_permit()
            .expect("freeing one held permit must free exactly one slot back");
        hub.deliver_tcp_accepted("fid-b", daemon_send_b, daemon_recv_b, Vec::new(), permit_b)
            .unwrap_or_else(|_| panic!("fid-b must be admitted once capacity returns"));
        let claimed_b = hub
            .claim_tcp_accepted("fid-b", &token_b, Duration::from_secs(5))
            .await;
        assert!(
            claimed_b.is_some(),
            "fid-b must be claimable once the hub has recovered capacity"
        );
        drop(held);
        drop(target_recv_b);
    }

    /// [`MAX_PARKED_CLAIMS_PER_HUB`] is exact, not advisory — the
    /// distinct resource `crate::localctl::daemon::LocalctlDaemon::serve_tcp_accepted`
    /// acquires *before* ever calling [`ControlHub::claim_tcp_accepted`]
    /// (finding E: a parked claim holds a `MAX_CONCURRENT_LOCAL_STREAM_CONDUITS`
    /// permit for its whole wait budget with nothing bounding how many of
    /// *this hub's* claims can be parked at once — a `(cap+1)`th
    /// parked claim must be refused, not queued behind the ones already
    /// parked).
    ///
    /// Driven through as many owning conduits as the hub's pool divides
    /// into, because one conduit can no longer reach the ceiling by
    /// itself ([`MAX_PARKED_CLAIMS_PER_CONDUIT`]) — the ceiling is what
    /// this test is about, and it must still be exact once the shares
    /// that fill it are spread across their owners.
    #[cfg(unix)]
    #[tokio::test]
    async fn claim_permit_hub_ceiling_is_exact_not_advisory() {
        let hub = test_hub();
        let shares = MAX_PARKED_CLAIMS_PER_HUB / MAX_PARKED_CLAIMS_PER_CONDUIT;
        let mut held = Vec::new();
        let mut forward_ids = Vec::new();
        // Inboxes kept alive for the whole test: a dropped receiver is not
        // what unregisters a conduit, but keeping them mirrors the live
        // CLIs these conduits stand in for.
        let mut inboxes = Vec::new();
        for n in 0..shares {
            let (conduit, rx) = hub.register_conduit();
            inboxes.push(rx);
            let forward_id = format!("fid-{n}");
            hub.register_forward_for_test(&forward_id, conduit);
            for _ in 0..MAX_PARKED_CLAIMS_PER_CONDUIT {
                held.push(
                    hub.try_acquire_claim_permit(&forward_id)
                        .expect("every permit up to each owner's own share must be grantable"),
                );
            }
            forward_ids.push(forward_id);
        }
        assert_eq!(
            hub.parked_claims_held(),
            MAX_PARKED_CLAIMS_PER_HUB,
            "the shares must add up to exactly the hub ceiling, with nothing double-counted"
        );

        // A fresh owner, well inside its own untouched share, is refused:
        // the ceiling binds independently of the shares.
        let (late, _rx_late) = hub.register_conduit();
        hub.register_forward_for_test("fid-late", late);
        assert!(
            hub.try_acquire_claim_permit("fid-late").is_none(),
            "the (cap+1)th parked claim must be refused, not silently admitted, even for an \
             owner holding none of its own share"
        );

        held.pop();
        assert!(
            hub.try_acquire_claim_permit("fid-late").is_some(),
            "releasing one held parked-claim permit must free exactly one slot"
        );
        drop(inboxes);
        drop(forward_ids);
    }

    /// **The fairness finding this share exists to close.** The steady
    /// state of a healthy `-R` is to *sit* holding a parked-claim permit
    /// (`crate::tunnel::remote::claim_remote_forward_reverse`: one
    /// long-poll per registered `forward_id`, re-armed the instant it
    /// returns), so a hub-wide pool with no per-owner share is exhausted
    /// by ordinary use: one CLI running [`MAX_PARKED_CLAIMS_PER_HUB`]
    /// reverse forwards would hold every permit on this host essentially
    /// forever and every other CLI's `-R` would be refused for as long as
    /// it kept them — normal operation starving normal operation.
    ///
    /// Conduit A here parks as many claims as it can across *many* of its
    /// own forwards — the shape of the real starvation, not a single
    /// forward's loop — and conduit B, which has done nothing wrong, must
    /// still be able to park and claim its own forward *without A giving
    /// anything back*. The ceiling still holds at the same time: A is
    /// capped at its share, far below the pool.
    #[cfg(unix)]
    #[tokio::test]
    async fn one_conduit_cannot_take_more_than_its_share_or_block_another_conduits_claim() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let token_b = hub.register_forward_for_test("fid-b", conduit_b);

        // Conduit A runs many reverse forwards and parks a claim on each,
        // the way a real claim loop does — and keeps going past its share.
        let a_forwards: Vec<String> = (0..MAX_PARKED_CLAIMS_PER_HUB)
            .map(|n| {
                let forward_id = format!("fid-a{n}");
                hub.register_forward_for_test(&forward_id, conduit_a);
                forward_id
            })
            .collect();
        let held: Vec<_> = a_forwards
            .iter()
            .filter_map(|forward_id| hub.try_acquire_claim_permit(forward_id))
            .collect();

        assert_eq!(
            held.len(),
            MAX_PARKED_CLAIMS_PER_CONDUIT,
            "one conduit must be held to its own share no matter how many distinct forwards it \
             spreads its claims across"
        );
        // ("a share equal to the pool would be no share at all" is
        // asserted at the constants themselves, in a `const _` next to
        // `MAX_PARKED_CLAIMS_PER_CONDUIT` — a compile error there, not a
        // test failure here.)

        // Conduit B, entirely uninvolved, parks its own claim — with A
        // still holding every permit it was allowed. Nothing was freed.
        let claim_permit_b = hub
            .try_acquire_claim_permit("fid-b")
            .expect("a conduit sitting at its own share must not deny another conduit a claim");

        // ...and the claim actually completes, end to end, against a real
        // queued arrival: the share bounds *waiting*, never delivery.
        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send_b, _target_recv_b) = client.open_bi().await.unwrap();
        target_send_b.write_all(b"x").await.unwrap();
        let (daemon_send_b, daemon_recv_b) = server.accept_bi().await.unwrap();
        let tunnel_permit_b = hub.try_acquire_tunnel_permit().unwrap();
        hub.deliver_tcp_accepted(
            "fid-b",
            daemon_send_b,
            daemon_recv_b,
            Vec::new(),
            tunnel_permit_b,
        )
        .unwrap_or_else(|_| panic!("fid-b is registered to conduit_b"));
        let claimed_b = hub
            .claim_tcp_accepted("fid-b", &token_b, Duration::from_secs(5))
            .await;
        assert!(
            claimed_b.is_some(),
            "conduit B must be able to claim its own forward while conduit A sits at its share"
        );

        // The hub ceiling is still the outer bound: A's share plus B's one
        // claim is all that is outstanding, and the pool is nowhere near
        // spent — the share divided it, it did not inflate it.
        assert_eq!(
            hub.parked_claims_held(),
            MAX_PARKED_CLAIMS_PER_CONDUIT + 1,
            "no permit may be conjured by spreading claims across forwards or conduits"
        );

        drop(claim_permit_b);
        drop(held);
    }

    /// A queued `TCP_ACCEPTED` nobody ever claims must not pin this hub's
    /// capacity forever (adversarial review finding): each queued arrival
    /// holds one [`MAX_TUNNEL_STREAMS_PER_HUB`] permit and one live QUIC
    /// stream, and before [`ControlHub::sweep_expired_arrivals`] existed a
    /// queue drained only on a successful claim, a conduit death, or an
    /// owner-checked close — so one starved or slow claimant's backlog
    /// was charged against *every other* CLI's tunnels on this host with
    /// no bound on how long.
    ///
    /// Proves all three halves of the fix: the arrival is expired only
    /// once it is actually old, its permit comes back to the pool, and
    /// the stream is **reset with a real code** rather than dropped clean
    /// (a bare drop would tell the target this connection ended normally —
    /// [`TunnelArrival::reset`]'s own doc). The registration itself must
    /// survive: an idle `-R` whose backlog aged out is still a live
    /// forward.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_queued_arrival_nobody_claims_expires_resetting_its_stream_and_freeing_its_permit() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit_a);

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send, mut target_recv) = client.open_bi().await.unwrap();
        // See the sibling tests above for why `accept_bi` needs this first.
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        let permit = hub.try_acquire_tunnel_permit().unwrap();
        hub.deliver_tcp_accepted("fid-a", daemon_send, daemon_recv, Vec::new(), permit)
            .unwrap_or_else(|_| panic!("fid-a is registered"));
        assert_eq!(
            hub.tunnel_permits_available(),
            MAX_TUNNEL_STREAMS_PER_HUB - 1,
            "a queued arrival holds a real hub tunnel permit for its whole queued life"
        );

        // A fresh arrival is not expired — the sweep must bound the wait,
        // not shorten it to nothing.
        assert_eq!(
            hub.sweep_expired_arrivals(),
            0,
            "an arrival that has just been queued must not be swept"
        );
        assert_eq!(hub.queued_arrival_count("fid-a"), 1);

        hub.backdate_queued_arrivals_for_test(
            MAX_QUEUED_TUNNEL_ARRIVAL_AGE + Duration::from_secs(1),
        );
        assert_eq!(
            hub.sweep_expired_arrivals(),
            1,
            "an arrival past its budget must be expired"
        );

        // Both resources are back: the permit and the stream.
        assert_eq!(
            hub.tunnel_permits_available(),
            MAX_TUNNEL_STREAMS_PER_HUB,
            "expiring an arrival must return its hub tunnel permit to the pool every other CLI \
             on this host draws from"
        );
        assert_eq!(
            hub.queued_arrival_count("fid-a"),
            0,
            "the expired arrival must leave the queue, not merely be marked"
        );
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
            .await
            .expect("the reset must be observed promptly, not hang");
        match read {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(
                    code,
                    quinn::VarInt::from_u32(RESET_CODE_TUNNEL_CLAIM_EXPIRED),
                    "an expired arrival must reset visibly, with its own documented code — never \
                     drop clean, which would report a normal end for a connection nobody spliced"
                );
            }
            other => panic!("expected a stream reset, got {other:?}"),
        }

        // The forward itself is untouched: still owned, still claimable,
        // just with nothing queued for it now.
        assert_eq!(
            hub.forward_owner("fid-a"),
            Some(conduit_a),
            "expiring a backlog must not close the forward it belonged to"
        );
        assert!(
            hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(50))
                .await
                .is_none(),
            "the expired arrival must be gone from the queue, so a later claim waits for a new \
             one rather than being handed a stream that was already reset"
        );
    }

    /// Send `header` on a fresh bidi stream `conn` opens, mirroring
    /// exactly what a real target's `TCP_ACCEPTED` leg writes
    /// (`crate::tunnel::remote`'s own `open_fake_tcp_accepted` test
    /// helper plays back the identical handshake for the direct-connect
    /// leg). Returns the target-side halves so a test can observe how
    /// [`Listen::handle_tcp_accepted_stream`] answered.
    #[cfg(unix)]
    async fn open_fake_target_tcp_accepted(
        conn: &Connection,
        ticket: &[u8],
    ) -> (quinn::SendStream, quinn::RecvStream) {
        let (send, recv) = conn.open_bi().await.unwrap();
        let mut framed = qsh_transport::FramedStream::data(send, recv);
        framed
            .send
            .send(&wire::StreamHeader {
                kind: wire::StreamKind::TcpAccepted as i32,
                ticket: ticket.to_vec(),
                host: String::new(),
                port: 0,
            })
            .await
            .unwrap();
        let (send, recv) = framed.split();
        (send.into_raw(), recv.into_raw().0)
    }

    /// `PLAN.md` M4 Step 5 (a): "shape-check with `wire::valid_forward_id`
    /// before the lookup". A `TCP_ACCEPTED` whose ticket fails that shape
    /// check must never reach [`ControlHub::deliver_tcp_accepted`] at
    /// all — proven here by registering `"not valid!"` (space and `!` are
    /// outside `[A-Za-z0-9_-]`) to a real conduit first: if the shape
    /// check were skipped, this delivery would succeed.
    #[cfg(unix)]
    #[tokio::test]
    async fn handle_tcp_accepted_stream_rejects_a_malformed_ticket_before_any_registry_lookup() {
        assert!(!wire::valid_forward_id("not valid!"));
        let hub = test_hub();
        let (conduit, _rx) = hub.register_conduit();
        hub.register_forward_for_test("not valid!", conduit);

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (_target_send, mut target_recv) =
            open_fake_target_tcp_accepted(&client, b"not valid!").await;
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();

        Listen::handle_tcp_accepted_stream(daemon_send, daemon_recv, hub.clone()).await;

        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
            .await
            .expect("a malformed ticket must be rejected promptly, not hang");
        match read {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(
                    code,
                    quinn::VarInt::from_u32(RESET_CODE_TUNNEL_UNKNOWN_FORWARD)
                );
            }
            other => panic!("expected a stream reset, got {other:?}"),
        }
        // No permit was ever spent and no queue entry was ever created for
        // the malformed ticket's literal bytes — the cap is fully intact.
        assert_eq!(
            hub.tunnel_permits.available_permits(),
            MAX_TUNNEL_STREAMS_PER_HUB
        );
    }

    /// A `TCP_ACCEPTED` naming a real, currently-registered `forward_id`
    /// is queued by [`Listen::handle_tcp_accepted_stream`] and reachable
    /// by [`ControlHub::claim_tcp_accepted`] for exactly that id —
    /// the ordinary, successful path this whole relay exists to serve.
    #[cfg(unix)]
    #[tokio::test]
    async fn handle_tcp_accepted_stream_queues_a_registered_forward_id_for_its_conduit_to_claim() {
        let hub = test_hub();
        let (conduit, _rx) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit);

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (_target_send, _target_recv) = open_fake_target_tcp_accepted(&client, b"fid-a").await;
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();

        Listen::handle_tcp_accepted_stream(daemon_send, daemon_recv, hub.clone()).await;

        let claimed = hub
            .claim_tcp_accepted("fid-a", &token_a, Duration::from_secs(5))
            .await;
        assert!(
            claimed.is_some(),
            "a registered forward_id's TCP_ACCEPTED must be claimable"
        );
    }

    /// `PLAN.md` M4 Step 5 (a)'s hub cap applies to the `TCP_ACCEPTED`
    /// ingress path too, not just `TCP_CONNECT`: a `TCP_ACCEPTED` naming
    /// a real registered `forward_id` that arrives while this hub is
    /// already at [`MAX_TUNNEL_STREAMS_PER_HUB`] is reset with
    /// [`RESET_CODE_TUNNEL_HUB_EXHAUSTED`] before it is ever queued — the
    /// cap is exact even for a legitimately-registered id.
    #[cfg(unix)]
    #[tokio::test]
    async fn handle_tcp_accepted_stream_at_the_hub_cap_resets_rather_than_queues() {
        let hub = test_hub();
        let (conduit, _rx) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-a", conduit);
        let _held: Vec<_> = (0..MAX_TUNNEL_STREAMS_PER_HUB)
            .map(|_| hub.try_acquire_tunnel_permit().unwrap())
            .collect();

        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (_target_send, mut target_recv) =
            open_fake_target_tcp_accepted(&client, b"fid-a").await;
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();

        Listen::handle_tcp_accepted_stream(daemon_send, daemon_recv, hub.clone()).await;

        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), target_recv.read(&mut buf))
            .await
            .expect("a hub-exhausted rejection must be prompt, not hang");
        match read {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(
                    code,
                    quinn::VarInt::from_u32(RESET_CODE_TUNNEL_HUB_EXHAUSTED)
                );
            }
            other => panic!("expected a stream reset, got {other:?}"),
        }
        assert!(
            hub.claim_tcp_accepted("fid-a", &token_a, Duration::from_millis(50))
                .await
                .is_none(),
            "the rejected arrival must never have been queued"
        );
    }

    // ------------------------------------------------------------------
    // **Ownership: who may claim, who may close** (adversarial-review
    // round 2 — the three holes that made `isolation_holds` false). Every
    // test below is written from conduit B's side: B knows conduit A's
    // `forward_id` (leaked, guessed, or simply observed) and tries to be
    // delivered to, or to tear down, something that is not its own.
    // `PLAN.md` M4 Step 5 (a)'s framing applies verbatim — misdelivery
    // here is a security incident, not a bug.
    // ------------------------------------------------------------------

    /// A `RemoteForwardOpen` carrying `token`, so a test can drive a real
    /// registration through [`ControlHub::send_request`]/
    /// [`ControlHub::deliver_response`] — the only path that ever seats
    /// one in production — instead of the `register_forward_for_test`
    /// shortcut.
    #[cfg(unix)]
    fn rfwd_open_body_with_token(token: &[u8]) -> wire::control_message::Body {
        wire::control_message::Body::RfwdOpen(wire::RemoteForwardOpen {
            claim_token: token.to_vec(),
            ..Default::default()
        })
    }

    /// The `RemoteForwardOpened` a target answers with — this module's
    /// own copy of `control_hub_tests`' identical helper (a sibling test
    /// module's private items are not in scope here).
    #[cfg(unix)]
    fn rfwd_opened_response(forward_id: &str) -> wire::Response {
        wire::Response {
            body: Some(wire::response::Body::RfwdOpened(
                wire::RemoteForwardOpened {
                    forward_id: forward_id.to_string(),
                    actual_port: 0,
                },
            )),
        }
    }

    #[cfg(unix)]
    fn rfwd_close_body(forward_id: &str) -> wire::control_message::Body {
        wire::control_message::Body::RfwdClose(wire::RemoteForwardClose {
            forward_id: forward_id.to_string(),
        })
    }

    /// Queue one real `TCP_ACCEPTED` arrival for `forward_id` off a fresh
    /// loopback pair. The returned tuple keeps both connections and the
    /// target-side halves alive, so a test can observe whether that
    /// stream was ever reset (`TunnelArrival::reset`) — dropping the
    /// connection instead would make every read fail for the wrong
    /// reason.
    #[cfg(unix)]
    async fn queue_one_arrival(
        hub: &Arc<ControlHub>,
        forward_id: &str,
    ) -> (Connection, Connection, SendStream, RecvStream) {
        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send, target_recv) = client.open_bi().await.unwrap();
        // A QUIC peer only learns a stream exists once a frame
        // referencing it actually arrives.
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        let permit = hub
            .try_acquire_tunnel_permit()
            .expect("a fresh hub is under its cap");
        hub.deliver_tcp_accepted(forward_id, daemon_send, daemon_recv, Vec::new(), permit)
            .unwrap_or_else(|_| panic!("{forward_id} must be registered and claimable here"));
        (client, server, target_send, target_recv)
    }

    /// **Hole 1 — the check-then-use one.** Before this fix
    /// [`ControlHub::claim_tcp_accepted`] validated the presented token
    /// exactly once, at entry, and then — inside the wait — *popped* the
    /// arrival and re-checked only that the id was still registered to
    /// *someone*. So a claimant that parked while it legitimately owned
    /// `fid-x`, and stayed parked while `fid-x` was closed and re-opened
    /// by a different conduit, woke up and was handed the **new owner's**
    /// stream. This is the interleaving verbatim: A parks, the id is
    /// re-seated to B mid-wait, the arrival lands, and A wakes.
    ///
    /// A must leave with nothing, and B — the conduit that actually owns
    /// the id at the moment the arrival exists — must be able to claim
    /// it afterwards, proving the arrival was never consumed by A's wake.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_forward_id_re_seated_mid_wait_never_delivers_to_the_conduit_that_parked_first() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let token_a = hub.register_forward_for_test("fid-x", conduit_a);

        // A parks: nothing is queued for fid-x yet, and A's token is (for
        // now) the seated one, so this reaches the wait rather than being
        // refused at once.
        let parked = tokio::spawn({
            let hub = Arc::clone(&hub);
            let token_a = token_a.clone();
            async move {
                hub.claim_tcp_accepted("fid-x", &token_a, Duration::from_secs(5))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // fid-x is closed and re-opened while A sleeps: the id is
        // re-seated to conduit B, with B's own, different token.
        let token_b = hub.register_forward_for_test("fid-x", conduit_b);
        assert_ne!(token_a, token_b, "the re-seat must mint a different token");

        // The target opens a TCP_ACCEPTED for the *new* registration.
        // This is what wakes A.
        let _arrival = queue_one_arrival(&hub, "fid-x").await;

        let woken = tokio::time::timeout(Duration::from_secs(5), parked)
            .await
            .expect("the parked claimant must wake, not hang")
            .expect("the parked claim task must not panic");
        assert!(
            woken.is_none(),
            "a claimant parked under the *previous* seat must be refused when it wakes — \
             the token has to be re-validated against the current seat at the moment the \
             arrival changes hands, never once at entry"
        );

        let claimed_by_b = hub
            .claim_tcp_accepted("fid-x", &token_b, Duration::from_secs(5))
            .await;
        assert!(
            claimed_by_b.is_some(),
            "the arrival belongs to the current seat and must still be there for it — if A's \
             wake had consumed it, this is the assertion that catches the misdelivery"
        );
    }

    /// The same interleaving with the **owner unchanged** — hole 1's
    /// nastier half, and the reason the re-validation is against the
    /// *seat* and not against `ForwardRegistration::owner`. Conduit A
    /// closes `fid-x` and re-opens it (a new
    /// [`crate::tunnel::remote::RemoteForwardAcceptor`] instance, hence a
    /// new claim token) while an older claim of its own is still parked.
    /// A check that compared only the owning conduit would happily hand
    /// the new instance's stream to the stale one; only comparing the
    /// token catches it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stale_claim_is_refused_even_when_the_re_seat_keeps_the_same_owner() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let stale_token = hub.register_forward_for_test("fid-x", conduit_a);

        let parked = tokio::spawn({
            let hub = Arc::clone(&hub);
            let stale_token = stale_token.clone();
            async move {
                hub.claim_tcp_accepted("fid-x", &stale_token, Duration::from_secs(5))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Same conduit, same id, brand-new instance and therefore a
        // brand-new token.
        let fresh_token = hub.register_forward_for_test("fid-x", conduit_a);
        assert_ne!(stale_token, fresh_token);
        assert_eq!(
            hub.forward_owner("fid-x"),
            Some(conduit_a),
            "the owner is deliberately unchanged — only the seat moved"
        );

        let _arrival = queue_one_arrival(&hub, "fid-x").await;

        let woken = tokio::time::timeout(Duration::from_secs(5), parked)
            .await
            .expect("the parked claimant must wake, not hang")
            .expect("the parked claim task must not panic");
        assert!(
            woken.is_none(),
            "a stale token must be refused on wake even when the owning conduit never changed"
        );
        assert!(
            hub.claim_tcp_accepted("fid-x", &fresh_token, Duration::from_secs(5))
                .await
                .is_some(),
            "the current seat's own claim must still find the arrival"
        );
    }

    /// **Hole 2 — the capability that defaulted to "anyone".** A
    /// `RemoteForwardOpen` that carried no `claim_token` used to seat an
    /// *empty* token, and an empty seat matched any same-uid conduit
    /// presenting an empty token — worse than no capability at all,
    /// because the surrounding code read as though it were protected.
    /// Driven through the real `send_request`/`deliver_response` path,
    /// with `wire::RemoteForwardOpen::default()`'s empty token — exactly
    /// what `ops::tunnel::remote_forward_open_from_spec` produces today.
    ///
    /// The registration is kept (so the id stays attributed to its
    /// conduit, is swept when that conduit dies, and cannot be adopted by
    /// a duplicate `RemoteForwardOpened`) but is **permanently
    /// unclaimable**: no token claims it, an empty one least of all, and
    /// no arrival is ever queued for it — so it holds no hub permit and
    /// no live QUIC stream on the strength of a capability nobody holds.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_open_that_carried_no_claim_token_is_registered_permanently_unclaimable() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");

        hub.send_request(conduit_a, 0, rfwd_open_body_with_token(b""))
            .unwrap();
        let (open_id, _) = outbound.recv().await.expect("queued send");
        hub.deliver_response(open_id, rfwd_opened_response("fid-empty"));

        assert_eq!(
            hub.forward_owner("fid-empty"),
            Some(conduit_a),
            "the id is still registered and still attributable to the conduit that opened it"
        );
        assert!(
            !hub.forward_is_claimable("fid-empty"),
            "an open that carried no claim token must never end up with a token that passes"
        );

        // The exact adversarial move: present the same nothing the
        // registration carried.
        let started = std::time::Instant::now();
        assert!(
            hub.claim_tcp_accepted("fid-empty", b"", Duration::from_secs(5))
                .await
                .is_none(),
            "an empty presented token must be refused, never matched against an empty seat"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the refusal must come from the seat check, not from waiting out the whole budget"
        );
        assert!(
            hub.claim_tcp_accepted("fid-empty", b"guessed", Duration::from_millis(50))
                .await
                .is_none(),
            "and no other token claims it either — unclaimable is terminal"
        );

        // Nothing is ever queued for it, so it cannot pin a hub tunnel
        // permit or a live QUIC stream waiting for a claimant that can
        // never come.
        let (client, server) = crate::tunnel::testutil::loopback_pair().await;
        let (mut target_send, _target_recv) = client.open_bi().await.unwrap();
        target_send.write_all(b"x").await.unwrap();
        let (daemon_send, daemon_recv) = server.accept_bi().await.unwrap();
        let permit = hub.try_acquire_tunnel_permit().unwrap();
        let rejected = hub
            .deliver_tcp_accepted("fid-empty", daemon_send, daemon_recv, Vec::new(), permit)
            .expect_err("an unclaimable registration must be refused exactly like an unknown id");
        rejected.reset(RESET_CODE_TUNNEL_UNKNOWN_FORWARD);
        assert_eq!(
            hub.tunnel_permits.available_permits(),
            MAX_TUNNEL_STREAMS_PER_HUB,
            "the refused arrival must give its permit straight back"
        );
    }

    /// **Finding 5 — `claim_token` never reaches the outbound channel,**
    /// i.e. never reaches the bytes [`Listen::drive_registered_session`]'s
    /// `recv_outbound` arm actually serializes onto the live QUIC
    /// connection to the peer. Driven through the same real
    /// `send_request`/`deliver_response` path the two tests above use,
    /// with a real, distinguishable token — so this cannot pass by
    /// accident the way an empty-token test could.
    ///
    /// Both halves of the claim matter: the *outbound* copy must have lost
    /// it (this is the actual fix — mutation check: revert `send_request`'s
    /// `mem::take` back to `.clone()` and `open_body.claim_token` below
    /// reads back `b"peer-must-never-see-this"`, failing the first
    /// assertion) and the *local* seat must still have it, unchanged
    /// (mutation check: change the `mem::take` to simply drop the value
    /// instead of feeding it to `pending_rfwd_open_claim_tokens`, and the
    /// real-token claim at the end gets refused, failing the last
    /// assertion) — proving this is a relocation, not a loss.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_claim_token_is_taken_off_the_body_actually_sent_to_the_peer() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");

        const TOKEN: &[u8] = b"peer-must-never-see-this";
        hub.send_request(conduit_a, 0, rfwd_open_body_with_token(TOKEN))
            .unwrap();
        let (open_id, sent_body) = outbound.recv().await.expect("queued send");
        let open_body = match sent_body {
            wire::control_message::Body::RfwdOpen(open) => open,
            other => panic!("expected RfwdOpen, got {other:?}"),
        };
        assert!(
            open_body.claim_token.is_empty(),
            "the body actually handed to the outbound channel — what a real reverse driver \
             loop would serialize onto the wire to the target — must never carry claim_token, \
             got {:?}",
            open_body.claim_token
        );

        // Not lost — relocated: `deliver_response` still seats the real
        // token, and only the real token claims the resulting
        // registration.
        hub.deliver_response(open_id, rfwd_opened_response("fid-taken"));
        assert!(
            hub.claim_tcp_accepted("fid-taken", b"wrong-token", Duration::from_millis(50))
                .await
                .is_none(),
            "a wrong token must still be refused — taking claim_token off the outbound body \
             must not have widened the seat"
        );
        let _arrival = queue_one_arrival(&hub, "fid-taken").await;
        assert!(
            hub.claim_tcp_accepted("fid-taken", TOKEN, Duration::from_secs(5))
                .await
                .is_some(),
            "the real token, captured locally before it was taken off the outbound body, must \
             still claim the arrival"
        );
    }

    /// Hole 2's exhaustive half: **no registration this hub can produce,
    /// by any path, ever ends up with a token an empty claim matches** —
    /// and an empty presented token is refused against every seat, not
    /// just against the unclaimable one. All three producers are covered:
    /// a real token over the wire path, no token over the wire path, and
    /// the `register_forward_for_test` shortcut the other unit tests use.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_empty_claim_token_is_refused_against_every_seat_this_hub_can_hold() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");

        hub.send_request(conduit_a, 0, rfwd_open_body_with_token(b"real-token"))
            .unwrap();
        let (with_token_id, _) = outbound.recv().await.expect("queued send");
        hub.deliver_response(with_token_id, rfwd_opened_response("fid-token"));

        hub.send_request(conduit_a, 1, rfwd_open_body_with_token(b""))
            .unwrap();
        let (no_token_id, _) = outbound.recv().await.expect("queued send");
        hub.deliver_response(no_token_id, rfwd_opened_response("fid-none"));

        hub.register_forward_for_test("fid-shortcut", conduit_a);

        assert_eq!(
            hub.forward_registry_len(),
            3,
            "all three registrations exist — this test is about their seats, not their presence"
        );
        for forward_id in ["fid-token", "fid-none", "fid-shortcut"] {
            // Timed on purpose. A bare `is_none()` here would pass even
            // if the empty token were *admitted*, because no arrival is
            // queued and an admitted claim simply parks until its budget
            // runs out — the assertion would prove nothing. Given five
            // seconds and asserting the answer comes back inside one,
            // only an actual refusal at the seat check can satisfy it.
            let started = std::time::Instant::now();
            let claimed = hub
                .claim_tcp_accepted(forward_id, b"", Duration::from_secs(5))
                .await;
            assert!(
                claimed.is_none(),
                "{forward_id}: an empty claim token must never pass, whatever the seat holds"
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{forward_id}: an empty claim token must be refused at the seat check, not merely time out"
            );
        }
        assert!(
            hub.forward_is_claimable("fid-token") && hub.forward_is_claimable("fid-shortcut"),
            "a registration whose open carried a real token stays claimable by that token"
        );
        assert!(
            !hub.forward_is_claimable("fid-none"),
            "and only the one that carried nothing is unclaimable"
        );
    }

    /// **Hole 3 — any conduit could tear down any forward.** The
    /// `RemoteForwardClose` arm removed the registration and reset every
    /// queued arrival without ever comparing against the conduit
    /// `ControlMux::map_inbound` had just resolved, so conduit B could
    /// delete conduit A's forward and kill A's in-flight streams. Both
    /// halves are proven here:
    ///
    /// 1. **inbound** — B's close is answered `success` by the target at
    ///    a moment when the id is registered to A (B sent it before the
    ///    id existed, which is the one shape the relay must still
    ///    forward): nothing may change, and A's queued arrival must
    ///    survive un-reset and still be claimable.
    /// 2. **outbound** — once the id *is* registered to A, B's next close
    ///    is refused before a `daemon_request_id` is even minted and
    ///    without a byte reaching the target, which cannot tell the two
    ///    conduits apart itself.
    ///
    /// And the guard refuses non-owners rather than everyone: A's own
    /// close of its own forward still tears it down.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_conduit_can_neither_relay_nor_land_a_close_for_another_conduits_forward() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");

        // B asks to close "fid-a" before it exists — an id this hub does
        // not know is relayed (it may be a close racing its own open, and
        // the target is the right place to answer for it), so B really
        // does hold a live `daemon_request_id` for a close of that id.
        hub.send_request(conduit_b, 0, rfwd_close_body("fid-a"))
            .expect("a close for an unknown id is relayed, not refused");
        let (close_id_b, _) = outbound.recv().await.expect("queued send");

        // A opens fid-a for real.
        hub.send_request(conduit_a, 1, rfwd_open_body_with_token(b"token-a"))
            .unwrap();
        let (open_id_a, _) = outbound.recv().await.expect("queued send");
        hub.deliver_response(open_id_a, rfwd_opened_response("fid-a"));
        assert_eq!(hub.forward_owner("fid-a"), Some(conduit_a));

        // ... and an arrival is queued for A, waiting to be claimed.
        let (_client, _server, _target_send, mut target_recv) =
            queue_one_arrival(&hub, "fid-a").await;

        // (1) B's close lands, answered success, while A owns the id.
        hub.deliver_response(close_id_b, wire::Response { body: None });

        assert_eq!(
            hub.forward_owner("fid-a"),
            Some(conduit_a),
            "a close from a conduit that does not own the id must change nothing"
        );
        assert!(
            hub.forward_is_claimable("fid-a"),
            "and must not disturb its seat either"
        );
        let mut buf = [0u8; 8];
        let quiet =
            tokio::time::timeout(Duration::from_millis(200), target_recv.read(&mut buf)).await;
        assert!(
            quiet.is_err(),
            "the owner's queued stream must not be reset by a stranger's close, got {quiet:?}"
        );
        assert!(
            hub.claim_tcp_accepted("fid-a", b"token-a", Duration::from_secs(5))
                .await
                .is_some(),
            "and the owner must still be able to claim the arrival that was waiting for it"
        );

        // (2) B tries again now that the id is registered to A: refused
        // before anything is allocated, and nothing reaches the target.
        assert!(
            matches!(
                hub.send_request(conduit_b, 2, rfwd_close_body("fid-a")),
                Err(HubSendError::NotOwner)
            ),
            "a close for another conduit's forward must be refused, not relayed"
        );
        let leaked = tokio::time::timeout(Duration::from_millis(100), outbound.recv()).await;
        assert!(
            leaked.is_err(),
            "nothing may reach the target — it cannot tell the two conduits apart, got {leaked:?}"
        );

        // The owner's own close still works: this is a non-owner guard,
        // not a blanket refusal.
        hub.send_request(conduit_a, 3, rfwd_close_body("fid-a"))
            .expect("the owner's own close must still be relayed");
        let (close_id_a, _) = outbound.recv().await.expect("queued send");
        hub.deliver_response(close_id_a, wire::Response { body: None });
        assert!(
            hub.forward_owner("fid-a").is_none(),
            "the owner's own close must tear its own registration down"
        );
    }

    /// **Finding F5 — a target cannot squat a `forward_id` by answering
    /// the wrong request.** The `RfwdOpened` arm of
    /// [`ControlHub::deliver_response`] used to fire on any
    /// `daemon_request_id` whatsoever, so a misbehaving target could
    /// answer an ordinary, unrelated request (a `SessionRead` here —
    /// long-poll, correlated, entirely routine) with
    /// `RemoteForwardOpened { forward_id: Z }` and have Z registered
    /// under whichever conduit made that request. With no pending open
    /// there was no token to seat, so Z landed permanently unclaimable —
    /// and the conduit that later legitimately opened Z hit the
    /// duplicate-rejection arm, kept no registration of its own, and was
    /// left with a forward that silently never worked.
    ///
    /// Both halves are asserted: the unsolicited answer registers
    /// *nothing at all* (registry length, not just "this id is absent"),
    /// and the same `forward_id` is then opened and claimed end to end by
    /// its rightful conduit.
    ///
    /// Mutation check: drop the `pending_claim_token.is_none()` arm from
    /// `deliver_response` and the first assertion fails —
    /// `forward_registry_len()` is 1, the squatted registration owned by
    /// conduit A.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_rfwd_opened_answering_a_request_that_was_never_an_open_registers_nothing() {
        let hub = test_hub();
        let (conduit_a, _rx_a) = hub.register_conduit();
        let (conduit_b, _rx_b) = hub.register_conduit();
        let mut outbound = hub
            .take_outbound_receiver()
            .expect("hub has an outbound receiver");

        // Conduit A issues something that is not a forward open at all.
        hub.send_request(
            conduit_a,
            0,
            wire::control_message::Body::SessionRead(wire::SessionRead {
                session_id: "sess-1".into(),
                ..Default::default()
            }),
        )
        .expect("an ordinary session read is relayed");
        let (read_id, _) = outbound.recv().await.expect("queued send");

        // The target answers that read with a forward-open reply.
        hub.deliver_response(read_id, rfwd_opened_response("fid-squat"));

        assert_eq!(
            hub.forward_registry_len(),
            0,
            "a RemoteForwardOpened answering a request that was never a RemoteForwardOpen must \
             register nothing — under the answering conduit or anyone else"
        );
        assert!(
            hub.forward_owner("fid-squat").is_none(),
            "and the squatted id must be owned by nobody"
        );

        // The id is therefore still free, and its rightful opener gets a
        // real, claimable registration rather than the duplicate-rejection
        // path and a forward that never works.
        hub.send_request(conduit_b, 0, rfwd_open_body_with_token(b"token-b"))
            .unwrap();
        let (open_id, _) = outbound.recv().await.expect("queued send");
        hub.deliver_response(open_id, rfwd_opened_response("fid-squat"));
        assert_eq!(
            hub.forward_owner("fid-squat"),
            Some(conduit_b),
            "the conduit that legitimately opened the id must own it"
        );
        assert!(
            hub.forward_is_claimable("fid-squat"),
            "and its seat must hold the token its own open carried, not be dead on arrival"
        );
        let _arrival = queue_one_arrival(&hub, "fid-squat").await;
        assert!(
            hub.claim_tcp_accepted("fid-squat", b"token-b", Duration::from_secs(5))
                .await
                .is_some(),
            "the rightful owner must be able to claim its arrivals end to end"
        );

        // The gate is "was there a pending open", never "was the token
        // non-empty": an open that carried no token still registers, still
        // permanently unclaimable (`ClaimSeat::seat`), exactly as before.
        hub.send_request(conduit_b, 1, rfwd_open_body_with_token(b""))
            .unwrap();
        let (empty_open_id, _) = outbound.recv().await.expect("queued send");
        hub.deliver_response(empty_open_id, rfwd_opened_response("fid-empty-open"));
        assert_eq!(
            hub.forward_owner("fid-empty-open"),
            Some(conduit_b),
            "an open carrying an empty claim token is still a pending open and must still \
             register — the F5 gate must not have swallowed the empty-token path"
        );
        assert!(
            !hub.forward_is_claimable("fid-empty-open"),
            "and it must stay permanently unclaimable, exactly as it was before the gate"
        );
    }

    /// **Finding F2 — an orphaned parked claim must not hold its permit
    /// for its whole budget.** [`ControlHub::unregister_conduit`] removes
    /// a dead conduit's registrations and resets its queued arrivals, but
    /// nothing woke the claimants parked in
    /// [`ControlHub::claim_tcp_accepted`] on those very forwards. Each
    /// such claimant sat out the rest of its wait budget (up to
    /// `qsh_proto::local::LOCAL_WAIT_MAX`) still holding its
    /// [`ClaimPool`] permit, in a bucket keyed by a [`ConduitId`] that is
    /// never reissued — so the hub-wide pool shrank with no live conduit
    /// holding anything, and repeating it emptied the pool outright.
    ///
    /// Driven at the hub ceiling, across as many conduits as the pool
    /// divides into, because that is the shape of the exhaustion: every
    /// permit on this hub held by conduits that are all dead. The window
    /// asserted is one second of a sixty-second budget — a claimant that
    /// merely times out cannot satisfy it.
    ///
    /// Mutation check: remove `unregister_conduit`'s
    /// `tunnel_notify.notify_waiters()` and the parked claimants never
    /// wake — the bounded `timeout` around the join handle fails with
    /// "must wake when its forward is swept".
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn unregister_conduit_wakes_the_claims_parked_on_the_forwards_it_sweeps() {
        let hub = test_hub();
        let shares = MAX_PARKED_CLAIMS_PER_HUB / MAX_PARKED_CLAIMS_PER_CONDUIT;
        let mut conduits = Vec::new();
        let mut inboxes = Vec::new();
        let mut parked = Vec::new();

        // Fill the hub pool exactly, the way real claim loops do: one
        // parked claim per registered forward, each holding the permit
        // `LocalctlDaemon::serve_tcp_accepted` acquires before it calls
        // `claim_tcp_accepted` and drops the instant that call returns.
        for c in 0..shares {
            let (conduit, rx) = hub.register_conduit();
            inboxes.push(rx);
            conduits.push(conduit);
            for n in 0..MAX_PARKED_CLAIMS_PER_CONDUIT {
                let forward_id = format!("fid-{c}-{n}");
                let token = hub.register_forward_for_test(&forward_id, conduit);
                let permit = hub
                    .try_acquire_claim_permit(&forward_id)
                    .expect("every permit up to each owner's own share must be grantable");
                let hub_for_task = Arc::clone(&hub);
                parked.push(tokio::spawn(async move {
                    let claimed = hub_for_task
                        .claim_tcp_accepted(&forward_id, &token, Duration::from_secs(60))
                        .await;
                    drop(permit);
                    claimed
                }));
            }
        }
        // Let every spawned claim actually reach its wait.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            hub.parked_claims_held(),
            MAX_PARKED_CLAIMS_PER_HUB,
            "the pool must start out exactly spent — this test is about giving it back"
        );

        // Every one of those conduits dies.
        for conduit in conduits {
            hub.unregister_conduit(conduit);
        }

        for handle in parked {
            let woken = tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect(
                    "a claim parked on a forward whose conduit just died must wake when its \
                     forward is swept, not sit out its whole wait budget holding a permit",
                )
                .expect("the parked claim task must not panic");
            assert!(
                woken.is_none(),
                "a swept forward admits nobody — the woken claimant must leave with nothing"
            );
        }
        assert_eq!(
            hub.parked_claims_held(),
            0,
            "every permit must be back in the hub pool, not stranded in the bucket of a \
             ConduitId that will never be reissued"
        );

        // ...and the restored capacity is real: a different, live conduit
        // can take a full share and park on its own forward.
        let (late, _rx_late) = hub.register_conduit();
        let late_token = hub.register_forward_for_test("fid-late", late);
        let late_permits: Vec<_> = (0..MAX_PARKED_CLAIMS_PER_CONDUIT)
            .map(|_| {
                hub.try_acquire_claim_permit("fid-late")
                    .expect("a live conduit must be able to park once the dead ones let go")
            })
            .collect();
        let late_claim = tokio::spawn({
            let hub = Arc::clone(&hub);
            async move {
                hub.claim_tcp_accepted("fid-late", &late_token, Duration::from_secs(60))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !late_claim.is_finished(),
            "the late conduit's claim must reach the wait — parked on its own live forward, \
             not refused"
        );

        late_claim.abort();
        drop(late_permits);
        drop(inboxes);
    }
}
