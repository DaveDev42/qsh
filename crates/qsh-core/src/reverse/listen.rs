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
use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, Hello};
use qsh_transport::{AcceptError, Connection, FramedStream, Incoming, Listener};
use tokio::sync::mpsc;

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
                dead: false,
            }),
            outbound_tx,
            outbound_rx: Mutex::new(Some(outbound_rx)),
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
    /// `ControlMux::unregister_conduit`'s own contract) and drops its
    /// inbox sender. Idempotent — safe to call from both the conduit's
    /// own EOF path and a concurrent host-death sweep racing it.
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
        body: wire::control_message::Body,
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
        let Some((conduit, peer_request_id)) = state.mux.map_inbound(daemon_request_id) else {
            drop(state);
            // The conduit that asked for this died before the reply
            // arrived (`ControlMux::unregister_conduit` already cleared
            // its table entry) — dropped, unconditionally, including a
            // `SessionOpened` body (see this method's own doc comment for
            // why that is correct, not a leak).
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
        let inbox = state.inboxes.get(&conduit).cloned();
        drop(state);
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
                () = watch.dead() => break,
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
}
