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
use std::time::Duration;

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
use crate::broker::Clock;
#[cfg(any(unix, test))]
use crate::broker::SystemClock;
use crate::client::pathwatch::{PathWatch, PathWatchConfig, watch_path};
use crate::client::{ControlIn, Session};
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
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
        "qsh listen listening"
    );
    listen.run(listener, shutdown).await;
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

        loop {
            tokio::select! {
                biased;
                () = watch.dead() => break,
                () = probes.notified() => {
                    if session.send_ping().await.is_err() {
                        break;
                    }
                }
                message = session.next_control() => {
                    match message {
                        // The answer to our own liveness probe — proof the
                        // path carries packets, nothing more (mirrors
                        // `pump_attach_control`'s identical comment: counting
                        // this as activity would keep the watchdog inside the
                        // active window forever).
                        Ok(Some(ControlIn::Pong)) => watch.inbound(),
                        // Symmetric probing (Step 4): with a `PathWatch`
                        // driving *both* ends of a registered connection,
                        // every `Ping` reaching this arm is the target's
                        // own probe loop (`server::drive_probes`) asking
                        // the same liveness question this side is asking
                        // it — never real session traffic, since this
                        // driver never opens sessions (this method's own
                        // doc comment). Counting it as activity
                        // (`PathWatch::traffic`) would re-arm
                        // `active_window` on every reply and pin this
                        // watch to the fast cadence forever — the same
                        // failure mode `PathState::observe_inbound`'s doc
                        // comment already names for an inbound `Pong`,
                        // just from the other message direction. Bare
                        // liveness only.
                        Ok(Some(ControlIn::Ping { request_id })) => {
                            watch.inbound();
                            if session.send_pong(request_id).await.is_err() {
                                break;
                            }
                        }
                        Ok(Some(ControlIn::Request { request_id })) => {
                            watch.traffic();
                            if session.reject_unsupported(request_id).await.is_err() {
                                break;
                            }
                        }
                        // The controller opened nothing, so no
                        // `SessionEvent` is ever its own — unreachable in
                        // practice, but still counts as traffic if it ever
                        // arrives.
                        Ok(Some(ControlIn::Event(_))) => watch.traffic(),
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }
        watchdog.abort();

        let still_live = self.conns.remove_if(&name, generation);
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
