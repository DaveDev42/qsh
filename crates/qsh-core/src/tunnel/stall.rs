//! Per-connection ledger of stalled tunnel streams (ADR-0037,
//! `docs/design/protocol.md` §12).
//!
//! **The failure this exists for.** Bytes a tunnel stream has received but
//! its local consumer has not read hold that stream's receive window *and*
//! the connection's. A consumer that never reads therefore pins up to
//! [`TUNNEL_STREAM_RECEIVE_WINDOW`] of [`CONNECTION_RECEIVE_WINDOW`], and
//! four of them pin all of it: the peer has no connection-level credit left
//! for the same connection's `SESSION_DATA`, and the shell stops
//! (`crates/qsh-testkit/tests/tunnel_stalled_streams.rs`). [`pump`] is not
//! at fault (it stalls only its own direction, as designed); the shared
//! connection window is.
//!
//! **What this does.** Every tunnel splice on a connection registers one
//! [`StallWatch`] in that connection's [`StallLedger`]. The ledger keeps one
//! timestamp per stream: when the stream's receive-direction pump (QUIC to
//! local) entered the local write it is still inside, or nothing when it is
//! not writing. A stream whose local write has made no progress for
//! [`STALL_AGE`] is stalled; a consumer that reads even slowly is not,
//! because every partial write resets the timestamp. Every
//! [`EVALUATE_INTERVAL`], the ledger:
//!
//! - stops the oldest stalled streams while more than
//!   [`MAX_STALLED_STREAMS_PER_CONNECTION`] are stalled (ADR-0037 decision
//!   3), so stalled streams can hold at most one stream window less than
//!   the connection window, and
//! - stops the single oldest stalled stream when the peer's `DATA_BLOCKED`
//!   count rose within [`DATA_BLOCKED_MEMORY`] (decision 4) — the case
//!   where several almost-stopped consumers fill the window without any of
//!   them holding a full stream window.
//!
//! Stopping is the splice's existing truncation teardown with
//! [`RESET_CODE_TUNNEL_STALLED`] instead of the generic abort code, so the
//! local application sees an RST, never a clean end (decision 6). quinn
//! returns a stopped stream's unread bytes to the connection's credit at
//! once, which is what un-starves the shell.
//!
//! Only tunnel splices register here: control, `SESSION_DATA` and
//! `EXEC_DATA` streams never appear in a ledger and are never stopped by
//! one (decision 5). There is no configuration switch (decision 9).
//!
//! The ledger holds byte *counts* and timestamps only — there is no field a
//! payload byte could be put in (`crate::tunnel::splice`'s module doc).
//!
//! **A second reader of the same counters: traffic hooks.** Every byte a
//! tunnel splice moves, on either end and through the `localctl` relay
//! alike, is reported through a [`StreamTrack`], which makes it the one
//! place that sees tunnel traffic on a connection whose control stream is
//! quiet. A reverse registration's path watch needs exactly that: it holds
//! the fast probe cadence only while the registration is *in use*
//! (`PathWatchConfig::active_window`), and a registration that carries
//! nothing but tunnels sends no control message the watch could count
//! (ADR-0041 decision 6). [`report_traffic`] registers a hook for one
//! connection; the tracks created on that connection call it whenever a
//! pump moves bytes. The hook carries no payload and no count, only "bytes
//! moved".
//!
//! [`pump`]: crate::tunnel::splice::pump

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use qsh_transport::endpoint::{CONNECTION_RECEIVE_WINDOW, TUNNEL_STREAM_RECEIVE_WINDOW};
use tokio::sync::Notify;

/// How long a stream's local write may make no progress at all before the
/// stream counts as stalled (ADR-0037 decision 2). Far above any write
/// stall a live consumer produces: `tunnel_throughput_meets_raw_quinn_ratio`
/// and `tunnel_saturated_pty_echo_p95_under_measured_rtt_plus_10ms` drive
/// line-rate consumers through the same splice without ever tripping it.
pub(crate) const STALL_AGE: Duration = Duration::from_secs(1);

/// How many tunnel streams on one connection may be stalled at once
/// (ADR-0037 decision 3): one stream window short of the connection window,
/// so the stalled streams together can never hold more than
/// `CONNECTION_RECEIVE_WINDOW - TUNNEL_STREAM_RECEIVE_WINDOW` (6 MiB today)
/// and every other stream on the connection, the PTY's included, keeps at
/// least one stream window of credit. Written as the relation, not the
/// number, so a change to either window constant moves it too.
pub(crate) const MAX_STALLED_STREAMS_PER_CONNECTION: usize =
    (CONNECTION_RECEIVE_WINDOW / TUNNEL_STREAM_RECEIVE_WINDOW as u64) as usize - 1;

// The relation above only protects anything if it leaves room for at
// least one stalled stream and at least one stream window of credit.
const _: () = assert!(MAX_STALLED_STREAMS_PER_CONNECTION >= 1);
const _: () = assert!(
    (MAX_STALLED_STREAMS_PER_CONNECTION as u64 + 1) * TUNNEL_STREAM_RECEIVE_WINDOW as u64
        <= CONNECTION_RECEIVE_WINDOW
);

/// How often a connection's ledger re-evaluates its streams. A quarter of
/// [`STALL_AGE`], so a stream is stopped at most this long after it
/// qualifies.
pub(crate) const EVALUATE_INTERVAL: Duration = Duration::from_millis(250);

/// How long a rise in the peer's `DATA_BLOCKED` count stays eligible to
/// trigger ADR-0037 decision 4. The rise and the stall need not be seen on
/// the same tick: the peer reports `DATA_BLOCKED` once when it runs out of
/// credit, while the stream that caused it only qualifies as stalled
/// [`STALL_AGE`] after its write stopped. Two stall ages cover that gap; a
/// rise older than this belonged to a moment that has since passed.
pub(crate) const DATA_BLOCKED_MEMORY: Duration = Duration::from_secs(2);

/// QUIC application error code a stalled tunnel stream is reset and
/// stopped with (ADR-0037 decision 6). Internal, like
/// [`crate::tunnel::splice::RESET_CODE_TUNNEL_ABORT`] (`0x2007`): kept
/// distinct from it only so diagnostics and audit can tell "the splice
/// failed" from "the stall limit stopped it". A receiving peer does not
/// branch on it (`docs/design/protocol.md` §16.5).
pub(crate) const RESET_CODE_TUNNEL_STALLED: u32 = 0x200E;

/// Why a stalled stream was stopped (ADR-0037 decisions 3 and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StallReason {
    /// More than [`MAX_STALLED_STREAMS_PER_CONNECTION`] were stalled.
    StalledLimit,
    /// The peer reported `DATA_BLOCKED` while a stream was stalled.
    DataBlocked,
}

impl StallReason {
    /// The `reason` field of the eviction diagnostic.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            StallReason::StalledLimit => "stalled_limit",
            StallReason::DataBlocked => "data_blocked",
        }
    }
}

/// Knobs the production ledger takes from the constants above; tests build
/// ledgers with shorter ones so they do not wait whole seconds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StallParams {
    pub(crate) stall_age: Duration,
    pub(crate) max_stalled: usize,
    pub(crate) data_blocked_memory: Duration,
    pub(crate) evaluate_interval: Duration,
}

impl StallParams {
    pub(crate) const PRODUCTION: StallParams = StallParams {
        stall_age: STALL_AGE,
        max_stalled: MAX_STALLED_STREAMS_PER_CONNECTION,
        data_blocked_memory: DATA_BLOCKED_MEMORY,
        evaluate_interval: EVALUATE_INTERVAL,
    };
}

/// One tunnel stream's entry: the timestamp the ledger judges by, the two
/// byte counts the eviction diagnostic reports, and the eviction signal.
pub(crate) struct StreamTrack {
    id: u64,
    /// `host:port` or `forward_id` — the tunnel identifier the diagnostic
    /// names (ADR-0037 decision 7). Never payload.
    label: String,
    epoch: Instant,
    /// Microseconds since `epoch`, plus one, at which the receive-direction
    /// pump entered the local write it is still inside; `0` while it is not
    /// inside one.
    write_entered: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
    evicted: AtomicBool,
    notify: Notify,
    /// The connection's [`report_traffic`] hook as of this stream's start.
    traffic: Option<TrafficHook>,
}

impl StreamTrack {
    fn note_traffic(&self, n: usize) {
        if n > 0
            && let Some(hook) = &self.traffic
        {
            hook();
        }
    }

    fn stamp(&self, at: Instant) -> u64 {
        let micros = at.saturating_duration_since(self.epoch).as_micros();
        u64::try_from(micros).unwrap_or(u64::MAX - 1) + 1
    }

    /// The receive-direction pump is about to wait on a local write.
    pub(crate) fn enter_write(&self) {
        self.write_entered
            .store(self.stamp(Instant::now()), Ordering::Relaxed);
    }

    /// That write returned, having moved `n` bytes (or failed with `0`).
    pub(crate) fn leave_write(&self, n: usize) {
        self.write_entered.store(0, Ordering::Relaxed);
        self.received.fetch_add(n as u64, Ordering::Relaxed);
        self.note_traffic(n);
    }

    /// The send-direction pump moved `n` bytes (counted for the diagnostic
    /// only — that direction never stalls the connection's receive window).
    pub(crate) fn count_sent(&self, n: usize) {
        self.sent.fetch_add(n as u64, Ordering::Relaxed);
        self.note_traffic(n);
    }

    /// When the current local write began, if the pump is inside one.
    fn write_entered_at(&self) -> Option<Instant> {
        match self.write_entered.load(Ordering::Relaxed) {
            0 => None,
            stamp => Some(self.epoch + Duration::from_micros(stamp - 1)),
        }
    }

    #[cfg(test)]
    pub(crate) fn force_write_entered_at(&self, at: Instant) {
        self.write_entered.store(self.stamp(at), Ordering::Relaxed);
    }
}

/// A stream the ledger decided to stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Eviction {
    pub(crate) id: u64,
    pub(crate) reason: StallReason,
    pub(crate) stalled_for: Duration,
}

struct LedgerState {
    next_id: u64,
    tracks: HashMap<u64, Arc<StreamTrack>>,
    last_data_blocked: u64,
    data_blocked_rose_at: Option<Instant>,
}

/// The stall ledger of one QUIC connection (ADR-0037 decision 1). Shared
/// by every tunnel splice on that connection, on either end and through
/// the `localctl` daemon's relay alike (decision 8).
pub(crate) struct StallLedger {
    /// Read for `DATA_BLOCKED` only. Holding it keeps the connection's
    /// state alive exactly as long as the splices registered here do —
    /// each of them already holds the connection through its own streams —
    /// so the ledger never outlives what it watches by more than that.
    conn: quinn::Connection,
    epoch: Instant,
    params: StallParams,
    state: Mutex<LedgerState>,
}

type Registry = Mutex<HashMap<usize, Weak<StallLedger>>>;

/// Called when a tunnel stream on a connection moves bytes. Cheap enough to
/// run per chunk (a path watch takes one short mutex), and never given the
/// bytes.
pub(crate) type TrafficHook = Arc<dyn Fn() + Send + Sync>;

type TrafficHooks = Mutex<HashMap<usize, TrafficHook>>;

fn traffic_hooks() -> &'static TrafficHooks {
    static HOOKS: OnceLock<TrafficHooks> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Report the tunnel traffic of `conn` to `hook` for as long as the returned
/// guard lives. One hook per connection: a second registration on the same
/// connection replaces the first, and the first's guard then leaves the
/// second's entry alone.
///
/// Keyed by `stable_id` like the ledger registry. The guard removes the
/// entry, so a hook never outlives the registration that owns it and the id
/// of a closed connection is not left behind.
pub(crate) fn report_traffic(conn: &quinn::Connection, hook: TrafficHook) -> TrafficGuard {
    let id = conn.stable_id();
    let token = Arc::as_ptr(&hook).cast::<()>() as usize;
    lock(traffic_hooks()).insert(id, hook);
    TrafficGuard { id, token }
}

/// See [`report_traffic`].
#[must_use = "dropping the guard stops the reporting"]
pub(crate) struct TrafficGuard {
    id: usize,
    /// Address of the hook this guard installed, so a replaced entry is not
    /// removed by the guard it replaced.
    token: usize,
}

impl Drop for TrafficGuard {
    fn drop(&mut self) {
        let mut hooks = lock(traffic_hooks());
        if hooks
            .get(&self.id)
            .is_some_and(|hook| Arc::as_ptr(hook).cast::<()>() as usize == self.token)
        {
            hooks.remove(&self.id);
        }
    }
}

fn traffic_hook_for(conn: &quinn::Connection) -> Option<TrafficHook> {
    lock(traffic_hooks()).get(&conn.stable_id()).cloned()
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl StallLedger {
    /// The ledger of `conn`, created (and its evaluation task spawned) on
    /// first use. Keyed by `stable_id`: a live ledger holds `conn`, so its
    /// id cannot be reused by another connection while the entry upgrades.
    pub(crate) fn for_connection(conn: &quinn::Connection) -> Arc<StallLedger> {
        let mut registry = lock(registry());
        registry.retain(|_, ledger| ledger.strong_count() > 0);
        if let Some(ledger) = registry.get(&conn.stable_id()).and_then(Weak::upgrade) {
            return ledger;
        }
        let ledger = Self::start(conn.clone(), StallParams::PRODUCTION);
        registry.insert(conn.stable_id(), Arc::downgrade(&ledger));
        ledger
    }

    /// A ledger outside the registry with its own parameters, evaluation
    /// task included.
    pub(crate) fn start(conn: quinn::Connection, params: StallParams) -> Arc<StallLedger> {
        let ledger = Self::new_unstarted(conn, params);
        tokio::spawn(evaluate_loop(
            Arc::downgrade(&ledger),
            params.evaluate_interval,
        ));
        ledger
    }

    fn new_unstarted(conn: quinn::Connection, params: StallParams) -> Arc<StallLedger> {
        let last_data_blocked = conn.stats().frame_rx.data_blocked;
        Arc::new(StallLedger {
            conn,
            epoch: Instant::now(),
            params,
            state: Mutex::new(LedgerState {
                next_id: 0,
                tracks: HashMap::new(),
                last_data_blocked,
                data_blocked_rose_at: None,
            }),
        })
    }

    /// Register one tunnel splice. The entry lives exactly as long as the
    /// returned watch.
    pub(crate) fn watch(self: &Arc<Self>, label: impl Into<String>) -> StallWatch {
        let mut state = lock(&self.state);
        let id = state.next_id;
        state.next_id += 1;
        let track = Arc::new(StreamTrack {
            id,
            label: label.into(),
            epoch: self.epoch,
            write_entered: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            evicted: AtomicBool::new(false),
            notify: Notify::new(),
            traffic: traffic_hook_for(&self.conn),
        });
        state.tracks.insert(id, Arc::clone(&track));
        StallWatch {
            ledger: Arc::clone(self),
            track,
        }
    }

    /// One evaluation tick against the connection's live `DATA_BLOCKED`
    /// count: decide, then signal every chosen stream and log it.
    fn tick(&self, now: Instant) {
        let data_blocked = self.conn.stats().frame_rx.data_blocked;
        let evictions = self.decide(now, data_blocked);
        if evictions.is_empty() {
            return;
        }
        let state = lock(&self.state);
        for eviction in evictions {
            let Some(track) = state.tracks.get(&eviction.id) else {
                continue;
            };
            track.evicted.store(true, Ordering::Relaxed);
            track.notify.notify_one();
            // Structural only (ADR-0037 decision 7): the tunnel's
            // identifier, how long it stalled, byte counts, the reason.
            tracing::warn!(
                tunnel = %track.label,
                stalled_ms = u64::try_from(eviction.stalled_for.as_millis()).unwrap_or(u64::MAX),
                sent = track.sent.load(Ordering::Relaxed),
                received = track.received.load(Ordering::Relaxed),
                reason = eviction.reason.as_str(),
                "qsh::tunnel: stopped a stalled tunnel stream to keep the connection's receive window open"
            );
        }
    }

    /// ADR-0037 decisions 3 and 4, given the time and the peer's current
    /// `DATA_BLOCKED` count. Pure apart from recording the count; returns
    /// the streams to stop, oldest stall first.
    pub(crate) fn decide(&self, now: Instant, data_blocked: u64) -> Vec<Eviction> {
        let mut state = lock(&self.state);
        if data_blocked > state.last_data_blocked {
            state.data_blocked_rose_at = Some(now);
        }
        state.last_data_blocked = data_blocked;

        let mut stalled: Vec<(u64, Instant)> = state
            .tracks
            .values()
            .filter(|track| !track.evicted.load(Ordering::Relaxed))
            .filter_map(|track| {
                let since = track.write_entered_at()?;
                (now.saturating_duration_since(since) >= self.params.stall_age)
                    .then_some((track.id, since))
            })
            .collect();
        stalled.sort_by_key(|&(id, since)| (since, id));

        let chosen: Vec<(u64, Instant, StallReason)> = if stalled.len() > self.params.max_stalled {
            let excess = stalled.len() - self.params.max_stalled;
            stalled
                .iter()
                .take(excess)
                .map(|&(id, since)| (id, since, StallReason::StalledLimit))
                .collect()
        } else if let (Some(&(id, since)), Some(rose_at)) =
            (stalled.first(), state.data_blocked_rose_at)
            && now.saturating_duration_since(rose_at) <= self.params.data_blocked_memory
        {
            vec![(id, since, StallReason::DataBlocked)]
        } else {
            Vec::new()
        };
        if !chosen.is_empty() {
            // Whatever rise there was has now been answered.
            state.data_blocked_rose_at = None;
        }
        chosen
            .into_iter()
            .map(|(id, since, reason)| Eviction {
                id,
                reason,
                stalled_for: now.saturating_duration_since(since),
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn unstarted_for_test(
        conn: quinn::Connection,
        params: StallParams,
    ) -> Arc<StallLedger> {
        Self::new_unstarted(conn, params)
    }

    #[cfg(test)]
    pub(crate) fn tick_for_test(&self, now: Instant) {
        self.tick(now);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        lock(&self.state).tracks.len()
    }

    /// When stream `id`'s receive-direction pump entered the local write it
    /// is still inside, if it is inside one.
    #[cfg(test)]
    pub(crate) fn writing_since(&self, id: u64) -> Option<Instant> {
        lock(&self.state).tracks.get(&id)?.write_entered_at()
    }

    #[cfg(test)]
    pub(crate) fn force_writing_since(&self, id: u64, at: Instant) {
        if let Some(track) = lock(&self.state).tracks.get(&id) {
            track.force_write_entered_at(at);
        }
    }
}

/// Re-evaluates one ledger every `interval` until the last watch on it is
/// gone.
async fn evaluate_loop(ledger: Weak<StallLedger>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(ledger) = ledger.upgrade() else {
            return;
        };
        ledger.tick(Instant::now());
    }
}

/// One tunnel splice's registration in its connection's [`StallLedger`].
/// Dropping it removes the entry.
pub(crate) struct StallWatch {
    ledger: Arc<StallLedger>,
    track: Arc<StreamTrack>,
}

impl StallWatch {
    /// A watch on `conn`'s production ledger.
    pub(crate) fn on(conn: &quinn::Connection, label: impl Into<String>) -> StallWatch {
        StallLedger::for_connection(conn).watch(label)
    }

    /// The entry the splice's pumps report progress to.
    pub(crate) fn track(&self) -> &StreamTrack {
        &self.track
    }

    /// Resolves once the ledger has chosen this stream to stop.
    /// Cancel-safe: the signal is a stored [`Notify`] permit, so a call
    /// started after the ledger fired still resolves.
    pub(crate) async fn evicted(&self) {
        self.track.notify.notified().await;
    }

    #[cfg(test)]
    pub(crate) fn id(&self) -> u64 {
        self.track.id
    }
}

impl Drop for StallWatch {
    fn drop(&mut self) {
        lock(&self.ledger.state).tracks.remove(&self.track.id);
    }
}

#[cfg(test)]
mod tests;
