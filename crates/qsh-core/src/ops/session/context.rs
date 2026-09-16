//! Per-attach driver state: the abort-on-drop helpers, [`AttachContext`], the reverse route, and the leg pumps.

use super::*;

/// A spawned task aborted when its handle is dropped, so tearing the
/// driver down takes its helpers with it.
pub(super) struct AbortOnDrop(pub(super) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Everything a recovery needs to rebuild a dead attach without going back
/// through the blocking `Ops` layer.
///
/// The peer is resolved **once**, when the attach is created: resolution
/// loads the device key, which platform key stores refuse to hand over from
/// inside a runtime, and a recovery re-dials from inside one.
pub(super) struct AttachContext {
    /// `Some` only on the forward route — `session_attach`'s own doc on
    /// why the reverse route never resolves one of these at all.
    /// [`reattach`] (the only reader) is reachable only when
    /// [`Self::link`] is [`RecoveryLink::Forward`] (`drive_attach`'s "no
    /// recovery on the reverse leg" gate), so this being `None` there is
    /// never actually observed.
    pub(super) target: Option<PeerTarget>,
    pub(super) host: String,
    pub(super) session_id: String,
    pub(super) session_ref: String,
    pub(super) paths: crate::config::Paths,
    pub(super) no_steal: bool,
    /// The transport this attach's hard-stop and recovery ride —
    /// [`RecoveryLink`]'s own doc.
    pub(super) link: RecoveryLink,
    /// The last window size the frontend asked for, if it ever did.
    ///
    /// A `Resize` is written straight through and is not part of the
    /// un-acked input axis, so one that lands while the path is dead is
    /// written to a stream nobody is reading. Remembering it lets the
    /// resume re-assert the geometry instead of leaving the remote PTY on
    /// a stale size until the user happens to resize again.
    pub(super) window: Arc<std::sync::Mutex<Option<(u16, u16)>>>,
    pub(super) recovery: RecoveryConfig,
    /// Set once the frontend deliberately ended the attach, so a connection
    /// **we** closed is never mistaken for a path that died and recovered
    /// from.
    pub(super) finished: Arc<std::sync::atomic::AtomicBool>,
    /// Highest cumulative input offset the host has confirmed *applying*
    /// (`InputAck`), published by whichever leg is reading.
    ///
    /// Separate from the un-acked buffer next to it, which the same acks
    /// drain, because this one has a waiter: the detach flush. A transport
    /// acknowledgement is not enough there — it says the bytes arrived,
    /// while the host only sends an `InputAck` once the child has actually
    /// been handed them (`crate::session_stream`), and a connection closed
    /// in between drops whatever the host had not read yet.
    pub(super) applied_input: tokio::sync::watch::Sender<u64>,
    /// `Some` only on the reverse route — the mirror image of
    /// [`Self::target`]'s "`Some` only on forward". Step 8's
    /// [`LocalReconnect`] input: which daemon to ask, and the highest
    /// registration generation this attach has ridden so far. Seeded at
    /// connect time by [`Ops::session_attach`]'s reverse arm from
    /// `LocalHelloAck.generation`, then advanced by every successful
    /// `LocalReconnect` landing — so a *second* leg death after a
    /// recovery waits past the generation the recovery itself landed on,
    /// never the original one again.
    pub(super) reverse_route: Option<ReverseRoute>,
}

impl AttachContext {
    pub(super) fn finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// [`AttachContext::reverse_route`]'s payload: which daemon socket and
/// host alias to reconnect to (`LocalHello.host`, `LocalRoute`'s own
/// fields — kept here as an owned copy rather than a borrow because this
/// outlives the `session_attach` call that resolved them), and the
/// generation baseline [`LocalReconnect`] must wait past. The generation
/// is interior-mutable (not just `u64`) because it is shared, through the
/// one `Arc<AttachContext>` every leg of this attach holds, between
/// whichever `LocalReconnect` is currently running and the next one
/// `drive_attach`'s gate builds after a *subsequent* leg death — see the
/// field's own doc on `AttachContext` for why the value must survive
/// across that boundary rather than being reset per-`LocalReconnect`.
pub(super) struct ReverseRoute {
    // `host`/`socket`/`generation` are read only by the `#[cfg(unix)]`
    // `local_reattach`/`LocalReconnect` dial path; the struct is still
    // constructed on every platform, so they are dead — not absent — on
    // Windows. (`registration_wait_ms` below stays live everywhere: the
    // recovery-report getter that reads it is not gated.)
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) host: String,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) socket: std::path::PathBuf,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) generation: std::sync::atomic::AtomicU64,
    /// Milliseconds the most recently *completed* [`LocalReconnect`] wait
    /// spent blocked on the daemon's new-generation registration before it
    /// could redeem the resume credential — measured across the wait
    /// only, not the redemption that follows it. This is Step 8's
    /// `registration_wait_ms` telemetry *input*: `docs/CLI.md` §6.4 names
    /// the field, and wiring it into the emitted `qsh::recovery` record is
    /// a later step's job, not this one's — this field only has to make
    /// the number available to whatever reads it next.
    /// `u64::MAX` means "no `LocalReconnect` wait has completed yet on
    /// this route" (the field's zero value would be indistinguishable
    /// from a wait that resolved instantly, which the daemon's own
    /// immediate-hit branch can genuinely do).
    pub(super) registration_wait_ms: std::sync::atomic::AtomicU64,
}

/// The reverse route's swappable hard-stop — the [`DataKillSwitch`]
/// counterpart to [`Link`]'s swappable endpoint/connection pair, and for
/// exactly the same reason ([`Link`]'s own doc: "every `AttachHandle` a
/// frontend already took — and the teardown path — must keep reaching the
/// live one"). Before Step 8 the reverse route never rebuilt a leg, so a
/// bare, un-swappable `DataKillSwitch` was enough; Step 8's
/// [`LocalReconnect`] lands a *new* `LOCAL_STREAM` conduit with its own
/// kill switch on every successful recovery, and every clone of
/// [`RecoveryLink::Reverse`] — [`AttachContext::link`]'s and
/// [`AttachHandle::link`]'s alike — has to observe that swap, not go on
/// killing the conduit that already died. One shared cell, exactly the
/// shape [`Link`] already uses.
#[derive(Clone, Default)]
pub(super) struct ReverseKill(Arc<std::sync::Mutex<DataKillSwitch>>);

impl ReverseKill {
    pub(super) fn new(kill: DataKillSwitch) -> Self {
        Self(Arc::new(std::sync::Mutex::new(kill)))
    }

    /// Shut the *current* conduit down — see [`DataKillSwitch::kill`].
    pub(super) fn kill(&self) {
        lock(&self.0).kill();
    }

    /// Install a new kill switch, handing back the one it replaced so the
    /// caller can decide whether it is still worth killing explicitly
    /// (mirrors [`Link::replace`]).
    // Only the `#[cfg(unix)]` `LocalReconnect` recovery swap calls this;
    // `kill`/`new` above are used cross-platform, `replace` is not.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) fn replace(&self, new: DataKillSwitch) -> DataKillSwitch {
        std::mem::replace(&mut *lock(&self.0), new)
    }
}

/// What an attach's [`AttachContext::link`]/[`AttachHandle::link`] rides —
/// the forward route's swappable [`Link`], or, on the reverse route
/// (`PLAN.md` M3 Step 7), this attach's own `LOCAL_STREAM` hard-stop,
/// swappable since Step 8 ([`ReverseKill`]'s own doc).
///
/// **Recovery on the reverse leg since Step 8** rides a different seam
/// than the forward route's, because the underlying transport really is
/// different: the forward route's migrate-or-resume machinery
/// ([`recover_attach`], [`reattach`], [`watch_path`]) is built on a QUIC
/// `Connection` this one attach owns exclusively — probeable for
/// liveness, swappable for a fresh dial, and safe to hand a full
/// `close()` to because nothing else is riding it. None of that holds on
/// the reverse route: the `Connection` a target sees is its *one*
/// long-lived registration to the controller, shared by every attach
/// every daemon-relayed CLI process has open to it, so there is nothing
/// attach-scoped to probe or migrate — only [`LocalReconnect`]'s wait-
/// then-reattach applies (`recover_attach`'s `link: None` branch, its own
/// doc). `drive_attach`'s gate still reads `&ctx.link` to decide *which*
/// [`Reconnect`] to build, but both branches now reach [`recover_attach`]
/// when `ctx.recovery.enabled` — a link death that recovery cannot use
/// (disabled, or `LocalReconnect` exhausted, `PLAN.md` M3 Step 8) still
/// ends the attach with a typed error (`LegEnd::Broken`'s existing path),
/// never a panic, an `unreachable!`, or a hang.
#[derive(Clone)]
pub(super) enum RecoveryLink {
    /// The forward route: a real, swappable QUIC endpoint/connection pair
    /// (recovery-capable — [`Link`]'s own doc).
    Forward(Link),
    /// The reverse route: this attach's own `LOCAL_STREAM` conduit,
    /// killable synchronously from any thread and swappable across a
    /// recovery ([`ReverseKill`]'s own doc) — no `Connection`, no
    /// `Endpoint`, nothing [`recover_attach`]'s migration half could
    /// probe (it never tries to on this route — its own doc).
    Reverse(ReverseKill),
}

/// How one leg of an attach ended.
pub(super) enum LegEnd {
    /// The host finished the data stream: the session is over.
    Ended,
    /// The frontend is gone; there is nobody to deliver to.
    Gone,
    /// The path was declared dead by the watchdog.
    PathDead,
    /// The data stream itself failed.
    Broken(ClientError),
}

impl LegEnd {
    /// Whether the leg's streams are still usable if the connection under
    /// them turns out to be alive.
    ///
    /// Only [`LegEnd::PathDead`] is: the watchdog suspects the *path*, and
    /// the streams on top of it are untouched, so a connection that
    /// answers a probe (or one a rebind rescues) can simply be read on.
    /// [`LegEnd::Broken`] is not — a reset or malformed `SESSION_DATA`
    /// stream stays broken however healthy the connection is (a host-side
    /// `RESET_CODE_SESSION_CONFLICT`/`RESET_CODE_BAD_HEADER` arrives on a
    /// perfectly live connection), so answering it with a migration would
    /// hand back the same failing reader for the driver to fail on again,
    /// immediately and forever. It has to be rebuilt.
    pub(super) fn leg_survived(&self) -> bool {
        matches!(self, LegEnd::PathDead)
    }
}

/// A leg's helper tasks, stoppable without losing queued input.
///
/// Stopping is a signal and a bounded wait, not an abort: a pump aborted
/// between taking a command off the queue and recording it would silently
/// eat a keystroke the user believes they typed. The abort is the fallback
/// for a pump parked mid-write on a connection that is already dead — by
/// then its bytes are recorded as un-acked and the resume retransmits them.
pub(super) struct LegPumps {
    pub(super) input: Option<Pump>,
    pub(super) control: Option<Pump>,
}

/// One pump: the signal that asks it to stop, and its handle.
pub(super) struct Pump {
    pub(super) stop: Option<tokio::sync::oneshot::Sender<()>>,
    pub(super) handle: tokio::task::JoinHandle<()>,
}

impl LegPumps {
    pub(super) async fn stop(&mut self) {
        for slot in [&mut self.input, &mut self.control] {
            {
                let Some(pump) = slot.as_mut() else {
                    continue;
                };
                if let Some(stop) = pump.stop.take() {
                    let _ = stop.send(());
                }
                // Awaited **in place**, with the handle still in the slot.
                // This future runs inside the recovery deadline and can be
                // cancelled here, and a dropped `JoinHandle` *detaches* its
                // task rather than aborting it — a pump left parked
                // mid-write on the dead connection would keep the shared
                // command queue locked, so the next leg's input pump could
                // not start. Leaving it in the slot means the retry, and
                // `Drop`, can still abort it.
                if tokio::time::timeout(PUMP_STOP_GRACE, &mut pump.handle)
                    .await
                    .is_err()
                {
                    pump.handle.abort();
                }
            }
            *slot = None;
        }
    }
}

impl Drop for LegPumps {
    fn drop(&mut self) {
        for slot in [&mut self.input, &mut self.control] {
            if let Some(pump) = slot.take() {
                pump.handle.abort();
            }
        }
    }
}
