//! Per-attach driver state: the abort-on-drop helpers, [`AttachContext`], and the leg pumps.

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
    /// Drawing state when the host granted screen sync for this attach
    /// (ADR-0052); a recovery asks for it again.
    pub(super) screen: Option<Arc<ScreenSink>>,
    /// What this attach knows about its host answering (ADR-0053 decision
    /// 9): the pumps report sends, the path watch of every leg reports
    /// replies, the recovery loop its attempt.
    pub(super) link_status: Arc<crate::client::linkstatus::LinkTracker>,
    /// The peer this attach dials. Resolved once, when the attach is
    /// created ([`reattach`] is the only reader).
    pub(super) target: PeerTarget,
    pub(super) host: String,
    pub(super) session_id: String,
    pub(super) session_ref: String,
    pub(super) paths: crate::config::Paths,
    pub(super) no_steal: bool,
    /// The swappable endpoint/connection pair this attach's hard-stop and
    /// recovery ride ([`Link`]'s own doc).
    pub(super) link: Link,
    /// The last window size the frontend asked for, if it ever did.
    ///
    /// A `Resize` is written straight through and is not part of the
    /// un-acked input axis, so one that lands while the path is dead is
    /// written to a stream nobody is reading. Remembering it lets the
    /// resume re-assert the geometry instead of leaving the remote PTY on
    /// a stale size until the user happens to resize again.
    pub(super) window: Arc<std::sync::Mutex<Option<(u16, u16)>>>,
    pub(super) recovery: RecoveryConfig,
    /// `[transport]` as read when the attach was created, so a recovery
    /// redial dials with the same keep-alive instead of re-reading
    /// `config.toml` from inside a runtime.
    pub(super) tuning: TransportTuning,
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
    /// The `-A` channel of this attach and the table it lives in. It stays
    /// registered for as long as the attach does, so a recovery's new
    /// connection can carry the same channel (ADR-0055 decision 9) and its
    /// `AGENT` streams still find it.
    pub(super) agent: Option<AgentAttach>,
}

/// An attach's agent forwarding state: the shared client agent and this
/// attach's registered channel, released when the attach ends.
pub(super) struct AgentAttach {
    pub(super) agent: Arc<crate::agent::ClientAgent>,
    pub(super) channel: crate::agent::AgentChannel,
}

impl AttachContext {
    pub(super) fn finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
    }
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
