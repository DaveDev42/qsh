//! The carrier a `-L`/`-D` accept loop reads at accept time (ADR-0023
//! decisions 3 and 5).
//!
//! Before this module the accept loops took one `Arc<ForwardCarrier>` at
//! start and used it for the forward's whole life. A supervised tunnel has
//! to swap the connection under a running listener, so the loops now read a
//! [`CarrierView`] instead: a `watch` channel whose value is either a live
//! carrier or "disconnected". A default (unsupervised) forward builds a
//! [`CarrierView::fixed`] view whose value never changes, so its behavior is
//! exactly what it was with the bare `Arc`.
//!
//! While the state is [`CarrierState::Disconnected`] a new connection is not
//! queued: `-L` resets it and `-D` answers `REP 0x01` at `CONNECT`. A
//! connection that is still waiting for `ConnectResult` on a carrier that
//! has since been left is refused the same way ([`CarrierView::left`]); one
//! that is already splicing is not touched.
//!
//! `--accept-hold` (decision 19) is the one exception to that refusal: a
//! view built [`with_hold`](CarrierView::with_hold) keeps a connection for up
//! to the hold window while a re-establishment is under way or about to
//! start, sends nothing for it, and dispatches it in the order it was taken
//! once the carrier is live again. Past the window, or past
//! [`HELD_MAX`] connections, it is refused exactly as above.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::time::Instant;

use crate::tunnel::local::ForwardCarrier;

/// What a forward can open tunnel streams on right now.
pub(crate) enum CarrierState {
    /// A carrier that is believed alive.
    Live(Arc<ForwardCarrier>),
    /// The carrier was declared lost and no replacement is up yet.
    Disconnected,
}

/// Called once per accepted connection so a supervisor can tell that the
/// forward is in use (ADR-0023 decision 4's `observe_activity`).
pub(crate) type ActivityHook = Arc<dyn Fn() + Send + Sync>;

/// The most connections one tunnel keeps at once while it is disconnected
/// (ADR-0023 decision 19).
pub(crate) const HELD_MAX: usize = 64;

/// A cheap, cloneable reader of the current [`CarrierState`].
#[derive(Clone)]
pub(crate) struct CarrierView {
    rx: watch::Receiver<CarrierState>,
    activity: Option<ActivityHook>,
    /// Told which carrier a peer answered `PERMISSION_DENIED` on.
    denied: Option<mpsc::UnboundedSender<Arc<ForwardCarrier>>>,
    /// Present only for a tunnel opened with `--accept-hold`.
    hold: Option<HoldGate>,
}

impl CarrierView {
    /// A view whose value is `carrier` for as long as anything reads it.
    /// The sender is dropped at once, which `watch` allows: the last value
    /// stays readable.
    pub(crate) fn fixed(carrier: Arc<ForwardCarrier>) -> Self {
        let (_tx, rx) = watch::channel(CarrierState::Live(carrier));
        Self {
            rx,
            activity: None,
            denied: None,
            hold: None,
        }
    }

    /// A view over a channel a supervisor writes to.
    pub(crate) fn watching(
        rx: watch::Receiver<CarrierState>,
        activity: Option<ActivityHook>,
    ) -> Self {
        Self {
            rx,
            activity,
            denied: None,
            hold: None,
        }
    }

    /// Keep connections that arrive while disconnected, as `gate` allows
    /// (decision 19).
    pub(crate) fn with_hold(mut self, gate: HoldGate) -> Self {
        self.hold = Some(gate);
        self
    }

    /// Report peer `PERMISSION_DENIED` answers to a supervisor (ADR-0023
    /// decision 9: the peer's policy only changes with a restart, so the
    /// supervisor ends the tunnel rather than let every connection be
    /// refused forever).
    pub(crate) fn with_denied(mut self, tx: mpsc::UnboundedSender<Arc<ForwardCarrier>>) -> Self {
        self.denied = Some(tx);
        self
    }

    /// The peer refused a `TCP_CONNECT` on `carrier` with
    /// `PERMISSION_DENIED`.
    pub(crate) fn note_permission_denied(&self, carrier: &Arc<ForwardCarrier>) {
        if let Some(tx) = &self.denied {
            let _ = tx.send(Arc::clone(carrier));
        }
    }

    /// The carrier to open a stream on now, or `None` while disconnected.
    pub(crate) fn current(&self) -> Option<Arc<ForwardCarrier>> {
        match &*self.rx.borrow() {
            CarrierState::Live(carrier) => Some(Arc::clone(carrier)),
            CarrierState::Disconnected => None,
        }
    }

    /// What to do with a connection that has just been accepted: ride the
    /// live carrier, be kept for a moment, or be refused (decision 6).
    /// Decided without awaiting, so a caller that runs it in its accept loop
    /// takes its place in the hold queue in accept order.
    pub(crate) fn admit(&self) -> Admit {
        if let Some(carrier) = self.current() {
            return Admit::Live(carrier);
        }
        if let Some(held) = self.begin_hold() {
            return Admit::Held(held);
        }
        // The carrier can have come back between the two reads above.
        match self.current() {
            Some(carrier) => Admit::Live(carrier),
            None => Admit::Refused,
        }
    }

    fn begin_hold(&self) -> Option<Held> {
        let gate = self.hold.as_ref()?;
        let now = Instant::now();
        // `None`: no attempt is scheduled (the carrier is live, or the
        // tunnel is over), so there is nothing to wait for.
        let starts = (*gate.next_attempt.borrow())?;
        // A long backoff wait outside the window is not held (decision 19).
        if starts > now + gate.window {
            return None;
        }
        let permit = Arc::clone(&gate.slots).try_acquire_owned().ok()?;
        Some(Held {
            deadline: now + gate.window,
            _permit: permit,
            ticket: gate.turns.enter(),
        })
    }

    /// Tell the supervisor, if there is one, that a connection arrived.
    pub(crate) fn note_activity(&self) {
        if let Some(hook) = &self.activity {
            hook();
        }
    }

    /// Resolves once the state is anything other than `Live(carrier)`:
    /// disconnected, or a different carrier. Never resolves for a
    /// [`Self::fixed`] view. Cancel-safe.
    pub(crate) async fn left(&self, carrier: &Arc<ForwardCarrier>) {
        let mut rx = self.rx.clone();
        loop {
            let still_live = matches!(
                &*rx.borrow_and_update(),
                CarrierState::Live(c) if Arc::ptr_eq(c, carrier)
            );
            if !still_live {
                return;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

impl From<Arc<ForwardCarrier>> for CarrierView {
    fn from(carrier: Arc<ForwardCarrier>) -> Self {
        Self::fixed(carrier)
    }
}

/// The outcome of [`CarrierView::admit`].
pub(crate) enum Admit {
    /// The carrier is live: use it.
    Live(Arc<ForwardCarrier>),
    /// Kept until the carrier is live again or the window ends.
    Held(Held),
    /// Refuse now: `-L` resets, `-D` answers `REP 0x01`.
    Refused,
}

/// The reading half of an accept-hold: how long to keep a connection, how
/// many at once, when the supervisor's next attempt starts, and the queue
/// that keeps dispatch in accept order.
#[derive(Clone)]
pub(crate) struct HoldGate {
    window: Duration,
    slots: Arc<Semaphore>,
    next_attempt: watch::Receiver<Option<Instant>>,
    turns: Arc<Turns>,
}

impl HoldGate {
    /// How many connections are being kept right now.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        HELD_MAX - self.slots.available_permits()
    }
}

/// The supervisor's half: it tells the gate when an attempt is under way,
/// when the next one starts, and that none is pending.
pub(crate) struct HoldSignal(watch::Sender<Option<Instant>>);

impl HoldSignal {
    /// An attempt is running or about to (a start in the past counts).
    pub(crate) fn attempting(&self) {
        let _ = self.0.send(Some(Instant::now()));
    }

    /// The next attempt starts `delay` from now.
    pub(crate) fn next_in(&self, delay: Duration) {
        let _ = self.0.send(Some(Instant::now() + delay));
    }

    /// No attempt is pending.
    pub(crate) fn idle(&self) {
        let _ = self.0.send(None);
    }
}

/// A gate holding at most [`HELD_MAX`] connections for `window` each, and
/// the supervisor's end of it.
pub(crate) fn hold_gate(window: Duration) -> (HoldGate, HoldSignal) {
    let (tx, rx) = watch::channel(None);
    (
        HoldGate {
            window,
            slots: Arc::new(Semaphore::new(HELD_MAX)),
            next_attempt: rx,
            turns: Arc::new(Turns::default()),
        },
        HoldSignal(tx),
    )
}

/// One connection kept while the tunnel is disconnected. Its slot is
/// released when it is consumed by [`Held::wait`].
pub(crate) struct Held {
    deadline: Instant,
    _permit: OwnedSemaphorePermit,
    ticket: Ticket,
}

impl Held {
    /// Wait for a live carrier and for this connection's turn. Returns the
    /// carrier and a [`Ticket`] the caller drops once the connection's
    /// stream is open, which is what lets the next one go: the requests
    /// reach the peer in the order the connections were taken. `None` when
    /// the window ends first, or the supervisor is gone: refuse it. Nothing
    /// has been sent for it by then.
    pub(crate) async fn wait(self, view: &CarrierView) -> Option<(Arc<ForwardCarrier>, Ticket)> {
        let Self {
            deadline, ticket, ..
        } = self;
        let mut rx = view.rx.clone();
        let timeout = tokio::time::sleep_until(deadline);
        tokio::pin!(timeout);
        loop {
            let live = matches!(&*rx.borrow_and_update(), CarrierState::Live(_));
            if live {
                tokio::select! {
                    biased;
                    () = ticket.turn() => {}
                    () = &mut timeout => return None,
                }
                // Read after the turn: the carrier may have changed while
                // an earlier connection was going first.
                if let Some(carrier) = view.current() {
                    return Some((carrier, ticket));
                }
                continue;
            }
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
                () = &mut timeout => return None,
            }
        }
    }
}

/// The queue of held connections, in the order they were taken.
#[derive(Default)]
struct Turns {
    state: Mutex<TurnState>,
    changed: Notify,
}

#[derive(Default)]
struct TurnState {
    next: u64,
    queue: VecDeque<u64>,
}

impl Turns {
    fn lock(&self) -> std::sync::MutexGuard<'_, TurnState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn enter(self: &Arc<Self>) -> Ticket {
        let mut state = self.lock();
        let id = state.next;
        state.next += 1;
        state.queue.push_back(id);
        Ticket {
            turns: Arc::clone(self),
            id,
        }
    }
}

/// A place in the hold queue. Dropping it, whether the connection was
/// dispatched, refused or cancelled, lets the next one go.
pub(crate) struct Ticket {
    turns: Arc<Turns>,
    id: u64,
}

impl Ticket {
    /// Resolves once every connection taken before this one is done.
    /// Cancel-safe.
    async fn turn(&self) {
        loop {
            let notified = self.turns.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.turns.lock().queue.front() == Some(&self.id) {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.turns.lock().queue.retain(|id| *id != self.id);
        self.turns.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
