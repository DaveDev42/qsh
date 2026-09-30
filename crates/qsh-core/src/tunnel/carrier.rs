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

use std::sync::Arc;

use tokio::sync::watch;

use crate::tunnel::local::ForwardCarrier;

/// What a forward can open tunnel streams on right now.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum CarrierState {
    /// A carrier that is believed alive.
    Live(Arc<ForwardCarrier>),
    /// The carrier was declared lost and no replacement is up yet.
    Disconnected,
}

/// Called once per accepted connection so a supervisor can tell that the
/// forward is in use (ADR-0023 decision 4's `observe_activity`).
pub(crate) type ActivityHook = Arc<dyn Fn() + Send + Sync>;

/// A cheap, cloneable reader of the current [`CarrierState`].
#[derive(Clone)]
pub(crate) struct CarrierView {
    rx: watch::Receiver<CarrierState>,
    activity: Option<ActivityHook>,
}

impl CarrierView {
    /// A view whose value is `carrier` for as long as anything reads it.
    /// The sender is dropped at once, which `watch` allows: the last value
    /// stays readable.
    pub(crate) fn fixed(carrier: Arc<ForwardCarrier>) -> Self {
        let (_tx, rx) = watch::channel(CarrierState::Live(carrier));
        Self { rx, activity: None }
    }

    /// A view over a channel a supervisor writes to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn watching(
        rx: watch::Receiver<CarrierState>,
        activity: Option<ActivityHook>,
    ) -> Self {
        Self { rx, activity }
    }

    /// The carrier to open a stream on now, or `None` while disconnected.
    pub(crate) fn current(&self) -> Option<Arc<ForwardCarrier>> {
        match &*self.rx.borrow() {
            CarrierState::Live(carrier) => Some(Arc::clone(carrier)),
            CarrierState::Disconnected => None,
        }
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
