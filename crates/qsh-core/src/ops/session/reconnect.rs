//! The redial path of a recovery: [`DialReconnect`].

use super::*;

/// The [`Reconnect`] of an attach: re-dial the peer directly.
///
/// Owns exactly what the forward route's reconnect step needs — the
/// [`Link`] to redial on and, through `ctx.target`, the [`PeerTarget`] to
/// dial — plus the one piece of state that has to survive a cancelled
/// attempt: a redemption [`spawn_reattach`] started that a timed-out
/// caller walked away from. That adoption logic used to live inline in
/// [`recover_attach`]'s loop as a bare `&mut Option<ReattachTask>`; it is
/// moved here verbatim, not rewritten, so the behaviour — a second
/// attempt finds and awaits the *same* in-flight task rather than starting
/// a second redemption of the same single-use resume token
/// (`spawn_reattach`'s own doc) — is unchanged.
pub(super) struct DialReconnect {
    ctx: Arc<AttachContext>,
    link: Link,
    pending: Arc<std::sync::Mutex<PendingInput>>,
    /// The in-flight redemption, if a previous attempt's deadline stopped
    /// waiting on it without stopping it. A `tokio::sync::Mutex` because
    /// [`Reconnect::reconnect`] has to hold the guard across the `.await`
    /// on the task handle: that is what lets the *outer* `recover()`
    /// timeout cancel this future while leaving the handle in the slot for
    /// the next attempt to pick back up, exactly as the bare `&mut`
    /// binding it replaces did.
    in_flight: tokio::sync::Mutex<Option<ReattachTask>>,
}

impl DialReconnect {
    pub(super) fn new(
        ctx: Arc<AttachContext>,
        link: Link,
        pending: Arc<std::sync::Mutex<PendingInput>>,
    ) -> Self {
        Self {
            ctx,
            link,
            pending,
            in_flight: tokio::sync::Mutex::new(None),
        }
    }
}

impl Reconnect for DialReconnect {
    /// [`REDIAL_DEADLINE`], or, for a host that can be punched to, the punch
    /// budget behind the direct dial's head start (ADR-0054 decision 18).
    /// A redial that outlives the deadline keeps running on its task and the
    /// next attempt adopts it (`Self::in_flight`), so the figure bounds the
    /// wait, not the dial.
    fn attempt_deadline(&self) -> Duration {
        self.ctx.target.redial_deadline()
    }

    fn has_pending(&self) -> bool {
        // Never contended at the point `recover_attach` calls this: it
        // asks at the top of a loop iteration, after any previous
        // `reconnect()` future has either run to completion (which clears
        // the slot below) or been dropped by the outer deadline (which
        // drops this guard along with it). A `try_lock` failure here would
        // itself be the bug, not a legitimate "still pending" answer.
        self.in_flight
            .try_lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn reconnect(&self, last_output_seq: u64) -> ReconnectFuture<'_> {
        Box::pin(async move {
            let mut in_flight = self.in_flight.lock().await;
            let handle = in_flight.get_or_insert_with(|| {
                spawn_reattach(
                    self.ctx.clone(),
                    self.link.clone(),
                    self.pending.clone(),
                    last_output_seq,
                )
            });
            let joined = handle.await;
            // Reached only when the redemption finished, so a
            // cancellation above (the recovery deadline firing while this
            // `.await` was pending) leaves the handle in the slot for the
            // next attempt to adopt.
            *in_flight = None;
            match joined {
                Ok(result) => result,
                Err(err) => Err(ResumeError::Local(OpError::new(
                    ErrorCode::Internal,
                    format!("the resume task did not finish: {err}"),
                ))),
            }
        })
    }
}
