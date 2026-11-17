//! [`Connected`], the dialed and negotiated peer connection the value ops and stream ops share.

use super::*;

/// A dialed, negotiated peer connection held open across calls, with its
/// own runtime — the backbone of both the value ops (one call, then
/// [`close`](Connected::close)) and the streaming ops (many calls).
///
/// `pub(crate)` only so the sibling `crate::ops::tunnel` module can hold
/// one for a foreground tunnel (M4 plan Step 3 (8237375)); nothing outside
/// `crate::ops` can name it.
pub(crate) struct Connected {
    /// `None` only between [`Connected::close`] and the drop. Shared with
    /// every other in-flight `Connected` on this `Ops` (the M7 plan (004ebd2) Step
    /// 7-2 ①, [`crate::ops::SharedRuntime`]'s own doc) — never the sole
    /// owner, so nothing on this type may shut it down; the wrapper (not a
    /// bare `Runtime`) is also what makes it safe for this field to be
    /// dropped from any context, including from inside another async
    /// runtime (as `qsh-testkit`'s fixtures do).
    pub(super) runtime: Option<Arc<crate::ops::SharedRuntime>>,
    /// The endpoint and connection currently carrying this attach — a
    /// swappable pair (recovery-capable — see [`Link`]'s own doc).
    pub(super) link: Link,
    /// `None` only after the session was consumed by the teardown.
    pub(super) session: Option<Session>,
}

/// The endpoint/connection pair an attach is riding right now.
///
/// A recovery builds a new QUIC connection on a new endpoint, but every
/// [`AttachHandle`] a frontend already took — and the teardown path — must
/// keep reaching the live one. So the pair lives behind one shared cell
/// that the recovery swaps, rather than being copied out at construction.
#[derive(Clone, Debug)]
pub(crate) struct Link {
    inner: Arc<std::sync::Mutex<(qsh_transport::Endpoint, qsh_transport::Connection)>>,
}

impl Link {
    pub(super) fn new(
        endpoint: qsh_transport::Endpoint,
        connection: qsh_transport::Connection,
    ) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new((endpoint, connection))),
        }
    }

    fn get(&self) -> (qsh_transport::Endpoint, qsh_transport::Connection) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn connection(&self) -> qsh_transport::Connection {
        self.get().1
    }

    pub(crate) fn endpoint(&self) -> qsh_transport::Endpoint {
        self.get().0
    }

    /// Install a new pair, returning the one it replaced so the caller can
    /// tear it down.
    pub(crate) fn replace(
        &self,
        endpoint: qsh_transport::Endpoint,
        connection: qsh_transport::Connection,
    ) -> (qsh_transport::Endpoint, qsh_transport::Connection) {
        let mut slot = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = std::mem::replace(&mut *slot, (endpoint, connection));
        // The chain under a jumped connection is rebuilt, never revived
        // (ADR-0056 decision 16): closing the old end connection is what
        // ends its layers, so no inner connection outlives the rebuild.
        if old.0.is_nested() {
            old.1.close(0, b"jump chain rebuilt");
        }
        old
    }
}

impl Connected {
    /// Build a forward-route `Connected` directly from an already-dialed
    /// endpoint/connection/session, with no wire handshake of its own —
    /// the test seam [`crate::ops::tunnel`]'s capability-gate tests need,
    /// since `Session::from_control` performs no I/O (just stores fields),
    /// so a fabricated [`Session`] (e.g. one built from a hand-written
    /// [`qsh_proto::wire::Hello`] whose `capabilities` omits
    /// `dial-filter.v1`) is enough to exercise
    /// `Ops::tunnel_dynamic_with_connected`'s capability check without a
    /// real peer answering a `Hello`.
    #[cfg(test)]
    pub(crate) fn for_test_forward(
        runtime: Arc<crate::ops::SharedRuntime>,
        endpoint: qsh_transport::Endpoint,
        connection: qsh_transport::Connection,
        session: Session,
    ) -> Self {
        Self {
            runtime: Some(runtime),
            link: Link::new(endpoint, connection),
            session: Some(session),
        }
    }

    /// Run one request closure on the live session.
    ///
    /// `pub(crate)`, not private: `crate::ops::tunnel`'s `-R` requester leg
    /// (M4 plan Step 4 (8237375)) needs the same one-request-closure shape
    /// `session_open`/`attach_request`/etc. already use here, for
    /// `Session::rfwd_open`/`rfwd_close` — a sibling `ops` module, not a
    /// descendant of this one, so plain module-private is not enough.
    pub(crate) fn run<T, F>(&mut self, f: F) -> Result<T, OpError>
    where
        F: for<'a> FnOnce(
            &'a mut Session,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, ClientError>> + Send + 'a>,
        >,
    {
        let (Some(runtime), Some(session)) = (self.runtime.as_ref(), self.session.as_mut()) else {
            return Err(OpError::new(
                ErrorCode::Internal,
                "connection already closed",
            ));
        };
        runtime.block_on(f(session)).map_err(map_client_error)
    }

    /// The runtime this connection lives on, for callers that drive their
    /// own tasks on it (the attach driver, and a `-L` forward's accept
    /// loop).
    pub(crate) fn runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime
            .as_deref()
            .expect("runtime is only taken by close()")
    }

    /// Take the negotiated session out, leaving the connection and runtime
    /// in place (the attach driver owns the session for its lifetime).
    pub(crate) fn take_session(&mut self) -> Option<Session> {
        self.session.take()
    }

    /// The swappable endpoint/connection pair, shared with this
    /// `Connected`: a supervisor that replaces the pair ([`Link::replace`])
    /// keeps [`Self::close`] and [`Self::wait_dead_with_cause`] pointed at
    /// the live one.
    pub(crate) fn forward_link(&self) -> Link {
        self.link.clone()
    }

    /// `sha256:…` fingerprint of the peer this connection verified — the
    /// identity a resume credential is bound to (protocol.md §10-2). Not
    /// an authorization input: the host authorizes on the mTLS principal.
    /// Read straight off this connection's own TLS-verified peer.
    pub(crate) fn peer_fingerprint(&self) -> Option<String> {
        self.link
            .connection()
            .peer_fingerprint()
            .map(|fp| fp.to_string())
    }

    /// The QUIC connection underneath.
    pub(crate) fn connection(&self) -> qsh_transport::Connection {
        self.link.connection()
    }

    /// The capabilities negotiated with the peer at handshake time
    /// (`crate::handshake::negotiated_capabilities`) — e.g.
    /// [`qsh_proto::wire::CAP_DIAL_FILTER_V1`], which
    /// [`crate::ops::tunnel::Ops::tunnel_dynamic`] requires before binding
    /// anything (ADR-0019 decision 3). Empty if the session was already
    /// taken out from under this `Connected` (there is no live negotiation
    /// left to read), which a caller here only ever sees on a
    /// structurally-already-closed connection.
    pub(crate) fn capabilities(&self) -> &[String] {
        self.session
            .as_ref()
            .map(|s| s.capabilities.as_slice())
            .unwrap_or(&[])
    }

    /// Wait until this connection ends, and say why — the one signal
    /// [`crate::ops::tunnel::TunnelHold::hold`] blocks on for as long as
    /// the tunnel it holds is alive (`docs/CLI.md` §6.14).
    ///
    /// [`qsh_transport::Connection::closed`], the QUIC connection's own
    /// close future. Returns the error plus the `cause` word for the close
    /// (`qsh::lifecycle`).
    pub(crate) async fn wait_dead_with_cause(&mut self) -> (OpError, Option<&'static str>) {
        let err = self.link.connection().closed().await;
        let cause = crate::reconnect::classify_connection_error(&err).as_str();
        (
            OpError::new(
                ErrorCode::ConnectionFailed,
                format!("the connection carrying this tunnel closed: {err}"),
            ),
            Some(cause),
        )
    }

    /// Give the peer a bounded chance to acknowledge something before the
    /// connection is closed.
    ///
    /// quinn-proto will not put a `CONNECTION_CLOSE` on the wire while the
    /// congestion window is full of unacknowledged data and stream frames
    /// are still queued, which is exactly the state of a transfer canceled
    /// mid-flight. Closing at once then only starts the closing timer: the
    /// connection drains a few hundred milliseconds later without the peer
    /// ever hearing of it, and its half of the transfer (a host's temp
    /// file) lives until the idle timeout. An authenticated frame from the
    /// peer is an acknowledgment that frees window, so the close frame goes
    /// out right after. `grace` caps the wait for a peer that is gone.
    pub(crate) fn settle_before_close(&self, grace: Duration) {
        let Some(runtime) = self.runtime.as_ref() else {
            return;
        };
        let connection = self.link.connection();
        runtime.block_on(async move {
            let seen = connection.rx_frames();
            let deadline = tokio::time::Instant::now() + grace;
            while connection.rx_frames() == seen && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
    }

    /// Close the control stream and the connection, then let the QUIC close
    /// frames drain.
    ///
    /// The runtime is shared (M7 plan Step 7-2 (004ebd2) ①), so this only drops
    /// this `Connected`'s own `Arc` handle to it — and only after
    /// `block_on` above has already run `connection.close()` and
    /// `endpoint.wait_idle()` to completion. If this handle happens to be
    /// the last `Arc`, `SharedRuntime::drop` (`ops/mod.rs`) does call
    /// `shutdown_background()`, but only once this function's own use of
    /// the runtime is done. This also means the `shutdown_timeout
    /// (CLOSE_DRAIN)` every close used to pay — up to 200ms per call,
    /// waiting out a runtime this process was about to throw away anyway
    /// — no longer happens.
    pub(crate) fn close(mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let session = self.session.take();
        let (endpoint, connection) = self.link.get();
        runtime.block_on(async move {
            if let Some(session) = session {
                session.close();
            }
            connection.close(0, b"done");
            drop(connection);
            endpoint.wait_idle().await;
        });
    }
}

impl Drop for Connected {
    fn drop(&mut self) {
        // `close()` already took the runtime on the normal path; this is the
        // panic / early-return path. Shared runtime (as in `close()`
        // above): dropping the `Arc` here releases only this `Connected`'s
        // own handle — if it happens to be the last one, `SharedRuntime::
        // drop` (`ops/mod.rs`) does shut the runtime down, via
        // `shutdown_background()`. `if EXPR.take().is_some() { BODY }` is
        // not `if let`: the condition expression's temporary is dropped
        // *before* `BODY` runs, not after, so the `Arc` must be bound by
        // name and held past `connection.close()` below — otherwise, on
        // the last-`Arc` path, the runtime's endpoint driver task could be
        // torn down before the CONNECTION_CLOSE frame requested here even
        // leaves.
        let taken = self.runtime.take();
        if taken.is_some() {
            self.session.take();
            self.link.connection().close(0, b"done");
            // Only release this `Connected`'s handle after the close
            // request above has gone out. If this was the last `Arc`,
            // `shutdown_background()` runs here.
            drop(taken);
        }
    }
}
