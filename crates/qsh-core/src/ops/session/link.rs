//! [`Connected`], the dialed and negotiated peer connection the value ops and stream ops share.

use super::*;

/// A dialed, negotiated peer connection held open across calls, with its
/// own runtime — the backbone of both the value ops (one call, then
/// [`close`](Connected::close)) and the streaming ops (many calls).
///
/// `pub(crate)` only so the sibling `crate::ops::tunnel` module can hold
/// one for a foreground tunnel (`PLAN.md` M4 Step 3); nothing outside
/// `crate::ops` can name it.
pub(crate) struct Connected {
    /// `None` only between [`Connected::close`] and the drop. Shared with
    /// every other in-flight `Connected` on this `Ops` (`PLAN.md` M7 Step
    /// 7-2 ①, [`crate::ops::SharedRuntime`]'s own doc) — never the sole
    /// owner, so nothing on this type may shut it down; the wrapper (not a
    /// bare `Runtime`) is also what makes it safe for this field to be
    /// dropped from any context, including from inside another async
    /// runtime (as `qsh-testkit`'s fixtures do).
    pub(super) runtime: Option<Arc<crate::ops::SharedRuntime>>,
    /// The endpoint and connection currently carrying this attach — the
    /// forward route's swappable pair — or, on the reverse route, the
    /// facts a `LOCAL_CONTROL` handshake produced instead of one
    /// (`PLAN.md` M3 Step 6).
    pub(super) link: ConnectedLink,
    /// `None` only after the session was consumed by the teardown.
    pub(super) session: Option<Session>,
}

/// Which of [`PeerRoute`](crate::ops::PeerRoute)'s two carriers this
/// [`Connected`] rides.
pub(super) enum ConnectedLink {
    /// The forward route: a real, swappable QUIC endpoint/connection pair
    /// (recovery-capable — see [`Link`]'s own doc).
    Forward(Link),
    /// The reverse route: relayed through this machine's `qsh listen`
    /// daemon over a `LOCAL_CONTROL` conduit. There is no separate
    /// endpoint/connection for this leg to hold — [`Connected::close`]'s
    /// `session.close()` alone tears the conduit down — so this variant
    /// carries only what [`Connected::peer_fingerprint`] needs: the
    /// `LocalHelloAck.peer_fingerprint` this connection's own handshake
    /// reported (`None` only if the daemon's ack omitted it, which never
    /// happens on a live registration but is not this type's job to
    /// assume).
    // Only ever constructed by `connect_reverse`'s `#[cfg(unix)]` body
    // (localctl/UDS is unix-only) in the non-test lib build — the
    // Windows twin returns `Err` before ever reaching a `Connected`, so
    // this variant is genuinely unconstructed there outside `#[cfg(test)]`
    // (where a unit test builds it directly to pin
    // `Connected::peer_fingerprint`'s reverse-leg behavior).
    #[cfg_attr(not(unix), allow(dead_code))]
    Reverse {
        peer_fingerprint: Option<String>,
        /// This machine's resident `qsh listen` daemon's localctl socket
        /// and the registered host alias this leg is for — exactly
        /// [`LocalRoute`]'s two fields, carried forward from
        /// [`Ops::connect_reverse`] rather than re-resolved, because
        /// re-resolving could name a *different* daemon/registration than
        /// the one this specific `Connected`'s `LOCAL_CONTROL` conduit is
        /// actually talking to. [`Connected::reverse_route`] is the only
        /// reader — `crate::ops::tunnel`'s route-aware `tunnel_open`
        /// (`PLAN.md` M4 Step 5 PR 5b), which needs both to open the
        /// per-connection `LOCAL_STREAM` conduits
        /// `crate::tunnel::LocalForwardHandle::start_reverse` and
        /// `crate::tunnel::remote::RemoteForwardAcceptor::spawn_reverse`
        /// take.
        socket: std::path::PathBuf,
        host: String,
    },
}

/// The endpoint/connection pair an attach is riding right now.
///
/// A recovery builds a new QUIC connection on a new endpoint, but every
/// [`AttachHandle`] a frontend already took — and the teardown path — must
/// keep reaching the live one. So the pair lives behind one shared cell
/// that the recovery swaps, rather than being copied out at construction.
#[derive(Clone, Debug)]
pub(super) struct Link {
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

    pub(super) fn connection(&self) -> qsh_transport::Connection {
        self.get().1
    }

    pub(super) fn endpoint(&self) -> qsh_transport::Endpoint {
        self.get().0
    }

    /// Install a new pair, returning the one it replaced so the caller can
    /// tear it down.
    pub(super) fn replace(
        &self,
        endpoint: qsh_transport::Endpoint,
        connection: qsh_transport::Connection,
    ) -> (qsh_transport::Endpoint, qsh_transport::Connection) {
        let mut slot = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut *slot, (endpoint, connection))
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
            link: ConnectedLink::Forward(Link::new(endpoint, connection)),
            session: Some(session),
        }
    }

    /// Run one request closure on the live session.
    ///
    /// `pub(crate)`, not private: `crate::ops::tunnel`'s `-R` requester leg
    /// (`PLAN.md` M4 Step 4) needs the same one-request-closure shape
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
    pub(super) fn take_session(&mut self) -> Option<Session> {
        self.session.take()
    }

    /// `sha256:…` fingerprint of the peer this connection verified — the
    /// identity a resume credential is bound to (protocol.md §10-2). Not
    /// an authorization input: the host authorizes on the mTLS principal.
    ///
    /// Forward: read straight off this connection's own TLS-verified peer.
    /// Reverse: the `LocalHelloAck.peer_fingerprint` this leg's own
    /// handshake reported — the daemon's TLS-verified peer for *this*
    /// registration, which is the ADR-0007 presentation-condition input on
    /// that leg since the CLI process is not itself a TLS endpoint on the
    /// underlying connection (`PLAN.md` M3 Step 6).
    pub(super) fn peer_fingerprint(&self) -> Option<String> {
        match &self.link {
            ConnectedLink::Forward(link) => link
                .connection()
                .peer_fingerprint()
                .map(|fp| fp.to_string()),
            ConnectedLink::Reverse {
                peer_fingerprint, ..
            } => peer_fingerprint.clone(),
        }
    }

    /// The QUIC connection underneath, on the forward route only.
    ///
    /// `None` on the reverse route, where this process is not a QUIC
    /// endpoint at all — its peer traffic is relayed by the resident `qsh
    /// listen` daemon over a `LOCAL_STREAM` conduit
    /// ([`ConnectedLink::Reverse`]). A caller that needs a raw byte pipe
    /// of its own (a tunnel splice) has to refuse there rather than
    /// improvise, which is what `PLAN.md` M4 Step 5 exists to fix.
    pub(crate) fn connection(&self) -> Option<qsh_transport::Connection> {
        match &self.link {
            ConnectedLink::Forward(link) => Some(link.connection()),
            ConnectedLink::Reverse { .. } => None,
        }
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

    /// The reverse-route carrier [`crate::ops::tunnel`]'s route-aware
    /// `tunnel_open` needs to open its own `LOCAL_STREAM` conduits
    /// (`PLAN.md` M4 Step 5 PR 5b) — this machine's resident `qsh listen`
    /// daemon socket and the registered host alias, i.e. exactly
    /// [`ConnectedLink::Reverse`]'s two extra fields. `None` on the
    /// forward route (the mirror image of [`Self::connection`] being
    /// `None` on the reverse route) — a caller branches on one or the
    /// other, never both.
    #[cfg(unix)]
    pub(crate) fn reverse_route(&self) -> Option<(&std::path::Path, &str)> {
        match &self.link {
            ConnectedLink::Forward(_) => None,
            ConnectedLink::Reverse { socket, host, .. } => Some((socket.as_path(), host.as_str())),
        }
    }

    /// Wait until this connection ends, and say why — the one signal
    /// [`crate::ops::tunnel::TunnelHold::hold`] blocks on for as long as
    /// the tunnel it holds is alive (`docs/CLI.md` §6.14).
    ///
    /// Forward route: [`qsh_transport::Connection::closed`], the QUIC
    /// connection's own close future. Reverse route: there is no such
    /// object on this side ([`Self::connection`]'s own doc), so this
    /// drives [`Session::next_control`] in a loop instead — `Ok(None)` is
    /// the daemon ending the `LOCAL_CONTROL` conduit, which is also how
    /// this side learns its reverse registration died
    /// (`crate::client::link::ControlLink::recv`'s own doc,
    /// `docs/design/protocol.md` §11-3), and any `Err` is the conduit
    /// itself failing. `next_control` performs no write (unlike
    /// [`Session::next_event`], which answers a peer `Ping` inline), so
    /// this is safe to run with nothing else touching the session — which
    /// is exactly `tunnel_open`'s reverse-route `Connected`, since it is
    /// never attached to any session and issues only the occasional
    /// `RfwdOpen`/`RfwdClose` request on it. A message that is not a
    /// clean end or an error (there should never legitimately be one on
    /// this bare value-op connection) is simply discarded and the loop
    /// keeps waiting — the same "nothing here to answer" posture every
    /// other bare value-op `Connected` already has, forward or reverse.
    pub(crate) async fn wait_dead(&mut self) -> OpError {
        match &self.link {
            ConnectedLink::Forward(link) => {
                let err = link.connection().closed().await;
                OpError::new(
                    ErrorCode::ConnectionFailed,
                    format!("the connection carrying this tunnel closed: {err}"),
                )
            }
            ConnectedLink::Reverse { .. } => {
                let Some(session) = self.session.as_mut() else {
                    return OpError::new(
                        ErrorCode::ConnectionFailed,
                        "the reverse connection carrying this tunnel is already closed",
                    );
                };
                loop {
                    match session.next_control().await {
                        Ok(None) => {
                            return OpError::new(
                                ErrorCode::ConnectionFailed,
                                "the reverse connection carrying this tunnel closed",
                            );
                        }
                        Ok(Some(_)) => continue,
                        Err(err) => {
                            return OpError::new(
                                ErrorCode::ConnectionFailed,
                                format!(
                                    "the reverse connection carrying this tunnel failed: {err}"
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    /// Close the control stream and the connection, then let the QUIC close
    /// frames drain (forward route) — or just the control stream (reverse
    /// route: there is no separate connection here to close, and no QUIC
    /// close frame of this process's own to drain).
    ///
    /// The runtime is shared (`PLAN.md` M7 Step 7-2 ①), so this only drops
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
        match &self.link {
            ConnectedLink::Forward(link) => {
                let (endpoint, connection) = link.get();
                runtime.block_on(async move {
                    if let Some(session) = session {
                        session.close();
                    }
                    connection.close(0, b"done");
                    drop(connection);
                    endpoint.wait_idle().await;
                });
            }
            ConnectedLink::Reverse { .. } => {
                runtime.block_on(async move {
                    if let Some(session) = session {
                        session.close();
                    }
                });
            }
        }
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
            if let ConnectedLink::Forward(link) = &self.link {
                link.connection().close(0, b"done");
            }
            // Only release this `Connected`'s handle after the close
            // request above has gone out. If this was the last `Arc`,
            // `shutdown_background()` runs here.
            drop(taken);
        }
    }
}
