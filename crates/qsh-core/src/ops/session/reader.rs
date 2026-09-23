//! Dialing a resolved peer and the cursor-pull reader behind [`Ops::session_reader`].

use super::*;

/// Dial a resolved peer and exchange `Hello`. The async half of
/// [`Ops::connect`], split out because a recovery re-dials from inside a
/// runtime that already exists.
pub(super) async fn dial_peer(
    target: &PeerTarget,
) -> Result<(qsh_transport::Endpoint, qsh_transport::Connection, Session), OpError> {
    let device_name = target.identity.identity.device_id.clone();
    let dialer = Dialer::new(
        target.identity.local.clone(),
        target.trust.clone() as Arc<dyn qsh_transport::TrustEvaluator>,
    );
    let address = target.address.clone();
    let addrs = crate::ops::resolve_all(&address).await?;
    let dialed =
        crate::ops::dial_first_reachable(&addrs, |addr| dialer.dial(addr, &target.server_name))
            .await
            .map_err(|(err, attempted)| map_dial_error(err, &address, attempted))?;
    let endpoint = dialed.endpoint.clone();
    let connection = dialed.connection.clone();
    match Session::negotiate(dialed.connection, &device_name).await {
        Ok(session) => Ok((endpoint, connection, session)),
        Err(err) => {
            connection.close(0, b"done");
            endpoint.wait_idle().await;
            Err(map_client_error(err))
        }
    }
}

/// Open a `LOCAL_CONTROL` conduit to `route`'s daemon and build a
/// [`Session`] over it — the async half of [`Ops::connect_reverse`], split
/// out the same way [`dial_peer`] is. `wait_ms: 0`, `known_generation:
/// None`: [`Ops::resolve_route`] already observed a *live* registration
/// before this is ever called (`crate::localctl::client::open_control`'s
/// own doc), so there is nothing to wait for and no prior generation to
/// gate on here — [`dial_reverse_wait`] is the Step 8 sibling that does
/// both.
///
/// Returns the ack's `peer_fingerprint` and `generation` alongside the
/// session — [`Connected::peer_fingerprint`] on the reverse leg is exactly
/// this `peer_fingerprint` value (`docs/adr/`'s ADR-0007 presentation
/// condition, `PLAN.md` M3 Step 6), never re-derived from a QUIC
/// connection this process does not itself hold; `generation` seeds
/// [`AttachContext`]'s reverse-route baseline that Step 8's
/// `LocalReconnect` waits past.
#[cfg(unix)]
pub(super) async fn dial_reverse(
    route: &LocalRoute,
) -> Result<(Session, Option<String>, u64), OpError> {
    dial_reverse_wait(route, 0, None).await
}

/// [`dial_reverse`], generalized with the two inputs Step 8's
/// `LocalReconnect` needs on top of a first attach's `wait_ms: 0,
/// known_generation: None`: how long to wait for a *live* registration
/// (`LOCAL_WAIT_MAX`-clamped by the daemon, `crate::localctl::client::open_control`'s
/// own doc) and which generation it must be strictly newer than
/// (`qsh/local/v1.proto`'s `LocalHello.known_generation` doc). Opens both
/// the `LOCAL_CONTROL` conduit this returns *and* nothing else — the data
/// conduit is a separate `open_stream` call the caller makes once it has
/// something to attach.
#[cfg(unix)]
pub(super) async fn dial_reverse_wait(
    route: &LocalRoute,
    wait_ms: u32,
    known_generation: Option<u64>,
) -> Result<(Session, Option<String>, u64), OpError> {
    let handshake = crate::localctl::client::open_control(
        &route.socket,
        &route.host,
        wait_ms,
        known_generation,
    )
    .await?;
    let peer_fingerprint = Some(handshake.peer_fingerprint.clone());
    let generation = handshake.generation;
    let session = Session::from_local_control(
        handshake.conduit,
        handshake.capabilities,
        handshake.host,
        route.socket.clone(),
        handshake.peer_fingerprint,
        handshake.generation,
    );
    Ok((session, peer_fingerprint, generation))
}

/// A live cursor on one session's replay ring — the single pull primitive
/// behind `session read --wait`, `session read --follow` and a long-running
/// external process's (e.g. an agent tool) long-poll. See
/// [`Ops::session_reader`].
pub struct SessionReader {
    pub(super) conn: Connected,
    /// Where this session's resume credential lives, so a `session.closed`
    /// seen while reading takes the dead entry with it (CLI.md §6.4).
    pub(super) store: ResumeStore,
    pub(super) session_ref: String,
    pub(super) session_id: String,
    pub(super) after: u64,
    pub(super) ctl_after: u64,
    pub(super) wait_ms: u64,
    pub(super) max_bytes: u64,
    pub(super) done: bool,
}

impl SessionReader {
    /// The session being read.
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }

    /// The cursor the next pull will use, as `(after, ctl_after)`.
    pub fn cursor(&self) -> (u64, u64) {
        (self.after, self.ctl_after)
    }

    /// Whether a terminal event (`session.exit`, `session.closed`) has been
    /// delivered — a follower stops here instead of polling a dead session.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// One pull. Advances the cursor by the reply's
    /// `next_after`/`next_ctl_after`, so consecutive pulls neither skip nor
    /// repeat.
    pub fn pull(&mut self) -> Result<SessionReadOutput, OpError> {
        let msg = wire::SessionRead {
            session_id: self.session_id.clone(),
            after: self.after,
            max_bytes: self.max_bytes,
            wait_ms: self.wait_ms,
            ctl_after: self.ctl_after,
        };
        let result = self.conn.run(move |s| Box::pin(s.session_read(msg)))?;
        self.after = result.next_after;
        self.ctl_after = result.next_ctl_after;
        let mut output = Vec::new();
        let mut json_events = Vec::with_capacity(result.events.len());
        for event in result.events {
            if let Some(session_read_event::Body::Output(o)) = &event.body {
                output.extend_from_slice(&o.data);
            }
            if let Some(json) = event_json(&self.session_ref, event) {
                self.done |= is_terminal(&json);
                forget_if_closed(&self.store, &self.session_ref, &json);
                json_events.push(json);
            }
        }
        Ok(SessionReadOutput {
            data: SessionReadData {
                session_ref: self.session_ref.clone(),
                events: json_events,
                next_after: self.after,
                next_ctl_after: self.ctl_after,
            },
            output,
        })
    }

    /// Close the connection this reader holds.
    pub fn close(self) {
        self.conn.close();
    }
}

/// Drop the stored resume credential once the host says the session is
/// gone (`docs/CLI.md` §6.4).
///
/// Only `session.closed` — not `session.exit`. An exited session is still
/// in the broker until the reaper takes it, and its output is still
/// attachable; a session that has been *removed* can only answer an attach
/// with the non-distinguishing `AUTH_FAILED`, and keeping the credential
/// around would turn "this session is over" into that opaque refusal.
pub(super) fn forget_if_closed(store: &ResumeStore, session_ref: &str, event: &SessionEvent) {
    if matches!(event, SessionEvent::Closed { .. }) {
        let _ = store.forget(session_ref);
    }
}

/// Whether an event ends the stream: nothing follows an exit or a close.
fn is_terminal(event: &SessionEvent) -> bool {
    matches!(
        event,
        SessionEvent::Exit { .. } | SessionEvent::Closed { .. }
    )
}
