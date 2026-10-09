//! The `Hello` handshake, shared by both connection roles.
//!
//! Connection direction (who dialed) and QSH role (host vs. client) are
//! separate axes (`docs/ROADMAP.md` principle 7c, `docs/design/protocol.md`
//! §7: "Control | dialer opens first bidi"). [`initiate`] is what the
//! *dialer* runs on a fresh connection; [`respond`] is what the *acceptor*
//! runs. Today that always pairs initiate+client with respond+host (`qsh
//! <host>`); M3's `qsh reverse` pairs initiate+host with respond+client
//! instead, and this module is what makes that pairing free — the
//! `HELLO_TIMEOUT`, minor-version-intersection and capability-intersection
//! rules live here exactly once, independent of role.
//!
//! Version-mismatch handling is deliberately asymmetric
//! (`docs/design/protocol.md` §11 header — the symmetric principle is
//! *who evaluates their own ACL*, not error-frame etiquette): the
//! responder always catches it first and answers with an `UNSUPPORTED`
//! error frame before ending the connection without its own `Hello`
//! ([`respond`]); the initiator's own check in [`initiate`] never sends a
//! frame — it is a local fail-safe against a peer that does not hold up
//! its end of that convention, not the primary signalling path.

use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, ControlMessage, Hello, control_message, response};
use qsh_transport::{Connection, FramedSend, FramedStream, StreamError};
use thiserror::Error;

/// How long a peer has to complete its half of the `Hello` exchange:
/// for the responder, opening the control stream *and* sending `Hello`;
/// for the initiator, only the wait for the reply. Single definition —
/// both roles used to keep their own copy of this constant (no change in
/// value; `docs/design/protocol.md` does not itself specify this timeout,
/// so no section is cited here).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the wait, after writing a rejection error frame, for the peer to
/// actually receive it before [`respond`] returns and its caller tears the
/// connection down (`docs/history/m3-plan.md` Step 3, "거부 error frame의 전달 보장").
///
/// `serve_connection`-style callers used to call `conn.close()` immediately
/// after `respond()` returned `Err`, which could beat the just-written frame
/// off the wire — a peer would see `ApplicationClosed` instead of
/// `UNSUPPORTED`/`INVALID_ARGUMENT`/`PERMISSION_DENIED` (a pre-existing race
/// a raw-QUIC probe proved in Step 2's review, not introduced by it). Short
/// and finite: a hostile peer that never acks the frame must not be able to
/// hold a responder open indefinitely by simply not reading.
pub const REJECTION_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Errors from the shared `Hello` exchange. Neither [`initiate`] nor
/// [`respond`] surfaces this type to callers directly for logs/JSON —
/// `server::serve_connection` and `client::Session::negotiate` each map it
/// onto their own pre-existing error type (`ConnError`, `ClientError`) so
/// the observable message is byte-identical to before this type existed
/// (docs/history/m3-plan.md Step 2 (d)).
#[derive(Debug, Error)]
pub enum HelloError {
    /// The peer's `Hello`, or the reply to ours, did not arrive within
    /// [`HELLO_TIMEOUT`].
    #[error("Hello handshake timed out")]
    Timeout,
    /// The peer closed the control stream before sending `Hello`.
    #[error("peer closed control stream before Hello")]
    ClosedBeforeHello,
    /// The first control message we read was not `Hello`.
    #[error("first control message was not Hello")]
    ExpectedHello,
    /// The two `Hello`s share no wire minor version.
    #[error("no common wire minor version")]
    VersionMismatch,
    /// The peer answered with a wire `Error` instead of `Hello`. Only
    /// reachable by [`initiate`] — a [`respond`]er never parses a reply to
    /// its own `Hello` during this exchange, it only ever reads the peer's
    /// first message.
    #[error("{code}: {message}")]
    Remote {
        /// Peer-reported code.
        code: ErrorCode,
        /// Peer-reported message.
        message: String,
        /// Peer-reported retryability.
        retryable: bool,
    },
    /// [`respond`]'s `make_local_hello` callback declined the peer's
    /// `Hello`; the returned error was already sent as an error frame, and
    /// no reply `Hello` follows. Only reachable by [`respond`] — this step
    /// (M3 Step 2) never returns `Err` from that callback (the version
    /// check above is the only rejection this step performs, and it does
    /// not go through the callback); Step 3 wires a real rejection reason
    /// into it.
    #[error("{}: {}", .0.error_code(), .0.message)]
    Rejected(wire::Error),
    /// The peer's first control message was a `PairingProof` — but this
    /// connection never routed through `Principal::Pairing`/
    /// `serve_pairing_connection` at all, because `qsh-transport::tls::
    /// verify_core`'s pin/CA paths take priority over the pairing fallback
    /// (`docs/design/protocol.md` §15.1): a peer this host already
    /// recognizes (pinned, or CA-signed) never reaches
    /// `TrustEvaluator::pairing_open`, invite or no invite. Report F-2: the
    /// old behavior here was a silent `ExpectedHello` return with no error
    /// frame at all, which the initiator (`crate::pairing::accept`) could
    /// only observe as a bare `ConnectionLost` — `CONNECTION_FAILED` +
    /// `retryable: true`, an unrecoverable retry loop (no amount of
    /// retrying, or even a fresh invite, changes this host's pin state). An
    /// explicit, non-retryable `SESSION_CONFLICT`-coded error frame is
    /// written and drained instead (like [`Self::Rejected`]), so
    /// `crate::pairing::accept` surfaces a clean, actionable error. Only
    /// the host clearing the existing pin (`qsh trust remove`) resolves
    /// this — never retryable.
    #[error("{}: {}", .0.error_code(), .0.message)]
    AlreadyPaired(wire::Error),
    /// The control stream itself failed (read/write/frame/codec).
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// Opening or accepting the control stream failed at the connection
    /// level.
    #[error(transparent)]
    Connection(#[from] qsh_transport::ConnectionError),
}

/// Capabilities both sides support: our full advertised list
/// ([`wire::LOCAL_CAPABILITIES`]) narrowed to what the peer's `Hello` also
/// lists (`docs/design/protocol.md` §4: "major 내 확장은 `Hello.versions`
/// … + `Hello.capabilities` … 로 협상한다"). `initiate` and `respond` both
/// advertise their *full* list in their own `Hello` — this intersection is
/// what a caller actually gates behavior on (`ConnCtx::capabilities`,
/// `client::Session::capabilities`), computed once here so the two never
/// diverge.
pub fn negotiated_capabilities(peer_hello: &Hello) -> Vec<String> {
    wire::LOCAL_CAPABILITIES
        .iter()
        .filter(|c| peer_hello.capabilities.iter().any(|p| p == *c))
        .map(|c| c.to_string())
        .collect()
}

/// A control-stream endpoint's `Hello`-relevant halves, abstracted just
/// enough that the exchange core ([`initiate_on`]/[`respond_on`]) can run
/// over an in-memory duplex pipe in this module's own tests as well as the
/// real control stream in production — without duplicating the frame codec
/// (`qsh_proto::frame`) [`FramedSend`](qsh_transport::FramedSend)/
/// [`FramedRecv`](qsh_transport::FramedRecv) already wrap. Private: this
/// abstraction does not leak outside `handshake.rs`.
trait HelloChannel {
    async fn send_hello(&mut self, msg: &ControlMessage) -> Result<(), StreamError>;
    async fn recv_hello(&mut self) -> Result<Option<ControlMessage>, StreamError>;
}

impl HelloChannel for FramedStream {
    async fn send_hello(&mut self, msg: &ControlMessage) -> Result<(), StreamError> {
        self.send.send(msg).await
    }

    async fn recv_hello(&mut self) -> Result<Option<ControlMessage>, StreamError> {
        self.recv.recv::<ControlMessage>().await
    }
}

/// The initiator's half of the exchange, generic over [`HelloChannel`] so
/// it is unit-testable without quinn. Send our `Hello`, then wait
/// (bounded by [`HELLO_TIMEOUT`]) for the peer's reply.
async fn initiate_on<C: HelloChannel>(io: &mut C, local_hello: Hello) -> Result<Hello, HelloError> {
    io.send_hello(&ControlMessage::new(
        0,
        control_message::Body::Hello(local_hello),
    ))
    .await?;

    let reply = tokio::time::timeout(HELLO_TIMEOUT, io.recv_hello())
        .await
        .map_err(|_| HelloError::Timeout)??
        .ok_or(HelloError::ClosedBeforeHello)?;
    let peer_hello = match reply.body {
        Some(control_message::Body::Hello(h)) => h,
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::Error(e)),
        })) => {
            return Err(HelloError::Remote {
                code: e.error_code(),
                message: e.message,
                retryable: e.retryable,
            });
        }
        _ => return Err(HelloError::ExpectedHello),
    };
    if !wire::WIRE_MINOR_VERSIONS
        .iter()
        .any(|v| peer_hello.versions.contains(v))
    {
        // Asymmetric on purpose (module doc): no frame, a symmetric peer
        // already caught this from the responder side.
        return Err(HelloError::VersionMismatch);
    }
    Ok(peer_hello)
}

/// The responder's half of the exchange, generic over [`HelloChannel`].
/// Wait (bounded by [`HELLO_TIMEOUT`]) for the peer's `Hello`, then answer:
/// an `UNSUPPORTED` error frame and no `Hello` on a version mismatch, or
/// whatever `make_local_hello` decides once versions are known to overlap.
async fn respond_on<C: HelloChannel>(
    io: &mut C,
    make_local_hello: impl FnOnce(&Hello) -> Result<Hello, wire::Error>,
) -> Result<Hello, HelloError> {
    let first = tokio::time::timeout(HELLO_TIMEOUT, io.recv_hello())
        .await
        .map_err(|_| HelloError::Timeout)??
        .ok_or(HelloError::ClosedBeforeHello)?;
    let peer_hello = match first.body {
        Some(control_message::Body::Hello(h)) => h,
        // Report F-2: this connection reached `respond_on` at all only
        // because `verify_core` admitted it via pin or CA — a pairing-only
        // connection (`Principal::Pairing`) never runs this exchange
        // (`Server::serve_connection_inner`'s routing check). A
        // `PairingProof` here means the peer is retrying `qsh trust
        // accept` against a host that already has it pinned. Narrowly
        // scoped to this one body shape — every other non-`Hello` first
        // frame keeps the pre-existing silent `ExpectedHello` behavior
        // below, unchanged.
        Some(control_message::Body::PairingProof(_)) => {
            let err = wire::Error::new(
                ErrorCode::SessionConflict,
                "peer is already trusted; re-pairing requires the host to \
                 `trust remove` this peer first",
                false,
            );
            let _ = io.send_hello(&ControlMessage::error(0, err.clone())).await;
            return Err(HelloError::AlreadyPaired(err));
        }
        _ => return Err(HelloError::ExpectedHello),
    };

    if !wire::WIRE_MINOR_VERSIONS
        .iter()
        .any(|v| peer_hello.versions.contains(v))
    {
        let _ = io
            .send_hello(&ControlMessage::error(
                0,
                wire::Error::new(
                    ErrorCode::Unsupported,
                    "no common wire minor version",
                    false,
                ),
            ))
            .await;
        return Err(HelloError::VersionMismatch);
    }

    match make_local_hello(&peer_hello) {
        Ok(local_hello) => {
            io.send_hello(&ControlMessage::new(
                0,
                control_message::Body::Hello(local_hello),
            ))
            .await?;
            Ok(peer_hello)
        }
        Err(e) => {
            let _ = io.send_hello(&ControlMessage::error(0, e.clone())).await;
            Err(HelloError::Rejected(e))
        }
    }
}

/// Open the control stream and run the initiator's half of the `Hello`
/// exchange: `open_bi`, top-of-band priority
/// ([`wire::PRIORITY_CONTROL`]), send `local_hello`, then wait for the
/// reply under [`HELLO_TIMEOUT`]. `docs/design/protocol.md` §7: the
/// initiator is whoever dialed the connection, independent of QSH role.
pub async fn initiate(
    conn: &Connection,
    local_hello: Hello,
) -> Result<(FramedStream, Hello), HelloError> {
    let (send, recv) = conn.open_bi().await?;
    let mut ctl = FramedStream::control(send, recv);
    ctl.send.set_priority(wire::PRIORITY_CONTROL);
    let peer_hello = initiate_on(&mut ctl, local_hello).await?;
    Ok((ctl, peer_hello))
}

/// Accept the control stream and run the responder's half of the `Hello`
/// exchange: `accept_bi` under [`HELLO_TIMEOUT`], top-of-band priority,
/// read the peer's `Hello` under [`HELLO_TIMEOUT`], then let
/// `make_local_hello` decide our reply now that the peer's `Hello` is
/// known (capability/minor-version intersection, and from M3 Step 3
/// onward, registration decisions — the callback shape exists from this
/// step so that lands here instead of duplicating the exchange).
pub async fn respond<F>(
    conn: &Connection,
    make_local_hello: F,
) -> Result<(FramedStream, Hello), HelloError>
where
    F: FnOnce(&Hello) -> Result<Hello, wire::Error>,
{
    let (send, recv) = tokio::time::timeout(HELLO_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| HelloError::Timeout)??;
    let mut ctl = FramedStream::control(send, recv);
    ctl.send.set_priority(wire::PRIORITY_CONTROL);
    match respond_on(&mut ctl, make_local_hello).await {
        Ok(peer_hello) => Ok((ctl, peer_hello)),
        // All three of these arms already wrote an error frame inside
        // `respond_on` — give it a bounded chance to actually reach the
        // peer before this returns and the caller (rightly) tears the
        // connection down. Every other `Err` arm (`Timeout`,
        // `ClosedBeforeHello`, `ExpectedHello`) never wrote a byte, so
        // there is nothing to drain.
        Err(
            err @ (HelloError::VersionMismatch
            | HelloError::Rejected(_)
            | HelloError::AlreadyPaired(_)),
        ) => {
            drain_rejection(&mut ctl.send).await;
            Err(err)
        }
        Err(err) => Err(err),
    }
}

/// See [`REJECTION_DRAIN_TIMEOUT`]. `finish()` signals FIN on the error
/// frame we just wrote; `stopped()` resolves once the peer has acknowledged
/// every byte (or reset the stream) — either outcome means the frame
/// actually reached the peer's QUIC stack, not just our own send buffer.
/// Best-effort: any outcome (ok, already-closed, or timeout) just falls
/// through to the caller's own `conn.close()`.
async fn drain_rejection(send: &mut FramedSend) {
    if send.finish().is_ok() {
        let _ = tokio::time::timeout(REJECTION_DRAIN_TIMEOUT, send.stopped()).await;
    }
}

#[cfg(test)]
mod tests;
