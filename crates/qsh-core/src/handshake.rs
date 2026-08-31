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
/// connection down (`PLAN.md` M3 Step 3, "거부 error frame의 전달 보장").
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
/// (PLAN M3 Step 2 (d)).
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
mod tests {
    use super::*;
    use qsh_proto::frame::{CONTROL_FRAME_MAX, FrameDecoder};
    use qsh_proto::wire::{decode_msg, encode_control};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// One half of an in-memory, `Hello`-only control-stream pipe. Frames
    /// exactly like the real control stream (`qsh_proto::frame`,
    /// `CONTROL_FRAME_MAX`, via `qsh_proto::wire::encode_control`/
    /// `decode_msg` — the same codec `FramedSend`/`FramedRecv` use, not a
    /// reimplementation of it) so `initiate_on`/`respond_on` run unmodified
    /// against it.
    struct DuplexChannel {
        io: DuplexStream,
        dec: FrameDecoder,
        buf: [u8; 4096],
    }

    impl DuplexChannel {
        fn new(io: DuplexStream) -> Self {
            Self {
                io,
                dec: FrameDecoder::new(CONTROL_FRAME_MAX),
                buf: [0u8; 4096],
            }
        }
    }

    impl HelloChannel for DuplexChannel {
        async fn send_hello(&mut self, msg: &ControlMessage) -> Result<(), StreamError> {
            let wire = encode_control(msg)?;
            self.io.write_all(&wire).await.expect("duplex write");
            Ok(())
        }

        async fn recv_hello(&mut self) -> Result<Option<ControlMessage>, StreamError> {
            loop {
                if let Some(payload) = self.dec.next_frame()? {
                    return Ok(Some(decode_msg(payload.as_slice())?));
                }
                let n = self.io.read(&mut self.buf).await.expect("duplex read");
                if n == 0 {
                    let buffered = self.dec.buffered();
                    return if buffered == 0 {
                        Ok(None)
                    } else {
                        Err(StreamError::Truncated { buffered })
                    };
                }
                self.dec.push(&self.buf[..n]);
            }
        }
    }

    fn pair() -> (DuplexChannel, DuplexChannel) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (DuplexChannel::new(a), DuplexChannel::new(b))
    }

    fn hello(versions: &[u32], caps: &[&str]) -> Hello {
        Hello {
            versions: versions.to_vec(),
            device_name: "peer".into(),
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            reverse: None,
        }
    }

    const ALL_CAPS: &[&str] = wire::LOCAL_CAPABILITIES;

    /// Both combinations of role (host/client — irrelevant to this layer,
    /// it only sees `Hello` values) crossed with direction
    /// (initiate/respond) exchange `Hello` and compute the same
    /// capability intersection.
    #[tokio::test]
    async fn initiate_and_respond_agree_on_capabilities() {
        let (mut a, mut b) = pair();
        let a_hello = hello(&[0], &["exec", "session"]);
        let b_hello = hello(&[0], &["session", "resume.v1"]);
        let b_hello_for_cb = b_hello.clone();

        let (init_result, resp_result) = tokio::join!(
            initiate_on(&mut a, a_hello.clone()),
            respond_on(&mut b, move |_peer| Ok(b_hello_for_cb)),
        );

        let init_peer_hello = init_result.expect("initiator sees responder's Hello");
        let resp_peer_hello = resp_result.expect("responder sees initiator's Hello");

        assert_eq!(init_peer_hello.device_name, b_hello.device_name);
        assert_eq!(resp_peer_hello.device_name, a_hello.device_name);

        // Each side intersects the *other's advertised* Hello against its
        // own LOCAL_CAPABILITIES — not against ALL_CAPS or the peer's own
        // filtered view — so compute each side's view the same way the
        // real caller (ConnCtx/Session) would, and assert they agree with
        // each other.
        let caps_seen_by_initiator: Vec<String> = ALL_CAPS
            .iter()
            .filter(|c| init_peer_hello.capabilities.iter().any(|p| p == *c))
            .map(|c| c.to_string())
            .collect();
        let caps_seen_by_responder: Vec<String> = ALL_CAPS
            .iter()
            .filter(|c| resp_peer_hello.capabilities.iter().any(|p| p == *c))
            .map(|c| c.to_string())
            .collect();
        // The initiator's peer_hello is `b_hello` (["session","resume_v1"]);
        // the responder's peer_hello is `a_hello` (["exec","session"]).
        assert_eq!(
            caps_seen_by_initiator,
            vec!["session".to_string(), "resume.v1".to_string()]
        );
        assert_eq!(
            caps_seen_by_responder,
            vec!["exec".to_string(), "session".to_string()]
        );
        assert_eq!(
            negotiated_capabilities(&init_peer_hello),
            caps_seen_by_initiator
        );
        assert_eq!(
            negotiated_capabilities(&resp_peer_hello),
            caps_seen_by_responder
        );
    }

    /// The same, run with the roles that matter for M3: host-as-initiator
    /// (`qsh reverse`'s eventual shape) and client-as-responder
    /// (`qsh listen`'s eventual shape). This layer treats both identically
    /// — the test exists to pin that down.
    ///
    /// Each side advertises a different proper subset of
    /// [`wire::LOCAL_CAPABILITIES`] (not `ALL_CAPS` on both sides, which
    /// made the old version of this assertion trivially true independent
    /// of what `negotiated_capabilities` actually does — intersecting
    /// `ALL_CAPS` with `ALL_CAPS` returns `ALL_CAPS` under any filter,
    /// even a broken one).
    ///
    /// `negotiated_capabilities` anchors on [`wire::LOCAL_CAPABILITIES`]
    /// (this build's own full list, a constant — not a parameter)
    /// intersected with *the single `Hello` it is given*; it is not a
    /// symmetric intersection of the two peers' adverts. So each side's
    /// hardcoded expected value here is the *other* side's advertised
    /// subset (both are already ⊆ `LOCAL_CAPABILITIES`, so the filter is
    /// an identity/reorder on them) — not one shared value for both
    /// sides. That asymmetry is itself part of what this test pins down:
    /// swapping which role initiates/responds does not change what
    /// `negotiated_capabilities` computes from a given `Hello`.
    #[tokio::test]
    async fn host_initiate_client_respond_also_agree() {
        let (mut host, mut client) = pair();
        let host_hello = hello(&[0], &["exec", "session"]);
        let client_hello = hello(&[0], &["session", "resume.v1"]);
        let client_hello_for_cb = client_hello.clone();

        let (host_result, client_result) = tokio::join!(
            initiate_on(&mut host, host_hello.clone()),
            respond_on(&mut client, move |_peer| Ok(client_hello_for_cb)),
        );

        // `initiate_on` returns the *responder's* Hello (`client_hello`);
        // `respond_on` returns the *initiator's* Hello (`host_hello`).
        let host_peer_hello = host_result.unwrap();
        let client_peer_hello = client_result.unwrap();
        assert_eq!(
            negotiated_capabilities(&host_peer_hello),
            vec!["session".to_string(), "resume.v1".to_string()]
        );
        assert_eq!(
            negotiated_capabilities(&client_peer_hello),
            vec!["exec".to_string(), "session".to_string()]
        );
    }

    /// `Server::local_hello` (host role) and `client::Session::negotiate`'s
    /// inline `Hello` literal (client role) are the two real negotiation
    /// inputs every duplex-pipe test above stands in for with the local
    /// `hello()` helper. `Session::negotiate`'s literal is not extracted
    /// into a function reachable from here, so its half is pinned by
    /// comparing directly against the `wire::WIRE_MINOR_VERSIONS`/
    /// `wire::LOCAL_CAPABILITIES` constants it is built from
    /// (`client/mod.rs`); the host half is pinned by actually calling
    /// `Server::local_hello(None)` (`server/mod.rs`), so a future change to
    /// that constructor — not just to the constants — trips this test too.
    #[tokio::test]
    async fn server_local_hello_matches_negotiation_constants() {
        use std::sync::Arc;

        use crate::acl::AllowAllPinned;
        use crate::audit::NullAuditSink;
        use crate::broker::{Broker, BrokerConfig, PipeFactory, TestClock};
        use crate::server::Server;

        let broker = Broker::new(
            Arc::new(TestClock::new()),
            BrokerConfig::default(),
            Arc::new(PipeFactory::new(64 * 1024)),
        );
        let server = Server::new(
            Arc::new(AllowAllPinned),
            Arc::new(NullAuditSink),
            broker,
            "host",
        );

        let server_hello = server.local_hello(None);

        assert_eq!(server_hello.versions, wire::WIRE_MINOR_VERSIONS.to_vec());
        assert_eq!(
            server_hello.capabilities,
            wire::LOCAL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    /// `respond_on`'s `make_local_hello` callback can decline the peer's
    /// `Hello` (the `Err` arm at handshake.rs's `respond_on`,
    /// `HelloError::Rejected`) — Step 3's registration-denial path lands
    /// on exactly this branch, so this L0 pins its I/O contract now, ahead
    /// of any real caller: (i) the callback's `wire::Error` goes out as an
    /// error frame addressed to `request_id=0`, code/message untouched
    /// from what the callback returned; (ii) no responder `Hello` follows
    /// (clean EOF, same proof technique as the version-mismatch tests
    /// below); (iii) the returned `Err` is `HelloError::Rejected` carrying
    /// the original `wire::Error` verbatim.
    #[tokio::test]
    async fn respond_on_rejected_sends_error_frame_no_hello() {
        let (mut initiator, mut responder) = pair();
        let rejection = wire::Error::new(ErrorCode::InvalidArgument, "not registered", false);
        let rejection_for_cb = rejection.clone();

        let respond_task = tokio::spawn(async move {
            respond_on(&mut responder, move |_peer| Err(rejection_for_cb)).await
        });

        initiator
            .send_hello(&ControlMessage::new(
                0,
                control_message::Body::Hello(hello(&[0], ALL_CAPS)),
            ))
            .await
            .unwrap();

        let resp_result = respond_task.await.unwrap();
        match resp_result {
            Err(HelloError::Rejected(e)) => assert_eq!(e, rejection),
            other => panic!("expected Err(HelloError::Rejected(_)), got {other:?}"),
        }

        let frame = initiator
            .recv_hello()
            .await
            .unwrap()
            .expect("responder wrote an error frame");
        assert_eq!(frame.request_id, 0);
        match frame.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => {
                assert_eq!(e, rejection);
            }
            other => panic!("expected error frame, got {other:?}"),
        }

        // No `Hello` follows: `responder` (and its duplex write half) was
        // dropped when `respond_task` returned, so this is a clean EOF,
        // not a second frame.
        assert!(matches!(initiator.recv_hello().await, Ok(None)));
    }

    /// Report F-2 regression: a peer whose first control message is a
    /// `PairingProof` instead of `Hello` (a `qsh trust accept` retry
    /// against a host that already has it pinned — `verify_core`'s pin/CA
    /// priority means this connection never routed through
    /// `Principal::Pairing` at all, so it ends up here) must get an
    /// explicit, non-retryable `SESSION_CONFLICT` error frame, not the old
    /// silent `ExpectedHello` return that left the initiator staring at a
    /// bare `ConnectionLost`.
    #[tokio::test]
    async fn respond_on_pairing_proof_first_sends_session_conflict_no_hello() {
        let (mut initiator, mut responder) = pair();

        let respond_task = tokio::spawn(async move {
            respond_on(&mut responder, move |_peer| Ok(hello(&[0], ALL_CAPS))).await
        });

        initiator
            .send_hello(&ControlMessage::new(
                0,
                control_message::Body::PairingProof(wire::PairingProof {
                    device_name: "laptop".to_string(),
                    proof: vec![0u8; 32],
                }),
            ))
            .await
            .unwrap();

        let resp_result = respond_task.await.unwrap();
        let sent_err = match resp_result {
            Err(HelloError::AlreadyPaired(e)) => e,
            other => panic!("expected Err(HelloError::AlreadyPaired(_)), got {other:?}"),
        };
        assert_eq!(sent_err.error_code(), ErrorCode::SessionConflict);
        assert!(
            !sent_err.retryable,
            "a same-peer re-pair can never succeed by retrying — a fresh \
             invite does not change this host's pin state"
        );

        let frame = initiator
            .recv_hello()
            .await
            .unwrap()
            .expect("responder wrote an error frame");
        assert_eq!(frame.request_id, 0);
        match frame.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => {
                assert_eq!(e, sent_err);
                assert_eq!(e.error_code(), ErrorCode::SessionConflict);
                assert!(!e.retryable);
            }
            other => panic!("expected SESSION_CONFLICT error frame, got {other:?}"),
        }

        // No `Hello` follows: same clean-EOF proof technique as the other
        // rejection tests in this module.
        assert!(matches!(initiator.recv_hello().await, Ok(None)));
    }

    /// No common minor version: the responder answers `UNSUPPORTED` and
    /// ends without its own `Hello`.
    ///
    /// This asserts only what an in-memory duplex pipe — no `Connection`
    /// object, no `conn.close()` — can actually prove: the bytes
    /// `respond_on` put on the wire, decoded directly rather than routed
    /// back through `initiate_on`. It deliberately stops short of
    /// asserting that a real initiator observes this as
    /// `HelloError::Remote`: on the real control stream,
    /// `server::serve_connection` calls `conn.close()` right after
    /// `respond()` returns `Err`, which can race the just-written error
    /// frame off the wire before quinn has sent/acked it — a pre-existing
    /// property of `server/mod.rs`, unchanged by this step, that this
    /// duplex harness has no way to reproduce (there is no `Connection` to
    /// close). Whether the initiator actually receives `UNSUPPORTED`
    /// end-to-end is real-transport behavior owed to an L3 test, not this
    /// L0 unit — asserting it here would document a guarantee the wire
    /// does not keep.
    #[tokio::test]
    async fn version_mismatch_responder_sends_unsupported_no_hello() {
        let (mut initiator, mut responder) = pair();
        let ok_hello = hello(&[0], ALL_CAPS);

        let respond_task =
            tokio::spawn(
                async move { respond_on(&mut responder, move |_peer| Ok(ok_hello)).await },
            );

        initiator
            .send_hello(&ControlMessage::new(
                0,
                control_message::Body::Hello(hello(&[7], ALL_CAPS)),
            ))
            .await
            .unwrap();

        let resp_result = respond_task.await.unwrap();
        assert!(matches!(resp_result, Err(HelloError::VersionMismatch)));

        let frame = initiator
            .recv_hello()
            .await
            .unwrap()
            .expect("responder wrote a frame");
        match frame.body {
            Some(control_message::Body::Response(wire::Response {
                body: Some(response::Body::Error(e)),
            })) => {
                assert_eq!(e.error_code(), ErrorCode::Unsupported);
                assert_eq!(e.message, "no common wire minor version");
                assert!(!e.retryable);
            }
            other => panic!("expected UNSUPPORTED error frame, got {other:?}"),
        }
        // No `Hello` follows: `responder` (and its duplex write half) was
        // dropped when `respond_task` returned, so this is a clean EOF,
        // not a second frame.
        assert!(matches!(initiator.recv_hello().await, Ok(None)));
    }

    /// Asymmetric case: the responder never runs (or is not itself
    /// checking), so it answers with a `Hello` whose versions still don't
    /// overlap. The initiator's own guard catches this locally — no frame
    /// is sent, because there is no callback to send one from.
    ///
    /// This is the assertion PLAN M3 Step 2 (c) requires ("initiator가
    /// frame 전송 없이 종료"): it does not just check the returned
    /// `Err`, it proves zero bytes followed the initiator's own `Hello` by
    /// draining that one frame and then observing a clean EOF. Run inline
    /// rather than via a spawned responder task, so the sequencing below
    /// is exactly what executes: `DuplexStream`'s two directions are
    /// independent buffers, so pre-seeding `a`'s read side before calling
    /// `initiate_on` does not require the fake responder to have read our
    /// `Hello` first.
    #[tokio::test]
    async fn version_mismatch_initiator_local_guard_no_frame() {
        let (mut a, mut b) = pair();

        b.send_hello(&ControlMessage::new(
            0,
            control_message::Body::Hello(hello(&[9], ALL_CAPS)),
        ))
        .await
        .unwrap();

        let result = initiate_on(&mut a, hello(&[0], ALL_CAPS)).await;
        assert!(matches!(result, Err(HelloError::VersionMismatch)));

        // Drain the one frame `initiate_on` actually wrote: its own
        // `Hello`, sent before it learned the versions didn't overlap.
        let sent = b
            .recv_hello()
            .await
            .unwrap()
            .expect("initiator's own Hello");
        assert!(matches!(sent.body, Some(control_message::Body::Hello(_))));

        // ... then prove nothing followed it: close the initiator's write
        // half and confirm a clean EOF (zero buffered bytes), not a
        // second (error) frame. Without this, an `initiate_on` that
        // regressed into sending an UNSUPPORTED error frame here would
        // still pass — the old version of this test only checked `result`.
        drop(a);
        assert!(matches!(b.recv_hello().await, Ok(None)));
    }

    /// The responder's `HELLO_TIMEOUT` wait for the peer's `Hello` expires
    /// when nothing arrives.
    #[tokio::test(start_paused = true)]
    async fn respond_times_out_waiting_for_hello() {
        let (_silent_initiator, mut responder) = pair();
        let ok_hello = hello(&[0], ALL_CAPS);

        let result = tokio::time::timeout(
            HELLO_TIMEOUT * 2,
            respond_on(&mut responder, move |_peer| Ok(ok_hello)),
        )
        .await
        .expect("respond_on itself must resolve well within 2x its own timeout");

        assert!(matches!(result, Err(HelloError::Timeout)));
    }

    /// The initiator's `HELLO_TIMEOUT` wait for the reply expires when the
    /// responder never answers.
    #[tokio::test(start_paused = true)]
    async fn initiate_times_out_waiting_for_reply() {
        let (mut initiator, _silent_responder) = pair();

        let result = tokio::time::timeout(
            HELLO_TIMEOUT * 2,
            initiate_on(&mut initiator, hello(&[0], ALL_CAPS)),
        )
        .await
        .expect("initiate_on itself must resolve well within 2x its own timeout");

        assert!(matches!(result, Err(HelloError::Timeout)));
    }
}
