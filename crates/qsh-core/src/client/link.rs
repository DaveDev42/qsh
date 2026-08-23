//! The two concrete carriers a `Session`'s control channel can run over
//! (`docs/design/protocol.md` §11-3, `PLAN.md` M3 Step 6): a QUIC control
//! stream dialed straight to the peer (the forward route, unchanged since
//! M1), or a `LOCAL_CONTROL` conduit to this machine's resident `qsh
//! listen` daemon, which relays to the peer over its live reverse
//! registration (`crate::localctl::client`, `crate::reverse::listen`'s
//! `ControlHub` on the daemon side).
//!
//! [`ControlLink`] is deliberately an **enum**, never a generic type
//! parameter or an ADR-0005 `Transport`/`StreamMux` trait object — a
//! `Session` is either dialed or relayed, never a third thing, and every
//! caller (`crate::client::Session`) already knows the wire messages it
//! sends and receives (`qsh.wire.v1::ControlMessage`) regardless of which
//! carrier is underneath, so there is nothing a trait's extra indirection
//! would buy here.
//!
//! Dependency direction: this file depends on [`crate::localctl::client`],
//! never the reverse — `localctl::client` stays transport-free (it must
//! never name `qsh_transport`/`quinn`/`rustls`, `xtask arch`'s
//! `LOCALCTL_CLIENT_FILE` ban) and has no reason to know this enum exists.
//!
//! Only the surface [`crate::client::Session`] actually uses is exposed:
//! send one `ControlMessage`, receive the next one, and a best-effort
//! half-close. Nothing here decides *when* to reconnect or *what* a
//! session_open/get/list/read/write/resize/close request looks like —
//! that stays entirely in `crate::ops::session`, unchanged by which
//! variant is underneath (`PLAN.md` M3 Step 6's "Zero reverse-specific
//! business logic" rule).

use qsh_proto::wire::ControlMessage;
use qsh_transport::FramedStream;

// `crate::localctl` is `#[cfg(unix)]`-only (`lib.rs`) — the `Local`
// carrier this file adds exists only there; `Quic` (unchanged since M1)
// stays available on every platform. Windows leg trap (b): an ungated
// import consumed only by unix-only code trips `unused_imports` under
// Windows clippy.
#[cfg(unix)]
use crate::localctl::client::ControlConduit;
#[cfg(unix)]
use crate::ops::OpError;

use super::ClientError;

/// A `Session`'s control channel: either half of a QUIC control stream
/// dialed straight to the peer, or a `LOCAL_CONTROL` conduit to this
/// machine's resident daemon that relays the exact same
/// `ControlMessage`/`Response` pair onto the peer's live reverse
/// registration (`docs/design/protocol.md` §11-3's "conn 이 아니라
/// stream 이 대상" framing extended to a second carrier).
pub(crate) enum ControlLink {
    /// Dialed straight to the peer over QUIC (forward route).
    Quic(FramedStream),
    /// Relayed through this machine's `qsh listen` daemon over a
    /// `LOCAL_CONTROL` conduit (reverse route). `#[cfg(unix)]`: localctl
    /// (UDS) is unix-only (`crate::localctl`'s own gate in `lib.rs`) —
    /// on Windows this carrier simply does not exist, and
    /// `Ops::resolve_route` never produces a reverse route there either
    /// (`ops/host.rs`'s own Windows-leg doc), so nothing ever needs to
    /// construct this variant on that platform.
    #[cfg(unix)]
    Local(ControlConduit),
}

impl ControlLink {
    /// Encode + send one `ControlMessage`, whichever carrier this is.
    pub(crate) async fn send(&mut self, msg: &ControlMessage) -> Result<(), ClientError> {
        match self {
            ControlLink::Quic(stream) => Ok(stream.send.send(msg).await?),
            #[cfg(unix)]
            ControlLink::Local(conduit) => {
                conduit.send(msg).await.map_err(op_error_to_client_error)
            }
        }
    }

    /// Read the next `ControlMessage`. `Ok(None)` on a clean end of the
    /// link — a QUIC stream FIN at a frame boundary, or the daemon closing
    /// the UDS conduit the same way (`crate::localctl::daemon`'s
    /// `serve_control`: a dead host ends every conduit of that host this
    /// way, so this is also how the CLI side learns of a reverse
    /// connection's death — `docs/design/protocol.md` §11-3).
    pub(crate) async fn recv(&mut self) -> Result<Option<ControlMessage>, ClientError> {
        match self {
            ControlLink::Quic(stream) => Ok(stream.recv.recv::<ControlMessage>().await?),
            #[cfg(unix)]
            ControlLink::Local(conduit) => conduit.recv().await.map_err(op_error_to_client_error),
        }
    }

    /// Best-effort half-close of the send side (`Session::close`'s
    /// "finish, then close the connection" sequence). Errors are ignored
    /// here exactly as [`qsh_transport::control::FramedSend::finish`]'s own
    /// doc allows ("a second call errors with `ClosedStream`, which
    /// callers may ignore") — the Local carrier has no equivalent
    /// close-frame drain to wait for: dropping the underlying `UnixStream`
    /// (this `Session`'s eventual drop) closes the fd, which the daemon
    /// sees as a clean EOF on its own read, the same signal a QUIC FIN
    /// gives it.
    // Two bodies, not one `if let`: without the `Local` variant (Windows,
    // no `unix` cfg), `ControlLink` has exactly one variant, so `if let
    // ControlLink::Quic(stream) = self` becomes an irrefutable pattern —
    // `-D warnings` under Windows clippy (`irrefutable_let_patterns`).
    #[cfg(unix)]
    pub(crate) fn finish(&mut self) {
        if let ControlLink::Quic(stream) = self {
            let _ = stream.send.finish();
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn finish(&mut self) {
        let ControlLink::Quic(stream) = self;
        let _ = stream.send.finish();
    }
}

/// [`OpError`] (what [`crate::localctl::client`]'s conduit calls return) →
/// [`ClientError`] (what every other `Session` method returns), preserving
/// the code/message/retryable triple verbatim — the same "nothing to
/// translate" shape as `crate::localctl::client::remote_error`'s
/// `LocalError` → `OpError` mapping one layer down.
#[cfg(unix)]
fn op_error_to_client_error(err: OpError) -> ClientError {
    ClientError::Remote {
        code: err.code,
        message: err.message,
        retryable: err.retryable,
    }
}

// Both tests below exercise the `Local` carrier (`ControlLink::Local`,
// `OpError`, `op_error_to_client_error`) or `crate::localctl` directly,
// all `#[cfg(unix)]`-only — so the whole module is, rather than splitting
// each test individually.
#[cfg(all(test, unix))]
mod tests {
    use qsh_proto::ErrorCode;
    use qsh_proto::local::{LocalHelloAck, LocalResponse, local_response};
    use qsh_proto::wire::{Ping, control_message};
    use tokio::net::UnixListener;

    use super::*;

    /// Proves the enum actually **dispatches** — a `Local`-carried
    /// `ControlLink` sends and receives real `ControlMessage` frames
    /// through a live `LOCAL_CONTROL` conduit, exactly the same call
    /// shape `crate::client::Session::request` uses regardless of which
    /// variant is underneath. The `Quic` variant's dispatch is exercised
    /// by every pre-existing forward-path `client::Session` test in this
    /// crate (nothing about `ControlLink::send`/`recv` changes that
    /// behavior — see `crate::client::mod`'s `request`), so this test adds
    /// coverage for the one variant that is actually new.
    #[tokio::test]
    async fn control_link_local_dispatches_send_and_recv_through_the_conduit() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("link-dispatch.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
            let _hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();
            let echoed: ControlMessage = conduit.recv().await.unwrap().unwrap();
            conduit.send(&echoed).await.unwrap();
        });

        let handshake = crate::localctl::client::open_control(&sock, "phone", 0)
            .await
            .unwrap();
        let mut link = ControlLink::Local(handshake.conduit);

        let ping = ControlMessage::new(1, control_message::Body::Ping(Ping {}));
        link.send(&ping).await.unwrap();
        let echoed = link.recv().await.unwrap().expect("daemon echoed a frame");
        assert_eq!(echoed, ping);

        // A no-op on the Local carrier (see `finish`'s own doc) — must not
        // panic or hang.
        link.finish();

        daemon.await.unwrap();
    }

    #[test]
    fn op_error_maps_to_client_error_remote_verbatim() {
        let err = OpError::new(ErrorCode::HostNotFound, "no such host").with_retryable(false);
        match op_error_to_client_error(err) {
            ClientError::Remote {
                code,
                message,
                retryable,
            } => {
                assert_eq!(code, ErrorCode::HostNotFound);
                assert_eq!(message, "no such host");
                assert!(!retryable);
            }
            other => panic!("expected ClientError::Remote, got {other:?}"),
        }
    }
}
