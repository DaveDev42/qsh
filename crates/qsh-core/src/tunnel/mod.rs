//! Tunnel stream-open seam (`PLAN.md` M4 Step 2; `docs/design/protocol.md`
//! §7 "스트림 배치", §12 "우선순위와 backpressure"; `docs/design/architecture.md`
//! §8's quinn selection rationale).
//!
//! [`open_stream`] itself stays deliberately bare — no listener, no dial,
//! no splice, no ACL check (those are its submodules' and
//! `crate::server`'s, added by M4 Step 3: [`dial`] the destination dialer
//! seam the host's inline `forward.local` gate calls *after* it authorizes,
//! [`splice`] the raw byte pipe a tunnel becomes past its handshake, and
//! [`local`] the requester's `-L` listener). What this seam *does* fix,
//! ahead of any tunnel business logic landing, is that opening a tunnel
//! data stream is symmetric across:
//!
//! - **carrier** — a forward QUIC connection dialed straight to the peer,
//!   or a reverse `LOCAL_STREAM` conduit to this machine's resident `qsh
//!   listen` daemon ([`crate::client::link::DataLink`], the same
//!   forward/reverse axis [`crate::client::link::ControlLink`] already
//!   uses for the control channel);
//! - **role** — the requester opens `TCP_CONNECT`, the peer that accepted
//!   the inbound TCP connection opens `TCP_ACCEPTED` (protocol.md §7's
//!   stream table); this function does not care which — it only opens
//!   whatever `header` already says, so `-R over reverse` (Step 5) is
//!   wiring a fourth combination onto a seam that already treats the other
//!   three uniformly, not a new code path.
//!
//! Every tunnel stream this seam opens gets quinn's [`PRIORITY_TUNNEL`]
//! send priority (`protocol.md` §12: control > session data > exec data >
//! tunnel), so a saturated tunnel never outranks a PTY chunk in the local
//! send queue. Session/exec stream priorities are untouched by this
//! module — they keep going through their own existing call sites
//! (`crate::client::Session::open_data_link`, `crate::exec`).

use qsh_proto::wire::{PRIORITY_TUNNEL, StreamHeader};

use crate::client::ClientError;
use crate::client::link::{DataKillSwitch, DataLink, DataRecv, DataSend};

pub use local::{LocalForwardError, LocalForwardHandle};
pub use remote::RemoteForwardAcceptor;

pub(crate) mod dial;
pub(crate) mod local;
pub(crate) mod remote;
pub(crate) mod splice;
#[cfg(test)]
pub(crate) mod testutil;

/// Open a tunnel data stream (`StreamHeader{TCP_CONNECT}` or
/// `StreamHeader{TCP_ACCEPTED}`) on `link`, sending `header` as its first
/// frame and applying [`PRIORITY_TUNNEL`] (`docs/design/protocol.md` §12).
///
/// Symmetric across [`DataLink::Quic`] (forward) and [`DataLink::Local`]
/// (reverse) — both are just `link.open_stream(...)` here, same as they
/// are for [`crate::client::Session`]'s `SESSION_DATA` stream. The
/// returned pair is framed (able to carry [`qsh_proto::wire::ConnectResult`]
/// as `TCP_CONNECT`'s first reply) — converting it to a raw byte splice
/// past that point is Step 3/4's job, not this seam's.
///
/// Called by [`local::LocalForward`] once per forwarded TCP connection
/// (M4 Step 3); Step 4/5 add the `TCP_ACCEPTED` callers.
pub(crate) async fn open_stream(
    link: &DataLink<'_>,
    header: &StreamHeader,
) -> Result<(DataSend, DataRecv, DataKillSwitch), ClientError> {
    link.open_stream(header, PRIORITY_TUNNEL).await
}

#[cfg(test)]
mod tests {
    use qsh_proto::wire::StreamKind;

    use super::*;
    use crate::tunnel::testutil::loopback_pair;

    /// (a) `open_stream` opens with quinn send priority ==
    /// [`PRIORITY_TUNNEL`] — read back directly off the local `SendStream`
    /// (`qsh_transport::control::FramedSend::priority`) rather than
    /// inferred, since priority is a local scheduler hint the peer never
    /// observes on the wire. Also confirms the stream really carries the
    /// `TCP_CONNECT` header this seam was asked to open, by having the
    /// accepting side read it back.
    #[tokio::test]
    async fn tunnel_stream_opens_with_tcp_connect_header_and_priority_tunnel() {
        let (client, server) = loopback_pair().await;

        let header = StreamHeader {
            kind: StreamKind::TcpConnect as i32,
            ticket: Vec::new(),
            host: "localhost".to_string(),
            port: 3000,
        };
        let link = DataLink::Quic(&client);
        let (mut send, _recv, _kill) = open_stream(&link, &header).await.unwrap();

        match &send {
            DataSend::Quic(quic_send) => {
                assert_eq!(quic_send.priority().unwrap(), PRIORITY_TUNNEL);
            }
            #[cfg(unix)]
            DataSend::Local(_) => unreachable!("loopback_pair only opens the forward Quic route"),
        }

        // Discriminating guard: `PRIORITY_TUNNEL == 0` coincides with
        // quinn's default send priority, so the assertion above alone would
        // still hold even if `open_stream` never reached `set_priority`.
        // Open one more stream straight through the seam with a non-default
        // sentinel and confirm it actually lands — that is what proves the
        // seam applies the priority it is handed rather than leaving the
        // stream at quinn's default.
        const SENTINEL_PRIORITY: i32 = 42;
        let link2 = DataLink::Quic(&client);
        let (mut sentinel_send, _r, _k) =
            link2.open_stream(&header, SENTINEL_PRIORITY).await.unwrap();
        match &sentinel_send {
            DataSend::Quic(s) => assert_eq!(
                s.priority().unwrap(),
                SENTINEL_PRIORITY,
                "the seam must apply the priority it is passed, not quinn's default"
            ),
            #[cfg(unix)]
            DataSend::Local(_) => unreachable!("forward Quic route only"),
        }
        sentinel_send.finish();

        let (accepted_send, accepted_recv) = server.accept_bi().await.unwrap();
        // The seam already sent `header` as the stream's first frame
        // before returning — read it back on the peer side and confirm
        // it is exactly the `TCP_CONNECT` header this test asked for.
        let mut recv = qsh_transport::FramedRecv::data(accepted_recv);
        let got: StreamHeader = recv.recv().await.unwrap().expect("header frame");
        assert_eq!(got, header);
        assert_eq!(got.stream_kind(), Some(StreamKind::TcpConnect));

        // Close cleanly — no tunnel business logic to exercise here.
        send.finish();
        drop(accepted_send);
    }

    /// (c) the symmetric seam compiles and runs over the reverse
    /// `DataLink::Local` carrier too: a fake `LOCAL_STREAM` responder
    /// (the same shape `crate::client::link`'s own
    /// `data_link_local_dispatches_send_and_recv_of_real_session_frames`
    /// test uses) accepts the handshake, reads the `TCP_ACCEPTED` header
    /// back, and both ends close immediately — an empty pipe, opened and
    /// torn down, proving this carrier is reachable through the seam with
    /// no divergent code path (this module's own doc, "not a new code
    /// path").
    #[cfg(unix)]
    #[tokio::test]
    async fn tunnel_stream_opens_symmetrically_over_the_reverse_data_link() {
        use qsh_proto::local::{LocalHelloAck, LocalResponse, local_response};
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("tunnel-reverse.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
            let _hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&LocalResponse {
                    body: Some(local_response::Body::HelloAck(LocalHelloAck {
                        host: "phone".to_string(),
                        peer_fingerprint: "sha256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
                            .to_string(),
                        generation: 1,
                        capabilities: Vec::new(),
                    })),
                })
                .await
                .unwrap();
            let header: StreamHeader = conduit.recv().await.unwrap().unwrap();
            assert_eq!(header.stream_kind(), Some(StreamKind::TcpAccepted));
            // Nothing more to do — an empty pipe, closed immediately, is
            // exactly what this seam-level test asks for.
        });

        let header = StreamHeader {
            kind: StreamKind::TcpAccepted as i32,
            ticket: b"forward-id".to_vec(),
            host: String::new(),
            port: 0,
        };
        let link = DataLink::Local {
            socket: &sock,
            host: "phone",
        };
        let (mut send, _recv, _kill) = open_stream(&link, &header).await.unwrap();
        send.finish();

        daemon.await.unwrap();
    }
}
