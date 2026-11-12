//! `qsh-transport`: QUIC transport glue (quinn + rustls) — and nothing
//! else. No session, ACL or business logic lives here
//! (`docs/design/architecture.md` §1).
//!
//! - [`identity`]: SPKI [`Fingerprint`] and certificate-derived [`Principal`].
//! - [`tls`]: [`QshPeerVerifier`] (pin OR private CA, no web PKI) behind
//!   the injected [`TrustEvaluator`].
//! - [`endpoint`]: [`Dialer`]/[`Listener`] producing verified
//!   [`Connection`]s; ALPN `qsh/1`, keep-alive 15 s / idle 45 s, no 0-RTT,
//!   no session tickets.
//!   [`PacketPipe`] with [`Dialer::dial_over_pipe`] is the jump hop's inner
//!   connection on an in-memory socket (ADR-0056 decisions 2, 5, 6).
//!   [`PunchEndpoint`] is the hole-punching variant: one endpoint on one
//!   punch-aware UDP socket (ADR-0054 decisions 3, 7, 13).
//! - [`control`]: framed prost message I/O over transport streams.
//! - [`stream`]: transport-neutral [`SendStream`]/[`RecvStream`].
//! - `mux` and `quic` (private): the contract every backend implements
//!   (`MuxConn`, `SendHalf`, `RecvHalf`) and the QUIC backend that does.
//!   `tests/it/conformance.rs` holds each backend to the same behavior list.
//! - [`peer_addr`]: [`PeerAddr`], the remote end of a connection (socket
//!   address today; key plus direct or relay path for ADR-0061's iroh backend).
//! - [`error`]: transport-neutral error and code types
//!   ([`ConnectionError`], [`ReadError`], [`WriteError`], [`StreamCode`]),
//!   whose `Display` matches the QUIC stack's byte for byte.
//!
//! Wire structure never depends on QUIC-specific concepts (stream IDs,
//! datagrams): stream identity is always the in-band `StreamHeader`
//! (`docs/design/protocol.md` §7, §14). QUIC DATAGRAM is enabled as an
//! optional carrier only (`Connection::send_datagram`, ADR-0052 decision 7):
//! every datagram message has a stream twin. The connection surface names no quinn
//! type (`docs/adr/0043-no-tcp-fallback.md` decision 3, ADR-0061 decision 5;
//! the `Connection::quinn` escape hatch is gone): [`Connection`],
//! [`Endpoint`], [`SendStream`] and [`RecvStream`] are closed enums over the
//! backends. QUIC is the only one: ADR-0043 withdrew the TCP fallback and
//! kept this surface as the boundary that confines quinn to this crate.

pub mod control;
pub mod endpoint;
pub mod error;
pub mod identity;
mod mux;
pub mod peer_addr;
mod quic;
pub mod stream;
pub mod tls;

pub use control::{FramedRecv, FramedSend, FramedStream, StreamError};
pub use endpoint::{
    AcceptError, CLOSE_CODE_NOT_ADOPTED, CLOSE_DRAIN_CAP, ConnStats, Connection, DialError, Dialed,
    Dialer, Endpoint, Incoming, JUMP_PACKET_MAX, JUMP_PACKET_MIN, Listener, LocalIdentity,
    MAX_PUNCH_WINDOWS, NOT_ADOPTED_REASON, PIPE_LOCAL_ADDR, PIPE_REMOTE_ADDR, PacketPipe, PipePeer,
    PipeStats, PunchArrival, PunchEndpoint, PunchInbox, PunchStats, PunchWindow, RESET_KEY_LEN,
    SetupError, SocketSource, TransportTuning, bind_tuned_udp_socket, default_dial_timeout,
    set_default_dial_timeout,
};
pub use error::{
    ApplicationClose, ClosedStream, ConnectError, ConnectionError, DatagramError, ExportError,
    ReadError, ReadExactError, ReadToEndError, StoppedError, StreamCode, WriteError,
};
pub use identity::{Fingerprint, FingerprintParseError, Principal, PrincipalParseError};
pub use mux::{TransportCaps, TransportKind};
pub use peer_addr::{PEER_KEY_LEN, PeerAddr, PeerKey, PeerPath};
pub use stream::{RecvStream, SendStream};
pub use tls::{
    AuthPath, BoundTrust, Observation, PeerBinding, PeerRole, QshPeerVerifier, RejectReason,
    StaticTrust, TrustEvaluator, VerifiedPeer,
};

// Re-export the certificate type callers need to build a `LocalIdentity`, so
// `qsh-core` never depends on rustls directly.
pub use rustls::pki_types::CertificateDer;
