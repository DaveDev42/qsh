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
//! - [`control`]: framed prost message I/O over transport streams.
//! - [`stream`]: transport-neutral [`SendStream`]/[`RecvStream`].
//! - `mux` and `quic` (private): the contract every backend implements
//!   (`MuxConn`, `SendHalf`, `RecvHalf`) and the QUIC backend that does.
//!   `tests/conformance.rs` holds each backend to the same behavior list.
//! - [`error`]: transport-neutral error and code types
//!   ([`ConnectionError`], [`ReadError`], [`WriteError`], [`StreamCode`]),
//!   whose `Display` matches the QUIC stack's byte for byte.
//!
//! Wire structure never depends on QUIC-specific concepts (stream IDs,
//! datagrams): stream identity is always the in-band `StreamHeader`
//! (`docs/design/protocol.md` §7, §14). The public surface names no quinn
//! type but the hidden `Connection::quinn` test escape hatch
//! (`docs/adr/0043-no-tcp-fallback.md` decision 3): [`Connection`],
//! [`Endpoint`], [`SendStream`] and [`RecvStream`] are closed enums over the
//! backends. QUIC is the only one: ADR-0043 withdrew the TCP fallback and
//! kept this surface as the boundary that confines quinn to this crate.

pub mod control;
pub mod endpoint;
pub mod error;
pub mod identity;
mod mux;
mod quic;
pub mod stream;
pub mod tls;

pub use control::{FramedRecv, FramedSend, FramedStream, StreamError};
pub use endpoint::{
    AcceptError, ConnStats, Connection, DialError, Dialed, Dialer, Endpoint, Incoming, Listener,
    LocalIdentity, RESET_KEY_LEN, SetupError, TransportTuning, bind_tuned_udp_socket,
};
pub use error::{
    ApplicationClose, ClosedStream, ConnectError, ConnectionError, ExportError, ReadError,
    ReadExactError, ReadToEndError, StoppedError, StreamCode, WriteError,
};
pub use identity::{Fingerprint, FingerprintParseError, Principal, PrincipalParseError};
pub use mux::{TransportCaps, TransportKind};
pub use stream::{RecvStream, SendStream};
pub use tls::{
    AuthPath, Observation, PeerRole, QshPeerVerifier, RejectReason, StaticTrust, TrustEvaluator,
    VerifiedPeer,
};

// Re-export the certificate type callers need to build a `LocalIdentity`, so
// `qsh-core` never depends on rustls directly.
pub use rustls::pki_types::CertificateDer;
