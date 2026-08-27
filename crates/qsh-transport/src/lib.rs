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
//! - [`control`]: framed prost message I/O over QUIC streams.
//!
//! Wire structure never depends on QUIC-specific concepts (stream IDs,
//! datagrams): stream identity is always the in-band `StreamHeader`
//! (`docs/design/protocol.md` §7, §14). quinn is the first `Transport`
//! implementation; the P1 TCP fallback (ADR-0005) adds another behind the
//! same [`Connection`]/framed-stream surface.

pub mod control;
pub mod endpoint;
pub mod identity;
pub mod tls;

pub use control::{FramedRecv, FramedSend, FramedStream, StreamError};
pub use endpoint::{
    AcceptError, Connection, DialError, Dialed, Dialer, Incoming, Listener, LocalIdentity,
    SetupError, bind_tuned_udp_socket,
};
pub use identity::{Fingerprint, FingerprintParseError, Principal, PrincipalParseError};
pub use tls::{
    AuthPath, Observation, PeerRole, QshPeerVerifier, RejectReason, StaticTrust, TrustEvaluator,
    VerifiedPeer,
};

// Re-export the certificate types callers need to build a `LocalIdentity`,
// quinn's connection error, and the `Endpoint` a `Dialed` hands back, so
// `qsh-core` never depends on rustls or quinn directly.
pub use quinn::{ConnectionError, Endpoint, ReadError, WriteError};
pub use rustls::pki_types::CertificateDer;
