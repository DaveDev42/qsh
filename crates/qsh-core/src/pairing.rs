//! The pairing wire exchange (ADR-0002, `PLAN.md` M7 Step 4,
//! `docs/design/protocol.md` §15).
//!
//! Two halves, mirroring `crate::handshake`'s initiate/respond split but
//! deliberately **not** built on that module: a pairing connection never
//! runs the `Hello` exchange at all (`crate::server::Server::
//! serve_pairing_connection`'s own doc — routed there instead of
//! `handshake::respond` before any session/ACL state could exist).
//!
//! - [`accept`] — the initiator's side (`qsh trust accept`). Sends one
//!   [`wire::PairingProof`], verifies the responder's
//!   [`wire::PairingAccepted`] before trusting anything it says.
//! - [`respond`] — the responder's side (`qsh serve`, once its trust
//!   evaluator's `pairing_open()` admitted the connection). Reads one
//!   `PairingProof`, redeems it against [`SharedInviteStore`], replies.
//!
//! Both directions' proofs are domain-separated derivations of the same
//! RFC 5705 TLS exporter value — see [`EXPORTER_LABEL`] and
//! `crate::trust::pairing`'s `CLIENT_PROOF_DOMAIN`/`SERVER_PROOF_DOMAIN`
//! for why a plain echo of the initiator's proof can never pass as the
//! responder's own.

use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, ControlMessage, control_message, response};
use qsh_transport::{
    CertificateDer, Connection, Fingerprint, FramedStream, Principal, StreamError, TrustEvaluator,
};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::ops::OpError;
use crate::trust::SharedInviteStore;
use crate::trust::pairing::{RedeemOutcome, proofs_from_secret};

/// RFC 5705 TLS exporter label pairing derives its channel-binding proofs
/// from (`docs/design/protocol.md` §15). Context is always empty — the
/// exporter output is already unique per TLS session/key-share, which is
/// exactly the channel-binding property this needs (a MITM terminating two
/// separate TLS sessions gets two different exporter values, so a proof
/// valid on one leg never verifies on the other).
pub const EXPORTER_LABEL: &[u8] = b"qsh pairing v1";

/// Width of the exported keying material pairing pulls per connection —
/// 32 bytes, matching blake3's own output width.
const EKM_LEN: usize = 32;

/// Bound on the whole pairing exchange (one message each way). Reuses
/// `handshake::HELLO_TIMEOUT`'s value for consistency — no protocol reason
/// the two must match, just no reason for a separate tunable yet.
pub const PAIRING_TIMEOUT: Duration = crate::handshake::HELLO_TIMEOUT;

/// Errors from the pairing exchange. Neither [`accept`] nor [`respond`]
/// leaks these to a wire peer or a log line at the secret-bearing detail
/// level — callers (`Ops::trust_accept`, `Server::serve_pairing_connection`)
/// map this onto `OpError`/an audit record exactly like `handshake::
/// HelloError` is mapped by their non-pairing counterparts.
#[derive(Debug, Error)]
pub enum PairingError {
    /// The exchange did not complete within [`PAIRING_TIMEOUT`].
    #[error("pairing exchange timed out")]
    Timeout,
    /// The peer closed the control stream before sending anything.
    #[error("peer closed the connection before completing pairing")]
    ClosedEarly,
    /// The first (only) control message was not the expected shape.
    #[error("unexpected control message during pairing")]
    UnexpectedMessage,
    /// `Connection::export_keying_material` failed (should be unreachable
    /// — the TLS handshake already completed).
    #[error("TLS exporter unavailable on this connection")]
    ExporterUnavailable,
    /// No live invite on the responder matched this proof at all.
    #[error("no matching invite")]
    NoMatch,
    /// The matching invite's TTL had already passed.
    #[error("invite expired")]
    Expired,
    /// The matching invite was already redeemed by an earlier attempt.
    #[error("invite already used")]
    AlreadyConsumed,
    /// The proof verified, but pinning the initiator locally would collide
    /// with an existing pin under the same name and a *different*
    /// fingerprint (this step's brief invariant #5 — unlike `trust add`'s
    /// own established silent no-op on this exact case, pairing must fail
    /// loudly). The invite was left unconsumed — a renamed or removed
    /// conflicting pin can retry within the same TTL.
    #[error("a peer is already pinned under this name with a different identity")]
    PinCollision,
    /// The responder answered `PairingAccepted`, but its proof did not
    /// verify against this initiator's own independently-derived
    /// expectation. **Never pin on this outcome** — see [`wire::PairingAccepted`]'s
    /// own doc for why this check exists at all.
    #[error("the responder's proof did not verify; refusing to trust it")]
    ResponderProofMismatch,
    /// The peer-reported `device_name` — `PairingProof.device_name` on the
    /// responder side, `PairingAccepted.device_name` on the initiator side
    /// — contained a control character (`char::is_control()`, tab
    /// included: a device name is a label, not formatted text). Rejected
    /// at ingest, before any pin, persist, or tracing emission
    /// (`docs/CLI.md` §6.11, `docs/design/protocol.md` §15.5) — a name
    /// like this reaching `human.rs`'s `print_trust_*` renderers could
    /// otherwise overwrite or hide the fingerprint printed right next to
    /// it, which is exactly the value pairing tells the operator to
    /// compare out of band. Never carries the rejected value itself, even
    /// here — only which field was rejected, never what it contained.
    #[error("{field} contains a control character; device names must not")]
    InvalidDeviceName {
        /// Which wire field failed validation.
        field: &'static str,
    },
    /// The responder answered with a wire `Error` frame.
    #[error("{code}: {message}")]
    Remote {
        /// Responder-reported code.
        code: ErrorCode,
        /// Responder-reported message.
        message: String,
        /// Responder-reported retryability.
        retryable: bool,
    },
    /// The control stream itself failed (read/write/frame/codec).
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// Opening or accepting the control stream failed at the connection
    /// level.
    #[error(transparent)]
    Connection(#[from] qsh_transport::ConnectionError),
    /// The invite store could not be read or persisted.
    #[error(transparent)]
    Store(#[from] OpError),
}

impl PairingError {
    /// Whether this is the connection going away (peer close, idle timeout,
    /// reset) rather than the peer misbehaving on an open one — same
    /// distinction `server::ConnError::is_connection_lost` draws for the
    /// ordinary `Hello` path, reused verbatim by
    /// `Server::serve_pairing_connection`'s own logging.
    pub fn is_connection_lost(&self) -> bool {
        matches!(
            self,
            PairingError::Connection(_)
                | PairingError::Stream(StreamError::Read(
                    qsh_transport::ReadError::ConnectionLost(_)
                ))
                | PairingError::Stream(StreamError::Write(
                    qsh_transport::WriteError::ConnectionLost(_)
                ))
        )
    }

    /// Map a redemption failure onto the matching [`PairingError`] variant
    /// (report §B7's `ErrorCode` table, one level up from the raw
    /// [`RedeemOutcome`]).
    fn from_redeem_outcome(outcome: RedeemOutcome) -> Self {
        match outcome {
            RedeemOutcome::Accepted { .. } => {
                unreachable!("Accepted is handled by the caller before this is ever built")
            }
            RedeemOutcome::Rejected => {
                unreachable!("Rejected is handled by the caller (PinCollision), not built here")
            }
            RedeemOutcome::Expired => PairingError::Expired,
            RedeemOutcome::AlreadyConsumed => PairingError::AlreadyConsumed,
            RedeemOutcome::NoMatch => PairingError::NoMatch,
        }
    }

    /// The wire `Error` a responder sends for this failure (report §B7).
    fn as_wire_error(&self) -> wire::Error {
        let code = match self {
            PairingError::NoMatch => ErrorCode::AuthFailed,
            PairingError::Expired => ErrorCode::TrustRequired,
            PairingError::AlreadyConsumed | PairingError::PinCollision => {
                ErrorCode::SessionConflict
            }
            PairingError::InvalidDeviceName { .. } => ErrorCode::InvalidArgument,
            _ => ErrorCode::Internal,
        };
        wire::Error::new(code, self.to_string(), false)
    }
}

/// Reject a peer-reported device name containing a control character
/// (`char::is_control()`, tab included) — applied to both wire directions
/// before any pin, persist, or tracing emission ever sees the value (see
/// [`PairingError::InvalidDeviceName`]'s own doc for why). Never echoes
/// `name` in the error it returns, even on rejection.
fn reject_control_chars(name: &str, field: &'static str) -> Result<(), PairingError> {
    if name.chars().any(char::is_control) {
        return Err(PairingError::InvalidDeviceName { field });
    }
    Ok(())
}

/// A verified pairing exchange's result: the *other* side's self-reported
/// name and this connection's own view of its certificate fingerprint —
/// everything [`crate::trust::TrustStore::add_peer`] needs to pin it
/// (`report §B9/§B10` — neither side ever carries a fingerprint over the
/// wire, `Connection::peer_fingerprint` already has it for free).
#[derive(Debug, Clone)]
pub struct PairingSuccess {
    /// The name to pin the peer under (its own self-reported device name).
    pub peer_device_name: String,
}

/// Pull this connection's RFC 5705 exported keying material under
/// [`EXPORTER_LABEL`] with an empty context.
fn export_keying_material(conn: &Connection) -> Result<[u8; EKM_LEN], PairingError> {
    let mut buf = [0u8; EKM_LEN];
    conn.export_keying_material(&mut buf, EXPORTER_LABEL, &[])
        .map_err(|_| PairingError::ExporterUnavailable)?;
    Ok(buf)
}

/// The initiator's side (`qsh trust accept <address> <code>`): open the
/// control stream, send one [`wire::PairingProof`] proving possession of
/// `secret`, and verify the responder's [`wire::PairingAccepted`] before
/// returning success. `secret` is the parsed invite code
/// ([`qsh_proto::pairing::parse_invite_code`]'s output) — this function
/// never displays or logs it.
///
/// **Never returns `Ok` without having verified the responder's own
/// proof.** This is the fix for the gap report §B13 records: without it, a
/// dial-time evaluator permissive enough to reach *any* endpoint
/// ([`AcceptAnyForPairing`]) would let any endpoint's bare "accepted" reply
/// be trusted.
pub async fn accept(
    conn: &Connection,
    device_name: &str,
    secret: &[u8],
) -> Result<PairingSuccess, PairingError> {
    let (send, recv) = conn.open_bi().await?;
    let mut ctl = FramedStream::control(send, recv);
    ctl.send.set_priority(wire::PRIORITY_CONTROL);

    let ekm = export_keying_material(conn)?;
    let (client_proof, expected_server_proof) = proofs_from_secret(secret, &ekm);

    ctl.send
        .send(&ControlMessage::new(
            0,
            control_message::Body::PairingProof(wire::PairingProof {
                device_name: device_name.to_string(),
                proof: client_proof.to_vec(),
            }),
        ))
        .await?;

    let reply = tokio::time::timeout(PAIRING_TIMEOUT, ctl.recv.recv::<ControlMessage>())
        .await
        .map_err(|_| PairingError::Timeout)??
        .ok_or(PairingError::ClosedEarly)?;

    match reply.body {
        Some(control_message::Body::PairingAccepted(accepted)) => {
            let received: [u8; 32] = accepted
                .proof
                .as_slice()
                .try_into()
                .map_err(|_| PairingError::ResponderProofMismatch)?;
            if !bool::from(received.ct_eq(&expected_server_proof)) {
                return Err(PairingError::ResponderProofMismatch);
            }
            reject_control_chars(&accepted.device_name, "PairingAccepted.device_name")?;
            Ok(PairingSuccess {
                peer_device_name: accepted.device_name,
            })
        }
        Some(control_message::Body::Response(wire::Response {
            body: Some(response::Body::Error(e)),
        })) => Err(PairingError::Remote {
            code: e.error_code(),
            message: e.message,
            retryable: e.retryable,
        }),
        _ => Err(PairingError::UnexpectedMessage),
    }
}

/// The responder's side (`qsh serve`, once `pairing_open()` admitted this
/// connection). Accept the peer-opened control stream, read one
/// [`wire::PairingProof`], redeem it against `store`, and reply. On
/// success, `local_device_name` (this host's own name — the same value its
/// ordinary `Hello.device_name` carries) is echoed back inside
/// `PairingAccepted` alongside this record's independently-derived
/// server-direction proof (never a copy of what the initiator sent — see
/// [`wire::PairingAccepted`]'s own doc). On any failure, a wire `Error`
/// frame is written and given a bounded chance to reach the peer (mirroring
/// `handshake::respond`'s own rejection-drain discipline) before this
/// returns `Err`.
///
/// `try_pin` runs once the initiator's proof has verified against a live
/// invite, but **before** that invite is marked consumed or `PairingAccepted`
/// is sent (`crate::trust::pairing::SharedInviteStore::redeem`'s own
/// `on_matched` hook) — the caller (`Server::serve_pairing_connection`)
/// attempts its local `TrustStore::add_peer` pin here, passing the
/// initiator's self-reported device name, and returns `false` on a name
/// collision (this step's brief invariant #5). A decline surfaces as
/// [`PairingError::PinCollision`] and leaves the invite untouched.
pub async fn respond(
    conn: &Connection,
    store: &SharedInviteStore,
    local_device_name: &str,
    try_pin: impl FnOnce(&str) -> bool,
) -> Result<PairingSuccess, PairingError> {
    let (send, recv) = tokio::time::timeout(PAIRING_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| PairingError::Timeout)??;
    let mut ctl = FramedStream::control(send, recv);
    ctl.send.set_priority(wire::PRIORITY_CONTROL);

    let first = tokio::time::timeout(PAIRING_TIMEOUT, ctl.recv.recv::<ControlMessage>())
        .await
        .map_err(|_| PairingError::Timeout)??
        .ok_or(PairingError::ClosedEarly)?;
    let Some(control_message::Body::PairingProof(proof_msg)) = first.body else {
        return Err(PairingError::UnexpectedMessage);
    };

    // Reject a control-character device name before anything else touches
    // it — before the invite is even looked up, let alone `try_pin`'d or
    // logged (`PairingError::InvalidDeviceName`'s own doc).
    if let Err(err) = reject_control_chars(&proof_msg.device_name, "PairingProof.device_name") {
        drain_rejection(&mut ctl, &err).await;
        return Err(err);
    }

    let ekm = export_keying_material(conn)?;
    let client_proof: [u8; 32] = match proof_msg.proof.as_slice().try_into() {
        Ok(p) => p,
        // A malformed proof can never match anything — same terminal
        // answer as a well-formed one that simply matches nothing.
        Err(_) => {
            let err = PairingError::NoMatch;
            drain_rejection(&mut ctl, &err).await;
            return Err(err);
        }
    };

    let outcome = store.redeem(&ekm, &client_proof, std::time::SystemTime::now(), || {
        try_pin(&proof_msg.device_name)
    })?;
    let server_proof = match outcome {
        RedeemOutcome::Accepted { server_proof } => server_proof,
        RedeemOutcome::Rejected => {
            let err = PairingError::PinCollision;
            drain_rejection(&mut ctl, &err).await;
            return Err(err);
        }
        other => {
            let err = PairingError::from_redeem_outcome(other);
            drain_rejection(&mut ctl, &err).await;
            return Err(err);
        }
    };

    ctl.send
        .send(&ControlMessage::new(
            0,
            control_message::Body::PairingAccepted(wire::PairingAccepted {
                device_name: local_device_name.to_string(),
                proof: server_proof.to_vec(),
            }),
        ))
        .await?;
    // Give the just-sent reply a bounded chance to actually reach the peer
    // before the caller (`Server::serve_pairing_connection`) tears down the
    // whole connection — without this, `conn.close()` right after `send`
    // returning (which only means the bytes were handed to the QUIC send
    // buffer, not that the peer has them) can race the initiator's own
    // read and replace a successful exchange with a bare `ConnectionLost`.
    // Same discipline as [`drain_rejection`]'s own delivery guarantee.
    if ctl.send.finish().is_ok() {
        let _ = tokio::time::timeout(
            crate::handshake::REJECTION_DRAIN_TIMEOUT,
            ctl.send.stopped(),
        )
        .await;
    }

    Ok(PairingSuccess {
        peer_device_name: proof_msg.device_name,
    })
}

/// See `handshake::REJECTION_DRAIN_TIMEOUT`'s doc — same bounded
/// best-effort delivery guarantee for a just-written error frame, reused
/// here for pairing's own rejection path.
async fn drain_rejection(ctl: &mut FramedStream, err: &PairingError) {
    let _ = ctl
        .send
        .send(&ControlMessage::error(0, err.as_wire_error()))
        .await;
    if ctl.send.finish().is_ok() {
        let _ = tokio::time::timeout(
            crate::handshake::REJECTION_DRAIN_TIMEOUT,
            ctl.send.stopped(),
        )
        .await;
    }
}

/// The initiator's dial-time [`TrustEvaluator`] (`qsh trust accept`, a
/// one-shot process with no long-lived trust store to gate). Accepts
/// *any* certificate the dialed address presents — pairing's real
/// authentication is possession of the invite secret, proven at the
/// application layer by [`accept`], never the TLS identity itself (report
/// §B3). This is why [`accept`] verifying the responder's own proof is
/// load-bearing, not optional (report §B13): TLS trust alone grants
/// nothing here.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAnyForPairing;

impl TrustEvaluator for AcceptAnyForPairing {
    fn lookup_pin(&self, _fingerprint: &Fingerprint) -> Option<Principal> {
        Some(Principal::Pairing)
    }

    fn ca_roots(&self) -> Vec<CertificateDer<'static>> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Report F-1 regression.** Zero test in this crate directly pinned
    /// down channel binding at the exact layer that provides it: this
    /// module's own [`export_keying_material`] wrapper. Before this test,
    /// replacing its body with `Ok([0u8; EKM_LEN])` (i.e. deriving both
    /// proofs from a constant instead of the TLS session) left every
    /// existing test green — the wire-level DoD-quadrant tests in
    /// `qsh-testkit/tests/pairing_loopback.rs` only ever exercise a single
    /// live connection at a time, so they cannot distinguish "bound to
    /// this session's TLS key material" from "bound to nothing at all".
    ///
    /// Two independent loopback connections must export different keying
    /// material, and neither may be the degenerate all-zero value a
    /// stubbed-out exporter would produce — the exact property
    /// `docs/design/protocol.md` §15.3 claims defeats a MITM that
    /// terminates two separate TLS sessions.
    #[tokio::test(flavor = "multi_thread")]
    async fn export_keying_material_differs_across_separate_connections() {
        let (client1, _server1) = crate::tunnel::testutil::loopback_pair().await;
        let (client2, _server2) = crate::tunnel::testutil::loopback_pair().await;

        let e1 = export_keying_material(&client1).expect("export 1");
        let e2 = export_keying_material(&client2).expect("export 2");

        assert_ne!(
            e1, e2,
            "two separate TLS sessions must export different keying material \
             (channel binding, protocol.md §15.3) — a MITM terminating two \
             legs would otherwise see the same value on both"
        );
        assert_ne!(
            e1, [0u8; EKM_LEN],
            "the exporter must not degenerate to an all-zero constant"
        );
        assert_ne!(
            e2, [0u8; EKM_LEN],
            "the exporter must not degenerate to an all-zero constant"
        );
    }

    /// Fix A2's ingest guard, at the pure-predicate level: an ordinary
    /// device name (letters, digits, hyphens, spaces — the shapes every
    /// existing pairing test in `qsh-testkit/tests/pairing_loopback.rs`
    /// already uses, e.g. `"laptop"`) must pass, so the guard is not
    /// over-broad.
    #[test]
    fn reject_control_chars_allows_an_ordinary_device_name() {
        assert!(reject_control_chars("laptop", "PairingProof.device_name").is_ok());
        assert!(reject_control_chars("Dave's MacBook Pro", "PairingProof.device_name").is_ok());
    }

    /// The actual threat this guard closes (report background: `human.rs`'s
    /// `print_trust_accept` prints `{name} ({fingerprint})` on one line —
    /// an escape sequence or bare `\r` in `name` can overwrite or hide the
    /// fingerprint printed right after it). Tab is control too (a device
    /// name is a label, not formatted text), unlike `human::sanitize`'s own
    /// tab exemption for free-form diagnostic text.
    #[test]
    fn reject_control_chars_rejects_escape_sequences_cr_and_tab() {
        for bad in ["evil\u{1b}[Kname", "evil\rname", "evil\tname", "evil\0name"] {
            let err = reject_control_chars(bad, "PairingProof.device_name")
                .expect_err(&format!("{bad:?} must be rejected"));
            assert!(
                matches!(
                    err,
                    PairingError::InvalidDeviceName {
                        field: "PairingProof.device_name"
                    }
                ),
                "unexpected error for {bad:?}: {err:?}"
            );
            // The rejected value itself must never appear in the error's
            // own `Display` — only the field name (fail-closed logging
            // rule: `PairingError::InvalidDeviceName`'s own doc).
            assert!(
                !err.to_string().contains("evil"),
                "the rejected device name must not be echoed: {err}"
            );
        }
    }

    /// [`PairingError::InvalidDeviceName`] must map to `INVALID_ARGUMENT`
    /// on the wire, not fall through the catch-all `_ => Internal` arm in
    /// [`PairingError::as_wire_error`].
    #[test]
    fn invalid_device_name_maps_to_invalid_argument_on_the_wire() {
        let err = PairingError::InvalidDeviceName {
            field: "PairingProof.device_name",
        };
        assert_eq!(err.as_wire_error().error_code(), ErrorCode::InvalidArgument);
    }
}
