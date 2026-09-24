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
    /// The matching invite's stored `assigned_name` failed
    /// [`crate::trust::validate_peer_label`] — a corrupted or hand-edited
    /// `invites.toml` (`qsh pair invite --as` only ever writes an
    /// already-validated name). Maps to the **same** wire error as
    /// [`Self::PinCollision`] (`SESSION_CONFLICT`) so the initiator cannot
    /// use the reply to distinguish this from an ordinary name collision;
    /// the invite is left unconsumed, exactly as [`Self::PinCollision`]
    /// leaves it. Never falls back to the peer's self-asserted name
    /// (ADR-0012 결정 6).
    #[error("the invite's assigned name failed validation")]
    InvalidAssignedName,
    /// The responder answered `PairingAccepted`, but its proof did not
    /// verify against this initiator's own independently-derived
    /// expectation. **Never pin on this outcome** — see [`wire::PairingAccepted`]'s
    /// own doc for why this check exists at all.
    #[error("the responder's proof did not verify; refusing to trust it")]
    ResponderProofMismatch,
    /// The peer-reported `device_name` — `PairingProof.device_name` on the
    /// responder side, `PairingAccepted.device_name` on the initiator side
    /// — failed [`wire::validate_device_name`] (control character, bidi
    /// control, zero-width character, or a length outside `1..=64` bytes;
    /// see that function's own doc for the full table and why homoglyphs
    /// are deliberately not on it). Rejected at ingest, before any pin,
    /// persist, or tracing emission (`docs/CLI.md` §6.11, `docs/design/
    /// protocol.md` §15.5) — a name like this reaching `human.rs`'s
    /// `print_trust_*` renderers could otherwise overwrite or hide the
    /// fingerprint printed right next to it, which is exactly the value
    /// pairing tells the operator to compare out of band. Never carries
    /// the rejected value itself, even here — only which field was
    /// rejected and why, never what it contained.
    #[error("{field} is not a valid device name: {reason}")]
    InvalidDeviceName {
        /// Which wire field failed validation.
        field: &'static str,
        /// Why [`wire::validate_device_name`] rejected it.
        reason: wire::DeviceNameError,
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
            RedeemOutcome::InvalidAssignedName => {
                unreachable!(
                    "InvalidAssignedName is handled by the caller (InvalidAssignedName), \
                     not built here"
                )
            }
            RedeemOutcome::Expired => PairingError::Expired,
            RedeemOutcome::AlreadyConsumed => PairingError::AlreadyConsumed,
            RedeemOutcome::NoMatch => PairingError::NoMatch,
        }
    }

    /// The wire `Error` a responder sends for this failure (report §B7).
    ///
    /// [`Self::InvalidAssignedName`] deliberately sends the *same* message
    /// as [`Self::PinCollision`], not its own `Display` text — see that
    /// variant's doc. The distinct `Display` stays for the host-local
    /// `tracing::warn!` in `server/mod.rs` and the distinct audit failure
    /// category; only the wire bytes are unified. Pinned byte-identical by
    /// `invalid_assigned_name_and_pin_collision_produce_the_same_wire_error`.
    fn as_wire_error(&self) -> wire::Error {
        let code = match self {
            PairingError::NoMatch => ErrorCode::AuthFailed,
            PairingError::Expired => ErrorCode::TrustRequired,
            PairingError::AlreadyConsumed
            | PairingError::PinCollision
            | PairingError::InvalidAssignedName => ErrorCode::SessionConflict,
            PairingError::InvalidDeviceName { .. } => ErrorCode::InvalidArgument,
            _ => ErrorCode::Internal,
        };
        let message = match self {
            PairingError::InvalidAssignedName => PairingError::PinCollision.to_string(),
            other => other.to_string(),
        };
        wire::Error::new(code, message, false)
    }
}

/// Reject a peer-reported device name that fails [`wire::validate_device_name`]
/// (control character, bidi control, zero-width character, or a length
/// outside `1..=64` bytes) — applied to both wire directions before any
/// pin, persist, or tracing emission ever sees the value (see
/// [`PairingError::InvalidDeviceName`]'s own doc for why). Never echoes
/// `name` in the error it returns, even on rejection.
fn reject_control_chars(name: &str, field: &'static str) -> Result<(), PairingError> {
    wire::validate_device_name(name)
        .map_err(|reason| PairingError::InvalidDeviceName { field, reason })
}

/// A verified pairing exchange's result: the name to pin the peer under —
/// everything [`crate::trust::TrustStore::add_peer`] needs to pin it
/// (`report §B9/§B10` — neither side ever carries a fingerprint over the
/// wire, `Connection::peer_fingerprint` already has it for free).
#[derive(Debug, Clone)]
pub struct PairingSuccess {
    /// The name to pin the peer under: on [`respond`]'s side, the
    /// invite's `assigned_name` when the invite carried one, else the
    /// peer's own self-reported device name (ADR-0012 결정 6); on
    /// [`accept`]'s side, always the responder's self-reported device
    /// name — `Ops::trust_accept` resolves its own `--as` override
    /// locally, this field never reflects it.
    pub pinned_name: String,
    /// `true` iff `pinned_name` came from an invite's `assigned_name`
    /// rather than the peer's self-assertion. Meaningful only on
    /// [`respond`]'s side (it selects [`pairing_pin_notice`]'s wording);
    /// always `false` from [`accept`], which has no invite of its own to
    /// consult.
    pub pinned_by_invite: bool,
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
                pinned_name: accepted.device_name,
                pinned_by_invite: false,
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

/// The self-asserted-name clause of the pairing-succeeded notice (ADR-0017
/// 결정 3, `:30-32`). Selected when the redeemed invite carried no
/// `--as`: the responder pins the peer under whatever `device_name` it
/// claimed for itself, and this notice exists so the operator running
/// `qsh serve` sees that fact rather than discovering it later from
/// `trust.toml`. Deliberately never says the peer "asked for itself" any
/// more — once `--as` exists, self-assertion is a fact about *this*
/// exchange, not a property the peer's own claim carries on its own; see
/// [`PAIRING_PINNED_INVITE_ASSIGNED`] for the other branch.
pub const PAIRING_PINNED_SELF_ASSERTED: &str =
    "pinned a new peer under the name it sent for itself because the invite carried no --as:";

/// [`pairing_pin_notice`]'s other branch: selected when the redeemed
/// invite's `assigned_name` (`qsh pair invite --as`) is what got pinned,
/// not the peer's self-reported name (ADR-0012 결정 6).
pub const PAIRING_PINNED_INVITE_ASSIGNED: &str =
    "pinned a new peer under the name the invite assigned with --as:";

/// [`pairing_pin_notice`]'s impact+next-command clause when no `[[acl]]`
/// row names the newly-pinned principal yet: it can authenticate, but
/// every action is still denied (default-deny, `docs/design/
/// architecture.md`'s security-defaults). The restart clause comes
/// *before* the `qsh acl check` command on purpose: `Ops::acl_check`
/// re-reads `acl.toml` on every call (`ops/acl.rs`), so a row added after
/// this `qsh serve` process started would otherwise look already-applied
/// to `acl check` while the running process still denies everything.
pub const PAIRING_ACL_ROW_ABSENT: &str = "No `[[acl]]` row names it, so it can authenticate but every action is still denied. Add a row for it to acl.toml and restart this `qsh serve` before it takes effect, then re-check with:";

/// [`pairing_pin_notice`]'s impact+next-command clause when an `[[acl]]`
/// row already names the newly-pinned principal — the peer inherits that
/// row's grants exactly as written, including any the operator did not
/// mean for this specific device (ADR-0017 결정 3, the condition that
/// decision accepts). No restart clause here: this branch is computed from
/// [`crate::acl::PinnedPrincipalIndex`], which is the very `Policy` this
/// running process is enforcing, not a fresh re-read of `acl.toml` — so
/// "inherits that row's grants exactly as written" is already true at the
/// moment this notice prints.
pub const PAIRING_ACL_ROW_PRESENT: &str = "An `[[acl]]` row already names it, so it inherits that row's grants exactly as written, including any you did not mean for this device. Confirm them with:";

/// The full pairing-succeeded stderr notice (`Server::serve_pairing_connection`'s
/// pin callback delivers this through the same `on_notice` sink
/// `crate::serve::run_serve` wires — `qsh-core` never writes to stderr
/// itself, ADR-0017 결정 3 / `docs/design/architecture.md` §1). `name` is
/// the peer's self-reported device name, already pinned by the time this
/// is called; `acl_row_present` comes from
/// [`crate::acl::PinnedPrincipalIndex::names_device`] against the `Policy`
/// this process loaded at startup, never a fresh read of `acl.toml`.
pub fn pairing_pin_notice(name: &str, acl_row_present: bool, pinned_by_invite: bool) -> String {
    let observation = if pinned_by_invite {
        PAIRING_PINNED_INVITE_ASSIGNED
    } else {
        PAIRING_PINNED_SELF_ASSERTED
    };
    let tail = if acl_row_present {
        PAIRING_ACL_ROW_PRESENT
    } else {
        PAIRING_ACL_ROW_ABSENT
    };
    // `name` is the pinned name — self-asserted or invite-assigned —
    // `wire::validate_device_name` rejects control/bidi/zero-width
    // characters and anything over 64 bytes, but not spaces, quotes or
    // shell metacharacters (`"Dave's MacBook Pro"` is a valid name,
    // asserted as such by `reject_control_chars_allows_an_ordinary_device_name`
    // below). The principal is shell-quoted so the printed "next command"
    // stays the command it claims to be.
    let principal = shell_single_quoted(&format!("device:{name}"));
    format!(
        "{observation} \"{name}\". {tail} qsh acl check --principal {principal} --action session.open"
    )
}

/// POSIX single-quote a string so it survives a shell as one word.
///
/// Wrapping in single quotes alone is not enough: a `'` inside `text` would
/// close the quote early, so each one becomes `'\''` — close, escaped
/// quote, reopen. This matters because `validate_device_name` admits an
/// apostrophe, and [`pairing_pin_notice`] advertises its output as a
/// command the operator can paste. A `text` with no apostrophe comes back
/// simply wrapped, which is what the notice's pinned wording expects.
fn shell_single_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The host-local stderr notice for a replayed invite
/// (`PairingError::AlreadyConsumed`) — ADR-0017 결정 4 exempts the wire
/// reply (`PairingError::as_wire_error`'s `SESSION_CONFLICT` mapping)
/// and the console `tracing::warn!` in
/// `Server::serve_pairing_connection` from carrying a remedy (folding a
/// host-state clause into either would turn a pairing failure into an
/// oracle for that state); this notice is the **third**, additional line,
/// on the same host-local channel [`pairing_pin_notice`] already uses, so
/// it is unambiguously additive on its own, not a change to either
/// exempted axis.
///
pub const PAIRING_INVITE_REPLAY_NOTICE: &str = "an invite code was presented again after it had already been redeemed. Nothing was pinned and the peer got SESSION_CONFLICT; an invite is single-use by design, so this is not a fault on this host. Mint a fresh one with `qsh pair invite` if that peer still needs to pair.";

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

    // Resolved inside the closure, once `redeem` has already confirmed the
    // matching invite's stored `assigned_name` (if any) is itself valid —
    // captured here rather than returned through `RedeemOutcome` because
    // the whole point of `on_matched`'s placement (`docs/design/
    // protocol.md` §15.6) is that the pin decision happens *before* the
    // invite is marked consumed.
    let mut pin_name = String::new();
    let mut pinned_by_invite = false;
    let outcome = store.redeem(
        &ekm,
        &client_proof,
        std::time::SystemTime::now(),
        |assigned_name| {
            pinned_by_invite = assigned_name.is_some();
            let candidate = assigned_name.unwrap_or(proof_msg.device_name.as_str());
            // The wire guard above only ran `wire::validate_device_name` on
            // the self-asserted name (no `/` check) — the effective name gets
            // the full `validate_peer_label` rule right before it is ever
            // handed to `try_pin` (`crate::trust::validate_peer_label`'s own
            // doc). A self-asserted name that fails here declines through the
            // same non-distinguishing `Rejected` -> `PinCollision` path a
            // fingerprint collision does; `qsh`-generated `device_id`s never
            // contain `/`, so this changes nothing for them.
            if crate::trust::validate_peer_label(candidate).is_err() {
                return false;
            }
            pin_name = candidate.to_string();
            try_pin(candidate)
        },
    )?;
    let server_proof = match outcome {
        RedeemOutcome::Accepted { server_proof } => server_proof,
        RedeemOutcome::Rejected => {
            let err = PairingError::PinCollision;
            drain_rejection(&mut ctl, &err).await;
            return Err(err);
        }
        RedeemOutcome::InvalidAssignedName => {
            let err = PairingError::InvalidAssignedName;
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
        pinned_name: pin_name,
        pinned_by_invite,
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
mod tests;
