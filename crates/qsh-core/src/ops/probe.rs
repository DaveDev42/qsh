//! Fingerprint probing ([`Ops::probe_fingerprint`]) and the dial and pairing failure classifiers.

use super::*;

impl Ops {
    /// Dial `address` once with an empty trust store and report the
    /// fingerprint the peer presented.
    ///
    /// Because nothing is trusted, the handshake always ends in a local
    /// rejection — the observation is the *point* of the dial, and no
    /// usable connection is ever established. Used by `trust.add` and by
    /// the CLI's interactive pin prompt.
    pub fn probe_fingerprint(&self, address: &str) -> Result<Fingerprint, OpError> {
        // Load the identity *before* entering the runtime: a platform key
        // store blocks on the OS credential service.
        let Some(loaded) = self.load_identity()? else {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "no device identity in {}; run qsh init first",
                    self.paths.config_dir.display()
                ),
            )
            .with_retryable(false));
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("failed to start an async runtime: {err}"),
                )
                .with_retryable(false)
            })?;

        let dialer = Dialer::new(loaded.local, Arc::new(StaticTrust::empty()))
            .with_timeout(PROBE_DIAL_TIMEOUT);
        let server_name = server_name_for(address);

        runtime.block_on(async move {
            let socket = resolve_one(address).await?;
            match dialer.dial(socket, &server_name).await {
                // Unreachable in practice (an empty trust store rejects
                // every peer), but never leave a connection open.
                Ok(dialed) => {
                    let observed = dialed.observation().and_then(|o| o.fingerprint);
                    dialed.connection.close(0, b"probe");
                    observed.ok_or_else(|| {
                        OpError::new(
                            ErrorCode::Internal,
                            "peer accepted by an empty trust store".to_string(),
                        )
                        .with_retryable(false)
                    })
                }
                // The expected outcome: our (empty) trust store rejected
                // the peer, and the verifier recorded what it presented.
                Err(DialError::LocalRejected {
                    observed: Some(fingerprint),
                    ..
                }) => Ok(fingerprint),
                Err(err) => Err(classify_probe_failure(err, address)),
            }
        })
    }
}

/// Turn a failed probe dial into the error the ops layer promises.
///
/// A *local* rejection with an observed fingerprint is the success case for
/// a probe and is handled by the caller; everything else is a genuine
/// failure. `AUTH_FAILED` details carry only a category — never a reason
/// that could leak trust-store contents (`docs/CLI.md` §6.11).
fn classify_probe_failure(err: DialError, address: &str) -> OpError {
    match err {
        DialError::LocalRejected {
            observed: Some(fingerprint),
            ..
        } => OpError::new(
            ErrorCode::TrustRequired,
            format!("peer {address} is not trusted"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({
            "observed_fingerprint": fingerprint.to_string(),
            "address": address,
        })),
        DialError::LocalRejected { observed: None, .. } => OpError::new(
            ErrorCode::AuthFailed,
            format!("could not read {address}'s certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "unverifiable_certificate"})),
        DialError::RemoteRejected => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address} rejected this device's certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "remote_rejected"})),
        // `PLAN.md` M8 Step 2 — same `ErrorCode::ConnectionFailed` as
        // `DialError::Failed` below, `qsh_transport::DialError::Refused`'s
        // own human message.
        DialError::Refused => {
            OpError::new(ErrorCode::ConnectionFailed, DialError::Refused.to_string())
        }
        DialError::Timeout(after) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} after {after:?}"),
        ),
        DialError::Connect(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot dial {address}: {err}"),
        ),
        DialError::Failed(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection to {address} failed: {err}"),
        ),
        DialError::Setup(err) => OpError::new(
            ErrorCode::Internal,
            format!("failed to build a client endpoint: {err}"),
        )
        .with_retryable(false),
    }
}

/// `trust.accept`'s own dial-failure classifier: unlike
/// [`classify_probe_failure`], the dialer here is
/// [`crate::pairing::AcceptAnyForPairing`] (accepts *any* fingerprint), so
/// a [`DialError::LocalRejected`] can only mean the peer's certificate
/// itself was structurally invalid (malformed, outside its validity
/// window — `qsh_transport::tls::verify_core`'s unconditional checks, which
/// run before any trust-evaluator branch), never "untrusted" — there is no
/// `observed_fingerprint` detail worth reporting since nothing was ever
/// evaluated against a fingerprint at all.
pub(super) fn classify_pairing_dial_failure(err: DialError, address: &str) -> OpError {
    match err {
        DialError::LocalRejected { .. } => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address}'s certificate could not be verified"),
        )
        .with_retryable(false),
        DialError::RemoteRejected => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address} rejected this device's certificate"),
        )
        .with_retryable(false),
        // `PLAN.md` M8 Step 2 — same as `classify_probe_failure`'s arm.
        DialError::Refused => {
            OpError::new(ErrorCode::ConnectionFailed, DialError::Refused.to_string())
        }
        DialError::Timeout(after) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} after {after:?}"),
        ),
        DialError::Connect(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot dial {address}: {err}"),
        ),
        DialError::Failed(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection to {address} failed: {err}"),
        ),
        DialError::Setup(err) => OpError::new(
            ErrorCode::Internal,
            format!("failed to build a client endpoint: {err}"),
        )
        .with_retryable(false),
    }
}

/// Turn a failed [`crate::pairing::accept`] exchange into the `OpError`
/// `trust.accept` reports. `Remote { code, .. }` is the common case — the
/// responder already picked one of `AUTH_FAILED`/`TRUST_REQUIRED`/
/// `SESSION_CONFLICT`/`INTERNAL` via its own `PairingError::as_wire_error`
/// (report §B7) and this just carries that verdict through unchanged. The
/// `NoMatch`/`Expired`/`AlreadyConsumed`/`PinCollision` arms are the
/// responder's own local-matching outcomes and are never constructed by
/// [`crate::pairing::accept`] itself (only by `respond`) — present here
/// only so the match stays exhaustive, matching this codebase's existing
/// style for structurally-unreachable-but-required arms.
pub(super) fn classify_pairing_exchange_failure(err: crate::pairing::PairingError) -> OpError {
    use crate::pairing::PairingError as E;
    match err {
        E::Remote {
            code,
            message,
            retryable,
        } => OpError::new(code, message).with_retryable(retryable),
        E::NoMatch => OpError::new(ErrorCode::AuthFailed, err.to_string()).with_retryable(false),
        E::Expired => OpError::new(ErrorCode::TrustRequired, err.to_string()).with_retryable(false),
        E::AlreadyConsumed | E::PinCollision | E::InvalidAssignedName => {
            OpError::new(ErrorCode::SessionConflict, err.to_string()).with_retryable(false)
        }
        E::InvalidDeviceName { .. } => {
            OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
        }
        E::ResponderProofMismatch => {
            OpError::new(ErrorCode::AuthFailed, err.to_string()).with_retryable(false)
        }
        E::Timeout => OpError::new(ErrorCode::Timeout, err.to_string()),
        E::ClosedEarly | E::UnexpectedMessage | E::Stream(_) | E::Connection(_) => {
            OpError::new(ErrorCode::ConnectionFailed, err.to_string())
        }
        E::ExporterUnavailable => {
            OpError::new(ErrorCode::Internal, err.to_string()).with_retryable(false)
        }
        E::Store(op_err) => op_err,
    }
}
