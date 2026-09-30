//! Which failures deserve another attempt (ADR-0023 decision 9).
//!
//! The table is one function. A combination it does not list is not
//! retried, and neither is an `ErrorCode::Unknown(_)`: a supervisor that
//! guesses "probably transient" about a code it has never seen would retry
//! forever against a refusal.
//!
//! Two exceptions belong to the callers, not to this function, because they
//! depend on more than a code: a `-R` re-open that loses its bind race with
//! the close it just sent is re-sent a bounded number of times, and a
//! `RemoteForwardClose` answered "no such forward_id" counts as success.
//! Callers apply those first and only then classify what is left.

use qsh_proto::ErrorCode;

/// Where a failure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// This machine dialing a forward-route peer.
    LocalDial,
    /// This machine asking its own `qsh listen` daemon (reverse route).
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the reverse route supervisor uses it")
    )]
    LocalDaemon,
    /// The supervisor's own checks on a fresh carrier (fingerprint match,
    /// capability presence).
    SupervisorCheck,
    /// The peer answered a request with an error.
    Peer,
    /// The local listener failed fatally.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the listener's own end is handled by the holder")
    )]
    LocalListener,
}

/// The verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Plan another attempt, budget permitting.
    Retry,
    /// End the tunnel with this error.
    Stop,
}

/// Classify one failure. `retryable` is the peer's own flag (or the local
/// error's), consulted only for [`Source::Peer`].
pub(crate) fn classify(source: Source, code: &ErrorCode, retryable: bool) -> Disposition {
    use Disposition::{Retry, Stop};
    match (source, code) {
        // DNS, connect, handshake deadline and admission refusal all map to
        // `CONNECTION_FAILED` on the dial path.
        (Source::LocalDial, ErrorCode::ConnectionFailed) => Retry,
        // `AUTH_FAILED` (we rejected the peer's certificate, or it rejected
        // us), `INTERNAL`, `CONFIG_ERROR` and everything else: stop. Retrying
        // an auth failure after `trust remove` would be failing open.
        (Source::LocalDial, _) => Stop,

        // Both `HOST_NOT_FOUND` shapes count: a stale entry inside
        // `stale_retention` (retryable) and an entry already swept
        // (not retryable) are both "the route we had is not there yet".
        (Source::LocalDaemon, ErrorCode::HostNotFound) => Retry,
        (Source::LocalDaemon, ErrorCode::Timeout | ErrorCode::ConnectionFailed) => Retry,
        (Source::LocalDaemon, _) => Stop,

        // A fingerprint mismatch or a missing capability never heals by
        // itself.
        (Source::SupervisorCheck, _) => Stop,

        // The peer's `acl.toml` is read once at start-up, so a denial only
        // changes with a restart and repeating it just fills its audit log.
        (Source::Peer, ErrorCode::PermissionDenied) => Stop,
        // Never repeat an authentication verdict, whatever the flag says.
        (Source::Peer, ErrorCode::AuthFailed | ErrorCode::TrustRequired) => Stop,
        // A code this build cannot interpret is not assumed transient.
        (Source::Peer, ErrorCode::Unknown(_)) => Stop,
        (Source::Peer, _) => {
            if retryable {
                Retry
            } else {
                Stop
            }
        }

        (Source::LocalListener, _) => Stop,
    }
}
