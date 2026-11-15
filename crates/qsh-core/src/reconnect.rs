//! Reconnect-cause vocabulary and the wire-frozen application close codes the
//! forward supervise loop and the session link share (ADR-0068 decision 9
//! step 3: moved out of the retired reverse modules, no behavior change).

/// Close code a connection's own watchdog (`PathWatch`) sends when it
/// declares an established connection's path dead. Wire-frozen: peers read
/// it back through `classify_connection_error` as
/// `ReconnectCause::PathDead`, so the value never changes. Not a transport
/// concern (registration semantics), so it lives here rather than in
/// `qsh-transport` (`docs/design/architecture.md` §1).
///
/// A silently severed path leaves the QUIC connection object technically
/// alive, so any stream still reading on it blocks until quinn's own
/// unconfigurable `max_idle_timeout` (`docs/design/protocol.md` §10, 45 s)
/// finally kills it; only closing the connection with this code ends it
/// promptly.
pub const CLOSE_CODE_PATH_DEAD: u32 = 0x1004;

/// Close code for the connection a NAT-rebind reconnect displaces
/// (`docs/design/protocol.md` §11-2's "same-fingerprint replace").
/// Wire-frozen: the value never changes. Local to qsh-core, not a transport
/// concern (`docs/design/architecture.md` §1).
pub const CLOSE_CODE_REPLACED: u32 = 0x1003;

/// Fixed vocabulary for the `cause` field on the `lost`/`retry` (target
/// `ReconnectEvent`) and `lost`/`denied` (controller `RegistrationEvent`)
/// stderr diagnostic lines (`docs/CLI.md` §6.13's `cause` bullet, issue #4
/// item 6). Exactly these nine — never an address, token, or
/// peer-supplied error body (`target::ReconnectEvent`/
/// `listen::RegistrationEvent`'s own `emit` never format one in). Both
/// `Debug`, `PartialEq` for tests to assert the exact classification
/// rather than string-matching `as_str()`'s output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconnectCause {
    /// DNS/resolver error, or the resolver returned no addresses at all
    /// (`ops::resolve_all`). Constructed only from `target::dial_and_register`.
    Resolve,
    /// The dial did not complete within the per-attempt timeout, or the
    /// controller's `Hello` reply after it did not arrive within
    /// `HELLO_TIMEOUT` (issue #11 request 3).
    DialTimeout,
    /// Transport-level refusal or connect error (peer at capacity,
    /// connection refused, unreachable, reset).
    Refused,
    /// Either side rejected the TLS peer — a local pin mismatch/missing
    /// pin, or the peer rejecting ours.
    TlsRejected,
    /// The controller's `host.reverse` ACL/registry choke point refused
    /// the registration.
    RegistrationDenied,
    /// The peer closed an already-established connection, or answered it with
    /// a stateless reset because it no longer holds it.
    PeerClosed,
    /// `PathWatch` declared the path dead on this side, or the peer closed
    /// the connection with [`CLOSE_CODE_PATH_DEAD`] because its own
    /// `PathWatch` did.
    PathDead,
    /// The QUIC idle timeout (`ConnectionError::TimedOut`) expired on an
    /// established connection. Distinct from [`Self::PathDead`]: no
    /// `PathWatch` verdict and no path-dead close frame was involved.
    IdleTimeout,
    /// Anything originating on this side, or ending in a way no other value
    /// names. Never a timeout: those are [`Self::DialTimeout`],
    /// [`Self::IdleTimeout`] and [`Self::PathDead`]. `docs/CLI.md` §6.13
    /// lists every code path that produces it.
    Local,
}

impl ReconnectCause {
    /// Every variant, for the documentation cross-check in this module's
    /// tests. Test-only: no production code enumerates the vocabulary, so
    /// a non-test definition would be dead code on the Windows lib build.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 9] = [
        Self::Resolve,
        Self::DialTimeout,
        Self::Refused,
        Self::TlsRejected,
        Self::RegistrationDenied,
        Self::PeerClosed,
        Self::PathDead,
        Self::IdleTimeout,
        Self::Local,
    ];

    /// The exact static string emitted on the `qsh::reverse` stderr
    /// diagnostic line (never derived from
    /// `Debug` — this is the frozen vocabulary, `Debug`'s spelling is free
    /// to drift with the variant names).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::DialTimeout => "dial_timeout",
            Self::Refused => "refused",
            Self::TlsRejected => "tls_rejected",
            Self::RegistrationDenied => "registration_denied",
            Self::PeerClosed => "peer_closed",
            Self::PathDead => "path_dead",
            Self::IdleTimeout => "idle_timeout",
            Self::Local => "local",
        }
    }
}

/// Classify a QUIC connection's death into [`ReconnectCause`]'s
/// `peer_closed`/`path_dead`/`idle_timeout`/`local` slice — the part of the
/// vocabulary that applies once a connection was already established
/// (dial-time failures go through `target`'s own `classify_dial_error`/
/// `classify_hello_error` instead, which report `resolve`/`dial_timeout`/
/// `refused`/`tls_rejected`/`registration_denied`). `ApplicationClosed`
/// carries the close code the peer sent: when it is
/// [`CLOSE_CODE_PATH_DEAD`], the peer's own watchdog condemned the path
/// before this side's did (the common asymmetric-loss/mobility case, the
/// whole reason `PathWatch` exists), and that is `path_dead`, not a
/// "clean, intentional end" `peer_closed` would otherwise imply; any other
/// code is a real clean close. `TimedOut` is quinn's idle-timeout expiry
/// on an otherwise-silent path. It is `idle_timeout`, not `path_dead`
/// (ADR-0022 결정 5·6): no `PathWatch` verdict and no path-dead close frame
/// was involved, and on a live reverse path `PathWatch` declares death
/// long before the 45 s idle timeout can expire, so the two causes tell an
/// operator different things. `Reset` — a stateless reset, which only the
/// peer's endpoint can send, for a connection it no longer holds — is
/// `peer_closed` (issue #11 request 3: it used to fall to `local`, which
/// read as a local decision when it was the peer dropping the connection,
/// usually after its own `path_dead` close frame did not get through).
/// Everything else — `LocallyClosed` (this side closed it, so `local` by
/// definition), `ConnectionClosed`, `VersionMismatch`, `TransportError`,
/// `CidsExhausted` — has no sharper bucket in this fixed nine-value
/// vocabulary, so it falls to `local` as the catch-all "nothing
/// peer-initiated or PathWatch-judged about this" bucket. `docs/CLI.md`
/// §6.13 lists every code path that ends there.
pub(crate) fn classify_connection_error(err: &qsh_transport::ConnectionError) -> ReconnectCause {
    if err.application_code() == Some(CLOSE_CODE_PATH_DEAD) {
        ReconnectCause::PathDead
    } else if err.is_application_closed() {
        ReconnectCause::PeerClosed
    } else if err.is_peer_reset() {
        // A stateless reset is a packet only the peer's endpoint can send,
        // and it answers a connection the peer no longer has: typically one
        // it already condemned (its own `path_dead` close was lost on the
        // way, or it restarted). Nothing about it originates here.
        ReconnectCause::PeerClosed
    } else if err.is_idle_timeout() {
        ReconnectCause::IdleTimeout
    } else {
        ReconnectCause::Local
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application_closed(code: u32) -> qsh_transport::ConnectionError {
        qsh_transport::ConnectionError::ApplicationClosed(qsh_transport::ApplicationClose {
            error_code: qsh_transport::StreamCode::from_u32(code),
            reason: bytes::Bytes::new(),
        })
    }

    /// The three-way split of an established connection's death
    /// (ADR-0022 결정 5·6): quinn's idle timeout, the path-dead close code,
    /// and every other application close.
    #[test]
    fn classify_connection_error_separates_idle_timeout_from_path_dead_and_peer_closed() {
        assert_eq!(
            classify_connection_error(&qsh_transport::ConnectionError::TimedOut),
            ReconnectCause::IdleTimeout
        );
        assert_eq!(
            classify_connection_error(&application_closed(CLOSE_CODE_PATH_DEAD)),
            ReconnectCause::PathDead
        );
        assert_eq!(
            classify_connection_error(&application_closed(0)),
            ReconnectCause::PeerClosed
        );
        assert_eq!(
            classify_connection_error(&qsh_transport::ConnectionError::LocallyClosed),
            ReconnectCause::Local
        );
    }

    /// Issue #11 request 3: a stateless reset is the peer dropping a
    /// connection, not a local decision. What stays `local` is what this
    /// side closed itself or what the transport reports about a peer that
    /// broke the protocol.
    #[test]
    fn classify_connection_error_reads_a_stateless_reset_as_the_peer_dropping_the_connection() {
        assert_eq!(
            classify_connection_error(&qsh_transport::ConnectionError::Reset),
            ReconnectCause::PeerClosed
        );
        assert_eq!(
            classify_connection_error(&qsh_transport::ConnectionError::CidsExhausted),
            ReconnectCause::Local
        );
        assert_eq!(
            classify_connection_error(&qsh_transport::ConnectionError::VersionMismatch),
            ReconnectCause::Local
        );
    }

    /// The `cause` value list in `docs/CLI.md` §6.13 and
    /// [`ReconnectCause::ALL`] name the same set, in both directions.
    #[test]
    fn reconnect_cause_vocabulary_matches_cli_md_section_6_13() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CLI.md");
        let cli_md = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let bullet = cli_md
            .lines()
            .find(|line| line.contains("`cause` 필드(고정 "))
            .expect("§6.13 must carry the `cause` field bullet");
        let start = bullet.find("`cause` 필드(").expect("marker") + "`cause` 필드(".len();
        let list = &bullet[start..];
        // The value list runs up to and including the last value, `local`.
        let list = &list[..list.find("`local`").expect("end of the value list") + "`local`".len()];
        let documented: std::collections::BTreeSet<&str> = list
            .split('`')
            .enumerate()
            .filter_map(|(i, part)| (i % 2 == 1).then_some(part))
            .collect();
        let coded: std::collections::BTreeSet<&str> =
            ReconnectCause::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(coded.len(), ReconnectCause::ALL.len(), "duplicate as_str");
        assert_eq!(
            documented, coded,
            "docs/CLI.md §6.13's `cause` list and ReconnectCause::ALL must name the same values"
        );
        assert!(
            list.starts_with(&format!("고정 {}값", coded.len())),
            "the documented count must match: {list}"
        );
    }
}
