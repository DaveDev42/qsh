//! Reverse mode (`docs/design/protocol.md` §11, `docs/CLI.md` §6.13):
//! `qsh listen` (controller) accepts dial-in registrations from `qsh
//! reverse` (target) and serves them as hosts.
//!
//! `PLAN.md` Step 3 lands in two PRs. **PR 3a**: [`registry`] (the
//! transport-free metadata table and name-resolution logic) and [`admit`]
//! (the `host.reverse` authorization choke point that bridges it to
//! `qsh_transport`'s typed `Principal`/`AuthPath`/`Authorizer`), factored so
//! both can be unit-tested without a transport. **PR 3b**: [`listen`] (`qsh
//! listen`'s `run_listen` — bind, accept, `handshake::respond`, `admit`,
//! the live-connection table) and [`target`] (`qsh reverse`'s `run_reverse`
//! — dial, `handshake::initiate` with `Hello.reverse`, then
//! `Server::serve_control` on the same connection). The CLI surface
//! (`Command::Listen`/`Command::Reverse`) lives in `qsh-cli`, not here.
//!
//! The `registry`/`admit` split exists so that `registry.rs` alone can
//! satisfy the transport-free arch-lint `PLAN.md` Step 5 commits to adding
//! for this exact file (the same six-token `BROKER_DIR`-style ban
//! `xtask/src/arch.rs` already enforces under `broker/`) — see
//! `registry`'s module docs.

pub mod admit;
pub mod listen;
pub mod registry;
pub mod target;

#[cfg(all(test, unix))]
mod test_harness;

/// The [`PathWatchConfig`] the target's registered-session watchdog uses
/// (`target::run_reverse_unix`). Production always gets
/// [`PathWatchConfig::default`]. Under `#[cfg(test)]` only, a test can wrap
/// the target future in [`TEST_PATH_WATCH_CONFIG`]`.scope(..)` to raise the
/// judgment floor (`min_dead_after`) above quinn's 45 s idle timeout, so the
/// idle timeout, not `PathWatch`, is what ends a silent connection. This is
/// compiled out of every non-test build, so it is not the `[recovery]`
/// config surface ADR-0021 결정 4 keeps closed, and it is deliberately not a
/// cargo feature (workspace feature unification could switch it on in the
/// shipped binary).
#[cfg(unix)]
pub(crate) fn path_watch_config() -> crate::client::pathwatch::PathWatchConfig {
    #[cfg(test)]
    if let Ok(config) = TEST_PATH_WATCH_CONFIG.try_with(|config| *config) {
        return config;
    }
    crate::client::pathwatch::PathWatchConfig::default()
}

#[cfg(all(test, unix))]
tokio::task_local! {
    /// Test-only override read by [`path_watch_config`]. A task-local, not
    /// a process global, so it only reaches the future it scopes.
    pub(crate) static TEST_PATH_WATCH_CONFIG: crate::client::pathwatch::PathWatchConfig;
}

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
    /// (`ops::resolve_all`). Constructed only from `target::dial_and_register`
    /// (`#[cfg(any(unix, test))]` — the dial path is unix-only in
    /// production, so this variant is otherwise dead on a non-unix,
    /// non-test build; see the sibling `#[cfg_attr]`s below).
    #[cfg_attr(not(any(unix, test)), allow(dead_code))]
    Resolve,
    /// The dial did not complete within the per-attempt timeout.
    #[cfg_attr(not(any(unix, test)), allow(dead_code))]
    DialTimeout,
    /// Transport-level refusal or connect error (peer at capacity,
    /// connection refused, unreachable, reset).
    #[cfg_attr(not(any(unix, test)), allow(dead_code))]
    Refused,
    /// Either side rejected the TLS peer — a local pin mismatch/missing
    /// pin, or the peer rejecting ours.
    #[cfg_attr(not(any(unix, test)), allow(dead_code))]
    TlsRejected,
    /// The controller's `host.reverse` ACL/registry choke point refused
    /// the registration.
    RegistrationDenied,
    /// The peer closed an already-established connection cleanly.
    PeerClosed,
    /// `PathWatch` declared the path dead on this side, or the peer closed
    /// the connection with [`CLOSE_CODE_PATH_DEAD`] because its own
    /// `PathWatch` did.
    PathDead,
    /// The QUIC idle timeout (`ConnectionError::TimedOut`) expired on an
    /// established connection. Distinct from [`Self::PathDead`]: no
    /// `PathWatch` verdict and no path-dead close frame was involved.
    IdleTimeout,
    /// Anything originating on this side: a shutdown signal, or a local
    /// I/O error.
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

/// Close code both `listen::registration` and `target::run_reverse_unix`
/// send when their own watchdog (`PathWatch`) declares an established
/// connection's path dead (`listen.rs`'s and `target.rs`'s identically-
/// valued, identically-named private consts — duplicated across those two
/// modules rather than shared, for the same "registration semantics, not
/// a transport concern" reason their own doc comments give). Duplicated a
/// third time here, for the same reason: [`classify_connection_error`]
/// needs to recognize the code, not to close a connection with it, so it
/// has no reason to depend on either module's own copy.
const CLOSE_CODE_PATH_DEAD: u32 = 0x1004;

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
/// operator different things. Everything else — `LocallyClosed` (this side
/// closed it, so `local` by definition), `ConnectionClosed`, `Reset`,
/// `VersionMismatch`, `TransportError`, `CidsExhausted` — has no sharper
/// bucket in this fixed nine-value vocabulary, so it falls to `local` as
/// the catch-all "nothing peer-initiated or PathWatch-judged about this"
/// bucket.
pub(crate) fn classify_connection_error(err: &qsh_transport::ConnectionError) -> ReconnectCause {
    use qsh_transport::ConnectionError;
    match err {
        ConnectionError::ApplicationClosed(close)
            if u64::from(close.error_code) == u64::from(CLOSE_CODE_PATH_DEAD) =>
        {
            ReconnectCause::PathDead
        }
        ConnectionError::ApplicationClosed(_) => ReconnectCause::PeerClosed,
        ConnectionError::TimedOut => ReconnectCause::IdleTimeout,
        _ => ReconnectCause::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application_closed(code: u32) -> qsh_transport::ConnectionError {
        qsh_transport::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(code),
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
