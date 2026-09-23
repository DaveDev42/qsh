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

/// Fixed vocabulary for the `cause` field on the `lost`/`retry` (target
/// `ReconnectEvent`) and `lost`/`denied` (controller `RegistrationEvent`)
/// stderr diagnostic lines (`docs/CLI.md` §6.13 bullet at :952, issue #4
/// item 6). Exactly these eight — never an address, token, or
/// peer-supplied error body (`target::ReconnectEvent`/
/// `listen::RegistrationEvent`'s own `emit` never format one in). Both
/// `Debug`, `PartialEq` for tests to assert the exact classification
/// rather than string-matching `as_str()`'s output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconnectCause {
    /// DNS/resolver error, or the resolver returned no addresses at all
    /// (`ops::resolve_one`). Constructed only from `target::dial_and_register`
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
    /// `PathWatch` declared the path dead, or the QUIC idle timeout fired
    /// on an established connection.
    PathDead,
    /// Anything originating on this side: a shutdown signal, or a local
    /// I/O error.
    Local,
}

impl ReconnectCause {
    /// The exact static string emitted on the wire (never derived from
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
/// `peer_closed`/`path_dead`/`local` slice — the part of the vocabulary
/// that applies once a connection was already established (dial-time
/// failures go through `target`'s own `classify_dial_error`/
/// `classify_hello_error` instead, which report `resolve`/`dial_timeout`/
/// `refused`/`tls_rejected`/`registration_denied`). `ApplicationClosed`
/// carries the close code the peer sent: when it is
/// [`CLOSE_CODE_PATH_DEAD`], the peer's own watchdog condemned the path
/// before this side's did (the common asymmetric-loss/mobility case, the
/// whole reason `PathWatch` exists), and that is `path_dead`, not a
/// "clean, intentional end" `peer_closed` would otherwise imply; any other
/// code is a real clean close. `TimedOut` is quinn's idle-timeout
/// judgment on an otherwise-silent path, the same condition `PathWatch`
/// exists to detect sooner, so it gets the same `path_dead` cause.
/// Everything else — `LocallyClosed` (this side closed it, so `local` by
/// definition), `ConnectionClosed`, `Reset`, `VersionMismatch`,
/// `TransportError`, `CidsExhausted` — has no sharper bucket in this
/// fixed eight-value vocabulary, so it falls to `local` as the catch-all
/// "nothing peer-initiated or PathWatch-judged about this" bucket.
pub(crate) fn classify_connection_error(err: &qsh_transport::ConnectionError) -> ReconnectCause {
    use qsh_transport::ConnectionError;
    match err {
        ConnectionError::ApplicationClosed(close)
            if u64::from(close.error_code) == u64::from(CLOSE_CODE_PATH_DEAD) =>
        {
            ReconnectCause::PathDead
        }
        ConnectionError::ApplicationClosed(_) => ReconnectCause::PeerClosed,
        ConnectionError::TimedOut => ReconnectCause::PathDead,
        _ => ReconnectCause::Local,
    }
}
