//! The trust role of a pinned peer (ADR-0045 결정 2·3).
//!
//! A `[[peer]]` entry in `trust.toml` may carry an optional `role` key
//! naming one of six fixed roles. The action set each role grants lives in
//! one closed constant, [`crate::acl::ROLE_GRANTS`]; this module only owns
//! the vocabulary. The type is deliberately not called `Role`:
//! `crate::acl::load::Role` already means the process role (`Serve` or
//! `Listen`).

use std::fmt;
use std::str::FromStr;

/// One of the six fixed trust roles (ADR-0045 결정 2). Adding a value or
/// changing what a role grants needs a new ADR; there are no user-defined
/// roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustRole {
    /// Every action a pinned device can be granted except `forward.socks`.
    Full,
    /// Shell, non-interactive exec and sessions; no tunnels, no files.
    Exec,
    /// Local and remote forwards over the principal's own resources.
    Tunnel,
    /// Session listing and output reading only.
    ReadOnly,
    /// Registering as a reverse target on a listener.
    Reverse,
    /// Identity only: no action.
    None,
}

impl TrustRole {
    /// Every role, in the order ADR-0045 결정 2 and `docs/CLI.md` §6.11
    /// list them.
    pub const ALL: [TrustRole; 6] = [
        TrustRole::Full,
        TrustRole::Exec,
        TrustRole::Tunnel,
        TrustRole::ReadOnly,
        TrustRole::Reverse,
        TrustRole::None,
    ];

    /// The role a pin gets when its writing command is given no `--role`
    /// (ADR-0045 결정 8). Pins are undirected, so the split is by whether the
    /// pin carries a dial address: a pin without one lets a device in
    /// (`full`), a pin with one names a peer to dial (`none`).
    pub fn default_for_trust_add(address_given: bool) -> TrustRole {
        if address_given {
            TrustRole::None
        } else {
            TrustRole::Full
        }
    }

    /// The role `qsh pair invite` pins its redeemer with when `--role` is
    /// absent (ADR-0045 결정 8): the invite brings a device in.
    pub const DEFAULT_FOR_INVITE: TrustRole = TrustRole::Full;

    /// The role `qsh pair accept` writes for the responder it pins when
    /// `--role` is absent (ADR-0045 결정 8): a peer to dial.
    pub const DEFAULT_FOR_ACCEPT: TrustRole = TrustRole::None;

    /// The string written to `trust.toml`, the audit log and JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            TrustRole::Full => "full",
            TrustRole::Exec => "exec",
            TrustRole::Tunnel => "tunnel",
            TrustRole::ReadOnly => "read-only",
            TrustRole::Reverse => "reverse",
            TrustRole::None => "none",
        }
    }
}

impl fmt::Display for TrustRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A string that is none of the six role names. Carries the offending text
/// so callers can build their own message; the text is operator-authored
/// (`trust.toml`, a CLI argument), never peer-controlled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown trust role {0:?}: expected one of full, exec, tunnel, read-only, reverse, none")]
pub struct TrustRoleParseError(pub String);

impl FromStr for TrustRole {
    type Err = TrustRoleParseError;

    /// Exact, case-sensitive match against [`TrustRole::ALL`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TrustRole::ALL
            .into_iter()
            .find(|role| role.as_str() == s)
            .ok_or_else(|| TrustRoleParseError(s.to_string()))
    }
}
