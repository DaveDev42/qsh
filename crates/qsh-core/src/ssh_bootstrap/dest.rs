//! The `<dest>` operand of `qsh pair ssh` and the `qsh [user@]host` shape
//! (ADR-0044 decision 7).
//!
//! `<dest>` is the user's own text. It is passed to `ssh` verbatim, after
//! `--`, so `~/.ssh/config` aliases and `Match` blocks apply as ssh
//! evaluates them. The only parts qsh derives from it are the host half
//! (the default pin name) and the user half (a hint, never stored,
//! decision 26).
//!
//! Two checks live apart on purpose. [`Dest::parse`] vets the ssh operand;
//! [`Dest::pin_name`] vets the name this machine pins the remote under.
//! A `Host` alias ssh accepts can break the pin-name rule (`web/prod`), and
//! `--as` must then be able to stand in for it.

use qsh_proto::ErrorCode;

use crate::ops::{OpError, validate_peer_label_arg};

/// Split a `[user@]host` operand at the last `@`, like ssh: an alias may not
/// contain one, but a user name conceivably does. The same rule backs the
/// `qsh [user@]host` positional (`docs/CLI.md` §7), so the interactive form
/// and the bootstrap read one text the same way.
///
/// The error is a fixed message that never repeats the whole operand more
/// than the caller already holds.
pub fn split_user_host(value: &str) -> Result<(Option<&str>, &str), String> {
    let (user, host) = match value.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, value),
    };
    if host.is_empty() {
        return Err(format!("expected [user@]host, got {value:?}"));
    }
    if user.is_some_and(str::is_empty) {
        return Err(format!("empty user in {value:?}"));
    }
    Ok((user, host))
}

/// A validated ssh destination.
///
/// Built only by [`Dest::parse`], so holding one means ssh can be called
/// with [`Dest::as_ssh_arg`] without the operand being read as an option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dest {
    raw: String,
    user: Option<String>,
    host: String,
}

impl Dest {
    /// Validate `raw` as an ssh operand before any ssh process exists
    /// (ADR-0044 decision 7).
    ///
    /// - A leading `-` would let ssh read the operand as an option, so it is
    ///   `INVALID_ARGUMENT`. (The `--` the argument builder puts in front of
    ///   it is the second line of defence, not the first.)
    /// - `ssh://` URIs are not accepted.
    /// - Whitespace and control characters are refused: no ssh destination
    ///   contains them, and they would only reach a log or a terminal.
    ///
    /// Whether the host half is usable as a pin name is a separate question
    /// ([`Self::pin_name`]): a `Host` alias with a `/` is a fine ssh operand.
    ///
    /// Errors never echo the operand beyond the fixed reason.
    pub fn parse(raw: &str) -> Result<Self, OpError> {
        if raw.starts_with('-') {
            return Err(invalid(
                "the destination must not start with '-' (it would be read as an ssh option)",
            ));
        }
        if raw.starts_with("ssh://") {
            return Err(invalid(
                "ssh:// URIs are not accepted; give [user@]host as ssh_config knows it",
            ));
        }
        if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(invalid(
                "the destination must not contain whitespace or control characters",
            ));
        }
        let (user, host) = split_user_host(raw).map_err(|_| {
            invalid("the destination must be [user@]host with a non-empty host and user")
        })?;
        Ok(Self {
            raw: raw.to_string(),
            user: user.map(str::to_string),
            host: host.to_string(),
        })
    }

    /// The operand exactly as the user typed it: what ssh receives.
    pub fn as_ssh_arg(&self) -> &str {
        &self.raw
    }

    /// The `user@` half, if given. Only a hint; qsh stores it nowhere
    /// (ADR-0044 decision 26).
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The host half: the ssh `Host` alias as typed, not the `HostName` ssh
    /// resolves.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The name this machine pins the remote under (ADR-0044 decision 7):
    /// `as_name` (`--as`) when given, otherwise the host half, so the next
    /// `qsh <host>` finds the pin under the name the user types.
    ///
    /// Either one must pass the one pin-name rule (`validate_peer_label` and
    /// no `/`, `docs/CLI.md` §6.11). The error is `INVALID_ARGUMENT` and
    /// names the rule, never the value.
    pub fn pin_name(&self, as_name: Option<&str>) -> Result<String, OpError> {
        match as_name {
            Some(name) => validate_peer_label_arg(name),
            None => validate_peer_label_arg(&self.host).map_err(|err| {
                invalid(format!(
                    "the host part of the destination is not a valid pin name ({}); \
                     name the pin with --as",
                    err.message
                ))
            }),
        }
    }
}

fn invalid(message: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}
