//! The value of `-J`, `--jump` and `-o ProxyJump` (ADR-0056 decisions 11, 20
//! and 21).
//!
//! The text is the one ssh takes: a comma-separated list of
//! `[user@]host[:port]`. Read for qsh, each item is a pin name (the host
//! part, with `user@` and `:port` taken off, ADR-0044 decision 7); the whole
//! item is kept as typed because the bootstrap hands it to ssh. `none` turns
//! the jump off for this command.

use qsh_proto::ErrorCode;

use super::dest::Dest;
use crate::ops::{OpError, validate_peer_label_arg};

/// One element of a jump list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpHop {
    /// The element as typed, for an ssh `-J` or a bootstrap of the hop.
    pub dest: String,
    /// The qsh pin name: the host part of `dest`.
    pub name: String,
    /// `dest` without a `:port`: the `[user@]host` operand ssh takes.
    pub ssh_dest: String,
    /// The `:port` of `dest`, which is the hop's sshd port.
    pub port: Option<u16>,
}

/// A parsed jump value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpSpec {
    /// `none`: ignore the pin's `jump` for this command.
    Off,
    /// The hops in order, first hop first.
    Hops(Vec<JumpHop>),
}

impl JumpSpec {
    /// Parse `value`. An empty list or item, a bad destination, a port that
    /// is not a number or an item that cannot be a pin name is
    /// `INVALID_ARGUMENT`; the error names the rule and never repeats the
    /// value.
    pub fn parse(value: &str) -> Result<Self, OpError> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("none") {
            return Ok(Self::Off);
        }
        if value.is_empty() {
            return Err(invalid("a jump list must not be empty"));
        }
        let mut hops = Vec::new();
        for item in value.split(',') {
            if item.is_empty() {
                return Err(invalid("a jump list must not have an empty element"));
            }
            let dest = Dest::parse(item)?;
            let host = dest.host();
            let (name, port) = match host.rsplit_once(':') {
                Some((name, port)) => match port.parse::<u16>() {
                    Ok(p) if p != 0 => (name, Some(p)),
                    _ => {
                        return Err(invalid(
                            "a jump element's :port must be a port number (1-65535)",
                        ));
                    }
                },
                None => (host, None),
            };
            if name.contains([':', '[', ']', '/']) {
                return Err(invalid(
                    "a jump element must be the name of a qsh pin, not an address",
                ));
            }
            let ssh_dest = match dest.user() {
                Some(user) => format!("{user}@{name}"),
                None => name.to_string(),
            };
            let name = validate_peer_label_arg(name).map_err(|err| {
                invalid(format!(
                    "a jump element must be the name of a qsh pin ({})",
                    err.message
                ))
            })?;
            hops.push(JumpHop {
                dest: item.to_string(),
                name,
                ssh_dest,
                port,
            });
        }
        Ok(Self::Hops(hops))
    }

    /// The pin names, in order. Empty for [`Self::Off`].
    pub fn names(&self) -> Vec<String> {
        match self {
            Self::Off => Vec::new(),
            Self::Hops(hops) => hops.iter().map(|h| h.name.clone()).collect(),
        }
    }
}

fn invalid(message: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_the_host_part_without_user_or_port() {
        let spec = JumpSpec::parse("dave@bastion:2222,inner").unwrap();
        assert_eq!(spec.names(), ["bastion", "inner"]);
        let JumpSpec::Hops(hops) = spec else {
            panic!("expected hops");
        };
        assert_eq!(hops[0].dest, "dave@bastion:2222");
    }

    #[test]
    fn none_turns_the_jump_off() {
        assert_eq!(JumpSpec::parse("none").unwrap(), JumpSpec::Off);
        assert_eq!(JumpSpec::parse("NONE").unwrap(), JumpSpec::Off);
        assert!(JumpSpec::Off.names().is_empty());
    }

    #[test]
    fn malformed_lists_are_invalid_argument() {
        for bad in [
            "",
            ",",
            "a,,b",
            "a,",
            "-oProxyCommand=x",
            "ssh://a",
            "a:0",
            "a:x",
            "a b",
            "[::1]:22",
            "a/b",
        ] {
            let err = JumpSpec::parse(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad:?}");
        }
    }
}
