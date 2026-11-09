//! How a failed jump chain is reported (ADR-0056 decision 12,
//! `docs/CLI.md` §3.2 `details.jump`).
//!
//! The client writes the report: it knows which step it asked for, while an
//! intermediate peer's refusal stays the uniform one. A report names the
//! step that could not be set up with `{hop, hops, name, stage}`.
//!
//! * `hops` is the number of intermediate peers plus the end target.
//! * `hop` counts from 1 and is the connection that was being set up: the
//!   first peer for `dial`, the second for a refusal by the first peer to
//!   open the second one, and `hops` for the end target. `name` is that
//!   step's pin name.
//! * `stage` is a closed vocabulary and fixes the error code, except for
//!   `dial`, which keeps the code the ordinary route produced.
//!
//! The human line starts with `jump 2/3 (b): `, and the message is the only
//! place the prefix goes; `details` carries the fields.

use qsh_proto::ErrorCode;
use serde_json::{Value, json};

use crate::ops::OpError;

/// The `stage` word of a failed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The pin is missing or has no address.
    Address,
    /// The first peer could not be reached.
    Dial,
    /// The previous peer does not advertise `jump.v1`.
    Unsupported,
    /// The previous peer refused (`forward.jump` or a host-local target).
    Denied,
    /// The previous peer could not resolve the name.
    Resolve,
    /// The previous peer is at one of its bounds.
    Limit,
    /// The previous peer's socket got an ICMP refusal or the channel died.
    Unreachable,
    /// The previous peer passed the packets and nobody answered in time.
    Handshake,
    /// The peer's fingerprint is not the pin's.
    Auth,
}

impl Stage {
    /// Every stage, in the order of the vocabulary.
    pub const ALL: [Stage; 9] = [
        Stage::Address,
        Stage::Dial,
        Stage::Unsupported,
        Stage::Denied,
        Stage::Resolve,
        Stage::Limit,
        Stage::Unreachable,
        Stage::Handshake,
        Stage::Auth,
    ];

    /// The word in `details.jump.stage`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Dial => "dial",
            Self::Unsupported => "unsupported",
            Self::Denied => "denied",
            Self::Resolve => "resolve",
            Self::Limit => "limit",
            Self::Unreachable => "unreachable",
            Self::Handshake => "handshake",
            Self::Auth => "auth",
        }
    }

    /// The error code this stage fixes. `None` for `dial`, which keeps the
    /// code of the route's own error.
    pub fn code(self) -> Option<ErrorCode> {
        match self {
            Self::Address => Some(ErrorCode::HostNotFound),
            Self::Dial => None,
            Self::Unsupported => Some(ErrorCode::Unsupported),
            Self::Denied => Some(ErrorCode::PermissionDenied),
            Self::Resolve | Self::Unreachable => Some(ErrorCode::ConnectionFailed),
            Self::Limit => Some(ErrorCode::ResourceExhausted),
            Self::Handshake => Some(ErrorCode::Timeout),
            Self::Auth => Some(ErrorCode::AuthFailed),
        }
    }
}

/// Which step failed and why: the content of `details.jump`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpFailure {
    /// 1-based position of the step that failed.
    pub hop: usize,
    /// Intermediate peers plus the end target.
    pub hops: usize,
    /// The pin name of that step.
    pub name: String,
    /// What failed.
    pub stage: Stage,
}

impl JumpFailure {
    /// The `details.jump` object.
    pub fn to_json(&self) -> Value {
        json!({
            "hop": self.hop,
            "hops": self.hops,
            "name": self.name,
            "stage": self.stage.as_str(),
        })
    }

    /// The prefix of the human line.
    pub fn prefix(&self) -> String {
        format!("jump {}/{} ({}): ", self.hop, self.hops, self.name)
    }

    /// The error for this failure. The code is the stage's; `dial` takes
    /// `route`, the ordinary route's error, as it is and only adds the
    /// report. `message` is the plain explanation (no prefix).
    pub fn into_op(self, message: impl Into<String>, route: Option<OpError>) -> OpError {
        let mut op = match (self.stage.code(), route) {
            (None, Some(route)) => route,
            (None, None) => OpError::new(ErrorCode::ConnectionFailed, message.into()),
            (Some(code), route) => {
                let retryable = match &code {
                    ErrorCode::AuthFailed
                    | ErrorCode::PermissionDenied
                    | ErrorCode::HostNotFound
                    | ErrorCode::Unsupported => false,
                    other => other.default_retryable(),
                };
                let mut op = OpError::new(code, message.into()).with_retryable(retryable);
                // What the route said besides the message (an auth
                // category, a punch) stays.
                if let Some(route) = route {
                    op.details = route.details;
                }
                op
            }
        };
        op.message = format!("{}{}", self.prefix(), op.message);
        match &mut op.details {
            Value::Object(map) => {
                map.insert("jump".to_string(), self.to_json());
            }
            slot => {
                *slot = json!({ "jump": self.to_json() });
            }
        }
        op
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stage_has_the_code_the_adr_fixes() {
        let table = [
            (Stage::Address, Some(ErrorCode::HostNotFound)),
            (Stage::Dial, None),
            (Stage::Unsupported, Some(ErrorCode::Unsupported)),
            (Stage::Denied, Some(ErrorCode::PermissionDenied)),
            (Stage::Resolve, Some(ErrorCode::ConnectionFailed)),
            (Stage::Limit, Some(ErrorCode::ResourceExhausted)),
            (Stage::Unreachable, Some(ErrorCode::ConnectionFailed)),
            (Stage::Handshake, Some(ErrorCode::Timeout)),
            (Stage::Auth, Some(ErrorCode::AuthFailed)),
        ];
        assert_eq!(table.len(), Stage::ALL.len());
        for (stage, code) in table {
            assert_eq!(stage.code(), code, "{}", stage.as_str());
        }
    }

    #[test]
    fn the_report_is_additive_and_prefixes_the_message() {
        let failure = JumpFailure {
            hop: 2,
            hops: 3,
            name: "b".into(),
            stage: Stage::Auth,
        };
        let op = failure.into_op("peer authentication failed", None);
        assert_eq!(op.code, ErrorCode::AuthFailed);
        assert!(!op.retryable);
        assert_eq!(op.message, "jump 2/3 (b): peer authentication failed");
        assert_eq!(
            op.details["jump"],
            json!({"hop": 2, "hops": 3, "name": "b", "stage": "auth"})
        );
    }

    #[test]
    fn dial_keeps_the_routes_code_and_other_details() {
        let route = OpError::new(ErrorCode::Timeout, "no response")
            .with_details(json!({"punch": {"rendezvous": "home", "reason": "timeout"}}));
        let failure = JumpFailure {
            hop: 1,
            hops: 2,
            name: "a".into(),
            stage: Stage::Dial,
        };
        let op = failure.into_op("unused", Some(route));
        assert_eq!(op.code, ErrorCode::Timeout);
        assert_eq!(op.details["punch"]["reason"], "timeout");
        assert_eq!(op.details["jump"]["stage"], "dial");
    }
}
