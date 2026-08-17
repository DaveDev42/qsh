//! Wire/CLI shared error vocabulary.
//!
//! [`ErrorCode`] is the single vocabulary shared by the wire protocol, the
//! `qsh.cli/v1` JSON envelope and the MCP adapter (see `docs/CLI.md` §3.3).
//! It is intentionally *not* `#[non_exhaustive]` in the Rust sense of that
//! attribute (matching on it exhaustively is fine and desired for the known
//! codes), but the wire format itself is open: a newer peer may send a code
//! this build does not know about yet.
//!
//! ## Unknown-code passthrough policy
//!
//! `ErrorCode` carries an [`ErrorCode::Unknown`] variant that holds the raw
//! string. Serialization/deserialization is implemented by hand (not
//! `#[derive(Serialize, Deserialize)]`) so that:
//!
//! - a known code round-trips to its `SCREAMING_SNAKE_CASE` string, and
//! - any string that does not match a known code deserializes into
//!   `Unknown(<that string>)` and serializes right back out unchanged.
//!
//! This means older builds never hard-fail on a new error code introduced by
//! a newer peer (matches the CLI.md compatibility rule: "알 수 없는 code는
//! 일반 QSH 오류로 처리한다").

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The shared error vocabulary used by the wire protocol and the CLI JSON
/// envelope.
///
/// Sixteen known codes, plus [`ErrorCode::Unknown`] for forward
/// compatibility (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Caller-supplied argument was malformed or out of range.
    InvalidArgument,
    /// Local configuration is missing or invalid.
    ConfigError,
    /// Named host is not known to this client.
    HostNotFound,
    /// Transport-level connection attempt failed.
    ConnectionFailed,
    /// Peer authentication failed.
    AuthFailed,
    /// Peer is not yet trusted; pairing is required first.
    TrustRequired,
    /// Peer authenticated but is not authorized for the requested action.
    PermissionDenied,
    /// Referenced session does not exist (anymore).
    SessionNotFound,
    /// A conflicting session state prevents the requested action.
    SessionConflict,
    /// Requested replay range is no longer available (ring overflow).
    ResumeGap,
    /// Operation exceeded its deadline.
    Timeout,
    /// Operation was canceled by the caller.
    Canceled,
    /// The remote side reported an error executing the request.
    RemoteError,
    /// The requested feature is not supported by this build/peer.
    Unsupported,
    /// A resource limit (backpressure, quota) was hit.
    ResourceExhausted,
    /// Unclassified internal error.
    Internal,
    /// A code this build does not recognize yet. Carries the raw wire
    /// string verbatim so it can be displayed and round-tripped without
    /// data loss. See module docs for the passthrough policy.
    Unknown(String),
}

impl ErrorCode {
    /// All known (non-[`Unknown`](ErrorCode::Unknown)) codes, in declaration
    /// order. Useful for exhaustiveness tests.
    pub const KNOWN: &'static [ErrorCode] = &[
        ErrorCode::InvalidArgument,
        ErrorCode::ConfigError,
        ErrorCode::HostNotFound,
        ErrorCode::ConnectionFailed,
        ErrorCode::AuthFailed,
        ErrorCode::TrustRequired,
        ErrorCode::PermissionDenied,
        ErrorCode::SessionNotFound,
        ErrorCode::SessionConflict,
        ErrorCode::ResumeGap,
        ErrorCode::Timeout,
        ErrorCode::Canceled,
        ErrorCode::RemoteError,
        ErrorCode::Unsupported,
        ErrorCode::ResourceExhausted,
        ErrorCode::Internal,
    ];

    /// The `SCREAMING_SNAKE_CASE` wire representation of this code.
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::ConfigError => "CONFIG_ERROR",
            ErrorCode::HostNotFound => "HOST_NOT_FOUND",
            ErrorCode::ConnectionFailed => "CONNECTION_FAILED",
            ErrorCode::AuthFailed => "AUTH_FAILED",
            ErrorCode::TrustRequired => "TRUST_REQUIRED",
            ErrorCode::PermissionDenied => "PERMISSION_DENIED",
            ErrorCode::SessionNotFound => "SESSION_NOT_FOUND",
            ErrorCode::SessionConflict => "SESSION_CONFLICT",
            ErrorCode::ResumeGap => "RESUME_GAP",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::Canceled => "CANCELED",
            ErrorCode::RemoteError => "REMOTE_ERROR",
            ErrorCode::Unsupported => "UNSUPPORTED",
            ErrorCode::ResourceExhausted => "RESOURCE_EXHAUSTED",
            ErrorCode::Internal => "INTERNAL",
            ErrorCode::Unknown(raw) => raw.as_str(),
        }
    }

    /// The default retry policy for this code, used when a caller has no
    /// more specific guidance. Codes that describe a plausibly-transient
    /// condition (connection, timing, backpressure, resume) default to
    /// `true`; everything else (including [`Unknown`](ErrorCode::Unknown),
    /// since we cannot reason about a code we don't recognize) defaults to
    /// `false`.
    pub fn default_retryable(&self) -> bool {
        matches!(
            self,
            ErrorCode::ConnectionFailed
                | ErrorCode::ResumeGap
                | ErrorCode::Timeout
                | ErrorCode::ResourceExhausted
        )
    }
}

impl schemars::JsonSchema for ErrorCode {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ErrorCode".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // Deliberately an open string, not a closed enum: the wire and the
        // envelope are forward-compatible with codes this build does not
        // know (module docs). `examples` lists the codes this build knows.
        let known: Vec<serde_json::Value> = ErrorCode::KNOWN
            .iter()
            .map(|c| serde_json::Value::String(c.as_str().to_string()))
            .collect();
        schemars::json_schema!({
            "type": "string",
            "description": "QSH error code (`SCREAMING_SNAKE_CASE`). Unknown codes are passed through.",
            "pattern": "^[A-Z][A-Z0-9_]*$",
            "examples": known,
        })
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ErrorCode {
    /// Parsing an [`ErrorCode`] from a wire string never fails: unrecognized
    /// strings become [`ErrorCode::Unknown`] (see module docs).
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
            "CONFIG_ERROR" => ErrorCode::ConfigError,
            "HOST_NOT_FOUND" => ErrorCode::HostNotFound,
            "CONNECTION_FAILED" => ErrorCode::ConnectionFailed,
            "AUTH_FAILED" => ErrorCode::AuthFailed,
            "TRUST_REQUIRED" => ErrorCode::TrustRequired,
            "PERMISSION_DENIED" => ErrorCode::PermissionDenied,
            "SESSION_NOT_FOUND" => ErrorCode::SessionNotFound,
            "SESSION_CONFLICT" => ErrorCode::SessionConflict,
            "RESUME_GAP" => ErrorCode::ResumeGap,
            "TIMEOUT" => ErrorCode::Timeout,
            "CANCELED" => ErrorCode::Canceled,
            "REMOTE_ERROR" => ErrorCode::RemoteError,
            "UNSUPPORTED" => ErrorCode::Unsupported,
            "RESOURCE_EXHAUSTED" => ErrorCode::ResourceExhausted,
            "INTERNAL" => ErrorCode::Internal,
            other => ErrorCode::Unknown(other.to_string()),
        })
    }
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        // FromStr::Err is Infallible, so this can never actually fail; the
        // `match {}` on the uninhabited error type proves it without a
        // runtime panic path.
        match raw.parse::<ErrorCode>() {
            Ok(code) => Ok(code),
            Err(never) => match never {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_round_trip_through_str() {
        for code in ErrorCode::KNOWN {
            let s = code.as_str();
            let parsed: ErrorCode = s.parse().unwrap();
            assert_eq!(&parsed, code, "round trip mismatch for {s}");
        }
    }

    #[test]
    fn known_codes_round_trip_through_json() {
        for code in ErrorCode::KNOWN {
            let json = serde_json::to_string(code).unwrap();
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, code);
        }
    }

    #[test]
    fn unknown_code_round_trips_verbatim() {
        let json = "\"SOME_FUTURE_CODE\"";
        let parsed: ErrorCode = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, ErrorCode::Unknown("SOME_FUTURE_CODE".to_string()));
        let out = serde_json::to_string(&parsed).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn as_str_matches_screaming_snake_case() {
        assert_eq!(ErrorCode::InvalidArgument.as_str(), "INVALID_ARGUMENT");
        assert_eq!(ErrorCode::ResourceExhausted.as_str(), "RESOURCE_EXHAUSTED");
        assert_eq!(ErrorCode::Unsupported.as_str(), "UNSUPPORTED");
    }

    #[test]
    fn default_retryable_policy() {
        assert!(ErrorCode::ConnectionFailed.default_retryable());
        assert!(ErrorCode::Timeout.default_retryable());
        assert!(ErrorCode::ResumeGap.default_retryable());
        assert!(ErrorCode::ResourceExhausted.default_retryable());
        assert!(!ErrorCode::PermissionDenied.default_retryable());
        assert!(!ErrorCode::Unknown("X".to_string()).default_retryable());
    }
}
