//! The typed operation layer: the single API surface the CLI, `--json`
//! renderer and (from M6) the MCP adapter all call through. See
//! `docs/CLI.md` §11 — frontends must not reimplement business logic, they
//! only translate an [`Ops`] call into their own presentation.

use qsh_proto::{ErrorCode, VersionData};

/// Marker trait for a single typed operation.
///
/// `COMMAND` is the dotted-form command name used as the `command` field in
/// the `qsh.cli/v1` envelope and as the audit/ACL join key (e.g.
/// `"version.get"`, `"session.open"`).
pub trait Operation {
    /// Dotted-form command name, e.g. `"version.get"`.
    const COMMAND: &'static str;
}

/// Error type returned by every operation. Carries everything the
/// `qsh.cli/v1` error envelope needs (`docs/CLI.md` §3.2) plus a structured
/// `details` payload for automation.
#[derive(Debug, Clone, PartialEq)]
pub struct OpError {
    /// Shared error vocabulary code.
    pub code: ErrorCode,
    /// Human-readable explanation. Automation must not parse this.
    pub message: String,
    /// Whether retrying the same request might succeed.
    pub retryable: bool,
    /// Structured, machine-readable detail payload. `Value::Null` when
    /// there is nothing to add beyond `code`/`message`.
    pub details: serde_json::Value,
}

impl OpError {
    /// Construct an [`OpError`] with `retryable` defaulted from
    /// [`ErrorCode::default_retryable`] and empty `details`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let retryable = code.default_retryable();
        Self {
            code,
            message: message.into(),
            retryable,
            details: serde_json::Value::Null,
        }
    }

    /// Override the default retryability.
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Attach a structured `details` payload.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl From<ErrorCode> for OpError {
    /// Build an [`OpError`] whose message is just the code's own display
    /// string. Callers that have a better message should use
    /// [`OpError::new`] instead; this exists for quick propagation of a
    /// bare code (e.g. from a lower layer that only has the code).
    fn from(code: ErrorCode) -> Self {
        let message = code.to_string();
        OpError::new(code, message)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for OpError {}

/// The `version.get` operation.
pub struct VersionOp;

impl Operation for VersionOp {
    const COMMAND: &'static str = "version.get";
}

/// Façade over every typed operation. This is the *only* entry point
/// frontends (`qsh-cli`'s human/JSON renderers, and later the MCP adapter)
/// are allowed to call into `qsh-core` through.
pub struct Ops;

impl Ops {
    /// Report this build's version and the wire/CLI schemas it understands.
    pub fn version() -> Result<VersionData, OpError> {
        Ok(VersionData {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_reports_schemas_and_own_version() {
        let data = Ops::version().unwrap();
        assert_eq!(data.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(data.schemas, vec!["qsh.cli/v1", "qsh.event/v1"]);
    }

    #[test]
    fn op_error_from_code_defaults_retryable() {
        let err = OpError::from(ErrorCode::Timeout);
        assert!(err.retryable);
        assert_eq!(err.code, ErrorCode::Timeout);
    }

    #[test]
    fn version_op_command_is_dotted_form() {
        assert_eq!(VersionOp::COMMAND, "version.get");
    }
}
