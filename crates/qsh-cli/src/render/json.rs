//! Owns the `qsh.cli/v1` envelope shape (`docs/CLI.md` §3). This is the
//! *only* place that envelope struct is defined; every JSON-mode command
//! must go through [`Envelope::success`]/[`Envelope::failure`].

use std::io::{self, Write};

use qsh_core::OpError;
use serde::Serialize;

/// The `schema` value stamped on every envelope.
pub const CLI_SCHEMA: &str = "qsh.cli/v1";

/// The `error` object of a failed envelope (`docs/CLI.md` §3.2).
#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub details: serde_json::Value,
}

/// The full `qsh.cli/v1` response envelope.
#[derive(Debug, Serialize)]
pub struct Envelope {
    pub schema: &'static str,
    pub request_id: String,
    pub command: &'static str,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

impl Envelope {
    /// Build a success envelope. `command` must be the dotted-form command
    /// name (e.g. `"version.get"`, see [`qsh_core::Operation::COMMAND`]).
    pub fn success(command: &'static str, data: serde_json::Value) -> Self {
        Self {
            schema: CLI_SCHEMA,
            request_id: ulid::Ulid::new().to_string(),
            command,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// Build a failure envelope from an [`OpError`].
    pub fn failure(command: &'static str, err: &OpError) -> Self {
        Self {
            schema: CLI_SCHEMA,
            request_id: ulid::Ulid::new().to_string(),
            command,
            ok: false,
            data: None,
            error: Some(ErrorPayload {
                code: err.code.as_str().to_string(),
                message: err.message.clone(),
                retryable: err.retryable,
                details: err.details.clone(),
            }),
        }
    }

    /// Serialize as a single JSON line and write it to stdout, per
    /// `docs/CLI.md` §2.2: results only on stdout, one line per response.
    pub fn print(&self) -> io::Result<()> {
        let line = serde_json::to_string(self).map_err(io::Error::other)?;
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{line}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_proto::ErrorCode;

    #[test]
    fn success_envelope_omits_error_field() {
        let env = Envelope::success("version.get", serde_json::json!({"version": "0.1.0"}));
        let value = serde_json::to_value(&env).unwrap();
        assert_eq!(value["schema"], "qsh.cli/v1");
        assert_eq!(value["command"], "version.get");
        assert_eq!(value["ok"], true);
        assert!(value.get("error").is_none());
        assert!(value["request_id"].as_str().is_some());
    }

    #[test]
    fn failure_envelope_omits_data_field() {
        let err = OpError::new(ErrorCode::Internal, "boom");
        let env = Envelope::failure("version.get", &err);
        let value = serde_json::to_value(&env).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "INTERNAL");
        assert!(value.get("data").is_none());
    }
}
