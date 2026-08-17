//! Renders the `qsh.cli/v1` envelope (`docs/CLI.md` §3). The envelope
//! *shape* is the contract type [`qsh_proto::CliEnvelope`] — this module
//! only fills it in and writes it out; every JSON-mode command must go
//! through [`Envelope::success`]/[`Envelope::failure`].

use std::io::{self, Write};

use qsh_core::OpError;
use qsh_proto::{CLI_SCHEMA_V1, CliEnvelope, CliError};

/// The `schema` value stamped on every envelope.
pub const CLI_SCHEMA: &str = CLI_SCHEMA_V1;

/// A `qsh.cli/v1` envelope ready to print.
#[derive(Debug)]
pub struct Envelope(pub CliEnvelope);

impl Envelope {
    /// Build a success envelope. `command` must be the dotted-form command
    /// name (e.g. `"version.get"`, see [`qsh_core::Operation::COMMAND`]).
    pub fn success(command: &'static str, data: serde_json::Value) -> Self {
        Self(CliEnvelope {
            schema: CLI_SCHEMA.to_string(),
            request_id: ulid::Ulid::new().to_string(),
            command: command.to_string(),
            ok: true,
            data: Some(data),
            error: None,
        })
    }

    /// Build a failure envelope from an [`OpError`].
    pub fn failure(command: &'static str, err: &OpError) -> Self {
        Self(CliEnvelope {
            schema: CLI_SCHEMA.to_string(),
            request_id: ulid::Ulid::new().to_string(),
            command: command.to_string(),
            ok: false,
            data: None,
            error: Some(CliError {
                code: err.code.clone(),
                message: err.message.clone(),
                retryable: err.retryable,
                details: err.details.clone(),
            }),
        })
    }

    /// Serialize as a single JSON line and write it to stdout, per
    /// `docs/CLI.md` §2.2: results only on stdout, one line per response.
    pub fn print(&self) -> io::Result<()> {
        let line = serde_json::to_string(&self.0).map_err(io::Error::other)?;
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
        let value = serde_json::to_value(&env.0).unwrap();
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
        let value = serde_json::to_value(&env.0).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "INTERNAL");
        assert_eq!(value["error"]["details"], serde_json::Value::Null);
        assert!(value.get("data").is_none());
    }
}
