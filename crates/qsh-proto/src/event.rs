//! `qsh.event/v1` session events (`docs/CLI.md` §6.4: output/gap/exit).
//!
//! This is a skeleton: the shape matches the documented JSON exactly so
//! `qsh session read`/`--follow --jsonl` and the future MCP `read_session`
//! long-poll can share one type, but no producer exists yet in this
//! milestone.

use serde::{Deserialize, Serialize};

/// The `schema` value stamped on every [`SessionEvent`].
pub const EVENT_SCHEMA: &str = "qsh.event/v1";

/// One `qsh.event/v1` event, tagged on `type` to match the wire examples in
/// `docs/CLI.md` §6.4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SessionEvent {
    /// A chunk of session output.
    #[serde(rename = "session.output")]
    Output {
        /// Always [`EVENT_SCHEMA`].
        schema: String,
        /// Opaque session handle this event belongs to.
        session_ref: String,
        /// Byte-offset sequence of the *end* of this chunk.
        sequence: u64,
        /// Output bytes, base64-encoded.
        data_b64: String,
    },
    /// The requested replay range is no longer available; the reader must
    /// resync from `available_from`.
    #[serde(rename = "session.gap")]
    Gap {
        /// Always [`EVENT_SCHEMA`].
        schema: String,
        /// Opaque session handle this event belongs to.
        session_ref: String,
        /// The `--after` sequence the reader asked for.
        requested_after: u64,
        /// Earliest sequence still available in the replay ring.
        available_from: u64,
    },
    /// The session's process has exited.
    #[serde(rename = "session.exit")]
    Exit {
        /// Always [`EVENT_SCHEMA`].
        schema: String,
        /// Opaque session handle this event belongs to.
        session_ref: String,
        /// Byte-offset sequence at the moment of exit.
        sequence: u64,
        /// Process exit code, or `null` if terminated by signal.
        exit_code: Option<i32>,
        /// Signal name that terminated the process, if any.
        signal: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_event_matches_documented_shape() {
        let event = SessionEvent::Output {
            schema: EVENT_SCHEMA.to_string(),
            session_ref: "personal-mac/01K0SESSION".to_string(),
            sequence: 43,
            data_b64: "SGVsbG8NCg==".to_string(),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["schema"], "qsh.event/v1");
        assert_eq!(json["type"], "session.output");
        assert_eq!(json["session_ref"], "personal-mac/01K0SESSION");
        assert_eq!(json["sequence"], 43);
        assert_eq!(json["data_b64"], "SGVsbG8NCg==");

        let back: SessionEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn exit_event_allows_null_exit_code_and_signal() {
        let json = serde_json::json!({
            "schema": EVENT_SCHEMA,
            "type": "session.exit",
            "session_ref": "personal-mac/01K0SESSION",
            "sequence": 180,
            "exit_code": null,
            "signal": "SIGKILL",
        });
        let event: SessionEvent = serde_json::from_value(json).unwrap();
        assert_eq!(
            event,
            SessionEvent::Exit {
                schema: EVENT_SCHEMA.to_string(),
                session_ref: "personal-mac/01K0SESSION".to_string(),
                sequence: 180,
                exit_code: None,
                signal: Some("SIGKILL".to_string()),
            }
        );
    }
}
