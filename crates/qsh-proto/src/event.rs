//! `qsh.event/v1` session events (`docs/CLI.md` §6.4:
//! output/gap/exit/writer_changed/closed).
//!
//! The shape matches the documented JSON exactly so `qsh session read`,
//! `--follow --jsonl` and the MCP `read_session` long-poll share one type.
//!
//! **Forward compatibility** (`docs/CLI.md` §6.4, §10): new event `type`s
//! may be added within `qsh.event/v1`, so consumers must skip unknown types
//! instead of failing. [`SessionEvent::Unknown`] is that fallback — any
//! object whose `type` is not one of the known variants deserializes into
//! it with the raw JSON preserved, and serializes back out unchanged.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The `schema` value stamped on every [`SessionEvent`].
pub const EVENT_SCHEMA: &str = "qsh.event/v1";

/// One `qsh.event/v1` event, tagged on `type` to match the wire examples in
/// `docs/CLI.md` §6.4.
///
/// Open string fields (`Closed::reason`) are modelled as `String`, not as
/// enums, because their value sets may grow additively (`docs/CLI.md` §10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
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
    /// The writer lease changed hands (stolen by another attach, or
    /// auto-released because the owning connection died — then
    /// `writer: null`). Broadcast to every read consumer of the session.
    #[serde(rename = "session.writer_changed")]
    WriterChanged {
        /// Always [`EVENT_SCHEMA`].
        schema: String,
        /// Opaque session handle this event belongs to.
        session_ref: String,
        /// Cumulative output byte offset at the moment of the change.
        sequence: u64,
        /// Principal string of the new lease holder (same format as
        /// `Session.writer`), or `null` when nobody holds it.
        writer: Option<String>,
    },
    /// The session was removed from the broker; always the last event for
    /// a `session_ref`.
    #[serde(rename = "session.closed")]
    Closed {
        /// Always [`EVENT_SCHEMA`].
        schema: String,
        /// Opaque session handle this event belongs to.
        session_ref: String,
        /// Cumulative output byte offset at removal.
        sequence: u64,
        /// Who removed the session — `"closed"` (explicit `session.close` or
        /// serve drain), `"exit"` (child exited, TTL reaper cleaned up) or
        /// `"ttl_expired"` (running session reaped without attach). Open
        /// set: unknown values mean only "the session is gone".
        reason: String,
    },
    /// An event `type` this build does not know. Holds the raw object so it
    /// can be skipped, logged structurally or re-emitted verbatim. Must stay
    /// the last variant (serde resolves it only after every tagged one).
    #[serde(untagged)]
    Unknown(serde_json::Value),
}

impl SessionEvent {
    /// The `session_ref` this event belongs to, when it carries one (an
    /// [`Unknown`](Self::Unknown) event may not).
    pub fn session_ref(&self) -> Option<&str> {
        match self {
            SessionEvent::Output { session_ref, .. }
            | SessionEvent::Gap { session_ref, .. }
            | SessionEvent::Exit { session_ref, .. }
            | SessionEvent::WriterChanged { session_ref, .. }
            | SessionEvent::Closed { session_ref, .. } => Some(session_ref),
            SessionEvent::Unknown(v) => v.get("session_ref").and_then(|s| s.as_str()),
        }
    }

    /// The `type` string of this event (`"session.output"`, ...), or the
    /// raw `type` of an unknown event if it has one.
    pub fn event_type(&self) -> Option<&str> {
        match self {
            SessionEvent::Output { .. } => Some("session.output"),
            SessionEvent::Gap { .. } => Some("session.gap"),
            SessionEvent::Exit { .. } => Some("session.exit"),
            SessionEvent::WriterChanged { .. } => Some("session.writer_changed"),
            SessionEvent::Closed { .. } => Some("session.closed"),
            SessionEvent::Unknown(v) => v.get("type").and_then(|s| s.as_str()),
        }
    }
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
    fn writer_changed_event_matches_documented_shape() {
        let event = SessionEvent::WriterChanged {
            schema: EVENT_SCHEMA.to_string(),
            session_ref: "personal-mac/01K0SESSION".to_string(),
            sequence: 180,
            writer: Some("device:hermes".to_string()),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "schema": "qsh.event/v1",
                "type": "session.writer_changed",
                "session_ref": "personal-mac/01K0SESSION",
                "sequence": 180,
                "writer": "device:hermes"
            })
        );
        let back: SessionEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);

        // Lease released with no holder → writer: null.
        let released: SessionEvent = serde_json::from_value(serde_json::json!({
            "schema": "qsh.event/v1",
            "type": "session.writer_changed",
            "session_ref": "personal-mac/01K0SESSION",
            "sequence": 200,
            "writer": null
        }))
        .unwrap();
        assert!(matches!(
            released,
            SessionEvent::WriterChanged { writer: None, .. }
        ));
    }

    #[test]
    fn closed_event_matches_documented_shape_and_reason_is_open() {
        let event = SessionEvent::Closed {
            schema: EVENT_SCHEMA.to_string(),
            session_ref: "personal-mac/01K0SESSION".to_string(),
            sequence: 180,
            reason: "closed".to_string(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "schema": "qsh.event/v1",
                "type": "session.closed",
                "session_ref": "personal-mac/01K0SESSION",
                "sequence": 180,
                "reason": "closed"
            })
        );
        let back: SessionEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);

        for reason in ["exit", "ttl_expired", "some_future_reason"] {
            let e: SessionEvent = serde_json::from_value(serde_json::json!({
                "schema": "qsh.event/v1",
                "type": "session.closed",
                "session_ref": "h/x",
                "sequence": 1,
                "reason": reason
            }))
            .unwrap();
            assert!(matches!(e, SessionEvent::Closed { .. }), "{reason}");
        }
    }

    #[test]
    fn unknown_event_type_is_preserved_not_rejected() {
        let json = serde_json::json!({
            "schema": "qsh.event/v1",
            "type": "session.something_new",
            "session_ref": "personal-mac/01K0SESSION",
            "sequence": 7,
            "extra": {"nested": true}
        });
        let event: SessionEvent = serde_json::from_value(json.clone()).unwrap();
        assert!(matches!(event, SessionEvent::Unknown(_)));
        assert_eq!(event.event_type(), Some("session.something_new"));
        assert_eq!(event.session_ref(), Some("personal-mac/01K0SESSION"));
        // Round-trips verbatim.
        assert_eq!(serde_json::to_value(&event).unwrap(), json);

        // Even an object with no `type` at all lands in Unknown rather than
        // failing the whole read.
        let odd: SessionEvent = serde_json::from_value(serde_json::json!({"x": 1})).unwrap();
        assert!(matches!(odd, SessionEvent::Unknown(_)));
        assert_eq!(odd.event_type(), None);
    }

    #[test]
    fn known_events_never_deserialize_as_unknown() {
        // A known type with the right fields must hit its typed variant —
        // the untagged fallback only catches what nothing else matched.
        let json = serde_json::json!({
            "schema": "qsh.event/v1",
            "type": "session.gap",
            "session_ref": "h/x",
            "requested_after": 42,
            "available_from": 120
        });
        let e: SessionEvent = serde_json::from_value(json).unwrap();
        assert!(matches!(e, SessionEvent::Gap { .. }));
        assert_eq!(e.event_type(), Some("session.gap"));
    }

    #[test]
    fn event_schema_generates_and_lists_all_types() {
        let schema = schemars::schema_for!(SessionEvent).to_value().to_string();
        for t in [
            "session.output",
            "session.gap",
            "session.exit",
            "session.writer_changed",
            "session.closed",
        ] {
            assert!(schema.contains(t), "schema lacks {t}");
        }
        assert!(!schema.contains("resume_token"));
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
