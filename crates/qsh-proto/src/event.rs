//! `qsh.event/v1` session events (`docs/CLI.md` §6.4:
//! output/gap/exit/writer_changed/closed).
//!
//! The shape matches the documented JSON exactly so `qsh session read`,
//! `--follow --jsonl` and the MCP `read_session` long-poll share one type.
//!
//! **Forward compatibility** (`docs/CLI.md` §6.4, §10): new event `type`s
//! may be added within `qsh.event/v1`, so consumers must skip unknown types
//! instead of failing. [`SessionEvent::Unknown`] is that fallback — any
//! object whose `type` is *not one of the known strings* deserializes into
//! it with the raw JSON preserved, and serializes back out unchanged.
//!
//! The fallback is deliberately narrow: an object whose `type` **is** a
//! known one but whose payload is malformed (missing `data_b64`, string
//! `sequence`, …) is a deserialization **error**, never `Unknown` —
//! otherwise a corrupt `session.output` would be silently skipped by a
//! consumer following the "skip unknown types" rule, which is exactly the
//! silent output loss `docs/design/protocol.md` §10.4 forbids. Non-object
//! values are rejected outright.

use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The `schema` value stamped on every [`SessionEvent`].
pub const EVENT_SCHEMA: &str = "qsh.event/v1";

/// Every `type` string this build knows. `Deserialize` routes these to
/// their typed variant (errors propagate); anything else → `Unknown`.
pub const KNOWN_EVENT_TYPES: &[&str] = &[
    "session.output",
    "session.gap",
    "session.exit",
    "session.writer_changed",
    "session.closed",
];

/// One `qsh.event/v1` event, tagged on `type` to match the wire examples in
/// `docs/CLI.md` §6.4.
///
/// Open string fields (`Closed::reason`) are modelled as `String`, not as
/// enums, because their value sets may grow additively (`docs/CLI.md` §10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
// `remote = "Self"` makes the derives inherent helpers; the real trait impls
// below add the "known type must parse or fail" routing on top.
#[serde(tag = "type", remote = "Self")]
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
    /// can be skipped, logged structurally or re-emitted verbatim. Only
    /// produced by the manual `Deserialize` impl for an object whose `type`
    /// is not in [`KNOWN_EVENT_TYPES`]; a known type with a bad payload is
    /// an error instead. Left out of the JSON Schema on purpose (the schema
    /// describes what this build emits; the open-set rule is documented in
    /// `docs/CLI.md` §6.4).
    #[serde(untagged, skip_deserializing)]
    #[schemars(skip)]
    Unknown(serde_json::Value),
}

impl Serialize for SessionEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Inherent helper generated by `#[serde(remote = "Self")]`.
        SessionEvent::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for SessionEvent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let obj = value
            .as_object()
            .ok_or_else(|| D::Error::custom("qsh.event/v1 event must be a JSON object"))?;
        match obj.get("type").and_then(serde_json::Value::as_str) {
            // Known type: the typed variant must parse; propagate its error.
            Some(t) if KNOWN_EVENT_TYPES.contains(&t) => {
                SessionEvent::deserialize(value).map_err(D::Error::custom)
            }
            // Unknown or missing type: preserved verbatim for skipping.
            _ => Ok(SessionEvent::Unknown(value)),
        }
    }
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
    fn malformed_known_event_is_an_error_not_unknown() {
        // A known `type` with a broken payload must fail loudly: routing it
        // to Unknown would let a "skip unknown types" consumer drop output
        // silently (protocol.md §10.4).
        let cases = [
            // session.output without data_b64
            serde_json::json!({
                "schema": "qsh.event/v1", "type": "session.output",
                "session_ref": "h/x", "sequence": 49
            }),
            // sequence of the wrong type
            serde_json::json!({
                "schema": "qsh.event/v1", "type": "session.output",
                "session_ref": "h/x", "sequence": "not-a-number", "data_b64": "AA=="
            }),
            // negative sequence
            serde_json::json!({
                "schema": "qsh.event/v1", "type": "session.exit",
                "session_ref": "h/x", "sequence": -5
            }),
            // known type, nothing else
            serde_json::json!({"type": "session.closed"}),
        ];
        for json in cases {
            let r: Result<SessionEvent, _> = serde_json::from_value(json.clone());
            assert!(r.is_err(), "{json} deserialized as {r:?}");
        }
    }

    #[test]
    fn non_object_events_are_rejected() {
        for json in [
            serde_json::json!(42),
            serde_json::json!("hello"),
            serde_json::json!(null),
            serde_json::json!([1, 2, 3]),
            serde_json::json!(true),
        ] {
            let r: Result<SessionEvent, _> = serde_json::from_value(json.clone());
            assert!(r.is_err(), "{json} deserialized as {r:?}");
        }
        // The same through the string path (what `--jsonl` consumers use).
        assert!(serde_json::from_str::<SessionEvent>("null").is_err());
        assert!(serde_json::from_str::<Vec<SessionEvent>>("[42]").is_err());
    }

    #[test]
    fn known_event_with_extra_fields_still_hits_typed_variant() {
        // Field-level forward compat: unknown extra fields on a known type
        // are ignored, the typed variant still wins.
        let e: SessionEvent = serde_json::from_value(serde_json::json!({
            "schema": "qsh.event/v1", "type": "session.gap", "session_ref": "h/x",
            "requested_after": 42, "available_from": 120, "brand_new_field": {"x": 1}
        }))
        .unwrap();
        assert!(matches!(e, SessionEvent::Gap { .. }));
    }

    #[test]
    fn known_event_types_constant_matches_event_type() {
        let samples = [
            SessionEvent::Output {
                schema: EVENT_SCHEMA.into(),
                session_ref: "h/x".into(),
                sequence: 1,
                data_b64: "AA==".into(),
            },
            SessionEvent::Gap {
                schema: EVENT_SCHEMA.into(),
                session_ref: "h/x".into(),
                requested_after: 0,
                available_from: 1,
            },
            SessionEvent::Exit {
                schema: EVENT_SCHEMA.into(),
                session_ref: "h/x".into(),
                sequence: 1,
                exit_code: Some(0),
                signal: None,
            },
            SessionEvent::WriterChanged {
                schema: EVENT_SCHEMA.into(),
                session_ref: "h/x".into(),
                sequence: 1,
                writer: None,
            },
            SessionEvent::Closed {
                schema: EVENT_SCHEMA.into(),
                session_ref: "h/x".into(),
                sequence: 1,
                reason: "closed".into(),
            },
        ];
        assert_eq!(samples.len(), KNOWN_EVENT_TYPES.len());
        for (e, t) in samples.iter().zip(KNOWN_EVENT_TYPES) {
            assert_eq!(e.event_type(), Some(*t));
            assert_eq!(serde_json::to_value(e).unwrap()["type"], *t);
            // And each round-trips through the manual impls.
            let back: SessionEvent =
                serde_json::from_value(serde_json::to_value(e).unwrap()).unwrap();
            assert_eq!(&back, e);
        }
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
    fn event_schema_is_constraining_and_lists_all_types() {
        let schema = schemars::schema_for!(SessionEvent).to_value();
        let text = schema.to_string();
        for t in KNOWN_EVENT_TYPES {
            assert!(text.contains(t), "schema lacks {t}");
        }
        // Exactly the five known variants — `Unknown` is skipped, so the
        // published schema is not an always-true `anyOf`.
        let branches = schema
            .get("oneOf")
            .or_else(|| schema.get("anyOf"))
            .and_then(|v| v.as_array())
            .expect("enum schema is a oneOf/anyOf");
        assert_eq!(branches.len(), KNOWN_EVENT_TYPES.len());
        for b in branches {
            assert!(
                b.get("properties")
                    .is_some_and(|p| !p.as_object().unwrap().is_empty()),
                "vacuous branch: {b}"
            );
            assert!(b.get("required").is_some(), "unconstrained branch: {b}");
        }
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
