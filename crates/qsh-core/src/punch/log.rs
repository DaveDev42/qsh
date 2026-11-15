//! The `qsh::punch` log target (ADR-0054 decision 20): one JSON object per
//! event, written the way `qsh::adapt` is. It is off by default and `-v` or
//! `QSH_LOG=qsh::punch=info` turns it on. Nothing emits on it since ADR-0068
//! retired the punch; the target stays a valid filter.
//!
//! Every field is a count, a duration, a word from a closed vocabulary or the
//! name of a pin on this device. **No IP address or port goes into a line,
//! whatever the verbosity** (decision 14, threat model D23); the helpers
//! below take counts and words only, so a caller has no way to hand them an
//! address.

use serde_json::Value;

/// The tracing target.
pub const TARGET: &str = "qsh::punch";

/// The line for `event`: `{"punch":"<event>",<fields>}`, no newline.
pub fn line(event: &str, fields: Value) -> String {
    let body = match fields {
        Value::Object(map) => serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string()),
        _ => "{}".to_string(),
    };
    let inner = body.trim_start_matches('{');
    if inner == "}" {
        format!(r#"{{"punch":"{event}"}}"#)
    } else {
        format!(r#"{{"punch":"{event}",{inner}"#)
    }
}

/// Writes one event.
pub fn emit(event: &str, fields: Value) {
    tracing::info!(target: TARGET, "{}", line(event, fields));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_line_is_one_json_object_led_by_the_event() {
        let l = line("attempt", json!({ "rendezvous": "hub" }));
        assert_eq!(l, r#"{"punch":"attempt","rendezvous":"hub"}"#);
        assert_eq!(line("x", json!({})), r#"{"punch":"x"}"#);
        let parsed: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(parsed["punch"], "attempt");
    }
}
