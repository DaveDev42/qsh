//! The `qsh::punch` log target (ADR-0054 decision 20): one JSON object per
//! event, written the way `qsh::adapt` is. It is off by default and `-v` or
//! `QSH_LOG=qsh::punch=info` turns it on.
//!
//! Every field is a count, a duration, a word from a closed vocabulary or the
//! name of a pin on this device. **No IP address or port goes into a line,
//! whatever the verbosity** (decision 14, threat model D23); the helpers
//! below take counts and words only, so a caller has no way to hand them an
//! address.

use std::net::SocketAddr;

use serde_json::{Map, Value, json};

/// The tracing target.
pub const TARGET: &str = "qsh::punch";

/// A candidate address the peers listed for themselves.
pub const KIND_HOST: &str = "host";
/// A candidate the rendezvous saw the target at.
pub const KIND_REFLEXIVE: &str = "reflexive";
/// An address learned from the target's own punch datagram.
pub const KIND_PEER_REFLEXIVE: &str = "peer_reflexive";

/// `"ipv4"` or `"ipv6"`.
pub fn family_of(addr: &SocketAddr) -> &'static str {
    if addr.ip().to_canonical().is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    }
}

/// Candidate counts by kind and family: numbers only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CandidateCounts {
    host_v4: u32,
    host_v6: u32,
    reflexive_v4: u32,
    reflexive_v6: u32,
}

impl CandidateCounts {
    /// Counts one candidate of `kind` (anything but [`KIND_HOST`] counts as
    /// reflexive).
    pub fn add(&mut self, kind: &str, addr: &SocketAddr) {
        let v4 = family_of(addr) == "ipv4";
        let slot = match (kind == KIND_HOST, v4) {
            (true, true) => &mut self.host_v4,
            (true, false) => &mut self.host_v6,
            (false, true) => &mut self.reflexive_v4,
            (false, false) => &mut self.reflexive_v6,
        };
        *slot += 1;
    }

    fn put(&self, map: &mut Map<String, Value>) {
        map.insert("host_v4".into(), json!(self.host_v4));
        map.insert("host_v6".into(), json!(self.host_v6));
        map.insert("reflexive_v4".into(), json!(self.reflexive_v4));
        map.insert("reflexive_v6".into(), json!(self.reflexive_v6));
    }
}

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

/// `attempt`: a punch begins through `rendezvous`.
pub(crate) fn attempt(rendezvous: &str) {
    emit("attempt", json!({ "rendezvous": rendezvous }));
}

/// `signaled`: the rendezvous answered with the target's candidates.
pub(crate) fn signaled(rendezvous: &str, counts: &CandidateCounts, rejected: usize, ms: u64) {
    let mut map = Map::new();
    map.insert("rendezvous".into(), json!(rendezvous));
    counts.put(&mut map);
    map.insert("rejected".into(), json!(rejected));
    map.insert("elapsed_ms".into(), json!(ms));
    emit("signaled", Value::Object(map));
}

/// `adopted`: a handshake passed the pin check.
pub(crate) fn adopted(
    rendezvous: &str,
    kind: &str,
    family: &str,
    ms: u64,
    tag_rejected: u64,
    losers_closed: usize,
) {
    emit(
        "adopted",
        json!({
            "rendezvous": rendezvous,
            "kind": kind,
            "family": family,
            "elapsed_ms": ms,
            "tag_rejected": tag_rejected,
            "losers_closed": losers_closed,
        }),
    );
}

/// `gave_up`: the punch ended without a connection.
pub(crate) fn gave_up(rendezvous: &str, reason: &str, ms: u64, tag_rejected: u64) {
    emit(
        "gave_up",
        json!({
            "rendezvous": rendezvous,
            "reason": reason,
            "elapsed_ms": ms,
            "tag_rejected": tag_rejected,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_one_json_object_led_by_the_event() {
        let l = line("attempt", json!({ "rendezvous": "hub" }));
        assert_eq!(l, r#"{"punch":"attempt","rendezvous":"hub"}"#);
        assert_eq!(line("x", json!({})), r#"{"punch":"x"}"#);
        let parsed: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(parsed["punch"], "attempt");
    }

    #[test]
    fn counts_split_by_kind_and_family() {
        let mut c = CandidateCounts::default();
        c.add(KIND_HOST, &"192.0.2.1:1".parse().unwrap());
        c.add(KIND_HOST, &"[2001:db8::1]:1".parse().unwrap());
        c.add(KIND_REFLEXIVE, &"192.0.2.9:1".parse().unwrap());
        let mut m = Map::new();
        c.put(&mut m);
        assert_eq!(m["host_v4"], 1);
        assert_eq!(m["host_v6"], 1);
        assert_eq!(m["reflexive_v4"], 1);
        assert_eq!(m["reflexive_v6"], 0);
    }
}
