//! Golden fixture loader (`docs/design/testing.md` L6). Fixtures live in
//! `crates/qsh-cli/tests/fixtures/cli-v1/<name>.json` and are append-only.

use std::path::{Path, PathBuf};

/// Directory holding the `qsh.cli/v1` golden fixtures.
pub fn cli_v1_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("qsh-cli")
        .join("tests")
        .join("fixtures")
        .join("cli-v1")
}

/// Load one fixture by file name (e.g. `"version.json"`).
pub fn load_cli_v1(name: &str) -> serde_json::Value {
    let path = cli_v1_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parsing fixture {}: {e}", path.display()))
}

/// Every fixture in the `cli-v1` directory, sorted by file name.
pub fn all_cli_v1() -> Vec<(String, serde_json::Value)> {
    let dir = cli_v1_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("listing {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let v = load_cli_v1(&n);
            (n, v)
        })
        .collect()
}

/// Replace volatile fields (`request_id`, timestamps, durations, paths) with
/// stable placeholders so an envelope can be compared to a fixture.
pub fn normalize(mut value: serde_json::Value) -> serde_json::Value {
    fn walk(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, child) in map.iter_mut() {
                    match k.as_str() {
                        "request_id" => *child = serde_json::Value::String("<request_id>".into()),
                        "added_at" | "created_at" | "ts" => {
                            *child = serde_json::Value::String("<timestamp>".into())
                        }
                        "duration_ms" => *child = serde_json::Value::from(0),
                        "config_dir" => *child = serde_json::Value::String("<config_dir>".into()),
                        "device_id" => *child = serde_json::Value::String("<device_id>".into()),
                        "fingerprint" | "observed_fingerprint" => {
                            *child = serde_json::Value::String("<fingerprint>".into())
                        }
                        "address" => *child = serde_json::Value::String("<address>".into()),
                        // Host-issued session ids are ULIDs; a `session_ref`
                        // keeps its (stable) host alias and masks the id.
                        "session_id" => *child = serde_json::Value::String("<session_id>".into()),
                        "session_ref" => {
                            if let serde_json::Value::String(text) = child {
                                *text = mask_session_ref(text);
                            }
                        }
                        // The binary's own version churns on every release;
                        // the fixture asserts the *shape*, and `schemas`
                        // (right next to it) still pins the contract ids.
                        "version" => *child = serde_json::Value::String("<version>".into()),
                        // Human-readable messages are part of the fixture —
                        // only the ephemeral loopback port inside them is
                        // masked (`127.0.0.1:53412` → `127.0.0.1:<port>`).
                        "message" => {
                            if let serde_json::Value::String(text) = child {
                                *text = mask_loopback_ports(text);
                            }
                        }
                        _ => walk(child),
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    value
}

/// Replace the session id half of `<host>/<session_id>` with the literal
/// `<session_id>`; anything without a `/` is left alone.
fn mask_session_ref(text: &str) -> String {
    match text.rsplit_once('/') {
        Some((host, _)) => format!("{host}/<session_id>"),
        None => text.to_string(),
    }
}

/// Replace the port of every `127.0.0.1:<digits>` occurrence in `text` with
/// the literal `<port>`, so a fixture generated against an ephemeral
/// (`:0`-bound) listener keeps the rest of its message intact.
fn mask_loopback_ports(text: &str) -> String {
    const HOST: &str = "127.0.0.1:";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(HOST) {
        let (head, tail) = rest.split_at(at + HOST.len());
        out.push_str(head);
        let digits = tail.len() - tail.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits > 0 {
            out.push_str("<port>");
        }
        rest = &tail[digits..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_ports_are_masked_in_place() {
        assert_eq!(
            mask_loopback_ports("no response from 127.0.0.1:53412 within 10s"),
            "no response from 127.0.0.1:<port> within 10s"
        );
        assert_eq!(
            mask_loopback_ports("cannot connect to 127.0.0.1:0: bad 127.0.0.1:0"),
            "cannot connect to 127.0.0.1:<port>: bad 127.0.0.1:<port>"
        );
        assert_eq!(mask_loopback_ports("nothing to mask"), "nothing to mask");
        // A bare host with no port is left alone.
        assert_eq!(mask_loopback_ports("127.0.0.1:x"), "127.0.0.1:x");
    }

    #[test]
    fn normalize_replaces_volatile_fields_only() {
        let value = serde_json::json!({
            "request_id": "01K0",
            "command": "exec.run",
            "ok": true,
            "data": {"duration_ms": 42, "remote_exit_code": 7},
            "error": {"message": "peer 127.0.0.1:1234 is not trusted"},
        });
        let normalized = normalize(value);
        assert_eq!(normalized["request_id"], "<request_id>");
        assert_eq!(normalized["command"], "exec.run");
        assert_eq!(normalized["data"]["duration_ms"], 0);
        assert_eq!(normalized["data"]["remote_exit_code"], 7);
        assert_eq!(
            normalized["error"]["message"],
            "peer 127.0.0.1:<port> is not trusted"
        );
    }
}
