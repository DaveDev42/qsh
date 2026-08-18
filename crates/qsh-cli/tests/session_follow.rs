//! L6 CLI: `qsh session read --follow` against a real `qsh serve`
//! (`docs/CLI.md` §6.4).
//!
//! The point of these tests is the *shared primitive*: `--wait` is one
//! `Ops::session_reader(..).pull()` and `--follow` is that same call in a
//! loop (`Ops::session_read` is literally a one-pull delegation), so a
//! session's event stream must look the same through either door.

// Sessions are PTY-backed, so this whole file only exists on POSIX hosts
// (Windows host is P2) — and `sh` is not there to run the script either.
#![cfg(unix)]

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{Fleet, HOST_ALIAS, Sandbox, exit_code};
use serde_json::Value;

/// A child that produces a known amount of output and then exits, so both
/// readers see a finite, terminated stream.
const SCRIPT: &str = "for i in $(seq 1 60); do echo line$i; done; exit 7";

/// Wall-clock bound for the `--wait` polling loop; every iteration is a
/// real round trip, never a sleep.
const POLL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Open a session running `SCRIPT` and return its `session_ref`.
fn open_noisy_session(client: &Sandbox) -> String {
    let (code, opened) = client.json(&[
        "session", "open", HOST_ALIAS, "--json", "--", "sh", "-c", SCRIPT,
    ]);
    assert_eq!(code, 0, "{opened}");
    opened["data"]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string()
}

/// Every stdout line parsed as a complete `qsh.event/v1` object.
fn parse_events(stdout: &[u8], label: &str) -> Vec<Value> {
    let text = std::str::from_utf8(stdout).expect("stdout must be utf-8");
    text.lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap_or_else(|err| {
                panic!("{label}: stdout line is not a complete JSON value: {err}: {line:?}")
            });
            assert!(
                value.is_object(),
                "{label}: every stdout line must be a JSON object, got {line:?}"
            );
            assert_eq!(
                value["schema"], "qsh.event/v1",
                "{label}: --follow emits bare events, not envelopes: {line:?}"
            );
            value
        })
        .collect()
}

/// Reduce an event stream to what must be identical whichever door it came
/// through: the output bytes in order, and the (type, sequence) of every
/// control event. Chunk boundaries are explicitly *not* part of it — the
/// host may split or merge freely (`docs/CLI.md` §6.4).
/// A control event reduced to what both doors must agree on: its `type`
/// and its `sequence` — `None` for `session.gap`, which has none.
type Control = (String, Option<u64>);

/// The comparable shape of one event stream: output bytes, control events,
/// and the final cumulative offset.
type Normalized = (Vec<u8>, Vec<Control>, u64);

fn normalize(events: &[Value], label: &str) -> Normalized {
    let mut bytes = Vec::new();
    let mut controls = Vec::new();
    let mut last_sequence = 0u64;
    for event in events {
        let kind = event["type"].as_str().expect("type").to_string();
        // `session.gap` carries `requested_after`/`available_from` and no
        // `sequence` at all (CLI.md §6.4). Recording it as `None` rather
        // than inventing one keeps the comparison honest exactly where a
        // gap would otherwise be papered over.
        let sequence = event["sequence"].as_u64();
        match kind.as_str() {
            "session.output" => {
                let sequence = sequence.expect("session.output carries a sequence");
                let data = BASE64
                    .decode(event["data_b64"].as_str().expect("data_b64"))
                    .expect("data_b64 is Base64");
                assert!(
                    sequence >= last_sequence,
                    "{label}: sequences must not go backwards"
                );
                last_sequence = sequence;
                bytes.extend_from_slice(&data);
            }
            other => {
                controls.push((other.to_string(), sequence));
                last_sequence = last_sequence.max(sequence.unwrap_or(last_sequence));
            }
        }
    }
    (bytes, controls, last_sequence)
}

/// Drain a session with `--wait` pulls, feeding `next_after`/`next_ctl_after`
/// back, until a terminal event arrives. This is the loop `--follow` runs
/// inside the binary.
fn drain_with_wait(client: &Sandbox, session_ref: &str) -> Vec<Value> {
    let mut events = Vec::new();
    let (mut after, mut ctl_after) = (0u64, 0u64);
    let deadline = std::time::Instant::now() + POLL_DEADLINE;
    loop {
        let (code, read) = client.json(&[
            "session",
            "read",
            session_ref,
            "--json",
            "--after",
            &after.to_string(),
            "--ctl-after",
            &ctl_after.to_string(),
            "--wait",
            "5000",
        ]);
        assert_eq!(code, 0, "{read}");
        after = read["data"]["next_after"].as_u64().expect("next_after");
        ctl_after = read["data"]["next_ctl_after"]
            .as_u64()
            .expect("next_ctl_after");
        let batch = read["data"]["events"].as_array().expect("events").clone();
        let terminal = batch
            .iter()
            .any(|e| matches!(e["type"].as_str(), Some("session.exit" | "session.closed")));
        events.extend(batch);
        if terminal {
            return events;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the session never reached a terminal event"
        );
    }
}

/// The same session read two ways delivers the same bytes and the same
/// control events. If `--follow` ever stopped being a loop over the
/// `--wait` primitive, this is what would drift.
#[test]
fn wait_and_follow_deliver_the_same_stream() {
    let fleet = Fleet::start();
    let session_ref = open_noisy_session(&fleet.client);

    // `--follow` runs the loop inside the binary and stops on the exit.
    let followed = fleet.client.qsh(&[
        "session",
        "read",
        &session_ref,
        "--jsonl",
        "--follow",
        "--after",
        "0",
    ]);
    assert_eq!(exit_code(&followed), 0, "--follow exits 0 on session.exit");
    let follow_events = parse_events(&followed.stdout, "--follow");

    // …and the same ring drained by hand through single `--wait` pulls.
    let wait_events = drain_with_wait(&fleet.client, &session_ref);

    let (follow_bytes, follow_controls, follow_end) = normalize(&follow_events, "--follow");
    let (wait_bytes, wait_controls, wait_end) = normalize(&wait_events, "--wait");

    assert_eq!(
        String::from_utf8_lossy(&follow_bytes),
        String::from_utf8_lossy(&wait_bytes),
        "the two readers must see the same bytes"
    );
    assert_eq!(
        follow_controls, wait_controls,
        "the two readers must see the same control events at the same offsets"
    );
    assert_eq!(follow_end, wait_end);

    // The stream really did carry the child's output and its exit.
    let text = String::from_utf8_lossy(&follow_bytes);
    assert!(text.contains("line1"), "{text:?}");
    assert!(text.contains("line60"), "{text:?}");
    assert!(
        follow_controls
            .iter()
            .any(|(kind, _)| kind == "session.exit"),
        "{follow_controls:?}"
    );
    let exit = follow_events
        .iter()
        .find(|e| e["type"] == "session.exit")
        .expect("session.exit");
    assert_eq!(exit["exit_code"], 7, "{exit}");
}

/// The one shape this step decided (`docs/CLI.md` §6.4): a follower is a
/// stream, so `--json --follow` emits the same bare `qsh.event/v1` lines as
/// `--jsonl --follow` — never a single `qsh.cli/v1` envelope. Without this
/// the sentence in the contract has no test behind it.
#[test]
fn json_and_jsonl_follow_emit_the_same_bare_event_stream() {
    let fleet = Fleet::start();

    let mut streams = Vec::new();
    for mode in ["--jsonl", "--json"] {
        let session_ref = open_noisy_session(&fleet.client);
        let out = fleet.client.qsh(&[
            "session",
            "read",
            &session_ref,
            mode,
            "--follow",
            "--after",
            "0",
        ]);
        assert_eq!(
            exit_code(&out),
            0,
            "{mode} --follow exits 0 on session.exit"
        );
        // `parse_events` already asserts every stdout line is a complete
        // `qsh.event/v1` *object* — an envelope would fail there.
        let events = parse_events(&out.stdout, mode);
        assert!(
            events.iter().all(|e| e["schema"] == "qsh.event/v1"),
            "{mode}: a follower never emits a qsh.cli/v1 envelope"
        );
        let (bytes, controls, end) = normalize(&events, mode);
        streams.push((bytes, controls, end));
    }

    let (jsonl, json) = (&streams[0], &streams[1]);
    assert_eq!(
        String::from_utf8_lossy(&jsonl.0),
        String::from_utf8_lossy(&json.0),
        "--json --follow and --jsonl --follow carry the same bytes"
    );
    assert_eq!(
        jsonl.1, json.1,
        "…and the same control events at the same offsets"
    );
    assert_eq!(jsonl.2, json.2);
    assert!(
        jsonl.1.iter().any(|(kind, _)| kind == "session.exit"),
        "{:?}",
        jsonl.1
    );
}
