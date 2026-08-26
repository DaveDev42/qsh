//! JSONL purity (`docs/design/testing.md` L6, `docs/CLI.md` §2.2): run a
//! deliberately noisy command at high verbosity and assert that **every**
//! stdout line is still a complete `qsh.cli/v1` JSON object, with all the
//! diagnostics on stderr where they belong.
//!
//! `exec.run` is a value operation, so "every line" is exactly one line;
//! the point is that verbosity never adds a second one.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{Fleet, HOST_ALIAS, Sandbox, ServeGuard, exit_code};
#[cfg(unix)]
use common::{ListenGuard, ReverseGuard, hosts_array, poll_until};
use serde_json::Value;
#[cfg(unix)]
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
#[cfg(unix)]
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

/// A command that writes plenty of interleaved stdout and stderr.
const NOISY: &str = "for i in $(seq 1 200); do echo line$i; echo e$i >&2; done";

/// Assert that `stdout` is one or more lines, each a `qsh.cli/v1` object,
/// and return them.
fn parse_stdout_lines(stdout: &[u8], label: &str) -> Vec<Value> {
    let text = std::str::from_utf8(stdout).expect("stdout must be utf-8");
    assert!(!text.is_empty(), "{label}: stdout was empty");
    text.lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap_or_else(|err| {
                panic!("{label}: stdout line is not a complete JSON value: {err}: {line:?}")
            });
            assert!(
                value.is_object(),
                "{label}: every stdout line must be a JSON object, got {line:?}"
            );
            assert_eq!(value["schema"], "qsh.cli/v1", "{label}: {line:?}");
            value
        })
        .collect()
}

#[test]
fn a_noisy_exec_keeps_stdout_pure_json_at_every_verbosity() {
    let fleet = Fleet::start();

    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = fleet
            .client
            .qsh(&["exec", HOST_ALIAS, verbosity, mode, "--", "sh", "-c", NOISY]);

        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(
            lines.len(),
            1,
            "{label}: exec.run is a value operation — one envelope, one line"
        );
        let data = &lines[0]["data"];
        assert_eq!(lines[0]["command"], "exec.run", "{label}");

        // The remote's own noise rode the envelope, not our streams.
        let stdout_bytes = BASE64
            .decode(data["stdout_b64"].as_str().expect("stdout_b64"))
            .expect("stdout_b64 is Base64");
        let stderr_bytes = BASE64
            .decode(data["stderr_b64"].as_str().expect("stderr_b64"))
            .expect("stderr_b64 is Base64");
        assert_eq!(
            String::from_utf8_lossy(&stdout_bytes).lines().count(),
            200,
            "{label}"
        );
        assert_eq!(
            String::from_utf8_lossy(&stderr_bytes).lines().count(),
            200,
            "{label}"
        );

        assert!(
            !output.stderr.is_empty(),
            "{label}: the diagnostics have to be somewhere — stderr was empty"
        );
    }
}

/// Assert that `stdout` is one or more lines, each a complete
/// `qsh.event/v1` object, and return them. Deliberately a separate parser
/// from [`parse_stdout_lines`]: a follower streams bare events, so the
/// envelope schema must *not* appear (`docs/CLI.md` §6.4).
#[cfg(unix)]
fn parse_stdout_events(stdout: &[u8], label: &str) -> Vec<Value> {
    let text = std::str::from_utf8(stdout).expect("stdout must be utf-8");
    assert!(!text.is_empty(), "{label}: stdout was empty");
    text.lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap_or_else(|err| {
                panic!("{label}: stdout line is not a complete JSON value: {err}: {line:?}")
            });
            assert!(
                value.is_object(),
                "{label}: every stdout line must be a JSON object, got {line:?}"
            );
            assert_eq!(value["schema"], "qsh.event/v1", "{label}: {line:?}");
            value
        })
        .collect()
}

/// The streaming counterpart of the exec test: `session read --follow` is a
/// value *stream*, so "every line is pure JSON" has to hold across many
/// lines and across chunk boundaries — a partially flushed `session.output`
/// would fail to parse here. Verbosity still only ever adds stderr.
// Sessions are PTY-backed, so this whole path only exists on POSIX hosts
// (Windows host is P2), and `sh` is not there to run either.
#[cfg(unix)]
#[test]
fn a_noisy_follow_keeps_every_stdout_line_a_complete_json_event() {
    let fleet = Fleet::start();
    let (code, opened) = fleet.client.json(&[
        "session", "open", HOST_ALIAS, "--json", "--", "sh", "-c", NOISY,
    ]);
    assert_eq!(code, 0, "{opened}");
    let session_ref = opened["data"]["session_ref"].as_str().expect("session_ref");

    let label = "session read --follow -vv --jsonl";
    let output = fleet.client.qsh(&[
        "session",
        "read",
        session_ref,
        "-vv",
        "--jsonl",
        "--follow",
        "--after",
        "0",
    ]);
    assert_eq!(exit_code(&output), 0, "{label}");

    let events = parse_stdout_events(&output.stdout, label);
    assert!(
        events.len() > 1,
        "{label}: a followed session is a stream, not one envelope"
    );
    assert!(
        events.iter().all(|e| e["session_ref"] == session_ref),
        "{label}: every event names its session"
    );
    assert_eq!(
        events.last().expect("events")["type"],
        "session.exit",
        "{label}: the follow ends on the child's exit"
    );

    // The child's own noise rode the events, not our streams. A PTY merges
    // stderr into stdout, so both halves land in the same byte stream.
    let mut bytes = Vec::new();
    for event in events.iter().filter(|e| e["type"] == "session.output") {
        bytes.extend_from_slice(
            &BASE64
                .decode(event["data_b64"].as_str().expect("data_b64"))
                .expect("data_b64 is Base64"),
        );
    }
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("line1"), "{label}: {text:?}");
    assert!(text.contains("line200"), "{label}: {text:?}");
    assert!(text.contains("e200"), "{label}: {text:?}");

    assert!(
        !output.stderr.is_empty(),
        "{label}: the diagnostics have to be somewhere — stderr was empty"
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("line200"),
        "{label}: session output must never leak into the diagnostics"
    );
}

/// The reverse-route counterpart of the test above (`PLAN.md` M3 Step 7
/// DoD 1): `session open`/`session read --follow` are both value ops, so
/// this drives them over the `LOCAL_CONTROL` relay (`localctl/daemon.rs`'s
/// `serve_control`) instead of a direct QUIC connection — a completely
/// different route from the CLI's own process all the way to the target
/// than the forward-route test above, so purity here is not implied by
/// it. This does **not** exercise `LOCAL_STREAM`/`serve_stream`'s raw
/// byte splice (that path only carries an interactive attach's
/// `SESSION_DATA` stream, never a value op) — that path's own stdout
/// purity is exercised by `reverse_e2e.rs`'s interactive-attach scenario
/// instead, which drives a real pty rather than `--jsonl`.
#[cfg(unix)]
#[test]
fn a_noisy_follow_over_a_reverse_route_keeps_every_stdout_line_a_complete_json_event() {
    let controller = Sandbox::initialized();
    let target = Sandbox::initialized();
    let target_fp = target.fingerprint();
    let controller_fp = controller.fingerprint();

    const NAME: &str = "reverse-noisy";
    controller.trust_add(NAME, None, &target_fp);
    let listen = ListenGuard::start(&controller);
    target.trust_add("hub", Some(listen.addr()), &controller_fp);
    let reverse = ReverseGuard::start(&target, "hub");

    poll_until(
        "the reverse registration to appear reachable",
        std::time::Duration::from_secs(15),
        || {
            hosts_array(&controller)
                .iter()
                .any(|h| {
                    h["name"] == NAME
                        && h["connection_mode"] == "reverse"
                        && h["state"] == "reachable"
                })
                .then_some(())
        },
    );

    let (code, opened) =
        controller.json(&["session", "open", NAME, "--json", "--", "sh", "-c", NOISY]);
    assert_eq!(code, 0, "{opened}");
    let session_ref = opened["data"]["session_ref"].as_str().expect("session_ref");

    let label = "reverse route: session read --follow -vv --jsonl";
    let output = controller.qsh(&[
        "session",
        "read",
        session_ref,
        "-vv",
        "--jsonl",
        "--follow",
        "--after",
        "0",
    ]);
    assert_eq!(exit_code(&output), 0, "{label}");

    let events = parse_stdout_events(&output.stdout, label);
    assert!(
        events.len() > 1,
        "{label}: a followed session is a stream, not one envelope"
    );
    assert!(
        events.iter().all(|e| e["session_ref"] == session_ref),
        "{label}: every event names its session"
    );
    assert_eq!(
        events.last().expect("events")["type"],
        "session.exit",
        "{label}: the follow ends on the child's exit"
    );

    let mut bytes = Vec::new();
    for event in events.iter().filter(|e| e["type"] == "session.output") {
        bytes.extend_from_slice(
            &BASE64
                .decode(event["data_b64"].as_str().expect("data_b64"))
                .expect("data_b64 is Base64"),
        );
    }
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("line1"), "{label}: {text:?}");
    assert!(text.contains("line200"), "{label}: {text:?}");
    assert!(text.contains("e200"), "{label}: {text:?}");

    // Unlike the forward-route test above, `-vv` here genuinely produces
    // no stderr output at all (verified empirically): a `LOCAL_CONTROL`
    // round trip is a short, already-established UDS conduit with no
    // connection-setup spans of its own to log at `debug` — there is
    // nothing wrong with that (purity does not require stderr to be
    // non-empty, only that *whatever* lands on stdout is pure JSON), so
    // this test does not assert on stderr's contents, only that no
    // session payload ever reaches it if it *is* written.
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("line200"),
        "{label}: session output must never leak into the diagnostics"
    );

    reverse.shut_down();
    drop(listen);
}

/// `qsh serve` has no envelope at all: stdout stays empty no matter how
/// loud the diagnostics get (`docs/CLI.md` §6.12).
#[test]
fn serve_writes_nothing_to_stdout_even_at_high_verbosity() {
    let host = Sandbox::initialized();
    let mut serve = ServeGuard::start_with(&host, &["-vv"]);
    let output = serve.finish();

    assert!(
        output.stdout.is_empty(),
        "qsh serve wrote to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.has_stderr_line_starting_with("qsh serve: listening on "),
        "stderr: {:#?}",
        output.stderr
    );
}

/// The failure twin of the test above: `qsh --json serve` against a sandbox
/// with no identity yet fails in setup, *before* `run_serve` ever builds a
/// runtime or binds a listener (`ops.load_identity()?` is the first
/// fallible call). This is the path that used to print a `qsh.cli/v1`
/// envelope to stdout (`report_long_running_setup_error`'s own module docs)
/// — `--json` must not change that: these three long-running modes have no
/// envelope at all, so a setup failure is stderr-only just like the success
/// path above, with `qsh serve`'s own diagnostic line, not JSON.
#[test]
fn serve_json_setup_failure_writes_nothing_to_stdout() {
    let host = Sandbox::new(); // deliberately uninitialized: no identity
    let output = host.qsh(&["--json", "serve"]);

    assert!(
        output.stdout.is_empty(),
        "qsh --json serve wrote to stdout on a setup failure: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(exit_code(&output), 255, "stderr: {:#?}", output.stderr);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no device identity"), "stderr: {stderr:?}");
    assert!(
        serde_json::from_str::<Value>(stderr.trim()).is_err(),
        "the stderr diagnostic must be a human line, not a JSON envelope: {stderr:?}"
    );
}

/// A tunnel in progress produces `qsh::tunnel` diagnostics on stderr while
/// it splices real traffic (`crates/qsh-core/src/tunnel/local.rs`'s
/// accept/close `tracing::debug!`s, `PLAN.md` M4 Step 6) — a completely
/// different code path from every value op above — and stdout must still
/// carry nothing but the one `tunnel.open` envelope for as long as the
/// process holds (`docs/CLI.md` §6.14: it blocks in `TunnelHold::hold`
/// right after printing that envelope), so "every stdout line is pure
/// JSON" here specifically means "there is never a second line".
///
/// Forward-route only (client-side `-L` bind), like `tunnel_e2e.rs` — the
/// client-side local listener is the one part of M4's tunnel stack this
/// file's other tests do not need, so this test alone carries the `unix`
/// gate (`PLAN.md` M4 Windows-leg note: the tunnel relay/host path is
/// `cfg(unix)`).
#[cfg(unix)]
#[test]
fn a_tunnel_in_progress_keeps_stdout_pure_json_while_qsh_tunnel_diagnostics_land_on_stderr() {
    let fleet = Fleet::start();

    // A plain loopback echo destination standing in for "a service on the
    // host" — mirrors `tunnel_e2e.rs`'s own `start_echo`, duplicated
    // rather than shared for the same self-containment reason
    // `fixtures.rs`'s `free_port` gives its own copy.
    let echo = TcpListener::bind("127.0.0.1:0").expect("bind echo destination");
    let echo_port = echo.local_addr().expect("echo addr").port();
    thread::spawn(move || {
        for stream in echo.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().expect("clone echo socket");
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
                let _ = writer.shutdown(std::net::Shutdown::Write);
            });
        }
    });

    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let listen_port = TcpListener::bind("127.0.0.1:0")
            .expect("pick a free listen port")
            .local_addr()
            .expect("port")
            .port();
        let spec = format!("{listen_port}:127.0.0.1:{echo_port}");

        let mut child = fleet
            .client
            .command(&[
                "tunnel", "open", HOST_ALIAS, "--local", &spec, verbosity, mode,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{label}: spawn qsh tunnel open: {e}"));

        let stdout = child.stdout.take().expect("stdout pipe");
        let stderr = child.stderr.take().expect("stderr pipe");

        let stdout_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let stdout_reader = Arc::clone(&stdout_lines);
        let stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                stdout_reader.lock().unwrap().push(line);
            }
        });

        // Appended line-by-line, not `read_to_string`ed in one shot: a
        // single blocking read would only ever update the shared buffer
        // once the pipe hits EOF (i.e. once the child has already
        // exited), which would make the `poll_until` below wait for
        // diagnostics that can never appear before the kill that is
        // supposed to happen *after* seeing them.
        let stderr_text: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let stderr_reader = Arc::clone(&stderr_text);
        let stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let mut text = stderr_reader.lock().unwrap();
                text.push_str(&line);
                text.push('\n');
            }
        });

        // The envelope line is only printed after the listener actually
        // binds and is flushed before the process blocks in `hold()`
        // (`run_tunnel_open`'s own doc) — wait for it before dialing.
        poll_until(
            &format!("{label}: the tunnel.open envelope line"),
            Duration::from_secs(10),
            || (!stdout_lines.lock().unwrap().is_empty()).then_some(()),
        );

        // Drive a couple of connections through the forward, each
        // producing its own accept/close diagnostic on `qsh::tunnel` at
        // `-vv`+.
        for i in 0..2u8 {
            let mut conn = TcpStream::connect(("127.0.0.1", listen_port))
                .unwrap_or_else(|e| panic!("{label}: connect to the forward #{i}: {e}"));
            conn.set_read_timeout(Some(Duration::from_secs(30)))
                .expect("set read timeout");
            let payload = format!("jsonl-purity-{i}").into_bytes();
            let mut writer = conn.try_clone().expect("clone forward socket");
            let sender_payload = payload.clone();
            let sender = thread::spawn(move || -> std::io::Result<()> {
                writer.write_all(&sender_payload)?;
                writer.flush()?;
                writer.shutdown(std::net::Shutdown::Write)
            });
            let mut back = Vec::new();
            conn.read_to_end(&mut back)
                .unwrap_or_else(|e| panic!("{label}: read #{i}: {e}"));
            sender
                .join()
                .expect("sender thread panicked")
                .unwrap_or_else(|e| panic!("{label}: write #{i}: {e}"));
            assert_eq!(back, payload, "{label}: echo #{i} mismatched");
        }

        poll_until(
            &format!("{label}: qsh::tunnel diagnostics on stderr"),
            Duration::from_secs(10),
            || {
                stderr_text
                    .lock()
                    .unwrap()
                    .contains("qsh::tunnel")
                    .then_some(())
            },
        );

        let _ = child.kill();
        let _ = child.wait();
        stdout_thread.join().expect("stdout reader thread");
        stderr_thread.join().expect("stderr reader thread");

        let lines = stdout_lines.lock().unwrap();
        assert_eq!(
            lines.len(),
            1,
            "{label}: exactly one tunnel.open envelope, no more, while holding: {lines:?}"
        );
        let envelope: Value = serde_json::from_str(&lines[0])
            .unwrap_or_else(|e| panic!("{label}: stdout line is not JSON: {e}: {:?}", lines[0]));
        assert_eq!(envelope["schema"], "qsh.cli/v1", "{label}");
        assert_eq!(envelope["command"], "tunnel.open", "{label}");
        assert_eq!(envelope["ok"], true, "{label}: {envelope}");

        let stderr = stderr_text.lock().unwrap();
        assert!(
            stderr.contains("qsh::tunnel"),
            "{label}: expected qsh::tunnel diagnostics on stderr, got {stderr:?}"
        );
        assert!(
            !stderr.contains("jsonl-purity"),
            "{label}: tunnel payload leaked into diagnostics: {stderr:?}"
        );
    }
}
