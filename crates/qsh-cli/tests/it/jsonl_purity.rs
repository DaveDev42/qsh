//! JSONL purity (`docs/design/testing.md` L6, `docs/CLI.md` §2.2): run a
//! deliberately noisy command at high verbosity and assert that **every**
//! stdout line is still a complete `qsh.cli/v1` JSON object, with all the
//! diagnostics on stderr where they belong.
//!
//! `exec.run` is a value operation, so "every line" is exactly one line;
//! the point is that verbosity never adds a second one.

use crate::common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{Fleet, HOST_ALIAS, Sandbox, ServeGuard, exit_code};
use common::{ListenGuard, ReverseGuard, hosts_array, poll_until};
use serde_json::Value;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A command that writes plenty of interleaved stdout and stderr: the lines
/// `line1`..`line200` on stdout and `e1`..`e200` on stderr.
fn noisy_argv() -> Vec<String> {
    #[cfg(unix)]
    {
        [
            "sh",
            "-c",
            "for i in $(seq 1 200); do echo line$i; echo e$i >&2; done",
        ]
        .map(String::from)
        .to_vec()
    }
    #[cfg(windows)]
    {
        [
            "cmd",
            "/c",
            "for /l %i in (1,1,200) do @(echo line%i& echo e%i 1>&2)",
        ]
        .map(String::from)
        .to_vec()
    }
}

/// `head` followed by [`noisy_argv`], as the argument list of one call.
fn with_noisy(head: &[&str]) -> Vec<String> {
    head.iter()
        .map(|a| a.to_string())
        .chain(noisy_argv())
        .collect()
}

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
        let args = with_noisy(&["exec", HOST_ALIAS, verbosity, mode, "--"]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = fleet.client.qsh(&args);

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

/// `qsh sessions` with all three filters set: the count line is a human
/// diagnostic, so machine mode keeps one envelope on stdout and no filter
/// echo anywhere in `data` (ADR-0033 decision 3).
#[test]
fn a_filtered_sessions_listing_keeps_stdout_pure_json_at_every_verbosity() {
    let fleet = Fleet::start();

    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = fleet.client.qsh(&[
            "sessions",
            HOST_ALIAS,
            "--state",
            "running",
            "--writer",
            "none",
            "--attachable",
            verbosity,
            mode,
        ]);
        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(lines.len(), 1, "{label}: one envelope, one line");
        assert_eq!(lines[0]["command"], "session.list", "{label}");
        assert_eq!(lines[0]["ok"], true, "{label}");
        let keys: Vec<&String> = lines[0]["data"]
            .as_object()
            .expect("data object")
            .keys()
            .collect();
        assert_eq!(keys, ["sessions"], "{label}: no new field in data");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("showing"),
            "{label}: the human count line is not a machine-mode diagnostic"
        );
    }
}

/// M9 plan Step 2 (b9a621b): refusing `trust accept` for lack of a code must
/// not leak the terminal-prompt wording onto stdout at any verbosity —
/// the resolver never opens the prompt in machine mode, so there is
/// nothing to leak, but this pins that as a regression test rather than
/// leaving it to the resolver's own unit test alone.
#[test]
fn trust_accept_with_no_code_keeps_stdout_pure_json_at_every_verbosity() {
    let client = Sandbox::initialized();
    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = client.qsh(&["trust", "accept", "127.0.0.1:1", verbosity, mode]);
        assert_eq!(exit_code(&output), 255, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(lines.len(), 1, "{label}");
        assert_eq!(lines[0]["ok"], false, "{label}");
        assert_eq!(lines[0]["command"], "trust.accept", "{label}");
        assert_eq!(lines[0]["error"]["code"], "INVALID_ARGUMENT", "{label}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains(qsh_core::ops::INVITE_CODE_PROMPT),
            "{label}: {stdout:?}"
        );
    }
}

/// `qsh trust invite`'s candidate-address block is a human-mode-only
/// channel (`docs/CLI.md` §6.11): `--json`/`--jsonl` must make no route
/// query at all, so neither wording constant can appear on stdout, and the
/// envelope's `data` object still carries exactly its three contract keys.
#[test]
fn trust_invite_keeps_stdout_pure_json_and_free_of_the_address_block_at_every_verbosity() {
    use qsh_core::trust::invite_address::{INVITE_ADDRESS_HEADING, INVITE_ADDRESS_NONE};

    let client = Sandbox::initialized();
    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = client.qsh(&["trust", "invite", verbosity, mode]);
        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(lines.len(), 1, "{label}");
        assert_eq!(lines[0]["ok"], true, "{label}");
        assert_eq!(lines[0]["command"], "trust.invite", "{label}");
        let keys: Vec<&str> = lines[0]["data"]
            .as_object()
            .expect("data object")
            .keys()
            .map(String::as_str)
            .collect();
        // Alphabetical: see `qsh_proto::types::trust`'s own key-set test.
        assert_eq!(
            keys,
            ["accept_command", "assigned_role", "code", "expires_at"],
            "{label}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for wording in [INVITE_ADDRESS_HEADING, INVITE_ADDRESS_NONE] {
            assert!(!stdout.contains(wording), "{label}: {stdout:?}");
        }
    }
}

/// Assert that `stdout` is one or more lines, each a complete
/// `qsh.event/v1` object, and return them. Deliberately a separate parser
/// from [`parse_stdout_lines`]: a follower streams bare events, so the
/// envelope schema must *not* appear (`docs/CLI.md` §6.4).
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
#[test]
fn a_noisy_follow_keeps_every_stdout_line_a_complete_json_event() {
    let fleet = Fleet::start();
    let args = with_noisy(&["session", "open", HOST_ALIAS, "--json", "--"]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, opened) = fleet.client.json(&args);
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

/// The reverse-route counterpart of the test above (M3 plan Step 7 (2473c88)
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

    let args = with_noisy(&["session", "open", NAME, "--json", "--"]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, opened) = controller.json(&args);
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
/// accept/close `tracing::debug!`s, M4 plan Step 6 (2473c88)) — a completely
/// different code path from every value op above — and stdout must still
/// carry nothing but the one `tunnel.open` envelope for as long as the
/// process holds (`docs/CLI.md` §6.14: it blocks in `TunnelHold::hold`
/// right after printing that envelope), so "every stdout line is pure
/// JSON" here specifically means "there is never a second line".
///
/// Forward-route only (client-side `-L` bind), like `tunnel_e2e.rs`; the
/// reverse route's stdout is the same renderer.
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

/// `-D`'s twin of the test just above (ADR-0019 decision 11):
/// `tunnel.dynamic` is a value-once-then-hold op exactly like `tunnel.open`
/// is, so the same "never a second stdout line" property has to hold once
/// a real SOCKS5 CONNECT drives traffic through the listener and produces
/// its own `qsh::tunnel` diagnostics. Unlike the `-L` test just above,
/// the CONNECT here targets a loopback destination on purpose and is
/// expected to come back `REP 0x02` — the host-local dial filter
/// (`dial-filter.v1`, ADR-0019 decision 3) denies it, since `-D`'s whole
/// point is that this filter is always on, and a real non-loopback
/// destination is not something a portable test can rely on being
/// reachable. `qsh::tunnel::dynamic: CONNECT`'s own debug log fires once
/// the request is parsed, before the dial is attempted, so it is on
/// stderr regardless of that outcome. Forward-route only, like
/// `a_tunnel_in_progress_…` above.
#[test]
fn a_dynamic_tunnel_in_progress_keeps_stdout_pure_json_while_qsh_tunnel_diagnostics_land_on_stderr()
{
    let fleet = Fleet::start();

    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let listen_port = TcpListener::bind("127.0.0.1:0")
            .expect("pick a free listen port")
            .local_addr()
            .expect("port")
            .port();

        let mut child = fleet
            .client
            .command(&[
                "tunnel",
                "open",
                HOST_ALIAS,
                "--dynamic",
                &listen_port.to_string(),
                verbosity,
                mode,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{label}: spawn qsh tunnel open --dynamic: {e}"));

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

        poll_until(
            &format!("{label}: the tunnel.dynamic envelope line"),
            Duration::from_secs(10),
            || (!stdout_lines.lock().unwrap().is_empty()).then_some(()),
        );

        // Speak SOCKS5 through the listener and drive one CONNECT — see
        // this test's own doc for why the destination is loopback and the
        // expected `REP` is the host-local filter's denial, not success.
        let mut conn = TcpStream::connect(("127.0.0.1", listen_port))
            .unwrap_or_else(|e| panic!("{label}: connect to the SOCKS listener: {e}"));
        conn.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set read timeout");
        conn.write_all(&[0x05, 0x01, 0x00])
            .expect("write socks5 greeting");
        let mut greeting_reply = [0u8; 2];
        conn.read_exact(&mut greeting_reply)
            .expect("read socks5 method-select reply");
        assert_eq!(greeting_reply, [0x05, 0x00], "{label}: expected no-auth");
        let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        connect_req.extend_from_slice(&1u16.to_be_bytes());
        conn.write_all(&connect_req).expect("write socks5 connect");
        let mut connect_reply = [0u8; 10];
        conn.read_exact(&mut connect_reply)
            .expect("read socks5 connect reply");
        assert_eq!(
            connect_reply[1], 0x02,
            "{label}: expected the host-local dial filter to deny a loopback destination"
        );
        drop(conn);

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
            "{label}: exactly one tunnel.dynamic envelope, no more, while holding: {lines:?}"
        );
        let envelope: Value = serde_json::from_str(&lines[0])
            .unwrap_or_else(|e| panic!("{label}: stdout line is not JSON: {e}: {:?}", lines[0]));
        assert_eq!(envelope["schema"], "qsh.cli/v1", "{label}");
        assert_eq!(envelope["command"], "tunnel.dynamic", "{label}");
        assert_eq!(envelope["ok"], true, "{label}: {envelope}");

        let stderr = stderr_text.lock().unwrap();
        assert!(
            stderr.contains("qsh::tunnel"),
            "{label}: expected qsh::tunnel diagnostics on stderr, got {stderr:?}"
        );
    }
}

// --- `qsh identity export` (ADR-0013) ---
//
// Without `--out`, machine mode's whole point is to hand the caller the PEM
// (the golden fixture `identity.export.json` pins exactly this shape), so
// `-----BEGIN` necessarily appears *inside* the envelope's `cert_pem`
// string. What purity actually promises here — and what these tests
// check — is that the PEM never escapes that one field onto a second raw
// stdout line: the whole line still parses as one `qsh.cli/v1` JSON object,
// and `cert_pem` is well-formed PEM text, never a partial or doubled block.
// The literal "never `-----BEGIN` on stdout" guarantee is real for the
// `--out` variant, where the cert goes to the file and never touches
// stdout at all — checked below in both machine and human mode.

/// `--json`/`--jsonl`, no `--out`: exactly one JSON line, and the PEM is
/// confined to `data.cert_pem` as one well-formed certificate block.
#[test]
fn identity_export_json_and_jsonl_confine_the_pem_to_one_field_on_one_line() {
    for mode in ["--json", "--jsonl"] {
        let sandbox = Sandbox::initialized();
        let output = sandbox.qsh(&["identity", "export", mode]);
        assert_eq!(exit_code(&output), 0, "{mode}");
        let lines = parse_stdout_lines(&output.stdout, mode);
        assert_eq!(
            lines.len(),
            1,
            "{mode}: identity.export is a value operation — one envelope, one line"
        );
        assert_eq!(lines[0]["command"], "identity.export", "{mode}");
        let cert_pem = lines[0]["data"]["cert_pem"]
            .as_str()
            .unwrap_or_else(|| panic!("{mode}: data.cert_pem must be a string: {}", lines[0]));
        assert_eq!(
            cert_pem.matches("-----BEGIN CERTIFICATE-----").count(),
            1,
            "{mode}: exactly one certificate block: {cert_pem:?}"
        );
        assert_eq!(
            cert_pem.matches("-----END CERTIFICATE-----").count(),
            1,
            "{mode}: exactly one certificate block: {cert_pem:?}"
        );
        assert!(
            !cert_pem.contains("PRIVATE KEY"),
            "{mode}: never a private key: {cert_pem:?}"
        );
    }
}

/// `--out PATH`: neither JSON mode nor human mode ever puts PEM text on
/// stdout — the cert goes to the file, full stop.
#[test]
fn identity_export_with_out_never_puts_pem_text_on_stdout_in_either_mode() {
    for json_mode in [false, true] {
        let sandbox = Sandbox::initialized();
        let dir = tempfile::tempdir().expect("tempdir");
        let out_path = dir.path().join("device.pem");
        let mut args = vec!["identity", "export", "--out"];
        let out_str = out_path.to_str().unwrap().to_string();
        args.push(&out_str);
        if json_mode {
            args.push("--json");
        }
        let output = sandbox.qsh(&args);
        assert_eq!(exit_code(&output), 0, "json_mode={json_mode}");
        let stdout = String::from_utf8(output.stdout).expect("stdout must be utf-8");
        assert!(
            !stdout.contains("-----BEGIN"),
            "json_mode={json_mode}: --out must never leak PEM text to stdout: {stdout:?}"
        );
        let file_contents = std::fs::read_to_string(&out_path).expect("read --out file");
        assert_eq!(
            file_contents.matches("-----BEGIN CERTIFICATE-----").count(),
            1,
            "json_mode={json_mode}: the file itself must hold exactly one certificate block"
        );
        if json_mode {
            let lines = parse_stdout_lines(stdout.as_bytes(), "identity export --out --json");
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0]["data"]["cert_pem"], Value::Null);
            assert_eq!(lines[0]["data"]["path"].as_str().unwrap(), out_str);
        }
    }
}

/// Human mode, no `--out`: exactly one `CERTIFICATE` block on stdout and no
/// `PRIVATE KEY` substring anywhere.
#[test]
fn identity_export_human_mode_without_out_prints_exactly_one_certificate_block() {
    let sandbox = Sandbox::initialized();
    let output = sandbox.qsh(&["identity", "export"]);
    assert_eq!(exit_code(&output), 0);
    let stdout = String::from_utf8(output.stdout).expect("stdout must be utf-8");
    assert_eq!(
        stdout.matches("-----BEGIN CERTIFICATE-----").count(),
        1,
        "{stdout:?}"
    );
    assert_eq!(
        stdout.matches("-----END CERTIFICATE-----").count(),
        1,
        "{stdout:?}"
    );
    assert!(!stdout.contains("PRIVATE KEY"), "{stdout:?}");
}

/// `qsh identity move-key` (ADR-0032 결정 15) is a value operation: one
/// `qsh.cli/v1` line at any verbosity, in both machine modes, and nothing of
/// the key anywhere. The key is already in the requested store here, so the
/// run touches no key store (the moving path needs a fake platform store
/// that a spawned binary cannot have; `identity_move_key.rs` covers it
/// in-process).
#[test]
fn identity_move_key_keeps_stdout_pure_json_at_every_verbosity() {
    let sandbox = Sandbox::initialized();
    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = sandbox.qsh(&["identity", "move-key", "--to", "file", verbosity, mode]);
        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(lines.len(), 1, "{label}: one envelope line");
        assert_eq!(lines[0]["ok"], true, "{label}");
        assert_eq!(lines[0]["command"], "identity.move_key", "{label}");
        assert_eq!(lines[0]["data"]["moved"], false, "{label}");
    }
}

/// `qsh audit` (`docs/CLI.md` §6.22): stdout is exactly one `qsh.cli/v1`
/// line at every verbosity, with a planted log that holds a skipped line,
/// and the skipped line's content never reaches either stream.
#[test]
fn audit_query_keeps_stdout_pure_json_at_every_verbosity() {
    let sandbox = Sandbox::initialized();
    crate::audit_query::plant(
        &sandbox,
        &crate::audit_query::series(),
        Some("{\"torn\":\"SECRET-PAYLOAD-must-not-leak"),
    );
    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = sandbox.qsh(&["audit", verbosity, mode]);
        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(lines.len(), 1, "{label}: one envelope line");
        assert_eq!(lines[0]["ok"], true, "{label}");
        assert_eq!(lines[0]["command"], "audit.query", "{label}");
        assert_eq!(lines[0]["data"]["skipped_lines"], 1, "{label}");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!all.contains("SECRET-PAYLOAD"), "{label}: {all}");
    }
}

/// `qsh service install` (`docs/CLI.md` §6.18, ROADMAP M9 (g)): at high
/// verbosity stdout must still be exactly one `qsh.cli/v1` line, with any
/// human-readable activation hint the renderer might print going to
/// stderr only — `render/human.rs`'s `print_service_install` output never
/// reaches stdout in `--json`/`--jsonl` mode, mirroring
/// `trust_accept_with_no_code_keeps_stdout_pure_json_at_every_verbosity`.
/// Runs on every platform: the Windows leg writes the Task Scheduler task
/// definition file and nothing else, and
/// [`fixtures::service_ops_on_windows_use_the_task_definition_file`]
/// (`crates/qsh-cli/tests/it/fixtures.rs`) pins its envelopes.
#[test]
fn service_install_keeps_stdout_pure_json_at_every_verbosity() {
    let sandbox = Sandbox::new();
    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = sandbox.qsh(&["service", "install", verbosity, mode]);
        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(lines.len(), 1, "{label}");
        assert_eq!(lines[0]["ok"], true, "{label}");
        assert_eq!(lines[0]["command"], "service.install", "{label}");
    }
}

/// `qsh service install --activate`, `status --live` and `uninstall
/// --deactivate` (ADR-0032) over a fake `launchctl`/`systemctl`: stdout stays
/// exactly one `qsh.cli/v1` line at high verbosity, and what the manager
/// printed or the renderer would say goes to stderr only. Unix only because
/// the fake manager is a shell script; no real manager is ever called. On
/// Windows `--activate` and `--deactivate` would register and delete a real
/// scheduled task, so they run only over a recording runner in `qsh-core`
/// (`ops::service::tests::windows_manager`), and the one flag that never
/// reaches the manager is the Windows twin below.
#[cfg(unix)]
#[test]
fn service_activation_flags_keep_stdout_pure_json_at_every_verbosity() {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    let sandbox = Sandbox::new();
    let manager = common::FakeServiceManager::new();
    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        for (args, command) in [
            (["service", "install", "--activate"], "service.install"),
            (["service", "status", "--live"], "service.status"),
            (
                ["service", "uninstall", "--deactivate"],
                "service.uninstall",
            ),
        ] {
            let mut full = args.to_vec();
            full.push(verbosity);
            full.push(mode);
            let output = manager.run(&sandbox, &full);
            assert_eq!(exit_code(&output), 0, "{label} {args:?}");
            let lines = parse_stdout_lines(&output.stdout, label);
            assert_eq!(lines.len(), 1, "{label} {args:?}");
            assert_eq!(lines[0]["ok"], true, "{label} {args:?}");
            assert_eq!(lines[0]["command"], command, "{label} {args:?}");
        }
    }
}

/// `service status --live` with no unit file answers `active: false` without
/// asking the Task Scheduler, so its stdout purity can be checked on Windows.
#[cfg(windows)]
#[test]
fn service_status_live_keeps_stdout_pure_json_at_every_verbosity_on_windows() {
    let sandbox = Sandbox::new();
    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        let output = sandbox.qsh(&["service", "status", "--live", verbosity, mode]);
        assert_eq!(exit_code(&output), 0, "{label}");
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(lines.len(), 1, "{label}");
        assert_eq!(lines[0]["ok"], true, "{label}");
        assert_eq!(lines[0]["command"], "service.status", "{label}");
    }
}

/// `qsh cp` (ADR-0029 decision 18, `docs/CLI.md` §6.21): at high verbosity
/// `--json` is one envelope line, and `--jsonl` is `qsh.event/v1`
/// `file.entry` lines followed by the envelope. No line is anything else,
/// and nothing of the file's contents reaches stdout or stderr.
#[test]
fn cp_keeps_stdout_pure_json_at_every_verbosity() {
    const CANARY: &str = "cp-purity-canary-payload";
    let host = Sandbox::initialized();
    let client = Sandbox::initialized();
    host.trust_add_with_role(common::CLIENT_ALIAS, None, &client.fingerprint(), "full");
    let serve = ServeGuard::start(&host);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host.fingerprint());
    let work = tempfile::tempdir().expect("work dir");
    let src = work.path().join("src.txt");
    std::fs::write(&src, CANARY).expect("write source");
    let src = src.to_str().expect("utf-8 path");

    for (label, mode, verbosity, lines_expected) in [
        ("--jsonl -vv", "--jsonl", "-vv", 2),
        ("--json -vvv", "--json", "-vvv", 1),
    ] {
        // A Windows host takes drive paths with forward slashes.
        let dst = format!(
            "{HOST_ALIAS}:{}",
            work.path()
                .join(format!("out{lines_expected}.txt"))
                .display()
                .to_string()
                .replace('\\', "/")
        );
        let output = client.qsh(&["cp", verbosity, mode, src, &dst]);
        assert_eq!(exit_code(&output), 0, "{label}");
        let text = std::str::from_utf8(&output.stdout).expect("stdout must be utf-8");
        let lines: Vec<Value> = text
            .lines()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|err| panic!("{label}: not a JSON line: {err}: {line:?}"))
            })
            .collect();
        assert_eq!(lines.len(), lines_expected, "{label}: {text}");
        let (envelope, events) = lines.split_last().expect("at least the envelope");
        assert_eq!(envelope["schema"], "qsh.cli/v1", "{label}");
        assert_eq!(envelope["command"], "file.copy", "{label}");
        assert_eq!(envelope["ok"], true, "{label}");
        for event in events {
            assert_eq!(event["schema"], "qsh.event/v1", "{label}");
            assert_eq!(event["type"], "file.entry", "{label}");
        }
        assert!(
            !text.contains(CANARY) && !String::from_utf8_lossy(&output.stderr).contains(CANARY),
            "{label}: file contents must never be printed"
        );
    }
}

/// `pair ssh` is a value operation: `--json` and `--jsonl` both print the
/// one envelope and nothing else on stdout, even at `-vvv`, while the ssh
/// child's own output and the bootstrap diagnostics stay off it.
#[test]
fn pair_ssh_keeps_stdout_pure_json_at_every_verbosity() {
    use crate::ssh_bootstrap::pair::World;

    for (label, mode, verbosity) in [
        ("--jsonl -vv", "--jsonl", "-vv"),
        ("--json -vvv", "--json", "-vvv"),
    ] {
        // A fresh pair per mode: the second run would otherwise find both
        // pins already in place.
        let world = World::new();
        let output = world.client.qsh(&[
            "pair",
            "ssh",
            "box",
            "--remote-as",
            "laptop",
            verbosity,
            mode,
        ]);
        assert_eq!(
            exit_code(&output),
            0,
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lines = parse_stdout_lines(&output.stdout, label);
        assert_eq!(
            lines.len(),
            1,
            "{label}: pair.ssh is a value operation — one envelope, one line"
        );
        assert_eq!(lines[0]["command"], "pair.ssh", "{label}");
        assert_eq!(lines[0]["ok"], true, "{label}");
    }
}
