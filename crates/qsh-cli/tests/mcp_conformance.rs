//! `qsh mcp` stdio conformance (`docs/CLI.md` §8, `PLAN.md` M6 Step 2 (c),
//! DoD 1's first half, DoD 5).
//!
//! Raw newline-delimited JSON-RPC over the real `qsh mcp` binary's own
//! stdio — deliberately **not** the `rmcp` client SDK (`PLAN.md` §4.1 #5):
//! the point is to prove the server keeps its own wire contract, not that
//! two copies of the same SDK can talk to each other. `rmcp-3.1.4`'s stdio
//! transport (`src/transport/io.rs`) is nothing more than a
//! `BufReader::read_line` in / one JSON object per line out pair over the
//! process's real stdin/stdout, so a bare `std::process::Command` with
//! piped stdio is sufficient (`crates/qsh-cli/src/mcp/mod.rs`'s own
//! `stdio_transport_pair_is_constructible_under_the_pinned_feature_set`
//! compiles the same claim at the unit level; this file exercises it
//! end-to-end).
//!
//! Every request below pins its own JSON-RPC `id` (`1`, `2`, `3`, …)
//! rather than reading it back off the wire: the client controls that
//! field, so nothing about it is volatile and the fixture below needs no
//! `request_id`-style masking (`PLAN.md` §4.1 #2's own "정규화 규칙은 …
//! request_id류 마스킹만 필요할 것" turned out to be avoidable rather than
//! merely simplified — see the module doc on [`INITIALIZE_ID`] and
//! friends). The protocol version is pinned the same way, for the same
//! reason: `docs/CLI.md` §8 does not fix a protocol version, and the
//! server negotiates whatever the client asks for as long as it is one it
//! knows (`rmcp-3.1.4/src/service/server.rs::negotiate_protocol_version`),
//! so leaving it to rmcp's own `ProtocolVersion::default()` would make the
//! `tools/list` fixture's shape depend on a value this crate does not
//! control and a future `rmcp` patch release could change out from under
//! it (SEP-2322's `resultType` field only appears for protocol
//! `2026-07-28`+; pinning below `2026-07-28` keeps the fixture in the
//! older, `resultType`-free shape either way).

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::{CLIENT_ALIAS, Fleet, HOST_ALIAS, Sandbox, ServeGuard};
use serde_json::{Value, json};

/// `id` of the `initialize` request every scenario below sends first.
const INITIALIZE_ID: i64 = 1;
/// `id` of the `tools/list` request.
const TOOLS_LIST_ID: i64 = 2;
/// `id` of the first (and, in a single-call scenario, only) `tools/call`
/// request a scenario sends after the handshake — scenarios that send more
/// than one just increment from here.
const TOOLS_CALL_ID: i64 = 3;

/// The exact, invariant `PERMISSION_DENIED` wording
/// (`qsh_core::acl::PERMISSION_DENIED_MESSAGE`), copied rather than
/// imported — same reasoning `acl_enforcement.rs`'s own copy gives: this
/// file's point is to observe what a real `qsh mcp` subprocess actually put
/// on the wire, not to call into the constant directly.
const PERMISSION_DENIED_MESSAGE: &str =
    "peer is not allowed to perform this operation on this host";

/// A loopback TCP echo server for the `open_tunnel`/`close_tunnel` E2E
/// scenario below — the same role `tunnel_e2e.rs`'s own `start_echo` plays
/// for the CLI's `qsh tunnel open`, reimplemented here rather than shared
/// (`tunnel_e2e.rs`'s helpers are private to that file, not `common`).
/// The accept loop is detached; it lives as long as this test process
/// (one process per test under `nextest`).
fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the echo server");
    let addr = listener.local_addr().expect("echo server address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().expect("clone the echo socket");
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
                let _ = writer.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

/// A port nothing is listening on, released before this returns so the
/// kernel — not this process — is the one that says it was free
/// (`tunnel_e2e.rs`'s own `free_port`, same small race accepted there).
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a free port");
    listener.local_addr().expect("picked port").port()
}

/// Connect to `127.0.0.1:port`, write `payload`, half-close, and read
/// everything that comes back — bounded by [`BOUND`] so a forward that
/// silently drops bytes fails fast instead of hanging the suite.
fn round_trip(port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(BOUND))?;
    socket.set_write_timeout(Some(BOUND))?;
    socket.write_all(payload)?;
    socket.flush()?;
    socket.shutdown(Shutdown::Write)?;
    let mut back = Vec::new();
    socket.read_to_end(&mut back)?;
    Ok(back)
}

/// Retry `f` until it returns `Some`, or panic after [`BOUND`] — the same
/// bounded-wait discipline [`McpClient::wait_bounded`] uses for "has the
/// child exited", applied here to "has the OS actually released this
/// port" — a `TunnelHold`'s listener task is aborted, not synchronously
/// joined (`crate::tunnel::LocalForwardHandle`'s own `Drop`), so the exact
/// instant the fd closes is not observable any other way without this
/// file reaching into `qsh-core` internals it has no business touching.
fn retry_bounded<T>(mut f: impl FnMut() -> Option<T>, what: &str) -> T {
    let deadline = Instant::now() + BOUND;
    loop {
        if let Some(value) = f() {
            return value;
        }
        if Instant::now() >= deadline {
            panic!("{what} did not happen within {BOUND:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// One `tools/call` JSON-RPC request for `name` with `arguments`.
fn call_tool_request(id: i64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        },
    })
}

/// The MCP protocol version this harness declares in `initialize`,
/// pinned rather than left to `rmcp`'s own default — see the module doc.
/// Below `2026-07-28` (SEP-2322) on purpose, so `tools/list`'s
/// `resultType` field stays absent (`ListToolsResult::result_type` is
/// stripped for any peer that negotiated an older version,
/// `rmcp-3.1.4/src/model.rs::strip_result_type_for_legacy_peer`), which is
/// what keeps the fixture to just `{"tools": [...]}`.
const PROTOCOL_VERSION: &str = "2025-11-25";

/// Set this to regenerate `tests/fixtures/mcp/tools_list.json` instead of
/// asserting against it — same env var and semantics as `fixtures.rs`'s own
/// `QSH_UPDATE_FIXTURES` (`docs/design/testing.md` L6, `PLAN.md` M6 Step 2
/// (c): "기존 `QSH_UPDATE_FIXTURES=1` 선례 준용").
const UPDATE_ENV: &str = "QSH_UPDATE_FIXTURES";

/// How long a single stdout line, or the whole process, is allowed to take
/// before a scenario declares it hung rather than waiting forever.
const BOUND: Duration = Duration::from_secs(10);

fn updating() -> bool {
    match std::env::var(UPDATE_ENV) {
        Ok(value) => !value.is_empty() && value != "0",
        Err(_) => false,
    }
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("mcp")
        .join(name)
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("encode json")
}

/// Compare `actual` (already fully deterministic — see the module doc on
/// why no normalization is needed) to the checked-in fixture, or write it
/// when `QSH_UPDATE_FIXTURES=1`.
fn check_fixture(name: &str, actual: &Value) {
    if updating() {
        let path = fixture_path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture dir");
        }
        let mut text = pretty(actual);
        text.push('\n');
        std::fs::write(&path, text).expect("write fixture");
        eprintln!("regenerated {}", path.display());
        return;
    }
    let path = fixture_path(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()));
    let expected: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parsing fixture {}: {e}", path.display()));
    assert_eq!(
        pretty(actual),
        pretty(&expected),
        "fixture {name} no longer matches `qsh mcp`'s tools/list response.\n\
         Fixtures are append-only (docs/CLI.md §10): if this is an intentional \
         tool-surface change it needs a new /v2 or additive-only justification. \
         If you are adding this fixture for the first time, regenerate with \
         {UPDATE_ENV}=1."
    );
}

/// A running `qsh mcp` child wired for raw newline-delimited JSON-RPC.
///
/// stderr is drained on a background thread into a shared buffer (the same
/// technique `common::ServeGuard` uses) rather than read from the test
/// thread on demand: a synchronous `read` against a pipe the child may
/// still be writing to would risk blocking a *diagnostic* helper forever,
/// which would turn a fast test failure into a hang.
struct McpClient {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_reader: Option<JoinHandle<()>>,
}

impl McpClient {
    /// Spawn `qsh [extra..] mcp` in `sandbox`'s isolated config/state dirs
    /// (`common::Sandbox`'s own doc: every test gets its own, so this never
    /// touches a developer's real `qsh` configuration).
    fn spawn(sandbox: &Sandbox, extra: &[&str]) -> Self {
        let mut args: Vec<&str> = extra.to_vec();
        args.push("mcp");
        let mut child = sandbox
            .command(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh mcp");
        let stdin = child.stdin.take().expect("mcp stdin pipe");
        let stdout = BufReader::new(child.stdout.take().expect("mcp stdout pipe"));
        let mut stderr_pipe = child.stderr.take().expect("mcp stderr pipe");
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let stderr_reader = {
            let sink = Arc::clone(&stderr);
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = stderr_pipe.read_to_end(&mut buf);
                sink.lock().unwrap_or_else(|e| e.into_inner()).extend(buf);
            })
        };
        Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr,
            stderr_reader: Some(stderr_reader),
        }
    }

    /// Write one JSON-RPC message as a single newline-terminated line —
    /// the framing `rmcp-3.1.4`'s stdio transport reads
    /// (`crate::mcp::stdio_transport_pair_is_constructible_under_the_pinned_feature_set`'s
    /// own doc).
    fn send(&mut self, message: &Value) {
        let mut line = serde_json::to_string(message).expect("encode json-rpc message");
        line.push('\n');
        let stdin = self.stdin.as_mut().expect("stdin not yet closed");
        stdin
            .write_all(line.as_bytes())
            .expect("write to qsh mcp stdin");
        stdin.flush().expect("flush qsh mcp stdin");
    }

    /// Read exactly one line of stdout and parse it as JSON. Panics (with
    /// the process's own stderr attached) if the line is missing or is not
    /// JSON — either is exactly what DoD 5 ("stdout에는 JSON-RPC frame만")
    /// forbids.
    fn recv(&mut self) -> Value {
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .expect("read qsh mcp stdout");
        assert!(
            read > 0,
            "qsh mcp closed stdout with no response; stderr so far:\n{}",
            self.stderr_so_far()
        );
        serde_json::from_str(line.trim_end()).unwrap_or_else(|e| {
            panic!(
                "qsh mcp stdout line is not JSON: {e}: {line:?}; stderr so far:\n{}",
                self.stderr_so_far()
            )
        })
    }

    /// Whatever stderr has produced so far, best-effort (used only for
    /// panic messages or for a *negative* assertion — "this marker never
    /// appears", `PLAN.md` M6 Step 2+3 검증 라운드 판정 ①/F1's own
    /// regression tests — never for stderr's exact wording, which is not
    /// this file's contract). Never blocks: it reads the background
    /// reader thread's buffer, not the pipe itself, so a still-running
    /// child's stderr may be incomplete here — [`Self::drain_stderr`] is
    /// the bounded-complete version for after the child is known to have
    /// exited or closed its stderr.
    fn stderr_so_far(&self) -> String {
        let buf = self.stderr.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// [`Self::stderr_so_far`], but only after joining the background
    /// reader thread — safe to call once the child is known to have
    /// exited (e.g. right after [`Self::wait_bounded`]), where it is
    /// guaranteed complete rather than a best-effort snapshot.
    fn drain_stderr(&mut self) -> String {
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
        self.stderr_so_far()
    }

    /// Assert stdout has produced nothing further right now (used after
    /// the expected exchange to catch trailing contamination — DoD 5), and
    /// that stdin EOF alone brought the process down cleanly (exit 0).
    fn assert_stdout_quiescent_after_close(mut self) {
        self.close_stdin();
        let status = self.wait_bounded();
        assert!(
            status.success(),
            "qsh mcp exited non-zero ({status:?}) after a clean stdin close; stderr:\n{}",
            self.stderr_so_far()
        );
        let mut trailing = Vec::new();
        self.stdout
            .read_to_end(&mut trailing)
            .expect("drain qsh mcp stdout");
        assert!(
            trailing.is_empty(),
            "qsh mcp wrote extra stdout bytes after the expected JSON-RPC \
             exchange (DoD 5): {trailing:?}"
        );
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }

    /// Close stdin (delivers EOF to the child) without waiting.
    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Poll for the child to exit on its own, bounded by [`BOUND`] — a
    /// clean stdin-EOF shutdown must not hang (`PLAN.md` M6 Step 2 (c)'s
    /// "종료 처리").
    fn wait_bounded(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + BOUND;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                panic!(
                    "qsh mcp did not exit within {BOUND:?} of stdin EOF; stderr so far:\n{}",
                    self.stderr_so_far()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // A scenario that panics mid-exchange must not leak a hung child
        // into the rest of the suite.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn initialize_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": INITIALIZE_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "qsh-mcp-conformance",
                "version": "0.0.0",
            },
        },
    })
}

fn initialized_notification() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
}

fn tools_list_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": TOOLS_LIST_ID,
        "method": "tools/list",
    })
}

/// Perform `initialize` → `notifications/initialized` and assert the
/// handshake is a real one (no `error`, sane `protocolVersion`/
/// `capabilities.tools`/`serverInfo`) — the shared prefix of every
/// scenario below.
fn handshake(client: &mut McpClient) {
    client.send(&initialize_request());
    let response = client.recv();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], INITIALIZE_ID);
    assert!(
        response.get("error").is_none(),
        "initialize failed: {response}"
    );
    let result = &response["result"];
    assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    assert!(
        result["capabilities"]["tools"].is_object(),
        "must declare the tools capability: {result}"
    );
    assert_eq!(result["serverInfo"]["name"], "qsh");
    assert!(result["serverInfo"]["version"].is_string(), "{result}");
    client.send(&initialized_notification());
}

/// DoD 1's first half: `initialize` round trip, then `tools/list` ==
/// the checked-in fixture, byte-for-byte (`docs/CLI.md` §8.2's 12 tools,
/// alphabetical — `PLAN.md` §4.1 #2).
#[test]
fn initialize_then_tools_list_matches_fixture() {
    let sandbox = Sandbox::new();
    let mut client = McpClient::spawn(&sandbox, &[]);
    handshake(&mut client);

    client.send(&tools_list_request());
    let response = client.recv();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], TOOLS_LIST_ID);
    assert!(
        response.get("error").is_none(),
        "tools/list failed: {response}"
    );

    let tools = response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list result has no tools array: {response}"));
    assert_eq!(tools.len(), 12, "{response}");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "tools/list must be alphabetical by tool name (PLAN.md §4.1 #2): {names:?}"
    );

    check_fixture("tools_list.json", &response);

    client.assert_stdout_quiescent_after_close();
}

/// DoD 5, exercised over the real binary at `-vv`: stdout carries only the
/// two JSON-RPC response lines this scenario asked for — nothing before,
/// between, or after them, no matter how verbose stderr gets.
#[test]
fn stdout_is_pure_json_rpc_even_at_vv() {
    let sandbox = Sandbox::new();
    let mut client = McpClient::spawn(&sandbox, &["-vv"]);
    handshake(&mut client);

    client.send(&tools_list_request());
    let response = client.recv();
    assert_eq!(response["id"], TOOLS_LIST_ID, "{response}");
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(
        response["result"]["tools"].as_array().map(Vec::len),
        Some(12),
        "{response}"
    );

    // Nothing else was ever written to stdout: `recv` above read exactly
    // one line per response (a stray diagnostic line ahead of either
    // response would already have failed `recv`'s own JSON parse), and
    // this checks nothing trails them either.
    client.assert_stdout_quiescent_after_close();
}

/// `PLAN.md` M6 Step 2+3 검증 라운드 판정 ①/F1 — regression: `rmcp`'s own
/// `debug!(?request, …)`/`debug!(?result, …)` events (`rmcp-3.1.4/src/
/// service.rs`'s `serve_inner`) `Debug`-format the entire JSON-RPC
/// message — for `write_session`/`read_session`, that is PTY input/output
/// as base64 — at plain `debug` level, so `-vv` (DoD 5 only proved stdout
/// stayed clean; it never checked stderr's *content*) would otherwise put
/// PTY payload on stderr, violating "PTY/command 내용 로그 금지"
/// (`docs/PRD.md` §9 fail-closed discipline, applied here to logging
/// rather than authorization). `init_tracing`'s `rmcp=warn` clamp is the
/// fix — this drives a real session round trip carrying a marker chosen
/// to appear nowhere else in this exchange, at `-vv`, and checks it is
/// absent from stderr both verbatim and as the exact base64 this call
/// site put on the wire for it.
#[cfg(unix)]
#[test]
fn session_payload_never_reaches_stderr_even_at_vv() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    const MARKER: &str = "QSH-MCP-F1-SESSION-SECRET-b7f0b0f6b4f7";

    let fleet = Fleet::start();
    let mut client = McpClient::spawn(&fleet.client, &["-vv"]);
    handshake(&mut client);

    let mut id = TOOLS_CALL_ID;
    client.send(&call_tool_request(
        id,
        "open_session",
        json!({"host": HOST_ALIAS, "argv": ["sh"]}),
    ));
    let response = client.recv();
    assert_eq!(response["result"]["isError"], false, "{response}");
    let session_ref = response["result"]["structuredContent"]["session_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("open_session: no session_ref: {response}"))
        .to_string();

    // `echo`'s the tty will read back — the marker crosses the wire twice:
    // once as this write's own `data_b64`, once inside the read's own
    // `events[].data_b64` a moment later.
    let write_data_b64 = BASE64.encode(format!("echo {MARKER}\n").as_bytes());
    id += 1;
    client.send(&call_tool_request(
        id,
        "write_session",
        json!({"session_ref": session_ref, "data_b64": write_data_b64}),
    ));
    let response = client.recv();
    assert_eq!(response["result"]["isError"], false, "{response}");

    id += 1;
    client.send(&call_tool_request(
        id,
        "read_session",
        json!({"session_ref": session_ref, "after_sequence": 0, "wait_ms": 5000}),
    ));
    let response = client.recv();
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(
        !response["result"]["structuredContent"]["events"]
            .as_array()
            .unwrap_or(&Vec::new())
            .is_empty(),
        "the read must actually see the echoed marker come back through the PTY: {response}"
    );

    id += 1;
    client.send(&call_tool_request(
        id,
        "close_session",
        json!({"session_ref": session_ref}),
    ));
    let response = client.recv();
    assert_eq!(response["result"]["isError"], false, "{response}");

    client.close_stdin();
    client.wait_bounded();
    let stderr = client.drain_stderr();
    assert!(
        !stderr.contains(MARKER),
        "the marker leaked into stderr verbatim at -vv:\n{stderr}"
    );
    let marker_b64 = BASE64.encode(MARKER.as_bytes());
    assert!(
        !stderr.contains(&marker_b64),
        "the marker leaked into stderr as its own base64 at -vv:\n{stderr}"
    );
    assert!(
        !stderr.contains(&write_data_b64),
        "the write_session call's exact wire payload leaked into stderr at -vv:\n{stderr}"
    );
}

/// `PLAN.md` M6 Step 2+3 검증 라운드 판정 ①/F1 — the other half: a
/// `tools/call` sent as the connection's very first message (before
/// `initialize`) makes `rmcp::serve_server` fail with
/// `ServerInitializeError::ExpectedInitializeRequest`, whose own `Display`
/// (`rmcp-3.1.4/src/service/server.rs`) `Debug`-formats the offending
/// message verbatim — `main.rs`'s `run_mcp` puts that on stderr through a
/// plain [`OpError`] message, not through `tracing`, so this leak is
/// **independent of verbosity** (unlike the sibling test above) and the
/// `rmcp=warn` clamp alone does not cover it —
/// `crate::mcp::redact_handshake_error` is the fix this half proves.
#[test]
fn a_tool_call_before_initialize_never_leaks_its_payload_to_stderr() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    const MARKER: &str = "QSH-MCP-F1-PREHANDSHAKE-SECRET-9c1e4a2d";

    let sandbox = Sandbox::new();
    let mut client = McpClient::spawn(&sandbox, &[]);

    // No `initialize` sent first — this is the connection's opening move.
    let data_b64 = BASE64.encode(format!("echo {MARKER}\n").as_bytes());
    client.send(&call_tool_request(
        TOOLS_CALL_ID,
        "write_session",
        json!({"session_ref": "nonexistent-host/01K0NOSUCHSESSION", "data_b64": data_b64}),
    ));

    // The server refuses the out-of-order message and the process ends —
    // no clean-stdin-EOF exit-0 contract applies here, unlike every other
    // scenario in this file.
    client.wait_bounded();
    let stderr = client.drain_stderr();
    assert!(
        !stderr.contains(MARKER),
        "a pre-handshake tools/call leaked its marker into stderr verbatim:\n{stderr}"
    );
    let marker_b64 = BASE64.encode(MARKER.as_bytes());
    assert!(
        !stderr.contains(&marker_b64),
        "a pre-handshake tools/call leaked its marker into stderr as base64:\n{stderr}"
    );
    assert!(
        !stderr.contains(&data_b64),
        "a pre-handshake tools/call leaked its exact wire payload into stderr:\n{stderr}"
    );
}

/// Regression proof for the conformance harness itself (task item ⑤): a
/// tool silently dropped from the adapter's tool surface must fail
/// `initialize_then_tools_list_matches_fixture`, not pass silently. This
/// does not mutate `tool_schemas` — it re-derives the same "one tool
/// missing" shape the fixture comparison would see and asserts the
/// comparison catches it, without touching checked-in state.
#[test]
fn a_dropped_tool_would_fail_the_fixture_comparison() {
    let expected = std::fs::read_to_string(fixture_path("tools_list.json"))
        .expect("read tools_list.json fixture");
    let expected: Value = serde_json::from_str(&expected).expect("parse fixture");
    let mut mutated = expected.clone();
    let tools = mutated["result"]["tools"]
        .as_array_mut()
        .expect("fixture has a tools array");
    assert_eq!(tools.len(), 12, "fixture must start at the full 12 tools");
    tools.remove(0); // simulate one tool silently dropped from tool_schemas()

    assert_ne!(
        pretty(&mutated),
        pretty(&expected),
        "a tool dropped from the surface must be distinguishable from the fixture — \
         if this ever passes, the fixture comparison above has stopped being able to \
         catch a shrunk tool surface"
    );
}

/// `PLAN.md` M6 Step 2 (a)-추기 ②'s prediction, now realized: Step 3 wires
/// `call_tool` for every listed tool, so this file's old
/// `calling_a_listed_tool_before_step_3_is_a_clean_protocol_error` no
/// longer holds — it is replaced by the success/error-path scenarios below
/// (`open_write_read_close_session_and_exec_round_trip_through_real_ops`,
/// `deny_policy_returns_permission_denied_as_a_structured_tool_error`). The
/// one piece of that old test still true after Step 3: an **unlisted** tool
/// name is still a clean JSON-RPC **protocol** error (`-32601 Method not
/// found`, `ServerHandler::call_tool`'s own doc on why "no such tool" is
/// not routed through `CallToolResult`), not a hang and not a stdout byte
/// outside the JSON-RPC frame.
#[test]
fn calling_an_unlisted_tool_is_still_a_clean_protocol_error() {
    let sandbox = Sandbox::new();
    let mut client = McpClient::spawn(&sandbox, &[]);
    handshake(&mut client);

    client.send(&call_tool_request(TOOLS_CALL_ID, "no_such_tool", json!({})));
    let response = client.recv();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], TOOLS_CALL_ID);
    assert!(
        response.get("result").is_none(),
        "an unlisted tool name must not report success: {response}"
    );
    assert_eq!(
        response["error"]["code"], -32601,
        "expected JSON-RPC Method not found: {response}"
    );

    client.assert_stdout_quiescent_after_close();
}

/// `PLAN.md` M6 Step 3 (c) — the success-path conformance harness owed for
/// DoD 1: `open_session` → `write_session` → `read_session` (one pull) →
/// `close_session`, plus `exec`, all through real `tools/call` requests
/// against a real `qsh serve` host (`common::Fleet`, which plants the same
/// allow-all `acl.toml` `docs/CLI.md` §8.4's "각 tool call에 일반 CLI와
/// 동일한 ACL을 적용한다" lets every other E2E fixture in this crate rely
/// on). Mirrors `tests/fixtures.rs`'s `golden_session_fixtures`'s own
/// open→read→write→…→close shape, but through MCP tool calls instead of
/// `qsh session …` subcommands, and in the order task item ⑤(i) asks for
/// (write before the first read, not after).
#[cfg(unix)]
#[test]
fn open_write_read_close_session_and_exec_round_trip_through_real_ops() {
    let fleet = Fleet::start();
    let mut client = McpClient::spawn(&fleet.client, &[]);
    handshake(&mut client);

    let mut id = TOOLS_CALL_ID;

    // open_session: a plain `sh`, no argv override needed beyond that —
    // same shape `fixtures.rs`'s own `golden_session_fixtures` opens.
    client.send(&call_tool_request(
        id,
        "open_session",
        json!({"host": HOST_ALIAS, "argv": ["sh"]}),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    let opened = &response["result"]["structuredContent"];
    let session_ref = opened["session_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("open_session: no session_ref: {response}"))
        .to_string();
    assert!(
        session_ref.starts_with(&format!("{HOST_ALIAS}/")),
        "{response}"
    );

    // write_session: "hi\n" (base64 `aGkK`, `fixtures.rs`'s own constant) —
    // the tty echoes it back, growing the ring by exactly 3 bytes.
    id += 1;
    client.send(&call_tool_request(
        id,
        "write_session",
        json!({"session_ref": session_ref, "data_b64": "aGkK"}),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["bytes_written"], 3,
        "{response}"
    );

    // read_session: one pull from the start — a single round trip, not the
    // long-poll cancellation semantics Step 4 owns (this file's module doc,
    // `QshMcpServer::call_tool`'s own doc on `read_session`).
    id += 1;
    client.send(&call_tool_request(
        id,
        "read_session",
        json!({"session_ref": session_ref, "after_sequence": 0, "wait_ms": 5000}),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    let read = &response["result"]["structuredContent"];
    assert_eq!(read["session_ref"], session_ref, "{response}");
    let events = read["events"]
        .as_array()
        .unwrap_or_else(|| panic!("read_session: no events array: {response}"));
    assert!(!events.is_empty(), "{response}");

    // close_session.
    id += 1;
    client.send(&call_tool_request(
        id,
        "close_session",
        json!({"session_ref": session_ref}),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["session_ref"], session_ref,
        "{response}"
    );

    // exec: a fresh, independent op — same host, no session involved.
    id += 1;
    client.send(&call_tool_request(
        id,
        "exec",
        json!({"host": HOST_ALIAS, "argv": ["true"]}),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["remote_exit_code"], 0,
        "{response}"
    );

    client.assert_stdout_quiescent_after_close();
}

/// `PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2 — the E2E this fix owes:
/// `open_tunnel` really forwards bytes (not just returns an envelope),
/// `close_tunnel` truthfully reports `closed: true` (the pre-fix bug: it
/// always answered `closed: false` while a detached, unregistered thread
/// kept forwarding forever), the listener is actually gone by the time
/// that response arrives — not merely signalled — and the freed port can
/// be reopened immediately. `qsh_core::ops::tunnel::Ops::
/// tunnel_open_and_hold`'s own doc has the fix; this is the real-binary
/// proof it works end to end, over the same forward route
/// `tunnel_e2e.rs`'s CLI-facing `tunnel_open_reports_the_bound_forward_and_holds_it`
/// exercises for `qsh tunnel open` directly.
#[cfg(unix)]
#[test]
fn open_tunnel_forwards_then_close_tunnel_truthfully_releases_the_port() {
    let fleet = Fleet::start();
    let echo = start_echo();
    let local_port = free_port();
    let mut client = McpClient::spawn(&fleet.client, &[]);
    handshake(&mut client);

    let mut id = TOOLS_CALL_ID;

    // open_tunnel: a "local" forward from `local_port` to the echo server.
    client.send(&call_tool_request(
        id,
        "open_tunnel",
        json!({
            "host": HOST_ALIAS,
            "mode": "local",
            "listen_port": local_port,
            "forward_host": "127.0.0.1",
            "forward_port": echo.port(),
        }),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    let opened = &response["result"]["structuredContent"];
    let tunnel_id = opened["tunnel_id"]
        .as_str()
        .unwrap_or_else(|| panic!("open_tunnel: no tunnel_id: {response}"))
        .to_string();
    assert_eq!(opened["mode"], "local", "{response}");
    assert_eq!(opened["actual_port"], local_port, "{response}");

    // The tool call already returned — prove the forward is real: send
    // bytes into the bound local port and get them back from the echo
    // server on the other side of the tunnel.
    let sent = b"qsh mcp open_tunnel F2 E2E".to_vec();
    let back = round_trip(local_port, &sent).expect("round trip through the MCP-held tunnel");
    assert_eq!(back, sent, "the held tunnel corrupted the payload");

    // Still held: a second bind on the same port must fail, or the round
    // trip above would have proven nothing about *this* listener.
    assert!(
        TcpListener::bind(("127.0.0.1", local_port)).is_err(),
        "the forward's listener should still own {local_port} while the tunnel is open"
    );

    // close_tunnel: must report `closed: true` — truthfully. Before the F2
    // fix this was always `closed: false` here, because the detached hold
    // thread was registered nowhere `tunnel_close` could find it.
    id += 1;
    client.send(&call_tool_request(
        id,
        "close_tunnel",
        json!({"tunnel_id": tunnel_id}),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["closed"], true,
        "close_tunnel must truthfully report the forward it just tore down: {response}"
    );

    // The port is released — proven by rebinding it, bounded rather than
    // immediate: the held listener's task is *aborted*, not synchronously
    // joined, so the exact instant the fd closes relative to this
    // response landing is not guaranteed to be "already" from outside
    // `qsh-core` (`retry_bounded`'s own doc). A real defect (close not
    // tearing the forward down at all) still fails this — it would never
    // succeed inside `BOUND`, not just arrive late.
    let rebound = retry_bounded(
        || TcpListener::bind(("127.0.0.1", local_port)).ok(),
        &format!("port {local_port} being released by close_tunnel"),
    );
    drop(rebound);

    // Idempotent: closing the same, already-closed `tunnel_id` again is
    // `closed: false`, not an error — the same contract every other
    // `tunnel.close` caller gets for an id nothing currently holds
    // (`docs/CLI.md` §6.9).
    id += 1;
    client.send(&call_tool_request(
        id,
        "close_tunnel",
        json!({"tunnel_id": tunnel_id}),
    ));
    let response = client.recv();
    assert_eq!(response["id"], id, "{response}");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["closed"], false,
        "closing an already-closed tunnel_id must be idempotent, not an error: {response}"
    );

    client.assert_stdout_quiescent_after_close();
}

/// `PLAN.md` M6 Step 2+3 검증 라운드 판정 ③/F3(i) — before this fix, only
/// 7 of the 12 tools (`open_session`/`write_session`/`read_session`/
/// `close_session`/`exec`, above, plus `open_tunnel`/`close_tunnel`,
/// F2's own test) were ever driven through a real `tools/call`; the other
/// 5 (`list_hosts`/`get_host`/`list_sessions`/`get_session`/
/// `resize_session`) had no conformance coverage at all — a match-string
/// typo routing one of them to `McpError::method_not_found` instead of its
/// `Ops` call (the verifier's "Mutation A": a `resize_session` typo in
/// `QshMcpServer::call_tool`'s router) would have passed every existing
/// test. This exercises all 5, and — reading each tool's `outputSchema`
/// straight from this same server's own `tools/list` response, no new
/// dependency — asserts every successful `structuredContent` this test
/// produces (for all 12 tools, not just the 5: the 7 already-covered ones
/// get the same schema check for free by sharing the helper) actually
/// carries every field its own advertised `outputSchema.required` lists.
#[cfg(unix)]
#[test]
fn all_twelve_tools_execute_and_match_their_advertised_output_schema() {
    let fleet = Fleet::start();
    let mut client = McpClient::spawn(&fleet.client, &[]);
    handshake(&mut client);

    client.send(&tools_list_request());
    let tools_list_response = client.recv();
    let required = required_fields_by_tool(&tools_list_response);

    let mut id = TOOLS_CALL_ID;
    let mut call = |client: &mut McpClient, name: &str, arguments: Value| -> Value {
        id += 1;
        client.send(&call_tool_request(id, name, arguments));
        let response = client.recv();
        assert_eq!(response["id"], id, "{name}: {response}");
        assert_eq!(response["result"]["isError"], false, "{name}: {response}");
        let structured = response["result"]["structuredContent"].clone();
        assert_required_fields_present(name, &structured, &required);
        structured
    };

    // list_hosts: `Fleet::start` already trust_add'd HOST_ALIAS on the
    // client side, so this is a real, non-empty listing.
    let listed = call(&mut client, "list_hosts", json!({}));
    let hosts = listed["hosts"]
        .as_array()
        .unwrap_or_else(|| panic!("list_hosts: no hosts array: {listed}"));
    assert!(
        hosts.iter().any(|h| h["name"] == HOST_ALIAS),
        "list_hosts must see the fleet's own trusted host: {listed}"
    );

    // get_host.
    let got_host = call(&mut client, "get_host", json!({"name": HOST_ALIAS}));
    assert_eq!(got_host["name"], HOST_ALIAS, "{got_host}");

    // open_session, to have a real session_ref for list_sessions/
    // get_session/resize_session to exercise against.
    let opened = call(
        &mut client,
        "open_session",
        json!({"host": HOST_ALIAS, "argv": ["sh"]}),
    );
    let session_ref = opened["session_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("open_session: no session_ref: {opened}"))
        .to_string();

    // list_sessions: scoped to HOST_ALIAS so the assertion below is exact
    // rather than "at least the one we opened, among however many other
    // fixtures' sessions happen to be live" — this file's own tests never
    // share a host, but scoping is free and makes the intent explicit.
    let listed_sessions = call(&mut client, "list_sessions", json!({"host": HOST_ALIAS}));
    let sessions = listed_sessions["sessions"]
        .as_array()
        .unwrap_or_else(|| panic!("list_sessions: no sessions array: {listed_sessions}"));
    assert!(
        sessions.iter().any(|s| s["session_ref"] == session_ref),
        "list_sessions must see the session just opened: {listed_sessions}"
    );

    // get_session.
    let got_session = call(
        &mut client,
        "get_session",
        json!({"session_ref": session_ref}),
    );
    assert_eq!(got_session["session_ref"], session_ref, "{got_session}");

    // resize_session — the verifier's "Mutation A" target.
    let resized = call(
        &mut client,
        "resize_session",
        json!({"session_ref": session_ref, "cols": 100, "rows": 40}),
    );
    assert_eq!(resized["session_ref"], session_ref, "{resized}");
    assert_eq!(resized["cols"], 100, "{resized}");
    assert_eq!(resized["rows"], 40, "{resized}");

    // close_session, so this test leaves nothing running behind it.
    call(
        &mut client,
        "close_session",
        json!({"session_ref": session_ref}),
    );

    client.assert_stdout_quiescent_after_close();
}

/// Read `tools/list`'s own response for each tool's `outputSchema.required`
/// array — `PLAN.md` M6 Step 2+3 검증 라운드 판정 ③/F3(i)'s "새 의존성
/// 추가 금지" constraint: this is a JSON-level read of the same response
/// [`initialize_then_tools_list_matches_fixture`] already checks against
/// the fixture, not a `schemars`/JSON-Schema-validator dependency.
fn required_fields_by_tool(
    tools_list_response: &Value,
) -> std::collections::HashMap<String, Vec<String>> {
    let tools = tools_list_response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list has no tools array: {tools_list_response}"));
    tools
        .iter()
        .map(|tool| {
            let name = tool["name"]
                .as_str()
                .expect("every tool has a name")
                .to_string();
            let required = tool["outputSchema"]["required"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .expect("required entries are strings")
                                .to_string()
                        })
                        .collect()
                })
                .unwrap_or_default();
            (name, required)
        })
        .collect()
}

/// Assert `structured_content` (a successful `tools/call`'s
/// `structuredContent`) has every field `tool_name`'s own advertised
/// `outputSchema.required` lists — the field just needs to be *present*
/// (`serde_json::Value::get`, not truthy/non-null: `false`/`0`/`""` are all
/// legitimate required-field values elsewhere in this contract).
fn assert_required_fields_present(
    tool_name: &str,
    structured_content: &Value,
    required: &std::collections::HashMap<String, Vec<String>>,
) {
    let Some(fields) = required.get(tool_name) else {
        panic!("{tool_name} does not appear in tools/list at all");
    };
    for field in fields {
        assert!(
            structured_content.get(field).is_some(),
            "{tool_name}'s structuredContent is missing required field {field:?} \
             (outputSchema.required = {fields:?}): {structured_content}"
        );
    }
}

/// `PLAN.md` M6 Step 2+3 검증 라운드 판정 ③/F3(ii) — every tool
/// `tools/list` advertises must actually be routable through
/// `tools/call`: calling each with minimal (empty-object) arguments must
/// never come back a JSON-RPC `-32601` (method not found) — a
/// [`CallToolResult`] with `isError: true` (e.g. `INVALID_ARGUMENT` from
/// failing to deserialize an empty object into a `*Req` that needs fields)
/// is an acceptable pass, since that is the tool being reached and
/// rejecting its input, not the router failing to find it at all.
#[test]
fn every_advertised_tool_is_routable_with_minimal_arguments() {
    let sandbox = Sandbox::new();
    let mut client = McpClient::spawn(&sandbox, &[]);
    handshake(&mut client);

    client.send(&tools_list_request());
    let tools_list_response = client.recv();
    let names: Vec<String> = tools_list_response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list has no tools array: {tools_list_response}"))
        .iter()
        .map(|t| t["name"].as_str().expect("tool name").to_string())
        .collect();
    assert_eq!(names.len(), 12, "{tools_list_response}");

    let mut id = TOOLS_CALL_ID;
    for name in &names {
        id += 1;
        client.send(&call_tool_request(id, name, json!({})));
        let response = client.recv();
        assert_eq!(response["id"], id, "{name}: {response}");
        assert!(
            response.get("error").is_none() || response["error"]["code"] != -32601,
            "{name} must be routable via tools/call, not -32601: {response}"
        );
    }

    client.assert_stdout_quiescent_after_close();
}

/// `PLAN.md` M6 Step 3 (c), error shape revised by M6 Step 2+3 검증 라운드
/// 판정 ⑤/F5 — the error-path conformance harness owed for DoD 1: under a
/// default-deny policy (`ServeGuard::start_without_policy`,
/// `acl_enforcement.rs`'s own precedent), `open_session` over MCP comes back
/// a `PERMISSION_DENIED` error whose `content[0].text` carries M5's uniform
/// rejection wording verbatim as `docs/CLI.md` §3.2 JSON — the same fixed,
/// non-distinguishing message every other authorization choke point in this
/// codebase uses, now pinned on the MCP tool surface too — and whose
/// `structuredContent` is absent (`op_error_result`'s own doc, `mcp/mod.rs`,
/// explains why: the error object does not conform to `open_session`'s
/// success-shaped `outputSchema`, so it must not be offered as
/// `structuredContent`).
#[test]
fn deny_policy_returns_permission_denied_as_a_structured_tool_error() {
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fp = host.fingerprint();
    let client_fp = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fp);
    let serve = ServeGuard::start_without_policy(&host, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fp);

    let mut mcp = McpClient::spawn(&client, &[]);
    handshake(&mut mcp);

    mcp.send(&call_tool_request(
        TOOLS_CALL_ID,
        "open_session",
        json!({"host": HOST_ALIAS, "argv": ["sh"]}),
    ));
    let response = mcp.recv();
    assert_eq!(response["id"], TOOLS_CALL_ID, "{response}");
    assert!(
        response.get("error").is_none(),
        "an OpError must never be promoted to a JSON-RPC protocol error: {response}"
    );
    let result = &response["result"];
    assert_eq!(result["isError"], true, "{response}");
    assert!(
        result.get("structuredContent").is_none() || result["structuredContent"].is_null(),
        "an error result must not carry structuredContent \
         (it does not conform to the tool's success-shaped outputSchema): {response}"
    );
    let content = result["content"]
        .as_array()
        .unwrap_or_else(|| panic!("error result must carry content: {response}"));
    assert_eq!(content.len(), 1, "{response}");
    assert_eq!(content[0]["type"], "text", "{response}");
    let error: Value = serde_json::from_str(
        content[0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("content[0].text must be a string: {response}")),
    )
    .unwrap_or_else(|err| {
        panic!("content[0].text must be the §3.2 JSON object: {err}: {response}")
    });
    assert_eq!(error["code"], "PERMISSION_DENIED", "{response}");
    assert_eq!(error["message"], PERMISSION_DENIED_MESSAGE, "{response}");
    assert_eq!(error["retryable"], false, "{response}");

    mcp.assert_stdout_quiescent_after_close();
}

/// `PLAN.md` M6 Step 2 (c): stdin EOF ends the server cleanly (exit 0),
/// with no signal needed — `qsh mcp`'s own doc on why it has no
/// SIGINT/SIGTERM handling.
#[test]
fn stdin_eof_shuts_the_server_down_cleanly() {
    let sandbox = Sandbox::new();
    let mut client = McpClient::spawn(&sandbox, &[]);
    handshake(&mut client);
    client.assert_stdout_quiescent_after_close();
}
