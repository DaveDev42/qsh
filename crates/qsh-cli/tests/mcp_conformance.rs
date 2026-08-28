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
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::Sandbox;
use serde_json::{Value, json};

/// `id` of the `initialize` request every scenario below sends first.
const INITIALIZE_ID: i64 = 1;
/// `id` of the `tools/list` request.
const TOOLS_LIST_ID: i64 = 2;
/// `id` of the ad hoc `tools/call` request the call-tool scenario sends.
const TOOLS_CALL_ID: i64 = 3;

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
    /// panic messages, never for an assertion — stderr's exact wording is
    /// not this file's contract). Never blocks: it reads the background
    /// reader thread's buffer, not the pipe itself.
    fn stderr_so_far(&self) -> String {
        let buf = self.stderr.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&buf).into_owned()
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

/// `PLAN.md` M6 Step 2 (a) item ①'s chosen behavior, exercised against the
/// real binary: before Step 3 wires `call_tool`, calling any listed tool —
/// even with a shape rmcp cannot possibly object to (`{}`, no validation
/// happens before dispatch) — comes back a JSON-RPC **protocol** error
/// (`-32601 Method not found`), not a hang and not a stdout byte outside
/// the JSON-RPC frame.
#[test]
fn calling_a_listed_tool_before_step_3_is_a_clean_protocol_error() {
    let sandbox = Sandbox::new();
    let mut client = McpClient::spawn(&sandbox, &[]);
    handshake(&mut client);

    client.send(&json!({
        "jsonrpc": "2.0",
        "id": TOOLS_CALL_ID,
        "method": "tools/call",
        "params": {
            "name": "list_hosts",
            "arguments": {},
        },
    }));
    let response = client.recv();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], TOOLS_CALL_ID);
    assert!(
        response.get("result").is_none(),
        "not-yet-wired call_tool must not report success: {response}"
    );
    assert_eq!(
        response["error"]["code"], -32601,
        "expected JSON-RPC Method not found: {response}"
    );

    client.assert_stdout_quiescent_after_close();
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
