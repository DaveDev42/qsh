//! MCP adapter (`docs/CLI.md` §8, `docs/design/architecture.md` §2/§8/§9,
//! `PLAN.md` M6). **`qsh-cli`-only** — architecture.md §1's dependency
//! matrix has no lane for `rmcp` below the frontend layer, and this module
//! must never leak an `rmcp` type into `qsh-core`'s `Ops` signatures
//! (architecture.md §9 risk 4's own monitoring bullet).
//!
//! M6 Step 1 (`PLAN.md` "계약·의존성 확정") landed the contract-level
//! surface this file's own tests substantiate — the tool↔op mapping table
//! and small, compiled probes of the five draft decisions in `PLAN.md`
//! §4.1. M6 Step 2 (this file's [`QshMcpServer`]/[`serve_stdio`]) wired
//! that surface to a real `rmcp` stdio server: `qsh mcp` (`crate::cli`'s
//! `Command::Mcp`, dispatched by `crate::main`'s `run_mcp`) reaches
//! [`serve_stdio`], which serves `initialize`/`tools/list` for real. M6
//! Step 3 (`QshMcpServer`'s `ServerHandler::call_tool` impl, `run_tool`)
//! wires the remaining 12 tools to the same [`Ops`] every other `qsh`
//! command calls — deserialize → `Ops` method (on a blocking-pool thread,
//! `run_tool`'s own doc on why) → structured content or a §3.2 error
//! object, never a protocol-level error for an operation outcome.
use std::sync::Arc;

use qsh_core::{ExecStdin, OpError, Ops};
use qsh_proto::ErrorCode;
use rmcp::model::{
    CallToolRequestMethod, CallToolRequestParams, CallToolResponse, CallToolResult, Implementation,
    JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The `docs/CLI.md` §8.2 tool↔op mapping, realized as a code constant
/// (`PLAN.md` M6 Step 1 (c)) — 12 pairs, in the same order as the doc
/// table. This is a different axis from `qsh_core::acl::OP_REGISTRY`
/// (op→ACL action): that table is consumed by the host-side choke point
/// and lives in `qsh-core` because both forward and reverse dispatch need
/// it; this one is consumed only by the MCP adapter's own tool router
/// (Step 3) and never crosses the `qsh-core`/`qsh-cli` boundary, so it
/// lives here instead — the same "belongs to its one consumer" reasoning
/// `docs/design/architecture.md` §3's tunnel-module placement note uses.
///
/// `mcp_tool_map_matches_cli_md_section_8_2_bidirectionally` (below) is
/// the L6 gate: a row added here without a matching `docs/CLI.md` §8.2 row
/// (or vice versa) fails `cargo test`.
///
/// Not read by any production path, by design, even after Step 3:
/// [`tool_schemas`] and [`QshMcpServer::call_tool`] both hardcode their own
/// per-tool call sites instead of looping over this table — Rust generics
/// need the concrete `*Req`/`*Data` type at each call site, not a runtime
/// string, and `call_tool`'s router doubles as task item ⑥(a)'s mutation
/// target precisely because each tool's wiring is one visible match arm
/// rather than a table lookup a closure map would hide. This table's only
/// reader is this module's own tests — the doc↔code cross-check below.
#[allow(
    dead_code,
    reason = "cross-checked against docs/CLI.md §8.2 by this module's own tests; never read by production code by design (see doc above)"
)]
pub const TOOL_MAP: &[(&str, &str)] = &[
    ("list_hosts", "host.list"),
    ("get_host", "host.get"),
    ("list_sessions", "session.list"),
    ("get_session", "session.get"),
    ("open_session", "session.open"),
    ("read_session", "session.read"),
    ("write_session", "session.write"),
    ("resize_session", "session.resize"),
    ("close_session", "session.close"),
    ("exec", "exec.run"),
    ("open_tunnel", "tunnel.open"),
    ("close_tunnel", "tunnel.close"),
];

/// Build the 12 `rmcp::model::Tool` entries whose `input_schema` comes
/// straight from `qsh-proto`'s existing `*Req` types, through **rmcp's
/// own** `Tool::with_input_schema::<T>()` pipeline (`rmcp-3.1.4`
/// `src/handler/server/common.rs::schema_for_input` — draft 2020-12
/// settings, validated root `type: "object"`, top-level `title`/
/// `description` stripped) rather than a hand-rolled call into `schemars`
/// — no MCP-adapter-side re-derivation of the contract shape
/// (`docs/design/architecture.md` §2 "Req/Data 타입 공유", `PLAN.md`
/// §4.1 #2's evidence target: this is the exact code path a real
/// `list_tools` (Step 2) would also run, in this same `rmcp` version).
/// Also doubles as the compiled proof that the `rmcp = "=3.1.4"` pin
/// (`default-features = false`, `features = ["server", "transport-io"]`)
/// actually links against this workspace's `schemars = "1"` (resolved
/// 1.2.2) without a version bump.
///
/// Order matches [`TOOL_MAP`]; `tools/list`'s own response ordering
/// (`PLAN.md` §4.1 #2's "tool 이름 사전순 정렬" normalization) is a Step 2
/// renderer concern, not this function's.
///
/// M6 Step 3 addendum (`PLAN.md` Step 2 (a)-추기 ④): every entry also
/// carries `output_schema`, from the same `*Data` type [`call_tool`]'s
/// router serializes a success result from — `schema_for!(Data)` through
/// **rmcp's own** `Tool::with_output_schema::<T>()`, the identical pairing
/// discipline [`tool`] already uses for `input_schema`/`*Req`. This is the
/// one behavior change `tools/list`'s fixture sees this step (this
/// function's own doc, still accurate above: `*Req` changes are the only
/// *input*-schema scope-creep tripwire; `*Data` changes are this one's).
pub fn tool_schemas() -> Vec<Tool> {
    vec![
        tool::<qsh_proto::HostListReq>(
            "list_hosts",
            "List configured forward hosts and any currently registered reverse hosts, \
             without dialing or checking reachability for any of them (docs/CLI.md §6.1).",
        )
        .with_output_schema::<qsh_proto::HostListData>(),
        tool::<qsh_proto::HostGetReq>(
            "get_host",
            "Look up a single host by its local alias (docs/CLI.md §6.1).",
        )
        .with_output_schema::<qsh_proto::Host>(),
        tool::<qsh_proto::SessionListReq>(
            "list_sessions",
            "List sessions on one host, or best-effort fan out across every pinned host \
             when no host is given (docs/CLI.md §6.2).",
        )
        .with_output_schema::<qsh_proto::SessionListData>(),
        tool::<qsh_proto::SessionGetReq>(
            "get_session",
            "Look up a single session by its session_ref (docs/CLI.md §6.2).",
        )
        .with_output_schema::<qsh_proto::Session>(),
        tool::<qsh_proto::SessionOpenReq>(
            "open_session",
            "Open a new interactive PTY session on a host, running a login shell or a \
             given argv (docs/CLI.md §6.3).",
        )
        .with_output_schema::<qsh_proto::SessionOpenData>(),
        tool::<qsh_proto::SessionReadReq>(
            "read_session",
            "Pull a session's buffered output and lifecycle events since a given byte \
             offset, optionally waiting for new data to arrive (docs/CLI.md §6.4).",
        )
        .with_output_schema::<qsh_proto::SessionReadData>(),
        tool::<qsh_proto::SessionWriteReq>(
            "write_session",
            "Write bytes to a session's PTY input (docs/CLI.md §6.5).",
        )
        .with_output_schema::<qsh_proto::SessionWriteData>(),
        tool::<qsh_proto::SessionResizeReq>(
            "resize_session",
            "Resize a session's PTY to the given terminal column/row dimensions \
             (docs/CLI.md §6.6).",
        )
        .with_output_schema::<qsh_proto::SessionResizeData>(),
        tool::<qsh_proto::SessionCloseReq>(
            "close_session",
            "Terminate a session's entire process group and remove the session from the \
             host (docs/CLI.md §6.7).",
        )
        .with_output_schema::<qsh_proto::SessionCloseData>(),
        tool::<qsh_proto::ExecRunReq>(
            "exec",
            "Run a single non-interactive command on a host and return its captured \
             stdout/stderr and exit status once it completes (docs/CLI.md §6.8).",
        )
        .with_output_schema::<qsh_proto::ExecRunData>(),
        tool::<qsh_proto::TunnelOpenReq>(
            "open_tunnel",
            "Open a local or remote TCP port forward through a host (docs/CLI.md §6.9).",
        )
        .with_output_schema::<qsh_proto::TunnelOpenData>(),
        tool::<qsh_proto::TunnelCloseReq>(
            "close_tunnel",
            "Close a previously opened tunnel by its tunnel_id (docs/CLI.md §6.9).",
        )
        .with_output_schema::<qsh_proto::TunnelCloseData>(),
    ]
}

/// One `rmcp::model::Tool`, named `name`, described by `description`
/// (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ④/F4 — every tool used to carry
/// `None` here, which a real MCP client would show a human/agent user
/// choosing among tools with nothing to go on), whose input schema is `T`'s
/// — via `Tool::with_input_schema`, the same generic-type-to-schema path a
/// macro-driven `#[tool_router]` server would use internally.
fn tool<T: schemars::JsonSchema + 'static>(name: &'static str, description: &'static str) -> Tool {
    Tool::new(name, description, Arc::new(JsonObject::new())).with_input_schema::<T>()
}

/// [`tool_schemas`], sorted by tool name — `tools/list`'s own wire
/// ordering (`PLAN.md` §4.1 #2, confirmed by this step: the checked-in
/// `crates/qsh-cli/tests/fixtures/mcp/tools_list.json` pins this exact
/// order). [`TOOL_MAP`]/[`tool_schemas`] themselves stay in the
/// `docs/CLI.md` §8.2 doc-table order because the L6 gate above zips them
/// 1:1 against it; this is the one place that reorders for the wire.
fn tools_list_schemas() -> Vec<Tool> {
    let mut tools = tool_schemas();
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

/// The `qsh mcp` server (`docs/CLI.md` §8, `PLAN.md` M6 Step 2/3). Holds
/// exactly one thing: the same [`Ops`] every other `qsh` command dials with
/// (`main.rs`'s `run_mcp`, built the same way as `run`'s own `Ops::from_env()`
/// — `docs/CLI.md` §11's "Human, JSON와 MCP adapter는 같은 Rust typed
/// operation을 호출한다"). `get_info`/`list_tools` never touch it;
/// `call_tool` (below) is its only reader.
#[derive(Debug, Clone)]
pub struct QshMcpServer {
    ops: Ops,
}

impl QshMcpServer {
    /// Bind this server to `ops` — the same handle [`serve_stdio`]'s caller
    /// (`main.rs`'s `run_mcp`) built from the environment, not a fresh one
    /// this module constructs itself (no `Paths`/`Config` knowledge belongs
    /// in the adapter, `docs/CLI.md` §11).
    pub fn new(ops: Ops) -> Self {
        Self { ops }
    }
}

impl ServerHandler for QshMcpServer {
    /// Declares the `tools` capability and reports **this** build's own
    /// identity. Without this override, `ServerInfo::default()`'s
    /// `Implementation::from_build_env()` would report `rmcp`'s own crate
    /// name/version (`env!("CARGO_CRATE_NAME")` expands inside the `rmcp`
    /// crate itself, not this one) — a confusing "server" for a real MCP
    /// client to show a user.
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("qsh", env!("CARGO_PKG_VERSION")))
    }

    /// `docs/CLI.md` §8.2's 12 tools, alphabetically (`tools_list_schemas`,
    /// `PLAN.md` §4.1 #2). No pagination: 12 tools is under any client's
    /// page size, so `request`/`next_cursor` go unused.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(tools_list_schemas()))
    }

    /// `docs/CLI.md` §8.2's 12 tools, wired for real (`PLAN.md` M6 Step 3).
    /// Router only: deserialize `arguments` into the tool's `*Req`, call the
    /// matching [`Ops`] method (item ①), shape the result (item ③) — no
    /// auth/ACL/session logic lives here (`docs/CLI.md` §11; the host-side
    /// dispatch this call eventually reaches, `docs/design/architecture.md`
    /// §6, is the sole ACL choke point, so `docs/CLI.md` §8.4's "각 tool
    /// call에 일반 CLI와 동일한 ACL을 적용한다" is inherited for free —
    /// every one of these `Ops` methods is the exact call the CLI frontend's
    /// own commands already make, nothing MCP-specific added).
    ///
    /// An unlisted tool name is still the inherited-default shape from
    /// before this step: a JSON-RPC **protocol** error
    /// (`McpError::method_not_found`, `-32601`) — never routed through
    /// [`run_tool`]'s `CallToolResult` channel, because "no such tool" is
    /// not an operation outcome either (same reasoning Step 2's own removed
    /// doc gave for the stub this replaces).
    ///
    /// `read_session` is wired to a **single** [`qsh_core::Ops::session_read`]
    /// pull (`docs/CLI.md` §8.3's request/reply shape, one round trip) — no
    /// MCP-specific long-poll cancellation plumbing lives in this adapter,
    /// and none needs to (`PLAN.md` M6 Step 4 (a)-추기 item ①). `rmcp-3.1.4`
    /// `src/service.rs`'s `serve_inner` already keeps a `local_ct_pool`: one
    /// `CancellationToken` per in-flight request id (declared ~L1347). A
    /// client-sent `notifications/cancelled` removes that request's token
    /// from the pool and cancels it (~L1611); when the handler eventually
    /// finishes and `serve_inner` goes to send the response, it looks the
    /// id up in the same pool again (~L1478) — gone means cancelled, and
    /// the response is silently dropped instead of being written to
    /// stdout. The handler task itself is never aborted: for `read_session`
    /// specifically, the `spawn_blocking`'d [`qsh_core::Ops::session_read`]
    /// call (`run_tool`'s own doc on why every `Ops` call gets one) keeps
    /// running server-side regardless, until data arrives or the host's own
    /// `SESSION_READ_MAX_WAIT` clamp fires — cancellation integrity (no
    /// stray response, no double response) is `rmcp`'s structural guarantee,
    /// not something this adapter implements. Session state, the PTY and the
    /// writer lease are untouched either way (`docs/CLI.md` §9's cancellation
    /// semantics) — nothing here reacts to `notifications/cancelled`
    /// differently for `read_session` than for any other tool, because
    /// nothing needs to.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let ops = self.ops.clone();
        let arguments = request.arguments.unwrap_or_default();
        let result: CallToolResult = match request.name.as_ref() {
            "list_hosts" => {
                run_tool(arguments, move |_req: qsh_proto::HostListReq| {
                    ops.host_list()
                })
                .await
            }
            "get_host" => {
                run_tool(arguments, move |req: qsh_proto::HostGetReq| {
                    ops.host_get(req)
                })
                .await
            }
            "list_sessions" => {
                run_tool(arguments, move |req: qsh_proto::SessionListReq| {
                    ops.session_list(req)
                })
                .await
            }
            "get_session" => {
                run_tool(arguments, move |req: qsh_proto::SessionGetReq| {
                    ops.session_get(req)
                })
                .await
            }
            "open_session" => {
                run_tool(arguments, move |req: qsh_proto::SessionOpenReq| {
                    ops.session_open(req)
                })
                .await
            }
            "read_session" => {
                run_tool(arguments, move |req: qsh_proto::SessionReadReq| {
                    ops.session_read(req).map(|out| out.data)
                })
                .await
            }
            "write_session" => {
                run_tool(arguments, move |req: qsh_proto::SessionWriteReq| {
                    ops.session_write(req)
                })
                .await
            }
            "resize_session" => {
                run_tool(arguments, move |req: qsh_proto::SessionResizeReq| {
                    ops.session_resize(req)
                })
                .await
            }
            "close_session" => {
                run_tool(arguments, move |req: qsh_proto::SessionCloseReq| {
                    ops.session_close(req)
                })
                .await
            }
            "exec" => {
                // No MCP tool argument carries remote stdin content
                // (`TOOL_MAP`'s `ExecRunReq` has none) — `ExecStdin::Closed`
                // sends EOF immediately, the same choice `main.rs`'s
                // `run_exec` makes whenever its own stdin is not a pipe.
                run_tool(arguments, move |req: qsh_proto::ExecRunReq| {
                    ops.exec_run(req, ExecStdin::Closed).map(|out| out.data)
                })
                .await
            }
            "open_tunnel" => {
                // `docs/CLI.md` §6.14: a tunnel's holder is the process
                // that opened it. `qsh tunnel open --json` is one process
                // per tunnel, so its own foreground `TunnelHold::hold` call
                // is enough — process death is the only close mechanism it
                // ever needs. `qsh mcp` is one *long-running* process
                // serving many `open_tunnel` calls, so it needs a tunnel's
                // hold to outlive this call *and* to be independently
                // closable by a later `close_tunnel` call without taking
                // the whole server down — `Ops::tunnel_open_and_hold`
                // (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ②/F2) is that
                // primitive: it keeps holding on a background thread and
                // registers a close signal in `Ops`'s own shared registry,
                // so all of this call site has to do is call it — no hold
                // lifecycle logic lives in `qsh-cli` at all.
                run_tool(arguments, move |req: qsh_proto::TunnelOpenReq| {
                    ops.tunnel_open_and_hold(req)
                })
                .await
            }
            "close_tunnel" => {
                run_tool(arguments, move |req: qsh_proto::TunnelCloseReq| {
                    ops.tunnel_close(req)
                })
                .await
            }
            _ => return Err(McpError::method_not_found::<CallToolRequestMethod>()),
        };
        Ok(result.into())
    }
}

/// Deserialize `arguments` into `Req`, run `op` — a **sync** [`Ops`] call —
/// on a blocking-pool thread, and shape the outcome per `PLAN.md` §4.1 #3 /
/// M6 Step 3 item ③, error shape revised by M6 Step 2+3 검증 라운드 판정
/// ⑤/F5: `Ok` becomes [`CallToolResult::structured`], every failure becomes
/// [`op_error_result`] — content-only, carrying a `qsh_proto::CliError`
/// (`docs/CLI.md` §3.2's error object, verbatim) — **never** a
/// protocol-level `Err`, so this function's return type has no `Result` for
/// a caller to mis-route one into.
///
/// The `spawn_blocking` is not an optional efficiency touch: every `Ops`
/// method (`crates/qsh-core/src/ops/*.rs`) builds and `block_on`s its own
/// dedicated Tokio runtime internally (`Ops::resolve_host_route`'s own doc,
/// `crates/qsh-core/src/ops/host.rs`, names the exact hazard — "calling it
/// from code that is itself already executing inside a Tokio runtime
/// panics", and predicts "a future async host (an MCP adapter...)" as the
/// caller that will hit it). `call_tool` already runs inside `qsh mcp`'s own
/// runtime (`serve_stdio`'s `rmcp::serve_server`), so calling `op` straight
/// from there would panic; `spawn_blocking` moves it to a thread that is not
/// driving any runtime's async tasks, sidestepping the hazard the same way
/// `crates/qsh-testkit/tests/host_list_reverse.rs` already does for the sync
/// twin of that same method.
async fn run_tool<Req, Data>(
    arguments: JsonObject,
    op: impl FnOnce(Req) -> Result<Data, OpError> + Send + 'static,
) -> CallToolResult
where
    Req: DeserializeOwned + Send + 'static,
    Data: Serialize + Send + 'static,
{
    let req: Req = match serde_json::from_value(Value::Object(arguments)) {
        Ok(req) => req,
        Err(err) => {
            return op_error_result(&OpError::new(
                ErrorCode::InvalidArgument,
                format!("invalid tool arguments: {err}"),
            ));
        }
    };
    match tokio::task::spawn_blocking(move || op(req)).await {
        Ok(Ok(data)) => match serde_json::to_value(&data) {
            Ok(value) => CallToolResult::structured(value),
            Err(err) => op_error_result(&OpError::new(
                ErrorCode::Internal,
                format!("qsh mcp: failed to encode tool result: {err}"),
            )),
        },
        Ok(Err(op_err)) => op_error_result(&op_err),
        Err(join_err) => op_error_result(&OpError::new(
            ErrorCode::Internal,
            format!("qsh mcp: tool task failed: {join_err}"),
        )),
    }
}

/// [`OpError`] → `docs/CLI.md` §3.2's error object, carried as
/// `content[0].text` (a serialized JSON string) on a
/// [`CallToolResult::error`] — **not** [`CallToolResult::structured_error`]
/// (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ⑤/F5). `structured_error` sets
/// `structuredContent` to the error object, but a tool's advertised
/// `outputSchema` (`tool_schemas`, below) is generated from its success
/// `*Data` type — an error object does not conform to that schema, so an
/// MCP client that validates `structuredContent` against `outputSchema` (as
/// the spec invites) would see this server's own error responses as
/// protocol violations. `content`-only text carries the identical §3.2 JSON
/// (byte-for-byte, still parseable by any caller that wants structure) with
/// no schema claim attached — this is [`run_tool`]'s three failure arms'
/// one shared shaping point, so they stay byte-identical to each other for
/// the same `OpError`.
fn op_error_result(err: &OpError) -> CallToolResult {
    let error = qsh_proto::CliError {
        code: err.code.clone(),
        message: err.message.clone(),
        retryable: err.retryable,
        details: err.details.clone(),
    };
    let value = serde_json::to_value(&error).expect("CliError always serializes");
    CallToolResult::error(vec![rmcp::model::ContentBlock::text(value.to_string())])
}

/// `qsh mcp`'s entry point (`docs/CLI.md` §8.1): serve the stdio transport
/// until the peer closes stdin (EOF) or the connection otherwise ends.
/// Blocks; `main.rs`'s `run_mcp` supplies the async runtime, the same
/// shape `qsh_core::serve::run_serve`/`run_listen`/`run_reverse` use for
/// their own long-running modes.
///
/// No SIGINT/SIGTERM handling here on purpose: `qsh mcp` holds no resource
/// of its own to drain on the way out — no session, no listener; each tool
/// call is its own `Ops` round trip (`open_tunnel`'s held tunnels,
/// `qsh_core::Ops::tunnel_open_and_hold`'s own doc, are the one exception,
/// and they are intentionally *not* drained here either — same "process exit
/// is already correct" reasoning) — so the OS's default signal disposition
/// (process exit) is already correct, and the only *graceful* shutdown this
/// transport promises is "stdin closed", which is this function's own loop
/// exit.
///
/// `ops` is `main.rs`'s `run_mcp`'s own `Ops::from_env()` handle, passed in
/// rather than built here (`QshMcpServer::new`'s own doc).
pub async fn serve_stdio(ops: Ops) -> std::io::Result<()> {
    let transport = rmcp::transport::io::stdio();
    let service = rmcp::serve_server(QshMcpServer::new(ops), transport)
        .await
        .map_err(redact_handshake_error)?;
    service.waiting().await.map_err(redact_join_error)?;
    Ok(())
}

/// Redact the serving loop's own [`tokio::task::JoinError`] the same way
/// [`redact_handshake_error`] redacts the handshake's — its `Display` can
/// include a panic payload (whatever `std::panic!` was called with,
/// wherever inside the serving task it fired), so this keeps only the
/// structural fact ("cancelled" vs. "panicked"), never that payload.
fn redact_join_error(join_err: tokio::task::JoinError) -> std::io::Error {
    let shape = if join_err.is_cancelled() {
        "the serving task was cancelled"
    } else {
        "the serving task panicked"
    };
    std::io::Error::other(format!("mcp: {shape}"))
}

/// Redact an `rmcp` handshake failure before it becomes this function's
/// `io::Error` (`PLAN.md` M6 Step 2+3 검증 라운드 판정 ①/F1). Two of
/// `rmcp::service::ServerInitializeError`'s variants
/// (`rmcp-3.1.4/src/service/server.rs`) `Debug`-format an entire received
/// JSON-RPC message straight into their own `Display` —
/// `ExpectedInitializeRequest` fires exactly when a `tools/call` (or
/// anything else) arrives before `initialize`, and its `{0:?}` is that
/// message verbatim, arguments included (PTY input b64, `exec` argv).
/// `main.rs`'s `run_mcp` puts this `io::Error`'s `Display` on stderr via a
/// plain [`OpError`](crate::main) message, not through `tracing` — so
/// `init_tracing`'s `rmcp=warn` clamp (the other half of this same finding)
/// does not cover it, and it would leak *unconditionally*, independent of
/// `-v`/`-vv`. This keeps only each variant's *shape* — never a payload —
/// the same "structural, never payload" discipline `docs/PRD.md`
/// §13/`docs/CLI.md` §11 already hold audit records to.
fn redact_handshake_error(err: rmcp::service::ServerInitializeError) -> std::io::Error {
    use rmcp::service::ServerInitializeError as E;
    let shape = match &err {
        E::ExpectedInitializeRequest(_) => "the client's first message was not `initialize`",
        E::ConnectionClosed(_) => "the connection closed before `initialize` finished",
        E::UnexpectedInitializeResponse(_) => {
            "the client sent an unexpected message during `initialize`"
        }
        E::InitializeFailed(_) => "the `initialize` handshake failed",
        E::TransportError { .. } => "the stdio transport failed during `initialize`",
        E::Cancelled => "the `initialize` handshake was cancelled",
        // `ServerInitializeError` is `#[non_exhaustive]`: a future `rmcp`
        // version may add a variant this match has not seen — fail closed
        // to the same redaction discipline rather than a compile error
        // that would force a choice between "match every future variant
        // by hand" and "give up and format `{err}` again".
        _ => "the `initialize` handshake failed",
    };
    std::io::Error::other(format!("mcp handshake: {shape}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;

    use super::*;

    /// A [`QshMcpServer`] bound to throwaway, never-created directories —
    /// good enough for the tests in this module, which only exercise
    /// `get_info`/`list_tools`/schema shape (neither ever touches disk); a
    /// real dial is a `tests/mcp_conformance.rs` concern (a real `Sandbox`).
    fn test_server() -> QshMcpServer {
        QshMcpServer::new(Ops::new(qsh_core::Paths::new(
            "/nonexistent/qsh-mcp-test/config",
            "/nonexistent/qsh-mcp-test/state",
        )))
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
    }

    fn read_doc(relative: &str) -> String {
        let path = repo_root().join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    /// Same trick `crates/qsh-core/tests/acl_docs.rs`/`acl_registry.rs`
    /// use: slice `doc` from `heading` (matched verbatim) up to, but not
    /// including, the next line starting with `#` at any level — CRLF is
    /// normalized away first (Windows CI checks sources out with `\r\n`,
    /// which would otherwise keep `"\n#"` from ever matching there,
    /// `acl_registry.rs`'s `source_scan::server_mod_production_source`
    /// precedent).
    fn heading_section_slice<'a>(doc: &'a str, heading: &str) -> &'a str {
        let start = doc
            .find(heading)
            .unwrap_or_else(|| panic!("doc must have a {heading:?} heading"));
        let rest = &doc[start..];
        let end = rest[heading.len()..]
            .find("\n#")
            .map(|i| i + heading.len())
            .unwrap_or(rest.len());
        &rest[..end]
    }

    /// Every backtick-quoted inline-code span in `cell`, in order
    /// (`acl_registry.rs`'s `backtick_tokens` precedent).
    fn backtick_tokens(cell: &str) -> Vec<&str> {
        cell.split('`').skip(1).step_by(2).collect()
    }

    /// `docs/CLI.md` §8.2's `| MCP tool | Typed operation |` table, as
    /// `(tool, op)` pairs — header and separator rows dropped.
    fn cli_md_section_8_2_pairs(cli_md: &str) -> Vec<(String, String)> {
        let cli_md = cli_md.replace("\r\n", "\n");
        let section = heading_section_slice(&cli_md, "### 8.2 Tool mapping").to_string();
        section
            .lines()
            .filter(|line| line.trim_start().starts_with('|'))
            .skip(2) // header + `|---|---|` separator
            .map(|line| {
                let body = line.trim().trim_matches('|');
                let mut cells = body.splitn(2, '|');
                let tool_cell = cells.next().unwrap_or_default();
                let op_cell = cells.next().unwrap_or_default();
                let tool_tokens = backtick_tokens(tool_cell);
                let op_tokens = backtick_tokens(op_cell);
                assert_eq!(
                    tool_tokens.len(),
                    1,
                    "§8.2 row's tool cell must be exactly one backtick token: {tool_cell:?}"
                );
                assert_eq!(
                    op_tokens.len(),
                    1,
                    "§8.2 row's op cell must be exactly one backtick token: {op_cell:?}"
                );
                (tool_tokens[0].to_string(), op_tokens[0].to_string())
            })
            .collect()
    }

    /// The L6 doc↔code cross-check `PLAN.md` M6 Step 1 (c) owes: `TOOL_MAP`
    /// and `docs/CLI.md` §8.2 must name exactly the same 12 (tool, op)
    /// pairs, in both directions — a row present on only one side fails
    /// (`crates/qsh-core/tests/acl_registry.rs`'s
    /// `registry_matches_cli_md_section_2_5_bidirectionally` precedent,
    /// applied to the MCP tool axis instead of the ACL action axis).
    #[test]
    fn mcp_tool_map_matches_cli_md_section_8_2_bidirectionally() {
        let cli_md = read_doc("docs/CLI.md");
        let doc_pairs = cli_md_section_8_2_pairs(&cli_md);
        assert_eq!(
            doc_pairs.len(),
            12,
            "docs/CLI.md §8.2 must list exactly the 12 tools ROADMAP M6 scopes: {doc_pairs:?}"
        );

        let doc_set: HashSet<(String, String)> = doc_pairs.into_iter().collect();
        let code_set: HashSet<(String, String)> = TOOL_MAP
            .iter()
            .map(|(tool, op)| (tool.to_string(), op.to_string()))
            .collect();

        assert_eq!(
            code_set.len(),
            12,
            "TOOL_MAP must have 12 distinct rows: {TOOL_MAP:?}"
        );
        assert_eq!(
            code_set, doc_set,
            "TOOL_MAP and docs/CLI.md §8.2 have drifted apart — a row in one and not the \
             other means the adapter and the doc disagree about the tool surface \
             (docs/CLI.md is binding, CLAUDE.md — conform the code)"
        );
    }

    /// L6 mutation proof (task item ③): a silent edit to one `TOOL_MAP` row
    /// (the kind a future Step 3 refactor could introduce without noticing)
    /// must fail the gate above, not pass silently. This asserts the
    /// negative directly rather than trusting it — same discipline
    /// `acl_registry.rs`'s own bidirectional-exclusion checks use.
    #[test]
    fn a_mutated_row_fails_the_bidirectional_gate() {
        let cli_md = read_doc("docs/CLI.md");
        let doc_set: HashSet<(String, String)> =
            cli_md_section_8_2_pairs(&cli_md).into_iter().collect();

        // Simulate the representative mutation: the last row's op typo'd
        // from `tunnel.close` to `tunnel.closed`.
        let mut mutated: HashSet<(String, String)> = TOOL_MAP
            .iter()
            .map(|(tool, op)| (tool.to_string(), op.to_string()))
            .collect();
        assert!(mutated.remove(&("close_tunnel".to_string(), "tunnel.close".to_string())));
        mutated.insert(("close_tunnel".to_string(), "tunnel.closed".to_string()));

        assert_ne!(
            mutated, doc_set,
            "a mutated TOOL_MAP row must be distinguishable from docs/CLI.md §8.2 — if this \
             ever passes, the bidirectional gate above has stopped being able to catch a \
             drifted row"
        );
    }

    /// `PLAN.md` §4.1 #2 — schema determinism. `schema_for!` is a pure
    /// function of the Rust type (no clock/random/env input anywhere in
    /// schemars' derive), so two calls for the same type must produce
    /// byte-identical JSON — this is what lets `tools/list`'s fixture
    /// comparison (Step 2) be an exact-equality check rather than a
    /// structural/fuzzy one.
    #[test]
    fn schema_generation_is_deterministic_across_calls() {
        for _ in 0..3 {
            let a = tool_schemas();
            let b = tool_schemas();
            assert_eq!(a.len(), b.len());
            for (x, y) in a.iter().zip(b.iter()) {
                assert_eq!(x.name, y.name);
                assert_eq!(
                    serde_json::to_string(&x.input_schema).unwrap(),
                    serde_json::to_string(&y.input_schema).unwrap(),
                    "{:?} schema must serialize identically across calls",
                    x.name
                );
            }
        }
    }

    /// Sanity check on [`tool_schemas`] itself: 12 tools, [`TOOL_MAP`]
    /// order, each with a non-empty object schema (never the degenerate
    /// `{}`/`true` schemars can emit for an all-optional-fields struct with
    /// no properties — every `*Req` here has at least one field).
    #[test]
    fn tool_schemas_cover_every_tool_map_row_with_a_real_object_schema() {
        let schemas = tool_schemas();
        assert_eq!(schemas.len(), TOOL_MAP.len());
        for (schema, (name, _op)) in schemas.iter().zip(TOOL_MAP.iter()) {
            assert_eq!(schema.name.as_ref(), *name);
            assert!(
                schema.input_schema.contains_key("type")
                    || schema.input_schema.contains_key("properties"),
                "{name}'s schema must be a real JSON Schema object, got {:?}",
                schema.input_schema
            );
        }
    }

    /// `PLAN.md` M6 Step 2+3 검증 라운드 판정 ④/F4 — the L6 gate for tool
    /// descriptions: every one of the 12 tools must carry a non-empty
    /// `description` (before this fix, [`tool`] hardcoded `None` for all of
    /// them — a real MCP client has nothing to show a human/agent user
    /// choosing among tools with `description: null`). Mutation-proof: a
    /// revert of any one tool back to no description makes this fail.
    #[test]
    fn every_tool_has_a_non_empty_description() {
        for schema in tool_schemas() {
            let description = schema
                .description
                .as_deref()
                .unwrap_or_else(|| panic!("{}: description must not be None", schema.name));
            assert!(
                !description.trim().is_empty(),
                "{}: description must not be empty/whitespace-only",
                schema.name
            );
        }
    }

    /// `PLAN.md` §4.1 #3, revised by M6 Step 2+3 검증 라운드 판정 ⑤/F5 —
    /// `OpError`/`CliError` → MCP tool error surface. `op_error_result`
    /// (this module) is "`isError: true` + `content[0].text` carrying the
    /// §3.2 error object JSON verbatim, `structuredContent` absent" — not
    /// [`CallToolResult::structured_error`] (its own doc, above, explains
    /// why: an error object does not conform to the tool's
    /// success-shaped `outputSchema`). This compiles a real `qsh.cli/v1`
    /// §3.2 example envelope's `error` object through the real function
    /// under test and checks the shape, including that `structuredContent`
    /// is `None` — the exact regression `structured_error` would reintroduce
    /// if it crept back in.
    #[test]
    fn op_error_maps_to_a_content_only_call_tool_error_without_structured_content() {
        let cli_error = qsh_proto::CliError {
            code: qsh_proto::ErrorCode::PermissionDenied,
            message: "peer is not allowed to perform this operation on this host".to_string(),
            retryable: false,
            details: serde_json::json!({}),
        };
        let op_err = OpError {
            code: cli_error.code.clone(),
            message: cli_error.message.clone(),
            retryable: cli_error.retryable,
            details: cli_error.details.clone(),
        };
        let value = serde_json::to_value(&cli_error).expect("CliError serializes");
        let result = op_error_result(&op_err);

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result.structured_content, None,
            "an error result must not carry structuredContent — the tool's \
             outputSchema is for its success type, not this error shape"
        );
        assert_eq!(result.content.len(), 1);
        let text = result.content[0]
            .as_text()
            .expect("error content must be a text block")
            .text
            .clone();
        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("content text must be the §3.2 JSON object");
        assert_eq!(parsed, value);
    }

    /// `PLAN.md` §4.1 #5 — a raw JSON-RPC harness (no `rmcp` client) is
    /// structurally sound: `rmcp::transport::io::stdio()` (rmcp 3.1.4,
    /// `src/transport/io.rs`) is a plain `(tokio::io::Stdin,
    /// tokio::io::Stdout)` pair, and the transport it feeds
    /// (`AsyncRwTransport`, `src/transport/async_rw.rs`) frames messages as
    /// one JSON object per newline-delimited line on each side (`BufReader`
    /// `read_line` in, `FramedWrite` + `JsonRpcMessageCodec` out) — nothing
    /// `qsh mcp`-specific and nothing that requires the `rmcp` client SDK
    /// to speak. A conformance harness can therefore be a bare
    /// `std::process::Command` with piped stdio (Step 2's `mcp_conformance
    /// .rs`) writing/reading newline-delimited JSON-RPC directly. This test
    /// only checks that `stdio()` still exists and constructs under our
    /// pinned feature set — it does not exercise a live server (Step 2).
    #[test]
    fn stdio_transport_pair_is_constructible_under_the_pinned_feature_set() {
        let (_stdin, _stdout) = rmcp::transport::io::stdio();
    }

    /// `docs/CLI.md` §8: the server must declare the `tools` capability
    /// (otherwise `tools/list`/`tools/call` are self-inconsistent with
    /// `get_info`) and must not leak `rmcp`'s own crate identity in place
    /// of this build's (see [`QshMcpServer::get_info`]'s own doc).
    #[test]
    fn get_info_declares_tools_and_reports_this_crates_own_identity() {
        let info = test_server().get_info();
        assert!(
            info.capabilities.tools.is_some(),
            "must declare the tools capability: {info:?}"
        );
        assert_eq!(info.server_info.name, "qsh");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
    }

    /// `PLAN.md` §4.1 #2: `tools/list`'s wire order is alphabetical by
    /// tool name, not [`TOOL_MAP`]'s doc-table order — and it is still
    /// exactly the same 12 tools [`TOOL_MAP`] names, none dropped or
    /// added by the reorder.
    #[test]
    fn tools_list_output_is_alphabetical_and_covers_every_tool_map_row() {
        let sorted = tools_list_schemas();
        assert_eq!(sorted.len(), TOOL_MAP.len());
        let names: Vec<&str> = sorted.iter().map(|t| t.name.as_ref()).collect();
        let mut expected = names.clone();
        expected.sort_unstable();
        assert_eq!(
            names, expected,
            "tools/list must be sorted by tool name (PLAN.md §4.1 #2)"
        );
        let mapped: HashSet<&str> = TOOL_MAP.iter().map(|(tool, _)| *tool).collect();
        let listed: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(
            listed, mapped,
            "tools_list_schemas must be a reordering of TOOL_MAP, not a different set"
        );
    }

    /// `PLAN.md` M6 Step 2 (a)-추기 ④ / task item ④: each tool's
    /// `output_schema` is exactly `schema_for_output::<Data>()` for the
    /// `*Data` type [`tool_schemas`]'s own doc pairs it with — the identical
    /// function `Tool::with_output_schema` calls internally
    /// (`rmcp::handler::server::common::schema_for_output`), so this checks
    /// the *pairing* [`tool_schemas`] wrote is right, not that rmcp's own
    /// schema generation works.
    #[test]
    fn output_schema_matches_the_paired_data_types_schema() {
        use rmcp::handler::server::common::schema_for_output;

        let schemas = tool_schemas();
        let expected: [(&str, Arc<JsonObject>); 12] = [
            ("list_hosts", schema_for_output::<qsh_proto::HostListData>()),
            ("get_host", schema_for_output::<qsh_proto::Host>()),
            (
                "list_sessions",
                schema_for_output::<qsh_proto::SessionListData>(),
            ),
            ("get_session", schema_for_output::<qsh_proto::Session>()),
            (
                "open_session",
                schema_for_output::<qsh_proto::SessionOpenData>(),
            ),
            (
                "read_session",
                schema_for_output::<qsh_proto::SessionReadData>(),
            ),
            (
                "write_session",
                schema_for_output::<qsh_proto::SessionWriteData>(),
            ),
            (
                "resize_session",
                schema_for_output::<qsh_proto::SessionResizeData>(),
            ),
            (
                "close_session",
                schema_for_output::<qsh_proto::SessionCloseData>(),
            ),
            ("exec", schema_for_output::<qsh_proto::ExecRunData>()),
            (
                "open_tunnel",
                schema_for_output::<qsh_proto::TunnelOpenData>(),
            ),
            (
                "close_tunnel",
                schema_for_output::<qsh_proto::TunnelCloseData>(),
            ),
        ];
        assert_eq!(schemas.len(), expected.len());
        for (schema, (name, expected_schema)) in schemas.iter().zip(expected.iter()) {
            assert_eq!(schema.name.as_ref(), *name);
            let actual = schema
                .output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{name} has no output_schema"));
            assert_eq!(
                actual, expected_schema,
                "{name}'s output_schema does not match schema_for_output for its own Data type"
            );
        }
    }
}
