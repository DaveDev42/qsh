//! MCP adapter (`docs/CLI.md` §8, `docs/design/architecture.md` §2/§8/§9,
//! `PLAN.md` M6). **`qsh-cli`-only** — architecture.md §1's dependency
//! matrix has no lane for `rmcp` below the frontend layer, and this module
//! must never leak an `rmcp` type into `qsh-core`'s `Ops` signatures
//! (architecture.md §9 risk 4's own monitoring bullet).
//!
//! M6 Step 1 (`PLAN.md` "계약·의존성 확정") landed the contract-level
//! surface this file's own tests substantiate — the tool↔op mapping table
//! and small, compiled probes of the five draft decisions in `PLAN.md`
//! §4.1. M6 Step 2 (this file's [`QshMcpServer`]/[`serve_stdio`]) wires
//! that surface to a real `rmcp` stdio server: `qsh mcp` (`crate::cli`'s
//! `Command::Mcp`, dispatched by `crate::main`'s `run_mcp`) now reaches
//! [`serve_stdio`], which serves `initialize`/`tools/list` for real.
//! `call_tool` is still Step 3's job — see [`QshMcpServer`]'s
//! `ServerHandler` impl for why this step deliberately leaves it as
//! rmcp's own default rather than stubbing a "not wired yet" response.
use std::sync::Arc;

use rmcp::model::{
    Implementation, JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};

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
/// Not yet read by any non-test production path: [`tool_schemas`] hardcodes
/// its own per-type calls (Rust generics need the concrete `*Req` type at
/// each call site, not a runtime string), so this step's `list_tools` never
/// dereferences this table at runtime. Step 3's `call_tool` router is the
/// production reader (`name` → `op` → the `Ops` method to call) — the
/// individual allow below is temporary to that step, not permanent.
#[allow(
    dead_code,
    reason = "read by Step 3's call_tool router; production-unreachable until then, cross-checked against docs/CLI.md §8.2 by this module's own tests in the meantime"
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
pub fn tool_schemas() -> Vec<Tool> {
    vec![
        tool::<qsh_proto::HostListReq>("list_hosts"),
        tool::<qsh_proto::HostGetReq>("get_host"),
        tool::<qsh_proto::SessionListReq>("list_sessions"),
        tool::<qsh_proto::SessionGetReq>("get_session"),
        tool::<qsh_proto::SessionOpenReq>("open_session"),
        tool::<qsh_proto::SessionReadReq>("read_session"),
        tool::<qsh_proto::SessionWriteReq>("write_session"),
        tool::<qsh_proto::SessionResizeReq>("resize_session"),
        tool::<qsh_proto::SessionCloseReq>("close_session"),
        tool::<qsh_proto::ExecRunReq>("exec"),
        tool::<qsh_proto::TunnelOpenReq>("open_tunnel"),
        tool::<qsh_proto::TunnelCloseReq>("close_tunnel"),
    ]
}

/// One `rmcp::model::Tool`, named `name`, whose input schema is `T`'s —
/// via `Tool::with_input_schema`, the same generic-type-to-schema path a
/// macro-driven `#[tool_router]` server would use internally.
fn tool<T: schemars::JsonSchema + 'static>(name: &'static str) -> Tool {
    Tool::new_with_raw(name, None, Arc::new(JsonObject::new())).with_input_schema::<T>()
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

/// The `qsh mcp` server (`docs/CLI.md` §8, `PLAN.md` M6 Step 2). Holds no
/// state: `get_info`/`list_tools` need none, and `call_tool` is
/// deliberately left unimplemented here (see the `ServerHandler` impl
/// below) — Step 3 adds an `Ops` field and wires real dispatch.
#[derive(Debug, Default, Clone, Copy)]
pub struct QshMcpServer;

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

    // `call_tool` is deliberately **not** overridden — Step 3's job
    // (`PLAN.md` M6 Step 2 (a) item ①). The inherited default
    // (`rmcp::handler::server`'s `server_handler_methods!` macro body,
    // `rmcp-3.1.4/src/handler/server.rs`) answers every `tools/call` with
    // a JSON-RPC **protocol** error (`-32601 Method not found`,
    // `CallToolRequestMethod` = `"tools/call"`) rather than a tool-scoped
    // `CallToolResult`. That is the safer of the two shapes this step
    // could ship, for two reasons:
    //
    // 1. A hand-rolled per-tool `CallToolResult::structured_error`
    //    "not wired yet" stub would invent an interim contract surface no
    //    `qsh-proto` `ErrorCode` backs — this project bans ad hoc error
    //    strings outside that one enum (`CLAUDE.md`: "Error codes come
    //    from the single `ErrorCode` enum in `qsh-proto` — never an ad
    //    hoc error string elsewhere"). "This tool has no implementation
    //    yet" is not an *operation outcome* in the first place (no `Ops`
    //    method ever ran), so routing it through `CallToolResult`'s
    //    success-shaped structured-content channel — the same channel
    //    `PLAN.md` §4.1 #3 reserves for a real `OpError` — would
    //    misrepresent a missing implementation as an operation that ran
    //    and failed.
    // 2. It is exactly the idiom every other unimplemented
    //    `ServerHandler` method in this same trait already uses
    //    (`get_prompt`, `read_resource`, `set_level`, …): a protocol
    //    `Method not found`. `list_tools`'s own declaration of 12 real
    //    tools is not misleading alongside it — the MCP spec's `tools`
    //    capability only promises `tools/list` is meaningful, and a
    //    client that calls `tools/call` before this handler is complete
    //    gets an honest, standard "not there yet" instead of a
    //    fabricated success-shaped result or (worse) a hang.
    //
    // `crates/qsh-cli/tests/mcp_conformance.rs` asserts this behavior
    // against the real binary: `tools/call` for a real, listed tool name
    // still comes back `-32601`, not a hang and not a mangled stdout byte.
}

/// `qsh mcp`'s entry point (`docs/CLI.md` §8.1): serve the stdio transport
/// until the peer closes stdin (EOF) or the connection otherwise ends.
/// Blocks; `main.rs`'s `run_mcp` supplies the async runtime, the same
/// shape `qsh_core::serve::run_serve`/`run_listen`/`run_reverse` use for
/// their own long-running modes.
///
/// No SIGINT/SIGTERM handling here on purpose: `qsh mcp` holds no resource
/// of its own to drain on the way out — no session, no listener; Step 3's
/// tool calls are each a single `Ops` round trip, the same shape the CLI
/// frontend's own commands already are — so the OS's default signal
/// disposition (process exit) is already correct, and the only *graceful*
/// shutdown this transport promises is "stdin closed", which is this
/// function's own loop exit.
pub async fn serve_stdio() -> std::io::Result<()> {
    let transport = rmcp::transport::io::stdio();
    let service = rmcp::serve_server(QshMcpServer, transport)
        .await
        .map_err(std::io::Error::other)?;
    service.waiting().await.map_err(std::io::Error::other)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;

    use rmcp::model::CallToolResult;

    use super::*;

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

    /// `PLAN.md` §4.1 #3 — `OpError`/`CliError` → MCP tool error surface.
    /// `rmcp::model::CallToolResult::structured_error` (rmcp 3.1.4,
    /// `src/model.rs`) is exactly "`isError: true` + content carrying the
    /// §3.2 error object JSON verbatim" the draft decision describes, with
    /// no MCP *protocol*-level error (`Err(ErrorData)`) involved — this
    /// compiles a real `qsh.cli/v1` §3.2 example envelope's `error` object
    /// through it and checks the shape.
    #[test]
    fn op_error_maps_to_a_structured_call_tool_error_without_a_protocol_error() {
        let cli_error = qsh_proto::CliError {
            code: qsh_proto::ErrorCode::PermissionDenied,
            message: "peer is not allowed to perform this operation on this host".to_string(),
            retryable: false,
            details: serde_json::json!({}),
        };
        let value = serde_json::to_value(&cli_error).expect("CliError serializes");
        let result = CallToolResult::structured_error(value.clone());

        assert_eq!(result.is_error, Some(true));
        assert_eq!(result.structured_content, Some(value));
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
        let info = QshMcpServer.get_info();
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
}
