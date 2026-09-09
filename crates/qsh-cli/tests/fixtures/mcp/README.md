# mcp fixtures

`tools_list.json` is a snapshot of the `tools/list` response the M6 MCP
adapter used to serve over stdio (`docs/CLI.md` §8, now retired).

The adapter itself was removed in M8 Step 6 per ADR-0011: agent
integration is the `qsh.cli/v1` JSON/JSONL CLI contract alone, and a
remote stdio MCP server runs under `qsh exec host -- <server>` instead.

This fixture stays because `crates/qsh-cli/tests/fixtures/**` is
append-only (`CLAUDE.md`, `docs/design/testing.md` L6) — existing files
are never edited or deleted, even once the code that produced them is
gone.
