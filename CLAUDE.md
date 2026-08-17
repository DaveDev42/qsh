# CLAUDE.md

QSH is a QUIC-based direct-connect remote shell (single Rust binary `qsh`) that decouples PTY session lifetime from QUIC connection lifetime, so the same shell survives IP changes, sleep, and network switches without a relay server.

`docs/PRD.md` and `docs/CLI.md` are the binding contract for behavior, wire format, and JSON envelope shape. `docs/adr/` holds decided architecture decisions (ADRs). **Read the relevant PRD/CLI.md section and any related ADR before proposing a change to protocol, wire format, or JSON contract** — do not re-litigate a decision that already has an ADR; propose a new ADR instead if you believe it's wrong.

## Commands

- `cargo test` (or `cargo nextest run` if installed — preferred, process isolation matters for PTY tests)
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo deny check`
- `cargo run -p xtask -- arch` (arch-lint: enforces the dependency-direction and layering rules below)

**Before committing**, fmt + clippy + test + arch-lint must all be green. Do not commit with any of these failing.

## Workspace map

- `crates/qsh-proto` — contract layer: wire framing, JSON contract types, `ErrorCode`. sans-IO, no async. This is the fuzz surface.
- `crates/qsh-transport` — quinn/rustls glue only. No session or ACL knowledge.
- `crates/qsh-core` — ALL business logic: typed `Ops` facade, session broker, ACL choke point, identity/trust.
- `crates/qsh-cli` (package `qsh-cli`, binary `qsh`) — thin frontends only: clap, human/JSON/JSONL renderers, interactive TUI, MCP adapter.
- `crates/qsh-testkit` — test harness.
- `xtask` — arch-lint.

## Hard architecture rules (CLI.md §11, enforced by xtask arch)

- Dependency direction is strictly `qsh-cli → qsh-core → qsh-transport → qsh-proto`. Never sideways, never backwards.
- Renderers and the MCP adapter contain **zero** auth/ACL/session logic. They call only the typed `Ops` layer.
- The MCP adapter never shells out to `qsh` and never re-parses CLI output. It calls `Ops` directly, same as the CLI frontend.

If a change requires putting logic in `qsh-cli` to make something work, that's a signal the logic belongs in `qsh-core`'s `Ops` facade instead — move it, don't work around arch-lint.

## Contract stability rules

- `qsh.cli/v1` and `qsh.event/v1` are **additive-only**: new optional fields are fine; removals or type changes require a new `/v2`.
- JSON fixtures under `tests/` are **append-only** — never edit or delete an existing fixture, add a new one.
- Every machine-mode stdout line must be **pure JSON**. Diagnostics, logs, and progress go to stderr only, never stdout, in `--json`/`--jsonl` mode.
- Error codes come from the single `ErrorCode` enum in `qsh-proto` — never invent an ad hoc error string elsewhere.

## Security defaults

- ACL is default-deny.
- Never create a resource (session, tunnel, listener) before authorization succeeds.
- Fail closed on any ambiguous auth/ACL state.
- Never log key material or PTY/command contents — audit records are structural (op, principal, result), never payload.
