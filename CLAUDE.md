# CLAUDE.md

QSH is a QUIC-based direct-connect remote shell (single Rust binary `qsh`) that decouples PTY session lifetime from QUIC connection lifetime, so the same shell survives IP changes, sleep, and network switches without a relay server.

`docs/PRD.md` and `docs/CLI.md` are the binding contract for behavior, wire format, and JSON envelope shape. `docs/adr/` holds decided architecture decisions (ADRs). **Read the relevant PRD/CLI.md section and any related ADR before proposing a change to protocol, wire format, or JSON contract** — do not re-litigate a decision that already has an ADR; propose a new ADR instead if you believe it's wrong.

## Session onboarding

1. Open `docs/ROADMAP.md` and find the current milestone (first one not marked Done). Its acceptance criteria are the definition of done — build to them, not past them.
2. Open `PLAN.md` — the execution plan for the current milestone (ordered PR-sized steps with per-step tests and completion criteria). It is a living doc: when a milestone is done, it is fully replaced by the next milestone's plan.
3. Before implementing, read the matching sections of `docs/design/protocol.md` (wire protocol), `docs/design/architecture.md` (crates, modules, key mechanisms), `docs/design/testing.md` (which tests the milestone owes), and the `docs/CLI.md` contract for any command you touch.
4. Features deferred to P1/P2 stay deferred: reserved flags (e.g. `-D`) parse and return `UNSUPPORTED`; do not implement them early.

## Document map

- `PLAN.md` — execution plan for the current milestone (living doc, replaced per milestone)
- `docs/PRD.md` — product requirements (binding)
- `docs/CLI.md` — CLI / JSON / MCP contract (binding)
- `docs/ROADMAP.md` — milestones M0–M9 with scope and acceptance criteria
- `docs/design/protocol.md` — wire protocol design (frames, streams, resume, reverse)
- `docs/design/architecture.md` — crate/module design and key mechanisms
- `docs/design/testing.md` — per-layer test strategy and CI discipline
- `docs/campaigns/m2-mobility.md` — manual Wi-Fi↔tethering mobility campaign: preconditions, pre-defined pass/fail, record template (scripts in `scripts/mobility/`)
- `docs/adr/` — architecture decision records (settled decisions)

## Commands

- `cargo nextest run --workspace` (required, not `cargo test` — see below)
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo deny check`
- `cargo run -p xtask -- arch` (arch-lint: enforces the dependency-direction and layering rules below)

**`cargo nextest run` is the test gate; plain `cargo test` is not.** Nextest's
per-test process isolation is a hard requirement here, not a convenience —
PTY/termios tests and other global-state tests interfere with each other
inside `cargo test`'s shared-process model, and `cargo test` has been red
from baseline for exactly that reason since M7 (`acl::load`, `localctl::
daemon`). CI (`.github/workflows/ci.yml`) only runs nextest. A red
`cargo test` run tells you nothing about a regression; run nextest on the
same tree to find out.

**Before committing**, fmt + clippy + nextest + arch-lint must all be green. Do not commit with any of these failing.

## Workspace map

- `crates/qsh-proto` — contract layer: wire framing, JSON contract types, `ErrorCode`. sans-IO, no async. This is the fuzz surface.
- `crates/qsh-transport` — quinn/rustls glue only. No session or ACL knowledge.
- `crates/qsh-core` — ALL business logic: typed `Ops` facade, session broker, ACL choke point, identity/trust.
- `crates/qsh-cli` (package `qsh-cli`, binary `qsh`) — thin frontends only: clap, human/JSON/JSONL renderers, interactive TUI, MCP adapter.
- `crates/qsh-testkit` — test harness.
- `xtask` — arch-lint.

## Hard architecture rules (docs/design/architecture.md §1, enforced by xtask arch)

- Allowed dependency matrix (exactly what `xtask arch` enforces): `qsh-proto` → nothing; `qsh-transport` → `qsh-proto`; `qsh-core` → `qsh-proto`, `qsh-transport`; `qsh-cli` → `qsh-core` and `qsh-proto` (contract types only — never `qsh-transport`); `qsh-testkit` → anything. Never backwards.
- Renderers and the MCP adapter contain **zero** auth/ACL/session logic. They call only the typed `Ops` layer.
- The MCP adapter never shells out to `qsh` and never re-parses CLI output. It calls `Ops` directly, same as the CLI frontend.

If a change requires putting logic in `qsh-cli` to make something work, that's a signal the logic belongs in `qsh-core`'s `Ops` facade instead — move it, don't work around arch-lint.

## Contract stability rules

- `qsh.cli/v1` and `qsh.event/v1` are **additive-only**: new optional fields are fine; removals or type changes require a new `/v2`.
- JSON fixtures under `tests/` are **append-only** — never edit or delete an existing fixture, add a new one.
- Every machine-mode stdout line must be **pure JSON**. Diagnostics, logs, and progress go to stderr only, never stdout, in `--json`/`--jsonl` mode.
- Error codes come from the single `ErrorCode` enum in `qsh-proto` — never invent an ad hoc error string elsewhere.

## Security defaults

- ACL is default-deny. The policy engine lands in M5; before that (M1–M4) the interim posture is the ROADMAP's allow-all-pinned (mTLS-authenticated pinned peers only), and any authentication failure is always denied.
- Never create a resource (session, tunnel, listener) before authorization succeeds.
- Fail closed on any ambiguous auth/ACL state.
- Never log key material or PTY/command contents — audit records are structural (op, principal, result), never payload.
