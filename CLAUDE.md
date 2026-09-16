# CLAUDE.md

QSH is a QUIC-based direct-connect remote shell (single Rust binary `qsh`) that decouples PTY session lifetime from QUIC connection lifetime, so the same shell survives IP changes, sleep, and network switches without a relay server.

`docs/PRD.md` and `docs/CLI.md` are the binding contract for behavior, wire format, and JSON envelope shape. `docs/adr/` holds decided architecture decisions (ADRs). **Read the relevant PRD/CLI.md section and any related ADR before proposing a change to protocol, wire format, or JSON contract** — do not re-litigate a decision that already has an ADR; propose a new ADR instead if you believe it's wrong.

## Session onboarding

1. Open `docs/ROADMAP.md` and find the current milestone (first one not marked Done). Its acceptance criteria are the definition of done — build to them, not past them.
2. Open `PLAN.md` — the execution plan for the current milestone (ordered PR-sized steps with per-step tests and completion criteria). It is a living doc: when a milestone is done, it is fully replaced by the next milestone's plan.
3. Before implementing, read the matching sections of `docs/design/protocol.md` (wire protocol), `docs/design/architecture.md` (crates, modules, key mechanisms), `docs/design/testing.md` (which tests the milestone owes), and the `docs/CLI.md` contract for any command you touch.
4. Features deferred to P1/P2 stay deferred: reserved flags (e.g. `-D`) parse and return `UNSUPPORTED`; do not implement them early.

## Document map

- `PLAN.md` — execution plan for the current milestone (M8, hardening). Replaced wholesale when a milestone closes; the superseded plan moves to `docs/history/`.
- `docs/PRD.md` — product requirements (binding)
- `docs/CLI.md` — CLI / JSON contract (binding)
- `docs/ROADMAP.md` — milestones M0–M10 with scope and acceptance criteria
- `docs/design/protocol.md` — wire protocol design (frames, streams, resume, reverse)
- `docs/design/architecture.md` — crate/module design and key mechanisms
- `docs/design/testing.md` — per-layer test strategy and CI discipline
- `docs/design/threat-model.md` — threat model: assets, trust boundaries, entry points, threats → controls → pinned tests, residual risks
- `docs/design/reexec-estimate.md` — costed estimate for graceful re-exec; the recorded decision is not in v1
- `docs/deploy/service.md` — systemd/launchd unit examples (`qsh service install` itself is M9)
- `docs/man/` — generated man pages; regenerate with `cargo xtask man`, never hand-edit a `.1` file
- `docs/campaigns/` — manual campaigns a person runs and records: `m2-mobility`, `m6-mcp`, `m7-stopwatch`, `m8-fuzz`, `m8-soak`, `m8-adversarial-load`
- `scripts/README.md` — installer and campaign harnesses under `scripts/`
- `fuzz/README.md` — the seventeen cargo-fuzz targets, why `fuzz/` sits outside the workspace, how to run a campaign
- `docs/adr/` — architecture decision records, 0001–0018 (settled decisions)

## Commands

- `cargo fmt --all` (`--check` in CI)
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo nextest run --workspace`
- `cargo test --workspace --doc`
- `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`
- `cargo xtask arch` (dependency-direction and module bans below; `cargo xtask` is an alias for `cargo run -p xtask --`, defined in `.cargo/config.toml`)
- `cargo deny check`

All seven must be green before a commit. `.github/workflows/ci.yml` runs the same set plus an interactive acceptance job (`tui_expect`, `reverse_blackout`, `tunnel_throughput`, `tunnel_echo_under_load`), which is also required for merge.

Nextest gives each test its own process; PTY/termios and other global-state tests corrupt each other under `cargo test`'s shared process, so `cargo test --workspace` has been red from baseline since M7 for that reason (`acl::load`, `localctl::daemon`). A red `cargo test` proves nothing; rerun under nextest.

`docs/man/` is gated by the test `checked_in_man_pages_match_the_generator` in `xtask/src/man.rs`, which compares the checked-in `.1` set and bytes against what the current clap tree renders; xtask is a workspace member so it already runs inside `cargo nextest run --workspace`, and there is no separate CI step. When it fails, run `cargo xtask man` and commit the diff.

`.config/nextest.toml` also defines `--profile load` and `--profile soak`, used by `.github/workflows/load.yml` and `scripts/soak/run.sh`; neither is part of the PR gate.

## Workspace map

- `crates/qsh-proto` — contract layer: wire framing, JSON contract types, `ErrorCode`. sans-IO, no async. This is the fuzz surface.
- `crates/qsh-transport` — quinn/rustls glue only. No session or ACL knowledge.
- `crates/qsh-core` — ALL business logic: typed `Ops` facade, session broker, ACL choke point, identity/trust.
- `crates/qsh-cli` (package `qsh-cli`, binary `qsh`) — thin frontends only: clap, human/JSON/JSONL renderers, interactive TUI.
- `crates/qsh-testkit` — test harness.
- `xtask` — arch-lint and the man-page generator (`cargo xtask arch|man`)

## Hard architecture rules (docs/design/architecture.md §1, enforced by xtask arch)

- Allowed dependency matrix (exactly what `xtask arch` enforces): `qsh-proto` → nothing; `qsh-transport` → `qsh-proto`; `qsh-core` → `qsh-proto`, `qsh-transport`; `qsh-cli` → `qsh-core` and `qsh-proto` (contract types only — never `qsh-transport`); `qsh-testkit` → anything. Never backwards.
- Renderers contain **zero** auth/ACL/session logic. They call only the typed `Ops` layer.
- The built-in MCP adapter was retired in M8 Step 6 (ADR-0011); the agent-facing surface is the `qsh.cli/v1` JSON/JSONL CLI alone.
- `xtask arch`'s module bans are path-scoped: `crates/qsh-core/src/broker/` and `crates/qsh-cli/src/` by directory, `localctl/frame.rs`, `localctl/client.rs` and `reverse/registry.rs` by exact file. Flattening a scoped directory to a `.rs` file silently drops its ban, and turning a scoped file into a directory makes `cargo xtask arch` fail. Update `xtask/src/arch.rs` in the same commit as any such move.

If a change requires putting logic in `qsh-cli` to make something work, that's a signal the logic belongs in `qsh-core`'s `Ops` facade instead — move it, don't work around arch-lint.

## Contract stability rules

- `qsh.cli/v1` and `qsh.event/v1` are **additive-only**: new optional fields are fine; removals or type changes require a new `/v2`.
- JSON fixtures under `crates/qsh-cli/tests/fixtures/` are **append-only** — never edit or delete an existing fixture; add a new one and register it in `REQUIRED_FIXTURES`. The single exception is the value-bearing golden `capabilities.json`, regenerated with `QSH_UPDATE_FIXTURES=1` and reviewed with the same weight as a contract change (`docs/design/testing.md` L6).
- Every machine-mode stdout line must be **pure JSON**. Diagnostics, logs, and progress go to stderr only, never stdout, in `--json`/`--jsonl` mode.
- Error codes come from the single `ErrorCode` enum in `qsh-proto` — never invent an ad hoc error string elsewhere.

## Security defaults

- ACL is default-deny, evaluated at a single choke point before any resource exists: a request matching no `[[acl]]` row is denied, and a missing or unparseable `acl.toml` denies every request from every peer. The process still binds and still answers; it just refuses everything. `acl.toml` loads once at startup; there is no hot reload.
- Never create a resource (session, tunnel, listener) before authorization succeeds.
- Fail closed on any ambiguous auth/ACL state. The audit writer is fail-closed too: no durable record, no operation.
- Never log key material or PTY/command contents — audit records are structural (op, principal, result) and have no field that could hold a payload.

## Conventions

- Language: English in `README.md`, `CLAUDE.md`, `scripts/README.md`, `fuzz/README.md`, and all code comments; Korean in `docs/**`, `PLAN.md`, `scripts/stopwatch/README.md`, and commit messages (`type(scope): 요약 — 상세`).
- Cite durable anchors only: an ADR, a `docs/design/*` or `docs/campaigns/*` section, `docs/CLI.md` §N, a test name, or a commit hash. Never a `PLAN.md` step number (steps are renumbered when a milestone rolls) and never a session scratchpad file (`BRIEF-*`, `REVIEW-*`, `ARBITRATION-*`, `PROGRESS-*`), none of which exist in this repository.
- Once a source file passes roughly 800 lines, its inline `#[cfg(test)]` module moves to a sibling `tests.rs` reached by `mod tests;`; `crates/qsh-core/src/pty/` is the pattern to copy.
- `PLAN.md` and `docs/ROADMAP.md` are edited by the main session only.
