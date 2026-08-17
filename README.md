# QSH

QSH is a direct, resilient remote shell built on QUIC.

SSH ties a PTY session's lifetime to its connection's lifetime, so an IP
change, a laptop sleep, or a network switch kills the session. QSH decouples
the two: the shell keeps running on the host, and the client resumes the
same session across connections instead of starting a new one. There is no
relay and no account — QSH connects directly to a user-provided routable
hostname or IP address.

**Status:** specs stable for implementation (PRD v0.4, CLI contract v0.3).
Pre-alpha — implementation in progress (M0 done), not usable yet.

## Usage (target UX, not yet implemented)

```bash
qsh dave@host              # interactive shell
qsh exec dave@host -- cmd  # run a command, no PTY
qsh -L 8080:localhost:80 dave@host   # local port forward
qsh mcp                    # expose QSH as an MCP server
```

## Documents

- [Product Requirements](docs/PRD.md)
- [CLI, JSON and MCP Contract](docs/CLI.md)
- [Roadmap — milestones, scope and acceptance criteria](docs/ROADMAP.md)
- [Wire Protocol Design](docs/design/protocol.md)
- [Architecture Design](docs/design/architecture.md)
- [Test Strategy](docs/design/testing.md)
- [Architecture Decision Records](docs/adr/)

## Architecture

```
qsh-cli (bin `qsh`)  →  qsh-core  →  qsh-transport  →  qsh-proto
        └─────────── contract types ───────────────────►
```

`qsh-cli` also depends directly on `qsh-proto` for contract types (never on
`qsh-transport`). The full allowed-dependency matrix is enforced by
`cargo xtask arch`.

- **qsh-proto** — sans-IO wire contract: framing, types, events, error codes. The fuzz surface.
- **qsh-transport** — QUIC glue (quinn/rustls). Owns the connection; knows nothing about sessions or ACL.
- **qsh-core** — all business logic: the typed operation layer, session broker, PTY, ACL, identity/trust, config.
- **qsh** (bin) — thin frontend: CLI, human/JSON/JSONL rendering, interactive TUI, MCP adapter.
- **qsh-testkit** — shared test harness (loopback transport, chaos proxy, fixtures).

The binary is named `qsh`; its crates.io package is `qsh-cli` (the name `qsh` was already taken). The workspace is locked with `publish = false` until the release milestone (M9).

## Roadmap

| # | Milestone | Status |
|---|---|---|
| M0 | Decisions, workspace scaffold, CI | Done |
| M1 | Walking skeleton (`init`/`serve`/`exec --json`, mTLS, JSON envelope) | Next |
| M2 | Session broker, PTY, migration and resume | Planned |
| M3 | Reverse connections (`listen`/`reverse`/`attach`) | Planned |
| M4 | Port forwarding (`-L`/`-R`) | Planned |
| M5 | ACL and audit | Planned |
| M6 | MCP adapter | Planned |
| M7 | Trust UX, host profiles, `doctor` | Planned |
| M8 | Hardening (fuzz, soak, real-device mobility campaign) | Planned |
| M9 | Release (installers, Homebrew, notarization) | Planned |

Per-milestone scope, in/out boundaries and acceptance criteria live in
[docs/ROADMAP.md](docs/ROADMAP.md).

## Known limitations (MVP, by design)

- Restarting the `qsh serve` listener terminates detached sessions. A
  separate session supervisor is planned after MVP
  ([ADR-0003](docs/adr/0003-sessions-in-listener.md)).
- Windows is P1 for the client and P2 for the host — not supported yet. PTY
  code is gated `#![cfg(unix)]` and there is no Windows CI.

## Product boundary

QSH owns secure sessions, PTY lifecycle, reconnect, command execution and port forwarding. It connects to a user-provided routable hostname or IP address and does not depend on a control plane or relay.

## Development

Requires Rust stable.

```bash
cargo test
cargo fmt
cargo clippy
cargo deny check
cargo xtask arch
```
