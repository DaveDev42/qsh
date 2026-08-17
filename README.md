# QSH

QSH is a direct, resilient remote shell built on QUIC.

SSH ties a PTY session's lifetime to its connection's lifetime, so an IP
change, a laptop sleep, or a network switch kills the session. QSH decouples
the two: the shell keeps running on the host, and the client resumes the
same session across connections instead of starting a new one. There is no
relay and no account — QSH connects directly to a user-provided routable
hostname or IP address.

**Status:** pre-alpha. M1 (walking skeleton) is done: `qsh init` /
`qsh serve` / `qsh trust add` / `qsh exec host --json -- cmd` work end to end
over QUIC + TLS 1.3 mutual authentication with pinned certificates
(PRD v0.4, CLI contract v0.4). Interactive PTY sessions and resume land in
M2. Not for production use.

## Quick start (M1: run a command on a pinned host)

Both machines need the same `qsh` binary (`cargo build --release`).

```bash
# On the host (the machine that will run commands):
qsh init --json                          # creates the device identity; note "fingerprint"
qsh serve --bind 0.0.0.0:4433            # foreground; prints the bound address to stderr

# On the client:
qsh init --json                          # note this device's "fingerprint" too
qsh trust add box --address host.example.com:4433 --fingerprint sha256:<HOST_FP>

# Back on the host, allow the client in (fingerprint only — no address needed):
qsh trust add laptop --fingerprint sha256:<CLIENT_FP>

# Client:
qsh exec box -- uname -a                 # human mode: stdout/stderr pass through, exit code too
qsh exec box --json -- sh -c 'echo out; echo err >&2; exit 7'
# {"schema":"qsh.cli/v1",…,"command":"exec.run","ok":true,
#  "data":{"stdout_b64":"b3V0Cg==","stderr_b64":"ZXJyCg==","remote_exit_code":7,"signal":null,"duration_ms":7}}
echo $?                                  # 7 — the remote exit code (255 is clamped to 254; qsh's own failures are 255)
```

Without `--fingerprint`, `qsh trust add box --address …` connects, shows the
observed fingerprint and asks for confirmation (ssh-style); in `--json` mode
it returns `TRUST_REQUIRED` with `details.observed_fingerprint` instead of
prompting. Every request the host authorizes is written as one structured
line to `$XDG_STATE_HOME/qsh/audit.log`. Config lives in
`$XDG_CONFIG_HOME/qsh` (`identity.toml`, `trust.toml`, `config.toml`);
override both with `QSH_CONFIG_DIR` / `QSH_STATE_DIR`.

## Usage (target UX — M2 and later)

```bash
qsh dave@host              # interactive shell (M2)
qsh -L 8080:localhost:80 dave@host   # local port forward (M4)
qsh mcp                    # expose QSH as an MCP server (M6)
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
| M1 | Walking skeleton (`init`/`serve`/`exec --json`, mTLS, JSON envelope) | Done |
| M2 | Session broker, PTY, migration and resume | Next |
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
- Until the policy engine lands (M5), the host authorizes **every** pinned
  peer for `exec.run` (allow-all-pinned). Peers that authenticate through a
  trusted CA (`[[ca]]` in `trust.toml`) connect but get `PERMISSION_DENIED`;
  anything else is refused at the TLS handshake. Pin only devices you would
  give a shell to.
- `exec.run` returns the whole output in one envelope, so it is capped at
  64 MiB of stdout+stderr (`RESOURCE_EXHAUSTED` beyond that). Streaming
  output is a session feature (M2).
- Host names are resolved through the trust store (`qsh trust add <name>
  --address …`) until the host directory arrives in M7.

## Product boundary

QSH owns secure sessions, PTY lifecycle, reconnect, command execution and port forwarding. It connects to a user-provided routable hostname or IP address and does not depend on a control plane or relay.

## Development

Requires Rust stable.

```bash
cargo nextest run --workspace     # or: cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo run -p xtask -- arch
```
