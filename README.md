# QSH

QSH is a remote shell that speaks QUIC and connects straight to the machine
you name. No relay, no broker, no account.

SSH ties a PTY session's lifetime to the lifetime of the connection carrying
it, so an IP change, a laptop sleep, or a switch from Wi-Fi to tethering
kills the shell. QSH separates the two. The shell keeps running on the host,
and the client reconnects and resumes the same session instead of starting a
new one. Every connection is a direct QUIC connection to a hostname or IP
you supply, authenticated by TLS 1.3 mutual authentication against pinned
certificates.

One binary (`qsh`) is both ends: it serves, and it connects.

## Status

Pre-alpha. **Not for production use.**

M0 through M3 are done and M4 (port forwarding) is partway through. What
works end to end today:

- `qsh exec host -- cmd`, in human mode or as a single `qsh.cli/v1` JSON
  envelope with the remote exit code, stdout and stderr.
- Interactive PTY sessions: open one with `qsh dave@host`, detach with `~d`,
  reattach later with `qsh attach`, and resume across a connection that
  dropped or moved to a different address.
- Reverse connections, so a host behind NAT dials out to a controller
  (`qsh listen` / `qsh reverse`) and you attach to it through that
  controller. The target reconnects with backoff when the link dies.
- `-L` and `-R` port forwards, over forward connections and over reverse
  ones.

What is not there yet: the tunnel management commands `qsh tunnels` and
`qsh tunnel close` (documented in `docs/CLI.md` §6.9, not yet in the binary),
`-D` SOCKS forwarding (P1, and the `UNSUPPORTED` stub for it has not landed
either, so `-D` is currently a clap usage error), the throughput and latency
gates M4 owes, and the MCP adapter.

Authorization is the other unfinished half: read [Security
posture](#security-posture) before you pin anything.

## Install

Prebuilt binaries for macOS (arm64, x86_64) and Linux (x86_64,
aarch64) are attached to each [GitHub
release](https://github.com/DaveDev42/qsh/releases). One line installs the
latest:

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

The script picks the archive for your platform, verifies it against the
release's `SHA256SUMS` before unpacking, and installs to `~/.local/bin`. It
never calls `sudo`; if the target directory is not writable it says so and
stops. That checksum is an integrity check against a bad download, not a
signature: the binaries are neither signed nor notarized until M9.

| Variable | Default | Meaning |
|---|---|---|
| `QSH_VERSION` | latest release | Release tag to install, e.g. `v0.1.0-alpha.1` |
| `QSH_INSTALL_DIR` | `$HOME/.local/bin` | Where the `qsh` binary lands (created if missing) |
| `QSH_REPO` | `DaveDev42/qsh` | `owner/repo` to install from, for forks and testing |

To download by hand, take the asset matching your platform, check it against
`SHA256SUMS`, and put `qsh` somewhere on your `PATH`:

| Platform | Asset |
|---|---|
| macOS, Apple silicon | `qsh-<tag>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `qsh-<tag>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `qsh-<tag>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `qsh-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `qsh-<tag>-x86_64-pc-windows-msvc.zip` |

The installer has no Windows path. Take the `.zip` from the releases page.
Note the Windows caveat under [Known limitations](#known-limitations): the
tree compiles and the portable tests run there, but nothing is promised.

Building from source needs a Rust toolchain. `rust-toolchain.toml` pins
1.97.1, which is what CI and the release builds use:

```bash
cargo build --release -p qsh-cli    # binary at target/release/qsh
```

`scripts/README.md` covers the installer in more detail.

## Quick start

Both machines need the same binary. Start with identity and trust, which is
the part with no SSH equivalent: each device generates a keypair on `init`,
and each side pins the other's certificate fingerprint before anything
connects.

```bash
# On the host, the machine that will run the shell:
qsh init --json                          # creates the device identity; note "fingerprint"
qsh serve --bind 0.0.0.0:4433            # foreground; bound address goes to stderr

# On the client:
qsh init --json                          # note this device's "fingerprint" too
qsh trust add box --address host.example.com:4433 --fingerprint sha256:<HOST_FP>

# Back on the host, let the client in. No address needed, just the fingerprint:
qsh trust add laptop --fingerprint sha256:<CLIENT_FP>
```

Now run something:

```bash
qsh exec box -- uname -a                 # stdout, stderr and the exit code pass through
qsh exec box --json -- sh -c 'echo out; echo err >&2; exit 7'
# {"schema":"qsh.cli/v1",…,"command":"exec.run","ok":true,
#  "data":{"stdout_b64":"b3V0Cg==","stderr_b64":"ZXJyCg==","remote_exit_code":7,"signal":null,"duration_ms":7}}
echo $?                                  # 7, the remote exit code (255 clamps to 254; qsh's own failures are 255)
```

Drop `--fingerprint` and `qsh trust add box --address …` connects, shows the
fingerprint it observed, and asks you to confirm, the way SSH does on first
contact. In `--json` mode it returns `TRUST_REQUIRED` with
`details.observed_fingerprint` instead of prompting.

`qsh hosts` lists everything this machine can reach, pinned forward hosts
and live reverse registrations together, without dialing any of them.

Every authorized request is written as one structured line to
`$XDG_STATE_HOME/qsh/audit.log`. Config lives in `$XDG_CONFIG_HOME/qsh`
(`identity.toml`, `trust.toml`, `config.toml`). `QSH_CONFIG_DIR` and
`QSH_STATE_DIR` override both.

### An interactive session that outlives the connection

```bash
qsh dave@box                             # interactive shell
# type ~d at the start of a line to detach; the shell keeps running
qsh sessions box                         # list what is still alive over there
qsh attach box/01K0SESSION               # reattach, replaying what you missed
qsh session close box/01K0SESSION        # end it for real
```

`~.` also detaches. It does not kill the session, which is the one place
QSH deliberately breaks SSH muscle memory. `~~` sends a literal tilde, `~?`
prints the escape help to stderr, and `--escape-char` changes or disables
the escape character. Escape handling is only active when stdin is a TTY.

The `user@` prefix asserts which account you expect; it never selects one.
The remote shell always runs as the account that runs `qsh serve`, and
naming a different login gets you `UNSUPPORTED` instead of a session.

### Port forwards

`-L` and `-R` are companion flags on the interactive form. They open
tunnels alongside a real shell:

```bash
qsh box -L 8080:localhost:3000           # local :8080 reaches the host's :3000
qsh box -R 9000:localhost:9000           # host's :9000 reaches this machine's :9000
```

Both are repeatable, both share the grammar `[bind:]listen_port:host:host_port`,
and both bind loopback by default. A non-loopback bind on `-R` is refused by
the host with `INVALID_ARGUMENT`, no matter what the ACL says.

For a tunnel with no shell attached, use the machine-mode form. It emits one
`tunnel.open` envelope and then blocks until you interrupt it:

```bash
qsh tunnel open box --local 8080:localhost:3000 --json
qsh tunnel open box --remote 9000:localhost:9000 --json
```

A tunnel lives as long as the process holding it, with one exception: an
`-R` listener over a reverse connection is held by the resident `qsh listen`
daemon, so it survives the CLI and dies with the reverse connection.

### Reverse connections

When the host cannot accept inbound packets, invert the dial. The
controller listens; the target dials out and then serves that connection as
a host.

```bash
# On the controller, which needs a reachable UDP address:
qsh listen --bind 0.0.0.0:4433

# On the target, behind NAT, using the controller's trust-store alias:
qsh reverse controller --offered-name workshop

# From the controller, as usual:
qsh sessions workshop
qsh workshop -L 8080:localhost:3000
```

`qsh reverse` keeps reconnecting with backoff, so the target comes back on
its own after the link drops. `--offered-name` only takes effect when the
controller has no trust-store alias for that peer and its
`[listen].allow_advertised_names` is set; otherwise the controller names the
peer from its own trust store.

## Security posture

Every connection is QUIC with TLS 1.3 mutual authentication. Both ends
present a certificate and both ends check the other's fingerprint against
the trust store. Anything that fails to authenticate is rejected during the
handshake, before a session, tunnel, or listener exists.

Authorization is the part that is not finished. The policy engine is M5.
Until it lands, a host that authenticated a pinned peer authorizes that peer
for everything: opening and attaching sessions, writing to them,
opening tunnels, registering as a reverse controller or dialing in as one.
There is no per-peer scoping. Peers that authenticate through a trusted CA
(`[[ca]]` in `trust.toml`) complete the handshake and then get
`PERMISSION_DENIED` on every operation. Pin only devices you would hand a
shell to.

## Documents

- [Product Requirements](docs/PRD.md)
- [CLI, JSON and MCP Contract](docs/CLI.md)
- [Roadmap: milestones, scope and acceptance criteria](docs/ROADMAP.md)
- [Wire Protocol Design](docs/design/protocol.md)
- [Architecture Design](docs/design/architecture.md)
- [Test Strategy](docs/design/testing.md)
- [Architecture Decision Records](docs/adr/)

`docs/PRD.md` and `docs/CLI.md` are binding: they define behavior, the wire
format, and the JSON envelope shape. `qsh.cli/v1` and `qsh.event/v1` are
additive-only.

## Architecture

```
qsh-cli (bin `qsh`)  →  qsh-core  →  qsh-transport  →  qsh-proto
        └─────────── contract types ───────────────────►
```

- `qsh-proto`: sans-IO wire contract, framing, types, events, error codes.
  This is the fuzz surface.
- `qsh-transport`: QUIC glue over quinn and rustls. Owns the connection,
  knows nothing about sessions or ACL.
- `qsh-core`: all business logic. Typed operation layer, session broker,
  PTY, ACL, identity and trust, config.
- `qsh-cli`: thin frontend. Argument parsing, human/JSON/JSONL rendering,
  the interactive TUI, and eventually the MCP adapter.
- `qsh-testkit`: shared test harness with a loopback transport, a chaos
  proxy, and fixtures.

`qsh-cli` depends on `qsh-proto` for contract types and never on
`qsh-transport`. The full allowed-dependency matrix is enforced by
`cargo run -p xtask -- arch`, and a violation fails CI.

The binary is `qsh`; the Cargo package is `qsh-cli`, because `qsh` was
already taken on crates.io. The workspace stays `publish = false` until M9.

## Roadmap

| # | Milestone | Status |
|---|---|---|
| M0 | Decisions, workspace scaffold, CI | Done |
| M1 | Walking skeleton (`init`/`serve`/`exec --json`, mTLS, JSON envelope) | Done |
| M2 | Session broker, PTY, migration and resume | Done |
| M3 | Reverse connections (`listen`/`reverse`/`attach`) | Done |
| M4 | Port forwarding (`-L`/`-R`) | In progress |
| M5 | ACL and audit | Planned |
| M6 | MCP adapter | Planned |
| M7 | Trust UX, host profiles, `doctor` | Planned |
| M8 | Hardening (fuzz, soak, real-device mobility campaign) | Planned |
| M9 | Release (installers, Homebrew, notarization) | Planned |

Per-milestone scope, in/out boundaries and acceptance criteria live in
[docs/ROADMAP.md](docs/ROADMAP.md).

## Known limitations

Some of these are MVP scope decisions, some are unfinished work.

- Sessions die with the listener process. A session lives only as long as
  the `qsh serve` or `qsh reverse` process that opened it, so restarting the
  listener is the end of every detached session on it, not a resume point. A
  clean SIGTERM does drain: no new `session.open`, `session.attach` or
  `exec.run` is admitted from the signal onward, and every live session runs
  its normal close procedure. That drain is best effort rather than a
  guarantee. Delivery of `session.closed` to an attached consumer is bounded
  by a short flush window instead of awaited outright, and the whole drain
  gives up after a generous but finite timeout, logging a warning rather
  than hanging the process on one wedged session. Under a congested consumer
  or a stuck child, a shell can still outlive the process. A separate
  session supervisor is planned after MVP
  ([ADR-0003](docs/adr/0003-sessions-in-listener.md)).
- Port forwarding is half-built. `-L` and `-R` work on forward and reverse
  connections, but `qsh tunnels` and `qsh tunnel close` are specified and
  not yet implemented, `-D` is neither implemented nor stubbed, and the
  throughput and PTY-latency gates M4 owes have not been run.
- No policy engine before M5, so it is allow-all among pinned peers. See
  [Security posture](#security-posture).
- `qsh trust remove` only affects future handshakes. A peer you removed
  keeps whatever sessions and access it already holds until its connection
  drops and it has to handshake again.
- `exec.run` output is capped at 64 MiB. The whole of stdout plus stderr
  comes back in one envelope, and anything beyond the cap is
  `RESOURCE_EXHAUSTED`. Streaming output is a session feature: use
  `qsh session read` or an interactive session.
- Host names resolve through the trust store. `qsh hosts` and `qsh host`
  read that store back, but `qsh trust add <name> --address …` is the only
  way a name gets created, and there is no per-host profile or connection
  option until M7.
- Windows is P1 for the client and P2 for the host. PTY code is gated
  `#[cfg(unix)]`, and so is reverse mode: `qsh listen` and `qsh reverse`
  return `UNSUPPORTED` there rather than running. CI builds, lints and runs
  the portable test subset on `windows-latest` so the tree keeps compiling,
  but POSIX-only behavior such as signal exits and process-group kill is
  never exercised there.
- Reverse mode needs a directly reachable path from the target to the
  controller:

  > Reverse attach needs a directly reachable UDP path from the target to the controller. QSH provides no relay, NAT traversal, or discovery — that is out of scope for P0.
  >
  > Put the controller on a publicly routable address, a forwarded port, or an existing overlay such as WireGuard or Tailscale. If the controller itself is behind NAT, M3 has no answer for that.

## Product boundary

QSH owns secure sessions, PTY lifecycle, reconnect, command execution and
port forwarding. Getting a routable address to the host is somebody else's
job, and stays that way: see the reverse-reachability entry under [Known
limitations](#known-limitations).

## Development

```bash
cargo nextest run --workspace     # or: cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
cargo run -p xtask -- arch
```

All five have to be green before a commit. `docs/design/testing.md`
explains which tests each layer owes.
