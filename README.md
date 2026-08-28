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

M0 through M3 are done, and M4 (port forwarding) has landed what its
acceptance criteria ask for. What works end to end today:

- `qsh exec host -- cmd`, in human mode or as a single `qsh.cli/v1` JSON
  envelope with the remote exit code, stdout and stderr.
- Interactive PTY sessions: open one with `qsh dave@host`, detach with `~d`,
  reattach later with `qsh attach`, and resume across a connection that
  dropped or moved to a different address.
- Reverse connections, so a host behind NAT dials out to a controller
  (`qsh listen` / `qsh reverse`) and you attach to it through that
  controller. The target reconnects with backoff when the link dies.
- `-L` and `-R` port forwards, over forward connections and over reverse
  ones, plus the standalone `qsh tunnel open`/`qsh tunnels`/
  `qsh tunnel close` machine-mode commands.

`-D` (SOCKS5 dynamic forwarding) parses on both the interactive and
`tunnel open` forms but always answers `UNSUPPORTED` with the message
"SOCKS dynamic forwarding (-D) is a P1 feature". The MCP adapter is
still M6.

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
the host with `INVALID_ARGUMENT` ("remote forward binds loopback only"), no
matter what the ACL says.

For a tunnel with no shell attached, use the machine-mode form. It emits one
`tunnel.open` envelope and then blocks until you interrupt it:

```bash
qsh tunnel open box --local 8080:localhost:3000 --json
qsh tunnel open box --remote 9000:localhost:9000 --json
qsh tunnels --json                       # tunnels a resident daemon holds
qsh tunnel close <tunnel-id> --json
```

A tunnel lives as long as the process holding it, with one exception: an
`-R` listener over a reverse connection is held by the resident `qsh listen`
daemon, so it survives the CLI and dies with the reverse connection. `qsh
tunnels`/`qsh tunnel close` only see and act on what a daemon holds, so a
plain foreground `-L`/`-R` never shows up there; closing one of those means
interrupting the process that opened it. See [Known
limitations](#known-limitations) for what happens to a tunnel across a
dropped connection; it is not the same as what happens to a session.

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

Authorization is `acl.toml`: a small, principal-scoped rule file at
`<config_dir>/acl.toml`. It is default-deny — a host with no `acl.toml`,
or one that fails to parse, denies every operation from every peer, full
stop. There is no fallback to "any pinned peer gets everything" any more,
and qsh never creates or edits the file for you; an operator writes it by
hand. Each rule names a principal (`user:<name>`, `device:<name>`, or
`fp:sha256:<fingerprint>`), the auth path it applies to (`pin`, the
default when omitted, or `ca`), and the actions it grants — an exact name
like `exec.run`, or a trailing-wildcard family like `session.*`. A peer
that authenticates through a trusted CA (`[[ca]]` in `trust.toml`) gets
exactly what a rule with an explicit `auth_path = "ca"` grants it; a rule
that omits `auth_path` (the pin default) never matches a CA-authenticated
peer, even when the principal string is identical. `forward.socks`,
`file.read`, and `file.write` are defined in the action vocabulary but
always denied regardless of any rule — those operations are P1,
unimplemented. Every refusal a remote peer sees is the same opaque
`PERMISSION_DENIED` message, whether it came from a missing rule, a
policy file that failed to load, or an audit-write failure.

The policy loads once, when `qsh serve`/`qsh listen`/`qsh reverse` starts
— there is no hot reload, so an edit to `acl.toml` only takes effect on
the next restart. If the file is missing or invalid at startup, the
process still comes up (it still answers, it just denies everything) and
prints a diagnostic to stderr exactly once: `no usable acl.toml policy`,
`every request is denied until this is fixed`, the exact path it looked
at, the `CONFIG_ERROR` code, a copy-pasteable minimal policy filled in
with this machine's actual pinned peers, and
`acl.toml is never auto-generated — create it by hand`, and finally
`verify a fix before restarting: qsh acl check`. The diagnostic's
`code` field tells the two causes apart: `acl_policy_missing` (no file)
versus `acl_policy_invalid` (parse/validation failure). It never dumps
raw source lines from the file; the only echo is a bounded (≤128-byte,
single-line-escaped) grammar token from the offending rule (unknown
action pattern / `auth_path` / scope). On unix, a group- or
world-writable `acl.toml` also gets a one-time stderr warning rather than
a refusal to load it: an operator locked out of their own host by a
permissions slip has no way back in if loading it denied instead of
warned. Windows ACL checking is out of scope. Pin only devices you would
hand a shell to, and write down what you actually want each of them to
be able to do.

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
| M4 | Port forwarding (`-L`/`-R`) | Done |
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
- A tunnel does not resume the way a session does. `-L` and `-R` work over
  both forward and reverse connections, `qsh tunnels`/`qsh tunnel close`
  manage what a resident daemon holds, and `-D` (SOCKS5 dynamic forwarding)
  parses but always answers `UNSUPPORTED` — implementation is P1, and there
  is no SOCKS proxy or UDP forwarding either. Remote forwards bind loopback
  only; a non-loopback `bind` is refused, ACL notwithstanding. What a
  tunnel does not have is a session's replay ring: a connection that drops
  and later resumes ends any in-flight tunnel TCP connection cleanly rather
  than replaying it. An `-L` listener survives that if the process holding
  it is still alive, but the forward itself does not — a new connection
  into that listener after the reconnect gets a clean reset until you
  restart the forward. An `-R` registration has to be reopened by hand; it
  is never reissued automatically. QUIC path migration is a different
  case from a drop-and-resume: switching networks without losing the
  connection outright (Wi-Fi to tethering, a changed IP) carries an open
  tunnel through transparently, the same as it does a session.
- `acl.toml` has no hot reload: an edit only takes effect the next time
  `qsh serve`/`qsh listen`/`qsh reverse` starts, and qsh never creates or
  edits the file for you. See [Security posture](#security-posture).
- The audit log is fail-closed: `qsh serve`/`qsh reverse` deny an
  otherwise-allowed `session.open`, `exec.run`, or `host.reverse`
  registration rather than let it through with no durable audit record —
  a full disk, a permissions problem on the audit directory, or a writer
  backlogged past its bounded queue all deny in the same way a policy
  refusal does. There is no override; recording an authorization decision
  is a precondition for granting it, not best-effort logging alongside it.
  While the audit log is unwritable, every privileged operation is denied,
  full stop — there is no degraded-but-serving mode. Recovery is automatic:
  once the audit log is writable again, the writer's own background retry
  clears the condition and operations start succeeding again on their own,
  with no restart and no operator action needed. The audit record's
  fields are structural by design: argv, PTY bytes, and key material never
  appear in it. `audit.log_argv` is named in the design docs as a
  sanctioned future exception; M5 does not implement it.
- There is no per-principal or per-forward quota. A pinned peer with
  `session.*`/`forward.*` can open as many sessions or remote forwards as
  it likes, and nothing here caps concurrent sessions, connections, or
  forwards per principal. M8's adversarial load gate adds that
  enforcement (`[serve].max_sessions` and a per-principal session cap);
  the ACL engine itself never will.
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
  return `UNSUPPORTED` there rather than running. A tunnel over a reverse
  connection needs that same daemon and inherits the restriction; `-D` is
  `UNSUPPORTED` on every platform regardless. CI builds, lints and runs
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
