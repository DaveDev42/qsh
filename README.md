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

Version 0.2.0. **Not for production use**: the M10 release gates
(codesign, notarization, a static musl build, SLSA provenance, and a
release-profile functional smoke test) are still open.

M0 through M6 are done. M7 (trust UX, host profiles, `doctor`) has landed
its features; what is left is the stopwatch campaign in
`docs/campaigns/m7-stopwatch.md`, which a person has to run. M8 (hardening)
has landed its code and closed its 24-hour soak (`docs/campaigns/m8-soak.md`
run #6, PASS): the admission and quota defenses, the adversarial-load gate
(`docs/campaigns/m8-adversarial-load.md`), the fuzz campaign
(`docs/campaigns/m8-fuzz.md`: 72 fuzz-hours per parser target, no crashes),
the wire-format freeze draft and the threat model. Two M8 items are still
open: the real-device mobility campaign and the independent security
review. The freeze draft takes effect once the operator decides on that
review. M9 (the human-facing surface: naming, pairing, `qsh service
install`) is underway. What works end to end today:

- `qsh exec host -- cmd`, in human mode or as a single `qsh.cli/v1` JSON
  envelope with the remote exit code, stdout and stderr.
- Interactive PTY sessions: open one with `qsh dave@host`, detach with `~d`,
  reattach later with `qsh attach`, and resume across a connection that
  dropped or moved to a different address.
- Reverse connections, so a host behind NAT dials out to a controller
  (`qsh listen` / `qsh serve --to`, formerly `qsh reverse`) and you attach
  to it through that controller. The target reconnects with backoff when
  the link dies.
- `-L` and `-R` port forwards, over forward connections and over reverse
  ones, plus the standalone `qsh tunnel open`/`qsh tunnels`/
  `qsh tunnel close` machine-mode commands. `-D` (SOCKS5 dynamic
  forwarding) is a third mode on both the interactive and `tunnel open`
  forms — see below.
- A default-deny ACL (`acl.toml`) and a fail-closed audit log gate every
  operation a remote peer requests. See [Security
  posture](#security-posture).
- A stable `--json`/`--jsonl` CLI contract (`qsh.cli/v1`) for agents and
  scripts. The built-in `qsh mcp` stdio server was retired in M8 Step 6
  (see [ADR-0011](docs/adr/0011-remove-mcp-adapter.md)); run a remote
  stdio MCP server through `qsh exec host -- <server>` instead.
- Four ways to pin a peer: trust-on-first-connect, `qsh pair
  invite`/`qsh pair accept` pairing with a one-time code, a private CA
  (`qsh cert init`/`qsh cert issue`) so a fleet trusts one CA root instead
  of pinning every device by hand, or exchanging certificate files
  directly (`qsh identity export`, `qsh trust add --cert-file`, `qsh
  trust add-ca` for a foreign CA root — ADR-0013). A pinned peer's local
  name can be changed later without re-pinning, with `qsh trust rename`.
  `hosts.toml` layers addresses and login names on top of whichever one
  pinned a peer. See [First run](#first-run).
- `qsh service install|uninstall|status` writes and removes the platform
  unit that keeps a listener running — a user LaunchAgent on macOS, a
  systemd user unit on Linux — inferring the mode (`serve`, `listen`, or
  `serve --to`) from `config.toml`. See
  [docs/deploy/service.md](docs/deploy/service.md).
- `qsh doctor` diagnoses one deployment — identity, ACL policy, audit log,
  trust store, clock, network reachability — as a single machine-readable
  report. `qsh schema --json` serves this build's JSON contract the same
  way, and `qsh capabilities` reports its supported capabilities, or, given
  a pinned host, what was actually negotiated with that peer.

`-D` (SOCKS5 dynamic forwarding, [ADR-0019](docs/adr/0019-socks-dynamic-forward.md))
opens a loopback-only SOCKS5 listener instead of a fixed destination:
`qsh dave@host -D 1080` (repeatable, alongside the session) or
`qsh tunnel open host --dynamic 1080` (one listener per call, mutually
exclusive with `--local`/`--remote`). It is not a new grant:

> `-D` runs SOCKS5 on this machine and authorizes every CONNECT on the peer as `forward.local`; `forward.socks` is never consulted.

so a peer already trusted with `forward.local` needs no extra
configuration to use it — see [Security posture](#security-posture) for
what that implies. It works over both forward and reverse routes
([ADR-0020](docs/adr/0020-socks-reverse-route.md) decisions 1–3): a
reverse route relays each CONNECT through this machine's resident
`qsh listen` daemon, with the same host-local address filter a forward
route enforces. It refuses before binding anything only when the
connected route does not advertise the `dial-filter.v1` capability that
lets the host filter out loopback/link-local/metadata addresses from a
proxied CONNECT. Point applications
at `socks5h://127.0.0.1:1080` (remote DNS), not `socks5://`, so a hostname
does not leak to local resolution: `curl --socks5-hostname 127.0.0.1:1080
http://internal-service/`.

## Install

Prebuilt binaries for macOS (arm64, x86_64), Linux (x86_64,
aarch64) and Windows (x86_64) are attached to each [GitHub
release](https://github.com/DaveDev42/qsh/releases). The one-line installer
below covers macOS and Linux; on Windows take the `.zip` (see [Manual
download](#manual-download)).

One line installs the latest:

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

The script picks the archive for your platform, verifies it against the
release's `SHA256SUMS` before unpacking, and installs to `~/.local/bin`. It
never calls `sudo`; if the target directory is not writable it says so and
stops. That checksum is an integrity check against a bad download, not a
signature: the binaries are neither signed nor notarized until M10.

| Variable | Default | Meaning |
|---|---|---|
| `QSH_VERSION` | latest release | Release tag to install, e.g. `v0.1.0-alpha.1` |
| `QSH_INSTALL_DIR` | `$HOME/.local/bin` | Where the `qsh` binary lands (created if missing) |
| `QSH_REPO` | `DaveDev42/qsh` | `owner/repo` to install from, for forks and testing |

### Manual download

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

### Homebrew (macOS)

```bash
brew install DaveDev42/tap/qsh
```

Apple silicon only for now — the formula tracks the `aarch64-apple-darwin`
release tarball. The Homebrew version is the release tag without its
leading `v`; there is no separate versioning scheme.

### From source

Building from source needs a Rust toolchain. `rust-toolchain.toml` pins
1.98.1, which is what CI and the release builds use. Either build in a
clone and place the binary yourself:

```bash
cargo build --release -p qsh-cli    # binary at target/release/qsh
```

or let `cargo install` build and place it in one step, straight from this
repository:

```bash
cargo install --locked --git https://github.com/DaveDev42/qsh qsh-cli
```

There is no `cargo install qsh-cli` from crates.io yet: the workspace is
`publish = false` until M10, so `--git` (or `--path` against a local clone)
is the only `cargo install` route today. The package name `qsh-cli` is
unclaimed and reserved for that release; the shorter name `qsh` is not —
it belongs to an unrelated project — which is why the crate is `qsh-cli`
even though the binary it installs is `qsh`.

`scripts/README.md` covers the installer in more detail.

Running qsh as a service: `qsh service install|uninstall|status` generates
and manages the unit for you — see
[docs/deploy/service.md](docs/deploy/service.md).

Man pages for every subcommand are generated from the same `clap`
definitions `--help` uses and live under [`docs/man/`](docs/man/)
(`cargo xtask man` regenerates them; `docs/design/testing.md` covers the
test that keeps them from drifting). Nothing installs them onto a system
`MANPATH` yet — that lands with M10's packaging — so point `man` at a page
directly instead: `man ./docs/man/qsh.1`, or `man ./docs/man/qsh-trust-add.1`
for a subcommand.

## First run

Six commands and one small policy file, two machines. This is the literal
script `docs/campaigns/m9-stopwatch.md` times (and
`docs/campaigns/m7-stopwatch.md` timed before the M9 surface landed): two
machines that have never run `qsh` before, nothing but this section open,
stopwatch running from the first command.

```bash
# Host, the machine that will run the shell:
qsh init --json                              # note "fingerprint" in the output
```

`acl.toml` loads once, at `qsh serve` startup, with no hot reload: it has to
exist *before* `serve` runs, or the host denies everything until it's
restarted. `laptop` below is just the name the client gets pinned under a
few steps down; the rule can reference it now and take effect once that
pin exists.

```toml
# <config_dir>/acl.toml, next to trust.toml: written by hand, qsh never
# generates this file:
[[acl]]
principal = "device:laptop"
allow = ["session.*"]
```

```bash
qsh serve --bind 0.0.0.0:4433               # leave this running

# Client, in a separate terminal on the other machine:
qsh init --json                              # note this device's fingerprint too
qsh trust add box --address host.example.com:4433 --fingerprint sha256:<HOST_FP>

# Host, in a second terminal, let the client in. This can happen after
# "serve" has already started; unlike acl.toml, trust.toml is re-read on
# every handshake, so no restart is needed:
qsh trust add laptop --fingerprint sha256:<CLIENT_FP>

# Client, first shell:
qsh dave@box
```

Swap `host.example.com:4433` for wherever the host actually listens, and
the two `sha256:…` fingerprints for what `qsh init --json` printed on each
side. `box` and `laptop` are names picked for this walkthrough. Call the
two machines whatever you want. `dave` has to be the account actually
running `qsh serve` on the host, or the host answers `UNSUPPORTED`; drop
the `dave@` prefix entirely (`qsh box`) and it always works, since the
shell runs as that account either way (`user@` only ever asserts, it never
selects; see [`user@`'s meaning](docs/CLI.md#7-human-interactive-mode)).

Typing the fingerprint by hand is the part most likely to cost time. Drop
`--fingerprint` from the client's `trust add` and it dials instead, prints
the fingerprint it observed, and asks you to confirm. It's the same
trust-on-first-connect flow SSH has for host keys, without needing the
value copied over some other channel first.

There's a third way to get two devices trusting each other, next to typing a
fingerprint and confirming one on first connect: pairing with a one-time
code. One side prints it, the other redeems it, and both ends up pinned in
the same exchange.

```bash
# Host:
qsh pair invite --json
# {"data":{"code":"abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab", "expires_at":"…",
#          "accept_command":"qsh pair accept <address> abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab"}}

# Client, filling in the host's real address:
qsh pair accept host.example.com:4433 abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab
```

The code carries no address, just a secret — read it over the phone, paste
it in a chat, whatever channel is at hand. Knowing it is what gets checked,
over a TLS-exporter-bound exchange (`docs/design/protocol.md` §15); neither
side needs the other's fingerprint ahead of time, since possession of the
secret is the whole proof. That's a different claim from "no need to ever
check a fingerprint" — the secret still travels over a human channel that
can be mistyped or overheard, so anyone who wants more assurance than
"whoever knew the code" can compare `trust list`'s fingerprint out of band
after pairing, same as they would after any other first connection. It
works once and expires in ten minutes, and a running `qsh serve` recognizes
a freshly minted invite without a restart, the same way it picks up `trust
remove` (`docs/CLI.md` §6.11).

A fourth way skips both fingerprint-typing and pairing codes: exchange
certificate files directly (ADR-0013). Only an inbound `qsh serve` opens
the invite-redemption window, so nothing can pair *to* a `qsh listen` or
`qsh serve --to` peer by code; a certificate file is how that peer gets
pinned.

```bash
qsh identity export > box.pem                     # on box
scp box.pem laptop:                                # however the file travels
qsh trust add box --cert-file box.pem --json       # on laptop
```

`qsh identity export` never prints a private key, only the certificate
that `qsh trust add --cert-file` reads back into a fingerprint pin
(`qsh trust add-ca` does the same for a foreign CA root). See
`docs/CLI.md` §6.11 for the full contract, including piping it straight
over SSH with `--cert-file -`.

From here, `qsh hosts` lists what this machine can reach, `qsh sessions
box` lists what's alive on the host, and the [Quick
start](#quick-start) section below covers detach/reattach, port
forwards, and reverse connections. Once a name is pinned, an operator who
wants to skip retyping `user@` or move an address without touching the
trust store can add it to `hosts.toml` by hand, next to `trust.toml`:

```toml
# <config_dir>/hosts.toml: read by qsh, never written by it
[[host]]
name = "box"
address = "host.example.com:4433"
user = "dave"
```

`hosts.toml`'s address wins over `trust.toml`'s when a name is in both, and
its `user` fills in when `user@` is left off. Identity is still
`trust.toml`'s job alone; `hosts.toml` never supplies one. That split cuts
both ways: write access to `hosts.toml` is the power to redirect a name to
a different already-pinned peer (mTLS still blocks an unpinned address).
`qsh hosts --json` reveals such a redirect through `"source": "hosts"`
(`docs/CLI.md` §5).

## Quick start

Everything below assumes the two machines from [First run](#first-run):
`box` is the host running `qsh serve`, `laptop` is the client, and each has
pinned the other. One addition to the host's `acl.toml`: the commands here
need `exec.run` alongside `session.*`.

### Running one command

Now run something:

```bash
qsh exec box -- uname -a                 # stdout, stderr and the exit code pass through
qsh exec box --json -- sh -c 'echo out; echo err >&2; exit 7'
# {"schema":"qsh.cli/v1",…,"command":"exec.run","ok":true,
#  "data":{"stdout_b64":"b3V0Cg==","stderr_b64":"ZXJyCg==","remote_exit_code":7,"signal":null,"duration_ms":7}}
echo $?                                  # 7, the remote exit code (255 clamps to 254; qsh's own failures are 255)
```

`qsh hosts` lists everything this machine can reach, pinned forward hosts
and live reverse registrations together, without dialing any of them.

Every authorized request is written as one structured line to
`$XDG_STATE_HOME/qsh/audit.log`. Config lives in `$XDG_CONFIG_HOME/qsh`
(`identity.toml`, `trust.toml`, `config.toml`). `QSH_CONFIG_DIR` and
`QSH_STATE_DIR` override both.

The private key does not live in any of those files by default: `init` puts
it in the OS credential store (Keychain on macOS, Secret Service on Linux)
and falls back to a 0600 file where none is reachable. `qsh init --key-store
file` skips the credential store entirely, which is what you want on a shared
or managed machine (`docs/CLI.md` §6.11).

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
the host with `INVALID_ARGUMENT`, no matter what the ACL says. The refusal's
message is exactly:

> remote forward binds loopback only: this bind could not be confirmed as a loopback address, so nothing was opened on the host. Re-run `-R` with a loopback bind (omit the bind, or use `127.0.0.1` / `[::1]`).

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

### SOCKS proxy (`-D`)

`-D` opens a SOCKS5 proxy on this machine. For every `CONNECT` a SOCKS
client sends to it, the host dials whatever destination that `CONNECT`
names:

```bash
qsh box -D 1080                             # SOCKS5 on 127.0.0.1:1080, alongside the shell
qsh tunnel open box --dynamic 1080 --json   # the same listener with no shell attached
curl --socks5-hostname 127.0.0.1:1080 http://internal-service/
```

Two things have to be true before the first `CONNECT` succeeds:

- The host's `acl.toml` grants the client `forward.local` (or the
  `forward.*` family). `-D` reuses the `-L` grant; the First run example
  above only grants `session.*`, so add the action there. `-R` needs
  `forward.remote` the same way.
- Both ends run a build that negotiates `dial-filter.v1`, which is what
  lets the host refuse loopback, link-local and metadata destinations. An
  older peer is refused before anything binds. Over a reverse route the
  resident `qsh listen` daemon relays the capability set it negotiated
  with the target when that target registered; a daemon still running
  from before this machine's own upgrade keeps relaying the old set, so
  restart it.

Point applications at `socks5h://127.0.0.1:1080` so the host resolves the
name; with plain `socks5://` it is resolved here and leaks to the local
resolver. Destinations on the host's loopback or link-local ranges get
`REP 0x02` no matter what the ACL says; `-L` is the tool for those.

### Reverse connections

When the host cannot accept inbound packets, invert the dial. The
controller listens; the target dials out and then serves that connection as
a host. The controller plays both listener and client roles; the target is
the host machine (ADR-0012).

Two axes decide the four commands (ADR-0012 decision 1):

| | accepts inbound | dials out |
|---|---|---|
| gives up a shell (host) | `qsh serve` | `qsh serve --to` |
| gets a shell (client) | `qsh listen` | `qsh <name>`, `qsh exec` |

```bash
# On the controller, which needs a reachable UDP address:
qsh listen --bind 0.0.0.0:4433

# On the target, behind NAT, using the controller's trust-store alias:
qsh serve --to controller --name workshop

# From the controller, as usual:
qsh sessions workshop
qsh workshop -L 8080:localhost:3000
```

`qsh serve --to` keeps reconnecting with backoff, so the target comes back
on its own after the link drops. `--name` only takes effect when the
controller has no trust-store alias for that peer and its
`[listen].allow_advertised_names` is set; otherwise the controller names the
peer from its own trust store. The former `qsh reverse controller
--offered-name workshop` spelling still works, silently, as a hidden
alias — no deprecation warning, no scheduled removal.

### MCP server (retired, ADR-0011)

The built-in `qsh mcp` stdio server, a twelve-tool adapter over the same
typed operation layer the CLI uses, was removed in M8 Step 6. Agents go
through the `qsh.cli/v1` JSON/JSONL CLI instead: `session read
--wait`/`--follow` carries the same `next_after`/`next_ctl_after` long-poll
cursor the old `read_session` tool did. To reach a remote stdio MCP server,
run it as the remote command itself (`qsh exec host -- <server>`) and let
qsh be the transport; see [ADR-0011](docs/adr/0011-remove-mcp-adapter.md),
whose fixture stays checked in at `crates/qsh-cli/tests/fixtures/mcp/`.

## Security posture

Every connection is QUIC with TLS 1.3 mutual authentication. Both ends
present a certificate and both ends check the other's fingerprint against
the trust store. Anything that fails to authenticate is rejected during the
handshake, before a session, tunnel, or listener exists. The one narrow,
time-boxed exception is `qsh pair invite`/`qsh pair accept`: while a
freshly minted invite is live, an otherwise-unpinned certificate is admitted
into a dedicated pairing exchange that can do nothing but verify possession
of the invite's secret and, on success, pin — it never reaches a session,
tunnel, or listener path (`docs/design/protocol.md` §15).

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
peer, even when the principal string is identical. `file.read` and
`file.write` are defined in the action vocabulary but always denied
regardless of any rule — those operations are P1, unimplemented.
`forward.socks` is defined too and always denied as well, but for a
different reason: no operation is ever authorized through it, by design
([ADR-0019](docs/adr/0019-socks-dynamic-forward.md)) — `-D` (SOCKS5
dynamic forwarding, see above) reuses `forward.local` instead. Every
refusal a remote peer sees is the same opaque
`PERMISSION_DENIED` message, whether it came from a missing rule, a
policy file that failed to load, or an audit-write failure.

The policy loads once, when `qsh serve`/`qsh listen`/`qsh serve --to` starts
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
- [CLI and JSON Contract](docs/CLI.md)
- [Roadmap: milestones, scope and acceptance criteria](docs/ROADMAP.md)
- [Wire Protocol Design](docs/design/protocol.md)
- [Architecture Design](docs/design/architecture.md)
- [Test Strategy](docs/design/testing.md)
- [Threat Model](docs/design/threat-model.md)
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
  This is the fuzz surface (`fuzz/` also drives the `qsh-core` broker
  state machine through `broker_ops`).
- `qsh-transport`: QUIC glue over quinn and rustls. Owns the connection,
  knows nothing about sessions or ACL.
- `qsh-core`: all business logic. Typed operation layer, session broker,
  PTY, ACL, identity and trust, config.
- `qsh-cli`: thin frontend. Argument parsing, human/JSON/JSONL rendering,
  and the interactive TUI. The built-in MCP adapter it once carried was
  retired in M8 Step 6 (ADR-0011).
- `qsh-testkit`: shared test harness with a loopback transport, a chaos
  proxy, and fixtures.

`qsh-cli` depends on `qsh-proto` for contract types and never on
`qsh-transport`. The full allowed-dependency matrix is enforced by
`cargo run -p xtask -- arch`, and a violation fails CI.

The binary is `qsh`; the Cargo package is `qsh-cli`, because `qsh` was
already taken on crates.io. The workspace stays `publish = false` until M10.

## Roadmap

| # | Milestone | Status |
|---|---|---|
| M0 | Decisions, workspace scaffold, CI | Done |
| M1 | Walking skeleton (`init`/`serve`/`exec --json`, mTLS, JSON envelope) | Done |
| M2 | Session broker, PTY, migration and resume | Done |
| M3 | Reverse connections (`listen`/`serve --to`/`attach`) | Done |
| M4 | Port forwarding (`-L`/`-R`) | Done |
| M5 | ACL and audit | Done |
| M6 | MCP adapter | Done (retired, ADR-0011) |
| M7 | Trust UX, host profiles, `doctor` | Features done; stopwatch campaign open |
| M8 | Hardening (fuzz, soak, real-device mobility campaign) | Code done; mobility campaign, wire freeze and security review open |
| M9 | Human-facing surface (naming, pairing, service install) | In progress |
| M10 | Release (installers, Homebrew, notarization) | Planned |

The Homebrew tap (`DaveDev42/tap`) and the release workflow's auto-bump job
already exist as a skeleton ahead of M10; the rest of M10's scope is still
Planned — see [docs/ROADMAP.md](docs/ROADMAP.md) for the full list.

Per-milestone scope, in/out boundaries and acceptance criteria live in
[docs/ROADMAP.md](docs/ROADMAP.md).

## Known limitations

Some of these are MVP scope decisions, some are unfinished work.

- Sessions die with the listener process. A session lives only as long as
  the `qsh serve` or `qsh serve --to` process that opened it, so restarting the
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
- A tunnel does not resume the way a session does. `-L`, `-R` and `-D`
  (SOCKS5 dynamic forwarding) all work over both forward and reverse
  connections (ADR-0020 decisions 1–3, superseding ADR-0019 decision 10's
  forward-only restriction): a `-D` listener over a reverse route relays
  every `CONNECT` through this machine's resident `qsh listen` daemon to
  the target's live registration, with the same host-local address filter
  a forward-route `-D` enforces. Either route is refused before anything
  binds if the connected peer never negotiated `dial-filter.v1`
  (`qsh tunnels`/`qsh tunnel close` manage what a resident daemon holds).
  There is still no UDP forwarding (`UDP ASSOCIATE` gets `REP 0x07`, the
  same "unsupported command" reply BIND gets). Remote forwards bind loopback
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
- `qsh serve` and `qsh listen` share one default port. Both bind `[::]:4433`
  unless told otherwise, so a machine taking both roles needs an explicit
  `--bind` (or `[serve].bind`/`[listen].bind`) for at least one of them. The
  second one to start fails immediately with `CONFIG_ERROR` and exit `255`
  rather than half-working, with this remedy on stderr, exactly:

  > Nothing is being served. `qsh serve` and `qsh listen` both default to port 4433, so one machine running both needs an explicit bind for at least one of them. Re-run with `--bind <ip:port>` on a free port.
- `acl.toml` has no hot reload: an edit only takes effect the next time
  `qsh serve`/`qsh listen`/`qsh serve --to` starts, and qsh never creates or
  edits the file for you. See [Security posture](#security-posture).
- The audit log is fail-closed: `qsh serve`/`qsh serve --to` deny an
  otherwise-allowed `session.open`, `session.attach`, session write,
  `exec.run`, or `host.reverse` registration rather than let it through
  with no durable audit record —
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
- Quotas are fixed defaults for now. Concurrent sessions, `exec.run`
  runs and connections are capped per listener and per principal, tunnel
  streams per principal and per forward, remote forwards per principal,
  and the admission gate caps concurrent handshakes and the per-source
  rate (`[serve].max_sessions` and friends, `docs/CLI.md` §6.12). A key
  set to `0` or left unset means the default, not unlimited, and there is
  no switch that turns a cap off. The ACL engine itself never enforces
  quotas.
- `qsh trust remove` only affects future handshakes. A peer you removed
  keeps the connection's entire negotiated authority — not just the
  sessions it already had open, but the ability to open brand-new ones,
  including new sessions, tunnels, and forwards within the ACL scope
  loaded when `qsh serve` started — until that connection drops and it
  has to handshake again. This applies to an already-running `qsh serve`
  with no restart: the host re-reads `trust.toml` on every handshake, so
  the very next connection attempt from the removed peer is rejected
  immediately (`docs/CLI.md` §6.11). Force-closing a peer's
  already-established connection on removal is P1.
- `qsh trust rename` takes effect on the *next handshake* immediately, no
  restart needed, the same way `qsh trust remove` does — but `acl.toml`
  rows do not: they still match the pre-rename name until `qsh serve` is
  restarted, since `acl.toml` has no hot reload at all (ADR-0012 decision 7).
  A renamed peer's next connection authenticates fine but can be denied
  every operation until the ACL rows catch up.
- `qsh service status`/`qsh service uninstall` only ever look at the run
  mode inferred from today's `config.toml` (`docs/CLI.md` §6.18) — a unit
  installed under a previous mode (say, `config.toml` used to say
  `listen` and now says `serve --to`) is invisible to both, and neither
  reports nor removes it. The unit's recorded binary path also means
  something different per platform: macOS keeps a Homebrew Cellar symlink
  unresolved on purpose, so `brew upgrade` does not pin a stale path,
  while Linux's `/proc/self/exe` has already resolved any symlink by the
  time `qsh service install` reads it.
- `qsh pair accept` pins both sides in one exchange, but the two pins are
  not atomic. The host's pin (and the invite's consumption) happens first,
  as part of the wire exchange; the client's own local pin happens after,
  entirely on its own. If the client hits a name collision in its own
  trust store at that point, the invite is already spent, and the client
  has to resolve the local collision and get a fresh invite rather than
  the whole exchange rolling back. A collision on the host's side, during
  the exchange itself, does roll back cleanly: the invite is left
  redeemable (`docs/design/protocol.md` §15.6).
- Retrying `qsh pair accept` against a peer the host already pinned
  fails as a non-retryable `SESSION_CONFLICT`, and **a fresh invite does
  not fix it** — the host's pin makes the ordinary mTLS path win before
  the connection ever reaches invite/pairing logic again, so the invite's
  own state is not the problem. Recovery is `qsh trust remove` on the
  host, then a new `pair invite`/`pair accept` round
  (`docs/design/protocol.md` §15.6, `docs/CLI.md` §6.11).
- `qsh pair invite` does not know this device's reachable address. Human
  mode suggests candidates by asking the kernel which source address a
  packet leaving this host would carry, but that is a routing observation,
  not a reachability check — behind NAT or a firewall none of them may work
  — and a host with no default route, or one whose only answer is an
  address that means nothing off this machine, gets no candidates at all,
  since there is no interface-enumeration fallback. The operator still
  picks the address and relays it out of band (`docs/CLI.md` §6.11).
- A listener is not a code-pairing peer: only an inbound `qsh serve`
  redeems invite codes, so `qsh pair invite`/`qsh pair accept` cannot
  pin a `qsh listen` or `qsh serve --to` peer. Pin that peer by
  certificate file instead (`qsh identity export`, `qsh trust add
  --cert-file`, `docs/CLI.md` §6.11, §6.13).
- `exec.run` output is capped at 64 MiB. The whole of stdout plus stderr
  comes back in one envelope, and anything beyond the cap is
  `RESOURCE_EXHAUSTED`. Streaming output is a session feature: use
  `qsh session read` or an interactive session.
- Host names resolve through `hosts.toml` first, falling back to the trust
  store. `qsh hosts` and `qsh host` read both back. `hosts.toml` is
  read-only from the CLI's side — nothing writes it for you, so `name =
  "…" / address = "…" / user = "…"` entries are added by hand, next to
  `trust.toml`. It is a pure address book: identity still comes from the
  trust store alone, and an entry there for a name with no matching pin
  dials an address nobody has vouched for.
- Windows is P1 for the client and P2 for the host. PTY code is gated
  `#[cfg(unix)]`, and so is reverse mode: `qsh listen` and `qsh serve --to`
  return `UNSUPPORTED` there rather than running. A tunnel over a reverse
  connection needs that same daemon and inherits the restriction.
  `qsh tunnel open --dynamic` is cross-platform like `--local`/`--remote`;
  the interactive `-D` spelling is not, since the interactive PTY driver
  it rides is itself `#[cfg(unix)]`. CI builds, lints and runs
  the portable test subset on `windows-latest` so the tree keeps compiling,
  but POSIX-only behavior such as signal exits and process-group kill is
  never exercised there.
- Reverse mode needs a directly reachable path from the target to the
  controller:

  > Reverse attach needs a directly reachable UDP path from the target to the controller. QSH provides no relay, NAT traversal, or discovery — that is out of scope for P0.
  >
  > Put the controller on a publicly routable address, a forwarded port, or an existing overlay such as WireGuard or Tailscale. If the controller itself is behind NAT, M3 has no answer for that.
- macOS asks "Do you want the application “qsh” to accept incoming network
  connections?" the first time a given build dials out, though `-L` and
  `-D` listeners are both loopback-only, so neither triggers it. The
  cause is qsh's QUIC client socket,
  which binds the wildcard address (`0.0.0.0:0`/`[::]:0`,
  `crates/qsh-transport/src/endpoint.rs`) on every dial because connection
  migration across IP changes needs it; a release build is only ad-hoc
  linker-signed, so macOS has no stable identity to remember an answer
  against and asks again after every rebuild or reinstall. Developer ID
  signing and notarization (M10) fix this; until then, sign the binary
  yourself (`codesign -fs "<cert>" $(which qsh)`) or register it with
  `/usr/libexec/ApplicationFirewall/socketfilterfw --add $(which qsh)
  --unblockapp $(which qsh)` (the tool is not on `PATH`).

## Product boundary

QSH owns secure sessions, PTY lifecycle, reconnect, command execution and
port forwarding. Getting a routable address to the host is somebody else's
job, and stays that way: see the reverse-reachability entry under [Known
limitations](#known-limitations).

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace   # the gate (plain cargo test is not)
cargo test --workspace --doc
RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps
cargo xtask arch
cargo deny check
```

All seven have to be green before a commit. `docs/design/testing.md`
explains which tests each layer owes.

## License

MIT OR Apache-2.0 — see `LICENSE-MIT` and `LICENSE-APACHE`.
