# QSH

QSH is a remote shell that speaks QUIC and connects straight to the machine
you name. No relay, no broker, no account. One binary, `qsh`, is both ends: it
serves, and it connects.

## Why it exists

SSH ties a shell's lifetime to the TCP connection carrying it. Change IP
address, close the laptop lid, or move from Wi-Fi to tethering, and the
connection dies and takes the shell with it.

QSH keeps the two lifetimes apart. The shell runs under the host's `qsh
serve` process, and the client's connection is only a way to reach it. When
the connection drops or the client's address changes, the client reconnects
and resumes the same session, with the output it missed replayed, instead of
starting a new shell. A change of network that QUIC can migrate across does
not even interrupt the connection. Nothing sits in the middle: every
connection is a direct QUIC connection to a hostname or IP you supply,
authenticated by TLS 1.3 mutual authentication against certificates you have
pinned.

Beyond the shell, the same connection carries one-shot commands (`qsh exec`),
port forwards (`-L`, `-R`, and a SOCKS5 proxy with `-D`), reverse connections
for hosts behind NAT, and a JSON CLI contract (`qsh.cli/v1`) for scripts and
agents.

QSH needs UDP. There is no TCP fallback, by design, so a network that blocks
UDP cannot connect (see [Known limitations](#known-limitations)).

**Status.** Version 0.4.3, not for production use. The independent review of
the protocol and key lifecycle that [docs/PRD.md](docs/PRD.md) §15 requires
has not been contracted, and the wire-format freeze waits on that decision.
Several campaigns that a person runs by hand are also still open; see
[Project status](#project-status).

## Contents

- [Install](#install): prebuilt binaries, Homebrew, or from source.
- [First run](#first-run): pin two machines to each other and open a shell.
- [Guided setup](#guided-setup-qsh-setup): the same steps, driven by `qsh setup`.
- [Everyday use](#everyday-use): commands, detach and reattach, forwards, reverse connections.
- [Automation](#automation): the JSON CLI for scripts and agents.
- [Security posture](#security-posture): authentication, the ACL, the audit log.
- [Known limitations](#known-limitations), including that QSH needs UDP.
- [Project status](#project-status), [Documents](#documents), [Development](#development).

## Install

Prebuilt binaries for macOS (arm64, x86_64), Linux (x86_64 and aarch64
against glibc, x86_64 and aarch64 against musl) and Windows (x86_64) are
attached to each [GitHub release](https://github.com/DaveDev42/qsh/releases). The
one-line installer below covers macOS and Linux; on Windows take the
`.zip` (see [Manual download](#manual-download)).

One line installs the latest:

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

The script picks the archive for your platform, verifies it against the
release's `SHA256SUMS` before unpacking, and installs to `~/.local/bin`. It
never calls `sudo`; if the target directory is not writable it says so and
stops. The checksum is an integrity check against a bad download, not a
signature. When the GitHub CLI is installed and logged in, the script also
verifies the archive's build provenance (below).

On macOS, a binary from the curl installer is ad-hoc signed unless the
release was cut with Apple credentials, and no published release has been.
[Known limitations](#known-limitations) explains how to check what you have
and what it means for the firewall prompt. The installer clears
`com.apple.quarantine` after it installs (`scripts/install.sh`), so that path
does not consult Gatekeeper; a manual download does.

| Variable | Default | Meaning |
|---|---|---|
| `QSH_VERSION` | latest release | Release tag to install, e.g. `v0.1.0-alpha.1` |
| `QSH_INSTALL_DIR` | `$HOME/.local/bin` | Where the `qsh` binary lands (created if missing) |
| `QSH_REPO` | `DaveDev42/qsh` | `owner/repo` to install from, for forks and testing |
| `QSH_LIBC` | `gnu` | Linux only. `musl` picks the static build (x86_64 or aarch64) for old-glibc distributions |
| `QSH_MAN_DIR` | `~/.local/share/man/man1` | Where the man pages from the archive are installed |
| `QSH_NO_MAN` | unset | Set to `1` to skip the man pages |
| `QSH_INSECURE_SKIP_VERIFY` | unset | Set to exactly `1` to skip both the `SHA256SUMS` check and the provenance check. Prints a warning |

Every release asset cut after `v0.2.0` carries a build provenance
attestation, `SHA256SUMS` included. With the GitHub CLI you can check one
before you unpack it:

```bash
gh attestation verify qsh-<tag>-<target>.tar.gz --repo DaveDev42/qsh
```

The attestation establishes that this exact file was produced by a workflow
in this repository, on a GitHub-hosted runner, from a named commit
(`scripts/README.md` shows how to pin it to `release.yml`). It says nothing
about whether the code in that commit is correct or safe to run.

The installer runs that check itself, after the `SHA256SUMS` check and
before it unpacks anything:

- `gh` installed and logged in: the archive must verify. A failed
  verification installs nothing.
- `gh` missing or not logged in: the installer prints `provenance not
  verified` on stderr and installs on the `SHA256SUMS` check alone.
- `QSH_INSECURE_SKIP_VERIFY=1`: both checks are skipped, with a warning.
  This is the only way past either check.

Releases up to `v0.2.0` have no attestation, so with `gh` logged in the
installer refuses them; use the flag for those, or log `gh` out.

What each release ships, what is signed and what is not, and how to check
any of it is in [RELEASE-NOTES.md](RELEASE-NOTES.md).

### Manual download

To download by hand, take the asset matching your platform, check it against
`SHA256SUMS`, and put `qsh` somewhere on your `PATH`:

| Platform | Asset |
|---|---|
| macOS, Apple silicon | `qsh-<tag>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `qsh-<tag>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `qsh-<tag>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `qsh-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64, static (musl) | `qsh-<tag>-x86_64-unknown-linux-musl.tar.gz` |
| Linux aarch64, static (musl) | `qsh-<tag>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `qsh-<tag>-x86_64-pc-windows-msvc.zip` |

The installer has no Windows path; take the `.zip` from the releases page.
See the Windows caveat under [Known limitations](#known-limitations).

### Homebrew (macOS)

```bash
brew install DaveDev42/tap/qsh
```

Apple silicon only for now. The formula tracks the `aarch64-apple-darwin`
release tarball, so the signing status is whatever that asset carries. The
Homebrew version is the release tag without its leading `v`. For tags after
`v0.2.0` this is the install path that puts the man pages on your `MANPATH`.

### From source

Building from source needs a Rust toolchain. `rust-toolchain.toml` pins
1.99.0, which is what CI and the release builds use. Either build in a
clone and place the binary yourself:

```bash
cargo build --release -p qsh-cli    # binary at target/release/qsh
```

or let `cargo install` build and place it in one step, straight from this
repository:

```bash
cargo install --locked --git https://github.com/DaveDev42/qsh qsh-cli
```

There is no `cargo install qsh-cli` from crates.io yet. The four contract
crates are cleared to publish and CI dry-runs the publish on every push to
`main` and every pull request, but nothing has been pushed to the registry,
so `--git` (or `--path` against a local clone) is the only `cargo install`
route. The package name `qsh-cli` is reserved for that release. The shorter
name `qsh` belongs to an unrelated project, which is why the crate is
`qsh-cli` even though the binary it installs is `qsh`.

`scripts/README.md` covers the installer in more detail. To keep a listener
running, see [docs/deploy/service.md](docs/deploy/service.md).

Man pages for every subcommand are generated from the same `clap`
definitions `--help` uses and live under [`docs/man/`](docs/man/)
(`cargo xtask man` regenerates them; `docs/design/testing.md` covers the
test that keeps them from drifting). A Homebrew install (tags after
`v0.2.0`) puts them on your `MANPATH`. The curl installer copies them from
the archive's `man/` directory to `~/.local/share/man/man1` and prints an
`export MANPATH=...` line when that directory is not on the search path; a
failure there is a warning and never undoes the binary install. From a
manual `.tar.gz` download (the Windows `.zip` has no pages) point `man` at a
page directly: `man ./man/qsh-trust-add.1` from an unpacked archive, or
`man ./docs/man/qsh.1` from a clone.

## First run

Six commands and one small policy file, two machines. This is the literal
script that `docs/campaigns/m9-stopwatch.md` and `docs/campaigns/m7-stopwatch.md`
time: two machines that have never run `qsh` before, nothing but this section
open, stopwatch running from the first command.

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
the fingerprint it observed, and asks you to confirm. This is the
trust-on-first-connect flow SSH uses for host keys.

A second way to pin is a one-time pairing code. One side prints it, the
other redeems it, and both ends are pinned in the same exchange.

```bash
# Host:
qsh pair invite --json
# {"data":{"code":"abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab", "expires_at":"…",
#          "accept_command":"qsh pair accept <address> abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab"}}

# Client, filling in the host's real address:
qsh pair accept host.example.com:4433 abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab
```

The code carries no address, just a secret, so any channel will do: read it
over the phone, paste it in a chat. Possession of the secret is the proof,
checked over a TLS-exporter-bound exchange (`docs/design/protocol.md` §15),
so neither side needs the other's fingerprint ahead of time. The channel
can still be mistyped or overheard; to be sure of more than "whoever knew
the code", compare `trust list`'s fingerprint out of band after pairing, as
after any first connection. A code works once and expires in ten minutes,
and a running `qsh serve` recognizes a freshly minted invite without a
restart, the same way it picks up `trust remove` (`docs/CLI.md` §6.11).

A third way is to exchange certificate files directly (ADR-0013). Only an
inbound `qsh serve` opens the invite-redemption window, so nothing can pair
*to* a `qsh listen` or `qsh serve --to` peer by code; a certificate file is
how that peer gets pinned.

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

From here, `qsh hosts` lists what this machine can reach and `qsh sessions
box` lists what is alive on the host. [Everyday use](#everyday-use) covers
detach/reattach, port forwards and reverse connections. To skip retyping
`user@` or to move an address without touching the trust store, add the
name to `hosts.toml` by hand, next to `trust.toml`:

```toml
# <config_dir>/hosts.toml: read by qsh, never written by it
[[host]]
name = "box"
address = "host.example.com:4433"
user = "dave"
```

`hosts.toml`'s address wins over `trust.toml`'s when a name is in both, and
its `user` fills in when `user@` is left off. Identity is still
`trust.toml`'s job alone; `hosts.toml` never supplies one. Write access to
`hosts.toml` is therefore the power to redirect a name to a different
already-pinned peer (mTLS still blocks an unpinned address). `qsh hosts
--json` reveals such a redirect through `"source": "hosts"` (`docs/CLI.md`
§5).

## Guided setup (`qsh setup`)

`qsh setup` walks one machine through the commands that "First run" types
by hand. It calls the existing operations in a fixed order (`qsh init`, the
pairing or `trust add` step, `qsh doctor`) and adds no new capability, so
the manual path above keeps working. One line per role:

```bash
qsh setup host --peer laptop                  # host: init, issue an invite named "laptop"
qsh setup host --to box --address host.example.com:4433 --peer-cert box.pem
                                              # host behind NAT, for `qsh serve --to box`
qsh setup client box --address host.example.com:4433 <code>
                                              # client: redeem the host's invite code
qsh setup listener --peer controller --peer-cert controller.pem
                                              # controller side, for `qsh listen`
```

`--peer-cert <path|->` takes the certificate file the other side made with
`qsh identity export`; the client role accepts either that or an invite
code. Add `--service` to write a service unit file, and `--forward` on a
host role to include `forward.local` in the printed rule. Without a
terminal, or with `--json`, setup asks nothing and fails with
`INVALID_ARGUMENT` if an input is missing. The exact flags are in
[docs/CLI.md](docs/CLI.md) §6.20.

Setup never writes `acl.toml`. It prints the `[[acl]]` rows this role needs,
checks with `qsh acl check` whether the file already allows them, and stops
with the step marked `pending` until you have saved the rows yourself and
run `qsh setup` again. The same holds for `config.toml` and `hosts.toml`.
Setup also does not start `qsh serve` or `qsh listen` and does not enable
the service unit.

There is no automatic trust. A peer is pinned only from an invite code or a
certificate file you hand over, never from a fingerprint setup observed on
the wire. Because `acl.toml` is read once at process start, setup ends the
ACL step with this notice:

```
restart serve/listen — acl.toml is only read once at process start.
```

## Everyday use

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

`-D` ([ADR-0019](docs/adr/0019-socks-dynamic-forward.md)) opens a
loopback-only SOCKS5 proxy on this machine. For every `CONNECT` a SOCKS
client sends to it, the host dials whatever destination that `CONNECT`
names. The flag is repeatable alongside a session; `tunnel open` takes one
`--dynamic` listener per call, exclusive with `--local`/`--remote`:

```bash
qsh box -D 1080                             # SOCKS5 on 127.0.0.1:1080, alongside the shell
qsh tunnel open box --dynamic 1080 --json   # the same listener with no shell attached
curl --socks5-hostname 127.0.0.1:1080 http://internal-service/
```

It is not a new grant:

> `-D` runs SOCKS5 on this machine and authorizes every CONNECT on the peer as `forward.local`; `forward.socks` is never consulted.

Two things have to be true before the first `CONNECT` succeeds:

- The host's `acl.toml` grants the client `forward.local` (or the
  `forward.*` family). The First run example only grants `session.*`, so add
  the action there. `-R` needs `forward.remote` the same way.
- Both ends run a build that negotiates `dial-filter.v1`, which lets the host
  refuse loopback, link-local and metadata destinations. An older peer is
  refused before anything binds. Over a reverse route
  ([ADR-0020](docs/adr/0020-socks-reverse-route.md)) the resident `qsh listen`
  daemon relays the capability set it negotiated with the target at
  registration; a daemon still running from before this machine's upgrade
  keeps relaying the old set, so restart it.

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

A peer address with no port defaults to 4433: `controller` and `controller:4433` resolve the same way, and an IPv6 literal needs brackets once a port follows it, as in `[::1]:4433`.

`qsh serve --to` keeps reconnecting with backoff, so the target comes back
on its own after the link drops. `--name` only takes effect when the
controller has no trust-store alias for that peer and its
`[listen].allow_advertised_names` is set; otherwise the controller names the
peer from its own trust store. The older `qsh reverse controller
--offered-name workshop` spelling still works as a hidden alias.

<!-- Behavior below is pinned by: lookup_pin_returns_the_first_name_pinned_for_a_shared_fingerprint,
     lookup_pin_follows_a_reordered_trust_toml_without_a_restart (qsh-core trust tests),
     an_acl_row_on_the_second_alias_denies_inbound_until_trust_toml_is_reordered (qsh-cli/tests/trust_alias_order.rs),
     acl_principal_unmatched_flags_the_first_alias_when_only_the_second_has_a_row (qsh-core doctor tests).
     A proper fix (per-direction pins) is docs/ROADMAP.md M16 (a). -->
#### One machine, two aliases

One machine can be reachable two ways: directly at an address for `qsh serve`,
and through `qsh serve --to` from behind NAT. You may want a trust-store
name for each, both pinning the same fingerprint (for example `workshop-lan`
with an address, and `workshop` for the reverse registration). qsh accepts
that, but the two names are not equal. When a peer authenticates, qsh looks
its fingerprint up in `trust.toml` and takes the first entry in file order.
That name is the principal every inbound `[[acl]]` row is matched against;
the second name never becomes one.

So write `[[acl]]` rows for the name that comes first in `trust.toml`, and
treat the second name as an outbound dial alias only. A row written for the
second name is not matched on inbound requests, which are then denied by
default. `qsh doctor` counts each name separately, so in that layout it
flags the first name (`acl_principal_unmatched`) and stays quiet about the
second. `trust.toml` is re-read on every handshake, so reordering the two
entries changes the principal immediately, without a restart; `acl.toml`
still needs the restart. Splitting the aliases by direction is planned work
(`docs/ROADMAP.md` M16), not something to rely on today.

#### Riding out a long outage

A controller keeps a registration whose connection died as `stale` for
`[listen].stale_retention` before it drops it from `qsh hosts` (default 120
seconds). If your targets can be offline longer than that and you want the
controller to keep the name across the gap, raise it in `config.toml`. It
must stay above `[reverse].backoff_max_ms` times 3 (default 30000 ms, so
above 90 s), or the controller refuses to start with a config error. The
limit on how many addresses a single reconnect attempt tries is in
`docs/CLI.md` §6.13.

## Automation

Every command takes `--json` for one result envelope, or `--jsonl` for a
stream of events from commands that run long. In either mode stdout carries
only JSON, diagnostics go to stderr, and nothing prompts: a missing input
fails with `INVALID_ARGUMENT`, and an unpinned peer fails with
`TRUST_REQUIRED`.

```bash
qsh hosts --json
qsh exec box --json -- uname -a
```

A success is `{"schema":"qsh.cli/v1","request_id":…,"command":"exec.run","ok":true,"data":{…}}`.
A failure has `"ok":false` and an `error` object with `code`, `message`,
`retryable` and `details`. Scripts should branch on `code` and `retryable`,
never on `message`. Byte payloads are Base64, times are UTC RFC 3339, and
durations are integer milliseconds.

Exit codes are `0` for success, `2` for a usage error and `255` for a QSH
runtime failure. `qsh exec` returns the remote command's own code instead
(`0` to `254`; a remote `255` is clamped to `254`), and the JSON
`remote_exit_code` always holds the true value. `qsh doctor --fail-on`
returns `1` when it finds something at or above the threshold.

The contract is additive-only. New optional fields can appear within
`qsh.cli/v1` and `qsh.event/v1`, so a client must ignore fields it does not
know; a removal or a type change would need a `/v2`. `qsh schema --json`
serves the contract of the build you are running, and `qsh capabilities`
reports what the build supports or, given a pinned host, what was
negotiated with that peer. `qsh doctor --json` reports the state of a
deployment (identity, ACL policy, audit log, trust store, clock, network
reachability) in a form a monitor can read.

The built-in `qsh mcp` server was retired ([ADR-0011](docs/adr/0011-remove-mcp-adapter.md)).
To give an agent a remote stdio MCP server, run it through
`qsh exec host -- <server>`. The full contract is in
[docs/CLI.md](docs/CLI.md) §2 to §4 and §6.

## Security posture

Every connection is QUIC with TLS 1.3 mutual authentication. Both ends
present a certificate and both ends check the other's fingerprint against
the trust store. Anything that fails to authenticate is rejected during the
handshake, before a session, tunnel, or listener exists. The one narrow,
time-boxed exception is `qsh pair invite`/`qsh pair accept`: while a
freshly minted invite is live, an otherwise-unpinned certificate is admitted
into a dedicated pairing exchange that can do nothing but verify possession
of the invite's secret and, on success, pin. It never reaches a session,
tunnel, or listener path (`docs/design/protocol.md` §15). The pinning side names the peer explicitly with `--as <name>` on `pair invite`/`pair accept`; without it, the peer's own self-reported name is used.

Authorization is `acl.toml`: a small, principal-scoped rule file at
`<config_dir>/acl.toml`. It is default-deny. A host with no `acl.toml`, or
one that fails to parse, denies every operation from every peer, and qsh
never creates or edits the file for you; an operator writes it by hand. Each
rule names a principal (`user:<name>`, `device:<name>`, or
`fp:sha256:<fingerprint>`), the auth path it applies to (`pin`, the default
when omitted, or `ca`), and the actions it grants: an exact name like
`exec.run`, or a trailing-wildcard family like `session.*`. A peer that
authenticates through a trusted CA (`[[ca]]` in `trust.toml`) gets exactly
what a rule with an explicit `auth_path = "ca"` grants it; a rule that omits
`auth_path` never matches a CA-authenticated peer, even when the principal
string is identical.

`file.read` and `file.write` are in the action vocabulary but always denied,
because those operations are not implemented. `forward.socks` is also always
denied, for a different reason: no operation is ever authorized through it
([ADR-0019](docs/adr/0019-socks-dynamic-forward.md)); `-D` reuses
`forward.local`. Every refusal a remote peer sees is the same opaque
`PERMISSION_DENIED` message, whether it came from a missing rule, a policy
file that failed to load, or an audit-write failure.

The policy loads once, when `qsh serve`/`qsh listen`/`qsh serve --to`
starts, so an edit to `acl.toml` only takes effect on the next restart. If
the file is missing or invalid at startup, the process still comes up (it
answers, and denies everything) and prints a diagnostic to stderr exactly
once, made of:

- `no usable acl.toml policy`
- `every request is denied until this is fixed`
- the exact path it looked at and the `CONFIG_ERROR` code
- a copy-pasteable minimal policy filled in with this machine's pinned peers
- `acl.toml is never auto-generated — create it by hand`
- `verify a fix before restarting: qsh acl check`

The diagnostic's `code` field tells the two causes apart: `acl_policy_missing`
(no file) versus `acl_policy_invalid` (parse or validation failure). It
never dumps raw source lines; the only echo is a bounded (at most 128 bytes,
single-line-escaped) grammar token from the offending rule (unknown action
pattern, `auth_path` or scope).

On unix, a group- or world-writable `acl.toml` gets a one-time stderr
warning instead of a refusal to load: an operator locked out of their own
host by a permissions slip has no way back in. Windows ACL checking is out
of scope. Pin only devices you would hand a shell to, and write down what
you want each of them to be able to do.

## Known limitations

Some of these are MVP scope decisions, some are unfinished work.

- No TCP fallback. QSH runs only over QUIC, which is UDP, so a network that
  blocks or drops UDP (some corporate and hotel networks) cannot connect.
  `qsh doctor` reports a blocked UDP egress. This is a scope decision, not
  pending work ([ADR-0043](docs/adr/0043-no-tcp-fallback.md)): on such a
  network use SSH, or run QSH inside an overlay such as WireGuard or
  Tailscale that can carry UDP.
- Sessions die with the listener process. A session lives only as long as
  the `qsh serve` or `qsh serve --to` process that opened it, so a restart
  ends every detached session on it; it is not a resume point. A client that
  was attached learns this within one round trip, not after the 45 s idle
  timeout, because the server keeps a stateless reset key in
  `stateless_reset.key` in the config directory (ADR-0036). `qsh serve` and
  `qsh serve --to` say so in one stderr line at startup (not under
  `--quiet`), and `qsh doctor` reports `service_restart_drops_sessions`
  (info) when a service unit is registered. A clean SIGTERM drains: no new
  `session.open`, `session.attach` or `exec.run` is admitted from the signal
  onward, and every live session runs its normal close procedure, with a
  `drained` lifecycle line carrying the session counts. The drain is best
  effort. Delivery of `session.closed` to an attached consumer is bounded by
  a short flush window, and the whole drain gives up after a finite timeout
  with a warning, so under a congested consumer or a stuck child a shell can
  still outlive the process. A separate session supervisor is planned after
  MVP ([ADR-0003](docs/adr/0003-sessions-in-listener.md)).
- A tunnel does not resume the way a session does. `-L`, `-R` and `-D` work
  over both forward and reverse connections (ADR-0020 decisions 1–3); a `-D`
  listener over a reverse route relays every `CONNECT` through this
  machine's resident `qsh listen` daemon to the target's live registration,
  with the same host-local address filter as a forward route. Either route
  is refused before anything binds if the peer never negotiated
  `dial-filter.v1`. `qsh tunnels`/`qsh tunnel close` manage what a resident
  daemon holds. There is no UDP forwarding (`UDP ASSOCIATE` gets `REP 0x07`,
  as BIND does), and remote forwards bind loopback only, ACL
  notwithstanding. A tunnel has no replay ring: when a connection drops and
  later resumes, any in-flight tunnel TCP connection ends cleanly instead of
  being replayed. An `-L` listener survives if the process holding it is
  alive, but a new connection into it after the reconnect gets a clean reset
  until you restart the forward. Without `--supervise`, an `-R`
  registration has to be reopened by hand. QUIC path migration is a
  different case: switching networks without losing the connection (Wi-Fi to
  tethering, a changed IP) carries an open tunnel through, as it does a
  session.
- `--supervise <ms>` keeps a `-L`, `-D` or `-R` tunnel alive across a lost
  connection, over a forward or a reverse route, within limits. A supervised
  `-R` tunnel closes the old registration and opens the same bind again on
  the new connection; if the port cannot be kept (someone else took it, or
  the peer's policy no longer allows it), the tunnel ends instead of moving
  to another port. Each reissue gets a new `tunnel_id`: the envelope printed
  at open keeps the first, and the current one is in the `reestablished`
  diagnostic line and in `qsh tunnels` on a reverse route. A supervised
  forward tunnel re-dials the address it resolved at open and never looks
  the host up again, so a peer that moved is not followed. A supervised
  reverse tunnel asks the local daemon again and never looks at a forward
  pin of the same name; a reverse-only host must therefore have no address in
  its pin if the first open is to take the reverse route. The first open is
  not supervised: if it fails, the command fails as it does without the flag
  (`--wait` or a service-manager restart covers a host that is not up yet).
  A TCP connection that was spliced when the connection died lives on only
  if the old connection comes back, which only a forward route can do;
  otherwise it ends, and only new connections ride the re-established one.
  Sleep detection compares the wall clock with the monotonic clock. Whether
  the monotonic clock stops during sleep on Windows is unverified, so a lost
  connection there may be found only by the ordinary dead-path detection.
- `qsh serve` and `qsh listen` share one default port. Both bind `[::]:4433`
  unless told otherwise, so a machine taking both roles needs an explicit
  `--bind` (or `[serve].bind`/`[listen].bind`) for at least one of them. The
  second one to start fails immediately with `CONFIG_ERROR` and exit `255`,
  with this remedy on stderr, exactly:

  > Nothing is being served. `qsh serve` and `qsh listen` both default to port 4433, so one machine running both needs an explicit bind for at least one of them. Re-run with `--bind <ip:port>` on a free port.
- `acl.toml` has no hot reload: an edit takes effect the next time
  `qsh serve`/`qsh listen`/`qsh serve --to` starts. See [Security
  posture](#security-posture).
- The audit log is fail-closed. `qsh serve`/`qsh serve --to` deny an
  otherwise-allowed `session.open`, `session.attach`, session write,
  `exec.run` or `host.reverse` registration rather than let it through with
  no durable audit record. A full disk, a permissions problem on the audit
  directory, or a writer backlogged past its bounded queue all deny the way
  a policy refusal does, with no override and no degraded-but-serving mode.
  Recovery is automatic: once the audit log is writable again, the writer's
  background retry clears the condition without a restart. Audit records are
  structural; argv, PTY bytes and key material never appear in them.
  `audit.log_argv` is named in the design docs as a sanctioned future
  exception, and M5 does not implement it.
- Quotas are fixed defaults. Concurrent sessions, `exec.run` runs and
  connections are capped per listener and per principal, tunnel streams per
  principal and per forward, remote forwards per principal, and the
  admission gate caps concurrent handshakes and the per-source rate
  (`[serve].max_sessions` and friends, `docs/CLI.md` §6.12). A key set to
  `0` or left unset means the default, not unlimited, and no switch turns a
  cap off. The ACL engine itself never enforces quotas.
- `qsh trust remove` only affects future handshakes. A removed peer keeps
  the connection's entire negotiated authority, including the ability to
  open new sessions, tunnels and forwards within the ACL scope loaded at
  startup, until that connection drops. The host re-reads `trust.toml` on
  every handshake, so the next connection attempt from the removed peer is
  rejected immediately, with no restart (`docs/CLI.md` §6.11). A tunnel with
  `--supervise` on such a connection keeps running too; only its next
  re-establishment meets the rejected handshake, after which it retries
  within its budget and gives up. Force-closing an established connection on
  removal is P1.
- `qsh trust rename` also takes effect on the next handshake without a
  restart, but `acl.toml` rows do not: they match the pre-rename name until
  `qsh serve` is restarted (ADR-0012 decision 7). A renamed peer's next
  connection authenticates but can be denied every operation until the ACL
  rows catch up.
- `qsh service status` and `qsh service uninstall` only look at the run mode
  inferred from today's `config.toml` (`docs/CLI.md` §6.18). A unit
  installed under a previous mode (say `listen`, with `config.toml` now
  saying `serve --to`) is invisible to both. The unit's recorded binary path
  differs per platform: macOS keeps a Homebrew Cellar symlink unresolved on
  purpose, so `brew upgrade` does not pin a stale path, while Linux's
  `/proc/self/exe` has already resolved any symlink.
- `qsh pair accept` pins both sides in one exchange, but the two pins are
  not atomic. The host's pin and the invite's consumption happen first, in
  the wire exchange; the client's local pin happens after. If the client then
  hits a name collision in its own trust store, the invite is already spent:
  resolve the collision and get a fresh invite. A collision on the host's
  side, during the exchange, rolls back cleanly and leaves the invite
  redeemable (`docs/design/protocol.md` §15.6).
- Retrying `qsh pair accept` against a peer the host already pinned fails as
  a non-retryable `SESSION_CONFLICT`, and a fresh invite does not fix it: the
  host's pin makes the ordinary mTLS path win before the connection reaches
  pairing logic. Run `qsh trust remove` on the host, then a new `pair
  invite`/`pair accept` round (`docs/design/protocol.md` §15.6, `docs/CLI.md`
  §6.11).
- `qsh pair invite` does not know this device's reachable address. Human
  mode suggests candidates by asking the kernel which source address a
  packet leaving this host would carry. That is a routing observation, not a
  reachability check: behind NAT or a firewall none of them may work, and a
  host with no default route gets no candidates at all. The operator picks
  the address and relays it out of band (`docs/CLI.md` §6.11).
- A listener is not a code-pairing peer: only an inbound `qsh serve` redeems
  invite codes, so `qsh pair invite`/`qsh pair accept` cannot pin a `qsh
  listen` or `qsh serve --to` peer. Pin it by certificate file (`qsh
  identity export`, `qsh trust add --cert-file`; `docs/CLI.md` §6.11,
  §6.13).
- `exec.run` output is capped at 64 MiB. Stdout plus stderr come back in one
  envelope, and anything beyond the cap is `RESOURCE_EXHAUSTED`. Use `qsh
  session read` or an interactive session for streaming output.
- Host names resolve through `hosts.toml` first, then the trust store. `qsh
  hosts` and `qsh host` read both. `hosts.toml` is read-only from the CLI's
  side and is a pure address book: identity comes from the trust store
  alone, and an entry for a name with no matching pin dials an address
  nobody has vouched for.
- qsh resolves hostnames with the system resolver. To avoid DNS altogether
  (for example behind an enterprise VPN that intercepts DNS), pin the peer by
  IP literal or turn on the OS's encrypted DNS settings. A built-in forced
  DNS-over-HTTPS resolver is a P2 candidate (ADR-0039).
- Windows is P1 for the client and P2 for the host. PTY code is gated
  `#[cfg(unix)]`, and so is reverse mode: `qsh listen` and `qsh serve --to`
  return `UNSUPPORTED` there, and a tunnel over a reverse connection
  inherits that. `qsh tunnel open --dynamic` is cross-platform like
  `--local`/`--remote`; the interactive `-D` spelling is not, since the
  interactive PTY driver it rides is `#[cfg(unix)]`. CI builds, lints and
  runs the portable test subset on `windows-latest`, but POSIX-only behavior
  such as signal exits and process-group kill is never exercised there.
- Reverse mode needs a directly reachable path from the target to the
  controller:

  > Reverse attach needs a directly reachable UDP path from the target to the controller. QSH provides no relay, NAT traversal, or discovery — that is out of scope for P0.
  >
  > Put the controller on a publicly routable address, a forwarded port, or an existing overlay such as WireGuard or Tailscale. If the controller itself is behind NAT, M3 has no answer for that.
- macOS asks "Do you want the application “qsh” to accept incoming network
  connections?" the first time a given build dials out (`-L` and `-D`
  listeners are loopback-only and do not trigger it). The cause is qsh's QUIC
  client socket, which binds the wildcard address (`0.0.0.0:0`/`[::]:0`,
  `crates/qsh-transport/src/endpoint.rs`) on every dial because connection
  migration across IP changes needs it. A binary with no stable code
  identity gives macOS nothing to remember an answer against, so it asks
  again after every rebuild or reinstall. The release workflow signs both
  macOS binaries with a Developer ID certificate (hardened runtime, trusted
  timestamp) and submits them to Apple's notary service, but only when the
  release is cut on a repository with all six Apple credentials configured.
  Otherwise the binaries ship ad-hoc signed, as a local `cargo build
  --release` produces them. No published release has been cut with those
  credentials, so assume ad-hoc until you have checked. `codesign -dv
  --verbose=4 $(which qsh)` tells them apart: a Developer ID build names an
  `Authority=Developer ID Application` and a `TeamIdentifier`, an ad-hoc one
  prints `Signature=adhoc` and `TeamIdentifier=not set`. Notarization is
  confirmed online rather than stapled, so even a signed build's first run on
  a machine with no route to Apple is not guaranteed; `spctl -a -vvv -t
  execute $(which qsh)` reports Gatekeeper's verdict. For an ad-hoc build,
  sign it yourself (`codesign -fs "<cert>" $(which qsh)`) or register it with
  `/usr/libexec/ApplicationFirewall/socketfilterfw --add $(which qsh)
  --unblockapp $(which qsh)` (the tool is not on `PATH`).
- `qsh init --import-ssh-key <path>` makes an existing OpenSSH Ed25519 key
  the device key, so SSH and qsh share one key and its lifetime: if either
  side leaks it, both are exposed. qsh has no key rotation or revocation
  yet; the only recovery is removing `identity/` from the config directory,
  running `qsh init` again and re-pinning on every peer
  ([ADR-0026](docs/adr/0026-ssh-key-import-scope.md)). Only unencrypted
  Ed25519 keys are read; passphrase-protected keys, RSA and ECDSA are
  refused. The command prints two different fingerprints for the same key
  (qsh's SPKI hash and the `ssh-keygen -lf` hash); only the qsh one goes
  into `trust.toml` or `acl.toml`.

## Project status

Milestone by milestone, with scope and acceptance criteria in
[docs/ROADMAP.md](docs/ROADMAP.md) and what each tag ships in
[RELEASE-NOTES.md](RELEASE-NOTES.md). Four campaigns that a person runs by
hand are still open: the clean-VM install campaign, the connect-time
stopwatch rounds, the real-device mobility round, and the aarch64 musl
old-glibc check.

| # | Milestone | Status |
|---|---|---|
| M0 | Decisions, workspace scaffold, CI | Done |
| M1 | Walking skeleton (`init`/`serve`/`exec --json`, mTLS, JSON envelope) | Done |
| M2 | Session broker, PTY, migration and resume | Done |
| M3 | Reverse connections (`listen`/`serve --to`/`attach`) | Done |
| M4 | Port forwarding (`-L`/`-R`) | Done |
| M5 | ACL and audit | Done |
| M6 | MCP adapter | Done, then retired (ADR-0011) |
| M7 | Trust UX, host profiles, `doctor` | Features done; stopwatch campaign open |
| M8 | Hardening (fuzz, soak, mobility) | Code done; mobility campaign, wire freeze and security review open |
| M9 | Human-facing surface (naming, pairing, service install) | Features done; stopwatch re-measurement open |
| M10 | Release (installers, Homebrew, notarization, musl, provenance) | Pipeline done; clean-VM campaign open |
| M11 | Issue follow-ups and ACL visibility | Features done; field observation open |
| M12 | Supervised tunnels and `qsh setup` | Done in `v0.4.0`; campaign rounds open |
| M13 | Measurement and release groundwork | Done (2026-10-08); aarch64 musl old-glibc check open |
| M14 | TCP/TLS fallback | Withdrawn (ADR-0043); the transport abstraction stays |
| M15–M19 | Rest of P1 | Design records drafted, awaiting approval; README rewrite (M17 b) done |

The Homebrew tap (`DaveDev42/tap`) and the release workflow's auto-bump job
have run on every tag since `v0.2.0`. The first crates.io push waits on the
clean-VM campaign.

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
  and the interactive TUI.
- `qsh-testkit`: shared test harness with a loopback transport, a chaos
  proxy, and fixtures.

`qsh-cli` depends on `qsh-proto` for contract types and never on
`qsh-transport`. The full allowed-dependency matrix is enforced by
`cargo run -p xtask -- arch`, and a violation fails CI.

The binary is `qsh`; the Cargo package is `qsh-cli`
([ADR-0006](docs/adr/0006-product-name-and-crate-name.md)).

## Product boundary

QSH owns secure sessions, PTY lifecycle, reconnect, command execution and
port forwarding. Getting a routable address to the host is somebody else's
job; see the reverse-reachability entry under [Known
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

MIT OR Apache-2.0, see `LICENSE-MIT` and `LICENSE-APACHE`.
