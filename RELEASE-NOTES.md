# Release notes

One section per release tag, newest first. Each section says what the tag
ships, which parts of it are signed, how to check any of that yourself,
and what is still unproven. A section whose heading reads `<tag>` is a
placeholder for the next tag; the commit that bumps the version replaces
it with that tag's name.

The GitHub Release page for a tag carries the commit list; this file
carries the parts that do not change commit to commit.

## `v0.4.1`

A patch release with one fix. There is no wire or contract change, and
`v0.4.0` peers interoperate with it.

### Fix

- `PathWatch` now also counts received UDP datagrams (quinn's
  `udp_rx.datagrams`) as proof the path is alive. Before, a `Pong` stuck
  in QUIC's ordered loss recovery on a lossy link could leave the watch
  with no sign of life, and it reported a false `path_dead` while packets
  were still arriving (DaveDev42/qsh#10, PR #12, commit 54ce47d).

What this means in use:

- The fix applies per end. On a reverse link (`qsh listen` with
  `qsh serve --to`), upgrade both ends.
- A real blackout is detected on the same schedule as before.
- A reverse controller may now report `replaced` instead of `lost` when
  the target dials back first, because the two ends no longer give up on
  the old path at the same tick.

### Assets and signing

The same as `v0.4.0`: the same seven assets plus `SHA256SUMS`, the same
install paths, the same provenance check, and the same Developer ID
signing and notarization of both macOS binaries. See "What is in the
archives" and "What is signed and what is not" under `v0.4.0` below,
with `v0.4.1` in place of `v0.4.0` in the asset names.

## `v0.4.0`

The first release with Developer ID signed, notarized macOS binaries, and
the first to carry the P1 work: milestones M11 and M12 in full and most of
M13. `docs/CLI.md` moves from v0.13 to v0.21; its status header lists
each delta. Every contract change is additive. Existing golden fixtures
are unchanged and the wire format is unchanged. A `v0.3.0` peer and a
`v0.4.0` peer still talk to each other, but run the same build at both
ends where you can: the controller's `qsh listen` relays streams for
local clients, and the relay fixes below only take effect once it runs
this build.

### New commands and options

- `qsh setup` runs the steps of one of four roles in a fixed order
  (`docs/CLI.md` §6.20, ADR-0024). It calls the existing operations only
  and never writes `acl.toml`. For the `client` role, a missing
  `acl.toml` no longer stops it from reporting `complete` (ADR-0038).
- `qsh tunnel open --supervise <ms>` keeps `-L`, `-D` and `-R` forwards
  alive across reconnects: the local listener stays bound, the peer's
  fingerprint is checked again, and a supervised `-R` is reissued on the
  new connection. `--accept-hold <ms>` (at most 2000, needs
  `--supervise`, `-L` and `-D` only) holds a connection accepted during
  a disconnect for up to that long when a reconnect is under way or due
  within that time, then sends it over the new connection in accept
  order; otherwise the connection is refused at once, as before (§6.9,
  §6.14, ADR-0023).
- `qsh acl show --principal <principal>` summarizes, read-only, what
  this machine's `acl.toml` allows that one principal (§6.19,
  ADR-0025).
- `qsh init --import-ssh-key <path>` uses an unencrypted Ed25519 OpenSSH
  key as the device key, and `qsh trust ssh-preview <path>` prints the
  pin commands and a draft ACL for each line of an `authorized_keys`
  file (§6.11, ADR-0026).
- `qsh doctor --fail-on <warn|error>` exits `1` when a finding at or
  above that level is present. Without the option, exit code and stdout
  are byte-for-byte what they were (§6.17, ADR-0027).
- `qsh doctor` gains two findings. `acl_forward_socks_ineffective`
  (warn) flags a `forward.socks` grant with no `forward.local` for the
  same principal: `forward.socks` authorizes nothing by itself, and `-D`
  is authorized per CONNECT as `forward.local`.
  `service_restart_drops_sessions` (info) appears when a service unit
  for `qsh serve` or `qsh serve --to` is registered, as a reminder that
  a service-manager restart ends the sessions it holds.

### Behavior changes

- `serve`, `listen`, `serve --to` and `tunnel open` write a timestamped
  `qsh::lifecycle` JSON line to stderr when they start serving and when
  they stop or end (`--quiet` turns these off). On SIGTERM, `serve` and
  `serve --to` also write a `drained` line saying how many sessions the
  drain closed and whether the 60-second drain timed out (§6.12, §6.13,
  §6.14).
- The client notices a wake from sleep, probes the path at once, and
  declares it lost within about two seconds. After a wake the
  `serve --to` target resets its backoff (§6.13).
- A QUIC idle timeout is reported as `cause=idle_timeout` on
  `qsh::reverse` lines instead of `path_dead`.
- A tunnel stream whose local side has not accepted a byte for over a
  second counts as stalled. When more than three streams on one
  connection are stalled, or the peer reports it is blocked on
  connection credit while any stream is stalled, the oldest stalled
  stream is reset. Before, four unread tunnel streams could use up the
  whole connection receive window and freeze the session's terminal
  output (ADR-0037).
- Inbound `qsh serve` and `qsh listen` keep their stateless reset key
  in `config_dir/stateless_reset.key` (mode 0600, created on first
  start). After a restart, a client still attached to the old process
  learns within about one round trip that the connection is gone,
  instead of waiting out the 45-second idle timeout (ADR-0036).
- The client no longer sends SNI in its TLS ClientHello (ADR-0040,
  decision 2). Encrypted ClientHello is not implemented, because the
  TLS library has no server-side support; DNS over HTTPS is not
  implemented either (ADR-0039).

### Fixes

- `qsh doctor`'s UDP probe sent a datagram a healthy QUIC server
  ignores, so working hosts were reported as `udp_egress_blocked`
  (issue #7). The probe is now a padded QUIC packet with an unsupported
  version, which a QUIC server answers with Version Negotiation, so a
  healthy qsh listener no longer looks like blocked UDP.
- Resolving a peer or controller name waits at most 10 seconds and then
  fails with `CONNECTION_FAILED`. A resolver that never answered used to
  hold `attach`, session commands, `exec` without `--timeout`,
  `pair accept`, the fingerprint probe behind `trust add`, and the
  `serve --to` reconnect loop indefinitely.
- `qsh listen`'s local relay could drop the target's final `ExecExit` or
  its last session replies when one direction closed first, so a local
  client saw its command or session end without the closing frames.
- The host returns an exec quota slot before it sends `ExecExit`, so a
  new exec started right after the previous one's result no longer hits
  the quota.
- `RemoteForwardClose` now waits up to one second for the listener to
  be released before it replies, so reopening the same bind right away
  no longer races the old listener.
- `serve` and `listen` register their signal handlers at startup, so a
  `SIGTERM` sent right after the listening line stops them cleanly.

### What is in the archives

Seven assets plus a `SHA256SUMS` file. Linux aarch64 (static, musl) is
new in this release.

| Platform | Asset |
|---|---|
| macOS, Apple silicon | `qsh-v0.4.0-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `qsh-v0.4.0-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (glibc) | `qsh-v0.4.0-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (glibc) | `qsh-v0.4.0-aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (static, musl) | `qsh-v0.4.0-x86_64-unknown-linux-musl.tar.gz` |
| Linux aarch64 (static, musl) | `qsh-v0.4.0-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `qsh-v0.4.0-x86_64-pc-windows-msvc.zip` |

Each `.tar.gz` holds the `qsh` binary and the generated man pages under
`man/`. The Windows `.zip` holds the binary alone.

### Three ways to install

**Homebrew**, Apple silicon only. The formula points at the
`aarch64-apple-darwin` tarball and puts the man pages on your `MANPATH`.

```bash
brew install DaveDev42/tap/qsh
```

**The installer script**, macOS and Linux. It picks the asset for your
platform, checks it against the release's `SHA256SUMS`, and installs to
`~/.local/bin` by default (`QSH_INSTALL_DIR` overrides it). It never
calls `sudo`. Two changes since `v0.3.0`:

- When the GitHub CLI is installed and logged in, the installer runs
  `gh attestation verify` on the archive and installs nothing if that
  fails. Without a usable `gh` it says "provenance not verified" on
  stderr and installs on the checksum alone. `QSH_INSECURE_SKIP_VERIFY=1`
  skips both checks, with a warning.
- It installs the man pages to
  `${XDG_DATA_HOME:-~/.local/share}/man/man1` (`QSH_MAN_DIR` overrides it, `QSH_NO_MAN=1` skips them). A problem
  with the man pages prints a warning and leaves the binary installed.

`QSH_LIBC=musl` selects the static Linux build, on x86_64 and now on
aarch64.

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

**By hand.** Download the asset, check it against `SHA256SUMS`, put `qsh`
on your `PATH`. Windows has no installer path, so this is the only one
there.

### Verifying provenance

Every asset, `SHA256SUMS` included, has a build provenance attestation
from the workflow run that built it:

```bash
gh attestation verify qsh-v0.4.0-x86_64-unknown-linux-gnu.tar.gz --repo DaveDev42/qsh
```

What that establishes is the same as for `v0.3.0` below: which workflow
and commit produced the file, not whether the code is correct.

### What is signed and what is not

- **Both macOS binaries are signed and notarized.** This tag is cut
  with all six Apple credentials configured. Each binary is signed with
  the Developer ID Application certificate of team `MU784AJZSW` under the
  hardened runtime with a trusted timestamp. The workflow fails the build
  unless Apple's notary service returns `Accepted`. The signing
  identity stays the same from release to release, so macOS sees each
  upgrade as the same developer's binary. Earlier releases were ad-hoc
  signed, and each new build looked like a different program to macOS.
  Whether every permission prompt stays quiet across upgrades is not
  something this release tests.
- **Linux and Windows assets are not code-signed.** Provenance
  attestation and the checksum file are what you get.
- **Nothing is stapled.** qsh ships a bare executable inside a `.tar.gz`,
  and a ticket cannot be stapled to one. Gatekeeper checks the
  notarization online, so a first run on a machine with no route to
  Apple is not guaranteed to be admitted.

Check what you have:

```bash
codesign -dv --verbose=4 $(which qsh)   # Authority=Developer ID Application: ...
spctl -a -vvv -t execute $(which qsh)   # the verdict Gatekeeper would reach
```

### Gates this build passed

The seven gates from `CLAUDE.md` and the interactive acceptance job ran
green on the tagged commit, and the release-profile functional smoke
ran on every build leg, as for `v0.3.0`. Before the tag, the full
workspace suite also ran 30 times in a row on Linux with every CPU kept
busy by other processes, with no failures. The flaky tests that earlier
runs of that loop surfaced were fixed first.

### Not for production use

Nothing here changes what the `v0.3.0` section says: the independent
protocol and key-lifecycle review is not contracted, the wire format is
not frozen, and the campaigns a person runs by hand are still open. The
clean-machine install rounds for macOS can now be run against a signed
release, which `v0.3.0` could not offer.

## `v0.3.0`

First release cut after the M10 release pipeline landed. It also carries
the fix for issue #5. `qsh exec <host>` used to look only at the forward
address book, so a host reachable through a live reverse registration
held by `qsh listen` failed with `CONNECTION_FAILED` against a stale
forward address. It now follows the same routing priority as `host get`
and attach (`docs/CLI.md` §6.1, §6.8). `docs/CLI.md` moves to v0.13 for
this one delta (§6.1, §6.8, §6.13).

The wire format does not change, but the controller's `qsh listen` has
to run this build or a newer one, because its resident daemon now relays
the `EXEC_DATA` stream (`docs/design/protocol.md` §11). An older
`qsh listen` rejects that stream with `INVALID_ARGUMENT`, and `qsh exec`
from this build reports it as a stale `qsh listen` to restart or upgrade.

### What is in the archives

Six assets plus a `SHA256SUMS` file:

| Platform | Asset |
|---|---|
| macOS, Apple silicon | `qsh-v0.3.0-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `qsh-v0.3.0-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (glibc) | `qsh-v0.3.0-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (glibc) | `qsh-v0.3.0-aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (static, musl) | `qsh-v0.3.0-x86_64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `qsh-v0.3.0-x86_64-pc-windows-msvc.zip` |

Each `.tar.gz` holds the `qsh` binary and the generated man pages under
`man/`. The Windows `.zip` holds the binary alone.

### Three ways to install

**Homebrew**, Apple silicon only. The formula points at the
`aarch64-apple-darwin` tarball, so this path inherits that one asset's
signing status, and it is the only path that puts the man pages on your
`MANPATH`.

```bash
brew install DaveDev42/tap/qsh
```

**The installer script**, macOS and Linux. It picks the asset for your
platform, checks it against the release's `SHA256SUMS` before unpacking,
and installs to `~/.local/bin` by default (`QSH_INSTALL_DIR` overrides
it). It never calls `sudo`, and it does not install the man pages. Set
`QSH_LIBC=musl` for the static Linux x86_64 build.

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

**By hand.** Download the asset, check it against `SHA256SUMS`, put `qsh`
on your `PATH`. Windows has no installer path, so this is the only one
there.

### Verifying provenance

Every asset in this release, `SHA256SUMS` included, has a build
provenance attestation produced by the same workflow run that built it.
With the GitHub CLI:

```bash
gh attestation verify qsh-v0.3.0-x86_64-unknown-linux-gnu.tar.gz --repo DaveDev42/qsh
```

Add `--signer-workflow DaveDev42/qsh/.github/workflows/release.yml` to
pin which workflow signed it rather than trusting any workflow in the
repository.

What this establishes is narrow: the exact file you hold came out of a
workflow in this repository, on a GitHub-hosted runner, from a named
commit. It says nothing about whether the code at that commit is correct
or safe to run. The `SHA256SUMS` check the installer already does
answers a different question: it catches a truncated or corrupted
download, not a compromised release. A checksum is not a signature.

### What is signed and what is not

- **Linux and Windows assets are not code-signed at all.** There is no
  signing step for them in the release workflow, and none is planned for
  v1. Provenance attestation and the checksum file are what you get.
- **macOS assets are signed only when the release is cut on a repository
  with all six Apple credentials configured.** When they are, both macOS
  binaries are signed with a Developer ID certificate under the hardened
  runtime and with a trusted timestamp, then submitted to Apple's notary
  service, and the workflow fails the build unless the notary returns
  `Accepted`. When the credentials are absent the build stays green and
  ships an ad-hoc signed binary, the same thing a local
  `cargo build --release` produces; a partial set of credentials is
  treated as a misconfiguration and fails the tag outright.
  For this tag, `Check for Apple signing secrets` in the release run
  log says which case applied. v0.3.0 is cut without the Apple
  credentials configured, so both macOS binaries in this release are
  ad-hoc signed, not notarized.
- **Nothing is stapled.** `xcrun stapler` attaches a ticket to a `.app`,
  `.dmg` or `.pkg`, and qsh ships a bare executable inside a `.tar.gz`.
  Gatekeeper confirms the notarization online instead, so a first run on
  a machine with no route to Apple is not guaranteed to be admitted.
- **The installer clears the quarantine attribute** after it copies the
  binary into place, best effort, so an install through that path
  normally does not reach Gatekeeper; `scripts/install.sh` does not
  check the result, so macOS may still object. A manual download
  always reaches Gatekeeper.

Check what you actually have:

```bash
codesign -dv --verbose=4 $(which qsh)   # Developer ID build vs Signature=adhoc
spctl -a -vvv -t execute $(which qsh)   # the verdict Gatekeeper would reach
```

### The musl binary

The `x86_64-unknown-linux-musl` asset is statically linked, for
distributions whose glibc is older than the gnu build needs. It is never
auto-selected: a glibc system runs the gnu build, and guessing would move
people off the tested artifact quietly.

One caveat on memory. The 30 MB idle-listener target in `docs/PRD.md`
§13 is claimed for the glibc build only. The gnu build carries a
jemalloc dependency; the musl build does not, because that dependency
targets a glibc allocator behavior musl does not have. The soak and
adversarial-load campaigns are run on the glibc build. What the musl
asset is checked for before release is the functional smoke and the
static-link evidence, not an idle memory number.

### Gates this build passed

- The release-profile functional smoke ran on every build leg:
  `init` to mutual trust to `exec --json` to a PTY shell to `~d` detach
  to `qsh attach`. On Windows it stops after `exec --json`, since there
  is no PTY client off unix. This is the shipped binary being tested, not
  a debug build.
- A 60-second total blackout of the reverse route, resumed on the same
  session with its replay ring intact, runs in the acceptance job on
  every merge.
- A 30-minute full blackout runs on demand in a separate workflow and
  was judged once. What that run measured: the attach that was holding
  the connection when the blackout started does not itself survive 30
  minutes at shipped defaults. What survives is the session, which the
  same `session_ref` reattaches to once the blackout lifts.

### Not for production use

That line in the README is not boilerplate. Two things are open.

The independent review of the protocol and key lifecycle that
`docs/PRD.md` §15 requires has not been contracted, and the wire-format
freeze waits on the same decision. Until then the wire format can still
change.

The campaigns a person has to run by hand are open too: installing on
clean machines of the four platforms, the installer or a manual
download everywhere and Homebrew on Apple silicon, the Gatekeeper
verdict on a quarantined download, the musl binary on an old-glibc
distribution, the two connect-time stopwatch rounds, and the
real-device Wi-Fi-to-tethering mobility rounds. The fuzz, soak and
adversarial-load campaigns are closed.

`README.md`'s "Known limitations" section lists what this build does
not do; "Product boundary" next to it says what it will never do. The
ones most likely to matter on a first install: sessions do not survive
a restart of the listener process that holds them, tunnels do not
resume the way sessions do, `acl.toml` has no hot reload and is never
written for you, and Windows is a client-side platform only.

### Installing from crates.io

Not yet. The four contract crates are cleared to publish and CI dry-runs
the publish, but nothing has been pushed to the registry. Until it is,
`cargo install --locked --git https://github.com/DaveDev42/qsh qsh-cli`
is the `cargo install` route.
