# Release notes

One section per release tag, newest first. Each section says what the tag
ships, which parts of it are signed, how to check any of that yourself,
and what is still unproven. The heading `<tag>` below is a placeholder:
the commit that bumps the version for a tag replaces it with that tag's
name.

The GitHub Release page for a tag carries the commit list; this file
carries the parts that do not change commit to commit.

## `<tag>`

First release cut after the M10 release pipeline landed. Nothing about
the protocol or the CLI contract changed in it.

### What is in the archives

Six assets plus a `SHA256SUMS` file:

| Platform | Asset |
|---|---|
| macOS, Apple silicon | `qsh-<tag>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `qsh-<tag>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (glibc) | `qsh-<tag>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (glibc) | `qsh-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (static, musl) | `qsh-<tag>-x86_64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `qsh-<tag>-x86_64-pc-windows-msvc.zip` |

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
gh attestation verify qsh-<tag>-x86_64-unknown-linux-gnu.tar.gz --repo DaveDev42/qsh
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
  log says which case applied.
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
