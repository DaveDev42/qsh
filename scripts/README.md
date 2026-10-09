# scripts/

## install.sh

POSIX-sh installer for a prebuilt `qsh` release archive. No Rust toolchain
needed. Supports macOS (arm64, x86_64) and Linux (x86_64 and aarch64 against
glibc, x86_64 and aarch64 against musl); on Windows it prints a pointer to the manual
`.zip` download instead of attempting an install.

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

| Var | Default | Meaning |
|---|---|---|
| `QSH_VERSION` | latest release | Release tag to install, e.g. `v0.1.0-alpha.1` |
| `QSH_INSTALL_DIR` | `$HOME/.local/bin` | Where the `qsh` binary is installed |
| `QSH_REPO` | `DaveDev42/qsh` | `owner/repo` to install from (forks, testing) |
| `QSH_LIBC` | `gnu` | Linux only. `musl` picks the static build (x86_64 or aarch64) for old-glibc distributions. On aarch64 the installer reads the tag's `SHA256SUMS` first and stops with a message if the tag predates the aarch64 musl asset |
| `QSH_MAN_DIR` | `${XDG_DATA_HOME:-$HOME/.local/share}/man/man1` | Where the archive's man pages are installed (created if missing) |
| `QSH_NO_MAN` | unset | Exactly `1` skips the man pages |
| `QSH_INSECURE_SKIP_VERIFY` | unset | Exactly `1` skips the checksum and the provenance check, with a warning |

The script downloads the release archive and that release's `SHA256SUMS`,
requires exactly one 64-character hex entry for the archive it fetched, and
compares digests before it unpacks anything. Any other outcome aborts with
nothing installed: no entry, a duplicate entry, a mismatch, a tarball whose
`qsh` member is missing or is a symlink. The binary lands via a temp file in
the destination directory followed by a rename, so an interrupted run never
leaves a half-written `qsh` on your `PATH`, and `sudo` is never invoked. An
unwritable `QSH_INSTALL_DIR` is an error, not a prompt to escalate. The
archive also carries the man pages under `man/` for tags after `v0.2.0`.
The installer copies every `man/<name>.1` member to `QSH_MAN_DIR` the same
way (temp name, then rename). A member whose name is not exactly
`man/<name>.1`, or that is a symlink, is reported and skipped. Man pages are
best effort: a failure prints a warning and leaves the installed binary in
place, an archive without `man/` is installed without comment, and
`QSH_NO_MAN=1` skips them. After installing, the script asks `manpath`
whether the man directory's parent is on the search path and prints an
`export MANPATH=...` line if it is not or if `manpath` is missing.
man-db finds `~/.local/share/man` by itself when `~/.local/bin` is on
`PATH`; macOS does not.

What the checksum proves is bounded. `SHA256SUMS` comes from the same
release as the archive, so it catches a truncated or corrupted download, not
a compromised release. It is an integrity check, not a signature. Whether
the macOS binaries are Developer ID signed and notarized depends on
whether the release was cut with Apple credentials configured
(`docs/deploy/release-secrets.md`); the installer does not check.

Provenance is a separate check. Every asset `release.yml` publishes for a
tag after `v0.2.0`, `SHA256SUMS` included, gets a build provenance
attestation from the same workflow run, which the GitHub CLI verifies:

```bash
gh attestation verify qsh-<tag>-<target>.tar.gz --repo DaveDev42/qsh
```

The installer runs exactly that command on the downloaded archive, after
the checksum and before unpacking. It fails closed where it can verify and
says so where it cannot:

- `gh` installed and logged in (`gh auth status` succeeds): the archive must
  verify. A failed verification installs nothing.
- `gh` missing, or installed but not logged in: the installer prints
  `provenance not verified` on stderr and installs on the `SHA256SUMS` check
  alone.
- `QSH_INSECURE_SKIP_VERIFY=1` (exactly `1`; any other value is ignored):
  skips both the checksum and the provenance check and prints a warning. It
  is the only way past either check.

Tags up to `v0.2.0` have no attestation, so with `gh` logged in the
installer refuses them. Use the flag for those, or log `gh` out.

What provenance shows is narrow: the file was produced by this repository's
`release.yml` run from a named commit. It says nothing about whether the
code at that commit is correct or safe to run. To pin the signing workflow
when verifying by hand, add
`--signer-workflow DaveDev42/qsh/.github/workflows/release.yml`; the
installer does not pass it.

Archive naming (`qsh-<tag>-<target>.tar.gz`, `.zip` on Windows) and the
`SHA256SUMS` file are produced by `.github/workflows/release.yml`. That
naming is a contract between the two files; changing one means changing the
other.

## fuzz/

`oss-fuzz-local.sh` builds every fuzz target the way OSS-Fuzz's own helper
would and produces the seed-corpus zips, so a submission can be checked
without cloning the OSS-Fuzz repo. Target inventory and campaign procedure
are in [fuzz/README.md](../fuzz/README.md).

## mobility/

Manual Wi-Fi to tethering mobility campaign scripts. See
[docs/campaigns/m2-mobility.md](../docs/campaigns/m2-mobility.md).

## soak/

`run.sh` drives the 24h/100-session soak scenario
(`crates/qsh-cli/tests/soak.rs`) under nextest's `[profile.soak]` on a
dedicated Linux host. `summarize.py` (stdlib only) reads the CSV that
`run.sh` writes and judges it against the thresholds fixed in
[docs/campaigns/m8-soak.md](../docs/campaigns/m8-soak.md) §3, exiting
non-zero on a violation. Neither script runs in CI; `load.yml` runs the
same scenario in its short mode instead.

## stress/

`run.sh <nextest-filterset> [rounds]` saturates every logical CPU with
`yes >/dev/null` busy loops and runs `cargo nextest run --workspace
--no-fail-fast -E '<filterset>'` for `rounds` rounds (default 50). The first
red round prints its number and the failing test names and exits 1; a green
run ends with `N/N passed under load`. The busy loops are reaped by an
`EXIT` trap. Set `QSH_ACCEPTANCE_SLOW=1` to include the wall-clock tests. It
runs on macOS and Linux and is not part of the PR gate: shared runners
reproduce load poorly and 50 rounds take tens of minutes. A new
timing-sensitive test must be green for 50 consecutive rounds here before it
lands (`docs/design/testing.md`, CI discipline).

## test/

`nextest-ns.sh [nextest args]` runs the suite (default `--workspace`) inside
`unshare -Urn` with `lo` brought up, plus a nested
`unshare -U --map-user=<uid> --map-group=<gid>` so tests do not run as uid 0.
Use it when the testkit's loopback-UDP self-check reports a host firewall rule
dropping loopback UDP (nft tables are per network namespace). Needs
`unshare` and `ip` (iproute2); Linux only.

`short-tmpdir.sh` is the nextest setup script wired in
`.config/nextest.toml`: when `$TMPDIR` is longer than 48 bytes it points the
tests at `/tmp/qsh-t-<uid>`, so unix socket paths stay inside `sun_path`.

## stopwatch/

A container pair that builds a never-configured machine for each round of
the SC1 stopwatch campaign and checks the campaign's preconditions before
the timer starts. It measures nothing — the thing being timed is human
time. See [docs/campaigns/m7-stopwatch.md](../docs/campaigns/m7-stopwatch.md),
[docs/campaigns/m9-stopwatch.md](../docs/campaigns/m9-stopwatch.md), and
stopwatch/README.md (Korean, like the campaign docs it serves).
