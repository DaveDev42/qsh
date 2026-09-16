# scripts/

## install.sh

POSIX-sh installer for a prebuilt `qsh` release archive. No Rust toolchain
needed. Supports macOS (arm64, x86_64) and Linux (x86_64, aarch64); on
Windows it prints a pointer to the manual `.zip` download instead of
attempting an install.

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

| Var | Default | Meaning |
|---|---|---|
| `QSH_VERSION` | latest release | Release tag to install, e.g. `v0.1.0-alpha.1` |
| `QSH_INSTALL_DIR` | `$HOME/.local/bin` | Where the `qsh` binary is installed |
| `QSH_REPO` | `DaveDev42/qsh` | `owner/repo` to install from (forks, testing) |

The script downloads the release archive and that release's `SHA256SUMS`,
requires exactly one 64-character hex entry for the archive it fetched, and
compares digests before it unpacks anything. Any other outcome aborts with
nothing installed: no entry, a duplicate entry, a mismatch, a tarball whose
`qsh` member is missing or is a symlink. The binary lands via a temp file in
the destination directory followed by a rename, so an interrupted run never
leaves a half-written `qsh` on your `PATH`, and `sudo` is never invoked. An
unwritable `QSH_INSTALL_DIR` is an error, not a prompt to escalate.

What the checksum proves is bounded. `SHA256SUMS` comes from the same
release as the archive, so it catches a truncated or corrupted download, not
a compromised release. It is an integrity check, not a signature. Signing
and notarization are M9.

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

## stopwatch/

A container pair that builds a never-configured machine for each round of
the SC1 stopwatch campaign and checks the campaign's preconditions before
the timer starts. It measures nothing — the thing being timed is human
time. See [docs/campaigns/m7-stopwatch.md](../docs/campaigns/m7-stopwatch.md)
and stopwatch/README.md (Korean, like the campaign doc it serves).
