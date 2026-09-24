# scripts/

## install.sh

POSIX-sh installer for a prebuilt `qsh` release archive. No Rust toolchain
needed. Supports macOS (arm64, x86_64) and Linux (x86_64 and aarch64 against
glibc, x86_64 against musl); on Windows it prints a pointer to the manual
`.zip` download instead of attempting an install.

```bash
curl -fsSL https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.sh | sh
```

| Var | Default | Meaning |
|---|---|---|
| `QSH_VERSION` | latest release | Release tag to install, e.g. `v0.1.0-alpha.1` |
| `QSH_INSTALL_DIR` | `$HOME/.local/bin` | Where the `qsh` binary is installed |
| `QSH_REPO` | `DaveDev42/qsh` | `owner/repo` to install from (forks, testing) |
| `QSH_LIBC` | `gnu` | Linux only. `musl` picks the static x86_64 build for old-glibc distributions |

The script downloads the release archive and that release's `SHA256SUMS`,
requires exactly one 64-character hex entry for the archive it fetched, and
compares digests before it unpacks anything. Any other outcome aborts with
nothing installed: no entry, a duplicate entry, a mismatch, a tarball whose
`qsh` member is missing or is a symlink. The binary lands via a temp file in
the destination directory followed by a rename, so an interrupted run never
leaves a half-written `qsh` on your `PATH`, and `sudo` is never invoked. An
unwritable `QSH_INSTALL_DIR` is an error, not a prompt to escalate. Starting
with the first tag cut after the man pages joined the release archive, the
archive also carries them under `man/`; the installer extracts only `qsh`
and leaves them behind, and Homebrew is the install path that puts them on
a `MANPATH`.

What the checksum proves is bounded. `SHA256SUMS` comes from the same
release as the archive, so it catches a truncated or corrupted download, not
a compromised release. It is an integrity check, not a signature. Whether
the macOS binaries are Developer ID signed and notarized depends on
whether the release was cut with Apple credentials configured
(`docs/deploy/release-secrets.md`); the installer does not check.

Provenance is a separate check, and the installer does not perform it.
Starting with the first tag cut after the attestation step joined `release.yml`, every asset
`release.yml` publishes, `SHA256SUMS` included, gets a build provenance
attestation from the same workflow run, which the GitHub CLI verifies:

```bash
gh attestation verify qsh-<tag>-<target>.tar.gz --repo DaveDev42/qsh
```

Add `--signer-workflow DaveDev42/qsh/.github/workflows/release.yml` to also
pin which workflow signed it, rather than trusting any workflow in the repo.
The installer stays free of a `gh` dependency on purpose: every required
tool is one more way for an install to fail.

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
time. See [docs/campaigns/m7-stopwatch.md](../docs/campaigns/m7-stopwatch.md),
[docs/campaigns/m9-stopwatch.md](../docs/campaigns/m9-stopwatch.md), and
stopwatch/README.md (Korean, like the campaign docs it serves).
