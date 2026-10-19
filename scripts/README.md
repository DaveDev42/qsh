# scripts/

## install.sh

POSIX-sh installer for a prebuilt `qsh` release archive. No Rust toolchain
needed. Supports macOS (arm64, x86_64) and Linux (x86_64 and aarch64, against
glibc or musl). On Windows it prints a pointer to the manual `.zip` download
instead of installing; the Windows installer is `install.ps1` below.

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
nothing installed: no entry, a duplicate entry, a mismatch, or a tarball
whose `qsh` member is missing or is a symlink. The binary lands via a temp file in
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

## install.ps1

PowerShell installer for a prebuilt Windows release zip, the counterpart of
`install.sh`. It runs under Windows PowerShell 5.1 and PowerShell 7, needs no
administrator rights and no Rust toolchain, and is plain ASCII so that
it does not depend on a byte order mark.

```powershell
irm https://raw.githubusercontent.com/DaveDev42/qsh/main/scripts/install.ps1 | iex
```

| Var | Default | Meaning |
|---|---|---|
| `QSH_VERSION` | newest release | Release tag to install, e.g. `v0.5.0` |
| `QSH_INSTALL_DIR` | `%USERPROFILE%\.local\bin` | Where `qsh.exe` is installed (created if missing) |
| `QSH_REPO` | `DaveDev42/qsh` | `owner/repo` to install from (forks, testing) |
| `QSH_MAN_DIR` | `%USERPROFILE%\.local\share\man\man1` | Where the zip's man pages are installed (created if missing) |
| `QSH_NO_MAN` | unset | Exactly `1` skips the man pages |
| `QSH_NO_MODIFY_PATH` | unset | Exactly `1` leaves the user `PATH` alone. Otherwise the install directory is appended to it when it is not already an entry |

The architecture comes from the Windows installation: `qsh-<tag>-x86_64-pc-windows-msvc.zip`
on AMD64, `qsh-<tag>-aarch64-pc-windows-msvc.zip` on ARM64, and anything else
is refused before anything is downloaded. The script downloads the zip and
that release's `SHA256SUMS`, requires exactly one 64-character hex entry for
the zip, and compares digests before it opens the zip. There is no path
around that check: unlike `install.sh`, `install.ps1` ignores
`QSH_INSECURE_SKIP_VERIFY`. The members are then
extracted one at a time by exact name (`qsh.exe`, and each `man/<name>.1`),
so a surprise path inside the zip cannot write elsewhere, and the binary
lands through a temporary name in the destination followed by a rename. Man
pages are best effort, as in `install.sh`. The user `PATH` is changed through
`HKCU\Environment`, keeping an existing `%VAR%` entry unexpanded and the
value's registry type, and nothing outside the user profile and the user's own
environment is touched.

The checksum is an integrity check against a bad download, not a signature,
and unlike `install.sh` this script does not run `gh attestation verify`.
`qsh.exe` and the `install.ps1` release asset are not Authenticode signed
(ADR-0035, revision of 2026-10-19), so the installer has no signature to check.

The tests are in `xtask/tests/install_script.rs` (`install_ps1::`), run on
Windows against a fake release directory with a stand-in `Invoke-WebRequest`.

## release/

Helpers `.github/workflows/release.yml` calls, kept as files so the tests can
run them.

- `secret-gate.sh` is the all-or-none gate for a set of signing secrets,
  used by the macOS leg (six Apple secrets). Every secret set writes `has-<platform>=true`; none set writes
  `false` and warns `Unsigned release` on a tag push; a partial set is an
  error on a tag push and a warning plus a skip on a branch run. It reads only
  presence flags, never a secret value. Tests: `secret_gate::` in
  `xtask/tests/install_script.rs`.
- `package-windows.ps1` builds the Windows zip (`qsh.exe` plus
  `man/*.1`, forward-slash entry names) and re-opens it to check that the
  member list and every member's bytes match the sources, so a zip that lost
  a man page fails the packaging step.

## fuzz/

`oss-fuzz-local.sh` builds every fuzz target the way OSS-Fuzz's own helper
would and produces the seed-corpus zips, so a submission can be checked
without cloning the OSS-Fuzz repo. Target inventory and campaign procedure
are in [fuzz/README.md](../fuzz/README.md).

## mobility/

Manual Wi-Fi to tethering mobility campaign: `switch-linux.sh` and
`switch-macos.sh` move the link, `summarize.py` tabulates the client's
recovery diagnostics. See
[docs/campaigns/m2-mobility.md](../docs/campaigns/m2-mobility.md).

## soak/

`run.sh` drives the 24h/100-session soak scenario
(`crates/qsh-cli/tests/it/soak.rs`) under nextest's `[profile.soak]` on a
dedicated Linux host. `preflight_udp.py` checks beforehand that the host
does not drop loopback UDP. `summarize.py` (stdlib only) reads the CSV that
`run.sh` writes and judges it against the thresholds fixed in
[docs/campaigns/m8-soak.md](../docs/campaigns/m8-soak.md) §3, exiting
non-zero on a violation. None of these runs in CI; `load.yml` runs the
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
lands (`docs/design/testing.md`, CI discipline). `m13.filter` and
`m13-latency.filter` are nextest filtersets for the M13 timing-sensitive
tests. `m15.filter` is the M15 set: the trust-role tests (live-server tests
that open real connections and change `trust.toml` underneath them, plus the
`trust.toml` reload and role-write unit tests in `qsh-core`) and the `qsh cp`
file-op tests (host, client, cancel, recursive copy, state-path guard, FILE_DATA
relay). Integration tests are selected by module prefix (`file_`, `cp_`, ...),
unit tests by module path, since nextest matches the full name. A few pure
table and fixture checks ride along because their names share a prefix. It
leaves out the three p95/throughput measurements, which are gated by
`QSH_ACCEPTANCE_STRICT` or `QSH_ACCEPTANCE_SLOW` and fail by design under CPU
saturation. `m15-latency.filter` selects exactly those three
(`role_resolution_per_decision_costs_*`, `file_copy_echo_under_load`,
`cp_many_small_files`); run them 50 times with no competing load at `-j 1`.
`m16.filter` is the M16 set: the trust-withdrawal tests (per-connection
watch, close code `0x1005`, the three processes `serve`, `serve --to` and
`listen`, the trust-store poll) and the SSH bootstrap tests (`ssh_bootstrap`,
`ssh_respond`, `auto_bootstrap`, `bootstrapped_` prefixes, run against the
fake `ssh` harness). It leaves out
`one_change_closes_many_connections_within_two_seconds`, a measurement whose
connection count is raised with `QSH_M16_CONNECTIONS`. M16 adds no p95
budget, so there is no `m16-latency.filter`.
`m17.filter` is the M17 set. For now it covers `qsh service`: the unit tests
in `ops::service::tests` (the argv per manager, the deadline paths of
`CommandRunner` on an injected clock and on a real child), the golden
activation scenario over a fake `launchctl`/`systemctl` on `PATH`, the
`--json`/`--jsonl` purity rows, and the doc-versus-argv comparison. None of
them calls a real service manager. It also covers `qsh identity move-key`:
the `identity_move_key::` module and the route-equivalence test
`move_key_then_serve_listen_and_serve_to_handshake_with_unchanged_pins`
(real `qsh serve`, `qsh listen` and `qsh serve --to` processes after a key
moved through a fake platform store; no test touches the OS credential
store). It also covers `qsh sessions` filters: the `sessions_filter::` module,
including the route-equivalence test
`sessions_filter_applies_identically_to_forward_and_reverse_hosts` (real
`qsh serve`, `qsh listen` and `qsh serve --to` processes, with a pty client
holding a writer lease on each host). It also covers `qsh audit`: the
`audit_query::` module (real binary against a planted log), the op-level
`ops::audit::tests::` and `audit_query_classification::` source-scan pins, and
the route-equivalence test
`audit_query_reads_records_written_by_serve_listen_and_serve_to` (real
`qsh serve`, `qsh listen` and `qsh serve --to` processes writing one device's
audit log, read back by one `qsh audit`). The `audit_query_reads_while_the_writer_rotates`
reader test is part of the same set. M17 adds no p95 budget, so there is no
`m17-latency.filter`.
`m20.filter` is the M20 set, for Windows only: the `conpty_` tests of the
ConPTY backend (output order against the exit event, a slow consumer, the Job
Object, resize, the owner-only host pipes, the environment and working
directory of the child, the close escalation), the hundred-session leak test
(`hundred_sequential_conpty_`) and the `pty_session_` route
cases (`windows_forward_e2e`, `windows_reverse_e2e`) that run the session ops
against a real `qsh serve` host. The session signals are in it too: the
`pty::conpty::tests::signals::` tests (each signal as the event a
`qsh-signal-probe` on the console receives, the escalation, the two named
events) and the `session_close_with_each_signal_` route cases. They start real
`cmd.exe` and probe processes and pseudo-consoles, so run it on a Windows host
(Git for Windows bash) with `run.sh`, after `cargo build -p qsh-testkit --bin
qsh-signal-probe` so the probe sits next to the test executables.

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
the timer starts. It measures nothing; the thing being timed is human time.
See [docs/campaigns/m7-stopwatch.md](../docs/campaigns/m7-stopwatch.md),
[docs/campaigns/m9-stopwatch.md](../docs/campaigns/m9-stopwatch.md), and
[stopwatch/README.md](stopwatch/README.md) (Korean, like the campaign docs
it serves).
