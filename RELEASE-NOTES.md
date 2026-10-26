# Release notes

One section per release tag, newest first. Each section says what the tag
ships, which parts of it are signed, how to check any of that yourself,
and what is still unproven. A section whose heading reads `<tag>` is a
placeholder for the next tag; the commit that bumps the version replaces
it with that tag's name.

The GitHub Release page for a tag carries the commit list; this file
carries the parts that do not change commit to commit.

## `v0.5.4`

A patch release on top of `v0.5.3` with one fix found while running the
Windows host round W3b with a Linux controller
(`docs/campaigns/p1-windows.md`). The wire format, `qsh.cli/v1`,
`qsh.event/v1` and the doctor code set are unchanged, so `v0.5.3` and
earlier `v0.5.x` and `v0.4.x` peers interoperate with this build as before.

### Fixes

- Reverse route: when another process closes a tunnel with
  `qsh tunnel close`, a `qsh tunnel open --remote` started without
  `--supervise` still ends with `CONNECTION_FAILED` and a `tunnel_ended`
  line, as on `v0.5.3`. On `v0.5.3` it could also print a tokio panic
  (`JoinHandle polled after completion`) on stderr as it exited, if the
  close landed while it was waiting 200 ms to retry its `TCP_ACCEPTED`
  claim. The tunnel and its port were already gone, so only the message
  was wrong. The cleanup path no longer polls the finished claim attempt
  a second time.

### Assets and signing

Unchanged from `v0.5.3`: the same nine assets plus `SHA256SUMS`, with
`v0.5.4` in the names.

### What is still unproven

Everything `v0.5.3` lists, with these changes from the rounds run on
`v0.5.3`:

- W3b passed with a Linux controller. The controller was a WSL2
  distribution on the Windows machine itself, dialed at its own Tailscale
  address, which the campaign now allows. The path between two physical
  machines was covered by the macOS controller run on `v0.5.2`.
- W7 passed in both variants after the Windows `qsh serve` was allowed
  through the firewall.
- W2 and W3a have still not been run.

### Not for production use

Unchanged from `v0.5.0`.

## `v0.5.3`

A patch release on top of `v0.5.2` with three fixes found while running
the Windows host rounds W3b and W7 on real machines
(`docs/campaigns/p1-windows.md`). The wire format, `qsh.cli/v1`,
`qsh.event/v1` and the doctor code set are unchanged, so `v0.5.2` and
earlier `v0.5.x` and `v0.4.x` peers interoperate with this build as before.

### Fixes

- Reverse route: a `qsh tunnel open --remote` started without
  `--supervise` now ends when another process closes its tunnel with
  `qsh tunnel close`. It exits 255 with `CONNECTION_FAILED` and a
  `tunnel_ended` line. On `v0.5.2` it stayed running after the close and
  logged a failed `TCP_ACCEPTED` claim every 200 ms until it got a signal
  (ADR-0023 revision history).
- `qsh pair ssh` against a Windows OpenSSH Server whose default shell is
  `cmd.exe` now reports a missing remote `qsh` as `REMOTE_ERROR` with
  `details.reason: "remote_qsh_missing"`. A missing command makes
  `cmd.exe /c` exit 1, not 9009 as ADR-0044 assumed, so `v0.5.2` reported
  `remote_command_failed`. ssh's stderr is now relayed through qsh as it
  arrives instead of being inherited. qsh keeps the last 4 KiB in memory
  to classify an early exit and never writes it anywhere. Password,
  passphrase and host key prompts use the terminal and are unaffected
  (ADR-0044 revision history).
- Windows: `qsh doctor` no longer reports `keystore_session_bound` for a
  task registered with a `Password` principal. A measurement on
  Windows 11 25H2 showed such a task reads the Credential Manager key
  without an interactive session. `docs/deploy/service.md` now also says
  the account needs the "Log on as a batch job" right
  (`SeBatchLogonRight`), without which the task fails with `0x80070569`
  before qsh runs (ADR-0032 revision history).

### Assets and signing

Unchanged from `v0.5.2`: the same nine assets plus `SHA256SUMS`, with
`v0.5.3` in the names.

### What is still unproven

Everything `v0.5.2` lists, with these changes from the rounds run on
`v0.5.2`:

- W3b passed with a macOS controller. The Linux controller variant has
  not been run.
- W7 ran with a macOS client. Variant A (`cmd.exe`) failed on the
  missing-`qsh` check, which this release fixes, and is to be rerun on
  this tag. The checks that need inbound UDP to the Windows `qsh serve`
  through its firewall are still open in both variants.
- W2 and W3a have still not been run.

### Not for production use

Unchanged from `v0.5.0`.

## `v0.5.2`

A patch release on top of `v0.5.1`. It picks up dependency fixes for
RUSTSEC-2026-0385 and RUSTSEC-2026-0386, and `qsh service status --live`
now reads the state of a macOS LaunchDaemon install. The wire format, `qsh.cli/v1`,
`qsh.event/v1` and the doctor code set are unchanged, so `v0.5.1`,
`v0.5.0` and `v0.4.x` peers interoperate with this build as before.

### Fixes

- `ctutils` goes to 0.4.4 for RUSTSEC-2026-0385: its `const fn` mask
  generation and its `u128` comparison on 32-bit targets were not
  constant time. It comes in through `digest` and `sha2`, and through
  `hmac` and `hkdf` on the Linux Secret Service path. The `v0.5.1` assets
  were built with 0.4.3.
- `tokio` goes to 1.53.3 for RUSTSEC-2026-0386: the safe `AsyncFd`
  constructors accepted any raw file descriptor, which breaks I/O safety.
  qsh registers two descriptors this way, the PTY master and a `dup` of
  a local control socket. Each is an `OwnedFd` that the `AsyncFd` owns
  until it drops it, so neither could be closed or replaced underneath
  it. Both now go through the `unsafe` `AsyncFd::register` constructors
  that 1.53.3 adds, and the minimum `tokio` version is now 1.53.3.
- macOS: when the always-on LaunchDaemon form of a unit is installed,
  `qsh service status --live` now runs `launchctl print
  system/io.qsh.<mode>`, which needs no root. Exit 0 reports
  `active: true` and exit 113 (not loaded) reports `active: false`. Any
  other exit status is still `INTERNAL` with `details.step: "live"` and
  names the `sudo` command to run. On `v0.5.1` this case always ended in
  that error. Exit 0 means loaded, so a daemon that is loaded but not
  running also reads as `active: true` (ADR-0032 revision history).

### Assets and signing

Unchanged from `v0.5.1`: the same nine assets plus `SHA256SUMS`, with
`v0.5.2` in the names.

### What is still unproven

Everything `v0.5.1` lists, with these changes from the rounds run on
`v0.5.1` (`docs/campaigns/p1-windows.md`):

- The Credential Manager round trip (W8) passed in full, including the
  check after a reboot.
- The `cargo install` route (W11c) passed, including the check that
  `qsh version` prints the commit.
- The Windows host rounds (W2, W3b, W7), the Windows `qsh listen` round
  (W3a) and the macOS Keychain `qsh identity move-key` round trip have
  still not been run.

### Not for production use

Unchanged from `v0.5.0`.

## `v0.5.1`

A patch release on top of `v0.5.0`. It fixes a Windows host that did not
accept IPv4 peers on the default bind, a shared admission bucket for IPv4
peers, and a missing commit in `qsh version` for `cargo install` builds.
The wire format, `qsh.cli/v1`, `qsh.event/v1` and the doctor code set are
unchanged, so `v0.5.0` and `v0.4.x` peers interoperate with this build as
they did with `v0.5.0`.

### Fixes

- Windows: `qsh serve` and `qsh listen` on the default `[::]:4433` now
  accept IPv4 peers. Windows opens new IPv6 sockets IPv6-only, so on
  `v0.5.0` those listeners silently refused every IPv4 peer, including
  Tailscale and most LAN addresses. The listener now clears
  `IPV6_V6ONLY` the way the client already did, which matches the Linux
  default (ADR-0046). If you worked around this with
  `--bind 0.0.0.0:4433`, that still works; you can drop it to accept IPv6
  peers too.
- `qsh doctor`'s `bindv6only_blocks_ipv4` now fires only when the OS
  refuses to clear `IPV6_V6ONLY`. On `v0.5.0` it fired on every Windows
  machine with an IPv6 wildcard bind.
- On a dual-stack listener an IPv4 peer shows up as an IPv4-mapped IPv6
  address. The per-source handshake rate limit keyed all such peers into
  one `::/64` bucket, so one IPv4 client could use up the limit for every
  other IPv4 client. Mapped addresses are now keyed as the plain IPv4
  address (ADR-0009 revision history). Linux hosts on the default bind
  have had this since the limiter landed. On Windows it appears only with
  the IPv4 fix above.
- `qsh version` in a build from `cargo install --locked --git
  https://github.com/DaveDev42/qsh --tag v0.5.1 qsh-cli` now prints the
  commit, read from the git checkout cargo made. Release assets carry
  the commit as before. A build from a working tree without
  `QSH_BUILD_COMMIT` still prints none.
- `rustls-webpki` goes to 0.103.16 for RUSTSEC-2026-0382. qsh uses webpki
  path validation only for CA-authenticated peers, whose anchors are
  your own CA, so the distrusted public intermediates in the advisory do
  not apply.

### Assets and signing

The same nine assets plus `SHA256SUMS` as `v0.5.0`, with `v0.5.1` in the
names. Signing is unchanged: both macOS binaries are Developer ID signed
and notarized, nothing is stapled, Linux assets are not code-signed, and
the Windows assets and `install.ps1` are not Authenticode signed. Every
asset has a build provenance attestation.

### What is still unproven

Everything `v0.5.0` lists below, with these changes from the first
Windows rounds (`docs/campaigns/p1-windows.md` section 7, run by an
agent on `v0.5.0`):

- The Credential Manager round trip (W8) passed except the check after a
  reboot, which has not been run.
- `install.ps1` without admin rights (W11b) passed.
- The `cargo install` route (W11c) built and installed without admin
  rights, but failed its check that `qsh version` prints the commit. This
  release fixes that, and the round runs again on this tag.
- The Windows host rounds (W2, W3b, W7) and the Windows `qsh listen`
  round (W3a) have not been run. They run on this tag because of the
  IPv4 fix above.
- The Linux Secret Service `qsh identity move-key` round trip passed in a
  container. The macOS Keychain round trip has not been run.

### Not for production use

Unchanged from `v0.5.0`.

## `v0.5.0`

This release closes milestones M15 to M17, M19 and M20: trust roles,
`qsh cp`, the ssh bootstrap, trust revocation that closes open
connections, the operations surface, and Windows as a full client and
host. M14 (TCP/TLS fallback) was withdrawn (ADR-0043) and M18
(session home) has not started. `docs/CLI.md` moves from v0.25 to v0.56;
its status header lists each delta.

### Compatibility with `v0.4.x`

The wire format changes only by addition, and `v0.4.x` peers interoperate
with this build in both directions. They do not get the new file
operations.

- `wire/v1.proto` adds `FileReadOpen`, `FileWriteOpen`, `FileListOpen` and
  `FileMkdirOpen` (control message numbers 80 to 83), their four
  responses (11 to 14), `StreamKind.FILE_DATA = 5` and the `FileFrame`
  messages. No existing field, number or message changed. `local/v1.proto`
  changed in a comment only.
- Hello advertises a new capability string, `file.v1`, on every platform.
  Capabilities are negotiated as the intersection of both sides, so a
  `v0.4.x` peer ignores the string. This build never sends a file
  operation to a peer that did not advertise `file.v1`.
- This build as client, `v0.4.x` host: `qsh cp` fails with `UNSUPPORTED`
  and says the peer does not advertise `file.v1`. Nothing is sent.
  Everything else works as before.
- `v0.4.x` client, this build as host: it never sends a file operation, so
  nothing changes for it. Its requests are authorized the same way.
- Reverse route: `qsh cp` needs `file.v1` on the target and on the
  controller's `qsh listen` daemon. A `qsh listen` process that started
  before the upgrade keeps relaying its old capability set, so restart it
  after upgrading. The error text says so.
- `qsh.cli/v1` and `qsh.event/v1` stay additive. New fields and commands
  only; the golden `capabilities.json` gains `file.v1` and the other
  fixtures are append-only. No new schema major.
- `trust.toml` gains an optional `role` key per `[[peer]]`. A `v0.4.x`
  binary reading a file written by this build ignores the key, so after a
  downgrade those pins fall back to `acl.toml` alone.

### Trust roles replace the need for an `acl.toml`

A trust pin now carries one role: `full`, `exec`, `tunnel`, `read-only`,
`reverse` or `none` (ADR-0045). A role grants a fixed set of actions, and
registering a peer now grants authority by default. This changes what
happens after pairing.

- `qsh pair invite` and `qsh trust add` without `--address` give the new
  pin role `full`. `qsh trust add --address` and `qsh pair accept` give
  `none`, because the pin only names a machine you dial. `--role`
  overrides any default. `qsh trust set-role <name> <role>` changes one
  later. `pair invite --role` fixes the role the host will give the
  redeeming peer; the redeemer cannot choose it.
- Existing pins have no `role` key and are judged as `none`. Upgrading does
  not widen anyone's access, and `acl.toml` keeps working for them as
  before. To move such a peer onto a role, run `qsh trust set-role`.
- A role and an `acl.toml` row are combined by union. `acl.toml` is now
  optional: with no file, roles still work. A file that does not parse
  still denies every request, role grants included. `forward.socks` is in
  no role, and the always-deny gate runs before roles.
- Roles are read on every request, so `trust set-role` and `trust remove`
  apply without a restart. `acl.toml` still has no hot reload. If
  `trust.toml` cannot be parsed, pin authentication keeps using the last
  good snapshot and role grants stop until the file parses again.
- `qsh acl show`, `qsh acl check` and `qsh doctor` report roles
  (`docs/CLI.md` §6.15, §6.17, §6.19).
- `full` lets the serve account reach any path through `qsh cp`, which is
  as strong as `exec.run`. Grant it deliberately.

### Closing connections when trust is withdrawn

`qsh trust remove`, lowering a role with `qsh trust set-role`, and renaming
a pin that has a role now close that peer's open connections on this device
within 2 seconds, in a running `qsh serve`, `qsh listen` or `qsh serve
--to` (ADR-0031). Before, an established connection kept its authority
until it dropped. Sessions are not ended; a closed connection detaches
them. The change applies to this device only. For up to 2 seconds a request
on the old connection can still pass on an `acl.toml` row.

### `qsh cp`

`qsh cp [-r] [-p] [-q] [--no-clobber] SRC... DST` copies between this
machine and a qsh host with scp's operand syntax, `[user@]host:path`
(ADR-0029, `docs/CLI.md` §6.21). It works over forward and reverse routes.
Transfers are checked with BLAKE3 and written to a temporary file that is
renamed into place, so an overwrite replaces the destination file rather
than writing into it. Remote paths under qsh's own config, state and
runtime directories are always refused, whatever the role or `paths` row,
and every such denial is the same `PERMISSION_DENIED`.

What it is not: scp's transport options are refused, remote-to-remote
copy is refused, there is no resume, a tree copy is not atomic and exits
`255` on a partial failure, and symlinks found inside a tree are skipped
and reported. `acl.toml` rows can carry a `paths` list to limit file
actions.

### SSH bootstrap

If you can already `ssh` to a machine, `qsh pair ssh <dest>` pins both
machines to each other over that connection (ADR-0044). The remote pin
gets role `full` unless you pass `--role`; the pin on this machine gets
`none`. `qsh pair ssh <dest> --reverse --to <address>` sets up a reverse
target the same way (remote pin `full`, this machine's pin `reverse`). In
human mode, `qsh <host>` and `qsh cp` on a name with no pin run the same
bootstrap on their own and print a line to stderr first. `--json`,
`--jsonl` and `[ssh].bootstrap = "off"` never start it. It uses the
system `ssh`, so `~/.ssh/config`, ssh-agent and known_hosts apply. It
does not install qsh on the remote or start `qsh serve`. The remote end
is the hidden `qsh pair ssh-respond`.

### Operations surface

- `qsh service install --activate`, `--deactivate` and `--live` call
  `launchctl`, `systemctl --user` or `schtasks`, and only when you pass the
  flag. Always-on recipes (Linux linger, a macOS LaunchDaemon, a Windows
  boot task) are documented in `docs/deploy/service.md` and qsh does not
  set them up. `qsh doctor` has new findings: `keystore_session_bound`,
  `launchagent_session_scoped` and `logon_task_session_scoped`.
- `qsh identity move-key --to file|platform` moves the device key between
  stores without changing the fingerprint.
- `qsh sessions` takes `--state`, `--writer` and `--attachable`.
- `qsh audit` queries this machine's audit log. It is local only and has no
  wire message. Nothing deletes or shortens the log.
- `README.md` was rewritten around the first-run flow.

### Windows

Windows 10 1809 or later runs both ends with the same features as Linux
and macOS (ADR-0035).

- Client: interactive attach on the console (raw VT input, resize
  polling), `exec`, `-L`/`-R`/`-D`, `qsh cp`, `qsh listen` and `serve --to`
  over a named pipe, the ssh bootstrap, `qsh service` on Task Scheduler,
  and sleep detection.
- Host: PTY sessions on ConPTY with each session in a Job Object, `exec` in
  a Job Object, the seven session signals mapped to console events,
  `qsh cp` (drive paths; UNC and device paths are refused), `setup host`,
  `pair invite` and `pair ssh-respond`.
- Files that qsh keeps private get an owner-only DACL, the device key can
  live in Credential Manager, and the audit log is locked with `LockFileEx`.
  Where an owner-only DACL cannot be applied (FAT/exFAT, a share without
  ACLs), qsh creates nothing and fails with `CONFIG_ERROR`.
- The first inbound bind triggers a Windows Defender Firewall prompt per
  executable path. See Known limitations in the README.

### Fixes and internal changes

- Several flaky tests were fixed on the test side (supervised tunnels,
  reverse registration budgets, trust withdrawal on `listen`), with no
  product behavior change.
- A Windows client attached to a Windows host session no longer lets the
  host's win32 input mode request reach the local console, which had made
  `~d` at the start of a line stop working.
- `qsh-core` and `qsh-cli` no longer depend on `quinn`. They use the neutral
  types in `qsh-transport`, and `cargo xtask arch` enforces it.
  Behavior is unchanged.
- Rust toolchain 1.99.0 (was 1.98.1). `rustls` 0.23.46, which fixes a
  certificate decompression advisory. The keychain code moved from
  `keyring` 3.6 to `keyring-core` 1 with per-platform store crates; the
  stored format (service `qsh`, account `device_id`, base64 PKCS#8) is
  unchanged. A Linux Secret Service round trip between the old and new
  binaries passed in both directions. A real macOS Keychain round trip
  has not been run on this build.
- Integration tests in each crate are now a single `tests/it` binary.

### Assets and signing

Nine assets plus `SHA256SUMS`. Windows aarch64 and the Windows installer
are new.

| Platform | Asset |
|---|---|
| macOS, Apple silicon | `qsh-v0.5.0-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `qsh-v0.5.0-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (glibc) | `qsh-v0.5.0-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (glibc) | `qsh-v0.5.0-aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (static, musl) | `qsh-v0.5.0-x86_64-unknown-linux-musl.tar.gz` |
| Linux aarch64 (static, musl) | `qsh-v0.5.0-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `qsh-v0.5.0-x86_64-pc-windows-msvc.zip` |
| Windows aarch64 | `qsh-v0.5.0-aarch64-pc-windows-msvc.zip` |
| Windows installer | `install.ps1` |

Each archive holds the binary and the generated man pages under `man/`.
Every asset, `SHA256SUMS` included, has a build provenance attestation;
`gh attestation verify qsh-v0.5.0-x86_64-unknown-linux-gnu.tar.gz --repo
DaveDev42/qsh` checks one, and it establishes which workflow and commit
built the file, not that the code is correct.

Installing on macOS and Linux is unchanged from `v0.4.0` (Homebrew on
Apple silicon, `scripts/install.sh`, or by hand), with `v0.5.0` in place of
`v0.4.0` in the asset names. On Windows there are three routes: the
release zip, `install.ps1`, and `cargo install --locked --git
https://github.com/DaveDev42/qsh qsh-cli` (which builds the default branch
unless you add `--tag v0.5.0`, and installs no man pages). `install.ps1`
checks the zip against `SHA256SUMS` before it opens it and does not run
`gh attestation verify`; run that by hand on the zip.

What is signed and what is not:

- Both macOS binaries are Developer ID signed and notarized, as in
  `v0.4.0`. Nothing is stapled.
- Linux assets are not code-signed.
- The Windows assets and `install.ps1` are not Authenticode signed.
  Authenticode signing was planned and withdrawn on 2026-10-19 because of
  cost, and Scoop and winget distribution was withdrawn the same day
  (ADR-0035 revision history). Expect a SmartScreen warning for a `qsh.exe`
  taken from a browser-downloaded zip and started from Explorer, and a
  block on a PC with Smart App Control on. A downloaded `install.ps1` may
  need `Unblock-File`. `irm ... | iex`, a `qsh.exe` started from a
  terminal, and a `cargo install` build are not affected. Integrity rests
  on `SHA256SUMS` and the provenance attestation.

### What is still unproven

- Windows has CI coverage on `windows-latest` (ConPTY sessions, signals,
  Job Objects, both routes) but no hands-on round: `docs/campaigns/p1-windows.md`
  has not been run. Real suspend and resume on Windows and the
  `cargo install` check are in that campaign.
- `docs/campaigns/p1-ssh-bootstrap.md` has had no round. The bootstrap is
  tested against a fake `ssh`, not against real OpenSSH with ProxyJump,
  ssh-agent or an encrypted key.
- `decode_file_frame` and `parse_ssh_bootstrap_line` have had CI smoke
  fuzz runs only, not the cumulative 72 hours the project asks for before a
  public beta.
- The `qsh setup` stopwatch round (`p1-setup-stopwatch`), the supervised
  tunnel sleep and network-switch rounds (`p1-supervise-wake`), and the
  P0 campaigns (clean-VM install on macOS, the SC1 stopwatch, the
  real-device mobility round) are open. M18 waits on the mobility round.
- The `v0.4.3` aarch64 musl old-glibc check passed, but an agent ran it in a
  container, and a person should repeat it.
- The macOS Keychain round trip and `qsh identity move-key` on a real
  Keychain have not been run.

### Not for production use

Unchanged from `v0.3.0` and `v0.4.0`: the independent protocol and
key-lifecycle review is not contracted, the wire format is not frozen, and
the campaigns a person runs by hand are still open. This release widens
what a new pin is allowed to do by default; read the roles section before
you pair machines you do not control.

## `v0.4.3`

A maintenance release. It updates dependencies and closes milestone M13.
It has no wire or `qsh.cli/v1` contract change, and `v0.4.x` peers
interoperate with it in both directions. The defaults and the
`config.toml` keys from `v0.4.2` are unchanged.

### Dependencies

- Lockfile refresh within semver for the workspace and `fuzz/`, including
  `quinn-proto` 0.11.19, `quinn-udp` 0.5.16 and `tokio` 1.53.2.
- Major bumps: `nix` 0.31, `sha2` 0.11, `base64` 0.23, `ulid` 3,
  `rand` 0.10, `toml` 1.1, and `jsonschema` 0.58 (tests only). Session
  and request ID strings, digest bytes and base64 output are unchanged.
  Resume tokens and the stateless reset key still come from the
  OS-seeded generator.
- `toml` 1.1 implements TOML 1.1. Every file that parsed before parses
  the same way. A few inputs that TOML 1.0 rejected are now accepted:
  newlines and a trailing comma inside an inline table, the `\e` and
  `\xHH` escapes, and times without seconds. That applies to
  `config.toml`, `acl.toml`, `trust.toml` and `hosts.toml`. A file that
  still does not parse keeps the old behavior: a broken `acl.toml` denies
  every request, and a broken `config.toml` stops startup with
  `CONFIG_ERROR`. The parser's message text in those errors may read
  differently.
- Still on the old versions: `keyring` stays on 3.6, because 4.x
  redesigns how the secret store is chosen and needs a hands-on check
  against a real Keychain and Secret Service. The Rust toolchain stays
  on 1.98.1.

### Internal

- Test modules in source files over about 800 lines moved to sibling
  `tests.rs` files. Test names and counts are unchanged.
- Duplicated test helpers were merged, two stale `dead_code` allowances
  were removed, and code comments now cite symbols instead of line
  numbers.
- CI moved to `actions/checkout` v7 and `setup-rust-toolchain` v2. The
  release workflow keeps its existing action versions.

### Assets and signing

The same as `v0.4.0`: the same seven assets plus `SHA256SUMS`, the same
install paths, the same provenance check, and the same Developer ID
signing and notarization of both macOS binaries. See "What is in the
archives" and "What is signed and what is not" under `v0.4.0` below,
with `v0.4.3` in place of `v0.4.0` in the asset names.

## `v0.4.2`

Reverse registrations hold up better on lossy links and on overloaded
hosts. This release finishes issues #10 and #11. It has no wire or
`qsh.cli/v1` contract change, and `v0.4.x` peers interoperate with it.
`docs/CLI.md` moves from v0.21 to v0.25.

Upgrade both ends of a reverse link. Each end runs its own path watch,
and an older build at either end keeps its 1-second detection and
closes the connection first.

### Reverse registrations ride out about 4 seconds of silence

- The path watch on a reverse registration, on both the `qsh listen`
  side and the `qsh serve --to` side, now declares the path dead after
  about 4.25 to 4.5 seconds of silence instead of about 1 second
  (`min_dead_after` 4250 ms, 3 strikes at 250 ms, ADR-0041). The longest
  uplink loss bursts measured in #10 were 2.1 to 3.6 seconds, and a
  registration now rides them out. A path that is really gone takes about
  3.25 seconds longer to detect.
- Interactive attach and supervised tunnels keep their 1-second budget.
- Tunnel traffic carried over a registration now counts as use of the
  registration. Before, a registration busy only with tunnel data fell
  back to the idle probe cadence after 15 seconds and took about
  20 seconds to notice a dead path. A registration with no traffic at all
  still uses the idle cadence, and detection there takes about 20 to 25
  seconds.

### New `config.toml` keys

All optional. Without them, behavior is the same as the defaults above.
A value out of range stops startup with `CONFIG_ERROR`. Nothing is
clamped.

- `[transport].keep_alive_ms`: QUIC keep-alive interval, default 15000,
  range 1000 to 20000 (ADR-0021).
- `[recovery].probe_interval_ms`, `min_dead_after_ms`, `strikes`: the
  path watch of interactive attach and supervised tunnels, default 250,
  1000 and 3, with `probe_interval_ms × strikes + min_dead_after_ms` at
  most 2000 (ADR-0021). `qsh serve` has no path watch of its own for
  these connections, so only the client's values matter.
- `[recovery].reverse_min_dead_after_ms`, `reverse_strikes`: the reverse
  registration's watch, default 4250 and 3, with the same formula at most
  5000 (ADR-0041). `probe_interval_ms` is shared. Each end reads its own
  file, so the two ends can be tuned separately. The default sits at the
  5000 ceiling, so raising one value means lowering another.

### An overloaded host no longer reads its own stall as a dead path

- When the path watch's own timer fires more than one probe interval
  late, the process was not running, and that time is not counted as
  silence on the path. That tick cannot declare the path dead (ADR-0042).
  This covers the scheduler stalls in #11. A peer that is itself starved
  still stops answering, so the healthy end can still cut a registration
  once the silence passes its 5-second budget.
- In `qsh serve --to`, when registrations keep ending within 60 seconds,
  the redial delay doubles from the second such loss, up to 8 seconds.
  A registration that lasts 60 seconds, or a wake from sleep, resets the
  count. The usual backoff after failed dials is unchanged.

### Diagnostics

- A `qsh::reverse` `lost` line with `cause=path_dead`, when this
  process's own watch made the call, now carries `srtt_ms`,
  `silence_ms` (how long this end saw no sign of life) and
  `tick_gap_ms` (how late this watch's worst tick fired). A stall of a
  few seconds then reads differently from a path that went away, without
  a packet capture.
- `cause` is classified more precisely: a stateless reset is now
  `peer_closed` and a `Hello` reply that never came is now
  `dial_timeout`; both used to be `local`. `docs/CLI.md` §6.13 lists
  every code path that still produces `cause=local`.

### Assets and signing

The same as `v0.4.0`: the same seven assets plus `SHA256SUMS`, the same
install paths, the same provenance check, and the same Developer ID
signing and notarization of both macOS binaries. See "What is in the
archives" and "What is signed and what is not" under `v0.4.0` below,
with `v0.4.2` in place of `v0.4.0` in the asset names.

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
