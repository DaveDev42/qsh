# Running qsh as a service

`qsh serve`, `qsh listen`, and `qsh reverse` are foreground-only (`docs/CLI.md`
§6.12/§6.13); qsh does not daemonize itself. Keeping one of them running
across logout, reboot, or a crash is the OS service manager's job. This page
gives a working unit for each of the three modes on launchd (macOS) and
systemd (Linux), plus the constraints that trip people up.

The examples assume the binary is at `~/.local/bin/qsh`, the default
install path (see [Install](../../README.md#install)). Substitute your own
path if you built elsewhere.

## launchd (macOS)

Each mode gets its own plist at `~/Library/LaunchAgents/io.qsh.<mode>.plist`.

`~/Library/LaunchAgents/io.qsh.serve.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.qsh.serve</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/qsh</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/YOU/Library/Logs/qsh/serve.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/Library/Logs/qsh/serve.err.log</string>
</dict>
</plist>
```

`~/Library/LaunchAgents/io.qsh.listen.plist` is the same shape with
`serve` replaced by `listen` throughout (label `io.qsh.listen`, argument
`listen`, logs `listen.out.log`/`listen.err.log`).

`~/Library/LaunchAgents/io.qsh.reverse.plist` adds the controller argument:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.qsh.reverse</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/qsh</string>
    <string>reverse</string>
    <string>controller</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/YOU/Library/Logs/qsh/reverse.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/Library/Logs/qsh/reverse.err.log</string>
</dict>
</plist>
```

`controller` here is a `trust.toml`/`hosts.toml` alias, the same name you'd
pass to `qsh reverse <controller>` by hand (`docs/CLI.md` §6.13), not a
literal string to copy.

Load and check one:

```bash
mkdir -p ~/Library/Logs/qsh
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/io.qsh.serve.plist
launchctl print gui/$UID/io.qsh.serve
```

`launchctl print` shows the last exit status and PID; the plist's own
`StandardOutPath`/`StandardErrorPath` files hold everything qsh itself
wrote to stderr (`docs/CLI.md` says stdout stays empty outside `--json`
commands, and none of these three modes are JSON commands).

A LaunchAgent runs only inside a login session: it starts when you log in
and stops when you log out, same as any other per-user agent. `linger`
(below) is a systemd concept with no launchd equivalent: on macOS, a
service that must run with nobody logged in is a LaunchDaemon
(`/Library/LaunchDaemons`, root-owned, loaded by `launchctl` as root), not
a LaunchAgent. That's a different lifecycle and permission model, and out
of scope for this page, which only covers the LaunchAgent path a normal
user account can set up without `sudo`.

## systemd (Linux, user units)

Each mode gets its own unit at `~/.config/systemd/user/qsh-<mode>.service`.

`~/.config/systemd/user/qsh-serve.service`:

```ini
[Unit]
Description=qsh serve

[Service]
ExecStart=%h/.local/bin/qsh serve
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

`qsh-listen.service` is the same with `serve` replaced by `listen`.
`qsh-reverse.service` fixes the controller argument in `ExecStart`:

```ini
[Unit]
Description=qsh reverse

[Service]
ExecStart=%h/.local/bin/qsh reverse controller
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

Enable and check one:

```bash
systemctl --user daemon-reload
systemctl --user enable --now qsh-serve.service
systemctl --user status qsh-serve.service
journalctl --user -u qsh-serve -f
```

A user unit stops when your last session ends unless you enable linger,
which lets systemd start and keep your user units running without any
session open (from boot, if `WantedBy=default.target` and the unit is
enabled):

```bash
loginctl enable-linger $USER
```

### WSL

`systemctl --user` only works inside WSL if systemd is running as PID 1 for
that distro, which is not the WSL default. Enable it in `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

then restart the distro (`wsl --shutdown` from Windows, then reopen it).
Without this, `systemctl` fails with a socket-connect error and the unit
above never starts.

## Notes for both

`Restart=always` (systemd) and `KeepAlive` (launchd) restart the process
after a crash, but neither retries a bad argument or a missing
`acl.toml` into working state. Both `serve` and `listen`/`reverse` read
`acl.toml` once at startup and deny everything if it's missing or invalid
(`docs/CLI.md` §6.12/§6.13), so a unit that keeps bouncing is usually a
config problem, not a supervisor problem. Check the log path first.

Every restart, whether the supervisor bounced a crashed process or you
asked for one, also ends every detached session on that listener. A
session lives only as long as the `serve` or `listen`/`reverse` process
that opened it, so a service-manager restart is not a resume point (README,
Known limitations). Detach before restarting only if you are fine losing
the shell.

The unit's `ExecStart`/`ProgramArguments` line is the whole invocation.
qsh itself never re-execs, backgrounds, or reparents; it stays in the
foreground for as long as the process lives, and the service manager owns
restart, logging redirection, and stop signals from outside.

`qsh service install` is planned for M9 to generate and register units
like the ones above instead of you writing them by hand; `qsh reverse` is
also expected to be renamed to `qsh serve --to` in M9. Both are forward
notes, not current behavior. This page describes the CLI as it exists
today.
