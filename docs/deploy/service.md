# Running qsh as a service

`qsh serve`, `qsh listen`, and `qsh serve --to` (old spelling `qsh reverse`,
`docs/CLI.md` §6.13) are foreground-only (`docs/CLI.md` §6.12/§6.13/§6.18);
qsh does not daemonize itself. Keeping one of them running across logout,
reboot, or a crash is the OS service manager's job. `qsh service
install|uninstall|status` (`docs/CLI.md` §6.18) generates and registers a
unit for this machine's inferred run mode; the fences on this page are
exactly what it writes, byte for byte, not merely illustrative examples.

The examples below assume the binary is at `~/.local/bin/qsh`, the default
install path (see [Install](../../README.md#install)). Substitute your own
path if you built elsewhere; `qsh service install` fills in the binary's
actual, currently running path for you.

`qsh service install` also creates the unit's parent directory
(`~/Library/LaunchAgents` on macOS, `~/.config/systemd/user` on Linux) and,
on macOS, `~/Library/Logs/qsh`, when they are missing, but never changes the
mode of a directory that already exists. The unit file itself is written
0600 regardless of manager.

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
  <key>ThrottleInterval</key>
  <integer>15</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/YOU</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>/Users/YOU/Library/Logs/qsh/serve.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/Library/Logs/qsh/serve.err.log</string>
</dict>
</plist>
```

`~/Library/LaunchAgents/io.qsh.listen.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.qsh.listen</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/qsh</string>
    <string>listen</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>15</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/YOU</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>/Users/YOU/Library/Logs/qsh/listen.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/Library/Logs/qsh/listen.err.log</string>
</dict>
</plist>
```

`~/Library/LaunchAgents/io.qsh.reverse.plist` — file name and `Label` still
say `reverse`, but `ProgramArguments` runs `qsh serve --to <controller>`, not
the hidden `qsh reverse` alias (`docs/CLI.md` §6.13, §6.18):

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
    <string>serve</string>
    <string>--to</string>
    <string>controller</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>15</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/YOU</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>/Users/YOU/Library/Logs/qsh/reverse.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/Library/Logs/qsh/reverse.err.log</string>
</dict>
</plist>
```

`controller` here is a `trust.toml`/`hosts.toml` alias, the same name you'd
pass to `qsh serve --to <controller>` by hand (`docs/CLI.md` §6.13), not a
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
ExecStart=/home/YOU/.local/bin/qsh serve
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

`~/.config/systemd/user/qsh-listen.service`:

```ini
[Unit]
Description=qsh listen

[Service]
ExecStart=/home/YOU/.local/bin/qsh listen
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

`~/.config/systemd/user/qsh-reverse.service` — file name still says
`reverse`, but `ExecStart` runs `qsh serve --to controller`, not the hidden
`qsh reverse` alias (`docs/CLI.md` §6.13, §6.18):

```ini
[Unit]
Description=qsh serve --to

[Service]
ExecStart=/home/YOU/.local/bin/qsh serve --to controller
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
`acl.toml` into working state. Both `serve` and `listen`/`serve --to` read
`acl.toml` once at startup and deny everything if it's missing or invalid
(`docs/CLI.md` §6.12/§6.13), so a unit that keeps bouncing is usually a
config problem, not a supervisor problem. Check the log path first.

Every restart, whether the supervisor bounced a crashed process or you
asked for one, also ends every detached session on that listener. A
session lives only as long as the `serve` or `listen`/`serve --to` process
that opened it, so a service-manager restart is not a resume point (README,
Known limitations). Detach before restarting only if you are fine losing
the shell.

The unit's `ExecStart`/`ProgramArguments` line is the whole invocation.
qsh itself never re-execs, backgrounds, or reparents; it stays in the
foreground for as long as the process lives, and the service manager owns
restart, logging redirection, and stop signals from outside.

`qsh service install|uninstall|status` (`docs/CLI.md` §6.18) generates and
registers, removes, and reports on the units above so you no longer have to
write them by hand. `service install` never writes `acl.toml`
(`docs/adr/0017-acl-toml-not-written.md` 결정 1) — you still need to grant the
peer(s) you expect an action there once the unit is running. Hand-writing a
unit from the fences above remains a working fallback: `qsh service install`
only manages the platforms and paths this page documents, and it writes
exactly these files, so the two paths never disagree.
