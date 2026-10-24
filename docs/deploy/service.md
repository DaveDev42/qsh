# Running qsh as a service

`qsh serve`, `qsh listen`, and `qsh serve --to` (old spelling `qsh reverse`,
`docs/CLI.md` §6.13) are foreground-only (`docs/CLI.md` §6.12/§6.13/§6.18);
qsh does not daemonize itself. Keeping one of them running across logout,
reboot, or a crash is the OS service manager's job. `qsh service
install|uninstall|status` (`docs/CLI.md` §6.18) generates a unit for this
machine's inferred run mode, and on macOS and Linux, with `--activate`,
`--deactivate` and `--live`, also loads, releases and checks it through the
service manager. On Windows the unit is a Task Scheduler task definition file
that you register yourself (see Task Scheduler below). The `xml` and `ini`
fences on this page are exactly what it writes, byte for byte, not merely
illustrative examples, and the launchd and systemd commands in the recipes
below are exactly the ones the flags run. The `plist` fences (the LaunchDaemon
and the supervised tunnel) and the always-on Task Scheduler variant are
recipes you install yourself; `qsh` does not write them.

Without a flag, `qsh service` writes and removes the unit file and never
calls `launchctl` or `systemctl`. The flags are the only way it does, and no
config key or environment variable turns them on:

| Command | What it adds to the unit file operation |
|---|---|
| `qsh service install --activate` | Loads and starts the unit as the last step. A unit that is already running is **not** restarted, so a new binary path applies at the next restart. |
| `qsh service uninstall --deactivate` | Releases the unit from the manager first, then removes the file. If the release fails the file stays. Without the flag a running unit keeps running. |
| `qsh service status --live` | Reports whether the unit is running, from one exit code of the manager. |

On Windows the flags drive `schtasks` and the Task Scheduler COM API instead
of a unit manager: `--activate` runs `schtasks /Create /F` (and `/Run` when
the task is not already running), `--deactivate` runs `/End` for a running
task and then `/Delete /F`, and `--live` reads the task state through COM.
The commands are the ones under "Register, check, stop" below. Without the
flags `qsh service` registers nothing.

`qsh service` never restarts a unit. A restart ends every detached session
(Notes for both below), so it stays a decision for a person.

The examples below assume the binary is at `~/.local/bin/qsh`, the default
install path (see [Install](../../README.md#install)). Substitute your own
path if you built elsewhere; `qsh service install` fills in the binary's
actual, currently running path for you.

`qsh service install` also creates the unit's parent directory
(`~/Library/LaunchAgents` on macOS, `~/.config/systemd/user` on Linux,
`%USERPROFILE%\.config\qsh\service` on Windows) and, on macOS,
`~/Library/Logs/qsh`, when they are missing, but never changes the mode of a
directory that already exists. The unit file itself is written 0600 regardless
of manager (on Windows an owner-only DACL).

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

Load and check one, which is what `qsh service install --activate` and
`qsh service status --live` run (`install` has already made the log
directory):

```bash
mkdir -p ~/Library/Logs/qsh
launchctl print gui/$UID/io.qsh.serve
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/io.qsh.serve.plist
```

`launchctl print` exits 0 when the label is loaded. `--activate` runs it
first and skips `bootstrap` when it is, because `launchctl bootstrap` fails
on a label that is already loaded and a reload would end detached sessions.
The `gui/$UID` domain exists only inside a logged-in GUI session: over SSH
alone `bootstrap` fails, and `qsh service install --activate` reports that
failure instead of falling back to the `user/$UID` domain.

Release one, which is what `qsh service uninstall --deactivate` runs when
`launchctl print` says the label is loaded:

```bash
launchctl bootout gui/$UID/io.qsh.serve
rm ~/Library/LaunchAgents/io.qsh.serve.plist
```

`launchctl print` shows the last exit status and PID; the plist's own
`StandardOutPath`/`StandardErrorPath` files hold everything qsh itself
wrote to stderr (`docs/CLI.md` says stdout stays empty outside `--json`
commands, and none of these three modes are JSON commands).

A LaunchAgent runs only inside a login session: it starts when you log in
and stops when you log out, same as any other per-user agent. `linger`
(below) is a systemd concept with no launchd equivalent. On macOS, a service
that must run with nobody logged in is a LaunchDaemon, and the next section
is the recipe for it.

### Always-on: a LaunchDaemon you install as root

A LaunchDaemon lives in `/Library/LaunchDaemons`, is owned by root and is
loaded into the `system` domain. `qsh` never writes that directory, never
loads the file and never runs `sudo`. You install it by hand, once, with the
commands below. After that `qsh` only looks for the file: `qsh service
install --activate` and `qsh service uninstall --deactivate` leave the
daemon alone and report `always_on_present`, and `qsh doctor` counts the
file as a registered unit (it checks that the file exists and does not call
`launchctl`).

The daemon uses the same label as the LaunchAgent, `io.qsh.<mode>`. Never
load both at once, because both would try to bind the same port. The steps
below take the LaunchAgent down first.

`/Library/LaunchDaemons/io.qsh.serve.plist`:

```plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.qsh.serve</string>
  <key>UserName</key>
  <string>YOU</string>
  <key>GroupName</key>
  <string>staff</string>
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

This is the LaunchAgent's plist for the same mode with two keys added.
`UserName` (your account) and `GroupName` (`staff`) make the daemon run as
you instead of root, so it reads your `~/.config/qsh`. A LaunchDaemon gets no
`HOME` of its own, which is why the `HOME` entry in `EnvironmentVariables`
matters. For `listen` and `reverse`, take `Label`, `ProgramArguments` and the
log file names from the LaunchAgent fence of that mode above and keep the
three other additions. Write the file somewhere you can read it, for
example the current directory, because the first command below removes the
LaunchAgent copy.

If `qsh identity` keeps the device key in the OS credential store
(`key_store = "platform"` in `identity/identity.toml`), run `qsh identity
move-key --to file` first. The Keychain belongs to a login session, so a
daemon started at boot cannot be sure to read the key from it. `qsh doctor`
reports this as `keystore_session_bound`. The move keeps the device id,
certificate and fingerprint, so peers' pins and ACL rows stay valid.

Install it:

```bash
qsh service uninstall --deactivate
sudo cp io.qsh.serve.plist /Library/LaunchDaemons/io.qsh.serve.plist
sudo chown root:wheel /Library/LaunchDaemons/io.qsh.serve.plist
sudo chmod 644 /Library/LaunchDaemons/io.qsh.serve.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.qsh.serve.plist
```

Check that it is loaded. `qsh service status --live` runs the same query
without root: exit 0 reads as active, exit 113 (not loaded) as not active,
and any other exit status is an error that names this command. To ask
`launchctl` yourself:

```bash
sudo launchctl print system/io.qsh.serve
```

Remove it:

```bash
sudo launchctl bootout system/io.qsh.serve
sudo rm /Library/LaunchDaemons/io.qsh.serve.plist
```

If you move the `qsh` binary, edit the path in `ProgramArguments`, then run
`bootout` and `bootstrap` again. The daemon does not pick up a new binary any
other way, and `qsh service install` does not rewrite this file. That restart
ends every detached session on the listener (see Notes for both below), so
detach first only if you can lose the shell.

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

Enable and check one, which is what `qsh service install --activate` and
`qsh service status --live` run:

```bash
systemctl --user is-active qsh-serve.service
systemctl --user daemon-reload
systemctl --user enable --now qsh-serve.service
systemctl --user status qsh-serve.service
journalctl --user -u qsh-serve -f
```

`is-active` exits 0 for a running unit. `enable --now` leaves a running unit
alone, so `--activate` on one reports `already_active` and the new binary path
applies at the next restart.

Release one, which is what `qsh service uninstall --deactivate` runs whenever
the unit file exists, running or not:

```bash
systemctl --user disable --now qsh-serve.service
rm ~/.config/systemd/user/qsh-serve.service
```

A user unit stops when your last session ends unless you enable linger,
which lets systemd start and keep your user units running without any
session open (from boot, if `WantedBy=default.target` and the unit is
enabled):

```bash
loginctl enable-linger $USER
```

If `qsh identity` keeps the device key in the OS credential store
(`key_store = "platform"` in `identity/identity.toml`), run `qsh identity
move-key --to file` before you rely on linger. The Secret Service belongs to
a login session, so a unit started at boot cannot be sure to read the key
from it. `qsh doctor` reports this as `keystore_session_bound` once linger is
on and the unit is registered. The move keeps the device id, certificate and
fingerprint, so peers' pins and ACL rows stay valid.

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

`qsh service install --activate` hits the same wall. If `systemctl` is not
found it ends with `UNSUPPORTED`, and if it is found but cannot reach the
manager it ends with `INTERNAL`. Both messages name `/etc/wsl.conf` under WSL.
The unit file is still written, so run the command again once systemd is up.

## Task Scheduler (Windows)

`qsh service install` writes one task definition per run mode to
`%USERPROFILE%\.config\qsh\service\qsh-<mode>.task.xml` (`<config_dir>\service`),
with an owner-only DACL. `qsh service status` reports whether that file
exists, and `qsh service uninstall` deletes it. Without a flag none of the
three starts `schtasks`, registers anything or reads the scheduler. Registering
the task is either `qsh service install --activate` or the recipe below, run by
you. The task name is `\qsh\qsh-<mode>`.

The file is UTF-16 little-endian with a byte order mark, and the XML says
`encoding="UTF-16"`. That is the one encoding `schtasks /Create /XML` accepted
when it was tried (see Measured below). The `<UserId>` elements hold the SID of
the user who ran `qsh service install`, so the file does not depend on how the
account name is spelled or localized. The fences show an example SID and
binary path.

The task does not run `qsh serve` directly. A console program started by the
Task Scheduler gets a console window and nowhere to put its output, and the
task definition has no field for a log path. The action is `qsh service run
<mode>`, a hidden subcommand that detaches from the console, appends stdout to
`%USERPROFILE%\.local\state\qsh\log\<mode>.out.log` and stderr to
`<mode>.err.log` (each created with an owner-only DACL), and then runs exactly
what `qsh serve`, `qsh listen` or `qsh serve --to` runs. The `listening on`
line and every error land in the `.err.log`. `qsh service run` does the same
redirection on macOS and Linux, but their units do not call it.

`%USERPROFILE%\.config\qsh\service\qsh-serve.task.xml`:

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>qsh serve</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\YOU\.local\bin\qsh.exe</Command>
      <Arguments>service run serve</Arguments>
    </Exec>
  </Actions>
</Task>
```

`%USERPROFILE%\.config\qsh\service\qsh-listen.task.xml`:

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>qsh listen</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\YOU\.local\bin\qsh.exe</Command>
      <Arguments>service run listen</Arguments>
    </Exec>
  </Actions>
</Task>
```

`%USERPROFILE%\.config\qsh\service\qsh-reverse.task.xml` — file name and task
name still say `reverse`, but the action runs `qsh serve --to controller`
(the controller literal is frozen into `Arguments` at install time and
quoted for the command line when it holds whitespace):

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>qsh serve --to</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\YOU\.local\bin\qsh.exe</Command>
      <Arguments>service run reverse controller</Arguments>
    </Exec>
  </Actions>
</Task>
```

What each setting is for:

| Setting | Why |
|---|---|
| `LogonTrigger` for the installing user, with a `Repetition` of `PT1M` and no duration | Starts the task at logon and again every minute. See Measured: this is what restarts a process that died. |
| `MultipleInstancesPolicy` `IgnoreNew` | A repetition tick that finds the process still running does nothing, so there is one process and a restart within a minute of a death. |
| `Principal` `InteractiveToken`, `RunLevel` `LeastPrivilege` | Runs as you, only while you are logged on, with your normal token. No password is stored and no elevation is asked for. |
| `ExecutionTimeLimit` `PT0S` | The scheduler's default of 72 hours would end a long-running host. |
| `DisallowStartIfOnBatteries` and `StopIfGoingOnBatteries` `false` | A laptop on battery keeps the host. |
| `RestartOnFailure` `PT1M`, `Count` 999 | Kept as a second line of defence, but it did not restart anything in the measurements below. The repetition does the work. |

### Register, check, stop

`qsh service install` stops after writing the file. Register it as the user
the file names, from a normal (not elevated) prompt:

```powershell
schtasks /Create /F /TN \qsh\qsh-serve /XML "$env:USERPROFILE\.config\qsh\service\qsh-serve.task.xml"
schtasks /Query /TN \qsh\qsh-serve
```

`/F` replaces an existing task of that name. It does not stop an instance that
is running (Measured below), so a new binary path applies at the next start.
The task starts at your next logon; to start it now, log off and on, or run
`schtasks /Run /TN \qsh\qsh-serve`. Registering a task with this definition
needed no elevation. `qsh service install --activate` runs the `/Create` line
and then the `/Run` line, and skips `/Run` when the task is already running.
The task is an `InteractiveToken` task, so it starts only in a logged-on
interactive session. Over an ssh login with no desktop session, `/Run` ends
non-zero and `--activate` ends with `INTERNAL`; the definition is registered
anyway.

Stop and remove it:

```powershell
schtasks /End /TN \qsh\qsh-serve
schtasks /Delete /F /TN \qsh\qsh-serve
```

`/End` stops the running process, and the repetition starts it again at the
next minute. `/Delete /F` is the way to stop it for good. `qsh service
uninstall --deactivate` runs `/End` (only when the task is running) and then
`/Delete /F`, and removes the file after both succeed. Plain `qsh service
uninstall` deletes only the file; it does not touch a registered task, so run
`/Delete` first.

`qsh service status --live` does not run `schtasks`: `schtasks /Query` exits 0
for any registered task and puts the state only in localized text. It reads the
task state from the Task Scheduler COM API, as `qsh doctor` does.

`qsh doctor` reads the file, not the scheduler, for these two: it reports
`service_not_registered` (info) when the file is absent, and
`service_restart_drops_sessions` (info) when it is present, for `serve` and
`reverse`. The notice means that `/End` or a restart ends the PTY sessions and
connections the host holds, as on the other platforms (Notes for both below).
`qsh setup host --service` and `qsh setup host --to --service` write the same
task definition files (`qsh-serve.task.xml`, `qsh-reverse.task.xml`) and
register nothing.

### Always-on: a task that runs with nobody logged on

The default task is an `InteractiveToken` task: it exists only while you are
logged on. It starts at logon and ends at logoff, like a macOS LaunchAgent
(`qsh doctor` says so as `logon_task_session_scoped`, a warning, once the
scheduler reports the task registered with that principal). To keep a host
running at boot with nobody logged on, register a variant yourself. `qsh` does
not register it for you and has no flag that does.

Copy `qsh-serve.task.xml` to `qsh-serve.always-on.xml` next to it and make two
changes: replace the `LogonTrigger` element with a `BootTrigger`, which has no
`UserId`, and set the principal's `LogonType` to `Password`. Save the copy as
UTF-16 with a byte order mark, as the original is (in Windows PowerShell,
`Get-Content` the original and pipe it to `Set-Content -Encoding Unicode`
after editing). The result:

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>qsh serve</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\YOU\.local\bin\qsh.exe</Command>
      <Arguments>service run serve</Arguments>
    </Exec>
  </Actions>
</Task>
```

Register it from an **elevated** prompt, naming the account and letting
`schtasks` ask for its password, so the password never lands in your shell
history or in this file:

```powershell
schtasks /Create /F /TN \qsh\qsh-serve /XML "$env:USERPROFILE\.config\qsh\service\qsh-serve.always-on.xml" /RU DOMAIN\you /RP *
```

Replace `DOMAIN\you` with the account (`COMPUTER\you` for a local account).
Without the password the registration fails: a `LogonType` of `Password` with
no password gave `ERROR: The user name or password is incorrect.` The
Task Scheduler keeps the password it was registered with. When the account's
password changes, the task cannot start at the next trigger until you run the
same `schtasks /Create /F ... /RP *` again, and a task that fails this way
fails silently from qsh's point of view. Re-register after every password
change.

The `qsh doctor` warning `logon_task_session_scoped` is silent for this task,
because the scheduler reports a `Password` principal.

`qsh service install --activate` leaves a task like this alone. When the
scheduler reports a `Password` principal for `\qsh\qsh-serve`, the command
writes the file, runs no `schtasks` command, and answers `activation:
always_on_present`: `/Create /F` would replace the definition with the default
one. `qsh service uninstall --deactivate` likewise only removes the file
(`deactivation: always_on_present`). To remove an always-on task, run the
`/End` and `/Delete /F` lines above from an elevated prompt. `qsh service
status --live` reports whether that task is running.

A `Password` task reads the `platform` key store (Windows Credential Manager)
without an interactive session. This was measured on Windows 11 25H2 (build
26200) with a local standard user whose identity was created in an interactive
logon: a task registered for that user with a `Password` principal, started
while the user had no session, ran `qsh serve`, loaded the key and printed the
same fingerprint, and `qsh doctor` and `qsh identity export` agreed. So `qsh
doctor` does not report `keystore_session_bound` on Windows, and moving the key
is not required. `qsh identity move-key --to file` remains available if you
prefer the key in the owner-only key file.

The account needs the "Log on as a batch job" right (`SeBatchLogonRight`) for a
`Password` task. Administrators have it. A standard local user does not, and
without it the task fails with `0x80070569` before qsh runs, so no qsh
message or `qsh doctor` finding explains it. Grant the right in Local Security
Policy (Local Policies, User Rights Assignment) before registering the task.

The always-on variant was not run during the measurements below: a
`BootTrigger` cannot be registered without elevation, and the stored password
is yours to supply. The file is the default task with the two changes above
and nothing else, and `crates/qsh-core/tests/it/service_docs.rs` keeps it
that way.

### Measured

These were measured on Windows 11 (build 26100) as a standard, non-elevated
user, with throwaway tasks in a folder of their own that was deleted
afterwards. No password was typed or stored.

| Question | Result |
|---|---|
| Does `RestartOnFailure` start the action again after it exits non-zero? | No. A task that exited with code 3 and one that crashed with `FailFast` (exit code `0xE0434352`), each with `RestartOnFailure` `PT1M` and `Count` 3, were started once and never again over 4 minutes. |
| Does a `Repetition` of `PT1M` with no `Duration`, plus `IgnoreNew`, start a dead task again? | Yes. A 5 second task that exits with 3 started at 22:42:33, 22:43:34, 22:44:34 and 22:45:34. For a 100 second task the tick at 60 seconds was ignored and the next start was at 121 seconds, so there was never a second copy. |
| Does a `LogonTrigger` with a `Repetition` register, and does the scheduler report it back? | Yes, with no elevation. Read back through the COM API, `Repetition.Interval` was `PT1M`. |
| Does `/Create /F` on a running task stop or restart it? | No. With a task running a `ping` action, `/Create /F` with a changed description left the same process (same PID, state Running) and the scheduler held the new description. `qsh service install --activate` therefore runs `/Create` only, and answers `already_active`. |
| Can a standard user register a `BootTrigger` task? | No. With an `InteractiveToken`, a `Password` and an `S4U` principal alike, `schtasks /Create` answered `ERROR: Access is denied.` The always-on variant needs an elevated prompt. |
| Can a standard user register a `LogonType` of `Password` task? | Not without the password: `ERROR: The user name or password is incorrect.` |
| Which encodings does `schtasks /Create /XML` accept? | UTF-16 little-endian with a byte order mark and `encoding="UTF-16"`. UTF-8 with the declaration, and UTF-8 with a byte order mark, were both rejected as `task XML is malformed`. |

### A supervised tunnel as a task

A tunnel task runs `qsh tunnel open` itself, not `qsh service run`, so nothing
collects its output unless you wrap it. Take the default task file and replace
its `Exec` element, wrapping the command in `cmd.exe` so stdout (the
`tunnel.open` envelope) and stderr (the `qsh::lifecycle` and
`qsh::tunnel::supervise` lines) go to a file:

```xml
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c ""C:\Users\YOU\.local\bin\qsh.exe" tunnel open hub --dynamic 1080 --supervise 300000 &gt;&gt; "C:\Users\YOU\.local\state\qsh\tunnel-hub.log" 2&gt;&amp;1"</Arguments>
    </Exec>
```

Change `Description` to say what the task is, save the file under another
name, and register it under another task name (`\qsh\qsh-tunnel-hub`). The
host alias `hub`, the port `1080`, the budget and the paths are yours. The
repetition restarts the process after a total outage past `--supervise`
(`gave_up`, exit `255`) and after a failed first `open`, and `IgnoreNew` keeps
the supervised process from being doubled. The console window of this task
stays open on screen. The doubled quote after `/c` is what `cmd.exe` strips,
and it keeps a path with spaces working; the form was run as a task with a
harmless executable in a directory whose name contains spaces.

## Supervised tunnels

`qsh tunnel open` holds its tunnel only as long as the foreground process lives (`docs/CLI.md` §6.14). With `--supervise <ms>` the process re-establishes a lost `--local`, `--dynamic` or `--remote` tunnel by itself, over a forward or a reverse route, and gives up with exit `255` once the total outage passes `<ms>` (`docs/CLI.md` §6.9, ADR-0023). A `--local` or `--dynamic` listener stays bound across the loss. The service manager covers what the supervisor deliberately does not: a first `open` that fails (nothing is supervised before the tunnel exists), an exhausted budget, and a crash. Together they leave no outer retry loop to write.

`qsh service install` does not generate these units. It manages the `serve`, `listen`, and `serve --to` modes only, and no test compares the fences below against generated output. They are hand-written examples, so the path, the host alias `hub`, the port `1080`, and the budget are yours to change. The fences use `plist` and `systemd` tags on purpose, so they stay outside the byte-for-byte check on the `xml` and `ini` fences above.

Both examples run `qsh tunnel open hub --dynamic 1080 --supervise 300000`. The budget is five minutes of total outage, not counting the time the machine was asleep. The tunnel process writes the `tunnel.open` envelope to stdout once and the `qsh::lifecycle` and `qsh::tunnel::supervise` lines to stderr, which the log paths below collect (`docs/CLI.md` §6.14).

`~/Library/LaunchAgents/io.qsh.tunnel-hub.plist`:

```plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.qsh.tunnel-hub</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/qsh</string>
    <string>tunnel</string>
    <string>open</string>
    <string>hub</string>
    <string>--dynamic</string>
    <string>1080</string>
    <string>--supervise</string>
    <string>300000</string>
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
  <string>/Users/YOU/Library/Logs/qsh/tunnel-hub.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/Library/Logs/qsh/tunnel-hub.err.log</string>
</dict>
</plist>
```

`~/.config/systemd/user/qsh-tunnel-hub.service`:

```systemd
[Unit]
Description=qsh tunnel open hub --dynamic 1080 --supervise

[Service]
ExecStart=/home/YOU/.local/bin/qsh tunnel open hub --dynamic 1080 --supervise 300000
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

Load and enable them the same way as the units above, with the new label or unit name.

What each side restarts:

| Situation | Who acts | Result |
|---|---|---|
| Connection lost (sleep, VPN or underlay switch, peer restart) | the supervisor inside the process | Same listener, same `tunnel_id` (a `--remote` tunnel gets a new one); `lost`, `retry`, `reestablished` lines on stderr |
| Total outage past `--supervise` | the process, then the service manager | `gave_up` line, exit `255`, a fresh `open` after `ThrottleInterval` or `RestartSec` |
| First `open` fails (host unreachable, no ACL yet, reverse registration stale) | the service manager | Exit `255` and a retry. Add `--wait <ms>` for a stale reverse registration (`docs/CLI.md` §6.9) |
| `SIGTERM` from `launchctl bootout` or `systemctl stop` | the supervisor | Listener released, exit `0` |

A restart by the service manager opens a new tunnel, so every TCP connection that went through the old one is gone. Only the supervisor keeps a listener across a loss, and only for the forms `docs/CLI.md` §6.9 lists as supported. Any other form answers `UNSUPPORTED` with `--supervise` and relies on the service manager alone. `--supervise` does not retry a peer that rejects the pinned fingerprint or a policy that denies the request: both end the process with `AUTH_FAILED` or `PERMISSION_DENIED`, and the service manager then retries to the same result every few seconds. Fix the pin or `acl.toml` instead of widening the restart interval.

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
the shell. `qsh doctor` reports this as `service_restart_drops_sessions`
(info) whenever a unit is registered for `serve` or `reverse`, and
`qsh sessions` lists what a restart would end.

A client that was attached when the listener restarted does not have to
wait for the 45 s idle timeout to find out. `serve` and `listen` keep a
stateless reset key in `stateless_reset.key` next to `config.toml`, so the
restarted process answers the client's first packet with a QUIC stateless
reset and the client knows the session is gone within one round trip
(ADR-0036, `docs/CLI.md` §6.12). The session is still lost; only the
detection is faster. This holds while the key file is intact. If it is
unreadable or malformed, the process starts on a temporary key, prints one
line to its log, and leaves the file as it was, so detection falls back to
the slower path until you fix or delete the file. Deleting the file and
restarting makes a new key, and that one restart is also slow to detect.

The unit's `ExecStart`/`ProgramArguments` line is the whole invocation.
qsh itself never re-execs, backgrounds, or reparents; it stays in the
foreground for as long as the process lives, and the service manager owns
restart, logging redirection, and stop signals from outside.

`qsh service install|uninstall|status` (`docs/CLI.md` §6.18) generates and
registers, removes, and reports on the units above. `service install` never
writes `acl.toml` (`docs/adr/0017-acl-toml-not-written.md` 결정 1), so you
still grant the peers you expect their actions there. Hand-writing a unit
from the fences above is a working fallback: `qsh service install` manages
only the platforms and paths this page documents and writes exactly these
files, so the two paths never disagree.
