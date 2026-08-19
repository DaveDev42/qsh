//! L5 expect harness: **the client itself runs under a pty**, so the
//! termios path really executes (`docs/design/testing.md` L5).
//!
//! This is the only place where `qsh`'s raw mode, `SIGWINCH` forwarding,
//! escape sequences and terminal restore are exercised end to end. Every
//! test drives a real `qsh serve` on the same machine, so "the remote" and
//! "the runner" share a filesystem — which is what lets the `vim` case
//! assert on the *file* rather than on screen paint.
//!
//! ## The named acceptance set (`docs/ROADMAP.md` M2, `PLAN.md` Step 6)
//!
//! bash/zsh prompt round trip, `vim` open-edit-quit, `tmux` with resize
//! propagation, and `claude` starting. Each one is skipped with a message
//! when the binary is absent (a bare runner must stay green) and *fails*
//! when the binary is there and the interaction breaks. Terminal quirks
//! outside this set are backlog, not M2.
//!
//! Those four are launched by absolute path on purpose: a session's `PATH`
//! is the host's pinned baseline (`docs/design/architecture.md` §4), not
//! the test runner's, so a package manager's prefix would otherwise be
//! unreachable from inside a session.
//!
//! Nothing here sleeps for correctness. Waiting is either a real round
//! trip under [`EXPECT_TIMEOUT`] or a bounded retry loop for the one
//! genuinely unordered case (a resize and the keystroke after it travel on
//! different threads — [`Client::expect_size`]).

#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use common::{Fleet, HOST_ALIAS, Sandbox};
use expectrl::process::unix::{Signal, WaitStatus};
use expectrl::session::OsSession;
use expectrl::{Eof, Expect as _, Regex, Session};
use nix::sys::termios::{self, LocalFlags};
use serde_json::Value;
use std::os::fd::AsFd as _;

/// How long any single `expect` waits. Generous on purpose: a cold `vim`
/// or `tmux` start on a loaded runner is slow, and the failure worth
/// reporting is "never arrived", not "arrived late".
const EXPECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The size `ptyprocess` gives every pty it opens, so this is the size the
/// client adopts at startup.
const START_SIZE: (u16, u16) = (80, 24);

/// The size the resize cases switch to (cols, rows).
const NEW_SIZE: (u16, u16) = (120, 40);

/// Bound on the resize retry loop.
const RESIZE_DEADLINE: Duration = Duration::from_secs(30);

/// A `qsh` client running under its own pty.
struct Client {
    session: OsSession,
}

impl Client {
    /// Spawn `qsh <args>` under a pty, with the sandbox's directories and
    /// a `TERM` a full-screen program will accept.
    fn spawn(sandbox: &Sandbox, args: &[&str]) -> Self {
        Self::spawn_with(sandbox.command(args))
    }

    /// Spawn a prepared command under a pty.
    fn spawn_with(mut command: Command) -> Self {
        command.env("TERM", "xterm-256color");
        let mut session = Session::spawn(command).expect("spawn qsh under a pty");
        session.set_expect_timeout(Some(EXPECT_TIMEOUT));
        Self { session }
    }

    /// Wait for `needle`, or fail naming what never arrived.
    fn expect(&mut self, needle: &str) {
        if let Err(err) = self.session.expect(needle) {
            panic!("waiting for {needle:?}: {err}");
        }
    }

    /// Wait for a regular expression and return what matched.
    fn expect_regex(&mut self, pattern: &str) -> String {
        match self.session.expect(Regex(pattern)) {
            Ok(found) => String::from_utf8_lossy(found.get(0).unwrap_or_default()).into_owned(),
            Err(err) => panic!("waiting for /{pattern}/: {err}"),
        }
    }

    /// Type bytes at the client verbatim. Enter is CR, exactly what a
    /// terminal sends and what the escape machine treats as a line end.
    fn type_(&mut self, keys: &str) {
        self.session.send(keys).expect("send to the client's pty");
    }

    /// Run `echo` in the attached shell and wait for its output. The
    /// marker is split by an empty quote so the *echo of the typed line*
    /// cannot satisfy the expectation — only the shell's own output can.
    fn round_trip(&mut self, marker: &str) {
        self.type_(&format!("echo {marker}''-OK\r"));
        self.expect(&format!("{marker}-OK"));
    }

    /// Change the local window size, the way a terminal emulator does.
    fn resize(&mut self, (cols, rows): (u16, u16)) {
        self.session
            .get_process_mut()
            .set_window_size(cols, rows)
            .expect("TIOCSWINSZ on the local pty");
    }

    /// Ask the remote shell for its terminal size until it reports
    /// `(cols, rows)`, or fail after [`RESIZE_DEADLINE`].
    ///
    /// The retry is not a sleep-for-correctness: a `SIGWINCH` is handled on
    /// the client's signal thread while the keystroke after it travels on
    /// the input thread, so the two are genuinely unordered and the only
    /// honest assertion is "the size converges, promptly".
    fn expect_size(&mut self, probe: &str, (cols, rows): (u16, u16)) {
        let want = format!("SIZE={cols}x{rows}");
        let deadline = Instant::now() + RESIZE_DEADLINE;
        let mut last = String::new();
        while Instant::now() < deadline {
            self.type_(&format!("{probe}\r"));
            last = self.expect_regex(r"SIZE=\d+x\d+");
            if last == want {
                return;
            }
        }
        panic!("the remote terminal never became {want:?}; last saw {last:?}");
    }

    /// Whether the local terminal is in canonical mode: `false` while the
    /// client holds it raw, `true` once it has put it back. This is the
    /// observable that makes "the terminal was restored" testable from
    /// outside the client process.
    fn is_cooked(&self) -> bool {
        let master = self
            .session
            .get_process()
            .get_raw_handle()
            .expect("pty master handle");
        let flags = termios::tcgetattr(master.as_fd()).expect("tcgetattr on the pty");
        flags.local_flags.contains(LocalFlags::ICANON)
    }

    /// Send a signal to the client process.
    fn signal(&mut self, signal: Signal) {
        self.session
            .get_process_mut()
            .signal(signal)
            .expect("signal the client");
    }

    /// Drain to EOF, then reap the client and return its wait status.
    fn wait(&mut self) -> WaitStatus {
        let _ = self.session.expect(Eof);
        self.session
            .get_process()
            .wait()
            .expect("wait for the client")
    }

    /// Wait for the client and assert its exit code (`docs/CLI.md` §4).
    fn expect_exit(&mut self, code: i32) {
        match self.wait() {
            WaitStatus::Exited(_, actual) => assert_eq!(actual, code, "client exit code"),
            other => panic!("expected exit {code}, got {other:?}"),
        }
    }
}

/// Resolve `binary` on the *runner's* `PATH`. `None` means the acceptance
/// item is skipped; `Some` means the interaction has to work.
fn locate(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| {
            // Executable, not merely present: a non-executable `vim` on
            // PATH would otherwise turn a clean skip into a confusing
            // failure inside the session.
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(candidate)
                .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// Which acceptance binaries a missing install must *fail* for, read from
/// `QSH_ACCEPTANCE_STRICT`.
///
/// * unset — nothing is required; every missing binary is a `SKIP:` line.
/// * `1` / `all` — the whole acceptance set is required. This is the M2
///   certification mode (`PLAN.md` DoD 2): a run that claims to certify
///   the acceptance set must not pass by skipping half of it.
/// * a comma-separated list — only those are required.
///
/// The list form exists because the certification set and what a *standing*
/// gate can promise are not the same. `claude` is not installable on a
/// hosted GitHub runner, so a CI job demanding it would be red for ever
/// and would teach nobody anything; the CI job requires the four that
/// `apt-get` provides, and the full set is certified where all five are
/// installed. Neither mode ever downgrades a failure to a skip.
fn required_by_strict(binary: &str) -> bool {
    let Some(value) = std::env::var_os("QSH_ACCEPTANCE_STRICT") else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return false;
    }
    if value == "1" || value == "all" {
        return true;
    }
    value.split(',').any(|name| name.trim() == binary)
}

/// Announce a skipped acceptance item, loudly enough to find in a CI log —
/// or fail, when [`required_by_strict`] says this runner promised it.
fn skip(binary: &str) {
    assert!(
        !required_by_strict(binary),
        "QSH_ACCEPTANCE_STRICT requires {binary}, but it is not installed on this runner"
    );
    eprintln!("SKIP: {binary} is not installed on this runner");
}

/// Open a session running `argv`, with `env` overlaid, and return its
/// `session_ref`. Opening through the JSON CLI keeps the pty under test
/// free for the attach itself.
fn open_session_with_env(client: &Sandbox, env: &[&str], argv: &[&str]) -> String {
    let mut args = vec!["session", "open", HOST_ALIAS, "--json"];
    for var in env {
        args.extend_from_slice(&["--env", var]);
    }
    if !argv.is_empty() {
        args.push("--");
        args.extend_from_slice(argv);
    }
    let (code, value) = client.json(&args);
    assert_eq!(code, 0, "session open failed: {value}");
    value["data"]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string()
}

/// Open a session running `argv`.
fn open_session(client: &Sandbox, argv: &[&str]) -> String {
    open_session_with_env(client, &[], argv)
}

/// One session's JSON snapshot (`docs/CLI.md` §6.3).
fn session_get(client: &Sandbox, session_ref: &str) -> Value {
    let (code, value) = client.json(&["session", "get", session_ref, "--json"]);
    assert_eq!(code, 0, "session get failed: {value}");
    value["data"].clone()
}

/// A `sh` probe that prints the terminal size as one grep-able token.
const SIZE_PROBE: &str = r#"echo SIZE=$(stty size | { read r c; echo ${c}x${r}; })"#;

/// The bare `qsh [user@]host` form end to end: a real login shell on a
/// real terminal, `~d` to leave it running, `qsh attach` to come back
/// (`docs/CLI.md` §7). This is the product's central promise — the session
/// outlives the client — exercised through the terminal path.
#[test]
fn the_bare_form_round_trips_and_survives_a_detach() {
    let fleet = Fleet::start();
    let mut client = Client::spawn(&fleet.client, &[HOST_ALIAS]);

    client.round_trip("QSH-LOGIN");
    assert!(
        !client.is_cooked(),
        "the client must hold the terminal raw while attached"
    );

    // `~d` at a line start detaches; the session keeps running.
    client.type_("~d");
    client.expect("detached");
    client.expect_exit(0);
    assert!(
        client.is_cooked(),
        "the terminal must be restored on the detach path"
    );

    let (code, listed) = fleet.client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    let sessions = listed["data"]["sessions"].as_array().expect("sessions");
    assert_eq!(sessions.len(), 1, "a detach must not remove the session");
    assert_eq!(sessions[0]["state"], "running");
    let session_ref = sessions[0]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string();

    // ...and a second terminal can pick it up where it was left.
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);
    client.round_trip("QSH-REATTACH");
    client.type_("exit\r");
    client.expect_exit(0);
    assert!(client.is_cooked());
}

/// `--escape-char none` turns the sequences off, so `~d` is just input
/// (`docs/CLI.md` §7).
#[test]
fn escape_processing_can_be_turned_off() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut client = Client::spawn(
        &fleet.client,
        &["attach", &session_ref, "--escape-char", "none"],
    );

    client.round_trip("QSH-NOESC");
    // `~d` now reaches the shell instead of detaching the client, so the
    // attach is still alive afterwards.
    client.type_("~d\r");
    client.round_trip("QSH-STILL-HERE");
    client.type_("exit\r");
    client.expect_exit(0);
    assert!(client.is_cooked());
}

/// `~?` prints the escape help on stderr and consumes the sequence
/// (`docs/CLI.md` §7).
#[test]
fn the_escape_help_lists_every_sequence() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    client.round_trip("QSH-HELP");
    client.type_("~?");
    client.expect("Supported escape sequences");
    client.expect("detach (the session keeps running)");
    // The sequence was consumed locally: the shell never saw it, and we
    // are still at a line start, so `~d` still detaches.
    client.type_("~d");
    client.expect_exit(0);
    assert!(client.is_cooked());
    assert_eq!(
        session_get(&fleet.client, &session_ref)["state"],
        "running",
        "`~?` then `~d` must leave the session alone"
    );
}

/// SIGWINCH → `session.resize` → the remote PTY, asserted with `stty size`
/// (`PLAN.md` Step 6).
#[test]
fn a_local_resize_reaches_the_remote_pty() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    // The attach adopts this terminal's size before anything is drawn.
    client.expect_size(SIZE_PROBE, START_SIZE);

    client.resize(NEW_SIZE);
    client.expect_size(SIZE_PROBE, NEW_SIZE);

    client.type_("exit\r");
    client.expect_exit(0);
}

/// The remote shell's exit code becomes the client's (`docs/CLI.md` §4).
#[test]
fn the_remote_exit_code_becomes_the_clients() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    client.round_trip("QSH-EXIT");
    client.type_("exit 7\r");
    client.expect_exit(7);
    assert!(client.is_cooked());
}

/// Acceptance item 1: real interactive `bash` and `zsh`, prompt and all.
/// The prompt only appears if the shell decided it is interactive on a
/// terminal, which is the property under test.
#[test]
fn bash_and_zsh_prompts_round_trip() {
    let fleet = Fleet::start();
    for (shell, flags) in [
        ("bash", &["--norc", "--noprofile", "-i"][..]),
        ("zsh", &["-f", "-i"][..]),
    ] {
        let Some(path) = locate(shell) else {
            skip(shell);
            continue;
        };
        let prompt = format!("QSH-{}-PROMPT> ", shell.to_uppercase());
        let mut argv = vec![path.to_str().expect("utf-8 path")];
        argv.extend_from_slice(flags);
        // The host pins only HOME/USER/LOGNAME/SHELL/PATH
        // (`architecture.md` §4), so `PS1` rides in as a session env
        // overlay.
        let ps1 = format!("PS1={prompt}");
        let session_ref = open_session_with_env(&fleet.client, &[&ps1], &argv);

        let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);
        client.expect(&prompt);
        client.round_trip("QSH-SHELL");
        client.expect(&prompt);
        client.type_("exit 3\r");
        client.expect_exit(3);
        assert!(client.is_cooked(), "{shell} left the terminal raw");
    }
}

/// Acceptance item 2: `vim` opens, edits and writes. Asserted on the file
/// it wrote, not on screen paint, so the test cannot pass on a redraw that
/// merely looked right.
#[test]
fn vim_opens_edits_and_quits() {
    let Some(vim) = locate("vim") else {
        skip("vim");
        return;
    };
    let fleet = Fleet::start();
    // Deliberately under `/tmp` rather than `TMPDIR`: on macOS the latter
    // is a ~50-character path, and vim's `"…" 1 line, 6 bytes` startup
    // message would then wrap and stop at a `Press ENTER` prompt instead
    // of painting the buffer.
    let dir = tempfile::Builder::new()
        .prefix("qsh-vim")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let file = dir.path().join("f.txt");
    std::fs::write(&file, "alpha\n").expect("seed the file");

    let session_ref = open_session(
        &fleet.client,
        &[
            vim.to_str().expect("utf-8 path"),
            "-u",
            "NONE",
            "-n",
            file.to_str().expect("utf-8 path"),
        ],
    );
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    // vim painted the buffer: the seeded line is on screen.
    client.expect("alpha");
    // Open a line, type, leave insert mode, write and quit.
    client.type_("oBETA\x1b:wq\r");
    client.expect_exit(0);
    assert!(client.is_cooked(), "vim left the terminal raw");

    let written = std::fs::read_to_string(&file).expect("read the edited file");
    assert_eq!(
        written, "alpha\nBETA\n",
        "vim's edit did not reach the file"
    );
}

/// Owns the tmux **server** on a private socket.
///
/// tmux daemonizes, so its server is reparented to init the moment it
/// starts: killing the session, the client or `qsh serve` does not touch
/// it. A clean run ends it by leaving the last pane, but any panic before
/// that would strand a tmux server — and a shell inside it — on the
/// developer's machine for ever. This makes the happy path's cleanup the
/// fallback rather than the only path.
struct TmuxServerGuard {
    tmux: PathBuf,
    socket: String,
}

impl Drop for TmuxServerGuard {
    fn drop(&mut self) {
        // Already gone on a clean run; `kill-server` then fails harmlessly
        // ("no server running on …"), which is why nothing is asserted.
        let _ = Command::new(&self.tmux)
            .args(["-L", &self.socket, "kill-server"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Acceptance item 3: `tmux`, including a resize that has to travel
/// through tmux's own client before it reaches the pane.
#[test]
fn tmux_runs_and_propagates_a_resize() {
    let Some(tmux) = locate("tmux") else {
        skip("tmux");
        return;
    };
    let fleet = Fleet::start();
    // A private socket and no config, so the test never touches (or is
    // touched by) a tmux the developer is already running. Unique per
    // test process, which under nextest is per test.
    let socket = format!("qsh-test-{}", std::process::id());
    let _tmux_server = TmuxServerGuard {
        tmux: tmux.clone(),
        socket: socket.clone(),
    };
    let session_ref = open_session(
        &fleet.client,
        &[
            tmux.to_str().expect("utf-8 path"),
            "-f",
            "/dev/null",
            "-L",
            &socket,
            "new-session",
            "sh",
        ],
    );
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    // Inside tmux the pane size follows the tmux client, which follows us.
    // tmux keeps a one-line status bar, so the pane is one row shorter.
    client.expect_size(SIZE_PROBE, (START_SIZE.0, START_SIZE.1 - 1));
    client.resize(NEW_SIZE);
    client.expect_size(SIZE_PROBE, (NEW_SIZE.0, NEW_SIZE.1 - 1));

    // Leaving the pane ends the tmux server on that socket.
    client.type_("exit\r");
    client.expect_exit(0);
    assert!(client.is_cooked(), "tmux left the terminal raw");
}

/// Acceptance item 4: `claude` starts inside a session and talks to the
/// PTY. `--version` deliberately: the interactive product needs
/// credentials and a network, neither of which belongs in a PR gate — what
/// this proves is that the binary starts under qsh's PTY and produces
/// output through it.
#[test]
fn claude_starts_inside_a_session() {
    let Some(claude) = locate("claude") else {
        skip("claude");
        return;
    };
    let fleet = Fleet::start();
    let session_ref = open_session(
        &fleet.client,
        &[claude.to_str().expect("utf-8 path"), "--version"],
    );
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    client.expect_regex(r"\d+\.\d+\.\d+");
    client.expect_exit(0);
    assert!(client.is_cooked(), "claude left the terminal raw");
}

/// Exit path: the client panics with the terminal raw. The panic hook has
/// to put it back before the message is printed, or the operator is left
/// with an unusable shell and a stair-stepped backtrace.
///
/// Only meaningful against a debug binary — the seam it uses does not
/// exist in a release build (`tui::unix::test_panic_hook`), which is
/// exactly the point: a shipped `qsh` cannot be talked into panicking by
/// its environment.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "the QSH_TUI_TEST_PANIC seam is debug-only"
)]
fn a_panic_restores_the_terminal() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut command = fleet.client.command(&["attach", &session_ref]);
    command.env("QSH_TUI_TEST_PANIC", "1");
    let mut client = Client::spawn_with(command);

    client.expect("QSH_TUI_TEST_PANIC");
    match client.wait() {
        // Rust's exit code for a panic that unwinds out of `main`.
        WaitStatus::Exited(_, 101) => {}
        other => panic!("expected a panic exit, got {other:?}"),
    }
    assert!(
        client.is_cooked(),
        "a panic must not leave the terminal raw"
    );
    assert_eq!(
        session_get(&fleet.client, &session_ref)["state"],
        "running",
        "a dead client must not take the session with it"
    );
}

/// Exit path: SIGTERM. The terminal is restored and the process still dies
/// *of the signal*, so a caller's `$?` tells the truth.
#[test]
fn a_signal_restores_the_terminal_and_kills_the_client() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    client.round_trip("QSH-SIGNAL");
    assert!(!client.is_cooked());
    client.signal(Signal::SIGTERM);

    match client.wait() {
        WaitStatus::Signaled(_, Signal::SIGTERM, _) => {}
        other => panic!("expected death by SIGTERM, got {other:?}"),
    }
    assert!(
        client.is_cooked(),
        "a signalled client must still restore the terminal"
    );
    assert_eq!(
        session_get(&fleet.client, &session_ref)["state"],
        "running",
        "a signalled client must not take the session with it"
    );
}

/// Exit path: the session is closed underneath a live attach. The client
/// says so, restores the terminal, and exits non-zero.
#[test]
fn a_closed_session_ends_the_attach_cleanly() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    client.round_trip("QSH-CLOSED");
    let (code, closed) = fleet
        .client
        .json(&["session", "close", &session_ref, "--json"]);
    assert_eq!(code, 0, "{closed}");

    // The client has to *say* which of the two happened; a silent
    // `Outcome::Lost` would otherwise satisfy the exit-code check below.
    let reason = client.expect_regex(r"terminated by SIGHUP|the session was closed");

    match client.wait() {
        // `session close` sends SIGHUP first (`docs/CLI.md` §6.7), so the
        // child dies of it and the client reports `128 + SIGHUP` exactly
        // like `qsh exec` (§4) — unless the session is removed before that
        // status reaches us, which is a qsh-side failure (255).
        WaitStatus::Exited(_, 129 | 255) => {}
        other => panic!("expected 129 or 255 after {reason:?}, got {other:?}"),
    }
    assert!(
        client.is_cooked(),
        "the terminal must be restored on the error path"
    );
}

/// A line typed immediately before `~d` still reaches the shell.
///
/// One `read(2)` carries both, so the detach and the bytes ahead of it race
/// unless the detach travels the same ordered queue as the input and the
/// send half is flushed before the connection closes — a QUIC close
/// discards unsent stream data. The replay a re-attach gets is where the
/// answer shows up (`docs/CLI.md` §7: the session outlives the client).
#[test]
fn input_typed_just_before_a_detach_is_not_lost() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    client.round_trip("QSH-BEFORE");
    // Deliberately one write: the command, its CR, and the escape.
    client.type_("echo LAST''-OK\r~d");
    client.expect("detached");
    client.expect_exit(0);

    let mut back = Client::spawn(&fleet.client, &["attach", &session_ref]);
    back.expect("LAST-OK");
    back.type_("exit\r");
    back.expect_exit(0);
}

/// `^C` reaches the remote PTY, both ways it can arrive (`docs/CLI.md`
/// §9): as a keystroke (raw mode clears `ISIG`, so it is an ordinary byte
/// the client forwards) and as an externally delivered `SIGINT`, which the
/// signal pump turns back into that byte.
///
/// The shell traps `INT` and prints, so the assertion is on the remote
/// *reacting*, not on a byte disappearing into a pipe.
#[test]
fn an_interrupt_reaches_the_remote_pty_from_both_directions() {
    let fleet = Fleet::start();
    let session_ref = open_session(
        &fleet.client,
        &[
            "sh",
            "-c",
            // No `|| exit`: a `read` interrupted by the signal returns
            // non-zero, so an exit-on-failure loop would end the shell
            // instead of proving the trap ran.
            "trap 'echo GOT-INT' INT; echo READY; while :; do read x; done",
        ],
    );
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    // Wait for the shell's banner before typing anything: it is written by
    // the event pump, which only runs once the terminal is raw. Until then
    // `ISIG` is still set on the *local* pty and a `^C` would kill the
    // client instead of travelling to the remote.
    client.expect("READY");

    client.type_("\x03");
    client.expect("GOT-INT");

    // ...and the same byte again, this time produced by the client itself
    // out of a signal nobody typed.
    client.signal(Signal::SIGINT);
    client.expect("GOT-INT");

    // The client is still attached: a forwarded SIGINT is not an exit.
    // (`^C` is not a line end, so a CR comes first or `~d` is just input.)
    client.type_("\r");
    client.type_("~d");
    client.expect_exit(0);
    assert_eq!(
        session_get(&fleet.client, &session_ref)["state"],
        "running",
        "a forwarded SIGINT must not end the session"
    );
}

/// The two escape sequences that end up as remote input: `~~` sends one
/// literal `~`, and an unrecognised `~x` sends **both** bytes
/// (`docs/CLI.md` §7). Unit-tested byte for byte; this is the same rule
/// through a real terminal, where the remote echo is in the way.
#[test]
fn literal_and_unknown_escapes_reach_the_shell() {
    let fleet = Fleet::start();
    // `cat` echoes its input back verbatim, so what the shell received is
    // exactly what comes out — no prompt, no expansion, no quoting.
    let session_ref = open_session(&fleet.client, &["cat"]);
    let mut client = Client::spawn(&fleet.client, &["attach", &session_ref]);

    // `~~` at a line start: one `~`, then a marker so the line is
    // identifiable in the echo.
    client.type_("~~TILDE\r");
    client.expect("~TILDE");

    // `~x` is not a sequence: both bytes go on. (`x` is not a line start
    // afterwards, so the `~` in the marker is ordinary input too.)
    client.type_("~xUNKNOWN\r");
    client.expect("~xUNKNOWN");

    client.type_("~d");
    client.expect_exit(0);
}

/// `user@` is an assertion, not a choice: a name that is not the serve
/// account's is refused with `UNSUPPORTED` and **no session is created**
/// (`docs/CLI.md` §7, fail closed). This is the only CLI surface that can
/// send the hint at all.
#[test]
fn a_foreign_user_hint_is_refused_without_creating_a_session() {
    let fleet = Fleet::start();
    let before = session_count(&fleet.client);

    let target = format!("qsh-no-such-user@{HOST_ALIAS}");
    let output = fleet.client.qsh(&[&target]);
    assert_eq!(
        common::exit_code(&output),
        255,
        "a refused hint is a qsh runtime failure (`docs/CLI.md` §4)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("user switching is not supported"),
        "stderr was {stderr:?}"
    );
    assert!(
        stderr.contains("UNSUPPORTED"),
        "the error code must reach the user: {stderr:?}"
    );
    assert_eq!(
        session_count(&fleet.client),
        before,
        "a refused `user@` must not leave a session behind"
    );
}

/// How many sessions the host is holding.
fn session_count(client: &Sandbox) -> usize {
    let (code, listed) = client.json(&["sessions", HOST_ALIAS, "--json"]);
    assert_eq!(code, 0, "{listed}");
    listed["data"]["sessions"]
        .as_array()
        .expect("sessions")
        .len()
}

/// Not a terminal: with a pipe on stdin the client forwards every byte
/// verbatim, escape sequences included, and never touches termios
/// (`docs/CLI.md` §7).
#[test]
fn a_piped_stdin_forwards_everything_verbatim() {
    let fleet = Fleet::start();
    let session_ref = open_session(&fleet.client, &["sh"]);
    let output = fleet
        .client
        .qsh_with_stdin(&["attach", &session_ref], b"echo PIPED''-OK\n~d\nexit 5\n");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PIPED-OK"), "{stdout:?}");
    assert_eq!(
        common::exit_code(&output),
        5,
        "`~d` on a pipe is input, not a detach: {stdout:?}"
    );
}
