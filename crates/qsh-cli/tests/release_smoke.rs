//! The release-profile functional smoke (`docs/ROADMAP.md` M10's acceptance
//! criteria, the 2026-08-21 audit revision). One scenario chains the four
//! axes that revision names: `init` -> mutual `trust add` -> an `exec --json`
//! round trip -> a real pty shell, `~d` detach and `qsh attach` re-attach
//! (`docs/CLI.md` §6.8, §6.2, §7).
//!
//! Unlike the rest of this suite it can run against an **arbitrary** `qsh`
//! binary, because what M10 ships is a release build and nothing in CI had
//! ever exercised a release binary's functional path — only
//! `version --json` (`.github/workflows/release.yml`'s `Binary starts`
//! step) and T2's absolute RSS/fd numbers (`adversarial_load.rs`,
//! `soak.rs`).
//!
//! - `QSH_SMOKE_BIN` names the binary to drive. Unset, this falls back to
//!   the nextest-built `CARGO_BIN_EXE_qsh` on purpose, so the scenario runs
//!   on every PR against the debug binary and cannot rot between releases.
//!   That is the one place this file departs from `adversarial_load.rs`'s
//!   `load_bin()`, which refuses any fallback: a debug binary's RSS shape is
//!   not what T2's bound is about, while a debug binary's *functional* round
//!   trip is exactly what this file is about.
//! - `QSH_SMOKE_STRICT=1` removes that fallback. A job that promised to
//!   certify a shipped binary must not pass by quietly certifying the debug
//!   one instead; a missing `QSH_SMOKE_BIN` under strict is a panic naming
//!   the variable, never a silent substitution. Same discipline as
//!   `QSH_ACCEPTANCE_STRICT`'s "never downgrade a promise to a skip"
//!   (`socks_curl.rs`, `tui_expect.rs`).
//! - A `QSH_SMOKE_BIN` that does not exist, or is not executable, is a panic
//!   naming the path. The silent-fallback failure mode this file exists to
//!   prevent has a twin: a typo'd path that fails deep inside a spawn.
//!
//! The pty half is `#[cfg(unix)]`: `expectrl` is a `cfg(unix)`
//! dev-dependency and `qsh`'s interactive client answers `UNSUPPORTED` off
//! unix. The `#[cfg(not(unix))]` twin runs init, trust and `exec --json`
//! only, and says so in its name.
//!
//! `Client` here is a trimmed copy of `tui_expect.rs`'s, not a move into
//! `tests/common/mod.rs`: that module is compiled into every test binary
//! that declares `mod common;` (most of this suite), and hoisting an
//! `expectrl` dependency into all of them to
//! serve two files is the trade `socks_curl.rs` already refused for
//! `tui_expect.rs`'s skip helpers.
//!
//! What this scenario does **not** assert: that a marker echoed before
//! detach replays on the re-attached screen. Replay is a wire-level
//! mechanism (`docs/design/protocol.md`'s `SessionAttach` `replay_from`),
//! but what an interactive `qsh attach` repaints right after re-attach is a
//! client behavior no other test pins today, and this smoke does not mint a
//! new contract. Its honest claim is narrower: the session survives detach
//! as `running`, and a freshly typed command round-trips on the re-attached
//! terminal — exactly what `tui_expect.rs`'s
//! `the_bare_form_round_trips_and_survives_a_detach` already pins.

mod common;

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{Fleet, HOST_ALIAS};
use serde_json::Value;

/// Whether an env var is set to something other than empty or `0`
/// (mirrors `adversarial_load.rs`'s `env_flag`).
fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim().to_string();
    !(value.is_empty() || value == "0")
}

/// Whether `QSH_SMOKE_BIN` is required — see the module doc.
fn strict() -> bool {
    env_flag("QSH_SMOKE_STRICT")
}

/// Resolve the `qsh` binary this scenario drives.
///
/// `QSH_SMOKE_BIN` set: that path, or a panic naming it if it is not a
/// file (unix: not executable either) — a clearer diagnosis than the
/// `Command::spawn` failure a typo'd path would otherwise produce deep
/// inside `Fleet::start_with_bin`.
///
/// `QSH_SMOKE_BIN` unset and [`strict`] false: `CARGO_BIN_EXE_qsh` — the
/// debug binary nextest already built, so the PR gate runs this scenario
/// on every push without needing a release build.
///
/// `QSH_SMOKE_BIN` unset and [`strict`] true: a panic naming
/// `QSH_SMOKE_BIN`. A job that set `QSH_SMOKE_STRICT=1` promised to
/// certify a shipped binary; falling back silently would let a typo'd or
/// missing env var pass as green.
fn smoke_bin() -> PathBuf {
    let Some(raw) = std::env::var_os("QSH_SMOKE_BIN") else {
        assert!(
            !strict(),
            "QSH_SMOKE_STRICT=1 but QSH_SMOKE_BIN is not set — release_smoke refuses to \
             silently substitute the nextest-built debug binary for a job that promised to \
             certify a shipped one; set QSH_SMOKE_BIN=$(pwd)/target/release/qsh (or the \
             matching target/<triple>/release/qsh) after `cargo build --release -p qsh-cli`."
        );
        return PathBuf::from(env!("CARGO_BIN_EXE_qsh"));
    };
    let bin = PathBuf::from(raw);
    let meta = std::fs::metadata(&bin)
        .unwrap_or_else(|err| panic!("QSH_SMOKE_BIN={bin:?} is not a usable file: {err}"));
    assert!(meta.is_file(), "QSH_SMOKE_BIN={bin:?} is not a file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert!(
            meta.permissions().mode() & 0o111 != 0,
            "QSH_SMOKE_BIN={bin:?} is not executable"
        );
    }
    eprintln!("release_smoke: driving {}", bin.display());
    bin
}

/// The three axes that exist on every platform: init (via
/// [`Fleet::start_with_bin`]'s own fingerprint assertions, plus one more
/// here), mutual trust, and an `exec --json` round trip that proves the
/// remote exit code actually travels back (`docs/CLI.md` §6.8).
fn assert_machine_axes(fleet: &Fleet) {
    assert!(
        fleet.host_fingerprint.starts_with("sha256:"),
        "host fingerprint: {}",
        fleet.host_fingerprint
    );
    assert!(
        fleet.client_fingerprint.starts_with("sha256:"),
        "client fingerprint: {}",
        fleet.client_fingerprint
    );
    assert_ne!(
        fleet.host_fingerprint, fleet.client_fingerprint,
        "host and client must be distinct identities"
    );

    let (code, listed) = fleet.client.json(&["trust", "list", "--json"]);
    assert_eq!(code, 0, "{listed}");
    let peers = listed["data"]["peers"].as_array().expect("peers");
    let box_peer = peers
        .iter()
        .find(|peer| peer["name"] == HOST_ALIAS)
        .unwrap_or_else(|| panic!("no {HOST_ALIAS:?} peer in {listed}"));
    assert_eq!(box_peer["fingerprint"], fleet.host_fingerprint, "{listed}");

    // exit 7, not 0: only a non-zero remote exit proves the code actually
    // rode back over the wire rather than a 0 default papering over a
    // broken path (`exec_e2e.rs`'s `exec_json_reports_both_streams_and_
    // the_remote_exit_code`, whose assertion set this mirrors).
    let (code, value) = fleet.exec_json(&["--", "sh", "-c", "echo out; echo err >&2; exit 7"]);
    assert_eq!(code, 7, "process exit code must be the remote one: {value}");
    assert_eq!(value["schema"], "qsh.cli/v1");
    assert_eq!(value["command"], "exec.run");
    assert_eq!(value["ok"], true, "{value}");
    let data = &value["data"];
    assert_eq!(data["stdout_b64"], BASE64.encode("out\n"));
    assert_eq!(data["stderr_b64"], BASE64.encode("err\n"));
    assert_eq!(data["remote_exit_code"], 7);
    assert_eq!(data["signal"], Value::Null);
    assert!(data["duration_ms"].is_u64(), "{data}");
}

/// A trimmed copy of `tui_expect.rs`'s `Client` (module doc explains why
/// this is a copy rather than a `tests/common/mod.rs` addition).
#[cfg(unix)]
mod pty {
    use std::time::Duration;

    use crate::common::Sandbox;
    use expectrl::process::unix::WaitStatus;
    use expectrl::session::OsSession;
    use expectrl::{Eof, Expect as _, Session};
    use nix::sys::termios::{self, LocalFlags};
    use std::os::fd::AsFd as _;

    /// How long any single `expect` waits (mirrors `tui_expect.rs`'s
    /// `EXPECT_TIMEOUT`).
    const EXPECT_TIMEOUT: Duration = Duration::from_secs(30);

    /// A `qsh` client running under its own pty.
    pub struct Client {
        session: OsSession,
    }

    impl Client {
        /// Spawn `qsh <args>` under a pty, with the sandbox's directories
        /// and a `TERM` a full-screen program will accept.
        pub fn spawn(sandbox: &Sandbox, args: &[&str]) -> Self {
            let mut command = sandbox.command(args);
            command.env("TERM", "xterm-256color");
            let mut session = Session::spawn(command).expect("spawn qsh under a pty");
            session.set_expect_timeout(Some(EXPECT_TIMEOUT));
            Self { session }
        }

        /// Wait for `needle`, or fail naming what never arrived.
        pub fn expect(&mut self, needle: &str) {
            if let Err(err) = self.session.expect(needle) {
                panic!("waiting for {needle:?}: {err}");
            }
        }

        /// Type bytes at the client verbatim. Enter is CR, exactly what a
        /// terminal sends and what the escape machine treats as a line
        /// end (`docs/CLI.md` §7: a line start is "session start, or the
        /// last byte sent to the remote was CR/LF").
        pub fn type_(&mut self, keys: &str) {
            self.session.send(keys).expect("send to the client's pty");
        }

        /// Run `echo` in the attached shell and wait for its output. The
        /// marker is split by an empty quote so the *echo of the typed
        /// line* cannot satisfy the expectation — only the shell's own
        /// output can. Ends in `\r`, which is what makes the very next
        /// `~d` land at a recognized line start.
        pub fn round_trip(&mut self, marker: &str) {
            self.type_(&format!("echo {marker}''-OK\r"));
            self.expect(&format!("{marker}-OK"));
        }

        /// Whether the local terminal is in canonical mode: `false` while
        /// the client holds it raw, `true` once it has put it back.
        pub fn is_cooked(&self) -> bool {
            let master = self
                .session
                .get_process()
                .get_raw_handle()
                .expect("pty master handle");
            let flags = termios::tcgetattr(master.as_fd()).expect("tcgetattr on the pty");
            flags.local_flags.contains(LocalFlags::ICANON)
        }

        /// Drain to EOF, then reap the client and return its wait status.
        fn wait(&mut self) -> WaitStatus {
            let _ = self.session.expect(Eof);
            self.session
                .get_process()
                .wait()
                .expect("wait for the client")
        }

        /// Wait for the client and assert its exit code (`docs/CLI.md`
        /// §4).
        pub fn expect_exit(&mut self, code: i32) {
            match self.wait() {
                WaitStatus::Exited(_, actual) => assert_eq!(actual, code, "client exit code"),
                other => panic!("expected exit {code}, got {other:?}"),
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn release_smoke_covers_init_trust_exec_pty_detach_and_reattach() {
    let bin = smoke_bin();
    let fleet = Fleet::start_with_bin(&bin, &[]);

    assert_machine_axes(&fleet);

    let mut client = pty::Client::spawn(&fleet.client, &[HOST_ALIAS]);
    client.round_trip("QSH-SMOKE");
    assert!(
        !client.is_cooked(),
        "the client must hold the terminal raw while attached"
    );

    // `~d` at a line start detaches; the session keeps running
    // (`docs/CLI.md` §7).
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

    // ...and a second terminal can pick it up where it was left. The
    // marker changes on purpose: a re-attach that only ever saw replay of
    // the pre-detach marker would satisfy an unchanged `round_trip` too,
    // and that is not what this axis is meant to prove.
    let mut client = pty::Client::spawn(&fleet.client, &["attach", &session_ref]);
    client.round_trip("QSH-SMOKE-REATTACH");
    client.type_("exit\r");
    client.expect_exit(0);
    assert!(client.is_cooked());
}

#[cfg(not(unix))]
#[test]
fn release_smoke_covers_init_trust_and_exec_on_a_platform_without_a_pty_client() {
    let bin = smoke_bin();
    let fleet = Fleet::start_with_bin(&bin, &[]);
    assert_machine_axes(&fleet);
}
