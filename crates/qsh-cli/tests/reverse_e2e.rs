//! L5/L6 — the full DoD 1 acceptance scenario for `PLAN.md` M3 Step 7:
//! three real OS processes, none of them fakes, proving "attach works
//! behind NAT by construction":
//!
//! 1. A **controller** process (`qsh listen`) — bound to `127.0.0.1`, never
//!    dials anyone.
//! 2. A **target** process (`qsh reverse <controller-alias>`) — dials the
//!    controller once, registers, and from that point on opens **no
//!    listening socket of its own** (asserted from outside the process,
//!    see [`assert_owns_no_listening_socket`]) — the literal shape of
//!    "behind NAT": the only reason the controller can ever reach this
//!    process again is the one connection the target itself opened.
//! 3. A **client** process (`qsh <name>`, then `qsh attach <name>/<id>`)
//!    run under a real pty (`expectrl`, same technique as
//!    `tui_expect.rs`) — a real login shell, `~d` detach, and a real
//!    reattach, all routed to the target through the controller's local
//!    daemon (`LOCAL_CONTROL`/`LOCAL_STREAM`, Step 6/Step 7) rather than
//!    any direct network path to the target.
//!
//! The client process runs from the **controller's own sandbox** —
//! `Ops::connect`'s reverse route reaches the target by discovering the
//! controller's localctl socket under `Paths::runtime_dir()`
//! (`docs/design/architecture.md` §7), which only resolves to the right
//! socket when the client shares the controller's `$QSH_STATE_DIR` (and
//! therefore its `<state>/run`). Two more processes sharing one sandbox is
//! exactly what a real "controller box with a local `qsh` client on it"
//! looks like — it is not a test-only shortcut.
//!
//! A small subset of `tui_expect.rs`'s `Client` is copied here rather than
//! imported — `tui_expect.rs` is a test *binary*, not a library module,
//! and per this stage's own instructions is left untouched.

#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use common::{ListenGuard, ReverseGuard, Sandbox, hosts_array, poll_until};
use expectrl::session::OsSession;
use expectrl::{Eof, Expect as _, Session};
use nix::sys::termios::{self, LocalFlags};
use std::os::fd::AsFd as _;

/// How long a single `expect` waits (mirrors `tui_expect.rs::EXPECT_TIMEOUT`).
const EXPECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long we wait for the reverse registration to show up on the
/// controller's `qsh hosts --json` (target dial + admit is a handful of
/// round trips, not instant, but should never take anywhere near this).
const REGISTRATION_DEADLINE: Duration = Duration::from_secs(15);

/// The name the controller's own trust store assigns the target
/// (`reverse::admit::admit` derives the registration's name from the
/// controller's pin on the incoming fingerprint, never from the target's
/// own `--offered-name` — `hosts_reverse.rs`'s module docs cover this in
/// full).
const TARGET_NAME: &str = "nat-target";

/// The alias the target's own trust store uses for the controller it
/// dials.
const CONTROLLER_ALIAS: &str = "hub";

/// A minimal `qsh` pty client — the subset of `tui_expect.rs::Client` this
/// file needs. See the module docs for why this is a copy, not an import.
struct Client {
    session: OsSession,
}

impl Client {
    fn spawn(sandbox: &Sandbox, args: &[&str]) -> Self {
        let mut command = sandbox.command(args);
        command.env("TERM", "xterm-256color");
        let mut session = Session::spawn(command).expect("spawn qsh under a pty");
        session.set_expect_timeout(Some(EXPECT_TIMEOUT));
        Self { session }
    }

    fn expect(&mut self, needle: &str) {
        if let Err(err) = self.session.expect(needle) {
            panic!("waiting for {needle:?}: {err}");
        }
    }

    fn type_(&mut self, keys: &str) {
        self.session.send(keys).expect("send to the client's pty");
    }

    /// Same discipline as `tui_expect.rs::Client::round_trip`: the marker
    /// is split so the *echo of the typed line* cannot satisfy the wait,
    /// only the shell's own output can.
    fn round_trip(&mut self, marker: &str) {
        self.type_(&format!("echo {marker}''-OK\r"));
        self.expect(&format!("{marker}-OK"));
    }

    fn is_cooked(&self) -> bool {
        let master = self
            .session
            .get_process()
            .get_raw_handle()
            .expect("pty master handle");
        let flags = termios::tcgetattr(master.as_fd()).expect("tcgetattr on the pty");
        flags.local_flags.contains(LocalFlags::ICANON)
    }

    fn expect_exit(&mut self, code: i32) {
        let _ = self.session.expect(Eof);
        match self.session.get_process().wait() {
            Ok(expectrl::process::unix::WaitStatus::Exited(_, actual)) => {
                assert_eq!(actual, code, "client exit code")
            }
            other => panic!("expected exit {code}, got {other:?}"),
        }
    }
}

/// Resolve `binary` on `PATH`, exactly `tui_expect.rs::locate`'s contract.
fn locate(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(candidate)
                .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// Same contract as `tui_expect.rs::required_by_strict` — governs whether a
/// missing `lsof` is a skip or a hard failure.
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

/// Assert (from **outside** the process — no cooperation from the target
/// required or trusted) that `pid` owns no listening socket at all: the
/// literal test of "behind NAT by construction" — the only path back to
/// this process is the connection it dialed out itself.
///
/// Method: `lsof -nP -p <pid> -iTCP -sTCP:LISTEN` must report nothing.
/// UDP is not asserted the same way because BSD sockets have no `LISTEN`
/// state for `SOCK_DGRAM` at all — a bound UDP socket used purely to send
/// packets out and receive replies on the same 4-tuple (exactly what the
/// QUIC client role here does) is not "a listener" in the sense this
/// assertion means, and `lsof` has no `-sUDP:LISTEN` filter to even ask
/// the question the TCP branch asks. What proves the UDP side instead:
/// `qsh reverse` never calls `qsh_transport`'s server-bind path at all
/// (only `qsh listen`/`qsh serve` do — `main.rs::run_reverse` dials via
/// `Dialer::dial`, a QUIC *client* endpoint, and never prints a
/// "listening on" line, unlike `run_listen`/`run_serve`), which this test
/// also asserts by construction: the argv spawned for the target below is
/// literally `["reverse", CONTROLLER_ALIAS]` — no `--bind`, no `listen`,
/// no `serve` anywhere in it.
fn assert_owns_no_listening_socket(pid: u32) {
    if locate("lsof").is_none() {
        assert!(
            !required_by_strict("lsof"),
            "QSH_ACCEPTANCE_STRICT requires lsof, but it is not installed on this runner"
        );
        eprintln!("SKIP: lsof is not installed on this runner; cannot assert no-listener");
        return;
    }
    // `-a` ANDs the selection options together; without it `lsof` ORs
    // `-p`/`-i`, which would list every listening socket on the whole
    // machine, not just this pid's (confirmed empirically on this host —
    // omitting `-a` fails the assertion on totally unrelated processes).
    let output = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN"])
        .output()
        .expect("run lsof");
    // lsof exits non-zero when nothing matches the filter — that is the
    // pass case here, not a tool failure. What matters is stdout is empty.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "the reverse target owns a listening TCP socket (pid {pid}), which breaks the NAT \
         story entirely:\n{stdout}"
    );
}

/// One session's JSON snapshot (`docs/CLI.md` §6.3).
fn session_get(sandbox: &Sandbox, session_ref: &str) -> serde_json::Value {
    let (code, value) = sandbox.json(&["session", "get", session_ref, "--json"]);
    assert_eq!(code, 0, "session get failed: {value}");
    value["data"].clone()
}

/// The full DoD 1 scenario, end to end.
#[test]
fn a_real_target_behind_nat_registers_and_a_local_client_attaches_detaches_and_reattaches() {
    let controller = Sandbox::initialized();
    let target = Sandbox::initialized();
    let target_fp = target.fingerprint();
    let controller_fp = controller.fingerprint();

    // The controller pins the target *by fingerprint only* — no address —
    // so the only route `Ops::connect` can ever find for `TARGET_NAME` is
    // a live reverse registration, never a forward dial. This is what
    // makes the scenario provably "reverse only", not merely "reverse
    // happens to win the merge" (`hosts_reverse.rs` proves the merge/
    // priority rule already; this file's job is the live attach on top of
    // it).
    controller.trust_add(TARGET_NAME, None, &target_fp);

    let listen = ListenGuard::start(&controller);

    // The target pins the controller (needs a real address to dial) and
    // registers, once, real backoff loop and all if the first attempt
    // races the controller's own startup — `ReverseGuard::start` never
    // blocks on this succeeding, `poll_until` below does.
    target.trust_add(CONTROLLER_ALIAS, Some(listen.addr()), &controller_fp);
    let reverse = ReverseGuard::start(&target, CONTROLLER_ALIAS);

    let merged = poll_until(
        "the reverse registration to appear reachable",
        REGISTRATION_DEADLINE,
        || {
            let hosts = hosts_array(&controller);
            hosts
                .iter()
                .find(|h| h["name"] == TARGET_NAME && h["connection_mode"] == "reverse")
                .filter(|h| h["state"] == "reachable")
                .is_some()
                .then_some(hosts)
        },
    );
    assert_eq!(
        merged.len(),
        1,
        "reverse-only pin: exactly one entry, {merged:?}"
    );

    // DoD 1's central "behind NAT by construction" proof: the target owns
    // no listening socket, and never ran `qsh serve`/`qsh listen`.
    assert_owns_no_listening_socket(reverse.pid());

    // --- the interactive path, under a real pty, routed to the target
    // entirely through the controller's local daemon --------------------
    let mut client = Client::spawn(&controller, &[TARGET_NAME]);
    client.round_trip("QSH-E2E-LOGIN");
    assert!(
        !client.is_cooked(),
        "the client must hold the terminal raw while attached"
    );

    client.type_("~d");
    client.expect("detached");
    client.expect_exit(0);
    assert!(
        client.is_cooked(),
        "the terminal must be restored on detach"
    );

    // The session must still be `running` — a detach never ends it
    // (`docs/CLI.md` §7).
    let (code, listed) = controller.json(&["sessions", TARGET_NAME, "--json"]);
    assert_eq!(code, 0, "{listed}");
    let sessions = listed["data"]["sessions"].as_array().expect("sessions");
    assert_eq!(sessions.len(), 1, "a detach must not remove the session");
    assert_eq!(sessions[0]["state"], "running");
    let session_ref = sessions[0]["session_ref"]
        .as_str()
        .expect("session_ref")
        .to_string();

    let snapshot = session_get(&controller, &session_ref);
    assert_eq!(snapshot["state"], "running", "{snapshot}");

    // Reattach: a second terminal, same reverse route, picks the session
    // back up.
    let mut client = Client::spawn(&controller, &["attach", &session_ref]);
    client.round_trip("QSH-E2E-REATTACH");
    client.type_("exit\r");
    client.expect_exit(0);
    assert!(client.is_cooked());

    reverse.shut_down();
    drop(listen);
}
