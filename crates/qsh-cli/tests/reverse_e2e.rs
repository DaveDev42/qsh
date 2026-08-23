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

/// What [`owned_sockets_via_lsof`]/[`owned_sockets_via_proc`] report about
/// one pid's open sockets — protocol-classified, not merely "some socket
/// exists", so the caller can tell a legitimate outbound QUIC client
/// socket from an accidental extra listener.
struct OwnedSockets {
    /// Count of TCP sockets in `LISTEN` state. QSH never speaks TCP at
    /// all, so this must always be `0`.
    tcp_listeners: usize,
    /// Count of UDP sockets, listening or not (`SOCK_DGRAM` has no
    /// `LISTEN` state to filter on — module doc below). `qsh reverse`
    /// opens exactly one: its own outbound QUIC client dial endpoint. A
    /// second one is exactly what a regression that also opened a
    /// `qsh_transport` server-bind endpoint on the target would produce,
    /// so this is the check that actually catches that mutation — the
    /// TCP-only check above cannot, by construction, since QSH has no TCP
    /// path for it to ever see.
    udp: usize,
}

/// `lsof -nP -a -p <pid> -iTCP -sTCP:LISTEN` / `-iUDP`. `None` if `lsof`
/// is not on `PATH`.
fn owned_sockets_via_lsof(pid: u32) -> Option<OwnedSockets> {
    locate("lsof")?;
    // `-a` ANDs the selection options together; without it `lsof` ORs
    // `-p`/`-i`, which would list every listening socket on the whole
    // machine, not just this pid's (confirmed empirically on this host —
    // omitting `-a` fails the assertion on totally unrelated processes).
    let tcp = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN"])
        .output()
        .expect("run lsof -iTCP");
    let udp = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-iUDP"])
        .output()
        .expect("run lsof -iUDP");
    // lsof exits non-zero when nothing matches the filter — a tool
    // outcome, not a failure to run; only stdout line counts matter here.
    let tcp_listeners = String::from_utf8_lossy(&tcp.stdout)
        .lines()
        .filter(|line| !line.starts_with("COMMAND"))
        .count();
    let udp_lines = String::from_utf8_lossy(&udp.stdout)
        .lines()
        .filter(|line| !line.starts_with("COMMAND"))
        .count();
    Some(OwnedSockets {
        tcp_listeners,
        udp: udp_lines,
    })
}

/// `/proc`-based fallback for runners without `lsof` (common on minimal
/// Linux CI images) — so the "no listening socket" half of DoD 1 is
/// enforced on every runner by default, not only under
/// `QSH_ACCEPTANCE_STRICT`. `None` on any platform without `/proc/<pid>`
/// (e.g. macOS — `lsof` is standard there, so the caller falls back to
/// [`owned_sockets_via_lsof`] first and only reaches here as the second
/// choice).
///
/// Method: collect the socket inodes `pid` holds open fds on (via
/// `/proc/<pid>/fd/*` symlinks, each pointing at `socket:[<inode>]` for a
/// socket fd), then cross-reference those inodes against
/// `/proc/net/{tcp,tcp6}` (state `0A` hex = `LISTEN`) and
/// `/proc/net/{udp,udp6}` (every row — `SOCK_DGRAM` has no listen state).
/// `/proc/net/*` is namespace-scoped, not machine-global, so this is
/// exactly as selective as `lsof -a -p <pid>` is.
fn owned_sockets_via_proc(pid: u32) -> Option<OwnedSockets> {
    let fd_dir = format!("/proc/{pid}/fd");
    let entries = std::fs::read_dir(&fd_dir).ok()?;
    let mut inodes = std::collections::HashSet::new();
    for entry in entries.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let Some(name) = target.to_str() else {
            continue;
        };
        let Some(inode) = name
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        else {
            continue;
        };
        if let Ok(inode) = inode.parse::<u64>() {
            inodes.insert(inode);
        }
    }

    fn count_matching(
        path: &str,
        inodes: &std::collections::HashSet<u64>,
        listen_only: bool,
    ) -> usize {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return 0;
        };
        contents
            .lines()
            .skip(1) // header row
            .filter(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // `/proc/net/{tcp,udp}[6]` columns: sl local_address rem_address
                // st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
                let Some(state) = fields.get(3) else {
                    return false;
                };
                let Some(inode) = fields.get(9).and_then(|s| s.parse::<u64>().ok()) else {
                    return false;
                };
                if !inodes.contains(&inode) {
                    return false;
                }
                !listen_only || *state == "0A"
            })
            .count()
    }

    let tcp_listeners = count_matching("/proc/net/tcp", &inodes, true)
        + count_matching("/proc/net/tcp6", &inodes, true);
    let udp = count_matching("/proc/net/udp", &inodes, false)
        + count_matching("/proc/net/udp6", &inodes, false);
    Some(OwnedSockets { tcp_listeners, udp })
}

/// The live process command line for `pid`, via `ps` — portable across
/// macOS and Linux, unlike `/proc/<pid>/cmdline`. A *runtime-observed*
/// check, not the "we wrote the argv this way in the test source" prose
/// the previous version of this assertion relied on: this reads back what
/// the OS actually recorded for the running process.
fn owned_command_line(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if cmd.is_empty() { None } else { Some(cmd) }
}

/// Assert (from **outside** the process — no cooperation from the target
/// required or trusted) that `pid` owns no listening socket at all, and
/// that its own argv never asked to bind one: the literal test of "behind
/// NAT by construction" — the only path back to this process is the
/// connection it dialed out itself.
///
/// Two independent checks, both enforced whenever a collector is
/// available (default, not opt-in — see [`owned_sockets_via_proc`]'s
/// doc): zero TCP listeners (QSH never speaks TCP, so this is always
/// true) and **exactly one** UDP socket (the target's own outbound QUIC
/// client dial — never zero, since it must have dialed the controller to
/// register at all, and never more than one, since a second UDP socket is
/// exactly what a regression that opened a `qsh_transport` server-bind
/// endpoint on the target would produce). Plus a runtime argv check: the
/// process's actual command line, read back via `ps`, must contain
/// neither `listen` nor `serve` nor `--bind`.
fn assert_owns_no_listening_socket(pid: u32) {
    if let Some(cmd) = owned_command_line(pid) {
        assert!(
            !cmd.contains("listen") && !cmd.contains("serve") && !cmd.contains("--bind"),
            "the reverse target's own argv looks like it asked to bind a listener: {cmd:?}"
        );
    }

    let sockets = owned_sockets_via_lsof(pid).or_else(|| owned_sockets_via_proc(pid));
    let Some(sockets) = sockets else {
        assert!(
            !required_by_strict("lsof"),
            "QSH_ACCEPTANCE_STRICT requires a socket-listing tool (lsof or /proc), but neither \
             is available on this runner"
        );
        eprintln!(
            "SKIP: neither lsof nor /proc is available on this runner; cannot assert no-listener"
        );
        return;
    };
    assert_eq!(
        sockets.tcp_listeners, 0,
        "the reverse target owns a listening TCP socket (pid {pid}), which breaks the NAT \
         story entirely"
    );
    assert_eq!(
        sockets.udp, 1,
        "the reverse target owns {} UDP socket(s) (pid {pid}), expected exactly 1 (its own \
         outbound QUIC client dial) — a different count means either it never dialed out, or \
         it opened a listening endpoint of its own, either way breaking the NAT story",
        sockets.udp
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
    // Continuity, not merely "a shell answered": the pre-detach output
    // must be replayed from the session's retained ring before anything
    // new is typed — proving this is the *same* shell with its own
    // scrollback, not a coincidentally-successful fresh one
    // (`sessions.len() == 1` above already rules out a second session,
    // but says nothing about the pty's own continuity).
    client.expect("QSH-E2E-LOGIN-OK");
    client.round_trip("QSH-E2E-REATTACH");
    client.type_("exit\r");
    client.expect_exit(0);
    assert!(client.is_cooked());

    reverse.shut_down();
    drop(listen);
}
