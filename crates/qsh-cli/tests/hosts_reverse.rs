//! `qsh hosts`/`qsh host get` against a real, live reverse registration
//! (`PLAN.md` M3 Step 5 (c), PR 5b's L3 debt: "L3 — `ReverseHarness` 위에서
//! `qsh hosts --json`이 forward+reverse를 한 배열로 반환하고, 연결을 끊으면
//! 그 항목이 `"stale"`로 바뀜. `qsh hosts`가 네트워크를 건드리지 않음을
//! 단언"). `localctl_perms.rs` already proves the localctl transport/
//! security layer against a real `qsh listen` process (PR 5a); this file
//! is PR 5b's counterpart, aimed at `Ops::host_list`/`host_get`/
//! `resolve_host_route` and the CLI/render surface on top of them instead
//! of the socket underneath — same "real OS process, no cheating"
//! discipline, two real `qsh` children rather than the in-process
//! `qsh-testkit::ReverseHarness` (which has no localctl attached at all;
//! see its module docs).
//!
//! Pinning the target's fingerprint under [`DUP_NAME`] *with* an address
//! on the listen side is what lets one real daemon produce a genuine
//! forward+reverse duplicate pair: that single trust-store entry is both
//! a forward host (it has an address) and the alias a live reverse
//! registration resolves to (`reverse::admit::admit` derives the name
//! from the controller's own trust-store pin, never from
//! `offered_name`). The pinned address is a real, RFC 5737 TEST-NET-1
//! address that is never actually reachable — which doubles as this
//! file's "`host.list` never dials" proof: a call that *did* dial it
//! would not return in this test's bounded window.
//!
//! `#![cfg(unix)]` for the same reason as `localctl_perms.rs`: `qsh
//! listen` never binds a localctl socket on Windows and `qsh reverse`
//! never dials there (`docs/CLI.md` §6.13).

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::Sandbox;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde_json::Value;

/// The name registered on both sides.
const DUP_NAME: &str = "dup-host";

/// RFC 5737 TEST-NET-1 — reserved for documentation, never routed. Used as
/// the forward pin's address so a `host.list`/`host.get` call that
/// actually dialed it would not return within [`NO_DIAL_BOUND`].
const UNREACHABLE_ADDRESS: &str = "192.0.2.1:1";

/// How long we are willing to wait for `qsh listen` to report its bound
/// address before declaring the test broken — mirrors
/// `localctl_perms.rs`'s own `ListenGuard`.
const LISTEN_START_TIMEOUT: Duration = Duration::from_secs(10);

/// The stderr line `qsh listen` prints once it is up (`main.rs`'s
/// `run_listen`).
const LISTENING_PREFIX: &str = "qsh listen: listening on ";

/// A bound on every "wait for cross-process state" poll below — a hard
/// deadline, never a bare sleep standing in for one (mirrors
/// `common::wait_for_audit`, which documents the same discipline for the
/// same reason: the state we are waiting for is produced by another OS
/// process, so there is no in-process event to await).
const POLL_DEADLINE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// A call that never dials must return far faster than any real connect
/// attempt to [`UNREACHABLE_ADDRESS`] could — generous enough to be
/// robust on a loaded CI box, tight enough that an accidental dial (which
/// would block for at least a TCP/QUIC connect timeout, several seconds
/// at minimum) still fails it.
const NO_DIAL_BOUND: Duration = Duration::from_secs(3);

/// A running real `qsh listen` child, killed on drop. Deliberately not
/// shared with `localctl_perms.rs`'s own `ListenGuard` — the same
/// "no shared state between test binaries" reasoning that struct's module
/// doc gives for not folding it into `common::ServeGuard` either.
struct ListenGuard {
    child: Child,
    addr: String,
}

impl ListenGuard {
    fn start(sandbox: &Sandbox) -> Self {
        // `PLAN.md` M5 Step 6: `qsh listen` now default-denies `host.reverse`
        // registrations without an `acl.toml` of its own — this struct is
        // deliberately not `common::ListenGuard` (see this file's module
        // doc), so it does not get that guard's automatic planting for
        // free and has to call the same choke point directly.
        common::plant_allow_all_acl(sandbox);
        let mut child = sandbox
            .command(&["listen", "--bind", "127.0.0.1:0"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh listen");

        // `qsh listen` never writes to stdout; drop the pipe reader in the
        // background purely so the child can never block on a full pipe.
        if let Some(mut out) = child.stdout.take() {
            thread::spawn(move || {
                let _ = std::io::copy(&mut out, &mut std::io::sink());
            });
        }

        let stderr = child.stderr.take().expect("listen stderr pipe");
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(addr) = line.strip_prefix(LISTENING_PREFIX) {
                    let _ = tx.send(addr.to_string());
                }
                // Drain (and drop) every other line silently.
            }
        });
        let addr = rx
            .recv_timeout(LISTEN_START_TIMEOUT)
            .expect("qsh listen never reported a bound address");

        Self { child, addr }
    }

    fn addr(&self) -> &str {
        &self.addr
    }
}

impl Drop for ListenGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A running real `qsh reverse` child. [`Self::shut_down`] sends `SIGTERM`
/// and waits (bounded) for the graceful-shutdown path
/// (`reverse/target.rs`'s `conn.close(0, b"shutdown")`) to actually close
/// the QUIC connection — the reason this test sends `SIGTERM` rather than
/// `child.kill()` (`SIGKILL`): a killed process sends no `CONNECTION_CLOSE`
/// frame, so the controller would only notice via
/// `qsh_transport::endpoint::MAX_IDLE_TIMEOUT` (45s) instead of the
/// near-immediate detection a clean close gives `Registry::mark_stale`.
struct ReverseGuard {
    child: Child,
}

impl ReverseGuard {
    fn start(sandbox: &Sandbox, controller: &str) -> Self {
        let mut child = sandbox
            .command(&["reverse", controller])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn qsh reverse");
        if let Some(mut out) = child.stdout.take() {
            thread::spawn(move || {
                let _ = std::io::copy(&mut out, &mut std::io::sink());
            });
        }
        if let Some(mut err) = child.stderr.take() {
            thread::spawn(move || {
                let _ = std::io::copy(&mut err, &mut std::io::sink());
            });
        }
        Self { child }
    }

    /// `SIGTERM`, then wait up to 5s for the child to actually exit —
    /// bounded, never a bare kill-and-hope.
    fn shut_down(mut self) {
        let _ = signal::kill(Pid::from_raw(self.child.id() as i32), Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for ReverseGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `qsh hosts --json` in `sandbox`, asserted to succeed, returning the
/// `data.hosts` array.
fn hosts_array(sandbox: &Sandbox) -> Vec<Value> {
    let (code, envelope) = sandbox.json(&["hosts", "--json"]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["command"], "host.list");
    envelope["data"]["hosts"]
        .as_array()
        .expect("data.hosts array")
        .clone()
}

/// Poll `f` (a bare "no daemon can hide this" read every time, never a
/// cached snapshot) until it returns `Some`, or fail after
/// [`POLL_DEADLINE`] — the same hard-deadline-not-fixed-sleep discipline
/// `common::wait_for_audit` documents.
fn poll_until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + POLL_DEADLINE;
    loop {
        if let Some(value) = f() {
            return value;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for {what}");
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn find<'a>(hosts: &'a [Value], mode: &str) -> Option<&'a Value> {
    hosts
        .iter()
        .find(|h| h["name"] == DUP_NAME && h["connection_mode"] == mode)
}

#[test]
fn forward_and_reverse_merge_into_two_entries_route_live_and_hosts_never_dials() {
    let listen_sandbox = Sandbox::initialized();
    let target_sandbox = Sandbox::initialized();
    let listen_fp = listen_sandbox.fingerprint();
    let target_fp = target_sandbox.fingerprint();

    // The listen side pins the target under `DUP_NAME` *with* an address
    // — a forward host, and (once the target dials in) the alias its live
    // registration resolves to.
    listen_sandbox.trust_add(DUP_NAME, Some(UNREACHABLE_ADDRESS), &target_fp);

    // Forward-only, no daemon running yet: `host.list` must return the
    // pinned entry immediately, never attempting to reach
    // `UNREACHABLE_ADDRESS` (`docs/CLI.md` §6.1: "host.list는 dial하지
    // 않는다").
    let start = Instant::now();
    let hosts = hosts_array(&listen_sandbox);
    let elapsed = start.elapsed();
    assert!(
        elapsed < NO_DIAL_BOUND,
        "qsh hosts took {elapsed:?} — looks like it dialed the unreachable forward pin"
    );
    assert_eq!(hosts.len(), 1, "forward-only before any daemon: {hosts:?}");
    assert_eq!(hosts[0]["connection_mode"], "forward");
    assert_eq!(hosts[0]["state"], "unknown");
    assert_eq!(hosts[0]["address"], UNREACHABLE_ADDRESS);

    // Bring up the real daemon and a real reverse target dialing into it.
    let listen = ListenGuard::start(&listen_sandbox);
    target_sandbox.trust_add("hub", Some(listen.addr()), &listen_fp);
    let reverse = ReverseGuard::start(&target_sandbox, "hub");

    // Wait (bounded) for the live registration to show up, then assert
    // the merge never collapsed the two sources by name (`docs/CLI.md`
    // §6.1: same name in both sources → two entries, not one).
    let merged = poll_until("the reverse registration to appear", || {
        let hosts = hosts_array(&listen_sandbox);
        (hosts.len() == 2).then_some(hosts)
    });
    let forward = find(&merged, "forward").expect("forward entry survives the merge");
    assert_eq!(forward["state"], "unknown");
    assert_eq!(forward["address"], UNREACHABLE_ADDRESS);
    let live_reverse = find(&merged, "reverse").expect("live reverse entry");
    assert_eq!(live_reverse["state"], "reachable");
    assert!(
        live_reverse["address"]
            .as_str()
            .is_some_and(|a| a.starts_with("127.0.0.1:")),
        "reverse address should be the target's real loopback peer addr: {live_reverse}"
    );
    assert_eq!(
        live_reverse["device_id"], forward["device_id"],
        "the live reverse registration's TLS-verified fingerprint must equal the forward \
         pin's — both name the same target device (a pin-authenticated connection cannot \
         succeed with a different key)"
    );

    // The human table renders the same name once per `connection_mode` —
    // two rows, not deduplicated (`PLAN.md` M3 Step 5 (a): "같은 이름의 두
    // 항목은 두 행으로 보인다").
    let human = listen_sandbox.qsh(&["hosts"]);
    assert_eq!(common::exit_code(&human), 0);
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    let dup_lines: Vec<&str> = human_stdout
        .lines()
        .filter(|line| line.contains(DUP_NAME))
        .collect();
    assert_eq!(
        dup_lines.len(),
        2,
        "human table must show the duplicate name as two rows, got:\n{human_stdout}"
    );
    assert!(
        dup_lines
            .iter()
            .any(|line| line.contains("forward") && line.contains("unknown")),
        "missing the forward/unknown row:\n{human_stdout}"
    );
    assert!(
        dup_lines
            .iter()
            .any(|line| line.contains("reverse") && line.contains("reachable")),
        "missing the reverse/reachable row:\n{human_stdout}"
    );

    // `resolve_host_route` (shared by `host.get` and, from Step 6,
    // `Ops::connect`): a live reverse registration outranks the forward
    // pin.
    let (code, got) = listen_sandbox.json(&["host", "get", DUP_NAME, "--json"]);
    assert_eq!(code, 0, "{got}");
    assert_eq!(got["command"], "host.get");
    assert_eq!(got["data"]["connection_mode"], "reverse");
    assert_eq!(got["data"]["state"], "reachable");

    // Gracefully end the reverse target — `SIGTERM`, real `CONNECTION_CLOSE`
    // frame, not a `SIGKILL` this test would then have to wait
    // `MAX_IDLE_TIMEOUT` out for.
    reverse.shut_down();

    // The registration must flip to `"stale"`, never vanish outright
    // (`docs/design/protocol.md` §11-4's stale-retention window) — and
    // `host.list` must keep returning the forward entry throughout
    // (listing never fails closed).
    let after_disconnect = poll_until("the reverse registration to go stale", || {
        let hosts = hosts_array(&listen_sandbox);
        find(&hosts, "reverse")
            .filter(|entry| entry["state"] == "stale")
            .is_some()
            .then_some(hosts)
    });
    assert_eq!(
        after_disconnect.len(),
        2,
        "the stale entry must stay listed, not disappear"
    );

    // With the reverse registration no longer live, routing falls back to
    // the forward pin.
    let (code, got) = listen_sandbox.json(&["host", "get", DUP_NAME, "--json"]);
    assert_eq!(code, 0, "{got}");
    assert_eq!(got["data"]["connection_mode"], "forward");
    assert_eq!(got["data"]["state"], "unknown");

    drop(listen);
}

#[test]
fn host_get_on_an_unknown_name_is_host_not_found() {
    let sandbox = Sandbox::initialized();
    let (code, got) = sandbox.json(&["host", "get", "nowhere-at-all", "--json"]);
    assert_eq!(code, 255, "{got}");
    assert_eq!(got["command"], "host.get");
    assert_eq!(got["ok"], false);
    assert_eq!(got["error"]["code"], "HOST_NOT_FOUND");
    assert_eq!(got["error"]["retryable"], false);
}
