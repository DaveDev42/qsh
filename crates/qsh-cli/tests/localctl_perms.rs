//! **L2/L5 — localctl socket security and discovery, against a real `qsh
//! listen` OS process** (`PLAN.md` M3 Step 5, PR 5a completion criterion
//! (i): "데몬↔CLI 프로세스 사이에서 registry가 IPC로 조회되고 권한·discovery
//! 테스트가 green").
//!
//! Every other localctl test in the tree (`crates/qsh-core/src/localctl/
//! {frame,client,daemon}.rs`'s own `#[cfg(test)]` modules) proves the
//! protocol and security rules in-process — a fake daemon task, or a real
//! `LocalctlDaemon` driven from the same Tokio runtime as its caller. That
//! is the right tool for framing/logic coverage, but it cannot prove the
//! one fact this file exists for: that the socket a *real, independently
//! scheduled* `qsh listen` process binds is actually locked down from
//! outside, that a peer speaking garbage at it cannot wedge that process,
//! and that this machine's own discovery/admin client library — the exact
//! code `qsh hosts` (PR 5b) will call — round-trips against it.
//! `CARGO_BIN_EXE_qsh` is what makes that a real second OS process (the
//! same reason `serve_sigterm_drain.rs`/`session_kill9.rs` live here rather
//! than in `qsh-testkit`), so every scenario below spawns a real `qsh
//! listen` child and treats it as this test's own OS process treats any
//! other socket peer: no shared memory, no cheating.
//!
//! `#![cfg(unix)]`: localctl (UDS, peer credentials) has no meaning on
//! Windows, and `qsh listen` there never binds a socket at all
//! (`docs/CLI.md` §6.13) — a real listen guard here would just hang
//! waiting for a "listening on" line that is never printed.

#![cfg(unix)]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::Sandbox;
use qsh_core::localctl::client::{self, DiscoverOutcome};
use qsh_proto::ErrorCode;

/// How long we wait for `qsh listen` to report its bound address before
/// declaring the test broken — mirrors `common::ServeGuard`'s own budget.
const LISTEN_START_TIMEOUT: Duration = Duration::from_secs(10);

/// The stderr line `qsh listen` prints once it is up (`main.rs`'s
/// `run_listen`).
const LISTENING_PREFIX: &str = "qsh listen: listening on ";

/// A bound on every "must not hang" assertion below — a real deadline, not
/// a sleep standing in for one.
const BOUND: Duration = Duration::from_secs(10);

/// A running real `qsh listen` child, killed on drop. Deliberately
/// self-contained here rather than folded into `common::ServeGuard`
/// (`qsh serve`'s equivalent): the two commands differ enough (the
/// localctl socket path this file cares about has no `qsh serve`
/// counterpart at all) that sharing one struct would mean threading
/// mode-specific fields through code the `qsh serve` tests never use.
struct ListenGuard {
    child: Child,
    /// The runtime directory this daemon's socket lives under —
    /// `<state_dir>/run`, computed the same way
    /// [`qsh_core::config::Paths::runtime_dir`] does for the "no
    /// `$XDG_RUNTIME_DIR`" branch. `env_remove`d below so both sides of
    /// this test agree on it deterministically, independent of whatever
    /// the ambient environment (CI runner, dev box) happens to export.
    runtime_dir: PathBuf,
}

impl ListenGuard {
    /// Start `qsh listen --bind 127.0.0.1:0` in `sandbox` and wait
    /// (bounded) for it to report it is up.
    fn start(sandbox: &Sandbox) -> Self {
        let runtime_dir = sandbox.state_dir().join("run");
        let mut command = sandbox.command(&["listen", "--bind", "127.0.0.1:0"]);
        command
            // Deterministic runtime dir: force the state-dir fallback
            // (`Paths::runtime_dir`'s documented two-tier rule) regardless
            // of what the host running this test suite happens to export.
            .env_remove("XDG_RUNTIME_DIR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("failed to spawn qsh listen");

        let stderr = child.stderr.take().expect("listen stderr pipe");
        let (tx, rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                if line.starts_with(LISTENING_PREFIX) {
                    let _ = tx.send(());
                    break;
                }
            }
            // Drain (and drop) the rest silently — nothing else here reads
            // the daemon's later stderr lines.
        });
        rx.recv_timeout(LISTEN_START_TIMEOUT)
            .expect("qsh listen never reported a bound address");

        Self { child, runtime_dir }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn socket_path(&self) -> PathBuf {
        self.runtime_dir.join(format!("{}.sock", self.pid()))
    }
}

impl Drop for ListenGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A small multi-thread Tokio runtime for driving the async localctl
/// client library against a real daemon from a plain `#[test]` — the same
/// shape `main.rs`'s own `run_listen`/`run_reverse` build for exactly the
/// same reason (no `#[tokio::test]` needed just to make one async call).
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut)
}

/// A pid this machine can prove is dead right now: spawn a trivial child
/// process and wait for it to exit, so `kill(pid, 0)` on the returned pid
/// is guaranteed `ESRCH` by the time the caller uses it — the one thing
/// `client::discover`'s liveness check (see its own doc) actually trusts
/// before unlinking a socket it found `ECONNREFUSED` on. A fixed-offset
/// guess like "one below some other pid" is not safe for this: pid 1
/// (`launchd`/`init`) is always alive, and any other guess can collide
/// with something genuinely running.
fn a_definitely_dead_pid() -> u32 {
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn a short-lived helper process");
    let status = child.wait().expect("wait for the helper process to exit");
    assert!(status.success(), "helper process must exit cleanly");
    child.id()
}

// ---------------------------------------------------------------------
// Socket and runtime-directory permissions, asserted from outside the
// daemon process (`PLAN.md` M3 Step 5 (a): "디렉터리 0700 · 소켓 0600").
// ---------------------------------------------------------------------

#[test]
fn socket_is_0600_inside_a_0700_runtime_dir_seen_from_outside_the_daemon() {
    let sandbox = Sandbox::initialized();
    let listen = ListenGuard::start(&sandbox);

    let dir_mode = std::fs::metadata(&listen.runtime_dir)
        .expect("runtime dir must exist once the daemon is up")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "the runtime directory a real qsh listen bound into must be 0700"
    );

    let socket_path = listen.socket_path();
    let sock_mode = std::fs::metadata(&socket_path)
        .expect("socket file must exist once the daemon is up")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        sock_mode, 0o600,
        "the socket file a real qsh listen bound must be 0600"
    );
}

// ---------------------------------------------------------------------
// A raw peer speaking garbage is refused without wedging the daemon
// (`PLAN.md` M3 Step 5 (c): "no panic or hang on malformed input").
// ---------------------------------------------------------------------

#[test]
fn a_garbage_peer_is_refused_with_a_bounded_close_and_the_daemon_keeps_serving() {
    let sandbox = Sandbox::initialized();
    let listen = ListenGuard::start(&sandbox);
    let socket_path = listen.socket_path();

    // A declared frame length larger than `CONTROL_FRAME_MAX` (256 KiB) —
    // exactly the "oversize declared length" shape
    // `localctl::frame::tests::oversize_declared_length_is_rejected_as_
    // connection_failed` proves the decoder rejects *before* allocating a
    // payload-sized buffer. Here the daemon is the one holding that
    // decoder, and this test is the peer sending it — the peer-cred check
    // passes (same euid), so this exercises the frame layer, not the
    // credential gate.
    let mut raw = StdUnixStream::connect(&socket_path).expect("connect to a real daemon socket");
    raw.set_read_timeout(Some(BOUND)).expect("set_read_timeout");
    raw.write_all(&u32::MAX.to_be_bytes())
        .expect("write the oversize length header");
    // No payload follows — the daemon must reject on the header alone.

    // The daemon's `serve_conduit` reads the failing frame, gets nothing
    // sensible back, and returns without ever answering — which, on this
    // end, surfaces as a clean, bounded EOF (0 bytes) or a connection
    // reset. Either way it must happen well inside `BOUND`, not hang.
    let mut buf = [0u8; 16];
    match raw.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("garbage peer expected a close, got {n} unexpected bytes"),
        Err(err) if err.kind() == ErrorKind::WouldBlock => {
            panic!("the daemon left a garbage peer hanging past {BOUND:?} instead of closing it")
        }
        // Any other close-shaped error (e.g. `ConnectionReset`) is exactly
        // the "refused, not wedged" outcome this test is checking for.
        Err(_) => {}
    }
    drop(raw);

    // The daemon itself must still be alive and answering — one bad peer
    // must not take the whole accept loop down.
    let hosts = block_on(client::admin_host_list(&socket_path))
        .expect("the daemon must still answer LOCAL_ADMIN after a garbage peer");
    assert!(
        hosts.is_empty(),
        "a fresh qsh listen has nothing registered yet"
    );
}

// ---------------------------------------------------------------------
// Discovery walks a stale socket, unlinks it, and continues to the real
// daemon (`docs/design/architecture.md` §7: "connect가 거부되는 stale
// 소켓은 unlink하고 넘어간다").
// ---------------------------------------------------------------------

#[test]
fn discovery_unlinks_a_stale_socket_ahead_of_the_real_daemon_and_still_finds_it() {
    let sandbox = Sandbox::initialized();
    // A pid that is provably dead by the time discovery runs — spawned and
    // reaped *before* the real daemon below, so it also sorts before it in
    // pid-ascending discovery order (pids are assigned monotonically
    // within one short test run). `discover` now checks `kill(pid, 0)`
    // before unlinking an `ECONNREFUSED` candidate (adversarial review
    // finding: a live daemon can answer `ECONNREFUSED` too — a full accept
    // backlog, or a connect landing in `bind`'s pre-`listen` window — so
    // unconditionally unlinking on that alone can delete a live daemon's
    // socket), which is exactly why a plain `real_pid - 1` guess is no
    // longer safe to use here: pid 1 (`launchd`/`init`) is always alive,
    // and any other fixed-offset guess risks naming a pid that still is.
    let dead_pid = a_definitely_dead_pid();
    let listen = ListenGuard::start(&sandbox);
    let real_pid = listen.pid();
    assert!(
        dead_pid < real_pid,
        "the dead helper pid must sort before the real daemon's pid for pid-ascending \
         discovery to visit it first"
    );

    // A socket file with nothing behind it: bind, then drop the listener
    // immediately, leaving the special file on disk — connecting to it now
    // fails ECONNREFUSED, exactly a crashed daemon's leftover. Named after
    // `dead_pid` so pid-ascending discovery visits it *first*, proving the
    // unlink-and-continue step actually runs rather than this test
    // accidentally only ever reaching the live socket.
    let stale_path = listen.runtime_dir.join(format!("{dead_pid}.sock"));
    {
        let _stale_listener = StdUnixListener::bind(&stale_path).expect("bind the stale socket");
    }
    assert!(
        stale_path.exists(),
        "the stale socket file must exist before discovery"
    );

    // A `LOCAL_ADMIN` probe that treats any answer from a daemon as
    // "found" — PR 5a has no host-specific probe yet (that is PR 5b/Step
    // 6's `LOCAL_CONTROL` job); this is exactly `client.rs`'s own test
    // helper (`probe_via_admin_host_list`), rebuilt here because that one
    // is private to the crate's unit tests.
    let outcome = block_on(client::discover(&listen.runtime_dir, |stream| async move {
        match client::admin_host_list_over(stream).await {
            Ok(hosts) => Ok(DiscoverOutcome::Found(hosts)),
            Err(err) if err.code == ErrorCode::HostNotFound => Ok(DiscoverOutcome::NotFound),
            Err(err) => Err(err),
        }
    }))
    .expect("discovery must reach the real daemon past the stale candidate");

    assert!(
        outcome.is_empty(),
        "the real daemon's registry is empty in this scenario"
    );
    assert!(
        !stale_path.exists(),
        "discovery must unlink a stale (ECONNREFUSED) socket it walks past"
    );
}

// ---------------------------------------------------------------------
// A real `LocalHostList` round trip between two OS processes: this test
// binary's own process (the CLI-side client library) and a real, separately
// scheduled `qsh listen` child (`PLAN.md` M3 Step 5 (i)).
// ---------------------------------------------------------------------

#[test]
fn local_host_list_round_trips_between_two_real_os_processes() {
    let sandbox = Sandbox::initialized();
    let listen = ListenGuard::start(&sandbox);
    let socket_path = listen.socket_path();

    // This call runs in the test binary's own process — a real, distinct
    // OS process from the `qsh listen` child `ListenGuard` just spawned
    // (`Command::new(CARGO_BIN_EXE_qsh)`, the same technique
    // `common::ServeGuard` uses for `qsh serve`). Registering a live
    // reverse host here as well, so the round trip carries real content
    // rather than only proving the empty-registry case, would mean
    // standing up a second real `qsh reverse` target with its own mutual
    // trust pinning against this daemon — a full reverse-registration e2e
    // rig that `PLAN.md` explicitly assigns to Step 7 ("실프로세스 e2e"),
    // not this PR. `daemon.rs`'s own
    // `local_host_list_returns_the_registrys_current_entries_including_stale`
    // already proves the registry-to-`LocalHost` mapping in-process; what
    // is missing there, and what this test is for, is the OS-process
    // boundary itself: real UDS `connect(2)`, a real `SO_PEERCRED`/
    // `getpeereid` syscall against a real other process's euid, real
    // framed I/O, and a real decode on the far side of it.
    let hosts = block_on(client::admin_host_list(&socket_path))
        .expect("LOCAL_ADMIN round trip against a real daemon process");
    assert_eq!(
        hosts,
        Vec::new(),
        "a freshly started qsh listen has no reverse registrations yet"
    );

    // Prove the daemon is still healthy for a second, independent request
    // — nothing about the first round trip left the conduit or the daemon
    // in a bad state.
    let hosts_again = block_on(client::admin_host_list(&socket_path))
        .expect("a second LOCAL_ADMIN round trip against the same real daemon");
    assert!(hosts_again.is_empty());
}
