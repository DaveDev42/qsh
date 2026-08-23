//! `PLAN.md` M3 Step 9 (c): "도달 불가 controller를 향한 `qsh reverse`가 그
//! 항목을 stderr에 정확히 한 번 내고 stdout에는 아무것도 쓰지 않음
//! (`docs/CLI.md` §2.2)." — a real `qsh reverse` child process, not an
//! in-process call, so this also proves the CLI-level wiring
//! (`crates/qsh-cli/src/main.rs`'s `run_reverse`) and not just the
//! `qsh-core` once-only guard `crates/qsh-core/src/reverse/target.rs`'s
//! own `run_reverse_future_is_send`-adjacent unit tests already cover.
//!
//! `#![cfg(unix)]`: `qsh reverse` itself is unix-only
//! (`docs/CLI.md` §6.13).

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Read};
use std::net::UdpSocket;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::Sandbox;

/// Trust-store alias this test pins to an address nothing listens on.
const CONTROLLER_ALIAS: &str = "unreachable-controller";

/// `qsh_core::doctor::CONTROLLER_UNREACHABLE.message`, copied rather than
/// imported — `qsh-cli`'s tests never depend on `qsh-core` types beyond
/// what `qsh_testkit`/`qsh_transport` already pull in (`qsh-transport.
/// workspace = true` here is scoped to the reverse acceptance harness
/// only, per its own doc comment in `Cargo.toml`), and this file's whole
/// point is to observe the *rendered* stderr text a real subprocess
/// writes, not to call into the constant directly (that half of the
/// anti-drift gate is `crates/qsh-core/tests/doctor_docs.rs`).
const MESSAGE: &str = "Reverse attach needs a directly reachable UDP path from the target to the controller. QSH provides no relay, NAT traversal, or discovery — that is out of scope for P0.";

/// `qsh_core::doctor::CONTROLLER_UNREACHABLE.remedy`, same rationale.
const REMEDY: &str = "Put the controller on a publicly routable address, a forwarded port, or an existing overlay such as WireGuard or Tailscale. If the controller itself is behind NAT, M3 has no answer for that.";

/// Bound on the whole test — generous: on a sandbox without a fast
/// ICMP-port-unreachable path back from a closed loopback UDP port, a
/// single dial attempt against it runs out the clock on
/// `qsh_transport::endpoint::DEFAULT_DIAL_TIMEOUT` (10s) before the target
/// even reaches its first backoff wait, so this bound must comfortably
/// cover at least one full attempt plus [`SETTLE_WINDOW`], not assume a
/// fast local refusal.
const TIMEOUT: Duration = Duration::from_secs(25);

/// Once the diagnostic has appeared at least once, keep watching stderr
/// for this long before declaring "exactly once" — the "at most once"
/// half of the guarantee is actually structural (`run_reverse_unix` wraps
/// the hook in `Option<F>` and takes it, so the closure physically cannot
/// run twice — `crates/qsh-testkit/tests/reverse_unreachable_hook.rs`'s
/// own module docs cover this), so this window only needs to be long
/// enough to be confident the process is not about to print a second line
/// from some other, unrelated path — not long enough to outlast a whole
/// extra 10s dial attempt.
const SETTLE_WINDOW: Duration = Duration::from_millis(800);

#[test]
fn qsh_reverse_prints_the_controller_unreachable_diagnostic_exactly_once() {
    let sandbox = Sandbox::initialized();

    // A UDP port nothing listens on: bind it to claim a real, otherwise
    // unused loopback port, then drop the socket immediately so nothing
    // ever answers there. Whether the OS delivers a fast ICMP
    // port-unreachable back to the dialer or not, this is real
    // unreachability, not a fault injected mid-connection — worst case a
    // single attempt costs the full `qsh_transport::endpoint::
    // DEFAULT_DIAL_TIMEOUT` (10s), which `TIMEOUT` above budgets for.
    let addr = {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a throwaway UDP port");
        socket.local_addr().expect("local addr")
    };

    let fingerprint = sandbox.fingerprint();
    sandbox.trust_add(CONTROLLER_ALIAS, Some(&addr.to_string()), &fingerprint);

    // A near-zero backoff — it barely matters against a ~10s-per-attempt
    // dial timeout either way, but there is no reason to make it worse.
    std::fs::write(
        sandbox.config_dir().join("config.toml"),
        "[reverse]\nbackoff_initial_ms = 10\nbackoff_max_ms = 40\nbackoff_jitter_pct = 0\n",
    )
    .expect("write config.toml");

    let mut child = sandbox
        .command(&["reverse", CONTROLLER_ALIAS])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn qsh reverse");

    let stdout_pipe = child.stdout.take().expect("qsh reverse stdout pipe");
    let stderr_pipe = child.stderr.take().expect("qsh reverse stderr pipe");

    let stdout_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let stderr_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let stdout_reader = {
        let sink = Arc::clone(&stdout_buf);
        thread::spawn(move || {
            let mut pipe = stdout_pipe;
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            sink.lock().unwrap_or_else(|e| e.into_inner()).extend(buf);
        })
    };
    let stderr_reader = {
        let sink = Arc::clone(&stderr_lines);
        thread::spawn(move || {
            for line in BufReader::new(stderr_pipe).lines().map_while(Result::ok) {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(line);
            }
        })
    };

    // Bounded poll: wait for the diagnostic to show up at least once, then
    // keep watching for `SETTLE_WINDOW` more to give a broken guard a real
    // chance to prove itself broken before this test calls it a pass.
    let deadline = Instant::now() + TIMEOUT;
    let mut first_seen: Option<Instant> = None;
    loop {
        let already_settled = {
            let lines = stderr_lines.lock().unwrap_or_else(|e| e.into_inner());
            let count = lines.iter().filter(|line| line.contains(MESSAGE)).count();
            if count >= 1 && first_seen.is_none() {
                first_seen = Some(Instant::now());
            }
            drop(lines);
            first_seen.is_some_and(|seen| seen.elapsed() >= SETTLE_WINDOW)
        };
        if already_settled || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    let _ = child.wait();
    let _ = stdout_reader.join();
    let _ = stderr_reader.join();

    let stdout = stdout_buf.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let stderr = stderr_lines
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    assert!(
        first_seen.is_some(),
        "the controller-unreachable diagnostic never appeared on stderr within {TIMEOUT:?}; \
         stderr so far:\n{}",
        stderr.join("\n")
    );
    assert!(
        stdout.is_empty(),
        "qsh reverse must write nothing to stdout (docs/CLI.md §2.2), got {:?}",
        String::from_utf8_lossy(&stdout)
    );

    let message_count = stderr.iter().filter(|line| line.contains(MESSAGE)).count();
    let remedy_count = stderr.iter().filter(|line| line.contains(REMEDY)).count();
    assert_eq!(
        message_count,
        1,
        "the diagnostic message must appear exactly once, not once per backoff retry; stderr:\n{}",
        stderr.join("\n")
    );
    assert_eq!(
        remedy_count,
        1,
        "the diagnostic remedy must appear exactly once, not once per backoff retry; stderr:\n{}",
        stderr.join("\n")
    );
}
