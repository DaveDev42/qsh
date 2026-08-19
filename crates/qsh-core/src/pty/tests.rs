//! L5 — PTY end-to-end (`docs/design/testing.md` L5), unix only.
//!
//! Real processes, real ptys, **no sleeps**: every wait is either an
//! event-driven `pull` on the broker (woken by the ring's `Notify` when the
//! pump appends) or bounded by a hard timeout that only elapses on failure.
//! The injected [`TestClock`] never advances, so `pull(wait)` blocks purely
//! on OS-driven appends and the close escalation never fires — a session
//! that does not die from the first `SIGHUP` would time the test out
//! instead of being force-cleaned (that is a real bug, not flake).
//!
//! Where macOS and Linux differ (EOF is `0` vs `EIO`; the kernel pty buffer
//! is smaller on macOS so the child blocks earlier) the tests assert the
//! shared invariant, never the platform detail.

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use crate::broker::{
    Broker, BrokerConfig, CloseReason, ConnectionId, ControlEvent, Cursor, ReplayEvent,
    SessionHandle, SessionSpec, SessionState, TestClock,
};

use super::PtySource;

/// Hard bound: only elapses when the PTY backend is broken.
const HARD_TIMEOUT: Duration = Duration::from_secs(60);
/// `pull` wait on the never-advancing test clock (= "until notified").
const FOREVER: Duration = Duration::from_secs(3600);
const CONN: ConnectionId = ConnectionId(7);

async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(HARD_TIMEOUT, fut)
        .await
        .expect("timed out: PTY backend stalled")
}

fn broker(replay_bytes: usize) -> (Arc<Broker>, TestClock) {
    let clock = TestClock::new();
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes,
            ..BrokerConfig::default()
        },
        crate::pty::factory(),
    );
    (broker, clock)
}

fn sh(script: &str) -> SessionSpec {
    SessionSpec {
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        env: vec![],
        term: Some("xterm-qshtest".into()),
        cols: 80,
        rows: 24,
        user: None,
    }
}

fn output_bytes(events: &[ReplayEvent]) -> Vec<u8> {
    let mut v = Vec::new();
    for e in events {
        if let ReplayEvent::Output { data, .. } = e {
            v.extend_from_slice(data);
        }
    }
    v
}

fn exit_index(events: &[ReplayEvent]) -> Option<usize> {
    events.iter().position(|e| {
        matches!(
            e,
            ReplayEvent::Control {
                event: ControlEvent::Exit { .. },
                ..
            }
        )
    })
}

fn exit_of(events: &[ReplayEvent]) -> Option<(Option<i32>, Option<String>)> {
    events.iter().find_map(|e| match e {
        ReplayEvent::Control {
            event: ControlEvent::Exit { exit_code, signal },
            ..
        } => Some((*exit_code, signal.clone())),
        _ => None,
    })
}

/// Pull (event-driven) until `done` holds over everything read so far.
async fn pull_until(
    handle: &SessionHandle,
    clock: &TestClock,
    max_bytes: usize,
    mut done: impl FnMut(&[ReplayEvent]) -> bool,
) -> Vec<ReplayEvent> {
    let mut cursor = Cursor::from_offset(0);
    let mut all = Vec::new();
    loop {
        let out = within(handle.pull(cursor, max_bytes, FOREVER, clock))
            .await
            .expect("pull");
        cursor = out.next;
        all.extend(out.events);
        if done(&all) {
            return all;
        }
    }
}

async fn pull_until_exit(handle: &SessionHandle, clock: &TestClock) -> Vec<ReplayEvent> {
    pull_until(handle, clock, 64 * 1024, |all| exit_index(all).is_some()).await
}

fn text(events: &[ReplayEvent]) -> String {
    String::from_utf8_lossy(&output_bytes(events)).into_owned()
}

/// Let aborted tasks (the pump/writer) be dropped by the scheduler.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

// --------------------------------------------------------------------------
// EOF semantics + ordering (the "last byte lost" class of bugs, SC4)
// --------------------------------------------------------------------------

/// `sh -c 'printf x; exit 0'`: `x` is in the ring **before** `session.exit`
/// on both platforms (Linux master read → `EIO`, macOS → `0`, both after the
/// data). The classic last-line-loss bug is exactly this failing.
#[tokio::test]
async fn last_byte_arrives_before_the_exit_event() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker.open(&sh("printf x; exit 0")).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let idx = exit_index(&events).unwrap();
    assert_eq!(output_bytes(&events[..idx]), b"x", "events: {events:?}");
    assert!(
        events[idx..]
            .iter()
            .all(|e| !matches!(e, ReplayEvent::Output { .. })),
        "output after session.exit: {events:?}"
    );
    assert_eq!(exit_of(&events), Some((Some(0), None)));
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// 1 MiB then immediate exit: every byte is in the ring before
/// `session.exit` is appended, no gap, nothing after it.
#[tokio::test]
async fn one_mib_of_output_precedes_exit_completely() {
    const N: usize = 1 << 20;
    let (broker, clock) = broker(4 << 20);
    let handle = broker
        .open(&sh(&format!("head -c {N} /dev/zero; exit 3")))
        .unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    assert!(!events.iter().any(|e| matches!(e, ReplayEvent::Gap { .. })));
    let idx = exit_index(&events).unwrap();
    let out = output_bytes(&events[..idx]);
    assert_eq!(out.len(), N, "byte count before session.exit");
    assert!(out.iter().all(|&b| b == 0));
    assert!(
        events[idx..]
            .iter()
            .all(|e| !matches!(e, ReplayEvent::Output { .. })),
        "output after session.exit"
    );
    assert_eq!(exit_of(&events), Some((Some(3), None)));
    let info = handle.info();
    assert_eq!(info.state, SessionState::Exited);
    assert_eq!(info.last_sequence, N as u64);
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// Multi-byte characters split across pull boundaries (offsets are bytes,
/// so any split is legal) reassemble byte-identically.
#[tokio::test]
async fn utf8_survives_arbitrary_chunk_boundaries() {
    const WORD: &str = "가나다라마바사아자차카타파하";
    const REPS: usize = 2000;
    let (broker, clock) = broker(4 << 20);
    let script = format!("i=0; while [ $i -lt {REPS} ]; do printf '{WORD}'; i=$((i+1)); done");
    let handle = broker.open(&sh(&script)).unwrap();
    // 1000 is not a multiple of 3, so pull boundaries land mid-character.
    let events = pull_until(&handle, &clock, 1000, |all| exit_index(all).is_some()).await;
    let idx = exit_index(&events).unwrap();
    let out = output_bytes(&events[..idx]);
    let expected = WORD.repeat(REPS);
    assert_eq!(out.len(), expected.len());
    assert_eq!(String::from_utf8(out).unwrap(), expected);
    // At least one individual chunk is *not* valid UTF-8 on its own — the
    // split really happened and the invariant is about the concatenation.
    let split_seen = events[..idx].iter().any(
        |e| matches!(e, ReplayEvent::Output { data, .. } if std::str::from_utf8(data).is_err()),
    );
    assert!(split_seen, "no pull boundary fell inside a character");
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// The PTY reader is never blocked by consumers: with a 64 KiB ring and a
/// consumer that never drains, a 4 MiB writer still completes (the pump
/// keeps reading, the ring evicts). macOS's smaller kernel pty buffer makes
/// the child block earlier than on Linux; the invariant is the same.
#[tokio::test]
async fn pty_reader_is_never_blocked_by_a_slow_consumer() {
    const N: u64 = 4 << 20;
    const BUDGET: usize = 64 * 1024;
    let (broker, clock) = broker(BUDGET);
    let handle = broker
        .open(&sh(&format!("head -c {N} /dev/zero; exit 0")))
        .unwrap();
    // "Slow consumer": never read the bulk. Wait for progress by pulling a
    // single byte at the current end (event-driven), never draining.
    let mut pulls = 0u32;
    loop {
        let info = handle.info();
        if info.state == SessionState::Exited {
            break;
        }
        let cursor = Cursor::from_offset(info.last_sequence);
        let _ = within(handle.pull(cursor, 1, FOREVER, &clock))
            .await
            .unwrap();
        pulls += 1;
        assert!(pulls < 1_000_000, "runaway");
    }
    // Now read from 0: the ring must have evicted (gap) and retain ≤ budget.
    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    let gap = out.events.iter().find_map(|e| match e {
        ReplayEvent::Gap { available_from, .. } => Some(*available_from),
        _ => None,
    });
    let available_from = gap.expect("a 4 MiB stream in a 64 KiB ring must have a gap");
    assert!(available_from > 0);
    let retained = output_bytes(&out.events).len();
    assert!(retained <= BUDGET, "retained {retained} > budget");
    assert_eq!(handle.info().last_sequence, N);
    assert_eq!(exit_of(&out.events), Some((Some(0), None)));
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

// --------------------------------------------------------------------------
// setsid + controlling tty + process group
// --------------------------------------------------------------------------

/// The child is a session leader whose controlling tty is the pty: stdin
/// is a tty, `/dev/tty` opens, and its pgid is its own pid.
#[tokio::test]
async fn child_is_a_session_leader_with_the_pty_as_controlling_tty() {
    let (broker, clock) = broker(1 << 20);
    let script = "test -t 0 && echo TTY_OK; \
                  if (: </dev/tty) 2>/dev/null; then echo CTTY_OK; fi; \
                  echo PGID=$(ps -o pgid= -p $$ | tr -d ' ') PID=$$";
    let handle = broker.open(&sh(script)).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);
    assert!(out.contains("TTY_OK"), "{out}");
    assert!(out.contains("CTTY_OK"), "{out}");
    let pgid = out
        .split("PGID=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or("?");
    let pid = out
        .split("PID=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or("!");
    assert_eq!(pgid, pid, "not the process-group leader: {out}");
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// Job control through the tty: `^C` written to the master delivers
/// `SIGINT` to the foreground process group (only possible when the pty is
/// the child's controlling tty), so the shell blocked in `read` dies and
/// `AFTER` never prints. (`read` is a builtin: no fork/exec window in which
/// a not-yet-exec'd child could swallow the signal — `sh -c '…; sleep 300'`
/// has exactly that race and flaked 1/16 on Linux.)
#[tokio::test]
async fn ctrl_c_on_the_tty_interrupts_the_foreground_group() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker
        .open(&sh("echo READY; read line; echo AFTER"))
        .unwrap();
    pull_until(&handle, &clock, 4096, |all| text(all).contains("READY")).await;
    within(handle.take_lease("tester", CONN, false))
        .await
        .unwrap();
    within(handle.write(CONN, vec![0x03])).await.unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);
    assert!(!out.contains("AFTER"), "shell survived ^C: {out}");
    // bash/dash report 130, zsh may die of SIGINT itself — either way the
    // session ended because of the interrupt.
    let (code, sig) = exit_of(&events).unwrap();
    assert!(
        code == Some(130) || sig.as_deref() == Some("SIGINT") || code.is_some_and(|c| c != 0),
        "unexpected exit {code:?}/{sig:?}: {out}"
    );
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// `close` signals the **whole process group**: the shell's background
/// grandchild (which holds the slave open) is gone too — proven by the
/// master reaching EOF (`session.exit` appended) and the grandchild pid no
/// longer existing.
#[tokio::test]
async fn close_terminates_the_whole_process_group_including_grandchildren() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker
        .open(&sh("sleep 300 & echo GRANDCHILD=$!; wait"))
        .unwrap();
    // `line_value_terminated`, not a `contains("GRANDCHILD=") && contains('\n')`
    // pair: a newline appearing anywhere in the buffer does not prove the
    // GRANDCHILD= line itself is the terminated one, and a still-growing
    // buffer's unterminated tail fragment must not satisfy this predicate
    // (see the helper's doc comment).
    let events = pull_until(&handle, &clock, 4096, |all| {
        line_value_terminated(&text(all), "GRANDCHILD=").is_some()
    })
    .await;
    let out = text(&events);
    let grandchild: libc::pid_t = out
        .split("GRANDCHILD=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no grandchild pid in {out:?}"));
    assert!(process_exists(grandchild), "grandchild not running");

    // Close on the never-advancing clock: only the first SIGHUP is ever
    // sent, so the close resolving at all proves HUP reached every slave
    // holder (EOF) — nothing was force-cleaned.
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    let (code, sig) = exit_of(&out.events).expect("session.exit appended (EOF reached)");
    assert!(
        sig.as_deref() == Some("SIGHUP") || code.is_some(),
        "shell should have died of SIGHUP: {code:?}/{sig:?}"
    );
    assert!(
        matches!(
            out.events.last(),
            Some(ReplayEvent::Control {
                event: ControlEvent::Closed { .. },
                ..
            })
        ),
        "closed must be last: {:?}",
        out.events
    );
    // The grandchild is dead: either fully gone, or a zombie awaiting init's
    // reap (its parent shell is dead), which holds no tty and no fds.
    let mut gone = false;
    for _ in 0..1000 {
        if !process_exists(grandchild) || is_zombie(grandchild) {
            gone = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(gone, "grandchild {grandchild} survived close");
}

// --------------------------------------------------------------------------
// Leaks
// --------------------------------------------------------------------------

/// 100 sequential sessions: every child reaped (no zombies) and the fd
/// table is back to its baseline (no master fd, signal or reactor leak).
#[tokio::test]
async fn hundred_sequential_sessions_leave_no_zombies_and_no_fd_growth() {
    let (broker, clock) = broker(64 * 1024);
    let mut pids: Vec<libc::pid_t> = Vec::new();

    async fn one(broker: &Broker, clock: &TestClock) -> libc::pid_t {
        let slot = Arc::new(AtomicI32::new(0));
        let source = PtySource::new().observe_pid(Arc::clone(&slot));
        let handle = broker
            .open_with(&sh("echo hi; exit 0"), Box::new(source))
            .unwrap();
        let events = pull_until_exit(&handle, clock).await;
        assert!(text(&events).contains("hi"));
        within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
            .await
            .unwrap();
        slot.load(Ordering::SeqCst)
    }

    // Warm up (reactor, signal handler, allocator) then take the baseline.
    for _ in 0..3 {
        one(&broker, &clock).await;
    }
    settle().await;
    let baseline = open_fd_count();

    for _ in 0..100 {
        pids.push(one(&broker, &clock).await);
    }
    // Aborted pump/writer tasks are dropped when the scheduler gets to
    // them; give it bounded turns (no sleep).
    let mut after = open_fd_count();
    for _ in 0..1000 {
        if after <= baseline {
            break;
        }
        tokio::task::yield_now().await;
        after = open_fd_count();
    }
    assert!(after <= baseline, "fd growth: {baseline} -> {after}");

    // Every child was reaped by us: `waitpid` has nothing left (ECHILD),
    // and a zombie would have answered with its pid instead.
    for pid in pids {
        assert!(pid > 0);
        let mut status = 0;
        // SAFETY: plain syscall with a valid out-pointer.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(rc, -1, "pid {pid} still waitable (zombie?)");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "pid {pid}"
        );
    }
}

// --------------------------------------------------------------------------
// Login-shell environment
// --------------------------------------------------------------------------

/// `TERM`, `SHELL`, `HOME`, `USER`/`LOGNAME`, baseline `PATH`, client env
/// overlay; the serve process's own env does not leak; identity keys and
/// `PATH` are pinned.
#[tokio::test]
async fn child_environment_is_the_login_environment_not_ours() {
    // `CARGO_MANIFEST_DIR` is always set in a cargo/nextest test process
    // and is neither passed through nor pinned: it must NOT reach the
    // child. (No `set_var`: other tests read the environment concurrently
    // under plain `cargo test`.)
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    let (broker, clock) = broker(1 << 20);
    let mut spec = sh(
        "echo T=$TERM; echo S=$SHELL; echo H=$HOME; echo U=$USER; echo L=$LOGNAME; \
         echo P=$PATH; echo X=$QSH_EXTRA; echo C=${CARGO_MANIFEST_DIR:-unset}",
    );
    spec.env = vec![
        ("QSH_EXTRA".into(), "extra".into()),
        ("HOME".into(), "/nope".into()),
        ("USER".into(), "root".into()),
        ("PATH".into(), "/nope/bin".into()),
    ];
    let handle = broker.open(&spec).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);
    let name = super::login_name().unwrap();
    // The password-database home, never `$HOME` of this process (they
    // differ e.g. in GH Actions container jobs).
    let home = super::posix::login_home().unwrap();
    assert!(out.contains("T=xterm-qshtest"), "{out}");
    assert!(
        out.contains("S=/"),
        "SHELL should be an absolute path: {out}"
    );
    assert!(!out.contains("H=/nope"), "HOME must be pinned: {out}");
    assert_eq!(
        line_value(&out, "H="),
        Some(home.as_str()),
        "HOME = pw_dir: {out}"
    );
    assert!(
        out.contains(&format!("U={name}")),
        "USER pinned to login name: {out}"
    );
    assert!(out.contains(&format!("L={name}")), "{out}");
    assert_eq!(
        line_value(&out, "P="),
        Some(super::posix::DEFAULT_PATH),
        "PATH pinned to the baseline (argv is exec'd directly, no profile): {out}"
    );
    assert!(out.contains("X=extra"), "client env overlay: {out}");
    assert!(out.contains("C=unset"), "serve process env leaked: {out}");
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// Empty `argv` ⇒ login shell with `argv[0] = "-<basename>"`, interactive
/// on a controlling tty (`test -t 0` succeeds; bash would otherwise print
/// "job control turned off"). Uses `/bin/sh` as the login shell so the
/// assertion does not depend on the developer's account; on macOS
/// `/etc/profile` runs `path_helper`, which must extend the baseline `PATH`.
#[tokio::test]
async fn empty_argv_runs_a_login_shell_with_dash_argv0() {
    let (broker, clock) = broker(1 << 20);
    let spec = SessionSpec {
        argv: vec![],
        env: vec![],
        term: Some("dumb".into()),
        cols: 80,
        rows: 24,
        user: None,
    };
    let source = PtySource::new().with_login_shell("/bin/sh");
    let handle = broker.open_with(&spec, Box::new(source)).unwrap();
    // Wait for the interactive shell's first output (its prompt) before
    // typing: a shell that preps the terminal with `TCSAFLUSH` would
    // discard typeahead sent earlier.
    pull_until(&handle, &clock, 4096, |all| !output_bytes(all).is_empty()).await;
    within(handle.take_lease("tester", CONN, false))
        .await
        .unwrap();
    within(
        handle.write(
            CONN,
            b"echo ARGV0=$0; test -t 0 && echo TTY_OK; echo LPATH=$PATH; echo QSH_DONE\nexit\n"
                .to_vec(),
        ),
    )
    .await
    .unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);
    assert!(out.contains("ARGV0=-sh"), "not a login shell: {out}");
    assert!(
        out.contains("TTY_OK"),
        "stdin is not the controlling tty: {out}"
    );
    assert!(
        !out.contains("job control turned off"),
        "no controlling tty: {out}"
    );
    #[cfg(target_os = "macos")]
    {
        // /etc/profile → path_helper: the baseline PATH grew (e.g. by
        // /usr/local/bin from /etc/paths).
        // The typed line is echoed (by the tty and by readline) before the
        // value prints; the value is the occurrence that starts with `/`.
        let lpath = out
            .split("LPATH=")
            .skip(1)
            .filter_map(|s| s.split_whitespace().next())
            .find(|s| s.starts_with('/'))
            .unwrap_or("");
        assert!(
            lpath.split(':').count() > super::posix::DEFAULT_PATH.split(':').count(),
            "path_helper did not run: {lpath:?} in {out}"
        );
    }
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// A `user` hint naming anyone but the serve account fails closed before
/// anything is spawned: `BrokerError::Unsupported` (→ `UNSUPPORTED`) with
/// the CLI.md §7 message.
#[tokio::test]
async fn foreign_user_hint_is_unsupported_and_spawns_nothing() {
    let (broker, _clock) = broker(1 << 20);
    let mut spec = sh("echo never");
    spec.user = Some(format!("not-{}", super::login_name().unwrap()));
    let err = broker.open(&spec).unwrap_err();
    assert!(
        matches!(err, crate::broker::BrokerError::Unsupported(_)),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "user switching is not supported");
    assert_eq!(broker.session_count(), 0);

    // The account's own name is accepted.
    spec.user = Some(super::login_name().unwrap());
    let handle = broker.open(&spec).unwrap();
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// A spawn that fails *after* the fork (fd exhaustion on the master dup,
/// reactor registration) must not leave a live child or a zombie: the
/// cleanup guard kills and reaps it.
#[test]
fn post_fork_spawn_failure_kills_and_reaps_the_child() {
    let child = std::process::Command::new("sleep")
        .arg("300")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    std::mem::forget(child); // like `portable_pty::Child`: no kill, no wait
    assert!(process_exists(pid));
    drop(super::posix::SpawnCleanup { pid: Some(pid) });
    // Reaped: nothing left to wait for, and the pid is not a zombie.
    let mut status = 0;
    // SAFETY: plain syscall with a valid out-pointer.
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    assert_eq!(rc, -1, "pid {pid} still waitable");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(!process_exists(pid), "pid {pid} still exists after cleanup");
}

/// Resize reaches the pty (`TIOCSWINSZ`): the child observes the new size.
/// A `0` dimension is normalised to 80x24 exactly like `spawn` does, so a
/// `session.resize --cols 0` can never hand the child a zero-width terminal
/// (the two paths must not disagree).
#[tokio::test]
async fn resize_is_applied_to_the_pty() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker
        .open(&sh(
            "echo READY; read a; echo SIZE=$(stty size); read b; echo ZERO=$(stty size)",
        ))
        .unwrap();
    pull_until(&handle, &clock, 4096, |all| text(all).contains("READY")).await;
    within(handle.resize(132, 43)).await.unwrap();
    within(handle.take_lease("tester", CONN, false))
        .await
        .unwrap();
    within(handle.write(CONN, b"go\n".to_vec())).await.unwrap();
    // `line_value_terminated`, not `line_value`: this predicate polls a
    // buffer that is still growing, so it must not be satisfied by the
    // SIZE= line before its trailing newline has actually arrived (see the
    // helper's doc comment).
    pull_until(&handle, &clock, 4096, |all| {
        line_value_terminated(&text(all), "SIZE=").is_some()
    })
    .await;
    within(handle.resize(0, 0)).await.unwrap();
    within(handle.write(CONN, b"go\n".to_vec())).await.unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);
    assert_eq!(line_value(&out, "SIZE="), Some("43 132"), "{out}");
    assert_eq!(
        line_value(&out, "ZERO="),
        Some("24 80"),
        "resize(0, 0) must normalise to 80x24 like spawn: {out}"
    );
    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

/// The rest of the first line that starts with `prefix` (tty output has
/// `\r\n` line endings; both are trimmed).
fn line_value<'a>(out: &'a str, prefix: &str) -> Option<&'a str> {
    out.lines()
        .map(|l| l.trim_end_matches('\r'))
        .find_map(|l| l.strip_prefix(prefix))
}

/// Like `line_value`, but only matches a line that is actually
/// newline-terminated in `out`. `str::lines()` is lenient about the tail: an
/// unterminated trailing fragment is still yielded as if it were a complete
/// line, so a predicate polling a buffer that may still be growing can match
/// on a half-written line just before its newline arrives — and the next
/// write's echo can then land ahead of that pending newline on the kernel
/// tty, corrupting the very value that was just matched. Use this (not
/// `line_value`) for any predicate evaluated against a buffer that has not
/// yet reached a known-final state (e.g. session exit).
fn line_value_terminated<'a>(out: &'a str, prefix: &str) -> Option<&'a str> {
    let terminated = if out.ends_with('\n') {
        out
    } else {
        out.rsplit_once('\n').map_or("", |(head, _)| head)
    };
    line_value(terminated, prefix)
}

fn handle_id(handle: &SessionHandle) -> crate::broker::SessionId {
    crate::broker::SessionId(handle.id().to_string())
}

fn process_exists(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only checks existence/permission.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn is_zombie(pid: libc::pid_t) -> bool {
    std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.trim().is_empty() || s.trim().starts_with('Z')
        })
        .unwrap_or(false)
}

/// Number of open descriptors in this process (`/dev/fd` exists on both
/// macOS and Linux — a symlink to `/proc/self/fd` there).
fn open_fd_count() -> usize {
    std::fs::read_dir("/dev/fd")
        .map(|d| d.count())
        .expect("/dev/fd readable")
}
