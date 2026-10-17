//! L5 for the ConPTY backend (`docs/design/testing.md` L5), Windows only:
//! the Windows counterpart of `pty/tests.rs`, with `cmd.exe` as the shell.
//!
//! Real processes, real pseudo-consoles, no fixed sleeps: waits are
//! event-driven `pull`s on the broker or bounded by a hard timeout that only
//! elapses on failure. The injected [`TestClock`] never advances, so the
//! close escalation never fires.
//!
//! ConPTY's output is a rendered VT stream, not the child's bytes: it opens
//! with mode switches, repaints, and wraps long lines. Tests therefore
//! assert on marker strings and on their order relative to `session.exit`,
//! never on the whole byte stream (a Server 2022 conhost and a Windows 11
//! one differ in the preamble).

use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use super::*;
use crate::broker::{
    Broker, BrokerConfig, CloseReason, ConnectionId, ControlEvent, Cursor, ReplayEvent,
    SessionHandle, SourceFactory, TestClock,
};
use crate::fsutil::dacl::testing::{assert_owner_only_report, read_dacl_of_handle};

/// Hard bound: only elapses when the ConPTY backend is broken.
const HARD_TIMEOUT: Duration = Duration::from_secs(60);
/// `pull` wait on the never-advancing test clock (= "until notified").
const FOREVER: Duration = Duration::from_secs(3600);
const CONN: ConnectionId = ConnectionId(7);

async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(HARD_TIMEOUT, fut)
        .await
        .expect("timed out: ConPTY backend stalled")
}

fn conpty_factory() -> Arc<dyn SourceFactory> {
    Arc::new(|_spec: &SessionSpec| Ok(Box::new(ConPtySource::new()) as Box<dyn SessionSource>))
}

fn broker(replay_bytes: usize) -> (Arc<Broker>, TestClock) {
    let clock = TestClock::new();
    let broker = Broker::new(
        Arc::new(clock.clone()),
        BrokerConfig {
            replay_bytes,
            ..BrokerConfig::default()
        },
        conpty_factory(),
    );
    (broker, clock)
}

/// `cmd.exe /d /c <script>`: `/d` skips AutoRun so a user's registry hook
/// cannot change the output.
fn cmd(script: &str) -> SessionSpec {
    SessionSpec {
        argv: vec!["cmd.exe".into(), "/d".into(), "/c".into(), script.into()],
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

fn text(events: &[ReplayEvent]) -> String {
    String::from_utf8_lossy(&output_bytes(events)).into_owned()
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

fn handle_id(handle: &SessionHandle) -> crate::broker::SessionId {
    crate::broker::SessionId(handle.id().to_string())
}

async fn close(broker: &Broker, handle: &SessionHandle) {
    within(broker.close(&handle_id(handle), CloseReason::Closed, None))
        .await
        .unwrap();
}

/// `cmd /c type <file>` over a fresh file of `lines` numbered lines (65
/// bytes each), returning the directory guard (keep it alive) and the script.
fn numbered_file(lines: usize) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lines.txt");
    let mut body = String::with_capacity(lines * 65);
    for i in 1..=lines {
        body.push_str(&format!("L{i:06} {}\r\n", "x".repeat(55)));
    }
    std::fs::write(&path, body).unwrap();
    let script = format!("type {}", path.display());
    (dir, script)
}

// --------------------------------------------------------------------------
// EOF semantics + ordering (the "last byte lost" class of bugs, SC4)
// --------------------------------------------------------------------------

/// `cmd /c echo <marker>`: the marker is in the ring **before**
/// `session.exit` and nothing follows the exit. The pseudo-console only ends
/// its output stream once it is closed, so this also pins that the backend
/// closes it after the child exits.
#[tokio::test]
async fn conpty_last_byte_arrives_before_the_exit_event() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker.open(&cmd("echo qsh-last-byte")).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let idx = exit_index(&events).unwrap();
    let before = text(&events[..idx]);
    assert!(
        before.contains("qsh-last-byte\r\n"),
        "marker missing before session.exit: {before:?}"
    );
    assert!(
        events[idx..]
            .iter()
            .all(|e| !matches!(e, ReplayEvent::Output { .. })),
        "output after session.exit: {events:?}"
    );
    assert_eq!(exit_of(&events), Some((Some(0), None)));
    close(&broker, &handle).await;
}

/// About 1 MiB of lines then an immediate exit: the last line is in the ring
/// before `session.exit`, nothing is dropped from the front (no gap), and
/// nothing follows the exit. The rendered stream carries cursor movement on
/// top of the file, so the count is a lower bound.
#[tokio::test]
async fn conpty_one_mib_of_output_precedes_exit_completely() {
    const LINES: usize = 16_384;
    let (_dir, script) = numbered_file(LINES);
    let (broker, clock) = broker(8 << 20);
    let handle = broker.open(&cmd(&script)).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    assert!(!events.iter().any(|e| matches!(e, ReplayEvent::Gap { .. })));
    let idx = exit_index(&events).unwrap();
    let out = text(&events[..idx]);
    assert!(
        out.contains(&format!("L{LINES:06} ")),
        "the last line is missing before session.exit"
    );
    // Every line, once, in order: the front of the stream is not dropped and
    // the tail is not cut by the close that follows the exit.
    let plain = format!("\n{}", strip_vt(&out));
    let ids: Vec<usize> = plain
        .match_indices("\nL")
        .filter_map(|(i, _)| plain.get(i + 2..i + 8)?.parse().ok())
        .collect();
    assert!(ids.windows(2).all(|w| w[0] <= w[1]), "lines out of order");
    let distinct: std::collections::BTreeSet<_> = ids.iter().copied().collect();
    assert_eq!(
        distinct,
        (1..=LINES).collect::<std::collections::BTreeSet<_>>(),
        "lines went missing before session.exit"
    );
    assert!(
        out.len() >= LINES * 64,
        "only {} bytes arrived before session.exit",
        out.len()
    );
    assert!(
        events[idx..]
            .iter()
            .all(|e| !matches!(e, ReplayEvent::Output { .. })),
        "output after session.exit"
    );
    assert_eq!(exit_of(&events), Some((Some(0), None)));
    close(&broker, &handle).await;
}

/// The reader is never blocked by consumers: with a 64 KiB ring and a
/// consumer that never drains, a multi-MiB writer still completes (the pump
/// keeps reading, the ring evicts).
#[tokio::test]
async fn conpty_reader_is_never_blocked_by_a_slow_consumer() {
    const LINES: usize = 32_768;
    const BUDGET: usize = 64 * 1024;
    let (_dir, script) = numbered_file(LINES);
    let (broker, clock) = broker(BUDGET);
    let handle = broker.open(&cmd(&script)).unwrap();
    // Wait for progress by pulling one byte at the current end (event-driven),
    // never draining.
    let mut pulls = 0u32;
    loop {
        let info = handle.info();
        if info.state == crate::broker::SessionState::Exited {
            break;
        }
        let cursor = Cursor::from_offset(info.last_sequence);
        let _ = within(handle.pull(cursor, 1, FOREVER, &clock))
            .await
            .unwrap();
        pulls += 1;
        assert!(pulls < 1_000_000, "runaway");
    }
    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    let available_from = out
        .events
        .iter()
        .find_map(|e| match e {
            ReplayEvent::Gap { available_from, .. } => Some(*available_from),
            _ => None,
        })
        .expect("a 2 MiB stream in a 64 KiB ring must have a gap");
    assert!(available_from > 0);
    let retained = output_bytes(&out.events).len();
    assert!(retained <= BUDGET, "retained {retained} > budget");
    assert!(handle.info().last_sequence > BUDGET as u64);
    assert_eq!(exit_of(&out.events), Some((Some(0), None)));
    close(&broker, &handle).await;
}

/// The child's exit code reaches `session.exit` unchanged.
#[tokio::test]
async fn conpty_exit_code_is_reported() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker.open(&cmd("exit 7")).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    assert_eq!(exit_of(&events), Some((Some(7), None)));
    close(&broker, &handle).await;
}

// --------------------------------------------------------------------------
// Job Object
// --------------------------------------------------------------------------

/// The pids in `job`, as the kernel lists them.
fn job_pids(job: &JobObject) -> Vec<u32> {
    // The list header is two u32 counts, then one pointer-sized id each.
    let mut buf = vec![0usize; 1 + 64];
    let mut returned = 0u32;
    // SAFETY: `buf` is a writable buffer of the length passed.
    let ok = unsafe {
        QueryInformationJobObject(
            job.raw(),
            JobObjectBasicProcessIdList,
            buf.as_mut_ptr().cast(),
            (buf.len() * size_of::<usize>()) as u32,
            &mut returned,
        )
    };
    assert_ne!(ok, 0, "QueryInformationJobObject failed");
    // SAFETY: the kernel filled the header it is reinterpreted as.
    let header = unsafe { &*buf.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
    let n = header.NumberOfProcessIdsInList as usize;
    buf[1..].iter().take(n).map(|&id| id as u32).collect()
}

/// Poll `job` until it holds at least `count` processes (a child starts its
/// own children asynchronously, so this observes state with a deadline).
async fn job_with_at_least(job: &JobObject, count: usize) -> Vec<u32> {
    let deadline = Instant::now() + HARD_TIMEOUT;
    loop {
        let pids = job_pids(job);
        if pids.len() >= count {
            return pids;
        }
        assert!(
            Instant::now() < deadline,
            "job never reached {count} processes: {pids:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A command whose process tree is two deep: `cmd` runs `ping`, which waits
/// about two minutes unless something ends it.
const LONG_TREE: &str = "ping -n 120 127.0.0.1 >nul";

fn start(script: &str) -> ConPtySession {
    let spec = cmd(script);
    ConPtySession::start(&command_line(&spec.argv), 80, 24).unwrap()
}

/// The unix test checks the child is a session leader on the pty. Here the
/// matching property is membership in the session's job, from the first
/// instruction: the child is in the job and so is what it starts.
#[tokio::test]
async fn conpty_child_is_in_the_session_job_from_creation() {
    let session = start(LONG_TREE);
    let mut member = 0i32;
    // SAFETY: both handles are live and owned by `session`.
    let ok = unsafe {
        IsProcessInJob(
            session.process.as_raw_handle(),
            session.job().raw(),
            &mut member,
        )
    };
    assert_ne!(ok, 0);
    assert_eq!(member, 1, "the child is not in the session job");
    let pids = job_with_at_least(session.job(), 2).await;
    assert!(pids.contains(&session.pid()), "{pids:?}");
}

/// Dropping the session's control ends the whole tree, grandchildren
/// included (the job has `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), which is
/// also what ends it when the host process dies.
#[tokio::test]
async fn conpty_job_close_ends_the_whole_tree() {
    let session = start(LONG_TREE);
    let pids = job_with_at_least(session.job(), 2).await;
    // Hold a handle to each member now: a pid alone could be reused.
    let members: Vec<OwnedHandle> = pids
        .iter()
        .map(|&pid| {
            // SAFETY: `OpenProcess` returns a fresh handle or null.
            let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(!h.is_null(), "OpenProcess({pid}) failed");
            // SAFETY: the handle is fresh and owned here.
            unsafe { OwnedHandle::from_raw_handle(h) }
        })
        .collect();
    for member in &members {
        // SAFETY: a live handle.
        let state = unsafe { WaitForSingleObject(member.as_raw_handle(), 0) };
        assert_eq!(state, WAIT_TIMEOUT, "a member was already gone");
    }
    drop(session.into_spawned().unwrap());
    for (pid, member) in pids.iter().zip(&members) {
        // SAFETY: a live handle.
        let state = unsafe { WaitForSingleObject(member.as_raw_handle(), 30_000) };
        assert_eq!(state, WAIT_OBJECT_0, "process {pid} survived the job close");
    }
}

/// Smoke test: `Kill` as the first signal terminates the job and the session
/// ends with an exit event, without any grace period. The reported status and
/// signal are Step 4's contract (a kill always reports signal KILL) and are
/// not pinned here.
#[tokio::test]
async fn conpty_kill_signal_terminates_the_job() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker.open(&cmd(LONG_TREE)).unwrap();
    within(broker.close(
        &handle_id(&handle),
        CloseReason::Closed,
        Some(crate::broker::Signal::Kill),
    ))
    .await
    .unwrap();
    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    assert!(exit_of(&out.events).is_some(), "{:?}", out.events);
}

// --------------------------------------------------------------------------
// Resize
// --------------------------------------------------------------------------

/// `out` without CSI (`ESC [ ... final`) and OSC (`ESC ] ... BEL`)
/// sequences, which ConPTY interleaves with the text.
fn strip_vt(out: &str) -> String {
    let mut plain = String::with_capacity(out.len());
    let mut chars = out.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            plain.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                for c in chars.by_ref() {
                    if c == '\u{7}' {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    plain
}

/// The numbers of the `mode con` lines shaped `<label>: <number>`, in output
/// order. The labels are localised ("Lines:", "Columns:" on English Windows),
/// the order is not: `mode con` prints the screen buffer's lines, then its
/// columns, then the keyboard settings.
fn mode_numbers(out: &str) -> Vec<u32> {
    strip_vt(out)
        .lines()
        .filter_map(|l| {
            let (_, rest) = l.rsplit_once([':', '\u{ff1a}'])?;
            rest.trim().parse().ok()
        })
        .collect()
}

/// The child asks the console for its size after a resize: `mode con` reads
/// the pseudo-console's screen buffer, so a size the host set with
/// `ResizePseudoConsole` is the size the child reports.
#[tokio::test]
async fn conpty_resize_is_applied_to_the_pseudo_console() {
    let (broker, clock) = broker(1 << 20);
    let handle = broker
        .open(&cmd("echo qsh-ready& set /p wait=& mode con"))
        .unwrap();
    pull_until(&handle, &clock, 4096, |all| text(all).contains("qsh-ready")).await;
    within(handle.resize(100, 31)).await.unwrap();
    within(handle.take_lease("tester", CONN, false))
        .await
        .unwrap();
    within(handle.write(CONN, b"\r".to_vec())).await.unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);
    let numbers = mode_numbers(&out);
    assert_eq!(numbers.get(..2), Some(&[31, 100][..]), "{out:?}");
    close(&broker, &handle).await;
}

// --------------------------------------------------------------------------
// Host pipes
// --------------------------------------------------------------------------

/// Both host pipe ends carry the owner-only DACL: another local user cannot
/// open the pipes and read a session's output or type into it.
#[tokio::test]
async fn conpty_host_pipe_is_owner_only() {
    let session = start("exit 0");
    for (what, handle) in ["output", "input"]
        .into_iter()
        .zip(session.host_pipe_handles())
    {
        assert_owner_only_report(
            &format!("the host {what} pipe"),
            read_dacl_of_handle(handle),
            ObjectKind::Pipe,
        );
    }
}

// --------------------------------------------------------------------------
// Command line
// --------------------------------------------------------------------------

fn quoted(args: &[&str]) -> String {
    let argv: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    command_line(&argv).to_string_lossy().into_owned()
}

/// The quoting rules every MSVCRT `argv` parser undoes.
#[test]
fn command_line_quotes_arguments_the_way_the_c_runtime_parses_them() {
    assert_eq!(
        quoted(&["cmd.exe", "/c", "echo x"]),
        r#"cmd.exe /c "echo x""#
    );
    assert_eq!(quoted(&["a", ""]), r#"a """#);
    assert_eq!(quoted(&["a", r#"say "hi""#]), r#"a "say \"hi\"""#);
    // Backslashes are literal unless a quote follows them.
    assert_eq!(quoted(&["a", r"C:\dir\"]), r"a C:\dir\");
    assert_eq!(quoted(&["a", r"C:\my dir\"]), r#"a "C:\my dir\\""#);
    assert_eq!(quoted(&["a", r#"x\"y"#]), r#"a x\\\"y"#);
}

/// `0` in either dimension means "unknown": 80x24, so a resize to zero can
/// not hand the child a zero-width console.
#[test]
fn zero_size_normalises_to_the_fallback() {
    assert_eq!(normalize_size(0, 40), FALLBACK_SIZE);
    assert_eq!(normalize_size(120, 0), FALLBACK_SIZE);
    assert_eq!(normalize_size(120, 40), (120, 40));
}

/// An argument with a NUL would end the command line early and silently drop
/// the arguments after it, so the source refuses it before creating anything.
#[tokio::test]
async fn nul_in_argv_is_rejected_before_anything_is_created() {
    let mut spec = cmd("exit 0");
    spec.argv[3] = "echo a\0b".into();
    let err = match Box::new(ConPtySource::new()).spawn(&spec) {
        Ok(_) => panic!("a NUL in argv must be refused"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
}
