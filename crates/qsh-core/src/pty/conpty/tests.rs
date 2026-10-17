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

use windows_sys::Win32::Foundation::{
    CloseHandle, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Environment::SetEnvironmentVariableW;
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, GetCurrentProcess, GetProcessHandleCount, OpenProcess, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW, WaitForSingleObject,
};

use super::*;
use crate::broker::BrokerError;
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

/// A handle to each of `pids`, so a pid cannot be reused while a test waits
/// on it.
fn open_members(pids: &[u32]) -> Vec<OwnedHandle> {
    pids.iter()
        .map(|&pid| {
            // SAFETY: `OpenProcess` returns a fresh handle or null.
            let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(!h.is_null(), "OpenProcess({pid}) failed");
            // SAFETY: the handle is fresh and owned here.
            unsafe { OwnedHandle::from_raw_handle(h) }
        })
        .collect()
}

/// Every process in `members` has ended (within the hard bound).
fn assert_all_ended(members: &[OwnedHandle], pids: &[u32], what: &str) {
    for (pid, member) in pids.iter().zip(members) {
        // SAFETY: a live handle.
        let state = unsafe { WaitForSingleObject(member.as_raw_handle(), 30_000) };
        assert_eq!(state, WAIT_OBJECT_0, "process {pid} survived {what}");
    }
}

/// The processes started, directly or not, by `root`, as a Toolhelp snapshot
/// lists them (parent links outlive a dead parent, so a pid that was reused
/// could be listed; the callers hold a live handle to `root`).
fn descendants(root: u32) -> Vec<u32> {
    // SAFETY: a snapshot handle, closed below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    assert_ne!(snapshot, INVALID_HANDLE_VALUE, "CreateToolhelp32Snapshot");
    let mut all: Vec<(u32, u32)> = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    // SAFETY: `entry` is a live struct with `dwSize` set; `snapshot` is open.
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    while ok != 0 {
        all.push((entry.th32ProcessID, entry.th32ParentProcessID));
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    // SAFETY: `snapshot` is open and closed once.
    unsafe { CloseHandle(snapshot) };
    let mut found: Vec<u32> = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for &(pid, ppid) in &all {
            if ppid == parent && pid != root && !found.contains(&pid) {
                found.push(pid);
                frontier.push(pid);
            }
        }
    }
    found
}

/// Poll until `root` has at least `count` descendants (they start
/// asynchronously), with a deadline.
async fn descendants_of(root: u32, count: usize) -> Vec<u32> {
    let deadline = Instant::now() + HARD_TIMEOUT;
    loop {
        let found = descendants(root);
        if found.len() >= count {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "{root} never reached {count} descendants: {found:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A command whose process tree is two deep: `cmd` runs `ping`, which waits
/// about two minutes unless something ends it.
const LONG_TREE: &str = "ping -n 120 127.0.0.1 >nul";

/// [`LONG_TREE`] with `ping`'s output left on the console. Its first reply
/// line carries `127.0.0.1:` in every locale (the title ConPTY renders from
/// the command line has no colon), so seeing it proves `ping` is attached
/// to the pseudo-console and running.
const VISIBLE_TREE: &str = "ping -n 120 127.0.0.1";
const PING_REPLY: &str = "127.0.0.1:";

fn start(script: &str) -> ConPtySession {
    start_spec(&cmd(script))
}

fn start_spec(spec: &SessionSpec) -> ConPtySession {
    let events = Arc::new(SignalEvents::create().unwrap());
    let launch = plan(spec, &events).unwrap();
    ConPtySession::start(&launch, events, 80, 24).unwrap()
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
    let members = open_members(&pids);
    for member in &members {
        // SAFETY: a live handle.
        let state = unsafe { WaitForSingleObject(member.as_raw_handle(), 0) };
        assert_eq!(state, WAIT_TIMEOUT, "a member was already gone");
    }
    drop(session.into_spawned().unwrap());
    assert_all_ended(&members, &pids, "the job close");
}

/// `Kill` as the first signal terminates the job and the session ends with
/// an exit event, without any grace period. The exit reports the signal the
/// kill stands for (the job's processes end with status 1).
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
    assert_eq!(
        exit_of(&out.events),
        Some((Some(1), Some("SIGKILL".to_string()))),
        "{:?}",
        out.events
    );
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
// Session close: the whole job, and the order of the steps
// --------------------------------------------------------------------------

/// The session's root process, observed through the source hook.
fn observed_root(slot: &Arc<std::sync::Mutex<Vec<Arc<OwnedHandle>>>>) -> (u32, Arc<OwnedHandle>) {
    let root = Arc::clone(slot.lock().unwrap().first().expect("a spawned child"));
    (process_id(&root), root)
}

fn process_id(process: &OwnedHandle) -> u32 {
    // SAFETY: a live process handle.
    let pid =
        unsafe { windows_sys::Win32::System::Threading::GetProcessId(process.as_raw_handle()) };
    assert_ne!(pid, 0, "GetProcessId failed");
    pid
}

/// Closing the session ends the root and everything it started: the unix
/// test asserts the grandchild is gone after a `SIGHUP` to the process
/// group. Here the first step is `ClosePseudoConsole`, so the close
/// resolving at all on the never-advancing clock (no escalation can fire)
/// proves that step ended the tree, and the job is what guarantees nothing
/// is left behind.
#[tokio::test]
async fn conpty_close_terminates_the_whole_job_including_grandchildren() {
    let (broker, clock) = broker(1 << 20);
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let source = ConPtySource::new().observe_processes(Arc::clone(&observed));
    let handle = broker
        .open_with(&cmd(VISIBLE_TREE), Box::new(source))
        .unwrap();
    let (root_pid, root) = observed_root(&observed);
    // The grandchild existing in a process snapshot is not enough: until it
    // has attached to the console it has no handler for the close event, so
    // the close would miss it and (with the clock frozen, no escalation)
    // wait for `ping` to finish. A real session would be ended by the
    // escalation's `TerminateJobObject`; this test pins the console close.
    // Its first reply line is proof of attachment.
    pull_until(&handle, &clock, usize::MAX, |ev| {
        text(ev).contains(PING_REPLY)
    })
    .await;
    let grandchildren = descendants_of(root_pid, 1).await;
    // Hold handles first: a pid alone could be reused.
    let members = open_members(&grandchildren);
    for member in &members {
        // SAFETY: a live handle.
        let state = unsafe { WaitForSingleObject(member.as_raw_handle(), 0) };
        assert_eq!(state, WAIT_TIMEOUT, "a grandchild was already gone");
    }

    within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
        .await
        .unwrap();
    let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
        .await
        .unwrap();
    assert!(exit_of(&out.events).is_some(), "{:?}", out.events);
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
    assert_all_ended(&members, &grandchildren, "the session close");
    // SAFETY: a live handle.
    let state = unsafe { WaitForSingleObject(root.as_raw_handle(), 30_000) };
    assert_eq!(state, WAIT_OBJECT_0, "the session root survived the close");
}

/// A signal-less `session close` starts with `ClosePseudoConsole` (the
/// `Hup` step) and, when that is not enough, the escalation ends the job.
/// The escalation's `Term` is the same event, so it sends nothing again;
/// `Kill` is `TerminateJobObject`, which also reaches a process that is in
/// the job but not on the console.
#[tokio::test]
async fn conpty_close_without_a_signal_starts_with_close_pseudo_console_and_escalates_to_terminate_job()
 {
    // Through the broker: with no signal named, and a clock that never
    // advances (no escalation), the only step taken is the console close,
    // and it is enough to end the session.
    {
        let (broker, clock) = broker(1 << 20);
        let log = StageLog::default();
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let source = ConPtySource::new()
            .observe_stages(Arc::clone(&log))
            .observe_processes(Arc::clone(&observed));
        let handle = broker
            .open_with(&cmd(VISIBLE_TREE), Box::new(source))
            .unwrap();
        // Close a session that is up (a console closed before the child has
        // attached to it never tells the child anything; the escalation is
        // what ends such a session, which this clock never fires). A process
        // snapshot showing the child is not enough, so wait for its first
        // reply line on the console.
        let (root_pid, _root) = observed_root(&observed);
        pull_until(&handle, &clock, usize::MAX, |ev| {
            text(ev).contains(PING_REPLY)
        })
        .await;
        descendants_of(root_pid, 1).await;
        within(broker.close(&handle_id(&handle), CloseReason::Closed, None))
            .await
            .unwrap();
        let out = within(handle.pull(Cursor::from_offset(0), usize::MAX, FOREVER, &clock))
            .await
            .unwrap();
        assert!(exit_of(&out.events).is_some(), "{:?}", out.events);
        assert_eq!(*log.lock().unwrap(), vec![Stage::CloseConsole]);
    }

    // The steps themselves, in the order the broker's escalation sends them
    // (HUP, TERM, KILL), against a session that also has a process the
    // console close cannot reach: it is in the job, not on the console.
    let session = start(VISIBLE_TREE);
    let log = Arc::clone(&session.log);
    let outside_command = OsString::from("ping -n 120 127.0.0.1");
    let outside_exe = winproc::windows_directory()
        .map(|dir| Path::new(&dir).join("System32").join("PING.EXE"))
        .unwrap();
    let outside = winproc::spawn_in_job(
        session.job(),
        &ProcessSpec {
            application: Some(outside_exe.as_os_str()),
            command_line: &outside_command,
            creation_flags: CREATE_NO_WINDOW,
            pseudo_console: None,
            environment: None,
            current_dir: None,
        },
    )
    .unwrap();
    let root = Arc::clone(&session.process);
    descendants_of(session.pid(), 1).await;
    let mut spawned = session.into_spawned().unwrap();
    // The session is the console's only reader: read until the console child
    // has printed its first reply line (proof it is attached to the console
    // and so will see the close event), then keep draining so the close
    // below can never wait on us.
    let mut output = spawned.output;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    while !String::from_utf8_lossy(&seen).contains(PING_REPLY) {
        let n = within(tokio::io::AsyncReadExt::read(&mut output, &mut chunk))
            .await
            .unwrap();
        assert_ne!(n, 0, "the console ended before ping replied");
        seen.extend_from_slice(&chunk[..n]);
    }
    let drain = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut output, &mut sink).await;
    });

    spawned.control.signal(crate::broker::Signal::Hup).unwrap();
    assert_eq!(*log.lock().unwrap(), vec![Stage::CloseConsole]);
    // Everything on the console ends with it.
    // SAFETY: a live handle.
    let state = unsafe { WaitForSingleObject(root.as_raw_handle(), 30_000) };
    assert_eq!(state, WAIT_OBJECT_0, "the root outlived the console close");
    // `Term` is the same event: nothing is sent a second time.
    spawned.control.signal(crate::broker::Signal::Term).unwrap();
    assert_eq!(*log.lock().unwrap(), vec![Stage::CloseConsole]);
    // The process outside the console is still there.
    // SAFETY: a live handle.
    let state = unsafe { WaitForSingleObject(outside.handle.as_raw_handle(), 0) };
    assert_eq!(
        state, WAIT_TIMEOUT,
        "the console close reached the job-only process"
    );

    spawned.control.signal(crate::broker::Signal::Kill).unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![Stage::CloseConsole, Stage::TerminateJob]
    );
    // SAFETY: a live handle.
    let state = unsafe { WaitForSingleObject(outside.handle.as_raw_handle(), 30_000) };
    assert_eq!(
        state, WAIT_OBJECT_0,
        "TerminateJobObject left a member running"
    );
    drain.abort();
}

// --------------------------------------------------------------------------
// Leaks and failed spawns
// --------------------------------------------------------------------------

/// A failure after the child exists (here: the exit watch cannot be
/// registered) must not leave it running: the session's job goes with the
/// error, and the child and what it started are in that job from the first
/// instruction. The unix test kills and reaps a half-spawned child; here
/// there is nothing to reap, only the job to close.
#[tokio::test]
async fn conpty_spawn_failure_leaves_no_process_in_the_job() {
    let session = start(LONG_TREE);
    let pids = job_with_at_least(session.job(), 2).await;
    let members = open_members(&pids);
    let result =
        session.into_spawned_with(|_| Err(io::Error::other("injected exit-watch failure")));
    let err = match result {
        Ok(_) => panic!("the injected failure must fail the spawn"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("injected"), "{err}");
    assert_all_ended(&members, &pids, "a failed spawn");
}

/// This process's open handle count.
fn handle_count() -> u32 {
    let mut count = 0u32;
    // SAFETY: the pseudo-handle of this process and a local out-pointer.
    let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
    assert_ne!(ok, 0, "GetProcessHandleCount failed");
    count
}

/// 100 sequential sessions: every child has ended (nothing left running) and
/// the process's handle table is back to its baseline (no pipe, console,
/// job, watch or process handle leaks). The unix test counts zombies and
/// descriptors.
#[tokio::test]
async fn hundred_sequential_conpty_sessions_leave_no_processes_and_no_handle_growth() {
    let (broker, clock) = broker(64 * 1024);
    let observed: Arc<std::sync::Mutex<Vec<Arc<OwnedHandle>>>> = Arc::default();

    async fn one(
        broker: &Broker,
        clock: &TestClock,
        observed: &Arc<std::sync::Mutex<Vec<Arc<OwnedHandle>>>>,
    ) {
        let source = ConPtySource::new().observe_processes(Arc::clone(observed));
        let handle = broker.open_with(&cmd("echo hi"), Box::new(source)).unwrap();
        let events = pull_until_exit(&handle, clock).await;
        assert!(text(&events).contains("hi"));
        close(broker, &handle).await;
    }

    // Warm up (reactor, thread pools, allocator) then take the baseline.
    for _ in 0..3 {
        one(&broker, &clock, &observed).await;
    }
    observed.lock().unwrap().clear();
    let baseline = settled_handle_count().await;

    for _ in 0..100 {
        one(&broker, &clock, &observed).await;
    }
    // Every child has ended; the handles the hook holds are what keeps the
    // pids from being reused meanwhile.
    let spawned: Vec<Arc<OwnedHandle>> = std::mem::take(&mut *observed.lock().unwrap());
    assert_eq!(spawned.len(), 100);
    for process in &spawned {
        // SAFETY: a live handle.
        let state = unsafe { WaitForSingleObject(process.as_raw_handle(), 30_000) };
        assert_eq!(state, WAIT_OBJECT_0, "a session child is still running");
    }
    drop(spawned);

    // Aborted pump and writer tasks are dropped when the scheduler gets to
    // them: observe with a deadline until the count settles.
    let after = settled_handle_count().await;
    assert!(after <= baseline, "handle growth: {baseline} -> {after}");
}

/// The handle count once it stops falling (or the deadline passes), for
/// teardown that completes on other tasks and threads.
async fn settled_handle_count() -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut best = handle_count();
    let mut stable = 0;
    while stable < 10 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let now = handle_count();
        if now < best {
            best = now;
            stable = 0;
        } else {
            stable += 1;
        }
    }
    best
}

// --------------------------------------------------------------------------
// Account, environment, shell
// --------------------------------------------------------------------------

/// Set a variable in this process the way a hostile serve environment would
/// carry one. `std::env::set_var` is `unsafe` because the C runtime's
/// environment is not synchronised; `SetEnvironmentVariableW` is.
fn set_process_variable(name: &str, value: &str) {
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let ok = unsafe { SetEnvironmentVariableW(wide(name).as_ptr(), wide(value).as_ptr()) };
    assert_ne!(ok, 0, "SetEnvironmentVariableW failed");
}

/// The text after `prefix` on the first output line that starts with it.
fn line_value(out: &str, prefix: &str) -> Option<String> {
    strip_vt(out)
        .lines()
        .find_map(|l| l.strip_prefix(prefix))
        .map(|v| v.trim_end().to_string())
}

fn user_value(user_env: &[(String, String)], key: &str) -> String {
    env_policy::windows_lookup(user_env, key)
        .unwrap_or_else(|| panic!("the user environment has no {key}"))
        .to_string()
}

/// The child's environment is the user's environment block plus `TERM` and
/// the client's `env`; what is only in the `qsh serve` process (here a
/// variable no logon defines) does not reach it, and the identity variables
/// are the account's.
#[tokio::test]
async fn conpty_child_environment_is_the_user_block_not_ours() {
    const LEAK: &str = "QSH_CONPTY_TEST_LEAK";
    set_process_variable(LEAK, "from-the-serve-process");
    assert!(std::env::var_os(LEAK).is_some());
    let user_env = winproc::user_environment().unwrap();
    assert!(
        env_policy::windows_lookup(&user_env, LEAK).is_none(),
        "the user block must not carry the serve process's variables"
    );

    let (broker, clock) = broker(1 << 20);
    let mut spec = cmd(&format!(
        "echo T=%TERM%& echo U=%USERNAME%& echo P=%USERPROFILE%& echo X=%QSH_EXTRA%& \
         echo L=%{LEAK}%& echo C=%CD%& echo R=%SystemRoot%"
    ));
    spec.env = vec![("QSH_EXTRA".into(), "extra".into())];
    let handle = broker.open(&spec).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);

    assert_eq!(
        line_value(&out, "T=").as_deref(),
        Some("xterm-qshtest"),
        "{out}"
    );
    assert_eq!(line_value(&out, "X=").as_deref(), Some("extra"), "{out}");
    // `cmd` leaves an undefined variable's reference as written.
    assert_eq!(
        line_value(&out, "L=").as_deref(),
        Some(format!("%{LEAK}%").as_str()),
        "the serve process's variable reached the child: {out}"
    );
    let profile = user_value(&user_env, "USERPROFILE");
    assert_eq!(
        line_value(&out, "P=").as_deref(),
        Some(profile.as_str()),
        "{out}"
    );
    let name = user_value(&user_env, "USERNAME");
    assert_eq!(
        line_value(&out, "U=").as_deref(),
        Some(name.as_str()),
        "{out}"
    );
    assert!(
        super::login_name().unwrap().eq_ignore_ascii_case(&name),
        "USERNAME is the token's account"
    );
    // The working directory is the profile directory.
    assert!(
        line_value(&out, "C=").is_some_and(|c| c.eq_ignore_ascii_case(&profile)),
        "{out}"
    );
    let root = user_value(&user_env, "SystemRoot");
    assert_eq!(
        line_value(&out, "R=").as_deref(),
        Some(root.as_str()),
        "{out}"
    );
    close(&broker, &handle).await;
}

/// The client's `env` cannot change a pinned key, whatever the case of its
/// name: the variables below name the same variable as a pinned one on
/// Windows.
#[tokio::test]
async fn conpty_pinned_keys_cannot_be_overridden_case_insensitively() {
    let user_env = winproc::user_environment().unwrap();
    let (broker, clock) = broker(1 << 20);
    let mut spec = cmd(
        "echo A=%PATH:~0,12%& echo B=%USERPROFILE%& echo D=%COMSPEC%& echo E=%SystemRoot%& \
         echo F=%USERNAME%& echo G=%HOME%& echo H=%QSH_FREE%",
    );
    spec.env = vec![
        ("path".into(), r"C:\evil".into()),
        ("UserProfile".into(), r"C:\evil".into()),
        ("comspec".into(), r"C:\evil\cmd.exe".into()),
        ("SYSTEMROOT".into(), r"C:\evil".into()),
        ("UserName".into(), "evil".into()),
        ("Home".into(), r"C:\evil".into()),
        ("QSH_FREE".into(), "free".into()),
    ];
    let handle = broker.open(&spec).unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);

    let path_head: String = user_value(&user_env, "PATH").chars().take(12).collect();
    assert_eq!(
        line_value(&out, "A=").as_deref(),
        Some(path_head.as_str()),
        "{out}"
    );
    for (prefix, key) in [
        ("B=", "USERPROFILE"),
        ("D=", "COMSPEC"),
        ("E=", "SystemRoot"),
        ("F=", "USERNAME"),
    ] {
        let want = user_value(&user_env, key);
        assert_eq!(
            line_value(&out, prefix).as_deref(),
            Some(want.as_str()),
            "{key} was overridden: {out}"
        );
    }
    // A pinned key the user's environment does not define stays undefined.
    assert_eq!(line_value(&out, "G=").as_deref(), Some("%HOME%"), "{out}");
    // The rest of the overlay still applies.
    assert_eq!(line_value(&out, "H=").as_deref(), Some("free"), "{out}");
    close(&broker, &handle).await;
}

/// A `user` hint naming anyone but the token's account fails closed before
/// anything is spawned: `BrokerError::Unsupported` (-> `UNSUPPORTED`) with
/// the CLI.md §7 message. Both spellings of the account are accepted.
#[tokio::test]
async fn conpty_foreign_user_hint_is_unsupported_and_spawns_nothing() {
    let (broker, _clock) = broker(1 << 20);
    let me = super::login_name().unwrap();
    let mut spec = cmd("exit 0");
    spec.user = Some(format!("not-{me}"));
    let err = broker.open(&spec).unwrap_err();
    assert!(matches!(err, BrokerError::Unsupported(_)), "{err:?}");
    assert_eq!(err.to_string(), "user switching is not supported");
    assert_eq!(broker.session_count(), 0);

    // `DOMAIN\user` with another domain is another account.
    spec.user = Some(format!(r"NOT-A-DOMAIN\{me}"));
    assert!(matches!(
        broker.open(&spec).unwrap_err(),
        BrokerError::Unsupported(_)
    ));
    assert_eq!(broker.session_count(), 0);

    // The account's own names are accepted, in any case.
    for hint in winproc::account_names()
        .unwrap()
        .into_iter()
        .flat_map(|n| [n.to_uppercase(), n.to_lowercase(), n])
    {
        spec.user = Some(hint.clone());
        let handle = broker
            .open(&spec)
            .unwrap_or_else(|e| panic!("{hint}: {e:?}"));
        close(&broker, &handle).await;
    }
}

/// An empty `argv` runs the user's `COMSPEC` as a full path, in the profile
/// directory.
#[tokio::test]
async fn conpty_empty_argv_runs_comspec_in_userprofile() {
    let user_env = winproc::user_environment().unwrap();
    let comspec = user_value(&user_env, "COMSPEC");
    let profile = user_value(&user_env, "USERPROFILE");
    let mut spec = cmd("");
    spec.argv.clear();

    // The image the root process runs.
    let events = Arc::new(SignalEvents::create().unwrap());
    let launch = plan(&spec, &events).unwrap();
    assert!(
        launch
            .application
            .to_string_lossy()
            .eq_ignore_ascii_case(&comspec),
        "{:?} is not COMSPEC {comspec}",
        launch.application
    );
    let session = ConPtySession::start(&launch, events, 80, 24).unwrap();
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: a live process handle and a writable buffer of `len` units.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            session.process.as_raw_handle(),
            0,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    assert_ne!(ok, 0, "QueryFullProcessImageNameW failed");
    let image = String::from_utf16_lossy(&buf[..len as usize]);
    assert!(image.eq_ignore_ascii_case(&comspec), "{image} vs {comspec}");
    drop(session);

    // The directory it starts in, and that it is an interactive shell.
    let (broker, clock) = broker(1 << 20);
    let handle = broker.open(&spec).unwrap();
    within(handle.take_lease("tester", CONN, false))
        .await
        .unwrap();
    within(handle.write(CONN, b"echo CWD=%CD%& exit\r".to_vec()))
        .await
        .unwrap();
    let events = pull_until_exit(&handle, &clock).await;
    let out = text(&events);
    assert!(
        line_value(&out, "CWD=").is_some_and(|c| c.eq_ignore_ascii_case(&profile)),
        "{out}"
    );
    close(&broker, &handle).await;
}

// --------------------------------------------------------------------------
// Planning the child (no process is created)
// --------------------------------------------------------------------------

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn argv(items: &[&str]) -> SessionSpec {
    SessionSpec {
        argv: items.iter().map(|s| (*s).to_string()).collect(),
        ..SessionSpec::default()
    }
}

#[test]
fn an_empty_argv_plans_comspec_as_a_full_path_in_the_profile_directory() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join("profile");
    std::fs::create_dir(&profile).unwrap();
    let comspec = dir.path().join("my shell").join("cmd.exe");
    let user_env = pairs(&[
        ("COMSPEC", comspec.to_str().unwrap()),
        ("USERPROFILE", profile.to_str().unwrap()),
        ("SystemRoot", r"C:\NoSuchWindows"),
        ("Path", dir.path().to_str().unwrap()),
    ]);
    let launch = plan_from(&argv(&[]), &user_env, &[], r"C:\Windows", &[]).unwrap();
    assert_eq!(launch.application, comspec);
    // The command line carries the same full path, quoted for the space.
    assert_eq!(
        launch.command_line.to_string_lossy(),
        format!("\"{}\"", comspec.display())
    );
    assert_eq!(launch.current_dir, profile);
}

#[test]
fn without_comspec_the_default_shell_is_cmd_in_the_system_directory() {
    let dir = tempfile::tempdir().unwrap();
    let user_env = pairs(&[
        ("USERPROFILE", dir.path().to_str().unwrap()),
        ("SystemRoot", r"C:\SomeWindows"),
    ]);
    let launch = plan_from(&argv(&[]), &user_env, &[], r"C:\Windows", &[]).unwrap();
    assert_eq!(
        launch.application,
        Path::new(r"C:\SomeWindows\System32\cmd.exe")
    );
    // No SystemRoot either: the host's Windows directory.
    let launch = plan_from(&argv(&[]), &[], &[], r"C:\Windows", &[]).unwrap();
    assert_eq!(
        launch.application,
        Path::new(r"C:\Windows\System32\cmd.exe")
    );
    // No usable profile directory: the Windows directory, not the host's
    // working directory.
    assert_eq!(launch.current_dir, Path::new(r"C:\Windows"));
}

#[test]
fn locale_and_time_zone_pass_through_from_the_serve_environment_and_nothing_else() {
    let serve_env = pairs(&[
        ("Lang", "en_US.UTF-8"),
        ("LC_ALL", "C"),
        ("tz", "UTC"),
        ("TERM", "serve-term"),
        ("SECRET", "hunter2"),
        ("PATH", r"C:\serve\only"),
        // Names whose third byte falls inside a multi-byte character (and
        // names shorter than the `LC_` prefix) must not panic the prefix test.
        ("aa\u{e9}", "non-ascii"),
        ("\u{e9}", "short"),
        ("L", "short"),
    ]);
    let user_env = pairs(&[("Path", r"C:\Windows\System32"), ("USERPROFILE", r"C:\")]);
    let mut spec = argv(&["cmd.exe"]);
    spec.term = Some("dumb".into());
    let launch = plan_from(&spec, &user_env, &serve_env, r"C:\Windows", &[]).unwrap();
    let block = String::from_utf16_lossy(&launch.environment);
    let entries: Vec<&str> = block.split('\0').filter(|e| !e.is_empty()).collect();
    for want in ["Lang=en_US.UTF-8", "LC_ALL=C", "tz=UTC", "TERM=dumb"] {
        assert!(entries.contains(&want), "{want} missing from {entries:?}");
    }
    assert!(
        !entries.iter().any(|e| e.starts_with("SECRET")),
        "{entries:?}"
    );
    assert!(
        entries.contains(&r"Path=C:\Windows\System32"),
        "the serve PATH leaked: {entries:?}"
    );
    // Without a hint the default terminal type applies.
    let launch = plan_from(&argv(&["cmd.exe"]), &user_env, &[], r"C:\Windows", &[]).unwrap();
    let block = String::from_utf16_lossy(&launch.environment);
    assert!(block.contains("TERM=xterm-256color\0"), "{block:?}");
}

/// The program `argv[0]` names is found on the child's own `PATH`, then the
/// system directories, never in the host's working directory.
#[test]
fn a_bare_program_name_is_never_searched_in_the_working_directory() {
    let cwd = tempfile::tempdir().unwrap();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let system = tempfile::tempdir().unwrap();
    for (dir, name) in [
        (&cwd, "evil.exe"),
        (&first, "tool.exe"),
        (&second, "tool.exe"),
        (&second, "only-second.exe"),
        (&system, "sysonly.exe"),
        (&cwd, "local.exe"),
    ] {
        std::fs::write(dir.path().join(name), b"").unwrap();
    }
    let path =
        std::env::join_paths([Path::new(r"relative\dir"), first.path(), second.path()]).unwrap();
    let path = path.to_str().unwrap();
    let system_dirs = [system.path().to_path_buf()];
    let find = |name: &str| resolve_program(name, Some(path), cwd.path(), &system_dirs);

    // A file in the working directory is not on the search path.
    assert_eq!(find("evil").unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(
        find("evil.exe").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    // The first `PATH` entry that has it wins; `.exe` is added.
    assert_eq!(find("tool").unwrap(), first.path().join("tool.exe"));
    assert_eq!(
        find("only-second").unwrap(),
        second.path().join("only-second.exe")
    );
    // The system directories come after `PATH`.
    assert_eq!(find("sysonly").unwrap(), system.path().join("sysonly.exe"));
    // A name with a directory part is that path, relative to the child's
    // working directory.
    assert_eq!(find(r".\local").unwrap(), cwd.path().join(r".\local.exe"));
    assert_eq!(
        find(first.path().join("tool").to_str().unwrap()).unwrap(),
        first.path().join("tool.exe")
    );
    assert_eq!(find("").unwrap_err().kind(), io::ErrorKind::NotFound);
    // No PATH at all still reaches the system directories.
    assert_eq!(
        resolve_program("sysonly", None, cwd.path(), &system_dirs).unwrap(),
        system.path().join("sysonly.exe")
    );
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

mod signals;
