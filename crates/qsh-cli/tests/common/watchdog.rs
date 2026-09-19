//! Diagnostic-only watchdog for the `qsh-cli` integration test binaries.
//!
//! `exit_codes_and_error_codes_are_identical_in_both_output_modes`
//! (`crates/qsh-cli/tests/exit_code_matrix.rs`) and tests in
//! `exec_e2e.rs` intermittently hang on Windows until nextest's
//! slow-timeout kills them at 180s. A bare timeout says nothing about
//! where the test was stuck: `Sandbox::qsh` waits on its child with no
//! bound, and `ServeGuard` teardown joins its reader threads with no
//! bound. This module makes the next hang name the stuck invocation or
//! teardown in the captured test output.
//!
//! Every child `qsh` invocation and every `ServeGuard` teardown in
//! `common/mod.rs` registers an [`InFlightGuard`] for as long as it is in
//! flight. A
//! background thread, started lazily on the first registration, wakes about
//! once a second and checks every registered operation's age. Once an
//! operation has been in flight longer than the threshold, and again at
//! every further multiple of it, the thread prints one `stderr` report
//! block naming that operation, every other operation still in flight, the
//! last stderr lines of any live `qsh serve` child, and a snapshot of the
//! OS process table filtered to `qsh` and its plausible children. Every
//! printed line is prefixed `qsh-test-watchdog: ` so a CI log is easy to
//! grep for it.
//!
//! `QSH_TEST_WATCHDOG_SECS` overrides the threshold (default 60s, the
//! nextest slow-timeout period, well under the 180s kill): a positive
//! integer is the threshold in seconds, `0` disables reporting entirely,
//! and anything else falls back to the 60s default. Read once, on first
//! use. `0` is a safety valve for a run that deliberately holds one
//! operation past the threshold; no current test needs it, and `soak.rs`
//! and `adversarial_load.rs` do not go through these helpers. Under plain
//! `cargo test`, this thread inherits libtest's output capture from
//! whichever test first registers, so reports can be swallowed; CI runs
//! nextest, which gives each test its own process.
//!
//! This module never fails, panics, kills, or slows the test it is
//! watching. It only reads state and writes to stderr. The lock guarding
//! the in-flight registry is released before any report is printed or any
//! process is spawned, so a guard's `Drop` (including during panic
//! unwinding) can never block on the watchdog thread.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

/// One operation currently in flight.
struct Entry {
    id: u64,
    label: String,
    start: Instant,
    pid: Option<u32>,
    /// The highest threshold multiple already reported for this entry, so
    /// a still-stuck operation is reported again only at each further
    /// multiple of the threshold rather than on every 1s tick.
    reported_multiple: u64,
}

/// A live `qsh serve` child, for the report's "what is the host doing"
/// section. `stderr` is a [`Weak`] of [`super::ServeGuard`]'s own retained
/// stderr buffer. This module never keeps a server alive on its own, and a
/// dead weak (the guard already dropped) is skipped and pruned.
struct ServeEntry {
    pid: u32,
    addr: String,
    stderr: Weak<Mutex<Vec<String>>>,
}

static ENTRIES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
static SERVES: Mutex<Vec<ServeEntry>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static WATCHDOG_STARTED: Once = Once::new();
static THRESHOLD_SECS: OnceLock<u64> = OnceLock::new();

/// RAII registration for one in-flight operation: registers on creation,
/// deregisters on [`Drop`] (including during panic unwinding), so a test
/// that panics mid-operation never leaves a stale entry behind.
pub(crate) struct InFlightGuard {
    id: u64,
}

impl InFlightGuard {
    /// Register `label` (and its child pid, if known) as in flight, and
    /// start the watchdog thread if this is the first registration ever
    /// made by this test binary.
    pub(crate) fn new(label: impl Into<String>, pid: Option<u32>) -> Self {
        ensure_watchdog_started();
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let entry = Entry {
            id,
            label: label.into(),
            start: Instant::now(),
            pid,
            reported_multiple: 0,
        };
        ENTRIES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(entry);
        Self { id }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        ENTRIES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|entry| entry.id != self.id);
    }
}

/// Record a live `qsh serve` child for the report's serve section. Called
/// once its bound address is known. Opportunistically prunes already-dead
/// entries so the list does not grow across a whole test binary's run.
pub(crate) fn register_serve(pid: u32, addr: String, stderr: Weak<Mutex<Vec<String>>>) {
    let mut serves = SERVES.lock().unwrap_or_else(|e| e.into_inner());
    serves.retain(|entry| entry.stderr.strong_count() > 0);
    serves.push(ServeEntry { pid, addr, stderr });
}

/// The report threshold, read from `QSH_TEST_WATCHDOG_SECS` exactly once.
fn threshold_secs() -> u64 {
    *THRESHOLD_SECS.get_or_init(|| match std::env::var("QSH_TEST_WATCHDOG_SECS") {
        Ok(value) => value.trim().parse().unwrap_or(60),
        Err(_) => 60,
    })
}

/// Start the polling thread on the first call, and never again. A `0`
/// threshold means "disabled", so the thread is never even spawned.
fn ensure_watchdog_started() {
    WATCHDOG_STARTED.call_once(|| {
        let threshold = threshold_secs();
        if threshold == 0 {
            return;
        }
        // Named so a stack dump of a hung process identifies this thread.
        // If spawning fails, there is simply no watchdog for this run;
        // that is not worth panicking over.
        let _ = thread::Builder::new()
            .name("qsh-test-watchdog".into())
            .spawn(move || watchdog_loop(Duration::from_secs(threshold)));
    });
}

fn watchdog_loop(threshold: Duration) -> ! {
    loop {
        thread::sleep(Duration::from_secs(1));
        check_and_report(threshold);
    }
}

/// One tick: find every entry that just crossed a new multiple of
/// `threshold`, and if any did, print a report block for each. The
/// registry lock is held only long enough to take a snapshot; every
/// printing and process-spawning step below happens after it is released.
fn check_and_report(threshold: Duration) {
    let now = Instant::now();
    let (stuck, snapshot) = {
        let mut entries = ENTRIES.lock().unwrap_or_else(|e| e.into_inner());
        let mut stuck = Vec::new();
        for entry in entries.iter_mut() {
            let age = now.saturating_duration_since(entry.start);
            let multiple = age.as_secs() / threshold.as_secs().max(1);
            if multiple > entry.reported_multiple {
                entry.reported_multiple = multiple;
                stuck.push((entry.id, entry.label.clone(), age, entry.pid));
            }
        }
        let snapshot: Vec<(u64, String, Duration, Option<u32>)> = entries
            .iter()
            .map(|entry| {
                (
                    entry.id,
                    entry.label.clone(),
                    now.saturating_duration_since(entry.start),
                    entry.pid,
                )
            })
            .collect();
        (stuck, snapshot)
    };

    if stuck.is_empty() {
        return;
    }

    let serves = serve_snapshot();
    let process_table = capture_process_table();

    for (id, label, age, pid) in stuck {
        print_report(id, &label, age, pid, &snapshot, &serves, &process_table);
    }
}

/// One live serve child's report row: pid, bound address and its last 40
/// stderr lines.
struct ServeSnapshot {
    pid: u32,
    addr: String,
    stderr_tail: Vec<String>,
}

/// Snapshot every still-live registered serve child, pruning dead weaks as
/// it goes.
fn serve_snapshot() -> Vec<ServeSnapshot> {
    let mut serves = SERVES.lock().unwrap_or_else(|e| e.into_inner());
    serves.retain(|entry| entry.stderr.strong_count() > 0);
    serves
        .iter()
        .filter_map(|entry| {
            let stderr = entry.stderr.upgrade()?;
            let lines = stderr.lock().unwrap_or_else(|e| e.into_inner());
            let tail: Vec<String> = lines.iter().rev().take(40).rev().cloned().collect();
            Some(ServeSnapshot {
                pid: entry.pid,
                addr: entry.addr.clone(),
                stderr_tail: tail,
            })
        })
        .collect()
}

/// Print one report block naming `stuck_label` as the operation that just
/// crossed a threshold multiple, with the rest of the state alongside it.
#[allow(clippy::too_many_arguments)]
fn print_report(
    stuck_id: u64,
    stuck_label: &str,
    stuck_age: Duration,
    stuck_pid: Option<u32>,
    all_entries: &[(u64, String, Duration, Option<u32>)],
    serves: &[ServeSnapshot],
    process_table: &str,
) {
    const PREFIX: &str = "qsh-test-watchdog: ";
    let mut out = String::new();
    out.push_str(PREFIX);
    out.push_str(&format!(
        "stuck: {stuck_label} (age {age:.1}s{pid})\n",
        age = stuck_age.as_secs_f64(),
        pid = format_pid(stuck_pid),
    ));

    out.push_str(PREFIX);
    out.push_str("other in-flight operations:\n");
    let mut others = 0;
    for (id, label, age, pid) in all_entries {
        if *id == stuck_id {
            continue;
        }
        others += 1;
        out.push_str(PREFIX);
        out.push_str(&format!(
            "  {label} (age {age:.1}s{pid})\n",
            age = age.as_secs_f64(),
            pid = format_pid(*pid),
        ));
    }
    if others == 0 {
        out.push_str(PREFIX);
        out.push_str("  (none)\n");
    }

    if serves.is_empty() {
        out.push_str(PREFIX);
        out.push_str("live qsh serve children: (none)\n");
    } else {
        for serve in serves {
            out.push_str(PREFIX);
            out.push_str(&format!(
                "live qsh serve: pid={} addr={}\n",
                serve.pid, serve.addr
            ));
            for line in &serve.stderr_tail {
                out.push_str(PREFIX);
                out.push_str(&format!("  stderr| {line}\n"));
            }
        }
    }

    out.push_str(PREFIX);
    out.push_str("process table:\n");
    for line in process_table.lines() {
        out.push_str(PREFIX);
        out.push_str(&format!("  {line}\n"));
    }

    eprint!("{out}");
}

fn format_pid(pid: Option<u32>) -> String {
    pid.map(|p| format!(", pid {p}")).unwrap_or_default()
}

/// Run the platform process lister, bounded to 20s, and never panic. A
/// failed or slow lister degrades the report; it never takes the watchdog
/// thread down with it.
fn capture_process_table() -> String {
    #[cfg(windows)]
    let result = capture_windows_process_table();
    #[cfg(not(windows))]
    let result = capture_unix_process_table();
    result.unwrap_or_else(|e| format!("(process table unavailable: {e})"))
}

#[cfg(not(windows))]
fn capture_unix_process_table() -> Result<String, String> {
    let mut command = Command::new("ps");
    command.args(["-A", "-o", "pid=,ppid=,etime=,args="]);
    let output = run_bounded(command)?;
    Ok(filter_unix_process_table(&output))
}

/// Keep only the `ps` lines whose first argv token names a `qsh` binary,
/// plus rows whose parent pid is one of those already-matched pids: the
/// qsh process tree plus whatever it shelled out to (`sh`, `bash`, `cat`,
/// `sleep`, `true`, and so on), mirroring the Windows lister's own filter
/// below. Each kept row is printed verbatim (trimmed), so the `etime`
/// column `ps` was asked for stays in the output.
#[cfg(not(windows))]
fn filter_unix_process_table(text: &str) -> String {
    let parsed: Vec<(u32, u32, &str, &str)> = text.lines().filter_map(parse_ps_line).collect();
    let qsh_pids: std::collections::HashSet<u32> = parsed
        .iter()
        .filter(|(_, _, _, args)| is_qsh_argv(args))
        .map(|(pid, ..)| *pid)
        .collect();
    parsed
        .into_iter()
        .filter(|(_, ppid, _, args)| is_qsh_argv(args) || qsh_pids.contains(ppid))
        .map(|(_, _, line, _)| line.trim().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// True when `args`'s first whitespace-delimited token names a `qsh`
/// binary: its file name, not its whole path, is exactly `qsh`. Matching
/// on the whole args string instead would also catch any process whose
/// path happens to mention "qsh", such as the checkout directory on CI
/// (`/home/runner/work/qsh/qsh`), cargo, nextest, or a shell.
#[cfg(not(windows))]
fn is_qsh_argv(args: &str) -> bool {
    let token = args.split_whitespace().next().unwrap_or("");
    std::path::Path::new(token)
        .file_name()
        .is_some_and(|name| name == "qsh")
}

/// Parse one `ps -o pid=,ppid=,etime=,args=` line into its pid, ppid, the
/// original line, and `args` (whatever is left after the first three
/// whitespace-delimited fields, so any internal spaces in the command
/// line stay intact). The original line is kept alongside the parsed
/// fields so a kept row can be printed byte for byte, `etime` included,
/// instead of reassembled from the parsed fields.
#[cfg(not(windows))]
fn parse_ps_line(line: &str) -> Option<(u32, u32, &str, &str)> {
    let (pid, rest) = split_first_field(line)?;
    let (ppid, rest) = split_first_field(rest)?;
    let (_etime, rest) = split_first_field(rest)?;
    Some((
        pid.parse().ok()?,
        ppid.parse().ok()?,
        line,
        rest.trim_start(),
    ))
}

#[cfg(not(windows))]
fn split_first_field(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let end = s.find(char::is_whitespace)?;
    Some((&s[..end], &s[end..]))
}

#[cfg(windows)]
fn capture_windows_process_table() -> Result<String, String> {
    // Win32_Process's ParentProcessId is a plain number, so the filter is
    // one WMI query: every qsh.exe/sh.exe/bash.exe/cat.exe/sleep.exe/
    // true.exe by name, plus anything parented by a matched qsh.exe.
    const SCRIPT: &str = r#"
$procs = Get-CimInstance Win32_Process
$names = @('qsh.exe','sh.exe','bash.exe','cat.exe','sleep.exe','true.exe')
$qshPids = $procs | Where-Object { $_.Name -ieq 'qsh.exe' } | ForEach-Object { $_.ProcessId }
$procs | Where-Object { ($names -icontains $_.Name) -or ($qshPids -contains $_.ParentProcessId) } | ForEach-Object {
    "$($_.ProcessId) $($_.ParentProcessId) $($_.Name) $($_.CreationDate) $($_.CommandLine)"
}
"#;
    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT]);
    run_bounded(command)
}

/// Spawn `command` with piped output and null stdin, wait up to 20s, and
/// kill it if it has not finished by then. Returns whatever stdout it
/// produced (partial, if it had to be killed) or an error string. Never
/// panics, and reaps the child on every return path.
fn run_bounded(mut command: Command) -> Result<String, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| format!("spawn failed: {e}"))?;

    let stdout_reader = child.stdout.take().map(spawn_reader);
    let stderr_reader = child.stderr.take().map(spawn_reader);

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("try_wait failed: {e}"));
            }
        }
    }

    let stdout = stdout_reader
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr = stderr_reader
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout).into_owned();

    if timed_out {
        return Err(format!("timed out after 20s; partial output: {stdout}"));
    }
    if stdout.trim().is_empty() && !stderr.is_empty() {
        return Err(format!(
            "no output; stderr: {}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    Ok(stdout)
}

fn spawn_reader(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}
