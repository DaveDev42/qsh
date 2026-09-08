//! Process resource-usage helpers shared by `qsh-cli`'s load/soak
//! integration tests (T2 `adversarial_load.rs`, M8 Step 5's `soak.rs`).
//!
//! Moved here from `crates/qsh-cli/tests/common/mod.rs`
//! (`BRIEF-5.md` §4.1, precedent: `raw_quic.rs`'s move in 4c): both test
//! files need the same `/proc`-based RSS/fd readers and the same
//! poll-until-stable convergence helper, and `qsh-cli` already carries
//! `qsh-testkit` as a dev-dependency, so a second copy in `soak.rs` would
//! just be drift waiting to happen. `crates/qsh-cli/tests/common/mod.rs`
//! keeps `pub use` re-exports of everything here so the existing test
//! files' `use common::{...}` lines do not need to change.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Resident set size of `pid` in KiB, read from `/proc/<pid>/status`'s
/// `VmRSS:` line. Linux only — `None` on every other platform, which a
/// caller under a strict env gate turns into a hard failure and a caller
/// without one turns into a skip (same shape as `reverse_e2e.rs`'s
/// `required_by_strict`).
#[cfg(target_os = "linux")]
pub fn rss_kib(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("VmRSS:")?;
        let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    })
}

#[cfg(not(target_os = "linux"))]
pub fn rss_kib(_pid: u32) -> Option<u64> {
    None
}

/// Count of open file descriptors `pid` currently holds, via
/// `/proc/<pid>/fd`'s entries. Linux only, same `None`-elsewhere contract
/// as [`rss_kib`]. Unlike `qsh-core`'s `pty::tests::open_fd_count` (which
/// only ever reads `/dev/fd` for *this* process), a `qsh serve` child does
/// not share an address space with the caller.
#[cfg(target_os = "linux")]
pub fn open_fd_count(pid: u32) -> Option<usize> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|entries| entries.count())
}

#[cfg(not(target_os = "linux"))]
pub fn open_fd_count(_pid: u32) -> Option<usize> {
    None
}

/// How many consecutive samples [`poll_stable`] waits to agree (to within
/// [`STABILIZE_REL_TOLERANCE`]) before calling a metric converged.
const STABILIZE_WINDOW: usize = 3;

/// Relative variation across the last [`STABILIZE_WINDOW`] samples below
/// which a metric counts as stable.
const STABILIZE_REL_TOLERANCE: f64 = 0.01;

/// Poll interval for [`poll_stable`] (`BRIEF-4c.md` §3.3 — 200ms steps).
pub const STABILIZE_INTERVAL: Duration = Duration::from_millis(200);

/// Poll ceiling for [`poll_stable`] (`BRIEF-4c.md` §3.3 — at most 25
/// reads, i.e. 5s worst case).
pub const STABILIZE_MAX_ITERS: usize = 25;

/// True once the last [`STABILIZE_WINDOW`] entries of `history` (oldest
/// first) are all within [`STABILIZE_REL_TOLERANCE`] of the window's max —
/// the pure predicate half of [`poll_stable`], split out so it has a unit
/// test that needs no `/proc` and no sleeping (`docs/design/testing.md`'s
/// sleep-free CI discipline is about wall-clock waits, not about this
/// judgement being untestable).
pub fn converged(history: &[u64]) -> bool {
    if history.len() < STABILIZE_WINDOW {
        return false;
    }
    let window = &history[history.len() - STABILIZE_WINDOW..];
    let max = *window.iter().max().expect("non-empty window");
    let min = *window.iter().min().expect("non-empty window");
    if max == 0 {
        return min == 0;
    }
    ((max - min) as f64) / (max as f64) < STABILIZE_REL_TOLERANCE
}

/// Poll `sample` on [`STABILIZE_INTERVAL`] up to [`STABILIZE_MAX_ITERS`]
/// times, stopping early once [`converged`] holds. Returns the last
/// reading and whether it converged before the ceiling — a caller that
/// gets `false` back writes "수렴하지 않음" into its diagnostic block
/// rather than trusting the value as settled (`BRIEF-4c.md` §3.3). A `None`
/// reading (metric unavailable on this platform) is not counted toward
/// convergence but does not stop the poll either — the ceiling still
/// applies, and the caller sees the final `None` and `converged = false`.
///
/// `async`, sleeping on `tokio::time::sleep` rather than
/// `std::thread::sleep` (4c adversarial review A13): every caller runs
/// inside a `#[tokio::test(flavor = "multi_thread")]` body, and a
/// synchronous sleep here blocked a whole tokio worker thread for up to 5s
/// per call while other scenario tasks (the flood, the echo loop) needed
/// to keep running concurrently on the same runtime. This is still a
/// wall-clock wait, not a substitute for `tokio::time::pause()` — it is a
/// *condition* poll (stop as soon as three readings agree) rather than a
/// *fixed* one, which is the distinction `docs/design/testing.md`'s
/// sleep-free CI discipline actually draws.
pub async fn poll_stable<F: FnMut() -> Option<u64>>(mut sample: F) -> (Option<u64>, bool) {
    let mut history = Vec::with_capacity(STABILIZE_MAX_ITERS);
    let mut last = None;
    for i in 0..STABILIZE_MAX_ITERS {
        last = sample();
        if let Some(value) = last {
            history.push(value);
            if converged(&history) {
                return (last, true);
            }
        }
        if i + 1 < STABILIZE_MAX_ITERS {
            tokio::time::sleep(STABILIZE_INTERVAL).await;
        }
    }
    (last, false)
}

/// Sampling interval for [`RssPeakSampler`] — the same 200ms cadence
/// [`poll_stable`] uses (`ARBITRATION-4.md` 4c 적대 검토 판정, A1/A2/A12/B2).
pub const RSS_PEAK_SAMPLE_INTERVAL: Duration = Duration::from_millis(200);

/// Tracks `rss_kib(pid)`'s maximum on a background task while a load
/// section runs concurrently with it, rather than after the fact.
///
/// [`poll_stable`] answers "what did RSS settle to once things quieted
/// down"; it cannot answer "what was the highest RSS *during* the load",
/// because by the time a caller invokes it the load section has already
/// returned (4c adversarial review A12: scenario 2's and 3's post-hoc
/// `rss_peak` reading was, in practice, a steady-state reading taken after
/// the flood/session-open loop had already finished awaiting, not a peak
/// sampled while it ran). This instead starts sampling before the load
/// section begins and keeps the running maximum until [`Self::stop`] is
/// awaited once the load section's own `.await` has resolved.
pub struct RssPeakSampler {
    stop: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<Option<u64>>,
}

impl RssPeakSampler {
    /// Start sampling `pid`'s RSS every [`RSS_PEAK_SAMPLE_INTERVAL`] in a
    /// background task. Call this immediately before the load section
    /// begins.
    pub fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_task = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            let mut peak: Option<u64> = None;
            loop {
                if let Some(sample) = rss_kib(pid) {
                    peak = Some(peak.map_or(sample, |p| p.max(sample)));
                }
                if stop_task.load(Ordering::Relaxed) {
                    return peak;
                }
                tokio::time::sleep(RSS_PEAK_SAMPLE_INTERVAL).await;
            }
        });
        Self { stop, handle }
    }

    /// Stop sampling — call this right after the load section's own
    /// `.await` resolves — and return the observed maximum (`None` only if
    /// `rss_kib` never returned `Some`, the same off-Linux/unavailable
    /// contract as [`poll_stable`]).
    pub async fn stop(self) -> Option<u64> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.await.unwrap_or(None)
    }
}

/// Minimum `RLIMIT_NOFILE` soft limit T2/soak need (4c adversarial review
/// B10): a flood/soak scenario opens many concurrent sockets in the test
/// process, on top of whatever fds the `qsh serve` child itself holds, so
/// an ambient `ulimit -n` below this produces failures indistinguishable
/// from a real fd leak.
pub const MIN_NOFILE_SOFT_LIMIT: u64 = 1200;

/// The current shell's `RLIMIT_NOFILE` soft limit (`ulimit -n` is a shell
/// builtin, not a program, so this shells out through `sh -c` rather than
/// executing it directly).
fn nofile_soft_limit() -> Option<u64> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("ulimit -n")
        .output()
        .ok()?;
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Fail loudly, with a clear diagnosis, when the ambient `ulimit -n` is
/// below [`MIN_NOFILE_SOFT_LIMIT`] (4c adversarial review B10). Call this
/// from every `boot`-style helper — those only ever run once a scenario's
/// own strict-mode gate has already let it through, so this never fires on
/// a plain skipped run. `None` (limit undeterminable) does not fail — same
/// fail-open-on-unknown contract [`rss_kib`]/[`open_fd_count`] already use.
pub fn ensure_nofile_limit() {
    if let Some(limit) = nofile_soft_limit()
        && limit < MIN_NOFILE_SOFT_LIMIT
    {
        panic!(
            "ulimit -n is {limit}, below this harness's {MIN_NOFILE_SOFT_LIMIT} minimum — a \
             flood/soak scenario alone can open hundreds of concurrent sockets; raise the \
             runner's/shell's open-file limit (`ulimit -n {MIN_NOFILE_SOFT_LIMIT}` or higher) \
             before re-running rather than reading a failure here as an RSS/fd regression"
        );
    }
}
