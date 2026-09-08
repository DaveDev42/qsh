//! T2 — the adversarial load harness (`PLAN.md` M8 Step 4c,
//! `docs/design/testing.md` L9/L10, `docs/ROADMAP.md` M8 DoD 5).
//!
//! Unlike the rest of `qsh-cli`'s integration suite, this file measures a
//! **release** `qsh serve` subprocess (`BRIEF-4c.md` §3.2/J2) and only runs
//! its scenarios under an explicit env gate:
//!
//! - `QSH_LOAD_STRICT=1` turns the gate on. This is deliberately a new name
//!   rather than the existing `QSH_ACCEPTANCE_STRICT`/`QSH_ACCEPTANCE_SLOW`
//!   (`tui_expect.rs`, `reverse_blackout.rs`,
//!   `qsh-testkit/tests/tunnel_echo_under_load.rs`): those flip on the
//!   acceptance job, which sits in `ci-ok`'s `needs` list
//!   (`.github/workflows/ci.yml:179-182`) and therefore runs on every PR;
//!   reusing them would drag T2's absolute-number scenarios into the PR
//!   gate, which J1 rejected in favor of a separate `load.yml` (push +
//!   `workflow_dispatch` only).
//! - With the gate on, `QSH_LOAD_BIN` must name the release binary to
//!   measure. Absent, the harness fails loudly rather than silently
//!   falling back to the nextest-built debug binary (`env!
//!   ("CARGO_BIN_EXE_qsh")`) — a debug binary's RSS/fd shape is not what
//!   DoD 5's 30 MB bound is about.
//! - `#[ignore]` is not used anywhere in this file: nextest's ignore
//!   filter does not say *why* a test did not run, and the env-gate +
//!   `skip()` pattern above already has three precedents in this repo.
//!
//! Every scenario is `#[cfg(target_os = "linux")]` per J9/§2.2: the
//! `/proc` readers in `common::rss_kib`/`common::open_fd_count` and
//! scenario 1's `127.0.0.0/8` source multiplexing both require Linux.
//! `load.yml` runs on `ubuntu-24.04` only, so this loses no CI coverage.

mod common;

use common::{Sandbox, ServeGuard, converged, open_fd_count, poll_stable, rss_kib};
use std::path::PathBuf;

// The idle-listener bound (`docs/PRD.md:305`, 30 MB) and the per-session
// load-time allowance (`docs/PRD.md:306`/J2, +8 MB per alive session) that
// every scenario's RSS assertion uses land with the scenarios themselves
// in S2/S3 — this stage only has a floor to check, not a ceiling.

/// Lower bound every RSS reading must clear (J2/J15 mutation M6) — a
/// measurement helper that always returns near-zero must not be mistaken
/// for "the listener is impossibly lean".
const RSS_FLOOR_KIB: u64 = 2 * 1024;

/// Lower bound every fd-count reading must clear — a listening `qsh serve`
/// always holds at least stdin/stdout/stderr plus its bound UDP socket.
const FD_FLOOR: usize = 3;

fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim().to_string();
    !(value.is_empty() || value == "0")
}

/// Whether T2's scenarios should run at all — mirrors
/// `tunnel_echo_under_load.rs`'s `gate_requested` shape, but on the new
/// `QSH_LOAD_STRICT` name (see the module doc).
fn gate_requested() -> bool {
    env_flag("QSH_LOAD_STRICT")
}

fn skip() {
    eprintln!(
        "SKIP: T2 adversarial load scenarios require QSH_LOAD_STRICT=1 (not set on this run) \
         plus QSH_LOAD_BIN pointing at a release `qsh` build — `.github/workflows/load.yml` \
         sets both; locally: cargo build --release -p qsh-cli && \
         QSH_LOAD_STRICT=1 QSH_LOAD_BIN=$(pwd)/target/release/qsh cargo nextest run -p qsh-cli \
         --test adversarial_load"
    );
}

/// A `qsh serve` release subprocess plus the sandbox it runs in, the unit
/// every T2 scenario is built from (`BRIEF-4c.md` §3.2, mirroring
/// `fixtures.rs:575-604`'s `golden_resource_exhausted_fixture` hand-built
/// host).
struct LoadFleet {
    host: Sandbox,
    serve: ServeGuard,
}

impl LoadFleet {
    fn pid(&self) -> u32 {
        self.serve.pid()
    }
}

/// Resolve the release `qsh` binary T2 measures. Panics — does not fall
/// back to `CARGO_BIN_EXE_qsh` — when `QSH_LOAD_BIN` is unset, per J2: a
/// caller only reaches this after [`gate_requested`] is already true, so a
/// missing `QSH_LOAD_BIN` at this point is a strict-mode configuration
/// error, not something to paper over quietly (mutation (b) in
/// `PROGRESS-4.md`'s Stage 4c-S1 exercises exactly this).
fn load_bin() -> PathBuf {
    std::env::var_os("QSH_LOAD_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "QSH_LOAD_STRICT=1 but QSH_LOAD_BIN is not set — T2 measures a release `qsh` \
                 binary and refuses to silently substitute the nextest-built debug binary \
                 (BRIEF-4c.md §3.5/J2); set QSH_LOAD_BIN=$(pwd)/target/release/qsh after \
                 `cargo build --release -p qsh-cli`."
            )
        })
}

/// Bring up a `qsh serve` release subprocess with `config_toml` written to
/// its `config.toml` before it starts (empty string: no `config.toml` at
/// all, i.e. every `[serve]` default applies). Mirrors
/// `fixtures.rs`'s `golden_resource_exhausted_fixture`, which is the only
/// existing precedent for planting a caller-written `config.toml` ahead of
/// `ServeGuard::start` (`Fleet::start_with` has no seam for it).
fn boot(config_toml: &str) -> LoadFleet {
    common::ensure_nofile_limit();
    let bin = load_bin();
    let host = Sandbox::initialized();
    if !config_toml.is_empty() {
        std::fs::write(host.config_dir().join("config.toml"), config_toml)
            .expect("write config.toml");
    }
    let serve = ServeGuard::start_with_bin(&host, &bin, &[]);
    LoadFleet { host, serve }
}

/// Smoke test for this stage: a release `qsh serve` boots and its RSS/fd
/// both clear the measurement floor. Every later scenario builds on this
/// same `boot()`/`rss_kib`/`open_fd_count` path.
#[tokio::test]
async fn fleet_boot_reports_rss_and_fd_above_the_floor() {
    if !gate_requested() {
        skip();
        return;
    }
    let fleet = boot("");
    let pid = fleet.pid();

    let (rss, rss_converged) = poll_stable(|| rss_kib(pid)).await;
    match rss {
        Some(rss) => {
            assert!(
                rss > RSS_FLOOR_KIB,
                "rss {rss} KiB did not clear the {RSS_FLOOR_KIB} KiB floor (converged: \
                 {rss_converged})"
            );
        }
        None if cfg!(target_os = "linux") => {
            panic!("rss_kib(pid) returned None on Linux, where it must return Some")
        }
        None => {}
    }

    let (fd, fd_converged) = poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;
    match fd {
        Some(fd) => {
            let fd = fd as usize;
            assert!(
                fd >= FD_FLOOR,
                "fd count {fd} did not clear the {FD_FLOOR} floor (converged: {fd_converged})"
            );
        }
        None if cfg!(target_os = "linux") => {
            panic!("open_fd_count(pid) returned None on Linux, where it must return Some")
        }
        None => {}
    }

    // Reachable in a non-strict run too (nothing above returns early) —
    // kept here so the assertions above are unconditional and `boot()`'s
    // sandbox/serve child both stay alive for the whole test body.
    let _ = fleet.host.config_dir();
}

/// Pure-function unit test for `common::converged` — no `/proc`, no
/// sleeping, runs on every platform including macOS (J15/`ARBITRATION-4.md`
/// 4c 판정: helper unit tests are pure-function level).
#[test]
fn converged_requires_three_consistent_samples_by_the_one_percent_bound() {
    assert!(!converged(&[]));
    assert!(!converged(&[100]));
    assert!(!converged(&[100, 100]));
    assert!(!converged(&[100, 90, 80]), "10% swings must not converge");
    assert!(converged(&[100, 100, 100]));
    assert!(
        converged(&[500, 100, 100, 100, 101]),
        "an early outlier must not block convergence once the window settles"
    );
    assert!(
        !converged(&[100, 50, 10]),
        "large relative swings must not converge"
    );
    assert!(converged(&[0, 0, 0]), "all-zero must count as converged");
}

#[cfg(target_os = "linux")]
mod linux_only {
    use super::*;
    use common::wait_for_audit;
    use qsh_core::client::{AttachEvent, Attached, ClientError, Session};
    use qsh_core::tunnel::RemoteForwardAcceptor;
    use qsh_proto::{ErrorCode, wire};
    use qsh_testkit::loopback::{TestIdentity, make_identity};
    use qsh_transport::{Dialer, Endpoint, Fingerprint, Principal, StaticTrust};
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Nearest-rank percentile (`p` in `[0, 1]`) over `samples` — copied from
    /// `qsh-testkit/tests/tunnel_echo_under_load.rs`'s `percentile` (J9: this
    /// 40-line duplication is accepted rather than promoting the helper to a
    /// shared crate for a single reused function). Used by scenario 3's PTY
    /// echo p95 (Stage 4c-S2).
    fn percentile(mut samples: Vec<f64>, p: f64) -> f64 {
        samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        let n = samples.len();
        let idx = ((n as f64) * p).ceil() as usize;
        samples[idx.saturating_sub(1).min(n - 1)]
    }

    /// One `scenario N name: observed vs bound (verdict)` diagnostic block
    /// (`BRIEF-4c.md` §3.6). Every T2 scenario `eprintln!`s this on both
    /// success and failure, so a green run's log is exactly what
    /// `docs/campaigns/m8-adversarial-load.md`'s round-record table copies
    /// from. Constructed by scenarios 1, 2 and 3 (Stage 4c-S2).
    struct Diagnostics<'a> {
        scenario: &'a str,
        verdict: &'a str,
        rss_baseline_kib: Option<u64>,
        rss_peak_kib: Option<u64>,
        rss_idle_kib: Option<u64>,
        rss_bound_kib: u64,
        fd_baseline: Option<usize>,
        fd_peak: Option<usize>,
        fd_after: Option<usize>,
        fd_delta_bound: i64,
        echo_baseline_p95_ms: Option<f64>,
        echo_load_p95_ms: Option<f64>,
        echo_samples: usize,
        echo_threshold_ms: Option<f64>,
        nofile_limit: Option<u64>,
        nproc: usize,
        bin: &'a Path,
        /// M8 Step 5a §3.3: scenario 2's per-dial timing/outcome report —
        /// `None` for every scenario that doesn't drive a counted-dial
        /// loop. `Some` carries either a one-line p50/p95/max summary
        /// (verdict "pass") or a full per-dial "dial #k: start +t_ms, end
        /// +t_ms, outcome" dump (verdict "FAIL") — [`dial_report`]
        /// decides which, since at construction time (before this
        /// scenario's own bound checks run) it isn't known yet which the
        /// final verdict will be.
        dial_report: Option<String>,
    }

    impl std::fmt::Display for Diagnostics<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            fn opt(v: Option<impl std::fmt::Display>) -> String {
                v.map(|v| v.to_string()).unwrap_or_else(|| "n/a".into())
            }
            writeln!(f, "{}: {}", self.scenario, self.verdict)?;
            writeln!(
                f,
                "  rss: baseline {} KiB, peak {} KiB, idle-after {} KiB (bound {} KiB)",
                opt(self.rss_baseline_kib),
                opt(self.rss_peak_kib),
                opt(self.rss_idle_kib),
                self.rss_bound_kib
            )?;
            writeln!(
                f,
                "  fd:  baseline {}, peak {}, after {} (delta bound {})",
                opt(self.fd_baseline),
                opt(self.fd_peak),
                opt(self.fd_after),
                self.fd_delta_bound
            )?;
            // A3 (rejected as a threshold change, kept as a diagnostic):
            // the 50ms floor in scenario 3's `max(baseline*3, 50ms)`
            // threshold dwarfs loopback baselines by design, so the
            // load/baseline ratio is what actually shows whether a run
            // moved at all — the threshold comparison alone would not.
            let ratio = match (self.echo_baseline_p95_ms, self.echo_load_p95_ms) {
                (Some(b), Some(l)) if b > 0.0 => format!(", load/baseline {:.2}x", l / b),
                _ => String::new(),
            };
            writeln!(
                f,
                "  echo: baseline p95 {} ms, load p95 {} ms, samples {} (threshold {} ms{ratio})",
                opt(self.echo_baseline_p95_ms),
                opt(self.echo_load_p95_ms),
                self.echo_samples,
                opt(self.echo_threshold_ms)
            )?;
            write!(
                f,
                "  env: ulimit -n {}, nproc {}, bin {}",
                opt(self.nofile_limit),
                self.nproc,
                self.bin.display()
            )?;
            if let Some(report) = &self.dial_report {
                write!(f, "\n  dials:\n{report}")?;
            }
            Ok(())
        }
    }

    /// One [`Diagnostics::dial_report`] entry: a counted dial's index,
    /// its start/end offset from the scenario's own dial-loop start, and
    /// its outcome — M8 Step 5a §3.3.
    struct DialRecord {
        index: usize,
        start: Duration,
        end: Duration,
        outcome: String,
    }

    /// Build [`Diagnostics::dial_report`]'s text: every dial's own line
    /// when `all_ok` is `false` (a bound violation — the detail a soak/
    /// load-flood investigation actually needs), otherwise just the
    /// p50/p95/max of dial round-trip time (§3.3: "성공 시에는 p50/p95/max
    /// 만"). `records` must be non-empty — every call site drives at
    /// least one counted dial.
    fn dial_report(records: &[DialRecord], all_ok: bool) -> String {
        if !all_ok {
            return records
                .iter()
                .map(|r| {
                    format!(
                        "    dial #{}: start +{}ms, end +{}ms, outcome {}",
                        r.index,
                        r.start.as_millis(),
                        r.end.as_millis(),
                        r.outcome
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
        let mut durations: Vec<Duration> = records.iter().map(|r| r.end - r.start).collect();
        durations.sort_unstable();
        let pct = |p: f64| -> Duration {
            let idx = ((durations.len() - 1) as f64 * p).round() as usize;
            durations[idx]
        };
        format!(
            "    {} dials: p50 {}ms, p95 {}ms, max {}ms",
            durations.len(),
            pct(0.50).as_millis(),
            pct(0.95).as_millis(),
            durations.last().expect("non-empty").as_millis()
        )
    }

    /// Finish one scenario: set `diag`'s verdict from whether `violations`
    /// is empty, then either log the block (pass) or panic with it
    /// (fail) — never the reverse (4c adversarial review B6). Every
    /// scenario used to build `diag` with `verdict: "pass"` hardcoded and
    /// `eprintln!` it *before* evaluating its own bound checks, so a
    /// failing run's log read "pass" right above the panic that actually
    /// failed it. Callers push a message onto `violations` for every bound
    /// they need checked instead of asserting immediately, so all of a
    /// scenario's checks are evaluated (and can all be reported) even when
    /// more than one fails.
    fn finish_scenario(mut diag: Diagnostics, violations: Vec<String>) {
        if violations.is_empty() {
            diag.verdict = "pass";
            eprintln!("{diag}");
        } else {
            diag.verdict = "FAIL";
            panic!(
                "{diag}\n  {} bound violation(s):\n    {}",
                violations.len(),
                violations.join("\n    ")
            );
        }
    }

    // ---------------------------------------------------------------------
    // Stage 4c-S2 (`BRIEF-4c.md` §4.1-§4.3, §6 S2): scenarios 1, 2, 3.
    // ---------------------------------------------------------------------

    /// `docs/PRD.md:305` idle-listener bound — also J2's post-flood idle
    /// ceiling every S2/S3 scenario's RSS assertion converges back to.
    const RSS_IDLE_BOUND_KIB: u64 = 30 * 1024;

    /// `docs/PRD.md:306`/J2's per-alive-session load-time allowance.
    const RSS_PER_SESSION_LOAD_KIB: u64 = 8 * 1024;

    fn open_req() -> wire::SessionOpen {
        wire::SessionOpen {
            argv: vec!["sh".into()],
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            ..Default::default()
        }
    }

    /// `qsh.cli/v1`'s `(code, retryable)` pair out of a `ClientError::Remote`
    /// — copied from `qsh-testkit/tests/quota.rs`'s own `remote` helper (same
    /// small-duplication call J9 makes for `percentile`).
    fn remote(err: ClientError) -> (ErrorCode, bool) {
        match err {
            ClientError::Remote {
                code, retryable, ..
            } => (code, retryable),
            other => panic!("expected a remote error, got {other:?}"),
        }
    }

    /// [`boot`] plus one pinned "flood" client identity — every S2/S3 scenario
    /// dials as this single principal (`BRIEF-4c.md` §4.2/§4.3 only override
    /// host-wide/per-principal caps, neither of which needs more than one
    /// identity to exercise). The pin has to land in `trust.toml` *before*
    /// [`ServeGuard::start_with_bin`] runs `plant_allow_all_acl` (`BRIEF-4c.md`
    /// §3.2's `boot()` has no such seam, hence this sibling rather than a
    /// `boot()` parameter every S1-era caller would have to thread through).
    fn boot_with_flood_client(config_toml: &str) -> (LoadFleet, TestIdentity) {
        common::ensure_nofile_limit();
        let bin = load_bin();
        let host = Sandbox::initialized();
        let identity = make_identity();
        host.trust_add("flood", None, &identity.fingerprint.to_string());
        if !config_toml.is_empty() {
            std::fs::write(host.config_dir().join("config.toml"), config_toml)
                .expect("write config.toml");
        }
        let serve = ServeGuard::start_with_bin(&host, &bin, &[]);
        (LoadFleet { host, serve }, identity)
    }

    /// A [`Dialer`] presenting `identity`, pinning only `server_fingerprint` —
    /// this harness never trusts an unpinned peer, not even its own
    /// subprocess (`docs/design/testing.md`'s pinned-peer discipline).
    /// `with_timeout(30s)` (4c adversarial review B4) replaces
    /// `qsh_transport::endpoint::DEFAULT_DIAL_TIMEOUT`'s 10s: under WSL host
    /// CPU contention (`~/fuzz`'s 8 workers saturating every vCPU) a dial
    /// occasionally needs longer than 10s just to complete the QUIC
    /// handshake, and a client-side timeout here must not be mistaken for
    /// (or, worse, silently retried into double-counting) a server-side
    /// admission/quota decision. This does not loosen any RSS/fd/count
    /// threshold — it only gives a slow-but-otherwise-fine dial room to
    /// finish before the harness gives up on it.
    fn flood_dialer(identity: &TestIdentity, server_fingerprint: &str) -> Dialer {
        let server_fp =
            Fingerprint::from_str(server_fingerprint).expect("host fingerprint string parses");
        let trust = StaticTrust::empty().with_pin(server_fp, Principal::Device("box".into()));
        Dialer::new(identity.local.clone(), Arc::new(trust)).with_timeout(Duration::from_secs(30))
    }

    /// Dial `addr` and run the qsh `Hello` handshake, returning the
    /// negotiated [`Session`] plus the `quinn::Endpoint` that must outlive it
    /// (`Dialed`'s own doc). A connection admitted past a quota answers this
    /// `Ok`; a connection refused at the connection-count choke point
    /// (`server/mod.rs::serve_connection`) fails the `Hello` exchange itself
    /// with `RESOURCE_EXHAUSTED` (`quota.rs`'s own
    /// `existing_session_echo_survives_a_connection_flood` establishes this
    /// exact shape against `LoopbackHarness`; this is its real-subprocess
    /// twin).
    async fn negotiate_session(
        dialer: &Dialer,
        addr: SocketAddr,
        name: &str,
    ) -> Result<(Session, Endpoint), ClientError> {
        let dialed = dialer
            .dial(addr, "127.0.0.1")
            .await
            .map_err(|err| ClientError::Protocol(format!("dial: {err:?}")))?;
        let endpoint = dialed.endpoint;
        let session = Session::negotiate(dialed.connection, name).await?;
        Ok((session, endpoint))
    }

    /// [`negotiate_session`], retried up to `attempts` times, but only on a
    /// raw transport-level error (a [`ClientError`] variant other than
    /// `Remote` — no qsh-level response at all, the shape of a dialer
    /// timeout firing under host CPU contention rather than of a server
    /// decision). Reserved for dials that do not themselves count toward a
    /// scenario's admitted/refused tally — a warm-up or healthcheck round
    /// trip retried after a transport timeout cannot double-count anything
    /// a server already admitted, unlike one of the counted dials in a
    /// flood batch (4c adversarial review A16/B4: retrying *those* risks a
    /// second attempt claiming a quota slot the first attempt's connection
    /// already holds). A [`ClientError::Remote`] answer — the server itself
    /// responded — is never retried, counted or not.
    async fn dial_with_retries(
        dialer: &Dialer,
        addr: SocketAddr,
        name: &str,
        attempts: usize,
    ) -> Result<(Session, Endpoint), ClientError> {
        assert!(attempts > 0, "attempts must be positive");
        let mut last_err = None;
        for _ in 0..attempts {
            match negotiate_session(dialer, addr, name).await {
                Ok(pair) => return Ok(pair),
                Err(err @ ClientError::Remote { .. }) => return Err(err),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.expect("attempts > 0 means the loop ran at least once"))
    }

    /// Non-counting dials (warm-up, healthcheck) get this many attempts
    /// before the transport-level error is treated as a real failure
    /// (4c adversarial review A16/B4).
    const NON_COUNTING_DIAL_ATTEMPTS: usize = 3;

    /// `ulimit -n`'s soft limit, shelled out (`sh -c ulimit -n`: it is a shell
    /// builtin, not a program, so there is nothing to exec directly) — for
    /// [`Diagnostics::nofile_limit`] only; never load-bearing for a scenario's
    /// own pass/fail (`BRIEF-4c.md` §2.2 asks only that it be *recorded*).
    fn nofile_limit() -> Option<u64> {
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

    fn nproc() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    }

    /// Shelled out the same way as [`nofile_limit`] rather than pulling in
    /// a `libc`/`nix` uid accessor this crate does not otherwise depend on
    /// (`nix`'s own feature list here is `["term", "ioctl", "signal"]`, no
    /// `user` feature). Only used to skip
    /// `session_open_fails_closed_when_a_freshly_restarted_writer_cannot_
    /// create_the_audit_log` under uid 0, where `chmod 500` on a directory
    /// does not stop file creation in it (A17's own judgment,
    /// `ARBITRATION-4.md` "root면 skip"). `false` on any failure to read
    /// `id -u` — a non-root default only ever makes the scenario run and
    /// hit its own bounded-attempts assertion instead of silently skipping.
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|out| {
                std::str::from_utf8(&out.stdout)
                    .ok()
                    .map(str::trim)
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .is_some_and(|uid| uid == 0)
    }

    /// True while `fleet`'s `qsh serve` child has not exited on its own — the
    /// "server survives the flood" half of every scenario's common assertions
    /// (`BRIEF-4c.md` §4 "서버가 살아 있고 stderr에 panic이 없다").
    fn server_alive(fleet: &mut LoadFleet) -> bool {
        fleet
            .serve
            .wait_timeout(Duration::from_millis(50))
            .is_none()
    }

    /// Scenario 2 (`BRIEF-4c.md` §4.2/J4): 64 dials past `max_connections=16`,
    /// 8 at a time, must admit exactly 16 and refuse the rest with
    /// `RESOURCE_EXHAUSTED`/`retryable`, leaving the subprocess listener's
    /// RSS/fd bounded both mid-flood and after every connection closes.
    /// `handshake_rate_per_source`/`validated_rate_per_source` are raised to
    /// 200 so admission (scenario 1's own axis) never intervenes here.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn connection_flood_past_the_cap_leaves_the_listener_rss_and_fd_bounded() {
        if !gate_requested() {
            skip();
            return;
        }
        const CONFIG: &str = "[serve]\nmax_connections = 16\nhandshake_rate_per_source = 200\n\
                           validated_rate_per_source = 200\n";
        const TOTAL: usize = 64;
        const BATCH: usize = 8;
        const CAP: usize = 16;

        let (mut fleet, identity) = boot_with_flood_client(CONFIG);
        let pid = fleet.pid();
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");
        let server_fp = fleet.host.fingerprint();
        let dialer = Arc::new(flood_dialer(&identity, &server_fp));

        // J9: the fd baseline is taken right after one normal round trip, not
        // at process start — a bare-started listener has not yet opened the
        // audit-log fd or handled any connection at all. That fd only opens
        // on the *first write* to it, though, and a bare connect+close
        // never calls the `authorize`/`authorize_session_control` choke
        // points that write one (WSL 실측, Stage 4c-S2) — a mere Hello
        // round trip is not enough. One throwaway `session.open` + close
        // is, and forces the log's fd open before baseline captures it,
        // rather than mid-flood where it would look like a leak.
        let (mut health, health_ep) =
            dial_with_retries(&dialer, addr, "healthcheck", NON_COUNTING_DIAL_ATTEMPTS)
                .await
                .expect("a healthcheck dial must be admitted before the flood saturates the cap");
        let warm = health
            .session_open(open_req())
            .await
            .expect("the warm-up session.open must be admitted");
        let _ = health.session_close(&warm.session_id, None).await;
        health.close();
        drop(health_ep);
        let (fd_baseline, _) = poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;
        let (rss_baseline, _) = poll_stable(|| rss_kib(pid)).await;

        // 4c adversarial review A12/B2: a post-hoc `poll_stable` reading
        // taken once the batch loop below has already finished awaiting is
        // a steady-state reading, not a peak sampled *during* the flood.
        // `RssPeakSampler` runs concurrently with the loop instead.
        let rss_sampler = common::RssPeakSampler::start(pid);

        let mut held: Vec<(Session, Endpoint)> = Vec::new();
        let mut refused = 0usize;
        // M8 Step 5a §3.3: per-dial start/end/outcome, relative to this
        // loop's own start — `dial_report` turns this into either a
        // p50/p95/max summary or (on a bound violation below) a full
        // per-dial dump.
        let dial_loop_start = std::time::Instant::now();
        let mut dial_records: Vec<DialRecord> = Vec::with_capacity(TOTAL);
        let mut next_dial_index = 0usize;
        for _ in 0..(TOTAL / BATCH) {
            let mut batch = tokio::task::JoinSet::new();
            for _ in 0..BATCH {
                let dialer = Arc::clone(&dialer);
                let index = next_dial_index;
                next_dial_index += 1;
                // No retry here (4c adversarial review A16/B4): this dial
                // counts toward `held`/`refused` below, and retrying a
                // transport-level timeout risks a second attempt claiming a
                // connection slot the first attempt's connection already
                // holds server-side — `held.len() == CAP` would then look
                // like a quota bug that is actually a double-counted retry.
                // `flood_dialer`'s 30s `with_timeout` (raised from the 10s
                // default) is what absorbs ordinary host contention
                // instead; a dial that still times out past that is a real
                // failure, reported below with the diagnostics block.
                batch.spawn(async move {
                    let start = std::time::Instant::now();
                    let result = negotiate_session(&dialer, addr, "flood").await;
                    let end = std::time::Instant::now();
                    (index, start, end, result)
                });
            }
            while let Some(joined) = batch.join_next().await {
                let (index, start, end, result) = joined.expect("flood dial task panicked");
                let (start_rel, end_rel) = (
                    start.duration_since(dial_loop_start),
                    end.duration_since(dial_loop_start),
                );
                match result {
                    Ok(pair) => {
                        dial_records.push(DialRecord {
                            index,
                            start: start_rel,
                            end: end_rel,
                            outcome: "admitted".to_string(),
                        });
                        held.push(pair);
                    }
                    Err(err) => {
                        let (code, retryable) = remote(err);
                        assert_eq!(
                            code,
                            ErrorCode::ResourceExhausted,
                            "a refused dial must be RESOURCE_EXHAUSTED"
                        );
                        assert!(retryable, "RESOURCE_EXHAUSTED must be retryable");
                        dial_records.push(DialRecord {
                            index,
                            start: start_rel,
                            end: end_rel,
                            outcome: format!("refused {code:?}"),
                        });
                        refused += 1;
                    }
                }
            }
        }

        assert_eq!(
            held.len(),
            CAP,
            "max_connections={CAP} must admit exactly {CAP} of the {TOTAL}-dial flood"
        );
        assert_eq!(
            refused,
            TOTAL - CAP,
            "the remaining dials must all be refused"
        );

        let rss_peak = rss_sampler.stop().await;
        let (fd_peak, fd_peak_converged) =
            poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;

        let records = wait_for_audit(&fleet.host, "quota_connections_host", |v| {
            v["resource"] == "quota_connections_host"
        });
        let quota_record = records
            .iter()
            .find(|v| v["resource"] == "quota_connections_host")
            .expect("a quota_connections_host record must exist");
        assert_eq!(
            quota_record["request_id"], "-",
            "the connection-cap refusal has no control request behind it"
        );
        let peer_addr = quota_record["peer_addr"]
            .as_str()
            .expect("peer_addr is a string");
        assert!(
            peer_addr.starts_with("127.0.0.1:"),
            "peer_addr must be the real QUIC peer, not a placeholder: {peer_addr}"
        );

        for (session, endpoint) in held.drain(..) {
            session.close();
            drop(endpoint);
        }
        let (rss_idle, _) = poll_stable(|| rss_kib(pid)).await;
        let (fd_after, fd_after_converged) =
            poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;

        assert!(
            server_alive(&mut fleet),
            "the serve subprocess must survive the connection flood"
        );

        let rss_load_bound = RSS_IDLE_BOUND_KIB; // 0 sessions ever opened in this scenario.
        let mut diag = Diagnostics {
            scenario: "scenario 2 connection_flood_past_the_cap",
            verdict: "pass",
            rss_baseline_kib: rss_baseline,
            rss_peak_kib: rss_peak,
            rss_idle_kib: rss_idle,
            rss_bound_kib: rss_load_bound,
            fd_baseline: fd_baseline.map(|n| n as usize),
            fd_peak: fd_peak.map(|n| n as usize),
            fd_after: fd_after.map(|n| n as usize),
            fd_delta_bound: 0,
            echo_baseline_p95_ms: None,
            echo_load_p95_ms: None,
            echo_samples: 0,
            echo_threshold_ms: None,
            nofile_limit: nofile_limit(),
            nproc: nproc(),
            bin: &load_bin(),
            // Filled in below, once `violations` is known — §3.3's
            // pass/fail split decides which shape `dial_report` builds.
            dial_report: None,
        };

        // (4c adversarial review A14): `fd_peak_converged` is a plain
        // `bool`, not an `Option` — it only ever describes *this* peak
        // reading, so it belongs in the message, not in the pattern.
        let mut violations = Vec::new();
        if let Some(peak) = rss_peak {
            if peak <= RSS_FLOOR_KIB {
                violations.push(format!(
                    "peak rss {peak} KiB did not clear the {RSS_FLOOR_KIB} KiB floor (a \
                     measurement helper reading near-zero must not pass as \"impossibly \
                     lean\", J15 mutation M6)"
                ));
            }
            if peak > rss_load_bound {
                violations.push(format!(
                    "peak rss {peak} KiB exceeded the {rss_load_bound} KiB load-time bound (fd \
                     converged: {fd_peak_converged})"
                ));
            }
        }
        if let Some(idle) = rss_idle
            && !(idle > RSS_FLOOR_KIB && idle <= RSS_IDLE_BOUND_KIB)
        {
            violations.push(format!(
                "idle rss {idle} KiB must clear the {RSS_FLOOR_KIB} KiB floor and stay under \
                 the {RSS_IDLE_BOUND_KIB} KiB idle bound"
            ));
        }
        if let (Some(after), Some(base)) = (fd_after, fd_baseline)
            && after as i64 - base as i64 > 0
        {
            violations.push(format!(
                "fd delta after close ({after} - {base}) must be <= 0 (converged: \
                 {fd_after_converged})"
            ));
        }
        diag.dial_report = Some(dial_report(&dial_records, violations.is_empty()));
        finish_scenario(diag, violations);
    }

    /// Scenario 3 (`BRIEF-4c.md` §4.3/J5): a single principal saturates
    /// `max_sessions_per_principal=8`, then floods `session.open` from a
    /// second connection for ~10s while an existing session's **real PTY**
    /// echo (not `PipeFactory`'s pipe echo — the property DoD 5 actually
    /// names) is measured on a third, dedicated attach stream. p95 during the
    /// flood must stay under `max(baseline p95 * 3, 50ms)`.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn session_flood_from_one_principal_keeps_the_existing_pty_echo_within_budget() {
        if !gate_requested() {
            skip();
            return;
        }
        const CONFIG: &str = "[serve]\nmax_sessions_per_principal = 8\nhandshake_rate_per_source = 200\n\
                           validated_rate_per_source = 200\n";
        const CAP: usize = 8;
        const MIN_SAMPLES: usize = 100;
        const LOAD_DURATION: Duration = Duration::from_secs(10);
        const ROUND_TIMEOUT: Duration = Duration::from_secs(2);

        let (mut fleet, identity) = boot_with_flood_client(CONFIG);
        let pid = fleet.pid();
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");
        let server_fp = fleet.host.fingerprint();
        let dialer = flood_dialer(&identity, &server_fp);

        let (mut control, _control_ep) = negotiate_session(&dialer, addr, "control")
            .await
            .expect("the control connection must be admitted");

        let mut opened = Vec::with_capacity(CAP);
        for i in 0..CAP {
            let o = control
                .session_open(open_req())
                .await
                .unwrap_or_else(|e| panic!("session {i} of {CAP} within the cap: {e:?}"));
            opened.push(o);
        }
        let first = opened[0].clone();

        let mut attached = control
            .attach(wire::SessionAttach {
                session_id: first.session_id.clone(),
                resume_token: first.resume_token.clone(),
                last_output_seq: 0,
                mode: wire::AttachMode::Rw as i32,
                no_steal: false,
            })
            .await
            .expect("attach the PTY-echo session");

        let (fd_baseline, _) = poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;
        let (rss_baseline, _) = poll_stable(|| rss_kib(pid)).await;

        /// One echo round: write `marker` (printable ASCII digits only — no
        /// `\n`/control bytes, so a *real* pty's canonical-mode line
        /// discipline neither executes the line nor rewrites it, unlike
        /// `tunnel_echo_under_load.rs`'s `PipeFactory` target, which has no
        /// line discipline to dodge) and wait for the tail of accumulated
        /// `Output` bytes to equal it — a fresh attach with `last_output_seq:
        /// 0` replays from session start, so the shell's own startup prompt
        /// can precede the first round's echo and must be tolerated as a
        /// prefix, not treated as a mismatch.
        async fn echo_round(
            attached: &mut Attached,
            control: &Session,
            round: u32,
            round_timeout: Duration,
        ) -> f64 {
            let marker = format!("{round:08}").into_bytes();
            let send_at = std::time::Instant::now();
            attached
                .send_input(&marker)
                .await
                .expect("send one echo round's input");
            let mut echoed: Vec<u8> = Vec::new();
            let recv_at = loop {
                let event = tokio::time::timeout(round_timeout, attached.next())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("round {round}: no attach event within {round_timeout:?}")
                    })
                    .expect("attach stream read")
                    .expect("attach stream ended mid-round");
                match event {
                    AttachEvent::Output { data, .. } => {
                        echoed.extend_from_slice(&data);
                        if echoed.ends_with(marker.as_slice()) {
                            break std::time::Instant::now();
                        }
                        if echoed.len() > marker.len() * 4 {
                            let cut = echoed.len() - marker.len();
                            echoed.drain(0..cut);
                        }
                    }
                    AttachEvent::InputAck { .. } => continue,
                    other => panic!("round {round}: unexpected attach event {other:?}"),
                }
            };
            let rtt = control.connection().quinn().stats().path.rtt;
            let elapsed = recv_at.saturating_duration_since(send_at);
            elapsed.checked_sub(rtt).unwrap_or_default().as_secs_f64() * 1000.0
        }

        let mut baseline_samples = Vec::with_capacity(MIN_SAMPLES);
        for round in 0..(MIN_SAMPLES as u32) {
            baseline_samples.push(echo_round(&mut attached, &control, round, ROUND_TIMEOUT).await);
        }
        let baseline_p95 = percentile(baseline_samples.clone(), 0.95);
        let threshold_ms = (baseline_p95 * 3.0).max(50.0);

        let (mut flood, _flood_ep) = negotiate_session(&dialer, addr, "flood")
            .await
            .expect("the flood connection must itself be admitted (only sessions are capped)");

        // 4c adversarial review A1/A2/A12: sample RSS concurrently with
        // the flood/load join below rather than after it returns — the 8
        // sessions this scenario keeps alive are what the `+ 8 MB * CAP`
        // load-time allowance is about, and that allowance is only ever
        // exercised while they are actually alive together.
        let rss_sampler = common::RssPeakSampler::start(pid);

        let flood_task = async {
            let mut admitted = 0usize;
            let mut refused = 0usize;
            let deadline = std::time::Instant::now() + LOAD_DURATION;
            while std::time::Instant::now() < deadline {
                match flood.session_open(open_req()).await {
                    Ok(_) => admitted += 1,
                    Err(err) => {
                        let (code, retryable) = remote(err);
                        assert_eq!(code, ErrorCode::ResourceExhausted);
                        assert!(retryable);
                        refused += 1;
                    }
                }
            }
            (admitted, refused)
        };
        let load_task = async {
            let mut samples = Vec::new();
            let deadline = std::time::Instant::now() + LOAD_DURATION;
            let mut round = MIN_SAMPLES as u32;
            while std::time::Instant::now() < deadline || samples.len() < MIN_SAMPLES {
                samples.push(echo_round(&mut attached, &control, round, ROUND_TIMEOUT).await);
                round = round.wrapping_add(1);
            }
            samples
        };
        let ((admitted, refused), load_samples) = tokio::join!(flood_task, load_task);
        let rss_peak = rss_sampler.stop().await;

        assert_eq!(
            admitted, 0,
            "an already-saturated max_sessions_per_principal={CAP} must admit none of the flood \
         opens"
        );
        assert!(
            refused > 0,
            "the flood must have attempted at least one session.open"
        );
        assert!(
            load_samples.len() >= MIN_SAMPLES,
            "only {} echo samples during the flood — MIN_SAMPLES={MIN_SAMPLES}",
            load_samples.len()
        );
        let load_p95 = percentile(load_samples.clone(), 0.95);

        let records = wait_for_audit(&fleet.host, "quota_sessions_principal", |v| {
            v["resource"] == "quota_sessions_principal"
        });
        assert!(
            records
                .iter()
                .any(|v| v["resource"] == "quota_sessions_principal"),
            "a quota_sessions_principal record must exist"
        );

        let rss_load_bound = RSS_IDLE_BOUND_KIB + RSS_PER_SESSION_LOAD_KIB * (CAP as u64);

        attached.finish();
        for o in opened {
            let _ = control.session_close(&o.session_id, None).await;
        }
        control.close();
        let (rss_idle, _) = poll_stable(|| rss_kib(pid)).await;
        let (fd_after, fd_after_converged) =
            poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;

        assert!(
            server_alive(&mut fleet),
            "the serve subprocess must survive the session flood"
        );

        let diag = Diagnostics {
            scenario: "scenario 3 session_flood_from_one_principal",
            verdict: "pass",
            rss_baseline_kib: rss_baseline,
            rss_peak_kib: rss_peak,
            rss_idle_kib: rss_idle,
            rss_bound_kib: rss_load_bound,
            fd_baseline: fd_baseline.map(|n| n as usize),
            fd_peak: None,
            fd_after: fd_after.map(|n| n as usize),
            fd_delta_bound: 0,
            echo_baseline_p95_ms: Some(baseline_p95),
            echo_load_p95_ms: Some(load_p95),
            echo_samples: load_samples.len(),
            echo_threshold_ms: Some(threshold_ms),
            nofile_limit: nofile_limit(),
            nproc: nproc(),
            bin: &load_bin(),
            dial_report: None,
        };

        let mut violations = Vec::new();
        if load_p95 > threshold_ms {
            violations.push(format!(
                "load p95 {load_p95:.3} ms exceeded max(baseline*3, 50ms) = {threshold_ms:.3} ms"
            ));
        }
        // 4c adversarial review A1/A12: the mid-flood bound (this scenario
        // is the one place the harness ever has `CAP` sessions alive
        // together) is asserted, not just carried in the diagnostic block
        // — a peak sampled while 8 sessions and a flood connection are
        // open must clear the near-zero floor and stay under `+8MB*CAP`.
        if let Some(peak) = rss_peak {
            if peak <= RSS_FLOOR_KIB {
                violations.push(format!(
                    "peak rss {peak} KiB did not clear the {RSS_FLOOR_KIB} KiB floor (J15 \
                     mutation M6)"
                ));
            }
            if peak > rss_load_bound {
                violations.push(format!(
                    "peak rss {peak} KiB exceeded the {rss_load_bound} KiB load-time bound \
                     (30MB + 8MB * {CAP} alive sessions)"
                ));
            }
        }
        if let Some(idle) = rss_idle
            && !(idle > RSS_FLOOR_KIB && idle <= RSS_IDLE_BOUND_KIB)
        {
            violations.push(format!(
                "idle rss {idle} KiB must clear the {RSS_FLOOR_KIB} KiB floor and stay under \
                 the {RSS_IDLE_BOUND_KIB} KiB idle bound (Q3: this is the meaningful RSS \
                 judgement — the load-time bound above is loose by design)"
            ));
        }
        // A2: the `poll_stable` convergence above already absorbs PTY
        // teardown's non-instantaneous fd release (it re-reads until three
        // consecutive samples agree, up to 5s), so the delta it settles on
        // is the one to assert against, not one to discard — this is the
        // one scenario that opens real PTYs and had no fd assertion at all
        // before this review.
        if let (Some(after), Some(base)) = (fd_after, fd_baseline)
            && after as i64 - base as i64 > 0
        {
            violations.push(format!(
                "fd delta after close ({after} - {base}) must be <= 0 (converged: \
                 {fd_after_converged})"
            ));
        }
        finish_scenario(diag, violations);
    }

    /// Scenario 1 (`BRIEF-4c.md` §4.1/J3): an 8-source spoofed Initial flood
    /// (40 dials/source, well past the default `burst_limit=20`) must produce
    /// both `rate_limited` (unvalidated) and `validated_rate_limited`
    /// (post-Retry) audit rows, survive a raw-UDP garbage sub-phase, and still
    /// admit a legitimate connection afterward. `admission::Gate::decide`
    /// (`crates/qsh-core/src/admission.rs`) runs at the QUIC accept/Retry
    /// layer, strictly before any qsh TLS identity is checked, so this flood
    /// needs no real device identity — an anonymous client with a
    /// skip-verification `rustls::ClientConfig` bound to each spoofed loopback
    /// source is enough to drive the traffic (`qsh_transport::Dialer::dial`
    /// has no seam to choose the bind address, hence the raw `quinn::Endpoint`
    /// here instead of it).
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn spoofed_initial_flood_leaves_the_listener_rss_and_fd_bounded() {
        if !gate_requested() {
            skip();
            return;
        }
        const ATTEMPTS_PER_SOURCE: usize = 40;
        const GARBAGE_PACKETS_PER_SOURCE: usize = 10_000;
        // `handshake_rate_per_source` stays at its default (10, burst 20 —
        // `BRIEF-4c.md`'s "burst 20을 넘기는 것이 목적" for the unvalidated
        // axis). `validated_rate_per_source` is lowered here (WSL 실측,
        // Stage 4c-S2): the unvalidated gate itself caps how many of each
        // source's attempts ever complete Retry and reach the validated
        // sketch at roughly its own burst (~20, same EPOCH/burst formula,
        // `admission.rs`'s hard per-`EPOCH` reset, no cross-epoch decay) —
        // at the *default* `validated_rate_per_source` (10, burst 20 too),
        // that is an exact tie, not an excess, so `validated_rate_limited`
        // never fires no matter how large `ATTEMPTS_PER_SOURCE` is made.
        // Lowering only this axis's burst below the unvalidated
        // pass-through count is what actually forces the tie to break.
        const CONFIG: &str = "[serve]\nvalidated_rate_per_source = 3\n";

        let (mut fleet, identity) = boot_with_flood_client(CONFIG);
        let pid = fleet.pid();
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");

        let mut endpoints = Vec::new();
        for i in 0u8..8 {
            let ip = std::net::Ipv4Addr::new(127, 0, 0, 2 + i);
            if let Some(ep) = qsh_testkit::raw_quic::raw_source_endpoint(ip) {
                endpoints.push((ip, ep));
            }
        }
        assert!(
            endpoints.len() >= 2,
            "Q5: fewer than 2 of 8 loopback sources could bind ({} succeeded) — cannot proceed",
            endpoints.len()
        );

        // Warm up the audit-log fd before baseline (same reasoning as
        // scenario 2, WSL 실측 Stage 4c-S2): a bare-started listener has not
        // written to `audit.log` yet, so its fd is not open, and the fd only
        // opens on first write. Without this, the flood's own first denial
        // record would be what opens it, making a real one-time open look
        // like a leak against a too-early baseline.
        let server_fp = fleet.host.fingerprint();
        let warm_dialer = flood_dialer(&identity, &server_fp);
        let (mut warm, warm_ep) =
            dial_with_retries(&warm_dialer, addr, "warmup", NON_COUNTING_DIAL_ATTEMPTS)
                .await
                .expect("the warm-up connection must be admitted before baseline");
        let warm_session = warm
            .session_open(open_req())
            .await
            .expect("the warm-up session.open must be admitted");
        let _ = warm.session_close(&warm_session.session_id, None).await;
        warm.close();
        drop(warm_ep);

        let (fd_baseline, _) = poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;
        let (rss_baseline, _) = poll_stable(|| rss_kib(pid)).await;

        // Fire every source's `ATTEMPTS_PER_SOURCE` dials concurrently
        // rather than one-at-a-time-and-await: `admission::Gate::decide`'s
        // burst budget lives inside a single 2s epoch
        // (`admission.rs::EPOCH`), and awaiting each dial's own up-to-N-ms
        // timeout before firing the next serializes the flood across
        // several epochs — the burst counter resets between them and the
        // per-source rate limit is never actually exceeded. Spawning all
        // of them at once (`JoinSet`, mirroring scenario 2's own batching)
        // is what makes this genuinely a *flood* within one epoch.
        let flood_started = std::time::Instant::now();
        let mut dial_tasks = tokio::task::JoinSet::new();
        for (_, ep) in &endpoints {
            for _ in 0..ATTEMPTS_PER_SOURCE {
                let ep = ep.clone();
                dial_tasks.spawn(async move {
                    if let Ok(connecting) = ep.connect(addr, "127.0.0.1") {
                        let _ = tokio::time::timeout(Duration::from_secs(2), connecting).await;
                    }
                });
            }
        }
        while dial_tasks.join_next().await.is_some() {}
        let flood_elapsed = flood_started.elapsed();

        // Raw UDP garbage sub-phase (4c adversarial review B12): each
        // source's `GARBAGE_PACKETS_PER_SOURCE`-packet blocking `send_to`
        // loop runs on `spawn_blocking` rather than inline in this async
        // fn — inline, it starves every tokio worker thread for the whole
        // sub-phase, and the very next steps (recovery, then healthcheck)
        // would then race that starvation against their own timeouts
        // instead of racing the server. Not valid QUIC at all — quinn
        // drops it at the endpoint, so this only exercises "server stays
        // alive", not admission's category rows.
        let mut udp_tasks = tokio::task::JoinSet::new();
        for (i, (ip, _)) in endpoints.iter().enumerate() {
            let ip = *ip;
            udp_tasks.spawn_blocking(move || {
                let Ok(sock) = std::net::UdpSocket::bind(SocketAddr::new(ip.into(), 0)) else {
                    return;
                };
                let mut buf = [0u8; 64];
                for j in 0..GARBAGE_PACKETS_PER_SOURCE {
                    for (k, b) in buf.iter_mut().enumerate() {
                        *b = ((i * 31 + j * 7 + k) % 256) as u8;
                    }
                    let _ = sock.send_to(&buf, addr);
                }
            });
        }
        while udp_tasks.join_next().await.is_some() {}

        // Recovery (4c adversarial review A9): a source rate-limited during
        // the flood must not stay rate-limited forever. `SourceKey::
        // from_addr` (`admission.rs`) keys an unvalidated attempt by its
        // *full* source address, so only a re-dial from one of the exact
        // spoofed sources above proves anything about recovery — the
        // healthcheck below dials from this process's own default bind
        // address, a different key that `admission::Gate::decide` never
        // rate-limited in the first place. Wait longer than one epoch past
        // the last burst (`admission.rs::EPOCH` is 2s; 6s clears at least
        // two rollovers, the same margin the crate's own
        // `generation_rollovers` unit test uses), then require a fresh
        // connect from that exact source to resolve within one epoch's
        // slack (4s).
        let (recovery_ip, recovery_ep) = &endpoints[0];
        tokio::time::sleep(Duration::from_secs(6)).await;
        let connecting = recovery_ep
            .connect(addr, "127.0.0.1")
            .unwrap_or_else(|err| {
                panic!("recovery re-dial from {recovery_ip} failed to start: {err}")
            });
        tokio::time::timeout(Duration::from_secs(4), connecting)
            .await
            .expect(
                "RECOVERY: a source rate-limited during the flood must be served again after \
             2+ epochs",
            )
            .expect("the post-recovery connection must complete the QUIC handshake");

        let server_fp = fleet.host.fingerprint();
        let dialer = flood_dialer(&identity, &server_fp);
        let (health, health_ep) =
            dial_with_retries(&dialer, addr, "healthcheck", NON_COUNTING_DIAL_ATTEMPTS)
                .await
                .expect("the server must still admit a legitimate connection after the flood");
        health.close();
        drop(health_ep);

        let records = fleet.host.audit_records();
        let rate_limited = records
            .iter()
            .filter(|v| v["resource"] == "rate_limited")
            .count();
        let validated_rate_limited = records
            .iter()
            .filter(|v| v["resource"] == "validated_rate_limited")
            .count();
        // Window-summary upper bound (`BRIEF-4c.md` §4.4's formula, applied
        // per single category here: `(ceil(T/10) + 1) * 2` — first row plus
        // one summary row per 10s aggregation window
        // (`admission.rs::AUDIT_AGGREGATION_WINDOW`), +1 window for the
        // end-of-flood flush. `T` is the *measured* wall-clock span of the
        // dial sub-phase, not assumed to fit in a single window — 320 dials
        // each carrying a 100ms timeout can genuinely take several times
        // the window length, which a fixed "1-2" bound does not account
        // for.
        const AUDIT_WINDOW_SECS: f64 = 10.0;
        let windows = (flood_elapsed.as_secs_f64() / AUDIT_WINDOW_SECS).ceil() + 1.0;
        let per_category_bound = (windows * 2.0) as usize;
        assert!(
            rate_limited >= 1 && rate_limited <= per_category_bound,
            "expected 1..={per_category_bound} rate_limited rows (flood took {flood_elapsed:?}), \
         got {rate_limited}: {records:#?}"
        );
        assert!(
            validated_rate_limited >= 1 && validated_rate_limited <= per_category_bound,
            "expected 1..={per_category_bound} validated_rate_limited rows (flood took \
         {flood_elapsed:?}), got {validated_rate_limited}: {records:#?}"
        );

        let bound_count = endpoints.len();
        drop(endpoints);
        let (rss_idle, _) = poll_stable(|| rss_kib(pid)).await;
        let (fd_after, fd_after_converged) =
            poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;
        assert!(
            server_alive(&mut fleet),
            "the serve subprocess must survive the spoofed flood"
        );

        let diag = Diagnostics {
            scenario: "scenario 1 spoofed_initial_flood",
            verdict: "pass",
            rss_baseline_kib: rss_baseline,
            rss_peak_kib: None,
            rss_idle_kib: rss_idle,
            rss_bound_kib: RSS_IDLE_BOUND_KIB,
            fd_baseline: fd_baseline.map(|n| n as usize),
            fd_peak: None,
            fd_after: fd_after.map(|n| n as usize),
            fd_delta_bound: 0,
            echo_baseline_p95_ms: None,
            echo_load_p95_ms: None,
            echo_samples: 0,
            echo_threshold_ms: None,
            nofile_limit: nofile_limit(),
            nproc: nproc(),
            bin: &load_bin(),
            dial_report: None,
        };
        let mut violations = Vec::new();
        if let Some(idle) = rss_idle
            && !(idle > RSS_FLOOR_KIB && idle <= RSS_IDLE_BOUND_KIB)
        {
            violations.push(format!(
                "idle rss {idle} KiB must clear the {RSS_FLOOR_KIB} KiB floor and stay under \
                 the {RSS_IDLE_BOUND_KIB} KiB idle bound"
            ));
        }
        if let (Some(after), Some(base)) = (fd_after, fd_baseline)
            && after as i64 - base as i64 > 0
        {
            violations.push(format!(
                "fd delta after close ({after} - {base}) must be <= 0 (converged: \
                 {fd_after_converged})"
            ));
        }
        eprintln!(
            "  sources bound: {bound_count} of 8, rate_limited rows: {rate_limited}, \
         validated_rate_limited rows: {validated_rate_limited}"
        );
        finish_scenario(diag, violations);
    }

    // ---------------------------------------------------------------------
    // Stage 4c-F2 (`ARBITRATION-4.md` "4c 적대 검토 판정" A4/A5/A6/A15/A17/
    // B5): scenario 12 split into three narrower ones. The original single
    // `a_sustained_rejection_flood_keeps_the_audit_log_bounded` is gone —
    // A4/A5/A6/B5 all independently found its two "bounds" non-
    // discriminating (A4: `max_bytes` never came close to triggering a
    // rotation, so the byte bound was 245x looser than the real number;
    // A5: the row bound tracked nothing about the aggregation window,
    // because window length was never the loop's binding constraint — see
    // 12a's doc comment; A6: the row count only ever read the live
    // `audit.log`, so once A4's fix makes rotation actually happen, the
    // count would silently miss every rotated file). 12a keeps the row-
    // count aggregation property with a bound that now actually depends
    // on `T`; 12b makes rotation really happen and bounds directory bytes
    // against it; 12c (A17), the rotation-*failure* fail-closed test §4.6
    // left "선택", was attempted and then dropped — see the doc comment
    // where it used to sit, just below 12b, for why the construction A17
    // proposed cannot reach the state it was meant to observe.
    // ---------------------------------------------------------------------

    /// Dial one rejected connection at a time, spaced to stay at
    /// `rate_per_sec` for the whole `duration`, instead of saturating the
    /// listener with `concurrency` inflight dials. Returns the actual
    /// elapsed wall-clock time.
    ///
    /// Stage 4c-F2c (ARBITRATION-4.md "4c 적대 검토 판정", F2a's own
    /// 반박 1): 12a's earlier rolling-concurrency flood (8 concurrent
    /// dials, replace-on-completion) drove `quota_connections_host`
    /// rejections at ~19/s, saturating `Server::run`'s accept loop with an
    /// always-ready `listener.accept()` future. `tokio::select!` there is
    /// unbiased, so in principle `audit_flush.tick()` should still win a
    /// fair share of polls, but repeated WSL runs showed the opposite:
    /// after the initial burst the tick branch stopped firing in any
    /// window shorter than the stock 10s one, regardless of how far
    /// `AUDIT_AGGREGATION_WINDOW` was mutated down — root cause not fully
    /// pinned (carried to Step 5), but the fix does not need the cause: a
    /// steady, spaced-out dial rate gives `listener.accept()` real idle
    /// gaps between arrivals, so `audit_flush.tick()` is not competing
    /// against an always-ready branch. `rate_per_sec` is chosen well under
    /// `[serve].handshake_rate_per_source`'s per-source Initial budget
    /// (200/epoch here) so every dial fails at the `quota_connections_
    /// host` choke point (S4 held connections) rather than being
    /// intercepted earlier by the admission rate limiter.
    async fn rate_limited_reject_flood_for(
        dialer: &Arc<Dialer>,
        addr: SocketAddr,
        duration: Duration,
        rate_per_sec: u64,
    ) -> Duration {
        assert!(rate_per_sec > 0, "rate_per_sec must be positive");
        let started = std::time::Instant::now();
        let deadline = started + duration;
        let interval = Duration::from_secs_f64(1.0 / rate_per_sec as f64);
        let mut next_dial_at = started;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Race each individual dial against the flood's own deadline
            // (same rationale `flood_rejections_for` used to document,
            // A15): `flood_dialer`'s own 30s `with_timeout` is far longer
            // than `remaining` can be here, and a WSL `~/fuzz`-contended
            // dial genuinely can stall that long — without this race one
            // stuck dial could blow `FLOOD_SLOP`'s budget on its own,
            // exactly as A15 first measured against the old batch loop.
            let result = tokio::select! {
                biased;
                _ = tokio::time::sleep(remaining) => break,
                r = negotiate_session(dialer, addr, "flood") => r,
            };
            match result {
                Err(err) if !matches!(err, ClientError::Remote { .. }) => {
                    // Dial-side transport error under host contention —
                    // not a qsh-level code assertion (scenario 2's own
                    // tolerance).
                }
                Err(err) => {
                    let (code, retryable) = remote(err);
                    assert_eq!(code, ErrorCode::ResourceExhausted);
                    assert!(retryable);
                }
                Ok((session, ep)) => {
                    // Should not happen while every held slot is taken —
                    // do not leak the fd if it somehow does.
                    session.close();
                    drop(ep);
                }
            }
            next_dial_at += interval;
            let now = std::time::Instant::now();
            if next_dial_at > now {
                tokio::time::sleep(next_dial_at - now).await;
            }
        }
        started.elapsed()
    }

    /// Open and immediately close `iterations` sessions, back to back —
    /// each a single `allow`-decision audit row (Stage 4c-F2c, B5/A4:
    /// rotation driven by ordinary allowed traffic instead of rejection
    /// rows, so the row rate is deterministic and not gated behind any
    /// connection-cap rejection choke point at all). Panics on the first
    /// admission failure — every open here is expected to succeed.
    async fn open_close_cycle(dialer: &Arc<Dialer>, addr: SocketAddr, iterations: usize) {
        // `Session::negotiate` alone (what `negotiate_session` drives) is
        // only the `Hello` exchange — it never sends a `session.open`
        // control message, so it writes no `allow`-decision audit row at
        // all. `session_open`/`session_close` (`qsh.cli/v1`'s real RPCs,
        // same pair scenario 2's warm-up throwaway uses) are what
        // `authorize`'s ACL choke point actually audits, one row per
        // `session.open`.
        //
        // One connection per `BATCH` opens, not one for the whole cycle:
        // `server::MAX_PENDING_TICKETS_PER_CONN` (32) is a hard per-
        // connection cap on outstanding `session.open` tickets that
        // `session_close` does *not* release (12c's own doc comment,
        // just above, independently found the same thing) — a single
        // connection run past 32 opens is refused with `ResourceExhausted`
        // regardless of how many of those sessions were already closed.
        // Reconnecting well under that cap keeps this scenario's row
        // count from depending on an unrelated ticket budget.
        const BATCH: usize = 20;
        let mut opened_total = 0usize;
        while opened_total < iterations {
            // `dial_with_retries` (A16/B4's own non-counting-dial
            // allowance) tolerates a WSL `~/fuzz`-contended transport-
            // level timeout on this batch's one dial.
            let (mut session, ep) =
                dial_with_retries(dialer, addr, "rot", NON_COUNTING_DIAL_ATTEMPTS)
                    .await
                    .expect("the rotation connection must be admitted");
            let batch_end = (opened_total + BATCH).min(iterations);
            for i in opened_total..batch_end {
                let opened = session
                    .session_open(open_req())
                    .await
                    .unwrap_or_else(|err| panic!("session open {i} must be admitted: {err:?}"));
                session
                    .session_close(&opened.session_id, None)
                    .await
                    .unwrap_or_else(|err| panic!("session close {i} must succeed: {err:?}"));
            }
            session.close();
            drop(ep);
            opened_total = batch_end;
        }
    }

    /// Scenario 12a (`BRIEF-4c.md` §4.4/J7, split by 4c adversarial review
    /// A4/A5/A6): a sustained connection-cap rejection flood held for
    /// `FLOOD_DURATION` must leave the reject-category audit row count
    /// bounded *both* ways — an upper bound from the window-aggregation
    /// math (unchanged from the original scenario 12) and a **new** lower
    /// bound (A5's fix) asserting aggregation actually tracked `T`: at
    /// least `floor(T/10)` windows must have closed for the one category
    /// this flood hammers (`quota_connections_host`, 16 held connections
    /// against `max_connections=16`, all later dials refused). `[audit]`
    /// is left at its default (64 MiB / retain 5) — deliberately far from
    /// rotating, so this scenario measures aggregation alone; 12b owns
    /// the rotation/volume property.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sustained_rejection_flood_bounds_the_audit_row_count() {
        if !gate_requested() {
            skip();
            return;
        }
        const HELD_CONNECTIONS: usize = 16;
        const CONFIG: &str = "[serve]\nmax_connections = 16\nhandshake_rate_per_source = 200\n\
                           validated_rate_per_source = 200\n";
        const FLOOD_DURATION: Duration = Duration::from_secs(12);
        // Stage 4c-F2c: well under `[serve].handshake_rate_per_source`'s
        // per-source Initial budget (200/`admission::EPOCH`, 2s) so every
        // dial fails at `quota_connections_host`, not the admission rate
        // limiter — see `rate_limited_reject_flood_for`'s doc comment.
        const FLOOD_DIAL_RATE_PER_SEC: u64 = 5;
        // M8 Step 5 (b-0): read the real window instead of carrying a
        // local hardcoded copy that can drift from
        // `admission::AUDIT_AGGREGATION_WINDOW` unnoticed.
        let audit_window_secs: f64 = qsh_core::admission::AUDIT_AGGREGATION_WINDOW.as_secs_f64();
        // A15: the flood loop's own real elapsed time must not silently
        // run away from `FLOOD_DURATION` — 2s of slop absorbs one
        // in-flight dial's round trip past the deadline check.
        const FLOOD_SLOP: Duration = Duration::from_secs(2);
        const FLOOD_CATEGORY: &str = "quota_connections_host";

        let (mut fleet, identity) = boot_with_flood_client(CONFIG);
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");
        let server_fp = fleet.host.fingerprint();
        let dialer = Arc::new(flood_dialer(&identity, &server_fp));

        // Saturate `max_connections=16` and hold every slot for the whole
        // flood — every later dial is refused at the same choke point
        // scenario 2 pins (`Quotas::reserve_connection`), which is what
        // drives the audit rows this scenario bounds.
        let mut held = Vec::with_capacity(HELD_CONNECTIONS);
        for i in 0..HELD_CONNECTIONS {
            // `dial_with_retries` (A16/B4's own non-counting-dial
            // allowance): these 16 setup dials are not part of the
            // flood's own counted tally, so a WSL `~/fuzz`-contended
            // transport timeout on one attempt must not fail the whole
            // scenario before the flood even starts.
            let pair = dial_with_retries(
                &dialer,
                addr,
                &format!("held-{i}"),
                NON_COUNTING_DIAL_ATTEMPTS,
            )
            .await
            .unwrap_or_else(|err| panic!("held connection {i} must be admitted: {err:?}"));
            held.push(pair);
        }

        let flood_elapsed =
            rate_limited_reject_flood_for(&dialer, addr, FLOOD_DURATION, FLOOD_DIAL_RATE_PER_SEC)
                .await;

        for (session, ep) in held {
            session.close();
            drop(ep);
        }

        fleet.serve.signal(nix::sys::signal::Signal::SIGTERM);
        let status = fleet
            .serve
            .wait_timeout(Duration::from_secs(10))
            .unwrap_or_else(|| panic!("qsh serve did not exit within 10s of SIGTERM"));
        let output = fleet.serve.captured();
        let no_panic = !output.stderr.iter().any(|line| line.contains("panicked"));

        let records: Vec<_> = fleet
            .host
            .audit_records_all()
            .into_iter()
            .filter(|v| v["decision"] == "deny")
            .collect();
        let categories: HashSet<&str> = records
            .iter()
            .filter_map(|v| v["resource"].as_str())
            .collect();
        let windows_upper = (flood_elapsed.as_secs_f64() / audit_window_secs).ceil() + 1.0;
        let row_bound = (windows_upper * 2.0 * (categories.len().max(1) as f64)) as usize;
        // A5's lower bound: over a genuinely continuous `T`-second flood of
        // one category, aggregation must have closed at least `floor(T/
        // 10)` windows — each a first-record row — for that category.
        // `rate_limited_reject_flood_for`'s spaced-out dial rate is what
        // makes this hold (F2c) — a saturating flood could not clear it.
        let windows_lower = (flood_elapsed.as_secs_f64() / audit_window_secs).floor();
        let row_floor = windows_lower as usize; // one flooded category

        let dir_bytes: u64 = std::fs::read_dir(fleet.host.state_dir())
            .expect("read state dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with("audit.log") && !name.ends_with(".lock")
            })
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();

        eprintln!(
            "scenario 12a a_sustained_rejection_flood_bounds_the_audit_row_count: rows {} \
         (bound {row_bound}, floor {row_floor}), dir bytes {dir_bytes}, flood elapsed \
         {flood_elapsed:?} (budget {FLOOD_DURATION:?} + {FLOOD_SLOP:?}), categories {categories:?}",
            records.len()
        );

        let mut violations = Vec::new();
        if !status.success() {
            violations.push(format!("qsh serve exited {status:?} on SIGTERM, not 0"));
        }
        if !no_panic {
            violations.push(format!("panic on stderr: {:?}", output.stderr));
        }
        if flood_elapsed > FLOOD_DURATION + FLOOD_SLOP {
            violations.push(format!(
                "flood loop took {flood_elapsed:?}, more than {FLOOD_SLOP:?} past the \
             {FLOOD_DURATION:?} budget (A15)"
            ));
        }
        if records.len() > row_bound {
            violations.push(format!(
                "audit row count {} exceeded the {row_bound}-row upper bound",
                records.len()
            ));
        }
        if !categories.contains(FLOOD_CATEGORY) {
            violations.push(format!(
                "expected the {FLOOD_CATEGORY} category to appear at all: {categories:?}"
            ));
        } else if records.len() < row_floor {
            violations.push(format!(
                "audit row count {} did not clear the {row_floor}-row lower bound (A5: \
             aggregation must actually track T)",
                records.len()
            ));
        }
        finish_scenario(
            Diagnostics {
                scenario: "scenario 12a a_sustained_rejection_flood_bounds_the_audit_row_count",
                verdict: "pass",
                rss_baseline_kib: None,
                rss_peak_kib: None,
                rss_idle_kib: None,
                rss_bound_kib: 0,
                fd_baseline: None,
                fd_peak: None,
                fd_after: None,
                fd_delta_bound: 0,
                echo_baseline_p95_ms: None,
                echo_load_p95_ms: None,
                echo_samples: 0,
                echo_threshold_ms: None,
                nofile_limit: nofile_limit(),
                nproc: nproc(),
                bin: &load_bin(),
                dial_report: None,
            },
            violations,
        );
    }

    /// Scenario 12b (`BRIEF-4c.md` §4.4/J7, split by A4/B5, reworked
    /// Stage 4c-F2c per F2a's 반박 2): `[audit].max_bytes` narrowed to a
    /// few hundred bytes so rotation *actually happens repeatedly* (A4's
    /// fix), driven by an `open_close_cycle` of ordinary allowed
    /// `session.open`/`close` traffic instead of a rejection flood — 12a's
    /// `FLOOD_DURATION=8s` used to be shorter than the default 10s
    /// `AUDIT_AGGREGATION_WINDOW`, so the old rejection-row construction
    /// could rotate once or twice at most (not enough to distinguish
    /// "retention enforced" from "retention disabled" — both look like a
    /// couple of files). Deterministic row count (`ITERATIONS`, one
    /// `allow` row per open, no aggregation window in the way at all)
    /// instead forces double-digit rotation counts, and the
    /// currently-present rotated-file count is asserted to equal
    /// `AUDIT_RETAIN` exactly — the number of *rotations that happened* is
    /// not directly observable once retention has deleted the older ones,
    /// but that is exactly the point: if retention were disabled, this
    /// count would equal every rotation instead of just the last
    /// `AUDIT_RETAIN`. Separate `ServeGuard`/sandbox from 12a (its own
    /// `[audit]` config).
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sustained_open_close_flood_rotates_and_bounds_audit_directory_bytes() {
        if !gate_requested() {
            skip();
            return;
        }
        const AUDIT_MAX_BYTES: u64 = 512;
        const AUDIT_RETAIN: u64 = 2;
        const CONFIG: &str = "[serve]\nhandshake_rate_per_source = 200\n\
                           validated_rate_per_source = 200\n\n[audit]\nmax_bytes = 512\n\
                           retain = 2\n";
        // Each `session.open` writes one `allow` audit row; at ~200 B/row
        // and `max_bytes=512`, ~2-3 rows fill one file, so 40 rows forces
        // well past 10 rotations — comfortably enough to distinguish
        // "the last `AUDIT_RETAIN` rotated files survive" from "every
        // rotated file survives" (B5/F2a 반박 2).
        const ITERATIONS: usize = 40;

        let (mut fleet, identity) = boot_with_flood_client(CONFIG);
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");
        let server_fp = fleet.host.fingerprint();
        let dialer = Arc::new(flood_dialer(&identity, &server_fp));

        open_close_cycle(&dialer, addr, ITERATIONS).await;

        fleet.serve.signal(nix::sys::signal::Signal::SIGTERM);
        let status = fleet
            .serve
            .wait_timeout(Duration::from_secs(10))
            .unwrap_or_else(|| panic!("qsh serve did not exit within 10s of SIGTERM"));
        let output = fleet.serve.captured();
        let no_panic = !output.stderr.iter().any(|line| line.contains("panicked"));

        // `audit.log.<N>` only — not F6's `audit.log.lock` advisory-lock
        // sidecar, which also matches a bare `starts_with("audit.log.")`
        // (Stage 4c-F2c's own first WSL run caught this: it counted the
        // lock file as a third "rotated" file).
        let rotated_count = std::fs::read_dir(fleet.host.state_dir())
            .expect("read state dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_prefix("audit.log.")
                    .is_some_and(|suffix| suffix.parse::<u32>().is_ok())
            })
            .count();
        let dir_bytes: u64 = std::fs::read_dir(fleet.host.state_dir())
            .expect("read state dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with("audit.log") && !name.ends_with(".lock")
            })
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        let byte_bound = AUDIT_MAX_BYTES * (AUDIT_RETAIN + 1);

        eprintln!(
            "scenario 12b a_sustained_open_close_flood_rotates_and_bounds_audit_directory_bytes: \
         rotated files present: {rotated_count} (want {AUDIT_RETAIN}), dir bytes {dir_bytes} \
         (bound {byte_bound}, max_bytes={AUDIT_MAX_BYTES} retain={AUDIT_RETAIN}, \
         iterations={ITERATIONS})"
        );

        let mut violations = Vec::new();
        if !status.success() {
            violations.push(format!("qsh serve exited {status:?} on SIGTERM, not 0"));
        }
        if !no_panic {
            violations.push(format!("panic on stderr: {:?}", output.stderr));
        }
        if rotated_count as u64 != AUDIT_RETAIN {
            violations.push(format!(
                "{rotated_count} audit.log.N files present after {ITERATIONS} allowed opens at \
             max_bytes={AUDIT_MAX_BYTES} — expected exactly retain={AUDIT_RETAIN} (A4: rotation \
             must actually run repeatedly; B5/F2a 반박 2: retention must actually be enforced, \
             not just rotation happening once or twice)"
            ));
        }
        if dir_bytes > byte_bound {
            violations.push(format!(
                "audit directory bytes {dir_bytes} exceeded {byte_bound} (max_bytes=\
             {AUDIT_MAX_BYTES} * (retain={AUDIT_RETAIN} + 1))"
            ));
        }
        finish_scenario(
            Diagnostics {
                scenario: "scenario 12b a_sustained_open_close_flood_rotates_and_bounds_audit_directory_bytes",
                verdict: "pass",
                rss_baseline_kib: None,
                rss_peak_kib: None,
                rss_idle_kib: None,
                rss_bound_kib: 0,
                fd_baseline: None,
                fd_peak: None,
                fd_after: None,
                fd_delta_bound: 0,
                echo_baseline_p95_ms: None,
                echo_load_p95_ms: None,
                echo_samples: 0,
                echo_threshold_ms: None,
                nofile_limit: nofile_limit(),
                nproc: nproc(),
                bin: &load_bin(),
                dial_report: None,
            },
            violations,
        );
    }

    // Scenario 12c (`BRIEF-4c.md` §4.6/A17) was attempted and dropped
    // in this stage (4c-F2) per the escape clause A17/§4.6 itself names
    // ("결정적으로 안 되면 근거 적고 뺀다"). The construction A17 proposed
    // — `chmod 500` the state directory to force `rotate_files`'s
    // `fs::rename` to EACCES — never reaches the fail-closed
    // `PERMISSION_DENIED` latch this scenario was meant to observe,
    // and cannot by this writer's own design:
    // `crates/qsh-core/src/audit/writer.rs`'s `rotate()` (F6 discipline,
    // doc comment there) treats a failed rename as *non-fatal* on
    // purpose — it logs a warning, skips rotation for that round, and
    // keeps appending to the still-open (still-writable — POSIX
    // permission checks happen at `open()`, not per-write, and the fd
    // was opened before the chmod) active file. Only a genuine failure
    // to *open* a destination file trips `degraded`
    // (`ensure_open()`'s own error path). Two runs of the constructed
    // scenario confirmed this empirically: repeated `session.open` +
    // `session.attach` + `session.close` cycles after `chmod 500` kept
    // succeeding (audit rows kept accumulating past `max_bytes`) all
    // the way to `Server::MAX_PENDING_TICKETS_PER_CONN` (32,
    // `server/mod.rs:159` — an unrelated hardcoded per-connection
    // ticket budget the loop exhausts well before any write ever
    // fails), never once hitting `PERMISSION_DENIED`. A construction
    // that actually reaches `degraded` would need to make the
    // *already-open* active file itself fail on write/reopen (e.g. a
    // fresh writer restart against a locked-down directory, or
    // removing the active file's own permissions rather than the
    // directory's) — out of this stage's scope; carried to Step 5.
    // The mandatory half of A17's judgment — the fail-closed contract
    // itself — is still pinned at the unit level by 4a's in-crate
    // `session_open_fails_closed_when_the_audit_sink_cannot_record_an_
    // allow` (`crates/qsh-core/src/server/mod.rs:5661`), unaffected by
    // this scenario's removal. M8 Step 5 (d)'s second construction below
    // (`session_open_fails_closed_when_a_freshly_restarted_writer_cannot_
    // create_the_audit_log`) is the "fresh writer restart" case this
    // comment names — it does reach `degraded` at the e2e level.

    /// Scenario 12c, second construction (`PLAN.md` M8 Step 5 (d),
    /// `ARBITRATION-5.md` "병행 정리 묶음 판정" Q5). The first construction
    /// (comment block directly above) locked the directory down *after*
    /// the writer already held an open fd on `audit.log` — POSIX
    /// permission checks happen at `open()`, not per-write, so it never
    /// reached `degraded`. This construction locks the directory down
    /// *before* any writer has ever opened `audit.log` in it, then starts
    /// a brand-new `qsh serve` (a fresh writer thread) against it: that
    /// writer's very first `ensure_open()` (`audit/writer.rs`) has to
    /// *create* the file (`OpenOptions::create(true)`), which needs write
    /// permission on the directory itself, not just an already-open fd.
    ///
    /// A manual reproduction against the debug binary (outside this
    /// suite, `scratchpad/d12c` — not part of the repo) confirmed the
    /// shape this test pins before writing it: `qsh serve` still binds
    /// and answers normally — `chmod 500` on `state_dir` never touches
    /// `identity`/`ca`/`trust`, which all live under the separate
    /// `config_dir` (`Paths::ca_dir`/`Paths::audit_log`'s own doc) — but
    /// the writer thread's first write trips `EACCES` creating
    /// `audit.log` and latches `degraded`
    /// (`crates/qsh-core/src/audit/writer.rs`'s own `tracing::error!` on
    /// that trip). Because that first write races the client's first
    /// `session.open` (`RotatingAuditSink::record`'s latch check runs
    /// before the background writer thread ever touches disk), the
    /// *first* attempt can still win the race and be admitted; every
    /// attempt after the latch is visibly tripped is deterministically
    /// `PERMISSION_DENIED`, and stays that way — the directory never
    /// becomes writable again, so the writer's own background retry
    /// (`RETRY_TICK`) can never clear it. This is outcome (i) of the
    /// stage's three-way judgment: the refusal is directly observed, so
    /// this test joins the strict axis (`QSH_LOAD_STRICT=1`) rather than
    /// being dropped again.
    ///
    /// Root bypasses every POSIX permission check this construction
    /// depends on (`chmod 500` on a directory does not stop `root` from
    /// creating files in it), so this test skips under uid 0 — A17's own
    /// judgment (`ARBITRATION-4.md` "12c 회전 실패 fail-closed를 A17의
    /// 구성으로 만든다... root면 skip") carried forward to this second
    /// construction.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn session_open_fails_closed_when_a_freshly_restarted_writer_cannot_create_the_audit_log()
    {
        if !gate_requested() {
            skip();
            return;
        }
        if running_as_root() {
            eprintln!(
                "SKIP: this construction depends on the POSIX permission check root bypasses \
                 (`chmod 500` on state_dir never stops root from creating `audit.log` in it), \
                 so it cannot observe the fail-closed latch under uid 0 — `ARBITRATION-4.md` \
                 \"12c 회전 실패 fail-closed를 A17의 구성으로 만든다... root면 skip\""
            );
            return;
        }

        let bin = load_bin();
        let host = Sandbox::initialized();
        let identity = make_identity();
        host.trust_add("flood", None, &identity.fingerprint.to_string());

        // First boot: a normal, writable state dir, but no session is ever
        // opened — no choke point (`Server::authorize` and siblings) ever
        // calls `record()`, so the writer thread never performs its first
        // write and `audit.log` is never created (`RotatingFile::
        // ensure_open` is lazy). This is the "no active file yet"
        // precondition the stage's construction depends on.
        {
            let serve = ServeGuard::start_with_bin(&host, &bin, &[]);
            assert!(
                !host.state_dir().join("audit.log").exists(),
                "a boot with no session opened must never create audit.log"
            );
            drop(serve); // Drop kills the child; no clean-shutdown drain needed here.
        }

        std::fs::set_permissions(host.state_dir(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod 500 the (still audit.log-less) state dir");

        // Second boot: a fresh writer thread against the now-locked-down
        // directory — the "writer restart" the stage's own name for this
        // construction refers to. `mut`: `finish()` at the end of this
        // test needs `&mut self` to drain the reader threads and capture
        // stderr.
        let mut serve = ServeGuard::start_with_bin(&host, &bin, &[]);
        let addr: SocketAddr = serve.addr().parse().expect("serve addr parses");
        let server_fp = host.fingerprint();
        let dialer = flood_dialer(&identity, &server_fp);

        let (mut session, _ep) = negotiate_session(&dialer, addr, "d12c")
            .await
            .expect("the QUIC connection itself must still be admitted (ACL is allow-all)");

        // Poll a bounded number of `session.open`s for the first
        // `PERMISSION_DENIED` — the very first can still win the race
        // against the writer's own first (failing) write attempt, so this
        // is not a one-shot assertion.
        const ATTEMPTS: usize = 50;
        let mut denied_at = None;
        for attempt in 0..ATTEMPTS {
            match session.session_open(open_req()).await {
                Ok(opened) => {
                    let _ = session.session_close(&opened.session_id, None).await;
                }
                Err(err) => {
                    let (code, retryable) = remote(err);
                    assert_eq!(
                        code,
                        ErrorCode::PermissionDenied,
                        "a degraded audit sink must fail closed with PERMISSION_DENIED, not any \
                         other code (attempt {attempt})"
                    );
                    assert!(
                        !retryable,
                        "PERMISSION_DENIED must not be marked retryable (attempt {attempt})"
                    );
                    denied_at = Some(attempt);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        session.close();

        let denied_at = denied_at.unwrap_or_else(|| {
            panic!(
                "expected a PERMISSION_DENIED session.open within {ATTEMPTS} attempts once the \
                 audit writer could never create audit.log; the fail-closed latch never tripped \
                 observably"
            )
        });

        // Once tripped, the latch must stay tripped — the directory never
        // becomes writable again, so a further attempt must also be
        // denied, not flap back to `Ok` on some later retry tick.
        let (mut session2, _ep2) = negotiate_session(&dialer, addr, "d12c-recheck")
            .await
            .expect("a new connection must still be admitted (ACL is allow-all)");
        let (code, retryable) = remote(
            session2
                .session_open(open_req())
                .await
                .expect_err("the degraded latch must still be tripped on a fresh connection"),
        );
        assert_eq!(code, ErrorCode::PermissionDenied);
        assert!(!retryable);
        session2.close();

        eprintln!(
            "scenario 12c (second construction) \
         session_open_fails_closed_when_a_freshly_restarted_writer_cannot_create_the_audit_log: \
         PERMISSION_DENIED first observed at attempt {denied_at}/{ATTEMPTS}"
        );

        // The writer's own `tracing::error!` (`crates/qsh-core/src/audit/
        // writer.rs`'s `handle_normal`, target `"qsh::audit"`) really does
        // reach this stderr at default verbosity: `common/mod.rs`'s
        // `.env_remove("QSH_LOG")` only strips an override, leaving the
        // child at `qsh-cli/src/main.rs`'s `init_tracing` default
        // (`cli.quiet == false`, `cli.verbose == 0`) `=> "warn"`, and
        // `ERROR` is strictly more severe than `WARN` — `EnvFilter` never
        // drops a level *above* the threshold it names. So (unlike
        // `qsh_core::telemetry`/`reverse::listen`'s dedicated targets,
        // which need `=info` appended to even reach `warn` default) the
        // degraded diagnostic needs no such carve-out and is asserted here
        // directly rather than falling back to a third `session.open` as
        // the latch-persistence-only proxy.
        let output = serve.finish();
        assert!(
            output
                .stderr
                .iter()
                .any(|line| line.contains("audit writer degraded")),
            "expected the writer's degraded diagnostic on stderr at default verbosity; got: \
             {:?}",
            output.stderr
        );
        assert!(
            !output.stderr.iter().any(|line| line.contains("panicked")),
            "the audit writer's write failure must degrade gracefully, never panic the serve \
             process; got: {:?}",
            output.stderr
        );

        // Restore state_dir's permissions before the sandbox's own
        // `TempDir` cleanup runs — `TempDir::drop` silently swallows a
        // removal failure under a still-locked-down directory rather than
        // panicking, so this is not required for correctness, but a
        // `chmod 500` directory left behind (however harmlessly reaped) is
        // not a state this test should hand back to whatever runs next.
        std::fs::set_permissions(host.state_dir(), std::fs::Permissions::from_mode(0o700))
            .expect("restore state_dir permissions before teardown");
    }

    /// Scenario 13 (`BRIEF-4c.md` §4.5/J13, B-P2-6): the *default*
    /// `max_tunnel_streams_per_forward=64` path, never exercised by any
    /// other test in the tree (`quota.rs`'s own twin lowers the cap to
    /// reach it quickly instead) — 512 concurrent TCP dials against one
    /// `-R` forward must admit exactly 64 and reject the remaining 448
    /// with no payload, leaving fds bounded both mid-flood and after.
    /// Carries the A-P2-5 diagnostic (normal `session.open` p95 during the
    /// accept flood) — observation only, no assertion.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn remote_forward_accepts_stay_bounded_at_the_default_per_forward_cap() {
        if !gate_requested() {
            skip();
            return;
        }
        const TOTAL: usize = 512;
        const CAP: usize = 64;
        const FD_SLACK: i64 = 8;

        let (mut fleet, identity) = boot_with_flood_client("");
        let pid = fleet.pid();
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");
        let server_fp = fleet.host.fingerprint();
        let dialer = flood_dialer(&identity, &server_fp);

        // The forward's destination: a plain in-process TCP echo server —
        // only the accept-cap axis is under test here, not the splice
        // itself (already proven end to end by `tunnel_e2e.rs`/L5).
        let echo_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local echo destination");
        let echo_port = echo_listener.local_addr().expect("echo addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = echo_listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        let (mut rfwd, rfwd_ep) = negotiate_session(&dialer, addr, "rfwd-control")
            .await
            .expect("the -R control connection must be admitted");
        let acceptor = RemoteForwardAcceptor::spawn(rfwd.connection().clone()).await;
        let opened = rfwd
            .rfwd_open(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                forward_host: "127.0.0.1".into(),
                forward_port: u32::from(echo_port),
                claim_token: Vec::new(),
            })
            .await
            .expect("RemoteForwardOpen must succeed at the default forward cap");
        acceptor.register(opened.forward_id.clone(), "127.0.0.1".into(), echo_port);
        let host_port = u16::try_from(opened.actual_port).expect("actual_port fits u16");
        let host_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

        // J9 fd baseline: one throwaway session.open+close on the same
        // control connection, same reasoning as scenarios 1/2/3.
        let warm = rfwd
            .session_open(open_req())
            .await
            .expect("warm-up session.open must be admitted");
        let _ = rfwd.session_close(&warm.session_id, None).await;
        let (fd_baseline, _) = poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;
        let (rss_baseline, _) = poll_stable(|| rss_kib(pid)).await;

        enum Outcome {
            Accepted(TcpStream),
            Rejected,
        }
        fn classify(err: std::io::Error) -> Outcome {
            match err.kind() {
                std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                // 4c adversarial review B9: the server closes a rejected
                // TCP stream right after accepting it, so a client's own
                // `write_all` can race an already-arrived RST and see
                // EPIPE (BrokenPipe) rather than the read-side errors
                // above — a normal kernel ordering under 512 concurrent
                // dials, not a real failure. `ConnectionRefused` is
                // deliberately *not* here: that means no listener at all.
                | std::io::ErrorKind::BrokenPipe => Outcome::Rejected,
                other => panic!("unexpected TCP error on a forward accept: {other:?} ({err})"),
            }
        }

        let p95_dialer = flood_dialer(&identity, &server_fp);
        let mut p95_session = negotiate_session(&p95_dialer, addr, "p95-probe")
            .await
            .expect("the p95 probe connection must be admitted");
        let p95_probe = async {
            let mut samples = Vec::new();
            for _ in 0..30 {
                let start = std::time::Instant::now();
                match p95_session.0.session_open(open_req()).await {
                    Ok(o) => {
                        let _ = p95_session.0.session_close(&o.session_id, None).await;
                        samples.push(start.elapsed().as_secs_f64() * 1000.0);
                    }
                    Err(_) => break,
                }
            }
            samples
        };

        let dial_all = async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..TOTAL {
                tasks.spawn(async move {
                    // 4c adversarial review A10: this only asserts that
                    // the TCP-level connect (SYN/SYN-ACK, well below qsh's
                    // own accept loop) succeeds — a rejection landing
                    // *before* any QUIC stream opens is a qsh-core
                    // property this e2e harness cannot observe from a bare
                    // TCP socket and does not claim to; that property is
                    // `tunnel/remote.rs`'s own
                    // `remote_forward_accept_past_the_per_forward_stream_cap_is_closed_before_any_quic_stream_opens`.
                    let mut sock = TcpStream::connect(host_addr)
                        .await
                        .expect("the TCP connect itself must succeed at the listener backlog");
                    if let Err(e) = sock.write_all(b"ping").await {
                        return classify(e);
                    }
                    let mut buf = [0u8; 4];
                    match sock.read_exact(&mut buf).await {
                        Ok(n) if n == buf.len() && buf == *b"ping" => Outcome::Accepted(sock),
                        Ok(_) => panic!("garbled echo through an accepted forward stream"),
                        Err(e) => classify(e),
                    }
                });
            }
            let mut results = Vec::with_capacity(TOTAL);
            while let Some(result) = tasks.join_next().await {
                results.push(result.expect("dial task panicked"));
            }
            results
        };

        let (p95_samples, results) = tokio::join!(p95_probe, dial_all);

        let mut held_socks = Vec::new();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for r in results {
            match r {
                Outcome::Accepted(sock) => {
                    accepted += 1;
                    held_socks.push(sock);
                }
                Outcome::Rejected => rejected += 1,
            }
        }
        assert_eq!(
            accepted, CAP,
            "exactly {CAP} of {TOTAL} dials must be admitted"
        );
        assert_eq!(
            rejected,
            TOTAL - CAP,
            "the remaining dials must all be refused"
        );

        let (fd_peak, fd_peak_converged) =
            poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;
        drop(held_socks);

        let records = wait_for_audit(&fleet.host, "quota_tunnels_forward", |v| {
            v["resource"] == "quota_tunnels_forward"
        });
        let forward_rows = records
            .iter()
            .filter(|v| v["resource"] == "quota_tunnels_forward")
            .count();
        assert!(
            (1..=2).contains(&forward_rows),
            "quota_tunnels_forward must land as first-row + summary only, not one row per \
         rejection ({forward_rows} rows for {} rejections): {records:#?}",
            TOTAL - CAP
        );

        p95_session.0.close();
        drop(p95_session.1);
        rfwd.close();
        drop(rfwd_ep);
        let (rss_idle, _) = poll_stable(|| rss_kib(pid)).await;
        let (fd_after, fd_after_converged) =
            poll_stable(|| open_fd_count(pid).map(|n| n as u64)).await;

        assert!(
            server_alive(&mut fleet),
            "the serve subprocess must survive the accept flood"
        );

        let p95_ms = if p95_samples.len() >= 5 {
            Some(percentile(p95_samples.clone(), 0.95))
        } else {
            None
        };
        let diag = Diagnostics {
            scenario: "scenario 13 remote_forward_accepts_default_cap",
            verdict: "pass",
            rss_baseline_kib: rss_baseline,
            rss_peak_kib: None,
            rss_idle_kib: rss_idle,
            rss_bound_kib: RSS_IDLE_BOUND_KIB,
            fd_baseline: fd_baseline.map(|n| n as usize),
            fd_peak: fd_peak.map(|n| n as usize),
            fd_after: fd_after.map(|n| n as usize),
            fd_delta_bound: 0,
            echo_baseline_p95_ms: None,
            echo_load_p95_ms: p95_ms,
            echo_samples: p95_samples.len(),
            echo_threshold_ms: None,
            nofile_limit: nofile_limit(),
            nproc: nproc(),
            bin: &load_bin(),
            dial_report: None,
        };
        eprintln!(
            "  A-P2-5 (diagnostic only, no assertion): session.open p95 during the accept \
         flood {} ms over {} samples\n  quota_tunnels_forward rows: {forward_rows} \
         (first+summary bound 2)",
            p95_ms
                .map(|v| format!("{v:.3}"))
                .unwrap_or_else(|| "n/a".into()),
            p95_samples.len()
        );

        let mut violations = Vec::new();
        if let (Some(base), Some(peak)) = (fd_baseline, fd_peak)
            && peak as i64 - base as i64 > CAP as i64 + FD_SLACK
        {
            violations.push(format!(
                "fd delta at peak ({peak} - {base}) must be <= {CAP}+{FD_SLACK} (converged: \
                 {fd_peak_converged})"
            ));
        }
        if let Some(idle) = rss_idle
            && !(idle > RSS_FLOOR_KIB && idle <= RSS_IDLE_BOUND_KIB)
        {
            violations.push(format!(
                "idle rss {idle} KiB must clear the {RSS_FLOOR_KIB} KiB floor and stay under \
                 the {RSS_IDLE_BOUND_KIB} KiB idle bound"
            ));
        }
        if let (Some(after), Some(base)) = (fd_after, fd_baseline)
            && after as i64 - base as i64 > 0
        {
            violations.push(format!(
                "fd delta after close ({after} - {base}) must be <= 0 (converged: \
                 {fd_after_converged})"
            ));
        }
        finish_scenario(diag, violations);
    }

    /// Scenario 13, assertion 7 (`BRIEF-4c.md` §4.5 item 7): with
    /// `max_tunnel_streams_per_principal` lowered below the forward's own
    /// default cap, the rejection category must shift from
    /// `quota_tunnels_forward` to `quota_tunnels_principal` — same accept
    /// path, a different choke point tripped first.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn remote_forward_accepts_are_capped_by_the_principal_limit_when_lower() {
        if !gate_requested() {
            skip();
            return;
        }
        const CONFIG: &str = "[serve]\nmax_tunnel_streams_per_principal = 4\n";
        const DIALS: usize = 12;

        let (mut fleet, identity) = boot_with_flood_client(CONFIG);
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");
        let server_fp = fleet.host.fingerprint();
        let dialer = flood_dialer(&identity, &server_fp);

        let echo_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local echo destination");
        let echo_port = echo_listener.local_addr().expect("echo addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = echo_listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        let (mut rfwd, rfwd_ep) = negotiate_session(&dialer, addr, "rfwd-control")
            .await
            .expect("the -R control connection must be admitted");
        let acceptor = RemoteForwardAcceptor::spawn(rfwd.connection().clone()).await;
        let opened = rfwd
            .rfwd_open(wire::RemoteForwardOpen {
                bind_host: String::new(),
                bind_port: 0,
                forward_host: "127.0.0.1".into(),
                forward_port: u32::from(echo_port),
                claim_token: Vec::new(),
            })
            .await
            .expect("RemoteForwardOpen must succeed");
        acceptor.register(opened.forward_id.clone(), "127.0.0.1".into(), echo_port);
        let host_port = u16::try_from(opened.actual_port).expect("actual_port fits u16");
        let host_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

        let mut held = Vec::new();
        for _ in 0..DIALS {
            if let Ok(mut sock) = TcpStream::connect(host_addr).await {
                let _ = sock.write_all(b"ping").await;
                let mut buf = [0u8; 4];
                if sock.read_exact(&mut buf).await.is_ok() {
                    held.push(sock);
                }
            }
        }
        assert_eq!(
            held.len(),
            4,
            "exactly 4 dials must succeed under a principal cap of 4"
        );

        let records = wait_for_audit(&fleet.host, "quota_tunnels_principal", |v| {
            v["resource"] == "quota_tunnels_principal"
        });
        assert!(
            records
                .iter()
                .any(|v| v["resource"] == "quota_tunnels_principal"),
            "with max_tunnel_streams_per_principal below the forward default, the rejection \
         category must be quota_tunnels_principal: {records:#?}"
        );
        assert!(
            !records
                .iter()
                .any(|v| v["resource"] == "quota_tunnels_forward"),
            "the forward-level cap (64) is never reached at {DIALS} dials — only the lower \
         principal cap should fire: {records:#?}"
        );

        drop(held);
        rfwd.close();
        drop(rfwd_ep);
        assert!(
            server_alive(&mut fleet),
            "the serve subprocess must survive the principal-cap variant"
        );
        eprintln!(
            "scenario 13 (principal-cap variant): 4 of {DIALS} admitted, rejection category \
         quota_tunnels_principal confirmed"
        );
    }

    /// A-P2-4 diagnostic (`BRIEF-4c.md` §4.5, code change deferred to Step
    /// 5): two independently owned `-R` forwards' accept-cap rejections
    /// share the *same* `quota_tunnels_forward` audit window — it is keyed
    /// on category alone (`crates/qsh-core/src/quota.rs:724`-adjacent), so
    /// once principal A's own forward rejection has already opened this
    /// run's window, principal B's own forward's first rejection inside
    /// the same window lands only as a summary bump, never a fresh
    /// first-row of its own. Observation only, no hard assertion — the
    /// brief calls this a diagnostic, not a bound.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_principals_forward_rejection_shares_the_first_principals_audit_window() {
        if !gate_requested() {
            skip();
            return;
        }
        const CONFIG: &str = "[serve]\nmax_tunnel_streams_per_forward = 1\n";

        let bin = load_bin();
        let host = Sandbox::initialized();
        let a = make_identity();
        let b = make_identity();
        host.trust_add("flood-a", None, &a.fingerprint.to_string());
        host.trust_add("flood-b", None, &b.fingerprint.to_string());
        std::fs::write(host.config_dir().join("config.toml"), CONFIG).expect("write config.toml");
        let serve = ServeGuard::start_with_bin(&host, &bin, &[]);
        let mut fleet = LoadFleet { host, serve };
        let addr: SocketAddr = fleet.serve.addr().parse().expect("serve addr parses");
        let server_fp = fleet.host.fingerprint();

        /// A do-nothing local destination for the forward to dial into on
        /// each accept — must actually be listening, or the dispatch task's
        /// own dial back to it fails and resets the *server-side* TCP
        /// accept before any quota decision is even reachable (a real qsh
        /// error, not a test setup shortcut: WSL 실측, Stage 4c-S3).
        async fn discard_listener() -> u16 {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind discard destination");
            let port = listener.local_addr().expect("discard addr").port();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    drop(sock);
                }
            });
            port
        }

        async fn open_forward(
            dialer: &Dialer,
            addr: SocketAddr,
            name: &str,
        ) -> (Session, Endpoint, RemoteForwardAcceptor, SocketAddr) {
            let discard_port = discard_listener().await;
            let (mut session, ep) = negotiate_session(dialer, addr, name)
                .await
                .expect("control connection admitted");
            let acceptor = RemoteForwardAcceptor::spawn(session.connection().clone()).await;
            let opened = session
                .rfwd_open(wire::RemoteForwardOpen {
                    bind_host: String::new(),
                    bind_port: 0,
                    forward_host: "127.0.0.1".into(),
                    forward_port: u32::from(discard_port),
                    claim_token: Vec::new(),
                })
                .await
                .expect("RemoteForwardOpen");
            acceptor.register(opened.forward_id.clone(), "127.0.0.1".into(), discard_port);
            let port = u16::try_from(opened.actual_port).expect("port fits u16");
            (
                session,
                ep,
                acceptor,
                SocketAddr::from(([127, 0, 0, 1], port)),
            )
        }

        let dialer_a = flood_dialer(&a, &server_fp);
        let dialer_b = flood_dialer(&b, &server_fp);
        let (session_a, ep_a, _acc_a, addr_a) = open_forward(&dialer_a, addr, "fwd-a").await;
        let (session_b, ep_b, _acc_b, addr_b) = open_forward(&dialer_b, addr, "fwd-b").await;

        let _hold_a = TcpStream::connect(addr_a)
            .await
            .expect("the first dial on forward a must be admitted (cap 1)");
        let _reject_a = TcpStream::connect(addr_a)
            .await
            .expect("the TCP connect itself must succeed — only the permit is refused");
        let records_after_a = wait_for_audit(&fleet.host, "quota_tunnels_forward", |v| {
            v["resource"] == "quota_tunnels_forward"
        });
        let rows_after_a = records_after_a
            .iter()
            .filter(|v| v["resource"] == "quota_tunnels_forward")
            .count();

        let _hold_b = TcpStream::connect(addr_b)
            .await
            .expect("the first dial on forward b must be admitted (cap 1)");
        let _reject_b = TcpStream::connect(addr_b)
            .await
            .expect("the TCP connect itself must succeed — only the permit is refused");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let records_after_b = fleet.host.audit_records();
        let rows_after_b = records_after_b
            .iter()
            .filter(|v| v["resource"] == "quota_tunnels_forward")
            .count();

        eprintln!(
            "A-P2-4 (diagnostic only, no assertion): quota_tunnels_forward rows after \
         principal A's first rejection: {rows_after_a}; after principal B's own first \
         rejection in the same window: {rows_after_b} (a fresh first-row of B's own would read \
         {}, a shared-window summary bump reads {rows_after_a})",
            rows_after_a + 1
        );

        session_a.close();
        session_b.close();
        drop(ep_a);
        drop(ep_b);
        assert!(
            server_alive(&mut fleet),
            "the serve subprocess must survive the A-P2-4 probe"
        );
    }
} // mod linux_only
