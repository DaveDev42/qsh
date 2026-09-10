//! M8 Step 5b — the 24h/100-session soak harness (`BRIEF-5.md` §4,
//! `docs/ROADMAP.md` M8 DoD 2).
//!
//! One scenario, one env gate, two speeds:
//!
//! - Short mode (the default: 120s / 8 sessions) is what `[profile.load]`
//!   runs under `.github/workflows/load.yml`'s `QSH_LOAD_STRICT=1`
//!   gate — a regression watchdog on every push, same shape as T2's
//!   `adversarial_load.rs`.
//! - 24h/100-session mode is the same test binary, driven by
//!   `scripts/soak/run.sh` under `[profile.soak]` on a dedicated Linux
//!   host, with every phase length and session count overridden by env
//!   (`QSH_SOAK_*`, see [`Params::from_env`]).
//!
//! Unlike T2, this scenario drives its client side through the real
//! [`Ops`] facade — `session_open`/`session_attach` — rather than a raw
//! wire client: `Ops::session_attach`'s `connect_target` call is exactly
//! the per-pull dial path M7 carryover (iii) is about (`BRIEF-5.md` §1.1,
//! `crates/qsh-core/src/ops/session.rs:1057`), so every cycle's replacement
//! session is a real fresh dial, not a simulation of one.
//!
//! `rss_kib`/`open_fd_count` are Linux-only (`qsh_testkit::procstat`), so
//! this file compiles and runs its skip path on every platform but only
//! ever measures anything on Linux — same discipline as
//! `adversarial_load.rs`, expressed as a runtime check here instead of a
//! `#[cfg(target_os = "linux")]` module split, because a caller who sets
//! `QSH_LOAD_STRICT=1` on a non-Linux host needs a loud, explicit failure
//! (`BRIEF-5.md` §2), not a silent compile-time absence.

mod common;

use common::{
    CLIENT_ALIAS, HOST_ALIAS, Sandbox, ServeGuard, ensure_nofile_limit, open_fd_count, poll_stable,
    rss_kib,
};
use qsh_core::{Ops, Paths, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{
    EnvVar, ErrorCode, SessionAttachReq, SessionCloseReq, SessionGetReq, SessionOpenReq,
};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// CSV header, pinned (`BRIEF-5.md` §4.3): `scripts/soak/summarize.py` and
/// `docs/campaigns/m8-soak.md`'s record template both depend on this exact
/// column order and spelling never drifting out from under them.
pub const SOAK_CSV_HEADER: &str = "t_secs,phase,listener_rss_kib,listener_fds,self_rss_kib,self_fds,live_sessions,cycles,echo_p95_ms,abandoned_live";

/// Pure pin test — no env gate, runs on every platform including macOS
/// (same "helper unit tests are pure-function level" discipline
/// `adversarial_load.rs`'s `converged_requires_three_consistent_samples_
/// by_the_one_percent_bound` uses).
#[test]
fn soak_csv_header_is_pinned() {
    assert_eq!(
        SOAK_CSV_HEADER,
        "t_secs,phase,listener_rss_kib,listener_fds,self_rss_kib,self_fds,live_sessions,cycles,\
         echo_p95_ms,abandoned_live"
    );
}

/// `scripts/soak/summarize.py`'s `CSV_HEADER` must be the exact same
/// string as [`SOAK_CSV_HEADER`] — the two used to be "pinned" only by a
/// comment on each side pointing at the other, which a drifted edit on
/// either file would not catch (REVIEW-5-B B10 / ARBITRATION-5 F2). This
/// reads the actual script source at compile time and greps for the
/// literal, so a hand-edit to either constant that breaks the match fails
/// this test instead of silently drifting until a CSV round-trip fails at
/// campaign time.
#[test]
fn summarize_py_pins_the_same_csv_header() {
    let summarize_py = include_str!("../../../scripts/soak/summarize.py");
    assert!(
        summarize_py.contains(SOAK_CSV_HEADER),
        "scripts/soak/summarize.py must contain the exact SOAK_CSV_HEADER literal \
         ({SOAK_CSV_HEADER:?}) as its own CSV_HEADER value — got a script that does not"
    );
}

fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim().to_string();
    !(value.is_empty() || value == "0")
}

/// Whether the soak scenario should run at all — same `QSH_LOAD_STRICT`
/// gate T2 uses (`BRIEF-5.md` §4.2: soak is a scenario in the same load
/// harness family, not a separate gate name).
fn gate_requested() -> bool {
    env_flag("QSH_LOAD_STRICT")
}

fn skip() {
    eprintln!(
        "SKIP: the soak scenario requires QSH_LOAD_STRICT=1 (not set on this run) plus \
         QSH_LOAD_BIN pointing at a release `qsh` build — `.github/workflows/load.yml` sets \
         both for the short mode; 24h/100-session mode is driven by `scripts/soak/run.sh` on a \
         dedicated Linux host. Locally: cargo build --release -p qsh-cli && \
         QSH_LOAD_STRICT=1 QSH_LOAD_BIN=$(pwd)/target/release/qsh cargo nextest run --profile \
         load -p qsh-cli --test soak"
    );
}

/// Resolve the release `qsh` binary this scenario measures — same
/// no-silent-fallback contract as `adversarial_load.rs::load_bin`.
fn load_bin() -> PathBuf {
    std::env::var_os("QSH_LOAD_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "QSH_LOAD_STRICT=1 but QSH_LOAD_BIN is not set — the soak scenario measures a \
                 release `qsh` binary and refuses to silently substitute the nextest-built debug \
                 binary; set QSH_LOAD_BIN=$(pwd)/target/release/qsh after `cargo build --release \
                 -p qsh-cli`."
            )
        })
}

/// Read `name` as a `u64`, or `default` when it is unset — but an env var
/// that *is* set and fails to parse panics with a clear message instead of
/// silently falling back to `default` (`BRIEF-5.md` §4.2's env knobs are
/// meant to be typo-caught immediately, not to quietly run the short-mode
/// default while the caller believes they set a 24h vector — REVIEW-5-B
/// B13 / ARBITRATION-5 F2).
fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => raw
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("{name}={raw:?} is not a valid non-negative integer: {e}")),
        Err(std::env::VarError::NotPresent) => default,
        Err(e) => panic!("{name}: {e}"),
    }
}

/// Same contract as [`env_u64`], for `f64`-valued knobs (`QSH_SOAK_CYCLE_
/// FRACTION`).
fn env_f64(name: &str, default: f64) -> f64 {
    match std::env::var(name) {
        Ok(raw) => raw
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("{name}={raw:?} is not a valid number: {e}")),
        Err(std::env::VarError::NotPresent) => default,
        Err(e) => panic!("{name}: {e}"),
    }
}

/// The scenario's env-tunable knobs (`BRIEF-5.md` §4.2's table). Defaults
/// are the short mode; the 24h/100-session mode is
/// `86400/100/5/60/0.1/5/600/<csv>`.
struct Params {
    duration: Duration,
    sessions: usize,
    sample: Duration,
    cycle: Duration,
    cycle_fraction: f64,
    abandon: usize,
    resume_ttl_secs: u64,
    csv_path: Option<PathBuf>,
}

impl Params {
    fn from_env() -> Self {
        let params = Self {
            duration: Duration::from_secs(env_u64("QSH_SOAK_DURATION_SECS", 120)),
            sessions: env_u64("QSH_SOAK_SESSIONS", 8) as usize,
            sample: Duration::from_secs(env_u64("QSH_SOAK_SAMPLE_SECS", 2)),
            cycle: Duration::from_secs(env_u64("QSH_SOAK_CYCLE_SECS", 20)),
            cycle_fraction: env_f64("QSH_SOAK_CYCLE_FRACTION", 0.125),
            abandon: env_u64("QSH_SOAK_ABANDON", 1) as usize,
            resume_ttl_secs: env_u64("QSH_SOAK_RESUME_TTL_SECS", 30),
            csv_path: std::env::var_os("QSH_SOAK_CSV").map(PathBuf::from),
        };
        assert!(
            params.abandon < params.sessions,
            "QSH_SOAK_ABANDON ({}) must be less than QSH_SOAK_SESSIONS ({}) — the scenario needs \
             at least one session left in the cycle pool after the always-abandoned prefix",
            params.abandon,
            params.sessions
        );
        params
    }

    /// `ceil(sessions * cycle_fraction)`, at least 1 (`BRIEF-5.md` §4.3
    /// step 3).
    fn cycle_batch(&self) -> usize {
        ((self.sessions as f64) * self.cycle_fraction)
            .ceil()
            .max(1.0) as usize
    }
}

/// The idle-listener bound every phase's `listener_rss_kib` sample is
/// judged against (`docs/PRD.md:286`, `BRIEF-5.md` §4.4).
const IDLE_RSS_BOUND_KIB: u64 = 30 * 1024;

/// Per-session buffer allowance (`docs/PRD.md:287`, `BRIEF-5.md` §4.4).
const PER_SESSION_BUFFER_KIB: u64 = 8 * 1024;

/// fd growth allowance across a phase (`BRIEF-5.md` §4.4): "does not grow
/// by more than 2" for both the listener and this test process.
const FD_GROWTH_ALLOWANCE: i64 = 2;

/// Floor of the echo p95 bound — same formula T2's scenario 3 uses
/// (`docs/design/testing.md:126`): `max(3 * ramp-phase baseline p95, this
/// floor)`. A fixed absolute number is what a shared, contended CI runner
/// cannot promise; this floor only kicks in when the same run's own
/// baseline was already fast (REVIEW-5-C C9 / ARBITRATION-5 F2).
const ECHO_P95_FLOOR_MS: f64 = 50.0;

/// Fraction of steady-phase echo p95 windows allowed to exceed
/// [`ECHO_P95_FLOOR_MS`]'s bound before the run is `ECHO_DEGRADED`
/// (`ARBITRATION-5` "load.yml 첫 GHA soak 실행 판정", GHA run 34203445617,
/// b9e67b1). The rule this constant replaced was "no steady window's p95
/// may ever exceed the bound" — that first real GHA run hit exactly 2 of 59
/// steady windows spiking to 129.5ms and 114.6ms while every other window
/// stayed at 1-2ms, and both spikes landed on top of a cycle's session
/// replacement (close + dial/open/attach), not a sustained regression. A
/// single-window ceiling breaks the first time a session spawn contends for
/// the runner's 4 shared vCPUs, and a 24h/100-session run (on the order of
/// 17k steady windows) is certain to hit that at least once, so it was
/// judging CI noise, not degradation. This fraction rule instead only flags
/// a run where more than 10% of all steady windows spiked; `SESSION_
/// STALLED`'s per-round 5s deadline remains the separate guard against a
/// session that never recovers, so a spike that never resolves is still
/// caught there, not silently absorbed by this fraction. The max observed
/// p95, the spike count, and the first/last-quarter median are recorded as
/// informational items — inputs for a future 24h-run degradation rule, not
/// asserted here.
const ECHO_SPIKE_FRACTION_MAX: f64 = 0.10;

/// Minimum steady-phase sample count before a fd-growth quarters check
/// (`quarter_split`) is trusted as a hard assert rather than downgraded to
/// an informational note — with fewer samples than this, "first quarter"
/// and "last quarter" are one or two points each and the comparison is
/// mostly noise. Mirrors `scripts/soak/summarize.py`'s identical constant
/// (REVIEW-5-C/B B8 / ARBITRATION-5 F2).
const MIN_QUARTER_SAMPLES: usize = 8;

/// `qsh_core::broker::REAPER_TICK` + `qsh_core::broker::CLOSED_RETENTION` —
/// both `pub` (verified: `crates/qsh-core/src/lib.rs` has `pub mod broker`,
/// and both constants are `pub const` on it), so this references them
/// directly rather than inlining their values by hand; a future change to
/// either constant now shows up here automatically instead of silently
/// diverging. This is the fixed wait every mode uses in the drain phase so
/// a cycle-pool session's own `session.close` (not the TTL path) has time
/// to reap before the idle-end sample — unrelated to `resume_ttl_secs`,
/// which is independently env-tunable; see [`ttl_reap_deadline`] for the
/// abandoned-session check, which must never compare against this instead
/// (REVIEW-5-C C4 / REVIEW-5-B B7 / ARBITRATION-5 F2 — an earlier version
/// of this file did exactly that, and it made any run with
/// `resume_ttl_secs` set above ~60s fail spuriously).
const DRAIN_WAIT: Duration = Duration::from_secs(
    qsh_core::broker::REAPER_TICK.as_secs() + qsh_core::broker::CLOSED_RETENTION.as_secs(),
);

/// The point by which an abandoned session's resume TTL should have
/// expired *and* the reaper should have swept it at least once since —
/// `resume_ttl_secs` (env-tunable, up to 600s in 24h mode) plus one
/// `REAPER_TICK`. [`DRAIN_WAIT`] above is a fixed constant sized for a
/// different thing (the cycle-pool sessions' cooperative `session.close`
/// path) and must not be reused here.
fn ttl_reap_deadline(params: &Params) -> Duration {
    Duration::from_secs(params.resume_ttl_secs) + qsh_core::broker::REAPER_TICK
}

/// A `qsh serve` release subprocess plus a pinned client sandbox
/// (`common::Fleet`'s shape, but against the release binary — mirrors
/// `adversarial_load.rs::LoadFleet`/`boot`).
struct SoakFleet {
    /// Kept alive only for its `Drop` (the sandbox's `TempDir`, which the
    /// running `serve` child's config/state directories live under) — no
    /// field read after `boot()` returns, same as `adversarial_load.rs`'s
    /// `LoadFleet` fields.
    #[allow(dead_code)]
    host: Sandbox,
    client: Sandbox,
    serve: ServeGuard,
}

/// `max_connections_per_principal`/`max_connections` (`crates/qsh-core/
/// src/config.rs`'s `ServeConfig`) for an `N`-session soak run: each
/// session in this harness holds its own independent QUIC connection (not
/// a shared control connection multiplexing N sessions), so an N=100 run
/// needs a principal-level cap north of 100, not the product default of 32
/// (`ServeConfig::DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL`) — at that
/// default the 33rd ramp session's `session_attach` is rejected with
/// `RESOURCE_EXHAUSTED`, which is not retryable, and ramp panics
/// (REVIEW-5-B B1 / ARBITRATION-5 F2). `max(64, 2*N)` and `max(512, 4*N)`
/// give headroom for the cycle-replacement window, where a victim's old
/// connection can still be tearing down while its replacement's new one is
/// already established.
fn listener_connection_caps(sessions: usize) -> (usize, usize) {
    let max_connections_per_principal = (2 * sessions).max(64);
    let max_connections = (4 * sessions).max(512);
    (max_connections_per_principal, max_connections)
}

/// `handshake_rate_per_source`/`validated_rate_per_source`
/// (`crates/qsh-core/src/config.rs`'s `ServeConfig`) for an `N`-session
/// soak run dialed from a single source IP (127.0.0.1). The harness ramps
/// `N` connections and cycle-replaces them all from one address, so at the
/// product default (10/s, `burst_limit = rate × EPOCH.as_secs()` = 20 per
/// 2s epoch) the ramp burst — an exp3 loopback `tcpdump` measured ~25 new
/// dials inside one 2s window for N=100 — trips the per-source unvalidated
/// rate limiter, whose over-budget Initials are silently `Decision::Ignore`d
/// (no packet sent). The client then sees `ConnectionFailed` "no response
/// within 10s" and, after [`DIAL_RETRY_ATTEMPTS`] exhausted retries, the
/// scenario dies (the 2026-09-11 24h-abort triage). The product default is
/// deliberately NOT changed (`PLAN.md` Step 5 Q1 arbitration: a single
/// high-rate source is *meant* to be limited in production) — this raises
/// the cap only in the harness's own listener config, where the single
/// dialing source is a trusted test driver, not a flood. `(2*N).max(64)`
/// mirrors [`listener_connection_caps`] and clears the observed ramp burst
/// with headroom; both axes get the same value so the validated axis never
/// becomes the tighter gate.
fn listener_source_rates(sessions: usize) -> (u32, u32) {
    let rate = (2 * sessions).max(64) as u32;
    (rate, rate)
}

/// Render the `[serve]` section of the soak listener's `config.toml`
/// (pulled out of [`boot`] so [`soak_listener_config_raises_caps_and_
/// rates_for_100_sessions`] can assert its content without booting a real
/// listener).
fn render_serve_config_toml(params: &Params) -> String {
    let (max_connections_per_principal, max_connections) =
        listener_connection_caps(params.sessions);
    let (handshake_rate_per_source, validated_rate_per_source) =
        listener_source_rates(params.sessions);
    format!(
        "[serve]\nmax_sessions_per_principal = 128\nresume_ttl_secs = {}\n\
         max_connections_per_principal = {max_connections_per_principal}\n\
         max_connections = {max_connections}\n\
         handshake_rate_per_source = {handshake_rate_per_source}\n\
         validated_rate_per_source = {validated_rate_per_source}\n",
        params.resume_ttl_secs
    )
}

#[test]
fn soak_listener_config_raises_caps_and_rates_for_100_sessions() {
    let params = Params {
        duration: Duration::from_secs(120),
        sessions: 100,
        sample: Duration::from_secs(2),
        cycle: Duration::from_secs(20),
        cycle_fraction: 0.125,
        abandon: 1,
        resume_ttl_secs: 30,
        csv_path: None,
    };
    let config = render_serve_config_toml(&params);
    assert!(
        config.contains("max_connections_per_principal = 200"),
        "config must raise max_connections_per_principal to 2*N (200) for N=100: {config}"
    );
    assert!(
        config.contains("max_connections = 512"),
        "config must keep max_connections at the product default 512 (4*N=400 < 512) for N=100: \
         {config}"
    );
    assert!(
        config.contains("handshake_rate_per_source = 200"),
        "config must raise handshake_rate_per_source to (2*N).max(64) (200) for N=100 so the \
         single-source ramp burst does not trip the product per-source rate limiter: {config}"
    );
    assert!(
        config.contains("validated_rate_per_source = 200"),
        "config must raise validated_rate_per_source to (2*N).max(64) (200) for N=100: {config}"
    );
}

fn boot(params: &Params) -> SoakFleet {
    ensure_nofile_limit();
    let bin = load_bin();
    let host = Sandbox::new();
    let client = Sandbox::new();
    let host_fingerprint = host.fingerprint();
    let client_fingerprint = client.fingerprint();
    host.trust_add(CLIENT_ALIAS, None, &client_fingerprint);
    let config_toml = render_serve_config_toml(params);
    std::fs::write(host.config_dir().join("config.toml"), config_toml).expect("write config.toml");
    let serve = ServeGuard::start_with_bin(&host, &bin, &[]);
    client.trust_add(HOST_ALIAS, Some(serve.addr()), &host_fingerprint);
    SoakFleet {
        host,
        client,
        serve,
    }
}

/// Block on a fresh, single-use tokio runtime — `poll_stable` is `async`
/// (`qsh_testkit::procstat`), but every `Ops` call in this file is
/// deliberately synchronous ("call from a plain thread, never from inside
/// an async runtime", `SessionAttachStream::next_event`'s own doc), so
/// this scenario's main body is a plain `#[test]`, not a `#[tokio::test]`.
/// A short-lived runtime built and dropped around one `poll_stable` call
/// is not itself an async context this test's own thread is "inside", so
/// it does not trip that rule.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build ephemeral tokio runtime for poll_stable")
        .block_on(fut)
}

/// One `t_secs` sample row (`BRIEF-5.md` §4.3's CSV schema).
struct Sample {
    t_secs: u64,
    phase: &'static str,
    listener_rss_kib: Option<u64>,
    listener_fds: Option<usize>,
    self_rss_kib: Option<u64>,
    self_fds: Option<usize>,
    live_sessions: usize,
    cycles: u64,
    echo_p95_ms: Option<f64>,
    abandoned_live: usize,
}

impl Sample {
    fn to_csv_row(&self) -> String {
        fn opt(v: Option<impl std::fmt::Display>) -> String {
            v.map(|v| v.to_string()).unwrap_or_default()
        }
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            self.t_secs,
            self.phase,
            opt(self.listener_rss_kib),
            opt(self.listener_fds),
            opt(self.self_rss_kib),
            opt(self.self_fds),
            self.live_sessions,
            self.cycles,
            opt(self.echo_p95_ms.map(|v| format!("{v:.3}"))),
            self.abandoned_live,
        )
    }
}

/// Nearest-rank p95 over `samples` (copied from `adversarial_load.rs`'s
/// `percentile` — J9's accepted small-duplication precedent, one 6-line
/// helper is not worth a shared crate for).
fn p95(mut samples: Vec<f64>) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let idx = ((samples.len() as f64) * 0.95).ceil() as usize;
    Some(samples[idx.saturating_sub(1).min(samples.len() - 1)])
}

/// First-quarter and last-quarter slices of a time-ordered series
/// (`BRIEF-5.md` §4.4's fd-growth-during-cycling axes compare these).
/// Mirrors `scripts/soak/summarize.py`'s `quarter_split` exactly so the
/// test binary's own verdict and the offline judge agree bit-for-bit. A
/// series of 1-3 samples puts everything in both quarters rather than
/// being empty, since that only makes *this function's* comparison
/// stricter (comparing a value against itself), never a silent skip —
/// this function itself never downgrades or refuses to split. Whether the
/// result is trusted as a hard assert or only recorded as an informational
/// note when the series is short is entirely the caller's call (see
/// [`judge_fd_quarters`]'s [`MIN_QUARTER_SAMPLES`] gate, mirrored in
/// `summarize.py`'s `evaluate` — REVIEW-5-B/C B8 / ARBITRATION-5 F2).
fn quarter_split<T: Copy>(values: &[T]) -> (&[T], &[T]) {
    if values.is_empty() {
        return (&[], &[]);
    }
    let q = (values.len() / 4).max(1);
    (&values[..q], &values[values.len() - q..])
}

/// Apply the steady-phase quarters fd-growth rule to `samples`: with fewer
/// than [`MIN_QUARTER_SAMPLES`] samples, the split is too coarse to trust
/// (one or two points per quarter), so this only prints an informational
/// note instead of asserting (`summarize.py`'s `evaluate` applies the same
/// downgrade — REVIEW-5-B/C B8 / ARBITRATION-5 F2). Otherwise, a last-
/// quarter max more than [`FD_GROWTH_ALLOWANCE`] above the first-quarter
/// max is pushed onto `violations`, tagged `tag`.
fn judge_fd_quarters(label: &str, tag: &str, samples: &[usize], violations: &mut Vec<String>) {
    if samples.len() < MIN_QUARTER_SAMPLES {
        eprintln!(
            "soak informational: {label} fd steady-phase quarters check skipped — only {} \
             sample(s), fewer than the {MIN_QUARTER_SAMPLES} needed for the first/last-quarter \
             split to mean anything",
            samples.len()
        );
        return;
    }
    let (first_q, last_q) = quarter_split(samples);
    if let (Some(&first_max), Some(&last_max)) = (first_q.iter().max(), last_q.iter().max()) {
        let delta_q = last_max as i64 - first_max as i64;
        if delta_q > FD_GROWTH_ALLOWANCE {
            violations.push(format!(
                "{tag}: {label} fd steady-state quarter max grew by {delta_q} (first-quarter max \
                 {first_max}, last-quarter max {last_max}), exceeds the {FD_GROWTH_ALLOWANCE} \
                 allowance"
            ));
        }
    }
}

/// Median of `values` (sorts a copy — nearest-rank on odd length, average of
/// the two middle elements on even length). Only ever called on a
/// [`quarter_split`] half that is already known non-empty.
fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = v.len();
    if n.is_multiple_of(2) {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

/// [`judge_echo_windows`]'s result for one steady-phase echo p95 series.
/// `spikes`/`windows`/`fraction`/`max_p95_ms` are recorded as informational
/// items regardless of `violation` (`ECHO_SPIKE_FRACTION_MAX`'s doc comment
/// — inputs for a future 24h degradation rule).
struct EchoVerdict {
    windows: usize,
    spikes: usize,
    fraction: f64,
    max_p95_ms: f64,
    violation: bool,
}

/// Pure judge for the echo axis (`ARBITRATION-5` "load.yml 첫 GHA soak 실행
/// 판정"): `windows` is one p95 per steady-phase sample window, `bound` is
/// the same-run adaptive bound (`max(3 * ramp baseline, ECHO_P95_FLOOR_MS)`,
/// computed by the caller). Returns `None` when `windows` is empty — nothing
/// to judge, never a violation by omission. Otherwise, [`EchoVerdict::
/// violation`] is true iff the fraction of windows whose own p95 exceeds
/// `bound` is itself greater than [`ECHO_SPIKE_FRACTION_MAX`].
fn judge_echo_windows(windows: &[f64], bound: f64) -> Option<EchoVerdict> {
    if windows.is_empty() {
        return None;
    }
    let spikes = windows.iter().filter(|&&p95| p95 > bound).count();
    let fraction = spikes as f64 / windows.len() as f64;
    let max_p95_ms = windows.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    Some(EchoVerdict {
        windows: windows.len(),
        spikes,
        fraction,
        max_p95_ms,
        violation: fraction > ECHO_SPIKE_FRACTION_MAX,
    })
}

/// GHA run 34203445617's actual shape (`ARBITRATION-5`): 59 steady windows,
/// 2 spikes (129.5ms, 114.6ms) against everything else near 1-2ms — 2/59 =
/// 3.4%, under the 10% fraction, so the run passes.
#[test]
fn judge_echo_windows_passes_under_the_ten_percent_fraction() {
    let mut windows = vec![1.2; 57];
    windows.push(129.495);
    windows.push(114.632);
    let verdict = judge_echo_windows(&windows, ECHO_P95_FLOOR_MS).expect("non-empty windows");
    assert_eq!(verdict.windows, 59);
    assert_eq!(verdict.spikes, 2);
    assert!(
        !verdict.violation,
        "2/59 = 3.4% must stay under the 10% ECHO_SPIKE_FRACTION_MAX"
    );
}

/// Same 2 spikes as the run-shaped case above, but out of only 10 windows:
/// 2/10 = 20%, over the 10% fraction, so this run is `ECHO_DEGRADED`.
#[test]
fn judge_echo_windows_flags_a_higher_spike_fraction() {
    let mut windows = vec![1.2; 8];
    windows.push(129.495);
    windows.push(114.632);
    let verdict = judge_echo_windows(&windows, ECHO_P95_FLOOR_MS).expect("non-empty windows");
    assert_eq!(verdict.windows, 10);
    assert_eq!(verdict.spikes, 2);
    assert!(
        verdict.violation,
        "2/10 = 20% exceeds the 10% ECHO_SPIKE_FRACTION_MAX"
    );
}

/// An empty window series has nothing to judge — `None`, not a false pass
/// or a false violation.
#[test]
fn judge_echo_windows_empty_input_is_not_judged() {
    assert!(judge_echo_windows(&[], ECHO_P95_FLOOR_MS).is_none());
}

/// `session.open` against `HOST_ALIAS`, PTY-backed (`argv: ["cat"]` — a
/// plain PTY echo target, unlike `adversarial_load.rs`'s `sh`: a shell
/// would try to interpret a non-newline-terminated marker as a
/// still-being-typed command line, whereas `cat` only ever echoes bytes
/// back, so the tty's own canonical-mode character echo is the entire
/// round trip being timed here, same isolation T2's scenario 3 relies on).
fn open_session(ops: &Ops) -> Result<String, qsh_core::OpError> {
    Ok(ops
        .session_open(SessionOpenReq {
            host: HOST_ALIAS.to_string(),
            argv: vec!["cat".to_string()],
            env: vec![EnvVar {
                name: "LANG".into(),
                value: "C".into(),
            }],
            term: Some("xterm-256color".into()),
            cols: Some(80),
            rows: Some(24),
            user: None,
        })?
        .session_ref)
}

fn attach_session(ops: &Ops, session_ref: &str) -> Result<SessionAttachStream, qsh_core::OpError> {
    ops.session_attach(
        SessionAttachReq {
            session_ref: session_ref.to_string(),
            no_steal: false,
        },
        &[],
    )
}

/// One echo round's marker: `round` folded into a printable-ASCII-digit
/// filler up to `len` bytes, no `\n`/control bytes — same reasoning
/// `adversarial_load.rs`'s scenario 3 gives for why that dodges any line
/// discipline concern.
fn marker(round: u64, len: usize) -> Vec<u8> {
    let seed = format!("{round:08}");
    seed.as_bytes().iter().cycle().take(len).copied().collect()
}

fn decode(data_b64: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .expect("session output is Base64")
}

/// What a cycled session's worker does once its stop signal fires; an
/// abandoned session never gets [`StopMode::Cycle`] (`BRIEF-5.md` §4.3
/// step 3: "ABANDON 세션은 ramp 직후 detach하고 다시 붙지 않는다").
///
/// `Copy` so [`spawn_session_retrying`] can reuse the same mode across
/// retry attempts without the caller needing to clone it at each call site.
#[derive(Clone, Copy)]
enum StopMode {
    /// Close the attach, then send `session.close` — this is the "닫고
    ///새로 열기" half of a cycle.
    Cycle,
    /// Drop the attach without closing the session — the orphaned session
    /// lingers server-side until `resume_ttl` reaps it.
    Abandon,
}

/// One live session's write/echo worker, running on its own OS thread —
/// `Ops`'s blocking API is meant to be driven from a plain thread
/// (`SessionAttachStream::next_event`'s doc), and each session needs its
/// own independent read/write loop so N of them can be chatty
/// concurrently.
struct SessionWorker {
    session_ref: String,
    stop: Arc<AtomicBool>,
    echo_samples_ms: Arc<Mutex<Vec<f64>>>,
    handle: std::thread::JoinHandle<()>,
}

/// 500ms write cadence, 1 KiB marker (`BRIEF-5.md` §4.3 step 2: "500 ms마다
/// 1 KiB 줄을 쓰고 echo를 기다린다").
const WRITE_INTERVAL: Duration = Duration::from_millis(500);
const MARKER_LEN: usize = 1024;

/// Per-round echo deadline (REVIEW-5-B B12 / ARBITRATION-5 F2): a session
/// that goes this long without completing one write/echo round is dropped
/// and every dropped session is a `SESSION_STALLED` violation in the
/// verdict — a real product-level stall, distinct from
/// [`spawn_session_retrying`]'s dial-retry budget, which only covers the
/// *opening* dial, never a round already in flight on an established
/// session.
///
/// This is only checked *between* [`SessionAttachStream::next_event`]
/// calls, not as a preemptive interrupt of one in-flight call: that method
/// has no timeout parameter or cancellation hook on its public surface (it
/// blocks until an event or its own internal credential-renewal wait, an
/// independent, normally much longer bound), and a plain OS thread cannot
/// be preempted from outside without one. In practice a stalled echo path
/// shows up as a gap *between* distinct received events (a partial echo,
/// then nothing), which this does catch; a single call that blocks past
/// this deadline while producing zero events at all would only be caught
/// by the scenario's own overall timeout (nextest's slow-timeout/
/// terminate-after) instead.
const SESSION_ROUND_DEADLINE: Duration = Duration::from_secs(5);

fn spawn_session(
    ops: Arc<Ops>,
    mode: StopMode,
    dead_sessions: Arc<AtomicU64>,
) -> Result<SessionWorker, qsh_core::OpError> {
    let session_ref = open_session(&ops)?;
    let stream = attach_session(&ops, &session_ref)?;
    let stop = Arc::new(AtomicBool::new(false));
    let echo_samples_ms = Arc::new(Mutex::new(Vec::new()));
    let stop_t = Arc::clone(&stop);
    let echo_t = Arc::clone(&echo_samples_ms);
    let session_ref_t = session_ref.clone();
    let handle = std::thread::spawn(move || {
        let mut stream = stream;
        let mut round: u64 = 0;
        loop {
            if stop_t.load(Ordering::Relaxed) {
                break;
            }
            let m = marker(round, MARKER_LEN);
            let send_at = Instant::now();
            let round_deadline = send_at + SESSION_ROUND_DEADLINE;
            if stream.write(m.clone()).is_err() {
                break;
            }
            let mut echoed: Vec<u8> = Vec::new();
            let mut alive = true;
            let mut stalled = false;
            loop {
                if Instant::now() >= round_deadline {
                    stalled = true;
                    alive = false;
                    break;
                }
                match stream.next_event() {
                    Some(Ok(SessionEvent::Output { data_b64, .. })) => {
                        echoed.extend(decode(&data_b64));
                        if echoed.ends_with(m.as_slice()) {
                            break;
                        }
                        if echoed.len() > m.len() * 4 {
                            let cut = echoed.len() - m.len();
                            echoed.drain(0..cut);
                        }
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => {
                        alive = false;
                        break;
                    }
                }
            }
            if stalled {
                dead_sessions.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "soak: SESSION_STALLED — session {session_ref_t} exceeded the \
                     {SESSION_ROUND_DEADLINE:?} per-round echo deadline on round {round}"
                );
            }
            if !alive {
                break;
            }
            let elapsed_ms = send_at.elapsed().as_secs_f64() * 1000.0;
            echo_t
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(elapsed_ms);
            round += 1;
            std::thread::sleep(WRITE_INTERVAL);
        }
        match mode {
            StopMode::Cycle => {
                stream.close();
                let _ = ops.session_close(SessionCloseReq {
                    session_ref: session_ref_t,
                    signal: None,
                });
            }
            StopMode::Abandon => drop(stream),
        }
    });
    Ok(SessionWorker {
        session_ref,
        stop,
        echo_samples_ms,
        handle,
    })
}

/// Dial-retry budget for ramp opens and cycle replacement opens (main's F1
/// call): a retryable `OpError` (`ConnectionFailed`/`Timeout`) gets this
/// many total attempts before [`spawn_session_retrying`] gives up. The 10s
/// dial timeout itself lives in `qsh-core` product code and is never
/// touched here — this only re-attempts the same call after that timeout
/// fires.
const DIAL_RETRY_ATTEMPTS: u32 = 3;
/// Backoff between dial retry attempts.
const DIAL_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Whether an [`qsh_core::OpError`] is the kind of transient dial failure
/// worth retrying — a connection attempt that failed or timed out, and
/// which the op itself already marked retryable. Anything else (auth
/// failure, permission denied, ...) fails immediately, unretried.
fn is_retryable_dial_error(err: &qsh_core::OpError) -> bool {
    err.retryable && matches!(err.code, ErrorCode::ConnectionFailed | ErrorCode::Timeout)
}

/// [`spawn_session`], but ramp opens and cycle replacement opens retry a
/// retryable dial failure up to [`DIAL_RETRY_ATTEMPTS`] times,
/// [`DIAL_RETRY_BACKOFF`] apart, instead of failing the whole scenario on
/// the first miss (`PROGRESS-5.md` S5 saw exactly this failure mode on a
/// fuzz-saturated WSL host, load 9.x/8 vCPU, otherwise well within qsh's
/// own 10s dial budget). Every retry increments `dial_retries` so the
/// caller can report the total as an informational verdict line — a retry
/// is never a violation by itself, only exhausting every attempt is.
fn spawn_session_retrying(
    ops: &Arc<Ops>,
    mode: StopMode,
    dial_retries: &AtomicU64,
    dead_sessions: &Arc<AtomicU64>,
) -> Result<SessionWorker, qsh_core::OpError> {
    let mut attempt = 1;
    loop {
        match spawn_session(Arc::clone(ops), mode, Arc::clone(dead_sessions)) {
            Ok(worker) => return Ok(worker),
            Err(err) if attempt < DIAL_RETRY_ATTEMPTS && is_retryable_dial_error(&err) => {
                dial_retries.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "soak: dial attempt {attempt}/{DIAL_RETRY_ATTEMPTS} failed with a retryable \
                     error, retrying in {:?}: {err:?}",
                    DIAL_RETRY_BACKOFF
                );
                std::thread::sleep(DIAL_RETRY_BACKOFF);
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

impl SessionWorker {
    /// Take (and clear) this window's echo samples for the caller's p95
    /// computation.
    fn drain_echo_samples(&self) -> Vec<f64> {
        std::mem::take(
            &mut *self
                .echo_samples_ms
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn signal_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn join(self) {
        let _ = self.handle.join();
    }
}

/// The 24h/100-session soak scenario (`BRIEF-5.md` §4). Short mode
/// (defaults) is what `[profile.load]` runs in CI; 24h/100-session mode is
/// the same test under `[profile.soak]`, driven by `scripts/soak/run.sh`.
#[test]
fn soak_session_load() {
    if !gate_requested() {
        skip();
        return;
    }
    if !cfg!(target_os = "linux") {
        panic!(
            "QSH_LOAD_STRICT=1 but this host is not Linux — the soak scenario's rss_kib/\
             open_fd_count measurement is Linux-only (BRIEF-5.md §2); rerun on a Linux host \
             (this repo's soak campaign runs on Dave-Windows-WSL) or unset QSH_LOAD_STRICT to \
             skip here instead of measuring nothing."
        );
    }

    let params = Params::from_env();
    let fleet = boot(&params);
    let listener_pid = fleet.serve.pid();
    let self_pid = std::process::id();
    let ops = Arc::new(Ops::new(Paths::new(
        fleet.client.config_dir(),
        fleet.client.state_dir(),
    )));

    let mut csv: Option<std::fs::File> = params.csv_path.as_ref().map(|p| {
        let mut f = std::fs::File::create(p).expect("create soak CSV");
        writeln!(f, "{SOAK_CSV_HEADER}").expect("write CSV header");
        f
    });
    let mut write_row = |sample: &Sample| {
        eprintln!(
            "soak t={}s phase={} listener_rss={:?}KiB listener_fds={:?} self_rss={:?}KiB \
             self_fds={:?} live={} cycles={} echo_p95={:?}ms abandoned_live={}",
            sample.t_secs,
            sample.phase,
            sample.listener_rss_kib,
            sample.listener_fds,
            sample.self_rss_kib,
            sample.self_fds,
            sample.live_sessions,
            sample.cycles,
            sample.echo_p95_ms,
            sample.abandoned_live
        );
        if let Some(f) = csv.as_mut() {
            writeln!(f, "{}", sample.to_csv_row()).expect("append CSV row");
        }
    };

    let start = Instant::now();
    let t = |start: Instant| start.elapsed().as_secs();
    // Total dial retries across ramp opens and cycle replacement opens
    // (main's F1 call) — informational in the verdict, never a violation
    // by itself.
    let dial_retries = AtomicU64::new(0);
    // Cycle-replacement dials that exhausted all DIAL_RETRY_ATTEMPTS
    // attempts — recorded as a DIAL_EXHAUSTED violation (verdict FAIL)
    // rather than panicking, so one exhausted replacement does not unwind
    // the scenario before drain and leave the CSV with no judgeable
    // verdict (the 2026-09-11 24h abort).
    let dial_exhausted = AtomicU64::new(0);
    // Sessions that hit SESSION_ROUND_DEADLINE mid-round (B12) — every one
    // is a SESSION_STALLED violation, tallied across every worker's
    // lifetime (ramp opens and cycle replacements alike).
    let dead_sessions = Arc::new(AtomicU64::new(0));

    // --- boot: baseline idle RSS/fd (BRIEF-5.md §4.3 step 1) ---
    let (baseline_listener_rss, _) = block_on(poll_stable(|| rss_kib(listener_pid)));
    let (baseline_listener_fds, _) = block_on(poll_stable(|| {
        open_fd_count(listener_pid).map(|n| n as u64)
    }));
    let (baseline_self_fds, _) =
        block_on(poll_stable(|| open_fd_count(self_pid).map(|n| n as u64)));
    write_row(&Sample {
        t_secs: t(start),
        phase: "boot",
        listener_rss_kib: baseline_listener_rss,
        listener_fds: baseline_listener_fds.map(|n| n as usize),
        self_rss_kib: rss_kib(self_pid),
        self_fds: baseline_self_fds.map(|n| n as usize),
        live_sessions: 0,
        cycles: 0,
        echo_p95_ms: None,
        abandoned_live: 0,
    });

    // --- ramp: open N sessions, `abandon` of which are never cycled ---
    let mut workers: Vec<SessionWorker> = Vec::with_capacity(params.sessions);
    for i in 0..params.sessions {
        let mode = if i < params.abandon {
            StopMode::Abandon
        } else {
            StopMode::Cycle
        };
        let worker = spawn_session_retrying(&ops, mode, &dial_retries, &dead_sessions)
            .unwrap_or_else(|e| panic!("ramp: session {i} of {}: {e:?}", params.sessions));
        workers.push(worker);
    }
    let abandoned_refs: Vec<String> = workers[..params.abandon]
        .iter()
        .map(|w| w.session_ref.clone())
        .collect();
    // "ABANDON 세션은 ramp 직후 detach하고 다시 붙지 않는다": signal their
    // stop right away, before steady begins, so they never take part in
    // the chatty echo load or the cycle pool.
    for worker in &workers[..params.abandon] {
        worker.signal_stop();
    }
    let abandon_signaled_at = Instant::now();

    // --- baseline: let the cycle-pool sessions settle for one sample
    // window before steady begins, so the echo p95 bound (below) has a
    // same-run reference point instead of a fixed absolute number a shared
    // runner cannot promise — same reasoning as `adversarial_load.rs`'s T2
    // baseline (`docs/design/testing.md:126`, REVIEW-5-C C9 /
    // ARBITRATION-5 F2).
    let baseline_window = params.sample.max(Duration::from_secs(2));
    std::thread::sleep(baseline_window);
    let baseline_echo_p95_ms = p95(workers
        .iter()
        .skip(params.abandon)
        .flat_map(|w| w.drain_echo_samples())
        .collect());
    let echo_p95_bound_ms =
        baseline_echo_p95_ms.map_or(ECHO_P95_FLOOR_MS, |b| (3.0 * b).max(ECHO_P95_FLOOR_MS));
    // Record this same baseline in the CSV itself (PROGRESS-5.md §F2: the
    // verdict above judges steady echo p95 against a baseline this test
    // measured in-process, but that number never used to reach the CSV, so
    // `scripts/soak/summarize.py` judging the same run offline had no way
    // to derive the identical bound and fell back to the fixed
    // `ECHO_P95_FLOOR_MS` floor instead — two judges, two different bounds
    // for one run. This "ramp" row is neither "boot" nor "steady" nor
    // "drain", so it is invisible to every phase-filtered check on both
    // sides (steady quarters, steady RSS-trend regression, steady echo
    // max) and only ever read back as the echo baseline.
    write_row(&Sample {
        t_secs: t(start),
        phase: "ramp",
        listener_rss_kib: rss_kib(listener_pid),
        listener_fds: open_fd_count(listener_pid),
        self_rss_kib: rss_kib(self_pid),
        self_fds: open_fd_count(self_pid),
        live_sessions: workers.len() - params.abandon,
        cycles: 0,
        echo_p95_ms: baseline_echo_p95_ms,
        abandoned_live: params.abandon,
    });

    // --- steady: SAMPLE_SECS CSV rows, CYCLE_SECS session replacement ---
    let mut cycles: u64 = 0;
    let mut cycle_cursor: usize = 0;
    // One p95 per steady-phase sample window (`ECHO_SPIKE_FRACTION_MAX`'s
    // fraction-of-windows judge reads this below — replaces the old running
    // `max_echo_p95_ms`, which [`judge_echo_windows`]'s own `max_p95_ms`
    // now derives from the same series instead of a separately-maintained
    // variable).
    let mut steady_echo_windows: Vec<f64> = Vec::new();
    // Steady-phase self (test process) and listener fd samples, for the
    // quarters checks (BRIEF-5.md §4.4's (iii) axis and its listener
    // counterpart: growth *during* cycling, not the ramp's one-shot
    // session-open/attach fd cost).
    let mut steady_self_fds: Vec<usize> = Vec::new();
    let mut steady_listener_fds: Vec<usize> = Vec::new();
    let mut peak_listener_rss_kib: Option<u64> = None;
    let mut cycle_deadline_skips: u64 = 0;
    let mut sample_deadline_skips: u64 = 0;
    let mut abandoned_live_cached: usize = params.abandon;
    let mut last_abandoned_probe: Option<Instant> = None;
    // Probe cadence ceiling for the abandoned-session check (B5): the
    // probe is itself a fresh control round trip, so running it on every
    // sample tick would let the harness's own dial churn leak into the fd
    // measurements taken just above it.
    const ABANDONED_PROBE_INTERVAL: Duration = Duration::from_secs(10);
    // Anchored at the steady phase's own start (after ramp + the baseline
    // window above), not the scenario's t=0 (B4 / ARBITRATION-5 F2) —
    // otherwise ramp's own N-sequential-dial latency eats into the first
    // cycle/sample period before steady-state load has even begun.
    let steady_start = Instant::now();
    let mut next_sample = steady_start + params.sample;
    let mut next_cycle = steady_start + params.cycle;
    let steady_end = steady_start + params.duration;
    while Instant::now() < steady_end {
        let now = Instant::now();
        if now >= next_cycle {
            let pool_size = workers.len() - params.abandon;
            let batch = params.cycle_batch().min(pool_size);
            // Cycle pool excludes the always-abandoned prefix and rotates
            // through it (rather than always recycling the same slots) so
            // a long run's cycles spread across every live session, not
            // just the first `batch` of them.
            let victims: Vec<usize> = (0..batch)
                .map(|i| params.abandon + (cycle_cursor + i) % pool_size)
                .collect();
            cycle_cursor = (cycle_cursor + batch) % pool_size;
            for &idx in &victims {
                workers[idx].signal_stop();
            }
            let mut replaced = Vec::with_capacity(victims.len());
            for &idx in &victims {
                match spawn_session_retrying(&ops, StopMode::Cycle, &dial_retries, &dead_sessions) {
                    Ok(new_worker) => {
                        let old = std::mem::replace(&mut workers[idx], new_worker);
                        replaced.push(old);
                    }
                    Err(e) => {
                        // The victim at `idx` was already `signal_stop`'d
                        // above; on an exhausted replacement dial we leave
                        // that stopped worker in place (it winds down and is
                        // joined at drain like any other) rather than
                        // panicking — a single exhausted replacement must not
                        // unwind the whole scenario before the drain phase,
                        // or the CSV loses its drain rows and the run yields
                        // no judgeable verdict at all (the 2026-09-11 24h
                        // abort). It is still a verdict FAIL via
                        // DIAL_EXHAUSTED below, just a survivable one.
                        dial_exhausted.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "soak: cycle replacement for slot {idx} exhausted all \
                             {DIAL_RETRY_ATTEMPTS} attempts; leaving the slot's stopped session \
                             in place and continuing to drain (DIAL_EXHAUSTED, a verdict FAIL): \
                             {e:?}"
                        );
                    }
                }
            }
            for old in replaced {
                old.join();
            }
            cycles += 1;
            // Clamp on overrun (B4): a slow tick (e.g. a batch of joins
            // that itself outran one cycle period) must not compound into
            // an ever-growing backlog of instantly-firing cycles. Counted,
            // never a violation by itself.
            let naive_next_cycle = next_cycle + params.cycle;
            let after_cycle = Instant::now();
            if naive_next_cycle <= after_cycle {
                cycle_deadline_skips += 1;
            }
            next_cycle = naive_next_cycle.max(after_cycle);
        }
        if Instant::now() >= next_sample {
            let echo_p95 = p95(workers
                .iter()
                .skip(params.abandon)
                .flat_map(|w| w.drain_echo_samples())
                .collect());
            if let Some(p95) = echo_p95 {
                steady_echo_windows.push(p95);
            }
            // Self fd sample BEFORE the abandoned-session probe below (B5)
            // — the probe's own `session.get` round trips must not
            // contaminate the (iii)-axis measurement.
            let self_fds_sample = open_fd_count(self_pid);
            if let Some(fds) = self_fds_sample {
                steady_self_fds.push(fds);
            }
            let listener_rss_sample = rss_kib(listener_pid);
            if let Some(rss) = listener_rss_sample {
                peak_listener_rss_kib =
                    Some(peak_listener_rss_kib.map_or(rss, |p: u64| p.max(rss)));
            }
            let listener_fds_sample = open_fd_count(listener_pid);
            if let Some(fds) = listener_fds_sample {
                steady_listener_fds.push(fds);
            }
            let probe_now = Instant::now();
            let should_probe = last_abandoned_probe
                .is_none_or(|t| probe_now.duration_since(t) >= ABANDONED_PROBE_INTERVAL);
            if should_probe {
                abandoned_live_cached = abandoned_refs
                    .iter()
                    .filter(|r| {
                        ops.session_get(SessionGetReq {
                            session_ref: (*r).clone(),
                        })
                        .is_ok()
                    })
                    .count();
                last_abandoned_probe = Some(probe_now);
            }
            write_row(&Sample {
                t_secs: t(start),
                phase: "steady",
                listener_rss_kib: listener_rss_sample,
                listener_fds: listener_fds_sample,
                self_rss_kib: rss_kib(self_pid),
                self_fds: self_fds_sample,
                live_sessions: workers.len() - params.abandon,
                cycles,
                echo_p95_ms: echo_p95,
                abandoned_live: abandoned_live_cached,
            });
            let naive_next_sample = next_sample + params.sample;
            let after_sample = Instant::now();
            if naive_next_sample <= after_sample {
                sample_deadline_skips += 1;
            }
            next_sample = naive_next_sample.max(after_sample);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // --- drain: close every remaining cycle-pool session, wait for reap ---
    for worker in workers.drain(params.abandon..) {
        worker.signal_stop();
        worker.join();
    }
    std::thread::sleep(DRAIN_WAIT);
    let (idle_end_listener_rss, _) = block_on(poll_stable(|| rss_kib(listener_pid)));
    let (idle_end_listener_fds, _) = block_on(poll_stable(|| {
        open_fd_count(listener_pid).map(|n| n as u64)
    }));
    let (idle_end_self_fds, _) =
        block_on(poll_stable(|| open_fd_count(self_pid).map(|n| n as u64)));
    let abandoned_live = abandoned_refs
        .iter()
        .filter(|r| {
            ops.session_get(SessionGetReq {
                session_ref: (*r).clone(),
            })
            .is_ok()
        })
        .count();
    write_row(&Sample {
        t_secs: t(start),
        phase: "drain",
        listener_rss_kib: idle_end_listener_rss,
        listener_fds: idle_end_listener_fds.map(|n| n as usize),
        self_rss_kib: rss_kib(self_pid),
        self_fds: idle_end_self_fds.map(|n| n as usize),
        live_sessions: 0,
        cycles,
        echo_p95_ms: None,
        abandoned_live,
    });

    // --- verdict (BRIEF-5.md §4.4) ---
    let mut violations: Vec<String> = Vec::new();
    if let (Some(baseline), Some(idle_end)) = (baseline_listener_rss, idle_end_listener_rss) {
        if baseline > IDLE_RSS_BOUND_KIB {
            violations.push(format!(
                "baseline listener RSS {baseline} KiB exceeds {IDLE_RSS_BOUND_KIB} KiB idle bound"
            ));
        }
        if idle_end > IDLE_RSS_BOUND_KIB {
            violations.push(format!(
                "idle-end listener RSS {idle_end} KiB exceeds {IDLE_RSS_BOUND_KIB} KiB idle bound"
            ));
        }
    }
    if let (Some(baseline_fds), Some(idle_end_fds)) = (baseline_listener_fds, idle_end_listener_fds)
    {
        let delta = idle_end_fds as i64 - baseline_fds as i64;
        if delta > FD_GROWTH_ALLOWANCE {
            violations.push(format!(
                "listener fd grew by {delta} (baseline {baseline_fds}, idle-end {idle_end_fds}), \
                 exceeds the {FD_GROWTH_ALLOWANCE} allowance"
            ));
        }
    }
    // Self (test process) fd growth is judged on the steady-phase quarters,
    // not the boot-baseline-vs-drain-idle_end span: the (iii) axis BRIEF-5.md
    // §4.4 names is growth *during* cycling, and the full-lifecycle
    // comparison also bundles in ramp's one-shot session-open/attach fd cost
    // (runtime warm-up), which is not what (iii) is about (main's F1 call,
    // PROGRESS-5.md S5 "self fd 판정식 불일치"). The boot->idle_end delta is
    // still worth recording, just never as a violation.
    if let (Some(baseline_fds), Some(idle_end_fds)) = (baseline_self_fds, idle_end_self_fds) {
        let delta = idle_end_fds as i64 - baseline_fds as i64;
        eprintln!(
            "soak informational: self fd boot-baseline->drain-idle_end delta={delta} (baseline \
             {baseline_fds}, idle-end {idle_end_fds}) — runtime warm-up, not a violation; the \
             (iii) axis is judged on the steady-phase quarters check below"
        );
    }
    judge_fd_quarters(
        "self",
        "FD_GROWTH_CLIENT",
        &steady_self_fds,
        &mut violations,
    );
    judge_fd_quarters(
        "listener",
        "FD_GROWTH_LISTENER",
        &steady_listener_fds,
        &mut violations,
    );
    if abandoned_live > 0
        && Instant::now().duration_since(abandon_signaled_at) >= ttl_reap_deadline(&params)
    {
        violations.push(format!(
            "{abandoned_live} abandoned session(s) still answer session.get after the \
             resume_ttl ({} s) + REAPER_TICK ({} s) deadline — TTL reap did not run",
            params.resume_ttl_secs,
            qsh_core::broker::REAPER_TICK.as_secs()
        ));
    }
    // ECHO_SPIKE_FRACTION_MAX's fraction-of-windows rule (ARBITRATION-5),
    // not "no window may ever exceed the bound" — see that constant's doc
    // comment. max/spikes/windows and the first/last-quarter median are
    // informational (inputs for a future 24h degradation rule); only the
    // fraction itself is asserted.
    match judge_echo_windows(&steady_echo_windows, echo_p95_bound_ms) {
        Some(echo_verdict) => {
            let quarter_note = if steady_echo_windows.len() >= MIN_QUARTER_SAMPLES {
                let (first_q, last_q) = quarter_split(&steady_echo_windows);
                format!(
                    "first-quarter median {:.3}ms, last-quarter median {:.3}ms",
                    median(first_q),
                    median(last_q)
                )
            } else {
                format!(
                    "first/last-quarter median n/a — only {} window(s), fewer than the \
                     {MIN_QUARTER_SAMPLES} needed",
                    steady_echo_windows.len()
                )
            };
            eprintln!(
                "soak informational: echo p95 steady windows={} spikes={} ({:.1}% of windows > \
                 {echo_p95_bound_ms:.3}ms bound) max={:.3}ms {quarter_note}",
                echo_verdict.windows,
                echo_verdict.spikes,
                echo_verdict.fraction * 100.0,
                echo_verdict.max_p95_ms
            );
            if echo_verdict.violation {
                violations.push(format!(
                    "ECHO_DEGRADED: {}/{} steady window(s) ({:.1}%) exceed the \
                     {echo_p95_bound_ms:.3}ms bound (max(3 x ramp-baseline \
                     {baseline_echo_p95_ms:?}ms, {ECHO_P95_FLOOR_MS}ms floor)), over the \
                     {:.0}% ECHO_SPIKE_FRACTION_MAX allowance (max observed {:.3}ms)",
                    echo_verdict.spikes,
                    echo_verdict.windows,
                    echo_verdict.fraction * 100.0,
                    ECHO_SPIKE_FRACTION_MAX * 100.0,
                    echo_verdict.max_p95_ms
                ));
            }
        }
        None => {
            eprintln!("soak informational: echo p95 steady windows=0 — nothing to judge");
        }
    }
    let dead_sessions_total = dead_sessions.load(Ordering::Relaxed);
    if dead_sessions_total > 0 {
        violations.push(format!(
            "SESSION_STALLED: {dead_sessions_total} session(s) exceeded the \
             {SESSION_ROUND_DEADLINE:?} per-round echo deadline"
        ));
    }
    let dial_exhausted_total = dial_exhausted.load(Ordering::Relaxed);
    if dial_exhausted_total > 0 {
        violations.push(format!(
            "DIAL_EXHAUSTED: {dial_exhausted_total} cycle replacement dial(s) exhausted all \
             {DIAL_RETRY_ATTEMPTS} attempts and were skipped (the run continued to drain so this \
             CSV still closes — a survivable FAIL, not a scenario-ending panic)"
        ));
    }
    // §4.4's per-session-buffer and RSS-trend axes are record-only in short
    // mode (too few samples for a regression line) — `scripts/soak/
    // summarize.py` (Step 5c) is what asserts them from the CSV in 24h
    // mode; this test only asserts the axes §4.4 marks as always-asserted
    // (idle bounds, fd growth, echo, TTL reap, SESSION_STALLED).
    let verdict = if violations.is_empty() {
        "pass"
    } else {
        "FAIL"
    };
    let dial_retries_total = dial_retries.load(Ordering::Relaxed);
    let sessions = params.sessions;
    // Record-only (never a violation): peak listener RSS reached during
    // steady state and its per-session delta over baseline, same
    // per-session-buffer shape `summarize.py`'s 24h-mode assert uses, just
    // not asserted here (too few samples in short mode) — REVIEW-5-B/C
    // C7/B9 / ARBITRATION-5 F2.
    let per_session_rss_delta_kib = match (peak_listener_rss_kib, baseline_listener_rss) {
        (Some(peak), Some(baseline)) if sessions > 0 => {
            Some((peak as i64 - baseline as i64) as f64 / sessions as f64)
        }
        _ => None,
    };
    eprintln!(
        "soak {verdict}: baseline_rss={baseline_listener_rss:?}KiB \
         idle_end_rss={idle_end_listener_rss:?}KiB peak_rss={peak_listener_rss_kib:?}KiB \
         per_session_rss_delta={per_session_rss_delta_kib:?}KiB \
         baseline_fds={baseline_listener_fds:?} idle_end_fds={idle_end_listener_fds:?} \
         self_baseline_fds={baseline_self_fds:?} self_idle_end_fds={idle_end_self_fds:?} \
         cycles={cycles} sessions={sessions} per_session_bound={PER_SESSION_BUFFER_KIB}KiB \
         echo_baseline_p95={baseline_echo_p95_ms:?}ms echo_p95_bound={echo_p95_bound_ms:.3}ms \
         dial_retries={dial_retries_total} (informational — a dial retry is never a violation by \
         itself, only exhausting all {DIAL_RETRY_ATTEMPTS} attempts is) \
         dead_sessions={dead_sessions_total} dial_exhausted={dial_exhausted_total} \
         cycle_deadline_skips={cycle_deadline_skips} \
         sample_deadline_skips={sample_deadline_skips} (informational — an overrun clamp, not a \
         violation)"
    );
    if !violations.is_empty() {
        panic!(
            "soak scenario FAIL ({} violation(s)):\n  - {}",
            violations.len(),
            violations.join("\n  - ")
        );
    }
}
