//! L4 acceptance: the literal 60-second blackout `docs/ROADMAP.md` M3 DoD 2
//! and `PLAN.md` Step 8 (a) promise — "60초 차단"/"60 s > 45 s idle
//! timeout... target의 backoff 루프가 복구를 담당하며... `resume_ttl`(기본
//! 24 h)에는 한참 못 미치므로 세션·credential 모두 살아 있어야 한다".
//!
//! `crates/qsh-testkit/tests/reverse_resume_chaos.rs` (`PLAN.md` Step 8
//! (b)/(c)/(d)) is the PR-always-on half of this DoD, proving the same
//! product path with an instantaneous `ChaosProxy::sever()` — a fresh
//! redial after a plain sever succeeds first try, so that file never
//! actually burns the target's own backoff loop or lets QUIC's own 45 s
//! idle timeout fire; its own module docs explain at length why forcing
//! that deterministically is not a PR-gate-shaped problem. This file is
//! the other half: a *real* [`qsh_testkit::chaos::ChaosProxy::blackhole`]
//! for a real 60 wall-clock seconds — no fault injection trick, no seeded
//! packet drop, just total silence on the wire for longer than the
//! connection can survive on its own. `docs/design/testing.md`'s "no
//! `sleep()`" CI discipline is exactly what Step 8 (a) names as the one
//! exception: "Step 8의 60초 수용 게이트만 벽시계를 쓰며 그 격리 방법을 그
//! step이 명시한다" — the isolation is [`QSH_ACCEPTANCE_SLOW`] (below),
//! which keeps this test out of the PR-gated unit suite entirely and into
//! the standing `acceptance` CI job instead, the same way M2's
//! `QSH_ACCEPTANCE_STRICT` did for the interactive shell set
//! (`crates/qsh-cli/tests/tui_expect.rs`).
//!
//! No `std::thread::sleep`/`tokio::time::sleep` anywhere below, even so —
//! the 60 real seconds this test spends are spent entirely inside
//! [`read_until`]'s blocking read of the attach stream, which only
//! returns once the target has actually redialed, re-registered, and
//! resumed the session on the far side of the blackout. That is the
//! thing under test, not a stand-in for it.
//!
//! Asserts the same five pass/fail criteria `reverse_resume_chaos.rs` does
//! (`PLAN.md` Step 8 (i)/(ii) both cite the identical five) — criterion ⑤
//! ("not a late idle-timeout fluke") is restated in the shape a real,
//! multi-attempt recovery actually produces rather than copied verbatim;
//! see the doc comment on the test function itself for why.
//!
//! **A second, longer round lives in this same file.**
//! [`a_real_30_minute_blackout_is_resumed_within_the_ttl`] is the
//! release-gate evidence for `docs/PRD.md` §13's "30분 단절 후에도 TTL 내
//! 세션 복구" row, gated behind its own `QSH_ACCEPTANCE_LONG` (never
//! `QSH_ACCEPTANCE_SLOW` — that gate is on `ci.yml`'s PR-required
//! `acceptance` job) and run to completion only by
//! `.github/workflows/long.yml`'s `workflow_dispatch` job. It reuses this
//! file's harness plumbing but asserts a different thing: not that the
//! pre-existing attach survives the whole outage (the shipped
//! `RecoveryConfig::default()` cannot make it do that over 1800 s — see
//! that function's own doc), but that the *session* is still there, inside
//! its resume TTL, once a fresh `session.attach` is made. The "Step 8의
//! 60초 수용 게이트만 벽시계를 쓰며" wall-clock exception above therefore
//! covers both rounds in this file, not only the 60-second one.
//!
//! `#![cfg(unix)]`: localctl (UDS) and PTY sessions are both unix-only,
//! same gating as every other localctl/reverse test in the tree.
#![cfg(unix)]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use qsh_core::acl::AllowAllPinned;
use qsh_core::client::reconnect::REDIAL_DEADLINE;
use qsh_core::config::{Config, ReverseConfig};
use qsh_core::{Fingerprint, Ops, PathWatchConfig, Paths, RecoveryConfig, SessionAttachStream};
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, IdentityInitReq, KeyStoreMode, SessionAttachReq, SessionOpenReq};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_testkit::{ChaosPolicy, ChaosProxy, TestIdentity, make_identity};
use qsh_transport::{Principal, StaticTrust};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// The literal DoD number (`docs/ROADMAP.md` M3 DoD 2, `PLAN.md` Step 8
/// (a)): longer than [`IDLE_TIMEOUT`] so the QUIC connection on both ends
/// is guaranteed dead by the time it lifts, far short of `[serve].resume_ttl`
/// (default 24 h) so the session and its resume credential must still be
/// there on the other side.
const BLACKOUT: Duration = Duration::from_secs(60);

/// quinn's idle timeout (`docs/design/protocol.md` §2,
/// `qsh_transport::endpoint::MAX_IDLE_TIMEOUT`, restated as a plain
/// constant rather than imported — `qsh-cli` production code never depends
/// on `qsh-transport`, `CLAUDE.md`'s dependency matrix; this file is a dev
/// dependency only, `crates/qsh-cli/Cargo.toml`'s own comment on why, but
/// there is no reason to reach for the transport crate here when the
/// number itself is the load-bearing fact, exactly `attach_recovery.rs`'s
/// own `IDLE_TIMEOUT` precedent). `BLACKOUT` > `IDLE_TIMEOUT` is asserted
/// below rather than merely commented, so the DoD's own "60 s > 45 s"
/// reasoning cannot silently stop holding if either number changes.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// quinn's own dial-attempt timeout
/// (`qsh_transport::endpoint::DEFAULT_DIAL_TIMEOUT`) — a redial the target
/// fires *while the blackout is still live* hangs, silently, for up to
/// this long before the target's backoff loop tries again. Included as
/// slack in [`recovery_budget`] because a redial attempt that happened to
/// start just before [`BLACKOUT`] lifts may still be mid-timeout when it
/// does.
const DIAL_TIMEOUT: Duration = qsh_transport::endpoint::DEFAULT_DIAL_TIMEOUT;

/// Bound on the whole blocking `Ops` scenario, generous over
/// [`recovery_budget`]'s own ceiling — a hang is a failure, not a slow
/// pass, but this test's own wall-clock assertion is the one that actually
/// polices timing.
const DEADLINE: Duration = Duration::from_secs(180);

/// The name a live reverse registration for `target` resolves to.
const HOST_ALIAS: &str = "revhost";

/// `docs/design/testing.md` L4 / `PLAN.md` Step 8 (c): "재등록 시점부터
/// resume 완료까지 2초" — restated here, identical to
/// `reverse_resume_chaos.rs`'s own copy, so a change to the contract fails
/// this test instead of passing quietly.
const REDIAL_DEADLINE_MS: u64 = 2_000;

/// Mirrors `attach_recovery.rs`/`reverse_resume_chaos.rs`'s own
/// `DETECTION_CEILING` — the ceiling [`detection_budget`] must stay under,
/// so a looser `PathWatchConfig` cannot raise its own allowance in
/// lockstep with the outage it causes.
const DETECTION_CEILING: Duration = Duration::from_millis(REDIAL_DEADLINE_MS);

/// Room for everything a derived budget does not model — a real localctl
/// daemon relay, the shell's own round trip, a real chaos proxy relay, and
/// CI scheduling noise over a genuinely 60-second-plus test.
const SCHEDULING_SLACK: Duration = Duration::from_secs(5);

fn detection_budget(cfg: &PathWatchConfig) -> Duration {
    cfg.probe_interval * cfg.strikes + cfg.min_dead_after
}

/// The ceiling on how long *this test* is willing to call the blackout's
/// aftermath, measured from the moment [`ChaosProxy::blackhole`] is issued
/// to the moment the recovered command's output arrives: the mandatory
/// [`BLACKOUT`] itself, plus one worst-case [`DIAL_TIMEOUT`] for a redial
/// attempt in flight when it lifts, plus detection, the target's own
/// (fast-configured) backoff ceiling, the 2 s resume ceiling, and
/// scheduling slack. A lower bound of exactly [`BLACKOUT`] is asserted
/// separately — this test does not pass by recovering early, which would
/// mean the blackout was not actually total.
fn recovery_budget(backoff_max: Duration) -> Duration {
    BLACKOUT
        + DIAL_TIMEOUT
        + detection_budget(&PathWatchConfig::default())
        + backoff_max
        + REDIAL_DEADLINE
        + SCHEDULING_SLACK
}

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// A short target-side `[reverse]` backoff, identical in spirit to
/// `reverse_resume_chaos.rs`'s own `fast_backoff` — unlike that file, this
/// scenario genuinely burns the backoff loop (every redial attempt while
/// the blackout is live fails), so keeping the *inter-attempt* wait small
/// is what keeps the target retrying promptly once the network comes
/// back, rather than possibly sitting in a long backoff sleep across the
/// moment [`BLACKOUT`] lifts.
fn fast_backoff() -> Config {
    Config {
        reverse: ReverseConfig {
            backoff_initial_ms: Some(5),
            backoff_max_ms: Some(20),
            backoff_jitter_pct: Some(0),
            ..Default::default()
        },
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// QSH_ACCEPTANCE_SLOW / QSH_ACCEPTANCE_LONG gates — mirror `tui_expect.rs`'s
// own `QSH_ACCEPTANCE_STRICT`/`skip` convention, simplified to a single
// binary switch per gate: there is exactly one item behind each (the 60 s
// function below, and the 30-minute one further down), not a set of
// per-binary items to enumerate.
// ---------------------------------------------------------------------------

/// Whether `name` is set to something other than unset, empty, or `"0"` —
/// the same "off" vocabulary `tui_expect.rs::required_by_strict` uses for
/// `QSH_ACCEPTANCE_STRICT` and `tunnel_echo_under_load.rs::env_flag` uses
/// for its own acceptance gates. Shared by [`slow_acceptance_requested`]
/// and [`long_acceptance_requested`] so the two gates cannot drift into
/// different "on" spellings.
fn env_on(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().to_lowercase();
    let value = value.trim().to_string();
    !(value.is_empty() || value == "0")
}

/// Whether this run asked for the slow acceptance set.
fn slow_acceptance_requested() -> bool {
    env_on("QSH_ACCEPTANCE_SLOW")
}

/// Announce the skip loudly enough to find in a CI log — `tui_expect.rs`'s
/// own `skip` does the equivalent for a missing binary. This gate is a
/// plain skip, never a failure, on a developer's box: the 60-second cost
/// is only ever paid deliberately (`.github/workflows/ci.yml`'s
/// `acceptance` job sets `QSH_ACCEPTANCE_SLOW: 1`; nothing else does).
fn skip() {
    eprintln!(
        "SKIP: the 60-second reverse blackout gate requires QSH_ACCEPTANCE_SLOW=1 (unset on \
         this run) — `.github/workflows/ci.yml`'s acceptance job sets it"
    );
}

/// Whether this run asked for the long (30-minute) acceptance round.
/// Deliberately *not* `QSH_ACCEPTANCE_SLOW`: that variable is set by
/// `.github/workflows/ci.yml`'s `acceptance` job, which is on `ci-ok`'s
/// `needs` list, and a 30-minute round has no business on the PR-required
/// path (`docs/design/testing.md`'s CI discipline: absolute numbers and
/// long wall clocks belong in a non-blocking job).
fn long_acceptance_requested() -> bool {
    env_on("QSH_ACCEPTANCE_LONG")
}

/// Announce the skip for the long round — the `QSH_ACCEPTANCE_LONG` twin
/// of [`skip`]. Only `.github/workflows/long.yml`'s `workflow_dispatch`
/// job ever sets the gate, so this is what a plain `cargo nextest run
/// --workspace` (or the 60-second `acceptance` job above) prints instead
/// of spending half an hour.
fn skip_long() {
    eprintln!(
        "SKIP: the 30-minute reverse blackout gate requires QSH_ACCEPTANCE_LONG=1 (unset on \
         this run) — `.github/workflows/long.yml`'s workflow_dispatch job sets it"
    );
}

/// `docs/PRD.md` §13's "30분 단절 후에도 TTL 내 세션 복구" — the literal
/// 30 minutes, in seconds.
const LONG_BLACKOUT_DEFAULT_SECS: u64 = 1_800;

/// Length of the long round's blackout. `QSH_BLACKOUT_SECS` overrides it
/// so the wiring can be smoked in a minute instead of half an hour, and so
/// `long.yml`'s dispatch input can shorten a dry run; unset means the PRD
/// row's own 1800 s. Values at or below `IDLE_TIMEOUT` are refused rather
/// than silently accepted — a "blackout" the QUIC connection can sit
/// through proves nothing about resume — by the test function's own
/// assertion ① below, not by this function, which only ever parses.
///
/// A value that is *set but not a plain non-negative integer* panics
/// rather than silently falling back to [`LONG_BLACKOUT_DEFAULT_SECS`] —
/// `long.yml`'s `blackout_secs` dispatch input is free text, and a typo
/// there (`"30m"`, `"1,800"`) should not quietly turn an intended smoke
/// run into the full 1800 s round.
fn long_blackout() -> Duration {
    let secs = match std::env::var("QSH_BLACKOUT_SECS") {
        Err(std::env::VarError::NotPresent) => LONG_BLACKOUT_DEFAULT_SECS,
        Err(err) => panic!("QSH_BLACKOUT_SECS is set but not readable ({err})"),
        Ok(raw) => raw.trim().parse::<u64>().unwrap_or_else(|err| {
            panic!(
                "QSH_BLACKOUT_SECS={raw:?} is set but is not a plain number of seconds ({err}) \
                 — fix the dispatch input rather than let this silently fall back to the \
                 {LONG_BLACKOUT_DEFAULT_SECS}s default"
            )
        }),
    };
    Duration::from_secs(secs)
}

/// Total wall-clock budget the shipped `RecoveryConfig::default()` gives a
/// single live attach to recover **on its own**, from the moment the
/// blackout starts. Two parts:
///
/// - detection: on the reverse leg [`spawn_watchdog`] never fires (there is
///   no `Connection` this attach owns alone to probe — `RecoveryLink`'s own
///   doc, `crates/qsh-core/src/ops/session/drive.rs`), so the leg's death
///   is only ever discovered when `read_leg`'s stream read itself errors —
///   which, under a total blackout, is quinn's own [`IDLE_TIMEOUT`] closing
///   the connection, not an instant signal at the moment the wire goes
///   silent;
/// - recovery: `attempts` sequential windows of `registration_wait +
///   REDIAL_DEADLINE` each, plus the (short, fixed) inter-attempt backoff
///   (`RecoveryConfig::backoff`, private to `ops/session.rs`: 0, 200 ms,
///   then 800 ms per further attempt — pinned here to `attempts == 3`;
///   revisit the two literal millisecond terms below if the shipped
///   default ever changes attempt count).
///
/// `docs/PRD.md` §13's literal 1800 s default blackout is close to 8x this
/// combined budget (`qsh_proto::local::LOCAL_WAIT_MAX`,
/// `RecoveryConfig::default()`'s `attempts`, `REDIAL_DEADLINE`, and
/// `qsh_transport::endpoint::MAX_IDLE_TIMEOUT`), so the pre-existing attach
/// in [`a_real_30_minute_blackout_is_resumed_within_the_ttl`] is guaranteed
/// to exhaust it there; a short `QSH_BLACKOUT_SECS` smoke value can
/// legitimately fall *inside* this budget instead, in which case that same
/// attach recovers on its own — exactly
/// [`a_real_60_second_blackout_survives_and_resumes_the_same_session`]'s
/// own mechanism, not a defect in the long round. The long test's own
/// assertion ③ is only meaningful, and only checked strictly, above this
/// budget.
fn exhaustion_budget() -> Duration {
    let cfg = RecoveryConfig::default();
    let per_attempt = cfg.registration_wait + REDIAL_DEADLINE;
    let attempts = cfg.attempts.max(1);
    IDLE_TIMEOUT
        + per_attempt.saturating_mul(attempts)
        + Duration::from_millis(200)
        + Duration::from_millis(800)
}

// ---------------------------------------------------------------------------
// qsh::recovery telemetry capture — identical technique to
// `reverse_resume_chaos.rs`'s own `CaptureLayer`.
// ---------------------------------------------------------------------------

fn recovery_lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

fn capture_recovery_records() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // No `EnvFilter` here, deliberately — see
        // `reverse_resume_chaos.rs`'s identical comment: an
        // `EnvFilter::from_default_env()` with `RUST_LOG` unset defaults
        // to ERROR-only and silently drops every `qsh::recovery` line
        // before `CaptureLayer` sees it.
        tracing_subscriber::registry()
            .with(CaptureLayer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(false),
            )
            .try_init()
            .ok();
    });
}

struct CaptureLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != qsh_core::telemetry::TARGET {
            return;
        }
        let mut line = String::new();
        event.record(&mut MessageOnly(&mut line));
        if !line.is_empty() {
            recovery_lines()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line);
        }
    }
}

struct MessageOnly<'a>(&'a mut String);

impl tracing::field::Visit for MessageOnly<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

/// One parsed recovery record, same additive `registration_wait_ms` shape
/// as `reverse_resume_chaos.rs`'s own `RecoveryRecord`.
#[derive(Debug, Clone)]
struct RecoveryRecord {
    recovery: String,
    time_to_recovery_ms: u64,
    registration_wait_ms: u64,
}

fn records_for(session_ref: &str) -> Vec<RecoveryRecord> {
    recovery_lines()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("a recovery line must be pure JSON ({err}): {line}"));
            (value["session_ref"].as_str() == Some(session_ref)).then(|| RecoveryRecord {
                recovery: value["recovery"].as_str().expect("recovery").to_string(),
                time_to_recovery_ms: value["time_to_recovery_ms"]
                    .as_u64()
                    .expect("time_to_recovery_ms"),
                registration_wait_ms: value["registration_wait_ms"]
                    .as_u64()
                    .expect("registration_wait_ms — Step 8's additive field must be present"),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// stream helpers — identical technique to `reverse_resume_chaos.rs`'s own
// `Delivered`/`read_until`.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Delivered {
    text: String,
    frames: Vec<(u64, usize)>,
    gaps: Vec<(u64, u64)>,
}

impl Delivered {
    fn push(&mut self, sequence: u64, data: &[u8]) {
        self.text.push_str(&String::from_utf8_lossy(data));
        self.frames.push((sequence, data.len()));
    }

    fn assert_tiles_the_stream(&self, ctx: &str) {
        assert!(self.gaps.is_empty(), "unexpected replay gap(s) — {ctx}");
        let mut expected = self
            .frames
            .first()
            .map(|(seq, len)| seq - *len as u64)
            .unwrap_or(0);
        for (index, (sequence, len)) in self.frames.iter().enumerate() {
            let start = sequence - *len as u64;
            assert_eq!(
                start,
                expected,
                "frame {index} starts at {start} but the stream had reached {expected}: {} — {ctx}",
                if start > expected {
                    "bytes were lost"
                } else {
                    "bytes were redelivered"
                }
            );
            expected = *sequence;
        }
    }
}

fn read_until(stream: &mut SessionAttachStream, seen: &mut Delivered, needle: &str, ctx: &str) {
    while let Some(event) = stream.next_event() {
        match event.unwrap_or_else(|err| panic!("attach stream failed: {err} — {ctx}")) {
            SessionEvent::Output {
                sequence, data_b64, ..
            } => {
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data_b64.as_bytes())
                    .expect("session output is Base64");
                seen.push(sequence, &data);
                if seen.text.contains(needle) {
                    return;
                }
            }
            SessionEvent::Gap {
                requested_after,
                available_from,
                ..
            } => seen.gaps.push((requested_after, available_from)),
            SessionEvent::Exit { .. } | SessionEvent::Closed { .. } => panic!(
                "the session ended before {needle:?} arrived; saw {:?} — {ctx}",
                seen.text
            ),
            _ => {}
        }
    }
    panic!(
        "the attach stream ended before {needle:?} arrived; saw {:?} — {ctx}",
        seen.text
    );
}

// ---------------------------------------------------------------------------
// harness: a real `Ops` behind a real localctl daemon, a real reverse
// registration, and a real chaos proxy blackholed for real time.
// ---------------------------------------------------------------------------

async fn fresh_ops() -> (tempfile::TempDir, Ops, Fingerprint) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    let ops = Ops::new(paths);
    let data = tokio::task::spawn_blocking({
        let ops = ops.clone();
        move || {
            ops.identity_init(IdentityInitReq {
                key_store: Some(KeyStoreMode::File),
            })
        }
    })
    .await
    .expect("identity.init did not panic")
    .expect("identity.init");
    let fingerprint = data
        .fingerprint
        .parse::<Fingerprint>()
        .expect("parse this device's own fingerprint");
    (dir, ops, fingerprint)
}

fn open_shell(ops: &Ops) -> String {
    ops.session_open(SessionOpenReq {
        host: HOST_ALIAS.to_string(),
        argv: vec!["sh".to_string()],
        env: vec![
            EnvVar {
                name: "LANG".into(),
                value: "C".into(),
            },
            EnvVar {
                name: "PS1".into(),
                value: String::new(),
            },
        ],
        term: Some("xterm-256color".into()),
        cols: Some(80),
        rows: Some(24),
        user: None,
    })
    .expect("session.open")
    .session_ref
}

fn attach(ops: &Ops, session_ref: &str) -> SessionAttachStream {
    ops.session_attach(
        SessionAttachReq {
            session_ref: session_ref.to_string(),
            no_steal: false,
        },
        &[],
    )
    .expect("session.attach")
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

/// The five pre-defined pass/fail criteria (`PLAN.md` Step 8 (i), reused
/// by (ii) for this file): ① the session stays alive through the blackout
/// and output keeps accumulating; ② re-registration is observed and
/// `generation` increases; ③ `SessionAttach` for the same `session_id`
/// succeeds; ④ output concatenated across the blackout is byte-identical
/// to the host's own stream with zero gap; ⑤ recovery is not a late
/// idle-timeout.
///
/// `LocalReconnect::attempt_deadline` (`ops/session.rs`) gives a single
/// `recover()` attempt a `registration_wait + REDIAL_DEADLINE` budget rather
/// than the flat `REDIAL_DEADLINE` `recover()` defaults to, so a real ~60 s
/// wait for the target's re-registration usually fits inside *one* attempt
/// — but not always: the client's `wait_ms` window is anchored to when
/// detection declared the path dead, a few milliseconds after the blackout
/// itself began, so on a knife's-edge seed that window can elapse a beat
/// before the target's redial actually lands, producing a `"failed"` record
/// immediately followed by a `"resumed"` one whose own wait resolves
/// near-instantly. Criterion ⑤ is asserted in the shape that tolerates this
/// benign race (see the test body's own comment for the full reasoning):
/// exactly one `"resumed"` record, it is the *last* one, none is ever
/// `"migrated"`, the direct `time_to_recovery_ms - registration_wait_ms <=
/// 2000` budget inequality on the successful record, some record's own
/// `registration_wait_ms` reaches at least [`BLACKOUT`] itself (the direct
/// proof the daemon held a live wait open across the *entire* blocked
/// window at least once rather than resolving on stale state), and an
/// independently measured wall clock inside [`recovery_budget`], itself
/// never shorter than [`BLACKOUT`] (the blackout must actually have been
/// total, not an early escape).
#[tokio::test(flavor = "multi_thread")]
async fn a_real_60_second_blackout_survives_and_resumes_the_same_session() {
    if !slow_acceptance_requested() {
        skip();
        return;
    }
    assert!(
        BLACKOUT > IDLE_TIMEOUT,
        "the DoD's own reasoning requires BLACKOUT ({BLACKOUT:?}) > IDLE_TIMEOUT \
         ({IDLE_TIMEOUT:?}) so the QUIC connection is guaranteed dead, not merely likely dead"
    );
    capture_recovery_records();

    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, HOST_ALIAS)).await;

    let chaos = ChaosProxy::start(harness.addr, ChaosPolicy::seeded(0xB1_ACC0))
        .await
        .expect("bind chaos proxy in front of the controller");
    let ctx = format!(
        "chaos seed={:#x} front={} controller={}",
        chaos.seed(),
        chaos.addr(),
        harness.addr
    );

    let target_config = fast_backoff();
    let backoff_max = Duration::from_millis(
        target_config
            .reverse
            .backoff_max_ms
            .expect("fast_backoff sets this"),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run_fut = harness.run_target_through_chaos(
        &target,
        "device-id",
        "controller",
        None,
        &target_config,
        &chaos,
        |_runtime| {},
        async {
            let _ = shutdown_rx.await;
        },
    );

    let scenario = async {
        let first = wait_for(Duration::from_secs(20), || {
            harness.listen.registry().get(HOST_ALIAS)
        })
        .await;
        let baseline_generation = first.generation;

        let (_ops_dir, ops, _cli_fp) = fresh_ops().await;
        let localctl = harness.attach_localctl(ops.paths()).await;
        let ops = ops.with_recovery(RecoveryConfig {
            // Migration does not exist on this leg (`docs/design/protocol.md`
            // §11-4) — off for the same reason `reverse_resume_chaos.rs`'s
            // own scenario turns it off.
            migration: false,
            // The shipped default (`RecoveryConfig::default()`, which this
            // struct-update already carries forward): `attempts: 3` and
            // `registration_wait: LOCAL_WAIT_MAX` (60 s). This is
            // deliberately *not* inflated past the production value —
            // `LocalReconnect::attempt_deadline` gives a single attempt a
            // `registration_wait + REDIAL_DEADLINE` budget, so one attempt
            // now legitimately spans the whole 60 s blackout below. An
            // earlier draft set `attempts: 60` to accumulate enough 2 s
            // `REDIAL_DEADLINE` windows before that budget split existed;
            // doing that here would once again let this acceptance gate
            // pass on a config the product never ships, hiding the exact
            // gap this test exists to catch.
            ..RecoveryConfig::default()
        });

        let (blackout_tx, blackout_rx) = tokio::sync::oneshot::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<Instant>();
        let ctx_thread = ctx.clone();

        let scenario_handle = tokio::task::spawn_blocking(move || {
            let session_ref = open_shell(&ops);
            let mut stream = attach(&ops, &session_ref);
            let mut seen = Delivered::default();

            stream
                .write(b"printf 'BEFORE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "BEFORE1", &ctx_thread);

            // ---- signal the async side: start the real 60 s blackout
            // now, the clock starts there.
            blackout_tx.send(()).ok();
            let started = started_rx
                .recv()
                .expect("the async side must report when the blackout started");

            // Typed into a session whose reverse path is now dead for a
            // real 60 seconds: this blocks — on real I/O, not a sleep —
            // until the target has redialed, re-registered, and resumed
            // on the far side of it.
            stream
                .write(b"printf 'AFTER%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "AFTER1", &ctx_thread);
            let elapsed = started.elapsed();

            // A second command on the recovered connection: its answer
            // proves any duplicate of the first would already have
            // arrived, because the stream is ordered.
            stream
                .write(b"printf 'DONE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "DONE1", &ctx_thread);

            let records = records_for(&session_ref);
            stream.close();
            (session_ref, seen, elapsed, records)
        });

        blackout_rx
            .await
            .expect("the blocking scenario must reach BEFORE1 before the blackout starts");
        let started = Instant::now();
        chaos.blackhole(BLACKOUT).await;
        started_tx.send(started).ok();

        let (session_ref, seen, elapsed, records) = tokio::time::timeout(DEADLINE, scenario_handle)
            .await
            .unwrap_or_else(|_| panic!("blackout scenario did not finish within {DEADLINE:?}"))
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));

        // ③ the same session_ref every read_until above kept using — the
        // scenario never opened a second session or attached twice.
        assert!(
            session_ref.starts_with(&format!("{HOST_ALIAS}/")),
            "unexpected session_ref shape: {session_ref} — {ctx}"
        );

        // ② re-registration observed, generation strictly advances.
        let after = wait_for(Duration::from_secs(30), || {
            let e = harness.listen.registry().get(HOST_ALIAS)?;
            (e.generation > baseline_generation).then_some(e)
        })
        .await;
        assert!(
            after.generation > baseline_generation,
            "generation must advance past {baseline_generation} — {ctx}"
        );

        // ①/③/④ same session, byte-tiled, zero gap — the session and its
        // ring stayed alive through the full 60 s blackout.
        seen.assert_tiles_the_stream(&ctx);

        // Never recovered early: the blackout must have actually been
        // total for its full duration, not merely attempted.
        assert!(
            elapsed >= BLACKOUT,
            "recovery took only {elapsed:?}, under the mandatory {BLACKOUT:?} blackout — the \
             path must not have been fully blocked — {}",
            chaos.detail()
        );

        // ⑤ recovery is not a late idle-timeout fluke.
        // `LocalReconnect::attempt_deadline` (`ops/session.rs`) gives a
        // single `recover()` attempt a `registration_wait + REDIAL_DEADLINE`
        // budget rather than the flat `REDIAL_DEADLINE` `recover()` defaults
        // to, so a real ~60 s registration wait fits inside *one* attempt —
        // unlike before that budget split existed, when `recover_attach`'s
        // outer loop necessarily produced one `"failed"` record per 2 s-
        // capped attempt. It usually still produces exactly one record, but
        // not always: the client's `wait_ms` window is anchored to when
        // *detection* declared the path dead, a few milliseconds after the
        // blackout itself started, so on a knife's-edge seed that window can
        // elapse a beat before the target's redial actually lands — a
        // `"failed"` record with `registration_wait_ms` at the full window,
        // immediately followed by a fresh attempt whose wait resolves
        // near-instantly because the registration is already there by the
        // time it asks. That is a benign race in a fixed-duration long-poll,
        // not a defect, and `reverse_resume_chaos.rs`'s instant-sever
        // scenario never hits it because its very first attempt always still
        // has the whole window ahead of it. So this test tolerates more than
        // one record (`reverse_resume_chaos.rs`'s own stricter "exactly one"
        // does not apply here) and asserts what must hold regardless: none
        // is ever `migrated` (`docs/design/protocol.md` §11-4: migration
        // does not exist on this leg), exactly one is `"resumed"` and it is
        // the last, the direct `time_to_recovery_ms - registration_wait_ms
        // <= 2000` budget inequality on *that* record (not the flat
        // `time_to_recovery_ms <= 2000` a pre-fix draft asserted, which only
        // ever held because every attempt back then was itself capped at
        // 2 s — this budget lives in the decomposition, not in
        // `time_to_recovery_ms` alone), and — the direct proof this was not
        // an idle-timeout fluke — some record's own `registration_wait_ms`
        // reaches at least the mandatory [`BLACKOUT`] itself, i.e. the
        // daemon really did hold a live wait open across the entire blocked
        // window at least once rather than every attempt resolving early on
        // stale state.
        assert!(
            records.iter().all(|r| r.recovery != "migrated"),
            "migration does not exist on the reverse leg (protocol.md §11-4) — {records:?} — {}",
            chaos.detail()
        );
        let resumed_count = records.iter().filter(|r| r.recovery == "resumed").count();
        assert_eq!(
            resumed_count,
            1,
            "expected exactly one resumed record among the attempts, got {records:?} — {}",
            chaos.detail()
        );
        let last = records.last().expect("at least one attempt was recorded");
        assert_eq!(
            last.recovery,
            "resumed",
            "the last recorded attempt must be the successful one — {records:?} — {}",
            chaos.detail()
        );
        assert!(
            last.time_to_recovery_ms >= last.registration_wait_ms,
            "time_to_recovery_ms must include registration_wait_ms, not race ahead of it — \
             {last:?} — {}",
            chaos.detail()
        );
        assert!(
            last.time_to_recovery_ms - last.registration_wait_ms <= REDIAL_DEADLINE_MS,
            "resume after re-registration took {} ms, over the {REDIAL_DEADLINE_MS} ms bound \
             (registration_wait_ms={}) — {last:?} — {}",
            last.time_to_recovery_ms - last.registration_wait_ms,
            last.registration_wait_ms,
            chaos.detail()
        );
        let max_registration_wait_ms = records
            .iter()
            .map(|r| r.registration_wait_ms)
            .max()
            .unwrap_or(0);
        assert!(
            max_registration_wait_ms >= u64::try_from(BLACKOUT.as_millis()).unwrap_or(u64::MAX),
            "no attempt ever observed a registration wait reaching the mandatory {BLACKOUT:?} \
             blackout (max seen: {max_registration_wait_ms} ms) — recovery must not have waited \
             out the real outage — {records:?} — {}",
            chaos.detail()
        );

        let detection = detection_budget(&RecoveryConfig::default().watch);
        assert!(
            detection <= DETECTION_CEILING,
            "the shipping detector needs {detection:?} to call a path dead, over the \
             {DETECTION_CEILING:?} ceiling"
        );
        let budget = recovery_budget(backoff_max);
        assert!(
            elapsed < budget,
            "reverse recovery took {elapsed:?} to turn back into a working shell after a real \
             {BLACKOUT:?} blackout, over the {budget:?} budget — {}",
            chaos.detail()
        );

        eprintln!(
            "reverse_blackout: elapsed={elapsed:?} records={} \
             successful_time_to_recovery_ms={} max_registration_wait_ms={max_registration_wait_ms} \
             budget={budget:?}",
            records.len(),
            last.time_to_recovery_ms
        );

        localctl.shutdown().await;
        let _ = shutdown_tx.send(());
    };

    let ((), result) = tokio::join!(scenario, run_fut);
    result.unwrap_or_else(|err| {
        panic!(
            "shutdown must resolve run_target_through_chaos cleanly even after a real blackout: \
             {err:?} — {ctx}"
        )
    });

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// the 30-minute round (`docs/PRD.md` §13 — "30분 단절 후에도 TTL 내 세션
// 복구"), gated behind `QSH_ACCEPTANCE_LONG` rather than the round above's
// `QSH_ACCEPTANCE_SLOW`.
// ---------------------------------------------------------------------------

/// Read the resume-credential store's current file bytes, for a
/// before/after comparison only — never parsed, never printed. `CLAUDE.md`
/// forbids logging key material; this function hands the caller raw bytes
/// to `==`-compare, and [`a_real_30_minute_blackout_is_resumed_within_the_ttl`]
/// is the only caller, which does exactly that and nothing else with them.
fn resume_bytes(ops: &Ops) -> Option<Vec<u8>> {
    std::fs::read(qsh_core::resume::ResumeStore::new(ops.paths()).path()).ok()
}

/// `docs/PRD.md` §13's "30분 단절 후에도 TTL 내 세션 복구" row, gated
/// behind [`long_acceptance_requested`] (`QSH_ACCEPTANCE_LONG`) rather
/// than the round above's `QSH_ACCEPTANCE_SLOW` — that variable is on
/// `ci.yml`'s `acceptance` job, which `ci-ok` requires on every PR, and a
/// 30-minute round has no business there. `.github/workflows/long.yml`'s
/// `workflow_dispatch` job is the only place this runs to completion at
/// the PRD row's own 1800 s; a developer's box (and every other CI job)
/// skips it.
///
/// The 60-second scenario above cannot simply be replayed at 30x the
/// length. The shipped `RecoveryConfig::default()` gives a single live
/// attach only [`exhaustion_budget`] (~232 s) before it gives up and ends
/// with a typed error (`crates/qsh-core/src/ops/session/tests.rs`'s
/// `reverse_leg_link_death_with_recovery_exhausted_ends_the_attach_with_a_typed_error_never_a_panic_or_hang`
/// pins that contract) — nowhere near the PRD row's literal 1800 s. So
/// this test does not expect the *same* attach to survive the whole
/// outage; it expects what the PRD row actually promises — the *session*
/// to still be there, inside its resume TTL, once someone reattaches:
///
/// 1. Open a shell through a live reverse registration, read `BEFORE1`
///    (identical setup to the 60-second scenario above).
/// 2. Blackhole the wire for [`long_blackout`] (default 1800 s,
///    `QSH_BLACKOUT_SECS` overrides it for a wiring smoke run).
/// 3. The pre-existing attach is left alone — not detached, not polled
///    for further events. Its own background recovery loop
///    (`drive_attach`, `crates/qsh-core/src/ops/session.rs`) either
///    exhausts the shipped budget (the real 1800 s case) or, for a short
///    `QSH_BLACKOUT_SECS` smoke value inside [`exhaustion_budget`],
///    recovers on its own — exactly
///    [`a_real_60_second_blackout_survives_and_resumes_the_same_session`]'s
///    own mechanism. Either way that is an observation, not something
///    this scenario forces; assertion ③ below is checked strictly only
///    above that budget.
/// 4. Once the target has re-registered (`generation` advances past
///    baseline), open a **fresh** `session.attach` on the same
///    `session_ref` — the assertion this test exists to make.
/// 5. The fresh attach must replay `BEFORE1` with zero `Gap`s (the ring
///    survived the outage), and a freshly typed `AFTER1` must round-trip
///    (the shell is alive, not a husk).
#[tokio::test(flavor = "multi_thread")]
async fn a_real_30_minute_blackout_is_resumed_within_the_ttl() {
    if !long_acceptance_requested() {
        skip_long();
        return;
    }
    // ① the blackout must outlast IDLE_TIMEOUT, or the QUIC connection is
    // only maybe dead by the time it lifts — same reasoning as the
    // 60-second round's own assertion, restated against the long knob.
    assert!(
        long_blackout() > IDLE_TIMEOUT,
        "the PRD row's own reasoning requires the blackout ({:?}) to exceed IDLE_TIMEOUT \
         ({IDLE_TIMEOUT:?}) so the QUIC connection is guaranteed dead, not merely likely dead \
         — QSH_BLACKOUT_SECS must be set above {}",
        long_blackout(),
        IDLE_TIMEOUT.as_secs()
    );
    // Built before assertion ② so that assertion can compare against the
    // resume TTL this scenario's own target broker actually runs with
    // (`BrokerConfig::from_serve`, `crates/qsh-core/src/serve.rs`'s
    // `host_runtime`), not a bare constant that only happens to agree with
    // it today because `fast_backoff()` leaves `[serve]` at its defaults.
    let target_config = fast_backoff();
    // ② the blackout must stay inside the resume TTL, or this is no
    // longer testing "TTL 내" at all.
    let resume_ttl = target_config.serve.resume_ttl();
    assert!(
        long_blackout() < resume_ttl,
        "the blackout ({:?}) must stay under the resume TTL the target broker is actually \
         configured with ({resume_ttl:?}) — otherwise the session itself may already have been \
         reaped before the reattach below",
        long_blackout()
    );
    capture_recovery_records();

    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, HOST_ALIAS)).await;

    let chaos = ChaosProxy::start(harness.addr, ChaosPolicy::seeded(0x1800_ACC0))
        .await
        .expect("bind chaos proxy in front of the controller");
    let ctx = format!(
        "chaos seed={:#x} front={} controller={}",
        chaos.seed(),
        chaos.addr(),
        harness.addr
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run_fut = harness.run_target_through_chaos(
        &target,
        "device-id",
        "controller",
        None,
        &target_config,
        &chaos,
        |_runtime| {},
        async {
            let _ = shutdown_rx.await;
        },
    );

    let scenario = async {
        let first = wait_for(Duration::from_secs(20), || {
            harness.listen.registry().get(HOST_ALIAS)
        })
        .await;
        let baseline_generation = first.generation;

        let (_ops_dir, ops, _cli_fp) = fresh_ops().await;
        let localctl = harness.attach_localctl(ops.paths()).await;
        let ops = ops.with_recovery(RecoveryConfig {
            // Same reasoning as the 60-second scenario's identical
            // struct-update: migration does not exist on this leg
            // (`docs/design/protocol.md` §11-4), and every other field
            // stays the shipped default (`attempts: 3`,
            // `registration_wait: LOCAL_WAIT_MAX`) — this scenario
            // measures the shipped budget, not a config the product
            // never ships.
            migration: false,
            ..RecoveryConfig::default()
        });

        let (blackout_tx, blackout_rx) = tokio::sync::oneshot::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<Instant>();
        let (reattach_ready_tx, reattach_ready_rx) = std::sync::mpsc::channel::<()>();
        let ctx_thread = ctx.clone();

        let scenario_handle = tokio::task::spawn_blocking(move || {
            let session_ref = open_shell(&ops);
            let mut stream1 = attach(&ops, &session_ref);
            let mut seen1 = Delivered::default();

            stream1
                .write(b"printf 'BEFORE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream1, &mut seen1, "BEFORE1", &ctx_thread);

            // ---- signal the async side: start the real blackout now.
            blackout_tx.send(()).ok();
            let started = started_rx
                .recv()
                .expect("the async side must report when the blackout started");

            // The pre-existing attach is deliberately left alone from
            // here on (step 3 in this function's own doc): `stream1` is
            // kept alive — not dropped, not explicitly detached — so its
            // background recovery loop keeps running exactly as it would
            // for a real interactive session nobody is looking at. It is
            // simply never read from again; whatever `records_for` shows
            // for it later is an observation, not a forced outcome.
            let _stream1 = stream1;

            reattach_ready_rx
                .recv()
                .expect("the async side must report the target's re-registration");

            // ---- the fresh attach: the assertion this test exists to
            // make. `session_attach` always takes the stored resume
            // token and, on success, persists a fresh successor
            // (`ops/session.rs`'s `session_attach`), so a bytes snapshot
            // just before and just after brackets the rotation.
            let before_bytes = resume_bytes(&ops);
            let mut stream2 = attach(&ops, &session_ref);
            let mut seen2 = Delivered::default();
            read_until(&mut stream2, &mut seen2, "BEFORE1", &ctx_thread);
            stream2
                .write(b"printf 'AFTER%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream2, &mut seen2, "AFTER1", &ctx_thread);
            let elapsed = started.elapsed();
            let after_bytes = resume_bytes(&ops);

            let records = records_for(&session_ref);
            stream2.close();
            (
                session_ref,
                seen2,
                elapsed,
                records,
                before_bytes,
                after_bytes,
            )
        });

        blackout_rx
            .await
            .expect("the blocking scenario must reach BEFORE1 before the blackout starts");
        let started = Instant::now();
        chaos.blackhole(long_blackout()).await;
        started_tx.send(started).ok();

        // Own deadline: the mandatory blackout itself, plus one worst-case
        // dial attempt in flight when it lifts, the 2 s resume ceiling,
        // and generous scheduling slack — the same shape as the
        // 60-second round's `recovery_budget`, sized for this round's own
        // (knob-controlled) blackout instead of the fixed 60 s constant.
        // Wider than a single `DIAL_TIMEOUT`/`SCHEDULING_SLACK` on both
        // budgets below: this round runs once, on a 2-vCPU hosted runner,
        // and a miss costs a full re-dispatch of the whole round rather
        // than a quick local rerun — worth the extra headroom against the
        // job's own 60-minute ceiling (`long.yml`'s `timeout-minutes`).
        let deadline = long_blackout() + DIAL_TIMEOUT * 2 + REDIAL_DEADLINE + SCHEDULING_SLACK * 8;
        let (after, joined) = tokio::time::timeout(deadline, async {
            // ⑤ wait for the target's re-registration — the event that
            // means the outage is over and a fresh attach can succeed.
            let after = wait_for(
                long_blackout() + DIAL_TIMEOUT * 2 + SCHEDULING_SLACK * 4,
                || {
                    let e = harness.listen.registry().get(HOST_ALIAS)?;
                    (e.generation > baseline_generation).then_some(e)
                },
            )
            .await;
            reattach_ready_tx.send(()).ok();
            let joined = scenario_handle.await;
            (after, joined)
        })
        .await
        .unwrap_or_else(|_| panic!("blackout scenario did not finish within {deadline:?}"));

        assert!(
            after.generation > baseline_generation,
            "generation must advance past {baseline_generation} — {ctx}"
        );

        let (session_ref, seen, elapsed, records, before_bytes, after_bytes) =
            joined.unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));

        // ⑥ the fresh attach targeted the same session_ref — literally
        // the same `String` reused for both attaches above, plus a shape
        // sanity check identical to the 60-second round's own.
        assert!(
            session_ref.starts_with(&format!("{HOST_ALIAS}/")),
            "unexpected session_ref shape: {session_ref} — {ctx}"
        );

        // ⑦ the ring survived the outage: BEFORE1 replayed, zero gaps.
        seen.assert_tiles_the_stream(&ctx);
        assert!(
            seen.text.contains("BEFORE1"),
            "the fresh attach's replay never delivered BEFORE1 — saw {:?} — {ctx}",
            seen.text
        );
        // ⑧ AFTER1 round-tripped on the fresh attach (a hang or a
        // `Closed`/`Exit` before it arrived would already have panicked
        // inside `read_until` above).
        assert!(
            seen.text.contains("AFTER1"),
            "the fresh attach never delivered AFTER1 — saw {:?} — {ctx}",
            seen.text
        );

        // ⑨ never recovered early: the blackout must have actually been
        // total for its full duration.
        assert!(
            elapsed >= long_blackout(),
            "recovery took only {elapsed:?}, under the mandatory {:?} blackout — the path must \
             not have been fully blocked — {}",
            long_blackout(),
            chaos.detail()
        );

        // ③ the pre-existing attach's own fate — see `exhaustion_budget`'s
        // doc for why this is only checked strictly above that budget.
        let budget = exhaustion_budget();
        let resumed_count = records.iter().filter(|r| r.recovery == "resumed").count();
        let failed_count = records.iter().filter(|r| r.recovery == "failed").count();
        if long_blackout() > budget {
            assert!(
                failed_count >= 1,
                "blackout ({:?}) exceeds the shipped recovery budget ({budget:?}) — the \
                 pre-existing attach should have exhausted every attempt, but no \"failed\" \
                 record was seen: {records:?} — {}",
                long_blackout(),
                chaos.detail()
            );
            assert_eq!(
                resumed_count,
                0,
                "blackout ({:?}) exceeds the shipped recovery budget ({budget:?}) — the \
                 pre-existing attach must not have resumed itself, or the outage was not total \
                 for the whole blackout: {records:?} — {}",
                long_blackout(),
                chaos.detail()
            );
        } else {
            eprintln!(
                "reverse_blackout_long: note blackout={:?} is inside the shipped recovery \
                 budget {budget:?} — the pre-existing attach may have recovered on its own \
                 (resumed={resumed_count} failed={failed_count}); assertion (3) (forced \
                 exhaustion) is only exercised above that budget",
                long_blackout()
            );
        }

        // ④ migration does not exist on the reverse leg
        // (`docs/design/protocol.md` §11-4) — true regardless of budget.
        assert!(
            records.iter().all(|r| r.recovery != "migrated"),
            "migration does not exist on the reverse leg (protocol.md §11-4) — {records:?} — {}",
            chaos.detail()
        );

        // Credential rotation: guaranteed by `session_attach`'s own
        // contract (this function's doc), so asserted rather than merely
        // observed. Bytes only — never the token itself.
        let rotated = before_bytes != after_bytes;
        assert!(
            rotated,
            "the fresh attach must have rewritten resume.json (a new successor token is \
             persisted on every successful session.attach) — bytes were identical before and \
             after — {ctx}"
        );

        // Computed from `seen`/`rotated` rather than hardcoded — every
        // field below has already gated an assertion above, so this line
        // reports what was actually observed, not a claim true only by
        // construction.
        let replayed_before_marker = seen.text.contains("BEFORE1");
        let after_marker = seen.text.contains("AFTER1");
        let gaps = seen.gaps.len();
        eprintln!(
            "reverse_blackout_long: blackout={:?} elapsed={elapsed:?} records={} \
             resumed_records={resumed_count} reattach=ok \
             replayed_before_marker={replayed_before_marker} after_marker={after_marker} \
             credential_rotated={rotated} gaps={gaps}",
            long_blackout(),
            records.len()
        );

        localctl.shutdown().await;
        let _ = shutdown_tx.send(());
    };

    let ((), result) = tokio::join!(scenario, run_fut);
    result.unwrap_or_else(|err| {
        panic!(
            "shutdown must resolve run_target_through_chaos cleanly even after a real blackout: \
             {err:?} — {ctx}"
        )
    });

    harness.shutdown().await;
}
