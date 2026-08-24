//! L4: the reverse-route recovery gate (`PLAN.md` M3 Step 8 (b)/(c)/(d),
//! `docs/design/testing.md` L4's "chaos is a PR gate", `docs/ROADMAP.md` M3
//! DoD 2's "60초 차단" — this file is the PR-always-on half of that DoD;
//! `crates/qsh-cli/tests/reverse_blackout.rs` is the other half).
//!
//! `reverse_chaos.rs` (M3 Step 4) already proved the *target*'s own half of
//! this: sever the target→controller leg, and the target's reconnect loop
//! redials and re-registers on its own, `generation` advancing by exactly
//! one, while a session opened directly on the target's own broker survives
//! under the same `session_id` — reached, in that file, only through a raw
//! handle to the target's broker, because M3 Step 5's localctl passthrough
//! did not exist yet.
//!
//! It exists now (Steps 5–7), so this file drives the *other* half — the
//! one `docs/design/protocol.md` §11-4's Reattach mapping actually promises
//! a user: a real `Ops::session_attach` stream, opened on the controller's
//! reverse registration through a real localctl daemon exactly the way
//! `crates/qsh-cli/src/main.rs` drives it, survives the same sever()
//! transparently — the client is never told the path died, and the same
//! `qsh::recovery` telemetry the forward route emits (`RecoveryConfig`,
//! `PLAN.md` M2 Step 7) comes out the other side with the additive
//! `registration_wait_ms` field this step adds. This file is the reverse
//! twin of `crates/qsh-cli/tests/attach_recovery.rs`, whose `Delivered`/
//! `read_until`/budget-assertion shape it mirrors line for line where nothing
//! about the reverse route changes it — Step 8 (a)'s own charter is "no new
//! resume logic", so nor is there new *test* logic where the old test logic
//! already applies.
//!
//! **Why this file never asserts a literal backoff *count*.** `PLAN.md`'s
//! own prose for this gate says to sever "long enough to burn detection and
//! at least two backoffs". Read as a literal assertion on the target's own
//! `client::reconnect`-style exponential backoff, that is not something
//! this harness can force deterministically: `ChaosProxy::sever` only
//! blacklists the *severed* flow's address, so a target's very next redial
//! — from a fresh ephemeral port — is relayed normally and succeeds on the
//! first try (`reverse_chaos.rs`'s own scenario is exactly this, and never
//! needs a backoff to fire). `ChaosProxy::blackhole` would block a fresh
//! redial too, but a blocked dial only fails once quinn's own dial timeout
//! elapses (`qsh_transport::endpoint::DEFAULT_DIAL_TIMEOUT`, 10 s) — far
//! outside this file's "seconds, not minutes" budget, and there is no
//! config seam (Step 8 does not add one) to shorten it. Forcing a fresh
//! registration to die again before the client's own attach driver can
//! complete on it would race that driver's real, production `recover_attach`
//! loop with no hook to synchronize against — a flaky test in exchange for
//! a number none of Step 8 (i)'s five pass/fail criteria actually name.
//! What *is* asserted instead, and is the substance "burn detection and
//! backoff" is reaching for: the independently-measured wall clock is held
//! to a budget that is *derived* from the target's own configured
//! `backoff_max_ms` plus the client's own detection budget plus the 2 s
//! resume ceiling (criterion ⑤ below) — so a regression that made recovery
//! quietly depend on a slow backoff path, or on idle-timeout luck, still
//! fails this test even though no line here counts retries.
//!
//! `#![cfg(unix)]`: localctl (UDS) and PTY sessions are both unix-only,
//! same gating as every other localctl/reverse testkit file.
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

/// Bound on any single "this must already have happened" harness wait.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Bound on the whole blocking `Ops` scenario. Generous — a hang is a
/// failure, not a slow pass.
const DEADLINE: Duration = Duration::from_secs(90);

/// The name a live reverse registration for `target` resolves to
/// (`ReverseHarness::start_with`'s own doc: pinning under this name is
/// what makes the registry resolve to it).
const HOST_ALIAS: &str = "revhost";

/// The contract bound from `docs/design/testing.md` L4 / `PLAN.md` Step 8
/// (c): "재등록 시점부터 resume 완료까지 2초". Restated here so a change to
/// it fails this test rather than passing quietly — same discipline as
/// `attach_recovery.rs`'s own `REDIAL_DEADLINE_MS`.
const REDIAL_DEADLINE_MS: u64 = 2_000;

/// The ceiling on [`detection_budget`] that no change to `PathWatchConfig`
/// may raise without this test noticing — mirrors `attach_recovery.rs`'s
/// own `DETECTION_CEILING` exactly (same number, same reasoning: a looser
/// detector must not get to raise its own allowance in lockstep with the
/// outage it causes).
const DETECTION_CEILING: Duration = Duration::from_millis(REDIAL_DEADLINE_MS);

/// Room for everything the derived budget below does not model: a real
/// localctl daemon relay, the shell's own round trip, and the chaos proxy
/// in the middle — same order of magnitude as `attach_recovery.rs`'s own
/// `SCHEDULING_SLACK`.
const SCHEDULING_SLACK: Duration = Duration::from_secs(3);

/// The longest the watchdog on either end of the severed connection may
/// take to call the silent path dead — `attach_recovery.rs`'s own
/// `detection_budget`, restated here because `docs/design/protocol.md`
/// §11-4 reuses the identical detector (and identical default config) on
/// both roles rather than inventing a reverse-specific one.
fn detection_budget(cfg: &PathWatchConfig) -> Duration {
    cfg.probe_interval * cfg.strikes + cfg.min_dead_after
}

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

/// A config-injected short `[reverse]` backoff for the *target* — never
/// exercised on this scenario's happy path (module docs: a fresh redial
/// after a plain `sever()` succeeds first try), but it is what makes the
/// wall-clock budget below meaningful rather than vacuous: the budget
/// includes this as its `backoff_max_ms` term, so keeping it small keeps
/// the budget tight enough to catch a real regression.
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
// qsh::recovery telemetry capture — identical technique to
// `crates/qsh-cli/tests/attach_recovery.rs`'s own `CaptureLayer`, duplicated
// here rather than shared because the two crates do not share a test-only
// module and the whole thing is a dozen lines.
// ---------------------------------------------------------------------------

fn recovery_lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

fn capture_recovery_records() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // No `EnvFilter` here, deliberately — same reason
        // `attach_recovery.rs`'s own `capture_recovery_records` has none:
        // an `EnvFilter::from_default_env()` with `RUST_LOG` unset (the
        // default in CI and most local runs) defaults to ERROR-level-only,
        // which silently drops every `tracing::info!` on `qsh::recovery`
        // before `CaptureLayer` ever sees it — a passing-looking setup
        // that in fact captures nothing. `CaptureLayer` filters by target
        // itself, so no global filter is needed for it to be correct.
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

/// One parsed recovery record — the additive `registration_wait_ms`
/// (`PLAN.md` Step 8 (b), `docs/CLI.md` §6.4) alongside the two fields
/// `attach_recovery.rs`'s own `RecoveryRecord` already reads.
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
// stream helpers — identical technique to `attach_recovery.rs`'s own
// `Delivered`/`read_until` (byte-tiling *is* the byte-identity check: a
// contiguous cover of cumulative offsets from first frame to last means
// every byte of the host's stream was seen exactly once, in order, with no
// gap at the seam a recovery leaves — Step 8 (i) criterion ④).
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
// registration, and a chaos proxy in the target→controller leg.
// ---------------------------------------------------------------------------

/// A fresh `Ops` with a file-mode device identity already initialized and
/// its `runtime_dir()` ready for `ReverseHarness::attach_localctl` to bind
/// under — identical to `reverse_attach.rs`'s own `fresh_ops`.
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

/// The five pre-defined pass/fail criteria (`PLAN.md` Step 8 (i)):
///
/// ① the session stays alive through the blackout and output keeps
///    accumulating (proved here the same way `attach_recovery.rs` proves
///    it for the forward route: input queued *while the path is dead*
///    reaches the shell and its output arrives intact once resumed — a
///    session the target had torn down could not do that, and a ring that
///    dropped bytes would surface as [`SessionEvent::Gap`], asserted empty
///    in [`Delivered::assert_tiles_the_stream`] below);
/// ② re-registration is observed and `generation` increases;
/// ③ `SessionAttach` for the *same* `session_id` succeeds (the whole
///    scenario never opens a second session or re-attaches by hand — one
///    `SessionAttachStream`, held live, end to end);
/// ④ output concatenated across the blackout is byte-identical to the
///    host's own stream with zero gap ([`Delivered::assert_tiles_the_stream`]);
/// ⑤ recovery is not a late idle-timeout: exactly one `qsh::recovery`
///    record, `recovery != "migrated"` (`docs/design/protocol.md` §11-4:
///    migration does not exist on this leg), the budget inequality
///    `time_to_recovery_ms - registration_wait_ms <= 2000` as a real
///    assertion, and an independently measured wall clock inside a budget
///    derived from `PathWatchConfig` + the target's own `backoff_max_ms` +
///    2 s — itself under [`DETECTION_CEILING`].
#[tokio::test(flavor = "multi_thread")]
async fn a_severed_reverse_path_resumes_the_same_session_under_a_live_cli_attach() {
    capture_recovery_records();

    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, HOST_ALIAS)).await;

    let chaos = ChaosProxy::start(harness.addr, ChaosPolicy::seeded(0x835_5E7))
        .await
        .expect("bind chaos proxy in front of the controller");
    let ctx = format!(
        "chaos seed={:#x} front={} controller={}",
        chaos.seed(),
        chaos.addr(),
        harness.addr
    );

    let target_config = fast_backoff();
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
        let first = wait_for(TIMEOUT, || harness.listen.registry().get(HOST_ALIAS)).await;
        let baseline_generation = first.generation;

        let (_ops_dir, ops, _cli_fp) = fresh_ops().await;
        let localctl = harness.attach_localctl(ops.paths()).await;
        let ops = ops.with_recovery(RecoveryConfig {
            // Migration does not exist on this leg (`docs/design/protocol.md`
            // §11-4: "migration은 이 leg에 존재하지 않는다") — off for the same
            // reason `attach_recovery.rs`'s own severed-path scenario turns
            // it off: correctness comes from resume alone, and leaving it on
            // would only add a probe round trip that can never succeed here.
            migration: false,
            ..RecoveryConfig::default()
        });

        let (sever_tx, sever_rx) = tokio::sync::oneshot::channel::<()>();
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

            // ---- signal the async side: sever now, the clock starts there
            // ---- ("immediately before sever()", `resume_chaos.rs`'s own
            // discipline for what "the clock" is allowed to mean).
            sever_tx.send(()).ok();
            let started = started_rx
                .recv()
                .expect("the async side must report when it severed the path");

            // Typed into a session whose reverse path is already dead: the
            // bytes are this client's responsibility now (`docs/design/
            // protocol.md` §10 step 5, unchanged by Step 8), and resume
            // owes them to the shell exactly once, on the far side of a
            // re-registration this client never dialed for itself.
            stream
                .write(b"printf 'AFTER%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "AFTER1", &ctx_thread);
            let elapsed = started.elapsed();

            // A second command on the recovered connection: its answer
            // proves any duplicate of the first would already have arrived,
            // because the stream is ordered.
            stream
                .write(b"printf 'DONE%s\\n' 1\n".to_vec())
                .expect("write");
            read_until(&mut stream, &mut seen, "DONE1", &ctx_thread);

            let records = records_for(&session_ref);
            stream.close();
            (session_ref, seen, elapsed, records)
        });

        sever_rx
            .await
            .expect("the blocking scenario must reach BEFORE1 before we sever");
        let started = Instant::now();
        chaos.sever().await;
        started_tx.send(started).ok();

        let (session_ref, seen, elapsed, records) = tokio::time::timeout(DEADLINE, scenario_handle)
            .await
            .unwrap_or_else(|_| panic!("attach scenario did not finish within {DEADLINE:?}"))
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));
        // ③ the same session_ref every read_until above kept using — the
        // scenario never opened a second session or attached twice.
        assert!(
            session_ref.starts_with(&format!("{HOST_ALIAS}/")),
            "unexpected session_ref shape: {session_ref} — {ctx}"
        );

        // ② re-registration observed, generation strictly advances.
        let after = wait_for(TIMEOUT, || {
            let e = harness.listen.registry().get(HOST_ALIAS)?;
            (e.generation > baseline_generation).then_some(e)
        })
        .await;
        assert!(
            after.generation > baseline_generation,
            "generation must advance past {baseline_generation} — {ctx}"
        );

        // ③/④ same session, byte-tiled, zero gap.
        seen.assert_tiles_the_stream(&ctx);

        // ⑤ exactly one record, never migrated, budget inequality, and an
        // independently measured wall clock under a derived ceiling.
        assert_eq!(
            records.len(),
            1,
            "expected exactly one recovery record, got {records:?} — {}",
            chaos.detail()
        );
        let record = &records[0];
        assert_ne!(
            record.recovery,
            "migrated",
            "migration does not exist on the reverse leg (protocol.md §11-4) — {records:?} — {}",
            chaos.detail()
        );
        assert!(
            record.time_to_recovery_ms >= record.registration_wait_ms,
            "time_to_recovery_ms must include registration_wait_ms, not race ahead of it — \
             {record:?} — {}",
            chaos.detail()
        );
        assert!(
            record.time_to_recovery_ms - record.registration_wait_ms <= REDIAL_DEADLINE_MS,
            "resume after re-registration took {} ms, over the {REDIAL_DEADLINE_MS} ms bound \
             (registration_wait_ms={}) — {}",
            record.time_to_recovery_ms - record.registration_wait_ms,
            record.registration_wait_ms,
            chaos.detail()
        );

        let detection = detection_budget(&RecoveryConfig::default().watch);
        assert!(
            detection <= DETECTION_CEILING,
            "the shipping detector needs {detection:?} to call a path dead, over the \
             {DETECTION_CEILING:?} ceiling"
        );
        let backoff_ceiling = Duration::from_millis(
            target_config
                .reverse
                .backoff_max_ms
                .expect("fast_backoff sets this"),
        );
        let budget = detection + backoff_ceiling + REDIAL_DEADLINE + SCHEDULING_SLACK;
        assert!(
            elapsed < budget,
            "reverse recovery took {elapsed:?} to turn back into a working shell, over the \
             {budget:?} detection+backoff+resume budget — {}",
            chaos.detail()
        );
        assert!(
            u128::from(record.time_to_recovery_ms) <= elapsed.as_millis(),
            "the driver reported a {} ms recovery inside a {elapsed:?} window it is nested \
             in — {}",
            record.time_to_recovery_ms,
            chaos.detail()
        );

        localctl.shutdown().await;
        let _ = shutdown_tx.send(());
    };

    let ((), result) = tokio::join!(scenario, run_fut);
    result.unwrap_or_else(|err| {
        panic!("shutdown must resolve run_target_through_chaos cleanly even after a sever: {err:?} — {ctx}")
    });

    harness.shutdown().await;
}
