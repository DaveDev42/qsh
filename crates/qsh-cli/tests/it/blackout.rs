//! L4 acceptance: real wall-clock blackouts over a forward connection
//! (client to `qsh serve`), the evidence for `docs/ROADMAP.md` M3 DoD 2
//! ("60초 차단") and `docs/PRD.md` §13's "30분 단절 후에도 TTL 내 세션 복구"
//! row. These two tests used to run over a reverse leg; ADR-0068 retired it,
//! and the claim they carry (a path that is dead for longer than the QUIC
//! idle timeout does not lose the session) belongs to the forward path too.
//!
//! `attach_recovery.rs` is the PR-always-on half: it severs the path
//! instantly, so a redial succeeds first try and quinn's idle timeout never
//! fires. This file is the other half. [`ProxiedFleet::blackhole`] swallows
//! every datagram in both directions for a real number of seconds, longer
//! than the connection can survive on its own.
//!
//! Two gates keep the wall clock off the PR path:
//!
//! - `QSH_ACCEPTANCE_SLOW` enables the 60-second round (`ci.yml`'s
//!   `acceptance` job sets it).
//! - `QSH_ACCEPTANCE_LONG` enables the 30-minute round, with
//!   `QSH_BLACKOUT_SECS` shortening it for a wiring smoke run. Only
//!   `.github/workflows/long.yml` sets it.
//!
//! The 60 s round keeps one attach alive through the whole blackout, so it
//! raises `RecoveryConfig::attempts` far above the shipped 3: three attempts
//! of 2 s each give up after roughly 7 s on the forward route. The 30-minute
//! round does not try that. It expects what the PRD row promises, that the
//! session is still there inside its resume TTL once someone attaches again.

use crate::attach_recovery::{
    Delivered, IDLE_TIMEOUT, ProxiedFleet, REDIAL_DEADLINE_MS, SCHEDULING_SLACK,
    capture_recovery_records, detection_budget, read_until, records_for,
};
use crate::attach_recovery::{attach, open_shell};

use std::time::{Duration, Instant};

use qsh_core::{Ops, RecoveryConfig};
use qsh_testkit::chaos::ChaosPolicy;
use qsh_testkit::shell::{said, say};

/// The blackout of the always-on-CI round.
const BLACKOUT: Duration = Duration::from_secs(60);

/// Attempts the 60 s round gives its attach. Each failed attempt costs
/// `REDIAL_DEADLINE_MS` plus at most 800 ms of backoff, so this covers about
/// 170 s, well past the blackout.
const BLACKOUT_ATTEMPTS: u32 = 60;

/// Wall-clock bound for the 60 s round: the blackout, plus the detection and
/// one full attempt that can be in flight when it lifts, plus the longest
/// backoff and the final resume.
fn recovery_budget(detection: Duration) -> Duration {
    BLACKOUT
        + detection
        + Duration::from_millis(REDIAL_DEADLINE_MS) * 2
        + Duration::from_millis(800)
        + SCHEDULING_SLACK
}

/// The 30-minute row in seconds.
const LONG_BLACKOUT_DEFAULT_SECS: u64 = 1_800;

/// The default `[serve].resume_ttl` the test host runs with.
fn resume_ttl() -> Duration {
    Duration::from_secs(qsh_core::config::ServeConfig::DEFAULT_RESUME_TTL_SECS)
}

/// Whether `name` is set to something other than unset, empty or `"0"`.
fn env_on(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return false;
    };
    let value = value.to_string_lossy().trim().to_lowercase();
    !(value.is_empty() || value == "0")
}

fn slow_acceptance_requested() -> bool {
    env_on("QSH_ACCEPTANCE_SLOW")
}

fn long_acceptance_requested() -> bool {
    env_on("QSH_ACCEPTANCE_LONG")
}

/// Length of the long round's blackout. A value that is set but is not a
/// plain number of seconds panics instead of falling back to the default:
/// `long.yml`'s dispatch input is free text, and a typo must not quietly
/// turn a smoke run into the full 1800 s round.
fn long_blackout() -> Duration {
    let secs = match std::env::var("QSH_BLACKOUT_SECS") {
        Err(std::env::VarError::NotPresent) => LONG_BLACKOUT_DEFAULT_SECS,
        Err(err) => panic!("QSH_BLACKOUT_SECS is set but not readable ({err})"),
        Ok(raw) => raw.trim().parse::<u64>().unwrap_or_else(|err| {
            panic!(
                "QSH_BLACKOUT_SECS={raw:?} is not a plain number of seconds ({err}); fix the \
                 dispatch input instead of letting it fall back to {LONG_BLACKOUT_DEFAULT_SECS}s"
            )
        }),
    };
    Duration::from_secs(secs)
}

/// The resume credential store's file bytes, for a before/after comparison
/// only. Never parsed and never printed.
fn resume_bytes(ops: &Ops) -> Option<Vec<u8>> {
    std::fs::read(qsh_core::resume::ResumeStore::new(ops.paths()).path()).ok()
}

/// **M3 DoD 2.** A real 60-second blackout, longer than quinn's 45 s idle
/// timeout, and the attach the frontend holds keeps working: the driver keeps
/// redialing underneath it and resumes the same session once the path is back.
///
/// Pass criteria: the session survives and output accumulates across the
/// blackout; the stream tiles with no gap and no repeated byte; the recovery
/// was a resume (exactly one `resumed` record, last, never `migrated`); the
/// host saw a second authorized `session.attach`; and it did not take longer
/// than [`recovery_budget`], which is never shorter than the blackout itself.
#[test]
fn a_real_60_second_blackout_survives_and_resumes_the_same_session() {
    if !slow_acceptance_requested() {
        eprintln!(
            "SKIP: the 60-second blackout gate requires QSH_ACCEPTANCE_SLOW=1 (unset on this \
             run); `.github/workflows/ci.yml`'s acceptance job sets it"
        );
        return;
    }
    assert!(
        BLACKOUT > IDLE_TIMEOUT,
        "BLACKOUT ({BLACKOUT:?}) must exceed IDLE_TIMEOUT ({IDLE_TIMEOUT:?}) so the QUIC \
         connection is certainly dead, not merely likely dead"
    );
    capture_recovery_records();
    let fleet = ProxiedFleet::start(ChaosPolicy::seeded(0xB1_ACC0));
    let ctx = fleet.context();
    // Migration off for the reason `attach_recovery.rs` gives: the proxy
    // models a dead path by blacklisting the client's source address, which a
    // rebind escapes by definition. Resume alone has to carry this.
    let recovery = RecoveryConfig {
        migration: false,
        attempts: BLACKOUT_ATTEMPTS,
        ..RecoveryConfig::default()
    };
    let detection = detection_budget(&recovery.watch);
    let budget = recovery_budget(detection);
    let ops = fleet.ops(recovery);
    let session_ref = open_shell(&ops);
    let attaches_before = fleet.attach_allows();

    let (seen, elapsed, records) = {
        let session_ref = session_ref.clone();
        let ctx = ctx.clone();
        let fleet = &fleet;
        std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let (started_tx, started_rx) = std::sync::mpsc::channel::<Instant>();
            let worker = scope.spawn(move || {
                let mut stream = attach(&ops, &session_ref);
                let mut seen = Delivered::default();
                stream.write(say("BEFORE")).expect("write");
                read_until(&mut stream, &mut seen, &said("BEFORE"), &ctx);

                tx.send(()).ok();
                let started = started_rx.recv().expect("blackout start time");

                // Typed into a path that is dead for a real minute. This
                // blocks on real I/O, not a sleep, until the driver has
                // redialed and resumed on the far side of the blackout.
                stream.write(say("AFTER")).expect("write");
                read_until(&mut stream, &mut seen, &said("AFTER"), &ctx);
                let elapsed = started.elapsed();

                // The answer to a second command proves a duplicate of the
                // first would already have arrived: the stream is ordered.
                stream.write(say("DONE")).expect("write");
                read_until(&mut stream, &mut seen, &said("DONE"), &ctx);

                let records = records_for(&session_ref);
                stream.close();
                (seen, elapsed, records)
            });
            rx.recv().expect("BEFORE must arrive before the blackout");
            let started = Instant::now();
            fleet.blackhole(BLACKOUT);
            started_tx.send(started).ok();

            let deadline = budget + Duration::from_secs(30);
            let begun = Instant::now();
            while !worker.is_finished() {
                assert!(
                    begun.elapsed() < deadline,
                    "the 60 s blackout round did not finish within {deadline:?} — {}",
                    fleet.detail()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            worker
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        })
    };

    assert!(
        elapsed >= BLACKOUT,
        "recovery took only {elapsed:?}, under the {BLACKOUT:?} blackout, so the path was not \
         fully blocked — {}",
        fleet.detail()
    );
    assert!(
        elapsed < budget,
        "the blackout took {elapsed:?} to turn back into a working shell, over the {budget:?} \
         budget — {}",
        fleet.detail()
    );

    // The recovery was a resume, and the successful attempt is the last
    // record. Earlier attempts inside the blackout are `failed` records.
    let resumed = records.iter().filter(|r| r.recovery == "resumed").count();
    assert_eq!(resumed, 1, "{records:?} — {}", fleet.detail());
    assert_eq!(
        records.last().map(|r| r.recovery.as_str()),
        Some("resumed"),
        "{records:?} — {}",
        fleet.detail()
    );
    assert!(
        records.iter().all(|r| r.recovery != "migrated"),
        "migration is off, yet a record says it migrated: {records:?} — {}",
        fleet.detail()
    );
    let last = records.last().expect("one record at least");
    assert!(
        last.time_to_recovery_ms <= REDIAL_DEADLINE_MS,
        "the successful resume took {} ms, over the {REDIAL_DEADLINE_MS} ms bound — {}",
        last.time_to_recovery_ms,
        fleet.detail()
    );

    seen.assert_tiles_the_stream(&fleet.detail());
    assert_eq!(
        qsh_testkit::shell::said_count(&seen.text, "AFTER"),
        1,
        "the input typed into the dead path was applied a number of times other than one — {}\n{:?}",
        fleet.detail(),
        seen.text
    );
    assert!(seen.text.contains(&said("BEFORE")), "{:?}", seen.text);

    assert_eq!(
        fleet.attach_allows(),
        attaches_before + 2,
        "the host did not see the initial attach and its resume — {}",
        fleet.detail()
    );
    eprintln!(
        "blackout 60s: resumed after {elapsed:?} (budget {budget:?}, {} recovery record(s), {ctx})",
        records.len()
    );
}

/// `docs/PRD.md` §13's "30분 단절 후에도 TTL 내 세션 복구". Gated behind
/// `QSH_ACCEPTANCE_LONG`, never `QSH_ACCEPTANCE_SLOW`: `ci.yml`'s acceptance
/// job sets that one and a 30-minute round has no place on the PR path.
///
/// The 60-second scenario cannot just be replayed at 30x. The shipped
/// `RecoveryConfig::default()` gives a live attach only a few seconds of
/// redialing before it ends with a typed error. So this test does not expect
/// that attach to survive. It expects the session to be there inside its
/// resume TTL once someone attaches again:
///
/// 1. open a shell, read `BEFORE`;
/// 2. blackhole the wire for [`long_blackout`] (1800 s by default);
/// 3. leave the first attach alone;
/// 4. when the blackout is over, open a fresh `session.attach` on the same
///    `session_ref`, which must replay `BEFORE` with no gap, and round-trip
///    a new `AFTER`, with the resume credential rotated.
#[test]
fn a_real_30_minute_blackout_is_resumed_within_the_ttl() {
    if !long_acceptance_requested() {
        eprintln!(
            "SKIP: the 30-minute blackout gate requires QSH_ACCEPTANCE_LONG=1 (unset on this \
             run); `.github/workflows/long.yml`'s workflow_dispatch job sets it"
        );
        return;
    }
    let blackout = long_blackout();
    assert!(
        blackout > IDLE_TIMEOUT,
        "the blackout ({blackout:?}) must exceed IDLE_TIMEOUT ({IDLE_TIMEOUT:?}) so the QUIC \
         connection is certainly dead; QSH_BLACKOUT_SECS must be above {}",
        IDLE_TIMEOUT.as_secs()
    );
    assert!(
        blackout < resume_ttl(),
        "the blackout ({blackout:?}) must stay under the resume TTL ({:?}), or the session may \
         already have been reaped before the reattach",
        resume_ttl()
    );
    capture_recovery_records();
    let fleet = ProxiedFleet::start(ChaosPolicy::seeded(0x1800_ACC0));
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig {
        migration: false,
        ..RecoveryConfig::default()
    });
    let session_ref = open_shell(&ops);

    // The blackout, plus a dial that can be in flight when it lifts, plus
    // slack. This round runs once on a small hosted runner and a miss costs
    // a whole re-dispatch, so the slack is wide.
    let deadline = blackout + Duration::from_secs(60) + SCHEDULING_SLACK * 8;

    let (seen, elapsed, before_bytes, after_bytes) = std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<Instant>();
        let ctx = ctx.clone();
        let session_ref = session_ref.clone();
        let worker = scope.spawn(move || {
            let mut stream1 = attach(&ops, &session_ref);
            let mut seen1 = Delivered::default();
            stream1.write(say("BEFORE")).expect("write");
            read_until(&mut stream1, &mut seen1, &said("BEFORE"), &ctx);

            tx.send(()).ok();
            let started = started_rx.recv().expect("blackout start time");

            // The first attach is kept alive but never read again, so its
            // recovery loop runs as it would for a session nobody watches.
            let _stream1 = stream1;

            // Wall clock on purpose: the blackhole call returned at once and
            // a fresh attach before it lifts would only time out. This is
            // the one place the round waits instead of blocking on I/O.
            let lift = started + blackout;
            if let Some(left) = lift.checked_duration_since(Instant::now()) {
                std::thread::sleep(left + SCHEDULING_SLACK);
            }

            // `session_attach` takes the stored resume token and persists a
            // successor on success, so a bytes snapshot on each side of it
            // brackets the rotation.
            let before_bytes = resume_bytes(&ops);
            let mut stream2 = attach(&ops, &session_ref);
            let mut seen2 = Delivered::default();
            read_until(&mut stream2, &mut seen2, &said("BEFORE"), &ctx);
            stream2.write(say("AFTER")).expect("write");
            read_until(&mut stream2, &mut seen2, &said("AFTER"), &ctx);
            let elapsed = started.elapsed();
            let after_bytes = resume_bytes(&ops);
            stream2.close();
            (seen2, elapsed, before_bytes, after_bytes)
        });
        rx.recv().expect("BEFORE must arrive before the blackout");
        let started = Instant::now();
        fleet.blackhole(blackout);
        started_tx.send(started).ok();

        let begun = Instant::now();
        while !worker.is_finished() {
            assert!(
                begun.elapsed() < deadline,
                "the long blackout round did not finish within {deadline:?} — {}",
                fleet.detail()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        worker
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    });

    // The ring survived the outage: BEFORE replayed with no gap.
    seen.assert_tiles_the_stream(&ctx);
    assert!(
        seen.text.contains(&said("BEFORE")),
        "the fresh attach never replayed BEFORE; saw {:?} — {ctx}",
        seen.text
    );
    assert!(
        seen.text.contains(&said("AFTER")),
        "the fresh attach never delivered AFTER; saw {:?} — {ctx}",
        seen.text
    );
    assert!(
        elapsed >= blackout,
        "the reattach finished after {elapsed:?}, under the {blackout:?} blackout, so the path \
         was not fully blocked — {}",
        fleet.detail()
    );
    // Only the credential's rotation is checked, never its content.
    assert!(
        before_bytes.is_some() && after_bytes.is_some() && before_bytes != after_bytes,
        "the resume credential was not rotated by the fresh attach — {ctx}"
    );
    let records = records_for(&session_ref);
    eprintln!(
        "blackout {}s: session resumed by a fresh attach after {elapsed:?} ({} recovery \
         record(s) from the first attach, {ctx})",
        blackout.as_secs(),
        records.len()
    );
}
