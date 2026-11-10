//! L8 acceptance for the connection status line (ADR-0053 decisions 9 and
//! 16, `docs/design/testing.md` L8): behind a real chaos blackhole the line
//! comes up on the top row of the local terminal model within
//! `max(2 s, 4 x srtt)` plus a second, counts the seconds, names the
//! reconnect attempt, and is gone once the host answers again, with the
//! window showing exactly the host's screen and input typed meanwhile
//! applied once.
//!
//! Two routes, one scenario each: the forward route behind a chaos proxy
//! in front of `qsh serve` ([`status_line_appears_during_a_blackhole_and_clears_on_recovery`]),
//! and the reverse route through a `qsh listen` daemon whose registration
//! rides a chaos proxy ([`reverse_status_line_appears_during_a_blackhole`]).
//! Both hold a blackhole for several wall-clock seconds, so they run under
//! `QSH_ACCEPTANCE_SLOW` like the other chaos gates; the clock-free rules
//! (threshold, text, clearing, row restoration) are unit tests in
//! `qsh-core` (`ops::session::status_tests`, `client::linkstatus::tests`).

use crate::common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::acl::AllowAllPinned;
use qsh_core::config::{Config, ReverseConfig};
use qsh_core::screen::HostScreen;
use qsh_core::{
    Fingerprint, Ops, PathWatchConfig, Paths, Predict, RecoveryConfig, ScreenAttach, ScreenSync,
    SessionAttachStream, StatusLine,
};
use qsh_proto::event::SessionEvent;
use qsh_proto::screen::cell_flags;
use qsh_proto::{IdentityInitReq, KeyStoreMode, SessionAttachReq};
use qsh_testkit::reverse::{ReverseHarness, wait_for};
use qsh_testkit::shell::{said, say};
use qsh_testkit::{ChaosPolicy, ChaosProxy, TestIdentity, make_identity};
use qsh_transport::{Principal, StaticTrust};

use super::attach_recovery::{ProxiedFleet, with_deadline};
use super::screen_sync::{COLS, LocalTerminal, ROWS, open_req, pump_until};

const HOST_ALIAS: &str = common::HOST_ALIAS;

/// How long the path is swallowed.
const BLACKOUT: Duration = Duration::from_secs(6);

/// The line is due `max(2 s, 4 x srtt)` after the first unanswered send;
/// loopback `srtt` is far below 500 ms, so 2 s. A second of slack for the
/// event loop and CI scheduling, as the ADR's test names it.
const APPEAR_BUDGET: Duration = Duration::from_secs(3);

fn slow_enabled() -> bool {
    std::env::var_os("QSH_ACCEPTANCE_SLOW").is_some_and(|v| {
        let v = v.to_string_lossy().trim().to_lowercase();
        !(v.is_empty() || v == "0")
    })
}

fn screen_attach() -> Option<ScreenAttach> {
    Some(ScreenAttach {
        mode: ScreenSync::On,
        cols: COLS,
        rows: ROWS,
        predict: Predict::Always,
        status_line: StatusLine::On,
        escape: Some(b'~'),
    })
}

// ---------------------------------------------------------------------
// what the local terminal shows
// ---------------------------------------------------------------------

/// The status line's text when row 0 carries it.
fn line_of(term: &LocalTerminal) -> Option<String> {
    term.rows()
        .first()
        .filter(|row| row.starts_with("qsh: last reply"))
        .cloned()
}

/// `N` of "last reply Ns ago".
fn seconds_of(line: &str) -> u64 {
    line.strip_prefix("qsh: last reply ")
        .and_then(|rest| rest.split('s').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no seconds count in {line:?}"))
}

/// A row that is exactly the prompt followed by `typed`.
fn has_prompt_row(term: &LocalTerminal, typed: &str) -> bool {
    let want = format!("{} {typed}", super::screen_sync::PROMPT);
    term.rows().contains(&want)
}

fn any_inverse(screen: &HostScreen) -> bool {
    screen
        .snapshot()
        .grid
        .iter()
        .flat_map(|row| &row.cells)
        .any(|c| c.flags & cell_flags::INVERSE != 0)
}

/// An underlined, non-blank cell somewhere below the status row.
fn any_underlined_text(screen: &HostScreen) -> bool {
    screen
        .snapshot()
        .grid
        .iter()
        .skip(1)
        .flat_map(|row| &row.cells)
        .any(|c| c.flags & cell_flags::UNDERLINE != 0 && !c.text.is_empty() && &*c.text != " ")
}

/// Let the host's judgment of the last typed key reach the client before the
/// path goes: the `ScreenEcho` follows the screen update it names, and a
/// blackout that swallows it leaves that key unjudged, which holds back
/// every prediction after it. The shell is idle, so nothing else arrives.
fn settle(_stream: &mut SessionAttachStream, _term: &mut LocalTerminal) {
    std::thread::sleep(Duration::from_millis(500));
}

/// What one blackout showed on the local terminal.
#[derive(Default)]
struct Observed {
    /// Time from the blackout's start to the first sight of the line.
    appeared_after: Option<Duration>,
    /// Every seconds count seen, in order.
    seconds: Vec<u64>,
    reconnecting: bool,
    underlined_typing: bool,
    guidance: bool,
    cleared: bool,
}

/// Feed events to the terminal until the line has come and gone and the
/// typed text is on the host's prompt row, recording what showed.
fn watch_blackout(
    stream: &mut SessionAttachStream,
    term: &mut LocalTerminal,
    started: Instant,
    typed_row: &str,
    ctx: &str,
) -> Observed {
    let mut seen = Observed::default();
    while let Some(event) = stream.next_event() {
        let event =
            event.unwrap_or_else(|err| panic!("attach failed during the blackout: {err} — {ctx}"));
        if let Some(end @ (SessionEvent::Exit { .. } | SessionEvent::Closed { .. })) =
            term.feed(event)
        {
            panic!("the session ended ({end:?}) — {ctx}");
        }
        match line_of(term) {
            Some(line) => {
                seen.appeared_after.get_or_insert_with(|| started.elapsed());
                let n = seconds_of(&line);
                if seen.seconds.last() != Some(&n) {
                    seen.seconds.push(n);
                }
                seen.reconnecting |= line.contains("reconnecting (attempt ");
                seen.guidance |= line.ends_with("; ~. to quit, ~d to detach");
                seen.underlined_typing |= any_underlined_text(&term.screen);
            }
            None if seen.appeared_after.is_some() => {
                seen.cleared = true;
                if has_prompt_row(term, typed_row) {
                    return seen;
                }
            }
            None => {}
        }
    }
    panic!(
        "the attach ended before the line cleared; saw {:?} — {ctx}",
        term.rows()
    );
}

/// The assertions both routes share.
fn check_blackout(seen: &Observed, term: &LocalTerminal, rows_before: &[String], ctx: &str) {
    let appeared = seen
        .appeared_after
        .unwrap_or_else(|| panic!("the line never appeared — {ctx}"));
    assert!(
        appeared <= APPEAR_BUDGET + Duration::from_secs(1),
        "the line took {appeared:?} to appear; budget {APPEAR_BUDGET:?} — {ctx}"
    );
    assert!(seen.guidance, "the escape guidance was missing — {ctx}");
    assert!(
        seen.seconds.windows(2).all(|w| w[0] <= w[1]),
        "the seconds count went backwards: {:?} — {ctx}",
        seen.seconds
    );
    assert!(
        seen.seconds.len() >= 2,
        "the line was not refreshed while the path was down: {:?} — {ctx}",
        seen.seconds
    );
    assert!(seen.cleared, "the line never cleared — {ctx}");
    assert!(
        seen.underlined_typing,
        "input typed during the blackout was not drawn underlined — {ctx}"
    );
    // The window is the host's again, row 0 included.
    assert!(
        !any_inverse(&term.screen),
        "reverse video left over — {ctx}"
    );
    let rows = term.rows();
    assert_eq!(
        rows[0], rows_before[0],
        "row 0 was not restored from the host state — {ctx}"
    );
    // Typed once, not twice.
    let doubled = rows.iter().filter(|r| r.contains("abab")).count();
    assert_eq!(doubled, 0, "input was applied twice: {rows:?} — {ctx}");
}

// ---------------------------------------------------------------------
// forward route
// ---------------------------------------------------------------------

/// A blackhole on an active attach: the line comes up on the top row within
/// the threshold, counts, names the reconnect, clears when the host
/// answers, and the text typed meanwhile lands once (ADR-0053 decision 16,
/// item 6).
#[test]
fn status_line_appears_during_a_blackhole_and_clears_on_recovery() {
    if !slow_enabled() {
        eprintln!("SKIP: needs QSH_ACCEPTANCE_SLOW=1");
        return;
    }
    let fleet = ProxiedFleet::start(ChaosPolicy::seeded(0x0057_A71E));
    let ctx = fleet.context();
    // Enough attempts to outlast the blackout (each redial is bounded by
    // the 2 s resume deadline).
    let ops = fleet.ops(RecoveryConfig {
        attempts: 10,
        ..RecoveryConfig::default()
    });
    let blackout = move || fleet.blackhole(BLACKOUT);
    with_deadline("forward status line", move || {
        let opened = ops
            .session_open_interactive(open_req(), false, screen_attach())
            .unwrap_or_else(|e| panic!("open: {e} — {ctx}"));
        let mut stream = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref,
                    no_steal: false,
                },
                &[],
                screen_attach(),
            )
            .unwrap_or_else(|e| panic!("attach: {e} — {ctx}"));
        let mut term = LocalTerminal::new();
        pump_until(&mut stream, &mut term, "the first prompt", |t| {
            t.shows_bare_prompt()
        });
        // Two answers push the prompt off row 0, so the line takes the top
        // row rather than the bottom one.
        for tag in ["ONE", "TWO"] {
            stream.write(say(tag)).unwrap();
            pump_until(&mut stream, &mut term, tag, |t| t.shows(&said(tag)));
        }
        // One confirmed epoch, so the keys typed during the blackout are
        // drawn ahead of the host: the first key of an epoch is judged, not
        // drawn, and only once the host has reported on the Enter before it.
        settle(&mut stream, &mut term);
        stream.write(b"q".to_vec()).unwrap();
        pump_until(&mut stream, &mut term, "q", |t| has_prompt_row(t, "q"));
        stream.write(b"z".to_vec()).unwrap();
        pump_until(&mut stream, &mut term, "qz", |t| has_prompt_row(t, "qz"));
        assert!(
            line_of(&term).is_none(),
            "no line on a healthy attach — {ctx}"
        );
        settle(&mut stream, &mut term);
        let rows_before = term.rows();

        blackout();
        let started = Instant::now();
        stream.write(b"ab".to_vec()).unwrap();
        let seen = watch_blackout(&mut stream, &mut term, started, "qzab", &ctx);
        assert!(
            seen.reconnecting,
            "the recovery attempt was never named — {ctx}"
        );
        check_blackout(&seen, &term, &rows_before, &ctx);
        assert_eq!(stream.link_status().recovering, None);
        stream.close();
    });
}

/// An attach nobody is typing into shows no line between the idle probes.
#[test]
fn idle_attach_shows_no_status_line() {
    if !slow_enabled() {
        eprintln!("SKIP: needs QSH_ACCEPTANCE_SLOW=1");
        return;
    }
    let fleet = ProxiedFleet::start(ChaosPolicy::seeded(0x0001_D1E1));
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    with_deadline("idle status line", move || {
        let opened = ops
            .session_open_interactive(open_req(), false, screen_attach())
            .unwrap_or_else(|e| panic!("open: {e} — {ctx}"));
        let mut stream = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref,
                    no_steal: false,
                },
                &[],
                screen_attach(),
            )
            .unwrap_or_else(|e| panic!("attach: {e} — {ctx}"));
        let mut term = LocalTerminal::new();
        pump_until(&mut stream, &mut term, "the first prompt", |t| {
            t.shows_bare_prompt()
        });
        // Several idle probe beats (5 s apart) go by. `next_event` blocks,
        // so a reader thread forwards what arrives.
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            while let Some(event) = stream.next_event() {
                if tx.send(event).is_err() {
                    break;
                }
            }
            stream
        });
        let until = Instant::now() + Duration::from_secs(12);
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(event) => {
                    term.feed(event.expect("no error on an idle attach"));
                    assert!(line_of(&term).is_none(), "a line on an idle attach — {ctx}");
                }
                Err(_) => break,
            }
        }
        assert!(line_of(&term).is_none(), "a line on an idle attach — {ctx}");
        drop(rx);
        drop(reader);
    });
}

// ---------------------------------------------------------------------
// reverse route
// ---------------------------------------------------------------------

fn pin(identity: &TestIdentity, name: &str) -> StaticTrust {
    StaticTrust::empty().with_pin(identity.fingerprint, Principal::Device(name.to_string()))
}

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
                ..Default::default()
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

/// The blackout switch the scenario thread (blocking) uses to ask the async
/// side for a chaos blackhole on the registration.
struct Blackout {
    ask: tokio::sync::oneshot::Sender<()>,
    started: std::sync::mpsc::Receiver<Instant>,
}

impl Blackout {
    /// Black the registration out and return when it started.
    fn start(self) -> Instant {
        self.ask.send(()).ok();
        self.started.recv().expect("the blackout start")
    }
}

/// Run `scenario` on a blocking thread against an interactive reverse attach
/// that is open and showing its first prompt, through a `qsh listen` daemon
/// whose registration rides a chaos proxy.
async fn run_reverse(
    seed: u64,
    recovery: RecoveryConfig,
    scenario: impl FnOnce(SessionAttachStream, LocalTerminal, Blackout, String) + Send + 'static,
) {
    let target = make_identity();
    let harness =
        ReverseHarness::start_with(Arc::new(AllowAllPinned), false, pin(&target, HOST_ALIAS)).await;
    let chaos = ChaosProxy::start(harness.addr, ChaosPolicy::seeded(seed))
        .await
        .expect("chaos proxy in front of the controller");
    let ctx = format!("chaos seed={:#x} front={}", chaos.seed(), chaos.addr());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let target_config = fast_backoff();
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

    let scenario_run = async {
        let _first = wait_for(Duration::from_secs(20), || {
            harness.listen.registry().get(HOST_ALIAS)
        })
        .await;
        let (_ops_dir, ops, _fp) = fresh_ops().await;
        let localctl = harness.attach_localctl(ops.paths()).await;
        let ops = ops.with_recovery(recovery);

        let (ask_tx, ask_rx) = tokio::sync::oneshot::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<Instant>();
        let blackout = Blackout {
            ask: ask_tx,
            started: started_rx,
        };
        let ctx_thread = ctx.clone();
        let mut handle = tokio::task::spawn_blocking(move || {
            let opened = ops
                .session_open_interactive(open_req(), false, screen_attach())
                .unwrap_or_else(|e| panic!("open: {e} — {ctx_thread}"));
            let mut stream = ops
                .session_attach_screen(
                    SessionAttachReq {
                        session_ref: opened.session_ref,
                        no_steal: false,
                    },
                    &[],
                    screen_attach(),
                )
                .unwrap_or_else(|e| panic!("attach: {e} — {ctx_thread}"));
            assert!(stream.screen_sync(), "the reverse route is screen-synced");
            let mut term = LocalTerminal::new();
            pump_until(&mut stream, &mut term, "the first prompt", |t| {
                t.shows_bare_prompt()
            });
            scenario(stream, term, blackout, ctx_thread);
        });

        // The scenario asks for a blackout at most once, and may finish
        // without asking.
        let mut ask_rx = Some(ask_rx);
        let finished = loop {
            tokio::select! {
                done = &mut handle => break done,
                asked = async { ask_rx.as_mut().expect("guarded").await }, if ask_rx.is_some() => {
                    ask_rx = None;
                    if asked.is_ok() {
                        let started = Instant::now();
                        chaos.blackhole(BLACKOUT).await;
                        started_tx.send(started).ok();
                    }
                }
            }
        };
        finished.unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));

        localctl.shutdown().await;
        let _ = shutdown_tx.send(());
    };

    let ((), result) = tokio::join!(
        async {
            tokio::time::timeout(Duration::from_secs(120), scenario_run)
                .await
                .unwrap_or_else(|_| panic!("the reverse scenario did not finish — {ctx}"));
        },
        run_fut
    );
    result.unwrap_or_else(|err| panic!("the target must shut down cleanly: {err:?} — {ctx}"));
    harness.shutdown().await;
}

/// The same scenario through a reverse registration: the wait the line
/// measures is the typed input that the target never answers, and the
/// reconnect it names is the local daemon's wait for the target to register
/// again.
#[tokio::test(flavor = "multi_thread")]
async fn reverse_status_line_appears_during_a_blackhole() {
    if !slow_enabled() {
        eprintln!("SKIP: needs QSH_ACCEPTANCE_SLOW=1");
        return;
    }
    run_reverse(
        0x5E7_A71,
        RecoveryConfig {
            migration: false,
            ..RecoveryConfig::default()
        },
        |mut stream, mut term, blackout, ctx| {
            for tag in ["ONE", "TWO"] {
                stream.write(say(tag)).unwrap();
                pump_until(&mut stream, &mut term, tag, |t| t.shows(&said(tag)));
            }
            settle(&mut stream, &mut term);
            stream.write(b"q".to_vec()).unwrap();
            pump_until(&mut stream, &mut term, "q", |t| has_prompt_row(t, "q"));
            stream.write(b"z".to_vec()).unwrap();
            pump_until(&mut stream, &mut term, "qz", |t| has_prompt_row(t, "qz"));
            assert!(line_of(&term).is_none(), "no line on a healthy attach");
            settle(&mut stream, &mut term);
            let rows_before = term.rows();

            let started = blackout.start();
            stream.write(b"ab".to_vec()).unwrap();
            let seen = watch_blackout(&mut stream, &mut term, started, "qzab", &ctx);
            check_blackout(&seen, &term, &rows_before, &ctx);
            assert_eq!(stream.link_status().recovering, None);
            stream.close();
        },
    )
    .await;
}

/// The idle beat the reverse tests run on: short enough that the heartbeat
/// is not the slow part of the scenario.
const IDLE_BEAT: Duration = Duration::from_secs(1);

fn idle_beat_recovery() -> RecoveryConfig {
    RecoveryConfig {
        migration: false,
        watch: PathWatchConfig {
            idle_probe_interval: IDLE_BEAT,
            ..PathWatchConfig::default()
        },
        ..RecoveryConfig::default()
    }
}

/// A reverse attach nobody types into still asks the host whether it is
/// there, so the link record's clock advances with no input at all (the
/// local daemon answers a control `Ping` itself, so the question is an
/// empty `Input`). Unix only: the reverse attach's local daemon route is.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn reverse_idle_attach_keeps_asking_the_host() {
    run_reverse(
        0x0001_D1E5,
        idle_beat_recovery(),
        |mut stream, mut term, _blackout, ctx| {
            settle(&mut stream, &mut term);
            let before = stream.link_status().last_reply;
            // Nothing is typed and nothing is read: the driver answers the
            // host on its own tasks, and an idle shell sends no events.
            std::thread::sleep(5 * IDLE_BEAT);
            let status = stream.link_status();
            let moved = status.last_reply.saturating_duration_since(before);
            assert!(
                moved >= 3 * IDLE_BEAT,
                "the host was not asked while the attach was idle: last reply moved {moved:?} \
                 — {ctx}"
            );
            assert!(status.recovering.is_none(), "{ctx}");
            stream.close();
        },
    )
    .await;
}

/// The case the heartbeat exists for: a blackhole on a fully idle reverse
/// attach. Nothing is typed, yet the line comes up within the threshold of
/// the next heartbeat, counts, and clears once the target registers again.
#[tokio::test(flavor = "multi_thread")]
async fn reverse_idle_status_line_appears_during_a_blackhole() {
    if !slow_enabled() {
        eprintln!("SKIP: needs QSH_ACCEPTANCE_SLOW=1");
        return;
    }
    run_reverse(
        0x001D_1EB1,
        idle_beat_recovery(),
        |mut stream, mut term, blackout, ctx| {
            // Two answers push the prompt off row 0, so the line takes the
            // top row rather than the bottom one.
            for tag in ["ONE", "TWO"] {
                stream.write(say(tag)).unwrap();
                pump_until(&mut stream, &mut term, tag, |t| t.shows(&said(tag)));
            }
            settle(&mut stream, &mut term);
            let started = blackout.start();
            let mut appeared = None;
            let mut first_line = String::new();
            let mut seconds = Vec::new();
            let mut cleared = false;
            while let Some(event) = stream.next_event() {
                let event = event.unwrap_or_else(|err| {
                    panic!("attach failed during the blackout: {err} — {ctx}")
                });
                if let Some(end @ (SessionEvent::Exit { .. } | SessionEvent::Closed { .. })) =
                    term.feed(event)
                {
                    panic!("the session ended ({end:?}) — {ctx}");
                }
                match line_of(&term) {
                    Some(line) => {
                        if appeared.is_none() {
                            appeared = Some(started.elapsed());
                            first_line = line.clone();
                        }
                        let n = seconds_of(&line);
                        if seconds.last() != Some(&n) {
                            seconds.push(n);
                        }
                    }
                    None if appeared.is_some() => {
                        cleared = true;
                        break;
                    }
                    None => {}
                }
            }
            let appeared = appeared.unwrap_or_else(|| panic!("the line never appeared — {ctx}"));
            // Raised by the unanswered question, not by the daemon's later
            // discovery that the registration is gone (which names the
            // reconnect): without the heartbeat the idle attach says nothing
            // until the recovery starts.
            assert!(
                !first_line.contains("reconnecting"),
                "the line first came up as {first_line:?}, from the recovery — {ctx}"
            );
            // One beat to the first question, then the threshold, and a
            // second of slack, as in the active scenario.
            assert!(
                appeared <= IDLE_BEAT + APPEAR_BUDGET + Duration::from_secs(1),
                "the line took {appeared:?} to appear on an idle attach — {ctx}"
            );
            assert!(
                seconds.len() >= 2,
                "the line was not refreshed: {seconds:?} — {ctx}"
            );
            assert!(cleared, "the line never cleared — {ctx}");
            assert!(
                !any_inverse(&term.screen),
                "reverse video left over — {ctx}"
            );
            assert_eq!(stream.link_status().recovering, None);
            stream.close();
        },
    )
    .await;
}
