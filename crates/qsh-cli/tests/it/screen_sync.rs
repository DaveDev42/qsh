//! The client end of screen state sync, driven through `Ops` against a real
//! `qsh serve` (ADR-0052 decisions 1, 9, 11, 15 and 18).
//!
//! The local terminal is modelled by a second emulator
//! ([`qsh_core::screen::HostScreen`]): the `Output` bytes the attach hands a
//! frontend are fed to it, and assertions read what it shows. The same model
//! reads the byte path, so a number measured on one path means the same thing
//! on the other.
//!
//! `ctrl_c_reaches_a_flooding_session_within_budget` is decision 18's item 2
//! and runs under `QSH_ACCEPTANCE_SLOW` like the other chaos gates; the rest
//! are ordinary tests and run on every platform.

use crate::common;

use std::time::{Duration, Instant};

use base64::Engine as _;
use common::{Fleet, HOST_ALIAS, Sandbox};
use qsh_core::screen::{HostScreen, ScreenOptions};
use qsh_core::{
    OpError, Ops, Paths, Predict, RecoveryConfig, ScreenAttach, ScreenSync, SessionAttachStream,
};
use qsh_proto::ErrorCode;
use qsh_proto::event::SessionEvent;
use qsh_proto::{EnvVar, SessionAttachReq, SessionOpenReq};
use qsh_testkit::chaos::{ChaosPolicy, DelayDist};
use qsh_testkit::shell::{ENTER, pty_shell, said, say};

use super::attach_recovery::{ProxiedFleet, with_deadline};

const COLS: u16 = 80;
const ROWS: u16 = 24;
const PROMPT: &str = "PRM>";

fn ops_for(sandbox: &Sandbox) -> Ops {
    Ops::new(Paths::new(sandbox.config_dir(), sandbox.state_dir()))
}

fn screen_attach(mode: ScreenSync) -> Option<ScreenAttach> {
    Some(ScreenAttach {
        mode,
        cols: COLS,
        rows: ROWS,
        predict: Default::default(),
        status_line: Default::default(),
    })
}

/// A shell whose prompt is exactly `PRM> `, so a prompt on the screen is a
/// row that reads `PRM>` and nothing else.
fn open_req() -> SessionOpenReq {
    SessionOpenReq {
        host: HOST_ALIAS.to_string(),
        argv: pty_shell(),
        env: vec![
            EnvVar {
                name: "LANG".into(),
                value: "C".into(),
            },
            EnvVar {
                name: "PS1".into(),
                value: format!("{PROMPT} "),
            },
            EnvVar {
                name: "PROMPT".into(),
                value: format!("{PROMPT}$S"),
            },
        ],
        term: Some("xterm-256color".into()),
        cols: Some(u32::from(COLS)),
        rows: Some(u32::from(ROWS)),
        user: None,
        shell_command: None,
    }
}

/// The local terminal: whatever the attach writes to it lands here.
struct LocalTerminal {
    screen: HostScreen,
    bytes: u64,
}

impl LocalTerminal {
    fn new() -> Self {
        Self {
            screen: HostScreen::new(ScreenOptions {
                rows: ROWS,
                cols: COLS,
                ..ScreenOptions::default()
            }),
            bytes: 0,
        }
    }

    /// Write one event to the terminal; `Some` when the session ended.
    fn feed(&mut self, event: SessionEvent) -> Option<SessionEvent> {
        match event {
            SessionEvent::Output { data_b64, .. } => {
                let data = base64::engine::general_purpose::STANDARD
                    .decode(data_b64.as_bytes())
                    .expect("output is Base64");
                self.bytes += data.len() as u64;
                self.screen.feed(&data, self.bytes);
                None
            }
            end @ (SessionEvent::Exit { .. } | SessionEvent::Closed { .. }) => Some(end),
            _ => None,
        }
    }

    fn rows(&self) -> Vec<String> {
        let state = self.screen.snapshot();
        state
            .grid
            .iter()
            .map(|row| {
                row.cells
                    .iter()
                    .map(|c| if c.text.is_empty() { " " } else { &*c.text })
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn shows(&self, needle: &str) -> bool {
        self.rows().iter().any(|row| row.contains(needle))
    }

    /// A row that is only the prompt.
    fn shows_bare_prompt(&self) -> bool {
        self.rows().iter().any(|row| row == PROMPT)
    }
}

/// Feed events until `done` holds for the terminal, or the stream ends.
fn pump_until(
    stream: &mut SessionAttachStream,
    term: &mut LocalTerminal,
    what: &str,
    done: impl Fn(&LocalTerminal) -> bool,
) {
    if done(term) {
        return;
    }
    while let Some(event) = stream.next_event() {
        let event = event.unwrap_or_else(|err| panic!("attach failed waiting for {what}: {err}"));
        if let Some(end) = term.feed(event) {
            panic!(
                "the session ended ({end:?}) before {what}; screen: {:?}",
                term.rows()
            );
        }
        if done(term) {
            return;
        }
    }
    panic!("the attach ended before {what}; screen: {:?}", term.rows());
}

fn open_and_attach(ops: &Ops, mode: ScreenSync) -> Result<(String, SessionAttachStream), OpError> {
    let opened = ops.session_open_interactive(open_req(), false, screen_attach(mode))?;
    let stream = ops.session_attach_screen(
        SessionAttachReq {
            session_ref: opened.session_ref.clone(),
            no_steal: false,
        },
        &[],
        screen_attach(mode),
    )?;
    Ok((opened.session_ref, stream))
}

#[test]
fn auto_draws_the_remote_screen_on_the_local_terminal() {
    let fleet = Fleet::start();
    let ops = ops_for(&fleet.client);
    with_deadline("screen-sync attach", move || {
        let (_ref, mut stream) = open_and_attach(&ops, ScreenSync::Auto).expect("open and attach");
        assert!(stream.screen_sync(), "a PTY session on this host is synced");
        let mut term = LocalTerminal::new();
        pump_until(&mut stream, &mut term, "the first prompt", |t| {
            t.shows_bare_prompt()
        });
        stream.write(say("SYNC")).unwrap();
        pump_until(&mut stream, &mut term, "the echo", |t| {
            t.shows(&said("SYNC"))
        });

        // A local resize repaints at the new size; the host follows.
        stream.resize(100, 30).unwrap();
        stream.write(say("AGAIN")).unwrap();
        pump_until(&mut stream, &mut term, "output after a resize", |t| {
            t.shows(&said("AGAIN"))
        });

        // Leaving the session restores the modes the program had set.
        stream.write(format!("exit{ENTER}").into_bytes()).unwrap();
        let reset = stream.screen_reset();
        stream.close();
        let _ = reset; // Empty for a plain shell; the renderer unit tests cover non-empty resets.
    });
}

/// A command that prints `HL1` .. `HL<n>`, one per line.
fn count_lines(n: u32) -> String {
    #[cfg(unix)]
    let cmd = format!("i=1; while [ $i -le {n} ]; do echo HL$i; i=$((i+1)); done{ENTER}");
    #[cfg(windows)]
    let cmd = format!("for /l %i in (1,1,{n}) do @echo HL%i{ENTER}");
    cmd
}

/// The numbers `HL<n>` found as whole rows in `rows`, in order.
fn hl_numbers<'a>(rows: impl IntoIterator<Item = &'a str>) -> Vec<u32> {
    rows.into_iter()
        .filter_map(|r| r.trim().strip_prefix("HL")?.parse().ok())
        .collect()
}

/// Drop SGR sequences from a scrollback line.
fn plain_line(line: &str) -> String {
    let mut out = String::new();
    let mut it = line.chars();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            for d in it.by_ref() {
                if d == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn rows_that_scroll_off_reach_the_local_scrollback_in_order() {
    let fleet = Fleet::start();
    let ops = ops_for(&fleet.client);
    with_deadline("history reaches the scrollback", move || {
        const N: u32 = 120;
        let (_ref, mut stream) = open_and_attach(&ops, ScreenSync::Auto).expect("open and attach");
        assert!(stream.screen_sync());
        let mut term = LocalTerminal::new();
        pump_until(&mut stream, &mut term, "the first prompt", |t| {
            t.shows_bare_prompt()
        });
        stream.write(count_lines(N).into_bytes()).unwrap();
        // The last line is on the screen once the loop is done and the
        // history that went with it has been drawn above it.
        let mut history: Vec<String> = Vec::new();
        pump_until(&mut stream, &mut term, "the last line", |t| {
            t.shows(&format!("HL{N}")) && t.shows_bare_prompt()
        });
        // History follows the screen on the stream; let it finish.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            history.extend(
                term.screen
                    .take_history()
                    .lines
                    .iter()
                    .map(|l| plain_line(l)),
            );
            let on_screen = hl_numbers(term.rows().iter().map(String::as_str));
            let mut all = hl_numbers(history.iter().map(String::as_str));
            all.extend(on_screen);
            if all.len() as u32 >= N || Instant::now() > deadline {
                break;
            }
            let Some(event) = stream.next_event() else {
                break;
            };
            if let Some(end) = term.feed(event.expect("attach")) {
                panic!("session ended: {end:?}");
            }
        }
        let mut all = hl_numbers(history.iter().map(String::as_str));
        let in_scrollback = all.len();
        all.extend(hl_numbers(term.rows().iter().map(String::as_str)));
        assert_eq!(
            all,
            (1..=N).collect::<Vec<_>>(),
            "every line, once, in order (scrollback then screen)"
        );
        assert!(in_scrollback > 0, "some lines scrolled into the scrollback");
        assert!(
            !history.iter().any(|l| l.contains("lines skipped")),
            "nothing was behind: {history:?}"
        );
        stream.write(format!("exit{ENTER}").into_bytes()).unwrap();
        stream.close();
    });
}

#[test]
fn off_keeps_the_byte_path() {
    let fleet = Fleet::start();
    let ops = ops_for(&fleet.client);
    with_deadline("byte-path attach", move || {
        let (_ref, mut stream) = open_and_attach(&ops, ScreenSync::Off).expect("open and attach");
        assert!(!stream.screen_sync());
        assert!(stream.screen_reset().is_empty());
        let mut term = LocalTerminal::new();
        stream.write(say("BYTES")).unwrap();
        pump_until(&mut stream, &mut term, "the echo", |t| {
            t.shows(&said("BYTES"))
        });
        stream.close();
    });
}

#[test]
fn a_session_opened_without_screen_sync_attaches_on_the_byte_path_under_auto() {
    let fleet = Fleet::start();
    let ops = ops_for(&fleet.client);
    with_deadline("fallback attach", move || {
        // Opened the way `qsh session open` opens: no screen request, so the
        // host runs no emulator for it.
        let opened = ops.session_open(open_req()).expect("open");
        let mut stream = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref.clone(),
                    no_steal: false,
                },
                &[],
                screen_attach(ScreenSync::Auto),
            )
            .expect("auto falls back to the byte path");
        assert!(!stream.screen_sync());
        let mut term = LocalTerminal::new();
        stream.write(say("FALLBACK")).unwrap();
        pump_until(&mut stream, &mut term, "the echo", |t| {
            t.shows(&said("FALLBACK"))
        });
        stream.close();

        // `on` cannot be honoured and says why.
        let err = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref,
                    no_steal: false,
                },
                &[],
                screen_attach(ScreenSync::On),
            )
            .err()
            .expect("on is refused");
        assert_eq!(err.code, ErrorCode::Unsupported);
        assert_eq!(err.details["reason"], "screen_sync_unsupported");
    });
}

// ---------------------------------------------------------------------
// ctrl_c_reaches_a_flooding_session_within_budget
// ---------------------------------------------------------------------

/// One-way delay of the chaos path: 150 ms round trip (ADR-0052 decision 18
/// item 2).
const ONE_WAY: Duration = Duration::from_millis(75);
/// The budget decision 18 item 2 sets.
const CTRL_C_BUDGET: Duration = Duration::from_secs(1);
/// How long the byte path is given before its number is recorded as "over".
const BYTE_PATH_CAP: Duration = Duration::from_secs(40);

#[cfg(unix)]
const FLOOD: &str = "yes";
#[cfg(windows)]
const FLOOD: &str = "for /l %i in (1,0,2) do @echo y";

fn slow_enabled() -> bool {
    std::env::var_os("QSH_ACCEPTANCE_SLOW")
        .or_else(|| std::env::var_os("QSH_ACCEPTANCE_STRICT"))
        .is_some_and(|v| !v.is_empty() && v != "0")
}

/// Run a flood in a shell behind 150 ms and 3% loss, send Ctrl-C, and return
/// how long the prompt took to appear on the local terminal, or `None` if it
/// had not within `cap`.
fn ctrl_c_latency(mode: ScreenSync, cap: Duration) -> Option<Duration> {
    let fleet = ProxiedFleet::start(
        ChaosPolicy::seeded(0xC0_FFEE)
            .drop(0.03)
            .delay(DelayDist::fixed(ONE_WAY)),
    );
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    with_deadline("flooding ctrl-c", move || {
        let (_ref, mut stream) =
            open_and_attach(&ops, mode).unwrap_or_else(|e| panic!("open and attach: {e} — {ctx}"));
        assert_eq!(stream.screen_sync(), mode == ScreenSync::On);
        let mut term = LocalTerminal::new();
        pump_until(&mut stream, &mut term, "the first prompt", |t| {
            t.shows_bare_prompt()
        });
        stream
            .write(format!("{FLOOD}{ENTER}").into_bytes())
            .unwrap();
        // The flood is on screen: most rows read `y`.
        pump_until(&mut stream, &mut term, "the flood", |t| {
            t.rows().iter().filter(|r| *r == "y").count() >= 12
        });
        // Let the backlog build, the way a real flood does before a person
        // notices it and reaches for Ctrl-C. Reading continues meanwhile.
        let settle = Instant::now() + Duration::from_secs(2);
        while Instant::now() < settle {
            let event = stream.next_event().expect("event").expect("ok");
            term.feed(event);
        }
        stream.write(vec![0x03]).unwrap();
        let sent = Instant::now();
        let mut latency = None;
        while let Some(event) = stream.next_event() {
            let event = event.unwrap_or_else(|e| panic!("attach failed: {e} — {ctx}"));
            if term.feed(event).is_some() {
                break;
            }
            if term.shows_bare_prompt() {
                latency = Some(sent.elapsed());
                break;
            }
            if sent.elapsed() > cap {
                break;
            }
        }
        stream.close();
        latency
    })
}

/// ADR-0052 decision 18 item 2: with 150 ms round trip and 3% loss, a `yes`
/// flood is interrupted and the prompt is on the client's screen within one
/// second. The byte path's value in the same scenario is recorded beside it.
#[test]
fn ctrl_c_reaches_a_flooding_session_within_budget() {
    if !slow_enabled() {
        eprintln!(
            "SKIP: the ctrl_c_reaches_a_flooding_session_within_budget gate requires QSH_ACCEPTANCE_SLOW=1"
        );
        return;
    }
    let synced = ctrl_c_latency(ScreenSync::On, Duration::from_secs(20));
    let bytes = ctrl_c_latency(ScreenSync::Off, BYTE_PATH_CAP);
    eprintln!(
        "ctrl-c latency under a flood (RTT 150 ms, loss 3%): screen sync {synced:?}, byte path {}",
        bytes.map_or_else(|| format!("over {BYTE_PATH_CAP:?}"), |d| format!("{d:?}"))
    );
    let synced = synced.expect("the prompt reached the client's screen");
    assert!(
        synced <= CTRL_C_BUDGET,
        "Ctrl-C took {synced:?} to show the prompt under a flood; budget {CTRL_C_BUDGET:?}"
    );
}

// ---------------------------------------------------------------------
// a_predicted_keystroke_is_drawn_before_the_echo_arrives
// ---------------------------------------------------------------------

/// Behind 300 ms of round trip, the second character typed at a shell
/// prompt is on the local terminal long before the host could have echoed
/// it (ADR-0053 decision 16, item 1; the first character of an epoch is
/// judged, not drawn). `predict=never` is the control.
fn second_key_latency(predict: Predict) -> Duration {
    let fleet = ProxiedFleet::start(
        ChaosPolicy::seeded(0xFEED).delay(DelayDist::fixed(Duration::from_millis(150))),
    );
    let ctx = fleet.context();
    let ops = fleet.ops(RecoveryConfig::default());
    with_deadline("predicted keystroke", move || {
        let screen = Some(ScreenAttach {
            mode: ScreenSync::On,
            cols: COLS,
            rows: ROWS,
            predict,
            status_line: Default::default(),
        });
        let opened = ops
            .session_open_interactive(open_req(), false, screen)
            .unwrap_or_else(|e| panic!("open: {e} — {ctx}"));
        let mut stream = ops
            .session_attach_screen(
                SessionAttachReq {
                    session_ref: opened.session_ref,
                    no_steal: false,
                },
                &[],
                screen,
            )
            .unwrap_or_else(|e| panic!("attach: {e} — {ctx}"));
        let mut term = LocalTerminal::new();
        pump_until(&mut stream, &mut term, "the first prompt", |t| {
            t.shows_bare_prompt()
        });
        // The policy samples once a second; give it two so it has seen the
        // round trip.
        // (An idle shell sends no events, so there is nothing to drain.)
        std::thread::sleep(Duration::from_millis(2500));
        stream.write(b"q".to_vec()).unwrap();
        pump_until(&mut stream, &mut term, "the first key", |t| t.shows("q"));
        stream.write(b"z".to_vec()).unwrap();
        let sent = Instant::now();
        pump_until(&mut stream, &mut term, "the second key", |t| t.shows("qz"));
        let latency = sent.elapsed();
        stream.close();
        latency
    })
}

#[test]
fn a_predicted_keystroke_is_drawn_before_the_echo_arrives() {
    if !slow_enabled() {
        eprintln!("skipped: needs QSH_ACCEPTANCE_SLOW");
        return;
    }
    let predicted = second_key_latency(Predict::Auto);
    let plain = second_key_latency(Predict::Never);
    eprintln!("second key: predicted {predicted:?}, never {plain:?}");
    assert!(plain >= Duration::from_millis(250), "control: {plain:?}");
    assert!(
        predicted <= Duration::from_millis(100),
        "predicted: {predicted:?}"
    );
}
