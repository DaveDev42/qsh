//! The attach driver's sink with local echo prediction, checked against a
//! model of the local terminal (a second [`HostScreen`] fed the drawn bytes),
//! with the clock walked by hand (ADR-0053 decisions 2, 6, 7 and 8;
//! `docs/design/testing.md` L2).

use std::time::{Duration, Instant};

use qsh_proto::screen::{ScreenState, cell_flags};
use qsh_proto::wire;

use super::screen_sink::{Predict, ScreenSink};
use crate::adapt::Prediction;
use crate::client::predict_drive::PredictDriver;
use crate::screen::{HostScreen, ScreenOptions};

const COLS: u16 = 40;
const ROWS: u16 = 5;

fn term() -> HostScreen {
    HostScreen::new(ScreenOptions {
        rows: ROWS,
        cols: COLS,
        ..ScreenOptions::default()
    })
}

struct Rig {
    sink: ScreenSink,
    /// What the host shows.
    host: HostScreen,
    /// What the user's terminal shows.
    local: HostScreen,
    t: Instant,
    state: u64,
    sent: u64,
    drawn: Vec<Vec<u8>>,
}

impl Rig {
    fn new(mode: Predict, capable: bool) -> Self {
        let mut r = Self {
            sink: ScreenSink::new(COLS, ROWS, PredictDriver::new(mode, capable, false), None),
            host: term(),
            local: term(),
            t: Instant::now(),
            state: 0,
            sent: 0,
            drawn: Vec::new(),
        };
        r.sink.set_policy(Prediction::Display);
        r.host_output(b"$ ");
        r
    }

    fn adv(&mut self, ms: u64) {
        self.t += Duration::from_millis(ms);
    }

    fn paint(&mut self, out: (Vec<u8>, u64)) {
        self.local.feed(&out.0, 0);
        if !out.0.is_empty() {
            self.drawn.push(out.0);
        }
    }

    /// The host program wrote `bytes`; the client applies the new state.
    fn host_output(&mut self, bytes: &[u8]) {
        self.host.feed(bytes, 0);
        self.state += 1;
        let state = self.host.snapshot();
        let out = self.sink.draw(&state, &[], 0, self.state, self.t);
        self.paint(out);
    }

    fn type_keys(&mut self, bytes: &[u8]) {
        self.sent += bytes.len() as u64;
        let out = self.sink.input(bytes, self.sent, self.t);
        self.paint(out);
    }

    fn echo(&mut self, state_num: u64) {
        let echo = wire::ScreenEcho {
            state_num,
            input_seq: self.sent,
            tty: wire::TtyEcho::App as i32,
        };
        let out = self.sink.echo(&echo, self.t);
        self.paint(out);
    }

    fn tick(&mut self) {
        let out = self.sink.tick(self.t);
        self.paint(out);
    }

    fn local_row(&self) -> String {
        row_text(&self.local.snapshot())
    }

    fn local_cell_flags(&self, col: usize) -> u32 {
        u32::from(self.local.snapshot().grid[0].cells[col].flags)
    }

    /// The local terminal shows what the host shows, cell for cell.
    fn assert_local_is_host(&self) {
        let (l, h) = (self.local.snapshot(), self.host.snapshot());
        assert_eq!(
            (l.cursor_row, l.cursor_col),
            (h.cursor_row, h.cursor_col),
            "cursor"
        );
        for (r, (a, b)) in l.grid.iter().zip(&h.grid).enumerate() {
            let text = |row: &qsh_proto::screen::Row| -> Vec<String> {
                row.cells
                    .iter()
                    .map(|c| {
                        if c.text.is_empty() {
                            " ".into()
                        } else {
                            c.text.to_string()
                        }
                    })
                    .collect()
            };
            assert_eq!(text(a), text(b), "row {r}");
        }
    }

    /// One character typed, answered by the host, so the epoch is drawn.
    fn confirm_the_first_epoch(&mut self) {
        self.type_keys(b"a");
        self.adv(40);
        self.host_output(b"a");
        self.echo(self.state);
    }
}

fn row_text(s: &ScreenState) -> String {
    s.grid[0]
        .cells
        .iter()
        .map(|c| if c.text.is_empty() { " " } else { &*c.text })
        .collect::<String>()
        .trim_end()
        .to_string()
}

#[test]
fn a_typed_character_is_drawn_before_the_host_echo_arrives() {
    let mut r = Rig::new(Predict::Auto, true);
    // The first character after the prompt is in a tentative epoch: judged,
    // not drawn.
    r.type_keys(b"a");
    assert_eq!(r.local_row(), "$");
    r.adv(300);
    r.host_output(b"a");
    r.echo(r.state);
    assert_eq!(r.local_row(), "$ a");
    // From here the epoch is drawn: the next key shows before the host has
    // said anything.
    r.type_keys(b"b");
    assert_eq!(r.local_row(), "$ ab", "drawn ahead of the host");
    assert_eq!(row_text(&r.host.snapshot()), "$ a");
    // The host catches up and the picture is the host's.
    r.adv(300);
    r.host_output(b"b");
    r.echo(r.state);
    r.assert_local_is_host();
    assert_eq!(r.local_row(), "$ ab");
}

#[test]
fn a_mispredicted_character_is_rolled_back_to_the_host_cells() {
    let mut r = Rig::new(Predict::Auto, true);
    r.confirm_the_first_epoch();
    r.type_keys(b"c");
    assert_eq!(r.local_row(), "$ ac");
    // The program echoes a different character (a password mask).
    r.adv(40);
    r.host_output(b"*");
    // The state alone is not a verdict: the host may not have reacted to
    // the key yet. The prediction stays until the reflection point covers it.
    assert_eq!(r.local_row(), "$ ac");
    r.echo(r.state);
    assert_eq!(
        r.local_row(),
        "$ a*",
        "rolled back at the first draw after the verdict"
    );
    r.assert_local_is_host();
}

#[test]
fn an_echo_for_a_state_not_yet_applied_is_held_and_judged_when_the_state_arrives() {
    let mut r = Rig::new(Predict::Auto, true);
    r.confirm_the_first_epoch();
    r.type_keys(b"c");
    r.adv(40);
    // The reflection point beats the screen update it names.
    r.echo(r.state + 1);
    assert_eq!(r.local_row(), "$ ac", "held, nothing judged");
    r.host_output(b"*");
    assert_eq!(r.local_row(), "$ a*");
    r.assert_local_is_host();
}

#[test]
fn a_late_confirmation_underlines_the_prediction_after_250_ms() {
    let mut r = Rig::new(Predict::Auto, true);
    r.confirm_the_first_epoch();
    r.type_keys(b"b");
    assert_eq!(r.local_row(), "$ ab");
    assert_eq!(r.local_cell_flags(3) & u32::from(cell_flags::UNDERLINE), 0);
    r.adv(200);
    r.tick();
    assert_eq!(r.local_cell_flags(3) & u32::from(cell_flags::UNDERLINE), 0);
    r.adv(60);
    r.tick();
    assert_ne!(
        r.local_cell_flags(3) & u32::from(cell_flags::UNDERLINE),
        0,
        "late: underlined"
    );
    // The host finally answers: the underline goes with the prediction.
    r.host_output(b"b");
    r.echo(r.state);
    assert_eq!(r.local_cell_flags(3) & u32::from(cell_flags::UNDERLINE), 0);
    r.assert_local_is_host();
}

#[test]
fn a_peer_without_screen_echo_is_never_predicted_against() {
    let mut r = Rig::new(Predict::Always, false);
    r.type_keys(b"a");
    r.adv(40);
    r.host_output(b"a");
    r.type_keys(b"b");
    assert_eq!(r.local_row(), "$ a", "nothing ahead of the host");
    assert!(r.drawn.iter().all(|d| !d.windows(1).any(|w| w == b"b")));
    r.host_output(b"b");
    r.assert_local_is_host();
}

#[test]
fn predict_never_draws_nothing_ahead_of_the_host() {
    // `Never` builds no driver at all.
    let mut r = Rig::new(Predict::Never, true);
    r.type_keys(b"a");
    r.adv(40);
    r.host_output(b"a");
    r.type_keys(b"b");
    assert_eq!(r.local_row(), "$ a");
}

#[test]
fn policy_off_draws_nothing_and_a_policy_change_is_drawn_on_the_next_tick() {
    let mut r = Rig::new(Predict::Auto, true);
    r.confirm_the_first_epoch();
    r.sink.set_policy(Prediction::Off);
    r.tick();
    r.type_keys(b"b");
    assert_eq!(r.local_row(), "$ a", "off on a fast path");
    r.sink.set_policy(Prediction::Display);
    r.tick();
    assert_eq!(r.local_row(), "$ ab", "turned on when the path got slow");
}

#[test]
fn an_empty_overlay_leaves_the_bytes_of_a_plain_draw() {
    // `Never` and a quiet `Auto` write the same bytes for the same host
    // output (nothing extra for the predictor's presence).
    let mut a = Rig::new(Predict::Never, true);
    let mut b = Rig::new(Predict::Auto, true);
    b.sink.set_policy(Prediction::Off);
    for chunk in [&b"x"[..], b"yz", b"\r\nok"] {
        a.host_output(chunk);
        b.host_output(chunk);
    }
    assert_eq!(a.drawn, b.drawn);
}

#[tokio::test]
async fn the_sink_wakes_for_the_late_confirmation_deadline() {
    let sink = ScreenSink::new(
        COLS,
        ROWS,
        PredictDriver::new(Predict::Always, true, false),
        None,
    );
    let mut host = term();
    host.feed(b"$ ", 0);
    let now = Instant::now();
    sink.draw(&host.snapshot(), &[], 0, 1, now);
    // Nothing waiting: no deadline, the future stays pending.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sink.tick_due())
            .await
            .is_err()
    );
    // A prediction waits for its verdict: the sink wakes once it is late.
    sink.input(b"a", 1, Instant::now());
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(2), sink.tick_due())
        .await
        .expect("woken by the deadline");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(240),
        "woken at the 250 ms deadline, not before: {waited:?}"
    );
    // The tick draws the consequence and the deadline is spent.
    sink.tick(Instant::now());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sink.tick_due())
            .await
            .is_err()
    );
}
