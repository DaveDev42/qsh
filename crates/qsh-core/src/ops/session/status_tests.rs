//! The connection status line on the attach driver's sink, checked against a
//! model of the local terminal (a second [`HostScreen`] fed the drawn bytes)
//! with the clock walked by hand (ADR-0053 decisions 7, 9 and 10;
//! `docs/design/testing.md` L2).

use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_proto::screen::{Row, cell_flags};

use super::screen_sink::{Predict, ScreenSink, StatusInit, WriterTrack};
use crate::adapt::Prediction;
use crate::client::linkstatus::LinkTracker;
use crate::client::predict_drive::PredictDriver;
use crate::screen::{HostScreen, ScreenOptions};

const COLS: u16 = 100;
const ROWS: u16 = 5;
const GUIDE: &str = "; ~. to quit, ~d to detach";

fn term(cols: u16) -> HostScreen {
    HostScreen::new(ScreenOptions {
        rows: ROWS,
        cols,
        ..ScreenOptions::default()
    })
}

struct Rig {
    sink: ScreenSink,
    link: Arc<LinkTracker>,
    host: HostScreen,
    local: HostScreen,
    t0: Instant,
    state: u64,
    /// Every non-empty draw, in order.
    drawn: Vec<Vec<u8>>,
}

impl Rig {
    fn new(status: bool, predict: Option<Predict>) -> Self {
        Self::with_cols(status, predict, COLS)
    }

    fn with_cols(status: bool, predict: Option<Predict>, cols: u16) -> Self {
        let t0 = Instant::now();
        let link = Arc::new(LinkTracker::new(t0));
        let driver = predict.and_then(|m| PredictDriver::new(m, true, false));
        let sink = ScreenSink::new(
            cols,
            ROWS,
            driver,
            status.then(|| StatusInit {
                link: link.clone(),
                escape: Some(b'~'),
            }),
        );
        sink.set_writer(true);
        let mut r = Self {
            sink,
            link,
            host: term(cols),
            local: term(cols),
            t0,
            state: 0,
            drawn: Vec::new(),
        };
        r.host_output(b"$ ls\r\nfile-a\r\nfile-b\r\n$ ");
        r
    }

    fn at(&self, ms: u64) -> Instant {
        self.t0 + Duration::from_millis(ms)
    }

    fn paint(&mut self, out: (Vec<u8>, u64)) {
        self.local.feed(&out.0, 0);
        if !out.0.is_empty() {
            self.drawn.push(out.0);
        }
    }

    fn host_output(&mut self, bytes: &[u8]) {
        self.host.feed(bytes, 0);
        self.state += 1;
        let state = self.host.snapshot();
        let out = self.sink.draw(&state, &[], 0, self.state, self.t0);
        self.paint(out);
    }

    fn tick(&mut self, ms: u64) -> usize {
        let before = self.drawn.len();
        let out = self.sink.tick(self.at(ms));
        self.paint(out);
        self.drawn.len() - before
    }

    fn row(&self, r: usize) -> String {
        text(&self.local.snapshot().grid[r])
    }

    fn inverse(&self, r: usize, col: usize) -> bool {
        self.local.snapshot().grid[r].cells[col].flags & cell_flags::INVERSE != 0
    }

    /// The local terminal shows exactly what the host shows.
    fn assert_local_is_host(&self) {
        let (l, h) = (self.local.snapshot(), self.host.snapshot());
        assert_eq!(
            (l.cursor_row, l.cursor_col),
            (h.cursor_row, h.cursor_col),
            "cursor"
        );
        for (r, (a, b)) in l.grid.iter().zip(&h.grid).enumerate() {
            assert_eq!(text(a), text(b), "row {r}");
            assert!(
                a.cells.iter().all(|c| c.flags & cell_flags::INVERSE == 0),
                "row {r} still has reverse video"
            );
        }
    }
}

fn text(row: &Row) -> String {
    row.cells
        .iter()
        .filter(|c| c.flags & cell_flags::WIDE_CONT == 0)
        .map(|c| if c.text.is_empty() { " " } else { &*c.text })
        .collect::<String>()
        .trim_end()
        .to_owned()
}

#[test]
fn the_line_appears_on_the_top_row_at_two_seconds_of_unanswered_wait() {
    let mut r = Rig::new(true, None);
    r.assert_local_is_host();
    r.link.sent(r.at(100));
    assert_eq!(r.tick(2099), 0, "one millisecond short of 2 s");
    assert!(r.sink.status_text().is_none());
    assert_eq!(r.tick(2100), 1);
    assert_eq!(
        r.row(0),
        format!("qsh: last reply 2s ago{GUIDE}"),
        "top row"
    );
    // Reverse video across the whole width, not only under the text.
    assert!(r.inverse(0, 0) && r.inverse(0, usize::from(COLS) - 1));
    // The rows below are the host's.
    assert_eq!(r.row(1), "file-a");
}

#[test]
fn the_line_is_drawn_again_each_second_and_only_that_row_is_written() {
    let mut r = Rig::new(true, None);
    r.link.sent(r.at(0));
    r.tick(2000);
    assert!(r.row(0).starts_with("qsh: last reply 2s ago"));
    // Between whole seconds nothing changes.
    assert_eq!(r.tick(2999), 0);
    assert_eq!(r.tick(3000), 1);
    assert!(r.row(0).starts_with("qsh: last reply 3s ago"));
    let bytes = r.drawn.last().unwrap();
    let s = String::from_utf8_lossy(bytes);
    assert!(
        !s.contains("file-a") && !s.contains("$ ls"),
        "the host rows are not rewritten: {s:?}"
    );
    r.tick(7000);
    assert!(r.row(0).starts_with("qsh: last reply 7s ago"));
}

#[test]
fn the_threshold_follows_four_times_the_round_trip() {
    let mut r = Rig::new(true, None);
    r.sink.set_srtt(Some(Duration::from_millis(900)));
    r.link.sent(r.at(0));
    assert_eq!(r.tick(3599), 0);
    assert_eq!(r.tick(3600), 1);
    // A fast path keeps the 2 s floor.
    let mut fast = Rig::new(true, None);
    fast.sink.set_srtt(Some(Duration::from_millis(20)));
    fast.link.sent(fast.at(0));
    assert_eq!(fast.tick(1999), 0);
    assert_eq!(fast.tick(2000), 1);
}

#[test]
fn recovery_names_the_attempt_and_shows_without_waiting_for_the_threshold() {
    let mut r = Rig::new(true, None);
    r.link.set_recovering(Some(1));
    assert_eq!(r.tick(900), 1);
    assert_eq!(
        r.row(0),
        format!("qsh: last reply 0s ago, reconnecting (attempt 1){GUIDE}")
    );
    r.link.set_recovering(Some(2));
    r.tick(4500);
    assert_eq!(
        r.row(0),
        format!("qsh: last reply 4s ago, reconnecting (attempt 2){GUIDE}")
    );
}

#[test]
fn the_first_authenticated_reply_clears_the_line_without_a_clear() {
    let mut r = Rig::new(true, None);
    r.link.sent(r.at(0));
    r.tick(2500);
    assert!(r.sink.status_text().is_some());
    r.link.reply(r.at(2600));
    assert_eq!(r.tick(2600), 1);
    assert!(r.sink.status_text().is_none());
    // Row 0 is the host's row again, byte for byte, with no clear.
    r.assert_local_is_host();
    let s = String::from_utf8_lossy(r.drawn.last().unwrap()).into_owned();
    assert!(
        !s.contains("\x1b[2J") && !s.contains("\x1b[J") && !s.contains("\x1b[H\x1b[0J"),
        "no full clear: {s:?}"
    );
    assert!(s.contains("$ ls"), "row 0 is rewritten from the host state");
}

#[test]
fn an_idle_attach_never_shows_the_line_however_old_the_last_reply() {
    let mut r = Rig::new(true, None);
    assert_eq!(r.tick(5000), 0);
    assert_eq!(r.tick(60_000), 0);
    assert!(r.sink.status_text().is_none());
}

#[test]
fn status_line_off_draws_nothing_while_the_link_is_still_tracked() {
    let mut r = Rig::new(false, None);
    r.link.sent(r.at(0));
    r.link.set_recovering(Some(3));
    assert_eq!(r.tick(10_000), 0);
    r.assert_local_is_host();
    let snap = r.link.snapshot();
    assert_eq!(snap.recovering, Some(3));
    assert_eq!(snap.waiting_since, Some(r.at(0)));
}

#[test]
fn the_line_moves_to_the_bottom_row_when_the_cursor_is_on_the_top_one() {
    let mut r = Rig::new(true, None);
    // Clear and home: the prompt is on row 0.
    r.host_output(b"\x1b[2J\x1b[H$ ");
    r.link.set_recovering(Some(1));
    r.tick(0);
    assert_eq!(r.row(0), "$");
    assert!(r.row(usize::from(ROWS) - 1).starts_with("qsh: last reply"));
    assert!(r.inverse(usize::from(ROWS) - 1, 0));
}

#[test]
fn a_window_narrower_than_twenty_columns_gets_no_line() {
    let mut r = Rig::with_cols(true, None, 19);
    r.link.set_recovering(Some(1));
    r.tick(0);
    assert_eq!(r.row(0).chars().take(3).collect::<String>(), "$ l");
    let mut r = Rig::with_cols(true, None, 20);
    r.link.set_recovering(Some(1));
    r.tick(0);
    assert!(r.row(0).starts_with("qsh: last reply 0s"));
    assert!(r.row(0).chars().count() <= 20);
}

#[test]
fn the_text_is_cut_at_the_window_edge() {
    let mut r = Rig::with_cols(true, None, 30);
    r.link.set_recovering(Some(12));
    r.tick(0);
    assert_eq!(r.row(0), "qsh: last reply 0s ago, reconn");
}

#[test]
fn a_new_leg_repaints_row_zero_from_the_host_when_the_line_goes() {
    let mut r = Rig::new(true, None);
    r.link.set_recovering(Some(1));
    r.tick(3000);
    assert!(r.sink.status_text().is_some());
    // The recovery ends; the new leg's first frame is a full screen and
    // the first authenticated inbound comes with it.
    r.link.set_recovering(None);
    r.sink.new_leg(true);
    r.link.reply(r.at(3100));
    r.host_output(b"");
    r.assert_local_is_host();
}

#[test]
fn predictions_are_underlined_while_the_line_shows() {
    let mut r = Rig::new(true, Some(Predict::Always));
    r.sink.set_policy(Prediction::Display);
    // Confirm one epoch so predictions are drawn at all.
    let mut sent = 1u64;
    let out = r.sink.input(b"a", sent, r.at(10));
    r.paint(out);
    r.host_output(b"a");
    let echo = qsh_proto::wire::ScreenEcho {
        state_num: r.state,
        input_seq: sent,
        tty: qsh_proto::wire::TtyEcho::App as i32,
    };
    let out = r.sink.echo(&echo, r.at(50));
    r.paint(out);

    // Healthy: a prediction is drawn plain.
    sent += 1;
    let out = r.sink.input(b"b", sent, r.at(60));
    r.paint(out);
    let col = usize::from(r.host.snapshot().cursor_col);
    let plain = r.local.snapshot().grid[3].cells[col].flags & cell_flags::UNDERLINE;
    assert_eq!(plain, 0, "no underline while the link is fine");

    // The line comes up; the same pending prediction is underlined.
    r.link.set_recovering(Some(1));
    r.tick(100);
    assert!(r.sink.status_text().is_some());
    let underlined = r.local.snapshot().grid[3].cells[col].flags & cell_flags::UNDERLINE;
    assert_ne!(underlined, 0, "underlined while the line shows");

    // And it goes plain again when the line goes.
    r.link.set_recovering(None);
    r.link.reply(r.at(120));
    r.tick(120);
    let plain = r.local.snapshot().grid[3].cells[col].flags & cell_flags::UNDERLINE;
    assert_eq!(plain, 0);
}

#[test]
fn a_lost_writer_lease_withdraws_predictions_and_draws_no_new_ones() {
    let mut r = Rig::new(false, Some(Predict::Always));
    r.sink.set_policy(Prediction::Display);
    let mut sent = 1u64;
    let out = r.sink.input(b"a", sent, r.at(10));
    r.paint(out);
    r.host_output(b"a");
    let echo = qsh_proto::wire::ScreenEcho {
        state_num: r.state,
        input_seq: sent,
        tty: qsh_proto::wire::TtyEcho::App as i32,
    };
    let out = r.sink.echo(&echo, r.at(50));
    r.paint(out);
    sent += 1;
    let out = r.sink.input(b"b", sent, r.at(60));
    r.paint(out);
    assert!(r.row(3).contains("$ ab"), "drawn: {:?}", r.row(3));

    // The host announces the lease holder at attach: that is us.
    let out = r.sink.writer_changed(Some("device:me"), r.at(65));
    r.paint(out);
    assert!(r.row(3).contains("$ ab"), "still drawn: {:?}", r.row(3));
    // Somebody else took the lease: the pending prediction goes and no new
    // one is drawn.
    let out = r.sink.writer_changed(Some("device:other"), r.at(70));
    r.paint(out);
    assert_eq!(r.row(3), "$ a");
    sent += 1;
    let out = r.sink.input(b"c", sent, r.at(80));
    r.paint(out);
    assert_eq!(r.row(3), "$ a");
    // A release is nobody's.
    let out = r.sink.writer_changed(None, r.at(90));
    r.paint(out);
    sent += 1;
    let out = r.sink.input(b"d", sent, r.at(100));
    r.paint(out);
    assert_eq!(r.row(3), "$ a");
}

#[test]
fn the_writer_track_learns_its_own_name_from_the_first_announcement() {
    let mut w = WriterTrack::default();
    w.attached(true);
    // The host announces the holder at attach: us.
    assert!(w.changed(Some("device:me")));
    // Somebody else took the lease.
    assert!(!w.changed(Some("device:other")));
    assert!(!w.changed(Some("device:other")));
    // And we took it back.
    assert!(w.changed(Some("device:me")));
    // Released: nobody holds it.
    assert!(!w.changed(None));
    assert!(w.changed(Some("device:me")));
    // A resumed leg answers for itself and keeps the name.
    w.attached(false);
    assert!(!w.changed(Some("device:other")));
    w.attached(true);
    assert!(w.changed(Some("device:me")));
}

#[test]
fn a_reader_never_becomes_the_writer_from_events_alone() {
    let mut w = WriterTrack::default();
    w.attached(false);
    assert!(!w.changed(Some("device:a")));
    assert!(!w.changed(Some("device:b")));
    assert!(!w.changed(None));
}

#[test]
fn a_new_leg_takes_the_lease_answer_of_its_attach() {
    let mut r = Rig::new(false, Some(Predict::Always));
    let _ = r.sink.writer_changed(Some("device:other"), r.at(10));
    // The resumed attach got the lease back (it asked for read-write).
    r.sink.new_leg(true);
    r.sink.set_policy(Prediction::Display);
    let out = r.sink.input(b"a", 1, r.at(20));
    r.paint(out);
    r.host_output(b"a");
    let echo = qsh_proto::wire::ScreenEcho {
        state_num: r.state,
        input_seq: 1,
        tty: qsh_proto::wire::TtyEcho::App as i32,
    };
    let out = r.sink.echo(&echo, r.at(60));
    r.paint(out);
    let out = r.sink.input(b"b", 2, r.at(70));
    r.paint(out);
    assert!(r.row(3).contains("$ ab"), "drawn: {:?}", r.row(3));
}

/// Frames made by different tasks (input pump, reader, recovery ticker) must
/// reach the frontend in the order the renderer made them: each is a diff
/// against the one before. The draw closure stalls right after it takes its
/// number, so a task that computed first is easily overtaken at the queue
/// unless computing and queueing are one step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_from_different_tasks_reach_the_frontend_in_the_order_they_were_made() {
    use std::sync::atomic::{AtomicU64, Ordering};

    use qsh_proto::event::SessionEvent;

    const TASKS: u64 = 4;
    const FRAMES: u64 = 150;

    let sink = Arc::new(ScreenSink::new(COLS, ROWS, None, None));
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let made = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for _ in 0..TASKS {
        let (sink, tx, made) = (sink.clone(), tx.clone(), made.clone());
        tasks.push(tokio::spawn(async move {
            for _ in 0..FRAMES {
                let sent = sink
                    .emit(&tx, "host/session", None, |_| {
                        let n = made.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_micros(200));
                        (vec![b'x'], n)
                    })
                    .await;
                assert!(sent, "the frontend is still there");
            }
        }));
    }
    drop(tx);
    let mut seen = Vec::new();
    while let Some(event) = rx.recv().await {
        let Ok(SessionEvent::Output { sequence, .. }) = event else {
            panic!("only screen output is emitted");
        };
        seen.push(sequence);
        if seen.len() % 7 == 0 {
            tokio::time::sleep(Duration::from_micros(300)).await;
        }
    }
    for task in tasks {
        task.await.expect("emitter");
    }
    let first_out_of_order = seen.iter().zip(0..).position(|(got, want)| *got != want);
    assert_eq!(
        (seen.len() as u64, first_out_of_order),
        (TASKS * FRAMES, None),
        "a frame overtook one made before it"
    );
}
