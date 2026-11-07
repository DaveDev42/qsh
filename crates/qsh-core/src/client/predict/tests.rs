use proptest::prelude::*;
use qsh_proto::screen::{Modes, ScreenState};

use super::*;

// ---- helpers ----

fn put(s: &mut ScreenState, row: u16, text: &str) {
    let mut c = 0usize;
    for ch in text.chars() {
        let w = ch.width().unwrap_or(1);
        let cell = &mut s.grid[usize::from(row)].cells[c];
        cell.text = ch.to_string().into();
        if w == 2 {
            cell.flags |= cell_flags::WIDE;
            s.grid[usize::from(row)].cells[c + 1].flags |= cell_flags::WIDE_CONT;
        }
        c += w;
    }
}

fn screen(rows: u16, cols: u16, row0: &str, cursor: (u16, u16)) -> ScreenState {
    let mut s = ScreenState::blank(rows, cols).unwrap();
    put(&mut s, 0, row0);
    s.cursor_row = cursor.0;
    s.cursor_col = cursor.1;
    s
}

fn width(s: &str) -> u16 {
    s.chars().map(|c| c.width().unwrap_or(1) as u16).sum()
}

/// A 3x`cols` screen whose first row is the prompt `$ ` and `typed`, with
/// the cursor after it.
fn line(cols: u16, typed: &str) -> ScreenState {
    screen(3, cols, &format!("$ {typed}"), (0, 2 + width(typed)))
}

struct Rig {
    p: Predictor,
    t: Instant,
    n: u64,
    sent: u64,
}

impl Rig {
    fn new() -> Self {
        Self {
            p: Predictor::new(true),
            t: Instant::now(),
            n: 0,
            sent: 0,
        }
    }
    fn adv(&mut self, ms: u64) {
        self.t += Duration::from_millis(ms);
    }
    fn state(&mut self, s: &ScreenState) {
        self.n += 1;
        self.p.on_state(s, self.n, self.t);
    }
    fn key(&mut self, b: &[u8]) {
        self.sent += b.len() as u64;
        self.p.on_input(b, self.sent, self.t);
    }
    fn echo_to(&mut self, covered: u64, tty: TtyEcho) {
        self.p.on_echo(
            EchoReport {
                state_num: self.n,
                input_seq: covered,
                tty,
            },
            self.t,
        );
    }
    fn echo(&mut self) {
        self.echo_to(self.sent, TtyEcho::App);
    }
    /// Host state plus a report covering everything sent.
    fn settle(&mut self, s: &ScreenState) {
        self.state(s);
        self.echo();
    }
    /// A rig on a prompt whose first typed character `a` was echoed, so the
    /// current epoch is confirmed. Typed text is `a`.
    fn confirmed(policy: Prediction) -> Self {
        let mut r = Self::new();
        r.p.on_policy(policy);
        r.state(&line(40, ""));
        r.key(b"a");
        assert_eq!(r.p.pending_len(), 1);
        assert!(r.p.overlay().is_empty(), "first prediction is tentative");
        r.state(&line(40, "a"));
        assert_eq!(r.p.pending_len(), 0);
        r
    }
}

fn cell_at(o: &Overlay, col: u16) -> Option<&OverlayCell> {
    o.cells.iter().find(|c| c.col == col)
}

// ---- what is predicted ----

#[test]
fn the_first_prediction_is_tentative_and_the_next_is_drawn_once_it_is_confirmed() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"b");
    let o = r.p.overlay();
    assert_eq!(o.cells.len(), 1);
    assert_eq!(&*o.cells[0].cell.text, "b");
    assert_eq!((o.cells[0].row, o.cells[0].col), (0, 3));
    assert_eq!(o.cursor, Some((0, 4)));
    assert_eq!(o.cells[0].cell.flags & cell_flags::UNDERLINE, 0);
}

#[test]
fn policy_and_status_line_decide_the_underline() {
    let table = [
        (Prediction::Off, false, None),
        (Prediction::Display, false, Some(false)),
        (Prediction::Underline, false, Some(true)),
        (Prediction::Display, true, Some(true)),
        (Prediction::Off, true, None),
    ];
    for (policy, status, want) in table {
        let mut r = Rig::confirmed(policy);
        r.p.on_status_line(status);
        r.key(b"b");
        let o = r.p.overlay();
        match want {
            None => assert!(o.is_empty(), "{policy:?} status={status}"),
            Some(u) => assert_eq!(
                o.cells[0].cell.flags & cell_flags::UNDERLINE != 0,
                u,
                "{policy:?} status={status}"
            ),
        }
    }
}

#[test]
fn wide_characters_take_two_cells_and_move_the_cursor_two_columns() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key("가".as_bytes());
    let o = r.p.overlay();
    assert_eq!(o.cells.len(), 2);
    assert_eq!(&*o.cells[0].cell.text, "가");
    assert_ne!(o.cells[0].cell.flags & cell_flags::WIDE, 0);
    assert_ne!(o.cells[1].cell.flags & cell_flags::WIDE_CONT, 0);
    assert_eq!(o.cursor, Some((0, 5)));
    // The host agrees: confirmed and gone.
    r.state(&line(40, "a가"));
    assert_eq!(r.p.pending_len(), 0);
    assert!(r.p.overlay().is_empty());
}

type Shape = Vec<(u16, bool, bool)>;

/// (column, wide lead, wide right half) of every overlay cell.
fn shape(o: &Overlay) -> Shape {
    o.cells
        .iter()
        .map(|c| {
            (
                c.col,
                c.cell.flags & cell_flags::WIDE != 0,
                c.cell.flags & cell_flags::WIDE_CONT != 0,
            )
        })
        .collect()
}

#[test]
fn a_shift_carries_the_right_half_of_a_wide_character_with_its_lead() {
    // (host row, cursor column, key, overlay shape). The wide character
    // that ends the line moves with both halves.
    let table: [(&str, u16, &[u8], Shape); 2] = [
        (
            "$ 가",
            2,
            b"a",
            vec![(2, false, false), (3, true, false), (4, false, true)],
        ),
        (
            "$ a가",
            3,
            &[0x7f],
            vec![(2, true, false), (3, false, true), (4, false, false)],
        ),
    ];
    for (row, col, key, want) in table {
        let mut r = Rig::confirmed(Prediction::Display);
        r.state(&screen(3, 40, row, (0, col)));
        r.key(key);
        assert_eq!(shape(&r.p.overlay()), want, "{row} {key:?}");
    }
}

#[test]
fn a_write_over_half_of_a_predicted_wide_character_blanks_the_other_half() {
    let wide = |flags: u8, text: &str| Cell {
        text: text.into(),
        flags,
        ..Cell::default()
    };
    let narrow = || wide(0, "a");
    // (column the narrow cell lands on, columns blank afterwards)
    let table: [(usize, [bool; 2]); 2] = [(1, [true, false]), (0, [false, true])];
    for (col, blank) in table {
        let mut cells = vec![Cell::default(); 4];
        let mut written = vec![false; 4];
        put_atomic(&mut cells, &mut written, 0, wide(cell_flags::WIDE, "가"));
        put_atomic(&mut cells, &mut written, 1, wide(cell_flags::WIDE_CONT, ""));
        put_atomic(&mut cells, &mut written, col, narrow());
        let flags: Vec<u8> = cells.iter().map(|c| c.flags).collect();
        assert_eq!(cells[col].text.as_ref(), "a", "{flags:?}");
        for (k, b) in blank.iter().enumerate() {
            if *b {
                assert!(cells[k].text.is_empty() && cells[k].flags == 0, "{col} {k}");
            }
        }
        assert!(written[..2].iter().all(|w| *w));
    }
}

#[test]
fn the_row_edge_decides_which_characters_fit() {
    // 10 columns, prompt takes two. (cursor column, input, predicted)
    let table: [(u16, &str, bool); 6] = [
        (7, "가", true),
        (8, "가", false),
        (9, "a", false),
        (8, "a", true),
        (7, "a", true),
        (6, "가", true),
    ];
    for (col, input, want) in table {
        let mut r = Rig::new();
        r.state(&screen(2, 10, "", (0, col)));
        r.key(input.as_bytes());
        assert_eq!(r.p.pending_len() == 1, want, "col {col} {input}");
    }
}

#[test]
fn characters_the_host_may_measure_differently_are_never_predicted() {
    let table = [
        ("ambiguous width", "±"),
        ("combining mark", "\u{301}"),
        ("zero width joiner", "\u{200d}"),
        ("variation selector", "\u{fe0f}"),
        ("invalid utf-8", "\u{0}"),
    ];
    for (name, s) in table {
        let mut r = Rig::new();
        r.state(&line(40, ""));
        let bytes: &[u8] = if name == "invalid utf-8" {
            &[0xff]
        } else {
            s.as_bytes()
        };
        r.key(bytes);
        assert_eq!(r.p.pending_len(), 0, "{name}");
    }
}

#[test]
fn a_character_split_across_reads_is_predicted_once_complete() {
    let mut r = Rig::new();
    r.state(&line(40, ""));
    let b = "가".as_bytes();
    r.key(&b[..2]);
    assert_eq!(r.p.pending_len(), 0);
    r.key(&b[2..]);
    assert_eq!(r.p.pending_len(), 1);
    // Its input offset is the end of the third byte.
    r.state(&line(40, "가"));
    assert_eq!(r.p.pending_len(), 0);
}

#[test]
fn typing_in_the_middle_of_a_line_pushes_the_rest_right() {
    let mut r = Rig::new();
    r.p.on_policy(Prediction::Display);
    r.state(&line(40, "bc"));
    r.key(b"a");
    r.state(&screen(3, 40, "$ abc", (0, 3)));
    // confirmed at col 2; cursor follows the host.
    assert_eq!(r.p.pending_len(), 0);

    let mut r = Rig::confirmed(Prediction::Display);
    // Line is now "$ a" with the cursor after it; move left, then type.
    r.state(&screen(3, 40, "$ ab", (0, 3)));
    r.key(b"\x1b[D");
    assert_eq!(r.p.pending_len(), 1);
    r.key(b"x");
    let o = r.p.overlay();
    assert_eq!(o.cursor, Some((0, 3)));
    let cols: Vec<_> = o.cells.iter().map(|c| (c.col, &*c.cell.text)).collect();
    assert_eq!(cols, [(2, "x"), (3, "a"), (4, "b")].map(|(c, t)| (c, t)));
}

#[test]
fn backspace_and_the_arrow_keys_stay_inside_the_row() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.state(&screen(3, 40, "$ abc", (0, 5)));
    r.key(b"\x7f");
    let o = r.p.overlay();
    assert_eq!(o.cursor, Some((0, 4)));
    assert_eq!(cell_at(&o, 4).map(|c| &*c.cell.text), Some(""));

    // Left, Left (application mode too), then Right is only allowed onto a
    // character.
    let mut r = Rig::confirmed(Prediction::Display);
    r.state(&screen(3, 40, "$ abc", (0, 5)));
    r.key(b"\x1b[D");
    r.key(b"\x1bOD");
    assert_eq!(r.p.overlay().cursor, Some((0, 3)));
    r.key(b"\x1b[C");
    assert_eq!(r.p.overlay().cursor, Some((0, 4)));
    r.key(b"\x1b[C");
    r.key(b"\x1b[C");
    // The third Right would step onto the empty cell after the text.
    assert_eq!(r.p.pending_len(), 4);

    // Nothing to the left of column 0, and an empty cell is not deleted.
    let mut r = Rig::new();
    r.state(&screen(3, 40, "", (0, 0)));
    r.key(b"\x7f");
    r.key(b"\x1b[D");
    assert_eq!(r.p.pending_len(), 0);
}

// ---- epoch breaks ----

#[test]
fn keys_the_predictor_does_not_follow_break_the_epoch() {
    let keys: [(&str, &[u8]); 12] = [
        ("enter", b"\r"),
        ("newline", b"\n"),
        ("tab", b"\t"),
        ("ctrl-c", b"\x03"),
        ("up", b"\x1b[A"),
        ("down", b"\x1b[B"),
        ("home", b"\x1b[H"),
        ("delete", b"\x1b[3~"),
        ("function key", b"\x1bOP"),
        ("alt-x", b"\x1bx"),
        ("lone escape", b"\x1b"),
        ("paste", b"hello world"),
    ];
    for (name, k) in keys {
        let mut r = Rig::confirmed(Prediction::Display);
        r.key(k);
        assert_eq!(r.p.pending_len(), 0, "{name}");
        // The cursor is unknown until the host has applied the key, so the
        // next character is not predicted either.
        r.key(b"x");
        assert_eq!(r.p.pending_len(), 0, "{name}: stale");
        r.settle(&line(40, "a"));
        r.key(b"y");
        assert_eq!(r.p.pending_len(), 1, "{name}: trusted again");
        // And it starts a tentative epoch.
        assert!(r.p.overlay().is_empty(), "{name}: tentative");
    }
}

#[test]
fn a_bracketed_paste_is_never_predicted() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"\x1b[200~ab");
    r.key(b"c\x1b[201~");
    assert_eq!(r.p.pending_len(), 0);
    r.settle(&line(40, "a"));
    r.key(b"z");
    assert_eq!(r.p.pending_len(), 1);
}

#[test]
fn a_tentative_epoch_is_not_drawn_without_a_confirmation() {
    // Enter, then a password the host does not echo.
    let mut r = Rig::confirmed(Prediction::Underline);
    r.key(b"\r");
    r.settle(&screen(3, 40, "Password: ", (0, 10)));
    for (i, ch) in "hunter2".bytes().enumerate() {
        r.key(&[ch]);
        assert!(r.p.overlay().is_empty(), "char {i} drawn");
    }
    assert_eq!(r.p.pending_len(), 7);
    r.state(&screen(3, 40, "Password: ", (0, 10)));
    r.echo();
    assert!(r.p.overlay().is_empty());
    assert_eq!(r.p.pending_len(), 0);
    assert!(r.p.stats().mispredicted >= 1);
}

#[test]
fn an_unpredicted_cursor_move_drops_the_predictions_without_a_count() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"b");
    r.key(b"c");
    assert_eq!(r.p.pending_len(), 2);
    // A new prompt on the next row.
    r.state(&screen(3, 40, "$ a", (1, 2)));
    assert_eq!(r.p.pending_len(), 0);
    assert_eq!(r.p.stats().mispredicted, 0);
    assert!(r.p.overlay().is_empty());
}

// ---- verdicts ----

#[test]
fn a_misprediction_is_rolled_back_within_one_echo() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"x");
    r.key(b"y");
    assert_eq!(r.p.overlay().cells.len(), 2);
    // The program prints stars; the report covers both keys.
    r.state(&line(40, "a**"));
    assert_eq!(r.p.overlay().cells.len(), 2, "no verdict before the report");
    r.echo();
    assert!(r.p.overlay().is_empty());
    assert_eq!(r.p.pending_len(), 0);
    assert_eq!(
        r.p.stats().mispredicted,
        1,
        "the later one is dropped, not counted"
    );
}

#[test]
fn a_report_that_does_not_cover_the_key_gives_no_verdict() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"x");
    r.state(&line(40, "a"));
    r.echo_to(r.sent - 1, TtyEcho::App);
    assert_eq!(r.p.pending_len(), 1);
    assert_eq!(r.p.stats().mispredicted, 0);
    r.echo_to(r.sent, TtyEcho::App);
    assert_eq!(r.p.pending_len(), 0);
}

#[test]
fn a_report_ahead_of_the_applied_state_waits_for_the_state() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"x");
    r.p.on_echo(
        EchoReport {
            state_num: r.n + 1,
            input_seq: r.sent,
            tty: TtyEcho::App,
        },
        r.t,
    );
    assert_eq!(r.p.pending_len(), 1, "state not applied yet");
    r.n += 1;
    r.p.on_state(&line(40, "ax"), r.n, r.t);
    assert_eq!(r.p.pending_len(), 0);
    assert_eq!(r.p.stats().confirmed, 2);
}

#[test]
fn reports_beyond_the_input_sent_or_not_newer_are_dropped_and_counted() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"x");
    r.p.on_echo(
        EchoReport {
            state_num: r.n,
            input_seq: r.sent + 1,
            tty: TtyEcho::Secret,
        },
        r.t,
    );
    assert_eq!(r.p.stats().echo_rejected, 1);
    assert_eq!(r.p.blocked(), None, "a rejected report changes nothing");
    r.echo_to(r.sent, TtyEcho::App);
    r.echo_to(r.sent, TtyEcho::App);
    assert_eq!(r.p.stats().echo_stale, 1);
}

#[test]
fn three_wrong_epochs_suspend_display_until_four_confirmations() {
    let mut r = Rig::confirmed(Prediction::Display);
    let mut typed = String::from("a");
    for k in 0..MISPREDICT_SUSPEND {
        r.key(b"x");
        typed.push('*');
        r.state(&line(40, &typed));
        r.echo();
        assert_eq!(r.p.stats().mispredicted, u64::from(k) + 1);
        assert_eq!(r.p.is_suspended(), k + 1 == MISPREDICT_SUSPEND);
    }
    // Suspended: predictions are still made and judged, never drawn.
    for k in 0..REENABLE_CONFIRMS {
        assert!(r.p.is_suspended(), "confirmation {k}");
        r.key(b"q");
        assert!(r.p.overlay().is_empty());
        typed.push('q');
        r.state(&line(40, &typed));
        r.echo();
    }
    assert!(!r.p.is_suspended());
    r.key(b"w");
    assert_eq!(r.p.overlay().cells.len(), 1, "drawing resumed");
}

#[test]
fn a_confirmation_resets_the_wrong_streak() {
    let mut r = Rig::confirmed(Prediction::Display);
    let mut typed = String::from("a");
    for round in 0..4 {
        r.key(b"x");
        typed.push(if round % 2 == 0 { '*' } else { 'x' });
        r.settle(&line(40, &typed));
    }
    assert!(!r.p.is_suspended());
}

#[test]
fn a_backspace_that_removes_a_just_typed_character_is_not_a_misprediction() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"b");
    r.key(b"\x7f");
    r.settle(&line(40, "a"));
    assert_eq!(r.p.pending_len(), 0);
    assert_eq!(r.p.stats().mispredicted, 0);
}

// ---- gates ----

#[test]
fn prediction_gates() {
    type Setup = fn(&mut Rig);
    let blocked: [(&str, Setup); 6] = [
        ("alternate screen", |r| {
            let mut s = line(40, "a");
            s.modes.flags |= Modes::ALT_SCREEN;
            r.state(&s);
        }),
        ("hidden cursor", |r| {
            let mut s = line(40, "a");
            s.modes.flags |= Modes::CURSOR_HIDDEN;
            r.state(&s);
        }),
        ("mouse mode", |r| {
            let mut s = line(40, "a");
            s.modes.mouse_mode = 2;
            r.state(&s);
        }),
        ("read-only attach", |r| r.p.on_writer(false)),
        ("secret tty", |r| {
            r.state(&line(40, "a"));
            r.echo_to(r.sent, TtyEcho::Secret);
        }),
        ("no screen-echo.v1", |r| r.p = Predictor::new(false)),
    ];
    for (name, setup) in blocked {
        let mut r = Rig::confirmed(Prediction::Display);
        r.key(b"b");
        assert_eq!(r.p.overlay().cells.len(), 1, "{name}: precondition");
        setup(&mut r);
        assert_eq!(r.p.pending_len(), 0, "{name}: pending kept");
        assert!(r.p.overlay().is_empty(), "{name}");
        r.state(&line(40, "a"));
        r.key(b"c");
        assert_eq!(r.p.pending_len(), 0, "{name}: predicted");
        assert!(r.p.overlay().is_empty(), "{name}");
    }

    // Paste-sized read, ambiguous width and last column break the epoch
    // without a prediction (rows above); policy Off predicts but draws
    // nothing.
    let mut r = Rig::confirmed(Prediction::Off);
    r.key(b"b");
    assert_eq!(r.p.pending_len(), 1);
    assert!(r.p.overlay().is_empty());

    // Unblocking: the secret prompt ends and predictions restart as a
    // tentative epoch.
    let mut r = Rig::confirmed(Prediction::Display);
    r.state(&line(40, "a"));
    r.echo_to(r.sent, TtyEcho::Secret);
    assert_eq!(r.p.blocked(), Some(Block::Secret));
    r.state(&line(40, "a"));
    r.echo_to(r.sent, TtyEcho::Kernel);
    assert_eq!(r.p.blocked(), None);
    r.key(b"z");
    assert_eq!(r.p.pending_len(), 1);
    assert!(r.p.overlay().is_empty(), "tentative after the block");
}

#[test]
fn pending_predictions_are_capped_at_256() {
    let mut r = Rig::new();
    r.state(&ScreenState::blank(1, 600).unwrap());
    for _ in 0..300 {
        r.key(b"a");
    }
    assert_eq!(r.p.pending_len(), MAX_PENDING);
}

#[test]
fn a_long_read_is_a_paste() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"abcd");
    assert_eq!(r.p.pending_len(), 4, "four characters are still typing");
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"abcde");
    assert_eq!(r.p.pending_len(), 0);
}

// ---- timing ----

#[test]
fn a_late_confirmation_forces_underline_until_ten_quick_ones() {
    let mut r = Rig::confirmed(Prediction::Display);
    let mut typed = String::from("a");
    r.key(b"x");
    r.adv(300);
    typed.push('x');
    r.state(&line(40, &typed));
    assert!(r.p.is_glitching());
    r.key(b"y");
    let o = r.p.overlay();
    assert_ne!(o.cells[0].cell.flags & cell_flags::UNDERLINE, 0);
    typed.push('y');
    r.state(&line(40, &typed));

    // `y` above was the first quick confirmation.
    for i in 0..GLITCH_REPAIR - 1 {
        assert!(r.p.is_glitching(), "confirmation {i}");
        r.key(b"q");
        r.adv(10);
        typed.push('q');
        r.state(&line(40, &typed));
    }
    assert!(!r.p.is_glitching());
    r.key(b"w");
    assert_eq!(r.p.overlay().cells[0].cell.flags & cell_flags::UNDERLINE, 0);
}

#[test]
fn a_slow_confirmation_restarts_the_repair_count() {
    let mut r = Rig::confirmed(Prediction::Display);
    let mut typed = String::from("a");
    let mut step = |r: &mut Rig, delay: u64| {
        r.key(b"q");
        r.adv(delay);
        typed.push('q');
        r.state(&line(40, &typed));
    };
    step(&mut r, 300);
    for _ in 0..GLITCH_REPAIR - 1 {
        step(&mut r, 10);
    }
    step(&mut r, 100);
    assert!(r.p.is_glitching(), "100 ms is not quick");
    for _ in 0..GLITCH_REPAIR {
        step(&mut r, 10);
    }
    assert!(!r.p.is_glitching());
}

#[test]
fn an_old_unconfirmed_prediction_is_drawn_underlined_even_when_the_policy_is_off() {
    let mut r = Rig::confirmed(Prediction::Off);
    r.key(b"x");
    assert!(r.p.overlay().is_empty());
    r.adv(300);
    r.p.on_tick(r.t);
    let o = r.p.overlay();
    assert_eq!(o.cells.len(), 1);
    assert_ne!(o.cells[0].cell.flags & cell_flags::UNDERLINE, 0);
}

#[test]
fn a_new_leg_keeps_the_predictions_and_judges_them_with_the_new_reports() {
    let mut r = Rig::confirmed(Prediction::Display);
    r.key(b"x");
    r.p.on_leg_change();
    r.state(&line(40, "a"));
    assert_eq!(r.p.pending_len(), 1);
    r.settle(&line(40, "ax"));
    assert_eq!(r.p.pending_len(), 0);
}

// ---- property: everything resolved leaves nothing on screen ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Echo,
    Star,
    Silent,
    Secret,
}

#[derive(Clone, Debug)]
enum Key {
    Char(char),
    Backspace,
    Left,
    Right,
    Enter,
    Paste,
}

impl Key {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Key::Char(c) => c.to_string().into_bytes(),
            Key::Backspace => vec![0x7f],
            Key::Left => b"\x1b[D".to_vec(),
            Key::Right => b"\x1b[C".to_vec(),
            Key::Enter => vec![b'\r'],
            Key::Paste => b"hello world".to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Key(Key),
    Deliver(usize),
}

struct Host {
    mode: Mode,
    line: Vec<char>,
    pos: usize,
}

impl Host {
    fn insert(&mut self, c: char) {
        let c = if self.mode == Mode::Star { '*' } else { c };
        let w: u16 = self
            .line
            .iter()
            .map(|c| c.width().unwrap_or(1) as u16)
            .sum();
        if w + c.width().unwrap_or(1) as u16 <= 20 {
            self.line.insert(self.pos, c);
            self.pos += 1;
        }
    }
    fn apply(&mut self, k: &Key) {
        if matches!(self.mode, Mode::Silent | Mode::Secret) {
            return;
        }
        match k {
            Key::Char(c) => self.insert(*c),
            Key::Backspace => {
                if self.pos > 0 {
                    self.pos -= 1;
                    self.line.remove(self.pos);
                }
            }
            Key::Left => self.pos = self.pos.saturating_sub(1),
            Key::Right => self.pos = (self.pos + 1).min(self.line.len()),
            Key::Enter => {
                self.line.clear();
                self.pos = 0;
            }
            Key::Paste => "hello world".chars().for_each(|c| self.insert(c)),
        }
    }
    fn screen(&self) -> ScreenState {
        let text: String = self.line.iter().collect();
        let before: String = self.line[..self.pos].iter().collect();
        let mut s = ScreenState::blank(3, 30).unwrap();
        put(&mut s, 1, &format!("$ {text}"));
        s.cursor_row = 1;
        s.cursor_col = 2 + width(&before);
        s
    }
    fn tty(&self) -> TtyEcho {
        match self.mode {
            Mode::Echo | Mode::Star => TtyEcho::App,
            Mode::Silent => TtyEcho::Unknown,
            Mode::Secret => TtyEcho::Secret,
        }
    }
}

fn key_strategy() -> impl Strategy<Value = Key> {
    prop_oneof![
        6 => prop::sample::select(vec!['a', 'b', 'Z', ' ', '가', '나', '±', 'é'])
            .prop_map(Key::Char),
        2 => Just(Key::Backspace),
        2 => Just(Key::Left),
        2 => Just(Key::Right),
        1 => Just(Key::Enter),
        1 => Just(Key::Paste),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn overlay_is_empty_and_screen_equals_host_once_every_prediction_resolves(
        mode in prop::sample::select(vec![Mode::Echo, Mode::Star, Mode::Silent, Mode::Secret]),
        ops in prop::collection::vec(
            prop_oneof![
                3 => key_strategy().prop_map(Op::Key),
                2 => (0usize..4).prop_map(Op::Deliver),
            ],
            0..60,
        ),
    ) {
        let mut host = Host { mode, line: Vec::new(), pos: 0 };
        let mut p = Predictor::new(true);
        p.on_policy(Prediction::Underline);
        let mut t = Instant::now();
        let mut n = 1u64;
        p.on_state(&host.screen(), n, t);
        let mut sent = 0u64;
        let mut queue: VecDeque<(Key, u64)> = VecDeque::new();
        let mut done = 0u64;

        let deliver = |p: &mut Predictor, host: &mut Host, queue: &mut VecDeque<(Key, u64)>,
                           done: &mut u64, n: &mut u64, t: Instant, count: usize| {
            for _ in 0..count {
                if let Some((k, end)) = queue.pop_front() {
                    host.apply(&k);
                    *done = end;
                }
            }
            *n += 1;
            let s = host.screen();
            p.on_state(&s, *n, t);
            p.on_echo(EchoReport { state_num: *n, input_seq: *done, tty: host.tty() }, t);
        };

        for op in ops {
            t += Duration::from_millis(3);
            match op {
                Op::Key(k) => {
                    let b = k.bytes();
                    sent += b.len() as u64;
                    p.on_input(&b, sent, t);
                    queue.push_back((k, sent));
                }
                Op::Deliver(c) => deliver(&mut p, &mut host, &mut queue, &mut done, &mut n, t, c),
            }
            let o = p.overlay();
            prop_assert!(p.pending_len() <= MAX_PENDING);
            for c in &o.cells {
                prop_assert!(c.row < 3 && c.col < 30);
            }
            if matches!(mode, Mode::Silent | Mode::Secret) {
                // Nothing the host never echoes is ever drawn.
                prop_assert!(o.is_empty(), "drew {:?}", o);
            }
        }
        t += Duration::from_millis(3);
        let rest = queue.len();
        deliver(&mut p, &mut host, &mut queue, &mut done, &mut n, t, rest);
        prop_assert_eq!(p.pending_len(), 0);
        prop_assert!(p.overlay().is_empty());
    }
}
