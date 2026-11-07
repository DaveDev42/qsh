//! The renderer is checked against a model of the local terminal: the bytes
//! it writes are fed to a second [`HostScreen`], whose snapshot must equal
//! the state that was drawn.

use proptest::prelude::*;
use qsh_proto::screen::{Color, Effect, Modes, ScreenState, cell_flags};

use super::*;
use crate::screen::{HostScreen, ScreenOptions};

fn term(rows: u16, cols: u16) -> HostScreen {
    HostScreen::new(ScreenOptions {
        rows,
        cols,
        ..ScreenOptions::default()
    })
}

fn feed(t: &mut HostScreen, data: &[u8]) {
    t.feed(data, 0);
}

/// Equal in everything the renderer draws: the soft-wrap flag is not
/// something a terminal can be told.
fn assert_same(local: &ScreenState, want: &ScreenState) {
    assert_eq!((local.rows, local.cols), (want.rows, want.cols));
    assert_eq!(
        (local.cursor_row, local.cursor_col),
        (want.cursor_row, want.cursor_col),
        "cursor"
    );
    assert_eq!(local.modes, want.modes, "modes");
    for (r, (a, b)) in local.grid.iter().zip(&want.grid).enumerate() {
        let norm = |row: &qsh_proto::screen::Row| -> Vec<_> {
            row.cells.iter().cloned().map(visible).collect()
        };
        assert_eq!(norm(a), norm(b), "row {r}");
    }
}

fn text_of(state: &ScreenState, row: usize) -> String {
    state.grid[row]
        .cells
        .iter()
        .filter(|c| c.flags & cell_flags::WIDE_CONT == 0)
        .map(|c| if c.text.is_empty() { " " } else { &*c.text })
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// Host emulator fed `bytes`, snapshot taken.
fn host(rows: u16, cols: u16, bytes: &[u8]) -> (HostScreen, ScreenState) {
    let mut h = term(rows, cols);
    feed(&mut h, bytes);
    let s = h.snapshot();
    (h, s)
}

#[test]
fn the_first_draw_paints_the_whole_state() {
    let (_h, state) = host(
        6,
        30,
        b"hello \x1b[1;31mred\x1b[0m \x1b[48;2;1;2;3mrgb\x1b[0m\r\n\x1b[38;5;200mpal\x1b[0m \x1b[4;7mul\x1b[0m",
    );
    let mut r = ScreenRenderer::new();
    let bytes = r.draw(&state, &[], (30, 6));
    let mut local = term(6, 30);
    feed(&mut local, &bytes);
    assert_same(&local.snapshot(), &state);
}

#[test]
fn an_unchanged_state_draws_nothing() {
    let (_h, state) = host(4, 20, b"abc");
    let mut r = ScreenRenderer::new();
    assert!(!r.draw(&state, &[], (20, 4)).is_empty());
    assert!(r.draw(&state, &[], (20, 4)).is_empty());
}

#[test]
fn a_one_cell_change_costs_one_cell() {
    let (mut h, a) = host(4, 20, b"abcdef");
    let mut r = ScreenRenderer::new();
    r.draw(&a, &[], (20, 4));
    // Overwrite column 2 and put the cursor back where it was.
    feed(&mut h, b"\x1b[1;3HX\x1b[1;7H");
    let b = h.snapshot();
    let bytes = r.draw(&b, &[], (20, 4));
    // One cursor move, the character, and the cursor placement.
    assert_eq!(bytes, b"\x1b[1;3HX\x1b[1;7H");
}

#[test]
fn only_the_changed_rows_are_written() {
    let (mut h, a) = host(5, 20, b"one\r\ntwo\r\nthree\r\nfour");
    let mut r = ScreenRenderer::new();
    r.draw(&a, &[], (20, 5));
    feed(&mut h, b"\x1b[3;1Hthree!");
    let b = h.snapshot();
    let bytes = r.draw(&b, &[], (20, 5));
    let text = String::from_utf8_lossy(&bytes).into_owned();
    assert!(text.contains('!'), "{text:?}");
    assert!(!text.contains("one") && !text.contains("two") && !text.contains("four"));
    assert!(bytes.len() < 30, "{} bytes: {text:?}", bytes.len());
}

#[test]
fn a_blank_tail_is_erased_not_written() {
    let (mut h, a) = host(2, 40, b"a long line of text that will shrink");
    let mut r = ScreenRenderer::new();
    r.draw(&a, &[], (40, 2));
    feed(&mut h, b"\x1b[1;1H\x1b[2Ksh");
    let bytes = r.draw(&h.snapshot(), &[], (40, 2));
    assert!(bytes.windows(3).any(|w| w == b"\x1b[K"), "{bytes:?}");
    assert!(bytes.len() < 40, "{bytes:?}");
}

#[test]
fn a_larger_host_screen_is_cropped_to_the_window() {
    let (_h, state) = host(
        6,
        20,
        b"0123456789abcdefghij\r\nrow1\r\nrow2\r\nrow3\r\nrow4\r\nlast",
    );
    // Cursor is on the last row (5): a window of 3 rows shows rows 3..6.
    let mut r = ScreenRenderer::new();
    let bytes = r.draw(&state, &[], (10, 3));
    let mut local = term(3, 10);
    feed(&mut local, &bytes);
    let l = local.snapshot();
    assert_eq!(text_of(&l, 0), "row3");
    assert_eq!(text_of(&l, 1), "row4");
    assert_eq!(text_of(&l, 2), "last");
    assert_eq!((l.cursor_row, l.cursor_col), (2, 4));

    // A cursor near the top keeps the top rows and drops the columns.
    let (_h, top) = host(6, 20, b"0123456789abcdefghij\x1b[1;1H");
    let mut r = ScreenRenderer::new();
    let bytes = r.draw(&top, &[], (10, 3));
    let mut local = term(3, 10);
    feed(&mut local, &bytes);
    assert_eq!(text_of(&local.snapshot(), 0), "0123456789");
}

#[test]
fn a_smaller_host_screen_is_filled_with_blanks() {
    let (_h, state) = host(2, 5, b"ab\r\ncd");
    let mut r = ScreenRenderer::new();
    // The local terminal starts with junk; the draw overwrites the area.
    let bytes = r.draw(&state, &[], (12, 4));
    let mut local = term(4, 12);
    feed(
        &mut local,
        b"zzzzzzzzzzzz\r\nzzzzzzzzzzzz\r\nzzzzzzzzzzzz\r\nzzzzzzzzzzzz",
    );
    feed(&mut local, &bytes);
    let l = local.snapshot();
    assert_eq!(text_of(&l, 0), "ab");
    assert_eq!(text_of(&l, 1), "cd");
    assert_eq!(text_of(&l, 2), "");
    assert_eq!(text_of(&l, 3), "");
    assert_eq!((l.cursor_row, l.cursor_col), (1, 2));
}

#[test]
fn a_size_change_repaints_everything() {
    let (_h, state) = host(4, 10, b"abc\r\ndef");
    let mut r = ScreenRenderer::new();
    r.draw(&state, &[], (10, 4));
    let bytes = r.draw(&state, &[], (14, 5));
    let mut local = term(5, 14);
    feed(&mut local, &bytes);
    assert_eq!(text_of(&local.snapshot(), 0), "abc");
    assert_eq!(text_of(&local.snapshot(), 1), "def");
}

#[test]
fn a_wide_character_cut_by_the_crop_is_blanked() {
    // Columns 0..=4 are "ab", then a wide character at columns 4-5 when
    // the window is 5 wide: the left half would show alone.
    let (_h, state) = host(2, 10, "abc\u{d55c}x".as_bytes());
    let mut r = ScreenRenderer::new();
    let bytes = r.draw(&state, &[], (4, 2));
    let mut local = term(2, 4);
    feed(&mut local, &bytes);
    // "abc" fits; the wide character starts at column 3 and needs 2.
    assert_eq!(text_of(&local.snapshot(), 0), "abc");
}

#[test]
fn wide_and_combining_characters_survive_a_diff() {
    let (mut h, a) = host(3, 20, "한글 e\u{301}x\r\nplain".as_bytes());
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 20);
    feed(&mut local, &r.draw(&a, &[], (20, 3)));
    assert_same(&local.snapshot(), &a);
    // Change the cell to the right of a wide character and the wide
    // character itself.
    feed(&mut h, "\x1b[1;1H漢\x1b[1;5Hz".as_bytes());
    let b = h.snapshot();
    feed(&mut local, &r.draw(&b, &[], (20, 3)));
    assert_same(&local.snapshot(), &b);
}

#[test]
fn modes_are_mirrored_and_reset() {
    let (_h, state) = host(
        3,
        10,
        b"\x1b[?1049h\x1b[?1h\x1b=\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[?25lhi",
    );
    assert_ne!(state.modes, Modes::default());
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 10);
    feed(&mut local, &r.draw(&state, &[], (10, 3)));
    assert_same(&local.snapshot(), &state);

    let reset = r.reset();
    feed(&mut local, &reset);
    assert_eq!(local.snapshot().modes, Modes::default());
    // A renderer that never changed a mode has nothing to undo.
    assert!(ScreenRenderer::new().reset().is_empty());
}

#[test]
fn leaving_the_alternate_screen_repaints_the_primary_screen() {
    let (mut h, primary) = host(3, 12, b"prompt$ ls");
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 12);
    feed(&mut local, &r.draw(&primary, &[], (12, 3)));
    feed(&mut h, b"\x1b[?1049h\x1b[2J\x1b[1;1Hvim");
    let alt = h.snapshot();
    feed(&mut local, &r.draw(&alt, &[], (12, 3)));
    assert_same(&local.snapshot(), &alt);
    feed(&mut h, b"\x1b[?1049l");
    let back = h.snapshot();
    feed(&mut local, &r.draw(&back, &[], (12, 3)));
    assert_same(&local.snapshot(), &back);
    assert_eq!(text_of(&back, 0), "prompt$ ls");
}

#[test]
fn a_hidden_cursor_stays_hidden_through_a_diff() {
    let (mut h, a) = host(3, 20, b"\x1b[?25lone");
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 20);
    feed(&mut local, &r.draw(&a, &[], (20, 3)));
    feed(&mut h, b"\r\ntwo\x1b[1;1Hone!");
    let b = h.snapshot();
    let bytes = r.draw(&b, &[], (20, 3));
    assert!(
        !bytes.windows(6).any(|w| w == b"\x1b[?25h"),
        "a hidden cursor must not be shown mid-draw: {bytes:?}"
    );
    feed(&mut local, &bytes);
    assert_same(&local.snapshot(), &b);
}

#[test]
fn effects_are_written_once_with_the_update_that_carried_them() {
    let (_h, state) = host(2, 10, b"x");
    let effects = [
        Effect::Title("build ok".into()),
        Effect::Bell,
        Effect::Clipboard {
            selection: "c".into(),
            data: "aGk=".into(),
        },
        Effect::Hyperlink {
            params: "id=1".into(),
            uri: "https://example.com/".into(),
        },
    ];
    let mut r = ScreenRenderer::new();
    let first = r.draw(&state, &effects, (10, 2));
    let s = String::from_utf8_lossy(&first).into_owned();
    assert!(s.contains("\x1b]2;build ok\x1b\\"), "{s:?}");
    assert_eq!(s.matches('\x07').count(), 1);
    assert!(s.contains("\x1b]52;c;aGk=\x1b\\"));
    assert!(s.contains("\x1b]8;id=1;https://example.com/\x1b\\"));
    // The link is closed before the draw returns.
    assert!(s.ends_with("\x1b]8;;\x1b\\"), "{s:?}");

    // A repaint of the same state carries no effect.
    r.invalidate();
    let again = r.draw(&state, &[], (10, 2));
    let s = String::from_utf8_lossy(&again).into_owned();
    assert!(!s.contains("\x1b]") && !s.contains('\x07'), "{s:?}");
}

#[test]
fn a_clipboard_read_request_is_never_written() {
    let (_h, state) = host(2, 10, b"x");
    let mut r = ScreenRenderer::new();
    let bytes = r.draw(
        &state,
        &[Effect::Clipboard {
            selection: "c".into(),
            data: "?".into(),
        }],
        (10, 2),
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("]52"));
}

#[test]
fn effects_alone_draw_even_when_the_cells_did_not_change() {
    let (_h, state) = host(2, 10, b"x");
    let mut r = ScreenRenderer::new();
    r.draw(&state, &[], (10, 2));
    assert_eq!(r.draw(&state, &[Effect::Bell], (10, 2)), b"\x07");
}

#[test]
fn colours_use_the_shortest_sgr() {
    let (_h, state) = host(2, 10, b"\x1b[31;102mx\x1b[0m");
    let mut r = ScreenRenderer::new();
    let bytes = String::from_utf8_lossy(&r.draw(&state, &[], (10, 2))).into_owned();
    assert!(bytes.contains("\x1b[0;31;102m"), "{bytes:?}");
    let _ = Color::Default;
}

proptest! {
    /// Whatever the application does, the local terminal ends up showing the
    /// host screen, through any sequence of incremental draws.
    #[test]
    fn local_terminal_follows_the_host(chunks in proptest::collection::vec(
        proptest::collection::vec(
            prop_oneof![
                Just(b"hello ".to_vec()),
                Just(b"\r\n".to_vec()),
                Just("한글 e\u{301}".as_bytes().to_vec()),
                Just(b"\x1b[31m".to_vec()),
                Just(b"\x1b[0m".to_vec()),
                Just(b"\x1b[1;1H".to_vec()),
                Just(b"\x1b[5;3H".to_vec()),
                Just(b"\x1b[2K".to_vec()),
                Just(b"\x1b[J".to_vec()),
                Just(b"\x1b[?25l".to_vec()),
                Just(b"\x1b[?25h".to_vec()),
                Just(b"\x1b[?1049h".to_vec()),
                Just(b"\x1b[?1049l".to_vec()),
                Just(b"\x1b[1;4;7m".to_vec()),
                Just(b"line\r\nline\r\nline\r\nline\r\nline\r\nline\r\n".to_vec()),
            ],
            0..6,
        ),
        1..30,
    )) {
        let mut h = term(6, 16);
        let mut r = ScreenRenderer::new();
        let mut local = term(6, 16);
        for chunk in chunks {
            for piece in chunk {
                feed(&mut h, &piece);
            }
            let state = h.snapshot();
            let bytes = r.draw(&state, &[], (16, 6));
            feed(&mut local, &bytes);
            let snap = local.snapshot();
            prop_assert_eq!(&snap.modes, &state.modes);
            prop_assert_eq!((snap.cursor_row, snap.cursor_col), (state.cursor_row, state.cursor_col));
            for (a, b) in snap.grid.iter().zip(&state.grid) {
                let norm = |row: &qsh_proto::screen::Row| -> Vec<_> { row.cells.iter().cloned().map(visible).collect() };
                prop_assert_eq!(norm(a), norm(b));
            }
        }
    }
}

fn lines(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("hist {i:03}")).collect()
}

fn plain(line: &str) -> String {
    line.trim_end().to_owned()
}

#[test]
fn history_lands_in_the_local_scrollback_above_an_intact_screen() {
    let (_h, state) = host(4, 20, b"one\r\ntwo\r\nthree");
    let mut r = ScreenRenderer::new();
    let mut local = term(4, 20);
    feed(&mut local, &r.draw(&state, &[], (20, 4)));
    let before = local.take_history();
    let hist = lines(9);
    feed(&mut local, &r.history(&hist, 0, (20, 4)));
    feed(&mut local, &r.draw(&state, &[], (20, 4)));
    assert_same(&local.snapshot(), &state);
    let got = local.take_history();
    let texts: Vec<String> = got.lines.iter().map(|l| plain(&strip_sgr(l))).collect();
    // Exactly the history, in order; no row of the window leaked in.
    assert_eq!(texts, hist, "scrollback after the first frame: {before:?}");
}

fn strip_sgr(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars();
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
fn a_skipped_count_becomes_one_line_after_the_history() {
    let (_h, state) = host(3, 30, b"x");
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 30);
    feed(&mut local, &r.draw(&state, &[], (30, 3)));
    local.take_history();
    feed(&mut local, &r.history(&lines(2), 1234, (30, 3)));
    feed(&mut local, &r.draw(&state, &[], (30, 3)));
    let got = local.take_history();
    let texts: Vec<String> = got.lines.iter().map(|l| plain(&strip_sgr(l))).collect();
    assert_eq!(
        texts,
        ["hist 000", "hist 001", "--- 1234 lines skipped ---"]
    );
    assert_same(&local.snapshot(), &state);
}

#[test]
fn history_before_the_first_frame_is_plain_output() {
    let (_h, state) = host(3, 30, b"x");
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 30);
    feed(&mut local, &r.history(&lines(5), 0, (30, 3)));
    feed(&mut local, &r.draw(&state, &[], (30, 3)));
    assert_same(&local.snapshot(), &state);
    let texts: Vec<String> = local
        .take_history()
        .lines
        .iter()
        .map(|l| plain(&strip_sgr(l)))
        .collect();
    assert_eq!(texts[..5], lines(5)[..]);
}

#[test]
fn history_in_the_alternate_screen_still_reaches_the_scrollback() {
    let (mut h, primary) = host(3, 20, b"prompt$ vim");
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 20);
    feed(&mut local, &r.draw(&primary, &[], (20, 3)));
    feed(&mut h, b"\x1b[?1049h\x1b[2J\x1b[1;1Hvim");
    let alt = h.snapshot();
    feed(&mut local, &r.draw(&alt, &[], (20, 3)));
    local.take_history();
    feed(&mut local, &r.history(&lines(4), 0, (20, 3)));
    feed(&mut local, &r.draw(&alt, &[], (20, 3)));
    assert_same(&local.snapshot(), &alt);
    let texts: Vec<String> = local
        .take_history()
        .lines
        .iter()
        .map(|l| plain(&strip_sgr(l)))
        .collect();
    assert_eq!(texts, lines(4));
    feed(&mut h, b"\x1b[?1049l");
    let back = h.snapshot();
    feed(&mut local, &r.draw(&back, &[], (20, 3)));
    assert_same(&local.snapshot(), &back);
}

#[test]
fn a_history_line_cannot_carry_anything_but_text_and_sgr() {
    let evil = "a\x1b]52;c;AAAA\x07b\x1b[2Jc\x1b[1;31md\x1b[0m\re\x1b[?1049hf";
    assert_eq!(sanitize_history_line(evil), "abc\x1b[1;31md\x1b[0mef");
}

#[test]
fn a_history_line_wider_than_the_window_is_cut_not_wrapped() {
    let (_h, state) = host(3, 10, b"x");
    let mut r = ScreenRenderer::new();
    let mut local = term(3, 10);
    feed(&mut local, &r.draw(&state, &[], (10, 3)));
    local.take_history();
    feed(
        &mut local,
        &r.history(&["0123456789ABCDEF".to_string()], 0, (10, 3)),
    );
    feed(&mut local, &r.draw(&state, &[], (10, 3)));
    let texts: Vec<String> = local
        .take_history()
        .lines
        .iter()
        .map(|l| plain(&strip_sgr(l)))
        .collect();
    assert_eq!(texts, ["0123456789"]);
    assert_same(&local.snapshot(), &state);
}

// ---- prediction overlay (ADR-0053 decision 8) ----

mod overlay {
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    use qsh_proto::screen::Cell;
    use unicode_width::UnicodeWidthChar as _;

    use super::*;
    use crate::adapt::Prediction;
    use crate::client::predict::{
        EchoReport, MAX_PENDING, Overlay, OverlayCell, Predictor, TtyEcho,
    };

    fn ocell(row: u16, col: u16, text: &str, flags: u8) -> OverlayCell {
        OverlayCell {
            row,
            col,
            cell: Cell {
                text: text.into(),
                flags,
                ..Cell::default()
            },
        }
    }

    fn wide(row: u16, col: u16, text: &str, flags: u8) -> [OverlayCell; 2] {
        let mut cont = ocell(row, col + 1, "", cell_flags::WIDE_CONT);
        cont.cell.flags |= flags & cell_flags::UNDERLINE;
        [ocell(row, col, text, flags | cell_flags::WIDE), cont]
    }

    fn overlay(cells: Vec<OverlayCell>, cursor: Option<(u16, u16)>) -> Overlay {
        Overlay { cells, cursor }
    }

    /// A drawn host screen and a local terminal model that has seen it.
    fn drawn(rows: u16, cols: u16, bytes: &[u8]) -> (ScreenRenderer, HostScreen, ScreenState) {
        let (_h, state) = host(rows, cols, bytes);
        let mut r = ScreenRenderer::new();
        let mut local = term(rows, cols);
        feed(&mut local, &r.draw(&state, &[], (cols, rows)));
        (r, local, state)
    }

    #[test]
    fn an_overlay_is_drawn_over_the_host_screen_and_moves_the_cursor() {
        let (mut r, mut local, state) = drawn(3, 20, b"$ ");
        let o = overlay(vec![ocell(0, 2, "a", 0)], Some((0, 3)));
        let bytes = r.draw_with_overlay(&state, &o, &[], (20, 3));
        feed(&mut local, &bytes);
        let l = local.snapshot();
        assert_eq!(text_of(&l, 0), "$ a");
        assert_eq!((l.cursor_row, l.cursor_col), (0, 3));
        // The synced state is untouched: only the local model has the glyph.
        assert_eq!(text_of(&state, 0), "$");
    }

    #[test]
    fn an_empty_overlay_gives_the_bytes_of_a_plain_draw() {
        let (_h, state) = host(4, 20, b"abc\x1b[1;31mred\x1b[0m");
        let mut plain_r = ScreenRenderer::new();
        let mut over_r = ScreenRenderer::new();
        let empty = Overlay::default();
        assert_eq!(
            plain_r.draw(&state, &[], (20, 4)),
            over_r.draw_with_overlay(&state, &empty, &[], (20, 4))
        );
        assert!(
            over_r
                .draw_with_overlay(&state, &empty, &[], (20, 4))
                .is_empty()
        );
    }

    #[test]
    fn nothing_changed_writes_zero_bytes() {
        let (mut r, _local, state) = drawn(3, 20, b"$ ");
        let o = overlay(vec![ocell(0, 2, "a", 0)], Some((0, 3)));
        assert!(!r.draw_with_overlay(&state, &o, &[], (20, 3)).is_empty());
        assert!(r.draw_with_overlay(&state, &o, &[], (20, 3)).is_empty());
        // The host catching up with exactly what was predicted changes
        // nothing on the terminal either.
        let (_h, caught_up) = host(3, 20, b"$ a");
        assert!(
            r.draw_with_overlay(&caught_up, &Overlay::default(), &[], (20, 3))
                .is_empty()
        );
    }

    #[test]
    fn a_rollback_rewrites_only_the_changed_cells_and_never_clears() {
        let (mut r, mut local, state) = drawn(4, 30, b"$ ls\r\nout1\r\nout2\x1b[1;5H");
        let o = overlay(vec![ocell(0, 4, "x", 0), ocell(0, 5, "y", 0)], Some((0, 6)));
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (30, 4)));
        assert_eq!(text_of(&local.snapshot(), 0), "$ lsxy");
        // The host disagrees: the prediction goes away.
        let bytes = r.draw_with_overlay(&state, &Overlay::default(), &[], (30, 4));
        let text = String::from_utf8_lossy(&bytes).into_owned();
        for clear in ["\x1b[2J", "\x1b[J", "\x1b[3J", "\x1b[0J"] {
            assert!(!text.contains(clear), "{text:?}");
        }
        assert!(!text.contains("out") && !text.contains("ls"), "{text:?}");
        assert!(bytes.len() < 30, "{} bytes: {text:?}", bytes.len());
        feed(&mut local, &bytes);
        assert_same(&local.snapshot(), &state);
    }

    #[test]
    fn a_changed_prediction_touches_only_the_cell_that_differs() {
        let (mut r, _local, state) = drawn(3, 20, b"$ ");
        let a = overlay(vec![ocell(0, 2, "a", 0), ocell(0, 3, "b", 0)], Some((0, 4)));
        let b = overlay(vec![ocell(0, 2, "a", 0), ocell(0, 3, "c", 0)], Some((0, 4)));
        r.draw_with_overlay(&state, &a, &[], (20, 3));
        let bytes = r.draw_with_overlay(&state, &b, &[], (20, 3));
        // One move, the pen, the cell; the cursor did not move.
        assert_eq!(bytes, b"\x1b[1;4Hc\x1b[1;5H");
    }

    #[test]
    fn the_underline_follows_the_overlay_cell_flag() {
        let (mut r, mut local, state) = drawn(3, 20, b"$ ");
        let o = overlay(
            vec![ocell(0, 2, "a", cell_flags::UNDERLINE), ocell(0, 3, "b", 0)],
            Some((0, 4)),
        );
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (20, 3)));
        let l = local.snapshot();
        let flags = |c: usize| l.grid[0].cells[c].flags & cell_flags::UNDERLINE;
        assert_ne!(flags(2), 0);
        assert_eq!(flags(3), 0);
        // Confirmed by the host: the underline goes, the glyph stays.
        let (_h, caught_up) = host(3, 20, b"$ ab");
        feed(
            &mut local,
            &r.draw_with_overlay(&caught_up, &Overlay::default(), &[], (20, 3)),
        );
        let l = local.snapshot();
        assert_eq!(l.grid[0].cells[2].flags & cell_flags::UNDERLINE, 0);
        assert_same(&l, &caught_up);
    }

    #[test]
    fn a_wide_prediction_fits_or_is_cut_at_the_window_edge() {
        let (mut r, mut local, state) = drawn(2, 6, b"$ ");
        // Fits in columns 4 and 5.
        let o = overlay(wide(0, 4, "가", 0).to_vec(), Some((0, 5)));
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (6, 2)));
        assert_eq!(text_of(&local.snapshot(), 0), "$   가");
        // Starting in the last column the right half does not fit: blank.
        let o = overlay(wide(0, 5, "가", 0).to_vec(), Some((0, 5)));
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (6, 2)));
        let l = local.snapshot();
        assert_eq!(text_of(&l, 0), "$");
        assert!(l.grid[0].cells[5].text.trim().is_empty());
    }

    #[test]
    fn a_narrow_prediction_over_half_a_wide_host_cell_blanks_the_other_half() {
        let (_h, state) = host(2, 10, "가나".as_bytes());
        let mut r = ScreenRenderer::new();
        let mut local = term(2, 10);
        feed(&mut local, &r.draw(&state, &[], (10, 2)));
        let o = overlay(vec![ocell(0, 0, "x", 0)], None);
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (10, 2)));
        assert_eq!(text_of(&local.snapshot(), 0), "x 나");
        feed(
            &mut local,
            &r.draw_with_overlay(&state, &Overlay::default(), &[], (10, 2)),
        );
        assert_same(&local.snapshot(), &state);
    }

    #[test]
    fn overlay_cells_outside_the_cropped_window_are_not_drawn() {
        // Host is 6x20, window 3x10: the cursor row 5 keeps rows 3..6.
        let (_h, state) = host(6, 20, b"a\r\nb\r\nc\r\nd\r\ne\r\nf");
        let mut r = ScreenRenderer::new();
        let o = overlay(
            vec![
                ocell(0, 1, "x", 0),
                ocell(5, 12, "y", 0),
                ocell(5, 1, "z", 0),
            ],
            Some((5, 2)),
        );
        let mut local = term(3, 10);
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (10, 3)));
        let l = local.snapshot();
        assert_eq!(text_of(&l, 2), "fz");
        assert_eq!(text_of(&l, 0), "d");
        assert_eq!((l.cursor_row, l.cursor_col), (2, 2));
    }

    #[test]
    fn history_is_emitted_first_and_the_overlay_is_composed_again_after_it() {
        let (mut r, mut local, state) = drawn(3, 20, b"$ ");
        let o = overlay(vec![ocell(0, 2, "a", cell_flags::UNDERLINE)], Some((0, 3)));
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (20, 3)));
        local.take_history();
        let hist = lines(2);
        let h_bytes = r.history(&hist, 0, (20, 3));
        let d_bytes = r.draw_with_overlay(&state, &o, &[], (20, 3));
        // The repaint after history writes the predicted cell again.
        assert!(d_bytes.contains(&b'a'));
        feed(&mut local, &h_bytes);
        feed(&mut local, &d_bytes);
        let l = local.snapshot();
        assert_eq!(text_of(&l, 0), "$ a");
        assert_eq!((l.cursor_row, l.cursor_col), (0, 3));
        let got: Vec<String> = local
            .take_history()
            .lines
            .iter()
            .map(|l| plain(&strip_sgr(l)))
            .collect();
        assert_eq!(got, hist);
    }

    #[test]
    fn the_overlay_is_dropped_when_the_host_switches_to_the_alternate_screen() {
        let (mut r, mut local, state) = drawn(3, 20, b"$ ");
        let o = overlay(vec![ocell(0, 2, "a", 0)], Some((0, 3)));
        feed(&mut local, &r.draw_with_overlay(&state, &o, &[], (20, 3)));
        let (_h, alt) = host(3, 20, b"\x1b[?1049h\x1b[2J\x1b[1;1Hvim");
        // A stale overlay passed with the alternate screen is not drawn.
        feed(&mut local, &r.draw_with_overlay(&alt, &o, &[], (20, 3)));
        assert_same(&local.snapshot(), &alt);
        assert_eq!(text_of(&local.snapshot(), 0), "vim");
        // Back on the primary screen the host's own content is repainted.
        feed(
            &mut local,
            &r.draw_with_overlay(&state, &Overlay::default(), &[], (20, 3)),
        );
        assert_same(&local.snapshot(), &state);
    }

    // ---- property: the local terminal ends up equal to the host ----

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mode {
        Echo,
        Star,
        Other,
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
    }

    impl Key {
        fn bytes(&self) -> Vec<u8> {
            match self {
                Key::Char(c) => c.to_string().into_bytes(),
                Key::Backspace => vec![0x7f],
                Key::Left => b"\x1b[D".to_vec(),
                Key::Right => b"\x1b[C".to_vec(),
                Key::Enter => vec![b'\r'],
            }
        }
    }

    #[derive(Clone, Debug)]
    enum Op {
        Key(Key),
        /// The host applies this many pending keys, then reports the state
        /// and the echo.
        Deliver(usize),
        /// The host applies keys and sends the state; the echo report comes
        /// with a later delivery.
        StateOnly(usize),
        /// The application moves the cursor on its own.
        HostMove(usize),
        /// A full-screen application starts or exits.
        Alt,
    }

    struct Host {
        mode: Mode,
        line: Vec<char>,
        pos: usize,
        above: Vec<String>,
        alt: bool,
    }

    const ROWS: u16 = 4;
    const COLS: u16 = 30;

    fn width_of(chars: &[char]) -> u16 {
        chars.iter().map(|c| c.width().unwrap_or(1) as u16).sum()
    }

    impl Host {
        fn insert(&mut self, c: char) {
            let c = match self.mode {
                Mode::Star => '*',
                Mode::Other => 'Q',
                _ => c,
            };
            if width_of(&self.line) + c.width().unwrap_or(1) as u16 <= 20 {
                self.line.insert(self.pos, c);
                self.pos += 1;
            }
        }
        fn apply(&mut self, k: &Key) {
            if matches!(self.mode, Mode::Silent | Mode::Secret) || self.alt {
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
                    let text: String = self.line.iter().collect();
                    self.above.push(format!("$ {text}"));
                    // The screen scrolls: the oldest line leaves.
                    if self.above.len() > usize::from(ROWS) - 1 {
                        self.above.remove(0);
                    }
                    self.line.clear();
                    self.pos = 0;
                }
            }
        }
        fn screen(&self) -> ScreenState {
            let mut s = ScreenState::blank(ROWS, COLS).unwrap();
            if self.alt {
                s.modes.flags |= Modes::ALT_SCREEN;
                put(&mut s, 0, "vim");
                return s;
            }
            for (i, l) in self.above.iter().enumerate() {
                put(&mut s, i as u16, l);
            }
            let row = self.above.len() as u16;
            let text: String = self.line.iter().collect();
            put(&mut s, row, &format!("$ {text}"));
            s.cursor_row = row;
            s.cursor_col = 2 + width_of(&self.line[..self.pos]);
            s
        }
        fn tty(&self) -> TtyEcho {
            match self.mode {
                Mode::Echo | Mode::Star | Mode::Other => TtyEcho::App,
                Mode::Silent => TtyEcho::Unknown,
                Mode::Secret => TtyEcho::Secret,
            }
        }
    }

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

    fn key_strategy() -> impl Strategy<Value = Key> {
        prop_oneof![
            6 => prop::sample::select(vec!['a', 'b', 'Z', ' ', '가', '나', 'é']).prop_map(Key::Char),
            2 => Just(Key::Backspace),
            2 => Just(Key::Left),
            2 => Just(Key::Right),
            1 => Just(Key::Enter),
        ]
    }

    /// The cell at (row, col) as the renderer draws it.
    fn shown(s: &ScreenState, row: u16, col: u16) -> Cell {
        visible(s.grid[usize::from(row)].cells[usize::from(col)].clone())
    }

    /// Draw `state` with the predictor's overlay into the local model and
    /// check what the local terminal shows against the two.
    fn show(
        p: &Predictor,
        host: &Host,
        renderer: &mut ScreenRenderer,
        local: &mut HostScreen,
    ) -> Result<(), TestCaseError> {
        let state = host.screen();
        let o = p.overlay();
        prop_assert!(p.pending_len() <= MAX_PENDING);
        let bytes = renderer.draw_with_overlay(&state, &o, &[], (COLS, ROWS));
        feed(local, &bytes);
        let l = local.snapshot();
        // The overlay is the only difference from the host screen (a wide
        // half it cuts is blanked, so the neighbours of its cells are
        // exempt).
        let touched = |r: u16, c: u16| {
            o.cells
                .iter()
                .any(|oc| oc.row == r && oc.col.abs_diff(c) <= 1)
        };
        for r in 0..ROWS {
            for c in 0..COLS {
                if let Some(oc) = o.cells.iter().find(|oc| oc.row == r && oc.col == c) {
                    let want = visible(oc.cell.clone());
                    let got = shown(&l, r, c);
                    prop_assert_eq!(got.text, want.text, "overlay text ({}, {})", r, c);
                    // A terminal keeps the pen on the left half of a wide
                    // character only.
                    if want.flags & cell_flags::WIDE_CONT == 0 {
                        prop_assert_eq!(
                            got.flags & cell_flags::UNDERLINE,
                            want.flags & cell_flags::UNDERLINE,
                            "overlay underline ({}, {})",
                            r,
                            c
                        );
                    }
                } else if !touched(r, c) {
                    prop_assert_eq!(
                        shown(&l, r, c),
                        shown(&state, r, c),
                        "host cell ({}, {})",
                        r,
                        c
                    );
                }
            }
        }
        let want_cursor = o.cursor.unwrap_or((state.cursor_row, state.cursor_col));
        prop_assert_eq!((l.cursor_row, l.cursor_col), want_cursor);
        prop_assert_eq!(l.modes, state.modes);
        if matches!(host.mode, Mode::Silent | Mode::Secret) {
            prop_assert!(o.is_empty());
        }
        Ok(())
    }

    /// Run `ops` against a host in `mode` and the predictor, checking the
    /// local terminal after every step and at the end.
    fn run(mode: Mode, ops: Vec<Op>) -> Result<(), TestCaseError> {
        {
            let mut host = Host {
                mode,
                line: Vec::new(),
                pos: 0,
                above: Vec::new(),
                alt: false,
            };
            let mut p = Predictor::new(true);
            p.on_policy(Prediction::Underline);
            let mut renderer = ScreenRenderer::new();
            let mut local = term(ROWS, COLS);
            let mut t = Instant::now();
            let mut n = 1u64;
            let (mut sent, mut done) = (0u64, 0u64);
            let mut queue: VecDeque<(Key, u64)> = VecDeque::new();

            p.on_state(&host.screen(), n, t);
            show(&p, &host, &mut renderer, &mut local)?;

            for op in ops {
                t += Duration::from_millis(3);
                match op {
                    Op::Key(k) => {
                        let b = k.bytes();
                        sent += b.len() as u64;
                        p.on_input(&b, sent, t);
                        queue.push_back((k, sent));
                    }
                    Op::Deliver(c) | Op::StateOnly(c) => {
                        for _ in 0..c {
                            if let Some((k, end)) = queue.pop_front() {
                                host.apply(&k);
                                done = end;
                            }
                        }
                        n += 1;
                        p.on_state(&host.screen(), n, t);
                        if matches!(op, Op::Deliver(_)) {
                            p.on_echo(
                                EchoReport {
                                    state_num: n,
                                    input_seq: done,
                                    tty: host.tty(),
                                },
                                t,
                            );
                        }
                    }
                    Op::HostMove(m) => {
                        if !host.alt && !matches!(host.mode, Mode::Silent | Mode::Secret) {
                            host.pos = m % (host.line.len() + 1);
                            n += 1;
                            p.on_state(&host.screen(), n, t);
                        }
                    }
                    Op::Alt => {
                        host.alt = !host.alt;
                        n += 1;
                        p.on_state(&host.screen(), n, t);
                    }
                }
                show(&p, &host, &mut renderer, &mut local)?;
            }

            // Everything still queued is applied and judged.
            t += Duration::from_millis(3);
            for (k, end) in queue.drain(..) {
                host.apply(&k);
                done = end;
            }
            n += 1;
            p.on_state(&host.screen(), n, t);
            p.on_echo(
                EchoReport {
                    state_num: n,
                    input_seq: done,
                    tty: host.tty(),
                },
                t,
            );
            prop_assert_eq!(p.pending_len(), 0);
            prop_assert!(p.overlay().is_empty());
            show(&p, &host, &mut renderer, &mut local)?;
            assert_same(&local.snapshot(), &host.screen());
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn local_terminal_matches_the_host_once_predictions_resolve(
            mode in prop::sample::select(vec![
                Mode::Echo, Mode::Star, Mode::Other, Mode::Silent, Mode::Secret,
            ]),
            ops in prop::collection::vec(
                prop_oneof![
                    6 => key_strategy().prop_map(Op::Key),
                    3 => (0usize..4).prop_map(Op::Deliver),
                    1 => (0usize..3).prop_map(Op::StateOnly),
                    1 => (0usize..8).prop_map(Op::HostMove),
                    1 => Just(Op::Alt),
                ],
                0..70,
            ),
        ) {
            run(mode, ops)?;
        }
    }

    /// The shrunk case of seed fb7d5ef9: the host's first echo makes a
    /// later prediction match by coincidence and removes predictions in the
    /// middle of the queue. The earlier ones keep snapshots of a wide
    /// character that a later one overwrote half of; the overlay must not
    /// carry the lead without its right half.
    #[test]
    fn a_prediction_resolved_in_the_middle_leaves_no_torn_wide_pair() {
        let k = |c: char| Op::Key(Key::Char(c));
        let ops = vec![
            k('가'),
            k('가'),
            Op::Key(Key::Left),
            Op::Key(Key::Backspace),
            Op::Key(Key::Left),
            k('é'),
            k('가'),
            Op::Key(Key::Right),
            Op::Key(Key::Backspace),
            k('a'),
            Op::Deliver(1),
        ];
        run(Mode::Echo, ops).unwrap();
    }

    /// The shrunk case of seed af9dc902: a wide character at the end of the
    /// line, shifted right by one typed character after another. The
    /// predictor used to move the lead without its right half, so the next
    /// character's cell sat where the half belonged and the renderer blanked
    /// it.
    #[test]
    fn typing_before_a_wide_character_keeps_every_typed_cell() {
        let k = |c: char| Op::Key(Key::Char(c));
        let ops = vec![
            k('가'),
            k('a'),
            Op::Key(Key::Backspace),
            Op::Key(Key::Left),
            k(' '),
            Op::Deliver(2),
            k('é'),
            k('a'),
            k('a'),
            k('a'),
            k('a'),
            Op::Deliver(2),
            k('a'),
            k('a'),
            k('a'),
            Op::StateOnly(2),
            k('a'),
        ];
        run(Mode::Echo, ops).unwrap();
    }
}

/// The connection status line composed over the host screen (ADR-0053
/// decision 9): the same local terminal model as above.
mod status {
    use super::*;

    const LINE: &str = "qsh: last reply 3s ago; ~. to quit, ~d to detach";

    fn drawn(rows: u16, cols: u16, bytes: &[u8]) -> (ScreenRenderer, HostScreen, ScreenState) {
        let (_h, state) = host(rows, cols, bytes);
        let mut r = ScreenRenderer::new();
        let mut local = term(rows, cols);
        feed(&mut local, &r.draw(&state, &[], (cols, rows)));
        (r, local, state)
    }

    fn inverse_row(s: &ScreenState, row: usize) -> bool {
        s.grid[row]
            .cells
            .iter()
            .all(|c| c.flags & cell_flags::INVERSE != 0)
    }

    #[test]
    fn the_line_fills_the_top_row_in_reverse_video() {
        let (mut r, mut local, state) = drawn(4, 60, b"$ ls\r\nout\r\nmore\r\n$ ");
        let bytes = r.draw_composed(&state, None, Some(LINE), &[], (60, 4));
        feed(&mut local, &bytes);
        let l = local.snapshot();
        assert_eq!(text_of(&l, 0), LINE);
        assert!(inverse_row(&l, 0), "reverse video across the whole width");
        assert_eq!(text_of(&l, 1), "out");
        // The host's cursor is where it was.
        assert_eq!((l.cursor_row, l.cursor_col), (3, 2));
        // The synced state is untouched.
        assert_eq!(text_of(&state, 0), "$ ls");
    }

    #[test]
    fn removing_the_line_writes_the_host_row_back_and_never_clears() {
        let (mut r, mut local, state) = drawn(4, 60, b"$ ls\r\nout\r\nmore\r\n$ ");
        feed(
            &mut local,
            &r.draw_composed(&state, None, Some(LINE), &[], (60, 4)),
        );
        let bytes = r.draw_composed(&state, None, None, &[], (60, 4));
        let s = String::from_utf8_lossy(&bytes).into_owned();
        assert!(!s.contains("\x1b[2J") && !s.contains("\x1b[J"), "{s:?}");
        feed(&mut local, &bytes);
        let l = local.snapshot();
        assert_eq!(text_of(&l, 0), "$ ls");
        assert!(
            l.grid[0]
                .cells
                .iter()
                .all(|c| c.flags & cell_flags::INVERSE == 0)
        );
        assert_same(&l, &state);
    }

    #[test]
    fn only_the_top_row_is_written_when_the_line_changes() {
        let (mut r, _local, state) = drawn(4, 60, b"$ ls\r\nout\r\nmore\r\n$ ");
        r.draw_composed(&state, None, Some(LINE), &[], (60, 4));
        let next = LINE.replace("3s", "4s");
        let bytes = r.draw_composed(&state, None, Some(&next), &[], (60, 4));
        let s = String::from_utf8_lossy(&bytes).into_owned();
        assert!(s.contains("\x1b[1;17H") && s.contains('4'), "{s:?}");
        assert!(!s.contains("out") && !s.contains("more"), "{s:?}");
        // Same text again: nothing.
        assert!(
            r.draw_composed(&state, None, Some(&next), &[], (60, 4))
                .is_empty()
        );
    }

    #[test]
    fn the_line_goes_to_the_bottom_row_when_the_cursor_is_on_the_top_one() {
        let (mut r, mut local, state) = drawn(4, 60, b"$ ");
        feed(
            &mut local,
            &r.draw_composed(&state, None, Some(LINE), &[], (60, 4)),
        );
        let l = local.snapshot();
        assert_eq!(text_of(&l, 0), "$");
        assert_eq!(text_of(&l, 3), LINE);
        assert!(inverse_row(&l, 3));
    }

    #[test]
    fn a_predicted_cursor_on_the_top_row_moves_the_line_down_too() {
        // The host cursor is on row 2, the overlay's is on row 0.
        let (mut r, mut local, state) = drawn(4, 60, b"a\r\nb\r\n$ ");
        let o = Overlay {
            cells: Vec::new(),
            cursor: Some((0, 3)),
        };
        feed(
            &mut local,
            &r.draw_composed(&state, Some(&o), Some(LINE), &[], (60, 4)),
        );
        assert_eq!(text_of(&local.snapshot(), 3), LINE);
    }

    #[test]
    fn the_text_is_cut_at_the_right_edge_and_a_narrow_window_gets_none() {
        let (mut r, mut local, state) = drawn(4, 30, b"x\r\ny\r\n$ ");
        feed(
            &mut local,
            &r.draw_composed(&state, None, Some(LINE), &[], (30, 4)),
        );
        assert_eq!(text_of(&local.snapshot(), 0), LINE[..30].trim_end());

        let (mut r, mut local, state) = drawn(4, 19, b"x\r\ny\r\n$ ");
        let bytes = r.draw_composed(&state, None, Some(LINE), &[], (19, 4));
        feed(&mut local, &bytes);
        assert_eq!(text_of(&local.snapshot(), 0), "x");
    }

    #[test]
    fn the_line_is_drawn_on_the_alternate_screen_too() {
        let (mut r, mut local, state) = drawn(4, 60, b"\x1b[?1049h\x1b[3;1Hvim");
        feed(
            &mut local,
            &r.draw_composed(&state, None, Some(LINE), &[], (60, 4)),
        );
        let l = local.snapshot();
        assert_eq!(text_of(&l, 0), LINE);
        assert_eq!(text_of(&l, 2), "vim");
    }
}
