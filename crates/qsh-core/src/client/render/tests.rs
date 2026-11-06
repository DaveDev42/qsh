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
