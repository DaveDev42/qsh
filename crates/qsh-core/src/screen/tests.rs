use std::time::Instant;

use proptest::prelude::*;
use qsh_proto::screen::{Color, Effect, Modes, ScreenState, cell_flags};

use super::*;

fn screen(rows: u16, cols: u16) -> HostScreen {
    HostScreen::new(ScreenOptions {
        rows,
        cols,
        ..ScreenOptions::default()
    })
}

fn feed(s: &mut HostScreen, data: &[u8]) {
    let end = s.fed_seq + data.len() as u64;
    s.feed(data, end);
}

fn row_text(state: &ScreenState, row: usize) -> String {
    state.grid[row]
        .cells
        .iter()
        .filter(|c| c.flags & cell_flags::WIDE_CONT == 0)
        .map(|c| if c.text.is_empty() { " " } else { &*c.text })
        .collect::<String>()
        .trim_end()
        .to_owned()
}

fn answers_to(input: &[u8]) -> Vec<u8> {
    let mut s = screen(24, 80);
    feed(&mut s, input);
    s.take_answers()
}

// ---- state numbering, diffs, hashes ----

#[test]
fn full_screen_update_from_base_zero_reproduces_the_snapshot() {
    let mut s = screen(5, 20);
    feed(
        &mut s,
        b"hello \x1b[1;31mred\x1b[0m\r\nsecond \xed\x95\x9c\xea\xb8\x80",
    );
    let u = s.update_since(0).unwrap();
    assert_eq!((u.base_num, u.new_num, u.output_seq), (0, 1, 35));
    let blank = ScreenState::blank(5, 20).unwrap();
    let state = u.apply(&blank).unwrap();
    assert_eq!(state, s.snapshot());
    assert_eq!(row_text(&state, 0), "hello red");
    assert_eq!(row_text(&state, 1), "second 한글");
    let red = &state.grid[0].cells[6];
    assert_eq!(
        (&*red.text, red.fg, red.flags),
        ("r", Color::Idx(1), cell_flags::BOLD)
    );
    let wide = &state.grid[1].cells[7];
    assert_eq!(wide.flags, cell_flags::WIDE);
    assert_eq!(state.grid[1].cells[8].flags, cell_flags::WIDE_CONT);
    assert_eq!((state.cursor_row, state.cursor_col), (1, 11));
}

#[test]
fn state_numbers_only_advance_when_the_screen_or_effects_change() {
    let mut s = screen(3, 10);
    feed(&mut s, b"a");
    let one = s.cut();
    assert_eq!(one.num, 1);
    // Output that leaves the screen as it was: same number, new offset.
    feed(&mut s, b"\x1b[1;1Ha");
    let again = s.cut();
    assert_eq!(again.num, 1);
    assert_eq!(again.output_seq, 8);
    assert_eq!(s.update_since(1), None);
    feed(&mut s, b"b");
    assert_eq!(s.cut().num, 2);
    // An effect alone is a new state.
    feed(&mut s, b"\x07");
    assert_eq!(s.cut().num, 3);
}

#[test]
fn incremental_update_carries_only_changed_cells_and_a_matching_hash() {
    let mut s = screen(4, 30);
    feed(&mut s, b"line one\r\nline two");
    let first = s.update_since(0).unwrap();
    let base = first.apply(&ScreenState::blank(4, 30).unwrap()).unwrap();
    feed(&mut s, b"\x1b[3;1Hline three");
    let second = s.update_since(first.new_num).unwrap();
    assert_eq!(second.base_num, first.new_num);
    // Only the new row's cells changed; the cursor moves in the header.
    assert_eq!(second.diff.changes.len(), 1);
    assert_eq!(second.diff.changes[0].row, 2);
    let next = second.apply(&base).unwrap();
    assert_eq!(next.hash(), second.state_hash);
    assert_eq!(next, s.snapshot());
    // The wire form survives a decode.
    let decoded = qsh_proto::screen::ScreenUpdate::decode(&second.encode()).unwrap();
    assert_eq!(decoded.apply(&base).unwrap(), next);
}

#[test]
fn a_base_that_fell_out_of_the_retained_window_gets_the_full_screen() {
    let mut s = screen(2, 10);
    for i in 0..(RETAINED_STATES + 3) {
        feed(&mut s, format!("\x1b[1;1H{i:>9}").as_bytes());
        s.cut();
    }
    let u = s.update_since(1).unwrap();
    assert_eq!(u.base_num, 0);
    let state = u.apply(&ScreenState::blank(2, 10).unwrap()).unwrap();
    assert_eq!(state, s.snapshot());
    // A base number from the future is treated the same way.
    assert_eq!(s.update_since(9999).unwrap().base_num, 0);
}

#[test]
fn resize_changes_the_state_and_the_diff_repaints_in_full() {
    let mut s = screen(3, 10);
    feed(&mut s, b"abc");
    let before = s.cut();
    s.resize(4, 12);
    assert_eq!(s.size(), (4, 12));
    let u = s.update_since(before.num).unwrap();
    assert_eq!((u.diff.rows, u.diff.cols), (4, 12));
    let base = s.cuts.front().unwrap().state.clone();
    assert_eq!(u.apply(&base).unwrap(), s.snapshot());
    // An unacceptable size is ignored.
    s.resize(0, 80);
    assert_eq!(s.size(), (4, 12));
}

/// Random terminal input: text, control characters, and the escape
/// sequences programs actually send.
fn arb_stream() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        6 => "[ -~]{1,12}".prop_map(String::into_bytes),
        2 => Just(b"\r\n".to_vec()),
        1 => Just(b"\r".to_vec()),
        1 => Just(b"\x08".to_vec()),
        1 => Just(b"\t".to_vec()),
        1 => Just("한글あ".as_bytes().to_vec()),
        1 => Just("e\u{301}x".as_bytes().to_vec()),
        2 => (1u8..30, 1u8..90).prop_map(|(r, c)| format!("\x1b[{r};{c}H").into_bytes()),
        1 => (0u8..4).prop_map(|n| format!("\x1b[{n}J").into_bytes()),
        1 => (0u8..3).prop_map(|n| format!("\x1b[{n}K").into_bytes()),
        2 => (0u8..108).prop_map(|n| format!("\x1b[{n}m").into_bytes()),
        1 => Just(b"\x1b[38;2;10;20;30m".to_vec()),
        1 => Just(b"\x1b[48;5;200m".to_vec()),
        1 => (1u8..5).prop_map(|n| format!("\x1b[{n}A").into_bytes()),
        1 => (1u8..5).prop_map(|n| format!("\x1b[{n}L").into_bytes()),
        1 => (1u8..5).prop_map(|n| format!("\x1b[{n}M").into_bytes()),
        1 => (1u8..5).prop_map(|n| format!("\x1b[{n}P").into_bytes()),
        1 => (1u8..5).prop_map(|n| format!("\x1b[{n}@").into_bytes()),
        1 => (1u8..5).prop_map(|n| format!("\x1b[{n}S").into_bytes()),
        1 => Just(b"\x1b[?1049h".to_vec()),
        1 => Just(b"\x1b[?1049l".to_vec()),
        1 => Just(b"\x1b[?25l".to_vec()),
        1 => Just(b"\x1b[?25h".to_vec()),
        1 => Just(b"\x1b[?2004h".to_vec()),
        1 => Just(b"\x1b[?1006h\x1b[?1002h".to_vec()),
        1 => Just(b"\x1b[3;8r".to_vec()),
        1 => Just(b"\x1b7\x1b8".to_vec()),
        1 => Just(b"\x1bM".to_vec()),
        1 => Just(b"\x1b]2;title\x07".to_vec()),
        1 => Just(b"\x07".to_vec()),
        1 => proptest::collection::vec(any::<u8>(), 1..8),
    ];
    proptest::collection::vec(piece, 1..60).prop_map(|v| v.concat())
}

proptest! {
    /// ADR-0052 decision 5 and DoD 2: for random terminal byte streams,
    /// applying diff(a -> b) to a gives b's hash, through the wire encoding,
    /// whatever the chunking and whenever the client asks.
    #[test]
    fn applying_the_diff_to_the_clients_state_gives_the_hosts_hash(
        stream in arb_stream(),
        cuts in proptest::collection::vec(1usize..64, 1..12),
        resize_at in proptest::option::of(0usize..12),
    ) {
        let mut host = screen(10, 40);
        let mut client_num = 0u64;
        let mut client = ScreenState::blank(10, 40).unwrap();
        let mut pos = 0;
        for (i, step) in cuts.iter().cycle().take(cuts.len().max(6)).enumerate() {
            let end = (pos + step * 7).min(stream.len());
            feed(&mut host, &stream[pos..end]);
            pos = end;
            if resize_at == Some(i) {
                host.resize(12, 33);
            }
            if let Some(u) = host.update_since(client_num) {
                let wire = qsh_proto::screen::ScreenUpdate::decode(&u.encode()).unwrap();
                prop_assert_eq!(&wire, &u);
                let next = wire.apply(&client).expect("hash must match");
                prop_assert_eq!(next.hash(), host.snapshot().hash());
                prop_assert!(next.is_valid());
                client = next;
                client_num = u.new_num;
            }
        }
        feed(&mut host, &stream[pos..]);
        if let Some(u) = host.update_since(client_num) {
            let next = u.apply(&client).expect("hash must match");
            prop_assert_eq!(next, host.snapshot());
        } else {
            prop_assert_eq!(client, host.snapshot());
        }
    }
}

// ---- effects ----

#[test]
fn title_bell_clipboard_and_hyperlink_become_effects_in_order() {
    let mut s = screen(3, 40);
    feed(
        &mut s,
        b"\x1b]0;my title\x07\x07\x07\x1b]52;c;aGVsbG8=\x1b\\\
          \x1b]8;id=1;https://example.com/a;b\x1b\\link\x1b]8;;\x1b\\",
    );
    let u = s.update_since(0).unwrap();
    // A full-screen update carries only the title; ask from a retained base
    // for the rest.
    assert_eq!(u.effects, vec![Effect::Title("my title".into())]);
    let mut s = screen(3, 40);
    feed(&mut s, b"x");
    let base = s.cut().num;
    feed(
        &mut s,
        b"\x1b]0;my title\x07\x07\x07\x1b]52;c;aGVsbG8=\x1b\\\
          \x1b]8;id=1;https://example.com/a;b\x1b\\link\x1b]8;;\x1b\\",
    );
    let u = s.update_since(base).unwrap();
    assert_eq!(
        u.effects,
        vec![
            Effect::Title("my title".into()),
            Effect::Bell,
            Effect::Clipboard {
                selection: "c".into(),
                data: "aGVsbG8=".into()
            },
            Effect::Hyperlink {
                params: "id=1".into(),
                uri: "https://example.com/a;b".into()
            },
            Effect::Hyperlink {
                params: String::new(),
                uri: String::new()
            },
        ]
    );
    assert_eq!(
        u.apply(&s.cuts[s.cuts.len() - 2].state).unwrap(),
        s.snapshot()
    );
}

#[test]
fn effects_are_sanitised_and_bounded() {
    let mut s = screen(3, 40);
    feed(&mut s, b"x");
    let base = s.cut().num;
    // Control characters in a title are dropped, an over-long title is cut,
    // an over-long clipboard payload and a query are not forwarded.
    let long = "a".repeat(5000);
    feed(&mut s, format!("\x1b]2;a\x01b\x1bc{long}\x07").as_bytes());
    feed(
        &mut s,
        format!("\x1b]52;c;{}\x07", "A".repeat(70_000)).as_bytes(),
    );
    feed(&mut s, b"\x1b]52;c;?\x07");
    for _ in 0..(MAX_EFFECT_TEST_SPAM) {
        feed(&mut s, b"\x1b]2;t\x07\x07");
    }
    let u = s.update_since(base).unwrap();
    let Effect::Title(t) = &u.effects[0] else {
        panic!("{:?}", u.effects)
    };
    assert!(t.starts_with("ab") && t.len() <= 1024 && !t.contains('\x1b'));
    assert!(u.effects.len() <= qsh_proto::screen::MAX_EFFECTS);
    assert!(
        !u.effects
            .iter()
            .any(|e| matches!(e, Effect::Clipboard { .. }))
    );
    assert!(s.effects_dropped() >= 1);
    // The cap keeps the update decodable.
    assert!(qsh_proto::screen::ScreenUpdate::decode(&u.encode()).is_ok());
}

const MAX_EFFECT_TEST_SPAM: usize = 200;

// ---- query answers (ADR-0052 decision 3) ----

#[test]
fn da1_da2_and_status_reports_are_answered() {
    assert_eq!(answers_to(b"\x1b[c"), b"\x1b[?62;22c");
    assert_eq!(answers_to(b"\x1b[0c"), b"\x1b[?62;22c");
    assert_eq!(answers_to(b"\x1b[>c"), b"\x1b[>0;0;0c");
    assert_eq!(answers_to(b"\x1b[>0c"), b"\x1b[>0;0;0c");
    assert_eq!(answers_to(b"\x1b[5n"), b"\x1b[0n");
}

#[test]
fn cursor_position_report_uses_the_emulators_cursor() {
    assert_eq!(answers_to(b"\x1b[6n"), b"\x1b[1;1R");
    assert_eq!(answers_to(b"\x1b[5;10H\x1b[6n"), b"\x1b[5;10R");
    assert_eq!(answers_to(b"ab\x1b[?6n"), b"\x1b[?1;3R");
    // At the right margin the cursor is reported inside the screen.
    let mut s = screen(24, 80);
    feed(&mut s, "x".repeat(80).as_bytes());
    feed(&mut s, b"\x1b[6n");
    assert_eq!(s.take_answers(), b"\x1b[1;80R");
}

#[test]
fn decrqm_answers_the_modes_the_emulator_implements() {
    assert_eq!(answers_to(b"\x1b[?2004$p"), b"\x1b[?2004;2$y");
    assert_eq!(answers_to(b"\x1b[?2004h\x1b[?2004$p"), b"\x1b[?2004;1$y");
    assert_eq!(answers_to(b"\x1b[?25$p"), b"\x1b[?25;1$y");
    assert_eq!(answers_to(b"\x1b[?25l\x1b[?25$p"), b"\x1b[?25;2$y");
    assert_eq!(answers_to(b"\x1b[?1h\x1b[?1$p"), b"\x1b[?1;1$y");
    assert_eq!(answers_to(b"\x1b[?1049h\x1b[?1049$p"), b"\x1b[?1049;1$y");
    assert_eq!(answers_to(b"\x1b[?1006h\x1b[?1006$p"), b"\x1b[?1006;1$y");
    assert_eq!(answers_to(b"\x1b[?1002h\x1b[?1002$p"), b"\x1b[?1002;1$y");
    // Not implemented: no answer.
    assert_eq!(answers_to(b"\x1b[?2026$p"), b"");
    assert_eq!(answers_to(b"\x1b[?7727$p"), b"");
}

#[test]
fn osc_colour_queries_are_answered_only_with_client_colours() {
    assert_eq!(answers_to(b"\x1b]10;?\x07\x1b]11;?\x1b\\"), b"");
    let mut s = screen(24, 80);
    s.set_client_colors(Some([0xe0, 0xe0, 0xe0]), Some([0x1e, 0x20, 0x30]));
    feed(&mut s, b"\x1b]10;?\x07\x1b]11;?\x1b\\");
    assert_eq!(
        s.take_answers(),
        b"\x1b]10;rgb:e0e0/e0e0/e0e0\x1b\\\x1b]11;rgb:1e1e/2020/3030\x1b\\"
    );
    // Only the colour the client reported.
    let mut s = screen(24, 80);
    s.set_client_colors(None, Some([1, 2, 3]));
    feed(&mut s, b"\x1b]10;?\x07\x1b]11;?\x07");
    assert_eq!(s.take_answers(), b"\x1b]11;rgb:0101/0202/0303\x1b\\");
    // Setting a colour is not a query.
    assert_eq!(answers_to(b"\x1b]10;rgb:ff/00/00\x07"), b"");
}

#[test]
fn nothing_else_is_answered() {
    for q in [
        &b"\x1b[>q"[..],         // XTVERSION
        b"\x1b[?u",              // kitty keyboard
        b"\x1b_Gi=1,a=q;\x1b\\", // kitty graphics
        b"\x1b[?1;1;0S",         // sixel/graphics attributes
        b"\x1b[18t",             // window size report
        b"\x1b[15n",             // printer status
        b"\x1b[?15n",            // printer status
        b"\x1b[?996n",           // colour scheme
        b"\x1b]52;c;?\x07",      // clipboard read
        b"\x1b]4;1;?\x07",       // palette
        b"\x1b[2$p",             // ANSI-mode DECRQM
        b"\x1b[1;2c",            // DA1 with arguments
        b"\x1bP$qm\x1b\\",       // DECRQSS
    ] {
        assert_eq!(answers_to(q), b"", "{:?}", String::from_utf8_lossy(q));
    }
}

#[test]
fn answers_are_taken_once_and_bounded() {
    let mut s = screen(24, 80);
    feed(&mut s, b"\x1b[c");
    assert_eq!(s.take_answers(), b"\x1b[?62;22c");
    assert_eq!(s.take_answers(), b"");
    feed(&mut s, "\x1b[c".repeat(5000).as_bytes());
    let a = s.take_answers();
    assert!(!a.is_empty() && a.len() <= 4096, "{}", a.len());
}

// ---- scrolled-off lines (decision 10) ----

#[test]
fn lines_scrolled_off_the_top_come_out_in_order() {
    let mut s = screen(4, 20);
    for i in 0..10 {
        feed(&mut s, format!("line {i}\r\n").as_bytes());
    }
    let h = s.take_history();
    assert_eq!(h.skipped, 0);
    // 10 lines and a final newline on a 4 row screen: rows 0..=6 left it.
    let texts: Vec<_> = h.lines.iter().map(|l| l.trim_end()).collect();
    assert_eq!(
        texts,
        [
            "line 0", "line 1", "line 2", "line 3", "line 4", "line 5", "line 6"
        ]
    );
    assert!(s.take_history().lines.is_empty());
    feed(&mut s, b"more\r\n");
    assert_eq!(s.take_history().lines, ["line 7"]);
}

#[test]
fn history_keeps_sgr_and_skips_the_alternate_screen() {
    let mut s = screen(2, 10);
    feed(&mut s, b"\x1b[31mred\x1b[0m\r\nb\r\nc\r\n");
    let h = s.take_history();
    assert!(
        h.lines[0].contains("\x1b[") && h.lines[0].contains("red"),
        "{:?}",
        h.lines
    );
    feed(&mut s, b"\x1b[?1049h");
    for _ in 0..10 {
        feed(&mut s, b"alt\r\n");
    }
    assert!(s.take_history().lines.is_empty());
    feed(&mut s, b"\x1b[?1049l");
    assert_eq!(s.snapshot().modes.flags & Modes::ALT_SCREEN, 0);
}

#[test]
fn history_is_capped_and_reports_what_it_dropped() {
    let mut s = HostScreen::new(ScreenOptions {
        rows: 2,
        cols: 10,
        history_rows: 5,
        history_bytes: 1 << 20,
    });
    for i in 0..20 {
        feed(&mut s, format!("n{i}\r\n").as_bytes());
    }
    let h = s.take_history();
    assert_eq!(h.lines.len(), 5);
    assert_eq!(h.skipped, 14);
    // The first rows are kept in order; the rest of the flood is counted.
    assert!(h.lines[0].starts_with("n0"), "{:?}", h.lines);
    assert!(h.lines[4].starts_with("n4"));
    // The byte cap bounds it too.
    let mut s = HostScreen::new(ScreenOptions {
        rows: 2,
        cols: 10,
        history_rows: 1000,
        history_bytes: 64,
    });
    for _ in 0..50 {
        feed(&mut s, b"0123456789\r\n");
    }
    let h = s.take_history();
    assert!(h.lines.iter().map(String::len).sum::<usize>() <= 64);
    assert!(h.skipped > 0);
}

#[test]
fn a_flood_is_counted_not_formatted_and_reported_once_taken() {
    let mut s = HostScreen::new(ScreenOptions {
        rows: 4,
        cols: 20,
        history_rows: 100,
        history_bytes: 1 << 20,
    });
    // 10_000 lines across many feeds with no take in between.
    for i in 0..10_000 {
        feed(&mut s, format!("flood {i}\r\n").as_bytes());
    }
    let h = s.take_history();
    // 10_000 newlines on a 4 row screen: rows 0..=9_996 scrolled off.
    assert_eq!(h.lines.len(), 100);
    assert_eq!(h.skipped, 9_997 - 100);
    assert!(h.lines[0].starts_with("flood 0"), "{:?}", h.lines[0]);
    assert!(h.lines[99].starts_with("flood 99"));
    // Taken once: the counters start over and rows are kept again.
    feed(&mut s, b"x\r\ny\r\nz\r\nw\r\n");
    let h = s.take_history();
    assert_eq!(h.skipped, 0);
    assert!(h.lines.len() >= 3);
}

#[test]
fn history_off_counts_every_row() {
    let mut s = HostScreen::new(ScreenOptions {
        rows: 2,
        cols: 10,
        history_rows: 0,
        history_bytes: 1 << 20,
    });
    for _ in 0..10 {
        feed(&mut s, b"x\r\n");
    }
    let h = s.take_history();
    assert!(h.lines.is_empty());
    assert_eq!(h.skipped, 9);
}

// ---- ConPTY-style output ----

#[test]
fn conpty_style_redraws_land_on_the_right_cells() {
    // ConPTY paints with absolute cursor moves and clears instead of
    // newlines: hide the cursor, clear, home, set the title, paint rows by
    // position, erase to the end of line, show the cursor.
    let mut s = screen(4, 20);
    feed(
        &mut s,
        b"\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;C:\\WINDOWS\\system32\\cmd.exe\x07\
          Microsoft Windows\x1b[K\x1b[2;1HC:\\>dir\x1b[K\x1b[?25h\x1b[2;7H",
    );
    let st = s.snapshot();
    assert_eq!(row_text(&st, 0), "Microsoft Windows");
    assert_eq!(row_text(&st, 1), "C:\\>dir");
    assert_eq!((st.cursor_row, st.cursor_col), (1, 6));
    assert_eq!(st.modes.flags & Modes::CURSOR_HIDDEN, 0);
    // A later partial repaint rewrites only the cells it names.
    feed(
        &mut s,
        b"\x1b[?25l\x1b[2;5Hcd\x1b[K\x1b[3;1H\x1b[1Mnext\x1b[?25h",
    );
    let st = s.snapshot();
    assert_eq!(row_text(&st, 0), "Microsoft Windows");
    assert_eq!(row_text(&st, 1), "C:\\>cd");
    assert_eq!(row_text(&st, 2), "next");
    // CRLF-only output (no cursor addressing) works as well.
    feed(&mut s, b"\x1b[2J\x1b[Hone\r\ntwo\r\n");
    let st = s.snapshot();
    assert_eq!(
        (row_text(&st, 0), row_text(&st, 1)),
        ("one".into(), "two".into())
    );
    let u = s.update_since(0).unwrap();
    assert_eq!(
        u.effects,
        vec![Effect::Title("C:\\WINDOWS\\system32\\cmd.exe".into())]
    );
}

// ---- cost ----

#[test]
fn a_large_chunk_is_fed_in_bounded_slices_and_stays_cheap() {
    // Worst-ish content per byte: SGR changes between wide characters on
    // every cell, scrolling the whole time.
    let line = "\x1b[31m한\x1b[44mx\x1b[0m\x1b[1;38;2;1;2;3m글\x1b[0m".repeat(12) + "\r\n";
    let mut chunk = Vec::new();
    while chunk.len() < FEED_SLICE {
        chunk.extend_from_slice(line.as_bytes());
    }
    chunk.truncate(FEED_SLICE);
    let mut s = screen(24, 80);
    let n = 200;
    let t = Instant::now();
    for _ in 0..n {
        feed(&mut s, &chunk);
    }
    let per_chunk = t.elapsed() / n;
    // Generous even for a debug build on a loaded runner; the measured
    // release cost is orders below it. The point is that one pump chunk is
    // bounded CPU, not a function of what the consumer does.
    assert!(per_chunk < Duration::from_millis(100), "{per_chunk:?}");
    // A feed larger than one slice splits (and still produces the same
    // screen as feeding it in pieces).
    let mut big = chunk.repeat(4);
    big.extend_from_slice(b"\x1b[1;1Hend");
    let mut a = screen(24, 80);
    let mut b = screen(24, 80);
    feed(&mut a, &big);
    for piece in big.chunks(1000) {
        feed(&mut b, piece);
    }
    assert_eq!(a.snapshot().hash(), b.snapshot().hash());
}

/// The history must not cost the pump a flood: with the default history the
/// emulator keeps within 70% of the speed it has with history off (formatting
/// every scrolled-off row used to cut it to about 40%). Best of three on a
/// few MiB once the history is full, so a loaded CI host moves both sides
/// alike.
#[test]
fn history_costs_a_flood_almost_nothing() {
    let line = b"0001 the quick brown fox jumps over the lazy dog 0123456789 abcdefghijklmnopqrstuvwxyz\r\n";
    let chunk: Vec<u8> = line.repeat(180);
    let run = |history_rows: usize| {
        (0..3)
            .map(|_| {
                let mut s = HostScreen::new(ScreenOptions {
                    history_rows,
                    ..ScreenOptions::default()
                });
                // Fill the history first: the claim is about a flood that
                // has already filled it, not the one-off formatting of the
                // first history_rows rows.
                let warm = (history_rows / 180 + 2) as u64;
                for i in 0..warm {
                    s.feed(&chunk, i);
                }
                let t = Instant::now();
                for i in warm..warm + 60 {
                    s.feed(&chunk, i);
                }
                std::hint::black_box(&s);
                t.elapsed()
            })
            .min()
            .unwrap()
    };
    let off = run(0);
    let on = run(DEFAULT_HISTORY_ROWS);
    assert!(
        on.as_secs_f64() < off.as_secs_f64() / 0.7,
        "history on {on:?} vs off {off:?}"
    );
}

use std::time::Duration;

/// DoD 11 groundwork: emulator throughput on 100 MB of `cat`-like output
/// against the same loop without feeding it. Run with
/// `cargo nextest run -p qsh-core --release --run-ignored only -- screen_throughput --no-capture`.
///
/// The "without" side is the pump's own work per chunk, the ring append. The
/// ratio printed here is the emulator's share on a CPU-only loop, which is a
/// worse case than a session (a PTY and QUIC add time the emulator does not).
#[test]
#[ignore = "measurement, run explicitly in release"]
fn screen_throughput_on_100mb_of_cat_output() {
    use crate::broker::ring::{RING_CHUNK_MAX, ReplayRing, ReplayStore};

    let text: Vec<u8> = (0..1500)
        .flat_map(|i| format!("{i:5} the quick brown fox jumps over the lazy dog 0123456789 abcdefghijklmnopqrstuvwxyz\r\n").into_bytes())
        .collect();
    let mut total = 0usize;
    let mut chunks = Vec::new();
    while total < 100 * 1024 * 1024 {
        let chunk: Vec<u8> = text
            .iter()
            .copied()
            .cycle()
            .skip(total % 997)
            .take(RING_CHUNK_MAX)
            .collect();
        total += chunk.len();
        chunks.push(chunk);
        if chunks.len() == 64 {
            break;
        }
    }
    let rounds = (100 * 1024 * 1024) / (chunks.len() * RING_CHUNK_MAX) + 1;
    let bytes = (rounds * chunks.len() * RING_CHUNK_MAX) as f64;

    let run = |feed_screen: bool, history_rows: usize| {
        let mut ring = ReplayRing::new(8 * 1024 * 1024);
        let mut s = HostScreen::new(ScreenOptions {
            history_rows,
            ..ScreenOptions::default()
        });
        let t = Instant::now();
        for _ in 0..rounds {
            for c in &chunks {
                ring.push(c);
                if feed_screen {
                    let end = ring.end();
                    s.feed(c, end);
                    std::hint::black_box(s.take_answers());
                }
            }
        }
        std::hint::black_box(s.snapshot());
        t.elapsed()
    };
    // Warm up, then take the best of three of each.
    run(true, DEFAULT_HISTORY_ROWS);
    let best = |f: bool, h: usize| (0..3).map(|_| run(f, h)).min().unwrap();
    let without = best(false, 0);
    let no_history = best(true, 0);
    println!(
        "screen_throughput: emulator without history {:.0} MiB/s",
        bytes / (1024.0 * 1024.0) / no_history.as_secs_f64()
    );
    let with = best(true, DEFAULT_HISTORY_ROWS);
    let mb = bytes / (1024.0 * 1024.0);
    println!(
        "screen_throughput: {mb:.0} MiB; ring only {:.0} MiB/s; ring + emulator {:.0} MiB/s; ratio {:.3}",
        mb / without.as_secs_f64(),
        mb / with.as_secs_f64(),
        without.as_secs_f64() / with.as_secs_f64(),
    );
}

/// The same measurement end to end: `cat` of a 100 MB file through a real
/// PTY into a session actor, with the host emulator off and on. Unix only.
/// The ring is the only consumer, so this is the host side of DoD 11 minus
/// QUIC. Run with
/// `cargo nextest run -p qsh-core --release --run-ignored only -- screen_throughput_through_a_pty --no-capture`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement, run explicitly in release"]
async fn screen_throughput_through_a_pty_cat_of_100mb() {
    use std::io::Write;
    use std::sync::Arc;

    use crate::broker::clock::TestClock;
    use crate::broker::session::{SessionActor, SessionConfig, SessionSpec};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    let line = b"the quick brown fox jumps over the lazy dog 0123456789 abcdefghijklmnopqrstuvwxyz abcdef\n";
    let block = line.repeat(1000);
    let mut size = 0u64;
    while size < 100 * 1024 * 1024 {
        f.write_all(&block).unwrap();
        size += block.len() as u64;
    }
    drop(f);

    let run = |screen: bool| {
        let path = path.clone();
        async move {
            let clock = TestClock::new();
            let spec = SessionSpec {
                argv: vec!["/bin/cat".into(), path.display().to_string()],
                term: Some("xterm".into()),
                cols: 80,
                rows: 24,
                ..SessionSpec::default()
            };
            let (handle, actor) = SessionActor::create(
                "01BENCH".into(),
                "2026-01-01T00:00:00Z".into(),
                "device:bench".into(),
                Arc::new(clock),
                &spec,
                Box::new(crate::pty::PtySource::new()),
                SessionConfig {
                    screen,
                    ..SessionConfig::default()
                },
            )
            .unwrap();
            let t = Instant::now();
            tokio::spawn(actor.run());
            // `cat` through the line discipline turns \n into \r\n.
            loop {
                if handle.info().state == crate::broker::session::SessionState::Exited {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let elapsed = t.elapsed();
            let bytes = handle.info().last_sequence;
            (
                bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64(),
                bytes,
            )
        }
    };
    let (off_a, bytes) = run(false).await;
    let (on_a, _) = run(true).await;
    let (off_b, _) = run(false).await;
    let (on_b, _) = run(true).await;
    let (off, on) = (off_a.max(off_b), on_a.max(on_b));
    let ratio = on / off;
    println!(
        "screen_throughput_pty: {} MiB through a PTY; emulator off {off:.0} MiB/s; on {on:.0} MiB/s; ratio {ratio:.3}",
        bytes >> 20,
    );
    // `QSH_PERF_OUT`: one line for the nightly trend, written before the
    // assertion so a red ratio is still recorded (`.github/workflows/perf.yml`).
    if let Some(out) = std::env::var_os("QSH_PERF_OUT").filter(|p| !p.is_empty()) {
        let line = format!(
            "{{\"test\":\"screen_throughput\",\"screen_cat_ratio\":{ratio:.4},\"emulator_off_mibps\":{off:.1},\"emulator_on_mibps\":{on:.1}}}\n"
        );
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .unwrap();
        file.write_all(line.as_bytes()).unwrap();
    }
    // ADR-0052 decision 18 item 11: at least half of the emulator-off rate.
    assert!(
        ratio >= SCREEN_CAT_RATIO_FLOOR,
        "emulator on {on:.0} MiB/s is {ratio:.3} of off {off:.0} MiB/s (floor {SCREEN_CAT_RATIO_FLOOR})"
    );
}

/// ADR-0052 decision 18 item 11; `xtask/src/perf.rs` holds the same floor for
/// the nightly judge.
#[cfg(unix)]
const SCREEN_CAT_RATIO_FLOOR: f64 = 0.5;

// ---- U+FE0F (threat-model C22) ----

const VS16: &str = "\u{fe0f}";

/// Short inputs `vt100` 0.18.1 panics on without [`Vs16Filter`].
fn vs16_repros() -> Vec<Vec<u8>> {
    let mut wrapped = b"RRRTRRRRR\x1b[C0".to_vec();
    wrapped.extend_from_slice("\u{fe0f}0\x1b[H0\u{fe0f}0é".as_bytes());
    vec![
        format!("0{VS16}").into_bytes(),
        format!("a0{VS16}{VS16}b#{VS16}\r\n\u{2764}{VS16}").into_bytes(),
        wrapped,
    ]
}

#[test]
fn u_fe0f_never_panics_the_emulator_at_any_small_size() {
    for input in vs16_repros() {
        for rows in 1..=6 {
            for cols in 1..=7 {
                let mut s = screen(rows, cols);
                feed(&mut s, &input);
                // The state layer reads the screen back without trouble.
                let state = s.snapshot();
                assert!(state.is_valid());
                assert!(
                    state
                        .grid
                        .iter()
                        .flat_map(|r| &r.cells)
                        .all(|c| !c.text.contains('\u{fe0f}')),
                    "{rows}x{cols}"
                );
            }
        }
    }
}

#[test]
fn u_fe0f_is_ignored_and_its_base_character_stays_narrow() {
    let mut s = screen(2, 10);
    feed(&mut s, format!("0{VS16}x\u{2764}{VS16}y").as_bytes());
    assert_eq!(row_text(&s.snapshot(), 0), "0x\u{2764}y");
}

#[test]
fn u_fe0f_split_at_every_byte_boundary_gives_the_unsplit_screen() {
    let input = format!("a{VS16}b0{VS16}{VS16}\u{ac00}{VS16}\r\nc").into_bytes();
    let mut whole = screen(3, 3);
    feed(&mut whole, &input);
    for a in 0..=input.len() {
        for b in a..=input.len() {
            let mut split = screen(3, 3);
            for part in [&input[..a], &input[a..b], &input[b..]] {
                feed(&mut split, part);
            }
            assert_eq!(split.snapshot().hash(), whole.snapshot().hash(), "{a} {b}");
        }
    }
}

/// Found by `host_emulator_input`: removing a selector would have joined the
/// bytes around it into a new one (`EF` + `EF B8 8F` + `B8 8F`).
#[test]
fn u_fe0f_cannot_be_rebuilt_from_the_bytes_around_one() {
    let mut f = Vs16Filter::default();
    let out = f.filter(&[b'0', 0xEF, 0xEF, 0xB8, 0x8F, 0xB8, 0x8F, b'0']);
    assert!(!out.windows(3).any(|w| w == Vs16Filter::SEQ), "{out:02x?}");
    // The reported fuzz input, on its 3x1 screen and split anywhere.
    let input = [
        b'R', b'0', 0xEF, 0xEF, 0xB8, 0x8F, 0xB8, 0x8F, b'0', 0x1b, b'[', 0x19, 0x19, b'{', b'T',
        b'R', b'R', 0x1c, b'R', b'R', b'0', b'[', b'{', 0, b'H',
    ];
    for rows in 1..=4 {
        for cols in 1..=4 {
            for at in 0..=input.len() {
                let mut s = screen(rows, cols);
                feed(&mut s, &input[..at]);
                feed(&mut s, &input[at..]);
                assert!(s.snapshot().is_valid());
            }
        }
    }
}

#[test]
fn a_cut_off_prefix_of_u_fe0f_is_released_when_the_next_byte_is_not_the_rest() {
    let mut f = Vs16Filter::default();
    assert_eq!(&*f.filter(&[b'a', 0xEF, 0xB8]), b"a");
    assert_eq!(&*f.filter(b"x"), &[0xEF, 0xB8, b'x']);
    assert_eq!(&*f.filter(&[0xEF]), b"");
    assert_eq!(&*f.filter(&[0xEF, 0xB8, 0x8F, b'z']), &[0xEF, 0, b'z']);
}

proptest! {
    /// The filter equals a left-to-right replacement of every `EF B8 8F` in
    /// the whole stream, whatever the chunking, once the held bytes are
    /// released by a byte that cannot continue them.
    #[test]
    fn the_filter_replaces_exactly_the_u_fe0f_sequences(
        stream in proptest::collection::vec(
            proptest::sample::select(vec![0xEFu8, 0xB8, 0x8F, b'0', b'A']), 0..64),
        cuts in proptest::collection::vec(0usize..8, 0..12),
    ) {
        let mut expected = Vec::new();
        let mut i = 0;
        while i < stream.len() {
            if stream[i..].starts_with(&Vs16Filter::SEQ) {
                expected.push(0);
                i += 3;
            } else {
                expected.push(stream[i]);
                i += 1;
            }
        }
        let mut f = Vs16Filter::default();
        let mut got = Vec::new();
        let mut rest = &stream[..];
        for c in cuts {
            let (head, tail) = rest.split_at(c.min(rest.len()));
            got.extend_from_slice(&f.filter(head));
            rest = tail;
        }
        got.extend_from_slice(&f.filter(rest));
        got.extend_from_slice(&f.filter(b"!"));
        got.pop();
        prop_assert!(!got.windows(3).any(|w| w == Vs16Filter::SEQ));
        prop_assert_eq!(got, expected);
    }

    /// No mix of the characters that matter for cell widening panics the
    /// emulator, on any small screen and any chunking.
    #[test]
    fn widening_sequences_never_panic_the_emulator(
        rows in 1u16..6,
        cols in 1u16..8,
        parts in proptest::collection::vec(
            proptest::sample::select(vec![
                "0", "#", "a", "\u{2764}", "\u{fe0f}", "\u{ac00}", "\u{301}", "é",
                "\r\n", "\x1b[C", "\x1b[H", "\x1b[D", "\x1b[2J", "R",
            ]), 0..48),
        cut in 1usize..9,
    ) {
        let mut s = screen(rows, cols);
        let bytes = parts.concat().into_bytes();
        for chunk in bytes.chunks(cut) {
            feed(&mut s, chunk);
        }
        prop_assert!(s.snapshot().is_valid());
    }
}
