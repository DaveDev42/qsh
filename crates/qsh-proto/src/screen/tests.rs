use proptest::prelude::*;

use super::*;

fn cell(text: &str, fg: Color, flags: u8) -> Cell {
    Cell {
        text: text.into(),
        fg,
        bg: Color::Default,
        flags,
    }
}

fn arb_color() -> impl Strategy<Value = Color> {
    prop_oneof![
        Just(Color::Default),
        any::<u8>().prop_map(Color::Idx),
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(r, g, b)| Color::Rgb(r, g, b)),
    ]
}

fn arb_cell() -> impl Strategy<Value = Cell> {
    (
        prop_oneof![
            4 => Just(String::new()),
            4 => "[a-z]{1}",
            1 => "[가-힣]{1}",
            1 => Just("e\u{301}".to_string()),
        ],
        arb_color(),
        arb_color(),
        0u8..32,
    )
        .prop_map(|(text, fg, bg, flags)| Cell {
            text: text.into(),
            fg,
            bg,
            flags,
        })
}

fn arb_state() -> impl Strategy<Value = ScreenState> {
    (1u16..12, 1u16..30).prop_flat_map(|(rows, cols)| {
        (
            proptest::collection::vec(
                (
                    proptest::collection::vec(arb_cell(), usize::from(cols)),
                    any::<bool>(),
                ),
                usize::from(rows),
            ),
            0..rows,
            0..cols,
            (0u8..32, 0u8..5, 0u8..3),
        )
            .prop_map(
                move |(grid, cursor_row, cursor_col, (flags, mouse_mode, mouse_encoding))| {
                    ScreenState {
                        rows,
                        cols,
                        cursor_row,
                        cursor_col,
                        modes: Modes {
                            flags,
                            mouse_mode,
                            mouse_encoding,
                        },
                        grid: grid
                            .into_iter()
                            .map(|(cells, wrapped)| Row { cells, wrapped })
                            .collect(),
                    }
                },
            )
    })
}

/// A state that mostly equals `base` with a few cells changed, so diffs have
/// both unchanged and changed rows.
fn mutate(base: &ScreenState, seed: &[(usize, usize, Cell)]) -> ScreenState {
    let mut s = base.clone();
    for (r, c, cell) in seed {
        let (r, c) = (r % usize::from(s.rows), c % usize::from(s.cols));
        s.grid[r].cells[c] = cell.clone();
    }
    s
}

proptest! {
    #[test]
    fn diff_of_unrelated_states_applies_to_the_new_hash(a in arb_state(), b in arb_state()) {
        let diff = ScreenDiff::between(&a, &b).unwrap();
        let applied = diff.apply(&a).unwrap();
        prop_assert_eq!(applied.hash(), b.hash());
        prop_assert_eq!(applied, b);
    }

    #[test]
    fn diff_of_a_small_edit_applies_and_round_trips(
        a in arb_state(),
        edits in proptest::collection::vec((0usize..64, 0usize..64, arb_cell()), 0..6),
    ) {
        let b = mutate(&a, &edits);
        let diff = ScreenDiff::between(&a, &b).unwrap();
        prop_assert_eq!(diff.apply(&a).unwrap().hash(), b.hash());
        let bytes = diff.encode();
        let decoded = ScreenDiff::decode(&bytes).unwrap();
        prop_assert_eq!(&decoded, &diff);
        prop_assert_eq!(decoded.encode(), bytes);
        prop_assert_eq!(decoded.apply(&a).unwrap().hash(), b.hash());
    }

    #[test]
    fn full_screen_diff_from_base_zero(b in arb_state()) {
        let blank = ScreenState::blank(b.rows, b.cols).unwrap();
        let diff = ScreenDiff::between(&blank, &b).unwrap();
        prop_assert_eq!(diff.apply(&blank).unwrap().hash(), b.hash());
        // A base of another size counts as blank, so the same diff applies.
        let other = ScreenState::blank(b.rows + 1, b.cols).unwrap();
        prop_assert_eq!(diff.apply(&other).unwrap().hash(), b.hash());
    }

    #[test]
    fn decoders_are_total_and_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(d) = ScreenDiff::decode(&bytes) {
            prop_assert_eq!(d.encode(), bytes.clone());
        }
        if let Ok(u) = ScreenUpdate::decode(&bytes) {
            prop_assert_eq!(u.encode(), bytes);
        }
    }

    #[test]
    fn canonical_hash_is_independent_of_how_the_state_was_reached(a in arb_state(), b in arb_state()) {
        // Base 0 means the blank screen (protocol §18.4), so the full-screen
        // diff is applied to a blank grid. It is not applied to `a`: a diff
        // carries only the cells that differ from its base, so cells of a
        // same-size `a` that `b` leaves blank would survive.
        let blank = ScreenState::blank(b.rows, b.cols).unwrap();
        let via_blank = ScreenDiff::between(&blank, &b).unwrap().apply(&blank).unwrap();
        let direct = ScreenDiff::between(&a, &b).unwrap().apply(&a).unwrap();
        prop_assert_eq!(via_blank.hash(), direct.hash());
        prop_assert_eq!(via_blank, direct);
    }
}

/// Regression for CI run 42305024031: the property used to apply the
/// full-screen diff to a same-size, non-blank `a`, which keeps `a`'s cells
/// wherever `b` is blank. The diff is right: a full screen is defined against
/// the blank screen (base 0), and only a differently sized base counts as blank.
#[test]
fn a_full_screen_diff_is_relative_to_blank_not_to_a_same_size_base() {
    let mut a = ScreenState::blank(10, 3).unwrap();
    a.grid[1].cells[0] = cell("e\u{301}", Color::Default, 0);
    let mut b = ScreenState::blank(10, 3).unwrap();
    b.grid[3].cells[2] = cell("x", Color::Default, 0);

    let blank = ScreenState::blank(10, 3).unwrap();
    let full = ScreenDiff::between(&blank, &b).unwrap();
    assert_eq!(full.apply(&blank).unwrap(), b);
    // Against a same-size non-blank base, a's cell that b leaves blank stays.
    assert_ne!(full.apply(&a).unwrap().hash(), b.hash());
    // The diff from a carries a to b, and a resized base counts as blank.
    assert_eq!(ScreenDiff::between(&a, &b).unwrap().apply(&a).unwrap(), b);
    let other = ScreenState::blank(11, 3).unwrap();
    assert_eq!(full.apply(&other).unwrap(), b);
}

#[test]
fn changed_cells_far_apart_get_separate_runs_and_near_ones_merge() {
    let a = ScreenState::blank(2, 40).unwrap();
    let mut b = a.clone();
    b.grid[0].cells[2] = cell("x", Color::Default, 0);
    b.grid[0].cells[4] = cell("y", Color::Default, 0);
    b.grid[0].cells[30] = cell("z", Color::Default, 0);
    let d = ScreenDiff::between(&a, &b).unwrap();
    assert_eq!(d.changes.len(), 1);
    let runs = &d.changes[0].runs;
    assert_eq!(runs.len(), 2);
    assert_eq!((runs[0].col, runs[0].cells.len()), (2, 3));
    assert_eq!((runs[1].col, runs[1].cells.len()), (30, 1));
}

#[test]
fn an_identical_state_has_an_empty_diff_and_a_wrap_only_change_has_no_runs() {
    let a = ScreenState::blank(3, 5).unwrap();
    let d = ScreenDiff::between(&a, &a).unwrap();
    assert!(d.changes.is_empty());
    let mut b = a.clone();
    b.grid[1].wrapped = true;
    let d = ScreenDiff::between(&a, &b).unwrap();
    assert_eq!(d.changes.len(), 1);
    assert!(d.changes[0].runs.is_empty());
    assert_eq!(d.apply(&a).unwrap(), b);
}

#[test]
fn the_state_hash_pins_the_canonical_encoding() {
    // A change to the canonical bytes changes every client's comparison, so
    // the value is pinned like a wire fixture: new encodings need a new hash
    // version (`docs/design/protocol.md` §18).
    let mut s = ScreenState::blank(2, 3).unwrap();
    s.grid[0].cells[0] = cell("a", Color::Idx(2), cell_flags::BOLD);
    s.cursor_col = 1;
    let mut want = vec![2, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0];
    want.extend_from_slice(&[0, 0x81, 0x01, 2, 1, b'a', 0, 0, 0, 0]);
    want.extend_from_slice(&[0; 7]);
    assert_eq!(s.canonical_bytes(), want);
    assert_eq!(s.hash(), s.clone().hash());
    let mut t = s.clone();
    t.cursor_col = 2;
    assert_ne!(s.hash(), t.hash());
}

fn sample_update() -> (ScreenState, ScreenState, ScreenUpdate) {
    let a = ScreenState::blank(2, 8).unwrap();
    let mut b = a.clone();
    b.grid[1].cells[3] = cell("한", Color::Rgb(1, 2, 3), cell_flags::WIDE);
    b.grid[1].cells[4] = Cell {
        flags: cell_flags::WIDE_CONT,
        ..Cell::default()
    };
    b.cursor_row = 1;
    b.cursor_col = 5;
    let update = ScreenUpdate {
        base_num: 3,
        new_num: 5,
        output_seq: 4096,
        diff: ScreenDiff::between(&a, &b).unwrap(),
        effects: vec![
            Effect::Title("t".into()),
            Effect::Bell,
            Effect::Clipboard {
                selection: "c".into(),
                data: "aGk=".into(),
            },
            Effect::Hyperlink {
                params: "id=1".into(),
                uri: "https://example.com/".into(),
            },
        ],
        state_hash: b.hash(),
    };
    (a, b, update)
}

#[test]
fn an_update_round_trips_applies_and_checks_the_hash() {
    let (a, b, update) = sample_update();
    let bytes = update.encode();
    let decoded = ScreenUpdate::decode(&bytes).unwrap();
    assert_eq!(decoded, update);
    assert_eq!(decoded.apply(&a).unwrap(), b);
    let mut bad = decoded;
    bad.state_hash[0] ^= 1;
    assert_eq!(bad.apply(&a), Err(ApplyError::HashMismatch));
}

#[test]
fn decode_rejects_each_malformed_field() {
    let (_, _, update) = sample_update();
    let good = update.encode();
    // Every strict prefix is truncated or otherwise refused, never accepted.
    for n in 0..good.len() {
        assert!(ScreenUpdate::decode(&good[..n]).is_err(), "prefix {n}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(ScreenUpdate::decode(&trailing).is_err());

    let mut u = update.clone();
    u.new_num = u.base_num;
    assert!(ScreenUpdate::decode(&u.encode()).is_err());

    let mut u = update.clone();
    u.effects = vec![Effect::Title("a\u{1b}]0;x".into())];
    assert!(ScreenUpdate::decode(&u.encode()).is_err());
    u.effects = vec![Effect::Clipboard {
        selection: "c".into(),
        data: "not base64!".into(),
    }];
    assert!(ScreenUpdate::decode(&u.encode()).is_err());
    u.effects = vec![Effect::Bell; MAX_EFFECTS + 1];
    assert!(ScreenUpdate::decode(&u.encode()).is_err());

    // Non-minimal varint.
    assert!(ScreenDiff::decode(&[0x81, 0x00]).is_err());
    // Oversize screen.
    let mut huge = Vec::new();
    for v in [u64::from(MAX_DIM), u64::from(MAX_DIM), 0, 0] {
        super::codec::put_varint(&mut huge, v);
    }
    assert!(ScreenDiff::decode(&huge).is_err());
}

#[test]
fn a_hostile_count_does_not_allocate() {
    // rows 24, cols 80, cursor 0,0, modes, then 2^62 changed rows.
    let mut b = vec![24, 80, 0, 0, 0, 0, 0];
    b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]);
    assert!(ScreenDiff::decode(&b).is_err());
}

#[test]
fn apply_refuses_what_decode_would_refuse() {
    let a = ScreenState::blank(2, 4).unwrap();
    let mut d = ScreenDiff::between(&a, &a).unwrap();
    d.changes.push(RowChange {
        row: 5,
        wrapped: false,
        runs: vec![],
    });
    assert_eq!(d.apply(&a), Err(ApplyError::OutOfRange));
    d.changes[0].row = 0;
    d.changes[0].runs.push(Run {
        col: 3,
        cells: vec![Cell::default(); 2],
    });
    assert_eq!(d.apply(&a), Err(ApplyError::OutOfRange));
    d.changes.clear();
    d.cursor_row = 2;
    assert_eq!(d.apply(&a), Err(ApplyError::BadHeader));
    d.rows = 0;
    assert_eq!(d.apply(&a), Err(ApplyError::BadSize));
}
