//! Fuzzes the screen diff codec of ADR-0052 decision 5 (`docs/design/
//! protocol.md` §18 draft): `ScreenDiff::decode` and `ScreenUpdate::decode`,
//! selected by the first input byte. The diff is the one structured,
//! length-and-count-heavy message of the screen path, so the harness
//! checks more than "no panic":
//!
//! - **canonical**: an accepted input re-encodes to the same bytes, so two
//!   implementations cannot disagree about what a message says;
//! - **applying is total**: an accepted diff applies to the blank screen of
//!   its size without panicking, giving a valid state, and applying it to a
//!   base of another size (counted as blank) gives the same state;
//! - **bounded**: decoding allocates nothing a short input could not pay
//!   for. This is not asserted directly (libFuzzer's RSS limit does it); the
//!   decoder checks every count against the bytes left before allocating.
//! - **hash is stable**: the state hash of the applied state is a function
//!   of the state only.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_proto::screen::{ScreenDiff, ScreenState, ScreenUpdate};

fn check_diff(diff: &ScreenDiff) {
    let blank = ScreenState::blank(diff.rows, diff.cols).expect("decode checked the size");
    let state = diff.apply(&blank).expect("a decoded diff applies to blank");
    assert!(state.is_valid());
    assert_eq!(state.hash(), state.clone().hash());
    // A base of another size counts as blank at the new size.
    let other = ScreenState::blank(1, 1).unwrap();
    assert_eq!(diff.apply(&other).unwrap(), state);
    // The diff between blank and the result applies back to the result.
    let again = ScreenDiff::between(&blank, &state).unwrap();
    assert_eq!(again.apply(&blank).unwrap(), state);
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    if which & 1 == 0 {
        if let Ok(diff) = ScreenDiff::decode(rest) {
            assert_eq!(diff.encode(), rest);
            check_diff(&diff);
        }
    } else if let Ok(update) = ScreenUpdate::decode(rest) {
        assert_eq!(update.encode(), rest);
        assert!(update.new_num > update.base_num);
        assert!(update.effects.iter().all(|e| e.is_valid()));
        check_diff(&update.diff);
    }
});
