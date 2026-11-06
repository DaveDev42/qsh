//! Fuzzes the host terminal emulator's input (ADR-0052 decision 2): the
//! bytes a program writes to the PTY, which the output pump feeds to
//! `qsh_core::screen::HostScreen`. Arbitrary program output is the
//! attacker-controlled input here (a hostile file `cat`ed, a hostile
//! server's reverse leg), so the emulator and the state/diff layer on top
//! of it must be total.
//!
//! The first two bytes pick the screen size and where to resize, the rest is
//! cut into chunks at positions taken from the data itself and fed with
//! increasing `end_seq`. After each chunk a client is simulated: it asks
//! for an update from its last state, decodes the wire form, applies it
//! and checks the hash.
//!
//! Invariants: no panic; every update decodes from its own encoding and
//! applies to the client's state with a matching hash; the client state is
//! structurally valid and equals the host's snapshot; answers per chunk are
//! bounded (4 KiB), effects per update are bounded, history stays within
//! its row cap.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::screen::{HostScreen, ScreenOptions};
use qsh_proto::screen::{MAX_EFFECTS, ScreenState, ScreenUpdate};

fuzz_target!(|data: &[u8]| {
    let [rows, cols, resize_at, rest @ ..] = data else {
        return;
    };
    let rows = u16::from(*rows % 40) + 1;
    let cols = u16::from(*cols % 120) + 1;
    let mut host = HostScreen::new(ScreenOptions {
        rows,
        cols,
        history_rows: 64,
        history_bytes: 8 * 1024,
    });
    host.set_client_colors(Some([1, 2, 3]), Some([250, 251, 252]));
    let mut client = ScreenState::blank(rows, cols).unwrap();
    let mut client_num = 0u64;
    let mut seq = 0u64;
    let mut pos = 0usize;
    let mut step = 0u8;
    while pos < rest.len() {
        // The chunk length comes from the data, 1..=300 bytes.
        let len = (usize::from(rest[pos]) % 300) + 1;
        let end = (pos + 1 + len).min(rest.len());
        let chunk = &rest[pos + 1..end];
        pos = end;
        seq += chunk.len() as u64;
        host.feed(chunk, seq);
        assert!(host.take_answers().len() <= 4096);
        step = step.wrapping_add(1);
        if step == *resize_at {
            host.resize(rows / 2 + 1, cols + 3);
        }
        if let Some(update) = host.update_since(client_num) {
            let wire = update.encode();
            let decoded = ScreenUpdate::decode(&wire).expect("own encoding decodes");
            assert_eq!(decoded, update);
            assert!(decoded.effects.len() <= MAX_EFFECTS);
            let next = decoded
                .apply(&client)
                .expect("the client reaches the host's hash");
            assert!(next.is_valid());
            client = next;
            client_num = decoded.new_num;
        }
        assert_eq!(client.hash(), host.snapshot().hash());
    }
    let history = host.take_history();
    assert!(history.lines.len() <= 64);
});
