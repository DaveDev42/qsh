use std::time::Duration;

use super::schedule::Schedule;
use super::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// ADR-0054 decision 14: the offsets are exactly these eight.
#[test]
fn offsets_are_the_adr_table() {
    assert_eq!(PUNCH_OFFSETS_MS, [0, 50, 100, 200, 400, 800, 1600, 3200]);
}

/// The schedule hands out one round per offset, at that offset, and no
/// other time.
#[test]
fn schedule_rounds_fall_due_at_their_offsets() {
    let mut s = Schedule::new(2);
    let mut seen = Vec::new();
    for t in 0..=3300u64 {
        let due = s.due(ms(t));
        if !due.is_empty() {
            seen.push((t, due));
        }
    }
    let at: Vec<u64> = seen.iter().map(|(t, _)| *t).collect();
    assert_eq!(at, PUNCH_OFFSETS_MS.to_vec());
    for (_, due) in &seen {
        assert_eq!(due, &vec![0, 1], "every candidate in every round");
    }
    assert_eq!(s.next_at(), None);
    assert_eq!(s.sent(), s.total());
}

/// A late caller gets the rounds it missed, once.
#[test]
fn a_late_caller_catches_up_without_repeats() {
    let mut s = Schedule::new(1);
    assert_eq!(s.due(ms(120)).len(), 3, "offsets 0, 50, 100");
    assert_eq!(s.due(ms(120)).len(), 0, "nothing twice");
    assert_eq!(s.next_at(), Some(ms(200)));
    assert_eq!(s.due(ms(10_000)).len(), 5, "the remaining offsets");
    assert_eq!(s.due(ms(20_000)).len(), 0);
}

/// ADR-0054 decision 14 and DoD 6: at most eight candidates times eight
/// offsets, 64 datagrams, 1 KiB.
#[test]
fn the_datagram_budget_is_sixty_four() {
    let mut s = Schedule::new(MAX_PUNCH_CANDIDATES);
    assert_eq!(s.due(Duration::from_secs(60)).len(), MAX_PUNCH_DATAGRAMS);
    assert_eq!(MAX_PUNCH_DATAGRAMS, 64);
    assert_eq!(
        MAX_PUNCH_DATAGRAMS * qsh_proto::punch::PUNCH_DATAGRAM_LEN,
        1024
    );
}

#[test]
fn an_empty_schedule_sends_nothing() {
    let mut s = Schedule::new(0);
    assert!(s.due(Duration::from_secs(60)).is_empty());
    assert_eq!(s.total(), 0);
}

/// The ADR's numbers, one row each.
#[test]
fn constants_match_the_adr() {
    assert_eq!(PUNCH_INITIAL_RTT, ms(100));
    assert_eq!(PUNCH_TARGET_WINDOW, ms(6000));
    assert_eq!(MAX_HANDSHAKES_PER_OFFER, 4);
    assert_eq!(MAX_PEER_REFLEXIVE, 4);
    assert_eq!(MAX_PUNCH_CANDIDATES, 8);
    assert_eq!(PUNCH_SIGNAL_BUDGET + PUNCH_WINDOW, ms(8000));
}
