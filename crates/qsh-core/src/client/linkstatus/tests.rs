use super::*;

fn t0() -> Instant {
    Instant::now()
}

fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
}

fn link(base: Instant, waiting_ms: Option<u64>, recovering: Option<u32>) -> LinkStatus {
    LinkStatus {
        last_reply: base,
        waiting_since: waiting_ms.map(|ms| at(base, ms)),
        recovering,
    }
}

#[test]
fn the_threshold_is_two_seconds_or_four_srtt() {
    assert_eq!(show_after(None), Duration::from_secs(2));
    assert_eq!(
        show_after(Some(Duration::from_millis(100))),
        Duration::from_secs(2)
    );
    assert_eq!(
        show_after(Some(Duration::from_millis(500))),
        Duration::from_secs(2)
    );
    assert_eq!(
        show_after(Some(Duration::from_millis(900))),
        Duration::from_millis(3600)
    );
}

#[test]
fn a_wait_shows_the_line_exactly_at_the_threshold() {
    let base = t0();
    let l = link(base, Some(0), None);
    let mut line = LinkLine::new(None);
    assert!(!line.update(&l, None, at(base, 1999)));
    assert!(line.update(&l, None, at(base, 2000)));
    // A slow path raises the bar to four round trips.
    let slow = Some(Duration::from_millis(900));
    assert!(!line.update(&l, slow, at(base, 3599)));
    assert!(line.update(&l, slow, at(base, 3600)));
}

#[test]
fn an_idle_attach_with_an_old_last_reply_shows_nothing() {
    let base = t0();
    let l = link(base, None, None);
    let mut line = LinkLine::new(Some(b'~'));
    assert!(!line.update(&l, None, at(base, 5000)));
    assert!(line.text().is_none());
    assert_eq!(line.next_deadline(&l, None, at(base, 5000)), None);
}

#[test]
fn the_text_counts_whole_seconds_since_the_last_reply() {
    let base = t0();
    let l = link(base, Some(500), None);
    let mut line = LinkLine::new(Some(b'~'));
    assert!(line.update(&l, None, at(base, 2600)));
    assert_eq!(
        line.text(),
        Some("qsh: last reply 2s ago; ~. to quit, ~d to detach")
    );
    line.update(&l, None, at(base, 3000));
    assert_eq!(
        line.text(),
        Some("qsh: last reply 3s ago; ~. to quit, ~d to detach")
    );
    line.update(&l, None, at(base, 3999));
    assert!(line.text().unwrap().contains("3s ago"));
}

#[test]
fn recovery_shows_the_line_at_once_with_the_attempt_number() {
    let base = t0();
    let mut line = LinkLine::new(Some(b'~'));
    assert!(line.update(&link(base, None, Some(2)), None, at(base, 9000)));
    assert_eq!(
        line.text(),
        Some("qsh: last reply 9s ago, reconnecting (attempt 2); ~. to quit, ~d to detach")
    );
}

#[test]
fn the_escape_character_follows_the_flag_and_off_names_none() {
    let base = t0();
    let l = link(base, None, Some(1));
    let mut custom = LinkLine::new(Some(b'^'));
    custom.update(&l, None, base);
    assert!(
        custom
            .text()
            .unwrap()
            .ends_with("; ^. to quit, ^d to detach")
    );
    let mut off = LinkLine::new(None);
    off.update(&l, None, base);
    assert_eq!(
        off.text(),
        Some("qsh: last reply 0s ago, reconnecting (attempt 1)")
    );
    // A control byte is not named.
    let mut ctl = LinkLine::new(Some(0x1e));
    ctl.update(&l, None, base);
    assert!(!ctl.text().unwrap().contains("to quit"));
}

#[test]
fn a_showing_line_is_due_again_on_each_whole_second() {
    let base = t0();
    let l = link(base, Some(0), None);
    let mut line = LinkLine::new(None);
    // Not showing yet: due when the wait crosses the threshold.
    assert_eq!(
        line.next_deadline(&l, None, at(base, 100)),
        Some(at(base, 2000))
    );
    line.update(&l, None, at(base, 2000));
    assert_eq!(
        line.next_deadline(&l, None, at(base, 2000)),
        Some(at(base, 3000))
    );
    assert_eq!(
        line.next_deadline(&l, None, at(base, 3400)),
        Some(at(base, 4000))
    );
}

#[test]
fn a_reply_clears_the_wait_and_the_line() {
    let base = t0();
    let tracker = LinkTracker::new(base);
    tracker.sent(at(base, 100));
    // The oldest unanswered send stays the reference.
    tracker.sent(at(base, 900));
    assert_eq!(tracker.snapshot().waiting_since, Some(at(base, 100)));
    let mut line = LinkLine::new(None);
    assert!(line.update(&tracker.snapshot(), None, at(base, 2200)));
    tracker.reply(at(base, 2300));
    let after = tracker.snapshot();
    assert_eq!(after.waiting_since, None);
    assert_eq!(after.last_reply, at(base, 2300));
    assert!(!line.update(&after, None, at(base, 2300)));
}

#[test]
fn recovery_ends_with_the_attempt_cleared() {
    let base = t0();
    let tracker = LinkTracker::new(base);
    tracker.set_recovering(Some(1));
    tracker.set_recovering(Some(2));
    assert_eq!(tracker.snapshot().recovering, Some(2));
    tracker.set_recovering(None);
    assert_eq!(tracker.snapshot().recovering, None);
}

#[test]
fn last_reply_never_goes_backwards() {
    let base = t0();
    let tracker = LinkTracker::new(at(base, 500));
    tracker.reply(base);
    assert_eq!(tracker.snapshot().last_reply, at(base, 500));
}
