//! Driver-level tests with a clock the test walks by hand (ADR-0053
//! decisions 3, 7, 8 and 11; `docs/design/testing.md` L2).

use qsh_proto::screen::cell_flags;

use super::*;
use crate::client::predict::{Block, GLITCH_AFTER};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A 3x40 screen whose first row is the prompt `$ ` and `typed`, cursor
/// after it.
fn line(typed: &str) -> ScreenState {
    let mut s = ScreenState::blank(3, 40).unwrap();
    for (i, ch) in format!("$ {typed}").chars().enumerate() {
        s.grid[0].cells[i].text = ch.to_string().into();
    }
    s.cursor_col = u16::try_from(2 + typed.len()).unwrap();
    s
}

fn echo(state_num: u64, input_seq: u64) -> wire::ScreenEcho {
    wire::ScreenEcho {
        state_num,
        input_seq,
        tty: WireTty::App as i32,
    }
}

fn underlined(d: &PredictDriver) -> bool {
    d.overlay()
        .cells
        .first()
        .is_some_and(|c| c.cell.flags & cell_flags::UNDERLINE != 0)
}

struct Rig {
    d: PredictDriver,
    t: Instant,
    /// Host state number so far.
    state: u64,
    /// Input offset so far.
    sent: u64,
}

impl Rig {
    fn new(mode: Predict, capable: bool, reverse: bool) -> Self {
        let mut r = Self {
            d: PredictDriver::new(mode, capable, reverse).expect("a driver"),
            t: Instant::now(),
            state: 0,
            sent: 0,
        };
        r.apply("");
        r
    }

    fn adv(&mut self, n: u64) {
        self.t += ms(n);
    }

    fn apply(&mut self, typed: &str) {
        self.state += 1;
        self.d.on_state(&line(typed), self.state, self.t);
    }

    fn key(&mut self, bytes: &[u8]) {
        self.sent += bytes.len() as u64;
        self.d.on_input(bytes, self.sent, self.t);
    }

    /// The host shows `typed` and says it has applied all input.
    fn host_shows(&mut self, typed: &str) {
        self.apply(typed);
        self.d.on_echo(&echo(self.state, self.sent), self.t);
    }

    /// One typed character, confirmed by the host: the epoch is drawn from
    /// here on. The policy is `Display` unless the route derives its own.
    fn confirmed(mode: Predict, reverse: bool) -> Self {
        let mut r = Self::new(mode, true, reverse);
        if !reverse {
            r.d.set_policy(Prediction::Display);
        }
        r.key(b"a");
        r.adv(40);
        if reverse {
            r.d.on_input_ack(r.sent, r.t);
        }
        r.host_shows("a");
        r
    }
}

#[test]
fn never_builds_no_predictor() {
    assert!(PredictDriver::new(Predict::Never, true, false).is_none());
    assert!(PredictDriver::new(Predict::Auto, true, false).is_some());
    assert_eq!(Predict::default(), Predict::Auto);
}

#[test]
fn a_peer_without_screen_echo_gets_nothing_predicted() {
    // Even `always` cannot predict without the host's verdicts.
    let mut r = Rig::new(Predict::Always, false, false);
    for _ in 0..5 {
        r.key(b"x");
        r.adv(10);
        assert!(r.d.overlay().is_empty());
    }
    r.host_shows("xxxxx");
    r.key(b"y");
    assert!(r.d.overlay().is_empty());
    assert_eq!(r.d.predictor().pending_len(), 0);
    assert_eq!(r.d.predictor().blocked(), Some(Block::NoCapability));
}

#[test]
fn auto_draws_nothing_until_the_policy_says_the_path_is_slow() {
    let mut r = Rig::new(Predict::Auto, true, false);
    r.key(b"a");
    r.adv(40);
    r.host_shows("a");
    r.key(b"b");
    assert!(r.d.overlay().is_empty(), "policy starts at off");
    r.d.set_policy(Prediction::Display);
    assert_eq!(r.d.overlay().cells.len(), 1);
    assert!(!underlined(&r.d));
    r.d.set_policy(Prediction::Underline);
    assert!(underlined(&r.d));
    r.d.set_policy(Prediction::Off);
    assert!(r.d.overlay().is_empty());
}

#[test]
fn always_draws_at_least_plainly_even_when_the_policy_is_off() {
    let mut r = Rig::new(Predict::Always, true, false);
    r.key(b"a");
    r.adv(40);
    r.host_shows("a");
    r.key(b"b");
    // The policy knob was never raised (a LAN, or `[transport].adaptive =
    // "off"`): `always` still draws.
    r.d.set_policy(Prediction::Off);
    assert_eq!(r.d.overlay().cells.len(), 1);
    assert!(!underlined(&r.d));
    // And it does not hold underlining back when the policy asks for it.
    r.d.set_policy(Prediction::Underline);
    assert!(underlined(&r.d));
}

#[test]
fn a_late_confirmation_forces_underlining_after_250_ms() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    r.key(b"b");
    assert!(!underlined(&r.d));
    let deadline =
        r.d.next_deadline()
            .expect("a waiting prediction has a deadline");
    assert_eq!(deadline, r.t + GLITCH_AFTER + ms(1));
    r.adv(250);
    r.d.on_tick(r.t);
    assert!(!underlined(&r.d), "exactly 250 ms is not late");
    r.adv(1);
    r.d.on_tick(r.t);
    assert!(underlined(&r.d));
    assert_eq!(r.d.next_deadline(), None, "nothing more to wait for");
}

#[test]
fn no_deadline_without_a_waiting_prediction() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    assert_eq!(r.d.next_deadline(), None);
    r.key(b"b");
    assert!(r.d.next_deadline().is_some());
    r.host_shows("ab");
    assert_eq!(r.d.next_deadline(), None);
}

#[test]
fn a_screen_echo_for_an_unapplied_state_is_held_until_that_state_is_applied() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    r.key(b"b");
    // The host's reflection point arrives before the screen update it names
    // (two carriers, so the order is not fixed).
    r.d.on_echo(&echo(r.state + 1, r.sent), r.t);
    assert_eq!(
        r.d.held_echo().map(|h| (h.state_num, h.input_seq)),
        Some((r.state + 1, r.sent))
    );
    assert_eq!(r.d.predictor().pending_len(), 1, "no verdict yet");
    // The state arrives and shows something else: the report is released
    // and the prediction is judged wrong.
    r.apply("a*");
    assert_eq!(r.d.held_echo(), None);
    assert_eq!(r.d.predictor().pending_len(), 0);
    assert_eq!(r.d.stats().mispredicted, 1);
    assert!(r.d.overlay().is_empty());
}

#[test]
fn the_hold_is_one_report_and_the_newest_one_wins() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    r.key(b"bcd");
    for ahead in 1..=50u64 {
        // Each report names a state further on; none has been applied.
        r.d.on_echo(&echo(r.state + ahead, r.sent), r.t);
        assert!(r.d.held_echo().is_some());
    }
    let held = r.d.held_echo().expect("one held");
    assert_eq!(held.state_num, r.state + 50, "the newest replaced the rest");
    // Applying a state short of it releases nothing and judges nothing.
    r.apply("a");
    assert_eq!(r.d.held_echo().map(|h| h.state_num), Some(held.state_num));
    assert_eq!(r.d.predictor().pending_len(), 3);
    // Reaching it releases it.
    r.state = held.state_num - 1;
    r.apply("abcd");
    assert_eq!(r.d.held_echo(), None);
    assert_eq!(r.d.predictor().pending_len(), 0);
}

#[test]
fn a_screen_echo_beyond_the_typed_input_is_not_held() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    r.d.on_echo(&echo(r.state + 5, r.sent + 1), r.t);
    assert_eq!(r.d.held_echo(), None);
    assert_eq!(r.d.stats().echo_rejected, 1);
}

#[test]
fn a_new_leg_forgets_the_old_numbering() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    for _ in 0..20 {
        r.apply("a");
    }
    r.key(b"b");
    r.d.on_leg_change();
    // The new leg numbers its states from 1 again. Its first report names
    // state 2, which is not applied yet: held, not judged against the old
    // leg's state 22.
    r.d.on_echo(&echo(2, r.sent), r.t);
    assert_eq!(r.d.held_echo().map(|h| h.state_num), Some(2));
    assert_eq!(r.d.predictor().pending_len(), 1);
}

#[test]
fn a_tty_state_is_mapped_from_the_wire() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    r.key(b"b");
    assert_eq!(r.d.overlay().cells.len(), 1);
    r.apply("a");
    let secret = wire::ScreenEcho {
        state_num: r.state,
        input_seq: r.sent,
        tty: WireTty::Secret as i32,
    };
    r.d.on_echo(&secret, r.t);
    assert_eq!(r.d.predictor().blocked(), Some(Block::Secret));
    assert!(r.d.overlay().is_empty());
}

#[test]
fn the_reverse_route_derives_its_policy_from_input_ack_spacing() {
    // Before any sample the policy is off.
    let mut r = Rig::new(Predict::Auto, true, true);
    r.key(b"a");
    r.adv(120);
    // 120 ms between the Input and the InputAck that covers it: underline
    // (over 80 ms).
    r.d.on_input_ack(r.sent, r.t);
    assert_eq!(r.d.input_srtt(), Some(ms(120)));
    r.host_shows("a");
    r.key(b"b");
    assert!(underlined(&r.d));

    // A 5 ms round trip: prediction off.
    let mut fast = Rig::new(Predict::Auto, true, true);
    fast.key(b"a");
    fast.adv(5);
    fast.d.on_input_ack(fast.sent, fast.t);
    fast.host_shows("a");
    fast.key(b"b");
    assert!(fast.d.overlay().is_empty(), "5 ms round trip: off");
}

#[test]
fn the_reverse_route_is_off_before_its_first_sample() {
    let mut r = Rig::new(Predict::Auto, true, true);
    r.key(b"a");
    r.adv(40);
    r.host_shows("a");
    r.key(b"b");
    assert!(r.d.overlay().is_empty());
    assert_eq!(r.d.input_srtt(), None);
}

#[test]
fn the_reverse_route_decides_once_a_second_with_the_policy_hysteresis() {
    let mut r = Rig::confirmed(Predict::Auto, true);
    // `confirmed` fed one 40 ms sample and decided on it: display.
    assert_eq!(r.d.input_srtt(), Some(ms(40)));
    let decided = r.t;
    // Samples of 240 ms (each key confirmed inside the 250 ms glitch limit)
    // pull the smoothed value over 80 ms within a second.
    let mut typed = String::from("a");
    for c in ["b", "c", "d"] {
        r.key(c.as_bytes());
        r.adv(240);
        r.d.on_input_ack(r.sent, r.t);
        typed.push_str(c);
        r.host_shows(&typed);
    }
    assert!(r.d.input_srtt().unwrap() > ms(80));
    r.key(b"e");
    assert!(!r.d.overlay().cells.is_empty());
    assert!(!underlined(&r.d), "the decision is under a second old");
    typed.push('e');
    r.host_shows(&typed);
    // A second after the decision the next sample is acted on.
    r.adv(300);
    assert!(r.t.duration_since(decided) >= ms(1000));
    r.key(b"f");
    r.adv(10);
    r.d.on_input_ack(r.sent, r.t);
    assert!(underlined(&r.d), "underline once the next decision is due");
}

#[test]
fn the_forward_route_takes_no_rtt_samples_of_its_own() {
    let mut r = Rig::confirmed(Predict::Auto, false);
    r.key(b"b");
    r.adv(120);
    r.d.on_input_ack(r.sent, r.t);
    assert_eq!(r.d.input_srtt(), None);
    assert!(!underlined(&r.d), "the policy is the monitor's alone");
}

#[test]
fn the_input_time_table_is_bounded() {
    let mut r = Rig::new(Predict::Auto, true, true);
    for _ in 0..(SENT_TIMES_MAX * 2) {
        r.key(b"x");
    }
    // An ack for the very first byte finds its entry forgotten and yields no
    // sample.
    r.adv(10);
    r.d.on_input_ack(1, r.t);
    assert_eq!(r.d.input_srtt(), None);
    r.d.on_input_ack(r.sent, r.t);
    assert!(r.d.input_srtt().is_some());
}
