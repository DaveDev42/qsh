//! Which carrier a jump channel's packets take in one direction (ADR-0056
//! decision 4, with the 1217 threshold and the numbers of ADR-0057).
//!
//! Both ends of a channel use this, the client for the client-to-J
//! direction and the intermediate peer for the other one. Each end chooses
//! for the packets it sends and receives on both carriers.
//!
//! [`choose_carrier`] is the static rule. [`SilenceFallback`] adds the
//! dynamic one: a datagram path that swallows everything (a middlebox that
//! drops DATAGRAM frames, say) looks healthy to the outer connection, so
//! when datagrams have gone out for 4 x srtt without one coming back while
//! the stream is alive, the channel moves to the stream and tests the
//! datagram path again every 30 s.

use std::time::{Duration, Instant};

use qsh_proto::datagram::DatagramFrame;
use qsh_proto::jump::JUMP_PACKET_MIN;

/// Bytes of the jump datagram header (channel and kind).
pub const DATAGRAM_HEADER: usize = DatagramFrame::HEADER_LEN;

/// How long after a switch to the stream the datagram path is tried again.
pub const DATAGRAM_RETRY: Duration = Duration::from_secs(30);

/// Datagrams unanswered for this many round trips make the channel leave
/// the datagram carrier.
pub const SILENCE_RTTS: u32 = 4;

/// The floor under the round trip the window is measured in, the same 50 ms
/// ADR-0052's rule has (`adapt::runner::RTT_FLOOR`).
pub const RTT_FLOOR: Duration = Duration::from_millis(50);

/// What the peer's delayed ack may add before an answer is overdue (QUIC's
/// default `max_ack_delay`).
pub const ACK_DELAY_ALLOWANCE: Duration = Duration::from_millis(25);

/// How long after a received datagram the sends that follow still count as
/// replies to it (ADR-0058 decision 1, as amended 2026-11-14). The receiver's
/// ack-only answers leave within `max_ack_delay` (25 ms) of the datagram that
/// asked for them, plus whatever the timer granularity and the scheduler add;
/// the allowance is eight times that, so a loaded host (a Windows timer tick
/// is 15.6 ms) does not turn an ack into the start of a silence.
pub const REPLY_WINDOW: Duration = Duration::from_millis(200);

/// How long datagrams may go unanswered before the channel falls back to the
/// stream: `4 x max(rtt, RTT_FLOOR) + 25 ms` (ADR-0058 decision 1). `rtt` is
/// the client's inner connection's srtt (the outer one until it has
/// handshaken), or the outer srtt on the middle peer and the daemon.
pub fn silence_window(rtt: Duration) -> Duration {
    rtt.max(RTT_FLOOR) * SILENCE_RTTS + ACK_DELAY_ALLOWANCE
}

/// The carrier packets are sent on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// One kind 14 datagram per packet.
    Datagram,
    /// Length-prefixed frames on the `JUMP` stream.
    Stream,
}

impl Carrier {
    /// The word logged for this carrier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Datagram => "datagram",
            Self::Stream => "stream",
        }
    }
}

/// Decision 4's static rule: a datagram when both sides advertise
/// `datagram.v1` and the outer connection's `max_datagram_size()` holds a
/// minimum-size inner packet and the 17-byte jump header; the stream
/// otherwise.
pub fn choose_carrier(both_datagram: bool, max_datagram_size: Option<usize>) -> Carrier {
    match max_datagram_size {
        Some(room) if both_datagram && room >= JUMP_PACKET_MIN + DATAGRAM_HEADER => {
            Carrier::Datagram
        }
        _ => Carrier::Stream,
    }
}

/// The silence rule of decision 4, as a small state machine over time that
/// the caller supplies (so it can be tested without sleeping).
#[derive(Debug, Default)]
pub struct SilenceFallback {
    /// When the oldest datagram that no datagram has answered since was
    /// sent.
    unanswered_since: Option<Instant>,
    /// When the last datagram came in. A send within [`REPLY_WINDOW`] of it
    /// is usually an ack-only reply, which no one answers in turn (QUIC does
    /// not ack acks), so it does not start the clock (ADR-0058 decision 1,
    /// as amended 2026-11-14). A single datagram can owe several such
    /// replies, and an ack can follow the datagram by a timer tick or more,
    /// so the rule is a window and not "the first send".
    last_received: Option<Instant>,
    /// When the channel left the datagram carrier for silence.
    fell_back_at: Option<Instant>,
}

impl SilenceFallback {
    /// A channel that has sent and received nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A datagram went out on the channel.
    pub fn sent_datagram(&mut self, now: Instant) {
        if self
            .last_received
            .is_some_and(|at| now.saturating_duration_since(at) <= REPLY_WINDOW)
        {
            return;
        }
        self.unanswered_since.get_or_insert(now);
    }

    /// A datagram came in on the channel: the path works, so a fallback
    /// ends.
    pub fn received_datagram(&mut self, now: Instant) {
        self.unanswered_since = None;
        self.fell_back_at = None;
        self.last_received = Some(now);
    }

    /// Whether the channel is on the stream because datagrams went quiet.
    pub fn fell_back(&self) -> bool {
        self.fell_back_at.is_some()
    }

    /// The carrier for the next packet. `rule` is [`choose_carrier`]'s
    /// answer and `srtt` the outer connection's smoothed round trip. A
    /// stream answer is never turned into a datagram.
    pub fn choose(&mut self, rule: Carrier, now: Instant, srtt: Duration) -> Carrier {
        if rule == Carrier::Stream {
            return Carrier::Stream;
        }
        if let Some(since) = self.fell_back_at {
            if now.saturating_duration_since(since) < DATAGRAM_RETRY {
                return Carrier::Stream;
            }
            // Test the datagram path again: the silence clock restarts.
            self.fell_back_at = None;
            self.unanswered_since = None;
            return Carrier::Datagram;
        }
        if let Some(since) = self.unanswered_since
            && now.saturating_duration_since(since) > silence_window(srtt)
        {
            self.fell_back_at = Some(now);
            self.unanswered_since = None;
            return Carrier::Stream;
        }
        Carrier::Datagram
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: usize = JUMP_PACKET_MIN + DATAGRAM_HEADER;

    #[test]
    fn the_static_rule_needs_both_sides_and_room_for_a_minimum_packet() {
        assert_eq!(choose_carrier(true, Some(ROOM)), Carrier::Datagram);
        assert_eq!(choose_carrier(true, Some(ROOM - 1)), Carrier::Stream);
        assert_eq!(choose_carrier(false, Some(2000)), Carrier::Stream);
        assert_eq!(choose_carrier(true, None), Carrier::Stream);
    }

    #[test]
    fn silence_moves_to_the_stream_and_retries_after_thirty_seconds() {
        let t0 = Instant::now();
        let srtt = Duration::from_millis(50);
        let mut f = SilenceFallback::new();
        assert_eq!(f.choose(Carrier::Datagram, t0, srtt), Carrier::Datagram);
        f.sent_datagram(t0);
        // Inside 4 x srtt nothing changes.
        let soon = t0 + Duration::from_millis(150);
        assert_eq!(f.choose(Carrier::Datagram, soon, srtt), Carrier::Datagram);
        // Past it the channel falls back.
        let late = t0 + Duration::from_millis(250);
        assert_eq!(f.choose(Carrier::Datagram, late, srtt), Carrier::Stream);
        assert!(f.fell_back());
        // Datagrams sent while on the stream do not restart anything.
        let later = late + Duration::from_secs(29);
        assert_eq!(f.choose(Carrier::Datagram, later, srtt), Carrier::Stream);
        // Thirty seconds on, the datagram path is tested again.
        let retry = late + DATAGRAM_RETRY;
        assert_eq!(f.choose(Carrier::Datagram, retry, srtt), Carrier::Datagram);
        assert!(!f.fell_back());
        f.sent_datagram(retry);
        // Silence again falls back again.
        let again = retry + Duration::from_millis(250);
        assert_eq!(f.choose(Carrier::Datagram, again, srtt), Carrier::Stream);
    }

    #[test]
    fn a_datagram_coming_back_ends_the_silence() {
        let t0 = Instant::now();
        let srtt = Duration::from_millis(50);
        let mut f = SilenceFallback::new();
        f.sent_datagram(t0);
        f.received_datagram(t0 + Duration::from_millis(10));
        let late = t0 + Duration::from_secs(5);
        assert_eq!(f.choose(Carrier::Datagram, late, srtt), Carrier::Datagram);
        // A fallback also ends when one arrives. A send long after the last
        // receive starts the clock.
        f.sent_datagram(late);
        let later = late + Duration::from_secs(1);
        assert_eq!(f.choose(Carrier::Datagram, later, srtt), Carrier::Stream);
        f.received_datagram(later);
        assert_eq!(f.choose(Carrier::Datagram, later, srtt), Carrier::Datagram);
    }

    #[test]
    fn sends_right_after_a_receive_do_not_start_the_clock() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let srtt = ms(50);
        let mut f = SilenceFallback::new();
        f.received_datagram(t0);
        // The ack-only replies to that datagram are never answered, however
        // many there are and however late the timer sends them.
        f.sent_datagram(t0);
        f.sent_datagram(t0 + ms(1));
        f.sent_datagram(t0 + ms(30));
        f.sent_datagram(t0 + REPLY_WINDOW);
        let late = t0 + Duration::from_secs(5);
        assert_eq!(f.choose(Carrier::Datagram, late, srtt), Carrier::Datagram);
        // A send past the window starts the clock and a blackhole is caught
        // in time.
        let past = t0 + REPLY_WINDOW + ms(1);
        f.sent_datagram(past);
        let after = past + ms(250);
        assert_eq!(f.choose(Carrier::Datagram, after, srtt), Carrier::Stream);
    }

    #[test]
    fn a_reply_burst_after_one_receive_leaves_a_healthy_path_alone() {
        // The field shape of the Windows flake: a receive batch of two
        // datagrams (a server ack and its follow-up) is answered by two
        // ack-only packets in separate sends, then the path idles for
        // longer than the window.
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let srtt = ms(1);
        let mut f = SilenceFallback::new();
        f.sent_datagram(t0);
        f.received_datagram(t0 + ms(1));
        f.sent_datagram(t0 + ms(28));
        f.received_datagram(t0 + ms(29));
        f.received_datagram(t0 + ms(29));
        f.sent_datagram(t0 + ms(29));
        f.sent_datagram(t0 + ms(29));
        let next = t0 + ms(600);
        assert_eq!(f.choose(Carrier::Datagram, next, srtt), Carrier::Datagram);
        assert!(!f.fell_back());
    }

    #[test]
    fn jump_silence_window_table() {
        let ms = Duration::from_millis;
        // Below the floor the floor rules, above it 4 x rtt, and the ack
        // allowance is always added.
        for (rtt, window) in [
            (ms(0), ms(225)),
            (ms(1), ms(225)),
            (ms(50), ms(225)),
            (ms(51), ms(229)),
            (ms(100), ms(425)),
            (ms(300), ms(1225)),
        ] {
            assert_eq!(silence_window(rtt), window, "rtt {rtt:?}");
        }
        // Unanswered for exactly the window is not yet silence; a
        // millisecond more is.
        let t0 = Instant::now();
        let mut f = SilenceFallback::new();
        f.sent_datagram(t0);
        let at = t0 + silence_window(ms(1));
        assert_eq!(f.choose(Carrier::Datagram, at, ms(1)), Carrier::Datagram);
        assert_eq!(
            f.choose(Carrier::Datagram, at + ms(1), ms(1)),
            Carrier::Stream
        );
        // A long end-to-end round trip keeps a healthy path whose answer
        // takes 200 ms.
        let mut f = SilenceFallback::new();
        f.sent_datagram(t0);
        assert_eq!(
            f.choose(Carrier::Datagram, t0 + ms(400), ms(200)),
            Carrier::Datagram
        );
    }

    #[test]
    fn a_stream_rule_is_never_overridden() {
        let mut f = SilenceFallback::new();
        let now = Instant::now();
        assert_eq!(
            f.choose(Carrier::Stream, now, Duration::from_millis(1)),
            Carrier::Stream
        );
    }
}
