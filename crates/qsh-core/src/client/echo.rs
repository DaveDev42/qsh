//! Receiver-side checks of `ScreenEcho` (ADR-0053 decision 3,
//! `docs/design/protocol.md` §18.12).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use qsh_proto::wire::ScreenEcho;

/// Shared by the stream and the datagram path: a signal beyond the sent
/// input offset is dropped and counted without closing anything, and of two
/// carriers' copies only the one further ahead in `(state_num, input_seq)`
/// is delivered.
pub(super) struct EchoFilter {
    /// `screen-echo.v1` was negotiated on a screen-sync attach.
    enabled: bool,
    sent: Arc<AtomicU64>,
    pub(super) rejected: AtomicU64,
    newest: Option<ScreenEcho>,
}

impl EchoFilter {
    pub(super) fn new(enabled: bool, sent: Arc<AtomicU64>) -> Self {
        Self {
            enabled,
            sent,
            rejected: AtomicU64::new(0),
            newest: None,
        }
    }

    /// The signal to deliver, if any.
    pub(super) fn accept(&mut self, echo: ScreenEcho) -> Option<ScreenEcho> {
        if !self.enabled {
            return None;
        }
        if echo
            .validate_against_sent(self.sent.load(Ordering::Acquire))
            .is_err()
        {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if let Some(newest) = &self.newest {
            let same_point =
                (newest.state_num, newest.input_seq) == (echo.state_num, echo.input_seq);
            if newest.is_newer_than(&echo) || (same_point && newest.tty == echo.tty) {
                return None;
            }
        }
        self.newest = Some(echo);
        Some(echo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo(state_num: u64, input_seq: u64, tty: i32) -> ScreenEcho {
        ScreenEcho {
            state_num,
            input_seq,
            tty,
        }
    }

    #[test]
    fn a_screen_echo_beyond_the_sent_input_is_rejected_and_counted() {
        let sent = Arc::new(AtomicU64::new(5));
        let mut f = EchoFilter::new(true, Arc::clone(&sent));
        assert_eq!(f.accept(echo(1, 6, 0)), None);
        assert_eq!(f.accept(echo(2, u64::MAX, 1)), None);
        assert_eq!(f.rejected.load(Ordering::Relaxed), 2);
        // A rejected signal leaves no trace: the same point is fine once the
        // client has really sent that much.
        assert_eq!(f.accept(echo(1, 5, 0)), Some(echo(1, 5, 0)));
        sent.store(9, Ordering::Release);
        assert_eq!(f.accept(echo(1, 9, 0)), Some(echo(1, 9, 0)));
        assert_eq!(f.rejected.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn the_newer_of_two_carriers_wins_and_older_copies_are_dropped() {
        let mut f = EchoFilter::new(true, Arc::new(AtomicU64::new(100)));
        assert!(f.accept(echo(3, 10, 1)).is_some());
        // The stream twin of the datagram copy.
        assert_eq!(f.accept(echo(3, 10, 1)), None);
        // A late, older datagram.
        assert_eq!(f.accept(echo(2, 50, 1)), None);
        assert_eq!(f.accept(echo(3, 9, 1)), None);
        // Same point, new tty state: delivered.
        assert!(f.accept(echo(3, 10, 3)).is_some());
        assert!(f.accept(echo(3, 11, 3)).is_some());
        assert!(f.accept(echo(4, 0, 3)).is_some());
        assert_eq!(f.rejected.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_connection_without_screen_echo_delivers_nothing() {
        let mut f = EchoFilter::new(false, Arc::new(AtomicU64::new(100)));
        assert_eq!(f.accept(echo(1, 1, 1)), None);
    }
}
