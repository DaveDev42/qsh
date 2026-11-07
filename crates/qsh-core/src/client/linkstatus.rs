//! What an attach knows about whether its host is answering, and the
//! connection status line drawn from it (ADR-0053 decisions 9 and 10,
//! `docs/design/protocol.md` §18.10).
//!
//! [`LinkTracker`] is the attach's shared record: the pumps and the path
//! watch report what they sent and what came back, the recovery loop reports
//! its attempt number, and anything that wants the picture takes a
//! [`LinkStatus`] snapshot. [`LinkLine`] is the pure rule that turns a
//! snapshot, a round-trip estimate and a clock into the line's text. Neither
//! reads a clock of its own: every method takes the instant, so the tests
//! walk time by hand.
//!
//! The line is about *unanswered* sends, not about how long ago the last
//! reply was. An idle shell is probed every few seconds, so a last reply
//! several seconds old is normal; counting from the oldest send nobody has
//! answered keeps the line away from a quiet, healthy attach and brings it
//! up within [`SHOW_FLOOR`] of a typed key that goes nowhere.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// The shortest unanswered wait that shows the line. The shown threshold is
/// `max(SHOW_FLOOR, 4 x srtt)` ([`show_after`]).
pub const SHOW_FLOOR: Duration = Duration::from_secs(2);

/// A window narrower than this gets no line.
pub const MIN_COLS: u16 = 20;

/// The picture of a link at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    /// When the last authenticated inbound (a frame, a `Pong`, session
    /// traffic) was seen.
    pub last_reply: Instant,
    /// When the oldest send that nothing has answered since was made (a
    /// liveness probe or typed input); `None` when nothing is waiting.
    pub waiting_since: Option<Instant>,
    /// The recovery attempt in progress (1-based), if one is running.
    pub recovering: Option<u32>,
}

/// An attach's shared link record. See the module documentation.
#[derive(Debug)]
pub struct LinkTracker {
    state: Mutex<LinkStatus>,
    /// Rung (one stored permit) when a change can alter the line: a send
    /// started a wait, a reply ended one, the recovery attempt changed.
    changed: Notify,
}

impl LinkTracker {
    /// A link that has just been proven (an attach starts on its
    /// `SessionAttached` answer).
    pub fn new(now: Instant) -> Self {
        Self {
            state: Mutex::new(LinkStatus {
                last_reply: now,
                waiting_since: None,
                recovering: None,
            }),
            changed: Notify::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, LinkStatus> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Something was sent that the host should answer. Only the oldest
    /// unanswered send counts, so this is a no-op while one is waiting.
    pub fn sent(&self, now: Instant) {
        let mut s = self.state();
        if s.waiting_since.is_none() {
            s.waiting_since = Some(now);
            drop(s);
            self.changed.notify_one();
        }
    }

    /// An authenticated inbound arrived at `at`. Any traffic answers every
    /// outstanding send: the question is whether the path carries packets.
    pub fn reply(&self, at: Instant) {
        let mut s = self.state();
        s.last_reply = s.last_reply.max(at);
        if s.waiting_since.take().is_some() {
            drop(s);
            self.changed.notify_one();
        }
    }

    /// The recovery loop starts attempt `attempt` (1-based), or ends.
    pub fn set_recovering(&self, attempt: Option<u32>) {
        let mut s = self.state();
        if s.recovering != attempt {
            s.recovering = attempt;
            drop(s);
            self.changed.notify_one();
        }
    }

    /// The current picture.
    pub fn snapshot(&self) -> LinkStatus {
        *self.state()
    }

    /// Completes when something that can alter the line changed. One
    /// permit is stored, so a change before the wait begins is not lost.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }
}

/// `max(2 s, 4 x srtt)`: the unanswered wait that shows the line. An
/// unknown `srtt` (before the first sample) is the floor.
pub fn show_after(srtt: Option<Duration>) -> Duration {
    srtt.map_or(SHOW_FLOOR, |s| SHOW_FLOOR.max(s.saturating_mul(4)))
}

/// Whether `link` calls for the line at `now`.
pub fn wants_line(link: &LinkStatus, srtt: Option<Duration>, now: Instant) -> bool {
    link.recovering.is_some()
        || link
            .waiting_since
            .is_some_and(|w| now.saturating_duration_since(w) >= show_after(srtt))
}

/// The line's text and whether it is showing. See the module documentation.
#[derive(Debug, Clone, Default)]
pub struct LinkLine {
    /// The escape character the guidance names (`--escape-char`); `None`
    /// when escapes are off.
    escape: Option<u8>,
    text: Option<String>,
}

impl LinkLine {
    /// A line that names `escape` in its guidance.
    pub fn new(escape: Option<u8>) -> Self {
        Self { escape, text: None }
    }

    /// Re-evaluate against `link` at `now`; returns whether the line shows.
    pub fn update(&mut self, link: &LinkStatus, srtt: Option<Duration>, now: Instant) -> bool {
        self.text = wants_line(link, srtt, now).then(|| self.compose(link, now));
        self.text.is_some()
    }

    /// The text to draw, when showing.
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Whether the line shows.
    pub fn visible(&self) -> bool {
        self.text.is_some()
    }

    fn compose(&self, link: &LinkStatus, now: Instant) -> String {
        let secs = now.saturating_duration_since(link.last_reply).as_secs();
        let mut text = format!("qsh: last reply {secs}s ago");
        if let Some(attempt) = link.recovering {
            text.push_str(&format!(", reconnecting (attempt {attempt})"));
        }
        // Only a printable ASCII escape is named; anything else would draw
        // as something other than the key the user presses.
        if let Some(e) = self.escape.filter(u8::is_ascii_graphic) {
            let e = e as char;
            text.push_str(&format!("; {e}. to quit, {e}d to detach"));
        }
        text
    }

    /// When [`Self::update`] next gives a different answer, assuming the
    /// link does not change: the moment a wait crosses the threshold, or the
    /// next whole second of a showing line. `None` when nothing is pending.
    pub fn next_deadline(
        &self,
        link: &LinkStatus,
        srtt: Option<Duration>,
        now: Instant,
    ) -> Option<Instant> {
        if self.visible() {
            let age = now.saturating_duration_since(link.last_reply);
            return Some(link.last_reply + Duration::from_secs(age.as_secs() + 1));
        }
        link.waiting_since.map(|w| w + show_after(srtt))
    }
}

#[cfg(test)]
mod tests;
