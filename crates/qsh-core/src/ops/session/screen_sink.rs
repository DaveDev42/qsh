//! The client end of screen state sync for an interactive attach
//! (ADR-0052 decisions 4, 5, 11 and 15): what the frontend asks for
//! ([`ScreenSync`], [`ScreenAttach`]) and the drawing state a screen-sync
//! attach keeps for its whole life, across the connections it runs on
//! ([`ScreenSink`]).
//!
//! The attach driver feeds the `ScreenUpdate` parts of each leg to that
//! leg's [`crate::client::screen::ClientScreen`], draws every applied state
//! through the sink's [`ScreenRenderer`], and hands the frontend the bytes as
//! ordinary [`qsh_proto::event::SessionEvent::Output`]. A frontend therefore
//! writes them to the terminal like any other output; it does not need to
//! know which path produced them, except that the replay filter of the byte
//! path has nothing to do (the renderer writes no queries).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qsh_proto::screen::{Effect, ScreenState};
use qsh_proto::wire;

use crate::adapt::{PredictPin, Prediction};
use qsh_proto::event::SessionEvent;

use super::pump::screen_output;
use crate::client::linkstatus::{LinkLine, LinkTracker};
use crate::client::pathwatch::PathWatch;
use crate::client::predict_drive::PredictDriver;
use crate::client::render::ScreenRenderer;
use crate::ops::OpError;

/// `--screen-sync` (ADR-0052 decision 15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScreenSync {
    /// Use screen sync when the host offers it for this session, otherwise
    /// the byte path, silently. The default.
    #[default]
    Auto,
    /// Require it: a host that cannot is `UNSUPPORTED`
    /// (`details.reason: "screen_sync_unsupported"`).
    On,
    /// Never: today's byte path.
    Off,
}

impl ScreenSync {
    /// Parse the `--screen-sync` value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// `--predict` (ADR-0053 decision 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Predict {
    /// Follow the adaptive policy's prediction knob (ADR-0052 decision 12
    /// (d)): draw above the RTT threshold, not on a fast link. The default.
    #[default]
    Auto,
    /// Draw at least `Display` whatever the RTT and `[transport].adaptive`
    /// say; the late-confirmation underline and the decision 7 gates still
    /// apply.
    Always,
    /// Never create a `Predictor`.
    Never,
}

impl Predict {
    /// Parse the `--predict` value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }

    /// The spelling the flag and the config key use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    /// The pin this choice puts on the adaptive policy (ADR-0053 decision
    /// 11); `auto` pins nothing.
    pub fn pin(self) -> Option<PredictPin> {
        match self {
            Self::Auto => None,
            Self::Always => Some(PredictPin::Always),
            Self::Never => Some(PredictPin::Never),
        }
    }
}

/// `--status-line` (ADR-0053 decision 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusLine {
    /// Draw the link-status line when the link is silent. The default.
    #[default]
    On,
    /// Never draw it. Link tracking and recovery are unaffected.
    Off,
}

impl StatusLine {
    /// Parse the `--status-line` value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    /// Whether the line may be drawn.
    pub fn enabled(self) -> bool {
        self == Self::On
    }
}

/// The resolved defaults of the interactive form's flags: each is the flag
/// when given, else its `[interactive]` key, else the built-in default.
/// Built by [`crate::Ops::interactive_options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InteractiveOptions {
    /// `--screen-sync`.
    pub screen_sync: ScreenSync,
    /// `--predict`.
    pub predict: Predict,
    /// `--status-line`.
    pub status_line: StatusLine,
}

/// What an interactive frontend tells `Ops` about the screen it will draw
/// on. Only built for an attach whose stdin and stdout are a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenAttach {
    /// The requested mode; [`ScreenSync::Off`] behaves as no request.
    pub mode: ScreenSync,
    /// Local window width.
    pub cols: u16,
    /// Local window height.
    pub rows: u16,
    /// The resolved `--predict`.
    pub predict: Predict,
    /// The resolved `--status-line`.
    pub status_line: StatusLine,
    /// The escape character the status line's guidance names
    /// (`--escape-char`); `None` when escapes are off.
    pub escape: Option<u8>,
}

impl ScreenAttach {
    /// Whether the frontend wants screen sync at all.
    pub fn wanted(&self) -> bool {
        self.mode != ScreenSync::Off
    }

    /// The `ScreenRequest` for `SessionOpen`/`SessionAttach`. The colours
    /// are not reported: the client does not query the terminal, so the host
    /// does not answer OSC 10/11 for this attach (decision 3).
    pub(super) fn request(&self) -> wire::ScreenRequest {
        wire::ScreenRequest {
            cols: u32::from(self.cols),
            rows: u32::from(self.rows),
            fg: None,
            bg: None,
        }
    }
}

/// `UNSUPPORTED` for `--screen-sync=on` when the host cannot (decision 15).
pub(crate) fn screen_sync_unsupported(why: &str) -> crate::ops::OpError {
    crate::ops::OpError::new(
        qsh_proto::ErrorCode::Unsupported,
        format!("--screen-sync=on: {why}; use --screen-sync=auto or off"),
    )
    .with_details(serde_json::json!({ "reason": "screen_sync_unsupported" }))
}

/// The connection status line's inputs (ADR-0053 decisions 9 and 10).
pub(super) struct StatusInit {
    /// The attach's link record.
    pub(super) link: Arc<LinkTracker>,
    /// The escape character the guidance names.
    pub(super) escape: Option<u8>,
}

/// Drawing state of one screen-sync attach.
pub(super) struct ScreenSink {
    inner: Mutex<Inner>,
    /// Rung when something outside the reader (the policy monitor) changed
    /// what the next frame should look like.
    wake: tokio::sync::Notify,
    /// Rung when the link changed in a way that can alter the status line.
    /// `None` when the line is off.
    link: Option<Arc<LinkTracker>>,
    /// Held from the moment a frame is computed until the frontend's queue
    /// has taken it ([`Self::emit`]), so frames reach the terminal in the
    /// order the renderer made them.
    gate: tokio::sync::Mutex<()>,
}

/// The status line and what it reads.
struct Status {
    line: LinkLine,
    link: Arc<LinkTracker>,
    /// The forward route's smoothed round trip, from the policy monitor.
    /// The reverse route has none and falls back to the `Input` to
    /// `InputAck` estimate the predictor keeps.
    srtt: Option<Duration>,
}

/// Whether this attach holds the writer lease, followed through the
/// `writer_changed` events of its control stream. The events name a
/// principal, not a connection, and the client does not know the name the
/// host gave it, so it is learned: an attach that holds the lease (the host
/// always grants it at attach) is announced by the first event, which names
/// it. From then on the lease is ours exactly when an event names that
/// principal. A second attach under the same principal cannot be told
/// apart from this one, and a first event that is a steal rather than our
/// own announcement is mistaken for it; the effect is a prediction drawn
/// that the host's echo check then withdraws, or one withheld, never a
/// wrong screen.
#[derive(Default)]
pub(super) struct WriterTrack {
    held: bool,
    me: Option<String>,
}

impl WriterTrack {
    /// A (new) leg was attached with `held` as its lease answer.
    pub(super) fn attached(&mut self, held: bool) {
        self.held = held;
    }

    /// A `writer_changed` event: the new holder, `None` when released.
    pub(super) fn changed(&mut self, new: Option<&str>) -> bool {
        match new {
            None => self.held = false,
            Some(p) => {
                if self.me.is_none() && self.held {
                    self.me = Some(p.to_owned());
                }
                if let Some(me) = &self.me {
                    self.held = p == me;
                }
            }
        }
        self.held
    }
}

struct Inner {
    renderer: ScreenRenderer,
    /// Local window, (columns, rows).
    local: (u16, u16),
    /// The state last drawn, to repaint on a local resize.
    last: Option<ScreenState>,
    /// Output offset of the last drawn state.
    seq: u64,
    /// Local echo prediction; `None` for `--predict=never`.
    predict: Option<PredictDriver>,
    /// The connection status line; `None` for `--status-line=off`.
    status: Option<Status>,
    writer: WriterTrack,
}

impl Inner {
    /// The round trip the status line's threshold scales with.
    fn srtt(&self) -> Option<Duration> {
        self.status
            .as_ref()
            .and_then(|s| s.srtt)
            .or_else(|| self.predict.as_ref().and_then(PredictDriver::input_srtt))
    }

    /// Re-evaluate the status line at `now` and tell the predictor when it
    /// came up or went (while it shows, every prediction is underlined).
    fn refresh_status(&mut self, now: Instant) {
        let srtt = self.srtt();
        let Self {
            status, predict, ..
        } = self;
        let Some(st) = status else {
            return;
        };
        let was = st.line.visible();
        let visible = st.line.update(&st.link.snapshot(), srtt, now);
        if was != visible
            && let Some(p) = predict
        {
            p.on_status_line(visible);
        }
    }

    /// Draw `state` with the predictor's overlay and the status line
    /// composed over it.
    fn paint(&mut self, state: &ScreenState, effects: &[Effect], now: Instant) -> Vec<u8> {
        self.refresh_status(now);
        let overlay = self.predict.as_ref().map(PredictDriver::overlay);
        let status = self.status.as_ref().and_then(|s| s.line.text());
        self.renderer
            .draw_composed(state, overlay.as_ref(), status, effects, self.local)
    }

    /// Draw the last state again with whatever the overlay and the line are
    /// now: only the cells that differ from what the terminal shows are
    /// written.
    fn repaint(&mut self, now: Instant) -> (Vec<u8>, u64) {
        if self.predict.is_none() && self.status.is_none() {
            return (Vec::new(), self.seq);
        }
        let Some(state) = self.last.take() else {
            return (Vec::new(), self.seq);
        };
        let bytes = self.paint(&state, &[], now);
        self.last = Some(state);
        (bytes, self.seq)
    }

    /// When [`ScreenSink::tick`] next has something to draw.
    fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let predict = self.predict.as_ref().and_then(PredictDriver::next_deadline);
        let status = self
            .status
            .as_ref()
            .and_then(|st| st.line.next_deadline(&st.link.snapshot(), self.srtt(), now));
        match (predict, status) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

impl ScreenSink {
    pub(super) fn new(
        cols: u16,
        rows: u16,
        predict: Option<PredictDriver>,
        status: Option<StatusInit>,
    ) -> Self {
        let link = status.as_ref().map(|s| s.link.clone());
        Self {
            inner: Mutex::new(Inner {
                renderer: ScreenRenderer::new(),
                local: (cols.max(1), rows.max(1)),
                last: None,
                seq: 0,
                predict,
                status: status.map(|s| Status {
                    line: LinkLine::new(s.escape),
                    link: s.link,
                    srtt: None,
                }),
                writer: WriterTrack::default(),
            }),
            wake: tokio::sync::Notify::new(),
            link,
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Compute one frame with `draw` and hand it to the frontend's event
    /// queue, as one step no other task's frame can interleave with.
    ///
    /// The renderer diffs each frame against what the previous one left on
    /// the terminal, so the bytes are only correct when written in the order
    /// they were made. The input pump, the leg reader, the control pump and
    /// the recovery ticker all draw, each from its own task; the sink's lock
    /// orders the computing, but not the `send` that follows it, and a task
    /// parked on a full queue would let a later frame overtake its earlier
    /// one. The gate covers both. `watch`, when given, marks the wait as a
    /// stalled consumer so the path watchdog does not read it as silence.
    ///
    /// Returns `false` when the frontend's receiver is gone.
    pub(super) async fn emit(
        &self,
        events: &tokio::sync::mpsc::Sender<Result<SessionEvent, OpError>>,
        session_ref: &str,
        watch: Option<&PathWatch>,
        draw: impl FnOnce(&Self) -> (Vec<u8>, u64),
    ) -> bool {
        let _gate = match self.gate.try_lock() {
            Ok(gate) => gate,
            Err(_) => {
                let _stalled = watch.map(PathWatch::stalled);
                self.gate.lock().await
            }
        };
        let (bytes, sequence) = draw(self);
        if bytes.is_empty() {
            return true;
        }
        let _stalled = watch.map(PathWatch::stalled);
        events
            .send(Ok(screen_output(session_ref, sequence, &bytes)))
            .await
            .is_ok()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether this attach draws the connection status line.
    pub(super) fn has_status_line(&self) -> bool {
        self.link.is_some()
    }

    /// The request to put in a recovery's `SessionAttach`: the window as it
    /// is now.
    pub(super) fn request(&self) -> wire::ScreenRequest {
        let (cols, rows) = self.lock().local;
        ScreenAttach {
            mode: ScreenSync::On,
            cols,
            rows,
            predict: Predict::Never,
            status_line: StatusLine::Off,
            escape: None,
        }
        .request()
    }

    /// Draw an applied state (number `state_num`); returns the bytes and the
    /// offset to stamp them with.
    pub(super) fn draw(
        &self,
        state: &ScreenState,
        effects: &[Effect],
        output_seq: u64,
        state_num: u64,
        now: Instant,
    ) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        if let Some(p) = &mut inner.predict {
            p.on_state(state, state_num, now);
        }
        let bytes = inner.paint(state, effects, now);
        inner.last = Some(state.clone());
        inner.seq = inner.seq.max(output_seq);
        (bytes, inner.seq)
    }

    /// Put scrolled-off lines into the local scrollback and repaint the
    /// last state under them (ADR-0052 decision 10); returns the bytes and
    /// the offset to stamp them with. `skipped` is the host's count of lines
    /// it did not keep.
    pub(super) fn history(&self, lines: &[String], skipped: u64) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let local = inner.local;
        let mut bytes = inner.renderer.history(lines, skipped, local);
        if !bytes.is_empty() {
            // `repaint` skips an attach with neither predictor nor line, but
            // the scrollback write cleared the renderer's picture, so the
            // screen must be drawn again either way.
            let Some(state) = inner.last.take() else {
                return (bytes, inner.seq);
            };
            bytes.extend(inner.paint(&state, &[], Instant::now()));
            inner.last = Some(state);
        }
        (bytes, inner.seq)
    }

    /// The local window changed: repaint the last state at the new size.
    pub(super) fn set_local(&self, cols: u16, rows: u16) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let local = (cols.max(1), rows.max(1));
        if inner.local == local {
            return (Vec::new(), inner.seq);
        }
        inner.local = local;
        // The terminal reflows or clears on a resize; trust nothing drawn.
        inner.renderer.invalidate();
        let Some(state) = inner.last.take() else {
            return (Vec::new(), inner.seq);
        };
        let bytes = inner.paint(&state, &[], Instant::now());
        inner.last = Some(state);
        (bytes, inner.seq)
    }

    /// A new connection took over (`writer` is its lease answer): the first
    /// update on it is a full screen, and diagnostics may have been written
    /// meanwhile, so repaint it all.
    pub(super) fn new_leg(&self, writer: bool) {
        let mut inner = self.lock();
        inner.renderer.invalidate();
        inner.writer.attached(writer);
        if let Some(p) = &mut inner.predict {
            p.on_leg_change();
            p.on_writer(writer);
        }
    }

    /// Whether this attach holds the writer lease at the start.
    pub(super) fn set_writer(&self, writer: bool) {
        let mut inner = self.lock();
        inner.writer.attached(writer);
        if let Some(p) = &mut inner.predict {
            p.on_writer(writer);
        }
    }

    /// A `writer_changed` event: the lease moved to `new_writer` (`None`:
    /// released). Predictions are blocked while this attach is read-only.
    pub(super) fn writer_changed(&self, new_writer: Option<&str>, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let held = inner.writer.changed(new_writer);
        if let Some(p) = &mut inner.predict {
            p.on_writer(held);
        }
        inner.repaint(now)
    }

    /// Bytes that restore the local terminal's modes.
    pub(super) fn reset(&self) -> Vec<u8> {
        self.lock().renderer.reset()
    }

    /// The status line's text while it shows (for the tests).
    #[cfg(test)]
    pub(super) fn status_text(&self) -> Option<String> {
        self.lock()
            .status
            .as_ref()
            .and_then(|s| s.line.text().map(str::to_owned))
    }

    // ---- local echo prediction (ADR-0053) ----

    /// The user typed `data` (cumulative input offset `end` after it): draw
    /// the predicted characters now, without waiting for the host.
    pub(super) fn input(&self, data: &[u8], end: u64, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let Some(p) = &mut inner.predict else {
            return (Vec::new(), inner.seq);
        };
        p.on_input(data, end, now);
        inner.repaint(now)
    }

    /// The host's input reflection point arrived; a verdict removes or keeps
    /// the predictions it covers.
    pub(super) fn echo(&self, echo: &wire::ScreenEcho, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let Some(p) = &mut inner.predict else {
            return (Vec::new(), inner.seq);
        };
        p.on_echo(echo, now);
        inner.repaint(now)
    }

    /// The host applied input up to `acked`: a round-trip sample on the
    /// reverse route, where no connection reports one.
    pub(super) fn input_ack(&self, acked: u64, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let Some(p) = &mut inner.predict else {
            return (Vec::new(), inner.seq);
        };
        p.on_input_ack(acked, now);
        inner.repaint(now)
    }

    /// The transport policy's prediction knob (forward route, called from
    /// the monitor's task). The next [`Self::tick`] draws the consequence.
    pub(super) fn set_policy(&self, policy: Prediction) {
        if let Some(p) = &mut self.lock().predict {
            p.set_policy(policy);
            self.wake.notify_one();
        }
    }

    /// The forward route's smoothed round trip (the policy monitor's, once a
    /// second): what the status line's `4 x srtt` threshold scales with.
    pub(super) fn set_srtt(&self, srtt: Option<Duration>) {
        if let Some(st) = &mut self.lock().status {
            st.srtt = srtt;
            self.wake.notify_one();
        }
    }

    /// Advance the clock and draw whatever changed: late-confirmation
    /// underlines, a new policy, the status line coming, going or counting.
    pub(super) fn tick(&self, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        if let Some(p) = &mut inner.predict {
            p.on_tick(now);
        }
        inner.repaint(now)
    }

    /// Completes when [`Self::tick`] has something to do: the instant a
    /// waiting prediction turns late, the status line is due to appear or
    /// count, or a change from outside. Pends forever with neither a
    /// predictor nor a status line.
    pub(super) async fn tick_due(&self) {
        // Registered before the deadline is read, so a policy change in
        // between is not lost.
        let woken = self.wake.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        let link_changed = async {
            match &self.link {
                Some(link) => link.changed().await,
                None => std::future::pending().await,
            }
        };
        let deadline = self.lock().next_deadline(Instant::now());
        match deadline {
            Some(at) => {
                let at = tokio::time::Instant::from_std(at);
                tokio::select! {
                    () = &mut woken => {}
                    () = link_changed => {}
                    () = tokio::time::sleep_until(at) => {}
                }
            }
            None => {
                tokio::select! {
                    () = &mut woken => {}
                    () = link_changed => {}
                }
            }
        }
    }
}
