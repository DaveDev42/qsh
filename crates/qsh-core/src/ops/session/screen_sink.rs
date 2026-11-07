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

use std::sync::Mutex;
use std::time::Instant;

use qsh_proto::screen::{Effect, ScreenState};
use qsh_proto::wire;

use crate::adapt::{PredictPin, Prediction};
use crate::client::predict_drive::PredictDriver;
use crate::client::render::ScreenRenderer;

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
    /// `--predict`. Consumed by the attach driver step; nothing acts on it
    /// yet.
    pub predict: Predict,
    /// `--status-line`. Consumed by the status-line step; nothing acts on it
    /// yet.
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
    /// The resolved `--predict` (hook for the attach driver step).
    pub predict: Predict,
    /// The resolved `--status-line` (hook for the status-line step).
    pub status_line: StatusLine,
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

/// Drawing state of one screen-sync attach.
pub(super) struct ScreenSink {
    inner: Mutex<Inner>,
    /// Rung when something outside the reader (the policy monitor) changed
    /// what the next frame should look like.
    wake: tokio::sync::Notify,
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
}

impl Inner {
    /// Draw `state` with the predictor's overlay composed over it.
    fn paint(&mut self, state: &ScreenState, effects: &[Effect]) -> Vec<u8> {
        let Self {
            renderer,
            local,
            predict,
            ..
        } = self;
        match predict {
            Some(p) => renderer.draw_with_overlay(state, &p.overlay(), effects, *local),
            None => renderer.draw(state, effects, *local),
        }
    }

    /// Draw the last state again with whatever the overlay is now: only the
    /// cells that differ from what the terminal shows are written.
    fn repaint(&mut self) -> (Vec<u8>, u64) {
        let Some(state) = self.last.take() else {
            return (Vec::new(), self.seq);
        };
        let bytes = self.paint(&state, &[]);
        self.last = Some(state);
        (bytes, self.seq)
    }
}

impl ScreenSink {
    pub(super) fn new(cols: u16, rows: u16, predict: Option<PredictDriver>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                renderer: ScreenRenderer::new(),
                local: (cols.max(1), rows.max(1)),
                last: None,
                seq: 0,
                predict,
            }),
            wake: tokio::sync::Notify::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        let bytes = inner.paint(state, effects);
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
            bytes.extend(inner.repaint().0);
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
        inner.repaint()
    }

    /// A new connection took over: the first update on it is a full screen,
    /// and diagnostics may have been written meanwhile, so repaint it all.
    pub(super) fn new_leg(&self) {
        let mut inner = self.lock();
        inner.renderer.invalidate();
        if let Some(p) = &mut inner.predict {
            p.on_leg_change();
        }
    }

    /// Whether this attach holds the writer lease.
    pub(super) fn set_writer(&self, writer: bool) {
        if let Some(p) = &mut self.lock().predict {
            p.on_writer(writer);
        }
    }

    /// Bytes that restore the local terminal's modes.
    pub(super) fn reset(&self) -> Vec<u8> {
        self.lock().renderer.reset()
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
        inner.repaint()
    }

    /// The host's input reflection point arrived; a verdict removes or keeps
    /// the predictions it covers.
    pub(super) fn echo(&self, echo: &wire::ScreenEcho, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let Some(p) = &mut inner.predict else {
            return (Vec::new(), inner.seq);
        };
        p.on_echo(echo, now);
        inner.repaint()
    }

    /// The host applied input up to `acked`: a round-trip sample on the
    /// reverse route, where no connection reports one.
    pub(super) fn input_ack(&self, acked: u64, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let Some(p) = &mut inner.predict else {
            return (Vec::new(), inner.seq);
        };
        p.on_input_ack(acked, now);
        inner.repaint()
    }

    /// The transport policy's prediction knob (forward route, called from
    /// the monitor's task). The next [`Self::tick`] draws the consequence.
    pub(super) fn set_policy(&self, policy: Prediction) {
        if let Some(p) = &mut self.lock().predict {
            p.set_policy(policy);
            self.wake.notify_one();
        }
    }

    /// Advance the prediction clock and draw whatever changed (late
    /// confirmation underlines, a new policy).
    pub(super) fn tick(&self, now: Instant) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let Some(p) = &mut inner.predict else {
            return (Vec::new(), inner.seq);
        };
        p.on_tick(now);
        inner.repaint()
    }

    /// Completes when [`Self::tick`] has something to do: the instant a
    /// waiting prediction turns late, or a policy change from outside.
    /// Pends forever without a predictor.
    pub(super) async fn tick_due(&self) {
        // Registered before the deadline is read, so a policy change in
        // between is not lost.
        let woken = self.wake.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        let deadline = self.lock().predict.as_ref().and_then(|p| p.next_deadline());
        match deadline {
            Some(at) => {
                let at = tokio::time::Instant::from_std(at);
                tokio::select! {
                    () = &mut woken => {}
                    () = tokio::time::sleep_until(at) => {}
                }
            }
            None => woken.await,
        }
    }
}
