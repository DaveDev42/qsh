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

use qsh_proto::screen::{Effect, ScreenState};
use qsh_proto::wire;

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
}

struct Inner {
    renderer: ScreenRenderer,
    /// Local window, (columns, rows).
    local: (u16, u16),
    /// The state last drawn, to repaint on a local resize.
    last: Option<ScreenState>,
    /// Output offset of the last drawn state.
    seq: u64,
}

impl ScreenSink {
    pub(super) fn new(cols: u16, rows: u16) -> Self {
        Self {
            inner: Mutex::new(Inner {
                renderer: ScreenRenderer::new(),
                local: (cols.max(1), rows.max(1)),
                last: None,
                seq: 0,
            }),
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

    /// Draw an applied state; returns the bytes and the offset to stamp
    /// them with.
    pub(super) fn draw(
        &self,
        state: &ScreenState,
        effects: &[Effect],
        output_seq: u64,
    ) -> (Vec<u8>, u64) {
        let mut inner = self.lock();
        let local = inner.local;
        let bytes = inner.renderer.draw(state, effects, local);
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
        if !bytes.is_empty()
            && let Some(state) = inner.last.take()
        {
            bytes.extend(inner.renderer.draw(&state, &[], local));
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
        let bytes = inner.renderer.draw(&state, &[], local);
        inner.last = Some(state);
        (bytes, inner.seq)
    }

    /// A new connection took over: the first update on it is a full screen,
    /// and diagnostics may have been written meanwhile, so repaint it all.
    pub(super) fn new_leg(&self) {
        self.lock().renderer.invalidate();
    }

    /// Bytes that restore the local terminal's modes.
    pub(super) fn reset(&self) -> Vec<u8> {
        self.lock().renderer.reset()
    }
}
