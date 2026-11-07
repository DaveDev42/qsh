//! Local echo prediction (ADR-0053 decisions 4 to 8, `docs/design/testing.md`
//! L2).
//!
//! [`Predictor`] is a state machine with no I/O and no clock. The attach
//! driver tells it what the user typed ([`Predictor::on_input`]), what the
//! host screen looks like ([`Predictor::on_state`]) and what the host says
//! about how far it has applied the input ([`Predictor::on_echo`]); the
//! renderer asks for [`Predictor::overlay`], the cells to draw over the host
//! screen. Time is always an argument.
//!
//! What it does, in short:
//!
//! - **Predicts** printable characters of width 1 and 2 (the same
//!   `unicode-width` table the host emulator, `vt100`, uses), Backspace and
//!   Left/Right inside the cursor row. Everything else breaks the epoch.
//! - **Epochs.** A prediction made right after a break belongs to a
//!   tentative epoch: it is tracked and judged but never drawn until one of
//!   its predictions has been confirmed by the host screen. That is what
//!   keeps a password typed after Enter off the screen.
//! - **Judges** with the host's [`EchoReport`]: a prediction is confirmed
//!   when the host cell shows the same character (attributes are ignored)
//!   and wrong when a report covering its input offset has been applied and
//!   the cell still differs. A wrong prediction and every later one are
//!   dropped.
//! - **Stays quiet** under a secret tty, the alternate screen, a cursor
//!   hidden in two states in a row, mouse reporting, a read-only attach and a host without
//!   `screen-echo.v1`; after three wrong predictions in a row it stops
//!   drawing until four undrawn predictions have been confirmed.
//!
//! Design choices the ADR leaves open are documented where they are made
//! (staleness after an unpredicted key, the 256 cap meaning pending
//! predictions, superseded predictions).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use qsh_proto::screen::{Cell, Modes, ScreenState, cell_flags};
use unicode_width::UnicodeWidthChar as _;

use crate::adapt::{PREDICT_ON_ABOVE, Prediction};

/// Wrong predictions in a row after which drawing stops.
pub const MISPREDICT_SUSPEND: u32 = 3;
/// Undrawn predictions confirmed in a row that end a suspension.
pub const REENABLE_CONFIRMS: u32 = 4;
/// A prediction unconfirmed for longer than this forces underlining.
pub const GLITCH_AFTER: Duration = Duration::from_millis(250);
/// Confirmations within [`PREDICT_ON_ABOVE`] in a row that end the forced
/// underlining.
pub const GLITCH_REPAIR: u32 = 10;
/// Most predictions waiting for a verdict at once.
pub const MAX_PENDING: usize = 256;
/// Applied host states in a row with the cursor hidden after which the
/// screen counts as a full-screen app (see [`Predictor::on_state`]).
pub const HIDDEN_CURSOR_STATES: u8 = 2;
/// More characters than this in one read are a paste.
pub const PASTE_CHARS: usize = 4;

/// What the host read from the PTY's termios (`TtyEcho` of ADR-0053
/// decision 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtyEcho {
    /// Not known (Windows host, read failure).
    Unknown,
    /// The kernel echoes (`ECHO` set).
    Kernel,
    /// The application echoes (`ECHO` and `ICANON` clear).
    App,
    /// No echo with line editing by the kernel: a password prompt.
    Secret,
}

/// The host's `ScreenEcho` message as the predictor needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoReport {
    /// The host screen state the report was made at.
    pub state_num: u64,
    /// Every input byte before this offset had been written to the PTY
    /// long enough before `state_num` for the application to react.
    pub input_seq: u64,
    /// The PTY's echo state at that time.
    pub tty: TtyEcho,
}

/// One cell to draw over the host screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayCell {
    /// Row.
    pub row: u16,
    /// Column.
    pub col: u16,
    /// The cell, with the underline bit already set when it is to be shown
    /// underlined.
    pub cell: Cell,
}

/// What the renderer draws over the host screen.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Overlay {
    /// Cells in row-major order.
    pub cells: Vec<OverlayCell>,
    /// Where the cursor goes instead of the host's, if a drawn prediction
    /// moved it.
    pub cursor: Option<(u16, u16)>,
}

impl Overlay {
    /// Nothing to draw.
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.cursor.is_none()
    }
}

/// Why predictions are blocked right now (never drawn, none kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Block {
    /// The host did not offer `screen-echo.v1`.
    NoCapability,
    /// This attach is read-only.
    ReadOnly,
    /// The PTY says the input is secret.
    Secret,
    /// Alternate screen, hidden cursor or mouse reporting.
    FullScreenApp,
}

/// Counters for the `qsh::predict` trace target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PredictStats {
    /// Predictions confirmed by the host screen.
    pub confirmed: u64,
    /// Predictions judged wrong.
    pub mispredicted: u64,
    /// Reports ahead of the input sent, dropped.
    pub echo_rejected: u64,
    /// Reports not newer than the last accepted one, dropped.
    pub echo_stale: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Insert,
    Backspace,
    Left,
    Right,
}

#[derive(Clone, Debug)]
struct Pred {
    kind: Kind,
    epoch: u64,
    input_end: u64,
    made_at: Instant,
    /// Column of the cell the host will show the result in.
    primary: Option<u16>,
    /// What that cell should hold.
    expect: Box<str>,
    /// First and last column the prediction rewrites.
    touch: Option<(u16, u16)>,
    cursor_before: u16,
    cursor_after: u16,
    /// Absolute result for each touched column, `true` when the cell is a
    /// newly typed character (the ones that get underlined).
    cells: Vec<(u16, Cell, bool)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Pending,
    Match { evidence: bool },
    Wrong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Char(char),
    Backspace,
    Left,
    Right,
    Break,
}

#[derive(Default)]
struct Snapshot {
    cursor_row_cells: Vec<Cell>,
    pred_row: Option<(u16, Vec<Cell>)>,
}

fn is_blank(t: &str) -> bool {
    t.is_empty() || t == " "
}

fn text_eq(a: &str, b: &str) -> bool {
    a == b || (is_blank(a) && is_blank(b))
}

/// Width of a character the predictor will draw, or `None` when it must not
/// predict it: control characters, zero width (combining marks, ZWJ,
/// variation selectors), widths above 2 and ambiguous widths (the width
/// differs between the plain and the CJK table).
fn predictable_width(c: char) -> Option<u16> {
    let w = c.width()?;
    if w == 0 || w > 2 || c.width_cjk() != Some(w) {
        return None;
    }
    u16::try_from(w).ok()
}

/// The local echo prediction engine. See the module documentation.
pub struct Predictor {
    capable: bool,
    writer: bool,
    tty: TtyEcho,
    policy: Prediction,
    status_line: bool,
    was_blocked: bool,

    have_state: bool,
    rows: u16,
    cols: u16,
    host_cursor: (u16, u16),
    mode_blocked: bool,
    /// Applied states in a row that showed the cursor hidden.
    hidden_streak: u8,
    applied_state: u64,
    snap: Snapshot,

    /// Row the view and the pending predictions are in.
    row: u16,
    /// The row as the host shows it with every pending prediction applied.
    view: Vec<Cell>,
    /// Predicted cursor; `None` while the position is unknown (stale).
    cursor: Option<(u16, u16)>,
    /// Input offset a report must cover before the host cursor is trusted
    /// again after a key the predictor did not follow.
    stale_until: Option<u64>,
    last_input_end: u64,
    covered: u64,
    last_report_key: Option<(u64, u64)>,
    held: Option<EchoReport>,

    pending: VecDeque<Pred>,
    epoch: u64,
    confirmed_epochs: Vec<u64>,

    wrong_run: u32,
    suspended: bool,
    undrawn_confirms: u32,
    glitch: bool,
    repair_run: u32,

    carry: Vec<u8>,
    in_paste: bool,
    now: Option<Instant>,
    stats: PredictStats,
}

impl Predictor {
    /// A predictor for one attach. `capable` is whether the host offered
    /// `screen-echo.v1`; without it nothing is ever predicted.
    pub fn new(capable: bool) -> Self {
        Self {
            capable,
            writer: true,
            tty: TtyEcho::Unknown,
            policy: Prediction::Display,
            status_line: false,
            was_blocked: !capable,
            have_state: false,
            rows: 0,
            cols: 0,
            host_cursor: (0, 0),
            mode_blocked: false,
            hidden_streak: 0,
            applied_state: 0,
            snap: Snapshot::default(),
            row: 0,
            view: Vec::new(),
            cursor: None,
            stale_until: None,
            last_input_end: 0,
            covered: 0,
            last_report_key: None,
            held: None,
            pending: VecDeque::new(),
            epoch: 0,
            confirmed_epochs: Vec::new(),
            wrong_run: 0,
            suspended: false,
            undrawn_confirms: 0,
            glitch: false,
            repair_run: 0,
            carry: Vec::new(),
            in_paste: false,
            now: None,
            stats: PredictStats::default(),
        }
    }

    // ---- inputs ----

    /// The user typed `bytes`; `input_end` is the cumulative input offset
    /// after them (the `Input.input_seq` convention of §10-5).
    pub fn on_input(&mut self, bytes: &[u8], input_end: u64, now: Instant) {
        self.tick(now);
        self.last_input_end = self.last_input_end.max(input_end);
        let events = self.parse(bytes, input_end);
        for (ev, end) in events {
            let ok = match ev {
                Ev::Break => false,
                _ => self.try_predict(ev, end, now),
            };
            if !ok {
                self.break_epoch(end);
            }
        }
    }

    /// A new host screen state was applied.
    pub fn on_state(&mut self, state: &ScreenState, state_num: u64, now: Instant) {
        self.tick(now);
        let size_changed = self.have_state && (state.rows != self.rows || state.cols != self.cols);
        if size_changed {
            self.discard_all();
        }
        self.have_state = true;
        self.rows = state.rows;
        self.cols = state.cols;
        self.host_cursor = (state.cursor_row, state.cursor_col);
        self.applied_state = self.applied_state.max(state_num);
        let m: Modes = state.modes;
        // A hidden cursor is a full-screen app only when it stays hidden:
        // PSReadLine hides it around every redraw of the line and shows it
        // again, so a state taken in between sees it hidden for one state.
        // Two states in a row are an app that draws its own cursor.
        self.hidden_streak = if m.flags & Modes::CURSOR_HIDDEN != 0 {
            self.hidden_streak.saturating_add(1)
        } else {
            0
        };
        self.mode_blocked = m.flags & Modes::ALT_SCREEN != 0
            || m.mouse_mode != 0
            || self.hidden_streak >= HIDDEN_CURSOR_STATES;

        let row_cells = |r: u16| -> Option<Vec<Cell>> {
            state.grid.get(usize::from(r)).map(|row| row.cells.clone())
        };
        self.snap.cursor_row_cells = row_cells(state.cursor_row).unwrap_or_default();
        self.snap.pred_row = if self.pending.is_empty() || self.row == state.cursor_row {
            None
        } else {
            row_cells(self.row).map(|c| (self.row, c))
        };

        if let Some(h) = self.held
            && h.state_num <= self.applied_state
        {
            self.held = None;
            self.covered = self.covered.max(h.input_seq);
        }
        self.check_block();
        self.reconcile();
    }

    /// The host's report arrived.
    pub fn on_echo(&mut self, report: EchoReport, now: Instant) {
        self.tick(now);
        if report.input_seq > self.last_input_end {
            self.stats.echo_rejected += 1;
            return;
        }
        let key = (report.state_num, report.input_seq);
        if self.last_report_key.is_some_and(|k| key <= k) {
            self.stats.echo_stale += 1;
            return;
        }
        self.last_report_key = Some(key);
        self.tty = report.tty;
        if report.state_num > self.applied_state {
            self.held = Some(report);
            self.check_block();
            return;
        }
        self.covered = self.covered.max(report.input_seq);
        self.check_block();
        self.reconcile();
    }

    /// The policy knob of `adapt` changed.
    pub fn on_policy(&mut self, policy: Prediction) {
        self.policy = policy;
    }

    /// The connection status line is (not) showing: while it is, every
    /// drawn prediction is underlined.
    pub fn on_status_line(&mut self, up: bool) {
        self.status_line = up;
    }

    /// Whether this attach holds the writer lease.
    pub fn on_writer(&mut self, writer: bool) {
        self.writer = writer;
        self.check_block();
        self.reconcile();
    }

    /// A new leg's first full screen is about to be applied: break the
    /// epoch, keep the predictions (they are judged by the new leg's
    /// reports). State numbers are per attach and start again at 1, so what
    /// was remembered about the old leg's numbering (applied state, the
    /// report held for a state not yet applied, the newest report key) is
    /// dropped; leaving it would judge the new leg's first reports against
    /// states it has not applied yet.
    pub fn on_leg_change(&mut self) {
        self.epoch += 1;
        self.applied_state = 0;
        self.held = None;
        self.last_report_key = None;
    }

    /// When [`Self::on_tick`] will next change something: the instant the
    /// oldest waiting prediction passes [`GLITCH_AFTER`] and forces
    /// underlining. `None` when nothing waits or underlining is already
    /// forced. The attach driver sleeps until it instead of polling.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.glitch {
            return None;
        }
        self.pending
            .front()
            .map(|p| p.made_at + GLITCH_AFTER + Duration::from_millis(1))
    }

    /// Advance the clock without another event (the glitch rule looks at
    /// how long the oldest prediction has been waiting).
    pub fn on_tick(&mut self, now: Instant) {
        self.tick(now);
    }

    // ---- outputs ----

    /// The cells to draw over the host screen now.
    pub fn overlay(&self) -> Overlay {
        let mode = self.effective_mode();
        if self.blocked().is_some() || self.suspended || mode == Prediction::Off {
            return Overlay::default();
        }
        let underline = mode == Prediction::Underline;
        let n = usize::from(self.cols);
        let mut cells = vec![Cell::default(); n];
        let mut written = vec![false; n];
        let mut cursor = None;
        for p in &self.pending {
            if !self.confirmed_epochs.contains(&p.epoch) {
                continue;
            }
            for (col, cell, fresh) in &p.cells {
                if *col >= self.cols {
                    continue;
                }
                let mut cell = cell.clone();
                if underline && *fresh {
                    cell.flags |= cell_flags::UNDERLINE;
                }
                put_atomic(&mut cells, &mut written, usize::from(*col), cell);
            }
            cursor = Some((self.row, p.cursor_after));
        }
        Overlay {
            cells: cells
                .into_iter()
                .zip(written)
                .enumerate()
                .filter(|(_, (_, w))| *w)
                .map(|(col, (cell, _))| OverlayCell {
                    row: self.row,
                    col: col as u16,
                    cell,
                })
                .collect(),
            cursor,
        }
    }

    /// Why predictions are blocked, if they are.
    pub fn blocked(&self) -> Option<Block> {
        if !self.capable {
            Some(Block::NoCapability)
        } else if !self.writer {
            Some(Block::ReadOnly)
        } else if self.tty == TtyEcho::Secret {
            Some(Block::Secret)
        } else if self.mode_blocked {
            Some(Block::FullScreenApp)
        } else {
            None
        }
    }

    /// Whether predictions are being drawn at all right now: not blocked,
    /// not suspended and the policy (or a late confirmation) wants them.
    pub fn drawing(&self) -> bool {
        self.blocked().is_none() && !self.suspended && self.effective_mode() != Prediction::Off
    }

    /// Whether the three-wrong-in-a-row rule has stopped drawing.
    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    /// Whether late confirmations force underlining.
    pub fn is_glitching(&self) -> bool {
        self.glitch
    }

    /// The report held until the state it names is applied. At most one:
    /// a newer report replaces it.
    pub fn held_echo(&self) -> Option<EchoReport> {
        self.held
    }

    /// Predictions waiting for a verdict.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Counters for the trace target.
    pub fn stats(&self) -> PredictStats {
        self.stats
    }

    // ---- internals ----

    fn effective_mode(&self) -> Prediction {
        let base = if self.glitch {
            Prediction::Underline
        } else {
            self.policy
        };
        if base != Prediction::Off && self.status_line {
            Prediction::Underline
        } else {
            base
        }
    }

    fn tick(&mut self, now: Instant) {
        self.now = Some(now);
        if let Some(p) = self.pending.front()
            && now.saturating_duration_since(p.made_at) > GLITCH_AFTER
        {
            self.glitch = true;
            self.repair_run = 0;
        }
    }

    fn check_block(&mut self) {
        let b = self.blocked().is_some();
        if b && !self.was_blocked {
            self.discard_all();
        }
        self.was_blocked = b;
    }

    /// Drop every pending prediction without a verdict. The inputs behind
    /// them are in flight, so the cursor is untrusted until a report covers
    /// them.
    fn discard_all(&mut self) {
        if let Some(last) = self.pending.back() {
            let end = last.input_end;
            self.stale_until = Some(self.stale_until.map_or(end, |s| s.max(end)));
        }
        self.pending.clear();
        self.epoch += 1;
        self.cursor = None;
        self.prune_epochs();
    }

    /// A key the predictor did not follow: new epoch, cursor unknown until
    /// a report covers `end`.
    fn break_epoch(&mut self, end: u64) {
        self.epoch += 1;
        self.stale_until = Some(self.stale_until.map_or(end, |s| s.max(end)));
        self.cursor = None;
        self.prune_epochs();
    }

    fn prune_epochs(&mut self) {
        let min = self.pending.front().map_or(self.epoch, |p| p.epoch);
        self.confirmed_epochs.retain(|e| *e >= min);
    }

    fn host_cells(&self, row: u16) -> Option<&[Cell]> {
        if row == self.host_cursor.0 {
            Some(&self.snap.cursor_row_cells)
        } else {
            self.snap
                .pred_row
                .as_ref()
                .filter(|(r, _)| *r == row)
                .map(|(_, c)| c.as_slice())
        }
    }

    fn rebuild_view(&mut self) {
        let cols = usize::from(self.cols);
        let mut view: Vec<Cell> = self
            .host_cells(self.row)
            .map(<[Cell]>::to_vec)
            .unwrap_or_default();
        view.resize(cols, Cell::default());
        let mut written = vec![false; cols];
        for p in &self.pending {
            for (col, cell, _) in &p.cells {
                if usize::from(*col) < cols {
                    put_atomic(&mut view, &mut written, usize::from(*col), cell.clone());
                }
            }
        }
        self.view = view;
    }

    /// Judge pending predictions against the stored host snapshot, drop
    /// the ones the host moved away from and resynchronise the cursor.
    fn reconcile(&mut self) {
        if !self.have_state {
            return;
        }
        if self.blocked().is_some() {
            self.row = self.host_cursor.0;
            self.rebuild_view();
            return;
        }
        for _ in 0..=self.pending.len() {
            if !self.resolve() {
                break;
            }
        }
        if !self.pending.is_empty() {
            let first_before = self.pending[0].cursor_before;
            let (hr, hc) = self.host_cursor;
            // ConPTY paints cells and moves the cursor in separate frames,
            // so a state can show the character the last confirmed key
            // typed with the cursor still one column short of where the
            // next prediction starts (PSReadLine, every key). That is the
            // host a step behind, not the host having moved the cursor.
            let lagging = first_before.checked_sub(1) == Some(hc);
            let consistent = hr == self.row
                && (hc == first_before
                    || lagging
                    || self.pending.iter().any(|p| p.cursor_after == hc));
            if !consistent {
                // The host moved the cursor somewhere we did not predict: a
                // new prompt, scrolled output. Not a misprediction.
                self.discard_all();
            }
        }
        if self.pending.is_empty() {
            self.row = self.host_cursor.0;
        }
        if self.stale_until.is_some_and(|s| s <= self.covered) {
            self.stale_until = None;
        }
        if self.pending.is_empty() {
            self.cursor = if self.stale_until.is_none() {
                Some(self.host_cursor)
            } else {
                None
            };
        }
        self.prune_epochs();
        self.rebuild_view();
    }

    fn verdict_own(&self, i: usize) -> Verdict {
        let p = &self.pending[i];
        let covered = p.input_end <= self.covered;
        match p.kind {
            Kind::Left | Kind::Right => {
                if !covered {
                    return Verdict::Pending;
                }
                let hc = self.host_cursor;
                let ok =
                    hc.0 == self.row && self.pending.iter().skip(i).any(|q| q.cursor_after == hc.1);
                if ok {
                    Verdict::Match { evidence: false }
                } else {
                    Verdict::Wrong
                }
            }
            Kind::Insert | Kind::Backspace => {
                let blank = is_blank(&p.expect);
                let needs_cover = blank || p.kind == Kind::Backspace;
                if needs_cover && !covered {
                    return Verdict::Pending;
                }
                let col = usize::from(p.primary.unwrap_or(0));
                let host = self
                    .host_cells(self.row)
                    .and_then(|c| c.get(col))
                    .map_or("", |c| &*c.text);
                if text_eq(host, &p.expect) {
                    Verdict::Match {
                        evidence: !blank && p.kind == Kind::Insert,
                    }
                } else if covered {
                    Verdict::Wrong
                } else {
                    Verdict::Pending
                }
            }
        }
    }

    /// One pass of judgement. Returns whether anything was removed.
    fn resolve(&mut self) -> bool {
        let n = self.pending.len();
        if n == 0 {
            return false;
        }
        let Some(now) = self.now else {
            return false;
        };
        // Back to front, so a prediction another one overwrites follows the
        // overwriting one's fate (mosh keeps one prediction per cell).
        let mut verdicts = vec![Verdict::Pending; n];
        for i in (0..n).rev() {
            let superseder =
                self.pending
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                    .rev()
                    .find_map(|(j, q)| {
                        let col = self.pending[i].primary?;
                        let (a, b) = q.touch?;
                        (a..=b).contains(&col).then_some(j)
                    });
            verdicts[i] = match superseder {
                Some(j) => match verdicts[j] {
                    Verdict::Match { .. } => Verdict::Match { evidence: false },
                    _ => Verdict::Pending,
                },
                None => self.verdict_own(i),
            };
        }
        // The host applies input in order, so a cell that shows a later
        // key's character shows the effect of every earlier key too. The
        // earlier predictions that wait for a report only because their own
        // result cannot be seen (a typed blank, a Backspace) are settled
        // with it: left pending, their cell snapshots, shifted tails of
        // wide characters among them, would be drawn over what the host
        // now shows.
        if let Some(last) = verdicts
            .iter()
            .rposition(|v| matches!(v, Verdict::Match { evidence: true }))
        {
            for (v, p) in verdicts.iter_mut().zip(&self.pending).take(last) {
                let unseen = is_blank(&p.expect) || p.kind == Kind::Backspace;
                if *v == Verdict::Pending
                    && matches!(p.kind, Kind::Insert | Kind::Backspace)
                    && unseen
                    && p.input_end > self.covered
                {
                    *v = Verdict::Match { evidence: false };
                }
            }
        }
        let mut keep = VecDeque::with_capacity(n);
        let mut changed = false;
        let old = std::mem::take(&mut self.pending);
        let mut dropped_end: Option<u64> = None;
        for (i, p) in old.into_iter().enumerate() {
            if dropped_end.is_some() {
                dropped_end = dropped_end.map(|e| e.max(p.input_end));
                changed = true;
                continue;
            }
            match verdicts[i] {
                Verdict::Pending => keep.push_back(p),
                Verdict::Match { evidence } => {
                    changed = true;
                    if evidence {
                        self.confirm(&p, now);
                    }
                }
                Verdict::Wrong => {
                    changed = true;
                    dropped_end = Some(p.input_end);
                    self.stats.mispredicted += 1;
                    self.wrong_run += 1;
                    self.undrawn_confirms = 0;
                    if self.wrong_run >= MISPREDICT_SUSPEND {
                        self.suspended = true;
                    }
                }
            }
        }
        self.pending = keep;
        if let Some(end) = dropped_end {
            self.epoch += 1;
            self.stale_until = Some(self.stale_until.map_or(end, |s| s.max(end)));
            self.cursor = None;
        }
        changed
    }

    fn confirm(&mut self, p: &Pred, now: Instant) {
        self.stats.confirmed += 1;
        if !self.confirmed_epochs.contains(&p.epoch) {
            self.confirmed_epochs.push(p.epoch);
        }
        self.wrong_run = 0;
        if self.suspended {
            self.undrawn_confirms += 1;
            if self.undrawn_confirms >= REENABLE_CONFIRMS {
                self.suspended = false;
                self.undrawn_confirms = 0;
            }
        }
        let delay = now.saturating_duration_since(p.made_at);
        if delay > GLITCH_AFTER {
            self.glitch = true;
            self.repair_run = 0;
        } else if self.glitch {
            if delay <= PREDICT_ON_ABOVE {
                self.repair_run += 1;
                if self.repair_run >= GLITCH_REPAIR {
                    self.glitch = false;
                    self.repair_run = 0;
                }
            } else {
                self.repair_run = 0;
            }
        }
    }

    // ---- input parsing ----

    fn parse(&mut self, bytes: &[u8], input_end: u64) -> Vec<(Ev, u64)> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(bytes);
        let start = input_end.saturating_sub(buf.len() as u64);
        let at = |i: usize| start + i as u64;
        let mut out: Vec<(Ev, u64)> = Vec::new();
        let mut i = 0;
        while i < buf.len() {
            if self.in_paste {
                // Everything up to the closing marker is one break.
                const END: &[u8] = b"\x1b[201~";
                match find(&buf[i..], END) {
                    Some(k) => {
                        i += k + END.len();
                        self.in_paste = false;
                    }
                    None => i = buf.len(),
                }
                out.push((Ev::Break, at(i)));
                continue;
            }
            let b = buf[i];
            match b {
                0x1b => {
                    let (ev, used) = parse_escape(&buf[i..], &mut self.in_paste);
                    i += used;
                    out.push((ev, at(i)));
                }
                0x7f | 0x08 => {
                    i += 1;
                    out.push((Ev::Backspace, at(i)));
                }
                0x00..=0x1f => {
                    i += 1;
                    out.push((Ev::Break, at(i)));
                }
                0x20..=0x7e => {
                    i += 1;
                    out.push((Ev::Char(char::from(b)), at(i)));
                }
                _ => {
                    let len = match b {
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => 0,
                    };
                    if len == 0 {
                        i += 1;
                        out.push((Ev::Break, at(i)));
                    } else if i + len > buf.len() {
                        // Split across reads: wait for the rest.
                        self.carry = buf[i..].to_vec();
                        break;
                    } else if let Ok(s) = std::str::from_utf8(&buf[i..i + len]) {
                        i += len;
                        let c = s.chars().next().unwrap_or('\u{fffd}');
                        let ev = if (c as u32) < 0xa0 {
                            Ev::Break
                        } else {
                            Ev::Char(c)
                        };
                        out.push((ev, at(i)));
                    } else {
                        i += 1;
                        out.push((Ev::Break, at(i)));
                    }
                }
            }
        }
        if out.iter().filter(|(e, _)| matches!(e, Ev::Char(_))).count() > PASTE_CHARS {
            for (e, _) in &mut out {
                if matches!(e, Ev::Char(_)) {
                    *e = Ev::Break;
                }
            }
        }
        out
    }

    // ---- making predictions ----

    fn try_predict(&mut self, ev: Ev, end: u64, now: Instant) -> bool {
        if self.blocked().is_some() || self.stale_until.is_some() || !self.have_state {
            return false;
        }
        let Some((r, c)) = self.cursor else {
            return false;
        };
        if self.pending.len() >= MAX_PENDING || r != self.row {
            return false;
        }
        let built = match ev {
            Ev::Char(ch) => self.build_insert(ch, usize::from(c), now),
            Ev::Backspace => self.build_backspace(usize::from(c), now),
            Ev::Left => self.build_left(usize::from(c), now),
            Ev::Right => self.build_right(usize::from(c), now),
            Ev::Break => None,
        };
        let Some(mut p) = built else {
            return false;
        };
        p.epoch = self.epoch;
        p.input_end = end;
        for (col, cell, _) in &p.cells {
            if let Some(slot) = self.view.get_mut(usize::from(*col)) {
                *slot = cell.clone();
            }
        }
        self.cursor = Some((r, p.cursor_after));
        self.pending.push_back(p);
        true
    }

    /// The last occupied column at or after `c`. The right half of a wide
    /// character has no text but is occupied: a shift that stopped at the
    /// lead would leave the half behind and move the lead alone.
    fn last_occupied_from(&self, c: usize) -> Option<usize> {
        (c..self.view.len()).rev().find(|k| {
            let cell = &self.view[*k];
            !cell.text.is_empty() || cell.flags & cell_flags::WIDE_CONT != 0
        })
    }

    fn base(kind: Kind, cursor_before: usize, cursor_after: usize, now: Instant) -> Pred {
        Pred {
            kind,
            epoch: 0,
            input_end: 0,
            made_at: now,
            primary: None,
            expect: "".into(),
            touch: None,
            cursor_before: cursor_before as u16,
            cursor_after: cursor_after as u16,
            cells: Vec::new(),
        }
    }

    fn build_insert(&self, ch: char, c: usize, now: Instant) -> Option<Pred> {
        let w = usize::from(predictable_width(ch)?);
        let cols = self.view.len();
        // The next character must not be able to wrap: the cursor ends up
        // at or before the last column.
        if c + w >= cols || self.view[c].flags & cell_flags::WIDE_CONT != 0 {
            return None;
        }
        let (fg, bg, flags) = if c > 0 {
            let l = &self.view[c - 1];
            (
                l.fg,
                l.bg,
                l.flags & !(cell_flags::WIDE | cell_flags::WIDE_CONT),
            )
        } else {
            Default::default()
        };
        let mut out = self.view.clone();
        let last = self.last_occupied_from(c);
        if let Some(e) = last {
            for k in (c..=e).rev() {
                if k + w < cols {
                    out[k + w] = self.view[k].clone();
                }
            }
            if out[cols - 1].flags & cell_flags::WIDE != 0 {
                out[cols - 1] = Cell::default();
            }
        }
        out[c] = Cell {
            text: ch.to_string().into(),
            fg,
            bg,
            flags: if w == 2 {
                flags | cell_flags::WIDE
            } else {
                flags
            },
        };
        if w == 2 {
            out[c + 1] = Cell {
                text: "".into(),
                fg,
                bg,
                flags: flags | cell_flags::WIDE_CONT,
            };
        }
        let hi = last
            .map_or(c + w - 1, |e| (e + w).max(c + w - 1))
            .min(cols - 1);
        let mut p = Self::base(Kind::Insert, c, c + w, now);
        p.primary = Some(c as u16);
        p.expect = ch.to_string().into();
        p.touch = Some((c as u16, hi as u16));
        p.cells = (c..=hi)
            .map(|k| (k as u16, out[k].clone(), k < c + w))
            .collect();
        Some(p)
    }

    fn build_backspace(&self, c: usize, now: Instant) -> Option<Pred> {
        let left = self.view.get(c.checked_sub(1)?)?;
        let w = if left.flags & cell_flags::WIDE_CONT != 0 {
            if c < 2 || self.view[c - 2].flags & cell_flags::WIDE == 0 {
                return None;
            }
            2
        } else if left.text.is_empty() {
            return None;
        } else {
            1
        };
        let s = c - w;
        let mut out = self.view.clone();
        let hi = match self.last_occupied_from(c) {
            Some(e) => {
                out[c - w..=e - w].clone_from_slice(&self.view[c..=e]);
                for cell in &mut out[e + 1 - w..=e] {
                    *cell = Cell::default();
                }
                e
            }
            None => {
                for cell in &mut out[s..c] {
                    *cell = Cell::default();
                }
                c - 1
            }
        };
        let mut p = Self::base(Kind::Backspace, c, s, now);
        p.primary = Some(s as u16);
        p.expect = out[s].text.clone();
        p.touch = Some((s as u16, hi as u16));
        p.cells = (s..=hi)
            .map(|k| (k as u16, out[k].clone(), false))
            .collect();
        Some(p)
    }

    fn build_left(&self, c: usize, now: Instant) -> Option<Pred> {
        let left = self.view.get(c.checked_sub(1)?)?;
        let t = if left.flags & cell_flags::WIDE_CONT != 0 {
            c.checked_sub(2)?
        } else if left.text.is_empty() {
            return None;
        } else {
            c - 1
        };
        Some(Self::base(Kind::Left, c, t, now))
    }

    fn build_right(&self, c: usize, now: Instant) -> Option<Pred> {
        let cell = self.view.get(c)?;
        if cell.text.is_empty() {
            return None;
        }
        let t = c + if cell.flags & cell_flags::WIDE != 0 {
            2
        } else {
            1
        };
        (t < self.view.len()).then(|| Self::base(Kind::Right, c, t, now))
    }
}

/// Write one predicted cell into a row of composed cells. Predictions are
/// absolute snapshots, so after one in the middle resolves, a later write can
/// land on one half of a wide character an earlier prediction wrote; the
/// other half is then blanked instead of left as a lone lead or a lone right
/// half (a terminal overwriting one half does the same).
fn put_atomic(cells: &mut [Cell], written: &mut [bool], col: usize, cell: Cell) {
    let old = cells[col].flags;
    if written[col] {
        if old & cell_flags::WIDE != 0
            && cell.flags & cell_flags::WIDE == 0
            && col + 1 < cells.len()
            && written[col + 1]
            && cells[col + 1].flags & cell_flags::WIDE_CONT != 0
        {
            cells[col + 1] = Cell::default();
        }
        if old & cell_flags::WIDE_CONT != 0
            && cell.flags & cell_flags::WIDE_CONT == 0
            && col > 0
            && written[col - 1]
            && cells[col - 1].flags & cell_flags::WIDE != 0
        {
            cells[col - 1] = Cell::default();
        }
    }
    cells[col] = cell;
    written[col] = true;
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse the escape sequence at the start of `b` (which begins with ESC).
/// Returns the key and how many bytes it used.
fn parse_escape(b: &[u8], in_paste: &mut bool) -> (Ev, usize) {
    match b.get(1) {
        None => (Ev::Break, 1),
        Some(b'[') => {
            let mut j = 2;
            while j < b.len() && (0x30..=0x3f).contains(&b[j]) {
                j += 1;
            }
            let params_end = j;
            while j < b.len() && (0x20..=0x2f).contains(&b[j]) {
                j += 1;
            }
            if j >= b.len() || !(0x40..=0x7e).contains(&b[j]) {
                return (Ev::Break, b.len());
            }
            let params = &b[2..params_end];
            let ev = match (params, b[j]) {
                (b"", b'D') => Ev::Left,
                (b"", b'C') => Ev::Right,
                (b"200", b'~') => {
                    *in_paste = true;
                    Ev::Break
                }
                _ => Ev::Break,
            };
            (ev, j + 1)
        }
        Some(b'O') => match b.get(2) {
            Some(b'D') => (Ev::Left, 3),
            Some(b'C') => (Ev::Right, 3),
            Some(_) => (Ev::Break, 3),
            None => (Ev::Break, 2),
        },
        Some(_) => (Ev::Break, 2),
    }
}

#[cfg(test)]
mod tests;
