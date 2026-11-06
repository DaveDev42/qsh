//! Host terminal emulator for screen state sync (ADR-0052 decisions 2 to 5
//! and 10; `docs/design/architecture.md` §3).
//!
//! [`HostScreen`] is one terminal emulator per PTY session. It is an I/O-free
//! state machine: the output pump feeds it the bytes it just wrote to the
//! replay ring, in the same task, and it never waits for a consumer or the
//! network. The ring and the byte path stay as they are. The emulator is
//! `vt100` (see `Cargo.toml` for why it was chosen); this module adds
//!
//! - the state numbering of decision 5: [`HostScreen::cut`] freezes the
//!   current screen as the next numbered state when it changed, and
//!   [`HostScreen::update_since`] builds the [`ScreenUpdate`] a client at a
//!   given state needs;
//! - answers to terminal queries (decision 3), which the pump writes into
//!   the PTY input ([`HostScreen::take_answers`]);
//! - the effects of decision 4, tied to the state they happened before;
//! - the lines scrolled off the top of the primary screen, in order
//!   ([`HostScreen::take_history`], decision 10; their transport is not in
//!   this module).
//!
//! Nothing here is on by default. The session broker creates a `HostScreen`
//! only when `SessionConfig::screen` is set, and nothing sets it yet.

mod collector;
#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::num::NonZeroU16;

use qsh_proto::screen::{
    Cell, Color, Effect, MAX_CELL_TEXT, Modes, Row, ScreenDiff, ScreenState, ScreenUpdate,
    cell_flags, size_is_valid,
};

use collector::Collector;
pub use collector::Rgb;

/// States kept for diffing (ADR-0052 decision 5: "the 8 most recent").
pub const RETAINED_STATES: usize = 8;
/// Bytes handed to the emulator at once. The pump's chunks are at most 16
/// KiB, so this bounds the work between two points where a reader of the
/// screen can take the lock.
pub const FEED_SLICE: usize = 16 * 1024;
/// Default history length (ADR-0052 decision 10).
pub const DEFAULT_HISTORY_ROWS: usize = 5000;
/// Default history byte cap.
pub const DEFAULT_HISTORY_BYTES: usize = 4 * 1024 * 1024;
/// Effects remembered for clients that are behind.
const EFFECT_LOG_MAX: usize = 256;

/// How a [`HostScreen`] starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenOptions {
    /// Row count (the PTY's).
    pub rows: u16,
    /// Column count (the PTY's).
    pub cols: u16,
    /// Most scrolled-off lines kept for the history transport.
    pub history_rows: usize,
    /// Byte cap of the same.
    pub history_bytes: usize,
}

impl Default for ScreenOptions {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            history_rows: DEFAULT_HISTORY_ROWS,
            history_bytes: DEFAULT_HISTORY_BYTES,
        }
    }
}

/// Lines scrolled off the top since the last [`HostScreen::take_history`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryBatch {
    /// Lines that scrolled off after `lines` and were counted instead of
    /// kept, because the history was full (row or byte cap) before it was
    /// taken: the newest rows of a flood. They come after `lines` in time.
    /// The history transport reports them as `--- N lines skipped ---`.
    pub skipped: u64,
    /// The lines, oldest first, as SGR-formatted text without a newline.
    pub lines: Vec<String>,
}

/// A numbered state as cut by [`HostScreen::cut`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateInfo {
    /// `state_num`.
    pub num: u64,
    /// Output offset the state reflects.
    pub output_seq: u64,
    /// `state_hash`.
    pub hash: [u8; qsh_proto::screen::HASH_LEN],
}

struct Cut {
    info: StateInfo,
    state: ScreenState,
}

/// The per-session host emulator.
pub struct HostScreen {
    parser: vt100::Parser<Collector>,
    cuts: VecDeque<Cut>,
    /// Effects by the state they precede, oldest first.
    effect_log: VecDeque<(u64, Effect)>,
    last_title: Option<String>,
    next_num: u64,
    fed_seq: u64,
    dirty: bool,
}

impl std::fmt::Debug for HostScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostScreen")
            .field("size", &self.size())
            .field("states", &self.cuts.len())
            .field("next_num", &self.next_num)
            .finish_non_exhaustive()
    }
}

impl HostScreen {
    /// A blank screen. A size outside the accepted range becomes 24x80.
    pub fn new(options: ScreenOptions) -> Self {
        let (rows, cols) = if size_is_valid(options.rows, options.cols) {
            (options.rows, options.cols)
        } else {
            (24, 80)
        };
        let collector = Collector::new(options.history_rows, options.history_bytes);
        let parser = vt100::Parser::new_with_callbacks(
            NonZeroU16::new(rows).unwrap_or(vt100::Parser::DEFAULT_ROWS),
            NonZeroU16::new(cols).unwrap_or(vt100::Parser::DEFAULT_COLS),
            // The emulator keeps no scrollback of its own: `on_scroll`
            // hands each line over as it leaves the top, and the history
            // here has a byte cap the emulator's does not.
            0,
            collector,
        );
        Self {
            parser,
            cuts: VecDeque::new(),
            effect_log: VecDeque::new(),
            last_title: None,
            next_num: 1,
            fed_seq: 0,
            dirty: true,
        }
    }

    /// Current size as (rows, cols).
    pub fn size(&self) -> (u16, u16) {
        let (r, c) = self.parser.screen().size();
        (r.get(), c.get())
    }

    /// Feed output the pump has just written to the ring. `end_seq` is the
    /// cumulative output offset after `data`. Work is done in slices of
    /// [`FEED_SLICE`]; nothing here blocks or waits.
    pub fn feed(&mut self, data: &[u8], end_seq: u64) {
        for slice in data.chunks(FEED_SLICE) {
            self.parser.process(slice);
        }
        self.fed_seq = end_seq;
        self.dirty = true;
    }

    /// Bytes to write into the PTY input: the host's answers to the queries
    /// fed since the last call. Empty when there are none.
    pub fn take_answers(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.parser.callbacks_mut().answers)
    }

    /// Follow a PTY resize. Rows pushed off the top by a smaller height go to
    /// the history. A size outside the accepted range is ignored.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        if !size_is_valid(rows, cols) {
            return;
        }
        if let (Some(r), Some(c)) = (NonZeroU16::new(rows), NonZeroU16::new(cols))
            && self.size() != (rows, cols)
        {
            self.parser.set_size(r, c);
            self.dirty = true;
        }
    }

    /// The colours the client reported at attach (`ScreenRequest.fg` /
    /// `bg`). OSC 10 and 11 queries are answered with them; with `None` they
    /// are not answered.
    pub fn set_client_colors(&mut self, fg: Option<Rgb>, bg: Option<Rgb>) {
        let c = self.parser.callbacks_mut();
        c.fg = fg;
        c.bg = bg;
    }

    /// Lines that scrolled off the top of the primary screen since the last
    /// call, oldest first.
    pub fn take_history(&mut self) -> HistoryBatch {
        let c = self.parser.callbacks_mut();
        c.history_bytes = 0;
        c.history_full = false;
        HistoryBatch {
            skipped: std::mem::take(&mut c.history_skipped),
            lines: c.history.drain(..).collect(),
        }
    }

    /// Effects dropped for size or count so far (never reset).
    pub fn effects_dropped(&self) -> u64 {
        self.parser.callbacks().effects_dropped
    }

    /// The screen as a normalised state, without numbering it.
    pub fn snapshot(&self) -> ScreenState {
        state_of(self.parser.screen())
    }

    /// Freeze the current screen as a numbered state.
    ///
    /// When nothing changed since the latest state (same hash, no new
    /// effects) that state is returned again, with its output offset moved
    /// forward; otherwise the number is the next one.
    pub fn cut(&mut self) -> StateInfo {
        if !self.dirty
            && let Some(latest) = self.cuts.back()
        {
            return latest.info;
        }
        self.dirty = false;
        let state = self.snapshot();
        let hash = state.hash();
        let effects = std::mem::take(&mut self.parser.callbacks_mut().effects);
        if effects.is_empty()
            && let Some(latest) = self.cuts.back_mut()
            && latest.info.hash == hash
        {
            latest.info.output_seq = self.fed_seq;
            return latest.info;
        }
        let info = StateInfo {
            num: self.next_num,
            output_seq: self.fed_seq,
            hash,
        };
        self.next_num += 1;
        for e in effects {
            if let Effect::Title(t) = &e {
                self.last_title = Some(t.clone());
            }
            self.effect_log.push_back((info.num, e));
        }
        while self.effect_log.len() > EFFECT_LOG_MAX {
            self.effect_log.pop_front();
        }
        self.cuts.push_back(Cut { info, state });
        while self.cuts.len() > RETAINED_STATES {
            self.cuts.pop_front();
        }
        if let Some(oldest) = self.cuts.front().map(|c| c.info.num) {
            while self.effect_log.front().is_some_and(|(n, _)| *n <= oldest) {
                self.effect_log.pop_front();
            }
        }
        info
    }

    /// The update that takes a client holding state `base_num` to the
    /// current screen, or `None` if it already has it. `base_num == 0`, or a
    /// base that is no longer retained, gives the full screen with
    /// `base_num` 0 and only the latest window title as an effect (old bells
    /// and clipboard writes are not replayed to a client that missed them).
    pub fn update_since(&mut self, base_num: u64) -> Option<ScreenUpdate> {
        let latest = self.cut();
        if base_num == latest.num {
            return None;
        }
        let new = &self.cuts.back()?.state;
        let base = self
            .cuts
            .iter()
            .find(|c| c.info.num == base_num && base_num != 0 && base_num < latest.num);
        let (base_num, diff, effects) = match base {
            Some(b) => (
                base_num,
                ScreenDiff::between(&b.state, new).ok()?,
                self.effect_log
                    .iter()
                    .filter(|(n, _)| *n > base_num)
                    .map(|(_, e)| e.clone())
                    .collect(),
            ),
            None => {
                let blank = ScreenState::blank(new.rows, new.cols).ok()?;
                (
                    0,
                    ScreenDiff::between(&blank, new).ok()?,
                    self.last_title.iter().cloned().map(Effect::Title).collect(),
                )
            }
        };
        Some(ScreenUpdate {
            base_num,
            new_num: latest.num,
            output_seq: latest.output_seq,
            diff,
            effects,
            state_hash: latest.hash,
        })
    }
}

fn convert_color(c: vt100::Color) -> Color {
    match c {
        vt100::Color::Default => Color::Default,
        vt100::Color::Idx(i) => Color::Idx(i),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

fn convert_cell(cell: &vt100::Cell) -> Cell {
    let mut flags = 0;
    for (on, bit) in [
        (cell.bold(), cell_flags::BOLD),
        (cell.dim(), cell_flags::DIM),
        (cell.italic(), cell_flags::ITALIC),
        (cell.underline(), cell_flags::UNDERLINE),
        (cell.inverse(), cell_flags::INVERSE),
    ] {
        if on {
            flags |= bit;
        }
    }
    let mut text = String::new();
    if cell.is_wide_continuation() {
        flags |= cell_flags::WIDE_CONT;
    } else {
        if cell.is_wide() {
            flags |= cell_flags::WIDE;
        }
        for c in cell.contents().chars() {
            if c.is_control() || text.len() + c.len_utf8() > MAX_CELL_TEXT {
                break;
            }
            text.push(c);
        }
    }
    Cell {
        text: text.into(),
        fg: convert_color(cell.fgcolor()),
        bg: convert_color(cell.bgcolor()),
        flags,
    }
}

fn state_of(screen: &vt100::Screen) -> ScreenState {
    use vt100::{MouseProtocolEncoding as Enc, MouseProtocolMode as Mouse};
    let (rows, cols) = screen.size();
    let (rows, cols) = (rows.get(), cols.get());
    let grid = (0..rows)
        .map(|r| Row {
            cells: (0..cols)
                .map(|c| screen.cell(r, c).map(convert_cell).unwrap_or_default())
                .collect(),
            wrapped: screen.row_wrapped(r),
        })
        .collect();
    let (cursor_row, cursor_col) = screen.cursor_position();
    let mut flags = 0;
    for (on, bit) in [
        (screen.alternate_screen(), Modes::ALT_SCREEN),
        (screen.hide_cursor(), Modes::CURSOR_HIDDEN),
        (screen.application_cursor(), Modes::APP_CURSOR),
        (screen.application_keypad(), Modes::APP_KEYPAD),
        (screen.bracketed_paste(), Modes::BRACKETED_PASTE),
    ] {
        if on {
            flags |= bit;
        }
    }
    ScreenState {
        rows,
        cols,
        cursor_row: cursor_row.min(rows - 1),
        cursor_col: cursor_col.min(cols - 1),
        modes: Modes {
            flags,
            mouse_mode: match screen.mouse_protocol_mode() {
                Mouse::None => 0,
                Mouse::Press => 1,
                Mouse::PressRelease => 2,
                Mouse::ButtonMotion => 3,
                Mouse::AnyMotion => 4,
            },
            mouse_encoding: match screen.mouse_protocol_encoding() {
                Enc::Default => 0,
                Enc::Utf8 => 1,
                Enc::Sgr => 2,
            },
        },
        grid,
    }
}
