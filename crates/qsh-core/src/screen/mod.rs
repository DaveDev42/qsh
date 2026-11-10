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
/// Test-only: a slice holding this makes [`HostScreen::feed`] panic inside
/// the emulator guard, to exercise the rebuild.
#[cfg(test)]
pub(crate) const PANIC_TRIGGER: &[u8] = b"\x00qsh-test-emulator-panic\x00";

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
    /// Leading bytes of a U+FE0F that a feed ended in the middle of.
    vs16: Vs16Filter,
    /// Times the emulator panicked and was rebuilt (see [`Self::feed`]).
    resets: u64,
}

/// Replaces U+FE0F (VARIATION SELECTOR-16, `EF B8 8F`) in the byte stream with
/// a NUL before it reaches the emulator, across feed boundaries.
///
/// `vt100` 0.18.1 widens the previous cell when U+FE0F follows a character
/// that has an emoji presentation (`0`, `#`, `(c)`, hearts), and the code
/// that repairs the neighbouring cells afterwards unwraps cells that do not
/// exist when the widened cell sits at the end of a row (`text_cleanup` in
/// `screen.rs`, lines 985, 1000 and 1013). A one-column screen with `0`
/// then U+FE0F panics; so do 3x2 and 2x3 screens fed a short wrapped
/// sequence. A program's output is untrusted, and the panic would kill the
/// session's output pump, so the selector never gets there. This is the only
/// path by which `vt100` widens a cell that is already drawn, so without it
/// the emulator only draws characters at their own width. The cost: an
/// emoji that needs the selector (a heart, a keycap) takes the one cell its
/// text form has instead of two. `docs/design/threat-model.md` C23 pins it.
///
/// The selector becomes a NUL, which the emulator ignores, and is not simply
/// removed: removing it would join the bytes on either side of it, and
/// `EF` + `EF B8 8F` + `B8 8F` would then hold a selector that was not in the
/// input. A replacement shares no byte with the sequence, so a single pass
/// leaves none behind.
#[derive(Debug, Default)]
struct Vs16Filter {
    held: [u8; 2],
    held_len: u8,
}

impl Vs16Filter {
    const SEQ: [u8; 3] = [0xEF, 0xB8, 0x8F];

    /// `data` with every U+FE0F turned into a NUL, preceded by the bytes held
    /// over from the last call. A trailing `EF` or `EF B8` is held until the next call
    /// decides whether it began one; it is an incomplete character the
    /// emulator would not have drawn yet anyway.
    fn filter<'a>(&mut self, data: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        if self.held_len == 0 && !data.contains(&Self::SEQ[0]) {
            return std::borrow::Cow::Borrowed(data);
        }
        let mut out = Vec::with_capacity(data.len() + 2);
        let mut have = usize::from(self.held_len);
        let mut pending = self.held;
        for &b in data {
            if b == Self::SEQ[have] {
                if have == 2 {
                    have = 0; // a whole U+FE0F
                    out.push(0);
                } else {
                    pending[have] = b;
                    have += 1;
                }
                continue;
            }
            // Not the next byte of the sequence: release what was held.
            out.extend_from_slice(&pending[..have]);
            have = 0;
            if b == Self::SEQ[0] {
                pending[0] = b;
                have = 1;
            } else {
                out.push(b);
            }
        }
        self.held = pending;
        self.held_len = have as u8;
        std::borrow::Cow::Owned(out)
    }
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
            vs16: Vs16Filter::default(),
            resets: 0,
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
    ///
    /// A panic inside the emulator on a slice does not escape: the output
    /// pump that calls this is the only thing moving the session's output,
    /// and a program's bytes are untrusted, so one that trips a `vt100` bug
    /// must not silence the session. The slice is dropped, the emulator is
    /// rebuilt blank at the same size (keeping the collected history,
    /// effects, answers and client colours) and every retained state is
    /// forgotten, so the next [`Self::update_since`] for any client is a
    /// full screen. See [`Self::emulator_resets`].
    pub fn feed(&mut self, data: &[u8], end_seq: u64) {
        let data = self.vs16.filter(data);
        for slice in data.chunks(FEED_SLICE) {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(test)]
                if slice
                    .windows(PANIC_TRIGGER.len())
                    .any(|w| w == PANIC_TRIGGER)
                {
                    panic!("injected emulator panic");
                }
                self.parser.process(slice);
            }));
            if outcome.is_err() {
                self.rebuild_emulator();
            }
        }
        self.fed_seq = end_seq;
        self.dirty = true;
    }

    /// How many times the emulator panicked on fed bytes and was rebuilt.
    pub fn emulator_resets(&self) -> u64 {
        self.resets
    }

    /// Replace a panicked emulator with a blank one of the same size.
    ///
    /// The old parser may be half-way through an operation, so none of its
    /// screen is trusted. What the collector holds is plain data the panic
    /// cannot have corrupted beyond the slice that caused it, so it moves
    /// to the new parser. Dropping the retained states makes the next
    /// update for every client a full screen (an unretained base), which the
    /// client applies like any other.
    fn rebuild_emulator(&mut self) {
        let (rows, cols) = self.size();
        let collector = std::mem::replace(self.parser.callbacks_mut(), Collector::new(0, 0));
        self.parser = vt100::Parser::new_with_callbacks(
            NonZeroU16::new(rows).unwrap_or(vt100::Parser::DEFAULT_ROWS),
            NonZeroU16::new(cols).unwrap_or(vt100::Parser::DEFAULT_COLS),
            0,
            collector,
        );
        self.cuts.clear();
        self.effect_log.clear();
        self.vs16 = Vs16Filter::default();
        self.resets += 1;
        tracing::error!(
            rows,
            cols,
            resets = self.resets,
            "terminal emulator panicked on session output; rebuilt it and resyncing clients"
        );
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
