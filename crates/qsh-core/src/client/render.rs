//! Drawing the synced screen on the local terminal (ADR-0052 decisions 4 and
//! 11, `docs/design/protocol.md` §18.10).
//!
//! [`ScreenRenderer`] turns a [`ScreenState`] into the terminal bytes that
//! take the local terminal from what it shows now to that state. It keeps
//! the frame it last drew, so an update that changed three cells costs three
//! cells, not a repaint. It does no I/O and reads no terminal: the caller
//! passes the local window size on every call and writes the returned bytes.
//!
//! What it decides:
//!
//! - **Size mismatch.** The host screen is the PTY's size; the local window
//!   can differ (another attach resized the PTY, or a resize has not
//!   reached the host yet). A larger host screen is cropped: columns on the
//!   right are dropped, rows keep the cursor visible (the window is the
//!   host rows ending at the cursor row when the cursor is below it). A
//!   smaller one is filled with blank cells. A double-width character the
//!   crop would cut in half is drawn as a blank.
//! - **First frame.** The terminal already shows the command that started
//!   `qsh` and anything the client printed before attaching, so the first
//!   frame scrolls the window up by its height before painting.
//! - **Diff.** Rows are compared cell by cell with the previous frame and
//!   only the changed runs are written, each after one absolute cursor
//!   move. The pen (colours and attributes) is always written absolute, so
//!   no state from before the draw is trusted. A full repaint (first frame,
//!   size change, alternate screen switch, [`ScreenRenderer::invalidate`])
//!   writes every cell and never clears the screen, which keeps the local
//!   scrollback clean.
//! - **Modes.** Alternate screen, cursor visibility, application cursor and
//!   keypad, bracketed paste and mouse reporting are mirrored when they
//!   change, so the local terminal turns key presses and mouse events into
//!   the bytes the remote program asked for.
//! - **Effects.** The window title, bell, clipboard write and hyperlink
//!   effects an update carries are written once, with the update that
//!   carried them; a repaint never repeats them. A hyperlink opened by an
//!   effect is closed again before the draw returns, because cells carry no
//!   link attribute.
//!
//! [`ScreenRenderer::reset`] gives the bytes that put the local terminal's
//! modes back when the attach ends.

use qsh_proto::screen::{Cell, Color, Effect, Modes, ScreenState, cell_flags};

#[cfg(test)]
mod tests;

/// Equal cells between two changed runs of a row that make a second cursor
/// move cheaper than rewriting them.
const GAP_SPLIT: usize = 6;
/// A tail of blank cells at least this long is erased with `EL` instead of
/// being written as spaces.
const ERASE_TAIL_MIN: usize = 4;

/// The attributes a run of cells is drawn with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Pen {
    fg: Color,
    bg: Color,
    flags: u8,
}

impl Pen {
    fn of(cell: &Cell) -> Self {
        Self {
            fg: cell.fg,
            bg: cell.bg,
            flags: cell.flags
                & (cell_flags::BOLD
                    | cell_flags::DIM
                    | cell_flags::ITALIC
                    | cell_flags::UNDERLINE
                    | cell_flags::INVERSE),
        }
    }

    /// `CSI 0 ; ... m`, absolute: it does not depend on the previous pen.
    fn sgr(self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"\x1b[0");
        for (bit, code) in [
            (cell_flags::BOLD, 1),
            (cell_flags::DIM, 2),
            (cell_flags::ITALIC, 3),
            (cell_flags::UNDERLINE, 4),
            (cell_flags::INVERSE, 7),
        ] {
            if self.flags & bit != 0 {
                push_num(out, b';', code);
            }
        }
        color(out, self.fg, 30, 90, 38);
        color(out, self.bg, 40, 100, 48);
        out.push(b'm');
    }
}

fn color(out: &mut Vec<u8>, c: Color, base: u32, bright: u32, ext: u32) {
    match c {
        Color::Default => {}
        Color::Idx(i) if i < 8 => push_num(out, b';', base + u32::from(i)),
        Color::Idx(i) if i < 16 => push_num(out, b';', bright + u32::from(i) - 8),
        Color::Idx(i) => {
            push_num(out, b';', ext);
            push_num(out, b';', 5);
            push_num(out, b';', u32::from(i));
        }
        Color::Rgb(r, g, b) => {
            push_num(out, b';', ext);
            push_num(out, b';', 2);
            for v in [r, g, b] {
                push_num(out, b';', u32::from(v));
            }
        }
    }
}

fn push_num(out: &mut Vec<u8>, sep: u8, n: u32) {
    out.push(sep);
    out.extend_from_slice(n.to_string().as_bytes());
}

/// The host screen as it is shown at the local window size.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    cols: u16,
    rows: u16,
    /// `rows * cols` cells, row-major.
    cells: Vec<Cell>,
    cursor_row: u16,
    cursor_col: u16,
}

impl Frame {
    fn row(&self, r: u16) -> &[Cell] {
        let c = usize::from(self.cols);
        &self.cells[usize::from(r) * c..(usize::from(r) + 1) * c]
    }

    /// Fit `state` to a `cols` x `rows` window: crop what does not fit,
    /// blank what is missing.
    fn fit(state: &ScreenState, cols: u16, rows: u16) -> Self {
        // Crop rows so the cursor row stays on screen.
        let row_offset = if state.rows > rows {
            usize::from(state.cursor_row + 1)
                .saturating_sub(usize::from(rows))
                .min(usize::from(state.rows - rows))
        } else {
            0
        };
        let mut cells = Vec::with_capacity(usize::from(rows) * usize::from(cols));
        for r in 0..usize::from(rows) {
            let src = state.grid.get(r + row_offset);
            for c in 0..usize::from(cols) {
                let mut cell = src
                    .and_then(|row| row.cells.get(c))
                    .cloned()
                    .unwrap_or_default();
                // A wide character whose right half the crop cut off, or
                // whose left half it cut off.
                let cut = (cell.flags & cell_flags::WIDE != 0 && c + 1 == usize::from(cols))
                    || (cell.flags & cell_flags::WIDE_CONT != 0 && c == 0);
                if cut {
                    cell = Cell::default();
                }
                cells.push(visible(cell));
            }
        }
        let cursor_row = state
            .cursor_row
            .saturating_sub(row_offset as u16)
            .min(rows - 1);
        Self {
            cols,
            rows,
            cells,
            cursor_row,
            cursor_col: state.cursor_col.min(cols - 1),
        }
    }
}

/// The cell as the local terminal can show it: a written space and an
/// erased cell look the same, and the foreground of a blank only shows
/// through an underline or inverse video.
pub(crate) fn visible(mut cell: Cell) -> Cell {
    if &*cell.text == " " {
        cell.text = "".into();
    }
    if cell.text.is_empty() && cell.flags & (cell_flags::UNDERLINE | cell_flags::INVERSE) == 0 {
        cell.fg = Color::Default;
    }
    cell
}

/// Turns synced screen states into terminal bytes. See the module docs.
#[derive(Debug, Default)]
pub struct ScreenRenderer {
    /// What the local terminal shows; `None` when unknown (nothing drawn
    /// yet, or [`Self::invalidate`]).
    drawn: Option<Frame>,
    /// The modes this renderer has set on the local terminal.
    modes: Modes,
    /// Whether a mode other than the default was ever written, so
    /// [`Self::reset`] has something to undo.
    touched: bool,
    /// Whether the first frame has been drawn.
    started: bool,
}

impl ScreenRenderer {
    /// A renderer for a terminal in its default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget what the local terminal shows: the next [`Self::draw`] writes
    /// every cell. Call it when something else may have written to the
    /// terminal (a resize reflow, a diagnostic line, a new connection).
    pub fn invalidate(&mut self) {
        self.drawn = None;
    }

    /// The bytes that take the local terminal from what it shows to
    /// `state`, drawn into a window of `local` = (columns, rows), followed
    /// by `effects` (written once, here and never again). An empty result
    /// means nothing changed.
    pub fn draw(&mut self, state: &ScreenState, effects: &[Effect], local: (u16, u16)) -> Vec<u8> {
        let (cols, rows) = (local.0.max(1), local.1.max(1));
        let frame = Frame::fit(state, cols, rows);
        let mut out = Vec::new();

        // The first frame lands on a terminal that already shows something:
        // the command line that started `qsh`, the `-L` announcements. Scroll
        // that out of the way (into the local scrollback) instead of painting
        // over it.
        if !self.started {
            self.started = true;
            out.extend_from_slice(format!("\x1b[{rows};1H").as_bytes());
            out.extend(std::iter::repeat_n(b'\n', usize::from(rows)));
        }

        // Mode changes first: leaving or entering the alternate screen
        // changes which buffer the cells below land in.
        let mut full = self
            .drawn
            .as_ref()
            .is_none_or(|d| (d.cols, d.rows) != (cols, rows));
        if (self.modes.flags ^ state.modes.flags) & Modes::ALT_SCREEN != 0 {
            full = true;
        }
        self.write_modes(&state.modes, &mut out);

        let mut body = Vec::new();
        let runs = self.write_cells(&frame, full, &mut body);
        // Hide the cursor while several runs are written, so it does not
        // flash across the screen.
        let hide = runs > 1 && state.modes.flags & Modes::CURSOR_HIDDEN == 0;
        if hide {
            out.extend_from_slice(b"\x1b[?25l");
        }
        out.extend_from_slice(&body);

        let cursor_moved = self
            .drawn
            .as_ref()
            .is_none_or(|d| (d.cursor_row, d.cursor_col) != (frame.cursor_row, frame.cursor_col));
        if runs > 0 || cursor_moved || full {
            cup(&mut out, frame.cursor_row, frame.cursor_col);
        }
        if hide {
            out.extend_from_slice(b"\x1b[?25h");
        }
        write_effects(effects, &mut out);
        self.drawn = Some(frame);
        out
    }

    /// The bytes that put the local terminal's modes back to their
    /// defaults. Empty when the renderer never changed one.
    pub fn reset(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.touched {
            self.write_modes(&Modes::default(), &mut out);
            out.extend_from_slice(b"\x1b[0m");
        }
        self.drawn = None;
        out
    }

    fn write_modes(&mut self, to: &Modes, out: &mut Vec<u8>) {
        let from = self.modes;
        let flag = |bit: u8| (from.flags & bit != 0, to.flags & bit != 0);
        let (was, is) = flag(Modes::ALT_SCREEN);
        if was != is {
            out.extend_from_slice(if is { b"\x1b[?1049h" } else { b"\x1b[?1049l" });
        }
        let (was, is) = flag(Modes::CURSOR_HIDDEN);
        if was != is {
            out.extend_from_slice(if is { b"\x1b[?25l" } else { b"\x1b[?25h" });
        }
        let (was, is) = flag(Modes::APP_CURSOR);
        if was != is {
            out.extend_from_slice(if is { b"\x1b[?1h" } else { b"\x1b[?1l" });
        }
        let (was, is) = flag(Modes::APP_KEYPAD);
        if was != is {
            out.extend_from_slice(if is { b"\x1b=" } else { b"\x1b>" });
        }
        let (was, is) = flag(Modes::BRACKETED_PASTE);
        if was != is {
            out.extend_from_slice(if is { b"\x1b[?2004h" } else { b"\x1b[?2004l" });
        }
        if from.mouse_mode != to.mouse_mode {
            if let Some(p) = mouse_param(from.mouse_mode) {
                out.extend_from_slice(format!("\x1b[?{p}l").as_bytes());
            }
            if let Some(p) = mouse_param(to.mouse_mode) {
                out.extend_from_slice(format!("\x1b[?{p}h").as_bytes());
            }
        }
        if from.mouse_encoding != to.mouse_encoding {
            if let Some(p) = encoding_param(from.mouse_encoding) {
                out.extend_from_slice(format!("\x1b[?{p}l").as_bytes());
            }
            if let Some(p) = encoding_param(to.mouse_encoding) {
                out.extend_from_slice(format!("\x1b[?{p}h").as_bytes());
            }
        }
        if *to != Modes::default() {
            self.touched = true;
        }
        self.modes = *to;
    }

    /// Write the cells of `frame` that differ from what is drawn (all of
    /// them when `full`). Returns how many runs were written.
    fn write_cells(&self, frame: &Frame, full: bool, out: &mut Vec<u8>) -> usize {
        let previous = if full { None } else { self.drawn.as_ref() };
        // Every draw ends with the default pen, so a diff starts from it; a
        // full repaint trusts nothing.
        let mut pen: Option<Pen> = previous.map(|_| Pen::default());
        let mut runs = 0;
        for r in 0..frame.rows {
            let now = frame.row(r);
            let spans = match previous {
                Some(prev) => changed_spans(prev.row(r), now),
                None if now.is_empty() => Vec::new(),
                None => vec![(0, now.len())],
            };
            for (start, end) in spans {
                runs += 1;
                cup(out, r, start as u16);
                write_span(now, start, end, &mut pen, out);
            }
        }
        if pen.is_some_and(|p| p != Pen::default()) {
            out.extend_from_slice(b"\x1b[0m");
        }
        runs
    }
}

fn mouse_param(mode: u8) -> Option<u16> {
    match mode {
        1 => Some(9),
        2 => Some(1000),
        3 => Some(1002),
        4 => Some(1003),
        _ => None,
    }
}

fn encoding_param(enc: u8) -> Option<u16> {
    match enc {
        1 => Some(1005),
        2 => Some(1006),
        _ => None,
    }
}

/// Absolute cursor move; `row` and `col` are 0-based.
fn cup(out: &mut Vec<u8>, row: u16, col: u16) {
    out.extend_from_slice(format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
}

/// The column ranges `[start, end)` of a row that differ, merged when
/// closer than [`GAP_SPLIT`] and widened to whole double-width characters.
fn changed_spans(prev: &[Cell], now: &[Cell]) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut c = 0;
    while c < now.len() {
        if prev[c] == now[c] {
            c += 1;
            continue;
        }
        let start = c;
        let mut end = c + 1;
        // Extend through the changed cells, bridging short equal gaps.
        let mut probe = end;
        while probe < now.len() {
            if prev[probe] != now[probe] {
                end = probe + 1;
                probe += 1;
            } else if probe - end < GAP_SPLIT {
                probe += 1;
            } else {
                break;
            }
        }
        spans.push((start, end));
        c = end;
    }
    // A span that ends in cleared cells reaches the row end when only blanks
    // follow it, so the tail is erased instead of written.
    if let Some((_, end)) = spans.last_mut()
        && *end < now.len()
        && is_plain_blank(&now[*end - 1])
        && now[*end..].iter().all(is_plain_blank)
    {
        *end = now.len();
    }
    for (start, end) in &mut spans {
        // Start on the left half of a double-width character.
        if *start > 0 && now[*start].flags & cell_flags::WIDE_CONT != 0 {
            *start -= 1;
        }
        // End after the right half.
        if *end < now.len() && now[*end - 1].flags & cell_flags::WIDE != 0 {
            *end += 1;
        }
    }
    spans
}

/// Write cells `[start, end)` of a row. The cursor is already at `start`.
fn write_span(row: &[Cell], start: usize, end: usize, pen: &mut Option<Pen>, out: &mut Vec<u8>) {
    // A tail of default-coloured blanks to the end of the row is erased.
    let mut stop = end;
    if end == row.len() {
        let blanks = row[start..end]
            .iter()
            .rev()
            .take_while(|c| is_plain_blank(c))
            .count();
        if blanks >= ERASE_TAIL_MIN {
            stop = end - blanks;
        }
    }
    for cell in &row[start..stop] {
        if cell.flags & cell_flags::WIDE_CONT != 0 {
            continue;
        }
        let want = Pen::of(cell);
        if *pen != Some(want) {
            want.sgr(out);
            *pen = Some(want);
        }
        if cell.text.is_empty() {
            out.push(b' ');
        } else {
            out.extend_from_slice(cell.text.as_bytes());
        }
    }
    if stop < end {
        if *pen != Some(Pen::default()) {
            Pen::default().sgr(out);
            *pen = Some(Pen::default());
        }
        out.extend_from_slice(b"\x1b[K");
    }
}

fn is_plain_blank(c: &Cell) -> bool {
    c.text.is_empty() && c.fg == Color::Default && c.bg == Color::Default && c.flags == 0
}

fn write_effects(effects: &[Effect], out: &mut Vec<u8>) {
    let mut link_open = false;
    for effect in effects {
        match effect {
            Effect::Title(t) => {
                out.extend_from_slice(b"\x1b]2;");
                out.extend_from_slice(t.as_bytes());
                out.extend_from_slice(b"\x1b\\");
            }
            Effect::Bell => out.push(0x07),
            Effect::Clipboard { selection, data } => {
                // `?` is a read request, not a write. The decoder already
                // refuses it; this keeps the renderer safe on its own.
                if data.bytes().all(|b| b != b'?') {
                    out.extend_from_slice(b"\x1b]52;");
                    out.extend_from_slice(selection.as_bytes());
                    out.push(b';');
                    out.extend_from_slice(data.as_bytes());
                    out.extend_from_slice(b"\x1b\\");
                }
            }
            Effect::Hyperlink { params, uri } => {
                out.extend_from_slice(b"\x1b]8;");
                out.extend_from_slice(params.as_bytes());
                out.push(b';');
                out.extend_from_slice(uri.as_bytes());
                out.extend_from_slice(b"\x1b\\");
                link_open = !uri.is_empty();
            }
        }
    }
    if link_open {
        out.extend_from_slice(b"\x1b]8;;\x1b\\");
    }
}
