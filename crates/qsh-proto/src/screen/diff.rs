//! [`ScreenDiff`], [`Effect`] and [`ScreenUpdate`]: computing, applying,
//! encoding and decoding them (ADR-0052 decision 5).

use super::codec::{DecodeError, Reader, cell_is_valid, put_cell, put_string, put_varint};
use super::{BadSize, Cell, HASH_LEN, Modes, Row, ScreenState, size_is_valid};

/// Longest accepted window title, in bytes.
pub const MAX_TITLE_BYTES: usize = 1024;
/// Longest accepted OSC 52 payload (base64 text), in bytes.
pub const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;
/// Longest accepted OSC 8 parameter string, in bytes.
pub const MAX_HYPERLINK_PARAMS: usize = 256;
/// Longest accepted OSC 8 URI, in bytes.
pub const MAX_HYPERLINK_URI: usize = 2048;
/// Most effects one [`ScreenUpdate`] carries.
pub const MAX_EFFECTS: usize = 64;
/// Largest accepted encoded [`ScreenUpdate`]. Equal to the datagram
/// reassembly cap of ADR-0052 decision 6.
pub const MAX_UPDATE_BYTES: usize = 1024 * 1024;

/// Two changed cells at most this far apart share one [`Run`] (the cells in
/// between are sent too), because a run header costs about as much.
const MERGE_GAP: usize = 4;
const MAX_SELECTION_BYTES: usize = 8;

/// Why a diff cannot be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// The diff's size is not an accepted size.
    #[error("diff has an invalid size")]
    BadSize,
    /// The cursor is outside the screen, or a mode value is out of range.
    #[error("diff has an invalid cursor or mode")]
    BadHeader,
    /// A change names a row, a column span or a cell outside the rules.
    #[error("diff change is out of range")]
    OutOfRange,
    /// The state after applying does not match `state_hash`.
    #[error("state hash does not match the applied state")]
    HashMismatch,
}

impl From<BadSize> for ApplyError {
    fn from(_: BadSize) -> Self {
        Self::BadSize
    }
}

/// Consecutive replaced cells of one row, starting at column `col`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// First column.
    pub col: u16,
    /// The new cells, at least one.
    pub cells: Vec<Cell>,
}

/// New content of one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowChange {
    /// Row index.
    pub row: u16,
    /// The row's wrap flag after the change.
    pub wrapped: bool,
    /// Replaced spans, ascending and non-overlapping. May be empty when only
    /// the wrap flag changed.
    pub runs: Vec<Run>,
}

/// Cell-level difference between two [`ScreenState`]s of the same session.
///
/// Size, cursor and mode bits are always sent in full (a few bytes). The
/// grid carries only changed rows. If the new size differs from the base's,
/// the base counts as blank at the new size, so a resize costs a full
/// repaint and no cell of the old grid has to be mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenDiff {
    /// New row count.
    pub rows: u16,
    /// New column count.
    pub cols: u16,
    /// New cursor row.
    pub cursor_row: u16,
    /// New cursor column.
    pub cursor_col: u16,
    /// New mode bits.
    pub modes: Modes,
    /// Changed rows, strictly ascending by `row`.
    pub changes: Vec<RowChange>,
}

impl ScreenDiff {
    /// The difference that turns `base` into `new`. Pass
    /// [`ScreenState::blank`] as `base` for the full-screen update.
    pub fn between(base: &ScreenState, new: &ScreenState) -> Result<Self, BadSize> {
        let blank;
        let base = if base.rows == new.rows && base.cols == new.cols {
            base
        } else {
            blank = ScreenState::blank(new.rows, new.cols)?;
            &blank
        };
        let mut changes = Vec::new();
        for (r, (old, row)) in base.grid.iter().zip(&new.grid).enumerate() {
            let mut runs = Vec::new();
            let n = row.cells.len();
            let mut c = 0;
            while c < n {
                if old.cells[c] == row.cells[c] {
                    c += 1;
                    continue;
                }
                let start = c;
                let mut end = c + 1;
                let mut k = end;
                while k < n && k - end <= MERGE_GAP {
                    if old.cells[k] != row.cells[k] {
                        end = k + 1;
                    }
                    k += 1;
                }
                runs.push(Run {
                    col: start as u16,
                    cells: row.cells[start..end].to_vec(),
                });
                c = end;
            }
            if !runs.is_empty() || old.wrapped != row.wrapped {
                changes.push(RowChange {
                    row: r as u16,
                    wrapped: row.wrapped,
                    runs,
                });
            }
        }
        Ok(Self {
            rows: new.rows,
            cols: new.cols,
            cursor_row: new.cursor_row,
            cursor_col: new.cursor_col,
            modes: new.modes,
            changes,
        })
    }

    /// Apply to `base`, giving the new state. A base of a different size is
    /// treated as blank at the new size.
    pub fn apply(&self, base: &ScreenState) -> Result<ScreenState, ApplyError> {
        if !size_is_valid(self.rows, self.cols) {
            return Err(ApplyError::BadSize);
        }
        if self.cursor_row >= self.rows || self.cursor_col >= self.cols || !self.modes.is_valid() {
            return Err(ApplyError::BadHeader);
        }
        let mut out = if base.rows == self.rows && base.cols == self.cols {
            base.clone()
        } else {
            ScreenState::blank(self.rows, self.cols)?
        };
        out.cursor_row = self.cursor_row;
        out.cursor_col = self.cursor_col;
        out.modes = self.modes;
        let mut last_row = None;
        for change in &self.changes {
            if change.row >= self.rows || last_row.is_some_and(|l| change.row <= l) {
                return Err(ApplyError::OutOfRange);
            }
            last_row = Some(change.row);
            let row: &mut Row = &mut out.grid[usize::from(change.row)];
            row.wrapped = change.wrapped;
            let mut next_free = 0usize;
            for run in &change.runs {
                let start = usize::from(run.col);
                let end = start + run.cells.len();
                if run.cells.is_empty()
                    || start < next_free
                    || end > usize::from(self.cols)
                    || !run.cells.iter().all(cell_is_valid)
                {
                    return Err(ApplyError::OutOfRange);
                }
                row.cells[start..end].clone_from_slice(&run.cells);
                next_free = end;
            }
        }
        Ok(out)
    }

    /// Append the encoding to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        for v in [self.rows, self.cols, self.cursor_row, self.cursor_col] {
            put_varint(out, u64::from(v));
        }
        out.extend_from_slice(&[
            self.modes.flags,
            self.modes.mouse_mode,
            self.modes.mouse_encoding,
        ]);
        put_varint(out, self.changes.len() as u64);
        for change in &self.changes {
            put_varint(out, u64::from(change.row));
            out.push(u8::from(change.wrapped));
            put_varint(out, change.runs.len() as u64);
            for run in &change.runs {
                put_varint(out, u64::from(run.col));
                put_varint(out, run.cells.len() as u64);
                for cell in &run.cells {
                    put_cell(out, cell);
                }
            }
        }
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let rows = r.varint_u16()?;
        let cols = r.varint_u16()?;
        if !size_is_valid(rows, cols) {
            return Err(DecodeError::Invalid("screen size out of range"));
        }
        let cursor_row = r.varint_u16()?;
        let cursor_col = r.varint_u16()?;
        if cursor_row >= rows || cursor_col >= cols {
            return Err(DecodeError::Invalid("cursor outside the screen"));
        }
        let modes = Modes {
            flags: r.u8()?,
            mouse_mode: r.u8()?,
            mouse_encoding: r.u8()?,
        };
        if !modes.is_valid() {
            return Err(DecodeError::Invalid("mode value out of range"));
        }
        // A change is at least a row, a wrap flag and a run count.
        let n_changes = r.count(3)?;
        if n_changes > usize::from(rows) {
            return Err(DecodeError::Invalid("more changed rows than rows"));
        }
        let mut changes = Vec::with_capacity(n_changes);
        let mut last_row: Option<u16> = None;
        for _ in 0..n_changes {
            let row = r.varint_u16()?;
            if row >= rows || last_row.is_some_and(|l| row <= l) {
                return Err(DecodeError::Invalid("changed rows are not ascending"));
            }
            last_row = Some(row);
            let wrapped = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::Invalid("wrap flag is not 0 or 1")),
            };
            // A run is at least a column, a count and one two-byte cell.
            let n_runs = r.count(4)?;
            if n_runs > usize::from(cols) {
                return Err(DecodeError::Invalid("more runs than columns"));
            }
            let mut runs = Vec::with_capacity(n_runs);
            let mut next_free = 0usize;
            for _ in 0..n_runs {
                let col = r.varint_u16()?;
                let n_cells = r.count(2)?;
                let start = usize::from(col);
                if n_cells == 0 || start < next_free || start + n_cells > usize::from(cols) {
                    return Err(DecodeError::Invalid(
                        "run is empty, overlapping or off the row",
                    ));
                }
                let mut cells = Vec::with_capacity(n_cells);
                for _ in 0..n_cells {
                    cells.push(r.cell()?);
                }
                next_free = start + n_cells;
                runs.push(Run { col, cells });
            }
            changes.push(RowChange { row, wrapped, runs });
        }
        Ok(Self {
            rows,
            cols,
            cursor_row,
            cursor_col,
            modes,
            changes,
        })
    }

    /// Decode a diff that fills `bytes` exactly. Total: never panics and
    /// never allocates more than the input length justifies.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let diff = Self::read(&mut r)?;
        r.finish()?;
        Ok(diff)
    }
}

/// An effect outside the screen grid (ADR-0052 decision 4) that the client
/// replays on its local terminal. Text fields hold no control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Window title (OSC 0 / 2).
    Title(String),
    /// Bell (BEL). Consecutive bells collapse into one.
    Bell,
    /// Clipboard write (OSC 52). `selection` is the target letters
    /// (`c`, `p`, `s`, digits), `data` the base64 payload as sent.
    Clipboard {
        /// Selection letters.
        selection: String,
        /// Base64 text.
        data: String,
    },
    /// Hyperlink open or close (OSC 8). An empty `uri` closes.
    Hyperlink {
        /// The `key=value:...` parameter string.
        params: String,
        /// The target, or empty to close the link.
        uri: String,
    },
}

fn plain_text(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(char::is_control)
}

fn base64_text(s: &str) -> bool {
    s.len() <= MAX_CLIPBOARD_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

fn selection_text(s: &str) -> bool {
    s.len() <= MAX_SELECTION_BYTES && s.bytes().all(|b| b"cpqs01234567".contains(&b))
}

impl Effect {
    /// Whether the effect obeys the limits [`ScreenUpdate::decode`] enforces.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Title(t) => plain_text(t, MAX_TITLE_BYTES),
            Self::Bell => true,
            Self::Clipboard { selection, data } => selection_text(selection) && base64_text(data),
            Self::Hyperlink { params, uri } => {
                plain_text(params, MAX_HYPERLINK_PARAMS) && plain_text(uri, MAX_HYPERLINK_URI)
            }
        }
    }

    fn put(&self, out: &mut Vec<u8>) {
        match self {
            Self::Title(t) => {
                out.push(1);
                put_string(out, t);
            }
            Self::Bell => out.push(2),
            Self::Clipboard { selection, data } => {
                out.push(3);
                put_string(out, selection);
                put_string(out, data);
            }
            Self::Hyperlink { params, uri } => {
                out.push(4);
                put_string(out, params);
                put_string(out, uri);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let effect = match r.u8()? {
            1 => Self::Title(r.string(MAX_TITLE_BYTES)?),
            2 => Self::Bell,
            3 => Self::Clipboard {
                selection: r.string(MAX_SELECTION_BYTES)?,
                data: r.string(MAX_CLIPBOARD_BYTES)?,
            },
            4 => Self::Hyperlink {
                params: r.string(MAX_HYPERLINK_PARAMS)?,
                uri: r.string(MAX_HYPERLINK_URI)?,
            },
            _ => return Err(DecodeError::Invalid("unknown effect kind")),
        };
        if !effect.is_valid() {
            return Err(DecodeError::Invalid("effect text breaks its rules"));
        }
        Ok(effect)
    }
}

/// The host's screen message (ADR-0052 decision 5): the difference from
/// state `base_num` to state `new_num`, the output offset the new state
/// reflects, the effects that happened up to it, and the hash the client
/// compares after applying.
///
/// `base_num == 0` is the blank screen, so the update is the full screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenUpdate {
    /// State the diff applies to; 0 for the blank screen.
    pub base_num: u64,
    /// State the diff produces. Greater than `base_num`.
    pub new_num: u64,
    /// Cumulative output offset (`docs/design/protocol.md` §8) the new state
    /// reflects.
    pub output_seq: u64,
    /// The cell difference.
    pub diff: ScreenDiff,
    /// Effects between `base_num` and `new_num`, in order.
    pub effects: Vec<Effect>,
    /// [`ScreenState::hash`] of the new state.
    pub state_hash: [u8; HASH_LEN],
}

impl ScreenUpdate {
    /// Apply to `base` and verify the result against `state_hash`.
    pub fn apply(&self, base: &ScreenState) -> Result<ScreenState, ApplyError> {
        let state = self.diff.apply(base)?;
        if state.hash() == self.state_hash {
            Ok(state)
        } else {
            Err(ApplyError::HashMismatch)
        }
    }

    /// The encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, self.base_num);
        put_varint(&mut out, self.new_num);
        put_varint(&mut out, self.output_seq);
        out.extend_from_slice(&self.state_hash);
        put_varint(&mut out, self.effects.len() as u64);
        for e in &self.effects {
            e.put(&mut out);
        }
        self.diff.encode_into(&mut out);
        out
    }

    /// Decode an update that fills `bytes` exactly. Total over arbitrary
    /// bytes; accepted input re-encodes to itself.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_UPDATE_BYTES {
            return Err(DecodeError::Invalid("update is larger than the cap"));
        }
        let mut r = Reader::new(bytes);
        let base_num = r.varint()?;
        let new_num = r.varint()?;
        if new_num <= base_num {
            return Err(DecodeError::Invalid("new_num is not greater than base_num"));
        }
        let output_seq = r.varint()?;
        let mut state_hash = [0u8; HASH_LEN];
        state_hash.copy_from_slice(r.take(HASH_LEN)?);
        let n_effects = r.count(1)?;
        if n_effects > MAX_EFFECTS {
            return Err(DecodeError::Invalid("too many effects"));
        }
        let mut effects = Vec::with_capacity(n_effects);
        for _ in 0..n_effects {
            effects.push(Effect::read(&mut r)?);
        }
        let diff = ScreenDiff::read(&mut r)?;
        r.finish()?;
        Ok(Self {
            base_num,
            new_num,
            output_seq,
            diff,
            effects,
            state_hash,
        })
    }
}
