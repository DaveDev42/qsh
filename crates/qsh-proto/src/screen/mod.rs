//! Screen state model and its diff codec (ADR-0052 decisions 4 and 5,
//! `docs/design/protocol.md` §18 draft).
//!
//! Sans-IO. [`ScreenState`] is the normalised terminal screen both sides
//! agree on: size, cursor, mode bits and a grid of [`Cell`]s. It is not a
//! VT byte stream, so two qsh versions with different emulators still
//! produce the same state for the same screen, and [`ScreenState::hash`]
//! (BLAKE3, first 8 bytes of the canonical encoding) is comparable across
//! them. [`ScreenDiff`] is a cell-level difference between two states and
//! [`ScreenUpdate`] is the message that carries one together with its
//! out-of-screen [`Effect`]s.
//!
//! Every decoder here is total over arbitrary bytes (it is a fuzz surface)
//! and canonical: bytes that decode re-encode to the same bytes, which the
//! `decode_screen_diff` fuzz target asserts. The `screen.v1` capability
//! carries the encoded [`ScreenUpdate`] on the session data stream in parts
//! ([`split_parts`], [`Reassembler`]).

mod codec;
mod diff;
mod parts;
#[cfg(test)]
mod tests;

pub use codec::DecodeError;
pub use diff::{
    ApplyError, Effect, MAX_CLIPBOARD_BYTES, MAX_EFFECTS, MAX_HYPERLINK_PARAMS, MAX_HYPERLINK_URI,
    MAX_TITLE_BYTES, MAX_UPDATE_BYTES, RowChange, Run, ScreenDiff, ScreenUpdate,
};
pub use parts::{
    DatagramReassembler, MAX_DATAGRAM_PARTS, MAX_PARTS, PART_MAX, PartError, Reassembler,
    split as split_parts, split_sized as split_parts_sized,
};

/// Largest accepted number of rows or columns.
pub const MAX_DIM: u16 = 2048;
/// Largest accepted `rows * cols`. Bounds what applying a decoded diff may
/// allocate.
pub const MAX_CELLS: usize = 1 << 20;
/// Longest accepted text of one cell, in bytes (a base character plus
/// combining marks or a ZWJ sequence).
pub const MAX_CELL_TEXT: usize = 32;
/// Length of [`ScreenState::hash`].
pub const HASH_LEN: usize = 8;

/// A cell colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    /// The terminal's default colour.
    #[default]
    Default,
    /// An entry of the 256-colour palette.
    Idx(u8),
    /// True colour.
    Rgb(u8, u8, u8),
}

/// Bits of [`Cell::flags`].
pub mod cell_flags {
    /// Bold.
    pub const BOLD: u8 = 1;
    /// Dim.
    pub const DIM: u8 = 2;
    /// Italic.
    pub const ITALIC: u8 = 4;
    /// Underline.
    pub const UNDERLINE: u8 = 8;
    /// Inverse video.
    pub const INVERSE: u8 = 16;
    /// The cell holds a double-width character; the next cell is its
    /// continuation.
    pub const WIDE: u8 = 32;
    /// The cell is the right half of the double-width cell before it. Its
    /// text is empty.
    pub const WIDE_CONT: u8 = 64;
    /// Every defined bit.
    pub const ALL: u8 = 127;
}

/// One screen cell. A blank cell has empty `text`, default colours and no
/// flags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cell {
    /// The characters shown in the cell: empty, one character, or a base
    /// character with combining marks.
    pub text: Box<str>,
    /// Foreground.
    pub fg: Color,
    /// Background.
    pub bg: Color,
    /// [`cell_flags`] bits.
    pub flags: u8,
}

/// One screen row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// `cols` cells.
    pub cells: Vec<Cell>,
    /// The row continues on the next one (soft wrap).
    pub wrapped: bool,
}

/// Terminal modes the client has to mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modes {
    /// [`Modes::ALT_SCREEN`] and the other flag bits.
    pub flags: u8,
    /// 0 none, 1 press (9), 2 press and release (1000), 3 button motion
    /// (1002), 4 any motion (1003).
    pub mouse_mode: u8,
    /// 0 default, 1 UTF-8 (1005), 2 SGR (1006).
    pub mouse_encoding: u8,
}

impl Modes {
    /// The alternate screen is active.
    pub const ALT_SCREEN: u8 = 1;
    /// The cursor is hidden.
    pub const CURSOR_HIDDEN: u8 = 2;
    /// Application cursor keys (DECCKM).
    pub const APP_CURSOR: u8 = 4;
    /// Application keypad (DECKPAM).
    pub const APP_KEYPAD: u8 = 8;
    /// Bracketed paste (2004).
    pub const BRACKETED_PASTE: u8 = 16;
    const FLAGS_ALL: u8 = 31;

    pub(crate) fn is_valid(self) -> bool {
        self.flags & !Self::FLAGS_ALL == 0 && self.mouse_mode <= 4 && self.mouse_encoding <= 2
    }
}

/// A normalised terminal screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenState {
    /// Row count.
    pub rows: u16,
    /// Column count.
    pub cols: u16,
    /// Cursor row, 0-based, `< rows`.
    pub cursor_row: u16,
    /// Cursor column, 0-based, `< cols`.
    pub cursor_col: u16,
    /// Mode bits.
    pub modes: Modes,
    /// `rows` rows of `cols` cells.
    pub grid: Vec<Row>,
}

/// Why a size is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("screen size {rows}x{cols} is outside 1..={MAX_DIM} per side or over {MAX_CELLS} cells")]
pub struct BadSize {
    /// Rows asked for.
    pub rows: u16,
    /// Columns asked for.
    pub cols: u16,
}

/// Whether `rows x cols` is an accepted size.
pub fn size_is_valid(rows: u16, cols: u16) -> bool {
    (1..=MAX_DIM).contains(&rows)
        && (1..=MAX_DIM).contains(&cols)
        && usize::from(rows) * usize::from(cols) <= MAX_CELLS
}

impl ScreenState {
    /// The blank screen of a size: "base 0" of the protocol. Diffing a state
    /// against it gives the full-screen update.
    pub fn blank(rows: u16, cols: u16) -> Result<Self, BadSize> {
        if !size_is_valid(rows, cols) {
            return Err(BadSize { rows, cols });
        }
        let row = Row {
            cells: vec![Cell::default(); usize::from(cols)],
            wrapped: false,
        };
        Ok(Self {
            rows,
            cols,
            cursor_row: 0,
            cursor_col: 0,
            modes: Modes::default(),
            grid: vec![row; usize::from(rows)],
        })
    }

    /// The canonical byte form [`ScreenState::hash`] is taken over:
    /// dimensions, cursor, modes, then every row's wrap flag and cells in
    /// the cell encoding of the diff codec.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + usize::from(self.rows) * usize::from(self.cols) * 2);
        for v in [self.rows, self.cols, self.cursor_row, self.cursor_col] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&[
            self.modes.flags,
            self.modes.mouse_mode,
            self.modes.mouse_encoding,
        ]);
        for row in &self.grid {
            out.push(u8::from(row.wrapped));
            for cell in &row.cells {
                codec::put_cell(&mut out, cell);
            }
        }
        out
    }

    /// `state_hash` of ADR-0052 decision 5: the first [`HASH_LEN`] bytes of
    /// BLAKE3 over [`ScreenState::canonical_bytes`].
    pub fn hash(&self) -> [u8; HASH_LEN] {
        let digest = blake3::hash(&self.canonical_bytes());
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&digest.as_bytes()[..HASH_LEN]);
        out
    }

    /// Structural check: sizes, cursor, modes and every cell's invariants.
    pub fn is_valid(&self) -> bool {
        size_is_valid(self.rows, self.cols)
            && self.cursor_row < self.rows
            && self.cursor_col < self.cols
            && self.modes.is_valid()
            && self.grid.len() == usize::from(self.rows)
            && self.grid.iter().all(|r| {
                r.cells.len() == usize::from(self.cols) && r.cells.iter().all(codec::cell_is_valid)
            })
    }
}
