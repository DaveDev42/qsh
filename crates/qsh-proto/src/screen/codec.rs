//! Byte-level helpers shared by the diff, update and canonical encodings.

use super::{Cell, Color, MAX_CELL_TEXT, cell_flags};

/// Why bytes do not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input ended inside a field.
    #[error("input is truncated")]
    Truncated,
    /// The input has bytes after the message.
    #[error("trailing bytes after the message")]
    Trailing,
    /// A field breaks a rule of the format; the text names the rule.
    #[error("invalid field: {0}")]
    Invalid(&'static str),
}

pub(super) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(super) fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub(super) fn finish(&self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }

    pub(super) fn u8(&mut self) -> Result<u8, DecodeError> {
        let (&b, rest) = self.buf.split_first().ok_or(DecodeError::Truncated)?;
        self.buf = rest;
        Ok(b)
    }

    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    /// LEB128, at most 10 bytes, shortest form only (so encoding is
    /// canonical).
    pub(super) fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            let low = u64::from(b & 0x7f);
            if i == 9 && low > 1 {
                return Err(DecodeError::Invalid("varint overflows 64 bits"));
            }
            value |= low << (7 * i);
            if b & 0x80 == 0 {
                if i > 0 && b == 0 {
                    return Err(DecodeError::Invalid("varint is not the shortest form"));
                }
                return Ok(value);
            }
        }
        Err(DecodeError::Invalid("varint is longer than 10 bytes"))
    }

    pub(super) fn varint_u16(&mut self) -> Result<u16, DecodeError> {
        u16::try_from(self.varint()?)
            .map_err(|_| DecodeError::Invalid("value does not fit in 16 bits"))
    }

    /// A count that must be backed by at least `min_bytes_each` remaining
    /// bytes per item, so a hostile count cannot make the caller allocate.
    pub(super) fn count(&mut self, min_bytes_each: usize) -> Result<usize, DecodeError> {
        let n =
            usize::try_from(self.varint()?).map_err(|_| DecodeError::Invalid("count too large"))?;
        if n > self.remaining() / min_bytes_each.max(1) {
            return Err(DecodeError::Truncated);
        }
        Ok(n)
    }

    pub(super) fn string(&mut self, max: usize) -> Result<String, DecodeError> {
        let n =
            usize::try_from(self.varint()?).map_err(|_| DecodeError::Invalid("string too long"))?;
        if n > max {
            return Err(DecodeError::Invalid("string longer than its limit"));
        }
        let bytes = self.take(n)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Invalid("string is not UTF-8"))
    }

    pub(super) fn cell(&mut self) -> Result<Cell, DecodeError> {
        let b0 = self.u8()?;
        let b1 = self.u8()?;
        let flags = b0 & cell_flags::ALL;
        let has_text = b0 & 0x80 != 0;
        if b1 & 0xf0 != 0 {
            return Err(DecodeError::Invalid("reserved colour bits"));
        }
        if flags & cell_flags::WIDE != 0 && flags & cell_flags::WIDE_CONT != 0 {
            return Err(DecodeError::Invalid("cell is both wide and a continuation"));
        }
        if has_text && flags & cell_flags::WIDE_CONT != 0 {
            return Err(DecodeError::Invalid("continuation cell has text"));
        }
        let fg = self.color(b1 & 3)?;
        let bg = self.color((b1 >> 2) & 3)?;
        let text: Box<str> = if has_text {
            let n = usize::try_from(self.varint()?)
                .map_err(|_| DecodeError::Invalid("text too long"))?;
            if n == 0 || n > MAX_CELL_TEXT {
                return Err(DecodeError::Invalid("cell text length is out of range"));
            }
            let s = std::str::from_utf8(self.take(n)?)
                .map_err(|_| DecodeError::Invalid("cell text is not UTF-8"))?;
            if s.chars().any(char::is_control) {
                return Err(DecodeError::Invalid("cell text has a control character"));
            }
            s.into()
        } else {
            Box::default()
        };
        Ok(Cell {
            text,
            fg,
            bg,
            flags,
        })
    }

    fn color(&mut self, kind: u8) -> Result<Color, DecodeError> {
        match kind {
            0 => Ok(Color::Default),
            1 => Ok(Color::Idx(self.u8()?)),
            2 => {
                let b = self.take(3)?;
                Ok(Color::Rgb(b[0], b[1], b[2]))
            }
            _ => Err(DecodeError::Invalid("unknown colour kind")),
        }
    }
}

pub(super) fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let low = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

pub(super) fn put_string(out: &mut Vec<u8>, s: &str) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn color_kind(c: Color) -> u8 {
    match c {
        Color::Default => 0,
        Color::Idx(_) => 1,
        Color::Rgb(..) => 2,
    }
}

fn put_color(out: &mut Vec<u8>, c: Color) {
    match c {
        Color::Default => {}
        Color::Idx(i) => out.push(i),
        Color::Rgb(r, g, b) => out.extend_from_slice(&[r, g, b]),
    }
}

/// Cell encoding: `flags | 0x80 if text`, `fg kind | bg kind << 2`, the
/// colour payloads, then (if text) a varint length and the UTF-8 bytes.
pub(super) fn put_cell(out: &mut Vec<u8>, cell: &Cell) {
    let has_text = !cell.text.is_empty();
    out.push((cell.flags & cell_flags::ALL) | if has_text { 0x80 } else { 0 });
    out.push(color_kind(cell.fg) | (color_kind(cell.bg) << 2));
    put_color(out, cell.fg);
    put_color(out, cell.bg);
    if has_text {
        put_string(out, &cell.text);
    }
}

/// Whether the cell obeys the rules [`Reader::cell`] enforces.
pub(super) fn cell_is_valid(cell: &Cell) -> bool {
    cell.flags & !cell_flags::ALL == 0
        && !(cell.flags & cell_flags::WIDE != 0 && cell.flags & cell_flags::WIDE_CONT != 0)
        && cell.text.len() <= MAX_CELL_TEXT
        && !cell.text.chars().any(char::is_control)
        && !(cell.flags & cell_flags::WIDE_CONT != 0 && !cell.text.is_empty())
}
