//! UTF-16 to UTF-8 transcoding of console input, for the Windows client.
//!
//! A raw console is read with `ReadConsoleW`, because `ReadFile` under code
//! page 65001 converts per UTF-16 code unit and so turns a non-BMP character
//! (an emoji is a surrogate pair) into two U+FFFD (campaign W3a, ADR-0035).
//! The transcoding is plain arithmetic and lives here, free of `cfg`, so it
//! is tested on every CI leg; `qsh-testkit`'s console probe includes this
//! file by path next to `windows.rs`.
//!
//! Keys are never parsed: every unit below 0x80 (VT sequences, `0x03`)
//! becomes the same single byte, and a well-formed character becomes its
//! UTF-8 form. Only an unpaired surrogate, which is not text, becomes
//! U+FFFD.

use std::collections::VecDeque;
use std::io;

/// U+FFFD in UTF-8.
const REPLACEMENT: [u8; 3] = [0xEF, 0xBF, 0xBD];

/// Streaming UTF-16 decoder that carries a trailing high surrogate into the
/// next [`push`](Self::push), so a pair split across two reads is one
/// character.
#[derive(Debug, Default)]
pub struct Utf16ToUtf8 {
    pending_high: Option<u16>,
}

impl Utf16ToUtf8 {
    /// Append the UTF-8 for `units` to `out`. A final high surrogate is held
    /// back until the next call or [`finish`](Self::finish).
    pub fn push(&mut self, units: &[u16], out: &mut Vec<u8>) {
        for &unit in units {
            if let Some(high) = self.pending_high.take() {
                if (0xDC00..0xE000).contains(&unit) {
                    let c =
                        0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
                    push_char(char::from_u32(c).unwrap_or('\u{FFFD}'), out);
                    continue;
                }
                out.extend_from_slice(&REPLACEMENT);
            }
            match unit {
                0xD800..=0xDBFF => self.pending_high = Some(unit),
                0xDC00..=0xDFFF => out.extend_from_slice(&REPLACEMENT),
                _ => push_char(char::from_u32(u32::from(unit)).unwrap_or('\u{FFFD}'), out),
            }
        }
    }

    /// End of input: a held high surrogate is lone and becomes U+FFFD.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if self.pending_high.take().is_some() {
            out.extend_from_slice(&REPLACEMENT);
        }
    }
}

fn push_char(c: char, out: &mut Vec<u8>) {
    let mut utf8 = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
}

/// Byte-oriented reader over a UTF-16 source: decodes what `read_units`
/// returns and hands the bytes out in caller-sized pieces, queueing what does
/// not fit (one code unit can be three bytes).
#[derive(Debug, Default)]
pub struct Utf16Reader {
    decoder: Utf16ToUtf8,
    queued: VecDeque<u8>,
    ended: bool,
}

impl Utf16Reader {
    /// Fill `buf` with at least one byte, or return 0 at end of input.
    /// `read_units` reads UTF-16 units into its slice and returns how many
    /// (0 is end of input); it is called again when a read produced only a
    /// held high surrogate.
    pub fn read(
        &mut self,
        buf: &mut [u8],
        mut read_units: impl FnMut(&mut [u16]) -> io::Result<usize>,
    ) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut units = [0u16; 512];
        let mut decoded = Vec::new();
        while self.queued.is_empty() && !self.ended {
            let n = read_units(&mut units)?;
            decoded.clear();
            if n == 0 {
                self.ended = true;
                self.decoder.finish(&mut decoded);
            } else {
                self.decoder.push(&units[..n], &mut decoded);
            }
            self.queued.extend(decoded.iter().copied());
        }
        let n = buf.len().min(self.queued.len());
        for (slot, byte) in buf.iter_mut().zip(self.queued.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn decode(chunks: &[&[u16]]) -> Vec<u8> {
        let mut d = Utf16ToUtf8::default();
        let mut out = Vec::new();
        for c in chunks {
            d.push(c, &mut out);
        }
        d.finish(&mut out);
        out
    }

    #[test]
    fn pair_inside_one_read_is_one_character() {
        assert_eq!(decode(&[&utf16("a😀b")]), "a😀b".as_bytes());
        assert_eq!(decode(&[&utf16("😀")]), [0xF0, 0x9F, 0x98, 0x80]);
    }

    #[test]
    fn pair_split_across_reads_is_one_character() {
        let u = utf16("😀");
        assert_eq!(decode(&[&u[..1], &u[1..]]), [0xF0, 0x9F, 0x98, 0x80]);
        let mut d = Utf16ToUtf8::default();
        let mut out = Vec::new();
        d.push(&u[..1], &mut out);
        assert!(out.is_empty(), "the high surrogate is held back");
    }

    #[test]
    fn lone_high_at_end_of_input_is_replaced() {
        assert_eq!(decode(&[&[0xD83D]]), REPLACEMENT);
    }

    #[test]
    fn lone_high_before_other_text_is_replaced_once() {
        assert_eq!(decode(&[&[0xD83D, 0x61]]), [0xEF, 0xBF, 0xBD, b'a']);
        assert_eq!(decode(&[&[0xD83D], &[0xD83D, 0xDE00]]), {
            let mut v = REPLACEMENT.to_vec();
            v.extend_from_slice("😀".as_bytes());
            v
        });
    }

    #[test]
    fn lone_low_is_replaced() {
        assert_eq!(decode(&[&[0xDE00, 0x61]]), [0xEF, 0xBF, 0xBD, b'a']);
    }

    #[test]
    fn ascii_and_vt_bytes_pass_unchanged() {
        let text = "hi\x03\r\x04\x1b[A\x1b[?1;2c\x7f";
        assert_eq!(decode(&[&utf16(text)]), text.as_bytes());
    }

    #[test]
    fn korean_is_intact() {
        assert_eq!(decode(&[&utf16("한글 테스트")]), "한글 테스트".as_bytes());
    }

    #[test]
    fn reader_hands_out_small_buffers_and_carries_a_split_pair() {
        let u = utf16("한😀");
        let mut chunks = vec![u[..2].to_vec(), u[2..].to_vec()].into_iter();
        let mut reader = Utf16Reader::default();
        let mut all = Vec::new();
        let mut buf = [0u8; 2];
        loop {
            let n = reader
                .read(&mut buf, |dst| {
                    let c = chunks.next().unwrap_or_default();
                    dst[..c.len()].copy_from_slice(&c);
                    Ok(c.len())
                })
                .unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(all, "한😀".as_bytes());
    }

    #[test]
    fn reader_reads_again_when_only_a_high_surrogate_arrived() {
        let mut chunks = vec![vec![0xD83Du16], vec![0xDE00]].into_iter();
        let mut reader = Utf16Reader::default();
        let mut buf = [0u8; 16];
        let n = reader
            .read(&mut buf, |dst| {
                let c = chunks.next().unwrap_or_default();
                dst[..c.len()].copy_from_slice(&c);
                Ok(c.len())
            })
            .unwrap();
        assert_eq!(&buf[..n], [0xF0, 0x9F, 0x98, 0x80]);
    }

    #[test]
    fn reader_propagates_errors_and_end_of_input() {
        let mut reader = Utf16Reader::default();
        let mut buf = [0u8; 4];
        let err = reader.read(&mut buf, |_| Err(io::Error::other("boom")));
        assert!(err.is_err());
        assert_eq!(reader.read(&mut buf, |_| Ok(0)).unwrap(), 0);
    }
}
