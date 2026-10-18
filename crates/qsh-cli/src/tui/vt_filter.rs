//! The output filter of a console that must keep its own input plain.
//!
//! A Windows host's pseudo-console starts its output with
//! `ESC [ ? 9001 h` (win32 input mode). When the client writes that to its
//! own console, the console starts answering `ReadFile` with
//! `ESC [ Vk ; Sc ; Uc ; Kd ; Cs ; Rc _` sequences instead of the bytes
//! typed, so the line-start escape machine never sees `~` and `d`, and the
//! remote receives sequences its own console did not ask this client for.
//! [`ModeFilter`] removes mode 9001 from the `CSI ? ... h` / `CSI ? ... l`
//! sequences of the session output and passes every other byte through.

/// The longest sequence held back across a chunk boundary. A longer one is
/// not a private-mode sequence worth parsing and goes through unchanged.
const MAX_HELD: usize = 32;

/// The private mode (win32 input mode) the filter removes.
const WIN32_INPUT_MODE: &[u8] = b"9001";

/// A stateful filter: a sequence cut at a chunk boundary is completed by the
/// next chunk.
#[derive(Default)]
pub(super) struct ModeFilter {
    held: Vec<u8>,
}

impl ModeFilter {
    /// Filter one chunk of session output.
    pub(super) fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(chunk.len() + self.held.len());
        for &byte in chunk {
            if self.held.is_empty() {
                if byte == 0x1b {
                    self.held.push(byte);
                } else {
                    out.push(byte);
                }
                continue;
            }
            if byte == 0x1b {
                // A new ESC cannot continue the held sequence: release what
                // was held and restart the hold at this byte.
                out.extend_from_slice(&self.held);
                self.held.clear();
                self.held.push(byte);
                continue;
            }
            self.held.push(byte);
            match classify(&self.held) {
                Prefix::Open if self.held.len() < MAX_HELD => {}
                Prefix::Complete => {
                    rewrite(&self.held, &mut out);
                    self.held.clear();
                }
                // Not a private-mode sequence, or too long to be one.
                Prefix::Open | Prefix::Other => {
                    out.extend_from_slice(&self.held);
                    self.held.clear();
                }
            }
        }
        out
    }

    /// Release whatever is still held. The session output ended, so no
    /// later chunk can complete the sequence.
    pub(super) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

enum Prefix {
    /// Could still become `ESC [ ? params final`.
    Open,
    /// A full private-mode sequence.
    Complete,
    /// Something else.
    Other,
}

fn classify(held: &[u8]) -> Prefix {
    match held {
        [0x1b] | [0x1b, b'['] => Prefix::Open,
        [0x1b, b'[', b'?'] => Prefix::Open,
        [0x1b, b'[', b'?', rest @ ..] => match rest.last() {
            Some(b'0'..=b'9' | b';') if rest.iter().all(|b| b.is_ascii_digit() || *b == b';') => {
                Prefix::Open
            }
            Some(b'h' | b'l')
                if rest[..rest.len() - 1]
                    .iter()
                    .all(|b| b.is_ascii_digit() || *b == b';') =>
            {
                Prefix::Complete
            }
            _ => Prefix::Other,
        },
        _ => Prefix::Other,
    }
}

/// Write a complete `ESC [ ? params (h|l)` sequence without mode 9001.
fn rewrite(seq: &[u8], out: &mut Vec<u8>) {
    let final_byte = seq[seq.len() - 1];
    let params = &seq[3..seq.len() - 1];
    let kept: Vec<&[u8]> = params
        .split(|b| *b == b';')
        .filter(|param| *param != WIN32_INPUT_MODE)
        .collect();
    if kept.len() == params.split(|b| *b == b';').count() {
        out.extend_from_slice(seq);
        return;
    }
    if kept.is_empty() {
        return;
    }
    out.extend_from_slice(b"\x1b[?");
    out.extend_from_slice(&kept.join(&b';'));
    out.push(final_byte);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&[u8]]) -> Vec<u8> {
        let mut filter = ModeFilter::default();
        chunks.iter().flat_map(|c| filter.feed(c)).collect()
    }

    #[test]
    fn mode_9001_is_dropped_alone() {
        assert_eq!(run(&[b"a\x1b[?9001hb\x1b[?9001lc"]), b"abc");
    }

    #[test]
    fn mode_9001_is_dropped_from_a_list() {
        assert_eq!(run(&[b"\x1b[?25;9001;1004h"]), b"\x1b[?25;1004h");
        assert_eq!(run(&[b"\x1b[?9001;25l"]), b"\x1b[?25l");
    }

    #[test]
    fn other_sequences_pass_through() {
        let input: &[u8] = b"\x1b[?25h\x1b[31mred\x1b[0m\x1b[?1004l\x1b]0;t\x07\x1b[";
        // The trailing partial `ESC [` stays held; everything before it is intact.
        assert_eq!(run(&[input]), &input[..input.len() - 2]);
    }

    #[test]
    fn a_sequence_cut_at_a_chunk_boundary_is_still_removed() {
        assert_eq!(run(&[b"x\x1b", b"[?90", b"01", b"hy"]), b"xy");
        assert_eq!(run(&[b"x\x1b[", b"?9001h"]), b"x");
    }

    #[test]
    fn a_cut_sequence_that_is_not_ours_is_released_intact() {
        assert_eq!(run(&[b"\x1b[?25", b"h!"]), b"\x1b[?25h!");
        assert_eq!(run(&[b"\x1b", b"[2J"]), b"\x1b[2J");
    }

    #[test]
    fn a_long_digit_run_is_not_held_forever() {
        let mut long = b"\x1b[?".to_vec();
        long.extend(std::iter::repeat_n(b'1', 100));
        let out = run(&[&long, b"x"]);
        assert_eq!(out, [long.as_slice(), b"x"].concat());
    }

    #[test]
    fn finish_releases_a_trailing_partial_sequence() {
        let mut filter = ModeFilter::default();
        assert_eq!(filter.feed(b"ab\x1b[?"), b"ab");
        assert_eq!(filter.finish(), b"\x1b[?");
        assert!(filter.finish().is_empty());
    }

    #[test]
    fn a_second_escape_restarts_the_hold() {
        assert_eq!(run(&[b"\x1b\x1b[?9001hz"]), b"\x1bz");
        assert_eq!(run(&[b"\x1b[?25\x1b[?9001hz"]), b"\x1b[?25z");
        assert_eq!(run(&[b"\x1b", b"\x1b[?9001h"]), b"\x1b");
    }

    #[test]
    fn utf8_text_is_untouched() {
        let text = "한글 \u{1b}[?9001h안녕".as_bytes();
        assert_eq!(run(&[text]), "한글 안녕".as_bytes());
    }
}
