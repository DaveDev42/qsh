//! Keeps terminal *queries* in replayed output away from the local terminal.
//!
//! An attach replays the session's retained output before the live stream
//! (`docs/design/protocol.md` §8). That history can contain requests a
//! full-screen program once sent to its terminal (cursor position report,
//! device attributes, mode and colour queries, ...). Written to the local
//! terminal again, each one is answered a second time, and the answers
//! arrive on stdin where the input pump forwards them to the remote PTY as
//! if the user had typed them. [`ReplayFilter`] removes those requests from
//! the replayed bytes only; live output is never touched, so a running
//! program's real queries are still answered. Every other control sequence
//! (SGR, cursor movement, mode sets, titles, colour *settings*) passes
//! through unchanged. The wire, the ring and the machine surfaces stay
//! byte-exact: this runs in the interactive renderer only.
//!
//! The replay boundary is the session's output end when the host authorized
//! the attach ([`qsh_core::SessionAttachStream::replay_end`]); a chunk's
//! `sequence` is the offset of its end, so the chunk's start offset is
//! `sequence - len` and the replay part of a chunk is the prefix below the
//! boundary.
//!
//! Removed (all of them are requests, never settings):
//!
//! - `CSI Ps n` / `CSI ? Ps n`: device status and cursor position reports
//! - `CSI c`, `CSI Ps c`, `CSI > Ps c`, `CSI = Ps c`, `ESC Z`: device attributes
//! - `CSI > q` / `CSI > 0 q`: XTVERSION
//! - `CSI Ps $ p` / `CSI ? Ps $ p`: DECRQM (so `CSI 2 $ p` is a query too)
//! - `CSI ? u`: kitty keyboard flags query
//! - `CSI Ps t` with Ps 11, 13..=16, 18..=21: window state/size reports
//! - `OSC 4|5|10..19 ; ... ? ...` and `OSC 52 ; ... ; ?`: colour and
//!   clipboard queries (a set such as `OSC 10;rgb:..` is kept), ended by BEL
//!   or ST
//! - `DCS $ q ... ST` (DECRQSS) and `DCS + q ... ST` (XTGETTCAP)
//!
//! A sequence still incomplete where the replay ends is released as it is:
//! the replay holds no complete query there, and holding it back would stall
//! live output. A query cut at a chunk boundary inside the replay is
//! completed by the next chunk, like `vt_filter::ModeFilter` does.

/// The longest sequence held back across a chunk boundary. Queries are
/// short; a longer sequence (a long title, a sixel image) is not one and is
/// released unchanged.
const MAX_HELD: usize = 256;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

/// Replay-only query remover; see the module docs.
pub(super) struct ReplayFilter {
    /// Output offset where live output starts.
    end: u64,
    /// A sequence cut at a chunk boundary inside the replay.
    held: Vec<u8>,
}

impl ReplayFilter {
    /// A filter for an attach whose replay ends at output offset `end`.
    /// `0` means nothing is replayed (or the host does not say), so nothing
    /// is filtered.
    pub(super) fn new(end: u64) -> Self {
        Self {
            end,
            held: Vec::new(),
        }
    }

    /// Filter one output chunk whose end offset is `sequence`.
    pub(super) fn feed(&mut self, chunk: &[u8], sequence: u64) -> Vec<u8> {
        let start = sequence.saturating_sub(chunk.len() as u64);
        if start >= self.end {
            // Entirely live (or no replay at all).
            return chunk.to_vec();
        }
        let replay_len =
            usize::try_from(self.end - start).map_or(chunk.len(), |n| n.min(chunk.len()));
        let (replay, live) = chunk.split_at(replay_len);
        let mut out = Vec::with_capacity(chunk.len() + self.held.len());
        for &byte in replay {
            self.push(byte, &mut out);
        }
        if sequence >= self.end {
            // The replay is over: whatever is still pending is not a complete
            // query, and live bytes must not wait behind it.
            out.append(&mut self.held);
        }
        out.extend_from_slice(live);
        out
    }

    /// Release anything still pending (the output ended).
    pub(super) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }

    fn in_string(&self) -> bool {
        matches!(self.held.get(1), Some(b']' | b'P'))
    }

    fn push(&mut self, byte: u8, out: &mut Vec<u8>) {
        if self.held.is_empty() {
            if byte == ESC {
                self.held.push(byte);
            } else {
                out.push(byte);
            }
            return;
        }
        // A new ESC cannot continue a CSI; inside OSC/DCS it may start ST.
        if byte == ESC && !self.in_string() {
            out.append(&mut self.held);
            self.held.push(byte);
            return;
        }
        self.held.push(byte);
        match classify(&self.held) {
            Class::Open if self.held.len() < MAX_HELD => {}
            Class::Query => self.held.clear(),
            Class::Other | Class::Open => {
                let n = self.held.len();
                if self.in_string() && n > 2 && self.held[n - 2] == ESC && byte != b'\\' {
                    // `ESC x` inside a string that is not ST: the ESC starts
                    // something new, and so is `x`'s to decide.
                    self.held.truncate(n - 2);
                    out.append(&mut self.held);
                    self.held.push(ESC);
                    self.push(byte, out);
                } else {
                    out.append(&mut self.held);
                }
            }
        }
    }
}

enum Class {
    /// Could still become a query.
    Open,
    /// A complete query: drop it.
    Query,
    /// Not a query (complete or not).
    Other,
}

fn classify(held: &[u8]) -> Class {
    match held {
        [] | [ESC] => Class::Open,
        [ESC, b'Z'] => Class::Query,
        [ESC, b'[', rest @ ..] => classify_csi(rest),
        [ESC, b']', rest @ ..] => classify_osc(rest),
        [ESC, b'P', rest @ ..] => classify_dcs(rest),
        _ => Class::Other,
    }
}

/// `rest` is everything after `ESC [`.
fn classify_csi(rest: &[u8]) -> Class {
    let mut i = 0;
    let prefix = match rest.first() {
        Some(&p @ (b'?' | b'>' | b'=' | b'<')) => {
            i = 1;
            Some(p)
        }
        _ => None,
    };
    let params_start = i;
    while i < rest.len() && matches!(rest[i], b'0'..=b'9' | b';' | b':') {
        i += 1;
    }
    let params = &rest[params_start..i];
    let inter_start = i;
    while i < rest.len() && (0x20..=0x2f).contains(&rest[i]) {
        i += 1;
    }
    let inters = &rest[inter_start..i];
    let Some(&fin) = rest.get(i) else {
        return Class::Open;
    };
    if i + 1 != rest.len() || !(0x40..=0x7e).contains(&fin) {
        return Class::Other;
    }
    let first = params
        .split(|b| *b == b';')
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .and_then(|p| p.parse::<u32>().ok());
    let plain = !params.contains(&b':');
    let query = plain
        && match (prefix, inters, fin) {
            (None | Some(b'?'), [], b'n') => true,
            (None | Some(b'>' | b'='), [], b'c') => true,
            (Some(b'>'), [], b'q') => params.is_empty() || params == b"0",
            (None | Some(b'?'), [b'$'], b'p') => true,
            (Some(b'?'), [], b'u') => params.is_empty(),
            (None, [], b't') => matches!(first, Some(11 | 13..=16 | 18..=21)),
            _ => false,
        };
    if query { Class::Query } else { Class::Other }
}

/// `rest` is everything after `ESC ]`.
fn classify_osc(rest: &[u8]) -> Class {
    let body = if let Some(body) = rest.strip_suffix(&[BEL]) {
        body
    } else if let Some(body) = rest.strip_suffix(&[ESC, b'\\']) {
        body
    } else {
        // Not terminated yet; a stray ESC not followed by `\` is handled by
        // the caller once the byte after it arrives.
        return match rest.iter().position(|b| *b == ESC) {
            Some(p) if p + 2 <= rest.len() && rest[p + 1] != b'\\' => Class::Other,
            _ => Class::Open,
        };
    };
    let mut fields = body.split(|b| *b == b';');
    let ps = fields
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .and_then(|p| p.parse::<u32>().ok());
    let rest_fields: Vec<&[u8]> = fields.collect();
    let query = match ps {
        Some(4 | 5 | 10..=19) => rest_fields.contains(&&b"?"[..]),
        Some(52) => rest_fields.last() == Some(&&b"?"[..]),
        _ => false,
    };
    if query { Class::Query } else { Class::Other }
}

/// `rest` is everything after `ESC P`.
fn classify_dcs(rest: &[u8]) -> Class {
    match rest {
        [] | [b'$' | b'+'] => Class::Open,
        [b'$' | b'+', b'q', tail @ ..] => {
            if tail.ends_with(&[ESC, b'\\']) {
                Class::Query
            } else {
                match tail.iter().position(|b| *b == ESC) {
                    Some(p) if p + 2 <= tail.len() && tail[p + 1] != b'\\' => Class::Other,
                    _ => Class::Open,
                }
            }
        }
        _ => Class::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `chunks` in order as one stream whose replay ends at `end`.
    fn run(end: u64, chunks: &[&[u8]]) -> Vec<u8> {
        let mut filter = ReplayFilter::new(end);
        let mut seq = 0u64;
        let mut out = Vec::new();
        for chunk in chunks {
            seq += chunk.len() as u64;
            out.extend(filter.feed(chunk, seq));
        }
        out.extend(filter.finish());
        out
    }

    /// Everything is replay.
    fn replay(input: &[u8]) -> Vec<u8> {
        run(u64::MAX, &[input])
    }

    #[test]
    fn every_query_form_is_stripped() {
        let queries: &[&[u8]] = &[
            b"\x1b[6n",
            b"\x1b[?6n",
            b"\x1b[5n",
            b"\x1b[?15n",
            b"\x1b[c",
            b"\x1b[0c",
            b"\x1b[>c",
            b"\x1b[>0c",
            b"\x1b[=c",
            b"\x1b[?2004$p",
            b"\x1b[4$p",
            b"\x1b[>q",
            b"\x1b[>0q",
            b"\x1b[?u",
            b"\x1b[18t",
            b"\x1b[14t",
            b"\x1bZ",
            b"\x1b]10;?\x1b\\",
            b"\x1b]11;?\x07",
            b"\x1b]4;1;?\x1b\\",
            b"\x1b]4;1;?;2;?\x07",
            b"\x1b]52;c;?\x07",
            b"\x1bP$qm\x1b\\",
            b"\x1bP+q544e\x1b\\",
        ];
        for query in queries {
            let input = [b"a".as_slice(), query, b"b"].concat();
            assert_eq!(
                replay(&input),
                b"ab",
                "{:?}",
                String::from_utf8_lossy(query)
            );
        }
    }

    #[test]
    fn look_alikes_and_other_sequences_are_kept() {
        let kept: &[&[u8]] = &[
            b"\x1b[6;1H",
            b"\x1b[?25h",
            b"\x1b[31;1mred\x1b[0m",
            b"\x1b]0;title\x07",
            b"\x1b]10;rgb:cccc/cccc/cccc\x1b\\",
            b"\x1b]4;1;rgb:ff/00/00\x07",
            b"\x1b]52;c;aGk=\x07",
            b"\x1b[?1;2c",
            b"\x1b[>4;2m",
            b"\x1b[>4;1q",
            b"\x1b[=5u",
            b"\x1b[>1u",
            b"\x1b[?1u",
            b"\x1b[!p",
            b"\x1b[8;24;80t",
            b"\x1b[22;0t",
            b"\x1b[>0n",
            b"\x1b7\x1b8",
            b"\x1bPq#0;2;0;0;0\x1b\\",
            "한글\x1b[2J".as_bytes(),
        ];
        for input in kept {
            assert_eq!(
                replay(input),
                *input,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn a_query_cut_at_chunk_boundaries_is_still_removed() {
        for query in [
            b"\x1b[6n".as_slice(),
            b"\x1b[?2004$p",
            b"\x1b]11;?\x07",
            b"\x1b]10;?\x1b\\",
            b"\x1bP$qm\x1b\\",
        ] {
            for cut in 1..query.len() {
                let (a, b) = query.split_at(cut);
                let out = run(u64::MAX, &[b"x", a, b, b"y"]);
                assert_eq!(out, b"xy", "{:?} cut {cut}", String::from_utf8_lossy(query));
            }
        }
    }

    #[test]
    fn a_cut_look_alike_is_released_intact() {
        assert_eq!(replay(b"\x1b[6;"), b"\x1b[6;");
        assert_eq!(run(u64::MAX, &[b"\x1b[6", b";1H!"]), b"\x1b[6;1H!");
        assert_eq!(run(u64::MAX, &[b"\x1b]0;t", b"\x07z"]), b"\x1b]0;t\x07z");
    }

    #[test]
    fn an_escape_inside_a_string_that_is_not_st_restarts() {
        // `OSC 10;? ESC [ 6 n`: the unterminated OSC is released, the CPR dropped.
        assert_eq!(replay(b"\x1b]10;?\x1b[6nz"), b"\x1b]10;?z");
        assert_eq!(replay(b"\x1b[3\x1b[6nz"), b"\x1b[3z");
    }

    #[test]
    fn an_overlong_sequence_is_not_held_forever() {
        let mut long = b"\x1b]0;".to_vec();
        long.extend(std::iter::repeat_n(b'a', 1000));
        let out = run(u64::MAX, &[&long, b"x"]);
        assert_eq!(out, [long.as_slice(), b"x"].concat());
    }

    #[test]
    fn live_output_is_untouched() {
        // Replay is the first 4 bytes; the rest is live and keeps its query.
        let aligned = run(4, &[b"a\x1b[c", b"b\x1b[6n"]);
        assert_eq!(aligned, b"ab\x1b[6n");
        assert_eq!(run(0, &[b"\x1b[6n"]), b"\x1b[6n");
    }

    #[test]
    fn a_chunk_straddling_the_boundary_filters_only_its_replay_part() {
        // Replay ends after "x\x1b[6n" (5 bytes); the live tail has its own query.
        let out = run(5, &[b"x\x1b[6ny\x1b[6n"]);
        assert_eq!(out, b"xy\x1b[6n");
    }

    #[test]
    fn a_query_straddling_the_replay_end_is_released_as_a_partial() {
        // The replay ends inside `ESC [ 6 n`; the partial is released rather
        // than held behind live output, and the live remainder passes.
        let out = run(3, &[b"x\x1b[", b"6n"]);
        assert_eq!(out, b"x\x1b[6n");
        // Same inside one chunk.
        assert_eq!(run(3, &[b"x\x1b[6n"]), b"x\x1b[6n");
    }

    #[test]
    fn a_partial_at_the_end_of_the_replay_is_not_held_for_live_output() {
        let mut filter = ReplayFilter::new(2);
        assert_eq!(filter.feed(b"a\x1b", 2), b"a\x1b");
        assert!(filter.finish().is_empty());
    }

    #[test]
    fn a_replay_spread_over_chunks_holds_a_partial_until_the_next_chunk() {
        let mut filter = ReplayFilter::new(100);
        assert_eq!(filter.feed(b"a\x1b[6", 4), b"a");
        assert_eq!(filter.feed(b"nb", 6), b"b");
    }

    #[test]
    fn a_replay_that_ends_mid_stream_flushes_the_partial_on_finish() {
        let mut filter = ReplayFilter::new(100);
        assert_eq!(filter.feed(b"a\x1b[", 3), b"a");
        assert_eq!(filter.finish(), b"\x1b[");
    }
}
