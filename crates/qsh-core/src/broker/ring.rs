//! Replay ring: the per-session output history behind the [`ReplayStore`]
//! trait (`docs/design/architecture.md` §3, ADR-0004).
//!
//! `sequence` is the **cumulative output byte offset** of the session
//! (`docs/CLI.md` §2.3, `docs/design/protocol.md` §8): the offset of a chunk's
//! last byte + 1. Offsets are assigned **only here**, at [`ReplayStore::push`]
//! — nothing downstream (stream pump, renderer) recomputes them.
//!
//! - Storage is a memory-only chunk ring with a byte budget (default 8 MiB,
//!   `[serve].replay_bytes`). Eviction is whole-chunk, oldest first; gap
//!   computation and replay truncation are byte-exact, so `--after N` always
//!   resumes at exactly `N` regardless of how the producer chunked its
//!   writes. Small pushes are **coalesced into the tail chunk** (up to the
//!   chunk size, at most [`RING_CHUNK_MAX`]), so per-entry overhead is bounded by
//!   `budget / chunk_max` regardless of how the producer chunks —
//!   a PTY echoing one byte at a time cannot blow the memory bound or make
//!   reads O(bytes).
//! - Overflow is never hidden: a cursor that points before
//!   [`ReplayStore::available_from`] gets a [`ReplayEvent::Gap`] first, then
//!   the data from `available_from` on (protocol.md §10 step 4).
//! - Control events (`session.exit` / `session.writer_changed` /
//!   `session.closed`) are **zero-length entries** in the same ring
//!   ([`ReplayStore::push_control`]). They sit at the offset current when
//!   they were appended, do not advance the offset, and are returned by
//!   [`ReplayStore::read`] in total order with the output — a caught-up
//!   consumer at offset `S` sees a control appended at `S` on its next pull
//!   (CLI.md §6.4 "전달 경로와 순서"). Eviction never drops a control that
//!   sits at [`ReplayStore::available_from`] while the output starting there
//!   is retained — the oldest *output* chunk goes first, and controls are
//!   dropped only once they are strictly behind `available_from` (a cursor
//!   there gets a [`ReplayEvent::Gap`] anyway). The one forced case — a ring
//!   holding nothing but control entries over budget — is signalled by a
//!   `Gap` with `requested_after == available_from` (ADR-0004: overflow is
//!   never hidden).
//!
//! ## Cursors
//!
//! Because control entries have no width, an offset alone cannot say
//! whether a control at exactly that offset was already delivered. A
//! [`Cursor`] therefore carries the offset plus the id of the last control
//! entry the consumer received (`ctl_after`; control ids are monotonic per
//! ring). Stateful consumers (the SESSION_DATA pump, `--follow` loops) feed
//! back the [`ReadOut::next`] cursor and see every control exactly once.
//! Stateless offset-only callers ([`Cursor::from_offset`] — a single
//! `session read --after N`, MCP long-poll) get *at-least-once* delivery of
//! controls positioned exactly at `N`; output bytes are never duplicated in
//! either case.

use std::collections::VecDeque;
use std::fmt;

use bytes::Bytes;

/// Largest single chunk kept in the ring. Bigger pushes are split and
/// smaller ones coalesced up to this size, which keeps whole-chunk eviction
/// granular, bounds the read-side copy, and bounds the entry count.
pub const RING_CHUNK_MAX: usize = 16 * 1024;

/// Chunks are also capped at `budget / RING_CHUNK_DIVISOR` so small budgets
/// keep eviction granular (a chunk is never more than 1/16 of the ring).
pub const RING_CHUNK_DIVISOR: usize = 16;

/// Budget charged for one control entry (they carry no bytes but must not
/// let a stream of pure control events grow the ring without bound).
pub const CONTROL_ENTRY_COST: usize = 64;

/// Why a session was removed from the broker (`session.closed.reason`,
/// CLI.md §6.4: decided by *who* removed the session, not its prior state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// Explicit `session.close` (running or already exited) or serve drain.
    Closed,
    /// Child exited on its own and the TTL reaper cleaned up the `exited`
    /// session with no caller involved.
    Exit,
    /// A running session sat unattached past the resume TTL; the reaper
    /// terminated its process group.
    TtlExpired,
}

impl CloseReason {
    /// The `reason` string of the `session.closed` event.
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::Closed => "closed",
            CloseReason::Exit => "exit",
            CloseReason::TtlExpired => "ttl_expired",
        }
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A zero-length control entry (architecture.md §3 "제어 event의 전달").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    /// The child exited (`session.exit`). `exit_code` is `None` when the
    /// process was terminated by `signal`.
    Exit {
        /// Process exit code, if it exited normally.
        exit_code: Option<i32>,
        /// Terminating signal in `SIGTERM` canonical form, if signaled.
        signal: Option<String>,
    },
    /// The writer lease changed hands (`session.writer_changed`); `None`
    /// means the lease was released and nobody holds it.
    WriterChanged {
        /// Principal string of the new holder.
        writer: Option<String>,
    },
    /// The session was removed from the broker (`session.closed`); always
    /// the last entry.
    Closed {
        /// Who removed it.
        reason: CloseReason,
    },
}

/// One item returned by [`ReplayStore::read`], in stream order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayEvent {
    /// Output bytes. `sequence` is the cumulative offset **after** this
    /// chunk (offset of its last byte + 1).
    Output {
        /// Cumulative byte offset after `data`.
        sequence: u64,
        /// The bytes; never empty.
        data: Bytes,
    },
    /// The requested offset is no longer retained; the stream resumes at
    /// `available_from`.
    Gap {
        /// The `after` the caller asked for.
        requested_after: u64,
        /// Oldest offset still in the ring — where the events that follow
        /// this one start.
        available_from: u64,
    },
    /// A control entry.
    Control {
        /// Cumulative output offset at the moment the entry was appended.
        sequence: u64,
        /// Monotonic per-ring id (feeds [`Cursor::ctl_after`]).
        ctl_id: u64,
        /// The event.
        event: ControlEvent,
    },
}

/// Read position of one consumer on the ring. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Cursor {
    /// Cumulative output offset already consumed (the `--after N` value):
    /// the next byte wanted is at offset `after`.
    pub after: u64,
    /// Id of the last control entry received; `0` = none yet, so a fresh
    /// cursor also gets controls positioned exactly at `after`.
    pub ctl_after: u64,
}

impl Cursor {
    /// A cursor from an offset alone (stateless callers).
    pub fn from_offset(after: u64) -> Self {
        Self {
            after,
            ctl_after: 0,
        }
    }
}

impl From<u64> for Cursor {
    fn from(after: u64) -> Self {
        Cursor::from_offset(after)
    }
}

/// Result of one [`ReplayStore::read`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOut {
    /// Events in stream order. Empty ⇔ nothing new for the cursor.
    pub events: Vec<ReplayEvent>,
    /// Cursor to pass to the next read to continue without gaps or
    /// duplicates.
    pub next: Cursor,
}

impl ReadOut {
    /// Whether this read produced a [`ReplayEvent::Gap`].
    pub fn has_gap(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, ReplayEvent::Gap { .. }))
    }
}

/// A read that cannot be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// `after` claims more bytes than the session has ever produced. This
    /// is a caller bug (or a cursor from another session), never something
    /// the ring silently clamps.
    #[error("cursor offset {after} is beyond the end of the stream ({end})")]
    CursorBeyondEnd {
        /// The offending offset.
        after: u64,
        /// Current end of the stream.
        end: u64,
    },
}

/// The store a session's output history lives in. `ReplayRing` is the only
/// implementation in P0; ADR-0004 keeps the seam so an encrypted disk spool
/// could be dropped in later without touching the actor.
pub trait ReplayStore: Send + fmt::Debug {
    /// Append output. Returns the new end offset (= the `sequence` of the
    /// last chunk of `data`). Empty data is a no-op returning [`end`].
    ///
    /// [`end`]: ReplayStore::end
    fn push(&mut self, data: &[u8]) -> u64;

    /// Append a zero-length control entry at the current end offset.
    /// Returns `(sequence, ctl_id)`.
    fn push_control(&mut self, event: ControlEvent) -> (u64, u64);

    /// Cumulative bytes ever pushed — the offset the next byte will get.
    fn end(&self) -> u64;

    /// Oldest output offset still retained (`== end()` when nothing is).
    fn available_from(&self) -> u64;

    /// Read from `cursor`, returning at most `max_bytes` of output plus any
    /// control entries due, in stream order.
    fn read(&self, cursor: Cursor, max_bytes: usize) -> Result<ReadOut, ReadError>;

    /// Configured byte budget.
    fn budget(&self) -> usize;

    /// Bytes currently charged against the budget (output bytes plus
    /// [`CONTROL_ENTRY_COST`] per control entry).
    fn retained(&self) -> usize;

    /// Number of entries (output chunks + control entries) retained — the
    /// per-entry overhead is bounded by `budget / chunk_max` plus controls.
    fn entry_count(&self) -> usize;

    /// Effective chunk size (pushes are split to it and coalesced up to it).
    fn chunk_max(&self) -> usize;
}

#[derive(Debug, Clone)]
enum Entry {
    Output {
        start: u64,
        /// Owned so the tail chunk can grow (coalescing); reads copy the
        /// requested slice into a `Bytes`.
        data: Vec<u8>,
    },
    Control {
        seq: u64,
        id: u64,
        event: ControlEvent,
    },
}

impl Entry {
    fn cost(&self) -> usize {
        match self {
            Entry::Output { data, .. } => data.len(),
            Entry::Control { .. } => CONTROL_ENTRY_COST,
        }
    }
}

/// Memory-only chunk ring (ADR-0004). See the module docs.
#[derive(Debug)]
pub struct ReplayRing {
    budget: usize,
    /// Chunk size: `clamp(budget / RING_CHUNK_DIVISOR, 1, RING_CHUNK_MAX)`.
    /// Pushes are split to it and coalesced up to it, so a single piece
    /// always fits the budget and the entry count is bounded by
    /// `budget / piece_max` (+ controls, each charged
    /// [`CONTROL_ENTRY_COST`]).
    piece_max: usize,
    entries: VecDeque<Entry>,
    retained: usize,
    end: u64,
    next_ctl_id: u64,
    /// The newest control entry force-evicted while still positioned at
    /// `available_from` (`(seq, id)`), if any. See [`ReplayRing::evict`].
    lost_ctl: Option<(u64, u64)>,
}

impl ReplayRing {
    /// A ring with the given byte budget (`budget >= 1`; `0` is treated
    /// as `1`).
    pub fn new(budget: usize) -> Self {
        let budget = budget.max(1);
        Self {
            budget,
            piece_max: (budget / RING_CHUNK_DIVISOR).clamp(1, RING_CHUNK_MAX),
            entries: VecDeque::new(),
            retained: 0,
            end: 0,
            next_ctl_id: 1,
            lost_ctl: None,
        }
    }

    /// Trim to budget. The oldest **output** chunk goes first; control
    /// entries are only dropped once they sit strictly behind
    /// `available_from` (a cursor there gets a `Gap` for the bytes anyway,
    /// so nothing is lost silently). Only when the ring holds nothing but
    /// control entries and is still over budget is a control force-evicted,
    /// and that is recorded in `lost_ctl` so [`ReplayStore::read`] can emit
    /// a `Gap` for the consumers that were owed it.
    ///
    /// The entry that was just appended is never evicted: with pieces
    /// capped at `piece_max <= budget` this only matters for budgets below
    /// `CONTROL_ENTRY_COST`, where the invariant becomes
    /// `retained <= budget + cost(last)`.
    fn evict(&mut self) {
        while self.retained > self.budget && self.entries.len() > 1 {
            let oldest_output = self
                .entries
                .iter()
                .position(|e| matches!(e, Entry::Output { .. }));
            match oldest_output {
                Some(i) if i + 1 < self.entries.len() => {
                    if let Some(gone) = self.entries.remove(i) {
                        self.retained -= gone.cost();
                    }
                }
                _ => {
                    // No evictable output: everything in front of the newest
                    // entry is a control positioned at `available_from`.
                    if let Some(Entry::Control { seq, id, .. }) = self.entries.pop_front() {
                        self.retained -= CONTROL_ENTRY_COST;
                        self.lost_ctl = Some((seq, id));
                    }
                }
            }
            // Controls now strictly behind the oldest retained output are
            // covered by the gap a cursor there receives; drop them.
            let available_from = self.available_from();
            while let Some(Entry::Control { seq, .. }) = self.entries.front() {
                if *seq < available_from {
                    self.entries.pop_front();
                    self.retained -= CONTROL_ENTRY_COST;
                } else {
                    break;
                }
            }
        }
    }

    /// Append `piece` to the tail output chunk if it is an output chunk with
    /// room, else start a new chunk. Returns how many bytes were appended.
    fn append_output(&mut self, piece: &[u8]) -> usize {
        let piece_max = self.piece_max;
        if let Some(Entry::Output { data, .. }) = self.entries.back_mut()
            && data.len() < piece_max
        {
            let take = piece.len().min(piece_max - data.len());
            data.extend_from_slice(&piece[..take]);
            return take;
        }
        let take = piece.len().min(piece_max);
        let start = self.end;
        self.entries.push_back(Entry::Output {
            start,
            data: piece[..take].to_vec(),
        });
        take
    }
}

impl ReplayStore for ReplayRing {
    fn push(&mut self, data: &[u8]) -> u64 {
        let mut rest = data;
        while !rest.is_empty() {
            let n = self.append_output(rest);
            self.retained += n;
            self.end += n as u64;
            rest = &rest[n..];
            self.evict();
        }
        self.end
    }

    fn push_control(&mut self, event: ControlEvent) -> (u64, u64) {
        let id = self.next_ctl_id;
        self.next_ctl_id += 1;
        let seq = self.end;
        self.entries.push_back(Entry::Control { seq, id, event });
        self.retained += CONTROL_ENTRY_COST;
        self.evict();
        (seq, id)
    }

    fn end(&self) -> u64 {
        self.end
    }

    fn available_from(&self) -> u64 {
        self.entries
            .iter()
            .find_map(|e| match e {
                Entry::Output { start, .. } => Some(*start),
                Entry::Control { .. } => None,
            })
            .unwrap_or(self.end)
    }

    fn read(&self, cursor: Cursor, max_bytes: usize) -> Result<ReadOut, ReadError> {
        if cursor.after > self.end {
            return Err(ReadError::CursorBeyondEnd {
                after: cursor.after,
                end: self.end,
            });
        }
        let mut events = Vec::new();
        let available_from = self.available_from();
        // `from` walks forward as bytes are emitted; `start_from` is where
        // this read effectively began (after a gap resync, if any).
        let mut from = cursor.after;
        if from < available_from {
            events.push(ReplayEvent::Gap {
                requested_after: from,
                available_from,
            });
            from = available_from;
        }
        let mut ctl_after = cursor.ctl_after;
        if let Some((lost_seq, lost_id)) = self.lost_ctl
            && ctl_after < lost_id
            && from <= lost_seq
        {
            // Control entries this consumer was owed were force-evicted
            // (control-only overflow). `from == available_from == lost_seq`
            // here (a smaller `from` already produced the gap above, and
            // `available_from` never moves behind a force-evicted control),
            // so the gap has equal offsets: no bytes lost, controls were.
            if events.is_empty() {
                events.push(ReplayEvent::Gap {
                    requested_after: cursor.after,
                    available_from: from,
                });
            }
            ctl_after = lost_id;
        }
        let start_from = from;
        let mut remaining = max_bytes;

        for entry in &self.entries {
            match entry {
                Entry::Output { start, data } => {
                    let entry_end = *start + data.len() as u64;
                    if entry_end <= from {
                        continue; // entirely before the cursor
                    }
                    if remaining == 0 {
                        break; // budget spent; everything after is later
                    }
                    // `from >= start` here: entries are contiguous and we
                    // have consumed everything before `from`.
                    let skip = (from - *start) as usize;
                    let take = (data.len() - skip).min(remaining);
                    let chunk = Bytes::copy_from_slice(&data[skip..skip + take]);
                    from += take as u64;
                    remaining -= take;
                    events.push(ReplayEvent::Output {
                        sequence: from,
                        data: chunk,
                    });
                    if take < data.len() - skip {
                        break; // budget spent mid-chunk
                    }
                }
                Entry::Control { seq, id, event } => {
                    if *seq < start_from {
                        // Positioned before this read began: already seen
                        // (or evicted-past); mark it so the cursor stays
                        // tight.
                        ctl_after = ctl_after.max(*id);
                        continue;
                    }
                    if *seq > from {
                        // Bytes before it are not delivered yet (budget
                        // hit); it belongs to a later read.
                        break;
                    }
                    if *id <= ctl_after {
                        continue; // already delivered to this consumer
                    }
                    ctl_after = *id;
                    events.push(ReplayEvent::Control {
                        sequence: *seq,
                        ctl_id: *id,
                        event: event.clone(),
                    });
                }
            }
        }

        Ok(ReadOut {
            events,
            next: Cursor {
                after: from,
                ctl_after,
            },
        })
    }

    fn budget(&self) -> usize {
        self.budget
    }

    fn retained(&self) -> usize {
        self.retained
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn chunk_max(&self) -> usize {
        self.piece_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn output_bytes(out: &ReadOut) -> Vec<u8> {
        let mut v = Vec::new();
        for e in &out.events {
            if let ReplayEvent::Output { data, .. } = e {
                v.extend_from_slice(data);
            }
        }
        v
    }

    fn controls(out: &ReadOut) -> Vec<(u64, u64)> {
        out.events
            .iter()
            .filter_map(|e| match e {
                ReplayEvent::Control {
                    sequence, ctl_id, ..
                } => Some((*sequence, *ctl_id)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn offsets_are_cumulative_and_sequence_is_end_of_chunk() {
        let mut ring = ReplayRing::new(1024);
        assert_eq!(ring.push(b"Hello\r\n"), 7);
        assert_eq!(ring.push(b"world"), 12);
        assert_eq!(ring.push(b""), 12);
        let out = ring.read(Cursor::from_offset(0), usize::MAX).unwrap();
        assert_eq!(output_bytes(&out), b"Hello\r\nworld");
        assert_eq!(out.next.after, 12);
        // The two pushes coalesce into one chunk (the producer's chunking
        // is not observable); every Output event's `sequence` is the offset
        // after its last byte.
        assert_eq!(out.events.len(), 1);
        match &out.events[0] {
            ReplayEvent::Output { sequence, data } => {
                assert_eq!(*sequence, 12);
                assert_eq!(&data[..], b"Hello\r\nworld");
            }
            other => panic!("unexpected {other:?}"),
        }
        // A read cut mid-way sees the same offsets: sequence 7 after 7 bytes.
        let cut = ring.read(Cursor::from_offset(0), 7).unwrap();
        match &cut.events[0] {
            ReplayEvent::Output { sequence, data } => {
                assert_eq!(*sequence, 7);
                assert_eq!(&data[..], b"Hello\r\n");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn replay_truncation_is_byte_exact_across_chunk_boundaries() {
        let mut ring = ReplayRing::new(1024);
        ring.push(b"abcdef");
        ring.push(b"ghij");
        for after in 0..=10u64 {
            let out = ring.read(Cursor::from_offset(after), usize::MAX).unwrap();
            assert!(!out.has_gap());
            assert_eq!(output_bytes(&out), &b"abcdefghij"[after as usize..]);
            assert_eq!(out.next.after, 10);
        }
        // max_bytes cuts mid-chunk and the next read resumes exactly there.
        let a = ring.read(Cursor::from_offset(2), 3).unwrap();
        assert_eq!(output_bytes(&a), b"cde");
        assert_eq!(a.next.after, 5);
        let b = ring.read(a.next, 3).unwrap();
        assert_eq!(output_bytes(&b), b"fgh");
        assert_eq!(b.next.after, 8);
    }

    #[test]
    fn utf8_multibyte_across_chunk_boundary_survives_intact() {
        // "한글" is 6 bytes; split the second code point across two pushes
        // and read it back one byte at a time and in one go.
        let s = "한글✓";
        let bytes = s.as_bytes();
        let mut ring = ReplayRing::new(1024);
        ring.push(&bytes[..4]);
        ring.push(&bytes[4..]);
        let out = ring.read(Cursor::from_offset(0), usize::MAX).unwrap();
        assert_eq!(std::str::from_utf8(&output_bytes(&out)).unwrap(), s);
        let mut cursor = Cursor::from_offset(0);
        let mut collected = Vec::new();
        loop {
            let out = ring.read(cursor, 1).unwrap();
            if out.events.is_empty() {
                break;
            }
            collected.extend(output_bytes(&out));
            cursor = out.next;
        }
        assert_eq!(std::str::from_utf8(&collected).unwrap(), s);
    }

    #[test]
    fn overflow_evicts_whole_chunks_and_reports_exact_available_from() {
        // Budget 64 ⇒ 4-byte chunks. 17 four-byte pushes = 68 bytes: the
        // oldest chunk (0..4) is evicted whole.
        let mut ring = ReplayRing::new(64);
        assert_eq!(ring.chunk_max(), 4);
        let mut oracle = Vec::new();
        for i in 0..17u8 {
            let chunk = [b'a' + i; 4];
            ring.push(&chunk);
            oracle.extend_from_slice(&chunk);
        }
        assert_eq!(ring.available_from(), 4);
        assert!(ring.retained() <= ring.budget());
        let out = ring.read(Cursor::from_offset(1), usize::MAX).unwrap();
        assert_eq!(
            out.events[0],
            ReplayEvent::Gap {
                requested_after: 1,
                available_from: 4
            }
        );
        assert_eq!(output_bytes(&out), &oracle[4..]);
        assert_eq!(out.next.after, 68);
        // Exactly at the boundary there is no gap.
        let out = ring.read(Cursor::from_offset(4), usize::MAX).unwrap();
        assert!(!out.has_gap());
        assert_eq!(output_bytes(&out), &oracle[4..]);
    }

    #[test]
    fn large_pushes_are_split_so_eviction_stays_granular() {
        // Budget 64 chunks ⇒ piece_max == RING_CHUNK_MAX.
        let mut ring = ReplayRing::new(64 * RING_CHUNK_MAX);
        assert_eq!(ring.chunk_max(), RING_CHUNK_MAX);
        let big = vec![7u8; 3 * RING_CHUNK_MAX + 5];
        ring.push(&big);
        assert_eq!(ring.entry_count(), 4);
        for _ in 0..40 {
            ring.push(&big);
        }
        assert!(ring.retained() <= ring.budget());
        // The oldest retained offset is a piece boundary, not 0, and the
        // budget is honoured to within one chunk (whole-chunk eviction).
        assert_eq!(ring.available_from() % RING_CHUNK_MAX as u64, 0);
        assert!(ring.available_from() > 0);
        assert!(ring.retained() > ring.budget() - RING_CHUNK_MAX);
    }

    #[test]
    fn cursor_beyond_end_is_rejected_not_clamped() {
        let mut ring = ReplayRing::new(64);
        ring.push(b"xyz");
        assert_eq!(
            ring.read(Cursor::from_offset(4), 10),
            Err(ReadError::CursorBeyondEnd { after: 4, end: 3 })
        );
        // Exactly at the end is fine (nothing new).
        let out = ring.read(Cursor::from_offset(3), 10).unwrap();
        assert!(out.events.is_empty());
        assert_eq!(out.next.after, 3);
    }

    #[test]
    fn control_entries_are_total_ordered_with_output_and_seen_once() {
        let mut ring = ReplayRing::new(1024);
        ring.push(b"aaaa"); // 0..4
        let (seq1, id1) = ring.push_control(ControlEvent::WriterChanged {
            writer: Some("device:a".into()),
        });
        assert_eq!((seq1, id1), (4, 1));
        ring.push(b"bbbb"); // 4..8
        let (seq2, id2) = ring.push_control(ControlEvent::Exit {
            exit_code: Some(0),
            signal: None,
        });
        assert_eq!((seq2, id2), (8, 2));
        assert_eq!(ring.end(), 8, "control entries do not advance the offset");

        // Full read: a, ctl1, b, ctl2 in order.
        let out = ring.read(Cursor::from_offset(0), usize::MAX).unwrap();
        let kinds: Vec<&str> = out
            .events
            .iter()
            .map(|e| match e {
                ReplayEvent::Output { .. } => "out",
                ReplayEvent::Control { .. } => "ctl",
                ReplayEvent::Gap { .. } => "gap",
            })
            .collect();
        assert_eq!(kinds, ["out", "ctl", "out", "ctl"]);
        assert_eq!(
            out.next,
            Cursor {
                after: 8,
                ctl_after: 2
            }
        );

        // Caught-up stateful consumer at 4 gets ctl1 once, then nothing.
        let first = ring.read(Cursor::from_offset(4), 0).unwrap();
        assert_eq!(controls(&first), [(4, 1)]);
        assert!(output_bytes(&first).is_empty());
        let again = ring.read(first.next, 0).unwrap();
        assert!(again.events.is_empty(), "{again:?}");
        // Stateless retry at the same offset is at-least-once.
        let retry = ring.read(Cursor::from_offset(4), 0).unwrap();
        assert_eq!(controls(&retry), [(4, 1)]);

        // Budget cut mid-way: ctl2 must not be delivered before bytes 6..8.
        let cut = ring.read(Cursor::from_offset(4), 2).unwrap();
        assert_eq!(controls(&cut), [(4, 1)]);
        assert_eq!(output_bytes(&cut), b"bb");
        assert_eq!(cut.next.after, 6);
        let rest = ring.read(cut.next, 10).unwrap();
        assert_eq!(output_bytes(&rest), b"bb");
        assert_eq!(controls(&rest), [(8, 2)]);
        assert_eq!(
            rest.next,
            Cursor {
                after: 8,
                ctl_after: 2
            }
        );

        // A consumer that skips ahead (--after 8) does not see ctl1
        // (positioned before its start) but does see ctl2 at its start.
        let late = ring.read(Cursor::from_offset(8), 10).unwrap();
        assert_eq!(controls(&late), [(8, 2)]);
        assert_eq!(late.next.ctl_after, 2);
    }

    #[test]
    fn control_only_streams_stay_bounded() {
        let mut ring = ReplayRing::new(CONTROL_ENTRY_COST * 4);
        for _ in 0..100 {
            ring.push_control(ControlEvent::WriterChanged { writer: None });
        }
        assert!(ring.retained() <= ring.budget());
        assert_eq!(ring.entry_count(), 4);
        assert_eq!(ring.available_from(), 0);
        assert_eq!(ring.end(), 0);
    }

    #[test]
    fn small_pushes_coalesce_so_entry_count_is_bounded() {
        // A PTY echoing one byte at a time must not create one entry per
        // byte: entries are bounded by budget / piece size, and memory by
        // the budget itself (DoD: per-session memory is bounded).
        let budget = 4096;
        let mut ring = ReplayRing::new(budget);
        let mut oracle = Vec::new();
        for i in 0..200_000u32 {
            let b = (i % 251) as u8;
            ring.push(&[b]);
            oracle.push(b);
        }
        assert!(ring.retained() <= budget);
        assert!(
            ring.entry_count() <= budget / ring.chunk_max() + 1,
            "entries {} for budget {budget}",
            ring.entry_count()
        );
        // Whatever is retained is still byte-exact.
        let avail = ring.available_from() as usize;
        let out = ring
            .read(Cursor::from_offset(avail as u64), usize::MAX)
            .unwrap();
        assert_eq!(output_bytes(&out), &oracle[avail..]);
        assert!(ring.end() as usize - avail <= budget);
    }

    #[test]
    fn coalescing_never_crosses_a_control_entry() {
        let mut ring = ReplayRing::new(1024);
        ring.push(b"ab");
        ring.push_control(ControlEvent::WriterChanged { writer: None });
        ring.push(b"cd");
        assert_eq!(
            ring.entry_count(),
            3,
            "output after a control starts a new chunk"
        );
        let out = ring.read(Cursor::from_offset(0), usize::MAX).unwrap();
        let kinds: Vec<&str> = out
            .events
            .iter()
            .map(|e| match e {
                ReplayEvent::Output { .. } => "out",
                ReplayEvent::Control { .. } => "ctl",
                ReplayEvent::Gap { .. } => "gap",
            })
            .collect();
        assert_eq!(kinds, ["out", "ctl", "out"]);
    }

    #[test]
    fn control_at_available_from_survives_output_eviction() {
        // Fill the budget, append a control at offset B, then push B-64 more
        // bytes: every chunk before the control is evicted and the ring
        // lands exactly on budget as [Ctl@B, Out(B..)]. The control at the
        // new available_from must survive and a cursor at B sees it with
        // no gap (the reviewer's silent-loss scenario).
        let budget = 3200;
        let mut ring = ReplayRing::new(budget);
        ring.push(&vec![b'a'; budget]);
        let (seq, id) = ring.push_control(ControlEvent::Exit {
            exit_code: Some(0),
            signal: None,
        });
        assert_eq!((seq, id), (budget as u64, 1));
        ring.push(&vec![b'b'; budget - CONTROL_ENTRY_COST]);
        assert_eq!(ring.available_from(), budget as u64);
        assert!(ring.retained() <= ring.budget());
        let out = ring
            .read(
                Cursor {
                    after: budget as u64,
                    ctl_after: 0,
                },
                usize::MAX,
            )
            .unwrap();
        assert!(!out.has_gap(), "{:?}", out.events.first());
        assert_eq!(controls(&out), [(budget as u64, 1)]);
        assert_eq!(output_bytes(&out), vec![b'b'; budget - CONTROL_ENTRY_COST]);
        // Byte gap semantics are unchanged for a cursor behind it.
        let behind = ring.read(Cursor::from_offset(5), usize::MAX).unwrap();
        assert_eq!(
            behind.events[0],
            ReplayEvent::Gap {
                requested_after: 5,
                available_from: budget as u64
            }
        );
        assert_eq!(controls(&behind), [(budget as u64, 1)]);
    }

    #[test]
    fn forced_control_loss_is_signalled_by_a_gap_never_hidden() {
        // Budget 80: 10 bytes then two controls at 10 = 138. Evicting all
        // output leaves [Ctl@10, Ctl@10] = 128 > 80 and the only thing
        // left to evict is a control still positioned at available_from.
        // That loss must surface as a gap (equal offsets: no bytes lost),
        // exactly once per consumer.
        let mut ring = ReplayRing::new(80);
        ring.push(&[b'a'; 10]);
        ring.push_control(ControlEvent::WriterChanged { writer: None });
        ring.push_control(ControlEvent::WriterChanged {
            writer: Some("device:b".into()),
        });
        assert!(ring.retained() <= ring.budget());
        assert_eq!(ring.available_from(), 10);
        let out = ring
            .read(
                Cursor {
                    after: 10,
                    ctl_after: 0,
                },
                usize::MAX,
            )
            .unwrap();
        assert_eq!(
            out.events[0],
            ReplayEvent::Gap {
                requested_after: 10,
                available_from: 10
            }
        );
        assert_eq!(controls(&out), [(10, 2)]);
        assert_eq!(
            out.next,
            Cursor {
                after: 10,
                ctl_after: 2
            }
        );
        // Stateful follow-up: no repeated gap.
        let again = ring.read(out.next, usize::MAX).unwrap();
        assert!(again.events.is_empty(), "{again:?}");
        // A consumer that already had the lost control sees no gap.
        let had = ring
            .read(
                Cursor {
                    after: 10,
                    ctl_after: 1,
                },
                usize::MAX,
            )
            .unwrap();
        assert!(!had.has_gap());
        assert_eq!(controls(&had), [(10, 2)]);
        // A consumer behind the byte gap gets the byte gap only, once.
        let behind = ring.read(Cursor::from_offset(3), usize::MAX).unwrap();
        assert_eq!(
            behind.events[0],
            ReplayEvent::Gap {
                requested_after: 3,
                available_from: 10
            }
        );
        assert_eq!(
            behind
                .events
                .iter()
                .filter(|e| matches!(e, ReplayEvent::Gap { .. }))
                .count(),
            1
        );
        assert_eq!(behind.next.ctl_after, 2);
    }

    // ---- oracle property tests (DoD item 1) -------------------------------

    #[derive(Debug, Clone)]
    enum Op {
        Push(Vec<u8>),
        Ctl,
        /// (offset chosen as a fraction of the stream so far, max_bytes)
        Read(u8, usize),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => prop::collection::vec(any::<u8>(), 1..200).prop_map(Op::Push),
            1 => Just(Op::Ctl),
            3 => (any::<u8>(), 0..300usize).prop_map(|(f, m)| Op::Read(f, m)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Any interleaving of appends and stateless offset reads: without a
        /// gap the returned bytes are byte-identical to the oracle suffix;
        /// with a gap `available_from` is exact and everything from it on
        /// is returned intact (no silent truncation). Small budgets make
        /// eviction happen constantly.
        #[test]
        fn read_matches_naive_vec_oracle(
            budget in 64usize..2048,
            ops in prop::collection::vec(op_strategy(), 1..120),
        ) {
            let mut ring = ReplayRing::new(budget);
            let mut oracle: Vec<u8> = Vec::new();
            let mut gaps = 0usize;
            let mut evictions = 0usize;
            for op in ops {
                match op {
                    Op::Push(data) => {
                        let before = ring.available_from();
                        let end = ring.push(&data);
                        oracle.extend_from_slice(&data);
                        prop_assert_eq!(end, oracle.len() as u64);
                        prop_assert!(ring.retained() <= ring.budget());
                        if ring.available_from() > before { evictions += 1; }
                    }
                    Op::Ctl => {
                        let (seq, _) = ring.push_control(ControlEvent::WriterChanged { writer: None });
                        prop_assert_eq!(seq, oracle.len() as u64);
                    }
                    Op::Read(frac, max_bytes) => {
                        let end = oracle.len() as u64;
                        let after = if end == 0 { 0 } else { (end * frac as u64) / 255 };
                        let out = ring.read(Cursor::from_offset(after), max_bytes).unwrap();
                        let avail = ring.available_from();
                        let bytes = output_bytes(&out);
                        if after < avail {
                            gaps += 1;
                            prop_assert_eq!(
                                out.events.first(),
                                Some(&ReplayEvent::Gap { requested_after: after, available_from: avail })
                            );
                            let want_len = ((end - avail) as usize).min(max_bytes);
                            prop_assert_eq!(&bytes[..], &oracle[avail as usize..avail as usize + want_len]);
                            prop_assert_eq!(out.next.after, avail + want_len as u64);
                        } else {
                            // The only gap allowed here is the control-loss
                            // gap (equal offsets), never a byte gap.
                            for e in &out.events {
                                if let ReplayEvent::Gap { requested_after, available_from } = e {
                                    prop_assert_eq!(*requested_after, after);
                                    prop_assert_eq!(*available_from, after);
                                }
                            }
                            let want_len = ((end - after) as usize).min(max_bytes);
                            prop_assert_eq!(&bytes[..], &oracle[after as usize..after as usize + want_len]);
                            prop_assert_eq!(out.next.after, after + want_len as u64);
                        }
                        // Every Output event's sequence is the end offset of
                        // its bytes, and events are contiguous.
                        let mut pos = out.next.after - bytes.len() as u64;
                        for e in &out.events {
                            if let ReplayEvent::Output { sequence, data } = e {
                                prop_assert!(!data.is_empty());
                                pos += data.len() as u64;
                                prop_assert_eq!(*sequence, pos);
                            }
                        }
                    }
                }
            }
            // Whatever the ring claims to retain is served exactly.
            let avail = ring.available_from();
            let out = ring.read(Cursor::from_offset(avail), usize::MAX).unwrap();
            for e in &out.events {
                if let ReplayEvent::Gap { requested_after, available_from } = e {
                    // Only the control-loss gap (equal offsets) may appear.
                    prop_assert_eq!(*requested_after, avail);
                    prop_assert_eq!(*available_from, avail);
                }
            }
            prop_assert_eq!(&output_bytes(&out)[..], &oracle[avail as usize..]);
            // Silence "unused" while keeping the counters available for
            // debugging a shrunk case.
            let _ = (gaps, evictions);
        }

        /// A stateful follower that feeds back `next` sees the whole
        /// stream from its start (or from `available_from` after a gap)
        /// byte-identically and every control entry exactly once, in
        /// order, regardless of how pushes and pulls interleave.
        #[test]
        fn stateful_follower_is_lossless_and_duplicate_free(
            budget in 256usize..4096,
            ops in prop::collection::vec(op_strategy(), 1..120),
        ) {
            let mut ring = ReplayRing::new(budget);
            let mut oracle: Vec<u8> = Vec::new();
            let mut ctl_ids: Vec<(u64, u64)> = Vec::new();
            let mut cursor = Cursor::from_offset(0);
            let mut got: Vec<u8> = Vec::new();
            let mut got_start = 0u64;
            let mut got_ctls: Vec<u64> = Vec::new();
            let mut gap_at: Vec<u64> = Vec::new();
            for op in ops {
                match op {
                    Op::Push(data) => {
                        ring.push(&data);
                        oracle.extend_from_slice(&data);
                    }
                    Op::Ctl => {
                        let (seq, id) = ring.push_control(ControlEvent::WriterChanged { writer: None });
                        ctl_ids.push((seq, id));
                    }
                    Op::Read(_, max_bytes) => {
                        let out = ring.read(cursor, max_bytes).unwrap();
                        for e in &out.events {
                            match e {
                                ReplayEvent::Gap { available_from, .. } => {
                                    // Resync: the follower's history restarts.
                                    got.clear();
                                    got_start = *available_from;
                                    gap_at.push(*available_from);
                                }
                                ReplayEvent::Output { data, .. } => got.extend_from_slice(data),
                                ReplayEvent::Control { ctl_id, .. } => got_ctls.push(*ctl_id),
                            }
                        }
                        cursor = out.next;
                    }
                }
            }
            // Drain to the end.
            loop {
                let out = ring.read(cursor, 4096).unwrap();
                if out.events.is_empty() { break; }
                for e in &out.events {
                    match e {
                        ReplayEvent::Gap { available_from, .. } => {
                            got.clear();
                            got_start = *available_from;
                            gap_at.push(*available_from);
                        }
                        ReplayEvent::Output { data, .. } => got.extend_from_slice(data),
                        ReplayEvent::Control { ctl_id, .. } => got_ctls.push(*ctl_id),
                    }
                }
                cursor = out.next;
            }
            prop_assert_eq!(cursor.after, oracle.len() as u64);
            prop_assert_eq!(&got[..], &oracle[got_start as usize..]);
            // Controls: strictly increasing ids (no dup, in order), and
            // every control positioned at or after the point where the
            // follower's retained history starts was delivered.
            for w in got_ctls.windows(2) {
                prop_assert!(w[0] < w[1], "duplicate/out-of-order control: {:?}", got_ctls);
            }
            // Against the running oracle (not just what the ring still
            // holds): every control positioned strictly after the start of
            // the follower's history was delivered — losing one requires
            // `available_from` to pass it, which the follower sees as a gap.
            // A control positioned exactly at `got_start` was delivered
            // unless a gap resynced the follower to that very offset (the
            // control-loss gap or a byte gap that landed there).
            for (seq, id) in &ctl_ids {
                if *seq > got_start {
                    prop_assert!(got_ctls.contains(id), "control {} at {} never delivered; got {:?}", id, seq, got_ctls);
                } else if *seq == got_start {
                    prop_assert!(
                        got_ctls.contains(id) || gap_at.contains(&got_start),
                        "control {} at {} (= history start) never delivered; got {:?}", id, seq, got_ctls
                    );
                }
            }
            // And nothing the oracle does not know about.
            for id in &got_ctls {
                prop_assert!(ctl_ids.iter().any(|(_, i)| i == id));
            }
        }
    }
}
