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
//!   writes.
//! - Overflow is never hidden: a cursor that points before
//!   [`ReplayStore::available_from`] gets a [`ReplayEvent::Gap`] first, then
//!   the data from `available_from` on (protocol.md §10 step 4).
//! - Control events (`session.exit` / `session.writer_changed` /
//!   `session.closed`) are **zero-length entries** in the same ring
//!   ([`ReplayStore::push_control`]). They sit at the offset current when
//!   they were appended, do not advance the offset, and are returned by
//!   [`ReplayStore::read`] in total order with the output — a caught-up
//!   consumer at offset `S` sees a control appended at `S` on its next pull
//!   (CLI.md §6.4 "전달 경로와 순서").
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

/// Largest single chunk kept in the ring. Bigger pushes are split, which
/// keeps whole-chunk eviction granular and bounds the read-side copy.
pub const RING_CHUNK_MAX: usize = 16 * 1024;

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
}

#[derive(Debug, Clone)]
enum Entry {
    Output {
        start: u64,
        data: Bytes,
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
    /// Largest piece a push is split into: `min(RING_CHUNK_MAX, budget)`,
    /// so a single piece always fits the budget.
    piece_max: usize,
    entries: VecDeque<Entry>,
    retained: usize,
    end: u64,
    next_ctl_id: u64,
}

impl ReplayRing {
    /// A ring with the given byte budget (`budget >= 1`; `0` is treated
    /// as `1`).
    pub fn new(budget: usize) -> Self {
        let budget = budget.max(1);
        Self {
            budget,
            piece_max: RING_CHUNK_MAX.min(budget),
            entries: VecDeque::new(),
            retained: 0,
            end: 0,
            next_ctl_id: 1,
        }
    }

    /// Number of entries (output chunks + control entries) retained.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn evict(&mut self) {
        // Never evict the entry that was just appended: with pieces capped
        // at `piece_max <= budget` this only matters for budgets below
        // `CONTROL_ENTRY_COST`, where the invariant becomes
        // `retained <= budget + cost(last)`.
        while self.retained > self.budget && self.entries.len() > 1 {
            if let Some(front) = self.entries.pop_front() {
                self.retained -= front.cost();
            }
        }
    }
}

impl ReplayStore for ReplayRing {
    fn push(&mut self, data: &[u8]) -> u64 {
        for piece in data.chunks(self.piece_max) {
            let start = self.end;
            self.entries.push_back(Entry::Output {
                start,
                data: Bytes::copy_from_slice(piece),
            });
            self.retained += piece.len();
            self.end += piece.len() as u64;
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
        let start_from = from;
        let mut ctl_after = cursor.ctl_after;
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
                    let chunk = data.slice(skip..skip + take);
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
        match &out.events[0] {
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
        let mut ring = ReplayRing::new(10);
        ring.push(b"aaaa"); // 0..4
        ring.push(b"bbbb"); // 4..8
        ring.push(b"cccc"); // 8..12 → evicts "aaaa"
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
        assert_eq!(output_bytes(&out), b"bbbbcccc");
        assert_eq!(out.next.after, 12);
        // Exactly at the boundary there is no gap.
        let out = ring.read(Cursor::from_offset(4), usize::MAX).unwrap();
        assert!(!out.has_gap());
        assert_eq!(output_bytes(&out), b"bbbbcccc");
    }

    #[test]
    fn large_pushes_are_split_so_eviction_stays_granular() {
        let mut ring = ReplayRing::new(4 * RING_CHUNK_MAX);
        let big = vec![7u8; 3 * RING_CHUNK_MAX + 5];
        ring.push(&big);
        assert_eq!(ring.entry_count(), 4);
        ring.push(&big);
        assert!(ring.retained() <= ring.budget());
        // The oldest retained offset is a piece boundary, not 0.
        assert_eq!(ring.available_from() % RING_CHUNK_MAX as u64, 0);
        assert!(ring.available_from() > 0);
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
                            prop_assert!(!out.has_gap());
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
            prop_assert!(!out.has_gap());
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
            let mut ctl_ids: Vec<u64> = Vec::new();
            let mut cursor = Cursor::from_offset(0);
            let mut got: Vec<u8> = Vec::new();
            let mut got_start = 0u64;
            let mut got_ctls: Vec<u64> = Vec::new();
            for op in ops {
                match op {
                    Op::Push(data) => {
                        ring.push(&data);
                        oracle.extend_from_slice(&data);
                    }
                    Op::Ctl => {
                        let (_, id) = ring.push_control(ControlEvent::WriterChanged { writer: None });
                        ctl_ids.push(id);
                    }
                    Op::Read(_, max_bytes) => {
                        let out = ring.read(cursor, max_bytes).unwrap();
                        for e in &out.events {
                            match e {
                                ReplayEvent::Gap { available_from, .. } => {
                                    // Resync: the follower's history restarts.
                                    got.clear();
                                    got_start = *available_from;
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
                        ReplayEvent::Gap { available_from, .. } => { got.clear(); got_start = *available_from; }
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
            // Every retained control the follower could have seen must
            // have been delivered: check against a full read from
            // `got_start`.
            let full = ring.read(Cursor::from_offset(got_start), usize::MAX).unwrap();
            let expected: Vec<u64> = full.events.iter().filter_map(|e| match e {
                ReplayEvent::Control { ctl_id, .. } => Some(*ctl_id),
                _ => None,
            }).collect();
            for id in expected {
                prop_assert!(got_ctls.contains(&id), "control {} never delivered; got {:?}", id, got_ctls);
            }
        }
    }
}
