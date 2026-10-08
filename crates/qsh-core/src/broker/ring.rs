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
//! `session read --after N`, a long-running external process's (e.g. an
//! agent tool) long-poll) get *at-least-once* delivery of
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
mod tests;
