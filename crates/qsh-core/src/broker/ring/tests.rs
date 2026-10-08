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
