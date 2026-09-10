//! Stateful op-sequence harness for the broker's core data structures
//! (`ReplayRing`/`ring.rs`, `WriterLease`/`lease.rs`, `ResumeRegistry`/
//! `resume.rs`, `TtlWindow`/`session.rs`). Shared, byte-for-byte, by the
//! `broker_ops_corpus` nextest binary (seed replay) and the `broker_ops`
//! libfuzzer target (`fuzz/fuzz_targets/broker_ops.rs`, `#[path]`-included)
//! — one decoder, one model, one oracle, compiled into two different
//! binaries so the fixed byte format is the only thing that has to agree.
//!
//! Public API: `qsh_core::broker::*` plus `std`. No `arbitrary`, no
//! `libfuzzer-sys`, no `rand`, no `Instant::now()`, no result that depends
//! on `HashMap` iteration order — the one `HashMap` here (`Reap`'s
//! deadline map) exists because `ResumeRegistry::sync_expiry` takes one,
//! and it is only ever `get`-queried, never iterated by this file — so it
//! compiles into both a plain nextest binary and a `#![no_main]` fuzz
//! target, and determinism here is the whole point: the same input must
//! decode to the same op sequence and hit the same assertions every time,
//! on every platform, forever (`docs/design/testing.md` L2's "injectable
//! clock" is why a `TestClock` driven only by `TestClock::advance` stands
//! in for wall time).
//!
//! # Op encoding
//!
//! The input is read front-to-back as a sequence of ops. Each op is one
//! opcode byte (`% N_OPS`, table below) followed by that op's fixed-size
//! arguments, little-endian. If an op's fixed arguments run past the end
//! of the input, decoding stops **before** that op (it is not executed) —
//! a truncated trailing op is silently dropped, not padded. At most 4096
//! ops run per input (`fuzz/fuzz_targets/frame_decoder.rs`'s convention).
//! `sess` always selects a slot as `sess % 4`; there are exactly 4 session
//! slots, `SessionId("s0")..SessionId("s3")`, created by `NewSession` and
//! never minted with `SessionId::generate_at` (that pulls ulid randomness
//! — the harness needs stable, human-nameable ids instead). An op that
//! names a slot with no session in it is a no-op (decoding continues).
//!
//! | opcode | op | args | derivation |
//! |---|---|---|---|
//! | 0 | `NewSession` | `sess: u8, budget: u16` | slot = `sess % 4`; budget = `1 + budget % 8192`; `ReplayRing::new(budget)`. A full slot is replaced: the old session is torn down (`registry.forget(id)`, lease dropped, fresh model) exactly as a real close would leave it. |
//! | 1 | `Append` | `sess: u8, len: u16` | `len %= 1024` bytes are taken verbatim from the remaining input; if the input runs short, the rest of *this op's own buffer* (not the whole run) is filled with `((model.stream.len() + i) as u8) ^ 0x5A` for `i` = that byte's position within the buffer — position-dependent so an off-by-one in the real offset shows up as a content mismatch, not a coincidental match. |
//! | 2 | `AppendControl` | `sess: u8, kind: u8` | `kind % 3` → `Exit{None,None}` / `WriterChanged{writer:None}` / `Closed{reason:Closed}`. |
//! | 3 | `ReadAt` | `sess: u8, frac: u8, max: u16` | `after = end * frac / 255` (stateless offset cursor — at-least-once, never asserted duplicate-free); `max %= 4096`. |
//! | 4 | `ReadBeyond` | `sess: u8, over: u8` | `after = end + 1 + over % 64` → must be `Err(CursorBeyondEnd{after, end})` exactly. |
//! | 5 | `ReadFollow` | `sess: u8, max: u16` | reads from the slot's own persistent stateful cursor (`ModelSession::got`), advances it to `out.next`; `max %= 4096`. |
//! | 6 | `TakeLease` | `sess: u8, principal: u8, owner: u8, physical: u8, flags: u8` | each identity byte `% 4`; `flags` bit0 = `no_steal`, bit1 = `take` (bit unset: `owner == physical`, the ordinary one-connection-is-one-asker path) vs `take_owned` (bit set: `owner`/`physical` independent, the reverse-route path, `lease.rs:114-132`). |
//! | 7 | `DropConnection` | `conn: u8` | `conn %= 4`; `lease.release_connection(ConnectionId(conn))` on **every live slot** — `server/mod.rs:2321-2322`'s `purge_connection` releases the same connection's lease on every session it touches, not just one. |
//! | 8 | `Attach` | `sess: u8` | `model.attached += 1`. |
//! | 9 | `Detach` | `sess: u8` | `model.attached = attached.saturating_sub(1)`; `attached == 0` ⇒ `ttl_base = now` (`session.rs:795-805`'s `AttachGuard::drop`). |
//! | 10 | `SetExited` | `sess: u8` | `state = Exited`, `ttl_base = now` (`session.rs:1338-1345`'s `set_state_exited`). |
//! | 11 | `SetClosing` | `sess: u8` | `closing = true`. |
//! | 12 | `IssueResume` | `sess: u8, peer: u8, ttl: u16` | `registry.issue(id, PeerFingerprint::new([peer; 32]), 1 + ttl % 60000 ms)`. |
//! | 13 | `VerifyResume` | `sess: u8, tokref: u8, peer: u8` | `tokref >> 6` selects which token bytes to present: 0 Live (the slot's current token, opaque bytes — see below; no live token in the slot ⇒ a `[0xAA; 32]` sentinel, denied by construction), 1 Spent (`model.spent[(tokref & 63) % spent.len()]` — always a real superseded generation: with nothing spent yet the op consumes its arguments and does nothing at all, since a stand-in would only re-ask what kinds 2 and 3 already ask), 2 Garbage (`[tokref & 63; 32]` — well-formed length, wrong content), 3 Truncated (`[tokref & 63; 5]` — wrong length entirely, still hashable). |
//! | 14 | `RotateResume` | `sess: u8, tokref: u8, peer: u8, ttl: u16, axis: u8` | `tokref` decodes as row 13, no-op on an empty `spent` list included; `rotate(id, presented, peer, ttl, InputStreamId(1 + axis as u64))`. |
//! | 15 | `ForgetResume` | `sess: u8` | `registry.forget(id)`, called twice to exercise idempotence. |
//! | 16 | `TickSmall` | `ms: u8` | `clock.advance(1 + ms ms)` — 1..=256ms steps. |
//! | 17 | `TickLarge` | `ms: u16` | `clock.advance(1 + ms ms)` — up to ~65.5s steps, the range that actually crosses `SESSION_TTL`. |
//! | 18 | `Reap` | *(none)* | the registry half of one reaper pass, plus one call production never makes: `broker/mod.rs:830-891` builds a deadline map of *every* session in its registry (doomed ones included, `:837-838`) and calls `sync_expiry` (`:870`) once, then closes doomed sessions and `forget`s them (`:878`, `:885`); this harness additionally calls `purge_expired` right after `sync_expiry` so a credential's own expiry is judged on the spot instead of at the next `sync_expiry`. Per occupied slot, `TtlWindow::reap_reason` and `TtlWindow::deadline` (both real) are compared against [`predict_reap_reason`] and [`predict_deadline`] (both hand-written, neither of which calls `TtlWindow`); a slot whose predicted reason is `Some` is *doomed*. Only the slots that survive the pass go into the map, which is the shape a real pass takes once the session it is closing has already left the session registry — that is what drives `sync_expiry`'s `None` arm (`resume.rs:344`), where a credential keeps its own expiry and lives on only while `expires_at > now`, the same strict inequality `purge_expired` (`resume.rs:324`) and `verify`'s freshness bit (`resume.rs:260`) use. After the two real calls `registry.len()` must equal the model's count; then every doomed slot is `registry.forget`-ten and emptied (a reap closes the session before forgetting its credential) and `len()` is checked once more. The one observable divergence from production: a slot that escaped doom only because it is `closing` but whose TTL has elapsed is a survivor here, so its credential is re-anchored to a past deadline and purged on the spot; production keeps that entry until `forget` (unusable either way — `verify`'s freshness check, `resume.rs:260`). The model applies the same rule. |
//!
//! `N_OPS` is 19 (opcodes 0..=18). Resume-token bytes are treated as
//! opaque throughout: the harness stores whatever `ResumeToken::expose()`
//! hands back (from `issue`/`rotate`, both real calls — never `rand`
//! itself) and only ever presents that blob back verbatim; nothing here
//! branches on token *content*, only on which of the four `tokref` kinds a
//! presented value came from. `SESSION_TTL` is a fixed 10s constant so a
//! seed's op sequence means the same thing on every run.
//!
//! # Model and oracle
//!
//! `ModelSession` is a from-scratch, independent re-derivation of what
//! each slot's real objects should say — it never calls the function it
//! is checking (that would make the assertion tautological). Fields:
//! `stream` (the full output history, never evicted, unlike the ring),
//! `ctl` (every `(sequence, ctl_id)` ever pushed), `appends` (every
//! `Append`'s end offset with a running chunk count, for the entry-count
//! bound), `got`/`got_start`/`last_ctl_seen` (the `ReadFollow` cursor, the
//! next control id it should see, and the last one it did see), `lease`
//! (`(principal, owner, physical)` or `None`), `attached`/`closing`/
//! `state`/`ttl_base` (the four `TtlWindow` facts), `live_token`/`spent`
//! (opaque token bytes), `peer`/`axis`/`expires_at` (the bound resume
//! identity). Every op above is followed by the oracle rows it exercises:
//!
//! - **sequence**: `Append`'s return and `push_control`'s `seq` both equal
//!   `model.stream.len()` after the update; `ring.end() == model.stream.len()`
//!   after every ring-touching op; every `Output` event's `sequence` equals
//!   the running offset after that chunk; `ReadFollow`'s `next.after` never
//!   moves backwards.
//! - **control ids**: `ReadFollow` sees ids in strictly increasing order,
//!   every id/seq pair it surfaces exists in `model.ctl` (never forged),
//!   and — outside of a `Gap` (which is the one place a skip is legal) —
//!   the next id is always exactly one past the last (no silent loss); the
//!   first id after a `Gap` may skip ahead but must still be strictly past
//!   the last id already delivered, so a gap can lose controls and never
//!   replay or reorder them. `ReadAt`/`ReadBeyond` are offset cursors
//!   (at-least-once) and are excluded from the ordering and contiguity
//!   halves (`ring.rs:44-48`) — but not from the forgery half: every
//!   `(sequence, ctl_id)` a `ReadAt` surfaces must exist in `model.ctl`
//!   too.
//! - **`ctl_after`**: the cursor a read hands back never moves backwards,
//!   covers every control id that read delivered, and — while nothing has
//!   been evicted yet, so `model.ctl` still describes the ring's live
//!   controls exactly — covers every control positioned before the offset
//!   the read started from (`ring.rs:484-490`'s "already seen (or
//!   evicted-past)" tightening; without it a later read from an earlier
//!   offset would surface those ids again, out of order).
//! - **gap / byte-identity**: `requested_after < available_from` ⇒ the
//!   first event is `Gap{requested_after, available_from}` verbatim and
//!   what follows is `model.stream[available_from..]`'s prefix; otherwise
//!   the bytes returned are `model.stream[after..]`'s prefix, byte for
//!   byte. A control-only overflow is required to carry the same-offset
//!   `Gap` `ring.rs:440-455` describes — enforced as a side effect of the
//!   control-id contiguity check above (a silent id skip with no `Gap` in
//!   between fails it).
//! - **memory**: `entry_count() == 1 || retained() <= budget()` (the
//!   `entry_count() == 1` escape hatch is for a budget so small the
//!   just-appended entry alone exceeds it — `ring.rs:322-327` — eviction
//!   never removes the entry it just added); `entry_count()` is bounded by
//!   what can still be live rather than by the budget alone — every live
//!   entry starts at or after `available_from` (`ring.rs:409-417`), so the
//!   live output chunks come only from `Append`s whose own end ran past
//!   `available_from`, at most `len.div_ceil(chunk_max)` chunks each
//!   (`ring.rs:363-378`), and the live controls only from those pushed at
//!   or after it (`ring.rs:348-357` drops the ones strictly behind);
//!   `chunk_max()` fixed at construction and equal to `(budget /
//!   RING_CHUNK_DIVISOR).clamp(1, RING_CHUNK_MAX)`. `retained()` is the ring's own
//!   self-reported charge — this file does not recompute it independently
//!   from the entries, only cross-checks it against `budget()`.
//! - **lease**: `holder()` matches the model; `is_held_by` is true for the
//!   current owner connection and false for every other; `Conflict` fires
//!   exactly when the model predicts `no_steal && holder.principal !=
//!   asker` (`lease.rs:145-147`); a re-take on the holding connection is
//!   `Acquired{displaced:None, changed:false}` regardless of principal
//!   (`lease.rs:141-144`); every other successful take is
//!   `Acquired{displaced:Some(old holder), changed:(old owner !=
//!   new owner)}` (`lease.rs:148-158`); `DropConnection` releases exactly
//!   the slots whose model `physical` equals the dropped connection and
//!   leaves every other slot's lease untouched (`lease.rs:166-171`).
//! - **resume**: whatever the model calls "no entry, expired, wrong hash,
//!   or wrong peer" is `Err(ResumeDenied)` on both `verify` and `rotate`,
//!   never mutates `registry.len()`, and never disturbs the stored axis (a
//!   denied `rotate` is followed by a `verify` proving the old axis still
//!   holds); a `Spent` token is denied unconditionally, and because kind 1
//!   never invents a stand-in, every such denial is a real superseded
//!   generation the registry itself refused; a successful
//!   `rotate` moves exactly one token to `spent` and mints exactly one new
//!   one (`registry.len()` unchanged); the same token can never rotate
//!   twice; `verify` never consumes (a later `rotate` on the same live
//!   token still succeeds — exercised end to end by seed 5's op sequence
//!   below, since a synthetic probe-rotate inside `VerifyResume`'s own
//!   handler would itself consume the credential and corrupt the replay);
//!   a successful `rotate(axis=X)` is followed by `verify == Ok(X)`; a
//!   fresh `issue` verifies at `Ok(FIRST_INPUT_STREAM)` immediately.
//! - **TTL/reap**: on every `Reap`, `TtlWindow::reap_reason` and
//!   `TtlWindow::deadline` (real) match [`predict_reap_reason`] and
//!   [`predict_deadline`] (hand-written, independent) on every occupied
//!   slot; after `sync_expiry` + `purge_expired`, `registry.len()` equals
//!   exactly the number of slots the model still believes hold a live
//!   token, counting a surviving slot by its re-anchored deadline and a
//!   doomed one by its own untouched `expires_at`; after the doomed slots
//!   are forgotten and emptied, `len()` equals what is left. Seed 7
//!   (`Attach` → many `TickLarge` → `Detach` → `Reap`) covers the
//!   re-anchoring arm, seed 11 the `None` arm where a credential outlives
//!   the session that owned it by a single millisecond.
//!
//! Deliberately out of scope (`docs/adr/` and `ARBITRATION-7b.md` Q7): the
//! default-deny ACL axis — that is `acl/policy.rs`'s proptest's job, this
//! file only measures the broker's own fail-closed shape (`ResumeDenied`,
//! `Conflict`, `CursorBeyondEnd`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::broker::ring::{CONTROL_ENTRY_COST, RING_CHUNK_DIVISOR, RING_CHUNK_MAX};
use qsh_core::broker::{
    Clock, CloseReason, ConnectionId, ControlEvent, Cursor, FIRST_INPUT_STREAM, InputStreamId,
    LeaseHolder, PeerFingerprint, ReadError, ReadOut, ReplayEvent, ReplayRing, ReplayStore,
    ResumeDenied, ResumeRegistry, SessionId, SessionState, TakeOutcome, TestClock, TtlWindow,
    WriterLease,
};

/// Number of session slots the harness keeps alive at once.
const SLOTS: u8 = 4;

/// Opcode byte is reduced modulo this.
const N_OPS: u8 = 19;

/// Hard cap on ops per run (`fuzz/fuzz_targets/frame_decoder.rs`'s
/// convention for a bounded, always-terminating decode loop).
const MAX_OPS: usize = 4096;

/// Fixed TTL the `Reap` op measures against, so a seed's meaning does not
/// depend on `[serve].resume_ttl`'s configured default.
const SESSION_TTL: Duration = Duration::from_secs(10);

/// Connection/principal identity space every `% 4`-reduced byte lands in.
const IDENTITY_MOD: u8 = 4;

fn session_id(slot: u8) -> SessionId {
    SessionId(format!("s{slot}"))
}

/// One session slot: the real objects under test plus the oracle's
/// independent prediction of what they should say.
struct Slot {
    ring: ReplayRing,
    lease: WriterLease,
    budget: usize,
    model: ModelSession,
}

/// Independent, hand-written model of one session's observable state. See
/// the module doc's "Model and oracle" section for what each field backs.
struct ModelSession {
    stream: Vec<u8>,
    ctl: Vec<(u64, u64)>,
    /// One `(end offset, running chunk count)` per `Append`. Both columns
    /// are non-decreasing, so a `partition_point` on the end offsets finds
    /// the first append that can still own a live ring entry. See
    /// [`assert_ring_invariants`].
    appends: Vec<(u64, usize)>,
    got: Cursor,
    /// Next control id `ReadFollow` should see; `None` right after a `Gap`
    /// (the next id seen there is an acceptable resync point).
    got_start: Option<u64>,
    /// Last control id `ReadFollow` actually delivered — the floor the
    /// resync point after a `Gap` has to clear.
    last_ctl_seen: Option<u64>,
    lease: Option<(String, ConnectionId, ConnectionId)>,
    attached: usize,
    closing: bool,
    state: SessionState,
    ttl_base: Instant,
    /// Opaque bytes of the token that currently verifies, if any.
    live_token: Option<Vec<u8>>,
    /// Every token ever superseded — always denied henceforth.
    spent: Vec<Vec<u8>>,
    peer: u8,
    axis: InputStreamId,
    /// Predicted expiry once `Reap`'s `sync_expiry` has run.
    expires_at: Instant,
}

impl ModelSession {
    fn new(now: Instant) -> Self {
        Self {
            stream: Vec::new(),
            ctl: Vec::new(),
            appends: Vec::new(),
            got: Cursor::default(),
            got_start: Some(1),
            last_ctl_seen: None,
            lease: None,
            attached: 0,
            closing: false,
            state: SessionState::Running,
            ttl_base: now,
            live_token: None,
            spent: Vec::new(),
            peer: 0,
            axis: FIRST_INPUT_STREAM,
            expires_at: now,
        }
    }

    /// The four facts `TtlWindow` reads, snapshotted from the model.
    fn ttl_window(&self) -> TtlWindow {
        TtlWindow {
            attached: self.attached,
            closing: self.closing,
            state: self.state,
            ttl_base: self.ttl_base,
        }
    }
}

/// Independent reimplementation of `TtlWindow::reap_reason`
/// (`session.rs`'s doc for [`SessionHandle::ttl_reap_reason`]) — written by
/// hand rather than calling `TtlWindow` so comparing the two has power to
/// catch a real regression instead of checking a function against itself.
fn predict_reap_reason(m: &ModelSession, now: Instant, ttl: Duration) -> Option<CloseReason> {
    if m.attached > 0 || m.closing {
        return None;
    }
    if now.saturating_duration_since(m.ttl_base) < ttl {
        return None;
    }
    Some(match m.state {
        SessionState::Exited => CloseReason::Exit,
        SessionState::Running => CloseReason::TtlExpired,
    })
}

/// Independent reimplementation of `TtlWindow::deadline`
/// (`SessionHandle::resume_deadline`'s rule) — hand-written for the same
/// reason [`predict_reap_reason`] is, so `Reap` never checks `TtlWindow`
/// against itself. The TTL only runs while nothing is attached, so an
/// attached session's credential is re-anchored to `now + ttl` on every
/// pass while an idle one's stays pinned to the moment it went idle.
fn predict_deadline(m: &ModelSession, now: Instant, ttl: Duration) -> Instant {
    if m.attached > 0 {
        now + ttl
    } else {
        m.ttl_base + ttl
    }
}

/// Chunk size the ring computes from a budget, re-derived here so the
/// oracle never asks the ring what it should be.
fn model_chunk_max(budget: usize) -> usize {
    (budget / RING_CHUNK_DIVISOR).clamp(1, RING_CHUNK_MAX)
}

/// What `ResumeRegistry::verify`/`rotate` should answer for a token of the
/// given `kind` (see the `VerifyResume` row) presented with `peer_arg`.
/// Only the `Live` kind (0) can ever succeed — `Spent`/`Garbage`/
/// `Truncated` are denied unconditionally by construction.
fn predict_verify(
    m: &ModelSession,
    now: Instant,
    kind: u8,
    peer_arg: u8,
) -> Result<InputStreamId, ResumeDenied> {
    if kind == 0 && m.live_token.is_some() && now < m.expires_at && peer_arg == m.peer {
        Ok(m.axis)
    } else {
        Err(ResumeDenied)
    }
}

/// Builds the bytes a `VerifyResume`/`RotateResume` op presents, per the
/// `tokref` encoding in the module doc's op table.
///
/// Kind 1 indexes `m.spent` directly: both callers skip the op outright
/// when nothing has been superseded yet, so a `Spent` presentation is
/// always a real dead generation and its denial is always the registry's
/// answer about that generation — never a stand-in re-asking what kinds 2
/// and 3 ask.
fn presented_bytes(m: &ModelSession, kind: u8, idx_sel: u8) -> Vec<u8> {
    match kind {
        0 => m.live_token.clone().unwrap_or_else(|| vec![0xAA; 32]),
        1 => m.spent[(idx_sel as usize) % m.spent.len()].clone(),
        2 => vec![idx_sel; 32],
        _ => vec![idx_sel; 5],
    }
}

/// Checks the gap/byte-identity contract every read shares (`ring.rs`
/// module docs). Two shapes of leading `Gap` are legal:
///
/// - the ordinary one, mandatory whenever `requested_after < available_from`:
///   `Gap{requested_after, available_from}` resyncing exactly to the ring's
///   `available_from()`;
/// - the control-only-overflow one (`ring.rs:439-455`), only ever possible
///   once the caller is already at/after `available_from`: a *same-offset*
///   `Gap{requested_after, available_from: requested_after}` signalling a
///   lost control with no bytes lost at all.
///
/// Whatever bytes follow — after the gap, or from `requested_after`
/// directly — must be `model_stream`'s prefix there, byte for byte, with
/// each `Output`'s `sequence` equal to the running offset after that
/// chunk. Returns whether a `Gap` was present, so a stateful caller
/// ([`ReadFollow`]) knows a control-id resync is due.
fn check_read_bytes(
    model_stream: &[u8],
    available_from: u64,
    requested_after: u64,
    out: &ReadOut,
) -> bool {
    let mut events = out.events.iter().peekable();
    let mut pos = requested_after;
    let mut saw_gap = false;
    let must_gap = requested_after < available_from;
    if let Some(ReplayEvent::Gap {
        requested_after: ra,
        available_from: af,
    }) = events.peek()
    {
        assert_eq!(
            *ra, requested_after,
            "Gap.requested_after must equal what was asked"
        );
        if must_gap {
            assert_eq!(
                *af, available_from,
                "a below-retention Gap must resync exactly to available_from"
            );
        } else {
            assert_eq!(
                *af, requested_after,
                "a Gap while already at/after available_from must be the \
                 same-offset control-overflow case (ring.rs:439-455)"
            );
        }
        pos = *af;
        saw_gap = true;
        events.next();
    } else {
        assert!(
            !must_gap,
            "requested_after={requested_after} < available_from={available_from} \
             but no leading Gap was returned"
        );
    }
    for ev in events {
        match ev {
            ReplayEvent::Output { sequence, data } => {
                let start = pos as usize;
                let end = start + data.len();
                assert!(
                    end <= model_stream.len(),
                    "read past the model's own stream end: {end} > {}",
                    model_stream.len()
                );
                assert_eq!(
                    &data[..],
                    &model_stream[start..end],
                    "byte-identity mismatch at offset {pos}"
                );
                pos += data.len() as u64;
                assert_eq!(
                    *sequence, pos,
                    "Output.sequence must equal the running offset after the chunk"
                );
            }
            ReplayEvent::Gap { .. } => panic!("unexpected second Gap in one read"),
            ReplayEvent::Control { .. } => {}
        }
    }
    saw_gap
}

/// Control-id half of the `ReadFollow` oracle: ids strictly increasing,
/// every one present in the model's own history (never forged), and — a
/// `Gap` aside — contiguous (no silent loss). See the module doc.
fn check_follow_controls(model: &mut ModelSession, out: &ReadOut, saw_gap: bool) {
    if saw_gap {
        model.got_start = None;
    }
    for ev in &out.events {
        if let ReplayEvent::Control {
            sequence, ctl_id, ..
        } = ev
        {
            assert!(
                model.ctl.contains(&(*sequence, *ctl_id)),
                "ReadFollow surfaced control id {ctl_id}@{sequence} the model never pushed"
            );
            match model.got_start {
                Some(expect) => assert_eq!(
                    *ctl_id, expect,
                    "control id skipped without an accompanying Gap"
                ),
                None => {
                    // Re-arming after a `Gap`: the resync point may skip
                    // ahead, but never back to or below an id already
                    // delivered. A gap licenses losing controls, not
                    // replaying or reordering them.
                    if let Some(last) = model.last_ctl_seen {
                        assert!(
                            *ctl_id > last,
                            "the first control id after a Gap ({ctl_id}) is not past the last \
                             id already delivered ({last})"
                        );
                    }
                }
            }
            model.got_start = Some(ctl_id + 1);
            model.last_ctl_seen = Some(*ctl_id);
        }
    }
}

/// Forgery half of the control oracle for the stateless readers: whatever
/// `(sequence, ctl_id)` pairs a `ReadAt` surfaces must be pairs this model
/// actually pushed. Ordering and contiguity stay out of scope for an
/// offset cursor (`ring.rs:44-48`), invention never does.
fn check_control_provenance(model: &ModelSession, out: &ReadOut) {
    for ev in &out.events {
        if let ReplayEvent::Control {
            sequence, ctl_id, ..
        } = ev
        {
            assert!(
                model.ctl.contains(&(*sequence, *ctl_id)),
                "ReadAt surfaced control id {ctl_id}@{sequence} the model never pushed"
            );
        }
    }
}

/// Whether the ring still holds everything ever pushed into it: no output
/// chunk evicted (`available_from` still at 0) and the full charge still
/// counted (every byte plus `CONTROL_ENTRY_COST` per control). Only under
/// that condition does `model.ctl` describe the ring's *live* controls
/// exactly, which is what [`check_ctl_after`]'s third clause needs — the
/// model deliberately does not track ring-side control eviction.
fn all_entries_live(ring: &ReplayRing, model: &ModelSession) -> bool {
    ring.available_from() == 0
        && ring.retained() == model.stream.len() + CONTROL_ENTRY_COST * model.ctl.len()
}

/// `ctl_after` half of the read oracle, shared by both readers: the cursor
/// a read hands back never moves backwards, always covers the ids that
/// read delivered, and — while nothing has been evicted — always covers
/// the ids positioned before the offset the read started from
/// (`ring.rs:484-490`). Dropping that last tightening is invisible to a
/// cursor that only ever moves forward, and shows up the moment a second
/// reader starts from an earlier offset and is handed those ids again.
fn check_ctl_after(
    model: &ModelSession,
    prev_ctl_after: u64,
    start_from: u64,
    out: &ReadOut,
    all_live: bool,
) {
    assert!(
        out.next.ctl_after >= prev_ctl_after,
        "next.ctl_after={} moved back behind the cursor it was read with ({prev_ctl_after})",
        out.next.ctl_after
    );
    for ev in &out.events {
        if let ReplayEvent::Control { ctl_id, .. } = ev {
            assert!(
                out.next.ctl_after >= *ctl_id,
                "next.ctl_after={} does not cover control id {ctl_id} this read delivered",
                out.next.ctl_after
            );
        }
    }
    // No `let`-chain here: this file also compiles as part of the `fuzz`
    // crate, which is on edition 2021.
    if all_live {
        let owed = model
            .ctl
            .iter()
            .filter(|(seq, _)| *seq < start_from)
            .map(|(_, id)| *id)
            .max();
        if let Some(owed) = owed {
            assert!(
                out.next.ctl_after >= owed,
                "next.ctl_after={} does not cover control id {owed}, which sits before this \
                 read's start offset {start_from} and is still in the ring",
                out.next.ctl_after
            );
        }
    }
}

/// Ring-side invariants that must hold after any op that touched this
/// slot's ring (`NewSession`/`Append`/`AppendControl`). See the module
/// doc's "memory" oracle row for the rationale behind each check.
fn assert_ring_invariants(ring: &ReplayRing, model: &ModelSession, budget: usize) {
    assert_eq!(
        ring.end(),
        model.stream.len() as u64,
        "ring.end() must track the model's cumulative output offset"
    );
    let entry_count = ring.entry_count();
    let retained = ring.retained();
    assert!(
        entry_count == 1 || retained <= budget,
        "retained={retained} over budget={budget} with entry_count={entry_count}"
    );
    let chunk_max = ring.chunk_max();
    let expected_chunk_max = model_chunk_max(budget);
    assert_eq!(
        chunk_max, expected_chunk_max,
        "chunk_max must stay fixed at what `new` computed from the budget"
    );
    // Entry-count bound, derived from what can still be live rather than
    // from the budget. Every live entry starts at or after `available_from`
    // (`ring.rs:409-417` reads it off the oldest retained output), so:
    //
    // - a live output chunk holds only bytes at or past `available_from`,
    //   hence the `Append` that created it ended past `available_from`;
    //   and one `Append` of `len` bytes creates at most
    //   `len.div_ceil(chunk_max)` chunks, since `append_output`
    //   (`ring.rs:363-378`) tops up the tail chunk first and then takes
    //   `chunk_max` bytes at a time;
    // - a live control was pushed at or after `available_from`, because
    //   eviction drops the ones strictly behind it (`ring.rs:348-357`)
    //   every time `available_from` moves.
    //
    // Both are upper bounds — nothing here claims an entry *is* live — so
    // the check stays sound while the ring is free to evict more.
    let available_from = ring.available_from();
    let all_chunks = model.appends.last().map_or(0, |(_, cum)| *cum);
    let past = model
        .appends
        .partition_point(|(end, _)| *end <= available_from);
    let dead_chunks = if past == 0 {
        0
    } else {
        model.appends[past - 1].1
    };
    let live_ctl = model
        .ctl
        .iter()
        .filter(|(seq, _)| *seq >= available_from)
        .count();
    let bound = live_ctl + (all_chunks - dead_chunks);
    assert!(
        entry_count <= bound,
        "entry_count={entry_count} exceeds {bound} = {live_ctl} controls at/after \
         available_from={available_from} + {} chunks from the appends that reach past it",
        all_chunks - dead_chunks
    );
}

/// A little-endian byte reader that stops (returns `None`) rather than
/// panicking once the input runs out; `take` is the one exception, used
/// only for `Append`'s payload, which is allowed to run short and is
/// padded by the caller instead of aborting the op.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let a = self.u8()?;
        let b = self.u8()?;
        Some(u16::from_le_bytes([a, b]))
    }

    /// Up to `n` raw bytes — fewer once the input is exhausted, never
    /// `None`. Once this returns short, every later read on this `Reader`
    /// also comes back empty/`None` (the input truly ran out).
    fn take(&mut self, n: usize) -> &'a [u8] {
        let end = (self.pos + n).min(self.data.len());
        let s = &self.data[self.pos..end];
        self.pos = end;
        s
    }
}

/// Decode and run one `broker_ops` input. Panics on any assertion failure
/// or oracle mismatch — a panic is a finding, same convention as every
/// other fuzz target in this workspace.
pub fn run(input: &[u8]) {
    let clock = TestClock::new();
    let registry = ResumeRegistry::new(Arc::new(clock.clone()));
    let mut slots: [Option<Slot>; SLOTS as usize] = [const { None }; SLOTS as usize];
    let mut r = Reader::new(input);

    for _ in 0..MAX_OPS {
        let Some(opcode_raw) = r.u8() else {
            break;
        };
        let opcode = opcode_raw % N_OPS;

        match opcode {
            0 => {
                // NewSession
                let Some(sess) = r.u8() else { break };
                let Some(budget_raw) = r.u16() else { break };
                let slot_idx = (sess % SLOTS) as usize;
                let budget = 1 + (budget_raw as usize % 8192);
                if slots[slot_idx].take().is_some() {
                    registry.forget(&session_id(slot_idx as u8));
                }
                let ring = ReplayRing::new(budget);
                assert_eq!(ring.end(), 0, "a fresh ring must start at offset 0");
                let now = clock.now();
                let model = ModelSession::new(now);
                assert_ring_invariants(&ring, &model, budget);
                slots[slot_idx] = Some(Slot {
                    ring,
                    lease: WriterLease::new(),
                    budget,
                    model,
                });
            }
            1 => {
                // Append
                let Some(sess) = r.u8() else { break };
                let Some(len_raw) = r.u16() else { break };
                let idx = (sess % SLOTS) as usize;
                let len_val = (len_raw as usize) % 1024;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let base = slot.model.stream.len();
                let raw = r.take(len_val);
                let mut buf = raw.to_vec();
                for i in buf.len()..len_val {
                    buf.push(((base + i) as u8) ^ 0x5A);
                }
                let seq = slot.ring.push(&buf);
                slot.model.stream.extend_from_slice(&buf);
                let chunks = buf.len().div_ceil(model_chunk_max(slot.budget));
                let cum = slot.model.appends.last().map_or(0, |(_, c)| *c) + chunks;
                slot.model
                    .appends
                    .push((slot.model.stream.len() as u64, cum));
                assert_eq!(
                    seq,
                    slot.model.stream.len() as u64,
                    "push() must return the new cumulative end offset"
                );
                assert_ring_invariants(&slot.ring, &slot.model, slot.budget);
            }
            2 => {
                // AppendControl
                let Some(sess) = r.u8() else { break };
                let Some(kind_raw) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let event = match kind_raw % 3 {
                    0 => ControlEvent::Exit {
                        exit_code: None,
                        signal: None,
                    },
                    1 => ControlEvent::WriterChanged { writer: None },
                    _ => ControlEvent::Closed {
                        reason: CloseReason::Closed,
                    },
                };
                let expected_seq = slot.model.stream.len() as u64;
                let expected_id = slot.model.ctl.len() as u64 + 1;
                let (seq, id) = slot.ring.push_control(event);
                assert_eq!(
                    seq, expected_seq,
                    "push_control's seq must be the current end offset"
                );
                assert_eq!(
                    id, expected_id,
                    "control ids must be 1-based and sequential"
                );
                slot.model.ctl.push((seq, id));
                assert_ring_invariants(&slot.ring, &slot.model, slot.budget);
            }
            3 => {
                // ReadAt
                let Some(sess) = r.u8() else { break };
                let Some(frac) = r.u8() else { break };
                let Some(max_raw) = r.u16() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let end = slot.ring.end();
                let after = ((end as u128) * (frac as u128) / 255) as u64;
                let max_val = (max_raw as usize) % 4096;
                let available_from = slot.ring.available_from();
                let all_live = all_entries_live(&slot.ring, &slot.model);
                let out = slot
                    .ring
                    .read(Cursor::from_offset(after), max_val)
                    .expect("ReadAt: after <= end by construction, must not error");
                check_read_bytes(&slot.model.stream, available_from, after, &out);
                check_control_provenance(&slot.model, &out);
                // A stateless cursor starts with `ctl_after == 0`
                // (`Cursor::from_offset`), so every control before the
                // read's start offset has to be folded in by the read
                // itself.
                check_ctl_after(&slot.model, 0, after.max(available_from), &out, all_live);
            }
            4 => {
                // ReadBeyond
                let Some(sess) = r.u8() else { break };
                let Some(over) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let end = slot.ring.end();
                let after = end + 1 + (over as u64 % 64);
                let result = slot.ring.read(Cursor::from_offset(after), 4096);
                assert_eq!(result, Err(ReadError::CursorBeyondEnd { after, end }));
            }
            5 => {
                // ReadFollow
                let Some(sess) = r.u8() else { break };
                let Some(max_raw) = r.u16() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let max_val = (max_raw as usize) % 4096;
                let requested_after = slot.model.got.after;
                let prev_ctl_after = slot.model.got.ctl_after;
                let available_from = slot.ring.available_from();
                let all_live = all_entries_live(&slot.ring, &slot.model);
                let out = slot
                    .ring
                    .read(slot.model.got, max_val)
                    .expect("ReadFollow's cursor only ever grows from a prior read's `next`");
                let saw_gap =
                    check_read_bytes(&slot.model.stream, available_from, requested_after, &out);
                check_follow_controls(&mut slot.model, &out, saw_gap);
                check_ctl_after(
                    &slot.model,
                    prev_ctl_after,
                    requested_after.max(available_from),
                    &out,
                    all_live,
                );
                assert!(
                    out.next.after >= requested_after,
                    "ReadFollow's cursor must never move backwards"
                );
                slot.model.got = out.next;
            }
            6 => {
                // TakeLease
                let Some(sess) = r.u8() else { break };
                let Some(principal_raw) = r.u8() else {
                    break;
                };
                let Some(owner_raw) = r.u8() else { break };
                let Some(physical_raw) = r.u8() else {
                    break;
                };
                let Some(flags) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let principal = format!("p{}", principal_raw % IDENTITY_MOD);
                let owner = ConnectionId((owner_raw % IDENTITY_MOD) as u64);
                let use_take_owned = flags & 2 != 0;
                let no_steal = flags & 1 != 0;
                let (eff_owner, eff_physical) = if use_take_owned {
                    (owner, ConnectionId((physical_raw % IDENTITY_MOD) as u64))
                } else {
                    (owner, owner)
                };
                let outcome = if use_take_owned {
                    slot.lease
                        .take_owned(&principal, eff_owner, eff_physical, no_steal)
                } else {
                    slot.lease.take(&principal, eff_owner, no_steal)
                };
                let predicted = match &slot.model.lease {
                    Some((_, o, _)) if *o == eff_owner => TakeOutcome::Acquired {
                        displaced: None,
                        changed: false,
                    },
                    Some((p, o, ph)) if no_steal && *p != principal => TakeOutcome::Conflict {
                        holder: LeaseHolder {
                            principal: p.clone(),
                            conn: *o,
                            physical: *ph,
                        },
                    },
                    Some((p, o, ph)) => TakeOutcome::Acquired {
                        displaced: Some(LeaseHolder {
                            principal: p.clone(),
                            conn: *o,
                            physical: *ph,
                        }),
                        changed: *o != eff_owner,
                    },
                    None => TakeOutcome::Acquired {
                        displaced: None,
                        changed: true,
                    },
                };
                assert_eq!(
                    outcome, predicted,
                    "TakeLease outcome diverged from the model"
                );
                // `lease.rs:140-144`'s first arm (`h.conn == owner`) returns
                // `Acquired { changed: false, .. }` *without* touching
                // `self.holder` at all — a same-owner re-acquire is a pure
                // no-op, including on `physical`, even when this call's
                // `eff_physical` differs from what the holder was first
                // taken with. Updating the model unconditionally here was
                // the model tracking the *call's* physical instead of the
                // *lease's* physical, and diverged from `holder()` the
                // moment a fuzzed input re-acquired the same owner with a
                // different physical byte.
                if let TakeOutcome::Acquired { changed: true, .. } = &outcome {
                    slot.model.lease = Some((principal, eff_owner, eff_physical));
                }
                let expected_holder = slot.model.lease.as_ref().map(|(p, o, ph)| LeaseHolder {
                    principal: p.clone(),
                    conn: *o,
                    physical: *ph,
                });
                assert_eq!(
                    slot.lease.holder().cloned(),
                    expected_holder,
                    "holder() diverged from the model"
                );
                for c in 0..(IDENTITY_MOD as u64) {
                    let conn = ConnectionId(c);
                    let expect_held = slot
                        .model
                        .lease
                        .as_ref()
                        .is_some_and(|(_, o, _)| *o == conn);
                    assert_eq!(
                        slot.lease.is_held_by(conn),
                        expect_held,
                        "is_held_by({c}) diverged from the model"
                    );
                }
            }
            7 => {
                // DropConnection
                let Some(conn_raw) = r.u8() else { break };
                let conn = ConnectionId((conn_raw % IDENTITY_MOD) as u64);
                for slot_opt in slots.iter_mut() {
                    let Some(slot) = slot_opt else { continue };
                    let expected = slot.model.lease.as_ref().and_then(|(p, o, ph)| {
                        (*ph == conn).then(|| LeaseHolder {
                            principal: p.clone(),
                            conn: *o,
                            physical: *ph,
                        })
                    });
                    let released = slot.lease.release_connection(conn);
                    assert_eq!(
                        released, expected,
                        "release_connection diverged from the model"
                    );
                    if released.is_some() {
                        slot.model.lease = None;
                        assert!(slot.lease.holder().is_none());
                    }
                }
            }
            8 => {
                // Attach
                let Some(sess) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                slot.model.attached += 1;
            }
            9 => {
                // Detach
                let Some(sess) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                slot.model.attached = slot.model.attached.saturating_sub(1);
                if slot.model.attached == 0 {
                    slot.model.ttl_base = clock.now();
                }
            }
            10 => {
                // SetExited
                let Some(sess) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                slot.model.state = SessionState::Exited;
                slot.model.ttl_base = clock.now();
            }
            11 => {
                // SetClosing
                let Some(sess) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                slot.model.closing = true;
            }
            12 => {
                // IssueResume
                let Some(sess) = r.u8() else { break };
                let Some(peer) = r.u8() else { break };
                let Some(ttl_raw) = r.u16() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let ttl = Duration::from_millis(1 + (ttl_raw as u64 % 60_000));
                let id = session_id(idx as u8);
                let now = clock.now();
                let token = registry.issue(&id, PeerFingerprint::new([peer; 32]), ttl);
                assert_eq!(
                    registry.verify(&id, token.expose(), PeerFingerprint::new([peer; 32])),
                    Ok(FIRST_INPUT_STREAM),
                    "a freshly issued token must verify at FIRST_INPUT_STREAM"
                );
                if let Some(old) = slot.model.live_token.take() {
                    slot.model.spent.push(old);
                }
                slot.model.live_token = Some(token.expose().to_vec());
                slot.model.peer = peer;
                slot.model.axis = FIRST_INPUT_STREAM;
                slot.model.expires_at = now + ttl;
            }
            13 => {
                // VerifyResume
                let Some(sess) = r.u8() else { break };
                let Some(tokref) = r.u8() else { break };
                let Some(peer) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let kind = tokref >> 6;
                if kind == 1 && slot.model.spent.is_empty() {
                    // Nothing has been superseded in this slot yet, so
                    // there is no dead generation to present. The op
                    // consumes its arguments and does nothing: a stand-in
                    // would only re-test "unknown bytes are denied", which
                    // kinds 2 and 3 already own, and would let a registry
                    // that kept honouring superseded tokens pass this row.
                    continue;
                }
                let id = session_id(idx as u8);
                let now = clock.now();
                let presented = presented_bytes(&slot.model, kind, tokref & 63);
                let len_before = registry.len();
                let result = registry.verify(&id, &presented, PeerFingerprint::new([peer; 32]));
                let predicted = predict_verify(&slot.model, now, kind, peer);
                assert_eq!(result, predicted, "verify diverged from the model");
                assert_eq!(
                    registry.len(),
                    len_before,
                    "verify must never mutate the registry"
                );
            }
            14 => {
                // RotateResume
                let Some(sess) = r.u8() else { break };
                let Some(tokref) = r.u8() else { break };
                let Some(peer) = r.u8() else { break };
                let Some(ttl_raw) = r.u16() else { break };
                let Some(axis_raw) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let kind = tokref >> 6;
                if kind == 1 && slot.model.spent.is_empty() {
                    // Same no-op as `VerifyResume`'s: kind 1 always
                    // presents a real superseded generation or nothing.
                    continue;
                }
                let id = session_id(idx as u8);
                let now = clock.now();
                let presented = presented_bytes(&slot.model, kind, tokref & 63);
                let ttl = Duration::from_millis(1 + (ttl_raw as u64 % 60_000));
                let axis = InputStreamId(1 + axis_raw as u64);
                let len_before = registry.len();
                let predicted_ok = predict_verify(&slot.model, now, kind, peer).is_ok();
                let result =
                    registry.rotate(&id, &presented, PeerFingerprint::new([peer; 32]), ttl, axis);
                match result {
                    Ok(new_token) => {
                        assert!(
                            predicted_ok,
                            "rotate succeeded but the model predicted denial"
                        );
                        let old = slot
                            .model
                            .live_token
                            .take()
                            .expect("predict_verify(Live) only succeeds with a live token");
                        let new_bytes = new_token.expose().to_vec();
                        assert_eq!(
                            registry.verify(&id, &new_bytes, PeerFingerprint::new([peer; 32])),
                            Ok(axis),
                            "the new token must verify at the rotated-to axis"
                        );
                        assert_eq!(
                            registry.verify(&id, &old, PeerFingerprint::new([peer; 32])),
                            Err(ResumeDenied),
                            "the rotated-away token must be spent"
                        );
                        slot.model.spent.push(old);
                        slot.model.live_token = Some(new_bytes);
                        slot.model.peer = peer;
                        slot.model.axis = axis;
                        slot.model.expires_at = now + ttl;
                        assert_eq!(
                            registry.len(),
                            len_before,
                            "a successful rotate replaces one entry, never adds"
                        );
                    }
                    Err(_) => {
                        assert!(
                            !predicted_ok,
                            "rotate denied but the model predicted success"
                        );
                        assert_eq!(
                            registry.len(),
                            len_before,
                            "a denied rotate must not touch the registry"
                        );
                        if let Some(live) = &slot.model.live_token {
                            let expect = if now < slot.model.expires_at {
                                Ok(slot.model.axis)
                            } else {
                                Err(ResumeDenied)
                            };
                            assert_eq!(
                                registry.verify(
                                    &id,
                                    live,
                                    PeerFingerprint::new([slot.model.peer; 32])
                                ),
                                expect,
                                "a denied rotate must leave the stored credential/axis untouched"
                            );
                        }
                    }
                }
            }
            15 => {
                // ForgetResume
                let Some(sess) = r.u8() else { break };
                let idx = (sess % SLOTS) as usize;
                let Some(slot) = slots[idx].as_mut() else {
                    continue;
                };
                let id = session_id(idx as u8);
                registry.forget(&id);
                if let Some(old) = slot.model.live_token.take() {
                    assert_eq!(
                        registry.verify(&id, &old, PeerFingerprint::new([slot.model.peer; 32])),
                        Err(ResumeDenied),
                        "a forgotten session's token must be denied"
                    );
                }
                registry.forget(&id); // idempotent
            }
            16 => {
                // TickSmall
                let Some(ms) = r.u8() else { break };
                clock.advance(Duration::from_millis(1 + ms as u64));
            }
            17 => {
                // TickLarge
                let Some(ms) = r.u16() else { break };
                clock.advance(Duration::from_millis(1 + ms as u64));
            }
            18 => {
                // Reap — the registry half of a reaper pass (`broker/mod.rs:830-891`):
                // judge, build the deadline map (survivors only — the shape
                // of a pass whose doomed session already left the registry),
                // `sync_expiry`, then `purge_expired` (harness-only, see the
                // op table), then close and forget.
                let now = clock.now();
                let mut doomed = [false; SLOTS as usize];
                let mut predicted_deadlines = [None::<Instant>; SLOTS as usize];
                let mut deadlines: HashMap<SessionId, Instant> = HashMap::new();
                for (i, slot_opt) in slots.iter().enumerate() {
                    let Some(slot) = slot_opt else { continue };
                    let window = slot.model.ttl_window();
                    let real_reason = window.reap_reason(now, SESSION_TTL);
                    let predicted_reason = predict_reap_reason(&slot.model, now, SESSION_TTL);
                    assert_eq!(
                        real_reason, predicted_reason,
                        "TtlWindow::reap_reason diverged from the independent model"
                    );
                    let real_deadline = window.deadline(now, SESSION_TTL);
                    let predicted_deadline = predict_deadline(&slot.model, now, SESSION_TTL);
                    assert_eq!(
                        real_deadline, predicted_deadline,
                        "TtlWindow::deadline diverged from the independent model"
                    );
                    predicted_deadlines[i] = Some(predicted_deadline);
                    doomed[i] = predicted_reason.is_some();
                    if !doomed[i] {
                        // Only the survivors are re-anchored. A session
                        // this pass is about to close falls through to
                        // `sync_expiry`'s `None` arm instead, the arm a
                        // real pass reaches once the session has left the
                        // session registry.
                        deadlines.insert(session_id(i as u8), predicted_deadline);
                    }
                }
                registry.sync_expiry(&deadlines);
                registry.purge_expired();
                let mut expected_len = 0usize;
                for (i, slot_opt) in slots.iter_mut().enumerate() {
                    let Some(slot) = slot_opt else { continue };
                    if slot.model.live_token.is_none() {
                        continue;
                    }
                    let survives = if doomed[i] {
                        // `resume.rs:344`: no deadline for this id, so the
                        // credential keeps its own expiry and lives only
                        // while it is strictly ahead of `now` — the same
                        // inequality `purge_expired` (`resume.rs:324`) and
                        // `verify`'s freshness bit (`resume.rs:260`) use.
                        slot.model.expires_at > now
                    } else {
                        let deadline =
                            predicted_deadlines[i].expect("every occupied slot was measured");
                        slot.model.expires_at = deadline;
                        deadline > now
                    };
                    if survives {
                        expected_len += 1;
                    } else {
                        slot.model.live_token = None;
                    }
                }
                assert_eq!(
                    registry.len(),
                    expected_len,
                    "resume registry length diverged from the model after sync_expiry + \
                     purge_expired"
                );
                for (i, slot_opt) in slots.iter_mut().enumerate() {
                    if !doomed[i] {
                        continue;
                    }
                    registry.forget(&session_id(i as u8));
                    *slot_opt = None;
                }
                let expected_after = slots
                    .iter()
                    .filter_map(|s| s.as_ref())
                    .filter(|s| s.model.live_token.is_some())
                    .count();
                assert_eq!(
                    registry.len(),
                    expected_after,
                    "forgetting the reaped sessions left credentials behind"
                );
            }
            _ => unreachable!("opcode is reduced modulo N_OPS"),
        }
    }
}
