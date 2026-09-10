//! Regression replay for the `broker_ops` stateful fuzz target
//! (`fuzz/fuzz_targets/broker_ops.rs`): every corpus seed under
//! `fuzz/corpus/broker_ops/` runs twice through the same harness the fuzz
//! target uses, so (a) the seeds stay green in plain `cargo nextest` on
//! every platform CI runs on, whether or not `cargo fuzz` itself is
//! available there, and (b) the harness's own decode-and-replay path is
//! deterministic — two runs of the same bytes must behave identically
//! (both clean, or both panicking at the same assertion).
//!
//! `regenerate_seeds` (below, `#[ignore]`) is how the fifteen seed files are
//! produced: named, human-readable op sequences built from the same
//! opcode table `support/broker_ops_harness.rs`'s module doc documents. It
//! only writes when `BROKER_OPS_WRITE_SEEDS=1` is set, so an ordinary test
//! run never touches the corpus.
//!
//! The replay also guards the corpus's shape: every file must carry a
//! `^[a-z0-9_]+$` name and none may carry libFuzzer's 40-hex-digit sha1
//! name. `cargo fuzz run` writes every input it keeps back into the corpus
//! directory it was pointed at, and a run pointed at this one buries the
//! curated seeds under hundreds of machine-named files. `.gitignore` has
//! no way to express "hex names only", so this test is the guard: a
//! polluted corpus turns `cargo nextest run --workspace` red instead of
//! quietly arriving in a commit.

#[path = "support/broker_ops_harness.rs"]
mod harness;

use std::fs;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/broker_ops")
}

#[test]
fn replays_every_seed_deterministically() {
    let dir = corpus_dir();
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read corpus dir {}: {e}", dir.display()))
        .map(|e| e.expect("readable dir entry").path())
        .filter(|p| p.is_file())
        .collect();
    // Replay order is filesystem order otherwise, so "which seed blew up
    // first" would differ per machine.
    entries.sort();
    assert!(
        !entries.is_empty(),
        "fuzz/corpus/broker_ops/ has no seeds — a missing/emptied corpus \
         directory must fail this test loudly, not pass green having \
         checked nothing"
    );
    for path in &entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_else(|| panic!("corpus entry {} has no usable name", path.display()));
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "corpus file {name:?} is not a named seed (`^[a-z0-9_]+$`): a fuzz run grew the \
             checked-in corpus; delete the hex-named files (fuzz/README.md's \"corpus\" \
             section) — this directory holds only what `regenerate_seeds` writes"
        );
        assert!(
            !(name.len() == 40 && name.bytes().all(|b| b.is_ascii_hexdigit())),
            "corpus file {name:?} carries libFuzzer's sha1 name: a fuzz run grew the checked-in \
             corpus; delete the hex-named files (fuzz/README.md's \"corpus\" section) — this \
             directory holds only what `regenerate_seeds` writes"
        );
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        harness::run(&bytes);
        harness::run(&bytes); // determinism: replaying the same bytes twice must agree
    }
}

// --- op encoding -----------------------------------------------------------
//
// One free function per opcode, byte-exact per `support/broker_ops_harness.rs`'s
// module doc table (opcode byte, then that op's fixed args, little-endian).
// Each seed below composes these by name, so its intent reads as a sequence
// of calls rather than a hex dump.

fn op_new_session(sess: u8, budget: u16) -> Vec<u8> {
    let mut v = vec![0, sess];
    v.extend_from_slice(&budget.to_le_bytes());
    v
}

fn op_append(sess: u8, len: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![1, sess];
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn op_append_control(sess: u8, kind: u8) -> Vec<u8> {
    vec![2, sess, kind]
}

fn op_read_at(sess: u8, frac: u8, max: u16) -> Vec<u8> {
    let mut v = vec![3, sess, frac];
    v.extend_from_slice(&max.to_le_bytes());
    v
}

fn op_read_beyond(sess: u8, over: u8) -> Vec<u8> {
    vec![4, sess, over]
}

fn op_read_follow(sess: u8, max: u16) -> Vec<u8> {
    let mut v = vec![5, sess];
    v.extend_from_slice(&max.to_le_bytes());
    v
}

fn op_take_lease(sess: u8, principal: u8, owner: u8, physical: u8, flags: u8) -> Vec<u8> {
    vec![6, sess, principal, owner, physical, flags]
}

fn op_drop_connection(conn: u8) -> Vec<u8> {
    vec![7, conn]
}

fn op_attach(sess: u8) -> Vec<u8> {
    vec![8, sess]
}

fn op_detach(sess: u8) -> Vec<u8> {
    vec![9, sess]
}

fn op_set_exited(sess: u8) -> Vec<u8> {
    vec![10, sess]
}

fn op_set_closing(sess: u8) -> Vec<u8> {
    vec![11, sess]
}

fn op_issue_resume(sess: u8, peer: u8, ttl: u16) -> Vec<u8> {
    let mut v = vec![12, sess, peer];
    v.extend_from_slice(&ttl.to_le_bytes());
    v
}

fn op_verify_resume(sess: u8, tokref: u8, peer: u8) -> Vec<u8> {
    vec![13, sess, tokref, peer]
}

fn op_rotate_resume(sess: u8, tokref: u8, peer: u8, ttl: u16, axis: u8) -> Vec<u8> {
    let mut v = vec![14, sess, tokref, peer];
    v.extend_from_slice(&ttl.to_le_bytes());
    v.push(axis);
    v
}

fn op_forget_resume(sess: u8) -> Vec<u8> {
    vec![15, sess]
}

fn op_tick_small(ms: u8) -> Vec<u8> {
    vec![16, ms]
}

fn op_tick_large(ms: u16) -> Vec<u8> {
    let mut v = vec![17];
    v.extend_from_slice(&ms.to_le_bytes());
    v
}

fn op_reap() -> Vec<u8> {
    vec![18]
}

/// `tokref`'s top 2 bits select the presented token's kind (0 Live / 1
/// Spent / 2 Garbage / 3 Truncated); the low 6 bits are the `Spent`/
/// `Garbage`/`Truncated` index byte (`VerifyResume`'s row in
/// `support/broker_ops_harness.rs`'s module doc).
fn tokref(kind: u8, idx: u8) -> u8 {
    (kind << 6) | (idx & 63)
}

// --- seeds -------------------------------------------------------------

/// ① Lease three-phase: fresh acquire, steal by a different connection,
/// then a `no_steal` take from yet another principal conflicts with the
/// steal's holder.
fn seed_lease_three_phase() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(0, 8000));
    b.extend(op_take_lease(0, 0, 0, 0, 0b00)); // p0 on conn0/phys0: free lease, plain acquire
    b.extend(op_take_lease(0, 1, 1, 1, 0b00)); // p1 on conn1/phys1: steals from p0
    b.extend(op_take_lease(0, 2, 2, 2, 0b01)); // no_steal, p2 != holder p1: Conflict
    b
}

/// ② `DropConnection` auto-releases a lease bound to that physical
/// connection (and only that one), then a session's own exit/TTL/closing
/// rules: an exited, unattached session reaps as `Exit` once past TTL, but
/// `closing` suppresses that even further past TTL.
fn seed_drop_connection_and_exit_ttl() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(1, 8000));
    b.extend(op_take_lease(1, 0, 0, 0, 0b00)); // p0 on conn0/phys0
    b.extend(op_drop_connection(0)); // releases it
    b.extend(op_take_lease(1, 1, 1, 1, 0b00)); // freely re-acquired: it really was released
    b.extend(op_set_exited(1));
    b.extend(op_tick_large(11_000)); // > SESSION_TTL, never attached
    b.extend(op_reap()); // reap_reason == Some(Exit): closes and empties the slot
    b.extend(op_set_closing(1)); // no-op: the slot the first Reap closed is empty
    b.extend(op_tick_large(11_000)); // no-op tick; nothing left in this slot to expire
    b.extend(op_reap()); // no-op: empty slot — the closing-suppresses-reap axis is seed 15
    b
}

/// ③ A small ring budget plus many appends past it, so a fresh
/// `ReadFollow` (cursor still at 0) must resync through a `Gap`; a control
/// pushed right after (sitting at the retained end) must still surface
/// correctly once the gap is past.
fn seed_small_budget_gap_then_follow() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(2, 64)); // budget = 1 + 64 = 65
    for i in 0..20u8 {
        let payload: Vec<u8> = (0..50u8).map(|j| i.wrapping_add(j)).collect();
        b.extend(op_append(2, 50, &payload));
    }
    b.extend(op_append_control(2, 1)); // WriterChanged, at the (retained) tail
    b.extend(op_read_follow(2, 4096));
    b
}

/// ④ Pure control-entry overflow (no output ever pushed, so `end` stays 0
/// throughout): once a control is force-evicted, a `ReadFollow` from the
/// start must see a same-offset `Gap` (`ring.rs:439-455`) rather than a
/// silently skipped control id.
fn seed_control_only_overflow_gap() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(3, 63)); // budget = 1 + 63 = 64 == CONTROL_ENTRY_COST
    for kind in [0u8, 1, 2, 0, 1, 2] {
        b.extend(op_append_control(3, kind));
    }
    b.extend(op_read_follow(3, 4096));
    b
}

/// ⑤ `issue` → `verify` → `rotate(axis=3)` → `verify` at the new axis →
/// the just-spent token is rejected on replay → forgetting denies the
/// (now-current) token too.
fn seed_resume_rotate_axis_and_reject_replay() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(0, 8000));
    b.extend(op_issue_resume(0, 7, 5000));
    b.extend(op_verify_resume(0, tokref(0, 0), 7)); // Live: still verifies
    b.extend(op_rotate_resume(0, tokref(0, 0), 7, 5000, 3)); // -> InputStreamId(4)
    b.extend(op_verify_resume(0, tokref(0, 0), 7)); // Live now means the new token: Ok(axis 4)
    b.extend(op_rotate_resume(0, tokref(1, 0), 7, 5000, 4)); // presenting the spent token: denied
    b.extend(op_forget_resume(0));
    b
}

/// ⑥ `issue` → `TickLarge` past the credential's own TTL → `verify` is
/// denied → `Reap` purges it from the registry.
fn seed_resume_ttl_expiry_then_reap_purges() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(1, 8000));
    b.extend(op_issue_resume(1, 3, 2000)); // ttl = 2001ms
    b.extend(op_tick_large(60_000)); // far past both the issue ttl and SESSION_TTL
    b.extend(op_verify_resume(1, tokref(0, 0), 3)); // denied: expired
    b.extend(op_reap()); // purged: registry.len() drops to 0 for this slot
    b
}

/// ⑦ `Attach` suspends the TTL through repeated large ticks and two
/// `Reap`s (the credential survives both); `Detach` restarts it, and a
/// further tick past `SESSION_TTL` makes the next `Reap` expire it.
fn seed_attach_survives_detach_then_expires() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(2, 8000));
    b.extend(op_issue_resume(2, 9, 500));
    b.extend(op_attach(2));
    b.extend(op_tick_small(50));
    b.extend(op_tick_large(40_000));
    b.extend(op_reap()); // attached > 0: survives regardless of elapsed time
    b.extend(op_tick_large(40_000));
    b.extend(op_reap()); // still attached: still survives
    b.extend(op_detach(2)); // ttl_base = now
    b.extend(op_tick_large(60_000)); // now unattached, far past SESSION_TTL
    b.extend(op_reap()); // expires: TtlExpired, credential purged
    b
}

/// ⑧ `ReadBeyond` against a session whose budget lands in the
/// `piece_max == 1` regime (`budget` in `1..=63`, P2-5's arbitration).
fn seed_read_beyond_tiny_budget() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(3, 30)); // budget = 1 + 30 = 31 => piece_max clamps to 1
    let payload = vec![0xAB; 10];
    b.extend(op_append(3, 10, &payload));
    b.extend(op_read_beyond(3, 5));
    b.extend(op_read_at(3, 128, 4096));
    b
}

/// ⑨ The reverse-route lease shape: `take_owned` with `owner` and
/// `physical` on different connections. Dropping the *owner* connection
/// must not release it, dropping the *physical* one must, and the lease is
/// freely re-acquirable afterwards. Every other seed takes the lease with
/// `owner == physical`, where the two are indistinguishable.
fn seed_lease_owned_split_physical() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(0, 8000));
    // take_owned: p1 asks on owner conn1, released by physical conn2.
    b.extend(op_take_lease(0, 1, 1, 2, 0b10));
    b.extend(op_drop_connection(1)); // the owner identity: not a release
    b.extend(op_drop_connection(2)); // the physical connection: releases
    b.extend(op_take_lease(0, 1, 1, 2, 0b10)); // free again, so it really was released
    b
}

/// ⑩ A credential expires on its own issue TTL with no `Reap` in the
/// sequence at all: rotate to a 2000ms TTL, verify just inside it, verify
/// exactly on the deadline (denied — `expires_at > now` is strict), verify
/// past it.
fn seed_rotate_then_expiry_without_reap() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(1, 8000));
    b.extend(op_issue_resume(1, 5, 999)); // ttl = 1000ms
    b.extend(op_rotate_resume(1, tokref(0, 0), 5, 1999, 2)); // ttl = 2000ms, axis 3
    b.extend(op_verify_resume(1, tokref(0, 0), 5)); // Ok(axis 3)
    b.extend(op_tick_large(1998)); // +1999ms: 1ms inside the deadline
    b.extend(op_verify_resume(1, tokref(0, 0), 5)); // still Ok
    b.extend(op_tick_small(0)); // +1ms: exactly on the deadline
    b.extend(op_verify_resume(1, tokref(0, 0), 5)); // denied
    b.extend(op_tick_small(0)); // +1ms: past it
    b.extend(op_verify_resume(1, tokref(0, 0), 5)); // still denied
    b
}

/// ⑪ `sync_expiry`'s `None` arm at its boundary: the session is doomed
/// (unattached, exactly `SESSION_TTL` past its `ttl_base`) but its
/// credential was issued for one millisecond longer, so the pass must
/// leave it alone — and then the reap's own `forget` takes it anyway.
fn seed_doomed_session_credential_outlives_by_1ms() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(2, 8000));
    b.extend(op_detach(2)); // ttl_base = t0
    b.extend(op_issue_resume(2, 1, 10_000)); // ttl = 10001ms, expires t0+10001
    b.extend(op_tick_large(9999)); // +10000ms: now == t0+10000
    b.extend(op_reap()); // doomed, credential survives by 1ms, then forgotten
    b.extend(op_new_session(2, 8000)); // the emptied slot is reusable
    b.extend(op_reap()); // and the registry stays at 0
    b
}

/// ⑫ A rotation refreshes the credential's expiry: without that refresh
/// the successor would inherit the superseded generation's deadline and be
/// purged by the reap this seed ends with.
fn seed_rotate_refreshes_expiry_before_doom() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(3, 8000));
    b.extend(op_detach(3)); // ttl_base = t0
    b.extend(op_issue_resume(3, 2, 4999)); // ttl = 5000ms, expires t0+5000
    b.extend(op_tick_large(2999)); // +3000ms
    b.extend(op_rotate_resume(3, tokref(0, 0), 2, 9999, 1)); // ttl = 10000ms, expires t0+13000
    b.extend(op_tick_large(6999)); // +7000ms: now == t0+10000, session doomed
    b.extend(op_reap()); // credential still 3000ms ahead: survives the purge
    b
}

/// ⑬ `ReadAt` over a stream with controls interleaved: the offset cursor
/// starts at `ctl_after == 0`, so a read that begins past a control has to
/// fold that control's id into the cursor it hands back instead of leaving
/// it to be replayed. The budget is far larger than the stream, so nothing
/// is ever evicted.
fn seed_read_at_surfaces_only_pushed_controls() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(0, 8000));
    let payload: Vec<u8> = (0..100u8).collect();
    b.extend(op_append(0, 100, &payload)); // 0..100
    b.extend(op_append_control(0, 0)); // ctl 1 @ 100
    b.extend(op_append(0, 100, &payload)); // 100..200
    b.extend(op_append_control(0, 1)); // ctl 2 @ 200
    b.extend(op_append(0, 100, &payload)); // 200..300
    b.extend(op_read_at(0, 255, 4096)); // from 300: both controls are behind it
    b.extend(op_read_at(0, 128, 4096)); // from 150: ctl 1 behind, ctl 2 delivered
    b.extend(op_read_at(0, 0, 4096)); // from 0: the whole stream, both controls
    b
}

/// ⑭ Three rotations, then each superseded generation is presented back in
/// turn. A registry that kept honouring a retired token would answer `Ok`
/// to one of these.
fn seed_spent_generations_stay_dead() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(0, 8000));
    b.extend(op_issue_resume(0, 4, 59_999)); // ttl = 60000ms, longer than the whole seed
    for axis in [1u8, 2, 3] {
        b.extend(op_tick_small(9)); // +10ms
        b.extend(op_rotate_resume(0, tokref(0, 0), 4, 59_999, axis));
    }
    b.extend(op_verify_resume(0, tokref(1, 0), 4)); // the issued generation: denied
    b.extend(op_verify_resume(0, tokref(1, 1), 4)); // the first successor: denied
    b.extend(op_verify_resume(0, tokref(1, 2), 4)); // the second: denied
    b.extend(op_verify_resume(0, tokref(0, 0), 4)); // the live one still verifies
    b
}

/// ⑮ `closing` suppresses reap even once the TTL is long past — the slot
/// must still be alive after a second `Reap`.
fn seed_closing_suppresses_reap() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(op_new_session(2, 8000));
    b.extend(op_set_closing(2)); // closing before the slot ever attaches
    b.extend(op_tick_large(11_000)); // > SESSION_TTL
    b.extend(op_reap()); // closing => reap_reason == None, slot survives
    b.extend(op_tick_large(11_000)); // further past TTL
    b.extend(op_reap()); // still closing => still None, slot must still be alive
    b
}

#[test]
#[ignore = "writes fuzz/corpus/broker_ops/*; run with BROKER_OPS_WRITE_SEEDS=1"]
fn regenerate_seeds() {
    if std::env::var("BROKER_OPS_WRITE_SEEDS").as_deref() != Ok("1") {
        eprintln!("skipping: set BROKER_OPS_WRITE_SEEDS=1 to (re)write fuzz/corpus/broker_ops/*");
        return;
    }
    let dir = corpus_dir();
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));

    type SeedBuilder = fn() -> Vec<u8>;
    let seeds: &[(&str, SeedBuilder)] = &[
        (
            "lease_three_phase_acquire_steal_conflict",
            seed_lease_three_phase,
        ),
        (
            "drop_connection_releases_lease_then_exit_ttl",
            seed_drop_connection_and_exit_ttl,
        ),
        (
            "small_budget_gap_then_follow",
            seed_small_budget_gap_then_follow,
        ),
        (
            "control_only_overflow_same_offset_gap",
            seed_control_only_overflow_gap,
        ),
        (
            "resume_rotate_axis_then_reject_spent_replay",
            seed_resume_rotate_axis_and_reject_replay,
        ),
        (
            "resume_ttl_expiry_then_reap_purges",
            seed_resume_ttl_expiry_then_reap_purges,
        ),
        (
            "attach_survives_ticks_then_expires_after_detach",
            seed_attach_survives_detach_then_expires,
        ),
        ("read_beyond_tiny_budget", seed_read_beyond_tiny_budget),
        (
            "lease_owned_split_physical_drop_then_reacquire",
            seed_lease_owned_split_physical,
        ),
        (
            "rotate_then_tick_past_ttl_verify_denied_without_reap",
            seed_rotate_then_expiry_without_reap,
        ),
        (
            "doomed_session_credential_outlives_by_issue_ttl",
            seed_doomed_session_credential_outlives_by_1ms,
        ),
        (
            "rotate_refreshes_expiry_before_doom",
            seed_rotate_refreshes_expiry_before_doom,
        ),
        (
            "read_at_surfaces_only_pushed_controls",
            seed_read_at_surfaces_only_pushed_controls,
        ),
        (
            "spent_generation_stays_dead_across_rotations",
            seed_spent_generations_stay_dead,
        ),
        (
            "closing_suppresses_reap_until_cleared",
            seed_closing_suppresses_reap,
        ),
    ];

    for (name, build) in seeds {
        let bytes = build();
        // A seed that panics the harness at generation time is a bug in
        // this file, not a finding worth shipping into the corpus.
        harness::run(&bytes);
        let path = dir.join(name);
        fs::write(&path, &bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
}
