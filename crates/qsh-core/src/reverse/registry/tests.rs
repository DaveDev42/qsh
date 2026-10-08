use super::*;
use crate::broker::TestClock;
use proptest::prelude::*;

fn addr() -> SocketAddr {
    "127.0.0.1:4433".parse().unwrap()
}

fn registry(allow_advertised_names: bool) -> Registry {
    Registry::new(Arc::new(TestClock::new()), allow_advertised_names)
}

fn entry<'a>(fingerprint: &'a str, principal: &'a str) -> AdmittedEntry<'a> {
    AdmittedEntry {
        fingerprint,
        principal,
        address: addr(),
        capabilities: vec!["exec".to_string()],
    }
}

fn stub_entry(name: &str, generation: u64) -> ReverseEntry {
    ReverseEntry {
        name: name.to_string(),
        fingerprint: "sha256:a".to_string(),
        principal: "device:x".to_string(),
        address: addr(),
        capabilities: Vec::new(),
        registered_at: "2026-01-01T00:00:00Z".to_string(),
        generation,
        state: EntryState::Live,
        stale_since: None,
        lost_at: None,
    }
}

// ---- name resolution priority table (PLAN.md Step 3 (c)) ----

#[test]
fn alias_present_wins_over_offered_name() {
    let r = registry(true);
    let name = r
        .resolve_name(Some("personal-mac"), "attacker-chosen-name")
        .expect("alias wins");
    assert_eq!(name, "personal-mac");
}

#[test]
fn empty_offered_name_with_alias_resolves_to_the_alias() {
    let r = registry(false);
    let name = r
        .resolve_name(Some("personal-mac"), "")
        .expect("empty offered_name is fine when an alias exists");
    assert_eq!(name, "personal-mac");
}

#[test]
fn no_alias_and_advertised_names_disallowed_is_permission_denied() {
    let r = registry(false);
    let err = r
        .resolve_name(None, "some-name")
        .expect_err("no alias, advertised names off");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
}

#[test]
fn no_alias_and_advertised_names_allowed_uses_offered_name() {
    let r = registry(true);
    let name = r
        .resolve_name(None, "advertised-name")
        .expect("advertised name accepted");
    assert_eq!(name, "advertised-name");
}

#[test]
fn shape_violation_is_invalid_argument() {
    let r = registry(true);
    // Contains a space: not `valid_host_name` and not empty.
    let err = r
        .resolve_name(Some("personal-mac"), "not a valid name")
        .expect_err("malformed offered_name");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn no_alias_no_offered_name_and_advertised_names_disallowed_is_permission_denied() {
    let r = registry(false);
    let err = r.resolve_name(None, "").expect_err("nothing to resolve to");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
}

/// An operator-pinned alias that doesn't satisfy `wire::valid_host_name`
/// (`Ops::trust_add` only rejects *empty* names, so this is reachable in
/// practice) must fail closed — `PERMISSION_DENIED`, not
/// `INVALID_ARGUMENT` — with the exact same opaque message the no-alias
/// case uses, never revealing the alias content (adversarial review
/// finding).
#[test]
fn malformed_alias_is_permission_denied_with_the_generic_message() {
    let r = registry(true);
    let err = r
        .resolve_name(Some("mac/work"), "attacker-chosen-name")
        .expect_err("alias contains '/', not a valid host name");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert_eq!(err.message, host_reverse_denied().message);
}

#[test]
fn oversized_alias_is_permission_denied() {
    let r = registry(true);
    let huge = "a".repeat(65);
    let err = r
        .resolve_name(Some(&huge), "")
        .expect_err("alias exceeds the 64-byte host-name bound");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
}

/// The no-alias `PERMISSION_DENIED` and the malformed-alias
/// `PERMISSION_DENIED` must be textually indistinguishable — that's the
/// whole point of [`host_reverse_denied`] (finding 2).
#[test]
fn no_alias_and_malformed_alias_denials_carry_the_identical_message() {
    let r = registry(false);
    let no_alias = r.resolve_name(None, "").expect_err("no alias");
    let bad_alias = r
        .resolve_name(Some("mac/work"), "")
        .expect_err("malformed alias");
    assert_eq!(no_alias.message, bad_alias.message);
}

// ---- conflict / generation ----

#[test]
fn conflicting_fingerprint_under_a_live_name_is_invalid_argument_and_creates_nothing() {
    let r = registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    assert_eq!(first.entry.generation, 0);

    let err = r
        .admit("shared".to_string(), entry("sha256:b", "device:shared"))
        .expect_err("different fingerprint, same name");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    // The original entry is untouched — no silent overwrite.
    let still = r.get("shared").expect("original entry remains");
    assert_eq!(still.fingerprint, "sha256:a");
    assert_eq!(still.generation, 0);
}

#[test]
fn conflicting_fingerprint_under_a_stale_name_is_also_denied() {
    // A stale entry still "occupies" its name — the whole point of
    // staying `Stale` instead of vanishing immediately is to deny a
    // squatter the gap between death and retention expiry
    // (`admit`'s doc comment).
    let (r, _clock) = clocked_registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    r.mark_stale("shared", first.entry.generation)
        .expect("goes stale");

    let err = r
        .admit("shared".to_string(), entry("sha256:b", "device:shared"))
        .expect_err("different fingerprint, stale name");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    let still = r.get("shared").expect("stale entry untouched");
    assert_eq!(still.fingerprint, "sha256:a");
    assert_eq!(still.state, EntryState::Stale);
}

#[test]
fn same_fingerprint_reregistering_a_stale_name_revives_it_as_live() {
    let (r, _clock) = clocked_registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    r.mark_stale("shared", first.entry.generation)
        .expect("goes stale");

    let second = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("same fingerprint revives it");
    assert_eq!(second.entry.state, EntryState::Live);
    assert!(second.entry.stale_since.is_none());
    assert!(
        second.entry.lost_at.is_none(),
        "a revived live entry must clear lost_at, not keep the stale one"
    );
    assert_eq!(second.entry.generation, 1);
    assert_eq!(second.replaced_generation, Some(0));
}

#[test]
fn same_fingerprint_reregistering_replaces_and_advances_generation() {
    let r = registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    assert_eq!(first.entry.generation, 0);
    assert!(first.replaced_generation.is_none());

    let second = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("reconnect from the same peer replaces the entry");
    assert_eq!(second.entry.generation, 1);
    assert_eq!(second.replaced_generation, Some(0));
    assert_eq!(r.snapshot().len(), 1, "replaced, not duplicated");
}

#[test]
fn registered_at_uses_the_injected_clock() {
    let r = registry(false);
    let outcome = r
        .admit(
            "personal-mac".to_string(),
            entry("sha256:a", "device:personal-mac"),
        )
        .expect("registers");
    // Pin the literal RFC 3339 shape against `TestClock`'s fixed start
    // instant (`broker::clock::TestClock::WALL_START_UNIX_SECS` =
    // 2026-01-01T00:00:00Z) instead of recomputing the expected value
    // with the function under test — a self-referential assertion would
    // never catch a formatting regression.
    assert_eq!(outcome.entry.registered_at, "2026-01-01T00:00:00Z");
}

// ---- rollback (undo an admit whose Hello reply never made it out) ----

#[test]
fn rollback_of_a_fresh_registration_frees_the_name() {
    let r = registry(false);
    let outcome = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    assert!(outcome.replaced_entry.is_none());

    r.rollback("shared", outcome.entry.generation, outcome.replaced_entry);
    assert!(r.get("shared").is_none(), "name is free again");
    assert!(r.snapshot().is_empty());
}

#[test]
fn rollback_of_a_replace_restores_the_previous_entry() {
    let r = registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    let second = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("same-fingerprint reconnect replaces");
    assert_eq!(second.entry.generation, 1);
    assert_eq!(second.replaced_entry.as_ref(), Some(&first.entry));

    r.rollback(
        "shared",
        second.entry.generation,
        second.replaced_entry.clone(),
    );
    let restored = r.get("shared").expect("the first entry is back");
    assert_eq!(restored, first.entry, "byte-for-byte the pre-image");
}

#[test]
fn a_rolled_back_generation_is_never_reissued() {
    // Regression for the adversarial review finding: `rollback`'s own
    // doc comment claims a rolled-back generation "must never be
    // reissued", but the replace branch used to compute the next
    // generation purely from `existing.generation`, which a rollback
    // moves *backwards* — so the very next admit handed the same
    // number straight back out.
    let r = registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    let second = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("reconnect");
    assert_eq!(second.entry.generation, 1);

    r.rollback(
        "shared",
        second.entry.generation,
        second.replaced_entry.clone(),
    );
    assert_eq!(
        r.get("shared").unwrap().generation,
        0,
        "rollback restores generation 0"
    );

    let third = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("registers again after the rollback");
    assert_eq!(
        third.entry.generation, 2,
        "generation 1 was already handed out once and rolled back — it must not come back"
    );
    assert_ne!(third.entry.generation, first.entry.generation);
    assert_ne!(third.entry.generation, second.entry.generation);
}

#[test]
fn prune_tombstones_bounds_growth_without_evicting_a_live_names_tombstone() {
    let mut state = RegistryState::default();
    state
        .entries
        .insert("still-live".to_string(), stub_entry("still-live", 0));
    state.last_generation.insert("still-live".to_string(), 0);
    for i in 0..(MAX_TOMBSTONES + 5) {
        state.last_generation.insert(format!("cold-{i}"), 0);
    }
    assert!(state.last_generation.len() > MAX_TOMBSTONES);

    prune_tombstones(&mut state);

    assert!(
        state.last_generation.len() <= MAX_TOMBSTONES,
        "growth must be bounded once the cap is exceeded"
    );
    assert!(
        state.last_generation.contains_key("still-live"),
        "a currently registered name's tombstone must never be evicted \
         — doing so would let a later admit reissue a generation that \
         name's own history already used"
    );
}

#[test]
fn rollback_is_a_no_op_once_a_newer_registration_already_superseded_it() {
    let r = registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    // A concurrent successful reconnect moves the name to generation 1
    // before the late rollback of generation 0 arrives.
    r.admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("reconnect");

    r.rollback("shared", first.entry.generation, None);
    let still = r.get("shared").expect("generation 1 must survive");
    assert_eq!(
        still.generation, 1,
        "late rollback of a stale generation is a no-op"
    );
}

#[test]
fn admit_stores_a_fresh_entry_as_live() {
    let r = registry(false);
    let outcome = r
        .admit(
            "personal-mac".to_string(),
            entry("sha256:a", "device:personal-mac"),
        )
        .expect("registers");
    assert_eq!(outcome.entry.state, EntryState::Live);
    assert!(outcome.entry.stale_since.is_none());
    assert_eq!(
        r.get("personal-mac").expect("entry present").state,
        EntryState::Live
    );
}

// ---- stale transition (`PLAN.md` M3 Step 4) ----

/// A `TestClock`-backed registry, for the deterministic stale/retention
/// tests below (`docs/design/testing.md` L2 — no `sleep()`).
fn clocked_registry(allow_advertised_names: bool) -> (Registry, TestClock) {
    let clock = TestClock::new();
    (
        Registry::new(Arc::new(clock.clone()), allow_advertised_names),
        clock,
    )
}

#[test]
fn mark_stale_transitions_a_live_entry_and_stamps_stale_since() {
    let (r, clock) = clocked_registry(false);
    let outcome = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    clock.advance(Duration::from_secs(7));

    let staled = r
        .mark_stale("shared", outcome.entry.generation)
        .expect("live entry at this generation transitions");
    assert_eq!(staled.state, EntryState::Stale);
    assert_eq!(staled.stale_since, Some(clock.now()));
    // Nothing else about the entry changes.
    assert_eq!(staled.fingerprint, "sha256:a");
    assert_eq!(staled.generation, outcome.entry.generation);

    let still = r.get("shared").expect("entry remains, just stale");
    assert_eq!(still.state, EntryState::Stale);
}

/// `lost_at` (issue #4 item 4) is `stale_since`'s wall-clock sibling —
/// stamped from the same injected [`Clock`], at the same transition,
/// in the same RFC 3339 shape [`registered_at_uses_the_injected_clock`]
/// already pins for `registered_at`.
#[test]
fn mark_stale_records_lost_at_from_the_injected_clock() {
    let (r, clock) = clocked_registry(false);
    let outcome = r
        .admit(
            "personal-mac".to_string(),
            entry("sha256:a", "device:personal-mac"),
        )
        .expect("registers");
    assert!(
        outcome.entry.lost_at.is_none(),
        "a fresh live entry has no lost_at"
    );
    clock.advance(Duration::from_secs(7));

    let staled = r
        .mark_stale("personal-mac", outcome.entry.generation)
        .expect("live entry at this generation transitions");
    assert_eq!(staled.lost_at.as_deref(), Some("2026-01-01T00:00:07Z"));
}

#[test]
fn mark_stale_is_a_no_op_once_a_newer_registration_already_superseded_it() {
    let (r, _clock) = clocked_registry(false);
    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    // A reconnect replaces it before the old connection's death report
    // arrives — the exact race `Registry::rollback`'s doc comment
    // already documents for the sibling method.
    r.admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("reconnect replaces");

    let result = r.mark_stale("shared", first.entry.generation);
    assert!(result.is_none(), "stale generation is not the live one");
    let still = r.get("shared").expect("generation 1 must survive live");
    assert_eq!(still.state, EntryState::Live);
    assert_eq!(still.generation, 1);
}

#[test]
fn mark_stale_is_idempotent_on_a_repeated_call() {
    let (r, clock) = clocked_registry(false);
    let outcome = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    clock.advance(Duration::from_secs(1));
    let first = r
        .mark_stale("shared", outcome.entry.generation)
        .expect("first transition succeeds");
    clock.advance(Duration::from_secs(1));
    // A second death report for the same generation (e.g. both the
    // probe driver and a concurrent path) must not re-stamp
    // `stale_since` or otherwise change anything.
    let second = r.mark_stale("shared", outcome.entry.generation);
    assert!(second.is_none());
    assert_eq!(
        r.get("shared").unwrap().stale_since,
        first.stale_since,
        "stale_since is stamped once, not refreshed"
    );
}

#[test]
fn mark_stale_unknown_name_is_a_no_op() {
    let (r, _clock) = clocked_registry(false);
    assert!(r.mark_stale("nobody-home", 0).is_none());
}

// ---- retention expiry (`docs/design/protocol.md` §11-4) ----

#[test]
fn sweep_expired_removes_nothing_before_retention_elapses() {
    let (r, clock) = clocked_registry(false);
    let outcome = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("registers");
    r.mark_stale("shared", outcome.entry.generation)
        .expect("goes stale");

    let retention = Duration::from_secs(120);
    clock.advance(Duration::from_secs(119));
    let removed = r.sweep_expired(retention);
    assert!(removed.is_empty(), "not due yet");
    assert!(
        r.get("shared").is_some(),
        "entry still present, still stale"
    );
}

#[test]
fn sweep_expired_removes_exactly_at_the_retention_boundary() {
    let (r, clock) = clocked_registry(false);
    let outcome = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("registers");
    r.mark_stale("shared", outcome.entry.generation)
        .expect("goes stale");

    let retention = Duration::from_secs(120);
    clock.advance(retention);
    let removed = r.sweep_expired(retention);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].name, "shared");
    assert!(r.get("shared").is_none(), "removed, not just marked");
    assert!(r.snapshot().is_empty());
}

#[test]
fn sweep_expired_never_touches_a_live_entry() {
    let (r, clock) = clocked_registry(false);
    r.admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("registers, stays live");
    clock.advance(Duration::from_secs(10_000));
    let removed = r.sweep_expired(Duration::from_secs(1));
    assert!(removed.is_empty());
    assert_eq!(
        r.get("shared").expect("still there").state,
        EntryState::Live
    );
}

#[test]
fn sweep_expired_only_removes_entries_actually_due_leaving_others() {
    let (r, clock) = clocked_registry(false);
    let old = r
        .admit("old".to_string(), entry("sha256:a", "device:old"))
        .expect("registers");
    r.mark_stale("old", old.entry.generation).expect("stale");
    clock.advance(Duration::from_secs(60));
    let recent = r
        .admit("recent".to_string(), entry("sha256:b", "device:recent"))
        .expect("registers");
    r.mark_stale("recent", recent.entry.generation)
        .expect("stale");

    // "old" went stale at t=0, "recent" at t=60. At t=125 only "old"
    // (125s stale) has cleared a 120s retention; "recent" (65s stale)
    // has not.
    clock.advance(Duration::from_secs(65));
    let removed = r.sweep_expired(Duration::from_secs(120));
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].name, "old");
    assert!(r.get("old").is_none());
    assert!(r.get("recent").is_some(), "not due yet");
}

// ---- generation monotonicity across replace/stale/remove (`PLAN.md`
// M3 Step 4 (1): "the registry generation stays strictly monotonic
// across replace/stale/remove") ----

#[test]
fn generation_survives_a_stale_eviction_and_keeps_advancing() {
    let (r, clock) = clocked_registry(false);
    let retention = Duration::from_secs(120);

    let first = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    assert_eq!(first.entry.generation, 0);
    r.mark_stale("shared", 0).expect("goes stale");
    clock.advance(retention);
    let removed = r.sweep_expired(retention);
    assert_eq!(removed.len(), 1, "the name is fully freed");
    assert!(r.get("shared").is_none());

    // Re-registration under the freed name — by the same fingerprint,
    // as a real reconnect would be, or even a different one now that
    // the slot is genuinely empty — must not restart at generation 0.
    let second = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("re-registers after eviction");
    assert_eq!(
        second.entry.generation, 1,
        "generation must never repeat, even across a full remove"
    );
    assert!(
        second.replaced_generation.is_none(),
        "no live entry to replace"
    );
}

#[test]
fn generation_survives_a_rollback_and_keeps_advancing() {
    let (r, _clock) = clocked_registry(false);
    let outcome = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("first registration");
    r.rollback("shared", outcome.entry.generation, None);
    assert!(r.get("shared").is_none(), "rolled back, name is free");

    let second = r
        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
        .expect("re-registers");
    assert_eq!(
        second.entry.generation, 1,
        "a rolled-back generation must never be reissued"
    );
}

proptest! {
    /// Any sequence of admit / mark_stale-then-sweep / rollback
    /// operations on one name never produces a repeated `generation`
    /// value across the whole history — the property `PLAN.md` M3 Step
    /// 4 (1) names explicitly. `docs/design/testing.md` L2 property
    /// test discipline.
    #[test]
    fn generation_is_never_repeated_across_any_replace_stale_remove_sequence(
        ops in proptest::collection::vec(0u8..3, 1..30),
    ) {
        let (r, clock) = clocked_registry(false);
        let retention = Duration::from_secs(10);
        let mut seen = std::collections::HashSet::new();
        let mut live_generation: Option<u64> = None;

        for op in ops {
            match op {
                // Register (fresh or same-fingerprint replace).
                0 => {
                    let outcome = r
                        .admit("shared".to_string(), entry("sha256:a", "device:shared"))
                        .expect("same fingerprint always admits");
                    prop_assert!(
                        seen.insert(outcome.entry.generation),
                        "generation {} reused",
                        outcome.entry.generation
                    );
                    live_generation = Some(outcome.entry.generation);
                }
                // Mark the live entry stale, then let retention elapse
                // and sweep it away.
                1 => {
                    if let Some(generation) = live_generation
                        && r.mark_stale("shared", generation).is_some()
                    {
                        clock.advance(retention);
                        r.sweep_expired(retention);
                        live_generation = None;
                    }
                }
                // Roll back the live entry to nothing.
                _ => {
                    if let Some(generation) = live_generation {
                        r.rollback("shared", generation, None);
                        live_generation = None;
                    }
                }
            }
        }
    }
}
