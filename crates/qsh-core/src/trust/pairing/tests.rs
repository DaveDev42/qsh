use super::*;

fn secret(seed: u8) -> [u8; qsh_proto::pairing::INVITE_SECRET_LEN] {
    [seed; qsh_proto::pairing::INVITE_SECRET_LEN]
}

fn ekm(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// The client-direction proof `store.redeem` expects, via the same
/// `proofs_from_secret` real callers (`crate::pairing`) use — not a
/// hand-rolled recomputation, so a future change to the domain
/// separation cannot silently desync the test fixture from production.
fn client_proof_for(secret: &[u8], ekm: &[u8]) -> [u8; 32] {
    proofs_from_secret(secret, ekm).0
}

#[test]
fn add_load_save_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();

    let mut store = InviteStore::default();
    let (created_at, expires_at) = store.add(&secret(1), now, None);
    assert!(!created_at.is_empty());
    assert!(!expires_at.is_empty());
    store.save(&path).unwrap();

    let back = InviteStore::load(&path).unwrap();
    assert_eq!(back.records.len(), 1);
    assert_eq!(back.records[0].created_at, created_at);
    assert!(back.records[0].consumed_at.is_none());
}

#[test]
fn redeem_accepts_a_correct_proof_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();
    let s = secret(7);
    let e = ekm(9);

    let mut store = InviteStore::default();
    store.add(&s, now, None);
    store.save(&path).unwrap();

    let shared = SharedInviteStore::open(&path).unwrap();
    assert!(shared.pairing_open(now));

    let (client_proof, expected_server_proof) = proofs_from_secret(&s, &e);
    match shared.redeem(&e, &client_proof, now, |_| true).unwrap() {
        RedeemOutcome::Accepted { server_proof } => {
            assert_eq!(
                server_proof, expected_server_proof,
                "the responder's returned proof must be the real, \
                     independently-derived server-direction value — never \
                     an echo of what the client sent"
            );
            assert_ne!(
                server_proof, client_proof,
                "client/server proofs must be domain-separated, not equal"
            );
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
    // Second attempt with the same proof: already consumed.
    assert_eq!(
        shared.redeem(&e, &client_proof, now, |_| true).unwrap(),
        RedeemOutcome::AlreadyConsumed
    );
}

#[test]
fn redeem_leaves_the_invite_untouched_when_on_matched_declines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();
    let s = secret(11);
    let e = ekm(12);

    let mut store = InviteStore::default();
    store.add(&s, now, None);
    store.save(&path).unwrap();

    let shared = SharedInviteStore::open(&path).unwrap();
    let proof = client_proof_for(&s, &e);

    // A verified proof whose `on_matched` hook declines (the caller's
    // local-pin collision check, `crate::pairing::respond`) must not
    // consume the invite at all — this is what lets the operator
    // rename/remove the conflicting pin and retry within the same TTL
    // (this step's brief invariant #5).
    assert_eq!(
        shared.redeem(&e, &proof, now, |_| false).unwrap(),
        RedeemOutcome::Rejected
    );
    match shared.redeem(&e, &proof, now, |_| true).unwrap() {
        RedeemOutcome::Accepted { .. } => {}
        other => panic!("expected the still-live invite to redeem on retry, got {other:?}"),
    }
}

/// A stored `assigned_name` that no longer passes
/// [`super::super::validate_peer_label`] (a hand-edited or otherwise
/// corrupted `invites.toml`) refuses the whole redemption before
/// `on_matched` ever runs — never a silent fallback to the self-asserted
/// `device_name` (`docs/CLI.md` §6.11, ADR-0012 decision 6). The record
/// must be left byte-identical, so the invite is still redeemable once
/// the name is fixed.
#[test]
fn a_corrupt_assigned_name_refuses_redemption_instead_of_falling_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();
    let s = secret(21);
    let e = ekm(22);

    let mut store = InviteStore::default();
    // `/` fails `validate_peer_label`; `add` stores it verbatim (no
    // validation on write, `InviteStore::add`'s own doc).
    store.add(&s, now, Some("bad/name".to_string()));
    store.save(&path).unwrap();
    let raw_before = std::fs::read_to_string(&path).unwrap();

    let shared = SharedInviteStore::open(&path).unwrap();
    let proof = client_proof_for(&s, &e);

    let on_matched_called = std::cell::Cell::new(false);
    let outcome = shared
        .redeem(&e, &proof, now, |_| {
            on_matched_called.set(true);
            true
        })
        .unwrap();
    assert_eq!(outcome, RedeemOutcome::InvalidAssignedName);
    assert!(
        !on_matched_called.get(),
        "a corrupt assigned_name must be refused before on_matched runs — \
         it must never see the self-asserted name as a fallback"
    );

    let raw_after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        raw_after, raw_before,
        "a refused redemption must leave invites.toml byte-identical, \
         so the invite is still live once the name is fixed"
    );

    // Fixing the name on disk lets the same secret redeem normally —
    // proof that InvalidAssignedName is not a general-purpose reject.
    let mut fixed = InviteStore::load(&path).unwrap();
    fixed.records[0].assigned_name = Some("good-name".to_string());
    fixed.save(&path).unwrap();
    let shared = SharedInviteStore::open(&path).unwrap();
    match shared.redeem(&e, &proof, now, |name| {
        assert_eq!(name, Some("good-name"));
        true
    }) {
        Ok(RedeemOutcome::Accepted { .. }) => {}
        other => panic!("expected Accepted once the name is valid, got {other:?}"),
    }
}

#[test]
fn redeem_rejects_a_wrong_proof_as_no_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();

    let mut store = InviteStore::default();
    store.add(&secret(1), now, None);
    store.save(&path).unwrap();

    let shared = SharedInviteStore::open(&path).unwrap();
    let garbage = [0xAAu8; 32];
    assert_eq!(
        shared.redeem(&ekm(1), &garbage, now, |_| true).unwrap(),
        RedeemOutcome::NoMatch
    );
    // A failed attempt never consumes or otherwise disturbs the record
    // (this step's brief, invariant #3 / report §B8: no burn-on-failure).
    let proof = client_proof_for(&secret(1), &ekm(1));
    assert!(matches!(
        shared.redeem(&ekm(1), &proof, now, |_| true).unwrap(),
        RedeemOutcome::Accepted { .. }
    ));
}

#[test]
fn redeem_after_ttl_reports_expired_not_no_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let created = SystemTime::now() - Duration::from_secs(60);
    let s = secret(3);
    let e = ekm(4);

    let mut store = InviteStore::default();
    store.add(&s, created, None);
    store.save(&path).unwrap();

    let shared = SharedInviteStore::open(&path).unwrap();
    let after_ttl = created + INVITE_TTL + Duration::from_secs(1);
    let proof = client_proof_for(&s, &e);
    assert_eq!(
        shared.redeem(&e, &proof, after_ttl, |_| true).unwrap(),
        RedeemOutcome::Expired
    );
    // Still within retention: pairing_open() stays true so this exact
    // exchange could happen at all.
    assert!(shared.pairing_open(after_ttl));
}

#[test]
fn pairing_open_is_false_once_every_record_ages_out_of_retention() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let created = SystemTime::now() - Duration::from_secs(60);

    let mut store = InviteStore::default();
    store.add(&secret(5), created, None);
    store.save(&path).unwrap();

    let shared = SharedInviteStore::open(&path).unwrap();
    assert!(shared.pairing_open(created + Duration::from_secs(1)));
    let after_retention = created + INVITE_RETENTION + Duration::from_secs(1);
    assert!(!shared.pairing_open(after_retention));
}

#[test]
fn prune_drops_records_past_retention_and_keeps_live_ones() {
    let now = SystemTime::now();
    let mut store = InviteStore::default();
    store.add(
        &secret(1),
        now - INVITE_RETENTION - Duration::from_secs(1),
        None,
    );
    store.add(&secret(2), now, None);
    assert_eq!(store.records.len(), 2);
    store.prune(now);
    assert_eq!(store.records.len(), 1);
}

#[test]
fn shared_store_reloads_a_freshly_added_invite_without_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();

    let shared = SharedInviteStore::open(&path).unwrap();
    assert!(!shared.pairing_open(now), "no invite yet");

    let mut store = InviteStore::default();
    store.add(&secret(1), now, None);
    store.save(&path).unwrap();

    assert!(
        shared.pairing_open(now),
        "a freshly written invite must be picked up without a restart"
    );
}

#[cfg(unix)]
#[test]
fn saved_store_is_private() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cfg/invites.toml");
    InviteStore::default().save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// Report F-9, direction 1: `Ops::trust_invite`'s writer path (load,
/// mutate a stale in-memory copy, save) must not un-consume an invite
/// that a *different* process (`qsh serve`'s `SharedInviteStore::
/// redeem`) already marked consumed on disk in the meantime. This is
/// the exact lost-update the verification round's minimal repro
/// produced: without the merge, a `trust invite` process's save would
/// silently revert `consumed_at` back to unset, making the invite
/// redeemable a second time.
#[test]
fn save_never_reverts_a_consumption_recorded_on_disk_by_another_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");

    // Writer A (`trust invite`-shaped): load a store with one live
    // invite.
    let mut writer_a = InviteStore::default();
    writer_a.add(&secret(1), SystemTime::now(), None);
    writer_a.save(&path).unwrap();
    let mut stale_copy = InviteStore::load(&path).unwrap();

    // Writer B (`qsh serve`-shaped): independently loads the *same*
    // file, then consumes the record and saves — simulating a
    // `redeem()` that completed while writer A was still holding its
    // own, now-stale, in-memory copy.
    let mut writer_b = InviteStore::load(&path).unwrap();
    writer_b.records[0].consumed_at = Some("2026-08-31T00:03:00Z".to_string());
    writer_b.save(&path).unwrap();

    // Writer A now saves its stale copy (e.g. after mint-ing a second,
    // unrelated invite) — must not blow away writer B's consumption.
    stale_copy.add(&secret(2), SystemTime::now(), None);
    stale_copy.save(&path).unwrap();

    let final_state = InviteStore::load(&path).unwrap();
    assert_eq!(final_state.records.len(), 2, "both invites must survive");
    let first = final_state
        .records
        .iter()
        .find(|r| r.mac_key == MacKey::of(&secret(1)).to_base64())
        .expect("writer A's original record survives");
    assert_eq!(
        first.consumed_at.as_deref(),
        Some("2026-08-31T00:03:00Z"),
        "a consumption already on disk must never be reverted by a \
             writer whose own copy predates it"
    );
}

/// Report F-9, direction 2: the reverse lost-update — `SharedInviteStore
/// ::redeem`'s save (writing back its own, possibly-stale full record
/// set) must not silently drop an invite a *different* process
/// (`trust invite`) minted after `redeem`'s in-memory copy was loaded.
#[test]
fn save_does_not_drop_an_invite_minted_by_another_writer_after_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");

    let mut writer_a = InviteStore::default();
    writer_a.add(&secret(1), SystemTime::now(), None);
    writer_a.save(&path).unwrap();

    // `redeem`-shaped writer loads the current (one-record) state.
    let mut redeemer = InviteStore::load(&path).unwrap();

    // A concurrent `trust invite` process mints a second invite and
    // saves, independently, before the redeemer writes back.
    let mut inviter = InviteStore::load(&path).unwrap();
    inviter.add(&secret(2), SystemTime::now(), None);
    inviter.save(&path).unwrap();

    // The redeemer now consumes its (only known) record and saves its
    // own, still one-record-stale, copy.
    redeemer.records[0].consumed_at = Some("2026-08-31T00:03:00Z".to_string());
    redeemer.save(&path).unwrap();

    let final_state = InviteStore::load(&path).unwrap();
    assert_eq!(
        final_state.records.len(),
        2,
        "the concurrently-minted invite must not be silently dropped"
    );
    assert!(
        final_state
            .records
            .iter()
            .any(|r| r.mac_key == MacKey::of(&secret(2)).to_base64()),
        "the other writer's fresh invite must survive"
    );
}

/// The F-9 merge above must not undo a legitimate `prune()` — an
/// expired-past-retention record dropped from `self.records` before
/// `save()` must not come back just because it is still sitting
/// on-disk at the moment `save()` re-reads the file to merge.
#[test]
fn save_still_drops_a_pruned_record_even_though_it_is_still_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();

    let mut store = InviteStore::default();
    store.add(
        &secret(1),
        now - INVITE_RETENTION - Duration::from_secs(1),
        None,
    );
    store.save(&path).unwrap();
    assert_eq!(InviteStore::load(&path).unwrap().records.len(), 1);

    // `Ops::trust_invite`'s real sequence: load, prune, add, save.
    let mut store = InviteStore::load(&path).unwrap();
    store.prune(now);
    assert_eq!(store.records.len(), 0, "pruned in memory");
    store.add(&secret(2), now, None);
    store.save(&path).unwrap();

    let final_state = InviteStore::load(&path).unwrap();
    assert_eq!(
        final_state.records.len(),
        1,
        "the expired record must stay pruned, not be resurrected by \
             the F-9 merge's union step: {:?}",
        final_state.records
    );
    assert_eq!(
        final_state.records[0].mac_key,
        MacKey::of(&secret(2)).to_base64()
    );
}

#[test]
fn on_disk_record_never_contains_the_raw_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let s = secret(0x42);

    let mut store = InviteStore::default();
    store.add(&s, SystemTime::now(), None);
    store.save(&path).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    let hex_secret = s.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert!(!text.contains(&hex_secret));
    // The base64 of the raw secret bytes must not appear either.
    assert!(!text.contains(&BASE64.encode(s.as_ref())));
}

/// Regression for `PLAN.md` M7 Step 7-1's close of report F-9's
/// residual lost-update window: 8 threads, each doing a full
/// `InviteStore::lock` → `load` → `add` → `save` cycle for a
/// distinct invite, must not lose each other's addition — mirrors
/// `TrustStore`'s own `concurrent_full_rmw_cycles_do_not_lose_each_others_peers`
/// and, further back, `crate::resume`'s
/// `concurrent_writers_do_not_lose_each_others_entries`, the
/// precedent this lock was lifted from. Before this lock, the F-9
/// merge only narrowed the window between two writers' merge-reads
/// and their own writes — two merge-reads landing before either
/// write could still each decide their own record is the winner.
#[test]
fn concurrent_full_rmw_cycles_do_not_lose_each_others_invites() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invites.toml");
    let now = SystemTime::now();
    let mut threads = Vec::new();
    for i in 0..8u8 {
        let path = path.clone();
        threads.push(std::thread::spawn(move || {
            let _lock = InviteStore::lock(&path).unwrap();
            let mut store = InviteStore::load(&path).unwrap();
            store.add(&secret(i), now, None);
            store.save(&path).unwrap();
        }));
    }
    for t in threads {
        t.join().expect("writer");
    }
    let final_store = InviteStore::load(&path).unwrap();
    assert_eq!(final_store.records.len(), 8, "a concurrent invite was lost");
}
