use super::*;

fn fp(seed: &[u8]) -> Fingerprint {
    Fingerprint::of_spki_der(seed)
}

/// PLAN.md M9 §2.1: every decision-table row, `(input, expected address,
/// expected port_filled)`. Row numbers in comments match the design doc.
#[test]
fn normalize_peer_address_decision_table() {
    let rows: &[(&str, &str, bool)] = &[
        // 1
        ("", "", false),
        // 2
        ("mac", "mac:4433", true),
        // 3
        ("mac.example.com", "mac.example.com:4433", true),
        // 4
        ("mac:4433", "mac:4433", false),
        // 5
        ("mac:22", "mac:22", false),
        // 6
        ("192.0.2.10", "192.0.2.10:4433", true),
        // 7
        ("192.0.2.10:4433", "192.0.2.10:4433", false),
        // 8
        ("[::1]:4433", "[::1]:4433", false),
        // 9
        ("[::1]", "[::1]:4433", true),
        // 10
        ("[fe80::1%eth0]", "[fe80::1%eth0]:4433", true),
        // 14
        ("mac:", "mac:", false),
        // 15
        ("mac:ssh", "mac:ssh", false),
        // 16
        ("[::1]:x", "[::1]:x", false),
        // 17
        ("mac:0", "mac:0", false),
        // 18
        ("mac:99999", "mac:99999", false),
        // 19
        (" mac ", " mac :4433", true),
    ];
    for (input, expected_address, expected_port_filled) in rows {
        let got = normalize_peer_address(input);
        assert_eq!(&got.address, expected_address, "input {input:?}");
        assert_eq!(
            got.port_filled, *expected_port_filled,
            "input {input:?} port_filled"
        );
    }
}

#[test]
fn normalize_peer_address_is_identity_on_an_empty_address() {
    let got = normalize_peer_address("");
    assert_eq!(got.address, "");
    assert!(!got.port_filled);
}

#[test]
fn normalize_peer_address_brackets_a_bare_ipv6_literal_instead_of_reading_its_last_group_as_a_port()
{
    // Row 11
    let got = normalize_peer_address("::1");
    assert_eq!(got.address, "[::1]:4433");
    assert!(got.port_filled);

    // Row 12
    let got = normalize_peer_address("2001:db8::1");
    assert_eq!(got.address, "[2001:db8::1]:4433");
    assert!(got.port_filled);

    // Row 13 — the last colon-group is not read as a port because the
    // whole string parses as an IPv6 literal first.
    let got = normalize_peer_address("2001:db8::1:4433");
    assert_eq!(got.address, "[2001:db8::1:4433]:4433");
    assert!(got.port_filled);
}

#[test]
fn normalize_peer_address_does_not_enforce_a_port_range() {
    // Rows 17-18, §4.1 #12: out-of-range ports are left untouched, no
    // new error code.
    let got = normalize_peer_address("mac:0");
    assert_eq!(got.address, "mac:0");
    assert!(!got.port_filled);

    let got = normalize_peer_address("mac:99999");
    assert_eq!(got.address, "mac:99999");
    assert!(!got.port_filled);
}

#[test]
fn normalize_peer_address_is_idempotent_on_its_own_output() {
    let inputs = [
        "",
        "mac",
        "mac.example.com",
        "mac:4433",
        "mac:22",
        "192.0.2.10",
        "192.0.2.10:4433",
        "[::1]:4433",
        "[::1]",
        "[fe80::1%eth0]",
        "::1",
        "2001:db8::1",
        "2001:db8::1:4433",
        "mac:",
        "mac:ssh",
        "[::1]:x",
        "mac:0",
        "mac:99999",
        " mac ",
    ];
    for input in inputs {
        let once = normalize_peer_address(input);
        let twice = normalize_peer_address(&once.address);
        assert_eq!(
            twice.address, once.address,
            "not a fixed point for input {input:?}"
        );
        assert!(
            !twice.port_filled,
            "second application still reports port_filled for input {input:?}"
        );
    }
}

#[test]
fn normalize_peer_address_leaves_a_malformed_trailing_colon_alone() {
    for input in ["mac:", "mac:ssh", "[::1]:x"] {
        let got = normalize_peer_address(input);
        assert_eq!(got.address, input);
        assert!(!got.port_filled);
        assert!(
            !got.address.contains("::4433"),
            "must not double up a colon: {:?}",
            got.address
        );
    }
}

#[test]
fn the_port_notice_names_the_default_port() {
    // Leading clause byte-identical to the pre-M9 wording — the
    // substring `init_trust.rs`/`trust_pairing_live.rs` count on.
    // `names_only_port`'s const-assert above already proves the notice
    // names `DEFAULT_PORT` and nothing else, so this unit only has to
    // pin the leading clause plus the three-part shape:
    // observation, impact, next-command.
    assert!(
        ADDRESS_PORT_ASSUMED_NOTICE
            .starts_with(&format!("assuming port {}", crate::serve::DEFAULT_PORT)),
        "leading clause must stay byte-identical: {ADDRESS_PORT_ASSUMED_NOTICE:?}"
    );
    // Two sentence-ending periods: observation+impact share one
    // sentence ("...goes."), next-command is the second ("...port.").
    assert_eq!(
        ADDRESS_PORT_ASSUMED_NOTICE.matches('.').count(),
        2,
        "observation+impact, then next-command, are two sentences: {ADDRESS_PORT_ASSUMED_NOTICE:?}"
    );
    assert!(
        ADDRESS_PORT_ASSUMED_NOTICE.contains("everywhere that address goes"),
        "must carry the impact clause: {ADDRESS_PORT_ASSUMED_NOTICE:?}"
    );
    assert!(
        ADDRESS_PORT_ASSUMED_NOTICE.contains("Re-run"),
        "must carry a next command: {ADDRESS_PORT_ASSUMED_NOTICE:?}"
    );
}

#[test]
fn add_list_find_and_remove() {
    let mut store = TrustStore::default();
    assert!(store.peers().is_empty());

    let (peer, created, updated) = store.add_peer(
        "mac",
        Some("mac.example:4433".into()),
        fp(b"one"),
        "2026-08-17T00:00:00Z".into(),
    );
    assert!(created);
    assert!(!updated);
    assert_eq!(peer.name, "mac");
    assert_eq!(peer.fingerprint, fp(b"one").to_string());
    assert_eq!(peer.address, "mac.example:4433");
    assert_eq!(store.peers().len(), 1);
    assert_eq!(store.find("mac"), Some(&peer));
    assert_eq!(store.find("nope"), None);

    assert!(store.remove("mac"));
    assert!(!store.remove("mac"));
    assert!(store.peers().is_empty());
}

#[test]
fn re_adding_with_the_same_address_is_a_pure_no_op() {
    let mut store = TrustStore::default();
    let (first, created, updated) = store.add_peer(
        "mac",
        Some("a:1".into()),
        fp(b"one"),
        "2026-08-17T00:00:00Z".into(),
    );
    assert!(created);
    assert!(!updated);

    // Same fingerprint, same address again.
    let (again, created, updated) = store.add_peer(
        "mac",
        Some("a:1".into()),
        fp(b"one"),
        "2026-08-18T00:00:00Z".into(),
    );
    assert!(!created);
    assert!(!updated);
    assert_eq!(again, first);
}

/// A *different* fingerprint must not silently re-pin, and must not
/// touch the stored address either — a fingerprint mismatch is a hard
/// no-op on the whole entry (`PLAN.md` M7 Step 2 decision B: identity
/// rebind is a deliberate `remove` + `add`, never a side effect).
#[test]
fn re_adding_with_a_different_fingerprint_never_overwrites() {
    let mut store = TrustStore::default();
    let (first, ..) = store.add_peer(
        "mac",
        Some("a:1".into()),
        fp(b"one"),
        "2026-08-17T00:00:00Z".into(),
    );

    let (conflicting, created, updated) = store.add_peer(
        "mac",
        Some("b:2".into()),
        fp(b"two"),
        "2026-08-19T00:00:00Z".into(),
    );
    assert!(!created);
    assert!(!updated);
    assert_eq!(conflicting, first);
    assert_eq!(store.peers().len(), 1);
    assert_eq!(
        store.find("mac").unwrap().fingerprint,
        fp(b"one").to_string()
    );
    assert_eq!(store.find("mac").unwrap().address, "a:1");
}

/// M7 Step 2 decision B, the address-refresh path itself: same name,
/// same fingerprint, a *different* address overwrites the stored
/// address in place — the M6 mobility campaign backlog item (host
/// address changed; a client re-runs `trust add` with the same
/// identity to follow it) reproduced at the `TrustStore` level.
#[test]
fn re_adding_with_the_same_fingerprint_and_a_new_address_updates_in_place() {
    let mut store = TrustStore::default();
    let (first, created, updated) = store.add_peer(
        "mac",
        Some("old.example:4433".into()),
        fp(b"one"),
        "2026-08-17T00:00:00Z".into(),
    );
    assert!(created);
    assert!(!updated);

    let (moved, created, updated) = store.add_peer(
        "mac",
        Some("new.example:5555".into()),
        fp(b"one"),
        "2026-08-19T00:00:00Z".into(),
    );
    assert!(!created, "identity already pinned — never re-created");
    assert!(updated, "address must be reported as updated");
    assert_eq!(moved.address, "new.example:5555");
    assert_eq!(moved.name, first.name);
    assert_eq!(moved.fingerprint, first.fingerprint);
    // `added_at` records when the *identity* was first pinned, not
    // when the address last moved — untouched by the update.
    assert_eq!(moved.added_at, first.added_at);
    assert_eq!(store.peers().len(), 1, "still one entry, not a duplicate");
    assert_eq!(store.find("mac"), Some(&moved));

    // Omitting `--address` entirely on a further re-add must not clear
    // the address back out — only an explicit *different* address
    // triggers the update path.
    let (unchanged, created, updated) =
        store.add_peer("mac", None, fp(b"one"), "2026-08-20T00:00:00Z".into());
    assert!(!created);
    assert!(!updated);
    assert_eq!(unchanged.address, "new.example:5555");
}

/// [`TrustStore::add_ca`]'s own created/updated tri-state, mirroring
/// [`TrustStore::add_peer`]'s tests: new name creates, same name +
/// identical PEM is a pure no-op, same name + a different PEM updates
/// in place (`docs/adr/0008-private-ca-cert-issuance.md` §6).
#[test]
fn add_ca_creates_then_is_idempotent_then_updates_on_a_changed_pem() {
    let mut store = TrustStore::default();
    assert!(store.cas().is_empty());

    let pem_a = pem::encode(pem::CERTIFICATE, b"root a");
    let (entry, created, updated) = store.add_ca("local", pem_a.clone());
    assert!(created);
    assert!(!updated);
    assert_eq!(entry.name, "local");
    assert_eq!(entry.cert_pem, pem_a);
    assert_eq!(store.cas().len(), 1);

    // Same name, identical PEM again: a pure no-op.
    let (again, created, updated) = store.add_ca("local", pem_a.clone());
    assert!(!created);
    assert!(!updated);
    assert_eq!(again, entry);
    assert_eq!(store.cas().len(), 1);

    // Same name, a different PEM: overwritten in place, not duplicated.
    let pem_b = pem::encode(pem::CERTIFICATE, b"root b");
    let (moved, created, updated) = store.add_ca("local", pem_b.clone());
    assert!(!created, "same name — never re-created");
    assert!(
        updated,
        "a changed PEM under the same name must be reported as updated"
    );
    assert_eq!(moved.name, "local");
    assert_eq!(moved.cert_pem, pem_b);
    assert_eq!(store.cas().len(), 1, "still one entry, not a duplicate");
    assert_eq!(store.cas()[0].cert_pem, pem_b);
}

/// A distinct name never collides with an existing one, even if it
/// happens to carry the identical PEM (a name, not a fingerprint, is
/// the dedup key — a CA root has no principal of its own).
#[test]
fn add_ca_with_a_distinct_name_never_collides() {
    let mut store = TrustStore::default();
    let pem = pem::encode(pem::CERTIFICATE, b"shared root bytes");
    store.add_ca("local", pem.clone());
    let (entry, created, updated) = store.add_ca("partner", pem.clone());
    assert!(created);
    assert!(!updated);
    assert_eq!(entry.name, "partner");
    assert_eq!(store.cas().len(), 2);
}

#[test]
fn address_is_empty_when_absent_and_does_not_resolve_as_a_host() {
    let mut store = TrustStore::default();
    let (peer, ..) = store.add_peer("client-only", None, fp(b"c"), "t".into());
    assert_eq!(peer.address, "");
    assert!(store.find("client-only").is_some());
    assert!(store.resolve_host("client-only").is_none());

    store.add_peer("server", Some("h:4433".into()), fp(b"s"), "t".into());
    assert_eq!(store.resolve_host("server").unwrap().address, "h:4433");
    assert!(store.resolve_host("absent").is_none());
}

#[test]
fn missing_file_loads_as_empty_and_round_trips_with_a_ca_entry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");
    let loaded = TrustStore::load(&path).unwrap();
    assert!(loaded.peers().is_empty() && loaded.cas().is_empty());

    let mut store = TrustStore::default();
    store.add_peer(
        "mac",
        Some("mac.example:4433".into()),
        fp(b"one"),
        "2026-08-17T00:00:00Z".into(),
    );
    store.cas.push(CaEntry {
        name: "corp-root".into(),
        cert_pem: pem::encode(pem::CERTIFICATE, b"pretend der"),
    });
    store.save(&path).unwrap();

    let back = TrustStore::load(&path).unwrap();
    assert_eq!(back, store);
    assert_eq!(back.cas()[0].name, "corp-root");
    assert_eq!(back.parsed_cas().len(), 1);
}

#[cfg(unix)]
#[test]
fn saved_store_is_private() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cfg/trust.toml");
    TrustStore::default().save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let dir_mode = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o700);
}

#[test]
fn malformed_store_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");
    std::fs::write(&path, "[[peer]]\nname = ").unwrap();
    let err = TrustStore::load(&path).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(!err.retryable);
}

#[test]
fn shared_store_reloads_when_the_file_mtime_moves() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");

    let mut store = TrustStore::default();
    store.add_peer("first", None, fp(b"one"), "t".into());
    store.save(&path).unwrap();

    let shared = SharedTrustStore::open(&path).unwrap();
    assert_eq!(
        shared.lookup_pin(&fp(b"one")),
        Some(Principal::Device("first".into()))
    );
    assert_eq!(shared.lookup_pin(&fp(b"two")), None);

    // Rewrite with an extra pin and push the mtime forward explicitly,
    // so the test never depends on filesystem timestamp granularity.
    store.add_peer("second", None, fp(b"two"), "t".into());
    store.save(&path).unwrap();
    let bumped = SystemTime::now() + std::time::Duration::from_secs(5);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(bumped)
        .unwrap();

    assert_eq!(
        shared.lookup_pin(&fp(b"two")),
        Some(Principal::Device("second".into())),
        "a changed trust.toml must be picked up without a restart"
    );
    assert_eq!(shared.snapshot().peers().len(), 2);
}

/// **`PLAN.md` M7 Step 2 P2-2, regression.** An mtime-only invalidator
/// is fail-open on a coarse-granularity filesystem (HFS+, exFAT/FAT,
/// some SMB/NFS mounts, 1-2s resolution): two edits landing in the same
/// tick share an mtime, so a check gated on `mtime != cached_mtime`
/// alone would never notice the second edit. This pins the file's mtime
/// back to its pre-edit value with [`std::fs::FileTimes`] — simulating
/// exactly that collision deterministically, no timing dependency — and
/// asserts the reload happens anyway, because `refresh` now compares
/// full file *content* on every call, never gated on `mtime`.
#[test]
fn refresh_reloads_on_a_content_change_even_when_the_mtime_does_not_move() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");

    let mut store = TrustStore::default();
    store.add_peer("first", None, fp(b"one"), "t".into());
    store.save(&path).unwrap();

    let shared = SharedTrustStore::open(&path).unwrap();
    assert_eq!(
        shared.lookup_pin(&fp(b"one")),
        Some(Principal::Device("first".into()))
    );

    // The mtime the store was opened with — the value a same-tick edit
    // on a coarse filesystem would collide on.
    let pinned_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();

    // Different content (peer "second" instead of "first"), written
    // normally (so its natural mtime is "now", not `pinned_mtime`)...
    let mut store2 = TrustStore::default();
    store2.add_peer("second", None, fp(b"two"), "t".into());
    store2.save(&path).unwrap();

    // ...then pinned back to the exact mtime the cache already has,
    // reproducing the same-tick collision without depending on the
    // filesystem's actual timestamp resolution or any sleep.
    let file = std::fs::File::options().write(true).open(&path).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(pinned_mtime))
        .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        pinned_mtime,
        "test setup: the mtime must be pinned back to the cached value"
    );

    // mtime is unchanged from the cached snapshot; content is not. The
    // reload must still happen — content is the final arbiter.
    assert_eq!(
        shared.lookup_pin(&fp(b"one")),
        None,
        "a same-mtime content change must drop the old pin"
    );
    assert_eq!(
        shared.lookup_pin(&fp(b"two")),
        Some(Principal::Device("second".into())),
        "a same-mtime content change must pick up the new pin"
    );
}

#[test]
fn shared_store_keeps_the_last_good_snapshot_on_a_broken_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");
    let mut store = TrustStore::default();
    store.add_peer("first", None, fp(b"one"), "t".into());
    store.save(&path).unwrap();

    let shared = SharedTrustStore::open(&path).unwrap();
    assert!(shared.lookup_pin(&fp(b"one")).is_some());

    std::fs::write(&path, "[[peer]]\nname = ").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() + std::time::Duration::from_secs(5))
        .unwrap();

    assert!(
        shared.lookup_pin(&fp(b"one")).is_some(),
        "a broken reload must not drop existing pins"
    );
}

#[test]
fn unparsable_pin_is_ignored_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");
    std::fs::write(
        &path,
        format!(
            "[[peer]]\nname = \"bad\"\nfingerprint = \"nonsense\"\naddress = \"\"\nadded_at = \"t\"\n\n\
             [[peer]]\nname = \"good\"\nfingerprint = \"{}\"\naddress = \"\"\nadded_at = \"t\"\n",
            fp(b"good")
        ),
    )
    .unwrap();

    let shared = SharedTrustStore::open(&path).unwrap();
    assert_eq!(
        shared.lookup_pin(&fp(b"good")),
        Some(Principal::Device("good".into()))
    );
    assert_eq!(shared.snapshot().peers().len(), 2);
}

#[test]
fn shared_store_opens_a_missing_file_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    let shared = SharedTrustStore::open(dir.path().join("trust.toml")).unwrap();
    assert!(shared.snapshot().peers().is_empty());
    assert!(shared.ca_roots().is_empty());
    assert_eq!(shared.lookup_pin(&fp(b"x")), None);
}

/// Regression for `PLAN.md` M7 Step 7-1's S1/general lost-update fix:
/// 8 threads, each doing a full `TrustStore::lock` → `load` →
/// `add_peer` → `save` cycle for a distinct peer, must not lose each
/// other's addition. Locking only around `save` (the pre-Step-7-1
/// state) would let a later writer's `save` silently overwrite an
/// earlier writer's still-unseen addition with a stale copy —
/// mirrors `crate::resume`'s own
/// `concurrent_writers_do_not_lose_each_others_entries`, the
/// precedent this lock was lifted from.
#[test]
fn concurrent_full_rmw_cycles_do_not_lose_each_others_peers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");
    let mut threads = Vec::new();
    for i in 0..8u8 {
        let path = path.clone();
        threads.push(std::thread::spawn(move || {
            let _lock = TrustStore::lock(&path).unwrap();
            let mut store = TrustStore::load(&path).unwrap();
            store.add_peer(
                format!("peer-{i}"),
                None,
                fp(&[i; 4]),
                "2026-08-17T00:00:00Z".into(),
            );
            store.save(&path).unwrap();
        }));
    }
    for t in threads {
        t.join().expect("writer");
    }
    let final_store = TrustStore::load(&path).unwrap();
    assert_eq!(
        final_store.peers().len(),
        8,
        "a concurrent read-modify-write lost a peer"
    );
}

/// Regression for `PLAN.md` M7 Step 7-1's S1 scenario specifically: a
/// pairing response's `add_peer` and an operator's concurrent `trust
/// remove` must not race into "the removed peer comes back" — the
/// worst outcome on this step's list, a revoked trust decision
/// silently un-revoking itself. This is the `TrustStore`-level
/// equivalent of the real race (`qsh serve`'s pairing responder vs. a
/// `qsh trust remove` CLI process); driving the actual server accept
/// loop concurrently with a CLI subprocess is integration-test
/// territory this crate's unit tests don't reach.
#[test]
fn a_concurrent_add_never_resurrects_a_concurrent_remove() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");

    let mut seed = TrustStore::default();
    seed.add_peer(
        "old-laptop",
        None,
        fp(b"old"),
        "2026-08-17T00:00:00Z".into(),
    );
    seed.save(&path).unwrap();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let remover = {
        let path = path.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let _lock = TrustStore::lock(&path).unwrap();
            let mut store = TrustStore::load(&path).unwrap();
            store.remove("old-laptop");
            store.save(&path).unwrap();
        })
    };
    let adder = {
        let path = path.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let _lock = TrustStore::lock(&path).unwrap();
            let mut store = TrustStore::load(&path).unwrap();
            store.add_peer(
                "new-device",
                None,
                fp(b"new"),
                "2026-08-17T00:00:01Z".into(),
            );
            store.save(&path).unwrap();
        })
    };
    remover.join().expect("remover");
    adder.join().expect("adder");

    let final_store = TrustStore::load(&path).unwrap();
    assert!(
        final_store.find("old-laptop").is_none(),
        "a removed peer was resurrected by a concurrent pairing write"
    );
    assert!(
        final_store.find("new-device").is_some(),
        "a concurrent addition was lost"
    );
}

/// Regression for `PLAN.md` M7 Step 7-1's file-corruption fix in
/// `crate::config::write_private_file_io` (the writer-scoped temp
/// ticket): many concurrent `save` calls racing the very same path,
/// deliberately **without** `TrustStore::lock` — every real call site
/// now holds it, but this isolates the temp-file ticket's own
/// guarantee from the lock's. Before the ticket, every writer shared
/// the same `.tmp<pid>` name: whichever writer's `rename` lost the
/// race hit `ENOENT` (its target already moved by the winner) rather
/// than a merely lost update, and depending on how the two writers'
/// writes interleaved on that one shared inode before either
/// renamed, the file that *did* land could carry bytes from more
/// than one writer — a corrupt `trust.toml`, not just a stale one.
///
/// Repeated 16 times (fresh path each round): a standalone reproduction
/// outside this repo (`PLAN.md` M7 Step 7-1 검증 라운드 A5) measured the
/// per-round corruption rate at 8/40 (20%) once the ticket is removed —
/// a single round only catches a reverted ticket about 4 times out of
/// 5. 16 independent rounds raise that to `1 - 0.8^16 ≈ 97%`, without
/// which this test's pass/fail is closer to a coin flip than a
/// regression gate for the one property this diff is graded on.
#[test]
fn concurrent_saves_to_the_same_path_never_corrupt_the_file() {
    let dir = tempfile::tempdir().unwrap();
    const WRITERS: u8 = 24;
    const ROUNDS: u32 = 16;

    for round in 0..ROUNDS {
        let path = dir.path().join(format!("trust-{round}.toml"));

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS as usize));
        let mut threads = Vec::new();
        for i in 0..WRITERS {
            let path = path.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let mut store = TrustStore::default();
                for j in 0..32u8 {
                    store.add_peer(
                        format!("round-{round}-writer-{i}-peer-{j}"),
                        None,
                        fp(&[i, j]),
                        "2026-08-17T00:00:00Z".into(),
                    );
                }
                barrier.wait();
                store.save(&path).unwrap();
                store
            }));
        }
        let candidates: Vec<TrustStore> = threads
            .into_iter()
            .map(|t| t.join().expect("writer"))
            .collect();

        let final_store = TrustStore::load(&path)
            .expect("the file must always be valid, parseable TOML, never corrupted");
        assert!(
            candidates.contains(&final_store),
            "round {round}: final trust.toml matches none of the writers exactly — \
             bytes from two writers were interleaved into it"
        );
    }
}
