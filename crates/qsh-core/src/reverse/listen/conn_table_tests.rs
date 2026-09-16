use super::*;

/// A cheap stand-in for [`Connection`] — an id plus a shared log of
/// which ids got "closed" — so [`ConnTable::publish`]'s race-freedom
/// claim is testable without a real QUIC connection ([`ConnTable`] is
/// generic exactly so this is possible).
#[derive(Clone, Debug, PartialEq, Eq)]
struct MockConn(u32);

fn close(log: &Mutex<Vec<u32>>, conn: MockConn) {
    log.lock().unwrap_or_else(|e| e.into_inner()).push(conn.0);
}

/// Both possible continuation orders described in [`ConnTable::publish`]'s
/// own doc comment converge on the same end state. `order` selects which
/// of the two concurrent registrations' `finish_registration` calls
/// reaches `publish` first — the whole point being that it must not
/// matter which one does.
fn replay(publish_gen2_first: bool) -> (u32, Vec<u32>) {
    let table = ConnTable::new();
    let log = Mutex::new(Vec::new());
    // Pre-existing occupant at generation 0 — the connection a fresh
    // reconnect (generation 1) is about to replace.
    match table.publish("name".to_string(), 0, MockConn(0)) {
        Published::Installed(None) => {}
        other => panic!("first publish must install cleanly: {other:?}"),
    }

    let call = |generation: u64, id: u32| match table.publish(
        "name".to_string(),
        generation,
        MockConn(id),
    ) {
        Published::Installed(old) => {
            if let Some(old) = old {
                close(&log, old);
            }
        }
        Published::Superseded(mine) => close(&log, mine),
    };

    if publish_gen2_first {
        call(2, 2);
        call(1, 1);
    } else {
        call(1, 1);
        call(2, 2);
    }

    let occupant = table.lock().get("name").map(|(g, _)| *g).unwrap();
    let mut closed = log.into_inner().unwrap_or_else(|e| e.into_inner());
    closed.sort_unstable();
    (occupant as u32, closed)
}

impl std::fmt::Debug for Published<MockConn> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Published::Installed(old) => write!(f, "Installed({old:?})"),
            Published::Superseded(v) => write!(f, "Superseded({v:?})"),
        }
    }
}

#[test]
fn admit_order_continuation_order_ends_with_the_newest_generation_open() {
    let (occupant, closed) = replay(false);
    assert_eq!(occupant, 2, "the newest generation must be the occupant");
    assert_eq!(closed, vec![0, 1], "everything else closed exactly once");
}

#[test]
fn reversed_continuation_order_still_ends_with_the_newest_generation_open() {
    // This is the exact scenario `PLAN.md` M3 Step 4 (4) names: the
    // higher-generation registration's `finish_registration` reaches
    // `publish` first. The old `(name, generation)`-keyed table leaked
    // generation 1's connection here; this table must not.
    let (occupant, closed) = replay(true);
    assert_eq!(occupant, 2, "the newest generation must be the occupant");
    assert_eq!(
        closed,
        vec![0, 1],
        "generation 1's own connection must close itself, not leak"
    );
}

#[test]
fn remove_if_only_removes_a_matching_generation() {
    let table: ConnTable<MockConn> = ConnTable::new();
    table.publish("name".to_string(), 0, MockConn(0));
    assert!(
        !table.remove_if("name", 1),
        "generation mismatch must not remove"
    );
    assert_eq!(table.len(), 1);
    assert!(table.remove_if("name", 0), "matching generation removes");
    assert_eq!(table.len(), 0);
}

#[test]
fn remove_if_on_an_unknown_name_is_a_no_op() {
    let table: ConnTable<MockConn> = ConnTable::new();
    assert!(!table.remove_if("nobody-home", 0));
}

fn sample_entry(generation: u64) -> registry::ReverseEntry {
    registry::ReverseEntry {
        name: "name".to_string(),
        fingerprint: "sha256:abc".to_string(),
        principal: "device:target".to_string(),
        address: "127.0.0.1:0".parse().unwrap(),
        capabilities: Vec::new(),
        registered_at: "2026-01-01T00:00:00Z".to_string(),
        generation,
        state: registry::EntryState::Live,
        stale_since: None,
    }
}

// `rollback_target` — the fix for the adversarial-review "permanent
// phantom host" finding (`Listen::register_connection`'s rollback
// branch): a `RegisterOutcome::replaced_entry` snapshot must only be
// restored while `conns` still backs it with a live connection.

#[test]
fn rollback_target_keeps_the_snapshot_while_its_connection_is_still_the_occupant() {
    let table = ConnTable::new();
    table.publish("name".to_string(), 0, MockConn(0));
    let prev = sample_entry(0);
    assert_eq!(
        rollback_target(&table, "name", Some(prev.clone())),
        Some(prev),
        "the connection it describes is still live — safe to restore"
    );
}

#[test]
fn rollback_target_drops_the_snapshot_once_its_connection_already_exited() {
    // Nothing published under `name`: the connection this snapshot
    // describes already ran its own `remove_if` and removed itself —
    // e.g. its watchdog declared the path dead in the window between
    // the admission this snapshot came from and the rollback.
    let table: ConnTable<MockConn> = ConnTable::new();
    let prev = sample_entry(0);
    assert_eq!(
        rollback_target(&table, "name", Some(prev)),
        None,
        "restoring a Live entry with no connection behind it must never happen"
    );
}

#[test]
fn rollback_target_drops_the_snapshot_once_a_further_generation_replaced_it() {
    let table = ConnTable::new();
    table.publish("name".to_string(), 2, MockConn(2));
    let prev = sample_entry(0);
    assert_eq!(
        rollback_target(&table, "name", Some(prev)),
        None,
        "generation 2 is the real occupant now — generation 0 must not come back"
    );
}

#[test]
fn rollback_target_passes_a_fresh_registrations_none_through_unchanged() {
    let table: ConnTable<MockConn> = ConnTable::new();
    assert_eq!(rollback_target(&table, "name", None), None);
}
