//! Where the rendezvous candidates come from (ADR-0054 decisions 4 and 5,
//! DoD 10): learning from a host's answer, `trust rendezvous`,
//! `--rendezvous`, and the modes that switch all of it off.

use qsh_proto::{ErrorCode, IdentityInitReq, KeyStoreMode, TrustAddReq, TrustSetRendezvousReq};
use qsh_transport::Fingerprint;

use crate::ops::test_support::temp_ops;
use crate::trust::TrustStore;

use super::{ClientPunch, PunchMode};

fn fp(n: u8) -> Fingerprint {
    Fingerprint::from_bytes([n; 32])
}

fn list(fps: &[Fingerprint]) -> Vec<Vec<u8>> {
    fps.iter().map(|f| f.as_bytes().to_vec()).collect()
}

/// A store with the host `b` (no address), and the candidates `r1`, `r2`
/// with addresses and `quiet` without one.
fn store() -> TrustStore {
    let mut store = TrustStore::default();
    let now = || "2026-11-09T00:00:00Z".to_string();
    store.add_peer("b", None, fp(1), now());
    store.add_peer("r1", Some("203.0.113.1:4433".into()), fp(2), now());
    store.add_peer("r2", Some("203.0.113.2:4433".into()), fp(3), now());
    store.add_peer("quiet", None, fp(4), now());
    store
}

fn hints(store: &TrustStore) -> Vec<String> {
    store.find("b").unwrap().rendezvous.clone()
}

/// Only fingerprints this device pins with an address are kept: an unpinned
/// one, an address-less pin, the host's own key and garbage are ignored.
#[test]
fn unpinned_and_addressless_fingerprints_are_ignored() {
    let mut store = store();
    let (count, changed) = store.learn_rendezvous(
        &fp(1),
        &list(&[fp(9), fp(4), fp(1), fp(2)])
            .into_iter()
            .chain([vec![1, 2, 3]])
            .collect::<Vec<_>>(),
    );
    assert!(changed);
    assert_eq!(count, 1);
    assert_eq!(hints(&store), vec![fp(2).to_string()]);
}

/// An answer with nothing usable writes nothing.
#[test]
fn an_answer_with_nothing_usable_changes_nothing() {
    let mut store = store();
    let before = store.clone();
    let (count, changed) = store.learn_rendezvous(&fp(1), &list(&[fp(9), fp(4)]));
    assert!(!changed);
    assert_eq!(count, 0);
    assert_eq!(store, before);
    // A host that is not pinned at all teaches nothing.
    let (_, changed) = store.learn_rendezvous(&fp(77), &list(&[fp(2)]));
    assert!(!changed);
}

/// The host's order is kept, newest first, older usable hints follow, and
/// the list stops at four.
#[test]
fn learned_hints_come_first_and_the_list_is_capped_at_four() {
    let mut store = store();
    store.add_peer(
        "r3",
        Some("203.0.113.3:4433".into()),
        fp(5),
        "2026-11-09T00:00:00Z".into(),
    );
    store.add_peer(
        "r4",
        Some("203.0.113.4:4433".into()),
        fp(6),
        "2026-11-09T00:00:00Z".into(),
    );
    store.add_peer(
        "r5",
        Some("203.0.113.5:4433".into()),
        fp(7),
        "2026-11-09T00:00:00Z".into(),
    );
    let (_, changed) = store.learn_rendezvous(&fp(1), &list(&[fp(2), fp(3)]));
    assert!(changed);
    assert_eq!(hints(&store), vec![fp(2).to_string(), fp(3).to_string()]);
    // The same answer again is no change.
    let (_, changed) = store.learn_rendezvous(&fp(1), &list(&[fp(2), fp(3)]));
    assert!(!changed);
    // A new answer is put in front; what it pushes past four falls off.
    let (count, changed) = store.learn_rendezvous(&fp(1), &list(&[fp(7), fp(6), fp(5)]));
    assert!(changed);
    assert_eq!(count, 4);
    assert_eq!(
        hints(&store),
        vec![
            fp(7).to_string(),
            fp(6).to_string(),
            fp(5).to_string(),
            fp(2).to_string()
        ]
    );
}

/// A hint whose pin lost its address no longer survives a merge.
#[test]
fn stale_hints_are_dropped_when_a_new_answer_merges() {
    let mut store = store();
    store.learn_rendezvous(&fp(1), &list(&[fp(2), fp(3)]));
    assert!(store.remove("r1"));
    let (_, changed) = store.learn_rendezvous(&fp(1), &list(&[fp(3)]));
    assert!(changed);
    assert_eq!(hints(&store), vec![fp(3).to_string()]);
}

/// A `trust.toml` written before the field existed loads, and saving it
/// does not invent a `rendezvous` key.
#[test]
fn a_trust_file_without_the_field_loads_and_saves_without_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.toml");
    std::fs::write(
        &path,
        format!(
            "[[peer]]\nname = \"old\"\nfingerprint = \"{}\"\naddress = \"h:1\"\nadded_at = \"2026-01-01T00:00:00Z\"\n",
            fp(1)
        ),
    )
    .unwrap();
    let store = TrustStore::load(&path).unwrap();
    assert!(store.find("old").unwrap().rendezvous.is_empty());
    store.save(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("rendezvous"), "{text}");

    // And a file that has it round-trips.
    std::fs::write(
        &path,
        format!(
            "[[peer]]\nname = \"b\"\nfingerprint = \"{}\"\naddress = \"\"\nadded_at = \"2026-01-01T00:00:00Z\"\nrendezvous = [\"{}\"]\n",
            fp(1),
            fp(2)
        ),
    )
    .unwrap();
    let store = TrustStore::load(&path).unwrap();
    assert_eq!(store.find("b").unwrap().rendezvous, vec![fp(2).to_string()]);
}

fn pin(ops: &crate::Ops, name: &str, address: Option<&str>, fingerprint: &Fingerprint) {
    ops.trust_add(TrustAddReq {
        name: name.into(),
        address: address.map(str::to_string),
        fingerprint: Some(fingerprint.to_string()),
        cert_pem: None,
        role: None,
    })
    .unwrap();
}

fn set_rendezvous(
    ops: &crate::Ops,
    name: &str,
    peers: &[&str],
    clear: bool,
) -> Result<qsh_proto::TrustSetRendezvousData, crate::ops::OpError> {
    ops.trust_set_rendezvous(TrustSetRendezvousReq {
        name: name.into(),
        rendezvous: peers.iter().map(|s| (*s).to_string()).collect(),
        clear,
    })
}

/// `trust rendezvous` sets, replaces and clears the list; a second identical
/// call writes nothing; the list is by fingerprint so a rename keeps it.
#[test]
fn trust_rendezvous_set_and_clear_round_trip() {
    let (_g, ops) = temp_ops();
    pin(&ops, "b", None, &fp(1));
    pin(&ops, "r1", Some("203.0.113.1:4433"), &fp(2));
    pin(&ops, "r2", Some("203.0.113.2:4433"), &fp(3));

    let set = set_rendezvous(&ops, "b", &["r2", "r1", "r2"], false).unwrap();
    assert_eq!(
        set.peer.rendezvous,
        vec![fp(3).to_string(), fp(2).to_string()],
        "the given order, without repeats"
    );
    let listed = ops.trust_list().unwrap();
    let b = listed.peers.iter().find(|p| p.name == "b").unwrap();
    assert_eq!(b.rendezvous, set.peer.rendezvous);

    // Renaming the relay keeps the hint, it is a fingerprint.
    ops.trust_rename(qsh_proto::TrustRenameReq {
        old: "r2".into(),
        new: "relay-two".into(),
    })
    .unwrap();
    let b = ops.trust_list().unwrap();
    assert_eq!(
        b.peers.iter().find(|p| p.name == "b").unwrap().rendezvous,
        vec![fp(3).to_string(), fp(2).to_string()]
    );

    let cleared = set_rendezvous(&ops, "b", &[], true).unwrap();
    assert!(cleared.peer.rendezvous.is_empty());
    let after = std::fs::read_to_string(ops.paths().trust_file()).unwrap();
    assert!(!after.contains("rendezvous"), "{after}");
}

#[test]
fn trust_rendezvous_refuses_what_cannot_relay() {
    let (_g, ops) = temp_ops();
    pin(&ops, "b", None, &fp(1));
    pin(&ops, "r1", Some("203.0.113.1:4433"), &fp(2));
    pin(&ops, "quiet", None, &fp(4));
    for (name, peers, clear, code) in [
        ("nobody", vec!["r1"], false, ErrorCode::HostNotFound),
        ("b", vec!["ghost"], false, ErrorCode::HostNotFound),
        ("b", vec!["quiet"], false, ErrorCode::HostNotFound),
        ("b", vec!["b"], false, ErrorCode::InvalidArgument),
        ("b", vec![], false, ErrorCode::InvalidArgument),
        ("b", vec!["r1"], true, ErrorCode::InvalidArgument),
        (
            "b",
            vec!["r1"; 5].into_iter().collect(),
            false,
            ErrorCode::InvalidArgument,
        ),
    ] {
        let err = set_rendezvous(&ops, name, &peers, clear).expect_err(name);
        assert_eq!(err.code, code, "{name} {peers:?} {clear}: {err:?}");
    }
    let listed = ops.trust_list().unwrap();
    assert!(
        listed.peers.iter().all(|p| p.rendezvous.is_empty()),
        "a refused call writes nothing"
    );
}

/// An identity so a plan can be built.
fn identity(ops: &crate::Ops) -> crate::LoadedIdentity {
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
        ..Default::default()
    })
    .unwrap();
    ops.load_identity().unwrap().unwrap()
}

fn candidate_names(plan: &super::PunchPlan) -> Vec<String> {
    plan.rendezvous.iter().map(|r| r.name.clone()).collect()
}

/// The pin's hints are the candidates when nothing is asked for on the
/// command line; `--rendezvous` replaces them; unusable hints make no plan.
#[test]
fn the_flag_overrides_the_pins_hints() {
    let (_g, ops) = temp_ops();
    let id = identity(&ops);
    pin(&ops, "b", None, &fp(1));
    pin(&ops, "r1", Some("203.0.113.1:4433"), &fp(2));
    pin(&ops, "r2", Some("203.0.113.2:4433"), &fp(3));
    pin(&ops, "other", Some("203.0.113.9:4433"), &fp(9));
    let trust = ops.open_trust().unwrap();

    // No hint and no flag: no plan at all (the route stays the direct dial).
    assert!(ops.punch_plan("b", &id, &trust).unwrap().is_none());

    set_rendezvous(&ops, "b", &["r2", "r1"], false).unwrap();
    let trust = ops.open_trust().unwrap();
    let plan = ops.punch_plan("b", &id, &trust).unwrap().expect("a plan");
    assert_eq!(candidate_names(&plan), ["r2", "r1"]);

    // `--rendezvous other`: only that one.
    let flagged = ops.clone().with_punch(ClientPunch {
        rendezvous: vec!["other".into()],
        ..ClientPunch::default()
    });
    let plan = flagged
        .punch_plan("b", &id, &trust)
        .unwrap()
        .expect("a plan");
    assert_eq!(candidate_names(&plan), ["other"]);

    // A flag naming something that is not pinned with an address is an error.
    for bad in ["ghost", "b"] {
        let flagged = ops.clone().with_punch(ClientPunch {
            rendezvous: vec![bad.into()],
            ..ClientPunch::default()
        });
        if bad == "b" {
            // The host itself is skipped like any other non-candidate.
            let plan = flagged
                .punch_plan("b", &id, &trust)
                .unwrap()
                .expect("a plan");
            assert!(candidate_names(&plan).is_empty());
        } else {
            let err = flagged.punch_plan("b", &id, &trust).expect_err(bad);
            assert_eq!(err.code, ErrorCode::HostNotFound);
        }
    }
    pin(&ops, "quiet", None, &fp(4));
    let trust = ops.open_trust().unwrap();
    let flagged = ops.clone().with_punch(ClientPunch {
        rendezvous: vec!["quiet".into()],
        ..ClientPunch::default()
    });
    assert_eq!(
        flagged
            .punch_plan("b", &id, &trust)
            .expect_err("no address")
            .code,
        ErrorCode::HostNotFound
    );
}

/// A hint whose pin was removed or has lost its address is skipped, and a
/// list with nothing usable makes no plan.
#[test]
fn hints_are_checked_against_the_pins_every_time() {
    let (_g, ops) = temp_ops();
    let id = identity(&ops);
    pin(&ops, "b", None, &fp(1));
    pin(&ops, "r1", Some("203.0.113.1:4433"), &fp(2));
    set_rendezvous(&ops, "b", &["r1"], false).unwrap();
    ops.trust_remove("r1").unwrap();
    let trust = ops.open_trust().unwrap();
    let plan = ops.punch_plan("b", &id, &trust).unwrap().expect("a plan");
    assert!(!plan.has_rendezvous(), "nobody usable is left");
    assert_eq!(
        plan.no_rendezvous().reason,
        super::GiveUpReason::NoRendezvous
    );
}

/// `--no-punch` and `[punch].mode = "off"` build no plan, and no learner.
#[test]
fn off_builds_no_plan_and_no_learner() {
    let (_g, ops) = temp_ops();
    let id = identity(&ops);
    pin(&ops, "b", None, &fp(1));
    pin(&ops, "r1", Some("203.0.113.1:4433"), &fp(2));
    set_rendezvous(&ops, "b", &["r1"], false).unwrap();
    let trust = ops.open_trust().unwrap();
    let learning = ClientPunch {
        learn_hints: true,
        ..ClientPunch::default()
    };
    let on = ops.clone().with_punch(learning.clone());
    assert!(on.punch_plan("b", &id, &trust).unwrap().is_some());
    assert!(on.hint_learner(&trust).is_some());
    // A library caller that did not ask to learn gets no learner.
    assert!(ops.hint_learner(&trust).is_none());

    // The flag.
    let flagged = ops.clone().with_punch(ClientPunch {
        mode: PunchMode::Off,
        ..learning.clone()
    });
    assert!(flagged.punch_plan("b", &id, &trust).unwrap().is_none());
    assert!(flagged.hint_learner(&trust).is_none());

    // The key.
    let path = ops.paths().config_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "[punch]\nmode = \"off\"\n").unwrap();
    assert!(on.punch_plan("b", &id, &trust).unwrap().is_none());
    assert!(on.hint_learner(&trust).is_none());

    // The flag wins over a key that says auto, and an unknown value is a
    // CONFIG_ERROR like any other key.
    std::fs::write(&path, "[punch]\nmode = \"auto\"\n").unwrap();
    assert!(on.punch_plan("b", &id, &trust).unwrap().is_some());
    assert!(flagged.punch_plan("b", &id, &trust).unwrap().is_none());
    std::fs::write(&path, "[punch]\nmode = \"sometimes\"\n").unwrap();
    assert_eq!(
        on.punch_plan("b", &id, &trust).expect_err("bad mode").code,
        ErrorCode::ConfigError
    );
}
