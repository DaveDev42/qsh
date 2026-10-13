use super::*;
use qsh_transport::Fingerprint;

#[test]
fn allow_all_pinned_allows_pinned_peers_only() {
    let acl = AllowAllPinned;
    assert_eq!(
        acl.check(
            &Requester::new(&Principal::Device("laptop".into()), AuthPath::Pin, None),
            Action::ExecRun,
            ResourceRef::unowned("exec")
        )
        .decision,
        Decision::Allow
    );
    assert_eq!(
        acl.check(
            &Requester::new(
                &Principal::Fingerprint(Fingerprint::of_spki_der(b"k")),
                AuthPath::Pin,
                None
            ),
            Action::ExecRun,
            ResourceRef::unowned("exec")
        )
        .decision,
        Decision::Allow
    );
    // CA-asserted user: not pinned → denied under the interim policy.
    assert_eq!(
        acl.check(
            &Requester::new(&Principal::User("dave".into()), AuthPath::Ca, None),
            Action::ExecRun,
            ResourceRef::unowned("exec")
        )
        .decision,
        Decision::Deny
    );
}

#[test]
fn allow_all_pinned_denies_ca_issued_device_principal() {
    // A CA-signed leaf whose SAN is `qsh://device/laptop` yields a
    // Device principal that *looks* pinned but was never pinned. The
    // interim policy must key on the auth path, not the principal shape.
    assert_eq!(
        AllowAllPinned
            .check(
                &Requester::new(&Principal::Device("laptop".into()), AuthPath::Ca, None),
                Action::ExecRun,
                ResourceRef::unowned("exec")
            )
            .decision,
        Decision::Deny
    );
}

#[test]
fn deny_all_denies_everything() {
    for path in [AuthPath::Pin, AuthPath::Ca] {
        assert_eq!(
            DenyAll
                .check(
                    &Requester::new(&Principal::Device("x".into()), path, None),
                    Action::ExecRun,
                    ResourceRef::unowned("exec")
                )
                .decision,
            Decision::Deny
        );
    }
}

/// M5 plan Step 5 (2473c88)'s interim invariant: `AllowAllPinned` must keep
/// denying a non-owner on an owned resource exactly as M3's hardcoded
/// `require_opener` gate did — production still runs this authorizer,
/// not a real `Policy`, until Step 6.
#[test]
fn allow_all_pinned_denies_a_pinned_non_owner_on_an_owned_resource() {
    let acl = AllowAllPinned;
    let owner_key = opener_key(&Principal::Device("laptop".into()), AuthPath::Pin);
    let verdict = acl.check(
        &Requester::new(&Principal::Device("desktop".into()), AuthPath::Pin, None),
        Action::SessionControl,
        ResourceRef {
            canonical_path: None,
            id: "sess-1",
            owner: Some(&owner_key),
        },
    );
    assert_eq!(verdict.decision, Decision::Deny);

    // The owner itself is unaffected.
    let verdict = acl.check(
        &Requester::new(&Principal::Device("laptop".into()), AuthPath::Pin, None),
        Action::SessionControl,
        ResourceRef {
            canonical_path: None,
            id: "sess-1",
            owner: Some(&owner_key),
        },
    );
    assert_eq!(verdict.decision, Decision::Allow);
}

/// An owned resource never leaks to a request with a *different*
/// `auth_path` even when the principal string matches — `opener_key`
/// folds `auth_path` in for exactly this reason (its own doc).
#[test]
fn allow_all_pinned_denies_a_ca_leaf_asserting_the_pinned_owners_principal() {
    let acl = AllowAllPinned;
    let owner_key = opener_key(&Principal::Device("laptop".into()), AuthPath::Pin);
    let verdict = acl.check(
        &Requester::new(&Principal::Device("laptop".into()), AuthPath::Ca, None),
        Action::SessionControl,
        ResourceRef {
            canonical_path: None,
            id: "sess-1",
            owner: Some(&owner_key),
        },
    );
    assert_eq!(verdict.decision, Decision::Deny);
}

/// `resource.owner: None` (`exec.run`, `host.reverse`, `forward.local`
/// — no owner concept) is never filtered by ownership: a pinned peer
/// is allowed regardless of who "owns" it, because nothing does.
#[test]
fn allow_all_pinned_never_filters_an_unowned_resource() {
    let acl = AllowAllPinned;
    let verdict = acl.check(
        &Requester::new(&Principal::Device("desktop".into()), AuthPath::Pin, None),
        Action::ExecRun,
        ResourceRef::unowned("exec"),
    );
    assert_eq!(verdict.decision, Decision::Allow);
}

#[test]
fn action_and_decision_strings() {
    assert_eq!(Action::ExecRun.as_str(), "exec.run");
    // CLI.md §2.5 mapping table / PRD §9, verbatim.
    assert_eq!(Action::SessionOpen.as_str(), "session.open");
    assert_eq!(Action::SessionList.as_str(), "session.list");
    assert_eq!(Action::SessionAttach.as_str(), "session.attach");
    assert_eq!(Action::SessionControl.as_str(), "session.control");
    assert_eq!(Action::HostReverse.as_str(), "host.reverse");
    assert_eq!(Action::ForwardLocal.as_str(), "forward.local");
    assert_eq!(Action::ForwardRemote.as_str(), "forward.remote");
    assert_eq!(Action::ForwardSocks.as_str(), "forward.socks");
    assert_eq!(Action::FileRead.as_str(), "file.read");
    assert_eq!(Action::FileWrite.as_str(), "file.write");
    let strings: std::collections::BTreeSet<&str> =
        Action::ALL.iter().map(|a| a.as_str()).collect();
    assert_eq!(strings.len(), Action::ALL.len(), "distinct strings");
    // PRD §9 lists exactly 11 actions; pin the count directly rather
    // than only the distinctness above, so a future removal (as
    // opposed to a duplicate) is caught here too.
    assert_eq!(Action::ALL.len(), 11, "PRD §9 defines 11 actions");
    // `ALL` is what an M5 policy file will be validated against, so a
    // new action that never made it into the array is a silent hole:
    // name the newcomer explicitly rather than trusting the count.
    assert!(
        Action::ALL.contains(&Action::ForwardLocal),
        "forward.local must be in Action::ALL"
    );
    assert!(
        Action::ALL.contains(&Action::ForwardRemote),
        "forward.remote must be in Action::ALL"
    );
    assert!(
        Action::ALL.contains(&Action::ForwardSocks),
        "forward.socks must be in Action::ALL"
    );
    assert!(
        Action::ALL.contains(&Action::FileRead),
        "file.read must be in Action::ALL"
    );
    assert!(
        Action::ALL.contains(&Action::FileWrite),
        "file.write must be in Action::ALL"
    );
    assert_eq!(Decision::Allow.as_str(), "allow");
    assert_eq!(Decision::Deny.as_str(), "deny");
    assert!(Decision::Allow.is_allow());
    assert!(!Decision::Deny.is_allow());
}

#[test]
fn action_from_str_round_trips_action_all_and_rejects_wildcards_and_garbage() {
    for action in Action::ALL {
        assert_eq!(action.as_str().parse::<Action>().unwrap(), action);
    }
    // A `.*` family wildcard is `acl.toml` grammar, not a concrete
    // action `--action` accepts.
    for bad in ["session.*", "session.open2", "SESSION.OPEN", "", "exec"] {
        assert!(bad.parse::<Action>().is_err(), "{bad:?}");
    }
}

#[test]
fn is_always_denied_is_exactly_the_undrivable_trio() {
    // docs/ROADMAP.md §3 deferred-feature guardrail table: exactly
    // `forward.socks`/`file.read`/`file.write` are "defined but always
    // denied" — every other action is a normal, policy-evaluated one.
    // The three share the outcome but not the reason: `file.read`/
    // `file.write` are P1-deferred (no wire op exists yet), while
    // `forward.socks` is undrivable by design — `-D` authorizes every
    // `CONNECT` as `forward.local` instead (ADR-0019 결정 6).
    let always_denied: std::collections::HashSet<Action> = Action::ALL
        .iter()
        .copied()
        .filter(|a| a.is_always_denied())
        .collect();
    assert_eq!(
        always_denied,
        std::collections::HashSet::from([
            Action::ForwardSocks,
            Action::FileRead,
            Action::FileWrite,
        ])
    );
    for a in [Action::ForwardSocks, Action::FileRead, Action::FileWrite] {
        assert!(a.is_always_denied(), "{a} must be always-denied");
    }
    for a in [
        Action::ExecRun,
        Action::SessionOpen,
        Action::SessionList,
        Action::SessionAttach,
        Action::SessionControl,
        Action::HostReverse,
        Action::ForwardLocal,
        Action::ForwardRemote,
    ] {
        assert!(!a.is_always_denied(), "{a} must not be always-denied");
    }
}

/// F6 (M5 Step 4 adversarial review): a machine-checked pin of
/// [`PERMISSION_DENIED_MESSAGE`]'s own non-distinguishing invariant
/// (the constant's doc comment, in prose) — the literal wording is
/// exactly the fixed sentence, and it contains none of the tokens a
/// future edit might accidentally reintroduce to name what was
/// denied: no action string from today's vocabulary, no brace (no
/// interpolated field ever crept in), and none of `"session"`/
/// `"forward"`/`"exec"`/`"host."` beyond what the fixed wording itself
/// legitimately contains (it does say "host", bare, as in "on this
/// host" — never "host.", which would suggest a `host.*` action name).
#[test]
fn permission_denied_message_names_no_action_and_stays_the_fixed_wording() {
    assert_eq!(
        PERMISSION_DENIED_MESSAGE, "peer is not allowed to perform this operation on this host",
        "PERMISSION_DENIED_MESSAGE must stay exactly this literal — any edit here is a \
         deliberate wording change, not a drift"
    );
    for action in Action::ALL {
        assert!(
            !PERMISSION_DENIED_MESSAGE.contains(action.as_str()),
            "PERMISSION_DENIED_MESSAGE must not name {action} — that would turn the \
             refusal into a capability-enumeration oracle (see the constant's own doc)"
        );
    }
    for token in ["{", "}", "session", "forward", "exec", "host."] {
        assert!(
            !PERMISSION_DENIED_MESSAGE.contains(token),
            "PERMISSION_DENIED_MESSAGE must not contain {token:?} — the fixed wording \
             has no interpolated field and names no action family"
        );
    }
}

#[test]
fn action_vocabulary_has_no_cross_family_string_prefixes() {
    // F5 (M5 Step 2 adversarial review): the dot-boundary invariant
    // every `ActionPattern::Prefix` match (`starts_with`) leans on —
    // no action's string is a strict prefix of another's, and every
    // action's family segment (up to and including its first `.`) is
    // a real, non-empty dotted family. Today's 11-action vocabulary
    // happens to satisfy this by construction, which made the
    // dot-boundary mutation class (matching by raw `starts_with`
    // instead of a dot-bounded prefix) inert against every other
    // test in this crate — this test is what would actually catch a
    // future action name that broke the invariant.
    for a in Action::ALL {
        for b in Action::ALL {
            if a == b {
                continue;
            }
            assert!(
                !b.as_str().starts_with(a.as_str()),
                "{a} is a strict prefix of {b}, which would make a `{a}` rule \
                 accidentally cover {b} too"
            );
        }
        let full = a.as_str();
        let dot = full.find('.').unwrap_or_else(|| panic!("{a} has no dot"));
        let prefix = &full[..=dot];
        assert!(
            prefix.ends_with('.'),
            "{a}'s family prefix must end with '.'"
        );
        assert!(
            prefix.len() > 1,
            "{a}'s family prefix must have a non-empty stem before the dot"
        );
    }
}
