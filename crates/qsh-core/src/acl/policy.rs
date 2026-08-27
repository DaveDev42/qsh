//! The pure policy evaluator (`docs/design/architecture.md` §6,
//! `PLAN.md` M5 Step 2). Nothing in this module touches the filesystem or
//! the network — [`crate::acl::load`] is the only thing that turns
//! `acl.toml` into a [`Policy`], and nothing in production constructs a
//! [`Policy`] yet (`PLAN.md` M5 Step 6 wires it in; until then production
//! stays on [`super::AllowAllPinned`]).
//!
//! **Evaluation order is canonical and lives here, not in prose**
//! (`docs/design/architecture.md` §6):
//!
//! 1. [`crate::acl::Action::is_always_denied`] — checked before any rule is
//!    even looked at. `forward.socks`/`file.read`/`file.write` cannot be
//!    granted by any rule, wildcard or exact (`allow = ["forward.*"]` does
//!    not reach `forward.socks`).
//! 2. Principal exact match (`Rule::principal` against the connection's
//!    `Principal::to_string()`) **and** `auth_path` match. A rule that
//!    omits `auth_path` defaults to [`AuthPath::Pin`] and so never matches
//!    an [`AuthPath::Ca`] request (`PLAN.md` M5 §4.1 #2).
//! 3. Action pattern match — exact or trailing-`.*` family wildcard
//!    (`ActionPattern::matches`).
//! 4. `scope` judgment (`PLAN.md` M5 Step 5): `Scope::Any` always passes.
//!    `Scope::Owned` (the default) passes only when `resource.owner` is
//!    `None` (no owner concept — never filtered either way) or equals the
//!    requester's own [`super::opener_key`] — see [`Policy::decide`]'s
//!    doc for the rationale.
//!
//! First matching rule wins (allow-only grammar, so there is no
//! conflict to resolve by priority) and its array index becomes
//! [`Verdict::rule`]. No matching rule at all is [`Decision::Deny`].

use qsh_transport::{AuthPath, Principal};

use super::{Action, Authorizer, Decision, ResourceRef, opener_key};

/// A validated action-family prefix — dot included, non-empty stem —
/// the only value [`ActionPattern::Prefix`] can hold. `FamilyPrefix` is
/// `pub` (so `ActionPattern` can stay `pub` without tripping
/// `private_interfaces`), but its field is private and its only
/// constructor is `pub(crate)`, which is what actually makes the
/// dot-boundary invariant *enforced* rather than merely asserted in a
/// doc comment (F8, M5 Step 2 adversarial review): nothing outside this
/// crate, and nothing inside it besides [`crate::acl::load::
/// parse_action_pattern`] (the only real caller — test helpers that want
/// one go through [`FamilyPrefix::new`] too, same assertion), can
/// construct a `FamilyPrefix` — only pass around, match on, or re-store
/// one an in-crate caller already built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyPrefix(&'static str);

impl FamilyPrefix {
    /// Builds a family prefix, asserting the invariant every
    /// `ActionPattern::Prefix` must uphold. Cheap and called only at
    /// `acl.toml` load time (or in tests), so a full `assert!` — not
    /// `debug_assert!` — is the right cost/benefit: this is a security
    /// invariant (an unforgeable prefix is what keeps wildcard matching
    /// dot-bounded), not a hot-path check.
    pub(crate) fn new(prefix: &'static str) -> Self {
        assert!(
            prefix.ends_with('.') && prefix.len() > 1,
            "FamilyPrefix must end with '.' and have a non-empty stem, got {prefix:?}"
        );
        Self(prefix)
    }

    fn as_str(self) -> &'static str {
        self.0
    }
}

/// One `allow` entry inside a [`Rule`] — either exactly one action, or
/// every action in one dotted family (a trailing `.*` in `acl.toml`).
/// Never a mid-string glob: `docs/design/architecture.md` §6 permits only
/// these two shapes, and [`crate::acl::load`] rejects anything else at
/// load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionPattern {
    /// Matches exactly one action.
    Exact(Action),
    /// Matches every action whose dotted name starts with this family
    /// prefix, dot included (e.g. `"session."` for the `acl.toml` entry
    /// `"session.*"`). See [`FamilyPrefix`] for how that invariant is
    /// enforced rather than merely documented.
    Prefix(FamilyPrefix),
}

impl ActionPattern {
    /// Whether this pattern covers `action`.
    pub fn matches(&self, action: Action) -> bool {
        match *self {
            ActionPattern::Exact(a) => a == action,
            ActionPattern::Prefix(prefix) => action.as_str().starts_with(prefix.as_str()),
        }
    }
}

/// Whether a `scope`-bearing rule applies to any instance of a resource or
/// only ones `principal` owns. `PLAN.md` M5 §4.1 #3's default is
/// [`Scope::Owned`] — the safe default that reproduces M3's
/// opener-principal binding.
///
/// **Evaluated by [`Policy::decide`]'s ④ since `PLAN.md` M5 Step 5**: a
/// matched rule with `scope = "owned"` allows only when the resource's
/// owner ([`ResourceRef::owner`]) equals the requester's own
/// [`super::opener_key`] — `owner: None` (a resource kind with no owner
/// concept: `exec.run`, `host.reverse`, `forward.local`) is never filtered
/// either way, so `scope` is meaningless-but-harmless on those rows.
/// Before Step 5, [`ResourceRef`] carried no owner concept at all, so this
/// was parsed and preserved on every [`Rule`] but never consulted; that
/// Step 2-era behavior is now pinned by this module's
/// `scope_owned_is_not_evaluated_when_the_resource_has_no_owner` test
/// instead, since `owner: None` is still exactly "unfiltered".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// Only the resource's owner (Step 5) — the default.
    #[default]
    Owned,
    /// Any principal this rule otherwise admits.
    Any,
}

/// One `[[acl]]` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Exact-match principal string, `Principal::to_string()`'s format
    /// (`device:<name>` | `user:<name>` | `fp:sha256:<base64>`).
    pub principal: String,
    /// Which trust path this rule applies to. Defaults to
    /// [`AuthPath::Pin`] when `acl.toml` omits the key
    /// (`PLAN.md` M5 §4.1 #2).
    pub auth_path: AuthPath,
    /// Action patterns this rule grants (never empty — the loader rejects
    /// a rule with no `allow` entries).
    pub allow: Vec<ActionPattern>,
    /// Ownership scope, evaluated since `PLAN.md` M5 Step 5 (see
    /// [`Scope`]'s doc).
    pub scope: Scope,
}

/// The outcome of [`Policy::decide`]: an allow/deny [`Decision`] plus,
/// when a rule matched, that rule's array index in [`Policy::rules`] —
/// the same value [`crate::audit::AuditRecord::rule`] and `acl check`'s
/// `rule` field carry (`PLAN.md` M5 §4.1 #8: `Authorizer::check` returns
/// this instead of a bare [`Decision`] so the two never have to be
/// computed twice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Allow or deny.
    pub decision: Decision,
    /// Index of the matching rule; always `None` for a `Deny` (allow-only
    /// grammar — nothing ever matches and still denies) and for the
    /// always-deny gate (which never gets far enough to look at rules).
    pub rule: Option<u32>,
}

impl Verdict {
    /// Shorthand for `self.decision.is_allow()`.
    pub fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// A loaded `acl.toml` — the M5 policy engine proper. Constructed only by
/// [`crate::acl::load::PolicySource::load`]; nothing else builds one
/// (tests aside), and nothing in production wires one into an
/// [`Authorizer`] slot yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Rules in file order — order matters, since the first match wins.
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Decide `action` on `resource` for `principal` (authenticated via
    /// `auth_path`), per the module-level canonical evaluation order.
    ///
    /// `resource.owner` only matters for a rule whose `scope` is the
    /// default `"owned"`: such a rule allows an owned resource
    /// (`resource.owner: Some(_)`) only when that owner is this same
    /// requester's own [`opener_key`] — a different principal's session or
    /// remote forward keeps denying under `scope = "owned"` exactly as
    /// M3's hardcoded `require_opener` gate did, now as an ordinary policy
    /// judgment instead of a second, separate check
    /// (`docs/design/architecture.md` §6, `PLAN.md` M5 Step 5 (a)). A
    /// resource with no owner concept at all (`resource.owner: None` —
    /// `exec.run`/`host.reverse`/`forward.local`) is never filtered by
    /// `scope` either way, `"owned"` or `"any"`.
    ///
    /// `pub(crate)`, not `pub` (`PLAN.md` M5 Step 7 DoD 1): the structural
    /// half of "`acl check` runs the same code path as enforcement" is that
    /// this is the **only** evaluator, and the only way to make that a
    /// compiler-enforced fact rather than a code-review claim is to make it
    /// impossible for any second evaluator to exist outside this crate.
    /// With this narrowed, the entire workspace has exactly two call sites
    /// of `Policy::decide`: [`Authorizer for Policy`](Policy)'s own `check`
    /// (production enforcement, `crate::server::Server::authorize` and
    /// siblings, via `Arc<dyn Authorizer>`) and `crate::ops::acl::Ops::
    /// acl_check` — both inside `qsh-core`, both calling this one method. A
    /// second, explaining-only evaluator would have to either reimplement
    /// this method's body (visibly duplicated logic, not a second call to
    /// this one) or live inside `qsh-core` too, where it would show up
    /// next to these two in a workspace-wide `grep -rn '\.decide(\|Policy::decide'`
    /// — the mechanical check `PLAN.md` §4's "acl check와 enforcement의
    /// 분기" risk item asks for.
    pub(crate) fn decide(
        &self,
        principal: &Principal,
        auth_path: AuthPath,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict {
        // ① Always-deny gate — before any rule is looked at, so no
        // wildcard or explicit exact pattern can reach it.
        if action.is_always_denied() {
            return Verdict {
                decision: Decision::Deny,
                rule: None,
            };
        }
        let principal_str = principal.to_string();
        for (index, rule) in self.rules.iter().enumerate() {
            // ② Principal exact match + auth_path match.
            if rule.principal != principal_str || rule.auth_path != auth_path {
                continue;
            }
            // ③ Action pattern match (exact or trailing-`.*`).
            if !rule.allow.iter().any(|pattern| pattern.matches(action)) {
                continue;
            }
            // ④ `scope` judgment — see this method's own doc. `Scope::Any`
            // always passes; `Scope::Owned` passes when the resource has
            // no owner to begin with, or when it does and this requester
            // is it.
            let scope_ok = match (rule.scope, resource.owner) {
                (Scope::Any, _) | (Scope::Owned, None) => true,
                (Scope::Owned, Some(owner)) => owner == opener_key(principal, auth_path),
            };
            if !scope_ok {
                continue;
            }
            let index = u32::try_from(index).expect(
                "rule index fits u32: crate::acl::load bounds rule count far below u32::MAX",
            );
            return Verdict {
                decision: Decision::Allow,
                rule: Some(index),
            };
        }
        Verdict {
            decision: Decision::Deny,
            rule: None,
        }
    }
}

impl Authorizer for Policy {
    fn check(
        &self,
        principal: &Principal,
        auth_path: AuthPath,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict {
        self.decide(principal, auth_path, action, resource)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use qsh_transport::Fingerprint;

    use super::*;

    fn rule(principal: &str, auth_path: AuthPath, allow: Vec<ActionPattern>) -> Rule {
        Rule {
            principal: principal.to_string(),
            auth_path,
            allow,
            scope: Scope::Owned,
        }
    }

    fn session_prefix() -> FamilyPrefix {
        family_prefix(Action::SessionOpen)
    }

    /// `Action::as_str()`'s family prefix, dot included — the same
    /// derivation `crate::acl::load::parse_action_pattern` uses, spelled
    /// out again here so tests can build [`ActionPattern::Prefix`] values
    /// without going through the loader. Goes through [`FamilyPrefix::new`]
    /// like the loader does, so a test helper can never construct an
    /// `ActionPattern::Prefix` that violates the dot-boundary invariant
    /// either (F8).
    fn family_prefix(action: Action) -> FamilyPrefix {
        let full = action.as_str();
        let dot = full.find('.').expect("every action has a dot");
        FamilyPrefix::new(&full[..=dot])
    }

    #[test]
    fn always_deny_trio_denies_under_the_most_generous_policy_with_no_rule_index() {
        // `docs/design/architecture.md` §6 / `PLAN.md` M5 Step 2 (a): even
        // the most permissive policy an operator could write cannot grant
        // the P1-deferred trio.
        let policy = Policy {
            rules: vec![rule(
                "user:dave",
                AuthPath::Pin,
                vec![
                    ActionPattern::Prefix(family_prefix(Action::ForwardLocal)),
                    ActionPattern::Prefix(family_prefix(Action::FileRead)),
                    ActionPattern::Prefix(session_prefix()),
                    ActionPattern::Exact(Action::ExecRun),
                ],
            )],
        };
        let principal = Principal::User("dave".into());
        for action in [Action::ForwardSocks, Action::FileRead, Action::FileWrite] {
            let verdict =
                policy.decide(&principal, AuthPath::Pin, action, ResourceRef::unowned("r"));
            assert_eq!(verdict.decision, Decision::Deny, "{action} must be denied");
            assert_eq!(verdict.rule, None, "{action} must carry no rule index");
        }
        // Sanity: the same policy *does* grant an ordinary action in one
        // of those families, so the trio's denial isn't just "the rule
        // never matches anything".
        let allowed = policy.decide(
            &principal,
            AuthPath::Pin,
            Action::ForwardLocal,
            ResourceRef::unowned("r"),
        );
        assert_eq!(allowed.decision, Decision::Allow);
        assert_eq!(allowed.rule, Some(0));
    }

    #[test]
    fn principal_match_is_exact_not_prefix_or_shape() {
        let policy = Policy {
            rules: vec![rule(
                "user:dave",
                AuthPath::Pin,
                vec![ActionPattern::Exact(Action::ExecRun)],
            )],
        };
        for principal in [
            Principal::User("dave2".into()),
            Principal::User("dav".into()),
            Principal::Device("dave".into()),
        ] {
            let verdict = policy.decide(
                &principal,
                AuthPath::Pin,
                Action::ExecRun,
                ResourceRef::unowned("r"),
            );
            assert_eq!(
                verdict.decision,
                Decision::Deny,
                "{principal} must not match a user:dave rule"
            );
        }
        // The exact principal the rule names still matches.
        let dave = Principal::User("dave".into());
        let verdict = policy.decide(
            &dave,
            AuthPath::Pin,
            Action::ExecRun,
            ResourceRef::unowned("r"),
        );
        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[test]
    fn omitted_auth_path_defaults_to_pin_and_never_admits_ca() {
        // A rule that never named `auth_path` in `acl.toml` — the loader
        // defaults it to `AuthPath::Pin` (`PLAN.md` M5 §4.1 #2); this test
        // pins that a `Rule` built that way can never admit a CA-asserted
        // peer, however broad `allow` is.
        let policy = Policy {
            rules: vec![rule(
                "user:dave",
                AuthPath::Pin,
                vec![ActionPattern::Prefix(session_prefix())],
            )],
        };
        let dave = Principal::User("dave".into());
        let via_ca = policy.decide(
            &dave,
            AuthPath::Ca,
            Action::SessionOpen,
            ResourceRef::unowned("r"),
        );
        assert_eq!(
            via_ca.decision,
            Decision::Deny,
            "an auth_path-omitted rule must never admit AuthPath::Ca"
        );
        let via_pin = policy.decide(
            &dave,
            AuthPath::Pin,
            Action::SessionOpen,
            ResourceRef::unowned("r"),
        );
        assert_eq!(via_pin.decision, Decision::Allow);
    }

    #[test]
    fn first_matching_rule_wins_and_its_index_is_reported() {
        let dave = Principal::User("dave".into());
        let policy = Policy {
            rules: vec![
                rule(
                    "user:someone-else",
                    AuthPath::Pin,
                    vec![ActionPattern::Exact(Action::ExecRun)],
                ),
                rule(
                    "user:dave",
                    AuthPath::Pin,
                    vec![ActionPattern::Exact(Action::ExecRun)],
                ),
                rule(
                    "user:dave",
                    AuthPath::Pin,
                    vec![ActionPattern::Exact(Action::ExecRun)],
                ),
            ],
        };
        let verdict = policy.decide(
            &dave,
            AuthPath::Pin,
            Action::ExecRun,
            ResourceRef::unowned("r"),
        );
        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(
            verdict.rule,
            Some(1),
            "the first matching rule (index 1) wins, not the only-matching-by-coincidence index 0"
        );
    }

    #[test]
    fn scope_owned_is_not_evaluated_when_the_resource_has_no_owner() {
        // `resource.owner: None` (no owner concept at all — `exec.run`/
        // `host.reverse`/`forward.local`) is never filtered by `scope`,
        // "owned" or "any" alike — this is the Step 2-era behavior
        // (`ResourceRef` then had no owner field to compare at all), still
        // exactly correct now that `scope` is actually evaluated (`PLAN.md`
        // M5 Step 5), since an absent owner can never fail an ownership
        // comparison.
        let dave = Principal::User("dave".into());
        let policy = Policy {
            rules: vec![rule(
                "user:dave",
                AuthPath::Pin,
                vec![ActionPattern::Exact(Action::SessionControl)],
            )],
        };
        assert_eq!(policy.rules[0].scope, Scope::Owned, "default is owned");
        for resource in ["dave-owns-this", "someone-elses-entirely", ""] {
            let verdict = policy.decide(
                &dave,
                AuthPath::Pin,
                Action::SessionControl,
                ResourceRef::unowned(resource),
            );
            assert_eq!(
                verdict.decision,
                Decision::Allow,
                "scope=owned must not filter an unowned resource — resource {resource:?}"
            );
        }
    }

    /// The headline `PLAN.md` M5 Step 5 behavior: `scope = "owned"` (the
    /// default) denies a request whose principal is not the resource's
    /// recorded owner, even though principal/auth_path/action all matched.
    #[test]
    fn scope_owned_denies_a_request_from_a_different_owner() {
        let dave = Principal::User("dave".into());
        let policy = Policy {
            rules: vec![rule(
                "user:dave",
                AuthPath::Pin,
                vec![ActionPattern::Exact(Action::SessionControl)],
            )],
        };
        let someone_elses_session = opener_key(&Principal::User("alice".into()), AuthPath::Pin);
        let verdict = policy.decide(
            &dave,
            AuthPath::Pin,
            Action::SessionControl,
            ResourceRef {
                id: "sess-1",
                owner: Some(&someone_elses_session),
            },
        );
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(
            verdict.rule, None,
            "a scope-refused match carries no rule index"
        );
    }

    /// The other half: the resource's actual owner is admitted.
    #[test]
    fn scope_owned_allows_the_resources_own_owner() {
        let dave = Principal::User("dave".into());
        let policy = Policy {
            rules: vec![rule(
                "user:dave",
                AuthPath::Pin,
                vec![ActionPattern::Exact(Action::SessionControl)],
            )],
        };
        let daves_own_key = opener_key(&dave, AuthPath::Pin);
        let verdict = policy.decide(
            &dave,
            AuthPath::Pin,
            Action::SessionControl,
            ResourceRef {
                id: "sess-1",
                owner: Some(&daves_own_key),
            },
        );
        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.rule, Some(0));
    }

    /// `scope = "any"` is the explicit widening: it admits a resource owned
    /// by someone else entirely, and only an operator writing that value
    /// into `acl.toml` can turn it on — the default stays `"owned"`
    /// (`PLAN.md` M5 §4.1 #3).
    #[test]
    fn scope_any_admits_a_foreign_owner() {
        let dave = Principal::User("dave".into());
        let mut widened = rule(
            "user:dave",
            AuthPath::Pin,
            vec![ActionPattern::Exact(Action::SessionControl)],
        );
        widened.scope = Scope::Any;
        let policy = Policy {
            rules: vec![widened],
        };
        let someone_elses_session = opener_key(&Principal::User("alice".into()), AuthPath::Pin);
        let verdict = policy.decide(
            &dave,
            AuthPath::Pin,
            Action::SessionControl,
            ResourceRef {
                id: "sess-1",
                owner: Some(&someone_elses_session),
            },
        );
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "scope=any must admit a resource owned by a different principal"
        );
        assert_eq!(verdict.rule, Some(0));
    }

    /// `opener_key` folds `auth_path` in, so a scope-owned rule that
    /// matched a request over `AuthPath::Ca` must not treat that request as
    /// the owner of a resource actually opened over `AuthPath::Pin`, even
    /// when the principal string is identical — the same CA-leaf-spoofing
    /// concern `session_loopback.rs`'s
    /// `ca_leaf_asserting_the_opener_principal_is_still_denied_ownership`
    /// pins end to end.
    #[test]
    fn scope_owned_does_not_let_a_different_auth_path_assert_the_same_principals_ownership() {
        let laptop_over_ca = Principal::Device("laptop".into());
        let mut ca_rule = rule(
            "device:laptop",
            AuthPath::Ca,
            vec![ActionPattern::Exact(Action::SessionControl)],
        );
        ca_rule.auth_path = AuthPath::Ca;
        let policy = Policy {
            rules: vec![ca_rule],
        };
        // The resource's real owner authenticated over the pin, not the CA.
        let real_owner_key = opener_key(&Principal::Device("laptop".into()), AuthPath::Pin);
        let verdict = policy.decide(
            &laptop_over_ca,
            AuthPath::Ca,
            Action::SessionControl,
            ResourceRef {
                id: "sess-1",
                owner: Some(&real_owner_key),
            },
        );
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "a CA-authenticated request must not inherit a pinned owner's identity"
        );
    }

    #[test]
    fn wildcard_matches_only_its_own_dot_bounded_family() {
        let session = ActionPattern::Prefix(session_prefix());
        for action in [
            Action::SessionOpen,
            Action::SessionList,
            Action::SessionAttach,
            Action::SessionControl,
        ] {
            assert!(session.matches(action), "{action} must match session.*");
        }
        for action in [Action::ExecRun, Action::HostReverse, Action::ForwardLocal] {
            assert!(
                !session.matches(action),
                "{action} must not match session.*"
            );
        }
    }

    /// F3 (M5 Step 2 adversarial review): includes prefix/superstring,
    /// case, and whitespace near-misses of `"dave"` on purpose. The
    /// original list (`"dave"`, `"alice"`, `"bob"`, `"laptop"`,
    /// `"phone"`) was pairwise prefix-free, so no generated principal
    /// pair could ever exercise a prefix-based (as opposed to
    /// exact-match) comparison bug — the principal property tests below
    /// were vacuous against exactly that mutation class.
    fn arb_principal_name() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "dave", "dave2", "dav", "Dave", "DAVE", "dave ", " dave", "alice", "bob", "laptop",
            "phone",
        ])
        .prop_map(|s| s.to_string())
    }

    fn arb_principal() -> impl Strategy<Value = Principal> {
        prop_oneof![
            arb_principal_name().prop_map(Principal::Device),
            arb_principal_name().prop_map(Principal::User),
            any::<[u8; 4]>()
                .prop_map(|seed| Principal::Fingerprint(Fingerprint::of_spki_der(&seed))),
        ]
    }

    /// A `Rule::principal` string generated independently of
    /// [`arb_principal`] (F3): a real `Principal::to_string()` shape most
    /// of the time, but also raw near-miss strings (a bare name with no
    /// `user:`/`device:` prefix, or a shaped string whose name half is a
    /// near-miss) that no `Principal` variant's `Display` would ever
    /// produce. `Policy::decide` only ever compares `Rule::principal`
    /// against `Principal::to_string()` byte-for-byte — it has no idea
    /// whether the rule's string came from a real principal — so a
    /// property test that only ever fed it real `Principal::to_string()`
    /// output couldn't tell "compares exactly" apart from "compares a
    /// prefix of something that happens to look like one".
    fn arb_rule_principal_string() -> impl Strategy<Value = String> {
        prop_oneof![
            arb_principal().prop_map(|p| p.to_string()),
            arb_principal_name(),
            arb_principal_name().prop_map(|s| format!("user:{s}")),
            arb_principal_name().prop_map(|s| format!("device:{s}")),
        ]
    }

    fn arb_auth_path() -> impl Strategy<Value = AuthPath> {
        prop_oneof![Just(AuthPath::Pin), Just(AuthPath::Ca)]
    }

    fn arb_action() -> impl Strategy<Value = Action> {
        prop::sample::select(Action::ALL.to_vec())
    }

    fn arb_action_pattern() -> impl Strategy<Value = ActionPattern> {
        prop_oneof![
            arb_action().prop_map(ActionPattern::Exact),
            arb_action().prop_map(|a| ActionPattern::Prefix(family_prefix(a))),
        ]
    }

    fn arb_rule() -> impl Strategy<Value = Rule> {
        (
            // F3: a rule's principal string, generated independently of
            // whatever `Principal` a test request happens to draw — see
            // `arb_rule_principal_string`'s doc.
            arb_rule_principal_string(),
            arb_auth_path(),
            proptest::collection::vec(arb_action_pattern(), 1..5),
            prop_oneof![Just(Scope::Owned), Just(Scope::Any)],
        )
            .prop_map(|(principal, auth_path, allow, scope)| Rule {
                principal,
                auth_path,
                allow,
                scope,
            })
    }

    fn arb_policy() -> impl Strategy<Value = Policy> {
        proptest::collection::vec(arb_rule(), 0..8).prop_map(|rules| Policy { rules })
    }

    /// Every action a pattern covers, computed by expanding it against
    /// `Action::ALL` directly (`docs/design/testing.md` L8: "패턴을
    /// 문자열로 전개해 `Action::ALL`과 대조") — never by calling
    /// [`ActionPattern::matches`], so this is a genuinely independent
    /// second implementation, not the evaluator checking itself.
    fn expand(pattern: &ActionPattern) -> Vec<Action> {
        match *pattern {
            ActionPattern::Exact(a) => vec![a],
            ActionPattern::Prefix(prefix) => Action::ALL
                .into_iter()
                .filter(|a| a.as_str().starts_with(prefix.as_str()))
                .collect(),
        }
    }

    /// Whether *some* rule in `policy` covers `(principal, auth_path,
    /// action, resource)`, independent of [`Policy::decide`]'s own
    /// matching logic — `resource`'s scope test (`PLAN.md` M5 Step 5)
    /// included, spelled out again here the same direct way `principal`/
    /// `auth_path` already were, rather than calling any of `decide`'s own
    /// helpers.
    fn oracle_covers(
        policy: &Policy,
        principal: &Principal,
        auth_path: AuthPath,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> bool {
        let principal_str = principal.to_string();
        policy.rules.iter().any(|rule| {
            rule.principal == principal_str
                && rule.auth_path == auth_path
                && rule
                    .allow
                    .iter()
                    .any(|pattern| expand(pattern).contains(&action))
                && match (rule.scope, resource.owner) {
                    (Scope::Any, _) | (Scope::Owned, None) => true,
                    (Scope::Owned, Some(owner)) => owner == opener_key(principal, auth_path),
                }
        })
    }

    proptest! {
        /// DoD 3 (`PLAN.md` M5 Step 2, `docs/design/testing.md` L2/L8):
        /// for an arbitrary policy and an arbitrary request, `Policy::
        /// decide`'s allow/deny agrees with an independent naive oracle —
        /// in particular, whenever the oracle finds no covering rule, the
        /// evaluator MUST deny. The always-deny trio is asserted to
        /// override any oracle coverage, since no rule can grant it.
        ///
        /// `owner_kind` (`PLAN.md` M5 Step 5) draws the resource into one
        /// of the three shapes `decide`'s ④ actually distinguishes: no
        /// owner at all, this exact requester as owner, or some other
        /// principal as owner. The "other" owner is built from
        /// `arb_principal_name`'s bare-name pool with no `auth_path:`
        /// prefix folded in, so it can never accidentally collide with a
        /// real `opener_key` output (always `"{auth_path:?}:{principal}"`,
        /// which itself always contains a `device:`/`user:`/`fp:sha256:`
        /// segment) — a genuinely foreign owner every time, not merely a
        /// different string that happens not to match today's pool.
        #[test]
        fn decide_agrees_with_naive_coverage_oracle(
            policy in arb_policy(),
            principal in arb_principal(),
            auth_path in arb_auth_path(),
            action in arb_action(),
            owner_kind in 0u8..3,
            foreign_owner_name in arb_principal_name(),
        ) {
            let foreign_owner = format!("{auth_path:?}:{foreign_owner_name}");
            let owner: Option<String> = match owner_kind {
                0 => None,
                1 => Some(opener_key(&principal, auth_path)),
                _ => Some(foreign_owner),
            };
            let resource = match owner.as_deref() {
                Some(owner) => ResourceRef { id: "r", owner: Some(owner) },
                None => ResourceRef::unowned("r"),
            };
            let verdict = policy.decide(&principal, auth_path, action, resource);
            // F4 (M5 Step 2 adversarial review): the literal P1-deferred
            // trio, spelled out again here rather than calling
            // `Action::is_always_denied()` — the very function `decide`
            // itself calls to implement this gate. Branching the oracle on
            // the code under test meant a mutation to `is_always_denied`
            // (e.g. dropping `FileWrite`) changed this test's expectation
            // in lockstep with `decide`'s behavior, so the oracle could
            // never disagree and the mutation went undetected.
            if matches!(action, Action::ForwardSocks | Action::FileRead | Action::FileWrite) {
                prop_assert_eq!(verdict.decision, Decision::Deny);
                prop_assert_eq!(verdict.rule, None);
            } else {
                let covered = oracle_covers(&policy, &principal, auth_path, action, resource);
                prop_assert_eq!(
                    verdict.is_allow(),
                    covered,
                    "evaluator/oracle disagreement for {} over {:?} on {} (owner {:?})",
                    principal,
                    auth_path,
                    action,
                    resource.owner,
                );
                if !covered {
                    prop_assert_eq!(verdict.decision, Decision::Deny);
                    prop_assert_eq!(verdict.rule, None);
                }
            }
        }

        /// Wildcard property (`docs/design/testing.md` L8): a family
        /// wildcard matches exactly the actions sharing its dot-bounded
        /// prefix, for every action in the vocabulary — not just the
        /// hand-picked `session.*` example.
        #[test]
        fn family_wildcard_matches_exactly_its_dot_bounded_family(
            family_action in arb_action(),
            probe in arb_action(),
        ) {
            let prefix = family_prefix(family_action);
            let pattern = ActionPattern::Prefix(prefix);
            let expected = probe.as_str().starts_with(prefix.as_str());
            prop_assert_eq!(pattern.matches(probe), expected);
        }

        /// Principal property: two different principal strings never
        /// cross-match, for arbitrary principal pairs.
        #[test]
        fn principal_never_matches_a_different_principal_string(
            a in arb_principal(),
            b in arb_principal(),
            action in arb_action(),
        ) {
            prop_assume!(a.to_string() != b.to_string());
            let policy = Policy {
                rules: vec![rule(&a.to_string(), AuthPath::Pin, vec![ActionPattern::Exact(action)])],
            };
            let verdict = policy.decide(&b, AuthPath::Pin, action, ResourceRef::unowned("r"));
            prop_assert_eq!(verdict.decision, Decision::Deny);
        }
    }
}
