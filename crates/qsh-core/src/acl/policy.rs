//! The pure policy evaluator (`docs/design/architecture.md` §6). Nothing
//! in this module touches the filesystem or the network —
//! [`crate::acl::load`] is the only thing that turns `acl.toml` into a
//! [`Policy`], and [`crate::acl::load_or_deny_with_index`] is what
//! `crate::serve` calls at startup to hand the result to the server (a
//! missing or unparseable file becomes a policy that denies everything,
//! plus a startup diagnostic).
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
//!    an [`AuthPath::Ca`] request.
//! 3. Action pattern match — exact or trailing-`.*` family wildcard
//!    (`ActionPattern::matches`).
//! 4. `scope` judgment: `Scope::Any` always passes.
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
/// these two shapes, and `crate::acl::load` rejects anything else at
/// load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionPattern {
    /// Matches exactly one action.
    Exact(Action),
    /// Matches every action whose dotted name starts with this family
    /// prefix, dot included (e.g. `"session."` for the `acl.toml` entry
    /// `"session.*"`). See `FamilyPrefix` for how that invariant is
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
/// **Evaluated by `Policy::decide`'s ④ since `PLAN.md` M5 Step 5**: a
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

/// The outcome of `Policy::decide`: an allow/deny [`Decision`] plus,
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
mod tests;
