//! `acl.check` (`docs/CLI.md` §6.15, `PLAN.md` M5 Step 7) — the local,
//! authorization-free operation that lets an operator ask "what would
//! enforcement decide?" without waiting for a restart (§2.5's "인가 불요"
//! row: `acl.check` never reaches a remote peer — a remote-visible policy
//! query would itself be a capability-enumeration oracle, ROADMAP M5 감사
//! 개정 ③).
//!
//! **This is not a second evaluator.** [`Ops::acl_check`] loads this
//! machine's own `acl.toml` with the exact same [`crate::acl::PolicySource::load`]
//! production uses, and calls the exact same `crate::acl::Policy::decide`
//! `crate::server::Server::authorize` (via `impl Authorizer for Policy`)
//! calls — `Policy::decide` is `pub(crate)`, so there is no way to build a
//! second, explaining-only judgment from outside this crate (`policy.rs`'s
//! own doc on that method spells out the three-call-site invariant this
//! relies on). No remote round trip, no re-implementation of `Policy::
//! decide`'s matching logic.

use std::str::FromStr;

use qsh_proto::{
    AclCheckData, AclCheckReq, AclMatchingRule, AclPolicyRef, AclShowData, AclShowReq, ErrorCode,
};
use qsh_transport::{AuthPath, Principal};

use crate::acl::{
    Action, ActionPattern, Decision, PolicyLoad, PolicySource, ResourceRef, Scope, opener_key,
};
use crate::ops::{OpError, Operation, Ops};

/// The `acl.check` operation (`qsh acl check`).
pub struct AclCheckOp;

impl Operation for AclCheckOp {
    const COMMAND: &'static str = "acl.check";
}

/// The `acl.show` operation (`qsh acl show`, `docs/CLI.md` §6.19).
pub struct AclShowOp;

impl Operation for AclShowOp {
    const COMMAND: &'static str = "acl.show";
}

/// `"pin"`/`"ca"` → [`AuthPath`], the same two-word grammar `acl.toml`'s own
/// `auth_path` key uses (`PLAN.md` M5 §4.1 #2). Not a `FromStr` impl on
/// `qsh_transport::AuthPath` itself — this two-armed match has exactly one
/// caller family (this module's `--auth-path`/`--owner-auth-path`), the
/// same reason `crate::audit`'s own `auth_path_str` (the render direction)
/// stays a private local helper rather than a shared, exported one.
fn parse_auth_path(s: &str) -> Result<AuthPath, OpError> {
    match s {
        "pin" => Ok(AuthPath::Pin),
        "ca" => Ok(AuthPath::Ca),
        other => Err(OpError::new(
            ErrorCode::InvalidArgument,
            format!("invalid auth_path {other:?}: expected \"pin\" or \"ca\""),
        )),
    }
}

/// [`AuthPath`] → `"pin"`/`"ca"`, the render direction of [`parse_auth_path`].
/// [`AuthPath::Pairing`] is unreachable through this op in practice
/// ([`parse_auth_path`] never produces it — `acl.check` simulates ordinary
/// ACL decisions only, and pairing never reaches the ACL choke point at
/// all, `crate::server::Server::serve_pairing_connection`'s own doc), but
/// the match must stay exhaustive since [`AuthPath`] is a shared transport
/// type; the arm exists so a hypothetical future caller gets the same
/// rendering `crate::audit`'s own `auth_path_str` uses, not a panic.
fn auth_path_str(auth_path: AuthPath) -> &'static str {
    match auth_path {
        AuthPath::Pin => "pin",
        AuthPath::Ca => "ca",
        AuthPath::Pairing => "pairing",
    }
}

/// Parse a principal string, mapping a bad shape to `INVALID_ARGUMENT` —
/// the CLI/renderer layer never sees the raw `qsh_transport::
/// PrincipalParseError`, only the uniform `qsh-core` error vocabulary.
fn parse_principal(s: &str) -> Result<Principal, OpError> {
    Principal::from_str(s).map_err(|err| OpError::new(ErrorCode::InvalidArgument, err.to_string()))
}

impl Ops {
    /// `acl.check` (`qsh acl check`, `docs/CLI.md` §6.15). Local,
    /// authorization-free (§2.5) — reads this machine's own `acl.toml` and
    /// evaluates it directly; never touches the network.
    ///
    /// `principal`/`action` outside the typed vocabulary is
    /// `INVALID_ARGUMENT` — what actions exist is discoverable via
    /// `--help`/`qsh schema`, so this rejection is not an information-
    /// disclosure oracle (`PLAN.md` M5 Step 7 (a)). `resource` omitted
    /// evaluates an unowned resource; `owner` given folds it (via the
    /// production [`opener_key`], never a second folding implementation)
    /// into an owned [`ResourceRef`] so `scope = "owned"` rows are
    /// explainable too (`PLAN.md` M5 §4.2's `--owner` decision) — the
    /// folded string's internal `{auth_path:?}` encoding never leaves this
    /// function; only the unfolded `owner`/`owner_auth_path` strings are
    /// echoed back.
    pub fn acl_check(&self, req: AclCheckReq) -> Result<AclCheckData, OpError> {
        let principal = parse_principal(&req.principal)?;
        let action = Action::from_str(&req.action)
            .map_err(|err| OpError::new(ErrorCode::InvalidArgument, err.to_string()))?;
        let auth_path = match req.auth_path.as_deref() {
            Some(s) => parse_auth_path(s)?,
            None => AuthPath::Pin,
        };

        // `owner`/`owner_auth_path`: present only when `--owner` was given
        // (`owner_auth_path` alone, without `owner`, is meaningless and
        // simply ignored — the CLI layer never constructs that shape, but
        // `Ops` does not trust its own frontend to have gotten that right).
        // `owner_ap` (distinct from the request's own `auth_path` above) is
        // the auth path *the owner* authenticated over, folded into the
        // owner key via the same production `opener_key` `Server::
        // require_opener`'s ownership comparison uses — never a second
        // folding implementation.
        let owner_ap: Option<AuthPath> = match &req.owner {
            Some(_) => Some(match req.owner_auth_path.as_deref() {
                Some(s) => parse_auth_path(s)?,
                None => AuthPath::Pin,
            }),
            None => None,
        };
        let owner_key = match (&req.owner, owner_ap) {
            (Some(owner_str), Some(owner_ap)) => {
                let owner_principal = parse_principal(owner_str)?;
                Some(opener_key(&owner_principal, owner_ap))
            }
            _ => None,
        };

        let resource_id = req.resource.as_deref().unwrap_or("");
        let resource = match owner_key.as_deref() {
            Some(owner) => ResourceRef {
                id: resource_id,
                owner: Some(owner),
            },
            None => ResourceRef::unowned(resource_id),
        };

        let path = self.paths.acl_file();
        let (decision, rule, policy) = match PolicySource::load(&self.paths) {
            PolicyLoad::Loaded(policy) => {
                let verdict = policy.decide(&principal, auth_path, action, resource);
                let rules = u32::try_from(policy.rules.len()).expect(
                    "rule count fits u32: crate::acl::load bounds rule count far below u32::MAX",
                );
                (
                    verdict.decision,
                    verdict.rule,
                    AclPolicyRef {
                        path: path.display().to_string(),
                        rules,
                        loaded: true,
                    },
                )
            }
            PolicyLoad::Missing | PolicyLoad::Invalid(_) => (
                Decision::Deny,
                None,
                AclPolicyRef {
                    path: path.display().to_string(),
                    rules: 0,
                    loaded: false,
                },
            ),
        };

        Ok(AclCheckData {
            principal: principal.to_string(),
            action: action.as_str().to_string(),
            resource: req.resource,
            auth_path: Some(auth_path_str(auth_path).to_string()),
            decision: decision.as_str().to_string(),
            rule,
            policy,
            owner: req.owner,
            owner_auth_path: owner_ap.map(auth_path_str).map(str::to_string),
        })
    }

    /// `acl.show` (`qsh acl show`, `docs/CLI.md` §6.19, ADR-0025). Local,
    /// authorization-free (§2.5) - summarizes what this machine's own
    /// `acl.toml` grants one principal, without a network round trip and
    /// without writing anything.
    ///
    /// The effective set comes from `crate::acl::Policy::effective_actions`,
    /// which runs the production `decide` once per action on an unowned
    /// resource, and the matching rows from `Policy::matching_rules`, which
    /// shares `decide`'s step 2 and 3 helpers. A missing, unparseable or
    /// unreadable `acl.toml` is `PolicyLoad::Missing`/`Invalid`: both give
    /// `loaded: false` with empty results and echo no rule content.
    /// A malformed principal or an `auth_path` other than `pin`/`ca` is
    /// `INVALID_ARGUMENT`, like `acl.check`.
    pub fn acl_show(&self, req: AclShowReq) -> Result<AclShowData, OpError> {
        let principal = parse_principal(&req.principal)?;
        let (auth_path, auth_path_defaulted) = match req.auth_path.as_deref() {
            Some(s) => (parse_auth_path(s)?, false),
            None => (AuthPath::Pin, true),
        };

        let path = self.paths.acl_file().display().to_string();
        let (policy_ref, matching_rules, effective_actions) = match PolicySource::load(&self.paths)
        {
            PolicyLoad::Loaded(policy) => {
                let rules = u32::try_from(policy.rules.len()).expect(
                    "rule count fits u32: crate::acl::load bounds rule count far below u32::MAX",
                );
                let matching = policy
                    .matching_rules(&principal, auth_path)
                    .into_iter()
                    .map(|(index, rule)| AclMatchingRule {
                        index,
                        allow: rule.allow.iter().map(ActionPattern::render).collect(),
                        auth_path: auth_path_str(rule.auth_path).to_string(),
                        scope: match rule.scope {
                            Scope::Owned => "owned",
                            Scope::Any => "any",
                        }
                        .to_string(),
                    })
                    .collect();
                let effective = policy
                    .effective_actions(&principal, auth_path)
                    .into_iter()
                    .map(|a| a.as_str().to_string())
                    .collect();
                (
                    AclPolicyRef {
                        path,
                        rules,
                        loaded: true,
                    },
                    matching,
                    effective,
                )
            }
            PolicyLoad::Missing | PolicyLoad::Invalid(_) => (
                AclPolicyRef {
                    path,
                    rules: 0,
                    loaded: false,
                },
                Vec::new(),
                Vec::new(),
            ),
        };

        Ok(AclShowData {
            principal: principal.to_string(),
            auth_path: auth_path_str(auth_path).to_string(),
            auth_path_defaulted,
            policy: policy_ref,
            matching_rules,
            effective_actions,
        })
    }
}
