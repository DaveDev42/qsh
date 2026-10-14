//! `acl.check` (`docs/CLI.md` §6.15, M5 plan Step 7 (2473c88)) — the local,
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
//!
//! **The trust role is an input here too** (ADR-0045 결정 10·11, M15 plan
//! Step 6 (1a4af3b)). For a `device:<name>` principal over `--auth-path pin`, the
//! pin of that name in this machine's `trust.toml` supplies the role, and
//! its own fingerprint stands in for the connection's (a local query has no
//! connection). The role goes into the same `Policy::decide` as an explicit
//! argument, so the role stage ⓡ cannot differ from enforcement. A
//! `trust.toml` that does not parse yields no role, the same answer a
//! running `qsh serve` gives while its role grants are suspended (ADR-0045
//! 결정 4).

use std::path::PathBuf;
use std::str::FromStr;

use qsh_proto::{
    AclCheckData, AclCheckReq, AclMatchingRule, AclPolicyRef, AclShowData, AclShowReq, ErrorCode,
};
use qsh_transport::{AuthPath, Principal};

use crate::acl::{
    Action, ActionPattern, GrantBasis, Policy, PolicyLoad, PolicySource, ResourceRef, Scope,
    Verdict, opener_key, role_grant,
};
use crate::file::guard::{FileOp, FsNormalizer, Normalizer, ShapeError, ShapedPath};
use crate::file::guard::{serve_home_dir, shape_path};
use crate::ops::{OpError, Operation, Ops};
use crate::trust::{TrustRole, TrustStore};

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
/// `auth_path` key uses (M5 plan §4.1 #2 (2473c88)). Not a `FromStr` impl on
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

/// The `state` strings of [`AclPolicyRef`] (ADR-0045 결정 10).
const STATE_LOADED: &str = "loaded";
const STATE_MISSING: &str = "missing";
const STATE_INVALID: &str = "invalid";

fn policy_ref(path: String, rules: u32, state: &str) -> AclPolicyRef {
    AclPolicyRef {
        path,
        rules,
        loaded: state == STATE_LOADED,
        state: Some(state.to_string()),
    }
}

/// The `--path` argument of `acl check` (ADR-0029 결정 19): a file action
/// needs it, every other action refuses it, and it must pass the file ops'
/// own shape check (결정 6-1). No message echoes the path.
fn shape_path_arg(action: Action, raw: Option<&str>) -> Result<Option<ShapedPath>, OpError> {
    let invalid = |message: String| OpError::new(ErrorCode::InvalidArgument, message);
    match (action.is_file(), raw) {
        (true, None) => Err(invalid(format!(
            "{action} needs --path: a file action is decided per path"
        ))),
        (false, Some(_)) => Err(invalid(
            "--path applies only to file.read and file.write".to_string(),
        )),
        (false, None) => Ok(None),
        (true, Some(raw)) => {
            let op = if action == Action::FileRead {
                FileOp::Read
            } else {
                FileOp::Write
            };
            match shape_path(raw.as_bytes(), op, serve_home_dir().as_deref()) {
                Ok(shaped) => Ok(Some(shaped)),
                // No file op exists off unix, so the question is still
                // answerable (no row can cover a path nobody normalizes);
                // the argument just goes unshaped.
                Err(ShapeError::Unsupported) => Ok(None),
                Err(other) => Err(invalid(other.to_string())),
            }
        }
    }
}

impl Ops {
    /// The role a local query evaluates for `principal` over `auth_path`
    /// (ADR-0045 결정 10·11): see the module doc. `None` means "no role in
    /// the question"; a pin with no `role` key is `Some(TrustRole::None)`.
    fn query_role(&self, principal: &Principal, auth_path: AuthPath) -> Option<TrustRole> {
        match TrustStore::load(&self.paths.trust_file()) {
            Ok(store) => store.query_role(principal, auth_path),
            Err(_) => None,
        }
    }

    /// This machine's `acl.toml` as the rows a decision runs over, plus its
    /// [`AclPolicyRef::state`] (ADR-0045 결정 6): `Some(rows)` when loaded,
    /// `Some(no rows)` when the file is missing (only a role can grant), and
    /// `None` when it is unusable (everything is refused, roles included).
    fn load_rows(&self) -> (Option<Policy>, &'static str) {
        match PolicySource::load(&self.paths) {
            PolicyLoad::Loaded(policy) => (Some(policy), STATE_LOADED),
            PolicyLoad::Missing => (Some(Policy::default()), STATE_MISSING),
            PolicyLoad::Invalid(_) => (None, STATE_INVALID),
        }
    }

    /// `acl.check` (`qsh acl check`, `docs/CLI.md` §6.15). Local,
    /// authorization-free (§2.5) — reads this machine's own `acl.toml` and
    /// evaluates it directly; never touches the network.
    ///
    /// `principal`/`action` outside the typed vocabulary is
    /// `INVALID_ARGUMENT` — what actions exist is discoverable via
    /// `--help`/`qsh schema`, so this rejection is not an information-
    /// disclosure oracle (M5 plan Step 7 (a) (2473c88)). `resource` omitted
    /// evaluates an unowned resource; `owner` given folds it (via the
    /// production [`opener_key`], never a second folding implementation)
    /// into an owned [`ResourceRef`] so `scope = "owned"` rows are
    /// explainable too (M5 plan §4.2 (2473c88)'s `--owner` decision) — the
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

        // `--path` is checked before anything is loaded: a bad argument is
        // `INVALID_ARGUMENT` whatever `acl.toml` says (ADR-0029 결정 19).
        let shaped = shape_path_arg(action, req.path.as_deref())?;

        // A file request's id is the path string as given, the same string
        // enforcement audits as `resource` (ADR-0029 결정 4-7).
        let resource_id = req
            .resource
            .as_deref()
            .or(req.path.as_deref())
            .unwrap_or("");
        let resource = match owner_key.as_deref() {
            Some(owner) => ResourceRef {
                id: resource_id,
                owner: Some(owner),
                canonical_path: None,
            },
            None => ResourceRef::unowned(resource_id),
        };

        let role = self.query_role(&principal, auth_path);
        let path = self.paths.acl_file().display().to_string();
        let (rows, state) = self.load_rows();
        // The same three steps as enforcement (ADR-0029 결정 4-6): (a) the
        // pure ground check, (b) normalize the request path only when there
        // is a ground, (c) the one evaluator. A principal with no file grant
        // never makes this query touch the filesystem, and a normalization
        // failure goes on without a path, which no row can cover.
        let normalizer = FsNormalizer;
        let canonical: Option<PathBuf> = match (&shaped, &rows) {
            (Some(shaped), Some(policy))
                if policy.file_grant_basis(&principal, auth_path, role, action) =>
            {
                normalizer.normalize(&shaped.absolute).ok()
            }
            _ => None,
        };
        let resource = match &canonical {
            Some(canonical) => resource.with_canonical_path(canonical, &normalizer),
            None => resource,
        };
        // One `decide` call for every state: an unusable file yields no
        // `Policy` and refuses everything, role grants included.
        let verdict = match &rows {
            Some(policy) => policy.decide(&principal, auth_path, role, action, resource),
            None => Verdict::DENY,
        };
        let rule_count = rows.as_ref().map_or(0, |policy| policy.rules.len());
        let rule_count = u32::try_from(rule_count)
            .expect("rule count fits u32: crate::acl::load bounds rule count far below u32::MAX");
        let policy = policy_ref(path, rule_count, state);
        let granted_by = verdict.granted_by().map(|basis| {
            match basis {
                GrantBasis::Role(_) => "role",
                GrantBasis::Rule(_) => "acl",
            }
            .to_string()
        });

        Ok(AclCheckData {
            principal: principal.to_string(),
            action: action.as_str().to_string(),
            resource: req.resource,
            auth_path: Some(auth_path_str(auth_path).to_string()),
            decision: verdict.decision.as_str().to_string(),
            rule: verdict.rule,
            policy,
            owner: req.owner,
            owner_auth_path: owner_ap.map(auth_path_str).map(str::to_string),
            role: role.map(|role| role.as_str().to_string()),
            granted_by,
            path: req.path,
            canonical_path: canonical.map(|p| p.to_string_lossy().into_owned()),
        })
    }

    /// `acl.show` (`qsh acl show`, `docs/CLI.md` §6.19, ADR-0025). Local,
    /// authorization-free (§2.5) - summarizes what this machine's own
    /// `acl.toml` grants one principal, without a network round trip and
    /// without writing anything.
    ///
    /// The effective set comes from `crate::acl::Policy::effective_actions`,
    /// which runs the production `decide` once per action on an unowned
    /// resource with the principal's pin role as an input, so it is the
    /// union of the role and the matching rows (ADR-0045 결정 11); the
    /// matching rows from `Policy::matching_rules`, which shares `decide`'s
    /// step 2 and 3 helpers. `role` and `role_actions` (the role's table
    /// row) are echoed when the principal has a pin role to evaluate.
    /// A missing `acl.toml` is a policy with no rows: `loaded: false`,
    /// `state: "missing"`, no matching rows, and the effective set is what
    /// the role alone grants. An unparseable or unreadable one is
    /// `state: "invalid"` with empty results (role grants are refused too)
    /// and echoes no rule content.
    /// A malformed principal or an `auth_path` other than `pin`/`ca` is
    /// `INVALID_ARGUMENT`, like `acl.check`.
    pub fn acl_show(&self, req: AclShowReq) -> Result<AclShowData, OpError> {
        let principal = parse_principal(&req.principal)?;
        let (auth_path, auth_path_defaulted) = match req.auth_path.as_deref() {
            Some(s) => (parse_auth_path(s)?, false),
            None => (AuthPath::Pin, true),
        };

        let role = self.query_role(&principal, auth_path);
        let path = self.paths.acl_file().display().to_string();
        let (rows, state) = self.load_rows();
        let (matching_rules, effective_actions, rule_count) = match &rows {
            Some(policy) => {
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
                        paths: rule.paths.clone(),
                        file_paths_missing: rule.paths.is_none() && rule.names_file_action(),
                    })
                    .collect();
                let effective = policy
                    .effective_actions(&principal, auth_path, role)
                    .into_iter()
                    .map(|a| a.as_str().to_string())
                    .collect();
                (matching, effective, policy.rules.len())
            }
            // An unusable file refuses everything, role grants included.
            None => (Vec::new(), Vec::new(), 0),
        };
        let rule_count = u32::try_from(rule_count)
            .expect("rule count fits u32: crate::acl::load bounds rule count far below u32::MAX");
        let policy = policy_ref(path, rule_count, state);
        let role_actions = role.map(|role| {
            role_grant(role)
                .actions
                .iter()
                .map(|a| a.as_str().to_string())
                .collect()
        });

        Ok(AclShowData {
            principal: principal.to_string(),
            auth_path: auth_path_str(auth_path).to_string(),
            auth_path_defaulted,
            policy,
            matching_rules,
            effective_actions,
            role: role.map(|role| role.as_str().to_string()),
            role_actions,
        })
    }
}
