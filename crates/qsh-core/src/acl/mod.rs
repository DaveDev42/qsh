//! Authorization choke point (`docs/design/architecture.md` §6,
//! `docs/ROADMAP.md` sequencing principle 5).
//!
//! The *point* of authorization exists from M1: every request the host
//! dispatches passes through [`Authorizer::check`] **before** any resource
//! (child process, ticket, PTY, socket) is created. The *policy engine*
//! (`acl.toml`, principal/wildcard matching, [`Policy`]/[`load::load_or_deny`])
//! is production-wired from M5 Step 6: `crate::serve::host_runtime` and
//! `crate::reverse::listen`'s controller both build their [`Authorizer`]
//! from `acl.toml` now, falling back to [`DenyAll`] — never to
//! [`AllowAllPinned`] — when no usable policy could be loaded. Nothing here
//! ever "fails open" — an unknown or unpinned principal is a deny, and so
//! is every principal at all until an operator writes a policy down.
//! [`AllowAllPinned`] itself survives only as the M1–M4 interim policy's
//! historical implementation and a test double; no production constructor
//! reaches for it any more.
//!
//! "Pinned" is a property of *how* the peer authenticated
//! ([`AuthPath::Pin`]), not of what its principal looks like: a CA-issued
//! leaf may carry a `qsh://device/…` SAN and thus present a
//! [`Principal::Device`] without ever having been pinned. The transport
//! reports the path alongside the principal and policy must use it.

use std::fmt;
use std::str::FromStr;

use qsh_transport::{AuthPath, Principal};

mod load;
mod policy;
mod registry;

// F8 (M5 Step 2 adversarial review) asked whether `ActionPattern` (and,
// to stay lint-consistent, its `Policy`/`Rule`/`Scope`/`PolicySource`/
// `PolicyLoad` neighbors — `Rule.allow: Vec<ActionPattern>` etc. would
// otherwise leak a narrower-than-its-container type and trip
// `private_interfaces` under `-D warnings`) should drop from `pub` to
// `pub(crate)`, since nothing outside `qsh-core` names any of them today.
// Tried it: `cargo build -p qsh-core --lib` (i.e. the plain library
// target `--all-targets` also builds, distinct from the test target)
// then reports every item in this whole family as `dead_code` — rustc
// exempts genuinely `pub` items from that lint on the theory that a
// downstream crate might use them, but a `pub(crate)` item needs an
// actual in-crate caller, and `PLAN.md` M5 Step 6 — not this step — is
// what wires `PolicySource::load`/`Policy` into a production
// `Authorizer` slot. That would fail this step's `-D warnings` gate for
// a purely cosmetic visibility narrowing, so these stay `pub` (REBUTTED
// half of F8; see the fixer's report). The actual fix — making
// `ActionPattern::Prefix` unforgeable — is [`policy::FamilyPrefix`]'s
// private field and `pub(crate)` constructor, which holds regardless of
// `ActionPattern` itself being nameable: no external crate can obtain a
// `FamilyPrefix` to put one in, `pub` enum or not.
pub use load::{
    ACL_POLICY_INVALID_CODE, ACL_POLICY_MISSING_CODE, ACL_STARTUP_CHECK_HINT,
    ACL_STARTUP_DENIED_CLAUSE, ACL_STARTUP_HEADLINE, ACL_STARTUP_NO_AUTOGEN, PolicyLoad,
    PolicySource, StartupDiagnostic, load_or_deny,
};
pub use policy::{ActionPattern, Policy, Rule, Scope, Verdict};
pub use registry::{
    ALWAYS_DENIED_NO_OP, DENY_SEAMS, DenySeam, OP_REGISTRY, Op, OpSpec, ResourceKind, SeamKind,
};

/// ACL action vocabulary (`docs/CLI.md` §2.5, PRD §9). Only the actions a
/// milestone can actually evaluate are listed; new ones are added when
/// their operations land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Run a non-PTY command (`exec.run`).
    ExecRun,
    /// Create a session (`session.open`).
    SessionOpen,
    /// See sessions (`session.list`, `session.get`).
    SessionList,
    /// Read a session's output stream (`session.read`, `session.attach`).
    SessionAttach,
    /// Drive a session (`session.write`, `session.resize`, `session.close`).
    SessionControl,
    /// Register as a reverse host on a `qsh listen` controller
    /// (`host.reverse`). Not an operation — the connection-time check a
    /// reverse target's `Hello.reverse` is put through before it becomes a
    /// registry entry (`docs/design/protocol.md` §11-2, `docs/CLI.md`
    /// §2.5).
    HostReverse,
    /// Dial a destination on this host's behalf for a peer's local forward
    /// (`forward.local`, `-L`). Not a control-stream operation either: it
    /// is the check a peer-opened `TCP_CONNECT` tunnel stream is put
    /// through **inline, before anything is dialed** — protocol.md §7's
    /// sole exception to the ticket rule (`docs/CLI.md` §2.5's
    /// `tunnel.open` local → `forward.local` row). The resource is the
    /// requested destination, `"host:port"`.
    ForwardLocal,
    /// Bind a listener on this host for a peer's remote forward
    /// (`forward.remote`, `-R`). This one *is* the ordinary control-stream
    /// choke point — `RemoteForwardOpen` is checked before the listener is
    /// bound, the same shape every other privileged op uses (`docs/design/
    /// protocol.md` §7's `RemoteForwardOpen`, `docs/CLI.md` §2.5's
    /// `tunnel.open` remote → `forward.remote` row). The resource is the
    /// requested bind address, `"bind_host:bind_port"`. Passing this check
    /// is necessary but not sufficient to bind: the loopback-only
    /// constraint enforced right after is a separate, non-ACL host
    /// constraint (`PLAN.md` M4 Step 4) — see `crate::tunnel::remote`.
    ForwardRemote,
    /// Dial a destination through a SOCKS5 proxy on this host's behalf
    /// (`forward.socks`, `-D`). PRD §9 defines the vocabulary now, but the
    /// feature itself is P1 and unimplemented (`docs/ROADMAP.md` §3
    /// deferred-feature guardrail table) — this action is **always denied**
    /// regardless of any `acl.toml` rule, see [`Action::is_always_denied`].
    /// The CLI already refuses `-D` at the flag layer with `UNSUPPORTED`
    /// (M4 Step 6); this action gate is what answers a peer that speaks the
    /// wire directly, bypassing the CLI.
    ForwardSocks,
    /// Read a file over a (not-yet-defined) file-transfer operation
    /// (`file.read`). PRD §9 vocabulary, P1-deferred, **always denied** —
    /// same guardrail as [`Action::ForwardSocks`].
    FileRead,
    /// Write a file over a (not-yet-defined) file-transfer operation
    /// (`file.write`). PRD §9 vocabulary, P1-deferred, **always denied** —
    /// same guardrail as [`Action::ForwardSocks`].
    FileWrite,
}

impl Action {
    /// Every action this build can evaluate, in a stable order — the full
    /// PRD §9 vocabulary (`crates/qsh-core/tests/acl_docs.rs` fails CI if
    /// this ever drifts from that list).
    pub const ALL: [Action; 11] = [
        Action::ExecRun,
        Action::SessionOpen,
        Action::SessionList,
        Action::SessionAttach,
        Action::SessionControl,
        Action::HostReverse,
        Action::ForwardLocal,
        Action::ForwardRemote,
        Action::ForwardSocks,
        Action::FileRead,
        Action::FileWrite,
    ];

    /// The dotted action string used in `acl.toml` and audit records
    /// (`docs/CLI.md` §2.5, right-hand column).
    pub fn as_str(self) -> &'static str {
        match self {
            Action::ExecRun => "exec.run",
            Action::SessionOpen => "session.open",
            Action::SessionList => "session.list",
            Action::SessionAttach => "session.attach",
            Action::SessionControl => "session.control",
            Action::HostReverse => "host.reverse",
            Action::ForwardLocal => "forward.local",
            Action::ForwardRemote => "forward.remote",
            Action::ForwardSocks => "forward.socks",
            Action::FileRead => "file.read",
            Action::FileWrite => "file.write",
        }
    }

    /// Whether this action is denied unconditionally, independent of any
    /// `acl.toml` rule — the closed set of PRD §9 actions that are defined
    /// but not implemented in P0 (`docs/ROADMAP.md` §3 deferred-feature
    /// guardrail table: `forward.socks`, `file.read`, `file.write`).
    ///
    /// The M5 policy evaluator (`PLAN.md` Step 2) must apply this gate
    /// **before** wildcard rule matching, not fold it into matching itself:
    /// an operator's `allow = ["forward.*"]` would otherwise silently
    /// swallow `forward.socks` too, since trailing-`.*` wildcard matching
    /// alone cannot express "defined but never allowed" — only this
    /// upfront gate can.
    pub fn is_always_denied(self) -> bool {
        matches!(
            self,
            Action::ForwardSocks | Action::FileRead | Action::FileWrite
        )
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure to parse an action string.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid action {0:?}: not one of the PRD §9 action vocabulary")]
pub struct ActionParseError(pub String);

impl FromStr for Action {
    type Err = ActionParseError;

    /// Exact match against [`Action::ALL`] only — never a `acl.toml`-style
    /// trailing-`.*` family wildcard (`qsh acl check --action` names one
    /// concrete action to evaluate, the same way a real request's wire
    /// action always does; wildcards are a policy-file-only grammar,
    /// `crate::acl::load::parse_action_pattern`'s own territory).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Action::ALL
            .into_iter()
            .find(|action| action.as_str() == s)
            .ok_or_else(|| ActionParseError(s.to_string()))
    }
}

/// The outcome of an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Permit the action.
    Allow,
    /// Refuse the action.
    Deny,
}

impl Decision {
    /// `"allow"` / `"deny"`, as written to the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }

    /// Whether this is [`Decision::Allow`].
    pub fn is_allow(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// The exact, invariant text of every remote-facing `PERMISSION_DENIED`
/// refusal (`PLAN.md` M5 Step 4 §4.2). Every seam that can answer a peer
/// with [`qsh_proto::ErrorCode::PermissionDenied`] — the authorization
/// choke points (`Server::authorize`, `Server::authorize_stream`, and
/// `Server::authorize`'s owner-aware sibling `Server::authorize_owned`
/// behind both `Server::authorize_session_control` and
/// `Server::handle_rfwd_close`'s `RemoteForwardClose` gate, `PLAN.md` M5
/// Step 5; `reverse::admit::admit`), their audit-record-failure
/// fail-closed branches (`PLAN.md` M5 Step 3), and the `forward.local`
/// inline `TCP_CONNECT` gate — uses this constant verbatim and nothing
/// else. [`registry::DENY_SEAMS`] is the enumeration of every such seam; a
/// remote-facing deny seam added without a row there is a defect.
///
/// Why one opaque sentence instead of a message naming the action,
/// capability, or resource that was refused: once the M5 policy engine
/// (`PLAN.md` Step 6) evaluates real `acl.toml` rules, a message that
/// names *what* was denied turns every refusal into a one-bit oracle. A
/// peer that cannot yet see a session, a forward, or a capability could
/// otherwise walk the action vocabulary one probe at a time and read
/// back its own missing permissions from the wording alone —
/// `session.write` worked, `session.resize` said "peer is not allowed
/// to session.resize", therefore resize (and only resize) is off. The
/// wire's `PermissionDenied` `code` already tells the caller *that* it
/// was denied; `code` is the only part of the envelope automation may
/// depend on (`docs/CLI.md` §3.2). This message carries no information
/// beyond the code — it never names the action, the capability, the
/// resource, or the principal — and it is byte-identical whether the
/// request was refused by an ordinary policy rule, by a `scope = "owned"`
/// ownership mismatch (`PLAN.md` M5 Step 5 — evaluated inside the same
/// [`Authorizer::check`] call as everything else since that step, fed by
/// `Server::require_opener`'s thin broker lookup), or by an audit-record
/// failure forcing fail-closed: the non-distinguishing error policy
/// `docs/design/protocol.md` §10-2 requires (re-pinned for
/// `session.control` in `crates/qsh-testkit/tests/session_loopback.rs`).
///
/// `localctl`'s `NotOwner` refusal ("this forward is owned by another
/// client on this host", [`crate::localctl::daemon`]) is deliberately
/// **not** this constant: it is a same-uid local trust boundary between
/// two local clients of one host's daemon, not a remote peer's
/// authorization outcome (`docs/design/protocol.md` §11-3, "localctl은
/// 인가 계층이 아니다"). Unifying the two would blur an axis the protocol
/// keeps separate on purpose.
pub const PERMISSION_DENIED_MESSAGE: &str =
    "peer is not allowed to perform this operation on this host";

/// A resource identifier passed to [`Policy::decide`], plus (`PLAN.md` M5
/// Step 5) that resource's owner, when it has one. `owner` is the
/// [`opener_key`] of whichever principal/auth_path pair created the
/// resource — a session's broker-recorded opener, or a remote forward's
/// registering principal — and is `None` for every resource kind that has
/// no owner concept at all (`exec.run`, `host.reverse`, `forward.local`:
/// [`Scope`](policy::Scope)'s own doc). `scope = "owned"` compares this
/// field against the requester's own `opener_key`; a resource with
/// `owner: None` is never affected by `scope` either way, which is what
/// lets a not-yet-existing resource (e.g. `session.control` racing a
/// session the broker cannot find) pass through unfiltered instead of
/// being invented into a false deny (`Server::require_opener`'s own doc).
#[derive(Debug, Clone, Copy)]
pub struct ResourceRef<'a> {
    /// Free-form resource identifier (e.g. `"exec"`, a session id,
    /// `"host:port"`) — the same string every [`Authorizer::check`] caller
    /// already passes.
    pub id: &'a str,
    /// This resource's owner key ([`opener_key`]), or `None` for a
    /// resource kind that has no owner concept.
    pub owner: Option<&'a str>,
}

impl<'a> ResourceRef<'a> {
    /// A resource with no owner concept — every call site but the two
    /// ownership-aware ones (`Server::authorize_session_control`,
    /// `Server::handle_rfwd_close`) construct their `ResourceRef` this way.
    pub fn unowned(id: &'a str) -> Self {
        Self { id, owner: None }
    }
}

/// The single interface every privileged operation is gated by.
///
/// Implementations must be pure with respect to resources: a check never
/// creates, reserves or touches anything — it only decides.
pub trait Authorizer: Send + Sync + 'static {
    /// Decide whether `principal` (authenticated via `auth_path`) may
    /// perform `action` on `resource`.
    ///
    /// Returns a [`Verdict`], not a bare [`Decision`]: the matching rule's
    /// index (when one matched) travels with the decision so callers can
    /// pass it straight to [`crate::audit::AuditRecord`] without a second
    /// lookup (`PLAN.md` M5 §4.1 #8).
    fn check(
        &self,
        principal: &Principal,
        auth_path: AuthPath,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict;
}

/// The opener/ownership key folding `(principal, auth_path)` into the one
/// string every owned [`ResourceRef::owner`] carries and every `scope =
/// "owned"` comparison is made against (`PLAN.md` M5 Step 5, `Scope`'s own
/// doc). Not `principal.to_string()` alone: a CA-issued leaf may legally
/// assert the same principal a trust-store pin does
/// (`qsh_transport::AuthPath`'s own doc), so folding `auth_path` in is
/// what keeps a pinned opener's identity from being re-assertable by any
/// CA-chained leaf that happens to share its principal.
///
/// Lived as a private `server::opener_key` since M3 (Step 3.5 PR②); moved
/// here when M5 Step 5 promoted the ownership comparison itself from a
/// `Server`-private post-check into the policy vocabulary
/// ([`Policy::decide`], [`AllowAllPinned::check`]). `pub`, not
/// `pub(crate)`: `crates/qsh-testkit`'s test doubles that reproduce this
/// same comparison for a hypothetical wider-admitting [`Authorizer`] (e.g.
/// `session_loopback.rs`'s `AllowAllAnyAuthPath`) need it too, and
/// `qsh-testkit` is allowed to depend on anything in `qsh-core`
/// (`CLAUDE.md`'s crate dependency matrix).
pub fn opener_key(principal: &Principal, auth_path: AuthPath) -> String {
    format!("{auth_path:?}:{principal}")
}

/// M1–M4 interim policy: every *pinned* principal is allowed every action;
/// principals authenticated any other way (CA-asserted users) are denied.
/// Replaced in every production constructor by the `acl.toml` engine
/// (`load::load_or_deny`) as of M5 Step 6 — kept only as a test double now
/// (e.g. `crates/qsh-testkit`'s in-process harnesses, which construct their
/// own `Authorizer` directly and were never routed through
/// `load_or_deny`).
///
/// Reproduces M3's opener-principal ownership P0 for `resource.owner:
/// Some(_)` (`PLAN.md` M5 Step 5's interim-invariant requirement: this
/// stand-in has to behave as `scope = "owned"` for every owned resource,
/// since it is what production still runs until Step 6 wires a real
/// `Policy` in) — a pinned principal is allowed every *unowned* action
/// unconditionally, but an owned one only when it is also the resource's
/// own owner. `resource.owner: None` is never filtered, same as
/// [`Policy::decide`]'s ④.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPinned;

impl Authorizer for AllowAllPinned {
    fn check(
        &self,
        principal: &Principal,
        auth_path: AuthPath,
        _action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict {
        let pinned = matches!(auth_path, AuthPath::Pin);
        let owned = match resource.owner {
            Some(owner) => owner == opener_key(principal, auth_path),
            None => true,
        };
        // No policy engine behind this constant-time interim rule, so no
        // rule index — `rule: None` is the mechanical, behavior-preserving
        // update `PLAN.md` M5 Step 2's `Authorizer::check` signature
        // change forces here.
        Verdict {
            decision: if pinned && owned {
                Decision::Allow
            } else {
                Decision::Deny
            },
            rule: None,
        }
    }
}

/// A policy that denies everything. Useful as a test double and as the
/// fail-closed fallback when no policy could be loaded.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAll;

impl Authorizer for DenyAll {
    fn check(
        &self,
        _principal: &Principal,
        _auth_path: AuthPath,
        _action: Action,
        _resource: ResourceRef<'_>,
    ) -> Verdict {
        Verdict {
            decision: Decision::Deny,
            rule: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_transport::Fingerprint;

    #[test]
    fn allow_all_pinned_allows_pinned_peers_only() {
        let acl = AllowAllPinned;
        assert_eq!(
            acl.check(
                &Principal::Device("laptop".into()),
                AuthPath::Pin,
                Action::ExecRun,
                ResourceRef::unowned("exec")
            )
            .decision,
            Decision::Allow
        );
        assert_eq!(
            acl.check(
                &Principal::Fingerprint(Fingerprint::of_spki_der(b"k")),
                AuthPath::Pin,
                Action::ExecRun,
                ResourceRef::unowned("exec")
            )
            .decision,
            Decision::Allow
        );
        // CA-asserted user: not pinned → denied under the interim policy.
        assert_eq!(
            acl.check(
                &Principal::User("dave".into()),
                AuthPath::Ca,
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
                    &Principal::Device("laptop".into()),
                    AuthPath::Ca,
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
                        &Principal::Device("x".into()),
                        path,
                        Action::ExecRun,
                        ResourceRef::unowned("exec")
                    )
                    .decision,
                Decision::Deny
            );
        }
    }

    /// `PLAN.md` M5 Step 5's interim invariant: `AllowAllPinned` must keep
    /// denying a non-owner on an owned resource exactly as M3's hardcoded
    /// `require_opener` gate did — production still runs this authorizer,
    /// not a real `Policy`, until Step 6.
    #[test]
    fn allow_all_pinned_denies_a_pinned_non_owner_on_an_owned_resource() {
        let acl = AllowAllPinned;
        let owner_key = opener_key(&Principal::Device("laptop".into()), AuthPath::Pin);
        let verdict = acl.check(
            &Principal::Device("desktop".into()),
            AuthPath::Pin,
            Action::SessionControl,
            ResourceRef {
                id: "sess-1",
                owner: Some(&owner_key),
            },
        );
        assert_eq!(verdict.decision, Decision::Deny);

        // The owner itself is unaffected.
        let verdict = acl.check(
            &Principal::Device("laptop".into()),
            AuthPath::Pin,
            Action::SessionControl,
            ResourceRef {
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
            &Principal::Device("laptop".into()),
            AuthPath::Ca,
            Action::SessionControl,
            ResourceRef {
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
            &Principal::Device("desktop".into()),
            AuthPath::Pin,
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
    fn is_always_denied_is_exactly_the_p1_deferred_trio() {
        // docs/ROADMAP.md §3 deferred-feature guardrail table: exactly
        // `forward.socks`/`file.read`/`file.write` are "defined but always
        // denied" — every other action is a normal, policy-evaluated one.
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
}
