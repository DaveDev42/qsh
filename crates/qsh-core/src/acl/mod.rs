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
use std::path::Path;
use std::str::FromStr;

use qsh_transport::{AuthPath, Principal};

use crate::broker::PeerFingerprint;
use crate::file::guard::Normalizer;

mod load;
mod paths;
mod policy;
mod registry;
mod resolving;
mod roles;

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
// actual in-crate caller, and M5 plan Step 6 (2473c88) — not this step — is
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
    ACL_STARTUP_DENIED_CLAUSE, ACL_STARTUP_HEADLINE, ACL_STARTUP_MISSING_LINE,
    ACL_STARTUP_NO_AUTOGEN, ACL_STARTUP_ROLES_ONLY_CLAUSE, PinnedPrincipalIndex, PolicyLoad,
    PolicySource, Role, StartupDiagnostic, load_or_deny, load_or_deny_with_index,
};
// Crate-internal only (not part of `qsh-core`'s public surface):
// `crate::ops::doctor`'s `acl_principal_unmatched`/`acl_ca_auth_path_missing`
// findings build their own `detail` example rows from these, the same
// generators `minimal_policy_example` (used only inside `acl::load` now)
// itself calls for `acl_policy_missing`/`acl_policy_invalid`.
pub(crate) use load::{
    ca_policy_example_row, example_allow_actions, load_policy_or_deny, policy_example_rows,
    policy_example_rows_with,
};
pub use policy::{ActionPattern, GrantBasis, Policy, Rule, Scope, Verdict};
pub use resolving::RoleResolvingAuthorizer;
pub use roles::{ROLE_GRANTS, RoleGrant, RoleScope, role_grant};

// Expands to the literal restart-notice string below. A `macro_rules!`
// rather than a plain `&str` fn/const alias so `crate::doctor`'s two
// `&'static str` `remedy` fields — which must stay `concat!`-able at
// compile time — can splice it in directly:
// `concat!("…, then ", crate::acl::acl_restart_notice!())`. Private by
// default (module-scoped macro namespace); the `pub(crate) use` below is
// what makes `crate::acl::acl_restart_notice!()` resolvable by path from
// `doctor.rs`, the same re-export idiom every other item in this file
// uses (`policy::…`, `load::…`) — no `#[macro_export]`, since nothing
// outside this crate calls it.
macro_rules! acl_restart_notice {
    () => {
        "restart serve/listen — acl.toml is only read once at process start."
    };
}
pub(crate) use acl_restart_notice;

/// The verbatim restart notice every ACL doctor remedy that requires a
/// restart ends with (ADR-0017 결정 2: `acl.toml` loads once at process
/// start, there is no hot reload) — the same `acl_restart_notice!()`
/// expansion as [`crate::doctor::ACL_PRINCIPAL_UNMATCHED`]'s and
/// [`crate::doctor::ACL_CA_AUTH_PATH_MISSING`]'s `remedy` tails (those two
/// use the macro directly, via `concat!`, since a `remedy` is
/// `&'static str` and this constant is not itself a literal). `qsh acl
/// show`'s human renderer (`docs/CLI.md` §6.19, ADR-0025 결정 6) is meant
/// to print this constant as its own standalone line, and M12's `qsh
/// setup` (ADR-0024 결정 4) a fourth consumer — both read from this one
/// constant rather than retyping the wording, so the surfaces can never
/// drift apart.
pub const ACL_RESTART_NOTICE: &str = acl_restart_notice!();
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
    /// constraint (M4 plan Step 4 (2473c88)) — see `crate::tunnel::remote`.
    ForwardRemote,
    /// Dial a destination through a SOCKS5 proxy on this host's behalf
    /// (`forward.socks`, `-D`). `-D` is implemented (ADR-0019, ADR-0020,
    /// both routes) — but every `CONNECT` it opens is authorized on the
    /// peer as [`Action::ForwardLocal`] against the requested `host:port`,
    /// the same gate `-L` uses (ADR-0019 결정 6). A client-attached label
    /// cannot carry authorization, so no wire op will ever be built to
    /// drive `forward.socks` — it is **always denied** regardless of any
    /// `acl.toml` rule, see [`Action::is_always_denied`], permanently by
    /// design rather than pending one.
    ForwardSocks,
    /// Read a file or list a directory over the remote file ops
    /// (`file.read`, `file.list`; ADR-0029 decision 3). A role grants it for
    /// any path, a row only together with `paths`; the host's state tree
    /// stays out of reach either way.
    FileRead,
    /// Write a file or create a directory over the remote file ops
    /// (`file.write`, `file.mkdir`; ADR-0029 decision 3). Same standing as
    /// [`Action::FileRead`].
    FileWrite,
}

impl Action {
    /// Every action this build can evaluate, in a stable order — the full
    /// PRD §9 vocabulary (`crates/qsh-core/tests/it/acl_docs.rs` fails CI if
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
    /// `acl.toml` rule and any trust role: today only `forward.socks`,
    /// which is always denied by design (ADR-0019 결정 6). `-D` is
    /// implemented, but every `CONNECT` it opens is authorized on the peer
    /// as `forward.local`, and a client-attached label cannot carry
    /// authorization, so no wire op will ever drive `forward.socks` itself.
    /// `file.read` and `file.write` left this set when the host control
    /// plane landed (ADR-0029 결정 3); they are granted by a role or by a
    /// row with `paths`, and the protected state tree stays out of reach
    /// whatever grants them (ADR-0029 결정 5, checked after the decision).
    ///
    /// The M5 policy evaluator (M5 plan Step 2 (2473c88)) must apply this gate
    /// **before** wildcard rule matching, not fold it into matching itself:
    /// an operator's `allow = ["forward.*"]` would otherwise silently
    /// swallow `forward.socks` too, since trailing-`.*` wildcard matching
    /// alone cannot express "defined but never allowed" — only this
    /// upfront gate can.
    pub fn is_always_denied(self) -> bool {
        matches!(self, Action::ForwardSocks)
    }
}

impl Action {
    /// Whether this is one of the two file actions (`file.read`,
    /// `file.write`), the ones a row can only grant together with `paths`
    /// (ADR-0029 결정 4).
    pub fn is_file(self) -> bool {
        matches!(self, Action::FileRead | Action::FileWrite)
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
/// refusal (M5 plan Step 4 §4.2 (2473c88)). Every seam that can answer a peer
/// with [`qsh_proto::ErrorCode::PermissionDenied`] — the authorization
/// choke points (`Server::authorize`, `Server::authorize_stream`, and
/// `Server::authorize`'s owner-aware sibling `Server::authorize_owned`
/// behind both `Server::authorize_session_control` and
/// `Server::handle_rfwd_close`'s `RemoteForwardClose` gate, the M5 plan (2473c88)
/// Step 5; `reverse::admit::admit`), their audit-record-failure
/// fail-closed branches (M5 plan Step 3 (2473c88)), and the `forward.local`
/// inline `TCP_CONNECT` gate — uses this constant verbatim and nothing
/// else. [`registry::DENY_SEAMS`] is the enumeration of every such seam; a
/// remote-facing deny seam added without a row there is a defect.
///
/// Why one opaque sentence instead of a message naming the action,
/// capability, or resource that was refused: once the M5 policy engine
/// (M5 plan Step 6 (2473c88)) evaluates real `acl.toml` rules, a message that
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
/// ownership mismatch (M5 plan Step 5 (2473c88) — evaluated inside the same
/// [`Authorizer::check`] call as everything else since that step, fed by
/// `Server::require_opener`'s thin broker lookup), or by an audit-record
/// failure forcing fail-closed: the non-distinguishing error policy
/// `docs/design/protocol.md` §10-2 requires (re-pinned for
/// `session.control` in `crates/qsh-testkit/tests/it/session_loopback.rs`).
///
/// `localctl`'s `NotOwner` refusal ("this forward is owned by another
/// client on this host", `crate::localctl::daemon`) is deliberately
/// **not** this constant: it is a same-uid local trust boundary between
/// two local clients of one host's daemon, not a remote peer's
/// authorization outcome (`docs/design/protocol.md` §11-3, "localctl은
/// 인가 계층이 아니다"). Unifying the two would blur an axis the protocol
/// keeps separate on purpose.
pub const PERMISSION_DENIED_MESSAGE: &str =
    "peer is not allowed to perform this operation on this host";

/// A resource identifier passed to `Policy::decide`, plus (the M5 plan (2473c88)
/// Step 5) that resource's owner, when it has one. `owner` is the
/// [`opener_key`] of whichever principal/auth_path pair created the
/// resource — a session's broker-recorded opener, or a remote forward's
/// registering principal — and is `None` for every resource kind that has
/// no owner concept at all (`exec.run`, `host.reverse`, `forward.local`:
/// [`Scope`]'s own doc). `scope = "owned"` compares this
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
    /// The canonical path of a remote file request (ADR-0029 결정 4-7), with
    /// the function that produced it. `None` for every non-file action, and
    /// for a file request whose normalization failed or was skipped. A row
    /// granting a file action only matches when this is `Some` and one of its
    /// `paths` entries covers it (evaluation step ③-1); a trust role's file
    /// grant ignores it (ADR-0045 결정 5).
    pub canonical_path: Option<CanonicalPath<'a>>,
}

impl<'a> ResourceRef<'a> {
    /// A resource with no owner concept — every call site but the two
    /// ownership-aware ones (`Server::authorize_session_control`,
    /// `Server::handle_rfwd_close`) construct their `ResourceRef` this way.
    pub fn unowned(id: &'a str) -> Self {
        Self {
            id,
            owner: None,
            canonical_path: None,
        }
    }

    /// This resource with the canonical path of a file request attached.
    /// Files have no qsh owner, so only the path is added (ADR-0029
    /// 결정 4-7).
    pub fn with_canonical_path(self, path: &'a Path, normalizer: &'a dyn Normalizer) -> Self {
        Self {
            canonical_path: Some(CanonicalPath { path, normalizer }),
            ..self
        }
    }
}

/// A file request's canonical path plus the normalization function that
/// produced it (ADR-0029 결정 4-4·6-2). The evaluator normalizes each `paths`
/// entry of a candidate row with the very same function, per request, so the
/// request and the entries always meet in one form; an entry that cannot be
/// normalized covers nothing.
#[derive(Clone, Copy)]
pub struct CanonicalPath<'a> {
    /// The request's canonical path.
    pub path: &'a Path,
    /// The normalizer that produced [`Self::path`] and normalizes `paths`
    /// entries.
    pub normalizer: &'a dyn Normalizer,
}

impl fmt::Debug for CanonicalPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalPath")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Who is asking: the authenticated identity of the connection a request
/// arrived on, as one bundle (ADR-0045 결정 6, PLAN M15 Step 3).
///
/// Three fields rather than three loose [`Authorizer::check`] arguments so
/// that adding a requester-side input never again changes every call site's
/// argument list. `fingerprint` is the connection's verified leaf
/// fingerprint (`ConnCtx::peer_fingerprint`): the role stage ⓡ compares it
/// against the *current* pin of a `device:<name>` principal, so a connection
/// that outlives a `trust remove` or a re-pin cannot inherit the new pin's
/// role (ADR-0045 결정 4). `None` means the leaf did not re-parse; a
/// fingerprint-dependent stage then grants nothing (fail closed).
#[derive(Debug, Clone, Copy)]
pub struct Requester<'a> {
    /// Authenticated peer principal (from the certificate).
    pub principal: &'a Principal,
    /// How the peer authenticated (pin vs. CA).
    pub auth_path: AuthPath,
    /// SPKI SHA-256 of the connection's verified leaf certificate.
    pub fingerprint: Option<PeerFingerprint>,
}

impl<'a> Requester<'a> {
    /// Bundle the three requester-side inputs.
    pub fn new(
        principal: &'a Principal,
        auth_path: AuthPath,
        fingerprint: Option<PeerFingerprint>,
    ) -> Self {
        Self {
            principal,
            auth_path,
            fingerprint,
        }
    }
}

/// The single interface every privileged operation is gated by.
///
/// Implementations must be pure with respect to resources: a check never
/// creates, reserves or touches anything — it only decides.
pub trait Authorizer: Send + Sync + 'static {
    /// Decide whether `requester` (a principal authenticated via an
    /// `auth_path`, on a connection with a verified leaf fingerprint) may
    /// perform `action` on `resource`.
    ///
    /// Returns a [`Verdict`], not a bare [`Decision`]: the matching rule's
    /// index (when one matched) travels with the decision so callers can
    /// pass it straight to [`crate::audit::AuditRecord`] without a second
    /// lookup (M5 plan §4.1 #8 (2473c88)).
    fn check(
        &self,
        requester: &Requester<'_>,
        action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict;

    /// Whether `requester` has any ground to be granted the file `action`
    /// at all (ADR-0029 결정 4-6 (a)): a role that lists it, or a row that
    /// selects the requester, covers the action and carries `paths`. A pure
    /// judgment with no path in it. The host asks it before it normalizes
    /// the request path, so a requester with no ground never makes the host
    /// look at a path. It is a pre-filter, not the decision: [`Self::check`]
    /// still decides, and a `false` here must agree with a deny there.
    ///
    /// The default answers `true` ("normalize, then let `check` decide"),
    /// which is right for any evaluator that does not model `paths`.
    fn has_file_grant(&self, _requester: &Requester<'_>, _action: Action) -> bool {
        true
    }
}

/// The opener/ownership key folding `(principal, auth_path)` into the one
/// string every owned [`ResourceRef::owner`] carries and every `scope =
/// "owned"` comparison is made against (M5 plan Step 5 (2473c88), `Scope`'s own
/// doc). Not `principal.to_string()` alone: a CA-issued leaf may legally
/// assert the same principal a trust-store pin does
/// (`qsh_transport::AuthPath`'s own doc), so folding `auth_path` in is
/// what keeps a pinned opener's identity from being re-assertable by any
/// CA-chained leaf that happens to share its principal.
///
/// Lived as a private `server::opener_key` since M3 (Step 3.5 PR②); moved
/// here when M5 Step 5 promoted the ownership comparison itself from a
/// `Server`-private post-check into the policy vocabulary
/// (`Policy::decide`, [`AllowAllPinned::check`]). `pub`, not
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
/// Some(_)` (M5 plan Step 5 (2473c88)'s interim-invariant requirement: this
/// stand-in has to behave as `scope = "owned"` for every owned resource,
/// since it is what production still runs until Step 6 wires a real
/// `Policy` in) — a pinned principal is allowed every *unowned* action
/// unconditionally, but an owned one only when it is also the resource's
/// own owner. `resource.owner: None` is never filtered, same as
/// `Policy::decide`'s ④.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPinned;

impl Authorizer for AllowAllPinned {
    fn check(
        &self,
        requester: &Requester<'_>,
        _action: Action,
        resource: ResourceRef<'_>,
    ) -> Verdict {
        let pinned = matches!(requester.auth_path, AuthPath::Pin);
        let owned = match resource.owner {
            Some(owner) => owner == opener_key(requester.principal, requester.auth_path),
            None => true,
        };
        // No policy engine behind this constant-time interim rule, so no
        // rule index — `rule: None` is the mechanical, behavior-preserving
        // update M5 plan Step 2 (2473c88)'s `Authorizer::check` signature
        // change forces here.
        if pinned && owned {
            Verdict::ALLOW_UNBASED
        } else {
            Verdict::DENY
        }
    }
}

/// A policy that denies everything. Useful as a test double and as the
/// fail-closed fallback when no policy could be loaded.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAll;

impl Authorizer for DenyAll {
    fn has_file_grant(&self, _requester: &Requester<'_>, _action: Action) -> bool {
        false
    }

    fn check(
        &self,
        _requester: &Requester<'_>,
        _action: Action,
        _resource: ResourceRef<'_>,
    ) -> Verdict {
        Verdict::DENY
    }
}

#[cfg(test)]
mod tests;
