//! Authorization choke point (`docs/design/architecture.md` §6,
//! `docs/ROADMAP.md` sequencing principle 5).
//!
//! The *point* of authorization exists from M1: every request the host
//! dispatches passes through [`Authorizer::check`] **before** any resource
//! (child process, ticket, PTY, socket) is created. The *policy engine*
//! (`acl.toml`, principal/wildcard matching) lands in M5; until then the
//! only policy is [`AllowAllPinned`]: any peer authenticated by a trust-store
//! pin is allowed everything, everyone else is denied. Nothing here ever
//! "fails open" — an unknown or unpinned principal is a deny.
//!
//! "Pinned" is a property of *how* the peer authenticated
//! ([`AuthPath::Pin`]), not of what its principal looks like: a CA-issued
//! leaf may carry a `qsh://device/…` SAN and thus present a
//! [`Principal::Device`] without ever having been pinned. The transport
//! reports the path alongside the principal and policy must use it.

use std::fmt;

use qsh_transport::{AuthPath, Principal};

mod load;
mod policy;

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
pub use load::{PolicyLoad, PolicySource};
pub use policy::{ActionPattern, Policy, Rule, Scope, Verdict};

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

/// A resource identifier passed to [`Policy::decide`] — just an opaque id
/// in this step (`PLAN.md` M5 Step 2). `PLAN.md` M5 Step 5 adds an
/// `owner` field once `scope` starts being evaluated; until then this is
/// a thin wrapper so `Policy::decide`'s signature doesn't have to change
/// again when that field lands.
#[derive(Debug, Clone, Copy)]
pub struct ResourceRef<'a> {
    /// Free-form resource identifier (e.g. `"exec"`, a session id,
    /// `"host:port"`) — the same string every [`Authorizer::check`] caller
    /// already passes.
    pub id: &'a str,
}

/// The single interface every privileged operation is gated by.
///
/// Implementations must be pure with respect to resources: a check never
/// creates, reserves or touches anything — it only decides.
pub trait Authorizer: Send + Sync + 'static {
    /// Decide whether `principal` (authenticated via `auth_path`) may
    /// perform `action` on `resource`. `resource` is a free-form identifier
    /// (e.g. `"exec"`, a session id).
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
        resource: &str,
    ) -> Verdict;
}

/// M1 interim policy: every *pinned* principal is allowed every action;
/// principals authenticated any other way (CA-asserted users) are denied.
/// Replaced by the `acl.toml` engine in M5.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPinned;

impl Authorizer for AllowAllPinned {
    fn check(
        &self,
        _principal: &Principal,
        auth_path: AuthPath,
        _action: Action,
        _resource: &str,
    ) -> Verdict {
        let decision = match auth_path {
            AuthPath::Pin => Decision::Allow,
            AuthPath::Ca => Decision::Deny,
        };
        // No policy engine behind this constant-time interim rule, so no
        // rule index — `rule: None` is the mechanical, behavior-preserving
        // update `PLAN.md` M5 Step 2's `Authorizer::check` signature
        // change forces here.
        Verdict {
            decision,
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
        _resource: &str,
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
                "exec"
            )
            .decision,
            Decision::Allow
        );
        assert_eq!(
            acl.check(
                &Principal::Fingerprint(Fingerprint::of_spki_der(b"k")),
                AuthPath::Pin,
                Action::ExecRun,
                "exec"
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
                "exec"
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
                    "exec"
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
                        "exec"
                    )
                    .decision,
                Decision::Deny
            );
        }
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
