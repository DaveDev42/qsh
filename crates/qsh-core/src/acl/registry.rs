//! The registry of every seam that can answer a remote peer with
//! [`qsh_proto::ErrorCode::PermissionDenied`] (`PLAN.md` M5 Step 4 DoD 4).
//!
//! This is not a test fixture that happens to live in `qsh-core` — it is
//! the one table both this milestone's exhaustive uniformity test
//! (`crates/qsh-testkit/tests/acl_uniformity.rs`) and `PLAN.md` M5 Step 8's
//! SC6 op registry enumeration are meant to consume. Adding a new
//! remote-facing deny seam (a new control-stream op, a new inline gate, a
//! new registration-time check) without adding a row here is a defect:
//! the seam would silently escape both the uniformity test's coverage and
//! Step 8's enumeration.
//!
//! What belongs here is deliberately narrower than "every ACL-gated
//! action": a row exists only for a seam that can *itself* put a remote
//! peer through a `PERMISSION_DENIED` refusal — verbatim
//! [`super::PERMISSION_DENIED_MESSAGE`] for a [`SeamKind::ControlStreamOp`]/
//! [`SeamKind::TunnelInline`]/[`SeamKind::ReverseRegistration`] row, or the
//! wire-shape-appropriate equivalent (a stream reset with the right code
//! and a real audit deny record) for the message-less
//! [`SeamKind::StreamReset`] row.
//!
//! The session-data reattach inline gate (`Server::handle_data_stream`'s
//! `SessionData` ticket branch, `authorize_stream` on
//! `Action::SessionAttach`) refuses by resetting the QUIC stream with no
//! message field at all — there is no text to unify, so its row
//! (`"session.attach@data-stream"`, [`SeamKind::StreamReset`]) is held to
//! a different uniformity obligation than every other row: the correct
//! reset code (`RESET_CODE_FORBIDDEN`) plus a real audit deny record,
//! never message equality. See [`SeamKind::StreamReset`]'s own doc.
//!
//! `forward.socks` / `file.read` / `file.write` are excluded too: they are
//! always-denied (`Action::is_always_denied`) but P1-unimplemented — no
//! wire op exists yet for a peer to hit the gate through. This exclusion
//! is anchored by this module's own `#[cfg(test)]`
//! `deny_seams_cover_every_action_except_the_always_denied_trio`: it fails
//! the moment a new `Action` — always-denied or not — has no row and no
//! documented exclusion here.

use super::Action;

/// The kind of seam a [`DenySeam`] row describes — distinguishes how the
/// exhaustive test (`acl_uniformity.rs`) must drive it, since the three
/// kinds are three different wire shapes:
///
/// - [`SeamKind::ControlStreamOp`]: an ordinary `qsh.cli/v1` control-stream
///   request/response op (`Server::authorize` /
///   `Server::authorize_session_control`, `docs/CLI.md` §2.4).
/// - [`SeamKind::TunnelInline`]: the `forward.local` `TCP_CONNECT` inline
///   gate — answered on the data stream via `ConnectResult`, not a control
///   message (`docs/design/protocol.md` §7).
/// - [`SeamKind::ReverseRegistration`]: the `host.reverse` connection-time
///   registration check (`reverse::admit::admit`, `docs/design/
///   protocol.md` §11-2).
/// - [`SeamKind::StreamReset`]: the `SessionData` reattach inline gate —
///   `Server::handle_data_stream`'s `SessionData` ticket branch, gated on
///   `Action::SessionAttach` through the same `authorize_stream` helper
///   [`SeamKind::TunnelInline`] uses, but answered with a bare QUIC stream
///   reset (`RESET_CODE_FORBIDDEN`), not any message — there is no wire
///   envelope here for [`super::PERMISSION_DENIED_MESSAGE`] to appear in,
///   so this kind's uniformity obligation is the reset code plus a real
///   audit deny record, never message equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeamKind {
    /// An ordinary control-stream request/response op.
    ControlStreamOp,
    /// The `forward.local` inline `TCP_CONNECT` gate.
    TunnelInline,
    /// The `host.reverse` connection-time registration check.
    ReverseRegistration,
    /// The `SessionData` reattach inline gate — message-less by wire
    /// shape (a QUIC stream reset), so its obligation is reset code +
    /// audit record, not text.
    StreamReset,
}

/// One row: a named seam, the [`Action`] it authorizes, and its
/// [`SeamKind`]. `name` is the wire op name (`docs/CLI.md` §2.4/§2.5)
/// where the seam is a control-stream op, and the seam's own name
/// otherwise (`forward.local`, `host.reverse`,
/// `session.attach@data-stream`).
#[derive(Debug, Clone, Copy)]
pub struct DenySeam {
    /// The seam's name — a wire op name for [`SeamKind::ControlStreamOp`]
    /// rows, the seam's own name otherwise.
    pub name: &'static str,
    /// The [`Action`] this seam authorizes against.
    pub action: Action,
    /// Which of the three wire shapes this seam is.
    pub kind: SeamKind,
}

/// Every seam that can answer a remote peer with
/// [`super::PERMISSION_DENIED_MESSAGE`]. See the module doc for what is
/// deliberately excluded and why.
pub const DENY_SEAMS: &[DenySeam] = &[
    DenySeam {
        name: "exec.run",
        action: Action::ExecRun,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.open",
        action: Action::SessionOpen,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.list",
        action: Action::SessionList,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.get",
        action: Action::SessionList,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.read",
        action: Action::SessionAttach,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.attach",
        action: Action::SessionAttach,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.write",
        action: Action::SessionControl,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.resize",
        action: Action::SessionControl,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "session.close",
        action: Action::SessionControl,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "forward.remote",
        action: Action::ForwardRemote,
        kind: SeamKind::ControlStreamOp,
    },
    // `RemoteForwardClose`'s choke point (`PLAN.md` M5 Step 5 closes what
    // used to be a gap here — see this module's own former exclusion
    // note, still in history). Named `"forward.remote.close"`, not
    // `"tunnel.close"`: `docs/CLI.md` §2.4's `tunnel.close` is an `Ops`-
    // layer operation that also covers a purely local `-L` teardown (no
    // wire op, no host-side ACL check at all — `TunnelHold::close`), so
    // using it here would wrongly imply this row gates that too. It is
    // also not simply `"forward.remote"` again: that name is already
    // this array's `RfwdOpen` row, and both `RfwdOpen`/`RfwdClose` are
    // checked against the very same `Action::ForwardRemote` (`PLAN.md`
    // M5 Step 5 (a): ownership, not a new action, is what changes) — two
    // distinct wire ops sharing one `Action` need two distinct row names,
    // the same reason `session.write`/`session.resize`/`session.close`
    // are three rows under one `Action::SessionControl` rather than one.
    // `".close"` mirrors the wire message name (`RemoteForwardClose`)
    // directly off its sibling `"forward.remote"` row.
    DenySeam {
        name: "forward.remote.close",
        action: Action::ForwardRemote,
        kind: SeamKind::ControlStreamOp,
    },
    DenySeam {
        name: "forward.local",
        action: Action::ForwardLocal,
        kind: SeamKind::TunnelInline,
    },
    DenySeam {
        name: "host.reverse",
        action: Action::HostReverse,
        kind: SeamKind::ReverseRegistration,
    },
    // F3 (M5 Step 4 adversarial review): the SessionData reattach inline
    // gate (`server/mod.rs`'s `handle_data_stream`, the `SessionData`
    // ticket branch) is a fifth remote-facing seam that answers
    // `Action::SessionAttach` through `authorize_stream` — the same
    // helper `forward.local` uses — but with a bare stream reset, no
    // message. `docs/design/architecture.md` §6 lists `authorize_stream`
    // as having exactly two production callers: this one and
    // `forward.local`'s inline `TCP_CONNECT` gate.
    DenySeam {
        name: "session.attach@data-stream",
        action: Action::SessionAttach,
        kind: SeamKind::StreamReset,
    },
];

// ---------------------------------------------------------------------
// `PLAN.md` M5 Step 8 (SC6): the op registry. Every privileged operation
// this build authorizes, as one table `server::dispatch`'s handlers
// consume for their `Action` instead of naming it a second time.
// ---------------------------------------------------------------------

/// The shape of an [`OpSpec`]'s resource string — documentation only, not
/// consulted by any evaluator (`Action` + [`super::ResourceRef`] remain
/// the only inputs [`super::Authorizer::check`] sees). Lets a reader tell
/// "this row's resource is a session id" from "this row's resource is a
/// dial destination" without re-deriving it from the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// A session id, or the [`super::SESSION_RESOURCE`]-shaped sentinel
    /// `"session"` for the two ops with no single session to name
    /// (`session.open`, `session.list`).
    Session,
    /// The literal `"exec"` sentinel — `exec.run` has no addressable
    /// resource narrower than the request itself.
    Exec,
    /// A `"host:port"` dial destination chosen by the requester
    /// (`forward.local`).
    ForwardDestination,
    /// A `"bind_host:bind_port"` listen address (`forward.remote`), or a
    /// host-minted `forward_id` naming an existing one
    /// (`forward.remote.close`).
    ForwardBinding,
    /// The resolved reverse-host name being registered (`host.reverse`).
    ReverseHost,
}

/// Derives [`Op`], [`Op::ALL`], [`Op::as_str`], [`Op::spec`], and
/// [`OP_REGISTRY`] from one list of rows given to a single invocation
/// below — the actual mechanism behind `PLAN.md` M5 Step 8's "표 두 벌
/// 금지" (`(d)②`). Before this macro existed, the variant list, `ALL`,
/// and `OP_REGISTRY` were three hand-typed arrays that nothing forced to
/// agree on *membership*: a variant could be added to the enum and given
/// a `spec()` arm (so `spec()` itself still compiled — its match already
/// had no wildcard) while never being added to `ALL`/`OP_REGISTRY`, and
/// every completeness test still passed because each one enumerates
/// starting from `Op::ALL` or `OP_REGISTRY` itself rather than from the
/// `Op` type. A row authorizing real traffic could exist with no entry
/// in either list — silent by every gate in this module, including the
/// exhaustive-`match` ones, because none of them starts from a source
/// that cannot omit a variant. With one invocation as the sole place a
/// variant name is written, that state is no longer representable: the
/// enum, `ALL`, and `OP_REGISTRY` cannot disagree on which variants exist
/// because they are the same macro expansion.
macro_rules! declare_ops {
    ($( $(#[$m:meta])* $v:ident => ($name:literal, $act:expr, $rk:expr, $owned:expr) ),+ $(,)?) => {
        /// The typed key for every privileged operation this build
        /// authorizes (`PLAN.md` M5 Step 8, PRD §15 SC6) — replaces what
        /// used to be a bare `&'static str` op name looked up at runtime
        /// by the now-deleted `action_of`. [`Op::spec`]'s match is
        /// **the** table (`PLAN.md` M5 Step 8's "표 두 벌 금지"):
        /// [`OP_REGISTRY`] is only that match's own const projection,
        /// never a second hand-maintained list, so a row cannot exist in
        /// one and not the other by construction.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Op {
            $( $(#[$m])* $v ),+
        }

        impl Op {
            /// Every [`Op`] variant, in [`OP_REGISTRY`]'s declaration
            /// order — for exhaustive enumeration. This is not a second
            /// hand-maintained list: the [`declare_ops!`] invocation
            /// below derives the variant list, [`Op::as_str`],
            /// [`Op::spec`], and [`OP_REGISTRY`] from one set of rows, so
            /// there is no separate membership list a variant can be
            /// missing from — `declare_ops!`'s own doc has the mechanism
            /// this replaced.
            pub const ALL: &'static [Op] = &[ $( Op::$v ),+ ];

            /// The op's dotted name (`docs/CLI.md` §2.4/§2.5) — the exact
            /// string [`DENY_SEAMS`] and the old string-keyed `action_of`
            /// used.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Op::$v => $name ),+
                }
            }

            /// **The one table.** Every other fact about an op — its
            /// dispatch [`Action`], its resource shape, whether
            /// `scope = "owned"` narrows it — is read off this match,
            /// never named a second time (`PLAN.md` M5 Step 8's "표 두
            /// 벌 금지"; [`OP_REGISTRY`] is this match's own const
            /// projection, below). This match's exhaustiveness (no
            /// wildcard arm) is also why `action_of`'s old
            /// `#[should_panic]` "unregistered name" test was deleted
            /// outright rather than ported: a `str` key could always
            /// name something absent from the table, but an `Op`
            /// variant with no `spec()` arm fails to *compile* —
            /// "registered nowhere" stopped being a state this type can
            /// hold.
            pub const fn spec(self) -> OpSpec {
                match self {
                    $( Op::$v => OpSpec {
                        op: Op::$v,
                        action: $act,
                        resource_kind: $rk,
                        owned: $owned,
                    } ),+
                }
            }
        }

        /// Every privileged operation this build authorizes (`PLAN.md`
        /// M5 Step 8, PRD §15 SC6) — the const projection of the same
        /// [`declare_ops!`] invocation that derives [`Op`] and
        /// [`Op::ALL`], in that invocation's order. See [`OpSpec`]'s own
        /// doc for the naming rule and the relationship to
        /// [`DENY_SEAMS`], and [`ALWAYS_DENIED_NO_OP`] for the three PRD
        /// §9 actions deliberately missing from this table.
        pub const OP_REGISTRY: &[OpSpec] = &[ $( Op::$v.spec() ),+ ];
    };
}

declare_ops! {
    SessionOpen => ("session.open", Action::SessionOpen, ResourceKind::Session, false),
    SessionList => ("session.list", Action::SessionList, ResourceKind::Session, false),
    SessionGet => ("session.get", Action::SessionList, ResourceKind::Session, false),
    SessionRead => ("session.read", Action::SessionAttach, ResourceKind::Session, false),
    SessionAttach => ("session.attach", Action::SessionAttach, ResourceKind::Session, false),
    SessionWrite => ("session.write", Action::SessionControl, ResourceKind::Session, true),
    SessionResize => ("session.resize", Action::SessionControl, ResourceKind::Session, true),
    // Documented exception (`docs/design/architecture.md` §6): shares
    // `Action::SessionControl` with write/resize but is intentionally
    // never narrowed by `scope = "owned"` (cross-device close, PRD §6).
    SessionClose => ("session.close", Action::SessionControl, ResourceKind::Session, false),
    ExecRun => ("exec.run", Action::ExecRun, ResourceKind::Exec, false),
    ForwardLocal => ("forward.local", Action::ForwardLocal, ResourceKind::ForwardDestination, false),
    ForwardRemote => ("forward.remote", Action::ForwardRemote, ResourceKind::ForwardBinding, false),
    ForwardRemoteClose => ("forward.remote.close", Action::ForwardRemote, ResourceKind::ForwardBinding, true),
    HostReverse => ("host.reverse", Action::HostReverse, ResourceKind::ReverseHost, false),
}

impl Op {
    /// This op's ACL [`Action`] — the sole replacement for the deleted
    /// `action_of(op: &str) -> Action`. Every production call site now
    /// writes `Op::X.action()` instead of `action_of("x")`: the typo that
    /// used to compile and panic at runtime (`action_of("sesion.open")`)
    /// is now a name the `Op` type simply does not have, caught by rustc
    /// at the call site instead of by a test run.
    pub const fn action(self) -> Action {
        self.spec().action
    }
}

/// One row of the op registry: every privileged operation this build
/// authorizes, its ACL [`Action`], the shape of its resource string, and
/// whether `scope = "owned"` can narrow it to the resource's own
/// opener/registering principal.
///
/// [`OpSpec::op`] names a `docs/CLI.md` §2.4 dotted operation for the nine
/// rows that are one, or the seam's own §2.5-prose name for the four that
/// are not (`forward.local`, `forward.remote`, `forward.remote.close`,
/// `host.reverse`) — the exact naming [`DENY_SEAMS`] already uses.
/// Deliberately not incidental: [`OP_REGISTRY`]'s (op, action) pairs are
/// exactly [`DENY_SEAMS`]'s minus the one row with no CLI.md-documented
/// op/seam name of its own (`"session.attach@data-stream"`, the internal
/// `SessionData` reattach gate — already exhaustively covered by this
/// module's own `SeamKind::StreamReset` uniformity obligation, so folding
/// it into this table a second time under a name CLI.md never uses would
/// only test `Action::SessionAttach` a third time without adding contract
/// coverage). `tests::op_registry_matches_deny_seams_by_name_and_action`
/// (below) is the mechanical cross-check that keeps these two tables from
/// ever being hand-maintained as independent sources of the same fact —
/// `PLAN.md` M5 Step 8's "표 두 벌 금지".
#[derive(Debug, Clone, Copy)]
pub struct OpSpec {
    /// The op's key. [`Op::as_str`] gives the `docs/CLI.md` §2.4/§2.5
    /// dotted name.
    pub op: Op,
    /// The ACL action this op is authorized against.
    pub action: Action,
    /// The shape of this op's resource string.
    pub resource_kind: ResourceKind,
    /// Whether `scope = "owned"` narrows this op to the resource's
    /// opener/registering principal. `true` only for `session.write`/
    /// `session.resize` (`Server::authorize_session_control`) and
    /// `forward.remote.close` (`Server::handle_rfwd_close`) — every other
    /// row's resource has no owner concept, or (`session.close`) is the
    /// documented exception that shares `Action::SessionControl` with
    /// `write`/`resize` but stays outside the ownership bind on purpose
    /// (`docs/design/architecture.md` §6's "session.control의 예외 —
    /// close").
    pub owned: bool,
}

/// PRD §9 actions with no [`OP_REGISTRY`] row, and why — the always-denied
/// trio ([`Action::is_always_denied`]) [`DENY_SEAMS`] already excludes for
/// the identical reason (its own
/// `deny_seams_cover_every_action_except_the_always_denied_trio` anchor).
/// Named here too, not merely inherited, so a reader of this table alone
/// sees the gap and its reason without cross-referencing that test — the
/// same `DEFERRED`-style discipline `PLAN.md` uses elsewhere: an exclusion
/// is only legitimate on record, with a reason, never a silent hole.
pub const ALWAYS_DENIED_NO_OP: &[(Action, &str)] = &[
    (
        Action::ForwardSocks,
        "forward.socks (-D SOCKS proxying) is P1-deferred; no wire op exists yet for a peer \
         to construct this action (docs/ROADMAP.md §3 deferred-feature guardrail table)",
    ),
    (
        Action::FileRead,
        "file.read (streaming file copy) is P1-deferred; no wire op exists yet for a peer to \
         construct this action (docs/ROADMAP.md §3)",
    ),
    (
        Action::FileWrite,
        "file.write (streaming file copy) is P1-deferred; no wire op exists yet for a peer to \
         construct this action (docs/ROADMAP.md §3)",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_name_is_distinct() {
        let mut names: Vec<&str> = DENY_SEAMS.iter().map(|s| s.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "DENY_SEAMS has a duplicate row name");
    }

    #[test]
    fn registry_is_non_empty() {
        assert!(!DENY_SEAMS.is_empty());
    }

    /// F1(c) (M5 Step 4 adversarial review) — the stopgap pin: the exact
    /// row-name list and count, in declaration order. Deliberately naive
    /// (no dedup/sort tolerance): a row added, removed, renamed, or
    /// reordered must touch this test, so a reviewer sees the diff.
    /// Update this list only as part of a change that is actually adding
    /// or removing a seam.
    #[test]
    fn deny_seams_row_names_and_count_are_pinned() {
        let names: Vec<&str> = DENY_SEAMS.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec![
                "exec.run",
                "session.open",
                "session.list",
                "session.get",
                "session.read",
                "session.attach",
                "session.write",
                "session.resize",
                "session.close",
                "forward.remote",
                "forward.remote.close",
                "forward.local",
                "host.reverse",
                "session.attach@data-stream",
            ],
            "DENY_SEAMS row list drifted from this pin — if the drift is a \
             deliberate seam addition/removal, update this list as part of \
             that change; otherwise a row silently changed shape"
        );
        assert_eq!(DENY_SEAMS.len(), 14, "DENY_SEAMS row count drifted");
    }

    /// F1(a) (M5 Step 4 adversarial review) — the registry's coverage
    /// anchor: the set of [`Action`]s covered by [`DENY_SEAMS`] rows must
    /// equal `Action::ALL` minus the always-denied trio
    /// (`ForwardSocks`/`FileRead`/`FileWrite`, `Action::is_always_denied`).
    /// That trio has no row here — not by oversight, but because no wire
    /// op exists today that can construct one of those three actions for
    /// a real peer to hit a gate through (they are P1-deferred,
    /// `docs/ROADMAP.md` §3's guardrail table); `PLAN.md` M5 Step 6
    /// re-checks that gap once real wire paths might exist. A newly added
    /// `Action` — always-denied or not — fails this test until it either
    /// gets a seam row or is added to the exclusion filter below with a
    /// reason.
    #[test]
    fn deny_seams_cover_every_action_except_the_always_denied_trio() {
        let covered: std::collections::HashSet<Action> =
            DENY_SEAMS.iter().map(|s| s.action).collect();
        let expected: std::collections::HashSet<Action> = Action::ALL
            .iter()
            .copied()
            .filter(|a| !a.is_always_denied())
            .collect();
        assert_eq!(
            covered, expected,
            "DENY_SEAMS must cover every Action::ALL member except the \
             always-denied trio (ForwardSocks/FileRead/FileWrite via \
             Action::is_always_denied) — no wire op can construct those \
             three actions today, so there is no seam to enumerate for \
             them yet (PLAN.md M5 Step 6 re-checks this once one might \
             exist); every other action needs a row here or this test \
             fails"
        );
    }

    /// F1(b) (M5 Step 4 adversarial review) — the compile-time anchor for
    /// control-stream rows. [`classify_control_message_body`]'s match has
    /// no wildcard arm, so a new `qsh_proto::wire::control_message::Body`
    /// variant fails **compilation** of this test target the moment it is
    /// added — not silently skipped, not a runtime-only gap. This test
    /// then checks the classification is honest: every variant mapped to
    /// `Seam(name)` is a real `ControlStreamOp` row in [`DENY_SEAMS`], and
    /// every `ControlStreamOp` row is reached by exactly one variant.
    #[test]
    fn every_control_message_body_variant_is_classified_and_seam_names_match_the_registry() {
        let control_stream_row_names: std::collections::BTreeSet<&'static str> = DENY_SEAMS
            .iter()
            .filter(|s| s.kind == SeamKind::ControlStreamOp)
            .map(|s| s.name)
            .collect();
        let mut mapped: std::collections::BTreeSet<&'static str> =
            std::collections::BTreeSet::new();
        for body in all_control_message_body_samples() {
            match classify_control_message_body(&body) {
                BodyClassification::Seam(name) => {
                    assert!(
                        control_stream_row_names.contains(name),
                        "classify_control_message_body mapped a Body variant to {name:?}, \
                         which is not a ControlStreamOp row in DENY_SEAMS"
                    );
                    assert!(
                        mapped.insert(name),
                        "two Body variants both classified as Seam({name:?}) — \
                         classify_control_message_body must be one-to-one onto \
                         DENY_SEAMS's ControlStreamOp rows"
                    );
                }
                BodyClassification::NoAuthorizationSurface(reason) => {
                    assert!(
                        !reason.is_empty(),
                        "NoAuthorizationSurface needs a one-line reason, got an empty one"
                    );
                }
            }
        }
        assert_eq!(
            mapped, control_stream_row_names,
            "every ControlStreamOp row in DENY_SEAMS must be reached by exactly one \
             Body variant classified Seam(...) in classify_control_message_body — a \
             mismatch means either a row has no driving variant, or a variant maps \
             to a name that is not (or no longer) a registry row"
        );
    }

    /// A [`qsh_proto::wire::control_message::Body`] variant's
    /// authorization classification for [`classify_control_message_body`]:
    /// either the [`DenySeam::name`] it drives, or a documented reason it
    /// carries no authorization surface at all (a handshake message, a
    /// pure reply, a keepalive, or an op with no ACL check yet).
    enum BodyClassification {
        /// This variant is the wire shape of the [`DENY_SEAMS`] row named
        /// here.
        Seam(&'static str),
        /// This variant never reaches an ACL choke point, for the one-line
        /// reason given.
        NoAuthorizationSurface(&'static str),
    }

    /// The exhaustive classifier: **no wildcard arm**. Adding a variant to
    /// `qsh_proto::wire::control_message::Body` fails this function's
    /// compilation — and so this whole test target's — until the new
    /// variant is classified here (F1(b)).
    fn classify_control_message_body(
        body: &qsh_proto::wire::control_message::Body,
    ) -> BodyClassification {
        use qsh_proto::wire::control_message::Body;
        match body {
            Body::Hello(_) => BodyClassification::NoAuthorizationSurface(
                "handshake-only: a Hello after the handshake is answered \
                 INVALID_ARGUMENT before any ACL check (Server::dispatch)",
            ),
            Body::Response(_) => BodyClassification::NoAuthorizationSurface(
                "a reply, never a request a peer sends to be authorized",
            ),
            Body::SessionOpen(_) => BodyClassification::Seam("session.open"),
            Body::SessionAttach(_) => BodyClassification::Seam("session.attach"),
            Body::SessionList(_) => BodyClassification::Seam("session.list"),
            Body::SessionGet(_) => BodyClassification::Seam("session.get"),
            Body::SessionResize(_) => BodyClassification::Seam("session.resize"),
            Body::SessionClose(_) => BodyClassification::Seam("session.close"),
            Body::SessionRead(_) => BodyClassification::Seam("session.read"),
            Body::SessionWrite(_) => BodyClassification::Seam("session.write"),
            Body::ExecStart(_) => BodyClassification::Seam("exec.run"),
            Body::RfwdOpen(_) => BodyClassification::Seam("forward.remote"),
            Body::RfwdClose(_) => BodyClassification::Seam("forward.remote.close"),
            Body::Ping(_) => BodyClassification::NoAuthorizationSurface(
                "keepalive, answered unconditionally with no ACL check",
            ),
            Body::Pong(_) => BodyClassification::NoAuthorizationSurface(
                "unsolicited reply, dropped unconditionally",
            ),
            Body::SessionEvent(_) => BodyClassification::NoAuthorizationSurface(
                "host-to-client only; an inbound one is dropped, never authorized",
            ),
            Body::PairingProof(_) => BodyClassification::NoAuthorizationSurface(
                "pairing-only: reaches a connection whose principal is \
                 Principal::Pairing, which Server::serve_connection_inner routes to \
                 a dedicated pairing responder before Server::dispatch (and ACL) \
                 ever run; a PairingProof arriving on an already-authenticated \
                 connection is refused before this classifier even matters \
                 (Server::dispatch's own arm, ADR-0002)",
            ),
            Body::PairingAccepted(_) => BodyClassification::NoAuthorizationSurface(
                "a reply, produced only by the pairing responder itself; never a \
                 request a peer sends to be authorized",
            ),
        }
    }

    /// One sample value per `Body` variant, for
    /// [`classify_control_message_body`] to classify in the test above.
    /// This list is *not* itself the compile-time anchor (that is the
    /// classifier's own exhaustive match, with no wildcard) — if a new
    /// variant is added and this list is not updated, the classifier
    /// still fails to compile first.
    fn all_control_message_body_samples() -> Vec<qsh_proto::wire::control_message::Body> {
        use qsh_proto::wire::control_message::Body;
        use qsh_proto::wire::{
            ExecStart, Hello, PairingAccepted, PairingProof, Ping, Pong, RemoteForwardClose,
            RemoteForwardOpen, Response, SessionAttach, SessionClose, SessionEvent, SessionGet,
            SessionList, SessionOpen, SessionRead, SessionResize, SessionWrite,
        };
        vec![
            Body::Hello(Hello::default()),
            Body::Response(Response::default()),
            Body::SessionOpen(SessionOpen::default()),
            Body::SessionAttach(SessionAttach::default()),
            Body::SessionList(SessionList::default()),
            Body::SessionGet(SessionGet::default()),
            Body::SessionResize(SessionResize::default()),
            Body::SessionClose(SessionClose::default()),
            Body::SessionRead(SessionRead::default()),
            Body::SessionWrite(SessionWrite::default()),
            Body::ExecStart(ExecStart::default()),
            Body::RfwdOpen(RemoteForwardOpen::default()),
            Body::RfwdClose(RemoteForwardClose::default()),
            Body::Ping(Ping::default()),
            Body::Pong(Pong::default()),
            Body::SessionEvent(SessionEvent::default()),
            Body::PairingProof(PairingProof::default()),
            Body::PairingAccepted(PairingAccepted::default()),
        ]
    }

    // ---- M5 Step 8 (SC6): OP_REGISTRY sanity + the anti-two-tables cross-check ----

    #[test]
    fn op_registry_is_non_empty() {
        assert!(!OP_REGISTRY.is_empty());
    }

    /// Sanity floor `PLAN.md` M5 Step 8 (c) names explicitly: an exclusion
    /// list that grew to swallow the whole registry would be a silent way
    /// to defeat DoD 2's audit-completeness sweep (every excluded op is
    /// one this build never actually authorizes anything for).
    #[test]
    fn always_denied_no_op_is_smaller_than_the_registry() {
        assert!(ALWAYS_DENIED_NO_OP.len() < OP_REGISTRY.len());
    }

    #[test]
    fn every_always_denied_no_op_reason_is_non_empty() {
        for (action, reason) in ALWAYS_DENIED_NO_OP {
            assert!(
                !reason.is_empty(),
                "{action:?}'s ALWAYS_DENIED_NO_OP exclusion needs a one-line reason"
            );
        }
    }

    /// `ALWAYS_DENIED_NO_OP` must name exactly `Action::is_always_denied`'s
    /// three actions — same anchor `deny_seams_cover_every_action_except_the_always_denied_trio`
    /// pins for `DENY_SEAMS`, restated here since this exclusion list is
    /// its own named thing (`OpSpec`'s own doc), not merely inherited.
    #[test]
    fn always_denied_no_op_names_exactly_the_always_denied_trio() {
        let excluded: std::collections::HashSet<Action> =
            ALWAYS_DENIED_NO_OP.iter().map(|(a, _)| *a).collect();
        let always_denied: std::collections::HashSet<Action> = Action::ALL
            .iter()
            .copied()
            .filter(|a| a.is_always_denied())
            .collect();
        assert_eq!(excluded, always_denied);
    }

    /// The "표 두 벌 금지" cross-check (`PLAN.md` M5 Step 8 (c)): `OP_REGISTRY`
    /// and `DENY_SEAMS` must name and authorize the exact same set of seams,
    /// minus the one internal-only row (`"session.attach@data-stream"`,
    /// [`OpSpec`]'s own doc explains why) that has no CLI.md-documented
    /// op/seam name of its own to carry into this table. Nobody can add a
    /// row to one table with a different `(name, action)` pair than the
    /// other without this test failing — the two tables cannot be
    /// hand-maintained as independent sources of the same fact.
    #[test]
    fn op_registry_matches_deny_seams_by_name_and_action() {
        let op_registry_pairs: std::collections::HashSet<(&str, Action)> = OP_REGISTRY
            .iter()
            .map(|spec| (spec.op.as_str(), spec.action))
            .collect();
        let deny_seam_pairs: std::collections::HashSet<(&str, Action)> = DENY_SEAMS
            .iter()
            .filter(|seam| seam.name != "session.attach@data-stream")
            .map(|seam| (seam.name, seam.action))
            .collect();
        assert_eq!(
            op_registry_pairs, deny_seam_pairs,
            "OP_REGISTRY and DENY_SEAMS have drifted: they must name and authorize the \
             exact same set of seams, minus the internal-only session.attach@data-stream \
             reattach gate (OpSpec's own doc) — a row added, removed, renamed, or \
             re-mapped to a different Action in either table must be mirrored in the \
             other"
        );
    }

    /// Set-equality half of "the match is the one table, `OP_REGISTRY` is
    /// only its projection": every [`Op`] variant's own [`Op::spec`] names
    /// itself, and appears in [`OP_REGISTRY`] exactly once. Replaces the
    /// old `action_of_resolves_every_registry_row` (string-keyed lookup
    /// sanity) now that a lookup by name cannot fail to begin with.
    #[test]
    fn every_op_variant_is_its_own_spec_row_and_appears_exactly_once_in_op_registry() {
        for op in Op::ALL {
            let spec = op.spec();
            assert_eq!(spec.op, *op, "{op:?}'s own spec() row must name itself");
            let count = OP_REGISTRY.iter().filter(|s| s.op == *op).count();
            assert_eq!(
                count, 1,
                "{op:?} must appear exactly once in OP_REGISTRY, found {count}"
            );
        }
        assert_eq!(
            Op::ALL.len(),
            OP_REGISTRY.len(),
            "Op::ALL and OP_REGISTRY must be the same size"
        );
    }

    // `action_of_panics_on_an_unregistered_name` (the old
    // `#[should_panic]` test for a typo'd/unregistered op-name string) is
    // deliberately not ported: `action_of(&str) -> Action` is gone, and
    // with it the state that test existed to catch. `Op::spec`'s match has
    // no wildcard arm, so "not a row in OP_REGISTRY" is no longer a value
    // any `Op` can hold — the panic path became unrepresentable, not
    // merely untested.
}
