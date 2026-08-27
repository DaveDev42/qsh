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
            ExecStart, Hello, Ping, Pong, RemoteForwardClose, RemoteForwardOpen, Response,
            SessionAttach, SessionClose, SessionEvent, SessionGet, SessionList, SessionOpen,
            SessionRead, SessionResize, SessionWrite,
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
        ]
    }
}
