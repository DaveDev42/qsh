//! Diagnostic items: stable, human-readable facts about a QSH deployment
//! that more than one surface needs to say — never operations of their
//! own (`docs/CLI.md` §6.11: `doctor.run`'s CLI/JSON contract is M7's to
//! confirm, not this crate's). `PLAN.md` M3 Step 9 (a): a milestone that
//! preempts another milestone's contract turns into debt *that* milestone
//! has to repay, so this module defines pure data only — no `doctor.run`
//! [`crate::ops::Operation`], no `qsh doctor` subcommand, no reachability
//! probe. `qsh-cli` renders it (`qsh reverse`'s connection-failure path,
//! `qsh listen`'s startup banner) and M7's `doctor.run` will eventually
//! consume the very same constant, so the wording only ever has one
//! source of truth.
//!
//! Deliberately has no `#[cfg(unix)]` gate anywhere in this file: a
//! diagnostic item is text, not behavior, so it must build *and* run on
//! every platform CI covers, Windows leg included.

/// Which diagnostic a [`Diagnostic`] value is — lets a caller match on
/// identity without string-comparing `code` (that string is still the one
/// M7's `doctor.run` contract will key off of; this enum is the in-process
/// convenience on top of it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticId {
    ControllerUnreachable,
}

/// A stable diagnostic: a machine `code`, a human `message` explaining the
/// condition, and a `remedy` saying what to do about it. `code` is the
/// part M7's `doctor.run` consumes verbatim (`docs/CLI.md` §6.11) — treat
/// it as part of the wire contract even though no wire type carries it
/// yet. `message`/`remedy` are also pinned: `docs/CLI.md` §6.13,
/// `docs/PRD.md` §6, and `README.md`'s "Known limitations" section each
/// embed them verbatim, and an integration test
/// (`crates/qsh-core/tests/doctor_docs.rs`) asserts the docs and this
/// constant never drift apart.
pub struct Diagnostic {
    pub id: DiagnosticId,
    /// Stable snake_case machine code — never changes shape once shipped.
    pub code: &'static str,
    pub message: &'static str,
    pub remedy: &'static str,
}

/// `docs/ROADMAP.md` M3 DoD 4 / `docs/PRD.md` §6: reverse attach needs a
/// direct UDP path from target to controller, and QSH provides no relay,
/// NAT traversal, or discovery in P0 (M3's explicit out-of-scope list).
/// Rendered on `qsh reverse`'s connection-failure path and `qsh listen`'s
/// startup banner (`crates/qsh-cli/src/main.rs`); the same text is quoted
/// verbatim in `README.md`, `docs/CLI.md` §6.13, and `docs/PRD.md` §6.
pub const CONTROLLER_UNREACHABLE: Diagnostic = Diagnostic {
    id: DiagnosticId::ControllerUnreachable,
    code: "controller_unreachable",
    message: "Reverse attach needs a directly reachable UDP path from the target to the controller. QSH provides no relay, NAT traversal, or discovery — that is out of scope for P0.",
    remedy: "Put the controller on a publicly routable address, a forwarded port, or an existing overlay such as WireGuard or Tailscale. If the controller itself is behind NAT, M3 has no answer for that.",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_unreachable_code_is_the_stable_snake_case_string() {
        assert_eq!(
            CONTROLLER_UNREACHABLE.id,
            DiagnosticId::ControllerUnreachable
        );
        assert_eq!(CONTROLLER_UNREACHABLE.code, "controller_unreachable");
    }
}
