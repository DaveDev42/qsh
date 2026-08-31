//! Diagnostic items: stable, human-readable facts about a QSH deployment
//! that more than one surface needs to say. Originally (`PLAN.md` M3 Step
//! 9 (a)) pure data with no `doctor.run` operation behind it — M7 Step 6
//! is the milestone that repays that debt: `crate::ops::doctor` is the
//! `doctor.run` [`crate::ops::Operation`] that actually detects,
//! classifies and assembles these into a `qsh doctor` report
//! (`docs/CLI.md` §6.17), and `qsh-cli`'s `render::human::print_doctor`
//! is a pure renderer on top of it (`CLAUDE.md`'s crate boundary — zero
//! diagnostic logic in `qsh-cli`). Two consumers predate that op and stay
//! unchanged: `qsh reverse`'s connection-failure path and `qsh listen`'s
//! startup banner render [`CONTROLLER_UNREACHABLE`] directly, so the
//! wording only ever has one source of truth across all three surfaces.
//!
//! Deliberately has no `#[cfg(unix)]` gate anywhere in this file (test-only
//! `#[cfg(unix)]` gates on tests that exercise unix-only file permissions
//! are the one standing exception — the production code they test still
//! builds and runs everywhere): a diagnostic item is text, not behavior,
//! so it must build *and* run on every platform CI covers, Windows leg
//! included. Platform-specific *detection* (the raw UDP egress probe, the
//! `$PATH` scan) lives in [`probe`] instead, precisely so this rule can
//! hold here without also forcing every detector to be portable in its
//! own implementation.

pub mod probe;

/// Which diagnostic a [`Diagnostic`] value is — lets a caller match on
/// identity without string-comparing `code` (that string is still the one
/// `doctor.run`'s contract keys off of; this enum is the in-process
/// convenience on top of it).
///
/// 13 variants, one per `docs/CLI.md` §6.17 finding code — a closed,
/// additive-only set (`PLAN.md` M7 §4.1 #5): [`EXPECTED_DOCTOR_CODES`] and
/// this enum's own `tests` module keep the two in lockstep, so a variant
/// added without updating the frozen list (or vice versa) fails CI rather
/// than shipping quietly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticId {
    ControllerUnreachable,
    AuditPathUnwritable,
    AclPolicyMissing,
    AclPolicyInvalid,
    UdpEgressBlocked,
    NoRoute,
    PeerUntrusted,
    CertExpired,
    CertExpiringSoon,
    KeystoreUnavailable,
    ClockSkew,
    QshPathShadowed,
    TrustRemoveScope,
}

impl DiagnosticId {
    /// The stable snake_case `code` this diagnostic reports as
    /// `doctor.run`'s `DoctorFinding.code` (`docs/CLI.md` §6.17) — the
    /// vocabulary `PLAN.md` M7 §4.1 #5 locks. Two variants
    /// ([`DiagnosticId::AclPolicyMissing`]/[`DiagnosticId::AclPolicyInvalid`])
    /// are verbatim references to
    /// [`crate::acl::ACL_POLICY_MISSING_CODE`]/[`crate::acl::ACL_POLICY_INVALID_CODE`]
    /// rather than a second, retyped copy of the same string — the same
    /// anti-drift discipline this module's own `Diagnostic` constants
    /// already follow for `CONTROLLER_UNREACHABLE`/`AUDIT_PATH_UNWRITABLE`.
    pub fn code(self) -> &'static str {
        match self {
            DiagnosticId::ControllerUnreachable => CONTROLLER_UNREACHABLE.code,
            DiagnosticId::AuditPathUnwritable => AUDIT_PATH_UNWRITABLE.code,
            DiagnosticId::AclPolicyMissing => crate::acl::ACL_POLICY_MISSING_CODE,
            DiagnosticId::AclPolicyInvalid => crate::acl::ACL_POLICY_INVALID_CODE,
            DiagnosticId::UdpEgressBlocked => UDP_EGRESS_BLOCKED.code,
            DiagnosticId::NoRoute => NO_ROUTE.code,
            DiagnosticId::PeerUntrusted => PEER_UNTRUSTED.code,
            DiagnosticId::CertExpired => CERT_EXPIRED.code,
            DiagnosticId::CertExpiringSoon => CERT_EXPIRING_SOON.code,
            DiagnosticId::KeystoreUnavailable => KEYSTORE_UNAVAILABLE.code,
            DiagnosticId::ClockSkew => CLOCK_SKEW.code,
            DiagnosticId::QshPathShadowed => QSH_PATH_SHADOWED.code,
            DiagnosticId::TrustRemoveScope => TRUST_REMOVE_SCOPE.code,
        }
    }
}

/// The closed, additive-only set of `doctor.run` finding codes
/// (`docs/CLI.md` §6.17, `PLAN.md` M7 §4.1 #5), sorted — mirroring
/// `qsh_proto::schema::CLI_V1_SCHEMA_COMMANDS`'s own frozen-set
/// discipline. A code is added here only alongside a new [`DiagnosticId`]
/// variant; nothing already shipped is ever removed or renamed (a new
/// meaning needs a new code, not a repurposed one).
pub const EXPECTED_DOCTOR_CODES: &[&str] = &[
    "acl_policy_invalid",
    "acl_policy_missing",
    "audit_path_unwritable",
    "cert_expired",
    "cert_expiring_soon",
    "clock_skew",
    "controller_unreachable",
    "keystore_unavailable",
    "no_route",
    "peer_untrusted",
    "qsh_path_shadowed",
    "trust_remove_scope",
    "udp_egress_blocked",
];

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

/// `PLAN.md` M5 Step 3 (F9): the configured `[audit].path` cannot currently
/// be appended to — the same failure class
/// [`crate::audit::RotatingAuditSink`] latches degraded on
/// (`docs/design/architecture.md` §6's audit fail-closed policy). Lets an
/// operator catch a permissions or disk-space problem ahead of time rather
/// than discover it only once a privileged operation starts getting denied.
pub const AUDIT_PATH_UNWRITABLE: Diagnostic = Diagnostic {
    id: DiagnosticId::AuditPathUnwritable,
    code: "audit_path_unwritable",
    message: "The configured audit log path could not be opened for append. Privileged operations (session.open, exec.run, host.reverse) are denied while the audit log is unwritable — that is fail-closed by design, not a bug.",
    remedy: "Check the audit log directory's permissions and available disk space, then retry. There is no override: recording the decision is a precondition for granting it, and the writer clears this on its own once writing succeeds again.",
};

/// `docs/CLI.md` §6.17: this machine's UDP egress for QSH's QUIC transport
/// appears to be silently dropped — a probe packet leaves the process but
/// nothing, not even an ICMP rejection, answers before the timeout.
/// Distinguished from [`NO_ROUTE`] by *how* the probe fails
/// ([`probe::classify_connectivity`]): a silent timeout here, an active
/// OS-level refusal there.
pub const UDP_EGRESS_BLOCKED: Diagnostic = Diagnostic {
    id: DiagnosticId::UdpEgressBlocked,
    code: "udp_egress_blocked",
    message: "UDP egress for QSH's QUIC transport appears to be silently blocked: a probe packet left this machine but nothing answered before the timeout. QSH has no TCP fallback (P1, ADR-0005) — every QSH connection is QUIC over UDP, so this is a hard stop, not a slow path.",
    remedy: "Open outbound UDP (default port 4433) on this machine's firewall. Until then, an existing overlay such as WireGuard or Tailscale is the only workaround.",
};

/// `docs/CLI.md` §6.17: the operating system reported the probed address
/// unreachable outright (`ENETUNREACH`/`EHOSTUNREACH`/connection-refused
/// class errors) rather than a silent timeout — an active routing failure,
/// not a firewall drop. See [`UDP_EGRESS_BLOCKED`] for the sibling case.
pub const NO_ROUTE: Diagnostic = Diagnostic {
    id: DiagnosticId::NoRoute,
    code: "no_route",
    message: "There is no network route to the probed address — the operating system reported the destination unreachable rather than the probe timing out.",
    remedy: "Check the address, routing table and network interface (e.g. `ip route`/`route -n`); if the host is on a different network, an overlay is required.",
};

/// `docs/CLI.md` §6.17: `hosts.toml` names a host `trust.toml` has no pin
/// for. `hosts.toml` never supplies identity (`crate::hosts` module doc),
/// so a name that exists only there is destined to fail `TRUST_REQUIRED`
/// the moment anything actually dials it — this diagnostic catches that
/// ahead of time, statically, from the two files alone.
pub const PEER_UNTRUSTED: Diagnostic = Diagnostic {
    id: DiagnosticId::PeerUntrusted,
    code: "peer_untrusted",
    message: "hosts.toml names this host, but trust.toml has no pin for it — connecting to it is going to fail with TRUST_REQUIRED.",
    remedy: "Pin it with `qsh trust add <name> --fingerprint <fingerprint>`, or pair with `qsh trust invite` / `qsh trust accept`.",
};

/// `docs/CLI.md` §6.17: a certificate this device relies on — its own
/// device leaf or its private CA root — has already passed `not_after`.
/// Mutually exclusive with [`CERT_EXPIRING_SOON`] for the same
/// certificate (`crate::ops::doctor` never emits both for one cert).
pub const CERT_EXPIRED: Diagnostic = Diagnostic {
    id: DiagnosticId::CertExpired,
    code: "cert_expired",
    message: "A certificate this device relies on has expired.",
    remedy: "Re-issue the device certificate with `qsh cert issue`, or regenerate the CA root with `qsh cert init`.",
};

/// `docs/CLI.md` §6.17, `docs/ROADMAP.md` §4 risk table (L136: "만료 30일
/// 전 doctor 경고"): the same certificate as [`CERT_EXPIRED`], caught
/// inside its final 30 days instead of after the fact. Should almost
/// never fire under normal operation — a device leaf is valid for 10
/// years — which is by design, not a bug (only real-world clock jumps or
/// an externally supplied certificate make this reachable in practice).
pub const CERT_EXPIRING_SOON: Diagnostic = Diagnostic {
    id: DiagnosticId::CertExpiringSoon,
    code: "cert_expiring_soon",
    message: "A certificate this device relies on expires within 30 days.",
    remedy: "Re-issue it ahead of the deadline with `qsh cert issue`.",
};

/// `docs/CLI.md` §6.17: the platform credential store (macOS Keychain /
/// Linux Secret Service) is not reachable from this process right now —
/// the same [`crate::identity::KeyStoreError::Unavailable`] condition
/// `auto` mode falls back to the file store for. A read-only probe: it
/// never touches or changes which store this device's own key actually
/// lives in.
pub const KEYSTORE_UNAVAILABLE: Diagnostic = Diagnostic {
    id: DiagnosticId::KeystoreUnavailable,
    code: "keystore_unavailable",
    message: "The platform key store is not reachable from this process.",
    remedy: "Nothing is broken by itself — `auto`/`file` key-store mode already falls back to the 0600 file store. To use the platform key store, make sure a Secret Service (Linux) or Keychain (macOS) session is reachable.",
};

/// `docs/CLI.md` §6.17: the local clock reads earlier than this device's
/// own certificate's backdated `not_before` — `crate::identity`'s 5-minute
/// backdate margin ([`crate::identity::CERT_BACKDATE_MINUTES`]) exists
/// exactly to absorb small skew, so `crate::ops::doctor` only calls this a
/// hard `error` once the observed skew exceeds that margin; smaller skew
/// still `warn`s; only [`SystemTime`]/`now` injection can reach this in a
/// test — real-time skew this large basically never happens
/// (`crate::ops::doctor`'s own module doc).
///
/// [`SystemTime`]: std::time::SystemTime
pub const CLOCK_SKEW: Diagnostic = Diagnostic {
    id: DiagnosticId::ClockSkew,
    code: "clock_skew",
    message: "This machine's clock reads earlier than this device's own certificate says it should be possible.",
    remedy: "Fix the system clock or NTP. A large clock skew breaks TLS certificate-validity checks and can fail the handshake outright.",
};

/// `docs/CLI.md` §6.17: an executable named `qsh` earlier on `$PATH` than
/// the one that is actually running right now would shadow it — running
/// `qsh` bare would launch that other binary instead.
pub const QSH_PATH_SHADOWED: Diagnostic = Diagnostic {
    id: DiagnosticId::QshPathShadowed,
    code: "qsh_path_shadowed",
    message: "Another `qsh` executable earlier on $PATH would run instead of the one currently executing.",
    remedy: "Fix the PATH order, or remove the stale `qsh` binary the finding's detail names.",
};

/// `docs/CLI.md` §6.17, `PLAN.md` M7 Step 2's confirmed `trust remove`
/// semantics (README "Known limitations", `docs/CLI.md` §6.11): an `info`
/// notice, not a problem — it surfaces whenever `trust.toml` has at least
/// one pin, unconditionally, so an operator always sees this scope
/// spelled out rather than discovering it only when a removal doesn't do
/// what they expected.
pub const TRUST_REMOVE_SCOPE: Diagnostic = Diagnostic {
    id: DiagnosticId::TrustRemoveScope,
    code: "trust_remove_scope",
    message: "trust.toml has at least one pinned peer. `qsh trust remove` only takes effect starting with that peer's next handshake — an already-established connection keeps its entire negotiated authority (including opening brand-new sessions, tunnels and forwards) until that connection drops and has to handshake again.",
    remedy: "Force-closing an already-established connection on removal is not implemented (P1). If that matters right now, restart the process holding the connection.",
};

/// `PLAN.md` M5 Step 3 (F9): attempts to open `path` for append, creating
/// the parent directory and the file itself if either is missing —
/// exactly what [`crate::audit::RotatingAuditSink`]'s writer thread does
/// on every fresh open. `true` means the current process could actually
/// write an audit record right now; `false` (any I/O error) means
/// [`AUDIT_PATH_UNWRITABLE`] applies. Structural signal only — never reads
/// or logs the file's content, and never writes any bytes of its own past
/// creating an empty file.
///
/// Best-effort and outside the write path itself: this is a point-in-time
/// probe for an operator or a startup banner, not something
/// `RotatingAuditSink::record` consults — that would reintroduce exactly
/// the extra I/O per decision the async writer thread exists to avoid.
pub fn probe_audit_path_writable(path: &std::path::Path) -> bool {
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .is_ok()
}

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

    #[test]
    fn audit_path_unwritable_code_is_the_stable_snake_case_string() {
        assert_eq!(AUDIT_PATH_UNWRITABLE.id, DiagnosticId::AuditPathUnwritable);
        assert_eq!(AUDIT_PATH_UNWRITABLE.code, "audit_path_unwritable");
    }

    /// `PLAN.md` M7 §4.1 #5's "code 안정성 fixture": every [`DiagnosticId`]
    /// variant, exhaustively hand-listed (a variant added here without a
    /// matching addition to [`EXPECTED_DOCTOR_CODES`], or vice versa, is
    /// exactly the drift this test exists to catch), must map to a unique
    /// code and the frozen set must be exactly those 13 codes — no more, no
    /// fewer. Mirrors `qsh_proto::schema`'s
    /// `cli_v1_schema_commands_is_sorted_and_deduplicated` precedent.
    #[test]
    fn expected_doctor_codes_matches_every_diagnostic_id_variant_exactly() {
        const ALL: [DiagnosticId; 13] = [
            DiagnosticId::ControllerUnreachable,
            DiagnosticId::AuditPathUnwritable,
            DiagnosticId::AclPolicyMissing,
            DiagnosticId::AclPolicyInvalid,
            DiagnosticId::UdpEgressBlocked,
            DiagnosticId::NoRoute,
            DiagnosticId::PeerUntrusted,
            DiagnosticId::CertExpired,
            DiagnosticId::CertExpiringSoon,
            DiagnosticId::KeystoreUnavailable,
            DiagnosticId::ClockSkew,
            DiagnosticId::QshPathShadowed,
            DiagnosticId::TrustRemoveScope,
        ];
        let mut codes: Vec<&str> = ALL.iter().map(|id| id.code()).collect();
        codes.sort_unstable();
        let mut deduped = codes.clone();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            ALL.len(),
            "DiagnosticId has two variants mapping to the same code: {codes:?}"
        );
        assert_eq!(
            codes, EXPECTED_DOCTOR_CODES,
            "EXPECTED_DOCTOR_CODES and DiagnosticId's variant set have drifted apart"
        );
    }

    #[test]
    fn expected_doctor_codes_is_sorted_and_deduplicated() {
        let mut sorted = EXPECTED_DOCTOR_CODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, EXPECTED_DOCTOR_CODES,
            "EXPECTED_DOCTOR_CODES must be sorted with no duplicates"
        );
    }

    /// Anti-drift (E-5, brief): the two reused-verbatim codes must equal
    /// the acl module's own constants by reference-comparison-of-value,
    /// never a retyped copy that could quietly diverge from them.
    #[test]
    fn acl_diagnostic_codes_are_the_acl_module_constants_verbatim() {
        assert_eq!(
            DiagnosticId::AclPolicyMissing.code(),
            crate::acl::ACL_POLICY_MISSING_CODE
        );
        assert_eq!(
            DiagnosticId::AclPolicyInvalid.code(),
            crate::acl::ACL_POLICY_INVALID_CODE
        );
    }

    #[test]
    fn probe_audit_path_writable_creates_missing_parents_and_reports_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("audit.log");
        assert!(!path.parent().unwrap().exists());
        assert!(probe_audit_path_writable(&path));
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn probe_audit_path_writable_reports_false_for_an_unwritable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o500)).unwrap();
        let path = state.join("audit.log");
        assert!(!probe_audit_path_writable(&path));
        // Repair, prove the probe recovers too — mirrors the writer's own
        // "no override, clears on its own" behavior (F9).
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(probe_audit_path_writable(&path));
    }
}
