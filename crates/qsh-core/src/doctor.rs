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
/// 22 variants, one per `docs/CLI.md` §6.17 finding code — a closed,
/// additive-only set (`PLAN.md` M7 §4.1 #5): [`EXPECTED_DOCTOR_CODES`] and
/// this enum's own `tests` module keep the two in lockstep, so a variant
/// added without updating the frozen list (or vice versa) fails CI rather
/// than shipping quietly. `ROADMAP.md` M9 (h)'s batch of seven —
/// `ServiceNotRegistered`/`SystemdLingerDisabled`/
/// `LaunchagentSessionScoped`/`Bindv6onlyBlocksIpv4`/
/// `AclPrincipalUnmatched`/`AclCaAuthPathMissing`/
/// `HostPinnedWithoutAddress` — landed 14 → 21; ROADMAP M9 (h)'s
/// `ConfigServeToConflict` (`qsh serve --to` rename, ADR-0012 결정 5) is
/// M9 (h)'s eighth, 21 → 22.
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
    ConfigUnknownKey,
    ServiceNotRegistered,
    SystemdLingerDisabled,
    LaunchagentSessionScoped,
    Bindv6onlyBlocksIpv4,
    AclPrincipalUnmatched,
    AclCaAuthPathMissing,
    HostPinnedWithoutAddress,
    ConfigServeToConflict,
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
            DiagnosticId::ConfigUnknownKey => CONFIG_UNKNOWN_KEY.code,
            DiagnosticId::ServiceNotRegistered => SERVICE_NOT_REGISTERED.code,
            DiagnosticId::SystemdLingerDisabled => SYSTEMD_LINGER_DISABLED.code,
            DiagnosticId::LaunchagentSessionScoped => LAUNCHAGENT_SESSION_SCOPED.code,
            DiagnosticId::Bindv6onlyBlocksIpv4 => BINDV6ONLY_BLOCKS_IPV4.code,
            DiagnosticId::AclPrincipalUnmatched => ACL_PRINCIPAL_UNMATCHED.code,
            DiagnosticId::AclCaAuthPathMissing => ACL_CA_AUTH_PATH_MISSING.code,
            DiagnosticId::HostPinnedWithoutAddress => HOST_PINNED_WITHOUT_ADDRESS.code,
            DiagnosticId::ConfigServeToConflict => CONFIG_SERVE_TO_CONFLICT.code,
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
    "acl_ca_auth_path_missing",
    "acl_policy_invalid",
    "acl_policy_missing",
    "acl_principal_unmatched",
    "audit_path_unwritable",
    "bindv6only_blocks_ipv4",
    "cert_expired",
    "cert_expiring_soon",
    "clock_skew",
    "config_serve_to_conflict",
    "config_unknown_key",
    "controller_unreachable",
    "host_pinned_without_address",
    "keystore_unavailable",
    "launchagent_session_scoped",
    "no_route",
    "peer_untrusted",
    "qsh_path_shadowed",
    "service_not_registered",
    "systemd_linger_disabled",
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
///
/// `remedy` deliberately does not say "re-issue with `qsh cert issue`" for
/// every case: `Ops::cert_issue` only re-signs when `identity.issued_by_ca`
/// does not already match the local CA's own fingerprint
/// (`crate::ops::cert`) — it never looks at `not_after`. So a leaf already
/// CA-issued (by *this* CA) that has since expired makes `qsh cert issue`
/// a silent no-op (`issued: false`), and `crate::ca::init` returns any
/// existing root unchanged regardless of its own expiry, making `qsh cert
/// init` an equally silent no-op for an expired CA root. Neither command
/// has a `--force` (out of scope — `docs/ROADMAP.md` lists cert
/// rotation/revocation UX as P1); the only recovery this build actually
/// has is deleting the stale material and letting the ordinary idempotent
/// path regenerate it, the same recipe `identity::read_cert_der`'s own
/// missing-file error already tells an operator ("re-run qsh init after
/// removing the identity directory").
pub const CERT_EXPIRED: Diagnostic = Diagnostic {
    id: DiagnosticId::CertExpired,
    code: "cert_expired",
    message: "A certificate this device relies on has expired.",
    remedy: "`qsh cert issue` only re-issues a leaf this CA has not signed yet; on one it already signed, or on the CA root, it and `qsh cert init` are no-ops. Recover by removing `identity/` or `ca/` from the config directory and re-running `qsh init`/`qsh cert init` — peers must then re-pin.",
};

/// `docs/CLI.md` §6.17, `docs/ROADMAP.md` §4 risk table (L136: "만료 30일
/// 전 doctor 경고"): the same certificate as [`CERT_EXPIRED`], caught
/// inside its final 30 days instead of after the fact. Should almost
/// never fire under normal operation — a device leaf is valid for 10
/// years — which is by design, not a bug (only real-world clock jumps or
/// an externally supplied certificate make this reachable in practice).
///
/// `remedy` carries the identical no-op gap [`CERT_EXPIRED`]'s own doc
/// works through — "expiring soon" instead of "already expired" changes
/// nothing about `Ops::cert_issue`/`crate::ca::init`'s idempotency checks.
pub const CERT_EXPIRING_SOON: Diagnostic = Diagnostic {
    id: DiagnosticId::CertExpiringSoon,
    code: "cert_expiring_soon",
    message: "A certificate this device relies on expires within 30 days.",
    remedy: "`qsh cert issue` only re-issues a leaf this CA has not signed yet; on one it already signed, or on the CA root, it and `qsh cert init` are no-ops. Renew ahead of the deadline by removing `identity/` or `ca/` from the config directory and re-running `qsh init`/`qsh cert init` — peers must then re-pin.",
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
/// backdate margin (`crate::identity::CERT_BACKDATE_MINUTES`) exists
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

/// `docs/CLI.md` §6.17, `PLAN.md` M8 Step 4b (J10): `config.toml` has a key
/// path [`crate::config::Config`] does not know about. `#[serde(default)]`
/// with no `deny_unknown_fields` means such a key is silently ignored
/// rather than rejected (`docs/CLI.md` §2.3's documented contract — never
/// tightened to `deny_unknown_fields`, which would break a newer config
/// against an older binary), so a typo'd cap key (e.g.
/// `mx_sessions_per_principal` instead of `max_sessions_per_principal`)
/// leaves that cap silently at its default forever with no signal
/// anywhere else. `warn`, not `error`: the file still parses and the
/// binary still runs correctly under its defaults — only an operator's
/// expectation about *which* value is in effect may be wrong.
pub const CONFIG_UNKNOWN_KEY: Diagnostic = Diagnostic {
    id: DiagnosticId::ConfigUnknownKey,
    code: "config_unknown_key",
    message: "config.toml has a key path that Config does not recognize, so it is being silently ignored rather than applied. If this was meant to override a setting (for example a cap), that setting is still at its default.",
    remedy: "Check the key path the finding's detail names for a typo against docs/CLI.md's config.toml layout, or remove it if it is leftover from an older build.",
};

/// `docs/ROADMAP.md` M9 (h), `docs/CLI.md` §6.17, `PLAN.md`/ADR-0012 결정 5
/// (ROADMAP M9 (b), `qsh serve --to` rename): `[serve].to` and the legacy
/// `[reverse].controller` are both set and name different values
/// (`crate::serve::config_serve_to_conflict`). `error`, not `warn` like
/// [`CONFIG_UNKNOWN_KEY`]'s shape: `config_unknown_key` is `warn` for a
/// reason its own doc gives — the file still parses *and the binary still
/// runs correctly* under its defaults. Here it does not: `qsh serve`/`qsh
/// service install` fail closed with `CONFIG_ERROR` the moment this
/// disagreement is present (`crate::serve::config_outbound_target`), the
/// same "certain, not latent" consequence class as `acl_policy_missing`/
/// `acl_policy_invalid` ([`DiagnosticId::AclPolicyMissing`]/
/// [`DiagnosticId::AclPolicyInvalid`]), both `error`. `qsh doctor` itself
/// never fails on this (or anything) — `doctor.run` stays exit `0` and
/// reports it as a finding, same as every other code here. Two values
/// agreeing is not a conflict at all — `[serve].to` silently wins and no
/// finding fires.
pub const CONFIG_SERVE_TO_CONFLICT: Diagnostic = Diagnostic {
    id: DiagnosticId::ConfigServeToConflict,
    code: "config_serve_to_conflict",
    message: "[serve].to and the legacy [reverse].controller are both set in config.toml and name different targets. qsh serve and qsh service install fail closed with CONFIG_ERROR while this disagreement stands.",
    remedy: "Delete one of the two keys, keep [serve].to, then restart qsh serve — config.toml is only read once at start.",
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

/// `docs/ROADMAP.md` M9 (h), `docs/CLI.md` §6.17: no platform service unit
/// is registered for this machine's inferred run mode (`serve`/`listen`/
/// `reverse`, precedence `[listen]` present > `[serve].to` set > legacy
/// `[reverse].controller` set > `serve` — ROADMAP M9 (h) added the `[serve].to`
/// tier) — `crate::ops::doctor`'s own
/// mode inference, not a new config field. `info`, not `warn`/`error`:
/// running in the foreground is a completely normal way to use `qsh`
/// (an interactive session, a one-off), not a misconfiguration — this
/// only tells an operator who *meant* to run unattended that they
/// haven't registered a unit yet.
///
/// Platform-gated in [`probe::service_unit_registered`]: macOS reads
/// `~/Library/LaunchAgents/io.qsh.<mode>.plist`, Linux reads
/// `~/.config/systemd/user/qsh-<mode>.service`; every other target
/// (Windows included) never fires this — `qsh service install` is
/// `UNSUPPORTED`/P1 there, so flagging its absence would be noise for a
/// thing the platform cannot do.
///
/// `qsh service install` does not exist yet (ROADMAP M9 (g)) — `remedy` points
/// at the manual unit in `docs/deploy/service.md` instead of a command
/// that would not run, and says the installer is coming so this finding
/// is not a dead end.
pub const SERVICE_NOT_REGISTERED: Diagnostic = Diagnostic {
    id: DiagnosticId::ServiceNotRegistered,
    code: "service_not_registered",
    message: "No platform service unit is registered for this machine's inferred run mode. Until one is, this mode only runs in the foreground; it does not survive logout, reboot, or a crash.",
    remedy: "`qsh service install` does not exist yet — for now, follow docs/deploy/service.md's manual unit example to run this mode unattended.",
};

/// `docs/ROADMAP.md` M9 (h), `docs/CLI.md` §6.17: Linux only, and only
/// reachable once [`SERVICE_NOT_REGISTERED`] did *not* fire for this
/// mode — there is no point warning about linger for a service that
/// is not installed yet. Detected via
/// [`probe::probe_systemd_linger`]'s file-existence read of
/// `/var/lib/systemd/linger/$USER` (systemd's own marker, no
/// `Command::new`); an unreadable probe (e.g. a sandboxed CI account)
/// is "unknown", not "disabled", and reports no finding either way —
/// the same caution [`probe::keystore_finding`]/`detect_path_shadow`
/// already apply to an ambiguous probe result.
pub const SYSTEMD_LINGER_DISABLED: Diagnostic = Diagnostic {
    id: DiagnosticId::SystemdLingerDisabled,
    code: "systemd_linger_disabled",
    message: "systemd user linger is not enabled for this account. The registered service's user unit stops the moment your last login session ends.",
    remedy: "Run `loginctl enable-linger $USER` (docs/deploy/service.md) so the unit keeps running once your last login session ends.",
};

/// `docs/ROADMAP.md` M9 (h), `docs/CLI.md` §6.17: macOS only, fires
/// whenever the inferred mode's LaunchAgent is registered
/// ([`probe::service_unit_registered`]) — unconditional once true, the
/// same "structural fact, not a misconfiguration" shape
/// [`TRUST_REMOVE_SCOPE`] already has: a user LaunchAgent has no
/// headless equivalent (`docs/deploy/service.md:94-98`), so an operator
/// who registered one should always see this spelled out, not only once
/// something goes wrong.
pub const LAUNCHAGENT_SESSION_SCOPED: Diagnostic = Diagnostic {
    id: DiagnosticId::LaunchagentSessionScoped,
    code: "launchagent_session_scoped",
    message: "qsh's service is registered as a user LaunchAgent, which only runs inside an active login session and stops at logout — unlike a systemd user unit with linger enabled, no headless equivalent exists for a normal user account.",
    remedy: "Keep a session logged in, or accept the limitation. A LaunchDaemon (root, out of scope) is the only headless option on macOS.",
};

/// `docs/ROADMAP.md` M9 (h) (ROADMAP/PLAN's own shorthand is the bare
/// term "bindv6only"; this repo's naming convention spells out the fuller code),
/// `docs/CLI.md` §6.17: the effective `serve`/`listen` bind address is
/// the IPv6 wildcard, and a live probe
/// ([`probe::probe_bindv6only`]) shows this OS defaults a fresh
/// dual-stack bind there to `IPV6_V6ONLY`. A real gap, not a
/// hypothetical: `Listener::bind` calls
/// [`qsh_transport::bind_tuned_udp_socket`] with `dual_stack_v6=false`,
/// so the server side never explicitly clears `IPV6_V6ONLY` the way the
/// client dialer does — on a v6-only-by-default OS (the canonical case
/// is Windows, though this is a genuine per-OS/per-sysctl variable, not
/// only a Windows one), a `[::]:4433` listener silently rejects IPv4
/// peers with no signal anywhere in this build.
pub const BINDV6ONLY_BLOCKS_IPV4: Diagnostic = Diagnostic {
    id: DiagnosticId::Bindv6onlyBlocksIpv4,
    code: "bindv6only_blocks_ipv4",
    message: "The configured listen address is the IPv6 wildcard, and this OS defaults new dual-stack sockets there to IPv6-only; qsh never asks for dual-stack explicitly on the listener side. An IPv4-only peer cannot reach this listener; the dial just times out on the caller's side with no signal here.",
    remedy: "Bind an explicit IPv4 address for IPv4 reachability (--bind 0.0.0.0:4433), or run separate listeners, or confirm this OS's IPv6 dual-stack default matches intent.",
};

/// `docs/adr/0017-acl-toml-not-written.md` 결정 2 (`:20-26`): the code
/// string itself is fixed by that ADR (`:21`'s matching rule, reused
/// verbatim by [`crate::acl::PinnedPrincipalIndex`]) — a `trust.toml`
/// pin that no pin-path `acl.toml` row (`device:<name>` or
/// `fp:sha256:<fingerprint>`, explicit or defaulted `auth_path = "pin"`)
/// matches. `error`, not `warn`: the same shape
/// [`PEER_UNTRUSTED`] already reasons through — a named, real peer that
/// is *certain* to be denied every request, not a latent gap.
pub const ACL_PRINCIPAL_UNMATCHED: Diagnostic = Diagnostic {
    id: DiagnosticId::AclPrincipalUnmatched,
    code: "acl_principal_unmatched",
    message: "trust.toml pins a peer that no acl.toml row with auth_path \"pin\" matches — neither its device:<name> principal nor its fp:sha256:<fingerprint> principal. Every request from this peer is denied (default-deny) until a matching row exists.",
    remedy: "Add a matching [[acl]] row (ADR-0017), then restart serve/listen — acl.toml is only read once at process start.",
};

/// `docs/adr/0017-acl-toml-not-written.md` 결정 2 (`:20-26`): the code
/// string is fixed by that ADR — `trust.toml` has at least one `[[ca]]`
/// entry, but no `acl.toml` row anywhere sets `auth_path = "ca"`. File-
/// wide by design ("peer 단위가 아니라 파일 전체 수준의 거친 검사", the ADR's
/// own words): a CA-authenticated principal is still `device:<id>`-
/// shaped and cannot be pre-enumerated (`docs/CLI.md` §6.16), so this
/// check names the gap, never a specific peer. `warn`, not `error`:
/// unlike [`ACL_PRINCIPAL_UNMATCHED`]'s named,
/// certain-to-fail peer, this is "a CA is provisioned but nothing is
/// proven to rely on it yet" — closer to [`CONFIG_UNKNOWN_KEY`]'s
/// latent-gap shape than to [`PEER_UNTRUSTED`]'s certain failure.
pub const ACL_CA_AUTH_PATH_MISSING: Diagnostic = Diagnostic {
    id: DiagnosticId::AclCaAuthPathMissing,
    code: "acl_ca_auth_path_missing",
    message: "trust.toml has a CA root, but no acl.toml row sets auth_path = \"ca\". Any peer authenticating via that CA is denied (default-deny) until one does.",
    remedy: "Add an [[acl]] row with auth_path = \"ca\" (ADR-0017), then restart serve/listen — acl.toml is only read once at process start.",
};

/// `docs/ROADMAP.md` M9 (h) (added to the batch in commit `fab8563`), `docs/CLI.md` §6.17: a
/// name `Ops::host_list`'s forward ∪ reverse merge already knows about
/// (a trust-store pin or a `hosts.toml` entry) has no routable address
/// from either book and no reverse registration — live or stale — for
/// it. The same defect `crate::ops::host::pinned_without_address_host_not_found`
/// only ever catches reactively, at dial time; this surfaces it
/// proactively, the same relationship [`PEER_UNTRUSTED`] already has to
/// `TRUST_REQUIRED`. `warn`, not `error`: a pure
/// reverse target that has not phoned home yet (pinned via `qsh trust
/// add --fingerprint`, no `--address`) is a normal transient state, not
/// a bug — flagging it `error` would false-alarm on an intended
/// workflow. Suppressed whenever any reverse entry for the name exists
/// at all, live or stale.
///
/// `remedy`'s `{name}` is a template placeholder, not literal output —
/// the caller (`Ops::doctor_pinned_no_address_findings`) already knows
/// the concrete host name and substitutes it in, the same way `detail`
/// interpolates it.
pub const HOST_PINNED_WITHOUT_ADDRESS: Diagnostic = Diagnostic {
    id: DiagnosticId::HostPinnedWithoutAddress,
    code: "host_pinned_without_address",
    message: "This host is configured (a trust-store pin or a hosts.toml entry) but has no address from either source and no reverse registration is currently held.",
    remedy: "Add an address with `qsh trust add {name} --address <host:port> --fingerprint sha256:...`, or register it by running `qsh reverse <controller>` on that host.",
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

    /// ROADMAP M9 (h) batch: each new const's `id`/`code` pairing, mirroring
    /// the two pre-existing checks above — a mutation swapping one
    /// const's `code` string or `DiagnosticId` would otherwise only be
    /// caught indirectly, by the frozen-set test below going red with a
    /// less specific message.
    #[test]
    fn m9_h_batch_diagnostic_consts_have_the_stable_snake_case_codes() {
        assert_eq!(
            SERVICE_NOT_REGISTERED.id,
            DiagnosticId::ServiceNotRegistered
        );
        assert_eq!(SERVICE_NOT_REGISTERED.code, "service_not_registered");
        assert_eq!(
            SYSTEMD_LINGER_DISABLED.id,
            DiagnosticId::SystemdLingerDisabled
        );
        assert_eq!(SYSTEMD_LINGER_DISABLED.code, "systemd_linger_disabled");
        assert_eq!(
            LAUNCHAGENT_SESSION_SCOPED.id,
            DiagnosticId::LaunchagentSessionScoped
        );
        assert_eq!(
            LAUNCHAGENT_SESSION_SCOPED.code,
            "launchagent_session_scoped"
        );
        assert_eq!(
            BINDV6ONLY_BLOCKS_IPV4.id,
            DiagnosticId::Bindv6onlyBlocksIpv4
        );
        assert_eq!(BINDV6ONLY_BLOCKS_IPV4.code, "bindv6only_blocks_ipv4");
        assert_eq!(
            ACL_PRINCIPAL_UNMATCHED.id,
            DiagnosticId::AclPrincipalUnmatched
        );
        assert_eq!(ACL_PRINCIPAL_UNMATCHED.code, "acl_principal_unmatched");
        assert_eq!(
            ACL_CA_AUTH_PATH_MISSING.id,
            DiagnosticId::AclCaAuthPathMissing
        );
        assert_eq!(ACL_CA_AUTH_PATH_MISSING.code, "acl_ca_auth_path_missing");
        assert_eq!(
            HOST_PINNED_WITHOUT_ADDRESS.id,
            DiagnosticId::HostPinnedWithoutAddress
        );
        assert_eq!(
            HOST_PINNED_WITHOUT_ADDRESS.code,
            "host_pinned_without_address"
        );
    }

    /// ROADMAP M9 (b)'s `qsh serve --to` rename adds an eighth M9 (h) code —
    /// same mutation-catching rationale as
    /// `m9_h_batch_diagnostic_consts_have_the_stable_snake_case_codes`
    /// above.
    #[test]
    fn config_serve_to_conflict_has_the_stable_snake_case_code() {
        assert_eq!(
            CONFIG_SERVE_TO_CONFLICT.id,
            DiagnosticId::ConfigServeToConflict
        );
        assert_eq!(CONFIG_SERVE_TO_CONFLICT.code, "config_serve_to_conflict");
    }

    /// `PLAN.md` M7 §4.1 #5's "code 안정성 fixture": every [`DiagnosticId`]
    /// variant, exhaustively hand-listed (a variant added here without a
    /// matching addition to [`EXPECTED_DOCTOR_CODES`], or vice versa, is
    /// exactly the drift this test exists to catch), must map to a unique
    /// code and the frozen set must be exactly those 22 codes — no more, no
    /// fewer. Mirrors `qsh_proto::schema`'s
    /// `cli_v1_schema_commands_is_sorted_and_deduplicated` precedent.
    #[test]
    fn expected_doctor_codes_matches_every_diagnostic_id_variant_exactly() {
        const ALL: [DiagnosticId; 22] = [
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
            DiagnosticId::ConfigUnknownKey,
            DiagnosticId::ServiceNotRegistered,
            DiagnosticId::SystemdLingerDisabled,
            DiagnosticId::LaunchagentSessionScoped,
            DiagnosticId::Bindv6onlyBlocksIpv4,
            DiagnosticId::AclPrincipalUnmatched,
            DiagnosticId::AclCaAuthPathMissing,
            DiagnosticId::HostPinnedWithoutAddress,
            DiagnosticId::ConfigServeToConflict,
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
