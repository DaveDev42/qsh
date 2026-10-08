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

/// ADR-0019 결과 절 R6's doctor follow-up — same mutation-catching
/// rationale as `config_serve_to_conflict_has_the_stable_snake_case_code`
/// above.
#[test]
fn acl_forward_socks_ineffective_has_the_stable_snake_case_code() {
    assert_eq!(
        ACL_FORWARD_SOCKS_INEFFECTIVE.id,
        DiagnosticId::AclForwardSocksIneffective
    );
    assert_eq!(
        ACL_FORWARD_SOCKS_INEFFECTIVE.code,
        "acl_forward_socks_ineffective"
    );
}

/// M13 graceful re-exec H1 — same mutation-catching rationale as
/// `acl_forward_socks_ineffective_has_the_stable_snake_case_code`.
#[test]
fn service_restart_drops_sessions_has_the_stable_snake_case_code() {
    assert_eq!(
        SERVICE_RESTART_DROPS_SESSIONS.id,
        DiagnosticId::ServiceRestartDropsSessions
    );
    assert_eq!(
        SERVICE_RESTART_DROPS_SESSIONS.code,
        "service_restart_drops_sessions"
    );
}

/// `PLAN.md` M7 §4.1 #5's "code 안정성 fixture": every [`DiagnosticId`]
/// variant, exhaustively hand-listed (a variant added here without a
/// matching addition to [`EXPECTED_DOCTOR_CODES`], or vice versa, is
/// exactly the drift this test exists to catch), must map to a unique
/// code and the frozen set must be exactly those 24 codes — no more, no
/// fewer. Mirrors `qsh_proto::schema`'s
/// `cli_v1_schema_commands_is_sorted_and_deduplicated` precedent.
#[test]
fn expected_doctor_codes_matches_every_diagnostic_id_variant_exactly() {
    const ALL: [DiagnosticId; 24] = [
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
        DiagnosticId::AclForwardSocksIneffective,
        DiagnosticId::ServiceRestartDropsSessions,
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
fn acl_restart_notice_is_the_verbatim_tail_of_both_acl_diagnostic_remedies() {
    // Deliberately does not retype the notice's own wording — that
    // literal exists exactly once in the whole crate, inside
    // `crate::acl::acl_restart_notice!()`'s definition. Both
    // assertions below reference the constant instead, so a wording
    // edit still only ever touches that one place.
    let notice = crate::acl::ACL_RESTART_NOTICE;
    assert_eq!(
        ACL_PRINCIPAL_UNMATCHED.remedy,
        format!("Add a matching [[acl]] row (ADR-0017), then {notice}")
    );
    assert_eq!(
        ACL_CA_AUTH_PATH_MISSING.remedy,
        format!("Add an [[acl]] row with auth_path = \"ca\" (ADR-0017), then {notice}")
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
