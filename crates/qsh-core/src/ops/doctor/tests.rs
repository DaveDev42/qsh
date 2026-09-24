use super::*;
use qsh_proto::{IdentityInitReq, KeyStoreMode, TrustAddReq};

use crate::config::Paths;

fn temp_ops() -> (tempfile::TempDir, Ops) {
    let dir = tempfile::tempdir().unwrap();
    // Pin `runtime_dir` into the sandbox (`Paths::with_runtime_dir`'s own
    // doc) so `reverse_host_entries()` — `host_pinned_without_address`'s
    // dependency, via `self.paths().runtime_dir()` — never reads this
    // developer's or CI runner's real `$XDG_RUNTIME_DIR`/localctl socket,
    // regardless of what real `qsh listen` state happens to exist there.
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"))
        .with_runtime_dir(dir.path().join("run"));
    (dir, Ops::new(paths))
}

fn init_identity(ops: &Ops) {
    ops.identity_init(IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
    })
    .unwrap();
}

/// A `linger_dir` no test's home directory ever coincides with — used by
/// every [`DoctorEnvironment`] literal that is not itself exercising
/// `systemd_linger_disabled` (`probe::probe_systemd_linger` only reads it
/// once a unit is registered, `env.home_dir` is `Some`, which most tests
/// below never set either).
fn no_linger_dir() -> &'static Path {
    Path::new("/nonexistent-m9-step4-doctor-test-linger-root")
}

/// A `bindv6only_probe` stub for every [`DoctorEnvironment`] literal that
/// is not itself exercising `bindv6only_blocks_ipv4` — `Ok(false)` never
/// fires [`probe::bindv6only_finding`] — the mutation check has its own
/// dedicated `Ok(true)` stub, [`always_v6_only`].
fn never_v6_only(_addr: SocketAddr) -> std::io::Result<bool> {
    Ok(false)
}

/// The wiring test's forcing stub — always reports `IPV6_V6ONLY`,
/// deterministically, on every OS/CI leg, regardless of this machine's
/// real dual-stack default.
fn always_v6_only(_addr: SocketAddr) -> std::io::Result<bool> {
    Ok(true)
}

/// A [`DoctorEnvironment`] with every probe stubbed to "not present"/
/// "cannot tell" — every ROADMAP M9 (h) test below overrides only the one or
/// two fields its own probe actually reads, via struct-update syntax,
/// rather than repeating all seven fields at every call site.
fn minimal_env(keystore: &dyn KeyStore) -> DoctorEnvironment<'_> {
    DoctorEnvironment {
        keystore,
        current_exe: None,
        path_dirs: &[],
        home_dir: None,
        linger_dir: no_linger_dir(),
        username: None,
        bindv6only_probe: never_v6_only,
    }
}

// -----------------------------------------------------------------
// Precondition: no identity is a hard Err, not a finding.
// -----------------------------------------------------------------

#[test]
fn doctor_without_identity_is_a_config_error() {
    let (_guard, ops) = temp_ops();
    let err = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(err.message.contains("qsh init"), "{err}");
}

// -----------------------------------------------------------------
// acl_policy_missing / acl_policy_invalid — startup diagnostic reuse.
// -----------------------------------------------------------------

#[test]
fn doctor_reports_acl_policy_missing_when_acl_toml_is_absent() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    assert_eq!(data.overall, "error");
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "acl_policy_missing")
        .expect("acl_policy_missing finding");
    assert_eq!(finding.status, "error");
}

#[test]
fn doctor_reports_acl_policy_invalid_for_malformed_acl_toml() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), "not valid toml {{{").unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "acl_policy_invalid")
        .expect("acl_policy_invalid finding");
    assert_eq!(finding.status, "error");
    assert!(
        data.findings.iter().all(|f| f.code != "acl_policy_missing"),
        "invalid and missing are mutually exclusive"
    );
}

fn minimal_acl_toml() -> &'static str {
    "[[acl]]\nprincipal = \"user:x\"\nallow = [\"exec.run\"]\n"
}

// -----------------------------------------------------------------
// audit_path_unwritable
// -----------------------------------------------------------------

#[cfg(unix)]
#[test]
fn doctor_reports_audit_path_unwritable_for_a_0500_directory() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, ops) = temp_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
    init_identity(&ops);

    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::write(
        ops.paths().config_file(),
        format!(
            "[audit]\npath = {:?}\n",
            locked.join("audit.log").display().to_string()
        ),
    )
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "audit_path_unwritable")
        .expect("audit_path_unwritable finding");
    assert_eq!(finding.status, "error");

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// P3-5 (verify round): the 0o500 trigger above is `#[cfg(unix)]`
/// only — permission bits do not port to Windows — while this
/// module's own doc requires the diagnostic to build *and run* on
/// the Windows CI leg too. A portable trigger instead: a regular file
/// sitting where the audit log's parent directory needs to be created
/// makes `std::fs::create_dir_all` fail deterministically on every
/// platform (it is not a permission error, so no `#[cfg(unix)]` is
/// needed at all).
#[test]
fn doctor_reports_audit_path_unwritable_when_the_parent_path_is_occupied_by_a_file() {
    let (dir, ops) = temp_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
    init_identity(&ops);

    let occupied = dir.path().join("occupied");
    std::fs::write(&occupied, b"not a directory").unwrap();
    std::fs::write(
        ops.paths().config_file(),
        format!(
            "[audit]\npath = {:?}\n",
            occupied.join("audit.log").display().to_string()
        ),
    )
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "audit_path_unwritable")
        .expect("audit_path_unwritable finding");
    assert_eq!(finding.status, "error");
}

// -----------------------------------------------------------------
// cert_expired / cert_expiring_soon / clock_skew — `now` injection.
// -----------------------------------------------------------------

fn healthy_ops() -> (tempfile::TempDir, Ops) {
    let (dir, ops) = temp_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
    init_identity(&ops);
    (dir, ops)
}

#[test]
fn doctor_reports_cert_expired_when_now_is_past_not_after() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (_not_before, not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_after + 86_400) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    assert_eq!(data.overall, "error");
    assert!(
        data.findings.iter().any(|f| f.code == "cert_expired"),
        "{:?}",
        data.findings
    );
    assert!(
        data.findings.iter().all(|f| f.code != "cert_expiring_soon"),
        "expired and expiring-soon are mutually exclusive for one cert"
    );
}

#[test]
fn doctor_reports_cert_expiring_soon_within_the_30_day_window() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (_not_before, not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_after - 20 * 86_400) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "cert_expiring_soon")
        .expect("cert_expiring_soon finding");
    assert_eq!(finding.status, "warn");
}

/// Boundary (verify round P3-2, mutation `MF`: `now_unix >= not_after`
/// weakened to `>`): `now == not_after` must still fire `cert_expired`,
/// not just strictly-past.
#[test]
fn doctor_reports_cert_expired_when_now_exactly_equals_not_after() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (_not_before, not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(not_after as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    assert!(
        data.findings.iter().any(|f| f.code == "cert_expired"),
        "{:?}",
        data.findings
    );
}

/// Boundary (verify round P3-2, mutation `MI`: the 30-day window
/// comparison weakened from `<=` to `<`): exactly 30 days out must
/// still fire `cert_expiring_soon`.
#[test]
fn doctor_reports_cert_expiring_soon_at_exactly_the_30_day_window() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (_not_before, not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH
        + Duration::from_secs((not_after - CERT_EXPIRING_SOON_WINDOW_SECS) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "cert_expiring_soon")
        .expect("cert_expiring_soon finding");
    assert_eq!(finding.status, "warn");
}

/// CA root half of `cert_expired` (verify round P2-3, mutation `MD`:
/// the CA branch checking `identity.cert_der` instead of `ca.cert_der`)
/// — `crate::ca::init` is never called anywhere else in this module's
/// tests, so without this test the CA branch of
/// `Ops::doctor_cert_findings` is never exercised at all. The CA root
/// is valid for 20 years (`crate::ca::CA_VALIDITY_DAYS`) vs. the
/// device leaf's 10 (`crate::identity::CERT_VALIDITY_DAYS`), so a
/// `now` past the CA's own `not_after` is also past the leaf's —
/// both fire, and `detail` must name each one distinctly.
#[test]
fn doctor_reports_cert_expired_for_both_leaf_and_ca_root_once_both_are_past_not_after() {
    let (_guard, ops) = healthy_ops();
    ops.cert_init(qsh_proto::CertInitReq {}).unwrap();
    let ca_root = crate::ca::read_root(ops.paths()).unwrap().unwrap();
    let (_not_before, ca_not_after) =
        qsh_transport::identity::validity_unix(&ca_root.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((ca_not_after + 86_400) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let expired: Vec<_> = data
        .findings
        .iter()
        .filter(|f| f.code == "cert_expired")
        .collect();
    assert_eq!(
        expired.len(),
        2,
        "expected both the device leaf and the CA root to report cert_expired: {:?}",
        data.findings
    );
    assert!(
        expired.iter().any(|f| f.detail.contains("own leaf")),
        "{expired:?}"
    );
    assert!(
        expired.iter().any(|f| f.detail.contains("CA root")),
        "{expired:?}"
    );
}

/// Distinguishes the CA-root branch from the leaf branch by actual
/// expiry state rather than by label text alone (verify round P2-3,
/// mutation `MD`: the CA branch reading `identity.cert_der` — the
/// leaf's own bytes — instead of `ca.cert_der`). The leaf's 10-year
/// validity ends well before the CA root's 20-year validity
/// ([`crate::identity::CERT_VALIDITY_DAYS`] vs.
/// [`crate::ca::CA_VALIDITY_DAYS`]), so `now` set just past the
/// leaf's own `not_after` but still years before the CA root's
/// `not_after` must report exactly one `cert_expired` (the leaf) —
/// under `MD` the mislabeled "CA root" entry would also fire
/// `cert_expired`, because it is secretly re-checking the
/// already-expired leaf bytes, producing two findings instead of one.
#[test]
fn doctor_reports_cert_expired_only_for_the_leaf_when_only_the_leaf_is_past_not_after() {
    let (_guard, ops) = healthy_ops();
    ops.cert_init(qsh_proto::CertInitReq {}).unwrap();
    let identity = ops.load_identity().unwrap().unwrap();
    let (_not_before, leaf_not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let ca_root = crate::ca::read_root(ops.paths()).unwrap().unwrap();
    let (_ca_not_before, ca_not_after) =
        qsh_transport::identity::validity_unix(&ca_root.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((leaf_not_after + 86_400) as u64);
    assert!(
        leaf_not_after + 86_400 < ca_not_after,
        "fixture assumption: leaf must expire well before the CA root"
    );

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let expired: Vec<_> = data
        .findings
        .iter()
        .filter(|f| f.code == "cert_expired")
        .collect();
    assert_eq!(
        expired.len(),
        1,
        "expected only the device leaf to report cert_expired while the CA root is still valid: {:?}",
        data.findings
    );
    assert!(
        expired.iter().any(|f| f.detail.contains("own leaf")),
        "{expired:?}"
    );
    assert!(
        !expired.iter().any(|f| f.detail.contains("CA root")),
        "{expired:?}"
    );
}

#[test]
fn doctor_reports_no_cert_findings_well_before_expiry() {
    let (_guard, ops) = healthy_ops();
    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    assert!(
        data.findings
            .iter()
            .all(|f| f.code != "cert_expired" && f.code != "cert_expiring_soon"),
        "{:?}",
        data.findings
    );
}

#[test]
fn doctor_reports_clock_skew_error_past_the_backdate_margin() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (not_before, _not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    // 10 minutes behind not_before: exceeds the 5-minute backdate margin.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 10 * 60) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "clock_skew")
        .expect("clock_skew finding");
    assert_eq!(finding.status, "error");
}

#[test]
fn doctor_reports_clock_skew_warn_within_the_backdate_margin() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (not_before, _not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    // 3 minutes behind not_before: inside the 5-minute backdate margin.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 3 * 60) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "clock_skew")
        .expect("clock_skew finding");
    assert_eq!(finding.status, "warn");
}

/// P3-1 regression: 301 seconds of skew already exceeds the 300s
/// (5-minute) backdate margin, and must classify as `error`. Before
/// the fix, `(301 / 60) == 5` truncated to exactly the margin and this
/// reported `warn` instead — the comparison must be in whole seconds,
/// not truncated minutes.
#[test]
fn doctor_reports_clock_skew_error_at_301_seconds_past_the_margin() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (not_before, _not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 301) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "clock_skew")
        .expect("clock_skew finding");
    assert_eq!(finding.status, "error", "{finding:?}");
}

/// Boundary (verify round P3-2, mutation `MG`: `skew_minutes >
/// CERT_BACKDATE_MINUTES` weakened to `>=`): skew of exactly 300
/// seconds (5 minutes) is *at* the margin, not past it, and must stay
/// `warn`.
#[test]
fn doctor_reports_clock_skew_warn_at_exactly_the_5_minute_margin() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap();
    let (not_before, _not_after) =
        qsh_transport::identity::validity_unix(&identity.identity.cert_der).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs((not_before - 300) as u64);

    let data = ops.doctor(DoctorReq { host: None }, now).unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "clock_skew")
        .expect("clock_skew finding");
    assert_eq!(finding.status, "warn", "{finding:?}");
}

// -----------------------------------------------------------------
// peer_untrusted / trust_remove_scope
// -----------------------------------------------------------------

#[test]
fn doctor_reports_peer_untrusted_for_a_hosts_toml_entry_with_no_pin() {
    let (_guard, ops) = healthy_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().hosts_file(),
        "[[host]]\nname = \"orphan\"\naddress = \"orphan.example:4433\"\n",
    )
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "peer_untrusted")
        .expect("peer_untrusted finding");
    assert_eq!(finding.status, "error");
    assert!(finding.detail.contains("orphan"), "{finding:?}");
}

#[test]
fn doctor_has_no_peer_untrusted_when_hosts_toml_is_empty() {
    let (_guard, ops) = healthy_ops();
    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    assert!(data.findings.iter().all(|f| f.code != "peer_untrusted"));
}

#[test]
fn doctor_reports_trust_remove_scope_only_once_a_peer_is_pinned() {
    let (_guard, ops) = healthy_ops();
    // A pin-path row for the peer this test pins below, so the only
    // `overall` delta the pin adds is `trust_remove_scope`'s own `info`
    // notice — otherwise `acl_principal_unmatched` would
    // (correctly) also fire for an ACL-unmatched "mac" pin and confound
    // this test's isolation.
    std::fs::write(
        ops.paths().acl_file(),
        "[[acl]]\nprincipal = \"device:mac\"\nallow = [\"exec.run\"]\n",
    )
    .unwrap();
    let before = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    assert!(
        before
            .findings
            .iter()
            .all(|f| f.code != "trust_remove_scope")
    );

    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: Some("mac.example:4433".into()),
        fingerprint: Some(fingerprint),
    })
    .unwrap();

    let after = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = after
        .findings
        .iter()
        .find(|f| f.code == "trust_remove_scope")
        .expect("trust_remove_scope finding");
    assert_eq!(finding.status, "info");
    // An `info`-only addition must not change `overall` — compared
    // against the "before" baseline rather than a hardcoded "ok"
    // defensively, in case some other finding on this test machine
    // already put the baseline at "warn"; `keystore_unavailable`
    // itself is no longer one of the ways that can happen for
    // `healthy_ops()`'s file-mode identity (below).
    assert_eq!(after.overall, before.overall);
}

// -----------------------------------------------------------------
// keystore_unavailable — `Ops::doctor` now probes the key store
// `identity.key_store` actually names (R1 판정 (g)), not
// unconditionally `PlatformKeyStore`. `healthy_ops()` inits a
// file-mode identity, so this probes `FileKeyStore` against the real
// `device.key` `init_identity` already wrote — deterministic, and it
// always finds the key, so `keystore_unavailable` does not fire in
// this suite at all. The test below stays as a defensive shape check
// (a broken/unreadable `device.key` on some other machine, or a
// platform-mode identity in the field, must still only ever surface
// as `"warn"`, never panic) — not a claim that this specific run
// exercises the unavailable path; the deterministic trigger for that
// path is the `AlwaysUnavailableKeyStore` stub two tests down.
// -----------------------------------------------------------------

#[test]
fn doctor_keystore_probe_does_not_panic_and_only_ever_reports_warn() {
    let (_guard, ops) = healthy_ops();
    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    if let Some(finding) = data
        .findings
        .iter()
        .find(|f| f.code == "keystore_unavailable")
    {
        assert_eq!(finding.status, "warn");
    }
}

/// A `KeyStore` stub whose `load()` always reports
/// `Err(KeyStoreError::Unavailable(_))` — the deterministic trigger
/// the test above cannot force on its own (verify round P2-2,
/// mutation `MA`: deleting `Ops::doctor`'s keystore-probe wiring
/// entirely used to leave every test in this file green).
struct AlwaysUnavailableKeyStore;

impl KeyStore for AlwaysUnavailableKeyStore {
    fn kind(&self) -> qsh_proto::KeyStoreKind {
        qsh_proto::KeyStoreKind::Platform
    }

    fn store(&self, _key_pkcs8_der: &[u8]) -> Result<(), crate::identity::KeyStoreError> {
        unimplemented!("keystore_finding_of only ever calls load()")
    }

    fn load(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, crate::identity::KeyStoreError> {
        Err(crate::identity::KeyStoreError::Unavailable(
            "stub: no secret service".to_string(),
        ))
    }

    fn delete(&self) -> Result<(), crate::identity::KeyStoreError> {
        unimplemented!("keystore_finding_of only ever calls load()")
    }
}

#[test]
fn keystore_finding_of_fires_deterministically_when_the_store_reports_unavailable() {
    let finding =
        keystore_finding_of(&AlwaysUnavailableKeyStore).expect("keystore_unavailable finding");
    assert_eq!(finding.code, "keystore_unavailable");
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("stub: no secret service"));
}

/// Wiring-level (verify round P2-2, mutation `MA`: deleting
/// `Ops::doctor_assemble`'s `findings.extend(keystore_finding_of(...))`
/// line entirely used to leave every test in this file green — the
/// unit test above only drives the pure classifier, never `Ops`'s own
/// finding-assembly). Goes through [`Ops::doctor_assemble`] itself
/// with a stub [`DoctorEnvironment`], the real code path `Ops::doctor`
/// calls, not a parallel reimplementation of it.
#[test]
fn doctor_wires_the_keystore_finding_into_the_full_report_deterministically() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    let env = DoctorEnvironment {
        keystore: &AlwaysUnavailableKeyStore,
        current_exe: None,
        path_dirs: &[],
        home_dir: None,
        linger_dir: no_linger_dir(),
        username: None,
        bindv6only_probe: never_v6_only,
    };

    let data = ops
        .doctor_assemble(
            DoctorReq { host: None },
            unix_seconds(SystemTime::now()),
            &identity,
            &config,
            &env,
        )
        .unwrap();
    assert!(
        data.findings
            .iter()
            .any(|f| f.code == "keystore_unavailable"),
        "{:?}",
        data.findings
    );
}

// -----------------------------------------------------------------
// qsh_path_shadowed — the underlying scan is already covered
// deterministically with an injected `$PATH`
// (`doctor::probe::tests::detect_path_shadow_*`). `Ops::doctor` itself
// reads the *real* `$PATH` and `current_exe()` (design brief row #12:
// this is meant to catch a real shadowing binary on this machine), so
// whether it fires at all depends on this test machine's actual
// environment — this only asserts the finding's shape when present,
// never its absence.
// -----------------------------------------------------------------

#[test]
fn doctor_path_shadow_probe_does_not_panic_and_only_ever_reports_warn() {
    let (_guard, ops) = healthy_ops();
    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    if let Some(finding) = data.findings.iter().find(|f| f.code == "qsh_path_shadowed") {
        assert_eq!(finding.status, "warn");
    }
}

/// A fake, executable `qsh` for the injected-`$PATH` test below — the
/// same shape `doctor::probe::tests::write_fake_exe` uses one layer
/// down, duplicated here rather than exported test-only from `probe`
/// (verify round P2-4).
#[cfg(unix)]
fn write_fake_qsh_exe(dir: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("qsh");
    std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(windows)]
fn write_fake_qsh_exe(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("qsh.exe");
    std::fs::write(&path, b"MZ").unwrap();
    path
}

/// Deterministic trigger for `path_shadow_finding` (verify round
/// P2-4, mutation `MB`: deleting `Ops::doctor`'s path-shadow-probe
/// wiring entirely used to leave every test in this file green, and
/// on a machine with no `qsh` on `$PATH` the shape-only test above is
/// completely vacuous). An injected temp `$PATH`, not this process's
/// real one — the same pattern
/// `doctor::probe::tests::detect_path_shadow_finds_an_earlier_qsh_before_the_running_one`
/// already uses one layer down.
#[test]
fn path_shadow_finding_fires_deterministically_for_an_earlier_qsh_on_path() {
    let dir = tempfile::tempdir().unwrap();
    let shadow_dir = dir.path().join("shadow");
    let real_dir = dir.path().join("real");
    std::fs::create_dir(&shadow_dir).unwrap();
    std::fs::create_dir(&real_dir).unwrap();
    let shadow_exe = write_fake_qsh_exe(&shadow_dir);
    let real_exe = write_fake_qsh_exe(&real_dir);

    let finding =
        path_shadow_finding(&real_exe, &[shadow_dir, real_dir]).expect("qsh_path_shadowed finding");
    assert_eq!(finding.code, "qsh_path_shadowed");
    assert_eq!(finding.status, "warn");
    assert!(
        finding.detail.contains(&shadow_exe.display().to_string()),
        "{finding:?}"
    );
    assert!(
        finding.detail.contains(&real_exe.display().to_string()),
        "{finding:?}"
    );
}

/// Wiring-level (verify round P2-4, mutation `MB`: deleting
/// `Ops::doctor_assemble`'s path-shadow line entirely used to leave
/// every test in this file green — the unit test above only drives
/// the pure classifier, never `Ops`'s own finding-assembly). Goes
/// through [`Ops::doctor_assemble`] itself with a stub
/// [`DoctorEnvironment`] (an injected temp `$PATH`, a `MemoryKeyStore`
/// so `keystore_unavailable` never fires and cannot be mistaken for
/// this finding), the real code path `Ops::doctor` calls.
#[test]
fn doctor_wires_the_path_shadow_finding_into_the_full_report_deterministically() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let shadow_dir = dir.path().join("shadow");
    let real_dir = dir.path().join("real");
    std::fs::create_dir(&shadow_dir).unwrap();
    std::fs::create_dir(&real_dir).unwrap();
    write_fake_qsh_exe(&shadow_dir);
    let real_exe = write_fake_qsh_exe(&real_dir);
    let path_dirs = vec![shadow_dir, real_dir];
    let never_unavailable = crate::identity::MemoryKeyStore::new();
    let env = DoctorEnvironment {
        keystore: &never_unavailable,
        current_exe: Some(&real_exe),
        path_dirs: &path_dirs,
        home_dir: None,
        linger_dir: no_linger_dir(),
        username: None,
        bindv6only_probe: never_v6_only,
    };

    let data = ops
        .doctor_assemble(
            DoctorReq { host: None },
            unix_seconds(SystemTime::now()),
            &identity,
            &config,
            &env,
        )
        .unwrap();
    assert!(
        data.findings.iter().any(|f| f.code == "qsh_path_shadowed"),
        "{:?}",
        data.findings
    );
}

// -----------------------------------------------------------------
// connectivity: controller_unreachable / no_route / udp_egress_blocked
// precedence, and an unresolvable req.host being a hard error.
// -----------------------------------------------------------------

/// `resolve_with_timeout` against a "slow resolver" seam — a closure
/// that sleeps well past a 1ms timeout — rather than a real DNS name,
/// per the brief's own steer away from depending on real DNS. Mirrors
/// `doctor::probe`'s `probe_times_out_against_a_silent_black_hole`
/// shape: an extreme, deterministic timeout injected directly at the
/// seam under test.
///
/// Two more checks land in this same test (R1 판정 (g), DNS-wiring
/// minors): an elapsed-time assertion that the wait itself is actually
/// bounded by the 1ms timeout rather than by how long the sleeping
/// resolver takes (a regression that swapped `recv_timeout` for a
/// plain, unbounded `recv` would still return the right `Err` above,
/// eventually — only the clock catches that); and a source-text pin,
/// the same shape as `fsutil.rs`'s `resume_and_config_pin_opposite_
/// durable_arguments_in_their_source`, that `resolve_probe_socket_
/// addr`'s production call site really does pass `DOCTOR_PROBE_
/// TIMEOUT` — not some other duration — as the resolve budget. Built
/// via `format!` rather than typed as one literal so the needle does
/// not just match itself inside this test's own source once
/// `include_str!` pulls the whole file in.
#[test]
fn probe_times_out_against_a_silent_black_hole_resolver() {
    let started = std::time::Instant::now();
    let result = resolve_with_timeout(Duration::from_millis(1), || {
        std::thread::sleep(Duration::from_millis(200));
        blocking_resolve("127.0.0.1:0")
    });
    let elapsed = started.elapsed();
    let err = result.expect_err("a resolver stuck past the timeout must not succeed");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        elapsed < Duration::from_millis(50),
        "resolve_with_timeout must return close to its 1ms timeout, not wait \
         out the 200ms sleeping resolver; took {elapsed:?}"
    );

    let call_site = format!(
        "resolve_with_timeout({}, move || blocking_resolve(&address))",
        "DOCTOR_PROBE_TIMEOUT"
    );
    assert_eq!(
        include_str!("../doctor.rs").matches(&call_site).count(),
        1,
        "resolve_probe_socket_addr must bound its resolve with \
         DOCTOR_PROBE_TIMEOUT, the same budget every other probe \
         already respects"
    );
}

#[test]
fn doctor_reports_controller_unreachable_for_a_dangling_controller_alias() {
    let (_guard, ops) = healthy_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().config_file(),
        "[reverse]\ncontroller = \"ctrl\"\n",
    )
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "controller_unreachable")
        .expect("controller_unreachable finding");
    assert_eq!(finding.status, "error");
    assert!(
        data.findings
            .iter()
            .all(|f| f.code != "no_route" && f.code != "udp_egress_blocked"),
        "precedence: a controller target must classify as controller_unreachable only"
    );
}

/// ROADMAP M9 (h) (`docs/CLI.md` §6.17): `doctor_connectivity_findings` reads
/// `[serve].to` before falling back to the legacy `[reverse].controller`
/// — the same precedence `infer_run_mode` uses (`doctor.rs`'s own doc on
/// `doctor_connectivity_findings`). With both set (and disagreeing, so
/// `config_serve_to_conflict` also fires — irrelevant to this test, which
/// only pins which alias gets probed), the probed alias must be
/// `[serve].to`'s.
#[test]
fn doctor_connectivity_probes_serve_to_before_the_legacy_reverse_controller() {
    let (_guard, ops) = healthy_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().config_file(),
        "[serve]\nto = \"serve-to-ctrl\"\n[reverse]\ncontroller = \"legacy-ctrl\"\n",
    )
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "controller_unreachable")
        .expect("controller_unreachable finding");
    assert!(
        finding.detail.contains("serve-to-ctrl"),
        "must probe [serve].to's alias: {finding:?}"
    );
    assert!(
        !finding.detail.contains("legacy-ctrl"),
        "must not probe the legacy alias once [serve].to is set: {finding:?}"
    );
}

/// ROADMAP M9 (h) (`docs/CLI.md` §6.17): with `[serve].to` unset, the legacy
/// `[reverse].controller` still drives connectivity probing exactly as
/// before this rename (ROADMAP M9 (b)) — this is the fallback half of the precedence pinned
/// above.
#[test]
fn doctor_connectivity_falls_back_to_the_legacy_reverse_controller_when_serve_to_is_unset() {
    let (_guard, ops) = healthy_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().config_file(),
        "[reverse]\ncontroller = \"legacy-ctrl\"\n",
    )
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "controller_unreachable")
        .expect("controller_unreachable finding");
    assert!(
        finding.detail.contains("legacy-ctrl"),
        "must fall back to probing the legacy alias: {finding:?}"
    );
}

// -----------------------------------------------------------------
// config_serve_to_conflict (ROADMAP M9 (h), ADR-0012 결정 5).
// -----------------------------------------------------------------

fn config_serve_to_conflict_findings(ops: &Ops) -> Vec<DoctorFinding> {
    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    data.findings
        .into_iter()
        .filter(|f| f.code == "config_serve_to_conflict")
        .collect()
}

#[test]
fn doctor_reports_config_serve_to_conflict_when_the_two_keys_disagree() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[serve]\nto = \"from-serve\"\n[reverse]\ncontroller = \"from-reverse\"\n",
    )
    .unwrap();

    let findings = config_serve_to_conflict_findings(&ops);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].status, "error");
    assert!(findings[0].detail.contains("from-serve"));
    assert!(findings[0].detail.contains("from-reverse"));
}

#[test]
fn doctor_does_not_report_config_serve_to_conflict_when_the_two_keys_agree() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[serve]\nto = \"same\"\n[reverse]\ncontroller = \"same\"\n",
    )
    .unwrap();

    assert!(config_serve_to_conflict_findings(&ops).is_empty());
}

#[test]
fn doctor_does_not_report_config_serve_to_conflict_when_only_one_key_is_set() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(ops.paths().config_file(), "[serve]\nto = \"from-serve\"\n").unwrap();
    assert!(config_serve_to_conflict_findings(&ops).is_empty());

    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[reverse]\ncontroller = \"from-reverse\"\n",
    )
    .unwrap();
    assert!(config_serve_to_conflict_findings(&ops).is_empty());
}

/// `doctor.run` always exits `0` (module doc) — a `config_serve_to_conflict`
/// finding is `status: "error"` (raising `overall` to `"error"`) but must
/// never turn into an `Err` from `Ops::doctor` itself, which is the
/// qsh-core-level half of that CLI-level guarantee.
#[test]
fn doctor_still_exits_zero_with_a_serve_to_conflict() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[serve]\nto = \"from-serve\"\n[reverse]\ncontroller = \"from-reverse\"\n",
    )
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .expect("doctor.run must still succeed with a serve_to conflict present");
    assert_eq!(data.overall, "error");
}

/// P3-4 (verify round): `req.host` naming the same peer as
/// `[reverse].controller` used to be probed twice — once via the
/// controller branch (`controller_unreachable`) and once via the
/// extra-host branch (`udp_egress_blocked`, since a non-controller
/// probe classifies differently) — reporting one failing target under
/// two contradictory codes at once. The extra-host branch must skip
/// its own probe once it recognizes the same target.
#[test]
fn doctor_probing_the_controller_alias_as_extra_host_reports_one_code_only() {
    let (_guard, ops) = healthy_ops();
    let black_hole = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let addr = black_hole.local_addr().unwrap();
    ops.trust_add(TrustAddReq {
        name: "ctrl".into(),
        address: Some(addr.to_string()),
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"ctrl").to_string()),
    })
    .unwrap();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().config_file(),
        "[reverse]\ncontroller = \"ctrl\"\n",
    )
    .unwrap();

    let data = ops
        .doctor(
            DoctorReq {
                host: Some("ctrl".to_string()),
            },
            SystemTime::now(),
        )
        .unwrap();
    let connectivity_codes: Vec<&str> = data
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.code.as_str(),
                "controller_unreachable" | "udp_egress_blocked" | "no_route"
            )
        })
        .map(|f| f.code.as_str())
        .collect();
    assert_eq!(
        connectivity_codes,
        vec!["controller_unreachable"],
        "the same target must not be reported under two different connectivity codes: {:?}",
        data.findings
    );
    drop(black_hole);
}

#[test]
fn doctor_with_an_unknown_extra_host_is_host_not_found() {
    let (_guard, ops) = healthy_ops();
    let err = ops
        .doctor(
            DoctorReq {
                host: Some("nowhere".to_string()),
            },
            SystemTime::now(),
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

#[test]
fn doctor_probes_a_pinned_extra_host_and_classifies_a_black_hole_as_udp_egress_blocked() {
    let (_guard, ops) = healthy_ops();
    let black_hole = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let addr = black_hole.local_addr().unwrap();
    ops.trust_add(TrustAddReq {
        name: "quiet".into(),
        address: Some(addr.to_string()),
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"quiet").to_string()),
    })
    .unwrap();

    let data = ops
        .doctor(
            DoctorReq {
                host: Some("quiet".to_string()),
            },
            SystemTime::now(),
        )
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "udp_egress_blocked")
        .expect("udp_egress_blocked finding");
    assert_eq!(finding.status, "error");
    drop(black_hole);
}

/// `no_route` — verify round P2-1, mutation `MC`
/// (`probe_address`'s `Err(_) => UdpProbeOutcome::Unreachable` branch
/// weakened to `TimedOut`). Rebuts design brief §C/§E-2's premise that
/// a real, OS-dependent socket is required to reach `no_route`: an
/// address whose port cannot be parsed fails
/// `resolve_probe_socket_addr`/`ToSocketAddrs::to_socket_addrs`'s
/// parse deterministically — no socket, no DNS, no OS dependency at
/// all.
///
/// The address used to be bare (`203.0.113.9`, no colon), which parsed
/// just as deterministically until M9 Step 1 (ADR-0014) made
/// `trust_add` fill the default port; a bare address now pins as
/// `203.0.113.9:4433`, resolves, and reaches the real UDP probe, which
/// is exactly the OS dependency this test exists to avoid. A non-numeric
/// port keeps the property, because `normalize_peer_address` passes a
/// colon it cannot read as a port through untouched — so this now also
/// pins that rule from the doctor side.
#[test]
fn doctor_reports_no_route_for_a_pinned_address_with_an_unparseable_port() {
    let (_guard, ops) = healthy_ops();
    ops.trust_add(TrustAddReq {
        name: "bad".into(),
        // `ToSocketAddrs` for `&str` splits at the last colon and parses
        // the remainder as a `u16`; `ssh` fails that parse before any
        // resolver runs, deterministically.
        address: Some("203.0.113.9:ssh".into()),
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"bad").to_string()),
    })
    .unwrap();

    let data = ops
        .doctor(
            DoctorReq {
                host: Some("bad".to_string()),
            },
            SystemTime::now(),
        )
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "no_route")
        .expect("no_route finding");
    assert_eq!(finding.status, "error", "{:?}", data.findings);
}

// -----------------------------------------------------------------
// status vocabulary — `DoctorFinding.status`/`DoctorData.overall` stay
// `String` (`docs/CLI.md` §10's open-string discipline), so nothing at
// the type level stops a stray value; this is the only thing that
// does (verify round P3-7).
// -----------------------------------------------------------------

#[test]
fn doctor_finding_status_is_always_one_of_the_locked_vocabulary() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    // No acl.toml at all (acl_policy_missing/error), an unpinned
    // hosts.toml entry (peer_untrusted/error), a dangling controller
    // alias (controller_unreachable/error), and one pinned peer
    // (trust_remove_scope/info) — enough findings in one report to
    // make this more than a vacuous pass.
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().hosts_file(),
        "[[host]]\nname = \"orphan\"\naddress = \"orphan.example:4433\"\n",
    )
    .unwrap();
    std::fs::write(
        ops.paths().config_file(),
        "[reverse]\ncontroller = \"ctrl\"\n",
    )
    .unwrap();
    ops.trust_add(TrustAddReq {
        name: "pinned".into(),
        address: Some("pinned.example:4433".into()),
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"vocab").to_string()),
    })
    .unwrap();

    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    assert!(
        !data.findings.is_empty(),
        "expected several findings to fire in this deliberately unhealthy setup"
    );
    for finding in &data.findings {
        assert!(
            matches!(finding.status.as_str(), "warn" | "error" | "info"),
            "unexpected status {:?} on finding {finding:?}",
            finding.status
        );
    }
    assert!(
        matches!(data.overall.as_str(), "ok" | "warn" | "error"),
        "unexpected overall {:?}",
        data.overall
    );
}

// -----------------------------------------------------------------
// Operation::COMMAND + overall_status
// -----------------------------------------------------------------

#[test]
fn doctor_op_command_is_dotted_form() {
    assert_eq!(DoctorOp::COMMAND, "doctor.run");
}

#[test]
fn overall_status_is_worst_of_error_warn_ok() {
    let error = DoctorFinding {
        code: "x".into(),
        status: "error".into(),
        detail: "d".into(),
        remedy: None,
    };
    let warn = DoctorFinding {
        code: "y".into(),
        status: "warn".into(),
        detail: "d".into(),
        remedy: None,
    };
    let info = DoctorFinding {
        code: "z".into(),
        status: "info".into(),
        detail: "d".into(),
        remedy: None,
    };
    assert_eq!(overall_status(&[]), "ok");
    assert_eq!(overall_status(std::slice::from_ref(&info)), "ok");
    assert_eq!(overall_status(&[info.clone(), warn.clone()]), "warn");
    assert_eq!(overall_status(&[info, warn, error]), "error");
}

// -----------------------------------------------------------------
// config_unknown_key (`PLAN.md` M8 Step 4b, J10).
// -----------------------------------------------------------------

fn config_unknown_key_findings(ops: &Ops) -> Vec<DoctorFinding> {
    let data = ops
        .doctor(DoctorReq { host: None }, SystemTime::now())
        .unwrap();
    data.findings
        .into_iter()
        .filter(|f| f.code == "config_unknown_key")
        .collect()
}

#[test]
fn doctor_reports_config_unknown_key_for_a_typo_d_key_in_a_known_section() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(ops.paths().config_file(), "[serve]\nmx_sessions = 4\n").unwrap();

    let findings = config_unknown_key_findings(&ops);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].status, "warn");
    assert!(
        findings[0].detail.contains("serve.mx_sessions"),
        "{:?}",
        findings[0]
    );
}

#[test]
fn doctor_reports_config_unknown_key_for_a_typo_d_section_name() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(ops.paths().config_file(), "[serv]\nbind = \"[::]:1\"\n").unwrap();

    let findings = config_unknown_key_findings(&ops);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].detail.contains("serv.bind"),
        "{:?}",
        findings[0]
    );
}

#[test]
fn doctor_reports_config_unknown_key_for_a_typo_d_key_nested_in_a_known_section() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[reverse]\nbackoff_initial_m = 5\n",
    )
    .unwrap();

    let findings = config_unknown_key_findings(&ops);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].detail.contains("reverse.backoff_initial_m"),
        "{:?}",
        findings[0]
    );
}

#[test]
fn doctor_reports_no_config_unknown_key_when_every_key_is_recognized() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[serve]\nmax_sessions_per_principal = 4\n\n[reverse]\ncontroller = \"ctrl\"\n",
    )
    .unwrap();

    assert!(config_unknown_key_findings(&ops).is_empty());
}

/// A-P1-1/B-P1-3 (4b adversarial round): `ServeConfig::resume_ttl` is
/// documented (`config.rs`) to accept `resume_ttl_secs` as a
/// `#[serde(alias)]`. `Serialize` never re-emits that alias — only
/// the canonical `resume_ttl` — so a naive present/known leaf-path
/// diff flags it as unknown even though it is fully recognized and
/// applied. This test fixes both halves at once: no finding, and
/// (loaded the real way, not through this probe) the alias actually
/// set the TTL.
#[test]
fn doctor_reports_no_config_unknown_key_for_the_documented_resume_ttl_alias() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[serve]\nresume_ttl_secs = 3600\n",
    )
    .unwrap();

    assert!(config_unknown_key_findings(&ops).is_empty());
    let config = Config::load(ops.paths()).unwrap();
    assert_eq!(config.serve.resume_ttl(), Duration::from_secs(3600));
}

/// The alias filter must not swallow an unrelated typo sitting next
/// to it in the same file — `accepted_under_another_name` is a
/// per-candidate probe, not a blanket "this section is fine" switch.
#[test]
fn doctor_reports_config_unknown_key_for_a_typo_next_to_a_recognized_alias() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(
        ops.paths().config_file(),
        "[serve]\nresume_ttl_secs = 3600\nmax_sesions_per_principal = 4\n",
    )
    .unwrap();

    let findings = config_unknown_key_findings(&ops);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0]
            .detail
            .contains("serve.max_sesions_per_principal"),
        "{:?}",
        findings[0]
    );
}

/// B-P2-4 (4b adversarial round): the module doc on
/// [`Ops::doctor_config_unknown_key_findings`] promises that a
/// config.toml which fails to parse as *any* TOML (e.g. clobbered by
/// a concurrent edit after `Config::load` already succeeded) is
/// "nothing to compare", not a second error source. Calls the
/// private probe directly with a malformed file, bypassing
/// `Ops::doctor`'s own `Config::load` (which would fail first on the
/// same input and never reach this method in practice).
#[test]
fn doctor_config_unknown_key_findings_is_empty_for_malformed_config_toml() {
    let (_guard, ops) = healthy_ops();
    std::fs::write(ops.paths().config_file(), "[serve\nthis = = broken\n").unwrap();

    let findings = ops.doctor_config_unknown_key_findings(&Config::default());
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn doctor_reports_no_config_unknown_key_when_config_toml_is_absent() {
    let (_guard, ops) = healthy_ops();
    // `healthy_ops` never writes a config.toml — `Config::load`
    // already yields `Config::default()` for a missing file
    // (`crate::config::Config::load`'s own doc), so there is nothing
    // for this probe to compare against.
    assert!(!ops.paths().config_file().exists());

    assert!(config_unknown_key_findings(&ops).is_empty());
}

/// B-P2-3 (4b adversarial round): a true lockstep in both directions,
/// not a one-way `contains` check. `ServeConfig` is built as a
/// struct literal with every field set to `Some(..)` and no
/// `..Default::default()` spread — if a field is ever added to
/// `ServeConfig`, this literal fails to compile until the new field
/// is named here too, and the expected set below is updated to
/// match. `toml`'s `Serialize` omits an `Option::None` field
/// entirely (no TOML `null`), which is why every field must be
/// `Some`: a `None` silently vanishes from `serve.*` on the
/// serialized side rather than producing a leaf to compare, and
/// would let a renamed/removed field escape detection.
/// [`toml::Value::try_from`] then round-trips the same way
/// [`Ops::doctor_config_unknown_key_findings`] does, and the
/// resulting `serve.*` leaf-path set must equal the hard-coded
/// expectation exactly — `assert_eq!` on two `BTreeSet`s, not
/// `contains`, so a name change (not just a field count change) also
/// fails this test.
#[test]
fn known_leaf_paths_round_trip_covers_every_serve_cap_key() {
    const ALL_SERVE_KEYS: [&str; 17] = [
        "bind",
        "to",
        "replay_bytes",
        "resume_ttl",
        "close_grace_ms",
        "max_concurrent_handshakes",
        "handshake_rate_per_source",
        "max_sessions",
        "max_sessions_per_principal",
        "max_exec_per_principal",
        "validated_rate_per_source",
        "max_exec",
        "max_tunnel_streams_per_principal",
        "max_tunnel_streams_per_forward",
        "max_remote_forwards_per_principal",
        "max_connections_per_principal",
        "max_connections",
    ];
    let serve = crate::config::ServeConfig {
        bind: Some("[::]:4433".to_string()),
        to: Some("personal-mac".to_string()),
        replay_bytes: Some(1),
        resume_ttl: Some(2),
        close_grace_ms: Some(3),
        max_concurrent_handshakes: Some(4),
        handshake_rate_per_source: Some(5),
        max_sessions: Some(6),
        max_sessions_per_principal: Some(7),
        max_exec_per_principal: Some(8),
        validated_rate_per_source: Some(9),
        max_exec: Some(10),
        max_tunnel_streams_per_principal: Some(11),
        max_tunnel_streams_per_forward: Some(12),
        max_remote_forwards_per_principal: Some(13),
        max_connections_per_principal: Some(14),
        max_connections: Some(15),
    };
    let config = Config {
        serve,
        ..Default::default()
    };
    let value = toml::Value::try_from(&config).unwrap();
    let mut known = std::collections::BTreeSet::new();
    collect_leaf_paths(&value, String::new(), &mut known);

    let serve_paths: std::collections::BTreeSet<&str> = known
        .iter()
        .filter_map(|p| p.strip_prefix("serve."))
        .collect();
    let expected: std::collections::BTreeSet<&str> = ALL_SERVE_KEYS.into_iter().collect();
    assert_eq!(serve_paths, expected);
}

// ===================================================================
// ROADMAP M9 (h): seven new diagnostics.
// ===================================================================

// -----------------------------------------------------------------
// infer_run_mode — the shared mode inference `service_not_registered`/
// `bindv6only_blocks_ipv4` both key off.
// -----------------------------------------------------------------

#[test]
fn infer_run_mode_prefers_listen_then_reverse_then_defaults_to_serve() {
    let mut config = Config::default();
    assert_eq!(infer_run_mode(&config), "serve");

    config.reverse.controller = Some("ctrl".to_string());
    assert_eq!(infer_run_mode(&config), "reverse");

    // `[listen]` present (any field set) wins outright, even over an
    // already-set `[reverse].controller` (`infer_run_mode`'s own precedence).
    config.listen.allow_advertised_names = true;
    assert_eq!(infer_run_mode(&config), "listen");
}

/// ROADMAP M9 (h): `[serve].to` sits between `[listen]` and the legacy
/// `[reverse].controller` in `infer_run_mode`'s precedence — both outbound
/// keys map to the same `"reverse"` token today (`infer_run_mode` is an
/// OR over the two, `ops/doctor.rs:690`), so this asserted `"reverse"`
/// holds whichever key `infer_run_mode` actually consults, disagreeing or
/// not; only the trailing `[listen]`-wins assertion below is load-bearing
/// against a mutation of this function. The distinct token that would
/// make the two keys' precedence itself observable is the `qsh service`
/// step's job (ROADMAP M9); this test's name records the eventual contract this
/// function documents, not a precedence this run of it can fail on yet.
#[test]
fn infer_run_mode_prefers_serve_to_over_the_legacy_controller() {
    let mut config = Config::default();
    config.reverse.controller = Some("legacy-ctrl".to_string());
    config.serve.to = Some("new-ctrl".to_string());
    assert_eq!(infer_run_mode(&config), "reverse");

    // `[listen]` still wins outright over both outbound keys.
    config.listen.allow_advertised_names = true;
    assert_eq!(infer_run_mode(&config), "listen");
}

/// Either outbound key alone is enough to infer `"reverse"` — the new
/// `[serve].to` key is additive, not a replacement for the legacy one.
#[test]
fn infer_run_mode_treats_either_outbound_key_as_reverse() {
    let mut only_serve_to = Config::default();
    only_serve_to.serve.to = Some("ctrl".to_string());
    assert_eq!(infer_run_mode(&only_serve_to), "reverse");

    let mut only_legacy = Config::default();
    only_legacy.reverse.controller = Some("ctrl".to_string());
    assert_eq!(infer_run_mode(&only_legacy), "reverse");
}

/// A CA to add to `trust.toml` for the `acl_ca_auth_path_missing` tests
/// below — content is never parsed as a real certificate by anything
/// this test touches, only counted (`TrustStore::cas().is_empty()`).
fn add_stub_ca(ops: &Ops, name: &str) {
    let mut store = TrustStore::load(&ops.paths().trust_file()).unwrap_or_default();
    store.add_ca(
        name,
        "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n".to_string(),
    );
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    store.save(&ops.paths().trust_file()).unwrap();
}

// -----------------------------------------------------------------
// service_not_registered / systemd_linger_disabled /
// launchagent_session_scoped — the injected-environment seam
// (`env.home_dir`/`env.linger_dir`/`env.username`).
// -----------------------------------------------------------------

#[test]
fn doctor_service_registration_findings_reports_not_registered_when_home_has_no_unit_file() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let home = tempfile::tempdir().unwrap();
    let env = DoctorEnvironment {
        home_dir: Some(home.path()),
        ..minimal_env(&keystore)
    };

    let findings = ops.doctor_service_registration_findings("listen", &env);
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        assert_eq!(findings.len(), 1, "{findings:?}");
        let finding = &findings[0];
        assert_eq!(finding.code, "service_not_registered");
        assert_eq!(finding.status, "info");
        assert!(finding.detail.contains("listen"), "{finding:?}");
    } else {
        assert!(findings.is_empty(), "{findings:?}");
    }
}

/// `None` `home_dir` (the real environment's own "could not even build
/// the path" case) is silent everywhere — portable, no platform cfg
/// needed: [`probe::service_unit_registered`] returns `None` on macOS/
/// Linux too once `home` is `None`.
#[test]
fn doctor_service_registration_findings_is_silent_with_no_home_dir() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let env = minimal_env(&keystore);
    assert!(
        ops.doctor_service_registration_findings("serve", &env)
            .is_empty()
    );
}

/// Off macOS/Linux, `service_unit_registered` is unconditionally `None`
/// (`infer_run_mode` never runs off macOS/Linux) — an injected `home_dir` that *would* trigger
/// `service_not_registered` on macOS/Linux must still report nothing
/// here.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn doctor_service_registration_findings_is_always_silent_off_macos_and_linux() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let home = tempfile::tempdir().unwrap();
    let env = DoctorEnvironment {
        home_dir: Some(home.path()),
        ..minimal_env(&keystore)
    };
    assert!(
        ops.doctor_service_registration_findings("serve", &env)
            .is_empty()
    );
}

/// Once the unit file is registered, `service_not_registered` must not
/// also fire — `systemd_linger_disabled`/`launchagent_session_scoped`
/// take over instead (`crate::doctor::SYSTEMD_LINGER_DISABLED`'s own
/// "only reachable once a unit IS registered" doc).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn doctor_service_registration_findings_is_silent_on_service_not_registered_once_the_unit_exists() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let home = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    let unit_path = probe::macos_launchagent_path(home.path(), "serve");
    #[cfg(target_os = "linux")]
    let unit_path = probe::linux_systemd_user_unit_path(home.path(), "serve");
    std::fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
    std::fs::write(&unit_path, b"stub").unwrap();

    let env = DoctorEnvironment {
        home_dir: Some(home.path()),
        username: Some("m9-step4-test-account"),
        ..minimal_env(&keystore)
    };
    let findings = ops.doctor_service_registration_findings("serve", &env);
    assert!(
        findings.iter().all(|f| f.code != "service_not_registered"),
        "a registered unit must not also report service_not_registered: {findings:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_service_registration_findings_reports_launchagent_session_scoped_once_registered() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let home = tempfile::tempdir().unwrap();
    let unit_path = probe::macos_launchagent_path(home.path(), "serve");
    std::fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
    std::fs::write(&unit_path, b"stub").unwrap();

    let env = DoctorEnvironment {
        home_dir: Some(home.path()),
        ..minimal_env(&keystore)
    };
    let findings = ops.doctor_service_registration_findings("serve", &env);
    let finding = findings
        .iter()
        .find(|f| f.code == "launchagent_session_scoped")
        .expect("launchagent_session_scoped finding");
    assert_eq!(finding.status, "warn");
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_service_registration_findings_reports_systemd_linger_disabled_once_registered() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let home = tempfile::tempdir().unwrap();
    let unit_path = probe::linux_systemd_user_unit_path(home.path(), "serve");
    std::fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
    std::fs::write(&unit_path, b"stub").unwrap();
    let linger_dir = tempfile::tempdir().unwrap();
    // No marker file for this account: `try_exists` on the missing leaf
    // is deterministically `Ok(false)` (`probe::LingerProbe`'s own
    // doc), never an error, so this observes `Disabled`, not `Unknown`.

    let env = DoctorEnvironment {
        home_dir: Some(home.path()),
        linger_dir: linger_dir.path(),
        username: Some("m9-step4-test-account"),
        ..minimal_env(&keystore)
    };
    let findings = ops.doctor_service_registration_findings("serve", &env);
    let finding = findings
        .iter()
        .find(|f| f.code == "systemd_linger_disabled")
        .expect("systemd_linger_disabled finding");
    assert_eq!(finding.status, "warn");
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_service_registration_findings_is_silent_once_linger_is_enabled() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let home = tempfile::tempdir().unwrap();
    let unit_path = probe::linux_systemd_user_unit_path(home.path(), "serve");
    std::fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
    std::fs::write(&unit_path, b"stub").unwrap();
    let linger_dir = tempfile::tempdir().unwrap();
    std::fs::write(linger_dir.path().join("m9-step4-test-account"), b"").unwrap();

    let env = DoctorEnvironment {
        home_dir: Some(home.path()),
        linger_dir: linger_dir.path(),
        username: Some("m9-step4-test-account"),
        ..minimal_env(&keystore)
    };
    let findings = ops.doctor_service_registration_findings("serve", &env);
    assert!(
        findings.iter().all(|f| f.code != "systemd_linger_disabled"),
        "{findings:?}"
    );
}

/// Wiring (mutation check: deleting the wiring line reds this test): goes through
/// [`Ops::doctor_assemble`] itself with an injected environment, the
/// real code path `Ops::doctor` calls — the same discipline
/// `doctor_wires_the_keystore_finding_into_the_full_report_deterministically`
/// already establishes. Deleting `doctor_assemble`'s
/// `findings.extend(self.doctor_service_registration_findings(mode, env))`
/// line reds this test on macOS/Linux (the two platforms this repo's
/// CI actually runs `cargo nextest run --workspace` on).
#[test]
fn doctor_wires_the_service_not_registered_finding_into_the_full_report_deterministically() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    let keystore = crate::identity::MemoryKeyStore::new();
    let home = tempfile::tempdir().unwrap();
    let env = DoctorEnvironment {
        home_dir: Some(home.path()),
        ..minimal_env(&keystore)
    };

    let data = ops
        .doctor_assemble(
            DoctorReq { host: None },
            unix_seconds(SystemTime::now()),
            &identity,
            &config,
            &env,
        )
        .unwrap();
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        assert!(
            data.findings
                .iter()
                .any(|f| f.code == "service_not_registered"),
            "{:?}",
            data.findings
        );
    }
}

// -----------------------------------------------------------------
// bindv6only_blocks_ipv4 — classifier already covered by
// `probe::tests`; this is the wiring layer, deterministic via
// `env.bindv6only_probe`.
// -----------------------------------------------------------------

#[test]
fn doctor_bindv6only_finding_fires_for_the_default_wildcard_bind_when_the_probe_reports_v6_only() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let config = Config::default();
    let env = DoctorEnvironment {
        bindv6only_probe: always_v6_only,
        ..minimal_env(&keystore)
    };

    let finding = ops
        .doctor_bindv6only_finding(&config, "serve", &env)
        .expect("bindv6only_blocks_ipv4 finding");
    assert_eq!(finding.code, "bindv6only_blocks_ipv4");
    assert_eq!(finding.status, "warn");
}

#[test]
fn doctor_bindv6only_finding_is_none_when_the_probe_reports_dual_stack() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let config = Config::default();
    let env = minimal_env(&keystore);
    assert!(
        ops.doctor_bindv6only_finding(&config, "serve", &env)
            .is_none()
    );
}

/// A non-wildcard bind is never probed at all, even with a stub that
/// would otherwise fire — [`probe::is_ipv6_wildcard`]'s own gate.
#[test]
fn doctor_bindv6only_finding_is_none_for_a_non_wildcard_bind() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let mut config = Config::default();
    config.serve.bind = Some("127.0.0.1:4433".to_string());
    let env = DoctorEnvironment {
        bindv6only_probe: always_v6_only,
        ..minimal_env(&keystore)
    };
    assert!(
        ops.doctor_bindv6only_finding(&config, "serve", &env)
            .is_none()
    );
}

/// `listen` mode reads `[listen].bind`, not `[serve].bind`.
#[test]
fn doctor_bindv6only_finding_reads_the_listen_bind_for_listen_mode() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let mut config = Config::default();
    config.serve.bind = Some("127.0.0.1:4433".to_string());
    config.listen.bind = Some("[::]:4433".to_string());
    let env = DoctorEnvironment {
        bindv6only_probe: always_v6_only,
        ..minimal_env(&keystore)
    };
    let finding = ops
        .doctor_bindv6only_finding(&config, "listen", &env)
        .expect("bindv6only_blocks_ipv4 finding");
    assert_eq!(finding.code, "bindv6only_blocks_ipv4");
}

/// `qsh reverse` dials out and binds no listener at all — falling
/// through to `serve`'s bind resolution here would report a listener
/// problem for a host that never opens one.
#[test]
fn doctor_bindv6only_finding_is_none_for_reverse_mode_even_with_a_wildcard_serve_bind() {
    let keystore = crate::identity::MemoryKeyStore::new();
    let (_guard, ops) = healthy_ops();
    let mut config = Config::default();
    config.serve.bind = Some("[::]:4433".to_string());
    let env = DoctorEnvironment {
        bindv6only_probe: always_v6_only,
        ..minimal_env(&keystore)
    };
    assert!(
        ops.doctor_bindv6only_finding(&config, "reverse", &env)
            .is_none()
    );
}

/// Wiring (mutation check) — deleting `doctor_assemble`'s
/// `findings.extend(self.doctor_bindv6only_finding(config, mode, env))`
/// line reds this test unconditionally (unlike the service-registration
/// wiring test above, this one needs no platform gate: the stub makes
/// it deterministic on every OS `cargo nextest run --workspace` runs
/// on).
#[test]
fn doctor_wires_the_bindv6only_finding_into_the_full_report_deterministically() {
    let (_guard, ops) = healthy_ops();
    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    let keystore = crate::identity::MemoryKeyStore::new();
    let env = DoctorEnvironment {
        bindv6only_probe: always_v6_only,
        ..minimal_env(&keystore)
    };

    let data = ops
        .doctor_assemble(
            DoctorReq { host: None },
            unix_seconds(SystemTime::now()),
            &identity,
            &config,
            &env,
        )
        .unwrap();
    assert!(
        data.findings
            .iter()
            .any(|f| f.code == "bindv6only_blocks_ipv4"),
        "{:?}",
        data.findings
    );
}

// -----------------------------------------------------------------
// acl_principal_unmatched / acl_ca_auth_path_missing (ADR-0017 결정 2).
// -----------------------------------------------------------------

#[test]
fn doctor_acl_findings_reports_acl_principal_unmatched_for_an_unmatched_pin() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"mac").to_string()),
    })
    .unwrap();

    let findings = ops.doctor_acl_findings("serve").unwrap();
    let finding = findings
        .iter()
        .find(|f| f.code == "acl_principal_unmatched")
        .expect("acl_principal_unmatched finding");
    assert_eq!(finding.status, "error");
    assert!(finding.detail.contains("mac"), "{finding:?}");
}

/// `detail` (not `remedy` — `docs/CLI.md` §6.17's "실행 가능한 다음 행동 한
/// 줄" keeps `remedy` to one line) carries a real copy-pasteable `[[acl]]`
/// row naming this machine's actual unmatched peer, role-aware:
/// `exec.run` for `serve`, `host.reverse` for `listen`, never both — and,
/// with a second, already-matched peer pinned alongside it, names only
/// the unmatched one, not every pinned peer.
#[test]
fn doctor_acl_findings_acl_principal_unmatched_detail_carries_a_role_aware_example_row() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().acl_file(),
        "[[acl]]\nprincipal = \"device:other\"\nallow = [\"exec.run\"]\n",
    )
    .unwrap();
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"mac").to_string()),
    })
    .unwrap();
    ops.trust_add(TrustAddReq {
        name: "other".into(),
        address: None,
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"other").to_string()),
    })
    .unwrap();

    let serve_finding = ops
        .doctor_acl_findings("serve")
        .unwrap()
        .into_iter()
        .find(|f| f.code == "acl_principal_unmatched")
        .expect("acl_principal_unmatched finding");
    assert!(
        serve_finding.remedy.as_deref() == Some(ACL_PRINCIPAL_UNMATCHED.remedy),
        "{:?}",
        serve_finding.remedy
    );
    let serve_detail = serve_finding.detail;
    assert!(serve_detail.contains("[[acl]]"), "{serve_detail}");
    assert!(serve_detail.contains("device:mac"), "{serve_detail}");
    assert!(serve_detail.contains("exec.run"), "{serve_detail}");
    assert!(!serve_detail.contains("host.reverse"), "{serve_detail}");
    assert!(
        !serve_detail.contains("device:other"),
        "the example row must name only the unmatched peer: {serve_detail}"
    );

    let listen_detail = ops
        .doctor_acl_findings("listen")
        .unwrap()
        .into_iter()
        .find(|f| f.code == "acl_principal_unmatched")
        .expect("acl_principal_unmatched finding")
        .detail;
    assert!(listen_detail.contains("host.reverse"), "{listen_detail}");
    assert!(!listen_detail.contains("exec.run"), "{listen_detail}");
}

#[test]
fn doctor_acl_findings_is_silent_when_a_pin_path_row_names_the_device() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().acl_file(),
        "[[acl]]\nprincipal = \"device:mac\"\nallow = [\"exec.run\"]\n",
    )
    .unwrap();
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"mac").to_string()),
    })
    .unwrap();

    let findings = ops.doctor_acl_findings("serve").unwrap();
    assert!(
        findings.iter().all(|f| f.code != "acl_principal_unmatched"),
        "{findings:?}"
    );
}

/// The other candidate [`crate::acl::PinnedPrincipalIndex::names_fingerprint`]
/// checks — a row naming `fp:sha256:<...>` also counts as matched, not
/// only `device:<name>`.
#[test]
fn doctor_acl_findings_is_silent_when_a_pin_path_row_names_the_fingerprint() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"mac").to_string();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().acl_file(),
        format!("[[acl]]\nprincipal = \"fp:{fingerprint}\"\nallow = [\"exec.run\"]\n"),
    )
    .unwrap();
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(fingerprint.clone()),
    })
    .unwrap();

    let findings = ops.doctor_acl_findings("serve").unwrap();
    assert!(
        findings.iter().all(|f| f.code != "acl_principal_unmatched"),
        "{findings:?}"
    );
}

#[test]
fn doctor_acl_findings_reports_acl_ca_auth_path_missing_when_no_row_sets_ca() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
    add_stub_ca(&ops, "corp-ca");

    let findings = ops.doctor_acl_findings("serve").unwrap();
    let finding = findings
        .iter()
        .find(|f| f.code == "acl_ca_auth_path_missing")
        .expect("acl_ca_auth_path_missing finding");
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("[[acl]]"), "{finding:?}");
    assert!(finding.detail.contains("auth_path = \"ca\""), "{finding:?}");
    assert!(
        finding.remedy.as_deref() == Some(ACL_CA_AUTH_PATH_MISSING.remedy),
        "{:?}",
        finding.remedy
    );
}

#[test]
fn doctor_acl_findings_is_silent_when_a_row_sets_auth_path_ca() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().acl_file(),
        "[[acl]]\nprincipal = \"device:x\"\nauth_path = \"ca\"\nallow = [\"exec.run\"]\n",
    )
    .unwrap();
    add_stub_ca(&ops, "corp-ca");

    let findings = ops.doctor_acl_findings("serve").unwrap();
    assert!(
        findings
            .iter()
            .all(|f| f.code != "acl_ca_auth_path_missing"),
        "{findings:?}"
    );
}

#[test]
fn doctor_acl_findings_is_silent_about_ca_auth_path_with_no_ca_entries_at_all() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();

    let findings = ops.doctor_acl_findings("serve").unwrap();
    assert!(
        findings
            .iter()
            .all(|f| f.code != "acl_ca_auth_path_missing"),
        "{findings:?}"
    );
}

/// Both new checks only run once `acl.toml` actually loaded — a missing
/// policy already reports `acl_policy_missing` and must not also pile
/// on `acl_principal_unmatched`/`acl_ca_auth_path_missing` noise for
/// data an unloaded `PinnedPrincipalIndex::empty()` cannot actually
/// speak to.
#[test]
fn doctor_acl_findings_skips_the_new_checks_when_the_policy_failed_to_load() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    add_stub_ca(&ops, "corp-ca");
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"mac").to_string()),
    })
    .unwrap();
    // No acl.toml at all: `PolicyLoad::Missing`.

    let findings = ops.doctor_acl_findings("serve").unwrap();
    assert!(findings.iter().any(|f| f.code == "acl_policy_missing"));
    assert!(
        findings.iter().all(|f| f.code != "acl_principal_unmatched"),
        "{findings:?}"
    );
    assert!(
        findings
            .iter()
            .all(|f| f.code != "acl_ca_auth_path_missing"),
        "{findings:?}"
    );
}

/// ADR-0017 결정 2: a `listen` role's minimal-policy example names
/// `host.reverse`, not `serve`'s five session/exec actions — checked
/// through the public surface (the embedded `StartupDiagnostic::render`
/// text in `acl_policy_missing`'s own `detail`) rather than reaching
/// into `acl::load`'s private `minimal_policy_example`.
#[test]
fn doctor_acl_findings_minimal_policy_example_is_role_aware() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    // No acl.toml: both calls hit `PolicyLoad::Missing`, embedding a
    // fresh example each time.

    let serve_finding = ops
        .doctor_acl_findings("serve")
        .unwrap()
        .into_iter()
        .find(|f| f.code == "acl_policy_missing")
        .expect("acl_policy_missing finding");
    assert!(
        serve_finding.detail.contains("exec.run"),
        "{serve_finding:?}"
    );
    assert!(
        !serve_finding.detail.contains("host.reverse"),
        "{serve_finding:?}"
    );

    let listen_finding = ops
        .doctor_acl_findings("listen")
        .unwrap()
        .into_iter()
        .find(|f| f.code == "acl_policy_missing")
        .expect("acl_policy_missing finding");
    assert!(
        listen_finding.detail.contains("host.reverse"),
        "{listen_finding:?}"
    );
    assert!(
        !listen_finding.detail.contains("exec.run"),
        "{listen_finding:?}"
    );
}

/// ADR-0017 결정 2's restart clause ("verbatim in spirit").
#[test]
fn acl_principal_unmatched_and_ca_auth_path_missing_remedies_mention_restart() {
    assert!(
        crate::doctor::ACL_PRINCIPAL_UNMATCHED
            .remedy
            .contains("restart")
    );
    assert!(
        crate::doctor::ACL_CA_AUTH_PATH_MISSING
            .remedy
            .contains("restart")
    );
}

/// Wiring (mutation check): deleting `doctor_assemble`'s
/// `findings.extend(self.doctor_acl_findings(mode)?)` line reds this
/// test. Goes through `doctor_assemble` with an injected environment
/// (the same discipline
/// `doctor_wires_the_service_not_registered_finding_into_the_full_report_deterministically`
/// already establishes) rather than the real `Ops::doctor`, even though
/// neither new ACL check itself reads `DoctorEnvironment`: the full
/// pipeline still runs every other probe (`bindv6only_probe`'s real UDP
/// bind included), so this keeps the test hermetic rather than merely
/// "happens not to care about the result".
#[test]
fn doctor_wires_the_acl_principal_and_ca_findings_into_the_full_report() {
    let (_guard, ops) = temp_ops();
    init_identity(&ops);
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(ops.paths().acl_file(), minimal_acl_toml()).unwrap();
    add_stub_ca(&ops, "corp-ca");
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"mac").to_string()),
    })
    .unwrap();

    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    let keystore = crate::identity::MemoryKeyStore::new();
    let data = ops
        .doctor_assemble(
            DoctorReq { host: None },
            unix_seconds(SystemTime::now()),
            &identity,
            &config,
            &minimal_env(&keystore),
        )
        .unwrap();
    assert!(
        data.findings
            .iter()
            .any(|f| f.code == "acl_principal_unmatched"),
        "{:?}",
        data.findings
    );
    assert!(
        data.findings
            .iter()
            .any(|f| f.code == "acl_ca_auth_path_missing"),
        "{:?}",
        data.findings
    );
}

// -----------------------------------------------------------------
// host_pinned_without_address — pure-function coverage lives in
// `crate::ops::host::tests` (`host_pinned_without_address_*`); this is
// only the doctor-side wiring.
// -----------------------------------------------------------------

/// Wiring (mutation check): deleting `doctor_assemble`'s
/// `findings.extend(self.doctor_pinned_no_address_findings()?)` line
/// reds this test.
#[test]
fn doctor_wires_the_host_pinned_without_address_finding_into_the_full_report() {
    let (_guard, ops) = healthy_ops();
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"mac").to_string()),
    })
    .unwrap();

    let identity = ops.load_identity().unwrap().unwrap().identity;
    let config = ops.config().unwrap();
    let keystore = crate::identity::MemoryKeyStore::new();
    let data = ops
        .doctor_assemble(
            DoctorReq { host: None },
            unix_seconds(SystemTime::now()),
            &identity,
            &config,
            &minimal_env(&keystore),
        )
        .unwrap();
    let finding = data
        .findings
        .iter()
        .find(|f| f.code == "host_pinned_without_address")
        .expect("host_pinned_without_address finding");
    assert_eq!(finding.status, "warn");
    assert!(finding.detail.contains("mac"), "{finding:?}");
    assert!(
        finding.remedy.as_deref().unwrap().contains("trust add mac"),
        "{finding:?}"
    );
}
