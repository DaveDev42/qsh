use super::*;

fn temp_paths() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, paths)
}

#[test]
fn init_creates_then_is_idempotent() {
    let (_guard, paths) = temp_paths();

    let first = init(&paths, KeyStoreMode::File).unwrap();
    assert!(first.created);
    assert_eq!(first.key_store, KeyStoreKind::File);
    assert!(first.device_id.starts_with("device_"));
    assert!(first.fingerprint.parse::<Fingerprint>().is_ok());
    assert!(paths.identity_dir().join(CERT_FILE).is_file());
    assert!(paths.identity_dir().join(KEY_FILE).is_file());
    assert!(paths.identity_dir().join(IDENTITY_FILE).is_file());

    let second = init(&paths, KeyStoreMode::File).unwrap();
    assert!(!second.created);
    assert_eq!(second.device_id, first.device_id);
    assert_eq!(second.fingerprint, first.fingerprint);
    assert_eq!(second.key_store, first.key_store);
    assert_eq!(second.config_dir, first.config_dir);
}

#[test]
fn init_reports_an_absolute_config_dir() {
    let (_guard, paths) = temp_paths();
    let data = init(&paths, KeyStoreMode::File).unwrap();
    assert!(Path::new(&data.config_dir).is_absolute(), "{data:?}");
}

#[test]
fn load_returns_none_before_init_and_the_identity_after() {
    let (_guard, paths) = temp_paths();
    assert!(load(&paths).unwrap().is_none());

    let created = init(&paths, KeyStoreMode::File).unwrap();
    let loaded = load(&paths).unwrap().expect("identity after init");
    assert_eq!(loaded.identity.device_id, created.device_id);
    assert_eq!(loaded.identity.fingerprint.to_string(), created.fingerprint);
    assert_eq!(loaded.local.cert_chain.len(), 1);
    assert!(!loaded.local.key_pkcs8_der.is_empty());
}

#[test]
fn generated_certificate_carries_the_device_san_and_a_ten_year_window() {
    let (_guard, paths) = temp_paths();
    let data = init(&paths, KeyStoreMode::File).unwrap();
    let identity = read_identity(&paths).unwrap().unwrap();

    let principal = qsh_transport::identity::principal_from_san(&identity.cert_der)
        .unwrap()
        .expect("device SAN");
    assert_eq!(
        principal,
        qsh_transport::Principal::Device(data.device_id.clone())
    );

    let (not_before, not_after) =
        qsh_transport::identity::validity_unix(&identity.cert_der).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!(not_before < now, "certificate must be backdated");
    let years = (not_after - now) as f64 / (365.25 * 86_400.0);
    assert!((9.0..=10.5).contains(&years), "validity was {years} years");
}

#[test]
fn a_missing_key_is_an_internal_error_not_a_panic() {
    let (_guard, paths) = temp_paths();
    init(&paths, KeyStoreMode::File).unwrap();
    std::fs::remove_file(paths.identity_dir().join(KEY_FILE)).unwrap();

    let err = load(&paths).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.message.contains("identity key missing"), "{err}");
    assert!(!err.retryable);
}

#[test]
fn a_corrupt_identity_record_is_a_config_error() {
    let (_guard, paths) = temp_paths();
    init(&paths, KeyStoreMode::File).unwrap();
    std::fs::write(paths.identity_dir().join(IDENTITY_FILE), "not = [toml").unwrap();
    let err = read_identity(&paths).unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
}

#[cfg(unix)]
#[test]
fn identity_directory_and_files_are_private() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_guard, paths) = temp_paths();
    init(&paths, KeyStoreMode::File).unwrap();

    let mode_of =
        |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode_of(paths.identity_dir()), 0o700);
    assert_eq!(mode_of(paths.identity_dir().join(KEY_FILE)), 0o600);
    assert_eq!(mode_of(paths.identity_dir().join(CERT_FILE)), 0o600);
    assert_eq!(mode_of(paths.identity_dir().join(IDENTITY_FILE)), 0o600);
}

/// The headless-Linux path `docs/ROADMAP.md` §4 risk 3 calls out: with
/// no D-Bus session there is no Secret Service, so `auto` must report
/// `file` — silently reporting `platform` would be a security-posture
/// lie.
#[cfg(target_os = "linux")]
#[test]
fn auto_falls_back_to_file_when_headless() {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        eprintln!("skipping: a D-Bus session bus is present, so this host is not headless");
        return;
    }
    let (_guard, paths) = temp_paths();
    let data = init(&paths, KeyStoreMode::Auto).unwrap();
    assert_eq!(data.key_store, KeyStoreKind::File);
    assert!(paths.identity_dir().join(KEY_FILE).is_file());
    assert!(load(&paths).unwrap().is_some());
}

/// Crash-safety regression for the cert-before-record write order
/// `promote_to_ca_issued`'s own doc comment promises (mirroring
/// `ca::init`'s key-before-cert rule): forces the *second* write
/// (`identity.toml`) to fail by pre-occupying its exact atomic-rename
/// temp path (`identity.toml.tmp<pid>-<ticket>`) with a directory, so
/// whichever file `promote_to_ca_issued` writes first genuinely lands
/// on disk before the call errors out — proof of the real order, not
/// an assumption about it. If that order were ever reversed (record
/// first, cert last), the *record* write — the one whose temp path we
/// block — would be attempted first and the call would fail before
/// ever touching `device.pem`.
///
/// The temp path now carries a writer-scoped ticket
/// (`crate::config::write_private_file_io`, `PLAN.md` M7 Step 7-1).
/// `promote_to_ca_issued` makes exactly two `write_private_file` calls
/// in a fixed order (cert, then record), so
/// `next_write_ticket_for_test() + 1` is exactly the record write's
/// ticket.
///
/// That prediction only holds under a **process-isolated test runner**
/// (`cargo nextest run`, this repo's required one —
/// `.github/workflows/ci.yml`). `WRITE_TICKET` is a single
/// process-global `AtomicU64` (`crate::config`), so under plain `cargo
/// test`'s in-process, thread-parallel execution any concurrently
/// scheduled sibling test that also calls `write_private_file`/
/// `write_private_file_io` can steal the predicted ticket out from
/// under this read, and the assertions below can fail spuriously
/// (`PLAN.md` M7 Step 7-1 검증 라운드 A1 — this test's sibling in
/// `crate::ca` was reproduced 3/3 failing this way under `cargo test`;
/// this one wasn't in that sample, but shares the identical
/// mechanism). This is a known test-isolation limitation of this
/// test, not of the production ticket/locking mechanism, which
/// nextest — the actual CI and commit-gate runner — validates
/// cleanly.
#[test]
fn promote_to_ca_issued_recovers_from_an_interrupted_record_write() {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    let (_guard, paths) = temp_paths();
    let created = init(&paths, KeyStoreMode::File).unwrap();
    let identity_dir = paths.identity_dir();
    let original_cert = std::fs::read(identity_dir.join(CERT_FILE)).unwrap();

    // A stand-in "CA-issued" leaf: this test only cares about
    // `promote_to_ca_issued`'s own write-order crash-safety, not ADR
    // §2's key-preservation claim (covered by `crate::ca`'s own
    // tests), so any distinguishable, valid cert will do.
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "ca-issued-leaf");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    let leaf_cert = params.self_signed(&leaf_key).unwrap();
    let leaf_pem = leaf_cert.pem();
    let leaf_der = leaf_cert.der().to_vec();

    let record_ticket = crate::config::next_write_ticket_for_test() + 1;
    let record_tmp = identity_dir.join(format!(
        "{IDENTITY_FILE}.tmp{}-{record_ticket}",
        std::process::id()
    ));
    std::fs::create_dir(&record_tmp).unwrap();

    let err = match promote_to_ca_issued(&paths, &leaf_pem, &leaf_der, "fake_ca_fp") {
        Err(err) => err,
        Ok(_) => {
            panic!("promote_to_ca_issued must fail while identity.toml's write is blocked")
        }
    };
    assert_eq!(err.code, ErrorCode::ConfigError);

    // The cert must already be on disk: written before the record, so
    // it survives the record write's failure.
    let cert_after_failure = std::fs::read(identity_dir.join(CERT_FILE)).unwrap();
    assert_eq!(cert_after_failure, leaf_pem.as_bytes());
    assert_ne!(cert_after_failure, original_cert);

    // The record must be untouched by the failed attempt: still the
    // pre-promotion identity, never a premature `issued_by_ca` claim
    // over a cert that (from the record's own perspective) hasn't
    // landed.
    let stale = read_identity(&paths).unwrap().unwrap();
    assert_eq!(stale.issued_by_ca, None);
    assert_eq!(stale.device_id, created.device_id);

    // Clear the blocker and retry: `promote_to_ca_issued` must recover
    // cleanly into a fully consistent, promoted identity.
    std::fs::remove_dir(&record_tmp).unwrap();
    let promoted = promote_to_ca_issued(&paths, &leaf_pem, &leaf_der, "fake_ca_fp").unwrap();
    assert_eq!(promoted.issued_by_ca.as_deref(), Some("fake_ca_fp"));
    let final_read = read_identity(&paths).unwrap().unwrap();
    assert_eq!(final_read.issued_by_ca.as_deref(), Some("fake_ca_fp"));
    assert_eq!(final_read.cert_der, leaf_der);
}
