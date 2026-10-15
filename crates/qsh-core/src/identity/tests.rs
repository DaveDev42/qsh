use super::*;
use qsh_proto::IdentityMoveKeyData;

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

/// The Windows twin of `identity_directory_and_files_are_private`.
#[cfg(windows)]
#[test]
fn identity_directory_and_files_have_an_owner_only_dacl() {
    use crate::fsutil::dacl::ObjectKind;
    use crate::fsutil::dacl::testing::assert_owner_only;

    let (_guard, paths) = temp_paths();
    init(&paths, KeyStoreMode::File).unwrap();

    assert_owner_only(&paths.config_dir, ObjectKind::Dir);
    assert_owner_only(&paths.identity_dir(), ObjectKind::Dir);
    for file in [KEY_FILE, CERT_FILE, IDENTITY_FILE] {
        assert_owner_only(&paths.identity_dir().join(file), ObjectKind::File);
    }
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
/// (`crate::config::write_private_file_io`, M7 plan Step 7-1 (69dd788)).
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
/// (M7 plan Step 7-1 (69dd788) 검증 라운드 A1 — this test's sibling in
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

// ---------------------------------------------------------------------------
// `--import-ssh-key` (ADR-0026)
// ---------------------------------------------------------------------------

const GOLDEN_HEX: &str = include_str!("../../../qsh-proto/testdata/openssh/ed25519_golden.hex");
const GOLDEN_SEED_HEX: &str = "e0a3d490ac207b6a613ef0d9ece980a23fc4fae80a11d6e8bb87836df909f6f0";
const GOLDEN_PUBLIC_HEX: &str = "c5823db0474406fc8765512b49112913f128b2418dfbaddee18ae88c7f54b23f";
/// `ssh-keygen -lf` output for the golden key.
const GOLDEN_SSH_FINGERPRINT: &str = "SHA256:XxSbKVKvD1gyArwLk6oM3TZnt9rZogny7tQgxWR2bek";

fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.bytes())
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn ssh_fingerprint_matches_ssh_keygen_output_for_the_golden_vector() {
    let public: [u8; 32] = unhex(GOLDEN_PUBLIC_HEX).try_into().unwrap();
    assert_eq!(ssh_fingerprint_of_ed25519(&public), GOLDEN_SSH_FINGERPRINT);
}

#[test]
fn pkcs8_v2_assembled_from_the_golden_seed_is_accepted_by_rcgen() {
    let seed: [u8; 32] = unhex(GOLDEN_SEED_HEX).try_into().unwrap();
    let public: [u8; 32] = unhex(GOLDEN_PUBLIC_HEX).try_into().unwrap();
    let der = import::pkcs8_v2_ed25519(&seed, &public);
    assert_eq!(der.len(), 2 + 0x51);
    let key = rcgen::KeyPair::try_from(der.as_slice()).expect("rcgen accepts the assembled DER");
    // The seed derives exactly the public key the file carries.
    assert_eq!(rcgen::PublicKeyData::der_bytes(&key), &public[..]);
}

#[test]
fn init_importing_issues_a_leaf_over_the_imported_key_and_stores_it() {
    let (_guard, paths) = temp_paths();
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("id_ed25519");
    std::fs::write(&key_path, unhex(GOLDEN_HEX)).unwrap();

    let data = init_importing(&paths, KeyStoreMode::File, key_path.to_str().unwrap()).unwrap();
    assert!(data.created);
    assert_eq!(
        data.ssh_fingerprint.as_deref(),
        Some(GOLDEN_SSH_FINGERPRINT)
    );

    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(&unhex(GOLDEN_PUBLIC_HEX));
    assert_eq!(
        data.fingerprint,
        Fingerprint::of_spki_der(&spki).to_string()
    );

    // The stored key is the imported one: a loaded identity signs for the
    // same SPKI.
    let loaded = load(&paths).unwrap().expect("identity");
    assert_eq!(loaded.identity.fingerprint.to_string(), data.fingerprint);
    let pair = rcgen::KeyPair::try_from(loaded.local.key_pkcs8_der.as_slice()).unwrap();
    assert_eq!(
        Fingerprint::of_spki_der(&rcgen::PublicKeyData::subject_public_key_info(&pair)).to_string(),
        data.fingerprint
    );

    // The source key file is never modified.
    assert_eq!(std::fs::read(&key_path).unwrap(), unhex(GOLDEN_HEX));
}

// ---------------------------------------------------------------------------
// `identity.move_key` (ADR-0032 결정 15)
//
// No test here touches the OS credential store: the `platform` side is a
// [`FakePlatform`] handed to `move_key` (`Ops::identity_move_key_with_platform_store`
// in production code's shape).
// ---------------------------------------------------------------------------

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

/// A stand-in for the OS credential store, with one switch per failure the
/// move has to survive.
#[derive(Default)]
struct FakePlatform {
    inner: MemoryKeyStore,
    unavailable: AtomicBool,
    fail_store: AtomicBool,
    fail_delete: AtomicBool,
    /// After a write, `load` answers with some other valid key, as a store
    /// that returns the wrong bytes would.
    wrong_key_on_load: AtomicBool,
    written: AtomicBool,
}

impl FakePlatform {
    fn flip(flag: &AtomicBool) {
        flag.store(true, Ordering::SeqCst);
    }

    fn holds(&self) -> Option<Vec<u8>> {
        self.inner.load().unwrap().map(|key| key.to_vec())
    }
}

impl KeyStore for FakePlatform {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::Platform
    }

    fn store(&self, key_pkcs8_der: &[u8]) -> Result<(), KeyStoreError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Unavailable("fake store is down".into()));
        }
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Other("fake store refused the write".into()));
        }
        self.written.store(true, Ordering::SeqCst);
        self.inner.store(key_pkcs8_der)
    }

    fn load(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, KeyStoreError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Unavailable("fake store is down".into()));
        }
        if self.wrong_key_on_load.load(Ordering::SeqCst) && self.written.load(Ordering::SeqCst) {
            let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            return Ok(Some(zeroize::Zeroizing::new(other.serialize_der())));
        }
        self.inner.load()
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Io(io::Error::other(
                "fake store is read-only",
            )));
        }
        self.inner.delete()
    }
}

/// A device whose key is in the `file` store.
fn file_identity() -> (tempfile::TempDir, Paths, IdentityInitData) {
    let (guard, paths) = temp_paths();
    let data = init(&paths, KeyStoreMode::File).unwrap();
    (guard, paths, data)
}

/// A device whose key is in the fake `platform` store, built without the
/// code under test: the key moves by hand and `identity.toml` is edited.
fn platform_identity() -> (tempfile::TempDir, Paths, IdentityInitData, FakePlatform) {
    let (guard, paths, data) = file_identity();
    let fake = FakePlatform::default();
    let key_path = paths.identity_dir().join(KEY_FILE);
    let key = FileKeyStore::new(&key_path).load().unwrap().unwrap();
    fake.store(&key).unwrap();
    std::fs::remove_file(&key_path).unwrap();
    let record_path = paths.identity_dir().join(IDENTITY_FILE);
    let record = std::fs::read_to_string(&record_path).unwrap();
    assert!(record.contains("key_store = \"file\""), "{record}");
    std::fs::write(
        &record_path,
        record.replace("key_store = \"file\"", "key_store = \"platform\""),
    )
    .unwrap();
    (guard, paths, data, fake)
}

fn bytes_of(paths: &Paths, name: &str) -> Option<Vec<u8>> {
    std::fs::read(paths.identity_dir().join(name)).ok()
}

/// Run `move_key`, counting the audit calls.
fn run_move(
    paths: &Paths,
    to: KeyStoreKind,
    platform: &FakePlatform,
) -> (Result<IdentityMoveKeyData, OpError>, u32) {
    let audited = Cell::new(0);
    let result = move_key(paths, to, Some(platform), |_, _| {
        audited.set(audited.get() + 1);
        Ok(())
    });
    (result, audited.get())
}

/// ADR-0032 결정 15: the device id, certificate and fingerprint do not
/// change, in either direction, so a peer's pin and ACL rows stay valid.
#[test]
fn move_key_keeps_the_fingerprint_and_device_id() {
    let (_guard, paths, created, fake) = platform_identity();
    let cert_before = bytes_of(&paths, CERT_FILE).unwrap();
    let record_before = read_identity(&paths).unwrap().unwrap();
    let key_before = fake.holds().unwrap();

    let (to_file, audited) = run_move(&paths, KeyStoreKind::File, &fake);
    let data = to_file.unwrap();
    assert_eq!(audited, 1);
    assert_eq!(
        data,
        IdentityMoveKeyData {
            from: KeyStoreKind::Platform,
            to: KeyStoreKind::File,
            moved: true,
            stale_entry_left: false
        }
    );
    let after = read_identity(&paths).unwrap().unwrap();
    assert_eq!(after.device_id, created.device_id);
    assert_eq!(after.fingerprint.to_string(), created.fingerprint);
    assert_eq!(after.created_at, record_before.created_at);
    assert_eq!(after.cert_der, record_before.cert_der);
    assert_eq!(after.key_store, KeyStoreKind::File);
    assert_eq!(bytes_of(&paths, CERT_FILE).unwrap(), cert_before);
    assert_eq!(fake.holds(), None, "the old entry is gone");
    assert!(bytes_of(&paths, KEY_FILE).is_some());
    let loaded = load(&paths).unwrap().expect("identity loads from the file");
    assert_eq!(loaded.local.key_pkcs8_der.as_slice(), key_before.as_slice());

    // And back again.
    let (to_platform, audited) = run_move(&paths, KeyStoreKind::Platform, &fake);
    assert_eq!(audited, 1);
    assert_eq!(
        to_platform.unwrap(),
        IdentityMoveKeyData {
            from: KeyStoreKind::File,
            to: KeyStoreKind::Platform,
            moved: true,
            stale_entry_left: false
        }
    );
    let back = read_identity(&paths).unwrap().unwrap();
    assert_eq!(back.device_id, created.device_id);
    assert_eq!(back.fingerprint.to_string(), created.fingerprint);
    assert_eq!(back.key_store, KeyStoreKind::Platform);
    assert_eq!(fake.holds().unwrap(), key_before);
    assert_eq!(bytes_of(&paths, KEY_FILE), None);
}

/// `issued_by_ca` and the record's own `fingerprint` string survive the
/// rewrite of `identity.toml` untouched.
#[test]
fn move_key_rewrites_only_the_key_store_line_of_the_record() {
    let (_guard, paths, _created, fake) = platform_identity();
    let before = std::fs::read_to_string(paths.identity_dir().join(IDENTITY_FILE)).unwrap();
    run_move(&paths, KeyStoreKind::File, &fake).0.unwrap();
    let after = std::fs::read_to_string(paths.identity_dir().join(IDENTITY_FILE)).unwrap();
    assert_eq!(
        after,
        before.replace("key_store = \"platform\"", "key_store = \"file\"")
    );
}

#[test]
fn move_key_to_the_current_store_is_a_no_op() {
    let (_guard, paths, _created) = file_identity();
    let fake = FakePlatform::default();
    let record = bytes_of(&paths, IDENTITY_FILE);
    let key = bytes_of(&paths, KEY_FILE);

    let (result, audited) = run_move(&paths, KeyStoreKind::File, &fake);
    assert_eq!(
        result.unwrap(),
        IdentityMoveKeyData {
            from: KeyStoreKind::File,
            to: KeyStoreKind::File,
            moved: false,
            stale_entry_left: false
        }
    );
    assert_eq!(
        audited, 0,
        "a no-op changes nothing, so it writes no record"
    );
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(bytes_of(&paths, KEY_FILE), key);
    assert_eq!(fake.holds(), None);

    // The platform side too.
    let (_guard, paths, _created, fake) = platform_identity();
    let record = bytes_of(&paths, IDENTITY_FILE);
    let held = fake.holds();
    let (result, audited) = run_move(&paths, KeyStoreKind::Platform, &fake);
    assert!(!result.unwrap().moved);
    assert_eq!(audited, 0);
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(fake.holds(), held);
}

/// Every failure path ends with the original store and `identity.toml`
/// byte for byte as they were.
#[test]
fn a_failed_move_key_write_leaves_the_original_store_untouched() {
    // file -> platform, the platform write is refused.
    let (_guard, paths, _created) = file_identity();
    let fake = FakePlatform::default();
    FakePlatform::flip(&fake.fail_store);
    let record = bytes_of(&paths, IDENTITY_FILE);
    let key = bytes_of(&paths, KEY_FILE);
    let (result, audited) = run_move(&paths, KeyStoreKind::Platform, &fake);
    let err = result.unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(!err.retryable);
    assert_eq!(audited, 1, "the attempt was recorded before it began");
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(bytes_of(&paths, KEY_FILE), key);
    assert_eq!(fake.holds(), None);

    // platform -> file, the file write cannot happen: `device.key` is a
    // directory.
    let (_guard, paths, _created, fake) = platform_identity();
    let record = bytes_of(&paths, IDENTITY_FILE);
    let held = fake.holds();
    std::fs::create_dir(paths.identity_dir().join(KEY_FILE)).unwrap();
    let (result, _) = run_move(&paths, KeyStoreKind::File, &fake);
    assert_eq!(result.unwrap_err().code, ErrorCode::Internal);
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(fake.holds(), held);
}

/// The step after the key is stored and verified: `identity.toml` cannot
/// be rewritten. The destination goes back to what it held before, even
/// when that was a stale entry, and the original store is not touched.
#[test]
fn a_failed_identity_record_rewrite_rolls_the_destination_back() {
    let (_guard, paths, _created) = file_identity();
    let fake = FakePlatform::default();
    fake.inner.store(b"an older entry").unwrap();
    let record = bytes_of(&paths, IDENTITY_FILE);
    let key = bytes_of(&paths, KEY_FILE);

    // The platform write is no file write, so the record's temp file gets
    // the next write ticket; occupy that name with a directory.
    let ticket = crate::config::next_write_ticket_for_test();
    std::fs::create_dir(paths.identity_dir().join(format!(
        "{IDENTITY_FILE}.tmp{}-{ticket}",
        std::process::id()
    )))
    .unwrap();

    let (result, _) = run_move(&paths, KeyStoreKind::Platform, &fake);
    assert!(result.is_err());
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(bytes_of(&paths, KEY_FILE), key);
    assert_eq!(fake.holds().as_deref(), Some(b"an older entry".as_slice()));
}

#[cfg(unix)]
#[test]
fn move_key_file_store_is_mode_0600() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_guard, paths, _created, fake) = platform_identity();
    run_move(&paths, KeyStoreKind::File, &fake).0.unwrap();
    let mode_of =
        |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode_of(paths.identity_dir().join(KEY_FILE)), 0o600);
    assert_eq!(mode_of(paths.identity_dir()), 0o700);
    assert_eq!(mode_of(paths.identity_dir().join(IDENTITY_FILE)), 0o600);
}

/// The Windows twin of `move_key_file_store_is_mode_0600`: the key that
/// `--to file` writes, and the record rewritten beside it, are owner-only.
#[cfg(windows)]
#[test]
fn move_key_file_store_has_an_owner_only_dacl() {
    use crate::fsutil::dacl::ObjectKind;
    use crate::fsutil::dacl::testing::assert_owner_only;

    let (_guard, paths, _created, fake) = platform_identity();
    run_move(&paths, KeyStoreKind::File, &fake).0.unwrap();
    assert_owner_only(&paths.identity_dir(), ObjectKind::Dir);
    assert_owner_only(&paths.identity_dir().join(KEY_FILE), ObjectKind::File);
    assert_owner_only(&paths.identity_dir().join(IDENTITY_FILE), ObjectKind::File);
}

/// A store that answers with the wrong key fails the check against the
/// device certificate; the write is undone.
#[test]
fn move_key_readback_mismatch_rolls_back() {
    let (_guard, paths, _created) = file_identity();
    let fake = FakePlatform::default();
    FakePlatform::flip(&fake.wrong_key_on_load);
    let record = bytes_of(&paths, IDENTITY_FILE);
    let key = bytes_of(&paths, KEY_FILE);

    let (result, _) = run_move(&paths, KeyStoreKind::Platform, &fake);
    let err = result.unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(err.message.contains("not the key of this device"), "{err}");
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(bytes_of(&paths, KEY_FILE), key);
    assert_eq!(fake.holds(), None, "the verified-bad copy is removed");
}

#[test]
fn move_key_reports_stale_entry_left_when_only_the_final_delete_fails() {
    let (_guard, paths, created, fake) = platform_identity();
    FakePlatform::flip(&fake.fail_delete);
    let held = fake.holds();

    let data = run_move(&paths, KeyStoreKind::File, &fake).0.unwrap();
    assert!(data.moved);
    assert!(data.stale_entry_left);
    // The identity already uses the file store; the copy that stayed behind
    // is the same key.
    let after = read_identity(&paths).unwrap().unwrap();
    assert_eq!(after.key_store, KeyStoreKind::File);
    assert_eq!(after.fingerprint.to_string(), created.fingerprint);
    assert!(load(&paths).unwrap().is_some());
    assert_eq!(fake.holds(), held);
}

#[test]
fn move_key_before_init_is_config_error() {
    let (_guard, paths) = temp_paths();
    let fake = FakePlatform::default();
    let (result, audited) = run_move(&paths, KeyStoreKind::File, &fake);
    let err = result.unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert_eq!(err.message, NO_LOCAL_IDENTITY);
    assert_eq!(audited, 0);
    assert!(
        !paths.identity_dir().exists(),
        "nothing is created for an identity that does not exist"
    );
}

#[test]
fn move_key_to_platform_without_a_store_is_internal() {
    let (_guard, paths, _created) = file_identity();
    let fake = FakePlatform::default();
    FakePlatform::flip(&fake.unavailable);
    let record = bytes_of(&paths, IDENTITY_FILE);
    let key = bytes_of(&paths, KEY_FILE);

    let err = run_move(&paths, KeyStoreKind::Platform, &fake)
        .0
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    assert!(!err.retryable);
    assert!(
        err.message.contains("platform key store unavailable"),
        "{err}"
    );
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(bytes_of(&paths, KEY_FILE), key);
}

/// The audit callback runs once and a failure from it stops the move before
/// any store is touched.
#[test]
fn move_key_stops_at_a_failed_audit_callback() {
    let (_guard, paths, _created, fake) = platform_identity();
    let record = bytes_of(&paths, IDENTITY_FILE);
    let held = fake.holds();
    let err = move_key(&paths, KeyStoreKind::File, Some(&fake), |_, _| {
        Err(OpError::new(ErrorCode::Internal, "audit down"))
    })
    .unwrap_err();
    assert_eq!(err.message, "audit down");
    assert_eq!(bytes_of(&paths, IDENTITY_FILE), record);
    assert_eq!(bytes_of(&paths, KEY_FILE), None);
    assert_eq!(fake.holds(), held);
}

/// ADR-0013: whatever the outcome, the key (raw, base64, hex or PEM) is in
/// no returned data, error message, error details or log line.
#[test]
fn move_key_never_emits_key_bytes() {
    use base64::Engine as _;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    let mut shown = String::new();
    let mut key = Vec::new();
    tracing::subscriber::with_default(subscriber, || {
        let mut outcome = |label: &str, result: Result<IdentityMoveKeyData, OpError>| {
            shown.push_str(&format!("{label}: {result:?}\n"));
            if let Err(err) = &result {
                shown.push_str(&format!("{err} {}\n", err.details));
            }
        };

        // A clean round trip, with the key known up front.
        let (_guard, paths, _created, fake) = platform_identity();
        key = fake.holds().unwrap();
        outcome("to file", run_move(&paths, KeyStoreKind::File, &fake).0);
        outcome(
            "to platform",
            run_move(&paths, KeyStoreKind::Platform, &fake).0,
        );
        // A move that leaves a stale entry.
        FakePlatform::flip(&fake.fail_delete);
        outcome("stale", run_move(&paths, KeyStoreKind::File, &fake).0);

        // Failures at every step that handles the key.
        let (_guard, paths, _created) = file_identity();
        let down = FakePlatform::default();
        FakePlatform::flip(&down.unavailable);
        outcome("down", run_move(&paths, KeyStoreKind::Platform, &down).0);
        let refusing = FakePlatform::default();
        FakePlatform::flip(&refusing.fail_store);
        outcome(
            "refused",
            run_move(&paths, KeyStoreKind::Platform, &refusing).0,
        );
        let lying = FakePlatform::default();
        FakePlatform::flip(&lying.wrong_key_on_load);
        outcome(
            "mismatch",
            run_move(&paths, KeyStoreKind::Platform, &lying).0,
        );
    });

    let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains("device key moved"),
        "the success line is logged, so this test reads real output: {logged}"
    );
    let b64 = base64::engine::general_purpose::STANDARD.encode(&key);
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    // PKCS#8 Ed25519 is a 16-byte header and the 32-byte seed; these
    // windows lie inside the seed, so a leak of any slice of it matches.
    let needles = [
        b64.clone(),
        b64[24..48].to_string(),
        hex.clone(),
        hex[40..72].to_string(),
        pem::encode(pem::PRIVATE_KEY, &key),
    ];
    for output in [&shown, &logged] {
        for needle in &needles {
            assert!(
                !output.contains(needle.as_str()),
                "key material in output: {output}"
            );
        }
    }
}
