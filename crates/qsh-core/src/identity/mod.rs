//! Device identity: Ed25519 keypair, long-lived self-signed X.509 device
//! certificate, and the on-disk layout that binds them
//! (`docs/design/architecture.md` §5, `docs/CLI.md` §6.11).
//!
//! ```text
//! <config_dir>/identity/       # 0700
//! ├── identity.toml            # device_id, key_store, created_at, fingerprint
//! ├── device.pem               # the certificate (0600)
//! └── device.key               # PKCS#8 PEM, 0600 — file key-store mode only
//! ```
//!
//! `identity.toml` is written **last**, after the private key is safely in
//! its store: a crash in the middle therefore never leaves behind an
//! identity record whose key is missing.

pub mod keystore;
pub(crate) mod pem;

use std::io;
use std::path::Path;

use qsh_proto::{ErrorCode, IdentityInitData, KeyStoreKind, KeyStoreMode};
use qsh_transport::{CertificateDer, Fingerprint, LocalIdentity};
use serde::{Deserialize, Serialize};

pub use keystore::{
    FileKeyStore, KEYRING_SERVICE, KeyStore, KeyStoreError, MemoryKeyStore, PlatformKeyStore,
};

use crate::config::{Paths, config_io_error, ensure_private_dir, now_rfc3339, write_private_file};
use crate::ops::OpError;

/// File name of the identity record inside the identity directory.
pub const IDENTITY_FILE: &str = "identity.toml";
/// File name of the device certificate (PEM).
pub const CERT_FILE: &str = "device.pem";
/// File name of the private key in file key-store mode (PKCS#8 PEM).
pub const KEY_FILE: &str = "device.key";

/// How long a freshly issued device certificate is valid
/// (`docs/design/architecture.md` §5: "장기(10y) self-signed").
const CERT_VALIDITY_DAYS: i64 = 3650;
/// Backdate `not_before` to absorb small clock skew between peers.
///
/// `pub(crate)`: `doctor.run`'s `clock_skew` diagnostic (`docs/CLI.md`
/// §6.17, `crate::ops::doctor`) reuses this exact threshold rather than
/// hard-coding a second copy of "5 minutes" — a peer this device's clock
/// could ever plausibly be off by without also invalidating certificates
/// this device itself just backdated by the same margin.
pub(crate) const CERT_BACKDATE_MINUTES: i64 = 5;

/// The public half of this device's identity: everything except the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `device_<ULID>`.
    pub device_id: String,
    /// SPKI SHA-256 fingerprint of [`cert_der`](Self::cert_der).
    pub fingerprint: Fingerprint,
    /// Where the private key lives.
    pub key_store: KeyStoreKind,
    /// RFC 3339 UTC creation timestamp.
    pub created_at: String,
    /// DER-encoded device certificate.
    pub cert_der: Vec<u8>,
    /// SPKI fingerprint of the local CA root that issued
    /// [`cert_der`](Self::cert_der), if it is CA-issued rather than
    /// self-signed (`docs/adr/0008-private-ca-cert-issuance.md` §2, `qsh
    /// cert issue`). `None` for a self-signed identity — the state every
    /// identity starts in and the only state before M7 Step 5.
    pub issued_by_ca: Option<String>,
}

/// An [`Identity`] plus the private key, ready to hand to the transport.
///
/// Deliberately has no `Debug` of its own beyond
/// [`LocalIdentity`]'s redacting one — key bytes must never reach a log.
#[derive(Debug, Clone)]
pub struct LoadedIdentity {
    /// The public identity record.
    pub identity: Identity,
    /// Cert chain + PKCS#8 key for `qsh-transport`.
    pub local: LocalIdentity,
}

/// `identity.toml` on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityFile {
    device_id: String,
    key_store: KeyStoreKind,
    created_at: String,
    fingerprint: String,
    /// Additive (`docs/adr/0008-private-ca-cert-issuance.md`, M7 Step 5):
    /// absent on any `identity.toml` written before this field existed,
    /// which `serde(default)` reads back as `None` — the correct answer,
    /// since every such identity is self-signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_by_ca: Option<String>,
}

/// Create this device's identity if it does not exist yet (idempotent).
///
/// `mode` picks the private-key store:
///
/// - [`KeyStoreMode::File`] — always the 0600 file store.
/// - [`KeyStoreMode::Platform`] — the OS credential store; an unavailable
///   store is a hard `INTERNAL` failure (never a silent downgrade).
/// - [`KeyStoreMode::Auto`] — platform, falling back to file with a
///   `WARN` log when the platform store is unavailable (headless Linux).
///
/// The returned data always names the store that was *actually* used
/// (`docs/CLI.md` §6.11).
///
/// **Runtime caveat:** with a platform store this blocks on the OS
/// credential store; call it outside an async context or from
/// `spawn_blocking`.
pub fn init(paths: &Paths, mode: KeyStoreMode) -> Result<IdentityInitData, OpError> {
    ensure_private_dir(&paths.config_dir)?;
    let config_dir = canonical_config_dir(paths);
    let identity_dir = paths.identity_dir();
    ensure_private_dir(&identity_dir)?;

    if let Some(existing) = read_identity(paths)? {
        return Ok(IdentityInitData {
            device_id: existing.device_id,
            fingerprint: existing.fingerprint.to_string(),
            key_store: existing.key_store,
            config_dir,
            created: false,
        });
    }

    let device_id = format!("device_{}", ulid::Ulid::new());
    let generated = generate(&device_id)?;
    let store = store_key(paths, &device_id, mode, &generated.key_pkcs8_der)?;

    write_private_file(&identity_dir.join(CERT_FILE), generated.cert_pem.as_bytes())?;

    let record = IdentityFile {
        device_id: device_id.clone(),
        key_store: store,
        created_at: now_rfc3339(),
        fingerprint: generated.fingerprint.to_string(),
        issued_by_ca: None,
    };
    let text = toml::to_string_pretty(&record).map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("failed to encode {IDENTITY_FILE}: {err}"),
        )
        .with_retryable(false)
    })?;
    // Written last: the key is already stored, so this record is never a
    // promise the key store cannot keep.
    write_private_file(&identity_dir.join(IDENTITY_FILE), text.as_bytes())?;

    Ok(IdentityInitData {
        device_id,
        fingerprint: generated.fingerprint.to_string(),
        key_store: store,
        config_dir,
        created: true,
    })
}

/// Load this device's identity **with** its private key, or `None` if
/// `qsh init` has not run in this config directory yet.
///
/// **Blocking:** when the key lives in the platform store this call blocks
/// on the OS credential store (the store runs the client on its own thread,
/// so it is safe from any context — but it still *waits*; prefer calling it
/// before entering a tokio runtime or from `spawn_blocking`).
pub fn load(paths: &Paths) -> Result<Option<LoadedIdentity>, OpError> {
    let Some(identity) = read_identity(paths)? else {
        return Ok(None);
    };
    let store = open_store(paths, &identity.device_id, identity.key_store);
    let key = store.load().map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!(
                "failed to read the device key from the {} key store: {err}",
                identity.key_store.as_str()
            ),
        )
        .with_retryable(false)
    })?;
    let Some(key) = key else {
        return Err(OpError::new(
            ErrorCode::Internal,
            format!(
                "identity key missing from {}; re-run qsh init after removing {}",
                identity.key_store.as_str(),
                paths.identity_dir().display()
            ),
        )
        .with_retryable(false));
    };

    let local = LocalIdentity {
        cert_chain: vec![CertificateDer::from(identity.cert_der.clone())],
        key_pkcs8_der: key.to_vec(),
    };
    Ok(Some(LoadedIdentity { identity, local }))
}

/// Read `identity.toml` + `device.pem` without touching the key store.
/// `None` when this config directory holds no identity.
pub fn read_identity(paths: &Paths) -> Result<Option<Identity>, OpError> {
    let identity_dir = paths.identity_dir();
    let record_path = identity_dir.join(IDENTITY_FILE);
    let text = match std::fs::read_to_string(&record_path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(config_io_error(&record_path, "read", &err)),
    };
    let record: IdentityFile = toml::from_str(&text).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("invalid identity record {}: {err}", record_path.display()),
        )
        .with_retryable(false)
    })?;

    let cert_path = identity_dir.join(CERT_FILE);
    let cert_der = read_cert_der(&cert_path)?;
    let fingerprint = Fingerprint::of_cert_der(&cert_der).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("invalid device certificate {}: {err}", cert_path.display()),
        )
        .with_retryable(false)
    })?;
    if record.fingerprint != fingerprint.to_string() {
        tracing::warn!(
            path = %record_path.display(),
            "identity.toml fingerprint does not match device.pem; using the certificate"
        );
    }

    Ok(Some(Identity {
        device_id: record.device_id,
        fingerprint,
        key_store: record.key_store,
        created_at: record.created_at,
        cert_der,
        issued_by_ca: record.issued_by_ca,
    }))
}

/// Promote this device's identity from self-signed to CA-issued: overwrite
/// `device.pem` in place with `cert_pem` and record `ca_fingerprint` as
/// its issuer, leaving `device_id`/`key_store`/`created_at` — and the
/// private key itself — untouched
/// (`docs/adr/0008-private-ca-cert-issuance.md` §2, §5).
///
/// The caller (`crate::ca::issue_device_leaf`) is responsible for the
/// certificate actually being signed by the CA at `ca_fingerprint` with
/// this device's own key; this function only persists the result.
///
/// Errors `CONFIG_ERROR` if no identity exists yet — `qsh cert issue`
/// promotes an existing identity, it never creates one (run `qsh init`
/// first).
pub fn promote_to_ca_issued(
    paths: &Paths,
    cert_pem: &str,
    cert_der: &[u8],
    ca_fingerprint: &str,
) -> Result<Identity, OpError> {
    let identity_dir = paths.identity_dir();
    let existing = read_identity(paths)?.ok_or_else(|| {
        OpError::new(
            ErrorCode::ConfigError,
            "no local identity; run `qsh init` first",
        )
        .with_retryable(false)
    })?;

    let fingerprint = Fingerprint::of_cert_der(cert_der).map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("failed to fingerprint the CA-issued device certificate: {err}"),
        )
        .with_retryable(false)
    })?;

    write_private_file(&identity_dir.join(CERT_FILE), cert_pem.as_bytes())?;

    let record = IdentityFile {
        device_id: existing.device_id.clone(),
        key_store: existing.key_store,
        created_at: existing.created_at.clone(),
        fingerprint: fingerprint.to_string(),
        issued_by_ca: Some(ca_fingerprint.to_string()),
    };
    let text = toml::to_string_pretty(&record).map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("failed to encode {IDENTITY_FILE}: {err}"),
        )
        .with_retryable(false)
    })?;
    // Written last, same crash-safety rule as `init`: the cert is already
    // on disk, so this record is never a promise the cert cannot keep.
    write_private_file(&identity_dir.join(IDENTITY_FILE), text.as_bytes())?;

    Ok(Identity {
        device_id: existing.device_id,
        fingerprint,
        key_store: existing.key_store,
        created_at: existing.created_at,
        cert_der: cert_der.to_vec(),
        issued_by_ca: Some(ca_fingerprint.to_string()),
    })
}

fn read_cert_der(path: &Path) -> Result<Vec<u8>, OpError> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "device certificate {} is missing; re-run qsh init after removing the identity directory",
                    path.display()
                ),
            )
            .with_retryable(false)
        } else {
            config_io_error(path, "read", &err)
        }
    })?;
    pem::decode_first(pem::CERTIFICATE, &text).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("invalid device certificate {}: {err}", path.display()),
        )
        .with_retryable(false)
    })
}

/// Build the [`KeyStore`] that holds (or will hold) `device_id`'s key.
fn open_store(paths: &Paths, device_id: &str, kind: KeyStoreKind) -> Box<dyn KeyStore> {
    match kind {
        KeyStoreKind::File => Box::new(FileKeyStore::new(paths.identity_dir().join(KEY_FILE))),
        KeyStoreKind::Platform => Box::new(PlatformKeyStore::new(device_id.to_string())),
    }
}

/// Apply the `auto`/`platform`/`file` policy and report the store actually
/// used.
fn store_key(
    paths: &Paths,
    device_id: &str,
    mode: KeyStoreMode,
    key_pkcs8_der: &[u8],
) -> Result<KeyStoreKind, OpError> {
    let file_store = || FileKeyStore::new(paths.identity_dir().join(KEY_FILE));

    match mode {
        KeyStoreMode::File => {
            file_store()
                .store(key_pkcs8_der)
                .map_err(internal_store_err)?;
            Ok(KeyStoreKind::File)
        }
        KeyStoreMode::Platform => {
            let platform = PlatformKeyStore::new(device_id.to_string());
            match platform.store(key_pkcs8_der) {
                Ok(()) => Ok(KeyStoreKind::Platform),
                Err(err @ KeyStoreError::Unavailable(_)) => Err(OpError::new(
                    ErrorCode::Internal,
                    format!(
                        "platform key store unavailable ({err}); re-run with --key-store auto or \
                         --key-store file"
                    ),
                )
                .with_retryable(false)),
                Err(err) => Err(internal_store_err(err)),
            }
        }
        KeyStoreMode::Auto => {
            let platform = PlatformKeyStore::new(device_id.to_string());
            match platform.store(key_pkcs8_der) {
                Ok(()) => Ok(KeyStoreKind::Platform),
                Err(KeyStoreError::Unavailable(reason)) => {
                    let path = paths.identity_dir().join(KEY_FILE);
                    tracing::warn!(
                        %reason,
                        path = %path.display(),
                        "platform key store unavailable, falling back to file store"
                    );
                    file_store()
                        .store(key_pkcs8_der)
                        .map_err(internal_store_err)?;
                    Ok(KeyStoreKind::File)
                }
                Err(err) => Err(internal_store_err(err)),
            }
        }
    }
}

/// `docs/CLI.md` §6.11: key-store write failures are reported as
/// `INTERNAL` with `retryable: false`, not a bespoke code.
fn internal_store_err(err: KeyStoreError) -> OpError {
    OpError::new(
        ErrorCode::Internal,
        format!("failed to store the device key: {err}"),
    )
    .with_retryable(false)
}

/// Absolute config directory as reported in `identity.init` data. Falls
/// back to the un-canonicalized path if the filesystem cannot resolve it.
fn canonical_config_dir(paths: &Paths) -> String {
    std::fs::canonicalize(&paths.config_dir)
        .unwrap_or_else(|_| paths.config_dir.clone())
        .display()
        .to_string()
}

/// A freshly generated keypair + self-signed certificate.
struct Generated {
    cert_pem: String,
    key_pkcs8_der: zeroize::Zeroizing<Vec<u8>>,
    fingerprint: Fingerprint,
}

/// Generate an Ed25519 keypair and a 10-year self-signed device
/// certificate with `CN=<device_id>` and SAN URI `qsh://device/<device_id>`.
fn generate(device_id: &str) -> Result<Generated, OpError> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PublicKeyData as _, SanType,
    };
    use time::{Duration, OffsetDateTime};

    let internal = |what: &str, err: rcgen::Error| {
        OpError::new(ErrorCode::Internal, format!("{what}: {err}")).with_retryable(false)
    };

    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|err| internal("failed to generate an Ed25519 keypair", err))?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, device_id);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    let san = rcgen::string::Ia5String::try_from(format!("qsh://device/{device_id}"))
        .map_err(|err| internal("failed to build the device SAN URI", err))?;
    params.subject_alt_names = vec![SanType::URI(san)];

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(CERT_BACKDATE_MINUTES);
    params.not_after = now + Duration::days(CERT_VALIDITY_DAYS);

    let cert = params
        .self_signed(&key)
        .map_err(|err| internal("failed to self-sign the device certificate", err))?;

    let fingerprint = Fingerprint::of_cert_der(cert.der()).map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("failed to fingerprint the device certificate: {err}"),
        )
        .with_retryable(false)
    })?;
    debug_assert_eq!(
        fingerprint,
        Fingerprint::of_spki_der(&key.subject_public_key_info()),
        "cert SPKI must be the keypair's public key"
    );

    Ok(Generated {
        cert_pem: cert.pem(),
        key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
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
}
