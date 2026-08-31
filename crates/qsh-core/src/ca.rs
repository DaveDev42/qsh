//! The private CA (`docs/adr/0008-private-ca-cert-issuance.md`): a single
//! self-signed root that signs device leaves directly, no intermediate.
//! `qsh cert init` creates the root; `qsh cert issue` "promotes" the
//! local device identity from self-signed to CA-issued by re-signing its
//! existing SAN (`qsh://device/<device_id>`) with its existing keypair —
//! the signer changes, nothing else does (ADR §2).
//!
//! ```text
//! <config_dir>/ca/       # 0700
//! ├── ca.pem              # root certificate (0600)
//! └── ca.key              # PKCS#8 PEM private key (0600)
//! ```
//!
//! Deliberately separate from `<config_dir>/identity/` (ADR §4): whether
//! this device can *issue* certs is a different threat than its own
//! identity, and the file tree should say so.
//!
//! Verification is entirely pre-existing and untouched by this module —
//! `qsh_transport::QshPeerVerifier::verify_core` already walks CA chains
//! against `TrustEvaluator::ca_roots()`, and `principal_from_san` already
//! parses the SAN this module reuses unchanged. This module only ever
//! *produces* bytes those already-tested paths consume.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};
use time::{Duration, OffsetDateTime};

use qsh_proto::ErrorCode;
use qsh_transport::Fingerprint;

use crate::config::{Paths, config_io_error, ensure_private_dir, write_private_file};
use crate::identity::pem;
use crate::ops::OpError;

/// File name of the CA root certificate (PEM).
pub const CA_CERT_FILE: &str = "ca.pem";
/// File name of the CA private key (PKCS#8 PEM).
pub const CA_KEY_FILE: &str = "ca.key";

/// How long a freshly generated CA root is valid. Longer than a device
/// leaf: re-issuing every device it signed is the only way to rotate it
/// in M7 (ADR §6 결과: rotation/CRL/OCSP is explicitly P1).
const CA_VALIDITY_DAYS: i64 = 3650 * 2;
/// Backdate `not_before` to absorb small clock skew between peers,
/// matching `identity`'s own backdating.
const BACKDATE_MINUTES: i64 = 5;
/// Validity window of an issued device leaf — matches
/// `identity`'s own device-cert validity.
const LEAF_VALIDITY_DAYS: i64 = 3650;

/// Fixed `CommonName` of the local CA root. The CA has no principal of its
/// own (ADR §1) — this exists only so the root certificate has a
/// human-legible subject; it is never parsed back into a `Principal`.
const CA_COMMON_NAME: &str = "qsh private CA";

/// The CA root as loaded from disk.
#[derive(Debug, Clone)]
pub struct CaRoot {
    /// PEM-encoded root certificate — what `trust.toml [[ca]].cert_pem`
    /// stores verbatim.
    pub cert_pem: String,
    /// DER of the same certificate.
    pub cert_der: Vec<u8>,
    /// SPKI fingerprint of the root. Never a peer trust decision by
    /// itself (the CA path is chain-based, not fingerprint-based) — used
    /// only as this device's own "which CA issued my leaf" marker.
    pub fingerprint: Fingerprint,
}

/// Result of [`init`].
pub struct CaInit {
    /// The root — freshly created, or the one already on disk.
    pub root: CaRoot,
    /// `false` when a CA already existed in this config directory.
    pub created: bool,
}

/// Create the local CA root if it does not exist yet (idempotent — an
/// existing root is returned unchanged with `created: false`, mirroring
/// `identity::init`'s own idempotency shape).
pub fn init(paths: &Paths) -> Result<CaInit, OpError> {
    ensure_private_dir(&paths.config_dir)?;
    let ca_dir = paths.ca_dir();
    ensure_private_dir(&ca_dir)?;

    if let Some(root) = read_root(paths)? {
        return Ok(CaInit {
            root,
            created: false,
        });
    }

    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|err| internal("failed to generate the CA keypair", err))?;
    let mut params = ca_issuer_params();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(BACKDATE_MINUTES);
    params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
    let cert = params
        .self_signed(&key)
        .map_err(|err| internal("failed to self-sign the CA root", err))?;

    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let fingerprint = Fingerprint::of_cert_der(&cert_der).map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("failed to fingerprint the CA root: {err}"),
        )
        .with_retryable(false)
    })?;

    // Key first: orphaning it on a crash before `ca.pem` lands is
    // harmless (nothing has registered it anywhere yet). `ca.pem` lands
    // last, so its presence is exactly the completion marker `read_root`
    // checks for — mirrors `identity::init`'s identity.toml-last rule.
    let key_pem = pem::encode(pem::PRIVATE_KEY, &key.serialize_der());
    write_private_file(&ca_dir.join(CA_KEY_FILE), key_pem.as_bytes())?;
    write_private_file(&ca_dir.join(CA_CERT_FILE), cert_pem.as_bytes())?;

    Ok(CaInit {
        root: CaRoot {
            cert_pem,
            cert_der,
            fingerprint,
        },
        created: true,
    })
}

/// Read the CA root certificate (never the key) if `qsh cert init` has
/// already run in this config directory. `None` if it has not.
pub fn read_root(paths: &Paths) -> Result<Option<CaRoot>, OpError> {
    let cert_path = paths.ca_dir().join(CA_CERT_FILE);
    let text = match std::fs::read_to_string(&cert_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(config_io_error(&cert_path, "read", &err)),
    };
    let cert_der = pem::decode_first(pem::CERTIFICATE, &text).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("invalid CA root {}: {err}", cert_path.display()),
        )
        .with_retryable(false)
    })?;
    let fingerprint = Fingerprint::of_cert_der(&cert_der).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("invalid CA root {}: {err}", cert_path.display()),
        )
        .with_retryable(false)
    })?;
    Ok(Some(CaRoot {
        cert_pem: text,
        cert_der,
        fingerprint,
    }))
}

/// A freshly issued device leaf.
#[derive(Debug)]
pub struct IssuedLeaf {
    /// PEM-encoded leaf certificate — replaces `identity/device.pem`.
    pub cert_pem: String,
    /// DER of the same certificate.
    pub cert_der: Vec<u8>,
}

/// CA-sign `device_id`'s *existing* keypair into a fresh leaf under the
/// local CA root (ADR §2: identical SAN body, only the signer changes).
///
/// `device_key_pkcs8_der` must be the device's own already-stored private
/// key (`identity::load`) — this function never generates a new keypair,
/// which is what makes this a promotion rather than a replacement:
/// anything that already knows this device by its key continues to.
pub fn issue_device_leaf(
    paths: &Paths,
    device_id: &str,
    device_key_pkcs8_der: &[u8],
) -> Result<IssuedLeaf, OpError> {
    let ca_key_path = paths.ca_dir().join(CA_KEY_FILE);
    let key_text = std::fs::read_to_string(&ca_key_path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            OpError::new(
                ErrorCode::ConfigError,
                "no local CA; run `qsh cert init` first",
            )
            .with_retryable(false)
        } else {
            config_io_error(&ca_key_path, "read", &err)
        }
    })?;
    let ca_key_der = pem::decode_first(pem::PRIVATE_KEY, &key_text).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("invalid CA key {}: {err}", ca_key_path.display()),
        )
        .with_retryable(false)
    })?;
    let ca_key = KeyPair::try_from(ca_key_der.as_slice())
        .map_err(|err| internal("failed to parse the local CA key", err))?;

    let device_key = KeyPair::try_from(device_key_pkcs8_der)
        .map_err(|err| internal("failed to parse the device key", err))?;

    let issuer = rcgen::Issuer::new(ca_issuer_params(), &ca_key);

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, device_id);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    let san = rcgen::string::Ia5String::try_from(format!("qsh://device/{device_id}"))
        .map_err(|err| internal("failed to build the device SAN URI", err))?;
    params.subject_alt_names = vec![SanType::URI(san)];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(BACKDATE_MINUTES);
    params.not_after = now + Duration::days(LEAF_VALIDITY_DAYS);

    let cert = params
        .signed_by(&device_key, &issuer)
        .map_err(|err| internal("failed to CA-sign the device certificate", err))?;

    Ok(IssuedLeaf {
        cert_pem: cert.pem(),
        cert_der: cert.der().to_vec(),
    })
}

/// The fixed issuer identity used both to self-sign the root ([`init`])
/// and, reconstructed identically, to sign device leaves
/// ([`issue_device_leaf`]).
///
/// `CertificateParams` is never persisted between CLI invocations — `qsh
/// cert init` and `qsh cert issue` are separate processes — so both call
/// sites must derive the exact same `DistinguishedName` here for a signed
/// leaf's `issuer` field to match the root's own `subject` field, which
/// is what lets ordinary X.509 chain building (inside
/// `QshPeerVerifier::verify_core`) find the root at all.
fn ca_issuer_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
}

fn internal(what: &str, err: rcgen::Error) -> OpError {
    OpError::new(ErrorCode::Internal, format!("{what}: {err}")).with_retryable(false)
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

        let first = init(&paths).unwrap();
        assert!(first.created);
        assert!(paths.ca_dir().join(CA_CERT_FILE).is_file());
        assert!(paths.ca_dir().join(CA_KEY_FILE).is_file());

        let second = init(&paths).unwrap();
        assert!(!second.created);
        assert_eq!(second.root.fingerprint, first.root.fingerprint);
        assert_eq!(second.root.cert_pem, first.root.cert_pem);
    }

    #[cfg(unix)]
    #[test]
    fn init_writes_private_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_guard, paths) = temp_paths();
        init(&paths).unwrap();

        let dir_mode = std::fs::metadata(paths.ca_dir())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        for file in [CA_CERT_FILE, CA_KEY_FILE] {
            let mode = std::fs::metadata(paths.ca_dir().join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{file} must be 0600");
        }
    }

    #[test]
    fn read_root_is_none_before_init_and_some_after() {
        let (_guard, paths) = temp_paths();
        assert!(read_root(&paths).unwrap().is_none());

        let created = init(&paths).unwrap();
        let read_back = read_root(&paths).unwrap().expect("root after init");
        assert_eq!(read_back.fingerprint, created.root.fingerprint);
        assert_eq!(read_back.cert_pem, created.root.cert_pem);
    }

    /// No local CA yet: `issue_device_leaf` must fail closed with
    /// `CONFIG_ERROR`, never generate or write anything
    /// (`ops::cert::CertIssueOp`'s own no-resource-before-prerequisite
    /// invariant, proven here at the pure-function level too).
    #[test]
    fn issue_device_leaf_before_init_is_a_config_error() {
        let (_guard, paths) = temp_paths();
        let device_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();

        let err =
            issue_device_leaf(&paths, "device_abc123", &device_key.serialize_der()).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(!err.retryable);
    }

    /// The core ADR-0008 §2 promotion claim, at the unit level: a leaf
    /// issued for `device_id` over a caller-supplied keypair carries
    /// exactly the same `qsh://device/<device_id>` SAN the *existing*,
    /// already-tested `principal_from_san` parser expects — proof that
    /// this module needs zero new SAN-parsing code, reusing it unchanged.
    #[test]
    fn issue_device_leaf_carries_the_device_san_and_signs_with_the_same_key() {
        let (_guard, paths) = temp_paths();
        init(&paths).unwrap();
        let device_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let device_key_der = device_key.serialize_der();

        let leaf = issue_device_leaf(&paths, "device_abc123", &device_key_der).unwrap();

        let principal = qsh_transport::identity::principal_from_san(&leaf.cert_der)
            .unwrap()
            .expect("device SAN");
        assert_eq!(
            principal,
            qsh_transport::Principal::Device("device_abc123".into())
        );

        // The leaf's own SPKI fingerprint must match the caller-supplied
        // key, not a freshly generated one — the "promotion, not
        // replacement" claim (ADR §2): whatever already trusts this
        // device's public key continues to.
        let leaf_fp = Fingerprint::of_cert_der(&leaf.cert_der).unwrap();
        let key_fp =
            Fingerprint::of_spki_der(&rcgen::PublicKeyData::subject_public_key_info(&device_key));
        assert_eq!(leaf_fp, key_fp);
    }

    /// Garbage key bytes must not panic — a clean `INTERNAL` error instead.
    #[test]
    fn issue_device_leaf_with_a_malformed_device_key_is_an_internal_error() {
        let (_guard, paths) = temp_paths();
        init(&paths).unwrap();

        let err = issue_device_leaf(&paths, "device_abc123", b"not a real pkcs8 key").unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert!(!err.retryable);
    }

    /// Re-issuing for a different `device_id` produces a distinct SAN each
    /// time — `issue_device_leaf` never caches or reuses a prior leaf
    /// (idempotency across repeated `cert issue` calls is `ops::cert`'s
    /// job, comparing `Identity.issued_by_ca`, not this pure function's).
    #[test]
    fn issue_device_leaf_reflects_the_requested_device_id_each_call() {
        let (_guard, paths) = temp_paths();
        init(&paths).unwrap();
        let key_a = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let key_b = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();

        let leaf_a = issue_device_leaf(&paths, "device_aaa", &key_a.serialize_der()).unwrap();
        let leaf_b = issue_device_leaf(&paths, "device_bbb", &key_b.serialize_der()).unwrap();

        let principal_a = qsh_transport::identity::principal_from_san(&leaf_a.cert_der)
            .unwrap()
            .unwrap();
        let principal_b = qsh_transport::identity::principal_from_san(&leaf_b.cert_der)
            .unwrap()
            .unwrap();
        assert_eq!(
            principal_a,
            qsh_transport::Principal::Device("device_aaa".into())
        );
        assert_eq!(
            principal_b,
            qsh_transport::Principal::Device("device_bbb".into())
        );
        assert_ne!(leaf_a.cert_der, leaf_b.cert_der);
    }

    /// Crash-safety regression for the key-before-cert write order the
    /// module doc and `init`'s own inline comment promise: forces the
    /// *second* write (`ca.pem`) to fail by pre-occupying its exact atomic-
    /// rename temp path (`ca.pem.tmp<pid>`) with a directory, so whichever
    /// file `init` writes first genuinely lands on disk before the call
    /// errors out — proof of the real order, not an assumption about it.
    /// If that order were ever reversed (cert first, key last), the *cert*
    /// write — the one whose temp path we block — would be attempted
    /// first and `init` would fail before ever touching `ca.key`.
    #[test]
    fn init_recovers_from_an_interrupted_cert_write() {
        let (_guard, paths) = temp_paths();
        ensure_private_dir(&paths.config_dir).unwrap();
        let ca_dir = paths.ca_dir();
        ensure_private_dir(&ca_dir).unwrap();

        let cert_tmp = ca_dir.join(format!("{CA_CERT_FILE}.tmp{}", std::process::id()));
        std::fs::create_dir(&cert_tmp).unwrap();

        let err = match init(&paths) {
            Err(err) => err,
            Ok(_) => panic!("init must fail while ca.pem's write is blocked"),
        };
        assert_eq!(err.code, ErrorCode::ConfigError);

        // The key must already be on disk: written before the cert, so it
        // survives the cert write's failure.
        assert!(
            ca_dir.join(CA_KEY_FILE).is_file(),
            "the key must be written before the cert"
        );
        assert!(!ca_dir.join(CA_CERT_FILE).is_file());

        // Clear the blocker and confirm this half-written state is not
        // mistaken for a completed init.
        std::fs::remove_dir(&cert_tmp).unwrap();
        assert!(read_root(&paths).unwrap().is_none());

        // A follow-up `init` must recover cleanly into a fully valid root,
        // discarding the orphaned key rather than trusting it.
        let recovered = init(&paths).unwrap();
        assert!(recovered.created);
        let read_back = read_root(&paths)
            .unwrap()
            .expect("root after recovery init");
        assert_eq!(read_back.fingerprint, recovered.root.fingerprint);
    }
}
