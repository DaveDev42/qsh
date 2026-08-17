//! Certificate-derived identity primitives: SPKI fingerprints and the
//! [`Principal`] a verified peer certificate reduces to.
//!
//! These are shared by the verifier (`tls.rs`), by `qsh-core`'s identity and
//! trust modules, and by the ACL/audit layer. The principal is **always**
//! derived from the certificate — never from `Hello` or any other wire
//! field (`docs/design/protocol.md` §3, `docs/design/architecture.md` §5).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::prelude::*;

/// Textual prefix of a fingerprint: `sha256:BASE64`.
pub const FINGERPRINT_PREFIX: &str = "sha256:";

/// SHA-256 over the DER-encoded SubjectPublicKeyInfo of a certificate.
///
/// This — not the whole certificate — is what QSH pins: it survives cert
/// re-issuance with the same key and is what SSH users expect a
/// "fingerprint" to mean.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute the SPKI SHA-256 fingerprint of a DER-encoded X.509 cert.
    pub fn of_cert_der(cert_der: &[u8]) -> Result<Self, CertParseError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| CertParseError(format!("x509 parse: {e}")))?;
        Ok(Self::of_spki_der(cert.tbs_certificate.subject_pki.raw))
    }

    /// Compute the fingerprint of an already-extracted SPKI DER blob (e.g.
    /// `rcgen::KeyPair::public_key_der()`).
    pub fn of_spki_der(spki_der: &[u8]) -> Self {
        let digest = Sha256::digest(spki_der);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    /// `sha256:` + standard Base64 (with padding), per `docs/CLI.md` §2.3 and
    /// `docs/design/architecture.md` §5.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{FINGERPRINT_PREFIX}{}", BASE64.encode(self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Failure to parse a fingerprint string.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid fingerprint {0:?}: expected sha256:<base64 of 32 bytes>")]
pub struct FingerprintParseError(pub String);

impl FromStr for Fingerprint {
    type Err = FingerprintParseError;

    /// Accepts `sha256:` (any case) followed by standard Base64 of exactly 32
    /// bytes; padding may be omitted. Output formatting is always canonical
    /// (`Display`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        // Byte-wise ASCII-case-insensitive prefix match; never slice `s`
        // at a byte offset that might not be a char boundary (the input is
        // untrusted user text and may contain multi-byte characters).
        let rest = match s
            .as_bytes()
            .get(..FINGERPRINT_PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(FINGERPRINT_PREFIX.as_bytes()))
        {
            // The prefix is pure ASCII, so its byte length is a char boundary.
            Some(_) => &s[FINGERPRINT_PREFIX.len()..],
            None => return Err(FingerprintParseError(s.to_string())),
        };
        let rest = rest.trim_end_matches('=');
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(rest)
            .map_err(|_| FingerprintParseError(s.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| FingerprintParseError(s.to_string()))?;
        Ok(Self(arr))
    }
}

/// Failure to parse a DER certificate.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct CertParseError(pub String);

/// The authenticated identity attached to a connection after the TLS
/// handshake. This is the *only* input the ACL layer sees.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
    /// A pinned peer, named by its trust-store alias: `device:<name>`.
    Device(String),
    /// A user asserted by a private-CA-signed cert (SAN `qsh://user/<name>`):
    /// `user:<name>`.
    User(String),
    /// A peer authenticated by fingerprint alone (no alias): `fp:<sha256:…>`.
    /// Not produced in M1 (every pin has a name) but reserved by the design.
    Fingerprint(Fingerprint),
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::Device(name) => write!(f, "device:{name}"),
            Principal::User(name) => write!(f, "user:{name}"),
            Principal::Fingerprint(fp) => write!(f, "fp:{fp}"),
        }
    }
}

/// Extract the QSH principal from a CA-signed leaf certificate's SAN URIs
/// (`qsh://user/<name>` → `User`, `qsh://device/<name>` → `Device`).
/// Returns `None` if the cert has no recognized SAN URI.
pub fn principal_from_san(cert_der: &[u8]) -> Result<Option<Principal>, CertParseError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| CertParseError(format!("x509 parse: {e}")))?;
    let san = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext.value,
        Ok(None) => return Ok(None),
        Err(e) => return Err(CertParseError(format!("SAN extension: {e}"))),
    };
    for name in &san.general_names {
        let GeneralName::URI(uri) = name else {
            continue;
        };
        let parsed = if let Some(user) = uri.strip_prefix("qsh://user/") {
            valid_segment(user).then(|| Principal::User(user.to_string()))
        } else if let Some(device) = uri.strip_prefix("qsh://device/") {
            valid_segment(device).then(|| Principal::Device(device.to_string()))
        } else {
            None
        };
        if parsed.is_some() {
            return Ok(parsed);
        }
    }
    Ok(None)
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty() && !s.contains('/')
}

/// Read the validity window (`not_before`, `not_after`) of a DER cert as
/// UNIX seconds.
pub fn validity_unix(cert_der: &[u8]) -> Result<(i64, i64), CertParseError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| CertParseError(format!("x509 parse: {e}")))?;
    let v = cert.validity();
    Ok((v.not_before.timestamp(), v.not_after.timestamp()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_display_and_parse_roundtrip() {
        let fp = Fingerprint::of_spki_der(b"not really an spki but deterministic");
        let s = fp.to_string();
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.parse::<Fingerprint>().unwrap(), fp);
        // Case-insensitive prefix, unpadded also accepted.
        let upper = format!("SHA256:{}", s.trim_start_matches("sha256:"));
        assert_eq!(upper.parse::<Fingerprint>().unwrap(), fp);
        let unpadded = s.trim_end_matches('=').to_string();
        assert_eq!(unpadded.parse::<Fingerprint>().unwrap(), fp);
    }

    #[test]
    fn fingerprint_rejects_garbage() {
        assert!("sha256:".parse::<Fingerprint>().is_err());
        assert!("md5:AAAA".parse::<Fingerprint>().is_err());
        assert!("sha256:AAAA".parse::<Fingerprint>().is_err()); // wrong length
        assert!("".parse::<Fingerprint>().is_err());
        // Multi-byte input shorter/longer than the prefix must not panic
        // on a char boundary (regression: `split_at` on untrusted text).
        assert!("샤256:AAAA".parse::<Fingerprint>().is_err());
        assert!("sha25６:AAAA".parse::<Fingerprint>().is_err());
        assert!("é".parse::<Fingerprint>().is_err());
        assert!("ééééé".parse::<Fingerprint>().is_err());
        assert!("sha256:é".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn principal_display() {
        assert_eq!(Principal::Device("mac".into()).to_string(), "device:mac");
        assert_eq!(Principal::User("dave".into()).to_string(), "user:dave");
        let fp = Fingerprint::of_spki_der(b"x");
        assert_eq!(Principal::Fingerprint(fp).to_string(), format!("fp:{fp}"));
    }
}
