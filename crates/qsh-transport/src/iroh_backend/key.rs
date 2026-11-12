//! The qsh identity key as an iroh key (ADR-0061 decision 3).
//!
//! A qsh identity is an Ed25519 key with a self-signed certificate. iroh
//! names an endpoint by its Ed25519 public key (`EndpointId`) and signs its
//! handshake with the matching `SecretKey`, so the same key serves both. The
//! qsh fingerprint is the SHA-256 of the key's SubjectPublicKeyInfo, which
//! depends on the key alone, so it can be computed from an `EndpointId`
//! without any certificate and equals what the certificate-based path
//! reports for the same key (`trust.toml` pins keep working unchanged).

use iroh::{EndpointId, SecretKey};

use crate::endpoint::{LocalIdentity, SetupError};
use crate::identity::Fingerprint;

/// DER of the fixed SPKI header for an Ed25519 key (RFC 8410): SEQUENCE {
/// SEQUENCE { OID 1.3.101.112 }, BIT STRING (33 bytes, 0 unused bits) }.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// DER content of the Ed25519 `AlgorithmIdentifier` SEQUENCE body
/// (OID 1.3.101.112, no parameters).
const ED25519_ALG_BODY: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// The qsh fingerprint (SPKI SHA-256) of an Ed25519 public key.
pub(crate) fn fingerprint_of_key(key: &[u8; 32]) -> Fingerprint {
    let mut spki = [0u8; 44];
    spki[..12].copy_from_slice(&ED25519_SPKI_PREFIX);
    spki[12..].copy_from_slice(key);
    Fingerprint::of_spki_der(&spki)
}

/// The qsh fingerprint of an iroh endpoint id.
pub(crate) fn fingerprint_of_endpoint(id: &EndpointId) -> Fingerprint {
    fingerprint_of_key(id.as_bytes())
}

/// One DER TLV: `(tag, content, rest)`. Only definite lengths up to 4 length
/// bytes, which is all a PKCS#8 Ed25519 key uses.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// The 32-byte Ed25519 seed inside a PKCS#8 `PrivateKeyInfo` (RFC 5958, v1 or
/// v2), or `None` when the DER is malformed or the key is not Ed25519.
fn ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let (tag, body, _) = tlv(pkcs8)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, _version, rest) = tlv(body)?;
    if tag != 0x02 {
        return None;
    }
    let (tag, alg, rest) = tlv(rest)?;
    if tag != 0x30 || alg != ED25519_ALG_BODY {
        return None;
    }
    let (tag, private_key, _) = tlv(rest)?;
    if tag != 0x04 {
        return None;
    }
    // The OCTET STRING wraps a CurvePrivateKey, itself an OCTET STRING.
    let (tag, seed, _) = tlv(private_key)?;
    if tag != 0x04 {
        return None;
    }
    seed.try_into().ok()
}

impl LocalIdentity {
    /// The identity key as an iroh [`SecretKey`]. Fails when the key is not
    /// an Ed25519 PKCS#8 key, or when the identity's leaf certificate is
    /// for a different key (a mismatched identity would make the iroh
    /// endpoint present a fingerprint the host never pinned).
    pub(crate) fn iroh_secret_key(&self) -> Result<SecretKey, SetupError> {
        let seed = ed25519_seed(&self.key_pkcs8_der).ok_or_else(|| {
            SetupError::Iroh("the identity key is not an Ed25519 PKCS#8 key".into())
        })?;
        let secret = SecretKey::from_bytes(&seed);
        if let Some(leaf) = self.cert_chain.first() {
            let expected = fingerprint_of_endpoint(&secret.public());
            let actual = Fingerprint::of_cert_der(leaf)
                .map_err(|e| SetupError::Iroh(format!("identity certificate: {e}")))?;
            if expected != actual {
                return Err(SetupError::Iroh(
                    "the identity certificate does not belong to the identity key".into(),
                ));
            }
        }
        Ok(secret)
    }

    /// The Ed25519 public key iroh knows this identity by (its
    /// `EndpointId`), as raw bytes. This is what a peer dials and what the
    /// qsh fingerprint is derived from.
    pub fn iroh_public_key(&self) -> Result<[u8; 32], SetupError> {
        Ok(*self.iroh_secret_key()?.public().as_bytes())
    }
}

/// The qsh fingerprint of a raw Ed25519 public key, the form an iroh peer is
/// named in.
pub fn fingerprint_of_ed25519_key(key: &[u8; 32]) -> Fingerprint {
    fingerprint_of_key(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> LocalIdentity {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let cert = params.self_signed(&key).unwrap();
        LocalIdentity {
            cert_chain: vec![cert.der().to_vec().into()],
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        }
    }

    /// The fingerprint computed from the bare key equals the one the
    /// certificate path computes, so existing pins match.
    #[test]
    fn key_fingerprint_equals_the_certificate_fingerprint() {
        let id = identity();
        let from_cert = Fingerprint::of_cert_der(&id.cert_chain[0]).unwrap();
        let key = id.iroh_public_key().unwrap();
        assert_eq!(fingerprint_of_key(&key), from_cert);
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        let a = identity();
        let b = identity();
        let mixed = LocalIdentity {
            cert_chain: b.cert_chain.clone(),
            key_pkcs8_der: a.key_pkcs8_der.clone(),
        };
        assert!(matches!(mixed.iroh_secret_key(), Err(SetupError::Iroh(_))));
    }

    #[test]
    fn a_non_ed25519_key_is_refused() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let id = LocalIdentity {
            cert_chain: Vec::new(),
            key_pkcs8_der: zeroize::Zeroizing::new(key.serialize_der()),
        };
        assert!(matches!(id.iroh_secret_key(), Err(SetupError::Iroh(_))));
    }

    #[test]
    fn garbage_is_refused() {
        for bad in [&[][..], &[0x30][..], &[0x30, 0x03, 0x02, 0x01, 0x00][..]] {
            assert_eq!(ed25519_seed(bad), None);
        }
    }
}
