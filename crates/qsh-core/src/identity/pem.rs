//! Minimal PEM encode/decode for the two labels QSH stores on disk:
//! `CERTIFICATE` (`identity/device.pem`, trust store CA entries) and
//! `PRIVATE KEY` (`identity/device.key`, file key-store mode).
//!
//! Deliberately tiny and dependency-free: QSH only ever reads back what it
//! itself wrote (plus operator-pasted CA certs), so a full PEM parser would
//! be more attack surface than value.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use qsh_transport::Fingerprint;
use thiserror::Error;

/// PEM label for X.509 certificates.
pub(crate) const CERTIFICATE: &str = "CERTIFICATE";
/// PEM label for PKCS#8 private keys.
pub(crate) const PRIVATE_KEY: &str = "PRIVATE KEY";

/// A PEM document could not be decoded.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PemError {
    /// No `-----BEGIN <label>-----` / `-----END <label>-----` pair found.
    #[error("no PEM block labeled {0:?}")]
    NoBlock(String),
    /// The Base64 payload was not decodable.
    #[error("invalid base64 in PEM block labeled {0:?}")]
    BadBase64(String),
}

/// Encode `der` as a PEM block with 64-column Base64 lines.
pub(crate) fn encode(label: &str, der: &[u8]) -> String {
    let body = BASE64.encode(der);
    let mut out = String::with_capacity(body.len() + body.len() / 64 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Decode every PEM block with `label` in `text`, in document order.
pub(crate) fn decode_all(label: &str, text: &str) -> Result<Vec<Vec<u8>>, PemError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else {
            break;
        };
        let body: String = after[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = BASE64
            .decode(body.as_bytes())
            .map_err(|_| PemError::BadBase64(label.to_string()))?;
        out.push(der);
        rest = &after[stop + end.len()..];
    }
    if out.is_empty() {
        return Err(PemError::NoBlock(label.to_string()));
    }
    Ok(out)
}

/// Decode the first PEM block with `label` in `text`.
pub(crate) fn decode_first(label: &str, text: &str) -> Result<Vec<u8>, PemError> {
    decode_all(label, text).map(|mut blocks| blocks.swap_remove(0))
}

/// Every `-----BEGIN <label>-----` header in `text`, in document order —
/// unlike [`decode_all`], this sees every label, including one
/// `decode_all(CERTIFICATE, …)` cannot itself distinguish from absent
/// (`PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`,
/// `ENCRYPTED PRIVATE KEY`, …). [`single_certificate`]'s foreign-block
/// check is why this exists (ADR-0013 결정 4).
pub(crate) fn block_labels(text: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN ";
    const DASHES: &str = "-----";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(DASHES) else {
            break;
        };
        out.push(after[..end].to_string());
        rest = &after[end..];
    }
    out
}

/// An operator-supplied PEM document (`trust add --cert-file`, `trust
/// add-ca`) failed one of the structural checks ADR-0013 결정 4 requires
/// before its fingerprint can be trusted. Every variant maps to
/// `INVALID_ARGUMENT` with `details: Value::Null` — the message never
/// contains any byte of the input (ADR-0013 결정 4).
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum CertPemError {
    /// Zero, or two-or-more, `CERTIFICATE` blocks (empty file, or a
    /// chain/bundle) — `decode_all`/`block_labels` never see mixed content
    /// in this case (see [`ForeignBlock`](Self::ForeignBlock) for that).
    #[error("cert file must contain exactly one CERTIFICATE block")]
    NotExactlyOneCertificate,
    /// At least one PEM block is not labeled `CERTIFICATE` — including
    /// every private-key label, which [`decode_all`] alone cannot see.
    #[error("cert file carries a non-certificate PEM block")]
    ForeignBlock,
    /// The lone `CERTIFICATE` block's Base64 payload does not decode.
    #[error("cert file is not valid PEM")]
    NotValidPem,
    /// The decoded DER does not parse as an X.509 certificate
    /// (`qsh_transport::Fingerprint::of_cert_der`).
    #[error("cert file is not a valid X.509 certificate")]
    InvalidX509,
}

/// Validate operator-supplied PEM text for `trust add --cert-file`/`trust
/// add-ca` (ADR-0013 결정 4/5): the block-label multiset must be exactly
/// `["CERTIFICATE"]`, [`decode_all`] must yield exactly one block, and the
/// DER must parse as X.509 — `qsh_transport::Fingerprint::of_cert_der`
/// already parses with `x509-parser`, so this needs no new dependency
/// (`qsh-core` already carries `qsh-transport`). Returns the certificate
/// DER and its SPKI fingerprint on success; `trust add-ca` computes and
/// discards the fingerprint (a CA root has no principal of its own).
pub(crate) fn single_certificate(text: &str) -> Result<(Vec<u8>, Fingerprint), CertPemError> {
    let labels = block_labels(text);
    if labels.iter().any(|label| label != CERTIFICATE) {
        return Err(CertPemError::ForeignBlock);
    }
    if labels.len() != 1 {
        return Err(CertPemError::NotExactlyOneCertificate);
    }
    let der = decode_first(CERTIFICATE, text).map_err(|_| CertPemError::NotValidPem)?;
    let fingerprint = Fingerprint::of_cert_der(&der).map_err(|_| CertPemError::InvalidX509)?;
    Ok((der, fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_wraps_at_64_columns() {
        let der: Vec<u8> = (0u8..=255).collect();
        let pem = encode(CERTIFICATE, &der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64, "line too long: {line}");
        }
        assert_eq!(decode_first(CERTIFICATE, &pem).unwrap(), der);
    }

    #[test]
    fn decodes_several_blocks_and_ignores_surrounding_text() {
        let text = format!(
            "# a comment\n{}\nmiddle noise\n{}\n",
            encode(CERTIFICATE, b"first"),
            encode(CERTIFICATE, b"second")
        );
        let blocks = decode_all(CERTIFICATE, &text).unwrap();
        assert_eq!(blocks, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn wrong_label_and_garbage_are_errors() {
        let pem = encode(PRIVATE_KEY, b"x");
        assert_eq!(
            decode_first(CERTIFICATE, &pem).unwrap_err(),
            PemError::NoBlock(CERTIFICATE.to_string())
        );
        let broken = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert_eq!(
            decode_first(CERTIFICATE, broken).unwrap_err(),
            PemError::BadBase64(CERTIFICATE.to_string())
        );
    }

    /// A real self-signed cert, for [`single_certificate`]'s success path
    /// and every failure row this test file drives.
    fn a_certificate_pem() -> String {
        use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "single-certificate-test");
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn block_labels_lists_every_header_in_order() {
        let text = format!("{}{}", encode(CERTIFICATE, b"a"), encode(PRIVATE_KEY, b"b"));
        assert_eq!(
            block_labels(&text),
            vec![CERTIFICATE.to_string(), PRIVATE_KEY.to_string()]
        );
        assert!(block_labels("no pem here").is_empty());
    }

    #[test]
    fn single_certificate_accepts_exactly_one_certificate_block() {
        let pem = a_certificate_pem();
        let (der, fingerprint) = single_certificate(&pem).expect("valid single cert");
        assert_eq!(der, decode_first(CERTIFICATE, &pem).unwrap());
        assert_eq!(fingerprint, Fingerprint::of_cert_der(&der).unwrap());
    }

    #[test]
    fn single_certificate_rejects_an_empty_document() {
        assert_eq!(
            single_certificate("not a pem file at all"),
            Err(CertPemError::NotExactlyOneCertificate)
        );
    }

    #[test]
    fn single_certificate_rejects_a_chain_of_two_certificates() {
        let text = format!("{}{}", a_certificate_pem(), a_certificate_pem());
        assert_eq!(
            single_certificate(&text),
            Err(CertPemError::NotExactlyOneCertificate)
        );
    }

    #[test]
    fn single_certificate_rejects_a_bundle_carrying_a_private_key() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let text = format!(
            "{}{}",
            a_certificate_pem(),
            encode(PRIVATE_KEY, &key.serialize_der())
        );
        assert_eq!(single_certificate(&text), Err(CertPemError::ForeignBlock));
    }

    #[test]
    fn single_certificate_rejects_bad_base64() {
        let broken = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert_eq!(single_certificate(broken), Err(CertPemError::NotValidPem));
    }

    #[test]
    fn single_certificate_rejects_non_x509_der() {
        let pem = encode(CERTIFICATE, b"not actually a certificate");
        assert_eq!(single_certificate(&pem), Err(CertPemError::InvalidX509));
    }
}
