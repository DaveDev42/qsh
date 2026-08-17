//! Minimal PEM encode/decode for the two labels QSH stores on disk:
//! `CERTIFICATE` (`identity/device.pem`, trust store CA entries) and
//! `PRIVATE KEY` (`identity/device.key`, file key-store mode).
//!
//! Deliberately tiny and dependency-free: QSH only ever reads back what it
//! itself wrote (plus operator-pasted CA certs), so a full PEM parser would
//! be more attack surface than value.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
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
}
