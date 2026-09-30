//! Deterministic OpenSSH key material for the `--import-ssh-key` and
//! `trust ssh-preview` tests (ADR-0026).
//!
//! The golden key is the test-only Ed25519 key checked in as hex under
//! `crates/qsh-proto/testdata/openssh/`; nothing here reads the
//! developer's `~/.ssh` or runs `ssh-keygen`. The non-golden keys
//! (encrypted, RSA, malformed) are synthesized at run time from the
//! `openssh-key-v1` layout, so no PEM armor line is checked in.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use base64::Engine as _;

const GOLDEN_HEX: &str = include_str!("../../../qsh-proto/testdata/openssh/ed25519_golden.hex");

/// Public half of the golden key.
pub const GOLDEN_PUBLIC_HEX: &str =
    "c5823db0474406fc8765512b49112913f128b2418dfbaddee18ae88c7f54b23f";
/// `ssh-keygen -lf` output for the golden key.
pub const GOLDEN_SSH_FINGERPRINT: &str = "SHA256:XxSbKVKvD1gyArwLk6oM3TZnt9rZogny7tQgxWR2bek";
/// The golden key's `authorized_keys` / `.pub` line.
pub const GOLDEN_PUB_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMWCPbBHRAb8h2VRK0kRKRPxKLJBjfut3uGK6Ix/VLI/ qsh-test-only";

/// A well-formed `ssh-rsa` authorized_keys line (the blob is only the key
/// type string; the classifier never looks further for other key types).
pub const RSA_PUB_LINE: &str = "ssh-rsa AAAAB3NzaC1yc2E= rsa-key";

/// The ASN.1 prefix of an Ed25519 SubjectPublicKeyInfo; the 32-byte public
/// key follows it directly.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.bytes())
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    assert_eq!(digits.len() % 2, 0);
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// The golden OpenSSH private key file bytes.
pub fn golden_key_file() -> Vec<u8> {
    unhex(GOLDEN_HEX)
}

/// SPKI DER of the golden public key (or any 32-byte Ed25519 key).
pub fn spki_der(public: &[u8]) -> Vec<u8> {
    assert_eq!(public.len(), 32);
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(public);
    der
}

/// The qsh fingerprint `qsh init --import-ssh-key` must report for the
/// golden key: SPKI SHA-256, the same value a leaf certificate over that
/// key carries.
pub fn golden_qsh_fingerprint() -> String {
    qsh_core::Fingerprint::of_spki_der(&spki_der(&unhex(GOLDEN_PUBLIC_HEX))).to_string()
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Armor a binary `openssh-key-v1` body the way `ssh-keygen` does.
pub fn pem_from_body(body: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(body);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out.into_bytes()
}

fn body(cipher: &[u8], kdf: &[u8], kdf_options: &[u8], key_type: &[u8]) -> Vec<u8> {
    let mut out = b"openssh-key-v1\0".to_vec();
    put_string(&mut out, cipher);
    put_string(&mut out, kdf);
    put_string(&mut out, kdf_options);
    out.extend_from_slice(&1u32.to_be_bytes());
    let mut public = Vec::new();
    put_string(&mut public, key_type);
    put_string(&mut public, &[7u8; 32]);
    put_string(&mut out, &public);
    put_string(&mut out, &[0u8; 8]);
    out
}

/// A key file whose cipher is not `none` (passphrase protected).
pub fn encrypted_key_file() -> Vec<u8> {
    pem_from_body(&body(b"aes256-ctr", b"bcrypt", &[0u8; 24], b"ssh-ed25519"))
}

/// A well-formed envelope carrying an RSA key type.
pub fn rsa_key_file() -> Vec<u8> {
    pem_from_body(&body(b"none", b"none", b"", b"ssh-rsa"))
}

/// A syntactically valid armor whose body is `marker` bytes behind the
/// `openssh-key-v1` magic: rejected as malformed, and a leak of the input
/// into an error would carry the marker.
pub fn malformed_key_file_with(marker: &[u8]) -> Vec<u8> {
    let mut body = b"openssh-key-v1\0".to_vec();
    body.extend_from_slice(marker);
    pem_from_body(&body)
}

pub fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write key fixture");
    path
}
