//! `qsh init --import-ssh-key`: reads a plaintext OpenSSH Ed25519 private
//! key and turns it into the PKCS#8 key the identity code already knows how
//! to certify and store (ADR-0026).
//!
//! Private key bytes only ever live in [`Zeroizing`] buffers here, are never
//! placed in an error, a `details` payload or a log line, and the file read
//! is bounded by [`SSH_KEY_FILE_MAX`] so an oversized path (a device node, a
//! huge file) is never buffered in full.

use std::fs::File;
use std::io::Read as _;

use base64::Engine as _;
use qsh_proto::openssh::{
    Ed25519PrivateKey, OpensshKeyError, ed25519_wire_blob, parse_openssh_private_key,
};
use qsh_proto::{ErrorCode, wire};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::ops::OpError;

/// Largest OpenSSH private key file `--import-ssh-key` reads. A plaintext
/// Ed25519 key file is about 400 bytes.
pub const SSH_KEY_FILE_MAX: usize = 16 * 1024;

/// Refusal text when `--import-ssh-key` meets an existing identity
/// (ADR-0026, `docs/CLI.md` §6.11). The error envelope has no remedy field
/// (`docs/CLI.md` §3.2), so the next command lives in the message, in
/// observation, impact, next-command order.
pub const IMPORT_SSH_KEY_IDENTITY_EXISTS: &str = "An identity already exists in this config directory; --import-ssh-key only creates a new one. To use the SSH key instead, remove identity/ from the config directory and re-run `qsh init --import-ssh-key <path>` \u{2014} peers must then re-pin. In-place key rotation does not exist yet.";

/// An imported key, ready for [`super::generate`].
pub(super) struct ImportedKey {
    /// PKCS#8 v2 DER (private key plus public key) of the Ed25519 key.
    pub(super) pkcs8_der: Zeroizing<Vec<u8>>,
    /// The 32-byte public key from the file, cross-checked against the
    /// key pair derived from the seed.
    pub(super) public: [u8; 32],
    /// `SHA256:<unpadded base64>` of the OpenSSH wire public key blob.
    pub(super) ssh_fingerprint: String,
}

/// `SHA256:` + unpadded base64 of the SHA-256 of an OpenSSH wire public key
/// blob: the exact string `ssh-keygen -lf` prints.
pub fn ssh_fingerprint(wire_blob: &[u8]) -> String {
    let digest = Sha256::digest(wire_blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// SSH fingerprint of an Ed25519 public key.
pub fn ssh_fingerprint_of_ed25519(public: &[u8; 32]) -> String {
    ssh_fingerprint(&ed25519_wire_blob(public))
}

/// The DER of an Ed25519 `SubjectPublicKeyInfo`: the fixed algorithm prefix
/// followed by the 32-byte public key. This is what a leaf certificate over
/// the key carries, so its SHA-256 is the qsh fingerprint.
pub(crate) fn ed25519_spki_der(public: &[u8; 32]) -> [u8; 44] {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&PREFIX);
    der[12..].copy_from_slice(public);
    der
}

/// Assemble the RFC 8410 `OneAsymmetricKey` (PKCS#8 v2) DER of an Ed25519
/// key: version 1, algorithm `1.3.101.112`, the seed as `CurvePrivateKey`
/// and the public key in the `[1]` field. v2 carries the public key so the
/// crypto backend can check the pair instead of trusting the seed alone.
pub(crate) fn pkcs8_v2_ed25519(seed: &[u8; 32], public: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut der = Zeroizing::new(Vec::with_capacity(83));
    der.extend_from_slice(&[0x30, 0x51, 0x02, 0x01, 0x01]);
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(seed);
    der.extend_from_slice(&[0x81, 0x21, 0x00]);
    der.extend_from_slice(public);
    der
}

fn refuse(code: ErrorCode, kind: &str, message: String) -> OpError {
    OpError::new(code, message)
        .with_retryable(false)
        .with_details(serde_json::json!({ "reason": kind }))
}

/// Read `path` up to [`SSH_KEY_FILE_MAX`] bytes into a zeroizing buffer.
fn read_key_file(path: &str) -> Result<Zeroizing<Vec<u8>>, OpError> {
    let unreadable = |err: std::io::Error| {
        refuse(
            ErrorCode::InvalidArgument,
            "unreadable",
            format!("failed to read {}: {err}", wire::sanitize_peer_text(path)),
        )
    };
    let file = File::open(path).map_err(unreadable)?;
    let mut buf = Zeroizing::new(Vec::new());
    file.take(SSH_KEY_FILE_MAX as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(unreadable)?;
    if buf.len() > SSH_KEY_FILE_MAX {
        return Err(refuse(
            ErrorCode::InvalidArgument,
            "too_large",
            format!(
                "{} is larger than {SSH_KEY_FILE_MAX} bytes, so it is not an OpenSSH Ed25519 private key",
                wire::sanitize_peer_text(path)
            ),
        ));
    }
    Ok(buf)
}

fn parse_error(path: &str, err: OpensshKeyError) -> OpError {
    let shown = wire::sanitize_peer_text(path);
    match err {
        OpensshKeyError::Encrypted => refuse(
            ErrorCode::Unsupported,
            "encrypted",
            format!(
                "{shown} is passphrase protected; --import-ssh-key only reads unencrypted Ed25519 keys"
            ),
        ),
        OpensshKeyError::UnsupportedKeyType => refuse(
            ErrorCode::Unsupported,
            "key_type",
            format!("{shown} is not an ssh-ed25519 key; --import-ssh-key only reads Ed25519 keys"),
        ),
        OpensshKeyError::TooLarge => refuse(
            ErrorCode::InvalidArgument,
            "too_large",
            format!("{shown} is too large to be an OpenSSH Ed25519 private key"),
        ),
        OpensshKeyError::Malformed
        | OpensshKeyError::CheckIntMismatch
        | OpensshKeyError::PublicKeyMismatch => refuse(
            ErrorCode::InvalidArgument,
            "malformed",
            format!("{shown} is not a valid OpenSSH Ed25519 private key file"),
        ),
    }
}

/// Read and validate the key at `path`.
pub(super) fn load_ssh_key(path: &str) -> Result<ImportedKey, OpError> {
    let bytes = read_key_file(path)?;
    let key: Ed25519PrivateKey =
        parse_openssh_private_key(&bytes).map_err(|err| parse_error(path, err))?;
    drop(bytes);
    let public = *key.public_key();
    Ok(ImportedKey {
        pkcs8_der: pkcs8_v2_ed25519(key.seed(), &public),
        public,
        ssh_fingerprint: ssh_fingerprint_of_ed25519(&public),
    })
}

/// The seed does not derive the public key the file claims.
pub(super) fn seed_public_mismatch(path: &str) -> OpError {
    parse_error(path, OpensshKeyError::PublicKeyMismatch)
}
