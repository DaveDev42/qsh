//! Hand-written OpenSSH key parsers (ADR-0026): the private-key reader behind
//! `qsh init --import-ssh-key` and the `authorized_keys` line classifier
//! behind the trust preview.
//!
//! Both parse untrusted local files, so they live in `qsh-proto` next to the
//! other sans-IO parsers and are covered by the `parse_openssh_key` fuzz
//! target (ADR-0001, `docs/design/protocol.md` §13). Invariants:
//!
//! - total over arbitrary bytes: no panic, no allocation sized by an
//!   attacker-controlled length prefix (a prefix larger than the remaining
//!   input is rejected before anything is sliced or copied);
//! - only a plaintext, single-key, Ed25519 `openssh-key-v1` file is
//!   accepted; encrypted keys and every other key type get a typed error;
//! - private material is held in [`Zeroizing`] buffers and no error or
//!   `Debug` output ever carries input bytes.
//!
//! The private-key path is two layers that can be called separately:
//! [`decode_pem_envelope`] strips the PEM armor and base64, and
//! [`parse_openssh_key_body`] reads the binary `openssh-key-v1` structure.
//! [`parse_openssh_private_key`] runs both.
//!
//! SSH fingerprints (SHA-256 of the wire blob) are deliberately not computed
//! here so this crate takes no hash dependency; [`ed25519_wire_blob`] hands
//! the blob to a caller that has one.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

/// PEM armor line that opens an OpenSSH private key file.
pub const PEM_BEGIN: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";
/// PEM armor line that closes an OpenSSH private key file.
pub const PEM_END: &[u8] = b"-----END OPENSSH PRIVATE KEY-----";

/// Largest private-key input (armored or binary) either layer will look at.
/// A plaintext Ed25519 key file is about 400 bytes; the callers' own file
/// cap is the same 16 KiB.
pub const OPENSSH_KEY_INPUT_MAX: usize = 16 * 1024;

/// Largest base64 public-key field an `authorized_keys` line may carry
/// before the line is treated as malformed.
pub const AUTHORIZED_KEY_BLOB_B64_MAX: usize = 16 * 1024;

const MAGIC: &[u8] = b"openssh-key-v1\0";
const KEY_TYPE_ED25519: &[u8] = b"ssh-ed25519";
const SEED_LEN: usize = 32;
const PUBLIC_LEN: usize = 32;
const SECRET_LEN: usize = SEED_LEN + PUBLIC_LEN;
/// Block size of the `none` cipher; the private section is padded to it.
const NONE_BLOCK: usize = 8;

/// Why a private key was rejected. Carries no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpensshKeyError {
    /// The key is passphrase protected (cipher other than `none`).
    #[error("the OpenSSH private key is encrypted")]
    Encrypted,
    /// A well-formed key of a type other than plain `ssh-ed25519`
    /// (RSA, ECDSA, security-key, certificate types).
    #[error("the OpenSSH private key is not a plain ssh-ed25519 key")]
    UnsupportedKeyType,
    /// Not a valid `openssh-key-v1` file, or it uses an unsupported layout
    /// (kdf with cipher `none`, more than one key, bad padding).
    #[error("the OpenSSH private key is malformed")]
    Malformed,
    /// The two check integers in the private section differ.
    #[error("the OpenSSH private key check integers differ")]
    CheckIntMismatch,
    /// The public key in the private section differs from the public
    /// section, or from the copy inside the secret.
    #[error("the OpenSSH private key public halves disagree")]
    PublicKeyMismatch,
    /// The input is larger than [`OPENSSH_KEY_INPUT_MAX`].
    #[error("the OpenSSH private key input is too large")]
    TooLarge,
}

/// A parsed plaintext Ed25519 OpenSSH private key.
///
/// The seed is zeroized on drop and hidden from `Debug`. The type is
/// deliberately not `Clone`.
pub struct Ed25519PrivateKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    public: [u8; PUBLIC_LEN],
}

impl Ed25519PrivateKey {
    /// The 32-byte Ed25519 seed (the RFC 8032 private key).
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The 32-byte public key as stored in the file.
    pub fn public_key(&self) -> &[u8; PUBLIC_LEN] {
        &self.public
    }

    /// The OpenSSH wire-format public key blob (`ssh-ed25519` + key).
    pub fn public_wire_blob(&self) -> [u8; ED25519_WIRE_BLOB_LEN] {
        ed25519_wire_blob(&self.public)
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PrivateKey")
            .field("seed", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Length of the OpenSSH wire blob of an Ed25519 public key.
pub const ED25519_WIRE_BLOB_LEN: usize = 4 + KEY_TYPE_ED25519.len() + 4 + PUBLIC_LEN;

/// The OpenSSH wire-format blob of an Ed25519 public key: two
/// length-prefixed strings, the key type and the 32 key bytes.
pub fn ed25519_wire_blob(public: &[u8; PUBLIC_LEN]) -> [u8; ED25519_WIRE_BLOB_LEN] {
    let mut out = [0u8; ED25519_WIRE_BLOB_LEN];
    out[..4].copy_from_slice(&(KEY_TYPE_ED25519.len() as u32).to_be_bytes());
    out[4..4 + KEY_TYPE_ED25519.len()].copy_from_slice(KEY_TYPE_ED25519);
    let at = 4 + KEY_TYPE_ED25519.len();
    out[at..at + 4].copy_from_slice(&(PUBLIC_LEN as u32).to_be_bytes());
    out[at + 4..].copy_from_slice(public);
    out
}

/// Bounds-checked big-endian reader over a byte slice. Every length is
/// checked against the remaining input before anything is sliced, so no
/// allocation ever depends on an attacker-supplied length.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], OpensshKeyError> {
        if n > self.0.len() {
            return Err(OpensshKeyError::Malformed);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, OpensshKeyError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| OpensshKeyError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn string(&mut self) -> Result<&'a [u8], OpensshKeyError> {
        let n = self.u32()?;
        self.take(usize::try_from(n).map_err(|_| OpensshKeyError::Malformed)?)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Strips the PEM armor from an OpenSSH private key file and base64-decodes
/// the body. The result is the binary `openssh-key-v1` structure, held in a
/// [`Zeroizing`] buffer because it contains the seed.
pub fn decode_pem_envelope(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpensshKeyError> {
    if input.len() > OPENSSH_KEY_INPUT_MAX {
        return Err(OpensshKeyError::TooLarge);
    }
    let trimmed = input.trim_ascii();
    let rest = trimmed
        .strip_prefix(PEM_BEGIN)
        .ok_or(OpensshKeyError::Malformed)?;
    let body = rest
        .strip_suffix(PEM_END)
        .ok_or(OpensshKeyError::Malformed)?;
    if !matches!(body.first(), Some(b'\n' | b'\r')) {
        return Err(OpensshKeyError::Malformed);
    }
    // The base64 text of the key is as sensitive as the key: keep it in a
    // zeroizing buffer too.
    let mut compact: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(body.len()));
    compact.extend(body.iter().copied().filter(|b| !b.is_ascii_whitespace()));
    if compact.is_empty() {
        return Err(OpensshKeyError::Malformed);
    }
    let mut decoded: Zeroizing<Vec<u8>> =
        Zeroizing::new(vec![0u8; base64::decoded_len_estimate(compact.len())]);
    let n = STANDARD
        .decode_slice(compact.as_slice(), decoded.as_mut_slice())
        .map_err(|_| OpensshKeyError::Malformed)?;
    decoded.truncate(n);
    Ok(decoded)
}

/// Reads the binary `openssh-key-v1` structure (the output of
/// [`decode_pem_envelope`]) and accepts one plaintext Ed25519 key.
pub fn parse_openssh_key_body(body: &[u8]) -> Result<Ed25519PrivateKey, OpensshKeyError> {
    if body.len() > OPENSSH_KEY_INPUT_MAX {
        return Err(OpensshKeyError::TooLarge);
    }
    let rest = body.strip_prefix(MAGIC).ok_or(OpensshKeyError::Malformed)?;
    let mut r = Reader(rest);
    let cipher = r.string()?;
    let kdf = r.string()?;
    let kdf_options = r.string()?;
    if cipher != b"none" {
        return Err(OpensshKeyError::Encrypted);
    }
    // A kdf without a cipher is an inconsistent file, not an encrypted one.
    if kdf != b"none" || !kdf_options.is_empty() {
        return Err(OpensshKeyError::Malformed);
    }
    if r.u32()? != 1 {
        return Err(OpensshKeyError::Malformed);
    }
    let public_section = r.string()?;
    let private_section = r.string()?;
    if !r.is_empty() {
        return Err(OpensshKeyError::Malformed);
    }

    let mut pr = Reader(public_section);
    if pr.string()? != KEY_TYPE_ED25519 {
        return Err(OpensshKeyError::UnsupportedKeyType);
    }
    let public: [u8; PUBLIC_LEN] = pr
        .string()?
        .try_into()
        .map_err(|_| OpensshKeyError::Malformed)?;
    if !pr.is_empty() {
        return Err(OpensshKeyError::Malformed);
    }

    if private_section.len() % NONE_BLOCK != 0 {
        return Err(OpensshKeyError::Malformed);
    }
    let mut sr = Reader(private_section);
    if sr.u32()? != sr.u32()? {
        return Err(OpensshKeyError::CheckIntMismatch);
    }
    if sr.string()? != KEY_TYPE_ED25519 {
        return Err(OpensshKeyError::Malformed);
    }
    let inner_public = sr.string()?;
    if inner_public != public {
        return Err(OpensshKeyError::PublicKeyMismatch);
    }
    let secret = sr.string()?;
    if secret.len() != SECRET_LEN {
        return Err(OpensshKeyError::Malformed);
    }
    if secret[SEED_LEN..] != public {
        return Err(OpensshKeyError::PublicKeyMismatch);
    }
    let _comment = sr.string()?;
    // Padding is 1, 2, 3, ... up to one short of the block size.
    let padding = sr.0;
    if padding.len() >= NONE_BLOCK
        || !padding
            .iter()
            .enumerate()
            .all(|(i, b)| usize::from(*b) == i + 1)
    {
        return Err(OpensshKeyError::Malformed);
    }

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&secret[..SEED_LEN]);
    Ok(Ed25519PrivateKey { seed, public })
}

/// Parses an armored OpenSSH private key file: [`decode_pem_envelope`]
/// then [`parse_openssh_key_body`].
pub fn parse_openssh_private_key(input: &[u8]) -> Result<Ed25519PrivateKey, OpensshKeyError> {
    let body = decode_pem_envelope(input)?;
    parse_openssh_key_body(&body)
}

/// One non-blank, non-comment line of an `authorized_keys` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedKeysLine<'a> {
    /// 1-based line number in the input.
    pub line: usize,
    /// How the line classified.
    pub entry: AuthorizedKeysEntry<'a>,
}

/// Classification of one `authorized_keys` line. `restricted` is true when
/// the line has an options prefix; the options themselves are not
/// interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedKeysEntry<'a> {
    /// A `ssh-ed25519` key with a well-formed 32-byte public key.
    Ed25519 {
        /// The Ed25519 public key.
        public_key: [u8; PUBLIC_LEN],
        /// The line carries an options prefix.
        restricted: bool,
        /// Raw trailing comment; callers sanitize it before display
        /// (`wire::sanitize_peer_text`).
        comment: &'a str,
    },
    /// A well-formed line of another key type.
    OtherKeyType {
        /// The key type token as written.
        key_type: &'a str,
        /// The line carries an options prefix.
        restricted: bool,
    },
    /// The line does not parse (bad UTF-8, unterminated quote, bad base64,
    /// blob type disagreeing with the key type, missing fields).
    Malformed,
}

/// Classifies every line of an `authorized_keys` file independently.
/// Blank lines and `#` comment lines produce no entry; CRLF is accepted.
/// The output holds at most one entry per input line.
pub fn parse_authorized_keys(input: &[u8]) -> Vec<AuthorizedKeysLine<'_>> {
    let mut out = Vec::new();
    for (idx, raw) in input.split(|b| *b == b'\n').enumerate() {
        let line = raw.trim_ascii();
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        out.push(AuthorizedKeysLine {
            line: idx + 1,
            entry: classify_line(line),
        });
    }
    out
}

fn classify_line(line: &[u8]) -> AuthorizedKeysEntry<'_> {
    let Ok(text) = std::str::from_utf8(line) else {
        return AuthorizedKeysEntry::Malformed;
    };
    classify_text(text).unwrap_or(AuthorizedKeysEntry::Malformed)
}

fn classify_text(text: &str) -> Option<AuthorizedKeysEntry<'_>> {
    let (first, mut rest) = next_field(text)??;
    let mut restricted = false;
    let key_type = if looks_like_key_type(first) {
        first
    } else {
        restricted = true;
        let (kt, after) = next_field(rest)??;
        if !looks_like_key_type(kt) {
            return None;
        }
        rest = after;
        kt
    };
    let (blob_b64, comment) = next_field(rest)??;
    if blob_b64.len() > AUTHORIZED_KEY_BLOB_B64_MAX {
        return None;
    }
    let mut blob = vec![0u8; base64::decoded_len_estimate(blob_b64.len())];
    let n = STANDARD.decode_slice(blob_b64.as_bytes(), &mut blob).ok()?;
    let mut r = Reader(&blob[..n]);
    if r.string().ok()? != key_type.as_bytes() {
        return None;
    }
    if key_type.as_bytes() != KEY_TYPE_ED25519 {
        return Some(AuthorizedKeysEntry::OtherKeyType {
            key_type,
            restricted,
        });
    }
    let public_key: [u8; PUBLIC_LEN] = r.string().ok()?.try_into().ok()?;
    if !r.is_empty() {
        return None;
    }
    Some(AuthorizedKeysEntry::Ed25519 {
        public_key,
        restricted,
        comment: comment.trim_start_matches([' ', '\t']),
    })
}

/// Key-type tokens are `ssh-*`, `ecdsa-*` or `sk-*` names; options such as
/// `command="..."` or `no-pty` never look like that.
fn looks_like_key_type(token: &str) -> bool {
    (token.starts_with("ssh-") || token.starts_with("ecdsa-") || token.starts_with("sk-"))
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

/// Splits off the next space/tab separated field. Whitespace inside double
/// quotes (with `\` escapes) does not end a field. The outer `None` is an
/// unterminated quote; `Some(None)` means no field is left.
fn next_field(s: &str) -> Option<Option<(&str, &str)>> {
    let s = s.trim_start_matches([' ', '\t']);
    if s.is_empty() {
        return Some(None);
    }
    let bytes = s.as_bytes();
    let mut in_quote = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_quote => i += 1,
            b'"' => in_quote = !in_quote,
            b' ' | b'\t' if !in_quote => break,
            _ => {}
        }
        i += 1;
    }
    if in_quote {
        return None;
    }
    let end = i.min(bytes.len());
    Some(Some((&s[..end], &s[end..])))
}
