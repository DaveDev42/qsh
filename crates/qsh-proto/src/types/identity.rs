//! `identity.init` request and data types and the key-store enums (`docs/CLI.md` §6.11).

use super::*;

// ---------------------------------------------------------------------------
// identity.init (`docs/CLI.md` §6.11)
// ---------------------------------------------------------------------------

/// Which private-key store `qsh init` was asked to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyStoreMode {
    /// Prefer the OS credential store, fall back to a 0600 file when it is
    /// unavailable (headless Linux). The default.
    #[default]
    Auto,
    /// OS credential store only; fail if unavailable.
    Platform,
    /// 0600 file under the config directory only.
    File,
}

impl KeyStoreMode {
    /// Lowercase name as used in `config.toml` and `--key-store`.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyStoreMode::Auto => "auto",
            KeyStoreMode::Platform => "platform",
            KeyStoreMode::File => "file",
        }
    }
}

impl std::str::FromStr for KeyStoreMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(KeyStoreMode::Auto),
            "platform" => Ok(KeyStoreMode::Platform),
            "file" => Ok(KeyStoreMode::File),
            other => Err(format!(
                "invalid key store mode {other:?} (expected auto, platform or file)"
            )),
        }
    }
}

/// The store that actually holds the private key. Unlike [`KeyStoreMode`],
/// this is never `auto` — `qsh init` always reports the concrete choice
/// (`docs/CLI.md` §6.11: "어느 쪽이 사용됐는지는 항상 결과에 명시한다").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KeyStoreKind {
    /// OS credential store (macOS Keychain, Linux Secret Service).
    Platform,
    /// `identity/device.key`, mode 0600.
    File,
}

impl KeyStoreKind {
    /// Lowercase name as reported in `identity.init` data.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyStoreKind::Platform => "platform",
            KeyStoreKind::File => "file",
        }
    }
}

/// Request for `identity.init`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct IdentityInitReq {
    /// Key store selection. `None` = use `config.toml` `[identity].key_store`
    /// or `auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_store: Option<KeyStoreMode>,
}

/// Data payload of `identity.init` (`docs/CLI.md` §6.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityInitData {
    /// Stable device identifier, `device_<ULID>`.
    pub device_id: String,
    /// SPKI SHA-256 fingerprint of the device certificate, `sha256:BASE64`.
    pub fingerprint: String,
    /// The store actually holding the private key.
    pub key_store: KeyStoreKind,
    /// Absolute config directory the identity lives in.
    pub config_dir: String,
    /// `true` if this call created the identity, `false` if it already
    /// existed (idempotent).
    pub created: bool,
}

// ---------------------------------------------------------------------------
// identity.export (`docs/CLI.md` §6.11, ADR-0013)
// ---------------------------------------------------------------------------

/// Request for `identity.export`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct IdentityExportReq {
    /// Write the certificate to this path instead of returning it inline.
    /// Refuses to overwrite an existing file (`INVALID_ARGUMENT`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out: Option<String>,
}

/// Data payload of `identity.export` (`docs/CLI.md` §6.11, ADR-0013
/// 결과: no command ever takes or emits this device's private key —
/// this op reads only `identity::read_identity`, never the key store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityExportData {
    /// This device's identifier (the same value `identity.init` reports
    /// as `device_id`).
    pub name: String,
    /// SPKI SHA-256 fingerprint of the exported certificate.
    pub fingerprint: String,
    /// The certificate, PEM-encoded, byte-identical to `device.pem` on
    /// disk. Present only when `--out` was not given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    /// The path the certificate was written to, exactly as the operator
    /// gave it (not canonicalized). Present only when `--out` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}
