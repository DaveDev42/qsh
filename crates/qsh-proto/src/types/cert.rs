//! `cert.*` and `trust.accept` request and data types (`docs/adr/0008-private-ca-cert-issuance.md`).

use super::*;

// ---------------------------------------------------------------------------
// cert.* (`docs/adr/0008-private-ca-cert-issuance.md`, `docs/CLI.md` §6.x)
// ---------------------------------------------------------------------------

/// Request for `cert.init`. No fields today — kept as a struct for
/// symmetry with every other typed request (same rationale as
/// [`TrustInviteReq`]), so a future optional parameter is additive, not a
/// new op.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertInitReq {}

/// Data payload of `cert.init` — create the local private CA root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertInitData {
    /// SPKI SHA-256 fingerprint of the CA root certificate,
    /// `sha256:BASE64`.
    pub fingerprint: String,
    /// Absolute config directory the CA root lives under (`<config_dir>/ca`,
    /// ADR-0008 §4) — same field name as `identity.init`'s `config_dir`.
    pub config_dir: String,
    /// `true` if this call created the CA root; `false` if one already
    /// existed (idempotent).
    pub created: bool,
}

/// Request for `cert.issue`. No fields today: `qsh cert issue` always
/// promotes *this* device's own identity (ADR-0008 §5 — remote/headless
/// provisioning is P1), so there is nothing to parametrize yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertIssueReq {}

/// The `trust.toml [[ca]]` registration half of `cert.issue`'s result —
/// the same created/updated shape as [`TrustAddData`] (ADR-0008 §6 결과:
/// "trust.toml \[\[ca\]\] 등재는... trust add(Step 2) 선례를 따른다"). Never
/// carries the raw PEM: only the CA's own fingerprint, so this payload
/// stays golden-fixture-stable across regenerations (a fresh CA's PEM
/// bytes differ every run; its trust-entry shape does not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CaRegistration {
    /// The `trust.toml [[ca]]` entry name this call registered under.
    pub name: String,
    /// SPKI SHA-256 fingerprint of the registered CA root.
    pub fingerprint: String,
    /// `true` if this call wrote a new `[[ca]]` entry.
    pub created: bool,
    /// `true` if an existing entry's `cert_pem` was overwritten in place
    /// (only reachable by re-initializing the local CA under the same
    /// name — `qsh_core::trust::TrustStore::add_ca`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<bool>,
}

/// Data payload of `cert.issue` — CA-sign the local device identity and
/// register the CA root in `trust.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertIssueData {
    /// The device this certificate authenticates as
    /// (`qsh://device/<device_id>` SAN) — always this device's existing
    /// `device_id`; the SAN body never changes, only its signer (ADR-0008
    /// §2).
    pub device_id: String,
    /// SPKI SHA-256 fingerprint of the (freshly issued, or already
    /// CA-issued) device certificate.
    pub fingerprint: String,
    /// `true` if this call (re-)signed `identity/device.pem`; `false` if
    /// it was already CA-issued by this exact local CA — re-running `qsh
    /// cert issue` is idempotent and never silently rotates the leaf
    /// (ADR-0008 §6 결과: rotation is out of scope for M7).
    pub issued: bool,
    /// The `trust.toml [[ca]]` registration this call ensured.
    pub ca: CaRegistration,
}

/// Request for `trust.accept` (ADR-0002, M7 Step 4): dial `address` and
/// redeem `code` against the invite it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAcceptReq {
    /// `host:port` to dial — the invite-issuing device's reachable address,
    /// supplied out of band (the code itself never carries one).
    pub address: String,
    /// The invite code as displayed by `trust.invite` (case-insensitive,
    /// hyphens ignored).
    pub code: String,
    /// Pin the redeemed peer under this name instead of its self-asserted
    /// one (`qsh pair accept --as`, ADR-0012 결정 6). Additive
    /// (`docs/CLI.md` §10): absent on any envelope produced before this
    /// field existed, and its absence means the peer's self-asserted name
    /// is pinned, as it always was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
}

/// Data payload of `trust.accept`. Same shape as [`TrustAddData`] — a
/// successful pairing exchange ends, from this device's perspective, in
/// exactly the same local pin `trust.add` would have written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAcceptData {
    /// The peer pinned as a result of this pairing exchange.
    pub peer: TrustPeer,
    /// `true` if this wrote a new pin.
    pub created: bool,
    /// `true` if an existing pin's address was updated in place. See
    /// [`TrustAddData::updated`] for the exact semantics (identical here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<bool>,
}
