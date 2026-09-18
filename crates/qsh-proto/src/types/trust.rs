//! `trust.*` request and data types (`docs/CLI.md` §6.11).

use super::*;

// ---------------------------------------------------------------------------
// trust.* (`docs/CLI.md` §6.11)
// ---------------------------------------------------------------------------

/// A pinned peer — the unified object used by `trust.add`/`list`/`remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPeer {
    /// Local alias for the peer (also the `device:<name>` principal it
    /// authenticates as).
    pub name: String,
    /// SPKI SHA-256 fingerprint, `sha256:BASE64`.
    pub fingerprint: String,
    /// `host:port` used to dial this peer. Empty when the pin exists only to
    /// authorize the peer as a *client* (no dial address).
    pub address: String,
    /// RFC 3339 UTC timestamp of when the pin was added.
    pub added_at: String,
}

/// Request for `trust.add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAddReq {
    /// Peer alias.
    pub name: String,
    /// `host:port`. Optional for client-only pins; required when
    /// `fingerprint` is absent (needed to observe it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// `sha256:BASE64`. When present the peer is pinned without connecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Data payload of `trust.add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustAddData {
    /// The (new, pre-existing, or address-updated) pin.
    pub peer: TrustPeer,
    /// `true` if a new pin was written; `false` if `name` was already
    /// pinned (idempotent).
    pub created: bool,
    /// `true` if `name` was already pinned under the *same* fingerprint and
    /// this call changed its stored `address` in place (`docs/CLI.md`
    /// §6.11's address-refresh path, `PLAN.md` M7 Step 2 decision B —
    /// e.g. the host's reachable address changed and the operator re-ran
    /// `trust add` with the same identity and a new `--address`). `false`
    /// (never `true`) alongside `created: true` — a brand-new pin has
    /// nothing to update — and also `false` when `name` already existed
    /// but nothing about it changed: same address, or a *different*
    /// fingerprint (a fingerprint mismatch is never applied — re-binding an
    /// identity is a deliberate `remove` then `add`, never a side effect of
    /// a repeated `trust add`). Additive (`docs/CLI.md` §10): absent on any
    /// envelope produced before M7 Step 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<bool>,
}

/// Data payload of `trust.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustListData {
    /// All pinned peers, in store order.
    pub peers: Vec<TrustPeer>,
}

/// Data payload of `trust.remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustRemoveData {
    /// The name that was asked to be removed.
    pub name: String,
    /// `true` if a pin was removed; `false` if none existed (idempotent).
    pub removed: bool,
}

/// Request for `trust.invite` (ADR-0002, M7 Step 4). No fields today — kept
/// as a struct for symmetry with every other typed request, so a future
/// optional parameter (e.g. a non-default TTL) is additive, not a new op.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustInviteReq {}

/// Data payload of `trust.invite`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrustInviteData {
    /// The one-time invite code, Crockford Base32, lowercase, hyphenated
    /// 4-char groups (`xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx`). Carries no
    /// address — give it to the other device's operator out of band
    /// alongside a reachable `host:port` for *this* device.
    pub code: String,
    /// RFC 3339 UTC expiry — creation time plus a 10-minute TTL
    /// (`docs/CLI.md` §6.11).
    pub expires_at: String,
    /// The complete command line for the other device to run, with `code`
    /// already filled in and `<address>` left as a literal placeholder this
    /// host cannot know on its own (its externally reachable address is a
    /// deployment fact, not something `trust.invite` observes — the same
    /// reason `HOST_NOT_FOUND`'s own remedy text uses a placeholder
    /// address). Human-mode output prints this verbatim; the operator
    /// substitutes a real `host:port` before sending it to the other party.
    pub accept_command: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope's `data` object for `trust.invite` has exactly these
    /// three keys, in alphabetical order — not declaration order. This
    /// crate's `serde_json` is built without the `preserve_order` feature
    /// (no `indexmap` in `Cargo.lock`), so `serde_json::Map` is a
    /// `BTreeMap` and `to_value`/`from_slice::<Value>` both return keys
    /// alphabetically. The checked-in fixture
    /// `crates/qsh-cli/tests/fixtures/cli-v1/trust.invite.json` already
    /// reads `accept_command` → `code` → `expires_at` for the same reason.
    #[test]
    fn trust_invite_data_serializes_exactly_three_keys() {
        let value = serde_json::to_value(TrustInviteData {
            code: "c".into(),
            expires_at: "e".into(),
            accept_command: "a".into(),
        })
        .expect("TrustInviteData serializes");
        let keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["accept_command", "code", "expires_at"]);
    }
}
