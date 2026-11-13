//! The `[[peer]]` table of `trust.toml` as it is written in the file
//! (ADR-0063).
//!
//! [`TrustPeer`] is the wire type: every pin has a `fingerprint`, an
//! `address` (empty for a pin that is only a client), an `added_at` and a
//! `routes` list. The file does not have to spell all of that out. A pin is
//! `name` plus a `key` (the host's Ed25519 public key in hex, its iroh
//! endpoint id) and, usually, a `role`:
//!
//! ```toml
//! [[peer]]
//! name = "toss"
//! key  = "<64 hex characters>"
//! role = "tunnel"
//! ```
//!
//! [`PinRecord`] is that file form. Reading one fills in what the file left
//! out ([`PinRecord::resolve`]); writing one leaves out what a reader would
//! fill in again ([`PinRecord::minimal`]).
//!
//! - `fingerprint` is the SPKI SHA-256 of the key, so a pin with a `key`
//!   needs no `fingerprint`. A file that has both must have them agree.
//! - `address` left out is the empty address.
//! - `added_at` left out is the empty string.
//! - `routes` left out is [`default_routes`]: `["iroh"]` for a pin with a key
//!   and no address (it can only be reached over the relay), nothing for
//!   every other pin. A `routes` that is written wins, empty list included.

use qsh_proto::TrustPeer;
use qsh_transport::{Fingerprint, fingerprint_of_ed25519_key};
use serde::{Deserialize, Serialize};

use super::iroh_pin::{self, ROUTE_IROH};

/// One `[[peer]]` table, with every key that may be left out optional.
/// Field order is the order the keys are written in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PinRecord {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    added_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grants: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_qsh: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rendezvous: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    jump: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    routes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

/// The `routes` a pin has when the file does not write any: `["iroh"]` for a
/// pin with a key and no address, none otherwise.
pub(super) fn default_routes(peer: &TrustPeer) -> Vec<String> {
    if peer.key.is_some() && peer.address.is_empty() {
        vec![ROUTE_IROH.to_string()]
    } else {
        Vec::new()
    }
}

impl PinRecord {
    /// The pin's name, for messages.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// The pin this record stands for, with the left-out keys filled in.
    /// `Err` carries the sentence that says why the record contradicts
    /// itself or says too little.
    pub(super) fn resolve(&self) -> Result<TrustPeer, String> {
        let (fingerprint, key) = match (&self.key, &self.fingerprint) {
            (Some(key), given) => {
                let bytes = iroh_pin::parse_key_hex(key).map_err(|why| format!("key: {why}"))?;
                let derived = fingerprint_of_ed25519_key(&bytes);
                if let Some(given) = given
                    && !given.parse::<Fingerprint>().is_ok_and(|g| g == derived)
                {
                    return Err(
                        "key: the key's SPKI SHA-256 is not this pin's fingerprint".to_string()
                    );
                }
                (derived.to_string(), Some(key.clone()))
            }
            (None, Some(fingerprint)) => (fingerprint.clone(), None),
            (None, None) => {
                return Err("a pin needs a key or a fingerprint, and has neither".to_string());
            }
        };
        let mut peer = TrustPeer {
            name: self.name.clone(),
            fingerprint,
            address: self.address.clone().unwrap_or_default(),
            added_at: self.added_at.clone().unwrap_or_default(),
            role: self.role.clone(),
            grants: self.grants.clone(),
            paths: self.paths.clone(),
            scope: self.scope.clone(),
            source: self.source.clone(),
            remote_qsh: self.remote_qsh.clone(),
            rendezvous: self.rendezvous.clone(),
            jump: self.jump.clone(),
            routes: Vec::new(),
            relay: self.relay.clone(),
            key,
        };
        peer.routes = match &self.routes {
            Some(routes) => routes.clone(),
            None => default_routes(&peer),
        };
        Ok(peer)
    }

    /// `peer` written over the record it was read from: the shortest record
    /// ([`Self::minimal`]) that still spells out every key `self` spelled out.
    /// A pin that changed keeps the `fingerprint`, `address`, `added_at` and
    /// `routes` its file had, so a change touches the lines it changes.
    pub(super) fn updated(&self, peer: &TrustPeer) -> Self {
        let mut record = Self::minimal(peer);
        if self.fingerprint.is_some() {
            record.fingerprint = Some(peer.fingerprint.clone());
        }
        if self.address.is_some() {
            record.address = Some(peer.address.clone());
        }
        if self.added_at.is_some() {
            record.added_at = Some(peer.added_at.clone());
        }
        if self.routes.is_some() {
            record.routes = Some(peer.routes.clone());
        }
        record
    }

    /// The shortest record that reads back as `peer`: no `fingerprint` when
    /// there is a `key` to derive it from, no empty `address` or `added_at`,
    /// and no `routes` that equal [`default_routes`].
    pub(super) fn minimal(peer: &TrustPeer) -> Self {
        let routes = default_routes(peer);
        Self {
            name: peer.name.clone(),
            fingerprint: peer.key.is_none().then(|| peer.fingerprint.clone()),
            address: (!peer.address.is_empty()).then(|| peer.address.clone()),
            added_at: (!peer.added_at.is_empty()).then(|| peer.added_at.clone()),
            role: peer.role.clone(),
            grants: peer.grants.clone(),
            paths: peer.paths.clone(),
            scope: peer.scope.clone(),
            source: peer.source.clone(),
            remote_qsh: peer.remote_qsh.clone(),
            rendezvous: peer.rendezvous.clone(),
            jump: peer.jump.clone(),
            routes: (peer.routes != routes).then(|| peer.routes.clone()),
            relay: peer.relay.clone(),
            key: peer.key.clone(),
        }
    }
}
