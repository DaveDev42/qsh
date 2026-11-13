//! The iroh fields of a pin: `routes`, `relay` and `key` (ADR-0061
//! decisions 1, 3 and 11, `docs/CLI.md` §6.11).
//!
//! - `routes` is the list of route kinds tried after the direct dial and
//!   hole punching. `"iroh"` is the only value this build acts on; a value it
//!   does not know is kept in the file and skipped.
//! - `relay` is the URL (`https://...`) of the relay the host's iroh
//!   endpoint is homed on.
//! - `key` is the host's Ed25519 public key in lowercase hex (its iroh
//!   endpoint id). The pin's `fingerprint` is the SPKI SHA-256 of that key,
//!   so the file is only valid when the two agree; a hash cannot be turned
//!   back into a key, which is why the key is stored at all.

use qsh_proto::TrustPeer;
use qsh_transport::{Fingerprint, fingerprint_of_ed25519_key};

use super::{SetRoleError, TrustStore};

/// The route kind that turns the iroh relay route on for a pin.
pub const ROUTE_IROH: &str = "iroh";

/// The longest `relay` value a pin may hold, in bytes (CLI.md §6.11).
pub const MAX_RELAY_URL_BYTES: usize = 2048;

/// Length of an Ed25519 public key in bytes.
const KEY_LEN: usize = 32;

/// An Ed25519 public key from its hex spelling: exactly 64 hex digits, either
/// case.
pub fn parse_key_hex(text: &str) -> Result<[u8; KEY_LEN], String> {
    let text = text.trim();
    if text.len() != KEY_LEN * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "an Ed25519 public key is {} hex characters",
            KEY_LEN * 2
        ));
    }
    let mut key = [0u8; KEY_LEN];
    for (byte, pair) in key.iter_mut().zip(text.as_bytes().chunks(2)) {
        let digits = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        *byte = u8::from_str_radix(digits, 16).map_err(|e| e.to_string())?;
    }
    Ok(key)
}

/// The lowercase hex spelling a pin stores.
pub fn key_to_hex(key: &[u8; KEY_LEN]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(KEY_LEN * 2);
    for byte in key {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether `key_hex` is a key whose fingerprint is `fingerprint` (the
/// `sha256:BASE64` spelling). A value that does not parse matches nothing.
pub fn key_matches(key_hex: &str, fingerprint: &str) -> bool {
    let (Ok(key), Ok(fingerprint)) = (parse_key_hex(key_hex), fingerprint.parse::<Fingerprint>())
    else {
        return false;
    };
    fingerprint_of_ed25519_key(&key) == fingerprint
}

/// `(host, port)` of an `https://` URL, or `None` when it is not a plain
/// `https://host[:port][/path]` URL: another scheme, credentials, an empty
/// host, a port that is not 1 to 65535, or characters a URL cannot hold.
fn split_https(url: &str) -> Option<(&str, Option<u16>)> {
    if url.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return None;
    }
    let scheme = url.get(..8)?;
    if !scheme.eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &url[8..];
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, tail) = inner.split_once(']')?;
        match tail {
            "" => (&authority[..host.len() + 2], None),
            _ => (
                &authority[..host.len() + 2],
                Some(tail.strip_prefix(':')?.parse::<u16>().ok()?),
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
            None => (authority, None),
        }
    };
    if host.is_empty() || host == "[]" || port == Some(0) {
        return None;
    }
    Some((host, port))
}

/// Check a relay URL: `https` only, no credentials, at most
/// [`MAX_RELAY_URL_BYTES`].
pub fn validate_relay_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_RELAY_URL_BYTES {
        return Err(format!(
            "a relay URL is at most {MAX_RELAY_URL_BYTES} bytes"
        ));
    }
    split_https(url)
        .map(|_| ())
        .ok_or_else(|| "a relay URL is https://host[:port] with no credentials".to_string())
}

/// The scheme and host of a relay URL (`https://relay.example`), the only
/// part of it a report, an audit record or a log line shows (ADR-0061
/// decision 6). `None` for a value [`validate_relay_url`] refuses.
pub fn relay_scheme_host(url: &str) -> Option<String> {
    split_https(url).map(|(host, _)| format!("https://{}", host.to_ascii_lowercase()))
}

/// Whether the pin asks for the iroh route.
pub fn wants_iroh(peer: &TrustPeer) -> bool {
    peer.routes.iter().any(|r| r == ROUTE_IROH)
}

/// Why the iroh fields of `peer` make a trust file invalid, if they do.
pub(super) fn field_error(peer: &TrustPeer) -> Option<String> {
    if let Some(relay) = &peer.relay
        && let Err(why) = validate_relay_url(relay)
    {
        return Some(format!("relay: {why}"));
    }
    if let Some(key) = &peer.key {
        if let Err(why) = parse_key_hex(key) {
            return Some(format!("key: {why}"));
        }
        if !key_matches(key, &peer.fingerprint) {
            return Some("key: the key's SPKI SHA-256 is not this pin's fingerprint".to_string());
        }
    }
    None
}

/// What `trust.set_iroh` changes on a pin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IrohPinChange {
    /// Drop `routes` and `relay`.
    pub off: bool,
    /// Set `relay` (the caller validated it).
    pub relay: Option<String>,
    /// Set `key` (the caller checked it against the fingerprint).
    pub key: Option<[u8; KEY_LEN]>,
}

impl TrustStore {
    /// Record `key` as the `key` of every pin whose fingerprint is that of
    /// `key` and which has none yet (ADR-0061 decision 3,
    /// `docs/CLI.md` §6.11 "채우는 길"). Pure: the caller holds the lock and
    /// saves. A pin that already has a key is never overwritten, a key whose
    /// fingerprint matches no pin creates nothing, and the fingerprint is
    /// recomputed from the key here, so a caller cannot attach a key to a
    /// pin it does not belong to. Returns whether anything changed.
    pub fn learn_key(&mut self, key: &[u8; KEY_LEN]) -> bool {
        let fingerprint = fingerprint_of_ed25519_key(key);
        let hex = key_to_hex(key);
        let mut changed = false;
        for peer in &mut self.peers {
            let same = peer
                .fingerprint
                .parse::<Fingerprint>()
                .is_ok_and(|fp| fp == fingerprint);
            if peer.key.is_none() && same {
                peer.key = Some(hex.clone());
                changed = true;
            }
        }
        changed
    }

    /// Apply `change` to the pin named `name` (`trust.set_iroh`). Pure: the
    /// caller holds the lock and saves. Without `off` the pin ends with
    /// `"iroh"` in `routes` (other values are kept), with `relay` and `key`
    /// set when given. Returns the pin as it now stands and whether anything
    /// changed.
    pub fn set_iroh(
        &mut self,
        name: &str,
        change: &IrohPinChange,
    ) -> Result<(TrustPeer, bool), SetRoleError> {
        let peer = self
            .peers
            .iter_mut()
            .find(|p| p.name == name)
            .ok_or(SetRoleError::NotFound)?;
        let before = (peer.routes.clone(), peer.relay.clone(), peer.key.clone());
        if change.off {
            peer.routes.clear();
            peer.relay = None;
        } else {
            if !peer.routes.iter().any(|r| r == ROUTE_IROH) {
                peer.routes.push(ROUTE_IROH.to_string());
            }
            if let Some(relay) = &change.relay {
                peer.relay = Some(relay.clone());
            }
        }
        if let Some(key) = &change.key {
            peer.key = Some(key_to_hex(key));
        }
        let changed = before != (peer.routes.clone(), peer.relay.clone(), peer.key.clone());
        Ok((peer.clone(), changed))
    }
}
