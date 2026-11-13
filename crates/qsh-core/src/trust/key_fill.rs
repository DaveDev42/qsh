//! Filling a pin's `key` from a connection that passed its pin check
//! (ADR-0061 decision 3, `docs/CLI.md` §6.11 "채우는 길 (가)").
//!
//! A direct or punched connection to a pinned host proved a certificate
//! whose SPKI fingerprint is the pin's. The certificate's Ed25519 key is
//! then the key behind that fingerprint, which is the one thing the iroh
//! route needs and a fingerprint cannot give (a hash does not turn back
//! into a key). Writing it adds no trust: the pin already named this key.
//!
//! The write is narrow on purpose. It only fills a pin that has no `key`,
//! only when the key's own fingerprint is the pin's (recomputed under the
//! lock, [`TrustStore::learn_key`]), never creates a pin and never replaces
//! a key. It runs off the dial path, under `trust.toml.lock`, and a failure
//! is a debug line: the next connection tries again.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use qsh_transport::{Connection, Fingerprint, PeerBinding, TransportKind};

use super::{SharedTrustStore, TrustStore};

/// Fills the `key` of one pin, at most once per dial target.
pub(crate) struct PinKeyFill {
    trust_path: PathBuf,
    pin: Fingerprint,
    done: AtomicBool,
}

impl std::fmt::Debug for PinKeyFill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinKeyFill").finish_non_exhaustive()
    }
}

impl PinKeyFill {
    /// A filler for the pin `binding` names, or `None` when there is nothing
    /// to fill: the name has no pin (a CA-issued leaf), or the pin has a key.
    pub(crate) fn for_target(
        trust: &SharedTrustStore,
        binding: Option<PeerBinding>,
    ) -> Option<Arc<Self>> {
        let Some(PeerBinding::Pin(pin)) = binding else {
            return None;
        };
        let store = trust.snapshot();
        let wants = store.peers().iter().any(|p| {
            p.key.is_none()
                && p.fingerprint
                    .parse::<Fingerprint>()
                    .is_ok_and(|fp| fp == pin)
        });
        wants.then(|| {
            Arc::new(Self {
                trust_path: trust.path().to_path_buf(),
                pin,
                done: AtomicBool::new(false),
            })
        })
    }

    /// Learn the key from `connection`, a connection the pin check let
    /// through. Anything but a certificate-carrying connection to this very
    /// pin is ignored.
    pub(crate) fn note(&self, connection: &Connection) {
        if connection.transport_kind() == TransportKind::Iroh {
            return;
        }
        let Some(key) = connection.peer_ed25519_key() else {
            return;
        };
        // The connection must be to the pin this filler is for, and the key
        // must be the one behind the fingerprint the check passed.
        if connection.peer_fingerprint() != Some(self.pin)
            || qsh_transport::fingerprint_of_ed25519_key(&key) != self.pin
        {
            return;
        }
        if self.done.swap(true, Ordering::Relaxed) {
            return;
        }
        let path = self.trust_path.clone();
        let write = move || match record(&path, &key) {
            Ok(changed) => {
                tracing::debug!(target: "qsh::iroh", event = "pin_key_learned", changed);
            }
            Err(_) => {
                tracing::debug!(target: "qsh::iroh", event = "pin_key_failed");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                drop(handle.spawn_blocking(write));
            }
            Err(_) => {
                drop(std::thread::spawn(write));
            }
        }
    }
}

/// Writes `key` into the trust file at `path`, under its lock.
pub(crate) fn record(path: &std::path::Path, key: &[u8; 32]) -> Result<bool, crate::ops::OpError> {
    let _lock = TrustStore::lock(path)?;
    let mut store = TrustStore::load(path)?;
    let changed = store.learn_key(key);
    if changed {
        store.save(path)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use qsh_transport::fingerprint_of_ed25519_key;

    use super::*;

    fn key() -> [u8; 32] {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        pair.public_key_raw().try_into().unwrap()
    }

    fn store_with(pins: &[(&str, [u8; 32])]) -> TrustStore {
        let mut store = TrustStore::default();
        for (name, key) in pins {
            store.add_peer(
                *name,
                None,
                fingerprint_of_ed25519_key(key),
                "2026-11-13T00:00:00Z".into(),
            );
        }
        store
    }

    #[test]
    fn a_key_fills_the_pin_it_belongs_to_and_nothing_else() {
        let (a, b, stranger) = (key(), key(), key());
        let mut store = store_with(&[("a", a), ("b", b)]);
        assert!(store.learn_key(&a));
        assert!(store.find("a").unwrap().key.is_some());
        assert!(store.find("b").unwrap().key.is_none());
        // A key no pin has creates no pin and changes nothing.
        assert!(!store.learn_key(&stranger));
        assert_eq!(store.peers().len(), 2);
    }

    #[test]
    fn a_key_is_never_overwritten() {
        let a = key();
        let mut store = store_with(&[("a", a)]);
        store.peers.iter_mut().for_each(|p| {
            p.key = Some("11".repeat(32));
        });
        assert!(!store.learn_key(&a));
        assert_eq!(
            store.find("a").unwrap().key.as_deref(),
            Some("11".repeat(32).as_str())
        );
    }

    #[test]
    fn every_pin_of_a_shared_fingerprint_is_filled() {
        let a = key();
        let mut store = store_with(&[("a", a)]);
        let (pin, _, _) = store.add_peer(
            "alias",
            None,
            fingerprint_of_ed25519_key(&a),
            "2026-11-13T00:00:00Z".into(),
        );
        assert_eq!(pin.name, "alias");
        assert!(store.learn_key(&a));
        assert!(store.peers().iter().all(|p| p.key.is_some()));
    }

    #[test]
    fn record_writes_the_file_once_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let a = key();
        store_with(&[("a", a)]).save(&path).unwrap();
        assert!(record(&path, &a).unwrap());
        assert!(!record(&path, &a).unwrap(), "already filled");
        assert!(!record(&path, &key()).unwrap(), "no pin has that key");
        let store = TrustStore::load(&path).unwrap();
        assert_eq!(store.peers().len(), 1);
        assert_eq!(
            store.find("a").unwrap().key.as_deref(),
            Some(iroh_key_hex(&a).as_str())
        );
    }

    fn iroh_key_hex(key: &[u8; 32]) -> String {
        super::super::iroh_pin::key_to_hex(key)
    }
}
