//! `identity.move_key`: move the device private key between the two
//! stores without changing the identity (`docs/CLI.md` §6.11, ADR-0032
//! 결정 15, `docs/design/architecture.md` §5).
//!
//! The device id, the certificate and the fingerprint do not change, so a
//! peer's pin and ACL rows for this device stay valid.
//!
//! The order, under the one identity lock:
//!
//! 1. one audit record, before anything changes (fail-closed);
//! 2. read the key from the store it lives in;
//! 3. write it to the new store (a file store writes 0600);
//! 4. read it back from the new store and check that it is the key the
//!    device certificate names;
//! 5. rewrite `identity.toml` with the new `key_store`;
//! 6. delete the entry in the old store.
//!
//! A failure in step 2 to 5 undoes what the earlier steps wrote and ends
//! with the original state; only a failure in step 6 is a success, flagged
//! `stale_entry_left`. Key bytes live in [`Zeroizing`] buffers and never
//! reach an error message, a log line or a result (ADR-0013).

use std::ops::Deref;

use qsh_proto::{ErrorCode, IdentityMoveKeyData, KeyStoreKind};
use qsh_transport::Fingerprint;
use zeroize::Zeroizing;

use super::keystore::{KeyStore, KeyStoreError};
use super::{IDENTITY_FILE, IdentityFile, NO_LOCAL_IDENTITY, open_store, read_identity};
use crate::config::{FileLock, lock_path_for, write_private_file};
use crate::ops::OpError;

/// The store a step talks to: the injected platform store of a test, or
/// one built by [`open_store`].
enum Slot<'a> {
    Owned(Box<dyn KeyStore>),
    Borrowed(&'a dyn KeyStore),
}

impl<'a> Deref for Slot<'a> {
    type Target = dyn KeyStore + 'a;

    fn deref(&self) -> &Self::Target {
        match self {
            Slot::Owned(store) => store.as_ref(),
            Slot::Borrowed(store) => *store,
        }
    }
}

/// Resolve the store for `kind`. `platform`, when given, replaces the OS
/// credential store (the seam tests use so none of them touches it).
fn slot<'a>(
    paths: &crate::config::Paths,
    device_id: &str,
    kind: KeyStoreKind,
    platform: Option<&'a dyn KeyStore>,
) -> Slot<'a> {
    match (kind, platform) {
        (KeyStoreKind::Platform, Some(store)) => Slot::Borrowed(store),
        _ => Slot::Owned(open_store(paths, device_id, kind)),
    }
}

/// The identity lock: the sidecar of `identity.toml`, shared by `init`,
/// `promote_to_ca_issued` and `move_key` so no two of them interleave their
/// read-modify-write of the identity record (ADR-0032 결정 15). It is the
/// same shape as `TrustStore::lock`.
pub(super) fn lock_identity(paths: &crate::config::Paths) -> Result<FileLock, OpError> {
    FileLock::acquire(&lock_path_for(&paths.identity_dir().join(IDENTITY_FILE)))
}

fn internal(message: String) -> OpError {
    OpError::new(ErrorCode::Internal, message).with_retryable(false)
}

fn read_error(kind: KeyStoreKind, err: &KeyStoreError) -> OpError {
    internal(format!(
        "failed to read the device key from the {} key store: {err}",
        kind.as_str()
    ))
}

/// A write to the destination store failed. An unreachable platform store
/// gets the same wording as `identity.init --key-store platform`.
fn write_error(kind: KeyStoreKind, err: &KeyStoreError) -> OpError {
    match (kind, err) {
        (KeyStoreKind::Platform, KeyStoreError::Unavailable(_)) => internal(format!(
            "platform key store unavailable ({err}); the device key stays in the {} key store",
            KeyStoreKind::File.as_str()
        )),
        _ => internal(format!(
            "failed to store the device key in the {} key store: {err}",
            kind.as_str()
        )),
    }
}

/// Whether `key_pkcs8_der` is the private half of the key `expected`
/// fingerprints (the SPKI hash the device certificate carries).
fn matches_certificate(key_pkcs8_der: &[u8], expected: &Fingerprint) -> bool {
    use rcgen::{KeyPair, PublicKeyData as _};

    KeyPair::try_from(key_pkcs8_der)
        .map(|key| Fingerprint::of_spki_der(&key.subject_public_key_info()) == *expected)
        .unwrap_or(false)
}

/// Put `destination` back to what it held before the move wrote to it.
/// Best effort: a failure here is logged by kind only, and the original
/// error is the one reported.
fn undo_destination(
    destination: &dyn KeyStore,
    kind: KeyStoreKind,
    prior: Option<&Zeroizing<Vec<u8>>>,
) {
    let result = match prior {
        Some(key) => destination.store(key),
        None => destination.delete(),
    };
    if let Err(err) = result {
        tracing::warn!(
            store = kind.as_str(),
            %err,
            "could not restore the {} key store after a failed identity.move_key",
            kind.as_str()
        );
    }
}

/// Move this device's private key to the `to` store.
///
/// `platform` replaces the OS credential store; production callers pass
/// `None`. `audit` writes the one fail-closed audit record, once, after
/// the move is known to be a change and before the first one.
///
/// **Runtime caveat:** with a platform store on either end this blocks on
/// the OS credential store, like [`super::load`].
pub fn move_key(
    paths: &crate::config::Paths,
    to: KeyStoreKind,
    platform: Option<&dyn KeyStore>,
    audit: impl FnOnce(KeyStoreKind, KeyStoreKind) -> Result<(), OpError>,
) -> Result<IdentityMoveKeyData, OpError> {
    let no_identity =
        || OpError::new(ErrorCode::ConfigError, NO_LOCAL_IDENTITY).with_retryable(false);
    // Nothing is created (not even the lock file) before an identity is
    // known to exist.
    if read_identity(paths)?.is_none() {
        return Err(no_identity());
    }
    let _lock = lock_identity(paths)?;
    // Read again under the lock: another `move-key` may have run between.
    let identity = read_identity(paths)?.ok_or_else(no_identity)?;
    let from = identity.key_store;
    if from == to {
        return Ok(IdentityMoveKeyData {
            from,
            to,
            moved: false,
            stale_entry_left: false,
        });
    }

    // The record to put back byte for byte on a failed rewrite is the file
    // as it is now; `write_private_file` renames over it atomically, so the
    // original survives a failed write on its own.
    let record_path = paths.identity_dir().join(IDENTITY_FILE);
    let record_text = std::fs::read_to_string(&record_path)
        .map_err(|err| crate::config::config_io_error(&record_path, "read", &err))?;
    let mut record: IdentityFile = toml::from_str(&record_text).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("invalid identity record {}: {err}", record_path.display()),
        )
        .with_retryable(false)
    })?;

    audit(from, to)?;

    let source = slot(paths, &identity.device_id, from, platform);
    let destination = slot(paths, &identity.device_id, to, platform);

    let Some(key) = source.load().map_err(|err| read_error(from, &err))? else {
        return Err(internal(format!(
            "identity key missing from {}; nothing was moved",
            from.as_str()
        )));
    };

    // What the destination held before, so a failed move puts it back
    // instead of deleting something that was there already.
    let prior = destination.load().map_err(|err| write_error(to, &err))?;

    if let Err(err) = destination.store(&key) {
        undo_destination(&*destination, to, prior.as_ref());
        return Err(write_error(to, &err));
    }

    let readback = match destination.load() {
        Ok(Some(readback)) if matches_certificate(&readback, &identity.fingerprint) => readback,
        outcome => {
            undo_destination(&*destination, to, prior.as_ref());
            return Err(match outcome {
                Err(err) => read_error(to, &err),
                Ok(_) => internal(format!(
                    "the key read back from the {} key store is not the key of this device \
                     certificate; nothing was moved",
                    to.as_str()
                )),
            });
        }
    };
    drop(readback);

    record.key_store = to;
    let text = match toml::to_string_pretty(&record) {
        Ok(text) => text,
        Err(err) => {
            undo_destination(&*destination, to, prior.as_ref());
            return Err(internal(format!("failed to encode {IDENTITY_FILE}: {err}")));
        }
    };
    if let Err(err) = write_private_file(&record_path, text.as_bytes()) {
        undo_destination(&*destination, to, prior.as_ref());
        return Err(err);
    }

    // The identity now points at the new store, so the move has happened;
    // a failed delete leaves a copy behind and says so.
    let stale_entry_left = match source.delete() {
        Ok(()) => false,
        Err(err) => {
            tracing::warn!(
                store = from.as_str(),
                %err,
                "the old key store entry could not be deleted after identity.move_key"
            );
            true
        }
    };
    tracing::info!(
        from = from.as_str(),
        to = to.as_str(),
        stale_entry_left,
        "device key moved"
    );

    Ok(IdentityMoveKeyData {
        from,
        to,
        moved: true,
        stale_entry_left,
    })
}
