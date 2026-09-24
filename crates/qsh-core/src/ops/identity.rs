//! `identity.init`/`identity.export` and loading this device's identity.

use std::fs::OpenOptions;
use std::io::Write as _;

use super::*;

impl Ops {
    // -----------------------------------------------------------------
    // identity
    // -----------------------------------------------------------------

    /// `identity.init` — create this device's identity if it does not exist
    /// (idempotent: an existing identity comes back with `created: false`).
    ///
    /// Key-store selection: the request wins over `config.toml`
    /// `[identity].key_store`, which wins over `auto`.
    pub fn identity_init(&self, req: IdentityInitReq) -> Result<IdentityInitData, OpError> {
        let mode = match req.key_store {
            Some(mode) => mode,
            None => self
                .config()?
                .identity
                .key_store
                .unwrap_or(KeyStoreMode::Auto),
        };
        crate::identity::init(&self.paths, mode)
    }

    /// This device's identity plus its private key, or `None` before
    /// `qsh init`.
    ///
    /// **Runtime caveat:** with a platform key store this blocks on the OS
    /// credential store — call it outside a tokio runtime, or from
    /// `spawn_blocking` (see [`crate::identity::load`]).
    pub fn load_identity(&self) -> Result<Option<LoadedIdentity>, OpError> {
        crate::identity::load(&self.paths)
    }

    /// `identity.export` — this device's certificate as PEM, never the
    /// private key (`docs/CLI.md` §6.11, ADR-0013).
    ///
    /// Reads only through [`crate::identity::read_identity`] — never
    /// [`crate::identity::load`], the key store, or `device.key`
    /// (`identity_export_never_opens_the_key_store` pins this). The bytes
    /// returned or written are `device.pem`'s file text verbatim, with its
    /// single-`CERTIFICATE`-block invariant re-asserted on read rather
    /// than assumed (that invariant is enforced on *write*, by `init` and
    /// `promote_to_ca_issued`, never checked on read until now).
    pub fn identity_export(&self, req: IdentityExportReq) -> Result<IdentityExportData, OpError> {
        let identity = crate::identity::read_identity(&self.paths)?.ok_or_else(|| {
            OpError::new(ErrorCode::ConfigError, crate::identity::NO_LOCAL_IDENTITY)
                .with_retryable(false)
        })?;

        let cert_path = self.paths.identity_dir().join(crate::identity::CERT_FILE);
        let text = std::fs::read_to_string(&cert_path)
            .map_err(|err| crate::config::config_io_error(&cert_path, "read", &err))?;
        let blocks = crate::identity::pem::decode_all(crate::identity::pem::CERTIFICATE, &text)
            .map_err(|_| {
                OpError::new(
                    ErrorCode::ConfigError,
                    "device certificate must contain exactly one CERTIFICATE block",
                )
                .with_retryable(false)
            })?;
        if blocks.len() != 1 {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                "device certificate must contain exactly one CERTIFICATE block",
            )
            .with_retryable(false));
        }

        let name = identity.device_id;
        // Derived from `blocks[0]` (this read of `text`), never from
        // `identity.fingerprint` (`read_identity`'s own, separate read of
        // the same file): the two reads are not atomic, so only a
        // fingerprint computed from the exact bytes this op is about to
        // return as `cert_pem` is guaranteed to describe them.
        let fingerprint = Fingerprint::of_cert_der(&blocks[0])
            .map_err(|err| {
                OpError::new(
                    ErrorCode::ConfigError,
                    format!("invalid device certificate {}: {err}", cert_path.display()),
                )
                .with_retryable(false)
            })?
            .to_string();

        let Some(out) = req.out else {
            return Ok(IdentityExportData {
                name,
                fingerprint,
                cert_pem: Some(text),
                path: None,
            });
        };

        let write_result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out)
            .and_then(|mut file| file.write_all(text.as_bytes()));
        if let Err(err) = write_result {
            return Err(if err.kind() == std::io::ErrorKind::AlreadyExists {
                OpError::new(ErrorCode::InvalidArgument, format!("{out} already exists"))
                    .with_retryable(false)
            } else {
                OpError::new(ErrorCode::Internal, format!("failed to write {out}: {err}"))
                    .with_retryable(false)
            });
        }

        Ok(IdentityExportData {
            name,
            fingerprint,
            cert_pem: None,
            path: Some(out),
        })
    }
}
