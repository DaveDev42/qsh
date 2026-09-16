//! `identity.init` and loading this device's identity.

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
}
