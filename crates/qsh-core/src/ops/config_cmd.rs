//! `config.*` operations: read and edit this machine's `config.toml`
//! (`docs/CLI.md` §6.23, ADR-0051 결정 10).
//!
//! Local operations with no authorization: they act on the invoking user's
//! own file and never touch the network. Writers serialise on
//! `config.toml.lock`, the same sidecar-lock discipline `trust.toml` uses,
//! and the edited document must load and validate before it replaces the
//! file; a rejected edit leaves the file byte-identical.

use qsh_proto::{
    ConfigEntry, ConfigGetData, ConfigGetReq, ConfigListData, ConfigListReq, ConfigSetData,
    ConfigSetReq, ConfigUnsetData, ConfigUnsetReq,
};

use super::*;
use crate::config::{FileLock, ensure_private_dir, lock_path_for, write_private_file};
use crate::config_edit::{self, ConfigKey, Edit};

impl Ops {
    fn read_config_text(&self) -> Result<String, OpError> {
        let path = self.paths.config_file();
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(err) => Err(crate::config::config_io_error(&path, "read", &err)),
        }
    }

    /// `config.get` — the stored value of one key. An unset key is
    /// `set: false`, not an error.
    pub fn config_get(&self, req: ConfigGetReq) -> Result<ConfigGetData, OpError> {
        let key = config_edit::lookup(&req.key)?;
        let doc = config_edit::parse_document(&self.read_config_text()?)?;
        let value = config_edit::read_value(&doc, key)?;
        Ok(ConfigGetData {
            key: key.path(),
            set: value.is_some(),
            value,
            applies_from: key.applies_from(),
        })
    }

    /// `config.list` — the keys `config.toml` sets, or with `all` every
    /// known key, in registry order.
    pub fn config_list(&self, req: ConfigListReq) -> Result<ConfigListData, OpError> {
        let doc = config_edit::parse_document(&self.read_config_text()?)?;
        let mut entries = Vec::new();
        for key in config_edit::KEYS {
            let value = config_edit::read_value(&doc, key)?;
            if value.is_none() && !req.all {
                continue;
            }
            entries.push(ConfigEntry {
                key: key.path(),
                set: value.is_some(),
                value,
                applies_from: key.applies_from(),
            });
        }
        Ok(ConfigListData { entries })
    }

    /// `config.set` — write one key. The edited document must pass the same
    /// parse and range checks the daemons apply at startup; on failure the
    /// file is untouched and the error is `INVALID_ARGUMENT` (the value
    /// itself is malformed or not allowed for the key) or `CONFIG_ERROR`
    /// (the value is well formed but the resulting configuration is not
    /// valid, for example outside a range or inconsistent with another key).
    /// Setting the value a key already holds writes nothing.
    pub fn config_set(&self, req: ConfigSetReq) -> Result<ConfigSetData, OpError> {
        let key = config_edit::lookup(&req.key)?;
        let edit = self.commit_config_edit(key, |text| config_edit::set(text, key, &req.value))?;
        let changed = edit.changed();
        Ok(ConfigSetData {
            key: key.path(),
            value: edit.current.unwrap_or(serde_json::Value::Null),
            previous: edit.previous,
            changed,
            applies_from: if changed { key.applies_from() } else { None },
        })
    }

    /// `config.unset` — remove one key so its built-in default applies.
    /// Unsetting a key that is not set writes nothing.
    pub fn config_unset(&self, req: ConfigUnsetReq) -> Result<ConfigUnsetData, OpError> {
        let key = config_edit::lookup(&req.key)?;
        let edit = self.commit_config_edit(key, |text| config_edit::unset(text, key))?;
        let changed = edit.changed();
        Ok(ConfigUnsetData {
            key: key.path(),
            previous: edit.previous,
            changed,
            applies_from: if changed { key.applies_from() } else { None },
        })
    }

    /// The shared read-modify-write: lock, read, edit, validate, save.
    fn commit_config_edit(
        &self,
        _key: &ConfigKey,
        edit: impl FnOnce(&str) -> Result<Edit, OpError>,
    ) -> Result<Edit, OpError> {
        let path = self.paths.config_file();
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let _lock = FileLock::acquire(&lock_path_for(&path))?;
        let text = self.read_config_text()?;
        let edit = edit(&text)?;
        if !edit.changed() && edit.text == text {
            return Ok(edit);
        }
        validate_edited(&edit.text)?;
        write_private_file(&path, edit.text.as_bytes())?;
        Ok(edit)
    }
}

/// The checks `config.toml` has to pass before an edit replaces it.
fn validate_edited(text: &str) -> Result<(), OpError> {
    let config: Config = toml::from_str(text).map_err(|err| {
        OpError::new(
            ErrorCode::InvalidArgument,
            format!("config.toml would not load after this change, so it was not changed: {err}"),
        )
        .with_retryable(false)
    })?;
    config.validate().map_err(|mut err| {
        err.message = format!("{}; config.toml was not changed", err.message);
        err
    })
}

#[cfg(test)]
mod tests;
