//! `config.get`, `config.set`, `config.unset` and `config.list` request and
//! data types (ADR-0051 결정 10).
//!
//! All four are **local** operations on this machine's own `config.toml`:
//! no wire counterpart, no authorization. A key is a dotted path
//! `<section>.<key>` (`serve.bind`, `transport.keep_alive_ms`). The value
//! travels as a string on the request side (the CLI has no types) and as a
//! native JSON scalar on the data side.

use super::*;

/// The only value of `applies_from`: the key is read once when a daemon or
/// command starts, so a running process keeps the old value until it is
/// restarted.
pub const CONFIG_APPLIES_FROM_NEXT_START: &str = "next_start";

/// Request for `config.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigGetReq {
    /// Dotted key path, e.g. `serve.bind`. An unknown key is
    /// `INVALID_ARGUMENT`.
    pub key: String,
}

/// Data payload of `config.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigGetData {
    /// The key asked for, as spelled in `config.toml` (an alias such as
    /// `serve.resume_ttl_secs` is reported under its canonical name).
    pub key: String,
    /// Whether `config.toml` has this key. `false` is not an error: the
    /// built-in default applies.
    pub set: bool,
    /// The stored value as a JSON string, number or boolean. Omitted when
    /// the key is not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    /// `"next_start"` for a key a running process does not re-read. Omitted
    /// for a key that takes effect on the next command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_from: Option<String>,
}

/// Request for `config.set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigSetReq {
    /// Dotted key path.
    pub key: String,
    /// The new value as typed on the command line. The key's type decides
    /// how it is read: a string key keeps it verbatim, an integer key
    /// requires decimal digits, a boolean key requires `true` or `false`.
    pub value: String,
}

/// Data payload of `config.set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigSetData {
    /// The canonical key name.
    pub key: String,
    /// The value now stored.
    pub value: serde_json::Value,
    /// The value before the call. Omitted when the key was not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<serde_json::Value>,
    /// `false` when the key already held exactly this value: nothing was
    /// written.
    pub changed: bool,
    /// `"next_start"` for a key a running process does not re-read.
    /// Omitted otherwise, and omitted when `changed` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_from: Option<String>,
}

/// Request for `config.unset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigUnsetReq {
    /// Dotted key path.
    pub key: String,
}

/// Data payload of `config.unset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigUnsetData {
    /// The canonical key name.
    pub key: String,
    /// The value that was removed. Omitted when the key was not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<serde_json::Value>,
    /// `false` when the key was not set: nothing was written.
    pub changed: bool,
    /// `"next_start"` for a key a running process does not re-read.
    /// Omitted otherwise, and omitted when `changed` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_from: Option<String>,
}

/// Request for `config.list`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigListReq {
    /// Also list the known keys `config.toml` does not set.
    #[serde(default)]
    pub all: bool,
}

/// One row of `config.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigEntry {
    /// Dotted key path.
    pub key: String,
    /// Whether `config.toml` has this key.
    pub set: bool,
    /// The stored value. Omitted when the key is not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    /// `"next_start"` for a key a running process does not re-read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_from: Option<String>,
}

/// Data payload of `config.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigListData {
    /// In the order the keys appear in the section table (not file order):
    /// stable across edits. Only set keys unless the request asked for
    /// `all`.
    pub entries: Vec<ConfigEntry>,
}
