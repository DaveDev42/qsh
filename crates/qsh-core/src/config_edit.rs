//! The key registry and the comment-preserving editor behind `qsh config
//! get|set|unset|list` (ADR-0051 결정 10).
//!
//! A key is the dotted path `<section>.<key>` over `config.toml`
//! (`serve.bind`, `transport.keep_alive_ms`). [`KEYS`] names every key
//! [`crate::config::Config`] reads; the test `every_config_key_is_settable`
//! builds a `Config` with struct literals that name every field, so adding
//! a field without adding its row here stops compiling or fails that test.
//!
//! Editing goes through `toml_edit`, which keeps comments, blank lines and
//! key order. The editor is pure (text in, text out): locking, validation
//! against [`crate::config::Config`] and the atomic write belong to the
//! caller, [`crate::ops::Ops::config_set`].

use qsh_proto::{CONFIG_APPLIES_FROM_NEXT_START, ErrorCode};
use serde_json::Value as Json;
use toml_edit::{DocumentMut, Item, Table, Value};

use crate::ops::OpError;

/// The TOML type a key holds. It decides how `config set` reads its
/// argument and what `config get` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// A string, kept verbatim.
    Str,
    /// A non-negative decimal integer.
    Int,
    /// `true` or `false`.
    Bool,
    /// One string, or a list of strings (`iroh.relay_url`, ADR-0062). On the
    /// command line the list is written separated by commas or spaces. One
    /// value is stored as a TOML string, so a key that has always held a
    /// string keeps doing so; two or more are stored as an array.
    StrOrList,
}

/// One settable key.
#[derive(Debug, Clone, Copy)]
pub struct ConfigKey {
    /// Section table name.
    pub section: &'static str,
    /// Key inside the section.
    pub key: &'static str,
    /// Value type.
    pub ty: KeyType,
    /// The only accepted strings for an enumerated string key; empty when
    /// any string is accepted.
    pub choices: &'static [&'static str],
    /// Older spellings of the key that `Config` still reads. `set` and
    /// `unset` remove them so the canonical key is the only one left.
    pub aliases: &'static [&'static str],
    /// `true` when a running daemon (or a command already underway) does
    /// not re-read the key: a new value applies from the next start.
    pub startup_only: bool,
}

impl ConfigKey {
    /// The dotted path, `section.key`.
    pub fn path(&self) -> String {
        format!("{}.{}", self.section, self.key)
    }

    /// `Some("next_start")` for a startup-only key.
    pub fn applies_from(&self) -> Option<String> {
        self.startup_only
            .then(|| CONFIG_APPLIES_FROM_NEXT_START.to_string())
    }
}

const fn key(
    section: &'static str,
    key: &'static str,
    ty: KeyType,
    startup_only: bool,
) -> ConfigKey {
    ConfigKey {
        section,
        key,
        ty,
        choices: &[],
        aliases: &[],
        startup_only,
    }
}

use KeyType::{Bool, Int, Str, StrOrList};

/// Every key `config.toml` reads, in documentation order.
///
/// `serve.*`, `listen.*`, `reverse.*`, `audit.*`, `transport.*` and
/// `recovery.*` are read once when a daemon or a connecting command starts.
/// `identity.key_store`, `ssh.*`, `interactive.*` and `agent.forward` are read by each command
/// that uses them, so they apply to the next command. `punch.mode` is read by
/// each client command, but `qsh listen` and `qsh serve --to` read it once at
/// start, so it applies from the next start. `iroh.enable`, `iroh.relay_url`,
/// `iroh.bind_port`, `iroh.proxy` and `iroh.portmap` are read once by a daemon
/// (ADR-0061, ADR-0064); `iroh.mode` and `iroh.head_start_ms` only by client
/// commands.
pub const KEYS: &[ConfigKey] = &[
    key("serve", "bind", Str, true),
    key("serve", "to", Str, true),
    key("serve", "replay_bytes", Int, true),
    ConfigKey {
        aliases: &["resume_ttl_secs"],
        ..key("serve", "resume_ttl", Int, true)
    },
    key("serve", "close_grace_ms", Int, true),
    key("serve", "max_concurrent_handshakes", Int, true),
    key("serve", "handshake_rate_per_source", Int, true),
    key("serve", "max_sessions", Int, true),
    key("serve", "max_sessions_per_principal", Int, true),
    key("serve", "max_exec_per_principal", Int, true),
    key("serve", "validated_rate_per_source", Int, true),
    key("serve", "max_exec", Int, true),
    key("serve", "max_tunnel_streams_per_principal", Int, true),
    key("serve", "max_tunnel_streams_per_forward", Int, true),
    key("serve", "max_remote_forwards_per_principal", Int, true),
    key("serve", "max_connections_per_principal", Int, true),
    key("serve", "max_connections", Int, true),
    key("serve", "max_file_transfers_per_principal", Int, true),
    key("serve", "max_file_transfers", Int, true),
    key("serve", "on_demand_idle_ms", Int, true),
    ConfigKey {
        choices: &["auto", "platform", "file"],
        ..key("identity", "key_store", Str, false)
    },
    key("listen", "bind", Str, true),
    key("listen", "allow_advertised_names", Bool, true),
    key("listen", "stale_retention", Int, true),
    key("listen", "serve", Bool, true),
    key("reverse", "controller", Str, true),
    key("reverse", "offered_name", Str, true),
    key("reverse", "backoff_initial_ms", Int, true),
    key("reverse", "backoff_max_ms", Int, true),
    key("reverse", "backoff_jitter_pct", Int, true),
    key("audit", "path", Str, true),
    key("audit", "max_bytes", Int, true),
    key("audit", "retain", Int, true),
    key("audit", "queue_depth", Int, true),
    key("transport", "keep_alive_ms", Int, true),
    ConfigKey {
        choices: &["on", "off"],
        ..key("transport", "adaptive", Str, true)
    },
    key("recovery", "probe_interval_ms", Int, true),
    key("recovery", "min_dead_after_ms", Int, true),
    key("recovery", "strikes", Int, true),
    key("recovery", "reverse_min_dead_after_ms", Int, true),
    key("recovery", "reverse_strikes", Int, true),
    ConfigKey {
        choices: &["auto", "off"],
        ..key("ssh", "bootstrap", Str, false)
    },
    key("ssh", "program", Str, false),
    key("ssh", "remote_qsh", Str, false),
    ConfigKey {
        choices: &["auto", "on", "off"],
        ..key("interactive", "screen_sync", Str, false)
    },
    ConfigKey {
        choices: &["auto", "always", "never"],
        ..key("interactive", "predict", Str, false)
    },
    ConfigKey {
        choices: &["on", "off"],
        ..key("interactive", "status_line", Str, false)
    },
    ConfigKey {
        choices: &["auto", "off"],
        ..key("punch", "mode", Str, true)
    },
    ConfigKey {
        choices: &["no", "yes"],
        ..key("agent", "forward", Str, false)
    },
    key("iroh", "enable", Bool, true),
    key("iroh", "relay_url", StrOrList, true),
    key("iroh", "bind_port", Int, true),
    ConfigKey {
        choices: &["auto", "off"],
        ..key("iroh", "mode", Str, false)
    },
    ConfigKey {
        choices: &["env", "off"],
        ..key("iroh", "proxy", Str, true)
    },
    key("iroh", "head_start_ms", Int, false),
    key("iroh", "portmap", Bool, true),
];

fn invalid(message: String) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}

fn config_error(message: String) -> OpError {
    OpError::new(ErrorCode::ConfigError, message).with_retryable(false)
}

/// Resolve a dotted path to its registry row. Anything not in [`KEYS`] is
/// `INVALID_ARGUMENT`: `config.toml` ignores unknown keys when it is read,
/// so a typo accepted here would be written and then silently do nothing.
pub fn lookup(path: &str) -> Result<&'static ConfigKey, OpError> {
    KEYS.iter().find(|k| k.path() == path).ok_or_else(|| {
        invalid(format!(
            "unknown config key {path:?}; keys are written <section>.<key>, \
                 run `qsh config list --all` for the full set"
        ))
    })
}

/// Parse `config.toml` text into an editable document. A parse failure is
/// `CONFIG_ERROR`: the file is not ours to repair.
pub fn parse_document(text: &str) -> Result<DocumentMut, OpError> {
    text.parse::<DocumentMut>().map_err(|err| {
        config_error(format!(
            "config.toml is not valid TOML and was not changed: {err}"
        ))
    })
}

fn scalar_to_json(k: &ConfigKey, value: &Value) -> Result<Json, OpError> {
    match value {
        Value::String(s) => Ok(Json::String(s.value().clone())),
        Value::Integer(i) => Ok(Json::from(*i.value())),
        Value::Boolean(b) => Ok(Json::Bool(*b.value())),
        Value::Array(items) if k.ty == KeyType::StrOrList => items
            .iter()
            .map(|item| match item {
                Value::String(s) => Ok(Json::String(s.value().clone())),
                other => Err(config_error(format!(
                    "config key {} holds a list with a {} where a string is expected",
                    k.path(),
                    other.type_name()
                ))),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Json::Array),
        other => Err(config_error(format!(
            "config key {} holds a {} where a string, integer or boolean is expected",
            k.path(),
            other.type_name()
        ))),
    }
}

/// The stored value of `k`, looking under its aliases too.
pub fn read_value(doc: &DocumentMut, k: &ConfigKey) -> Result<Option<Json>, OpError> {
    let Some(item) = doc.get(k.section) else {
        return Ok(None);
    };
    let table = item
        .as_table_like()
        .ok_or_else(|| config_error(format!("config.toml [{}] is not a table", k.section)))?;
    for name in std::iter::once(&k.key).chain(k.aliases.iter()) {
        if let Some(entry) = table.get(name) {
            let value = entry.as_value().ok_or_else(|| {
                config_error(format!("config key {} is not a plain value", k.path()))
            })?;
            return scalar_to_json(k, value).map(Some);
        }
    }
    Ok(None)
}

/// Read `raw` as `k`'s type.
pub fn parse_argument(k: &ConfigKey, raw: &str) -> Result<Value, OpError> {
    match k.ty {
        KeyType::Str => {
            if !k.choices.is_empty() && !k.choices.contains(&raw) {
                return Err(invalid(format!(
                    "{} must be one of {}, got {raw:?}",
                    k.path(),
                    k.choices.join(", ")
                )));
            }
            Ok(Value::from(raw))
        }
        KeyType::Int => {
            let n: u64 = raw.parse().map_err(|_| {
                invalid(format!(
                    "{} takes a non-negative decimal integer, got {raw:?}",
                    k.path()
                ))
            })?;
            let n = i64::try_from(n)
                .map_err(|_| invalid(format!("{} value {n} is too large to store", k.path())))?;
            Ok(Value::from(n))
        }
        KeyType::StrOrList => {
            let items: Vec<&str> = raw
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|item| !item.is_empty())
                .collect();
            match items.as_slice() {
                [] => Err(invalid(format!(
                    "{} takes a value, or several separated by commas, got {raw:?}",
                    k.path()
                ))),
                [one] => Ok(Value::from(*one)),
                many => Ok(Value::Array(many.iter().copied().collect())),
            }
        }
        KeyType::Bool => match raw {
            "true" => Ok(Value::from(true)),
            "false" => Ok(Value::from(false)),
            _ => Err(invalid(format!(
                "{} takes true or false, got {raw:?}",
                k.path()
            ))),
        },
    }
}

/// The outcome of one edit: the new file text and the values around it.
#[derive(Debug)]
pub struct Edit {
    /// The document after the edit, comments and order intact.
    pub text: String,
    /// The value before, `None` when the key was not set.
    pub previous: Option<Json>,
    /// The value after, `None` when the key is now unset.
    pub current: Option<Json>,
}

impl Edit {
    /// Whether the edit changed the stored value.
    pub fn changed(&self) -> bool {
        self.previous != self.current
    }
}

/// Set `k` to `value` in `text`. The trailing comment on an existing line
/// stays with the new value.
pub fn set(text: &str, k: &ConfigKey, raw: &str) -> Result<Edit, OpError> {
    let mut doc = parse_document(text)?;
    let previous = read_value(&doc, k)?;
    let value = parse_argument(k, raw)?;
    let current = scalar_to_json(k, &value)?;
    if previous.as_ref() == Some(&current) && !has_alias(&doc, k) {
        return Ok(Edit {
            text: text.to_string(),
            previous,
            current: Some(current),
        });
    }
    if doc.get(k.section).is_none() {
        doc[k.section] = Item::Table(Table::new());
    }
    let table = doc[k.section]
        .as_table_like_mut()
        .ok_or_else(|| config_error(format!("config.toml [{}] is not a table", k.section)))?;
    for alias in k.aliases {
        table.remove(alias);
    }
    match table.get_mut(k.key).and_then(Item::as_value_mut) {
        Some(existing) => {
            let mut value = value;
            *value.decor_mut() = existing.decor().clone();
            *existing = value;
        }
        None => {
            table.insert(k.key, Item::Value(value));
        }
    }
    Ok(Edit {
        text: doc.to_string(),
        previous,
        current: Some(current),
    })
}

fn has_alias(doc: &DocumentMut, k: &ConfigKey) -> bool {
    doc.get(k.section)
        .and_then(Item::as_table_like)
        .is_some_and(|t| k.aliases.iter().any(|a| t.contains_key(a)))
}

/// Remove `k` (and its aliases) from `text`. An emptied section table with
/// no comment of its own goes with it.
pub fn unset(text: &str, k: &ConfigKey) -> Result<Edit, OpError> {
    let mut doc = parse_document(text)?;
    let previous = read_value(&doc, k)?;
    if previous.is_none() {
        return Ok(Edit {
            text: text.to_string(),
            previous: None,
            current: None,
        });
    }
    if let Some(table) = doc.get_mut(k.section).and_then(Item::as_table_like_mut) {
        table.remove(k.key);
        for alias in k.aliases {
            table.remove(alias);
        }
    }
    let drop_section = doc
        .get(k.section)
        .and_then(Item::as_table)
        .is_some_and(|t| {
            t.is_empty()
                && t.decor()
                    .prefix()
                    .and_then(|p| p.as_str())
                    .is_none_or(|p| p.trim().is_empty())
        });
    if drop_section {
        doc.remove(k.section);
    }
    Ok(Edit {
        text: doc.to_string(),
        previous,
        current: None,
    })
}
