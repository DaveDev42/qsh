//! `hosts.toml` — the host profile address book
//! (`docs/design/architecture.md` §7, `PLAN.md` M7 Step 3):
//!
//! ```toml
//! [[host]]
//! name = "personal-mac"
//! address = "personal-mac.example.com:4433"
//! user = "dave"
//! ```
//!
//! **Read-only in M7** — no CLI command writes this file (a manually-edited
//! directory, same posture `docs/design/architecture.md` §7 documents).
//!
//! **Deliberately separate from [`crate::trust::TrustStore`].** `hosts.toml`
//! is an address/user-hint book, never a trust source: it carries no
//! fingerprint, and nothing in this module ever asserts a peer's identity.
//! `Ops::resolve_peer`/`Ops::host_list`/`Ops::host_get`/`Ops::resolve_host_route`
//! layer this over the trust store's pinned peers — hosts.toml's address
//! wins when both name a host, trust remains the sole arbiter of *who* that
//! address may turn out to be (`PLAN.md` M7 §4.1 #4). See `crate::ops::host`
//! for the merge/priority logic that actually implements that decision;
//! this module only loads and indexes the file.

use std::io;
use std::path::Path;

use qsh_proto::ErrorCode;
use serde::Deserialize;

use crate::config::config_io_error;
use crate::ops::OpError;

/// One `[[host]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HostEntry {
    /// Local alias — matched against `qsh <name>`/`qsh exec <name>`/etc.
    pub name: String,
    /// `host:port` to dial. Required by the TOML shape (unlike
    /// `trust.toml`'s `TrustPeer.address`, which is legitimately empty for
    /// a client-only pin) — hosts.toml exists purely to answer "where do I
    /// dial this name", so an entry with nothing to say there is malformed
    /// input, not a valid client-only record. An explicit `address = ""`
    /// still parses (TOML has no way to reject a value shape-only), but is
    /// treated as "no route from hosts.toml for this name" the same way
    /// `trust.toml`'s own empty address is (`TrustStore::resolve_host`).
    pub address: String,
    /// Assertion hint for `SessionOpen.user` (`docs/CLI.md` §7) — never an
    /// identity, never a login selector. Absent unless the file sets it.
    #[serde(default)]
    pub user: Option<String>,
}

/// `hosts.toml` as serialized.
#[derive(Debug, Default, Deserialize)]
struct HostsToml {
    #[serde(default, rename = "host")]
    host: Vec<HostEntry>,
}

/// An in-memory snapshot of `hosts.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostsFile {
    entries: Vec<HostEntry>,
}

impl HostsFile {
    /// Load `path`. A missing file is an empty directory (not an error) —
    /// the M7-before posture (`architecture.md` §7's own doc). A malformed
    /// one is `CONFIG_ERROR`, the same failure mode
    /// [`crate::trust::TrustStore::load`] uses for `trust.toml`: this
    /// module never guesses at an address any more than trust guesses at
    /// identity.
    pub fn load(path: &Path) -> Result<Self, OpError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(config_io_error(path, "read", &err)),
        };
        let file: HostsToml = toml::from_str(&text).map_err(|err| {
            OpError::new(
                ErrorCode::ConfigError,
                format!("invalid hosts file {}: {err}", path.display()),
            )
            .with_retryable(false)
        })?;
        Ok(Self { entries: file.host })
    }

    /// Every `[[host]]` entry, in file order.
    pub fn entries(&self) -> &[HostEntry] {
        &self.entries
    }

    /// The entry named `name`, if any. The *first* match when a file
    /// (malformed operator input, never produced by this crate) repeats a
    /// name — mirrors [`crate::trust::TrustStore::find`]'s own "first
    /// match wins" rule rather than inventing a different one.
    pub fn find(&self, name: &str) -> Option<&HostEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = HostsFile::load(&dir.path().join("hosts.toml")).unwrap();
        assert!(loaded.entries().is_empty());
        assert_eq!(loaded.find("anything"), None);
    }

    #[test]
    fn parses_name_address_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\nname = \"personal-mac\"\naddress = \"personal-mac.example.com:4433\"\n\
             user = \"dave\"\n\n\
             [[host]]\nname = \"headless-server\"\naddress = \"server.example.com:4433\"\n",
        )
        .unwrap();

        let loaded = HostsFile::load(&path).unwrap();
        assert_eq!(loaded.entries().len(), 2);

        let mac = loaded.find("personal-mac").unwrap();
        assert_eq!(mac.address, "personal-mac.example.com:4433");
        assert_eq!(mac.user.as_deref(), Some("dave"));

        // `user` is genuinely optional — omitting it must not be a parse
        // error, and must not synthesize an empty string.
        let server = loaded.find("headless-server").unwrap();
        assert_eq!(server.user, None);

        assert_eq!(loaded.find("nowhere"), None);
    }

    #[test]
    fn malformed_file_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.toml");
        std::fs::write(&path, "[[host]]\nname = ").unwrap();
        let err = HostsFile::load(&path).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(!err.retryable);
    }

    /// `address` has no `#[serde(default)]` — an entry that omits it
    /// entirely is a parse error (missing required field), not a silent
    /// empty string. An operator who writes `address = ""` explicitly gets
    /// a *parsed* entry with an empty address instead (covered by
    /// `crate::ops::host`'s merge tests, which is where "empty address"
    /// is actually interpreted as "not routable from hosts.toml").
    #[test]
    fn a_missing_address_field_is_a_config_error_not_an_empty_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.toml");
        std::fs::write(&path, "[[host]]\nname = \"no-address\"\n").unwrap();
        let err = HostsFile::load(&path).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
    }

    #[test]
    fn an_empty_file_is_the_same_as_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.toml");
        std::fs::write(&path, "").unwrap();
        let loaded = HostsFile::load(&path).unwrap();
        assert!(loaded.entries().is_empty());
    }

    #[test]
    fn duplicate_names_first_entry_wins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.toml");
        std::fs::write(
            &path,
            "[[host]]\nname = \"dup\"\naddress = \"first.example.com:1\"\n\n\
             [[host]]\nname = \"dup\"\naddress = \"second.example.com:2\"\n",
        )
        .unwrap();
        let loaded = HostsFile::load(&path).unwrap();
        assert_eq!(loaded.entries().len(), 2, "both entries still parse");
        assert_eq!(
            loaded.find("dup").unwrap().address,
            "first.example.com:1",
            "first match wins, mirroring TrustStore::find"
        );
    }
}
