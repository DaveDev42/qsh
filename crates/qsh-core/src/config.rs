//! Config and state path resolution plus `config.toml` loading
//! (`docs/design/architecture.md` §7).
//!
//! macOS and Linux use the same, ssh-style predictable layout — never
//! `~/Library/…`:
//!
//! ```text
//! ~/.config/qsh/       # $QSH_CONFIG_DIR → $XDG_CONFIG_HOME/qsh → this
//! ├── config.toml
//! ├── trust.toml
//! └── identity/        # device.pem (+ device.key 0600 in file mode)
//! ~/.local/state/qsh/  # $QSH_STATE_DIR → $XDG_STATE_HOME/qsh → this
//! └── audit.log
//! ```

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use qsh_proto::{ErrorCode, KeyStoreMode};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ops::OpError;

/// Resolved config and state directories for one QSH invocation.
///
/// Resolution happens once, at startup ([`Paths::from_env`]); every module
/// that needs a file derives it from these two roots so tests can redirect
/// the whole tree with a single temporary directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `~/.config/qsh` by default: identity, trust store, config.
    pub config_dir: PathBuf,
    /// `~/.local/state/qsh` by default: audit log and other mutable state.
    pub state_dir: PathBuf,
}

impl Paths {
    /// Build from explicit directories (tests, embedding).
    pub fn new(config_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
            state_dir: state_dir.into(),
        }
    }

    /// Resolve from the environment:
    ///
    /// - config: `$QSH_CONFIG_DIR` → `$XDG_CONFIG_HOME/qsh` → `$HOME/.config/qsh`
    /// - state: `$QSH_STATE_DIR` → `$XDG_STATE_HOME/qsh` → `$HOME/.local/state/qsh`
    ///
    /// Returns [`ErrorCode::ConfigError`] when no home directory can be
    /// determined and no explicit override is set.
    pub fn from_env() -> Result<Self, OpError> {
        Self::from_lookup(|key| std::env::var_os(key).map(PathBuf::from), home_dir())
    }

    /// The env-independent core of [`Paths::from_env`], so the precedence
    /// rules can be tested without mutating process-global state.
    fn from_lookup(
        get: impl Fn(&str) -> Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> Result<Self, OpError> {
        let resolve = |explicit: &str, xdg: &str, tail: &str| -> Option<PathBuf> {
            if let Some(dir) = get(explicit).filter(|p| !p.as_os_str().is_empty()) {
                return Some(dir);
            }
            if let Some(dir) = get(xdg).filter(|p| !p.as_os_str().is_empty()) {
                return Some(dir.join("qsh"));
            }
            home.as_ref().map(|h| h.join(tail))
        };

        let config_dir = resolve("QSH_CONFIG_DIR", "XDG_CONFIG_HOME", ".config/qsh")
            .ok_or_else(|| Self::no_home("config"))?;
        let state_dir = resolve("QSH_STATE_DIR", "XDG_STATE_HOME", ".local/state/qsh")
            .ok_or_else(|| Self::no_home("state"))?;
        Ok(Self {
            config_dir,
            state_dir,
        })
    }

    fn no_home(which: &str) -> OpError {
        OpError::new(
            ErrorCode::ConfigError,
            format!(
                "cannot determine the {which} directory: no home directory in the environment \
                 (set $HOME, $XDG_{}_HOME or $QSH_{}_DIR)",
                which.to_uppercase(),
                which.to_uppercase()
            ),
        )
        .with_retryable(false)
    }

    /// `<config_dir>/config.toml`.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// `<config_dir>/trust.toml`.
    pub fn trust_file(&self) -> PathBuf {
        self.config_dir.join("trust.toml")
    }

    /// `<config_dir>/identity`.
    pub fn identity_dir(&self) -> PathBuf {
        self.config_dir.join("identity")
    }

    /// `<state_dir>/audit.log`.
    pub fn audit_log(&self) -> PathBuf {
        self.state_dir.join("audit.log")
    }

    /// `<state_dir>/resume.json` — the client's resume-token store
    /// (0600, ADR-0007). Never readable output: see [`crate::resume`].
    pub fn resume_file(&self) -> PathBuf {
        self.state_dir.join("resume.json")
    }

    /// The lock file serialising cross-process read-modify-write of
    /// [`Paths::resume_file`] (ADR-0007 "원자성·durability·동시성").
    pub fn resume_lock_file(&self) -> PathBuf {
        self.state_dir.join("resume.json.lock")
    }
}

/// The user's home directory, as `$HOME` or the platform equivalent.
fn home_dir() -> Option<PathBuf> {
    std::env::home_dir()
}

/// Create `dir` (and its parents) with mode 0700, and tighten an existing
/// directory's mode to 0700.
///
/// Private-by-construction: the identity directory holds a 0600 key in file
/// mode, so the enclosing directory must be as tight as an sshd host-key
/// directory (`docs/design/architecture.md` §5).
pub fn ensure_private_dir(dir: &Path) -> Result<(), OpError> {
    ensure_private_dir_io(dir).map_err(|err| config_io_error(dir, "create directory", &err))
}

pub(crate) fn ensure_private_dir_io(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        if !dir.exists() {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            // `recursive` + `mode` only applies the mode to directories this
            // call actually creates; re-assert it on the leaf.
        }
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `contents` to `path` with mode 0600, atomically (temp file in the
/// same directory + rename) so a crash never leaves a half-written key,
/// certificate or trust store.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), OpError> {
    write_private_file_io(path, contents).map_err(|err| config_io_error(path, "write", &err))
}

pub(crate) fn write_private_file_io(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tmp = dir.join(file_name);
    tmp.as_mut_os_string()
        .push(format!(".tmp{}", std::process::id()));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let result = (|| -> io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        // `OpenOptions::mode` is ignored for a pre-existing file; re-assert.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Wrap an I/O failure on a config-tree path as a `CONFIG_ERROR`.
pub(crate) fn config_io_error(path: &Path, what: &str, err: &io::Error) -> OpError {
    OpError::new(
        ErrorCode::ConfigError,
        format!("failed to {what} {}: {err}", path.display()),
    )
    .with_retryable(false)
}

/// Current UTC time as an RFC 3339 string truncated to whole seconds, e.g.
/// `2026-08-17T00:00:00Z` (`docs/CLI.md` §2.3: UTC RFC 3339 everywhere).
pub fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    now.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// RFC 3339, second precision, formatted from an explicit `t` rather than
/// "now" — for callers that hold their own injected clock (`docs/design/
/// testing.md` L2) instead of reading the system clock directly.
///
/// Shared by `broker::Broker::now_rfc3339` and
/// `reverse::registry::Registry::admit`, which both need "seconds since
/// epoch, formatted as RFC 3339, falling back to the Unix epoch string on
/// out-of-range input" and previously carried byte-for-byte copies of this
/// body.
pub(crate) fn rfc3339_of(t: SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// `config.toml` (`docs/design/architecture.md` §7).
///
/// Every field is optional and unknown keys are ignored: a newer build's
/// config must not break an older binary (`docs/CLI.md` §2.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Config {
    /// `[serve]` — long-running listener settings.
    pub serve: ServeConfig,
    /// `[identity]` — device identity settings.
    pub identity: IdentityConfig,
    /// `[listen]` — reverse-mode controller settings (`qsh listen`).
    pub listen: ListenConfig,
    /// `[reverse]` — reverse-mode target settings (`qsh reverse`).
    pub reverse: ReverseConfig,
}

/// `[serve]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ServeConfig {
    /// Listen address. `qsh serve --bind` wins over this, which wins over
    /// the `[::]:4433` default (`docs/CLI.md` §6.12).
    pub bind: Option<String>,
    /// Per-session replay ring byte budget. Unset ⇒
    /// [`ServeConfig::DEFAULT_REPLAY_BYTES`] (8 MiB, `docs/PRD.md` §13,
    /// ADR-0004).
    pub replay_bytes: Option<usize>,
    /// Resume TTL for unattached sessions, in seconds (`[serve].resume_ttl`
    /// — `docs/design/architecture.md` §7, `docs/CLI.md` §6.4). Unset ⇒
    /// [`ServeConfig::DEFAULT_RESUME_TTL_SECS`] (24 h, `docs/PRD.md` §13).
    /// `resume_ttl_secs` is accepted as an alias.
    #[serde(alias = "resume_ttl_secs")]
    pub resume_ttl: Option<u64>,
    /// Per-step grace of the close signal escalation, in milliseconds.
    /// Unset ⇒ [`ServeConfig::DEFAULT_CLOSE_GRACE_MS`] (5 s,
    /// `docs/CLI.md` §6.7).
    pub close_grace_ms: Option<u64>,
}

impl ServeConfig {
    /// Default per-session replay budget: 8 MiB (`docs/PRD.md` §13).
    pub const DEFAULT_REPLAY_BYTES: usize = 8 * 1024 * 1024;
    /// Default resume TTL: 24 hours (`docs/PRD.md` §13).
    pub const DEFAULT_RESUME_TTL_SECS: u64 = 24 * 60 * 60;
    /// Default close escalation grace: 5 seconds (`docs/CLI.md` §6.7).
    pub const DEFAULT_CLOSE_GRACE_MS: u64 = 5000;

    /// Effective replay budget (never zero; a `0` in config is treated as
    /// the default rather than an unusable ring).
    pub fn replay_bytes(&self) -> usize {
        match self.replay_bytes {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_REPLAY_BYTES,
        }
    }

    /// Effective resume TTL.
    pub fn resume_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.resume_ttl.unwrap_or(Self::DEFAULT_RESUME_TTL_SECS))
    }

    /// Effective close escalation grace.
    pub fn close_grace(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.close_grace_ms.unwrap_or(Self::DEFAULT_CLOSE_GRACE_MS),
        )
    }
}

/// `[identity]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Private-key store preference; `qsh init --key-store` wins over it.
    pub key_store: Option<KeyStoreMode>,
}

/// `[listen]` section — `qsh listen`, the reverse-mode controller
/// (`docs/CLI.md` §6.13, `docs/design/protocol.md` §11-2).
///
/// `PLAN.md` Step 3 PR 3a wires `bind`/`allow_advertised_names` only;
/// `stale_retention` (§11-4) is Step 4 scope and is not read yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ListenConfig {
    /// Listen address. `qsh listen --bind` wins over this, which wins over
    /// the `[::]:4433` default — the same default `qsh serve` uses, so
    /// running both roles on one host requires an explicit `--bind`
    /// (`docs/CLI.md` §6.13).
    pub bind: Option<String>,
    /// Whether a reverse target with no trust-store alias may register
    /// under its self-reported `offered_name`. Default `false`: name-
    /// squatting prevention wins unless an operator opts in
    /// (`docs/design/protocol.md` §11-2).
    pub allow_advertised_names: bool,
}

/// `[reverse]` section — `qsh reverse <controller>`, the reverse-mode
/// target (`docs/CLI.md` §6.13, `docs/design/protocol.md` §11-2).
///
/// `PLAN.md` Step 3 PR 3a wires `controller`/`offered_name` only; the
/// backoff/heartbeat knobs (§11-4) are Step 4 scope and are not read yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ReverseConfig {
    /// Trust-store alias of the controller to dial. The `qsh reverse
    /// <controller>` positional argument wins over this.
    pub controller: Option<String>,
    /// Name this target offers itself as. `--offered-name` wins over this.
    /// Only takes effect when the controller has no trust-store alias for
    /// this peer *and* the controller's `[listen].allow_advertised_names`
    /// is set — see `reverse::admit::admit`.
    pub offered_name: Option<String>,
}

impl Config {
    /// Load `<config_dir>/config.toml`. A missing file is not an error —
    /// it yields [`Config::default`]. A malformed file is a hard
    /// `CONFIG_ERROR` (fail closed on ambiguous configuration).
    pub fn load(paths: &Paths) -> Result<Self, OpError> {
        let path = paths.config_file();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(config_io_error(&path, "read", &err)),
        };
        toml::from_str(&text).map_err(|err| {
            OpError::new(
                ErrorCode::ConfigError,
                format!("invalid config file {}: {err}", path.display()),
            )
            .with_retryable(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<PathBuf> + use<> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| {
            owned
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| PathBuf::from(v))
        }
    }

    #[test]
    fn explicit_override_wins_over_xdg_and_home() {
        let paths = Paths::from_lookup(
            lookup(&[
                ("QSH_CONFIG_DIR", "/explicit/config"),
                ("XDG_CONFIG_HOME", "/xdg"),
                ("XDG_STATE_HOME", "/xdgstate"),
            ]),
            Some(PathBuf::from("/home/dave")),
        )
        .unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("/explicit/config"));
        assert_eq!(paths.state_dir, PathBuf::from("/xdgstate/qsh"));
    }

    #[test]
    fn home_is_the_last_resort() {
        let paths = Paths::from_lookup(lookup(&[]), Some(PathBuf::from("/home/dave"))).unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("/home/dave/.config/qsh"));
        assert_eq!(
            paths.state_dir,
            PathBuf::from("/home/dave/.local/state/qsh")
        );
    }

    #[test]
    fn missing_home_is_a_config_error() {
        let err = Paths::from_lookup(lookup(&[]), None).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(!err.retryable);
    }

    #[test]
    fn derived_paths_hang_off_the_two_roots() {
        let paths = Paths::new("/c", "/s");
        assert_eq!(paths.config_file(), PathBuf::from("/c/config.toml"));
        assert_eq!(paths.trust_file(), PathBuf::from("/c/trust.toml"));
        assert_eq!(paths.identity_dir(), PathBuf::from("/c/identity"));
        assert_eq!(paths.audit_log(), PathBuf::from("/s/audit.log"));
    }

    #[test]
    fn missing_config_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path(), dir.path());
        let config = Config::load(&paths).unwrap();
        assert_eq!(config, Config::default());
        assert!(config.identity.key_store.is_none());
    }

    #[test]
    fn config_file_is_parsed_and_unknown_keys_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path(), dir.path());
        std::fs::write(
            paths.config_file(),
            "[identity]\nkey_store = \"file\"\n\n[serve]\nbind = \"127.0.0.1:4433\"\n\n\
             [future]\nsomething = 1\n",
        )
        .unwrap();
        let config = Config::load(&paths).unwrap();
        assert_eq!(config.identity.key_store, Some(KeyStoreMode::File));
        assert_eq!(config.serve.bind.as_deref(), Some("127.0.0.1:4433"));
    }

    #[test]
    fn serve_broker_keys_use_the_documented_names_and_defaults() {
        // architecture.md §7 / PLAN Step 2: `[serve] replay_bytes ·
        // resume_ttl · close_grace_ms`. Unknown keys are ignored, so a
        // misnamed key would silently fall back to the default — pin the
        // documented spellings.
        let serve: ServeConfig =
            toml::from_str("replay_bytes = 1024\nresume_ttl = 60\nclose_grace_ms = 250\n").unwrap();
        assert_eq!(serve.replay_bytes(), 1024);
        assert_eq!(serve.resume_ttl(), std::time::Duration::from_secs(60));
        assert_eq!(serve.close_grace(), std::time::Duration::from_millis(250));
        // The `_secs` spelling is an accepted alias.
        let alias: ServeConfig = toml::from_str("resume_ttl_secs = 5\n").unwrap();
        assert_eq!(alias.resume_ttl(), std::time::Duration::from_secs(5));
        // Defaults: 8 MiB, 24 h, 5 s; replay_bytes = 0 degrades to default.
        let empty: ServeConfig = toml::from_str("replay_bytes = 0\n").unwrap();
        assert_eq!(empty.replay_bytes(), 8 * 1024 * 1024);
        assert_eq!(
            empty.resume_ttl(),
            std::time::Duration::from_secs(24 * 3600)
        );
        assert_eq!(empty.close_grace(), std::time::Duration::from_millis(5000));
    }

    #[test]
    fn listen_and_reverse_keys_use_the_documented_names_and_defaults() {
        // architecture.md §7 / CLI.md §6.13 / PLAN Step 3 PR 3a:
        // `[listen] bind · allow_advertised_names` and `[reverse]
        // controller · offered_name`. Pin the documented spellings and the
        // `allow_advertised_names = false` default (name-squatting
        // prevention wins unless explicitly opted into).
        let listen: ListenConfig =
            toml::from_str("bind = \"[::]:5000\"\nallow_advertised_names = true\n").unwrap();
        assert_eq!(listen.bind.as_deref(), Some("[::]:5000"));
        assert!(listen.allow_advertised_names);

        let listen_default = ListenConfig::default();
        assert_eq!(listen_default.bind, None);
        assert!(!listen_default.allow_advertised_names);

        let reverse: ReverseConfig =
            toml::from_str("controller = \"personal-mac\"\noffered_name = \"phone\"\n").unwrap();
        assert_eq!(reverse.controller.as_deref(), Some("personal-mac"));
        assert_eq!(reverse.offered_name.as_deref(), Some("phone"));

        let reverse_default = ReverseConfig::default();
        assert_eq!(reverse_default.controller, None);
        assert_eq!(reverse_default.offered_name, None);
    }

    #[test]
    fn config_file_parses_listen_and_reverse_sections() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path(), dir.path());
        std::fs::write(
            paths.config_file(),
            "[listen]\nbind = \"127.0.0.1:5000\"\nallow_advertised_names = true\n\n\
             [reverse]\ncontroller = \"personal-mac\"\noffered_name = \"phone\"\n",
        )
        .unwrap();
        let config = Config::load(&paths).unwrap();
        assert_eq!(config.listen.bind.as_deref(), Some("127.0.0.1:5000"));
        assert!(config.listen.allow_advertised_names);
        assert_eq!(config.reverse.controller.as_deref(), Some("personal-mac"));
        assert_eq!(config.reverse.offered_name.as_deref(), Some("phone"));
    }

    #[test]
    fn malformed_config_file_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path(), dir.path());
        std::fs::write(paths.config_file(), "[identity\nkey_store =").unwrap();
        let err = Config::load(&paths).unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(!err.retryable);
        assert!(
            err.message.contains("config.toml"),
            "message: {}",
            err.message
        );
    }

    #[test]
    fn now_rfc3339_has_second_granularity_and_z_suffix() {
        let now = now_rfc3339();
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(now.len(), "2026-08-17T00:00:00Z".len(), "{now}");
        assert!(OffsetDateTime::parse(&now, &Rfc3339).is_ok(), "{now}");
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_and_file_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        ensure_private_dir(&nested).unwrap();
        let mode = std::fs::metadata(&nested).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // Idempotent, and tightens an already-loose directory.
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&nested).unwrap();
        let mode = std::fs::metadata(&nested).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        let file = nested.join("secret");
        write_private_file(&file, b"hello").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(&file).unwrap(), b"hello");

        // Overwriting keeps 0600 and leaves no temp file behind.
        write_private_file(&file, b"world").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"world");
        let leftovers: Vec<_> = std::fs::read_dir(&nested)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind");
    }
}
