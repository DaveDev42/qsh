//! Config and state path resolution plus `config.toml` loading
//! (`docs/design/architecture.md` §7).
//!
//! macOS and Linux use the same, ssh-style predictable layout — never
//! `~/Library/…`:
//!
//! ```text
//! ~/.config/qsh/       # $QSH_CONFIG_DIR → $XDG_CONFIG_HOME/qsh → this
//! ├── config.toml
//! ├── hosts.toml       # [[host]] name·address·user (crate::hosts, M7 Step 3)
//! ├── trust.toml
//! └── identity/        # device.pem (+ device.key 0600 in file mode)
//! ~/.local/state/qsh/  # $QSH_STATE_DIR → $XDG_STATE_HOME/qsh → this
//! └── audit.log
//! ```

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use qsh_proto::{ErrorCode, KeyStoreMode};
use serde::{Deserialize, Serialize};
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
    /// Test/embedding-only override for [`Paths::runtime_dir`], bypassing
    /// the `$XDG_RUNTIME_DIR` environment lookup entirely. `None` (the
    /// default from every constructor) means "resolve from the process
    /// environment as documented".
    ///
    /// Exists because `runtime_dir()` reads `$XDG_RUNTIME_DIR` from the
    /// *process* environment (unlike `config_dir`/`state_dir`, which are
    /// resolved once by the caller and stored), so a `Paths` built from a
    /// tempdir does **not**, on its own, keep localctl sockets inside that
    /// tempdir on a machine where `$XDG_RUNTIME_DIR` happens to be set
    /// (any Linux desktop/SSH session under systemd-logind, WSL2+systemd,
    /// most CI images) — every `localctl`/`reverse::listen` unit test binds
    /// a real socket at `paths.localctl_socket(pid)` and must not do that
    /// outside its own tempdir (adversarial review finding: without this,
    /// those tests raced and unlinked sockets in the ambient runtime
    /// directory, including a real resident `qsh listen`'s). Set with
    /// [`Paths::with_runtime_dir`].
    runtime_dir_override: Option<PathBuf>,
}

impl Paths {
    /// Build from explicit directories (tests, embedding).
    pub fn new(config_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
            state_dir: state_dir.into(),
            runtime_dir_override: None,
        }
    }

    /// Pin [`Paths::runtime_dir`] to `dir`, independent of
    /// `$XDG_RUNTIME_DIR` and the `state_dir/run` fallback. For tests (and
    /// any other embedding) that need a deterministic, sandboxed location
    /// for localctl sockets regardless of what the host process's
    /// environment happens to export — see `Paths::runtime_dir_override`'s
    /// doc for why this is necessary rather than merely convenient.
    pub fn with_runtime_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.runtime_dir_override = Some(dir.into());
        self
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
            runtime_dir_override: None,
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

    /// `<config_dir>/hosts.toml` — the host profile address book
    /// (`docs/design/architecture.md` §7, `PLAN.md` M7 Step 3,
    /// `crate::hosts::HostsFile`). Read-only in M7: no CLI command writes
    /// this path.
    pub fn hosts_file(&self) -> PathBuf {
        self.config_dir.join("hosts.toml")
    }

    /// `<config_dir>/acl.toml` (`docs/design/architecture.md` §7,
    /// `crate::acl::load::PolicySource`). serve/listen roles only.
    pub fn acl_file(&self) -> PathBuf {
        self.config_dir.join("acl.toml")
    }

    /// `<config_dir>/invites.toml` — open pairing invites (ADR-0002, M7
    /// Step 4, `crate::trust::pairing::InviteStore`). Never carries the raw
    /// invite secret, only its `blake3` hash — see that module's doc.
    pub fn invites_file(&self) -> PathBuf {
        self.config_dir.join("invites.toml")
    }

    /// `<config_dir>/identity`.
    pub fn identity_dir(&self) -> PathBuf {
        self.config_dir.join("identity")
    }

    /// `<config_dir>/ca` — the private CA's root cert + key
    /// (`docs/adr/0008-private-ca-cert-issuance.md` §4, `PLAN.md` M7 Step
    /// 5). Deliberately separate from [`Paths::identity_dir`]: this
    /// device's own identity and its issuance authority (if any) are
    /// different threats and belong in different directories.
    pub fn ca_dir(&self) -> PathBuf {
        self.config_dir.join("ca")
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

    /// Runtime directory for this machine's localctl UDS sockets:
    /// `$XDG_RUNTIME_DIR/qsh` when that variable is set (and non-empty),
    /// else `<state_dir>/run` (`docs/design/architecture.md` §7).
    ///
    /// This is a **two-tier** rule, unlike `config_dir`/`state_dir`'s
    /// three-tier one ([`Paths::from_env`]) — the documented contract has
    /// no `$QSH_RUNTIME_DIR` override, only the XDG variable and the
    /// state-dir fallback, so this method does not invent one.
    ///
    /// The daemon (`qsh listen`) is responsible for creating this
    /// directory with mode 0700 ([`ensure_private_dir`]) before binding a
    /// socket in it and for unlinking its socket on exit; this method only
    /// computes the path, so both the daemon and a discovering CLI process
    /// agree on where to look whether or not the directory exists yet — a
    /// missing runtime directory just means no `qsh listen` has ever run
    /// here (`localctl::client::candidate_sockets`, `#[cfg(unix)]`-only,
    /// treats it the same way).
    pub fn runtime_dir(&self) -> PathBuf {
        if let Some(dir) = &self.runtime_dir_override {
            return dir.clone();
        }
        self.runtime_dir_from(|key| std::env::var_os(key).map(PathBuf::from))
    }

    /// The env-independent core of [`Paths::runtime_dir`], so the
    /// precedence rule can be tested without mutating process-global state
    /// (same technique as [`Paths::from_lookup`]).
    fn runtime_dir_from(&self, get: impl Fn(&str) -> Option<PathBuf>) -> PathBuf {
        get("XDG_RUNTIME_DIR")
            .filter(|p| !p.as_os_str().is_empty())
            .map(|dir| dir.join("qsh"))
            .unwrap_or_else(|| self.state_dir.join("run"))
    }

    /// `<runtime_dir>/<pid>.sock` — the localctl UDS path a `qsh listen`
    /// daemon with this pid binds, and a CLI process connects to
    /// (`docs/design/architecture.md` §7, `docs/design/protocol.md`
    /// §11-3).
    pub fn localctl_socket(&self, pid: u32) -> PathBuf {
        self.runtime_dir().join(format!("{pid}.sock"))
    }
}

/// The user's home directory, as `$HOME` or the platform equivalent.
///
/// `pub(crate)`: `crate::ops::doctor`'s `service_not_registered`/
/// `launchagent_session_scoped` detectors (`docs/CLI.md` §6.17) need this
/// same resolution to build `~/Library/LaunchAgents/…`/`~/.config/systemd/
/// user/…` service-unit paths — one source of truth for "what `$HOME`
/// means on this process" rather than a second, possibly-drifted
/// `std::env::home_dir()` call in `ops/doctor.rs`.
pub(crate) fn home_dir() -> Option<PathBuf> {
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

/// The ticket [`write_private_file_io`]'s *next* call will consume. Lets a
/// crash-safety test predict the exact temp path a write will use without
/// racing the write itself or resetting shared state — `ca::init`'s and
/// `identity::promote_to_ca_issued`'s `*_recovers_from_an_interrupted_*_write`
/// tests block a specific temp path with a directory to force that write to
/// fail. Forwards to [`crate::fsutil`]'s shared ticket counter (`PLAN.md`
/// M7 Step 7-2 carryover (iv)) — this crate's other durable writer
/// (`resume::write_durably`) draws from the exact same counter now, not a
/// second one of its own, so this prediction is unaffected by which of
/// the two call sites the previous write went through.
///
/// The prediction this enables is only sound under a **process-isolated
/// test runner** (`cargo nextest run`, this repo's required one —
/// `.github/workflows/ci.yml`): under plain `cargo test`'s in-process,
/// thread-parallel execution, any other test scheduled at the same time
/// that also writes a private file can consume a ticket between this read
/// and the write it's predicting for, making the caller's prediction
/// wrong (`PLAN.md` M7 Step 7-1 검증 라운드 A1, reproduced). Callers of
/// this function carry the same caveat in their own doc comments.
#[cfg(test)]
pub(crate) fn next_write_ticket_for_test() -> u64 {
    crate::fsutil::next_write_ticket_for_test()
}

pub(crate) fn write_private_file_io(path: &Path, contents: &[u8]) -> io::Result<()> {
    crate::fsutil::write_atomically(path, contents, false)
}

/// Wrap an I/O failure on a config-tree path as a `CONFIG_ERROR`.
pub(crate) fn config_io_error(path: &Path, what: &str, err: &io::Error) -> OpError {
    OpError::new(
        ErrorCode::ConfigError,
        format!("failed to {what} {}: {err}", path.display()),
    )
    .with_retryable(false)
}

/// `<path>.lock` — the sidecar advisory-lock path for one file's whole
/// read-modify-write cycle. Shared naming convention for every
/// [`FileLock`] site in the config tree (`trust.toml`, `invites.toml`, the
/// CA directory) — mirrors `audit::writer`'s own `lock_path_for` (a
/// directory of rotated files, `<active>.<n>`, so `.lock` can never
/// collide with a rotation slot; here a directory of config files, so
/// `.lock` can never collide with a real file name either).
pub(crate) fn lock_path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// An exclusive advisory lock held for the duration of one
/// read-modify-write, on **every** platform — promoted from
/// `crate::resume` (`PLAN.md` M7 Step 7-1 brief §4) so `trust.toml`,
/// `invites.toml` and the CA root's key+cert pair share the same
/// mechanism `resume.json` already relies on, instead of each config file
/// re-deriving its own.
///
/// `std::fs::File::lock` is `flock(2)` on unix — the mechanism ADR-0007
/// names — and `LockFileEx` on Windows, so the serialisation a `qsh
/// serve` pairing responder running next to an interactive `trust`
/// command depends on is real there too rather than a no-op that quietly
/// loses a write.
///
/// **Lock ordering.** Every call site in this crate that also holds a
/// `std::sync::RwLock`/`Mutex` (`SharedInviteStore::redeem`'s cache lock
/// is the one example today) must acquire that lock **first** and this
/// one **second**, never the reverse — reversing it risks a deadlock
/// between a thread waiting on the `RwLock` while holding this file lock,
/// and another thread (or process) waiting on this file lock while
/// holding the `RwLock`. Every site in this codebase acquires this lock
/// directly around a synchronous read-modify-write with no `.await` and
/// no further lock acquisition inside its critical section, so that
/// ordering is the only invariant that matters.
pub(crate) struct FileLock {
    file: std::fs::File,
}

impl FileLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, OpError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| config_io_error(path, "open lock file", &e))?;
        // Blocking exclusive lock: every critical section behind this lock
        // is a small file rewrite (no network I/O, see the call sites'
        // docs), and a failed lock would mean losing a write outright.
        file.lock().map_err(|e| config_io_error(path, "lock", &e))?;
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing the file releases the lock anyway; being explicit keeps
        // the critical section obvious.
        let _ = self.file.unlock();
    }
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// `[audit]` — audit log lifecycle settings (rotation, retention, async
    /// writer queue depth; `docs/design/architecture.md` §7, `PLAN.md` M5
    /// Step 1). No `[acl]` section exists — policy lives in the separate
    /// `acl.toml` file, not `config.toml` (same file/`Config` split
    /// `trust.toml` already has).
    pub audit: AuditConfig,
}

/// `[serve]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Upper bound on connections concurrently *in handshake* — from
    /// admission through `Incoming::accept()` resolving, released before
    /// `serve_connection` (`crate::admission::Gate`, `PLAN.md` M8 Step 2,
    /// `docs/adr/0009-admission-defenses.md`). Unset or `0` ⇒
    /// [`ServeConfig::DEFAULT_MAX_CONCURRENT_HANDSHAKES`] (64) — same "0
    /// degrades to default, never unlimited" discipline as
    /// [`ServeConfig::replay_bytes`]: this defense has no off switch.
    /// `[listen]` has no key of its own — `Listen::run` reads this same
    /// value (design arbitration, `PLAN.md` M8 Step 2).
    pub max_concurrent_handshakes: Option<usize>,
    /// Per-source rate limit on address-*unvalidated* Initials, in new
    /// attempts per second (key: IPv4 /32, IPv6 /64; burst 2x, not
    /// separately configurable). Unset or `0` ⇒
    /// [`ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE`] (10). Same
    /// no-off-switch discipline as `max_concurrent_handshakes`.
    pub handshake_rate_per_source: Option<u32>,
    /// Global cap on live (not closed) sessions across all principals
    /// (`crate::quota`, `PLAN.md` M8 Step 3, `docs/adr/0010-resource-
    /// quotas.md`). Derived from the broker registry, not a separate
    /// counter (`docs/design/architecture.md` §1). Unset or `0` ⇒
    /// [`ServeConfig::DEFAULT_MAX_SESSIONS`] (256) — same no-off-switch
    /// discipline as `max_concurrent_handshakes`.
    pub max_sessions: Option<usize>,
    /// Per-principal cap on live sessions, keyed by the session's
    /// `opener` (`crate::acl::opener_key`). Unset or `0` ⇒
    /// [`ServeConfig::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL`] (32). Same
    /// no-off-switch discipline.
    pub max_sessions_per_principal: Option<usize>,
    /// Per-principal cap on concurrently *running* (unredeemed-ticket)
    /// `exec.run` children (`crate::quota::QuotaKind::ExecPerPrincipal`).
    /// Unset or `0` ⇒ [`ServeConfig::DEFAULT_MAX_EXEC_PER_PRINCIPAL`]
    /// (32). Same no-off-switch discipline.
    pub max_exec_per_principal: Option<usize>,
    /// Per-source rate limit on address-*validated* handshake attempts
    /// (P2-3, `docs/adr/0010-resource-quotas.md`) — a second axis beside
    /// `handshake_rate_per_source`'s unvalidated one; same key shape
    /// (IPv4 /32, IPv6 /64). Unset or `0` ⇒
    /// [`ServeConfig::DEFAULT_VALIDATED_RATE_PER_SOURCE`] (10). Same
    /// no-off-switch discipline.
    pub validated_rate_per_source: Option<u32>,
    /// Host-wide cap on concurrently running `exec.run` children
    /// (`crate::quota::QuotaKind::ExecHost`), checked before the
    /// per-principal axis (`crate::quota::Quotas::reserve_exec`). Unset or
    /// `0` ⇒ [`ServeConfig::DEFAULT_MAX_EXEC`] (256). Same no-off-switch
    /// discipline.
    pub max_exec: Option<usize>,
    /// Per-principal cap on concurrently open tunnel (`-L`) streams
    /// (`crate::quota::QuotaKind::TunnelStreamsPerPrincipal`, M8 Step 3b,
    /// `docs/adr/0010-resource-quotas.md`). Unset or `0` ⇒
    /// [`ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_PRINCIPAL`] (256).
    /// Same no-off-switch discipline.
    pub max_tunnel_streams_per_principal: Option<usize>,
    /// Per-`(principal, destination)` cap on concurrently open tunnel
    /// streams (`crate::quota::QuotaKind::TunnelStreamsPerForward`). Unset
    /// or `0` ⇒ [`ServeConfig::DEFAULT_MAX_TUNNEL_STREAMS_PER_FORWARD`]
    /// (64). Same no-off-switch discipline.
    pub max_tunnel_streams_per_forward: Option<usize>,
    /// Per-principal cap on concurrently open remote-forward (`-R`)
    /// listeners (`crate::quota::QuotaKind::RemoteForwardsPerPrincipal`).
    /// Unset or `0` ⇒
    /// [`ServeConfig::DEFAULT_MAX_REMOTE_FORWARDS_PER_PRINCIPAL`] (16).
    /// Same no-off-switch discipline.
    pub max_remote_forwards_per_principal: Option<usize>,
    /// Per-principal cap on concurrently open connections
    /// (`crate::quota::QuotaKind::ConnectionsPerPrincipal`). Unset or `0`
    /// ⇒ [`ServeConfig::DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL`] (32). Same
    /// no-off-switch discipline.
    pub max_connections_per_principal: Option<usize>,
    /// Accept-arm-wide cap on concurrently open connections
    /// (`crate::quota::QuotaKind::Connections`) — per accept arm (`qsh
    /// serve`'s `Server::run` and `qsh listen`'s `Listen` each get an
    /// independent budget; M8 Step 3b ruling R6), not per process. Unset
    /// or `0` ⇒ [`ServeConfig::DEFAULT_MAX_CONNECTIONS`] (512). Same
    /// no-off-switch discipline. The fixed pre-identity (pairing)
    /// connection cap (`crate::quota::MAX_CONCURRENT_PAIRING_CONNECTIONS`,
    /// 8) has no config key of its own.
    pub max_connections: Option<usize>,
}

impl ServeConfig {
    /// Default per-session replay budget: 8 MiB (`docs/PRD.md` §13).
    pub const DEFAULT_REPLAY_BYTES: usize = 8 * 1024 * 1024;
    /// Default resume TTL: 24 hours (`docs/PRD.md` §13).
    pub const DEFAULT_RESUME_TTL_SECS: u64 = 24 * 60 * 60;
    /// Default close escalation grace: 5 seconds (`docs/CLI.md` §6.7).
    pub const DEFAULT_CLOSE_GRACE_MS: u64 = 5000;
    /// Default handshake concurrency cap: 64 (`PLAN.md` M8 Step 2 — the
    /// same magnitude as `localctl::daemon::MAX_CONCURRENT_LOCALCTL_HANDSHAKES`,
    /// so the codebase tells one story about this class of bound).
    pub const DEFAULT_MAX_CONCURRENT_HANDSHAKES: usize = 64;
    /// Default per-source unvalidated-Initial rate: 10/s (`PLAN.md` M8
    /// Step 2).
    pub const DEFAULT_HANDSHAKE_RATE_PER_SOURCE: u32 = 10;
    /// Default global live-session cap: 256 (`PLAN.md` M8 Step 3,
    /// `docs/adr/0010-resource-quotas.md`).
    pub const DEFAULT_MAX_SESSIONS: usize = 256;
    /// Default per-principal live-session cap: 32.
    pub const DEFAULT_MAX_SESSIONS_PER_PRINCIPAL: usize = 32;
    /// Default per-principal concurrent-`exec.run` cap: 32.
    pub const DEFAULT_MAX_EXEC_PER_PRINCIPAL: usize = 32;
    /// Default per-source validated-handshake rate: 10/s — deliberately the
    /// same number as [`ServeConfig::DEFAULT_HANDSHAKE_RATE_PER_SOURCE`], not
    /// an oversight. `admission::Gate::decide` runs the unvalidated axis
    /// first, so the validated axis only ever sees attempts that axis already
    /// passed; at equal rates (and therefore equal per-epoch burst, `rate ×
    /// EPOCH`) it can never see more than the first axis let through, and a
    /// `validated_rate_limited` rejection is close to unreachable at the
    /// defaults — only an epoch-boundary skew between the two sketches
    /// produces one. That is the intended shape, not a hole to close by
    /// lowering this value: ADR-0011 makes several concurrent `qsh exec` runs
    /// from one host a supported pattern and their handshakes share a source
    /// key, so a smaller validated budget would refuse legitimate concurrency
    /// the unvalidated axis has already bounded. An operator who wants this
    /// axis to bite lowers it alone (`crates/qsh-cli/tests/adversarial_load.
    /// rs` scenario 1 does exactly that, with 3). Revisit if quinn's
    /// NEW_TOKEN validation tokens are adopted: a returning client's Initial
    /// would then arrive already validated, skipping Retry, and this axis
    /// becomes the only gate on that path.
    pub const DEFAULT_VALIDATED_RATE_PER_SOURCE: u32 = 10;
    /// Default host-wide concurrent-`exec.run` cap: 256 (`PLAN.md` M8 Step
    /// 3b, `docs/adr/0010-resource-quotas.md`).
    pub const DEFAULT_MAX_EXEC: usize = 256;
    /// Default per-principal concurrent tunnel-stream cap: 256.
    pub const DEFAULT_MAX_TUNNEL_STREAMS_PER_PRINCIPAL: usize = 256;
    /// Default per-`(principal, destination)` concurrent tunnel-stream cap:
    /// 64.
    pub const DEFAULT_MAX_TUNNEL_STREAMS_PER_FORWARD: usize = 64;
    /// Default per-principal concurrent remote-forward-listener cap: 16.
    pub const DEFAULT_MAX_REMOTE_FORWARDS_PER_PRINCIPAL: usize = 16;
    /// Default per-principal concurrent-connection cap: 32.
    pub const DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL: usize = 32;
    /// Default accept-arm-wide concurrent-connection cap: 512.
    pub const DEFAULT_MAX_CONNECTIONS: usize = 512;

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

    /// Effective handshake concurrency cap (never zero — `0` in config
    /// degrades to the default, same discipline as
    /// [`ServeConfig::replay_bytes`]: this defense cannot be switched off).
    pub fn max_concurrent_handshakes(&self) -> usize {
        match self.max_concurrent_handshakes {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        }
    }

    /// Effective per-source handshake rate (never zero, same discipline).
    pub fn handshake_rate_per_source(&self) -> u32 {
        match self.handshake_rate_per_source {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_HANDSHAKE_RATE_PER_SOURCE,
        }
    }

    /// Effective global live-session cap (never zero, same discipline).
    pub fn max_sessions(&self) -> usize {
        match self.max_sessions {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_SESSIONS,
        }
    }

    /// Effective per-principal live-session cap (never zero, same
    /// discipline).
    pub fn max_sessions_per_principal(&self) -> usize {
        match self.max_sessions_per_principal {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL,
        }
    }

    /// Effective per-principal concurrent-`exec.run` cap (never zero,
    /// same discipline).
    pub fn max_exec_per_principal(&self) -> usize {
        match self.max_exec_per_principal {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_EXEC_PER_PRINCIPAL,
        }
    }

    /// Effective per-source validated-handshake rate (never zero, same
    /// discipline).
    pub fn validated_rate_per_source(&self) -> u32 {
        match self.validated_rate_per_source {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_VALIDATED_RATE_PER_SOURCE,
        }
    }

    /// Effective host-wide concurrent-`exec.run` cap (never zero, same
    /// discipline).
    pub fn max_exec(&self) -> usize {
        match self.max_exec {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_EXEC,
        }
    }

    /// Effective per-principal concurrent tunnel-stream cap (never zero,
    /// same discipline).
    pub fn max_tunnel_streams_per_principal(&self) -> usize {
        match self.max_tunnel_streams_per_principal {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_TUNNEL_STREAMS_PER_PRINCIPAL,
        }
    }

    /// Effective per-`(principal, destination)` concurrent tunnel-stream
    /// cap (never zero, same discipline).
    pub fn max_tunnel_streams_per_forward(&self) -> usize {
        match self.max_tunnel_streams_per_forward {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_TUNNEL_STREAMS_PER_FORWARD,
        }
    }

    /// Effective per-principal concurrent remote-forward-listener cap
    /// (never zero, same discipline).
    pub fn max_remote_forwards_per_principal(&self) -> usize {
        match self.max_remote_forwards_per_principal {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_REMOTE_FORWARDS_PER_PRINCIPAL,
        }
    }

    /// Effective per-principal concurrent-connection cap (never zero, same
    /// discipline).
    pub fn max_connections_per_principal(&self) -> usize {
        match self.max_connections_per_principal {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL,
        }
    }

    /// Effective accept-arm-wide concurrent-connection cap (never zero,
    /// same discipline).
    pub fn max_connections(&self) -> usize {
        match self.max_connections {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_CONNECTIONS,
        }
    }
}

/// `[identity]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Private-key store preference; `qsh init --key-store` wins over it.
    pub key_store: Option<KeyStoreMode>,
}

/// `[audit]` section — audit log lifecycle (`docs/design/architecture.md`
/// §6/§7, `PLAN.md` M5 Step 1/3). `crate::serve::host_runtime` reads these
/// values to build the rotating, bounded-queue writer
/// (`crate::audit::RotatingAuditSink::spawn`): `max_bytes`/`retain` govern
/// its rotation and retention, `queue_depth` its backpressure bound.
/// Deliberately has **no `fail_closed` knob**: `docs/ROADMAP.md` treats
/// disk-full fail-closed as a fixed policy, not an operator option.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Audit log path. Unset ⇒ [`Paths::audit_log`] (`<state_dir>/audit.log`).
    pub path: Option<String>,
    /// Rotation trigger, in bytes: once the active log reaches this size it
    /// is rotated. Unset ⇒ [`AuditConfig::DEFAULT_MAX_BYTES`] (64 MiB).
    pub max_bytes: Option<u64>,
    /// Number of rotated log files kept alongside the active one. Unset ⇒
    /// [`AuditConfig::DEFAULT_RETAIN`] (5).
    pub retain: Option<u32>,
    /// Bounded queue depth of the async audit writer. Unset ⇒
    /// [`AuditConfig::DEFAULT_QUEUE_DEPTH`] (1024).
    pub queue_depth: Option<u32>,
}

impl AuditConfig {
    /// Default rotation trigger: 64 MiB (`docs/design/architecture.md` §7,
    /// `PLAN.md` M5 §4.2).
    pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
    /// Default retained rotated files: 5.
    pub const DEFAULT_RETAIN: u32 = 5;
    /// Default async writer queue depth: 1024.
    pub const DEFAULT_QUEUE_DEPTH: u32 = 1024;

    /// Effective audit log path — `paths.audit_log()` unless overridden.
    pub fn path(&self, paths: &Paths) -> PathBuf {
        self.path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| paths.audit_log())
    }

    /// Effective rotation trigger (never `0` — treated as the default the
    /// same way `[serve].replay_bytes = 0` degrades to its default).
    pub fn max_bytes(&self) -> u64 {
        match self.max_bytes {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_MAX_BYTES,
        }
    }

    /// Effective retained-file count.
    pub fn retain(&self) -> u32 {
        self.retain.unwrap_or(Self::DEFAULT_RETAIN)
    }

    /// Effective async writer queue depth (never `0`, same "0 degrades to
    /// default" discipline as [`AuditConfig::max_bytes`]).
    pub fn queue_depth(&self) -> u32 {
        match self.queue_depth {
            Some(n) if n > 0 => n,
            _ => Self::DEFAULT_QUEUE_DEPTH,
        }
    }
}

/// `[listen]` section — `qsh listen`, the reverse-mode controller
/// (`docs/CLI.md` §6.13, `docs/design/protocol.md` §11-2/§11-4).
///
/// `PLAN.md` Step 3 PR 3a wired `bind`/`allow_advertised_names`. Step 4 adds
/// `stale_retention`, read by [`crate::reverse::listen::Listen`]'s stale-eviction
/// sweeper (`crates/qsh-core/src/reverse/listen.rs`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// How long a registration whose connection died stays visible as
    /// `state: "stale"` before the controller removes it, in seconds
    /// (`docs/design/protocol.md` §11-4, `docs/CLI.md` §6.13). Unset ⇒
    /// [`ListenConfig::DEFAULT_STALE_RETENTION_SECS`] (120 s). Validated
    /// against `[reverse].backoff_max_ms` by [`ListenConfig::stale_retention`]
    /// — see that method's doc for why.
    pub stale_retention: Option<u64>,
}

impl ListenConfig {
    /// Default stale retention: 120 s (`docs/design/protocol.md` §11-4,
    /// `docs/CLI.md` §6.13).
    pub const DEFAULT_STALE_RETENTION_SECS: u64 = 120;

    /// The multiple of `[reverse].backoff_max_ms` [`ListenConfig::stale_retention`]
    /// requires `stale_retention` to clear (`docs/design/protocol.md` §11-4:
    /// `stale_retention > backoff_max_ms × 3`).
    pub const STALE_RETENTION_BACKOFF_MULTIPLE: u32 = 3;

    /// Defaulted and validated stale retention, checked against `backoff_max`
    /// — the *other* section's already-validated [`ReverseConfig::backoff`]
    /// ceiling, taken as a parameter here rather than read from a sibling
    /// `Config::reverse` field so this section stays ignorant of its
    /// sibling's shape (`Config::stale_retention` below is the one call site
    /// that wires the two together, the same split
    /// `reverse::listen::run_listen_unix` already keeps between config
    /// sections).
    ///
    /// **Why `× 3`:** a target's worst-case re-registration delay is
    /// `backoff_max_ms` (the exponential backoff ceiling) plus jitter —
    /// bounded well under `backoff_max_ms × 2`. `stale_retention` must clear
    /// that with real headroom or the entry is evicted while a legitimate
    /// reconnect is still in flight, which would make `qsh hosts` show a
    /// host as gone right as it is about to come back. The extra margin
    /// beyond `× 2` is reserved for Step 8's re-attach wait, which needs to
    /// observe the *stale* state (not a vanished entry) for long enough to
    /// still be waiting when the reconnect lands. Fails closed
    /// (`CONFIG_ERROR`, non-retryable) rather than silently clamping —
    /// the same discipline [`ReverseConfig::backoff`] applies to its own
    /// knobs.
    pub fn stale_retention(
        &self,
        backoff_max: std::time::Duration,
    ) -> Result<std::time::Duration, OpError> {
        let secs = self
            .stale_retention
            .unwrap_or(Self::DEFAULT_STALE_RETENTION_SECS);
        if secs == 0 {
            return Err(Self::stale_retention_config_error(
                "[listen].stale_retention must be greater than 0",
            ));
        }
        let retention = std::time::Duration::from_secs(secs);
        let floor = backoff_max.saturating_mul(Self::STALE_RETENTION_BACKOFF_MULTIPLE);
        if retention <= floor {
            return Err(Self::stale_retention_config_error(format!(
                "[listen].stale_retention ({secs}s) must be greater than \
                 [reverse].backoff_max_ms × {} ({}ms)",
                Self::STALE_RETENTION_BACKOFF_MULTIPLE,
                floor.as_millis(),
            )));
        }
        Ok(retention)
    }

    fn stale_retention_config_error(message: impl Into<String>) -> OpError {
        OpError::new(ErrorCode::ConfigError, message).with_retryable(false)
    }
}

/// `[reverse]` section — `qsh reverse <controller>`, the reverse-mode
/// target (`docs/CLI.md` §6.13, `docs/design/protocol.md` §11-2, §11-4).
///
/// `PLAN.md` Step 3 PR 3a wired `offered_name` only — `controller` parses
/// but is not read by any code path (see its own field doc). `PLAN.md`
/// Step 4 adds the backoff knobs below, read by the reconnect loop in
/// `reverse::target::run_reverse`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReverseConfig {
    /// Trust-store alias of the controller to dial. **Reserved, not
    /// currently read by any code path.** `docs/CLI.md` §6.13's synopsis
    /// (`qsh reverse <controller> [--offered-name <name>]`, no brackets
    /// around `<controller>`) makes the CLI positional mandatory —
    /// `crates/qsh-cli/src/cli.rs`'s `Command::Reverse.controller` is a
    /// plain `String`, never absent — so there is no code path that would
    /// ever fall back to this key the way `offered_name` genuinely falls
    /// back to its own (`resolve_offered_name`, `reverse/target.rs`).
    /// Kept so a `config.toml` carrying `[reverse].controller`
    /// (`docs/design/architecture.md` §7's documented layout) parses
    /// instead of hard-failing, and reserved in case a future milestone
    /// relaxes the positional to optional — no ROADMAP/PLAN step currently
    /// commits to that (`PLAN.md` M3 Step 3 review finding).
    pub controller: Option<String>,
    /// Name this target offers itself as. `--offered-name` wins over this.
    /// Only takes effect when the controller has no trust-store alias for
    /// this peer *and* the controller's `[listen].allow_advertised_names`
    /// is set — see `reverse::admit::admit`.
    pub offered_name: Option<String>,
    /// Delay before the first re-dial after the reconnect loop judges the
    /// connection to the controller dead, in milliseconds. Doubles on each
    /// further failure up to [`ReverseConfig::backoff`]'s `max`
    /// (`docs/design/protocol.md` §11-4 — the multiplier itself is fixed
    /// at 2, not configurable). Unset ⇒
    /// [`ReverseConfig::DEFAULT_BACKOFF_INITIAL_MS`] (500 ms).
    pub backoff_initial_ms: Option<u64>,
    /// Ceiling the backoff delay never exceeds, in milliseconds. Unset ⇒
    /// [`ReverseConfig::DEFAULT_BACKOFF_MAX_MS`] (30 s) —
    /// `[listen].stale_retention`'s documented default (120 s) is sized
    /// against this default specifically (`docs/design/protocol.md`
    /// §11-4: `stale_retention > backoff_max_ms × 3`).
    pub backoff_max_ms: Option<u64>,
    /// `±` jitter applied to every backoff delay, as a whole-number
    /// percentage. Unset ⇒ [`ReverseConfig::DEFAULT_BACKOFF_JITTER_PCT`]
    /// (20, i.e. `±20%`).
    pub backoff_jitter_pct: Option<u8>,
}

/// Effective, validated `[reverse]` backoff parameters
/// (`docs/design/protocol.md` §11-4), returned by [`ReverseConfig::backoff`].
/// The multiplier is fixed at 2 and is not a field here — nothing in the
/// CLI/config contract makes it configurable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffLimits {
    /// Delay before the first re-dial after a connection death.
    pub initial: std::time::Duration,
    /// Ceiling the (pre-jitter) delay never exceeds.
    pub max: std::time::Duration,
    /// `±` jitter applied to each delay, as a percentage in `0..100`.
    pub jitter_pct: u8,
}

impl ReverseConfig {
    /// Default initial backoff: 500 ms (`docs/design/protocol.md` §11-4).
    pub const DEFAULT_BACKOFF_INITIAL_MS: u64 = 500;
    /// Default backoff ceiling: 30 s (`docs/design/protocol.md` §11-4).
    pub const DEFAULT_BACKOFF_MAX_MS: u64 = 30_000;
    /// Default backoff jitter: `±20%` (`docs/design/protocol.md` §11-4).
    pub const DEFAULT_BACKOFF_JITTER_PCT: u8 = 20;
    /// Upper bound on `backoff_max_ms` (and therefore `backoff_initial_ms`,
    /// which is validated `<= max_ms` below) — 24 hours, wildly more
    /// generous than any real reconnect ceiling but small enough that
    /// `target::jitter`'s `u128 → i64` millisecond cast and its
    /// `millis * offset_pct` multiply (`offset_pct` bounded to `±99` by the
    /// `< 100` check below) never come close to overflowing (adversarial
    /// review finding: an unbounded config value let that arithmetic wrap
    /// or go negative, producing a zero-length backoff that busy-loops
    /// redials — exactly what this validation exists to fail closed on
    /// instead).
    const MAX_BACKOFF_MS: u64 = 24 * 60 * 60 * 1000;

    /// Defaulted and validated backoff parameters. Fails closed
    /// (`CONFIG_ERROR`, non-retryable) on nonsense rather than silently
    /// clamping it: a `0` initial delay would busy-loop redials, a `max`
    /// below `initial` is a contradiction, a jitter `≥ 100%` can swing a
    /// delay down to (or past) zero, defeating backoff's entire purpose,
    /// and a `max` past `Self::MAX_BACKOFF_MS` risks the same zero-delay
    /// failure through integer overflow in `target::jitter` instead.
    pub fn backoff(&self) -> Result<BackoffLimits, OpError> {
        let initial_ms = self
            .backoff_initial_ms
            .unwrap_or(Self::DEFAULT_BACKOFF_INITIAL_MS);
        let max_ms = self.backoff_max_ms.unwrap_or(Self::DEFAULT_BACKOFF_MAX_MS);
        let jitter_pct = self
            .backoff_jitter_pct
            .unwrap_or(Self::DEFAULT_BACKOFF_JITTER_PCT);
        if initial_ms == 0 {
            return Err(Self::backoff_config_error(
                "[reverse].backoff_initial_ms must be greater than 0",
            ));
        }
        if max_ms < initial_ms {
            return Err(Self::backoff_config_error(format!(
                "[reverse].backoff_max_ms ({max_ms}) must be >= backoff_initial_ms ({initial_ms})"
            )));
        }
        if max_ms > Self::MAX_BACKOFF_MS {
            return Err(Self::backoff_config_error(format!(
                "[reverse].backoff_max_ms ({max_ms}) must be <= {} (24h)",
                Self::MAX_BACKOFF_MS
            )));
        }
        if jitter_pct >= 100 {
            return Err(Self::backoff_config_error(format!(
                "[reverse].backoff_jitter_pct ({jitter_pct}) must be < 100"
            )));
        }
        Ok(BackoffLimits {
            initial: std::time::Duration::from_millis(initial_ms),
            max: std::time::Duration::from_millis(max_ms),
            jitter_pct,
        })
    }

    fn backoff_config_error(message: impl Into<String>) -> OpError {
        OpError::new(ErrorCode::ConfigError, message).with_retryable(false)
    }
}

impl Config {
    /// Defaulted and validated `[listen].stale_retention`, checked against
    /// this same config's `[reverse].backoff_max_ms` — the one call site
    /// that wires [`ListenConfig::stale_retention`] to
    /// [`ReverseConfig::backoff`] (`docs/design/protocol.md` §11-4). Used by
    /// `reverse::listen::run_listen_unix` before constructing the
    /// controller's stale sweeper — fail closed on either section's
    /// nonsense before any resource is created.
    pub fn stale_retention(&self) -> Result<std::time::Duration, OpError> {
        let backoff = self.reverse.backoff()?;
        self.listen.stale_retention(backoff.max)
    }

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
mod tests;
