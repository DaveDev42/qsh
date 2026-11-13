//! `doctor.run` (`docs/CLI.md` §6.17, M7 plan Step 6 (69dd788)) — orchestrates
//! every diagnostic in [`crate::doctor`]/[`crate::doctor::probe`] into one
//! report. Local, authorization-free operation (`docs/CLI.md` §2.5's "인가
//! 불요" row), same discipline as `acl.check` ([`crate::ops::acl`]): never
//! dispatched to a remote peer.
//!
//! **Exit-code discipline** (M7 plan §4.1 #6 (69dd788), design brief §B): every
//! finding is reported as *data*, never a nonzero exit — `finish()` yields
//! exit 0 for a successful `doctor.run` unless the caller opted into
//! `--fail-on` (ADR-0027, see [`DoctorThreshold`]), mirroring `acl.check`'s own
//! precedent (`docs/CLI.md` §6.15: "acl check 자체는 실패하지 않는다— deny나
//! no-policy조차 exit 0"). [`Ops::doctor`] only returns `Err` (exit 255)
//! for a precondition doctor cannot work around at all: no device identity
//! yet (`qsh init` was never run). Every other condition, however bad, is
//! reported as a [`qsh_proto::DoctorFinding`], never a hard error.
//!
//! **`now`-injection is mandatory, not optional**: three of the thirteen
//! diagnostics (`cert_expired`/`cert_expiring_soon`/`clock_skew`) are
//! unreachable in real time under normal operation — a device leaf is
//! valid for 10 years — and are only testable by supplying a synthetic
//! `now`. Not a new architectural pattern: [`crate::trust::pairing`]'s
//! `InviteStore::add`/`prune` and `crate::config::rfc3339_of` already
//! take `SystemTime` as a parameter rather than calling
//! `SystemTime::now()` internally.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use qsh_proto::{
    DoctorData, DoctorFinding, DoctorPunch, DoctorReq, DoctorTransport, ErrorCode, KeyStoreKind,
};
use qsh_transport::{AuthPath, TransportTuning};

use crate::acl::{Role, ca_policy_example_row, load_policy_or_deny, policy_example_rows};
use crate::config::Config;
use crate::doctor::probe::{self, UdpProbeOutcome};
use crate::doctor::{
    ACL_CA_AUTH_PATH_MISSING, ACL_FILE_PATHS_MISSING, ACL_FORWARD_SOCKS_INEFFECTIVE,
    ACL_POLICY_INVALID_ROLE_CLAUSE, ACL_POLICY_MISSING_SET_ROLE_HINT, ACL_PRINCIPAL_UNMATCHED,
    CERT_EXPIRED, CERT_EXPIRING_SOON, CLOCK_SKEW, CONFIG_SERVE_TO_CONFLICT, CONFIG_UNKNOWN_KEY,
    DATAGRAM_UNAVAILABLE, PEER_UNTRUSTED, PUNCH_FAILED, PUNCH_NO_RENDEZVOUS, PUNCH_SUCCEEDED,
    QSH_PATH_SHADOWED, SCREEN_ECHO_UNSUPPORTED, SCREEN_SYNC_UNSUPPORTED,
    TRUST_FILE_ROLES_SUSPENDED_CLAUSE, TRUST_PIN_ROLE_UNSET, TRUST_REMOVE_SCOPE,
    probe_audit_path_writable,
};
use crate::hosts::HostsFile;
use crate::identity::{
    CERT_BACKDATE_MINUTES, FileKeyStore, Identity, KEY_FILE, KeyStore, PlatformKeyStore,
};
use crate::ops::PeerRoute;
#[cfg(windows)]
use crate::ops::service::ComTaskScheduler;
use crate::ops::service::{TaskDefinitionReader, TaskLogonType, UnreadableTaskScheduler};
use crate::ops::{OpError, Operation, Ops, resolve_peer_address};
use crate::trust::{TrustRole, TrustStore};

/// The `doctor.run` operation (`qsh doctor [host]`).
pub struct DoctorOp;

impl Operation for DoctorOp {
    const COMMAND: &'static str = "doctor.run";
}

/// How long a single connectivity probe ([`probe::probe_udp_egress`]) waits
/// before it counts as a timeout. Reuses [`super::PROBE_DIAL_TIMEOUT`]
/// rather than a second "3s" constant — doctor's probes are exactly the
/// kind of "expected to sometimes fail, must not hold a human or CI
/// hostage" dial that constant already exists for (`trust.add`'s own
/// fingerprint probe).
const DOCTOR_PROBE_TIMEOUT: Duration = super::PROBE_DIAL_TIMEOUT;

/// Certs expiring within this many seconds of `now` are `cert_expiring_soon`
/// rather than silently `ok` (`docs/ROADMAP.md` §4 risk table L136: "만료
/// 30일 전 doctor 경고", design brief row #5).
const CERT_EXPIRING_SOON_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

/// The kind of device `doctor.run` judged (ADR-0066 decision 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceMode {
    /// Dials out only: takes no inbound request.
    Client,
    /// Takes inbound connections (or may, the moment it is started).
    Server,
}

impl DeviceMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// A [`DeviceMode`] and the closed word that says why (`DoctorData.mode_basis`).
struct ModeJudgment {
    mode: DeviceMode,
    basis: &'static str,
}

/// Said beside an unparseable `acl.toml` on a client-only device
/// (ADR-0066 decision 4), in place of the role clause a server gets.
const ACL_POLICY_INVALID_CLIENT_CLAUSE: &str = "This device is judged a client, which takes no inbound request, so nothing is refused for it today. If it ever serves, this file refuses every request and role grants too.";

/// The host state [`Ops::doctor_with_host_state`] takes instead of reading
/// the real machine: the key store the diagnosed identity records, `$HOME`,
/// the root under which `Library/LaunchDaemons` is looked up, the systemd
/// linger marker directory and `$USER`. Each is the value
/// [`Ops::doctor`] reads from the environment, made explicit.
pub struct DoctorHostState<'a> {
    pub keystore: &'a dyn KeyStore,
    pub home_dir: Option<&'a Path>,
    pub system_root: &'a Path,
    pub linger_dir: &'a Path,
    pub username: Option<&'a str>,
}

/// The real-process inputs [`Ops::doctor_assemble`]'s
/// `keystore_unavailable`/`qsh_path_shadowed`/`service_not_registered`/
/// `systemd_linger_disabled`/`launchagent_session_scoped`/
/// `bindv6only_blocks_ipv4` probes depend on that are not files under
/// `self.paths` — bundled into one borrow so [`Ops::doctor_assemble`]
/// stays under clippy's argument-count lint (verify round P2-2/P2-4).
/// [`Ops::doctor`] always builds this from the real environment; a test
/// builds it from a stub `KeyStore`, an injected temp `$PATH`/`$HOME`/
/// linger root, or a synthetic bind-probe function to force any of these
/// probes deterministically through the real assembly path — the same
/// injected-environment seam this struct exists for.
///
/// `home_dir`/`linger_dir`/`username`/`bindv6only_probe` are **always**
/// constructed and read on every target, never behind a `#[cfg(...)]` —
/// see [`Ops::doctor_service_registration_findings`]'s own doc for why:
/// gating individual fields on a struct built at one shared call site
/// would force every construction site (production plus every test) to
/// mirror the same `#[cfg(...)]` attributes, and an ungated field that is
/// only *read* inside a platform-gated body would still trip `-D
/// warnings`' dead-code lint on the one target where it goes unread
/// (`x86_64-pc-windows-gnu`, this crate's own cross-compiled CI leg).
/// `if cfg!(target_os = "...")` at the point of *use* avoids both.
struct DoctorEnvironment<'a> {
    keystore: &'a dyn KeyStore,
    current_exe: Option<&'a Path>,
    path_dirs: &'a [PathBuf],
    /// `$HOME` — `None` when [`crate::config::home_dir`] could not resolve
    /// one, the same "could not even build the path" case
    /// [`probe::service_unit_registered`]'s own `None` already covers.
    home_dir: Option<&'a Path>,
    /// `/var/lib/systemd/linger` in production; a test points this at a
    /// tempdir instead ([`probe::probe_systemd_linger`]'s own doc).
    linger_dir: &'a Path,
    /// `/` in production. The macOS LaunchDaemon plist is looked up under
    /// it (`<system_root>/Library/LaunchDaemons`, ADR-0032 결정 14), so a test
    /// points it at a tempdir and never reads the real `/Library`.
    system_root: &'a Path,
    /// The OS whose service layout the registration probes read:
    /// [`probe::HostOs::current`] in production, any value in a test, so the
    /// macOS rules run on a Linux host too.
    os: probe::HostOs,
    /// `identity.key_store` of the device being diagnosed, which
    /// `keystore_session_bound` (ADR-0032 결정 15) keys off.
    key_store: KeyStoreKind,
    /// `$USER` — `None` when the real environment could not resolve one
    /// (no finding either way; matches [`probe::LingerProbe::Unknown`]'s
    /// own "cannot tell" reading rather than guessing an account name).
    username: Option<&'a str>,
    /// [`probe::probe_bindv6only`] in production — a real-socket probe,
    /// injected the same way `keystore`/`path_dirs` are so a test can
    /// force `bindv6only_blocks_ipv4`'s wiring through [`Ops::doctor_assemble`]
    /// deterministically (mutation-checked: deleting the wiring line
    /// goes red) without depending on this OS's actual `IPV6_V6ONLY`
    /// default — the classifier itself ([`probe::bindv6only_finding`]) is
    /// already unit-tested with a synthetic bool; this is the one
    /// layer up, closing the same wiring gap
    /// [`keystore_finding_of`]/[`path_shadow_finding`] already close for
    /// their own probes.
    bindv6only_probe: fn(SocketAddr) -> std::io::Result<bool>,
    /// The Task Scheduler read behind `logon_task_session_scoped`
    /// (ADR-0035 결정 27): the COM reader in production on Windows, a fake in
    /// a test, and a reader that reads nothing everywhere else. Only
    /// consulted when `os` is [`probe::HostOs::Windows`].
    task_reader: &'a dyn TaskDefinitionReader,
    /// Whether this machine's own ssh-agent answered, read only when
    /// `[agent].forward` is `"yes"` (`agent_unreachable`, ADR-0055 decision
    /// 19). `None`: not checked.
    local_agent: Option<bool>,
    /// The runtime directory to look in for `agent_dir_unusable`; `None`
    /// when this machine has none (it has never served).
    agent_runtime_dir: Option<&'a Path>,
}

impl Ops {
    /// `doctor.run` (`qsh doctor [host]`, `docs/CLI.md` §6.17). Inspects
    /// this host's own config, identity, and (best-effort) network
    /// reachability, and assembles every finding that fired into one
    /// report — never touches a remote peer's state (§2.5).
    ///
    /// `req.host`: an additional pinned host to probe connectivity for,
    /// beyond whatever `[reverse].controller` names — same UX shape as
    /// `qsh capabilities [host]`. `now`: mandatory injection point for the
    /// three time-dependent diagnostics (module doc) — the CLI passes
    /// `SystemTime::now()`; tests pass a fixed instant.
    ///
    /// Fails outright (`Err`, exit 255 via `finish()`) only when doctor
    /// itself has no way to proceed: no device identity (`qsh init` not
    /// run), or `config.toml`/`hosts.toml`/`trust.toml` fails to parse —
    /// each loader already turns a malformed file into `CONFIG_ERROR`
    /// (`crate::config::Config::load`/`HostsFile::load`/`TrustStore::load`'s
    /// own contracts) and doctor does not re-implement a second, tolerant
    /// parse of the same file just to keep running past it. `config_
    /// unknown_key` (below) is a different kind of check on the same file
    /// and does not relax this: it only ever runs after `Config::load`
    /// has already succeeded, and compares two parses of the same
    /// well-formed TOML rather than tolerating a malformed one.
    pub fn doctor(&self, req: DoctorReq, now: SystemTime) -> Result<DoctorData, OpError> {
        let now_unix = unix_seconds(now);
        let identity = crate::identity::read_identity(&self.paths)?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
            .with_retryable(false)
        })?;
        let config = self.config()?;

        // Real environment: the key store this device's identity actually
        // records (`identity.key_store`, `crate::identity::open_store`'s
        // own match — mirrored here rather than exposed, since `open_store`
        // is private to the `identity` module) and this process's actual
        // `current_exe()`/`$PATH` — the inputs `doctor_assemble`'s
        // `keystore_unavailable`/`qsh_path_shadowed` probes depend on that
        // are not files under `self.paths` (verify round P2-2/P2-4). Read
        // here, once, and handed down as data rather than read again inside
        // `doctor_assemble` — the same "read once at the edge, pass data
        // down" shape [`unix_seconds`]'s own `now` injection already uses.
        //
        // Always probing `PlatformKeyStore` regardless of `identity.
        // key_store` used to make `keystore_unavailable` mean "the OS
        // keychain is unreachable" even for a `file`-mode identity that
        // never touches it — a probe of a store nothing reads from, and on
        // this project's own macOS dev hosts, one that can cost tens of
        // seconds per `doctor.run` (an unsigned binary's first keychain
        // access prompts for user consent; R1 판정 (g)). Probing the store
        // actually in use makes the finding mean what its name says: "the
        // key store this device relies on cannot be opened right now."
        let keystore: Box<dyn KeyStore> = match identity.key_store {
            KeyStoreKind::File => {
                Box::new(FileKeyStore::new(self.paths.identity_dir().join(KEY_FILE)))
            }
            KeyStoreKind::Platform => Box::new(PlatformKeyStore::new(identity.device_id.clone())),
        };
        let current_exe = std::env::current_exe().ok();
        let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        let home_dir = crate::config::home_dir();
        // Production linger root — real systemd state, `/var/lib/systemd/
        // linger` (`probe::probe_systemd_linger`'s own doc); a test swaps
        // this for a tempdir via `DoctorEnvironment` directly.
        let linger_dir = Path::new("/var/lib/systemd/linger");
        let username = std::env::var("USER").ok();
        #[cfg(windows)]
        let task_reader = ComTaskScheduler;
        #[cfg(not(windows))]
        let task_reader = UnreadableTaskScheduler;
        let local_agent = (config.agent.forward == Some(crate::config::AgentForwardMode::Yes))
            .then(|| self.doctor_local_agent_reachable());
        let runtime_dir = self.paths.runtime_dir();
        let env = DoctorEnvironment {
            keystore: keystore.as_ref(),
            current_exe: current_exe.as_deref(),
            path_dirs: &path_dirs,
            home_dir: home_dir.as_deref(),
            linger_dir,
            system_root: Path::new("/"),
            os: probe::HostOs::current(),
            key_store: identity.key_store,
            username: username.as_deref(),
            bindv6only_probe: probe::probe_bindv6only,
            task_reader: &task_reader,
            local_agent,
            agent_runtime_dir: runtime_dir.is_dir().then_some(runtime_dir.as_path()),
        };

        self.doctor_assemble(req, now_unix, &identity, &config, &env)
    }

    /// [`Ops::doctor`] with the host state it reads outside `self.paths`
    /// handed in, the seam that keeps tests off the real key store,
    /// `$HOME`, `/Library/LaunchDaemons` and `/var/lib/systemd/linger`
    /// (`docs/design/testing.md` L1). The executable path, `$PATH` and the
    /// IPv6 bind probe are left out: this entry reports none of
    /// `qsh_path_shadowed` or `bindv6only_blocks_ipv4`, and it reads no Task
    /// Scheduler, so it reports no `logon_task_session_scoped` either. Production
    /// code calls [`Ops::doctor`].
    pub fn doctor_with_host_state(
        &self,
        req: DoctorReq,
        now: SystemTime,
        host: &DoctorHostState<'_>,
    ) -> Result<DoctorData, OpError> {
        let identity = crate::identity::read_identity(&self.paths)?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
            .with_retryable(false)
        })?;
        let config = self.config()?;
        let env = DoctorEnvironment {
            keystore: host.keystore,
            current_exe: None,
            path_dirs: &[],
            home_dir: host.home_dir,
            linger_dir: host.linger_dir,
            system_root: host.system_root,
            os: probe::HostOs::current(),
            key_store: identity.key_store,
            username: host.username,
            bindv6only_probe: |_| Ok(false),
            task_reader: &UnreadableTaskScheduler,
            local_agent: None,
            agent_runtime_dir: None,
        };
        self.doctor_assemble(req, unix_seconds(now), &identity, &config, &env)
    }

    /// The rest of `doctor.run` past reading `identity`/`config` and this
    /// real process's environment — split out from [`Ops::doctor`] purely
    /// as a test seam (verify round P2-2/P2-4, mutations `MA`/`MB`): a
    /// test can call this directly with a stub [`DoctorEnvironment`] (an
    /// always-`Unavailable` `KeyStore`, an injected temp `$PATH`) to force
    /// `keystore_unavailable`/`qsh_path_shadowed` deterministically
    /// through the *real* finding-assembly code path, not just through the
    /// pure classifiers ([`keystore_finding_of`]/[`path_shadow_finding`])
    /// one layer down — closing the exact gap the verify round's `MA`/`MB`
    /// mutations (deleting the wiring line entirely) exploited: those
    /// mutations are only observable if some test's report actually
    /// depends on the finding being present, which — for these two
    /// probes — real-environment nondeterminism otherwise prevents any
    /// test from guaranteeing.
    fn doctor_assemble(
        &self,
        req: DoctorReq,
        now_unix: i64,
        identity: &Identity,
        config: &Config,
        env: &DoctorEnvironment<'_>,
    ) -> Result<DoctorData, OpError> {
        let judged = self.doctor_judge_mode(req.mode.as_deref(), config, env, now_unix)?;
        let server = judged.mode == DeviceMode::Server;
        let mode = infer_run_mode(config);
        // `qsh listen` with `[listen].serve` is also a forward host
        // (ADR-0059): the checks that only a session host needs run for it.
        let combined = combined::is_combined(mode, config);
        let mut findings = Vec::new();
        findings.extend(self.doctor_audit_finding(config));
        findings.extend(self.doctor_config_unknown_key_findings(config));
        findings.extend(self.doctor_config_serve_to_conflict_finding(config));
        // A client-only device takes no inbound request, so everything that
        // only matters for inbound authorization, the service unit, the
        // listener and the session host is left out (ADR-0066 decision 4).
        if server {
            findings.extend(self.doctor_acl_findings_for(
                mode,
                combined,
                unix_to_system_time(now_unix),
            )?);
        } else {
            findings.extend(self.doctor_acl_findings_client());
        }
        findings.extend(self.doctor_cert_findings(identity, now_unix)?);
        findings.extend(self.doctor_clock_skew_finding(identity, now_unix)?);
        findings.extend(keystore_finding_of(env.keystore));
        findings.extend(
            env.current_exe
                .and_then(|exe| path_shadow_finding(exe, env.path_dirs)),
        );
        findings.extend(self.doctor_trust_findings()?);
        findings.extend(self.doctor_pinned_no_address_findings()?);
        let (connectivity, direct_missing) =
            self.doctor_connectivity_findings(config, req.host.as_deref())?;
        findings.extend(connectivity);
        if server {
            findings.extend(self.doctor_service_registration_findings_for(mode, combined, env));
            if combined {
                findings.extend(self.doctor_combined_findings(config, env));
            }
            findings.extend(self.doctor_bindv6only_finding(config, mode, env));
        }
        findings.extend(doctor_agent_findings(config, env, server));
        let transport = match req.host.as_deref() {
            Some(host) if !direct_missing && !reachability_failed(&findings) => {
                self.doctor_transport(config, host, &mut findings)
            }
            _ => None,
        };
        // A host with no direct path gets one hole punch (ADR-0054 decision
        // 20); a host with one does not.
        let punch = match req.host.as_deref() {
            Some(host) if direct_missing => self.doctor_punch(host, &mut findings),
            _ => None,
        };
        // A host behind a jump chain: which steps run on the stream carrier
        // (ADR-0056 decision 22). Only when the host is reachable at all.
        if let Some(host) = req.host.as_deref()
            && !direct_missing
            && !reachability_failed(&findings)
        {
            findings.extend(self.doctor_jump_carrier_finding(host));
        }

        Ok(DoctorData {
            overall: overall_status(&findings),
            mode: Some(judged.mode.as_str().to_string()),
            mode_basis: Some(judged.basis.to_string()),
            findings,
            transport,
            punch,
        })
    }

    /// Which kind of device this is (ADR-0066 decisions 2 and 3): the
    /// request's `mode`, else `[doctor].mode`, else what the device's own
    /// state shows. A `"server"` signal wins over everything an absent
    /// signal would say, because the wrong answer in that direction (a
    /// server judged a client) silences the checks that guard inbound
    /// authorization.
    fn doctor_judge_mode(
        &self,
        requested: Option<&str>,
        config: &Config,
        env: &DoctorEnvironment<'_>,
        now_unix: i64,
    ) -> Result<ModeJudgment, OpError> {
        use crate::config::DoctorModeSetting;
        let requested = match requested {
            None | Some("auto") => None,
            Some("client") => Some(DoctorModeSetting::Client),
            Some("server") => Some(DoctorModeSetting::Server),
            Some(other) => {
                return Err(OpError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid doctor mode {other:?}: expected `auto`, `client` or `server`"),
                )
                .with_retryable(false));
            }
        };
        let fixed = |setting: DoctorModeSetting, basis: &'static str| match setting {
            DoctorModeSetting::Client => Some(ModeJudgment {
                mode: DeviceMode::Client,
                basis,
            }),
            DoctorModeSetting::Server => Some(ModeJudgment {
                mode: DeviceMode::Server,
                basis,
            }),
            DoctorModeSetting::Auto => None,
        };
        if let Some(judged) = requested.and_then(|setting| fixed(setting, "request")) {
            return Ok(judged);
        }
        if let Some(judged) = config
            .doctor
            .mode
            .and_then(|setting| fixed(setting, "config"))
        {
            return Ok(judged);
        }
        let basis = self.doctor_server_signal(config, env, unix_to_system_time(now_unix))?;
        Ok(match basis {
            Some(basis) => ModeJudgment {
                mode: DeviceMode::Server,
                basis,
            },
            None => ModeJudgment {
                mode: DeviceMode::Client,
                basis: "no_server_signal",
            },
        })
    }

    /// The first sign that this device takes inbound connections, in the
    /// order ADR-0066 decision 3 lists them: a `[serve]`, `[listen]` or
    /// `[reverse]` table with a key set, a registered service unit, a daemon
    /// (a `serve.json` record, live or left by a crash, or a live localctl
    /// endpoint), a pin with a role other than `none`, a live invite that
    /// pins one. `None` when there is none.
    fn doctor_server_signal(
        &self,
        config: &Config,
        env: &DoctorEnvironment<'_>,
        now: SystemTime,
    ) -> Result<Option<&'static str>, OpError> {
        if config.serve != crate::config::ServeConfig::default()
            || config.listen != crate::config::ListenConfig::default()
            || config.reverse != crate::config::ReverseConfig::default()
        {
            return Ok(Some("config_section"));
        }
        let unit_registered = ["serve", "listen", "reverse"].iter().any(|mode| {
            let registered = if env.os == probe::HostOs::Windows {
                Some(probe::windows_task_definition_present(
                    &self.paths.config_dir,
                    mode,
                ))
            } else {
                probe::service_unit_registered(env.os, env.home_dir, env.system_root, mode)
            };
            registered == Some(true)
        });
        if unit_registered {
            return Ok(Some("service_unit"));
        }
        let listening = crate::localctl::client::candidate_sockets(&self.paths.runtime_dir())
            .unwrap_or_default()
            .iter()
            .any(|(pid, _)| crate::serve::record::process_is_alive(*pid));
        if crate::serve::record::read(&self.paths).is_some() || listening {
            return Ok(Some("daemon"));
        }
        let trust = self.doctor_load_trust()?;
        if trust.peers().iter().any(peer_authorizes_inbound) {
            return Ok(Some("role_pin"));
        }
        // An `invites.toml` that exists and cannot be read is an unknown
        // too: only a device that takes inbound pairing writes one.
        if crate::trust::live_role_invite_count(&self.paths.invites_file(), now)
            .map_or(true, |live| live > 0)
        {
            return Ok(Some("role_invite"));
        }
        Ok(None)
    }

    /// What `acl.toml` still means on a client-only device (ADR-0066
    /// decision 4): nothing is enforced here, so the missing file, the
    /// unmatched pins and the other rows that only matter once a request
    /// arrives are left out. A file that does not parse is still a broken
    /// file, and it would refuse every request the day this device serves,
    /// so it is reported as a `warn`, not an `error`.
    fn doctor_acl_findings_client(&self) -> Option<DoctorFinding> {
        let (_policy, diagnostic, _index) = load_policy_or_deny(&self.paths, Role::Serve);
        let diagnostic = diagnostic.filter(|d| d.code == crate::acl::ACL_POLICY_INVALID_CODE)?;
        Some(DoctorFinding {
            code: diagnostic.code.to_string(),
            status: "warn".to_string(),
            detail: format!(
                "{}\n{ACL_POLICY_INVALID_CLIENT_CLAUSE}",
                diagnostic.render_block()
            ),
            remedy: Some(format!(
                "{}. {}",
                crate::acl::ACL_STARTUP_NO_AUTOGEN,
                crate::acl::ACL_STARTUP_CHECK_HINT
            )),
        })
    }

    /// The `transport` object and its two `info` findings (ADR-0052 decision
    /// 14): a 3 s measurement connection to `host`, sampled twice a second,
    /// with the adaptive policy run over the samples under this device's
    /// own `config.toml` pins. `None` when the connection does not come up
    /// (the reachability findings say why) or the host is only reachable
    /// through a reverse registration. The connection carries no interactive
    /// traffic, so knob (a) reads `off` here whatever the path.
    fn doctor_transport(
        &self,
        config: &Config,
        host: &str,
        findings: &mut Vec<DoctorFinding>,
    ) -> Option<DoctorTransport> {
        use crate::adapt::{PolicySampler, User};
        use qsh_proto::wire::{CAP_DATAGRAM_V1, CAP_SCREEN_ECHO_V1, CAP_SCREEN_V1};

        const SAMPLES: u32 = 6;
        const PERIOD: Duration = Duration::from_millis(500);

        let mut connected = self
            .connect_probe(host, TRANSPORT_PROBE_DIAL_BUDGET)
            .ok()??;
        let connection = connected.connection()?;
        let capabilities = connected.capabilities().to_vec();
        let has = |cap: &str| capabilities.iter().any(|c| c == cap);
        let screen_offered = has(CAP_SCREEN_V1);
        let datagram_offered = has(CAP_DATAGRAM_V1);
        let echo_offered = has(CAP_SCREEN_ECHO_V1);
        let predict_mode = config.interactive.predict.unwrap_or_default();
        let predict_wanted = predict_mode != crate::ops::Predict::Never;
        let screen_wanted =
            config.interactive.screen_sync.unwrap_or_default() != crate::ops::ScreenSync::Off;
        let user = User {
            adaptive: config.transport.adaptive_mode().enabled(),
            keep_alive: config.transport.keep_alive_ms.map(Duration::from_millis),
            // The same pin an attach puts on the policy, so the reasons
            // (`user_override`) match what an attach would report.
            prediction: predict_mode.pin(),
        };
        let mut sampler =
            PolicySampler::new(user, screen_offered && screen_wanted, datagram_offered);
        let mut last = None;
        let mut max_datagram = None;
        for _ in 0..SAMPLES {
            // A control `Ping` makes the peer answer, so the RTT estimate
            // moves even though nothing else is on the connection.
            let _ = connected.run(|s| Box::pin(async move { s.send_ping().await }));
            max_datagram = connection.max_datagram_size();
            last = Some(sampler.step(
                std::time::Instant::now(),
                connection.stats(),
                max_datagram,
                false,
                false,
            ));
            // The timer is built inside the runtime: `sleep()` outside one panics.
            connected
                .runtime()
                .block_on(async { tokio::time::sleep(PERIOD).await });
        }
        connected.close();
        let sample = last?;

        findings.extend(transport_findings(
            host,
            screen_offered,
            datagram_offered,
            max_datagram,
        ));
        findings.extend(echo_finding(
            host,
            screen_offered,
            echo_offered,
            predict_wanted,
        ));
        Some(sample.report)
    }

    /// One connection to this machine's ssh-agent, opened and closed without
    /// a byte sent (ADR-0055 decision 11): does anything answer?
    fn doctor_local_agent_reachable(&self) -> bool {
        let Ok(runtime) = self.connect_runtime() else {
            return false;
        };
        let agent = crate::agent::ClientAgent::from_env(None);
        runtime.block_on(agent.unreachable_note()).is_none()
    }

    /// `audit_path_unwritable` (design brief row #9) — reuses
    /// [`probe_audit_path_writable`] and [`crate::doctor::AUDIT_PATH_UNWRITABLE`]
    /// verbatim, the same detector `qsh listen`'s own startup path uses.
    fn doctor_audit_finding(&self, config: &Config) -> Option<DoctorFinding> {
        let path = config.audit.path(&self.paths);
        if probe_audit_path_writable(&path) {
            return None;
        }
        let diag = &crate::doctor::AUDIT_PATH_UNWRITABLE;
        Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "error".to_string(),
            detail: format!("{} (path: {})", diag.message, path.display()),
            remedy: Some(diag.remedy.to_string()),
        })
    }

    /// `acl_policy_missing`/`acl_policy_invalid` (design brief rows
    /// #10/#11), plus ROADMAP M9 (h)'s `acl_principal_unmatched`/
    /// `acl_ca_auth_path_missing` (ADR-0017 결정 2), plus
    /// `acl_forward_socks_ineffective` (ADR-0019 결과 절 R6) — one
    /// `acl.toml` read for all five codes via [`load_or_deny_with_index`]
    /// (the exact same detection `qsh serve`/`qsh listen`'s own startup
    /// banner runs, plus the [`crate::acl::PinnedPrincipalIndex`] extracted
    /// from the same load), discarding the throwaway
    /// [`crate::acl::Authorizer`] it also constructs (loading `acl.toml`
    /// has no side effects worth avoiding). `role` (ADR-0017 결정 2)
    /// is [`Role::Listen`] for an inferred `listen` mode, [`Role::Serve`]
    /// otherwise — the same precedence [`infer_run_mode`] already
    /// establishes for `service_not_registered`.
    ///
    /// The two new checks only run once `acl.toml` actually loaded
    /// ([`crate::acl::PolicyLoad::Loaded`], i.e. `diagnostic.is_none()`):
    /// `acl_policy_missing`/`acl_policy_invalid` already cover "nothing
    /// enforced", and a [`crate::acl::PinnedPrincipalIndex::empty`] on
    /// either of those outcomes has no data worth checking — no false
    /// `acl_principal_unmatched`/`acl_ca_auth_path_missing` noise on top
    /// of a report that already says the file itself is the problem.
    ///
    /// `remedy` on both new findings is `docs/CLI.md` §6.17's "실행 가능한
    /// 다음 행동 한 줄" verbatim — the copy-pasteable `[[acl]]` example row
    /// lives in `detail` instead ([`crate::acl::policy_example_rows`] for
    /// `acl_principal_unmatched`, naming only the one unmatched peer, not
    /// every pinned peer; [`crate::acl::ca_policy_example_row`] for
    /// `acl_ca_auth_path_missing`, which is file-wide and has no peer to
    /// name).
    ///
    /// Trust roles change what these codes mean (ADR-0045 결정 12). A missing
    /// `acl.toml` is `acl_policy_missing` only when nothing else authorizes a
    /// request either: no pin with a role other than `none`, and no live
    /// invite that will pin one (`now` is the clock for "live"). An
    /// unparseable `acl.toml` is `acl_policy_invalid` whatever the roles are,
    /// because it refuses role grants too. `acl_principal_unmatched` does
    /// not count a pin with a role, and `acl_ca_auth_path_missing` also
    /// fires when `acl.toml` is absent, since a role pin can silence
    /// `acl_policy_missing` while the CA path (which has no role) stays shut.
    #[cfg(test)]
    fn doctor_acl_findings(
        &self,
        mode: &str,
        now: SystemTime,
    ) -> Result<Vec<DoctorFinding>, OpError> {
        self.doctor_acl_findings_for(mode, false, now)
    }

    /// [`Self::doctor_acl_findings`] for a `qsh listen` that may also serve
    /// (`combined`, ADR-0059): the missing/invalid-policy example then shows
    /// the row of both roles.
    fn doctor_acl_findings_for(
        &self,
        mode: &str,
        combined: bool,
        now: SystemTime,
    ) -> Result<Vec<DoctorFinding>, OpError> {
        // The combined endpoint starts from the `Serve` row and gets the
        // `Listen` one added below, as its own startup does.
        let role = if mode == "listen" && !combined {
            Role::Listen
        } else {
            Role::Serve
        };
        let (_policy, mut diagnostic, index) = load_policy_or_deny(&self.paths, role);
        if combined && let Some(diagnostic) = &mut diagnostic {
            // Both roles read this one file, so the example shows both rows
            // (ADR-0059 decision 8), as the endpoint's own startup does.
            crate::serve::add_listen_example(&self.paths, diagnostic);
        }
        let trust = self.doctor_load_trust()?;
        let mut out = Vec::new();
        let mut policy_loaded = true;
        if let Some(diagnostic) = diagnostic {
            policy_loaded = false;
            if diagnostic.code == crate::acl::ACL_POLICY_INVALID_CODE {
                out.push(DoctorFinding {
                    code: diagnostic.code.to_string(),
                    status: "error".to_string(),
                    detail: format!(
                        "{}\n{ACL_POLICY_INVALID_ROLE_CLAUSE}",
                        diagnostic.render_block()
                    ),
                    remedy: Some(format!(
                        "{}. {}",
                        crate::acl::ACL_STARTUP_NO_AUTOGEN,
                        crate::acl::ACL_STARTUP_CHECK_HINT
                    )),
                });
                return Ok(out);
            }
            if !self.doctor_roles_authorize_something(&trust, now) {
                out.push(DoctorFinding {
                    code: diagnostic.code.to_string(),
                    status: "error".to_string(),
                    detail: diagnostic.render_block(),
                    remedy: Some(format!(
                        "{ACL_POLICY_MISSING_SET_ROLE_HINT}. {}. {}",
                        crate::acl::ACL_STARTUP_NO_AUTOGEN,
                        crate::acl::ACL_STARTUP_CHECK_HINT
                    )),
                });
            }
        }

        // `docs/CLI.md` §6.17: `remedy` is one actionable line; the
        // copy-pasteable `[[acl]]` example row goes in `detail` instead
        // (the same split `acl_policy_missing`/`acl_policy_invalid`'s
        // `StartupDiagnostic::render` already uses). `acl_principal_
        // unmatched`'s row names only the one unmatched peer
        // ([`policy_example_rows`] with a single-element slice), not every
        // pinned peer — `acl_ca_auth_path_missing`'s row
        // ([`ca_policy_example_row`]) is file-wide, so it has no peer to
        // name at all.
        let diag = &ACL_PRINCIPAL_UNMATCHED;
        // A missing `acl.toml` has no rows to match against, so the check
        // is only meaningful against a policy that loaded.
        let candidates = if policy_loaded { trust.peers() } else { &[] };
        for peer in candidates {
            // A pin with a role other than `none` is authorized without a
            // row, so "no row names it" is not a problem (ADR-0045 결정 12).
            let matched = peer_has_role(peer)
                || index.names_device(&peer.name)
                || index.names_fingerprint(&peer.fingerprint);
            if !matched {
                let example = policy_example_rows(&[peer.name.as_str()], role);
                out.push(DoctorFinding {
                    code: diag.code.to_string(),
                    status: "error".to_string(),
                    detail: format!(
                        "{} (peer: {})\nminimal example:\n{example}",
                        diag.message, peer.name
                    ),
                    remedy: Some(diag.remedy.to_string()),
                });
            }
        }

        if !trust.cas().is_empty() && !index.has_ca_auth_path() {
            let diag = &ACL_CA_AUTH_PATH_MISSING;
            let example = ca_policy_example_row(role);
            out.push(DoctorFinding {
                code: diag.code.to_string(),
                status: "warn".to_string(),
                detail: format!("{}\nminimal example:\n{example}", diag.message),
                remedy: Some(diag.remedy.to_string()),
            });
        }

        // `acl_forward_socks_ineffective` (ADR-0019 결정 6·14, 결과 절 R6):
        // `detail` carries only the row's array index and `auth_path` — F1
        // discipline (`crate::acl::load`'s own doc), never the principal
        // string a row names.
        for (row_index, auth_path) in index.forward_socks_ineffective_rows() {
            let diag = &ACL_FORWARD_SOCKS_INEFFECTIVE;
            out.push(DoctorFinding {
                code: diag.code.to_string(),
                status: "warn".to_string(),
                detail: format!(
                    "{} (row: {row_index}, auth_path: {})",
                    diag.message,
                    auth_path_str(*auth_path)
                ),
                remedy: Some(diag.remedy.to_string()),
            });
        }

        // `acl_file_paths_missing` (ADR-0029 결정 19): a row that names a file
        // action and has no `paths`. `detail` carries the row's index and
        // `auth_path` only. A `device:<name>` pin-path row is silent when the
        // same-named pin has role `full`: files are open to it by role, so no
        // intent is broken. The index is empty for a missing or unparseable
        // policy, which keeps this silent there.
        for (row_index, auth_path, device) in index.file_paths_missing_rows() {
            let role_opens_files = device.as_deref().is_some_and(|name| {
                trust.peers().iter().any(|peer| {
                    peer.name == name
                        && peer
                            .role
                            .as_deref()
                            .and_then(|r| r.parse::<TrustRole>().ok())
                            == Some(TrustRole::Full)
                })
            });
            if role_opens_files {
                continue;
            }
            let diag = &ACL_FILE_PATHS_MISSING;
            out.push(DoctorFinding {
                code: diag.code.to_string(),
                status: "warn".to_string(),
                detail: format!(
                    "{} (row: {row_index}, auth_path: {})",
                    diag.message,
                    auth_path_str(*auth_path)
                ),
                remedy: Some(diag.remedy.to_string()),
            });
        }

        Ok(out)
    }

    /// Load `trust.toml` for a finding. A failure here is the same failure
    /// that suspends role grants in a running `qsh serve`/`qsh listen`
    /// (ADR-0045 결정 4), so the `CONFIG_ERROR` doctor ends with says so
    /// (결정 12). `code` and `retryable` are the loader's own.
    fn doctor_load_trust(&self) -> Result<TrustStore, OpError> {
        TrustStore::load(&self.paths.trust_file()).map_err(|mut err| {
            err.message = format!(
                "{}. {TRUST_FILE_ROLES_SUSPENDED_CLAUSE}",
                err.message.trim_end_matches('.')
            );
            err
        })
    }

    /// Whether anything but `acl.toml` rows authorizes a request: a pin with
    /// a role other than `none`, or an invite that is still redeemable at
    /// `now` and will pin one (ADR-0045 결정 12). An unreadable
    /// `invites.toml` counts as "no invite": the invite cannot be redeemed
    /// either, and the finding errs toward reporting.
    fn doctor_roles_authorize_something(&self, trust: &TrustStore, now: SystemTime) -> bool {
        trust.peers().iter().any(peer_has_role)
            || crate::trust::live_role_invite_count(&self.paths.invites_file(), now)
                .is_ok_and(|live| live > 0)
    }

    /// `cert_expired`/`cert_expiring_soon` (design brief rows #4/#5) —
    /// checks both certificates this device relies on: its own device leaf
    /// (always present once `identity` exists) and the local CA root, when
    /// one has been initialized (`qsh cert init`, M7 Step 5 — its absence
    /// is not a diagnostic, per the brief's own completeness argument:
    /// "CA 미초기화는 실패가 아니라 부재").
    fn doctor_cert_findings(
        &self,
        identity: &Identity,
        now_unix: i64,
    ) -> Result<Vec<DoctorFinding>, OpError> {
        let mut out = Vec::new();
        out.extend(cert_expiry_finding(
            "this device's own leaf certificate",
            &identity.cert_der,
            now_unix,
        )?);
        if let Some(ca) = crate::ca::read_root(&self.paths)? {
            out.extend(cert_expiry_finding(
                "the local CA root certificate",
                &ca.cert_der,
                now_unix,
            )?);
        }
        Ok(out)
    }

    /// `clock_skew` (design brief row #7) — compares `now` against this
    /// device's own leaf certificate `not_before`, the same backdated
    /// timestamp [`crate::identity::init`] stamped at `qsh init` time.
    fn doctor_clock_skew_finding(
        &self,
        identity: &Identity,
        now_unix: i64,
    ) -> Result<Option<DoctorFinding>, OpError> {
        let (not_before, _not_after) = qsh_transport::identity::validity_unix(&identity.cert_der)
            .map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("failed to read this device's own certificate validity: {err}"),
            )
            .with_retryable(false)
        })?;
        Ok(clock_skew_finding(not_before, now_unix))
    }

    /// `config_unknown_key` (M8 plan Step 4b (52639fc), J10). Reads `config.toml`
    /// a second time as a bare [`toml::Value`] (not through [`Config`]'s
    /// `#[serde(default)]` `Deserialize`, which silently drops anything it
    /// does not recognize — that silence is exactly what this finding
    /// exists to surface) and compares its leaf key paths against
    /// `config`'s own, re-serialized the same way. No hand-maintained key
    /// list: [`collect_leaf_paths`] derives the "known" set from the
    /// struct itself via `Serialize`, so a future field addition/removal
    /// to [`Config`] or any of its sections updates this finding's
    /// vocabulary for free, with nothing here to keep in sync by hand. A
    /// candidate that only `serde`'s deserializer recognizes under a
    /// different name (a `#[serde(alias = ...)]`, which never appears in
    /// `Serialize`'s output) is filtered out by
    /// [`accepted_under_another_name`] before being reported — see its
    /// own doc for the one corner it cannot see.
    ///
    /// Only reachable once [`Ops::doctor`] already holds a successfully
    /// loaded `config` — a missing file means `Config::load` returned
    /// `Config::default()` with nothing to compare against (no finding,
    /// same as every other "file absent" case in this module), and a
    /// malformed file would already have failed `Config::load` itself
    /// (module doc). This method's own re-read can still race a
    /// concurrent edit or removal after that load; either failure mode
    /// (unreadable, or fails to parse as *any* TOML) is treated the same
    /// as "nothing to compare" rather than escalated to a second
    /// `CONFIG_ERROR` — this diagnostic is best-effort, not a second
    /// source of truth for whether the file is valid.
    fn doctor_config_unknown_key_findings(&self, config: &Config) -> Vec<DoctorFinding> {
        let path = self.paths.config_file();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let Ok(raw) = text.parse::<toml::Table>().map(toml::Value::Table) else {
            return Vec::new();
        };
        let Ok(known) = toml::Value::try_from(config) else {
            return Vec::new();
        };

        let mut present = std::collections::BTreeSet::new();
        collect_leaf_paths(&raw, String::new(), &mut present);
        let mut known_paths = std::collections::BTreeSet::new();
        collect_leaf_paths(&known, String::new(), &mut known_paths);

        present
            .difference(&known_paths)
            .filter(|key_path| !accepted_under_another_name(&raw, key_path))
            .map(|key_path| DoctorFinding {
                code: CONFIG_UNKNOWN_KEY.code.to_string(),
                status: "warn".to_string(),
                detail: format!("{} (key: {key_path})", CONFIG_UNKNOWN_KEY.message),
                remedy: Some(CONFIG_UNKNOWN_KEY.remedy.to_string()),
            })
            .collect()
    }

    /// `config_serve_to_conflict` (ROADMAP M9 (h), ADR-0012 결정 5) — the same
    /// `[serve].to`-vs-`[reverse].controller` disagreement
    /// [`crate::serve::config_outbound_target`] turns into a hard
    /// `CONFIG_ERROR` for `qsh serve`/`qsh service install` becomes a
    /// finding here instead, never a doctor failure (`doctor.run` always
    /// exits `0`, module doc). `crate::serve::config_serve_to_conflict` is
    /// the single source of truth both surfaces read, so the two can never
    /// disagree about what counts as a conflict.
    fn doctor_config_serve_to_conflict_finding(&self, config: &Config) -> Option<DoctorFinding> {
        let (serve_to, controller) = crate::serve::config_serve_to_conflict(config)?;
        Some(DoctorFinding {
            code: CONFIG_SERVE_TO_CONFLICT.code.to_string(),
            status: "error".to_string(),
            detail: format!(
                "{} ([serve].to: {serve_to:?}, [reverse].controller: {controller:?})",
                CONFIG_SERVE_TO_CONFLICT.message
            ),
            remedy: Some(CONFIG_SERVE_TO_CONFLICT.remedy.to_string()),
        })
    }

    /// `peer_untrusted`/`trust_remove_scope` (design brief rows #3/#13) —
    /// a static cross-reference between `hosts.toml` and `trust.toml`
    /// (`peer_untrusted`: `docs/CLI.md`'s `Host` contract guarantees
    /// `hosts.toml` only ever supplies an address, never identity, so a
    /// name with no trust pin is destined to fail `TRUST_REQUIRED` the
    /// moment anything dials it — no false positive is possible), plus an
    /// unconditional notice (`trust_remove_scope`) whenever at least one
    /// peer is pinned at all.
    fn doctor_trust_findings(&self) -> Result<Vec<DoctorFinding>, OpError> {
        let trust = self.doctor_load_trust()?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let mut out = Vec::new();

        let peer_diag = &PEER_UNTRUSTED;
        for entry in hosts.entries() {
            if trust.find(&entry.name).is_none() {
                out.push(DoctorFinding {
                    code: peer_diag.code.to_string(),
                    status: "error".to_string(),
                    detail: format!("{} (host: {})", peer_diag.message, entry.name),
                    remedy: Some(peer_diag.remedy.to_string()),
                });
            }
        }

        // `trust_pin_role_unset` (ADR-0045 결정 12): one info finding per pin
        // with no `role` key. `detail` carries the pin name and nothing of
        // the pin beyond it.
        let unset_diag = &TRUST_PIN_ROLE_UNSET;
        for peer in trust.peers().iter().filter(|peer| peer.role.is_none()) {
            out.push(DoctorFinding {
                code: unset_diag.code.to_string(),
                status: "info".to_string(),
                detail: format!("{} (peer: {})", unset_diag.message, peer.name),
                remedy: Some(unset_diag.remedy.replace("{name}", &peer.name)),
            });
        }

        // `jump_hop_missing` (ADR-0056 decision 22): a pin whose `jump` names
        // a pin this store does not have. One finding per missing name.
        let missing_diag = &crate::doctor::JUMP_HOP_MISSING;
        for peer in trust.peers() {
            for hop in &peer.jump {
                if trust.find(hop).is_none() {
                    out.push(DoctorFinding {
                        code: missing_diag.code.to_string(),
                        status: "warn".to_string(),
                        detail: format!(
                            "{} (peer: {}, missing hop: {})",
                            missing_diag.message, peer.name, hop
                        ),
                        remedy: Some(missing_diag.remedy.to_string()),
                    });
                }
            }
        }

        if !trust.peers().is_empty() {
            let scope_diag = &TRUST_REMOVE_SCOPE;
            out.push(DoctorFinding {
                code: scope_diag.code.to_string(),
                status: "info".to_string(),
                detail: scope_diag.message.to_string(),
                remedy: Some(scope_diag.remedy.to_string()),
            });
        }

        Ok(out)
    }

    /// `udp_egress_blocked`/`no_route`/`controller_unreachable` (design
    /// brief rows #1/#2/#8) — one probe for the outbound controller target
    /// (when configured — `[serve].to` first, the legacy
    /// `[reverse].controller` as a fallback when `[serve].to` is unset,
    /// same precedence [`infer_run_mode`] uses; ROADMAP M9 (h) —
    /// `crate::config::ReverseConfig::controller`'s own doc), one for
    /// `req.host` (when given). Precedence between the three codes is
    /// [`probe::classify_connectivity`]'s alone (design brief risk #6):
    /// this method never constructs a `DoctorFinding` itself, only feeds
    /// it a `(outcome, is_controller_target)` pair.
    ///
    /// The flag is whether `extra_host` has no direct path: its UDP probe
    /// failed (`no_route`, `udp_egress_blocked`, or `controller_unreachable`
    /// when the host is the controller), or it is a pin with no address.
    /// That is when `qsh doctor <host>` punches (ADR-0054 decision 20).
    fn doctor_connectivity_findings(
        &self,
        config: &Config,
        extra_host: Option<&str>,
    ) -> Result<(Vec<DoctorFinding>, bool), OpError> {
        let trust = TrustStore::load(&self.paths.trust_file())?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let mut out = Vec::new();
        let mut direct_missing = false;

        let controller = config
            .serve
            .to
            .as_deref()
            .or(config.reverse.controller.as_deref());
        if let Some(controller) = controller {
            out.extend(probe_named_target(&trust, &hosts, controller, true));
        }
        if let Some(host) = extra_host {
            // An explicit `--host`/positional target: an unknown name is a
            // hard error, the same precedent `resolve_peer_address`'s own
            // `HOST_NOT_FOUND` wording sets for every other host-targeting
            // op (`qsh capabilities <host>`; `qsh exec` now reaches the
            // same wording through its own `resolve_exec_route` instead,
            // `host::not_in_trust_store_host_not_found`) — the caller named
            // a specific peer, so a typo fails loudly rather than
            // silently turning into an "unreachable" finding.
            let (address, _server_name) = match resolve_peer_address(&trust, &hosts, host) {
                Ok(resolved) => resolved,
                // A pin with no address has no direct path to probe; only a
                // punch can reach it. Anything else stays the hard error.
                Err(err)
                    if err.code == ErrorCode::HostNotFound && pin_has_no_address(&trust, host) =>
                {
                    // Behind a jump chain the address is not dialed from here
                    // at all, so it is not a missing path (ADR-0056).
                    if matches!(self.jump_hops_for(host), Ok(Some(_))) {
                        return Ok((out, false));
                    }
                    return Ok((out, true));
                }
                Err(err) => return Err(err),
            };
            // A host reached through a jump chain is dialed only at the first
            // hop; that is the address whose UDP path matters from here
            // (ADR-0056 decision 13). `jump_hop_missing` reports a hop that
            // is gone, so an unresolved first hop is left to it.
            if let Ok(Some(hops)) = self.jump_hops_for(host) {
                // A first hop pinned without an address is reached by
                // punching; there is no direct path to probe.
                if let Some(first) = hops
                    .first()
                    .filter(|first| !pin_has_no_address(&trust, first))
                {
                    out.extend(probe_named_target(&trust, &hosts, first, false));
                }
                return Ok((out, false));
            }
            // P3-4 (verify round): when `host` resolves to the very peer
            // `[reverse].controller` already names, the branch above
            // already probed it once as `controller_unreachable` — probing
            // it again here would report the *same* underlying failure a
            // second time under a *different* code
            // (`no_route`/`udp_egress_blocked`), which reads as two
            // contradictory diagnoses of one problem rather than one.
            // Matches on the alias name first (cheap, and correct even
            // when the controller alias itself does not resolve), then
            // falls back to comparing resolved addresses (the same name
            // pinned under two different aliases).
            let same_as_controller = controller.is_some_and(|controller| {
                controller == host
                    || resolve_peer_address(&trust, &hosts, controller)
                        .is_ok_and(|(controller_address, _)| controller_address == address)
            });
            if same_as_controller {
                direct_missing = out.iter().any(|f| f.code == "controller_unreachable");
            } else {
                let finding = probe_address(&address, host, false);
                direct_missing = finding
                    .as_ref()
                    .is_some_and(|f| matches!(f.code.as_str(), "no_route" | "udp_egress_blocked"));
                out.extend(finding);
            }
        }

        Ok((out, direct_missing))
    }

    /// The `punch` object and its finding (ADR-0054 decision 20): one punch
    /// through the host's rendezvous peer, on the 8 s budget a command's
    /// punch has, with the connection closed again once it stands. `None`
    /// when punching is off or the host is reached through a reverse
    /// registration. No address or port reaches the object, the finding, or
    /// the `qsh::punch` lines the attempt writes.
    ///
    /// The rendezvous candidates are the route's own: `--rendezvous` when
    /// given, else the pin's `rendezvous` hints. `--no-punch` or
    /// `[punch].mode = "off"` turns the check off; an unreadable
    /// `config.toml` does too, since the config findings already report it.
    fn doctor_punch(&self, host: &str, findings: &mut Vec<DoctorFinding>) -> Option<DoctorPunch> {
        use crate::punch::{PUNCH_BUDGET, PunchMode};

        if !matches!(self.punch_mode(), Ok(PunchMode::Auto)) {
            return None;
        }
        let plan = match self.resolve_route(host) {
            Ok(PeerRoute::Forward(target)) => target.punch.filter(|plan| plan.has_rendezvous()),
            Ok(PeerRoute::Reverse(_)) => return None,
            // An address-less pin with no usable rendezvous is `HOST_NOT_FOUND`.
            Err(err) if err.code == ErrorCode::HostNotFound => None,
            Err(_) => return None,
        };
        let Some(plan) = plan else {
            findings.push(punch_finding(&PUNCH_NO_RENDEZVOUS, "info", host, ""));
            return Some(DoctorPunch {
                rendezvous: None,
                outcome: "no_rendezvous".to_string(),
                reason: Some(
                    crate::punch::GiveUpReason::NoRendezvous
                        .as_str()
                        .to_string(),
                ),
                candidate_kind: None,
                family: None,
                elapsed_ms: None,
            });
        };
        let runtime = self.connect_runtime().ok()?;
        let started = std::time::Instant::now();
        let result = runtime.block_on(async {
            let deadline = tokio::time::Instant::now() + PUNCH_BUDGET;
            crate::punch::attempt(&plan, TransportTuning::default(), deadline).await
        });
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Some(match result {
            Ok(win) => {
                let info = win.info.clone();
                // The point was that it stands; nothing runs over it.
                win.connection.close(0, b"done");
                win.endpoint.close(0, b"done");
                findings.push(punch_finding(
                    &PUNCH_SUCCEEDED,
                    "info",
                    host,
                    &format!(
                        ", rendezvous: {}, candidate: {}, family: {}",
                        info.rendezvous, info.kind, info.family
                    ),
                ));
                DoctorPunch {
                    rendezvous: Some(info.rendezvous),
                    outcome: "succeeded".to_string(),
                    reason: None,
                    candidate_kind: Some(info.kind.to_string()),
                    family: Some(info.family.to_string()),
                    elapsed_ms: Some(info.elapsed_ms),
                }
            }
            Err(failure) => {
                findings.push(punch_finding(
                    &PUNCH_FAILED,
                    "warn",
                    host,
                    &format!(
                        ", rendezvous: {}, reason: {}",
                        failure.rendezvous, failure.reason
                    ),
                ));
                DoctorPunch {
                    rendezvous: Some(failure.rendezvous),
                    outcome: "failed".to_string(),
                    reason: Some(failure.reason.as_str().to_string()),
                    candidate_kind: None,
                    family: None,
                    elapsed_ms: Some(elapsed_ms),
                }
            }
        })
    }

    /// `service_restart_drops_sessions` (M13 H1) joins the registered-unit
    /// branch: it fires for every mode that hosts sessions, beside the
    /// platform finding below, reusing the same unit detection.
    ///
    /// `service_not_registered`/`systemd_linger_disabled`/
    /// `launchagent_session_scoped` (ROADMAP M9 (h)) — one
    /// platform-unit-file existence read
    /// ([`probe::service_unit_registered`]) off `env.home_dir` decides
    /// which of the three fires: no unit ⇒ `service_not_registered`
    /// alone; a registered unit ⇒ `systemd_linger_disabled` (Linux, via
    /// `env.linger_dir`/`env.username`) or `launchagent_session_scoped`
    /// (macOS) instead, never both together and never alongside
    /// `service_not_registered` — mirrors
    /// [`crate::doctor::SYSTEMD_LINGER_DISABLED`]'s own "only reachable
    /// once a unit IS registered" doc.
    ///
    /// `if cfg!(target_os = "...")` rather than `#[cfg(...)]`-gating any
    /// of this body: [`probe::launchagent_session_scoped_finding`],
    /// [`probe::probe_systemd_linger`] and [`probe::linger_finding`] are
    /// themselves portable (no `#[cfg(target_os = ...)]` of their own),
    /// precisely so this method can call them
    /// unconditionally on every target and let the runtime, compile-time-
    /// foldable `target_os` check alone decide which branch's result is
    /// kept — the same struct-field dead-code hazard
    /// [`DoctorEnvironment`]'s own doc explains this sidesteps.
    #[cfg(test)]
    fn doctor_service_registration_findings(
        &self,
        mode: &str,
        env: &DoctorEnvironment<'_>,
    ) -> Vec<DoctorFinding> {
        self.doctor_service_registration_findings_for(mode, false, env)
    }

    /// [`Self::doctor_service_registration_findings`] for a `qsh listen`
    /// that may also host sessions (`combined`, ADR-0059).
    fn doctor_service_registration_findings_for(
        &self,
        mode: &str,
        combined: bool,
        env: &DoctorEnvironment<'_>,
    ) -> Vec<DoctorFinding> {
        let mut out = Vec::new();
        // Windows keeps its task definition under the config directory, so
        // its file-existence answer cannot come from `$HOME` like the other
        // two.
        let registered = if env.os == probe::HostOs::Windows {
            Some(probe::windows_task_definition_present(
                &self.paths.config_dir,
                mode,
            ))
        } else {
            probe::service_unit_registered(env.os, env.home_dir, env.system_root, mode)
        };
        match registered {
            Some(true) => {
                out.extend(probe::service_restart_drops_sessions_finding(
                    mode, combined,
                ));
                // The LaunchAgent notice is silent once the same mode has a
                // LaunchDaemon plist: the always-on form already answers it
                // (ADR-0032 결정 14).
                if env.os == probe::HostOs::Macos
                    && probe::macos_launchagent_present(env.home_dir, mode)
                    && !probe::macos_launchdaemon_present(env.system_root, mode)
                {
                    out.push(probe::launchagent_session_scoped_finding(mode));
                }
                let linger = match env.username {
                    Some(username) if env.os == probe::HostOs::Linux => {
                        probe::probe_systemd_linger(env.linger_dir, username)
                    }
                    _ => probe::LingerProbe::Unknown,
                };
                out.extend(probe::linger_finding(linger, mode));
                if env.key_store == KeyStoreKind::Platform
                    && probe::always_on_form_present(
                        env.os,
                        env.home_dir,
                        env.system_root,
                        linger,
                        mode,
                    )
                {
                    out.push(probe::keystore_session_bound_finding(mode));
                }
            }
            Some(false) => out.push(probe::service_not_registered_finding(mode)),
            None => {}
        }
        if env.os == probe::HostOs::Windows {
            // The task is what is registered, not the file qsh wrote, so the
            // finding does not depend on the file being there. A `Password`
            // principal reads Credential Manager (measured, ADR-0032 결정 15),
            // so there is no `keystore_session_bound` on Windows.
            let logon = env.task_reader.logon_type(&probe::windows_task_name(mode));
            out.extend(Self::logon_task_session_scoped(mode, &logon));
        }
        out
    }

    /// `logon_task_session_scoped` (ADR-0035 결정 27): the task of `mode` is
    /// registered with an `InteractiveToken` principal. The registration and
    /// the principal come from the Task Scheduler COM read (`logon`), not
    /// from the task definition file, because the task may have been
    /// registered from a file qsh did not write and re-registered since.
    /// Nothing is reported for an unregistered task, for any other principal
    /// (the always-on `Password` variant), or when the scheduler cannot be
    /// read, the way an unreadable linger marker reports nothing.
    fn logon_task_session_scoped(
        mode: &str,
        logon: &Result<Option<TaskLogonType>, OpError>,
    ) -> Option<DoctorFinding> {
        match logon {
            Ok(Some(TaskLogonType::InteractiveToken)) => {
                Some(probe::logon_task_session_scoped_finding(mode))
            }
            Ok(Some(TaskLogonType::Password | TaskLogonType::Other) | None) | Err(_) => None,
        }
    }

    /// `bindv6only_blocks_ipv4` (ROADMAP M9 (h)) —
    /// resolves the effective bind address for `mode` the same way
    /// `qsh serve`/`qsh listen` themselves do
    /// ([`crate::serve::resolve_bind`]/[`crate::reverse::listen::resolve_bind`],
    /// both `--bind` flag > config > [`crate::serve::DEFAULT_BIND`] —
    /// `doctor.run` passes no flag, so this reads exactly what a plain
    /// `qsh <mode>` invocation would bind to), skips the real probe
    /// entirely unless that address is the IPv6 wildcard
    /// ([`probe::is_ipv6_wildcard`] — every other address has no
    /// IPv4-blocking consequence, `crate::doctor::BINDV6ONLY_BLOCKS_IPV4`'s
    /// own doc), then defers to `env.bindv6only_probe` (production:
    /// [`probe::probe_bindv6only`]) plus [`probe::bindv6only_finding`]'s
    /// pure classification. A `reverse` target has no listener config of
    /// its own — treated the same as `serve` here (`resolve_bind` falls
    /// back to `[serve].bind` either way), since a reverse target can
    /// still have `[serve]` configured and `DEFAULT_BIND` is a harmless
    /// fallback regardless.
    ///
    /// `Err`/unresolvable bind spec (a config that would already fail
    /// `qsh <mode>`'s own startup) and a bind failure on the throwaway
    /// probe socket both fold into "no finding" — this diagnostic is
    /// best-effort on top of an address doctor did not itself validate,
    /// the same stance [`probe_named_target`] already takes for a
    /// dangling `[reverse].controller` alias.
    fn doctor_bindv6only_finding(
        &self,
        config: &Config,
        mode: &str,
        env: &DoctorEnvironment<'_>,
    ) -> Option<DoctorFinding> {
        // `qsh reverse` dials out; it binds no listener at all (the only
        // two `Listener::bind` call sites in the workspace are `serve`'s
        // and `listen`'s), so there is no bind address to probe here —
        // falling through to `serve`'s default would report a listener
        // problem for a host that runs no listener.
        if mode == "reverse" {
            return None;
        }
        let bind = if mode == "listen" {
            crate::reverse::listen::resolve_bind(None, config)
        } else {
            crate::serve::resolve_bind(None, config)
        }
        .ok()?;
        if !probe::is_ipv6_wildcard(bind) {
            return None;
        }
        let only_v6 = (env.bindv6only_probe)(bind).ok()?;
        probe::bindv6only_finding(&bind.to_string(), only_v6)
    }
}

/// `service_not_registered`/`bindv6only_blocks_ipv4`'s shared mode
/// inference: `[listen]` present (any field set,
/// via `!= ListenConfig::default()` — the same "any field set" test
/// `docs/CLI.md` gives no dedicated accessor for) wins outright; else
/// `[serve].to` (ROADMAP M9 (b), `qsh serve --to`'s own config key — `config.rs`'s
/// own doc); else the legacy `[reverse].controller` key
/// (`crate::config::ReverseConfig::controller`'s own doc — kept here so a
/// `config.toml` written for an older build still infers `reverse`
/// instead of silently falling through to `serve`); else `serve`, the
/// default role for a bare `config.toml`. Both outbound keys map to the
/// same `"reverse"` token — there is no separate token for `qsh serve
/// --to` yet (a later milestone's job). `config_serve_to_conflict`
/// (`crate::doctor::CONFIG_SERVE_TO_CONFLICT`) is the only thing this
/// deliberately leaves out: no diagnostic here for a config that sets more
/// than one of these at once and disagrees, only a precedence rule —
/// conflicting values still infer `"reverse"`.
pub(crate) fn infer_run_mode(config: &Config) -> &'static str {
    if config.listen != crate::config::ListenConfig::default() {
        "listen"
    } else if config.serve.to.is_some() || config.reverse.controller.is_some() {
        "reverse"
    } else {
        "serve"
    }
}

/// Whether `peer` carries a role other than `none`. A value that is not one
/// of the six names cannot get here (the loader refuses the whole file) and
/// reads as no role.
fn peer_has_role(peer: &qsh_proto::TrustPeer) -> bool {
    peer.role
        .as_deref()
        .and_then(|role| role.parse::<TrustRole>().ok())
        .is_some_and(|role| role != TrustRole::None)
}

/// Whether `peer` is authorized for something without an `acl.toml` row: a
/// role other than `none`, or `grants` from `qsh trust allow` (ADR-0051
/// 결정 12), which are judged whatever the role is. Either one says this
/// device authorizes inbound requests, which is what makes it a server
/// (ADR-0066 decision 3, `role_pin`).
fn peer_authorizes_inbound(peer: &qsh_proto::TrustPeer) -> bool {
    peer_has_role(peer)
        || peer
            .grants
            .as_ref()
            .is_some_and(|grants| !grants.is_empty())
}

/// `now_unix` back to a `SystemTime`, for the one finding that needs a clock
/// type (live invites). Second precision is enough: an invite lives ten
/// minutes. A negative value clamps to the epoch.
fn unix_to_system_time(now_unix: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(now_unix).unwrap_or(0))
}

/// [`AuthPath`] → `"pin"`/`"ca"`, the same rendering `crate::audit`'s and
/// `crate::ops::acl`'s own private `auth_path_str` helpers use —
/// `acl_forward_socks_ineffective`'s `detail` names the row's `auth_path`
/// but never its principal string (F1 discipline, `crate::acl::load`'s own
/// doc). [`AuthPath::Pairing`] never reaches a loaded [`crate::acl::Policy`]
/// rule (`crate::acl::load`'s parser only ever produces `Pin`/`Ca`), but the
/// match stays exhaustive since `AuthPath` is a shared transport type.
fn auth_path_str(auth_path: AuthPath) -> &'static str {
    match auth_path {
        AuthPath::Pin => "pin",
        AuthPath::Ca => "ca",
        AuthPath::Pairing => "pairing",
    }
}

/// `now` as unix seconds. `SystemTime::duration_since` only fails for a
/// `now` before `UNIX_EPOCH`, which no real clock and no test in this
/// codebase produces — handled here anyway (a negative timestamp) rather
/// than panicking, since `doctor.run`'s entire point is to stay useful
/// under a badly wrong clock.
fn unix_seconds(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(before_epoch) => -i64::try_from(before_epoch.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Walks a [`toml::Value`] tree and inserts every *leaf* key path into
/// `out`, dotted (`serve.max_sessions_per_principal`). A table array's
/// index is deliberately dropped from the path (`reverse.foo` not
/// `reverse[0].foo`) so an array-of-tables entry compares by shape, not by
/// position — [`Ops::doctor_config_unknown_key_findings`]'s own doc
/// explains why this matters for `Config`, which currently has no such
/// array field but should not silently break this comparison the day one
/// is added. An empty table contributes no leaf of its own (nothing to
/// diff against — an empty `[serve]` and an absent one look identical
/// either way) — this also means a wholly unknown *empty* section, e.g.
/// a config.toml with nothing but `[garbage]` and no keys under it, has
/// no leaf path to compare and so is not reported by
/// `config_unknown_key` either; only an unknown key (leaf) is ever
/// flagged, never an unknown but empty table.
fn collect_leaf_paths(
    value: &toml::Value,
    prefix: String,
    out: &mut std::collections::BTreeSet<String>,
) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_leaf_paths(child, path, out);
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_leaf_paths(item, prefix.clone(), out);
            }
        }
        _ => {
            if !prefix.is_empty() {
                out.insert(prefix);
            }
        }
    }
}

/// Looks up the [`toml::Value`] living at a dotted `key_path` inside
/// `raw`, descending through tables only. A path that runs through an
/// array along the way (its index already dropped by
/// [`collect_leaf_paths`]) cannot be resolved to one unambiguous value
/// and yields `None` — [`accepted_under_another_name`] treats that as
/// "cannot probe this candidate", not as "this key is unknown".
fn lookup<'a>(raw: &'a toml::Value, key_path: &str) -> Option<&'a toml::Value> {
    let mut current = raw;
    for segment in key_path.split('.') {
        current = current.as_table()?.get(segment)?;
    }
    Some(current)
}

/// Wraps a single leaf `value` back up in the nested tables its dotted
/// `key_path` implies, e.g. `serve.resume_ttl_secs` + `3600` becomes the
/// document `{ serve = { resume_ttl_secs = 3600 } }` and nothing else.
fn single_key_document(key_path: &str, value: &toml::Value) -> toml::Value {
    let mut segments: Vec<&str> = key_path.split('.').collect();
    let mut doc = value.clone();
    while let Some(segment) = segments.pop() {
        let mut table = toml::value::Table::new();
        table.insert(segment.to_string(), doc);
        doc = toml::Value::Table(table);
    }
    doc
}

/// Filters a `config_unknown_key` candidate that `serde` actually
/// recognizes under a different name than the one it was written with —
/// today, only [`crate::config::ServeConfig::resume_ttl`]'s
/// `#[serde(alias = "resume_ttl_secs")]`, which `Serialize` never
/// re-emits, so a file written with the alias always looks "unknown" by
/// [`collect_leaf_paths`]'s round trip alone. Builds a single-key TOML
/// document containing nothing but this one candidate at its original
/// path and deserializes it as a [`Config`]: a genuine typo can never
/// move `Config` off [`Config::default`] (there is no field for it to
/// land on), so only a real alias — or the canonical name itself —
/// makes this `true`. A key path [`lookup`] cannot resolve (it runs
/// through an array) is left flagged rather than probed. A malformed
/// single-key document (should not happen — it is built from an
/// already-parsed [`toml::Value`]) is likewise treated as "not an
/// alias", i.e. still flagged. The one corner this cannot see: an alias
/// key written with exactly the default value is indistinguishable from
/// an unrecognized one and stays flagged — harmless, since this
/// finding's remedy (delete the key) would not change any applied cap
/// either way.
fn accepted_under_another_name(raw: &toml::Value, key_path: &str) -> bool {
    let Some(leaf) = lookup(raw, key_path) else {
        return false;
    };
    let doc = single_key_document(key_path, leaf);
    matches!(doc.try_into::<Config>(), Ok(config) if config != Config::default())
}

/// `cert_expired`/`cert_expiring_soon`, pure over an already-read
/// certificate's validity window — the two codes are mutually exclusive
/// for the same certificate (design brief row #5): expired wins outright,
/// expiring-soon only applies to a certificate that has not expired yet.
fn cert_expiry_finding(
    label: &str,
    cert_der: &[u8],
    now_unix: i64,
) -> Result<Option<DoctorFinding>, OpError> {
    let (_not_before, not_after) =
        qsh_transport::identity::validity_unix(cert_der).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("failed to read {label}'s certificate validity: {err}"),
            )
            .with_retryable(false)
        })?;

    if now_unix >= not_after {
        let diag = &CERT_EXPIRED;
        return Ok(Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "error".to_string(),
            detail: format!("{} ({label}, not_after unix: {not_after})", diag.message),
            remedy: Some(diag.remedy.to_string()),
        }));
    }
    if not_after - now_unix <= CERT_EXPIRING_SOON_WINDOW_SECS {
        let diag = &CERT_EXPIRING_SOON;
        return Ok(Some(DoctorFinding {
            code: diag.code.to_string(),
            status: "warn".to_string(),
            detail: format!("{} ({label}, not_after unix: {not_after})", diag.message),
            remedy: Some(diag.remedy.to_string()),
        }));
    }
    Ok(None)
}

/// `clock_skew`, pure over an already-read `not_before` and `now`
/// (design brief row #7 / E-1): `error` once the observed skew exceeds
/// [`CERT_BACKDATE_MINUTES`] (the same 5-minute margin
/// [`crate::identity::init`] already backdates every fresh certificate
/// by, to absorb ordinary clock drift between peers), `warn` for any
/// smaller skew, `None` when the clock is not behind `not_before` at all.
fn clock_skew_finding(not_before_unix: i64, now_unix: i64) -> Option<DoctorFinding> {
    if now_unix >= not_before_unix {
        return None;
    }
    let skew_seconds = not_before_unix - now_unix;
    // Compare in whole seconds, not truncated minutes (P2 verify round
    // P3-1): a 301s skew already exceeds the 300s (5-minute) margin, but
    // `301 / 60 == 5`, which is not `> 5` — the truncated-minutes
    // comparison used to under-report that as `warn` instead of `error`.
    // `skew_minutes` still exists, for the detail string only.
    let skew_minutes = skew_seconds / 60;
    let status = if skew_seconds > CERT_BACKDATE_MINUTES * 60 {
        "error"
    } else {
        "warn"
    };
    let diag = &CLOCK_SKEW;
    Some(DoctorFinding {
        code: diag.code.to_string(),
        status: status.to_string(),
        detail: format!(
            "{} (observed skew: {skew_minutes} minute(s); backdate margin: {CERT_BACKDATE_MINUTES} minute(s))",
            diag.message
        ),
        remedy: Some(diag.remedy.to_string()),
    })
}

/// `keystore_unavailable`, pure over an already-performed
/// [`KeyStore::load`] probe (verify round P2-2). Split out of
/// [`Ops::doctor_keystore_finding`] so a test can force the
/// `Err(KeyStoreError::Unavailable(_))` branch with a stub `KeyStore`
/// rather than depending on whether this test machine happens to have a
/// reachable platform credential store — the same "detection and
/// classification kept apart" discipline
/// [`probe::classify_connectivity`]'s own doc states, one layer up: this
/// is the seam between "which store to probe" (`Ops`'s job) and "what a
/// probe result means" ([`probe::keystore_finding`]'s job, reused
/// verbatim here).
fn keystore_finding_of(store: &(impl KeyStore + ?Sized)) -> Option<DoctorFinding> {
    probe::keystore_finding(store.load())
}

/// `qsh_path_shadowed`, pure over an already-read `current_exe`/`$PATH`
/// (verify round P2-4). Split out of [`Ops::doctor_path_shadow_finding`]
/// for the same reason [`keystore_finding_of`] is: `std::env::current_exe`/
/// `std::env::var_os("PATH")` stay in the one caller that reads the real
/// environment, so a test can drive this deterministically with an
/// injected temp `$PATH` (the same pattern
/// `doctor::probe::tests::detect_path_shadow_*` already uses one layer
/// down) instead of only ever exercising it through whatever `qsh`
/// binaries happen to be on this test machine's real `$PATH`.
fn path_shadow_finding(current_exe: &Path, dirs: &[PathBuf]) -> Option<DoctorFinding> {
    let shadow = probe::detect_path_shadow(current_exe, dirs)?;
    let diag = &QSH_PATH_SHADOWED;
    Some(DoctorFinding {
        code: diag.code.to_string(),
        status: "warn".to_string(),
        detail: format!(
            "{} (shadowing: {}, running: {})",
            diag.message,
            shadow.display(),
            current_exe.display()
        ),
        remedy: Some(diag.remedy.to_string()),
    })
}

/// Resolve `name` (a trust-store/`hosts.toml` alias) to an address and
/// probe it, or — when the alias itself does not resolve — report that
/// the same way an unreachable probe would ([`UdpProbeOutcome::Unreachable`]):
/// an alias this device cannot even resolve to an address is exactly what
/// `controller_unreachable`/`no_route` already mean, so
/// [`Ops::doctor_connectivity_findings`]'s `[reverse].controller` branch
/// never aborts the whole report over a config value it did not validate
/// itself (see [`crate::config::ReverseConfig::controller`]'s own doc: a
/// dangling alias there has never been validated by any code path before
/// this one).
fn probe_named_target(
    trust: &TrustStore,
    hosts: &HostsFile,
    name: &str,
    is_controller_target: bool,
) -> Option<DoctorFinding> {
    match resolve_peer_address(trust, hosts, name) {
        Ok((address, _server_name)) => probe_address(&address, name, is_controller_target),
        Err(_) => probe::classify_connectivity(
            UdpProbeOutcome::Unreachable,
            is_controller_target,
            name,
            "<unresolved>",
        ),
    }
}

/// Resolve `address` (`host:port`) to a socket address and run the raw UDP
/// egress probe against it; a DNS/parse failure classifies the same as
/// [`UdpProbeOutcome::Unreachable`] rather than propagating as a hard
/// error, for the same reason [`probe_named_target`]'s alias-resolution
/// failure does not.
fn probe_address(address: &str, name: &str, is_controller_target: bool) -> Option<DoctorFinding> {
    let outcome = match resolve_probe_socket_addr(address) {
        Ok(socket_addr) => probe::probe_udp_egress(socket_addr, DOCTOR_PROBE_TIMEOUT),
        Err(_) => UdpProbeOutcome::Unreachable,
    };
    probe::classify_connectivity(outcome, is_controller_target, name, address)
}

/// Blocking `host:port` → `SocketAddr` resolution for the connectivity
/// probe. Deliberately not [`crate::ops::resolve_one`] (that is `async`,
/// for callers already inside a Tokio runtime) — `doctor.run` is entirely
/// synchronous end to end, so this uses the blocking
/// [`std::net::ToSocketAddrs`] resolver instead of starting a runtime just
/// for one DNS lookup.
///
/// Bounded by [`DOCTOR_PROBE_TIMEOUT`] via [`resolve_with_timeout`] — a
/// slow or silent resolver (a real risk for a real, possibly stale-network
/// `--host`/`[reverse].controller` value) no longer holds `doctor.run`
/// hostage past the same budget every other probe already respects. A
/// timeout is surfaced as a plain [`std::io::Error`] and falls through
/// [`probe_address`]'s existing `Err(_) => `[`UdpProbeOutcome::Unreachable`]
/// arm — the same path a parse failure or NXDOMAIN already took, so this
/// adds no new [`DoctorFinding`] code (`EXPECTED_DOCTOR_CODES` stays at
/// 14). This resolve budget is on top of, not shared with,
/// [`probe_address`]'s own `DOCTOR_PROBE_TIMEOUT`-bounded
/// [`probe::probe_udp_egress`] call that follows a successful resolution —
/// so one unreachable target costs at most `2 × DOCTOR_PROBE_TIMEOUT`, not
/// `DOCTOR_PROBE_TIMEOUT`.
fn resolve_probe_socket_addr(address: &str) -> std::io::Result<std::net::SocketAddr> {
    let address = address.to_string();
    resolve_with_timeout(DOCTOR_PROBE_TIMEOUT, move || blocking_resolve(&address))
}

/// The actual blocking `ToSocketAddrs` lookup, factored out of
/// [`resolve_probe_socket_addr`] so [`resolve_with_timeout`] can be tested
/// against a synthetic slow closure instead of a real DNS name.
fn blocking_resolve(address: &str) -> std::io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved"))
}

/// Run a blocking `resolve` (in practice, [`blocking_resolve`]'s DNS
/// lookup) on its own thread and wait up to `timeout` for it to finish.
///
/// The thread is detached, not joined: if the resolver never returns —
/// genuinely hung, not merely slow — that thread stays parked past this
/// function's return, until the resolver eventually answers (its `send`
/// then silently fails, since `rx` has already been dropped) or the
/// process exits. This is a deliberate, bounded leak of at most one thread
/// per timed-out probe, not an unbounded one: `doctor.run` issues a small,
/// fixed number of probes per invocation (one per pinned `--host`/
/// `[reverse].controller` target), never a loop over untrusted input.
fn resolve_with_timeout<F>(timeout: Duration, resolve: F) -> std::io::Result<std::net::SocketAddr>
where
    F: FnOnce() -> std::io::Result<std::net::SocketAddr> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("qsh-doctor-resolve".to_string())
        .spawn(move || {
            // The receiver may already be gone (timed out and returned) by
            // the time this resolves — that's the detach: a
            // dropped-receiver send error is expected, not a bug, and is
            // deliberately discarded.
            let _ = tx.send(resolve());
        });
    if let Err(err) = spawned {
        // Thread creation itself failing (`EAGAIN`/`ENOMEM` — OS-level
        // resource exhaustion) must not panic `doctor.run` the way
        // `std::thread::spawn` would; it is the same "could not probe"
        // outcome as a timeout, just diagnosed at spawn time rather than
        // after waiting on it.
        return Err(std::io::Error::new(
            err.kind(),
            format!("could not spawn resolver thread: {err}"),
        ));
    }
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "resolver did not respond within the probe timeout",
        )),
        // `tx` was dropped without a `send` — the resolver thread died
        // (panicked) before it could report a result. Distinct from a
        // plain timeout: this is not "still working, too slow" but "will
        // never answer."
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::other(
            "resolver thread died before sending a result",
        )),
    }
}

/// Worst severity across every finding — `"error"` beats `"warn"` beats
/// (no findings, or only `"info"`) `"ok"`. `"info"` findings never affect
/// this: an unconditional notice like `trust_remove_scope` is not a
/// problem (design brief §A: `ok` never appears on an individual finding,
/// only here).
fn overall_status(findings: &[DoctorFinding]) -> String {
    if findings.iter().any(|f| f.status == "error") {
        "error".to_string()
    } else if findings.iter().any(|f| f.status == "warn") {
        "warn".to_string()
    } else {
        "ok".to_string()
    }
}

/// The `--fail-on` threshold vocabulary (ADR-0027): `warn` or `error`.
/// `info` is deliberately absent, because `"info"` findings are standing
/// notices and a gate that counted them would be red on most machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorThreshold {
    /// Trips on any `"warn"` or `"error"` finding.
    Warn,
    /// Trips on any `"error"` finding.
    Error,
}

impl std::str::FromStr for DoctorThreshold {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "invalid fail-on threshold {other:?}: expected `warn` or `error`"
            )),
        }
    }
}

/// Whether any finding in `data` is at or above `threshold`, in the same
/// `"error"` > `"warn"` order `overall_status` uses (ADR-0027 decision 2).
/// Only called after a successful run; it never changes the report.
#[must_use]
pub fn meets_threshold(data: &DoctorData, threshold: DoctorThreshold) -> bool {
    data.findings.iter().any(|f| match threshold {
        DoctorThreshold::Warn => f.status == "warn" || f.status == "error",
        DoctorThreshold::Error => f.status == "error",
    })
}

mod combined;
mod jump;

#[cfg(test)]
mod tests;

/// One of the three punch findings: the diagnostic's text, then the host
/// and `extra` (words from closed vocabularies and pin names, never an
/// address).
fn punch_finding(
    diag: &crate::doctor::Diagnostic,
    status: &str,
    host: &str,
    extra: &str,
) -> DoctorFinding {
    DoctorFinding {
        code: diag.code.to_string(),
        status: status.to_string(),
        detail: format!("{} (host: {host}{extra})", diag.message),
        remedy: Some(diag.remedy.to_string()),
    }
}

/// Whether `host` names a pin that records no address.
fn pin_has_no_address(trust: &TrustStore, host: &str) -> bool {
    trust
        .find(crate::ops::host::lookup_name(host))
        .is_some_and(|pin| pin.address.is_empty())
}

/// How long `qsh doctor <host>` waits for the measurement connection to come
/// up before it reports no `transport` (ADR-0052 decision 14).
const TRANSPORT_PROBE_DIAL_BUDGET: Duration = Duration::from_secs(3);

/// Whether the UDP probes already found `host` unreachable. The measurement
/// connection would only wait out its dial budget on a path they just called
/// dead, so it is skipped.
fn reachability_failed(findings: &[DoctorFinding]) -> bool {
    findings.iter().any(|f| {
        matches!(
            f.code.as_str(),
            "controller_unreachable" | "udp_egress_blocked" | "no_route"
        )
    })
}

/// `screen_echo_unsupported` (ADR-0053 decision 11): the peer offers
/// `screen.v1` but not `screen-echo.v1` and prediction is not switched off by
/// `[interactive].predict = "never"`. A peer without `screen.v1` already gets
/// `screen_sync_unsupported`, which covers it.
fn echo_finding(
    host: &str,
    screen_offered: bool,
    echo_offered: bool,
    predict_wanted: bool,
) -> Option<DoctorFinding> {
    if !(screen_offered && !echo_offered && predict_wanted) {
        return None;
    }
    let diag = &SCREEN_ECHO_UNSUPPORTED;
    Some(DoctorFinding {
        code: diag.code.to_string(),
        status: "info".to_string(),
        detail: format!("{} (peer: {host})", diag.message),
        remedy: Some(diag.remedy.to_string()),
    })
}

/// The two `info` findings a measurement connection can raise (ADR-0052
/// decision 14): the peer does not advertise `screen.v1`, and there is no
/// DATAGRAM path (`datagram.v1` missing on either end, or the path reports no
/// payload size).
fn transport_findings(
    host: &str,
    screen_offered: bool,
    datagram_offered: bool,
    max_datagram: Option<usize>,
) -> Vec<DoctorFinding> {
    let mut out = Vec::new();
    for (raised, diag) in [
        (!screen_offered, &SCREEN_SYNC_UNSUPPORTED),
        (
            !datagram_offered || max_datagram.is_none(),
            &DATAGRAM_UNAVAILABLE,
        ),
    ] {
        if raised {
            out.push(DoctorFinding {
                code: diag.code.to_string(),
                status: "info".to_string(),
                detail: format!("{} (peer: {host})", diag.message),
                remedy: Some(diag.remedy.to_string()),
            });
        }
    }
    out
}

/// `agent_unreachable` and `agent_dir_unusable` (ADR-0055 decision 19).
/// Both are `warn`: nothing is refused, forwarding just cannot work.
fn doctor_agent_findings(
    config: &Config,
    env: &DoctorEnvironment<'_>,
    server: bool,
) -> Vec<DoctorFinding> {
    use crate::doctor::{AGENT_DIR_UNUSABLE, AGENT_UNREACHABLE};
    let mut out = Vec::new();
    if config.agent.forward == Some(crate::config::AgentForwardMode::Yes)
        && env.local_agent == Some(false)
    {
        out.push(DoctorFinding {
            code: AGENT_UNREACHABLE.code.to_string(),
            status: "warn".to_string(),
            detail: AGENT_UNREACHABLE.message.to_string(),
            remedy: Some(AGENT_UNREACHABLE.remedy.to_string()),
        });
    }
    // The agent directory is where a serving host puts the sockets it
    // forwards to; a client-only device has no use for it (ADR-0066).
    if server
        && let Some(dir) = env.agent_runtime_dir
        && let Err(why) = crate::agent::check_agent_dir(dir)
    {
        out.push(DoctorFinding {
            code: AGENT_DIR_UNUSABLE.code.to_string(),
            status: "warn".to_string(),
            detail: format!("{} ({why})", AGENT_DIR_UNUSABLE.message),
            remedy: Some(AGENT_DIR_UNUSABLE.remedy.to_string()),
        });
    }
    out
}
