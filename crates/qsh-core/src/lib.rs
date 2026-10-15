//! `qsh-core`: all business logic, exposed as a typed operation layer.
//!
//! [`ops::Ops`] is the single API every frontend (`qsh-cli`'s human/JSON
//! renderers, and any long-running external process — e.g. an agent tool —
//! integrating over `qsh.cli/v1`) calls through — see
//! `docs/CLI.md` §11. Renderers and adapters contain zero auth, ACL or
//! session logic; if something has to be reimplemented in a frontend to
//! work, it belongs here instead.
//!
//! - [`config`]: config/state path resolution and `config.toml`.
//! - [`identity`]: device keypair, certificate and the 3-mode key store.
//! - [`ca`]: the private CA root and device-leaf issuance (`qsh cert`,
//!   `docs/adr/0008-private-ca-cert-issuance.md`).
//! - [`trust`]: `trust.toml` — pinned peers, private CA roots, and the
//!   [`qsh_transport::TrustEvaluator`] the verifier is driven by.
//! - [`hosts`]: `hosts.toml` — the host profile address book layered over
//!   `trust`'s pinned peers (M7 plan Step 3 (69dd788)). Never a trust source.
//! - [`mod@file`]: remote file operations; today only the shared path judgement
//!   [`file::guard`] (`docs/adr/0029-file-copy.md`).
//! - [`ssh_bootstrap`]: the ssh child, `ssh -G` and argument building behind
//!   `qsh pair ssh` (`docs/adr/0044-ssh-bootstrap.md`).
//! - [`ops`]: the typed operation façade.

pub mod acl;
pub mod admission;
pub mod audit;
pub mod broker;
pub mod ca;
pub mod client;
pub mod config;
pub mod doctor;
pub mod exec;
pub mod file;
pub(crate) mod fsutil;
pub mod handshake;
pub mod hosts;
pub mod identity;
pub mod lifecycle;
// localctl (UDS IPC to this machine's resident `qsh listen` daemon) has no
// meaning on Windows — no daemon, no socket, no peer credential concept —
// so the whole module tree compiles out there rather than growing internal
// platform splits (`crates/qsh-core/src/localctl/mod.rs` module docs,
// `docs/CLI.md` §6.13, M3 plan Step 5 (2473c88)).
#[cfg(unix)]
pub mod localctl;
pub mod ops;
pub mod pairing;
pub mod pty;
pub mod quota;
pub mod reset_key;
pub mod resume;
pub mod reverse;
pub mod serve;
pub mod server;
pub mod session_stream;
pub mod setup;
pub mod ssh_bootstrap;
pub mod telemetry;
pub mod trust;
pub mod tunnel;

pub use client::pathwatch::PathWatchConfig;
pub use config::{Config, Paths, SshBootstrapMode, SshConfig, now_rfc3339};
pub use doctor::{CONTROLLER_UNREACHABLE, Diagnostic, DiagnosticId};
pub use hosts::{HostEntry, HostsFile};
pub use identity::{Identity, KeyStore, KeyStoreError, LoadedIdentity};
pub use ops::service::{
    CommandRunner, DOC_EXAMPLE_CONTROLLER, DOC_EXAMPLE_EXE_LINUX, DOC_EXAMPLE_EXE_MACOS,
    DOC_EXAMPLE_HOME_MACOS, MANAGER_CALL_DEADLINE, MANAGER_STDERR_CAP, ManagerClock, ManagerOutput,
    ManagerRunner, RunError, SERVICE_UNSUPPORTED_PLATFORM, SystemManagerClock, TaskStateQuery,
    launchd_bootout_argv, launchd_bootstrap_argv, launchd_print_argv, launchd_print_system_argv,
    render_launchd_plist, render_systemd_unit, systemd_daemon_reload_argv,
    systemd_disable_now_argv, systemd_enable_now_argv, systemd_is_active_argv,
};
pub use ops::{
    AclCheckOp, AclShowOp, AttachHandle, AutoBootstrap, AutoBootstrapReport, CancelToken,
    CapabilitiesOp, CertInitOp, CertIssueOp, DetachFlush, DoctorHostState, DoctorOp,
    DoctorThreshold, ExecRunOp, ExecRunOutput, ExecStdin, FILE_COPY_PARALLEL, FileCopyError,
    FileCopyObserver, FileCopyOp, FileProgress, HostGetOp, HostListOp, HostRoute,
    INVITE_CODE_PROMPT, INVITE_CODE_STDIN_MAX, IdentityExportOp, IdentityInitOp, IdentityMoveKeyOp,
    InviteCodeSource, OpError, Operation, Ops, PairSshEnv, PairSshOp, PairSshOutput,
    RecoveryConfig, SchemaOp, ServiceInstallOp, ServiceStatusOp, ServiceUninstallOp,
    SessionAttachOp, SessionAttachStream, SessionCloseOp, SessionFilter, SessionGetOp,
    SessionListOp, SessionOpenOp, SessionReadOp, SessionReadOutput, SessionReader, SessionResizeOp,
    SessionWriteOp, SetupRunOp, SilentObserver, TrustAcceptOp, TrustAddCaOp, TrustAddOp,
    TrustInviteOp, TrustListOp, TrustRemoveOp, TrustRenameOp, TrustSetRoleOp, TrustSshPreviewOp,
    TunnelCloseOp, TunnelDynamicOp, TunnelHold, TunnelListOp, TunnelOpenOp, VersionOp,
    cert_file_fingerprint_conflict, meets_threshold, normalize_invite_code, parse_dynamic_forwards,
    parse_local_forwards, parse_remote_forwards, read_cert_file_arg, resolve_invite_code_source,
    unconfigured_host_name,
};
pub use setup::SetupEnv;
pub use trust::{SharedTrustStore, TrustStore};

// Certificate-derived identity types belong to the transport layer, but they
// are part of `Ops`' public surface (fingerprints, principals), so frontends
// can name them without depending on `qsh-transport` themselves
// (`docs/design/architecture.md` §1 dependency matrix).
pub use qsh_transport::{Fingerprint, Principal};
