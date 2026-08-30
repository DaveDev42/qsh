//! `qsh-core`: all business logic, exposed as a typed operation layer.
//!
//! [`ops::Ops`] is the single API every frontend (`qsh-cli`'s human/JSON
//! renderers today; the MCP adapter from M6) calls through — see
//! `docs/CLI.md` §11. Renderers and adapters contain zero auth, ACL or
//! session logic; if something has to be reimplemented in a frontend to
//! work, it belongs here instead.
//!
//! - [`config`]: config/state path resolution and `config.toml`.
//! - [`identity`]: device keypair, certificate and the 3-mode key store.
//! - [`trust`]: `trust.toml` — pinned peers, private CA roots, and the
//!   [`qsh_transport::TrustEvaluator`] the verifier is driven by.
//! - [`ops`]: the typed operation façade.

pub mod acl;
pub mod audit;
pub mod broker;
pub mod client;
pub mod config;
pub mod doctor;
pub mod exec;
pub mod handshake;
pub mod identity;
// localctl (UDS IPC to this machine's resident `qsh listen` daemon) has no
// meaning on Windows — no daemon, no socket, no peer credential concept —
// so the whole module tree compiles out there rather than growing internal
// platform splits (`crates/qsh-core/src/localctl/mod.rs` module docs,
// `docs/CLI.md` §6.13, `PLAN.md` M3 Step 5).
#[cfg(unix)]
pub mod localctl;
pub mod ops;
pub mod pty;
pub mod resume;
pub mod reverse;
pub mod serve;
pub mod server;
pub mod session_stream;
pub mod telemetry;
pub mod trust;
pub mod tunnel;

pub use client::pathwatch::PathWatchConfig;
pub use config::{Config, Paths, now_rfc3339};
pub use doctor::{CONTROLLER_UNREACHABLE, Diagnostic, DiagnosticId};
pub use identity::{Identity, KeyStore, KeyStoreError, LoadedIdentity};
pub use ops::{
    AclCheckOp, AttachHandle, CapabilitiesOp, DetachFlush, ExecRunOp, ExecRunOutput, ExecStdin,
    HostGetOp, HostListOp, HostRoute, IdentityInitOp, OpError, Operation, Ops, RecoveryConfig,
    SchemaOp, SessionAttachOp, SessionAttachStream, SessionCloseOp, SessionGetOp, SessionListOp,
    SessionOpenOp, SessionReadOp, SessionReadOutput, SessionReader, SessionResizeOp,
    SessionWriteOp, TrustAddOp, TrustListOp, TrustRemoveOp, TunnelCloseOp, TunnelHold,
    TunnelListOp, TunnelOpenOp, VersionOp, dynamic_forward_unsupported, parse_local_forwards,
    parse_remote_forwards,
};
pub use trust::{SharedTrustStore, TrustStore};

// Certificate-derived identity types belong to the transport layer, but they
// are part of `Ops`' public surface (fingerprints, principals), so frontends
// can name them without depending on `qsh-transport` themselves
// (`docs/design/architecture.md` §1 dependency matrix).
pub use qsh_transport::{Fingerprint, Principal};
