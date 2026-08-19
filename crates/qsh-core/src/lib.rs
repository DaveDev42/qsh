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
pub mod exec;
pub mod identity;
pub mod ops;
pub mod pty;
pub mod resume;
pub mod serve;
pub mod server;
pub mod session_stream;
pub mod telemetry;
pub mod trust;

pub use config::{Config, Paths, now_rfc3339};
pub use identity::{Identity, KeyStore, KeyStoreError, LoadedIdentity};
pub use ops::{
    AttachHandle, ExecRunOp, ExecRunOutput, ExecStdin, IdentityInitOp, OpError, Operation, Ops,
    SessionAttachOp, SessionAttachStream, SessionCloseOp, SessionGetOp, SessionListOp,
    SessionOpenOp, SessionReadOp, SessionReadOutput, SessionReader, SessionResizeOp,
    SessionWriteOp, TrustAddOp, TrustListOp, TrustRemoveOp, VersionOp,
};
pub use trust::{SharedTrustStore, TrustStore};

// Certificate-derived identity types belong to the transport layer, but they
// are part of `Ops`' public surface (fingerprints, principals), so frontends
// can name them without depending on `qsh-transport` themselves
// (`docs/design/architecture.md` §1 dependency matrix).
pub use qsh_transport::{Fingerprint, Principal};
