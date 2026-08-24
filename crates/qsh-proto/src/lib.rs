//! `qsh-proto`: the sans-IO contract layer shared by every other QSH crate.
//!
//! This crate has no async runtime and no I/O of its own. It owns:
//!
//! - [`frame`]: the length-prefixed framing used on every QSH byte stream.
//! - [`wire`]: the prost-generated `qsh/1` control/data messages
//!   (`proto/qsh/wire/v1.proto`) and their frame-layer glue.
//! - [`error`]: [`error::ErrorCode`], the vocabulary shared by the wire
//!   protocol and the `qsh.cli/v1` JSON envelope.
//! - [`types`]: JSON contract types (`docs/CLI.md` §5, §6).
//! - [`event`]: `qsh.event/v1` session events (`docs/CLI.md` §6.4). Note
//!   that [`event::SessionEvent`] (JSON) and [`wire::SessionEvent`]
//!   (protobuf, control-stream notification) are distinct types; only the
//!   JSON one is re-exported at the crate root.
//! - [`local`]: the prost-generated `qsh.local.v1` messages (localctl IPC,
//!   `proto/qsh/local/v1.proto`) and their frame-layer glue — a separate
//!   package from [`wire`] but sharing its frame layer (M3,
//!   `docs/design/protocol.md` §11-3).
//!
//! Because this crate parses untrusted input from the network, it is the
//! designated fuzzing surface for the project (`docs/design/protocol.md`
//! §13) and depends on no other workspace crate.

pub mod error;
pub mod event;
pub mod frame;
pub mod local;
pub mod types;
pub mod wire;

pub use error::ErrorCode;
pub use event::SessionEvent;
pub use types::{
    CLI_SCHEMA_V1, CliEnvelope, CliError, EnvVar, ExecRunData, ExecRunReq, Host, HostGetReq,
    HostListData, HostListReq, IdentityInitData, IdentityInitReq, KeyStoreKind, KeyStoreMode,
    Session, SessionAttachReq, SessionCloseData, SessionCloseReq, SessionGetReq, SessionListData,
    SessionListReq, SessionOpenData, SessionOpenReq, SessionReadData, SessionReadReq,
    SessionResizeData, SessionResizeReq, SessionWriteData, SessionWriteReq, TrustAddData,
    TrustAddReq, TrustListData, TrustPeer, TrustRemoveData, Tunnel, TunnelCloseData,
    TunnelCloseReq, TunnelListData, TunnelListReq, TunnelOpenData, TunnelOpenReq, UnreachableHost,
    VersionData,
};
