//! The typed operation layer: the single API surface the CLI, `--json`
//! renderer and (from M6) the MCP adapter all call through. See
//! `docs/CLI.md` §11 — frontends must not reimplement business logic, they
//! only translate an [`Ops`] call into their own presentation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::{
    ErrorCode, IdentityInitData, IdentityInitReq, KeyStoreMode, TrustAddData, TrustAddReq,
    TrustListData, TrustRemoveData, VersionData,
};
use qsh_transport::{DialError, Dialer, Fingerprint, StaticTrust};

use crate::config::{Config, Paths, now_rfc3339};
use crate::identity::LoadedIdentity;
use crate::trust::{SharedTrustStore, TrustStore};

pub mod exec;
pub mod session;

pub use exec::{ExecRunOp, ExecRunOutput, ExecStdin};
pub use session::{
    AttachHandle, SESSION_WRITE_MAX, SessionAttachOp, SessionAttachStream, SessionCloseOp,
    SessionGetOp, SessionListOp, SessionOpenOp, SessionReadOp, SessionReadOutput, SessionReader,
    SessionRef, SessionResizeOp, SessionWriteOp, make_session_ref, parse_session_ref,
};

/// Everything a remote call needs to reach a pinned host: our identity,
/// the trust evaluator, and where to dial.
pub(crate) struct PeerTarget {
    /// This device's identity and private key.
    pub identity: LoadedIdentity,
    /// The trust store as the transport's evaluator.
    pub trust: Arc<SharedTrustStore>,
    /// `host:port` recorded for the peer.
    pub address: String,
    /// SNI value for the dial (see [`server_name_for`]).
    pub server_name: String,
}

/// How long the `trust.add` fingerprint probe waits for a handshake before
/// reporting `CONNECTION_FAILED`. Deliberately shorter than the transport's
/// default dial timeout: this dial is expected to fail (we trust nothing),
/// so it must not hold a human or a test hostage.
const PROBE_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Marker trait for a single typed operation.
///
/// `COMMAND` is the dotted-form command name used as the `command` field in
/// the `qsh.cli/v1` envelope and as the audit/ACL join key (e.g.
/// `"version.get"`, `"session.open"`).
pub trait Operation {
    /// Dotted-form command name, e.g. `"version.get"`.
    const COMMAND: &'static str;
}

/// Error type returned by every operation. Carries everything the
/// `qsh.cli/v1` error envelope needs (`docs/CLI.md` §3.2) plus a structured
/// `details` payload for automation.
#[derive(Debug, Clone, PartialEq)]
pub struct OpError {
    /// Shared error vocabulary code.
    pub code: ErrorCode,
    /// Human-readable explanation. Automation must not parse this.
    pub message: String,
    /// Whether retrying the same request might succeed.
    pub retryable: bool,
    /// Structured, machine-readable detail payload. `Value::Null` when
    /// there is nothing to add beyond `code`/`message`.
    pub details: serde_json::Value,
}

impl OpError {
    /// Construct an [`OpError`] with `retryable` defaulted from
    /// [`ErrorCode::default_retryable`] and empty `details`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let retryable = code.default_retryable();
        Self {
            code,
            message: message.into(),
            retryable,
            details: serde_json::Value::Null,
        }
    }

    /// Override the default retryability.
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Attach a structured `details` payload.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl From<ErrorCode> for OpError {
    /// Build an [`OpError`] whose message is just the code's own display
    /// string. Callers that have a better message should use
    /// [`OpError::new`] instead; this exists for quick propagation of a
    /// bare code (e.g. from a lower layer that only has the code).
    fn from(code: ErrorCode) -> Self {
        let message = code.to_string();
        OpError::new(code, message)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for OpError {}

/// The `version.get` operation.
pub struct VersionOp;

impl Operation for VersionOp {
    const COMMAND: &'static str = "version.get";
}

/// The `identity.init` operation (`qsh init`).
pub struct IdentityInitOp;

impl Operation for IdentityInitOp {
    const COMMAND: &'static str = "identity.init";
}

/// The `trust.add` operation.
pub struct TrustAddOp;

impl Operation for TrustAddOp {
    const COMMAND: &'static str = "trust.add";
}

/// The `trust.list` operation.
pub struct TrustListOp;

impl Operation for TrustListOp {
    const COMMAND: &'static str = "trust.list";
}

/// The `trust.remove` operation.
pub struct TrustRemoveOp;

impl Operation for TrustRemoveOp {
    const COMMAND: &'static str = "trust.remove";
}

/// Façade over every typed operation. This is the *only* entry point
/// frontends (`qsh-cli`'s human/JSON renderers, and later the MCP adapter)
/// are allowed to call into `qsh-core` through.
///
/// One `Ops` is bound to one pair of config/state directories, so a test —
/// or a `QSH_CONFIG_DIR` override — redirects the whole tree at once.
#[derive(Debug, Clone)]
pub struct Ops {
    paths: Paths,
}

impl Ops {
    /// Bind operations to explicit directories.
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Bind operations to the directories resolved from the environment
    /// ([`Paths::from_env`]).
    pub fn from_env() -> Result<Self, OpError> {
        Ok(Self::new(Paths::from_env()?))
    }

    /// The config/state directories these operations act on.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Load `config.toml` (missing = defaults).
    pub fn config(&self) -> Result<Config, OpError> {
        Config::load(&self.paths)
    }

    /// Report this build's version and the wire/CLI schemas it understands.
    pub fn version(&self) -> Result<VersionData, OpError> {
        Ok(VersionData {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schemas: vec!["qsh.cli/v1".to_string(), "qsh.event/v1".to_string()],
        })
    }

    // -----------------------------------------------------------------
    // identity
    // -----------------------------------------------------------------

    /// `identity.init` — create this device's identity if it does not exist
    /// (idempotent: an existing identity comes back with `created: false`).
    ///
    /// Key-store selection: the request wins over `config.toml`
    /// `[identity].key_store`, which wins over `auto`.
    pub fn identity_init(&self, req: IdentityInitReq) -> Result<IdentityInitData, OpError> {
        let mode = match req.key_store {
            Some(mode) => mode,
            None => self
                .config()?
                .identity
                .key_store
                .unwrap_or(KeyStoreMode::Auto),
        };
        crate::identity::init(&self.paths, mode)
    }

    /// This device's identity plus its private key, or `None` before
    /// `qsh init`.
    ///
    /// **Runtime caveat:** with a platform key store this blocks on the OS
    /// credential store — call it outside a tokio runtime, or from
    /// `spawn_blocking` (see [`crate::identity::load`]).
    pub fn load_identity(&self) -> Result<Option<LoadedIdentity>, OpError> {
        crate::identity::load(&self.paths)
    }

    /// The shared, reload-on-change trust store to inject into the
    /// transport as a [`qsh_transport::TrustEvaluator`].
    pub fn open_trust(&self) -> Result<Arc<SharedTrustStore>, OpError> {
        SharedTrustStore::open(self.paths.trust_file())
    }

    // -----------------------------------------------------------------
    // trust
    // -----------------------------------------------------------------

    /// `trust.add` — pin a peer.
    ///
    /// With `--fingerprint` the peer is pinned **without connecting**
    /// (provisioning-friendly, `docs/CLI.md` §6.11). Without one, the peer
    /// is dialed once to observe its fingerprint and the result is always a
    /// `TRUST_REQUIRED` error carrying `details.observed_fingerprint` and
    /// `details.address`: the caller (human prompt or automation) verifies
    /// that value out of band and re-calls with `--fingerprint`. Nothing is
    /// ever pinned on the strength of what the network said.
    pub fn trust_add(&self, req: TrustAddReq) -> Result<TrustAddData, OpError> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "peer name must not be empty",
            ));
        }

        let fingerprint = match req.fingerprint.as_deref() {
            Some(text) => text
                .parse::<Fingerprint>()
                .map_err(|err| OpError::new(ErrorCode::InvalidArgument, err.to_string()))?,
            None => {
                let Some(address) = req.address.as_deref() else {
                    return Err(OpError::new(
                        ErrorCode::InvalidArgument,
                        "--address is required to observe a fingerprint",
                    ));
                };
                let observed = self.probe_fingerprint(address)?;
                return Err(OpError::new(
                    ErrorCode::TrustRequired,
                    format!(
                        "peer {address} is not trusted; verify the fingerprint and re-run with \
                         --fingerprint"
                    ),
                )
                .with_retryable(false)
                .with_details(serde_json::json!({
                    "observed_fingerprint": observed.to_string(),
                    "address": address,
                })));
            }
        };

        let path = self.paths.trust_file();
        let mut store = TrustStore::load(&path)?;
        let (peer, created) = store.add_peer(name, req.address, fingerprint, now_rfc3339());
        if created {
            store.save(&path)?;
        }
        Ok(TrustAddData { peer, created })
    }

    /// `trust.list` — every pinned peer, in store order.
    pub fn trust_list(&self) -> Result<TrustListData, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        Ok(TrustListData {
            peers: store.peers().to_vec(),
        })
    }

    /// `trust.remove` — unpin a peer. Removing an unknown name is not an
    /// error (`removed: false`, idempotent).
    pub fn trust_remove(&self, name: &str) -> Result<TrustRemoveData, OpError> {
        let path = self.paths.trust_file();
        let mut store = TrustStore::load(&path)?;
        let removed = store.remove(name);
        if removed {
            store.save(&path)?;
        }
        Ok(TrustRemoveData {
            name: name.to_string(),
            removed,
        })
    }

    /// Resolve `host` (a trust-store peer name) to a dial target: loads the
    /// identity (`CONFIG_ERROR` before `qsh init`) and requires the peer to
    /// be pinned with an address (`HOST_NOT_FOUND` otherwise). Until the
    /// hosts directory lands (M7) the trust store is the host directory.
    ///
    /// **Runtime caveat:** loads the identity synchronously — call it
    /// outside a tokio runtime (see [`Ops::load_identity`]).
    pub(crate) fn resolve_peer(&self, host: &str) -> Result<PeerTarget, OpError> {
        let identity = self.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::ConfigError,
                "no device identity; run `qsh init` first",
            )
        })?;
        let trust = self.open_trust()?;
        let peer = trust.snapshot().find(host).cloned().ok_or_else(|| {
            OpError::new(
                ErrorCode::HostNotFound,
                format!(
                    "host {host:?} is not in the trust store; pin it with `qsh trust add {host} --address <host:port> --fingerprint sha256:...`"
                ),
            )
        })?;
        if peer.address.is_empty() {
            return Err(OpError::new(
                ErrorCode::HostNotFound,
                format!("host {host:?} has no address recorded in the trust store"),
            ));
        }
        let server_name = server_name_for(&peer.address);
        Ok(PeerTarget {
            identity,
            trust,
            address: peer.address,
            server_name,
        })
    }

    /// Dial `address` once with an empty trust store and report the
    /// fingerprint the peer presented.
    ///
    /// Because nothing is trusted, the handshake always ends in a local
    /// rejection — the observation is the *point* of the dial, and no
    /// usable connection is ever established. Used by `trust.add` and by
    /// the CLI's interactive pin prompt.
    pub fn probe_fingerprint(&self, address: &str) -> Result<Fingerprint, OpError> {
        // Load the identity *before* entering the runtime: a platform key
        // store blocks on the OS credential service.
        let Some(loaded) = self.load_identity()? else {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "no device identity in {}; run qsh init first",
                    self.paths.config_dir.display()
                ),
            )
            .with_retryable(false));
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("failed to start an async runtime: {err}"),
                )
                .with_retryable(false)
            })?;

        let dialer = Dialer::new(loaded.local, Arc::new(StaticTrust::empty()))
            .with_timeout(PROBE_DIAL_TIMEOUT);
        let server_name = server_name_for(address);

        runtime.block_on(async move {
            let socket = resolve_one(address).await?;
            match dialer.dial(socket, &server_name).await {
                // Unreachable in practice (an empty trust store rejects
                // every peer), but never leave a connection open.
                Ok(dialed) => {
                    let observed = dialed.observation().and_then(|o| o.fingerprint);
                    dialed.connection.close(0, b"probe");
                    observed.ok_or_else(|| {
                        OpError::new(
                            ErrorCode::Internal,
                            "peer accepted by an empty trust store".to_string(),
                        )
                        .with_retryable(false)
                    })
                }
                // The expected outcome: our (empty) trust store rejected
                // the peer, and the verifier recorded what it presented.
                Err(DialError::LocalRejected {
                    observed: Some(fingerprint),
                    ..
                }) => Ok(fingerprint),
                Err(err) => Err(classify_probe_failure(err, address)),
            }
        })
    }
}

/// Resolve `host:port` to its first socket address.
async fn resolve_one(address: &str) -> Result<SocketAddr, OpError> {
    let mut addrs = tokio::net::lookup_host(address).await.map_err(|err| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            format!("failed to resolve {address}: {err}"),
        )
    })?;
    addrs.next().ok_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            format!("{address} resolved to no addresses"),
        )
    })
}

/// SNI value for a dial. The verifier ignores it entirely
/// (`docs/design/protocol.md` §3), so this only needs to be a name rustls
/// will accept; the host part of the address is the most useful one for
/// packet captures.
fn server_name_for(address: &str) -> String {
    let host = match address.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => address,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        "qsh".to_string()
    } else {
        host.to_string()
    }
}

/// Turn a failed probe dial into the error the ops layer promises.
///
/// A *local* rejection with an observed fingerprint is the success case for
/// a probe and is handled by the caller; everything else is a genuine
/// failure. `AUTH_FAILED` details carry only a category — never a reason
/// that could leak trust-store contents (`docs/CLI.md` §6.11).
fn classify_probe_failure(err: DialError, address: &str) -> OpError {
    match err {
        DialError::LocalRejected {
            observed: Some(fingerprint),
            ..
        } => OpError::new(
            ErrorCode::TrustRequired,
            format!("peer {address} is not trusted"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({
            "observed_fingerprint": fingerprint.to_string(),
            "address": address,
        })),
        DialError::LocalRejected { observed: None, .. } => OpError::new(
            ErrorCode::AuthFailed,
            format!("could not read {address}'s certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "unverifiable_certificate"})),
        DialError::RemoteRejected => OpError::new(
            ErrorCode::AuthFailed,
            format!("{address} rejected this device's certificate"),
        )
        .with_retryable(false)
        .with_details(serde_json::json!({"category": "remote_rejected"})),
        DialError::Timeout(after) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("no response from {address} after {after:?}"),
        ),
        DialError::Connect(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot dial {address}: {err}"),
        ),
        DialError::Failed(err) => OpError::new(
            ErrorCode::ConnectionFailed,
            format!("connection to {address} failed: {err}"),
        ),
        DialError::Setup(err) => OpError::new(
            ErrorCode::Internal,
            format!("failed to build a client endpoint: {err}"),
        )
        .with_retryable(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_proto::KeyStoreKind;

    fn temp_ops() -> (tempfile::TempDir, Ops) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
        (dir, Ops::new(paths))
    }

    fn file_mode() -> IdentityInitReq {
        IdentityInitReq {
            key_store: Some(KeyStoreMode::File),
        }
    }

    #[test]
    fn version_reports_schemas_and_own_version() {
        let (_guard, ops) = temp_ops();
        let data = ops.version().unwrap();
        assert_eq!(data.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(data.schemas, vec!["qsh.cli/v1", "qsh.event/v1"]);
    }

    #[test]
    fn op_error_from_code_defaults_retryable() {
        let err = OpError::from(ErrorCode::Timeout);
        assert!(err.retryable);
        assert_eq!(err.code, ErrorCode::Timeout);
    }

    #[test]
    fn operation_commands_are_dotted_form() {
        assert_eq!(VersionOp::COMMAND, "version.get");
        assert_eq!(IdentityInitOp::COMMAND, "identity.init");
        assert_eq!(TrustAddOp::COMMAND, "trust.add");
        assert_eq!(TrustListOp::COMMAND, "trust.list");
        assert_eq!(TrustRemoveOp::COMMAND, "trust.remove");
    }

    #[test]
    fn identity_init_is_idempotent() {
        let (_guard, ops) = temp_ops();
        let first = ops.identity_init(file_mode()).unwrap();
        assert!(first.created);
        let second = ops.identity_init(file_mode()).unwrap();
        assert!(!second.created);
        assert_eq!(second.device_id, first.device_id);
    }

    #[test]
    fn identity_init_takes_the_key_store_from_config_when_unset() {
        let (_guard, ops) = temp_ops();
        crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
        std::fs::write(
            ops.paths().config_file(),
            "[identity]\nkey_store = \"file\"\n",
        )
        .unwrap();
        let data = ops
            .identity_init(IdentityInitReq { key_store: None })
            .unwrap();
        assert_eq!(data.key_store, KeyStoreKind::File);
    }

    #[test]
    fn trust_add_list_remove_round_trip() {
        let (_guard, ops) = temp_ops();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();

        let added = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("mac.example:4433".into()),
                fingerprint: Some(fingerprint.clone()),
            })
            .unwrap();
        assert!(added.created);
        assert_eq!(added.peer.fingerprint, fingerprint);

        let again = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: Some("other:1".into()),
                fingerprint: Some(fingerprint.clone()),
            })
            .unwrap();
        assert!(!again.created);
        assert_eq!(again.peer, added.peer);

        let listed = ops.trust_list().unwrap();
        assert_eq!(listed.peers, vec![added.peer.clone()]);

        let removed = ops.trust_remove("mac").unwrap();
        assert!(removed.removed);
        assert_eq!(removed.name, "mac");
        let removed_again = ops.trust_remove("mac").unwrap();
        assert!(!removed_again.removed);
        assert!(ops.trust_list().unwrap().peers.is_empty());
    }

    #[test]
    fn trust_add_rejects_bad_input() {
        let (_guard, ops) = temp_ops();

        let err = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: None,
                fingerprint: Some("not-a-fingerprint".into()),
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let err = ops
            .trust_add(TrustAddReq {
                name: "  ".into(),
                address: None,
                fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"x").to_string()),
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let err = ops
            .trust_add(TrustAddReq {
                name: "mac".into(),
                address: None,
                fingerprint: None,
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(err.message.contains("--address"), "{err}");
    }

    #[test]
    fn probing_without_an_identity_asks_for_init_first() {
        let (_guard, ops) = temp_ops();
        let err = ops.probe_fingerprint("127.0.0.1:9").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigError);
        assert!(err.message.contains("qsh init"), "{err}");
    }

    #[test]
    fn open_trust_serves_pins_as_device_principals() {
        let (_guard, ops) = temp_ops();
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer");
        ops.trust_add(TrustAddReq {
            name: "mac".into(),
            address: None,
            fingerprint: Some(fingerprint.to_string()),
        })
        .unwrap();

        let evaluator = ops.open_trust().unwrap();
        assert_eq!(
            qsh_transport::TrustEvaluator::lookup_pin(evaluator.as_ref(), &fingerprint),
            Some(qsh_transport::Principal::Device("mac".into()))
        );
    }

    #[test]
    fn server_name_strips_the_port_and_brackets() {
        assert_eq!(server_name_for("example.com:4433"), "example.com");
        assert_eq!(server_name_for("127.0.0.1:4433"), "127.0.0.1");
        assert_eq!(server_name_for("[::1]:4433"), "::1");
        assert_eq!(server_name_for("example.com"), "example.com");
        assert_eq!(server_name_for(":4433"), "qsh");
    }
}
