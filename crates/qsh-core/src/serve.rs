//! `qsh serve` — the long-running host mode (`docs/CLI.md` §6.12). Not an
//! operation: no envelope, foreground only, prints the bound address to
//! stderr via the `on_bound` callback and runs until `shutdown` resolves.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use qsh_proto::ErrorCode;
use qsh_transport::Listener;

use crate::acl::AllowAllPinned;
use crate::audit::FileAuditSink;
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
use crate::ops::OpError;
use crate::server::Server;
use crate::trust::SharedTrustStore;

/// Default listen address when neither `--bind` nor `[serve].bind` is set.
pub const DEFAULT_BIND: &str = "[::]:4433";

/// Resolve the bind address: CLI flag > `config.toml` `[serve].bind` >
/// [`DEFAULT_BIND`]. Accepts `ip:port` or `host:port` (first resolution).
pub fn resolve_bind(flag: Option<&str>, config: &Config) -> Result<SocketAddr, OpError> {
    let spec = flag
        .map(str::to_owned)
        .or_else(|| config.serve.bind.clone())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(addr);
    }
    spec.to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| {
            OpError::new(
                ErrorCode::InvalidArgument,
                format!("invalid bind address {spec:?} (expected ip:port or host:port)"),
            )
        })
}

/// Run the host until `shutdown` resolves.
///
/// `identity` must already be loaded (synchronously, before entering the
/// runtime — see `identity::load`). `on_bound` receives the actual bound
/// address once the listener is up.
pub async fn run_serve(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    bind_flag: Option<&str>,
    on_bound: impl FnOnce(SocketAddr),
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    let bind = resolve_bind(bind_flag, config)?;
    let trust = SharedTrustStore::open(paths.trust_file())?;
    // A bind that cannot be satisfied (port in use, privileged port, no
    // such interface) is a configuration problem on this host, not an
    // internal fault: report it as such so `--bind`/`[serve].bind` is the
    // obvious thing to look at.
    let listener = Listener::bind(bind, identity.local, trust).map_err(|err| {
        OpError::new(
            ErrorCode::ConfigError,
            format!("cannot listen on {bind}: {err}"),
        )
    })?;
    let actual = listener.local_addr().map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("cannot read bound address: {err}"),
        )
    })?;
    on_bound(actual);

    let audit = Arc::new(FileAuditSink::new(paths.audit_log()));
    let server = Server::new(
        Arc::new(AllowAllPinned),
        audit,
        identity.identity.device_id.clone(),
    );
    tracing::info!(
        device_id = %identity.identity.device_id,
        fingerprint = %identity.identity.fingerprint,
        %actual,
        "qsh serve listening"
    );
    server.run(listener, shutdown).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_precedence_flag_then_config_then_default() {
        let mut config = Config::default();
        assert_eq!(
            resolve_bind(None, &config).unwrap(),
            DEFAULT_BIND.parse::<SocketAddr>().unwrap()
        );
        config.serve.bind = Some("127.0.0.1:5000".into());
        assert_eq!(
            resolve_bind(None, &config).unwrap(),
            "127.0.0.1:5000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind(Some("127.0.0.1:6000"), &config).unwrap(),
            "127.0.0.1:6000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind(Some("localhost:7000"), &config)
                .unwrap()
                .port(),
            7000
        );
        let err = resolve_bind(Some("not an address"), &config).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}
