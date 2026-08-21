//! `qsh reverse <controller>` — the reverse-mode target (`docs/CLI.md`
//! §6.13, `docs/design/protocol.md` §11-3, `PLAN.md` Step 3, PR 3b).
//! Registers **once** and exits with a diagnostic when the connection
//! dies — the reconnect loop (heartbeat, exponential backoff) is Step 4.
//!
//! [`run_reverse`] resolves `<controller>` as a trust-store alias (the same
//! `Ops::resolve_peer` path `qsh <host>`/`qsh exec` use today — hosts.toml
//! directory lookup is M7), dials it, and runs
//! [`crate::handshake::initiate`] with `Hello{reverse: Some(..)}`. From the
//! wire's point of view this connection is now indistinguishable from one
//! `qsh serve` accepted: on success this process *is* a host on it, reusing
//! [`crate::serve::host_runtime`] (the exact factory `qsh serve` uses, no
//! second broker/audit/authorizer construction — `serve.rs`'s module docs)
//! and running [`crate::server::Server::serve_control`] on the connection
//! `initiate` just negotiated.
//!
//! A rejection from the controller (`PERMISSION_DENIED`/`INVALID_ARGUMENT`/
//! `UNSUPPORTED` — name-squatting shape check, the `host.reverse` choke
//! point, or an unpinned peer) arrives as `HelloError::Remote` from
//! `initiate` and is surfaced verbatim, reusing exactly the mapping
//! `client::Session::negotiate` already applies to the same error
//! ([`crate::client::map_hello_error`] chained into
//! [`crate::ops::exec::map_client_error`]) rather than a second copy of it.

// Most of this import block is consumed only by the unix body (and this
// module's tests) — the Windows `run_reverse` refuses before touching any
// of it, so ungated these would trip `unused_imports` under the Windows
// leg's `clippy -D warnings` (same gating as `tui/mod.rs`).
#[cfg(unix)]
use std::sync::Arc;

#[cfg(any(unix, test))]
use qsh_proto::ErrorCode;
#[cfg(any(unix, test))]
use qsh_proto::wire;
#[cfg(unix)]
use qsh_transport::{Dialer, TrustEvaluator};

#[cfg(unix)]
use crate::broker::PeerFingerprint;
use crate::config::{Config, Paths};
use crate::identity::LoadedIdentity;
use crate::ops::OpError;
#[cfg(unix)]
use crate::server::ConnCtx;
#[cfg(unix)]
use crate::trust::SharedTrustStore;

/// Resolve the offered name: `--offered-name` > `[reverse].offered_name` >
/// this device's `device_id`. There is no separate "device name" concept
/// anywhere in this codebase (`Hello.device_name` and `qsh serve`/`qsh
/// listen`'s own `Hello` both already use `device_id` as their display
/// name) — this fallback matches that.
pub fn resolve_offered_name(flag: Option<&str>, config: &Config, device_id: &str) -> String {
    flag.map(str::to_owned)
        .or_else(|| config.reverse.offered_name.clone())
        .unwrap_or_else(|| device_id.to_string())
}

/// Dial `controller`, register as a reverse target, then serve as a host
/// until the connection dies or `shutdown` resolves.
///
/// `identity` must already be loaded synchronously before entering the
/// runtime, exactly like [`crate::serve::run_serve`]/
/// [`super::listen::run_listen`]. `shutdown` resolving first is a clean
/// exit (`Ok(())`, the connection is closed on our own initiative); the
/// connection dying on its own — cleanly closed by the controller or not —
/// is not (`Err`, `docs/CLI.md` §6.13: `qsh reverse` does not reconnect in
/// this step, so that is fatal to the process).
pub async fn run_reverse(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    controller: &str,
    offered_name_flag: Option<&str>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    // Twin cfg blocks as alternative tail expressions — the exact shape
    // `pty::factory` established; a `return` here instead would trip
    // clippy's `needless_return` on the Windows leg (probed empirically).
    #[cfg(not(unix))]
    {
        let _ = (
            paths,
            config,
            identity,
            controller,
            offered_name_flag,
            shutdown,
        );
        Err(super::listen::windows_unsupported())
    }
    #[cfg(unix)]
    {
        run_reverse_unix(
            paths,
            config,
            identity,
            controller,
            offered_name_flag,
            shutdown,
        )
        .await
    }
}

/// `docs/CLI.md` §6.13's Windows gate (module docs on
/// [`super::listen::windows_unsupported`]) — this is the target's half.
#[cfg(unix)]
async fn run_reverse_unix(
    paths: &Paths,
    config: &Config,
    identity: LoadedIdentity,
    controller: &str,
    offered_name_flag: Option<&str>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), OpError> {
    let device_id = identity.identity.device_id.clone();
    let offered_name = resolve_offered_name(offered_name_flag, config, &device_id);

    let trust = SharedTrustStore::open(paths.trust_file())?;
    let (address, server_name) = crate::ops::resolve_peer_address(&trust.snapshot(), controller)?;
    let addr = crate::ops::resolve_one(&address).await?;

    let dialer = Dialer::new(identity.local, trust as Arc<dyn TrustEvaluator>);
    let dialed = dialer
        .dial(addr, &server_name)
        .await
        .map_err(|err| crate::ops::exec::map_dial_error(err, &address))?;
    // Must outlive the connection (`Dialer::dial`'s own docs).
    let _endpoint = dialed.endpoint;
    let conn = dialed.connection;

    let runtime = crate::serve::host_runtime(paths, config, device_id.clone());
    let local_hello = runtime.server.local_hello(Some(wire::ReverseRegistration {
        offered_name: offered_name.clone(),
        // Empty means "same as Hello.capabilities" (`v1.proto`'s field
        // doc) — this target offers everything its own `Hello` does, so
        // there is nothing narrower to say here.
        capabilities: Vec::new(),
    }));

    let (ctl, peer_hello) = crate::handshake::initiate(&conn, local_hello)
        .await
        .map_err(|err| {
            let op_err = crate::ops::exec::map_client_error(crate::client::map_hello_error(err));
            tracing::warn!(controller, %op_err, "qsh reverse: registration failed");
            op_err
        })?;

    tracing::info!(
        controller,
        offered_name,
        "qsh reverse: registered, serving this connection as a host"
    );

    let ctx = ConnCtx {
        principal: conn.principal().clone(),
        auth_path: conn.auth_path(),
        peer_fingerprint: conn
            .peer_fingerprint()
            .map(|fp| PeerFingerprint::new(*fp.as_bytes())),
        peer_addr: conn.remote_address(),
        conn_id: conn.stable_id(),
        capabilities: crate::handshake::negotiated_capabilities(&peer_hello),
    };

    // KNOWN RACE, deferred to Step 4 (`PLAN.md` M3 Step 3 review — LOW,
    // deliberately not fixed here): two gaps against `server/mod.rs`'s
    // documented discipline (`Server::serve_connection`'s own shape —
    // `serve_connection_inner` to completion, *then*
    // `purge_connection(conn_id).await`, always):
    //   (a) neither arm below ever calls `purge_connection` — a real
    //       `Server::serve_connection` always does, right after
    //       `serve_control` returns, to drop this connection's tickets and
    //       release any writer lease it held.
    //   (b) the `shutdown` arm races `serve_control` in the same `select!`,
    //       so a shutdown mid-flight cancels `serve_control` instead of
    //       letting it reach its own `blocking.shutdown()` join (the exact
    //       ordering `serve_control`'s module docs above call out as *why*
    //       `purge_connection` can safely observe the connection's final
    //       state) — even if this call site did add a `purge_connection`
    //       here, a cancelled `serve_control` would make it race the
    //       parked tasks it never got to join.
    // Acceptable for Step 3: registration is single-shot and this process
    // exits immediately after this `select!` resolves either way (no
    // reconnect loop yet), so the leak is reclaimed by process exit before
    // anything could observe it — there is no second connection on this
    // process for a stale lease to block. Step 4's reconnect loop removes
    // that cover (the process keeps running and re-registers), so Step 4
    // MUST add the join-before-purge ordering `serve_connection` already
    // has, here.
    tokio::pin!(shutdown);
    tokio::select! {
        _ = &mut shutdown => {
            conn.close(0, b"shutdown");
            Ok(())
        }
        result = runtime.server.clone().serve_control(&conn, ctl, ctx) => {
            let detail = match &result {
                Ok(()) => "connection closed".to_string(),
                Err(err) => err.to_string(),
            };
            tracing::warn!(controller, %detail, "qsh reverse: connection to the controller ended");
            Err(OpError::new(
                ErrorCode::ConnectionFailed,
                format!("connection to controller {controller:?} ended: {detail}"),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offered_name_precedence_flag_then_config_then_device_id() {
        let mut config = Config::default();
        assert_eq!(
            resolve_offered_name(None, &config, "device_abc"),
            "device_abc"
        );
        config.reverse.offered_name = Some("configured".into());
        assert_eq!(
            resolve_offered_name(None, &config, "device_abc"),
            "configured"
        );
        assert_eq!(
            resolve_offered_name(Some("flagged"), &config, "device_abc"),
            "flagged"
        );
    }

    // `host_runtime` spawns the broker's TTL reaper (`tokio::spawn`), so
    // this needs a runtime in context — same reason
    // `serve::tests::host_runtime_wires_device_id_and_a_shared_audit_sink`
    // is a `#[tokio::test]` rather than a plain `#[test]`.
    #[tokio::test]
    async fn reverse_hello_carries_only_offered_name_capabilities_empty() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path(), dir.path());
        let runtime = crate::serve::host_runtime(&paths, &Config::default(), "hermes");
        let hello = runtime.server.local_hello(Some(wire::ReverseRegistration {
            offered_name: "phone".into(),
            capabilities: Vec::new(),
        }));
        let reg = hello.reverse.expect("Hello.reverse is Some");
        assert_eq!(reg.offered_name, "phone");
        assert!(
            reg.capabilities.is_empty(),
            "empty means \"same as Hello.capabilities\" (v1.proto)"
        );
    }

    /// `docs/CLI.md` §6.13's Windows gate, mechanically: `run_reverse`
    /// refuses on every non-unix target before it ever touches its
    /// arguments (module docs on [`super::listen::windows_unsupported`]),
    /// so the identity/paths/config below are throwaway. This is the
    /// positive Windows-leg assertion `PLAN.md` Step 3 (d) owes ("Windows
    /// leg의 nextest green … 나머지가 컴파일·통과") — a real `#[tokio::test]`
    /// that runs and passes on the Windows CI leg, not just an absence of
    /// a compile error there.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn run_reverse_is_unsupported_on_non_unix() {
        let identity = LoadedIdentity {
            identity: crate::identity::Identity {
                device_id: "device".into(),
                fingerprint: qsh_transport::Fingerprint::of_spki_der(&[]),
                key_store: qsh_proto::KeyStoreKind::File,
                created_at: "2026-01-01T00:00:00Z".into(),
                cert_der: Vec::new(),
            },
            local: qsh_transport::LocalIdentity {
                cert_chain: Vec::new(),
                key_pkcs8_der: Vec::new(),
            },
        };
        let paths = Paths::new("unused-config", "unused-state");
        let err = run_reverse(
            &paths,
            &Config::default(),
            identity,
            "controller",
            None,
            std::future::pending::<()>(),
        )
        .await
        .expect_err("non-unix must refuse to run");
        assert_eq!(err.code, ErrorCode::Unsupported);
    }
}
