//! The relay route of a registration (`docs/CLI.md` §6.13, ADR-0061): a
//! `qsh serve --to <controller>` whose controller pin has `routes = ["iroh"]`
//! and a recorded `key` can register over the iroh relay when the controller
//! has no address, or when its address does not answer.
//!
//! The order is the forward route's: a controller with an address is dialed
//! directly first and the relay starts beside it after `[iroh].head_start_ms`
//! (or at once when the direct dial fails sooner); a controller with no
//! address goes over the relay at once. The first connection that stands is
//! the registration connection, and the handshake that follows is the same
//! whichever path carried it. Route memory (`route-cache.json`) is a
//! forward-route state and is not read or written here.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use qsh_proto::ErrorCode;
use qsh_transport::{BoundTrust, CertificateDer, LocalIdentity, TrustEvaluator};
use tokio::time::{Instant, sleep};

use super::ReconnectCause;
use crate::config::Config;
use crate::iroh_settings::{IrohPlan, IrohSettings, IrohTarget};
use crate::ops::OpError;
use crate::ops::route::{Routed, attach_iroh, dial_iroh};
use crate::trust::SharedTrustStore;

/// What a registration needs to take the relay route: this device's identity
/// and the validated `[iroh]` settings. Holds no socket.
pub(super) struct RelayRoute {
    identity: LocalIdentity,
    settings: IrohSettings,
}

impl RelayRoute {
    /// The route `config` allows, or `None` when `[iroh].mode = "off"` or the
    /// section does not validate (fail closed: no relay contact).
    /// `relay_roots` is the test seam for an in-process relay; production
    /// passes none and the OS store judges the relay's certificate.
    /// `client_bind` is the same kind of seam for the endpoint's sockets.
    pub(super) fn new(
        config: &Config,
        identity: LocalIdentity,
        relay_roots: &[CertificateDer],
        client_bind: &[std::net::SocketAddr],
    ) -> Option<Self> {
        let settings = config
            .iroh
            .settings()
            .ok()?
            .with_relay_roots(relay_roots.to_vec())
            .with_client_bind(client_bind.to_vec());
        settings
            .route_enabled()
            .then_some(Self { identity, settings })
    }

    /// The plan for dialing `controller` by key, or `None` when its pin does
    /// not ask for the relay route or has no key yet. Reads the trust store as
    /// it is now, so an operator's `qsh trust add` is seen on the next dial.
    pub(super) fn plan_for(
        &self,
        trust: &Arc<SharedTrustStore>,
        controller: &str,
    ) -> Result<Option<IrohPlan>, OpError> {
        let store = trust.snapshot();
        let Some(pin) = store.find(crate::ops::host::lookup_name(controller)) else {
            return Ok(None);
        };
        let Some(target) = IrohTarget::for_pin(&self.settings, pin) else {
            return Ok(None);
        };
        let binding = crate::ops::peer_binding(&store, controller)?;
        let evaluator: Arc<dyn TrustEvaluator> = Arc::new(BoundTrust::new(
            trust.clone() as Arc<dyn TrustEvaluator>,
            binding,
        ));
        Ok(Some(IrohPlan {
            name: pin.name.clone(),
            target,
            identity: self.identity.clone(),
            evaluator,
            memory: None,
        }))
    }
}

/// The vocabulary cause of a failed relay dial (`ReconnectCause`'s nine
/// values have no relay value; the detail rides in the log line's error).
pub(super) fn cause_of(err: &OpError) -> ReconnectCause {
    match err.code {
        ErrorCode::AuthFailed => ReconnectCause::TlsRejected,
        ErrorCode::Timeout => ReconnectCause::DialTimeout,
        ErrorCode::Internal | ErrorCode::ConfigError => ReconnectCause::Local,
        _ => ReconnectCause::Refused,
    }
}

type Failure = (OpError, ReconnectCause);

type Boxed<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send>>;

/// The relay route alone, for a controller with no address.
pub(super) async fn dial_only(plan: &IrohPlan) -> Result<Routed, Failure> {
    let plan = Arc::new(plan.clone());
    let deadline = Instant::now() + qsh_transport::default_dial_timeout();
    dial_iroh(&plan, deadline)
        .await
        .map_err(|op| (op.clone(), cause_of(&op)))
}

/// The direct dial with the relay beside it: the relay starts after the head
/// start, or when the direct dial has failed. The first connection that stands
/// wins and the other is dropped.
pub(super) async fn race(
    direct: impl Future<Output = Result<Routed, Failure>>,
    plan: &IrohPlan,
) -> Result<Routed, Failure> {
    let plan = Arc::new(plan.clone());
    let deadline = Instant::now() + qsh_transport::default_dial_timeout();
    tokio::pin!(direct);
    let head = sleep(head_start(&plan));
    tokio::pin!(head);
    let mut relay: Option<Boxed<Result<Routed, OpError>>> = None;
    let mut relay_started = false;
    let mut direct_failed: Option<Failure> = None;
    let mut relay_failed: Option<OpError> = None;
    loop {
        if direct_failed.is_some() && relay_failed.is_some() {
            break;
        }
        tokio::select! {
            biased;
            r = &mut direct, if direct_failed.is_none() => match r {
                Ok(routed) => return Ok(routed),
                Err(fail) => {
                    direct_failed = Some(fail);
                    if !relay_started {
                        relay_started = true;
                        relay = Some(Box::pin(relay_dial(plan.clone(), deadline)));
                    }
                }
            },
            r = within(&mut relay) => match r {
                Ok(routed) => return Ok(routed),
                Err(op) => {
                    relay = None;
                    relay_failed = Some(op);
                }
            },
            () = &mut head, if !relay_started => {
                relay_started = true;
                relay = Some(Box::pin(relay_dial(plan.clone(), deadline)));
            }
        }
    }
    let (op, cause) = direct_failed.expect("both routes failed");
    let relay_op = relay_failed.expect("both routes failed");
    // The relay reached the controller and it refused us: that is the better
    // answer than an address that does not answer.
    if relay_op.code == ErrorCode::AuthFailed && op.code != ErrorCode::AuthFailed {
        let cause = cause_of(&relay_op);
        return Err((relay_op, cause));
    }
    Err((attach_iroh(op, &relay_op), cause))
}

fn head_start(plan: &IrohPlan) -> Duration {
    plan.head_start()
}

async fn relay_dial(plan: Arc<IrohPlan>, deadline: Instant) -> Result<Routed, OpError> {
    dial_iroh(&plan, deadline).await
}

async fn within<T>(slot: &mut Option<Boxed<T>>) -> T {
    match slot {
        Some(fut) => fut.await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LoadedIdentity;
    use crate::trust::TrustStore;
    use crate::trust::iroh_pin::{IrohPinChange, key_to_hex};

    fn identity_in(dir: &std::path::Path) -> LoadedIdentity {
        let paths = crate::config::Paths::new(dir.join("config"), dir.join("state"))
            .with_runtime_dir(dir.join("run"));
        crate::identity::init(&paths, qsh_proto::KeyStoreMode::File).expect("identity.init");
        crate::identity::load(&paths)
            .expect("load")
            .expect("an identity")
    }

    /// A trust store pinning `peer` as `ctl`, with `change` applied.
    fn pinned(
        peer: &LoadedIdentity,
        change: Option<IrohPinChange>,
    ) -> (tempfile::TempDir, Arc<SharedTrustStore>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trust.toml");
        let mut store = TrustStore::default();
        store.add_peer(
            "ctl",
            None,
            peer.identity.fingerprint,
            "2026-01-01T00:00:00Z".to_string(),
        );
        if let Some(change) = change {
            store.set_iroh("ctl", &change).expect("set_iroh");
        }
        store.save(&path).expect("save");
        let trust = SharedTrustStore::open(path).expect("open");
        (dir, trust)
    }

    #[test]
    fn a_pin_with_routes_and_a_key_gets_a_plan_and_one_without_a_key_does_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let me = identity_in(&dir.path().join("me"));
        let ctl = identity_in(&dir.path().join("ctl"));
        let key = ctl.local.iroh_public_key().expect("ed25519");
        let route =
            RelayRoute::new(&Config::default(), me.local.clone(), &[], &[]).expect("mode auto");
        assert_eq!(key_to_hex(&key).len(), 64);

        let with_key = IrohPinChange {
            off: false,
            relay: None,
            key: Some(key),
        };
        let (_d, trust) = pinned(&ctl, Some(with_key));
        let plan = route
            .plan_for(&trust, "ctl")
            .expect("no error")
            .expect("a plan");
        assert_eq!(plan.name, "ctl");
        assert!(
            plan.memory.is_none(),
            "route memory is a forward-route state"
        );

        // routes has iroh but no key yet: not dialed.
        let no_key = IrohPinChange {
            off: false,
            relay: None,
            key: None,
        };
        let (_d, trust) = pinned(&ctl, Some(no_key));
        assert!(route.plan_for(&trust, "ctl").expect("no error").is_none());

        // No routes at all, and a name that is not pinned.
        let (_d, trust) = pinned(&ctl, None);
        assert!(route.plan_for(&trust, "ctl").expect("no error").is_none());
        assert!(route.plan_for(&trust, "other").expect("no error").is_none());
    }

    #[test]
    fn mode_off_and_a_bad_section_keep_the_route_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let me = identity_in(dir.path());
        let mut config = Config::default();
        config.iroh.mode = Some(crate::iroh_settings::IrohMode::Off);
        assert!(RelayRoute::new(&config, me.local.clone(), &[], &[]).is_none());
        let mut config = Config::default();
        config.iroh.relay_url = Some("http://not-https".into());
        assert!(RelayRoute::new(&config, me.local.clone(), &[], &[]).is_none());
    }

    #[test]
    fn a_failed_relay_dial_has_a_cause_from_its_code() {
        let cause = |code| cause_of(&OpError::new(code, "x"));
        assert_eq!(cause(ErrorCode::AuthFailed), ReconnectCause::TlsRejected);
        assert_eq!(cause(ErrorCode::Timeout), ReconnectCause::DialTimeout);
        assert_eq!(cause(ErrorCode::ConfigError), ReconnectCause::Local);
        assert_eq!(cause(ErrorCode::ConnectionFailed), ReconnectCause::Refused);
    }
}
