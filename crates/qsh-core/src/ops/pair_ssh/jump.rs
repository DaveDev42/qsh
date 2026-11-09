//! The bootstrap and `ProxyJump` (ADR-0056 decision 21, amending ADR-0044
//! decision 6).
//!
//! When ssh reached the remote through a `ProxyJump` (or the command line
//! gave `-J`), the QUIC path can go through the same hops if every hop is a
//! qsh pin. This turns the hops into pins, one at a time, and the caller
//! writes the list as the remote's `jump`. Any hop that cannot become a pin
//! leaves the bootstrap as it was: no `jump`, a direct QUIC dial, and the
//! `ssh_proxied` warning.

use super::*;
use crate::ssh_bootstrap::{JumpHop, JumpSpec};

/// How deep a hop's own `ProxyJump` may nest before the bootstrap stops
/// following it (the hop limit of a chain, `MAX_JUMP_HOPS`).
const MAX_NESTING: u8 = crate::jump::MAX_JUMP_HOPS as u8;

/// What the bootstrap made of the remote's jump hops.
#[derive(Debug, Default)]
pub(super) struct JumpBootstrap {
    /// The pin names to write as the remote's `jump`. Empty: write nothing.
    pub names: Vec<String>,
    /// Human-mode stderr lines about the hops: installs and questions the
    /// hops' own bootstraps made, and which hop stopped the chain.
    pub notices: Vec<String>,
}

impl JumpBootstrap {
    fn fallback(notices: Vec<String>, why: String) -> Self {
        let mut notices = notices;
        notices.push(why);
        Self {
            names: Vec::new(),
            notices,
        }
    }
}

impl Ops {
    /// Make a qsh pin of every hop of the remote's `ProxyJump`, bootstrapping
    /// the ones that have none (each with the hops in front of it as ssh's
    /// `-J`, and with the install and replace questions of ADR-0051 as for
    /// the remote itself). Only a cancel is an error; a hop that cannot be
    /// made a pin ends in [`JumpBootstrap::fallback`].
    pub(super) fn bootstrap_jump(
        &self,
        plan: &Plan,
        env: &PairSshEnv,
        resolved: &SshResolved,
    ) -> Result<JumpBootstrap, OpError> {
        if plan.is_reverse() {
            return Ok(JumpBootstrap::default());
        }
        let spec = match env.ssh.jump_spec() {
            Some(JumpSpec::Off) => return Ok(JumpBootstrap::default()),
            Some(spec) => spec.clone(),
            None => match resolved.proxy_jump.as_deref() {
                None => return Ok(JumpBootstrap::default()),
                Some(text) => match JumpSpec::parse(text) {
                    Ok(spec) => spec,
                    Err(_) => {
                        return Ok(JumpBootstrap::fallback(
                            Vec::new(),
                            "ssh reaches this host through a ProxyJump qsh cannot read as pin \
                             names, so it is dialed directly"
                                .to_string(),
                        ));
                    }
                },
            },
        };
        let JumpSpec::Hops(hops) = spec else {
            return Ok(JumpBootstrap::default());
        };
        let names: Vec<&str> = hops.iter().map(|h| h.name.as_str()).collect();
        if let Err(err) = crate::jump::chain::check_shape(&names, &plan.pin_name) {
            return Ok(JumpBootstrap::fallback(
                Vec::new(),
                format!("{}; the host is dialed directly", err.message),
            ));
        }
        if env.jump_depth >= MAX_NESTING {
            return Ok(JumpBootstrap::fallback(
                Vec::new(),
                "the ProxyJump of a jump hop nests too deep, so the host is dialed directly"
                    .to_string(),
            ));
        }

        let mut notices = Vec::new();
        for (index, hop) in hops.iter().enumerate() {
            let known = TrustStore::load(&self.paths.trust_file())?
                .find(&hop.name)
                .map(|pin| !pin.address.is_empty());
            match known {
                Some(true) => continue,
                Some(false) => {
                    return Ok(JumpBootstrap::fallback(
                        notices,
                        format!(
                            "the pin {:?} has no address, so {} is dialed directly; set one with \
                             qsh trust add",
                            hop.name, plan.pin_name
                        ),
                    ));
                }
                None => {}
            }
            match self.bootstrap_hop(env, &hops[..index], hop) {
                Ok(done) => notices.extend(done),
                Err(err) if err.code == ErrorCode::Canceled => return Err(err),
                Err(err) => {
                    return Ok(JumpBootstrap::fallback(
                        notices,
                        format!(
                            "could not make {:?} a qsh pin ({}); {} is dialed directly",
                            hop.name,
                            sanitize_remote_text(&err.message, 200),
                            plan.pin_name
                        ),
                    ));
                }
            }
        }
        Ok(JumpBootstrap {
            names: hops.into_iter().map(|h| h.name).collect(),
            notices,
        })
    }

    /// One hop's own `pair.ssh`: the hops before it are its ssh `-J`, no
    /// confirming dial is made, and a serve that is not listening is a
    /// failure (a chain cannot go through it).
    fn bootstrap_hop(
        &self,
        env: &PairSshEnv,
        before: &[JumpHop],
        hop: &JumpHop,
    ) -> Result<Vec<String>, OpError> {
        let hop_env = PairSshEnv {
            ssh: env.ssh.for_jump_hop(before, hop.port),
            jump_depth: env.jump_depth + 1,
            ..env.clone()
        };
        let req = PairSshReq {
            dest: hop.ssh_dest.clone(),
            as_name: None,
            remote_as: None,
            role: None,
            address: None,
            reverse: false,
            to: None,
            remote_qsh: None,
            replace_pin: false,
        };
        let output = self.pair_ssh_with(req, hop_env, Confirmation::Deferred)?;
        if let Some(failure) = output.data.verify_error {
            return Err(OpError {
                code: failure.code,
                message: failure.message,
                retryable: failure.retryable,
                details: failure.details,
            });
        }
        Ok(output.notices)
    }

    /// Write `names` as the `jump` of the pin `name` and return the pin.
    pub(super) fn write_pin_jump(
        &self,
        name: &str,
        names: &[String],
    ) -> Result<TrustPeer, OpError> {
        let path = self.paths.trust_file();
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let (peer, changed) = store.set_jump(name, names.to_vec()).map_err(|_| {
            OpError::new(
                ErrorCode::HostNotFound,
                format!("{name:?} is not a pinned peer"),
            )
        })?;
        if changed {
            store.save(&path)?;
        }
        Ok(peer)
    }

    /// The confirming dial (ADR-0044 decision 13) for a remote with a jump:
    /// the chain the pin now names, ending in a handshake with the remote's
    /// pin. No session is opened.
    pub(super) fn confirm_dial_chain(
        &self,
        runtime: &SharedRuntime,
        name: &str,
        cancel: &CancelToken,
    ) -> Result<(), OpError> {
        let target = self.resolve_peer(name)?;
        runtime.block_on(async {
            let dial = async {
                let dialed = tokio::time::timeout(
                    CONFIRM_DIAL_TIMEOUT * 2,
                    crate::ops::session::dial_target(&target),
                )
                .await
                .map_err(|_| {
                    OpError::new(
                        ErrorCode::Timeout,
                        format!("the jump chain to {name} did not answer in time"),
                    )
                })??;
                let (endpoint, connection, session) = dialed;
                drop(session);
                connection.close(0, b"verified");
                let _ = tokio::time::timeout(CONFIRM_SETTLE, endpoint.wait_idle()).await;
                Ok(())
            };
            tokio::select! {
                biased;
                () = cancel.canceled() => Err(canceled()),
                outcome = dial => outcome,
            }
        })
    }
}
