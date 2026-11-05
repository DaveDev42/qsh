//! Reviving the serve of a pin the SSH bootstrap wrote (ADR-0051 decision 4).
//!
//! A pin that `qsh [user@]host` made over ssh points at an on-demand serve,
//! and that serve is gone after its idle limit. When a dial to such a pin
//! fails, the command that was dialing runs the responder conversation again
//! with `ensure_serve`, and dials once more. Nothing in `trust.toml` is
//! created or changed except the pin's address, and only for the same
//! fingerprint: the conversation is verify-only on this side.
//!
//! No question is asked by qsh. ssh keeps whatever prompting its own mode
//! allows (`BatchMode` when the command is a machine mode or stdin is not a
//! terminal, the same rule as the first bootstrap).

use std::io::IsTerminal as _;
use std::sync::Arc;

use qsh_proto::PairSshReq;
use qsh_proto::ssh_bootstrap::{BootstrapLine, Commit};

use super::*;
use crate::config::SshBootstrapMode;
use crate::trust::PIN_SOURCE_SSH_BOOTSTRAP;

/// What a command tells [`Ops`] about how to revive a pin (set by the
/// frontend with [`Ops::with_ssh_revival`]; an `Ops` without one never runs
/// ssh on its own).
#[derive(Clone)]
pub struct SshRevival {
    /// `--json` or `--jsonl`: ssh runs with `BatchMode=yes`.
    pub machine_mode: bool,
    /// The `user@` the person typed, when the command has one. The pin does
    /// not store it (ADR-0044 decision 26).
    pub user: Option<String>,
    /// The root form's ssh options (`-p`, `-i`, `-F`, `-o`, ...), forwarded to
    /// the revival's `ssh -G` and responder call as to the first bootstrap.
    pub ssh: SshOptions,
    /// Where the one-line notices go (the frontend's stderr). Called with
    /// text only; the frontend adds its own prefix and honours `--quiet`.
    pub notice: Arc<dyn Fn(&str) + Send + Sync>,
}

impl std::fmt::Debug for SshRevival {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshRevival")
            .field("machine_mode", &self.machine_mode)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// Whether a failed dial can be a serve that is not running: a refused or
/// silent connection. `udp_egress_blocked` is a network that eats UDP, which
/// starting the serve cannot fix; `CANCELED`, auth and every other code are
/// not about the serve being absent.
pub(crate) fn failure_may_be_a_missing_serve(err: &OpError) -> bool {
    matches!(err.code, ErrorCode::ConnectionFailed | ErrorCode::Timeout)
        && err.details.get("reason").and_then(|v| v.as_str()) != Some("udp_egress_blocked")
}

impl Ops {
    /// Let commands that dial a pin revive its serve over ssh when the dial
    /// fails (ADR-0051 decision 4). Without this an `Ops` never does.
    #[must_use]
    pub fn with_ssh_revival(mut self, revival: SshRevival) -> Self {
        self.revival = Some(Arc::new(revival));
        self
    }

    /// After `cause` ended a dial to `target`: if the address is the pin of an
    /// SSH-bootstrapped host and ssh can restart its serve, do that and
    /// return the target to dial once more (the same, or with the new
    /// address). `None` leaves `cause` as the answer.
    ///
    /// Failure to revive is reported as one notice and is not an error of its
    /// own: the command fails with the dial error it already had.
    ///
    /// **Runtime caveat:** blocks on the shared dial runtime; call it from an
    /// ordinary thread, not from inside a tokio runtime.
    pub(crate) fn revive_target(&self, target: &PeerTarget, cause: &OpError) -> Option<PeerTarget> {
        let revival = self.revival.as_ref()?;
        if !failure_may_be_a_missing_serve(cause) {
            return None;
        }
        if self.config().ok()?.ssh.bootstrap_mode() == SshBootstrapMode::Off {
            return None;
        }
        let store = TrustStore::load(&self.paths.trust_file()).ok()?;
        let normalized = normalize_peer_address(&target.address).address;
        let mut matching = store.find_by_address(&normalized);
        let pin = matching.next()?.clone();
        if matching.next().is_some() || pin.source.as_deref() != Some(PIN_SOURCE_SSH_BOOTSTRAP) {
            return None;
        }
        let dest = match &revival.user {
            Some(user) => format!("{user}@{}", pin.name),
            None => pin.name.clone(),
        };
        (revival.notice)(&format!(
            "{} did not answer; starting its serve over ssh (ssh {dest}); pass --no-ssh to \
             prevent this",
            pin.name
        ));
        match self.run_revival(revival, target, &pin, &dest) {
            Ok(address) => Some(PeerTarget {
                identity: target.identity.clone(),
                trust: target.trust.clone(),
                server_name: server_name_for(&address),
                address,
            }),
            Err(err) => {
                (revival.notice)(&format!(
                    "could not start the serve of {} over ssh: {}",
                    pin.name, err.message
                ));
                None
            }
        }
    }

    /// The conversation: `ssh -G`, the `hello` (its fingerprint must be the
    /// pin's), a `commit` with `ensure_serve`, the `result`. Returns the
    /// address to dial, after updating the pin when it changed.
    fn run_revival(
        &self,
        revival: &SshRevival,
        target: &PeerTarget,
        pin: &TrustPeer,
        dest: &str,
    ) -> Result<String, OpError> {
        let env = PairSshEnv {
            machine_mode: revival.machine_mode,
            stdin_is_terminal: std::io::stdin().is_terminal(),
            cancel: CancelToken::new(),
            ssh: revival.ssh.clone(),
        };
        let plan = self.pair_ssh_plan(
            &PairSshReq {
                dest: dest.to_string(),
                as_name: None,
                remote_as: None,
                role: None,
                address: None,
                reverse: false,
                to: None,
                remote_qsh: None,
            },
            &env,
        )?;
        let identity = &target.identity.identity;
        let runtime = self.connect_runtime()?;
        let (mut child, hello, resolved) = runtime.block_on(exchange_hello(&plan, &env.cancel))?;
        let end = |child: SshChild| {
            runtime.block_on(child.finish());
        };
        let hello = match check_hello(&hello, &plan.dest) {
            Ok(hello) => hello,
            Err(err) => {
                end(child);
                return Err(err);
            }
        };
        // Verify only: whatever answers over ssh must be the host this pin
        // names, or nothing is sent.
        if hello.fingerprint.to_string() != pin.fingerprint {
            end(child);
            return Err(OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "ssh {dest} reached a qsh with another identity than the pin {:?}; the pin \
                     was left as it is",
                    pin.name
                ),
            )
            .with_retryable(false)
            .with_details(json!({ "reason": "pin_conflict", "side": "remote" })));
        }
        if !hello.on_demand {
            end(child);
            return Err(OpError::new(
                ErrorCode::Unsupported,
                "the remote qsh is too old to start a serve; start one there (`qsh serve`)",
            )
            .with_retryable(false));
        }
        let commit = Commit {
            version: hello.version,
            fingerprint: identity.fingerprint.to_string(),
            name: default_remote_name(local_hostname().as_deref(), &identity.device_id),
            role: plan.role.as_str().to_string(),
            address: None,
            ensure_serve: Some(true),
        };
        let result = runtime.block_on(async {
            child.send(&BootstrapLine::Commit(commit)).await?;
            let line = child.recv().await?;
            let BootstrapLine::Result(result) = line else {
                let _ = child.finish().await;
                return Err(protocol_violation(
                    "the remote answered with the wrong message",
                ));
            };
            let _ = child.finish().await;
            Ok(result)
        })?;
        remote_from_result(&result, &pin.name, &identity.fingerprint, dest)?;
        let Some(serve) = ServeInfo::from_result(&result) else {
            let why = result
                .message
                .as_deref()
                .map(|text| sanitize_remote_text(text, 200))
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| "it reported no serve address".to_string());
            return Err(OpError::new(
                ErrorCode::RemoteError,
                format!("the remote could not start its serve: {why}"),
            ));
        };
        let address =
            pin_address(&resolved.hostname, &serve.bind).unwrap_or_else(|| pin.address.clone());
        self.update_pin_address(&pin.name, &pin.fingerprint, &address)?;
        if serve.session_scoped {
            (revival.notice)(&serve_session_scoped_warning(dest));
        }
        Ok(address)
    }

    /// Give the pin `name` a new address, under the `trust.toml` lock, if it
    /// still holds `fingerprint`. A pin that changed or vanished while ssh
    /// ran is left alone (the dial then fails as it did).
    fn update_pin_address(
        &self,
        name: &str,
        fingerprint: &str,
        address: &str,
    ) -> Result<(), OpError> {
        let path = self.paths.trust_file();
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let Some(existing) = store.find(name).cloned() else {
            return Ok(());
        };
        if existing.fingerprint != fingerprint || existing.address == address {
            return Ok(());
        }
        let Ok(remote) = existing.fingerprint.parse::<Fingerprint>() else {
            return Ok(());
        };
        let (_peer, _created, updated) = store.add_peer_with_role(
            name.to_string(),
            Some(address.to_string()),
            remote,
            now_rfc3339(),
            TrustRole::None,
        );
        if updated {
            store.save(&path)?;
        }
        Ok(())
    }
}
