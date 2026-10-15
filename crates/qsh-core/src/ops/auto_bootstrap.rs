//! The automatic bootstrap (ADR-0044 decisions 2, 3, 13, 16): `qsh
//! [user@]host` and `qsh cp` set up the pin over ssh themselves when the name
//! they were given resolves nowhere, then carry on with the original command.
//!
//! This module only decides and runs. The frontend asks
//! [`Ops::should_auto_bootstrap`] (or the `qsh cp` twin) before it resolves
//! anything, prints [`AutoBootstrap::notice`] when the answer is yes, and
//! calls [`Ops::auto_bootstrap`]. The surfaces that never start it (`qsh
//! exec`, `qsh session open`, `qsh tunnel open`, `qsh sessions`) simply do
//! not ask.
//!
//! The bootstrap itself is `pair.ssh` with the default flags
//! (`Ops::pair_ssh_with`), except for the confirmation: the original
//! command's own connection is the confirmation (decision 13), so no second
//! dial is made. A remote whose responder saw nothing on the serve port still
//! ends the call with `CONNECTION_FAILED` (`remote_serve_not_listening`), and
//! the pins stay.
//!
//! The automatic path never picks the reverse direction: the name alone does
//! not say which side dials (decision 22).

use qsh_proto::{FileCopyReq, PairSshReq};

use super::pair_ssh::Confirmation;
use super::*;
use crate::config::SshBootstrapMode;
use crate::ssh_bootstrap::{Dest, auto_bootstrap_notice};

/// A decision to start the bootstrap for one name, from
/// [`Ops::should_auto_bootstrap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoBootstrap {
    dest: String,
    host: String,
}

impl AutoBootstrap {
    /// The `[user@]host` operand ssh receives, as the person typed it.
    pub fn dest(&self) -> &str {
        &self.dest
    }

    /// The name nothing resolved: the host half of [`Self::dest`], and the
    /// name the new pin gets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The one stderr line to write before the bootstrap starts
    /// ([`crate::ssh_bootstrap::AUTO_BOOTSTRAP_NOTICE`]).
    pub fn notice(&self) -> String {
        auto_bootstrap_notice(&self.host, &self.dest)
    }
}

/// How an automatic bootstrap went. The human notices are returned on both
/// outcomes: a run that pinned both sides and then found no serve there has
/// still written, and said so.
#[derive(Debug)]
pub struct AutoBootstrapReport {
    /// Human-mode stderr lines, in order (what `qsh pair ssh` prints).
    pub notices: Vec<String>,
    /// `Ok` when the pins stand and the original command may run.
    pub result: Result<(), OpError>,
}

impl Ops {
    /// Whether `qsh [user@]host` should start the bootstrap before it
    /// connects (ADR-0044 decision 2).
    ///
    /// `Some` only when all of this holds, and nothing is read once one
    /// fails:
    ///
    /// - not a machine mode (`--json`/`--jsonl`);
    /// - the name is wholly unregistered: no `hosts.toml` entry, no pin in
    ///   `trust.toml`, no reverse registration live or stale
    ///   (`docs/CLI.md` §6.1's first `HOST_NOT_FOUND` branch);
    /// - `[ssh].bootstrap` is not `"off"`.
    ///
    /// A name that cannot be an ssh destination or a pin name is not a
    /// trigger either; the original command then reports its usual
    /// `HOST_NOT_FOUND`.
    ///
    /// **Runtime caveat:** like [`Self::resolve_host_route`], not callable
    /// from inside a tokio runtime.
    pub fn should_auto_bootstrap(
        &self,
        host: &str,
        user: Option<&str>,
        machine_mode: bool,
    ) -> Result<Option<AutoBootstrap>, OpError> {
        if machine_mode {
            return Ok(None);
        }
        let dest_text = match user {
            Some(user) => format!("{user}@{host}"),
            None => host.to_string(),
        };
        let Ok(dest) = Dest::parse(&dest_text) else {
            return Ok(None);
        };
        if dest.host() != host || dest.pin_name(None).is_err() {
            return Ok(None);
        }
        if !self.host_is_unconfigured(host) {
            return Ok(None);
        }
        // Read last: a broken `config.toml` is reported only when it would
        // have mattered, and the original command reports it for every name
        // that is registered.
        if self.config()?.ssh.bootstrap_mode() == SshBootstrapMode::Off {
            return Ok(None);
        }
        Ok(Some(AutoBootstrap {
            dest: dest_text,
            host: host.to_string(),
        }))
    }

    /// [`Self::should_auto_bootstrap`] for `qsh cp`: the host and the `user@`
    /// assertion come from the operands. An operand list that names no
    /// remote host, or two, is not a trigger; the copy reports its own
    /// usage error.
    pub fn should_auto_bootstrap_cp(
        &self,
        req: &FileCopyReq,
        machine_mode: bool,
    ) -> Result<Option<AutoBootstrap>, OpError> {
        if machine_mode {
            return Ok(None);
        }
        let Ok(plan) = crate::file::operand::plan(req) else {
            return Ok(None);
        };
        self.should_auto_bootstrap(&plan.host, plan.user.as_deref(), machine_mode)
    }

    /// Run the bootstrap `plan` decided on: `pair.ssh` with the default
    /// flags, forward, no confirming dial (decision 13).
    ///
    /// The caller has written [`AutoBootstrap::notice`] already. `env` is
    /// the same environment `qsh pair ssh` passes; a human run leaves ssh
    /// its terminal, and the caller starts raw mode only after this returns
    /// (decision 16).
    ///
    /// **Runtime caveat:** as for [`Self::pair_ssh`].
    pub fn auto_bootstrap(&self, plan: &AutoBootstrap, env: PairSshEnv) -> AutoBootstrapReport {
        let req = PairSshReq {
            dest: plan.dest.clone(),
            as_name: None,
            remote_as: None,
            role: None,
            address: None,
            reverse: false,
            to: None,
            remote_qsh: None,
        };
        match self.pair_ssh_with(req, env, Confirmation::Deferred) {
            Err(err) => AutoBootstrapReport {
                notices: Vec::new(),
                result: Err(err),
            },
            Ok(output) => {
                let result = match output.data.verify_error {
                    Some(failure) => Err(OpError {
                        code: failure.code,
                        message: failure.message,
                        retryable: failure.retryable,
                        details: failure.details,
                    }),
                    None => Ok(()),
                };
                AutoBootstrapReport {
                    notices: output.notices,
                    result,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
