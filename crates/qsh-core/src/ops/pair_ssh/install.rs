//! The install step of `pair.ssh` (ADR-0051 decision 3): when the responder
//! call ends `remote_qsh_missing` or `remote_qsh_too_old`, decide whether to
//! put this machine's `qsh` on the remote, do it, and let the caller run the
//! responder again by the installed absolute path.
//!
//! The decision and the transfer live in `ssh_bootstrap::install`; this is
//! the part that knows the `Plan` and the environment a frontend gave.

use qsh_proto::PairSshInstalled;

use super::*;
use crate::ssh_bootstrap::install::{
    InstallCtx, InstallReason, ReleaseSource, consent, install_remote, release_tag,
};

/// An install that went through.
pub(super) struct Done {
    pub installed: PairSshInstalled,
    pub notices: Vec<String>,
}

/// `Ok(None)` when `err` is not one an install fixes, or the person (or the
/// absence of a terminal) said no: the caller returns `err` as it always
/// did. `Err` is a failed install, a plain `remote_install_failed` or
/// `remote_arch_unsupported` error.
pub(super) async fn offer_install(
    plan: &Plan,
    env: &PairSshEnv,
    err: &OpError,
) -> Result<Option<Done>, OpError> {
    let Some(reason) = InstallReason::of(err) else {
        return Ok(None);
    };
    let tag = release_tag();
    let host = plan.dest.host();
    if !consent(
        env.install_remote,
        env.prompter.as_ref(),
        reason,
        host,
        &tag,
    ) {
        return Ok(None);
    }
    let source = ReleaseSource::from_env()?;
    let ctx = InstallCtx {
        runner: &plan.runner,
        dest: &plan.dest,
        ssh: &plan.ssh,
        batch: plan.batch,
        cancel: &env.cancel,
        source: &source,
        tag: &tag,
    };
    let outcome = install_remote(&ctx, reason == InstallReason::TooOld).await?;
    Ok(Some(Done {
        installed: outcome.installed,
        notices: outcome.notices,
    }))
}
