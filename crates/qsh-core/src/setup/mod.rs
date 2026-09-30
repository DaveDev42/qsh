//! `qsh setup`: the planning half of `setup.run` (`docs/CLI.md` §6.20,
//! ADR-0024).
//!
//! `setup.run` creates no capability of its own. It reads state through
//! existing operations, decides which of the fixed steps a role needs and
//! in what order, and calls the operations that already write. This module
//! is under a directory-scoped `cargo xtask arch` ban (`xtask/src/arch.rs`,
//! `SETUP_DIR`) so that it cannot grow its own way to write `acl.toml` or
//! any other file: the only writes are the ones `Ops::identity_init`,
//! `Ops::trust_invite`, `Ops::trust_accept`, `Ops::trust_add`,
//! `Ops::service_install` and `Ops::doctor` already perform, and no code
//! here dials a peer to learn its fingerprint (ADR-0024 결정 3, 6).

use qsh_proto::{SetupRole, SetupStepId};

use crate::ops::Operation;

mod run;

pub use run::SetupEnv;

/// The `setup.run` operation (`qsh setup`, `docs/CLI.md` §6.20).
pub struct SetupRunOp;

impl Operation for SetupRunOp {
    const COMMAND: &'static str = "setup.run";
}

/// The steps `role` runs, in run order (ADR-0024 결정 8).
///
/// `with_cert` says the pin comes from a certificate file (`--peer-cert`)
/// rather than an invite: for `host` it turns the `invite` step into
/// `pin_cert`, for `client` it turns `pair` into `pin_cert`. `host_to` and
/// `listener` always pin from a certificate, so the flag does not change
/// them.
pub fn step_order(role: SetupRole, with_cert: bool) -> Vec<SetupStepId> {
    use SetupStepId::{Acl, Doctor, Identity, Invite, ModeConfig, Pair, PinCert, Service};
    match role {
        SetupRole::Host => vec![
            Identity,
            ModeConfig,
            Acl,
            Service,
            if with_cert { PinCert } else { Invite },
            Doctor,
        ],
        SetupRole::HostTo => vec![Identity, PinCert, ModeConfig, Acl, Service, Doctor],
        SetupRole::Client => vec![Identity, if with_cert { PinCert } else { Pair }, Doctor],
        SetupRole::Listener => vec![Identity, PinCert, ModeConfig, Acl, Service, Doctor],
    }
}

/// `true` for the steps that only read state: `mode_config` and `acl`.
/// They are evaluated even when an earlier step is `pending`, so one run
/// shows everything a person has to fix (ADR-0024 결정 8).
pub fn is_read_only_step(id: SetupStepId) -> bool {
    matches!(id, SetupStepId::ModeConfig | SetupStepId::Acl)
}

#[cfg(test)]
mod tests;
