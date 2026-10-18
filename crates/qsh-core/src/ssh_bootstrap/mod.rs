//! The ssh side of `qsh pair ssh` that does not talk to the remote qsh
//! (ADR-0044).
//!
//! - `dest`: the `<dest>` operand, validated before any ssh process exists
//!   (decision 7).
//! - `ssh`: `ssh -G`, the fixed responder argument list and the quoting of
//!   `<remote_qsh>` (decisions 4, 9), the ssh child with its deadlines,
//!   interrupt handling and exit-status mapping (decisions 14, 16, 25), and
//!   the logging rule that only stages, result codes and counts reach
//!   `tracing` (decision 19).
//! - `respond` (decisions 9, 10, 12): the remote responder behind the
//!   hidden `qsh pair ssh-respond`, on every platform: identity read, the
//!   UDP bind probe, the `hello`, and the locked, audited pin write on
//!   `commit`.
//!
//! The bootstrap messages and their line parser are `qsh-proto`'s
//! `ssh_bootstrap` module; nothing here parses a line itself. The two-phase
//! client writes and the `pair.ssh` operation are built on top of this
//! module and are not part of it.
//!
//! The module spawns child processes and binds one UDP socket for the
//! responder's probe, and never names the QUIC stack, so `xtask arch`'s
//! `quinn::` ban on `qsh-core/src/` covers it and it needs no
//! directory-scoped ban of its own.

/// The line `qsh [user@]host` and `qsh cp` write to stderr before they start
/// the bootstrap on their own (ADR-0044 decision 2). `{host}` is the name
/// nothing resolved and `{dest}` the operand ssh receives; fill them with
/// [`auto_bootstrap_notice`]. The wording is fixed here so a person learns
/// that ssh is about to run, and how to stop it, before ssh prompts for
/// anything.
pub const AUTO_BOOTSTRAP_NOTICE: &str = "no qsh pin for \"{host}\"; setting one up over ssh \
     (ssh {dest}); set [ssh].bootstrap = \"off\" to disable";

/// [`AUTO_BOOTSTRAP_NOTICE`] for one name. Both arguments passed
/// [`Dest::parse`], so neither holds whitespace or a control character.
pub fn auto_bootstrap_notice(host: &str, dest: &str) -> String {
    AUTO_BOOTSTRAP_NOTICE
        .replace("{host}", host)
        .replace("{dest}", dest)
}

mod dest;
mod respond;
mod ssh;

pub use dest::{Dest, split_user_host};
pub use respond::{AUDIT_ACTION, RespondEnd, Responder};
pub use ssh::{
    BATCH_HELLO_TIMEOUT, BootstrapTimeouts, MESSAGE_TIMEOUT, ResponderOptions, SSH_G_OUTPUT_MAX,
    SshChild, SshExit, SshResolved, SshRunner, batch_mode, map_ssh_exit, parse_ssh_g,
    quote_remote_program, responder_args, ssh_g_args, ssh_not_found,
};

#[cfg(test)]
mod tests;
