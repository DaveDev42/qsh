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
//!
//! The bootstrap messages and their line parser are `qsh-proto`'s
//! `ssh_bootstrap` module; nothing here parses a line itself. The remote
//! responder, the two-phase writes and the `pair.ssh` operation are built
//! on top of this module and are not part of it.
//!
//! The module spawns child processes and probes nothing on the network, and
//! never names the QUIC stack, so `xtask arch`'s `quinn::` ban on
//! `qsh-core/src/` covers it and it needs no directory-scoped ban of its
//! own.

mod dest;
mod ssh;

pub use dest::{Dest, split_user_host};
pub use ssh::{
    BATCH_HELLO_TIMEOUT, BootstrapTimeouts, MESSAGE_TIMEOUT, ResponderOptions, SSH_G_OUTPUT_MAX,
    SshChild, SshExit, SshResolved, SshRunner, batch_mode, map_ssh_exit, parse_ssh_g,
    quote_remote_program, responder_args, ssh_g_args, ssh_not_found,
};

#[cfg(test)]
mod tests;
