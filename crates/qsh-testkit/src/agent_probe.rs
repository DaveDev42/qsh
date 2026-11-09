//! The host-side program of the agent-forwarding tests: where to find the
//! `qsh-agent-probe` binary and how to spell its command lines.
//!
//! The probe speaks the ssh-agent protocol to `$SSH_AUTH_SOCK` on every OS (a
//! Unix socket on unix, a named pipe on Windows), which is why the tests use
//! it instead of a `python3` one-liner.

use std::path::PathBuf;

use crate::fake_agent::sign_request_body;

/// The path of the `qsh-agent-probe` executable, built if need be
/// (`QSH_AGENT_PROBE_BIN` overrides).
pub fn bin() -> PathBuf {
    crate::testbin::locate("qsh-agent-probe", "QSH_AGENT_PROBE_BIN")
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `KIND:BODY_HEX` argument of a sign request (13) for `key_blob` over
/// `data`.
pub fn sign_arg(key_blob: &[u8], data: &[u8]) -> String {
    format!("13:{}", hex(&sign_request_body(key_blob, data, 0)))
}

/// `argv` of a probe run that sends `messages` (each `KIND` or
/// `KIND:BODY_HEX`) on one connection.
pub fn call_argv(messages: &[String]) -> Vec<String> {
    let mut argv = vec![bin().to_string_lossy().into_owned(), "call".into()];
    argv.extend(messages.iter().cloned());
    argv
}

/// `argv` of a probe run that prints the host's `SSH_AUTH_SOCK`.
pub fn sock_argv() -> Vec<String> {
    vec![bin().to_string_lossy().into_owned(), "sock".into()]
}

/// The line a shell is given to run the probe with a tag: the executable
/// quoted for the platform's shell, then `call --tag LABEL MESSAGES`.
pub fn shell_tagged_call(label: &str, messages: &[String]) -> String {
    let exe = bin().to_string_lossy().into_owned();
    let quoted = if cfg!(windows) {
        format!("\"{exe}\"")
    } else {
        format!("'{exe}'")
    };
    format!("{quoted} call --tag {label} {}", messages.join(" "))
}
