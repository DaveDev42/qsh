//! `pair.ssh`: pin two machines to each other over an ssh connection
//! (ADR-0044, `docs/CLI.md` §6.11).
//!
//! The operation is one conversation with the remote responder
//! (`crate::ssh_bootstrap`), written in two phases so a failure leaves at
//! worst a pin on the remote that the same command, run again, converges
//! (decision 12):
//!
//! 1. Everything that can be checked without writing: the arguments, this
//!    machine's identity, `ssh -G`, the responder's `hello`, and this
//!    machine's own trust store against the remote fingerprint.
//! 2. The `commit`. The remote writes its pin under its own lock, then this
//!    machine writes its pin (role `none`), then a QUIC handshake with
//!    mutual pin verification confirms the pair (decision 13).
//!
//! `--reverse --to` runs the same conversation the other way round
//! (decision 22): the commit carries the address the remote dials, this
//! machine's pin of the remote has no address and role `reverse` (with an
//! audit record, written before the pin is saved), and no confirming dial is
//! made because nothing listens on the remote yet; the result names the
//! command to run there instead.
//!
//! Nothing here reads a key, a passphrase or an agent socket; ssh does all of
//! that in its own process (decision 19). `hosts.toml`, `config.toml` and
//! `acl.toml` are never written, and the ssh `User` is stored nowhere
//! (decision 26).

use std::time::Duration;

use qsh_proto::ssh_bootstrap::{
    BOOTSTRAP_VERSIONS, BootstrapLine, BootstrapResult, Commit, Hello, HelloStatus, ResultStatus,
    negotiate_version,
};
use qsh_proto::{
    CliError, IdentityInitReq, PairSshData, PairSshDirection, PairSshRemote, PairSshReq,
};
use serde_json::json;

use super::trust::parse_role_arg;
use super::*;
use crate::pairing::{pairing_role_clause, shell_single_quoted};
use crate::ssh_bootstrap::{
    Dest, ResponderOptions, SshChild, SshResolved, SshRunner, batch_mode, quote_remote_program,
};
use crate::trust::validate_peer_label;

/// How long the confirming dial waits for the handshake (ADR-0044 decision
/// 13). Shorter than the transport default: the remote was just reached by
/// ssh, and a person is waiting on the answer.
pub const CONFIRM_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the confirming dial waits, once the handshake has completed, for
/// a late rejection. TLS 1.3 lets the client finish before the server has
/// judged the client's certificate, so "the server does not know this
/// device" arrives as a close shortly after the handshake.
pub const CONFIRM_SETTLE: Duration = Duration::from_millis(500);

/// What a frontend tells `pair.ssh` about its environment.
#[derive(Clone)]
pub struct PairSshEnv {
    /// `--json` or `--jsonl`. ssh then runs with `BatchMode=yes`
    /// (ADR-0044 decision 16).
    pub machine_mode: bool,
    /// Whether standard input is a terminal. A script's stdin is not, and ssh
    /// then runs with `BatchMode=yes` too.
    pub stdin_is_terminal: bool,
    /// Fires when the user interrupts. The ssh child is ended and the call
    /// fails with `CANCELED`; nothing is written after that point.
    pub cancel: CancelToken,
}

/// The result of `pair.ssh`: the envelope data and the notices a human
/// renderer writes to stderr. The notices are decided here so a frontend
/// formats nothing (`docs/design/architecture.md` §1).
#[derive(Debug, Clone, PartialEq)]
pub struct PairSshOutput {
    /// The `data` of the `qsh.cli/v1` envelope.
    pub data: PairSshData,
    /// Human-mode stderr lines, in order. Machine modes ignore them.
    pub notices: Vec<String>,
}

/// The arguments of a `pair.ssh` call after validation.
struct Plan {
    dest: Dest,
    pin_name: String,
    remote_as: Option<String>,
    role: TrustRole,
    address: Option<String>,
    /// `--to`, normalized: `Some` is the reverse direction (decision 22).
    to: Option<String>,
    remote_qsh: String,
    runner: SshRunner,
    batch: bool,
}

impl Plan {
    fn is_reverse(&self) -> bool {
        self.to.is_some()
    }
}

impl Ops {
    /// `pair.ssh` — pin this machine and a remote one to each other over ssh
    /// (ADR-0044 decisions 1 and 5 to 21).
    ///
    /// Arguments are validated first, before this machine's identity is
    /// created or any ssh process starts (decisions 7 and 18). Then, in
    /// order: the identity (`identity.init`, idempotent), `ssh -G`, the
    /// responder's `hello`, the local check, the `commit`, this machine's
    /// pin, and the confirming dial. A failed confirmation still succeeds
    /// with `verified: false`, because the pins stand.
    ///
    /// **Runtime caveat:** blocks on the shared dial runtime and loads the
    /// identity synchronously (see [`Self::load_identity`]): call it from an
    /// ordinary thread, not from inside a tokio runtime.
    pub fn pair_ssh(&self, req: PairSshReq, env: PairSshEnv) -> Result<PairSshOutput, OpError> {
        let plan = self.pair_ssh_plan(&req, &env)?;

        let init = self.identity_init(IdentityInitReq {
            key_store: None,
            import_ssh_key: None,
        })?;
        let loaded = self.load_identity()?.ok_or_else(|| {
            OpError::new(
                ErrorCode::Internal,
                "the device identity is missing right after it was created",
            )
        })?;
        let our_fingerprint = loaded.identity.fingerprint;
        let runtime = self.connect_runtime()?;

        // Phase one: nothing is written anywhere.
        let (mut child, hello, resolved) = runtime.block_on(exchange_hello(&plan, &env.cancel))?;
        let end_child = |child: SshChild| {
            runtime.block_on(child.finish());
        };
        let hello = match check_hello(&hello, &plan.dest) {
            Ok(hello) => hello,
            Err(err) => {
                end_child(child);
                return Err(err);
            }
        };

        let remote_name = match plan.remote_as.clone() {
            Some(name) => name,
            None => default_remote_name(local_hostname().as_deref(), &loaded.identity.device_id),
        };

        // Forward: where this machine dials the remote. Reverse: where the
        // remote dials this machine.
        let address = match (&plan.to, &plan.address) {
            (Some(to), _) => to.clone(),
            (None, Some(address)) => address.clone(),
            (None, None) => {
                normalize_peer_address(&qsh_proto::wire::format_host_port(
                    &resolved.hostname,
                    hello.port,
                ))
                .address
            }
        };

        if let Err(err) = self.local_pin_check(&plan, &hello.fingerprint) {
            end_child(child);
            return Err(err);
        }
        if env.cancel.is_canceled() {
            end_child(child);
            return Err(canceled());
        }

        // Phase two: the commit, the remote pin, this machine's pin.
        let commit = Commit {
            version: hello.version,
            fingerprint: our_fingerprint.to_string(),
            name: remote_name.clone(),
            role: plan.role.as_str().to_string(),
            address: plan.to.clone(),
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
        let remote = remote_from_result(
            &result,
            &remote_name,
            &our_fingerprint,
            plan.dest.as_ssh_arg(),
        )?;
        if env.cancel.is_canceled() {
            return Err(canceled());
        }

        let written = if plan.is_reverse() {
            self.write_local_reverse_pin(&plan, &hello.fingerprint)
        } else {
            self.write_local_pin(&plan, &address, &hello.fingerprint)
        };
        let (peer, created) = written.map_err(|err| {
            OpError::new(
                err.code,
                format!(
                    "{}; the remote pin was written, so run this command again to finish",
                    err.message
                ),
            )
            .with_retryable(err.retryable)
            .with_details(err.details)
        })?;

        // Confirmation: the pins stand whatever this says. The reverse
        // direction makes no dial (decision 13): the remote is not serving
        // anything yet, and that is the expected state.
        let (verified, verify_error) = if plan.is_reverse() {
            (false, None)
        } else if hello.listening == Some(false) {
            (false, Some(cli_error(serve_not_listening(&peer.name))))
        } else {
            match self.confirm_dial(
                &runtime,
                &loaded,
                &address,
                &hello.fingerprint,
                &peer.name,
                &plan.dest,
                resolved.proxied,
                &env.cancel,
            ) {
                Ok(()) => (true, None),
                Err(err) if err.code == ErrorCode::Canceled => return Err(err),
                Err(err) => (false, Some(cli_error(err))),
            }
        };

        let (direction, next_command) = if plan.is_reverse() {
            (
                PairSshDirection::Reverse,
                Some(reverse_next_command(&remote.name)),
            )
        } else {
            (PairSshDirection::Forward, None)
        };
        let data = PairSshData {
            direction,
            peer,
            created,
            remote,
            next_command,
            identity_created: init.created,
            ssh_proxied: resolved.proxied,
            verified,
            verify_error,
        };
        let notices = notices(&data, &plan, &resolved, &address);
        Ok(PairSshOutput { data, notices })
    }

    /// Validate every argument that can be validated without a side effect.
    fn pair_ssh_plan(&self, req: &PairSshReq, env: &PairSshEnv) -> Result<Plan, OpError> {
        // The direction flags first (decision 1): no other argument can make
        // an inconsistent pair valid.
        let to = match req.to.as_deref() {
            None => None,
            Some("") => {
                return Err(
                    OpError::new(ErrorCode::InvalidArgument, "--to must not be empty")
                        .with_retryable(false),
                );
            }
            Some(to) => Some(normalize_peer_address(to).address),
        };
        if req.reverse != to.is_some() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "--reverse and --to go together: the remote dials the address given with --to",
            )
            .with_retryable(false));
        }
        if req.reverse && req.address.is_some() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "--address is the address this machine dials, so it does not combine with \
                 --reverse; the remote dials the --to address",
            )
            .with_retryable(false));
        }
        let dest = Dest::parse(&req.dest)?;
        let pin_name = dest.pin_name(req.as_name.as_deref())?;
        let remote_as = req
            .remote_as
            .as_deref()
            .map(validate_peer_label_arg)
            .transpose()?;
        let role = match req.role.as_deref() {
            Some(role) => parse_role_arg(role)?,
            None => TrustRole::Full,
        };
        let address = match req.address.as_deref() {
            None => None,
            Some("") => {
                return Err(OpError::new(
                    ErrorCode::InvalidArgument,
                    "--address must not be empty",
                )
                .with_retryable(false));
            }
            Some(address) => Some(normalize_peer_address(address).address),
        };
        let config = self.config()?;
        let remote_qsh = match req.remote_qsh.as_deref() {
            Some(word) => word.to_string(),
            None => config.ssh.remote_qsh()?.to_string(),
        };
        // The quoting rule refuses a word that would split the remote
        // command; do it here so it fails before any side effect.
        quote_remote_program(&remote_qsh)?;
        let runner = SshRunner::from_config(&config.ssh)?;
        Ok(Plan {
            dest,
            pin_name,
            remote_as,
            role,
            address,
            to,
            remote_qsh,
            runner,
            batch: batch_mode(env.machine_mode, env.stdin_is_terminal),
        })
    }

    /// Refuse, before anything is written, a remote fingerprint that
    /// conflicts with this machine's trust store (ADR-0044 decisions 12, 15).
    fn local_pin_check(&self, plan: &Plan, remote: &Fingerprint) -> Result<(), OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        match local_conflict(&store, &plan.pin_name, remote, plan.dest.as_ssh_arg()) {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Write this machine's pin: lock, load, check again, mutate, save. The
    /// role is `none`, so ADR-0045 decision 8 writes no audit record. The
    /// address of an existing pin for the same identity is refreshed, as in
    /// `trust.add`.
    fn write_local_pin(
        &self,
        plan: &Plan,
        address: &str,
        remote: &Fingerprint,
    ) -> Result<(TrustPeer, bool), OpError> {
        let path = self.paths.trust_file();
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        if let Some(err) = local_conflict(&store, &plan.pin_name, remote, plan.dest.as_ssh_arg()) {
            return Err(err);
        }
        let (peer, created, updated) = store.add_peer_with_role(
            plan.pin_name.clone(),
            Some(address.to_string()),
            *remote,
            now_rfc3339(),
            TrustRole::None,
        );
        if created || updated {
            store.save(&path)?;
        }
        Ok((peer, created))
    }

    /// Write this machine's pin of the remote in the reverse direction: no
    /// address, role `reverse` (decision 12, 22). The role grants an action,
    /// so the order is lock, load, check again, mutate, audit, save, and with
    /// no durable audit record there is no pin. An existing pin for the same
    /// identity is left as it is; its role is reported, not changed.
    fn write_local_reverse_pin(
        &self,
        plan: &Plan,
        remote: &Fingerprint,
    ) -> Result<(TrustPeer, bool), OpError> {
        let path = self.paths.trust_file();
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        if let Some(err) = local_conflict(&store, &plan.pin_name, remote, plan.dest.as_ssh_arg()) {
            return Err(err);
        }
        let (peer, created, _updated) = store.add_peer_with_role(
            plan.pin_name.clone(),
            None,
            *remote,
            now_rfc3339(),
            TrustRole::Reverse,
        );
        if created {
            self.record_role_write(PairSshOp::COMMAND, &peer.name, TrustRole::Reverse)?;
            store.save(&path)?;
        }
        Ok((peer, created))
    }

    /// The confirming dial (ADR-0044 decision 13): a QUIC handshake with
    /// mutual pin verification, no session. The pin this call just wrote is
    /// what is verified against.
    #[allow(clippy::too_many_arguments)]
    fn confirm_dial(
        &self,
        runtime: &SharedRuntime,
        loaded: &LoadedIdentity,
        address: &str,
        expected: &Fingerprint,
        name: &str,
        dest: &Dest,
        proxied: bool,
        cancel: &CancelToken,
    ) -> Result<(), OpError> {
        let trust = SharedTrustStore::open(self.paths.trust_file())?;
        let dialer = Dialer::new(
            loaded.local.clone(),
            trust as Arc<dyn qsh_transport::TrustEvaluator>,
        )
        .with_timeout(CONFIRM_DIAL_TIMEOUT);
        let server_name = server_name_for(address);
        runtime.block_on(async {
            let dial = async {
                let addrs = resolve_all(address)
                    .await
                    .map_err(|err| with_proxy_note(err, proxied))?;
                let dialed = dial_first_reachable(&addrs, |addr| {
                    dialer.dial(addr, &server_name)
                })
                .await
                .map_err(|(err, attempted)| {
                    classify_confirm_failure(err, address, attempted, name, dest, proxied)
                })?;
                if dialed.connection.peer_fingerprint().as_ref() != Some(expected) {
                    dialed.connection.close(0, b"identity mismatch");
                    return Err(serve_identity_mismatch(address, name, dest, proxied));
                }
                // A server that does not know this device closes shortly
                // after our side of the handshake completed.
                let settled =
                    tokio::time::timeout(CONFIRM_SETTLE, dialed.connection.closed()).await;
                let outcome = match settled {
                    Err(_) => Ok(()),
                    Ok(err) if err.is_crypto_failure() => {
                        Err(serve_rejected_this_device(address, name, dest))
                    }
                    Ok(err) => Err(with_proxy_note(
                        OpError::new(
                            ErrorCode::ConnectionFailed,
                            format!("the connection to {address} closed right after the handshake: {err}"),
                        ),
                        proxied,
                    )),
                };
                dialed.connection.close(0, b"verified");
                let _ = tokio::time::timeout(CONFIRM_SETTLE, dialed.endpoint.wait_idle()).await;
                outcome
            };
            tokio::select! {
                biased;
                () = cancel.canceled() => Err(canceled()),
                outcome = dial => outcome,
            }
        })
    }
}

// ---------------------------------------------------------------------
// the ssh conversation
// ---------------------------------------------------------------------

/// What the `hello` told this machine, validated.
struct CheckedHello {
    fingerprint: Fingerprint,
    version: u32,
    port: u16,
    listening: Option<bool>,
}

/// `ssh -G`, the responder call and the `hello` (ADR-0044 decisions 4, 9).
async fn exchange_hello(
    plan: &Plan,
    cancel: &CancelToken,
) -> Result<(SshChild, Hello, SshResolved), OpError> {
    let resolved = plan.runner.resolve(&plan.dest, cancel).await?;
    let mut child = plan.runner.spawn_responder(
        &plan.dest,
        &plan.remote_qsh,
        ResponderOptions::new(plan.batch, cancel.clone()),
    )?;
    match child.recv().await? {
        BootstrapLine::Hello(hello) => Ok((child, hello, resolved)),
        _ => {
            let _ = child.finish().await;
            Err(protocol_violation(
                "the remote did not start with a hello message",
            ))
        }
    }
}

/// Decide what the `hello` allows (ADR-0044 decisions 10, 11, 14).
fn check_hello(hello: &Hello, dest: &Dest) -> Result<CheckedHello, OpError> {
    match &hello.status {
        HelloStatus::Ready => {}
        HelloStatus::NotInitialized => return Err(remote_not_initialized(dest)),
        HelloStatus::Unknown(_) => {
            return Err(protocol_violation(
                "the remote reported a status this qsh does not know",
            ));
        }
    }
    let Some(version) = negotiate_version(BOOTSTRAP_VERSIONS, &hello.versions) else {
        return Err(bootstrap_version_unsupported());
    };
    let fingerprint = hello
        .fingerprint
        .as_deref()
        .and_then(|text| text.parse::<Fingerprint>().ok())
        .ok_or_else(|| protocol_violation("the remote hello carries no usable fingerprint"))?;
    let port = crate::trust::invite_address::port_from_bind_spec(hello.serve_bind.as_deref());
    Ok(CheckedHello {
        fingerprint,
        version,
        port,
        listening: hello.serve_listening,
    })
}

/// Read the responder's `result`. Everything it says is peer-authored text:
/// it is bounded and stripped of control characters before it is used.
fn remote_from_result(
    result: &BootstrapResult,
    asked_name: &str,
    ours: &Fingerprint,
    dest: &str,
) -> Result<PairSshRemote, OpError> {
    match &result.status {
        ResultStatus::Pinned | ResultStatus::Exists => {}
        ResultStatus::Conflict => {
            return Err(remote_pin_conflict(
                asked_name,
                dest,
                ours,
                result.message.as_deref(),
            ));
        }
        ResultStatus::Error => {
            let code = match &result.code {
                Some(ErrorCode::Unknown(_)) | None => ErrorCode::RemoteError,
                Some(code) => code.clone(),
            };
            return Err(remote_responder_error(
                code,
                result.message.as_deref().unwrap_or(""),
                dest,
            ));
        }
        ResultStatus::Unknown(_) => {
            return Err(protocol_violation(
                "the remote answered with a status this qsh does not know",
            ));
        }
    }
    let created = result.status == ResultStatus::Pinned;
    let name = sanitize_remote_text(&result.name, 64);
    let name = if name.is_empty() {
        asked_name.to_string()
    } else {
        name
    };
    Ok(PairSshRemote {
        name,
        role: result
            .role
            .as_deref()
            .map(|role| sanitize_remote_text(role, 32)),
        created,
    })
}

/// Peer-authored text made safe to show: control characters and invisible
/// format characters become spaces and the length is capped.
pub(crate) fn sanitize_remote_text(text: &str, max_chars: usize) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || is_invisible_format(c) {
                ' '
            } else {
                c
            }
        })
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Bidi overrides and isolates, zero-width characters and the BOM: the
/// format characters that can make remote-authored text read differently on
/// a terminal than it is.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

// ---------------------------------------------------------------------
// names
// ---------------------------------------------------------------------

/// The name the remote pins this machine under when `--remote-as` is not
/// given (ADR-0044 decision 8): the first label of this machine's host
/// name when it is a valid pin name, otherwise the `device_id`.
pub fn default_remote_name(hostname: Option<&str>, device_id: &str) -> String {
    hostname
        .and_then(|host| host.split('.').next())
        .filter(|label| !label.is_empty() && validate_peer_label(label).is_ok())
        .map_or_else(|| device_id.to_string(), str::to_string)
}

#[cfg(unix)]
fn local_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname(2) writes at most `buf.len()` bytes into `buf`.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

#[cfg(not(unix))]
fn local_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

/// The command to run on the remote once a reverse pair is in place
/// (decision 22): `qsh serve --to` registers with this machine under the name
/// the remote pinned it by.
fn reverse_next_command(remote_name: &str) -> String {
    format!("qsh serve --to {}", shell_word(remote_name))
}

// ---------------------------------------------------------------------
// conflicts (ADR-0044 decision 15)
// ---------------------------------------------------------------------

/// The conflict, if any, between `name -> remote` and this machine's store:
/// the same name pinned to another fingerprint, or the remote fingerprint
/// already pinned under another name.
fn local_conflict(
    store: &TrustStore,
    name: &str,
    remote: &Fingerprint,
    dest: &str,
) -> Option<OpError> {
    let remote_text = remote.to_string();
    if let Some(existing) = store.find(name)
        && existing.fingerprint != remote_text
    {
        return Some(local_pin_conflict(
            name,
            dest,
            &existing.fingerprint,
            &remote_text,
        ));
    }
    store
        .peers()
        .iter()
        .find(|peer| peer.fingerprint == remote_text && peer.name != name)
        .map(|other| local_fingerprint_conflict(name, &other.name, dest, &remote_text))
}

/// A word safe to paste into a shell: bare when it is made of safe
/// characters, POSIX single-quoted otherwise.
fn shell_word(text: &str) -> String {
    let bare = !text.is_empty()
        && text.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '/' | '+' | '-')
        });
    if bare {
        text.to_string()
    } else {
        shell_single_quoted(text)
    }
}

/// `SESSION_CONFLICT`, local side, same name (decision 15): `name` is
/// already pinned here under another identity than the one the remote
/// reported. Nothing is written on either side.
pub fn local_pin_conflict(
    name: &str,
    dest: &str,
    pinned_fingerprint: &str,
    observed_fingerprint: &str,
) -> OpError {
    let name_w = shell_word(name);
    let dest_w = shell_word(dest);
    OpError::new(
        ErrorCode::SessionConflict,
        format!(
            "{name:?} is already pinned on this machine under a different identity than the one \
             the remote reported, so nothing was written on either side; if the remote was \
             re-initialized, run `qsh trust remove {name_w}` and then `qsh pair ssh {dest_w}`, or \
             keep the old pin and pass --as <other name>"
        ),
    )
    .with_retryable(false)
    .with_details(json!({
        "reason": "pin_conflict",
        "side": "local",
        "name": name,
        "pinned_fingerprint": pinned_fingerprint,
        "observed_fingerprint": observed_fingerprint,
    }))
}

/// `SESSION_CONFLICT`, local side, same identity under another name: the
/// remote's fingerprint is already pinned here as `other`.
pub fn local_fingerprint_conflict(
    name: &str,
    other: &str,
    dest: &str,
    fingerprint: &str,
) -> OpError {
    let other_w = shell_word(other);
    let dest_w = shell_word(dest);
    OpError::new(
        ErrorCode::SessionConflict,
        format!(
            "the remote's identity is already pinned on this machine as {other:?}, so a second \
             pin named {name:?} was not written and nothing was written on the remote; use \
             `qsh {other_w}` as it is, or run `qsh trust remove {other_w}` and then \
             `qsh pair ssh {dest_w}`"
        ),
    )
    .with_retryable(false)
    .with_details(json!({
        "reason": "pin_conflict",
        "side": "local",
        "name": name,
        "pinned_name": other,
        "pinned_fingerprint": fingerprint,
        "observed_fingerprint": fingerprint,
    }))
}

/// `SESSION_CONFLICT`, remote side (decision 15): the name this machine
/// asked the remote to use is pinned there under another identity. The
/// remote's own message is read only for the fingerprint it names, which has
/// to parse as one.
pub fn remote_pin_conflict(
    name: &str,
    dest: &str,
    observed: &Fingerprint,
    remote_message: Option<&str>,
) -> OpError {
    let name_w = shell_word(name);
    let dest_w = shell_word(dest);
    let pinned = remote_message
        .and_then(|message| message.split_whitespace().next_back())
        .and_then(|word| word.parse::<Fingerprint>().ok());
    let mut details = json!({
        "reason": "pin_conflict",
        "side": "remote",
        "name": name,
        "observed_fingerprint": observed.to_string(),
    });
    if let (Some(pinned), Some(map)) = (pinned, details.as_object_mut()) {
        map.insert("pinned_fingerprint".into(), json!(pinned.to_string()));
    }
    OpError::new(
        ErrorCode::SessionConflict,
        format!(
            "{name:?} is already pinned on the remote under a different identity, so nothing was \
             written on either side; pass --remote-as <other name>, or remove the stale entry \
             with `ssh {dest_w} qsh trust remove {name_w}` and run this again"
        ),
    )
    .with_retryable(false)
    .with_details(details)
}

// ---------------------------------------------------------------------
// the remote's refusals (decision 14)
// ---------------------------------------------------------------------

/// `REMOTE_ERROR`/`remote_not_initialized`: the remote has no identity.
pub fn remote_not_initialized(dest: &Dest) -> OpError {
    let dest_w = shell_word(dest.as_ssh_arg());
    OpError::new(
        ErrorCode::RemoteError,
        format!(
            "the remote qsh has no device identity yet, so nothing was written on either side; \
             run `ssh {dest_w} qsh setup host` (or `qsh init` there), then run this again"
        ),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "remote_not_initialized" }))
}

/// `UNSUPPORTED`/`bootstrap_version`: no bootstrap version in common.
pub fn bootstrap_version_unsupported() -> OpError {
    OpError::new(
        ErrorCode::Unsupported,
        "the remote qsh and this qsh share no bootstrap version, so nothing was written on \
         either side; upgrade the older one and run this again",
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "bootstrap_version" }))
}

/// `REMOTE_ERROR`/`remote_responder_error`: the responder answered `error`.
/// Its text is peer-authored and goes through
/// `sanitize_remote_text`.
pub fn remote_responder_error(code: ErrorCode, remote_message: &str, dest: &str) -> OpError {
    let dest_w = shell_word(dest);
    let text = sanitize_remote_text(remote_message, 200);
    let retryable = code.default_retryable();
    OpError::new(
        code,
        format!(
            "the remote qsh could not write the pin ({text}), so nothing was written on this \
             machine; check the remote with `ssh {dest_w} qsh doctor`, then run this again"
        ),
    )
    .with_retryable(retryable)
    .with_details(json!({ "reason": "remote_responder_error" }))
}

fn protocol_violation(what: &str) -> OpError {
    OpError::new(
        ErrorCode::RemoteError,
        format!("bootstrap protocol violation: {what}"),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "bootstrap_protocol" }))
}

fn canceled() -> OpError {
    OpError::new(ErrorCode::Canceled, "canceled").with_retryable(false)
}

// ---------------------------------------------------------------------
// the confirming dial (decision 13)
// ---------------------------------------------------------------------

/// The ssh path is not the QUIC path: say so on a dial failure
/// (decision 6).
fn with_proxy_note(mut err: OpError, proxied: bool) -> OpError {
    if !proxied {
        return err;
    }
    err.message = format!(
        "{}; ssh reached the host through ProxyJump or ProxyCommand, which the QUIC dial does \
         not use, so the host may not be reachable directly",
        err.message
    );
    match err.details.as_object_mut() {
        Some(map) => {
            map.insert("ssh_proxied".into(), json!(true));
        }
        None => err.details = json!({ "ssh_proxied": true }),
    }
    err
}

/// `CONNECTION_FAILED`/`remote_serve_not_listening`: the responder saw
/// nothing bound to the serve port, so no dial was tried.
pub fn serve_not_listening(name: &str) -> OpError {
    let name_w = shell_word(name);
    OpError::new(
        ErrorCode::ConnectionFailed,
        format!(
            "the remote reported that no `qsh serve` is listening on its serve port, so no \
             connection was tried; both pins stay in place, and once the remote runs `qsh serve` \
             (or `qsh service install`) `qsh {name_w}` connects"
        ),
    )
    .with_details(json!({ "reason": "remote_serve_not_listening" }))
}

/// `AUTH_FAILED`/`remote_serve_identity_mismatch`: what answers at the
/// recorded address is not the identity the ssh account reported.
pub fn serve_identity_mismatch(address: &str, name: &str, dest: &Dest, proxied: bool) -> OpError {
    let name_w = shell_word(name);
    let dest_w = shell_word(dest.as_ssh_arg());
    with_proxy_note(
        OpError::new(
            ErrorCode::AuthFailed,
            format!(
                "what answers at {address} presented a different identity than the one the ssh \
                 account reported (the serve there runs as another account or with another \
                 config directory), so the connection was refused and the pins were left as \
                 they are; fix that serve, or run `qsh trust remove {name_w}` and then \
                 `qsh pair ssh {dest_w} --address <host:port>` with the right address"
            ),
        )
        .with_retryable(false)
        .with_details(json!({ "reason": "remote_serve_identity_mismatch" })),
        proxied,
    )
}

/// `AUTH_FAILED`/`remote_serve_rejected_this_device`: the serve at the
/// address does not know this machine's identity.
pub fn serve_rejected_this_device(address: &str, name: &str, dest: &Dest) -> OpError {
    let name_w = shell_word(name);
    let dest_w = shell_word(dest.as_ssh_arg());
    OpError::new(
        ErrorCode::AuthFailed,
        format!(
            "the serve at {address} rejected this device's certificate (it runs as another \
             account or with another config directory than the ssh account), so no connection \
             was made and the pins were left as they are; run `qsh trust remove {name_w}` and \
             then `qsh pair ssh {dest_w} --address <host:port>` once that serve is fixed"
        ),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "remote_serve_rejected_this_device" }))
}

fn classify_confirm_failure(
    err: qsh_transport::DialError,
    address: &str,
    attempted: usize,
    name: &str,
    dest: &Dest,
    proxied: bool,
) -> OpError {
    use qsh_transport::DialError;
    match err {
        DialError::LocalRejected { .. } => serve_identity_mismatch(address, name, dest, proxied),
        DialError::RemoteRejected => serve_rejected_this_device(address, name, dest),
        DialError::Failed(ref inner) if inner.is_crypto_failure() => {
            serve_rejected_this_device(address, name, dest)
        }
        other => with_proxy_note(exec::map_dial_error(other, address, attempted), proxied),
    }
}

fn cli_error(err: OpError) -> CliError {
    CliError {
        code: err.code,
        message: err.message,
        retryable: err.retryable,
        details: err.details,
    }
}

// ---------------------------------------------------------------------
// the human notices
// ---------------------------------------------------------------------

/// The stderr lines a human run adds to the result (ADR-0044 decisions 6,
/// 12, 18, 22, ADR-0045 decision 13).
fn notices(data: &PairSshData, plan: &Plan, resolved: &SshResolved, address: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if data.identity_created {
        lines.push(
            "created this machine's qsh identity first, as `qsh init` would (the bootstrap \
             needs one)"
                .to_string(),
        );
    }
    let verb = if data.created {
        "pinned"
    } else {
        "already pinned"
    };
    if plan.is_reverse() {
        // No address on this side: the remote is the one that dials.
        let role = data
            .peer
            .role
            .as_deref()
            .and_then(|role| role.parse::<TrustRole>().ok());
        // An existing pin from an earlier forward pair keeps its address
        // (`add_peer_with_role` only changes the address for a known name),
        // so say what the pin really holds rather than assuming none.
        let held_address = if data.peer.address.is_empty() {
            "without an address".to_string()
        } else {
            format!("at {}", data.peer.address)
        };
        lines.push(format!(
            "{verb} \"{}\" on this machine {held_address}. {}",
            data.peer.name,
            pairing_role_clause(role.unwrap_or(TrustRole::Reverse)),
        ));
        if let Some(line) = local_role_notice(data) {
            lines.push(line);
        }
    } else {
        lines.push(format!(
            "{verb} \"{}\" on this machine at {address}. {}",
            data.peer.name,
            pairing_role_clause(TrustRole::None),
        ));
    }
    let remote_role = data
        .remote
        .role
        .as_deref()
        .and_then(|role| role.parse::<TrustRole>().ok());
    if data.remote.created {
        let clause = remote_role.map_or_else(
            || "Its trust role there has no `role` key, so only `[[acl]]` rows apply.".into(),
            pairing_role_clause,
        );
        let at = if plan.is_reverse() {
            format!(" with address {address}")
        } else {
            String::new()
        };
        lines.push(format!(
            "pinned this machine on {} as \"{}\"{at}. {clause}",
            plan.dest.as_ssh_arg(),
            data.remote.name,
        ));
    } else {
        lines.push(format!(
            "this machine was already pinned on {} as \"{}\"; that pin was left as it is",
            plan.dest.as_ssh_arg(),
            data.remote.name,
        ));
    }
    if let Some(line) = role_mismatch_notice(data, plan) {
        lines.push(line);
    }
    if let Some(command) = &data.next_command {
        lines.push(format!(
            "nothing was started on {}; there, run `{command}` (or `qsh service install` to keep \
             it running) to register with this machine at {address}",
            plan.dest.as_ssh_arg(),
        ));
    } else if resolved.proxied {
        lines.push(format!(
            "ssh reached {} through ProxyJump or ProxyCommand, but qsh dials {} directly (it has \
             no relay), so the QUIC connection may not get through",
            plan.dest.as_ssh_arg(),
            resolved.hostname,
        ));
    }
    lines
}

/// An existing pin of the remote on this machine keeps the role it has. In
/// the reverse direction that is worth saying when it is not `reverse`,
/// because the remote's registration is then judged by `acl.toml` rows alone.
fn local_role_notice(data: &PairSshData) -> Option<String> {
    if data.created || data.peer.role.as_deref() == Some(TrustRole::Reverse.as_str()) {
        return None;
    }
    let held = match data.peer.role.as_deref() {
        Some(role) => format!("role {role}"),
        None => "no role (only `[[acl]]` rows apply)".to_string(),
    };
    let name = shell_word(&data.peer.name);
    Some(format!(
        "local pin {name} keeps {held}; run `qsh trust set-role {name} reverse` to let the \
         remote register"
    ))
}

/// The ADR-0044 decision 12 line for an existing remote pin whose role
/// differs from the one asked for.
fn role_mismatch_notice(data: &PairSshData, plan: &Plan) -> Option<String> {
    if data.remote.created {
        return None;
    }
    let asked = plan.role.as_str();
    if data.remote.role.as_deref() == Some(asked) {
        return None;
    }
    let held = match data.remote.role.as_deref() {
        Some(role) => format!("role {role}"),
        None => "no role (only `[[acl]]` rows apply)".to_string(),
    };
    let remote_qsh = quote_remote_program(&plan.remote_qsh).unwrap_or_else(|_| "qsh".into());
    Some(format!(
        "remote pin {} keeps {held}; run `ssh {} {remote_qsh} trust set-role {} {asked}` to \
         change it",
        shell_word(&data.remote.name),
        shell_word(plan.dest.as_ssh_arg()),
        shell_word(&data.remote.name),
    ))
}

#[cfg(test)]
mod tests;
