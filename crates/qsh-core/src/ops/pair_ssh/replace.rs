//! Replacing a pin over ssh (ADR-0051 decision 5).
//!
//! A remote that was reinstalled has a new key, and this machine may have a
//! new key too, so a pin on one side or the other holds a fingerprint that is
//! no longer the machine behind the ssh login. `qsh pair ssh` refuses that by
//! default (`pin_conflict`). With `--replace-pin`, or after a "yes" on a
//! terminal, it replaces the stale pin instead. The trust is the one the pin
//! was made on in the first place: the ssh login and ssh's own host key
//! verification (threat model A16). The invite-code path never reaches this
//! file (ADR-0002).
//!
//! What a replacement is, on either side:
//!
//! - the old pin is deleted and a new one written as if the name had been
//!   free: fresh `added_at`, the role a new pin gets, and none of the old
//!   pin's `grants`, `paths`, `scope` (they were given to the old key, threat
//!   model B41);
//! - the audit record is written before the file is saved, for any role,
//!   because the call changes who is trusted under a name (B21): no durable
//!   record, no replacement;
//! - `source` is set again exactly as for a new pin, so a pin the bootstrap
//!   writes under the ssh host name stays one the revival may use.
//!
//! The remote side is the responder's (`ssh_bootstrap::respond`), driven by
//! `commit.replace`; this file is this machine's side and the questions.

use super::*;
use crate::prompts;
use crate::trust::PIN_SOURCE_SSH_BOOTSTRAP;

/// The audit `action` of a pin this machine replaced (ADR-0051 decision 5).
pub const AUDIT_ACTION_REPLACE: &str = "pair.ssh.replace_pin";

/// What to do about this machine's own pin before the `commit`.
pub(super) enum LocalDecision {
    /// No conflict (or an identical pin): carry on as before.
    Proceed,
    /// Replace this machine's pin `old` after the remote side is done.
    /// `asked` is `true` when a question was answered, which took longer than
    /// the responder waits for a `commit`, so the conversation is opened
    /// again.
    Replace { old: Box<TrustPeer>, asked: bool },
}

/// The pin that [`local_conflict`] would refuse for holding another
/// fingerprint under the same name, when replacing it is well defined: no
/// other pin already holds the remote's fingerprint under another name.
fn replaceable_pin(store: &TrustStore, name: &str, remote: &Fingerprint) -> Option<TrustPeer> {
    let remote_text = remote.to_string();
    let existing = store.find(name)?;
    if existing.fingerprint == remote_text
        || store.peers().iter().any(|p| p.fingerprint == remote_text)
    {
        return None;
    }
    Some(existing.clone())
}

impl Ops {
    /// Decide, before anything is written, whether this machine's pin may be
    /// replaced. A pin that conflicts and cannot be replaced is the same
    /// error [`Self::local_pin_check`] gives.
    pub(super) fn local_replace_decision(
        &self,
        plan: &Plan,
        env: &PairSshEnv,
        remote: &Fingerprint,
    ) -> Result<LocalDecision, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        let Some(old) = replaceable_pin(&store, &plan.pin_name, remote) else {
            return self
                .local_pin_check(plan, remote)
                .map(|()| LocalDecision::Proceed);
        };
        let asked = !plan.replace_pin;
        if asked {
            env.prompter.note(&format!(
                "이 장비의 pin {:?}는 {}인데, ssh로 닿은 {}는 {}다. 바꾸면 옛 pin에 준 grants도 사라진다. \
                 근거는 ssh 로그인과 ssh host key 검증이다.",
                plan.pin_name,
                old.fingerprint,
                plan.dest.as_ssh_arg(),
                remote,
            ));
            if env.prompter.ask(&prompts::REPLACE_PIN) != Some(true) {
                return Err(local_pin_conflict(
                    &plan.pin_name,
                    plan.dest.as_ssh_arg(),
                    &old.fingerprint,
                    &remote.to_string(),
                ));
            }
        }
        Ok(LocalDecision::Replace {
            old: Box::new(old),
            asked,
        })
    }

    /// Ask whether the pin the remote holds for this machine may be
    /// replaced, after the remote answered `conflict`. `old` is what the
    /// remote's message named, when it parsed.
    pub(super) fn ask_replace_remote(
        &self,
        env: &PairSshEnv,
        plan: &Plan,
        remote_name: &str,
        old: Option<&Fingerprint>,
        ours: &Fingerprint,
    ) -> bool {
        let old = old.map_or_else(|| "another fingerprint".to_string(), ToString::to_string);
        env.prompter.note(&format!(
            "{}의 qsh에 이 장비 이름 {:?}로 올라 있는 pin은 {old}인데, 이 장비의 fingerprint는 {ours}다. \
             바꾸면 그 pin에 준 grants도 사라진다. 근거는 ssh 로그인과 ssh host key 검증이다.",
            plan.dest.as_ssh_arg(),
            remote_name,
        ));
        env.prompter.ask(&prompts::REPLACE_PIN) == Some(true)
    }

    /// Open the conversation again and check it reaches the machine the
    /// first one did. A second ssh login is the price of waiting for an
    /// answer: the responder gives up on a `commit` after 30 seconds and
    /// ends after its `result`.
    pub(super) fn reconnect(
        &self,
        runtime: &SharedRuntime,
        plan: &Plan,
        env: &PairSshEnv,
        expected: &Fingerprint,
    ) -> Result<(SshChild, CheckedHello), OpError> {
        let (child, hello, _resolved) = runtime.block_on(exchange_hello(plan, &env.cancel))?;
        let hello = match check_hello(&hello, &plan.dest) {
            Ok(hello) => hello,
            Err(err) => {
                runtime.block_on(child.finish());
                return Err(err);
            }
        };
        if &hello.fingerprint != expected {
            runtime.block_on(child.finish());
            return Err(OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "ssh {} reached a qsh with another identity the second time, so nothing was \
                     written on either side",
                    plan.dest.as_ssh_arg()
                ),
            )
            .with_retryable(false)
            .with_details(json!({ "reason": "pin_conflict", "side": "remote" })));
        }
        Ok((child, hello))
    }

    /// Replace this machine's pin `plan.pin_name`, which still has to hold
    /// `old_fingerprint`: lock, load, check, mutate, audit, save. No durable
    /// audit record, no change. `reverse` writes the pin as the reverse
    /// direction does (no address, role `reverse`).
    pub(super) fn replace_local_pin(
        &self,
        plan: &Plan,
        address: &str,
        remote: &Fingerprint,
        old_fingerprint: &str,
    ) -> Result<TrustPeer, OpError> {
        let path = self.paths.trust_file();
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let still_old = store
            .find(&plan.pin_name)
            .is_some_and(|peer| peer.fingerprint == old_fingerprint);
        if !still_old || replaceable_pin(&store, &plan.pin_name, remote).is_none() {
            // Changed while ssh ran: do not guess, ask again.
            return Err(OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "the pin {:?} on this machine changed while the remote was being reached, so \
                     it was not replaced; run this command again",
                    plan.pin_name
                ),
            )
            .with_retryable(false)
            .with_details(json!({
                "reason": "pin_conflict",
                "side": "local",
                "name": plan.pin_name,
            })));
        }
        let (address, role) = if plan.is_reverse() {
            (None, TrustRole::Reverse)
        } else {
            (Some(address.to_string()), TrustRole::None)
        };
        let (peer, _old) = store
            .replace_peer(&plan.pin_name, address, *remote, now_rfc3339(), role)
            .expect("the pin was found under the lock");
        if plan.pin_name == plan.dest.host() && !plan.is_reverse() {
            store.mark_source(&peer.name, PIN_SOURCE_SSH_BOOTSTRAP);
        }
        let mut record = AuditRecord::local_op(
            AUDIT_ACTION_REPLACE,
            Principal::Device(peer.name.clone()).to_string(),
            peer.name.clone(),
        );
        record.role = Some(role.as_str().to_string());
        self.audit_sink()?.record(&record).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("audit record could not be written; trust.toml left unchanged: {err}"),
            )
            .with_retryable(true)
        })?;
        store.save(&path)?;
        // As for a new pin, the returned pin does not carry its origin mark:
        // `pair.ssh`'s `peer` is an append-only shape that way.
        Ok(peer)
    }
}

/// `UNSUPPORTED`/`remote_replace_unsupported`: the person asked to replace
/// the remote's pin and the remote qsh cannot (it did not advertise
/// `replace_pin`). Nothing was sent that it would misread, and nothing was
/// written on either side.
pub fn remote_replace_unsupported(name: &str, dest: &str) -> OpError {
    let name_w = shell_word(name);
    let dest_w = shell_word(dest);
    OpError::new(
        ErrorCode::Unsupported,
        format!(
            "{name:?} is pinned on the remote under a different identity and the remote qsh is \
             too old to replace a pin, so nothing was written on either side; remove the stale \
             entry with `ssh {dest_w} qsh trust remove {name_w}` and run this again, or upgrade \
             the remote"
        ),
    )
    .with_retryable(false)
    .with_details(json!({ "reason": "remote_replace_unsupported", "name": name }))
}

/// The fingerprint a responder's `conflict` message names, if it parses
/// (`remote_pin_conflict` reads it the same way).
pub(super) fn pinned_fingerprint_in(message: Option<&str>) -> Option<Fingerprint> {
    message
        .and_then(|message| message.split_whitespace().next_back())
        .and_then(|word| word.parse::<Fingerprint>().ok())
}
