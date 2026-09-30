//! Planning and running `setup.run`: [`Ops::setup_plan`], [`Ops::setup_step`]
//! and [`Ops::setup_run`] (ADR-0024 결정 1).
//!
//! Every judgement lives here: which steps a role runs, whether a step is
//! already satisfied, blocked or waiting on a person. The frontend only
//! renders the result and hands over the inputs a plan asks for.

use std::path::PathBuf;
use std::time::SystemTime;

use qsh_proto::{
    AclCheckData, AclCheckReq, DoctorReq, ErrorCode, IdentityInitReq, SetupRole, SetupRunData,
    SetupRunReq, SetupStatus, SetupStep, SetupStepId, TrustAcceptReq, TrustAddReq, TrustInviteReq,
    TrustPeer,
};
use serde_json::{Value, json};

use super::{is_read_only_step, step_order};
use crate::acl::{ACL_RESTART_NOTICE, Role};
use crate::ops::{OpError, Ops};

/// How long an invite stays redeemable (`crate::trust::pairing::INVITE_TTL`,
/// `docs/CLI.md` §6.11), in the words a person is told.
const INVITE_TTL_TEXT: &str = "10 minutes";

/// The two facts `setup.run` reads from outside the config directory: the
/// clock and the home directory the service unit path is built from. Tests
/// inject both; [`SetupEnv::real`] is what the binary uses.
#[derive(Debug, Clone)]
pub struct SetupEnv {
    /// "Now", for invite expiry and the doctor run.
    pub now: SystemTime,
    /// Home directory for the service unit path; `None` is an environment
    /// with no resolvable home.
    pub home: Option<PathBuf>,
}

impl SetupEnv {
    /// The real clock and the real home directory.
    pub fn real() -> Self {
        Self {
            now: SystemTime::now(),
            home: crate::config::home_dir(),
        }
    }
}

/// Which mode a step function runs in. A plan never changes state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plan,
    Run,
}

fn id_str(id: SetupStepId) -> &'static str {
    match id {
        SetupStepId::Identity => "identity",
        SetupStepId::ModeConfig => "mode_config",
        SetupStepId::Acl => "acl",
        SetupStepId::PinCert => "pin_cert",
        SetupStepId::Pair => "pair",
        SetupStepId::Invite => "invite",
        SetupStepId::Service => "service",
        SetupStepId::Doctor => "doctor",
    }
}

fn status_str(status: SetupStatus) -> &'static str {
    match status {
        SetupStatus::Done => "done",
        SetupStatus::Already => "already",
        SetupStatus::Pending => "pending",
        SetupStatus::Blocked => "blocked",
        SetupStatus::Skipped => "skipped",
    }
}

fn invalid(message: impl Into<String>) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, message).with_retryable(false)
}

fn acl_role(role: SetupRole) -> Role {
    match role {
        SetupRole::Listener => Role::Listen,
        _ => Role::Serve,
    }
}

fn forwards(req: &SetupRunReq) -> bool {
    req.forward && matches!(req.role, SetupRole::Host | SetupRole::HostTo)
}

/// Actions the `acl` step needs `allow`ed for the requested role.
fn required_actions(req: &SetupRunReq) -> Vec<&'static str> {
    let mut actions = crate::acl::example_allow_actions(acl_role(req.role));
    if forwards(req) {
        actions.push("forward.local");
    }
    actions
}

/// The `[[acl]]` rows a person pastes into `acl.toml`.
fn acl_rows_text(req: &SetupRunReq, name: &str) -> String {
    let extra: &[&str] = if forwards(req) {
        &["forward.local"]
    } else {
        &[]
    };
    crate::acl::policy_example_rows_with(&[name], acl_role(req.role), extra)
}

fn step(
    id: SetupStepId,
    status: SetupStatus,
    command: String,
    detail: Option<String>,
    result: Option<Value>,
) -> SetupStep {
    SetupStep {
        id,
        status,
        command,
        detail,
        result,
    }
}

fn to_value<T: serde::Serialize>(data: &T) -> Result<Value, OpError> {
    serde_json::to_value(data).map_err(|err| {
        OpError::new(
            ErrorCode::Internal,
            format!("could not encode a step result: {err}"),
        )
    })
}

/// Check every input before the first step runs (ADR-0024 결정 7). Nothing
/// echoes the certificate or the code, only which rule they broke.
fn validate(req: &SetupRunReq) -> Result<(), OpError> {
    let role = req.role;
    let Some(name) = req.name.as_deref() else {
        return Err(invalid(match role {
            SetupRole::Host | SetupRole::Listener => "--peer <name> is required",
            SetupRole::HostTo => "--to <name> is required",
            SetupRole::Client => "the peer name is required",
        }));
    };
    crate::ops::validate_peer_label_arg(name)?;

    let needs_address = matches!(role, SetupRole::HostTo | SetupRole::Client);
    match (req.address.as_deref(), needs_address) {
        (None, true) => return Err(invalid("--address <host[:port]> is required for this role")),
        (Some(_), false) => return Err(invalid("--address does not apply to this role")),
        (Some(address), true) => {
            if address.trim().is_empty()
                || address.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(invalid(
                    "--address must be a host or host:port without whitespace",
                ));
            }
        }
        (None, false) => {}
    }

    if req.peer_cert_pem.is_some() && req.code.is_some() {
        return Err(invalid(
            "an invite code and --peer-cert are different ways to pin; give one",
        ));
    }
    match role {
        SetupRole::HostTo | SetupRole::Listener => {
            if req.peer_cert_pem.is_none() {
                return Err(invalid("--peer-cert is required for this role"));
            }
            if req.code.is_some() {
                return Err(invalid("an invite code does not apply to this role"));
            }
        }
        SetupRole::Host => {
            if req.code.is_some() {
                return Err(invalid("an invite code does not apply to this role"));
            }
        }
        SetupRole::Client => {
            if req.peer_cert_pem.is_none() && req.code.is_none() {
                return Err(invalid("an invite code or --peer-cert is required"));
            }
            if req.service {
                return Err(invalid("--service does not apply to this role"));
            }
        }
    }
    if req.forward && !matches!(role, SetupRole::Host | SetupRole::HostTo) {
        return Err(invalid("--forward does not apply to this role"));
    }

    if let Some(pem) = req.peer_cert_pem.as_deref() {
        crate::ops::check_cert_pem_size(pem)?;
        crate::identity::pem::single_certificate(pem).map_err(crate::ops::cert_pem_op_error)?;
    }
    if let Some(code) = req.code.as_deref() {
        qsh_proto::pairing::parse_invite_code(code).map_err(|err| invalid(err.to_string()))?;
    }
    Ok(())
}

/// The pin name (`validate` guarantees it exists).
fn pin_name(req: &SetupRunReq) -> &str {
    req.name.as_deref().unwrap_or("")
}

fn peer_named<'a>(peers: &'a [TrustPeer], name: &str) -> Option<&'a TrustPeer> {
    peers.iter().find(|peer| peer.name == name)
}

impl Ops {
    /// `setup.run`, read-only: the steps `req.role` needs, each marked
    /// `already` when the current state satisfies it and `pending`
    /// otherwise. Writes nothing. Steps are judged independently, so a plan
    /// never reports `blocked`.
    pub fn setup_plan(&self, req: &SetupRunReq, env: &SetupEnv) -> Result<SetupRunData, OpError> {
        validate(req)?;
        let mut steps = Vec::new();
        for id in step_order(req.role, req.peer_cert_pem.is_some()) {
            steps.push(self.setup_eval(req, env, id, Mode::Plan)?);
        }
        Ok(assemble(req, steps))
    }

    /// Run one step. It changes state only through the existing `Ops`
    /// method the step names, and only when the step is not already
    /// satisfied. The caller decides order and blocking; [`Ops::setup_run`]
    /// is the non-interactive driver.
    pub fn setup_step(
        &self,
        req: &SetupRunReq,
        env: &SetupEnv,
        id: SetupStepId,
    ) -> Result<SetupStep, OpError> {
        validate(req)?;
        self.setup_eval(req, env, id, Mode::Run)
    }

    /// The non-interactive `setup.run`: validate every input, run the
    /// role's steps in order, and stop running writing steps once one is
    /// `pending`. `mode_config` and `acl` only read, so they are still
    /// evaluated after a `pending` step (ADR-0024 결정 8).
    ///
    /// **Runtime caveat:** `identity` and `pair` block on a key store and a
    /// nested runtime; call this outside a tokio runtime.
    pub fn setup_run(&self, req: &SetupRunReq, env: &SetupEnv) -> Result<SetupRunData, OpError> {
        validate(req)?;
        let mut steps: Vec<SetupStep> = Vec::new();
        let mut blocked = false;
        for id in step_order(req.role, req.peer_cert_pem.is_some()) {
            if blocked && !is_read_only_step(id) {
                steps.push(step(
                    id,
                    SetupStatus::Blocked,
                    self.setup_command(req, id),
                    Some("waiting on an earlier step that is still pending".to_string()),
                    None,
                ));
                continue;
            }
            match self.setup_eval(req, env, id, Mode::Run) {
                Ok(done) => {
                    if done.status == SetupStatus::Pending {
                        blocked = true;
                    }
                    steps.push(done);
                }
                Err(err) => return Err(annotate(err, id, &steps)),
            }
        }
        Ok(assemble(req, steps))
    }

    fn setup_eval(
        &self,
        req: &SetupRunReq,
        env: &SetupEnv,
        id: SetupStepId,
        mode: Mode,
    ) -> Result<SetupStep, OpError> {
        match id {
            SetupStepId::Identity => self.setup_identity(req, mode),
            SetupStepId::ModeConfig => self.setup_mode_config(req),
            SetupStepId::Acl => self.setup_acl(req, env),
            SetupStepId::PinCert => self.setup_pin_cert(req, mode),
            SetupStepId::Pair => self.setup_pair(req, mode),
            SetupStepId::Invite => self.setup_invite(req, env, mode),
            SetupStepId::Service => self.setup_service(req, env, mode),
            SetupStepId::Doctor => self.setup_doctor(req, env, mode),
        }
    }

    /// The standalone command that does what step `id` does (ADR-0024
    /// 결정 9), so a person or a provisioning script can follow it without
    /// `qsh setup`. An invite code is never spelled out.
    fn setup_command(&self, req: &SetupRunReq, id: SetupStepId) -> String {
        let name = pin_name(req);
        match id {
            SetupStepId::Identity => "qsh init".to_string(),
            // Relative on purpose: the location is a machine fact the
            // human renderer prints, and a fixture must not embed it.
            SetupStepId::ModeConfig => "edit config.toml".to_string(),
            SetupStepId::Acl => {
                let first = required_actions(req).first().copied().unwrap_or("exec.run");
                format!("qsh acl check --principal device:{name} --action {first}")
            }
            SetupStepId::PinCert => match req.address.as_deref() {
                Some(address) => {
                    format!("qsh trust add {name} --cert-file <peer.pem> --address {address}")
                }
                None => format!("qsh trust add {name} --cert-file <peer.pem>"),
            },
            SetupStepId::Pair => format!(
                "qsh pair accept {} <code> --as {name}",
                req.address.as_deref().unwrap_or("<address>")
            ),
            SetupStepId::Invite => format!("qsh pair invite --as {name}"),
            SetupStepId::Service => "qsh service install".to_string(),
            SetupStepId::Doctor => "qsh doctor".to_string(),
        }
    }

    fn setup_identity(&self, req: &SetupRunReq, mode: Mode) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::Identity);
        if crate::identity::read_identity(self.paths())?.is_some() {
            return Ok(step(
                SetupStepId::Identity,
                SetupStatus::Already,
                command,
                None,
                None,
            ));
        }
        if mode == Mode::Plan {
            return Ok(step(
                SetupStepId::Identity,
                SetupStatus::Pending,
                command,
                Some("no device identity yet; `qsh setup` creates one".to_string()),
                None,
            ));
        }
        let data = self.identity_init(IdentityInitReq::default())?;
        let status = if data.created {
            SetupStatus::Done
        } else {
            SetupStatus::Already
        };
        Ok(step(
            SetupStepId::Identity,
            status,
            command,
            None,
            Some(to_value(&data)?),
        ))
    }

    fn setup_mode_config(&self, req: &SetupRunReq) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::ModeConfig);
        let name = pin_name(req);
        let config = self.config()?;
        let inferred = crate::ops::doctor::infer_run_mode(&config);
        let target = crate::serve::config_outbound_target(&config)?;

        let problem: Option<String> = match req.role {
            SetupRole::Host if inferred != "serve" => Some(if inferred == "listen" {
                "config.toml has a [listen] table, so this machine is set up for `qsh listen`. \
                 Remove the [listen] table to run `qsh serve`, or use `qsh setup listener`."
                    .to_string()
            } else {
                "config.toml sets [serve].to or [reverse].controller, so `qsh serve` would dial \
                 out. Remove that key to accept inbound connections, or use `qsh setup host --to`."
                    .to_string()
            }),
            SetupRole::Listener if inferred != "listen" => Some(
                "config.toml has no [listen] table. Add one so this machine runs `qsh listen`:\n\
                 [listen]\nbind = \"[::]:4433\""
                    .to_string(),
            ),
            SetupRole::HostTo if inferred == "listen" => Some(format!(
                "config.toml has a [listen] table, which takes precedence over an outbound \
                 target. Remove it, then set:\n[serve]\nto = \"{name}\""
            )),
            SetupRole::HostTo if target.as_deref() != Some(name) => Some(match target {
                Some(current) => format!(
                    "config.toml points `qsh serve` at {current:?}, not {name:?}. Set:\n\
                     [serve]\nto = \"{name}\""
                ),
                None => {
                    format!("config.toml has no outbound target. Add:\n[serve]\nto = \"{name}\"")
                }
            }),
            _ => None,
        };
        Ok(match problem {
            Some(detail) => step(
                SetupStepId::ModeConfig,
                SetupStatus::Pending,
                command,
                Some(detail),
                None,
            ),
            None => step(
                SetupStepId::ModeConfig,
                SetupStatus::Already,
                command,
                None,
                None,
            ),
        })
    }

    fn setup_acl(&self, req: &SetupRunReq, env: &SetupEnv) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::Acl);
        let name = pin_name(req);
        let principal = format!("device:{name}");
        let mut results: Vec<AclCheckData> = Vec::new();
        for action in required_actions(req) {
            results.push(self.acl_check(AclCheckReq {
                principal: principal.clone(),
                action: action.to_string(),
                resource: None,
                auth_path: Some("pin".to_string()),
                owner: None,
                owner_auth_path: None,
            })?);
        }
        let loaded = results.first().is_some_and(|r| r.policy.loaded);
        let denied: Vec<&str> = results
            .iter()
            .filter(|r| r.decision != "allow")
            .map(|r| r.action.as_str())
            .collect();

        let mut problems: Vec<String> = Vec::new();
        if !loaded {
            problems.push(String::from(
                "no usable acl.toml: every request is denied until it exists and parses. \
                 Save the rows in `acl_rows` there (`policy.path` in the result names the file).",
            ));
        } else if !denied.is_empty() {
            problems.push(format!(
                "acl.toml does not allow {principal} to: {}. Add the rows in `acl_rows`.",
                denied.join(", ")
            ));
        }
        if req.role == SetupRole::Host {
            let counts = crate::trust::live_invite_counts(&self.paths().invites_file(), env.now)?;
            if counts.unassigned > 0 {
                problems.push(format!(
                    "{} live invite(s) were minted without --as: whoever redeems one could \
                     claim {name:?} and inherit these rows. They stop being redeemable within \
                     {INVITE_TTL_TEXT}; run this again then.",
                    counts.unassigned
                ));
            }
        }
        let result = Some(to_value(&results)?);
        if problems.is_empty() {
            Ok(step(
                SetupStepId::Acl,
                SetupStatus::Already,
                command,
                Some(ACL_RESTART_NOTICE.to_string()),
                result,
            ))
        } else {
            Ok(step(
                SetupStepId::Acl,
                SetupStatus::Pending,
                command,
                Some(problems.join(" ")),
                result,
            ))
        }
    }

    fn setup_pin_cert(&self, req: &SetupRunReq, mode: Mode) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::PinCert);
        let name = pin_name(req);
        let Some(pem) = req.peer_cert_pem.as_deref() else {
            return Ok(step(
                SetupStepId::PinCert,
                SetupStatus::Pending,
                command,
                Some("a peer certificate file (--peer-cert) is required".to_string()),
                None,
            ));
        };
        let (_der, fingerprint) =
            crate::identity::pem::single_certificate(pem).map_err(crate::ops::cert_pem_op_error)?;
        let fp = fingerprint.to_string();
        let peers = self.trust_list()?.peers;
        let address = req
            .address
            .as_deref()
            .map(|a| crate::trust::normalize_peer_address(a).address);

        if let Some(existing) = peer_named(&peers, name) {
            if existing.fingerprint != fp {
                return Ok(step(
                    SetupStepId::PinCert,
                    SetupStatus::Pending,
                    command,
                    Some(format!(
                        "{name:?} is already pinned with a different fingerprint ({}); \
                         `trust add` would silently keep it. If the key change is intended, run \
                         `qsh trust remove {name}` and run this again.",
                        existing.fingerprint
                    )),
                    None,
                ));
            }
            if address.is_none() || address.as_deref() == Some(existing.address.as_str()) {
                return Ok(step(
                    SetupStepId::PinCert,
                    SetupStatus::Already,
                    command,
                    None,
                    None,
                ));
            }
        } else if let Some(other) = peers.iter().find(|peer| peer.fingerprint == fp) {
            return Ok(step(
                SetupStepId::PinCert,
                SetupStatus::Pending,
                command,
                Some(format!(
                    "this certificate is already pinned as {:?}. A second name for one \
                     fingerprint never matches an [[acl]] row. Run `qsh trust remove {}` or \
                     `qsh trust rename {} {name}` and run this again.",
                    other.name, other.name, other.name
                )),
                None,
            ));
        }
        if mode == Mode::Plan {
            return Ok(step(
                SetupStepId::PinCert,
                SetupStatus::Pending,
                command,
                Some(format!("will pin {fp} as {name:?}")),
                None,
            ));
        }
        let data = self.trust_add(TrustAddReq {
            name: name.to_string(),
            address,
            fingerprint: None,
            // Always the certificate: without one `trust_add` would dial the
            // peer and offer whatever it presents (ADR-0024 결정 3, 6).
            cert_pem: Some(pem.to_string()),
        })?;
        Ok(step(
            SetupStepId::PinCert,
            SetupStatus::Done,
            command,
            None,
            Some(to_value(&data)?),
        ))
    }

    fn setup_pair(&self, req: &SetupRunReq, mode: Mode) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::Pair);
        let name = pin_name(req);
        let peers = self.trust_list()?.peers;
        if let Some(existing) = peer_named(&peers, name) {
            return Ok(step(
                SetupStepId::Pair,
                SetupStatus::Already,
                command,
                Some(format!(
                    "{name:?} is already pinned ({}); the fingerprint was not compared to the \
                     peer's",
                    existing.fingerprint
                )),
                None,
            ));
        }
        if mode == Mode::Plan {
            return Ok(step(
                SetupStepId::Pair,
                SetupStatus::Pending,
                command,
                Some("redeem the invite code from the host".to_string()),
                None,
            ));
        }
        let (Some(address), Some(code)) = (req.address.as_deref(), req.code.as_deref()) else {
            return Err(invalid("an invite code and --address are required to pair"));
        };
        let data = self.trust_accept(TrustAcceptReq {
            address: address.to_string(),
            code: code.to_string(),
            as_name: Some(name.to_string()),
        })?;
        let peers = self.trust_list()?.peers;
        Ok(pair_outcome(
            command,
            name,
            &data.peer.fingerprint,
            &peers,
            to_value(&data)?,
        ))
    }

    fn setup_invite(
        &self,
        req: &SetupRunReq,
        env: &SetupEnv,
        mode: Mode,
    ) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::Invite);
        let name = pin_name(req);
        let peers = self.trust_list()?.peers;
        if peer_named(&peers, name).is_some() {
            return Ok(step(
                SetupStepId::Invite,
                SetupStatus::Already,
                command,
                None,
                None,
            ));
        }
        if mode == Mode::Plan {
            return Ok(step(
                SetupStepId::Invite,
                SetupStatus::Pending,
                command,
                Some(format!(
                    "will mint an invite that pins the redeemer as {name:?}"
                )),
                None,
            ));
        }
        let earlier = crate::trust::live_invite_counts(&self.paths().invites_file(), env.now)?
            .assigned_to(name);
        // Always `--as`: the redeemer is pinned under the name the ACL rows
        // were written for, whatever it calls itself (ADR-0024 결정 5).
        let data = self.trust_invite(TrustInviteReq {
            as_name: Some(name.to_string()),
        })?;
        let detail = (earlier > 0).then(|| {
            format!(
                "{earlier} earlier invite code(s) for {name:?} are still live; only one can be \
                 redeemed, and a second redemption ends in SESSION_CONFLICT"
            )
        });
        Ok(step(
            SetupStepId::Invite,
            SetupStatus::Done,
            command,
            detail,
            Some(to_value(&data)?),
        ))
    }

    fn setup_service(
        &self,
        req: &SetupRunReq,
        env: &SetupEnv,
        mode: Mode,
    ) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::Service);
        if !req.service {
            return Ok(step(
                SetupStepId::Service,
                SetupStatus::Skipped,
                command,
                Some("not requested; pass --service to write the unit file".to_string()),
                None,
            ));
        }
        // `UNSUPPORTED` is the one op error that is not a failure here
        // (ADR-0024 결정 8, 10): this platform has no service manager.
        let skip_or_fail = |err: OpError| -> Result<SetupStep, OpError> {
            if err.code == ErrorCode::Unsupported {
                Ok(step(
                    SetupStepId::Service,
                    SetupStatus::Skipped,
                    command.clone(),
                    Some(err.message),
                    None,
                ))
            } else {
                Err(err)
            }
        };
        let status = match self.service_status_with_home(env.home.clone()) {
            Ok(status) => status,
            Err(err) => return skip_or_fail(err),
        };
        if status.installed {
            return Ok(step(
                SetupStepId::Service,
                SetupStatus::Already,
                command,
                Some(
                    "the unit is left as it is; if you changed config.toml or moved the binary, \
                     run `qsh service install` again"
                        .to_string(),
                ),
                None,
            ));
        }
        if mode == Mode::Plan {
            return Ok(step(
                SetupStepId::Service,
                SetupStatus::Pending,
                command,
                Some("will write the service unit file".to_string()),
                None,
            ));
        }
        match self.service_install_with_home(env.home.clone()) {
            Ok(data) => Ok(step(
                SetupStepId::Service,
                SetupStatus::Done,
                command,
                None,
                Some(to_value(&data)?),
            )),
            Err(err) => skip_or_fail(err),
        }
    }

    fn setup_doctor(
        &self,
        req: &SetupRunReq,
        env: &SetupEnv,
        mode: Mode,
    ) -> Result<SetupStep, OpError> {
        let command = self.setup_command(req, SetupStepId::Doctor);
        if mode == Mode::Plan {
            return Ok(step(
                SetupStepId::Doctor,
                SetupStatus::Pending,
                command,
                Some("runs after the other steps".to_string()),
                None,
            ));
        }
        let data = self.doctor(DoctorReq { host: None }, env.now)?;
        let detail = format!("overall: {}", data.overall);
        Ok(step(
            SetupStepId::Doctor,
            SetupStatus::Done,
            command,
            Some(detail),
            Some(to_value(&data)?),
        ))
    }
}

/// The `pair` outcome once `trust.accept` succeeded: `pending` if the same
/// fingerprint is now pinned under another name too, because the ACL row for
/// `name` would never match (ADR-0024 결정 6). The earlier pin is a person's,
/// so it is not undone.
fn pair_outcome(
    command: String,
    name: &str,
    fingerprint: &str,
    peers: &[TrustPeer],
    result: Value,
) -> SetupStep {
    if let Some(other) = peers
        .iter()
        .find(|peer| peer.fingerprint == fingerprint && peer.name != name)
    {
        return step(
            SetupStepId::Pair,
            SetupStatus::Pending,
            command,
            Some(format!(
                "this peer was already pinned as {:?}, so {name:?} shares its fingerprint and an \
                 [[acl]] row for {name:?} would never match. Keep one name: `qsh trust remove {}` \
                 or `qsh trust remove {name}`.",
                other.name, other.name
            )),
            Some(result),
        );
    }
    step(
        SetupStepId::Pair,
        SetupStatus::Done,
        command,
        None,
        Some(result),
    )
}

impl Ops {
    /// [`pair_outcome`] for a test that pins the fingerprint by hand; the
    /// dial itself needs a live host.
    #[cfg(test)]
    pub(crate) fn setup_pair_after_accept(&self, name: &str, fingerprint: &str) -> SetupStep {
        let peers = self.trust_list().expect("trust list").peers;
        pair_outcome(
            format!("qsh pair accept <address> <code> --as {name}"),
            name,
            fingerprint,
            &peers,
            Value::Null,
        )
    }
}

/// Put `details.step` and `details.steps` (ids and statuses, never results)
/// on a failed op's error, keeping its `code` and `retryable` (ADR-0024
/// 결정 10).
fn annotate(mut err: OpError, failed: SetupStepId, done: &[SetupStep]) -> OpError {
    let steps: Vec<Value> = done
        .iter()
        .map(|s| json!({ "id": id_str(s.id), "status": status_str(s.status) }))
        .collect();
    let mut details = match std::mem::take(&mut err.details) {
        Value::Object(map) => map,
        Value::Null => serde_json::Map::new(),
        other => {
            let mut map = serde_json::Map::new();
            map.insert("cause".to_string(), other);
            map
        }
    };
    details.insert("step".to_string(), json!(id_str(failed)));
    details.insert("steps".to_string(), Value::Array(steps));
    err.details = Value::Object(details);
    err
}

/// Roll the steps into `SetupRunData`: `acl_rows`, `next`, `complete`.
fn assemble(req: &SetupRunReq, steps: Vec<SetupStep>) -> SetupRunData {
    let name = pin_name(req);
    let has_acl = steps.iter().any(|s| s.id == SetupStepId::Acl);
    let acl_rows = has_acl.then(|| acl_rows_text(req, name));
    let any_open = steps
        .iter()
        .any(|s| matches!(s.status, SetupStatus::Pending | SetupStatus::Blocked));
    let doctor_error = steps.iter().any(|s| {
        s.id == SetupStepId::Doctor
            && s.result
                .as_ref()
                .and_then(|r| r.get("overall"))
                .and_then(Value::as_str)
                == Some("error")
    });
    let complete = !any_open && !doctor_error;

    let mut next: Vec<String> = Vec::new();
    for s in steps.iter().filter(|s| s.status == SetupStatus::Pending) {
        if s.id == SetupStepId::Acl {
            next.push(
                "save the rows in `acl_rows` to acl.toml, then run `qsh setup` again".to_string(),
            );
        } else {
            next.push(s.command.clone());
        }
    }
    if complete {
        match req.role {
            SetupRole::Host => {
                next.push(if req.service {
                    "activate the unit as in docs/deploy/service.md".to_string()
                } else {
                    "qsh serve".to_string()
                });
                let minted = steps
                    .iter()
                    .any(|s| s.id == SetupStepId::Invite && s.status == SetupStatus::Done);
                if minted {
                    next.push(
                        "on the peer, before the invite expires: \
                         qsh setup client <host-name> --address <this-host:port> <code>"
                            .to_string(),
                    );
                }
            }
            SetupRole::HostTo => next.push(format!("qsh serve --to {name}")),
            SetupRole::Listener => next.push("qsh listen".to_string()),
            SetupRole::Client => next.push(format!("qsh {name}")),
        }
    }
    SetupRunData {
        role: req.role,
        complete,
        steps,
        acl_rows,
        next,
    }
}
