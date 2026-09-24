//! `trust.*` operations and the shared trust store: add, list, remove, invite, accept.

use std::net::IpAddr;

use super::*;
use crate::trust::invite_address::{self, InviteAddressAdvice};

impl Ops {
    /// The shared, reload-on-change trust store to inject into the
    /// transport as a [`qsh_transport::TrustEvaluator`].
    pub fn open_trust(&self) -> Result<Arc<SharedTrustStore>, OpError> {
        SharedTrustStore::open(self.paths.trust_file())
    }

    // -----------------------------------------------------------------
    // trust
    // -----------------------------------------------------------------

    /// `trust.add` — pin a peer.
    ///
    /// With `--fingerprint` the peer is pinned **without connecting**
    /// (provisioning-friendly, `docs/CLI.md` §6.11). Without one, the peer
    /// is dialed once to observe its fingerprint and the result is always a
    /// `TRUST_REQUIRED` error carrying `details.observed_fingerprint` and
    /// `details.address`: the caller (human prompt or automation) verifies
    /// that value out of band and re-calls with `--fingerprint`. Nothing is
    /// ever pinned on the strength of what the network said.
    ///
    /// Re-adding an already-pinned name is idempotent, with one deliberate
    /// exception (`PLAN.md` M7 Step 2 decision B, `TrustStore::add_peer`'s
    /// own doc): the *same* fingerprint with a *different* `--address`
    /// overwrites the stored address in place (`data.updated: true`,
    /// `data.created` stays `false`) instead of being a no-op — the M6
    /// mobility campaign's backlog item. A *different* fingerprint is still
    /// a hard no-op on the whole entry; re-binding an identity is `trust
    /// remove` then `trust add`, never a side effect of a repeated call.
    pub fn trust_add(&self, req: TrustAddReq) -> Result<TrustAddData, OpError> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "peer name must not be empty",
            ));
        }

        if req.cert_pem.is_some() && req.fingerprint.is_some() {
            return Err(cert_file_fingerprint_conflict());
        }

        // ADR-0014 결정 3: op 진입점에서 한 번. 아래 세 사용처(probe dial,
        // TRUST_REQUIRED details.address, add_peer) 전부 이 값을 쓴다.
        let address = req
            .address
            .as_deref()
            .map(|address| crate::trust::normalize_peer_address(address).address);

        let fingerprint = if let Some(cert_pem) = req.cert_pem.as_deref() {
            // ADR-0013 결정 4/5: 구조 검증(라벨 multiset·단일 블록·X.509
            // 파싱)까지 마친 값만 fingerprint로 쓴다.
            let (_der, fingerprint) =
                crate::identity::pem::single_certificate(cert_pem).map_err(cert_pem_op_error)?;
            fingerprint
        } else {
            match req.fingerprint.as_deref() {
                Some(text) => text
                    .parse::<Fingerprint>()
                    .map_err(|err| OpError::new(ErrorCode::InvalidArgument, err.to_string()))?,
                None => {
                    let Some(address) = address.as_deref() else {
                        return Err(OpError::new(
                            ErrorCode::InvalidArgument,
                            "--address is required to observe a fingerprint",
                        ));
                    };
                    let observed = self.probe_fingerprint(address)?;
                    return Err(OpError::new(
                        ErrorCode::TrustRequired,
                        format!(
                            "peer {address} is not trusted; verify the fingerprint and re-run with \
                             --fingerprint"
                        ),
                    )
                    .with_retryable(false)
                    .with_details(serde_json::json!({
                        "observed_fingerprint": observed.to_string(),
                        "address": address,
                    })));
                }
            }
        };

        let path = self.paths.trust_file();
        // Whole load→mutate→save under lock, not just the write — a
        // concurrent `qsh serve` pairing response or another CLI process
        // racing this same read-modify-write must not have its change
        // silently discarded (`TrustStore::lock`'s own doc, `PLAN.md` M7
        // Step 7-1).
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let (peer, created, updated) = store.add_peer(name, address, fingerprint, now_rfc3339());
        if created || updated {
            store.save(&path)?;
        }
        Ok(TrustAddData {
            peer,
            created,
            updated: (!created).then_some(updated),
        })
    }

    /// `trust.list` — every pinned peer, in store order.
    pub fn trust_list(&self) -> Result<TrustListData, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        Ok(TrustListData {
            // ADR-0014 결정 4: 응답을 파생시키는 자리다. `TrustStore::save`
            // 경로가 아니므로 `trust.toml`의 바이트는 그대로다. 빈 `address`
            // (주소 없는 client-only pin)는 정규화가 항등이므로 빈 채로 남는다.
            peers: store
                .peers()
                .iter()
                .map(|peer| TrustPeer {
                    address: crate::trust::normalize_peer_address(&peer.address).address,
                    ..peer.clone()
                })
                .collect(),
        })
    }

    /// `trust.add_ca` — register a foreign CA root supplied by an operator
    /// as PEM text (`qsh trust add-ca`, ADR-0013 결정 3/4/5).
    ///
    /// Append-only, unlike [`TrustStore::add_ca`]'s local-re-init path
    /// (`qsh cert issue`): an existing `name` under a *different*
    /// `cert_pem` is refused (`INVALID_ARGUMENT`) rather than overwritten.
    /// The fingerprint `single_certificate` derives is computed only to
    /// validate the PEM's X.509 structure and is then discarded — a CA
    /// root has no principal of its own.
    pub fn trust_add_ca(&self, req: TrustAddCaReq) -> Result<TrustAddCaData, OpError> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                "CA name must not be empty",
            ));
        }
        let (_der, _fingerprint) =
            crate::identity::pem::single_certificate(&req.cert_pem).map_err(cert_pem_op_error)?;

        let path = self.paths.trust_file();
        // Whole load→mutate→save under lock — same discipline as every
        // other trust-store write (`TrustStore::lock`'s own doc).
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let (entry, created, updated) = store.add_ca_append_only(&name, req.cert_pem)?;
        if created {
            store.save(&path)?;
        }
        Ok(TrustAddCaData {
            name: entry.name,
            cert_pem: entry.cert_pem,
            created,
            updated: Some(updated),
        })
    }

    /// `trust.remove` — unpin a peer. Removing an unknown name is not an
    /// error (`removed: false`, idempotent).
    pub fn trust_remove(&self, name: &str) -> Result<TrustRemoveData, OpError> {
        let path = self.paths.trust_file();
        // See `trust_add`'s identical comment — whole cycle under lock.
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let removed = store.remove(name);
        if removed {
            store.save(&path)?;
        }
        Ok(TrustRemoveData {
            name: name.to_string(),
            removed,
        })
    }

    /// `trust.rename` — rename a pinned peer without unpinning it
    /// (`docs/CLI.md` §6.11, ADR-0012 결정 7). No ACL surface: this is a
    /// local operator op against the operator's own `trust.toml`, not an
    /// authorization decision, so `acl::Action` gains no variant for it
    /// (`AuditRecord::local_op`'s own doc).
    ///
    /// `new` is validated first (§4's `validate_peer_label`), then `old !=
    /// new` — both `INVALID_ARGUMENT`, before the store is even opened.
    /// The remaining cycle is `TrustStore::lock` → `load` → `rename` →
    /// **audit record** → `save`, all under the one lock: a crash between
    /// `rename` and `save` is invisible (the in-memory mutation is
    /// discarded with the process), but a crash between the audit write
    /// and `save` must never happen with the audit record durable and the
    /// rename lost — hence audit *before* save, matching `AuditRecord::
    /// local_op`'s "no record, no rename" contract. Lock order: `trust.
    /// toml.lock` first (already held for the whole call), then whatever
    /// lock `sink.record` takes internally ([`FileAuditSink`]'s own
    /// `Mutex`) — never the other way around, so this can never deadlock
    /// against a concurrent audit write started from elsewhere.
    ///
    /// Errors: `new` failing [`crate::trust::validate_peer_label`] or `old
    /// == new` is `INVALID_ARGUMENT`; `old` naming no pinned peer is
    /// `HOST_NOT_FOUND`; `new` colliding with an existing peer or CA label
    /// is `SESSION_CONFLICT` (`retryable: false` — retrying with the same
    /// arguments can never succeed); an unreadable `trust.toml` or
    /// `config.toml` is `CONFIG_ERROR`; a failed audit write is
    /// `INTERNAL` (`retryable: true`) and leaves `trust.toml` untouched.
    pub fn trust_rename(&self, req: TrustRenameReq) -> Result<TrustRenameData, OpError> {
        let new = validate_peer_label_arg(&req.new)?;
        if req.old == new {
            return Err(
                OpError::new(ErrorCode::InvalidArgument, "old and new names must differ")
                    .with_retryable(false),
            );
        }

        let path = self.paths.trust_file();
        // Whole load→mutate→audit→save under lock — same discipline as
        // every other trust-store write (`TrustStore::lock`'s own doc),
        // extended here to cover the audit write too (this fn's own doc).
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        let peer = store.rename(&req.old, &new).map_err(|err| match err {
            crate::trust::RenameError::OldMissing => OpError::new(
                ErrorCode::HostNotFound,
                format!("{:?} is not a pinned peer", req.old),
            )
            .with_retryable(false),
            crate::trust::RenameError::NewTaken => OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "{new:?} already names a pinned peer or a CA root; \
                     remove or rename that entry first"
                ),
            )
            .with_retryable(false),
        })?;

        let record = AuditRecord::local_op(
            "trust.rename",
            Principal::Device(req.old.clone()).to_string(),
            Principal::Device(new.clone()).to_string(),
        );
        let sink: Arc<dyn AuditSink> = match &self.audit {
            Some(sink) => Arc::clone(sink),
            None => Arc::new(FileAuditSink::new(
                Config::load(&self.paths)?.audit.path(&self.paths),
            )),
        };
        sink.record(&record).map_err(|err| {
            OpError::new(
                ErrorCode::Internal,
                format!("audit record could not be written; trust.toml left unchanged: {err}"),
            )
            .with_retryable(true)
        })?;

        store.save(&path)?;

        Ok(TrustRenameData {
            peer,
            old_name: req.old,
        })
    }

    /// `trust.invite` — mint a one-time pairing invite (ADR-0002, `PLAN.md`
    /// M7 Step 4).
    ///
    /// The raw secret exists only for the lifetime of this call: it is
    /// generated, hashed into `invites.toml` (never the raw bytes —
    /// `crate::trust::pairing`'s own module doc), rendered as the Crockford
    /// Base32 display code, and zeroized on drop before this returns. `qsh
    /// serve`'s own `SharedInviteStore` picks up the freshly written invite
    /// on its very next check, without a restart (Step 2's content-based
    /// reload, invariant #6). `accept_command` is the exact command line to
    /// hand the other party — the code alone carries no address (`PLAN.md`
    /// M7 §4.1 #7), so this is the only place that pairing is complete.
    pub fn trust_invite(&self, req: TrustInviteReq) -> Result<TrustInviteData, OpError> {
        let assigned_name = req
            .as_name
            .map(|name| validate_peer_label_arg(&name))
            .transpose()?;

        let secret = crate::trust::pairing::generate_secret();
        let now = std::time::SystemTime::now();
        let path = self.paths.invites_file();
        // Whole load→mutate→save under lock, not just the write — closes
        // report F-9's residual lost-update window against a concurrent
        // `qsh serve` redeeming a different invite at the same time
        // (`InviteStore::lock`'s own doc, `PLAN.md` M7 Step 7-1).
        let _lock = crate::trust::pairing::InviteStore::lock(&path)?;
        let mut store = crate::trust::pairing::InviteStore::load(&path)?;
        store.prune(now);
        let (_created_at, expires_at) = store.add(secret.as_slice(), now, assigned_name.clone());
        store.save(&path)?;

        let code = qsh_proto::pairing::encode_invite_code(&secret);
        Ok(TrustInviteData {
            assigned_name,
            accept_command: format!("qsh pair accept <address> {code}"),
            code,
            expires_at,
        })
    }

    /// The human-mode address block that goes under `trust.invite`'s
    /// `accept_command` (`docs/CLI.md` §6.11): candidate `host:port`
    /// strings for the `<address>` placeholder, or the single line that
    /// says why there are none.
    ///
    /// Deliberately **not** part of [`Self::trust_invite`]'s result.
    /// `TrustInviteData` is a `qsh.cli/v1` contract type and this is a
    /// routing observation about the machine the CLI happens to be running
    /// on — merging the two would put a host-local, unverifiable fact
    /// inside a frozen envelope, and would make every machine-mode caller
    /// pay for an observation it never asked for. Keeping them separate is
    /// also what lets the frontend call this from inside `finish`'s
    /// human-only closure, so machine mode makes no route query at all.
    ///
    /// The port comes from this host's `[serve].bind`, or
    /// [`crate::serve::DEFAULT_PORT`] when `config.toml` names none or
    /// cannot be read at all — an unreadable config is a bigger problem
    /// than this line and must not turn an invite into an error, so it
    /// degrades to the default the wording already names.
    pub fn invite_address_advice(&self) -> InviteAddressAdvice {
        self.invite_address_advice_with(invite_address::route::observe_source_addresses)
    }

    /// [`Self::invite_address_advice`] over a caller-supplied observation.
    ///
    /// The injected-observation seam: the effect arrives as an argument
    /// and nothing is stored, the same shape
    /// `crate::doctor::probe::detect_path_shadow` and
    /// `crate::doctor::probe::keystore_finding` use, and for the reason
    /// their own docs give — so the rule under test is tested against a
    /// fixed input instead of against whatever the machine running the
    /// tests happens to have. (`crate::serve::run_serve`'s
    /// `on_bound`/`on_notice` parameters are the same shape on the
    /// effect-out side.) `FnOnce` is the minimum bound: the observation
    /// happens exactly once.
    pub fn invite_address_advice_with(
        &self,
        observe: impl FnOnce() -> Vec<IpAddr>,
    ) -> InviteAddressAdvice {
        let config = self.config().ok();
        let port = invite_address::port_from_bind_spec(
            config
                .as_ref()
                .and_then(|config| config.serve.bind.as_deref()),
        );
        invite_address::assemble(&observe(), port)
    }

    /// `trust.accept <address> <code>` — complete a pairing exchange with
    /// `qsh trust invite`'s counterpart (ADR-0002, `PLAN.md` M7 Step 4).
    ///
    /// Dials `address` with a trust evaluator that accepts *any*
    /// certificate ([`crate::pairing::AcceptAnyForPairing`], report §B3) —
    /// pairing's real authentication is possession of `code`'s secret,
    /// proven over a TLS-exporter-bound channel
    /// ([`crate::pairing::accept`]), never the TLS identity presented. Only
    /// once the responder's own proof has verified (never on the strength
    /// of a reply merely arriving — report §B13) is the responder pinned,
    /// using this connection's own observed fingerprint, via the same
    /// [`TrustStore::add_peer`] path `qsh trust add` uses. A name collision
    /// here (the responder's self-reported name already pinned locally
    /// under a *different* fingerprint) fails loudly with `SESSION_CONFLICT`
    /// — unlike `trust add`'s own established silent no-op on the same
    /// underlying case (`TrustStore::add_peer`'s own doc; left untouched).
    ///
    /// **Runtime caveat:** loads the identity synchronously — call it
    /// outside a tokio runtime (see [`Self::load_identity`]).
    pub fn trust_accept(&self, req: TrustAcceptReq) -> Result<TrustAcceptData, OpError> {
        // Validated before any dial (fail fast, ADR-0012 결정 6) — a bad
        // `--as` must never spend a network round trip first.
        let as_name = req
            .as_name
            .map(|name| validate_peer_label_arg(&name))
            .transpose()?;

        let secret = qsh_proto::pairing::parse_invite_code(&req.code).map_err(|err| {
            OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
        })?;

        // ADR-0014 결정 3: dial·pin·오류 문면이 모두 같은 한 값을 쓴다.
        let address = crate::trust::normalize_peer_address(&req.address).address;

        let Some(loaded) = self.load_identity()? else {
            return Err(OpError::new(
                ErrorCode::ConfigError,
                format!(
                    "no device identity in {}; run qsh init first",
                    self.paths.config_dir.display()
                ),
            )
            .with_retryable(false));
        };
        let device_name = loaded.identity.device_id.clone();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                OpError::new(
                    ErrorCode::Internal,
                    format!("failed to start an async runtime: {err}"),
                )
                .with_retryable(false)
            })?;

        let dialer = Dialer::new(loaded.local, Arc::new(crate::pairing::AcceptAnyForPairing));
        let server_name = server_name_for(&address);
        let dial_address = address.clone();

        let outcome = runtime.block_on(async move {
            let socket = resolve_one(&dial_address).await?;
            let dialed = dialer
                .dial(socket, &server_name)
                .await
                .map_err(|err| classify_pairing_dial_failure(err, &dial_address))?;
            let success = crate::pairing::accept(&dialed.connection, &device_name, &secret)
                .await
                .map_err(classify_pairing_exchange_failure)?;
            let observed_fp = dialed.connection.peer_fingerprint().ok_or_else(|| {
                OpError::new(
                    ErrorCode::Internal,
                    "paired connection reported no peer certificate fingerprint",
                )
                .with_retryable(false)
            })?;
            dialed.connection.close(0, b"paired");
            Ok::<_, OpError>((success, observed_fp))
        });
        runtime.shutdown_timeout(Duration::from_millis(200));
        let (success, observed_fp) = outcome?;

        let path = self.paths.trust_file();
        // See `trust_add`'s identical comment — whole cycle under lock.
        // Acquired only now, after the network dial above has already
        // completed: the critical section stays a small local file
        // rewrite, never a network wait.
        let _lock = TrustStore::lock(&path)?;
        let mut store = TrustStore::load(&path)?;
        // The effective name: `--as` when given, else the responder's own
        // self-reported name (ADR-0012 결정 6) — used at both the pin site
        // and in the collision message below, never the self-asserted
        // value alone once `--as` overrides it. Re-validated here even
        // when it is the self-asserted name (already checked pre-dial
        // when it came from `--as`): the wire-level guard
        // (`crate::pairing::accept`'s `reject_control_chars`) only ran
        // `validate_device_name`, not the `/` rule, so this is the one
        // place a self-asserted name with `/` is caught — fail-closed,
        // same `INVALID_ARGUMENT` outcome the wire path's own
        // `InvalidDeviceName` mapping produces, and changes nothing for
        // qsh-generated `device_id`s.
        let effective_name = match as_name {
            Some(name) => name,
            None => validate_peer_label_arg(&success.pinned_name)?,
        };
        // Report F-6: pin with the address this exchange just dialed
        // successfully (`req.address`, the same meaning `trust add
        // --address` gives it) rather than `None` — otherwise `qsh exec
        // <peer>` right after a successful pairing would come back
        // `HOST_NOT_FOUND` (§6.1/§6.8: an address-less pin is never a
        // dial-address candidate), directly undercutting ADR-0002's SC1
        // (5-minute pairing to first connection).
        let (peer, created, updated) = store.add_peer(
            effective_name.clone(),
            Some(address.clone()),
            observed_fp,
            now_rfc3339(),
        );
        if !created && !updated && peer.fingerprint != observed_fp.to_string() {
            return Err(OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "paired with {address}, but {effective_name:?} is already pinned locally \
                     under a different identity; rename or remove the conflicting entry and retry"
                ),
            )
            .with_retryable(false));
        }
        if created || updated {
            store.save(&path)?;
        }
        Ok(TrustAcceptData {
            peer,
            created,
            updated: (!created).then_some(updated),
        })
    }
}

/// Validate an operator-supplied trust-store label (`--as` on `pair
/// invite`/`pair accept`, `trust rename`'s `new`) against the one shared
/// rule (`crate::trust::validate_peer_label`, ADR-0012 결정 6), mapping a
/// failure to `INVALID_ARGUMENT`. Never echoes `label` itself — only which
/// rule it broke (`crate::trust::PeerLabelError`'s own `Display`).
fn validate_peer_label_arg(label: &str) -> Result<String, OpError> {
    crate::trust::validate_peer_label(label)
        .map(|()| label.to_string())
        .map_err(|err| {
            OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
        })
}

/// Map a [`crate::identity::pem::CertPemError`] to the `INVALID_ARGUMENT`
/// [`OpError`] both `trust add --cert-file` and `trust add-ca` report for
/// it (ADR-0013 결정 4): `details` stays `Value::Null` and the message is
/// one of `CertPemError`'s own fixed strings — never an input byte.
fn cert_pem_op_error(err: crate::identity::pem::CertPemError) -> OpError {
    OpError::new(ErrorCode::InvalidArgument, err.to_string()).with_retryable(false)
}

/// The `--cert-file`/`--fingerprint` mutual-exclusion error `trust add`
/// reports (`docs/CLI.md` §6.11, ADR-0013). Exposed so the CLI can raise
/// it *before* reading `--cert-file` — a real path or, for `-`, standard
/// input — instead of after: reading first would otherwise block on an
/// unwritten stdin, or surface a file-read error, ahead of ever telling
/// the operator the two flags don't mix.
pub fn cert_file_fingerprint_conflict() -> OpError {
    OpError::new(
        ErrorCode::InvalidArgument,
        "--cert-file and --fingerprint are mutually exclusive",
    )
    .with_retryable(false)
}

/// Read PEM text from a real `--cert-file <path>` argument (`docs/CLI.md`
/// §6.11, ADR-0013). The CLI reads `-` (standard input) itself — this is
/// only the real-path case, called with the path exactly as the operator
/// gave it. A missing or unreadable path names a bad *argument*, not this
/// machine's own config tree, so it is `INVALID_ARGUMENT`
/// (`docs/CLI.md` §6.11), never `CONFIG_ERROR`; the
/// message names the path only, never any byte the file might contain.
pub fn read_cert_file_arg(path: &str) -> Result<String, OpError> {
    std::fs::read_to_string(path).map_err(|err| {
        OpError::new(
            ErrorCode::InvalidArgument,
            format!("failed to read {path}: {err}"),
        )
        .with_retryable(false)
    })
}
