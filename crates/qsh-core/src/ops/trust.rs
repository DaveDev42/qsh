//! `trust.*` operations and the shared trust store: add, list, remove, invite, accept.

use super::*;

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

        // ADR-0014 결정 3: op 진입점에서 한 번. 아래 세 사용처(probe dial,
        // TRUST_REQUIRED details.address, add_peer) 전부 이 값을 쓴다.
        let address = req
            .address
            .as_deref()
            .map(|address| crate::trust::normalize_peer_address(address).address);

        let fingerprint = match req.fingerprint.as_deref() {
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
    pub fn trust_invite(&self, _req: TrustInviteReq) -> Result<TrustInviteData, OpError> {
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
        let (_created_at, expires_at) = store.add(secret.as_slice(), now);
        store.save(&path)?;

        let code = qsh_proto::pairing::encode_invite_code(&secret);
        Ok(TrustInviteData {
            accept_command: format!("qsh trust accept <address> {code}"),
            code,
            expires_at,
        })
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
        // Report F-6: pin with the address this exchange just dialed
        // successfully (`req.address`, the same meaning `trust add
        // --address` gives it) rather than `None` — otherwise `qsh exec
        // <peer>` right after a successful pairing would come back
        // `HOST_NOT_FOUND` (§6.1/§6.8: an address-less pin is never a
        // dial-address candidate), directly undercutting ADR-0002's SC1
        // (5-minute pairing to first connection).
        let (peer, created, updated) = store.add_peer(
            success.peer_device_name.clone(),
            Some(address.clone()),
            observed_fp,
            now_rfc3339(),
        );
        if !created && !updated && peer.fingerprint != observed_fp.to_string() {
            return Err(OpError::new(
                ErrorCode::SessionConflict,
                format!(
                    "paired with {}, but {:?} is already pinned locally under a different \
                     identity; rename or remove the conflicting entry and retry",
                    address, success.peer_device_name
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
