use super::*;
use qsh_proto::KeyStoreKind;

fn temp_ops() -> (tempfile::TempDir, Ops) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));
    (dir, Ops::new(paths))
}

fn file_mode() -> IdentityInitReq {
    IdentityInitReq {
        key_store: Some(KeyStoreMode::File),
    }
}

#[test]
fn version_reports_schemas_and_own_version() {
    let (_guard, ops) = temp_ops();
    let data = ops.version().unwrap();
    assert_eq!(data.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(data.schemas, vec!["qsh.cli/v1", "qsh.event/v1"]);
}

/// `PLAN.md` M7 Step 7-2 ①: the shared dial runtime must be **lazy** —
/// nothing may build it until a `connect*` call actually reaches
/// [`Ops::connect_runtime`], or a purely local command (`qsh version`,
/// tested here) would pay for a `num_cpus`-sized `multi_thread`
/// runtime it never uses. Reaches into the private `connect_runtime`
/// `OnceLock` directly (this test module is `super`'s own, not an
/// external caller) rather than inferring laziness indirectly, so a
/// regression that starts eagerly building the runtime in `Ops::new`
/// is caught here rather than only showing up as a thread-count
/// regression under load.
#[test]
fn connect_runtime_is_lazy_until_first_connect_call() {
    let (_guard, ops) = temp_ops();
    assert!(
        ops.connect_runtime.get().is_none(),
        "Ops::new must not build the shared dial runtime eagerly"
    );
    // A local-only op — no host, no dial — must still leave it unbuilt.
    ops.version().unwrap();
    assert!(
        ops.connect_runtime.get().is_none(),
        "a local-only op (version.get) must not build the shared dial runtime"
    );
    // `qsh trust list` by name — the field doc on `Ops::connect_runtime`
    // points at it explicitly as a local-only op that must not force
    // the runtime into existence.
    ops.trust_list().unwrap();
    assert!(
        ops.connect_runtime.get().is_none(),
        "a local-only op (trust.list) must not build the shared dial runtime"
    );
    // The schema surface is local-only too (no host, no dial).
    ops.schema().unwrap();
    assert!(
        ops.connect_runtime.get().is_none(),
        "a local-only op (schema.get) must not build the shared dial runtime"
    );
}

/// The other half of `PLAN.md` M7 Step 7-2 ①: once built, the runtime
/// is **shared** — every `connect_runtime()` call on the same `Ops`
/// (and on every clone of it, since `Ops::clone` only bumps the outer
/// `Arc`'s refcount) returns a handle to the exact same
/// `tokio::runtime::Runtime`, not a fresh one per call. `Arc::ptr_eq`
/// is the direct claim — same allocation, not merely
/// equal-by-value — which is what makes a pull's per-call `Builder::
/// new_multi_thread()` (the 11-threads-per-pull cost this step
/// removes) actually go away.
#[test]
fn connect_runtime_is_the_same_instance_across_calls_and_clones() {
    let (_guard, ops) = temp_ops();
    let first = ops.connect_runtime().unwrap();
    let second = ops.connect_runtime().unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "two connect_runtime() calls on the same Ops must share one Runtime"
    );

    let cloned = ops.clone();
    let third = cloned.connect_runtime().unwrap();
    assert!(
        Arc::ptr_eq(&first, &third),
        "Ops::clone must not fork a second dial runtime"
    );

    // The other direction: a wholly independent `Ops` (its own
    // `Paths`, not a clone of the first) must NOT share the first's
    // runtime. The field doc on `Ops::connect_runtime` explicitly
    // rejects a `static OnceLock` for this reason — it "would outlive
    // `Ops` and break test isolation" — so this pins that rejection
    // both ways: same `Ops`/clones share one instance (above), a
    // second `Ops` gets its own.
    let (_other_guard, other_ops) = temp_ops();
    let other = other_ops.connect_runtime().unwrap();
    assert!(
        !Arc::ptr_eq(&first, &other),
        "two independent Ops instances must not share one dial runtime \
         (a static OnceLock would fail this)"
    );
}

/// Regression pin for the failure this step's own nextest run caught:
/// `qsh-testkit::reverse_attach
/// detaching_leaves_the_session_running_and_a_reattach_replays_the_retained_ring`
/// panicked with "Cannot drop a runtime in a context where blocking is
/// not allowed" the first time `Ops`'s shared runtime shipped as a bare
/// `Arc<tokio::runtime::Runtime>`. Root cause: `connect_runtime` is
/// reference-counted and shared, so its very last `Arc` can be dropped
/// almost anywhere — that fixture builds an `Ops` inside a
/// `#[tokio::test]` and drops it before the async test function
/// returns, and the plain `Runtime::drop` blocks (panicking if that
/// block happens on a thread already executing inside *any* async
/// task). [`SharedRuntime`] fixes this generally by routing its `Drop`
/// through `Runtime::shutdown_background` instead. This test
/// reproduces the minimal shape directly, without going through a full
/// loopback fixture: populate the shared-runtime cell, then drop the
/// `Ops` that owns it from inside a *different*, already-running
/// runtime. Passing (not panicking) is the assertion.
#[test]
fn dropping_ops_with_a_live_shared_runtime_from_inside_another_runtime_does_not_panic() {
    let (_guard, ops) = temp_ops();
    ops.connect_runtime()
        .expect("build the shared runtime so there is something to drop");

    let outer = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build the outer async context this test drops `ops` from");
    outer.block_on(async move {
        // `ops` (and with it, `connect_runtime`'s last `Arc<SharedRuntime>`)
        // drops here, on a thread `outer` currently has executing this
        // async block — exactly the context the plain `Runtime::drop`
        // cannot tolerate.
        drop(ops);
    });
}

/// The other half of that same `Drop`: outside any runtime context it
/// must *not* return while the runtime's threads are still running.
/// `qsh`'s `main` calls `std::process::exit` immediately after the last
/// `Ops` goes away, and on Windows a worker thread killed mid-teardown
/// deadlocks the exiting process for good — the failure
/// [`SharedRuntime`]'s own doc describes, seen as intermittent
/// `exit_code_matrix`/`exec_e2e` timeouts on Windows CI. The deadlock
/// itself is Windows-only and inherently racy, so what is pinned here is
/// the property that removes it, which holds on every platform: a
/// blocking task still running when the drop starts has finished by the
/// time it returns.
#[test]
fn dropping_ops_outside_a_runtime_context_waits_for_its_threads() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_guard, ops) = temp_ops();
    let runtime = ops
        .connect_runtime()
        .expect("build the shared runtime so there is something to drop");
    let finished = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&finished);
    runtime.spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(300));
        flag.store(true, Ordering::SeqCst);
    });

    // Two `Arc`s point at the runtime: this local handle and the one
    // `ops` keeps in its `connect_runtime` cell. Dropping the second is
    // what runs the teardown, here on a plain test thread.
    drop(runtime);
    drop(ops);

    assert!(
        finished.load(Ordering::SeqCst),
        "drop returned while a runtime thread was still running"
    );
}

#[test]
fn op_error_from_code_defaults_retryable() {
    let err = OpError::from(ErrorCode::Timeout);
    assert!(err.retryable);
    assert_eq!(err.code, ErrorCode::Timeout);
}

#[test]
fn operation_commands_are_dotted_form() {
    assert_eq!(VersionOp::COMMAND, "version.get");
    assert_eq!(IdentityInitOp::COMMAND, "identity.init");
    assert_eq!(TrustAddOp::COMMAND, "trust.add");
    assert_eq!(TrustListOp::COMMAND, "trust.list");
    assert_eq!(TrustRemoveOp::COMMAND, "trust.remove");
}

#[test]
fn identity_init_is_idempotent() {
    let (_guard, ops) = temp_ops();
    let first = ops.identity_init(file_mode()).unwrap();
    assert!(first.created);
    let second = ops.identity_init(file_mode()).unwrap();
    assert!(!second.created);
    assert_eq!(second.device_id, first.device_id);
}

#[test]
fn identity_init_takes_the_key_store_from_config_when_unset() {
    let (_guard, ops) = temp_ops();
    crate::config::ensure_private_dir(&ops.paths().config_dir).unwrap();
    std::fs::write(
        ops.paths().config_file(),
        "[identity]\nkey_store = \"file\"\n",
    )
    .unwrap();
    let data = ops
        .identity_init(IdentityInitReq { key_store: None })
        .unwrap();
    assert_eq!(data.key_store, KeyStoreKind::File);
}

#[test]
fn trust_add_list_remove_round_trip() {
    let (_guard, ops) = temp_ops();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();

    let added = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("mac.example:4433".into()),
            fingerprint: Some(fingerprint.clone()),
        })
        .unwrap();
    assert!(added.created);
    assert_eq!(added.updated, None, "nothing to update on a fresh pin");
    assert_eq!(added.peer.fingerprint, fingerprint);

    // Same fingerprint, same address: a pure no-op.
    let again = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("mac.example:4433".into()),
            fingerprint: Some(fingerprint.clone()),
        })
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.updated, Some(false));
    assert_eq!(again.peer, added.peer);

    let listed = ops.trust_list().unwrap();
    assert_eq!(listed.peers, vec![added.peer.clone()]);

    let removed = ops.trust_remove("mac").unwrap();
    assert!(removed.removed);
    assert_eq!(removed.name, "mac");
    let removed_again = ops.trust_remove("mac").unwrap();
    assert!(!removed_again.removed);
    assert!(ops.trust_list().unwrap().peers.is_empty());
}

/// M7 Step 2 decision B: the same identity re-pinned at a new address
/// updates the stored address in place instead of being a silent
/// no-op (`docs/CLI.md` §6.11) — the M6 mobility campaign backlog item.
#[test]
fn trust_add_updates_the_address_of_an_identity_it_already_knows() {
    let (_guard, ops) = temp_ops();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();

    let added = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("old.example:4433".into()),
            fingerprint: Some(fingerprint.clone()),
        })
        .unwrap();
    assert!(added.created);

    let moved = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("new.example:5555".into()),
            fingerprint: Some(fingerprint.clone()),
        })
        .unwrap();
    assert!(!moved.created, "identity already pinned — never re-created");
    assert_eq!(moved.updated, Some(true));
    assert_eq!(moved.peer.address, "new.example:5555");
    assert_eq!(moved.peer.fingerprint, fingerprint);
    assert_eq!(
        moved.peer.added_at, added.peer.added_at,
        "added_at tracks the identity's first pin, not the address move"
    );

    let listed = ops.trust_list().unwrap();
    assert_eq!(listed.peers, vec![moved.peer], "no duplicate entry");
}

/// ADR-0014: `trust add --address` with no `:port` pins the default
/// port (4433) — the file on disk carries the normalized value, not
/// the bare name the operator typed.
#[test]
fn trust_add_with_a_port_less_address_pins_the_default_port() {
    let (_guard, ops) = temp_ops();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();

    let added = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("mac.example".into()),
            fingerprint: Some(fingerprint.clone()),
        })
        .unwrap();
    assert_eq!(added.peer.address, "mac.example:4433");

    let listed = ops.trust_list().unwrap();
    assert_eq!(listed.peers[0].address, "mac.example:4433");

    let raw = std::fs::read_to_string(ops.paths().trust_file()).unwrap();
    assert!(
        raw.contains("mac.example:4433"),
        "trust.toml must carry the normalized address: {raw:?}"
    );
    assert!(
        !raw.contains("address = \"mac.example\"\n"),
        "trust.toml must not carry the port-less address: {raw:?}"
    );
}

/// `Ops::invite_address_advice_with` lists every surviving candidate from
/// a synthetic observation — the injected-observation seam
/// (`crate::doctor::probe::detect_path_shadow`'s doc gives the same
/// reason) instead of depending on this test machine's real routes.
#[test]
fn invite_address_advice_with_a_synthetic_observation_lists_every_surviving_candidate() {
    let (_guard, ops) = temp_ops();
    let advice = ops.invite_address_advice_with(|| {
        vec![
            "192.0.2.10".parse().unwrap(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ]
    });
    assert_eq!(
        advice.lines(),
        &[
            crate::trust::invite_address::INVITE_ADDRESS_HEADING.to_string(),
            "  192.0.2.10:4433".to_string(),
        ]
    );
}

/// An empty observation (no default route in either family) falls back to
/// the three-part zero-candidate wording rather than an empty block.
#[test]
fn invite_address_advice_with_an_empty_observation_yields_the_none_wording() {
    let (_guard, ops) = temp_ops();
    let advice = ops.invite_address_advice_with(Vec::new);
    assert_eq!(
        advice.lines(),
        &[crate::trust::invite_address::INVITE_ADDRESS_NONE.to_string()]
    );
}

/// The port attached to a candidate line comes from `[serve].bind` in
/// `config.toml`, not the hardcoded default, when the sandbox's config
/// names one.
#[test]
fn invite_address_advice_reads_the_configured_serve_port() {
    let (dir, ops) = temp_ops();
    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(ops.paths().config_file(), "[serve]\nbind = \"[::]:5555\"\n").unwrap();

    let advice = ops.invite_address_advice_with(|| vec!["192.0.2.10".parse().unwrap()]);
    assert_eq!(
        advice.lines(),
        &[
            crate::trust::invite_address::INVITE_ADDRESS_HEADING.to_string(),
            "  192.0.2.10:5555".to_string(),
        ]
    );
}

/// `trust.list` normalizes a hand-written port-less pin on read, and
/// leaves an address-less (client-only) pin's empty address alone
/// (§6.11: an address-less pin is never a dial candidate).
#[test]
fn trust_list_normalizes_a_port_less_pin_and_leaves_an_address_less_pin_empty() {
    let (dir, ops) = temp_ops();
    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("trust.toml"),
        r#"
[[peer]]
name = "mac"
fingerprint = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "mac.example"
added_at = "2026-08-17T00:00:00Z"

[[peer]]
name = "phone"
fingerprint = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
address = ""
added_at = "2026-08-17T00:00:00Z"
"#,
    )
    .unwrap();

    let listed = ops.trust_list().unwrap();
    assert_eq!(listed.peers[0].address, "mac.example:4433");
    assert_eq!(listed.peers[1].address, "");
}

/// ADR-0014 결정 4·6: normalization never rewrites `trust.toml` — the
/// on-disk bytes are identical before and after a read-path op.
#[test]
fn a_hand_written_port_less_trust_toml_is_read_with_the_default_port_and_never_rewritten() {
    let (dir, ops) = temp_ops();
    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let trust_path = config_dir.join("trust.toml");
    std::fs::write(
        &trust_path,
        r#"
[[peer]]
name = "mac"
fingerprint = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "mac.example"
added_at = "2026-08-17T00:00:00Z"
"#,
    )
    .unwrap();

    let before_bytes = std::fs::read(&trust_path).unwrap();
    let before_hash = blake3::hash(&before_bytes);

    let listed = ops.trust_list().unwrap();
    assert_eq!(listed.peers[0].address, "mac.example:4433");

    let store = TrustStore::load(&trust_path).unwrap();
    let hosts = HostsFile::default();
    let (address, _server_name) = resolve_peer_address(&store, &hosts, "mac").unwrap();
    assert_eq!(address, "mac.example:4433");

    let after_bytes = std::fs::read(&trust_path).unwrap();
    let after_hash = blake3::hash(&after_bytes);
    assert_eq!(
        before_hash, after_hash,
        "trust.toml bytes must be unchanged"
    );
    assert_eq!(
        before_bytes, after_bytes,
        "trust.toml bytes must be unchanged"
    );
}

/// ADR-0014 결정 3, `design.md` §6 C12: `trust_accept`'s dial path
/// (`resolve_one(&dial_address)`, just above) uses the *normalized*
/// address, not the port-less string the operator typed — so a
/// resolution failure reports the address with the port already
/// filled in, never the bare input. `mac.example.invalid` is RFC
/// 2606's reserved, permanently-unresolvable TLD, so this fails before
/// any dial opens a socket: no network, no server, no dial timeout to
/// wait out (the risk `design.md` flagged for this case).
#[test]
fn trust_accept_uses_the_normalized_address_for_the_dial_and_its_failure_message() {
    let (_dir, ops) = temp_ops();
    ops.identity_init(file_mode()).unwrap();

    let err = ops
        .trust_accept(TrustAcceptReq {
            address: "mac.example.invalid".into(),
            code: "0000-0000-0000-0000-0000-0000-0000-0000".into(),
        })
        .expect_err("an unresolvable host must fail before any dial opens");

    assert_eq!(err.code, ErrorCode::ConnectionFailed);
    assert!(
        err.message.contains("mac.example.invalid:4433"),
        "the failure must name the normalized (ported) address, not the \
         port-less input the operator typed: {:?}",
        err.message
    );
}

/// Regression for `PLAN.md` M7 Step 7-1 검증 라운드 A2: `crate::trust`'s
/// own concurrency regressions (`concurrent_full_rmw_cycles_do_not_lose_each_others_peers`
/// et al.) call `TrustStore::lock`/`load`/`save` directly from test
/// threads and never go through `Ops::trust_add` — so a future edit
/// that silently dropped the `TrustStore::lock(&path)?` line at the
/// real call site (`Ops::trust_add`, this file) would leave the whole
/// suite green. This drives that actual call site instead: 8 threads,
/// each its own `Ops` bound to the same config directory (a fresh
/// `Ops` per thread rather than a shared clone, so the wiring under
/// test is the file lock, not any in-process synchronization `Ops`
/// might incidentally provide), concurrently `trust_add`ing a distinct
/// peer. All 8 must survive.
#[test]
fn concurrent_trust_add_through_ops_does_not_lose_a_peer() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));

    let mut threads = Vec::new();
    for i in 0..8u8 {
        let ops = Ops::new(paths.clone());
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(&[i; 4]).to_string();
        threads.push(std::thread::spawn(move || {
            ops.trust_add(TrustAddReq {
                name: format!("peer-{i}"),
                address: None,
                fingerprint: Some(fingerprint),
            })
            .unwrap();
        }));
    }
    for t in threads {
        t.join().expect("writer");
    }

    let listed = Ops::new(paths).trust_list().unwrap();
    assert_eq!(
        listed.peers.len(),
        8,
        "a concurrent Ops::trust_add lost a peer — the lock wired into the real call \
         site isn't doing its job"
    );
}

/// Fix A2 (initiator side), at the layer that actually writes
/// `trust.toml`: `Ops::trust_accept` must reject a responder's
/// `PairingAccepted.device_name` containing a control character with
/// `INVALID_ARGUMENT` *before* ever touching the local trust store —
/// even when the responder's own proof genuinely verifies (a rogue or
/// misconfigured responder that really does know the invite secret
/// must still not get pinned under an escape-sequence name). Proven
/// against the store itself (`trust.toml` is never even created), not
/// just the returned error — mirroring
/// `qsh-testkit/tests/pairing_loopback.rs`'s responder-side sibling of
/// this test. The rogue responder here hand-crafts its own wire reply
/// (rather than going through `crate::server::Server`) so it can send
/// a genuinely verifying proof alongside a bad device name — something
/// a real, unmodified `qsh serve` never does, but a modified or
/// compromised one could, and the wire format itself does not forbid.
#[test]
fn trust_accept_rejects_a_control_character_responder_device_name_and_leaves_trust_toml_untouched()
{
    use qsh_proto::pairing::{INVITE_SECRET_LEN, encode_invite_code};
    use qsh_proto::wire::{self, ControlMessage, control_message};
    use qsh_transport::{FramedStream, Listener};

    let (dir, ops) = temp_ops();
    ops.identity_init(file_mode()).unwrap();

    let secret = [0x33u8; INVITE_SECRET_LEN];
    let code = encode_invite_code(&secret);

    let (rogue_identity, _rogue_fp) = crate::tunnel::testutil::self_signed();
    // `Listener::bind` itself needs an active Tokio reactor (quinn
    // registers the socket against `Handle::current()` at bind time),
    // and this test function is a plain synchronous `#[test]` with none
    // running on its own thread — so the listener is built inside the
    // rogue thread's own runtime via `block_on`, then both the runtime
    // and the already-bound listener move into the spawned thread
    // together, keeping every later async call on the same reactor.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(async {
        Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            rogue_identity,
            Arc::new(StaticTrust::empty().with_pairing_open(true)),
        )
        .unwrap()
    });
    let addr = listener.local_addr().unwrap();

    let rogue = std::thread::spawn(move || {
        rt.block_on(async move {
            let incoming = listener.accept().await.unwrap();
            let conn = incoming.accept().await.unwrap();
            let (send, recv) = conn.accept_bi().await.unwrap();
            let mut ctl = FramedStream::control(send, recv);
            let _proof: ControlMessage = ctl.recv.recv().await.unwrap().unwrap();

            // A genuinely verifying proof — computed the same way
            // `crate::pairing::respond` would — so the initiator has no
            // reason to reject on that basis; only the device name is
            // bad here.
            let mut ekm = [0u8; 32];
            conn.export_keying_material(&mut ekm, crate::pairing::EXPORTER_LABEL, &[])
                .expect("export keying material");
            let (_client_proof, server_proof) =
                crate::trust::pairing::proofs_from_secret(&secret, &ekm);

            ctl.send
                .send(&ControlMessage::new(
                    0,
                    control_message::Body::PairingAccepted(wire::PairingAccepted {
                        device_name: "host\u{1b}[2Kname".to_string(),
                        proof: server_proof.to_vec(),
                    }),
                ))
                .await
                .expect("send PairingAccepted with a bad device name");
            if ctl.send.finish().is_ok() {
                let _ = tokio::time::timeout(Duration::from_secs(2), ctl.send.stopped()).await;
            }
        });
    });

    let err = ops
        .trust_accept(TrustAcceptReq {
            address: addr.to_string(),
            code,
        })
        .expect_err("a control-character responder device name must be rejected");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    rogue.join().expect("rogue responder thread");

    assert!(
        !dir.path().join("config").join("trust.toml").exists(),
        "the initiator's trust store must be untouched when the responder's \
         device name is rejected"
    );
}

/// Same regression, `Ops::trust_remove`'s call site instead of
/// `trust_add`'s: 8 peers are pre-seeded, then 8 threads each their own
/// `Ops` on the same config directory concurrently `trust_remove` a
/// distinct one. All 8 removals must land — a lost one would mean a
/// peer that was supposed to be unpinned came back because a stale,
/// concurrently-loaded snapshot overwrote the file that already
/// reflected its removal.
#[test]
fn concurrent_trust_remove_through_ops_does_not_lose_a_removal() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::new(dir.path().join("config"), dir.path().join("state"));

    let seed = Ops::new(paths.clone());
    for i in 0..8u8 {
        let fingerprint = qsh_transport::Fingerprint::of_spki_der(&[i; 4]).to_string();
        seed.trust_add(TrustAddReq {
            name: format!("peer-{i}"),
            address: None,
            fingerprint: Some(fingerprint),
        })
        .unwrap();
    }
    assert_eq!(seed.trust_list().unwrap().peers.len(), 8, "seed setup");

    let mut threads = Vec::new();
    for i in 0..8u8 {
        let ops = Ops::new(paths.clone());
        threads.push(std::thread::spawn(move || {
            let removed = ops.trust_remove(&format!("peer-{i}")).unwrap();
            assert!(removed.removed, "peer-{i} was not found to remove");
        }));
    }
    for t in threads {
        t.join().expect("remover");
    }

    let listed = Ops::new(paths).trust_list().unwrap();
    assert!(
        listed.peers.is_empty(),
        "a concurrent Ops::trust_remove lost a removal (peers left: {:?}) — the lock \
         wired into the real call site isn't doing its job",
        listed.peers.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

/// M7 Step 2 decision B, the guardrail half: a *different* fingerprint
/// under an already-pinned name changes nothing at all — identity
/// rebind stays a deliberate `trust remove` + `trust add`, never a
/// side effect of a repeated call (`docs/CLI.md` §6.11's existing
/// idempotence contract, preserved).
#[test]
fn trust_add_rejects_a_different_fingerprint_for_an_already_pinned_name() {
    let (_guard, ops) = temp_ops();
    let first_fp = qsh_transport::Fingerprint::of_spki_der(b"first").to_string();
    let second_fp = qsh_transport::Fingerprint::of_spki_der(b"second").to_string();

    let added = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("mac.example:4433".into()),
            fingerprint: Some(first_fp.clone()),
        })
        .unwrap();
    assert!(added.created);

    let rejected = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: Some("attacker.example:1".into()),
            fingerprint: Some(second_fp),
        })
        .unwrap();
    assert!(!rejected.created);
    assert_eq!(rejected.updated, Some(false));
    assert_eq!(
        rejected.peer, added.peer,
        "a fingerprint mismatch must not touch the existing pin at all"
    );

    let listed = ops.trust_list().unwrap();
    assert_eq!(listed.peers, vec![added.peer]);
}

#[test]
fn trust_add_rejects_bad_input() {
    let (_guard, ops) = temp_ops();

    let err = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: None,
            fingerprint: Some("not-a-fingerprint".into()),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let err = ops
        .trust_add(TrustAddReq {
            name: "  ".into(),
            address: None,
            fingerprint: Some(qsh_transport::Fingerprint::of_spki_der(b"x").to_string()),
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let err = ops
        .trust_add(TrustAddReq {
            name: "mac".into(),
            address: None,
            fingerprint: None,
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("--address"), "{err}");
}

#[test]
fn probing_without_an_identity_asks_for_init_first() {
    let (_guard, ops) = temp_ops();
    let err = ops.probe_fingerprint("127.0.0.1:9").unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfigError);
    assert!(err.message.contains("qsh init"), "{err}");
}

#[test]
fn open_trust_serves_pins_as_device_principals() {
    let (_guard, ops) = temp_ops();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer");
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: None,
        fingerprint: Some(fingerprint.to_string()),
    })
    .unwrap();

    let evaluator = ops.open_trust().unwrap();
    assert_eq!(
        qsh_transport::TrustEvaluator::lookup_pin(evaluator.as_ref(), &fingerprint),
        Some(qsh_transport::Principal::Device("mac".into()))
    );
}

#[test]
fn server_name_strips_the_port_and_brackets() {
    assert_eq!(server_name_for("example.com:4433"), "example.com");
    assert_eq!(server_name_for("127.0.0.1:4433"), "127.0.0.1");
    assert_eq!(server_name_for("[::1]:4433"), "::1");
    assert_eq!(server_name_for("example.com"), "example.com");
    assert_eq!(server_name_for(":4433"), "qsh");
    assert_eq!(server_name_for("[::1]"), "::1");
}

// ---- `Ops::resolve_route` — `PeerRoute` selection (`PLAN.md` M3
// Step 6) ----
//
// `resolve_route` is a thin `HostRoute` -> `PeerRoute` mapping over
// the same routing decision `resolve_host_route`/
// `resolve_host_route_async` already make and already test
// exhaustively at the `HostRoute` level (`crate::ops::host`'s own
// test module). What these add is proof the *mapping* itself is
// right: a forward `HostRoute` becomes a fully resolved `PeerTarget`
// (identity loaded, address/server_name carried through
// `resolve_peer`), a reverse `HostRoute` becomes the `LocalRoute`
// `Ops::connect_reverse` actually dials with (host alias + that
// daemon's own socket, nothing else), and not-found/duplicate stay
// plain error propagation through the mapping.
//
// `resolve_route` is sync — same identity-load constraint as
// `resolve_peer` — so on the reverse/duplicate cases below the fake
// `LOCAL_ADMIN` daemon has to live on its own OS thread with its own
// runtime (mirroring a real `qsh listen` process), never on the
// test's own thread: calling `resolve_route` from inside a runtime
// that already exists is exactly the "cannot start a runtime from
// within a runtime" hazard `resolve_host_route`'s own doc flags.

fn resolve_route_ops(dir: &std::path::Path) -> Ops {
    let paths = Paths::new(dir.join("config"), dir.join("state")).with_runtime_dir(dir.join("run"));
    Ops::new(paths)
}

#[test]
fn resolve_route_not_found_is_host_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let ops = resolve_route_ops(dir.path());

    let err = match ops.resolve_route("nowhere") {
        Err(err) => err,
        Ok(_) => panic!("expected an error for an unknown host"),
    };
    assert_eq!(err.code, ErrorCode::HostNotFound);
}

#[test]
fn resolve_route_forward_resolves_a_peer_target_with_the_pinned_address() {
    let dir = tempfile::tempdir().unwrap();
    let ops = resolve_route_ops(dir.path());
    ops.identity_init(file_mode()).unwrap();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"peer").to_string();
    ops.trust_add(TrustAddReq {
        name: "mac".into(),
        address: Some("mac.example.com:4433".into()),
        fingerprint: Some(fingerprint),
    })
    .unwrap();

    match ops.resolve_route("mac").unwrap() {
        PeerRoute::Forward(target) => {
            assert_eq!(target.address, "mac.example.com:4433");
            assert_eq!(target.server_name, "mac.example.com");
        }
        PeerRoute::Reverse(_) => panic!("expected a forward route"),
    }
}

/// ADR-0019 decision 9's loopback-only `-D` bind check runs **before**
/// route resolution or any connect attempt — `"nowhere"` names no host
/// this `Ops` (no identity, no trust entry, no daemon) could ever resolve,
/// so getting `INVALID_ARGUMENT` back rather than `HOST_NOT_FOUND` (or a
/// connect failure) proves zero connect attempts were made.
#[test]
fn tunnel_dynamic_non_loopback_bind_is_invalid_argument_before_connect() {
    let dir = tempfile::tempdir().unwrap();
    let ops = resolve_route_ops(dir.path());

    let err = match ops.tunnel_dynamic(qsh_proto::TunnelDynamicReq {
        host: "nowhere".into(),
        bind: Some("0.0.0.0".into()),
        listen_port: 1080,
    }) {
        Err(err) => err,
        Ok(_) => panic!("a non-loopback -D bind must never succeed"),
    };
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[cfg(unix)]
fn sample_local_host(name: &str) -> qsh_proto::local::LocalHost {
    qsh_proto::local::LocalHost {
        name: name.to_string(),
        address: "203.0.113.5:51820".to_string(),
        state: "reachable".to_string(),
        fingerprint: qsh_transport::Fingerprint::of_spki_der(b"reverse-peer").to_string(),
        capabilities: vec!["pty".to_string()],
        generation: 1,
        registered_at: "2026-08-22T00:00:00Z".to_string(),
        lost_at: None,
    }
}

/// Bind a one-shot fake `LOCAL_ADMIN` daemon at `<pid>.sock` under
/// `runtime_dir`, answering exactly one `LocalHostList` with `hosts`,
/// on its own OS thread with its own runtime — see this section's own
/// header for why it cannot share the test's thread/runtime.
#[cfg(unix)]
fn spawn_fake_admin_daemon_thread(
    runtime_dir: &std::path::Path,
    pid: u32,
    hosts: Vec<qsh_proto::local::LocalHost>,
) -> std::thread::JoinHandle<()> {
    std::fs::create_dir_all(runtime_dir).unwrap();
    let sock = runtime_dir.join(format!("{pid}.sock"));
    // Bind synchronously, on the caller's thread, before handing off:
    // `resolve_route` must never race the socket file into existence.
    let std_listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std_listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = crate::localctl::frame::LocalConduit::new(stream);
            let _hello: qsh_proto::local::LocalHello = conduit.recv().await.unwrap().unwrap();
            let _req: qsh_proto::local::LocalHostList = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&qsh_proto::local::LocalResponse {
                    body: Some(qsh_proto::local::local_response::Body::HostListResult(
                        qsh_proto::local::LocalHostListResult { hosts },
                    )),
                })
                .await
                .unwrap();
        });
    })
}

#[test]
#[cfg(unix)]
fn resolve_route_reverse_returns_the_local_route_to_the_live_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let ops = resolve_route_ops(dir.path());
    let runtime_dir = ops.paths().runtime_dir();
    let daemon =
        spawn_fake_admin_daemon_thread(&runtime_dir, 100, vec![sample_local_host("phone")]);

    match ops.resolve_route("phone").unwrap() {
        PeerRoute::Reverse(route) => {
            assert_eq!(route.host, "phone");
            assert_eq!(route.socket, runtime_dir.join("100.sock"));
        }
        PeerRoute::Forward(_) => panic!("expected a reverse route"),
    }
    daemon.join().unwrap();
}

// `tunnel_dynamic_on_reverse_route_is_unsupported_before_connect` used to
// live here, pinning ADR-0019 decision 10's forward-only restriction on
// `-D`: a reverse route was refused with `UNSUPPORTED` strictly before
// `Ops::tunnel_dynamic` ever tried to connect. ADR-0020 decision 1 lifted
// that restriction — `-D` over reverse now connects and is gated on
// `dial-filter.v1` instead (`crate::ops::tunnel`'s
// `tunnel_dynamic_over_reverse_without_dial_filter_capability_is_unsupported_and_binds_nothing`
// pins the new refusal at the point that actually needs a fabricated
// `Connected`, `Connected::for_test_reverse`). This file's fake admin
// daemon answers only `LocalHostList` (`spawn_fake_admin_daemon_thread`'s
// own doc) and cannot play the `LOCAL_CONTROL` handshake side of a real
// connect, so there is no cheap way to keep a same-shaped test here — the
// full round trip is `crates/qsh-testkit`'s `ReverseHarness` job instead.

#[test]
#[cfg(unix)]
fn resolve_route_reverse_prefers_the_live_daemon_over_a_forward_pin() {
    let dir = tempfile::tempdir().unwrap();
    let ops = resolve_route_ops(dir.path());
    ops.identity_init(file_mode()).unwrap();
    let fingerprint = qsh_transport::Fingerprint::of_spki_der(b"forward-pin").to_string();
    ops.trust_add(TrustAddReq {
        name: "phone".into(),
        address: Some("stale.example.com:4433".into()),
        fingerprint: Some(fingerprint),
    })
    .unwrap();
    let runtime_dir = ops.paths().runtime_dir();
    let daemon =
        spawn_fake_admin_daemon_thread(&runtime_dir, 100, vec![sample_local_host("phone")]);

    match ops.resolve_route("phone").unwrap() {
        PeerRoute::Reverse(route) => assert_eq!(route.host, "phone"),
        PeerRoute::Forward(_) => {
            panic!("a live reverse registration must beat a forward pin")
        }
    }
    daemon.join().unwrap();
}

#[test]
#[cfg(unix)]
fn resolve_route_duplicate_live_daemons_is_invalid_argument() {
    let dir = tempfile::tempdir().unwrap();
    let ops = resolve_route_ops(dir.path());
    let runtime_dir = ops.paths().runtime_dir();
    let a = spawn_fake_admin_daemon_thread(&runtime_dir, 100, vec![sample_local_host("dup")]);
    let b = spawn_fake_admin_daemon_thread(&runtime_dir, 101, vec![sample_local_host("dup")]);

    let err = match ops.resolve_route("dup") {
        Err(err) => err,
        Ok(_) => panic!("expected an error for two live daemons holding the same name"),
    };
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    a.join().unwrap();
    b.join().unwrap();
}

#[test]
fn resolve_peer_address_strips_a_user_at_hint_from_the_host_not_found_remedy() {
    // `qsh exec <user>@<host> -- ...` (`ExecArgs.host`, a raw
    // positional that bypasses `parse_target`'s own `user@` split,
    // `docs/CLI.md` §6.9) used to echo the hint straight into this
    // function's `qsh trust add` remedy — the exact shape
    // `Ops::resolve_host_route` had before `PLAN.md` §3 Step 6 fixed
    // it. Pin both halves: no `@` survives in the message, and the
    // suggested alias itself is one `qsh trust add` would accept
    // (lens-2 finding).
    let trust = TrustStore::default();
    let hosts = HostsFile::default();
    let err = resolve_peer_address(&trust, &hosts, "dave@nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        !err.message.contains('@'),
        "message leaked the user@ hint: {:?}",
        err.message
    );
    assert!(
        err.message.contains("qsh trust add nowhere --address"),
        "remedy did not name the bare alias: {:?}",
        err.message
    );
    assert!(
        qsh_proto::wire::valid_host_name("nowhere"),
        "the suggested alias itself must satisfy `qsh trust add`'s own name rule",
    );
}

#[test]
fn resolve_peer_address_on_an_at_prefix_with_no_alias_left_is_invalid_argument() {
    let trust = TrustStore::default();
    let hosts = HostsFile::default();
    for name in ["dave@", "@", "dave@ "] {
        let err = resolve_peer_address(&trust, &hosts, name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "name {name:?}");
        assert_eq!(err.message, "host name must not be empty", "name {name:?}");
    }
}

#[test]
fn resolve_peer_address_trims_a_stray_space_left_by_an_at_split() {
    // `PLAN.md` §3 Step 7, Q10 — same trim `resolve_route` gets,
    // reused here via the shared `host::hint_alias`.
    let trust = TrustStore::default();
    let hosts = HostsFile::default();
    let err = resolve_peer_address(&trust, &hosts, "dave@ nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert!(
        err.message.contains("qsh trust add nowhere --address"),
        "remedy did not name the trimmed bare alias: {:?}",
        err.message
    );
}

#[test]
fn resolve_peer_address_on_an_internal_space_is_invalid_argument_not_host_not_found() {
    let trust = TrustStore::default();
    let hosts = HostsFile::default();
    let err = resolve_peer_address(&trust, &hosts, "dave@no where").unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(
        err.message,
        "host name \"no where\" is not a valid host alias"
    );
}

#[test]
fn resolve_peer_address_leaves_an_at_free_host_byte_identical() {
    // The golden fixture
    // (`crates/qsh-cli/tests/fixtures/cli-v1/error.HOST_NOT_FOUND.json`,
    // via `qsh exec nowhere`) has no `@` in its input, so
    // `host::hint_alias` must be a no-op for it.
    let trust = TrustStore::default();
    let hosts = HostsFile::default();
    let err = resolve_peer_address(&trust, &hosts, "nowhere").unwrap_err();
    assert_eq!(err.code, ErrorCode::HostNotFound);
    assert_eq!(
        err.message,
        "host \"nowhere\" is not in the trust store; pin it with `qsh trust add nowhere \
         --address <host:port> --fingerprint sha256:...`"
    );
}

/// `PLAN.md` M9 Step 2 (c)'s 4 combinations, plus every other real
/// branch the resolver answers (`PLAN.md` "### Step 2" (a)④, ADR-0013
/// decision 8 at `docs/adr/0013-cert-file-exchange.md:29`). Each error
/// row pins the exact code *and* message, not merely
/// `ErrorCode::InvalidArgument` — two different refusals sharing a
/// substring (both mention `--code-stdin`) would otherwise pass under
/// a looser check even after one arm's wording silently became the
/// other's.
#[test]
fn resolve_invite_code_source_decision_table() {
    let code = || Some("abcd-efgh".to_string());
    #[allow(clippy::type_complexity)]
    let cases: &[(
        &str,
        Option<String>,
        bool,
        bool,
        bool,
        bool,
        Result<InviteCodeSource, (ErrorCode, &'static str)>,
    )] = &[
        // (label, code, code_stdin, machine_mode, stdin_is_tty, echo_can_be_suppressed, expected)
        (
            "explicit code",
            code(),
            false,
            true,
            false,
            true,
            Ok(InviteCodeSource::UseCode("abcd-efgh".into())),
        ),
        (
            "--code-stdin, piped",
            None,
            true,
            true,
            false,
            true,
            Ok(InviteCodeSource::ReadStdin {
                suppress_echo: false,
            }),
        ),
        (
            "--code-stdin, terminal, human",
            None,
            true,
            false,
            true,
            true,
            Ok(InviteCodeSource::ReadStdin {
                suppress_echo: true,
            }),
        ),
        (
            "--code-stdin, terminal, human, platform cannot suppress echo",
            None,
            true,
            false,
            true,
            false,
            Ok(InviteCodeSource::ReadStdin {
                suppress_echo: false,
            }),
        ),
        (
            "--code-stdin, terminal, machine mode",
            None,
            true,
            true,
            true,
            true,
            Err((ErrorCode::InvalidArgument, CODE_STDIN_BLOCKS_MACHINE_MODE)),
        ),
        (
            "human tty",
            None,
            false,
            false,
            true,
            true,
            Ok(InviteCodeSource::Prompt {
                text: INVITE_CODE_PROMPT.to_string(),
            }),
        ),
        (
            "human tty, platform cannot suppress echo",
            None,
            false,
            false,
            true,
            false,
            Err((ErrorCode::Unsupported, NO_TERMINAL_ECHO_SUPPRESSION)),
        ),
        (
            "machine, none",
            None,
            false,
            true,
            false,
            true,
            Err((ErrorCode::InvalidArgument, NO_CODE_IN_MACHINE_MODE)),
        ),
        (
            "machine, none, terminal",
            None,
            false,
            true,
            true,
            true,
            Err((ErrorCode::InvalidArgument, NO_CODE_IN_MACHINE_MODE)),
        ),
        (
            "both sources",
            code(),
            true,
            false,
            false,
            true,
            Err((ErrorCode::InvalidArgument, BOTH_CODE_SOURCES)),
        ),
        (
            "human, no terminal",
            None,
            false,
            false,
            false,
            true,
            Err((ErrorCode::InvalidArgument, NO_CODE_WITHOUT_A_TERMINAL)),
        ),
    ];
    for (label, code, code_stdin, machine, tty, echo_ok, expected) in cases {
        let got = resolve_invite_code_source(code.clone(), *code_stdin, *machine, *tty, *echo_ok);
        match expected {
            Ok(want) => assert_eq!(got.as_ref().ok(), Some(want), "{label}"),
            Err((want_code, want_message)) => {
                let err = got.expect_err(label);
                assert_eq!(err.code, *want_code, "{label}");
                assert!(!err.retryable, "{label}");
                assert_eq!(err.message, *want_message, "{label}");
            }
        }
    }
}

/// An explicit code wins regardless of mode or tty-ness.
#[test]
fn resolve_invite_code_source_ignores_the_mode_when_a_code_is_given() {
    for machine_mode in [false, true] {
        for stdin_is_tty in [false, true] {
            let got = resolve_invite_code_source(
                Some("abcd-efgh".to_string()),
                false,
                machine_mode,
                stdin_is_tty,
                true,
            );
            assert_eq!(
                got,
                Ok(InviteCodeSource::UseCode("abcd-efgh".to_string())),
                "machine_mode={machine_mode} stdin_is_tty={stdin_is_tty}"
            );
        }
    }
}

/// `exit_code_matrix.rs`'s human leg runs with a non-terminal stdin
/// too (`Sandbox::qsh`'s `Stdio::null()`) — that state must not
/// silently open a prompt that then reads an empty code from
/// `/dev/null`.
#[test]
fn resolve_invite_code_source_rejects_a_missing_code_without_a_terminal() {
    let err = resolve_invite_code_source(None, false, false, false, true).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(err.message, NO_CODE_WITHOUT_A_TERMINAL);
}

/// Clap's `conflicts_with` blocks this through the CLI, but the
/// resolver still answers it — this test is that arm's only caller.
#[test]
fn resolve_invite_code_source_rejects_a_code_from_both_sources() {
    let err = resolve_invite_code_source(Some("abcd-efgh".to_string()), true, false, false, true)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(err.message, BOTH_CODE_SOURCES);
}

/// The two "no code" rejections read distinctly, so the real cause
/// (machine mode vs. no terminal) survives into the error message.
#[test]
fn the_two_missing_code_rejections_have_distinct_messages() {
    let machine = resolve_invite_code_source(None, false, true, false, true).unwrap_err();
    let no_tty = resolve_invite_code_source(None, false, false, false, true).unwrap_err();
    assert_ne!(machine.message, no_tty.message);
    assert!(
        machine.message.contains("--json/--jsonl"),
        "{}",
        machine.message
    );
    assert!(no_tty.message.contains("terminal"), "{}", no_tty.message);
}

/// Trim rule: surrounding whitespace (including CRLF) removed, internal
/// whitespace left alone (`PLAN.md` M9 Step 2 (c)'s two trim inputs).
#[test]
fn normalize_invite_code_trims_surrounding_whitespace_only() {
    let code = "abcd-efgh-jkmn-pqrs-tvwx-yz23-4567-89ab";
    assert_eq!(normalize_invite_code(&format!("{code}\n")), code);
    assert_eq!(normalize_invite_code(&format!("  {code}  ")), code);
    assert_eq!(normalize_invite_code(&format!("{code}\r\n")), code);
    assert_eq!(normalize_invite_code(" ab cd "), "ab cd"); // internal space kept
}

// --- issue #4 item 2: `dial_first_reachable` / `resolve_all` --------------
//
// These drive `dial_first_reachable` with a synthetic per-address `dial`
// closure instead of a real `Dialer` — no network, no DNS, deterministic —
// exactly the seam its own doc comment describes. `DialError` has no
// `PartialEq` (`qsh_transport::endpoint`), so assertions match on the
// variant with `matches!`/`Display` rather than `assert_eq!`.

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// The single-address case `error.CONNECTION_FAILED.json` pins: an IP
/// literal (`127.0.0.1:<port>`, as `golden_connection_failed_fixture`
/// dials) resolves to exactly one address, no real DNS query involved —
/// `resolve_all`/`dial_first_reachable` replacing the old first-address-
/// only path must not turn this into more than one attempt.
#[tokio::test]
async fn resolve_all_returns_exactly_one_address_for_an_ip_literal() {
    let addrs = resolve_all("127.0.0.1:4433").await.unwrap();
    assert_eq!(addrs, vec![addr(4433)]);
}

/// `[unreachable, good]` → succeeds on the second address, and the
/// closure was called with the addresses in exactly resolver order (not
/// the reverse, not just the winner) — dial succeeds on the second
/// address, with resolver order preserved (issue #4 item 2).
#[tokio::test]
async fn dial_first_reachable_tries_addresses_in_order_and_stops_at_the_first_success() {
    let addrs = vec![addr(1), addr(2)];
    let seen = std::sync::Mutex::new(Vec::new());
    let result = dial_first_reachable(&addrs, |a| {
        seen.lock().unwrap().push(a);
        async move {
            if a == addr(1) {
                Err(DialError::Refused)
            } else {
                Ok(a)
            }
        }
    })
    .await;
    assert_eq!(
        result.ok(),
        Some(addr(2)),
        "must resolve to the reachable address"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![addr(1), addr(2)],
        "must try addr(1) before addr(2), not skip straight to the winner"
    );
}

/// Five resolved addresses, all failing: only the first
/// [`MAX_DIAL_ADDRESSES`] are ever tried — the fifth is never dialed.
#[tokio::test]
async fn dial_first_reachable_caps_at_max_dial_addresses() {
    let addrs: Vec<SocketAddr> = (1..=5).map(addr).collect();
    let seen = std::sync::Mutex::new(Vec::new());
    let result = dial_first_reachable(&addrs, |a| {
        seen.lock().unwrap().push(a);
        async move { Err::<SocketAddr, _>(DialError::Refused) }
    })
    .await;
    let (_err, attempted) = result.expect_err("every address fails");
    assert_eq!(attempted, MAX_DIAL_ADDRESSES);
    assert_eq!(
        *seen.lock().unwrap(),
        addrs[..MAX_DIAL_ADDRESSES].to_vec(),
        "must try only the first four addresses, not the last four or all five"
    );
}

/// When every address fails, the error returned is the *last* address's
/// failure, not the first — `dial_and_register`'s PR-A `cause`
/// classification and `map_dial_error`'s message both key off this same
/// value, so they must agree with each other about which attempt "the"
/// failure is.
#[tokio::test]
async fn dial_first_reachable_returns_the_last_addresss_error() {
    let addrs = vec![addr(1), addr(2), addr(3)];
    let result = dial_first_reachable(&addrs, |a| async move {
        if a == addr(3) {
            Err::<(), _>(DialError::RemoteRejected)
        } else {
            Err::<(), _>(DialError::Refused)
        }
    })
    .await;
    let (err, attempted) = result.expect_err("every address fails");
    assert_eq!(attempted, 3);
    assert!(
        matches!(err, DialError::RemoteRejected),
        "expected the third (last) address's error, got {err:?}"
    );
}

/// Mixed-severity precedence (fail closed on ambiguous auth,
/// CLAUDE.md "Security defaults"): an earlier address's non-retryable
/// auth-class rejection (`LocalRejected` — we rejected the peer's cert)
/// must not be silently downgraded to a later address's ordinary,
/// retryable transport failure (`Timeout`). Plain last-error-wins would
/// report `Timeout` here and flip `retryable` from `false` to `true`,
/// hiding the pin mismatch entirely.
#[tokio::test]
async fn dial_first_reachable_prefers_an_earlier_auth_rejection_over_a_later_transport_failure() {
    let addrs = vec![addr(1), addr(2)];
    let result = dial_first_reachable(&addrs, |a| async move {
        if a == addr(1) {
            Err::<(), _>(DialError::LocalRejected {
                reason: qsh_transport::RejectReason::Untrusted,
                observed: None,
            })
        } else {
            Err::<(), _>(DialError::Timeout(std::time::Duration::from_secs(10)))
        }
    })
    .await;
    let (err, attempted) = result.expect_err("every address fails");
    assert_eq!(
        attempted, 2,
        "both addresses must still have been attempted"
    );
    assert!(
        matches!(err, DialError::LocalRejected { .. }),
        "the earlier auth-class rejection must win over the later timeout, got {err:?}"
    );
}

/// Same precedence rule, reversed order: a later auth-class rejection
/// still wins over an earlier transport failure (this direction already
/// matched plain last-error-wins, but pins it so the precedence logic
/// cannot regress into "always keep the first error").
#[tokio::test]
async fn dial_first_reachable_prefers_a_later_auth_rejection_over_an_earlier_transport_failure() {
    let addrs = vec![addr(1), addr(2)];
    let result = dial_first_reachable(&addrs, |a| async move {
        if a == addr(1) {
            Err::<(), _>(DialError::Refused)
        } else {
            Err::<(), _>(DialError::RemoteRejected)
        }
    })
    .await;
    let (err, attempted) = result.expect_err("every address fails");
    assert_eq!(attempted, 2);
    assert!(
        matches!(err, DialError::RemoteRejected),
        "the later auth-class rejection must still win, got {err:?}"
    );
}

/// The full mapping a multi-address dial failure goes through
/// (`crate::ops::exec::map_dial_error`, driven with a real
/// `dial_first_reachable` failure rather than a hand-built `DialError`):
/// still `CONNECTION_FAILED`/`retryable: true` (`qsh.cli/v1` unchanged,
/// PR-B's own contract note), and the message names the attempt count
/// only once more than one address was tried — the single-address case
/// (`attempted == 1`) must read exactly as it did before this feature,
/// which is what keeps `error.CONNECTION_FAILED.json` byte-identical.
#[tokio::test]
async fn all_addresses_failing_maps_to_connection_failed_naming_the_attempt_count() {
    let addrs = vec![addr(1), addr(2), addr(3)];
    let (err, attempted) =
        dial_first_reachable(&addrs, |_a| async { Err::<(), _>(DialError::Refused) })
            .await
            .expect_err("every address fails");
    let multi = crate::ops::exec::map_dial_error(err, "widget:4433", attempted);
    assert_eq!(multi.code, ErrorCode::ConnectionFailed);
    assert!(multi.retryable);
    assert!(
        multi.message.contains('3'),
        "message must name the attempt count: {}",
        multi.message
    );

    let single = crate::ops::exec::map_dial_error(DialError::Refused, "widget:4433", 1);
    assert!(
        !single.message.contains("tried"),
        "a single-address failure must not mention an attempt count: {}",
        single.message
    );
    assert_ne!(multi.message, single.message);
}
