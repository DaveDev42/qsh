//! `host.list`/`host.get` — the local, authorization-free host query
//! (`docs/CLI.md` §2.5: "인가 불요 — local operation으로 원격 peer의 ACL
//! 평가 대상이 아님"; §5 `Host`; §6.1) — plus [`resolve_host_route`], the
//! one function that also backs `host.get`'s single entry, the human
//! renderer's "route that would be used", and (Step 6) `Ops::connect`'s
//! path choice (`PLAN.md` M3 Step 5, PR 5b).
//!
//! Two data sources, concatenated into `host.list`'s result but never
//! merged by name (`docs/CLI.md` §6.1: "같은 이름이 forward pin과 reverse
//! 등록 양쪽에 존재하면... 두 항목으로 나타난다"):
//!
//! - **forward** — `trust.toml` pins that carry an address
//!   ([`forward_hosts`]). Never probed: `state` is always `"unknown"`.
//! - **reverse** — the union of `LocalHostList` across every localctl
//!   daemon discovered on this machine
//!   ([`crate::localctl::client::admin_host_list_all`], unix only). A
//!   daemon this machine cannot reach is dropped from the result, never
//!   turned into an error — one sleeping laptop must not hide every other
//!   host (`docs/CLI.md` §6.2). `state` is whatever the daemon reported
//!   (`"reachable"`/`"stale"`), `device_id` is the fingerprint the daemon
//!   TLS-verified, never a wire display name.
//!
//! `host.list` never dials — both sources are purely local reads.
//! [`resolve_host_route`] is the one place a name turns into "which peer,
//! reached how": live reverse registration beats a forward pin (a proven
//! reachable path beats an address that is only ever an estimate), and two
//! daemons holding the same name live is a routing failure
//! (`ErrorCode::InvalidArgument`) rather than a silent pick — fail closed
//! in routing, never in listing.

use std::path::PathBuf;

use qsh_proto::local::LocalHost;
use qsh_proto::{ErrorCode, Host, HostGetReq, HostListData};

use crate::ops::{OpError, Operation, Ops};
use crate::trust::TrustStore;

/// The `host.list` operation (`qsh hosts`).
pub struct HostListOp;

impl Operation for HostListOp {
    const COMMAND: &'static str = "host.list";
}

/// The `host.get` operation (`qsh host get <name>`).
pub struct HostGetOp;

impl Operation for HostGetOp {
    const COMMAND: &'static str = "host.get";
}

/// One reverse-source entry: a single daemon's answer about one
/// registered host, carrying enough about *which* daemon it came from for
/// [`resolve_host_route`]'s two-daemon-duplicate check and — from Step 6 —
/// for actually dialing through it. Plain data, no I/O: this is the
/// injectable seam that lets the merge/routing tables in this module's own
/// tests run without a real socket (`docs/design/testing.md` L2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReverseHostEntry {
    /// The daemon's pid — from its own `<pid>.sock` filename
    /// (`docs/design/architecture.md` §7).
    pub pid: u32,
    /// The daemon's localctl socket path.
    pub socket: PathBuf,
    /// What that daemon reported for this registration.
    pub local: LocalHost,
}

/// The route `host.get`, the human renderer, and (Step 6) `Ops::connect`
/// all resolve one host name to — decided in exactly one place
/// ([`Ops::resolve_host_route`]) so list, single-entry and routing never
/// grow their own, divergent rules (`PLAN.md` M3 Step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRoute {
    /// Dial the trust-store-pinned address directly.
    Forward {
        /// `host:port` to dial.
        address: String,
        /// The pinned SPKI SHA-256 fingerprint.
        fingerprint: String,
    },
    /// Relay through this machine's resident `qsh listen` daemon, over its
    /// live reverse registration — the proven-reachable path, preferred
    /// over a forward pin's estimate.
    Reverse {
        /// The daemon's pid — which `<pid>.sock` to speak to (Step 6).
        pid: u32,
        /// The daemon's localctl socket path.
        socket: PathBuf,
        /// Last observed remote address. Diagnostic only: a reverse host
        /// is never dialed directly, only through the daemon
        /// (`docs/CLI.md` §6.13).
        address: String,
        /// The peer fingerprint the daemon TLS-verified — the ADR-0007
        /// presentation condition also applies on this leg.
        fingerprint: String,
        /// The registration's generation (Step 8's `LocalReconnect` needs
        /// this to detect a re-registration).
        generation: u64,
    },
}

impl HostRoute {
    /// Render this route as the `Host` `host.get`/the human renderer
    /// shows for `name` — "the route that would be used"
    /// (`docs/CLI.md` §6.1).
    fn into_host(self, name: &str) -> Host {
        match self {
            HostRoute::Forward {
                address,
                fingerprint,
            } => Host {
                name: name.to_string(),
                address,
                connection_mode: "forward".to_string(),
                state: "unknown".to_string(),
                device_id: fingerprint,
            },
            HostRoute::Reverse {
                address,
                fingerprint,
                ..
            } => Host {
                name: name.to_string(),
                address,
                connection_mode: "reverse".to_string(),
                state: "reachable".to_string(),
                device_id: fingerprint,
            },
        }
    }
}

/// Pure mapping: pinned peers that carry an address become forward `Host`
/// entries (`docs/CLI.md` §5: "forward source = trust store pinned peers
/// that have an address"). Split out from any I/O so the merge table
/// (`PLAN.md` M3 Step 5 (c)) is testable against a hand-built
/// [`TrustStore`], never a real file.
///
/// The `!address.is_empty()` filter here is the same "routable pin" rule
/// [`TrustStore::resolve_host`] applies for a single name — `resolve_route`
/// below calls that method rather than re-deriving the rule, and
/// `forward_hosts_and_resolve_route_agree_on_routability` (this module's
/// tests) pins the two together so a future change to what counts as
/// routable can't drift silently between listing and routing.
fn forward_hosts(store: &TrustStore) -> Vec<Host> {
    store
        .peers()
        .iter()
        .filter(|peer| !peer.address.is_empty())
        .map(|peer| Host {
            name: peer.name.clone(),
            address: peer.address.clone(),
            connection_mode: "forward".to_string(),
            state: "unknown".to_string(),
            device_id: peer.fingerprint.clone(),
        })
        .collect()
}

/// Pure mapping: one reverse-source entry becomes a `Host` (`docs/CLI.md`
/// §5: reverse `state` is whatever the daemon reported, `device_id` is the
/// TLS-verified fingerprint).
fn reverse_host(entry: &ReverseHostEntry) -> Host {
    Host {
        name: entry.local.name.clone(),
        address: entry.local.address.clone(),
        connection_mode: "reverse".to_string(),
        state: entry.local.state.clone(),
        device_id: entry.local.fingerprint.clone(),
    }
}

/// `host.list`'s merge: forward and reverse entries, concatenated —
/// **never** merged by name (`docs/CLI.md` §6.1). The same name present in
/// both sources yields two entries; the same name held live by two
/// daemons still yields two entries (listing never fails closed —
/// `resolve_host_route` is where routing fails closed instead).
fn merge_hosts(forward: Vec<Host>, reverse: &[ReverseHostEntry]) -> Vec<Host> {
    let mut hosts = forward;
    hosts.extend(reverse.iter().map(reverse_host));
    hosts
}

/// A reverse-source entry counts as "live" for routing purposes when the
/// daemon that reported it currently holds an authenticated connection to
/// it (`state == "reachable"`, `daemon.rs`'s `to_local_host` mapping of
/// [`crate::reverse::registry::EntryState::Live`]). A `"stale"` entry is
/// not a proven-reachable path — `resolve_host_route` falls through to the
/// forward pin (or `HOST_NOT_FOUND`) exactly as if it were absent.
fn is_live(entry: &ReverseHostEntry) -> bool {
    entry.local.state == "reachable"
}

/// The pure decision [`Ops::resolve_host_route`] delegates to — see that
/// method's doc for the rule. Split out from any I/O (daemon queries,
/// trust-file load) so the routing table (`PLAN.md` M3 Step 5 (c)) is
/// testable against hand-built sources, exactly like [`merge_hosts`]
/// above.
fn resolve_route(
    reverse: &[ReverseHostEntry],
    store: &TrustStore,
    name: &str,
) -> Result<HostRoute, OpError> {
    if name.trim().is_empty() {
        // An empty/whitespace-only name is an argument defect, not a
        // missing host: falling through to `HOST_NOT_FOUND` below would
        // interpolate `name` into that error's remediation message and
        // produce a malformed, un-runnable `qsh trust add` suggestion
        // (adversarial review finding). `ErrorCode::InvalidArgument` is
        // already the vocabulary this function uses for the two-daemon
        // case, so this reuses it rather than inventing a new code.
        return Err(OpError::new(
            ErrorCode::InvalidArgument,
            "host name must not be empty",
        ));
    }

    let live: Vec<&ReverseHostEntry> = reverse
        .iter()
        .filter(|entry| entry.local.name == name && is_live(entry))
        .collect();

    match live.as_slice() {
        [] => {}
        [entry] => {
            return Ok(HostRoute::Reverse {
                pid: entry.pid,
                socket: entry.socket.clone(),
                address: entry.local.address.clone(),
                fingerprint: entry.local.fingerprint.clone(),
                generation: entry.local.generation,
            });
        }
        many => {
            let mut pids: Vec<u32> = many.iter().map(|entry| entry.pid).collect();
            pids.sort_unstable();
            pids.dedup();
            return Err(OpError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "host {name:?} is registered live by more than one qsh listen daemon on \
                     this machine (pids {pids:?}); routing refuses to guess which one to use \
                     — stop the stale daemon or use distinct registration names"
                ),
            )
            .with_details(serde_json::json!({ "pids": pids })));
        }
    }

    // Reuses `TrustStore::resolve_host` — the single existing "a pin only
    // routes when it carries an address" predicate `ops::resolve_peer_address`
    // (`qsh exec`'s own routing) already applies — rather than
    // re-implementing the `!address.is_empty()` rule inline a second time.
    // [`forward_hosts`] below applies the identical rule across every pin
    // for listing; keeping both on `TrustStore::resolve_host`'s definition
    // is what keeps listing and routing from growing divergent rules
    // (adversarial review finding: the two were previously hand-duplicated).
    if let Some(peer) = store.resolve_host(name) {
        return Ok(HostRoute::Forward {
            address: peer.address.clone(),
            fingerprint: peer.fingerprint.clone(),
        });
    }

    Err(OpError::new(
        ErrorCode::HostNotFound,
        format!(
            "host {name:?} has no live reverse registration on this machine and no address \
             pinned for it; register it (`qsh reverse <controller>` run on that host) or pin \
             one here with `qsh trust add {name} --address <host:port> --fingerprint sha256:...`"
        ),
    ))
}

impl Ops {
    /// `host.list` (`qsh hosts`, `docs/CLI.md` §6.1). Authorization-free
    /// local operation (§2.5) — no ACL check, no dial, purely local reads.
    pub fn host_list(&self) -> Result<HostListData, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        let forward = forward_hosts(&store);
        let reverse = self.reverse_host_entries();
        Ok(HostListData {
            hosts: merge_hosts(forward, &reverse),
        })
    }

    /// `host.get` (`qsh host get <name>`, `docs/CLI.md` §6.1). Authorization-
    /// free local operation (§2.5). Returns the single [`Host`] that
    /// [`Ops::resolve_host_route`] would route to — the exact same
    /// decision `Ops::connect` (Step 6) and the human renderer's "route
    /// that would be used" reuse.
    pub fn host_get(&self, req: HostGetReq) -> Result<Host, OpError> {
        let route = self.resolve_host_route(&req.name)?;
        Ok(route.into_host(&req.name))
    }

    /// Resolve `name` to the peer this machine would actually reach it
    /// through — the one function `host.get`, the human renderer, and
    /// (Step 6) `Ops::connect` all share (`PLAN.md` M3 Step 5).
    ///
    /// Rule: a live reverse registration wins over a forward pin (a proven
    /// reachable path beats trust store's estimated address);
    /// unregistered-and-unpinned is [`ErrorCode::HostNotFound`] with a
    /// message that guides both remedies; the same name held live by two
    /// daemons on this machine is [`ErrorCode::InvalidArgument`] with the
    /// pid list in `details` — routing fails closed rather than guessing
    /// which daemon to trust (`docs/CLI.md` §6.1's "라우팅 우선순위는 live
    /// reverse 등록이 우선").
    ///
    /// **Sync, and not callable from inside a running Tokio runtime.** This
    /// method (via [`Self::reverse_host_entries`]) builds its own
    /// current-thread runtime and `block_on`s it; calling it from code that
    /// is itself already executing inside a Tokio runtime panics ("Cannot
    /// start a runtime from within a runtime"). PR 5b's own callers are all
    /// sync (`Ops::host_list`, `Ops::host_get`, the CLI frontend), so this
    /// is not reached today — `crates/qsh-testkit/tests/host_list_reverse.rs`
    /// calls this method from `#[tokio::test]` code via
    /// `tokio::task::spawn_blocking`, which sidesteps the panic by running
    /// the `block_on` on a blocking-pool thread rather than the calling
    /// task's own thread. Step 6's `Ops::connect` (`crate::ops::session`)
    /// already runs its dial logic inside its own outer `block_on`, so it
    /// will hit this exact hazard when it starts calling this method — it
    /// will need either the same `spawn_blocking` wrapper or a dedicated
    /// async variant of the reverse-source lookup; this is a Step 6 wiring
    /// concern, not a PR 5b defect (adversarial review finding).
    pub fn resolve_host_route(&self, name: &str) -> Result<HostRoute, OpError> {
        let reverse = self.reverse_host_entries();
        let store = TrustStore::load(&self.paths.trust_file())?;
        resolve_route(&reverse, &store, name)
    }

    /// The reverse source: the union of `LocalHostList` across every
    /// localctl daemon discovered on this machine — unix only, since
    /// localctl (UDS) has no meaning on Windows (`docs/CLI.md` §6.13:
    /// Windows `qsh hosts` returns forward hosts only, not an error).
    fn reverse_host_entries(&self) -> Vec<ReverseHostEntry> {
        #[cfg(unix)]
        {
            let runtime_dir = self.paths().runtime_dir();
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    // Never fail `host.list` over this: a runtime that
                    // cannot even start is exactly the "one sleeping
                    // laptop must not hide every other host" discipline
                    // extended to "this machine's own daemons must not
                    // hide the forward hosts" (`docs/CLI.md` §6.2).
                    tracing::warn!(
                        %err,
                        "host.list: failed to start an async runtime for the reverse source; \
                         reporting forward hosts only"
                    );
                    return Vec::new();
                }
            };
            runtime.block_on(async {
                crate::localctl::client::admin_host_list_all(&runtime_dir)
                    .await
                    .into_iter()
                    .flat_map(|daemon| {
                        let pid = daemon.pid;
                        let socket = daemon.socket;
                        daemon.hosts.into_iter().map(move |local| ReverseHostEntry {
                            pid,
                            socket: socket.clone(),
                            local,
                        })
                    })
                    .collect()
            })
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_local(name: &str, state: &str, fingerprint: &str) -> LocalHost {
        LocalHost {
            name: name.to_string(),
            address: "203.0.113.5:51820".to_string(),
            state: state.to_string(),
            fingerprint: fingerprint.to_string(),
            capabilities: vec!["pty".to_string()],
            generation: 1,
            registered_at: "2026-08-22T00:00:00Z".to_string(),
        }
    }

    fn reverse_entry(pid: u32, name: &str, state: &str, fingerprint: &str) -> ReverseHostEntry {
        ReverseHostEntry {
            pid,
            socket: PathBuf::from(format!("/run/qsh/{pid}.sock")),
            local: sample_local(name, state, fingerprint),
        }
    }

    fn forward_store(name: &str, address: &str, fingerprint: &str) -> TrustStore {
        let mut store = TrustStore::default();
        store.add_peer(
            name,
            Some(address.to_string()),
            fingerprint.parse().expect("fingerprint"),
            "2026-01-01T00:00:00Z".to_string(),
        );
        store
    }

    const FP_A: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // Not "BBBB…B": an all-`B` run of 43 base64 chars has non-zero trailing
    // bits in its last symbol, which `Fingerprint::from_str`'s canonical
    // decoder rejects (`FingerprintParseError`) — this is the base64
    // encoding of 32 `0xBB` bytes, which round-trips cleanly through
    // `.parse()` at line ~502 below (caught by gate run: nextest failure
    // pre-existing in this diff, not a change in behavior).
    const FP_B: &str = "sha256:u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";

    // ---- merge table (`PLAN.md` M3 Step 5 (c)) ----

    #[test]
    fn merge_forward_only() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let hosts = merge_hosts(forward_hosts(&store), &[]);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].connection_mode, "forward");
        assert_eq!(hosts[0].state, "unknown");
    }

    #[test]
    fn merge_reverse_only() {
        let reverse = vec![reverse_entry(100, "phone", "reachable", FP_A)];
        let hosts = merge_hosts(Vec::new(), &reverse);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].connection_mode, "reverse");
        assert_eq!(hosts[0].state, "reachable");
    }

    #[test]
    fn merge_same_name_both_sources_yields_two_entries() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let reverse = vec![reverse_entry(100, "mac", "reachable", FP_B)];
        let hosts = merge_hosts(forward_hosts(&store), &reverse);
        assert_eq!(hosts.len(), 2, "same name in both sources must not merge");
        let modes: std::collections::BTreeSet<&str> =
            hosts.iter().map(|h| h.connection_mode.as_str()).collect();
        assert_eq!(
            modes,
            std::collections::BTreeSet::from(["forward", "reverse"])
        );
    }

    #[test]
    fn merge_includes_stale_reverse_entries() {
        let reverse = vec![reverse_entry(100, "old-laptop", "stale", FP_A)];
        let hosts = merge_hosts(Vec::new(), &reverse);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].state, "stale");
    }

    #[test]
    fn merge_with_no_daemons_is_forward_only_not_an_error() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let hosts = merge_hosts(forward_hosts(&store), &[]);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].connection_mode, "forward");
    }

    #[test]
    fn forward_hosts_skips_pins_with_no_address() {
        let mut store = TrustStore::default();
        store.add_peer(
            "addressless",
            None,
            FP_A.parse().expect("fingerprint"),
            "2026-01-01T00:00:00Z".to_string(),
        );
        assert!(forward_hosts(&store).is_empty());
    }

    #[test]
    fn forward_hosts_and_resolve_route_agree_on_routability() {
        // Pins a `forward_hosts` (listing) and `resolve_route` (routing)
        // must agree on: one with an address, one without. If the two ever
        // re-diverge (adversarial review finding: they used to be two
        // hand-written copies of the same filter), this catches it as a
        // mismatch rather than as two independently-passing but
        // inconsistent test suites.
        let mut store = TrustStore::default();
        store.add_peer(
            "routable",
            Some("routable.example.com:4433".to_string()),
            FP_A.parse().expect("fingerprint"),
            "2026-01-01T00:00:00Z".to_string(),
        );
        store.add_peer(
            "addressless",
            None,
            FP_B.parse().expect("fingerprint"),
            "2026-01-01T00:00:00Z".to_string(),
        );

        let listed: std::collections::BTreeSet<String> = forward_hosts(&store)
            .into_iter()
            .map(|host| host.name)
            .collect();
        assert_eq!(
            listed,
            std::collections::BTreeSet::from(["routable".to_string()])
        );

        assert!(resolve_route(&[], &store, "routable").is_ok());
        let err = resolve_route(&[], &store, "addressless").unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    // ---- routing table (`PLAN.md` M3 Step 5 (c)) ----
    //
    // These call `resolve_route` (the pure function `Ops::resolve_host_route`
    // itself delegates to) directly against hand-built sources — the
    // injectable seam the module docs promise, no real socket or on-disk
    // trust file involved.

    #[test]
    fn routing_prefers_live_reverse_over_forward_pin() {
        let store = forward_store("mac", "stale-estimate.example.com:4433", FP_A);
        let reverse = vec![reverse_entry(100, "mac", "reachable", FP_B)];
        let route = resolve_route(&reverse, &store, "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Reverse {
                pid: 100,
                socket: PathBuf::from("/run/qsh/100.sock"),
                address: "203.0.113.5:51820".to_string(),
                fingerprint: FP_B.to_string(),
                generation: 1,
            }
        );
    }

    #[test]
    fn routing_falls_back_to_forward_pin_when_no_live_reverse_entry() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        // Only a stale reverse entry — not live, must not win.
        let reverse = vec![reverse_entry(100, "mac", "stale", FP_B)];
        let route = resolve_route(&reverse, &store, "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Forward {
                address: "mac.example.com:4433".to_string(),
                fingerprint: FP_A.to_string(),
            }
        );
    }

    #[test]
    fn routing_on_an_empty_or_whitespace_name_is_invalid_argument_not_host_not_found() {
        // An empty name is an argument defect (`ErrorCode::InvalidArgument`),
        // never `HOST_NOT_FOUND` — falling through to `HOST_NOT_FOUND`
        // would interpolate the empty name into that error's remediation
        // message and produce a malformed `qsh trust add` suggestion
        // (adversarial review finding).
        let store = TrustStore::default();
        for name in ["", "   ", "\t"] {
            let err = resolve_route(&[], &store, name).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "name {name:?}");
        }
    }

    #[test]
    fn routing_unregistered_and_unpinned_is_host_not_found() {
        let store = TrustStore::default();
        let err = resolve_route(&[], &store, "nowhere").unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    #[test]
    fn routing_two_live_daemons_is_invalid_argument_with_pids() {
        let store = TrustStore::default();
        let reverse = vec![
            reverse_entry(200, "mac", "reachable", FP_A),
            reverse_entry(100, "mac", "reachable", FP_B),
        ];
        let err = resolve_route(&reverse, &store, "mac").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.details["pids"], serde_json::json!([100, 200]));
    }

    #[test]
    fn routing_ignores_a_stale_duplicate_and_uses_the_live_one() {
        let store = TrustStore::default();
        let reverse = vec![
            reverse_entry(200, "mac", "stale", FP_A),
            reverse_entry(100, "mac", "reachable", FP_B),
        ];
        let route = resolve_route(&reverse, &store, "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Reverse {
                pid: 100,
                socket: PathBuf::from("/run/qsh/100.sock"),
                address: "203.0.113.5:51820".to_string(),
                fingerprint: FP_B.to_string(),
                generation: 1,
            }
        );
    }

    #[test]
    fn host_route_into_host_matches_the_json_contract_vocabulary() {
        let forward = HostRoute::Forward {
            address: "mac.example.com:4433".to_string(),
            fingerprint: FP_A.to_string(),
        }
        .into_host("mac");
        assert_eq!(forward.connection_mode, "forward");
        assert_eq!(forward.state, "unknown");

        let reverse = HostRoute::Reverse {
            pid: 100,
            socket: PathBuf::from("/run/qsh/100.sock"),
            address: "203.0.113.5:51820".to_string(),
            fingerprint: FP_B.to_string(),
            generation: 3,
        }
        .into_host("phone");
        assert_eq!(reverse.connection_mode, "reverse");
        assert_eq!(reverse.state, "reachable");
    }
}
