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

use std::collections::HashSet;
use std::path::PathBuf;

use qsh_proto::local::LocalHost;
use qsh_proto::{ErrorCode, Host, HostGetReq, HostListData, TrustPeer};

use crate::hosts::{HostEntry, HostsFile};
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
    /// Dial directly — the address `hosts.toml`/the trust store pin
    /// resolves to (`PLAN.md` M7 Step 3, [`resolve_forward`]).
    Forward {
        /// `host:port` to dial — `hosts.toml`'s address when it has this
        /// name, the trust store pin's address otherwise.
        address: String,
        /// The pinned SPKI SHA-256 fingerprint, from the trust store.
        /// Empty when no trust-store peer shares this name — a
        /// `hosts.toml`-only entry names an address, never an identity
        /// (this module's own doc).
        fingerprint: String,
        /// Which directory's *address* actually won — `"hosts"`/`"trust"`/
        /// `"both"` (`"both"` only when they agree — [`resolve_forward`]'s
        /// own doc, `PLAN.md` Step 3 (a)-추기 ②) — or `None` when
        /// `hosts.toml` has no entries at all (preserves the pre-M7-Step-3
        /// `Host` shape exactly, `docs/CLI.md` §5).
        source: Option<String>,
        /// `hosts.toml`'s `user` hint for this name, if it set one.
        user: Option<String>,
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
        /// `hosts.toml`'s `user` hint for this name, if it set a non-empty
        /// one — carried through so a reverse-routed name's displayed
        /// `Host.user` matches what `Ops::session_open`'s
        /// `resolve_user_hint` actually sends: that helper resolves the
        /// hint purely from the host *name*, before routing ever decides
        /// forward vs. reverse, so a reverse route showing `user: None`
        /// while the hint is genuinely applied would be a display/
        /// applied-value mismatch (`PLAN.md` Step 3 (a)-추기 ④, P3-5). `source`
        /// stays `None`/omitted for a reverse route regardless (this
        /// struct's own field doc on the Forward arm) — `source` is an
        /// *address* concept and a reverse route's address never comes
        /// from `hosts.toml`; `user` has no such tie to the address.
        user: Option<String>,
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
                source,
                user,
            } => Host {
                name: name.to_string(),
                address,
                connection_mode: "forward".to_string(),
                state: "unknown".to_string(),
                device_id: fingerprint,
                source,
                user,
            },
            HostRoute::Reverse {
                address,
                fingerprint,
                user,
                ..
            } => Host {
                name: name.to_string(),
                address,
                connection_mode: "reverse".to_string(),
                state: "reachable".to_string(),
                device_id: fingerprint,
                // A reverse registration is never `hosts.toml`-sourced —
                // it comes from a live daemon, not either address book
                // (this struct's own field doc). `user` is not tied to
                // that — see `HostRoute::Reverse::user`'s own doc.
                source: None,
                user,
            },
        }
    }
}

/// The resolved forward-route data for one host name, after layering
/// `hosts.toml` over `trust.toml`'s pinned peers (`PLAN.md` M7 §4.1 #4,
/// `crate::hosts` module doc): `hosts.toml`'s address wins when both name
/// this host; the fingerprint always comes from `trust.toml` —
/// `hosts.toml` never supplies identity, only ever an address/user hint.
///
/// `pub(super)`: [`crate::ops::resolve_peer_address`] (`ops/mod.rs`) reuses
/// this exact struct/function rather than re-deriving the merge rule a
/// second time — the same "one choke point" discipline `forward_hosts`'s
/// own doc calls out for [`crate::trust::TrustStore::resolve_host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ForwardEntry {
    pub(super) address: String,
    pub(super) fingerprint: String,
    pub(super) source: Option<String>,
    pub(super) user: Option<String>,
}

/// Layer one name's `hosts.toml` entry over its `trust.toml` pin
/// (`PLAN.md` M7 §4.1 #4). `None` means neither source has a routable
/// address for this name.
///
/// - **Address:** `hosts.toml`'s address when it has a non-empty one for
///   this name; the trust pin's address otherwise. An explicit
///   `hosts.toml` entry with an empty `address` is not routable from
///   there — falls through to the trust pin exactly like a client-only
///   pin's own empty address does (`crate::hosts::HostEntry::address`'s
///   doc).
/// - **Fingerprint:** always `trust_peer`'s, empty when no trust peer
///   shares this name — `hosts.toml` never asserts identity.
/// - **`source`:** which directory's *address* actually won, redefined
///   post-Step-3-verification (`PLAN.md` Step 3 (a)-추기 ②) away from "which
///   directory names this host" — the original definition let `"both"`
///   mean "the two directories disagree on the address" exactly as often
///   as it meant "they agree", which hid the one thing an operator most
///   needs `qsh hosts`/`qsh host get` to say out loud: whether `hosts.toml`
///   silently redirected a pinned name somewhere `trust.toml` never said
///   (`docs/CLI.md` §6.1's threat paragraph). Now: `"hosts"` when
///   `hosts.toml`'s address is the one used, because either `trust.toml`
///   has none for this name or the two addresses differ (`hosts.toml`
///   always wins a disagreement — the priority rule above — so a
///   disagreement is exactly a redirect, not an agreement); `"trust"`
///   when `trust.toml`'s address is the one used, because either
///   `hosts.toml` has no entry for this name or its entry's address is
///   empty; `"both"` **only** when both sides name a non-empty address
///   and the two addresses are identical — the one case that is actually
///   "they agree", which is the only case the old definition's "both"
///   claimed to mean but didn't reliably. `None` (not `Some(_)`) whenever
///   `hosts.toml` has zero entries anywhere in the whole file, so a
///   deployment that never adopted `hosts.toml` gets byte-identical
///   `Host` JSON to before M7 Step 3 (`docs/CLI.md` §5's additive-only
///   contract; pinned by the pre-existing `host.list.json`/
///   `host.get.json` goldens) — this part of the rule is unchanged by the
///   redefinition.
/// - **`user`:** `hosts.toml`'s hint for this name, if it set one —
///   independent of which address won, since the hint is a property of
///   the name, not of the winning route.
pub(super) fn resolve_forward(
    trust_peer: Option<&TrustPeer>,
    hosts_entry: Option<&HostEntry>,
    hosts_has_any: bool,
) -> Option<ForwardEntry> {
    let hosts_address = hosts_entry
        .map(|entry| entry.address.as_str())
        .filter(|address| !address.is_empty());
    let trust_address = trust_peer
        .map(|peer| peer.address.as_str())
        .filter(|address| !address.is_empty());

    let address = match (hosts_address, trust_address) {
        (Some(address), _) => address.to_string(),
        (None, Some(address)) => address.to_string(),
        (None, None) => return None,
    };

    // Address-winner based, not name-presence based (this function's own
    // doc, above) — the `(None, None)` arm is unreachable because the
    // `address` match above already returned `None` for that case.
    let source = match (hosts_address, trust_address) {
        (Some(hosts), Some(trust)) if hosts == trust => "both",
        (Some(_), _) => "hosts",
        (None, Some(_)) => "trust",
        (None, None) => unreachable!("an address above came from one of the two sources"),
    };

    Some(ForwardEntry {
        address,
        fingerprint: trust_peer
            .map(|peer| peer.fingerprint.clone())
            .unwrap_or_default(),
        source: hosts_has_any.then(|| source.to_string()),
        user: hosts_entry.and_then(|entry| entry.user.clone()),
    })
}

/// Pure mapping: every name either `hosts.toml` or a routable `trust.toml`
/// pin knows about becomes one forward `Host` entry (`docs/CLI.md` §5,
/// extended `PLAN.md` M7 Step 3 by [`resolve_forward`]). Split out from
/// any I/O so the merge table (`PLAN.md` M3 Step 5 (c)) is testable
/// against hand-built [`TrustStore`]/[`HostsFile`] values, never real
/// files.
///
/// Name order: trust pins first (in store order, the pre-M7-Step-3
/// order), then any `hosts.toml`-only names not already covered, in file
/// order — keeps the existing goldens' entry order unperturbed when
/// `hosts.toml` is absent or only restates trust names.
fn forward_hosts(store: &TrustStore, hosts: &HostsFile) -> Vec<Host> {
    let hosts_has_any = !hosts.entries().is_empty();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut names: Vec<&str> = Vec::new();
    for peer in store.peers() {
        if seen.insert(peer.name.as_str()) {
            names.push(peer.name.as_str());
        }
    }
    for entry in hosts.entries() {
        if seen.insert(entry.name.as_str()) {
            names.push(entry.name.as_str());
        }
    }

    names
        .into_iter()
        .filter_map(|name| {
            let entry = resolve_forward(store.find(name), hosts.find(name), hosts_has_any)?;
            Some(Host {
                name: name.to_string(),
                address: entry.address,
                connection_mode: "forward".to_string(),
                state: "unknown".to_string(),
                device_id: entry.fingerprint,
                source: entry.source,
                user: entry.user,
            })
        })
        .collect()
}

/// `hosts.toml`'s `user` hint for `name`, if it set a non-empty one — the
/// exact same lookup+filter [`crate::ops::session::Ops::resolve_user_hint`]
/// applies (`docs/CLI.md` §7), reused here so a reverse-routed name's
/// listed/displayed `user` matches what that choke point actually sends
/// (`PLAN.md` Step 3 (a)-추기 ④, P3-5) — that helper resolves the hint from
/// the host *name* alone, before routing ever decides forward vs. reverse,
/// so this module's own reverse-`Host` builders have to do the identical
/// lookup rather than hard-coding `None`.
fn hosts_toml_user(hosts: &HostsFile, name: &str) -> Option<String> {
    hosts
        .find(name)
        .and_then(|entry| entry.user.clone())
        .filter(|user| !user.trim().is_empty())
}

/// Pure mapping: one reverse-source entry becomes a `Host` (`docs/CLI.md`
/// §5: reverse `state` is whatever the daemon reported, `device_id` is the
/// TLS-verified fingerprint). `hosts` is consulted only for [`hosts_toml_user`]
/// — a reverse route's `source`/address never come from `hosts.toml`.
fn reverse_host(entry: &ReverseHostEntry, hosts: &HostsFile) -> Host {
    Host {
        name: entry.local.name.clone(),
        address: entry.local.address.clone(),
        connection_mode: "reverse".to_string(),
        state: entry.local.state.clone(),
        device_id: entry.local.fingerprint.clone(),
        // Never `hosts.toml`-sourced — see `HostRoute::into_host`'s
        // identical Reverse-arm comment.
        source: None,
        user: hosts_toml_user(hosts, &entry.local.name),
    }
}

/// `host.list`'s merge: forward and reverse entries, concatenated —
/// **never** merged by name (`docs/CLI.md` §6.1). The same name present in
/// both sources yields two entries; the same name held live by two
/// daemons still yields two entries (listing never fails closed —
/// `resolve_host_route` is where routing fails closed instead).
fn merge_hosts(forward: Vec<Host>, reverse: &[ReverseHostEntry], hosts: &HostsFile) -> Vec<Host> {
    let mut all = forward;
    all.extend(reverse.iter().map(|entry| reverse_host(entry, hosts)));
    all
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
    hosts: &HostsFile,
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
                user: hosts_toml_user(hosts, name),
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

    // Reuses `resolve_forward` — the single existing "layer hosts.toml over
    // the trust pin" rule `ops::resolve_peer_address` (`qsh exec`'s own
    // routing) also calls — rather than re-implementing the merge inline a
    // second time. [`forward_hosts`] above applies the identical rule
    // across every name for listing; keeping both on `resolve_forward`'s
    // definition is what keeps listing and routing from growing divergent
    // rules (the same discipline the pre-M7-Step-3 code already followed
    // for `TrustStore::resolve_host`).
    let hosts_has_any = !hosts.entries().is_empty();
    if let Some(entry) = resolve_forward(store.find(name), hosts.find(name), hosts_has_any) {
        return Ok(HostRoute::Forward {
            address: entry.address,
            fingerprint: entry.fingerprint,
            source: entry.source,
            user: entry.user,
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
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let forward = forward_hosts(&store, &hosts);
        let reverse = self.reverse_host_entries();
        Ok(HostListData {
            hosts: merge_hosts(forward, &reverse, &hosts),
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
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        resolve_route(&reverse, &store, &hosts, name)
    }

    /// The async twin of [`Self::resolve_host_route`] — same decision
    /// (delegates to the same pure [`resolve_route`]), but never builds or
    /// blocks on its own runtime, so it is safe to call from *inside* one
    /// that already exists (`PLAN.md` M3 Step 6's async seam).
    ///
    /// `Ops::connect` (`crate::ops::session`) does **not** need this seam
    /// today: it calls the sync [`Self::resolve_host_route`] from
    /// `Ops::resolve_route` *before* `connect_target`/`connect_reverse`
    /// build their own dial runtime, so the throwaway probe runtime this
    /// resolves with and the dial's own multi-thread runtime are
    /// sequential, never nested — no caller on the current CLI/MCP-less
    /// call graph reaches `connect` from inside an already-running
    /// runtime (`main` is a plain sync `fn`). This method exists as the
    /// seam for the caller that eventually will run inside one — a future
    /// async host (an MCP adapter, or any other async entry point) that
    /// needs the same routing decision without the sync method's "cannot
    /// start a runtime from within a runtime" hazard — so that caller
    /// never has to reach for `crates/qsh-testkit/tests/host_list_reverse.rs`'s
    /// `spawn_blocking` workaround the way today's sync-only callers do.
    pub async fn resolve_host_route_async(&self, name: &str) -> Result<HostRoute, OpError> {
        let reverse = self.reverse_host_entries_async().await;
        let store = TrustStore::load(&self.paths.trust_file())?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        resolve_route(&reverse, &store, &hosts, name)
    }

    /// The reverse source: the union of `LocalHostList` across every
    /// localctl daemon discovered on this machine — unix only, since
    /// localctl (UDS) has no meaning on Windows (`docs/CLI.md` §6.13:
    /// Windows `qsh hosts` returns forward hosts only, not an error).
    ///
    /// Sync wrapper around [`Self::reverse_host_entries_async`]: builds a
    /// throwaway current-thread runtime and `block_on`s it, exactly the
    /// way [`Self::resolve_host_route`] always has — this method is that
    /// runtime-management, factored out so the async logic itself lives in
    /// exactly one place.
    fn reverse_host_entries(&self) -> Vec<ReverseHostEntry> {
        #[cfg(unix)]
        {
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
            runtime.block_on(self.reverse_host_entries_async())
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    }

    /// The truly-async half of [`Self::reverse_host_entries`] — no runtime
    /// of its own, so it is safe to `.await` directly from inside a
    /// caller's own runtime (see [`Self::resolve_host_route_async`]).
    #[cfg(unix)]
    async fn reverse_host_entries_async(&self) -> Vec<ReverseHostEntry> {
        let runtime_dir = self.paths().runtime_dir();
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
    }

    /// Windows twin of [`Self::reverse_host_entries_async`]: localctl (UDS)
    /// has no meaning there, so the reverse source is always empty
    /// (`docs/CLI.md` §6.13).
    #[cfg(not(unix))]
    async fn reverse_host_entries_async(&self) -> Vec<ReverseHostEntry> {
        Vec::new()
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

    /// The pre-M7-Step-3 shape every test in this module that isn't
    /// specifically about `hosts.toml` layering keeps using — an absent
    /// directory, so `source`/`user` stay `None` throughout
    /// (`resolve_forward`'s own doc).
    fn no_hosts() -> HostsFile {
        HostsFile::default()
    }

    fn hosts_with(entries: &[(&str, &str, Option<&str>)]) -> HostsFile {
        let toml = entries
            .iter()
            .map(|(name, address, user)| match user {
                Some(user) => format!(
                    "[[host]]\nname = \"{name}\"\naddress = \"{address}\"\nuser = \"{user}\"\n"
                ),
                None => format!("[[host]]\nname = \"{name}\"\naddress = \"{address}\"\n"),
            })
            .collect::<Vec<_>>()
            .join("\n");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hosts.toml");
        std::fs::write(&path, toml).expect("write hosts.toml");
        // `HostsFile::load` reads and fully owns its result before `dir`
        // goes out of scope at the end of this function — nothing in the
        // returned value references the directory afterward.
        HostsFile::load(&path).expect("parses")
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
        let hosts = merge_hosts(forward_hosts(&store, &no_hosts()), &[], &no_hosts());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].connection_mode, "forward");
        assert_eq!(hosts[0].state, "unknown");
    }

    #[test]
    fn merge_reverse_only() {
        let reverse = vec![reverse_entry(100, "phone", "reachable", FP_A)];
        let hosts = merge_hosts(Vec::new(), &reverse, &no_hosts());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].connection_mode, "reverse");
        assert_eq!(hosts[0].state, "reachable");
    }

    #[test]
    fn merge_same_name_both_sources_yields_two_entries() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let reverse = vec![reverse_entry(100, "mac", "reachable", FP_B)];
        let hosts = merge_hosts(forward_hosts(&store, &no_hosts()), &reverse, &no_hosts());
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
        let hosts = merge_hosts(Vec::new(), &reverse, &no_hosts());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].state, "stale");
    }

    #[test]
    fn merge_with_no_daemons_is_forward_only_not_an_error() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let hosts = merge_hosts(forward_hosts(&store, &no_hosts()), &[], &no_hosts());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].connection_mode, "forward");
    }

    #[test]
    fn merge_carries_the_hosts_toml_user_hint_onto_a_reverse_entry() {
        // P3-5 (`PLAN.md` Step 3 (a)-추기 ④): `Ops::session_open`'s
        // `resolve_user_hint` fills the default purely from the host
        // *name*, before routing ever decides forward vs. reverse — so a
        // reverse-routed name's listed `Host.user` must match, not show
        // `None` while the hint is genuinely applied.
        let reverse = vec![reverse_entry(100, "phone", "reachable", FP_A)];
        let hosts = hosts_with(&[("phone", "unused.example.com:1", Some("dave"))]);
        let listed = merge_hosts(Vec::new(), &reverse, &hosts);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].user.as_deref(), Some("dave"));
        assert_eq!(
            listed[0].source, None,
            "source stays a pure address concept — never set for a reverse entry"
        );
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
        assert!(forward_hosts(&store, &no_hosts()).is_empty());
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

        let listed: std::collections::BTreeSet<String> = forward_hosts(&store, &no_hosts())
            .into_iter()
            .map(|host| host.name)
            .collect();
        assert_eq!(
            listed,
            std::collections::BTreeSet::from(["routable".to_string()])
        );

        assert!(resolve_route(&[], &store, &no_hosts(), "routable").is_ok());
        let err = resolve_route(&[], &store, &no_hosts(), "addressless").unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    // ---- hosts.toml priority/merge (`PLAN.md` M7 Step 3, §4.1 #4) ----
    //
    // `resolve_forward` (via `forward_hosts`/`resolve_route`, its only two
    // callers) is the single place this decision is made; these tests pin
    // every combination the design draft calls out by name: hosts.toml
    // absent, hosts.toml naming a host trust doesn't, trust naming a host
    // hosts.toml doesn't, and both naming the same host with different
    // addresses (hosts.toml's address must win, trust's fingerprint must
    // still be the one reported).

    #[test]
    fn absent_hosts_toml_is_byte_identical_to_pre_m7_step_3_forward_hosts() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let hosts = forward_hosts(&store, &no_hosts());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].address, "mac.example.com:4433");
        assert_eq!(hosts[0].device_id, FP_A);
        assert_eq!(
            hosts[0].source, None,
            "no hosts.toml entries anywhere -> source stays unset, not Some(\"trust\")"
        );
        assert_eq!(hosts[0].user, None);
    }

    #[test]
    fn hosts_toml_only_name_is_forward_routable_with_no_fingerprint() {
        // A name hosts.toml knows and trust.toml has never heard of: still
        // listed/routable (an address, no identity) — trust alone remains
        // the authority on *who* answers at that address when actually
        // dialed (this module's own `HostRoute::Forward::fingerprint` doc).
        let store = TrustStore::default();
        let hosts = hosts_with(&[("headless", "headless.example.com:4433", None)]);

        let listed = forward_hosts(&store, &hosts);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].address, "headless.example.com:4433");
        assert_eq!(
            listed[0].device_id, "",
            "no trust peer -> empty fingerprint"
        );
        assert_eq!(listed[0].source.as_deref(), Some("hosts"));

        let route = resolve_route(&[], &store, &hosts, "headless").unwrap();
        assert_eq!(
            route,
            HostRoute::Forward {
                address: "headless.example.com:4433".to_string(),
                fingerprint: String::new(),
                source: Some("hosts".to_string()),
                user: None,
            }
        );
    }

    #[test]
    fn trust_only_name_reports_source_trust_once_hosts_toml_exists_at_all() {
        // hosts.toml has *some* entries (for an unrelated name), so
        // `source` starts appearing at all — a name only trust.toml knows
        // must then report `"trust"`, not silently omit the field the way
        // `absent_hosts_toml_is_byte_identical_to_pre_m7_step_3_forward_hosts`
        // pins for the *no hosts.toml entries anywhere* case.
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let hosts = hosts_with(&[("phone", "phone.example.com:4433", None)]);

        let listed = forward_hosts(&store, &hosts);
        let mac = listed.iter().find(|h| h.name == "mac").unwrap();
        assert_eq!(mac.address, "mac.example.com:4433");
        assert_eq!(mac.source.as_deref(), Some("trust"));
        assert_eq!(mac.user, None);
    }

    #[test]
    fn hosts_toml_address_wins_over_trust_toml_address_for_the_same_name() {
        // The one decision `PLAN.md` M7 §4.1 #4 names explicitly:
        // hosts.toml's address wins; trust.toml's fingerprint is still the
        // one reported (hosts.toml never supplies identity). The two
        // addresses disagree here, so under the redefined `source`
        // (`PLAN.md` Step 3 (a)-추기 ②: which side's *address* won, not
        // which sides merely *name* the host) this is exactly the
        // silent-redirect-to-a-different-pinned-peer shape `source` exists
        // to surface -> `"hosts"`, not `"both"`.
        let store = forward_store("mac", "stale-trust-address.example.com:4433", FP_A);
        let hosts = hosts_with(&[("mac", "fresh-hosts-address.example.com:4433", None)]);

        let listed = forward_hosts(&store, &hosts);
        assert_eq!(
            listed.len(),
            1,
            "same name in both -> one merged entry, not two"
        );
        assert_eq!(listed[0].address, "fresh-hosts-address.example.com:4433");
        assert_eq!(
            listed[0].device_id, FP_A,
            "identity still comes from trust.toml alone"
        );
        assert_eq!(
            listed[0].source.as_deref(),
            Some("hosts"),
            "addresses disagree -> hosts.toml's address won, not a same-address agreement"
        );

        let route = resolve_route(&[], &store, &hosts, "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Forward {
                address: "fresh-hosts-address.example.com:4433".to_string(),
                fingerprint: FP_A.to_string(),
                source: Some("hosts".to_string()),
                user: None,
            }
        );
    }

    #[test]
    fn hosts_toml_and_trust_toml_agreeing_on_the_same_address_report_source_both() {
        // `"both"` is reserved for the case the two sides actually agree —
        // distinct from `hosts_toml_address_wins_over_trust_toml_address_for_the_same_name`
        // above, where they disagree and hosts.toml's address wins alone.
        let store = forward_store("mac", "shared-address.example.com:4433", FP_A);
        let hosts = hosts_with(&[("mac", "shared-address.example.com:4433", None)]);

        let listed = forward_hosts(&store, &hosts);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].address, "shared-address.example.com:4433");
        assert_eq!(listed[0].device_id, FP_A);
        assert_eq!(
            listed[0].source.as_deref(),
            Some("both"),
            "same address on both sides -> \"both\", not just \"hosts\""
        );

        let route = resolve_route(&[], &store, &hosts, "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Forward {
                address: "shared-address.example.com:4433".to_string(),
                fingerprint: FP_A.to_string(),
                source: Some("both".to_string()),
                user: None,
            }
        );
    }

    #[test]
    fn hosts_toml_user_hint_is_carried_through_forward_hosts_and_resolve_route() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        let hosts = hosts_with(&[("mac", "mac.example.com:4433", Some("dave"))]);

        let listed = forward_hosts(&store, &hosts);
        assert_eq!(listed[0].user.as_deref(), Some("dave"));

        let route = resolve_route(&[], &store, &hosts, "mac").unwrap();
        match route {
            HostRoute::Forward { user, .. } => assert_eq!(user.as_deref(), Some("dave")),
            other => panic!("expected a forward route, got {other:?}"),
        }
    }

    #[test]
    fn a_hosts_toml_entry_with_an_empty_address_falls_back_to_the_trust_pin() {
        // `crate::hosts::HostEntry::address`'s own doc: an explicit empty
        // string still parses but is "no route from hosts.toml for this
        // name" — must fall through to trust.toml's address exactly like a
        // client-only trust pin's own empty address does.
        let store = forward_store("mac", "trust-address.example.com:4433", FP_A);
        let hosts = hosts_with(&[("mac", "", Some("dave"))]);

        let listed = forward_hosts(&store, &hosts);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].address, "trust-address.example.com:4433");
        assert_eq!(
            listed[0].source.as_deref(),
            Some("trust"),
            "hosts.toml's address is empty (no route) -> trust.toml's address is the one \
             that actually won, so `source` reports \"trust\" (which side's *address* won), \
             not \"both\" merely because hosts.toml also names this host"
        );
        assert_eq!(
            listed[0].user.as_deref(),
            Some("dave"),
            "the user hint isn't gated on the address actually winning"
        );
    }

    #[test]
    fn hosts_toml_never_makes_an_addressless_client_only_pin_forward_routable_on_its_own_error() {
        // Sanity check on the "trust remains the sole arbiter of identity"
        // rule from the other direction: a hosts.toml-only name with an
        // address is routable (proven above) purely as an address, with no
        // fingerprint — dialing it still fails closed at the TLS layer
        // (`TrustEvaluator::lookup_pin` is fingerprint-keyed, not
        // name-scoped) if no trust peer anywhere shares that fingerprint.
        // This module has no dial step to assert that with directly; the
        // fingerprint being empty here is the on-paper proof of it.
        let store = TrustStore::default();
        let hosts = hosts_with(&[("ghost", "ghost.example.com:4433", None)]);
        let route = resolve_route(&[], &store, &hosts, "ghost").unwrap();
        match route {
            HostRoute::Forward { fingerprint, .. } => assert_eq!(fingerprint, ""),
            other => panic!("expected a forward route, got {other:?}"),
        }
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
        let route = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Reverse {
                pid: 100,
                socket: PathBuf::from("/run/qsh/100.sock"),
                address: "203.0.113.5:51820".to_string(),
                fingerprint: FP_B.to_string(),
                generation: 1,
                user: None,
            }
        );
    }

    #[test]
    fn routing_falls_back_to_forward_pin_when_no_live_reverse_entry() {
        let store = forward_store("mac", "mac.example.com:4433", FP_A);
        // Only a stale reverse entry — not live, must not win.
        let reverse = vec![reverse_entry(100, "mac", "stale", FP_B)];
        let route = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Forward {
                address: "mac.example.com:4433".to_string(),
                fingerprint: FP_A.to_string(),
                source: None,
                user: None,
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
            let err = resolve_route(&[], &store, &no_hosts(), name).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "name {name:?}");
        }
    }

    #[test]
    fn routing_unregistered_and_unpinned_is_host_not_found() {
        let store = TrustStore::default();
        let err = resolve_route(&[], &store, &no_hosts(), "nowhere").unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }

    #[test]
    fn routing_two_live_daemons_is_invalid_argument_with_pids() {
        let store = TrustStore::default();
        let reverse = vec![
            reverse_entry(200, "mac", "reachable", FP_A),
            reverse_entry(100, "mac", "reachable", FP_B),
        ];
        let err = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap_err();
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
        let route = resolve_route(&reverse, &store, &no_hosts(), "mac").unwrap();
        assert_eq!(
            route,
            HostRoute::Reverse {
                pid: 100,
                socket: PathBuf::from("/run/qsh/100.sock"),
                address: "203.0.113.5:51820".to_string(),
                fingerprint: FP_B.to_string(),
                generation: 1,
                user: None,
            }
        );
    }

    #[test]
    fn host_route_into_host_matches_the_json_contract_vocabulary() {
        let forward = HostRoute::Forward {
            address: "mac.example.com:4433".to_string(),
            fingerprint: FP_A.to_string(),
            source: Some("both".to_string()),
            user: Some("dave".to_string()),
        }
        .into_host("mac");
        assert_eq!(forward.connection_mode, "forward");
        assert_eq!(forward.state, "unknown");
        assert_eq!(forward.source.as_deref(), Some("both"));
        assert_eq!(forward.user.as_deref(), Some("dave"));

        // `user: Some(...)` here too (unlike `source`, which a reverse
        // route always omits) — P3-5, `into_host`'s Reverse arm must carry
        // the hint through rather than hard-coding `None`.
        let reverse = HostRoute::Reverse {
            pid: 100,
            socket: PathBuf::from("/run/qsh/100.sock"),
            address: "203.0.113.5:51820".to_string(),
            fingerprint: FP_B.to_string(),
            generation: 3,
            user: Some("dave".to_string()),
        }
        .into_host("phone");
        assert_eq!(reverse.connection_mode, "reverse");
        assert_eq!(reverse.state, "reachable");
        assert_eq!(
            reverse.source, None,
            "a reverse route is never hosts.toml-sourced"
        );
        assert_eq!(
            reverse.user.as_deref(),
            Some("dave"),
            "user is not tied to source — it must still come through"
        );
    }

    // ---- `resolve_host_route_async` (`PLAN.md` M3 Step 6's async seam) ----
    //
    // `#[cfg(unix)]`: localctl (UDS, `tokio::net::UnixListener`) is
    // unix-only, same gate as `crate::localctl` itself (`lib.rs`) —
    // Windows leg trap (b), an ungated `#[cfg(test)]` item under
    // `--all-targets` breaks the Windows leg exactly like ungated
    // production code would.
    //
    // These drive the seam `Ops::connect`/`connect_target` (`crate::ops::
    // session`) actually use, straight from a `#[tokio::test]` worker
    // thread with **no** `spawn_blocking` bridge — proving it is genuinely
    // safe to `.await` from inside a runtime that already exists, which is
    // exactly the hazard the sync `resolve_host_route`'s own doc comment
    // flags. Where a live registration matters, a hand-rolled `LOCAL_ADMIN`
    // fake daemon (mirroring `localctl::client`'s own test idiom) stands in
    // for a real `qsh listen` process — no `qsh-testkit`/`ReverseHarness`
    // here, since `qsh-core` deliberately does not dev-depend on it.
    #[cfg(unix)]
    mod reverse_route_async_tests {
        use super::*;
        use tokio::net::UnixListener;

        use crate::config::Paths;

        /// Bind a one-shot fake `LOCAL_ADMIN` daemon at `<pid>.sock` under
        /// `runtime_dir`, answering exactly one `LocalHostList` with `hosts`.
        fn spawn_fake_admin_daemon(
            runtime_dir: &std::path::Path,
            pid: u32,
            hosts: Vec<LocalHost>,
        ) -> tokio::task::JoinHandle<()> {
            std::fs::create_dir_all(runtime_dir).unwrap();
            let sock = runtime_dir.join(format!("{pid}.sock"));
            let listener = UnixListener::bind(&sock).unwrap();
            tokio::spawn(async move {
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
            })
        }

        fn ops_at(runtime_dir: &std::path::Path, trust: &TrustStore) -> Ops {
            let paths = Paths::new(runtime_dir.join("config"), runtime_dir.join("state"))
                .with_runtime_dir(runtime_dir.join("run"));
            trust.save(&paths.trust_file()).unwrap();
            Ops::new(paths)
        }

        #[tokio::test]
        async fn resolve_host_route_async_is_host_not_found_with_no_pin_and_no_daemon() {
            let dir = tempfile::tempdir().unwrap();
            let ops = ops_at(dir.path(), &TrustStore::default());

            let err = ops.resolve_host_route_async("nowhere").await.unwrap_err();
            assert_eq!(err.code, ErrorCode::HostNotFound);
        }

        #[tokio::test]
        async fn resolve_host_route_async_returns_the_forward_pin_when_nothing_is_live() {
            let dir = tempfile::tempdir().unwrap();
            let store = forward_store("mac", "mac.example.com:4433", FP_A);
            let ops = ops_at(dir.path(), &store);

            let route = ops.resolve_host_route_async("mac").await.unwrap();
            assert!(matches!(route, HostRoute::Forward { .. }), "{route:?}");
        }

        #[tokio::test]
        async fn resolve_host_route_async_prefers_a_live_reverse_daemon_over_a_forward_pin() {
            let dir = tempfile::tempdir().unwrap();
            let store = forward_store("mac", "mac.example.com:4433", FP_A);
            let ops = ops_at(dir.path(), &store);
            let daemon = spawn_fake_admin_daemon(
                &ops.paths().runtime_dir(),
                100,
                vec![sample_local("mac", "reachable", FP_B)],
            );

            let route = ops.resolve_host_route_async("mac").await.unwrap();
            match route {
                HostRoute::Reverse {
                    pid, fingerprint, ..
                } => {
                    assert_eq!(pid, 100);
                    assert_eq!(fingerprint, FP_B);
                }
                other => panic!("expected a live reverse route, got {other:?}"),
            }
            daemon.await.unwrap();
        }

        #[tokio::test]
        async fn resolve_host_route_async_is_invalid_argument_when_two_daemons_both_hold_it_live() {
            let dir = tempfile::tempdir().unwrap();
            let ops = ops_at(dir.path(), &TrustStore::default());
            let a = spawn_fake_admin_daemon(
                &ops.paths().runtime_dir(),
                100,
                vec![sample_local("dup", "reachable", FP_A)],
            );
            let b = spawn_fake_admin_daemon(
                &ops.paths().runtime_dir(),
                101,
                vec![sample_local("dup", "reachable", FP_B)],
            );

            let err = ops.resolve_host_route_async("dup").await.unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument);
            a.await.unwrap();
            b.await.unwrap();
        }
    } // mod reverse_route_async_tests
}
