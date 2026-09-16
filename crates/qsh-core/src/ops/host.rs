//! `host.list`/`host.get` — the local, authorization-free host query
//! (`docs/CLI.md` §2.5: "인가 불요 — local operation으로 원격 peer의 ACL
//! 평가 대상이 아님"; §5 `Host`; §6.1) — plus [`Ops::resolve_host_route`], the
//! one function that also backs `host.get`'s single entry, the human
//! renderer's "route that would be used", and (Step 6) `Ops::connect`'s
//! path choice (`PLAN.md` M3 Step 5, PR 5b).
//!
//! Two data sources, concatenated into `host.list`'s result but never
//! merged by name (`docs/CLI.md` §6.1: "같은 이름이 forward pin과 reverse
//! 등록 양쪽에 존재하면... 두 항목으로 나타난다"):
//!
//! - **forward** — `trust.toml` pins that carry an address
//!   (`forward_hosts`). Never probed: `state` is always `"unknown"`.
//! - **reverse** — the union of `LocalHostList` across every localctl
//!   daemon discovered on this machine
//!   (`crate::localctl::client::admin_host_list_all`, unix only). A
//!   daemon this machine cannot reach is dropped from the result, never
//!   turned into an error — one sleeping laptop must not hide every other
//!   host (`docs/CLI.md` §6.2). `state` is whatever the daemon reported
//!   (`"reachable"`/`"stale"`), `device_id` is the fingerprint the daemon
//!   TLS-verified, never a wire display name.
//!
//! `host.list` never dials — both sources are purely local reads.
//! [`Ops::resolve_host_route`] is the one place a name turns into "which peer,
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
    /// resolves to (`PLAN.md` M7 Step 3, `resolve_forward`).
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
        /// `"both"` (`"both"` only when they agree — `resolve_forward`'s
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

/// `ErrorCode::InvalidArgument` for an empty/whitespace-only (or, after
/// [`hint_alias`] strips a `user@` prefix, empty-after-stripping) host
/// name. One error value, every empty-alias call site in [`resolve_route`]
/// and `Ops::resolve_peer_address` (`PLAN.md` §3 Step 6 — same code, same
/// wording, not just the same code) so neither can drift from the other.
pub(crate) fn empty_host_name_error() -> OpError {
    OpError::new(ErrorCode::InvalidArgument, "host name must not be empty")
}

/// `ErrorCode::InvalidArgument` for a [`hint_alias`] result that is
/// non-empty but still fails `qsh_proto::wire::valid_host_name` (`PLAN.md`
/// §3 Step 7, Q10) — a name like `"dave@no where"` strips down to `"no
/// where"`, which is neither empty (so [`empty_host_name_error`] would be
/// the wrong wording) nor an alias `qsh trust add` could ever accept (so
/// falling through to the `HOST_NOT_FOUND` remedy would suggest an
/// un-runnable `qsh trust add "no where" --address ...` command). Distinct
/// wording from the empty case so an operator can tell "you gave me
/// nothing" apart from "what you gave me isn't a legal host name" — same
/// vocabulary [`empty_host_name_error`] already uses for the sibling
/// defect, kept in this one function so the two call sites below can't
/// drift from each other either.
pub(crate) fn invalid_host_alias_error(alias: &str) -> OpError {
    OpError::new(
        ErrorCode::InvalidArgument,
        format!("host name {alias:?} is not a valid host alias"),
    )
}

/// The three outcomes of [`hint_alias`] stripping and validating a `user@`
/// hint off a host alias (`PLAN.md` §3 Step 7, Q10): nothing usable is
/// left ([`HintAlias::Empty`]), something is left but it is not a legal
/// alias ([`HintAlias::Invalid`]), or it is ([`HintAlias::Valid`]). Kept as
/// three explicit outcomes rather than folding `Invalid` back into `Empty`
/// so callers can pick [`empty_host_name_error`] vs.
/// [`invalid_host_alias_error`] instead of always reaching for the "must
/// not be empty" wording on input that plainly is not empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HintAlias<'a> {
    /// Trimmed remainder was empty (`"dave@"`, `"@"`, `"dave@ "`, or a
    /// bare name that is itself all whitespace).
    Empty,
    /// Trimmed remainder is non-empty but fails
    /// `qsh_proto::wire::valid_host_name` (`"dave@no where"` -> `"no
    /// where"`, which contains a space `valid_host_name` rejects).
    Invalid(&'a str),
    /// Trimmed remainder is a legal host alias — the display name a
    /// `HOST_NOT_FOUND` remedy can safely interpolate.
    Valid(&'a str),
}

/// Strip a `user@` hint off a host alias, the way `parse_target` does for
/// the bare `qsh [user@]host` form (`docs/CLI.md` §7) — for positionals
/// that bypass that parser (`qsh host get <name>`, `qsh exec <name> --
/// ...`, `docs/CLI.md` §6.1/§6.9) and so can still carry one when they
/// reach routing or `Ops::resolve_peer_address`'s remedy-message assembly.
///
/// Splits on the *last* `@`, then **trims** the remainder (`PLAN.md` §3
/// Step 7, Q10: a stray space survives an `@`-split unnoticed otherwise,
/// e.g. `"dave@ nowhere"` -> `" nowhere"`, and a bare name with no `@` at
/// all can carry the same leading/trailing whitespace, e.g. `" nowhere"`)
/// and validates it against `qsh_proto::wire::valid_host_name` — the exact
/// rule `qsh trust add` itself enforces on an alias, so a name this
/// function calls [`HintAlias::Valid`] is always one a suggested `qsh
/// trust add <alias> --address ...` remedy could actually run.
/// [`HintAlias::Empty`] when the trimmed remainder is empty (`"dave@"`,
/// `"@"`, `"dave@ "`, `" "`) — such input has no alias left to name in a
/// remedy at all. [`HintAlias::Invalid`] when it is non-empty but still not
/// a legal alias (`"dave@no where"` -> `"no where"`, an internal space) —
/// interpolating it verbatim would produce an un-runnable remedy just the
/// same, but for a different reason than "empty" (`PLAN.md` §3 Step 6
/// lens-2 findings; Step 7 extends the same discipline to this third
/// case). Shared by [`resolve_route`] here and
/// `Ops::resolve_peer_address` (`crate::ops::resolve_peer_address`) so the
/// two `HOST_NOT_FOUND`/`INVALID_ARGUMENT` choices never diverge on this
/// rule.
pub(crate) fn hint_alias(name: &str) -> HintAlias<'_> {
    let stripped = name.rsplit_once('@').map_or(name, |(_, host)| host);
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        HintAlias::Empty
    } else if qsh_proto::wire::valid_host_name(trimmed) {
        HintAlias::Valid(trimmed)
    } else {
        HintAlias::Invalid(trimmed)
    }
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
        return Err(empty_host_name_error());
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

    // A host alias never carries a `user@` hint (`docs/CLI.md` §7: the
    // bare `qsh [user@]host` form strips it at the CLI before the alias
    // ever reaches routing), so any input that still has one here came
    // through a positional that does not do that stripping (`qsh host get
    // <name>`, `docs/CLI.md` §6.1) and is not itself a valid alias — it
    // will never match a trust-store or reverse-registration name. Left
    // as-is, interpolating it verbatim below would echo the `user@` back
    // into both the diagnostic and the `qsh trust add` remedy, and the
    // latter is not even parseable: alias names are `[A-Za-z0-9._-]`
    // (`qsh_proto::wire::valid_host_name`), which rejects `@`. Strip the
    // same "last `@`" hint `parse_target` uses (`PLAN.md` §3 Step 6, M7
    // carry-over v) via [`hint_alias`] so the message and remedy always
    // name a bare alias. `"dave@"`/`"@"` strip down to an empty alias,
    // which is the same argument defect the guard above rejects — fall
    // into the identical `InvalidArgument` rather than let an empty alias
    // reach the `qsh trust add  --address ...` remedy below (un-runnable:
    // two spaces, no name; lens-2 finding).
    let display_name = match hint_alias(name) {
        HintAlias::Valid(alias) => alias,
        HintAlias::Empty => return Err(empty_host_name_error()),
        HintAlias::Invalid(alias) => return Err(invalid_host_alias_error(alias)),
    };

    Err(OpError::new(
        ErrorCode::HostNotFound,
        format!(
            "host {display_name:?} has no live reverse registration on this machine and no \
             address pinned for it; register it (`qsh reverse <controller>` run on that host) \
             or pin one here with `qsh trust add {display_name} --address <host:port> \
             --fingerprint sha256:...`"
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
    /// method (via `Self::reverse_host_entries`) builds its own
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
    /// (delegates to the same pure `resolve_route`), but never builds or
    /// blocks on its own runtime, so it is safe to call from *inside* one
    /// that already exists (`PLAN.md` M3 Step 6's async seam).
    ///
    /// `Ops::connect` (`crate::ops::session`) does **not** need this seam
    /// today: it calls the sync [`Self::resolve_host_route`] from
    /// `Ops::resolve_route` *before* `connect_target`/`connect_reverse`
    /// build their own dial runtime, so the throwaway probe runtime this
    /// resolves with and the dial's own multi-thread runtime are
    /// sequential, never nested — no caller on the current CLI call graph
    /// reaches `connect` from inside an already-running runtime (`main` is
    /// a plain sync `fn`). This method exists as the seam for the caller
    /// that eventually will run inside one — a future long-running
    /// external-process host, or any other async entry point — that needs
    /// the same routing decision without the sync method's "cannot start a
    /// runtime from within a runtime" hazard — so that caller never has to
    /// reach for `crates/qsh-testkit/tests/host_list_reverse.rs`'s
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
mod tests;
