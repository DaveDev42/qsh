//! `host.list`/`host.get` — the local, authorization-free host query
//! (`docs/CLI.md` §2.5: "인가 불요 — local operation으로 원격 peer의 ACL
//! 평가 대상이 아님"; §5 `Host`; §6.1) — plus [`Ops::resolve_host_route`], the
//! one function that also backs `host.get`'s single entry, the human
//! renderer's "route that would be used", and `Ops::connect`'s path choice.
//!
//! One data source: `trust.toml` pins and `hosts.toml` entries that carry an
//! address (`forward_hosts`). Never probed: `state` is always `"unknown"`.
//! ADR-0068 retired the reverse source (the registrations of a resident
//! `qsh listen` daemon), so `connection_mode: "reverse"` and `lost_at` are
//! never produced; the `Host` fields stay for `qsh.cli/v1`.
//!
//! `host.list` never dials. [`Ops::resolve_host_route`] is the one place a
//! name turns into "which peer, reached how".

use std::collections::HashSet;

use qsh_proto::{DoctorFinding, ErrorCode, Host, HostGetReq, HostListData, TrustPeer};

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

/// The route `host.get`, the human renderer, and (Step 6) `Ops::connect`
/// all resolve one host name to — decided in exactly one place
/// ([`Ops::resolve_host_route`]) so list, single-entry and routing never
/// grow their own, divergent rules (M3 plan Step 5 (8237375)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRoute {
    /// Dial directly — the address `hosts.toml`/the trust store pin
    /// resolves to (M7 plan Step 3 (004ebd2), `resolve_forward`).
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
        /// own doc, M7 plan Step 3 (a)-추기 ② (004ebd2)) — or `None` when
        /// `hosts.toml` has no entries at all (preserves the pre-M7-Step-3
        /// `Host` shape exactly, `docs/CLI.md` §5).
        source: Option<String>,
        /// `hosts.toml`'s `user` hint for this name, if it set one.
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
                // A forward host is never probed (`state` is always
                // `"unknown"` above) and so is never `"stale"` — no
                // connection loss to time-stamp.
                lost_at: None,
            },
        }
    }
}

/// The resolved forward-route data for one host name, after layering
/// `hosts.toml` over `trust.toml`'s pinned peers (M7 plan §4.1 #4 (004ebd2),
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
/// (M7 plan §4.1 #4 (004ebd2)). `None` means neither source has a routable
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
///   post-Step-3-verification (M7 plan Step 3 (a)-추기 ② (004ebd2)) away from "which
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
///
/// The two addresses are compared after the default port is filled in —
/// the same address spelled with and without a port is still `"both"`
/// (ADR-0014 결정 4).
pub(super) fn resolve_forward(
    trust_peer: Option<&TrustPeer>,
    hosts_entry: Option<&HostEntry>,
    hosts_has_any: bool,
) -> Option<ForwardEntry> {
    // ADR-0014 결정 4: 파생값만 정규화한다. `HostEntry`/`TrustPeer`가 메모리에
    // 들고 있는 문자열도, 디스크의 바이트도 손대지 않는다.
    let hosts_address = hosts_entry
        .map(|entry| entry.address.as_str())
        .filter(|address| !address.is_empty())
        .map(|address| crate::trust::normalize_peer_address(address).address);
    let trust_address = trust_peer
        .map(|peer| peer.address.as_str())
        .filter(|address| !address.is_empty())
        .map(|address| crate::trust::normalize_peer_address(address).address);

    let address = match (&hosts_address, &trust_address) {
        (Some(address), _) => address.clone(),
        (None, Some(address)) => address.clone(),
        (None, None) => return None,
    };

    // Address-winner based, not name-presence based (this function's own
    // doc, above) — the `(None, None)` arm is unreachable because the
    // `address` match above already returned `None` for that case.
    //
    // 정규화 **후** 비교다(ADR-0014 결정 4): `hosts.toml`이 `mac:4433`,
    // `trust.toml`이 `mac`처럼 표기만 다르고 같은 주소를 가리키는 경우를
    // `"hosts"`(=redirect)로 보고하면 운영자에게 거짓 신호를 준다. 두 주소의
    // 비교는 기본 포트를 채운 뒤에 한다 — 포트 표기만 다른 같은 주소는
    // `"both"`다(ADR-0014 결정 4).
    let source = match (&hosts_address, &trust_address) {
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

/// Every name either `hosts.toml` or `trust.toml` knows about, deduplicated
/// — trust pins first (in store order, the pre-M7-Step-3 order), then any
/// `hosts.toml`-only names not already covered, in file order. Split out
/// of [`forward_hosts`] (ROADMAP M9 (h)) so
/// [`host_pinned_without_address`]'s own candidate set can reuse the
/// identical enumeration instead of a second, hand-copied loop that could
/// silently drift from it — the same "single source of truth" discipline
/// [`resolve_route`] already applies to [`resolve_forward`] itself.
fn host_candidate_names<'a>(store: &'a TrustStore, hosts: &'a HostsFile) -> Vec<&'a str> {
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
}

/// Pure mapping: every name either `hosts.toml` or a routable `trust.toml`
/// pin knows about becomes one forward `Host` entry (`docs/CLI.md` §5,
/// extended M7 plan Step 3 (004ebd2) by [`resolve_forward`]). Split out from
/// any I/O so the merge table (M3 plan Step 5 (c) (8237375)) is testable
/// against hand-built [`TrustStore`]/[`HostsFile`] values, never real
/// files.
///
/// Name order: [`host_candidate_names`]'s own order — keeps the existing
/// goldens' entry order unperturbed when `hosts.toml` is absent or only
/// restates trust names.
fn forward_hosts(store: &TrustStore, hosts: &HostsFile) -> Vec<Host> {
    let hosts_has_any = !hosts.entries().is_empty();
    host_candidate_names(store, hosts)
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
                // Forward hosts are never probed, never `"stale"`.
                lost_at: None,
            })
        })
        .collect()
}

/// ROADMAP M9 (h)'s `host_pinned_without_address`: every
/// [`host_candidate_names`] name [`resolve_forward`] cannot route at all —
/// no non-empty address from either `hosts.toml` or the trust-store pin.
///
/// Re-derives the same candidate-name enumeration
/// [`forward_hosts`]/[`host_candidate_names`] use and calls
/// [`resolve_forward`] directly, rather than filtering `Ops::host_list()`'s
/// merged `Vec<Host>` for an empty `address`: [`forward_hosts`]/[`resolve_forward`]
/// never produce a `Host` entry with an empty address at all, so an
/// addressless pinned name never appears in `host_list()`'s output to
/// filter in the first place. Calling [`resolve_forward`] directly reuses
/// the existing merge rule rather than hand-rolling a second one.
pub(super) fn host_pinned_without_address(store: &TrustStore, hosts: &HostsFile) -> Vec<String> {
    let hosts_has_any = !hosts.entries().is_empty();
    host_candidate_names(store, hosts)
        .into_iter()
        .filter(|name| resolve_forward(store.find(name), hosts.find(name), hosts_has_any).is_none())
        .map(str::to_string)
        .collect()
}

/// `ErrorCode::InvalidArgument` for an empty/whitespace-only (or, after
/// [`hint_alias`] strips a `user@` prefix, empty-after-stripping) host
/// name. One error value, every empty-alias call site in [`resolve_route`]
/// and `Ops::resolve_peer_address` (M8 plan Step 6 (3b23162) — same code, same
/// wording, not just the same code) so neither can drift from the other.
pub(crate) fn empty_host_name_error() -> OpError {
    OpError::new(ErrorCode::InvalidArgument, "host name must not be empty")
}

/// `ErrorCode::InvalidArgument` for a [`hint_alias`] result that is
/// non-empty but still fails `qsh_proto::wire::valid_host_name` (the M8 plan (3b23162)
/// Step 7, Q10) — a name like `"dave@no where"` strips down to `"no
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
/// hint off a host alias (M8 plan Step 7 (3b23162), Q10): nothing usable is
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
/// Splits on the *last* `@`, then **trims** the remainder (the M8 plan (3b23162)
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
/// same, but for a different reason than "empty" (M8 plan Step 6 (3b23162)
/// lens-2 findings; Step 7 extends the same discipline to this third
/// case). Shared by [`resolve_route`] here and
/// `Ops::resolve_peer_address` (`crate::ops::resolve_peer_address`) so the
/// two `HOST_NOT_FOUND`/`INVALID_ARGUMENT` choices never diverge on this
/// rule.
/// The key a host name is looked up under: the name with surrounding
/// whitespace removed, and nothing else.
///
/// **Not [`hint_alias`].** That one also strips a `user@` prefix, which is
/// right for a remedy message and wrong for a lookup key: `qsh exec
/// dave@mac -- …` must keep failing closed with `HOST_NOT_FOUND` rather
/// than silently resolving to `mac` and running as the *default* account
/// while the operator asked for `dave` (`docs/CLI.md` §6.9·§7 — the bare
/// `qsh [user@]host` form is the only shape that carries a user hint, and
/// it is split at the CLI before routing ever sees it). Whitespace is the
/// one difference that carries no meaning, so it is the one this trims
/// (M9 plan §6 (cdf4015) 행 i).
pub(crate) fn lookup_name(name: &str) -> &str {
    name.trim()
}

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

/// The `details.reason` a retryable `HOST_NOT_FOUND` carried while the
/// target's reverse registration was disconnected (`docs/CLI.md` §3.2).
/// ADR-0068 retired the registry, so nothing emits it any more; the value
/// stays as `qsh.cli/v1` vocabulary that clients may still recognize.
pub const STALE_REGISTRATION_REASON: &str = "reverse_registration_stale";

/// `HOST_NOT_FOUND` for a name neither `hosts.toml`, `trust.toml` nor the
/// reverse registry knows about at all — `qsh exec`'s own frozen legacy
/// text (issue #5), extracted verbatim from what
/// `crate::ops::resolve_peer_address`'s `ok_or_else` used to build
/// inline. `error.HOST_NOT_FOUND.json` (`qsh exec nowhere`,
/// `crates/qsh-cli/tests/it/fixtures.rs`) compares this message byte for
/// byte, so it is kept exactly as it read before issue #5 gave `exec`
/// [`Ops::resolve_host_route`]'s own routing (fixtures are append-only —
/// `CLAUDE.md`) — even though [`unconfigured_host_not_found`] below says
/// the same thing at more length for every *other* caller of that
/// routing. `exec`'s call site passes this function in as the "wholly
/// unconfigured" branch constructor (see that method's own doc) instead
/// of switching to the newer wording, which would have broken the pinned
/// fixture.
pub fn not_in_trust_store_host_not_found(display_name: &str) -> OpError {
    OpError::new(
        ErrorCode::HostNotFound,
        format!(
            "host {display_name:?} is not in the trust store; pin it with `qsh trust add \
             {display_name} --address <host:port> --fingerprint sha256:...`"
        ),
    )
}

/// `HOST_NOT_FOUND` for a name `resolve_route` cannot place anywhere at
/// all — branch (i) of issue #3 item b2's three-way split. Until this
/// split the same OR-ed message covered this case and branch (iii)
/// ([`pinned_without_address_host_not_found`]) at once (commit b328a19's
/// observation/impact/next-command discipline names the defect: one
/// wording, two causes, and a third reading — DDNS failure — it can never
/// actually be, since `resolve_route` never resolves DNS). Message text
/// is not contract (`docs/CLI.md` §3.2); `error.HOST_NOT_FOUND.json`
/// pins a different call site's text (`qsh exec`'s
/// [`not_in_trust_store_host_not_found`], the constructor it passes to
/// `Ops::resolve_host_route_with` instead of this one), left untouched
/// by this split.
///
/// `qsh pair accept` is not offered as an alternative next command: no
/// such verb exists in this tree (`crates/qsh-cli/src/cli.rs`'s
/// `TrustCmd` has `add`/`accept` under `trust`, not `pair`).
pub fn unconfigured_host_not_found(display_name: &str) -> OpError {
    OpError::new(
        ErrorCode::HostNotFound,
        format!(
            "host {display_name:?} is not configured on this machine: no trust-store pin, no \
             hosts.toml entry, and no reverse registration naming it; nothing will be dialed. \
             Pin it with `qsh trust add {display_name} --address <host:port> --fingerprint \
             sha256:...`, or register it by running `qsh reverse <controller>` on that host"
        ),
    )
}

/// The message [`Ops::host_is_unconfigured`]'s probe constructor builds. Never
/// shown: it only tells the one "wholly unconfigured" branch of
/// [`resolve_route`] apart from every other `HOST_NOT_FOUND` without
/// restating the routing rule a second time.
const UNCONFIGURED_PROBE: &str = "unconfigured-host-probe";

fn unconfigured_probe(_display_name: &str) -> OpError {
    OpError::new(ErrorCode::HostNotFound, UNCONFIGURED_PROBE).with_retryable(false)
}

/// What follows the quoted name in the two messages of the "wholly
/// unconfigured" branch: [`unconfigured_host_not_found`] and `qsh exec`'s
/// frozen [`not_in_trust_store_host_not_found`].
const UNCONFIGURED_TAILS: [&str; 2] = [
    " is not configured on this machine:",
    " is not in the trust store;",
];

/// The name in a "wholly unconfigured" `HOST_NOT_FOUND` (`docs/CLI.md`
/// §6.1's first branch: no `hosts.toml` entry, no pin, no reverse
/// registration), or `None` for any other error. A human renderer uses it to
/// add the next command `qsh pair ssh <name>` to the message without
/// changing the message or `details` an envelope carries (ADR-0044 decision
/// 2).
pub fn unconfigured_host_name(err: &OpError) -> Option<&str> {
    if err.code != ErrorCode::HostNotFound || err.retryable || !err.details.is_null() {
        return None;
    }
    let rest = err.message.strip_prefix("host \"")?;
    let (name, tail) = rest.split_once('"')?;
    if name.is_empty() || !UNCONFIGURED_TAILS.iter().any(|t| tail.starts_with(t)) {
        return None;
    }
    Some(name)
}

/// `HOST_NOT_FOUND` for a name `resolve_route` already knows about — a
/// trust-store pin, or a `hosts.toml` entry with an explicit empty
/// address (`crate::hosts::HostEntry::address`'s doc: parses, but is "no
/// route from hosts.toml" the same way an empty trust-pin address is) —
/// but that has neither a routable address nor a live-or-stale reverse
/// registration. Branch (iii) of issue #3 item b2's three-way split; see
/// [`unconfigured_host_not_found`]'s doc for the wording it used to
/// share this message with.
///
/// The observation says "configured", not "pinned": a `hosts.toml`
/// empty-address entry can reach this branch with no trust-store pin at
/// all, and `docs/CLI.md` §6.1's `hosts.toml` paragraph is explicit that
/// `hosts.toml` is a pure address book that never participates in
/// identity — "pinned" is trust-store vocabulary and would misreport
/// that source.
pub fn pinned_without_address_host_not_found(display_name: &str) -> OpError {
    OpError::new(
        ErrorCode::HostNotFound,
        format!(
            "host {display_name:?} is configured on this machine but has no address for it \
             and no reverse registration is currently held; nothing will be dialed. Add one \
             with `qsh trust add {display_name} --address <host:port> --fingerprint \
             sha256:...`, or run `qsh reverse <controller>` on that host to register it here"
        ),
    )
}

/// `HOST_NOT_FOUND` for a positional that still carries a `user@` hint
/// (`docs/CLI.md` §6.1's `qsh host get <name>`/`qsh exec <name> -- ...`
/// forms do not strip it the way the bare `qsh [user@]host` form does,
/// §7) naming an alias that *is* configured on this machine under its
/// bare form. Neither [`unconfigured_host_not_found`] nor
/// [`pinned_without_address_host_not_found`] fits: both assert something
/// specific about the alias's configuration state, and a `user@`-hinted
/// query never actually looked that state up (`key` still has the `@` in
/// it and can never match a stored alias, which cannot contain one —
/// `qsh_proto::wire::valid_host_name`). This is not a fourth named
/// branch of issue #3 item b2's three-way split — routing still falls
/// through to `HOST_NOT_FOUND`, non-retryable, exactly like before —
/// only the wording, decided on `display_name` instead of `key` so it
/// cannot assert a falsehood about the name it names.
pub fn user_prefix_not_accepted_host_not_found(display_name: &str) -> OpError {
    OpError::new(
        ErrorCode::HostNotFound,
        format!(
            "host {display_name:?} is configured on this machine, but this command does not \
             accept a leading account-name hint (the kind separated by an at sign) in front of \
             the alias; pass the bare alias by itself, or run `qsh trust add {display_name} \
             --address <host:port> --fingerprint sha256:...` to update its pin directly, or \
             `qsh reverse <controller>` on that host to register it"
        ),
    )
}

/// The pure decision [`Ops::resolve_host_route`] delegates to — see that
/// method's doc for the rule. Split out from any I/O (trust-file load) so
/// the routing table is testable against hand-built sources.
///
/// `unconfigured` is the constructor for the one branch two callers
/// disagree on wording for (issue #5): [`Ops::resolve_host_route`] passes
/// [`unconfigured_host_not_found`], `qsh exec`'s
/// [`Ops::resolve_host_route_with`] passes
/// [`not_in_trust_store_host_not_found`] instead, to keep
/// `error.HOST_NOT_FOUND.json`'s frozen text byte-identical. Every other
/// branch (forward, pinned-without-address, `user@`-prefixed) is unchanged
/// by which constructor is passed — those wordings are shared by every
/// caller.
fn resolve_route(
    store: &TrustStore,
    hosts: &HostsFile,
    name: &str,
    unconfigured: fn(&str) -> OpError,
) -> Result<HostRoute, OpError> {
    if name.trim().is_empty() {
        // An empty/whitespace-only name is an argument defect, not a
        // missing host: falling through to `HOST_NOT_FOUND` below would
        // interpolate `name` into that error's remediation message and
        // produce a malformed, un-runnable `qsh trust add` suggestion
        // (adversarial review finding). `ErrorCode::InvalidArgument` is the
        // code an argument defect already carries elsewhere.
        return Err(empty_host_name_error());
    }
    // M9 plan §6 (cdf4015) 행 i: the lookup key is trimmed, independently of
    // `hint_alias`'s remedy-message stripping below.
    let key = lookup_name(name);

    // Reuses `resolve_forward` — the single existing "layer hosts.toml over
    // the trust pin" rule `ops::resolve_peer_address` (`Ops::resolve_peer`,
    // `qsh serve --to` and `qsh doctor`'s own routing) also calls — rather
    // than re-implementing the merge inline a second time. [`forward_hosts`]
    // above applies the identical rule across every name for listing;
    // keeping both on `resolve_forward`'s definition is what keeps listing
    // and routing from growing divergent rules (the same discipline the
    // pre-M7-Step-3 code already followed for `TrustStore::resolve_host`).
    let hosts_has_any = !hosts.entries().is_empty();
    if let Some(entry) = resolve_forward(store.find(key), hosts.find(key), hosts_has_any) {
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
    // will never match a trust-store name. Left
    // as-is, interpolating it verbatim below would echo the `user@` back
    // into both the diagnostic and the `qsh trust add` remedy, and the
    // latter is not even parseable: alias names are `[A-Za-z0-9._-]`
    // (`qsh_proto::wire::valid_host_name`), which rejects `@`. Strip the
    // same "last `@`" hint `parse_target` uses (M8 plan Step 6 (3b23162), M7
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

    // issue #3 item b2 fix-up: every lookup above (live, forward) and
    // every lookup below (stale, "known") is keyed on `key` — trimmed
    // only, still carrying a `user@` hint when one was given — while the
    // enumerated branches below name `display_name`, the hint-stripped
    // alias. When the two differ, `key` can never match anything those
    // lookups check (`qsh_proto::wire::valid_host_name` rejects `@`, so
    // no stored alias ever equals a key that still has one), but
    // `display_name` itself might still be fully configured. Left as-is,
    // the enumerated branches below would then assert specific — and
    // false — things about `display_name` ("no trust-store pin" for a
    // name that has one; "no address" for a name that has one), and
    // branch (iii)'s remedy would invite silently overwriting a working
    // pin. Decide this shape on `display_name` before reaching either
    // enumerated branch; routing itself does not change; here too, a
    // `user@`-prefixed positional was never going to route to anything
    // (`docs/CLI.md` §7).
    if display_name != key
        && (store.find(display_name).is_some() || hosts.find(display_name).is_some())
    {
        return Err(user_prefix_not_accepted_host_not_found(display_name));
    }

    // issue #3 item b2 (PR-D): the two remaining causes get their own
    // wording instead of sharing one OR-ed message
    // (`unconfigured_host_not_found`'s doc has the history). "Known" here
    // means either source names the alias at all, even with no routable
    // address from it — a trust-store pin or a `hosts.toml` entry with an
    // explicit empty address (branch (iii)'s "configured on this
    // machine" wording covers both without claiming either specifically),
    // the one `hosts.toml` shape `resolve_forward` above does not already
    // turn into a route
    // (`crate::hosts::HostEntry::address`'s doc). Both mean an operator
    // already told qsh about this name, which "not configured on this
    // machine" would misreport.
    let known = store.find(key).is_some() || hosts.find(key).is_some();
    Err(if known {
        pinned_without_address_host_not_found(display_name)
    } else {
        unconfigured(display_name)
    })
}

impl Ops {
    /// `host.list` (`qsh hosts`, `docs/CLI.md` §6.1). Authorization-free
    /// local operation (§2.5) — no ACL check, no dial, purely local reads.
    pub fn host_list(&self) -> Result<HostListData, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        Ok(HostListData {
            hosts: forward_hosts(&store, &hosts),
        })
    }

    /// `host_pinned_without_address` (`crate::ops::doctor`'s ROADMAP
    /// M9 (h) wiring) — [`host_pinned_without_address`] fed this
    /// process's real `trust.toml`/`hosts.toml`, the same sources
    /// [`Ops::host_list`] itself reads.
    pub(crate) fn doctor_pinned_no_address_findings(&self) -> Result<Vec<DoctorFinding>, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        let diag = &crate::doctor::HOST_PINNED_WITHOUT_ADDRESS;
        // A key-only pin that the iroh route dials by key is reachable with
        // no address at all (ADR-0063), so it is not flagged either.
        let iroh_trust = self.open_trust().ok();
        Ok(host_pinned_without_address(&store, &hosts)
            .into_iter()
            .filter(|name| {
                !iroh_trust
                    .as_ref()
                    .is_some_and(|trust| self.iroh_only_pin(name, trust))
            })
            .map(|name| DoctorFinding {
                code: diag.code.to_string(),
                status: "warn".to_string(),
                detail: format!("{} (host: {name})", diag.message),
                remedy: Some(diag.remedy.replace("{name}", &name)),
            })
            .collect())
    }

    /// Whether `name` is in the first `HOST_NOT_FOUND` branch of
    /// `docs/CLI.md` §6.1: nothing on this machine mentions it. A
    /// `hosts.toml` entry and a `trust.toml` pin each make it `false`, and
    /// so does any error while looking. The
    /// answer comes from [`resolve_route`] itself, so the rule has one
    /// definition (ADR-0044 decision 2).
    ///
    /// Sync, with the caveat of [`Self::resolve_host_route`]: not callable
    /// from inside a running Tokio runtime.
    pub(crate) fn host_is_unconfigured(&self, name: &str) -> bool {
        matches!(
            self.resolve_host_route_with(name, unconfigured_probe),
            Err(err) if err.code == ErrorCode::HostNotFound && err.message == UNCONFIGURED_PROBE
        )
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
    /// `Ops::connect` all share (M3 plan Step 5 (8237375)).
    ///
    /// Rule: a name with a routable forward address (`hosts.toml` over the
    /// `trust.toml` pin) routes there; unregistered-and-unpinned is
    /// [`ErrorCode::HostNotFound`] with a message that guides the remedy.
    /// Purely local reads, so it is safe to call from inside a runtime.
    pub fn resolve_host_route(&self, name: &str) -> Result<HostRoute, OpError> {
        self.resolve_host_route_with(name, unconfigured_host_not_found)
    }

    /// [`Self::resolve_host_route`], with the "wholly unconfigured" branch's
    /// constructor chosen by the caller instead of fixed at
    /// [`unconfigured_host_not_found`] — `qsh exec`'s own routing
    /// (`crate::ops::exec::ExecRunOp`, issue #5) passes
    /// [`not_in_trust_store_host_not_found`] here, to keep
    /// `error.HOST_NOT_FOUND.json`'s pinned text byte-identical, while
    /// every other branch of the decision is exactly [`Self::resolve_host_route`]'s own rule — see
    /// [`resolve_route`]'s own doc on the one parameter this adds.
    pub(crate) fn resolve_host_route_with(
        &self,
        name: &str,
        unconfigured: fn(&str) -> OpError,
    ) -> Result<HostRoute, OpError> {
        let store = TrustStore::load(&self.paths.trust_file())?;
        let hosts = HostsFile::load(&self.paths.hosts_file())?;
        resolve_route(&store, &hosts, name, unconfigured)
    }
}

#[cfg(test)]
mod tests;
