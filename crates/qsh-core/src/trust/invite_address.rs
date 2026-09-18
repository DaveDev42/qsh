//! Candidate addresses for the `<address>` placeholder `qsh trust invite`
//! prints (`docs/CLI.md` §6.11, ADR-0002): the wording that frames them,
//! the opaque value a renderer prints, and the pure assembly that turns an
//! already-made observation into that value.
//!
//! Pure on purpose, the same split `crate::doctor::probe`'s own module doc
//! describes — detection apart from classification, so the deciding half
//! is unit-testable with synthetic inputs and no real socket. This file
//! opens no socket, reads no file and carries no `#[cfg]`; every OS
//! contact lives in the child `route` module instead. `crate::doctor` /
//! `crate::doctor::probe` are a sibling instance of the same shape, not
//! this module's home: that module's first line scopes its detectors to
//! `doctor.run`, and pointing `trust.invite` at them would make a
//! diagnostic module a dependency of the pairing path.
//!
//! [`InviteAddressAdvice`] does not reach the `qsh.cli/v1` envelope. It is
//! declared here in `qsh-core`, not in the contract crate, it has no serde
//! derive and no public field, and the single door to an envelope
//! (`qsh-cli`'s `finish`) is bound on `Serialize` — so as long as the type
//! implements no `Serialize`, a value of it does not type-check into an
//! envelope at all. `xtask arch` bans the serde tokens in this file and in
//! the child directory, which keeps the derive from being added where the
//! type is declared. Trait coherence still lets an `impl Serialize` for a
//! `qsh-core` type live in any other file of the crate, so the ban is one
//! input to that property rather than a crate-wide proof of it.
//!
//! The wording lives here rather than in the frontend because
//! operator-facing text has one canonical copy in `qsh-core` and the CLI
//! only writes what it is handed (`docs/design/architecture.md` §1;
//! precedents: [`crate::ops::INVITE_CODE_PROMPT`],
//! [`crate::trust::ADDRESS_PORT_ASSUMED_NOTICE`]).

use std::net::IpAddr;

use super::split_port;

pub(crate) mod route;

/// How many times `route::observe_source_addresses` has run, this
/// process's whole lifetime. Plain backticks, not an intra-doc link:
/// `route` and everything in it are `pub(crate)`, and a link from this
/// `pub` item to a crate-private one fails
/// `rustdoc::private_intra_doc_links` under `-D warnings`.
///
/// `pub`, not `pub(crate)`: the machine-mode
/// invariant it exists to pin (`--json`/`--jsonl` never makes this route
/// query, `docs/CLI.md` §2.2) is proven by a `qsh-cli` test driving the
/// real `Command::Trust(TrustCmd::Invite)` dispatch arm in both output
/// modes and comparing two reads of this counter around it — necessarily
/// from outside `qsh-core`, since that is where the dispatch arm and the
/// `finish` closure it must stay inside of both live
/// (`crates/qsh-cli/src/main.rs`). `route` itself stays `pub(crate)`; only
/// this read-only forward crosses the crate boundary.
pub fn route_query_count() -> usize {
    route::observation_count()
}

/// Heading for the human-mode candidate block `qsh trust invite` prints
/// under `accept_command` (`docs/CLI.md` §6.11).
///
/// Claims a routing observation and nothing else, and only the observation
/// this command actually makes. Kept to the 271-byte cap this repo's
/// three-part wordings share (`ADDRESS_PORT_ASSUMED_NOTICE`,
/// `BIND_UNAVAILABLE_REMEDY`); the fuller detail this rustdoc carries lives
/// in `docs/CLI.md` §6.11's surrounding prose instead of in the constant
/// itself, which is why the wording below is terser than the review that
/// produced it:
///
/// - one candidate at most per IP family, the source address for that
///   family's *default route* — not an enumeration of this host's
///   interfaces (adversarial review: a host with both a LAN and an
///   overlay address only ever gets the default-route one printed here).
/// - the port is `[serve].bind`'s, or [`crate::serve::DEFAULT_PORT`] when
///   this command cannot read one from it — unset, an unreadable or
///   unparsable `config.toml`, and a bind spec whose port fails to parse
///   as a `u16` all collapse to the same fallback, and the wording covers
///   all three rather than naming only "if unset" (adversarial review: a
///   broken `config.toml` degrading silently to 4433 while naming a
///   different port would otherwise be exactly the
///   unobserved-value-as-observed failure this file's module doc warns
///   against). A running `qsh serve --bind` is a runtime flag of another
///   process this command cannot observe either way.
/// - reachability is not asserted. A connect-only route query says
///   nothing about whether a peer on the other side of a NAT or a
///   firewall can reach the printed address, nor whether this host's own
///   `[serve].bind` even listens on it (a loopback-only bind still lets a
///   LAN address print here — `docs/CLI.md` §6.11 discloses this
///   separately since there is no room left in the constant), nor whether
///   an IPv6 candidate is a short-lived RFC 8981 privacy address this same
///   host rotates on its own within a day or so
///   (`docs/adr/0009-admission-defenses.md`'s "privacy extension이 하위
///   64비트를 회전하는 정상 호스트" already names this behavior for a
///   different reason — a stable pin can outlive the address it was made
///   from; also disclosed separately in `docs/CLI.md` §6.11). Asserting
///   reachability or durability from this evidence would be the same
///   overreach `crate::tunnel::REMOTE_FORWARD_LOOPBACK_ONLY_MESSAGE`'s own
///   doc refuses for the same kind of under-determined observation, so the
///   last sentence retracts every claim the first could otherwise be read
///   as making.
pub const INVITE_ADDRESS_HEADING: &str = "Default-route source address per IP family, not every interface -- port is `[serve].bind`'s, or 4433 when it gives none this command can read, never a running `qsh serve --bind`. Not a reachability check: a NAT or firewall can still block any of these for the peer:";

/// The heading must name the one default port and nothing else — a second
/// literal here would be a second source of truth (ADR-0014 결정 1). Same
/// assertion, same reason, as [`crate::trust::ADDRESS_PORT_ASSUMED_NOTICE`]'s.
const _: () = assert!(
    crate::serve::names_only_port(INVITE_ADDRESS_HEADING, crate::serve::DEFAULT_PORT),
    "INVITE_ADDRESS_HEADING must name serve::DEFAULT_PORT and no other number"
);

/// What `qsh trust invite` prints instead of a candidate block when no
/// candidate survived (`docs/CLI.md` §6.11).
///
/// Three parts, the discipline `crates/qsh-core/tests/
/// failure_text_discipline.rs` pins. Kept to the same 271-byte cap as
/// [`INVITE_ADDRESS_HEADING`], so each part below is terser than the
/// review that produced it — the reasoning is spelled out here, not fully
/// carried in the wording itself:
///
/// - observation — two paths reach zero candidates and the wording covers
///   both, because only one of them is "the kernel named nothing": a host
///   with no default route gets no answer at all, and a host on a
///   link-local-only IPv6 link gets an answer that `assemble` then drops
///   for being unprintable (its zone index has no place in a plain
///   `host:port` string). Saying only the first would be false on the
///   second. Neither is "this device has no address" — that stronger claim
///   is what the wording explicitly refuses.
/// - impact — the invite is untouched and still valid; the one thing
///   missing is the `<address>` placeholder, and a human has to fill it.
/// - next command — `ip route`/`route -n`, the same pair
///   [`crate::doctor::NO_ROUTE`]'s own remedy already points an operator
///   to for this exact question. Deliberately **not** `qsh doctor`: with
///   no target and no `[reverse].controller` configured — the state a
///   fresh device in the middle of its first `trust invite` is in —
///   `doctor.run` probes no connectivity at all (`docs/CLI.md` §6.17:
///   "인자 없는 `qsh doctor`는 `[reverse].controller`가 설정돼 있으면
///   그 연결성만 점검하고"), so naming it here as "the command that
///   diagnoses this host's routing" would send the operator to a command
///   that, in this state, says nothing about routing (adversarial review).
///
/// No default-port digits appear here on purpose, so no
/// `crate::serve::names_only_port` assertion applies — that function
/// returns `false` for a string with no digit run at all, so asserting it
/// here would not compile. This wording never names a port.
pub const INVITE_ADDRESS_NONE: &str = "No candidate: the kernel named no source address, or only ones this line can't offer (loopback, unspecified, or an unprintable link-local) -- not \"this device has no address\". Invite still valid; fill `<address>` by hand. Check routing with `ip route`/`route -n`.";

/// How far each candidate line is indented under
/// [`INVITE_ADDRESS_HEADING`] — the same two spaces `qsh-cli`'s
/// `render::human::print_trust_invite` already puts under "Give this
/// command to the other device's operator:", so the two blocks line up in
/// a terminal.
const CANDIDATE_INDENT: &str = "  ";

/// The finished human-mode address block: whole lines, already decided.
///
/// Opaque by design. The caller that renders it is a renderer — it must
/// contain no auth/ACL/session logic and, here, not even the choice
/// between "there are candidates" and "there are none"
/// (`docs/design/architecture.md` §1). That choice is made once, in
/// `assemble`, and what crosses the crate boundary is the answer, not
/// the inputs. A renderer that can only iterate cannot drift.
///
/// No serde derive: see this module's doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAddressAdvice {
    lines: Vec<String>,
}

impl InviteAddressAdvice {
    /// The lines to print, in order, one per output line. Never empty:
    /// `assemble` always yields at least [`INVITE_ADDRESS_NONE`].
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// Turn one already-made observation into the block to print.
///
/// `observed` is whatever source addresses the kernel named
/// (`route::observe_source_addresses` in production, a synthetic vector in
/// tests); `port` is the port to attach ([`port_from_bind_spec`]). Pure:
/// no socket, no clock, no file — so every rule below is unit-testable
/// with synthetic inputs, which is the whole reason the observation is a
/// parameter and not something this function makes.
///
/// Four rules, each dropping something that is *not an address an operator
/// could hand to a peer*, and nothing else:
///
/// 1. unspecified (`0.0.0.0`, `::`) — not an address.
/// 2. loopback (`127.0.0.0/8`, `::1`) — reachable only from this device.
/// 3. IPv6 unicast link-local (`fe80::/10`) — its zone index is not part
///    of an [`std::net::Ipv6Addr`], so the printed string would be missing
///    the one part that makes it usable. Dropped for *information loss*,
///    not for being "less routable": an IPv4 link-local
///    (`169.254.0.0/16`) loses nothing when printed and is kept, since on
///    a link-local-only network it is the real answer and the heading
///    already disclaims reachability. (`Ipv6Addr::is_unicast_link_local`
///    is still unstable, hence the explicit prefix test.)
/// 4. an IPv4-mapped IPv6 address is folded onto its IPv4 spelling
///    *before* deduplication, so one address cannot survive twice under
///    two spellings.
///
/// Surviving candidates keep first-seen order (the IPv4 axis is observed
/// first) and are rendered with [`qsh_proto::wire::format_host_port`], the
/// same formatter [`crate::trust::normalize_peer_address`] uses, so IPv6
/// bracketing has one implementation in the workspace and not two.
pub(crate) fn assemble(observed: &[IpAddr], port: u16) -> InviteAddressAdvice {
    let mut candidates: Vec<IpAddr> = Vec::new();
    for ip in observed.iter().copied().map(canonical) {
        if !is_offerable(ip) || candidates.contains(&ip) {
            continue;
        }
        candidates.push(ip);
    }
    if candidates.is_empty() {
        return InviteAddressAdvice {
            lines: vec![INVITE_ADDRESS_NONE.to_string()],
        };
    }
    let mut lines = Vec::with_capacity(candidates.len() + 1);
    lines.push(INVITE_ADDRESS_HEADING.to_string());
    for ip in candidates {
        lines.push(format!(
            "{CANDIDATE_INDENT}{}",
            qsh_proto::wire::format_host_port(&ip.to_string(), port)
        ));
    }
    InviteAddressAdvice { lines }
}

/// Rule 4: one address, one spelling, decided before deduplication.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Rules 1-3: is this something an operator could hand to a peer?
fn is_offerable(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() {
        return false;
    }
    match ip {
        // `Ipv6Addr::is_unicast_link_local` is unstable; `fe80::/10` is
        // the prefix it tests.
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 != 0xfe80,
        IpAddr::V4(_) => true,
    }
}

/// The port to print, from the same `[serve].bind` spec `qsh serve`
/// resolves its listen address out of ([`crate::serve::resolve_bind`]), or
/// [`crate::serve::DEFAULT_PORT`] when that spec names none.
///
/// Reads the port out of the spec with [`crate::trust::split_port`] rather
/// than calling `resolve_bind`: `resolve_bind` falls through to
/// `to_socket_addrs`, which is a name lookup, and `qsh trust invite` is an
/// interactive command that must not block on a resolver. Only the port is
/// wanted here, and the port is in the string.
///
/// What this deliberately does **not** see is `qsh serve --bind`: that is
/// a runtime flag of a different process, and [`INVITE_ADDRESS_HEADING`]
/// says as much rather than letting the printed port imply an observation
/// nobody made.
pub(crate) fn port_from_bind_spec(spec: Option<&str>) -> u16 {
    spec.and_then(split_port)
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(crate::serve::DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn assemble_drops_loopback_and_unspecified_candidates() {
        let observed = [
            "127.0.0.1".parse().unwrap(),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "0.0.0.0".parse().unwrap(),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            "192.0.2.10".parse().unwrap(),
        ];
        let advice = assemble(&observed, 4433);
        assert_eq!(
            advice.lines(),
            &[
                INVITE_ADDRESS_HEADING.to_string(),
                "  192.0.2.10:4433".to_string(),
            ]
        );
    }

    #[test]
    fn assemble_drops_an_ipv6_link_local_whose_zone_index_cannot_be_printed() {
        let observed = ["fe80::1".parse().unwrap()];
        let advice = assemble(&observed, 4433);
        assert_eq!(advice.lines(), &[INVITE_ADDRESS_NONE.to_string()]);
    }

    #[test]
    fn assemble_keeps_an_ipv4_link_local() {
        // Deliberate asymmetry with the IPv6 case above: an IPv4
        // link-local loses no information when printed, so it survives.
        let observed = ["169.254.5.6".parse().unwrap()];
        let advice = assemble(&observed, 4433);
        assert_eq!(
            advice.lines(),
            &[
                INVITE_ADDRESS_HEADING.to_string(),
                "  169.254.5.6:4433".to_string(),
            ]
        );
    }

    #[test]
    fn assemble_folds_an_ipv4_mapped_ipv6_onto_its_ipv4_spelling_before_deduping() {
        let observed: [IpAddr; 2] = [
            "192.0.2.10".parse().unwrap(),
            "::ffff:192.0.2.10".parse().unwrap(),
        ];
        let advice = assemble(&observed, 4433);
        assert_eq!(
            advice.lines(),
            &[
                INVITE_ADDRESS_HEADING.to_string(),
                "  192.0.2.10:4433".to_string(),
            ]
        );
    }

    #[test]
    fn assemble_deduplicates_preserving_first_seen_order() {
        let observed: [IpAddr; 3] = [
            "198.51.100.7".parse().unwrap(),
            "2001:db8::7".parse().unwrap(),
            "198.51.100.7".parse().unwrap(),
        ];
        let advice = assemble(&observed, 4433);
        assert_eq!(
            advice.lines(),
            &[
                INVITE_ADDRESS_HEADING.to_string(),
                "  198.51.100.7:4433".to_string(),
                "  [2001:db8::7]:4433".to_string(),
            ]
        );
    }

    #[test]
    fn assemble_brackets_an_ipv6_candidate_and_attaches_the_port() {
        let observed: [IpAddr; 1] = ["2001:db8::7".parse().unwrap()];
        let advice = assemble(&observed, 5555);
        assert_eq!(
            advice.lines(),
            &[
                INVITE_ADDRESS_HEADING.to_string(),
                "  [2001:db8::7]:5555".to_string(),
            ]
        );
    }

    #[test]
    fn assemble_with_no_surviving_candidate_yields_exactly_the_none_wording() {
        let advice = assemble(&[], 4433);
        assert_eq!(advice.lines(), &[INVITE_ADDRESS_NONE.to_string()]);

        let loopback_only: [IpAddr; 2] = [
            "127.0.0.1".parse().unwrap(),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ];
        let advice = assemble(&loopback_only, 4433);
        assert_eq!(advice.lines(), &[INVITE_ADDRESS_NONE.to_string()]);
    }

    #[test]
    fn port_from_bind_spec_prefers_the_configured_port_over_the_default() {
        for spec in ["[::]:5555", "0.0.0.0:5555", "serve.example.com:5555"] {
            assert_eq!(
                port_from_bind_spec(Some(spec)),
                5555,
                "spec {spec:?} must not trigger a DNS lookup and must yield its own port"
            );
        }
    }

    #[test]
    fn port_from_bind_spec_falls_back_to_the_default_for_a_portless_or_malformed_spec() {
        for spec in [
            None,
            Some("[::]"),
            Some("host:"),
            Some("host:ssh"),
            Some("host:99999"),
        ] {
            assert_eq!(
                port_from_bind_spec(spec),
                crate::serve::DEFAULT_PORT,
                "spec {spec:?} must fall back to the default port"
            );
        }
    }
}
