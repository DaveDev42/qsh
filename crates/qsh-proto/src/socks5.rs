//! SOCKS5 sans-IO codec for `-D` (dynamic port forwarding, ADR-0019).
//!
//! This is a client-facing local codec, not a wire contract between two
//! `qsh` peers: it decodes the bytes a SOCKS5-speaking application (a
//! browser via `curl --socks5-hostname`, for instance) sends to the
//! loopback listener `-D` binds, and encodes the method-selection and
//! `REP` replies sent back. It lives in `qsh-proto` next to
//! [`crate::wire::parse_forward_spec`] for the same reason that parser
//! does: it reads untrusted **local** input and is part of the project's
//! designated fuzz surface (`docs/design/protocol.md` §13, ADR-0001).
//! `docs/design/protocol.md` §16.3 lists this codec outside the wire
//! freeze.
//!
//! Only the subset of SOCKS5 that `-D` needs is accepted (ADR-0019
//! decision 7):
//!
//! - one negotiated method, no-auth (`0x00`);
//! - one command, `CONNECT` (`0x01`);
//! - three address types, IPv4 (`0x01`), domain (`0x03`), IPv6 (`0x04`).
//!
//! Both parsers are pure `&[u8] -> Result<..>` with no I/O and no
//! allocation beyond the returned value: an incremental IO driver feeds
//! them a growing buffer and reads [`Parsed::consumed`] off a successful
//! parse to know how many bytes belonged to the message (any bytes after
//! that are the client's first payload segment, e.g. an HTTP request line
//! pipelined right after the `CONNECT`, and must be spliced through
//! unread, never dropped).
//!
//! Every parse of a byte string that is a **strict prefix** of a
//! well-formed message returns [`GreetingError::Incomplete`] /
//! [`RequestError::Incomplete`], never a hard failure — the driver's only
//! job on `Incomplete` is "read more bytes and try again". The one
//! exception, by design, is [`GreetingError::Invalid`]: a first byte other
//! than `0x05` means this is not SOCKS5 at all (an HTTP verb, a TLS
//! ClientHello, a SOCKS4 request, ...), and the driver closes the
//! connection without writing anything back — sending SOCKS5 bytes to a
//! peer that never spoke SOCKS5 would be its own information leak.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ErrorCode;

/// Maximum length of a greeting message: 1 (`VER`) + 1 (`NMETHODS`) + 255
/// (`METHODS`, since `NMETHODS` is a single byte). This is a structural
/// fact about the grammar, not a policy choice — [`parse_greeting`] can
/// never ask for more bytes than this.
pub const GREETING_MAX_LEN: usize = 1 + 1 + u8::MAX as usize;

/// Maximum length of a request message: 4 (`VER`,`CMD`,`RSV`,`ATYP`) + 1
/// (domain length byte) + 255 (domain, since the length byte is a single
/// byte) + 2 (`DST.PORT`). The domain length byte can structurally encode
/// up to 255, even though `normalize_domain` rejects anything over 253
/// bytes as a shape violation (ADR-0019 decision 7) — the driver must
/// still be prepared to buffer up to this many bytes before it learns
/// that. [`parse_request`] can never ask for more than this.
pub const REQUEST_MAX_LEN: usize = 4 + 1 + u8::MAX as usize + 2;

const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REPLY_BND_ATYP: u8 = 0x01;

/// A successfully decoded message, paired with how many bytes of the input
/// it consumed. Any bytes at `input[consumed..]` were not part of this
/// message — for [`parse_request`] specifically, they may be the first
/// payload segment the client pipelined right after the request and must
/// be spliced through, never dropped (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    /// The decoded value.
    pub value: T,
    /// How many bytes of the input the message occupied.
    pub consumed: usize,
}

/// A decoded SOCKS5 greeting (`VER`, `NMETHODS`, `METHODS`).
///
/// A greeting with zero methods, or with methods that never include
/// no-auth, decodes successfully — [`encode_method_select`] is what turns
/// "no acceptable method" into the `05 FF` reply (ADR-0019 decision 7:
/// "no `0x00`, or `NMETHODS = 0` → reply `05 FF`"). Parsing itself only
/// fails on [`GreetingError::Invalid`] (wrong first byte) or
/// [`GreetingError::Incomplete`] (not enough bytes yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// The raw `METHODS` bytes, in the order the client sent them.
    pub methods: Vec<u8>,
}

impl Greeting {
    /// Whether no-auth (`0x00`) is among the offered methods.
    fn offers_no_auth(&self) -> bool {
        self.methods.contains(&METHOD_NO_AUTH)
    }
}

/// Why [`parse_greeting`] did not return a [`Greeting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreetingError {
    /// Not enough bytes yet to tell. A strict prefix of a well-formed
    /// greeting always lands here, never [`GreetingError::Invalid`].
    Incomplete,
    /// The first byte was not `0x05`: this connection is not speaking
    /// SOCKS5 (an HTTP verb, a TLS ClientHello, a SOCKS4 request, ...).
    /// The driver closes the connection immediately and writes nothing —
    /// see the module docs.
    Invalid,
}

/// Parse a SOCKS5 greeting: `VER(1) NMETHODS(1) METHODS(0..=255)`.
///
/// Returns [`GreetingError::Invalid`] only for a first byte other than
/// `0x05` (checked as soon as one byte is available, without waiting for
/// more). Every other incomplete prefix is [`GreetingError::Incomplete`].
/// Never allocates more than [`GREETING_MAX_LEN`] bytes' worth of methods
/// and never panics on any input.
pub fn parse_greeting(input: &[u8]) -> Result<Parsed<Greeting>, GreetingError> {
    let Some(&ver) = input.first() else {
        return Err(GreetingError::Incomplete);
    };
    if ver != SOCKS5_VERSION {
        return Err(GreetingError::Invalid);
    }
    let Some(&nmethods) = input.get(1) else {
        return Err(GreetingError::Incomplete);
    };
    let total = 2 + nmethods as usize;
    if input.len() < total {
        return Err(GreetingError::Incomplete);
    }
    Ok(Parsed {
        value: Greeting {
            methods: input[2..total].to_vec(),
        },
        consumed: total,
    })
}

/// Encode the method-selection reply (`VER(1) METHOD(1)`) for a decoded
/// [`Greeting`]: `05 00` if no-auth was offered, `05 FF` ("no acceptable
/// method") otherwise — including the `NMETHODS = 0` case (ADR-0019
/// decision 7).
pub fn encode_method_select(greeting: &Greeting) -> [u8; 2] {
    [
        SOCKS5_VERSION,
        if greeting.offers_no_auth() {
            METHOD_NO_AUTH
        } else {
            0xFF
        },
    ]
}

/// A decoded, fully-validated `CONNECT` request: destination host and
/// port. `host` is never empty and never carries the shapes ADR-0019
/// decision 7 excludes (control bytes, brackets, an inet_aton-style
/// numeric hostname such as `127.1`); it is one of a lowercase LDH
/// hostname, a dotted-quad IPv4 literal, or an unbracketed IPv6 literal —
/// the same "unbracketed IPv6 text" shape [`crate::wire::parse_forward_spec`]
/// produces. `port` is `1..=65535` (never `0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Destination host: hostname, IPv4 literal, or unbracketed IPv6
    /// literal.
    pub host: String,
    /// Destination port, always nonzero.
    pub port: u16,
}

/// Why [`parse_request`] did not return a [`Request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// Not enough bytes yet. A strict prefix of a well-formed request
    /// always lands here, never [`RequestError::Rejected`].
    Incomplete,
    /// The request parsed far enough to classify exactly which `REP` code
    /// the driver owes the client (ADR-0019 decision 8's local rows): the
    /// driver encodes this reply, writes it, and closes without opening a
    /// tunnel stream.
    Rejected(Rep),
}

/// How many bytes an address of this [`Request`]'s `ATYP` occupies, and —
/// for [`AddrKind::Domain`] — how many of those bytes are the domain name
/// itself (after the one length-prefix byte). Splitting this out of
/// [`parse_request`] means the `ATYP` byte is decoded exactly once and the
/// three address shapes can never fall through to an `unreachable!()`.
enum AddrKind {
    V4,
    V6,
    Domain(usize),
}

impl AddrKind {
    /// Total request length once this address kind's length is known:
    /// `VER CMD RSV ATYP` (4) + address + `DST.PORT` (2).
    fn total_len(&self) -> usize {
        4 + match self {
            AddrKind::V4 => 4,
            AddrKind::V6 => 16,
            AddrKind::Domain(len) => 1 + len,
        } + 2
    }
}

/// Classify `input[3]` (`ATYP`) into an [`AddrKind`], reading the domain
/// length byte (`input[4]`) when `ATYP` is domain. Returns
/// [`RequestError::Incomplete`] if `ATYP` is domain but `input` does not
/// yet reach the length byte, and [`RequestError::Rejected`] with
/// [`Rep::AddressTypeNotSupported`] for any `ATYP` outside `{1,3,4}`
/// (ADR-0019 decision 7).
fn addr_kind(atyp: u8, input: &[u8]) -> Result<AddrKind, RequestError> {
    match atyp {
        ATYP_IPV4 => Ok(AddrKind::V4),
        ATYP_IPV6 => Ok(AddrKind::V6),
        ATYP_DOMAIN => match input.get(4) {
            Some(&len) => Ok(AddrKind::Domain(len as usize)),
            None => Err(RequestError::Incomplete),
        },
        _ => Err(RequestError::Rejected(Rep::AddressTypeNotSupported)),
    }
}

/// Parse a SOCKS5 `CONNECT` request:
/// `VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(..) DST.PORT(2)`.
///
/// Checks run in ADR-0019 decision 7/8's priority order, each against
/// only the bytes it needs so a truncated prefix of a *valid* request
/// never misclassifies as [`RequestError::Rejected`] — it is always
/// [`RequestError::Incomplete`] until every byte the check needs has
/// arrived:
///
/// 1. `VER != 0x05` → [`Rep::GeneralFailure`]. Unlike [`parse_greeting`]'s
///    first byte, SOCKS5 negotiation is already established by the
///    request line, so the driver still owes a reply, not a silent close.
/// 2. `CMD != CONNECT (0x01)` → [`Rep::CommandNotSupported`].
/// 3. `ATYP` outside `{1,3,4}` → [`Rep::AddressTypeNotSupported`].
/// 4. `RSV != 0` or `DST.PORT == 0` → [`Rep::GeneralFailure`].
/// 5. A domain `DST.ADDR` that fails `normalize_domain`'s shape rules →
///    [`Rep::AddressTypeNotSupported`].
///
/// An IPv4/IPv6 `DST.ADDR` is never rejected by shape (every 4/16-byte
/// value is a valid address); only a domain `DST.ADDR` can fail step 5.
/// Never panics on any input.
pub fn parse_request(input: &[u8]) -> Result<Parsed<Request>, RequestError> {
    if input.len() < 4 {
        return Err(RequestError::Incomplete);
    }
    let ver = input[0];
    let cmd = input[1];
    let rsv = input[2];
    let atyp = input[3];

    if ver != SOCKS5_VERSION {
        return Err(RequestError::Rejected(Rep::GeneralFailure));
    }
    if cmd != CMD_CONNECT {
        return Err(RequestError::Rejected(Rep::CommandNotSupported));
    }

    let kind = addr_kind(atyp, input)?;
    let total = kind.total_len();
    if input.len() < total {
        return Err(RequestError::Incomplete);
    }

    let port = u16::from_be_bytes([input[total - 2], input[total - 1]]);
    if rsv != 0 || port == 0 {
        return Err(RequestError::Rejected(Rep::GeneralFailure));
    }

    let host = match kind {
        AddrKind::V4 => Ipv4Addr::new(input[4], input[5], input[6], input[7]).to_string(),
        AddrKind::V6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&input[4..20]);
            Ipv6Addr::from(octets).to_string()
        }
        AddrKind::Domain(len) => match normalize_domain(&input[5..5 + len]) {
            Some(host) => host,
            None => return Err(RequestError::Rejected(Rep::AddressTypeNotSupported)),
        },
    };

    Ok(Parsed {
        value: Request { host, port },
        consumed: total,
    })
}

/// Validate and normalize a domain `DST.ADDR` (ADR-0019 decision 7).
///
/// Order matters twice over:
///
/// 1. Length must be `1..=253` bytes and valid UTF-8, or this is rejected
///    outright — every later check operates on ASCII text only.
/// 2. Lowercase, then strip at most one trailing `.` (decision 7: "소문자로
///    바꾸고 끝의 점 하나를 뗀다"). This runs *before* the literal parse
///    below, so a dotted-quad or IPv6 literal written with a trailing dot
///    (`127.0.0.1.`) still normalizes instead of falling through to the
///    hostname rules. What remains must be non-empty with no empty label
///    (rules out `..`, `a..b`, and a second trailing dot such as
///    `127.0.0.1..`, none of which resolve).
/// 3. A string that parses as a strict IPv6 literal (`std`'s parser; no
///    brackets — the domain field is never bracketed) normalizes to that
///    literal's canonical unbracketed text.
/// 4. A string that parses as a strict dotted-quad IPv4 literal (`std`'s
///    parser, which already rejects leading zeros and non-4-octet forms)
///    normalizes to that literal's canonical text.
/// 5. Otherwise every byte must be an LDH character (`std`'s
///    `is_ascii_alphanumeric` plus `-`) or `.`/`_`; anything else (`:`,
///    `[`, `%`, whitespace, a control byte, non-ASCII) is rejected. This
///    charset check runs *after* the literal parse above, because a
///    literal's own text (an IPv6 literal's colons, most sharply) would
///    otherwise fail it.
/// 6. A rejected-but-charset-valid string that still *looks* like an
///    address is rejected too: a **last label** made entirely of digits,
///    or starting with `0x`, is the inet_aton-style shape ADR-0019 names
///    (`127.1`, `0x7f.1`, `2130706433`) — accepting it as a plain hostname
///    would let a resolver that still understands those forms quietly
///    turn it back into an address this codec never validated as one.
///    Checking only the *last* label (not the whole string) matters both
///    ways: `127.0x1` must still be rejected even though `0x` is not at
///    offset 0, and `0xproject.com` must be accepted because its last
///    label (`com`) is an ordinary one.
///
/// Returns `None` for any rejection above.
fn normalize_domain(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;

    let mut host = text.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return None;
    }

    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return Some(v6.to_string());
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(v4.to_string());
    }

    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }

    let last_label = host.rsplit('.').next().unwrap_or(&host);
    let looks_like_a_bare_address = (!last_label.is_empty()
        && last_label.bytes().all(|b| b.is_ascii_digit()))
        || last_label.starts_with("0x");
    if looks_like_a_bare_address {
        return None;
    }

    Some(host)
}

/// A SOCKS5 `REP` code (the second byte of a `CONNECT` reply).
///
/// Named after RFC 1928's canonical meanings. ADR-0019 decision 8's
/// mapping table only ever produces [`Rep::Succeeded`],
/// [`Rep::GeneralFailure`], [`Rep::NotAllowedByRuleset`],
/// [`Rep::HostUnreachable`], [`Rep::ConnectionRefused`],
/// [`Rep::CommandNotSupported`], and [`Rep::AddressTypeNotSupported`] —
/// [`Rep::NetworkUnreachable`] and [`Rep::TtlExpired`] exist for
/// completeness of [`encode_reply`]'s input type but are never produced by
/// [`Rep::from_error_code`] or by [`parse_request`] (ADR-0019 lists this
/// coarseness as residual risk R4, not a bug here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rep {
    /// `0x00`: the `CONNECT` succeeded.
    Succeeded = 0x00,
    /// `0x01`: general SOCKS server failure — the catch-all for anything
    /// [`Rep::from_error_code`] cannot classify more specifically, and for
    /// [`parse_request`]'s `RSV`/`DST.PORT` shape violations.
    GeneralFailure = 0x01,
    /// `0x02`: connection not allowed by ruleset (ACL denial).
    NotAllowedByRuleset = 0x02,
    /// `0x03`: network unreachable. Never produced today (see the enum
    /// doc).
    NetworkUnreachable = 0x03,
    /// `0x04`: host unreachable (remote name resolution failure).
    HostUnreachable = 0x04,
    /// `0x05`: connection refused (dial failure after resolution).
    ConnectionRefused = 0x05,
    /// `0x06`: TTL expired. Never produced today (see the enum doc).
    TtlExpired = 0x06,
    /// `0x07`: command not supported (`CMD != CONNECT`).
    CommandNotSupported = 0x07,
    /// `0x08`: address type not supported (`ATYP` outside `{1,3,4}`, or a
    /// domain `DST.ADDR` that fails `normalize_domain`'s shape rules).
    AddressTypeNotSupported = 0x08,
}

impl Rep {
    /// The wire byte for this `REP` code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Map a peer [`ErrorCode`] (from a `TCP_CONNECT` stream's
    /// `ConnectResult{ok: false, code, ..}`) to the `REP` code ADR-0019
    /// decision 8's table assigns it.
    ///
    /// This match has no wildcard arm: it names every
    /// [`ErrorCode`] variant, including [`ErrorCode::Unknown`], so that
    /// adding a new [`ErrorCode`] variant fails to compile here until this
    /// function (and the pinned exhaustiveness test next to it) says where
    /// it lands, rather than silently falling through to
    /// [`Rep::GeneralFailure`] by accident.
    ///
    /// [`Rep::Succeeded`] is deliberately unreachable from this function —
    /// the `ok: true` case of a [`crate::wire::ConnectResult`] carries no
    /// [`ErrorCode`] at all, so callers construct it directly instead of
    /// going through this mapping (decision 8's table lists it as its own
    /// row precisely because it isn't an error).
    #[must_use]
    pub fn from_error_code(code: &ErrorCode) -> Rep {
        match code {
            ErrorCode::PermissionDenied => Rep::NotAllowedByRuleset,
            ErrorCode::HostNotFound => Rep::HostUnreachable,
            ErrorCode::ConnectionFailed => Rep::ConnectionRefused,
            ErrorCode::InvalidArgument
            | ErrorCode::ConfigError
            | ErrorCode::AuthFailed
            | ErrorCode::TrustRequired
            | ErrorCode::SessionNotFound
            | ErrorCode::SessionConflict
            | ErrorCode::ResumeGap
            | ErrorCode::Timeout
            | ErrorCode::Canceled
            | ErrorCode::RemoteError
            | ErrorCode::Unsupported
            | ErrorCode::ResourceExhausted
            | ErrorCode::Internal
            | ErrorCode::Unknown(_) => Rep::GeneralFailure,
        }
    }
}

/// Encode a `CONNECT` reply: `VER(1) REP(1) RSV(1)=0 ATYP(1)=1 BND.ADDR(4)=0.0.0.0
/// BND.PORT(2)=0`.
///
/// `BND` is always the fixed IPv4 `0.0.0.0:0` (ADR-0019 decision 8): a
/// [`crate::wire::ConnectResult`] carries no field for the address a dial
/// actually bound or connected from, and none is added — the reply's
/// `BND` fields are a legacy of SOCKS5's `BIND` command, which this codec
/// never implements.
#[must_use]
pub fn encode_reply(rep: Rep) -> [u8; 10] {
    [
        SOCKS5_VERSION,
        rep.code(),
        0x00,
        REPLY_BND_ATYP,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

#[cfg(test)]
mod tests;
