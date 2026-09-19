//! `tunnel.*` request and data types (`docs/CLI.md` §6.9).

use super::*;

// ---------------------------------------------------------------------------
// tunnel.* (`docs/CLI.md` §6.9, M4)
// ---------------------------------------------------------------------------

/// A tunnel entry as returned by `tunnel.open`/`tunnels`/`tunnel.close`
/// (`docs/CLI.md` §6.9, "Tunnel").
///
/// This is the JSON DTO: the wire `RemoteForwardOpen`/`RemoteForwardOpened`
/// and the localctl `LocalTunnel` carry `tunnel_id`/`mode`/`bind`/
/// `forward_to`/`actual_port` only, and the client `Ops` layer adds `host`
/// from its own local alias knowledge — the same pattern `Session.host`
/// uses over the wire `SessionInfo` (ADR-0007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Tunnel {
    /// Opaque handle for `tunnel.close` / filtering `tunnels`.
    pub tunnel_id: String,
    /// Open string set: `"local"` (`-L`) or `"remote"` (`-R`) — same
    /// open-string discipline as `Host.connection_mode` (`docs/CLI.md`
    /// §10).
    pub mode: String,
    /// The `[bind:]listen_port` half of the forward spec, as bound.
    pub bind: String,
    /// The `host:host_port` half of the forward spec — the dial target, in
    /// the canonical form [`crate::wire::format_host_port`] produces (an
    /// IPv6 literal is bracketed: `"[::1]:5432"`).
    pub forward_to: String,
    /// The port actually bound — the kernel-assigned one for a `0`
    /// request, and the requested one when it was granted as asked
    /// (`docs/CLI.md` §6.9's `Tunnel` example carries it for a fixed-port
    /// forward). Optional because a tunnel that is not bound yet has no
    /// port to report; a producer that knows the bound port always fills
    /// it, so a reader never has to fall back to splitting `bind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_port: Option<u32>,
    /// Host alias this tunnel is on (`Ops`-filled; never present on the
    /// wire — ADR-0007, same rule as `Session.host`).
    pub host: String,
}

/// Request for `tunnel.open` (`docs/CLI.md` §6.9, `-L`/`-R`). `mode`
/// selects the direction (`"local"` for `-L`, `"remote"` for `-R` —
/// `wire::ForwardDirection`'s JSON mirror); `bind`/`listen_port`/
/// `forward_host`/`forward_port` are the already-parsed halves of the
/// `[bind:]listen_port:host:host_port` spec (`wire::parse_forward_spec`
/// parses the raw CLI string into these before a request is built — this
/// type never carries the unparsed string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelOpenReq {
    /// Host alias.
    pub host: String,
    /// `"local"` or `"remote"`.
    pub mode: String,
    /// The `[bind:]` prefix, when present; `None` = caller-side default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// The `listen_port` component.
    pub listen_port: u32,
    /// The `host` component of the forward spec (the dial target host —
    /// distinct from this request's own `host` field, which is the QSH
    /// peer).
    pub forward_host: String,
    /// The `host_port` component of the forward spec.
    pub forward_port: u32,
}

/// Data payload of a successful `tunnel.open`: the opened tunnel, exactly
/// the shape `tunnels`/`tunnel.close` also return — same "the data payload
/// is a [`Tunnel`]" pattern `HostGetReq`/`SessionGetReq` already use for
/// their respective single-entity gets.
pub type TunnelOpenData = Tunnel;

/// Request for `tunnel.list` (`qsh tunnels`, `docs/CLI.md` §6.9). No
/// filters — every tunnel visible under the caller's ownership is
/// returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct TunnelListReq {}

/// Data payload of `tunnel.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelListData {
    /// Every tunnel visible to this caller.
    pub tunnels: Vec<Tunnel>,
}

/// Request for `tunnel.close` (`docs/CLI.md` §6.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelCloseReq {
    /// Opaque tunnel handle.
    pub tunnel_id: String,
}

/// Data payload of `tunnel.close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelCloseData {
    /// Opaque tunnel handle that was asked to be closed.
    pub tunnel_id: String,
    /// `true` if a tunnel was closed; `false` if none existed with that id
    /// (idempotent, same pattern as `TrustRemoveData::removed`).
    pub closed: bool,
}

// ---------------------------------------------------------------------------
// tunnel.dynamic (`-D`, `docs/CLI.md` §6.9, ADR-0019 decision 11)
// ---------------------------------------------------------------------------

/// Request for `tunnel.dynamic` (`-D`, ADR-0019 decision 11). A dedicated
/// request/data pair rather than a widened `TunnelOpenReq`/[`Tunnel`]: the
/// existing pair's `forward_host`/`forward_port` mean "the dial target",
/// which `-D` has none of at open time (the SOCKS client picks one per
/// `CONNECT`) — turning them `Option` or reinterpreting an empty value as
/// "no target" would be a type or meaning change either way, and
/// `docs/CLI.md` §10's additive-only rule allows neither on an existing
/// type (ADR-0019's own rationale section).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TunnelDynamicReq {
    /// Host alias to open the SOCKS5 listener's tunnel streams against.
    pub host: String,
    /// The `[bind:]` prefix, when present; `None` = loopback default —
    /// same convention as [`TunnelOpenReq::bind`]. A non-loopback value is
    /// refused (`INVALID_ARGUMENT`) before anything connects, never
    /// honored (ADR-0019 decision 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// The port to bind the SOCKS5 listener on.
    pub listen_port: u32,
}

/// Data payload of a successful `tunnel.dynamic`: the opened `-D` listener
/// (ADR-0019 decision 11). Deliberately not a [`Tunnel`] — there is no
/// `forward_to`, because the destination is chosen per `CONNECT` by
/// whatever speaks SOCKS5 through this listener, not fixed at open time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DynamicTunnel {
    /// Opaque handle for `tunnel.close` — same id space as [`Tunnel::tunnel_id`],
    /// just never listed by `tunnel.list` (`-D` is a foreground holder like
    /// `tunnel.open`'s `"local"` mode, ADR-0019 decision 11).
    pub tunnel_id: String,
    /// Always `"dynamic"` — an open string, same discipline as
    /// [`Tunnel::mode`].
    pub mode: String,
    /// The `[bind:]listen_port` half, as bound — same shape and meaning as
    /// [`Tunnel::bind`].
    pub bind: String,
    /// The port actually bound — same type and meaning as
    /// [`Tunnel::actual_port`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_port: Option<u32>,
    /// The local protocol this listener speaks. Always `"socks5"` today;
    /// an open string in case a future SOCKS variant needs a second value
    /// (ADR-0019 decision 11).
    pub protocol: String,
    /// The dial policy every `CONNECT` on this listener rides
    /// (`StreamHeader.deny_host_local`, ADR-0019 decision 3). Always
    /// `"deny_host_local"` today; an open string for the same reason as
    /// `protocol`.
    pub dial_policy: String,
    /// Host alias this tunnel is on (`Ops`-filled; never present on the
    /// wire — ADR-0007, same rule as [`Tunnel::host`]).
    pub host: String,
}
