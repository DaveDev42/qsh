//! The settings of the iroh relay route (ADR-0061, `docs/CLI.md` §6.12 and
//! §6.23), in a form the route layer and the daemons read without knowing
//! the config file.
//!
//! `config.toml`'s `[iroh]` section ([`IrohSection`]) holds six optional
//! keys. [`IrohSection::settings`] validates them (a bad value is
//! `CONFIG_ERROR`, before any socket opens) and fills the defaults, which
//! gives [`IrohSettings`]. [`IrohSettings`] then answers the questions the
//! rest of qsh asks: is the route on for this command, which relay does this
//! pin use, and what endpoint configuration does that make. It never names
//! the iroh crate; the configuration it builds is `qsh_transport`'s neutral
//! [`IrohConfig`].

use std::sync::Arc;
use std::time::Duration;

use qsh_proto::{ErrorCode, TrustPeer};
use qsh_transport::{
    CertificateDer, IrohConfig, IrohPeer, IrohRelay, IrohRelayTrust, LocalIdentity, TrustEvaluator,
};
use serde::{Deserialize, Serialize};

use crate::ops::OpError;
use crate::trust::iroh_pin;

/// One of n0's public relays, the first of [`DEFAULT_RELAY_URLS`]
/// (ADR-0061 decision 10). Public relays are rate limited and their terms can
/// change; a self-hosted `iroh-relay` is the alternative.
pub const DEFAULT_RELAY_URL: &str = "https://aps1-1.relay.n0.iroh.link";

/// The relays used when neither the pin nor `[iroh].relay_url` names any:
/// n0's four public relays (ADR-0062). A daemon homes on the one that answers
/// fastest and moves to another when it stops answering; a client dial
/// offers all of them.
pub const DEFAULT_RELAY_URLS: [&str; 4] = [
    "https://aps1-1.relay.n0.iroh.link",
    "https://usw1-1.relay.n0.iroh.link",
    "https://use1-1.relay.n0.iroh.link",
    "https://euc1-1.relay.n0.iroh.link",
];

/// The most relay URLs `[iroh].relay_url` may list
/// ([`qsh_transport::MAX_RELAY_CANDIDATES`]).
pub const MAX_RELAY_URLS: usize = qsh_transport::MAX_RELAY_CANDIDATES;

/// `[iroh].relay_url` as written: one URL (a string) or a candidate list (an
/// array of strings, ADR-0062). A string keeps meaning what it always did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelayUrlSetting {
    /// `relay_url = "https://relay.example"`.
    One(String),
    /// `relay_url = ["https://a.example", "https://b.example"]`.
    Many(Vec<String>),
}

impl RelayUrlSetting {
    fn urls(&self) -> Vec<&str> {
        match self {
            Self::One(url) => vec![url.as_str()],
            Self::Many(urls) => urls.iter().map(String::as_str).collect(),
        }
    }
}

impl From<&str> for RelayUrlSetting {
    fn from(url: &str) -> Self {
        Self::One(url.to_string())
    }
}

/// `[iroh].head_start_ms` when the key is unset.
pub const DEFAULT_HEAD_START_MS: u64 = 1000;

/// The largest `[iroh].head_start_ms`.
pub const MAX_HEAD_START_MS: u64 = 10_000;

/// `[iroh].mode` (`docs/CLI.md` §6.23): the client-side switch of the route.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IrohMode {
    /// A pin whose `routes` has `iroh` may use the relay route.
    #[default]
    Auto,
    /// This device ignores every pin's `routes`.
    Off,
}

impl IrohMode {
    /// The spelling the config key uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Off => "off",
        }
    }
}

/// `[iroh].proxy`: whether the relay connection follows the proxy variables
/// of the environment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IrohProxy {
    /// Follow `HTTPS_PROXY` and its relatives.
    #[default]
    Env,
    /// Connect to the relay directly.
    Off,
}

impl IrohProxy {
    /// The spelling the config key uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Off => "off",
        }
    }
}

/// `[iroh]` section (ADR-0061 decisions 2, 10 and 11). Every key is
/// optional; read it with [`IrohSection::settings`], which checks the values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IrohSection {
    /// Whether a daemon (`qsh serve`, `qsh listen`, `qsh serve --to`) brings
    /// up an iroh endpoint. Unset is `true` (ADR-0063); `false` keeps the
    /// daemon off every relay.
    pub enable: Option<bool>,
    /// The relay (`https://...`) this device homes on, or the list of
    /// candidate relays it homes on the best of and fails over among
    /// (ADR-0062). Unset is [`DEFAULT_RELAY_URLS`].
    pub relay_url: Option<RelayUrlSetting>,
    /// The UDP port of the daemon's iroh endpoint, `0..=65535`. Unset or `0`
    /// is an ephemeral port. Held wide so an out-of-range value reaches
    /// [`IrohSection::settings`] as a `CONFIG_ERROR` rather than a parse
    /// failure.
    pub bind_port: Option<u64>,
    /// The client-side switch. Unset is `auto`.
    pub mode: Option<IrohMode>,
    /// Proxy handling for the relay connection. Unset is `env`.
    pub proxy: Option<IrohProxy>,
    /// How long direct dial and hole punching run alone before the relay
    /// attempt starts, in milliseconds, `0..=10000`. Unset is 1000.
    pub head_start_ms: Option<u64>,
    /// Whether a daemon endpoint asks the router for a port mapping (UPnP,
    /// NAT-PMP, PCP) so a peer behind a symmetric NAT can send first to the
    /// mapped address (ADR-0064). Unset is `true`; `false` leaves the router
    /// alone. A client command never maps.
    pub portmap: Option<bool>,
}

fn config_error(message: String) -> OpError {
    OpError::new(ErrorCode::ConfigError, message).with_retryable(false)
}

impl IrohSection {
    /// Check the section and fill its defaults. Fails with `CONFIG_ERROR`
    /// (not retryable) for a relay URL that is not an `https` URL, a port or
    /// a head start out of range.
    pub fn settings(&self) -> Result<IrohSettings, OpError> {
        let relay_urls = match &self.relay_url {
            Some(setting) => {
                let given = setting.urls();
                if given.is_empty() {
                    return Err(config_error(
                        "[iroh].relay_url is an empty list; name at least one relay or unset \
                         the key for the default relays"
                            .to_string(),
                    ));
                }
                let mut urls: Vec<String> = Vec::with_capacity(given.len());
                for url in given {
                    iroh_pin::validate_relay_url(url)
                        .map_err(|why| config_error(format!("[iroh].relay_url: {why}")))?;
                    // The same relay spelled twice is one candidate.
                    if !urls.iter().any(|seen| same_relay(seen, url)) {
                        urls.push(url.to_string());
                    }
                }
                if urls.len() > MAX_RELAY_URLS {
                    return Err(config_error(format!(
                        "[iroh].relay_url lists {} relays, at most {MAX_RELAY_URLS} are taken",
                        urls.len()
                    )));
                }
                urls
            }
            None => default_relay_urls(),
        };
        let bind_port = match self.bind_port {
            None => 0,
            Some(port) => u16::try_from(port).map_err(|_| {
                config_error(format!("[iroh].bind_port ({port}) must be 0 to 65535"))
            })?,
        };
        let head_start_ms = self.head_start_ms.unwrap_or(DEFAULT_HEAD_START_MS);
        if head_start_ms > MAX_HEAD_START_MS {
            return Err(config_error(format!(
                "[iroh].head_start_ms ({head_start_ms}) must be 0 to {MAX_HEAD_START_MS}"
            )));
        }
        Ok(IrohSettings {
            enable: self.enable.unwrap_or(true),
            relay_urls,
            bind_port,
            mode: self.mode.unwrap_or_default(),
            proxy: self.proxy.unwrap_or_default(),
            head_start: Duration::from_millis(head_start_ms),
            portmap: self.portmap.unwrap_or(true),
            relay_roots: Vec::new(),
            client_bind: Vec::new(),
        })
    }
}

/// The validated, defaulted iroh settings of this device
/// ([`IrohSection::settings`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohSettings {
    /// A daemon brings up an iroh endpoint.
    pub enable: bool,
    /// The relays this device homes on the best of and dials through (the
    /// default relays when unset); never empty.
    pub relay_urls: Vec<String>,
    /// The daemon endpoint's UDP port, `0` for an ephemeral one.
    pub bind_port: u16,
    /// Whether client commands may use the relay route at all.
    pub mode: IrohMode,
    /// Whether the relay connection follows the environment's proxy.
    pub proxy: IrohProxy,
    /// How long direct dial and punching run alone before the relay attempt
    /// starts. Zero starts everything at once.
    pub head_start: Duration,
    /// Whether a daemon endpoint asks the router for a port mapping
    /// (ADR-0064). Only [`Self::server_config`] carries it; a client
    /// endpoint never maps.
    pub portmap: bool,
    /// Roots trusted for the relay's TLS certificate besides the operating
    /// system's store. Never read from a config file: only a test that runs
    /// its own relay sets it ([`Self::with_relay_roots`]).
    pub relay_roots: Vec<CertificateDer>,
    /// The sockets a client endpoint binds; empty is ephemeral ports on every
    /// interface. Never read from a config file: only a test that must keep
    /// the relay the sole path sets it ([`Self::with_client_bind`]).
    pub client_bind: Vec<std::net::SocketAddr>,
}

impl Default for IrohSettings {
    fn default() -> Self {
        // The defaults of an empty section; `settings()` of an empty section
        // cannot fail.
        Self {
            enable: true,
            relay_urls: default_relay_urls(),
            bind_port: 0,
            mode: IrohMode::Auto,
            proxy: IrohProxy::Env,
            head_start: Duration::from_millis(DEFAULT_HEAD_START_MS),
            portmap: true,
            relay_roots: Vec::new(),
            client_bind: Vec::new(),
        }
    }
}

fn default_relay_urls() -> Vec<String> {
    DEFAULT_RELAY_URLS
        .iter()
        .map(|u| (*u).to_string())
        .collect()
}

/// A relay URL without a trailing slash or a fully-qualified-name dot, in
/// lower case: what two spellings of one relay have in common.
fn relay_key(url: &str) -> String {
    url.trim_end_matches('/')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn same_relay(a: &str, b: &str) -> bool {
    relay_key(a) == relay_key(b)
}

/// Whether `url` is one of the built-in default relays, ignoring a trailing
/// slash or a fully-qualified-name dot.
pub fn is_default_relay(url: &str) -> bool {
    DEFAULT_RELAY_URLS.iter().any(|d| same_relay(url, d))
}

impl IrohSettings {
    /// These settings with the route off: what `--no-iroh` does to one
    /// command. The daemon's `enable` is left as it was.
    #[must_use]
    pub fn route_off(mut self) -> Self {
        self.mode = IrohMode::Off;
        self
    }

    /// These settings that also trust `roots` for the relay's TLS
    /// certificate. A seam for tests that run their own relay; no config key
    /// or flag reaches it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_relay_roots(mut self, roots: Vec<CertificateDer>) -> Self {
        self.relay_roots = roots;
        self
    }

    /// These settings whose client endpoints bind `addrs`. A seam for tests
    /// that must keep the relay the only path; no config key or flag reaches
    /// it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_client_bind(mut self, addrs: Vec<std::net::SocketAddr>) -> Self {
        self.client_bind = addrs;
        self
    }

    /// Whether a client command may take the relay route.
    pub fn route_enabled(&self) -> bool {
        self.mode == IrohMode::Auto
    }

    /// The relays a dial to `pin` goes through: the pin's own `relay` alone
    /// (a pin that names a relay names the one it is homed on, so it has no
    /// failover), else this device's candidates (`docs/CLI.md` §6.11). The
    /// pin's value is read only when its `routes` has `iroh`.
    pub fn relays_for<'a>(&'a self, pin: &'a TrustPeer) -> Vec<&'a str> {
        match &pin.relay {
            Some(relay) if iroh_pin::wants_iroh(pin) => vec![relay.as_str()],
            _ => self.relay_urls.iter().map(String::as_str).collect(),
        }
    }

    /// The relay URL's scheme and host, for reports (`doctor`, audit): the
    /// only part of it that leaves the machine's own files.
    pub fn relay_label(url: &str) -> String {
        iroh_pin::relay_scheme_host(url).unwrap_or_else(|| "https://-".to_string())
    }

    fn base_config(
        &self,
        relays: &[&str],
        bind: Vec<std::net::SocketAddr>,
        portmap: bool,
    ) -> IrohConfig {
        IrohConfig {
            relay: match relays {
                [one] => IrohRelay::Url((*one).to_string()),
                many => IrohRelay::Urls(many.iter().map(|u| (*u).to_string()).collect()),
            },
            // The operating system's store (ADR-0061 decision 12), plus the
            // roots a test relay brings.
            relay_trust: if self.relay_roots.is_empty() {
                IrohRelayTrust::System
            } else {
                IrohRelayTrust::SystemWithRoots(self.relay_roots.clone())
            },
            bind,
            proxy_from_env: self.proxy == IrohProxy::Env,
            portmap,
            relay_quic_port: None,
        }
    }

    /// The configuration of a client endpoint that dials `pin`: the relays
    /// [`Self::relays_for`] picks, on ephemeral UDP ports.
    pub fn client_config(&self, pin: &TrustPeer) -> IrohConfig {
        // A client endpoint never asks the router for a mapping (ADR-0064).
        self.base_config(&self.relays_for(pin), self.client_bind.clone(), false)
    }

    /// The configuration of a daemon's endpoint: homed on the best of this
    /// device's relays, on `bind_port` when one is set (IPv4 and IPv6) and on
    /// ephemeral ports otherwise, asking the router for a port mapping unless
    /// `[iroh].portmap` is off (ADR-0064).
    pub fn server_config(&self) -> IrohConfig {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
        let bind = if self.bind_port == 0 {
            Vec::new()
        } else {
            vec![
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.bind_port)),
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, self.bind_port)),
            ]
        };
        let relays: Vec<&str> = self.relay_urls.iter().map(String::as_str).collect();
        self.base_config(&relays, bind, self.portmap)
    }
}

/// Everything the route layer needs to dial one pin over the relay route
/// ([`Ops::iroh_plan`](crate::Ops)).
#[derive(Debug, Clone)]
pub struct IrohTarget {
    /// The settings this target was built from.
    pub settings: IrohSettings,
    /// Whom to dial: the pin's key, offered through every relay of the
    /// endpoint.
    pub peer: IrohPeer,
    /// The client endpoint configuration for this pin.
    pub config: IrohConfig,
    /// The relays this dial goes through: the pin's own, or the device's
    /// candidates.
    pub relay_urls: Vec<String>,
}

impl IrohTarget {
    /// Build the target for `pin`, or `None` when the pin cannot be dialed
    /// by key: it does not ask for the route, or it has no (valid) key yet.
    pub fn for_pin(settings: &IrohSettings, pin: &TrustPeer) -> Option<Self> {
        if !settings.route_enabled() || !iroh_pin::wants_iroh(pin) {
            return None;
        }
        let key = iroh_pin::parse_key_hex(pin.key.as_deref()?).ok()?;
        Some(Self {
            settings: settings.clone(),
            peer: IrohPeer::new(key),
            config: settings.client_config(pin),
            relay_urls: settings
                .relays_for(pin)
                .into_iter()
                .map(str::to_string)
                .collect(),
        })
    }

    /// Whether this dial uses only the built-in public relays.
    pub fn uses_default_relay(&self) -> bool {
        self.relay_urls.iter().all(|url| is_default_relay(url))
    }
}

/// How the route layer dials one pin over the relay route: the target, and
/// the identity and trust the endpoint is built with. One per command (and
/// per recovery re-dial); it holds no socket, so building it touches no
/// network (`crate::ops::route` binds the endpoint when the route starts).
#[derive(Clone)]
pub struct IrohPlan {
    /// The pin name, for messages.
    pub name: String,
    /// Whom to dial and through which relay.
    pub target: IrohTarget,
    /// This device's identity: the endpoint's secret key is derived from it.
    pub identity: LocalIdentity,
    /// The trust store narrowed to the pin's exact key (ADR-0060), the same
    /// view the direct dial uses.
    pub evaluator: Arc<dyn TrustEvaluator>,
    /// What this device remembers about the pin's routes (`docs/CLI.md`
    /// §6.1 "route 기억"); `None` keeps every dial in the usual order.
    pub memory: Option<crate::route_memory::RouteMemory>,
}

impl IrohPlan {
    /// How long direct dial and punching run alone before iroh starts.
    pub fn head_start(&self) -> Duration {
        self.target.settings.head_start
    }
}

impl std::fmt::Debug for IrohPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohPlan")
            .field("name", &self.name)
            .field(
                "relays",
                &self
                    .target
                    .relay_urls
                    .iter()
                    .map(|url| IrohSettings::relay_label(url))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// The error for a route that iroh cannot take: `UNSUPPORTED` with
/// `details.iroh.reason` set (`docs/CLI.md` §3.3). `host` is a pin name, never
/// an address.
pub(crate) fn unsupported(reason: &str, message: String) -> OpError {
    OpError::new(ErrorCode::Unsupported, message)
        .with_retryable(false)
        .with_details(serde_json::json!({ "iroh": { "reason": reason } }))
}

/// A private-CA peer cannot be reached over iroh (ADR-0061 decision 4).
pub(crate) fn unsupported_private_ca(name: &str) -> OpError {
    unsupported(
        "private_ca_unsupported",
        format!(
            "{name:?} is a private CA root, not a pinned peer; the iroh relay route reaches \
             pinned peers by key and does not support private CA certificates"
        ),
    )
}

/// A jump chain cannot open a hop or its target over iroh (ADR-0061
/// decision 14). The `jump.stage` detail matches the other jump failures.
pub(crate) fn unsupported_jump(name: &str) -> OpError {
    let mut err = unsupported(
        "jump_unsupported",
        format!(
            "{name:?} can only be reached over the iroh relay route, and a -J chain uses direct \
             and hole-punched routes only; give the pin an address or connect without -J"
        ),
    );
    if let Some(details) = err.details.as_object_mut() {
        details.insert(
            "jump".to_string(),
            serde_json::json!({ "stage": "unsupported" }),
        );
    }
    err
}

#[cfg(test)]
mod tests;
