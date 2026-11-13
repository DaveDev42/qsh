//! Whether an endpoint asks its router for a port mapping (ADR-0064).
//!
//! iroh's portmapper (UPnP, NAT-PMP, PCP) asks the gateway for a public
//! UDP port that forwards to the endpoint's socket and then advertises that
//! address like any other. A peer behind a fully symmetric NAT cannot be
//! punched toward, because its mapping changes with every destination; it
//! can still send first to a mapped address, which is why a daemon asks.
//!
//! What is fixed here:
//!
//! - **Only a daemon endpoint maps.** A client endpoint is a short-lived
//!   process with a random key; a mapping for it would be a router entry per
//!   command. iroh's own default is *on* once its `portmapper` feature is
//!   compiled in, so a client says `Disabled` explicitly instead of leaving
//!   the default.
//! - **A daemon maps only when asked** ([`crate::IrohConfig::portmap`]); the
//!   transport's default is off, so a test that builds an `IrohConfig` by
//!   hand never talks to the LAN gateway. `[iroh].portmap` (unset is on)
//!   feeds it for a real daemon.
//! - **A relay-less endpoint never maps.** iroh's net report, which is where
//!   it normally asks for a mapping, is skipped without a relay. But iroh also
//!   hands its IPv4 socket's port to the portmapper when it binds, and the
//!   portmapper starts a mapping on that alone (an SSDP search on the LAN and
//!   a probe of the gateway), relay or not. So qsh passes
//!   `Disabled` when the relay list is empty instead of relying on iroh.
//!
//! The reflexive keeper (`reflexive.rs`) does not touch a mapped address.
//! It only calls `add_external_addr` and `remove_external_addr`, which edit
//! iroh's *configured* set; iroh builds the advertised set from the
//! portmapper's address first, then the net report's, the interfaces' and the
//! configured set, keeping the first type seen for an address. A mapped
//! address therefore stays `Portmapped` even when the keeper pins the same
//! socket address.

use iroh::endpoint::PortmapperConfig;

/// Whether the endpoint being built asks the router for a mapping: a daemon
/// endpoint with at least one relay whose configuration says so.
pub(crate) fn mapping_wanted(daemon: bool, requested: bool, has_relay: bool) -> bool {
    daemon && requested && has_relay
}

/// The portmapper setting handed to iroh's endpoint builder.
pub(crate) fn portmapper_config(mapping: bool) -> PortmapperConfig {
    if mapping {
        // The variant is `non_exhaustive`: `default()` is how it is built,
        // and it is `Enabled` (iroh's own default).
        PortmapperConfig::default()
    } else {
        PortmapperConfig::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_daemon_that_asks_maps() {
        assert!(mapping_wanted(true, true, true));
        assert!(!mapping_wanted(true, false, true));
        // A client endpoint never maps, whatever the config says.
        assert!(!mapping_wanted(false, true, true));
        assert!(!mapping_wanted(false, false, true));
        // No relay, no mapping: iroh would still start one at bind.
        assert!(!mapping_wanted(true, true, false));
    }

    #[test]
    fn the_builder_gets_an_explicit_setting_both_ways() {
        assert!(matches!(
            portmapper_config(true),
            PortmapperConfig::Enabled { .. }
        ));
        // `Disabled`, not iroh's default: with the `portmapper` feature
        // compiled in, the default is `Enabled`.
        assert!(matches!(
            portmapper_config(false),
            PortmapperConfig::Disabled
        ));
    }
}
