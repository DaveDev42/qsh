//! [`PeerAddr`]: where the far end of a connection is, in a form that does
//! not assume a UDP socket address (ADR-0061 decision 6).
//!
//! A QUIC connection reports [`PeerAddr::Socket`], which renders exactly like
//! the `SocketAddr` it wraps (audit records, logs and JSON output are
//! byte-identical to before the type existed). [`PeerAddr::Keyed`] is what
//! the iroh backend reports (ADR-0061 decisions 1, 3 and 6): the peer is
//! known by its Ed25519 key, and the path that carried the connection is
//! either a direct socket address or a relay URL. It renders as
//! `iroh:<fingerprint>` whatever the path (`docs/CLI.md` §6.22); the path
//! is a separate field in the audit record.
//!
//! Callers that truly need an IP (admission rate limits, hole punching,
//! prediction of the NAT mapping) go through [`PeerAddr::socket_addr`] and
//! decide what a missing address means for them.

use std::fmt;
use std::net::SocketAddr;

use crate::identity::Fingerprint;
use crate::iroh_backend::fingerprint_of_ed25519_key;

/// Length of a [`PeerKey`] in bytes (an Ed25519 public key).
pub const PEER_KEY_LEN: usize = 32;

/// A peer's Ed25519 public key (the iroh `EndpointId`, ADR-0061 decision 3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerKey(pub [u8; PEER_KEY_LEN]);

impl fmt::Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl PeerKey {
    /// The qsh fingerprint (SPKI SHA-256) of this key, the name a pin and
    /// an audit record give the peer.
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_of_ed25519_key(&self.0)
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey({self})")
    }
}

/// The path that carries a keyed connection right now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PeerPath {
    /// A direct (possibly hole-punched) UDP path.
    Direct(SocketAddr),
    /// Through a relay, identified by its URL.
    Relay(String),
}

impl fmt::Display for PeerPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerPath::Direct(addr) => write!(f, "{addr}"),
            PeerPath::Relay(url) => write!(f, "relay:{url}"),
        }
    }
}

/// The remote end of a connection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PeerAddr {
    /// A plain UDP socket address (every QUIC backend connection today).
    Socket(SocketAddr),
    /// A peer identified by key, reached over `path` (iroh backend).
    Keyed {
        /// The peer's public key.
        key: PeerKey,
        /// The path in use now; it can change over the connection's life.
        path: PeerPath,
    },
}

impl PeerAddr {
    /// The socket address, when this peer has one. `Some` for
    /// [`Socket`](Self::Socket) and for a [`Keyed`](Self::Keyed) peer on a
    /// [`Direct`](PeerPath::Direct) path; `None` behind a relay, where no
    /// address of the peer is visible. Callers that key state by IP must say
    /// what `None` means for them.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            PeerAddr::Socket(addr) => Some(*addr),
            PeerAddr::Keyed {
                path: PeerPath::Direct(addr),
                ..
            } => Some(*addr),
            PeerAddr::Keyed { .. } => None,
        }
    }

    /// The peer key, for a keyed peer.
    pub fn key(&self) -> Option<&PeerKey> {
        match self {
            PeerAddr::Socket(_) => None,
            PeerAddr::Keyed { key, .. } => Some(key),
        }
    }
}

/// Renders the socket variant exactly like `SocketAddr` (audit `peer_addr`
/// strings and log fields depend on it). The keyed variant renders
/// `iroh:<fingerprint>` whatever its path (`docs/CLI.md` §6.22: the path is
/// a separate additive audit field, not part of this string).
impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddr::Socket(addr) => addr.fmt(f),
            PeerAddr::Keyed { key, .. } => write!(f, "iroh:{}", key.fingerprint()),
        }
    }
}

impl From<SocketAddr> for PeerAddr {
    fn from(addr: SocketAddr) -> Self {
        PeerAddr::Socket(addr)
    }
}

/// Parses a socket address (the only form callers can write down today).
impl std::str::FromStr for PeerAddr {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<SocketAddr>().map(PeerAddr::Socket)
    }
}

impl PartialEq<SocketAddr> for PeerAddr {
    fn eq(&self, other: &SocketAddr) -> bool {
        matches!(self, PeerAddr::Socket(a) if a == other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_variant_renders_like_the_socket_address() {
        for s in ["192.0.2.7:4433", "[2001:db8::1]:9", "[::ffff:192.0.2.1]:1"] {
            let sa: SocketAddr = s.parse().unwrap();
            assert_eq!(PeerAddr::from(sa).to_string(), sa.to_string());
        }
    }

    #[test]
    fn socket_addr_accessor_by_variant() {
        let sa: SocketAddr = "192.0.2.7:4433".parse().unwrap();
        let key = PeerKey([7; PEER_KEY_LEN]);
        assert_eq!(PeerAddr::Socket(sa).socket_addr(), Some(sa));
        let direct = PeerAddr::Keyed {
            key,
            path: PeerPath::Direct(sa),
        };
        assert_eq!(direct.socket_addr(), Some(sa));
        let relay = PeerAddr::Keyed {
            key,
            path: PeerPath::Relay("https://relay.example".into()),
        };
        assert_eq!(relay.socket_addr(), None);
        assert_eq!(relay.key(), Some(&key));
    }

    #[test]
    fn keyed_variant_renders_as_iroh_fingerprint_on_every_path() {
        let sa: SocketAddr = "192.0.2.7:4433".parse().unwrap();
        let key = PeerKey([7; PEER_KEY_LEN]);
        let want = format!("iroh:{}", fingerprint_of_ed25519_key(&key.0));
        assert!(want.starts_with("iroh:sha256:"));
        for path in [
            PeerPath::Direct(sa),
            PeerPath::Relay("https://relay.example".into()),
        ] {
            assert_eq!(PeerAddr::Keyed { key, path }.to_string(), want);
        }
    }
}
