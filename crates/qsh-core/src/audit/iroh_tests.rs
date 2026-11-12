//! ADR-0061 decision 6: the audit record of a keyed (iroh) peer.

use super::*;
use qsh_transport::{PEER_KEY_LEN, PeerAddr, PeerKey, PeerPath, Principal};

fn key() -> PeerKey {
    PeerKey([9; PEER_KEY_LEN])
}

fn record_for(peer: &PeerAddr) -> AuditRecord {
    AuditRecord::now(
        3,
        &Principal::Device("laptop".into()),
        AuthPath::Pin,
        Action::ExecRun,
        "exec",
        Decision::Allow,
        None,
        peer,
    )
}

/// A socket peer's record has neither new key: the line is what it was
/// before iroh existed.
#[test]
fn a_socket_peer_record_carries_no_path_keys() {
    let record = record_for(&"192.0.2.7:4433".parse().unwrap());
    assert_eq!(record.peer_path, None);
    assert_eq!(record.relay, None);
    let value = serde_json::to_value(&record).unwrap();
    assert!(value.get("peer_path").is_none(), "{value}");
    assert!(value.get("relay").is_none(), "{value}");
    assert_eq!(value["peer_addr"], "192.0.2.7:4433");
}

/// A relay peer shows `iroh:<fingerprint>`, `peer_path = "relay"` and the
/// relay's scheme and host; a direct one only `peer_path = "direct"`.
#[test]
fn a_keyed_peer_record_names_its_path_and_relay() {
    let relay = PeerAddr::Keyed {
        key: key(),
        path: PeerPath::Relay("https://relay.example.test:4443/relay?token=secret".into()),
    };
    let record = record_for(&relay);
    assert_eq!(record.peer_addr, format!("iroh:{}", key().fingerprint()));
    assert_eq!(record.peer_path.as_deref(), Some("relay"));
    // Scheme, host and port only: nothing that follows the authority.
    assert_eq!(
        record.relay.as_deref(),
        Some("https://relay.example.test:4443")
    );
    let line = serde_json::to_string(&record).unwrap();
    assert!(!line.contains("token"), "{line}");

    let direct = PeerAddr::Keyed {
        key: key(),
        path: PeerPath::Direct("192.0.2.9:51000".parse().unwrap()),
    };
    let record = record_for(&direct);
    assert_eq!(record.peer_addr, format!("iroh:{}", key().fingerprint()));
    assert_eq!(record.peer_path.as_deref(), Some("direct"));
    assert_eq!(record.relay, None);
}

#[test]
fn the_relay_field_drops_credentials_and_unparseable_urls() {
    assert_eq!(
        relay_scheme_host("https://user:pw@relay.example.test./x").as_deref(),
        Some("https://relay.example.test")
    );
    assert_eq!(relay_scheme_host("not a url"), None);
    assert_eq!(relay_scheme_host("https:///path"), None);
    // The empty URL a closing connection reports.
    assert_eq!(relay_scheme_host(""), None);
}

/// Every record constructor that takes a peer carries the path keys of a
/// keyed one, and the ones that take none leave them out.
#[test]
fn every_peer_taking_constructor_carries_the_path_keys() {
    let peer = PeerAddr::Keyed {
        key: key(),
        path: PeerPath::Relay("https://relay.example.test".into()),
    };
    let records = [
        AuditRecord::handshake_rejected(&peer, "untrusted"),
        AuditRecord::pairing(&peer, Decision::Deny, "no-match"),
        AuditRecord::connection_withdrawn(
            &Principal::Device("laptop".into()),
            AuthPath::Pin,
            &peer,
            "trust_withdrawn",
        ),
    ];
    for record in records {
        assert_eq!(record.peer_path.as_deref(), Some("relay"), "{record:?}");
        assert_eq!(
            record.relay.as_deref(),
            Some("https://relay.example.test"),
            "{record:?}"
        );
    }
    let summary = AuditRecord::handshake_rejected_summary("at_capacity", 4);
    assert_eq!(summary.peer_path, None);
    assert_eq!(summary.relay, None);
}
