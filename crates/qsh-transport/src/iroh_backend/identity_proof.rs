//! The in-band proof of a client's qsh identity on an iroh connection
//! (`docs/design/protocol.md` §22.8).
//!
//! A client endpoint is bound with a fresh random iroh key, so two client
//! processes of one machine never share an `EndpointId` (a relay keeps one
//! home connection per id and drops the older one). The qsh identity the
//! server pins therefore cannot be read off the handshake. The client proves
//! it instead: right after the handshake, before any other stream, it sends
//! one unidirectional stream with the frame below, and the server binds the
//! connection's peer identity to the proven key.
//!
//! ```text
//! frame     = version(1) || identity_public_key(32) || signature(64)   97 bytes
//! signature = Ed25519(identity_key,
//!                     DOMAIN || exporter(32) || server_endpoint_id(32) || client_endpoint_id(32))
//! exporter  = TLS exporter of this iroh connection, label EXPORTER_LABEL, empty context
//! ```
//!
//! The exporter ties the signature to this one connection (a frame copied to
//! another connection verifies against another exporter), and the two
//! endpoint ids tie it to this pair. The frame is fixed-size, so the reader
//! never holds more than [`FRAME_LEN`] bytes.

use std::time::Duration;

use iroh::endpoint as ie;
use iroh::{EndpointId, PublicKey, SecretKey};

/// Domain separation for the signed message.
pub(crate) const DOMAIN: &[u8] = b"qsh iroh client identity v1";

/// The TLS exporter label (RFC 5705) the signature is bound to.
pub(crate) const EXPORTER_LABEL: &[u8] = b"qsh iroh client identity exporter v1";

/// Bytes of exporter output signed over.
pub(crate) const EXPORTER_LEN: usize = 32;

/// The only frame version.
pub(crate) const VERSION: u8 = 1;

/// Length of a proof frame: version, public key, signature.
pub(crate) const FRAME_LEN: usize = 1 + 32 + 64;

/// How long the server waits for the proof after the handshake. Matches the
/// header timeout of `qsh-core` (`server::HEADER_TIMEOUT`), the bound every
/// other first message of a connection has.
pub(crate) const PROOF_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a proof was not accepted.
#[derive(Debug)]
pub(crate) enum ProofError {
    /// The connection ended before the proof arrived.
    Lost(ie::ConnectionError),
    /// The frame is missing, malformed, over-long or its signature does not
    /// verify for this connection.
    Invalid(&'static str),
}

fn exporter(conn: &ie::Connection) -> Result<[u8; EXPORTER_LEN], ProofError> {
    let mut out = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, &[])
        .map_err(|_| ProofError::Invalid("tls exporter unavailable"))?;
    Ok(out)
}

fn signed_message(
    exporter: &[u8; EXPORTER_LEN],
    server: &EndpointId,
    client: &EndpointId,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + EXPORTER_LEN + 64);
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(exporter);
    msg.extend_from_slice(server.as_bytes());
    msg.extend_from_slice(client.as_bytes());
    msg
}

fn encode(
    identity: &SecretKey,
    exporter: &[u8; EXPORTER_LEN],
    server: &EndpointId,
    client: &EndpointId,
) -> [u8; FRAME_LEN] {
    let signature = identity.sign(&signed_message(exporter, server, client));
    let mut frame = [0u8; FRAME_LEN];
    frame[0] = VERSION;
    frame[1..33].copy_from_slice(identity.public().as_bytes());
    frame[33..].copy_from_slice(&signature.to_bytes());
    frame
}

/// Check `frame` against this connection's exporter and endpoint ids, and
/// return the identity key it proves.
fn verify(
    frame: &[u8],
    exporter: &[u8; EXPORTER_LEN],
    server: &EndpointId,
    client: &EndpointId,
) -> Result<[u8; 32], ProofError> {
    let frame: &[u8; FRAME_LEN] = frame
        .try_into()
        .map_err(|_| ProofError::Invalid("proof frame has the wrong length"))?;
    if frame[0] != VERSION {
        return Err(ProofError::Invalid("unknown proof version"));
    }
    let key_bytes: [u8; 32] = frame[1..33].try_into().expect("32 bytes");
    let key = PublicKey::from_bytes(&key_bytes)
        .map_err(|_| ProofError::Invalid("proof key is not an Ed25519 key"))?;
    let sig_bytes: [u8; 64] = frame[33..].try_into().expect("64 bytes");
    let signature = iroh::Signature::from_bytes(&sig_bytes);
    key.verify(&signed_message(exporter, server, client), &signature)
        .map_err(|_| ProofError::Invalid("proof signature does not verify"))?;
    Ok(key_bytes)
}

/// Client side: send the proof for `conn` (dialed from the endpoint
/// `local`), signed by `identity`. One unidirectional stream, written and
/// finished; the client does not wait for an answer, a refusal arrives as a
/// close of the connection.
pub(crate) async fn send(
    conn: &ie::Connection,
    identity: &SecretKey,
    local: &EndpointId,
) -> Result<(), ProofError> {
    let frame = encode(identity, &exporter(conn)?, &conn.remote_id(), local);
    let mut stream = conn.open_uni().await.map_err(ProofError::Lost)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|_| ProofError::Invalid("proof stream was reset"))?;
    stream
        .finish()
        .map_err(|_| ProofError::Invalid("proof stream was closed"))?;
    Ok(())
}

/// Server side: read the proof from `conn` (accepted on the endpoint
/// `local`) and return the identity key it proves. The caller bounds the
/// wait with [`PROOF_TIMEOUT`].
pub(crate) async fn receive(
    conn: &ie::Connection,
    local: &EndpointId,
) -> Result<[u8; 32], ProofError> {
    let mut stream = conn.accept_uni().await.map_err(ProofError::Lost)?;
    let frame = stream.read_to_end(FRAME_LEN).await.map_err(|e| match e {
        ie::ReadToEndError::TooLong => ProofError::Invalid("proof frame is too long"),
        ie::ReadToEndError::Read(ie::ReadError::ConnectionLost(lost)) => ProofError::Lost(lost),
        ie::ReadToEndError::Read(_) => ProofError::Invalid("proof stream was reset"),
    })?;
    verify(&frame, &exporter(conn)?, local, &conn.remote_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (EndpointId, EndpointId) {
        (
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        )
    }

    #[test]
    fn a_frame_verifies_for_the_connection_it_was_made_for() {
        let identity = SecretKey::generate();
        let (server, client) = ids();
        let ex = [7u8; EXPORTER_LEN];
        let frame = encode(&identity, &ex, &server, &client);
        assert_eq!(
            verify(&frame, &ex, &server, &client).unwrap(),
            *identity.public().as_bytes()
        );
    }

    #[test]
    fn another_exporter_or_pair_or_length_is_refused() {
        let identity = SecretKey::generate();
        let (server, client) = ids();
        let ex = [7u8; EXPORTER_LEN];
        let frame = encode(&identity, &ex, &server, &client);
        let other_ex = [8u8; EXPORTER_LEN];
        assert!(verify(&frame, &other_ex, &server, &client).is_err());
        let (other_server, other_client) = ids();
        assert!(verify(&frame, &ex, &other_server, &client).is_err());
        assert!(verify(&frame, &ex, &server, &other_client).is_err());
        assert!(verify(&frame[..FRAME_LEN - 1], &ex, &server, &client).is_err());
        let mut long = frame.to_vec();
        long.push(0);
        assert!(verify(&long, &ex, &server, &client).is_err());
        let mut bad_version = frame;
        bad_version[0] = 2;
        assert!(verify(&bad_version, &ex, &server, &client).is_err());
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let identity = SecretKey::generate();
        let forger = SecretKey::generate();
        let (server, client) = ids();
        let ex = [7u8; EXPORTER_LEN];
        let mut frame = encode(&forger, &ex, &server, &client);
        // The forger claims the identity's key but signs with its own.
        frame[1..33].copy_from_slice(identity.public().as_bytes());
        assert!(verify(&frame, &ex, &server, &client).is_err());
    }
}
