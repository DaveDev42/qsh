//! A fake ssh-agent for the agent-forwarding tests (ADR-0055 decision 23).
//!
//! [`FakeAgent`] listens on a Unix socket in a private temporary directory
//! (on Windows, on a named pipe) and speaks just enough of the ssh-agent
//! protocol to stand in for the local agent behind the client:
//!
//! - `REQUEST_IDENTITIES` (11) is answered with `IDENTITIES_ANSWER` (12)
//!   listing the configured identities.
//! - `SIGN_REQUEST` (13) for a listed key is answered with `SIGN_RESPONSE`
//!   (14) carrying [`fake_signature`], a deterministic blob that is not a
//!   real signature. An unlisted key or a malformed request gets `FAILURE`.
//! - Every other type gets `FAILURE` (5).
//!
//! Every message type the agent receives is recorded in arrival order, so a
//! test can assert that a request the client should have filtered (add,
//! remove, lock, an extension) never reached it. There is no cryptography
//! here.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use qsh_proto::agent::{
    AgentDecoder, FAILURE_REPLY, SSH2_AGENT_IDENTITIES_ANSWER, SSH2_AGENT_SIGN_RESPONSE,
    SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST, encode_message,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::{JoinHandle, JoinSet};

/// The client end of a connection to a [`FakeAgent`].
#[cfg(unix)]
pub type AgentClientStream = tokio::net::UnixStream;
/// The client end of a connection to a [`FakeAgent`].
#[cfg(windows)]
pub type AgentClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// The algorithm name inside every fake signature.
pub const FAKE_SIGNATURE_ALGORITHM: &str = "ssh-ed25519";

/// One key the fake agent lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeIdentity {
    /// The public key blob, opaque to the fake.
    pub blob: Vec<u8>,
    /// The comment shown by `ssh-add -l`.
    pub comment: String,
}

impl FakeIdentity {
    /// An identity with the given blob and comment.
    pub fn new(blob: impl Into<Vec<u8>>, comment: impl Into<String>) -> Self {
        Self {
            blob: blob.into(),
            comment: comment.into(),
        }
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_string<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(*buf.first_chunk::<4>()?) as usize;
    let rest = &buf[4..];
    let s = rest.get(..len)?;
    *buf = &rest[len..];
    Some(s)
}

/// The signature blob the fake returns for `data` signed with the key
/// `key_blob`: `string("ssh-ed25519") string(64 bytes)`, the 64 bytes being
/// two chained SHA-256 digests of the key blob and the data. Deterministic,
/// so a test computes the expected answer itself.
pub fn fake_signature(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let first = Sha256::new()
        .chain_update(key_blob)
        .chain_update(data)
        .finalize();
    let second = Sha256::new().chain_update(first).finalize();
    let mut raw = Vec::with_capacity(64);
    raw.extend_from_slice(&first);
    raw.extend_from_slice(&second);
    let mut sig = Vec::new();
    put_string(&mut sig, FAKE_SIGNATURE_ALGORITHM.as_bytes());
    put_string(&mut sig, &raw);
    sig
}

/// The complete `IDENTITIES_ANSWER` message for `identities`.
pub fn identities_answer(identities: &[FakeIdentity]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u32::try_from(identities.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for id in identities {
        put_string(&mut body, &id.blob);
        put_string(&mut body, id.comment.as_bytes());
    }
    encode_message(SSH2_AGENT_IDENTITIES_ANSWER, &body).unwrap_or_else(|| FAILURE_REPLY.to_vec())
}

/// The complete `SIGN_RESPONSE` message for `key_blob` over `data`.
pub fn sign_response(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put_string(&mut body, &fake_signature(key_blob, data));
    encode_message(SSH2_AGENT_SIGN_RESPONSE, &body).unwrap_or_else(|| FAILURE_REPLY.to_vec())
}

/// A request body of `SIGN_REQUEST`: `string key_blob, string data, u32 flags`.
pub fn sign_request_body(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut body = Vec::new();
    put_string(&mut body, key_blob);
    put_string(&mut body, data);
    body.extend_from_slice(&flags.to_be_bytes());
    body
}

#[derive(Default)]
struct Record {
    kinds: Mutex<Vec<u8>>,
    connections: AtomicUsize,
}

fn answer(identities: &[FakeIdentity], kind: u8, message: &[u8]) -> Vec<u8> {
    match kind {
        SSH2_AGENTC_REQUEST_IDENTITIES => identities_answer(identities),
        SSH2_AGENTC_SIGN_REQUEST => {
            // length(4) + type(1) + body
            let mut body = message.get(5..).unwrap_or(&[]);
            let (Some(blob), Some(data)) = (take_string(&mut body), take_string(&mut body)) else {
                return FAILURE_REPLY.to_vec();
            };
            if identities.iter().any(|i| i.blob == blob) {
                sign_response(blob, data)
            } else {
                FAILURE_REPLY.to_vec()
            }
        }
        _ => FAILURE_REPLY.to_vec(),
    }
}

async fn serve_connection<S>(mut stream: S, identities: Arc<Vec<FakeIdentity>>, record: Arc<Record>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    record.connections.fetch_add(1, Ordering::SeqCst);
    let mut decoder = AgentDecoder::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        decoder.push(&buf[..n]);
        loop {
            match decoder.next_message() {
                Ok(Some(m)) => {
                    if let Ok(mut kinds) = record.kinds.lock() {
                        kinds.push(m.kind);
                    }
                    let reply = answer(&identities, m.kind, &m.bytes);
                    if stream.write_all(&reply).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                // A malformed stream: hang up like a real agent.
                Err(_) => return,
            }
        }
    }
}

/// Open a connection to an agent endpoint: a Unix socket path, or on Windows
/// a named pipe name. Works for the host's own socket as well as a
/// [`FakeAgent`].
#[cfg(unix)]
pub async fn connect_endpoint(endpoint: &str) -> io::Result<AgentClientStream> {
    tokio::net::UnixStream::connect(endpoint).await
}

/// Open a connection to an agent endpoint: a Unix socket path, or on Windows
/// a named pipe name.
///
/// A pipe server creates the next instance only after a client has connected
/// to the current one, so a second client that arrives in between sees
/// `ERROR_PIPE_BUSY`. Retry briefly, as the tokio named-pipe client example
/// does.
#[cfg(windows)]
pub async fn connect_endpoint(endpoint: &str) -> io::Result<AgentClientStream> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint) {
            Err(err)
                if err.raw_os_error() == Some(ERROR_PIPE_BUSY)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            other => return other,
        }
    }
}

/// A fake ssh-agent listening on a Unix socket (Windows: a named pipe).
/// Dropping it stops the listener and every connection.
pub struct FakeAgent {
    endpoint: String,
    record: Arc<Record>,
    task: JoinHandle<()>,
    #[cfg(unix)]
    _dir: tempfile::TempDir,
}

impl FakeAgent {
    /// Start an agent that lists `identities`.
    #[cfg(unix)]
    pub async fn start(identities: Vec<FakeIdentity>) -> io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("qsh-fake-agent")
            .tempdir()?;
        let path: std::path::PathBuf = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path)?;
        let record = Arc::new(Record::default());
        let ids = Arc::new(identities);
        let rec = Arc::clone(&record);
        let task = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                conns.spawn(serve_connection(stream, Arc::clone(&ids), Arc::clone(&rec)));
            }
        });
        Ok(Self {
            endpoint: path.to_string_lossy().into_owned(),
            record,
            task,
            _dir: dir,
        })
    }

    /// Start an agent that lists `identities`.
    #[cfg(windows)]
    pub async fn start(identities: Vec<FakeIdentity>) -> io::Result<Self> {
        use tokio::net::windows::named_pipe::ServerOptions;

        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            r"\\.\pipe\qsh-fake-agent-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)?;
        let record = Arc::new(Record::default());
        let ids = Arc::new(identities);
        let rec = Arc::clone(&record);
        let pipe_name = name.clone();
        let task = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            loop {
                if server.connect().await.is_err() {
                    return;
                }
                let Ok(next) = ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&pipe_name)
                else {
                    return;
                };
                let conn = std::mem::replace(&mut server, next);
                conns.spawn(serve_connection(conn, Arc::clone(&ids), Arc::clone(&rec)));
            }
        });
        Ok(Self {
            endpoint: name,
            record,
            task,
        })
    }

    /// The value for `SSH_AUTH_SOCK`: the socket path, or the pipe name.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Open a new connection to the agent.
    pub async fn connect(&self) -> io::Result<AgentClientStream> {
        connect_endpoint(&self.endpoint).await
    }

    /// Every message type received so far, in arrival order, across all
    /// connections.
    pub fn received_kinds(&self) -> Vec<u8> {
        self.record
            .kinds
            .lock()
            .map(|k| k.clone())
            .unwrap_or_default()
    }

    /// How many connections have been accepted.
    pub fn connections(&self) -> usize {
        self.record.connections.load(Ordering::SeqCst)
    }
}

impl Drop for FakeAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_proto::agent::SSH_AGENT_FAILURE;

    fn ids() -> Vec<FakeIdentity> {
        vec![
            FakeIdentity::new(b"key-blob-one".to_vec(), "one@test"),
            FakeIdentity::new(b"key-blob-two".to_vec(), "two@test"),
        ]
    }

    /// Send one message and read one whole reply.
    async fn roundtrip(conn: &mut AgentClientStream, request: &[u8]) -> (u8, Vec<u8>) {
        conn.write_all(request).await.unwrap();
        let mut decoder = AgentDecoder::new();
        let mut buf = [0u8; 1024];
        loop {
            if let Some(m) = decoder.next_message().unwrap() {
                return (m.kind, m.bytes);
            }
            let n = conn.read(&mut buf).await.unwrap();
            assert!(n > 0, "agent closed the connection");
            decoder.push(&buf[..n]);
        }
    }

    #[tokio::test]
    async fn it_lists_the_configured_identities() {
        let agent = FakeAgent::start(ids()).await.unwrap();
        let mut conn = agent.connect().await.unwrap();
        let req = encode_message(SSH2_AGENTC_REQUEST_IDENTITIES, &[]).unwrap();
        let (kind, bytes) = roundtrip(&mut conn, &req).await;
        assert_eq!(kind, SSH2_AGENT_IDENTITIES_ANSWER);
        assert_eq!(bytes, identities_answer(&ids()));
        // count field = 2
        assert_eq!(&bytes[5..9], &[0, 0, 0, 2]);
        assert_eq!(agent.received_kinds(), vec![11]);
    }

    #[tokio::test]
    async fn it_signs_with_a_deterministic_blob_for_a_listed_key() {
        let agent = FakeAgent::start(ids()).await.unwrap();
        let mut conn = agent.connect().await.unwrap();
        let req = encode_message(
            SSH2_AGENTC_SIGN_REQUEST,
            &sign_request_body(b"key-blob-two", b"hello", 0),
        )
        .unwrap();
        let (kind, bytes) = roundtrip(&mut conn, &req).await;
        assert_eq!(kind, SSH2_AGENT_SIGN_RESPONSE);
        assert_eq!(bytes, sign_response(b"key-blob-two", b"hello"));
        let (_, again) = roundtrip(&mut conn, &req).await;
        assert_eq!(again, bytes);
        // A different key or different data signs differently.
        assert_ne!(
            fake_signature(b"key-blob-one", b"hello"),
            fake_signature(b"key-blob-two", b"hello")
        );
        assert_ne!(
            fake_signature(b"key-blob-two", b"other"),
            fake_signature(b"key-blob-two", b"hello")
        );
    }

    #[tokio::test]
    async fn it_fails_an_unlisted_key_and_a_malformed_sign_request() {
        let agent = FakeAgent::start(ids()).await.unwrap();
        let mut conn = agent.connect().await.unwrap();
        let unlisted = encode_message(
            SSH2_AGENTC_SIGN_REQUEST,
            &sign_request_body(b"nope", b"x", 0),
        )
        .unwrap();
        assert_eq!(roundtrip(&mut conn, &unlisted).await.0, SSH_AGENT_FAILURE);
        let malformed = encode_message(SSH2_AGENTC_SIGN_REQUEST, &[0, 0, 0, 9, 1]).unwrap();
        assert_eq!(roundtrip(&mut conn, &malformed).await.0, SSH_AGENT_FAILURE);
    }

    #[tokio::test]
    async fn it_answers_everything_else_with_failure_and_records_it() {
        let agent = FakeAgent::start(ids()).await.unwrap();
        let mut conn = agent.connect().await.unwrap();
        for kind in [17u8, 18, 19, 22, 23, 25, 27, 99] {
            let req = encode_message(kind, b"payload").unwrap();
            let (reply, bytes) = roundtrip(&mut conn, &req).await;
            assert_eq!(reply, SSH_AGENT_FAILURE, "type {kind}");
            assert_eq!(bytes, FAILURE_REPLY);
        }
        assert_eq!(agent.received_kinds(), vec![17, 18, 19, 22, 23, 25, 27, 99]);
    }

    #[tokio::test]
    async fn it_records_across_connections_and_counts_them() {
        let agent = FakeAgent::start(ids()).await.unwrap();
        let req = encode_message(SSH2_AGENTC_REQUEST_IDENTITIES, &[]).unwrap();
        let mut a = agent.connect().await.unwrap();
        let mut b = agent.connect().await.unwrap();
        roundtrip(&mut a, &req).await;
        roundtrip(&mut b, &encode_message(22, &[]).unwrap()).await;
        assert_eq!(agent.received_kinds(), vec![11, 22]);
        assert_eq!(agent.connections(), 2);
    }

    #[tokio::test]
    async fn it_hangs_up_on_an_oversized_frame() {
        let agent = FakeAgent::start(ids()).await.unwrap();
        let mut conn = agent.connect().await.unwrap();
        conn.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(conn.read(&mut buf).await.unwrap_or(0), 0);
        assert!(agent.received_kinds().is_empty());
    }

    #[tokio::test]
    async fn the_unix_socket_is_gone_after_drop() {
        let agent = FakeAgent::start(ids()).await.unwrap();
        let endpoint = agent.endpoint().to_owned();
        drop(agent);
        #[cfg(unix)]
        assert!(!std::path::Path::new(&endpoint).exists());
        #[cfg(windows)]
        let _ = endpoint;
    }
}
