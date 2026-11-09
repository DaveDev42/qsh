//! L3 loopback for the client half of agent forwarding (ADR-0055 decisions
//! 10, 12, 13 and 14): a test "host" opens `AGENT` streams on a real client
//! connection, and the client's dispatcher bridges them to a `FakeAgent`.
//!
//! The host side here is a few lines of test code. The end-to-end tests that
//! need the real host (`agent_forward_loopback_lists_and_signs`,
//! `agent_forward_over_a_punched_connection`) belong to the host-side step.

use std::sync::Arc;
use std::time::Duration;

use qsh_core::agent::{AgentEndpoint, ClientAgent};
use qsh_core::tunnel::RemoteForwardAcceptor;
use qsh_proto::agent::{
    AGENT_MESSAGE_MAX, FAILURE_REPLY, SSH2_AGENT_IDENTITIES_ANSWER, SSH2_AGENT_SIGN_RESPONSE,
    SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST, encode_message,
};
use qsh_proto::wire::{StreamHeader, StreamKind};
use qsh_testkit::chaos::ChaosPolicy;
use qsh_testkit::fake_agent::{
    FakeAgent, FakeIdentity, identities_answer, sign_request_body, sign_response,
};
use qsh_testkit::loopback::LoopbackHarness;
use qsh_transport::{Connection, Dialed, FramedSend, RecvStream, SendStream};

const WAIT: Duration = Duration::from_secs(5);

/// The key the fake agent lists.
fn key() -> FakeIdentity {
    FakeIdentity::new(b"test-key-blob".to_vec(), "test key")
}

/// A client connection with its dispatcher running and the host-side peer of
/// the same connection.
struct Rig {
    agent: Arc<ClientAgent>,
    host: Connection,
    _acceptor: RemoteForwardAcceptor,
    _harness: LoopbackHarness,
    _dialed: Dialed,
}

async fn rig(endpoint: Option<&str>) -> Rig {
    let harness = LoopbackHarness::start_chaotic(ChaosPolicy::seeded(0xA6E27)).await;
    let dialed = harness.dial().await;
    let agent = ClientAgent::new(AgentEndpoint::resolve(endpoint, &|_| None));
    let acceptor = RemoteForwardAcceptor::spawn_with_agent(
        dialed.connection.clone(),
        Some(agent.dispatcher()),
    )
    .await;
    let host = tokio::time::timeout(WAIT, async {
        loop {
            if let Some(conn) = harness.server_connections().last() {
                return conn.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the host side of the connection");
    Rig {
        agent,
        host,
        _acceptor: acceptor,
        _harness: harness,
        _dialed: dialed,
    }
}

/// What a host does: open a bidi stream and announce an `AGENT` stream for
/// `channel`. The raw halves come back for the agent bytes.
async fn open_agent_stream(host: &Connection, channel: &[u8]) -> (SendStream, RecvStream) {
    let (send, recv) = host.open_bi().await.expect("open_bi");
    let mut framed = FramedSend::data(send);
    framed
        .send(&StreamHeader {
            kind: StreamKind::Agent as i32,
            ticket: channel.to_vec(),
            ..Default::default()
        })
        .await
        .expect("stream header");
    (framed.into_raw(), recv)
}

/// Read one whole agent message, or `None` when the stream ended or was
/// reset first.
async fn read_message(recv: &mut RecvStream) -> Option<Vec<u8>> {
    tokio::time::timeout(WAIT, async {
        let mut head = [0u8; 4];
        recv.read_exact(&mut head).await.ok()?;
        let len = u32::from_be_bytes(head) as usize;
        let mut body = vec![0u8; len];
        recv.read_exact(&mut body).await.ok()?;
        let mut all = head.to_vec();
        all.extend_from_slice(&body);
        Some(all)
    })
    .await
    .expect("an answer or a close within the deadline")
}

/// One request, one answer.
async fn exchange(send: &mut SendStream, recv: &mut RecvStream, request: &[u8]) -> Option<Vec<u8>> {
    send.write_all(request).await.ok()?;
    read_message(recv).await
}

fn list_request() -> Vec<u8> {
    encode_message(SSH2_AGENTC_REQUEST_IDENTITIES, &[]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registered_channel_lists_and_signs_through_the_local_agent() {
    let fake = FakeAgent::start(vec![key()]).await.unwrap();
    let rig = rig(Some(fake.endpoint())).await;
    let channel = rig.agent.register();
    let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;

    let listed = exchange(&mut send, &mut recv, &list_request()).await;
    assert_eq!(listed, Some(identities_answer(&[key()])));
    assert_eq!(
        listed.as_ref().map(|m| m[4]),
        Some(SSH2_AGENT_IDENTITIES_ANSWER)
    );

    let body = sign_request_body(&key().blob, b"challenge", 0);
    let request = encode_message(SSH2_AGENTC_SIGN_REQUEST, &body).unwrap();
    let signed = exchange(&mut send, &mut recv, &request).await;
    assert_eq!(signed, Some(sign_response(&key().blob, b"challenge")));
    assert_eq!(
        signed.as_ref().map(|m| m[4]),
        Some(SSH2_AGENT_SIGN_RESPONSE)
    );

    assert_eq!(
        fake.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST]
    );
    assert_eq!(fake.connections(), 1, "one local connection per stream");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disallowed_request_is_answered_by_the_client_and_never_reaches_the_agent() {
    let fake = FakeAgent::start(vec![key()]).await.unwrap();
    let rig = rig(Some(fake.endpoint())).await;
    let channel = rig.agent.register();
    let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;

    // 17 is ADD_IDENTITY, 18 REMOVE_IDENTITY, 25 ADD_ID_CONSTRAINED, 27
    // EXTENSION: none is on the allow list.
    for kind in [17u8, 18, 25, 27, 99] {
        let request = encode_message(kind, b"secret-looking-bytes").unwrap();
        let answer = exchange(&mut send, &mut recv, &request).await;
        assert_eq!(answer.as_deref(), Some(&FAILURE_REPLY[..]), "kind {kind}");
    }
    // The stream is still usable afterwards.
    assert_eq!(
        exchange(&mut send, &mut recv, &list_request()).await,
        Some(identities_answer(&[key()]))
    );
    assert_eq!(
        fake.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES],
        "only the allowed request reached the agent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unregistered_agent_channel_never_reaches_the_local_agent() {
    let fake = FakeAgent::start(vec![key()]).await.unwrap();
    let rig = rig(Some(fake.endpoint())).await;
    let _registered = rig.agent.register();

    for channel in [vec![0x5a; 16], vec![], vec![0x5a; 15]] {
        let (mut send, mut recv) = open_agent_stream(&rig.host, &channel).await;
        assert_eq!(exchange(&mut send, &mut recv, &list_request()).await, None);
    }
    assert_eq!(fake.connections(), 0, "no local connection was opened");
    assert!(fake.received_kinds().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_released_channel_is_unregistered_again() {
    let fake = FakeAgent::start(vec![key()]).await.unwrap();
    let rig = rig(Some(fake.endpoint())).await;
    let channel = rig.agent.register();
    let bytes = channel.bytes();
    drop(channel);

    let (mut send, mut recv) = open_agent_stream(&rig.host, &bytes).await;
    assert_eq!(exchange(&mut send, &mut recv, &list_request()).await, None);
    assert_eq!(fake.connections(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_agent_frame_resets_the_stream() {
    let fake = FakeAgent::start(vec![key()]).await.unwrap();
    let rig = rig(Some(fake.endpoint())).await;
    let channel = rig.agent.register();

    // A length prefix one past the cap, then a zero-length frame, each on its
    // own stream: both are framing violations, not agent requests.
    let too_big = u32::try_from(AGENT_MESSAGE_MAX + 1).unwrap().to_be_bytes();
    for prefix in [too_big, [0, 0, 0, 0]] {
        let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;
        assert_eq!(exchange(&mut send, &mut recv, &prefix).await, None);
    }
    assert!(
        fake.received_kinds().is_empty(),
        "nothing reached the agent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_bounds() {
    // 64 streams per connection (ADR-0055 decision 10): the 65th is reset.
    const PER_CONNECTION: usize = 64;
    let fake = FakeAgent::start(vec![key()]).await.unwrap();
    let rig = rig(Some(fake.endpoint())).await;
    let channel = rig.agent.register();

    let mut held = Vec::new();
    for _ in 0..PER_CONNECTION {
        let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;
        assert!(
            exchange(&mut send, &mut recv, &list_request())
                .await
                .is_some(),
            "a stream within the bound is served"
        );
        held.push((send, recv));
    }
    assert_eq!(fake.connections(), PER_CONNECTION);

    let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;
    assert_eq!(exchange(&mut send, &mut recv, &list_request()).await, None);
    assert_eq!(
        fake.connections(),
        PER_CONNECTION,
        "the 65th never connected"
    );

    // Closing one frees its slot.
    let (mut send, recv) = held.pop().unwrap();
    send.finish().unwrap();
    drop(recv);
    tokio::time::timeout(WAIT, async {
        loop {
            let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;
            if exchange(&mut send, &mut recv, &list_request())
                .await
                .is_some()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a freed slot is reusable");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_local_agent_the_host_sees_the_stream_close() {
    let rig = rig(Some("/nonexistent/qsh-test/agent.sock")).await;
    let channel = rig.agent.register();
    let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;
    assert_eq!(exchange(&mut send, &mut recv, &list_request()).await, None);
}

/// ADR-0055 DoD 23.9: on Windows the discovery takes a `SSH_AUTH_SOCK`-style
/// named pipe path, refuses anything that is not a pipe, and the dispatcher
/// then reaches a fake agent listening on that pipe.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_client_reaches_an_agent_on_a_named_pipe() {
    let fake = FakeAgent::start(vec![key()]).await.unwrap();
    let pipe = fake.endpoint().to_string();
    assert!(pipe.starts_with(r"\\.\pipe\"), "{pipe}");

    // Discovery: the same pipe whether it comes from the environment value,
    // from `-o ForwardAgent=<path>` or from `-o ForwardAgent=$VAR`.
    let from_env = |name: &str| (name == "SSH_AUTH_SOCK").then(|| pipe.clone());
    let by_env = AgentEndpoint::resolve(None, &from_env).expect("env value");
    let by_path = AgentEndpoint::resolve(Some(&pipe), &|_| None).expect("path");
    let by_var = AgentEndpoint::resolve(Some("$SSH_AUTH_SOCK"), &from_env).expect("var");
    assert_eq!(by_env, by_path);
    assert_eq!(by_path, by_var);
    assert_eq!(by_path.shown(), pipe);
    // A unix-style path cannot be connected to on Windows.
    assert!(AgentEndpoint::resolve(Some(r"C:\tmp\agent.sock"), &|_| None).is_err());
    assert!(AgentEndpoint::resolve(None, &|_| Some("/tmp/agent.sock".into())).is_err());

    // The dispatcher, given only that value, lists and signs, and a request
    // outside the allow list still stops at the client.
    let rig = rig(Some(&pipe)).await;
    let channel = rig.agent.register();
    let (mut send, mut recv) = open_agent_stream(&rig.host, &channel.bytes()).await;
    assert_eq!(
        exchange(&mut send, &mut recv, &list_request()).await,
        Some(identities_answer(&[key()]))
    );
    let body = sign_request_body(&key().blob, b"challenge", 0);
    let request = encode_message(SSH2_AGENTC_SIGN_REQUEST, &body).unwrap();
    assert_eq!(
        exchange(&mut send, &mut recv, &request).await,
        Some(sign_response(&key().blob, b"challenge"))
    );
    let remove_all = encode_message(19, &[]).unwrap();
    assert_eq!(
        exchange(&mut send, &mut recv, &remove_all).await.as_deref(),
        Some(&FAILURE_REPLY[..])
    );
    assert_eq!(
        fake.received_kinds(),
        vec![SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST]
    );
}
