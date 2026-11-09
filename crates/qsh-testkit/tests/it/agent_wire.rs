//! L3 loopback for the `agent.v1` wire (ADR-0055 decision 3): a client that
//! asks for agent forwarding reaches a host that has no agent support yet,
//! and gets `UNAVAILABLE` on a session that still opens. An old peer never
//! sees the field.

use qsh_core::client::ClientError;
use qsh_core::exec::ExecSpec;
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, AgentGrant};
use qsh_testkit::HostedPair;
use qsh_testkit::loopback::LoopbackHarness;

const CHANNEL: [u8; wire::AGENT_CHANNEL_LEN] = [0xa5; wire::AGENT_CHANNEL_LEN];

fn open_req(agent_channel: Vec<u8>) -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        agent_channel,
        ..Default::default()
    }
}

fn exec_spec() -> ExecSpec {
    ExecSpec {
        argv: vec!["true".into()],
        env: vec![],
        timeout: None,
        shell: None,
    }
}

fn is_invalid_argument(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::Remote {
            code: ErrorCode::InvalidArgument,
            ..
        }
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_agent_support_answers_unavailable_and_still_opens_the_session() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    assert!(s.agent_supported());

    // session.open
    let opened = s.session_open(open_req(CHANNEL.to_vec())).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Unavailable as i32);
    assert!(!opened.session_id.is_empty() && !opened.ticket.is_empty());
    let _pipe = h.pipes().take().expect("the session exists");

    // session.attach
    let attached = s
        .attach_request(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            mode: wire::AttachMode::Rw as i32,
            agent_channel: CHANNEL.to_vec(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(attached.agent, AgentGrant::Unavailable as i32);

    // exec.run
    let started = s
        .exec_start_with_agent(&exec_spec(), CHANNEL.to_vec())
        .await
        .unwrap();
    assert_eq!(started.agent, AgentGrant::Unavailable as i32);
    assert!(!started.ticket.is_empty());
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_request_means_no_grant() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let opened = s.session_open(open_req(Vec::new())).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Unspecified as i32);
    let _pipe = h.pipes().take().expect("the session exists");
    let started = s.exec_start(&exec_spec()).await.unwrap();
    assert_eq!(started.agent, AgentGrant::Unspecified as i32);
    s.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_channel_of_the_wrong_length_is_invalid_argument_and_creates_nothing() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let err = s.session_open(open_req(vec![1; 5])).await.unwrap_err();
    assert!(is_invalid_argument(&err), "{err:?}");
    assert!(h.pipes().take().is_none(), "no session was created");
    let err = s
        .exec_start_with_agent(&exec_spec(), vec![1; 17])
        .await
        .unwrap_err();
    assert!(is_invalid_argument(&err), "{err:?}");
    assert!(
        h.audit.records().is_empty(),
        "a shape error writes no audit"
    );
    s.close();
    h.shutdown().await;
}

/// A client never sends `agent_channel` to a peer that did not advertise
/// `agent.v1`: the field is dropped before the request leaves, so the old
/// host sees exactly today's bytes and the reply stays `UNSPECIFIED`.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_peer_never_sees_the_field() {
    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    s.capabilities.retain(|c| c != wire::CAP_AGENT_V1);
    assert!(!s.agent_supported());

    // Had the field been sent, the 5-byte channel would be INVALID_ARGUMENT.
    let opened = s.session_open(open_req(vec![1; 5])).await.unwrap();
    assert_eq!(opened.agent, AgentGrant::Unspecified as i32);
    let _pipe = h.pipes().take().expect("the session exists");
    let started = s
        .exec_start_with_agent(&exec_spec(), vec![1; 5])
        .await
        .unwrap();
    assert_eq!(started.agent, AgentGrant::Unspecified as i32);
    let attached = s
        .attach_request(wire::SessionAttach {
            session_id: opened.session_id,
            resume_token: opened.resume_token,
            mode: wire::AttachMode::Rw as i32,
            agent_channel: vec![1; 5],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(attached.agent, AgentGrant::Unspecified as i32);
    s.close();
    h.shutdown().await;
}
