//! L3 loopback end-to-end for **resume across connections** (PLAN M2
//! Step 7, `docs/design/protocol.md` §10): a session outlives the QUIC
//! connection it was opened on, and a `session.attach` carrying the resume
//! credential on a *brand new* connection continues the same byte stream.
//!
//! What is being proved here is a single property — **the stitch is
//! invisible**. A reader that concatenates what it got before the break
//! with what it gets after must hold exactly the bytes the child wrote,
//! with nothing lost at the seam and nothing repeated. Everything else in
//! this file (gap, input dedup, credential binding, hygiene) is a way that
//! property can silently fail.
//!
//! Every wait is a real round trip under a wall-clock deadline — no
//! sleep-based synchronisation.
//!
//! **Role-axis parametrization (`PLAN.md` M3 Step 3 PR 3b).** The first
//! three scenarios are generic `async fn<P: HostedPair>(h: P)`, each run
//! once against [`LoopbackHarness`] (forward) and once against
//! [`ReversePairHarness`] (reverse) with an identical body — the mechanical
//! proof that resume's `Ops` code never learns which side dialed. The last
//! three (`a_stolen_credential_is_useless_to_a_different_peer`,
//! `an_attach_without_a_credential_is_refused_by_the_host`,
//! `no_steal_conflicts_with_a_foreign_lease_and_spends_no_credential`) stay
//! forward-only — a **named exclusion**, not a silent one:
//! [`ReversePairHarness`]'s own module docs explain why a reverse target
//! structurally cannot have a *second, distinct* principal reach the same
//! host (it has exactly one peer, ever — the controller it dialed to
//! register with), which is exactly the shape these three scenarios need
//! (an "owner" and a "thief"/"other" device racing for the same session on
//! one host).

use std::sync::Arc;
use std::time::Duration;

use qsh_core::acl::AllowAllPinned;
use qsh_core::broker::PipeHandle;
use qsh_core::client::{ClientError, Session};
use qsh_proto::ErrorCode;
use qsh_proto::wire::{self, StreamHeader, session_frame};
use qsh_testkit::HostedPair;
use qsh_testkit::loopback::{LoopbackHarness, make_identity};
use qsh_testkit::reverse::ReversePairHarness;
use qsh_transport::{Dialer, FramedStream, Principal, StaticTrust};

/// Wall-clock ceiling for anything that should resolve in milliseconds.
/// A miss is a hang, which is a failure, not flake.
const DEADLINE: Duration = Duration::from_secs(20);

/// The harness' replay ring: what the ring still holds is what a resume
/// can still be given. Both [`LoopbackHarness`] and [`ReversePairHarness`]
/// build a 64 KiB ring.
const RING_BYTES: usize = 64 * 1024;

fn open_req() -> wire::SessionOpen {
    wire::SessionOpen {
        argv: vec!["sh".into()],
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        ..Default::default()
    }
}

fn attach_req(session_id: &str, token: Vec<u8>, last_output_seq: u64) -> wire::SessionAttach {
    wire::SessionAttach {
        session_id: session_id.to_string(),
        resume_token: token,
        last_output_seq,
        mode: wire::AttachMode::Rw as i32,
        no_steal: false,
    }
}

/// Open a session and redeem its `SESSION_DATA` ticket, the way the first
/// attach does. Returns the open reply, the child side of the pipe, and
/// the live data stream.
async fn open_and_attach<P: HostedPair>(
    h: &P,
    s: &mut Session,
) -> (wire::SessionOpened, PipeHandle, FramedStream) {
    let opened = s.session_open(open_req()).await.expect("session.open");
    let pipe = h.pipes().take().expect("pipe handle");
    let data = redeem(s, opened.ticket.clone()).await;
    (opened, pipe, data)
}

/// Open the `SESSION_DATA` stream for `ticket` on `s`'s connection.
async fn redeem(s: &Session, ticket: Vec<u8>) -> FramedStream {
    let (send, recv) = s.connection().open_bi().await.expect("open_bi");
    let mut data = FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::session_data(ticket))
        .await
        .expect("stream header");
    data
}

/// Send `session.attach` and return the reply, or the peer's error code.
/// The data stream is deliberately *not* opened here: the tests below want
/// to inspect the reply before anything flows.
async fn attach(
    s: &mut Session,
    req: wire::SessionAttach,
) -> Result<wire::SessionAttached, ErrorCode> {
    match tokio::time::timeout(DEADLINE, s.attach_request(req))
        .await
        .expect("the attach is answered within the deadline")
    {
        Ok(attached) => Ok(attached),
        Err(ClientError::Remote { code, .. }) => Err(code),
        Err(other) => panic!("attach failed unexpectedly: {other:?}"),
    }
}

/// A second pinned device: its own dialer, its own connection, its own
/// principal. Forward-topology-specific (module docs) — used only by the
/// three forward-only multi-principal scenarios below.
async fn other_device(
    h: &LoopbackHarness,
    identity: &qsh_testkit::loopback::TestIdentity,
) -> Session {
    let client_trust = StaticTrust::empty().with_pin(
        h.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let dialer = Dialer::new(identity.local.clone(), Arc::new(client_trust));
    let dialed = dialer
        .dial(h.addr, "127.0.0.1")
        .await
        .expect("the second device is pinned");
    Session::negotiate(dialed.connection, "desktop")
        .await
        .expect("negotiate")
}

/// Read frames until `want` output bytes have arrived. Returns the bytes
/// and the cumulative offset of the last one — the `L` a resume continues
/// from.
async fn read_output(data: &mut FramedStream, want: usize) -> (Vec<u8>, u64) {
    let mut bytes = Vec::new();
    let mut last_seq = 0;
    tokio::time::timeout(DEADLINE, async {
        while bytes.len() < want {
            let frame = data
                .recv
                .recv::<wire::SessionFrame>()
                .await
                .expect("frame")
                .expect("stream ended early");
            if let Some(session_frame::Body::Output(o)) = frame.body {
                bytes.extend_from_slice(&o.data);
                last_seq = o.sequence;
            }
        }
    })
    .await
    .expect("output arrives within the deadline");
    (bytes, last_seq)
}

/// Lowercase hex, for "these bytes appear nowhere in that text"
/// assertions. Not a contract format — just a stable rendering.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The property this whole step exists for: a session survives the death
/// of its connection, and the bytes stitched at `L` across the break are
/// byte-identical to the stream a reader that never disconnected would
/// have seen.
async fn a_resumed_attach_stitches_the_stream_exactly_at_the_last_delivered_offset<
    P: HostedPair,
>(
    h: P,
) {
    let mut first = h.session().await;
    let (opened, mut pipe, mut data) = open_and_attach(&h, &mut first).await;

    // The reference stream: what the child writes, in order, across the
    // whole test. Nothing else may appear in what the client assembles.
    let before = b"first half of the story\r\n";
    let after = b"second half, after the break\r\n";

    pipe.write_output(before).await.expect("child output");
    let (delivered, last_seq) = read_output(&mut data, before.len()).await;
    assert_eq!(delivered, before);
    assert_eq!(last_seq, before.len() as u64);

    // The connection dies. Not a `session.close` — the session is meant to
    // outlive its transport (PRD §8).
    drop(data);
    first.close();

    // Output produced while nobody is attached is retained by the ring.
    pipe.write_output(after).await.expect("child output");

    // A brand new connection: new QUIC handshake, new control stream, and
    // a credential that is the only thing tying it to the old session.
    let mut second = h.session().await;
    let attached = attach(
        &mut second,
        attach_req(&opened.session_id, opened.resume_token.clone(), last_seq),
    )
    .await
    .expect("the resume credential is accepted on a new connection");

    assert_eq!(
        attached.replay_from, last_seq,
        "replay must continue at exactly the offset the client had"
    );
    assert_eq!(
        attached.new_resume_token.len(),
        32,
        "a redemption must return its successor (protocol.md §10 Rotation)"
    );
    assert_ne!(
        attached.new_resume_token, opened.resume_token,
        "the successor must not be the token that was just spent"
    );

    let mut data = redeem(&second, attached.ticket.clone()).await;
    let (resumed, _) = read_output(&mut data, after.len()).await;

    let mut stitched = delivered.clone();
    stitched.extend_from_slice(&resumed);
    let mut reference = before.to_vec();
    reference.extend_from_slice(after);
    assert_eq!(
        stitched, reference,
        "the stitch at {last_seq} is not byte-identical to the reference stream"
    );

    // The spent token is dead the moment it is redeemed — single
    // generation, no second winner (protocol.md §10).
    let mut third = h.session().await;
    assert_eq!(
        attach(
            &mut third,
            attach_req(&opened.session_id, opened.resume_token.clone(), last_seq)
        )
        .await
        .unwrap_err(),
        ErrorCode::AuthFailed,
        "a spent resume token was accepted a second time"
    );

    // …and the successor works, so single-use is not "the session became
    // unattachable".
    let mut fourth = h.session().await;
    attach(
        &mut fourth,
        attach_req(
            &opened.session_id,
            attached.new_resume_token.clone(),
            last_seq,
        ),
    )
    .await
    .expect("the successor credential must work");

    // Nothing in the host's audit trail carries a credential. This is a
    // tripwire, not a behavioural assertion: `AuditRecord` has no payload
    // field, so today it cannot fail. It is here to fail the day someone
    // adds one — the behavioural version is
    // `record_has_only_structural_fields`, and `resume_secrecy.rs` covers
    // the log/JSON surfaces properly.
    let audit = serde_json::to_string(&h.audit().records()).expect("audit records serialise");
    for token in [&opened.resume_token, &attached.new_resume_token] {
        assert!(
            !audit.contains(&hex(token)),
            "a resume credential reached the audit trail"
        );
    }

    fourth.close();
    third.close();
    second.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_attach_stitches_the_stream_exactly_at_the_last_delivered_offset_forward() {
    a_resumed_attach_stitches_the_stream_exactly_at_the_last_delivered_offset(
        LoopbackHarness::start().await,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_attach_stitches_the_stream_exactly_at_the_last_delivered_offset_reverse() {
    a_resumed_attach_stitches_the_stream_exactly_at_the_last_delivered_offset(
        ReversePairHarness::start().await,
    )
    .await;
}

/// A resume that asks for an offset the ring has evicted opens with a
/// `Gap` naming where the stream can actually continue, and then continues
/// from exactly there. The client is told output was lost; it is never
/// silently handed a different stream.
async fn a_request_older_than_the_ring_opens_with_a_gap_and_resumes_from_available_from<
    P: HostedPair,
>(
    h: P,
) {
    let mut first = h.session().await;
    let (opened, mut pipe, mut data) = open_and_attach(&h, &mut first).await;

    let head = b"the beginning\r\n";
    pipe.write_output(head).await.expect("child output");
    let (_, last_seq) = read_output(&mut data, head.len()).await;
    drop(data);
    first.close();

    // Overrun the ring so `last_seq` cannot be replayed any more. Written
    // in chunks so the pipe's own buffer never has to hold it all.
    let chunk = vec![b'x'; 8 * 1024];
    for _ in 0..(RING_BYTES / chunk.len() + 2) {
        pipe.write_output(&chunk).await.expect("filler");
    }
    pipe.write_output(b"tail\r\n").await.expect("tail");

    let mut second = h.session().await;
    let attached = attach(
        &mut second,
        attach_req(&opened.session_id, opened.resume_token.clone(), last_seq),
    )
    .await
    .expect("resume is accepted");
    let mut data = redeem(&second, attached.ticket.clone()).await;

    let frame = tokio::time::timeout(DEADLINE, data.recv.recv::<wire::SessionFrame>())
        .await
        .expect("first frame arrives")
        .expect("frame")
        .expect("stream ended before the first frame");
    let Some(session_frame::Body::Gap(gap)) = frame.body else {
        panic!("expected a Gap as the first frame, got {frame:?}");
    };
    assert_eq!(gap.requested_after, last_seq);
    assert!(
        gap.available_from > last_seq,
        "a gap must name an offset ahead of what was asked for: {gap:?}"
    );

    // …and the stream really does continue from `available_from`, with no
    // second gap and no silent rewind.
    let mut got = 0u64;
    tokio::time::timeout(DEADLINE, async {
        loop {
            let frame = data
                .recv
                .recv::<wire::SessionFrame>()
                .await
                .expect("frame")
                .expect("stream ended early");
            match frame.body {
                Some(session_frame::Body::Output(o)) => {
                    let start = o.sequence - o.data.len() as u64;
                    if got == 0 {
                        assert_eq!(
                            start, gap.available_from,
                            "output after a gap must start at available_from"
                        );
                    }
                    got += o.data.len() as u64;
                    if got >= 4 {
                        return;
                    }
                }
                Some(session_frame::Body::Gap(g)) => panic!("a second gap: {g:?}"),
                _ => continue,
            }
        }
    })
    .await
    .expect("output follows the gap within the deadline");

    second.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_older_than_the_ring_opens_with_a_gap_and_resumes_from_available_from_forward() {
    a_request_older_than_the_ring_opens_with_a_gap_and_resumes_from_available_from(
        LoopbackHarness::start().await,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_older_than_the_ring_opens_with_a_gap_and_resumes_from_available_from_reverse() {
    a_request_older_than_the_ring_opens_with_a_gap_and_resumes_from_available_from(
        ReversePairHarness::start().await,
    )
    .await;
}

/// Input that was sent but never acknowledged is retransmitted after a
/// resume — and the child must not see it twice. The dedup cursor lives in
/// the session, keyed by the input stream a resumed attach inherits
/// (protocol.md §10-5); this is what proves the reattach inherited it
/// instead of starting a fresh axis.
async fn retransmitted_input_is_applied_exactly_once_across_a_resume<P: HostedPair>(h: P) {
    let mut first = h.session().await;
    let (opened, mut pipe, mut data) = open_and_attach(&h, &mut first).await;

    data.send
        .send(&wire::SessionFrame::input(3, b"abc".to_vec()))
        .await
        .expect("input");
    // A round trip, not a sleep: the ack is the host saying it applied it.
    let acked = tokio::time::timeout(DEADLINE, async {
        loop {
            let frame = data
                .recv
                .recv::<wire::SessionFrame>()
                .await
                .expect("frame")
                .expect("stream ended early");
            if let Some(session_frame::Body::InputAck(a)) = frame.body {
                return a.acked_input_seq;
            }
        }
    })
    .await
    .expect("the host acks the input");
    assert_eq!(acked, 3);

    drop(data);
    first.close();

    let mut second = h.session().await;
    let attached = attach(
        &mut second,
        attach_req(&opened.session_id, opened.resume_token.clone(), 0),
    )
    .await
    .expect("resume is accepted");
    assert_eq!(
        attached.input_seq, 3,
        "a resumed attach must inherit the host's input cursor, not restart at 0"
    );
    let mut data = redeem(&second, attached.ticket.clone()).await;

    // A client that never saw the ack retransmits from its own last known
    // offset. Both frames go out; only the new bytes may reach the child.
    data.send
        .send(&wire::SessionFrame::input(3, b"abc".to_vec()))
        .await
        .expect("retransmit");
    data.send
        .send(&wire::SessionFrame::input(6, b"def".to_vec()))
        .await
        .expect("input");

    let seen = tokio::time::timeout(DEADLINE, async {
        let mut seen = Vec::new();
        while seen.len() < 6 {
            let chunk = pipe.read_input(64).await.expect("the child's input");
            assert!(!chunk.is_empty(), "the child's input side closed early");
            seen.extend_from_slice(&chunk);
        }
        seen
    })
    .await
    .expect("the child receives the input within the deadline");
    assert_eq!(
        seen, b"abcdef",
        "the retransmitted prefix was applied a second time"
    );

    second.close();
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn retransmitted_input_is_applied_exactly_once_across_a_resume_forward() {
    retransmitted_input_is_applied_exactly_once_across_a_resume(LoopbackHarness::start().await)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn retransmitted_input_is_applied_exactly_once_across_a_resume_reverse() {
    retransmitted_input_is_applied_exactly_once_across_a_resume(ReversePairHarness::start().await)
        .await;
}

// ==========================================================================
// Forward-only: multi-principal scenarios (module docs above — a reverse
// target has exactly one peer, ever, so there is no reverse-mode analogue
// of "a second, distinct device reaches the same host").
// ==========================================================================

/// A credential is bound to the peer it was issued to (protocol.md §10-2,
/// PRD §9). A different device holding a stolen token is refused — and
/// refused by the *binding*, not by authorization: this host's ACL allows
/// the thief, and the theft still fails.
#[tokio::test(flavor = "multi_thread")]
async fn a_stolen_credential_is_useless_to_a_different_peer() {
    let owner = make_identity();
    let thief = make_identity();
    let server_trust = StaticTrust::empty()
        .with_pin(owner.fingerprint, Principal::Device("laptop".into()))
        .with_pin(thief.fingerprint, Principal::Device("thief".into()));
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllPinned), owner, server_trust).await;

    let mut session = h.session().await;
    let (opened, _pipe, data) = open_and_attach(&h, &mut session).await;
    drop(data);
    session.close();

    let client_trust = StaticTrust::empty().with_pin(
        h.server_identity.fingerprint,
        Principal::Device("box".into()),
    );
    let thief_dialer = Dialer::new(thief.local.clone(), Arc::new(client_trust));
    let dialed = thief_dialer
        .dial(h.addr, "127.0.0.1")
        .await
        .expect("the thief is a pinned peer, so the handshake succeeds");
    let mut stolen = Session::negotiate(dialed.connection, "thief")
        .await
        .expect("negotiate");

    assert_eq!(
        attach(
            &mut stolen,
            attach_req(&opened.session_id, opened.resume_token.clone(), 0)
        )
        .await
        .unwrap_err(),
        ErrorCode::AuthFailed,
        "a credential must be useless to a peer it was not issued to"
    );

    // The failed theft did not consume the owner's credential.
    let mut owner_again = h.session().await;
    attach(
        &mut owner_again,
        attach_req(&opened.session_id, opened.resume_token.clone(), 0),
    )
    .await
    .expect("the owner's credential still works after a failed theft");

    owner_again.close();
    stolen.close();
    h.shutdown().await;
}

/// An attach that presents no credential is refused by the **host**, not
/// just by the client (protocol.md §10-2, ADR-0007 결정 2).
///
/// The client refuses locally when it has no entry, but that is a
/// convenience, not a boundary: under the M1–M4 allow-all-pinned posture
/// every pinned device passes the ACL, so a `resume_token` the host treats
/// as optional would hand any of them an RW PTY on somebody else's shell —
/// and the credential's peer binding, which is the thing that makes attach
/// device-local, would never be consulted.
#[tokio::test(flavor = "multi_thread")]
async fn an_attach_without_a_credential_is_refused_by_the_host() {
    let owner = make_identity();
    let other = make_identity();
    let server_trust = StaticTrust::empty()
        .with_pin(owner.fingerprint, Principal::Device("laptop".into()))
        .with_pin(other.fingerprint, Principal::Device("desktop".into()));
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllPinned), owner, server_trust).await;

    let mut first = h.session().await;
    let (opened, _pipe, data) = open_and_attach(&h, &mut first).await;
    drop(data);
    first.close();

    // The owner itself, on a new connection, with the field left empty.
    let mut owner_conn = h.session().await;
    assert_eq!(
        attach(
            &mut owner_conn,
            attach_req(&opened.session_id, Vec::new(), 0)
        )
        .await
        .unwrap_err(),
        ErrorCode::AuthFailed,
        "an empty resume_token must not skip the credential gate"
    );

    // A second pinned device the ACL allows everything: same answer, and
    // the same one it gets for an id that never existed — no oracle.
    let mut desktop = other_device(&h, &other).await;
    assert_eq!(
        attach(&mut desktop, attach_req(&opened.session_id, Vec::new(), 0))
            .await
            .unwrap_err(),
        ErrorCode::AuthFailed
    );
    assert_eq!(
        attach(&mut desktop, attach_req("01K0NOSUCHSESSION", Vec::new(), 0))
            .await
            .unwrap_err(),
        ErrorCode::AuthFailed
    );

    // None of it spent the owner's credential.
    attach(
        &mut owner_conn,
        attach_req(&opened.session_id, opened.resume_token.clone(), 0),
    )
    .await
    .expect("the credential is untouched by the refusals");

    desktop.close();
    owner_conn.close();
    h.shutdown().await;
}

/// The writer lease is decided under the broker's single lock, after the
/// credential and the ACL (architecture.md §3 rule b) — and the control
/// message only **probes** it: `session.attach` answers `SESSION_CONFLICT`
/// without moving anything, because the redemption is not final until the
/// successor credential is minted (protocol.md §10-2 "전부 통과 후에만").
/// The binding take happens where the data stream opens.
///
/// The contender has to be a different *principal* (a second connection
/// from the same principal is the same writer moving devices), and since
/// an attach requires the session's credential, the only way a foreign
/// principal comes to hold the lease is the `session.write` value op.
#[tokio::test(flavor = "multi_thread")]
async fn no_steal_conflicts_with_a_foreign_lease_and_spends_no_credential() {
    let owner = make_identity();
    let other = make_identity();
    let server_trust = StaticTrust::empty()
        .with_pin(owner.fingerprint, Principal::Device("laptop".into()))
        .with_pin(other.fingerprint, Principal::Device("desktop".into()));
    let h = LoopbackHarness::start_custom(Arc::new(AllowAllPinned), owner, server_trust).await;

    let mut first = h.session().await;
    let (opened, mut pipe, data) = open_and_attach(&h, &mut first).await;
    drop(data);
    first.close();

    // A foreign principal takes the writer lease the only way it can.
    let mut desktop = other_device(&h, &other).await;
    desktop
        .session_write(&opened.session_id, b"x".to_vec())
        .await
        .expect("the value op is ACL-allowed and takes the lease");

    // Refusing to steal loses. The code says exactly why: this is not the
    // non-distinguishing path — nothing about a credential failed.
    let mut owner_conn = h.session().await;
    let mut careful = attach_req(&opened.session_id, opened.resume_token.clone(), 0);
    careful.no_steal = true;
    assert_eq!(
        attach(&mut owner_conn, careful).await.unwrap_err(),
        ErrorCode::SessionConflict,
        "no_steal must not take a lease a different principal holds"
    );

    // The refusal was decided before the rotation, so the credential is
    // still spendable — a conflict must not orphan the session.
    let attached = attach(
        &mut owner_conn,
        attach_req(&opened.session_id, opened.resume_token.clone(), 0),
    )
    .await
    .expect("a stealing attach is allowed");
    assert!(attached.writer_lease, "an RW attach is granted the lease");
    // …and it is the data stream that actually moves it.
    let mut data = redeem(&owner_conn, attached.ticket.clone()).await;
    pipe.write_output(b"hi").await.unwrap();
    let _ = read_output(&mut data, 2).await;
    assert_eq!(
        h.broker
            .get(&qsh_core::broker::SessionId(opened.session_id.clone()))
            .unwrap()
            .info()
            .writer
            .as_deref(),
        Some("device:laptop"),
        "the steal lands when the stream opens"
    );

    drop(data);
    desktop.close();
    owner_conn.close();
    h.shutdown().await;
}
