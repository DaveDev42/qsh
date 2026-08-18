//! One test, one property: **the resume credential never leaves the two
//! places it is allowed to be** — the wire, and the client's 0600
//! `resume.json` (ADR-0007, PLAN M2 Step 7 (d)).
//!
//! It lives in its own test binary on purpose. Proving "it is in none of
//! the logs" means capturing *every* tracing event the host and the client
//! emit, which needs a process-wide subscriber; sharing a process with
//! other tests would mean either capturing their events or failing to
//! install at all.
//!
//! The assertion is deliberately about renderings rather than about one
//! format. A credential leaks the same amount whether it was logged as
//! Base64, as hex, or as the `[125, 169, …]` a stray `{:?}` on a
//! `Vec<u8>` produces — so all three are searched for.

use std::io;
use std::sync::{Arc, Mutex};

use qsh_proto::wire::{self, StreamHeader};
use qsh_testkit::loopback::LoopbackHarness;
use tracing_subscriber::fmt::MakeWriter;

/// Everything written by the tracing subscriber during the test.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("capture lock")).into_owned()
    }
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("capture lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The three ways a byte string plausibly reaches a log line.
fn renderings(bytes: &[u8]) -> Vec<(&'static str, String)> {
    use base64::Engine as _;
    vec![
        (
            "base64",
            base64::engine::general_purpose::STANDARD.encode(bytes),
        ),
        (
            "hex",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        ),
        ("debug array", format!("{bytes:?}")),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resume_credential_never_reaches_a_log_line_or_the_json_contract() {
    let capture = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    )
    .expect("this binary holds exactly one test, so nothing else installed one");

    let h = LoopbackHarness::start().await;
    let mut s = h.session().await;
    let opened = s
        .session_open(wire::SessionOpen {
            argv: vec!["sh".into()],
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            ..Default::default()
        })
        .await
        .expect("session.open");
    assert_eq!(opened.resume_token.len(), 32);

    // Exercise every host path that touches a credential: a redemption
    // that succeeds (rotation), one that fails (a wrong token), and the
    // close that forgets it.
    let mut second = h.session().await;
    let attached = second
        .attach_request(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: opened.resume_token.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
        })
        .await
        .expect("resume is accepted");
    let (send, recv) = second.connection().open_bi().await.expect("open_bi");
    let mut data = qsh_transport::FramedStream::data(send, recv);
    data.send
        .send(&StreamHeader::session_data(attached.ticket.clone()))
        .await
        .expect("stream header");

    let bogus = vec![0xA5u8; 32];
    let mut third = h.session().await;
    let refused = third
        .attach_request(wire::SessionAttach {
            session_id: opened.session_id.clone(),
            resume_token: bogus.clone(),
            last_output_seq: 0,
            mode: wire::AttachMode::Rw as i32,
            no_steal: false,
        })
        .await;
    assert!(refused.is_err(), "a bogus credential must be refused");

    second
        .session_close(&opened.session_id, None)
        .await
        .expect("session.close");

    drop(data);
    third.close();
    second.close();
    s.close();
    h.shutdown().await;

    // ---- the assertions ----
    let logs = capture.text();
    assert!(
        !logs.is_empty(),
        "nothing was captured, so this test proves nothing"
    );
    for (label, name) in [
        (&opened.resume_token, "the issued credential"),
        (&attached.new_resume_token, "the rotated credential"),
        (&bogus, "the rejected credential"),
    ]
    .into_iter()
    .flat_map(|(bytes, name)| {
        renderings(bytes)
            .into_iter()
            .map(move |(how, text)| ((how, text), name))
    }) {
        let (how, text) = label;
        assert!(
            !logs.contains(&text),
            "{name} appeared in a log line as {how}"
        );
    }

    // The other half of the claim: the `qsh.cli/v1` payload for
    // `session.open` has nowhere to put a credential in the first place.
    // A field added later would show up here rather than in a leak.
    let payload = serde_json::to_value(qsh_proto::SessionOpenData {
        session_ref: "box/01K0".into(),
        initial_sequence: 0,
    })
    .expect("the contract type serialises");
    let mut fields: Vec<&str> = payload
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["initial_sequence", "session_ref"],
        "session.open's contract payload grew a field; if it can hold a \
         credential, it must not (CLI.md §6.3)"
    );
}
