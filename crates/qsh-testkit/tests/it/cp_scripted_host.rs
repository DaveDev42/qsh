//! PLAN M15 Step 15, ADR-0029 decisions 21 and 22: `qsh cp -r` against a
//! scripted host.
//!
//! A real `Server` never lists a name like `..` and never drops a
//! connection at a chosen request, so these two scenarios need a peer that
//! speaks the wire protocol by hand: a QUIC listener that completes the
//! `Hello` handshake, then answers each control request from a closure.
//! The client side is the production copy engine, [`file_copy_over`], on a
//! [`Session`] negotiated over a real connection.

#![cfg(unix)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qsh_core::client::Session;
use qsh_core::handshake;
use qsh_core::ops::{CancelToken, FileCopyObserver, file_copy_over};
use qsh_proto::wire::{
    self, ControlMessage, FileEntry, FileKind, FileListed, Hello, control_message, response,
};
use qsh_proto::{ErrorCode, FileCopyEntry, FileCopyErrorDetails, FileCopyReq};
use qsh_testkit::loopback::make_identity;
use qsh_transport::{Connection, Dialer, Listener, Principal, StaticTrust};

/// What the scripted host does with one control request.
enum Step {
    /// Answer it.
    Reply(response::Body),
    /// Drop the connection instead of answering.
    Hang,
}

type Script = Box<dyn FnMut(&control_message::Body) -> Step + Send>;

/// Start the host and dial it. Returns the negotiated session, which keeps
/// the listener task alive until the test ends.
async fn session_against(mut script: Script) -> (Session, tokio::task::JoinHandle<()>) {
    let client = make_identity();
    let server = make_identity();
    let listener = Listener::bind(
        "127.0.0.1:0".parse().expect("addr"),
        server.local.clone(),
        Arc::new(
            StaticTrust::empty().with_pin(client.fingerprint, Principal::Device("laptop".into())),
        ),
    )
    .expect("bind scripted host");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    let host = tokio::spawn(async move {
        let incoming = listener.accept().await.expect("an incoming connection");
        let conn: Connection = incoming.accept().await.expect("accept the handshake");
        let (mut ctl, _peer) = handshake::respond(&conn, |_peer| {
            Ok(Hello {
                versions: wire::WIRE_MINOR_VERSIONS.to_vec(),
                device_name: "box".into(),
                capabilities: wire::LOCAL_CAPABILITIES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                reverse: None,
            })
        })
        .await
        .expect("answer Hello");
        while let Ok(Some(msg)) = ctl.recv.recv::<ControlMessage>().await {
            let Some(body) = msg.body else { continue };
            match script(&body) {
                Step::Reply(reply) => {
                    if ctl
                        .send
                        .send(&ControlMessage::response(msg.request_id, reply))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Step::Hang => {
                    conn.close(0x7, b"scripted drop");
                    return;
                }
            }
        }
    });
    let dialer = Dialer::new(
        client.local.clone(),
        Arc::new(
            StaticTrust::empty().with_pin(server.fingerprint, Principal::Device("box".into())),
        ),
    );
    let dialed = dialer.dial(addr, "127.0.0.1").await.expect("dial host");
    let session = Session::negotiate(dialed.connection, "laptop")
        .await
        .expect("negotiate with the scripted host");
    // `dialed.endpoint` must outlive the connection; leak it to the test.
    std::mem::forget(dialed.endpoint);
    (session, host)
}

fn listed_dir(entries: Vec<FileEntry>) -> response::Body {
    response::Body::FileListed(FileListed {
        kind: FileKind::Dir as i32,
        size: 0,
        mode: 0o755,
        mtime: 0,
        entries,
        more: false,
        unlistable: 0,
    })
}

fn entry(name: &str, kind: FileKind) -> FileEntry {
    FileEntry {
        name: name.to_string(),
        kind: kind as i32,
        size: 0,
        mode: 0o755,
        mtime: 0,
    }
}

/// Records every item the copy reports.
#[derive(Default)]
struct Recorder(Mutex<Vec<FileCopyEntry>>);

impl FileCopyObserver for Recorder {
    fn entry(&self, entry: &FileCopyEntry) {
        self.0.lock().unwrap().push(entry.clone());
    }
}

fn get_req(remote: &str, local: &Path) -> FileCopyReq {
    FileCopyReq {
        sources: vec![format!("box:{remote}")],
        destination: local.display().to_string(),
        recursive: true,
        preserve: false,
        no_clobber: false,
    }
}

/// Every path under `root`, relative, sorted.
fn tree_of(root: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            out.push(
                path.strip_prefix(base)
                    .expect("under base")
                    .to_string_lossy()
                    .into_owned(),
            );
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn details_of(err: &qsh_core::ops::FileCopyError) -> FileCopyErrorDetails {
    serde_json::from_value(err.error.details.clone())
        .expect("details decode as FileCopyErrorDetails")
}

#[tokio::test(flavor = "multi_thread")]
async fn cp_rejects_hostile_entry_names() {
    // The top directory lists four names that must never become a local
    // path component, and one good directory.
    let script: Script = Box::new(|body| match body {
        control_message::Body::FileListOpen(req) if req.path == "/srv/tree" => {
            // Strictly increasing byte order, as a host must list them.
            Step::Reply(listed_dir(vec![
                entry("", FileKind::File),
                entry("..", FileKind::Dir),
                entry("a/b", FileKind::Dir),
                entry("good", FileKind::Dir),
                entry("x\0y", FileKind::File),
            ]))
        }
        control_message::Body::FileListOpen(req) if req.path == "/srv/tree/good" => {
            Step::Reply(listed_dir(Vec::new()))
        }
        other => panic!("the walk asked the scripted host for something unexpected: {other:?}"),
    });
    let (mut session, host) = session_against(script).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(dir.path()).expect("canonical");
    // `out` is the destination; its parent holds a sentinel to prove nothing
    // climbed out.
    let out = root.join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(root.join("sentinel"), b"s").unwrap();

    let recorder = Arc::new(Recorder::default());
    let observer: Arc<dyn FileCopyObserver> = recorder.clone();
    let err = tokio::time::timeout(
        Duration::from_secs(30),
        file_copy_over(
            &mut session,
            &get_req("/srv/tree", &out),
            observer,
            &CancelToken::new(),
        ),
    )
    .await
    .expect("the copy ended")
    .expect_err("four hostile names fail the copy");

    let details = details_of(&err);
    assert_eq!(details.failed, 4, "{details:?}");
    assert_eq!(details.created, 2, "tree and tree/good: {details:?}");
    assert_eq!(details.copied, 0, "{details:?}");
    assert_eq!(details.not_attempted, 0, "{details:?}");
    assert!(
        details
            .failures
            .iter()
            .all(|f| f.side == "local" && f.code == ErrorCode::InvalidArgument),
        "{details:?}"
    );
    assert_eq!(err.error.code, ErrorCode::InvalidArgument, "{err:?}");

    // Nothing but the two good directories exists, and nothing outside `out`.
    assert_eq!(tree_of(&out), vec!["tree", "tree/good"]);
    assert_eq!(
        tree_of(&root),
        vec!["out", "out/tree", "out/tree/good", "sentinel"]
    );
    let entries = recorder.0.lock().unwrap();
    assert_eq!(
        entries.iter().filter(|e| e.status == "failed").count(),
        4,
        "{entries:?}"
    );

    session.close();
    host.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn cp_connection_loss_stops_the_walk_and_reports_not_attempted() {
    // The host answers the top listing and the first subdirectory, then
    // drops the connection when the second one is asked for.
    let script: Script = Box::new(|body| match body {
        control_message::Body::FileListOpen(req) if req.path == "/srv/tree" => {
            Step::Reply(listed_dir(vec![
                entry("d1", FileKind::Dir),
                entry("d2", FileKind::Dir),
                entry("d3", FileKind::Dir),
                entry("z.txt", FileKind::File),
            ]))
        }
        control_message::Body::FileListOpen(req) if req.path == "/srv/tree/d1" => {
            Step::Reply(listed_dir(Vec::new()))
        }
        control_message::Body::FileListOpen(req) if req.path == "/srv/tree/d2" => Step::Hang,
        other => panic!("the walk went on after the connection died: {other:?}"),
    });
    let (mut session, host) = session_against(script).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let out = std::fs::canonicalize(dir.path()).expect("canonical");

    let recorder = Arc::new(Recorder::default());
    let observer: Arc<dyn FileCopyObserver> = recorder.clone();
    let err = tokio::time::timeout(
        Duration::from_secs(30),
        file_copy_over(
            &mut session,
            &get_req("/srv/tree", &out),
            observer,
            &CancelToken::new(),
        ),
    )
    .await
    .expect("the copy ended instead of hanging on a dead connection")
    .expect_err("a lost connection fails the copy");

    let details = details_of(&err);
    // tree and d1 were made; d2 is the item the connection died on; d3 and
    // z.txt were never tried.
    assert_eq!(details.created, 2, "{details:?}");
    assert_eq!(details.failed, 1, "{details:?}");
    assert_eq!(details.not_attempted, 2, "{details:?}");
    assert_eq!(details.copied, 0, "{details:?}");
    assert_eq!(details.failures[0].side, "remote", "{details:?}");
    assert_ne!(err.error.code, ErrorCode::Canceled, "{err:?}");
    // d3 was not made: the walk stopped.
    assert_eq!(tree_of(&out), vec!["tree", "tree/d1"]);

    session.close();
    host.abort();
}
