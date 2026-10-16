use std::time::Duration;

use qsh_proto::local::{LOCAL_HELLO_VERSION, LocalHello, LocalStreamKind};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use windows_sys::Win32::Storage::FileSystem::{SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};

use super::*;
use crate::fsutil::dacl::testing::{NoSid, assert_owner_only_report, read_dacl_of_handle};
use crate::localctl::frame::LocalConduit;

/// `S-1-5-18` (LocalSystem), a user this test process is not.
fn other_sid() -> Vec<u32> {
    vec![0x0000_0101, 0x0500_0000, 18]
}

/// Lookups that name this process's real SID as its own and a different one
/// for every peer.
struct PeerIsAnotherUser;

impl ProcessSids for PeerIsAnotherUser {
    fn own(&self) -> io::Result<Vec<u32>> {
        token_user_sid()
    }
    fn of_process(&self, _pid: u32) -> io::Result<Vec<u32>> {
        Ok(other_sid())
    }
}

/// Lookups whose peer lookup fails outright.
struct PeerLookupFails;

impl ProcessSids for PeerLookupFails {
    fn own(&self) -> io::Result<Vec<u32>> {
        token_user_sid()
    }
    fn of_process(&self, _pid: u32) -> io::Result<Vec<u32>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

fn bind_in(dir: &Path, pid: u32) -> PipeListener {
    PipeListener::bind(dir, pid).unwrap()
}

fn bind_with(dir: &Path, pid: u32, sids: impl ProcessSids + 'static) -> PipeListener {
    PipeListener::bind_named(
        scoped_pipe_name(dir, pid).unwrap(),
        Arc::new(sids),
        Arc::new(CurrentUser),
    )
    .unwrap()
}

fn hello() -> LocalHello {
    LocalHello {
        version: LOCAL_HELLO_VERSION,
        kind: LocalStreamKind::LocalAdmin as i32,
        host: String::new(),
        wait_ms: 0,
        known_generation: None,
    }
}

// ---- the DoD pins ----

#[tokio::test]
async fn pipe_instance_dacl_is_protected_and_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_in(dir.path(), 4000);
    assert_owner_only_report(
        "the first pipe instance",
        read_dacl_of_handle(raw(listener.waiting_handle())),
        ObjectKind::Pipe,
    );

    // The instance created after a connection carries the same descriptor.
    let client = connect(listener.name()).await.unwrap();
    let served = listener.accept().await.unwrap();
    assert_owner_only_report(
        "the next pipe instance",
        read_dacl_of_handle(raw(listener.waiting_handle())),
        ObjectKind::Pipe,
    );
    drop((client, served));
}

#[tokio::test]
async fn pipe_bind_without_a_dacl_creates_no_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let name = scoped_pipe_name(dir.path(), 4001).unwrap();
    let err = PipeListener::bind_named(name.clone(), Arc::new(Os), Arc::new(NoSid))
        .err()
        .expect("a pipe must never be created without its DACL");
    assert!(err.to_string().contains("injected"), "{err}");
    assert!(
        ClientOptions::new().open(&name).is_err(),
        "no pipe may exist under {}",
        name.display()
    );
}

#[tokio::test]
async fn pipe_server_drops_a_client_with_another_sid_before_reading_a_frame() {
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_with(dir.path(), 4002, PeerIsAnotherUser);
    let name = listener.name().to_path_buf();
    let accepting = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

    let mut client = connect(&name).await.unwrap();
    // The frame is written, and the server must never surface the stream.
    let mut conduit = LocalConduit::new(&mut client);
    let _ = conduit.send(&hello()).await;
    let mut byte = [0u8; 1];
    let ended = tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
        .await
        .expect("the server must drop the connection, not hold it");
    assert!(
        matches!(ended, Ok(0) | Err(_)),
        "the server sent {ended:?} to a client of another user"
    );
    assert!(
        !accepting.is_finished(),
        "accept must keep waiting after it rejects a client"
    );
    accepting.abort();
}

#[tokio::test]
async fn pipe_server_drops_a_client_whose_credentials_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_with(dir.path(), 4003, PeerLookupFails);
    let name = listener.name().to_path_buf();
    let accepting = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

    let mut client = connect(&name).await.unwrap();
    let mut byte = [0u8; 1];
    let ended = tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
        .await
        .expect("an unverifiable client must be dropped");
    assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");
    assert!(!accepting.is_finished());
    accepting.abort();
}

#[tokio::test]
async fn pipe_client_writes_nothing_to_a_server_with_another_sid() {
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_in(dir.path(), 4004);
    let name = listener.name().to_path_buf();
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut all = Vec::new();
        // The client's end is dropped without a byte, so this ends at once.
        stream.read_to_end(&mut all).await.map(|_| all)
    });

    let err = connect_with(&name, &PeerIsAnotherUser)
        .await
        .expect_err("a server of another user must be refused");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    let received = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the refused client must close its end")
        .unwrap();
    assert!(
        received.map(|bytes| bytes.is_empty()).unwrap_or(true),
        "the refused client wrote to the server"
    );
}

// ---- create options, names, discovery ----

#[test]
fn pipe_create_options_reject_remote_clients_and_claim_the_first_instance() {
    let first = CreateOptions::for_instance(true);
    assert!(first.first_instance, "the first instance claims the name");
    assert!(first.reject_remote_clients);
    assert!(first.byte_stream);

    let later = CreateOptions::for_instance(false);
    assert!(
        !later.first_instance,
        "later instances join the claimed name"
    );
    assert!(
        later.reject_remote_clients,
        "every instance rejects remote clients"
    );
    assert!(later.byte_stream);
}

#[tokio::test]
async fn pipe_bind_fails_when_the_name_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let _held = bind_in(dir.path(), 4005);
    let second = PipeListener::bind(dir.path(), 4005);
    assert!(
        second.is_err(),
        "a second bind of a held name must fail, not share it"
    );
}

#[test]
fn pipe_client_opens_with_sqos_identification() {
    let flags = client_qos_flags();
    assert_eq!(flags, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    assert_ne!(flags & SECURITY_SQOS_PRESENT, 0, "QoS must be present");
    // Identification, not impersonation or delegation.
    assert_eq!(flags & 0x0003_0000, SECURITY_IDENTIFICATION);
}

#[test]
fn pipe_name_differs_by_sid_or_state_dir_and_matches_otherwise() {
    let sid = "S-1-5-21-1-2-3-1001";
    let dir = Path::new(r"C:\Users\Dave\AppData\Local\qsh\run");
    let scope = pipe_scope(sid, dir);
    assert_eq!(scope.len(), 16);
    assert!(
        scope
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );

    assert_eq!(
        pipe_scope(sid, dir),
        scope,
        "the same inputs, the same name"
    );
    assert_eq!(
        pipe_scope(sid, Path::new(r"c:/users/dave/appdata/local/qsh/run/")),
        scope,
        "case, separators and a trailing separator do not matter"
    );
    assert_eq!(
        pipe_scope(sid, Path::new(r"\\?\C:\Users\Dave\AppData\Local\qsh\run")),
        scope,
        "a verbatim prefix does not matter"
    );
    assert_ne!(
        pipe_scope("S-1-5-21-1-2-3-1002", dir),
        scope,
        "another user"
    );
    assert_ne!(
        pipe_scope(sid, Path::new(r"C:\state\other\run")),
        scope,
        "another state directory"
    );
    assert_eq!(
        pipe_name(&scope, 77),
        PathBuf::from(format!(r"\\.\pipe\qsh-{scope}-77"))
    );
}

#[test]
fn pipe_enumeration_picks_only_scope_prefixed_names() {
    let scope = "0123456789abcdef";
    let names = [
        "qsh-0123456789abcdef-300",
        "qsh-0123456789abcdef-12",
        "qsh-fedcba9876543210-12",
        "qsh-0123456789abcdef-",
        "qsh-0123456789abcdef-abc",
        "qsh-0123456789abcdef-12x",
        "qsh-0123456789abcdef",
        "other-0123456789abcdef-5",
        "mojo.1234.5678",
    ]
    .map(OsString::from);
    let picked = pick_scoped_pipes(names, scope);
    assert_eq!(
        picked,
        vec![
            (12, PathBuf::from(r"\\.\pipe\qsh-0123456789abcdef-12")),
            (300, PathBuf::from(r"\\.\pipe\qsh-0123456789abcdef-300")),
        ]
    );
}

#[tokio::test]
async fn pipe_enumeration_finds_a_live_pipe_of_this_scope_only() {
    let mine = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let held = bind_in(mine.path(), 4006);
    let _other_held = bind_in(other.path(), 4007);

    let found = candidate_endpoints(mine.path()).unwrap();
    assert_eq!(found, vec![(4006, held.name().to_path_buf())]);
    assert!(
        candidate_endpoints(&mine.path().join("missing"))
            .unwrap()
            .is_empty()
    );
}

// ---- accept ----

#[tokio::test]
async fn the_next_pipe_instance_exists_before_the_current_connection_is_handed_off() {
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_in(dir.path(), 4008);
    let name = listener.name().to_path_buf();

    let first = connect(&name).await.unwrap();
    let served_first = listener.accept().await.unwrap();

    // `accept` returned the first connection and nothing is waiting in an
    // `accept` call now. A plain open that does not retry on `PIPE_BUSY`
    // succeeds only if a free instance already exists.
    let second = ClientOptions::new()
        .security_qos_flags(client_qos_flags())
        .open(&name)
        .expect("the name must never be without a free instance");
    let served_second = listener.accept().await.unwrap();
    drop((first, served_first, second, served_second));
}

#[tokio::test]
async fn pipe_stream_carries_localctl_frames_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_in(dir.path(), 4009);
    let name = listener.name().to_path_buf();
    let server = tokio::spawn(async move {
        let mut conduit = LocalConduit::new(listener.accept().await.unwrap());
        let got: LocalHello = conduit.recv().await.unwrap().unwrap();
        conduit.send(&got).await.unwrap();
    });

    let mut conduit = LocalConduit::new(connect(&name).await.unwrap());
    conduit.send(&hello()).await.unwrap();
    let echoed: LocalHello = conduit.recv().await.unwrap().unwrap();
    assert_eq!(echoed, hello());
    server.await.unwrap();
}

#[tokio::test]
async fn pipe_shutdown_both_ends_reads_and_fails_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_in(dir.path(), 4010);
    let name = listener.name().to_path_buf();
    let client = Arc::new(connect(&name).await.unwrap());
    let _served = listener.accept().await.unwrap();

    let reader = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            client.readable().await.unwrap();
            let mut byte = [0u8; 1];
            client.try_read(&mut byte)
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown_both(&client);

    let read = tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .expect("shutdown_both must wake a pending read")
        .unwrap();
    assert_eq!(read.unwrap(), 0, "a stopped stream reads as ended");
    assert!(
        client.try_write(b"x").is_err(),
        "a stopped stream refuses writes"
    );
}

/// Many clients open the same name at once while the server accepts one
/// connection after another. Each client must be served: the name is never
/// without a free instance for longer than a client is willing to retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipe_accept_serves_concurrent_clients_without_a_name_gap() {
    const CLIENTS: u8 = 16;
    let dir = tempfile::tempdir().unwrap();
    let mut listener = bind_in(dir.path(), 4011);
    let name = listener.name().to_path_buf();

    let server = tokio::spawn(async move {
        for _ in 0..CLIENTS {
            let mut stream = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                stream.write_all(&[byte[0] ^ 0xff]).await.unwrap();
                stream.flush().await.unwrap();
                // Hold the end until the client has read its answer.
                let _ = stream.read(&mut byte).await;
            });
        }
    });

    let mut clients = Vec::new();
    for index in 0..CLIENTS {
        let name = name.clone();
        clients.push(tokio::spawn(async move {
            let mut stream = connect(&name).await.unwrap();
            stream.write_all(&[index]).await.unwrap();
            let mut answer = [0u8; 1];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer[0], index ^ 0xff);
        }));
    }
    for client in clients {
        tokio::time::timeout(Duration::from_secs(20), client)
            .await
            .expect("a client was never served")
            .unwrap();
    }
    server.await.unwrap();
}
