use super::*;

#[test]
fn budget_hands_out_cap_permits_and_takes_them_back() {
    let budget = StreamBudget::new(2);
    let a = budget.try_acquire().expect("first");
    let _b = budget.try_acquire().expect("second");
    assert!(budget.try_acquire().is_none());
    assert_eq!(budget.in_use(), 2);
    drop(a);
    assert_eq!(budget.in_use(), 1);
    assert!(budget.try_acquire().is_some());
}

#[test]
fn endpoint_names_are_128_random_bits() {
    let a = random_hex_name();
    let b = random_hex_name();
    assert_eq!(a.len(), 32);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    use std::path::Path;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixStream;

    use super::super::*;
    use crate::localctl::transport::peer_is_authorized;

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[tokio::test]
    async fn agent_dir_is_0700_and_socket_is_0600() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let listener = AgentListener::create(tmp.path()).expect("create");
        let sock = listener.auth_sock().to_path_buf();
        assert!(!listener.uses_fallback_dir());
        assert_eq!(sock.parent().expect("parent"), tmp.path().join("agent"));
        assert_eq!(mode(&tmp.path().join("agent")), 0o700);
        assert_eq!(mode(&sock), 0o600);
        assert!(
            std::fs::symlink_metadata(&sock)
                .expect("metadata")
                .file_type()
                .is_socket()
        );
        let name = sock.file_name().and_then(|n| n.to_str()).expect("name");
        let stem = name.strip_suffix(".sock").expect("suffix");
        assert_eq!(stem.len(), 32);
        assert!(stem.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn an_existing_agent_dir_with_loose_mode_is_tightened() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("agent");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let _listener = AgentListener::create(tmp.path()).expect("create");
        assert_eq!(mode(&dir), 0o700);
    }

    #[tokio::test]
    async fn agent_socket_is_removed_when_the_session_ends() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let listener = AgentListener::create(tmp.path()).expect("create");
        let sock = listener.auth_sock().to_path_buf();
        assert!(sock.exists());
        drop(listener);
        assert!(!sock.exists());

        let listener = AgentListener::create(tmp.path()).expect("create");
        let sock = listener.auth_sock().to_path_buf();
        listener.close();
        assert!(!sock.exists());
    }

    #[tokio::test]
    async fn accepted_connections_carry_bytes_both_ways() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut listener = AgentListener::create(tmp.path()).expect("create");
        let mut client = UnixStream::connect(listener.auth_sock())
            .await
            .expect("connect");
        let mut conn = listener.accept().await.expect("accept");
        client.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
        conn.write_all(b"pong").await.expect("write");
        client.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"pong");
        assert_eq!(listener.stats().accepted, 1);
    }

    #[tokio::test]
    async fn per_socket_cap_closes_the_extra_connection() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut listener = AgentListener::create_with_cap(tmp.path(), 2).expect("create");
        let path = listener.auth_sock().to_path_buf();

        let _c1 = UnixStream::connect(&path).await.expect("c1");
        let a1 = listener.accept().await.expect("a1");
        let _c2 = UnixStream::connect(&path).await.expect("c2");
        let _a2 = listener.accept().await.expect("a2");
        assert_eq!(listener.connections_open(), 2);

        // The third connects at the kernel level, then is closed by accept,
        // which goes on waiting for a usable one.
        let mut c3 = UnixStream::connect(&path).await.expect("c3");
        let _c4 = UnixStream::connect(&path).await.expect("c4");
        let waiting = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(waiting.is_err(), "no usable connection while at the cap");
        assert_eq!(listener.stats().refused_cap, 2);
        let mut buf = [0u8; 1];
        assert_eq!(c3.read(&mut buf).await.expect("eof"), 0);

        // A slot freed by dropping a connection admits the next one.
        drop(a1);
        assert_eq!(listener.connections_open(), 1);
        let _c5 = UnixStream::connect(&path).await.expect("c5");
        let _a5 = listener.accept().await.expect("a5");
        assert_eq!(listener.connections_open(), 2);
    }

    #[tokio::test]
    async fn extra_budgets_are_held_until_the_connection_drops() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut listener = AgentListener::create(tmp.path()).expect("create");
        let per_conn = StreamBudget::new(1);
        let _c1 = UnixStream::connect(listener.auth_sock()).await.expect("c1");
        let mut a1 = listener.accept().await.expect("a1");
        assert!(a1.hold(&per_conn));
        let _c2 = UnixStream::connect(listener.auth_sock()).await.expect("c2");
        let mut a2 = listener.accept().await.expect("a2");
        assert!(!a2.hold(&per_conn));
        let (_stream, guard) = a1.into_parts();
        assert_eq!(per_conn.in_use(), 1);
        drop(guard);
        assert_eq!(per_conn.in_use(), 0);
        assert!(a2.hold(&per_conn));
    }

    #[test]
    fn only_the_serve_uid_is_authorized() {
        assert!(peer_is_authorized(1000, 1000));
        assert!(!peer_is_authorized(1001, 1000));
        assert!(!peer_is_authorized(0, 1000));
    }

    #[tokio::test]
    async fn a_long_runtime_path_falls_back_to_a_private_tmp_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fallback_parent = tempfile::tempdir().expect("fallback parent");
        let runtime = tmp.path().join("r".repeat(120));
        let listener = AgentListener::create_in(&runtime, 16, fallback_parent.path())
            .expect("create with fallback");
        assert!(listener.uses_fallback_dir());
        let sock = listener.auth_sock().to_path_buf();
        let dir = sock.parent().expect("parent").to_path_buf();
        assert_eq!(dir.parent().expect("grandparent"), fallback_parent.path());
        assert!(
            dir.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("qsh-agent-") && n.len() == "qsh-agent-".len() + 10)
        );
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&sock), 0o600);
        assert!(UnixStream::connect(&sock).await.is_ok());
        drop(listener);
        assert!(!sock.exists());
        assert!(!dir.exists(), "the fallback directory goes with the socket");
    }

    #[tokio::test]
    async fn stale_agent_sockets_are_swept_at_start() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let live = AgentListener::create(tmp.path()).expect("live");
        let agent_dir = tmp.path().join("agent");

        // A dead socket: bound, then abandoned without unlinking, as a
        // crashed serve leaves it.
        let dead = agent_dir.join(format!("{}.sock", random_hex_name()));
        drop(std::os::unix::net::UnixListener::bind(&dead).expect("bind dead"));
        assert!(dead.exists());
        // Things that are not sockets, or not ours by name, stay.
        let plain = agent_dir.join(format!("{}.sock", random_hex_name()));
        std::fs::write(&plain, b"not a socket").expect("write");
        let other = agent_dir.join("notes.txt");
        std::fs::write(&other, b"keep").expect("write");
        let other_dead = agent_dir.join("dead-but-oddly-named");
        drop(std::os::unix::net::UnixListener::bind(&other_dead).expect("bind"));

        // A fresh node is left for a few seconds, in case it is a socket
        // between bind and listen.
        assert_eq!(sweep_stale(tmp.path()).await.expect("sweep"), 0);
        assert!(dead.exists());

        let removed = sweep_stale_older_than(tmp.path(), Duration::ZERO)
            .await
            .expect("sweep");
        assert_eq!(removed, 1);
        assert!(!dead.exists());
        assert!(live.auth_sock().exists(), "a live socket is never removed");
        assert!(plain.exists());
        assert!(other.exists());
        assert!(other_dead.exists());
    }

    #[tokio::test]
    async fn sweeping_without_an_agent_dir_is_a_no_op() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            sweep_stale_older_than(tmp.path(), Duration::ZERO)
                .await
                .expect("sweep"),
            0
        );
    }
}

#[cfg(windows)]
mod windows {
    use std::path::PathBuf;

    use super::super::*;

    fn unique_name() -> PathBuf {
        PathBuf::from(format!(r"\\.\pipe\qsh-agent-test-{}", random_hex_name()))
    }

    #[tokio::test]
    async fn a_second_first_instance_of_the_same_name_fails() {
        let name = unique_name();
        let first = AgentListener::bind_at(&name, 16).expect("first");
        assert!(AgentListener::bind_at(&name, 16).is_err());
        drop(first);
    }

    #[tokio::test]
    async fn created_pipe_has_the_agent_name_and_carries_bytes() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::windows::named_pipe::ClientOptions;

        let tmp = std::env::temp_dir();
        let mut listener = AgentListener::create(&tmp).expect("create");
        let name = listener.auth_sock().to_path_buf();
        let text = name.to_string_lossy().into_owned();
        let tail = text.strip_prefix(r"\\.\pipe\qsh-agent-").expect("prefix");
        assert_eq!(tail.len(), 32);

        let mut client = ClientOptions::new().open(&name).expect("open");
        let mut conn = listener.accept().await.expect("accept");
        client.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
    }

    /// ADR-0055 decision 7 and threat model B48: every instance of the agent
    /// pipe carries a protected DACL that grants only the owner, and the pipe
    /// is created with `PIPE_REJECT_REMOTE_CLIENTS`. `GetNamedPipeInfo` does
    /// not report the reject-remote flag, so that half is pinned by the
    /// creation parameters the listener builds every instance from.
    #[tokio::test]
    async fn windows_agent_pipe_is_owner_only_and_rejects_remote_clients() {
        use crate::fsutil::dacl::ObjectKind;
        use crate::fsutil::dacl::testing::{assert_owner_only_report, read_dacl_of_handle};
        use crate::localctl::transport::windows::CreateOptions;
        use tokio::net::windows::named_pipe::ClientOptions;

        let name = unique_name();
        let mut listener = AgentListener::bind_at(&name, 16).expect("bind");
        assert_owner_only_report(
            "the first agent pipe instance",
            read_dacl_of_handle(listener.waiting_handle().cast()),
            ObjectKind::Pipe,
        );

        // The instance created after a connection carries the same descriptor.
        let client = ClientOptions::new().open(&name).expect("open");
        let served = listener.accept().await.expect("accept");
        assert_owner_only_report(
            "the next agent pipe instance",
            read_dacl_of_handle(listener.waiting_handle().cast()),
            ObjectKind::Pipe,
        );
        drop((client, served));

        for first in [true, false] {
            let options = CreateOptions::for_instance(first);
            assert!(options.reject_remote_clients, "first_instance = {first}");
            assert_eq!(options.first_instance, first);
        }
        // A second first-instance claim of the same name fails.
        assert!(AgentListener::bind_at(&name, 16).is_err());
    }

    #[tokio::test]
    async fn per_socket_cap_closes_the_extra_connection() {
        use tokio::net::windows::named_pipe::ClientOptions;

        let tmp = std::env::temp_dir();
        let mut listener = AgentListener::create_with_cap(&tmp, 1).expect("create");
        let name = listener.auth_sock().to_path_buf();
        let _c1 = ClientOptions::new().open(&name).expect("c1");
        let _a1 = listener.accept().await.expect("a1");
        let _c2 = ClientOptions::new().open(&name).expect("c2");
        let waiting =
            tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept()).await;
        assert!(waiting.is_err());
        assert_eq!(listener.stats().refused_cap, 1);
    }
}

/// ADR-0055 decision 22 B48: the host's agent endpoint is reachable by its
/// owner only. Unix: a 0700 directory owned by this user holds a 0600 socket
/// owned by this user, a connection from this user is accepted, and a peer
/// with any other uid would not be. Windows: every instance of the pipe has a
/// protected DACL that grants only the owner, remote clients are rejected, and
/// nobody else can claim the first instance of the name.
#[tokio::test]
async fn agent_socket_is_owner_only() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        // SAFETY: `geteuid(2)` takes no arguments, touches no memory and
        // cannot fail.
        let euid = unsafe { libc::geteuid() };
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut listener = AgentListener::create(tmp.path()).expect("create");
        let sock = listener.auth_sock().to_path_buf();
        let dir = sock.parent().expect("parent").to_path_buf();

        let dir_meta = std::fs::symlink_metadata(&dir).expect("dir metadata");
        assert!(dir_meta.is_dir());
        assert_eq!(dir_meta.uid(), euid);
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
        let sock_meta = std::fs::symlink_metadata(&sock).expect("socket metadata");
        assert_eq!(sock_meta.uid(), euid);
        assert_eq!(sock_meta.permissions().mode() & 0o777, 0o600);

        // The accepted peer is checked by uid: ours passes.
        let client = tokio::net::UnixStream::connect(&sock)
            .await
            .expect("connect as the owner");
        let peer = client.peer_cred().expect("peer credentials");
        assert_eq!(peer.uid(), euid);
        let _served = listener.accept().await.expect("the owner is accepted");
        assert_eq!(listener.stats().accepted, 1);
        let other = euid.wrapping_add(1);
        assert!(crate::localctl::transport::peer_is_authorized(euid, euid));
        assert!(!crate::localctl::transport::peer_is_authorized(other, euid));
        assert!(!crate::localctl::transport::peer_is_authorized(0, 1000));
    }
    #[cfg(windows)]
    {
        use crate::fsutil::dacl::ObjectKind;
        use crate::fsutil::dacl::testing::{assert_owner_only_report, read_dacl_of_handle};
        use crate::localctl::transport::windows::CreateOptions;
        use tokio::net::windows::named_pipe::ClientOptions;

        let name =
            std::path::PathBuf::from(format!(r"\\.\pipe\qsh-agent-test-{}", random_hex_name()));
        let mut listener = AgentListener::bind_at(&name, 16).expect("bind");
        assert_owner_only_report(
            "the first agent pipe instance",
            read_dacl_of_handle(listener.waiting_handle().cast()),
            ObjectKind::Pipe,
        );
        let client = ClientOptions::new()
            .open(&name)
            .expect("connect as the owner");
        let served = listener.accept().await.expect("the owner is accepted");
        assert_owner_only_report(
            "the next agent pipe instance",
            read_dacl_of_handle(listener.waiting_handle().cast()),
            ObjectKind::Pipe,
        );
        drop((client, served));
        for first in [true, false] {
            let options = CreateOptions::for_instance(first);
            assert!(options.reject_remote_clients, "first_instance = {first}");
        }
        assert!(
            AgentListener::bind_at(&name, 16).is_err(),
            "the name cannot be claimed twice"
        );
    }
}
