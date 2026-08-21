//! CLI-process side of localctl: connect to a resident `qsh listen`
//! daemon's UDS socket, speak the `LOCAL_ADMIN` conduit, and (for a later
//! step's host-specific routing) discover *which* daemon on this machine
//! knows a given host by trying each of this machine's sockets in turn
//! (`docs/design/protocol.md` §11-3, `docs/design/architecture.md` §7
//! "런타임 소켓 discovery", `PLAN.md` M3 Step 5).
//!
//! Deliberately transport-free (`crate::localctl` module docs): this file
//! must never name `qsh_transport`, `quinn` or `rustls` —
//! `xtask/src/arch.rs`'s `ModuleBan` enforces exactly that trio for this
//! file mechanically. It also never names `crate::client`/
//! `crate::Principal`/`crate::Fingerprint`, but that is true by
//! construction (this file never touches a live connection or a
//! principal), not a fourth-through-sixth token arch-lint separately
//! checks here — see `crate::localctl` module docs for which files get the
//! full six-token set and why. Holding any of the six is the daemon side's
//! business (`daemon.rs`, a later step), which bridges a `LOCAL_CONTROL`
//! conduit onto a live reverse QUIC connection.

use std::io;
use std::path::{Path, PathBuf};

use qsh_proto::ErrorCode;
use qsh_proto::local::{
    LOCAL_HELLO_VERSION, LocalError, LocalHello, LocalHost, LocalHostList, LocalHostListResult,
    LocalResponse, LocalStreamKind, local_response,
};
use tokio::net::UnixStream;

use crate::localctl::frame::LocalConduit;
use crate::ops::OpError;

/// Open a `LOCAL_ADMIN` conduit to the daemon listening on `socket_path`
/// and return its current reverse-host registrations
/// (`docs/design/protocol.md` §11-3's `LocalHostList`/`LocalHostListResult`
/// round trip).
///
/// This talks to exactly the one socket named — it does not retry and does
/// not consult [`discover`]. "Try every socket on this machine and merge
/// the results" is `Ops::host_list`'s job (PR 5b), built on top of this and
/// [`candidate_sockets`].
pub async fn admin_host_list(socket_path: &Path) -> Result<Vec<LocalHost>, OpError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| io_error("connect", socket_path, &err))?;
    admin_host_list_over(stream).await
}

/// Same exchange as [`admin_host_list`], over an already-connected
/// conduit. Split out so tests — and, later, [`discover`] probes for
/// PR 5b/Step 6's host-specific routing — can drive the `LOCAL_ADMIN`
/// exchange without going through a real `connect(2)` first.
pub async fn admin_host_list_over(stream: UnixStream) -> Result<Vec<LocalHost>, OpError> {
    match tokio::time::timeout(PROBE_TIMEOUT, admin_host_list_over_inner(stream)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            format!(
                "localctl: daemon accepted the conduit but never answered LocalHostList within \
                 {PROBE_TIMEOUT:?}"
            ),
        )),
    }
}

async fn admin_host_list_over_inner(stream: UnixStream) -> Result<Vec<LocalHost>, OpError> {
    let mut conduit = LocalConduit::new(stream);
    conduit
        .send(&LocalHello {
            version: LOCAL_HELLO_VERSION,
            kind: LocalStreamKind::LocalAdmin as i32,
            host: String::new(), // ignored for LOCAL_ADMIN (qsh/local/v1.proto)
            wait_ms: 0,          // a local admin query never needs to wait
        })
        .await?;
    conduit.send(&LocalHostList {}).await?;

    let response: LocalResponse = conduit.recv().await?.ok_or_else(|| {
        OpError::new(
            ErrorCode::ConnectionFailed,
            "localctl: daemon closed the conduit without answering LocalHostList",
        )
    })?;
    match response.body {
        Some(local_response::Body::HostListResult(LocalHostListResult { hosts })) => Ok(hosts),
        Some(local_response::Body::Error(err)) => Err(remote_error(err)),
        _ => Err(OpError::new(
            ErrorCode::ConnectionFailed,
            "localctl: daemon answered LocalHostList with an unexpected response",
        )),
    }
}

/// Convert a `LocalError` the daemon sent us into an [`OpError`], preserving
/// its code and message verbatim — `code` is already drawn from the shared
/// `docs/CLI.md` §3.3 vocabulary (`qsh.local/v1.proto`'s `LocalError` doc
/// comment), so there is nothing to translate.
fn remote_error(err: LocalError) -> OpError {
    OpError::new(err.error_code(), err.message)
}

fn io_error(step: &str, path: &Path, err: &io::Error) -> OpError {
    OpError::new(
        ErrorCode::ConnectionFailed,
        format!("localctl: {step} {}: {err}", path.display()),
    )
}

/// This machine's localctl sockets, named `<pid>.sock`
/// (`docs/design/architecture.md` §7), in pid-ascending order. A missing
/// runtime directory (no daemon has ever bound a socket here) yields an
/// empty list, not an error — that is the normal "no `qsh listen` running"
/// state. Entries that are not `<digits>.sock` are silently skipped: the
/// runtime directory is not exclusively ours to police.
pub fn candidate_sockets(runtime_dir: &Path) -> io::Result<Vec<(u32, PathBuf)>> {
    let entries = match std::fs::read_dir(runtime_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if let Some(pid) = socket_pid(&path) {
            out.push((pid, path));
        }
    }
    out.sort_by_key(|(pid, _)| *pid);
    Ok(out)
}

fn socket_pid(path: &Path) -> Option<u32> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("sock") {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}

/// What one candidate daemon said in answer to a [`discover`] probe.
pub enum DiscoverOutcome<T> {
    /// This daemon answered with what the caller was looking for — stop
    /// searching and return this value.
    Found(T),
    /// This daemon doesn't have it (e.g. its own `HOST_NOT_FOUND` answer)
    /// — move on to the next socket.
    NotFound,
}

/// Try this machine's localctl sockets in pid-ascending order until one
/// answers [`DiscoverOutcome::Found`] — the discovery mechanism
/// `docs/design/protocol.md` §11-3 and `docs/design/architecture.md` §7
/// describe, built generic over *what* is being asked for so it is ready
/// for PR 5b/Step 6's host-specific routing (the concrete probe that opens
/// a `LOCAL_CONTROL` conduit for one host name and reads back
/// `LocalHelloAck` vs a `HOST_NOT_FOUND` `LocalError`) without this loop
/// changing shape when that lands. `probe` receives one already-connected
/// stream per candidate and decides continue-or-stop; this function owns
/// everything about *which* socket to try and in what order.
///
/// - A candidate whose connection is refused (`ECONNREFUSED` — the daemon
///   that bound it has already exited) is unlinked and skipped, exactly
///   like a crashed daemon's stale pid file.
/// - Any other failure to connect, or any error `probe` itself returns,
///   also moves on to the next candidate rather than aborting the whole
///   search — one unreachable or misbehaving daemon must not hide the
///   others (`docs/CLI.md` §6.2's "부분 실패를 감추지 않는다" discipline
///   applied to discovery: a bad daemon doesn't get to hide the good
///   ones).
/// - Every candidate exhausted (or none exist) ⇒ [`ErrorCode::HostNotFound`]
///   (`docs/design/architecture.md` §7: "전부 실패하면 `HOST_NOT_FOUND`다").
pub async fn discover<T>(
    runtime_dir: &Path,
    mut probe: impl AsyncFnMut(UnixStream) -> Result<DiscoverOutcome<T>, OpError>,
) -> Result<T, OpError> {
    let candidates =
        candidate_sockets(runtime_dir).map_err(|err| io_error("list", runtime_dir, &err))?;
    for (pid, sock) in candidates {
        match tokio::time::timeout(PROBE_TIMEOUT, UnixStream::connect(&sock)).await {
            Ok(Ok(stream)) => {
                match tokio::time::timeout(PROBE_TIMEOUT, probe(stream)).await {
                    Ok(Ok(DiscoverOutcome::Found(value))) => return Ok(value),
                    Ok(Ok(DiscoverOutcome::NotFound)) => {
                        tracing::debug!(pid, "localctl discover: candidate said not-found");
                        continue;
                    }
                    Ok(Err(err)) => {
                        tracing::debug!(pid, %err, "localctl discover: candidate probe failed");
                        continue;
                    }
                    Err(_elapsed) => {
                        // A daemon that accepted but never answered would
                        // otherwise wedge every remaining candidate behind
                        // it forever — one misbehaving daemon must not
                        // hide the others (this function's own doc, and
                        // `docs/CLI.md` §6.2). Its socket is left alone:
                        // an unresponsive-but-connectable daemon is not
                        // provably dead, so nothing here unlinks it.
                        tracing::warn!(
                            pid,
                            "localctl discover: candidate accepted but never answered within {:?}; skipping",
                            PROBE_TIMEOUT
                        );
                        continue;
                    }
                }
            }
            Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
                // ECONNREFUSED is *not* proof the daemon is dead: on
                // macOS/BSD a live listener whose accept backlog is full
                // reports it exactly this way, and even on Linux a
                // just-`bind`-not-yet-`listen`ing socket can produce it
                // for an instant. Only unlink when the pid the socket's
                // own filename names (`<pid>.sock`,
                // `docs/design/architecture.md` §7) is actually gone —
                // `kill(pid, 0)` returning `ESRCH` is the one thing that
                // proves that (adversarial review finding: unconditional
                // unlink here could delete a live, merely-busy daemon's
                // socket, permanently orphaning it from `qsh hosts` and
                // Step 6 routing until a manual restart).
                if process_is_verifiably_dead(pid) {
                    let _ = std::fs::remove_file(&sock);
                } else {
                    tracing::debug!(
                        pid,
                        "localctl discover: connection refused but pid {pid} is still alive; \
                         leaving its socket in place"
                    );
                }
                continue;
            }
            Ok(Err(err)) => {
                tracing::debug!(pid, %err, "localctl discover: could not connect to candidate");
                continue;
            }
            Err(_elapsed) => {
                // `connect(2)` on a UDS does not block on the network, so
                // this branch is defensive rather than expected — but a
                // stuck connect must not be able to wedge discovery any
                // more than a stuck probe can.
                tracing::warn!(pid, "localctl discover: connect to candidate timed out");
                continue;
            }
        }
    }
    Err(OpError::new(
        ErrorCode::HostNotFound,
        "no daemon on this machine has that host registered",
    ))
}

/// Bound on how long [`discover`] waits for any single candidate's
/// `connect`/probe round trip before moving on — the ceiling
/// `qsh_proto::local::LOCAL_WAIT_MAX` already defines for "a caller must
/// not be able to pin a daemon slot open indefinitely" (`qsh/local/v1.proto`),
/// reused here for the symmetric client-side guarantee: no single candidate
/// may pin *discovery itself* open indefinitely.
const PROBE_TIMEOUT: std::time::Duration = qsh_proto::local::LOCAL_WAIT_MAX;

/// Whether the process named by `pid` — the pid `<pid>.sock`'s own
/// filename already carries — is provably gone, via `kill(pid, 0)`
/// (`man 2 kill`: signal `0` performs no signal delivery, only the
/// existence/permission check). Only `ESRCH` ("no such process") counts as
/// proof of death; a permission error (`EPERM`, a different uid holding
/// that pid — impossible for a genuine same-user daemon, but not this
/// function's job to assume) or success (the process exists) both leave
/// the socket alone, because unlinking a live daemon's socket is
/// unrecoverable for that process's lifetime while leaving a truly stale
/// one costs nothing but a retry on the next discovery pass.
fn process_is_verifiably_dead(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        // A pid that doesn't fit `pid_t` can't name a live process on this
        // machine either way; treat it as dead so a garbage filename
        // doesn't linger forever.
        return true;
    };
    // SAFETY: `kill` with signal `0` sends no signal; it only performs the
    // existence/permission check documented above, and touches no memory
    // this function does not own.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return false; // the signal would have been delivered: pid exists.
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use tokio::net::UnixListener;

    use super::*;

    fn sample_host(name: &str) -> LocalHost {
        LocalHost {
            name: name.to_string(),
            address: "203.0.113.5:51820".to_string(),
            state: "reachable".to_string(),
            fingerprint: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            capabilities: vec!["pty".to_string()],
            generation: 1,
            registered_at: "2026-08-22T00:00:00Z".to_string(),
        }
    }

    /// Spawn a one-shot fake daemon on `path`: reads a `LocalHello` +
    /// `LocalHostList` request off `LOCAL_ADMIN`, and answers with
    /// whatever `LocalResponse` body the caller supplies. No real `qsh
    /// listen` process anywhere in these tests — this is `docs/design/
    /// testing.md` L2 "no real daemon needed" for the discovery/framing
    /// contract, not an L3 harness.
    fn spawn_fake_admin_daemon(
        listener: UnixListener,
        body: local_response::Body,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let mut conduit = LocalConduit::new(stream);
            let hello: LocalHello = conduit.recv().await.unwrap().unwrap();
            assert_eq!(hello.kind, LocalStreamKind::LocalAdmin as i32);
            let _req: LocalHostList = conduit.recv().await.unwrap().unwrap();
            conduit
                .send(&LocalResponse { body: Some(body) })
                .await
                .unwrap();
        })
    }

    #[tokio::test]
    async fn admin_host_list_round_trips_through_a_fake_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("100.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let expected = vec![sample_host("personal-mac")];
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let hosts = admin_host_list(&sock).await.unwrap();
        assert_eq!(hosts, expected);
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn admin_host_list_surfaces_a_remote_error_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("101.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::HostNotFound,
                "no such registration",
            )),
        );

        let err = admin_host_list(&sock).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert_eq!(err.message, "no such registration");
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn admin_host_list_over_a_socket_nothing_is_listening_on_fails_connection() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("102.sock");
        // Never bound at all — plain ENOENT, not ECONNREFUSED, but either
        // way `admin_host_list` (unlike `discover`) surfaces the failure
        // rather than silently treating it as "not found".
        let err = admin_host_list(&sock).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
    }

    #[test]
    fn candidate_sockets_are_sorted_ascending_by_pid_and_skip_non_matching_names() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "20.sock",
            "3.sock",
            "100.sock",
            "notasocket.txt",
            "abc.sock",
        ] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }

        let found = candidate_sockets(dir.path()).unwrap();
        let pids: Vec<u32> = found.iter().map(|(pid, _)| *pid).collect();
        assert_eq!(pids, vec![3, 20, 100]);
        assert_eq!(found[0].1, dir.path().join("3.sock"));
    }

    // ---- liveness check backing the `ECONNREFUSED` unlink decision ----

    #[test]
    fn process_is_verifiably_dead_distinguishes_a_live_pid_from_a_reaped_one() {
        assert!(
            !process_is_verifiably_dead(std::process::id()),
            "this test's own process must never be reported dead"
        );
        assert!(
            process_is_verifiably_dead(a_definitely_dead_pid()),
            "a spawned-and-reaped child's pid must be reported dead"
        );
    }

    // ---- bounded waits (`discover`/`admin_host_list_over` must never hang
    // forever on one misbehaving daemon) ----

    #[tokio::test(start_paused = true)]
    async fn admin_host_list_over_a_daemon_that_never_answers_times_out_instead_of_hanging() {
        let (client_end, _daemon_end) = UnixStream::pair().unwrap();
        // `_daemon_end` is held open (accepted the conduit) but never read
        // or written to — the "daemon wedged after accept" shape a
        // deadline must catch, since it is neither a connect failure nor a
        // clean close. `start_paused` auto-advances virtual time past the
        // timeout the instant nothing else is runnable, so this proves the
        // deadline fires without an real wall-clock wait.
        let err = admin_host_list_over(client_end).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::ConnectionFailed);
    }

    #[tokio::test(start_paused = true)]
    async fn discover_moves_past_a_silent_daemon_instead_of_hanging_on_it_forever() {
        let dir = tempfile::tempdir().unwrap();
        let silent = dir.path().join("7.sock");
        let healthy = dir.path().join("8.sock");

        let silent_listener = UnixListener::bind(&silent).unwrap();
        let silent_daemon = tokio::spawn(async move {
            let (_stream, _addr) = silent_listener.accept().await.unwrap();
            // Accept the conduit, then never read or write anything —
            // exactly the daemon-wedged-after-accept scenario `discover`'s
            // own doc promises "one misbehaving daemon must not hide the
            // others" against.
            std::future::pending::<()>().await
        });

        let healthy_listener = UnixListener::bind(&healthy).unwrap();
        let expected = vec![sample_host("found-on-healthy")];
        let healthy_daemon = spawn_fake_admin_daemon(
            healthy_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        // pid-ascending order visits the silent "7.sock" before the
        // healthy "8.sock"; without a deadline this call never returns.
        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, expected);

        silent_daemon.abort();
        healthy_daemon.await.unwrap();
    }

    // ---- `discover` must never unlink a live daemon's socket ----

    #[tokio::test]
    async fn discover_does_not_unlink_a_refused_socket_whose_pid_is_still_alive() {
        let dir = tempfile::tempdir().unwrap();
        // Named after *this test process's own pid* — by construction
        // alive for the whole test — to prove `discover` consults
        // liveness rather than treating every `ECONNREFUSED` as proof of
        // death (adversarial review finding: a live daemon whose accept
        // backlog is full, or that is caught between `bind` and `listen`,
        // answers `ECONNREFUSED` too).
        let live_pid = std::process::id();
        let refused = dir.path().join(format!("{live_pid}.sock"));
        {
            // Bind then immediately drop the listener: the socket file
            // stays on disk, but nothing is listening any more, so a
            // connect to it now fails `ECONNREFUSED` — the same wire
            // symptom a full accept backlog on a genuinely live daemon
            // would produce, deliberately reused here for a
            // process-inspection-only assertion (this test cannot
            // actually fill an OS accept backlog deterministically).
            let _listener = UnixListener::bind(&refused).unwrap();
        }
        assert!(refused.exists());

        let err = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
        assert!(
            refused.exists(),
            "a socket named after a still-alive pid must never be unlinked on ECONNREFUSED alone"
        );
    }

    #[test]
    fn candidate_sockets_on_a_missing_runtime_dir_is_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert_eq!(candidate_sockets(&missing).unwrap(), Vec::new());
    }

    /// Turn `admin_host_list_over`'s result into a [`DiscoverOutcome`] the
    /// way a real host-routing probe eventually will: a clean answer is
    /// `Found`, the daemon's own `HOST_NOT_FOUND` is `NotFound`, anything
    /// else propagates as an error `discover` will skip past.
    async fn probe_via_admin_host_list(
        stream: UnixStream,
    ) -> Result<DiscoverOutcome<Vec<LocalHost>>, OpError> {
        match admin_host_list_over(stream).await {
            Ok(hosts) => Ok(DiscoverOutcome::Found(hosts)),
            Err(err) if err.code == ErrorCode::HostNotFound => Ok(DiscoverOutcome::NotFound),
            Err(err) => Err(err),
        }
    }

    /// A pid this test can prove is dead right now (spawn a trivial child,
    /// wait for it to exit) — the one thing `discover`'s liveness check
    /// actually trusts before unlinking an `ECONNREFUSED` candidate. A
    /// hardcoded low pid like `1` (`init`/`launchd`, always alive) is not
    /// safe to use for a "stale" candidate any more now that `discover`
    /// verifies liveness rather than unlinking on `ECONNREFUSED` alone
    /// (adversarial review finding).
    fn a_definitely_dead_pid() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn a short-lived helper process");
        let status = child.wait().expect("wait for the helper process to exit");
        assert!(status.success(), "helper process must exit cleanly");
        child.id()
    }

    #[tokio::test]
    async fn discover_unlinks_a_refused_stale_socket_and_finds_the_next_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let dead_pid = a_definitely_dead_pid();
        let stale = dir.path().join(format!("{dead_pid}.sock"));
        // `dead_pid + 1` sorts immediately after it by construction, so
        // pid-ascending discovery is guaranteed to visit the stale
        // candidate first regardless of what `dead_pid` actually is.
        let live = dir.path().join(format!("{}.sock", dead_pid + 1));

        // A socket file with no listener behind it: bind, then drop the
        // listener immediately. The special file stays on disk; connecting
        // to it now fails ECONNREFUSED — exactly a crashed daemon's leftover.
        {
            let _listener = UnixListener::bind(&stale).unwrap();
        }
        assert!(stale.exists(), "the stale socket file must still exist");

        let listener = UnixListener::bind(&live).unwrap();
        let expected = vec![sample_host("phone")];
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, expected);
        assert!(
            !stale.exists(),
            "the refused stale socket must be unlinked during discovery"
        );
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn discover_tries_candidates_in_pid_ascending_order() {
        let dir = tempfile::tempdir().unwrap();
        let lower = dir.path().join("5.sock");
        let higher = dir.path().join("50.sock");

        let lower_hosts = vec![sample_host("lower-answered")];
        let higher_hosts = vec![sample_host("higher-answered")];

        let lower_listener = UnixListener::bind(&lower).unwrap();
        let higher_listener = UnixListener::bind(&higher).unwrap();
        let lower_daemon = spawn_fake_admin_daemon(
            lower_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: lower_hosts.clone(),
            }),
        );
        let higher_daemon = spawn_fake_admin_daemon(
            higher_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: higher_hosts,
            }),
        );

        // Both candidates would answer `Found` — if discovery visited
        // pid-descending (or arbitrary directory order) it could just as
        // easily return the higher-pid daemon's answer. Getting the
        // lower-pid one back is the only outcome consistent with
        // pid-ascending order and "stop at the first `Found`".
        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, lower_hosts);

        lower_daemon.await.unwrap();
        // The higher-pid daemon is never dialed once the lower one answers
        // `Found` — nothing to await there but its accept() never completes,
        // which is exactly the point; drop it without joining.
        higher_daemon.abort();
    }

    #[tokio::test]
    async fn discover_moves_past_daemons_that_say_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("10.sock");
        let second = dir.path().join("11.sock");

        let first_listener = UnixListener::bind(&first).unwrap();
        let second_listener = UnixListener::bind(&second).unwrap();
        let first_daemon = spawn_fake_admin_daemon(
            first_listener,
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::HostNotFound,
                "unknown host",
            )),
        );
        let expected = vec![sample_host("found-on-second")];
        let second_daemon = spawn_fake_admin_daemon(
            second_listener,
            local_response::Body::HostListResult(LocalHostListResult {
                hosts: expected.clone(),
            }),
        );

        let hosts = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap();
        assert_eq!(hosts, expected);
        first_daemon.await.unwrap();
        second_daemon.await.unwrap();
    }

    #[tokio::test]
    async fn discover_exhausted_is_host_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let only = dir.path().join("42.sock");
        let listener = UnixListener::bind(&only).unwrap();
        let daemon = spawn_fake_admin_daemon(
            listener,
            local_response::Body::Error(LocalError::from_code(
                ErrorCode::HostNotFound,
                "unknown host",
            )),
        );

        let err = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
        daemon.await.unwrap();
    }

    #[tokio::test]
    async fn discover_with_no_candidates_at_all_is_host_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = discover(dir.path(), probe_via_admin_host_list)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::HostNotFound);
    }
}
