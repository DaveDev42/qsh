//! L5 — `qsh cp` end to end (ADR-0029, `docs/CLI.md` §6.21), M15 plan Step 14 (1a4af3b).
//!
//! Real processes, no fakes: a `qsh serve` host (forward route) or a
//! `qsh listen` controller plus a `qsh serve --to` target (reverse route,
//! where the FILE_DATA bytes go through the controller's localctl daemon
//! relay), and the `qsh cp` client as a subprocess.
//!
//! The host authorizes file actions from the pin's role (ADR-0045), so the
//! host pins the client with `--role full`; the stock `acl.toml` planted by
//! `ServeGuard` has no file rows and none are needed.

#![cfg(unix)]

use crate::common;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use common::{
    CLIENT_ALIAS, HOST_ALIAS, ListenGuard, ReverseGuard, Sandbox, ServeGuard, exit_code,
    hosts_array, poll_until,
};
use serde_json::Value;
use sha2::Digest as _;

/// An isolated forward rig: a serving host that pins the client with the
/// `full` role, and a client that pins the host by address.
pub(crate) struct Forward {
    pub(crate) client: Sandbox,
    _host: Sandbox,
    _serve: ServeGuard,
    pub(crate) work: tempfile::TempDir,
}

impl Forward {
    pub(crate) fn start() -> Self {
        let host = Sandbox::initialized();
        let client = Sandbox::initialized();
        host.trust_add_with_role(CLIENT_ALIAS, None, &client.fingerprint(), "full");
        let serve = ServeGuard::start(&host);
        client.trust_add(HOST_ALIAS, Some(serve.addr()), &host.fingerprint());
        Self {
            client,
            _host: host,
            _serve: serve,
            work: tempfile::tempdir().expect("work dir"),
        }
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    pub(crate) fn remote(&self, name: &str) -> String {
        format!("{HOST_ALIAS}:{}", self.path(name).display())
    }

    pub(crate) fn cp(&self, args: &[&str]) -> Output {
        let mut argv = vec!["cp"];
        argv.extend_from_slice(args);
        self.client.qsh(&argv)
    }

    pub(crate) fn cp_json(&self, args: &[&str]) -> (i32, Value) {
        let mut argv = vec!["cp", "--json"];
        argv.extend_from_slice(args);
        self.client.json(&argv)
    }
}

/// A reverse rig. The client runs from the controller's own sandbox so it
/// finds the controller's localctl daemon, which relays FILE_DATA to the
/// target (`docs/design/architecture.md` §7).
pub(crate) struct Reverse {
    pub(crate) controller: Sandbox,
    _target: Sandbox,
    _listen: ListenGuard,
    _reverse: ReverseGuard,
    pub(crate) work: tempfile::TempDir,
}

pub(crate) const TARGET_NAME: &str = "nat-target";
pub(crate) const CONTROLLER_ALIAS: &str = "hub";

impl Reverse {
    pub(crate) fn start() -> Self {
        let controller = Sandbox::initialized();
        let target = Sandbox::initialized();
        controller.trust_add(TARGET_NAME, None, &target.fingerprint());
        let listen = ListenGuard::start(&controller);
        target.trust_add_with_role(
            CONTROLLER_ALIAS,
            Some(listen.addr()),
            &controller.fingerprint(),
            "full",
        );
        let reverse = ReverseGuard::start_serve_to(&target, CONTROLLER_ALIAS);
        poll_until(
            "the reverse registration to appear reachable",
            Duration::from_secs(20),
            || {
                hosts_array(&controller)
                    .iter()
                    .any(|h| {
                        h["name"] == TARGET_NAME
                            && h["connection_mode"] == "reverse"
                            && h["state"] == "reachable"
                    })
                    .then_some(())
            },
        );
        Self {
            controller,
            _target: target,
            _listen: listen,
            _reverse: reverse,
            work: tempfile::tempdir().expect("work dir"),
        }
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    pub(crate) fn remote(&self, name: &str) -> String {
        format!("{TARGET_NAME}:{}", self.path(name).display())
    }

    pub(crate) fn cp_json(&self, args: &[&str]) -> (i32, Value) {
        let mut argv = vec!["cp", "--json"];
        argv.extend_from_slice(args);
        self.controller.json(&argv)
    }
}

/// A deterministic pseudo-random byte stream (splitmix64), so a 64 MiB file
/// costs no extra dependency and an accidental all-zero or repeating
/// pattern cannot hide a reordered chunk.
pub(crate) fn write_random_file(path: &Path, len: usize, seed: u64) {
    let mut state = seed;
    let mut file = std::fs::File::create(path).expect("create random file");
    let mut written = 0usize;
    let mut chunk = vec![0u8; 1 << 20];
    while written < len {
        let take = chunk.len().min(len - written);
        for word in chunk[..take].chunks_mut(8) {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            word.copy_from_slice(&bytes[..word.len()]);
        }
        file.write_all(&chunk[..take]).expect("write random file");
        written += take;
    }
    file.sync_all().expect("sync random file");
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// BLAKE3 and SHA-256 of a file, streamed.
pub(crate) fn digests(path: &Path) -> (String, String) {
    let mut file = std::fs::File::open(path).expect("open for hashing");
    let mut blake = blake3::Hasher::new();
    let mut sha = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).expect("read for hashing");
        if n == 0 {
            break;
        }
        blake.update(&buf[..n]);
        sha.update(&buf[..n]);
    }
    (blake.finalize().to_hex().to_string(), hex(&sha.finalize()))
}

pub(crate) fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Remove the `.<name>.qsh-<hex>.part` leftovers check: no temp file may
/// stay behind in `dir`.
pub(crate) fn assert_no_part_files(dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.ends_with(".part"),
            "a temp file was left behind in {}: {name}",
            dir.display()
        );
    }
}

/// put then get a large file over `rig`, comparing both hashes at every hop.
pub(crate) fn round_trip(
    work: &Path,
    put_dst: &str,
    get_src: &str,
    run: impl Fn(&[&str]) -> (i32, Value),
) {
    const LEN: usize = 64 * 1024 * 1024 + 12_345;
    let original = work.join("original.bin");
    write_random_file(&original, LEN, 0x5EED_0001);
    let (blake, sha) = digests(&original);

    let (code, put) = run(&[original.to_str().unwrap(), put_dst]);
    assert_eq!(code, 0, "put failed: {put}");
    assert_eq!(put["data"]["direction"], "put", "{put}");
    assert_eq!(put["data"]["files"], 1, "{put}");
    assert_eq!(put["data"]["bytes"], LEN as u64, "{put}");
    assert_eq!(put["data"]["entries"][0]["blake3"], blake, "{put}");

    let back = work.join("back.bin");
    let (code, get) = run(&[get_src, back.to_str().unwrap()]);
    assert_eq!(code, 0, "get failed: {get}");
    assert_eq!(get["data"]["direction"], "get", "{get}");
    assert_eq!(get["data"]["bytes"], LEN as u64, "{get}");
    assert_eq!(get["data"]["entries"][0]["blake3"], blake, "{get}");

    assert_eq!(
        std::fs::metadata(&back).expect("stat back").len(),
        LEN as u64
    );
    assert_eq!(digests(&back), (blake, sha), "round trip changed the bytes");
    assert_no_part_files(work);
}

#[test]
fn file_round_trip_is_byte_identical_forward() {
    let rig = Forward::start();
    let dst = rig.remote("stored.bin");
    round_trip(rig.work.path(), &dst, &dst, |args| rig.cp_json(args));
    // The host really holds the bytes in the middle: its copy is the same.
    assert_eq!(
        digests(&rig.path("stored.bin")),
        digests(&rig.path("original.bin"))
    );
}

#[test]
fn file_round_trip_is_byte_identical_reverse() {
    // The FILE_DATA stream of both directions runs through the controller's
    // localctl daemon relay (ADR-0029 decision 16), end to end.
    let rig = Reverse::start();
    let dst = rig.remote("stored.bin");
    round_trip(rig.work.path(), &dst, &dst, |args| rig.cp_json(args));
    assert_eq!(
        digests(&rig.path("stored.bin")),
        digests(&rig.path("original.bin"))
    );
}

#[test]
fn cp_remote_to_remote_is_invalid_argument() {
    let rig = Forward::start();
    let output = rig.cp(&["box:/a", "box:/b"]);
    assert_eq!(exit_code(&output), 2, "{}", stderr_of(&output));
    let (code, value) = rig.cp_json(&["box:/a", "box:/b"]);
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
}

#[test]
fn cp_mixed_operands_are_invalid_argument() {
    let rig = Forward::start();
    let local = rig.path("l");
    std::fs::write(&local, b"x").unwrap();
    // A local and a remote source, and a remote destination.
    let (code, value) = rig.cp_json(&[local.to_str().unwrap(), "box:/a", "box:/d"]);
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
    // Two local operands: neither is remote.
    let (code, value) = rig.cp_json(&[local.to_str().unwrap(), "./elsewhere"]);
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
    // Nothing was created on either side.
    assert!(!rig.path("r").exists() && !Path::new("./elsewhere").exists());
}

#[test]
fn cp_dash_operand_is_invalid_argument() {
    let rig = Forward::start();
    let (code, value) = rig.cp_json(&["-", &rig.remote("x")]);
    // `-` is not a flag either: it reaches the grammar and is refused there.
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
}

#[test]
fn cp_rejects_unsupported_scp_flags_with_exit_2() {
    let rig = Forward::start();
    let local = rig.path("l");
    std::fs::write(&local, b"x").unwrap();
    let remote = rig.remote("r");
    for flag in [
        &["-P", "22"][..],
        &["-i", "key"],
        &["-o", "StrictHostKeyChecking=no"],
        &["-F", "cfg"],
        &["-J", "jump"],
        &["-S", "ssh"],
        &["-c", "aes"],
        &["-l", "100"],
        &["-C"],
        &["-B"],
        &["-3"],
        &["-4"],
        &["-6"],
        &["-T"],
        &["-O"],
        &["-s"],
        &["-A"],
        &["-R"],
    ] {
        let mut args: Vec<&str> = flag.to_vec();
        args.push(local.to_str().unwrap());
        args.push(&remote);
        let output = rig.cp(&args);
        assert_eq!(
            exit_code(&output),
            2,
            "scp flag {flag:?} must exit 2, stderr: {}",
            stderr_of(&output)
        );
        assert!(
            output.stdout.is_empty(),
            "scp flag {flag:?} wrote to stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !rig.path("r").exists(),
            "scp flag {flag:?} copied something"
        );
    }
}

#[test]
fn cp_into_existing_directory_uses_the_source_name_get_and_put() {
    let rig = Forward::start();
    // put into an existing remote directory.
    let src = rig.path("name.txt");
    std::fs::write(&src, b"payload").unwrap();
    let remote_dir = rig.path("rdir");
    std::fs::create_dir(&remote_dir).unwrap();
    let (code, value) = rig.cp_json(&[src.to_str().unwrap(), &rig.remote("rdir")]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        std::fs::read(remote_dir.join("name.txt")).unwrap(),
        b"payload"
    );
    // The same with a trailing slash.
    let remote_dir2 = rig.path("rdir2");
    std::fs::create_dir(&remote_dir2).unwrap();
    let dst = format!("{}/", rig.remote("rdir2"));
    let (code, value) = rig.cp_json(&[src.to_str().unwrap(), &dst]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        std::fs::read(remote_dir2.join("name.txt")).unwrap(),
        b"payload"
    );

    // get into an existing local directory.
    let local_dir = rig.path("ldir");
    std::fs::create_dir(&local_dir).unwrap();
    let (code, value) = rig.cp_json(&[
        &format!("{HOST_ALIAS}:{}", remote_dir.join("name.txt").display()),
        local_dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        std::fs::read(local_dir.join("name.txt")).unwrap(),
        b"payload"
    );
    assert_no_part_files(&local_dir);
}

#[test]
fn cp_multiple_sources_require_an_existing_directory() {
    let rig = Forward::start();
    let a = rig.path("a.txt");
    let b = rig.path("b.txt");
    std::fs::write(&a, b"A").unwrap();
    std::fs::write(&b, b"B").unwrap();

    // Destination is not a directory (it does not exist): nothing is
    // written.
    let (code, value) = rig.cp_json(&[
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        &rig.remote("missing"),
    ]);
    // Both items fail on the host (`path is not a directory`), so the copy
    // ends 255 with INVALID_ARGUMENT as the first failure's code.
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
    assert_eq!(value["error"]["details"]["failed"], 2, "{value}");
    assert_eq!(value["error"]["details"]["copied"], 0, "{value}");
    assert!(!rig.path("missing").exists(), "{value}");

    // Into an existing directory both land.
    let dir = rig.path("dir");
    std::fs::create_dir(&dir).unwrap();
    let (code, value) =
        rig.cp_json(&[a.to_str().unwrap(), b.to_str().unwrap(), &rig.remote("dir")]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["files"], 2, "{value}");
    assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(dir.join("b.txt")).unwrap(), b"B");

    // Get with several sources into a missing local directory.
    let (code, value) = rig.cp_json(&[
        &rig.remote("dir/a.txt"),
        &rig.remote("dir/b.txt"),
        rig.path("no-such-local").to_str().unwrap(),
    ]);
    // The local destination is checked before anything is dialed: nothing
    // was fetched, so there is no per-item `details`.
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{value}");
    assert!(!rig.path("no-such-local").exists(), "{value}");
}

/// A name for a scratch file in the serve account's home directory that is
/// removed again however the test ends.
struct HomeFile {
    path: PathBuf,
    name: String,
}

impl HomeFile {
    fn new(tag: &str) -> Self {
        let home = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .expect("passwd lookup")
            .expect("a passwd entry for the test account")
            .dir;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(".qsh-cp-e2e-{tag}-{}-{nanos}", std::process::id());
        Self {
            path: home.join(&name),
            name,
        }
    }
}

impl Drop for HomeFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn cp_home_relative_paths_expand_against_the_serve_account() {
    let rig = Forward::start();
    let src = rig.path("src.txt");
    std::fs::write(&src, b"home bytes").unwrap();
    let home_file = HomeFile::new("home");

    // `host:name` is relative to the account's home, as is `host:~/name`.
    let (code, value) = rig.cp_json(&[
        src.to_str().unwrap(),
        &format!("{HOST_ALIAS}:{}", home_file.name),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(std::fs::read(&home_file.path).unwrap(), b"home bytes");

    // Read it back through the `~/` spelling and the bare-name spelling.
    for spelling in [
        format!("{HOST_ALIAS}:~/{}", home_file.name),
        format!("{HOST_ALIAS}:{}", home_file.name),
    ] {
        let back = rig.path("back.txt");
        let _ = std::fs::remove_file(&back);
        let (code, value) = rig.cp_json(&[&spelling, back.to_str().unwrap()]);
        assert_eq!(code, 0, "{spelling}: {value}");
        assert_eq!(std::fs::read(&back).unwrap(), b"home bytes", "{spelling}");
    }

    // `host:` alone is the home directory itself: copying into it uses the
    // source's name.
    let into_home = HomeFile {
        path: home_file.path.with_file_name("src.txt"),
        name: "src.txt".into(),
    };
    if !into_home.path.exists() {
        let (code, value) = rig.cp_json(&[src.to_str().unwrap(), &format!("{HOST_ALIAS}:")]);
        assert_eq!(code, 0, "{value}");
        assert_eq!(std::fs::read(&into_home.path).unwrap(), b"home bytes");
    }
}

#[test]
fn cp_tilde_user_is_invalid_argument() {
    let rig = Forward::start();
    let src = rig.path("src.txt");
    std::fs::write(&src, b"x").unwrap();
    for dst in [
        format!("{HOST_ALIAS}:~root/x"),
        format!("{HOST_ALIAS}:~someone/x"),
    ] {
        let (code, value) = rig.cp_json(&[src.to_str().unwrap(), &dst]);
        assert_ne!(code, 0, "{dst}: {value}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT", "{dst}: {value}");
    }
}

#[test]
fn cp_user_hint_mismatch_is_unsupported_after_acl() {
    let rig = Forward::start();
    let src = rig.path("src.txt");
    std::fs::write(&src, b"x").unwrap();
    let dst = format!(
        "definitely-not-the-serve-account@{HOST_ALIAS}:{}",
        rig.path("out.txt").display()
    );
    let (code, value) = rig.cp_json(&[src.to_str().unwrap(), &dst]);
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["error"]["code"], "UNSUPPORTED", "{value}");
    assert!(!rig.path("out.txt").exists());
}

#[test]
fn cp_preserve_sets_mode_and_mtime() {
    use std::os::unix::fs::PermissionsExt as _;
    let rig = Forward::start();
    let src = rig.path("pres.sh");
    std::fs::write(&src, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o751)).unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
    std::fs::File::options()
        .write(true)
        .open(&src)
        .unwrap()
        .set_modified(old)
        .unwrap();

    // put -p
    let (code, value) = rig.cp_json(&["-p", src.to_str().unwrap(), &rig.remote("put.sh")]);
    assert_eq!(code, 0, "{value}");
    let meta = std::fs::metadata(rig.path("put.sh")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o751);
    assert_eq!(meta.modified().unwrap(), old);

    // get -p
    let (code, value) = rig.cp_json(&[
        "-p",
        &rig.remote("put.sh"),
        rig.path("get.sh").to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{value}");
    let meta = std::fs::metadata(rig.path("get.sh")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o751);
    assert_eq!(meta.modified().unwrap(), old);
}

#[test]
fn cp_without_preserve_applies_the_umask() {
    use std::os::unix::fs::PermissionsExt as _;
    let rig = Forward::start();
    let mask = {
        let m = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        nix::sys::stat::umask(m);
        m.bits() as u32
    };
    let src = rig.path("plain.sh");
    std::fs::write(&src, b"x").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o777)).unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
    std::fs::File::options()
        .write(true)
        .open(&src)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let before = std::time::SystemTime::now();

    let (code, value) = rig.cp_json(&[src.to_str().unwrap(), &rig.remote("put.sh")]);
    assert_eq!(code, 0, "{value}");
    let meta = std::fs::metadata(rig.path("put.sh")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o777 & !mask);
    assert!(meta.modified().unwrap() >= before - Duration::from_secs(2));

    let (code, value) = rig.cp_json(&[&rig.remote("put.sh"), rig.path("get.sh").to_str().unwrap()]);
    assert_eq!(code, 0, "{value}");
    let meta = std::fs::metadata(rig.path("get.sh")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o777 & !mask);
    assert!(meta.modified().unwrap() >= before - Duration::from_secs(2));
}

#[test]
fn cp_no_clobber_skips_an_existing_destination_and_default_replaces_it() {
    let rig = Forward::start();
    let src = rig.path("src.txt");
    std::fs::write(&src, b"new").unwrap();
    std::fs::write(rig.path("dst.txt"), b"old").unwrap();

    let (code, value) = rig.cp_json(&[
        "--no-clobber",
        src.to_str().unwrap(),
        &rig.remote("dst.txt"),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["skipped"], 1, "{value}");
    assert_eq!(value["data"]["files"], 0, "{value}");
    assert_eq!(value["data"]["entries"][0]["status"], "skipped", "{value}");
    assert_eq!(value["data"]["entries"][0]["reason"], "exists", "{value}");
    assert_eq!(std::fs::read(rig.path("dst.txt")).unwrap(), b"old");

    // get side
    std::fs::write(rig.path("local.txt"), b"local-old").unwrap();
    let (code, value) = rig.cp_json(&[
        "--no-clobber",
        &rig.remote("dst.txt"),
        rig.path("local.txt").to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["skipped"], 1, "{value}");
    assert_eq!(std::fs::read(rig.path("local.txt")).unwrap(), b"local-old");

    // Without the flag the destination is replaced.
    let (code, value) = rig.cp_json(&[src.to_str().unwrap(), &rig.remote("dst.txt")]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["entries"][0]["overwritten"], true, "{value}");
    assert_eq!(std::fs::read(rig.path("dst.txt")).unwrap(), b"new");
}

#[test]
fn cp_partial_failure_exits_255_and_reports_failures() {
    let rig = Forward::start();
    let dir = rig.path("dir");
    std::fs::create_dir(&dir).unwrap();
    let good = rig.path("good.txt");
    std::fs::write(&good, b"good").unwrap();
    let missing = rig.path("missing.txt");
    let (code, value) = rig.cp_json(&[
        good.to_str().unwrap(),
        missing.to_str().unwrap(),
        &rig.remote("dir"),
    ]);
    // Local source missing: a local failure for that item, the other one
    // still copied.
    assert_eq!(code, 255, "{value}");
    assert_eq!(value["ok"], false, "{value}");
    let details = &value["error"]["details"];
    assert_eq!(details["copied"], 1, "{value}");
    assert_eq!(details["failed"], 1, "{value}");
    assert_eq!(details["not_attempted"], 0, "{value}");
    assert_eq!(details["failures"][0]["side"], "local", "{value}");
    // A missing source is INVALID_ARGUMENT (ADR-0029 decision 17).
    assert_eq!(
        details["failures"][0]["code"], "INVALID_ARGUMENT",
        "{value}"
    );
    assert_eq!(std::fs::read(dir.join("good.txt")).unwrap(), b"good");

    // Get side: one remote file missing, one present.
    let out = rig.path("out");
    std::fs::create_dir(&out).unwrap();
    let (code, value) = rig.cp_json(&[
        &rig.remote("dir/good.txt"),
        &rig.remote("dir/absent.txt"),
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 255, "{value}");
    let details = &value["error"]["details"];
    assert_eq!(details["copied"], 1, "{value}");
    assert_eq!(details["failed"], 1, "{value}");
    assert_eq!(details["failures"][0]["side"], "remote", "{value}");
    assert_eq!(
        details["failures"][0]["code"], "INVALID_ARGUMENT",
        "{value}"
    );
    assert_eq!(std::fs::read(out.join("good.txt")).unwrap(), b"good");
    assert_no_part_files(&out);
}

#[test]
fn cp_json_and_jsonl_report_every_entry() {
    let rig = Forward::start();
    let dir = rig.path("dir");
    std::fs::create_dir(&dir).unwrap();
    let mut sources = Vec::new();
    for i in 0..5 {
        let p = rig.path(&format!("f{i}.txt"));
        std::fs::write(&p, format!("file {i}")).unwrap();
        sources.push(p);
    }

    // --json: one envelope with every entry.
    let mut args: Vec<String> = sources.iter().map(|p| p.display().to_string()).collect();
    args.push(rig.remote("dir"));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, value) = rig.cp_json(&refs);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["host"], HOST_ALIAS, "{value}");
    assert_eq!(value["data"]["direction"], "put", "{value}");
    assert_eq!(value["data"]["files"], 5, "{value}");
    assert_eq!(value["data"]["entries_truncated"], false, "{value}");
    let entries = value["data"]["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 5, "{value}");
    for entry in entries {
        assert_eq!(entry["status"], "copied", "{entry}");
        assert_eq!(entry["kind"], "file", "{entry}");
        assert_eq!(entry["blake3"].as_str().unwrap().len(), 64, "{entry}");
    }

    // --jsonl: a `file.entry` line per item, then the envelope; stdout is
    // pure JSON lines.
    let mut argv = vec!["cp".to_string(), "--jsonl".to_string()];
    argv.extend(args.iter().cloned());
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = rig.client.qsh(&refs);
    assert_eq!(exit_code(&output), 0, "{}", stderr_of(&output));
    let lines: Vec<Value> = String::from_utf8(output.stdout)
        .expect("utf8 stdout")
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON: {l:?}: {e}")))
        .collect();
    assert_eq!(lines.len(), 6, "{lines:?}");
    for line in &lines[..5] {
        assert_eq!(line["schema"], "qsh.event/v1", "{line}");
        assert_eq!(line["type"], "file.entry", "{line}");
        assert_eq!(line["status"], "copied", "{line}");
    }
    let last = &lines[5];
    assert_eq!(last["ok"], true, "{last}");
    assert_eq!(last["data"]["files"], 5, "{last}");
    assert_eq!(
        last["data"]["entries"].as_array().map(Vec::len),
        Some(0),
        "a --jsonl run streams its entries instead of repeating them: {last}"
    );
}

#[test]
fn cp_get_refuses_an_existing_symlink_under_the_destination() {
    let rig = Forward::start();
    let victim = rig.path("victim.txt");
    std::fs::write(&victim, b"untouched").unwrap();
    let remote_dir = rig.path("rdir");
    std::fs::create_dir(&remote_dir).unwrap();
    std::fs::write(remote_dir.join("f.txt"), b"data").unwrap();

    // Into a directory whose `f.txt` is a symlink to the victim.
    let into = rig.path("into");
    std::fs::create_dir(&into).unwrap();
    std::os::unix::fs::symlink(&victim, into.join("f.txt")).unwrap();
    let (code, value) = rig.cp_json(&[&rig.remote("rdir/f.txt"), into.to_str().unwrap()]);
    assert_eq!(code, 255, "{value}");
    let failure = &value["error"]["details"]["failures"][0];
    assert_eq!(failure["side"], "local", "{value}");
    assert_eq!(failure["code"], "INVALID_ARGUMENT", "{value}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    assert!(
        std::fs::symlink_metadata(into.join("f.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // The destination the user typed is followed (ADR-0029 decision 7): a
    // symlink given as DST is written through, and stays a symlink.
    let leaf = rig.path("leaf-link");
    std::os::unix::fs::symlink(&victim, &leaf).unwrap();
    let (code, value) = rig.cp_json(&[&rig.remote("rdir/f.txt"), leaf.to_str().unwrap()]);
    assert_eq!(code, 0, "{value}");
    assert!(
        std::fs::symlink_metadata(&leaf)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"data");
    assert_no_part_files(&into);
    assert_no_part_files(rig.work.path());
}

/// `file.copy` is local only: it is the client stringing `file.read` and
/// `file.write` together, so no wire message carries it (twin of
/// `setup.rs`'s `setup_run_never_appears_as_a_control_message_wire_variant`,
/// ADR-0029 decision 3).
#[test]
fn file_copy_never_appears_as_a_control_message_wire_variant() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../qsh-proto/proto/qsh/wire/v1.proto"
    ))
    .expect("read v1.proto");
    assert!(source.contains("message "), "v1.proto looks empty");
    let lower = source.to_lowercase();
    assert!(
        !lower.contains("filecopy") && !lower.contains("file_copy") && !lower.contains("file.copy"),
        "the wire proto must never gain a file.copy message"
    );
}
