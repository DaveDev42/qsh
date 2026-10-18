//! The Windows twins of the guard's unix tests (`tests.rs`), run against the
//! real filesystem. The string rules themselves are pinned on every platform
//! in `windows_path/tests.rs`; here the same cases go through
//! [`shape_path`]'s dispatch, and the normalization, protected-set, recheck,
//! hard-link and file-kind cases use an NTFS directory.
//!
//! Where Windows differs from unix the test says so: `..` folds lexically
//! before any link is followed (Win32 does the same to the string), a
//! directory link is a junction (`mklink /J` needs no privilege, a file
//! symlink does and is exercised only when the account may make one), and
//! a swapped intermediate directory is refused by the open itself, one step
//! earlier than the recheck.

use std::process::Command;

use super::windows_path::strip_verbatim_prefix;
use super::*;

const HOME: &str = r"C:\Users\serve";

fn home() -> Option<&'static Path> {
    Some(Path::new(HOME))
}

fn shape(raw: &str, op: FileOp) -> Result<ShapedPath, ShapeError> {
    shape_path(raw.as_bytes(), op, home())
}

/// `mklink /J` wants backslashes; every path here is built by `join`, which
/// may leave a `/` in the middle.
fn backslashed(path: &Path) -> String {
    path.to_str().unwrap().replace('/', "\\")
}

fn junction(link: &Path, target: &Path) {
    let _spawning = crate::winproc::spawn_guard();
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(backslashed(link))
        .arg(backslashed(target))
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "mklink /J: {}",
        String::from_utf8_lossy(&made.stdout)
    );
}

/// A file symlink, `false` when this account has no right to make one
/// (`ERROR_PRIVILEGE_NOT_HELD`).
fn file_symlink(link: &Path, target: &Path) -> bool {
    match std::os::windows::fs::symlink_file(target, link) {
        Ok(()) => true,
        Err(e) if e.raw_os_error() == Some(1314) => {
            eprintln!("skipped a file symlink: the account may not create symbolic links");
            false
        }
        Err(e) => panic!("symlink_file: {e}"),
    }
}

// --- shape check and home resolution (decision 6-1), through the dispatch ---

#[test]
fn file_path_shape_resolves_absolute_tilde_and_relative_forms() {
    let cases = [
        (r"C:\srv\a", r"C:\srv\a"),
        ("C:/srv/a", r"C:\srv\a"),
        ("~", HOME),
        ("~/", HOME),
        ("~/x/y", r"C:\Users\serve\x\y"),
        (r"dir\x", r"C:\Users\serve\dir\x"),
        ("dir/x", r"C:\Users\serve\dir\x"),
        (r"C:\srv\..\etc\x", r"C:\srv\..\etc\x"),
        (r"~\..\other", r"C:\Users\serve\..\other"),
    ];
    for (raw, want) in cases {
        let got = shape(raw, FileOp::Read).unwrap();
        assert_eq!(got.absolute, PathBuf::from(want), "raw {raw:?}");
    }
}

#[test]
fn file_path_shape_records_the_trailing_slash_assertion() {
    assert!(shape(r"C:\srv\dir\", FileOp::List).unwrap().must_be_dir);
    assert!(shape("C:/srv/dir/", FileOp::List).unwrap().must_be_dir);
    assert!(shape("~/", FileOp::List).unwrap().must_be_dir);
    assert!(shape(r"C:\", FileOp::List).unwrap().must_be_dir);
    assert!(!shape(r"C:\srv\dir", FileOp::List).unwrap().must_be_dir);
    assert!(!shape("~", FileOp::List).unwrap().must_be_dir);
}

#[test]
fn file_path_shape_refuses_malformed_requests() {
    assert_eq!(shape("", FileOp::Read), Err(ShapeError::Empty));
    assert_eq!(shape("~dave/x", FileOp::Read), Err(ShapeError::TildeUser));
    assert_eq!(shape("~dave", FileOp::Read), Err(ShapeError::TildeUser));
    assert_eq!(shape("C:\\a\0b", FileOp::Read), Err(ShapeError::Nul));
    assert_eq!(
        shape_path(b"C:\\a\\\xff", FileOp::Read, home()),
        Err(ShapeError::NotUtf8)
    );
    let long = format!(r"C:\{}", "a".repeat(PATH_MAX_BYTES));
    assert_eq!(shape(&long, FileOp::Read), Err(ShapeError::TooLong));
    let at_limit = format!(r"C:\{}", "a".repeat(PATH_MAX_BYTES - 3));
    assert!(shape(&at_limit, FileOp::Read).is_ok());
}

#[test]
fn file_path_shape_refuses_a_home_relative_path_that_grows_past_the_limit() {
    let rel = "a".repeat(PATH_MAX_BYTES - 5);
    assert_eq!(shape(&rel, FileOp::Read), Err(ShapeError::TooLong));
}

#[test]
fn file_path_shape_creating_ops_refuse_dot_last_components() {
    for op in [FileOp::Write, FileOp::Mkdir] {
        for raw in [".", "..", r"C:\srv\.", r"C:\srv\..", r"C:\srv\..\\", "~/.."] {
            assert_eq!(shape(raw, op), Err(ShapeError::DotLastComponent), "{raw:?}");
        }
        assert!(shape("~", op).is_ok());
        assert!(shape(r"C:\srv\a.b", op).is_ok());
        assert!(shape(r"C:\srv\.hidden", op).is_ok());
    }
    for op in [FileOp::Read, FileOp::List] {
        assert!(shape(r"C:\srv\.", op).is_ok());
        assert!(shape(r"C:\srv\..", op).is_ok());
    }
}

#[test]
fn file_path_shape_needs_a_home_only_for_home_relative_forms() {
    for raw in ["~", "~/x", "x"] {
        assert_eq!(
            shape_path(raw.as_bytes(), FileOp::Read, None),
            Err(ShapeError::NoHome)
        );
        assert_eq!(
            shape_path(raw.as_bytes(), FileOp::Read, Some(Path::new("relative"))),
            Err(ShapeError::NoHome)
        );
    }
    assert!(shape_path(br"C:\abs", FileOp::Read, None).is_ok());
}

#[test]
fn file_path_shape_errors_never_echo_the_request() {
    let err = shape("~secret-name/x", FileOp::Read).unwrap_err();
    assert!(!err.to_string().contains("secret-name"));
}

#[test]
fn file_name_if_dir_is_one_plain_component() {
    assert!(shape_name_if_dir(b"report.txt").is_ok());
    assert!(shape_name_if_dir(b".hidden").is_ok());
    assert!(shape_name_if_dir("\u{d55c}\u{ae00}".as_bytes()).is_ok());
    assert!(shape_name_if_dir(&[b'a'; NAME_MAX_BYTES]).is_ok());
    for bad in [
        &b""[..],
        b".",
        b"..",
        b"a/b",
        br"a\b",
        b"/",
        b"a\0b",
        b"\xff",
        b"a:b",
        b"NUL",
        &[b'a'; NAME_MAX_BYTES + 1],
    ] {
        assert_eq!(shape_name_if_dir(bad), Err(ShapeError::BadName), "{bad:?}");
    }
}

#[test]
fn windows_remote_path_refuses_unc_and_device_namespaces_before_any_filesystem_access() {
    for raw in [
        r"\\server\share\x",
        "//server/share/x",
        r"\\?\C:\x",
        r"\\.\pipe\x",
    ] {
        assert_eq!(
            shape(raw, FileOp::Read),
            Err(ShapeError::UncOrDevice),
            "{raw:?}"
        );
    }
}

/// Child half of `file_serve_home_ignores_the_home_env_var`: prints what
/// `serve_home_dir` returns while the parent has poisoned the profile
/// variables.
#[test]
#[ignore = "child half of file_serve_home_ignores_the_home_env_var"]
fn file_serve_home_probe_child() {
    let home = serve_home_dir().map(|p| p.display().to_string());
    println!("PROBE_HOME={}", home.unwrap_or_default());
}

#[test]
fn file_serve_home_ignores_the_home_env_var() {
    const POISON: &str = r"C:\qsh-probe-not-the-home";
    let relative = module_path!().split_once("::").unwrap().1;
    let out = {
        let _spawning = crate::winproc::spawn_guard();
        Command::new(std::env::current_exe().unwrap())
            .env("USERPROFILE", POISON)
            .env("HOME", POISON)
            .args([
                "--exact",
                &format!("{relative}::file_serve_home_probe_child"),
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap()
    };
    assert!(out.status.success(), "child failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let reported = stdout
        .split_once("PROBE_HOME=")
        .and_then(|(_, rest)| rest.lines().next())
        .unwrap_or_else(|| panic!("no probe line in {stdout:?}"));
    let expected = serve_home_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    assert_eq!(reported, expected);
    assert_ne!(reported, POISON);
    assert!(
        windows_path::split_drive_path(&expected).is_some(),
        "the profile of the token is a drive path: {expected:?}"
    );
}

// --- normalization (decision 6-2) ---

struct Sandbox {
    _dir: tempfile::TempDir,
    /// The final path of the temp directory without the `\\?\` prefix: the
    /// spelling the normalizer returns (a temp directory may be reached
    /// through an 8.3 short name).
    root: PathBuf,
    paths: Paths,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = PathBuf::from(strip_verbatim_prefix(
            fs::canonicalize(dir.path()).unwrap().to_str().unwrap(),
        ));
        for sub in ["config", "state"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let paths =
            Paths::new(root.join("config"), root.join("state")).with_runtime_dir(root.join("run"));
        Self {
            _dir: dir,
            root,
            paths,
        }
    }

    fn audit(&self) -> AuditConfig {
        AuditConfig::default()
    }

    fn protected(&self) -> ProtectedSet {
        ProtectedSet::resolve(&self.paths, &self.audit(), &[], &FsNormalizer)
    }

    fn write(&self, rel: &str, body: &str) -> PathBuf {
        let path = self.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        path
    }
}

fn norm(path: &Path) -> Result<PathBuf, NormalizeError> {
    FsNormalizer.normalize(path)
}

#[test]
fn windows_canonical_path_strips_the_verbatim_prefix() {
    let sb = Sandbox::new();
    let file = sb.write("real/Target.txt", "x");
    let got = norm(&file).unwrap();
    assert_eq!(got, file);
    assert!(!got.to_str().unwrap().starts_with(r"\\?\"), "{got:?}");
    // The system itself spells it with the prefix; the normalizer's result is
    // that spelling with the prefix taken off.
    let verbatim = fs::canonicalize(&file).unwrap();
    assert!(verbatim.to_str().unwrap().starts_with(r"\\?\"));
    assert_eq!(
        PathBuf::from(strip_verbatim_prefix(verbatim.to_str().unwrap())),
        got
    );
    // The on-disk spelling wins over the spelling typed.
    let typed = sb.root.join("REAL").join("target.TXT");
    assert_eq!(norm(&typed).unwrap(), file);
}

#[test]
fn file_normalize_follows_existing_symlinks_to_the_end() {
    let sb = Sandbox::new();
    let target = sb.write("real/target.txt", "x");
    junction(&sb.root.join("dirlink"), &sb.root.join("real"));
    assert_eq!(norm(&sb.root.join("dirlink/target.txt")).unwrap(), target);
    assert_eq!(
        norm(&sb.root.join("dirlink")).unwrap(),
        sb.root.join("real")
    );
    if file_symlink(&sb.root.join("link"), &target) {
        assert_eq!(norm(&sb.root.join("link")).unwrap(), target);
    }
}

#[test]
fn file_normalize_folds_the_missing_tail_lexically() {
    let sb = Sandbox::new();
    sb.write("real/a.txt", "x");
    let want = sb.root.join("real/new/deeper/file");
    assert_eq!(norm(&sb.root.join("real/new/deeper/file")).unwrap(), want);
    let raw = sb.root.join("real/missing/../new/./deeper//file");
    assert_eq!(norm(&raw).unwrap(), want);
    let raw = sb.root.join("real/missing/../../real/b.txt");
    assert_eq!(norm(&raw).unwrap(), sb.root.join("real/b.txt"));
}

/// Windows folds `..` in the string before the kernel sees the path, so a
/// `..` after a link is the link's lexical parent, not its target's. The
/// unix twin interprets it physically; the normalizer matches what each
/// system's own open would do with the same text.
#[test]
fn file_normalize_folds_dotdot_before_following_a_junction() {
    let sb = Sandbox::new();
    sb.write("far/deep/x", "x");
    fs::create_dir_all(sb.root.join("near")).unwrap();
    junction(&sb.root.join("near/link"), &sb.root.join("far/deep"));
    let got = norm(&sb.root.join("near/link/../absent")).unwrap();
    assert_eq!(got, sb.root.join("near/absent"));
    // What Win32 opens for the same text.
    let text = format!(r"{}\near\link\..\absent", sb.root.display());
    assert_eq!(
        fs::metadata(&text).map_err(|e| e.kind()).err(),
        Some(io::ErrorKind::NotFound)
    );
    assert!(sb.root.join("near").is_dir());
}

#[test]
fn file_normalize_refuses_loops_and_files_used_as_directories() {
    let sb = Sandbox::new();
    // a -> b -> a: made in two steps so each junction has a target.
    fs::create_dir_all(sb.root.join("b")).unwrap();
    junction(&sb.root.join("a"), &sb.root.join("b"));
    fs::remove_dir(sb.root.join("b")).unwrap();
    junction(&sb.root.join("b"), &sb.root.join("a"));
    assert!(matches!(
        norm(&sb.root.join("a/x")),
        Err(NormalizeError::Io(_))
    ));
    let file = sb.write("f", "x");
    assert!(matches!(
        norm(&file.join("below")),
        Err(NormalizeError::Io(_))
    ));
    assert_eq!(
        norm(Path::new("relative")),
        Err(NormalizeError::NotAbsolute)
    );
    let long = PathBuf::from(format!(r"C:\{}", "a".repeat(PATH_MAX_BYTES)));
    assert_eq!(norm(&long), Err(NormalizeError::TooLong));
    fs::remove_dir(sb.root.join("a")).unwrap();
    fs::remove_dir(sb.root.join("b")).unwrap();
}

#[test]
fn file_normalize_root_and_dotdot_at_root() {
    let sb = Sandbox::new();
    let drive_root = sb.root.ancestors().last().unwrap().to_path_buf();
    let want = PathBuf::from(format!(
        "{}\\",
        drive_root.to_str().unwrap().trim_end_matches('\\')
    ));
    assert_eq!(norm(&drive_root).unwrap(), want);
    let up = PathBuf::from(format!("{}..\\..\\", want.display()));
    assert_eq!(norm(&up).unwrap(), want);
}

#[test]
fn file_normalizer_counts_calls_through_the_wrapper() {
    let counting = CountingNormalizer::new(FsNormalizer);
    assert_eq!(counting.calls(), 0);
    let _ = counting.normalize(Path::new(r"C:\"));
    let _ = counting.normalize(Path::new(r"C:\nonexistent-for-count"));
    assert_eq!(counting.calls(), 2);
}

#[test]
fn windows_paths_prefix_match_folds_case_by_component() {
    let root = Path::new(r"C:\Srv\Share");
    assert!(path_within(Path::new(r"c:\srv\share\a\b"), root, true));
    assert!(path_within(Path::new(r"C:\SRV\SHARE"), root, true));
    // Component-wise: a sibling that shares a prefix is not inside.
    assert!(!path_within(Path::new(r"C:\srv\shared\a"), root, true));
    assert!(!path_within(Path::new(r"D:\srv\share\a"), root, true));
    assert!(!path_within(Path::new(r"C:\srv"), root, true));
    // The ACL's own comparison on Windows folds, and the protected set does.
    assert!(!path_within(Path::new(r"c:\srv\share\a"), root, false));
    let sb = Sandbox::new();
    assert!(
        sb.protected()
            .denies(&sb.root.join("CONFIG").join("Acl.Toml"))
    );
}

// --- protected set (decisions 5 and 6-3) ---

#[test]
fn state_path_guard_denies_nonexistent_paths_under_state_dirs() {
    let sb = Sandbox::new();
    sb.write("config/acl.toml", "[[acl]]");
    let set = sb.protected();
    let check = |p: PathBuf| set.check_request(&FsNormalizer, &p);

    for rel in [
        "config/trust.toml",
        "config/invites.toml",
        "config/identity/device.key",
        "config/not/yet/created/file",
        "state/audit.log",
        "state/resume.json",
        "run/12345.sock",
        "run/deeper/still/missing",
    ] {
        assert_eq!(
            check(sb.root.join(rel)),
            Err(StatePathDenied::Protected),
            "{rel}"
        );
    }
    for rel in ["config", "state", "run", "config/acl.toml"] {
        assert_eq!(
            check(sb.root.join(rel)),
            Err(StatePathDenied::Protected),
            "{rel}"
        );
    }
    assert_eq!(
        check(sb.root.join("elsewhere/../config/trust.toml")),
        Err(StatePathDenied::Protected)
    );
    // A junction is judged by where it lands.
    fs::create_dir_all(sb.root.join("tmp")).unwrap();
    junction(&sb.root.join("tmp/link"), &sb.root.join("config"));
    assert_eq!(
        check(sb.root.join("tmp/link/acl.toml")),
        Err(StatePathDenied::Protected)
    );
    assert_eq!(
        check(sb.root.join("tmp/link")),
        Err(StatePathDenied::Protected)
    );
    for rel in [
        "config-sibling/x",
        "configx",
        "state2/audit.log",
        "tmp/other",
    ] {
        assert_eq!(
            check(sb.root.join(rel)),
            Ok(sb.root.join(rel)),
            "{rel} must stay reachable"
        );
    }
    assert!(check(sb.root.clone()).is_ok(), "the parent is listable");
    fs::remove_dir(sb.root.join("tmp/link")).unwrap();
}

#[test]
fn state_path_guard_refuses_what_it_cannot_normalize() {
    let sb = Sandbox::new();
    let file = sb.write("f", "x");
    assert!(matches!(
        sb.protected().check_request(&FsNormalizer, &file.join("x")),
        Err(StatePathDenied::Unnormalizable(_))
    ));
    // A path that does not name a drive is not one the policy can judge.
    assert!(matches!(
        sb.protected()
            .check_request(&FsNormalizer, Path::new(r"\\server\share\x")),
        Err(StatePathDenied::Unnormalizable(_))
    ));
}

#[test]
fn state_path_guard_covers_env_overridden_and_default_dirs() {
    let sb = Sandbox::new();
    let passwd_home = sb.root.join("passwd-home");
    let env_home = sb.root.join("env-home");
    let set = ProtectedSet::resolve(
        &sb.paths,
        &sb.audit(),
        &[passwd_home.clone(), env_home.clone()],
        &FsNormalizer,
    );
    let denied = |p: PathBuf| set.denies(&p);

    assert!(denied(sb.root.join("config/trust.toml")));
    assert!(denied(sb.root.join("state/audit.log")));
    assert!(denied(sb.root.join("run/1.sock")));
    for home in [&passwd_home, &env_home] {
        assert!(denied(home.join(".config/qsh/acl.toml")));
        assert!(denied(home.join(".config/qsh/identity/device.key")));
        assert!(denied(home.join(".local/state/qsh/audit.log")));
        assert!(denied(home.join(".local/state/qsh/run/9.sock")));
        assert!(!denied(home.join(".config/other/x")));
        assert!(!denied(home.join(".ssh/id_ed25519")));
        assert!(!denied(home.join("notes.txt")));
    }
    let moved = Paths::new(sb.root.join("config2"), sb.root.join("state2"))
        .with_runtime_dir(sb.root.join("run2"));
    let set2 = ProtectedSet::resolve(&moved, &sb.audit(), &[], &FsNormalizer);
    assert!(set2.denies(&sb.root.join("config2/acl.toml")));
    assert!(!set2.denies(&sb.root.join("config/acl.toml")));
}

#[test]
fn state_path_guard_for_process_includes_the_serve_account_home() {
    let sb = Sandbox::new();
    let set = ProtectedSet::for_process(&sb.paths, &sb.audit(), &FsNormalizer);
    let home = serve_home_dir().expect("the process token has a profile directory");
    assert!(set.denies(&home.join(".config/qsh/trust.toml")));
    assert!(set.denies(&home.join(".local/state/qsh/audit.log")));
}

#[test]
fn state_path_guard_follows_a_symlinked_config_dir() {
    // dotfiles layout: the config directory is a link into a repository.
    let sb = Sandbox::new();
    fs::create_dir_all(sb.root.join("dots/qsh")).unwrap();
    junction(&sb.root.join("cfg-link"), &sb.root.join("dots/qsh"));
    let paths = Paths::new(sb.root.join("cfg-link"), sb.root.join("state"))
        .with_runtime_dir(sb.root.join("run"));
    let set = ProtectedSet::resolve(&paths, &sb.audit(), &[], &FsNormalizer);
    assert!(set.denies(&sb.root.join("dots/qsh/acl.toml")));
    assert!(set.denies(&sb.root.join("dots/qsh/never/made")));
    assert!(set.denies(&sb.root.join("cfg-link/acl.toml")));
    assert!(!set.denies(&sb.root.join("dots/other")));
    fs::remove_dir(sb.root.join("cfg-link")).unwrap();
}

#[test]
fn state_path_guard_protects_the_audit_file_outside_the_state_dir() {
    let sb = Sandbox::new();
    let audit = AuditConfig {
        path: Some(sb.root.join("logs/qsh/audit.log").display().to_string()),
        retain: Some(3),
        ..AuditConfig::default()
    };
    let set = ProtectedSet::resolve(&sb.paths, &audit, &[], &FsNormalizer);
    let logs = sb.root.join("logs/qsh");
    for name in [
        "audit.log",
        "audit.log.1",
        "audit.log.3",
        "audit.log.4",
        "audit.log.99",
        "audit.log.lock",
        "AUDIT.LOG.2",
    ] {
        assert!(set.denies(&logs.join(name)), "{name}");
    }
    for name in [
        "audit.log.0",
        "audit.log.old",
        "audit.log.1x",
        "other.log",
        "audit.log.",
    ] {
        assert!(!set.denies(&logs.join(name)), "{name}");
    }
    assert!(!set.denies(&logs));
    assert!(!set.denies(&sb.root.join("logs/audit.log")));
}

#[test]
fn state_path_guard_protects_the_file_mode_key() {
    let sb = Sandbox::new();
    let set = sb.protected();
    assert!(
        set.files()
            .iter()
            .any(|f| f.ends_with("identity/device.key"))
    );
    assert!(set.denies(&sb.root.join("config/identity/device.key")));
}

#[test]
fn state_path_guard_case_folding_is_a_platform_default_and_overridable() {
    let sb = Sandbox::new();
    let upper = sb.root.join("CONFIG/ACL.TOML");
    let folded = sb.protected().with_case_folding(true);
    assert!(folded.denies(&upper));
    assert!(folded.denies(&sb.root.join("State/Audit.Log")));
    let sensitive = sb.protected().with_case_folding(false);
    assert!(!sensitive.denies(&upper));
    let audit = AuditConfig {
        path: Some(sb.root.join("logs/Audit.Log").display().to_string()),
        ..AuditConfig::default()
    };
    let set = ProtectedSet::resolve(&sb.paths, &audit, &[], &FsNormalizer).with_case_folding(true);
    assert!(set.denies(&sb.root.join("LOGS/audit.log.1")));
    assert!(sb.protected().denies(&upper), "Windows folds by default");
}

/// The Windows twin of the macOS leg: the volume ignores case, so a
/// differently cased spelling of a state path is the same file and must be
/// refused, existing or not.
#[test]
fn state_path_guard_denies_case_only_variants_of_state_paths_on_windows() {
    let sb = Sandbox::new();
    sb.write("config/acl.toml", "[[acl]]");
    let set = sb.protected();
    let root = sb.root.display().to_string();
    let swapped = |rel: &str| PathBuf::from(format!("{root}\\{}", rel.to_uppercase()));
    for rel in ["config/acl.toml", "config/trust.toml", "state/audit.log"] {
        let request = swapped(&rel.replace('/', "\\"));
        assert_eq!(
            set.check_request(&FsNormalizer, &request),
            Err(StatePathDenied::Protected),
            "{request:?}"
        );
    }
}

// --- opened-handle recheck (decision 6-4) ---

/// Open `path` for reading with no reparse-point check, the way the open of
/// a path with a swapped intermediate component would land.
fn raw_open(path: &Path) -> File {
    use std::os::windows::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(path)
        .unwrap()
}

#[test]
fn state_path_guard_rechecks_the_opened_handle() {
    assert!(handle_resolution_available());
    let sb = Sandbox::new();
    sb.write("config/f", "secret");
    sb.write("share/sub/f", "public");
    let set = sb.protected();
    let requested = sb.root.join("share/sub/f");

    let canonical = set.check_request(&FsNormalizer, &requested).unwrap();
    assert_eq!(canonical, requested);

    let clean = open_read_nofollow(&canonical).unwrap();
    let mut seen = None;
    let rechecked = recheck_handle(&clean, &set, |p| {
        seen = Some(p.to_path_buf());
        true
    })
    .unwrap();
    assert_eq!(rechecked, canonical);
    assert_eq!(seen.as_deref(), Some(canonical.as_path()));
    drop(clean);

    // The race: between the check and the open, a directory component is
    // swapped for a junction into the protected tree. A plain open lands on
    // the protected file and the recheck sees it...
    fs::rename(sb.root.join("share/sub"), sb.root.join("share/sub.bak")).unwrap();
    junction(&sb.root.join("share/sub"), &sb.root.join("config"));
    let raced = raw_open(&canonical);
    assert_eq!(
        recheck_handle(&raced, &set, |_| true),
        Err(HandleDenied::Protected)
    );
    // ...and the guard's own open refuses it one step earlier.
    assert!(open_read_nofollow(&canonical).is_err());
    fs::remove_dir(sb.root.join("share/sub")).unwrap();
}

#[test]
fn windows_open_handle_revalidation_catches_a_swapped_component() {
    let sb = Sandbox::new();
    sb.write("elsewhere/f", "other");
    sb.write("share/sub/f", "mine");
    let canonical = sb.root.join("share/sub/f");
    assert!(open_read_nofollow(&canonical).is_ok());
    // Swap `sub` for a junction to an allowed-looking directory: the open
    // succeeds at the Win32 level, but the handle is not at the path asked
    // for, and the guard's open says so.
    fs::rename(sb.root.join("share/sub"), sb.root.join("share/sub.bak")).unwrap();
    junction(&sb.root.join("share/sub"), &sb.root.join("elsewhere"));
    let err = open_read_nofollow(&canonical).unwrap_err();
    assert!(
        matches!(
            crate::file::local::classify(&err),
            crate::file::local::IoClass::SymlinkRefused
        ),
        "{err:?}"
    );
    let err = open_dir_nofollow(&sb.root.join("share/sub")).unwrap_err();
    assert!(is_not_a_directory_error(&err), "{err:?}");
    // The directory-component swap on the parent of a creating op.
    let err = open_dir_nofollow(&sb.root.join("share/sub")).unwrap_err();
    assert!(is_not_a_directory_error(&err));
    fs::remove_dir(sb.root.join("share/sub")).unwrap();
}

#[test]
fn state_path_guard_recheck_runs_the_evaluator_on_the_real_path() {
    let sb = Sandbox::new();
    let file = sb.write("share/f", "x");
    let set = sb.protected();
    let handle = open_read_nofollow(&file).unwrap();
    let mut asked = Vec::new();
    let result = recheck_handle(&handle, &set, |p| {
        asked.push(p.to_path_buf());
        false
    });
    assert_eq!(result, Err(HandleDenied::Reevaluation));
    assert_eq!(asked, vec![file]);
}

#[test]
fn state_path_guard_recheck_refuses_when_the_handle_path_is_unknown() {
    let sb = Sandbox::new();
    let set = sb.protected();
    let unknown = Err(io::Error::from(io::ErrorKind::NotFound));
    let mut evaluated = false;
    let result = recheck_handle_path(unknown, &set, |_| {
        evaluated = true;
        true
    });
    assert_eq!(
        result,
        Err(HandleDenied::Unresolvable(io::ErrorKind::NotFound))
    );
    assert!(
        !evaluated,
        "an unresolved handle never reaches the evaluator"
    );
}

#[test]
fn state_path_guard_an_unlinked_protected_file_is_still_caught_by_identity() {
    // NTFS reports a file deleted while open under `\$Extend\$Deleted\...`,
    // outside every protected directory, so the path recheck alone lets the
    // handle through. The identity set built before the delete is what keeps
    // a read of the protected bytes refused (ADR-0029 decision 6-5).
    let sb = Sandbox::new();
    let acl = sb.write("config/acl.toml", "old");
    let set = sb.protected();
    let inodes = ProtectedInodes::collect(&set).unwrap();
    let handle = open_read_nofollow(&acl).unwrap();
    fs::remove_file(&acl).unwrap();
    let result = recheck_handle(&handle, &set, |_| true);
    assert!(
        matches!(
            result,
            Ok(_) | Err(HandleDenied::Protected | HandleDenied::Unresolvable(_))
        ),
        "{result:?}"
    );
    assert_eq!(
        check_read_target(&handle, &inodes).unwrap_err(),
        ReadTargetDenied::ProtectedInode
    );
}

#[test]
fn state_path_guard_handle_path_follows_directory_opens() {
    let sb = Sandbox::new();
    fs::create_dir_all(sb.root.join("share/d")).unwrap();
    let dir = open_dir_nofollow(&sb.root.join("share/d")).unwrap();
    assert_eq!(handle_path(&dir).unwrap(), sb.root.join("share/d"));
    // A file is not a directory, and a directory link is not followed.
    let file = sb.write("share/file", "x");
    assert!(open_dir_nofollow(&file).is_err());
    junction(&sb.root.join("share/dlink"), &sb.root.join("share/d"));
    assert!(open_dir_nofollow(&sb.root.join("share/dlink")).is_err());
    assert!(open_read_nofollow(&sb.root.join("share/dlink")).is_err());
    fs::remove_dir(sb.root.join("share/dlink")).unwrap();
}

#[test]
fn windows_open_refuses_a_symlink_and_a_junction() {
    let sb = Sandbox::new();
    let file = sb.write("share/plain", "abc");
    fs::create_dir_all(sb.root.join("share/d")).unwrap();
    junction(&sb.root.join("share/junction"), &sb.root.join("share/d"));
    for open in [open_read_nofollow, open_dir_nofollow] {
        let err = open(&sb.root.join("share/junction")).unwrap_err();
        assert!(
            matches!(
                crate::file::local::classify(&err),
                crate::file::local::IoClass::SymlinkRefused
            ),
            "{err:?}"
        );
    }
    assert!(is_not_a_directory_error(
        &open_dir_nofollow(&sb.root.join("share/junction")).unwrap_err()
    ));
    if file_symlink(&sb.root.join("share/sym"), &file) {
        let err = open_read_nofollow(&sb.root.join("share/sym")).unwrap_err();
        assert!(
            matches!(
                crate::file::local::classify(&err),
                crate::file::local::IoClass::SymlinkRefused
            ),
            "{err:?}"
        );
    }
    fs::remove_dir(sb.root.join("share/junction")).unwrap();
}

// --- inode set and file kind (decisions 6-5 and 6-6) ---

#[test]
fn state_path_guard_denies_a_hard_link_to_a_protected_file() {
    let sb = Sandbox::new();
    let acl = sb.write("config/acl.toml", "[[acl]]");
    let key = sb.write("config/identity/device.key", "key");
    fs::create_dir_all(sb.root.join("share")).unwrap();
    fs::hard_link(&acl, sb.root.join("share/innocent.txt")).unwrap();
    fs::hard_link(&key, sb.root.join("share/also-innocent")).unwrap();
    let ordinary = sb.write("share/ordinary.txt", "hello");

    let set = sb.protected();
    // The path judgement alone lets the link through: that is the gap.
    assert!(!set.denies(&sb.root.join("share/innocent.txt")));

    let inodes = ProtectedInodes::collect(&set).unwrap();
    assert!(!inodes.is_empty());
    for linked in ["share/innocent.txt", "share/also-innocent"] {
        let file = open_read_nofollow(&sb.root.join(linked)).unwrap();
        assert_eq!(
            check_read_target(&file, &inodes).unwrap_err(),
            ReadTargetDenied::ProtectedInode,
            "{linked}"
        );
    }
    let file = open_read_nofollow(&ordinary).unwrap();
    assert_eq!(check_read_target(&file, &inodes).unwrap().len(), 5);
}

#[test]
fn state_path_guard_inode_set_covers_audit_rotations_and_nested_files() {
    let sb = Sandbox::new();
    let audit = AuditConfig {
        path: Some(sb.root.join("logs/audit.log").display().to_string()),
        retain: Some(2),
        ..AuditConfig::default()
    };
    let live = sb.write("logs/audit.log", "{}");
    let rotated = sb.write("logs/audit.log.2", "{}");
    let lock = sb.write("logs/audit.log.lock", "");
    let stale = sb.write("logs/audit.log.9", "{}");
    let nested = sb.write("config/ca/root.key", "k");
    fs::create_dir_all(sb.root.join("run")).unwrap();
    let set = ProtectedSet::resolve(&sb.paths, &audit, &[], &FsNormalizer);
    let inodes = ProtectedInodes::collect(&set).unwrap();
    let id = |p: &Path| crate::fsutil::file_identity::of_path(p).unwrap();
    for protected in [&live, &rotated, &lock, &nested, &stale] {
        assert!(inodes.ids.contains(&id(protected)), "{protected:?}");
    }
    let other = sb.write("logs/other.log", "{}");
    let inodes = ProtectedInodes::collect(&set).unwrap();
    assert!(
        !inodes.ids.contains(&id(&other)),
        "unrelated neighbours stay open"
    );
}

#[test]
fn state_path_guard_inode_scan_fails_closed_on_oversized_trees() {
    let sb = Sandbox::new();
    for n in 0..5 {
        sb.write(&format!("config/f{n}"), "x");
    }
    let set = sb.protected();
    assert_eq!(
        ProtectedInodes::collect_with_limits(&set, 3, INODE_SCAN_MAX_DEPTH),
        Err(InodeScanError::TooLarge)
    );
    sb.write("config/a/b/c", "x");
    assert_eq!(
        ProtectedInodes::collect_with_limits(&set, 100, 1),
        Err(InodeScanError::TooLarge),
        "a tree deeper than the limit is not silently skipped"
    );
    assert!(ProtectedInodes::collect_with_limits(&set, 100, 2).is_ok());
}

#[test]
fn state_path_guard_inode_scan_ignores_missing_dirs_and_symlinks() {
    let sb = Sandbox::new();
    // run/ does not exist; a junction inside config/ is not an entry to walk.
    let outside = sb.write("outside/secret", "x");
    junction(&sb.root.join("config/link"), &sb.root.join("outside"));
    let inodes = ProtectedInodes::collect(&sb.protected()).unwrap();
    let id = crate::fsutil::file_identity::of_path(&outside).unwrap();
    assert!(!inodes.ids.contains(&id));
    fs::remove_dir(sb.root.join("config/link")).unwrap();
}

#[test]
fn file_read_target_must_be_a_regular_file() {
    let sb = Sandbox::new();
    let inodes = ProtectedInodes::default();
    fs::create_dir_all(sb.root.join("share/d")).unwrap();
    let dir = open_read_nofollow(&sb.root.join("share/d")).unwrap();
    assert_eq!(
        check_read_target(&dir, &inodes).unwrap_err(),
        ReadTargetDenied::NotRegular(FileKind::Directory)
    );

    let file = sb.write("share/plain", "abc");
    assert_eq!(file_kind(&fs::metadata(&file).unwrap()), FileKind::Regular);
    let opened = open_read_nofollow(&file).unwrap();
    assert!(check_read_target(&opened, &inodes).is_ok());

    junction(&sb.root.join("share/sym"), &sb.root.join("share/d"));
    assert_eq!(
        file_kind(&fs::symlink_metadata(sb.root.join("share/sym")).unwrap()),
        FileKind::Symlink
    );
    fs::remove_dir(sb.root.join("share/sym")).unwrap();
}

#[test]
fn file_read_open_refuses_a_final_symlink() {
    let sb = Sandbox::new();
    let file = sb.write("share/plain", "abc");
    fs::create_dir_all(sb.root.join("share/d")).unwrap();
    junction(&sb.root.join("share/jun"), &sb.root.join("share/d"));
    assert!(open_read_nofollow(&sb.root.join("share/jun")).is_err());
    if file_symlink(&sb.root.join("share/sym"), &file) {
        assert!(open_read_nofollow(&sb.root.join("share/sym")).is_err());
    }
    fs::remove_dir(sb.root.join("share/jun")).unwrap();
}
