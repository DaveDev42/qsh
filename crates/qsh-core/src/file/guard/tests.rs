#[cfg(unix)]
mod unix {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    use super::super::*;

    const HOME: &str = "/home/serve";

    fn home() -> Option<&'static Path> {
        Some(Path::new(HOME))
    }

    fn shape(raw: &str, op: FileOp) -> Result<ShapedPath, ShapeError> {
        shape_path(raw.as_bytes(), op, home())
    }

    // --- shape check and home resolution (decision 6-1) ---

    #[test]
    fn file_path_shape_resolves_absolute_tilde_and_relative_forms() {
        let cases = [
            ("/srv/a", "/srv/a"),
            ("~", HOME),
            ("~/", HOME),
            ("~/x/y", "/home/serve/x/y"),
            ("dir/x", "/home/serve/dir/x"),
            ("./x", "/home/serve/./x"),
            // `..` is not a shape violation; normalization decides.
            ("/srv/../etc/x", "/srv/../etc/x"),
            ("~/../other", "/home/serve/../other"),
        ];
        for (raw, want) in cases {
            let got = shape(raw, FileOp::Read).unwrap();
            assert_eq!(got.absolute, PathBuf::from(want), "raw {raw:?}");
        }
    }

    #[test]
    fn file_path_shape_records_the_trailing_slash_assertion() {
        assert!(shape("/srv/dir/", FileOp::List).unwrap().must_be_dir);
        assert!(shape("~/", FileOp::List).unwrap().must_be_dir);
        assert!(shape("/", FileOp::List).unwrap().must_be_dir);
        assert!(!shape("/srv/dir", FileOp::List).unwrap().must_be_dir);
        assert!(!shape("~", FileOp::List).unwrap().must_be_dir);
    }

    #[test]
    fn file_path_shape_refuses_malformed_requests() {
        assert_eq!(shape("", FileOp::Read), Err(ShapeError::Empty));
        assert_eq!(shape("~dave/x", FileOp::Read), Err(ShapeError::TildeUser));
        assert_eq!(shape("~dave", FileOp::Read), Err(ShapeError::TildeUser));
        assert_eq!(shape("/a\0b", FileOp::Read), Err(ShapeError::Nul));
        assert_eq!(
            shape_path(b"/a/\xff", FileOp::Read, home()),
            Err(ShapeError::NotUtf8)
        );
        let long = format!("/{}", "a".repeat(PATH_MAX_BYTES));
        assert_eq!(shape(&long, FileOp::Read), Err(ShapeError::TooLong));
        let at_limit = format!("/{}", "a".repeat(PATH_MAX_BYTES - 1));
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
            for raw in [".", "..", "/srv/.", "/srv/..", "/srv/..//", "~/..", "a/./"] {
                assert_eq!(shape(raw, op), Err(ShapeError::DotLastComponent), "{raw:?}");
            }
            // `~` is the home directory, not a `.`-style component.
            assert!(shape("~", op).is_ok());
            assert!(shape("/srv/a.b", op).is_ok());
            assert!(shape("/srv/.hidden", op).is_ok());
        }
        // Reads and listings may end in `.` or `..`.
        for op in [FileOp::Read, FileOp::List] {
            assert!(shape("/srv/.", op).is_ok());
            assert!(shape("/srv/..", op).is_ok());
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
        assert!(shape_path(b"/abs", FileOp::Read, None).is_ok());
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
            b"/",
            b"a\0b",
            b"\xff",
            &[b'a'; NAME_MAX_BYTES + 1],
        ] {
            assert_eq!(shape_name_if_dir(bad), Err(ShapeError::BadName), "{bad:?}");
        }
    }

    /// Child half of `file_serve_home_ignores_the_home_env_var`: prints what
    /// `serve_home_dir` returns while the parent has poisoned `$HOME`.
    #[test]
    #[ignore = "child half of file_serve_home_ignores_the_home_env_var"]
    fn file_serve_home_probe_child() {
        let home = serve_home_dir().map(|p| p.display().to_string());
        println!("PROBE_HOME={}", home.unwrap_or_default());
    }

    #[test]
    fn file_serve_home_ignores_the_home_env_var() {
        const POISON: &str = "/qsh-probe-not-the-home";
        let relative = module_path!().split_once("::").unwrap().1;
        let out = Command::new(std::env::current_exe().unwrap())
            .env("HOME", POISON)
            .args([
                "--exact",
                &format!("{relative}::file_serve_home_probe_child"),
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "child failed: {out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        // libtest prints the test name before its output, on the same line.
        let reported = stdout
            .split_once("PROBE_HOME=")
            .and_then(|(_, rest)| rest.lines().next())
            .unwrap_or_else(|| panic!("no probe line in {stdout:?}"));
        let expected = serve_home_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        assert_eq!(reported, expected);
        assert_ne!(reported, POISON);
        if !expected.is_empty() {
            assert!(Path::new(&expected).is_absolute());
        }
    }

    // --- normalization (decision 6-2) ---

    struct Sandbox {
        _dir: tempfile::TempDir,
        /// Canonical root: macOS tempdirs live behind the `/var` symlink.
        root: PathBuf,
        paths: Paths,
    }

    impl Sandbox {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(dir.path()).unwrap();
            for sub in ["config", "state"] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }
            let paths = Paths::new(root.join("config"), root.join("state"))
                .with_runtime_dir(root.join("run"));
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
    fn file_normalize_follows_existing_symlinks_to_the_end() {
        let sb = Sandbox::new();
        let target = sb.write("real/target.txt", "x");
        symlink(&target, sb.root.join("link")).unwrap();
        symlink(sb.root.join("real"), sb.root.join("dirlink")).unwrap();
        assert_eq!(norm(&sb.root.join("link")).unwrap(), target);
        assert_eq!(norm(&sb.root.join("dirlink/target.txt")).unwrap(), target);
    }

    #[test]
    fn file_normalize_folds_the_missing_tail_lexically() {
        let sb = Sandbox::new();
        sb.write("real/a.txt", "x");
        let want = sb.root.join("real/new/deeper/file");
        assert_eq!(norm(&sb.root.join("real/new/deeper/file")).unwrap(), want);
        // `..` after missing components removes them; `.` and `//` vanish.
        let raw = sb.root.join("real/missing/../new/./deeper//file");
        assert_eq!(norm(&raw).unwrap(), want);
        // `..` with nothing missing left steps above the existing prefix.
        let raw = sb.root.join("real/missing/../../real/b.txt");
        assert_eq!(norm(&raw).unwrap(), sb.root.join("real/b.txt"));
    }

    #[test]
    fn file_normalize_interprets_dotdot_through_a_symlink_physically() {
        let sb = Sandbox::new();
        sb.write("far/deep/x", "x");
        fs::create_dir_all(sb.root.join("near")).unwrap();
        // near/link -> far/deep, so near/link/.. is far, not near.
        symlink(sb.root.join("far/deep"), sb.root.join("near/link")).unwrap();
        let got = norm(&sb.root.join("near/link/../absent")).unwrap();
        assert_eq!(got, sb.root.join("far/absent"));
    }

    #[test]
    fn file_normalize_refuses_loops_and_files_used_as_directories() {
        let sb = Sandbox::new();
        symlink(sb.root.join("b"), sb.root.join("a")).unwrap();
        symlink(sb.root.join("a"), sb.root.join("b")).unwrap();
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
        let long = PathBuf::from(format!("/{}", "a".repeat(PATH_MAX_BYTES)));
        assert_eq!(norm(&long), Err(NormalizeError::TooLong));
    }

    #[test]
    fn file_normalize_root_and_dotdot_at_root() {
        assert_eq!(norm(Path::new("/")).unwrap(), PathBuf::from("/"));
        assert_eq!(norm(Path::new("/../../")).unwrap(), PathBuf::from("/"));
    }

    #[test]
    fn file_normalizer_counts_calls_through_the_wrapper() {
        let counting = CountingNormalizer::new(FsNormalizer);
        assert_eq!(counting.calls(), 0);
        let _ = counting.normalize(Path::new("/"));
        let _ = counting.normalize(Path::new("/nonexistent-for-count"));
        assert_eq!(counting.calls(), 2);
    }

    #[test]
    fn file_normalize_with_injects_realpath() {
        // A fake filesystem where only "/" and "/a" exist and /a -> /real.
        let fake = |p: &Path| -> io::Result<PathBuf> {
            match p.to_str().unwrap() {
                "/" => Ok(PathBuf::from("/")),
                "/a" => Ok(PathBuf::from("/real")),
                _ => Err(io::Error::from(io::ErrorKind::NotFound)),
            }
        };
        assert_eq!(
            normalize_with(Path::new("/a/b/c"), &fake).unwrap(),
            PathBuf::from("/real/b/c")
        );
        let denied = |_: &Path| -> io::Result<PathBuf> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        };
        assert_eq!(
            normalize_with(Path::new("/a"), &denied),
            Err(NormalizeError::Io(io::ErrorKind::PermissionDenied))
        );
    }

    // --- protected set (decisions 5 and 6-3) ---

    #[test]
    fn state_path_guard_denies_nonexistent_paths_under_state_dirs() {
        let sb = Sandbox::new();
        sb.write("config/acl.toml", "[[acl]]");
        let set = sb.protected();
        let check = |p: PathBuf| set.check_request(&FsNormalizer, &p);

        // Never created, and below directories that do not exist either.
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
        // The directories themselves, and an existing file.
        for rel in ["config", "state", "run", "config/acl.toml"] {
            assert_eq!(
                check(sb.root.join(rel)),
                Err(StatePathDenied::Protected),
                "{rel}"
            );
        }
        // `..` and symlinks are judged by where they land.
        assert_eq!(
            check(sb.root.join("elsewhere/../config/trust.toml")),
            Err(StatePathDenied::Protected)
        );
        fs::create_dir_all(sb.root.join("tmp")).unwrap();
        symlink(sb.root.join("config/acl.toml"), sb.root.join("tmp/link")).unwrap();
        assert_eq!(
            check(sb.root.join("tmp/link")),
            Err(StatePathDenied::Protected)
        );
        // A component-wise comparison: siblings that only share a prefix, and
        // the parent, are not protected.
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
    }

    #[test]
    fn state_path_guard_refuses_what_it_cannot_normalize() {
        let sb = Sandbox::new();
        symlink(sb.root.join("b"), sb.root.join("a")).unwrap();
        symlink(sb.root.join("a"), sb.root.join("b")).unwrap();
        assert!(matches!(
            sb.protected()
                .check_request(&FsNormalizer, &sb.root.join("a/x")),
            Err(StatePathDenied::Unnormalizable(_))
        ));
    }

    #[test]
    fn state_path_guard_covers_env_overridden_and_default_dirs() {
        let sb = Sandbox::new();
        // Two homes: the passwd one and an environment one that differs.
        let passwd_home = sb.root.join("passwd-home");
        let env_home = sb.root.join("env-home");
        let set = ProtectedSet::resolve(
            &sb.paths,
            &sb.audit(),
            &[passwd_home.clone(), env_home.clone()],
            &FsNormalizer,
        );
        let denied = |p: PathBuf| set.denies(&p);

        // The paths this process really uses (the overridden ones).
        assert!(denied(sb.root.join("config/trust.toml")));
        assert!(denied(sb.root.join("state/audit.log")));
        assert!(denied(sb.root.join("run/1.sock")));
        // The `$HOME` defaults, for both homes, existing or not.
        for home in [&passwd_home, &env_home] {
            assert!(denied(home.join(".config/qsh/acl.toml")));
            assert!(denied(home.join(".config/qsh/identity/device.key")));
            assert!(denied(home.join(".local/state/qsh/audit.log")));
            assert!(denied(home.join(".local/state/qsh/run/9.sock")));
            // Only the qsh directories, not the rest of the home.
            assert!(!denied(home.join(".config/other/x")));
            assert!(!denied(home.join(".ssh/id_ed25519")));
            assert!(!denied(home.join("notes.txt")));
        }
        // A request resolved a second time sees a changed environment: the
        // set is built per call and never frozen.
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
        if let Some(home) = serve_home_dir() {
            assert!(set.denies(&home.join(".config/qsh/trust.toml")));
            assert!(set.denies(&home.join(".local/state/qsh/audit.log")));
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: geteuid has no preconditions.
            let uid = unsafe { libc::geteuid() };
            assert!(set.denies(Path::new(&format!("/run/user/{uid}/qsh/1.sock"))));
        }
    }

    #[test]
    fn state_path_guard_follows_a_symlinked_config_dir() {
        // dotfiles layout: ~/.config/qsh is a link into a repository.
        let sb = Sandbox::new();
        fs::create_dir_all(sb.root.join("dots/qsh")).unwrap();
        symlink(sb.root.join("dots/qsh"), sb.root.join("cfg-link")).unwrap();
        let paths = Paths::new(sb.root.join("cfg-link"), sb.root.join("state"))
            .with_runtime_dir(sb.root.join("run"));
        let set = ProtectedSet::resolve(&paths, &sb.audit(), &[], &FsNormalizer);
        // Canonical request paths land under the link's target...
        assert!(set.denies(&sb.root.join("dots/qsh/acl.toml")));
        assert!(set.denies(&sb.root.join("dots/qsh/never/made")));
        // ...and the link spelling stays covered too.
        assert!(set.denies(&sb.root.join("cfg-link/acl.toml")));
        assert!(!set.denies(&sb.root.join("dots/other")));
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
        // Slots past `retain` stay covered: a lowered `retain` leaves them
        // behind until the writer's startup sweep.
        for name in [
            "audit.log",
            "audit.log.1",
            "audit.log.3",
            "audit.log.4",
            "audit.log.99",
            "audit.log.lock",
        ] {
            assert!(set.denies(&logs.join(name)), "{name}");
        }
        // Non-numeric suffixes, slot zero and the directory stay readable.
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
        // Audit rotations fold too.
        let audit = AuditConfig {
            path: Some(sb.root.join("logs/Audit.Log").display().to_string()),
            ..AuditConfig::default()
        };
        let set =
            ProtectedSet::resolve(&sb.paths, &audit, &[], &FsNormalizer).with_case_folding(true);
        assert!(set.denies(&sb.root.join("LOGS/audit.log.1")));
        let default_folds = cfg!(any(target_os = "macos", windows));
        assert_eq!(sb.protected().denies(&upper), default_folds);
    }

    /// The `macos-14` leg: the volume ignores case, so a differently cased
    /// spelling of a state path is the same file and must be refused.
    #[cfg(target_os = "macos")]
    #[test]
    fn state_path_guard_denies_case_only_variants_of_state_paths_on_macos() {
        let sb = Sandbox::new();
        sb.write("config/acl.toml", "[[acl]]");
        let set = sb.protected();
        let root = sb.root.display().to_string();
        let swapped = |rel: &str| PathBuf::from(format!("{root}/{}", rel.to_uppercase()));
        for rel in ["config/acl.toml", "config/trust.toml", "state/audit.log"] {
            let request = swapped(rel);
            assert_eq!(
                set.check_request(&FsNormalizer, &request),
                Err(StatePathDenied::Protected),
                "{request:?}"
            );
        }
    }

    // --- opened-handle recheck (decision 6-4) ---

    #[test]
    fn state_path_guard_rechecks_the_opened_handle() {
        if !handle_resolution_available() {
            eprintln!("skipped: {HANDLE_RECHECK_UNAVAILABLE}");
            return;
        }
        let sb = Sandbox::new();
        sb.write("config/f", "secret");
        sb.write("share/sub/f", "public");
        let set = sb.protected();
        let requested = sb.root.join("share/sub/f");

        // Time of check: the request is clean and normalizes to itself.
        let canonical = set.check_request(&FsNormalizer, &requested).unwrap();
        assert_eq!(canonical, requested);

        // Time of use, no race: the handle points where the check said.
        let clean = open_read_nofollow(&canonical).unwrap();
        let mut seen = None;
        let rechecked = recheck_handle(&clean, &set, |p| {
            seen = Some(p.to_path_buf());
            true
        })
        .unwrap();
        assert_eq!(rechecked, canonical);
        assert_eq!(seen.as_deref(), Some(canonical.as_path()));

        // The race: between the check and the open, a directory component
        // is swapped for a symlink into the protected tree. O_NOFOLLOW only
        // guards the last component, so the open succeeds...
        fs::rename(sb.root.join("share/sub"), sb.root.join("share/sub.bak")).unwrap();
        symlink(sb.root.join("config"), sb.root.join("share/sub")).unwrap();
        let raced = open_read_nofollow(&canonical).unwrap();
        // ...and the handle is the protected file, which the recheck sees.
        assert_eq!(
            recheck_handle(&raced, &set, |_| true),
            Err(HandleDenied::Protected)
        );
    }

    #[test]
    fn state_path_guard_recheck_runs_the_evaluator_on_the_real_path() {
        if !handle_resolution_available() {
            eprintln!("skipped: {HANDLE_RECHECK_UNAVAILABLE}");
            return;
        }
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
    fn state_path_guard_handle_path_survives_an_unlinked_file() {
        if !handle_resolution_available() {
            eprintln!("skipped: {HANDLE_RECHECK_UNAVAILABLE}");
            return;
        }
        // A protected file replaced after the open still reads as protected
        // (Linux appends " (deleted)", which is stripped).
        let sb = Sandbox::new();
        let acl = sb.write("config/acl.toml", "old");
        let set = sb.protected();
        let handle = open_read_nofollow(&acl).unwrap();
        fs::remove_file(&acl).unwrap();
        assert_eq!(
            recheck_handle(&handle, &set, |_| true),
            Err(HandleDenied::Protected)
        );
    }

    #[test]
    fn state_path_guard_handle_path_follows_directory_opens() {
        if !handle_resolution_available() {
            eprintln!("skipped: {HANDLE_RECHECK_UNAVAILABLE}");
            return;
        }
        let sb = Sandbox::new();
        fs::create_dir_all(sb.root.join("share/d")).unwrap();
        let dir = open_dir_nofollow(&sb.root.join("share/d")).unwrap();
        assert_eq!(handle_path(&dir).unwrap(), sb.root.join("share/d"));
        // O_DIRECTORY on a file, and O_NOFOLLOW on a directory link, fail.
        let file = sb.write("share/file", "x");
        assert!(open_dir_nofollow(&file).is_err());
        symlink(sb.root.join("share/d"), sb.root.join("share/dlink")).unwrap();
        assert!(open_dir_nofollow(&sb.root.join("share/dlink")).is_err());
        assert!(open_read_nofollow(&sb.root.join("share/dlink")).is_err());
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
        let sock_dir = sb.root.join("run");
        fs::create_dir_all(&sock_dir).unwrap();
        let set = ProtectedSet::resolve(&sb.paths, &audit, &[], &FsNormalizer);
        let inodes = ProtectedInodes::collect(&set).unwrap();
        let id = |p: &Path| {
            use std::os::unix::fs::MetadataExt;
            let md = fs::metadata(p).unwrap();
            (md.dev(), md.ino())
        };
        for protected in [&live, &rotated, &lock, &nested, &stale] {
            let (dev, ino) = id(protected);
            assert!(inodes.contains(dev, ino), "{protected:?}");
        }
        let other = sb.write("logs/other.log", "{}");
        let inodes = ProtectedInodes::collect(&set).unwrap();
        let (dev, ino) = id(&other);
        assert!(!inodes.contains(dev, ino), "unrelated neighbours stay open");
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
        // run/ does not exist; a symlink inside config/ is not an inode.
        let outside = sb.write("outside/secret", "x");
        symlink(&outside, sb.root.join("config/link")).unwrap();
        let inodes = ProtectedInodes::collect(&sb.protected()).unwrap();
        use std::os::unix::fs::MetadataExt;
        let md = fs::metadata(&outside).unwrap();
        assert!(!inodes.contains(md.dev(), md.ino()));
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

        // A FIFO opens without blocking (O_NONBLOCK) and is refused.
        let fifo = sb.root.join("share/fifo");
        let c_path =
            std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(fifo.as_os_str()))
                .unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated path for the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let opened = open_read_nofollow(&fifo).unwrap();
        assert_eq!(
            check_read_target(&opened, &inodes).unwrap_err(),
            ReadTargetDenied::NotRegular(FileKind::Fifo)
        );

        let sock = sb.root.join("share/sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let md = fs::symlink_metadata(&sock).unwrap();
        assert_eq!(file_kind(&md), FileKind::Socket);

        let dev_null = open_read_nofollow(Path::new("/dev/null")).unwrap();
        assert_eq!(
            check_read_target(&dev_null, &inodes).unwrap_err(),
            ReadTargetDenied::NotRegular(FileKind::CharDevice)
        );

        let file = sb.write("share/plain", "abc");
        assert_eq!(file_kind(&fs::metadata(&file).unwrap()), FileKind::Regular);
        symlink(&file, sb.root.join("share/sym")).unwrap();
        assert_eq!(
            file_kind(&fs::symlink_metadata(sb.root.join("share/sym")).unwrap()),
            FileKind::Symlink
        );
    }

    #[test]
    fn file_read_open_refuses_a_final_symlink() {
        let sb = Sandbox::new();
        let file = sb.write("share/plain", "abc");
        symlink(&file, sb.root.join("share/sym")).unwrap();
        assert!(open_read_nofollow(&sb.root.join("share/sym")).is_err());
    }
}
