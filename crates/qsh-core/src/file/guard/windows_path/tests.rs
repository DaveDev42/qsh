//! The Windows path rules, pinned on every platform: they are pure string
//! functions, so a Linux or macOS build runs the same cases the Windows host
//! applies.

use super::*;

const PROFILE: &str = r"C:\Users\serve";

fn shaped(raw: &str, op: FileOp) -> Result<ShapedPath, ShapeError> {
    shape(raw, op, Some(PROFILE))
}

fn abs(raw: &str) -> String {
    shaped(raw, FileOp::Read)
        .unwrap()
        .absolute
        .to_str()
        .unwrap()
        .to_string()
}

// --- shape check and home resolution (decision 6-1, ADR-0035 decision 26) ---

#[test]
fn windows_path_shape_resolves_drive_tilde_and_relative_forms() {
    let cases = [
        (r"C:\srv\a", r"C:\srv\a"),
        ("C:/srv/a", r"C:\srv\a"),
        (r"d:\srv\a", r"d:\srv\a"),
        (r"C:\", r"C:\"),
        ("~", PROFILE),
        (r"~\", PROFILE),
        ("~/", PROFILE),
        ("~/x/y", r"C:\Users\serve\x\y"),
        (r"~\x\y", r"C:\Users\serve\x\y"),
        (r"dir\x", r"C:\Users\serve\dir\x"),
        ("dir/x", r"C:\Users\serve\dir\x"),
        (r".\x", r"C:\Users\serve\.\x"),
        // `..` is not a shape violation; normalization decides.
        (r"C:\srv\..\etc\x", r"C:\srv\..\etc\x"),
        (r"~\..\other", r"C:\Users\serve\..\other"),
        // Doubled separators collapse.
        (r"C:\srv\\a", r"C:\srv\a"),
    ];
    for (raw, want) in cases {
        assert_eq!(abs(raw), want, "raw {raw:?}");
    }
}

#[test]
fn windows_path_shape_records_the_trailing_separator_assertion() {
    for raw in [r"C:\srv\dir\", "C:/srv/dir/", "~/", r"~\", r"C:\"] {
        assert!(shaped(raw, FileOp::List).unwrap().must_be_dir, "{raw:?}");
    }
    for raw in [r"C:\srv\dir", "~", "dir"] {
        assert!(!shaped(raw, FileOp::List).unwrap().must_be_dir, "{raw:?}");
    }
}

#[test]
fn windows_path_shape_refuses_unc_and_device_paths() {
    for raw in [
        r"\\server\share\x",
        "//server/share/x",
        r"\\?\C:\x",
        "//?/C:/x",
        r"\\.\pipe\x",
        r"\\.\C:\x",
        r"\\?\UNC\server\share\x",
        r"\\",
    ] {
        assert_eq!(
            shaped(raw, FileOp::Read),
            Err(ShapeError::UncOrDevice),
            "{raw:?}"
        );
    }
}

#[test]
fn windows_path_shape_refuses_a_path_without_a_usable_drive() {
    for raw in [r"\x", "/x", r"\", "/", "C:", "C:x", r"C:x\y", "z:rel"] {
        assert_eq!(
            shaped(raw, FileOp::Read),
            Err(ShapeError::NoDrive),
            "{raw:?}"
        );
    }
}

#[test]
fn windows_path_shape_refuses_alternate_data_streams() {
    for raw in [
        r"C:\a\b:stream",
        r"C:\a\b:stream:$DATA",
        r"C:\a:b\c",
        r"C:\a\b::$DATA",
        "x:y",
        r"dir\f:s",
        r"~\f:s",
    ] {
        let got = shaped(raw, FileOp::Read);
        assert!(
            matches!(got, Err(ShapeError::AlternateStream | ShapeError::NoDrive)),
            "{raw:?}: {got:?}"
        );
    }
    // The ones with a real drive prefix are the stream error exactly.
    for raw in [r"C:\a\b:stream", r"C:\a:b\c", r"~\f:s", r"dir\f:s"] {
        assert_eq!(
            shaped(raw, FileOp::Read),
            Err(ShapeError::AlternateStream),
            "{raw:?}"
        );
    }
}

#[test]
fn windows_path_shape_refuses_names_windows_cannot_store_as_written() {
    for raw in [
        r"C:\dir\NUL",
        r"C:\dir\nul.txt",
        r"C:\dir\CON",
        r"C:\dir\Aux.log",
        r"C:\dir\COM1",
        r"C:\dir\lpt9.x",
        r"C:\dir\CONIN$",
        r"C:\a.",
        r"C:\a ",
        r"C:\dir.\x",
        r"C:\a<b",
        r"C:\a>b",
        r"C:\a|b",
        r"C:\a?b",
        r"C:\a*b",
        "C:\\a\"b",
        "C:\\a\u{1}b",
        r"C:\...",
    ] {
        assert_eq!(
            shaped(raw, FileOp::Read),
            Err(ShapeError::BadComponent),
            "{raw:?}"
        );
    }
    // Close neighbours that are fine.
    for raw in [
        r"C:\dir\nul-ish",
        r"C:\dir\COM10",
        r"C:\dir\com",
        r"C:\dir\.hidden",
        r"C:\dir\a.b",
        r"C:\dir\a b",
        r"C:\dir\Lpt",
    ] {
        assert!(shaped(raw, FileOp::Read).is_ok(), "{raw:?}");
    }
}

#[test]
fn windows_path_shape_creating_ops_refuse_dot_last_components() {
    for op in [FileOp::Write, FileOp::Mkdir] {
        for raw in [
            ".",
            "..",
            r"C:\srv\.",
            r"C:\srv\..",
            r"C:\srv\..\\",
            "C:/srv/../",
            r"~\..",
            r"a\.\",
        ] {
            assert_eq!(
                shaped(raw, op),
                Err(ShapeError::DotLastComponent),
                "{raw:?}"
            );
        }
        assert!(shaped("~", op).is_ok());
        assert!(shaped(r"C:\srv\a.b", op).is_ok());
        assert!(shaped(r"C:\srv\.hidden", op).is_ok());
    }
    for op in [FileOp::Read, FileOp::List] {
        assert!(shaped(r"C:\srv\.", op).is_ok());
        assert!(shaped(r"C:\srv\..", op).is_ok());
    }
}

#[test]
fn windows_path_shape_needs_a_profile_only_for_profile_relative_forms() {
    for raw in ["~", r"~\x", "x", r"dir\x"] {
        assert_eq!(
            shape(raw, FileOp::Read, None),
            Err(ShapeError::NoHome),
            "{raw:?}"
        );
        // A profile that is not a drive path is no profile.
        for bad in ["relative", r"\\server\share\me", r"\Users\me", ""] {
            assert_eq!(
                shape(raw, FileOp::Read, Some(bad)),
                Err(ShapeError::NoHome),
                "{raw:?} with {bad:?}"
            );
        }
    }
    assert!(shape(r"C:\abs", FileOp::Read, None).is_ok());
}

#[test]
fn windows_path_shape_refuses_another_accounts_tilde() {
    assert_eq!(shaped(r"~dave\x", FileOp::Read), Err(ShapeError::TildeUser));
    assert_eq!(shaped("~dave", FileOp::Read), Err(ShapeError::TildeUser));
}

#[test]
fn windows_path_shape_refuses_a_path_that_grows_past_the_limit() {
    let long = format!(r"C:\{}", "a".repeat(PATH_MAX_BYTES));
    assert_eq!(shaped(&long, FileOp::Read), Err(ShapeError::TooLong));
    // Home-relative: the profile counts.
    let rel = "a".repeat(PATH_MAX_BYTES - 5);
    assert_eq!(shaped(&rel, FileOp::Read), Err(ShapeError::TooLong));
}

#[test]
fn windows_path_shape_errors_never_echo_the_request() {
    for raw in [
        r"~secret-name\x",
        r"\\secret-host\share",
        r"C:\secret-dir\f:stream",
        r"C:\secret-dir\NUL",
    ] {
        let err = shaped(raw, FileOp::Read).unwrap_err();
        assert!(!err.to_string().contains("secret"), "{err}");
    }
}

#[test]
fn windows_name_if_dir_is_one_plain_component() {
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
        b"con.txt",
        b"a.",
        b"a ",
        b"a*b",
        &[b'a'; NAME_MAX_BYTES + 1],
    ] {
        assert_eq!(shape_name_if_dir(bad), Err(ShapeError::BadName), "{bad:?}");
    }
}

// --- spelling helpers ---

#[test]
fn windows_drive_paths_split_into_a_drive_and_components() {
    let split = split_drive_path(r"C:\a\b").unwrap();
    assert_eq!(
        (split.drive, split.parts.as_slice()),
        ('C', &["a".to_string(), "b".to_string()][..])
    );
    assert_eq!(split.render(), r"C:\a\b");
    assert_eq!(split_drive_path("c:/a//b/").unwrap().render(), r"c:\a\b");
    assert_eq!(split_drive_path(r"C:\").unwrap().render(), r"C:\");
    for bad in [
        "",
        "C:",
        "C:x",
        r"\a",
        "a",
        r"\\server\share",
        r"\\?\C:\a",
        "1:\\a",
        "é:\\a",
    ] {
        assert!(split_drive_path(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn windows_final_paths_lose_their_verbatim_prefix() {
    assert_eq!(strip_verbatim_prefix(r"\\?\C:\a\b"), r"C:\a\b");
    assert_eq!(
        strip_verbatim_prefix(r"\\?\UNC\server\share\x"),
        r"\\server\share\x"
    );
    assert_eq!(strip_verbatim_prefix(r"C:\a"), r"C:\a");
    // A volume with no drive letter keeps its shape and is not a drive path.
    let volume = strip_verbatim_prefix(r"\\?\Volume{1234}\a");
    assert_eq!(volume, r"Volume{1234}\a");
    assert!(split_drive_path(&volume).is_none());
}

// --- normalization (decision 6-2) ---

/// A fake filesystem: `C:\` and `C:\real` are directories, `C:\real\f.txt`
/// is a file, `C:\link` is a junction to `C:\real`, `C:\out` leads to a UNC
/// share and `C:\vol` to a volume with no letter.
fn fake(prefix: &str) -> io::Result<Resolved> {
    let dir = |path: &str| {
        Ok(Resolved {
            path: path.into(),
            is_dir: true,
        })
    };
    match prefix.to_ascii_lowercase().as_str() {
        r"c:\" => dir(r"C:\"),
        r"c:\real" => dir(r"C:\real"),
        r"c:\real\f.txt" => Ok(Resolved {
            path: r"C:\real\f.txt".into(),
            is_dir: false,
        }),
        r"c:\link" => dir(r"C:\real"),
        r"c:\out" => dir(r"\\server\share"),
        r"c:\vol" => dir(r"Volume{1}\x"),
        r"c:\locked" => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        _ => Err(io::Error::from(io::ErrorKind::NotFound)),
    }
}

#[test]
fn windows_normalize_follows_existing_links_and_takes_the_on_disk_spelling() {
    assert_eq!(
        normalize_with(r"C:\link\f.txt", &fake).unwrap(),
        r"C:\real\f.txt"
    );
    assert_eq!(
        normalize_with(r"c:\LINK\f.txt", &fake).unwrap(),
        r"C:\real\f.txt"
    );
    assert_eq!(normalize_with(r"C:\real", &fake).unwrap(), r"C:\real");
}

#[test]
fn windows_normalize_folds_the_missing_tail_lexically() {
    assert_eq!(
        normalize_with(r"C:\real\new\deeper\file", &fake).unwrap(),
        r"C:\real\new\deeper\file"
    );
    // `.`, `..` and doubled separators fold; `..` removes the component
    // before it, existing or not.
    assert_eq!(
        normalize_with(r"C:\real\missing\..\new\.\deeper\\file", &fake).unwrap(),
        r"C:\real\new\deeper\file"
    );
    assert_eq!(
        normalize_with(r"C:\real\missing\..\..\real\b.txt", &fake).unwrap(),
        r"C:\real\b.txt"
    );
}

#[test]
fn windows_normalize_folds_dotdot_before_resolving_as_win32_does() {
    // Win32 folds `..` in the string before the kernel sees the path, so
    // `link\..` is `C:\`, not the parent of the junction's target.
    assert_eq!(normalize_with(r"C:\link\..\new", &fake).unwrap(), r"C:\new");
}

#[test]
fn windows_normalize_root_and_dotdot_at_root() {
    assert_eq!(normalize_with(r"C:\", &fake).unwrap(), r"C:\");
    assert_eq!(normalize_with(r"C:\..\..\", &fake).unwrap(), r"C:\");
}

#[test]
fn windows_normalize_refuses_files_used_as_directories_and_other_failures() {
    assert_eq!(
        normalize_with(r"C:\real\f.txt\below", &fake),
        Err(NormalizeError::Io(io::ErrorKind::NotADirectory))
    );
    assert_eq!(
        normalize_with(r"C:\locked\x", &fake),
        Err(NormalizeError::Io(io::ErrorKind::PermissionDenied)),
        "only a missing path shortens the prefix"
    );
    // A drive that does not exist: nothing resolves, not even the root.
    assert_eq!(
        normalize_with(r"Z:\x", &fake),
        Err(NormalizeError::Io(io::ErrorKind::NotFound))
    );
}

#[test]
fn windows_normalize_refuses_a_result_that_is_not_a_drive_path() {
    for raw in [r"C:\out\x", r"C:\vol\x"] {
        assert_eq!(
            normalize_with(raw, &fake),
            Err(NormalizeError::Io(io::ErrorKind::InvalidInput)),
            "{raw:?}"
        );
    }
}

#[test]
fn windows_normalize_needs_an_absolute_drive_path_within_the_limit() {
    for raw in ["relative", r"\x", "C:x", r"\\server\share", r"\\?\C:\x"] {
        assert_eq!(
            normalize_with(raw, &fake),
            Err(NormalizeError::NotAbsolute),
            "{raw:?}"
        );
    }
    let long = format!(r"C:\{}", "a".repeat(PATH_MAX_BYTES));
    assert_eq!(normalize_with(&long, &fake), Err(NormalizeError::TooLong));
}

// --- the three cases the milestone plan names ---

#[test]
fn windows_remote_path_treats_slash_and_backslash_alike() {
    for (slash, back) in [
        ("C:/srv/a/b", r"C:\srv\a\b"),
        ("~/a/b", r"~\a\b"),
        ("a/b/", r"a\b\"),
        ("C:/srv/../a", r"C:\srv\..\a"),
    ] {
        let a = shaped(slash, FileOp::Read).unwrap();
        let b = shaped(back, FileOp::Read).unwrap();
        assert_eq!(a, b, "{slash:?} vs {back:?}");
    }
    // Mixed separators in one path.
    assert_eq!(abs(r"C:\srv/a\b"), r"C:\srv\a\b");
}

#[test]
fn windows_remote_path_resolves_relative_and_empty_to_userprofile() {
    // The client sends an empty remote path as `~`; a relative path is
    // relative to the same directory.
    assert_eq!(abs("~"), PROFILE);
    assert_eq!(abs("notes.txt"), r"C:\Users\serve\notes.txt");
    assert_eq!(abs(r"a\b"), r"C:\Users\serve\a\b");
    // Never to the process's own environment: with no profile there is no
    // answer, not a guess.
    assert_eq!(
        shape("notes.txt", FileOp::Read, None),
        Err(ShapeError::NoHome)
    );
    assert_eq!(shape("~", FileOp::Read, None), Err(ShapeError::NoHome));
}

#[test]
fn windows_remote_path_refuses_unc_and_device_namespaces_before_acl() {
    for raw in [
        r"\\server\share\x",
        "//server/share/x",
        r"\\?\C:\x",
        r"\\?\UNC\server\share",
        r"\\.\pipe\x",
        r"\\.\COM1",
    ] {
        assert_eq!(
            shaped(raw, FileOp::Read),
            Err(ShapeError::UncOrDevice),
            "{raw:?}"
        );
        assert_eq!(shaped(raw, FileOp::Write), Err(ShapeError::UncOrDevice));
    }
}
