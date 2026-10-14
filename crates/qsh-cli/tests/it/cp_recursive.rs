//! L5 — `qsh cp -r` end to end (ADR-0029 decisions 12, 14, 20 to 22,
//! `docs/CLI.md` §6.21), PLAN M15 Step 15.
//!
//! The same real-process rigs as `cp_e2e.rs`: a `qsh serve` host (forward)
//! or a `qsh listen` controller plus a `qsh serve --to` target (reverse),
//! and `qsh cp` as a subprocess. A hostile host and a lost connection need a
//! scripted peer, so those live in `qsh-testkit`'s `cp_scripted_host.rs`.

#![cfg(unix)]

use crate::cp_e2e::{Forward, Reverse, digests, write_random_file};

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde_json::Value;

/// What a tree holds, keyed by path relative to its root: `dir`,
/// `file:<blake3>` or `link:<target>`, each with the permission bits.
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        names.sort();
        for name in names {
            let path = dir.join(&name);
            let rel = path
                .strip_prefix(base)
                .expect("under base")
                .to_string_lossy()
                .into_owned();
            let md = std::fs::symlink_metadata(&path).expect("lstat");
            let mode = md.mode() & 0o777;
            if md.is_dir() {
                out.insert(rel, format!("dir:{mode:o}"));
                walk(base, &path, out);
            } else if md.file_type().is_symlink() {
                let target = std::fs::read_link(&path).expect("readlink");
                out.insert(rel, format!("link:{}", target.display()));
            } else {
                out.insert(rel, format!("file:{}:{mode:o}", digests(&path).0));
            }
        }
    }
    let mut out = BTreeMap::new();
    out.insert(String::new(), {
        let md = std::fs::metadata(root).expect("stat root");
        format!("dir:{:o}", md.mode() & 0o777)
    });
    walk(root, root, &mut out);
    out
}

fn count(snap: &BTreeMap<String, String>, prefix: &str) -> u64 {
    snap.values().filter(|v| v.starts_with(prefix)).count() as u64
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// A tree with nesting, an empty directory, an empty file, a file larger
/// than one transfer chunk, names with spaces and non-ASCII letters, and a
/// spread of permission bits.
fn build_tree(root: &Path) {
    std::fs::create_dir(root).expect("tree root");
    std::fs::write(root.join("a.txt"), b"alpha\n").unwrap();
    std::fs::write(root.join("empty.bin"), b"").unwrap();
    std::fs::write(root.join("with space.txt"), b"spaced").unwrap();
    std::fs::write(root.join("ünï-çødé.txt"), "unicode".as_bytes()).unwrap();
    write_random_file(&root.join("big.bin"), 300_000, 0xB16);
    std::fs::write(root.join("run.sh"), b"#!/bin/sh\n").unwrap();
    set_mode(&root.join("run.sh"), 0o755);
    std::fs::write(root.join("secret.key"), b"k").unwrap();
    set_mode(&root.join("secret.key"), 0o600);
    std::fs::create_dir_all(root.join("sub/deep/er")).unwrap();
    std::fs::write(root.join("sub/one.txt"), b"one").unwrap();
    std::fs::write(root.join("sub/deep/two.txt"), b"two").unwrap();
    std::fs::write(root.join("sub/deep/er/three.txt"), b"three").unwrap();
    std::fs::create_dir(root.join("empty-dir")).unwrap();
    set_mode(&root.join("sub/deep"), 0o750);
}

/// put a tree to a name that does not exist yet, get it back to a name that
/// does not exist yet, then into existing directories, comparing the whole
/// tree (content, kinds, permission bits under `-p`) at every hop.
fn tree_round_trip(
    work: &Path,
    remote: impl Fn(&str) -> String,
    run: impl Fn(&[&str]) -> (i32, Value),
) {
    let tree = work.join("tree");
    build_tree(&tree);
    let want = snapshot(&tree);
    let files = count(&want, "file:");
    let dirs = count(&want, "dir:");

    // put to a missing name: the destination becomes the tree.
    let (code, put) = run(&["-r", "-p", tree.to_str().unwrap(), &remote("stored")]);
    assert_eq!(code, 0, "put -r failed: {put}");
    assert_eq!(put["data"]["direction"], "put", "{put}");
    assert_eq!(put["data"]["files"], files, "{put}");
    assert_eq!(put["data"]["directories"], dirs, "{put}");
    assert_eq!(put["data"]["skipped"], 0, "{put}");
    assert_eq!(snapshot(&work.join("stored")), want, "put changed the tree");

    // get to a missing name.
    let back = work.join("back");
    let (code, get) = run(&["-r", "-p", &remote("stored"), back.to_str().unwrap()]);
    assert_eq!(code, 0, "get -r failed: {get}");
    assert_eq!(get["data"]["direction"], "get", "{get}");
    assert_eq!(get["data"]["files"], files, "{get}");
    assert_eq!(get["data"]["directories"], dirs, "{get}");
    assert_eq!(snapshot(&back), want, "get changed the tree");

    // put into an existing directory: it lands under the source's name.
    let existing = work.join("existing");
    std::fs::create_dir(&existing).unwrap();
    let (code, put) = run(&["-r", "-p", tree.to_str().unwrap(), &remote("existing")]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(snapshot(&existing.join("tree")), want);

    // get into an existing directory: likewise.
    let into = work.join("into");
    std::fs::create_dir(&into).unwrap();
    let (code, get) = run(&["-r", "-p", &remote("stored"), into.to_str().unwrap()]);
    assert_eq!(code, 0, "{get}");
    assert_eq!(snapshot(&into.join("stored")), want);

    // Copying again merges into the tree that is already there: files are
    // replaced, directories are not new (`directories` counts only new ones).
    std::fs::write(existing.join("tree/a.txt"), b"stale").unwrap();
    let (code, put) = run(&["-r", "-p", tree.to_str().unwrap(), &remote("existing")]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(put["data"]["files"], files, "{put}");
    assert_eq!(put["data"]["directories"], 0, "{put}");
    assert_eq!(snapshot(&existing.join("tree")), want, "{put}");

    crate::cp_e2e::assert_no_part_files(work);
}

#[test]
fn cp_recursive_round_trip_tree_is_identical_forward() {
    let rig = Forward::start();
    tree_round_trip(
        rig.work.path(),
        |name| rig.remote(name),
        |args| rig.cp_json(args),
    );
}

#[test]
fn cp_recursive_round_trip_tree_is_identical_reverse() {
    let rig = Reverse::start();
    tree_round_trip(
        rig.work.path(),
        |name| rig.remote(name),
        |args| rig.cp_json(args),
    );
}

fn entries_with<'a>(value: &'a Value, status: &str) -> Vec<&'a Value> {
    value["data"]["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|e| e["status"] == status)
        .collect()
}

#[test]
fn cp_recursive_skips_symlinks_inside_trees_and_follows_an_operand_symlink() {
    let rig = Forward::start();
    let work = rig.work.path();
    let tree = work.join("t");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("real.txt"), b"real").unwrap();
    std::fs::write(tree.join("sub/inner.txt"), b"inner").unwrap();
    std::os::unix::fs::symlink("real.txt", tree.join("link-file")).unwrap();
    std::os::unix::fs::symlink("sub", tree.join("link-dir")).unwrap();
    std::os::unix::fs::symlink("nowhere", tree.join("dangling")).unwrap();

    // put: three skipped symlinks, the rest copied.
    let (code, put) = rig.cp_json(&["-r", tree.to_str().unwrap(), &rig.remote("out")]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(put["data"]["files"], 2, "{put}");
    assert_eq!(put["data"]["skipped"], 3, "{put}");
    let skipped = entries_with(&put, "skipped");
    assert_eq!(skipped.len(), 3, "{put}");
    assert!(skipped.iter().all(|e| e["reason"] == "symlink"), "{put}");
    let out = work.join("out");
    assert_eq!(
        snapshot(&out).keys().cloned().collect::<Vec<_>>(),
        vec!["", "real.txt", "sub", "sub/inner.txt"],
        "no symlink may reach the host"
    );

    // get: the same tree on the host side.
    let (code, get) = rig.cp_json(&["-r", &rig.remote("t"), work.join("got").to_str().unwrap()]);
    assert_eq!(code, 0, "{get}");
    assert_eq!(get["data"]["skipped"], 3, "{get}");
    assert!(
        entries_with(&get, "skipped")
            .iter()
            .all(|e| e["reason"] == "symlink"),
        "{get}"
    );
    assert_eq!(
        snapshot(&work.join("got"))
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["", "real.txt", "sub", "sub/inner.txt"],
    );

    // An operand that is itself a symlink to a directory is followed, on
    // both sides, and its own contents are walked as usual.
    let operand_link = work.join("operand-link");
    std::os::unix::fs::symlink(&tree, &operand_link).unwrap();
    let (code, put) = rig.cp_json(&["-r", operand_link.to_str().unwrap(), &rig.remote("out2")]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(put["data"]["files"], 2, "{put}");
    assert_eq!(put["data"]["skipped"], 3, "{put}");
    assert!(work.join("out2/sub/inner.txt").is_file());

    let (code, get) = rig.cp_json(&[
        "-r",
        &rig.remote("operand-link"),
        work.join("got2").to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{get}");
    assert_eq!(get["data"]["files"], 2, "{get}");
    assert!(work.join("got2/sub/inner.txt").is_file());
    crate::cp_e2e::assert_no_part_files(work);
}

#[test]
fn cp_special_files_fail_their_entry_and_the_walk_continues() {
    let rig = Forward::start();
    let work = rig.work.path();
    let tree = work.join("t");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a.txt"), b"a").unwrap();
    std::fs::write(tree.join("sub/z.txt"), b"z").unwrap();
    nix::unistd::mkfifo(
        &tree.join("pipe"),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .expect("mkfifo");

    // put: the fifo is its own failed entry; both files still arrive.
    let (code, put) = rig.cp_json(&["-r", tree.to_str().unwrap(), &rig.remote("out")]);
    assert_eq!(code, 255, "{put}");
    let details = &put["error"]["details"];
    assert_eq!(details["failed"], 1, "{put}");
    assert_eq!(details["copied"], 2, "{put}");
    assert_eq!(details["not_attempted"], 0, "{put}");
    assert_eq!(details["failures"][0]["side"], "local", "{put}");
    assert_eq!(details["failures"][0]["code"], "INVALID_ARGUMENT", "{put}");
    assert_eq!(std::fs::read(work.join("out/a.txt")).unwrap(), b"a");
    assert_eq!(std::fs::read(work.join("out/sub/z.txt")).unwrap(), b"z");
    assert!(!work.join("out/pipe").exists(), "{put}");

    // get: the host lists the fifo; it fails there, the rest is copied.
    let got = work.join("got");
    let (code, get) = rig.cp_json(&["-r", &rig.remote("t"), got.to_str().unwrap()]);
    assert_eq!(code, 255, "{get}");
    let details = &get["error"]["details"];
    assert_eq!(details["failed"], 1, "{get}");
    assert_eq!(details["copied"], 2, "{get}");
    assert_eq!(details["failures"][0]["side"], "remote", "{get}");
    assert_eq!(details["failures"][0]["code"], "INVALID_ARGUMENT", "{get}");
    assert_eq!(std::fs::read(got.join("sub/z.txt")).unwrap(), b"z");
    assert!(!got.join("pipe").exists(), "{get}");
    crate::cp_e2e::assert_no_part_files(work);
}

#[test]
fn cp_dot_source_copies_contents() {
    let rig = Forward::start();
    let work = rig.work.path();
    let tree = work.join("t");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a.txt"), b"a").unwrap();
    std::fs::write(tree.join("sub/b.txt"), b"b").unwrap();
    let dot = format!("{}/.", tree.display());

    // put `t/.` into an existing directory: contents land directly in it.
    let existing = work.join("existing");
    std::fs::create_dir(&existing).unwrap();
    let (code, put) = rig.cp_json(&["-r", &dot, &rig.remote("existing")]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(std::fs::read(existing.join("a.txt")).unwrap(), b"a");
    assert_eq!(std::fs::read(existing.join("sub/b.txt")).unwrap(), b"b");
    assert!(!existing.join("t").exists(), "{put}");
    // The destination already existed, so it is not counted as created.
    assert_eq!(put["data"]["directories"], 1, "only sub: {put}");

    // put `t/.` to a missing name: the name becomes the tree.
    let (code, put) = rig.cp_json(&["-r", &dot, &rig.remote("fresh")]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(std::fs::read(work.join("fresh/sub/b.txt")).unwrap(), b"b");

    // get `host:t/.` into an existing directory, and to a missing name.
    let remote_dot = format!("{}/.", rig.remote("t"));
    let into = work.join("into");
    std::fs::create_dir(&into).unwrap();
    let (code, get) = rig.cp_json(&["-r", &remote_dot, into.to_str().unwrap()]);
    assert_eq!(code, 0, "{get}");
    assert_eq!(std::fs::read(into.join("a.txt")).unwrap(), b"a");
    assert_eq!(std::fs::read(into.join("sub/b.txt")).unwrap(), b"b");
    assert!(!into.join("t").exists(), "{get}");
    let fresh = work.join("fresh-get");
    let (code, get) = rig.cp_json(&["-r", &remote_dot, fresh.to_str().unwrap()]);
    assert_eq!(code, 0, "{get}");
    assert_eq!(std::fs::read(fresh.join("sub/b.txt")).unwrap(), b"b");

    // A file operand under -r is an ordinary file copy.
    let (code, put) = rig.cp_json(&[
        "-r",
        tree.join("a.txt").to_str().unwrap(),
        &rig.remote("plain.txt"),
    ]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(std::fs::read(work.join("plain.txt")).unwrap(), b"a");
}

/// Restores owner access under a tree on drop, so the temp dir can go even
/// when an assertion fails halfway.
struct Unlock(PathBuf);

impl Unlock {
    fn tree(path: &Path) {
        if let Ok(md) = std::fs::symlink_metadata(path)
            && md.is_dir()
        {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
            if let Ok(read) = std::fs::read_dir(path) {
                for entry in read.flatten() {
                    Self::tree(&entry.path());
                }
            }
        }
    }
}

impl Drop for Unlock {
    fn drop(&mut self) {
        Self::tree(&self.0);
    }
}

#[test]
fn cp_directories_are_owner_writable_while_filling() {
    let rig = Forward::start();
    let work = rig.work.path();
    let _unlock = Unlock(work.to_path_buf());
    let tree = work.join("ro");
    std::fs::create_dir_all(tree.join("inner")).unwrap();
    std::fs::write(tree.join("file.txt"), b"f").unwrap();
    std::fs::write(tree.join("inner/deep.txt"), b"d").unwrap();
    set_mode(&tree.join("inner"), 0o500);
    set_mode(&tree, 0o555);

    for (label, flags) in [("default", vec!["-r"]), ("preserve", vec!["-r", "-p"])] {
        let remote_dst = format!("put-{label}");
        let mut args = flags.clone();
        let remote_arg = rig.remote(&remote_dst);
        args.extend([tree.to_str().unwrap(), remote_arg.as_str()]);
        let (code, put) = rig.cp_json(&args);
        assert_eq!(code, 0, "{label} put: {put}");
        let out = work.join(&remote_dst);
        assert_eq!(std::fs::read(out.join("inner/deep.txt")).unwrap(), b"d");
        for dir in [out.clone(), out.join("inner")] {
            let mode = std::fs::metadata(&dir).unwrap().mode() & 0o777;
            assert_eq!(mode & 0o700, 0o700, "{label} put: {dir:?} is {mode:o}");
        }

        let local_dst = work.join(format!("get-{label}"));
        let mut args = flags.clone();
        let source = rig.remote("ro");
        args.extend([source.as_str(), local_dst.to_str().unwrap()]);
        let (code, get) = rig.cp_json(&args);
        assert_eq!(code, 0, "{label} get: {get}");
        assert_eq!(
            std::fs::read(local_dst.join("inner/deep.txt")).unwrap(),
            b"d"
        );
        for dir in [local_dst.clone(), local_dst.join("inner")] {
            let mode = std::fs::metadata(&dir).unwrap().mode() & 0o777;
            assert_eq!(mode & 0o700, 0o700, "{label} get: {dir:?} is {mode:o}");
        }
    }
    crate::cp_e2e::assert_no_part_files(work);
}

#[test]
fn cp_json_truncates_entries_but_not_totals() {
    let rig = Forward::start();
    let work = rig.work.path();

    // More successes than the envelope lists: 1100 files, 1000 entries.
    let many = work.join("many");
    std::fs::create_dir(&many).unwrap();
    for i in 0..1100 {
        std::fs::write(many.join(format!("f{i:04}")), format!("{i}")).unwrap();
    }
    let (code, put) = rig.cp_json(&["-r", many.to_str().unwrap(), &rig.remote("many-out")]);
    assert_eq!(code, 0, "{put}");
    assert_eq!(put["data"]["files"], 1100, "{put}");
    assert_eq!(put["data"]["directories"], 1, "{put}");
    assert_eq!(put["data"]["entries"].as_array().unwrap().len(), 1000);
    assert_eq!(put["data"]["entries_truncated"], true, "{put}");
    assert_eq!(
        std::fs::read_dir(work.join("many-out")).unwrap().count(),
        1100
    );

    // More failures than the error lists: 70 fifos, 64 failures.
    let bad = work.join("bad");
    std::fs::create_dir(&bad).unwrap();
    std::fs::write(bad.join("ok.txt"), b"ok").unwrap();
    for i in 0..70 {
        nix::unistd::mkfifo(
            &bad.join(format!("p{i:02}")),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .expect("mkfifo");
    }
    let (code, put) = rig.cp_json(&["-r", bad.to_str().unwrap(), &rig.remote("bad-out")]);
    assert_eq!(code, 255, "{put}");
    let details = &put["error"]["details"];
    assert_eq!(details["failed"], 70, "{put}");
    assert_eq!(details["copied"], 1, "{put}");
    assert_eq!(details["failures"].as_array().unwrap().len(), 64, "{put}");
    assert_eq!(details["failures_truncated"], true, "{put}");
    assert!(
        put["error"]["message"]
            .as_str()
            .unwrap()
            .contains("70 of 72"),
        "the message counts every entry: {put}"
    );
}

#[test]
fn cp_human_mode_prints_a_failed_item_once_and_closes_with_a_one_line_summary() {
    let rig = Forward::start();
    let work = rig.work.path();
    let dir = work.join("dir");
    std::fs::create_dir(&dir).unwrap();
    let good = work.join("good.txt");
    std::fs::write(&good, b"good").unwrap();
    let missing = work.join("missing-source.txt");
    let output = rig.cp(&[
        good.to_str().unwrap(),
        missing.to_str().unwrap(),
        &rig.remote("dir"),
    ]);
    assert_eq!(crate::common::exit_code(&output), 255);
    let stderr = crate::cp_e2e::stderr_of(&output);
    let item_lines = stderr
        .lines()
        .filter(|l| l.contains("missing-source.txt"))
        .count();
    assert_eq!(item_lines, 1, "the failed item is named once:\n{stderr}");
    let summaries: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("entries failed"))
        .collect();
    assert_eq!(summaries.len(), 1, "{stderr}");
    assert_eq!(
        summaries[0], "qsh: 1 of 2 entries failed (INVALID_ARGUMENT)",
        "the summary does not repeat the item's text"
    );
    assert!(output.stdout.is_empty(), "human errors stay on stderr");
}
