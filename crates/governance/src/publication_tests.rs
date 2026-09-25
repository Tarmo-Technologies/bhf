// SPDX-License-Identifier: Apache-2.0
//! Filesystem regressions for Linux atomic update-pack publication.
//! These call the production helper, not a model of its behavior.

use super::publish_pack_stage;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::sync::{Arc, Barrier};

fn staged(root: &std::path::Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let stage = root.join(name);
    fs::create_dir(&stage).unwrap();
    fs::write(stage.join("item"), contents).unwrap();
    stage
}

#[test]
fn publication_moves_complete_stage_to_absent_destination() {
    let dir = tempfile::tempdir().unwrap();
    let stage = staged(dir.path(), "stage", b"verified contents");
    let target = dir.path().join("installed");
    publish_pack_stage(&stage, &target).unwrap();
    assert!(!stage.exists());
    assert_eq!(fs::read(target.join("item")).unwrap(), b"verified contents");
}

#[test]
fn publication_preserves_an_existing_empty_directory() {
    let dir = tempfile::tempdir().unwrap();
    let stage = staged(dir.path(), "stage", b"new");
    let target = dir.path().join("installed");
    fs::create_dir(&target).unwrap();
    let before = fs::metadata(&target).unwrap().ino();
    assert!(publish_pack_stage(&stage, &target).is_err());
    assert_eq!(fs::metadata(&target).unwrap().ino(), before);
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    assert_eq!(fs::read(stage.join("item")).unwrap(), b"new");
}

#[test]
fn publication_preserves_an_existing_nonempty_directory() {
    let dir = tempfile::tempdir().unwrap();
    let stage = staged(dir.path(), "stage", b"new");
    let target = staged(dir.path(), "installed", b"original");
    assert!(publish_pack_stage(&stage, &target).is_err());
    assert_eq!(fs::read(target.join("item")).unwrap(), b"original");
    assert_eq!(fs::read(stage.join("item")).unwrap(), b"new");
}

#[test]
fn publication_preserves_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let stage = staged(dir.path(), "stage", b"new");
    let target = dir.path().join("installed");
    fs::write(&target, b"original").unwrap();
    assert!(publish_pack_stage(&stage, &target).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"original");
    assert_eq!(fs::read(stage.join("item")).unwrap(), b"new");
}

#[test]
fn publication_preserves_a_dangling_destination_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let stage = staged(dir.path(), "stage", b"new");
    let target = dir.path().join("installed");
    symlink("missing", &target).unwrap();
    assert!(publish_pack_stage(&stage, &target).is_err());
    assert_eq!(fs::read_link(&target).unwrap(), std::path::Path::new("missing"));
    assert_eq!(fs::read(stage.join("item")).unwrap(), b"new");
}

#[test]
fn publication_missing_source_does_not_create_destination() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("installed");
    assert!(publish_pack_stage(&dir.path().join("missing"), &target).is_err());
    assert!(fs::symlink_metadata(&target).is_err());
}

#[test]
fn publication_rejects_nul_paths_without_changing_stage() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    let stage = staged(dir.path(), "stage", b"new");
    let target = dir.path().join(std::ffi::OsString::from_vec(b"bad\0name".to_vec()));
    assert!(publish_pack_stage(&stage, &target).is_err());
    assert_eq!(fs::read(stage.join("item")).unwrap(), b"new");
}

#[test]
fn publication_allows_exactly_one_concurrent_publisher() {
    let dir = tempfile::tempdir().unwrap();
    let stages = [
        staged(dir.path(), "stage-a", b"a"),
        staged(dir.path(), "stage-b", b"b"),
    ];
    let target = dir.path().join("installed");
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = stages.iter().cloned().map(|stage| {
        let target = target.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            publish_pack_stage(&stage, &target).is_ok()
        })
    }).collect();
    let results: Vec<_> = handles.into_iter().map(|handle| handle.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|&&won| won).count(), 1);
    let winner = if results[0] { 0 } else { 1 };
    let expected: &[u8] = if winner == 0 { b"a" } else { b"b" };
    assert_eq!(fs::read(target.join("item")).unwrap(), expected);
    assert!(!stages[winner].exists());
    assert!(stages[1 - winner].join("item").is_file());
}
