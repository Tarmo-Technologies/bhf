// SPDX-License-Identifier: Apache-2.0

//! The cli build script's git watch list (`build_support/git_watch.rs`): a
//! development build watches only files of its own worktree, so a fetch, a
//! `git pack-refs` or a branch deletion in another worktree of the same clone
//! does not rebuild it.

#[path = "../build_support/git_watch.rs"]
mod git_watch;

#[test]
fn the_dev_watch_list_has_no_shared_refs() {
    let watched = git_watch::watched_git_paths();
    assert!(watched.contains(&"HEAD"), "{watched:?}");
    for shared in [
        "packed-refs",
        "refs/tags",
        "refs",
        "FETCH_HEAD",
        "ORIG_HEAD",
    ] {
        assert!(
            !watched.contains(&shared),
            "{shared} is shared: {watched:?}"
        );
    }
}

#[test]
fn a_dev_build_reports_its_commit() {
    assert_eq!(
        git_watch::dev_version("0.3.0", Some("5136e5d")),
        "v0.3.0-dev+5136e5d"
    );
    assert_eq!(git_watch::dev_version("0.3.0", None), "v0.3.0-dev");
}

#[test]
fn this_build_reports_a_dev_or_release_version() {
    let version = env!("BHF_VERSION_FULL");
    let package = env!("CARGO_PKG_VERSION");
    assert!(
        version == format!("v{package}") || version.starts_with(&format!("v{package}-dev")),
        "{version}"
    );
}
