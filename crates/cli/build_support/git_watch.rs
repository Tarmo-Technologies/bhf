// SPDX-License-Identifier: Apache-2.0

//! Which git files the cli build script watches, shared with the test that
//! checks the list (`tests/build_git_watch.rs`).
//!
//! `packed-refs` and `refs/tags` live in the git directory every worktree of
//! a clone shares, so watching them rebuilt bhf in every worktree whenever any
//! of them fetched, packed refs or deleted a branch. A development build stamps
//! only its own commit, so it watches only this worktree's `HEAD` (and the
//! branch ref the build script resolves from it). A release build takes its
//! version from the package and needs nothing more.

/// The `git rev-parse --git-path` names the build script watches.
pub fn watched_git_paths() -> &'static [&'static str] {
    &["HEAD"]
}

/// The version a development build reports: the package version and the
/// short commit, e.g. `v0.3.0-dev+5136e5d`.
pub fn dev_version(package_version: &str, short_commit: Option<&str>) -> String {
    match short_commit {
        Some(commit) => format!("v{package_version}-dev+{commit}"),
        None => format!("v{package_version}-dev"),
    }
}
