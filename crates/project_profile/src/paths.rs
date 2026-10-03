// SPDX-License-Identifier: Apache-2.0

//! Resolve and sanity-check asset paths declared in a manifest.
//!
//! Every path is interpreted relative to the manifest's own directory. By
//! default a path may not escape that directory (`..` components) and may not
//! be absolute — both are the sort of thing a hostile or careless manifest
//! would use to read files outside the project. The operator opts into either
//! with `--allow-external-paths`, which flips [`ResolveOptions::allow_external`].

use std::path::{Component, Path, PathBuf};

use crate::error::ProjectError;

/// Options controlling path-safety behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolveOptions {
    /// Permit absolute paths and `..` escapes outside the manifest directory.
    pub allow_external: bool,
}

/// Classify a raw path for the escape / absolute checks, before any FS access.
fn is_absolute_or_prefixed(raw: &Path) -> bool {
    raw.components()
        .next()
        .is_some_and(|c| matches!(c, Component::RootDir | Component::Prefix(_)))
}

fn has_parent_escape(raw: &Path) -> bool {
    raw.components().any(|c| matches!(c, Component::ParentDir))
}

/// Resolve a single declared asset path against the manifest directory and
/// confirm it exists.
///
/// Order of checks matters: path-safety (escape / absolute) is rejected before
/// existence, so a `../etc/passwd` is reported as an escape regardless of
/// whether it happens to exist. With `allow_external` the safety checks are
/// skipped, but the asset must still exist.
pub fn resolve_asset(
    manifest_dir: &Path,
    raw: &Path,
    opts: &ResolveOptions,
) -> Result<PathBuf, ProjectError> {
    if !opts.allow_external {
        if is_absolute_or_prefixed(raw) {
            return Err(ProjectError::AbsolutePathNotAllowed(
                raw.display().to_string(),
            ));
        }
        if has_parent_escape(raw) {
            return Err(ProjectError::PathEscape(raw.display().to_string()));
        }
    }

    let resolved = if is_absolute_or_prefixed(raw) {
        raw.to_path_buf()
    } else {
        manifest_dir.join(raw)
    };

    if !resolved.exists() {
        return Err(ProjectError::MissingAsset(resolved));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn touch(dir: &Path, rel: &str) -> PathBuf {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn rejects_parent_escape() {
        let dir = tempdir().unwrap();
        let err = resolve_asset(
            dir.path(),
            Path::new("../outside.bin"),
            &ResolveOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ProjectError::PathEscape(_)), "{err:?}");
    }

    #[test]
    fn rejects_absolute_without_flag() {
        let dir = tempdir().unwrap();
        let err = resolve_asset(
            dir.path(),
            Path::new("/etc/passwd"),
            &ResolveOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ProjectError::AbsolutePathNotAllowed(_)),
            "{err:?}"
        );
    }

    #[test]
    fn allow_external_paths_permits_escape() {
        let root = tempdir().unwrap();
        let manifest_dir = root.path().join("project");
        fs::create_dir_all(&manifest_dir).unwrap();
        // The escaping target lives in the parent, outside the manifest dir.
        touch(root.path(), "outside.bin");
        let resolved = resolve_asset(
            &manifest_dir,
            Path::new("../outside.bin"),
            &ResolveOptions {
                allow_external: true,
            },
        )
        .unwrap();
        assert!(resolved.ends_with("outside.bin"));
    }

    #[test]
    fn resolves_relative_inside_manifest_dir() {
        let dir = tempdir().unwrap();
        touch(dir.path(), "corpus/seed0");
        let resolved = resolve_asset(
            dir.path(),
            Path::new("corpus/seed0"),
            &ResolveOptions::default(),
        )
        .unwrap();
        assert_eq!(resolved, dir.path().join("corpus/seed0"));
    }

    #[test]
    fn missing_asset_reported() {
        let dir = tempdir().unwrap();
        let err = resolve_asset(
            dir.path(),
            Path::new("corpus/ghost"),
            &ResolveOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ProjectError::MissingAsset(_)), "{err:?}");
    }
}
