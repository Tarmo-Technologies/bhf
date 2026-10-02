// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

/// Resolve a `--finding` / positional argument against the default work dir.
pub fn resolve_finding_arg(positional: Option<PathBuf>, named: Option<PathBuf>) -> PathBuf {
    resolve_finding_arg_in(Path::new("bhf_work"), positional, named)
}

/// Resolve a `--finding` / positional argument: an existing directory or an
/// absolute path is used as-is; a bare id is looked up via
/// [`corpus::layout::resolve_finding_id`] under `work_dir`.
pub fn resolve_finding_arg_in(
    work_dir: &Path,
    positional: Option<PathBuf>,
    named: Option<PathBuf>,
) -> PathBuf {
    let raw = named
        .or(positional)
        .expect("clap enforces a finding argument");
    if raw.is_dir() || raw.is_absolute() {
        return raw;
    }
    let looks_like_id = raw.components().count() == 1;
    if looks_like_id {
        if let Some(found) = raw
            .to_str()
            .and_then(|id| corpus::layout::resolve_finding_id(work_dir, id))
        {
            return found;
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::resolve_finding_arg_in;
    use std::path::PathBuf;

    #[test]
    fn bare_id_resolves_under_work_dir_results() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("bhf_work");
        std::fs::create_dir_all(work.join("results/findings/F-0001-ab")).unwrap();
        let got = resolve_finding_arg_in(&work, None, Some(PathBuf::from("F-0001-ab")));
        assert_eq!(got, work.join("results/findings/F-0001-ab"));
    }

    #[test]
    fn explicit_dir_is_returned_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let got = resolve_finding_arg_in(tmp.path(), Some(tmp.path().to_path_buf()), None);
        assert_eq!(got, tmp.path());
    }

    #[test]
    fn bare_id_falls_back_to_legacy_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("bhf_work");
        std::fs::create_dir_all(work.join("findings/F-0001-ab")).unwrap();
        let got = resolve_finding_arg_in(&work, None, Some(PathBuf::from("F-0001-ab")));
        assert_eq!(got, work.join("findings/F-0001-ab"));
    }

    #[test]
    fn unresolvable_bare_id_returns_raw() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("bhf_work");
        std::fs::create_dir_all(&work).unwrap();
        let got = resolve_finding_arg_in(&work, None, Some(PathBuf::from("F-does-not-exist")));
        assert_eq!(got, PathBuf::from("F-does-not-exist"));
    }
}
