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

/// Why `finding_dir` is not a finding, naming the path that was looked at, or
/// `None` when it holds a `finding.json` (or, for a session finding, a
/// `session.json`). Replay and minimize check this before anything runs, so a
/// mistyped path is not reported as a harness problem.
pub fn missing_finding(finding_dir: &Path) -> Option<String> {
    if finding_dir.join("finding.json").is_file() || finding_dir.join("session.json").is_file() {
        return None;
    }
    let problem = if finding_dir.is_dir() {
        format!("{} has no finding.json", finding_dir.display())
    } else {
        format!("{} does not exist", finding_dir.display())
    };
    Some(format!(
        "no finding at {}: {problem}. Pass a finding directory, such as \
         bhf_work/results/findings/<finding-id>, or the id of a finding in ./bhf_work",
        finding_dir.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::{missing_finding, resolve_finding_arg_in};
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

    #[test]
    fn a_missing_finding_names_the_path() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("findings/F-0001");
        let message = missing_finding(&absent).unwrap();
        assert!(
            message.starts_with(&format!("no finding at {}:", absent.display())),
            "{message}"
        );
        assert!(message.contains("does not exist"), "{message}");

        std::fs::create_dir_all(&absent).unwrap();
        assert!(missing_finding(&absent)
            .unwrap()
            .contains("has no finding.json"));

        // A session finding is its session.json.
        std::fs::write(absent.join("session.json"), "{}").unwrap();
        assert_eq!(missing_finding(&absent), None);
        std::fs::remove_file(absent.join("session.json")).unwrap();

        std::fs::write(absent.join("finding.json"), "{}").unwrap();
        assert_eq!(missing_finding(&absent), None);
    }
}
