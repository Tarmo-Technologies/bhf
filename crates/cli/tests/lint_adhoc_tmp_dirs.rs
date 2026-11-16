// SPDX-License-Identifier: Apache-2.0

//! Test code makes its scratch directories with the `TestDir` guard
//! (`crates/cli/src/test_support.rs`) or a `tempfile` directory, both removed
//! when they are dropped, including while a failing test unwinds. A directory
//! built by hand as `temp_dir().join(format!(..))` is removed, at best, by the
//! test's last statement, so a failing test leaves it behind; this lint keeps
//! new ones out of test code. Library code that names a temporary file at run
//! time is not test code and is not checked.

use std::path::{Path, PathBuf};

/// The hand-built scratch path this lint rejects in test code.
const ADHOC: &str = concat!("temp_dir()", ".join(format!");

/// Files allowed to build such a path: the guard itself.
const ALLOWED: &[&str] = &["crates/cli/src/test_support.rs"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/cli")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if !matches!(name.to_str(), Some("target" | "vendor" | ".git")) {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The part of `text` that is test code: all of a file under a `tests` or
/// `benches` directory, else everything from the first test module on (a
/// `mod` under `#[cfg(test)]` or `#[cfg(all(test, ..))]`). A test-only item
/// elsewhere in a library file is not counted; test modules come last.
fn test_region<'a>(relative: &Path, text: &'a str) -> &'a str {
    if relative
        .components()
        .any(|part| matches!(part.as_os_str().to_str(), Some("tests" | "benches")))
    {
        return text;
    }
    let mut offset = 0;
    let mut cfg_test_at = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test") {
            cfg_test_at = Some(offset);
        } else if let Some(start) = cfg_test_at {
            let item = trimmed
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ");
            if item.starts_with("mod ") {
                return &text[start..];
            }
            if !trimmed.starts_with("#[") && !trimmed.is_empty() {
                cfg_test_at = None;
            }
        }
        offset += line.len();
    }
    ""
}

/// The 1-based lines of `text` that build an ad-hoc scratch path in test code.
fn adhoc_lines(relative: &Path, text: &str) -> Vec<usize> {
    let region = test_region(relative, text);
    let first = text[..text.len() - region.len()].matches('\n').count();
    region
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(ADHOC))
        .map(|(index, _)| first + index + 1)
        .collect()
}

#[test]
fn no_adhoc_bhf_tmp_dirs() {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    assert!(files.len() > 100, "found only {} Rust files", files.len());
    let this_file = Path::new(file!());
    let mut offenders = Vec::new();
    for path in files {
        let relative = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
        if ALLOWED.iter().any(|allowed| relative == Path::new(allowed))
            || relative.ends_with(this_file.file_name().unwrap())
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in adhoc_lines(&relative, &text) {
            offenders.push(format!("{}:{line}", relative.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "test code builds scratch dirs by hand; use the TestDir guard or a tempfile \
         directory instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_lint_flags_a_new_adhoc_site_in_test_code_only() {
    let site = format!("    let dir = std::env::{ADHOC}\"bhf-widget-{{}}\", 7));\n");
    let unit = format!("fn run() {{}}\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n{site}    }}\n}}\n");
    assert_eq!(
        adhoc_lines(Path::new("crates/widget/src/lib.rs"), &unit),
        [7]
    );
    assert_eq!(
        adhoc_lines(Path::new("crates/widget/tests/parse.rs"), &site),
        [1]
    );
    // A test-only item ahead of library code does not make it test code.
    let item_then_library = format!(
        "#[cfg(test)]\nconst WIDGET: u8 = 1;\n\npub fn event_path() -> std::path::PathBuf {{\n{site}    dir\n}}\n"
    );
    assert!(adhoc_lines(Path::new("crates/widget/src/lib.rs"), &item_then_library).is_empty());
    // Library code that names a temporary file at run time is not test code.
    let library = format!("pub fn event_path() -> std::path::PathBuf {{\n{site}    dir\n}}\n");
    assert!(adhoc_lines(Path::new("crates/widget/src/lib.rs"), &library).is_empty());
}
