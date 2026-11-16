// SPDX-License-Identifier: Apache-2.0

//! The docs describe the `results/` layout a run writes (#224). Several pages
//! still sent readers to `<work>/FINDINGS.md`, `<work>/findings.csv` and
//! `<work>/findings/`, which a run has not produced since the results
//! migration: the legacy names live on only under `results/legacy/` of a
//! migrated work dir.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{collections::BTreeSet, process::Command};

#[cfg(unix)]
mod support;

#[cfg(unix)]
#[path = "../src/test_support.rs"]
mod test_support;
#[cfg(unix)]
use test_support::TestDir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The user-facing docs: the site pages and the README.
fn docs() -> Vec<(PathBuf, String)> {
    let site = repo_root().join("docs/site");
    let mut pages: Vec<PathBuf> = std::fs::read_dir(&site)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
        .collect();
    pages.push(repo_root().join("README.md"));
    pages.sort();
    pages
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            (path, text)
        })
        .collect()
}

/// How a page names a legacy index as a path of the work dir.
fn legacy_spellings() -> Vec<String> {
    let mut names: Vec<String> = results::migrate::LEGACY_DERIVED
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    names.push("findings/".to_owned());
    let mut spellings = vec!["FINDINGS.md".to_owned()];
    for prefix in ["<work>/", "<work-dir>/", "bhf_work/", "<work_dir>/"] {
        for name in &names {
            spellings.push(format!("{prefix}{name}"));
        }
    }
    spellings
}

#[test]
fn the_docs_name_no_legacy_result_paths() {
    let spellings = legacy_spellings();
    let mut stale = Vec::new();
    for (path, text) in docs() {
        for (number, line) in text.lines().enumerate() {
            // A line about the legacy layout or its migration may name it.
            let lower = line.to_ascii_lowercase();
            if lower.contains("legacy") || lower.contains("migrat") {
                continue;
            }
            for spelling in &spellings {
                if line.contains(spelling.as_str()) {
                    stale.push(format!(
                        "{}:{}: {spelling}",
                        path.strip_prefix(repo_root()).unwrap_or(&path).display(),
                        number + 1
                    ));
                }
            }
        }
    }
    assert!(
        stale.is_empty(),
        "legacy result paths:\n{}",
        stale.join("\n")
    );
}

#[cfg(unix)]
/// The entries one level under `dir` in a `├──` tree, as names (`harnesses`
/// for `harnesses/<harness-id>/`), and whether each is marked `(when ...)`.
fn tree_entries(block: &str, indent: &str) -> Vec<(String, bool)> {
    block
        .lines()
        .filter_map(|line| {
            let rest = line
                .strip_prefix(&format!("{indent}├── "))
                .or_else(|| line.strip_prefix(&format!("{indent}└── ")))?;
            let (entry, comment) = rest.split_once('#').unwrap_or((rest, ""));
            let name = entry.trim().split('/').next().unwrap_or("").to_owned();
            Some((name, comment.contains("(when")))
        })
        .collect()
}

#[cfg(unix)]
/// The `<work>/` tree under auto.md's `## Outputs`.
fn documented_tree() -> String {
    let text = std::fs::read_to_string(repo_root().join("docs/site/auto.md")).unwrap();
    let section = text
        .split("\n## Outputs\n")
        .nth(1)
        .expect("auto.md ## Outputs");
    let block = section.split("```").nth(1).expect("the output tree block");
    assert!(block.contains("<work>/"), "{block}");
    block.to_owned()
}

#[cfg(unix)]
fn listing(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| !name.starts_with('.'))
        .collect()
}

#[cfg(unix)]
#[test]
fn the_auto_output_tree_matches_a_real_run() {
    let present = {
        Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    if !support::require_tool(present, "clang") {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("docs-output-tree");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("record.c"),
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n\
         char *volatile kept;\n\
         int parse_record(const uint8_t *data, size_t len) {\n\
         \x20   char *buf;\n\
         \x20   if (len < 4 || data[0] != 'B') return 0;\n\
         \x20   buf = malloc(8);\n\
         \x20   memcpy(buf, data, len);\n\
         \x20   kept = buf;\n\
         \x20   free(buf);\n\
         \x20   return 1;\n\
         }\n",
    )
    .unwrap();
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"BBBBBBBBBBBBBBBB").unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "5", "--jobs", "1", "--seed-file"])
        .arg(&seed)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let tree = documented_tree();
    for (indent, dir) in [
        ("", work.clone()),
        ("│   ", work.join("auto")),
        ("    ", work.join("results")),
    ] {
        let documented = tree_entries(&tree, indent);
        let real = listing(&dir);
        // Each entry the tree shows is there, unless it is marked `(when ...)`.
        for (name, optional) in &documented {
            assert!(
                *optional || real.contains(name),
                "auto.md lists {name} in {}, which the run did not write: {real:?}",
                dir.display()
            );
        }
        // Each entry at the top and in results/ is in the tree (auto/ holds
        // bookkeeping the tree leaves out).
        if !indent.starts_with('│') {
            let names: BTreeSet<_> = documented.iter().map(|(name, _)| name.clone()).collect();
            let missing: Vec<_> = real.difference(&names).collect();
            assert!(
                missing.is_empty(),
                "the run wrote {missing:?} in {}, which auto.md's tree leaves out",
                dir.display()
            );
        }
    }
}

/// expected-gaps.md's ranked work list sends effort only to open classes
/// (#240): it kept items its own sections marked fixed.
#[test]
fn the_ranked_work_list_names_no_fixed_class() {
    let text = std::fs::read_to_string(repo_root().join("docs/expected-gaps.md")).unwrap();
    // `### Go-2. Method needs a receiver — 24 — **[FIXED]**` -> ("Go-2", fixed).
    let classes: Vec<(String, bool)> = text
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("### ")?;
            let (id, _) = rest.split_once(". ")?;
            let fixed = line.contains("**[FIXED]");
            Some((id.to_owned(), fixed))
        })
        .collect();
    assert!(classes.iter().any(|(id, _)| id == "C-1"), "{classes:?}");
    let ranked = text
        .split("\n## Ranked work list\n")
        .nth(1)
        .and_then(|rest| rest.split("\nClosed since").next())
        .expect("the ranked work list");
    for (id, fixed) in &classes {
        let named = ranked.contains(&format!("({id};")) || ranked.contains(&format!("({id},"));
        assert!(
            !(*fixed && named),
            "the ranked work list names {id}, which expected-gaps.md marks [FIXED]"
        );
    }
    // Every ranked item names the classes it is about.
    for line in ranked.lines().filter(|line| {
        line.split_once(". ")
            .is_some_and(|(n, _)| n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty())
    }) {
        assert!(
            classes
                .iter()
                .any(|(id, _)| line.contains(&format!("({id}"))),
            "{line}"
        );
    }
}
