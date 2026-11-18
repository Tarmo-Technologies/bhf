// SPDX-License-Identifier: Apache-2.0

//! The bhf-pr action's run script with a real `bhf` (#317): a second run in
//! the work dir the first left, as the action's corpus cache restores it,
//! starts from that corpus and says so.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "#include <stddef.h>\n#include <stdint.h>\n\n\
                      int checksum(const uint8_t *data, size_t len) {\n  int sum = 0;\n  \
                      for (size_t i = 0; i < len; i++) {\n    if (data[i] == 'A') sum += 2;\n    \
                      else if (data[i] == 'B') sum += 3;\n    else sum += 1;\n  }\n  return sum;\n}\n";

fn tools() -> bool {
    ["git", "bash", "clang"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    })
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

pub(crate) fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/actions/bhf-pr/scripts/run-bhf.sh")
}

/// Run the script in `repo` against `base`, as the action's run step does.
fn run(repo: &Path, base: &str, work: &Path, temp: &Path) -> (String, String) {
    let bhf = Path::new(env!("CARGO_BIN_EXE_bhf"));
    let path = format!(
        "{}:{}",
        bhf.parent().unwrap().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    std::fs::create_dir_all(temp).unwrap();
    let output = Command::new("bash")
        .arg(script())
        .current_dir(repo)
        .env("PATH", path)
        .env("INPUT_PATH", ".")
        .env("INPUT_LANGUAGES", "c")
        .env("INPUT_CAMPAIGN_TIME", "30")
        .env("INPUT_PER_TARGET_TIME", "3")
        .env("INPUT_PR_GATE", "confirmed")
        .env("BASE_REF", base)
        .env("BHF_WORK_DIR", work)
        .env("RUNNER_TEMP", temp)
        .env("GITHUB_OUTPUT", temp.join("output"))
        .env("GITHUB_STEP_SUMMARY", temp.join("summary.md"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        std::fs::read_to_string(temp.join("output")).unwrap_or_default(),
    )
}

#[test]
fn a_second_run_starts_from_the_corpus_the_first_left() {
    if !tools() {
        eprintln!("skipping: needs git, bash and clang");
        return;
    }
    let root = TestDir::new("ci-action-cache");
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("README"), "demo\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);
    std::fs::write(repo.join("checksum.c"), TARGET).unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "change"]);
    let work = root.join("work");

    let (first, outputs) = run(&repo, &base, &work, &root.join("t1"));
    assert!(first.contains("no restored corpus"), "{first}");
    assert!(outputs.contains("exit=0"), "{outputs}\n{first}");
    let (second, outputs) = run(&repo, &base, &work, &root.join("t2"));
    assert!(outputs.contains("exit=0"), "{outputs}\n{second}");
    let restored = second
        .lines()
        .find(|line| line.starts_with("bhf: restored corpus: "))
        .unwrap_or_else(|| panic!("{second}"));
    let inputs: usize = restored
        .trim_start_matches("bhf: restored corpus: ")
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(inputs > 0, "{restored}");
    let summary = std::fs::read_to_string(root.join("t2/summary.md")).unwrap();
    assert!(summary.contains("restored corpus"), "{summary}");
}
