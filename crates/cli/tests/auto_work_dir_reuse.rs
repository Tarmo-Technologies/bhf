// SPDX-License-Identifier: Apache-2.0

//! One work directory, two source trees: the second run reports only its own
//! tree, and the first tree's run is kept under `archived/`, not reported.

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn python3() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn auto(tree: &Path, work: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto"])
        .arg(tree)
        .arg("--work-dir")
        .arg(work)
        .args(["--per-target-time", "5", "--jobs", "1"])
        .env("RAYON_NUM_THREADS", "1")
        .output()
        .expect("run bhf auto");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.code().is_some_and(|code| code <= 1),
        "bhf auto failed: {text}"
    );
    text
}

fn finding_count(work: &Path) -> usize {
    std::fs::read_dir(work.join("results/findings"))
        .map(|entries| entries.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0)
}

#[test]
fn a_second_tree_in_the_same_work_dir_reports_only_itself() {
    if !python3() {
        eprintln!("skipping: python3 not installed");
        return;
    }
    let dir = TestDir::new("work-dir-reuse");
    let tree_a = dir.join("a");
    let tree_b = dir.join("b");
    std::fs::create_dir_all(&tree_a).unwrap();
    std::fs::create_dir_all(&tree_b).unwrap();
    std::fs::write(
        tree_a.join("alpha.py"),
        "def pick(data: bytes) -> int:\n    return data[len(data) + 1]\n",
    )
    .unwrap();
    std::fs::write(
        tree_b.join("beta.py"),
        "def total(data: bytes) -> int:\n    return sum(data) & 0xFF\n",
    )
    .unwrap();
    let work = dir.join("work");

    auto(&tree_a, &work);
    assert!(finding_count(&work) >= 1, "tree a's planted bug is found");
    // A rerun over the same tree keeps its findings.
    let rerun = auto(&tree_a, &work);
    assert!(!rerun.contains("moved it to"), "{rerun}");
    assert!(finding_count(&work) >= 1, "{rerun}");

    let second = auto(&tree_b, &work);
    assert!(second.contains("moved it to"), "{second}");
    assert_eq!(finding_count(&work), 0, "{second}");
    assert!(!second.contains("alpha.py") && !second.contains("IndexError"), "{second}");
    let index = std::fs::read_to_string(work.join("results/INDEX.md")).unwrap_or_default();
    assert!(!index.contains("alpha.py"), "{index}");
    let canonical_a = tree_a.canonicalize().unwrap();
    assert!(
        !index.contains(&*canonical_a.to_string_lossy()),
        "INDEX names tree a: {index}"
    );
    // Tree a's run is kept, not deleted.
    let archived: Vec<_> = std::fs::read_dir(work.join("archived"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(archived.len(), 1);
    assert!(archived[0].path().join("results/findings").is_dir());
}
