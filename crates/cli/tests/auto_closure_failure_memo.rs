// SPDX-License-Identifier: Apache-2.0

//! When several targets share a build closure that cannot be built, the repair
//! cascade must run once — not once per target reaching the same verdict.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("bhf-closure-memo-{prefix}-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// A source whose closure cannot be satisfied offline, carrying several entry
/// points so the sweep attempts more than one.
///
/// The blocker is an object of an INCOMPLETE class type. A missing header or an
/// undefined function is not enough — the repair loop synthesizes a placeholder
/// header and blind-stubs the symbols, and the target builds and fuzzes. A type
/// that is declared but never defined is the documented unsynthesizable case:
/// nothing bhf can write completes it, so the cascade genuinely exhausts.
const UNBUILDABLE_WITH_SIBLINGS: &str = "\
class MissingExternalType;

int parse_alpha(const unsigned char *d, unsigned long n) {
    MissingExternalType m;
    return (int)(n + (d ? 0 : 0));
}
int parse_beta(const unsigned char *d, unsigned long n) {
    MissingExternalType m;
    return (int)(n + (d ? 1 : 0));
}
int parse_gamma(const unsigned char *d, unsigned long n) {
    MissingExternalType m;
    return (int)(n + (d ? 2 : 0));
}
";

#[test]
fn a_sibling_target_inherits_the_closure_verdict_instead_of_repeating_the_cascade() {
    if !support::libfuzzer_toolchain_available("closure-memo") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("broken.cpp"), UNBUILDABLE_WITH_SIBLINGS).unwrap();
    let work = root.join("work");

    let output = support::bhf_cargo_command()
        .current_dir(&root)
        .args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "1",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    let memo_path = work.join("closure_failures.json");
    assert!(
        memo_path.is_file(),
        "an exhausted cascade must leave a verdict for its siblings; stderr=\n{stderr}"
    );
    let memo: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&memo_path).unwrap()).expect("memo is JSON");
    let entries = memo["entries"].as_object().expect("memo has entries");
    assert_eq!(
        entries.len(),
        1,
        "one closure, one verdict — not one per target: {entries:?}"
    );

    let run_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let targets = run_json["targets"].as_array().expect("targets array");
    assert!(
        targets.len() >= 2,
        "the fixture must produce siblings for the memo to matter: {} target(s)",
        targets.len()
    );
    // Every sibling still reports the same honest outcome it would have reached
    // the slow way. The memo changes what work is done, never what is reported.
    for target in targets {
        let outcome = target["outcome"]["outcome"].as_str().unwrap_or("<none>");
        assert_eq!(
            outcome, "report_only",
            "a memo hit must report exactly what the sibling that ran the full \
             cascade reported — it substitutes for the work, not the verdict"
        );
    }
}

#[test]
fn a_verdict_does_not_survive_a_change_in_project_repair_state() {
    if !support::libfuzzer_toolchain_available("closure-memo-invalidate") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("invalidate");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("broken.cpp"), UNBUILDABLE_WITH_SIBLINGS).unwrap();
    let work = root.join("work");

    let run = || {
        support::bhf_cargo_command()
            .current_dir(&root)
            .args([
                "auto",
                "--work-dir",
                work.to_str().unwrap(),
                "--per-target-time",
                "1",
                src.to_str().unwrap(),
            ])
            .output()
            .expect("run bhf auto")
    };
    run();
    assert!(work.join("closure_failures.json").is_file());

    // A fresh run refreshes regenerable state, so a verdict reached by an older
    // binary — or under a poorer repair model — can never cap a later sweep.
    let stderr = String::from_utf8_lossy(&run().stderr).into_owned();
    let memo: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("closure_failures.json")).expect("memo exists"),
    )
    .expect("memo is JSON");
    assert!(
        memo["entries"].as_object().is_some_and(|e| !e.is_empty()),
        "the second run must re-derive the verdict rather than inherit a stale \
         one silently; stderr=\n{stderr}"
    );
}

/// Build lanes belong to the attempt that built the harness. A target that
/// `--resume` re-runs and that inherits a sibling's verdict builds nothing, so
/// a lane record an interrupted attempt left in its dir is not reported. A
/// target `--resume` reloads keeps its lanes, reported as the earlier run's.
#[test]
fn a_resumed_run_reports_only_lanes_of_the_attempt_behind_each_result() {
    if !support::libfuzzer_toolchain_available("closure-memo-lanes") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("lanes");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("broken.cpp"), UNBUILDABLE_WITH_SIBLINGS).unwrap();
    let work = root.join("work");

    // The bhf this test binary was built with.
    let mut bhf = std::env::current_exe().unwrap();
    bhf.pop();
    if bhf.ends_with("deps") {
        bhf.pop();
    }
    let bhf = bhf.join(format!("bhf{}", std::env::consts::EXE_SUFFIX));
    let run = |resume: bool| {
        let mut command = std::process::Command::new(&bhf);
        command.current_dir(&root).args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "1",
            "--jobs",
            "1",
        ]);
        if resume {
            command.arg("--resume");
        }
        command.arg(&src).output().expect("run bhf auto")
    };
    run(false);
    assert!(work.join("closure_failures.json").is_file());
    // The target that ran the cascade holds its harness; its siblings
    // inherited the verdict and hold only their result.
    let mut dirs: Vec<PathBuf> = fs::read_dir(work.join("harnesses"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join("result.json").is_file())
        .collect();
    dirs.sort();
    let built = dirs
        .iter()
        .find(|dir| dir.join("Makefile").is_file())
        .expect("the target that ran the cascade")
        .clone();
    let sibling = dirs
        .iter()
        .find(|dir| !dir.join("Makefile").is_file())
        .expect("a target that inherited the verdict")
        .clone();
    // The reloaded target's lane, recorded by the first run.
    fs::write(
        built.join("lanes.json"),
        r#"{"cov":{"built":false,"reason":"make main_cov failed: reloaded","recorded_at":"2001-01-01T00:00:00+00:00"}}"#,
    )
    .unwrap();
    // An attempt interrupted before it saved its result, after a lane.
    fs::remove_file(sibling.join("result.json")).unwrap();
    fs::write(
        sibling.join("lanes.json"),
        r#"{"cov":{"built":false,"reason":"make main_cov failed: interrupted"}}"#,
    )
    .unwrap();

    let output = run(true);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("--resume: reloaded"), "{stderr}");
    let run_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let targets = run_json["targets"].as_array().expect("targets array");
    let lanes_of = |dir: &PathBuf| {
        let id = dir.file_name().unwrap().to_str().unwrap();
        targets
            .iter()
            .find(|target| target["harness_id"] == id)
            .unwrap_or_else(|| panic!("{id} in {targets:?}"))["lanes"]
            .clone()
    };
    assert!(
        !lanes_of(&sibling).to_string().contains("interrupted"),
        "a lane of an interrupted attempt is reported: {}\nstderr=\n{stderr}",
        lanes_of(&sibling)
    );
    assert_eq!(
        lanes_of(&built)["cov"]["recorded_at"],
        "2001-01-01T00:00:00+00:00"
    );
    let run_md = fs::read_to_string(work.join("auto").join("run.md")).unwrap();
    assert!(!run_md.contains("interrupted"), "{run_md}");
    assert!(
        run_md.contains(
            "line coverage unavailable: make main_cov failed: reloaded (recorded by an \
             earlier run at 2001-01-01T00:00:00+00:00)"
        ),
        "{run_md}"
    );
}
