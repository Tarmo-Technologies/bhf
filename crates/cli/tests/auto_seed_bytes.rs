// SPDX-License-Identifier: Apache-2.0
//
// `bhf auto` seeds end to end: every seed (mined from the tree's test data,
// `--seed-file`, `--seed-dir`) must reach the engine byte for byte, including
// bytes that are not valid UTF-8, and the run must record which files seeded it
// in `auto/seeds.json`. Mining can be turned off, and build/IDE artifacts next
// to the test data are never mined. The AFL++ stage must receive the same bytes,
// uncut by a fixed 4096-byte cap. Skips cleanly without clang/make (and without
// afl-fuzz/afl-clang-fast for the AFL++ case).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn have_clang() -> bool {
    Command::new("clang").arg("--version").output().is_ok()
        && Command::new("make").arg("--version").output().is_ok()
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// A seed that is not valid UTF-8: every byte value, lone continuation bytes,
/// bytes that never occur in UTF-8, embedded NULs and a truncated lead byte.
fn binary_seed(tag: u8) -> Vec<u8> {
    let mut seed = vec![0x4d, 0x5a, 0x90, 0x00, tag];
    seed.extend((0x80..=0xffu8).rev());
    seed.extend(0x00..0x80u8);
    seed.extend_from_slice(&[0x80, 0xbf, 0xfe, 0xff, 0x00, 0xc3]);
    seed
}

/// A tiny C target whose behaviour does not depend on the input, so every
/// seed it is given lands in the coverage corpus unchanged.
fn write_tree(root: &Path) {
    std::fs::create_dir_all(root.join("tests/data")).unwrap();
    std::fs::write(
        root.join("record.c"),
        "#include <stddef.h>\n\
         int parse_record(const unsigned char *data, size_t len) {\n\
         \x20   volatile size_t seen = 0;\n\
         \x20   for (size_t i = 0; i < len; i++) seen += data[i];\n\
         \x20   return (int)seen;\n\
         }\n",
    )
    .unwrap();
    std::fs::write(root.join("tests/data/record.bin"), binary_seed(1)).unwrap();
    // Build/IDE artifacts next to the test data are not inputs.
    std::fs::write(
        root.join("tests/data/Widget.vcxproj"),
        "\u{feff}<?xml version=\"1.0\"?><Project/>",
    )
    .unwrap();
    std::fs::write(root.join("tests/data/Widget.pdb"), binary_seed(2)).unwrap();
}

fn run_auto(src: &Path, work: &Path, seconds: &str, extra: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bhf"));
    cmd.arg("auto")
        .arg(src)
        .args([
            "--per-target-time",
            seconds,
            "--max-targets",
            "1",
            "--work-dir",
        ])
        .arg(work)
        .args(extra);
    let out = cmd.output().expect("run bhf auto");
    assert!(
        out.status.success(),
        "bhf auto failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Every persisted coverage-corpus entry under `<work>/corpus/*/queue/`.
fn queue_entries(work: &Path) -> Vec<Vec<u8>> {
    let mut entries = Vec::new();
    let Ok(harnesses) = std::fs::read_dir(work.join("corpus")) else {
        return entries;
    };
    for harness in harnesses.flatten() {
        if let Ok(files) = std::fs::read_dir(harness.path().join("queue")) {
            for file in files.flatten() {
                if let Ok(bytes) = std::fs::read(file.path()) {
                    entries.push(bytes);
                }
            }
        }
    }
    entries
}

fn seed_manifest(work: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(work.join("auto/seeds.json")).expect("seeds.json"))
        .expect("seeds.json is JSON")
}

fn listed_names(manifest: &serde_json::Value) -> Vec<String> {
    manifest["seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|seed| {
            Path::new(seed["path"].as_str().unwrap())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bhf-auto-seed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn mined_seed_reaches_the_corpus_byte_exact_and_is_listed() {
    if !have_clang() {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let tmp = scratch("mined");
    let src = tmp.join("src");
    write_tree(&src);
    let work = tmp.join("work");

    let out = run_auto(&src, &work, "2", &["-v"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    let seed = binary_seed(1);
    assert!(
        queue_entries(&work).contains(&seed),
        "the mined seed must be in the corpus byte for byte:\n{stderr}"
    );
    let manifest = seed_manifest(&work);
    assert_eq!(manifest["mining"], "ran");
    assert_eq!(listed_names(&manifest), ["record.bin"], "{manifest}");
    let entry = &manifest["seeds"][0];
    assert_eq!(entry["source"], "mined");
    assert_eq!(entry["size"], seed.len());
    assert_eq!(entry["sha256"], sha256_hex(&seed));
    // `-v` names every seed file.
    assert!(
        stderr.contains("tests/data/record.bin"),
        "-v lists the mined seed:\n{stderr}"
    );
    // run.json says where the seeds came from.
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    assert_eq!(run["seeds"]["source"], "mined", "{}", run["seeds"]);
    assert_eq!(run["seeds"]["count"], 1);
    assert_eq!(run["seeds"]["manifest"], "auto/seeds.json");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn a_rerun_that_resolves_no_seeds_does_not_report_an_earlier_runs_seeds() {
    // The seed list of an earlier run in the same work dir must not be reported
    // as this run's when this run stops before resolving seeds (no targets).
    let tmp = scratch("rerun");
    let work = tmp.join("work");
    std::fs::create_dir_all(work.join("auto")).unwrap();
    let earlier = serde_json::json!({
        "schema_version": 1,
        "mining": "ran",
        "seeds": [{
            "path": "/earlier/tree/tests/data/record.bin",
            "source": "mined",
            "sha256": sha256_hex(&binary_seed(1)),
            "size": binary_seed(1).len(),
            "bytes_used": binary_seed(1).len(),
        }],
    });
    std::fs::write(
        work.join("auto/seeds.json"),
        serde_json::to_vec_pretty(&earlier).unwrap(),
    )
    .unwrap();
    let empty = tmp.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    std::fs::write(empty.join("README.txt"), "nothing to fuzz here\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&empty)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf auto");
    assert_eq!(
        out.status.code(),
        Some(2),
        "no targets: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    assert!(
        run["source_root"].as_str().unwrap().ends_with("empty"),
        "run.json is this run's: {run}"
    );
    assert!(
        run.get("seeds").is_none(),
        "a run that resolved no seeds reports none: {}",
        run["seeds"]
    );
    assert!(
        !work.join("auto/seeds.json").exists(),
        "the earlier run's seed list is not left behind as this run's"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn seed_file_and_seed_dir_reach_the_corpus_byte_exact() {
    if !have_clang() {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let tmp = scratch("user");
    let src = tmp.join("src");
    write_tree(&src);
    let seed_file = tmp.join("one.bin");
    std::fs::write(&seed_file, binary_seed(3)).unwrap();
    let seed_dir = tmp.join("seeds");
    std::fs::create_dir_all(&seed_dir).unwrap();
    std::fs::write(seed_dir.join("two.bin"), binary_seed(4)).unwrap();
    let work = tmp.join("work");

    let out = run_auto(
        &src,
        &work,
        "2",
        &[
            "--seed-file",
            seed_file.to_str().unwrap(),
            "--seed-dir",
            seed_dir.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);

    let queue = queue_entries(&work);
    assert!(queue.contains(&binary_seed(3)), "--seed-file:\n{stderr}");
    assert!(queue.contains(&binary_seed(4)), "--seed-dir:\n{stderr}");
    assert!(
        !queue.contains(&binary_seed(1)),
        "explicit seeds replace mining"
    );
    let manifest = seed_manifest(&work);
    assert_eq!(manifest["mining"], "skipped_user_seeds");
    assert_eq!(listed_names(&manifest), ["one.bin", "two.bin"]);
    assert!(manifest["seeds"]
        .as_array()
        .unwrap()
        .iter()
        .all(|seed| seed["source"] == "user"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn no_seed_mining_keeps_tree_data_out_of_the_corpus() {
    if !have_clang() {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let tmp = scratch("nomine");
    let src = tmp.join("src");
    write_tree(&src);
    let work = tmp.join("work");

    run_auto(&src, &work, "2", &["--no-seed-mining"]);

    assert!(!queue_entries(&work).contains(&binary_seed(1)));
    let manifest = seed_manifest(&work);
    assert_eq!(manifest["mining"], "disabled");
    assert!(manifest["seeds"].as_array().unwrap().is_empty());

    // The same through the tree's own config file.
    std::fs::write(src.join(".bhf.toml"), "seed-mining = false\n").unwrap();
    let work_cfg = tmp.join("work_cfg");
    run_auto(&src, &work_cfg, "2", &[]);
    assert!(!queue_entries(&work_cfg).contains(&binary_seed(1)));
    assert_eq!(seed_manifest(&work_cfg)["mining"], "disabled");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn afl_stage_receives_seed_bytes_unchanged_past_4096() {
    if !have_clang() || !on_path("afl-fuzz") || !on_path("afl-clang-fast") {
        eprintln!("skip: clang/make/afl-fuzz/afl-clang-fast unavailable");
        return;
    }
    let tmp = scratch("afl");
    let src = tmp.join("src");
    write_tree(&src);
    let mut big = Vec::new();
    while big.len() < 10 * 1024 {
        big.extend(binary_seed(5));
    }
    let seed_file = tmp.join("big.bin");
    std::fs::write(&seed_file, &big).unwrap();
    let work = tmp.join("work");

    let out = run_auto(
        &src,
        &work,
        "3",
        &[
            "--engine",
            "afl++",
            "--seed-file",
            seed_file.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);

    let mut handed_to_afl = Vec::new();
    if let Ok(harnesses) = std::fs::read_dir(work.join("afl_out")) {
        for harness in harnesses.flatten() {
            if let Ok(files) = std::fs::read_dir(harness.path().join("seeds")) {
                for file in files.flatten() {
                    handed_to_afl.push(std::fs::read(file.path()).unwrap());
                }
            }
        }
    }
    assert!(
        handed_to_afl.contains(&big),
        "afl-fuzz must get the 10 KiB seed whole and unchanged (got sizes {:?}):\n{stderr}",
        handed_to_afl.iter().map(Vec::len).collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
