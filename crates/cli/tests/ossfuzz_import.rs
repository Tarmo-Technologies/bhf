// SPDX-License-Identifier: Apache-2.0

//! `bhf project import-ossfuzz`: an OSS-Fuzz `build.sh` runs in a sandbox
//! with the OSS-Fuzz build variables, and the fuzzers it leaves in `$OUT`
//! are collected.
//!
//! The fixture (`tests/fixtures/ossfuzz_project`) is a small record parser
//! with an OSS-Fuzz build script, staged into a temporary directory so the
//! test can check the build never wrote into it. The tests that check what
//! the sandbox refuses (network, writes outside `$SRC`, `$WORK` and `$OUT`)
//! need a working bubblewrap or firejail, and skip without one;
//! `BHF_OSSFUZZ_SANDBOX=1`, which the nightly job that gives bubblewrap its
//! namespaces sets, makes that a failure. (A hosted Ubuntu 24.04 runner, as
//! the nightly's other shards are, denies an unprivileged bubblewrap its
//! user namespace.) The others build with `--sandbox none` where no sandbox
//! works.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ossfuzz_project")
}

fn runs(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn have_clang() -> bool {
    support::require_tool(
        runs("clang", &["--version"]) && runs("clang++", &["--version"]),
        "clang",
    )
}

/// What an import of the fixture needs: clang, the `zip` its build.sh
/// packs the seed corpus with, and the `unzip` bhf unpacks it with.
fn have_fixture_tools() -> bool {
    have_clang()
        && support::require_tool(runs("zip", &["-v"]), "zip")
        && support::require_tool(runs("unzip", &["-v"]), "unzip")
}

/// Whether a sandbox bhf can build in works here: bubblewrap with every
/// namespace (the network one included), or firejail without network.
fn working_sandbox() -> bool {
    runs(
        "bwrap",
        &[
            "--die-with-parent",
            "--unshare-all",
            "--ro-bind",
            "/",
            "/",
            "--",
            "true",
        ],
    ) || runs(
        "firejail",
        &["--quiet", "--noprofile", "--net=none", "--", "true"],
    )
}

/// Set to `1` where a working sandbox is required, so the sandbox tests fail
/// instead of skipping without one.
const SANDBOX_REQUIRED: &str = "BHF_OSSFUZZ_SANDBOX";

/// For a test of what the sandbox refuses: whether one works here, or the
/// skip line saying why not.
fn sandbox_available(test: &str) -> bool {
    let required = std::env::var_os(SANDBOX_REQUIRED).is_some_and(|value| value == "1");
    if support::require_tool_with(
        working_sandbox(),
        "a working bubblewrap or firejail",
        required,
    ) {
        return true;
    }
    eprintln!(
        "skip {test}: no working bubblewrap or firejail here (set {SANDBOX_REQUIRED}=1 to \
         require one)"
    );
    false
}

/// The flags a test that needs a build, but not the sandbox itself, passes:
/// none where a sandbox works, `--sandbox none` elsewhere.
fn sandbox_flags() -> Vec<&'static str> {
    if working_sandbox() {
        Vec::new()
    } else {
        eprintln!("note: no working bubblewrap or firejail here; building with --sandbox none");
        vec!["--sandbox", "none"]
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// Every path under `dir`, relative, sorted.
fn listing(dir: &Path) -> Vec<PathBuf> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(path.strip_prefix(base).unwrap().to_path_buf());
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// A project directory `root/<name>` holding `build_sh`.
fn write_project(root: &Path, name: &str, build_sh: &str) -> PathBuf {
    let project = root.join(name);
    fs::create_dir_all(&project).unwrap();
    let script = project.join("build.sh");
    fs::write(&script, build_sh).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    project
}

/// The end of a test build script: the import needs a fuzzer in `$OUT`.
const STUB_FUZZER: &str =
    "printf '#!/bin/sh\\n' > \"$OUT/stub_fuzzer\"\nchmod +x \"$OUT/stub_fuzzer\"\n";

fn import(project: &Path, work: &Path, extra: &[&str]) -> Output {
    bhf()
        .args(["project", "import-ossfuzz"])
        .arg(project)
        .arg("--work-dir")
        .arg(work)
        .args(extra)
        .output()
        .expect("run bhf project import-ossfuzz")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_ok(out: &Output) {
    assert!(
        out.status.success(),
        "import failed ({}):\n{}\n{}",
        out.status,
        text(&out.stdout),
        text(&out.stderr)
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The fixture's build.sh, run as OSS-Fuzz runs it, leaves its two fuzz
/// targets in `$OUT`, each linked with bhf's driver through
/// `$LIB_FUZZING_ENGINE`; the tool it also leaves there is not taken for a
/// fuzzer, the objects are in `$WORK`, and the operator's tree is untouched.
#[test]
fn the_fixture_build_sh_leaves_its_fuzzers_in_out() {
    if !have_fixture_tools() {
        eprintln!("skipping: clang, zip or unzip not available");
        return;
    }
    let root = TestDir::new("ossfuzz-fixture");
    let project = root.join("ossfuzz_project");
    copy_tree(&fixture(), &project);
    let before = listing(&project);
    let work = root.join("work");

    let out = import(
        &project,
        &work,
        &[&sandbox_flags()[..], &["--json"]].concat(),
    );
    assert_ok(&out);
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON record");
    let work = work.canonicalize().unwrap();
    let out_dir = work.join("ossfuzz/out");
    assert_eq!(record["out"], out_dir.to_str().unwrap());
    let fuzzers = record["fuzzers"].as_array().unwrap();
    let names: Vec<&str> = fuzzers
        .iter()
        .map(|fuzzer| fuzzer["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["checksum_fuzzer", "parse_record_fuzzer"]);
    for fuzzer in fuzzers {
        let binary = PathBuf::from(fuzzer["binary"].as_str().unwrap());
        assert_eq!(binary.parent().unwrap(), out_dir);
        let bytes = fs::read(&binary).unwrap();
        assert!(
            contains(&bytes, b"BHF_FRAMED"),
            "{}: no bhf driver",
            binary.display()
        );
        assert!(
            contains(&bytes, b"__asan_init"),
            "{}: no ASan",
            binary.display()
        );
        assert_eq!(fuzzer["protocol"], "bhf framed");
    }
    assert!(out_dir.join("record_tool").is_file());
    assert!(work.join("ossfuzz/work/record.o").is_file());
    assert!(work.join("ossfuzz/src/build.sh").is_file());
    assert!(work
        .join("ossfuzz/src/ossfuzz_project/src/record.c")
        .is_file());
    assert_eq!(
        listing(&project),
        before,
        "build.sh wrote into the source tree"
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("ossfuzz/import.json")).unwrap()).unwrap();
    assert_eq!(saved, record);
}

/// Each fuzzer the fixture builds is registered as a harness of the work
/// dir, and listed; `bhf fuzz --harness <name>` runs the registered
/// `parse_record_fuzzer` with coverage and finds its planted heap overflow;
/// and the import's manifest names both for `bhf project run`.
#[test]
fn the_imported_fuzzers_are_registered_and_bhf_fuzz_finds_the_planted_bug() {
    if !have_fixture_tools() {
        eprintln!("skipping: clang, zip or unzip not available");
        return;
    }
    let root = TestDir::new("ossfuzz-register");
    let project = root.join("ossfuzz_project");
    copy_tree(&fixture(), &project);
    let work = root.join("work");
    let out = import(&project, &work, &sandbox_flags());
    assert_ok(&out);
    let work = work.canonicalize().unwrap();
    let listing = text(&out.stdout);
    assert!(
        listing.contains("build.sh produced 2 fuzzer(s), registered as harnesses of"),
        "{listing}"
    );
    for name in ["checksum_fuzzer", "parse_record_fuzzer"] {
        let harness = work.join("build").join(name).join("main");
        assert!(
            listing.contains(&format!("{}  [bhf driver]", harness.display())),
            "{name} not listed:\n{listing}"
        );
        let declared: serde_json::Value = serde_json::from_slice(
            &fs::read(work.join("build").join(name).join("harness-protocol.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(declared["input_mode"], "framed");
    }
    assert!(!work.join("build/record_tool").exists());
    // The commands that fuzz one, the one that came with options included.
    for command in [
        format!(
            "bhf project run --manifest {} --target parse_record_fuzzer --work-dir {}",
            work.join("ossfuzz/bhf.project.toml").display(),
            work.display()
        ),
        format!(
            "bhf fuzz {} --harness parse_record_fuzzer --time 60s --max-len 64 --timeout 5s \
             --rss-limit-mb 1024",
            work.display()
        ),
        format!(
            "bhf auto {} --work-dir {}",
            project.canonicalize().unwrap().display(),
            work.display()
        ),
    ] {
        assert!(listing.contains(&command), "{command} in {listing}");
    }

    // The manifest bhf project run takes, checked by bhf itself.
    let manifest = work.join("ossfuzz/bhf.project.toml");
    let list = bhf()
        .args(["project", "list", "--json", "--manifest"])
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(list.status.success(), "{}", text(&list.stderr));
    let listed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let targets: Vec<(&str, &str)> = listed["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["id"].as_str().unwrap(), t["engine"].as_str().unwrap()))
        .collect();
    assert_eq!(
        targets,
        [
            ("checksum_fuzzer", "builtin"),
            ("parse_record_fuzzer", "builtin")
        ]
    );
    let validate = bhf()
        .args(["project", "validate", "--manifest"])
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(validate.status.success(), "{}", text(&validate.stderr));

    // A well-formed record, one length-byte change from the overflow.
    let seed = root.join("record.bin");
    let mut record = b"REC1\x10".to_vec();
    record.extend_from_slice(&[b'A'; 20]);
    fs::write(&seed, &record).unwrap();
    let _serial = support::fuzz_serial_guard();
    let fuzz = bhf()
        .arg("fuzz")
        .arg(&work)
        .args([
            "--harness",
            "parse_record_fuzzer",
            "--time",
            "15s",
            "--seed-file",
        ])
        .arg(&seed)
        .output()
        .unwrap();
    assert!(fuzz.status.success(), "{}", text(&fuzz.stderr));
    let summary: serde_json::Value = serde_json::from_slice(
        &fs::read(work.join("fuzz_runs/parse_record_fuzzer-latest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(summary["execution"]["harness_protocol"], "bhf_framed");
    assert_eq!(summary["coverage"]["source"], "sancov-trace-pc-guard");
    assert!(
        summary["coverage"]["edges"].as_u64().unwrap() > 0,
        "{summary}"
    );
    let findings: Vec<PathBuf> = fs::read_dir(work.join("results/findings"))
        .expect("a finding")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert!(!findings.is_empty(), "no finding: {}", text(&fuzz.stderr));
    let found = findings.iter().any(|dir| {
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        let log = fs::read_to_string(dir.join("sanitizer.log")).unwrap_or_default();
        finding["harness_id"] == "parse_record_fuzzer"
            && log.contains("heap-buffer-overflow")
            && log.contains("record_parse")
    });
    assert!(found, "the planted overflow was not found: {findings:?}");
}

/// The fixture's seed corpus is unpacked with the system `unzip`, its
/// `.dict` and the dictionary its `.options` names are merged into the
/// harness's dictionary, and its `[libfuzzer]` options set the manifest
/// target's; the options bhf has no equivalent for are reported. `bhf
/// project run` on the import's manifest then runs the unpacked seeds
/// (finding the overflow the corpus's regression input triggers, with that
/// seed as its lineage root) and loads the merged dictionary.
#[test]
fn the_seed_corpus_dictionaries_and_options_are_imported_and_applied() {
    if !have_fixture_tools() {
        eprintln!("skipping: clang, zip or unzip not available");
        return;
    }
    let root = TestDir::new("ossfuzz-extras");
    let project = root.join("ossfuzz_project");
    copy_tree(&fixture(), &project);
    let work = root.join("work");
    let out = import(
        &project,
        &work,
        &[&sandbox_flags()[..], &["--json"]].concat(),
    );
    assert_ok(&out);
    let work = work.canonicalize().unwrap();
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let fuzzer = |name: &str| {
        record["fuzzers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|fuzzer| fuzzer["name"] == name)
            .cloned()
            .unwrap()
    };

    // Seeds: exactly the corpus build.sh zipped, byte for byte.
    let parse = fuzzer("parse_record_fuzzer");
    let seeds = work.join("ossfuzz/seeds/parse_record_fuzzer");
    assert_eq!(parse["seeds"]["dir"], seeds.to_str().unwrap());
    let corpus = fixture().join("fuzz/corpus/parse_record");
    assert_eq!(listing(&seeds), listing(&corpus));
    assert_eq!(parse["seeds"]["files"], listing(&corpus).len());
    for seed in listing(&corpus) {
        assert_eq!(
            fs::read(seeds.join(&seed)).unwrap(),
            fs::read(corpus.join(&seed)).unwrap()
        );
    }

    // Dictionaries: <name>.dict, then the options' record.dict, merged.
    let out_dir = work.join("ossfuzz/out");
    assert_eq!(
        parse["dictionaries"],
        serde_json::json!([
            out_dir.join("parse_record_fuzzer.dict"),
            out_dir.join("record.dict")
        ])
    );
    let merged = "\"REC1\"\n\"\\x10\"\n\"\\xc5\\x9d\\x1c\\x81\"\n";
    assert_eq!(
        fs::read_to_string(work.join("build/parse_record_fuzzer/dictionary.txt")).unwrap(),
        merged
    );

    // Options: the ones bhf applies, and a note for each of the others.
    assert_eq!(
        parse["options"],
        serde_json::json!({ "max_len": 64, "timeout_secs": 5, "rss_limit_mb": 1024 })
    );
    let notes = parse["notes"].to_string();
    for note in [
        "[libfuzzer] close_fd_mask = 3 is not applied",
        "[asan] detect_leaks = 0 is not applied",
    ] {
        assert!(notes.contains(note), "{note} in {notes}");
        assert!(text(&out.stderr).contains(note), "{note} not reported");
    }

    // The fuzzer that came with nothing gets nothing.
    let checksum = fuzzer("checksum_fuzzer");
    assert!(checksum["seeds"].is_null());
    assert_eq!(checksum["dictionary_tokens"], 0);
    assert!(!work.join("build/checksum_fuzzer/dictionary.txt").exists());

    // The manifest target carries them for `bhf project run`.
    let manifest_path = work.join("ossfuzz/bhf.project.toml");
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let targets = manifest["target"].as_array().unwrap();
    let target = |id: &str| {
        targets
            .iter()
            .find(|target| target["id"].as_str() == Some(id))
            .unwrap()
            .as_table()
            .unwrap()
            .clone()
    };
    let parse_target = target("parse_record_fuzzer");
    assert_eq!(
        parse_target["seeds"].as_array().unwrap(),
        &[toml::Value::from("seeds/parse_record_fuzzer")]
    );
    assert_eq!(
        parse_target["dictionaries"].as_array().unwrap(),
        &[
            toml::Value::from("out/parse_record_fuzzer.dict"),
            toml::Value::from("out/record.dict")
        ]
    );
    assert_eq!(parse_target["max-len"].as_str(), Some("64"));
    assert_eq!(parse_target["timeout"].as_str(), Some("5s"));
    assert_eq!(parse_target["rss-limit-mb"].as_integer(), Some(1024));
    let checksum_target = target("checksum_fuzzer");
    for key in [
        "seeds",
        "dictionaries",
        "max-len",
        "timeout",
        "rss-limit-mb",
    ] {
        assert!(!checksum_target.contains_key(key), "{key}");
    }

    // `bhf project run` runs the unpacked seeds and loads the dictionaries.
    let run_dir = root.join("run");
    let _serial = support::fuzz_serial_guard();
    let run = bhf()
        .args([
            "project",
            "run",
            "--target",
            "parse_record_fuzzer",
            "--manifest",
        ])
        .arg(&manifest_path)
        .arg("--work-dir")
        .arg(&run_dir)
        .output()
        .unwrap();
    assert!(run.status.success(), "{}", text(&run.stderr));
    assert_eq!(
        fs::read_to_string(run_dir.join("build/parse_record_fuzzer/dictionary.txt")).unwrap(),
        merged
    );
    let regression = seeds.join("regression_long_record");
    let found = fs::read_dir(run_dir.join("results/findings"))
        .expect("a finding")
        .map(|entry| entry.unwrap().path())
        .any(|dir| {
            let finding: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
            finding["lineage"]["origin"] == "user_seed"
                && finding["lineage"]["root_path"] == regression.to_str().unwrap()
                && fs::read(dir.join("testcase.bin")).unwrap() == fs::read(&regression).unwrap()
        });
    assert!(found, "no finding from the unpacked regression seed");
}

/// After the import, `bhf auto --work-dir <the same>` fuzzes the fuzzers it
/// registered as provided harnesses, ahead of the targets it generates: each
/// is a target at the source that defines it, staged from the import with
/// its seeds, dictionaries and options, and `parse_record_fuzzer` finds the
/// planted overflow. `run.json` marks both with their origin, and the run
/// leaves the import's registrations for `bhf fuzz --harness`.
#[test]
fn bhf_auto_fuzzes_the_imported_fuzzers_with_their_seeds_and_dictionaries() {
    if !have_fixture_tools() {
        eprintln!("skipping: clang, zip or unzip not available");
        return;
    }
    let root = TestDir::new("ossfuzz-auto");
    let project = root.join("ossfuzz_project");
    copy_tree(&fixture(), &project);
    let project = project.canonicalize().unwrap();
    let work = root.join("work");
    assert_ok(&import(&project, &work, &sandbox_flags()));
    let work = work.canonicalize().unwrap();
    let _serial = support::fuzz_serial_guard();
    // The two imported fuzzers rank first, so `--max-targets 2` is them.
    let auto = bhf()
        .args([
            "auto",
            "--per-target-time",
            "15",
            "--single-pass",
            "--jobs",
            "1",
            "--max-targets",
            "2",
            "--work-dir",
        ])
        .arg(&work)
        .arg(&project)
        .output()
        .unwrap();
    let stderr = text(&auto.stderr);
    assert!(auto.status.success(), "bhf auto failed: {stderr}");
    assert!(
        stderr.contains("provided harnesses: 2 the project ships (2 imported OSS-Fuzz fuzzer(s))"),
        "{stderr}"
    );
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    assert_eq!(run["summary"]["provided_harnesses"], 2, "{run:#}");
    let targets = run["targets"].as_array().unwrap();
    let target = |name: &str| {
        targets
            .iter()
            .find(|target| target["name"] == name)
            .unwrap_or_else(|| panic!("no target {name} in run.json: {run:#}"))
    };
    assert!(
        targets
            .iter()
            .all(|target| target["name"] != "LLVMFuzzerTestOneInput"),
        "an imported fuzzer is not fuzzed again as a generated driver target"
    );
    let out_dir = work.join("ossfuzz/out");
    for (name, source) in [
        ("parse_record_fuzzer", "fuzz/parse_record_fuzzer.cc"),
        ("checksum_fuzzer", "fuzz/checksum_fuzzer.c"),
    ] {
        let target = target(name);
        assert_eq!(
            target["outcome"]["outcome"], "built_and_fuzzed",
            "{target:#}"
        );
        let provided = &target["provided_harness"];
        assert_eq!(provided["origin"], "ossfuzz-import", "{target:#}");
        assert_eq!(provided["entry"], name);
        assert_eq!(provided["source"], project.join(source).to_str().unwrap());
    }

    // parse_record_fuzzer: its unpacked corpus, its two dictionaries and its
    // options, staged in its harness dir.
    let parse = target("parse_record_fuzzer");
    let provided = &parse["provided_harness"];
    let seeds = work.join("ossfuzz/seeds/parse_record_fuzzer");
    assert_eq!(provided["seeds"], 3, "{provided:#}");
    assert_eq!(
        provided["seed_sources"],
        serde_json::json!([seeds.to_str().unwrap()])
    );
    assert_eq!(
        provided["dictionaries"],
        serde_json::json!([
            out_dir.join("parse_record_fuzzer.dict"),
            out_dir.join("record.dict")
        ])
    );
    assert_eq!(provided["dictionary_tokens"], 3);
    assert_eq!(
        provided["options"],
        serde_json::json!({ "max_len": 64, "timeout_secs": 5, "rss_limit_mb": 1024 })
    );
    let id = parse["harness_id"].as_str().unwrap();
    let harness = work.join("harnesses").join(id);
    assert_eq!(
        fs::read(harness.join("main")).unwrap(),
        fs::read(out_dir.join("parse_record_fuzzer")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(harness.join("dictionary.txt")).unwrap(),
        "\"REC1\"\n\"\\x10\"\n\"\\xc5\\x9d\\x1c\\x81\"\n"
    );
    let mut staged: Vec<Vec<u8>> = fs::read_dir(harness.join("provided-seeds"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect();
    staged.sort();
    let mut corpus: Vec<Vec<u8>> = listing(&seeds)
        .iter()
        .map(|seed| fs::read(seeds.join(seed)).unwrap())
        .collect();
    corpus.sort();
    assert_eq!(staged, corpus);
    let checksum = target("checksum_fuzzer");
    assert_eq!(checksum["provided_harness"]["seeds"], 0);
    assert!(checksum["provided_harness"].get("options").is_none());

    // The planted overflow, found through the imported fuzzer.
    let findings: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    let found = findings["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|finding| {
            finding["fuzz"]["harness_id"] == id
                && finding["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("heap-buffer-overflow"))
                && finding["location"]["function"] == "record_parse"
        });
    assert!(found, "the planted overflow was not found: {findings:#}");
    // Located in the project's own file, not in the copy the import built.
    let overflow = findings["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|finding| {
            finding["fuzz"]["harness_id"] == id && finding["location"]["function"] == "record_parse"
        })
        .unwrap();
    assert_eq!(overflow["location"]["file"], "src/record.c", "{overflow:#}");
    assert!(
        !overflow.to_string().contains("ossfuzz/src"),
        "the finding names the import's $SRC copy: {overflow:#}"
    );
    // The fuzzer sources are fuzzed, so the note on what discovery skipped
    // by default does not count them.
    assert!(
        !stderr.contains("fuzz/ ("),
        "the fuzzers' dir is named as skipped: {stderr}"
    );
    let summary = fs::read_to_string(work.join("auto/summary.txt")).unwrap();
    assert!(
        summary.contains(&format!(
            "{id} parse_record_fuzzer [ossfuzz-import]: built+fuzzed, 3 seed(s)"
        )),
        "{summary}"
    );
    // The import's registrations are still there for `bhf fuzz --harness`.
    for name in ["checksum_fuzzer", "parse_record_fuzzer"] {
        assert!(
            work.join("build").join(name).join("main").is_file(),
            "{name}"
        );
    }
}

/// A seed corpus is unpacked with the system `unzip`; without it the import
/// stops with what is missing and how to get it, naming the corpus.
#[test]
fn a_missing_unzip_is_refused_with_a_clear_message() {
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let root = TestDir::new("ossfuzz-nounzip");
    // What bhf and this build.sh run, and no unzip.
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    for tool in ["bash", "clang", "clang++", "ar", "cp", "chmod"] {
        let path = which::which(tool).unwrap_or_else(|_| panic!("{tool} on PATH"));
        std::os::unix::fs::symlink(path, bin.join(tool)).unwrap();
    }
    // An empty zip archive: its end-of-central-directory record alone.
    let mut empty_zip = b"PK\x05\x06".to_vec();
    empty_zip.resize(22, 0);
    let project = write_project(
        &root,
        "zipproj",
        &format!(
            "#!/bin/bash -eu\ncp seeds.zip \"$OUT/stub_fuzzer_seed_corpus.zip\"\n{STUB_FUZZER}"
        ),
    );
    fs::write(project.join("seeds.zip"), &empty_zip).unwrap();
    let out = bhf()
        .args(["project", "import-ossfuzz"])
        .arg(&project)
        .arg("--work-dir")
        .arg(root.join("work"))
        .args(["--sandbox", "none"])
        .env("PATH", &bin)
        .output()
        .unwrap();
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    for needle in [
        "`unzip` is not on PATH",
        "stub_fuzzer_seed_corpus.zip",
        "apt-get install unzip",
    ] {
        assert!(stderr.contains(needle), "{needle:?} in {stderr}");
    }
}

/// A symlink in a seed corpus, which could name a host file, is not a seed.
#[test]
fn a_symlink_in_a_seed_corpus_is_not_a_seed() {
    if !have_fixture_tools() {
        eprintln!("skipping: clang, zip or unzip not available");
        return;
    }
    let root = TestDir::new("ossfuzz-zipsymlink");
    let project = write_project(
        &root,
        "linkproj",
        &format!(
            "#!/bin/bash -eu\n\
             mkdir -p \"$WORK/corpus\"\n\
             printf 'seed' > \"$WORK/corpus/plain\"\n\
             ln -s /etc/hostname \"$WORK/corpus/host\"\n\
             (cd \"$WORK/corpus\" && zip -q --symlinks \"$OUT/stub_fuzzer_seed_corpus.zip\" plain host)\n\
             {STUB_FUZZER}"
        ),
    );
    let work = root.join("work");
    let out = import(
        &project,
        &work,
        &[&sandbox_flags()[..], &["--json"]].concat(),
    );
    assert_ok(&out);
    let seeds = work.join("ossfuzz/seeds/stub_fuzzer");
    assert_eq!(listing(&seeds), [PathBuf::from("plain")]);
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(record["fuzzers"][0]["seeds"]["files"], 1);
}

/// build.sh runs from `$SRC/<name>` with the OSS-Fuzz variables, `$CC`/
/// `$CXX` being clang and `$LIB_FUZZING_ENGINE` bhf's driver archive, and
/// with nothing else of bhf's environment.
#[test]
fn build_sh_runs_with_the_oss_fuzz_build_variables() {
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let root = TestDir::new("ossfuzz-env");
    let script = format!(
        "#!/bin/bash -eu\n{{\n{}}} > \"$OUT/env.txt\"\n{STUB_FUZZER}",
        [
            "SRC",
            "WORK",
            "OUT",
            "CC",
            "CXX",
            "CFLAGS",
            "CXXFLAGS",
            "LIB_FUZZING_ENGINE",
            "SANITIZER",
            "FUZZING_ENGINE",
            "PWD",
        ]
        .iter()
        .map(|var| format!("echo \"{var}=${var}\"\n"))
        .chain(["echo \"SECRET=${BHF_TEST_SECRET:-unset}\"\n".to_owned()])
        .collect::<String>()
    );
    let project = write_project(&root, "envproj", &script);
    let work = root.join("work");
    let out = bhf()
        .args(["project", "import-ossfuzz"])
        .arg(&project)
        .arg("--work-dir")
        .arg(&work)
        .args(sandbox_flags())
        .env("BHF_TEST_SECRET", "hunter2")
        .output()
        .unwrap();
    assert_ok(&out);
    let work = work.canonicalize().unwrap();
    let env: std::collections::BTreeMap<String, String> =
        fs::read_to_string(work.join("ossfuzz/out/env.txt"))
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
    let dir = |sub: &str| work.join("ossfuzz").join(sub).display().to_string();
    assert_eq!(env["SRC"], dir("src"));
    assert_eq!(env["WORK"], dir("work"));
    assert_eq!(env["OUT"], dir("out"));
    assert_eq!(env["PWD"], dir("src/envproj"));
    assert!(env["CC"].ends_with("/clang"), "{}", env["CC"]);
    assert!(env["CXX"].ends_with("/clang++"), "{}", env["CXX"]);
    for flags in [&env["CFLAGS"], &env["CXXFLAGS"]] {
        assert!(flags.contains("-fsanitize=address"), "{flags}");
        assert!(flags.contains("-fsanitize-coverage=trace-pc-guard,trace-cmp"));
    }
    assert_eq!(env["SANITIZER"], "address");
    assert_eq!(env["FUZZING_ENGINE"], "libfuzzer");
    let engine = fs::read(&env["LIB_FUZZING_ENGINE"]).unwrap();
    assert!(engine.starts_with(b"!<arch>\n"), "not an archive");
    assert!(contains(&engine, b"BHF_FRAMED"), "not bhf's driver");
    assert!(contains(&engine, b"LLVMFuzzerTestOneInput"));
    assert_eq!(env["SECRET"], "unset", "bhf's environment reached build.sh");
}

/// In the sandbox build.sh has no network: a listener on this host's
/// loopback, which the test itself reaches, is not reached from build.sh.
#[test]
fn build_sh_has_no_network() {
    if !sandbox_available("build_sh_has_no_network") {
        return;
    }
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    TcpStream::connect(("127.0.0.1", port)).expect("the listener is reachable here");
    listener.accept().expect("the test's own connection");
    listener.set_nonblocking(true).unwrap();

    let root = TestDir::new("ossfuzz-net");
    let project = write_project(
        &root,
        "netproj",
        &format!(
            "#!/bin/bash -eu\n\
             if (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null; then\n\
             \x20 echo connected\n\
             else\n\
             \x20 echo refused\n\
             fi > \"$OUT/net.txt\"\n{STUB_FUZZER}"
        ),
    );
    let work = root.join("work");
    let out = import(&project, &work, &[]);
    assert_ok(&out);
    let net = fs::read_to_string(work.join("ossfuzz/out/net.txt")).unwrap();
    assert_eq!(net.trim(), "refused");
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => panic!("build.sh reached the host's network: {other:?}"),
    }
}

/// In the sandbox build.sh writes to `$SRC`, `$WORK` and `$OUT` and nowhere
/// else: not next to the work dir, not into the operator's source tree, not
/// into the home directory and not into the host's /tmp.
#[test]
fn build_sh_cannot_write_outside_src_work_and_out() {
    if !sandbox_available("build_sh_cannot_write_outside_src_work_and_out") {
        return;
    }
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let root = TestDir::new("ossfuzz-writes");
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    let unique = root.file_name().unwrap().to_str().unwrap().to_owned();
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let escapes = [
        outside.join("escape.txt"),
        root.join("writeproj/escape.txt"),
        home.join(format!(".{unique}-escape.txt")),
        PathBuf::from(format!("/tmp/{unique}-escape.txt")),
    ];
    let mut script = String::from(
        "#!/bin/bash -eu\n\
         try() { if (echo x > \"$1\") 2>/dev/null; then echo \"wrote $1\"; else echo \"refused $1\"; fi; }\n\
         {\n",
    );
    for target in escapes.iter().map(|p| p.display().to_string()).chain([
        "$SRC/inside.txt".to_owned(),
        "$WORK/inside.txt".to_owned(),
        "$OUT/inside.txt".to_owned(),
    ]) {
        script.push_str(&format!("try \"{target}\"\n"));
    }
    script.push_str(&format!("}} > \"$OUT/writes.txt\"\n{STUB_FUZZER}"));
    let project = write_project(&root, "writeproj", &script);
    let work = root.join("work");

    let out = import(&project, &work, &[]);
    let written: Vec<&PathBuf> = escapes.iter().filter(|path| path.exists()).collect();
    for path in &written {
        let _ = fs::remove_file(path);
    }
    assert_ok(&out);
    assert!(written.is_empty(), "build.sh wrote outside: {written:?}");
    let log = fs::read_to_string(work.join("ossfuzz/out/writes.txt")).unwrap();
    for escape in &escapes {
        assert!(
            log.contains(&format!("refused {}", escape.display())),
            "{}: {log}",
            escape.display()
        );
    }
    let work = work.canonicalize().unwrap();
    for dir in ["src", "work", "out"] {
        let inside = work.join("ossfuzz").join(dir).join("inside.txt");
        assert!(inside.is_file(), "{log}");
        assert!(
            log.contains(&format!("wrote {}", inside.display())),
            "{log}"
        );
    }
}

/// Without a sandbox that works, nothing of the project runs or is staged,
/// and the message says what is missing and what to do.
#[test]
fn a_missing_sandbox_tool_is_refused_with_a_clear_message() {
    let root = TestDir::new("ossfuzz-nosandbox");
    let project = write_project(
        &root,
        "proj",
        &format!("#!/bin/bash -eu\ntouch \"$OUT/ran\"\n{STUB_FUZZER}"),
    );
    let empty_path = root.join("empty-path");
    fs::create_dir(&empty_path).unwrap();
    let broken_path = root.join("broken-path");
    fs::create_dir(&broken_path).unwrap();
    let broken = broken_path.join("bwrap");
    fs::write(
        &broken,
        "#!/bin/sh\necho 'bwrap: setting up uid map: Permission denied' >&2\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o755)).unwrap();
    let missing = root.join("missing/bwrap");

    let cases: [(&str, Vec<String>, &Path, Vec<String>); 4] = [
        (
            "named tool missing",
            vec![
                "--sandbox".into(),
                "bubblewrap".into(),
                "--sandbox-tool".into(),
                missing.display().to_string(),
            ],
            &empty_path,
            vec![
                "--sandbox bubblewrap".into(),
                format!("'{}' is not found", missing.display()),
                "--sandbox none".into(),
            ],
        ),
        (
            "neither on PATH",
            vec![],
            &empty_path,
            vec![
                "neither bubblewrap (`bwrap`) nor firejail is on PATH".into(),
                "apt-get install bubblewrap".into(),
                "--sandbox none".into(),
            ],
        ),
        (
            "firejail not on PATH",
            vec!["--sandbox".into(), "firejail".into()],
            &empty_path,
            vec!["`firejail` is not on PATH".into(), "--sandbox none".into()],
        ),
        (
            "bwrap cannot create namespaces",
            vec![],
            &broken_path,
            vec![
                "no working sandbox for build.sh".into(),
                "setting up uid map: Permission denied".into(),
                "user and network namespaces".into(),
                "--sandbox none".into(),
            ],
        ),
    ];
    for (case, flags, path, needles) in cases {
        let work = root.join(format!("work-{}", case.replace(' ', "-")));
        let out = bhf()
            .args(["project", "import-ossfuzz"])
            .arg(&project)
            .arg("--work-dir")
            .arg(&work)
            .args(&flags)
            .env("PATH", path)
            .output()
            .unwrap();
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{case}: {stderr}");
        for needle in &needles {
            assert!(
                stderr.contains(needle.as_str()),
                "{case}: {needle:?} in {stderr}"
            );
        }
        assert!(
            !work.join("ossfuzz/out/ran").exists(),
            "{case}: build.sh ran"
        );
        assert!(
            listing(&work.join("ossfuzz/src")).is_empty(),
            "{case}: the project was staged"
        );
    }
}

/// An import refused for want of a sandbox leaves the earlier import of the
/// work dir as it was.
#[test]
fn a_refused_import_keeps_the_earlier_one() {
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let root = TestDir::new("ossfuzz-keep");
    let project = write_project(
        &root,
        "keepproj",
        &format!("#!/bin/bash -eu\n{STUB_FUZZER}"),
    );
    let work = root.join("work");
    assert_ok(&import(&project, &work, &sandbox_flags()));
    let earlier = listing(&work.join("ossfuzz"));
    assert!(
        earlier.contains(&PathBuf::from("out/stub_fuzzer")),
        "{earlier:?}"
    );
    assert!(
        earlier.contains(&PathBuf::from("import.json")),
        "{earlier:?}"
    );

    let missing = root.join("missing/bwrap");
    let refused = import(
        &project,
        &work,
        &[
            "--sandbox",
            "bubblewrap",
            "--sandbox-tool",
            missing.to_str().unwrap(),
        ],
    );
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert_eq!(listing(&work.join("ossfuzz")), earlier);
}

/// A failing build.sh fails the import with the end of its output.
#[test]
fn a_failing_build_sh_fails_the_import_with_its_output() {
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let root = TestDir::new("ossfuzz-fail");
    let project = write_project(
        &root,
        "failproj",
        "#!/bin/bash -eu\necho 'fatal: the compiler said no' >&2\nexit 3\n",
    );
    let out = import(&project, &root.join("work"), &sandbox_flags());
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("build.sh failed"), "{stderr}");
    assert!(stderr.contains("fatal: the compiler said no"), "{stderr}");
}
