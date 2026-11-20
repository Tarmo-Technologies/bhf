// SPDX-License-Identifier: Apache-2.0

//! `bhf project import-ossfuzz`: an OSS-Fuzz `build.sh` runs in a sandbox
//! with the OSS-Fuzz build variables, and the fuzzers it leaves in `$OUT`
//! are collected.
//!
//! The fixture (`tests/fixtures/ossfuzz_project`) is a small record parser
//! with an OSS-Fuzz build script, staged into a temporary directory so the
//! test can check the build never wrote into it. The tests of what the
//! sandbox refuses (network, writes outside `$SRC`, `$WORK` and `$OUT`, the
//! host's files, its log socket, shared memory, devices and terminal, and
//! new privileges) run once under bubblewrap and once under firejail, and
//! skip where that one does not work; `BHF_OSSFUZZ_SANDBOX=1`, which the
//! nightly job that installs both and gives bubblewrap its namespaces sets,
//! makes that a failure. (A hosted Ubuntu 24.04 runner, as the nightly's
//! other shards are, denies an unprivileged bubblewrap its user namespace
//! and has no firejail.) The others build in whichever sandbox works, or
//! with `--sandbox none` where none does.

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

/// A sandbox `--sandbox` names.
#[derive(Clone, Copy, Debug)]
enum Sandbox {
    Bubblewrap,
    Firejail,
}

impl Sandbox {
    /// Its `--sandbox` value.
    fn flag(self) -> &'static str {
        match self {
            Self::Bubblewrap => "bubblewrap",
            Self::Firejail => "firejail",
        }
    }

    /// Whether bhf can build in it here: bubblewrap with every namespace
    /// (the network one included), firejail without network.
    fn works(self) -> bool {
        match self {
            Self::Bubblewrap => runs(
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
            ),
            Self::Firejail => runs(
                "firejail",
                &["--quiet", "--noprofile", "--net=none", "--", "true"],
            ),
        }
    }
}

/// Whether a sandbox bhf can build in works here.
fn working_sandbox() -> bool {
    Sandbox::Bubblewrap.works() || Sandbox::Firejail.works()
}

/// Set to `1` where both sandboxes work, so their tests fail instead of
/// skipping without one.
const SANDBOX_REQUIRED: &str = "BHF_OSSFUZZ_SANDBOX";

/// For a test of what `sandbox` refuses: whether it works here, or the skip
/// line saying why not.
fn sandbox_available(test: &str, sandbox: Sandbox) -> bool {
    let works = sandbox.works();
    let required = std::env::var_os(SANDBOX_REQUIRED).is_some_and(|value| value == "1");
    assert!(
        works || !required,
        "{SANDBOX_REQUIRED}=1 and {} does not work here",
        sandbox.flag()
    );
    if !works {
        eprintln!(
            "skip {test}: {} does not work here (set {SANDBOX_REQUIRED}=1 to require it)",
            sandbox.flag()
        );
    }
    works
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

/// `bhf project import-ossfuzz <project> --work-dir <work> <extra>`.
fn import_command(project: &Path, work: &Path, extra: &[&str]) -> Command {
    let mut command = bhf();
    command
        .args(["project", "import-ossfuzz"])
        .arg(project)
        .arg("--work-dir")
        .arg(work)
        .args(extra);
    command
}

fn import(project: &Path, work: &Path, extra: &[&str]) -> Output {
    import_command(project, work, extra)
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

/// `bhf project run` on the import's manifest finds the planted overflow by
/// fuzzing, not by replaying a crashing seed: the project's corpus holds one
/// well-formed record whose length byte is one change away from the
/// overflow, and the target gets a 20-second budget (an imported target has
/// no `time`, so it would run `bhf fuzz`'s default 256 iterations). The
/// finding descends from that seed by mutation.
#[test]
fn bhf_project_run_finds_the_overflow_by_fuzzing_from_a_non_crashing_seed() {
    if !have_fixture_tools() {
        eprintln!("skipping: clang, zip or unzip not available");
        return;
    }
    let root = TestDir::new("ossfuzz-project-run");
    let project = root.join("ossfuzz_project");
    copy_tree(&fixture(), &project);
    // A 16-byte payload declared, 20 given: within the input, so no
    // overflow, until a mutation raises the length byte past 16.
    let corpus = project.join("fuzz/corpus/parse_record");
    fs::remove_dir_all(&corpus).unwrap();
    fs::create_dir(&corpus).unwrap();
    let mut near = b"REC1\x10".to_vec();
    near.extend_from_slice(&[b'A'; 20]);
    fs::write(corpus.join("near_overflow"), &near).unwrap();
    let work = root.join("work");
    assert_ok(&import(&project, &work, &sandbox_flags()));
    let work = work.canonicalize().unwrap();
    let seed = work.join("ossfuzz/seeds/parse_record_fuzzer/near_overflow");
    assert_eq!(fs::read(&seed).unwrap(), near, "the seed was not imported");

    // The budget, on the imported target.
    let manifest_path = work.join("ossfuzz/bhf.project.toml");
    let mut manifest: toml::Value =
        toml::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let target = manifest["target"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|target| target["id"].as_str() == Some("parse_record_fuzzer"))
        .unwrap();
    assert!(target.get("time").is_none(), "{target}");
    target
        .as_table_mut()
        .unwrap()
        .insert("time".to_owned(), toml::Value::from("20s"));
    fs::write(&manifest_path, toml::to_string(&manifest).unwrap()).unwrap();

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
    let findings: Vec<PathBuf> = fs::read_dir(run_dir.join("results/findings"))
        .unwrap_or_else(|error| panic!("no findings dir ({error}): {}", text(&run.stderr)))
        .map(|entry| entry.unwrap().path())
        .collect();
    let mut overflows = Vec::new();
    for dir in &findings {
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        let log = fs::read_to_string(dir.join("sanitizer.log")).unwrap_or_default();
        let testcase = fs::read(dir.join("testcase.bin")).unwrap();
        assert_ne!(testcase, near, "the seed itself crashed: {finding:#}");
        if log.contains("heap-buffer-overflow") && log.contains("record_parse") {
            overflows.push(finding);
        }
    }
    assert!(
        !overflows.is_empty(),
        "the overflow was not found in 20s: {findings:?}\n{}",
        text(&run.stderr)
    );
    let mutated = overflows.iter().any(|finding| {
        let lineage = &finding["lineage"];
        lineage["origin"] == "user_seed"
            && lineage["root_path"] == seed.to_str().unwrap()
            && lineage["depth"].as_u64().is_some_and(|depth| depth >= 1)
    });
    assert!(mutated, "no overflow mutated from the seed: {overflows:#?}");
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

/// The fixture's build.sh builds its two fuzzers in `sandbox`, each linked
/// with bhf's driver and ASan, and the import records that sandbox.
fn the_fixture_builds_in(sandbox: Sandbox, test: &str) {
    if !sandbox_available(test, sandbox) {
        return;
    }
    if !have_fixture_tools() {
        eprintln!("skipping: clang, zip or unzip not available");
        return;
    }
    let root = TestDir::new("ossfuzz-sandboxed-fixture");
    let project = root.join("ossfuzz_project");
    copy_tree(&fixture(), &project);
    let before = listing(&project);
    let work = root.join("work");
    let out = import(&project, &work, &["--sandbox", sandbox.flag(), "--json"]);
    assert_ok(&out);
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON record");
    assert_eq!(record["sandbox"]["mode"], sandbox.flag(), "{record:#}");
    let fuzzers = record["fuzzers"].as_array().unwrap();
    let names: Vec<&str> = fuzzers
        .iter()
        .map(|fuzzer| fuzzer["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["checksum_fuzzer", "parse_record_fuzzer"]);
    for fuzzer in fuzzers {
        let binary = PathBuf::from(fuzzer["binary"].as_str().unwrap());
        let bytes = fs::read(&binary).unwrap();
        assert!(contains(&bytes, b"BHF_FRAMED"), "{}", binary.display());
        assert!(contains(&bytes, b"__asan_init"), "{}", binary.display());
    }
    assert_eq!(record["fuzzers"][1]["seeds"]["files"], 3, "{record:#}");
    assert_eq!(listing(&project), before, "build.sh wrote into the tree");
}

#[test]
fn build_sh_builds_the_fixture_under_bubblewrap() {
    the_fixture_builds_in(
        Sandbox::Bubblewrap,
        "build_sh_builds_the_fixture_under_bubblewrap",
    );
}

#[test]
fn build_sh_builds_the_fixture_under_firejail() {
    the_fixture_builds_in(
        Sandbox::Firejail,
        "build_sh_builds_the_fixture_under_firejail",
    );
}

/// In `sandbox` build.sh has no network: a listener on this host's
/// loopback, which the test itself reaches, is not reached from build.sh.
fn has_no_network(sandbox: Sandbox, test: &str) {
    if !sandbox_available(test, sandbox) {
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
    let out = import(&project, &work, &["--sandbox", sandbox.flag()]);
    assert_ok(&out);
    let net = fs::read_to_string(work.join("ossfuzz/out/net.txt")).unwrap();
    assert_eq!(net.trim(), "refused");
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => panic!("build.sh reached the host's network: {other:?}"),
    }
}

#[test]
fn build_sh_has_no_network_under_bubblewrap() {
    has_no_network(
        Sandbox::Bubblewrap,
        "build_sh_has_no_network_under_bubblewrap",
    );
}

#[test]
fn build_sh_has_no_network_under_firejail() {
    has_no_network(Sandbox::Firejail, "build_sh_has_no_network_under_firejail");
}

/// In `sandbox` build.sh writes to `$SRC`, `$WORK` and `$OUT` and nowhere
/// else: not next to the work dir, not into the operator's source tree, not
/// into the home directory, the host's /tmp or this user's runtime
/// directory; and what it writes to the sandbox's own /dev/shm never
/// reaches the host's.
fn cannot_write_outside_src_work_and_out(sandbox: Sandbox, test: &str) {
    if !sandbox_available(test, sandbox) {
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
    let mut escapes = vec![
        outside.join("escape.txt"),
        root.join("writeproj/escape.txt"),
        home.join(format!(".{unique}-escape.txt")),
        PathBuf::from(format!("/tmp/{unique}-escape.txt")),
    ];
    let uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata(&outside).unwrap());
    let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
    if runtime_dir.is_dir() {
        escapes.push(runtime_dir.join(format!("{unique}-escape.txt")));
    }
    let shm = PathBuf::from(format!("/dev/shm/{unique}-escape.txt"));
    let mut script = String::from(
        "#!/bin/bash -eu\n\
         try() { if (echo x > \"$1\") 2>/dev/null; then echo \"wrote $1\"; else echo \"refused $1\"; fi; }\n\
         {\n",
    );
    for target in escapes
        .iter()
        .chain([&shm])
        .map(|p| p.display().to_string())
        .chain([
            "$SRC/inside.txt".to_owned(),
            "$WORK/inside.txt".to_owned(),
            "$OUT/inside.txt".to_owned(),
        ])
    {
        script.push_str(&format!("try \"{target}\"\n"));
    }
    script.push_str(&format!("}} > \"$OUT/writes.txt\"\n{STUB_FUZZER}"));
    let project = write_project(&root, "writeproj", &script);
    let work = root.join("work");

    let out = import(&project, &work, &["--sandbox", sandbox.flag()]);
    let written: Vec<&PathBuf> = escapes
        .iter()
        .chain([&shm])
        .filter(|path| path.exists())
        .collect();
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

#[test]
fn build_sh_cannot_write_outside_src_work_and_out_under_bubblewrap() {
    cannot_write_outside_src_work_and_out(
        Sandbox::Bubblewrap,
        "build_sh_cannot_write_outside_src_work_and_out_under_bubblewrap",
    );
}

#[test]
fn build_sh_cannot_write_outside_src_work_and_out_under_firejail() {
    cannot_write_outside_src_work_and_out(
        Sandbox::Firejail,
        "build_sh_cannot_write_outside_src_work_and_out_under_firejail",
    );
}

/// Removes a file the test put in the home directory, however it ends.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// The `cksum` of `path` ("<crc> <size>"), or `None` when it cannot be read.
fn cksum(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let out = Command::new("cksum").stdin(file).output().ok()?;
    out.status
        .success()
        .then(|| text(&out.stdout).trim().to_owned())
}

/// In `sandbox` build.sh sees none of the host's own files: not a file next
/// to the work dir, not the operator's source tree (only its copy in
/// `$SRC`), not a file in the home directory, not a Unix socket, which a
/// read-only mount would still let it connect to, and not /sys. It does see
/// the import's directories. Of the home directory it sees nothing the host
/// has there: no entry, and no file with the host's contents (firejail
/// copies the X11 cookie, `~/.Xauthority`, into the home it empties unless
/// told not to). A file firejail writes itself, such as a `.bashrc` from
/// /etc/skel, is not the host's.
fn cannot_see_the_hosts_files(sandbox: Sandbox, test: &str) {
    if !sandbox_available(test, sandbox) {
        return;
    }
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let root = TestDir::new("ossfuzz-reads");
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    let secret = outside.join("secret.txt");
    fs::write(&secret, "secret").unwrap();
    let socket = outside.join("service.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let unique = root.file_name().unwrap().to_str().unwrap().to_owned();
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
        .canonicalize()
        .unwrap();
    let home_secret = RemoveOnDrop(home.join(format!(".{unique}-secret.txt")));
    fs::write(&home_secret.0, "secret").unwrap();
    let project_dir = root.join("readproj");
    let hidden = [
        secret.clone(),
        socket.clone(),
        home_secret.0.clone(),
        project_dir.join("build.sh"),
        PathBuf::from("/sys/class"),
    ];
    let mut script = String::from(
        "#!/bin/bash -eu\n\
         look() { if [ -e \"$1\" ]; then echo \"saw $1\"; else echo \"hidden $1\"; fi; }\n\
         {\n",
    );
    for path in hidden
        .iter()
        .map(|p| p.display().to_string())
        .chain(["$SRC/readproj/build.sh".to_owned()])
    {
        script.push_str(&format!("look \"{path}\"\n"));
    }
    // Every entry of the home directory as the build sees it, with the
    // cksum of each regular file.
    script.push_str(&format!(
        "for f in \"{home}\"/* \"{home}\"/.[!.]* \"{home}\"/..?*; do\n\
         \x20 if [ -f \"$f\" ] && [ ! -L \"$f\" ]; then\n\
         \x20   echo \"home file $(cksum < \"$f\" 2>/dev/null) ${{f##*/}}\"\n\
         \x20 elif [ -e \"$f\" ] || [ -L \"$f\" ]; then\n\
         \x20   echo \"home other ${{f##*/}}\"\n\
         \x20 fi\n\
         done\n",
        home = home.display()
    ));
    script.push_str(&format!("}} > \"$OUT/reads.txt\"\n{STUB_FUZZER}"));
    let project = write_project(&root, "readproj", &script);
    let work = root.join("work");

    let out = import(&project, &work, &["--sandbox", sandbox.flag()]);
    assert_ok(&out);
    let log = fs::read_to_string(work.join("ossfuzz/out/reads.txt")).unwrap();
    for path in &hidden {
        assert!(path.exists(), "{}", path.display());
        assert!(
            log.contains(&format!("hidden {}", path.display())),
            "{}: {log}",
            path.display()
        );
    }
    let work = work.canonicalize().unwrap();
    let copy = work.join("ossfuzz/src/readproj/build.sh");
    assert!(log.contains(&format!("saw {}", copy.display())), "{log}");

    let mut leaked = Vec::new();
    for line in log.lines() {
        let Some(entry) = line.strip_prefix("home ") else {
            continue;
        };
        let (kind, rest) = entry.split_once(' ').unwrap();
        let (sum, name) = match kind {
            "file" => {
                let (sum, name) = rest.rsplit_once(' ').unwrap();
                (Some(sum.trim()), name)
            }
            _ => (None, rest),
        };
        let on_host = home.join(name);
        // An ancestor of the import's directories, bound in with only them.
        if work.starts_with(&on_host) || on_host.symlink_metadata().is_err() {
            continue;
        }
        let leak = match sum {
            Some(sum) => {
                let skel = cksum(&Path::new("/etc/skel").join(name));
                on_host.is_file()
                    && cksum(&on_host).as_deref() == Some(sum)
                    && skel.as_deref() != Some(sum)
            }
            None => true,
        };
        if leak {
            leaked.push(name.to_owned());
        }
    }
    assert!(
        leaked.is_empty(),
        "build.sh saw the host's {leaked:?} in {}: {log}",
        home.display()
    );
}

#[test]
fn build_sh_cannot_see_the_hosts_files_under_bubblewrap() {
    cannot_see_the_hosts_files(
        Sandbox::Bubblewrap,
        "build_sh_cannot_see_the_hosts_files_under_bubblewrap",
    );
}

#[test]
fn build_sh_cannot_see_the_hosts_files_under_firejail() {
    cannot_see_the_hosts_files(
        Sandbox::Firejail,
        "build_sh_cannot_see_the_hosts_files_under_firejail",
    );
}

/// A SysV shared-memory segment of this user's, removed however the test
/// ends.
struct SharedMemory(libc::c_int);

impl SharedMemory {
    fn new() -> Self {
        // SAFETY: shmget takes no pointers.
        let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
        assert!(id >= 0, "shmget: {}", std::io::Error::last_os_error());
        Self(id)
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        // SAFETY: IPC_RMID reads no buffer.
        unsafe { libc::shmctl(self.0, libc::IPC_RMID, std::ptr::null_mut()) };
    }
}

/// `command`'s output, run as the leader of a session whose controlling
/// terminal is a new pseudo-terminal: what bhf has when an operator runs
/// it from a terminal.
fn output_on_a_terminal(command: &mut Command) -> Output {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    // SAFETY: posix_openpt takes no pointers; the fd it returns is owned here.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    assert!(
        master >= 0,
        "posix_openpt: {}",
        std::io::Error::last_os_error()
    );
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: `name` is as long as the length passed.
    unsafe {
        assert_eq!(libc::grantpt(master.as_raw_fd()), 0);
        assert_eq!(libc::unlockpt(master.as_raw_fd()), 0);
        assert_eq!(
            libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()),
            0
        );
    }
    // SAFETY: ptsname_r wrote a NUL-terminated name.
    let terminal = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_owned();
    // SAFETY: setsid, open and ioctl are async-signal-safe, and the closure
    // allocates nothing.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let fd = libc::open(terminal.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if fd == -1 || libc::ioctl(fd, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command
        .stdin(Stdio::null())
        .output()
        .expect("run on a terminal");
    drop(master);
    output
}

/// A program that says whether it can reach the host's log socket
/// (`/dev/log`) and attach the SysV shared-memory segment its argument
/// names.
const REACH_PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct sockaddr_un log;
  memset(&log, 0, sizeof log);
  log.sun_family = AF_UNIX;
  strcpy(log.sun_path, "/dev/log");
  int reached = 0;
  int types[] = {SOCK_DGRAM, SOCK_STREAM};
  for (int i = 0; i < 2; i++) {
    int fd = socket(AF_UNIX, types[i], 0);
    if (fd >= 0 && connect(fd, (struct sockaddr *)&log, sizeof log) == 0) reached = 1;
    if (fd >= 0) close(fd);
  }
  printf("log %s\n", reached ? "reached" : "refused");
  void *shm = argc > 1 ? shmat(atoi(argv[1]), NULL, SHM_RDONLY) : (void *)-1;
  printf("shm %s\n", shm == (void *)-1 ? "refused" : "reached");
  return 0;
}
"#;

/// The device nodes either sandbox may show the build: bubblewrap's
/// `--dev` set and firejail's `--private-dev` set without its sound, video,
/// GPU, U2F, DVD, TV and input devices (`log` is firejail's, made
/// unreachable).
const SANDBOX_DEVICES: [&str; 16] = [
    "console", "core", "fd", "full", "log", "null", "ptmx", "pts", "random", "shm", "stderr",
    "stdin", "stdout", "tty", "urandom", "zero",
];

/// In `sandbox` build.sh cannot reach the host by any route but its files:
/// not the host's log socket (`/dev/log`), not a SysV shared-memory segment
/// of this user's, not the terminal bhf runs on, and no device but the
/// sandbox's own. No setuid program raises its privileges: no_new_privs is
/// set, and where this user may `sudo` without a password, sudo is refused.
fn cannot_reach_the_host_through_ipc_devices_or_its_terminal(sandbox: Sandbox, test: &str) {
    if !sandbox_available(test, sandbox) {
        return;
    }
    if !have_clang() {
        eprintln!("skipping: clang not available");
        return;
    }
    let root = TestDir::new("ossfuzz-reach");
    let project = root.join("reachproj");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("probe.c"), REACH_PROBE).unwrap();
    let probe = project.join("probe");
    let built = Command::new("clang")
        .arg("-o")
        .arg(&probe)
        .arg(project.join("probe.c"))
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", text(&built.stderr));
    let segment = SharedMemory::new();

    // Outside the sandbox the probe attaches the segment (and reaches
    // /dev/log where the host has a logger), and a shell on the terminal
    // opens it.
    let host = Command::new(&probe)
        .arg(segment.0.to_string())
        .output()
        .unwrap();
    let host = text(&host.stdout);
    assert!(host.contains("shm reached"), "{host}");
    if !host.contains("log reached") {
        eprintln!("note: nothing listens on /dev/log here; the log check proves little");
    }
    let tty_check = "if (: > /dev/tty) 2>/dev/null; then echo \"tty reached\"; \
                     else echo \"tty refused\"; fi";
    let control = output_on_a_terminal(Command::new("bash").args(["-c", tty_check]));
    assert_eq!(text(&control.stdout).trim(), "tty reached");
    let sudo_works = runs("sudo", &["-n", "true"]);

    let build_sh = format!(
        "#!/bin/bash -eu\n\
         {{\n\
         \"$SRC/reachproj/probe\" {id}\n\
         {tty_check}\n\
         if sudo -n true 2>/dev/null; then echo \"sudo reached\"; else echo \"sudo refused\"; fi\n\
         sed -n 's/^NoNewPrivs:[[:space:]]*/nonewprivs /p' /proc/self/status\n\
         for d in /dev/* /dev/.[!.]*; do\n\
         \x20 if [ -e \"$d\" ] || [ -L \"$d\" ]; then echo \"dev ${{d#/dev/}}\"; fi\n\
         done\n\
         }} > \"$OUT/reach.txt\"\n{STUB_FUZZER}",
        id = segment.0
    );
    let project = write_project(&root, "reachproj", &build_sh);
    let work = root.join("work");
    let out = output_on_a_terminal(&mut import_command(
        &project,
        &work,
        &["--sandbox", sandbox.flag()],
    ));
    assert_ok(&out);
    let log = fs::read_to_string(work.join("ossfuzz/out/reach.txt")).unwrap();
    for refused in ["log refused", "shm refused", "tty refused", "nonewprivs 1"] {
        assert!(log.lines().any(|line| line == refused), "{refused}: {log}");
    }
    if sudo_works {
        assert!(log.lines().any(|line| line == "sudo refused"), "{log}");
    }
    let devices: Vec<&str> = log
        .lines()
        .filter_map(|line| line.strip_prefix("dev "))
        .filter(|name| !SANDBOX_DEVICES.contains(name))
        .collect();
    assert!(devices.is_empty(), "the build sees /dev/{devices:?}: {log}");
}

#[test]
fn build_sh_cannot_reach_the_host_through_ipc_devices_or_its_terminal_under_bubblewrap() {
    cannot_reach_the_host_through_ipc_devices_or_its_terminal(
        Sandbox::Bubblewrap,
        "build_sh_cannot_reach_the_host_through_ipc_devices_or_its_terminal_under_bubblewrap",
    );
}

#[test]
fn build_sh_cannot_reach_the_host_through_ipc_devices_or_its_terminal_under_firejail() {
    cannot_reach_the_host_through_ipc_devices_or_its_terminal(
        Sandbox::Firejail,
        "build_sh_cannot_reach_the_host_through_ipc_devices_or_its_terminal_under_firejail",
    );
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
