// SPDX-License-Identifier: Apache-2.0
//
// Seed lineage end to end: a finding records what its input descends from,
// through `bhf fuzz` with a seed file, multi-worker campaigns merged into
// their parent (reseeded from the shared queue, with a layout-prefixed seed,
// and under a small record cap), the AFL++ lanes (which keep their own
// queue, so the lineage is unknown and says why), and `bhf auto` with a seed
// mined from the tree, and `bhf explain` prints it. The shell-script harnesses are Unix only; the
// `bhf auto` cases build a tiny C target and skip without clang/make.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A scratch dir removed when the test ends, passed or failed.
fn scratch(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("bhf-lineage-{name}-"))
        .tempdir()
        .unwrap()
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

const ASAN_REPORT: &str = "\
  >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x601 at pc 0x333'\n\
  >&2 echo '    #0 0x333 in parse_record /src/record.c:15'\n\
  >&2 echo '    #1 0x334 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
  exit 1\n";

/// A libFuzzer-style shell harness at `<work>/build/<id>/main` (one input file
/// per process) that reports an ASan crash when `crashes` (a shell test on
/// the input file `$1`) holds.
fn write_harness(work: &Path, id: &str, crashes: &str) {
    let dir = work.join("build").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
    let main = dir.join("main");
    std::fs::write(
        &main,
        format!("#!/bin/sh\nif {crashes}; then\n{ASAN_REPORT}fi\nexit 0\n"),
    )
    .unwrap();
    make_executable(&main);
}

/// [`write_harness`] crashing when the input starts with `LINEAGE` but is
/// not the seed itself: a mutation of the seed.
fn write_mutation_crash_harness(work: &Path, id: &str, seed_file: &Path) {
    write_harness(
        work,
        id,
        &format!(
            "[ \"$(head -c 7 \"$1\")\" = LINEAGE ] && ! cmp -s \"$1\" '{}'",
            seed_file.display()
        ),
    );
}

/// [`write_harness`] crashing on exactly the bytes of `crash_file`.
fn write_exact_crash_harness(work: &Path, id: &str, crash_file: &Path) {
    write_harness(
        work,
        id,
        &format!("cmp -s \"$1\" '{}'", crash_file.display()),
    );
}

fn bhf_fuzz(work: &Path, args: &[&str]) -> Output {
    bhf_fuzz_with(work, args, &[])
}

fn bhf_fuzz_with(work: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work)
        .args(args)
        .envs(env.iter().copied())
        .output()
        .expect("run bhf fuzz");
    assert!(
        out.status.success(),
        "bhf fuzz failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Every `finding.json` under `<work>/results/findings`.
fn findings(work: &Path) -> Vec<serde_json::Value> {
    let Ok(entries) = std::fs::read_dir(work.join("results/findings")) else {
        return Vec::new();
    };
    let mut records: Vec<serde_json::Value> = entries
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .collect();
    records.sort_by_key(|record| record["id"].as_str().unwrap_or("").to_owned());
    records
}

/// The lines of a harness's `lineage.jsonl`.
fn lineage_index(work: &Path, harness: &str) -> Vec<serde_json::Value> {
    let path = work.join("corpus").join(harness).join("lineage.jsonl");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The seed file, read back as `bhf fuzz` names it.
fn seed_file(root: &Path) -> (PathBuf, Vec<u8>) {
    let seed = b"LINEAGE-SEED-0001".to_vec();
    let path = root.join("seeds").join("record.bin");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &seed).unwrap();
    (path, seed)
}

#[test]
fn a_finding_mutated_from_a_seed_file_names_that_file() {
    let temp = scratch("seed-file");
    let root = temp.path();
    let work = root.join("work");
    let (path, seed) = seed_file(root);
    write_mutation_crash_harness(&work, "H-LIN", &path);

    let seed_arg = path.display().to_string();
    bhf_fuzz(
        &work,
        &[
            "--harness",
            "H-LIN",
            "--seed-file",
            &seed_arg,
            "--iterations",
            "300",
        ],
    );

    let records = findings(&work);
    assert_eq!(records.len(), 1, "{records:?}");
    let lineage = &records[0]["lineage"];
    assert_eq!(lineage["origin"], "user_seed", "{lineage}");
    assert_eq!(lineage["root_path"], seed_arg.as_str());
    assert_eq!(lineage["root_sha256"], sha256_hex(&seed));
    assert_eq!(lineage["parent_sha256"], sha256_hex(&seed));
    assert!(lineage["depth"].as_u64().unwrap() >= 1, "{lineage}");
    // The seed's own record is kept beside the queue it is in.
    let index = lineage_index(&work, "H-LIN");
    let seed_line = index
        .iter()
        .find(|line| line["sha256"] == sha256_hex(&seed))
        .expect("the seed's record");
    assert_eq!(seed_line["origin"], "seed");
    assert_eq!(seed_line["source"], "user");
    assert_eq!(seed_line["path"], seed_arg.as_str());
}

#[test]
fn a_worker_finding_merged_into_the_campaign_keeps_its_lineage() {
    let temp = scratch("workers");
    let root = temp.path();
    let work = root.join("work");
    let (path, seed) = seed_file(root);
    write_mutation_crash_harness(&work, "H-MC", &path);

    let seed_arg = path.display().to_string();
    bhf_fuzz(
        &work,
        &[
            "--harness",
            "H-MC",
            "--seed-file",
            &seed_arg,
            "--iterations",
            "300",
            "--workers",
            "2",
        ],
    );

    // Both workers find the crash; the campaign keeps one, with the lineage
    // the worker that found it recorded.
    let records = findings(&work);
    assert_eq!(records.len(), 1, "{records:?}");
    let lineage = &records[0]["lineage"];
    assert_eq!(lineage["origin"], "user_seed", "{lineage}");
    assert_eq!(lineage["root_path"], seed_arg.as_str());
    assert!(lineage["depth"].as_u64().unwrap() >= 1, "{lineage}");
    // The workers' records are merged into the campaign's own index, beside
    // the queue their entries were merged into.
    let index = lineage_index(&work, "H-MC");
    assert!(
        index
            .iter()
            .any(|line| line["sha256"] == sha256_hex(&seed) && line["source"] == "user"),
        "{index:?}"
    );
}

/// Write `lines` as a harness's `lineage.jsonl` and each of `entries` into
/// its queue, named by sha256 as bhf names them.
fn write_queue(work: &Path, harness: &str, entries: &[&[u8]], lines: &[serde_json::Value]) {
    let dir = work.join("corpus").join(harness);
    std::fs::create_dir_all(dir.join("queue")).unwrap();
    for entry in entries {
        std::fs::write(
            dir.join("queue").join(format!("{}.bin", sha256_hex(entry))),
            entry,
        )
        .unwrap();
    }
    let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
    std::fs::write(dir.join("lineage.jsonl"), text).unwrap();
}

/// A second campaign, run with workers and given no seed, is reseeded from
/// the shared queue: its finding still names the seed file the first pass
/// recorded, one generation further down, not the queue file bhf copied the
/// seed to.
#[test]
fn a_worker_reseeded_from_the_shared_queue_names_the_seed_an_earlier_pass_recorded() {
    let temp = scratch("reseeded-workers");
    let root = temp.path();
    let work = root.join("work");
    let (path, seed) = seed_file(root);
    let seed_arg = path.display().to_string();
    write_harness(&work, "H-RS", "false");
    bhf_fuzz(
        &work,
        &[
            "--harness",
            "H-RS",
            "--seed-file",
            &seed_arg,
            "--iterations",
            "20",
        ],
    );
    let index = lineage_index(&work, "H-RS");
    let seed_line = index
        .iter()
        .find(|line| line["sha256"] == sha256_hex(&seed))
        .expect("the seed's record");
    assert_eq!(seed_line["path"], seed_arg.as_str());

    write_mutation_crash_harness(&work, "H-RS", &path);
    bhf_fuzz(
        &work,
        &["--harness", "H-RS", "--workers", "2", "--iterations", "300"],
    );
    let records = findings(&work);
    assert_eq!(records.len(), 1, "{records:?}");
    let lineage = &records[0]["lineage"];
    assert_eq!(lineage["origin"], "user_seed", "{lineage}");
    assert_eq!(lineage["root_path"], seed_arg.as_str(), "{lineage}");
    assert_eq!(lineage["root_sha256"], sha256_hex(&seed));
    assert_eq!(lineage["parent_sha256"], sha256_hex(&seed));
    assert_eq!(lineage["depth"], 1, "recorded at 0, one more: {lineage}");
}

/// A queue entry recorded as a seed's child keeps that chain when a worker
/// finds a crash on it: the worker reads the campaign's records instead of
/// taking its copy of the entry for a seed of its own.
#[test]
fn a_worker_finding_on_a_recorded_queue_entry_keeps_its_recorded_chain() {
    let temp = scratch("recorded-entry");
    let root = temp.path();
    let work = root.join("work");
    let (path, seed) = seed_file(root);
    let child = b"LINEAGE-SEED-0001X".to_vec();
    let child_file = root.join("child.bin");
    std::fs::write(&child_file, &child).unwrap();
    let seed_arg = path.display().to_string();
    write_queue(
        &work,
        "H-RE",
        &[&seed, &child],
        &[
            serde_json::json!({"sha256": sha256_hex(&seed), "origin": "seed",
                               "source": "user", "path": seed_arg}),
            serde_json::json!({"sha256": sha256_hex(&child), "parent": sha256_hex(&seed)}),
        ],
    );
    write_exact_crash_harness(&work, "H-RE", &child_file);
    bhf_fuzz(
        &work,
        &["--harness", "H-RE", "--workers", "2", "--iterations", "30"],
    );

    let records = findings(&work);
    assert_eq!(records.len(), 1, "{records:?}");
    let lineage = &records[0]["lineage"];
    assert_eq!(lineage["origin"], "user_seed", "{lineage}");
    assert_eq!(lineage["root_path"], seed_arg.as_str(), "{lineage}");
    assert_eq!(lineage["root_sha256"], sha256_hex(&seed));
    assert_eq!(lineage["parent_sha256"], sha256_hex(&seed));
    assert_eq!(lineage["depth"], 1, "{lineage}");
    let text = explain(&work);
    assert!(
        text.contains(&format!(
            "Lineage (testcase.bin): descends from user seed {seed_arg} (sha256 {}…) after 1 \
             mutation generation.",
            &sha256_hex(&seed)[..12]
        )),
        "{text}"
    );
}

/// A queue entry with no record is a corpus root whatever its file is named:
/// a classified input's file is named by its signature, and the merge names
/// a colliding worker file `worker-N-<name>`. A worker handed it from the
/// shared queue says so, as it does for a file named by sha256.
#[test]
fn a_queue_entry_with_no_record_is_a_corpus_root_whatever_its_file_is_named() {
    let entry = b"QUEUE-ENTRY-0001".to_vec();
    let signature = format!("{}.bin", sha256_hex(b"exception signature"));
    for name in [signature.as_str(), "worker-1-entry.bin"] {
        let temp = scratch("unrecorded-entry");
        let root = temp.path();
        let work = root.join("work");
        let queue = work.join("corpus/H-UE/queue");
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join(name), &entry).unwrap();
        let entry_file = root.join("entry.bin");
        std::fs::write(&entry_file, &entry).unwrap();
        write_exact_crash_harness(&work, "H-UE", &entry_file);
        bhf_fuzz(
            &work,
            &["--harness", "H-UE", "--workers", "2", "--iterations", "5"],
        );

        let records = findings(&work);
        assert_eq!(records.len(), 1, "{name}: {records:?}");
        let lineage = &records[0]["lineage"];
        assert_eq!(lineage["origin"], "corpus", "{name}: {lineage}");
        assert_eq!(lineage["root_sha256"], sha256_hex(&entry));
        assert_eq!(lineage["depth"], 0, "{lineage}");
        assert!(
            lineage["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("no lineage record")),
            "{lineage}"
        );
    }
}

/// With a queue limit of 2 (so a record cap of 4) and ten records on file,
/// the chain the shared queue's entry needs survives however the file
/// sorts: in the workers, which read every record before trimming, and in
/// what the merge writes back.
#[test]
fn a_small_record_cap_keeps_the_chain_the_shared_queue_needs() {
    let temp = scratch("record-cap");
    let root = temp.path();
    let work = root.join("work");
    // The entry and its seed sort last of the ten.
    let mut inputs: Vec<Vec<u8>> = (0..10)
        .map(|n| format!("record-{n}").into_bytes())
        .collect();
    inputs.sort_by_key(|input| sha256_hex(input));
    let (entry, seed) = (inputs[8].clone(), inputs[9].clone());
    let seed_path = root.join("seeds").join("first.bin").display().to_string();
    let mut lines: Vec<serde_json::Value> = inputs[..8]
        .iter()
        .map(|other| serde_json::json!({"sha256": sha256_hex(other), "origin": "generated"}))
        .collect();
    lines.push(
        serde_json::json!({"sha256": sha256_hex(&seed), "origin": "seed",
                                  "source": "user", "path": seed_path}),
    );
    lines.push(serde_json::json!({"sha256": sha256_hex(&entry), "parent": sha256_hex(&seed)}));
    write_queue(&work, "H-CAP", &[&entry], &lines);
    let entry_file = root.join("entry.bin");
    std::fs::write(&entry_file, &entry).unwrap();
    write_exact_crash_harness(&work, "H-CAP", &entry_file);
    bhf_fuzz_with(
        &work,
        &["--harness", "H-CAP", "--workers", "2", "--iterations", "5"],
        &[("BHF_MAX_CORPUS_ENTRIES", "2")],
    );

    let records = findings(&work);
    assert_eq!(records.len(), 1, "{records:?}");
    let lineage = &records[0]["lineage"];
    assert_eq!(lineage["origin"], "user_seed", "{lineage}");
    assert_eq!(lineage["root_path"], seed_path.as_str(), "{lineage}");
    assert_eq!(lineage["depth"], 1, "{lineage}");
    let index = lineage_index(&work, "H-CAP");
    assert!(index.len() <= 4, "the merge keeps the cap: {index:?}");
    for kept in [&entry, &seed] {
        assert!(
            index.iter().any(|line| line["sha256"] == sha256_hex(kept)),
            "{index:?}"
        );
    }
}

/// An `arg-layout.json` whose harness decodes two 4-byte scalars before its
/// buffer, so a seed is also given behind 8 zero bytes.
const SCALARS_FIRST_LAYOUT: &str = r#"{"schema_version":"bhf.arg-layout.v1","harness_format_version":4,"language":"c","harness":"direct","static_decode":true,
 "steps":[{"step":"param","call":"target","role":"param","index":1,"name":"a","type":"uint32_t","order":0,"input":"cursor","decoder":"scalar","primitive":"bhf_i32","width":4,"static_decode":true},
 {"step":"param","call":"target","role":"param","index":2,"name":"b","type":"uint32_t","order":1,"input":"cursor","decoder":"scalar","primitive":"bhf_i32","width":4,"static_decode":true},
 {"step":"remainder","call":"target","sized":false},
 {"step":"param","call":"target","role":"param","index":0,"name":"buf","type":"const uint8_t *","order":2,"input":"remainder","decoder":"input_buffer","copied":true,"static_decode":true}]}"#;

/// A seed file given behind the harness's layout prefix names that file and
/// the prefix, in one process and with workers alike, never the file of
/// prefixed bytes the campaign wrote for its workers.
#[test]
fn a_layout_prefixed_seed_names_the_seed_file_with_or_without_workers() {
    for workers in [None, Some("2")] {
        let temp = scratch("layout-prefix");
        let root = temp.path();
        let work = root.join("work");
        let seed = b"MAGC".to_vec();
        let path = root.join("seeds").join("magic.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &seed).unwrap();
        let variant = root.join("variant.bin");
        std::fs::write(&variant, b"\0\0\0\0\0\0\0\0MAGC").unwrap();
        write_exact_crash_harness(&work, "H-LP", &variant);
        std::fs::write(
            work.join("build/H-LP/arg-layout.json"),
            SCALARS_FIRST_LAYOUT,
        )
        .unwrap();
        let seed_arg = path.display().to_string();
        let mut args = vec![
            "--harness",
            "H-LP",
            "--seed-file",
            &seed_arg,
            "--iterations",
            "10",
        ];
        if let Some(workers) = workers {
            args.extend(["--workers", workers]);
        }
        bhf_fuzz(&work, &args);

        let records = findings(&work);
        assert_eq!(records.len(), 1, "{workers:?}: {records:?}");
        let lineage = &records[0]["lineage"];
        assert_eq!(lineage["origin"], "user_seed", "{workers:?}: {lineage}");
        assert_eq!(
            lineage["root_path"],
            seed_arg.as_str(),
            "{workers:?}: {lineage}"
        );
        assert_eq!(lineage["root_sha256"], sha256_hex(&seed), "{workers:?}");
        assert_eq!(lineage["layout_prefix"], 8, "{workers:?}: {lineage}");
        assert_eq!(lineage["depth"], 0, "{workers:?}: {lineage}");
    }
}

/// An `afl-fuzz` stand-in that leaves one crash, `crash`, in its output
/// directory.
fn fake_afl_fuzz(dir: &Path, crash: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let script = dir.join("afl-fuzz");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             [ \"$1\" = -h ] && exit 1\n\
             while [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=\"$2\"; shift; done\n\
             mkdir -p \"$out/default/crashes\"\n\
             printf '{crash}' > \"$out/default/crashes/{AFL_CRASH}\"\n\
             exit 0\n"
        ),
    )
    .unwrap();
    make_executable(&script);
}

/// The name the fake `afl-fuzz` gives its crash.
const AFL_CRASH: &str = "id:000000,sig:06,src:000000,time:1,execs:2,op:havoc,rep:2";

#[test]
fn an_afl_finding_says_its_lineage_is_unknown_and_why() {
    let temp = scratch("afl");
    let root = temp.path();
    let work = root.join("work");
    let dir = work.join("build").join("H-AFL");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
    std::fs::write(dir.join("main"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&dir.join("main"));
    // AFL++ replays its crashes through stdin.
    std::fs::write(
        dir.join("main_afl"),
        format!("#!/bin/sh\ncat >/dev/null\n{ASAN_REPORT}"),
    )
    .unwrap();
    make_executable(&dir.join("main_afl"));
    let afl = root.join("afl");
    fake_afl_fuzz(&afl, "X");

    let afl_arg = afl.display().to_string();
    bhf_fuzz(
        &work,
        &[
            "--harness",
            "H-AFL",
            "--engine",
            "afl++",
            "--afl-path",
            &afl_arg,
            "--time",
            "1s",
            "--seed-input",
            "seed",
        ],
    );

    let records = findings(&work);
    assert_eq!(records.len(), 1, "{records:?}");
    let lineage = &records[0]["lineage"];
    assert_eq!(lineage["origin"], "unknown", "{lineage}");
    let reason = lineage["reason"].as_str().unwrap();
    assert!(reason.contains("AFL++"), "{reason}");
    assert!(reason.contains("id:000000,sig:06,src:000000"), "{reason}");
    assert!(
        lineage.get("depth").is_none(),
        "nothing is guessed: {lineage}"
    );
}

/// `bhf binary-fuzz --engine afl-qemu` hands the campaign to AFL++, which
/// schedules its own queue: the finding's lineage is unknown, says why and
/// names the crash file, and guesses nothing.
#[test]
fn a_binary_fuzz_afl_qemu_finding_says_its_lineage_is_unknown_and_why() {
    let temp = scratch("afl-qemu");
    let root = temp.path();
    let tools = root.join("afl");
    fake_afl_fuzz(&tools, "CRASH");
    std::fs::write(tools.join("afl-qemu-trace"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&tools.join("afl-qemu-trace"));
    let target = root.join("crash-stdin.sh");
    std::fs::write(
        &target,
        "#!/bin/sh\ninput=$(cat)\nif [ \"$input\" = CRASH ]; then echo crash >&2; exit 42; fi\nexit 0\n",
    )
    .unwrap();
    make_executable(&target);
    let work = root.join("work");
    let path = std::env::join_paths(std::iter::once(tools.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("binary-fuzz")
        .arg(&target)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--engine",
            "afl-qemu",
            "--input-mode",
            "stdin",
            "--seed-input",
            "SEED",
            "--time",
            "1s",
            "--timeout-ms",
            "1000",
        ])
        .env("PATH", path)
        .env("BHF_AFL_QEMU_TRACE", tools.join("afl-qemu-trace"))
        .output()
        .expect("run bhf binary-fuzz");
    assert!(
        out.status.success(),
        "bhf binary-fuzz failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let records = findings(&work);
    assert_eq!(records.len(), 1, "{records:?}");
    let lineage = &records[0]["lineage"];
    assert_eq!(lineage["origin"], "unknown", "{lineage}");
    let reason = lineage["reason"].as_str().unwrap();
    assert!(reason.contains("AFL++ QEMU mode"), "{reason}");
    assert!(reason.contains(AFL_CRASH), "{reason}");
    assert!(
        lineage.get("depth").is_none() && lineage.get("root_sha256").is_none(),
        "nothing is guessed: {lineage}"
    );
}

fn have_clang() -> bool {
    Command::new("clang").arg("--version").output().is_ok()
        && Command::new("make").arg("--version").output().is_ok()
}

/// FNV-1a, as the C target computes it, so a seed's first 8 bytes can gate
/// the code under test without the comparison operands spelling them (a
/// built-in start input cannot reach it by splicing a compared constant).
fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

/// A tree whose target crashes on `crash_condition` once an input's first 8
/// bytes hash like `seed`'s, with `seed` as its only test data.
fn write_tree(src: &Path, seed: &[u8], crash_condition: &str) {
    std::fs::create_dir_all(src.join("tests/data")).unwrap();
    std::fs::write(
        src.join("record.c"),
        format!(
            "#include <stddef.h>\n\
             #include <stdint.h>\n\
             #include <string.h>\n\
             static uint32_t fnv(const unsigned char *data, size_t len) {{\n\
             \x20   uint32_t hash = 2166136261u;\n\
             \x20   for (size_t i = 0; i < len; i++) {{ hash ^= data[i]; hash *= 16777619u; }}\n\
             \x20   return hash;\n\
             }}\n\
             int parse_record(const unsigned char *data, size_t len) {{\n\
             \x20   if (len < 8 || fnv(data, 8) != {hash}u) return 0;\n\
             \x20   if ({crash_condition}) {{ volatile int *sink = 0; *sink = (int)len; }}\n\
             \x20   return 1;\n\
             }}\n",
            hash = fnv1a(&seed[..8]),
        ),
    )
    .unwrap();
    std::fs::write(src.join("tests/data/record.bin"), seed).unwrap();
}

fn run_auto(src: &Path, work: &Path) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(src)
        // Room for a loaded host: the crash needs a few hundred executions.
        .args(["--per-target-time", "8", "--max-targets", "1", "--work-dir"])
        .arg(work)
        .output()
        .expect("run bhf auto");
    assert!(
        out.status.success(),
        "bhf auto failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn explain(work: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("explain")
        .arg("--work-dir")
        .arg(work)
        .output()
        .expect("run bhf explain");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    // Wrapped lines rejoined, so a phrase can be searched whole.
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The one finding of the run and the seed path `auto/seeds.json` lists.
fn auto_finding(work: &Path, stderr: &str) -> (serde_json::Value, String) {
    // The MSan corpus replay can report the crash line too, as a finding of
    // its own (BHF-212); that lane keeps no lineage.
    let records: Vec<serde_json::Value> = findings(work)
        .into_iter()
        .filter(|record| record["rule_id"] != "BHF-212")
        .collect();
    assert_eq!(records.len(), 1, "one crash: {records:?}\n{stderr}");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/seeds.json")).unwrap()).unwrap();
    let path = manifest["seeds"][0]["path"].as_str().unwrap().to_owned();
    assert!(path.ends_with("tests/data/record.bin"), "{manifest}");
    (records[0].clone(), path)
}

#[test]
fn a_crash_mutated_from_a_mined_seed_names_the_seed_and_its_generations() {
    if !have_clang() {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let temp = scratch("auto-mutated");
    let root = temp.path();
    let (src, work) = (root.join("src"), root.join("work"));
    // The seed passes the gate and does not crash; a mutation of its tail
    // (or its length) does.
    let seed = b"BHFSEED1tailtail";
    write_tree(
        &src,
        seed,
        "len != 16 || memcmp(data + 8, \"tailtail\", 8) != 0",
    );
    let out = run_auto(&src, &work);
    let stderr = String::from_utf8_lossy(&out.stderr);

    let (finding, path) = auto_finding(&work, &stderr);
    let lineage = &finding["lineage"];
    assert_eq!(lineage["origin"], "mined_seed", "{lineage}");
    assert_eq!(lineage["root_path"], path.as_str(), "{lineage}");
    assert_eq!(lineage["root_sha256"], sha256_hex(seed));
    let depth = lineage["depth"].as_u64().expect("a depth");
    assert!(depth >= 1, "{lineage}");

    let text = explain(&work);
    let generations = if depth == 1 {
        "generation"
    } else {
        "generations"
    };
    assert!(
        text.contains(&format!(
            "Lineage (testcase.bin): descends from mined seed {path} (sha256 {}…) after {depth} mutation {generations}",
            &sha256_hex(seed)[..12]
        )),
        "{text}"
    );
}

#[test]
fn a_crash_on_the_mined_seed_itself_is_zero_generations_and_byte_identical() {
    if !have_clang() {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let temp = scratch("auto-as-is");
    let root = temp.path();
    let (src, work) = (root.join("src"), root.join("work"));
    // Exactly the seed's 8 bytes crash: nothing shorter, nothing else.
    let seed = b"BHFSEED2";
    write_tree(&src, seed, "len == 8");
    let out = run_auto(&src, &work);
    let stderr = String::from_utf8_lossy(&out.stderr);

    let (finding, path) = auto_finding(&work, &stderr);
    let lineage = &finding["lineage"];
    assert_eq!(lineage["origin"], "mined_seed", "{lineage}");
    assert_eq!(lineage["root_path"], path.as_str());
    assert_eq!(lineage["depth"], 0, "{lineage}");

    let text = explain(&work);
    // explain names the input it shows: the minimized one when there is one.
    let dir = work
        .join("results/findings")
        .join(finding["id"].as_str().expect("a finding id"));
    let shown = if dir.join("min_testcase.bin").is_file() {
        "min_testcase.bin"
    } else {
        "testcase.bin"
    };
    assert!(
        text.contains(&format!(
            "This input ({shown}) is byte-identical to the seed mined from {path}"
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "is mined seed {path} (sha256 {}…) itself, unmutated",
            &sha256_hex(seed)[..12]
        )),
        "{text}"
    );
}
