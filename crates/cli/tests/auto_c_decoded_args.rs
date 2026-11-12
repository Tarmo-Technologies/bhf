// SPDX-License-Identifier: Apache-2.0
//
// A C finding records the value the generated harness decoded for each
// parameter. The fuzz loop re-runs a new finding's testcase once with the
// harness's argument trace on (BHF_TRACE_ARGS=1) and stores the arguments in
// decoded.json and, summarised, in finding.json `decoded_args`; the heap access
// names the parameter whose buffer it overflowed. `bhf replay --show-args`
// prints the same values. The scalars take the leading bytes and the
// length-less buffer the bytes after them (harness format 3), so no byte is
// both.

use std::path::PathBuf;
use std::process::Command;

fn bhf_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("bhf")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bhf_decoded_args_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_c_finding_records_its_decoded_arguments() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    let src = scratch("src");
    std::fs::write(
        src.join("widget.h"),
        "int widget_scan(const unsigned char *data, unsigned int bit_index, unsigned short width);\n",
    )
    .unwrap();
    // The planted read is one byte past the buffer, behind a gate on the two
    // scalars, so it fires on the seed only.
    std::fs::write(
        src.join("widget.c"),
        "#include \"widget.h\"\n\
         int widget_scan(const unsigned char *data, unsigned int bit_index, unsigned short width) {\n\
         \x20   if (bit_index == 0x41414141u && width == 0x4141u) {\n\
         \x20       volatile const unsigned char *p = data;\n\
         \x20       return p[9];\n\
         \x20   }\n\
         \x20   return data[0];\n\
         }\n",
    )
    .unwrap();
    let seeds = scratch("seeds");
    std::fs::write(seeds.join("trigger"), b"AAAAAAAAWXYZ").unwrap();
    let work = scratch("work");

    let out = Command::new(&bin)
        .args([
            "auto",
            src.to_str().unwrap(),
            "--target",
            "widget_scan",
            "--per-target-time",
            "10",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--seed-dir",
            seeds.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let findings = work.join("results/findings");
    let finding = std::fs::read_dir(&findings)
        .unwrap_or_else(|e| panic!("no findings dir ({e}):\n{combined}"))
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            std::fs::read_to_string(path.join("finding.json")).is_ok_and(|text| {
                text.contains("heap-buffer-overflow") || text.contains("HEAP_BUFFER_OVERFLOW")
            })
        })
        .unwrap_or_else(|| panic!("no heap-buffer-overflow finding:\n{combined}"));

    let decoded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("decoded.json")).unwrap()).unwrap();
    assert_eq!(decoded["arguments_source"], "harness_trace", "{decoded:#}");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    let args = record["decoded_args"].as_array().expect("decoded_args");
    let arg = |name: &str| {
        args.iter()
            .find(|arg| arg["name"] == name)
            .unwrap_or_else(|| panic!("no {name} in {args:#?}"))
    };
    let testcase = std::fs::read(finding.join("testcase.bin")).unwrap();
    // The crashing testcase is the built-in `AAAAAAAA` seed or the supplied one.
    assert!(testcase.starts_with(b"AAAAAAAA"), "{testcase:?}");
    let rest = &testcase[8..];
    assert_eq!(arg("bit_index")["value"], "1094795585");
    assert_eq!(arg("bit_index")["span"], serde_json::json!([0, 4]));
    assert_eq!(arg("width")["value"], "16705");
    assert_eq!(arg("width")["span"], serde_json::json!([4, 8]));
    assert_eq!(arg("data")["span"], serde_json::json!([8, testcase.len()]));
    assert_eq!(arg("data")["len"], rest.len());
    let hex: String = rest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(arg("data")["preview_hex"], hex);
    assert_eq!(record["harness_format_version"], 3, "{record:#}");
    assert_eq!(
        record["exception"]["access"]["parameter"]["name"], "data",
        "{record:#}"
    );

    let replay = Command::new(&bin)
        .args(["replay", finding.to_str().unwrap(), "--show-args"])
        .output()
        .expect("run bhf replay");
    let stdout = String::from_utf8_lossy(&replay.stdout);
    assert!(stdout.contains("decoded arguments"), "{stdout}");
    assert!(stdout.contains("1094795585"), "{stdout}");
    assert!(
        stdout.contains("the access hit parameter `data`'s buffer, at offset 9"),
        "{stdout}"
    );

    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_dir_all(&seeds);
}
