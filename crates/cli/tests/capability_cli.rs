// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for fuzz-driven capability profiling. A parser that execs a
//! command and opens an input-derived path ONLY once the input carries a magic gate
//! must, after fuzzing, produce a BHF-668 "input-triggered capability" finding for
//! the process-exec surface (CWE-77) — a capability no baseline (empty / unstructured)
//! input reaches — plus an `auto/capabilities.json` profile.

use std::path::Path;
use std::process::Command;

mod support;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

/// Command exec + path open gated behind the "RUN" magic bytes.
const GATED_EXEC_C: &str = "\
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int process_cmd(const char *data, unsigned int len) {
    if (len < 4) return 0;
    if (data[0]=='R' && data[1]=='U' && data[2]=='N') {
        char cmd[64];
        snprintf(cmd, sizeof cmd, \"/bin/echo %.20s\", data + 3);
        system(cmd);
        return 1;
    }
    return 0;
}
";

#[test]
fn input_triggered_command_exec_is_profiled_as_capability() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("bhf-capability-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let src = work.with_extension("src.c");
    std::fs::write(&src, GATED_EXEC_C).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    support::configure_runtrace_shim(&mut command);
    let out = command
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("10")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf snippet");
    let _ = std::fs::remove_file(&src);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // A capabilities profile must be written.
    let profile_path = work.join("auto/capabilities.json");
    assert!(
        profile_path.is_file(),
        "expected auto/capabilities.json; stderr:\n{stderr}"
    );

    // A BHF-668 process-exec capability finding, input-triggered (never on baseline).
    let (exec_source, baseline_empty) = scan_capability_findings(&work);
    let exec_source = exec_source.unwrap_or_else(|| {
        panic!(
            "expected an input-triggered process-exec (CWE-77) BHF-668 finding; stderr:\n{stderr}"
        )
    });
    assert!(
        baseline_empty,
        "the exec capability must NOT be present in the baseline set (it is gated \
         behind the RUN magic); stderr:\n{stderr}"
    );

    // #22 regression: the finding's sink location must be the system() CALL line, not
    // process_cmd's declaration line. The source evidence is `file:line[:function]`;
    // the pointed-at source line must be the exec call itself.
    let (sink_file, sink_line) = parse_source_location(&exec_source)
        .unwrap_or_else(|| panic!("exec finding source is not file:line: {exec_source}"));
    let sink_src = std::fs::read_to_string(&sink_file)
        .unwrap_or_else(|e| panic!("read sink source {sink_file}: {e}"));
    let line_text = sink_src
        .lines()
        .nth(sink_line.saturating_sub(1))
        .unwrap_or("");
    assert!(
        line_text.contains("system("),
        "#22: capability finding must point at the system() call site, not the \
         function declaration; line {sink_line} of {sink_file} is: {line_text:?}\n\
         source evidence: {exec_source}"
    );
    let _ = std::fs::remove_dir_all(&work);
}

/// Split a `file:line[:function]` source-evidence value into `(file, line)`. The
/// line is the first purely-numeric colon-delimited component (so a Windows drive
/// prefix is not mistaken for it).
fn parse_source_location(source: &str) -> Option<(String, usize)> {
    let parts: Vec<&str> = source.split(':').collect();
    let idx = parts
        .iter()
        .position(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))?;
    if idx == 0 {
        return None;
    }
    let file = parts[..idx].join(":");
    let line = parts[idx].parse::<usize>().ok()?;
    Some((file, line))
}

/// Returns `(exec_finding_source, baseline_has_no_exec)` — the input-triggered
/// process-exec finding's `file:line:function` source evidence, if present.
fn scan_capability_findings(work: &Path) -> (Option<String>, bool) {
    let mut exec_source = None;
    if let Ok(entries) = std::fs::read_dir(work.join("findings")) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with("F-CAP-") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(e.path().join("finding.json")) {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let kind = v.pointer("/capability/kind").and_then(|x| x.as_str());
                    let cwe = v.pointer("/actionability/cwe/0").and_then(|x| x.as_str());
                    if kind == Some("process-exec") && cwe == Some("CWE-77") {
                        exec_source = v
                            .pointer("/oracle/evidence/0/value")
                            .and_then(|x| x.as_str())
                            .map(ToOwned::to_owned);
                    }
                }
            }
        }
    }
    // The profile must show the exec capability was NOT reached on baseline input.
    let baseline_no_exec = std::fs::read_to_string(work.join("auto/capabilities.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .map(|v| {
            v.get("harnesses")
                .and_then(|h| h.as_array())
                .map(|hs| {
                    hs.iter().all(|h| {
                        h.get("baseline_capabilities")
                            .and_then(|b| b.as_array())
                            .map(|caps| {
                                caps.iter().all(|c| {
                                    c.get("kind").and_then(|k| k.as_str()) != Some("process-exec")
                                })
                            })
                            .unwrap_or(true)
                    })
                })
                .unwrap_or(true)
        })
        .unwrap_or(false);
    (exec_source, baseline_no_exec)
}
