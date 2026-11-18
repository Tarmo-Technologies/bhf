// SPDX-License-Identifier: Apache-2.0
//
// The harness's forward declaration of a C target matches the target's own:
// a variadic target keeps its `...` (#416), so the harness builds where it
// also sees the target's prototype.

use std::path::PathBuf;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// `bhf auto` on `source` (as `name`) for `target`: the log, the harness's
/// main.c and the findings document.
fn auto(tag: &str, name: &str, source: &str, target: &str) -> (String, String, serde_json::Value) {
    let src = TestDir::new(&format!("c-decl-{tag}-src"));
    std::fs::write(src.join(name), source).unwrap();
    let work = TestDir::new(&format!("c-decl-{tag}-work"));
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(["auto", src.to_str().unwrap(), "--target", target])
        .args([
            "--per-target-time",
            "10",
            "--max-targets",
            "1",
            "--jobs",
            "1",
        ])
        .args(["--work-dir", work.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let main = std::fs::read_dir(work.join("harnesses"))
        .ok()
        .into_iter()
        .flatten()
        .map(|entry| entry.unwrap().path().join("main.c"))
        .find(|path| path.exists())
        .map(|path| std::fs::read_to_string(path).unwrap())
        .unwrap_or_default();
    let findings = std::fs::read(work.join("results/findings.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    (log, main, findings)
}

fn finds_in(findings: &serde_json::Value, function: &str) -> bool {
    findings["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|finding| finding["title"].as_str().unwrap_or("").contains(function))
}

/// #416: the harness declared a variadic target without its `...`. With the
/// target's own prototype in view (a translation unit with a `main` is
/// included whole) that was `conflicting types`, a failed build.
#[test]
fn a_variadic_target_is_declared_with_its_ellipsis() {
    let (log, main, findings) = auto(
        "variadic",
        "report.c",
        "#include <stdarg.h>\n\
         #include <string.h>\n\
         void report(const char *tag, int level, const char *fmt, ...);\n\
         static char last[8];\n\
         void report(const char *tag, int level, const char *fmt, ...) {\n\
         \x20   va_list ap;\n\
         \x20   va_start(ap, fmt);\n\
         \x20   if (tag && tag[0] == 'T')\n\
         \x20       strcpy(last, tag);\n\
         \x20   va_end(ap);\n\
         \x20   (void)level;\n\
         }\n\
         int main(void) {\n\
         \x20   report(\"T\", 0, \"%s\", \"x\");\n\
         \x20   return 0;\n\
         }\n",
        "report",
    );
    assert!(log.contains("1 built+fuzzed"), "{log}");
    assert!(
        main.contains("extern void report(const char *, int, const char *, ...);"),
        "{main}"
    );
    assert!(finds_in(&findings, "report"), "{findings:#}\n{log}");
}
