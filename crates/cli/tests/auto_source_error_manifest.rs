// SPDX-License-Identifier: Apache-2.0

//! A tree with a file that does not compile: `bhf auto` left missing-deps
//! empty, said "the tree built against its own sources", and filed the
//! compile error in the project's own file as a bhf `[codegen-bug]`. It now
//! records one `source_error` entry, does not say the tree built, and files
//! the target as a failed build.

use std::fs;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn a_compile_error_in_the_tree_is_a_source_error_not_a_codegen_bug() {
    if !support::libfuzzer_toolchain_available("source-error") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let root = TestDir::new("auto-source-error");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("bad.c"),
        "#include <stddef.h>\n\
         int parse_bad(const unsigned char *data, size_t len) {\n\
             if (len > 2) return undefined_counter + data[0];\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    fs::write(
        src.join("good.c"),
        "#include <stddef.h>\n\
         int parse_good(const unsigned char *data, size_t len) {\n\
             return len > 1 && data[0] == 'A';\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--per-target-time", "1", src.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "{stderr}"
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("auto/missing-deps.json")).unwrap()).unwrap();
    let source_errors: Vec<&serde_json::Value> = manifest["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["kind"] == "source_error")
        .collect();
    assert_eq!(source_errors.len(), 1, "{manifest:#}");
    assert_eq!(
        source_errors[0]["name"], "bad.c:3: use of undeclared identifier 'undefined_counter'",
        "{manifest:#}"
    );
    let text = fs::read_to_string(work.join("auto/missing-deps.txt")).unwrap();
    assert!(!text.contains("tree built"), "{text}");
    assert!(
        text.contains("1 compile error in the project's own source"),
        "{text}"
    );

    let bugs = fs::read_to_string(work.join("auto/bug-report.md")).unwrap();
    assert!(!bugs.contains("[codegen-bug]"), "{bugs}");
    assert!(bugs.contains("[failed-build]"), "{bugs}");
}
