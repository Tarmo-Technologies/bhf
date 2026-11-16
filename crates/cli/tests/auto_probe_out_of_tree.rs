// SPDX-License-Identifier: Apache-2.0

//! `--probe-build` builds outside the scanned tree (#210). It wrote
//! `.bhf-build` and the build's objects into the tree, and on a read-only
//! checkout produced nothing without saying why. A CMake probe now configures
//! into the work dir (`-B`), a Make probe builds a copy of the tree there,
//! the tree is byte-identical afterwards, and a probe that yields no compile
//! database says why.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have(tool: &str) -> bool {
    let present = { which::which(tool).is_ok() };
    support::require_tool(present, tool)
}

const WIDGET_C: &str = "#include <stddef.h>\n\
     int widget_sum(const unsigned char *data, size_t len) {\n\
         int total = 0;\n\
         for (size_t i = 0; i < len; i++) total += data[i];\n\
         return total;\n\
     }\n";

/// Every file under `dir` with its bytes, and every directory.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).unwrap().flatten() {
            let path = entry.path();
            let relative = path.strip_prefix(dir).unwrap().to_path_buf();
            if path.is_dir() {
                out.push((relative, None));
                pending.push(path);
            } else {
                out.push((relative, Some(std::fs::read(&path).unwrap())));
            }
        }
    }
    out.sort();
    out
}

fn probe(tree: &Path, work: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(tree)
        .arg("--work-dir")
        .arg(work)
        .args(["--probe-build", "--per-target-time", "1", "--jobs", "1"])
        .output()
        .expect("run bhf auto");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_cmake_probe_leaves_the_tree_as_it_was() {
    if !have("cmake") || !have("make") || !have("clang") {
        eprintln!("skipping: cmake, make or clang unavailable");
        return;
    }
    let dir = TestDir::new("probe-cmake");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(
        tree.join("CMakeLists.txt"),
        "cmake_minimum_required(VERSION 3.10)\nproject(widget C)\n\
         add_library(widget STATIC widget.c)\n",
    )
    .unwrap();
    std::fs::write(tree.join("widget.c"), WIDGET_C).unwrap();
    let before = snapshot(&tree);
    let work = dir.join("work");
    let log = probe(&tree, &work);

    assert_eq!(
        snapshot(&tree),
        before,
        "the probe wrote into the tree:\n{log}"
    );
    let db = support::probe_dir_in(&work).join("compile_commands.json");
    let text = std::fs::read_to_string(&db).unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(text.contains("widget.c"), "{text}");
}

#[test]
fn a_make_probe_builds_a_copy_and_leaves_the_tree_as_it_was() {
    if !have("make") || !have("clang") {
        eprintln!("skipping: make or clang unavailable");
        return;
    }
    let dir = TestDir::new("probe-make");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(
        tree.join("Makefile"),
        "libwidget.a: widget.o\n\tar rcs $@ $^\n\
         widget.o: widget.c\n\t$(CC) -DWIDGET_MAGIC=7 -c -o $@ widget.c\n",
    )
    .unwrap();
    std::fs::write(tree.join("widget.c"), WIDGET_C).unwrap();
    let before = snapshot(&tree);
    let work = dir.join("work");
    let log = probe(&tree, &work);

    assert_eq!(
        snapshot(&tree),
        before,
        "the probe wrote into the tree:\n{log}"
    );
    let probe = support::probe_dir_in(&work);
    let db: serde_json::Value = serde_json::from_slice(
        &std::fs::read(probe.join("compile_commands.json"))
            .unwrap_or_else(|e| panic!("{e}\n{log}")),
    )
    .unwrap();
    let entry = &db[0];
    // Named by the tree's file, built in the copy.
    assert_eq!(
        Path::new(entry["file"].as_str().unwrap()),
        tree.canonicalize().unwrap().join("widget.c"),
        "{db:#}"
    );
    assert!(entry.to_string().contains("-DWIDGET_MAGIC=7"), "{db:#}");
    let copy = probe.parent().unwrap().join("src");
    assert!(copy.join("libwidget.a").is_file(), "{log}");
}

#[cfg(unix)]
#[test]
fn a_read_only_checkout_is_probed() {
    use std::os::unix::fs::PermissionsExt;
    if !have("make") || !have("clang") {
        eprintln!("skipping: make or clang unavailable");
        return;
    }
    let dir = TestDir::new("probe-read-only");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(
        tree.join("Makefile"),
        "widget.o: widget.c\n\t$(CC) -c -o $@ widget.c\n",
    )
    .unwrap();
    std::fs::write(tree.join("widget.c"), WIDGET_C).unwrap();
    let set_mode = |mode: u32| {
        for path in [tree.join("Makefile"), tree.join("widget.c"), tree.clone()] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    };
    set_mode(0o555);
    let work = dir.join("work");
    let log = probe(&tree, &work);
    set_mode(0o755);
    let db = support::probe_dir_in(&work).join("compile_commands.json");
    assert!(db.is_file(), "{log}");
    assert!(!tree.join("widget.o").exists());
}

#[test]
fn a_make_probe_that_compiles_nothing_says_why() {
    if !have("make") || !have("clang") {
        eprintln!("skipping: make or clang unavailable");
        return;
    }
    let dir = TestDir::new("probe-make-fails");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(
        tree.join("Makefile"),
        "all: config.h widget.o\nconfig.h:\n\t@echo configure step failed; false\n\
         widget.o: widget.c\n\t$(CC) -c -o $@ widget.c\n",
    )
    .unwrap();
    std::fs::write(tree.join("widget.c"), WIDGET_C).unwrap();
    let log = probe(&tree, &dir.join("work"));
    assert!(
        log.contains("make ran no compiler") && log.contains("no compile database"),
        "{log}"
    );
}
