// SPDX-License-Identifier: Apache-2.0

//! The toolchain `bhf build` and `bhf auto` build with: compilers, flags, a
//! cross target with its runner, and the Ada toolchain, from the command line
//! or a `[toolchain]` config table. Each test drives the real binary and skips
//! (with a notice) when the compiler or emulator it needs is not installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn have(program: &str) -> bool {
    which::which(program).is_ok()
}

fn text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_json(work: &Path) -> serde_json::Value {
    let bytes = std::fs::read(work.join("auto/run.json")).unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// The first target whose outcome is one of `outcomes`.
fn target_with_outcome(work: &Path, outcomes: &[&str]) -> Option<serde_json::Value> {
    run_json(work)["targets"].as_array().and_then(|targets| {
        targets
            .iter()
            .find(|target| {
                target["outcome"]["outcome"]
                    .as_str()
                    .is_some_and(|outcome| outcomes.contains(&outcome))
            })
            .cloned()
    })
}

fn harness_main(work: &Path, target: &serde_json::Value) -> PathBuf {
    work.join("harnesses")
        .join(target["harness_id"].as_str().expect("harness id"))
        .join("main")
}

/// The ELF `e_machine` of `binary`.
fn elf_machine(binary: &Path) -> u16 {
    let bytes = std::fs::read(binary).expect("read binary");
    u16::from_le_bytes([bytes[18], bytes[19]])
}

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// The `.comment` section of `binary`, which names the compilers that built it.
fn compiler_comment(binary: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-p", ".comment"])
        .arg(binary)
        .output()
        .expect("run readelf");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn write_parser(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("parse.c"),
        "#include <stddef.h>\n\
         int parse_record(const unsigned char *data, size_t size) {\n\
             if (size >= 4 && data[0] == 'B' && data[1] == 'U' && data[2] == 'G' && data[3] == '!') {\n\
                 volatile int *p = (volatile int *)0;\n\
                 *p = 1;\n\
             }\n\
             return size > 0 ? data[0] : 0;\n\
         }\n",
    )
    .unwrap();
}

fn auto_args<'a>(src: &'a Path, work: &'a Path) -> Vec<&'a std::ffi::OsStr> {
    vec![
        "auto".as_ref(),
        src.as_os_str(),
        "--work-dir".as_ref(),
        work.as_os_str(),
        "--max-targets".as_ref(),
        "1".as_ref(),
        "--jobs".as_ref(),
        "1".as_ref(),
        "--no-discovery-cache".as_ref(),
    ]
}

/// `bhf build --target <triple>` builds a C/C++ harness with the cross
/// compiler for that triple. It used to build a host binary and say nothing.
#[test]
fn bhf_build_target_cross_compiles_a_c_harness() {
    if !have("aarch64-linux-gnu-gcc") || !have("make") {
        eprintln!("skip: aarch64-linux-gnu-gcc/make unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src);
    let work = tmp.path().join("work");
    let generated = bhf()
        .arg("generate-harness")
        .arg(src.join("parse.c"))
        .args(["--target", "parse_record", "--id", "H-XC", "--output"])
        .arg(work.join("harnesses"))
        .output()
        .unwrap();
    assert!(generated.status.success(), "{}", text(&generated));

    let built = bhf()
        .arg("build")
        .arg(&work)
        .args(["--harness", "H-XC", "--target", "aarch64-linux-gnu"])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&built);
    assert!(built.status.success(), "{out}");
    assert!(
        out.contains("CC=aarch64-linux-gnu-gcc"),
        "the choice is announced: {out}"
    );
    assert_eq!(
        elf_machine(&work.join("build/H-XC/main")),
        EM_AARCH64,
        "{out}"
    );

    // The same harness directory, back to the host compiler: the toolchain
    // stamp rebuilds the driver object instead of linking the aarch64 one.
    let host = bhf()
        .arg("build")
        .arg(&work)
        .args(["--harness", "H-XC"])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    assert!(host.status.success(), "{}", text(&host));
    assert_eq!(elf_machine(&work.join("build/H-XC/main")), EM_X86_64);
}

/// `--sanitizers` keeps an operator's gcc (it used to swap in clang without a
/// word) and builds with GCC-spelled flags.
#[test]
fn auto_sanitizers_keep_an_operator_gcc() {
    if !have("gcc") || !have("make") || !have("readelf") {
        eprintln!("skip: gcc/make/readelf unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src);
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args(["--languages", "c", "--deps-only", "--sanitizers", "asan"])
        .env("CC", "gcc")
        .env("CXX", "g++")
        .output()
        .unwrap();
    let target = target_with_outcome(&work, &["built", "built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the target must build with gcc:\n{}", text(&output)));
    let comment = compiler_comment(&harness_main(&work, &target));
    assert!(comment.contains("GCC:"), "{comment}");
    assert!(!comment.to_ascii_lowercase().contains("clang"), "{comment}");
}

/// An explicit `--config` sets the compiler, defines and include dirs from its
/// `[toolchain]` table, with paths relative to the config file.
#[test]
fn auto_builds_with_the_config_toolchain() {
    if !have("gcc") || !have("make") || !have("readelf") {
        eprintln!("skip: gcc/make/readelf unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("widget.c"),
        "#include \"widget_board.h\"\n\
         #if WIDGET_MODE != 2\n\
         #error \"WIDGET_MODE must come from the toolchain defines\"\n\
         #endif\n\
         int parse_record(const unsigned char *data, unsigned long size) {\n\
             return size > 0 ? data[0] + WIDGET_BOARD : 0;\n\
         }\n",
    )
    .unwrap();
    let config_dir = tmp.path().join("ci");
    std::fs::create_dir_all(config_dir.join("board")).unwrap();
    std::fs::write(
        config_dir.join("board/widget_board.h"),
        "#define WIDGET_BOARD 7\n",
    )
    .unwrap();
    std::fs::write(
        config_dir.join("bhf.toml"),
        "[toolchain]\ncc = \"gcc\"\ncxx = \"g++\"\ndefines = [\"WIDGET_MODE=2\"]\n\
         include-dirs = [\"board\"]\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    // Run from an unrelated directory: the relative include dir still resolves.
    let output = bhf()
        .current_dir(tmp.path())
        .args(auto_args(&src, &work))
        .args(["--languages", "c", "--deps-only", "--config"])
        .arg(config_dir.join("bhf.toml"))
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    assert!(out.contains("C/C++ toolchain: CC=gcc"), "{out}");
    let target = target_with_outcome(&work, &["built", "built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the target must build with the config toolchain:\n{out}"));
    let comment = compiler_comment(&harness_main(&work, &target));
    assert!(
        comment.contains("GCC:") && !comment.contains("clang"),
        "{comment}"
    );
}

/// A whole sweep built for aarch64 and run under qemu-user, with coverage: the
/// planted crash is found and the passes report edges.
#[test]
fn auto_cross_sweep_finds_a_planted_crash_under_the_runner_with_coverage() {
    if !have("aarch64-linux-gnu-gcc") || !have("qemu-aarch64") || !have("make") {
        eprintln!("skip: aarch64-linux-gnu-gcc/qemu-aarch64/make unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src);
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args([
            "--languages",
            "c",
            "--per-target-time",
            "20",
            "--target-triple",
            "aarch64-linux-gnu",
            "--runner",
            "qemu-aarch64",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    assert!(out.contains("cross sweep"), "{out}");
    let target = target_with_outcome(&work, &["built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the aarch64 target must build and fuzz:\n{out}"));
    assert_eq!(elf_machine(&harness_main(&work, &target)), EM_AARCH64);
    let passes = target["outcome"]["passes"].as_array().expect("passes");
    let edges = passes
        .iter()
        .filter_map(|pass| pass["coverage_edges"].as_u64())
        .max()
        .unwrap_or(0);
    assert!(
        edges > 0,
        "the emulated harness must report coverage: {passes:?}"
    );
    let findings: usize = passes
        .iter()
        .map(|pass| pass["findings"].as_array().map_or(0, Vec::len))
        .sum();
    assert!(
        findings > 0,
        "the planted crash must be found: {passes:?}\n{out}"
    );
}

/// A target this host cannot run, with no runner, is refused up front.
#[test]
fn auto_refuses_a_foreign_target_without_a_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src);
    let work = tmp.path().join("work");
    let foreign = if std::env::consts::ARCH == "aarch64" {
        "x86_64-linux-gnu"
    } else {
        "aarch64-linux-gnu"
    };
    let output = bhf()
        .args(auto_args(&src, &work))
        .args(["--dry-run", "--target-triple", foreign])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        text(&output).contains("toolchain.runner"),
        "{}",
        text(&output)
    );
}

/// A C++ member declared with its own class's qualification (MSVC-only by
/// default) builds: auto retries with the flag the compiler needs and keeps
/// it in the work dir's C++ compatibility fragment, for clang and for g++.
#[test]
fn auto_builds_an_extra_qualified_member_with_the_compat_flag() {
    if !have("clang++") || !have("make") {
        eprintln!("skip: clang++/make unavailable");
        return;
    }
    let compilers: &[(&str, &str)] = if have("g++") {
        &[("clang", "clang++"), ("gcc", "g++")]
    } else {
        &[("clang", "clang++")]
    };
    for (cc, cxx) in compilers {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("widget.h"),
            "#ifndef WIDGET_H\n#define WIDGET_H\n#include <cstddef>\n\
             class Widget {\npublic:\n\
                 int Widget::parse_record(const unsigned char *data, std::size_t size);\n\
             };\n#endif\n",
        )
        .unwrap();
        std::fs::write(
            src.join("widget.cpp"),
            "#include \"widget.h\"\n\
             int Widget::parse_record(const unsigned char *data, std::size_t size) {\n\
                 return size > 1 && data[0] == 'W' ? data[1] : 0;\n\
             }\n",
        )
        .unwrap();
        let work = tmp.path().join("work");
        let output = bhf()
            .args(auto_args(&src, &work))
            .args([
                "--languages",
                "cpp",
                "--deps-only",
                "--max-repair-rounds",
                "4",
            ])
            .env("CC", cc)
            .env("CXX", cxx)
            .output()
            .unwrap();
        assert!(
            target_with_outcome(&work, &["built", "built_and_fuzzed"]).is_some(),
            "{cxx}: the extra-qualified member must build:\n{}",
            text(&output)
        );
        let fragment = std::fs::read_to_string(work.join("cxx_compat.mk")).unwrap_or_default();
        assert!(
            fragment.contains("CXX_COMPAT_FLAGS_CLANG := -fms-extensions")
                && fragment.contains("CXX_COMPAT_FLAGS_GCC := -fpermissive"),
            "{cxx}: {fragment}"
        );
    }
}

/// `bhf auto` forwards its Ada toolchain settings into the generated project:
/// the target, extra switches and the probe backend.
#[test]
fn auto_forwards_the_ada_toolchain_to_the_generated_project() {
    if !have("gprbuild") || !have("gcc") {
        eprintln!("skip: gprbuild/gcc unavailable");
        return;
    }
    let host = Command::new("gcc").arg("-dumpmachine").output().unwrap();
    let host = String::from_utf8_lossy(&host.stdout).trim().to_owned();
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("widgets.ads"),
        "package Widgets is\n   function Checksum (Data : String) return Natural;\nend Widgets;\n",
    )
    .unwrap();
    std::fs::write(
        src.join("widgets.adb"),
        "package body Widgets is\n   function Checksum (Data : String) return Natural is\n      \
         Sum : Natural := 0;\n   begin\n      for C of Data loop\n         \
         Sum := (Sum + Character'Pos (C)) mod 65_521;\n      end loop;\n      \
         return Sum;\n   end Checksum;\nend Widgets;\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args(["--languages", "ada", "--deps-only", "--ada-target"])
        .arg(&host)
        .args(["--ada-switch=-O1", "--ada-switch=-gnatVa"])
        .output()
        .unwrap();
    let out = text(&output);
    let projects: Vec<PathBuf> = std::fs::read_dir(work.join("build"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path().join("bhf_build.gpr"))
                .filter(|path| path.is_file())
                .collect()
        })
        .unwrap_or_default();
    let project = projects
        .first()
        .map(|path| std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|| panic!("no generated Ada project:\n{out}"));
    assert!(
        project.contains(&format!("for Target use \"{host}\";")),
        "{project}"
    );
    assert!(project.contains("\"-O1\", \"-gnatVa\""), "{project}");
    assert!(
        target_with_outcome(&work, &["built", "built_and_fuzzed"]).is_some(),
        "the host-targeted Ada harness must still build:\n{out}"
    );
}

/// A C file whose `parse_record` reads one byte past its input: only an
/// AddressSanitizer build reports it.
fn write_over_read(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("parse.c"),
        "#include <stddef.h>\n\
         int parse_record(const unsigned char *data, size_t size) {\n\
             return size > 0 ? data[size] : 0;\n\
         }\n",
    )
    .unwrap();
}

/// An executable shell script at `path`.
fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A runner configured for a foreign Ada target only runs the Ada harnesses:
/// the C/C++ candidates still build for the host, with sanitizers, and run
/// natively. It used to turn the whole C/C++ sweep into an emulated one.
#[test]
fn an_ada_only_runner_leaves_the_c_candidates_native() {
    if !have("clang") || !have("make") || std::env::consts::ARCH != "x86_64" {
        eprintln!("skip: clang/make unavailable or not an x86_64 host");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_over_read(&src);
    // Never meant to run here: a C candidate that reached it would fail.
    let runner = tmp.path().join("bin/qemu-aarch64");
    write_script(&runner, "#!/bin/sh\nexit 1\n");
    let config = tmp.path().join("bhf.toml");
    std::fs::write(
        &config,
        format!(
            "[toolchain]\nrunner = \"{}\"\n[toolchain.ada]\ntarget = \"aarch64-linux-gnu\"\n",
            runner.display()
        ),
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args(["--languages", "c", "--per-target-time", "5", "--config"])
        .arg(&config)
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    assert!(!out.contains("cross sweep"), "{out}");
    assert!(
        out.contains("Ada"),
        "the runner's scope is announced: {out}"
    );
    let target = target_with_outcome(&work, &["built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the C target must build and fuzz natively:\n{out}"));
    let main = harness_main(&work, &target);
    assert_eq!(elf_machine(&main), EM_X86_64);
    let binary = std::fs::read(&main).unwrap();
    assert!(
        binary
            .windows(b"__asan_init".len())
            .any(|window| window == b"__asan_init"),
        "the native build keeps AddressSanitizer:\n{out}"
    );
}

/// A runner with nothing foreign to run is refused rather than wrapped around
/// host builds.
#[test]
fn auto_refuses_a_runner_when_nothing_builds_for_another_target() {
    if !have("clang") {
        eprintln!("skip: clang unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src);
    let runner = tmp.path().join("bin/qemu-aarch64");
    write_script(&runner, "#!/bin/sh\nexit 1\n");
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args(["--dry-run", "--runner"])
        .arg(&runner)
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    assert!(!output.status.success(), "{out}");
    assert!(out.contains("toolchain.target"), "{out}");
}

/// A C/C++ compiler that builds for another target, with no runner, is
/// refused up front, whether it comes from --cc or from CC. It used to build
/// foreign binaries and run them natively, rejecting every input.
#[test]
fn auto_refuses_a_foreign_compiler_without_a_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src);
    let foreign = if std::env::consts::ARCH == "aarch64" {
        "x86_64-linux-gnu"
    } else {
        "aarch64-linux-gnu"
    };
    // Answers -dumpmachine like a cross gcc for `foreign` does.
    let cross_cc = tmp.path().join(format!("bin/{foreign}-gcc"));
    write_script(
        &cross_cc,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = -dumpmachine ]; then echo {foreign}; exit 0; fi\nexit 1\n"
        ),
    );
    let work = tmp.path().join("work");
    let from_flag = bhf()
        .args(auto_args(&src, &work))
        .arg("--dry-run")
        .arg("--cc")
        .arg(&cross_cc)
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&from_flag);
    assert!(!from_flag.status.success(), "{out}");
    assert!(
        out.contains("toolchain.runner") && out.contains(foreign),
        "{out}"
    );
    let from_env = bhf()
        .args(auto_args(&src, &work))
        .arg("--dry-run")
        .env("CC", &cross_cc)
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&from_env);
    assert!(!from_env.status.success(), "{out}");
    assert!(
        out.contains("toolchain.runner") && out.contains("CC"),
        "{out}"
    );
}

/// CC=clang in the environment is bhf's own default compiler, so a target only
/// gcc accepts still gets the gcc retry.
#[test]
fn an_ambient_clang_keeps_the_gcc_retry() {
    if !have("gcc") || !have("clang") || !have("make") {
        eprintln!("skip: gcc/clang/make unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    // A nested function: a GNU C extension clang rejects.
    std::fs::write(
        src.join("parse.c"),
        "#include <stddef.h>\n\
         int parse_record(const unsigned char *data, size_t size) {\n\
             int scale(int value) { return value * 2; }\n\
             return size > 0 ? scale(data[0]) : 0;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args(["--languages", "c", "--deps-only"])
        .env("CC", "clang")
        .env("CXX", "clang++")
        .output()
        .unwrap();
    let out = text(&output);
    assert!(out.contains("gcc accepted it"), "{out}");
    assert!(
        target_with_outcome(&work, &["built", "built_and_fuzzed"]).is_some(),
        "the gcc-only target must build:\n{out}"
    );
}

/// A cross sweep does not link the archives a build probe built for this
/// host: it says so and builds the target from its sources instead of failing
/// every link with "file in wrong format".
#[test]
fn a_cross_sweep_does_not_link_host_probe_archives() {
    if !have("aarch64-linux-gnu-gcc")
        || !have("qemu-aarch64")
        || !have("cmake")
        || !have("clang")
        || !have("make")
    {
        eprintln!("skip: aarch64-linux-gnu-gcc/qemu-aarch64/cmake/clang/make unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("CMakeLists.txt"),
        "cmake_minimum_required(VERSION 3.10)\nproject(widget C)\n\
         add_library(widget STATIC parse.c util.c)\n",
    )
    .unwrap();
    std::fs::write(src.join("util.h"), "int widget_scale(int value);\n").unwrap();
    std::fs::write(
        src.join("util.c"),
        "#include \"util.h\"\nint widget_scale(int value) { return value * 3; }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("parse.c"),
        "#include <stddef.h>\n#include \"util.h\"\n\
         int parse_record(const unsigned char *data, size_t size) {\n\
             return size > 0 ? widget_scale(data[0]) : 0;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args([
            "--languages",
            "c",
            "--deps-only",
            "--probe-build",
            "--target-triple",
            "aarch64-linux-gnu",
            "--runner",
            "qemu-aarch64",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    assert!(
        out.contains("not linked into the cross-built harnesses"),
        "the limitation is announced: {out}"
    );
    assert!(
        !out.contains("linking probe-built instrumented library"),
        "{out}"
    );
    let target = target_with_outcome(&work, &["built", "built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the aarch64 target must build:\n{out}"));
    assert_eq!(elf_machine(&harness_main(&work, &target)), EM_AARCH64);
}
