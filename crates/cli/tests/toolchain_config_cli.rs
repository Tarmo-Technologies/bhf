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

/// A CMake project with a two-member static library, for the build-probe tests.
fn write_cmake_widget(src: &Path) {
    std::fs::create_dir_all(src).unwrap();
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
}

/// A cross sweep rebuilds the archives a build probe built for this host with
/// the cross toolchain and links those, instead of leaving the project's
/// library out of every cross-built harness.
#[test]
fn a_cross_sweep_links_the_probe_archives_rebuilt_for_its_target() {
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
    write_cmake_widget(&src);
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
    let rebuilt = work.join("auto/probe-archives/aarch64-linux-gnu/libwidget.a");
    assert!(
        out.contains(&format!("rebuilt probe archive {}", rebuilt.display())),
        "{out}"
    );
    assert_eq!(elf_machine_of_archive(&rebuilt), EM_AARCH64);
    assert!(
        out.contains(&format!(
            "linking probe-built instrumented library {}",
            rebuilt.display()
        )),
        "the rebuilt archive is linked: {out}"
    );
    assert!(!out.contains("is not linked into the"), "{out}");
    let target = target_with_outcome(&work, &["built", "built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the aarch64 target must build:\n{out}"));
    assert_eq!(elf_machine(&harness_main(&work, &target)), EM_AARCH64);
}

/// A plain Makefile project's probe (the Make tier) builds its archive in the
/// tree, beside its sources; a cross sweep rebuilds that archive for its
/// target and links it too.
#[test]
fn a_cross_sweep_rebuilds_the_archive_a_plain_makefile_builds_in_the_tree() {
    if !have("aarch64-linux-gnu-gcc") || !have("qemu-aarch64") || !have("make") || !have("cc") {
        eprintln!("skip: aarch64-linux-gnu-gcc/qemu-aarch64/make/cc unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_cmake_widget(&src);
    std::fs::remove_file(src.join("CMakeLists.txt")).unwrap();
    std::fs::write(
        src.join("Makefile"),
        "CC ?= cc\nall: libwidget.a\nlibwidget.a: parse.o util.o\n\tar rcs $@ $^\n\
         %.o: %.c\n\t$(CC) $(CFLAGS) -c $< -o $@\n",
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
        src.join("libwidget.a").is_file(),
        "the Make tier builds in place:\n{out}"
    );
    let rebuilt = work.join("auto/probe-archives/aarch64-linux-gnu/libwidget.a");
    assert!(
        out.contains(&format!("rebuilt probe archive {}", rebuilt.display())),
        "{out}"
    );
    assert_eq!(elf_machine_of_archive(&rebuilt), EM_AARCH64);
    assert!(
        out.contains(&format!(
            "linking probe-built instrumented library {}",
            rebuilt.display()
        )),
        "the rebuilt archive is linked: {out}"
    );
}

/// The ELF `e_machine` of the first object in the archive at `path`.
fn elf_machine_of_archive(path: &Path) -> u16 {
    let bytes = std::fs::read(path).expect("read archive");
    let elf = bytes
        .windows(4)
        .position(|window| window == b"\x7fELF")
        .expect("an ELF member");
    u16::from_le_bytes([bytes[elf + 18], bytes[elf + 19]])
}

/// A native sweep with a GCC toolchain builds the probe's archives with that
/// GCC and links them, instead of linking clang-built AddressSanitizer
/// archives into GCC-built harnesses.
#[test]
fn a_gcc_toolchain_builds_and_links_gcc_probe_archives() {
    if !have("gcc") || !have("cmake") || !have("make") || !have("readelf") {
        eprintln!("skip: gcc/cmake/make/readelf unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    gcc_probe_builds_and_links_its_archive(&tmp.path().join("src"), &tmp.path().join("work"));
}

/// The GCC probe build works in a tree whose path has a space: the coverage
/// hooks its links need still reach CMake's linker flags as one word.
#[test]
fn a_gcc_toolchain_probes_a_tree_whose_path_has_a_space() {
    if !have("gcc") || !have("cmake") || !have("make") || !have("readelf") {
        eprintln!("skip: gcc/cmake/make/readelf unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("my tree");
    gcc_probe_builds_and_links_its_archive(&root.join("src"), &root.join("work"));
}

/// Run a native `--cc gcc` sweep with `--probe-build` over the CMake widget at
/// `src`, and check the probe built its archive with GCC and the harness
/// linked it.
fn gcc_probe_builds_and_links_its_archive(src: &Path, work: &Path) {
    let (src, work) = (src.to_path_buf(), work.to_path_buf());
    write_cmake_widget(&src);
    let output = bhf()
        .args(auto_args(&src, &work))
        .args([
            "--languages",
            "c",
            "--deps-only",
            "--probe-build",
            "--cc",
            "gcc",
            "--cxx",
            "g++",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(src.join(".bhf-build/bhf-artifacts.json"))
            .unwrap_or_else(|_| panic!("no probe manifest:\n{out}")),
    )
    .unwrap();
    assert_eq!(manifest["instrumentation"]["cc"], "gcc", "{manifest}");
    let flags = manifest["instrumentation"]["c_flags"].to_string();
    assert!(
        flags.contains("trace-pc,trace-cmp") && !flags.contains("trace-pc-guard"),
        "{flags}"
    );
    let archive = src.join(".bhf-build/libwidget.a");
    assert!(
        compiler_comment(&archive).contains("GCC:")
            && !compiler_comment(&archive).contains("clang"),
        "{}",
        compiler_comment(&archive)
    );
    assert!(
        out.contains(&format!(
            "linking probe-built instrumented library {}",
            archive.display()
        )),
        "the gcc-built archive is linked: {out}"
    );
    let target = target_with_outcome(&work, &["built", "built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the gcc target must build:\n{out}"));
    let comment = compiler_comment(&harness_main(&work, &target));
    assert!(
        comment.contains("GCC:") && !comment.contains("clang"),
        "{comment}"
    );
}

/// `[cross.<guard>]` tables replace the compiler and the emulator of the
/// guard-driven aarch64 and armhf lanes: the candidates under `arm64/` and
/// `arm/` build with the configured compiler and run under the configured
/// runner, with coverage.
#[test]
fn cross_tables_override_the_guard_lanes_compiler_and_runner() {
    let tools = [
        "aarch64-linux-gnu-gcc",
        "arm-linux-gnueabihf-gcc",
        "qemu-aarch64",
        "qemu-arm",
        "make",
    ];
    if tools.iter().any(|tool| !have(tool)) || std::env::consts::ARCH != "x86_64" {
        eprintln!("skip: needs {tools:?} on an x86_64 host");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src.join("arm64"));
    std::fs::create_dir_all(src.join("arm")).unwrap();
    std::fs::write(
        src.join("arm/scale.c"),
        "#include <stddef.h>\n\
         int scale_record(const unsigned char *data, size_t size) {\n\
             return size > 1 ? data[0] * data[1] : 0;\n\
         }\n",
    )
    .unwrap();
    let cfg = tmp.path().join("cfg");
    let log = |name: &str| cfg.join(format!("{name}.log"));
    write_script(
        &cfg.join("tools/a64-gcc"),
        &format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexec aarch64-linux-gnu-gcc \"$@\"\n",
            log("a64-gcc").display()
        ),
    );
    write_script(
        &cfg.join("tools/a64-g++"),
        "#!/bin/sh\nexec aarch64-linux-gnu-g++ \"$@\"\n",
    );
    write_script(
        &cfg.join("tools/a64-run"),
        &format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexec qemu-aarch64 \"$@\"\n",
            log("a64-run").display()
        ),
    );
    write_script(
        &cfg.join("tools/arm-run"),
        &format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexec qemu-arm -L /usr/arm-linux-gnueabihf \"$@\"\n",
            log("arm-run").display()
        ),
    );
    std::fs::write(
        cfg.join("bhf.toml"),
        "[cross.aarch64]\ncc = \"tools/a64-gcc\"\nrunner = \"tools/a64-run\"\n\
         runner-args = [\"-L\", \"/usr/aarch64-linux-gnu\"]\n\n\
         [cross.armhf]\ntarget = \"arm-linux-gnueabihf\"\nrunner = \"tools/arm-run\"\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = bhf()
        .args([
            "auto".as_ref(),
            src.as_os_str(),
            "--work-dir".as_ref(),
            work.as_os_str(),
            "--max-targets".as_ref(),
            "2".as_ref(),
            "--jobs".as_ref(),
            "1".as_ref(),
            "--no-discovery-cache".as_ref(),
        ])
        .args(["--languages", "c", "--per-target-time", "10", "--config"])
        .arg(cfg.join("bhf.toml"))
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    assert!(
        out.contains(&format!(
            "[cross.aarch64]: aarch64-linux-gnu targets build with {}",
            cfg.join("tools/a64-gcc").display()
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "[cross.armhf]: arm-linux-gnueabihf targets build with arm-linux-gnueabihf-gcc / \
             arm-linux-gnueabihf-g++ and run under {}",
            cfg.join("tools/arm-run").display()
        )),
        "{out}"
    );
    let targets = run_json(&work)["targets"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let fuzzed = |name: &str| {
        targets
            .iter()
            .find(|target| target["name"] == name)
            .filter(|target| target["outcome"]["outcome"] == "built_and_fuzzed")
            .cloned()
            .unwrap_or_else(|| panic!("{name} must build and fuzz:\n{out}"))
    };
    for (name, machine, logs) in [
        (
            "parse_record",
            EM_AARCH64,
            ["a64-gcc", "a64-run"].as_slice(),
        ),
        ("scale_record", 40u16, ["arm-run"].as_slice()),
    ] {
        let target = fuzzed(name);
        let harness = harness_main(&work, &target);
        assert_eq!(elf_machine(&harness), machine, "{name}");
        for log_name in logs {
            let text = std::fs::read_to_string(log(log_name)).unwrap_or_default();
            assert!(
                !text.is_empty(),
                "{log_name} was not used for {name}:\n{out}"
            );
        }
        let edges = target["outcome"]["passes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|pass| pass["coverage_edges"].as_u64())
            .max()
            .unwrap_or(0);
        assert!(edges > 0, "{name} must be fuzzed with coverage: {target}");
    }
    assert!(
        std::fs::read_to_string(log("a64-run"))
            .unwrap()
            .contains("-L /usr/aarch64-linux-gnu"),
        "the runner gets its configured arguments"
    );
}

/// A cross sweep's finding behind a `strcmp` gate records comparison
/// evidence: the capture replays the harness under the sweep's emulator, and
/// the harness reports its string comparisons without a sanitizer runtime.
/// Its coverage is labelled with the instrumentation GCC used.
#[test]
fn a_cross_sweep_records_comparison_evidence_for_a_strcmp_gated_finding() {
    if !have("aarch64-linux-gnu-gcc") || !have("qemu-aarch64") || !have("make") {
        eprintln!("skip: aarch64-linux-gnu-gcc/qemu-aarch64/make unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("parse.c"),
        "#include <stddef.h>\n#include <string.h>\n\
         int parse_record(const unsigned char *data, size_t size) {\n\
             char word[16];\n\
             if (size == 0 || size >= sizeof word) return 0;\n\
             memcpy(word, data, size);\n\
             word[size] = 0;\n\
             if (strcmp(word, \"OPEN-SESAME\") == 0) {\n\
                 volatile int *p = (volatile int *)0;\n\
                 *p = 1;\n\
             }\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let seed = tmp.path().join("seed.bin");
    std::fs::write(&seed, b"OPEN-SESAME").unwrap();
    let work = tmp.path().join("work");
    let output = bhf()
        .args(auto_args(&src, &work))
        .args([
            "--languages",
            "c",
            "--per-target-time",
            "15",
            "--target-triple",
            "aarch64-linux-gnu",
            "--runner",
            "qemu-aarch64",
            "--seed-file",
        ])
        .arg(&seed)
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let out = text(&output);
    let target = target_with_outcome(&work, &["built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the aarch64 target must build and fuzz:\n{out}"));
    let passes = target["outcome"]["passes"].as_array().expect("passes");
    assert!(
        passes
            .iter()
            .any(|pass| pass["coverage_instrumentation"] == "sancov-trace-pc"),
        "GCC's trace-pc coverage is labelled as such: {passes:?}"
    );
    let harness_dir = harness_main(&work, &target).parent().unwrap().to_path_buf();
    let runner: serde_json::Value =
        serde_json::from_slice(&std::fs::read(harness_dir.join("bhf_runner.json")).unwrap())
            .unwrap();
    assert_eq!(runner["program"], "qemu-aarch64", "{runner}");
    let findings: Vec<serde_json::Value> = std::fs::read_dir(work.join("results/findings"))
        .unwrap_or_else(|_| panic!("no findings:\n{out}"))
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect();
    let finding = findings
        .iter()
        .find(|finding| finding["gate_capture"].is_object())
        .unwrap_or_else(|| panic!("no finding has a comparison capture: {findings:?}\n{out}"));
    assert_eq!(
        finding["gate_capture"]["status"], "recorded",
        "{}",
        finding["gate_capture"]
    );
    assert_eq!(finding["gate_capture"]["runner"], "qemu-aarch64");
    let gate = finding["gates"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|gate| gate["cmp_kind"] == "strcmp")
        .unwrap_or_else(|| panic!("no strcmp gate: {}", finding["gates"]));
    assert_eq!(gate["operand_hex"], "4f50454e2d534553414d45", "{gate}");
    assert_eq!(
        finding["build"]["binary"]["coverage_instrumentation"], "sancov-trace-pc",
        "{}",
        finding["build"]
    );
}

/// Run `bhf auto` over `src` with the config at `config`, fuzzing each target
/// briefly.
fn auto_with_config(src: &Path, work: &Path, config: &Path) -> String {
    let output = bhf()
        .args(auto_args(src, work))
        .args(["--languages", "c", "--per-target-time", "5", "--config"])
        .arg(config)
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    text(&output)
}

/// A `[cross.<lane>]` sysroot reaches every compile and link of the lane,
/// bhf's own driver object included: an SDK compiler that refuses to compile
/// or link a file without its sysroot still builds the guarded target.
#[test]
fn a_cross_table_sysroot_reaches_every_compile_and_link() {
    let tools = ["aarch64-linux-gnu-gcc", "qemu-aarch64", "make"];
    if tools.iter().any(|tool| !have(tool)) || std::env::consts::ARCH != "x86_64" {
        eprintln!("skip: needs {tools:?} on an x86_64 host");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src.join("arm64"));
    let cfg = tmp.path().join("cfg");
    let sdk = cfg.join("sdk root");
    std::fs::create_dir_all(&sdk).unwrap();
    let log = cfg.join("sdk.log");
    for (name, real) in [
        ("sdk-gcc", "aarch64-linux-gnu-gcc"),
        ("sdk-g++", "aarch64-linux-gnu-g++"),
    ] {
        // Refuse a compile or link of any file without `--sysroot=<sdk>`,
        // then run the installed cross compiler, whose own layout is the SDK.
        write_script(
            &cfg.join("tools").join(name),
            &format!(
                "#!/bin/sh\n\
                 sysroot=no; files=no\n\
                 for a in \"$@\"; do\n\
                   case \"$a\" in '--sysroot={sdk}') sysroot=yes;; esac\n\
                   case \"$a\" in *.c|*.cc|*.cpp|*.o|*.a) files=yes;; esac\n\
                 done\n\
                 if [ $files = yes ] && [ $sysroot = no ]; then\n\
                   echo \"REFUSED $*\" >> '{log}'; echo '{name}: no --sysroot' >&2; exit 1\n\
                 fi\n\
                 echo \"OK $*\" >> '{log}'\n\
                 for a do shift; case \"$a\" in --sysroot=*) ;; *) set -- \"$@\" \"$a\";; esac; done\n\
                 exec {real} \"$@\"\n",
                sdk = sdk.display(),
                log = log.display(),
            ),
        );
    }
    std::fs::write(
        cfg.join("bhf.toml"),
        "[cross.aarch64]\ncc = \"tools/sdk-gcc\"\ncxx = \"tools/sdk-g++\"\n\
         sysroot = \"sdk root\"\nrunner = \"qemu-aarch64\"\n\
         runner-args = [\"-L\", \"/usr/aarch64-linux-gnu\"]\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let out = auto_with_config(&src, &work, &cfg.join("bhf.toml"));
    let calls = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !calls.contains("REFUSED"),
        "a compile or link ran without the sysroot:\n{calls}\n{out}"
    );
    let sysroot = format!("--sysroot={}", sdk.display());
    assert!(
        calls
            .lines()
            .any(|line| line.contains("-o bhf_driver.o") && line.contains(&sysroot)),
        "the driver object is compiled with the sysroot:\n{calls}"
    );
    let target = target_with_outcome(&work, &["built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the guarded target must build and fuzz:\n{out}"));
    assert_eq!(elf_machine(&harness_main(&work, &target)), EM_AARCH64);
}

/// A clang lane compiler builds for the lane's target: bhf adds
/// `--target=<triple>` to its compiles and links, as it does for a
/// `[toolchain]` clang.
#[test]
fn a_clang_cross_table_builds_for_the_lane_target() {
    let tools = ["clang", "aarch64-linux-gnu-gcc", "qemu-aarch64", "make"];
    if tools.iter().any(|tool| !have(tool)) || std::env::consts::ARCH != "x86_64" {
        eprintln!("skip: needs {tools:?} on an x86_64 host");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_parser(&src.join("arm64"));
    let cfg = tmp.path().join("bhf.toml");
    std::fs::write(&cfg, "[cross.aarch64]\ncc = \"clang\"\n").unwrap();
    let work = tmp.path().join("work");
    let out = auto_with_config(&src, &work, &cfg);
    let target = target_with_outcome(&work, &["built_and_fuzzed"])
        .unwrap_or_else(|| panic!("the clang-built aarch64 target must build and fuzz:\n{out}"));
    let harness = harness_main(&work, &target);
    assert_eq!(elf_machine(&harness), EM_AARCH64);
    assert!(
        compiler_comment(&harness).contains("clang"),
        "{}",
        compiler_comment(&harness)
    );
    let passes = target["outcome"]["passes"].as_array().expect("passes");
    assert!(
        passes
            .iter()
            .any(|pass| pass["coverage_instrumentation"] == "sancov-trace-pc-guard"),
        "{passes:?}"
    );
}
