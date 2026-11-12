// SPDX-License-Identifier: Apache-2.0
//! A Visual Studio solution's compile settings reach the harness build by
//! default. The solution sits in its own directory, so `$(SolutionDir)`
//! differs from the project directory; a property sheet adds an include dir and
//! a define the target's header requires (`#error` without it); and the
//! project's two configurations define the same macro differently. The import
//! must apply the solution directory, the sheet, and exactly one configuration,
//! so the harness builds with the project's real headers and no fabricated
//! macro — and the planted heap overflow is found against the real constants.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/windows/vs_solution")
}

fn have(tool: &str) -> bool {
    which::which(tool).is_ok()
}

/// A copy of the fixture, so a run never writes into the repository.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn run_auto(
    source: &Path,
    work: &Path,
    extra: &[&str],
) -> (std::process::Output, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(source)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--jobs",
            "1",
            "--max-targets",
            "1",
            "--per-target-time",
            "8",
        ])
        .args(["--languages", "c", "--no-discovery-cache"])
        .args(extra)
        .output()
        .expect("spawn bhf auto");
    let run_json = std::fs::read(work.join("auto/run.json")).unwrap_or_else(|error| {
        panic!(
            "no run.json ({error}):\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, serde_json::from_slice(&run_json).unwrap())
}

fn harness_makefile(work: &Path, run: &serde_json::Value) -> String {
    let id = run["targets"][0]["harness_id"]
        .as_str()
        .expect("harness id");
    std::fs::read_to_string(work.join("harnesses").join(id).join("Makefile")).expect("Makefile")
}

#[test]
fn a_visual_studio_solution_is_imported_by_default() {
    if !have("clang") || !have("make") {
        eprintln!("skipping: clang/make not on PATH");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("tree");
    copy_tree(&fixture(), &source);
    let work = temp.path().join("work");
    let (output, run) = run_auto(&source, &work, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "read 2 ClCompile entries from vs/Widget.sln (config Debug|x64, static evaluation)"
        ),
        "the import names the solution and configuration it read:\n{stderr}"
    );
    assert!(
        !source.join(".bhf-build").exists(),
        "the default import writes nothing into the scanned tree"
    );
    assert_eq!(run["summary"]["built_and_fuzzed"], 1, "{stderr}");
    let makefile = harness_makefile(&work, &run);
    assert!(
        !makefile.contains("BUILD_CONTEXT_PROVENANCE = none"),
        "the harness was built from the imported context:\n{makefile}"
    );
    let flags = makefile
        .lines()
        .find(|line| line.starts_with("COMPILE_DB_FLAGS ="))
        .expect("COMPILE_DB_FLAGS");
    for expected in [
        "-DWIDGET_HAVE_TABLES=1",
        "-DWIDGET_MODE=1",
        "-DUNICODE",
        "include/gen",
    ] {
        assert!(flags.contains(expected), "missing {expected}: {flags}");
    }
    assert!(
        !flags.contains("WIDGET_MODE=2"),
        "only one configuration applies: {flags}"
    );
    let id = run["targets"][0]["harness_id"].as_str().unwrap();
    assert!(
        !work
            .join("harnesses")
            .join(id)
            .join("repairs/auto_defines.h")
            .exists(),
        "no macro value was fabricated"
    );
    assert!(
        run["targets"][0].get("build_fidelity").is_none(),
        "a build from the real context carries no reduced-fidelity record: {}",
        run["targets"][0]
    );
    let index = std::fs::read_to_string(work.join("results/INDEX.md")).unwrap_or_default();
    assert!(
        index.contains("Heap-based Buffer Overflow in parse\\_record"),
        "the planted overflow is found:\n{index}\n{stderr}"
    );
}

#[test]
fn the_import_can_be_turned_off_and_a_compile_database_wins() {
    if !have("clang") || !have("make") {
        eprintln!("skipping: clang/make not on PATH");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("tree");
    copy_tree(&fixture(), &source);
    let list = |work: &str, extra: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("auto")
            .arg(&source)
            .arg("--work-dir")
            .arg(temp.path().join(work))
            .args(["--languages", "c", "--list-targets", "--no-discovery-cache"])
            .args(extra)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let stderr = list("on", &[]);
    assert!(
        stderr.contains("ClCompile entr"),
        "imported by default:\n{stderr}"
    );
    let stderr = list("off", &["--no-msbuild-import"]);
    assert!(
        !stderr.contains("ClCompile entr"),
        "--no-msbuild-import skips the import:\n{stderr}"
    );
    let stderr = list("release", &["--msbuild-config", "Release|x64"]);
    assert!(
        stderr.contains("(config Release|x64, static evaluation)"),
        "--msbuild-config selects the configuration:\n{stderr}"
    );

    // Off Windows, a tree with its own build follows that build unless the
    // solution is named.
    std::fs::write(source.join("Makefile"), "all:\n").unwrap();
    let stderr = list("own-build", &[]);
    if cfg!(windows) {
        assert!(stderr.contains("ClCompile entr"), "{stderr}");
    } else {
        assert!(
            stderr.contains("has its own build (Makefile); not importing"),
            "{stderr}"
        );
        let stderr = list("named", &["--msbuild-solution", "vs/Widget.sln"]);
        assert!(stderr.contains("ClCompile entr"), "{stderr}");
    }
    std::fs::remove_file(source.join("Makefile")).unwrap();

    std::fs::write(source.join("compile_commands.json"), "[]\n").unwrap();
    let stderr = list("db", &[]);
    assert!(
        stderr.contains("rather than importing the Visual Studio solution"),
        "an existing compile database is authoritative:\n{stderr}"
    );
}

/// A portable project that ships Visual Studio files beside its autotools
/// inputs (no generated `configure` yet) is analysed with its own build off
/// Windows: the solution's Windows-only defines must not reach its harnesses.
#[test]
fn a_portable_tree_with_autotools_inputs_is_not_imported_off_windows() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("tree");
    std::fs::create_dir_all(source.join("src")).unwrap();
    std::fs::create_dir_all(source.join("win32")).unwrap();
    std::fs::write(source.join("configure.ac"), "AC_INIT([widget], [1.0])\n").unwrap();
    std::fs::write(source.join("Makefile.am"), "SUBDIRS = src\n").unwrap();
    std::fs::write(
        source.join("src/widget.c"),
        "#ifdef WIN32\n#error portable build only\n#endif\n\
         int parse_record(const unsigned char *data, int size) { return size > 0 ? data[0] : 0; }\n",
    )
    .unwrap();
    std::fs::write(
        source.join("win32/widget.vcxproj"),
        r#"<Project>
  <ItemDefinitionGroup><ClCompile><PreprocessorDefinitions>WIN32;_WINDOWS;%(PreprocessorDefinitions)</PreprocessorDefinitions></ClCompile></ItemDefinitionGroup>
  <ItemGroup><ClCompile Include="..\src\widget.c" /></ItemGroup>
</Project>"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&source)
        .arg("--work-dir")
        .arg(temp.path().join("work"))
        .args(["--languages", "c", "--list-targets", "--no-discovery-cache"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if cfg!(windows) {
        assert!(stderr.contains("ClCompile entr"), "{stderr}");
    } else {
        assert!(
            !stderr.contains("ClCompile entr"),
            "the autotools build is followed, not the solution:\n{stderr}"
        );
        assert!(
            stderr.contains("has its own build (configure.ac); not importing"),
            "{stderr}"
        );
    }
}

/// `--msbuild-solution` is honoured for a solution outside the scanned
/// directory, and a path that names no file is an error, not an empty import.
#[test]
fn a_named_solution_is_imported_wherever_it_is_and_a_missing_one_is_an_error() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("tree");
    copy_tree(&fixture(), &source);
    let list = |tree: &Path, work: &str, solution: &Path| {
        Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("auto")
            .arg(tree)
            .arg("--work-dir")
            .arg(temp.path().join(work))
            .args(["--languages", "c", "--list-targets", "--no-discovery-cache"])
            .arg("--msbuild-solution")
            .arg(solution)
            .output()
            .unwrap()
    };
    let output = list(
        &source.join("src"),
        "outside",
        &source.join("vs").join("Widget.sln"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ClCompile entr"),
        "a solution outside the scanned directory is imported when named:\n{stderr}"
    );

    let output = list(&source, "missing", Path::new("nosuch.sln"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("--msbuild-solution nosuch.sln: no such file")
            && stderr.contains("resolved against the scanned tree"),
        "{stderr}"
    );
}
