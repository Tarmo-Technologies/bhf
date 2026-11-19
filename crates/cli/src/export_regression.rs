// SPDX-License-Identifier: Apache-2.0

//! `bhf export regression` (#339): a work dir's harnesses, corpora and
//! findings as a standalone regression suite.
//!
//! For each C/C++ harness the suite keeps its sources and Makefile, the
//! build context bhf recovered for it (`build.env`), its corpus and the
//! minimized input of each of its findings, with bhf's C runtime copied in.
//! The Makefile's paths into the scanned tree and the runtime become
//! `$(SOURCE_ROOT)` and `$(SUITE_DIR)`, so the suite rebuilds against a later
//! checkout of the tree. `run.sh` builds each harness and runs every input:
//! an input that crashes fails the suite, so a finding's input fails it until
//! the bug is fixed, and a corpus input that crashes is a regression. A
//! finding of a replay lane's build (MSan, TSan, CFI, RealtimeSanitizer) is
//! left out: the suite runs each harness's own build.

use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RegressionLang {
    /// C and C++ harnesses.
    C,
    /// Ada harnesses.
    Ada,
}

#[derive(Debug, clap::Args)]
pub struct RegressionArgs {
    /// The work directory to export.
    #[arg(long, default_value = "bhf_work")]
    pub work_dir: PathBuf,
    /// The directory to write the suite to (created; must be empty if it
    /// exists).
    #[arg(long)]
    pub out: PathBuf,
    /// The harnesses to export.
    #[arg(long, value_enum, default_value_t = RegressionLang::C)]
    pub lang: RegressionLang,
    /// At most this many corpus inputs per harness (the smallest first).
    #[arg(long = "max-corpus", default_value_t = 500)]
    pub max_corpus: usize,
}

/// What an export wrote.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Exported {
    pub(crate) harnesses: usize,
    pub(crate) findings: usize,
    pub(crate) corpus: usize,
}

pub fn run(args: RegressionArgs) -> i32 {
    match export(&args) {
        Ok(exported) if exported.harnesses == 0 => {
            bhfeprintln!(
                "bhf export regression: {} has no {} harness to export",
                args.work_dir.display(),
                match args.lang {
                    RegressionLang::C => "C/C++",
                    RegressionLang::Ada => "Ada",
                }
            );
            1
        }
        Ok(exported) => {
            println!(
                "regression suite: {} harness(es), {} finding input(s), {} corpus input(s): {}",
                exported.harnesses,
                exported.findings,
                exported.corpus,
                args.out.join("run.sh").display()
            );
            0
        }
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}

pub(crate) fn export(args: &RegressionArgs) -> Result<Exported, String> {
    if args.out.exists()
        && std::fs::read_dir(&args.out)
            .map_err(|error| format!("read {}: {error}", args.out.display()))?
            .next()
            .is_some()
    {
        return Err(format!("{} is not empty", args.out.display()));
    }
    let source_root = source_root(&args.work_dir).ok_or_else(|| {
        format!(
            "{} has no results/findings.json naming the scanned tree (run `bhf auto` first)",
            args.work_dir.display()
        )
    })?;
    match args.lang {
        RegressionLang::C => export_c(args, &source_root),
        RegressionLang::Ada => crate::export_regression_ada::export(args, &source_root),
    }
}

/// The tree the work dir's run scanned (`results/findings.json` `source.root`).
fn source_root(work_dir: &Path) -> Option<PathBuf> {
    let doc: Value = serde_json::from_slice(
        &std::fs::read(corpus::layout::results_dir(work_dir).join("findings.json")).ok()?,
    )
    .ok()?;
    doc.pointer("/source/root")?.as_str().map(PathBuf::from)
}

/// The harness directories under `work_dir` with a file named one of `mains`.
pub(crate) fn harness_dirs(work_dir: &Path, mains: &[&str]) -> Vec<(String, PathBuf)> {
    let mut dirs: Vec<(String, PathBuf)> = std::fs::read_dir(work_dir.join("harnesses"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|dir| mains.iter().any(|main| dir.join(main).is_file()))
                .filter_map(|dir| Some((dir.file_name()?.to_str()?.to_owned(), dir)))
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs
}

/// Copy each finding's minimized input (else its testcase) for `harness_id`
/// into `dest`, as `<finding id>.bin`. Returns how many.
pub(crate) fn copy_finding_inputs(work_dir: &Path, harness_id: &str, dest: &Path) -> usize {
    let mut copied = 0;
    let Ok(entries) = std::fs::read_dir(corpus::layout::findings_dir(work_dir)) else {
        return 0;
    };
    let mut dirs: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    dirs.sort();
    for dir in dirs {
        let Some(raw) = std::fs::read(dir.join("finding.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        else {
            continue;
        };
        if raw.get("harness_id").and_then(Value::as_str) != Some(harness_id) {
            continue;
        }
        // The suite runs each harness's own build: a finding of another
        // build (the MSan, TSan, CFI or RealtimeSanitizer replay's) would
        // pass there whether or not its bug is fixed.
        let fixture = raw.get("fixture_path").and_then(Value::as_str);
        if fixture.is_some_and(|fixture| {
            Path::new(fixture)
                .file_stem()
                .is_some_and(|name| name != "main")
        }) {
            continue;
        }
        let Some(input) = ["min_testcase.bin", "testcase.bin"]
            .iter()
            .map(|name| dir.join(name))
            .find(|path| path.is_file())
        else {
            continue;
        };
        let id = raw
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| Some(dir.file_name()?.to_string_lossy().into_owned()))
            .unwrap_or_default();
        if std::fs::create_dir_all(dest).is_ok()
            && std::fs::copy(&input, dest.join(format!("{id}.bin"))).is_ok()
        {
            copied += 1;
        }
    }
    copied
}

/// Copy at most `max` of the corpus inputs of `harness_id` into `dest`, the
/// smallest first. Returns how many.
pub(crate) fn copy_corpus(work_dir: &Path, harness_id: &str, dest: &Path, max: usize) -> usize {
    let queue = work_dir.join("corpus").join(harness_id).join("queue");
    let mut inputs: Vec<(u64, PathBuf)> = std::fs::read_dir(&queue)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .map(|path| (path.metadata().map(|m| m.len()).unwrap_or(0), path))
                .collect()
        })
        .unwrap_or_default();
    inputs.sort();
    let mut copied = 0;
    for (_, input) in inputs.into_iter().take(max) {
        let Some(name) = input.file_name() else {
            continue;
        };
        if std::fs::create_dir_all(dest).is_ok() && std::fs::copy(&input, dest.join(name)).is_ok() {
            copied += 1;
        }
    }
    copied
}

/// A harness's source files: generated C/C++ and headers, its Makefile, and
/// the stubs bhf wrote under `repairs/`. No binaries, objects or maps.
fn is_harness_source(path: &Path) -> bool {
    if path.file_name().is_some_and(|name| name == "Makefile") {
        return true;
    }
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension,
                "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" | "inc" | "def" | "S"
            )
        })
}

fn copy_sources(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|error| format!("create {}: {error}", to.display()))?;
    for entry in std::fs::read_dir(from)
        .map_err(|error| format!("read {}: {error}", from.display()))?
        .flatten()
    {
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if path.is_dir() {
            if entry.file_name() == "repairs" || from.ends_with("repairs") {
                copy_sources(&path, &dest)?;
            }
        } else if is_harness_source(&path) {
            std::fs::copy(&path, &dest)
                .map_err(|error| format!("copy {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

/// The C runtime directory a harness Makefile builds bhf's driver from
/// (`BHF_DRIVER_SOURCE ?= <dir>/bhf_driver.c`).
fn makefile_runtime_dir(makefile: &str) -> Option<PathBuf> {
    makefile.lines().find_map(|line| {
        let value = line.trim().strip_prefix("BHF_DRIVER_SOURCE ?=")?.trim();
        Path::new(value).parent().map(Path::to_path_buf)
    })
}

/// `text` with each of `from` replaced by its `to`, longest first so a
/// prefix of another is not replaced inside it.
fn replace_paths(text: &str, replacements: &[(String, String)]) -> String {
    let mut ordered: Vec<&(String, String)> = replacements
        .iter()
        .filter(|(from, _)| !from.is_empty())
        .collect();
    ordered.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    let mut out = text.to_owned();
    for (from, to) in ordered {
        out = out.replace(from.as_str(), to.as_str());
    }
    out
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn export_c(args: &RegressionArgs, source_root: &Path) -> Result<Exported, String> {
    let harnesses = harness_dirs(&args.work_dir, &["main.c", "main.cpp"]);
    let mut exported = Exported::default();
    let mut runtime_copied = false;
    for (id, dir) in &harnesses {
        let makefile_path = dir.join("Makefile");
        let Ok(makefile) = std::fs::read_to_string(&makefile_path) else {
            continue;
        };
        let dest = args.out.join("harnesses").join(id);
        copy_sources(dir, &dest)?;
        let runtime = makefile_runtime_dir(&makefile);
        if let (Some(runtime), false) = (&runtime, runtime_copied) {
            copy_sources(runtime, &args.out.join("c_runtime"))?;
            runtime_copied = true;
        }
        let harness_abs = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
        let mut replacements = vec![
            (
                source_root.display().to_string(),
                "$(SOURCE_ROOT)".to_owned(),
            ),
            (harness_abs.display().to_string(), "$(CURDIR)".to_owned()),
            (dir.display().to_string(), "$(CURDIR)".to_owned()),
        ];
        if let Some(runtime) = &runtime {
            replacements.push((
                runtime.display().to_string(),
                "$(SUITE_DIR)/c_runtime".to_owned(),
            ));
        }
        let header = format!(
            "# bhf regression suite: SOURCE_ROOT is the scanned tree (override it for\n\
             # another checkout), SUITE_DIR the suite's root.\n\
             SOURCE_ROOT ?= {}\n\
             SUITE_DIR ?= $(abspath $(CURDIR)/../..)\n",
            source_root.display()
        );
        std::fs::write(
            dest.join("Makefile"),
            format!("{header}{}", replace_paths(&makefile, &replacements)),
        )
        .map_err(|error| format!("write {}: {error}", dest.join("Makefile").display()))?;

        // The build context bhf recovered for the harness's `main` build.
        let recipe: Value = std::fs::read(dir.join("coverage-build-recipe.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        let words = |key: &str, prefix: &str| -> String {
            recipe
                .get(key)
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|value| {
                            format!(
                                "{prefix}{}",
                                value.replace(&source_root.display().to_string(), "${SOURCE_ROOT}")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        };
        let env = format!(
            "# The build context bhf recovered for this harness (sourced by run.sh).\n\
             AUTO_EXTRA_SOURCES=\"{}\"\n\
             AUTO_EXTRA_INCLUDES=\"{}\"\n\
             AUTO_EXTRA_LDFLAGS=\"{}\"\n\
             BHF_EXTRA_CFLAGS=\"{}\"\n",
            words("extra_sources", ""),
            words("extra_includes", "-I "),
            words("extra_ldflags", ""),
            words("extra_compile_flags", ""),
        );
        std::fs::write(dest.join("build.env"), env)
            .map_err(|error| format!("write {}: {error}", dest.join("build.env").display()))?;

        exported.findings +=
            copy_finding_inputs(&args.work_dir, id, &dest.join("inputs").join("findings"));
        exported.corpus += copy_corpus(
            &args.work_dir,
            id,
            &dest.join("inputs").join("corpus"),
            args.max_corpus,
        );
        exported.harnesses += 1;
    }
    if exported.harnesses > 0 {
        write_c_runner(&args.out, source_root)?;
    }
    Ok(exported)
}

fn write_c_runner(out: &Path, source_root: &Path) -> Result<(), String> {
    let script = format!(
        "#!/bin/sh\n\
         # SPDX-License-Identifier: Apache-2.0\n\
         # bhf regression suite: build each harness against the scanned tree and run\n\
         # every input. An input that crashes (a finding's, until its bug is fixed, or\n\
         # a corpus input that has started to) fails the suite.\n\
         #\n\
         #   SOURCE_ROOT=<checkout> ./run.sh\n\
         set -u\n\
         SUITE_DIR=$(cd \"$(dirname \"$0\")\" && pwd)\n\
         SOURCE_ROOT=${{SOURCE_ROOT:-{root}}}\n\
         export SUITE_DIR SOURCE_ROOT\n\
         ASAN_OPTIONS=\"${{ASAN_OPTIONS:-}}:abort_on_error=1:halt_on_error=1:detect_leaks=1:symbolize=1\"\n\
         UBSAN_OPTIONS=\"${{UBSAN_OPTIONS:-}}:abort_on_error=1:halt_on_error=1:print_stacktrace=1\"\n\
         export ASAN_OPTIONS UBSAN_OPTIONS\n\
         failed=0\n\
         ran=0\n\
         for harness in \"$SUITE_DIR\"/harnesses/*/; do\n\
         \x20 id=$(basename \"$harness\")\n\
         \x20 (\n\
         \x20   . \"$harness/build.env\"\n\
         \x20   CFLAGS=\"${{CFLAGS:-}} $BHF_EXTRA_CFLAGS\"\n\
         \x20   export AUTO_EXTRA_SOURCES AUTO_EXTRA_INCLUDES AUTO_EXTRA_LDFLAGS CFLAGS\n\
         \x20   # -B: the Makefile does not list the tree's sources as prerequisites.\n\
         \x20   make -s -B -C \"$harness\" main >\"$harness/build.log\" 2>&1\n\
         \x20 ) || {{ echo \"BUILD FAILED $id (see $harness/build.log)\"; failed=1; continue; }}\n\
         \x20 for input in \"$harness\"inputs/findings/* \"$harness\"inputs/corpus/*; do\n\
         \x20   [ -f \"$input\" ] || continue\n\
         \x20   ran=$((ran + 1))\n\
         \x20   kind=$(basename \"$(dirname \"$input\")\")\n\
         \x20   if \"$harness/main\" \"$input\" >/dev/null 2>\"$harness/last.log\"; then\n\
         \x20     echo \"pass $id $kind/$(basename \"$input\")\"\n\
         \x20   else\n\
         \x20     echo \"FAIL $id $kind/$(basename \"$input\") (exit $?; $harness/last.log)\"\n\
         \x20     cp \"$harness/last.log\" \"$harness/$(basename \"$input\").log\"\n\
         \x20     failed=1\n\
         \x20   fi\n\
         \x20 done\n\
         done\n\
         echo \"$ran input(s) run\"\n\
         exit $failed\n",
        root = shell_quote(&source_root.display().to_string()),
    );
    let path = out.join("run.sh");
    std::fs::write(&path, script).map_err(|error| format!("write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::write(
        out.join("README.md"),
        "# bhf regression suite\n\n\
         `bhf export regression` wrote this suite from a bhf work directory. Each\n\
         directory under `harnesses/` is one harness: its sources and Makefile, the\n\
         build context bhf recovered for it (`build.env`), its corpus\n\
         (`inputs/corpus/`) and the minimized input of each finding\n\
         (`inputs/findings/<finding id>.bin`). `c_runtime/` is bhf's C runtime the\n\
         harnesses link.\n\n\
         `./run.sh` builds every harness against the scanned tree and runs every\n\
         input; it exits non-zero when one crashes. Point it at another checkout of\n\
         the tree with `SOURCE_ROOT=<dir> ./run.sh`.\n",
    )
    .map_err(|error| format!("write README.md: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_longest_path_is_replaced_first() {
        let text = "-I /w/src/inc -I /w/src";
        let out = replace_paths(
            text,
            &[
                ("/w/src".to_owned(), "$(SOURCE_ROOT)".to_owned()),
                ("/w/src/inc".to_owned(), "$(INC)".to_owned()),
            ],
        );
        assert_eq!(out, "-I $(INC) -I $(SOURCE_ROOT)");
        assert_eq!(
            makefile_runtime_dir("X = 1\nBHF_DRIVER_SOURCE ?= /opt/bhf/c_runtime/bhf_driver.c\n"),
            Some(PathBuf::from("/opt/bhf/c_runtime"))
        );
        assert!(is_harness_source(Path::new("main.c")));
        assert!(is_harness_source(Path::new("Makefile")));
        assert!(!is_harness_source(Path::new("main")));
        assert!(!is_harness_source(Path::new("coverage.shm")));
    }
}
