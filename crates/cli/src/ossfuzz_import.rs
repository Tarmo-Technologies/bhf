// SPDX-License-Identifier: Apache-2.0

//! `bhf project import-ossfuzz` — build a project's existing OSS-Fuzz (or
//! ClusterFuzzLite) integration and collect the fuzzers its `build.sh`
//! produces.
//!
//! OSS-Fuzz's build contract, which this reproduces: `build.sh` runs as
//! `bash -eux $SRC/build.sh` from the project's checkout (`$SRC/<name>`, the
//! Dockerfile's `WORKDIR`), compiles with `$CC`/`$CXX` and `$CFLAGS`/
//! `$CXXFLAGS`, links each fuzz target with `$LIB_FUZZING_ENGINE` and leaves
//! the targets in `$OUT`, keeping intermediate files in `$WORK`. Here:
//!
//! - `$SRC`, `$WORK` and `$OUT` are `<work>/ossfuzz/{src,work,out}`, emptied
//!   before every import. The source tree is copied to `$SRC/<name>`, so the
//!   build never writes into the operator's checkout.
//! - `$CC`/`$CXX` are clang, and `$CFLAGS`/`$CXXFLAGS` OSS-Fuzz's address
//!   build with the SanitizerCoverage bhf's driver reads (`trace-pc-guard`,
//!   `trace-cmp`) in place of libFuzzer's `fuzzer-no-link`.
//! - `$LIB_FUZZING_ENGINE` is an archive of bhf's own driver
//!   (`c_runtime/bhf_driver.c`, the framed fork-server `main` and coverage
//!   runtime every generated C harness links) and a `bhf_run_one` that calls
//!   the target's `LLVMFuzzerTestOneInput`, so each fuzzer the build links
//!   is a bhf harness the builtin engine drives with coverage.
//! - `build.sh` runs in a sandbox: bubblewrap or firejail, with no network
//!   and with every path outside `$SRC`, `$WORK` and `$OUT` read-only (or,
//!   under bubblewrap, absent), `/tmp` included: `$TMPDIR` is `$WORK/tmp`.
//!   The environment is cleared to the build contract's variables, so no
//!   host secret reaches the build. A host with
//!   neither tool, or with one that cannot isolate the network, is refused
//!   with what to install; `--sandbox none` runs the build directly, which
//!   is the operator's explicit choice.
//!
//! The fuzzers are found in `$OUT` the way OSS-Fuzz's `get_fuzz_targets`
//! finds them: a regular, executable file named `[A-Za-z0-9_-]+` (with no
//! extension or `.exe`), not `jazzer_driver*`, whose name ends in `_fuzzer`
//! or whose bytes contain `LLVMFuzzerTestOneInput`.
//!
//! Each fuzzer is then registered as a harness of the work dir, under its
//! name: staged at `<work>/build/<name>/main`, where `bhf fuzz <work>
//! --harness <name>` finds it, with the framed input mode declared beside a
//! fuzzer linked with bhf's driver. Every fuzzer is also a target of a
//! `bhf.project.v1` manifest, `<work>/ossfuzz/bhf.project.toml`, for
//! `bhf project run`: `engine = "builtin"` for one linked with bhf's driver,
//! and `engine = "binary"` with `input-mode = "file"` for a libFuzzer binary
//! the build linked without it (`-fsanitize=fuzzer` in place of
//! `$LIB_FUZZING_ENGINE`), which runs one input file per process.
//!
//! What OSS-Fuzz keeps beside a fuzzer in `$OUT` comes with it:
//! `<name>_seed_corpus.zip` is unpacked, with the system `unzip` (bhf takes
//! no zip library for it), into `<work>/ossfuzz/seeds/<name>`, the target's
//! seeds; `<name>.dict` and the dictionary its `.options` names are merged
//! into the harness's `dictionary.txt`, which `bhf fuzz` loads, and are the
//! target's dictionaries; and the `[libfuzzer]` options bhf has an
//! equivalent for (`max_len`, `timeout`, `rss_limit_mb`) set the target's
//! `max-len`, `timeout` and `rss-limit-mb`. Every other option is reported
//! as not applied.

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;

use crate::protocol_detect::{self, HarnessProtocol};
use crate::runner::SandboxModeArg;

/// The import record written to `<work>/ossfuzz/import.json`.
const IMPORT_SCHEMA: &str = "bhf.ossfuzz-import.v1";

/// The `bhf.project.v1` manifest the import writes in `<work>/ossfuzz/`.
const MANIFEST_FILE: &str = "bhf.project.toml";

/// What OSS-Fuzz's fuzzer search looks for in a binary.
const FUZZ_TARGET_MARKER: &[u8] = b"LLVMFuzzerTestOneInput";

/// The `$CFLAGS` and `$CXXFLAGS` `build.sh` gets: OSS-Fuzz's base flags and
/// its address-sanitizer flags, with the coverage bhf's driver reads.
const BASE_FLAGS: &str =
    "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION";
const SANITIZER_FLAGS: &str = "-fsanitize=address -fsanitize-address-use-after-scope";
const COVERAGE_FLAGS: &str = "-fsanitize-coverage=trace-pc-guard,trace-cmp";

/// The `bhf_run_one` bhf's driver calls for each input, forwarding it to the
/// fuzz target's libFuzzer entry point. `bhf_target_enter` marks the entry
/// into the target, as a generated passthrough harness's `bhf_run_one` does.
const ENGINE_ENTRY_SOURCE: &str = "\
/* SPDX-License-Identifier: Apache-2.0 */
/* Written by bhf project import-ossfuzz: bhf's driver calls bhf_run_one for
 * every input; forward it to the OSS-Fuzz target's entry point. */
#include <stddef.h>
#include <stdint.h>
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
extern void bhf_target_enter(void);
int bhf_run_one(const uint8_t *Data, size_t Size) {
    bhf_target_enter();
    return LLVMFuzzerTestOneInput(Data, Size);
}
";

/// `bhf project import-ossfuzz <PROJECT>`.
#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// The directory holding the OSS-Fuzz `build.sh`: an OSS-Fuzz
    /// `projects/<name>/` directory (pass the checkout it builds with
    /// --src), or a source tree with its own `build.sh` or
    /// `.clusterfuzzlite/build.sh`.
    project: PathBuf,
    /// The source tree `build.sh` builds, copied to `$SRC/<name>` (the
    /// directory `build.sh` runs in). Default: PROJECT.
    #[arg(long)]
    src: Option<PathBuf>,
    /// The build script. Default: PROJECT/build.sh, else
    /// PROJECT/.clusterfuzzlite/build.sh.
    #[arg(long = "build-script")]
    build_script: Option<PathBuf>,
    /// The project name, which names `$SRC/<name>`. Default: the source
    /// tree's directory name.
    #[arg(long)]
    name: Option<String>,
    /// Work directory; the build runs under `<work>/ossfuzz/`.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    work_dir: PathBuf,
    /// The sandbox `build.sh` runs in. `auto` uses bubblewrap, else firejail,
    /// and refuses to run the build when neither can isolate it; `none` runs
    /// it directly.
    #[arg(long, value_enum, default_value_t = SandboxModeArg::Auto)]
    sandbox: SandboxModeArg,
    /// The bubblewrap or firejail executable to use.
    #[arg(long = "sandbox-tool", value_name = "PATH")]
    sandbox_tool: Option<PathBuf>,
    /// Print the import record as JSON on stdout.
    #[arg(long)]
    json: bool,
}

/// The directories of one import under `<work>/ossfuzz/`.
struct Layout {
    root: PathBuf,
    src: PathBuf,
    work: PathBuf,
    out: PathBuf,
    engine: PathBuf,
    /// The unpacked seed corpora, `<seeds>/<name>`.
    seeds: PathBuf,
}

impl Layout {
    fn new(work_dir: &Path) -> Self {
        let root = work_dir.join("ossfuzz");
        Self {
            src: root.join("src"),
            work: root.join("work"),
            out: root.join("out"),
            engine: root.join("engine"),
            seeds: root.join("seeds"),
            root,
        }
    }

    /// Empty `$SRC`, `$WORK`, `$OUT`, the engine dir and the seeds, as a
    /// fresh OSS-Fuzz build container starts. Only these bhf-owned
    /// directories are removed.
    fn reset(&self) -> Result<()> {
        for dir in [&self.src, &self.work, &self.out, &self.engine, &self.seeds] {
            if dir.exists() {
                fs::remove_dir_all(dir).with_context(|| format!("empty '{}'", dir.display()))?;
            }
            fs::create_dir_all(dir).with_context(|| format!("create '{}'", dir.display()))?;
        }
        // A private temporary directory in `$WORK`: TMPDIR points here, so
        // the compilers' scratch files never need a writable /tmp.
        fs::create_dir_all(self.work.join("tmp")).context("create $WORK/tmp")?;
        // The record and manifest of the import this one replaces.
        for stale in [self.root.join("import.json"), self.root.join(MANIFEST_FILE)] {
            if stale.exists() {
                fs::remove_file(&stale).with_context(|| format!("remove '{}'", stale.display()))?;
            }
        }
        Ok(())
    }

    /// The directories `build.sh` may write: `$SRC`, `$WORK` and `$OUT`.
    fn writable(&self) -> [&Path; 3] {
        [&self.src, &self.work, &self.out]
    }

    /// Create the directories the sandbox mounts, keeping what is in them,
    /// so the sandbox can be probed before an earlier import is emptied.
    fn create(&self) -> Result<()> {
        for dir in self.writable().into_iter().chain([self.engine.as_path()]) {
            fs::create_dir_all(dir).with_context(|| format!("create '{}'", dir.display()))?;
        }
        Ok(())
    }
}

/// The sandbox `build.sh` runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BuildSandbox {
    Bubblewrap(PathBuf),
    Firejail(PathBuf),
    /// `--sandbox none`: the build runs directly.
    None,
}

impl BuildSandbox {
    fn label(&self) -> &'static str {
        match self {
            Self::Bubblewrap(_) => "bubblewrap",
            Self::Firejail(_) => "firejail",
            Self::None => "none",
        }
    }

    fn tool(&self) -> Option<&Path> {
        match self {
            Self::Bubblewrap(tool) | Self::Firejail(tool) => Some(tool),
            Self::None => None,
        }
    }
}

/// The host programs the build needs.
struct Tools {
    bash: PathBuf,
    cc: PathBuf,
    cxx: PathBuf,
    ar: PathBuf,
}

/// A fuzzer the build left in `$OUT`.
struct Fuzzer {
    name: String,
    path: PathBuf,
    protocol: HarnessProtocol,
}

/// How bhf runs an imported fuzzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    /// Linked with bhf's driver: the builtin engine drives it through the
    /// framed protocol, with coverage.
    Builtin,
    /// Anything else, such as a libFuzzer binary without bhf's driver: the
    /// binary lane runs it on one input file per process.
    BinaryFile,
}

impl Lane {
    fn of(fuzzer: &Fuzzer) -> Self {
        if fuzzer.protocol == HarnessProtocol::BhfFramed
            && !protocol_detect::libfuzzer_without_bhf_driver(&fuzzer.path)
        {
            Self::Builtin
        } else {
            Self::BinaryFile
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Builtin => "bhf driver",
            Self::BinaryFile => "no bhf driver: one input file per process",
        }
    }
}

/// A fuzzer registered as a harness of the work dir.
struct Registered<'a> {
    fuzzer: &'a Fuzzer,
    lane: Lane,
    /// `<work>/build/<name>/main`.
    harness: PathBuf,
    extras: Extras,
}

/// What the import took from the seed corpus, dictionaries and `.options`
/// OSS-Fuzz keeps beside a fuzzer.
#[derive(Debug, Default, PartialEq, Eq)]
struct Extras {
    /// `<work>/ossfuzz/seeds/<name>`, unpacked from `<name>_seed_corpus.zip`,
    /// and the number of seed files in it.
    seeds: Option<(PathBuf, usize)>,
    /// `<name>.dict` and the dictionary the `.options` file names, in that
    /// order, merged into the harness's `dictionary.txt`.
    dictionaries: Vec<PathBuf>,
    /// The merged dictionary's token count.
    tokens: usize,
    options: FuzzerOptions,
    /// What was not applied, and why.
    notes: Vec<String>,
}

/// The `[libfuzzer]` options of a `.options` file that bhf applies.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FuzzerOptions {
    max_len: Option<u64>,
    timeout_secs: Option<u64>,
    rss_limit_mb: Option<u64>,
    /// The dictionary to use, relative to the fuzzer's directory.
    dict: Option<String>,
}

impl FuzzerOptions {
    /// The `bhf fuzz` flags these options are.
    fn fuzz_flags(&self) -> String {
        let mut flags = String::new();
        if let Some(max_len) = self.max_len {
            flags.push_str(&format!(" --max-len {max_len}"));
        }
        if let Some(timeout) = self.timeout_secs {
            flags.push_str(&format!(" --timeout {timeout}s"));
        }
        if let Some(rss) = self.rss_limit_mb {
            flags.push_str(&format!(" --rss-limit-mb {rss}"));
        }
        flags
    }
}

/// Run `bhf project import-ossfuzz`.
pub(crate) fn run(args: &ImportArgs) -> Result<()> {
    let project = fs::canonicalize(&args.project)
        .with_context(|| format!("project directory '{}'", args.project.display()))?;
    let build_script = find_build_script(&project, args.build_script.as_deref())?;
    let source = match &args.src {
        Some(src) => {
            fs::canonicalize(src).with_context(|| format!("source tree '{}'", src.display()))?
        }
        None => project.clone(),
    };
    if !source.is_dir() {
        bail!("source tree '{}' is not a directory", source.display());
    }
    let name = match &args.name {
        Some(name) => name.clone(),
        None => source
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("name the project with --name"))?,
    };
    check_name(&name)?;

    fs::create_dir_all(&args.work_dir)
        .with_context(|| format!("create work dir '{}'", args.work_dir.display()))?;
    let work_dir = fs::canonicalize(&args.work_dir)
        .with_context(|| format!("work dir '{}'", args.work_dir.display()))?;
    if work_dir == source || source.starts_with(&work_dir) {
        bail!(
            "the work dir '{}' must not be the source tree or hold it",
            work_dir.display()
        );
    }
    let layout = Layout::new(&work_dir);
    layout.create()?;

    // The sandbox is resolved, and probed with the real mounts, before
    // anything of the project is staged (or an earlier import emptied), so a
    // host that cannot isolate the build never runs any of it.
    let sandbox = resolve_sandbox(args.sandbox, args.sandbox_tool.as_deref(), &layout)?;
    layout.reset()?;
    if sandbox == BuildSandbox::None {
        bhfeprintln!(
            "bhf project import-ossfuzz: warning: --sandbox none: build.sh runs without \
             isolation, with this user's network and file access"
        );
    }
    let tools = resolve_tools()?;
    let engine = build_engine(&layout, &tools)?;

    let project_dir = layout.src.join(&name);
    copy_tree(&source, &project_dir, &work_dir)
        .with_context(|| format!("copy '{}' to $SRC", source.display()))?;
    let staged_script = layout.src.join("build.sh");
    fs::copy(&build_script, &staged_script)
        .with_context(|| format!("copy '{}' to $SRC", build_script.display()))?;

    let env = build_env(&layout, &tools, &engine);
    let log = layout.root.join("build.log");
    bhfeprintln!(
        "bhf project import-ossfuzz: running {} in {} (SRC={}, WORK={}, OUT={}); log: {}",
        build_script.display(),
        match sandbox.tool() {
            Some(tool) => format!("{} ({})", sandbox.label(), tool.display()),
            None => "no sandbox".to_owned(),
        },
        layout.src.display(),
        layout.work.display(),
        layout.out.display(),
        log.display()
    );
    run_build_script(&sandbox, &layout, &project_dir, &tools, &env, &log)?;

    let fuzzers = collect_fuzzers(&layout.out)?;
    if fuzzers.is_empty() {
        bail!(
            "build.sh finished but left no fuzzer in $OUT ({}): OSS-Fuzz takes an \
             executable whose name ends in `_fuzzer` or that defines \
             LLVMFuzzerTestOneInput",
            layout.out.display()
        );
    }

    let mut registered = fuzzers
        .iter()
        .map(|fuzzer| register(&work_dir, fuzzer))
        .collect::<Result<Vec<_>>>()?;
    unpack_seed_corpora(&layout, &mut registered)?;
    for entry in &mut registered {
        apply_dictionaries_and_options(&layout, &work_dir, entry)?;
        for note in &entry.extras.notes {
            bhfeprintln!(
                "bhf project import-ossfuzz: note: {}: {note}",
                entry.fuzzer.name
            );
        }
    }
    let manifest = write_manifest(&layout, &name, &registered)?;

    let record = json!({
        "schema": IMPORT_SCHEMA,
        "project": name,
        "build_script": build_script,
        "source": source,
        "sandbox": { "mode": sandbox.label(), "tool": sandbox.tool() },
        "env": env.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
        "src": layout.src,
        "work": layout.work,
        "out": layout.out,
        "build_log": log,
        "manifest": manifest,
        "fuzzers": registered.iter().map(|entry| json!({
            "name": entry.fuzzer.name,
            "binary": entry.fuzzer.path,
            "protocol": entry.fuzzer.protocol.label(),
            "harness": entry.harness,
            "engine": match entry.lane {
                Lane::Builtin => "builtin",
                Lane::BinaryFile => "binary",
            },
            "seeds": entry.extras.seeds.as_ref().map(|(dir, files)| json!({
                "dir": dir,
                "files": files,
            })),
            "dictionaries": entry.extras.dictionaries,
            "dictionary_tokens": entry.extras.tokens,
            "options": {
                "max_len": entry.extras.options.max_len,
                "timeout_secs": entry.extras.options.timeout_secs,
                "rss_limit_mb": entry.extras.options.rss_limit_mb,
            },
            "notes": entry.extras.notes,
        })).collect::<Vec<_>>(),
    });
    let record_text = serde_json::to_string_pretty(&record)?;
    fs::write(layout.root.join("import.json"), &record_text).context("write import.json")?;

    if args.json {
        println!("{record_text}");
    } else {
        print_listing(&name, &work_dir, &manifest, &registered);
    }
    Ok(())
}

/// The registered fuzzers, what came with them, and how to run them.
fn print_listing(name: &str, work_dir: &Path, manifest: &Path, registered: &[Registered]) {
    println!(
        "project '{name}': build.sh produced {} fuzzer(s), registered as harnesses of {}:",
        registered.len(),
        work_dir.display()
    );
    let width = registered
        .iter()
        .map(|entry| entry.fuzzer.name.len())
        .max()
        .unwrap_or(0);
    for entry in registered {
        println!(
            "  {:width$}  {}  [{}]",
            entry.fuzzer.name,
            entry.harness.display(),
            entry.lane.label()
        );
        let extras = &entry.extras;
        let mut taken = Vec::new();
        if let Some((dir, files)) = &extras.seeds {
            taken.push(format!("{files} seed(s) in {}", dir.display()));
        }
        if extras.tokens > 0 {
            taken.push(format!(
                "{} dictionary token(s) from {}",
                extras.tokens,
                extras
                    .dictionaries
                    .iter()
                    .filter_map(|path| path.file_name())
                    .map(|name| name.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let flags = extras.options.fuzz_flags();
        if !flags.is_empty() {
            taken.push(format!("options{flags}"));
        }
        if !taken.is_empty() {
            println!("  {:width$}  {}", "", taken.join("; "));
        }
    }
    // The example: the first fuzzer that came with something, else the first.
    let example = registered
        .iter()
        .find(|entry| entry.extras != Extras::default())
        .unwrap_or(&registered[0]);
    println!("fuzz one with its seeds, dictionary and options:");
    println!(
        "  bhf project run --manifest {} --target {} --work-dir {}",
        manifest.display(),
        example.fuzzer.name,
        work_dir.display()
    );
    let builtin = std::iter::once(example)
        .chain(registered)
        .find(|entry| entry.lane == Lane::Builtin);
    if let Some(entry) = builtin {
        println!("or with its dictionary and options (add each seed with --seed-file):");
        println!(
            "  bhf fuzz {} --harness {} --time 60s{}",
            work_dir.display(),
            entry.fuzzer.name,
            entry.extras.options.fuzz_flags()
        );
    }
}

/// Stage `fuzzer` as the harness `<work>/build/<name>/main`, declaring the
/// framed input mode beside one linked with bhf's driver.
fn register<'a>(work_dir: &Path, fuzzer: &'a Fuzzer) -> Result<Registered<'a>> {
    let lane = Lane::of(fuzzer);
    let dir = work_dir.join("build").join(&fuzzer.name);
    fs::create_dir_all(&dir).with_context(|| format!("create '{}'", dir.display()))?;
    let harness = dir.join("main");
    fs::copy(&fuzzer.path, &harness).with_context(|| {
        format!(
            "register '{}' as '{}'",
            fuzzer.path.display(),
            harness.display()
        )
    })?;
    make_executable(&harness)?;
    let sidecar = dir.join(protocol_detect::PROTOCOL_SIDECAR);
    match lane {
        Lane::Builtin => protocol_detect::write_declared_input_mode(
            &dir,
            "framed",
            "OSS-Fuzz build.sh linked with bhf's driver (bhf project import-ossfuzz)",
        )
        .context("record the fuzzer's input mode")?,
        // A fuzzer that lost bhf's driver since an earlier import must not
        // keep that import's declaration.
        Lane::BinaryFile => {
            if sidecar.exists() {
                fs::remove_file(&sidecar)
                    .with_context(|| format!("remove '{}'", sidecar.display()))?;
            }
        }
    }
    Ok(Registered {
        fuzzer,
        lane,
        harness,
        extras: Extras::default(),
    })
}

/// Whether `path` is a regular file, not a symlink that could name a file
/// outside `$OUT`.
fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Unpack each fuzzer's `<name>_seed_corpus.zip` into
/// `<work>/ossfuzz/seeds/<name>` with the system `unzip`.
fn unpack_seed_corpora(layout: &Layout, registered: &mut [Registered]) -> Result<()> {
    let corpora: Vec<(usize, PathBuf)> = registered
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let zip = entry
                .fuzzer
                .path
                .with_file_name(format!("{}_seed_corpus.zip", entry.fuzzer.name));
            (index, zip)
        })
        .filter(|(_, zip)| regular_file(zip))
        .collect();
    if corpora.is_empty() {
        return Ok(());
    }
    let unzip = program_on_path("unzip").ok_or_else(|| {
        anyhow!(
            "`unzip` is not on PATH: bhf unpacks OSS-Fuzz seed corpora with the system \
             `unzip`, and the build left {}. Install it (e.g. `apt-get install unzip`) \
             and import again",
            corpora
                .iter()
                .filter_map(|(_, zip)| zip.file_name())
                .map(|name| name.to_string_lossy())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    for (index, zip) in corpora {
        let entry = &mut registered[index];
        let dir = layout.seeds.join(&entry.fuzzer.name);
        let files = unpack_seeds(&unzip, &zip, &dir)?;
        if files == 0 {
            entry.extras.notes.push(format!(
                "{} holds no seed file",
                zip.file_name().unwrap_or_default().to_string_lossy()
            ));
        } else {
            entry.extras.seeds = Some((dir, files));
        }
    }
    Ok(())
}

/// Unpack `zip` into `dir` with `unzip`, which keeps every entry inside `dir`
/// (it drops `../` components and a leading `/`). A symlink or other special
/// file it restores is removed: a seed is a regular file, and a symlink could
/// name a host file. Returns the number of seed files.
fn unpack_seeds(unzip: &Path, zip: &Path, dir: &Path) -> Result<usize> {
    fs::create_dir_all(dir).with_context(|| format!("create '{}'", dir.display()))?;
    let output = Command::new(unzip)
        .args(["-qq", "-o"])
        .arg(zip)
        .arg("-d")
        .arg(dir)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("start '{}'", unzip.display()))?;
    // 1 is unzip's exit status for warnings, such as an empty archive.
    if !matches!(output.status.code(), Some(0 | 1)) {
        bail!(
            "unzip could not unpack '{}' ({}): {}",
            zip.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    fn prune(dir: &Path, files: &mut usize) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                prune(&entry.path(), files)?;
            } else if kind.is_file() {
                *files += 1;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
    let mut files = 0;
    prune(dir, &mut files).with_context(|| format!("read '{}'", dir.display()))?;
    Ok(files)
}

/// Read an OSS-Fuzz `.options` file, an INI file as ClusterFuzz reads it:
/// the `[libfuzzer]` options bhf has an equivalent for, and a note for every
/// other line, so none is dropped without a word.
fn parse_options(text: &str) -> (FuzzerOptions, Vec<String>) {
    let mut options = FuzzerOptions::default();
    let mut notes = Vec::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=').or_else(|| line.split_once(':')) else {
            notes.push(format!(
                "`{line}` is not a `key = value` line, and is ignored"
            ));
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let number = value.parse::<u64>().ok();
        let slot = match (section.as_str(), key) {
            ("libfuzzer", "max_len") => &mut options.max_len,
            ("libfuzzer", "timeout") => &mut options.timeout_secs,
            ("libfuzzer", "rss_limit_mb") => &mut options.rss_limit_mb,
            ("libfuzzer", "dict") => {
                options.dict = Some(value.to_owned());
                continue;
            }
            _ => {
                notes.push(format!(
                    "[{section}] {key} = {value} is not applied: bhf has no equivalent"
                ));
                continue;
            }
        };
        match number {
            Some(number) => *slot = Some(number),
            None => notes.push(format!(
                "[{section}] {key} = {value} is not applied: not a whole number"
            )),
        }
    }
    (options, notes)
}

/// The file a `.options` file's `dict` names, relative to the fuzzer's
/// directory, or `None` when that would leave `$OUT`.
fn option_dictionary(out: &Path, fuzzer_dir: &Path, dict: &str) -> Option<PathBuf> {
    let relative = Path::new(dict);
    let plain = relative.components().all(|part| {
        matches!(
            part,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    });
    let path = fuzzer_dir.join(relative);
    (plain && path.starts_with(out)).then_some(path)
}

/// Read the fuzzer's `.options`, merge `<name>.dict` and the dictionary the
/// options name into the harness's `dictionary.txt`, and note what is not
/// applied.
fn apply_dictionaries_and_options(
    layout: &Layout,
    work_dir: &Path,
    entry: &mut Registered,
) -> Result<()> {
    let name = &entry.fuzzer.name;
    let fuzzer_dir = entry.fuzzer.path.parent().unwrap_or(&layout.out);
    let extras = &mut entry.extras;
    let options_path = fuzzer_dir.join(format!("{name}.options"));
    if regular_file(&options_path) {
        match fs::read_to_string(&options_path) {
            Ok(text) => {
                let (options, notes) = parse_options(&text);
                extras.options = options;
                extras.notes.extend(
                    notes
                        .into_iter()
                        .map(|note| format!("{name}.options: {note}")),
                );
            }
            Err(error) => extras.notes.push(format!(
                "{name}.options could not be read ({error}); ignored"
            )),
        }
    }

    let mut candidates = Vec::new();
    let own = fuzzer_dir.join(format!("{name}.dict"));
    if regular_file(&own) {
        candidates.push(own);
    }
    if let Some(dict) = extras.options.dict.clone() {
        match option_dictionary(&layout.out, fuzzer_dir, &dict) {
            Some(path) if regular_file(&path) => {
                if !candidates.contains(&path) {
                    candidates.push(path);
                }
            }
            Some(_) => extras.notes.push(format!(
                "{name}.options: dict = {dict} names no file in $OUT"
            )),
            None => extras.notes.push(format!(
                "{name}.options: dict = {dict} is outside $OUT, and is ignored"
            )),
        }
    }
    // A dictionary bhf cannot read (not UTF-8, or past the size limit) is
    // left out with its reason, so `bhf project run` never trips on it.
    for path in candidates {
        match project_profile::merge_dictionaries(std::slice::from_ref(&path)) {
            Ok(_) => extras.dictionaries.push(path),
            Err(error) => extras
                .notes
                .push(format!("{error}; the dictionary is left out")),
        }
    }
    let merged = project_profile::merge_dictionaries(&extras.dictionaries)?;
    extras.tokens = merged.tokens.len();
    let dictionary = work_dir.join("build").join(name).join("dictionary.txt");
    if merged.tokens.is_empty() {
        if dictionary.exists() {
            fs::remove_file(&dictionary)
                .with_context(|| format!("remove '{}'", dictionary.display()))?;
        }
    } else {
        fs::write(&dictionary, merged.to_afl_format())
            .with_context(|| format!("write '{}'", dictionary.display()))?;
    }

    if entry.lane == Lane::BinaryFile {
        let options = &extras.options;
        let mut unapplied = Vec::new();
        if !extras.dictionaries.is_empty() {
            unapplied.push("its dictionaries");
        }
        if options.max_len.is_some() {
            unapplied.push("max_len");
        }
        if options.rss_limit_mb.is_some() {
            unapplied.push("rss_limit_mb");
        }
        if !unapplied.is_empty() {
            extras.notes.push(format!(
                "{} do(es) not apply to a binary-lane target in the manifest",
                unapplied.join(", ")
            ));
        }
    }
    Ok(())
}

/// `path`, under `<work>/ossfuzz/`, as the manifest names it.
fn manifest_path(layout: &Layout, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(&layout.root)
        .with_context(|| format!("'{}' is outside the import", path.display()))?;
    Ok(relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

/// Write `<work>/ossfuzz/bhf.project.toml`, one target per fuzzer, and check
/// that it loads and validates as `bhf project run` will load it.
fn write_manifest(layout: &Layout, name: &str, registered: &[Registered]) -> Result<PathBuf> {
    #[derive(serde::Serialize)]
    struct Doc<'a> {
        schema: &'a str,
        project: ProjectDoc<'a>,
        target: Vec<TargetDoc>,
    }
    #[derive(serde::Serialize)]
    struct ProjectDoc<'a> {
        id: &'a str,
        version: &'a str,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct TargetDoc {
        id: String,
        engine: &'static str,
        binary: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_mode: Option<&'static str>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        seeds: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dictionaries: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_len: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rss_limit_mb: Option<u64>,
    }

    let mut targets = Vec::with_capacity(registered.len());
    for entry in registered {
        let extras = &entry.extras;
        let options = &extras.options;
        let seeds = extras
            .seeds
            .iter()
            .map(|(dir, _)| manifest_path(layout, dir))
            .collect::<Result<Vec<_>>>()?;
        let mut target = TargetDoc {
            id: entry.fuzzer.name.clone(),
            engine: "builtin",
            binary: manifest_path(layout, &entry.fuzzer.path)?,
            input_mode: None,
            seeds,
            dictionaries: Vec::new(),
            max_len: None,
            timeout: None,
            timeout_ms: None,
            rss_limit_mb: None,
        };
        match entry.lane {
            Lane::Builtin => {
                target.dictionaries = extras
                    .dictionaries
                    .iter()
                    .map(|path| manifest_path(layout, path))
                    .collect::<Result<_>>()?;
                target.max_len = options.max_len.map(|n| n.to_string());
                target.timeout = options.timeout_secs.map(|n| format!("{n}s"));
                target.rss_limit_mb = options.rss_limit_mb;
            }
            Lane::BinaryFile => {
                target.engine = "binary";
                target.input_mode = Some("file");
                target.timeout_ms = options.timeout_secs.map(|n| n.saturating_mul(1000));
            }
        }
        targets.push(target);
    }
    let doc = Doc {
        schema: project_profile::SCHEMA_V1,
        project: ProjectDoc {
            id: name,
            version: "0",
        },
        target: targets,
    };
    let text = format!(
        "# Written by `bhf project import-ossfuzz`: one target per fuzzer the\n\
         # project's OSS-Fuzz build.sh left in out/. Importing again rewrites it.\n\
         {}",
        toml::to_string(&doc).context("serialize the import's manifest")?
    );
    let manifest = project_profile::load(&text).context("the import's manifest")?;
    project_profile::validate(&manifest, env!("CARGO_PKG_VERSION"))
        .context("the import's manifest")?;
    let path = layout.root.join(MANIFEST_FILE);
    fs::write(&path, text).with_context(|| format!("write '{}'", path.display()))?;
    Ok(path)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("set +x on '{}'", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// `build.sh` as given, or in PROJECT, or in PROJECT/.clusterfuzzlite.
fn find_build_script(project: &Path, given: Option<&Path>) -> Result<PathBuf> {
    if let Some(script) = given {
        return fs::canonicalize(script)
            .with_context(|| format!("build script '{}'", script.display()));
    }
    let candidates = [
        project.join("build.sh"),
        project.join(".clusterfuzzlite").join("build.sh"),
    ];
    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "no OSS-Fuzz build script in '{}' (looked for build.sh and \
                 .clusterfuzzlite/build.sh); name it with --build-script",
                project.display()
            )
        })
}

/// A project name is one path component: OSS-Fuzz's `$SRC/<name>`.
fn check_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(anyhow!(
            "project name '{name}' is not a plain directory name ([A-Za-z0-9._-]); \
             pass --name"
        ))
    }
}

/// The first executable called `program` on PATH.
fn program_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// bash, clang, clang++ and an archiver, or what to install.
fn resolve_tools() -> Result<Tools> {
    let need = |program: &str, why: &str| {
        program_on_path(program).ok_or_else(|| anyhow!("`{program}` is not on PATH: {why}"))
    };
    Ok(Tools {
        bash: need("bash", "OSS-Fuzz runs build.sh with bash")?,
        cc: need("clang", "OSS-Fuzz builds with clang ($CC); install clang")?,
        cxx: need(
            "clang++",
            "OSS-Fuzz builds with clang++ ($CXX); install clang",
        )?,
        ar: program_on_path("ar")
            .or_else(|| program_on_path("llvm-ar"))
            .ok_or_else(|| {
                anyhow!(
                    "neither `ar` nor `llvm-ar` is on PATH: bhf archives its driver \
                     into $LIB_FUZZING_ENGINE with one; install binutils or llvm"
                )
            })?,
    })
}

/// Resolve the sandbox for `mode` and check that it can run a command with
/// the build's mounts and without network.
fn resolve_sandbox(
    mode: SandboxModeArg,
    tool: Option<&Path>,
    layout: &Layout,
) -> Result<BuildSandbox> {
    let explicit = |kind: &str, default: &str| -> Result<PathBuf> {
        let program = match tool {
            Some(tool) => tool.to_path_buf(),
            None => program_on_path(default).ok_or_else(|| {
                anyhow!(
                    "--sandbox {kind}: `{default}` is not on PATH. Install {kind}, name \
                     its executable with --sandbox-tool, or pass --sandbox none to run \
                     build.sh without isolation"
                )
            })?,
        };
        if !is_executable(&program) {
            bail!(
                "--sandbox {kind}: '{}' is not found or not executable. Install {kind}, \
                 or pass --sandbox none to run build.sh without isolation",
                program.display()
            );
        }
        Ok(program)
    };
    match mode {
        SandboxModeArg::None => Ok(BuildSandbox::None),
        SandboxModeArg::Bubblewrap => {
            let sandbox = BuildSandbox::Bubblewrap(explicit("bubblewrap", "bwrap")?);
            probe(&sandbox, layout).map_err(|why| anyhow!("{why}"))?;
            Ok(sandbox)
        }
        SandboxModeArg::Firejail => {
            let sandbox = BuildSandbox::Firejail(explicit("firejail", "firejail")?);
            probe(&sandbox, layout).map_err(|why| anyhow!("{why}"))?;
            Ok(sandbox)
        }
        SandboxModeArg::Auto => {
            let mut candidates = Vec::new();
            match tool {
                // A named tool is bubblewrap or firejail by its file name.
                Some(tool) => {
                    let name = tool.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.contains("firejail") {
                        candidates.push(BuildSandbox::Firejail(tool.to_path_buf()));
                    } else {
                        candidates.push(BuildSandbox::Bubblewrap(tool.to_path_buf()));
                    }
                }
                None => {
                    if let Some(bwrap) = program_on_path("bwrap") {
                        candidates.push(BuildSandbox::Bubblewrap(bwrap));
                    }
                    if let Some(firejail) = program_on_path("firejail") {
                        candidates.push(BuildSandbox::Firejail(firejail));
                    }
                }
            }
            if candidates.is_empty() {
                bail!(
                    "no sandbox for build.sh: neither bubblewrap (`bwrap`) nor firejail \
                     is on PATH. build.sh runs project code, so bhf runs it without \
                     network and with writes confined to $SRC, $WORK and $OUT. Install \
                     one (e.g. `apt-get install bubblewrap`), or pass --sandbox none to \
                     run build.sh without isolation"
                );
            }
            let mut failures = Vec::new();
            for candidate in candidates {
                match probe(&candidate, layout) {
                    Ok(()) => return Ok(candidate),
                    Err(why) => failures.push(why),
                }
            }
            Err(anyhow!(
                "no working sandbox for build.sh:\n  {}",
                failures.join("\n  ")
            ))
        }
    }
}

/// Run `true` in `sandbox` with the build's mounts and network isolation, and
/// say why it failed.
fn probe(sandbox: &BuildSandbox, layout: &Layout) -> std::result::Result<(), String> {
    let truth = program_on_path("true").unwrap_or_else(|| PathBuf::from("/bin/true"));
    let output = sandboxed(sandbox, layout, &layout.src, &truth, &[])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    let label = sandbox.label();
    let tool = sandbox
        .tool()
        .map(|tool| tool.display().to_string())
        .unwrap_or_default();
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr.trim();
            let hint = if message.contains("uid map") || message.contains("RTM_NEWADDR") {
                " This host does not let an unprivileged user create the user and \
                 network namespaces bubblewrap needs (on Ubuntu 24.04, \
                 kernel.apparmor_restrict_unprivileged_userns=1 without an AppArmor \
                 profile for bwrap); allow them, use firejail, or pass --sandbox none \
                 to run build.sh without isolation."
            } else {
                " Pass --sandbox none to run build.sh without isolation."
            };
            Err(format!(
                "{label} ({tool}) cannot run the build without network and with writes \
                 confined to $SRC, $WORK and $OUT: it exited with {} ({}).{hint}",
                output.status,
                if message.is_empty() {
                    "no message"
                } else {
                    message
                }
            ))
        }
        Err(error) => Err(format!("{label} ({tool}) could not be started: {error}")),
    }
}

/// System directories mounted read-only into a bubblewrap sandbox.
const BWRAP_SYSTEM_DIRS: [&str; 9] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt",
];

/// `program args` in `sandbox`, run from `cwd` with an empty environment
/// (the caller adds the build's).
///
/// - bubblewrap: every namespace unshared, the network included; the system
///   directories and bhf's engine read-only, `$SRC`, `$WORK` and `$OUT`
///   read-write, a private `/proc` and `/dev`, an empty read-only `/tmp`,
///   and nothing else of the host (no home directory).
/// - firejail: no network, the whole filesystem read-only except `$SRC`,
///   `$WORK` and `$OUT`.
fn sandboxed(
    sandbox: &BuildSandbox,
    layout: &Layout,
    cwd: &Path,
    program: &Path,
    args: &[OsString],
) -> Command {
    let mut command = match sandbox {
        BuildSandbox::Bubblewrap(bwrap) => {
            let mut command = Command::new(bwrap);
            command.args(["--die-with-parent", "--unshare-all", "--new-session"]);
            command.args(["--proc", "/proc", "--dev", "/dev", "--dir", "/tmp"]);
            for dir in BWRAP_SYSTEM_DIRS {
                if Path::new(dir).exists() {
                    command.args(["--ro-bind", dir, dir]);
                }
            }
            command
                .arg("--ro-bind")
                .arg(&layout.engine)
                .arg(&layout.engine);
            for dir in layout.writable() {
                command.arg("--bind").arg(dir).arg(dir);
            }
            // The sandbox's own root (and the empty /tmp in it) read-only
            // too, so a write anywhere but the three binds fails.
            command.args(["--remount-ro", "/"]);
            command.arg("--chdir").arg(cwd).arg("--").arg(program);
            command
        }
        BuildSandbox::Firejail(firejail) => {
            let mut command = Command::new(firejail);
            command.args(["--quiet", "--noprofile", "--net=none", "--read-only=/"]);
            for dir in layout.writable() {
                let mut flag = OsString::from("--read-write=");
                flag.push(dir);
                command.arg(flag);
            }
            command.arg("--").arg(program);
            command
        }
        BuildSandbox::None => Command::new(program),
    };
    command.args(args).current_dir(cwd).env_clear();
    command
}

/// The environment `build.sh` runs with: OSS-Fuzz's build variables, and
/// PATH, HOME and TMPDIR.
fn build_env(layout: &Layout, tools: &Tools, engine: &Path) -> Vec<(String, String)> {
    let path = |p: &Path| p.display().to_string();
    let flags = format!("{BASE_FLAGS} {SANITIZER_FLAGS} {COVERAGE_FLAGS}");
    let architecture = match std::env::consts::ARCH {
        "x86" => "i386",
        other => other,
    };
    vec![
        ("SRC".to_owned(), path(&layout.src)),
        ("WORK".to_owned(), path(&layout.work)),
        ("OUT".to_owned(), path(&layout.out)),
        ("CC".to_owned(), path(&tools.cc)),
        ("CXX".to_owned(), path(&tools.cxx)),
        ("CCC".to_owned(), path(&tools.cxx)),
        ("CFLAGS".to_owned(), flags.clone()),
        ("CXXFLAGS".to_owned(), flags),
        ("LIB_FUZZING_ENGINE".to_owned(), path(engine)),
        ("SANITIZER".to_owned(), "address".to_owned()),
        ("SANITIZER_FLAGS".to_owned(), SANITIZER_FLAGS.to_owned()),
        ("COVERAGE_FLAGS".to_owned(), COVERAGE_FLAGS.to_owned()),
        ("FUZZING_ENGINE".to_owned(), "libfuzzer".to_owned()),
        ("FUZZING_LANGUAGE".to_owned(), "c++".to_owned()),
        ("ARCHITECTURE".to_owned(), architecture.to_owned()),
        // As OSS-Fuzz's compile step does: a configure check or a code
        // generator built with $CFLAGS must not fail the build on a leak.
        (
            "ASAN_OPTIONS".to_owned(),
            "detect_leaks=0:symbolize=0:detect_odr_violation=0".to_owned(),
        ),
        (
            "PATH".to_owned(),
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned()),
        ),
        ("HOME".to_owned(), path(&layout.work)),
        ("TMPDIR".to_owned(), path(&layout.work.join("tmp"))),
    ]
}

/// Compile bhf's driver and the entry forwarder, and archive them as
/// `<engine>/libFuzzingEngine.a`: the `$LIB_FUZZING_ENGINE` the build links.
fn build_engine(layout: &Layout, tools: &Tools) -> Result<PathBuf> {
    let runtime = crate::runtime_assets::locate("c_runtime", "bhf_driver.c")
        .ok_or_else(|| anyhow!("bhf's C runtime (c_runtime/bhf_driver.c) was not found"))?;
    let entry = layout.engine.join("bhf_engine_entry.c");
    fs::write(&entry, ENGINE_ENTRY_SOURCE).context("write the engine entry source")?;
    let objects = [
        (
            runtime.join("bhf_driver.c"),
            layout.engine.join("bhf_driver.o"),
        ),
        (entry, layout.engine.join("bhf_engine_entry.o")),
    ];
    for (source, object) in &objects {
        // The driver's own flags (a generated harness Makefile's
        // BHF_DRIVER_CFLAGS): no sanitizer and no coverage, so the driver
        // adds no edges of its own.
        run_tool(
            Command::new(&tools.cc)
                .args(["-O1", "-g", "-c", "-o"])
                .arg(object)
                .arg(source),
            "compile bhf's fuzzing engine",
        )?;
    }
    let archive = layout.engine.join("libFuzzingEngine.a");
    run_tool(
        Command::new(&tools.ar)
            .arg("rcs")
            .arg(&archive)
            .args(objects.iter().map(|(_, object)| object)),
        "archive bhf's fuzzing engine",
    )?;
    Ok(archive)
}

/// Run a host tool bhf itself needs, with its error output on failure.
fn run_tool(command: &mut Command, what: &str) -> Result<()> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("{what}: start {:?}", command.get_program()))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "{what}: {:?} exited with {}: {}",
        command.get_program(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// Run `bash -eux $SRC/build.sh` in the sandbox from the project's `$SRC`
/// directory, with its output in `log`.
fn run_build_script(
    sandbox: &BuildSandbox,
    layout: &Layout,
    cwd: &Path,
    tools: &Tools,
    env: &[(String, String)],
    log: &Path,
) -> Result<()> {
    let script = layout.src.join("build.sh");
    let file = fs::File::create(log).with_context(|| format!("create '{}'", log.display()))?;
    let mut command = sandboxed(
        sandbox,
        layout,
        cwd,
        &tools.bash,
        &[OsString::from("-eux"), script.into_os_string()],
    );
    command
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(file.try_clone().context("share the build log")?)
        .stderr(file);
    let status = command.status().context("start build.sh")?;
    if status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "build.sh failed ({status}); the end of {}:\n{}",
        log.display(),
        log_tail(log, 30)
    ))
}

/// The last `lines` lines of `log`.
fn log_tail(log: &Path, lines: usize) -> String {
    let Ok(file) = fs::File::open(log) else {
        return String::new();
    };
    let all: Vec<String> = std::io::BufReader::new(file)
        .lines()
        .map_while(std::result::Result::ok)
        .collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// Copy `from` to `to`: directories recursively, symlinks as symlinks,
/// leaving out `skip` (the work dir, when it is inside the source tree).
fn copy_tree(from: &Path, to: &Path, skip: &Path) -> Result<()> {
    fs::create_dir_all(to).with_context(|| format!("create '{}'", to.display()))?;
    let mut entries = fs::read_dir(from)
        .with_context(|| format!("read '{}'", from.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let source = entry.path();
        if source == skip {
            continue;
        }
        let dest = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            copy_symlink(&source, &dest)?;
        } else if kind.is_dir() {
            copy_tree(&source, &dest, skip)?;
        } else if kind.is_file() {
            fs::copy(&source, &dest).with_context(|| format!("copy '{}'", source.display()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_symlink(source: &Path, dest: &Path) -> Result<()> {
    let target = fs::read_link(source)?;
    std::os::unix::fs::symlink(target, dest)
        .with_context(|| format!("copy symlink '{}'", source.display()))
}

#[cfg(not(unix))]
fn copy_symlink(_source: &Path, _dest: &Path) -> Result<()> {
    Ok(())
}

/// The fuzzers in `out` (searched recursively, as OSS-Fuzz does), by name;
/// of two with one name, the first in path order.
fn collect_fuzzers(out: &Path) -> Result<Vec<Fuzzer>> {
    let mut files = Vec::new();
    walk_files(out, &mut files).with_context(|| format!("read $OUT '{}'", out.display()))?;
    files.sort();
    let mut fuzzers: Vec<Fuzzer> = Vec::new();
    for path in files {
        if !is_fuzz_target(&path) {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        if fuzzers.iter().any(|fuzzer| fuzzer.name == name) {
            bhfeprintln!(
                "bhf project import-ossfuzz: warning: a second fuzzer named '{name}' \
                 ({}) is left out",
                path.display()
            );
            continue;
        }
        let protocol = protocol_detect::detect(&path, &[]).protocol;
        fuzzers.push(Fuzzer {
            name,
            path,
            protocol,
        });
    }
    fuzzers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(fuzzers)
}

/// Every regular file under `dir`; symlinks are not followed or listed.
fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            walk_files(&entry.path(), out)?;
        } else if kind.is_file() {
            out.push(entry.path());
        }
    }
    Ok(())
}

/// OSS-Fuzz's `is_fuzz_target_local`, for a regular file.
fn is_fuzz_target(path: &Path) -> bool {
    let (Some(stem), extension) = (
        path.file_stem().and_then(|s| s.to_str()),
        path.extension().and_then(|e| e.to_str()),
    ) else {
        return false;
    };
    let valid_name = !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !valid_name || stem.starts_with("jazzer_driver") {
        return false;
    }
    if !matches!(extension, None | Some("exe")) || !is_executable(path) {
        return false;
    }
    stem.ends_with("_fuzzer") || file_contains(path, FUZZ_TARGET_MARKER).unwrap_or(false)
}

/// Whether the bytes of `path` contain `needle`, read in bounded chunks.
fn file_contains(path: &Path, needle: &[u8]) -> std::io::Result<bool> {
    let mut file = fs::File::open(path)?;
    let mut window: Vec<u8> = Vec::with_capacity(1 << 16);
    let mut chunk = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(false);
        }
        window.extend_from_slice(&chunk[..read]);
        if window.windows(needle.len()).any(|w| w == needle) {
            return Ok(true);
        }
        // Keep the tail a match could start in.
        let keep = needle.len().saturating_sub(1).min(window.len());
        window.drain(..window.len() - keep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::test_support::TestDir;

    #[cfg(unix)]
    fn write_executable(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The `$OUT` search follows OSS-Fuzz's rule: a `_fuzzer` name or the
    /// entry point's name in the bytes, an executable regular file with a
    /// plain name and no extension. Seeds, dictionaries, options, helper
    /// tools and non-executables are left out.
    #[cfg(unix)]
    #[test]
    fn the_out_search_takes_what_oss_fuzz_takes() {
        let out = TestDir::new("ossfuzz-out-search");
        let mut entry = vec![0x7f, b'E', b'L', b'F'];
        entry.resize(200_000, 0);
        // Across the read chunk boundary, so the search keeps its tail.
        entry.splice(65_530..65_530, FUZZ_TARGET_MARKER.iter().copied());
        write_executable(&out.join("decode"), &entry);
        write_executable(&out.join("parse_fuzzer"), b"#!/bin/sh\n");
        write_executable(&out.join("tool"), b"\x7fELF no entry point");
        write_executable(&out.join("jazzer_driver"), FUZZ_TARGET_MARKER);
        write_executable(&out.join("bad name"), FUZZ_TARGET_MARKER);
        write_executable(&out.join("lib_fuzzer.so"), FUZZ_TARGET_MARKER);
        fs::write(out.join("plain_fuzzer"), FUZZ_TARGET_MARKER).unwrap();
        fs::write(out.join("parse_fuzzer_seed_corpus.zip"), b"PK").unwrap();
        fs::write(out.join("parse_fuzzer.dict"), b"\"a\"\n").unwrap();
        fs::create_dir(out.join("nested")).unwrap();
        write_executable(&out.join("nested/inner_fuzzer"), b"#!/bin/sh\n");
        // A second `decode` deeper down is left out.
        write_executable(&out.join("nested/decode"), &entry);
        std::os::unix::fs::symlink("/bin/true", out.join("link_fuzzer")).unwrap();

        let names: Vec<String> = collect_fuzzers(&out)
            .unwrap()
            .into_iter()
            .map(|fuzzer| fuzzer.name)
            .collect();
        assert_eq!(names, ["decode", "inner_fuzzer", "parse_fuzzer"]);
    }

    /// An `$OUT` with a fuzzer linked with bhf's driver and a libFuzzer one
    /// linked without it.
    #[cfg(unix)]
    fn out_with_two_fuzzers(work: &Path) -> (Layout, Vec<Fuzzer>) {
        let layout = Layout::new(work);
        fs::create_dir_all(layout.out.join("sub")).unwrap();
        let mut driver = b"\x7fELF\0BHF_FRAMED\0LLVMFuzzerTestOneInput\0".to_vec();
        driver.resize(9000, 0);
        write_executable(&layout.out.join("decode_fuzzer"), &driver);
        let mut libfuzzer = b"\x7fELF\0LLVMFuzzerTestOneInput\0".to_vec();
        libfuzzer.extend_from_slice(b"INFO: libFuzzer ignores flags that start with '--'\0");
        libfuzzer.resize(9000, 0);
        write_executable(&layout.out.join("sub/legacy_fuzzer"), &libfuzzer);
        let fuzzers = collect_fuzzers(&layout.out).unwrap();
        (layout, fuzzers)
    }

    /// A fuzzer linked with bhf's driver is staged where `bhf fuzz --harness
    /// <name>` finds it, with the framed input mode declared; a libFuzzer
    /// binary without the driver is staged with no declaration (and loses
    /// one an earlier import left), so it runs one input file per process.
    #[cfg(unix)]
    #[test]
    fn each_fuzzer_is_registered_where_bhf_fuzz_finds_it() {
        let work = TestDir::new("ossfuzz-register");
        let (_layout, fuzzers) = out_with_two_fuzzers(&work);
        let stale = work.join("build/legacy_fuzzer");
        fs::create_dir_all(&stale).unwrap();
        protocol_detect::write_declared_input_mode(&stale, "framed", "earlier import").unwrap();

        let registered: Vec<Registered> = fuzzers
            .iter()
            .map(|fuzzer| register(&work, fuzzer).unwrap())
            .collect();
        let lanes: Vec<(&str, Lane)> = registered
            .iter()
            .map(|entry| (entry.fuzzer.name.as_str(), entry.lane))
            .collect();
        assert_eq!(
            lanes,
            [
                ("decode_fuzzer", Lane::Builtin),
                ("legacy_fuzzer", Lane::BinaryFile)
            ]
        );
        for entry in &registered {
            let found = crate::fuzz::find_harness_executable(
                &work,
                &entry.fuzzer.name,
                crate::fuzz::FuzzEngine::Builtin,
            )
            .unwrap();
            assert_eq!(found, entry.harness);
            assert_eq!(
                fs::read(&found).unwrap(),
                fs::read(&entry.fuzzer.path).unwrap()
            );
            assert!(is_executable(&found));
        }
        let decode = protocol_detect::detect(&registered[0].harness, &[&work]);
        assert_eq!(decode.protocol, HarnessProtocol::BhfFramed);
        assert!(matches!(
            decode.basis,
            protocol_detect::ProtocolBasis::Declared(ref mode) if mode == "framed"
        ));
        assert!(!stale.join(protocol_detect::PROTOCOL_SIDECAR).exists());
        assert_eq!(
            protocol_detect::detect(&registered[1].harness, &[&work]).protocol,
            HarnessProtocol::LibFuzzerSingleInput
        );
    }

    /// The manifest has a builtin target for the fuzzer with bhf's driver and
    /// a binary, file-input one for the libFuzzer binary, each naming its
    /// binary in `$OUT` relative to the manifest, and loads and validates.
    #[cfg(unix)]
    #[test]
    fn the_manifest_has_one_target_per_fuzzer() {
        let work = TestDir::new("ossfuzz-manifest");
        let (layout, fuzzers) = out_with_two_fuzzers(&work);
        let registered: Vec<Registered> = fuzzers
            .iter()
            .map(|fuzzer| register(&work, fuzzer).unwrap())
            .collect();
        let path = write_manifest(&layout, "libdemo", &registered).unwrap();
        assert_eq!(path, layout.root.join(MANIFEST_FILE));
        let manifest = project_profile::load(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(manifest.project.id, "libdemo");
        let targets: Vec<(&str, &str, Option<&str>, PathBuf)> = manifest
            .targets
            .iter()
            .map(|target| {
                (
                    target.id.as_str(),
                    target.engine.as_str(),
                    target.input_mode.as_deref(),
                    layout.root.join(target.binary.as_ref().unwrap()),
                )
            })
            .collect();
        assert_eq!(
            targets,
            [
                (
                    "decode_fuzzer",
                    "builtin",
                    None,
                    layout.out.join("decode_fuzzer")
                ),
                (
                    "legacy_fuzzer",
                    "binary",
                    Some("file"),
                    layout.out.join("sub/legacy_fuzzer")
                ),
            ]
        );
    }

    /// The `[libfuzzer]` options bhf has an equivalent for are read; every
    /// other line is noted as not applied, a bad number included.
    #[test]
    fn the_options_bhf_has_an_equivalent_for_are_read_and_the_rest_noted() {
        let (options, notes) = parse_options(
            "# a comment\n\
             ; another\n\
             [libfuzzer]\n\
             max_len = 64\n\
             timeout: 25\n\
             rss_limit_mb=2560\n\
             dict = shared.dict\n\
             close_fd_mask = 3\n\
             only_ascii = yes\n\
             [LibFuzzer]\n\
             runs = 10\n\
             [asan]\n\
             detect_leaks = 0\n\
             [libfuzzer]\n\
             max_len = big\n\
             stray line\n",
        );
        assert_eq!(
            options,
            FuzzerOptions {
                max_len: Some(64),
                timeout_secs: Some(25),
                rss_limit_mb: Some(2560),
                dict: Some("shared.dict".to_owned()),
            }
        );
        assert_eq!(
            options.fuzz_flags(),
            " --max-len 64 --timeout 25s --rss-limit-mb 2560"
        );
        assert_eq!(
            notes,
            [
                "[libfuzzer] close_fd_mask = 3 is not applied: bhf has no equivalent",
                "[libfuzzer] only_ascii = yes is not applied: bhf has no equivalent",
                "[libfuzzer] runs = 10 is not applied: bhf has no equivalent",
                "[asan] detect_leaks = 0 is not applied: bhf has no equivalent",
                "[libfuzzer] max_len = big is not applied: not a whole number",
                "`stray line` is not a `key = value` line, and is ignored",
            ]
        );
    }

    /// A `.options` file's `dict` is a file beside the fuzzer in `$OUT`, or
    /// below it; an absolute path or a `..` that leaves `$OUT` is refused.
    #[test]
    fn an_options_dictionary_stays_in_out() {
        let out = Path::new("/w/ossfuzz/out");
        let sub = out.join("sub");
        assert_eq!(
            option_dictionary(out, out, "shared.dict"),
            Some(out.join("shared.dict"))
        );
        assert_eq!(
            option_dictionary(out, &sub, "./dicts/x.dict"),
            Some(sub.join("./dicts/x.dict"))
        );
        for bad in ["/etc/passwd", "../secret.dict", "dicts/../../x.dict"] {
            assert_eq!(option_dictionary(out, &sub, bad), None, "{bad}");
        }
    }

    /// `<name>.dict` and the options' dictionary are merged into the
    /// harness's `dictionary.txt`, de-duplicated; a dictionary that is not
    /// UTF-8 is left out with a note; a binary-lane fuzzer notes what its
    /// manifest target cannot take.
    #[cfg(unix)]
    #[test]
    fn dictionaries_are_merged_into_the_harness_dictionary() {
        let work = TestDir::new("ossfuzz-dicts");
        let (layout, fuzzers) = out_with_two_fuzzers(&work);
        fs::write(
            layout.out.join("decode_fuzzer.dict"),
            "# kw\nmagic=\"HDR1\"\n\"\\x00\\xff\"\n",
        )
        .unwrap();
        fs::write(layout.out.join("shared.dict"), "\"HDR1\"\nend=\"END\"\n").unwrap();
        fs::write(
            layout.out.join("decode_fuzzer.options"),
            "[libfuzzer]\ndict = shared.dict\nmax_len = 128\n",
        )
        .unwrap();
        fs::write(layout.out.join("sub/legacy_fuzzer.dict"), b"\"\xff\xfe\"\n").unwrap();
        fs::write(
            layout.out.join("sub/legacy_fuzzer.options"),
            "[libfuzzer]\nmax_len = 8\ntimeout = 3\n",
        )
        .unwrap();
        let mut registered: Vec<Registered> = fuzzers
            .iter()
            .map(|fuzzer| register(&work, fuzzer).unwrap())
            .collect();
        for entry in &mut registered {
            apply_dictionaries_and_options(&layout, &work, entry).unwrap();
        }

        let decode = &registered[0].extras;
        assert_eq!(
            decode.dictionaries,
            [
                layout.out.join("decode_fuzzer.dict"),
                layout.out.join("shared.dict")
            ]
        );
        assert_eq!(decode.tokens, 3);
        assert_eq!(decode.options.max_len, Some(128));
        assert!(decode.notes.is_empty(), "{:?}", decode.notes);
        assert_eq!(
            fs::read_to_string(work.join("build/decode_fuzzer/dictionary.txt")).unwrap(),
            "\"HDR1\"\n\"\\x00\\xff\"\n\"END\"\n"
        );

        let legacy = &registered[1].extras;
        assert!(legacy.dictionaries.is_empty());
        assert!(!work.join("build/legacy_fuzzer/dictionary.txt").exists());
        assert!(
            legacy.notes[0].contains("not valid UTF-8"),
            "{:?}",
            legacy.notes
        );
        assert_eq!(
            legacy.notes[1],
            "max_len do(es) not apply to a binary-lane target in the manifest"
        );

        // The manifest takes what each lane runs with.
        write_manifest(&layout, "libdemo", &registered).unwrap();
        let manifest =
            project_profile::load(&fs::read_to_string(layout.root.join(MANIFEST_FILE)).unwrap())
                .unwrap();
        let decode = &manifest.targets[0];
        assert_eq!(
            decode.dictionaries,
            [
                PathBuf::from("out/decode_fuzzer.dict"),
                PathBuf::from("out/shared.dict")
            ]
        );
        assert_eq!(decode.max_len.as_deref(), Some("128"));
        let legacy = &manifest.targets[1];
        assert!(legacy.dictionaries.is_empty());
        assert_eq!(legacy.max_len, None);
        assert_eq!(legacy.timeout_ms, Some(3000));
    }

    #[test]
    fn a_project_name_is_one_plain_path_component() {
        for good in ["libpng", "re2", "json-c", "lib_x.y"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "x;y"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    /// bubblewrap gets no network, the system read-only, and only `$SRC`,
    /// `$WORK` and `$OUT` writable; firejail the same with the whole
    /// filesystem read-only. The environment is cleared either way.
    #[cfg(unix)]
    #[test]
    fn the_sandbox_confines_the_build_to_src_work_and_out() {
        let layout = Layout::new(Path::new("/w"));
        let args = |sandbox: &BuildSandbox| -> Vec<String> {
            let command = sandboxed(
                sandbox,
                &layout,
                Path::new("/w/ossfuzz/src/p"),
                Path::new("/bin/bash"),
                &[OsString::from("build.sh")],
            );
            assert!(command.get_envs().all(|(_, value)| value.is_none()));
            command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let bwrap = args(&BuildSandbox::Bubblewrap(PathBuf::from("/usr/bin/bwrap")));
        let joined = bwrap.join(" ");
        assert!(joined.starts_with("--die-with-parent --unshare-all"));
        for bind in [
            "--bind /w/ossfuzz/src /w/ossfuzz/src",
            "--bind /w/ossfuzz/work /w/ossfuzz/work",
            "--bind /w/ossfuzz/out /w/ossfuzz/out",
            "--ro-bind /w/ossfuzz/engine /w/ossfuzz/engine",
            "--dir /tmp",
            "--bind /w/ossfuzz/out /w/ossfuzz/out --remount-ro / --chdir /w/ossfuzz/src/p \
             -- /bin/bash build.sh",
        ] {
            assert!(joined.contains(bind), "{bind} in {joined}");
        }
        assert_eq!(bwrap.iter().filter(|a| *a == "--bind").count(), 3);

        let firejail = args(&BuildSandbox::Firejail(PathBuf::from("/usr/bin/firejail")));
        assert_eq!(
            firejail,
            [
                "--quiet",
                "--noprofile",
                "--net=none",
                "--read-only=/",
                "--read-write=/w/ossfuzz/src",
                "--read-write=/w/ossfuzz/work",
                "--read-write=/w/ossfuzz/out",
                "--",
                "/bin/bash",
                "build.sh",
            ]
        );
    }

    /// The build contract's variables, pointing at the import's directories
    /// and bhf's engine, with the coverage bhf's driver reads.
    #[cfg(unix)]
    #[test]
    fn build_sh_gets_the_oss_fuzz_variables() {
        let layout = Layout::new(Path::new("/w"));
        let tools = Tools {
            bash: PathBuf::from("/usr/bin/bash"),
            cc: PathBuf::from("/usr/bin/clang"),
            cxx: PathBuf::from("/usr/bin/clang++"),
            ar: PathBuf::from("/usr/bin/ar"),
        };
        let env: std::collections::BTreeMap<String, String> = build_env(
            &layout,
            &tools,
            Path::new("/w/ossfuzz/engine/libFuzzingEngine.a"),
        )
        .into_iter()
        .collect();
        assert_eq!(env["SRC"], "/w/ossfuzz/src");
        assert_eq!(env["WORK"], "/w/ossfuzz/work");
        assert_eq!(env["OUT"], "/w/ossfuzz/out");
        assert_eq!(env["CC"], "/usr/bin/clang");
        assert_eq!(env["CXX"], "/usr/bin/clang++");
        assert_eq!(
            env["LIB_FUZZING_ENGINE"],
            "/w/ossfuzz/engine/libFuzzingEngine.a"
        );
        assert_eq!(env["SANITIZER"], "address");
        assert_eq!(env["FUZZING_ENGINE"], "libfuzzer");
        assert_eq!(env["TMPDIR"], "/w/ossfuzz/work/tmp");
        for flags in [&env["CFLAGS"], &env["CXXFLAGS"]] {
            assert!(flags.contains("-fsanitize=address"), "{flags}");
            assert!(flags.contains("trace-pc-guard,trace-cmp"), "{flags}");
            assert!(flags.contains("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"));
            assert!(!flags.contains("-fsanitize=fuzzer"), "{flags}");
        }
    }
}
