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
}

impl Layout {
    fn new(work_dir: &Path) -> Self {
        let root = work_dir.join("ossfuzz");
        Self {
            src: root.join("src"),
            work: root.join("work"),
            out: root.join("out"),
            engine: root.join("engine"),
            root,
        }
    }

    /// Empty `$SRC`, `$WORK`, `$OUT` and the engine dir, as a fresh OSS-Fuzz
    /// build container starts. Only these bhf-owned directories are removed.
    fn reset(&self) -> Result<()> {
        for dir in [&self.src, &self.work, &self.out, &self.engine] {
            if dir.exists() {
                fs::remove_dir_all(dir).with_context(|| format!("empty '{}'", dir.display()))?;
            }
            fs::create_dir_all(dir).with_context(|| format!("create '{}'", dir.display()))?;
        }
        // A private temporary directory in `$WORK`: TMPDIR points here, so
        // the compilers' scratch files never need a writable /tmp.
        fs::create_dir_all(self.work.join("tmp")).context("create $WORK/tmp")?;
        // The record of the import this one replaces.
        let record = self.root.join("import.json");
        if record.exists() {
            fs::remove_file(&record).with_context(|| format!("remove '{}'", record.display()))?;
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
        "fuzzers": fuzzers.iter().map(|fuzzer| json!({
            "name": fuzzer.name,
            "binary": fuzzer.path,
            "protocol": fuzzer.protocol.label(),
        })).collect::<Vec<_>>(),
    });
    let record_text = serde_json::to_string_pretty(&record)?;
    fs::write(layout.root.join("import.json"), &record_text).context("write import.json")?;

    if args.json {
        println!("{record_text}");
    } else {
        println!(
            "project '{name}': build.sh produced {} fuzzer(s) in {}:",
            fuzzers.len(),
            layout.out.display()
        );
        for fuzzer in &fuzzers {
            println!("  {} [{}]", fuzzer.name, fuzzer.protocol.label());
        }
    }
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
