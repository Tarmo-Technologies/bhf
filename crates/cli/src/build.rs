// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::AdaStandard;
use compiler_adapter::{probe_compiler, BuildMode, CompilerAdapter, ToolchainConfig};
use project_synth::{write_project, ProjectSpec, SourceRoot, Switches};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::probe_backend::{materialize_runtime_sources, ProbeBackend};

/// Explicit C/C++ compiler + flag override for the harness `make` invocation.
/// `bhf auto` passes this ONLY for a foreign-platform/arch candidate it is
/// cross-compiling (see `auto::cross_target`); host-native builds pass `None`
/// and keep the existing clang defaults. `cflags`/`cxxflags`, when non-empty,
/// replace the Makefile's `CFLAGS ?=`/`CXXFLAGS ?=` defaults — the cross GCCs
/// reject the clang `-fsanitize-coverage=trace-pc-guard` baked into them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFamilyCompilerOverride {
    pub cc: String,
    pub cxx: String,
    pub cflags: Vec<String>,
    pub cxxflags: Vec<String>,
    /// `Some`: the target-selection flags (`--sysroot=`, `--target=`) every
    /// object and link of the build takes, bhf's driver object included,
    /// rendered for a recipe; they replace the `[toolchain]`'s published
    /// `BHF_TOOLCHAIN_TARGET_FLAGS`. `None` keeps those.
    pub target_flags: Option<Vec<String>>,
}

/// Activate a coverage-capable Clang from the RHEL 7 LLVM Software Collection
/// when the base-system `clang` is too old for SanitizerCoverage. The SCL ships
/// outside the normal PATH and needs its lib64 directory at compiler run time;
/// applying those variables to this process also covers every later `make`,
/// replay, and optional sanitizer build spawned by `auto`.
///
/// This is deliberately capability-based rather than version-based: a vendor
/// compiler is accepted when it compiles the exact edge+comparison coverage
/// flags bhf uses. Explicit CC/CXX choices remain authoritative.
pub(crate) fn activate_compatible_clang() -> bool {
    #[cfg(unix)]
    {
        if std::env::var_os("CC").is_some() || std::env::var_os("CXX").is_some() {
            return false;
        }
        if clang_supports_bhf_coverage("clang", None) {
            return false;
        }

        const SCL_ROOTS: [&str; 2] = [
            "/opt/rh/llvm-toolset-7.0/root/usr",
            "/opt/rh/llvm-toolset-7/root/usr",
        ];
        for root in SCL_ROOTS {
            let root = Path::new(root);
            let clang = root.join("bin/clang");
            let lib64 = root.join("lib64");
            if !clang.is_file() || !clang_supports_bhf_coverage(&clang, Some(&lib64)) {
                continue;
            }

            prepend_process_path("PATH", &[root.join("bin"), root.join("sbin")]);
            prepend_process_path("LD_LIBRARY_PATH", &[lib64]);
            bhfeprintln!(
                "bhf: using RHEL 7 LLVM Toolset compiler {} (base clang lacks SanitizerCoverage)",
                clang.display()
            );
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn clang_supports_bhf_coverage(
    compiler: impl AsRef<std::ffi::OsStr>,
    runtime_lib: Option<&Path>,
) -> bool {
    let mut command = std::process::Command::new(compiler);
    command.args([
        "-x",
        "c",
        "-c",
        "/dev/null",
        "-o",
        "/dev/null",
        "-fsanitize-coverage=trace-pc-guard,trace-cmp",
    ]);
    if let Some(runtime_lib) = runtime_lib {
        let mut paths = vec![runtime_lib.to_path_buf()];
        if let Some(existing) = std::env::var_os("LD_LIBRARY_PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        if let Ok(joined) = std::env::join_paths(paths) {
            command.env("LD_LIBRARY_PATH", joined);
        }
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// LLVM's Windows ASan DLL lives under its resource directory, outside `bin`.
/// Make it available to harnesses and replay children without changing the
/// user's persistent PATH or copying a compiler runtime into the release.
#[cfg(windows)]
pub(crate) fn activate_windows_clang_runtime() {
    for variable in ["CC", "CXX"] {
        let compiler = std::env::var_os(variable).unwrap_or_else(|| "clang".into());
        let Ok(output) = std::process::Command::new(compiler)
            .arg("-print-resource-dir")
            .output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let resource = String::from_utf8_lossy(&output.stdout);
        let resource = Path::new(resource.trim());
        if !resource.is_absolute() {
            continue;
        }
        let runtime = resource.join("lib/windows");
        if !["x86_64", "i386", "aarch64"].iter().any(|arch| {
            runtime
                .join(format!("clang_rt.asan_dynamic-{arch}.dll"))
                .is_file()
        }) {
            continue;
        }
        let already_present = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).any(|entry| entry == runtime))
            .unwrap_or(false);
        if !already_present {
            prepend_process_path("PATH", &[runtime]);
        }
    }
}

#[cfg(any(unix, windows))]
fn prepend_process_path(key: &str, prefixes: &[PathBuf]) {
    let mut paths = prefixes.to_vec();
    if let Some(existing) = std::env::var_os(key) {
        paths.extend(std::env::split_paths(&existing));
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        std::env::set_var(key, joined);
    }
}

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct BuildArgs {
    /// Path to the bhf_work directory: the parent of `harnesses/` or
    /// `generated_harnesses/` (and of `src_instrumented/` for Ada). A C/C++
    /// harness directory (`<work>/harnesses/<id>`) or `<work>/harnesses` itself
    /// is also accepted and mapped onto its work directory.
    pub work_dir: PathBuf,

    /// Governing Ada project whose evaluated build semantics the generated
    /// instrumented overlay should inherit.
    #[arg(long)]
    pub source_project: Option<PathBuf>,

    /// Harness id to build. Defaults to the only harness present; with several,
    /// the error lists their ids.
    #[arg(long)]
    pub harness: Option<String>,

    /// Target triple to build for. C/C++ harness: selects `<triple>-gcc` /
    /// `<triple>-g++` unless --cc/--cxx name the compilers (a clang compiler
    /// gets `--target=<triple>`). Ada harness: written as `for Target use`, and
    /// the default tool prefix. Config key: `toolchain.target`.
    #[arg(long, visible_alias = "target-triple")]
    pub target: Option<String>,

    /// Ada runtime name to pass through the generated GPR project. Ada
    /// harnesses only; rejected for a C/C++ harness. Config key:
    /// `toolchain.ada.runtime`.
    #[arg(long, visible_alias = "ada-runtime")]
    pub runtime: Option<String>,

    /// Toolchain executable prefix. Ada harness: `<prefix>-gprbuild` /
    /// `<prefix>-gnat`, and the Target when --target is not given (config key:
    /// `toolchain.ada.prefix`). C/C++ harness: `<prefix>-gcc`/`<prefix>-g++`
    /// unless --cc/--cxx are given; in a config file that choice is
    /// `toolchain.target` or `toolchain.cc`/`toolchain.cxx`, because
    /// `toolchain.ada.prefix` applies to Ada harnesses only.
    #[arg(long, visible_alias = "ada-prefix")]
    pub toolchain: Option<String>,

    /// AdaFuzz.Probe runtime backend to compile into the harness runtime. Ada
    /// harnesses only. Config key: `toolchain.ada.probe-backend`.
    #[arg(long, value_enum, default_value = "host_file")]
    pub(crate) probe_backend: ProbeBackend,

    #[command(flatten)]
    pub(crate) toolchain_args: BuildToolchainArgs,

    /// For C/C++ harnesses: which Makefile target to build.
    /// `libfuzzer` (default) runs `make` which produces a libFuzzer binary
    /// driven by sanitizers; `afl++` runs `make afl` which produces a
    /// persistent-mode AFL++ binary suitable for `bhf fuzz --engine afl++`.
    #[arg(long, value_enum, default_value = "libfuzzer")]
    pub c_engine: CEngine,
}

/// The toolchain options of `bhf build` beyond the historical Ada flags.
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub(crate) struct BuildToolchainArgs {
    /// TOML file whose `[toolchain]` table sets the compiler, flags, target,
    /// sysroot and Ada toolchain (the same table `bhf auto --config` reads).
    /// Command-line flags override it key by key; relative paths in it
    /// resolve against the file's directory.
    #[arg(long = "config", value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) c: crate::toolchain::CToolchainArgs,

    /// Program that runs a harness built for another target, such as
    /// `qemu-aarch64`. A C/C++ build for a target this host cannot run, or
    /// one whose compiler does not name its target, records it beside the
    /// binary (`build/<id>/bhf_runner.json`) and the harness, as does an Ada
    /// build for another target (`build/<id>/obj/`); `bhf replay`, `bhf
    /// minimize`, `bhf fuzz`, `bhf decode-args` and the finding's `replay.py`
    /// run the binary under it when no `--qemu-user` is given. A runner for a
    /// build this host runs natively is an error. Config key:
    /// `toolchain.runner`.
    #[arg(long = "runner", value_name = "PROGRAM")]
    pub(crate) runner: Option<String>,

    /// Argument placed between the runner and the harness (repeatable).
    /// Defaults to `-L <sysroot>` (or `-L /usr/<triple>`) for a qemu-user
    /// runner. Config key: `toolchain.runner-args`.
    #[arg(long = "runner-arg", value_name = "ARG", allow_hyphen_values = true)]
    pub(crate) runner_args: Vec<String>,

    /// `gprbuild` to run for an Ada harness (name or path). Config key:
    /// `toolchain.ada.gprbuild`.
    #[arg(long = "ada-gprbuild", value_name = "PROGRAM")]
    pub(crate) ada_gprbuild: Option<String>,

    /// `gnat` driver for an Ada harness (name or path). Config key:
    /// `toolchain.ada.gnat`.
    #[arg(long = "ada-gnat", value_name = "PROGRAM")]
    pub(crate) ada_gnat: Option<String>,

    /// Extra Ada compiler switch, appended to bhf's own (repeatable). Config
    /// key: `toolchain.ada.switches`.
    #[arg(long = "ada-switch", value_name = "SWITCH", allow_hyphen_values = true)]
    pub(crate) ada_switches: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CEngine {
    /// `make` target - libFuzzer entrypoint (default).
    Libfuzzer,
    /// `make afl` target - AFL++ persistent-mode entrypoint.
    #[value(name = "afl++")]
    AflPlusPlus,
}

pub fn run(args: BuildArgs) -> i32 {
    let toolchain = match resolve_build_toolchain(&args) {
        Ok(toolchain) => toolchain,
        Err(error) => {
            bhfeprintln!("bhf build: {error}");
            return 2;
        }
    };
    if let Some(note) = args
        .toolchain_args
        .config
        .as_deref()
        .and_then(cross_tables_note)
    {
        bhfeprintln!("bhf build: note: {note}");
    }
    // Try the C / C++ make-based build path first. The generated harness
    // ships its own Makefile (Slice A / B of #286); if it's present, the
    // Ada-specific prepare_layout below would fail on the missing
    // src_instrumented dir anyway.
    if let Some(exit) = try_run_c_make_build(&args, &toolchain) {
        return exit;
    }

    let given = args.toolchain_args.c.given_flag_names();
    if !given.is_empty() {
        bhfeprintln!(
            "bhf build: note: {} set the C/C++ toolchain and do not apply to an Ada harness",
            given.join(", ")
        );
    }
    let runner = match ada_build_runner(&toolchain) {
        Ok(runner) => runner,
        Err(error) => {
            bhfeprintln!("bhf build: {error}");
            return 2;
        }
    };
    let runs_natively = crate::toolchain::AdaBuildSettings::from_config(&toolchain).runs_natively();
    // A probe backend from the config file that keeps the events on the
    // target, for a harness built for this host: nothing would read them.
    if args.probe_backend == ProbeBackend::HostFile && runs_natively {
        if let Err(error) = crate::toolchain::check_host_probe_backend(&toolchain) {
            bhfeprintln!("bhf build: {error}");
            return 2;
        }
    }
    let args = with_ada_toolchain(args, &toolchain);

    let layout = match prepare_layout(&args) {
        Ok(layout) => layout,
        Err(error) => {
            bhfeprintln!("{error}");
            return 3;
        }
    };

    let adapter = match ada_compiler_adapter(&args) {
        Ok(adapter) => adapter,
        Err(error) => {
            bhfeprintln!("{error}");
            return 2;
        }
    };

    if let Err(error) = probe_compiler(&adapter) {
        bhfeprintln!("{error}");
        return 2;
    }

    let result = match adapter.build(&layout.project_path) {
        Ok(result) => result,
        Err(error) => {
            bhfeprintln!("{error}");
            return 2;
        }
    };

    print!("{}", result.stdout);
    bhfeprint!("{}", result.stderr);

    if result.exit_code != 0 {
        return 1;
    }
    // The emulator an Ada harness built for another target runs under,
    // recorded beside its binary and beside the harness, as for a C/C++
    // build; a native rebuild forgets one an earlier build recorded.
    if runner.is_some() || runs_natively {
        if let Some(runner) = &runner {
            bhfeprintln!(
                "bhf build: the Ada harness runs under `{}`, recorded in bhf_runner.json",
                std::iter::once(runner.program.display().to_string())
                    .chain(runner.args.iter().cloned())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        for dir in [&layout.exec_dir, &layout.harness_dir] {
            if let Err(error) = crate::gate_evidence::record_runner(dir, runner.as_ref()) {
                bhfeprintln!(
                    "bhf build: warning: could not record the runner in {}: {error}",
                    dir.display()
                );
            }
        }
    }
    0
}

pub(crate) struct BuildLayout {
    pub(crate) project_path: PathBuf,
    /// Where the harness executable is linked (`build/<id>/obj`).
    pub(crate) exec_dir: PathBuf,
    /// The generated harness directory.
    pub(crate) harness_dir: PathBuf,
}

/// The toolchain of this `bhf build`: the `--config` file's `[toolchain]`
/// table with the command-line flags laid over it, validated.
fn resolve_build_toolchain(args: &BuildArgs) -> Result<config::ToolchainConfig, String> {
    let file = match &args.toolchain_args.config {
        Some(path) => crate::toolchain::load_config_file(path)?,
        None => None,
    };
    let mut cli = args.toolchain_args.c.to_config();
    cli.target = args.target.clone();
    cli.runner = args.toolchain_args.runner.clone();
    cli.runner_args = args.toolchain_args.runner_args.clone();
    // `--toolchain <prefix>` names the C/C++ compilers too, unless --cc/--cxx do
    // (a gprconfig compiler name such as `GNAT` is Ada-only).
    if let Some(prefix) = args
        .toolchain
        .as_deref()
        .filter(|toolchain| project_synth::gpr_toolchain_name(toolchain).is_none())
    {
        if cli.cc.is_none() && cli.cxx.is_none() {
            let prefix = prefix.trim_end_matches('-');
            cli.cc = Some(format!("{prefix}-gcc"));
            cli.cxx = Some(format!("{prefix}-g++"));
        }
    }
    cli.ada.prefix = args.toolchain.clone();
    cli.ada.runtime = args.runtime.clone();
    cli.ada.gprbuild = args.toolchain_args.ada_gprbuild.clone();
    cli.ada.gnat = args.toolchain_args.ada_gnat.clone();
    cli.ada.switches = args.toolchain_args.ada_switches.clone();
    if args.probe_backend != ProbeBackend::HostFile {
        cli.ada.probe_backend = Some(
            clap::ValueEnum::to_possible_value(&args.probe_backend).map_or_else(
                || "host_file".to_owned(),
                |value| value.get_name().to_owned(),
            ),
        );
    }
    crate::toolchain::resolve(file, cli)
}

/// The note for a config file whose `[cross.<guard>]` tables `bhf build`
/// does not use (they choose the toolchain of `bhf auto`'s guard-driven cross
/// lanes), or `None` when it has none.
fn cross_tables_note(config: &Path) -> Option<String> {
    let text = fs::read_to_string(config).ok()?;
    let tables = config::cross_config_from_file_text(&text).ok()?;
    if tables.is_empty() {
        return None;
    }
    let names: Vec<String> = tables
        .keys()
        .map(|guard| format!("[cross.{guard}]"))
        .collect();
    Some(format!(
        "{} in {} apply to bhf auto only; bhf build builds with the [toolchain] table \
         (toolchain.target, toolchain.cc/cxx, toolchain.runner)",
        names.join(", "),
        config.display()
    ))
}

/// The runner of a C/C++ build, checked against what the build produces
/// (`built_for`, the triple the compiler builds for when it says): a build
/// for a target this host cannot run, or for one the compiler would not name,
/// records the runner `config` names; a runner for a build this host runs is
/// refused, as `bhf auto` refuses it. `compiler` names the compiler for the
/// message.
fn build_runner(
    config: &config::ToolchainConfig,
    built_for: Option<&str>,
    compiler: &str,
) -> Result<Option<crate::gate_evidence::HarnessRunner>, String> {
    let Some(runner) = config.runner.clone() else {
        return Ok(None);
    };
    if !crate::toolchain::program_exists(&runner) {
        return Err(format!(
            "the toolchain's runner `{runner}` was not found; install it or fix toolchain.runner"
        ));
    }
    let args = match built_for {
        Some(triple) if crate::toolchain::triple_runs_natively(triple) => {
            return Err(format!(
                "toolchain.runner `{runner}` is set, but nothing this build produces targets \
                 another platform: `{compiler}` builds for {triple} (this host); set \
                 toolchain.target (--target) to cross-build the harness, or drop the runner"
            ));
        }
        Some(triple) => {
            crate::toolchain::runner_args(config, &runner, triple, config.sysroot.as_deref())
        }
        // A compiler that does not say what it builds for (a wrapper, some
        // vendor toolchains): the runner is taken as given.
        None => config.runner_args.clone(),
    };
    Ok(Some(crate::gate_evidence::HarnessRunner {
        program: PathBuf::from(&runner),
        args,
    }))
}

/// The runner of an Ada harness, as [`build_runner`] gives one for a C/C++
/// build: an Ada harness built for another target (its Ada target, else the
/// tool prefix) records the runner `config` names; a runner for one this host
/// runs is refused rather than dropped.
fn ada_build_runner(
    config: &config::ToolchainConfig,
) -> Result<Option<crate::gate_evidence::HarnessRunner>, String> {
    let Some(runner) = &config.runner else {
        return Ok(None);
    };
    let settings = crate::toolchain::AdaBuildSettings::from_config(config);
    match settings.effective_target() {
        Some(triple) if !crate::toolchain::triple_runs_natively(&triple) => {
            build_runner(config, Some(&triple), "gprbuild")
        }
        target => Err(format!(
            "toolchain.runner `{runner}` is set, but the Ada harness builds for this host{}; \
             set --target or --toolchain <prefix> (toolchain.ada.target or \
             toolchain.ada.prefix) to cross-build it, or drop the runner",
            target
                .map(|triple| format!(" ({triple})"))
                .unwrap_or_default()
        )),
    }
}

/// `args` with the Ada toolchain fields set from the resolved `[toolchain]`
/// (command-line values already won in [`resolve_build_toolchain`]).
fn with_ada_toolchain(mut args: BuildArgs, toolchain: &config::ToolchainConfig) -> BuildArgs {
    args.target = toolchain.ada_target().map(str::to_owned);
    args.runtime = toolchain.ada.runtime.clone();
    args.toolchain = toolchain.ada.prefix.clone();
    args.probe_backend = crate::toolchain::probe_backend(toolchain);
    args.toolchain_args.ada_gprbuild = toolchain.ada.gprbuild.clone();
    args.toolchain_args.ada_gnat = toolchain.ada.gnat.clone();
    args.toolchain_args.ada_switches = toolchain.ada.switches.clone();
    args
}

/// A config file's `toolchain.ada.prefix` does not choose a C/C++ harness's
/// compilers (the `--toolchain` flag does). The note saying so, when nothing
/// else chose them.
fn ada_prefix_note(
    toolchain: &config::ToolchainConfig,
    toolchain_flag: Option<&str>,
    harness_id: &str,
) -> Option<String> {
    let prefix = toolchain.ada.prefix.as_deref()?;
    if toolchain_flag.is_some() || crate::toolchain::selected_compilers(toolchain) != (None, None) {
        return None;
    }
    Some(format!(
        "toolchain.ada.prefix `{prefix}` applies to Ada harnesses only; set toolchain.target \
         or toolchain.cc/cxx (or pass --toolchain) to choose the compilers of the C/C++ \
         harness '{harness_id}'"
    ))
}

/// The Ada flags given to a C/C++ harness build, which cannot apply to it.
fn ada_only_flags_given(args: &BuildArgs) -> Vec<&'static str> {
    let mut given = Vec::new();
    if args.runtime.is_some() {
        given.push("--runtime");
    }
    if args.probe_backend != ProbeBackend::HostFile {
        given.push("--probe-backend");
    }
    if args.toolchain_args.ada_gprbuild.is_some() {
        given.push("--ada-gprbuild");
    }
    if args.toolchain_args.ada_gnat.is_some() {
        given.push("--ada-gnat");
    }
    if !args.toolchain_args.ada_switches.is_empty() {
        given.push("--ada-switch");
    }
    given
}

/// The compiler adapter for an Ada build: explicit `gprbuild`/`gnat` programs
/// when the toolchain names them, else the (prefixed) tools on `PATH`.
fn ada_compiler_adapter(args: &BuildArgs) -> Result<CompilerAdapter, String> {
    let toolchain = toolchain_config(args);
    let explicit_gprbuild = args.toolchain_args.ada_gprbuild.as_deref();
    let explicit_gnat = args.toolchain_args.ada_gnat.as_deref();
    let prefixed = |tool: &str| match toolchain.compiler_prefix() {
        Some(prefix) => format!("{}-{tool}", prefix.trim_end_matches('-')),
        None => tool.to_owned(),
    };
    if explicit_gprbuild.is_none() && explicit_gnat.is_none() {
        return match CompilerAdapter::discover_for(toolchain.clone()) {
            Ok(adapter) => Ok(adapter),
            // A GNAT cross toolchain ships prefixed compiler drivers
            // (`<prefix>-gnat`, `<prefix>-gcc`), while gprbuild is usually one
            // multi-target program that takes the target from the project's
            // `for Target use`. Use it when there is no prefixed gprbuild.
            Err(error) => match (
                toolchain.compiler_prefix(),
                which::which("gprbuild"),
                which::which(prefixed("gnat")),
            ) {
                (Some(_), Ok(gprbuild), Ok(gnat)) => Ok(CompilerAdapter::with_binaries(
                    Some(gprbuild),
                    which::which(prefixed("gnatmake")).ok(),
                    Some(gnat),
                    toolchain,
                )),
                _ => Err(error.to_string()),
            },
        };
    }
    let locate = |explicit: Option<&str>, tool: &str| -> Result<Option<PathBuf>, String> {
        match explicit {
            Some(program) => {
                let found = if crate::toolchain::program_exists(program) {
                    which::which(program)
                        .ok()
                        .or_else(|| Some(PathBuf::from(program)))
                } else {
                    None
                };
                found
                    .map(Some)
                    .ok_or_else(|| format!("the toolchain's {tool} `{program}` was not found"))
            }
            None => Ok(which::which(prefixed(tool)).ok()),
        }
    };
    let gprbuild = locate(explicit_gprbuild, "gprbuild")?;
    let gnat = locate(explicit_gnat, "gnat")?;
    if gprbuild.is_none() {
        return Err(format!(
            "no `{}` found for the Ada build; set toolchain.ada.gprbuild (--ada-gprbuild)",
            prefixed("gprbuild")
        ));
    }
    // An explicitly named gnat is the compiler the operator wants probed; only
    // without one does a prefixed gnatmake stand in for the canary.
    let gnatmake = explicit_gnat
        .is_none()
        .then(|| which::which(prefixed("gnatmake")).ok())
        .flatten();
    Ok(CompilerAdapter::with_binaries(
        gprbuild, gnatmake, gnat, toolchain,
    ))
}

/// Whether `dir` directly contains at least one C source file (`.c`). Used to
/// decide whether the generated Ada project must also declare the C language so
/// gprbuild compiles + links the C glue a real Ada library binds to. Non-recursive
/// because the generated project lists each source dir explicitly (no `**`).
fn dir_contains_c_source(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("c"))
            })
        })
        .unwrap_or(false)
}

/// Whether a staged source directory contains an explicit implementation of a
/// predefined Ada hierarchy. Alternate runtime projects intentionally provide
/// `Ada.*`/`System.*` units; GNAT requires implementation mode (`-gnatg`) to
/// compile those bodies. Structural parsing avoids triggering on comments or on
/// ordinary files that merely `with` a runtime unit.
fn dir_contains_in_tree_ada_runtime_unit(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let path = entry.path();
            if !path.extension().is_some_and(|extension| {
                extension.eq_ignore_ascii_case("ads") || extension.eq_ignore_ascii_case("adb")
            }) {
                return false;
            }
            let Ok(source) = crate::source_text::read_source_text(&path) else {
                return false;
            };
            let Ok(ast) = ada_parser::reconcile::build_structural_ast(&source, None, &path) else {
                return false;
            };
            ast.packages.iter().any(|package| {
                let root = package.name.split('.').next().unwrap_or(&package.name);
                matches!(
                    root.to_ascii_lowercase().as_str(),
                    "ada" | "system" | "interfaces" | "gnat"
                )
            })
        })
    })
}

/// C source *base names* in the source closure whose stem matches an Ada
/// `.ads`/`.adb` stem — these would collide on `<stem>.o`, which gprbuild rejects
/// ("... have the same object file name"). Returned for `Excluded_Source_Files`
/// so the Ada unit (the harness target) wins. Non-recursive to match the gpr's
/// literal `Source_Dirs` and the flat `src_instrumented/` layout; stems compared
/// case-insensitively (GNAT object names are the lowercased base stem).
fn colliding_c_basenames(roots: &[SourceRoot]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut ada_stems = BTreeSet::new();
    let mut c_files: Vec<(String, String)> = Vec::new(); // (stem, basename)
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root.path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let (Some(stem), Some(ext)) = (path.file_stem(), path.extension()) else {
                continue;
            };
            let stem = stem.to_string_lossy().to_ascii_lowercase();
            if ext.eq_ignore_ascii_case("ads") || ext.eq_ignore_ascii_case("adb") {
                ada_stems.insert(stem);
            } else if ext.eq_ignore_ascii_case("c") {
                if let Some(name) = path.file_name() {
                    c_files.push((stem, name.to_string_lossy().into_owned()));
                }
            }
        }
    }
    let mut out: Vec<String> = c_files
        .into_iter()
        .filter(|(stem, _)| ada_stems.contains(stem))
        .map(|(_, name)| name)
        .collect();
    out.sort();
    out.dedup();
    out
}

pub(crate) fn prepare_layout(args: &BuildArgs) -> Result<BuildLayout, String> {
    let work_dir = absolutize(&args.work_dir)?;
    if !work_dir.is_dir() {
        return Err(format!("work dir '{}' does not exist", work_dir.display()));
    }

    let source_dir = work_dir.join("src_instrumented");
    if !source_dir.is_dir() {
        return Err(format!(
            "work dir malformed: missing {}",
            source_dir.display()
        ));
    }

    let (harness_id, harness_dir) = select_harness(&work_dir, args.harness.as_deref())?;
    // Usually `main.adb` (`procedure Main`). A private-child-subprogram harness
    // (for a target whose signature uses parent-private types) is instead
    // `<parent>-bhf_harness.adb`; detect it and the gpr renames its executable to
    // `main` so the rest of the pipeline finds `obj/main` unchanged.
    let main_file = detect_harness_main_file(&harness_dir).ok_or_else(|| {
        format!(
            "work dir malformed: no main.adb or *-bhf_harness.adb in {}",
            harness_dir.display()
        )
    })?;

    let build_dir = work_dir.join("build").join(&harness_id);
    let ada_standard = detect_ada_standard(&source_dir, &work_dir)?;
    let obj_dir = build_dir.join("obj");
    fs::create_dir_all(&obj_dir)
        .map_err(|error| format!("create build directory '{}': {error}", obj_dir.display()))?;
    // Every harness in a sweep compiles the SAME project closure — only the main
    // and the stub set differ — so a per-harness object directory made a project
    // with N targets compile its units N times. Share one object directory across
    // the run and let gprbuild's own staleness check decide what to redo; the
    // executable stays in the per-harness `obj/` (via `Exec_Dir`) so a later
    // target's link cannot overwrite a binary an earlier finding replays against.
    let shared_obj_dir = work_dir.join(SHARED_ADA_OBJ_DIR);
    fs::create_dir_all(&shared_obj_dir).map_err(|error| {
        format!(
            "create shared object directory '{}': {error}",
            shared_obj_dir.display()
        )
    })?;

    let mut source_roots = vec![
        SourceRoot {
            path: source_dir,
            language: "Ada".to_owned(),
        },
        SourceRoot {
            path: harness_dir.clone(),
            language: "Ada".to_owned(),
        },
    ];
    let fake_corba_dir = work_dir.join("fake_corba");
    if fake_corba_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: fake_corba_dir,
            language: "Ada".to_owned(),
        });
    }
    let global_stubs_dir = work_dir.join("generated_stubs");
    if global_stubs_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: global_stubs_dir,
            language: "Ada".to_owned(),
        });
    }
    let auto_repair_stubs_dir = crate::auto::layout::harness_dir(&work_dir, &harness_id)
        .join("repairs")
        .join(crate::auto::repair::AUTO_ADA_STUBS_DIR);
    if auto_repair_stubs_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: auto_repair_stubs_dir,
            language: "Ada".to_owned(),
        });
    }
    let external_stubs_dir = work_dir.join(SHARED_ADA_STUBS_DIR);
    if external_stubs_dir.is_dir() {
        source_roots.push(SourceRoot {
            path: external_stubs_dir,
            language: "Ada".to_owned(),
        });
    }

    let runtime_project_path = build_dir.join("adafuzz_runtime.gpr");
    write_runtime_project(&runtime_project_path, &build_dir, args.probe_backend).map_err(
        |error| {
            format!(
                "write runtime project '{}': {error}",
                runtime_project_path.display()
            )
        },
    )?;

    // Forward `with "<x>.gpr";` clauses from any user-supplied .gpr
    // files in the source root into our generated build project.
    // When a forwarded import resolves cleanly it's a no-op; when it
    // resolves to a missing path, gprbuild fails with "cannot find
    // <x>.gpr" which build_classifier maps to MissingGprImport so the
    // upstream maintainer sees the dependency they need to ship.
    let mut with_clauses = vec![PathBuf::from("adafuzz_runtime.gpr")];
    // <work_dir>/.. is the source root the auto CLI was pointed at;
    // for the standalone build path it's the project directory the
    // user invoked bhf against. Either way that's where the
    // user's *.gpr files live.
    let user_root = work_dir
        .parent()
        .unwrap_or(work_dir.as_path())
        .to_path_buf();
    // An extended project keeps all of its imports, and GPR has no way for the
    // child project to subtract one. Do not extend a project that imports
    // `adafuzz.gpr`: this build already supplies `adafuzz_runtime.gpr`, while a
    // stale relative AdaFuzz import either fails at the parent's original path
    // or creates duplicate runtime units. The instrumented source overlay still
    // carries the target sources, and the normal import-forwarder below keeps
    // every non-AdaFuzz dependency visible.
    // Offline-legacy audit #1/#7: never EXTEND a library, aggregate, or abstract
    // project. GNAT rejects extending a library project without `Library_Dir`
    // (and it can't hold the harness `Main`), an aggregate can't be extended at
    // all, and an abstract project has no sources — each aborts the whole build,
    // so an entire class of real Alire/GNAT library repos never fuzzes. The
    // instrumented source overlay already carries the governing project's
    // Source_Dirs, so those cases build as a standalone project with the user's
    // dependency imports forwarded below.
    let extends_project = args
        .source_project
        .as_ref()
        .filter(|project| !gpr_imports_adafuzz(project))
        .filter(|project| crate::auto::gpr_scenario::gpr_is_extendable_base(project))
        .cloned();
    if extends_project.is_none() {
        with_clauses.extend(discover_user_gpr_with_clauses(&user_root));
    }
    // The governing project's own `package Compiler` is extended, not
    // replaced: its switches stay, and bhf's follow them.
    let parent_compiler = extends_project
        .as_deref()
        .and_then(project_synth::parent_compiler_package);
    if let Some(parent) = &parent_compiler {
        bhfeprintln!(
            "bhf build: note: the harness project extends {}'s package Compiler; bhf's \
             switches follow its Default_Switches (\"Ada\"){}",
            parent.project_name,
            if parent.ada_switches.is_empty() {
                String::new()
            } else {
                format!(": {}", parent.ada_switches.join(" "))
            }
        );
    }

    let project_path = build_dir.join("bhf_build.gpr");
    // A non-`main.adb` main (a child-subprogram harness) gets its executable
    // renamed to `main` so the downstream `obj/main` path is unchanged.
    let executable_name = (main_file != "main.adb").then(|| "main".to_owned());
    // #412: instrument the target+harness compile (NOT the uninstrumented runtime
    // project) with `-fsanitize-coverage=trace-pc` so the AdaFuzz trace-pc callback
    // records edge coverage and the engine fuzzes coverage-guided instead of blind.
    // Gated behind a cached probe of the Ada gcc: GNAT/GCC that lacks trace-pc
    // degrades to today's behavior (no flag, coverage_edges=0) rather than breaking
    // the build. A sentinel next to the build dir tells the fuzz engine the harness
    // is coverage-instrumented so it engages its CoverageTracker.
    let mut switches = Switches::default();
    let ada_cov_instrumented = ada_trace_pc_supported(&toolchain_config(args));
    if ada_cov_instrumented {
        switches.default.push(ADA_COV_TRACE_PC_FLAG.to_owned());
    }
    // Enable Ada 2012 assertion checks (-gnata): a failed precondition, postcondition,
    // type invariant, or `pragma Assert` raises Assertion_Error, which the exception
    // oracle reports as a contract violation (BHF-557). This turns the target's OWN
    // specification into a fuzzing oracle — code that ships with assertions disabled
    // still gets them exercised under the fuzzer, at no cost to production behavior.
    switches.default.push("-gnata".to_owned());
    // Operator switches (`toolchain.ada.switches`, --ada-switch) come after
    // bhf's own, so an operator setting wins where the two disagree.
    switches
        .default
        .extend(args.toolchain_args.ada_switches.iter().cloned());
    if source_roots
        .iter()
        .any(|root| dir_contains_in_tree_ada_runtime_unit(&root.path))
    {
        // `-gnatg` authorizes compilation of predefined-hierarchy units. It also
        // enables GNAT's own style profile, which is inappropriate for generated
        // harness/runtime support, so cancel style checks while retaining the
        // implementation-unit semantics.
        switches.default.push("-gnatg".to_owned());
        switches.default.push("-gnatyN".to_owned());
        switches.default.push("-gnatws".to_owned());
    }
    // Declare C in the project when any source dir carries C glue (copied in by
    // ensure_ada_src_instrumented from a real Ada library's bindings — gnatcoll's
    // gnatcoll_support.c / libc-wrappers.c). Without this gprbuild skips the .c and
    // the Ada link fails on the bound C symbols (gnatcoll_mmap, __gnatcoll_open, …).
    let compile_c = source_roots
        .iter()
        .any(|root| dir_contains_c_source(&root.path));
    // A C source that shares its stem with an Ada body/spec in the closure would
    // collide on object-file name (`sxxx.adb` + `sxxx.c` -> `sxxx.o`) and gprbuild
    // rejects the whole project. Exclude the C file — the Ada unit is the harness
    // target and must win. Only reachable when C is actually compiled.
    let excluded_source_files = if compile_c {
        colliding_c_basenames(&source_roots)
    } else {
        Vec::new()
    };
    let spec = ProjectSpec {
        project_name: "Bhf_Build".to_owned(),
        extends_project,
        parent_compiler,
        source_roots,
        object_dir: shared_obj_dir,
        exec_dir: Some(obj_dir.clone()),
        main_adb: Some(main_file),
        ada_standard,
        target: args.target.clone(),
        runtime: args.runtime.clone(),
        toolchain: args.toolchain.clone(),
        switches,
        with_clauses,
        executable_name,
        compile_c,
        excluded_source_files,
    };
    write_project(&spec, &project_path)
        .map_err(|error| format!("write project '{}': {error}", project_path.display()))?;

    // Force-fuzz: copy any synthesized stub `.gpr` for a missing external `with`ed
    // project (repairs/gpr_stubs/*.gpr) NEXT TO bhf_build.gpr, so gprbuild
    // resolves the import from the root project's directory and the project LOADS.
    // The repair loop then stubs the packages the code actually uses from it.
    // Copied every round because prepare_layout owns the build dir.
    let gpr_stubs_dir = crate::auto::layout::harness_dir(&work_dir, &harness_id)
        .join("repairs")
        .join(crate::auto::repair::AUTO_GPR_STUBS_DIR);
    if let Ok(entries) = fs::read_dir(&gpr_stubs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("gpr"))
            {
                if let Some(name) = path.file_name() {
                    let _ = fs::copy(&path, build_dir.join(name));
                }
            }
        }
    }

    // Drop / refresh the coverage sentinel to match what we actually emitted, so a
    // rebuild on a toolchain that lost trace-pc support doesn't leave a stale flag.
    let sentinel = build_dir.join(ADA_COV_SENTINEL);
    if ada_cov_instrumented {
        fs::write(&sentinel, b"trace-pc\n").map_err(|error| {
            format!("write coverage sentinel '{}': {error}", sentinel.display())
        })?;
    } else {
        let _ = fs::remove_file(&sentinel);
    }

    Ok(BuildLayout {
        project_path,
        exec_dir: obj_dir,
        harness_dir,
    })
}

/// Walk `root` for top-level `.gpr` files and extract their
/// `with "...";` clauses to forward into the generated
/// `bhf_build.gpr`.
///
/// Relative imports are resolved against `root` (the directory of the
/// `.gpr` they were read from — these are top-level gprs sitting
/// directly in `root`) and lexically normalized into ABSOLUTE paths.
/// This is load-bearing: `bhf_build.gpr` lives at
/// `<work_dir>/build/<id>/`, a *different* directory depth than the
/// source gpr the clause came from, and gprbuild resolves a `with`
/// clause relative to the IMPORTING project's own directory. A clause
/// kept relative therefore resolves against the wrong base and the
/// `../` depth comes out wrong (work-dir-depth dependent), which is
/// the #411 bug. Absolutizing makes the forwarded clause
/// depth-independent. Already-absolute imports are normalized but
/// otherwise preserved. We deliberately do NOT `canonicalize`: a
/// genuinely-missing user dependency need not exist on disk, and we
/// still want the absolute *intended* path so the resulting
/// "imported project file not found" diagnostic names the real
/// location.
///
/// Imports of bhf's own bundled runtime (`ada_runtime/adafuzz.gpr`)
/// are skipped entirely: `prepare_layout` always adds the build-local
/// `adafuzz_runtime.gpr` to the with-clauses, which already provides
/// the AdaFuzz runtime units. Re-forwarding the bundled `adafuzz.gpr`
/// is redundant and is precisely the #411 trigger — depending on the
/// work-dir depth it either fails to resolve (reported as a missing
/// `adafuzz.gpr` import) or resolves and collides with
/// `adafuzz_runtime.gpr` ("unit ... cannot belong to several
/// projects"). Genuine user deps with other names are still forwarded
/// (now absolutized).
///
/// Subdirectories are skipped — we only want the project's
/// root-level user gprs, not the generated build/* gprs we created
/// ourselves.
fn discover_user_gpr_with_clauses(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let with_re = regex::Regex::new(r#"with\s+"([^"]+\.gpr)"\s*;"#).expect("regex");
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_file = path.is_file();
        let is_gpr = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("gpr"));
        if !is_file || !is_gpr {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for caps in with_re.captures_iter(&text) {
            let imported = PathBuf::from(&caps[1]);
            // Never re-forward bhf's bundled runtime: the build-local
            // adafuzz_runtime.gpr (added in prepare_layout) already provides
            // those units, so forwarding it is redundant and breaks the
            // build (#411 — missing-import or duplicate-unit, depending on
            // work-dir depth).
            if imported
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("adafuzz.gpr"))
            {
                continue;
            }
            // Absolutize relative imports against the source gpr's own dir so
            // the forwarded clause is depth-independent when written into
            // bhf_build.gpr at its deeper build/<id>/ location (#411).
            let resolved = if imported.is_absolute() {
                normalize_path_lexical(&imported)
            } else {
                normalize_path_lexical(&root.join(&imported))
            };
            out.push(resolved);
        }
    }
    out
}

fn gpr_imports_adafuzz(project: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(project) else {
        return false;
    };
    let with_re = regex::Regex::new(r#"with\s+"([^"]+\.gpr)"\s*;"#).expect("regex");
    let imports_runtime = with_re.captures_iter(&text).any(|caps| {
        Path::new(&caps[1])
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("adafuzz.gpr"))
    });
    imports_runtime
}

/// Lexically collapse `.`/`..` components of `path` without touching
/// the filesystem. Unlike `std::fs::canonicalize` this neither requires
/// the path to exist nor resolves symlinks — we want the absolute
/// *intended* path even for a dependency the user has not shipped yet.
fn normalize_path_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Detect a C/C++ harness layout (generated by Slice A/B of #286) and run
/// the harness's Makefile directly. Returns `Some(exit_code)` when the
/// build was dispatched; `None` to fall through to the Ada path.
fn try_run_c_make_build(args: &BuildArgs, toolchain: &config::ToolchainConfig) -> Option<i32> {
    let requested_dir = absolutize(&args.work_dir).ok()?;
    let (work_dir, requested_harness) =
        match resolve_c_family_work_dir(&requested_dir, args.harness.as_deref()) {
            Ok(resolved) => resolved,
            Err(error) => {
                bhfeprintln!("{error}");
                return Some(3);
            }
        };
    if !work_dir.is_dir() {
        return None;
    }
    let (harness_id, harness_dir) = match select_harness(&work_dir, requested_harness.as_deref()) {
        Ok(selected) => selected,
        Err(error) => {
            // An Ada work dir reports through `prepare_layout`. Anything else —
            // a C/C++ harness root, or no `src_instrumented` at all — gets the
            // lookup error itself rather than a misleading Ada layout complaint.
            if work_dir.join("src_instrumented").is_dir() && !has_c_family_harness(&work_dir) {
                return None;
            }
            bhfeprintln!("{error}");
            bhfeprintln!("{C_FAMILY_BUILD_LAYOUT_HINT}");
            return Some(3);
        }
    };
    if !is_c_family_harness_dir(&harness_dir) {
        return None;
    }

    // Ada flags given for a C/C++ harness would be silently meaningless; say so
    // and point at the flags that do apply.
    let ada_only = ada_only_flags_given(args);
    if !ada_only.is_empty() {
        bhfeprintln!(
            "bhf build: {} appl{} only to Ada harnesses; '{harness_id}' is a C/C++ harness. \
             Choose its toolchain with --cc/--cxx, --target, --toolchain <prefix>, --cflags, \
             --sysroot, or a [toolchain] table in --config.",
            ada_only.join(", "),
            if ada_only.len() == 1 { "ies" } else { "y" }
        );
        return Some(2);
    }
    if let Some(note) = ada_prefix_note(toolchain, args.toolchain.as_deref(), &harness_id) {
        bhfeprintln!("bhf build: note: {note}");
    }
    match crate::toolchain::publish(toolchain) {
        Ok(published) => {
            for note in published.notes {
                bhfeprintln!("bhf build: {note}");
            }
        }
        Err(error) => {
            bhfeprintln!("bhf build: {error}");
            return Some(2);
        }
    }
    // What the build produces: a binary for the toolchain's target, or for
    // whatever the selected compiler builds for (a prefixed or cross --cc).
    let compiler = {
        let effective = crate::toolchain::effective_compilers();
        if harness_dir.join("main.cpp").is_file() {
            effective.cxx
        } else {
            effective.cc
        }
    };
    let built_for = toolchain
        .target
        .clone()
        .or_else(|| crate::toolchain::compiler_target_triple(&compiler));
    let foreign = built_for
        .as_deref()
        .filter(|triple| !crate::toolchain::triple_runs_natively(triple));
    let runner = match build_runner(toolchain, built_for.as_deref(), &compiler) {
        Ok(runner) => runner,
        Err(error) => {
            bhfeprintln!("bhf build: {error}");
            return Some(2);
        }
    };
    let runs_natively = built_for
        .as_deref()
        .is_some_and(crate::toolchain::triple_runs_natively);
    if let (None, Some(runner)) = (foreign, &runner) {
        bhfeprintln!(
            "bhf build: `{compiler}` does not say which target it builds for; '{harness_id}' \
             runs under `{}` as configured, recorded in bhf_runner.json",
            std::iter::once(runner.program.display().to_string())
                .chain(runner.args.iter().cloned())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    if let Some(triple) = foreign {
        match &runner {
            Some(runner) => bhfeprintln!(
                "bhf build: building '{harness_id}' for {triple}; it runs under `{}`, recorded \
                 in bhf_runner.json beside the binary",
                std::iter::once(runner.program.display().to_string())
                    .chain(runner.args.iter().cloned())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            None => bhfeprintln!(
                "bhf build: building '{harness_id}' for {triple}; run it under an emulator \
                 (set toolchain.runner or --runner to record one, or run `bhf replay \
                 --qemu-user <qemu> --qemu-arg=-L --qemu-arg=<sysroot>`)"
            ),
        }
    }

    // Mirror the Ada path's `build/<harness-id>/main` layout so `bhf fuzz`
    // and the existing find_harness_executable helper find the binary.
    let build_dir = work_dir.join("build").join(&harness_id);
    if let Err(error) = fs::create_dir_all(&build_dir) {
        bhfeprintln!("create build directory '{}': {error}", build_dir.display());
        return Some(2);
    }

    let (make_target, built_name, staged_name) = match args.c_engine {
        CEngine::Libfuzzer => (Some("main"), "main", "main"),
        CEngine::AflPlusPlus => (Some("afl"), "main_afl", "main_afl"),
    };
    bhfeprintln!(
        "Building C/C++ harness '{}' via make{}",
        harness_id,
        make_target.map(|t| format!(" {t}")).unwrap_or_default()
    );
    let mut cmd = std::process::Command::new("make");
    cmd.current_dir(&harness_dir);
    if let Some(t) = make_target {
        cmd.arg(t);
    }
    let force_includes = repair_force_includes(&harness_dir);
    apply_c_family_make_env(&mut cmd, &[], &[], &force_includes, None);
    // Bounded and process-grouped: an unbounded `status()` here let one spinning
    // compile consume a whole campaign and outlive bhf entirely. The output is
    // shown as it arrives and also kept, so a failed build can be explained.
    let output = crate::command_output::output_with_timeout_teed(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    );
    match output {
        Ok((_, true)) => {
            bhfeprintln!("invoke make: timed out");
            Some(2)
        }
        Ok((out, false)) if out.status.success() => {
            let built = harness_dir.join(built_name);
            if built.is_file() {
                let dest = build_dir.join(staged_name);
                if let Err(error) = fs::copy(&built, &dest) {
                    bhfeprintln!(
                        "copy '{}' -> '{}': {error}",
                        built.display(),
                        dest.display()
                    );
                    return Some(2);
                }
                bhfeprintln!("built harness binary -> {}", dest.display());
                // The emulator a foreign binary runs under, recorded beside it
                // (and beside the harness) for the commands that run it. A
                // native rebuild forgets one an earlier build recorded.
                if runner.is_some() || runs_natively {
                    for dir in [&build_dir, &harness_dir] {
                        if let Err(error) =
                            crate::gate_evidence::record_runner(dir, runner.as_ref())
                        {
                            bhfeprintln!(
                                "bhf build: warning: could not record the runner in {}: {error}",
                                dir.display()
                            );
                        }
                    }
                }
                if cfg!(windows) {
                    let path = std::env::var_os("PATH");
                    stage_sanitizer_runtime(&harness_dir, path.as_deref());
                    stage_sanitizer_runtime(&build_dir, path.as_deref());
                }
            } else {
                bhfeprintln!(
                    "make reported success but did not produce expected harness binary '{}'",
                    built.display()
                );
                return Some(2);
            }
            Some(0)
        }
        Ok((out, false)) => {
            bhfeprintln!("make exited with status {:?}", out.status.code());
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let inherited = RebuildEnv::inherited();
            for line in
                c_build_failure_hints(&work_dir, &harness_id, &harness_dir, &text, &inherited)
            {
                bhfeprintln!("{line}");
            }
            Some(1)
        }
        Err(error) => {
            bhfeprintln!("invoke make: {error}");
            Some(2)
        }
    }
}

const C_FAMILY_BUILD_LAYOUT_HINT: &str = "hint: bhf build takes the work directory that holds \
     the harness as harnesses/<id>/ or generated_harnesses/<id>/ (generate it with \
     `bhf generate-harness <source> --target <name> --output <work>/harnesses`), then run \
     `bhf build <work> --harness <id>`";

/// Whether `dir` is a generated C/C++ harness directory (a Makefile beside
/// `main.c` or `main.cpp`).
fn is_c_family_harness_dir(dir: &Path) -> bool {
    dir.join("Makefile").is_file()
        && (dir.join("main.c").is_file() || dir.join("main.cpp").is_file())
}

/// Whether `root` directly holds at least one C/C++ harness directory.
fn root_holds_c_family_harness(root: &Path) -> bool {
    fs::read_dir(root).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.path().is_dir() && is_c_family_harness_dir(&entry.path()))
    })
}

/// Whether either harness root of `work_dir` holds a C/C++ harness.
fn has_c_family_harness(work_dir: &Path) -> bool {
    harness_roots(work_dir)
        .iter()
        .any(|root| root_holds_c_family_harness(root))
}

fn is_harness_root_name(dir: &Path) -> bool {
    dir.file_name().is_some_and(|name| {
        name == crate::auto::layout::HARNESSES_DIR
            || name == crate::auto::layout::GENERATED_HARNESSES_DIR
    })
}

/// Map the directory given to `bhf build` onto the work directory and harness
/// id. Besides a work directory, it accepts a C/C++ harness directory itself
/// (`<work>/harnesses/<id>`) and a harness root (`<work>/harnesses`, which is
/// what `generate-harness --output` names), printing the equivalent canonical
/// invocation. A harness directory that is not inside a work layout is an
/// error naming the layout `bhf build` expects.
fn resolve_c_family_work_dir(
    dir: &Path,
    harness: Option<&str>,
) -> Result<(PathBuf, Option<String>), String> {
    let unchanged = || Ok((dir.to_path_buf(), harness.map(str::to_owned)));
    if !dir.is_dir() || dir.join("src_instrumented").is_dir() {
        return unchanged();
    }
    if is_c_family_harness_dir(dir) {
        let id = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(requested) = harness.filter(|requested| *requested != id) {
            return Err(format!(
                "{} is the harness directory of '{id}', but --harness asks for '{requested}'; \
                 pass the work directory instead",
                dir.display()
            ));
        }
        let work = dir
            .parent()
            .filter(|root| is_harness_root_name(root))
            .and_then(Path::parent);
        let Some(work) = work else {
            return Err(format!(
                "{} is a harness directory, but bhf build expects the work directory that \
                 holds it as harnesses/<id>/ (or generated_harnesses/<id>/); generate it there \
                 with `bhf generate-harness ... --output <work>/harnesses`, then run \
                 `bhf build <work> --harness {id}`",
                dir.display()
            ));
        };
        bhfeprintln!(
            "note: {} is a harness directory; building it as `bhf build {} --harness {id}`",
            dir.display(),
            work.display()
        );
        return Ok((work.to_path_buf(), Some(id)));
    }
    if is_harness_root_name(dir)
        && root_holds_c_family_harness(dir)
        && !harness_roots(dir).iter().any(|root| root.is_dir())
    {
        if let Some(work) = dir.parent() {
            bhfeprintln!(
                "note: {} holds harness directories; using its parent {} as the work directory",
                dir.display(),
                work.display()
            );
            return Ok((work.to_path_buf(), harness.map(str::to_owned)));
        }
    }
    unchanged()
}

/// The symbols a failed link reported as undefined, in first-seen order:
/// GNU ld (`undefined reference to `sym'`) and lld (`undefined symbol: sym`).
fn undefined_symbols_in(output: &str) -> Vec<String> {
    const MAX_SYMBOLS: usize = 64;
    let mut symbols: Vec<String> = Vec::new();
    for line in output.lines() {
        // link.exe / lld-link (`unresolved external symbol NAME`) first: the
        // lld spelling below would otherwise keep the `>>>` decoration.
        let msvc = build_classifier::gcc_clang::msvc_unresolved_symbol(line);
        let symbol = msvc
            .as_deref()
            .or_else(|| {
                line.split_once("undefined reference to `")
                    .and_then(|(_, rest)| rest.rsplit_once('\''))
                    .map(|(symbol, _)| symbol)
            })
            .or_else(|| {
                line.split_once("undefined symbol: ")
                    .map(|(_, rest)| rest.trim())
            });
        let Some(symbol) = symbol.map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        if !symbols.iter().any(|known| known == symbol) {
            symbols.push(symbol.to_owned());
            if symbols.len() == MAX_SYMBOLS {
                break;
            }
        }
    }
    symbols
}

/// Split a Makefile recipe or an `AUTO_EXTRA_SOURCES` value into words,
/// honouring the double/single quotes generated recipes put around paths with
/// spaces.
fn recipe_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in text.chars() {
        match (quote, ch) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => quote = Some(ch),
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            (None, c) => current.push(c),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// The target sources the harness Makefile compiles into `main` (the operands
/// after `main.c`/`main.cpp` on the `main:` recipe), and the first `-iquote`
/// include directory, which is the target's own directory.
fn makefile_target_context(harness_dir: &Path) -> (Vec<PathBuf>, Option<PathBuf>) {
    let Ok(text) = fs::read_to_string(harness_dir.join("Makefile")) else {
        return (Vec::new(), None);
    };
    let mut sources = Vec::new();
    let mut target_dir = None;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if let Some(includes) = line.strip_prefix("INCLUDES = ") {
            let words = recipe_words(includes);
            target_dir = words
                .iter()
                .position(|word| word == "-iquote")
                .and_then(|index| words.get(index + 1))
                .map(PathBuf::from);
        } else if line.starts_with("main:") {
            let Some(recipe) = lines.next() else {
                break;
            };
            let words = recipe_words(recipe);
            if let Some(start) = words
                .iter()
                .position(|word| word == "main.c" || word == "main.cpp")
            {
                sources = words[start + 1..]
                    .iter()
                    .take_while(|word| !word.starts_with("$("))
                    .map(PathBuf::from)
                    .collect();
            }
        }
    }
    (sources, target_dir)
}

/// The include directories a harness Makefile searches for the target
/// (`-iquote <dir>` in its `INCLUDES`), in order.
fn makefile_include_dirs(harness_dir: &Path) -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string(harness_dir.join("Makefile")) else {
        return Vec::new();
    };
    let Some(includes) = text
        .lines()
        .find_map(|line| line.strip_prefix("INCLUDES = "))
    else {
        return Vec::new();
    };
    let words = recipe_words(includes);
    words
        .windows(2)
        .filter(|pair| pair[0] == "-iquote")
        .map(|pair| PathBuf::from(&pair[1]))
        .collect()
}

/// The `--extra-source` files, `--extra-include` dirs and `--source-root`s
/// generation recorded in the harness's `generation-metadata.json`.
fn recorded_build_inputs(harness_dir: &Path) -> Vec<PathBuf> {
    let Ok(bytes) = fs::read(harness_dir.join("generation-metadata.json")) else {
        return Vec::new();
    };
    let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    ["extra_sources", "extra_includes", "source_roots"]
        .iter()
        .filter_map(|key| metadata.get(*key).and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(PathBuf::from)
        .collect()
}

/// Every directory to look in for the definitions of a failed link's
/// undefined symbols: [`definition_search_root`] around the target first,
/// then the directories of the harness's other inputs — each source its
/// Makefile compiles, each include dir it searches, and the extra sources,
/// extra include dirs and source roots generation recorded — so a library
/// kept beside the harness outside any checkout (`harness/` + `lib/`) is
/// searched too. A directory inside one already listed, or inside the work
/// dir, is left out, and so is one that would take the sources indexed in
/// all past [`MAX_INDEXED_SOURCES`].
fn definition_search_roots(target_dir: &Path, harness_dir: &Path, work_dir: &Path) -> Vec<PathBuf> {
    // Resolved as the caller resolves the work dir and the linked sources,
    // without Windows' `\\?\` prefix: the roots are shown in a hint.
    let canonical = crate::workdir::plain_canonical;
    let primary = canonical(&definition_search_root(target_dir));
    let mut budget =
        MAX_INDEXED_SOURCES.saturating_sub(c_family_source_count(&primary, MAX_INDEXED_SOURCES));
    let (sources, _) = makefile_target_context(harness_dir);
    let mut candidates: Vec<PathBuf> = sources
        .iter()
        .filter_map(|source| source.parent().map(Path::to_path_buf))
        .collect();
    candidates.extend(makefile_include_dirs(harness_dir));
    for input in recorded_build_inputs(harness_dir) {
        if input.is_file() {
            candidates.extend(input.parent().map(Path::to_path_buf));
        } else {
            candidates.push(input);
        }
    }
    // Shallowest first, so a directory is skipped when one containing it
    // is already searched.
    let mut candidates: Vec<PathBuf> = candidates.iter().map(|dir| canonical(dir)).collect();
    candidates.sort_by_key(|dir| dir.components().count());
    candidates.dedup();
    let mut roots = vec![primary];
    for dir in candidates {
        if !dir.is_dir()
            || dir.starts_with(work_dir)
            || roots.iter().any(|root| dir.starts_with(root))
        {
            continue;
        }
        let count = c_family_source_count(&dir, budget + 1);
        if count == 0 || count > budget {
            continue;
        }
        budget -= count;
        roots.push(dir);
    }
    roots
}

/// Where to look for the in-tree definitions of undefined symbols: the
/// enclosing checkout when it is close by, the project directory around a
/// conventional `src/`/`lib/` directory, or the target's own directory. A tree
/// with too many sources to index quickly falls back to the target directory.
/// The most C/C++ sources the undefined-symbol hint indexes, over every
/// directory it searches.
const MAX_INDEXED_SOURCES: usize = 5_000;

fn definition_search_root(target_dir: &Path) -> PathBuf {
    const MAX_ASCENT: usize = 3;
    let mut candidate = None;
    let mut current = Some(target_dir);
    for _ in 0..=MAX_ASCENT {
        let Some(dir) = current else {
            break;
        };
        if dir.join(".git").exists() {
            candidate = Some(dir.to_path_buf());
            break;
        }
        current = dir.parent();
    }
    let candidate = candidate.unwrap_or_else(|| {
        let conventional = target_dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "src" | "source" | "sources" | "lib" | "libs"
                )
            });
        match target_dir.parent() {
            Some(parent) if conventional => parent.to_path_buf(),
            _ => target_dir.to_path_buf(),
        }
    });
    if candidate != target_dir
        && c_family_source_count(&candidate, MAX_INDEXED_SOURCES + 1) > MAX_INDEXED_SOURCES
    {
        return target_dir.to_path_buf();
    }
    candidate
}

/// The number of C/C++ sources under `root`, counting at most `cap`. Symbolic
/// links are not followed, so a link cycle cannot keep the walk going.
fn c_family_source_count(root: &Path, cap: usize) -> usize {
    const MAX_DIRS: usize = 50_000;
    let mut count = 0;
    let mut visited_dirs = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        visited_dirs += 1;
        if visited_dirs > MAX_DIRS {
            return cap;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                if !entry.file_name().to_string_lossy().starts_with('.') {
                    stack.push(path);
                }
            } else if file_type.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        matches!(
                            ext,
                            "c" | "cc" | "cpp" | "cxx" | "C" | "h" | "hh" | "hpp" | "hxx"
                        )
                    })
            {
                count += 1;
                if count >= cap {
                    return count;
                }
            }
        }
    }
    count
}

/// A path for a shell command line: single-quoted when it needs quoting.
fn shell_word(path: &Path) -> String {
    let text = path.display().to_string();
    if text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+:@%,=".contains(c))
    {
        text
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The make variables an operator sets on `bhf build` to extend a harness
/// build, in the order a suggested command spells them.
const REBUILD_ENV_VARS: [&str; 5] = [
    "AUTO_EXTRA_SOURCES",
    "AUTO_EXTRA_INCLUDES",
    "AUTO_EXTRA_LDFLAGS",
    "CXX_STD",
    "C_STD",
];

/// The build variables a suggested `bhf build` command sets. It starts from
/// the operator's own values, so following one hint never drops another fix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RebuildEnv {
    vars: Vec<(&'static str, String)>,
}

impl RebuildEnv {
    /// The values this `bhf build` was run with.
    fn inherited() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let vars = REBUILD_ENV_VARS
            .iter()
            .filter_map(|name| {
                let value = lookup(name)?;
                let value = value.trim();
                (!value.is_empty()).then(|| (*name, value.to_owned()))
            })
            .collect();
        Self { vars }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }

    /// A copy with each of `phrases` (a flag with its operand, or a path)
    /// appended to `name`, unless the value already holds it.
    fn with(&self, name: &'static str, phrases: &[String]) -> Self {
        let mut value = self.get(name).unwrap_or_default().to_owned();
        for phrase in phrases {
            let held: Vec<String> = recipe_words(&value);
            let wanted: Vec<String> = recipe_words(phrase);
            if wanted.is_empty() || held.windows(wanted.len()).any(|window| window == wanted) {
                continue;
            }
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(phrase);
        }
        let mut next = self.clone();
        next.vars.retain(|(key, _)| *key != name);
        if !value.is_empty() {
            next.vars.push((name, value));
        }
        next
    }

    /// `VAR=value ... <rebuild>`, with the variables in [`REBUILD_ENV_VARS`] order.
    fn command(&self, rebuild: &str) -> String {
        let mut parts: Vec<String> = REBUILD_ENV_VARS
            .iter()
            .filter_map(|name| {
                self.get(name)
                    .map(|value| format!("{name}={}", shell_text(value)))
            })
            .collect();
        parts.push(rebuild.to_owned());
        parts.join(" ")
    }
}

/// `text` as one shell word: bare when it has no special characters, else
/// single-quoted.
fn shell_text(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:@%,=".contains(c))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// What a failed C/C++ harness build was missing, with the exact command that
/// adds it: in-tree sources that define the symbols the link could not
/// resolve (`AUTO_EXTRA_SOURCES` or `--extra-source`), standard stream headers
/// an old source never included (`AUTO_EXTRA_INCLUDES='-include iostream'`),
/// system libraries (`AUTO_EXTRA_LDFLAGS`), and the MSVC-only extra member
/// qualification. Every suggested command keeps the operator's own build
/// variables (`inherited`); when several hints apply, a last line combines them.
fn c_build_failure_hints(
    work_dir: &Path,
    harness_id: &str,
    harness_dir: &Path,
    output: &str,
    inherited: &RebuildEnv,
) -> Vec<String> {
    let mut hints = Vec::new();
    let rebuild = format!("bhf build {} --harness {harness_id}", shell_word(work_dir));
    let classified = build_classifier::classify(output);
    // Every suggestion, applied together.
    let mut combined = inherited.clone();
    let mut suggestions = 0usize;

    // Standard stream headers a pre-standard source relied on getting
    // transitively.
    let mut stream_names: Vec<&str> = Vec::new();
    let mut stream_headers: Vec<&str> = Vec::new();
    for kind in &classified {
        if let build_classifier::BuildErrorKind::MissingType { name } = kind {
            if let Some(header) = build_classifier::std_stream_header(name) {
                if !stream_names.contains(&name.as_str()) {
                    stream_names.push(name);
                }
                if !stream_headers.contains(&header) {
                    stream_headers.push(header);
                }
            }
        }
    }
    if !stream_headers.is_empty() {
        let includes: Vec<String> = stream_headers
            .iter()
            .map(|header| format!("-include {header}"))
            .collect();
        hints.push(format!(
            "hint: the sources use {} without including <{}>; force-include it into every \
             translation unit: {}",
            stream_names.join(", "),
            stream_headers.join(">, <"),
            inherited
                .with("AUTO_EXTRA_INCLUDES", &includes)
                .command(&rebuild)
        ));
        combined = combined.with("AUTO_EXTRA_INCLUDES", &includes);
        suggestions += 1;
    }
    let qualified: Vec<(&str, u32, &str)> = classified
        .iter()
        .filter_map(|kind| match kind {
            build_classifier::BuildErrorKind::ExtraQualification { file, line, member } => {
                Some((file.as_str(), *line, member.as_str()))
            }
            _ => None,
        })
        .collect();
    if let Some((file, line, member)) = qualified.first() {
        // g++ tags the error with the flag that relaxes it; clang does not.
        let (flag, other) = if output.contains("[-fpermissive]") {
            ("-fpermissive", "with clang++, -fms-extensions")
        } else {
            ("-fms-extensions", "with g++, -fpermissive")
        };
        let more = match qualified.len() {
            1 => String::new(),
            n => format!(" (and {} more)", n - 1),
        };
        let flags = [flag.to_owned()];
        hints.push(format!(
            "hint: {file}:{line} declares member '{member}' with an extra class qualification{more} \
             (`int Widget::{member}();` inside class Widget), which only MSVC accepts; remove the \
             qualification, or relax the check: {} ({other})",
            inherited
                .with("AUTO_EXTRA_INCLUDES", &flags)
                .command(&rebuild)
        ));
        combined = combined.with("AUTO_EXTRA_INCLUDES", &flags);
        suggestions += 1;
    }

    'link: {
        let undefined = undefined_symbols_in(output);
        if undefined.is_empty() {
            break 'link;
        }
        let (target_sources, include_dir) = makefile_target_context(harness_dir);
        let mut linked: Vec<PathBuf> = target_sources.clone();
        let inherited_sources: Vec<String> = inherited
            .get("AUTO_EXTRA_SOURCES")
            .map(recipe_words)
            .unwrap_or_default();
        linked.extend(inherited_sources.iter().map(PathBuf::from));
        // Resolved without Windows' `\\?\` prefix: the paths are shown in
        // commands to run.
        let canonical = crate::workdir::plain_canonical;
        let linked: Vec<PathBuf> = linked.iter().map(|path| canonical(path)).collect();
        let reference = target_sources.first().cloned();
        let Some(target_dir) = reference
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .or(include_dir)
        else {
            break 'link;
        };
        let reference = reference.unwrap_or_else(|| target_dir.join("main.cpp"));
        let work_canonical = canonical(work_dir);
        let roots = definition_search_roots(&target_dir, harness_dir, &work_canonical);
        let Some((primary, extra)) = roots.split_first() else {
            break 'link;
        };
        let mut index = match crate::auto::decl_index::DeclarationIndex::build(primary) {
            Ok(index) => index,
            Err(_) => break 'link,
        };
        // The other inputs' directories add their headers (so a definer that
        // includes `widgets/table.h` from a sibling include dir still counts)
        // and their definitions.
        if index.add_header_search_roots(extra).is_err()
            || index.add_definition_search_roots(extra).is_err()
        {
            break 'link;
        }
        let mut definers: Vec<(String, PathBuf)> = Vec::new();
        let mut unresolved: Vec<String> = Vec::new();
        let mut libraries: Vec<String> = Vec::new();
        for symbol in &undefined {
            let as_link_error = format!("undefined reference to `{symbol}'");
            if let Some(build_classifier::BuildErrorKind::MissingSharedLib { name }) =
                build_classifier::classify(&as_link_error)
                    .into_iter()
                    .next()
            {
                if !libraries.contains(&name) {
                    libraries.push(name);
                }
                continue;
            }
            let definer = index
                .lookup_definition_source_near(symbol, &reference)
                .map(canonical)
                .filter(|path| {
                    !linked.contains(path)
                        && !path.starts_with(&work_canonical)
                        && !crate::generate_harness::source_defines_main(path)
                });
            match definer {
                Some(path) => definers.push((symbol.clone(), path)),
                None => unresolved.push(symbol.clone()),
            }
        }
        if !definers.is_empty() {
            let mut files: Vec<PathBuf> = Vec::new();
            for (_, path) in &definers {
                if !files.contains(path) {
                    files.push(path.clone());
                }
            }
            hints.push(format!(
                "hint: the link failed on {} symbol(s) defined in source files this harness does \
                 not compile:",
                definers.len()
            ));
            for (symbol, path) in definers.iter().take(10) {
                hints.push(format!("  {symbol}  (defined in {})", path.display()));
            }
            if definers.len() > 10 {
                hints.push(format!("  ... and {} more", definers.len() - 10));
            }
            let needs_quoting = |text: &str| {
                text.chars()
                    .any(|c| c.is_whitespace() || c == '"' || c == '\'')
            };
            // make splits AUTO_EXTRA_SOURCES on whitespace, so a path that needs
            // quoting cannot travel through it.
            let env_safe = !files
                .iter()
                .any(|path| needs_quoting(&path.display().to_string()))
                && !inherited_sources.iter().any(|word| needs_quoting(word));
            if env_safe {
                let added: Vec<String> = files
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect();
                hints.push(format!(
                    "  link them without regenerating: {}",
                    inherited
                        .with("AUTO_EXTRA_SOURCES", &added)
                        .command(&rebuild)
                ));
                combined = combined.with("AUTO_EXTRA_SOURCES", &added);
                suggestions += 1;
            }
            let flags: Vec<String> = files
                .iter()
                .map(|path| format!("--extra-source {}", shell_word(path)))
                .collect();
            hints.push(format!(
                "  or regenerate the harness with them: add {} to the bhf generate-harness command",
                flags.join(" ")
            ));
        }
        if !libraries.is_empty() {
            let flags: Vec<String> = libraries.iter().map(|lib| format!("-l{lib}")).collect();
            hints.push(format!(
                "hint: link the system libraries: {}",
                inherited
                    .with("AUTO_EXTRA_LDFLAGS", &flags)
                    .command(&rebuild)
            ));
            combined = combined.with("AUTO_EXTRA_LDFLAGS", &flags);
            suggestions += 1;
        }
        if !unresolved.is_empty() {
            let shown: Vec<&str> = unresolved.iter().take(10).map(String::as_str).collect();
            hints.push(format!(
                "hint: no in-tree definition found under {} for: {}{}; link the library that \
                 provides them (AUTO_EXTRA_LDFLAGS='-L<dir> -l<name>') or add the source with \
                 --extra-source",
                roots
                    .iter()
                    .map(|root| root.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                shown.join(", "),
                if unresolved.len() > 10 { ", ..." } else { "" }
            ));
        }
    }
    if suggestions > 1 {
        hints.push(format!(
            "hint: every suggestion above at once: {}",
            combined.command(&rebuild)
        ));
    }
    hints
}

/// Core of the auto C/C++ make build, parameterized on the make target. With
/// `make_target = None` it explicitly requests `main`; with `Some("afl")` it builds
/// the `main_afl` persistent-mode AFL binary. Explicit `main` is load-bearing:
/// an included per-TU object fragment can otherwise become GNU make's first/default
/// goal, return success, and leave no harness executable. Both targets receive the SAME
/// `AUTO_EXTRA_*` recovery env (extra sources / includes / force-includes), so the
/// AFL build sees the identical recovered context the `main` build used.
pub(crate) fn try_run_c_make_build_with_target(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    compiler: Option<&CFamilyCompilerOverride>,
    make_target: Option<&str>,
    cxx_std: Option<&str>,
) -> std::process::Output {
    try_run_c_make_build_with_target_and_ldflags(
        work_dir,
        harness_id,
        extra_sources,
        extra_includes,
        compiler,
        make_target,
        cxx_std,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn try_run_c_make_build_with_target_and_ldflags(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    compiler: Option<&CFamilyCompilerOverride>,
    make_target: Option<&str>,
    cxx_std: Option<&str>,
    extra_ldflags: Option<&str>,
) -> std::process::Output {
    let harness_dir = crate::auto::layout::harness_dir(work_dir, harness_id);
    let mut cmd = std::process::Command::new("make");
    cmd.current_dir(&harness_dir);
    let is_cpp = harness_dir.join("main.cpp").is_file();
    let prepared_extra_sources = match crate::generate_harness::prepare_repair_per_tu_context(
        &harness_dir,
        extra_sources,
        is_cpp,
    ) {
        Ok(sources) => sources,
        Err(error) => {
            // Make consumes this environment variable at parse time and
            // fails before compiling anything. Falling back to the shared
            // target flags here would silently recreate the context-loss
            // bug this preparation step exists to prevent.
            cmd.env(
                "BHF_CONTEXT_PREPARE_FAILED",
                format!("could not prepare exact repair TU contexts: {error:#}"),
            );
            extra_sources.to_vec()
        }
    };
    cmd.arg(make_target.unwrap_or("main"));
    // Override the language standard for the legacy-dialect ladder. A make
    // command-line assignment wins over the Makefile's `?=` default. The two
    // Makefiles carry different variables, so route by which harness this is:
    // `CXX_STD` names a bare standard (`gnu++14`) that the C++ template splices
    // into `-std=`, and `C_STD` does the same on the C side, where it is empty by
    // default so an ordinary build carries no `-std` at all.
    if let Some(std) = cxx_std {
        cmd.arg(if is_cpp {
            format!("CXX_STD={std}")
        } else {
            format!("C_STD={std}")
        });
    }
    let force_includes = repair_force_includes(&harness_dir);
    apply_c_family_make_env(
        &mut cmd,
        &prepared_extra_sources,
        extra_includes,
        &force_includes,
        compiler,
    );
    if let Some(extra_ldflags) = extra_ldflags.filter(|value| !value.trim().is_empty()) {
        append_command_env_flags(&mut cmd, "AUTO_EXTRA_LDFLAGS", extra_ldflags);
    }
    let output = crate::command_output::output_with_timeout(
        &mut cmd,
        std::time::Duration::from_secs(30 * 60),
    )
    .unwrap_or_else(|error| make_spawn_failure(&error));
    if cfg!(windows) && output.status.success() {
        stage_sanitizer_runtime(&harness_dir, std::env::var_os("PATH").as_deref());
    }
    output
}

/// The result of a `make` that could not be started (not installed, or not
/// on PATH): a failed build whose output says why, instead of a panic.
fn make_spawn_failure(error: &std::io::Error) -> std::process::Output {
    #[cfg(unix)]
    let status = std::os::unix::process::ExitStatusExt::from_raw(127 << 8);
    #[cfg(windows)]
    let status = std::os::windows::process::ExitStatusExt::from_raw(1);
    std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: format!("bhf: could not run make: {error}\n").into_bytes(),
    }
}

/// Sidecar beside a harness binary naming the directories of the sanitizer
/// runtime DLLs it needs, one per line. Windows finds a DLL only through PATH
/// (or the binary's own directory): `bhf` puts them on its own PATH, and the
/// finding's `replay.py` reads this file to do the same for a reproducer run
/// from a plain shell.
pub(crate) const RUNTIME_PATH_FILE: &str = "bhf-runtime-path.txt";

/// The PATH entries holding a clang/MSVC AddressSanitizer runtime DLL
/// (`clang_rt.asan_dynamic-x86_64.dll`, its debug variant), in PATH order.
pub(crate) fn sanitizer_runtime_dirs(path: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    let Some(path) = path else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    for dir in std::env::split_paths(path) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let holds_runtime = entries.flatten().any(|entry| {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            name.starts_with("clang_rt.asan") && name.contains("dynamic") && name.ends_with(".dll")
        });
        if holds_runtime && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// Give a Windows harness its sanitizer runtime: the DLLs of the first
/// runtime directory on PATH (the one the build used: cl's own for the MSVC
/// lane, clang's resource directory otherwise) are linked — or copied — next
/// to the binary, where the loader looks before PATH, so the harness starts
/// from any shell and never picks up another toolchain's same-named DLL. The
/// directories are also recorded in [`RUNTIME_PATH_FILE`].
fn stage_sanitizer_runtime(harness_dir: &Path, path: Option<&std::ffi::OsStr>) {
    let dirs = sanitizer_runtime_dirs(path);
    let sidecar = harness_dir.join(RUNTIME_PATH_FILE);
    let Some(first) = dirs.first() else {
        let _ = fs::remove_file(sidecar);
        return;
    };
    let text = dirs
        .iter()
        .map(|dir| format!("{}\n", dir.display()))
        .collect::<String>();
    let _ = fs::write(sidecar, text);
    let Ok(entries) = fs::read_dir(first) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_ascii_lowercase();
        if !(lower.starts_with("clang_rt.asan")
            && lower.contains("dynamic")
            && lower.ends_with(".dll"))
        {
            continue;
        }
        let source = entry.path();
        let target = harness_dir.join(&name);
        let same = fs::metadata(&target)
            .ok()
            .zip(fs::metadata(&source).ok())
            .is_some_and(|(a, b)| a.len() == b.len());
        if same {
            continue;
        }
        let _ = fs::remove_file(&target);
        if fs::hard_link(&source, &target).is_err() {
            let _ = fs::copy(&source, &target);
        }
    }
}

/// Append flags to an environment value already staged on a command.
///
/// Reading the parent process environment here is incorrect: C/C++ context
/// recovery may just have placed an inferred value (notably a libstdc++ `-L`)
/// directly on `cmd`. Coverage replay appends its portable system libraries
/// after that step, so it must preserve the command-local value.
fn append_command_env_flags(cmd: &mut std::process::Command, key: &str, extra: &str) {
    let current = cmd
        .get_envs()
        .find(|(candidate, _)| *candidate == std::ffi::OsStr::new(key))
        .and_then(|(_, value)| value)
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.trim().is_empty());
    let combined = current
        .map(|value| format!("{value} {extra}"))
        .unwrap_or_else(|| extra.to_owned());
    cmd.env(key, combined);
}

/// The (make target, staged artifact) for an AFL build — the Makefile's `afl`
/// target produces `main_afl` via `$(AFLPP_CC)`. A small seam so the selection is
/// unit-testable without a toolchain.
pub(crate) fn afl_make_target_and_artifact() -> (Option<&'static str>, &'static str) {
    (Some("afl"), "main_afl")
}

/// Build the AFL-instrumented `main_afl` for an auto-recovered C/C++ harness,
/// reusing the SAME recovered extras (`extra_sources` / `extra_includes` →
/// `AUTO_EXTRA_*`) so the afl build sees the identical recovery context the `main`
/// build used. No sanitizer/cross compiler override — the Makefile's `AFLPP_CC` /
/// `AFLPP_CFLAGS` defaults drive the afl target. Runs `make afl` in the harness
/// dir; the caller inspects `.status.success()`.
pub(crate) fn try_run_c_make_afl_build_with_extras(
    work_dir: &Path,
    harness_id: &str,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
) -> std::process::Output {
    let (target, _staged) = afl_make_target_and_artifact();
    try_run_c_make_build_with_target(
        work_dir,
        harness_id,
        extra_sources,
        extra_includes,
        None,
        target,
        None,
    )
}

/// Synthesised repair headers that must be force-included into every TU of
/// the harness compile so their content precedes the first use in `main` and
/// in the target source: the collision-safe C++-stdlib `#include`s and the
/// build-config macro `#define`s. Never `auto_types.h`, whose `void *`
/// placeholders would clash with a real typedef in any target TU.
fn repair_force_includes(harness_dir: &Path) -> Vec<PathBuf> {
    let repairs = harness_dir.join("repairs");
    [
        crate::auto::repair::AUTO_CPP_INCLUDES_FILE,
        crate::auto::repair::AUTO_DEFINES_FILE,
    ]
    .iter()
    .map(|name| repairs.join(name))
    .filter(|path| path.is_file())
    .collect()
}

fn apply_c_family_make_env(
    cmd: &mut std::process::Command,
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    force_includes: &[PathBuf],
    compiler: Option<&CFamilyCompilerOverride>,
) {
    // The generated Makefiles use libFuzzer sanitizer flags. GNU make's
    // built-in CC/CXX defaults are usually cc/g++, which do not support
    // -fsanitize=fuzzer on common Linux hosts. Respect explicit caller
    // choices, but provide clang defaults when no compiler was selected.
    let (cc, cxx) = if let Some(compiler) = compiler {
        // An explicit override (a cross build, the gcc retry, a sanitizer
        // matrix): force its CC/CXX (and replacement flags), overriding both the
        // Makefile defaults and the ambient CC/CXX. `$(CC)`/`$(CXX)` head each
        // recipe line, so a toolchain installed under a spaced directory is
        // double-quoted to stay one word.
        cmd.env("CC", compiler_recipe_word(&compiler.cc));
        cmd.env("CXX", compiler_recipe_word(&compiler.cxx));
        if !compiler.cflags.is_empty() {
            cmd.env("CFLAGS", compiler.cflags.join(" "));
        }
        if !compiler.cxxflags.is_empty() {
            cmd.env("CXXFLAGS", compiler.cxxflags.join(" "));
        }
        // CFLAGS/CXXFLAGS miss bhf's driver object, whose rule takes the
        // target flags: a sysroot an SDK compiler needs goes there.
        if let Some(flags) = &compiler.target_flags {
            cmd.env(crate::toolchain::ENV_TARGET_FLAGS, flags.join(" "));
        }
        (compiler.cc.clone(), compiler.cxx.clone())
    } else {
        let effective = crate::toolchain::effective_compilers();
        // `$(CC)`/`$(CXX)` head each recipe line, so a compiler from the
        // environment (or a `[toolchain]`) installed under a directory with a
        // space or ampersand is double-quoted to stay one word.
        for (variable, default) in [("CC", "clang"), ("CXX", "clang++")] {
            match std::env::var(variable) {
                Err(_) => {
                    cmd.env(variable, default);
                }
                Ok(value)
                    if !value.starts_with('"')
                        && compiler_recipe_word(&value) != value
                        && crate::toolchain::program_exists(&value) =>
                {
                    cmd.env(variable, compiler_recipe_word(&value));
                }
                Ok(_) => {}
            }
        }
        (effective.cc, effective.cxx)
    };
    // The Makefile picks its instrumentation flags from the compiler that
    // runs. Probe each compiler once per process and hand make the answer, so
    // the Makefile need not ask again; an unknown compiler leaves the
    // Makefile's own probe in charge.
    for (variable, compiler, cxx) in [
        ("BHF_CC_FAMILY", &cc, false),
        ("BHF_CXX_FAMILY", &cxx, true),
    ] {
        if let Some(family) = crate::toolchain::compiler_family(compiler, cxx) {
            cmd.env(variable, family.make_value());
        }
    }

    let inherited_includes = std::env::var("AUTO_EXTRA_INCLUDES").ok();
    let inherited_ldflags = std::env::var("AUTO_EXTRA_LDFLAGS").ok();
    for (key, value) in c_family_make_env(
        extra_sources,
        extra_includes,
        inherited_includes.as_deref(),
        &detect_libstdcxx_include_flags(),
        inherited_ldflags.as_deref(),
        detect_libstdcxx_search_path(),
        force_includes,
    ) {
        cmd.env(key, value);
    }
}

#[allow(clippy::too_many_arguments)]
fn c_family_make_env(
    extra_sources: &[PathBuf],
    extra_includes: &[PathBuf],
    inherited_extra_includes: Option<&str>,
    detected_include_flags: &[String],
    inherited_ldflags: Option<&str>,
    detected_ld_search_path: Option<String>,
    force_includes: &[PathBuf],
) -> Vec<(String, String)> {
    let mut env = Vec::new();

    // Every path below reaches a recipe through a make variable, so it is
    // double-quoted when it carries a space (or parenthesis/apostrophe), and
    // dropped with a warning when no quoting could make it safe.
    let extra_sources = recipe_paths_or_warn("extra source", extra_sources);
    if !extra_sources.is_empty() {
        env.push(("AUTO_EXTRA_SOURCES".to_owned(), extra_sources.join(" ")));
    }
    let extra_includes = recipe_paths_or_warn("extra include dir", extra_includes);
    let force_includes = recipe_paths_or_warn("force-include header", force_includes);

    let mut include_flags = inherited_extra_includes
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .into_iter()
        .collect::<Vec<_>>();
    // #366: recovered project include dirs use `-iquote` (searched only for
    // quoted `#include "..."`, never for angle `#include <...>`) so a project
    // header cannot shadow a same-named system header. `-isystem` would not
    // help — those dirs still precede the built-in system dirs. Detected
    // project `-I` flags below are left as-is so project-internal angle
    // includes still resolve.
    include_flags.extend(extra_includes.iter().map(|p| format!("-iquote {p}")));
    // Also search the same dirs AFTER the system dirs (`-idirafter`) so a
    // synthesized placeholder for a genuinely-missing ANGLED system header (a
    // stubbed `<vxWorks.h>`/`<sys/neutrino.h>` for RTOS code, or any `<...>`
    // header the host lacks) resolves. `-idirafter` is searched last, so a real
    // same-named system header still wins — #366's no-shadow guarantee holds; this
    // only adds a fallback for headers the host genuinely does not provide.
    include_flags.extend(extra_includes.iter().map(|p| format!("-idirafter {p}")));
    include_flags.extend(detected_include_flags.iter().cloned());
    // Force-include synthesised repair headers (C++-stdlib includes, build-config
    // defines) into every TU so their content is seen by the harness `main` and
    // the target source, not only by `auto_stubs.c`. Prepend so each lands before
    // the first line of every source.
    // `make_path` (forward-slash, verbatim-prefix-stripped): these land in an
    // `AUTO_EXTRA_INCLUDES` make variable whose recipe runs through `sh`, which
    // eats Windows backslashes — `-include C:\...\auto_defines.h` would arrive as
    // `C:...auto_defines.h` and the repair header would never be found.
    for force in force_includes.iter().rev() {
        include_flags.insert(0, format!("-include {force}"));
    }
    if !include_flags.is_empty() {
        env.push(("AUTO_EXTRA_INCLUDES".to_owned(), include_flags.join(" ")));
    }

    let mut ldflags = inherited_ldflags
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(extra) = detected_ld_search_path {
        if let Some(dir) = recipe_paths_or_warn("library search dir", &[PathBuf::from(extra)]).pop()
        {
            ldflags.push(format!("-L{dir}"));
        }
    }
    if !ldflags.is_empty() {
        env.push(("AUTO_EXTRA_LDFLAGS".to_owned(), ldflags.join(" ")));
    }

    env
}

/// A compiler for `CC`/`CXX`: double-quoted when its path has a space. Any
/// other value passes through unchanged, as before; overrides come from bhf's
/// own toolchain selection, not from the scanned tree.
fn compiler_recipe_word(compiler: &str) -> String {
    if harness_gen::build_safety::is_compiler_token(compiler) {
        harness_gen::build_safety::recipe_path(compiler)
    } else {
        compiler.to_owned()
    }
}

/// Render paths for a recipe (see [`harness_gen::build_safety::recipe_path`]),
/// leaving out, with a warning, any path that quoting cannot make safe.
fn recipe_paths_or_warn(kind: &str, paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(
            |path| match harness_gen::build_safety::checked_recipe_path(kind, path) {
                Ok(rendered) => Some(rendered),
                Err(error) => {
                    bhfeprintln!("warning: {error}; leaving it out of the harness build");
                    None
                }
            },
        )
        .collect()
}

fn detect_libstdcxx_include_flags() -> Vec<String> {
    let cxx = std::env::var("CXX").unwrap_or_else(|_| "clang++".to_owned());
    detect_cpp_stdlib_include_flags_for(&cxx, &[])
}

/// Recover C++ standard-library include paths for the exact compiler and base
/// flags used by an independent probe. Header preflights call this too so a
/// mixed GCC/Clang installation is judged under the same toolchain recovery as
/// the eventual harness build.
pub(crate) fn detect_cpp_stdlib_include_flags_for(cxx: &str, base_flags: &[String]) -> Vec<String> {
    if cxx_accepts_cpp_standard_headers(cxx, base_flags) {
        return Vec::new();
    }
    for dirs in candidate_libstdcxx_include_sets_from_root(Path::new("/usr/include")) {
        let flags = libstdcxx_include_flags(&dirs);
        let mut probe_flags = base_flags.to_vec();
        probe_flags.extend(flags.iter().cloned());
        if cxx_accepts_cpp_standard_headers(cxx, &probe_flags) {
            return flags;
        }
    }
    Vec::new()
}

fn cxx_accepts_cpp_standard_headers(cxx: &str, flags: &[String]) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = match Command::new(cxx)
        .arg("-std=c++17")
        .args(flags)
        .args(["-x", "c++", "-", "-fsyntax-only"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };
    let Some(stdin) = child.stdin.as_mut() else {
        return false;
    };
    if stdin
        .write_all(b"#include <string>\n#include <cstring>\nint main() { return 0; }\n")
        .is_err()
    {
        return false;
    }
    child.wait().map(|status| status.success()).unwrap_or(false)
}

fn libstdcxx_include_flags(dirs: &[PathBuf]) -> Vec<String> {
    dirs.iter()
        .flat_map(|dir| ["-isystem".to_owned(), dir.display().to_string()])
        .collect()
}

fn candidate_libstdcxx_include_sets_from_root(include_root: &Path) -> Vec<Vec<PathBuf>> {
    let cxx_root = include_root.join("c++");
    let mut versions = fs::read_dir(&cxx_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() {
                return None;
            }
            let version = entry.file_name().to_string_lossy().into_owned();
            if !version.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let base = cxx_root.join(&version);
            if base.join("string").is_file() {
                Some(version)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    versions.sort_by(|left, right| {
        right
            .parse::<u32>()
            .unwrap_or(0)
            .cmp(&left.parse::<u32>().unwrap_or(0))
    });

    versions
        .into_iter()
        .map(|version| {
            let base = cxx_root.join(&version);
            let mut dirs = vec![base.clone()];
            let mut arch_dirs = fs::read_dir(include_root)
                .ok()
                .into_iter()
                .flat_map(|entries| entries.filter_map(Result::ok))
                .filter_map(|entry| {
                    let file_type = entry.file_type().ok()?;
                    if !file_type.is_dir() {
                        return None;
                    }
                    let candidate = entry.path().join("c++").join(&version);
                    if candidate.is_dir() {
                        Some(candidate)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            arch_dirs.sort();
            dirs.extend(arch_dirs);
            let backward = base.join("backward");
            if backward.is_dir() {
                dirs.push(backward);
            }
            dirs
        })
        .collect()
}

/// Probe whether the linker can find libstdc++ in clang's default
/// search path. clang's libFuzzer runtime pulls in `-lstdc++`; on
/// hosts where clang picks a gcc toolchain version that's installed
/// without the C++ runtime (common: clang-18 picks gcc-14 paths but
/// only gcc-13 libstdc++ is installed), the link fails with
/// "cannot find -lstdc++". Find the actual libstdc++.so on the
/// filesystem and return its parent directory so the Makefile can
/// pass it through `-L`. Returns `None` if libstdc++ is already on
/// the default path or genuinely missing — both cases let the build
/// proceed and the classifier surface the real diagnostic.
pub(crate) fn detect_libstdcxx_search_path() -> Option<String> {
    use std::process::Command;
    // Ask clang where it would find libstdc++ by default. If
    // -print-file-name returns the bare filename (no absolute path),
    // it's not on the default path.
    let out = Command::new(std::env::var("CC").unwrap_or_else(|_| "clang".to_owned()))
        .args(["-print-file-name=libstdc++.so"])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if path != "libstdc++.so" && std::path::Path::new(&path).is_file() && !path.ends_with(".so")
    // double-check; -print-file-name returns the canonical path
    {
        return None;
    }
    if std::path::Path::new(&path).is_file() {
        // clang already knows where it is; nothing to inject.
        return None;
    }
    // Fall back: search common gcc toolchain dirs.
    let candidates: &[&str] = &[
        "/usr/lib/gcc/x86_64-linux-gnu/13",
        "/usr/lib/gcc/x86_64-linux-gnu/14",
        "/usr/lib/gcc/x86_64-linux-gnu/12",
        "/usr/lib/gcc/aarch64-linux-gnu/13",
        "/usr/lib/gcc/aarch64-linux-gnu/14",
        "/usr/lib/gcc/aarch64-linux-gnu/12",
    ];
    for dir in candidates {
        let p = std::path::Path::new(dir).join("libstdc++.so");
        if p.is_file() {
            return Some(dir.to_string());
        }
    }
    None
}

/// Captured stdout/stderr from a programmatic gprbuild invocation,
/// used by `bhf auto`'s attempt loop to classify Ada build
/// failures with the build_classifier crate.
pub(crate) struct CapturedBuild {
    pub(crate) status_success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Programmatic Ada-build driver used by `bhf auto`'s attempt
/// loop. Mirrors the `build::run` happy path (prepare layout +
/// discover compiler + probe + build) but returns the captured
/// stdout/stderr instead of printing to the process streams so the
/// classifier can see GNAT diagnostics.
pub(crate) fn try_run_ada_build_capturing(args: &BuildArgs) -> Result<CapturedBuild, String> {
    run_ada_project(args, BuildMode::Full)
}

/// Semantic-only counterpart of [`try_run_ada_build_capturing`]: compiles no code
/// and links nothing, but reports every diagnostic the repair loop reads. A repair
/// round that is going to fail costs only this, and the expensive full build runs
/// once the closure is semantically clean.
pub(crate) fn try_run_ada_check_capturing(args: &BuildArgs) -> Result<CapturedBuild, String> {
    run_ada_project(args, BuildMode::CheckOnly)
}

fn run_ada_project(args: &BuildArgs, mode: BuildMode) -> Result<CapturedBuild, String> {
    let layout = prepare_layout(args)?;
    let adapter = ada_compiler_adapter(args)?;
    probe_compiler(&adapter).map_err(|error| format!("{error}"))?;
    let result = match mode {
        BuildMode::Full => adapter.build(&layout.project_path),
        BuildMode::CheckOnly => adapter.check(&layout.project_path),
    }
    .map_err(|error| format!("{error}"))?;
    Ok(CapturedBuild {
        status_success: result.exit_code == 0,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub(crate) fn toolchain_config(args: &BuildArgs) -> ToolchainConfig {
    ToolchainConfig {
        target: args.target.clone(),
        runtime: args.runtime.clone(),
        // A gprconfig compiler name (`--toolchain GNAT`) names the project's
        // Toolchain_Name, not a prefix of the tools to run.
        toolchain: args
            .toolchain
            .clone()
            .filter(|toolchain| project_synth::gpr_toolchain_name(toolchain).is_none()),
    }
}

/// The GCC SanitizerCoverage flag the Ada lane uses (#412). GNAT/GCC does NOT
/// accept `trace-pc-guard` (the C/C++ driver's flag); `trace-pc` emits calls to
/// the parameterless `__sanitizer_cov_trace_pc` that `ada_runtime/adafuzz_cov.c`
/// defines.
pub(crate) const ADA_COV_TRACE_PC_FLAG: &str = "-fsanitize-coverage=trace-pc";

/// Marker file written into a harness's `build/<id>` dir when its compile was
/// instrumented with [`ADA_COV_TRACE_PC_FLAG`]. The fuzz engine keys its
/// CoverageTracker on this (#412) so coverage-guided fuzzing engages for the Ada
/// lane exactly when the SHM bitmap is actually being written.
pub(crate) const ADA_COV_SENTINEL: &str = ".bhf_ada_cov";

/// Whether the Ada gcc accepts [`ADA_COV_TRACE_PC_FLAG`], probed once per process
/// per compiler and cached. GNAT/GCC 13.x supports `trace-pc` but earlier/odd
/// toolchains may not; a compiler that rejects it would otherwise fail every Ada
/// build the moment we add the flag, so we degrade to no-coverage instead.
///
/// Probes the same gcc gprbuild would invoke (toolchain/target-prefixed when set,
/// else host `gcc`) by compiling an empty translation unit with the flag.
fn ada_trace_pc_supported(toolchain: &ToolchainConfig) -> bool {
    use std::collections::HashMap;
    use std::process::{Command, Stdio};
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let gcc = toolchain
        .compiler_prefix()
        .map(|prefix| format!("{prefix}-gcc"))
        .unwrap_or_else(|| "gcc".to_owned());

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&cached) = cache.lock().expect("trace-pc probe cache").get(&gcc) {
        return cached;
    }

    let supported = Command::new(&gcc)
        .args([
            ADA_COV_TRACE_PC_FLAG,
            "-xc",
            "-c",
            "/dev/null",
            "-o",
            "/dev/null",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    cache
        .lock()
        .expect("trace-pc probe cache")
        .insert(gcc, supported);
    supported
}

fn write_runtime_project(
    project_path: &Path,
    build_dir: &Path,
    probe_backend: ProbeBackend,
) -> Result<(), String> {
    let object_dir = build_dir.join("adafuzz_obj");
    let library_dir = build_dir.join("adafuzz_lib");
    fs::create_dir_all(&object_dir).map_err(|error| {
        format!(
            "create runtime object directory '{}': {error}",
            object_dir.display()
        )
    })?;
    fs::create_dir_all(&library_dir).map_err(|error| {
        format!(
            "create runtime library directory '{}': {error}",
            library_dir.display()
        )
    })?;

    let runtime_source_dir =
        materialize_runtime_sources(&build_dir.join("adafuzz_runtime_src"), probe_backend)?;
    let rendered = format!(
        "--  SPDX-License-Identifier: Apache-2.0\n\
project AdaFuzz_Runtime is\n\
   --  C is built alongside Ada so adafuzz_cov.c (the trace-pc edge callback,\n\
   --  #412) lands in the runtime archive. It is compiled at `-g` only (no\n\
   --  coverage instrumentation) so the callback is itself uninstrumented and\n\
   --  never recurses; the instrumented target+harness pull it in via the\n\
   --  unresolved `__sanitizer_cov_trace_pc` reference.\n\
   for Languages use (\"Ada\", \"C\");\n\
   for Source_Dirs use (\"{}\");\n\
   for Source_Files use\n\
     (\"adafuzz.ads\",\n\
      \"adafuzz-probe.ads\",\n\
      \"adafuzz-probe.adb\",\n\
      \"adafuzz-input.ads\",\n\
      \"adafuzz-input.adb\",\n\
      \"adafuzz-decode.ads\",\n\
      \"adafuzz-decode.adb\",\n\
      \"adafuzz_cov.c\");\n\
   for Object_Dir use \"adafuzz_obj\";\n\
   for Library_Name use \"adafuzz\";\n\
   for Library_Kind use \"static\";\n\
   for Library_Dir use \"adafuzz_lib\";\n\
\n\
   package Compiler is\n\
      for Default_Switches (\"Ada\") use (\"-g\");\n\
      for Default_Switches (\"C\") use (\"-g\");\n\
   end Compiler;\n\
end AdaFuzz_Runtime;\n",
        path_string(&runtime_source_dir)
    );
    fs::write(project_path, rendered)
        .map_err(|error| format!("write '{}': {error}", project_path.display()))
}

/// The harness's main source-file base name: `main.adb` when present, otherwise
/// a single `*-bhf_harness.adb` (a private-child-subprogram harness). Returns
/// `None` when neither exists.
fn detect_harness_main_file(harness_dir: &Path) -> Option<String> {
    if harness_dir.join("main.adb").is_file() {
        return Some("main.adb".to_owned());
    }
    let entries = fs::read_dir(harness_dir).ok()?;
    entries.flatten().find_map(|entry| {
        let name = entry.file_name().to_string_lossy().into_owned();
        (name.ends_with("-bhf_harness.adb") && entry.path().is_file()).then_some(name)
    })
}

fn select_harness(work_dir: &Path, requested: Option<&str>) -> Result<(String, PathBuf), String> {
    if let Some(harness_id) = requested {
        for harness_root in harness_roots(work_dir) {
            let harness_dir = harness_root.join(harness_id);
            if harness_dir.is_dir() {
                return Ok((harness_id.to_owned(), harness_dir));
            }
        }
        let available = harness_ids_under(work_dir);
        return Err(format!(
            "work dir malformed: harness '{}' not found under {} or {}{}",
            harness_id,
            work_dir
                .join(crate::auto::layout::GENERATED_HARNESSES_DIR)
                .display(),
            crate::auto::layout::harness_root(work_dir).display(),
            if available.is_empty() {
                String::new()
            } else {
                format!(" (available: {})", available.join(", "))
            }
        ));
    }

    let mut harnesses = BTreeMap::new();
    for harness_root in harness_roots(work_dir) {
        if !harness_root.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&harness_root).map_err(|error| {
            format!(
                "read harness directory '{}': {error}",
                harness_root.display()
            )
        })? {
            let entry = entry.map_err(|error| {
                format!(
                    "read harness directory entry under '{}': {error}",
                    harness_root.display()
                )
            })?;
            let file_type = entry.file_type().map_err(|error| {
                format!(
                    "read harness entry type '{}': {error}",
                    entry.path().display()
                )
            })?;
            if file_type.is_dir() {
                harnesses
                    .entry(entry.file_name().to_string_lossy().into_owned())
                    .or_insert_with(|| entry.path());
            }
        }
    }

    match harnesses.len() {
        0 => Err(format!(
            "work dir malformed: no harnesses under {} or {}",
            work_dir
                .join(crate::auto::layout::GENERATED_HARNESSES_DIR)
                .display(),
            crate::auto::layout::harness_root(work_dir).display()
        )),
        1 => {
            let (id, dir) = harnesses.into_iter().next().expect("one harness");
            Ok((id, dir))
        }
        count => {
            let ids: Vec<String> = harnesses.into_keys().collect();
            Err(format!(
                "work dir malformed: {count} harnesses found ({}); pass --harness <id>",
                ids.join(", ")
            ))
        }
    }
}

/// The harness ids under either harness root of `work_dir`, sorted.
fn harness_ids_under(work_dir: &Path) -> Vec<String> {
    let mut ids: Vec<String> = harness_roots(work_dir)
        .iter()
        .filter_map(|root| fs::read_dir(root).ok())
        .flat_map(|entries| entries.flatten())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn harness_roots(work_dir: &Path) -> [PathBuf; 2] {
    [
        work_dir.join(crate::auto::layout::GENERATED_HARNESSES_DIR),
        crate::auto::layout::harness_root(work_dir),
    ]
}

/// The Ada standard the harness build compiles under. The build pulls in
/// dependency sources of mixed, often unmarked vintage, all under one
/// `-gnatXXXX`; detecting one standard from a single source and applying it
/// build-wide made an Ada 2022 dependency (SweetAda's `bits.adb`, which uses the
/// `@` target name and formal-parameter aspects) fail with "... is an Ada 2022
/// feature". `-gnat2022` is the latest supported standard and accepts older code
/// too (the harness main still carries its own `pragma Ada_2012`), so it is the
/// safe, maximally-buildable choice — squarely bhf's "fuzz code that doesn't
/// cleanly build" thesis. (The `@` form is not a token the standard-probe
/// recognises, so per-source detection cannot reliably pick 2022 here anyway.)
fn detect_ada_standard(_source_dir: &Path, work_dir: &Path) -> Result<AdaStandard, String> {
    // The legacy-dialect ladder (see `crate::auto::attempt`) writes the standard it
    // found buildable to this cache; honor it so the whole build (and any
    // synthesized stub bodies) compiles under the SAME `-gnatXXXX`. Absent a cache,
    // Ada 2022 is the maximally-buildable default — where the compiler HAS it.
    let chosen = read_ada_dialect_cache(work_dir).unwrap_or(AdaStandard::Ada2022);
    Ok(clamp_ada_standard_to_compiler(chosen))
}

/// Lower `-gnat2022` to `-gnat2012` on a compiler that does not know the switch.
///
/// `-gnat2022` arrived in GNAT 12. On GNAT 11 — the default on Ubuntu 22.04 and
/// every still-supported RHEL 9 derivative — `gnat1` answers `invalid switch:
/// -gnat2022` and the build dies before it reads a line of Ada, so NO Ada target
/// could be harnessed there at all. The whole GNAT 11 row of the nightly matrix
/// (all four dialects, both profiles) failed this way, and so would any user on
/// an older distribution.
///
/// Ada 2012 is the right fallback: it is fully supported on every GNAT this tool
/// targets and accepts the same older code 2022 does. The only thing lost is a
/// dependency that genuinely uses a 2022 feature, which on such a compiler could
/// not have built regardless.
fn clamp_ada_standard_to_compiler(standard: AdaStandard) -> AdaStandard {
    if standard == AdaStandard::Ada2022 && !gnat_accepts_ada2022() {
        return AdaStandard::Ada2012;
    }
    standard
}

/// Whether this host's GNAT accepts `-gnat2022`, probed once by compiling a
/// trivial unit. Probed rather than parsed from a version string because vendor
/// GNATs spell their versions freely. Any probe failure answers `true`, which is
/// the historical behaviour — this must never turn a working build into a
/// downgraded one.
fn gnat_accepts_ada2022() -> bool {
    use std::sync::OnceLock;
    static ACCEPTS: OnceLock<bool> = OnceLock::new();
    *ACCEPTS.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("bhf-gnat-probe-{}", std::process::id()));
        if fs::create_dir_all(&dir).is_err() {
            return true;
        }
        let src = dir.join("bhf_probe.adb");
        let wrote = fs::write(&src, "procedure Bhf_Probe is begin null; end Bhf_Probe;\n").is_ok();
        let accepts = wrote
            && std::process::Command::new("gcc")
                .arg("-c")
                .arg("-gnat2022")
                .arg(&src)
                .current_dir(&dir)
                .output()
                .map(|out| !String::from_utf8_lossy(&out.stderr).contains("invalid switch"))
                .unwrap_or(true);
        let _ = fs::remove_dir_all(&dir);
        accepts
    })
}

/// Run-level object directory shared by every Ada harness of a sweep, so the
/// project's own closure is compiled once rather than once per target. Ada
/// attempts are serialized within a sweep (they share the staged source layout),
/// so no two gprbuild runs write here at the same time.
pub(crate) const SHARED_ADA_OBJ_DIR: &str = "ada_obj";

/// Run-level source directory holding the reconstructed external-library stubs.
/// Project-scoped for the same reason the model behind it is: the stub set is a
/// property of the project. Keeping it at a stable path also means the compiled
/// stub objects survive in [`SHARED_ADA_OBJ_DIR`] from one target to the next —
/// a per-target path would make gprbuild recompile every stub, and everything
/// depending on it, for each harness.
pub(crate) const SHARED_ADA_STUBS_DIR: &str = "ada_external_stubs";

/// Path of the Ada dialect cache written by the legacy-dialect ladder.
///
/// RUN-level, not per harness. Which `-gnatXXXX` a project's sources compile
/// under is a property of the project — one target does not use Ada 95 while its
/// neighbour uses Ada 2022 — but the cache used to sit in `build/<harness>/`, so
/// every target of a legacy project re-ran the whole ladder, paying up to three
/// extra full builds each to rediscover the same answer.
pub(crate) fn ada_dialect_cache_path(work_dir: &Path) -> PathBuf {
    work_dir.join("ada_dialect")
}

/// Read the cached Ada standard (a `-gnatXXXX` token) for this run, if any.
pub(crate) fn read_ada_dialect_cache(work_dir: &Path) -> Option<AdaStandard> {
    let raw = fs::read_to_string(ada_dialect_cache_path(work_dir)).ok()?;
    ada_standard_from_switch(raw.trim())
}

/// Map a `-gnatXXXX` dialect switch to its [`AdaStandard`].
pub(crate) fn ada_standard_from_switch(switch: &str) -> Option<AdaStandard> {
    match switch {
        "-gnat83" => Some(AdaStandard::Ada83),
        "-gnat95" => Some(AdaStandard::Ada95),
        "-gnat05" | "-gnat2005" => Some(AdaStandard::Ada2005),
        "-gnat12" | "-gnat2012" => Some(AdaStandard::Ada2012),
        "-gnat2022" => Some(AdaStandard::Ada2022),
        _ => None,
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn absolutize(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("resolve current directory: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runner applies to an Ada harness built for another target (the Ada
    /// target, else the tool prefix), and is refused for one this host runs,
    /// which would otherwise drop it silently.
    #[test]
    fn an_ada_harness_takes_a_runner_only_for_another_target() {
        let runner = std::env::current_exe().unwrap().display().to_string();
        let mut config = config::ToolchainConfig {
            runner: Some(runner.clone()),
            runner_args: vec!["--board".to_owned(), "b1".to_owned()],
            ..Default::default()
        };
        let error = ada_build_runner(&config).unwrap_err();
        assert!(
            error.contains(&format!("toolchain.runner `{runner}` is set"))
                && error.contains("builds for this host"),
            "{error}"
        );
        let expected = Some(crate::gate_evidence::HarnessRunner {
            program: PathBuf::from(&runner),
            args: vec!["--board".to_owned(), "b1".to_owned()],
        });
        config.ada.target = Some("powerpc-linux-gnu".to_owned());
        assert_eq!(ada_build_runner(&config).unwrap(), expected);
        config.ada.target = None;
        config.ada.prefix = Some("powerpc-linux-gnu-".to_owned());
        assert_eq!(ada_build_runner(&config).unwrap(), expected);
        // A gprconfig compiler name is not a target.
        config.ada.prefix = Some("GNAT".to_owned());
        assert!(ada_build_runner(&config).is_err());
        config.runner = None;
        assert_eq!(ada_build_runner(&config).unwrap(), None);
    }

    #[test]
    fn detects_staged_in_tree_ada_runtime_unit() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("s-valint.ads"),
            "package System.Val_Int is\nend System.Val_Int;\n",
        )
        .unwrap();
        assert!(dir_contains_in_tree_ada_runtime_unit(temp.path()));

        fs::write(
            temp.path().join("ordinary.ads"),
            "with System;\npackage Ordinary is\nend Ordinary;\n",
        )
        .unwrap();
        fs::remove_file(temp.path().join("s-valint.ads")).unwrap();
        assert!(!dir_contains_in_tree_ada_runtime_unit(temp.path()));
    }

    #[test]
    fn afl_build_uses_afl_target_and_main_afl() {
        // The AFL build must request the `afl` make target, producing `main_afl`.
        let (target, staged) = afl_make_target_and_artifact();
        assert_eq!(target, Some("afl"));
        assert_eq!(staged, "main_afl");
    }

    #[test]
    fn native_make_build_explicitly_requests_main_after_included_object_graph() {
        if std::process::Command::new("make")
            .arg("--version")
            .output()
            .is_err()
        {
            bhfeprintln!("skipping explicit make goal test: make not on PATH");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path();
        let harness = work.join("harnesses/H-X");
        fs::create_dir_all(&harness).unwrap();
        fs::write(harness.join("main.c"), "int main(void) { return 0; }\n").unwrap();
        fs::write(
            harness.join("build_context_objects.mk"),
            "context_objs:\n\tmkdir -p context_objs\n",
        )
        .unwrap();
        fs::write(
            harness.join("Makefile"),
            "-include build_context_objects.mk\n.PHONY: all\nall: main\nmain: main.c\n\ttouch main\n",
        )
        .unwrap();

        let output = try_run_c_make_build_with_target(work, "H-X", &[], &[], None, None, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            harness.join("main").is_file(),
            "the included fragment's first target must not replace the harness goal"
        );
        assert!(
            !harness.join("context_objs").exists(),
            "make must not stop after the fragment's default-looking target"
        );
    }

    #[test]
    fn discover_user_gpr_absolutizes_relative_imports_and_skips_bundled_adafuzz() {
        // #411: forwarded `with` clauses must be depth-independent. A
        // relative import is resolved against the source gpr's own dir
        // into a normalized ABSOLUTE path (so it still resolves when
        // written into bhf_build.gpr at its deeper build/<id>/ dir),
        // an already-absolute import is preserved, and bhf's own
        // bundled adafuzz.gpr is dropped (adafuzz_runtime.gpr already
        // provides it).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // An absolute path carries a drive on Windows.
        let absolute_import = if cfg!(windows) {
            "C:/opt/x.gpr"
        } else {
            "/opt/x.gpr"
        };
        fs::write(
            root.join("foo.gpr"),
            format!(
                "with \"../sub/dep.gpr\";\n\
                 with \"{absolute_import}\";\n\
                 with \"../../whatever/adafuzz.gpr\";\n\
                 project Foo is\n\
                 end Foo;\n"
            ),
        )
        .unwrap();

        let clauses = discover_user_gpr_with_clauses(root);

        assert!(
            gpr_imports_adafuzz(&root.join("foo.gpr")),
            "a governing project that imports adafuzz.gpr must not be extended"
        );

        // Relative dep -> normalized ABSOLUTE path rooted at the gpr dir.
        let expected_dep = root.parent().unwrap().join("sub").join("dep.gpr");
        assert!(
            expected_dep.is_absolute(),
            "fixture root must be absolute for this assertion"
        );
        // Absolute import preserved verbatim.
        let expected_abs = PathBuf::from(absolute_import);
        assert_eq!(
            clauses,
            vec![expected_dep, expected_abs],
            "expected the relative dep absolutized and the absolute one kept, \
             with the bundled adafuzz.gpr skipped; got {clauses:?}"
        );
        // Belt-and-suspenders: the bundled runtime is never forwarded.
        assert!(
            !clauses
                .iter()
                .any(|p| p.file_name().is_some_and(|n| n == "adafuzz.gpr")),
            "bundled adafuzz.gpr must not be forwarded: {clauses:?}"
        );
    }

    #[test]
    fn normalize_path_lexical_collapses_dot_and_dotdot_without_touching_fs() {
        assert_eq!(
            normalize_path_lexical(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
        // Non-existent path is normalized lexically (no canonicalize).
        assert_eq!(
            normalize_path_lexical(Path::new("/x/y/../../nope/here.gpr")),
            PathBuf::from("/nope/here.gpr")
        );
    }

    #[test]
    fn libstdcxx_include_candidates_pair_base_arch_and_backward_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let include_root = tmp.path().join("usr/include");
        let base = include_root.join("c++/13");
        let arch = include_root.join("x86_64-linux-gnu/c++/13");
        let backward = include_root.join("c++/13/backward");
        fs::create_dir_all(&arch).unwrap();
        fs::create_dir_all(&backward).unwrap();
        fs::write(base.join("string"), "").unwrap();
        fs::create_dir_all(include_root.join("c++/v1")).unwrap();
        fs::write(include_root.join("c++/v1/string"), "").unwrap();

        let sets = candidate_libstdcxx_include_sets_from_root(&include_root);

        assert_eq!(sets, vec![vec![base, arch, backward]]);
    }

    #[test]
    fn recovered_extra_includes_use_iquote_to_avoid_system_header_shadow() {
        // #366: bhf's recovered project include dirs must be -iquote, not
        // -I, so a project header (e.g. capnproto's C++ endian.h) cannot shadow
        // a system header pulled in via an angle include. The project's own
        // detected -I flags pass through untouched, and the harness includes its
        // target headers via quoted `#include "..."`, which -iquote resolves.
        let env = c_family_make_env(
            &[],
            &[PathBuf::from("/proj/src/capnp")],
            None,
            &["-I/proj/build".to_owned()],
            None,
            None,
            &[],
        );
        let includes = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_INCLUDES is set");
        assert!(
            includes.contains("-iquote /proj/src/capnp"),
            "recovered include dirs must be -iquote: {includes}"
        );
        assert!(
            !includes.contains("-I/proj/src/capnp"),
            "recovered include dirs must NOT be -I: {includes}"
        );
        assert!(
            includes.contains("-I/proj/build"),
            "detected project -I flags must pass through untouched: {includes}"
        );
    }

    /// `--extra-include`/`--extra-source` dirs and the work dir's own repair
    /// headers can live under a path with spaces (`SDK 10/Include`, a user
    /// profile). They reach the recipe through make variables, so each one must
    /// arrive double-quoted or the shell splits it into two arguments.
    #[test]
    fn extra_paths_with_spaces_are_quoted_for_the_recipe() {
        let env = c_family_make_env(
            &[PathBuf::from("/work dir/repairs/auto_stubs.c")],
            &[PathBuf::from("/opt/SDK 10/Include")],
            None,
            &[],
            None,
            Some("/opt/tool chain/lib".to_owned()),
            &[PathBuf::from("/work dir/repairs/auto_defines.h")],
        );
        let value = |key: &str| {
            env.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{key} is set: {env:?}"))
        };
        assert_eq!(
            crate::generate_harness::split_compile_command(&value("AUTO_EXTRA_INCLUDES")),
            vec![
                "-include",
                "/work dir/repairs/auto_defines.h",
                "-iquote",
                "/opt/SDK 10/Include",
                "-idirafter",
                "/opt/SDK 10/Include",
            ]
        );
        assert_eq!(
            value("AUTO_EXTRA_SOURCES"),
            "\"/work dir/repairs/auto_stubs.c\""
        );
        assert_eq!(value("AUTO_EXTRA_LDFLAGS"), "-L\"/opt/tool chain/lib\"");
    }

    /// Windows SDK, Visual Studio and user-profile dirs live under paths such as
    /// `C:/Program Files (x86)/...` and `C:/Users/<First Last>/OneDrive - Org`.
    /// Rendered with forward slashes, they are quoted like any spaced path. This
    /// runs on every platform; the Windows CI job selects it by name.
    #[test]
    fn windows_style_extra_paths_with_spaces_are_quoted_for_the_recipe() {
        let sdk = "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/ucrt";
        let helper = "C:/Users/Dana Smith/OneDrive - Org/proj/helpers.c";
        let env = c_family_make_env(
            &[PathBuf::from(helper)],
            &[PathBuf::from(sdk)],
            None,
            &[],
            None,
            None,
            &[],
        );
        let value = |key: &str| {
            env.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{key} is set: {env:?}"))
        };
        assert_eq!(
            crate::generate_harness::split_compile_command(&value("AUTO_EXTRA_INCLUDES")),
            vec!["-iquote", sdk, "-idirafter", sdk]
        );
        assert_eq!(value("AUTO_EXTRA_SOURCES"), format!("\"{helper}\""));
    }

    /// On Windows a native path is first rendered with forward slashes and
    /// without the `\\?\` verbatim prefix, then quoted like any other; a
    /// command-interpreter metacharacter (`%`) stays refused.
    #[cfg(windows)]
    #[test]
    fn windows_native_paths_with_spaces_are_rendered_and_quoted() {
        let env = c_family_make_env(
            &[PathBuf::from(r"C:\Users\Dana Smith\proj\helpers.c")],
            &[PathBuf::from(
                r"\\?\C:\Program Files (x86)\Windows Kits\10\Include",
            )],
            None,
            &[],
            None,
            None,
            &[],
        );
        let value = |key: &str| {
            env.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{key} is set: {env:?}"))
        };
        let sdk = "C:/Program Files (x86)/Windows Kits/10/Include";
        assert_eq!(
            crate::generate_harness::split_compile_command(&value("AUTO_EXTRA_INCLUDES")),
            vec!["-iquote", sdk, "-idirafter", sdk]
        );
        assert_eq!(
            value("AUTO_EXTRA_SOURCES"),
            "\"C:/Users/Dana Smith/proj/helpers.c\""
        );
        assert_eq!(
            harness_gen::build_safety::checked_recipe_path(
                "source path",
                std::path::Path::new(r"C:\src\a.c")
            )
            .unwrap(),
            "C:/src/a.c"
        );
        assert!(harness_gen::build_safety::checked_recipe_path(
            "source path",
            std::path::Path::new(r"C:\a%PATH%\b.c")
        )
        .is_err());
    }

    /// A path no quoting can make safe (`make` expands `$` before the shell runs)
    /// never reaches the recipe.
    #[test]
    fn extra_paths_with_unquotable_characters_are_dropped() {
        let env = c_family_make_env(
            &[PathBuf::from("/tmp/$(id)/stub.c")],
            &[
                PathBuf::from("/tmp/a`id`/include"),
                PathBuf::from("/usr/include/x"),
            ],
            None,
            &[],
            None,
            None,
            &[],
        );
        assert!(
            env.iter()
                .all(|(_, v)| !v.contains("$(id)") && !v.contains('`')),
            "{env:?}"
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "AUTO_EXTRA_INCLUDES" && v.contains("-iquote /usr/include/x")),
            "a safe dir beside a refused one is still passed: {env:?}"
        );
    }

    #[test]
    fn recovered_extra_includes_also_idirafter_for_angled_placeholders() {
        // A synthesized placeholder for a genuinely-missing ANGLED system header
        // (a stubbed `<vxWorks.h>`/`<sys/neutrino.h>` for RTOS code) lives in the
        // repair includes dir. `-iquote` never resolves `<...>` includes, so the
        // dir must ALSO be `-idirafter`: searched AFTER the real system dirs, so a
        // real `<stdio.h>` still wins (no shadow — #366 preserved) while a header
        // the host genuinely lacks falls through to the placeholder.
        let env = c_family_make_env(
            &[],
            &[PathBuf::from("/work/repairs/auto_includes")],
            None,
            &[],
            None,
            None,
            &[],
        );
        let includes = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_INCLUDES is set");
        assert!(
            includes.contains("-iquote /work/repairs/auto_includes"),
            "{includes}"
        );
        assert!(
            includes.contains("-idirafter /work/repairs/auto_includes"),
            "angled-include placeholders need -idirafter fallback: {includes}"
        );
    }

    #[test]
    fn c_family_make_env_threads_detected_libstdcxx_flags() {
        let env = c_family_make_env(
            &[],
            &[],
            Some("-I/custom"),
            &["-isystem".to_owned(), "/usr/include/c++/13".to_owned()],
            Some("-Wl,--as-needed"),
            Some("/usr/lib/gcc/x86_64-linux-gnu/13".to_owned()),
            &[],
        );

        let includes = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_INCLUDES is set");
        assert!(includes.contains("-I/custom"));
        assert!(includes.contains("-isystem /usr/include/c++/13"));

        let forced = c_family_make_env(
            &[],
            &[],
            None,
            &[],
            None,
            None,
            &[
                PathBuf::from("/wk/harnesses/H/repairs/auto_cpp_includes.h"),
                PathBuf::from("/wk/harnesses/H/repairs/auto_defines.h"),
            ],
        );
        let forced_includes = forced
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.as_str())
            .expect("force-include sets AUTO_EXTRA_INCLUDES");
        // Both headers force-included, in order.
        assert!(
            forced_includes.starts_with(
                "-include /wk/harnesses/H/repairs/auto_cpp_includes.h \
                 -include /wk/harnesses/H/repairs/auto_defines.h"
            ),
            "{forced_includes}"
        );

        let ldflags = env
            .iter()
            .find(|(key, _)| key == "AUTO_EXTRA_LDFLAGS")
            .map(|(_, value)| value.as_str())
            .expect("AUTO_EXTRA_LDFLAGS is set");
        assert!(ldflags.contains("-Wl,--as-needed"));
        assert!(ldflags.contains("-L/usr/lib/gcc/x86_64-linux-gnu/13"));
    }

    /// An override's target flags reach make as `BHF_TOOLCHAIN_TARGET_FLAGS`,
    /// which every object rule takes (bhf's driver object included, which
    /// CFLAGS does not reach); without them the published value stays.
    #[test]
    fn an_override_publishes_its_target_flags_to_every_object_rule() {
        let staged = |target_flags: Option<Vec<String>>| {
            let compiler = CFamilyCompilerOverride {
                cc: "cc".to_owned(),
                cxx: "c++".to_owned(),
                cflags: vec!["-O1".to_owned()],
                cxxflags: vec!["-O1".to_owned()],
                target_flags,
            };
            let mut command = std::process::Command::new("make");
            apply_c_family_make_env(&mut command, &[], &[], &[], Some(&compiler));
            command
                .get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new(crate::toolchain::ENV_TARGET_FLAGS))
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned())
        };
        assert_eq!(
            staged(Some(vec![
                "--sysroot=\"/opt/sdk root\"".to_owned(),
                "--target=aarch64-linux-gnu".to_owned(),
            ]))
            .as_deref(),
            Some("--sysroot=\"/opt/sdk root\" --target=aarch64-linux-gnu")
        );
        // An empty set still replaces a host toolchain's sysroot.
        assert_eq!(staged(Some(Vec::new())).as_deref(), Some(""));
        assert_eq!(staged(None), None);
    }

    #[test]
    fn appending_coverage_ldflags_preserves_command_local_recovery() {
        let mut command = std::process::Command::new("make");
        command.env("AUTO_EXTRA_LDFLAGS", "-L/usr/lib/gcc/x86_64-linux-gnu/13");

        append_command_env_flags(&mut command, "AUTO_EXTRA_LDFLAGS", "-lm -ldl -lpthread");

        let value = command
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new("AUTO_EXTRA_LDFLAGS"))
            .and_then(|(_, value)| value)
            .expect("command-local linker flags")
            .to_string_lossy();
        assert_eq!(
            value,
            "-L/usr/lib/gcc/x86_64-linux-gnu/13 -lm -ldl -lpthread"
        );
    }

    #[test]
    fn ada_prepare_layout_includes_auto_repair_stubs_source_root() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("bhf_work");
        let src = work.join("src_instrumented");
        let harness = work.join("generated_harnesses/H-A0001");
        let repair_stubs = work
            .join("harnesses")
            .join("H-A0001")
            .join("repairs")
            .join("ada_stubs");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&harness).unwrap();
        fs::create_dir_all(&repair_stubs).unwrap();
        fs::write(
            src.join("pkg.adb"),
            "package body Pkg is begin null; end Pkg;\n",
        )
        .unwrap();
        fs::write(
            harness.join("main.adb"),
            "procedure Main is begin null; end Main;\n",
        )
        .unwrap();
        fs::write(
            repair_stubs.join("aux_pkg.ads"),
            "package Aux_Pkg is end Aux_Pkg;\n",
        )
        .unwrap();

        let args = BuildArgs {
            work_dir: work.clone(),
            source_project: None,
            harness: Some("H-A0001".to_owned()),
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: ProbeBackend::HostFile,
            toolchain_args: BuildToolchainArgs::default(),
            c_engine: CEngine::Libfuzzer,
        };

        let layout = prepare_layout(&args).unwrap();
        let project = fs::read_to_string(layout.project_path).unwrap();

        assert!(
            project.contains(&repair_stubs.to_string_lossy().to_string()),
            "generated GPR should include auto Ada stubs dir; got:\n{project}"
        );
    }

    /// `-gnat2022` arrived in GNAT 12. On GNAT 11 — Ubuntu 22.04's default —
    /// `gnat1` answers `invalid switch: -gnat2022` and the build dies before
    /// reading a line of Ada, so no Ada target could be harnessed at all. The
    /// whole GNAT 11 row of the nightly matrix failed exactly this way.
    #[test]
    fn ada_2022_is_lowered_on_a_compiler_that_lacks_the_switch() {
        // Only 2022 is clamped; a standard the ladder actually found buildable
        // is passed through untouched.
        for standard in [
            AdaStandard::Ada83,
            AdaStandard::Ada95,
            AdaStandard::Ada2005,
            AdaStandard::Ada2012,
        ] {
            assert_eq!(clamp_ada_standard_to_compiler(standard), standard);
        }
        // On THIS host the answer follows the probe, and either answer is a
        // legal Ada standard the writer can spell.
        let clamped = clamp_ada_standard_to_compiler(AdaStandard::Ada2022);
        assert!(
            clamped == AdaStandard::Ada2022 || clamped == AdaStandard::Ada2012,
            "unexpected clamp: {clamped:?}"
        );
        assert_eq!(clamped == AdaStandard::Ada2022, gnat_accepts_ada2022());
    }

    #[test]
    fn ada_overlay_build_inherits_governing_project_semantics_from_external_work_dir() {
        if std::process::Command::new("gprbuild")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let app = project_root.join("app");
        let original = app.join("original");
        let common = project_root.join("common/src");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&common).unwrap();
        fs::write(
            common.join("common.ads"),
            "package Common is X : constant Integer := 7; end Common;\n",
        )
        .unwrap();
        fs::write(
            project_root.join("common/common.gpr"),
            "project Common is for Source_Dirs use (\"src\"); end Common;\n",
        )
        .unwrap();
        let package_source =
            "with Common; package Pkg is X : constant Integer := Common.X; end Pkg;\n";
        fs::write(original.join("vendor_pkg.ads"), package_source).unwrap();
        fs::write(app.join("gnat.adc"), "pragma Warnings (Off);\n").unwrap();
        let source_project = app.join("app.gpr");
        fs::write(
            &source_project,
            "with \"../common/common.gpr\";\n\
             project App is\n\
                type Mode_Type is (\"host\", \"other\");\n\
                Mode : Mode_Type := external (\"MODE\", \"host\");\n\
                for Source_Dirs use (\"original\");\n\
                package Compiler is\n\
                   for Local_Configuration_Pragmas use \"gnat.adc\";\n\
                end Compiler;\n\
                package Naming is\n\
                   case Mode is\n\
                      when \"host\" => for Spec (\"Pkg\") use \"vendor_pkg.ads\";\n\
                      when others => for Spec (\"Pkg\") use \"unselected.ads\";\n\
                   end case;\n\
                end Naming;\n\
                package Binder is for Default_Switches (\"Ada\") use (\"-E\"); end Binder;\n\
                package Linker is for Default_Switches (\"Ada\") use (\"-Wl,--as-needed\"); end Linker;\n\
             end App;\n",
        )
        .unwrap();

        // Deliberately outside the project: parent-directory inference cannot
        // find App.gpr, so only the explicit governing-project plumbing works.
        let work = temp.path().join("external-work/bhf_work");
        let staged = work.join("src_instrumented");
        let harness = work.join("generated_harnesses/H-GPR-OVERLAY");
        fs::create_dir_all(&staged).unwrap();
        fs::create_dir_all(&harness).unwrap();
        fs::write(staged.join("vendor_pkg.ads"), package_source).unwrap();
        fs::write(
            harness.join("main.adb"),
            "with Pkg; procedure Main is X : Integer := Pkg.X; begin X := X + 1; end Main;\n",
        )
        .unwrap();
        let args = BuildArgs {
            work_dir: work,
            source_project: Some(source_project.clone()),
            harness: Some("H-GPR-OVERLAY".to_owned()),
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: ProbeBackend::HostFile,
            toolchain_args: BuildToolchainArgs::default(),
            c_engine: CEngine::Libfuzzer,
        };

        let captured = try_run_ada_build_capturing(&args).unwrap();
        assert!(
            captured.status_success,
            "overlay should inherit custom Naming, scenario, config, import, binder and linker settings:\n{}\n{}",
            captured.stdout, captured.stderr
        );
        let generated =
            fs::read_to_string(args.work_dir.join("build/H-GPR-OVERLAY/bhf_build.gpr")).unwrap();
        assert!(generated.contains(&format!("extends \"{}\"", source_project.display())));
    }

    #[test]
    fn ada_runtime_project_builds_c_and_is_never_coverage_instrumented() {
        // #412: the AdaFuzz runtime project ships the C trace-pc callback
        // (adafuzz_cov.c) but is compiled WITHOUT any coverage instrumentation, so
        // the callback never recurses into itself.
        let tmp = tempfile::tempdir().unwrap();
        let build_dir = tmp.path();
        let gpr = build_dir.join("adafuzz_runtime.gpr");
        write_runtime_project(&gpr, build_dir, ProbeBackend::HostFile).unwrap();
        let rendered = fs::read_to_string(&gpr).unwrap();
        assert!(
            rendered.contains("for Languages use (\"Ada\", \"C\")"),
            "runtime project must build C:\n{rendered}"
        );
        assert!(
            rendered.contains("\"adafuzz_cov.c\""),
            "runtime project must include the trace-pc callback source:\n{rendered}"
        );
        assert!(
            !rendered.contains("-fsanitize-coverage"),
            "runtime project must never be coverage-instrumented:\n{rendered}"
        );
    }

    #[test]
    fn bhf_build_renders_trace_pc_only_when_instrumented() {
        // #412: the target/harness ProjectSpec carries
        // `-fsanitize-coverage=trace-pc` in its Ada Default_Switches when
        // instrumented, and the default (uninstrumented) spec carries none — the
        // switch wiring prepare_layout toggles behind the gcc capability probe.
        let spec_with = |switches: Switches| ProjectSpec {
            project_name: "Bhf_Build".to_owned(),
            extends_project: None,
            parent_compiler: None,
            source_roots: vec![SourceRoot {
                path: PathBuf::from("/tmp/src"),
                language: "Ada".to_owned(),
            }],
            object_dir: PathBuf::from("/tmp/obj"),
            exec_dir: None,
            main_adb: Some("main.adb".to_owned()),
            ada_standard: AdaStandard::Ada2012,
            target: None,
            runtime: None,
            toolchain: None,
            switches,
            with_clauses: vec![PathBuf::from("adafuzz_runtime.gpr")],
            executable_name: None,
            compile_c: false,
            excluded_source_files: Vec::new(),
        };

        let mut instrumented = Switches::default();
        instrumented.default.push(ADA_COV_TRACE_PC_FLAG.to_owned());
        let with_flag = project_synth::render_project(&spec_with(instrumented)).unwrap();
        assert!(
            with_flag.contains("-fsanitize-coverage=trace-pc"),
            "instrumented Bhf_Build must carry trace-pc:\n{with_flag}"
        );

        let without = project_synth::render_project(&spec_with(Switches::default())).unwrap();
        assert!(
            !without.contains("-fsanitize-coverage"),
            "default Bhf_Build must carry no coverage flag:\n{without}"
        );
    }

    fn c_build_args(work_dir: &Path, harness: Option<&str>) -> BuildArgs {
        BuildArgs {
            work_dir: work_dir.to_path_buf(),
            source_project: None,
            harness: harness.map(str::to_owned),
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: ProbeBackend::HostFile,
            toolchain_args: BuildToolchainArgs::default(),
            c_engine: CEngine::Libfuzzer,
        }
    }

    /// A C++ harness directory whose Makefile `main` goal just writes a file, so
    /// the layout handling can be exercised without a compiler.
    fn write_trivial_cpp_harness(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("main.cpp"), "int main() { return 0; }\n").unwrap();
        fs::write(dir.join("Makefile"), "main:\n\tprintf built > main\n").unwrap();
    }

    /// The C/C++ make path with no toolchain configured.
    fn c_make_build(args: &BuildArgs) -> Option<i32> {
        try_run_c_make_build(args, &config::ToolchainConfig::default())
    }

    /// `--toolchain GNAT` names the project's Toolchain_Name; only a prefix
    /// (a triple) selects prefixed tools.
    #[test]
    fn a_gprconfig_compiler_name_is_not_a_tool_prefix() {
        let mut args = c_build_args(Path::new("/w"), None);
        args.toolchain = Some("GNAT".to_owned());
        assert_eq!(toolchain_config(&args).toolchain, None);
        args.toolchain = Some("aarch64-linux-gnu".to_owned());
        assert_eq!(
            toolchain_config(&args).toolchain.as_deref(),
            Some("aarch64-linux-gnu")
        );
    }

    /// A config file's Ada prefix chooses no C/C++ compilers, and a C/C++
    /// harness build says so instead of quietly using the host compilers.
    #[test]
    fn a_config_ada_prefix_on_a_c_family_harness_gets_a_note() {
        let mut toolchain = config::ToolchainConfig::default();
        assert_eq!(ada_prefix_note(&toolchain, None, "H-ONE"), None);
        toolchain.ada.prefix = Some("aarch64-linux-gnu".to_owned());
        let note = ada_prefix_note(&toolchain, None, "H-ONE").expect("a note");
        assert!(
            note.contains("toolchain.ada.prefix") && note.contains("toolchain.target"),
            "{note}"
        );
        // The --toolchain flag, a target or a compiler do choose them.
        assert_eq!(
            ada_prefix_note(&toolchain, Some("aarch64-linux-gnu"), "H-ONE"),
            None
        );
        toolchain.target = Some("aarch64-linux-gnu".to_owned());
        assert_eq!(ada_prefix_note(&toolchain, None, "H-ONE"), None);
        toolchain.target = None;
        toolchain.cc = Some("gcc".to_owned());
        assert_eq!(ada_prefix_note(&toolchain, None, "H-ONE"), None);
    }

    /// Ada-only flags on a C/C++ harness used to be accepted and ignored (exit
    /// 0, a host binary). They are refused, naming the flags that do apply.
    #[test]
    fn ada_only_flags_are_refused_for_a_c_family_harness() {
        if std::process::Command::new("make")
            .arg("--version")
            .output()
            .is_err()
        {
            bhfeprintln!("skipping: make not on PATH");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        write_trivial_cpp_harness(&work.join("harnesses").join("H-ONE"));
        let mut args = c_build_args(&work, Some("H-ONE"));
        args.runtime = Some("light".to_owned());
        assert_eq!(run(args), 2);
        assert!(
            !work.join("harnesses/H-ONE/main").exists(),
            "a refused build must not run make"
        );
        let mut args = c_build_args(&work, Some("H-ONE"));
        args.probe_backend = ProbeBackend::MemoryBuffer;
        assert_eq!(run(args), 2);
        let mut args = c_build_args(&work, Some("H-ONE"));
        args.toolchain_args.ada_switches = vec!["-O2".to_owned()];
        assert_eq!(run(args), 2);
        // The cross options that do apply still build.
        assert_eq!(run(c_build_args(&work, Some("H-ONE"))), 0);
    }

    /// `--target` / `--toolchain` select the C/C++ compilers for a C/C++
    /// harness (they used to reach only the Ada adapter), and `--config`'s
    /// `[toolchain]` table does the same with paths relative to the file.
    #[test]
    fn target_and_toolchain_select_the_c_family_compilers() {
        if std::process::Command::new("make")
            .arg("--version")
            .output()
            .is_err()
            || which::which("aarch64-linux-gnu-gcc").is_err()
            || which::which("aarch64-linux-gnu-g++").is_err()
        {
            bhfeprintln!("skipping: make or the aarch64 cross gcc not on PATH");
            return;
        }
        let saved: Vec<_> = ["CC", "CXX", crate::toolchain::ENV_CPPFLAGS]
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let harness = work.join("harnesses").join("H-ONE");
        fs::create_dir_all(&harness).unwrap();
        fs::write(harness.join("main.cpp"), "int main() { return 0; }\n").unwrap();
        fs::write(
            harness.join("Makefile"),
            "main:\n\tprintf '%s|%s|%s' \"$(CXX)\" \"$(CC)\" \"$(BHF_TOOLCHAIN_CPPFLAGS)\" > main\n",
        )
        .unwrap();
        let built = || fs::read_to_string(harness.join("main")).unwrap();

        let mut args = c_build_args(&work, Some("H-ONE"));
        args.target = Some("aarch64-linux-gnu".to_owned());
        assert_eq!(run(args), 0);
        assert_eq!(built(), "aarch64-linux-gnu-g++|aarch64-linux-gnu-gcc|");

        fs::remove_file(harness.join("main")).unwrap();
        let mut args = c_build_args(&work, Some("H-ONE"));
        args.toolchain = Some("aarch64-linux-gnu".to_owned());
        assert_eq!(run(args), 0);
        assert!(built().starts_with("aarch64-linux-gnu-g++|"), "{}", built());

        fs::remove_file(harness.join("main")).unwrap();
        let config_dir = temp.path().join("cfg");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("bhf.toml"),
            "[toolchain]\ncxx = \"aarch64-linux-gnu-g++\"\ndefines = [\"BOARD=2\"]\n\
             include-dirs = [\"vendor\"]\n",
        )
        .unwrap();
        let mut args = c_build_args(&work, Some("H-ONE"));
        args.toolchain_args.config = Some(config_dir.join("bhf.toml"));
        assert_eq!(run(args), 0);
        assert_eq!(
            built(),
            format!(
                "aarch64-linux-gnu-g++|aarch64-linux-gnu-gcc|-DBOARD=2 -I{}",
                config_dir.join("vendor").display()
            )
        );

        // A compiler that is not installed is reported, not silently replaced.
        let mut args = c_build_args(&work, Some("H-ONE"));
        args.toolchain_args.c.cc = Some("/nonexistent/bin/gcc".to_owned());
        assert_eq!(run(args), 2);
        for (key, value) in saved {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn c_build_reports_the_harness_lookup_error_instead_of_the_ada_layout() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        write_trivial_cpp_harness(&work.join("harnesses").join("H-ONE"));
        write_trivial_cpp_harness(&work.join("harnesses").join("H-TWO"));
        // Two harnesses and no --harness, or an unknown id: the C/C++ lookup error
        // is the answer (exit 3), not a fall-through to the Ada src_instrumented check.
        assert_eq!(c_make_build(&c_build_args(&work, None)), Some(3));
        assert_eq!(
            c_make_build(&c_build_args(&work, Some("H-MISSING"))),
            Some(3)
        );
        assert!(!work.join("build").exists(), "nothing may be built");
    }

    #[test]
    fn c_build_accepts_a_harness_directory_or_harness_root_as_work_dir() {
        if std::process::Command::new("make")
            .arg("--version")
            .output()
            .is_err()
        {
            bhfeprintln!("skipping harness-dir layout test: make not on PATH");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let harness = work.join("harnesses").join("H-ONE");
        write_trivial_cpp_harness(&harness);
        assert_eq!(c_make_build(&c_build_args(&harness, None)), Some(0));
        let staged = work.join("build").join("H-ONE").join("main");
        assert_eq!(fs::read_to_string(&staged).unwrap(), "built");
        fs::remove_file(&staged).unwrap();
        assert_eq!(
            c_make_build(&c_build_args(&work.join("harnesses"), Some("H-ONE"))),
            Some(0)
        );
        assert!(staged.is_file());
    }

    #[test]
    fn c_build_layout_rejects_a_conflicting_harness_id_for_a_harness_dir() {
        let temp = tempfile::tempdir().unwrap();
        let harness = temp.path().join("work").join("harnesses").join("H-ONE");
        write_trivial_cpp_harness(&harness);
        let error = resolve_c_family_work_dir(&harness, Some("H-TWO")).unwrap_err();
        assert!(
            error.contains("H-ONE") && error.contains("H-TWO"),
            "{error}"
        );
        // A harness directory outside a work layout gets the expected layout.
        let loose = temp.path().join("loose");
        write_trivial_cpp_harness(&loose);
        let error = resolve_c_family_work_dir(&loose, None).unwrap_err();
        assert!(error.contains("harnesses/<id>/"), "{error}");
    }

    #[test]
    fn undefined_symbols_are_read_from_gnu_ld_and_lld_output() {
        let output = "/usr/bin/ld: /tmp/codec.o: in function `widgets::Codec::decode(unsigned char const*, unsigned long)':\n\
            codec.cpp:12: undefined reference to `widgets::Table::store(unsigned char const*, unsigned long)'\n\
            ld.lld: error: undefined symbol: parse_record\n\
            >>> referenced by codec.c:4\n\
            codec.cpp:13: undefined reference to `widgets::Table::store(unsigned char const*, unsigned long)'\n\
            /usr/bin/ld: undefined reference to `sqrt'\n\
            main.obj : error LNK2019: unresolved external symbol widget_lookup referenced in function bhf_run_one\r\n\
            lld-link: error: undefined symbol: widget_reset\n";
        assert_eq!(
            undefined_symbols_in(output),
            vec![
                "widgets::Table::store(unsigned char const*, unsigned long)".to_owned(),
                "parse_record".to_owned(),
                "sqrt".to_owned(),
                "widget_lookup".to_owned(),
                "widget_reset".to_owned(),
            ],
            "the MSVC linkers' spellings are read too"
        );
    }

    /// A `make` that cannot be started is a failed build that says why, not a
    /// panic. The harness directory does not exist, so starting `make` in it
    /// fails the way a `make` missing from PATH does, without changing PATH
    /// under the tests running beside this one.
    #[test]
    fn a_make_that_cannot_start_is_a_failed_build_with_its_reason() {
        let work = tempfile::tempdir().unwrap();
        let output = try_run_c_make_build_with_target_and_ldflags(
            work.path(),
            "no-such-harness",
            &[],
            &[],
            None,
            None,
            None,
            None,
        );
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("bhf: could not run make: "), "{stderr}");
        assert!(
            stderr.trim_end().len() > "bhf: could not run make:".len(),
            "the reason follows: {stderr}"
        );
    }

    #[test]
    fn failed_link_hint_names_the_in_tree_definer_and_the_exact_flags() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("lib").join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("table.h"),
            "#pragma once\n#include <cstddef>\nnamespace widgets { struct Table { static int store(const unsigned char *d, size_t n); }; }\n",
        )
        .unwrap();
        fs::write(
            src.join("table.cpp"),
            "#include \"table.h\"\nnamespace widgets {\nint Table::store(const unsigned char *d, size_t n) { return n ? d[0] : 0; }\n}\n",
        )
        .unwrap();
        fs::write(
            src.join("codec.cpp"),
            "#include \"table.h\"\nint decode(const unsigned char *d, size_t n) { return widgets::Table::store(d, n); }\n",
        )
        .unwrap();
        let work = temp.path().join("work");
        let harness = work.join("harnesses").join("H-ONE");
        fs::create_dir_all(&harness).unwrap();
        fs::write(harness.join("main.cpp"), "").unwrap();
        fs::write(
            harness.join("Makefile"),
            format!(
                "main: main.cpp bhf_driver.o $(CONTEXT_MAIN_OBJECTS)\n\t$(CXX) $(CXXFLAGS) -DBHF_EXTERNAL_DRIVER -o $@ main.cpp {} $(CONTEXT_MAIN_OBJECTS) $(AUTO_EXTRA_SOURCES) bhf_driver.o\n",
                harness_gen::build_safety::make_path(&src.join("codec.cpp"))
            ),
        )
        .unwrap();
        let output = "codec.cpp:2: undefined reference to `widgets::Table::store(unsigned char const*, unsigned long)'\n\
                      codec.cpp:2: undefined reference to `vendor_checksum'\n";
        let none = RebuildEnv::default();
        let hints = c_build_failure_hints(&work, "H-ONE", &harness, output, &none).join("\n");
        // The definer is named by its resolved path (Windows short names
        // expanded, no `\\?\` prefix).
        let table_path = crate::workdir::plain_canonical(&src.join("table.cpp"));
        let table = table_path.display().to_string();
        assert!(
            hints.contains(&format!("--extra-source {}", shell_word(&table_path))),
            "{hints}"
        );
        assert!(!hints.contains(r"\\?\"), "{hints}");
        assert!(
            hints.contains(&format!(
                "AUTO_EXTRA_SOURCES={} bhf build",
                shell_text(&table)
            )),
            "{hints}"
        );
        assert!(hints.contains("vendor_checksum"), "{hints}");
        assert!(
            !hints.contains(&format!(
                "--extra-source {}",
                shell_word(&crate::workdir::plain_canonical(&src.join("codec.cpp")))
            )),
            "an already-linked source is never suggested: {hints}"
        );
        // The operator's own build variables are kept in the suggested command.
        let inherited = RebuildEnv::from_lookup(|name| match name {
            "AUTO_EXTRA_SOURCES" => Some("/opt/extra.cpp".to_owned()),
            "AUTO_EXTRA_INCLUDES" => Some("-fms-extensions".to_owned()),
            "CXX_STD" => Some("gnu++14".to_owned()),
            _ => None,
        });
        let hints = c_build_failure_hints(&work, "H-ONE", &harness, output, &inherited).join("\n");
        assert!(
            hints.contains(&format!(
                "AUTO_EXTRA_SOURCES='/opt/extra.cpp {table}' AUTO_EXTRA_INCLUDES=-fms-extensions \
                 CXX_STD=gnu++14 bhf build"
            )),
            "{hints}"
        );
    }

    /// A custom harness kept beside its library outside any checkout
    /// (`harness/` + `lib/`): the target's own directory holds no definer, so
    /// the hint searches the directories of the harness's other inputs too —
    /// the extra sources the Makefile compiles, its include dirs, and the
    /// paths generation recorded — and names the file that defines the symbol.
    #[test]
    fn failed_link_hint_finds_the_definer_beside_the_harness_outside_a_checkout() {
        let temp = tempfile::tempdir().unwrap();
        let proj = temp.path().join("proj");
        let harness_src = proj.join("harness");
        let lib_src = proj.join("lib").join("src");
        let lib_inc = proj.join("lib").join("include").join("widgets");
        for dir in [&harness_src, &lib_src, &lib_inc] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(
            lib_inc.join("table.h"),
            "#pragma once\n#include <cstddef>\nnamespace widgets { struct Table { static int store(const unsigned char *d, std::size_t n); }; }\n",
        )
        .unwrap();
        fs::write(
            lib_src.join("table.cpp"),
            "#include \"widgets/table.h\"\nnamespace widgets {\nint Table::store(const unsigned char *d, std::size_t n) { return n ? d[0] : 0; }\n}\n",
        )
        .unwrap();
        fs::write(
            lib_src.join("codec.cpp"),
            "#include \"widgets/table.h\"\nint decode(const unsigned char *d, std::size_t n) { return widgets::Table::store(d, n); }\n",
        )
        .unwrap();
        fs::write(
            harness_src.join("drive_codec.cpp"),
            "#include <cstddef>\n#include <cstdint>\nint decode(const unsigned char *d, std::size_t n);\n\
             extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return decode(data, size); }\n",
        )
        .unwrap();
        let output = "codec.cpp:2: undefined reference to `widgets::Table::store(unsigned char const*, unsigned long)'\n";
        // Named by its resolved path (Windows short names expanded, no
        // `\\?\` prefix), one shell word.
        let table = shell_word(&crate::workdir::plain_canonical(&lib_src.join("table.cpp")));
        let none = RebuildEnv::default();

        // The library's source dir is known from the extra source the
        // Makefile compiles.
        let work = temp.path().join("work");
        let harness = work.join("harnesses").join("H-XCODEC");
        fs::create_dir_all(&harness).unwrap();
        fs::write(harness.join("main.cpp"), "").unwrap();
        fs::write(
            harness.join("Makefile"),
            format!(
                "INCLUDES = -I . -I /opt/bhf/c_runtime -iquote {h} -idirafter {h} -iquote {i} -idirafter {i}\n\
                 main: main.cpp bhf_driver.o $(CONTEXT_MAIN_OBJECTS)\n\t$(CXX) $(CXXFLAGS) -DBHF_EXTERNAL_DRIVER -o $@ main.cpp {t} {c} $(CONTEXT_MAIN_OBJECTS) $(AUTO_EXTRA_SOURCES) bhf_driver.o\n",
                h = harness_gen::build_safety::make_path(&harness_src),
                i = harness_gen::build_safety::make_path(&proj.join("lib").join("include")),
                t = harness_gen::build_safety::make_path(&harness_src.join("drive_codec.cpp")),
                c = harness_gen::build_safety::make_path(&lib_src.join("codec.cpp")),
            ),
        )
        .unwrap();
        let hints = c_build_failure_hints(&work, "H-XCODEC", &harness, output, &none).join("\n");
        assert!(
            hints.contains(&format!("--extra-source {table}")),
            "{hints}"
        );
        assert!(!hints.contains("no in-tree definition found"), "{hints}");

        // Known only from the --extra-include dirs generation recorded.
        let work = temp.path().join("work2");
        let harness = work.join("harnesses").join("H-XCODEC");
        fs::create_dir_all(&harness).unwrap();
        fs::write(harness.join("main.cpp"), "").unwrap();
        fs::write(
            harness.join("Makefile"),
            format!(
                "main: main.cpp bhf_driver.o\n\t$(CXX) $(CXXFLAGS) -o $@ main.cpp {t} bhf_driver.o\n",
                t = harness_gen::build_safety::make_path(&harness_src.join("drive_codec.cpp")),
            ),
        )
        .unwrap();
        fs::write(
            harness.join("generation-metadata.json"),
            serde_json::json!({
                "schema_version": 1,
                "language": "cpp",
                "extra_includes": [
                    proj.join("lib").join("include").display().to_string(),
                    lib_src.display().to_string(),
                ],
            })
            .to_string(),
        )
        .unwrap();
        let hints = c_build_failure_hints(&work, "H-XCODEC", &harness, output, &none).join("\n");
        assert!(
            hints.contains(&format!("--extra-source {table}")),
            "{hints}"
        );
    }

    #[test]
    fn failed_compile_hints_cover_std_streams_and_extra_qualification() {
        let temp = tempfile::tempdir().unwrap();
        let harness = temp.path().join("harnesses").join("H-ONE");
        fs::create_dir_all(&harness).unwrap();
        let output = "src/parser.cpp:331:2: error: use of undeclared identifier 'cerr'\n\
                      src/lexer.cpp:52:19: error: implicit instantiation of undefined template 'std::basic_istream<char>'\n\
                      src/widget.h:136:18: error: extra qualification on member 'name'\n";
        let none = RebuildEnv::default();
        let hints = c_build_failure_hints(temp.path(), "H-ONE", &harness, output, &none);
        let text = hints.join("\n");
        let line_with = |needle: &str| {
            hints
                .iter()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no hint with {needle}: {text}"))
                .clone()
        };
        assert!(
            line_with("without including")
                .contains("AUTO_EXTRA_INCLUDES='-include iostream' bhf build"),
            "{text}"
        );
        let qualification = line_with("extra class qualification");
        assert!(qualification.contains("src/widget.h:136"), "{text}");
        assert!(
            qualification.contains("AUTO_EXTRA_INCLUDES=-fms-extensions bhf build"),
            "{text}"
        );
        assert!(qualification.contains("-fpermissive"), "{text}");
        // One command applies both fixes.
        assert!(
            line_with("at once")
                .contains("AUTO_EXTRA_INCLUDES='-include iostream -fms-extensions' bhf build"),
            "{text}"
        );

        // The operator's own variables travel into every suggested command, and a
        // flag already set is not repeated.
        let inherited = RebuildEnv::from_lookup(|name| match name {
            "AUTO_EXTRA_SOURCES" => Some("/src/table.cpp".to_owned()),
            "AUTO_EXTRA_INCLUDES" => Some("-fms-extensions".to_owned()),
            "C_STD" => Some("gnu89".to_owned()),
            _ => None,
        });
        let hints = c_build_failure_hints(temp.path(), "H-ONE", &harness, output, &inherited);
        let text = hints.join("\n");
        let commands: Vec<&String> = hints
            .iter()
            .filter(|line| line.contains("bhf build"))
            .collect();
        assert!(!commands.is_empty(), "{text}");
        for command in &commands {
            assert!(
                command.contains("AUTO_EXTRA_SOURCES=/src/table.cpp ")
                    && command.contains(" C_STD=gnu89 bhf build"),
                "{text}"
            );
            assert_eq!(command.matches("-fms-extensions").count(), 1, "{text}");
        }
        assert!(
            text.contains("AUTO_EXTRA_INCLUDES='-fms-extensions -include iostream' C_STD=gnu89"),
            "{text}"
        );

        // g++ names -fpermissive itself; that is the flag to suggest.
        let gcc = "src/widget.h:136:12: error: extra qualification 'Widget::' on member 'name' [-fpermissive]\n";
        let hints = c_build_failure_hints(temp.path(), "H-ONE", &harness, gcc, &none).join("\n");
        assert!(
            hints.contains("AUTO_EXTRA_INCLUDES=-fpermissive bhf build"),
            "{hints}"
        );
        assert!(
            !hints.contains("at once"),
            "a single fix needs no combined line: {hints}"
        );
    }

    #[test]
    fn colliding_c_basenames_flags_only_same_stem_c_sources() {
        // `sxxx.adb` + `sxxx.c` -> both `sxxx.o` -> gprbuild "same object file name".
        // Only the colliding C file is returned; a C file with no Ada twin, and the
        // Ada files themselves, are left alone.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for name in [
            "sxxx.adb",
            "sxxx.c",
            "sxxx.h",
            "other.c",
            "widget.ads",
            "widget.c",
        ] {
            fs::write(dir.join(name), "x").unwrap();
        }
        let roots = vec![SourceRoot {
            path: dir.to_path_buf(),
            language: "Ada".to_owned(),
        }];
        let collisions = colliding_c_basenames(&roots);
        assert_eq!(
            collisions,
            vec!["sxxx.c".to_owned(), "widget.c".to_owned()],
            "only the C sources sharing a stem with an Ada unit collide"
        );
        assert!(
            !collisions.iter().any(|f| f == "other.c"),
            "a C file with no Ada twin must not be excluded: {collisions:?}"
        );
    }

    /// The sidecar a Windows harness build writes names exactly the PATH
    /// directories that hold an AddressSanitizer runtime DLL, in PATH order,
    /// and the first directory's DLL is staged beside the binary.
    #[test]
    fn sanitizer_runtime_dirs_are_the_path_entries_holding_the_dll() {
        let temp = tempfile::tempdir().unwrap();
        let llvm = temp.path().join("LLVM/lib/clang/23/lib/windows");
        let msvc = temp.path().join("MSVC/bin/Hostx64/x64");
        let other = temp.path().join("tools");
        for dir in [&llvm, &msvc, &other] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(llvm.join("clang_rt.asan_dynamic-x86_64.dll"), b"").unwrap();
        std::fs::write(msvc.join("clang_rt.asan_dbg_dynamic-x86_64.dll"), b"").unwrap();
        std::fs::write(other.join("clang_rt.asan_static-x86_64.lib"), b"").unwrap();
        let path =
            std::env::join_paths([&other, &msvc, &llvm, &msvc, &temp.path().join("missing")])
                .unwrap();
        assert_eq!(
            super::sanitizer_runtime_dirs(Some(&path)),
            vec![msvc.clone(), llvm.clone()]
        );
        let harness = temp.path().join("harness");
        std::fs::create_dir_all(&harness).unwrap();
        super::stage_sanitizer_runtime(&harness, Some(&path));
        assert_eq!(
            std::fs::read_to_string(harness.join(super::RUNTIME_PATH_FILE)).unwrap(),
            format!("{}\n{}\n", msvc.display(), llvm.display())
        );
        assert!(
            harness
                .join("clang_rt.asan_dbg_dynamic-x86_64.dll")
                .is_file(),
            "the first runtime directory's DLL sits beside the binary"
        );
        assert!(
            !harness.join("clang_rt.asan_dynamic-x86_64.dll").exists(),
            "another toolchain's runtime is not mixed in"
        );
        super::stage_sanitizer_runtime(&harness, Some(other.as_os_str()));
        assert!(
            !harness.join(super::RUNTIME_PATH_FILE).exists(),
            "a stale sidecar is removed"
        );
    }
}
