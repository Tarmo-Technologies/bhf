// SPDX-License-Identifier: Apache-2.0

//! The C/C++ and Ada toolchain that `bhf build` and `bhf auto` build with.
//!
//! Both commands read the same `[toolchain]` table ([`config::ToolchainConfig`])
//! from a config file and accept the same flags for it. The resolved settings
//! are published to this process's environment once, before any build starts:
//! `CC`/`CXX`, and the `BHF_TOOLCHAIN_*` variables the generated Makefiles
//! append to their own instrumentation flags. Every later `make` (harness
//! builds, retries, coverage and replay builds) inherits them, so no build path
//! can miss the operator's choice.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use config::ToolchainConfig;
use harness_gen::compiler_family::{self, CompilerFamily};

/// Make variable (published as an environment variable) carrying the C flags
/// of the toolchain, appended to bhf's on every `$(CC)` lane.
pub(crate) const ENV_CFLAGS: &str = "BHF_TOOLCHAIN_CFLAGS";
/// The C++ counterpart of [`ENV_CFLAGS`].
pub(crate) const ENV_CXXFLAGS: &str = "BHF_TOOLCHAIN_CXXFLAGS";
/// Defines and include directories, applied to every lane.
pub(crate) const ENV_CPPFLAGS: &str = "BHF_TOOLCHAIN_CPPFLAGS";
/// Link flags for the `$(CC)`/`$(CXX)` links.
pub(crate) const ENV_LDFLAGS: &str = "BHF_TOOLCHAIN_LDFLAGS";
/// `--sysroot=`/`--target=`, for every compile and link of the `$(CC)` lanes.
pub(crate) const ENV_TARGET_FLAGS: &str = "BHF_TOOLCHAIN_TARGET_FLAGS";

/// The C/C++ toolchain flags `bhf build` and `bhf auto` both accept. Each one
/// has a `[toolchain]` config key of the same name (`--toolchain-include` is
/// `include-dirs`, `--define` is `defines`).
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct CToolchainArgs {
    /// C compiler for the harness build (a program on PATH or a path). It
    /// replaces CC; bhf's instrumentation is chosen to match it (gcc and clang,
    /// cross-prefixed or not). Config key: `toolchain.cc`.
    #[arg(long = "cc", value_name = "PROGRAM")]
    pub cc: Option<String>,

    /// C++ compiler for the harness build. Config key: `toolchain.cxx`.
    #[arg(long = "cxx", value_name = "PROGRAM")]
    pub cxx: Option<String>,

    /// Extra C compiler flags, APPENDED to bhf's coverage and sanitizer flags
    /// (whitespace-separated; repeatable). Config key: `toolchain.cflags`.
    #[arg(long = "cflags", value_name = "FLAGS", allow_hyphen_values = true)]
    pub cflags: Vec<String>,

    /// Extra C++ compiler flags, appended like --cflags. Config key:
    /// `toolchain.cxxflags`.
    #[arg(long = "cxxflags", value_name = "FLAGS", allow_hyphen_values = true)]
    pub cxxflags: Vec<String>,

    /// Extra link flags for the harness binary (whitespace-separated;
    /// repeatable). Config key: `toolchain.ldflags`.
    #[arg(long = "ldflags", value_name = "FLAGS", allow_hyphen_values = true)]
    pub ldflags: Vec<String>,

    /// Preprocessor definition, `NAME` or `NAME=VALUE`, for every harness
    /// compile (repeatable). Config key: `toolchain.defines`.
    #[arg(long = "define", value_name = "NAME[=VALUE]")]
    pub defines: Vec<String>,

    /// Header search directory (`-I`) for every harness compile
    /// (repeatable). Config key: `toolchain.include-dirs`.
    #[arg(long = "toolchain-include", value_name = "DIR")]
    pub include_dirs: Vec<PathBuf>,

    /// Sysroot handed to the C/C++ compiler as `--sysroot=`. Config key:
    /// `toolchain.sysroot`.
    #[arg(long = "sysroot", value_name = "DIR")]
    pub sysroot: Option<PathBuf>,
}

impl CToolchainArgs {
    /// These flags as a `[toolchain]` table (paths relative to the CWD).
    pub(crate) fn to_config(&self) -> ToolchainConfig {
        ToolchainConfig {
            cc: self.cc.clone(),
            cxx: self.cxx.clone(),
            cflags: split_flag_args(&self.cflags),
            cxxflags: split_flag_args(&self.cxxflags),
            ldflags: split_flag_args(&self.ldflags),
            defines: self.defines.clone(),
            include_dirs: self.include_dirs.clone(),
            sysroot: self.sysroot.clone(),
            ..ToolchainConfig::default()
        }
    }

    /// The flags given, for a message about where they do not apply.
    pub(crate) fn given_flag_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.cc.is_some() {
            names.push("--cc");
        }
        if self.cxx.is_some() {
            names.push("--cxx");
        }
        if !self.cflags.is_empty() {
            names.push("--cflags");
        }
        if !self.cxxflags.is_empty() {
            names.push("--cxxflags");
        }
        if !self.ldflags.is_empty() {
            names.push("--ldflags");
        }
        if !self.defines.is_empty() {
            names.push("--define");
        }
        if !self.include_dirs.is_empty() {
            names.push("--toolchain-include");
        }
        if self.sysroot.is_some() {
            names.push("--sysroot");
        }
        names
    }
}

/// The toolchain flags of `bhf auto`: the shared C/C++ flags plus the cross
/// target, its runner, and the Ada toolchain (which `bhf build` spells
/// `--target`/`--toolchain`/`--runtime`).
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct AutoToolchainArgs {
    #[command(flatten)]
    pub c: CToolchainArgs,

    /// Build every C/C++ candidate for this GNU target triple
    /// (`aarch64-linux-gnu`), with `<triple>-gcc`/`<triple>-g++` unless
    /// --cc/--cxx name the compilers. A triple this host cannot run needs
    /// --runner. Config key: `toolchain.target`.
    #[arg(long = "target-triple", value_name = "TRIPLE")]
    pub target_triple: Option<String>,

    /// Program that runs each harness built for another target, such as
    /// `qemu-aarch64`. With --target-triple (or a cross --cc) the whole sweep
    /// is a cross sweep: every C/C++ candidate is built for the target with
    /// coverage and fuzzed under the runner. With only a foreign --ada-target
    /// it runs the Ada harnesses and the C/C++ candidates stay native. A
    /// runner with nothing foreign to run is an error. Config key:
    /// `toolchain.runner`.
    #[arg(long = "runner", value_name = "PROGRAM")]
    pub runner: Option<String>,

    /// Argument placed between the runner and the harness (repeatable, e.g.
    /// `--runner-arg=-L --runner-arg=/usr/aarch64-linux-gnu`). Defaults to
    /// `-L <sysroot>` (or `-L /usr/<triple>`) for a qemu-user runner. Config
    /// key: `toolchain.runner-args`.
    #[arg(long = "runner-arg", value_name = "ARG", allow_hyphen_values = true)]
    pub runner_args: Vec<String>,

    /// Ada tool prefix: run `<prefix>-gprbuild`/`<prefix>-gnat`; also the Ada
    /// Target when --ada-target is not given. Config key: `toolchain.ada.prefix`.
    #[arg(long = "ada-prefix", value_name = "PREFIX")]
    pub ada_prefix: Option<String>,

    /// Ada target (`for Target use`). Defaults to --target-triple. Config key:
    /// `toolchain.ada.target`.
    #[arg(long = "ada-target", value_name = "TRIPLE")]
    pub ada_target: Option<String>,

    /// Ada runtime (`for Runtime ("Ada") use`). Config key:
    /// `toolchain.ada.runtime`.
    #[arg(long = "ada-runtime", value_name = "RUNTIME")]
    pub ada_runtime: Option<String>,

    /// `gprbuild` to run (name or path). Config key: `toolchain.ada.gprbuild`.
    #[arg(long = "ada-gprbuild", value_name = "PROGRAM")]
    pub ada_gprbuild: Option<String>,

    /// `gnat` driver to run (name or path). Config key: `toolchain.ada.gnat`.
    #[arg(long = "ada-gnat", value_name = "PROGRAM")]
    pub ada_gnat: Option<String>,

    /// Extra Ada compiler switch, appended to bhf's own (repeatable). Config
    /// key: `toolchain.ada.switches`.
    #[arg(long = "ada-switch", value_name = "SWITCH", allow_hyphen_values = true)]
    pub ada_switches: Vec<String>,

    /// AdaFuzz.Probe runtime backend compiled into each Ada harness
    /// (host_file, memory_buffer, semihosting, stub; default host_file).
    /// Config key: `toolchain.ada.probe-backend`.
    #[arg(long = "probe-backend", value_name = "BACKEND")]
    pub probe_backend: Option<String>,
}

impl AutoToolchainArgs {
    /// These flags as a `[toolchain]` table (paths relative to the CWD).
    pub(crate) fn to_config(&self) -> ToolchainConfig {
        let mut config = self.c.to_config();
        config.target = self.target_triple.clone();
        config.runner = self.runner.clone();
        config.runner_args = self.runner_args.clone();
        config.ada.prefix = self.ada_prefix.clone();
        config.ada.target = self.ada_target.clone();
        config.ada.runtime = self.ada_runtime.clone();
        config.ada.gprbuild = self.ada_gprbuild.clone();
        config.ada.gnat = self.ada_gnat.clone();
        config.ada.switches = self.ada_switches.clone();
        config.ada.probe_backend = self.probe_backend.clone();
        config
    }
}

/// Each flag value split on whitespace, so `--cflags "-O2 -g"` and
/// `--cflags=-O2 --cflags=-g` mean the same.
fn split_flag_args(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split_whitespace().map(str::to_owned))
        .collect()
}

/// Read the `[toolchain]` table of `path`, resolving its relative paths
/// against the file's own directory. `Ok(None)` when the file has no table.
pub(crate) fn load_config_file(path: &Path) -> Result<Option<ToolchainConfig>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read config {}: {e}", path.display()))?;
    let mut config = ToolchainConfig::from_config_file_text(&text)
        .map_err(|e| format!("parse config {}: {e}", path.display()))?;
    if let Some(config) = &mut config {
        config.resolve_relative_to(&config_base_dir(path));
    }
    Ok(config)
}

/// The directory relative paths of a config file resolve against: the file's
/// own directory, made absolute.
pub(crate) fn config_base_dir(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::path::absolute(parent).unwrap_or_else(|_| parent.to_path_buf())
}

/// Merge command-line settings over a config file's and validate the result.
/// Command-line paths are relative to the working directory.
pub(crate) fn resolve(
    file: Option<ToolchainConfig>,
    mut cli: ToolchainConfig,
) -> Result<ToolchainConfig, String> {
    if let Ok(cwd) = std::env::current_dir() {
        cli.resolve_relative_to(&cwd);
    }
    let merged = file.unwrap_or_default().overlaid_with(cli);
    validate(&merged)?;
    Ok(merged)
}

/// [`ToolchainConfig::validate`] plus what only bhf knows: every value must be
/// usable in a generated Makefile recipe, and the probe backend must exist.
pub(crate) fn validate(config: &ToolchainConfig) -> Result<(), String> {
    config.validate().map_err(|error| error.to_string())?;
    use harness_gen::build_safety::{is_build_path_usable, is_compile_flag_usable};
    for (key, flags) in [
        ("toolchain.cflags", &config.cflags),
        ("toolchain.cxxflags", &config.cxxflags),
        ("toolchain.ldflags", &config.ldflags),
    ] {
        if let Some(flag) = flags.iter().find(|flag| !is_compile_flag_usable(flag)) {
            return Err(format!(
                "{key}: {flag:?} cannot be passed through the harness Makefile \
                 (a `$` or control character)"
            ));
        }
    }
    if let Some(define) = config
        .defines
        .iter()
        .find(|define| !is_compile_flag_usable(&format!("-D{define}")))
    {
        return Err(format!(
            "toolchain.defines: {define:?} cannot be passed through the harness Makefile"
        ));
    }
    for (key, path) in config
        .include_dirs
        .iter()
        .map(|dir| ("toolchain.include-dirs", dir))
        .chain(config.sysroot.iter().map(|dir| ("toolchain.sysroot", dir)))
    {
        if !is_build_path_usable(&path.to_string_lossy()) {
            return Err(format!(
                "{key}: {} cannot be passed through the harness Makefile",
                path.display()
            ));
        }
    }
    for (key, program) in [("toolchain.cc", &config.cc), ("toolchain.cxx", &config.cxx)] {
        if let Some(program) = program {
            if !harness_gen::build_safety::is_compiler_token(program) {
                return Err(format!(
                    "{key}: {program:?} cannot head a harness Makefile recipe"
                ));
            }
        }
    }
    if let Some(backend) = &config.ada.probe_backend {
        <crate::probe_backend::ProbeBackend as clap::ValueEnum>::from_str(backend, true).map_err(
            |_| {
                format!(
                    "toolchain.ada.probe-backend: unknown backend {backend:?} \
                     (host_file, memory_buffer, semihosting, stub)"
                )
            },
        )?;
    }
    Ok(())
}

/// The configured probe backend, defaulting to `host_file`.
pub(crate) fn probe_backend(config: &ToolchainConfig) -> crate::probe_backend::ProbeBackend {
    config
        .ada
        .probe_backend
        .as_deref()
        .and_then(|backend| {
            <crate::probe_backend::ProbeBackend as clap::ValueEnum>::from_str(backend, true).ok()
        })
        .unwrap_or(crate::probe_backend::ProbeBackend::HostFile)
}

/// The C and C++ compilers a toolchain selects, or `None` for each it leaves
/// to the environment. `cc` wins, then `<target>-gcc`; a missing one of the
/// pair is derived from the other (`clang` <-> `clang++`, `gcc` <-> `g++`).
pub(crate) fn selected_compilers(config: &ToolchainConfig) -> (Option<String>, Option<String>) {
    let from_target = |driver: &str| {
        config
            .target
            .as_deref()
            .map(|target| format!("{target}-{driver}"))
    };
    let mut cc = config.cc.clone();
    let mut cxx = config.cxx.clone();
    if cc.is_none() && cxx.is_none() {
        cc = from_target("gcc");
        cxx = from_target("g++");
    }
    if cc.is_none() {
        cc = cxx
            .as_deref()
            .filter(|cxx| compiler_family::driver_from_name(cxx).is_some())
            .map(compiler_family::c_driver_for);
    }
    if cxx.is_none() {
        cxx = cc
            .as_deref()
            .filter(|cc| compiler_family::driver_from_name(cc).is_some())
            .map(compiler_family::cxx_driver_for);
    }
    (cc, cxx)
}

/// What [`publish`] did, for the caller to report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Published {
    /// One line per setting that took effect, and per environment value it
    /// replaced.
    pub notes: Vec<String>,
}

/// Publish the C/C++ part of `config` to this process's environment. Must run
/// before any thread that reads the environment starts. Returns notes naming
/// what was set and which environment values it replaced; fails when a
/// selected compiler is not installed.
pub(crate) fn publish(config: &ToolchainConfig) -> Result<Published, String> {
    let mut published = Published::default();
    let (cc, cxx) = selected_compilers(config);
    for (variable, compiler) in [("CC", &cc), ("CXX", &cxx)] {
        let Some(compiler) = compiler else {
            continue;
        };
        if !program_exists(compiler) {
            return Err(format!(
                "the toolchain's {variable} `{compiler}` was not found{}; install it or set \
                 toolchain.{} (--{})",
                config
                    .target
                    .as_deref()
                    .filter(|_| config.cc.is_none() && config.cxx.is_none())
                    .map(|target| format!(" (derived from target {target})"))
                    .unwrap_or_default(),
                variable.to_ascii_lowercase(),
                variable.to_ascii_lowercase(),
            ));
        }
        if let Ok(previous) = std::env::var(variable) {
            if previous != *compiler {
                published.notes.push(format!(
                    "toolchain {variable}={compiler} replaces {variable}={previous} from the environment"
                ));
            }
        }
        std::env::set_var(variable, compiler);
    }
    if cc.is_some() || cxx.is_some() {
        TOOLCHAIN_CHOSE_COMPILERS.store(true, Ordering::Relaxed);
        published.notes.push(format!(
            "C/C++ toolchain: CC={} CXX={}",
            cc.as_deref().unwrap_or("(environment)"),
            cxx.as_deref().unwrap_or("(environment)")
        ));
    }
    if let Some(note) = route_msvc_through_front_end()? {
        published.notes.push(note);
    }
    let effective_cc = cc
        .clone()
        .or_else(|| std::env::var("CC").ok())
        .unwrap_or_else(|| "clang".to_owned());
    // Without any C/C++ setting the environment is left exactly as it was.
    if !config.has_c_family_settings() {
        return Ok(published);
    }
    let values = make_values(config, compiler_family(&effective_cc, false));
    for (variable, value) in values {
        if value.is_empty() {
            std::env::remove_var(variable);
            continue;
        }
        published.notes.push(format!("{variable}={value}"));
        std::env::set_var(variable, value);
    }
    Ok(published)
}

/// MSVC lane: a `CC`/`CXX` naming `cl` or `clang-cl` (from the toolchain or
/// the environment) is replaced by bhf's `bhf-cl` front end, which reads the
/// generated Makefiles' GCC-style command lines and runs that compiler with
/// cl's options. The compiler itself is published as `BHF_MSVC_CL`. Returns a
/// note saying so, or `None` when no MSVC driver was named.
pub(crate) fn route_msvc_through_front_end() -> Result<Option<String>, String> {
    let mut real: Option<PathBuf> = None;
    let mut routed = Vec::new();
    for variable in ["CC", "CXX"] {
        let Ok(value) = std::env::var(variable) else {
            continue;
        };
        let unquoted = value.trim().trim_matches('"');
        if compiler_family::family_from_name(unquoted) != Some(CompilerFamily::Msvc)
            || Path::new(unquoted)
                .file_stem()
                .is_some_and(|stem| stem.eq_ignore_ascii_case(crate::msvc_cc::FRONT_END_STEM))
        {
            continue;
        }
        let resolved = if Path::new(unquoted).is_absolute() {
            PathBuf::from(unquoted)
        } else {
            which::which(unquoted).map_err(|_| {
                format!(
                    "{variable}={unquoted} was not found on PATH (on Windows, bhf finds Visual \
                     Studio's cl.exe itself unless --no-vs-env is given)"
                )
            })?
        };
        real.get_or_insert(resolved);
        routed.push(variable);
    }
    let Some(real) = real else {
        return Ok(None);
    };
    let front_end = crate::msvc_cc::front_end_path()?;
    // `$(CC)` heads recipes that run through `sh`, which eats backslashes:
    // the front end is named with forward slashes, which Windows also reads.
    let front_end_word = harness_gen::build_safety::make_path(&front_end);
    for variable in &routed {
        std::env::set_var(variable, &front_end_word);
    }
    std::env::set_var(crate::msvc_cc::REAL_COMPILER_ENV, &real);
    // MSVC ships its own AddressSanitizer runtime DLL beside cl.exe. A
    // cl-built harness must load that one, not a clang release's same-named
    // DLL that may come earlier on PATH (it fails to start with
    // STATUS_ENTRYPOINT_NOT_FOUND), so cl's directory goes first.
    if let Some(dir) = real.parent() {
        let mut paths = vec![dir.to_path_buf()];
        if let Some(existing) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&existing).filter(|entry| entry != dir));
        }
        if let Ok(joined) = std::env::join_paths(paths) {
            std::env::set_var("PATH", joined);
        }
    }
    TOOLCHAIN_CHOSE_COMPILERS.store(true, Ordering::Relaxed);
    Ok(Some(format!(
        "C/C++ harnesses build with {} (MSVC lane) through bhf's cl front end {}",
        real.display(),
        front_end.display()
    )))
}

/// The `BHF_TOOLCHAIN_*` make values for `config`, rendered for a recipe.
/// `family` is the C compiler's: a clang building for another target needs
/// `--target=` where a cross gcc needs nothing.
pub(crate) fn make_values(
    config: &ToolchainConfig,
    family: Option<CompilerFamily>,
) -> Vec<(&'static str, String)> {
    use harness_gen::build_safety::{make_path, recipe_path, recipe_token};
    let words = |flags: &[String]| {
        flags
            .iter()
            .map(|flag| recipe_token(flag))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut target_flags = Vec::new();
    if let Some(sysroot) = &config.sysroot {
        target_flags.push(format!("--sysroot={}", recipe_path(&make_path(sysroot))));
    }
    if let (Some(target), Some(CompilerFamily::Clang)) = (&config.target, family) {
        target_flags.push(format!("--target={target}"));
    }
    let mut cppflags: Vec<String> = config
        .defines
        .iter()
        .map(|define| recipe_token(&format!("-D{define}")))
        .collect();
    cppflags.extend(
        config
            .include_dirs
            .iter()
            .map(|dir| format!("-I{}", recipe_path(&make_path(dir)))),
    );
    vec![
        (ENV_TARGET_FLAGS, target_flags.join(" ")),
        (ENV_CFLAGS, words(&config.cflags)),
        (ENV_CXXFLAGS, words(&config.cxxflags)),
        (ENV_CPPFLAGS, cppflags.join(" ")),
        (ENV_LDFLAGS, words(&config.ldflags)),
    ]
}

/// The toolchain's compile flags as plain arguments, for a compiler bhf runs
/// directly rather than through a Makefile recipe: `--sysroot=`, a clang
/// `--target=`, the defines and include directories, then `cflags` (or
/// `cxxflags` for C++).
pub(crate) fn compile_args(
    config: &ToolchainConfig,
    family: Option<CompilerFamily>,
    cxx: bool,
) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(sysroot) = &config.sysroot {
        args.push(format!("--sysroot={}", sysroot.display()));
    }
    if let (Some(target), Some(CompilerFamily::Clang)) = (&config.target, family) {
        args.push(format!("--target={target}"));
    }
    args.extend(config.defines.iter().map(|define| format!("-D{define}")));
    args.extend(
        config
            .include_dirs
            .iter()
            .map(|dir| format!("-I{}", dir.display())),
    );
    args.extend(
        if cxx {
            &config.cxxflags
        } else {
            &config.cflags
        }
        .iter()
        .cloned(),
    );
    args
}

/// Whether `program` names an executable: a path to a file, or a name found
/// on `PATH`.
pub(crate) fn program_exists(program: &str) -> bool {
    let path = Path::new(program);
    if program.contains('/') || program.contains('\\') {
        return path.is_file();
    }
    which::which(program).is_ok()
}

/// Probed compiler families, keyed by (compiler, C++ preprocessor).
type FamilyCache = Mutex<HashMap<(String, bool), Option<CompilerFamily>>>;

/// The flag family of `compiler`, asked of the compiler itself once per
/// process (`<compiler> -dM -E`), falling back to its name when it cannot run.
/// `cxx` selects the C++ preprocessor. A compiler given with arguments
/// (`ccache gcc`, `gcc -m32`) is run with them.
pub(crate) fn compiler_family(compiler: &str, cxx: bool) -> Option<CompilerFamily> {
    static CACHE: OnceLock<FamilyCache> = OnceLock::new();
    let key = (compiler.to_owned(), cxx);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache.lock().expect("family cache").get(&key) {
        return *cached;
    }
    let family = probe_family(compiler, cxx).or_else(|| {
        command_words(compiler)
            .last()
            .and_then(|program| compiler_family::family_from_name(program))
    });
    cache.lock().expect("family cache").insert(key, family);
    family
}

/// `compiler` as program + arguments: one program when it names an existing
/// file or a `PATH` entry, else split on whitespace.
fn command_words(compiler: &str) -> Vec<String> {
    let unquoted = compiler.trim().trim_matches('"');
    if program_exists(unquoted) || !unquoted.contains(char::is_whitespace) {
        vec![unquoted.to_owned()]
    } else {
        unquoted.split_whitespace().map(str::to_owned).collect()
    }
}

fn probe_family(compiler: &str, cxx: bool) -> Option<CompilerFamily> {
    use std::process::{Command, Stdio};
    let words = command_words(compiler);
    let (program, args) = words.split_first()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .args(["-dM", "-E", "-x", if cxx { "c++" } else { "c" }, "-"])
        .stdin(Stdio::null());
    let output = crate::command_output::output_with_timeout(
        &mut command,
        std::time::Duration::from_secs(60),
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    compiler_family::family_from_predefined_macros(&String::from_utf8_lossy(&output.stdout))
}

/// Set by [`publish`] once the toolchain (`[toolchain]` cc/cxx/target or
/// `--cc`/`--cxx`/`--target-triple`) has chosen the C/C++ compilers.
static TOOLCHAIN_CHOSE_COMPILERS: AtomicBool = AtomicBool::new(false);

/// The C and C++ compilers a `make` run with no explicit override uses: the
/// environment's `CC`/`CXX` (which a published toolchain set), else the clang
/// defaults bhf has always used.
pub(crate) fn effective_compilers() -> EffectiveCompilers {
    let cc = std::env::var("CC").ok().filter(|v| !v.trim().is_empty());
    let cxx = std::env::var("CXX").ok().filter(|v| !v.trim().is_empty());
    EffectiveCompilers {
        explicit: TOOLCHAIN_CHOSE_COMPILERS.load(Ordering::Relaxed)
            || cc
                .as_deref()
                .is_some_and(|cc| !is_default_compiler(cc, "clang"))
            || cxx
                .as_deref()
                .is_some_and(|cxx| !is_default_compiler(cxx, "clang++")),
        cc: cc.unwrap_or_else(|| "clang".to_owned()),
        cxx: cxx.unwrap_or_else(|| "clang++".to_owned()),
    }
}

/// Whether `compiler` (a `CC`/`CXX` value) is bhf's own default `default`:
/// the same name, or another name or path for the program that name finds on
/// `PATH` (`/usr/bin/clang`, a versioned `clang-18` it links to).
fn is_default_compiler(compiler: &str, default: &str) -> bool {
    let compiler = compiler.trim().trim_matches('"');
    if compiler == default {
        return true;
    }
    let resolve = |program: &str| {
        which::which(program)
            .ok()
            .and_then(|path| path.canonicalize().ok())
    };
    match (resolve(compiler), resolve(default)) {
        (Some(compiler), Some(default)) => compiler == default,
        _ => false,
    }
}

/// The compilers a harness build runs without an override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveCompilers {
    pub cc: String,
    pub cxx: String,
    /// Whether the operator chose them: through the toolchain (`[toolchain]`,
    /// `--cc`/`--cxx`/`--target-triple`), or with a CC/CXX that is not bhf's
    /// clang default. `CC=clang` in the environment is the default, so bhf's
    /// gcc retry still applies to it.
    pub explicit: bool,
}

/// The Ada toolchain a sweep builds with, from `[toolchain.ada]` and the
/// `--ada-*` / `--probe-backend` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaBuildSettings {
    pub(crate) target: Option<String>,
    pub(crate) runtime: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) gprbuild: Option<String>,
    pub(crate) gnat: Option<String>,
    pub(crate) switches: Vec<String>,
    pub(crate) probe_backend: crate::probe_backend::ProbeBackend,
    /// The runner Ada harnesses built for a target this host cannot run go
    /// through ([`ada_runner`]); `None` when they run natively.
    pub(crate) runner: Option<crate::auto::cross_target::CrossRunner>,
}

impl Default for AdaBuildSettings {
    fn default() -> Self {
        Self {
            target: None,
            runtime: None,
            prefix: None,
            gprbuild: None,
            gnat: None,
            switches: Vec::new(),
            probe_backend: crate::probe_backend::ProbeBackend::HostFile,
            runner: None,
        }
    }
}

impl AdaBuildSettings {
    pub(crate) fn from_config(config: &ToolchainConfig) -> Self {
        Self {
            target: config.ada_target().map(str::to_owned),
            runtime: config.ada.runtime.clone(),
            prefix: config.ada.prefix.clone(),
            gprbuild: config.ada.gprbuild.clone(),
            gnat: config.ada.gnat.clone(),
            switches: config.ada.switches.clone(),
            probe_backend: probe_backend(config),
            runner: None,
        }
    }

    /// The target the Ada harness is built for: the explicit target, else the
    /// tool prefix (which is a triple), else the host.
    pub(crate) fn effective_target(&self) -> Option<String> {
        self.target.clone().or_else(|| {
            self.prefix
                .as_deref()
                // A gprconfig compiler name (`GNAT`) is not a target.
                .filter(|prefix| project_synth::gpr_toolchain_name(prefix).is_none())
                .map(|prefix| prefix.trim_end_matches('-').to_owned())
        })
    }

    /// Whether an Ada harness built with these settings runs on this host.
    pub(crate) fn runs_natively(&self) -> bool {
        self.effective_target()
            .is_none_or(|target| triple_runs_natively(&target))
    }

    /// Fill the Ada fields of a `bhf build` argument set.
    pub(crate) fn apply_to(&self, args: &mut crate::build::BuildArgs) {
        args.target = self.target.clone();
        args.runtime = self.runtime.clone();
        args.toolchain = self.prefix.clone();
        args.probe_backend = self.probe_backend;
        args.toolchain_args.ada_gprbuild = self.gprbuild.clone();
        args.toolchain_args.ada_gnat = self.gnat.clone();
        args.toolchain_args.ada_switches = self.switches.clone();
    }
}

/// The whole-sweep cross target `bhf auto` builds every C/C++ candidate for.
/// `Ok(None)` without a runner, and when the runner is only for a foreign Ada
/// target: a C/C++ toolchain that builds for this host keeps its native,
/// sanitizer-instrumented builds. The C/C++ triple comes from `target`, else
/// from the compiler (`-dumpmachine`); a runner with no foreign C/C++ or Ada
/// target is refused.
pub(crate) fn cross_sweep_target(
    config: &ToolchainConfig,
) -> Result<Option<crate::auto::cross_target::CrossTarget>, String> {
    cross_sweep_target_with(config, &effective_compilers())
}

fn cross_sweep_target_with(
    config: &ToolchainConfig,
    effective: &EffectiveCompilers,
) -> Result<Option<crate::auto::cross_target::CrossTarget>, String> {
    let Some(runner) = config.runner.clone() else {
        return Ok(None);
    };
    if !program_exists(&runner) {
        return Err(format!(
            "the toolchain's runner `{runner}` was not found; install it or fix toolchain.runner"
        ));
    }
    let (cc, cxx) = selected_compilers(config);
    let cc = cc.unwrap_or_else(|| effective.cc.clone());
    let cxx = cxx.unwrap_or_else(|| effective.cxx.clone());
    let triple = match &config.target {
        Some(target) => target.clone(),
        None => match dump_machine(&cc) {
            Some(triple) if !triple_runs_natively(&triple) => triple,
            built_for => {
                // The C/C++ compiler builds for this host (or cannot say): a
                // runner is then only meaningful for a foreign Ada target.
                if !AdaBuildSettings::from_config(config).runs_natively() {
                    return Ok(None);
                }
                return Err(match built_for {
                    Some(triple) => format!(
                        "toolchain.runner `{runner}` is set, but nothing this sweep builds \
                         targets another platform: `{cc}` builds for {triple} (this host) and \
                         no foreign toolchain.ada target is set; set toolchain.target \
                         (--target-triple) to cross-build the C/C++ candidates, or drop the runner"
                    ),
                    None => format!(
                        "toolchain.runner `{runner}` is set but there is no toolchain.target, \
                         and `{cc} -dumpmachine` did not name one; set toolchain.target \
                         (--target-triple)"
                    ),
                });
            }
        },
    };
    let args = runner_args(config, &runner, &triple, config.sysroot.as_deref());
    Ok(Some(crate::auto::cross_target::CrossTarget {
        triple,
        cc,
        cxx,
        runner: crate::auto::cross_target::CrossRunner::Configured { exe: runner, args },
        // The toolchain's sysroot reaches every compile through the
        // published BHF_TOOLCHAIN_TARGET_FLAGS.
        sysroot: None,
        guard_lane: false,
    }))
}

/// The runner the Ada harnesses go through when they are built for a target
/// this host cannot run: the toolchain's runner, with its qemu-user `-L` taken
/// from the Ada target (the toolchain sysroot only when the C/C++ cross sweep
/// builds for that same triple). `None` without a runner or for a native Ada
/// target.
pub(crate) fn ada_runner(
    config: &ToolchainConfig,
    c_sweep: Option<&crate::auto::cross_target::CrossTarget>,
) -> Option<crate::auto::cross_target::CrossRunner> {
    let runner = config.runner.clone()?;
    let ada = AdaBuildSettings::from_config(config);
    if ada.runs_natively() {
        return None;
    }
    let triple = ada.effective_target()?;
    let sysroot = config
        .sysroot
        .as_deref()
        .filter(|_| c_sweep.is_some_and(|sweep| sweep.triple == triple));
    let args = runner_args(config, &runner, &triple, sysroot);
    Some(crate::auto::cross_target::CrossRunner::Configured { exe: runner, args })
}

/// The arguments placed between `runner` and a harness built for `triple`:
/// `toolchain.runner-args` when given, else `-L <sysroot>` for a qemu-user
/// runner (`sysroot`, or `/usr/<triple>` when that directory exists).
fn runner_args(
    config: &ToolchainConfig,
    runner: &str,
    triple: &str,
    sysroot: Option<&Path>,
) -> Vec<String> {
    if !config.runner_args.is_empty() {
        return config.runner_args.clone();
    }
    let qemu_user = Path::new(runner)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("qemu-"));
    if !qemu_user {
        return Vec::new();
    }
    sysroot
        .map(Path::to_path_buf)
        .or_else(|| Some(PathBuf::from("/usr").join(triple)).filter(|dir| dir.is_dir()))
        .map(|dir| vec!["-L".to_owned(), dir.display().to_string()])
        .unwrap_or_default()
}

/// Refuse a toolchain `bhf auto` could build but never run: a C/C++ or Ada
/// target this host cannot execute, with no runner to execute it. Without a
/// `target`, the C/C++ compilers the toolchain or the environment (CC/CXX)
/// name are asked which target they build for.
pub(crate) fn check_runnable(config: &ToolchainConfig) -> Result<(), String> {
    let ambient = |variable: &str| {
        std::env::var(variable)
            .ok()
            .filter(|v| !v.trim().is_empty())
    };
    check_runnable_with(config, ambient("CC"), ambient("CXX"))
}

fn check_runnable_with(
    config: &ToolchainConfig,
    ambient_cc: Option<String>,
    ambient_cxx: Option<String>,
) -> Result<(), String> {
    if config.runner.is_some() {
        return Ok(());
    }
    if let Some(target) = config.target.as_deref() {
        if !triple_runs_natively(target) {
            return Err(format!(
                "toolchain.target `{target}` does not run on this host; set toolchain.runner \
                 (--runner, an emulator such as {}) so bhf auto can fuzz it, or use bhf build \
                 to only compile",
                runner_hint(target)
            ));
        }
    } else {
        let (cc, cxx) = selected_compilers(config);
        let chosen = [
            ("CC", "toolchain.cc (--cc)", cc, ambient_cc),
            ("CXX", "toolchain.cxx (--cxx)", cxx, ambient_cxx),
        ];
        for (variable, key, selected, ambient) in chosen {
            let (origin, compiler) = match (selected, ambient) {
                (Some(compiler), _) => (format!("the toolchain's {variable} ({key})"), compiler),
                (None, Some(compiler)) => (format!("{variable} from the environment"), compiler),
                (None, None) => continue,
            };
            if let Some(triple) = dump_machine(&compiler).filter(|t| !triple_runs_natively(t)) {
                return Err(format!(
                    "{origin}, `{compiler}`, builds for {triple}, which does not run on this \
                     host; set toolchain.runner (--runner, an emulator such as {}) so bhf auto \
                     can fuzz it, or use bhf build to only compile",
                    runner_hint(&triple)
                ));
            }
        }
    }
    let ada = AdaBuildSettings::from_config(config);
    if !ada.runs_natively() {
        let target = ada.effective_target().unwrap_or_default();
        return Err(format!(
            "toolchain.ada target `{target}` does not run on this host; set toolchain.runner \
             (--runner, an emulator such as {}) so bhf auto can fuzz it, or use bhf build to \
             only compile",
            runner_hint(&target)
        ));
    }
    Ok(())
}

/// An emulator that runs `triple`'s programs, for an error message.
fn runner_hint(triple: &str) -> String {
    let lower = triple.to_ascii_lowercase();
    if lower.contains("mingw") || lower.contains("windows") {
        return "wine".to_owned();
    }
    let arch = triple.split('-').next().unwrap_or_default();
    format!("qemu-{}", if arch.is_empty() { "<arch>" } else { arch })
}

/// Whether `compiler` builds programs this host runs: its `-dumpmachine`
/// triple is the host's, or it cannot say. Asked once per compiler.
pub(crate) fn compiler_builds_for_host(compiler: &str) -> bool {
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(known) = cache.lock().expect("host cache").get(compiler) {
        return *known;
    }
    let host = dump_machine(compiler).is_none_or(|triple| triple_runs_natively(&triple));
    cache
        .lock()
        .expect("host cache")
        .insert(compiler.to_owned(), host);
    host
}

/// `<compiler> -dumpmachine`, the triple it builds for.
fn dump_machine(compiler: &str) -> Option<String> {
    let words = command_words(compiler);
    let (program, args) = words.split_first()?;
    let mut command = std::process::Command::new(program);
    command.args(args).arg("-dumpmachine");
    let output = crate::command_output::output_with_timeout(
        &mut command,
        std::time::Duration::from_secs(60),
    )
    .ok()?;
    let triple = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && !triple.is_empty()).then_some(triple)
}

/// Whether `triple` can run on this host without an emulator: its
/// architecture is the host's and it targets the host OS family.
pub(crate) fn triple_runs_natively(triple: &str) -> bool {
    let arch = triple.split('-').next().unwrap_or_default();
    let host = std::env::consts::ARCH;
    let same_arch = match host {
        "x86_64" => matches!(arch, "x86_64" | "amd64"),
        "x86" => matches!(arch, "i386" | "i486" | "i586" | "i686" | "x86"),
        "aarch64" => matches!(arch, "aarch64" | "arm64"),
        "arm" => arch.starts_with("arm"),
        other => arch == other,
    };
    let os = triple.to_ascii_lowercase();
    let same_os = match std::env::consts::OS {
        "linux" => os.contains("linux"),
        "windows" => os.contains("mingw") || os.contains("windows") || os.contains("msvc"),
        "macos" => os.contains("darwin") || os.contains("apple"),
        other => os.contains(other),
    };
    same_arch && same_os
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_selects_the_prefixed_gcc_pair_unless_a_compiler_is_given() {
        let config = ToolchainConfig {
            target: Some("aarch64-linux-gnu".to_owned()),
            ..ToolchainConfig::default()
        };
        assert_eq!(
            selected_compilers(&config),
            (
                Some("aarch64-linux-gnu-gcc".to_owned()),
                Some("aarch64-linux-gnu-g++".to_owned())
            )
        );
        let config = ToolchainConfig {
            target: Some("aarch64-linux-gnu".to_owned()),
            cc: Some("clang".to_owned()),
            ..ToolchainConfig::default()
        };
        assert_eq!(
            selected_compilers(&config),
            (Some("clang".to_owned()), Some("clang++".to_owned()))
        );
        let config = ToolchainConfig {
            cxx: Some("/opt/x/bin/arm-none-eabi-g++".to_owned()),
            ..ToolchainConfig::default()
        };
        assert_eq!(
            selected_compilers(&config),
            (
                Some("/opt/x/bin/arm-none-eabi-gcc".to_owned()),
                Some("/opt/x/bin/arm-none-eabi-g++".to_owned())
            )
        );
        assert_eq!(
            selected_compilers(&ToolchainConfig::default()),
            (None, None)
        );
    }

    #[test]
    fn make_values_render_defines_dirs_sysroot_and_a_clang_target() {
        let config = ToolchainConfig {
            defines: vec!["BOARD=3".to_owned(), "NAME=a b".to_owned()],
            include_dirs: vec![PathBuf::from("/opt/sdk dir/include")],
            sysroot: Some(PathBuf::from("/opt/sysroot")),
            target: Some("aarch64-linux-gnu".to_owned()),
            cflags: vec!["-O2".to_owned()],
            ldflags: vec!["-lm".to_owned()],
            ..ToolchainConfig::default()
        };
        let values: HashMap<_, _> = make_values(&config, Some(CompilerFamily::Clang))
            .into_iter()
            .collect();
        assert_eq!(values[ENV_CFLAGS], "-O2");
        assert_eq!(values[ENV_LDFLAGS], "-lm");
        assert_eq!(
            values[ENV_CPPFLAGS],
            "-DBOARD=3 '-DNAME=a b' -I\"/opt/sdk dir/include\""
        );
        assert_eq!(
            values[ENV_TARGET_FLAGS],
            "--sysroot=/opt/sysroot --target=aarch64-linux-gnu"
        );
        // A cross gcc already builds for its target; it gets no --target=.
        let values: HashMap<_, _> = make_values(&config, Some(CompilerFamily::Gcc))
            .into_iter()
            .collect();
        assert_eq!(values[ENV_TARGET_FLAGS], "--sysroot=/opt/sysroot");
    }

    #[test]
    fn compile_args_are_plain_arguments_in_toolchain_order() {
        let config = ToolchainConfig {
            defines: vec!["NAME=a b".to_owned()],
            include_dirs: vec![PathBuf::from("/opt/sdk dir/include")],
            sysroot: Some(PathBuf::from("/opt/sysroot")),
            target: Some("aarch64-linux-gnu".to_owned()),
            cflags: vec!["-mcpu=cortex-a53".to_owned()],
            cxxflags: vec!["-fno-rtti".to_owned()],
            ..ToolchainConfig::default()
        };
        assert_eq!(
            compile_args(&config, Some(CompilerFamily::Gcc), false),
            [
                "--sysroot=/opt/sysroot",
                "-DNAME=a b",
                "-I/opt/sdk dir/include",
                "-mcpu=cortex-a53"
            ]
        );
        assert_eq!(
            compile_args(&config, Some(CompilerFamily::Clang), true),
            [
                "--sysroot=/opt/sysroot",
                "--target=aarch64-linux-gnu",
                "-DNAME=a b",
                "-I/opt/sdk dir/include",
                "-fno-rtti"
            ]
        );
    }

    #[test]
    fn flag_arguments_split_on_whitespace() {
        let args = CToolchainArgs {
            cflags: vec!["-O2 -g".to_owned(), "-Wall".to_owned()],
            ..CToolchainArgs::default()
        };
        assert_eq!(args.to_config().cflags, ["-O2", "-g", "-Wall"]);
        assert_eq!(args.given_flag_names(), ["--cflags"]);
    }

    #[test]
    fn validation_refuses_values_a_makefile_cannot_carry_and_unknown_backends() {
        let config = ToolchainConfig {
            cflags: vec!["-DX=$(shell id)".to_owned()],
            ..ToolchainConfig::default()
        };
        assert!(validate(&config).unwrap_err().contains("toolchain.cflags"));
        let mut config = ToolchainConfig::default();
        config.ada.probe_backend = Some("serial".to_owned());
        assert!(validate(&config)
            .unwrap_err()
            .contains("toolchain.ada.probe-backend"));
        config.ada.probe_backend = Some("memory_buffer".to_owned());
        validate(&config).unwrap();
        assert_eq!(
            probe_backend(&config),
            crate::probe_backend::ProbeBackend::MemoryBuffer
        );
    }

    #[test]
    fn a_foreign_target_needs_a_runner_and_a_runner_makes_a_cross_sweep() {
        let foreign = if std::env::consts::ARCH == "aarch64" {
            "x86_64-linux-gnu"
        } else {
            "aarch64-linux-gnu"
        };
        let config = ToolchainConfig {
            target: Some(foreign.to_owned()),
            ..ToolchainConfig::default()
        };
        assert!(check_runnable_with(&config, None, None)
            .unwrap_err()
            .contains("toolchain.runner"));
        let mut ada = ToolchainConfig::default();
        ada.ada.prefix = Some(foreign.to_owned());
        assert!(check_runnable_with(&ada, None, None)
            .unwrap_err()
            .contains("toolchain.ada"));
        check_runnable_with(&ToolchainConfig::default(), None, None).unwrap();
        assert_eq!(cross_sweep_target(&config).unwrap(), None);

        if program_exists("qemu-aarch64") && foreign == "aarch64-linux-gnu" {
            let config = ToolchainConfig {
                target: Some(foreign.to_owned()),
                runner: Some("qemu-aarch64".to_owned()),
                sysroot: Some(PathBuf::from("/opt/sysroot")),
                ..ToolchainConfig::default()
            };
            check_runnable_with(&config, None, None).unwrap();
            let target = cross_sweep_target(&config).unwrap().unwrap();
            assert_eq!(target.triple, foreign);
            assert_eq!(target.cc, "aarch64-linux-gnu-gcc");
            assert_eq!(target.cxx, "aarch64-linux-gnu-g++");
            assert_eq!(
                target.runner,
                crate::auto::cross_target::CrossRunner::Configured {
                    exe: "qemu-aarch64".to_owned(),
                    args: vec!["-L".to_owned(), "/opt/sysroot".to_owned()],
                }
            );
            let explicit = ToolchainConfig {
                runner_args: vec!["-cpu".to_owned(), "max".to_owned()],
                ..config
            };
            let target = cross_sweep_target(&explicit).unwrap().unwrap();
            assert!(matches!(
                target.runner,
                crate::auto::cross_target::CrossRunner::Configured { ref args, .. }
                    if args == &["-cpu", "max"]
            ));
        }
        let missing = ToolchainConfig {
            target: Some(foreign.to_owned()),
            runner: Some("/nonexistent/qemu".to_owned()),
            ..ToolchainConfig::default()
        };
        assert!(cross_sweep_target(&missing)
            .unwrap_err()
            .contains("not found"));
    }

    /// The triple a foreign architecture would use on this host.
    fn foreign_triple() -> &'static str {
        if std::env::consts::ARCH == "aarch64" {
            "x86_64-linux-gnu"
        } else {
            "aarch64-linux-gnu"
        }
    }

    /// A stand-in compiler at `dir/name` that answers `-dumpmachine` with
    /// `triple` and fails everything else.
    #[cfg(unix)]
    fn fake_compiler(dir: &Path, name: &str, triple: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = -dumpmachine ]; then echo {triple}; exit 0; fi\nexit 1\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    #[cfg(unix)]
    #[test]
    fn a_compiler_that_builds_for_another_target_needs_a_runner() {
        let dir = tempfile::tempdir().unwrap();
        let foreign = foreign_triple();
        let cross = fake_compiler(dir.path(), &format!("{foreign}-gcc"), foreign);
        let host = fake_compiler(
            dir.path(),
            "host-cc",
            &format!("{}-pc-linux-gnu", std::env::consts::ARCH),
        );
        let config = ToolchainConfig {
            cc: Some(cross.clone()),
            ..ToolchainConfig::default()
        };
        let error = check_runnable_with(&config, None, None).unwrap_err();
        assert!(
            error.contains("toolchain.runner") && error.contains(foreign) && error.contains("--cc"),
            "{error}"
        );
        // From the environment, with nothing configured.
        let error = check_runnable_with(&ToolchainConfig::default(), Some(cross.clone()), None)
            .unwrap_err();
        assert!(
            error.contains("CC from the environment") && error.contains("toolchain.runner"),
            "{error}"
        );
        // A toolchain compiler wins over the environment's.
        let host_config = ToolchainConfig {
            cc: Some(host.clone()),
            cxx: Some(host.clone()),
            ..ToolchainConfig::default()
        };
        check_runnable_with(&host_config, Some(cross.clone()), Some(cross.clone())).unwrap();
        // With a runner, the foreign compiler is what the cross sweep builds with.
        let with_runner = ToolchainConfig {
            runner: Some("qemu-user".to_owned()),
            ..config
        };
        check_runnable_with(&with_runner, None, None).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_runner_for_a_foreign_ada_target_leaves_the_c_family_sweep_native() {
        let dir = tempfile::tempdir().unwrap();
        let foreign = foreign_triple();
        let runner = fake_compiler(dir.path(), "user-emulator", foreign);
        let host = fake_compiler(
            dir.path(),
            "host-cc",
            &format!("{}-pc-linux-gnu", std::env::consts::ARCH),
        );
        let effective = EffectiveCompilers {
            cc: host.clone(),
            cxx: host.clone(),
            explicit: false,
        };
        let mut config = ToolchainConfig {
            runner: Some(runner.clone()),
            sysroot: Some(PathBuf::from("/opt/c-sysroot")),
            ..ToolchainConfig::default()
        };
        // Nothing foreign at all: the runner has nothing to run.
        let error = cross_sweep_target_with(&config, &effective).unwrap_err();
        assert!(
            error.contains("toolchain.target") && error.contains("this host"),
            "{error}"
        );
        assert_eq!(ada_runner(&config, None), None);

        // A foreign Ada target: the C/C++ candidates stay native, and the Ada
        // harnesses get the runner with the Ada target's library directory, not
        // the C/C++ sysroot.
        config.ada.target = Some(foreign.to_owned());
        assert_eq!(cross_sweep_target_with(&config, &effective).unwrap(), None);
        let usr = PathBuf::from("/usr").join(foreign);
        let expected = if usr.is_dir() {
            vec!["-L".to_owned(), usr.display().to_string()]
        } else {
            Vec::new()
        };
        assert_eq!(
            ada_runner(&config, None),
            Some(crate::auto::cross_target::CrossRunner::Configured {
                exe: runner.clone(),
                args: Vec::new(),
            }),
            "a runner not named qemu-* gets no default arguments"
        );
        let qemu = fake_compiler(dir.path(), "qemu-aarch64", foreign);
        config.runner = Some(qemu.clone());
        assert_eq!(
            ada_runner(&config, None),
            Some(crate::auto::cross_target::CrossRunner::Configured {
                exe: qemu.clone(),
                args: expected,
            })
        );
        // A C/C++ sweep for the same triple shares its sysroot with Ada.
        let sweep = crate::auto::cross_target::CrossTarget {
            triple: foreign.to_owned(),
            cc: String::new(),
            cxx: String::new(),
            runner: crate::auto::cross_target::CrossRunner::Configured {
                exe: qemu.clone(),
                args: Vec::new(),
            },
            sysroot: None,
            guard_lane: false,
        };
        assert_eq!(
            ada_runner(&config, Some(&sweep)),
            Some(crate::auto::cross_target::CrossRunner::Configured {
                exe: qemu.clone(),
                args: vec!["-L".to_owned(), "/opt/c-sysroot".to_owned()],
            })
        );

        // A compiler that builds for the foreign target makes a C/C++ sweep.
        let cross = fake_compiler(dir.path(), "cross-cc", foreign);
        let effective = EffectiveCompilers {
            cc: cross.clone(),
            cxx: cross.clone(),
            explicit: true,
        };
        let sweep = cross_sweep_target_with(&config, &effective)
            .unwrap()
            .expect("a foreign compiler with a runner is a cross sweep");
        assert_eq!(sweep.triple, foreign);
        assert_eq!(sweep.cc, cross);
    }

    #[test]
    fn bhfs_own_clang_default_is_not_an_operator_compiler() {
        assert!(is_default_compiler("clang", "clang"));
        assert!(is_default_compiler(" \"clang++\" ", "clang++"));
        assert!(!is_default_compiler("/nonexistent/bin/clang", "clang"));
        if let Ok(path) = which::which("clang") {
            assert!(is_default_compiler(&path.display().to_string(), "clang"));
        }
        if program_exists("gcc") && program_exists("clang") {
            assert!(!is_default_compiler("gcc", "clang"));
        }
    }

    #[test]
    fn ada_settings_take_the_toolchain_target_and_fill_build_args() {
        let mut config = ToolchainConfig {
            target: Some("x86_64-linux-gnu".to_owned()),
            ..ToolchainConfig::default()
        };
        config.ada.runtime = Some("light".to_owned());
        config.ada.switches = vec!["-O1".to_owned()];
        config.ada.probe_backend = Some("stub".to_owned());
        let ada = AdaBuildSettings::from_config(&config);
        assert_eq!(ada.target.as_deref(), Some("x86_64-linux-gnu"));
        let named = AdaBuildSettings {
            prefix: Some("GNAT".to_owned()),
            ..AdaBuildSettings::default()
        };
        assert_eq!(
            named.effective_target(),
            None,
            "a compiler name is no target"
        );
        assert!(named.runs_natively());
        let mut args = crate::build::BuildArgs {
            work_dir: PathBuf::from("/w"),
            source_project: None,
            harness: None,
            target: None,
            runtime: None,
            toolchain: None,
            probe_backend: crate::probe_backend::ProbeBackend::HostFile,
            toolchain_args: Default::default(),
            c_engine: crate::build::CEngine::Libfuzzer,
        };
        ada.apply_to(&mut args);
        assert_eq!(args.target.as_deref(), Some("x86_64-linux-gnu"));
        assert_eq!(args.runtime.as_deref(), Some("light"));
        assert_eq!(args.toolchain_args.ada_switches, ["-O1"]);
        assert_eq!(args.probe_backend, crate::probe_backend::ProbeBackend::Stub);
    }

    #[test]
    fn the_host_triple_runs_natively_and_a_foreign_one_does_not() {
        let host = format!(
            "{}-unknown-{}-gnu",
            std::env::consts::ARCH,
            std::env::consts::OS
        );
        assert!(triple_runs_natively(&host), "{host}");
        let foreign = if std::env::consts::ARCH == "aarch64" {
            "x86_64-linux-gnu"
        } else {
            "aarch64-linux-gnu"
        };
        assert!(!triple_runs_natively(foreign));
        assert!(!triple_runs_natively("x86_64-w64-mingw32") || cfg!(windows));
    }

    #[test]
    fn the_family_comes_from_the_compiler_and_falls_back_to_its_name() {
        if program_exists("gcc") {
            assert_eq!(compiler_family("gcc", false), Some(CompilerFamily::Gcc));
        }
        if program_exists("clang++") {
            assert_eq!(
                compiler_family("clang++", true),
                Some(CompilerFamily::Clang)
            );
        }
        // Not installed: the name decides.
        assert_eq!(
            compiler_family("/nonexistent/bin/mips-linux-gnu-gcc", false),
            Some(CompilerFamily::Gcc)
        );
        assert_eq!(compiler_family("/nonexistent/bin/cc", false), None);
    }
}
