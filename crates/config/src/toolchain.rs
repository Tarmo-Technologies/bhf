// SPDX-License-Identifier: Apache-2.0

//! The `[toolchain]` table that `bhf auto --config` and `bhf build --config`
//! share: which C/C++ compiler builds a harness, the flags it gets, the target
//! it builds for, the emulator that runs a foreign binary, and the Ada
//! toolchain. One struct serves both commands so a project describes its
//! toolchain once.
//!
//! ```toml
//! [toolchain]
//! cc = "aarch64-linux-gnu-gcc"
//! cxx = "aarch64-linux-gnu-g++"
//! cflags = ["-O1"]
//! defines = ["BOARD=3"]
//! include-dirs = ["vendor/include"]
//! target = "aarch64-linux-gnu"
//! runner = "qemu-aarch64"
//! runner-args = ["-L", "/usr/aarch64-linux-gnu"]
//!
//! [toolchain.ada]
//! prefix = "aarch64-linux-gnu"
//! runtime = "light"
//! switches = ["-O1"]
//! probe-backend = "memory_buffer"
//! ```
//!
//! Relative paths are resolved against the directory of the file they came
//! from ([`ToolchainConfig::resolve_relative_to`]), so a config behaves the same
//! whatever directory bhf runs from.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// C/C++ and Ada toolchain settings. Every field is optional: an empty table
/// changes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ToolchainConfig {
    /// C compiler: a program name looked up on `PATH`, or a path.
    pub cc: Option<String>,
    /// C++ compiler: a program name looked up on `PATH`, or a path.
    pub cxx: Option<String>,
    /// Extra flags for the C compiler, appended to bhf's own instrumentation.
    #[serde(default)]
    pub cflags: Vec<String>,
    /// Extra flags for the C++ compiler, appended to bhf's own instrumentation.
    #[serde(default)]
    pub cxxflags: Vec<String>,
    /// Extra flags for the harness link.
    #[serde(default)]
    pub ldflags: Vec<String>,
    /// Preprocessor definitions, `NAME` or `NAME=VALUE`.
    #[serde(default)]
    pub defines: Vec<String>,
    /// Header search directories (`-I`).
    #[serde(default)]
    pub include_dirs: Vec<PathBuf>,
    /// GNU target triple to build for (`aarch64-linux-gnu`). Without `cc`/`cxx`
    /// it selects `<target>-gcc`/`<target>-g++`.
    pub target: Option<String>,
    /// Sysroot handed to the compiler as `--sysroot=`.
    pub sysroot: Option<PathBuf>,
    /// Program that runs a harness built for `target` (`qemu-aarch64`).
    pub runner: Option<String>,
    /// Arguments placed between the runner and the harness.
    #[serde(default)]
    pub runner_args: Vec<String>,
    /// Ada toolchain settings (`[toolchain.ada]`).
    #[serde(default)]
    pub ada: AdaToolchainConfig,
}

/// The `[toolchain.ada]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AdaToolchainConfig {
    /// Tool prefix: bhf runs `<prefix>-gprbuild` and `<prefix>-gnat`.
    pub prefix: Option<String>,
    /// Explicit `gprbuild` program (name or path).
    pub gprbuild: Option<String>,
    /// Explicit `gnat` driver (name or path).
    pub gnat: Option<String>,
    /// Target written into the generated project as `for Target use`.
    /// Defaults to `[toolchain] target`.
    pub target: Option<String>,
    /// Ada runtime (`for Runtime ("Ada") use`).
    pub runtime: Option<String>,
    /// Extra Ada compiler switches, appended to bhf's own.
    #[serde(default)]
    pub switches: Vec<String>,
    /// AdaFuzz probe backend compiled into the harness runtime.
    pub probe_backend: Option<String>,
}

/// One `[cross.<guard>]` table of a `bhf auto` config: the toolchain and
/// emulator the guard-driven cross lane uses for candidates whose definition
/// is guarded for that foreign platform (`aarch64`, `armhf`, `mingw`, `ppc`,
/// ...), in place of bhf's built-in choice. Every field is optional; one left
/// out keeps the built-in value.
///
/// ```toml
/// [cross.aarch64]
/// cc = "/opt/arm/bin/aarch64-none-linux-gnu-gcc"
/// sysroot = "/opt/arm/aarch64-none-linux-gnu/libc"
/// runner = "qemu-aarch64"
/// runner-args = ["-L", "/opt/arm/aarch64-none-linux-gnu/libc"]
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CrossGuardConfig {
    /// GNU target triple the candidates are built for. Without `cc`/`cxx` it
    /// selects `<target>-gcc`/`<target>-g++`.
    pub target: Option<String>,
    /// C compiler: a program name looked up on `PATH`, or a path.
    pub cc: Option<String>,
    /// C++ compiler: a program name looked up on `PATH`, or a path.
    pub cxx: Option<String>,
    /// Sysroot handed to the compiler as `--sysroot=` (and, for a qemu-user
    /// runner without `runner-args`, as its `-L`).
    pub sysroot: Option<PathBuf>,
    /// Program that runs the cross-built harness (`qemu-aarch64`, `wine`).
    pub runner: Option<String>,
    /// Arguments placed between the runner and the harness.
    #[serde(default)]
    pub runner_args: Vec<String>,
}

/// The `[cross]` tables of a config file, by guard name.
pub type CrossConfig = BTreeMap<String, CrossGuardConfig>;

impl CrossGuardConfig {
    /// Whether the table sets nothing at all.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Resolve relative paths against `base` (the directory of the config
    /// file), as [`ToolchainConfig::resolve_relative_to`] does.
    pub fn resolve_relative_to(&mut self, base: &Path) {
        if let Some(sysroot) = &mut self.sysroot {
            resolve_dir(sysroot, base);
        }
        for program in [&mut self.cc, &mut self.cxx, &mut self.runner]
            .into_iter()
            .flatten()
        {
            resolve_program(program, base);
        }
    }

    /// Check every value of the `[cross.<guard>]` table for shape; errors name
    /// the key as `cross.<guard>.<key>`.
    pub fn validate(&self, guard: &str) -> Result<(), ToolchainConfigError> {
        let key = |name: &str| format!("cross.{guard}.{name}");
        for (name, program) in [
            ("cc", &self.cc),
            ("cxx", &self.cxx),
            ("runner", &self.runner),
        ] {
            if let Some(program) = program {
                check_program(&key(name), program)?;
            }
        }
        for arg in &self.runner_args {
            check_word(&key("runner-args"), arg)?;
        }
        if let Some(sysroot) = &self.sysroot {
            check_dir(&key("sysroot"), sysroot)?;
        }
        if let Some(target) = &self.target {
            check_triple(&key("target"), target)?;
        }
        Ok(())
    }
}

/// The `[cross]` tables of a whole config file (empty when it has none).
/// Other top-level keys are not looked at here.
pub fn cross_config_from_file_text(text: &str) -> Result<CrossConfig, String> {
    let table: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
    match table.get("cross") {
        None => Ok(CrossConfig::new()),
        Some(value) => value
            .clone()
            .try_into::<CrossConfig>()
            .map_err(|error| format!("[cross]: {error}")),
    }
}

/// A `[toolchain]` value that cannot be used, naming the key and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainConfigError {
    key: String,
    reason: String,
}

impl ToolchainConfigError {
    fn new(key: &str, reason: impl Into<String>) -> Self {
        Self {
            key: key.to_owned(),
            reason: reason.into(),
        }
    }

    /// The offending key, in its config spelling (`toolchain.ada.runtime`).
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for ToolchainConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.reason)
    }
}

impl std::error::Error for ToolchainConfigError {}

impl ToolchainConfig {
    /// Parse a `[toolchain]` table on its own (the table body, not the file).
    pub fn from_toml_str(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|error| error.to_string())
    }

    /// The `[toolchain]` table of a whole config file, or `None` when the file
    /// has none. Other top-level keys belong to the command that owns them and
    /// are not looked at here.
    pub fn from_config_file_text(text: &str) -> Result<Option<Self>, String> {
        let table: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
        match table.get("toolchain") {
            None => Ok(None),
            Some(value) => value
                .clone()
                .try_into::<ToolchainConfig>()
                .map(Some)
                .map_err(|error| format!("[toolchain]: {error}")),
        }
    }

    /// Whether the table sets nothing at all.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Whether any C/C++ setting is present.
    pub fn has_c_family_settings(&self) -> bool {
        self.cc.is_some()
            || self.cxx.is_some()
            || !self.cflags.is_empty()
            || !self.cxxflags.is_empty()
            || !self.ldflags.is_empty()
            || !self.defines.is_empty()
            || !self.include_dirs.is_empty()
            || self.target.is_some()
            || self.sysroot.is_some()
    }

    /// The Ada target: `[toolchain.ada] target`, else `[toolchain] target`.
    pub fn ada_target(&self) -> Option<&str> {
        self.ada.target.as_deref().or(self.target.as_deref())
    }

    /// Resolve relative paths against `base` (the directory of the config
    /// file). Directories always resolve; a program (`cc`, `runner`, ...)
    /// resolves only when it names a path, since a bare name is looked up on
    /// `PATH`.
    pub fn resolve_relative_to(&mut self, base: &Path) {
        for dir in &mut self.include_dirs {
            resolve_dir(dir, base);
        }
        if let Some(sysroot) = &mut self.sysroot {
            resolve_dir(sysroot, base);
        }
        for program in [
            &mut self.cc,
            &mut self.cxx,
            &mut self.runner,
            &mut self.ada.gprbuild,
            &mut self.ada.gnat,
        ]
        .into_iter()
        .flatten()
        {
            resolve_program(program, base);
        }
    }

    /// `self` with every value `over` sets taking its place. A list replaces
    /// the whole list when `over` gives a non-empty one, so command-line flags
    /// win over a config file key by key.
    pub fn overlaid_with(mut self, over: ToolchainConfig) -> Self {
        fn scalar<T>(base: &mut Option<T>, over: Option<T>) {
            if over.is_some() {
                *base = over;
            }
        }
        fn list<T>(base: &mut Vec<T>, over: Vec<T>) {
            if !over.is_empty() {
                *base = over;
            }
        }
        scalar(&mut self.cc, over.cc);
        scalar(&mut self.cxx, over.cxx);
        list(&mut self.cflags, over.cflags);
        list(&mut self.cxxflags, over.cxxflags);
        list(&mut self.ldflags, over.ldflags);
        list(&mut self.defines, over.defines);
        list(&mut self.include_dirs, over.include_dirs);
        scalar(&mut self.target, over.target);
        scalar(&mut self.sysroot, over.sysroot);
        scalar(&mut self.runner, over.runner);
        list(&mut self.runner_args, over.runner_args);
        scalar(&mut self.ada.prefix, over.ada.prefix);
        scalar(&mut self.ada.gprbuild, over.ada.gprbuild);
        scalar(&mut self.ada.gnat, over.ada.gnat);
        scalar(&mut self.ada.target, over.ada.target);
        scalar(&mut self.ada.runtime, over.ada.runtime);
        list(&mut self.ada.switches, over.ada.switches);
        scalar(&mut self.ada.probe_backend, over.ada.probe_backend);
        self
    }

    /// Check every value for shape. This catches what would otherwise surface
    /// as a confusing compiler or gprbuild error much later: an empty program
    /// name, a define that is not `NAME[=VALUE]`, a target that is not a
    /// triple, a quote that would end a GPR string, `runner-args` without a
    /// `runner`.
    pub fn validate(&self) -> Result<(), ToolchainConfigError> {
        for (key, program) in [
            ("toolchain.cc", &self.cc),
            ("toolchain.cxx", &self.cxx),
            ("toolchain.runner", &self.runner),
            ("toolchain.ada.gprbuild", &self.ada.gprbuild),
            ("toolchain.ada.gnat", &self.ada.gnat),
        ] {
            if let Some(program) = program {
                check_program(key, program)?;
            }
        }
        for (key, flags) in [
            ("toolchain.cflags", &self.cflags),
            ("toolchain.cxxflags", &self.cxxflags),
            ("toolchain.ldflags", &self.ldflags),
            ("toolchain.runner-args", &self.runner_args),
        ] {
            for flag in flags {
                check_word(key, flag)?;
            }
        }
        for define in &self.defines {
            check_define(define)?;
        }
        for dir in &self.include_dirs {
            check_dir("toolchain.include-dirs", dir)?;
        }
        if let Some(sysroot) = &self.sysroot {
            check_dir("toolchain.sysroot", sysroot)?;
        }
        if let Some(target) = &self.target {
            check_triple("toolchain.target", target)?;
        }
        if !self.runner_args.is_empty() && self.runner.is_none() {
            return Err(ToolchainConfigError::new(
                "toolchain.runner-args",
                "is set but toolchain.runner is not; name the program the arguments belong to",
            ));
        }
        if let Some(prefix) = &self.ada.prefix {
            // A tool prefix (a triple), or a gprconfig compiler name such as
            // `GNAT`, which the generated project names as its Toolchain_Name.
            if !is_compiler_name(prefix) {
                check_triple("toolchain.ada.prefix", prefix.trim_end_matches('-'))?;
            }
        }
        if let Some(target) = &self.ada.target {
            check_triple("toolchain.ada.target", target)?;
        }
        if let Some(runtime) = &self.ada.runtime {
            check_gpr_value("toolchain.ada.runtime", runtime)?;
        }
        for switch in &self.ada.switches {
            check_gpr_value("toolchain.ada.switches", switch)?;
            if !switch.starts_with('-') {
                return Err(ToolchainConfigError::new(
                    "toolchain.ada.switches",
                    format!("{switch:?} is not a compiler switch (switches start with '-')"),
                ));
            }
        }
        if let Some(backend) = &self.ada.probe_backend {
            check_word("toolchain.ada.probe-backend", backend)?;
        }
        Ok(())
    }
}

fn resolve_dir(dir: &mut PathBuf, base: &Path) {
    if dir.is_relative() {
        *dir = base.join(&*dir);
    }
}

fn resolve_program(program: &mut String, base: &Path) {
    let path = Path::new(program.as_str());
    let names_a_path = program.contains('/') || program.contains('\\');
    if names_a_path && path.is_relative() {
        *program = base.join(path).to_string_lossy().into_owned();
    }
}

fn check_word(key: &str, value: &str) -> Result<(), ToolchainConfigError> {
    if value.is_empty() {
        return Err(ToolchainConfigError::new(key, "holds an empty string"));
    }
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        return Err(ToolchainConfigError::new(
            key,
            format!("{value:?} contains the control character {c:?}"),
        ));
    }
    Ok(())
}

fn check_program(key: &str, value: &str) -> Result<(), ToolchainConfigError> {
    check_word(key, value)?;
    if value.trim() != value {
        return Err(ToolchainConfigError::new(
            key,
            format!("{value:?} has leading or trailing whitespace"),
        ));
    }
    if value.starts_with('-') {
        return Err(ToolchainConfigError::new(
            key,
            format!("{value:?} looks like a flag, not a program"),
        ));
    }
    if let Some(c) = value
        .chars()
        .find(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '<' | '>' | '"' | '#'))
    {
        return Err(ToolchainConfigError::new(
            key,
            format!("{value:?} contains {c:?}; name a single program, without shell syntax"),
        ));
    }
    Ok(())
}

fn check_dir(key: &str, value: &Path) -> Result<(), ToolchainConfigError> {
    let text = value.to_string_lossy();
    check_word(key, &text)
}

fn check_define(value: &str) -> Result<(), ToolchainConfigError> {
    const KEY: &str = "toolchain.defines";
    check_word(KEY, value)?;
    let name = value.split_once('=').map_or(value, |(name, _)| name);
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(ToolchainConfigError::new(
            KEY,
            format!("{value:?} is not NAME or NAME=VALUE (write the define without -D)"),
        ))
    }
}

/// A gprconfig compiler name: an identifier (`GNAT`, `GNAT_LLVM`).
fn is_compiler_name(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn check_triple(key: &str, value: &str) -> Result<(), ToolchainConfigError> {
    let shaped = !value.is_empty()
        && value.contains('-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if shaped {
        Ok(())
    } else {
        Err(ToolchainConfigError::new(
            key,
            format!("{value:?} is not a target triple such as aarch64-linux-gnu"),
        ))
    }
}

fn check_gpr_value(key: &str, value: &str) -> Result<(), ToolchainConfigError> {
    check_word(key, value)?;
    if value.contains('"') {
        return Err(ToolchainConfigError::new(
            key,
            format!("{value:?} contains a double quote, which would end its GPR string"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[toolchain]
cc = "aarch64-linux-gnu-gcc"
cxx = "tools/bin/aarch64-linux-gnu-g++"
cflags = ["-O1", "-mcpu=cortex-a53"]
cxxflags = ["-fno-exceptions"]
ldflags = ["-static"]
defines = ["BOARD=3", "WITH_LOG"]
include-dirs = ["vendor/include", "/opt/sdk/include"]
target = "aarch64-linux-gnu"
sysroot = "sysroot"
runner = "qemu-aarch64"
runner-args = ["-L", "/usr/aarch64-linux-gnu"]

[toolchain.ada]
prefix = "aarch64-linux-gnu"
gprbuild = "/opt/gnat/bin/gprbuild"
runtime = "light"
switches = ["-O1", "-gnatwa"]
probe-backend = "memory_buffer"
"#;

    #[test]
    fn reads_every_key_from_a_config_file() {
        let config = ToolchainConfig::from_config_file_text(FULL)
            .unwrap()
            .expect("the file has a [toolchain] table");
        assert_eq!(config.cc.as_deref(), Some("aarch64-linux-gnu-gcc"));
        assert_eq!(config.cflags, ["-O1", "-mcpu=cortex-a53"]);
        assert_eq!(config.defines, ["BOARD=3", "WITH_LOG"]);
        assert_eq!(config.target.as_deref(), Some("aarch64-linux-gnu"));
        assert_eq!(config.runner_args, ["-L", "/usr/aarch64-linux-gnu"]);
        assert_eq!(config.ada.runtime.as_deref(), Some("light"));
        assert_eq!(config.ada.switches, ["-O1", "-gnatwa"]);
        assert_eq!(config.ada.probe_backend.as_deref(), Some("memory_buffer"));
        assert_eq!(config.ada_target(), Some("aarch64-linux-gnu"));
        config.validate().unwrap();
    }

    #[test]
    fn a_file_without_the_table_has_no_toolchain_and_other_keys_are_left_alone() {
        assert_eq!(
            ToolchainConfig::from_config_file_text("jobs = 2\n").unwrap(),
            None
        );
    }

    #[test]
    fn unknown_keys_are_rejected_with_their_name() {
        let error = ToolchainConfig::from_config_file_text("[toolchain]\ncompiler = \"gcc\"\n")
            .unwrap_err();
        assert!(error.contains("compiler"), "{error}");
        let error = ToolchainConfig::from_config_file_text("[toolchain.ada]\nrts = \"light\"\n")
            .unwrap_err();
        assert!(error.contains("rts"), "{error}");
    }

    #[test]
    fn relative_paths_resolve_against_the_config_directory() {
        let mut config = ToolchainConfig::from_config_file_text(FULL)
            .unwrap()
            .unwrap();
        config.resolve_relative_to(Path::new("/projects/widget"));
        assert_eq!(
            config.include_dirs,
            [
                PathBuf::from("/projects/widget/vendor/include"),
                PathBuf::from("/opt/sdk/include"),
            ]
        );
        assert_eq!(
            config.sysroot.as_deref(),
            Some(Path::new("/projects/widget/sysroot"))
        );
        // A bare program name stays a PATH lookup; a relative path resolves.
        assert_eq!(config.cc.as_deref(), Some("aarch64-linux-gnu-gcc"));
        assert_eq!(
            config.cxx.as_deref(),
            Some("/projects/widget/tools/bin/aarch64-linux-gnu-g++")
        );
        assert_eq!(config.runner.as_deref(), Some("qemu-aarch64"));
        assert_eq!(
            config.ada.gprbuild.as_deref(),
            Some("/opt/gnat/bin/gprbuild")
        );
    }

    #[test]
    fn command_line_values_replace_config_values_key_by_key() {
        let file = ToolchainConfig {
            cc: Some("gcc".to_owned()),
            cflags: vec!["-O1".to_owned()],
            defines: vec!["A=1".to_owned()],
            ..ToolchainConfig::default()
        };
        let cli = ToolchainConfig {
            cc: Some("clang".to_owned()),
            defines: vec!["B=2".to_owned()],
            ..ToolchainConfig::default()
        };
        let merged = file.overlaid_with(cli);
        assert_eq!(merged.cc.as_deref(), Some("clang"));
        assert_eq!(merged.cflags, ["-O1"], "an unset list keeps the config's");
        assert_eq!(
            merged.defines,
            ["B=2"],
            "a given list replaces the config's"
        );
    }

    #[test]
    fn validation_names_the_key_and_the_problem() {
        let check = |config: ToolchainConfig| config.validate().unwrap_err();

        let error = check(ToolchainConfig {
            runner_args: vec!["-L".to_owned()],
            ..ToolchainConfig::default()
        });
        assert_eq!(error.key(), "toolchain.runner-args");

        let error = check(ToolchainConfig {
            defines: vec!["-DX=1".to_owned()],
            ..ToolchainConfig::default()
        });
        assert_eq!(error.key(), "toolchain.defines");
        assert!(error.to_string().contains("without -D"), "{error}");

        let error = check(ToolchainConfig {
            target: Some("aarch64".to_owned()),
            ..ToolchainConfig::default()
        });
        assert_eq!(error.key(), "toolchain.target");

        let error = check(ToolchainConfig {
            cc: Some("gcc; id".to_owned()),
            ..ToolchainConfig::default()
        });
        assert_eq!(error.key(), "toolchain.cc");

        let error = check(ToolchainConfig {
            cflags: vec![String::new()],
            ..ToolchainConfig::default()
        });
        assert_eq!(error.key(), "toolchain.cflags");

        let mut ada = ToolchainConfig::default();
        ada.ada.runtime = Some("light\"; for X use \"y".to_owned());
        assert_eq!(check(ada).key(), "toolchain.ada.runtime");

        let mut ada = ToolchainConfig::default();
        ada.ada.switches = vec!["O1".to_owned()];
        assert_eq!(check(ada).key(), "toolchain.ada.switches");
    }

    #[test]
    fn a_trailing_dash_on_the_ada_prefix_is_accepted() {
        let mut config = ToolchainConfig::default();
        config.ada.prefix = Some("aarch64-linux-gnu-".to_owned());
        config.validate().unwrap();
        // A gprconfig compiler name is accepted too; a malformed value is not.
        config.ada.prefix = Some("GNAT_LLVM".to_owned());
        config.validate().unwrap();
        config.ada.prefix = Some("aarch64 linux".to_owned());
        assert_eq!(config.validate().unwrap_err().key(), "toolchain.ada.prefix");
    }

    #[test]
    fn cross_tables_are_read_by_guard_resolved_and_validated() {
        let text = r#"
jobs = 2
[cross.aarch64]
cc = "tools/aarch64-linux-gnu-gcc"
sysroot = "sysroots/arm64"
runner = "qemu-aarch64"
runner-args = ["-L", "/opt/arm64"]

[cross.armhf]
target = "arm-linux-gnueabihf"
"#;
        let mut cross = cross_config_from_file_text(text).unwrap();
        assert_eq!(cross.len(), 2);
        let aarch64 = cross.get_mut("aarch64").unwrap();
        aarch64.resolve_relative_to(Path::new("/projects/widget"));
        assert_eq!(
            aarch64.cc.as_deref(),
            Some("/projects/widget/tools/aarch64-linux-gnu-gcc")
        );
        assert_eq!(
            aarch64.sysroot.as_deref(),
            Some(Path::new("/projects/widget/sysroots/arm64"))
        );
        assert_eq!(
            aarch64.runner.as_deref(),
            Some("qemu-aarch64"),
            "a bare name stays a PATH lookup"
        );
        aarch64.validate("aarch64").unwrap();
        assert_eq!(
            cross["armhf"].target.as_deref(),
            Some("arm-linux-gnueabihf")
        );
        assert!(cross_config_from_file_text("jobs = 2\n")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cross_table_errors_name_the_guard_and_key() {
        let error =
            cross_config_from_file_text("[cross.aarch64]\ncompiler = \"gcc\"\n").unwrap_err();
        assert!(
            error.contains("compiler") && error.contains("[cross]"),
            "{error}"
        );
        let bad = CrossGuardConfig {
            runner: Some("qemu-aarch64; id".to_owned()),
            ..CrossGuardConfig::default()
        };
        assert_eq!(
            bad.validate("aarch64").unwrap_err().key(),
            "cross.aarch64.runner"
        );
        let bad = CrossGuardConfig {
            target: Some("arm64".to_owned()),
            ..CrossGuardConfig::default()
        };
        assert_eq!(
            bad.validate("aarch64").unwrap_err().key(),
            "cross.aarch64.target"
        );
        let bad = CrossGuardConfig {
            runner_args: vec![String::new()],
            ..CrossGuardConfig::default()
        };
        assert_eq!(
            bad.validate("ppc").unwrap_err().key(),
            "cross.ppc.runner-args"
        );
        assert!(CrossGuardConfig::default().is_empty());
    }

    #[test]
    fn an_empty_table_is_empty_and_carries_no_c_family_settings() {
        let config = ToolchainConfig::from_config_file_text("[toolchain]\n")
            .unwrap()
            .unwrap();
        assert!(config.is_empty());
        assert!(!config.has_c_family_settings());
        let ada_only = ToolchainConfig::from_config_file_text("[toolchain.ada]\nruntime = \"x\"\n")
            .unwrap()
            .unwrap();
        assert!(!ada_only.is_empty());
        assert!(!ada_only.has_c_family_settings());
    }
}
