// SPDX-License-Identifier: Apache-2.0

//! Visual Studio and Windows SDK environment discovery.
//!
//! clang (for the MSVC target) and cl need the MSVC headers, CRT and linker
//! and the Windows SDK; a Developer PowerShell provides them through
//! `INCLUDE`, `LIB`, `LIBPATH` and `PATH`. When bhf starts without those, it
//! finds the newest Visual Studio (or Build Tools) instance with the C++
//! toolset through `vswhere`, runs its `VsDevCmd.bat` once, captures the
//! environment it sets, caches it per instance, version and architecture, and
//! applies it to its own process before any build starts. Every `make`,
//! harness and reproducer bhf starts inherits it.
//!
//! The same step makes the default clang lane work without a separate LLVM
//! install: a clang already on PATH is kept; otherwise the standalone LLVM
//! (`%ProgramFiles%\LLVM\bin`), then Visual Studio's bundled clang
//! (`VC\Tools\Llvm\x64\bin`, the "C++ Clang tools" component) is used. GNU
//! make is looked up in its usual Windows install locations. `--no-vs-env`
//! (or `BHF_NO_VS_ENV=1`) turns all of it off.
//!
//! Discovered directories reach builds only through `PATH`/`INCLUDE`/`LIB`;
//! none is ever written into a recipe, so their spaces (`Program Files
//! (x86)`) need no quoting.

// The discovery itself runs only on Windows; its parsing and merging are
// plain functions, tested on every host.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// One Visual Studio instance, from `vswhere -format json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VsInstance {
    pub instance_id: String,
    pub installation_path: PathBuf,
    pub installation_version: String,
    pub display_name: String,
}

/// What discovery did, for the run report and `--dry-run`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct BuildEnvironment {
    /// The Visual Studio instance whose environment was applied, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visual_studio: Option<VsInstance>,
    /// `x64`, `x86`, `arm64`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// `developer_shell` (INCLUDE/LIB were already set), `captured`,
    /// `cached`, `disabled`, or `not_found`.
    pub source: String,
    /// The clang the default lane resolves to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clang: Option<PathBuf>,
    /// cl.exe, when the environment provides it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cl: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub make: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msbuild: Option<PathBuf>,
    /// Why discovery found nothing to apply, when it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

impl BuildEnvironment {
    /// One line for the console and `--dry-run`.
    pub(crate) fn summary(&self) -> String {
        let mut parts = Vec::new();
        match (&self.visual_studio, self.source.as_str()) {
            (Some(vs), source) => parts.push(format!(
                "{} {} ({}, {})",
                vs.display_name,
                vs.installation_version,
                self.arch.as_deref().unwrap_or("x64"),
                source.replace('_', " ")
            )),
            (None, "developer_shell") => parts.push("Developer shell environment".to_owned()),
            (None, _) => parts.push(format!(
                "no Visual Studio environment ({})",
                self.problem.as_deref().unwrap_or(&self.source)
            )),
        }
        for (label, tool) in [
            ("clang", &self.clang),
            ("cl", &self.cl),
            ("make", &self.make),
            ("msbuild", &self.msbuild),
        ] {
            if let Some(tool) = tool {
                parts.push(format!("{label} {}", tool.display()));
            }
        }
        parts.join("; ")
    }
}

static ACTIVATED: OnceLock<BuildEnvironment> = OnceLock::new();

/// What [`activate`] did in this process, if it ran.
pub(crate) fn activated() -> Option<&'static BuildEnvironment> {
    ACTIVATED.get()
}

/// Parse `vswhere -format json` output, newest first as vswhere lists it.
pub(crate) fn parse_vswhere(json: &str) -> Vec<VsInstance> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json.trim_start_matches('\u{feff}'))
    else {
        return Vec::new();
    };
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|instance| {
            Some(VsInstance {
                instance_id: instance.get("instanceId")?.as_str()?.to_owned(),
                installation_path: PathBuf::from(instance.get("installationPath")?.as_str()?),
                installation_version: instance
                    .get("installationVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                display_name: instance
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Visual Studio")
                    .to_owned(),
            })
        })
        .collect()
}

/// Parse the output of `set` (`NAME=value` per line).
pub(crate) fn parse_set_output(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            let (name, value) = line.split_once('=')?;
            // `set` prints `=C:=C:\dir` style entries for per-drive cwd.
            (!name.is_empty() && !name.starts_with('='))
                .then(|| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Variables a captured Developer environment adds or changes, other than
/// PATH (which [`merged_path`] combines). Names compare case-insensitively,
/// as Windows environment names do; prompt cosmetics are left out.
pub(crate) fn environment_changes(
    original: &[(String, String)],
    captured: &[(String, String)],
) -> Vec<(String, String)> {
    let before: BTreeMap<String, &str> = original
        .iter()
        .map(|(name, value)| (name.to_ascii_uppercase(), value.as_str()))
        .collect();
    captured
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.to_ascii_uppercase().as_str(),
                "PATH" | "PROMPT" | "__VSCMD_PREINIT_PATH"
            )
        })
        .filter(|(name, value)| before.get(&name.to_ascii_uppercase()) != Some(&value.as_str()))
        .cloned()
        .collect()
}

/// A Windows `PATH` value's directories (`;`-separated, quotes dropped), on
/// every host.
fn windows_path_list(value: &str) -> Vec<PathBuf> {
    value
        .split(';')
        .map(|dir| dir.trim().trim_matches('"'))
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// What one VsDevCmd run changed, which is all bhf caches and reapplies: the
/// variables it set or changed and the `PATH` directories it added. Everything
/// else in the environment it ran in (the operator's own variables, their
/// values at that time, any credentials) is neither written to disk nor
/// brought back on a later run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EnvironmentDelta {
    /// Variables VsDevCmd set or changed, `PATH` aside.
    pub vars: Vec<(String, String)>,
    /// The `PATH` directories VsDevCmd added, in its order.
    pub path_added: Vec<PathBuf>,
}

impl EnvironmentDelta {
    /// The change from `before` (the environment VsDevCmd started in) to
    /// `after` (the one it left).
    pub(crate) fn between(before: &[(String, String)], after: &[(String, String)]) -> Self {
        let path_of = |vars: &[(String, String)]| {
            vars.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
                .map(|(_, value)| windows_path_list(value))
                .unwrap_or_default()
        };
        let before_path = path_of(before);
        let path_added = path_of(after)
            .into_iter()
            .filter(|dir| !before_path.iter().any(|known| same_dir(known, dir)))
            .collect();
        EnvironmentDelta {
            vars: environment_changes(before, after),
            path_added,
        }
    }

    /// The variables to set, and the `PATH`, for a process whose `PATH` is
    /// `current_path` now.
    pub(crate) fn applied_to(
        &self,
        current_path: &[PathBuf],
    ) -> (Vec<(String, String)>, Vec<PathBuf>) {
        (
            self.vars.clone(),
            merged_path(current_path, &self.path_added),
        )
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        p.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// Whether `dir` is Visual Studio's bundled LLVM (`VC\Tools\Llvm\...\bin`).
fn is_bundled_llvm(dir: &Path) -> bool {
    let text = dir
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    text.contains("\\vc\\tools\\llvm\\")
}

/// The PATH after applying a captured Developer environment: the directories
/// it added go first (cl, link, the SDK tools, MSBuild), as VsDevCmd orders
/// them — except Visual Studio's bundled clang, which goes after the
/// operator's own PATH, so a clang the operator installed keeps winning.
pub(crate) fn merged_path(original: &[PathBuf], captured: &[PathBuf]) -> Vec<PathBuf> {
    let added: Vec<&PathBuf> = captured
        .iter()
        .filter(|dir| !original.iter().any(|known| same_dir(known, dir)))
        .collect();
    let mut out: Vec<PathBuf> = Vec::new();
    let push = |dir: &PathBuf, out: &mut Vec<PathBuf>| {
        if !out.iter().any(|known| same_dir(known, dir)) {
            out.push(dir.clone());
        }
    };
    for dir in added.iter().filter(|dir| !is_bundled_llvm(dir)) {
        push(dir, &mut out);
    }
    for dir in original {
        push(dir, &mut out);
    }
    for dir in added.iter().filter(|dir| is_bundled_llvm(dir)) {
        push(dir, &mut out);
    }
    out
}

/// Where the default lane's clang comes from when none is on PATH: the
/// standalone LLVM, then Visual Studio's bundled one.
pub(crate) fn clang_fallback_dirs(
    program_files: Option<&Path>,
    vs: Option<&Path>,
    arch: &str,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(program_files) = program_files {
        dirs.push(program_files.join("LLVM").join("bin"));
    }
    if let Some(vs) = vs {
        let llvm = vs.join("VC").join("Tools").join("Llvm");
        if arch.eq_ignore_ascii_case("arm64") {
            dirs.push(llvm.join("ARM64").join("bin"));
        }
        dirs.push(llvm.join("x64").join("bin"));
        dirs.push(llvm.join("bin"));
    }
    dirs
}

/// GNU make's usual Windows install locations.
pub(crate) fn make_fallback_dirs(env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("C:\\w64devkit\\bin")];
    if let Some(profile) = env("USERPROFILE") {
        dirs.push(PathBuf::from(profile).join("w64devkit").join("bin"));
    }
    if let Some(data) = env("ProgramData") {
        dirs.push(PathBuf::from(data).join("chocolatey").join("bin"));
    }
    if let Some(x86) = env("ProgramFiles(x86)") {
        dirs.push(PathBuf::from(x86).join("GnuWin32").join("bin"));
    }
    dirs.push(PathBuf::from("C:\\msys64\\usr\\bin"));
    dirs
}

/// The cache file of one instance's captured environment.
pub(crate) fn cache_path(base: &Path, instance: &VsInstance, arch: &str) -> PathBuf {
    let safe = |text: &str| -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    base.join("bhf").join("vs-env").join(format!(
        "{}-{}-{}.json",
        safe(&instance.instance_id),
        safe(&instance.installation_version),
        safe(arch)
    ))
}

/// The cache file's layout; a file of another one is captured again.
const CACHE_FORMAT: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
struct CachedEnvironment {
    #[serde(default)]
    format: u32,
    instance_id: String,
    installation_version: String,
    arch: String,
    /// `VCToolsInstallDir` at capture time; the cache is stale once it is gone.
    toolset_dir: PathBuf,
    delta: EnvironmentDelta,
}

/// Options for [`activate`]: `--no-vs-env` and `--vs-arch`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ActivationOptions {
    pub disabled: bool,
    pub arch: Option<String>,
}

/// Apply the Visual Studio/SDK environment to this process (Windows only;
/// elsewhere a no-op). Runs once; later calls return the first result.
pub(crate) fn activate(options: &ActivationOptions) -> &'static BuildEnvironment {
    ACTIVATED.get_or_init(|| activate_once(options))
}

#[cfg(not(windows))]
fn activate_once(_options: &ActivationOptions) -> BuildEnvironment {
    BuildEnvironment {
        source: "not_windows".to_owned(),
        ..BuildEnvironment::default()
    }
}

#[cfg(windows)]
fn activate_once(options: &ActivationOptions) -> BuildEnvironment {
    let arch = options.arch.clone().unwrap_or_else(|| {
        if cfg!(target_arch = "aarch64") {
            "arm64".to_owned()
        } else {
            "x64".to_owned()
        }
    });
    let mut environment = BuildEnvironment {
        arch: Some(arch.clone()),
        ..BuildEnvironment::default()
    };
    let disabled = options.disabled
        || std::env::var("BHF_NO_VS_ENV")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let developer_shell =
        std::env::var_os("INCLUDE").is_some() && std::env::var_os("LIB").is_some();
    if disabled {
        environment.source = "disabled".to_owned();
    } else if developer_shell {
        environment.source = "developer_shell".to_owned();
    } else {
        match capture_or_load(&arch) {
            Ok((instance, delta, source)) => {
                apply(&delta);
                environment.visual_studio = Some(instance);
                environment.source = source.to_owned();
            }
            Err(problem) => {
                environment.source = "not_found".to_owned();
                environment.problem = Some(problem);
            }
        }
    }
    if !disabled {
        // The default clang lane: keep a clang on PATH, else the standalone
        // LLVM, else Visual Studio's bundled clang.
        if which::which("clang").is_err() {
            let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from);
            let vs = environment
                .visual_studio
                .as_ref()
                .map(|vs| vs.installation_path.clone())
                .or_else(|| std::env::var_os("VSINSTALLDIR").map(PathBuf::from));
            if let Some(dir) = clang_fallback_dirs(program_files.as_deref(), vs.as_deref(), &arch)
                .into_iter()
                .find(|dir| dir.join("clang.exe").is_file())
            {
                append_path(&dir);
            }
        }
        if which::which("make").is_err() {
            let env = |name: &str| std::env::var(name).ok();
            if let Some(dir) = make_fallback_dirs(&env)
                .into_iter()
                .find(|dir| dir.join("make.exe").is_file())
            {
                append_path(&dir);
            }
        }
    }
    environment.clang = which::which("clang").ok();
    environment.cl = which::which("cl").ok();
    environment.make = which::which("make").ok();
    environment.msbuild = which::which("MSBuild").ok();
    environment
}

#[cfg(windows)]
fn append_path(dir: &Path) {
    let mut paths: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    paths.push(dir.to_path_buf());
    if let Ok(joined) = std::env::join_paths(paths) {
        std::env::set_var("PATH", joined);
    }
}

/// Apply what VsDevCmd changed to this process, onto its current PATH.
#[cfg(windows)]
fn apply(delta: &EnvironmentDelta) {
    let current_path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    let (vars, path) = delta.applied_to(&current_path);
    for (name, value) in vars {
        std::env::set_var(name, value);
    }
    if let Ok(joined) = std::env::join_paths(path) {
        std::env::set_var("PATH", joined);
    }
}

#[cfg(windows)]
fn vswhere() -> Option<PathBuf> {
    let x86 = std::env::var_os("ProgramFiles(x86)").map(PathBuf::from)?;
    let path = x86
        .join("Microsoft Visual Studio")
        .join("Installer")
        .join("vswhere.exe");
    path.is_file().then_some(path)
}

/// An instance, what its VsDevCmd changes, and where that came from
/// (`cached` or `captured`).
#[cfg(windows)]
type LoadedEnvironment = (VsInstance, EnvironmentDelta, &'static str);

/// The cached environment of the newest instance, or a fresh capture.
#[cfg(windows)]
fn capture_or_load(arch: &str) -> Result<LoadedEnvironment, String> {
    let vswhere = vswhere().ok_or_else(|| {
        "vswhere.exe not found: install Visual Studio 2022 Build Tools with the \
         \"Desktop development with C++\" workload"
            .to_owned()
    })?;
    let output = std::process::Command::new(&vswhere)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-format",
            "json",
            "-utf8",
        ])
        .output()
        .map_err(|error| format!("could not run {}: {error}", vswhere.display()))?;
    let instance = parse_vswhere(&String::from_utf8_lossy(&output.stdout))
        .into_iter()
        .next()
        .ok_or_else(|| {
            "no Visual Studio instance with the C++ toolset (component \
             Microsoft.VisualStudio.Component.VC.Tools.x86.x64) is installed"
                .to_owned()
        })?;
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let cache = cache_path(&base, &instance, arch);
    if let Some(delta) = load_cache(&cache, &instance, arch) {
        return Ok((instance, delta, "cached"));
    }
    let dev_cmd = instance
        .installation_path
        .join("Common7")
        .join("Tools")
        .join("VsDevCmd.bat");
    if !dev_cmd.is_file() {
        return Err(format!("{} is missing", dev_cmd.display()));
    }
    let host = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    // VsDevCmd runs in a copy of this process's environment, so the change is
    // measured against it, and only the change is kept.
    let before: Vec<(String, String)> = std::env::vars().collect();
    let captured = capture(&dev_cmd, arch, host)?;
    let delta = EnvironmentDelta::between(&before, &captured);
    let toolset_dir = captured
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("VCToolsInstallDir"))
        .map(|(_, value)| PathBuf::from(value))
        .unwrap_or_default();
    if let Ok(bytes) = serde_json::to_vec_pretty(&CachedEnvironment {
        format: CACHE_FORMAT,
        instance_id: instance.instance_id.clone(),
        installation_version: instance.installation_version.clone(),
        arch: arch.to_owned(),
        toolset_dir,
        delta: delta.clone(),
    }) {
        if let Some(parent) = cache.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&cache, bytes);
    }
    Ok((instance, delta, "captured"))
}

/// A cached capture, if it is in this format, for this instance, and its
/// toolset still exists.
fn load_cache(path: &Path, instance: &VsInstance, arch: &str) -> Option<EnvironmentDelta> {
    let cached: CachedEnvironment = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    if cached.format != CACHE_FORMAT
        || cached.instance_id != instance.instance_id
        || cached.installation_version != instance.installation_version
        || cached.arch != arch
    {
        return None;
    }
    (!cached.toolset_dir.as_os_str().is_empty() && cached.toolset_dir.is_dir())
        .then_some(cached.delta)
}

/// Run VsDevCmd and capture the environment it leaves.
#[cfg(windows)]
fn capture(dev_cmd: &Path, arch: &str, host: &str) -> Result<Vec<(String, String)>, String> {
    use std::os::windows::process::CommandExt;
    let mut command = std::process::Command::new("cmd.exe");
    command.raw_arg(format!(
        "/d /s /c \"\"{}\" -arch={arch} -host_arch={host} -no_logo >nul && set\"",
        dev_cmd.display()
    ));
    let output = crate::command_output::output_with_timeout(
        &mut command,
        std::time::Duration::from_secs(120),
    )
    .map_err(|error| format!("could not run {}: {error}", dev_cmd.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} -arch={arch} failed: {}",
            dev_cmd.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let vars = parse_set_output(&String::from_utf8_lossy(&output.stdout));
    if !vars
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("INCLUDE"))
    {
        return Err(format!("{} set no INCLUDE", dev_cmd.display()));
    }
    Ok(vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_vswhere_json_lists_instances() {
        let json = r#"[{
            "instanceId": "3fb6dd60",
            "installationPath": "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools",
            "installationVersion": "17.14.37906.3",
            "displayName": "Visual Studio Build Tools 2022",
            "catalog": {"productLineVersion": "2022"}
        }]"#;
        let instances = parse_vswhere(json);
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, "3fb6dd60");
        assert_eq!(
            instances[0].installation_path,
            PathBuf::from("C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools")
        );
        assert_eq!(instances[0].installation_version, "17.14.37906.3");
        assert!(parse_vswhere("").is_empty());
        assert!(parse_vswhere("[]").is_empty());
    }

    #[test]
    fn windows_developer_environment_capture_keeps_what_vsdevcmd_changed() {
        let set = "ALLUSERSPROFILE=C:\\ProgramData\r\n=C:=C:\\src\r\nINCLUDE=C:\\VS\\include;C:\\Kits\\ucrt\r\n\
                   LIB=C:\\VS\\lib\\x64\r\nPath=C:\\VS\\bin\\HostX64\\x64;C:\\Windows\r\nPROMPT=$P$G\r\n\
                   VCToolsInstallDir=C:\\VS\\Tools\\MSVC\\14.44\\\r\n";
        let captured = parse_set_output(set);
        assert!(captured.iter().all(|(name, _)| !name.starts_with('=')));
        let original = vec![
            ("ALLUSERSPROFILE".to_owned(), "C:\\ProgramData".to_owned()),
            ("PATH".to_owned(), "C:\\Windows".to_owned()),
        ];
        let changes: BTreeMap<String, String> = environment_changes(&original, &captured)
            .into_iter()
            .collect();
        assert_eq!(
            changes.keys().cloned().collect::<Vec<_>>(),
            vec!["INCLUDE", "LIB", "VCToolsInstallDir"],
            "unchanged and cosmetic variables are left alone; PATH is merged separately"
        );
    }

    #[test]
    fn windows_cached_environment_is_only_what_vsdevcmd_changed() {
        let capture_time = vec![
            ("CC".to_owned(), "clang".to_owned()),
            ("ASAN_OPTIONS".to_owned(), "a".to_owned()),
            ("API_TOKEN".to_owned(), "secret".to_owned()),
            ("Path".to_owned(), "C:\\old\\clang;C:\\Windows".to_owned()),
        ];
        let mut captured = capture_time.clone();
        captured.retain(|(name, _)| name != "Path");
        captured.extend([
            ("INCLUDE".to_owned(), "C:\\VS\\include".to_owned()),
            ("LIB".to_owned(), "C:\\VS\\lib".to_owned()),
            (
                "VCToolsInstallDir".to_owned(),
                "C:\\VS\\Tools\\MSVC\\14.44\\".to_owned(),
            ),
            (
                "Path".to_owned(),
                "C:\\VS\\bin;C:\\old\\clang;C:\\Windows".to_owned(),
            ),
        ]);
        let delta = EnvironmentDelta::between(&capture_time, &captured);
        let names: Vec<&str> = delta.vars.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["INCLUDE", "LIB", "VCToolsInstallDir"]);
        assert_eq!(delta.path_added, vec![PathBuf::from("C:\\VS\\bin")]);
        let cached = serde_json::to_string(&delta).unwrap();
        assert!(
            !cached.contains("secret") && !cached.contains("ASAN_OPTIONS"),
            "nothing VsDevCmd did not set is written to disk: {cached}"
        );

        // A later run in a different environment keeps its own values and
        // PATH, plus what VsDevCmd adds.
        let now_path = vec![
            PathBuf::from("C:\\new\\clang"),
            PathBuf::from("C:\\Windows"),
        ];
        let (set, path) = delta.applied_to(&now_path);
        let set_names: Vec<&str> = set.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(set_names, vec!["INCLUDE", "LIB", "VCToolsInstallDir"]);
        assert_eq!(
            path,
            vec![
                PathBuf::from("C:\\VS\\bin"),
                PathBuf::from("C:\\new\\clang"),
                PathBuf::from("C:\\Windows"),
            ],
            "the capture-time PATH does not come back"
        );
    }

    #[test]
    fn windows_path_merge_puts_the_toolset_first_and_bundled_clang_last() {
        let original = vec![
            PathBuf::from("C:\\Program Files\\LLVM\\bin"),
            PathBuf::from("C:\\Windows\\system32"),
        ];
        let captured = vec![
            PathBuf::from("C:\\VS\\VC\\Tools\\MSVC\\14.44\\bin\\HostX64\\x64"),
            PathBuf::from("C:\\VS\\VC\\Tools\\Llvm\\x64\\bin"),
            PathBuf::from("C:\\Kits\\10\\bin\\x64"),
            PathBuf::from("c:\\windows\\System32\\"),
        ];
        assert_eq!(
            merged_path(&original, &captured),
            vec![
                PathBuf::from("C:\\VS\\VC\\Tools\\MSVC\\14.44\\bin\\HostX64\\x64"),
                PathBuf::from("C:\\Kits\\10\\bin\\x64"),
                PathBuf::from("C:\\Program Files\\LLVM\\bin"),
                PathBuf::from("C:\\Windows\\system32"),
                PathBuf::from("C:\\VS\\VC\\Tools\\Llvm\\x64\\bin"),
            ],
            "the operator's clang stays ahead of the bundled one; nothing is listed twice"
        );
    }

    #[test]
    fn windows_tool_fallbacks_prefer_standalone_llvm_then_the_bundled_clang() {
        let dirs = clang_fallback_dirs(
            Some(Path::new("C:\\Program Files")),
            Some(Path::new("C:\\VS")),
            "x64",
        );
        assert_eq!(
            dirs[0],
            Path::new("C:\\Program Files").join("LLVM").join("bin")
        );
        assert_eq!(
            dirs[1],
            Path::new("C:\\VS")
                .join("VC")
                .join("Tools")
                .join("Llvm")
                .join("x64")
                .join("bin")
        );
        let env = |name: &str| (name == "USERPROFILE").then(|| "C:\\Users\\Some One".to_owned());
        let make = make_fallback_dirs(&env);
        assert_eq!(make[0], PathBuf::from("C:\\w64devkit\\bin"));
        assert!(make.contains(
            &PathBuf::from("C:\\Users\\Some One")
                .join("w64devkit")
                .join("bin")
        ));
    }

    #[test]
    fn windows_environment_cache_is_keyed_by_instance_version_and_arch() {
        let temp = tempfile::tempdir().unwrap();
        let instance = VsInstance {
            instance_id: "3fb6dd60".to_owned(),
            installation_path: PathBuf::from("C:/VS"),
            installation_version: "17.14.37906.3".to_owned(),
            display_name: "Visual Studio Build Tools 2022".to_owned(),
        };
        let path = cache_path(temp.path(), &instance, "x64");
        assert!(path.ends_with("bhf/vs-env/3fb6dd60-17.14.37906.3-x64.json"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let tools = temp.path().join("MSVC");
        std::fs::create_dir_all(&tools).unwrap();
        let cached = CachedEnvironment {
            format: CACHE_FORMAT,
            instance_id: instance.instance_id.clone(),
            installation_version: instance.installation_version.clone(),
            arch: "x64".to_owned(),
            toolset_dir: tools.clone(),
            delta: EnvironmentDelta {
                vars: vec![("INCLUDE".to_owned(), "C:/VS/include".to_owned())],
                path_added: vec![PathBuf::from("C:/VS/bin")],
            },
        };
        std::fs::write(&path, serde_json::to_vec(&cached).unwrap()).unwrap();
        assert_eq!(
            load_cache(&path, &instance, "x64"),
            Some(cached.delta.clone())
        );
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "instance_id": instance.instance_id,
                "installation_version": instance.installation_version,
                "arch": "x64",
                "vars": [["VCToolsInstallDir", tools]]
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            load_cache(&path, &instance, "x64").is_none(),
            "a cache of the full environment (the first layout) is captured again"
        );
        std::fs::write(&path, serde_json::to_vec(&cached).unwrap()).unwrap();
        assert!(
            load_cache(&path, &instance, "arm64").is_none(),
            "another arch"
        );
        let newer = VsInstance {
            installation_version: "17.15.0".to_owned(),
            ..instance.clone()
        };
        assert!(
            load_cache(&path, &newer, "x64").is_none(),
            "an updated instance recaptures"
        );
        std::fs::remove_dir_all(&tools).unwrap();
        assert!(
            load_cache(&path, &instance, "x64").is_none(),
            "a removed toolset recaptures"
        );
    }
}
