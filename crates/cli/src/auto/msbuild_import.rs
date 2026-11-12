// SPDX-License-Identifier: Apache-2.0

//! Read a Visual Studio solution's compile wiring without building it.
//!
//! Two tiers produce the same per-source compile settings:
//!
//! * **Static** (default, every host): parse the `.sln`/`.slnx` and each
//!   `.vcxproj`, follow the project's local `<Import>`s and property sheets,
//!   evaluate `Condition=` for ONE selected `Configuration|Platform`, resolve
//!   `$(...)` properties (the solution and project macros, properties the
//!   project files define, environment variables), and read each `ClCompile`
//!   item's evaluated metadata. Nothing is executed.
//! * **MSBuild evaluation** (`--probe-build`/`--run-untrusted`, when MSBuild is
//!   installed): `msbuild -getItem:ClCompile` evaluates the project exactly as
//!   a build would and prints every item's metadata as JSON. Evaluation runs
//!   the project's property functions, so it needs the same consent as running
//!   its build.
//!
//! Both tiers normalise `\` to `/` in every path they read, so a solution
//! analysed on a POSIX host resolves its include directories correctly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One translation unit of an imported project, with the compile settings the
/// project gives it in the selected configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ImportedSource {
    pub file: PathBuf,
    pub directory: PathBuf,
    pub include_dirs: Vec<PathBuf>,
    pub defines: Vec<String>,
    pub undefines: Vec<String>,
    pub forced_includes: Vec<PathBuf>,
    /// `-std=` value (`c11`, `c++17`).
    pub standard: Option<String>,
    /// `-x c` / `-x c++` from `CompileAs`.
    pub language: Option<&'static str>,
    /// Clang spellings of `AdditionalOptions` and the few metadata switches
    /// with a clang equivalent (`/Zp`, `wchar_t`).
    pub extra_flags: Vec<String>,
}

/// One imported project.
#[derive(Debug, Clone, Default)]
pub(crate) struct ImportedProject {
    pub project: PathBuf,
    pub configuration: String,
    pub platform: String,
    pub sources: Vec<ImportedSource>,
    /// `AdditionalDependencies` of the project's link (or lib) step, resolved
    /// against `AdditionalLibraryDirectories` when the file is found there.
    pub link_inputs: Vec<String>,
    /// `$(...)` references with no value here, by name. The token they appear
    /// in is left out (an include dir that starts with an empty `$(SDK)` would
    /// otherwise point at the wrong place).
    pub unresolved: BTreeSet<String>,
    pub notes: Vec<String>,
}

/// Which solution and configuration to import.
#[derive(Debug, Clone, Default)]
pub(crate) struct ImportRequest {
    pub solution: Option<PathBuf>,
    /// `Configuration|Platform`, e.g. `Release|x64`.
    pub configuration: Option<String>,
}

/// The import of one solution (or of the projects of a tree without one).
#[derive(Debug, Clone, Default)]
pub(crate) struct SolutionImport {
    /// The solution read, or `None` when the tree has only project files.
    pub solution: Option<PathBuf>,
    /// Every solution found, in the deterministic order the choice was made in.
    pub candidates: Vec<PathBuf>,
    pub configuration: String,
    pub platform: String,
    pub projects: Vec<ImportedProject>,
    /// `static` or `msbuild`.
    pub tier: &'static str,
}

#[cfg(test)]
impl SolutionImport {
    pub fn source_count(&self) -> usize {
        self.projects.iter().map(|p| p.sources.len()).sum()
    }
}

/// MSBuild's toolset include-path macros. Their directories are the compiler's
/// own system include path, which clang and cl find through `INCLUDE`; leaving
/// them out is correct and needs no warning.
const TOOLSET_INCLUDE_MACROS: &[&str] = &[
    "vc_includepath",
    "windowssdk_includepath",
    "universalcrt_includepath",
    "includepath",
    "externalincludepath",
    "vc_sourcepath",
    "netfxkitsdir",
    "windowssdkdir",
    "vctoolsinstalldir",
    "vcinstalldir",
];

// ---------------------------------------------------------------------------
// Discovery and selection
// ---------------------------------------------------------------------------

/// Every `.sln`/`.slnx` under `tree` (bounded depth, output and VCS dirs
/// skipped), ordered shallowest first, then by path, so the choice among
/// several is the same on every run and host.
pub(crate) fn find_solutions(tree: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk_project_files(
        tree,
        &mut |path| matches!(extension_lower(path).as_deref(), Some("sln") | Some("slnx")),
        &mut found,
    );
    sort_by_depth(tree, &mut found);
    found
}

/// Every `.vcxproj` under `tree`, in the same deterministic order.
pub(crate) fn find_projects(tree: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk_project_files(
        tree,
        &mut |path| extension_lower(path).as_deref() == Some("vcxproj"),
        &mut found,
    );
    sort_by_depth(tree, &mut found);
    found
}

fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
}

fn sort_by_depth(tree: &Path, paths: &mut [PathBuf]) {
    paths.sort_by_key(|path| {
        let relative = path.strip_prefix(tree).unwrap_or(path);
        (
            relative.components().count(),
            relative.to_string_lossy().to_ascii_lowercase(),
        )
    });
}

fn walk_project_files(
    tree: &Path,
    accept: &mut dyn FnMut(&Path) -> bool,
    found: &mut Vec<PathBuf>,
) {
    let mut stack = vec![(tree.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if depth < 5
                    && !name.starts_with('.')
                    && !matches!(name.as_ref(), "target" | "node_modules" | "bhf_work")
                {
                    stack.push((path, depth + 1));
                }
            } else if accept(&path) {
                found.push(path);
            }
        }
    }
}

/// A parsed solution: its projects and configurations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Solution {
    pub projects: Vec<SolutionProject>,
    /// `Configuration|Platform` pairs, in file order.
    pub configurations: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SolutionProject {
    pub path: PathBuf,
    pub guid: Option<String>,
    /// Solution configuration -> the project configuration it builds.
    pub mapping: BTreeMap<String, String>,
}

/// Parse a `.sln` (text) or `.slnx` (XML) solution. Project paths are
/// resolved against the solution directory with `\` read as a separator.
pub(crate) fn parse_solution(path: &Path) -> Solution {
    let Ok(text) = read_project_text(path) else {
        return Solution::default();
    };
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    if extension_lower(path).as_deref() == Some("slnx") {
        parse_slnx(&text, dir)
    } else {
        parse_sln(&text, dir)
    }
}

fn parse_sln(text: &str, dir: &Path) -> Solution {
    let mut solution = Solution::default();
    let mut section: Option<String> = None;
    let mut by_guid: BTreeMap<String, usize> = BTreeMap::new();
    let mut mappings: Vec<(String, String, String)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim().trim_start_matches('\u{feff}');
        if line.starts_with("Project(") {
            let quoted: Vec<&str> = line.split('"').collect();
            let (Some(rel), guid) = (quoted.get(5), quoted.get(7)) else {
                continue;
            };
            if !rel.to_ascii_lowercase().ends_with(".vcxproj") {
                continue;
            }
            let path = normalize_lexically(&dir.join(slashes(rel)));
            let guid = guid.map(|g| g.to_ascii_uppercase());
            if let Some(guid) = &guid {
                by_guid.insert(guid.clone(), solution.projects.len());
            }
            solution.projects.push(SolutionProject {
                path,
                guid,
                mapping: BTreeMap::new(),
            });
        } else if let Some(rest) = line.strip_prefix("GlobalSection(") {
            section = rest.split(')').next().map(str::to_owned);
        } else if line.starts_with("EndGlobalSection") {
            section = None;
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            match section.as_deref() {
                Some("SolutionConfigurationPlatforms") => {
                    if !solution.configurations.iter().any(|c| c == key) {
                        solution.configurations.push(key.to_owned());
                    }
                }
                Some("ProjectConfigurationPlatforms") => {
                    // `{GUID}.Debug|x64.ActiveCfg = Debug|x64`
                    if let Some(prefix) = key.strip_suffix(".ActiveCfg") {
                        if let Some((guid, config)) = prefix.split_once('.') {
                            mappings.push((
                                guid.to_ascii_uppercase(),
                                config.to_owned(),
                                value.to_owned(),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    for (guid, solution_config, project_config) in mappings {
        if let Some(&index) = by_guid.get(&guid) {
            solution.projects[index]
                .mapping
                .insert(solution_config, project_config);
        }
    }
    solution
}

fn parse_slnx(text: &str, dir: &Path) -> Solution {
    let mut solution = Solution::default();
    let Ok(root) = parse_xml(text) else {
        return solution;
    };
    let mut build_types = Vec::new();
    let mut platforms = Vec::new();
    let mut projects = Vec::new();
    root.walk(&mut |element| match element.name.as_str() {
        "BuildType" => {
            if let Some(name) = element.attr("Name") {
                build_types.push(name.to_owned());
            }
        }
        "Platform" => {
            if let Some(name) = element.attr("Name") {
                platforms.push(name.to_owned());
            }
        }
        "Project" => {
            if let Some(path) = element.attr("Path") {
                if path.to_ascii_lowercase().ends_with(".vcxproj") {
                    projects.push(path.to_owned());
                }
            }
        }
        _ => {}
    });
    if build_types.is_empty() {
        build_types = vec!["Debug".to_owned(), "Release".to_owned()];
    }
    if platforms.is_empty() {
        platforms = vec!["x64".to_owned()];
    }
    for build in &build_types {
        for platform in &platforms {
            solution.configurations.push(format!("{build}|{platform}"));
        }
    }
    solution.projects = projects
        .into_iter()
        .map(|rel| SolutionProject {
            path: normalize_lexically(&dir.join(slashes(&rel))),
            guid: None,
            mapping: BTreeMap::new(),
        })
        .collect();
    solution
}

/// The configuration to import: the requested one, else the first listed for
/// a 64-bit x86 platform (the harness is a 64-bit program), else the first
/// listed, else `Debug|x64`.
pub(crate) fn choose_configuration(listed: &[String], requested: Option<&str>) -> (String, String) {
    let split = |value: &str| -> (String, String) {
        match value.split_once('|') {
            Some((config, platform)) => (config.trim().to_owned(), platform.trim().to_owned()),
            None => (value.trim().to_owned(), "x64".to_owned()),
        }
    };
    if let Some(requested) = requested.filter(|r| !r.trim().is_empty()) {
        return split(requested);
    }
    listed
        .iter()
        .find(|config| {
            config
                .split_once('|')
                .is_some_and(|(_, platform)| platform.eq_ignore_ascii_case("x64"))
        })
        .or_else(|| listed.first())
        .map(|config| split(config))
        .unwrap_or_else(|| ("Debug".to_owned(), "x64".to_owned()))
}

// ---------------------------------------------------------------------------
// The static tier
// ---------------------------------------------------------------------------

/// Import the solution chosen from `tree` (or every project when there is no
/// solution) with the static evaluator. `None` when the tree has no Visual
/// Studio project at all.
pub(crate) fn import_tree(tree: &Path, request: &ImportRequest) -> Option<SolutionImport> {
    let candidates = find_solutions(tree);
    let solution_path = request
        .solution
        .as_ref()
        .map(|path| {
            if path.is_absolute() {
                path.clone()
            } else {
                tree.join(path)
            }
        })
        .or_else(|| candidates.first().cloned());
    let env = |name: &str| std::env::var(name).ok();
    match solution_path {
        Some(solution_path) => {
            let solution = parse_solution(&solution_path);
            let (configuration, platform) =
                choose_configuration(&solution.configurations, request.configuration.as_deref());
            let solution_key = format!("{configuration}|{platform}");
            let mut projects = Vec::new();
            for project in &solution.projects {
                if !project.path.is_file() {
                    continue;
                }
                let (project_config, project_platform) = project
                    .mapping
                    .get(&solution_key)
                    .map(|mapped| choose_configuration(&[], Some(mapped)))
                    .unwrap_or_else(|| (configuration.clone(), platform.clone()));
                projects.push(evaluate_project(
                    &project.path,
                    Some(&solution_path),
                    &project_config,
                    &project_platform,
                    &env,
                ));
            }
            Some(SolutionImport {
                solution: Some(solution_path),
                candidates,
                configuration,
                platform,
                projects,
                tier: "static",
            })
        }
        None => {
            let project_paths = find_projects(tree);
            let first = project_paths.first()?;
            let listed = project_configurations(first);
            let (configuration, platform) =
                choose_configuration(&listed, request.configuration.as_deref());
            let projects = project_paths
                .iter()
                .map(|path| evaluate_project(path, None, &configuration, &platform, &env))
                .collect();
            Some(SolutionImport {
                solution: None,
                candidates,
                configuration,
                platform,
                projects,
                tier: "static",
            })
        }
    }
}

/// The `ProjectConfiguration` items a project lists (`Debug|x64`, ...).
pub(crate) fn project_configurations(project: &Path) -> Vec<String> {
    let Ok(text) = read_project_text(project) else {
        return Vec::new();
    };
    let Ok(root) = parse_xml(&text) else {
        return Vec::new();
    };
    let mut configs = Vec::new();
    root.walk(&mut |element| {
        if element.name == "ProjectConfiguration" {
            if let Some(include) = element.attr("Include") {
                configs.push(include.to_owned());
            }
        }
    });
    configs
}

/// Statically evaluate one project for `configuration|platform`.
pub(crate) fn evaluate_project(
    project: &Path,
    solution: Option<&Path>,
    configuration: &str,
    platform: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> ImportedProject {
    let mut evaluator = Evaluator::new(project, solution, configuration, platform, env);
    evaluator.load(project, 0);
    evaluator.finish()
}

/// Marks an unresolved `$(...)` inside an expanded value. NUL never appears in
/// project XML (the reader drops `&#0;`), so a piece carrying it is known to be
/// incomplete.
const UNRESOLVED: char = '\u{0}';

/// The longest value one expansion may produce (an include path list, a define
/// list). Anything longer is treated as unresolved.
const MAX_EXPANDED_VALUE: usize = 256 * 1024;

/// The bytes one project's evaluation may produce by expansion and item
/// metadata, over all its properties, conditions and items.
const EXPANSION_BUDGET: usize = 64 * 1024 * 1024;

/// How deep a property value's own references are expanded.
const MAX_EXPANSION_DEPTH: usize = 32;

/// The largest project, property sheet or solution file read.
const MAX_PROJECT_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// An unresolved piece standing for a value bhf will not compute.
fn unresolved_marker(reason: &str) -> String {
    format!("{UNRESOLVED}{reason}{UNRESOLVED}")
}

/// A project, property sheet or solution file's text, refused past
/// [`MAX_PROJECT_FILE_BYTES`].
fn read_project_text(path: &Path) -> Result<String, String> {
    let size = std::fs::metadata(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?
        .len();
    if size > MAX_PROJECT_FILE_BYTES {
        return Err(format!(
            "skipped {}: {size} bytes is more than the {MAX_PROJECT_FILE_BYTES} a project file \
             may have",
            path.display()
        ));
    }
    std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))
}

struct Deferred {
    element: XmlElement,
    file: PathBuf,
}

struct Item {
    include: String,
    metadata: BTreeMap<String, String>,
}

struct Evaluator<'a> {
    project: PathBuf,
    project_dir: PathBuf,
    props: BTreeMap<String, String>,
    env: &'a dyn Fn(&str) -> Option<String>,
    unresolved: BTreeSet<String>,
    notes: Vec<String>,
    item_definitions: Vec<Deferred>,
    item_groups: Vec<Deferred>,
    visited: BTreeSet<PathBuf>,
    /// Bytes left of [`EXPANSION_BUDGET`].
    budget: usize,
    noted_budget: bool,
    noted_long_value: bool,
}

impl<'a> Evaluator<'a> {
    fn new(
        project: &Path,
        solution: Option<&Path>,
        configuration: &str,
        platform: &str,
        env: &'a dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let project = normalize_lexically(project);
        let project_dir = project
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let mut props = BTreeMap::new();
        let mut set = |name: &str, value: String| {
            props.insert(name.to_ascii_lowercase(), value);
        };
        let dir_slash = |dir: &Path| format!("{}/", slash_text(dir).trim_end_matches('/'));
        let stem = |path: &Path| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned()
        };
        set("Configuration", configuration.to_owned());
        set("Platform", platform.to_owned());
        set("ProjectDir", dir_slash(&project_dir));
        set("ProjectPath", slash_text(&project));
        set("ProjectName", stem(&project));
        set("TargetName", stem(&project));
        set(
            "ProjectFileName",
            project
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned(),
        );
        set("ProjectExt", ".vcxproj".to_owned());
        set(
            "MSBuildProjectDirectory",
            slash_text(&project_dir).trim_end_matches('/').to_owned(),
        );
        set("MSBuildProjectFullPath", slash_text(&project));
        set("MSBuildProjectName", stem(&project));
        // A solution build passes its directory as SolutionDir. Without one,
        // the project directory stands in (what Visual Studio uses when a
        // project is opened on its own).
        let solution_dir = solution
            .and_then(Path::parent)
            .map(normalize_lexically)
            .unwrap_or_else(|| project_dir.clone());
        set("SolutionDir", dir_slash(&solution_dir));
        if let Some(solution) = solution {
            set("SolutionPath", slash_text(&normalize_lexically(solution)));
            set("SolutionName", stem(solution));
            set(
                "SolutionFileName",
                solution
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
        // Microsoft.Cpp.Default.props' output-directory defaults.
        let (out_dir, int_dir) = if platform.eq_ignore_ascii_case("Win32") {
            (
                format!("$(SolutionDir){configuration}/"),
                format!("{configuration}/"),
            )
        } else {
            (
                format!("$(SolutionDir){platform}/{configuration}/"),
                format!("{platform}/{configuration}/"),
            )
        };
        set("OutDir", out_dir);
        set("IntDir", int_dir);
        Evaluator {
            project,
            project_dir,
            props,
            env,
            unresolved: BTreeSet::new(),
            notes: Vec::new(),
            item_definitions: Vec::new(),
            item_groups: Vec::new(),
            visited: BTreeSet::new(),
            budget: EXPANSION_BUDGET,
            noted_budget: false,
            noted_long_value: false,
        }
    }

    /// Pass 1 over one file (and its imports, in place): properties. Item
    /// definitions and items are deferred until every property has its final
    /// value, as MSBuild evaluates them.
    fn load(&mut self, file: &Path, depth: usize) {
        let file = normalize_lexically(file);
        if depth > 16 || !self.visited.insert(file.clone()) {
            return;
        }
        let text = match read_project_text(&file) {
            Ok(text) => text,
            Err(problem) => {
                self.notes.push(problem);
                return;
            }
        };
        let root = match parse_xml(&text) {
            Ok(root) => root,
            Err(error) => {
                self.notes
                    .push(format!("could not parse {}: {error}", file.display()));
                return;
            }
        };
        for child in root.elements() {
            self.load_element(child, &file, depth, true);
        }
    }

    fn load_element(&mut self, element: &XmlElement, file: &Path, depth: usize, parent_ok: bool) {
        if !parent_ok {
            return;
        }
        match element.name.as_str() {
            // Their conditions are read in the later passes, with every
            // property at its final value.
            "ItemDefinitionGroup" => {
                self.item_definitions.push(Deferred {
                    element: element.clone(),
                    file: file.to_path_buf(),
                });
                return;
            }
            "ItemGroup" => {
                self.item_groups.push(Deferred {
                    element: element.clone(),
                    file: file.to_path_buf(),
                });
                return;
            }
            _ => {}
        }
        if !self.condition(element, file) {
            return;
        }
        match element.name.as_str() {
            "PropertyGroup" => {
                for property in element.elements() {
                    if !self.condition(property, file) {
                        continue;
                    }
                    let value = self.expand(&property.text(), file, None);
                    self.props.insert(property.name.to_ascii_lowercase(), value);
                }
            }
            "ImportGroup" => {
                for import in element.elements() {
                    self.load_element(import, file, depth, true);
                }
            }
            "Import" => {
                let Some(raw) = element.attr("Project") else {
                    return;
                };
                if is_toolset_import(raw) {
                    return;
                }
                let expanded = self.expand(raw, file, None);
                if expanded.contains(UNRESOLVED) || expanded.contains('*') {
                    self.notes.push(format!(
                        "skipped import {raw:?} in {}: its path is not known without MSBuild",
                        file.display()
                    ));
                    return;
                }
                let base = file.parent().unwrap_or_else(|| Path::new("."));
                let target = resolve_path(base, &expanded);
                if target.is_file() {
                    self.load(&target, depth + 1);
                }
            }
            "Choose" => {
                // <Choose><When Condition>...</When><Otherwise>...</Otherwise>
                for branch in element.elements() {
                    let taken = match branch.name.as_str() {
                        "When" => self.condition(branch, file),
                        "Otherwise" => true,
                        _ => false,
                    };
                    if taken {
                        for child in branch.elements() {
                            self.load_element(child, file, depth, true);
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    fn condition(&mut self, element: &XmlElement, file: &Path) -> bool {
        let Some(condition) = element.attr("Condition") else {
            return true;
        };
        let base = self.project_dir.clone();
        match evaluate_condition(condition, &base, &mut |text| {
            self.expand_for_condition(text, file)
        }) {
            Ok(value) => value,
            Err(error) => {
                self.notes.push(format!(
                    "treated condition {condition:?} in {} as false: {error}",
                    file.display()
                ));
                false
            }
        }
    }

    /// `$(...)` expansion for a condition: an undefined property is empty,
    /// exactly as MSBuild reads it.
    fn expand_for_condition(&mut self, text: &str, file: &Path) -> String {
        self.expand(text, file, None)
            .split(UNRESOLVED)
            .enumerate()
            .filter(|(index, _)| index % 2 == 0)
            .map(|(_, piece)| piece)
            .collect()
    }

    fn property(&self, name: &str, file: &Path) -> Option<String> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "msbuildthisfiledirectory" => {
                return file
                    .parent()
                    .map(|dir| format!("{}/", slash_text(dir).trim_end_matches('/')));
            }
            "msbuildthisfile" => {
                return file.file_name().and_then(|n| n.to_str()).map(str::to_owned);
            }
            "msbuildthisfilefullpath" => return Some(slash_text(file)),
            "msbuildthisfilename" => {
                return file.file_stem().and_then(|n| n.to_str()).map(str::to_owned);
            }
            _ => {}
        }
        if let Some(value) = self.props.get(&lower) {
            return Some(value.clone());
        }
        (self.env)(name)
    }

    /// Expand `$(Property)` and, with `metadata`, `%(Metadata)` references.
    /// A reference with no value becomes `UNRESOLVED name UNRESOLVED`, so the
    /// list piece holding it can be left out as a whole. A value longer than
    /// [`MAX_EXPANDED_VALUE`], or one expanded after the project's
    /// [`EXPANSION_BUDGET`] is spent, is unresolved too: project files are
    /// untrusted, and a chain of properties that each double the last would
    /// otherwise grow without bound.
    fn expand(
        &mut self,
        text: &str,
        file: &Path,
        metadata: Option<&BTreeMap<String, String>>,
    ) -> String {
        if self.budget == 0 {
            return unresolved_marker("over budget");
        }
        let out = self.expand_at(text, file, metadata, 0);
        if out.len() > MAX_EXPANDED_VALUE {
            if !self.noted_long_value {
                self.noted_long_value = true;
                self.notes.push(format!(
                    "a value in {} expands to longer than {MAX_EXPANDED_VALUE} bytes; it is \
                     left out as unresolved",
                    file.display()
                ));
            }
            return unresolved_marker("too long");
        }
        if !self.charge(out.len()) {
            return unresolved_marker("over budget");
        }
        out
    }

    /// Take `bytes` from the project's expansion budget; `false` (with a note,
    /// once) when it is spent.
    fn charge(&mut self, bytes: usize) -> bool {
        if bytes <= self.budget {
            self.budget -= bytes;
            return true;
        }
        self.budget = 0;
        if !self.noted_budget {
            self.noted_budget = true;
            self.notes.push(format!(
                "the expansion budget ({EXPANSION_BUDGET} bytes) for {} is spent; later \
                 values are left out as unresolved",
                self.project.display()
            ));
        }
        false
    }

    fn expand_at(
        &mut self,
        text: &str,
        file: &Path,
        metadata: Option<&BTreeMap<String, String>>,
        depth: usize,
    ) -> String {
        let mut out = String::with_capacity(text.len().min(MAX_EXPANDED_VALUE));
        let chars: Vec<char> = text.chars().collect();
        let mut index = 0;
        while index < chars.len() {
            if out.len() > MAX_EXPANDED_VALUE {
                // The caller replaces the whole value; stop copying.
                break;
            }
            let ch = chars[index];
            if ch == UNRESOLVED {
                // An unresolved reference carried in from a stored value is
                // kept as it is, not expanded (and wrapped) again.
                let close = chars[index + 1..]
                    .iter()
                    .position(|c| *c == UNRESOLVED)
                    .map_or(chars.len(), |offset| index + 1 + offset);
                out.extend(&chars[index..(close + 1).min(chars.len())]);
                index = close + 1;
                continue;
            }
            if (ch == '$' || ch == '%' || ch == '@') && chars.get(index + 1) == Some(&'(') {
                let Some(close) = matching_paren(&chars, index + 1) else {
                    out.extend(&chars[index..]);
                    break;
                };
                let inner: String = chars[index + 2..close].iter().collect();
                let name = inner.trim();
                let simple = !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                let value = match ch {
                    '$' if simple => self.property(name, file),
                    '%' if simple => {
                        metadata.and_then(|meta| meta.get(&name.to_ascii_lowercase()).cloned())
                    }
                    _ => None,
                };
                match value {
                    Some(value) => {
                        // A property's value may hold references of its own
                        // (the output-directory defaults, environment values).
                        if value.contains("$(")
                            && ch == '$'
                            && !value.contains(&format!("$({name})"))
                        {
                            if depth < MAX_EXPANSION_DEPTH {
                                let nested = self.expand_at(&value, file, metadata, depth + 1);
                                out.push_str(&nested);
                            } else {
                                out.push_str(&unresolved_marker("nested too deep"));
                            }
                        } else {
                            out.push_str(&value);
                        }
                    }
                    None if ch == '%' && simple && metadata.is_some() => {
                        // An item metadata reference with no value is empty.
                    }
                    None => {
                        // Named on the console, so a long one is shortened.
                        let shown: String = name.chars().take(80).collect();
                        let ellipsis = if shown.len() < name.len() { "..." } else { "" };
                        let label = format!("{ch}({shown}{ellipsis})");
                        if !(ch == '$'
                            && TOOLSET_INCLUDE_MACROS.contains(&name.to_ascii_lowercase().as_str()))
                        {
                            self.unresolved.insert(label.clone());
                        }
                        out.push(UNRESOLVED);
                        out.push_str(&label);
                        out.push(UNRESOLVED);
                    }
                }
                index = close + 1;
                continue;
            }
            out.push(ch);
            index += 1;
        }
        out
    }

    /// Passes 2 and 3: item definitions, then the `ClCompile` items with their
    /// metadata, then the per-source compile settings.
    fn finish(mut self) -> ImportedProject {
        let mut definitions: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let deferred = std::mem::take(&mut self.item_definitions);
        for group in &deferred {
            if !self.condition(&group.element, &group.file) {
                continue;
            }
            for item_type in group.element.elements() {
                if !self.condition(item_type, &group.file) {
                    continue;
                }
                let kind = item_type.name.to_ascii_lowercase();
                let mut current = definitions.remove(&kind).unwrap_or_default();
                for meta in item_type.elements() {
                    if !self.condition(meta, &group.file) {
                        continue;
                    }
                    let value = self.expand(&meta.text(), &group.file, Some(&current));
                    current.insert(meta.name.to_ascii_lowercase(), value);
                }
                definitions.insert(kind, current);
            }
        }

        let mut items: Vec<Item> = Vec::new();
        let groups = std::mem::take(&mut self.item_groups);
        for group in &groups {
            if !self.condition(&group.element, &group.file) {
                continue;
            }
            for element in group.element.elements() {
                if !element.name.eq_ignore_ascii_case("ClCompile") {
                    continue;
                }
                if !self.condition(element, &group.file) {
                    continue;
                }
                if let Some(remove) = element.attr("Remove") {
                    let remove = self.expand(remove, &group.file, None);
                    let removed: BTreeSet<String> = split_list(&remove)
                        .map(|path| slashes(path).to_ascii_lowercase())
                        .collect();
                    items.retain(|item| !removed.contains(&item.include.to_ascii_lowercase()));
                    continue;
                }
                let Some(include) = element.attr("Include") else {
                    continue;
                };
                let include = self.expand(include, &group.file, None);
                let exclude: BTreeSet<String> = element
                    .attr("Exclude")
                    .map(|exclude| self.expand(exclude, &group.file, None))
                    .map(|exclude| {
                        split_list(&exclude)
                            .map(|path| slashes(path).to_ascii_lowercase())
                            .collect()
                    })
                    .unwrap_or_default();
                for path in split_list(&include) {
                    if path.contains(UNRESOLVED) {
                        continue;
                    }
                    for include in expand_wildcard(&self.project_dir, &slashes(path)) {
                        if exclude.contains(&include.to_ascii_lowercase()) {
                            continue;
                        }
                        let mut metadata =
                            definitions.get("clcompile").cloned().unwrap_or_default();
                        let file_name = Path::new(&include);
                        metadata.insert("identity".to_owned(), include.clone());
                        metadata.insert(
                            "filename".to_owned(),
                            file_name
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or_default()
                                .to_owned(),
                        );
                        metadata.insert(
                            "extension".to_owned(),
                            file_name
                                .extension()
                                .and_then(|s| s.to_str())
                                .map(|e| format!(".{e}"))
                                .unwrap_or_default(),
                        );
                        for meta in element.elements() {
                            if !self.condition(meta, &group.file) {
                                continue;
                            }
                            let value = self.expand(&meta.text(), &group.file, Some(&metadata));
                            metadata.insert(meta.name.to_ascii_lowercase(), value);
                        }
                        // Every item holds its own copy of the definitions.
                        let size = metadata.iter().map(|(k, v)| k.len() + v.len()).sum();
                        if !self.charge(size) {
                            break;
                        }
                        items.push(Item { include, metadata });
                    }
                }
            }
        }

        let character_set = self.props.get("characterset").cloned().unwrap_or_default();
        let configuration_type = self
            .props
            .get("configurationtype")
            .cloned()
            .unwrap_or_default();
        let mut sources = Vec::new();
        for item in items {
            if metadata_true(item.metadata.get("excludedfrombuild")) {
                continue;
            }
            let file = resolve_path(&self.project_dir, &item.include);
            let mut source = ImportedSource {
                file,
                directory: self.project_dir.clone(),
                ..ImportedSource::default()
            };
            source_settings(&mut source, &item.metadata, &self.project_dir);
            // Microsoft.Cpp.props turns the character set into defines.
            match character_set.to_ascii_lowercase().as_str() {
                "unicode" => {
                    push_unique(&mut source.defines, "_UNICODE".to_owned());
                    push_unique(&mut source.defines, "UNICODE".to_owned());
                }
                "multibyte" => push_unique(&mut source.defines, "_MBCS".to_owned()),
                _ => {}
            }
            if configuration_type.eq_ignore_ascii_case("DynamicLibrary") {
                push_unique(&mut source.defines, "_WINDLL".to_owned());
            }
            sources.push(source);
        }

        let mut link_inputs = Vec::new();
        for kind in ["link", "lib"] {
            let Some(meta) = definitions.get(kind) else {
                continue;
            };
            let library_dirs: Vec<PathBuf> = meta
                .get("additionallibrarydirectories")
                .map(|dirs| {
                    split_list(dirs)
                        .filter(|piece| complete_piece(piece))
                        .map(|dir| resolve_path(&self.project_dir, &slashes(dir)))
                        .collect()
                })
                .unwrap_or_default();
            if let Some(dependencies) = meta.get("additionaldependencies") {
                for dependency in split_list(dependencies).filter(|piece| complete_piece(piece)) {
                    let dependency = slashes(dependency);
                    let resolved = if dependency.contains('/') {
                        Some(resolve_path(&self.project_dir, &dependency))
                    } else {
                        library_dirs
                            .iter()
                            .map(|dir| dir.join(&dependency))
                            .find(|path| path.is_file())
                    };
                    let input = match resolved {
                        Some(path) => slash_text(&path),
                        None => dependency,
                    };
                    push_unique(&mut link_inputs, input);
                }
            }
        }

        let configuration = self.props.get("configuration").cloned().unwrap_or_default();
        let platform = self.props.get("platform").cloned().unwrap_or_default();
        ImportedProject {
            project: self.project,
            configuration,
            platform,
            sources,
            link_inputs,
            unresolved: self.unresolved,
            notes: self.notes,
        }
    }
}

/// The compile settings in one item's evaluated metadata (shared with the
/// MSBuild evaluation tier, whose JSON carries the same metadata names).
fn source_settings(
    source: &mut ImportedSource,
    metadata: &BTreeMap<String, String>,
    project_dir: &Path,
) {
    let get = |name: &str| metadata.get(name).map(String::as_str).unwrap_or_default();
    for dir in split_list(get("additionalincludedirectories")).filter(|p| complete_piece(p)) {
        let dir = resolve_path(project_dir, &slashes(dir));
        if !source.include_dirs.contains(&dir) {
            source.include_dirs.push(dir);
        }
    }
    for define in split_list(get("preprocessordefinitions")).filter(|p| complete_piece(p)) {
        push_unique(&mut source.defines, define.to_owned());
    }
    for name in split_list(get("undefinepreprocessordefinitions")).filter(|p| complete_piece(p)) {
        push_unique(&mut source.undefines, name.to_owned());
    }
    for header in split_list(get("forcedincludefiles")).filter(|p| complete_piece(p)) {
        let header = resolve_path(project_dir, &slashes(header));
        if !source.forced_includes.contains(&header) {
            source.forced_includes.push(header);
        }
    }
    let is_cpp = matches!(
        source
            .file
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("cpp" | "cc" | "cxx" | "c++")
    );
    source.language = match get("compileas") {
        "CompileAsC" => Some("c"),
        "CompileAsCpp" => Some("c++"),
        _ => None,
    };
    let compiles_cpp = source.language.map(|l| l == "c++").unwrap_or(is_cpp);
    source.standard = if compiles_cpp {
        match get("languagestandard") {
            "stdcpp14" => Some("c++14"),
            "stdcpp17" => Some("c++17"),
            "stdcpp20" => Some("c++20"),
            "stdcpp23" | "stdcpplatest" => Some("c++2b"),
            _ => None,
        }
    } else {
        match get("languagestandard_c") {
            "stdc11" => Some("c11"),
            "stdc17" => Some("c17"),
            "stdclatest" => Some("c2x"),
            _ => None,
        }
    }
    .map(str::to_owned);
    match get("structmemberalignment") {
        "1Byte" => source.extra_flags.push("-fpack-struct=1".to_owned()),
        "2Bytes" => source.extra_flags.push("-fpack-struct=2".to_owned()),
        "4Bytes" => source.extra_flags.push("-fpack-struct=4".to_owned()),
        "8Bytes" => source.extra_flags.push("-fpack-struct=8".to_owned()),
        _ => {}
    }
    if get("treatwchar_tasbuiltintype").eq_ignore_ascii_case("false") {
        source.extra_flags.push("-fno-wchar".to_owned());
    }
    let options = get("additionaloptions");
    if complete_piece(options) && !options.trim().is_empty() {
        let mut words = vec!["cl".to_owned()];
        words.extend(
            crate::generate_harness::split_windows_command_line(options)
                .into_iter()
                .filter(|word| !word.starts_with('%')),
        );
        let (translated, _) =
            crate::generate_harness::translate_msvc_compile_arguments(&words, project_dir);
        source.extra_flags.extend(translated.into_iter().skip(1));
    }
}

fn metadata_true(value: Option<&String>) -> bool {
    value.is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Whether a list piece is complete: no unresolved reference and no inherited
/// `%(...)` placeholder.
fn complete_piece(piece: &str) -> bool {
    !piece.contains(UNRESOLVED) && !piece.contains("%(") && !piece.contains("@(")
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(';')
        .map(str::trim)
        .filter(|piece| !piece.is_empty())
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

fn is_toolset_import(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    [
        "$(vctargetspath)",
        "$(msbuildextensionspath",
        "$(msbuildtoolspath)",
        "$(msbuildbinpath)",
        "$(userrootdir)",
        "$(msbuildsdkspath)",
        "$(vsinstalldir)",
    ]
    .iter()
    .any(|prefix| lower.contains(prefix))
}

fn matching_paren(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in chars[open..].iter().enumerate() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// `\` as a path separator, on every host.
fn slashes(path: &str) -> String {
    path.replace('\\', "/")
}

fn slash_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// `value` (a project path, `/` separators) against `base`: absolute paths
/// (`C:/x`, `/x`) as given, the rest joined, then `.`/`..` folded.
fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let value = slashes(value.trim().trim_matches('"'));
    let is_drive = value.len() >= 2
        && value.as_bytes()[1] == b':'
        && value.as_bytes()[0].is_ascii_alphabetic();
    let joined = if is_drive || Path::new(&value).is_absolute() {
        PathBuf::from(&value)
    } else {
        base.join(&value)
    };
    normalize_lexically(&joined)
}

/// Fold `.` and `..` components without touching the filesystem, and drop
/// the empty components a `dir\\..\\x` (doubled separator) leaves.
pub(crate) fn normalize_lexically(path: &Path) -> PathBuf {
    let mut text = slash_text(path);
    // A canonicalized Windows path carries the verbatim prefix (`\\?\C:\...`,
    // `\\?\UNC\server\share`); its separators would otherwise fold away.
    if let Some(rest) = text.strip_prefix("//?/UNC/") {
        text = format!("//{rest}");
    } else if let Some(rest) = text.strip_prefix("//?/") {
        text = rest.to_owned();
    }
    let (prefix, rest) = if text.len() >= 2 && text.as_bytes()[1] == b':' {
        let (drive, rest) = text.split_at(2);
        (format!("{drive}/"), rest.to_owned())
    } else if let Some(unc) = text.strip_prefix("//") {
        ("//".to_owned(), unc.to_owned())
    } else if text.starts_with('/') {
        ("/".to_owned(), text.clone())
    } else {
        (String::new(), text.clone())
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if prefix.is_empty() {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = format!("{prefix}{}", parts.join("/"));
    if joined.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(joined)
    }
}

/// The files a `ClCompile Include` names: the path itself, or the matches of a
/// `*`/`**` wildcard in its file name (bounded).
fn expand_wildcard(base: &Path, include: &str) -> Vec<String> {
    if !include.contains('*') && !include.contains('?') {
        return vec![include.to_owned()];
    }
    let (dir_part, pattern) = match include.rsplit_once('/') {
        Some((dir, pattern)) => (dir.to_owned(), pattern.to_owned()),
        None => (String::new(), include.to_owned()),
    };
    let recursive = dir_part.ends_with("**");
    let root_rel = dir_part
        .trim_end_matches("**")
        .trim_end_matches('/')
        .to_owned();
    let root = base.join(&root_rel);
    let mut out = Vec::new();
    let mut stack = vec![(root.clone(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<_> = entries.flatten().collect();
        names.sort_by_key(|entry| entry.file_name());
        for entry in names {
            let path = entry.path();
            if path.is_dir() {
                if recursive && depth < 8 {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if wildcard_matches(&pattern, &name) {
                if let Ok(relative) = path.strip_prefix(base) {
                    out.push(slash_text(relative));
                }
            }
        }
    }
    out.sort();
    out
}

/// `*`/`?` file-name glob, ASCII case-insensitive, in O(pattern x name): on a
/// mismatch the last `*` takes one more byte of the name and matching resumes
/// after it, instead of retrying every split (exponential on `*a*a*a...`).
fn wildcard_matches(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut p, mut n) = (0usize, 0usize);
    let mut last_star: Option<(usize, usize)> = None;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'*') => {
                last_star = Some((p, n));
                p += 1;
            }
            Some(&c) if c == b'?' || c.eq_ignore_ascii_case(&name[n]) => {
                p += 1;
                n += 1;
            }
            _ => match last_star {
                Some((star, taken)) => {
                    last_star = Some((star, taken + 1));
                    p = star + 1;
                    n = taken + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Value(String),
    Word(String),
    Op(&'static str),
    Open,
    Close,
    Comma,
}

/// Evaluate an MSBuild `Condition`: quoted and bare values (expanded by
/// `expand`), `==` `!=` `<` `>` `<=` `>=`, `!`, `and`, `or`, parentheses,
/// `Exists(...)` and `HasTrailingSlash(...)`. Comparisons are case-insensitive;
/// the ordering operators compare numbers or dotted versions.
pub(crate) fn evaluate_condition(
    condition: &str,
    base: &Path,
    expand: &mut dyn FnMut(&str) -> String,
) -> Result<bool, String> {
    let tokens = tokenize_condition(condition)?;
    let mut parser = ConditionParser {
        tokens,
        index: 0,
        base,
        expand,
    };
    let value = parser.or_expr()?;
    if parser.index != parser.tokens.len() {
        return Err(format!("unexpected text after position {}", parser.index));
    }
    Ok(value)
}

fn tokenize_condition(text: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        match ch {
            c if c.is_whitespace() => index += 1,
            '\'' | '"' => {
                let end = chars[index + 1..]
                    .iter()
                    .position(|c| *c == ch)
                    .ok_or("unterminated quote")?;
                tokens.push(Token::Value(
                    chars[index + 1..index + 1 + end].iter().collect(),
                ));
                index += end + 2;
            }
            '(' => {
                tokens.push(Token::Open);
                index += 1;
            }
            ')' => {
                tokens.push(Token::Close);
                index += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                index += 1;
            }
            '=' | '!' | '<' | '>' => {
                let next = chars.get(index + 1).copied();
                let op = match (ch, next) {
                    ('=', Some('=')) => "==",
                    ('!', Some('=')) => "!=",
                    ('<', Some('=')) => "<=",
                    ('>', Some('=')) => ">=",
                    ('<', _) => "<",
                    ('>', _) => ">",
                    ('!', _) => "!",
                    _ => return Err("lone '='".to_owned()),
                };
                index += op.len();
                tokens.push(Token::Op(op));
            }
            '$' | '%' | '@' if chars.get(index + 1) == Some(&'(') => {
                let close = matching_paren(&chars, index + 1).ok_or("unbalanced $(")?;
                tokens.push(Token::Value(chars[index..=close].iter().collect()));
                index = close + 1;
            }
            _ => {
                let start = index;
                while index < chars.len()
                    && !chars[index].is_whitespace()
                    && !matches!(
                        chars[index],
                        '(' | ')' | ',' | '=' | '!' | '<' | '>' | '\'' | '"'
                    )
                {
                    index += 1;
                }
                tokens.push(Token::Word(chars[start..index].iter().collect()));
            }
        }
    }
    Ok(tokens)
}

struct ConditionParser<'e> {
    tokens: Vec<Token>,
    index: usize,
    /// What a relative `Exists()` path is relative to: the project directory.
    base: &'e Path,
    expand: &'e mut dyn FnMut(&str) -> String,
}

impl ConditionParser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.index).cloned();
        self.index += 1;
        token
    }

    fn keyword(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if w.eq_ignore_ascii_case(word))
    }

    fn or_expr(&mut self) -> Result<bool, String> {
        let mut value = self.and_expr()?;
        while self.keyword("or") {
            self.index += 1;
            let rhs = self.and_expr()?;
            value = value || rhs;
        }
        Ok(value)
    }

    fn and_expr(&mut self) -> Result<bool, String> {
        let mut value = self.unary()?;
        while self.keyword("and") {
            self.index += 1;
            let rhs = self.unary()?;
            value = value && rhs;
        }
        Ok(value)
    }

    fn unary(&mut self) -> Result<bool, String> {
        if self.peek() == Some(&Token::Op("!")) {
            self.index += 1;
            return Ok(!self.unary()?);
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<bool, String> {
        if self.peek() == Some(&Token::Open) {
            self.index += 1;
            let value = self.or_expr()?;
            if self.next() != Some(Token::Close) {
                return Err("missing ')'".to_owned());
            }
            return Ok(value);
        }
        // A function call: Exists('...'), HasTrailingSlash('...').
        if let Some(Token::Word(word)) = self.peek().cloned() {
            if self.tokens.get(self.index + 1) == Some(&Token::Open) {
                self.index += 2;
                let mut args = Vec::new();
                loop {
                    match self.next() {
                        Some(Token::Close) => break,
                        Some(Token::Comma) => {}
                        Some(Token::Value(value)) | Some(Token::Word(value)) => {
                            args.push((self.expand)(&value));
                        }
                        _ => return Err(format!("bad arguments to {word}")),
                    }
                }
                let arg = args.first().cloned().unwrap_or_default();
                return match word.to_ascii_lowercase().as_str() {
                    "exists" => {
                        Ok(!arg.trim().is_empty() && resolve_path(self.base, arg.trim()).exists())
                    }
                    "hastrailingslash" => Ok(arg.ends_with('/') || arg.ends_with('\\')),
                    other => Err(format!("unsupported function {other}")),
                };
            }
        }
        let lhs = self.operand()?;
        match self.peek() {
            Some(Token::Op(op)) if *op != "!" => {
                let op = *op;
                self.index += 1;
                let rhs = self.operand()?;
                compare(&lhs, op, &rhs)
            }
            _ => match lhs.trim().to_ascii_lowercase().as_str() {
                "true" | "on" | "yes" => Ok(true),
                "false" | "off" | "no" | "" => Ok(false),
                other => Err(format!("{other:?} is not a boolean")),
            },
        }
    }

    fn operand(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Token::Value(value)) | Some(Token::Word(value)) => Ok((self.expand)(&value)),
            other => Err(format!("expected a value, found {other:?}")),
        }
    }
}

fn compare(lhs: &str, op: &str, rhs: &str) -> Result<bool, String> {
    match op {
        "==" => Ok(lhs.eq_ignore_ascii_case(rhs)),
        "!=" => Ok(!lhs.eq_ignore_ascii_case(rhs)),
        _ => {
            let (Some(a), Some(b)) = (version_key(lhs), version_key(rhs)) else {
                return Err(format!("cannot order {lhs:?} and {rhs:?}"));
            };
            Ok(match op {
                "<" => a < b,
                ">" => a > b,
                "<=" => a <= b,
                _ => a >= b,
            })
        }
    }
}

fn version_key(value: &str) -> Option<Vec<u64>> {
    let value = value.trim().trim_start_matches(['v', 'V']);
    if value.is_empty() {
        return None;
    }
    value
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

// ---------------------------------------------------------------------------
// The MSBuild evaluation tier
// ---------------------------------------------------------------------------

/// Parse `msbuild -getItem:ClCompile` JSON (MSBuild 17.8+) into sources. Items
/// excluded from the build are left out.
pub(crate) fn sources_from_msbuild_json(
    json: &str,
    project_dir: &Path,
) -> Option<Vec<ImportedSource>> {
    let start = json.find('{')?;
    let value: serde_json::Value = serde_json::from_str(&json[start..]).ok()?;
    let items = value.pointer("/Items/ClCompile")?.as_array()?;
    let mut sources = Vec::new();
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let metadata: BTreeMap<String, String> = object
            .iter()
            .filter_map(|(key, value)| {
                value
                    .as_str()
                    .map(|v| (key.to_ascii_lowercase(), v.to_owned()))
            })
            .collect();
        if metadata_true(metadata.get("excludedfrombuild")) {
            continue;
        }
        let full_path = metadata
            .get("fullpath")
            .or_else(|| metadata.get("identity"))
            .cloned()
            .unwrap_or_default();
        if full_path.is_empty() {
            continue;
        }
        let mut source = ImportedSource {
            file: resolve_path(project_dir, &full_path),
            directory: project_dir.to_path_buf(),
            ..ImportedSource::default()
        };
        source_settings(&mut source, &metadata, project_dir);
        sources.push(source);
    }
    Some(sources)
}

/// MSBuild found on PATH (after Visual Studio environment discovery), if any.
pub(crate) fn msbuild_program() -> Option<PathBuf> {
    ["MSBuild.exe", "msbuild.exe", "msbuild"]
        .iter()
        .find_map(|name| which::which(name).ok())
}

/// Evaluate `project` with MSBuild for `configuration|platform` and read its
/// `ClCompile` items. `None` when MSBuild is missing, fails, or prints no
/// items (an MSBuild older than 17.8 has no `-getItem`).
pub(crate) fn evaluate_with_msbuild(
    msbuild: &Path,
    project: &Path,
    solution: Option<&Path>,
    configuration: &str,
    platform: &str,
) -> Option<Vec<ImportedSource>> {
    let project_dir = project.parent()?.to_path_buf();
    let mut command = std::process::Command::new(msbuild);
    command
        .arg(project)
        .arg("-nologo")
        .arg(format!("-p:Configuration={configuration}"))
        .arg(format!("-p:Platform={platform}"))
        .arg("-getItem:ClCompile")
        .env("MSBUILDDISABLENODEREUSE", "1")
        .stdin(std::process::Stdio::null());
    if let Some(dir) = solution.and_then(Path::parent) {
        let mut dir = dir.display().to_string();
        if !dir.ends_with('\\') && !dir.ends_with('/') {
            dir.push(std::path::MAIN_SEPARATOR);
        }
        command.arg(format!("-p:SolutionDir={dir}"));
    }
    if let Some(solution) = solution {
        command.arg(format!("-p:SolutionPath={}", solution.display()));
    }
    let output = crate::command_output::output_with_timeout(
        &mut command,
        std::time::Duration::from_secs(180),
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    sources_from_msbuild_json(&String::from_utf8_lossy(&output.stdout), &project_dir)
}

// ---------------------------------------------------------------------------
// A small XML reader (MSBuild files are plain XML: elements, attributes, text,
// comments, CDATA and the five predefined entities).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct XmlElement {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<XmlNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XmlNode {
    Element(XmlElement),
    Text(String),
}

impl XmlElement {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn elements(&self) -> impl Iterator<Item = &XmlElement> {
        self.children.iter().filter_map(|child| match child {
            XmlNode::Element(element) => Some(element),
            XmlNode::Text(_) => None,
        })
    }

    pub fn text(&self) -> String {
        let mut out = String::new();
        for child in &self.children {
            if let XmlNode::Text(text) = child {
                out.push_str(text);
            }
        }
        out.trim().to_owned()
    }

    pub fn walk(&self, visit: &mut dyn FnMut(&XmlElement)) {
        visit(self);
        for child in self.elements() {
            child.walk(visit);
        }
    }
}

/// The deepest element nesting the reader accepts. MSBuild files nest a
/// handful of levels.
const MAX_XML_DEPTH: usize = 256;

pub(crate) fn parse_xml(text: &str) -> Result<XmlElement, String> {
    let text = text.trim_start_matches('\u{feff}');
    let mut parser = XmlParser { text, pos: 0 };
    let mut stack: Vec<XmlElement> = vec![XmlElement::default()];
    while parser.pos < text.len() {
        let rest = &text[parser.pos..];
        if let Some(after) = rest.strip_prefix("<!--") {
            let end = after.find("-->").ok_or("unterminated comment")?;
            parser.pos += 4 + end + 3;
        } else if let Some(after) = rest.strip_prefix("<![CDATA[") {
            let end = after.find("]]>").ok_or("unterminated CDATA")?;
            if let Some(top) = stack.last_mut() {
                top.children.push(XmlNode::Text(after[..end].to_owned()));
            }
            parser.pos += 9 + end + 3;
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            let end = rest.find('>').ok_or("unterminated declaration")?;
            parser.pos += end + 1;
        } else if let Some(after) = rest.strip_prefix("</") {
            let end = after.find('>').ok_or("unterminated end tag")?;
            let name = local_name(after[..end].trim());
            parser.pos += 2 + end + 1;
            let element = stack.pop().ok_or("unbalanced end tag")?;
            if element.name != name {
                return Err(format!("</{name}> closes <{}>", element.name));
            }
            stack
                .last_mut()
                .ok_or("end tag without a parent")?
                .children
                .push(XmlNode::Element(element));
        } else if rest.starts_with('<') {
            let (element, self_closing) = parser.start_tag()?;
            if self_closing {
                stack
                    .last_mut()
                    .ok_or("element without a parent")?
                    .children
                    .push(XmlNode::Element(element));
            } else {
                // The tree is walked, cloned and dropped recursively; a bound
                // on its depth keeps a hostile file from overflowing the stack.
                if stack.len() > MAX_XML_DEPTH {
                    return Err(format!("elements nest deeper than {MAX_XML_DEPTH} levels"));
                }
                stack.push(element);
            }
        } else {
            let end = rest.find('<').unwrap_or(rest.len());
            let raw = &rest[..end];
            if !raw.trim().is_empty() {
                if let Some(top) = stack.last_mut() {
                    top.children.push(XmlNode::Text(decode_entities(raw)));
                }
            }
            parser.pos += end;
        }
    }
    if stack.len() != 1 {
        return Err("unclosed element".to_owned());
    }
    let document = stack.pop().unwrap_or_default();
    document
        .children
        .into_iter()
        .find_map(|child| match child {
            XmlNode::Element(element) => Some(element),
            XmlNode::Text(_) => None,
        })
        .ok_or_else(|| "no root element".to_owned())
}

struct XmlParser<'t> {
    text: &'t str,
    pos: usize,
}

impl XmlParser<'_> {
    fn start_tag(&mut self) -> Result<(XmlElement, bool), String> {
        let bytes = self.text.as_bytes();
        let mut index = self.pos + 1;
        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b'>'
            && bytes[index] != b'/'
        {
            index += 1;
        }
        let mut element = XmlElement {
            name: local_name(&self.text[name_start..index]),
            ..XmlElement::default()
        };
        loop {
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            match bytes.get(index) {
                None => return Err("unterminated start tag".to_owned()),
                Some(b'>') => {
                    self.pos = index + 1;
                    return Ok((element, false));
                }
                Some(b'/') if bytes.get(index + 1) == Some(&b'>') => {
                    self.pos = index + 2;
                    return Ok((element, true));
                }
                _ => {}
            }
            let key_start = index;
            while index < bytes.len()
                && bytes[index] != b'='
                && !bytes[index].is_ascii_whitespace()
                && bytes[index] != b'>'
            {
                index += 1;
            }
            let key = local_name(&self.text[key_start..index]);
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if bytes.get(index) != Some(&b'=') {
                return Err(format!("attribute {key} has no value"));
            }
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            let quote = *bytes.get(index).ok_or("attribute value missing")?;
            if quote != b'"' && quote != b'\'' {
                return Err(format!("attribute {key} is not quoted"));
            }
            let value_start = index + 1;
            let value_end = self.text[value_start..]
                .find(quote as char)
                .map(|offset| value_start + offset)
                .ok_or("unterminated attribute value")?;
            element
                .attrs
                .push((key, decode_entities(&self.text[value_start..value_end])));
            index = value_end + 1;
        }
    }
}

fn local_name(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_owned()
}

fn decode_entities(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let Some(semi) = after.find(';').filter(|semi| *semi <= 10) else {
            out.push('&');
            rest = after;
            continue;
        };
        let entity = &after[..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32)
                // NUL marks unresolved references in expanded values.
                .filter(|ch| *ch != '\0'),
        };
        match decoded {
            Some(ch) => {
                out.push(ch);
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/windows/vs_solution")
            .canonicalize()
            .expect("fixture")
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn xml_reader_handles_attributes_entities_comments_and_cdata() {
        let root = parse_xml(
            "\u{feff}<?xml version=\"1.0\"?>\n<!-- c --><Project a='1' b=\"x &amp; y\">\
             <A Condition=\"'$(X)'=='&quot;q&quot;'\">t&lt;1</A><B/><![CDATA[raw <x>]]></Project>",
        )
        .unwrap();
        assert_eq!(root.name, "Project");
        assert_eq!(root.attr("A"), Some("1"));
        assert_eq!(root.attr("b"), Some("x & y"));
        let a = root.elements().next().unwrap();
        assert_eq!(a.attr("Condition"), Some("'$(X)'=='\"q\"'"));
        assert_eq!(a.text(), "t<1");
        assert_eq!(root.elements().count(), 2);
        assert_eq!(root.text(), "raw <x>");
        assert!(parse_xml("<A><B></A>").is_err());
    }

    #[test]
    fn conditions_compare_configurations_and_test_existence() {
        let props: BTreeMap<&str, &str> = [
            ("$(Configuration)", "Debug"),
            ("$(Platform)", "x64"),
            ("$(Ver)", "17.4"),
        ]
        .into_iter()
        .collect();
        let mut expand = |text: &str| {
            let mut out = text.to_owned();
            for (key, value) in &props {
                out = out.replace(key, value);
            }
            out.replace("$(Missing)", "")
        };
        let base = Path::new("/");
        let mut check = |condition: &str| evaluate_condition(condition, base, &mut expand).unwrap();
        assert!(check("'$(Configuration)|$(Platform)'=='Debug|x64'"));
        assert!(check("'$(Configuration)|$(Platform)' == 'debug|X64'"));
        assert!(!check("'$(Configuration)|$(Platform)'=='Release|x64'"));
        assert!(check("'$(Missing)' == ''"));
        assert!(check(
            "'$(Configuration)' != 'Release' and ('$(Platform)'=='x64' or false)"
        ));
        assert!(!check("!('$(Platform)'=='x64')"));
        assert!(check("'$(Ver)' >= '16.0'"));
        assert!(check("$(Configuration) == Debug"));
        assert!(!check("exists('/no/such/bhf/file')"));
        assert!(check("!Exists('/no/such/bhf/file')"));
        assert!(check("HasTrailingSlash('C:/x/')"));
        assert!(
            evaluate_condition("$([System.DateTime]::Now) == 'x' oops", base, &mut expand).is_err()
        );
    }

    #[test]
    fn solution_lists_projects_configurations_and_mappings() {
        let solution = parse_solution(&fixture().join("vs/Widget.sln"));
        assert_eq!(
            solution.configurations,
            vec!["Debug|x64".to_owned(), "Release|x64".to_owned()]
        );
        assert_eq!(solution.projects.len(), 1);
        assert_eq!(
            solution.projects[0].path,
            normalize_lexically(&fixture().join("src/core/WidgetCore.vcxproj"))
        );
        assert_eq!(
            solution.projects[0]
                .mapping
                .get("Release|x64")
                .map(String::as_str),
            Some("Release|x64")
        );
        // CRLF line endings and a .slnx solution read the same way.
        let temp = tempfile::tempdir().unwrap();
        let crlf = fs::read_to_string(fixture().join("vs/Widget.sln"))
            .unwrap()
            .replace('\n', "\r\n");
        fs::write(temp.path().join("w.sln"), crlf).unwrap();
        assert_eq!(
            parse_solution(&temp.path().join("w.sln"))
                .configurations
                .len(),
            2
        );
        fs::write(
            temp.path().join("w.slnx"),
            "<Solution><Configurations><BuildType Name=\"Debug\" /><BuildType Name=\"Release\" />\
             <Platform Name=\"x64\" /></Configurations><Folder Name=\"/lib/\">\
             <Project Path=\"lib\\core.vcxproj\" /></Folder></Solution>",
        )
        .unwrap();
        let slnx = parse_solution(&temp.path().join("w.slnx"));
        assert_eq!(slnx.configurations, vec!["Debug|x64", "Release|x64"]);
        assert_eq!(
            slnx.projects[0].path,
            normalize_lexically(&temp.path().join("lib/core.vcxproj"))
        );
    }

    #[test]
    fn configuration_choice_is_requested_then_first_x64_then_first() {
        let listed = vec!["Debug|Win32".to_owned(), "Release|x64".to_owned()];
        assert_eq!(
            choose_configuration(&listed, None),
            ("Release".into(), "x64".into())
        );
        assert_eq!(
            choose_configuration(&listed, Some("Debug|Win32")),
            ("Debug".into(), "Win32".into())
        );
        assert_eq!(
            choose_configuration(&["Debug|ARM64".to_owned()], None),
            ("Debug".into(), "ARM64".into())
        );
        assert_eq!(
            choose_configuration(&[], None),
            ("Debug".into(), "x64".into())
        );
    }

    /// The solution directory is the solution's (not the project's), property
    /// sheets are followed, `Condition=` selects ONE configuration's settings,
    /// the character set becomes its defines, and an item excluded from the
    /// build is left out.
    #[test]
    fn static_import_evaluates_the_selected_configuration() {
        let root = fixture();
        let import = import_tree(&root, &ImportRequest::default()).expect("import");
        assert_eq!(
            import.solution.as_deref(),
            Some(root.join("vs/Widget.sln").as_path())
        );
        assert_eq!(
            (import.configuration.as_str(), import.platform.as_str()),
            ("Debug", "x64")
        );
        assert_eq!(import.source_count(), 2, "{import:?}");
        let files: Vec<&PathBuf> = import.projects[0].sources.iter().map(|s| &s.file).collect();
        assert_eq!(
            files,
            vec![
                &normalize_lexically(&root.join("src/core/widget.c")),
                &normalize_lexically(&root.join("src/core/mode.c")),
            ],
            "the item excluded from the build is left out"
        );
        let source = &import.projects[0].sources[0];
        assert_eq!(
            source.include_dirs,
            vec![
                normalize_lexically(&root.join("include")),
                normalize_lexically(&root.join("include/gen")),
            ]
        );
        for define in [
            "_DEBUG",
            "WIDGET_MODE=1",
            "WIDGET_HAVE_TABLES=1",
            "_UNICODE",
            "UNICODE",
        ] {
            assert!(
                source.defines.iter().any(|d| d == define),
                "{define}: {:?}",
                source.defines
            );
        }
        assert!(!source
            .defines
            .iter()
            .any(|d| d == "NDEBUG" || d == "WIDGET_MODE=2"));
        assert_eq!(source.standard.as_deref(), Some("c11"));

        let release = import_tree(
            &root,
            &ImportRequest {
                solution: None,
                configuration: Some("Release|x64".to_owned()),
            },
        )
        .unwrap();
        let source = &release.projects[0].sources[0];
        assert!(source.defines.iter().any(|d| d == "WIDGET_MODE=2"));
        assert!(source.defines.iter().any(|d| d == "NDEBUG"));
        assert!(!source
            .defines
            .iter()
            .any(|d| d == "_DEBUG" || d == "WIDGET_MODE=1"));
    }

    #[test]
    fn unresolved_macros_are_named_and_environment_macros_resolve() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        fs::write(dir.join("a.c"), "int a;\n").unwrap();
        fs::write(dir.join("b.cpp"), "int b;\n").unwrap();
        fs::write(
            dir.join("p.vcxproj"),
            r#"<Project>
  <PropertyGroup><LocalInc>$(ProjectDir)local</LocalInc></PropertyGroup>
  <ItemDefinitionGroup>
    <ClCompile>
      <AdditionalIncludeDirectories>$(WIDGET_SDK)\include;$(VC_IncludePath);$(NoSuchProp)\x;$(LocalInc);%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PreprocessorDefinitions>CACHE=$(IntDir);VALUE=$(WIDGET_SDK);%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ForcedIncludeFiles>pre.h</ForcedIncludeFiles>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <AdditionalOptions>/utf-8 /DFROM_OPTIONS=1 /Zc:wchar_t- %(AdditionalOptions)</AdditionalOptions>
    </ClCompile>
    <Link><AdditionalDependencies>ws2_32.lib;$(OutDir)core.lib;%(AdditionalDependencies)</AdditionalDependencies></Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="a.c;b.cpp" />
    <ClCompile Include="b.cpp"><PreprocessorDefinitions>ONLY_B;%(PreprocessorDefinitions)</PreprocessorDefinitions></ClCompile>
  </ItemGroup>
</Project>"#,
        )
        .unwrap();
        let env = |name: &str| (name == "WIDGET_SDK").then(|| "C:/sdk".to_owned());
        let project = evaluate_project(&dir.join("p.vcxproj"), None, "Debug", "x64", &env);
        assert_eq!(project.sources.len(), 3);
        let a = &project.sources[0];
        assert_eq!(
            a.include_dirs,
            vec![
                PathBuf::from("C:/sdk/include"),
                normalize_lexically(&dir.join("local"))
            ]
        );
        assert!(a.defines.iter().any(|d| d == "VALUE=C:/sdk"));
        assert!(
            a.defines.iter().any(|d| d.starts_with("CACHE=x64/Debug")),
            "IntDir has its default: {:?}",
            a.defines
        );
        assert_eq!(
            a.forced_includes,
            vec![normalize_lexically(&dir.join("pre.h"))]
        );
        assert_eq!(a.standard, None, "LanguageStandard is the C++ standard");
        assert!(
            a.extra_flags.iter().any(|f| f == "-DFROM_OPTIONS=1"),
            "{:?}",
            a.extra_flags
        );
        assert!(
            a.extra_flags.iter().any(|f| f == "-fno-wchar"),
            "{:?}",
            a.extra_flags
        );
        assert!(
            !a.extra_flags.iter().any(|f| f.contains("utf-8")),
            "{:?}",
            a.extra_flags
        );
        assert_eq!(project.sources[1].standard.as_deref(), Some("c++17"));
        assert!(project.sources[2].defines.iter().any(|d| d == "ONLY_B"));
        assert!(
            project.unresolved.contains("$(NoSuchProp)"),
            "{:?}",
            project.unresolved
        );
        assert!(
            !project
                .unresolved
                .iter()
                .any(|name| name.contains("VC_IncludePath")),
            "toolset include macros are the compiler's own and need no warning"
        );
        assert_eq!(project.link_inputs[0], "ws2_32.lib");
        assert!(
            project.link_inputs[1].ends_with("x64/Debug/core.lib"),
            "{:?}",
            project.link_inputs
        );

        let without_env = evaluate_project(&dir.join("p.vcxproj"), None, "Debug", "x64", &no_env);
        assert!(without_env.unresolved.contains("$(WIDGET_SDK)"));
        assert_eq!(
            without_env.sources[0].include_dirs,
            vec![normalize_lexically(&dir.join("local"))],
            "a dir built on an unresolved macro is left out, not rooted at the drive"
        );
    }

    #[test]
    fn backslash_paths_resolve_on_every_host() {
        assert_eq!(
            resolve_path(Path::new("/proj/src/core"), "..\\..\\include\\"),
            PathBuf::from("/proj/include")
        );
        assert_eq!(
            resolve_path(Path::new("/proj"), "C:\\sdk\\\\include"),
            PathBuf::from("C:/sdk/include")
        );
        assert_eq!(
            normalize_lexically(Path::new("/a/b/../../../c")),
            PathBuf::from("/c")
        );
        assert_eq!(
            normalize_lexically(Path::new("\\\\?\\C:\\src\\vs\\..\\core\\w.vcxproj")),
            PathBuf::from("C:/src/core/w.vcxproj"),
            "a canonicalized (verbatim) Windows path"
        );
        assert_eq!(
            normalize_lexically(Path::new("\\\\server\\share\\a\\..\\b.sln")),
            PathBuf::from("//server/share/b.sln"),
            "a UNC path keeps its leading separators"
        );
        assert_eq!(
            normalize_lexically(Path::new("\\\\?\\UNC\\server\\share\\b.sln")),
            PathBuf::from("//server/share/b.sln")
        );
    }

    #[test]
    fn several_solutions_are_ordered_shallowest_first() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("build/vs2019")).unwrap();
        fs::create_dir_all(root.join("ide")).unwrap();
        fs::write(root.join("build/vs2019/b.sln"), "").unwrap();
        fs::write(root.join("ide/z.sln"), "").unwrap();
        fs::write(root.join("ide/a.slnx"), "<Solution/>").unwrap();
        let found = find_solutions(root);
        assert_eq!(
            found,
            vec![
                root.join("ide/a.slnx"),
                root.join("ide/z.sln"),
                root.join("build/vs2019/b.sln"),
            ]
        );
    }

    #[test]
    fn wildcards_match_in_linear_time_on_star_heavy_patterns() {
        assert!(wildcard_matches("*.c", "widget.c"));
        assert!(wildcard_matches("w?dget.C", "widget.c"), "case-insensitive");
        assert!(wildcard_matches("a*b*c", "aXXbYYc"));
        assert!(wildcard_matches("*", ""));
        assert!(wildcard_matches("**", "x.c"));
        assert!(!wildcard_matches("a*", "b"));
        assert!(!wildcard_matches("*.c", "widget.cc"));
        assert!(wildcard_matches("*a*b", "aab"));

        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src").join(format!("{}.c", "a".repeat(60))), "").unwrap();
        fs::write(
            dir.join("w.vcxproj"),
            r#"<Project><ItemGroup><ClCompile Include="src\*a*a*a*a*a*a*a*a*a*a*a*a*b.c" /></ItemGroup></Project>"#,
        )
        .unwrap();
        let started = std::time::Instant::now();
        let project = evaluate_project(&dir.join("w.vcxproj"), None, "Debug", "x64", &no_env);
        assert!(project.sources.is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn deeply_nested_project_xml_is_refused_with_a_note() {
        let depth = 300_000;
        let text = format!(
            "<Project><PropertyGroup>{}{}</PropertyGroup></Project>",
            "<a>".repeat(depth),
            "</a>".repeat(depth)
        );
        let error = parse_xml(&text).unwrap_err();
        assert!(error.contains("nest"), "{error}");
        assert!(parse_xml(&format!(
            "<P>{}{}</P>",
            "<a>".repeat(200),
            "</a>".repeat(200)
        ))
        .is_ok());

        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("widget.vcxproj"), &text).unwrap();
        let project = evaluate_project(
            &temp.path().join("widget.vcxproj"),
            None,
            "Debug",
            "x64",
            &no_env,
        );
        assert!(
            project
                .notes
                .iter()
                .any(|note| note.contains("could not parse")),
            "{:?}",
            project.notes
        );
    }

    #[test]
    fn property_expansion_is_capped_per_value_and_per_project() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        fs::write(dir.join("a.c"), "int a;\n").unwrap();
        // Each property doubles the one before: 16 bytes * 2^33 if unbounded.
        let mut doubling = String::from("<P0>aaaaaaaaaaaaaaaa</P0>");
        for i in 1..34 {
            doubling.push_str(&format!("<P{i}>$(P{prev})$(P{prev})</P{i}>", prev = i - 1));
        }
        fs::write(
            dir.join("double.vcxproj"),
            format!(
                "<Project><PropertyGroup>{doubling}</PropertyGroup><ItemDefinitionGroup><ClCompile>\
                 <PreprocessorDefinitions>BIG=$(P33);SMALL=$(P2)</PreprocessorDefinitions>\
                 </ClCompile></ItemDefinitionGroup><ItemGroup><ClCompile Include=\"a.c\" />\
                 </ItemGroup></Project>"
            ),
        )
        .unwrap();
        let started = std::time::Instant::now();
        let project = evaluate_project(&dir.join("double.vcxproj"), None, "Debug", "x64", &no_env);
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
        assert_eq!(project.sources.len(), 1);
        let defines = &project.sources[0].defines;
        assert!(
            defines
                .iter()
                .any(|d| d == &format!("SMALL={}", "a".repeat(64))),
            "{defines:?}"
        );
        assert!(
            !defines.iter().any(|d| d.starts_with("BIG")),
            "an over-long value is unresolved and its piece left out"
        );
        assert!(
            project
                .notes
                .iter()
                .any(|note| note.contains("longer than")),
            "{:?}",
            project.notes
        );

        // Many properties each copying one large value exhaust the project's
        // expansion budget instead of memory.
        let mut copies = String::from("<P0>aaaaaaaaaaaaaaaa</P0>");
        for i in 1..14 {
            copies.push_str(&format!("<P{i}>$(P{prev})$(P{prev})</P{i}>", prev = i - 1));
        }
        for i in 0..800 {
            copies.push_str(&format!("<R{i}>$(P13)</R{i}>"));
        }
        fs::write(
            dir.join("copies.vcxproj"),
            format!(
                "<Project><PropertyGroup>{copies}</PropertyGroup><ItemGroup>\
                 <ClCompile Include=\"a.c\" /></ItemGroup></Project>"
            ),
        )
        .unwrap();
        let project = evaluate_project(&dir.join("copies.vcxproj"), None, "Debug", "x64", &no_env);
        assert!(
            project.notes.iter().any(|note| note.contains("budget")),
            "{:?}",
            project.notes
        );
    }

    #[test]
    fn msbuild_item_json_becomes_sources() {
        let json = r#"
        {
          "Items": {
            "ClCompile": [
              {
                "Identity": "widget.c",
                "FullPath": "C:\\proj\\src\\core\\widget.c",
                "AdditionalIncludeDirectories": "C:\\proj\\vs\\\\..\\include;C:\\proj\\include\\gen;",
                "PreprocessorDefinitions": "_DEBUG;WIDGET_MODE=1;_UNICODE;UNICODE;",
                "LanguageStandard_C": "stdc11",
                "ExcludedFromBuild": ""
              },
              { "Identity": "legacy.c", "FullPath": "C:\\proj\\legacy.c", "ExcludedFromBuild": "true" }
            ]
          }
        }"#;
        let sources = sources_from_msbuild_json(json, Path::new("C:/proj/src/core")).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].file, PathBuf::from("C:/proj/src/core/widget.c"));
        assert_eq!(
            sources[0].include_dirs,
            vec![
                PathBuf::from("C:/proj/include"),
                PathBuf::from("C:/proj/include/gen")
            ]
        );
        assert_eq!(
            sources[0].defines,
            vec!["_DEBUG", "WIDGET_MODE=1", "_UNICODE", "UNICODE"]
        );
        assert_eq!(sources[0].standard.as_deref(), Some("c11"));
        assert!(sources_from_msbuild_json("MSBuild version 16", Path::new("/")).is_none());
    }
}
