// SPDX-License-Identifier: Apache-2.0

//! The Ada lane.
//!
//! An Ada harness (`main.adb`, or a `<parent>-bhf_harness.adb` child) is built
//! by gprbuild from `build/<id>/bhf_build.gpr`, the project bhf generates: it
//! extends the operator's own project when there is one, takes the
//! instrumented copy of the sources (`src_instrumented/`), the generated
//! harness and the stub packages bhf synthesized as source dirs, `with`s
//! `adafuzz_runtime.gpr` (bhf's Ada runtime, copied into the build dir) and
//! the operator's dependencies, and records the target, runtime and compiler
//! switches the harness was built with. A capsule ships all of it: each source
//! dir, the build dir's project files and runtime sources, and the scanned
//! tree when the generated project extends or `with`s a project in it. A
//! project file it names outside the scanned tree (other than one gprbuild
//! finds on its own project path, like an installed library) cannot ship, so
//! the harness is refused with the path. A harness built for another target is
//! refused too: a capsule rebuilds for this host.
//!
//! `build.sh` rebuilds with `gprbuild -p` in a clean `build/`. The PoC reads its
//! input on stdin and writes what it raised to the event log in
//! `$BHF_EVENTS_PATH` (the protocol the shared detector reads off the GNAT
//! binary), and the crash oracle is the unhandled exception recorded there, or
//! a sanitizer report when the harness was built with one.

use super::relocate::{self, Contents, Mount, Relocator};
use super::{
    refuse, CapsulePlan, HarnessContext, Lane, ReplayOutput, Tool, Toolchain, CARTOGRAPHY_GAP,
};
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) struct AdaLane;

pub(crate) static ADA_LANE: AdaLane = AdaLane;

const ADA_TOOLS: &[Toolchain] = &[
    Toolchain::new(
        "GPRBUILD",
        "gprbuild",
        "builds the harness project (GNAT's project builder)",
    ),
    Toolchain::new("GNAT", "gnat", "the GNAT Ada compiler gprbuild runs"),
];

/// The project bhf generates for an Ada harness.
const BUILD_PROJECT: &str = "bhf_build.gpr";

/// What `bhf_build.gpr` says.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BuildProject {
    pub(crate) withs: Vec<String>,
    pub(crate) extends: Option<String>,
    pub(crate) source_dirs: Vec<String>,
    pub(crate) object_dir: Option<String>,
    pub(crate) exec_dir: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) runtime: Option<String>,
    pub(crate) switches: Vec<String>,
    pub(crate) executable: Option<String>,
}

/// The quoted strings of `text`, in order.
fn quoted(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        out.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    out
}

/// Read the attributes of a generated `bhf_build.gpr`.
pub(crate) fn parse_build_project(text: &str) -> BuildProject {
    let mut project = BuildProject::default();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("--") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("with ") {
            project.withs.extend(quoted(rest));
        } else if trimmed.starts_with("project ") && trimmed.contains(" extends ") {
            project.extends = quoted(trimmed).into_iter().next();
        } else if let Some(rest) = trimmed.strip_prefix("for ") {
            let values = quoted(rest);
            if rest.starts_with("Source_Dirs ") {
                project.source_dirs = values;
            } else if rest.starts_with("Object_Dir ") {
                project.object_dir = values.into_iter().next();
            } else if rest.starts_with("Exec_Dir ") {
                project.exec_dir = values.into_iter().next();
            } else if rest.starts_with("Target ") {
                project.target = values.into_iter().next();
            } else if rest.starts_with("Runtime ") {
                project.runtime = values.into_iter().nth(1);
            } else if rest.starts_with("Default_Switches (\"Ada\")") {
                project.switches = values.into_iter().skip(1).collect();
            } else if rest.starts_with("Executable ") {
                project.executable = values.into_iter().nth(1);
            }
        }
    }
    project
}

impl AdaLane {
    fn build_dir(harness: &HarnessContext) -> PathBuf {
        harness.work_dir.join("build").join(&harness.harness_id)
    }

    fn read_project(harness: &HarnessContext) -> Result<(PathBuf, BuildProject), String> {
        let build_dir = Self::build_dir(harness);
        let path = build_dir.join(BUILD_PROJECT);
        let text = std::fs::read_to_string(&path).map_err(|_| {
            format!(
                "{} does not exist, so the harness was never built; build it with `bhf build \
                 {} --harness {}`",
                path.display(),
                harness.work_dir.display(),
                harness.harness_id
            )
        })?;
        Ok((build_dir, parse_build_project(&text)))
    }

    /// Why the generated project cannot rebuild here, if it cannot: a foreign
    /// target, or a project file it names outside the scanned tree.
    fn project_problem(
        harness: &HarnessContext,
        build_dir: &Path,
        project: &BuildProject,
    ) -> Option<String> {
        if let Some(target) = &project.target {
            if !is_native_target(target) {
                return Some(format!(
                    "it was built for the target {target}, and a capsule rebuilds for this host"
                ));
            }
        }
        let tree = super::recorded_source_root(&harness.work_dir);
        let named = project
            .extends
            .iter()
            .map(|path| ("extends", path))
            .chain(project.withs.iter().map(|path| ("withs", path)));
        for (how, name) in named {
            let Some(path) = project_file(build_dir, name) else {
                continue;
            };
            if path.starts_with(build_dir) {
                continue;
            }
            if !tree.as_ref().is_some_and(|tree| path.starts_with(tree)) {
                return Some(format!(
                    "its project {how} {}, which is outside the scanned tree{}, so a capsule \
                     cannot ship it",
                    path.display(),
                    tree.as_ref()
                        .map(|tree| format!(" {}", tree.display()))
                        .unwrap_or_default()
                ));
            }
        }
        None
    }
}

/// The project file a `with`/`extends` names, resolved against the build dir,
/// when it names one by path (`"/x/y.gpr"`, `"../y.gpr"`) and it exists; `None`
/// for one gprbuild finds on its project path (`"gnatcoll"`).
fn project_file(build_dir: &Path, name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let beside = build_dir.join(path);
        let with_ext = if beside.extension().is_none() {
            beside.with_extension("gpr")
        } else {
            beside.clone()
        };
        if !name.contains('/') && !beside.is_file() && !with_ext.is_file() {
            return None;
        }
        if with_ext.is_file() {
            with_ext
        } else {
            beside
        }
    };
    let resolved = super::normalize(&resolved);
    resolved.is_file().then_some(resolved)
}

/// Whether a GPR `Target` names this host (`x86_64-linux-gnu` on an x86_64
/// Linux host, `native`).
fn is_native_target(target: &str) -> bool {
    if target == "native" {
        return true;
    }
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    target.starts_with(arch) && target.contains(os)
}

impl Lane for AdaLane {
    fn tag(&self) -> &'static str {
        "ada"
    }

    fn name(&self) -> &'static str {
        "Ada"
    }

    fn tools(&self) -> &'static [Toolchain] {
        ADA_TOOLS
    }

    fn recognizes(&self, harness_dir: &Path) -> bool {
        harness_dir.join("main.adb").is_file()
            || std::fs::read_dir(harness_dir)
                .into_iter()
                .flatten()
                .flatten()
                .any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .ends_with("-bhf_harness.adb")
                })
    }

    fn harness_problem(&self, harness: &HarnessContext) -> Option<String> {
        let (build_dir, project) = match Self::read_project(harness) {
            Ok(read) => read,
            Err(problem) => return Some(problem),
        };
        if project.source_dirs.is_empty() {
            return Some(format!(
                "{} names no source dirs",
                build_dir.join(BUILD_PROJECT).display()
            ));
        }
        Self::project_problem(harness, &build_dir, &project)
    }

    fn plan_capsule(&self, harness: &HarnessContext) -> anyhow::Result<CapsulePlan> {
        let (build_dir, project) = Self::read_project(harness).map_err(refuse)?;
        if let Some(problem) = Self::project_problem(harness, &build_dir, &project) {
            return Err(refuse(problem));
        }
        let tree = super::recorded_source_root(&harness.work_dir);
        let work = &harness.work_dir;
        let mut mounts = vec![Mount::rendered(
            &build_dir,
            "ada/build",
            Contents::Tree {
                skip: build_dir_output,
            },
        )];
        let mut source_dirs = Vec::new();
        for (index, dir) in project.source_dirs.iter().enumerate() {
            let dir = PathBuf::from(dir);
            if dir.starts_with(&build_dir) || !dir.is_dir() {
                continue;
            }
            let is_harness = dir.starts_with(work.join("generated_harnesses"))
                || dir.starts_with(work.join("harnesses"))
                    && !dir.ends_with(crate::auto::repair::AUTO_ADA_STUBS_DIR);
            let to = if dir == work.join("src_instrumented") {
                "ada/src_instrumented".to_owned()
            } else if is_harness {
                "ada/harness".to_owned()
            } else if dir.ends_with(crate::auto::repair::AUTO_ADA_STUBS_DIR) {
                "ada/stubs".to_owned()
            } else {
                format!("ada/src_{index}")
            };
            let to = if mounts
                .iter()
                .any(|mount| mount.ship_to.as_deref() == Some(to.as_str()))
            {
                format!("ada/src_{index}")
            } else {
                to
            };
            mounts.push(Mount::in_place(
                &dir,
                &to,
                Contents::Tree {
                    skip: if is_harness {
                        ada_harness_noise
                    } else {
                        ada_source_noise
                    },
                },
            ));
            source_dirs.push(to);
        }
        if let Some(object_dir) = &project.object_dir {
            let object_dir = PathBuf::from(object_dir);
            if object_dir.is_absolute() && !object_dir.starts_with(&build_dir) {
                mounts.push(Mount::output(object_dir, "build/ada/obj"));
            }
        }
        // The operator's projects the generated one extends or withs live in
        // the scanned tree, with the sources they name.
        let names_tree = project
            .extends
            .iter()
            .chain(&project.withs)
            .filter_map(|name| project_file(&build_dir, name))
            .any(|path| !path.starts_with(&build_dir));
        if names_tree {
            if let Some(tree) = &tree {
                mounts.push(Mount::in_place(
                    tree,
                    "sources",
                    Contents::Tree {
                        skip: relocate::is_tree_noise,
                    },
                ));
            }
        }
        let mut protected = vec![work.clone()];
        protected.extend(tree.iter().cloned());
        let relocator = Relocator {
            mounts,
            tools: Vec::new(),
            protected,
            exclude: vec![work.clone()],
        };
        let relocated = relocator.relocate()?;
        let executable = project.executable.as_deref().unwrap_or("main");
        let exec_dir = project
            .exec_dir
            .as_deref()
            .map(Path::new)
            .and_then(|dir| relocator.build_path(dir))
            .unwrap_or_else(|| "build/ada/build".to_owned());
        let mut script = String::from(
            "#!/bin/sh\n\
             # Rebuild this bhf PoC offline. Needs only GNAT with gprbuild (or $GPRBUILD)\n\
             # and a shell.\n\
             set -e\n\
             cd \"$(dirname \"$0\")\"\n",
        );
        script.push_str(&relocate::resolve_tool("TOOL_GPRBUILD", &ADA_TOOLS[0]));
        script.push_str(&relocator.render_script(&relocated));
        script.push_str(&format!(
            "GPR_PROJECT_PATH=\"$here/build/ada/build${{GPR_PROJECT_PATH:+:$GPR_PROJECT_PATH}}\" \\\n\
             \x20 \"$TOOL_GPRBUILD\" -p -q -P build/ada/build/{BUILD_PROJECT}\n\
             cp {exe} poc\n\
             chmod +x poc\n",
            exe = super::sh_word(&format!("{exec_dir}/{executable}")),
        ));
        let requires: Vec<_> = ADA_TOOLS.iter().map(Toolchain::requirement).collect();
        let system_projects: Vec<&String> = project
            .withs
            .iter()
            .filter(|name| project_file(&build_dir, name).is_none())
            .collect();
        let mut layout = vec![
            (
                format!("ada/build/{BUILD_PROJECT}"),
                "the project bhf generated (relocated by build.sh into build/)".to_owned(),
            ),
            (
                "ada/build/adafuzz_runtime.gpr".to_owned(),
                "bhf's Ada runtime project and its sources".to_owned(),
            ),
        ];
        for dir in &source_dirs {
            let what = match dir.as_str() {
                "ada/src_instrumented" => "the target's Ada sources, as bhf instrumented them",
                "ada/harness" => "the generated harness",
                "ada/stubs" => "the stub packages bhf synthesized to make the tree build",
                _ => "a source dir of the generated project",
            };
            layout.push((format!("{dir}/"), what.to_owned()));
        }
        if relocated
            .files
            .iter()
            .any(|file| file.to.starts_with("sources/"))
        {
            layout.push((
                "sources/".to_owned(),
                "the scanned tree holding the operator's project files".to_owned(),
            ));
        }
        Ok(CapsulePlan {
            files: relocated.files,
            generated: relocated.generated,
            build_script: script,
            build_summary: "gprbuild ./poc".to_owned(),
            build_facts: json!({
                "project": format!("ada/build/{BUILD_PROJECT}"),
                "extends": project.extends.as_deref().and_then(|name| {
                    project_file(&build_dir, name).and_then(|path| relocator.build_path(&path))
                }),
                "withs": project.withs,
                "system_projects": system_projects,
                "source_dirs": source_dirs,
                "target": project.target,
                "runtime": project.runtime,
                "switches": project.switches,
                "gprbuild_version": requires.first().and_then(|r| r.version.clone()),
                "gnat_version": requires.get(1).and_then(|r| r.version.clone()),
                "relocated_files": relocated.templates,
            }),
            requires,
            layout,
            build_outputs: vec!["poc", "build"],
            warnings: relocated.warnings,
            windows: None,
        })
    }

    fn protocol(&self) -> crate::protocol_detect::HarnessProtocol {
        crate::protocol_detect::HarnessProtocol::StdinEventLog
    }

    fn crash_signature(&self, replay: &ReplayOutput) -> Option<String> {
        // A harness built with a sanitizer reports through it first.
        if let Some(signature) = super::sanitizer_signature(&replay.stderr, &replay.status)
            .filter(|signature| signature != "signal:crash")
        {
            return Some(signature);
        }
        if let Some(name) = replay.events.as_deref().and_then(unhandled_exception) {
            return Some(format!("ada:{name}"));
        }
        super::sanitizer_signature(&replay.stderr, &replay.status)
    }

    fn finding_signature(&self, finding: &serde_json::Value) -> Option<String> {
        // A sanitizer finding is named by its report, which the replay reads
        // the same way; an exception finding by the exception it recorded.
        if finding
            .pointer("/exception/sanitizer")
            .is_some_and(|sanitizer| !sanitizer.is_null())
        {
            return None;
        }
        finding
            .pointer("/exception/name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .map(|name| format!("ada:{}", name.to_ascii_uppercase()))
    }

    fn tool_gap(&self, tool: Tool) -> Option<&'static str> {
        match tool {
            Tool::Cartography => Some(CARTOGRAPHY_GAP),
            Tool::Capsule | Tool::EnvCapsule => None,
        }
    }
}

/// The exception that escaped the target unhandled, per the Ada runtime's
/// event log (the fuzz loop's own `unhandled` classification).
pub(crate) fn unhandled_exception(events: &[u8]) -> Option<String> {
    let testcases = event_log::group_into_testcases(event_log::EventReader::new(events)).ok()?;
    testcases.iter().find_map(|testcase| {
        let top_level = testcase.top_level.as_ref()?;
        corpus::classify(testcase)
            .iter()
            .any(|(_, classification)| *classification == corpus::Classification::Unhandled)
            .then(|| top_level.exception_name.to_ascii_uppercase())
    })
}

/// What the build dir holds that the build writes: objects, libraries, the
/// executable dir and the coverage sentinel.
fn build_dir_output(rel: &Path, is_dir: bool) -> bool {
    let Some(name) = rel.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if is_dir {
        return rel.components().count() == 1
            && matches!(name, "obj" | "adafuzz_obj" | "adafuzz_lib");
    }
    name.starts_with('.') || name.ends_with(".o") || name.ends_with(".ali")
}

/// Build leftovers and bhf's coverage maps beside Ada sources.
fn ada_source_noise(rel: &Path, is_dir: bool) -> bool {
    let Some(name) = rel.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if is_dir {
        return matches!(name, ".git" | "obj");
    }
    matches!(name, "Mayhemfile" | "PORTABILITY.md")
        || name.ends_with(".bhf-lines.json")
        || name.ends_with(".o")
        || name.ends_with(".ali")
        || name.ends_with(".stderr")
        || name.ends_with(".stdout")
}

/// What a generated harness dir holds beside the harness sources: the noise
/// beside any Ada sources, and the harness's standalone project file. That
/// file names the bhf checkout and the scanned tree, and the generated build
/// project does not use it (it takes the dir as a source dir).
fn ada_harness_noise(rel: &Path, is_dir: bool) -> bool {
    ada_source_noise(rel, is_dir)
        || (!is_dir
            && rel
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("gpr")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT: &str = "--  SPDX-License-Identifier: Apache-2.0\n\
        with \"adafuzz_runtime.gpr\";\n\
        with \"/t/deps/widget_lib.gpr\";\n\n\
        project Bhf_Build extends \"/t/src/multidir.gpr\" is\n\n\
        \x20  for Source_Dirs use (\"/w/src_instrumented\", \"/w/generated_harnesses/H-A0001\", \"/w/harnesses/H-A0001/repairs/ada_stubs\");\n\
        \x20  for Object_Dir use \"/w/ada_obj\";\n\
        \x20  for Exec_Dir use \"/w/build/H-A0001/obj\";\n\
        \x20  for Main use (\"main.adb\");\n\
        \x20  for Target use \"aarch64-linux-gnu\";\n\
        \x20  for Runtime (\"Ada\") use \"light\";\n\n\
        \x20  package Compiler is\n\
        \x20     for Default_Switches (\"Ada\") use (\"-g\", \"-gnatwa\", \"-gnata\", \"-gnat2022\");\n\
        \x20  end Compiler;\n\n\
        end Bhf_Build;\n";

    #[test]
    fn the_generated_project_is_read() {
        let project = parse_build_project(PROJECT);
        assert_eq!(
            project.withs,
            vec!["adafuzz_runtime.gpr", "/t/deps/widget_lib.gpr"]
        );
        assert_eq!(project.extends.as_deref(), Some("/t/src/multidir.gpr"));
        assert_eq!(project.source_dirs.len(), 3);
        assert_eq!(project.object_dir.as_deref(), Some("/w/ada_obj"));
        assert_eq!(project.exec_dir.as_deref(), Some("/w/build/H-A0001/obj"));
        assert_eq!(project.target.as_deref(), Some("aarch64-linux-gnu"));
        assert_eq!(project.runtime.as_deref(), Some("light"));
        assert_eq!(project.switches, ["-g", "-gnatwa", "-gnata", "-gnat2022"]);
    }

    /// A project the generated one extends outside the scanned tree is
    /// refused with its path; so is a harness built for another target.
    #[test]
    fn a_project_outside_the_tree_and_a_foreign_target_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let tree = temp.path().join("tree");
        let elsewhere = temp.path().join("elsewhere");
        let build = work.join("build/H-A0001-00000001");
        for dir in [&build, &tree, &elsewhere, &work.join("auto")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(
            work.join("auto/run.json"),
            json!({"source_root": tree}).to_string(),
        )
        .unwrap();
        std::fs::write(elsewhere.join("base.gpr"), "project Base is\nend Base;\n").unwrap();
        std::fs::write(
            build.join(BUILD_PROJECT),
            format!(
                "project Bhf_Build extends \"{}\" is\n   for Source_Dirs use (\"{}\");\nend Bhf_Build;\n",
                elsewhere.join("base.gpr").display(),
                tree.display()
            ),
        )
        .unwrap();
        let harness = HarnessContext {
            work_dir: work.clone(),
            harness_id: "H-A0001-00000001".to_owned(),
            harness_dir: work.join("harnesses/H-A0001-00000001"),
        };
        let problem = ADA_LANE.harness_problem(&harness).unwrap();
        assert!(
            problem.contains(&elsewhere.join("base.gpr").display().to_string())
                && problem.contains("outside the scanned tree"),
            "{problem}"
        );
        std::fs::write(
            build.join(BUILD_PROJECT),
            format!(
                "project Bhf_Build is\n   for Source_Dirs use (\"{}\");\n   for Target use \"arm-eabi\";\nend Bhf_Build;\n",
                tree.display()
            ),
        )
        .unwrap();
        let problem = ADA_LANE.harness_problem(&harness).unwrap();
        assert!(problem.contains("arm-eabi"), "{problem}");
        // An installed library project gprbuild finds itself is no problem.
        std::fs::write(
            build.join(BUILD_PROJECT),
            format!(
                "with \"gnatcoll\";\nproject Bhf_Build is\n   for Source_Dirs use (\"{}\");\nend Bhf_Build;\n",
                tree.display()
            ),
        )
        .unwrap();
        assert_eq!(ADA_LANE.harness_problem(&harness), None);
    }

    #[test]
    fn the_finding_names_the_exception_a_replay_must_raise() {
        let finding =
            json!({"exception": {"name": "Ada.Assertions.Assertion_Error", "sanitizer": null}});
        assert_eq!(
            ADA_LANE.finding_signature(&finding).as_deref(),
            Some("ada:ADA.ASSERTIONS.ASSERTION_ERROR")
        );
        let sanitized =
            json!({"exception": {"name": "ASAN_HEAP_BUFFER_OVERFLOW", "sanitizer": "asan"}});
        assert_eq!(ADA_LANE.finding_signature(&sanitized), None);
    }

    #[test]
    fn a_never_built_harness_says_how_to_build_it() {
        let temp = tempfile::tempdir().unwrap();
        let harness = HarnessContext {
            work_dir: temp.path().to_path_buf(),
            harness_id: "H-A0002-00000002".to_owned(),
            harness_dir: temp.path().join("harnesses/H-A0002-00000002"),
        };
        let problem = ADA_LANE.harness_problem(&harness).unwrap();
        assert!(problem.contains("bhf build"), "{problem}");
        assert!(problem.contains("--harness H-A0002-00000002"), "{problem}");
    }
}
