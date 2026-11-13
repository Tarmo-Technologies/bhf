// SPDX-License-Identifier: Apache-2.0

//! The Java lane.
//!
//! A Java harness is a generated class (`harness-src/`) compiled against the
//! target's classes and bhf's JVM agent jar (coverage agent and driver), run
//! by a `main` launcher: `java -javaagent:<agent> -cp <classpath>
//! com.bhf.Driver <harness class>`. A capsule ships the launcher, the harness
//! source, the agent jar, the scanned tree and any dependency jars on the
//! classpath, and rebuilds with `javac`: the target's sources (the same ones
//! bhf compiled, listed in `java-sources.txt`), then the harness. A target
//! bhf built through Maven or Gradle has a classes dir of that build on its
//! classpath, which a capsule does not rebuild: it is refused with that
//! reason. The crash oracle is the driver's `== bhf JVM finding:` report.

use super::relocate::{self, Contents, Mount, Relocator};
use super::{
    refuse, report_signature, CapsulePlan, GeneratedFile, HarnessContext, Lane, ReplayOutput, Tool,
    Toolchain, CARTOGRAPHY_GAP, ENV_CAPSULE_INTERPRETED_GAP,
};
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) struct JavaLane;

pub(crate) static JAVA_LANE: JavaLane = JavaLane;

const JAVA_TOOLS: &[Toolchain] = &[
    Toolchain {
        env_var: "JAVAC",
        default: "javac",
        fallbacks: &[],
        purpose: "compiles the target and the harness",
        version_args: &["-version"],
    },
    Toolchain {
        env_var: "JAVA",
        default: "java",
        fallbacks: &[],
        purpose: "runs the harness",
        version_args: &["-version"],
    },
];

const MARKER: &str = "BHF_JVM_LAUNCHER";

/// What a Java launcher runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JvmLaunch {
    pub(crate) agent: PathBuf,
    pub(crate) classpath: Vec<PathBuf>,
    pub(crate) preview: bool,
}

/// Read the agent jar, the classpath and the preview switch off a launcher.
pub(crate) fn parse_launcher(launcher: &str) -> Option<JvmLaunch> {
    let quoted_after = |needle: &str| -> Option<String> {
        let start = launcher.find(needle)? + needle.len();
        let end = launcher[start..].find('"')?;
        Some(launcher[start..start + end].to_owned())
    };
    Some(JvmLaunch {
        agent: PathBuf::from(quoted_after("-javaagent:\"")?),
        classpath: quoted_after("-cp \"")?
            .split(':')
            .filter(|entry| !entry.is_empty())
            .map(PathBuf::from)
            .collect(),
        preview: launcher.contains(" --enable-preview"),
    })
}

impl Lane for JavaLane {
    fn tag(&self) -> &'static str {
        "java"
    }

    fn name(&self) -> &'static str {
        "Java"
    }

    fn tools(&self) -> &'static [Toolchain] {
        JAVA_TOOLS
    }

    fn recognizes(&self, harness_dir: &Path) -> bool {
        std::fs::read_to_string(harness_dir.join("main")).is_ok_and(|text| text.contains(MARKER))
    }

    fn harness_problem(&self, harness: &HarnessContext) -> Option<String> {
        let Ok(launcher) = std::fs::read_to_string(harness.harness_dir.join("main")) else {
            return Some("it has no `main` launcher (the harness was never built)".to_owned());
        };
        if !launcher.contains(MARKER) {
            return Some("its `main` is not a bhf Java launcher".to_owned());
        }
        let Some(launch) = parse_launcher(&launcher) else {
            return Some("its launcher names no agent jar or classpath".to_owned());
        };
        if !harness.harness_dir.join("harness-src").is_dir() {
            return Some("it has no harness-src/ to rebuild the harness from".to_owned());
        }
        classpath_problem(&harness.harness_dir, &launch)
    }

    fn plan_capsule(&self, harness: &HarnessContext) -> anyhow::Result<CapsulePlan> {
        let dir = &harness.harness_dir;
        let launcher = std::fs::read_to_string(dir.join("main"))?;
        let launch = parse_launcher(&launcher)
            .ok_or_else(|| refuse("its launcher names no agent jar or classpath"))?;
        if let Some(problem) = classpath_problem(dir, &launch) {
            return Err(refuse(problem));
        }
        let tree = super::recorded_source_root(&harness.work_dir).ok_or_else(|| {
            refuse(format!(
                "{} does not record the scanned tree the target was compiled from",
                harness.work_dir.join("auto/run.json").display()
            ))
        })?;
        let agent_dir = launch
            .agent
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let agent_name = launch
            .agent
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_default();
        let jars: Vec<&PathBuf> = launch
            .classpath
            .iter()
            .filter(|entry| **entry != launch.agent && !entry.starts_with(dir))
            .collect();
        let mut harness_files = vec![PathBuf::from("main")];
        harness_files.extend(
            java_files(&dir.join("harness-src"))
                .into_iter()
                .map(|rel| Path::new("harness-src").join(rel)),
        );
        let mut relocator = Relocator {
            mounts: vec![
                Mount::rendered(dir, "harness", Contents::Files(harness_files.clone())),
                Mount::in_place(
                    &agent_dir,
                    "runtime/jvm",
                    Contents::Files(vec![agent_name.clone()]),
                ),
                Mount::in_place(
                    &tree,
                    "sources",
                    Contents::Tree {
                        skip: relocate::is_tree_noise,
                    },
                ),
            ],
            tools: Vec::new(),
            protected: vec![harness.work_dir.clone(), tree.clone()],
            exclude: vec![harness.work_dir.clone()],
        };
        // One mount per dir the jars live in, so two jars of one dir stay apart.
        let mut jar_dirs: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> =
            std::collections::BTreeMap::new();
        for jar in &jars {
            let name = jar.file_name().map(PathBuf::from).unwrap_or_default();
            jar_dirs
                .entry(jar.parent().unwrap_or(Path::new("/")).to_path_buf())
                .or_default()
                .push(name);
        }
        let jar_dir_index: Vec<PathBuf> = jar_dirs.keys().cloned().collect();
        let jar_paths: Vec<String> = jars
            .iter()
            .map(|jar| {
                let parent = jar.parent().unwrap_or(Path::new("/"));
                let index = jar_dir_index
                    .iter()
                    .position(|dir| dir == parent)
                    .unwrap_or_default();
                format!(
                    "vendor/jars/{index}/{}",
                    jar.file_name().unwrap_or_default().to_string_lossy()
                )
            })
            .collect();
        for (index, (jar_dir, names)) in jar_dirs.into_iter().enumerate() {
            relocator.mounts.push(Mount::in_place(
                jar_dir,
                &format!("vendor/jars/{index}"),
                Contents::Files(names),
            ));
        }
        relocator.exec_tool(&launcher, JAVA_TOOLS[1]);
        let mut relocated = relocator.relocate()?;
        // The sources bhf compiled the target from, as javac argument files.
        let target_sources: Vec<String> = crate::auto::java_build::collect_java_sources(&tree)
            .iter()
            .filter_map(|source| source.strip_prefix(&tree).ok())
            .map(|rel| format!("sources/{}", rel.to_string_lossy().replace('\\', "/")))
            .collect();
        if target_sources.is_empty() {
            return Err(refuse(format!("no .java sources under {}", tree.display())));
        }
        let harness_sources: Vec<String> = harness_files
            .iter()
            .filter(|rel| rel.extension().is_some_and(|ext| ext == "java"))
            .map(|rel| format!("build/harness/{}", rel.to_string_lossy().replace('\\', "/")))
            .collect();
        relocated.generated.push(GeneratedFile {
            to: "java-sources.txt".to_owned(),
            bytes: argument_file(&target_sources).into_bytes(),
            executable: false,
        });
        relocated.generated.push(GeneratedFile {
            to: "harness-sources.txt".to_owned(),
            bytes: argument_file(&harness_sources).into_bytes(),
            executable: false,
        });
        let agent = format!("runtime/jvm/{}", agent_name.to_string_lossy());
        let target_cp = jar_paths.join(":");
        let harness_cp = std::iter::once(agent.clone())
            .chain(std::iter::once("build/harness/target-classes".to_owned()))
            .chain(jar_paths.iter().cloned())
            .collect::<Vec<_>>()
            .join(":");
        let mut script = String::from(
            "#!/bin/sh\n\
             # Rebuild this bhf PoC offline. Needs only a JDK (javac and java, or $JAVAC\n\
             # and $JAVA) and a shell.\n\
             set -e\n\
             cd \"$(dirname \"$0\")\"\n",
        );
        script.push_str(&relocate::resolve_tool("TOOL_JAVAC", &JAVA_TOOLS[0]));
        if relocator.tools.is_empty() {
            script.push_str(&relocate::resolve_tool("TOOL_JAVA", &JAVA_TOOLS[1]));
        }
        script.push_str(&relocator.render_script(&relocated));
        if launch.preview {
            // Preview features compile only for javac's own feature release.
            script.push_str(
                "RELEASE=$(\"$TOOL_JAVAC\" -version 2>&1 | sed -n 's/^javac \\([0-9][0-9]*\\).*/\\1/p')\n\
                 PREVIEW=\"--enable-preview --release $RELEASE\"\n",
            );
        } else {
            script.push_str("PREVIEW=\n");
        }
        script.push_str(&format!(
            "mkdir -p build/harness/target-classes build/harness/harness-classes\n\
             \"$TOOL_JAVAC\" $PREVIEW -nowarn {target_cp_flag}-d build/harness/target-classes @java-sources.txt\n\
             \"$TOOL_JAVAC\" $PREVIEW -nowarn -cp {harness_cp} -d build/harness/harness-classes @harness-sources.txt\n\
             cp build/harness/main poc\n\
             chmod +x poc\n",
            target_cp_flag = if target_cp.is_empty() {
                String::new()
            } else {
                format!("-cp {} ", super::sh_word(&target_cp))
            },
            harness_cp = super::sh_word(&harness_cp),
        ));
        let requires: Vec<_> = JAVA_TOOLS.iter().map(Toolchain::requirement).collect();
        let mut layout = vec![
            (
                "harness/main".to_owned(),
                "the JVM launcher bhf generated (relocated by build.sh into build/)".to_owned(),
            ),
            (
                "harness/harness-src/".to_owned(),
                "the generated harness class (decodes the input, calls the target)".to_owned(),
            ),
            (agent.clone(), "bhf's JVM agent and driver".to_owned()),
            (
                "sources/".to_owned(),
                "the scanned tree; java-sources.txt lists the sources build.sh compiles".to_owned(),
            ),
        ];
        if !jar_paths.is_empty() {
            layout.push((
                "vendor/jars/".to_owned(),
                "the dependency jars on the target's classpath".to_owned(),
            ));
        }
        Ok(CapsulePlan {
            files: relocated.files,
            generated: relocated.generated,
            build_script: script,
            build_summary: "javac the target and the harness, relocate the launcher".to_owned(),
            build_facts: json!({
                "target_sources": target_sources.len(),
                "dependency_jars": jar_paths.len(),
                "preview": launch.preview,
                "relocated_files": relocated.templates,
            }),
            requires,
            layout,
            build_outputs: vec!["poc", "build"],
            warnings: relocated.warnings,
            windows: None,
            portability: Default::default(),
        })
    }

    fn crash_signature(&self, replay: &ReplayOutput) -> Option<String> {
        report_signature(&replay.stderr, &replay.status)
    }

    fn tool_gap(&self, tool: Tool) -> Option<&'static str> {
        match tool {
            Tool::Capsule => None,
            Tool::Cartography => Some(CARTOGRAPHY_GAP),
            Tool::EnvCapsule => Some(ENV_CAPSULE_INTERPRETED_GAP),
        }
    }
}

/// Why a capsule cannot rebuild the launcher's classpath: an entry that is
/// neither bhf's agent, nor a classes dir bhf compiled into the harness dir,
/// nor a jar file (a Maven or Gradle build's classes dir).
fn classpath_problem(harness_dir: &Path, launch: &JvmLaunch) -> Option<String> {
    for entry in &launch.classpath {
        if *entry == launch.agent {
            continue;
        }
        if entry.starts_with(harness_dir) {
            let name = entry.strip_prefix(harness_dir).ok()?.to_string_lossy();
            if name == "target-classes" || name == "harness-classes" {
                continue;
            }
            return Some(format!(
                "its classpath names {}, which the capsule does not know how to rebuild",
                entry.display()
            ));
        }
        let is_jar = entry
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jar"))
            && entry.is_file();
        if !is_jar {
            return Some(format!(
                "its target classes are {}, built by the project's Maven or Gradle build, \
                 which a capsule does not rerun offline (a capsule rebuilds targets bhf \
                 compiled with javac)",
                entry.display()
            ));
        }
    }
    if !launch.agent.is_file() {
        return Some(format!(
            "bhf's JVM agent {} no longer exists",
            launch.agent.display()
        ));
    }
    None
}

/// The `.java` files under `dir`, relative.
fn java_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for entry in std::fs::read_dir(dir.join(&rel))
            .into_iter()
            .flatten()
            .flatten()
        {
            let child = rel.join(entry.file_name());
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                stack.push(child);
            } else if child.extension().is_some_and(|ext| ext == "java") {
                out.push(child);
            }
        }
    }
    out.sort();
    out
}

/// A javac `@argfile` naming `paths`, each quoted.
fn argument_file(paths: &[String]) -> String {
    paths
        .iter()
        .map(|path| format!("\"{}\"\n", path.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAUNCHER: &str = "#!/bin/sh\n# BHF_FRAMED BHF_JVM_LAUNCHER\nBHF_EXPECTED_EXCEPTIONS=\"\" \\\n\
        exec \"/usr/bin/java\" -javaagent:\"/c/bhf-jvm-agent.jar\" -cp \"/c/bhf-jvm-agent.jar:/w/h/target-classes:/w/h/harness-classes\" \\\n    com.bhf.Driver bhfgen.Harness \"$@\"\n";

    #[test]
    fn the_launcher_names_agent_classpath_and_preview() {
        let launch = parse_launcher(LAUNCHER).unwrap();
        assert_eq!(launch.agent, PathBuf::from("/c/bhf-jvm-agent.jar"));
        assert_eq!(launch.classpath.len(), 3);
        assert!(!launch.preview);
        let preview = LAUNCHER.replace("\"/usr/bin/java\"", "\"/usr/bin/java\" --enable-preview");
        assert!(parse_launcher(&preview).unwrap().preview);
    }

    /// A target whose classes came from a Maven or Gradle build is refused
    /// with that reason; jar files on the classpath are fine.
    #[test]
    fn a_build_tool_classes_dir_is_refused_and_jars_are_not() {
        let temp = tempfile::tempdir().unwrap();
        let agent = temp.path().join("bhf-jvm-agent.jar");
        let jar = temp.path().join("dep.jar");
        std::fs::write(&agent, b"PK").unwrap();
        std::fs::write(&jar, b"PK").unwrap();
        let harness = temp.path().join("w/h");
        let launch = |extra: &Path| JvmLaunch {
            agent: agent.clone(),
            classpath: vec![
                agent.clone(),
                extra.to_path_buf(),
                harness.join("harness-classes"),
            ],
            preview: false,
        };
        assert_eq!(classpath_problem(&harness, &launch(&jar)), None);
        let problem =
            classpath_problem(&harness, &launch(&temp.path().join("proj/target/classes"))).unwrap();
        assert!(problem.contains("Maven or Gradle"), "{problem}");
    }

    #[test]
    fn argument_files_quote_each_path() {
        assert_eq!(
            argument_file(&["sources/a b/A.java".to_owned(), "x\"y.java".to_owned()]),
            "\"sources/a b/A.java\"\n\"x\\\"y.java\"\n"
        );
    }
}
