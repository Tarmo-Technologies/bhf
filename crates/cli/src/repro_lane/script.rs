// SPDX-License-Identifier: Apache-2.0

//! The interpreted lanes: Python, JavaScript, TypeScript, Ruby, Perl, PHP and
//! Lua.
//!
//! Each harness is a `main` launcher script that `exec`s the interpreter on
//! bhf's driver for the language, with the generated harness module and the
//! scanned tree on the interpreter's module path. A capsule ships the harness
//! dir (launcher, driver, decoder and coverage helpers, generated harness, and
//! for TypeScript the transpiled target), the scanned tree, and a `build.sh`
//! that relocates the launcher onto the copies and the interpreter it finds.
//! The replay is the launcher on one input file (`argv[1]`), and the crash
//! oracle is the driver's `== bhf <lang> finding:` report, read by the same
//! parser the fuzz loop uses. The interpreter version the harness ran under is
//! recorded in the manifest.

use super::relocate::{self, Contents, Mount, Relocator};
use super::{
    report_signature, CapsulePlan, HarnessContext, Lane, ReplayOutput, Tool, Toolchain,
    CARTOGRAPHY_GAP, ENV_CAPSULE_INTERPRETED_GAP,
};
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) struct ScriptLane {
    tag: &'static str,
    name: &'static str,
    /// The marker bhf writes into this language's launcher.
    marker: &'static str,
    /// A file only this language's harness dir holds beside the launcher
    /// (TypeScript's transpiled target), or one it must not hold.
    distinct: Distinct,
    tools: &'static [Toolchain],
}

enum Distinct {
    None,
    Has(&'static str),
    Lacks(&'static str),
}

const PYTHON_TOOLS: &[Toolchain] = &[Toolchain::new("PYTHON", "python3", "runs the harness")];
const NODE_TOOLS: &[Toolchain] = &[Toolchain::new("NODE", "node", "runs the harness")];
const RUBY_TOOLS: &[Toolchain] = &[Toolchain::new("RUBY", "ruby", "runs the harness")];
const PERL_TOOLS: &[Toolchain] = &[Toolchain::new("PERL", "perl", "runs the harness")];
const PHP_TOOLS: &[Toolchain] = &[Toolchain::new("PHP", "php", "runs the harness")];
const LUA_TOOLS: &[Toolchain] = &[Toolchain {
    env_var: "LUA",
    default: "lua",
    fallbacks: &["lua5.4", "lua5.3", "luajit"],
    purpose: "runs the harness",
    version_args: &["-v"],
}];

pub(crate) static PYTHON_LANE: ScriptLane = ScriptLane {
    tag: "python",
    name: "Python",
    marker: "BHF_PY_LAUNCHER",
    distinct: Distinct::None,
    tools: PYTHON_TOOLS,
};

pub(crate) static JAVASCRIPT_LANE: ScriptLane = ScriptLane {
    tag: "javascript",
    name: "JavaScript",
    marker: "BHF_JS_LAUNCHER",
    distinct: Distinct::Lacks("target.js"),
    tools: NODE_TOOLS,
};

pub(crate) static TYPESCRIPT_LANE: ScriptLane = ScriptLane {
    tag: "typescript",
    name: "TypeScript",
    marker: "BHF_JS_LAUNCHER",
    distinct: Distinct::Has("target.js"),
    tools: NODE_TOOLS,
};

pub(crate) static RUBY_LANE: ScriptLane = ScriptLane {
    tag: "ruby",
    name: "Ruby",
    marker: "BHF_RB_LAUNCHER",
    distinct: Distinct::None,
    tools: RUBY_TOOLS,
};

pub(crate) static PERL_LANE: ScriptLane = ScriptLane {
    tag: "perl",
    name: "Perl",
    marker: "BHF_PL_LAUNCHER",
    distinct: Distinct::None,
    tools: PERL_TOOLS,
};

pub(crate) static PHP_LANE: ScriptLane = ScriptLane {
    tag: "php",
    name: "PHP",
    marker: "BHF_PHP_LAUNCHER",
    distinct: Distinct::None,
    tools: PHP_TOOLS,
};

pub(crate) static LUA_LANE: ScriptLane = ScriptLane {
    tag: "lua",
    name: "Lua",
    marker: "BHF_LUA_LAUNCHER",
    distinct: Distinct::None,
    tools: LUA_TOOLS,
};

impl ScriptLane {
    fn launcher(&self, harness_dir: &Path) -> Option<String> {
        std::fs::read_to_string(harness_dir.join("main"))
            .ok()
            .filter(|text| text.contains(self.marker))
    }
}

impl Lane for ScriptLane {
    fn tag(&self) -> &'static str {
        self.tag
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn tools(&self) -> &'static [Toolchain] {
        self.tools
    }

    fn recognizes(&self, harness_dir: &Path) -> bool {
        self.launcher(harness_dir).is_some()
            && match self.distinct {
                Distinct::None => true,
                Distinct::Has(name) => harness_dir.join(name).is_file(),
                Distinct::Lacks(name) => !harness_dir.join(name).is_file(),
            }
    }

    fn harness_problem(&self, harness: &HarnessContext) -> Option<String> {
        if !harness.harness_dir.join("main").is_file() {
            return Some("it has no `main` launcher (the harness was never built)".to_owned());
        }
        let Some(launcher) = self.launcher(&harness.harness_dir) else {
            return Some(format!("its `main` is not a bhf {} launcher", self.name));
        };
        scanned_tree(harness, &launcher).err()
    }

    fn plan_capsule(&self, harness: &HarnessContext) -> anyhow::Result<CapsulePlan> {
        let launcher = self.launcher(&harness.harness_dir).ok_or_else(|| {
            super::refuse(format!("its `main` is not a bhf {} launcher", self.name))
        })?;
        let tree = scanned_tree(harness, &launcher).map_err(super::refuse)?;
        let interpreter = self.tools[0];
        let mut relocator = Relocator {
            mounts: vec![
                Mount::rendered(
                    &harness.harness_dir,
                    "harness",
                    Contents::Tree {
                        skip: relocate::is_harness_state,
                    },
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
        relocator.exec_tool(&launcher, interpreter);
        let relocated = relocator.relocate()?;
        let requirement = interpreter.requirement();
        let mut script = format!(
            "#!/bin/sh\n\
             # Rebuild this bhf PoC offline. Needs only {} and a shell: the harness\n\
             # is interpreted, so the rebuild relocates its launcher onto this copy.\n\
             set -e\n\
             cd \"$(dirname \"$0\")\"\n",
            interpreter.describe()
        );
        script.push_str(&relocator.render_script(&relocated));
        if relocator.tools.is_empty() {
            // The launcher runs the interpreter by name: check it is here.
            script.push_str(&relocate::resolve_tool("TOOL_INTERPRETER", &interpreter));
        }
        script.push_str("cp build/harness/main poc\nchmod +x poc\n");
        let mut layout = vec![
            (
                "harness/main".to_owned(),
                format!(
                    "the {} launcher bhf generated (relocated by build.sh into build/)",
                    self.name
                ),
            ),
            (
                "harness/".to_owned(),
                "bhf's driver for the language, the decoder and the generated harness".to_owned(),
            ),
        ];
        if relocated.files.iter().any(|f| f.to.starts_with("sources/")) {
            layout.push((
                "sources/".to_owned(),
                "the scanned tree the harness loads the target from".to_owned(),
            ));
        }
        Ok(CapsulePlan {
            files: relocated.files.clone(),
            generated: relocated.generated.clone(),
            build_script: script,
            build_summary: format!("relocate the {} launcher into ./poc", self.name),
            build_facts: json!({
                "interpreter_env": interpreter.env_var,
                "interpreter": requirement.program,
                "interpreter_version": requirement.version,
                "launcher": "harness/main",
                "relocated_files": relocated.templates,
            }),
            requires: vec![requirement],
            layout,
            build_outputs: vec!["poc", "build"],
            warnings: relocated.warnings,
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

/// The scanned tree a harness loads its target from: the `source_root` the
/// run recorded (`auto/run.json`), else the one the launcher names
/// (`BHF_TRACE_PREFIX`, or the dir of the JavaScript module it loads).
pub(crate) fn scanned_tree(harness: &HarnessContext, launcher: &str) -> Result<PathBuf, String> {
    if let Some(root) = super::recorded_source_root(&harness.work_dir) {
        return Ok(root);
    }
    if let Some(prefix) = launcher_value(launcher, "BHF_TRACE_PREFIX") {
        return Ok(PathBuf::from(prefix));
    }
    if let Some(module) = launcher_value(launcher, "BHF_JS_MODULE") {
        let module = PathBuf::from(module);
        if !module.starts_with(&harness.harness_dir) {
            if let Some(dir) = module.parent() {
                return Ok(dir.to_path_buf());
            }
        }
    }
    Err(format!(
        "neither {} nor its launcher records the scanned tree the target loads from",
        harness.work_dir.join("auto/run.json").display()
    ))
}

/// The value of `NAME="value"` in a launcher script.
pub(crate) fn launcher_value(launcher: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = launcher.find(&needle)? + needle.len();
    let end = launcher[start..].find('"')?;
    Some(launcher[start..start + end].to_owned()).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_values_are_read_from_the_env_prefix() {
        let launcher = "#!/bin/sh\nBHF_HARNESS=\"/w/h/bhfgen.lua\" \\\nBHF_TRACE_PREFIX=\"/t/src\" \\\nexec \"/usr/bin/lua\" x\n";
        assert_eq!(
            launcher_value(launcher, "BHF_TRACE_PREFIX").as_deref(),
            Some("/t/src")
        );
        assert_eq!(launcher_value(launcher, "BHF_MISSING"), None);
    }

    /// JavaScript and TypeScript harnesses share the Node launcher; the
    /// transpiled target beside it tells them apart.
    #[test]
    fn the_node_lanes_are_told_apart_by_the_transpiled_target() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        std::fs::write(
            dir.join("main"),
            "#!/bin/sh\n# BHF_FRAMED BHF_JS_LAUNCHER\n",
        )
        .unwrap();
        assert!(JAVASCRIPT_LANE.recognizes(dir));
        assert!(!TYPESCRIPT_LANE.recognizes(dir));
        std::fs::write(dir.join("target.js"), "exports.f = () => 0;\n").unwrap();
        assert!(TYPESCRIPT_LANE.recognizes(dir));
        assert!(!JAVASCRIPT_LANE.recognizes(dir));
        assert!(!PYTHON_LANE.recognizes(dir));
    }

    /// A harness whose run recorded no scanned tree and whose launcher names
    /// none is refused with what is missing.
    #[test]
    fn a_harness_without_a_recorded_tree_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let dir = work.join("harnesses/H-P0001-00000001");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("main"),
            "#!/bin/sh\n# BHF_FRAMED BHF_PY_LAUNCHER\nexec python3 d.py \"$@\"\n",
        )
        .unwrap();
        let harness = HarnessContext {
            work_dir: work.clone(),
            harness_id: "H-P0001-00000001".to_owned(),
            harness_dir: dir,
        };
        let problem = PYTHON_LANE.harness_problem(&harness).unwrap();
        assert!(problem.contains("auto/run.json"), "{problem}");
        assert!(problem.contains("scanned tree"), "{problem}");
    }
}
