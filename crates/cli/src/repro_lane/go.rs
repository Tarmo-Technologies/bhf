// SPDX-License-Identifier: Apache-2.0

//! The Go lane.
//!
//! A Go harness is a generated `main` package (`bhf_harness.go`) in its own
//! module whose `go.mod` replaces the target module with the scanned tree,
//! built by `go build` into a native `main` that speaks bhf's framed protocol
//! (one input file as `argv[1]` outside the fuzz loop). A capsule ships the
//! harness module, the scanned tree and, when the target needs modules from
//! outside it, a `vendor/` dir made from the local module cache, then rebuilds
//! with `go build` offline (`GOPROXY=off`, `GOTOOLCHAIN=local`). A module that
//! needs dependencies the local cache does not hold is refused: they cannot be
//! vendored without the network. The crash oracle is the harness's recovered
//! panic (`== bhf go finding:`) or the runtime's own `panic:`.

use super::relocate::{self, Contents, Mount, Relocator};
use super::{
    refuse, report_signature, CapsulePlan, GeneratedFile, HarnessContext, Lane, ReplayOutput, Tool,
    Toolchain, CARTOGRAPHY_GAP,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub(crate) struct GoLane;

pub(crate) static GO_LANE: GoLane = GoLane;

const GO_TOOLS: &[Toolchain] = &[Toolchain {
    env_var: "GO",
    default: "go",
    fallbacks: &[],
    purpose: "builds the harness module",
    version_args: &["version"],
}];

/// The environment every capsule `go` command runs with: the installed Go,
/// no network, no workspace.
const GO_ENV: &[(&str, &str)] = &[
    ("GOTOOLCHAIN", "local"),
    ("GOPROXY", "off"),
    ("GOWORK", "off"),
    ("GOFLAGS", "-mod=mod"),
];

impl Lane for GoLane {
    fn tag(&self) -> &'static str {
        "go"
    }

    fn name(&self) -> &'static str {
        "Go"
    }

    fn tools(&self) -> &'static [Toolchain] {
        GO_TOOLS
    }

    fn recognizes(&self, harness_dir: &Path) -> bool {
        harness_dir.join("bhf_harness.go").is_file() && harness_dir.join("go.mod").is_file()
    }

    fn harness_problem(&self, harness: &HarnessContext) -> Option<String> {
        let dir = &harness.harness_dir;
        if !dir.join("bhf_harness.go").is_file() {
            return Some("it has no bhf_harness.go".to_owned());
        }
        let Ok(go_mod) = std::fs::read_to_string(dir.join("go.mod")) else {
            return Some("it has no readable go.mod".to_owned());
        };
        if replaced_dirs(&go_mod).is_empty() {
            return Some(
                "its go.mod replaces no module with a local dir, so there is no target \
                 module to ship"
                    .to_owned(),
            );
        }
        None
    }

    fn plan_capsule(&self, harness: &HarnessContext) -> anyhow::Result<CapsulePlan> {
        let dir = &harness.harness_dir;
        let go_mod = std::fs::read_to_string(dir.join("go.mod"))?;
        let replaced = replaced_dirs(&go_mod);
        let tree = super::recorded_source_root(&harness.work_dir)
            .filter(|root| replaced.iter().all(|module| module.starts_with(root)))
            .or_else(|| replaced.first().cloned())
            .ok_or_else(|| refuse("its go.mod replaces no module with a local dir"))?;
        if let Some(outside) = replaced.iter().find(|module| !module.starts_with(&tree)) {
            return Err(refuse(format!(
                "its go.mod replaces a module with {}, which is outside the scanned tree {}",
                outside.display(),
                tree.display()
            )));
        }
        let go = GO_TOOLS[0].compiler();
        let vendor = vendored_dependencies(&go, dir)?;
        let mut harness_files: Vec<PathBuf> = std::fs::read_dir(dir)?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .filter_map(|path| path.file_name().map(PathBuf::from))
            .filter(|name| {
                let name = name.to_string_lossy();
                name.ends_with(".go")
                    || matches!(
                        name.as_ref(),
                        "go.mod" | "go.sum" | "bhf_overlay.json" | "bhf_lowered_go.mod"
                    )
            })
            .collect();
        harness_files.sort();
        let mut relocator = Relocator {
            mounts: vec![
                Mount::rendered(dir, "harness", Contents::Files(harness_files)),
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
        if let Some(vendor) = &vendor {
            relocator.mounts.push(Mount::rendered(
                vendor.path().join("vendor"),
                "harness/vendor",
                Contents::Tree { skip: |_, _| false },
            ));
        }
        let mut relocated = relocator.relocate()?;
        // The vendor dir is a scratch copy: ship its files' bytes now.
        if let Some(vendor) = &vendor {
            let scratch = vendor.path().to_path_buf();
            let mut kept = Vec::new();
            for file in std::mem::take(&mut relocated.files) {
                if file.from.starts_with(&scratch) {
                    relocated.generated.push(GeneratedFile {
                        to: file.to.clone(),
                        bytes: std::fs::read(&file.from)?,
                        executable: false,
                    });
                } else {
                    kept.push(file);
                }
            }
            relocated.files = kept;
        }
        let module_mode = if vendor.is_some() { "vendor" } else { "mod" };
        let overlay = if dir.join("bhf_overlay.json").is_file() {
            " -overlay=bhf_overlay.json"
        } else {
            ""
        };
        let mut script = String::from(
            "#!/bin/sh\n\
             # Rebuild this bhf PoC offline. Needs only go (or $GO) and a shell.\n\
             set -e\n\
             cd \"$(dirname \"$0\")\"\n",
        );
        script.push_str(&relocate::resolve_tool("TOOL_GO", &GO_TOOLS[0]));
        script.push_str(&relocator.render_script(&relocated));
        script.push_str(&format!(
            "(cd build/harness && GOTOOLCHAIN=local GOPROXY=off GOWORK=off GOFLAGS=-mod={module_mode} \
             \"$TOOL_GO\" build -o main{overlay} .)\n\
             cp build/harness/main poc\n\
             chmod +x poc\n"
        ));
        let requirement = GO_TOOLS[0].requirement();
        let mut layout = vec![
            (
                "harness/bhf_harness.go".to_owned(),
                "the generated harness (decodes the input, calls the target)".to_owned(),
            ),
            (
                "harness/go.mod".to_owned(),
                "its module, which replaces the target module with sources/".to_owned(),
            ),
            (
                "sources/".to_owned(),
                "the scanned tree holding the target module".to_owned(),
            ),
        ];
        if vendor.is_some() {
            layout.push((
                "harness/vendor/".to_owned(),
                "the target's dependencies, vendored from the local module cache".to_owned(),
            ));
        }
        Ok(CapsulePlan {
            files: relocated.files,
            generated: relocated.generated,
            build_script: script,
            build_summary: "go build ./poc offline".to_owned(),
            build_facts: json!({
                "go": requirement.program,
                "go_version": requirement.version,
                "module_mode": module_mode,
                "vendored": vendor.is_some(),
                "overlay": !overlay.is_empty(),
                "relocated_files": relocated.templates,
            }),
            requires: vec![requirement],
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
            Tool::Cartography => Some(CARTOGRAPHY_GAP),
            Tool::Capsule | Tool::EnvCapsule => None,
        }
    }
}

/// The local dirs a `go.mod` replaces modules with (`replace m => /dir` or
/// `=> "/dir with space"`).
pub(crate) fn replaced_dirs(go_mod: &str) -> Vec<PathBuf> {
    go_mod
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("replace ").unwrap_or(line);
            let (_, target) = rest.split_once("=>")?;
            let target = target.trim();
            let path = if target.starts_with('"') {
                serde_json::from_str::<String>(target).ok()?
            } else {
                target.split_whitespace().next()?.to_owned()
            };
            let path = PathBuf::from(path);
            path.is_absolute().then_some(path)
        })
        .collect()
}

/// A `vendor/` dir for the harness module, made from the local module cache,
/// when the module needs anything outside the dirs it replaces; `None` when it
/// needs nothing else. A refusal when the cache cannot provide it.
fn vendored_dependencies(
    go: &str,
    harness_dir: &Path,
) -> anyhow::Result<Option<tempfile::TempDir>> {
    let mut list = Command::new(go);
    list.args([
        "list",
        "-m",
        "-f",
        "{{.Path}}\t{{if .Replace}}{{.Replace.Dir}}{{else}}{{.Dir}}{{end}}",
        "all",
    ])
    .current_dir(harness_dir);
    for (key, value) in GO_ENV {
        list.env(key, value);
    }
    let output = crate::command_output::output_with_timeout(&mut list, Duration::from_secs(300))
        .map_err(|error| anyhow::anyhow!("cannot run {go} list: {error}"))?;
    let local_requirements: Vec<String> = std::fs::read_to_string(harness_dir.join("go.mod"))
        .map(|go_mod| replaced_dirs(&go_mod))
        .unwrap_or_default()
        .iter()
        .filter_map(|dir| std::fs::read_to_string(dir.join("go.mod")).ok())
        .flat_map(|go_mod| requirements(&go_mod))
        .collect();
    let named = if local_requirements.is_empty() {
        String::new()
    } else {
        format!(
            " (the target module requires {})",
            local_requirements.join(", ")
        )
    };
    if !output.status.success() {
        return Err(refuse(format!(
            "the Go module needs dependencies that are not in the local module cache, so \
             they cannot be vendored for an offline rebuild{named}: {}",
            go_error(&String::from_utf8_lossy(&output.stderr))
        )));
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let local: Vec<PathBuf> = std::iter::once(harness_dir.to_path_buf())
        .chain(
            std::fs::read_to_string(harness_dir.join("go.mod"))
                .map(|go_mod| replaced_dirs(&go_mod))
                .unwrap_or_default(),
        )
        .collect();
    let external = listing.lines().any(|line| {
        let dir = line.split('\t').nth(1).unwrap_or_default();
        !dir.is_empty() && !local.iter().any(|root| Path::new(dir).starts_with(root))
    });
    if !external {
        return Ok(None);
    }
    let scratch = tempfile::Builder::new()
        .prefix("bhf-go-vendor-")
        .tempdir()?;
    for entry in std::fs::read_dir(harness_dir)?.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        if path.is_file() && (name_text.ends_with(".go") || name_text.starts_with("go.")) {
            std::fs::copy(&path, scratch.path().join(&name))?;
        }
    }
    let mut vendor = Command::new(go);
    vendor.args(["mod", "vendor"]).current_dir(scratch.path());
    for (key, value) in GO_ENV {
        vendor.env(key, value);
    }
    let output = crate::command_output::output_with_timeout(&mut vendor, Duration::from_secs(600))
        .map_err(|error| anyhow::anyhow!("cannot run {go} mod vendor: {error}"))?;
    if !output.status.success() || !scratch.path().join("vendor").is_dir() {
        return Err(refuse(format!(
            "the Go module needs dependencies that are not in the local module cache, so \
             they cannot be vendored for an offline rebuild{named}: {}",
            go_error(&String::from_utf8_lossy(&output.stderr))
        )));
    }
    Ok(Some(scratch))
}

/// The `require`d modules of a `go.mod` (`path version`), from single lines
/// and `require (...)` blocks.
fn requirements(go_mod: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in go_mod.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        if in_block {
            if line == ")" {
                in_block = false;
            } else if !line.is_empty() {
                out.push(line.to_owned());
            }
        } else if line == "require (" {
            in_block = true;
        } else if let Some(rest) = line.strip_prefix("require ") {
            out.push(rest.trim().to_owned());
        }
    }
    out
}

/// `go`'s error, its lines joined (it names the module on one line and why
/// on the next), bounded.
fn go_error(stderr: &str) -> String {
    let joined = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        return "no output".to_owned();
    }
    joined.chars().take(400).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_are_read_from_lines_and_blocks() {
        let go_mod = "module m\n\nrequire a.example/x v1.0.0\nrequire (\n\tb.example/y v2.1.0 // indirect\n)\n";
        assert_eq!(
            requirements(go_mod),
            ["a.example/x v1.0.0", "b.example/y v2.1.0"]
        );
    }

    // Unix only: the fixture's replace targets are POSIX absolute paths.
    #[cfg(unix)]
    #[test]
    fn replaced_dirs_are_read_quoted_or_bare() {
        let go_mod = "module bhf.example/x/bhfharness\n\ngo 1.21\n\n\
                      require bhf.example/x v0.0.0-incompatible\n\n\
                      replace bhf.example/x => \"/t/my src\"\n\
                      replace other => /t/other\n\
                      replace remote => example.com/fork v1.2.3\n";
        assert_eq!(
            replaced_dirs(go_mod),
            vec![PathBuf::from("/t/my src"), PathBuf::from("/t/other")]
        );
    }

    /// A module whose dependency is in no local cache is refused with that
    /// reason: it cannot be vendored offline.
    #[test]
    fn a_dependency_missing_from_the_module_cache_is_refused() {
        if which::which("go").is_err() {
            eprintln!("skipping: go not installed");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let tree = temp.path().join("tree");
        let harness = temp.path().join("work/harnesses/H-G0001-00000001");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::create_dir_all(&harness).unwrap();
        std::fs::write(
            tree.join("go.mod"),
            "module example.com/widget\n\ngo 1.21\n\nrequire example.invalid/absent v1.0.0\n",
        )
        .unwrap();
        std::fs::write(tree.join("widget.go"), "package widget\n").unwrap();
        std::fs::write(
            harness.join("go.mod"),
            format!(
                "module example.com/widget/bhfharness\n\ngo 1.21\n\n\
                 require example.com/widget v0.0.0-incompatible\n\n\
                 replace example.com/widget => {:?}\n",
                tree.display().to_string()
            ),
        )
        .unwrap();
        std::fs::write(
            harness.join("bhf_harness.go"),
            "package main\nimport _ \"example.com/widget\"\nfunc main() {}\n",
        )
        .unwrap();
        let error = vendored_dependencies("go", &harness)
            .expect_err("an unresolvable dependency is refused");
        let refusal = error
            .downcast_ref::<super::super::PlanRefusal>()
            .expect("a refusal, not a failure");
        assert!(refusal.0.contains("cannot be vendored"), "{refusal}");
        assert!(refusal.0.contains("example.invalid/absent"), "{refusal}");
    }
}
