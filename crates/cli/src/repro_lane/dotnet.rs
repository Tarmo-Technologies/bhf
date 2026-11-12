// SPDX-License-Identifier: Apache-2.0

//! The C# lane.
//!
//! A C# harness is a generated entry (`proj/BhfEntry.cs`) and bhf's .NET
//! driver (`proj/Driver.cs`) in an exe project (`proj/bhf_harness.csproj`)
//! that references the target project, built by `dotnet build` into `out/`
//! and run by a `main` launcher (`dotnet out/bhf_harness.dll`). The fuzz build
//! also references the SharpFuzz package (the coverage map the driver binds to
//! by reflection) and instruments the target's IL; a replay needs neither the
//! package feed nor the instrumentation, only the `SharpFuzz.Common` assembly
//! the build put in `out/`. A capsule ships the harness project with that
//! assembly vendored as a plain reference, the scanned tree, and every other
//! NuGet package the restore resolved (`proj/obj/project.assets.json`) as a
//! local feed taken from the NuGet package cache. It restores and builds with
//! that feed alone and an empty package cache of its own, in a copy of the
//! sources under `build/` (the SDK writes `obj/` and `bin/` beside every
//! project), so the rebuild is offline and leaves the shipped files as they
//! were; a package missing from the local cache is refused with its name.
//! The crash oracle is the driver's `== bhf csharp finding:` report.

use super::relocate::{self, Contents, Mount, Relocator};
use super::{
    refuse, report_signature, CapsuleFile, CapsulePlan, GeneratedFile, HarnessContext, Lane,
    ReplayOutput, Tool, Toolchain, CARTOGRAPHY_GAP, ENV_CAPSULE_INTERPRETED_GAP,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) struct CSharpLane;

pub(crate) static CSHARP_LANE: CSharpLane = CSharpLane;

const DOTNET_TOOLS: &[Toolchain] = &[Toolchain::new(
    "DOTNET",
    "dotnet",
    "builds and runs the harness project (the .NET SDK)",
)];

const MARKER: &str = "BHF_CS_LAUNCHER";
/// The assembly the driver binds the coverage map through.
const SHARPFUZZ_COMMON: &str = "SharpFuzz.Common.dll";

impl Lane for CSharpLane {
    fn tag(&self) -> &'static str {
        "csharp"
    }

    fn name(&self) -> &'static str {
        "C#"
    }

    fn tools(&self) -> &'static [Toolchain] {
        DOTNET_TOOLS
    }

    fn recognizes(&self, harness_dir: &Path) -> bool {
        std::fs::read_to_string(harness_dir.join("main")).is_ok_and(|text| text.contains(MARKER))
    }

    fn harness_problem(&self, harness: &HarnessContext) -> Option<String> {
        let dir = &harness.harness_dir;
        let Ok(launcher) = std::fs::read_to_string(dir.join("main")) else {
            return Some("it has no `main` launcher (the harness was never built)".to_owned());
        };
        if !launcher.contains(MARKER) {
            return Some("its `main` is not a bhf .NET launcher".to_owned());
        }
        for file in [
            "proj/bhf_harness.csproj",
            "proj/Driver.cs",
            "proj/BhfEntry.cs",
        ] {
            if !dir.join(file).is_file() {
                return Some(format!("it has no {file}"));
            }
        }
        if !dir.join("out").join(SHARPFUZZ_COMMON).is_file() {
            return Some(format!(
                "its build output has no {SHARPFUZZ_COMMON}, the coverage assembly the driver \
                 needs at run time"
            ));
        }
        None
    }

    fn plan_capsule(&self, harness: &HarnessContext) -> anyhow::Result<CapsulePlan> {
        let dir = &harness.harness_dir;
        let tree = super::recorded_source_root(&harness.work_dir).ok_or_else(|| {
            refuse(format!(
                "{} does not record the scanned tree the target project is in",
                harness.work_dir.join("auto/run.json").display()
            ))
        })?;
        let packages = resolved_packages(dir)?;
        let feed = nuget_package_cache();
        let mut vendored = Vec::new();
        for (name, version) in &packages {
            let id = name.to_ascii_lowercase();
            let version = version.to_ascii_lowercase();
            let nupkg = feed
                .join(&id)
                .join(&version)
                .join(format!("{id}.{version}.nupkg"));
            if !nupkg.is_file() {
                return Err(refuse(format!(
                    "the harness project needs the NuGet package {name} {version}, which is not \
                     in the local package cache ({}), so the capsule cannot restore it offline",
                    feed.display()
                )));
            }
            vendored.push(CapsuleFile {
                from: nupkg,
                to: format!("vendor/nuget/{id}.{version}.nupkg"),
            });
        }
        let mut harness_files = vec![
            PathBuf::from("main"),
            PathBuf::from("proj/bhf_harness.csproj"),
            PathBuf::from("proj/Driver.cs"),
            PathBuf::from("proj/BhfEntry.cs"),
        ];
        if dir.join("proj/target/bhf_target.csproj").is_file() {
            harness_files.push(PathBuf::from("proj/target/bhf_target.csproj"));
        }
        let relocator = Relocator {
            mounts: vec![
                Mount::rendered(dir, "harness", Contents::Files(harness_files)),
                // `dotnet build` writes obj/ and bin/ beside each project it
                // builds, so the target project builds from a copy in build/.
                Mount::rendered(
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
        let mut relocated = relocator.relocate()?;
        // The harness project references the SharpFuzz package for the fuzz
        // build; the capsule references the assembly it shipped instead.
        let csproj = "harness/proj/bhf_harness.csproj";
        let text = match relocated.generated.iter().find(|file| file.to == csproj) {
            Some(file) => String::from_utf8_lossy(&file.bytes).into_owned(),
            None => std::fs::read_to_string(dir.join("proj/bhf_harness.csproj"))?,
        };
        let rewritten = reference_vendored_sharpfuzz(&text);
        relocated.files.retain(|file| file.to != csproj);
        relocated.generated.retain(|file| file.to != csproj);
        relocated.generated.push(GeneratedFile {
            to: csproj.to_owned(),
            bytes: rewritten.into_bytes(),
            executable: false,
        });
        if !relocated
            .templates
            .iter()
            .any(|template| template == csproj)
        {
            relocated.templates.push(csproj.to_owned());
        }
        relocated.files.push(CapsuleFile {
            from: dir.join("out").join(SHARPFUZZ_COMMON),
            to: format!("vendor/{SHARPFUZZ_COMMON}"),
        });
        // An empty feed still has to exist; it lives with the build outputs.
        let feed_dir = if vendored.is_empty() {
            "build/nuget-feed"
        } else {
            "vendor/nuget"
        };
        relocated.files.extend(vendored);
        let mut script = String::from(
            "#!/bin/sh\n\
             # Rebuild this bhf PoC offline. Needs only the .NET SDK (dotnet, or $DOTNET)\n\
             # and a shell: packages restore from vendor/nuget alone, into a package cache\n\
             # of the capsule's own.\n\
             set -e\n\
             cd \"$(dirname \"$0\")\"\n",
        );
        script.push_str(&relocate::resolve_tool("TOOL_DOTNET", &DOTNET_TOOLS[0]));
        script.push_str(&relocator.render_script(&relocated));
        script.push_str(&format!(
            "mkdir -p {feed_dir} build/nuget-packages\n\
             DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 NUGET_PACKAGES=\"$here/build/nuget-packages\" \\\n\
             \x20 \"$TOOL_DOTNET\" build build/harness/proj/bhf_harness.csproj -c Release --nologo -v quiet \\\n\
             \x20 -o build/harness/out \"-p:RestoreSources=$here/{feed_dir}\" \\\n\
             \x20 -p:RestoreAdditionalProjectSources=\n\
             cp build/harness/main poc\n\
             chmod +x poc\n"
        ));
        let requirement = DOTNET_TOOLS[0].requirement();
        Ok(CapsulePlan {
            files: relocated.files,
            generated: relocated.generated,
            build_script: script,
            build_summary: "dotnet build the harness project offline".to_owned(),
            build_facts: json!({
                "dotnet": requirement.program,
                "sdk_version": requirement.version,
                "vendored_packages": packages
                    .iter()
                    .map(|(name, version)| format!("{name} {version}"))
                    .collect::<Vec<_>>(),
                "sharpfuzz": format!("vendor/{SHARPFUZZ_COMMON} (no IL instrumentation: a replay needs no coverage)"),
                "relocated_files": relocated.templates,
            }),
            requires: vec![requirement],
            layout: vec![
                (
                    "harness/proj/".to_owned(),
                    "the harness project: bhf's driver and the generated entry".to_owned(),
                ),
                (
                    "harness/main".to_owned(),
                    "the .NET launcher bhf generated (relocated by build.sh into build/)"
                        .to_owned(),
                ),
                (
                    "sources/".to_owned(),
                    "the scanned tree holding the target project".to_owned(),
                ),
                (
                    "vendor/".to_owned(),
                    "SharpFuzz.Common.dll and the NuGet packages the restore resolved".to_owned(),
                ),
            ],
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

/// The NuGet packages the harness project's restore resolved, other than
/// SharpFuzz (`proj/obj/project.assets.json` `libraries` of type `package`).
fn resolved_packages(harness_dir: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let assets = harness_dir.join("proj/obj/project.assets.json");
    let Ok(bytes) = std::fs::read(&assets) else {
        return Ok(Vec::new());
    };
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", assets.display()))?;
    let mut packages = Vec::new();
    for (key, library) in value
        .get("libraries")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if library.get("type").and_then(Value::as_str) != Some("package") {
            continue;
        }
        let Some((name, version)) = key.split_once('/') else {
            continue;
        };
        if name.eq_ignore_ascii_case("SharpFuzz") {
            continue;
        }
        packages.push((name.to_owned(), version.to_owned()));
    }
    packages.sort();
    Ok(packages)
}

/// Where NuGet keeps downloaded packages: `$NUGET_PACKAGES`, else
/// `~/.nuget/packages`.
fn nuget_package_cache() -> PathBuf {
    if let Some(dir) = std::env::var_os("NUGET_PACKAGES").filter(|dir| !dir.is_empty()) {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".nuget").join("packages")
}

/// The harness project with its SharpFuzz package reference replaced by a
/// reference to the vendored `SharpFuzz.Common` assembly.
pub(crate) fn reference_vendored_sharpfuzz(csproj: &str) -> String {
    let reference = format!(
        "<Reference Include=\"SharpFuzz.Common\"><HintPath>{}/vendor/{SHARPFUZZ_COMMON}</HintPath></Reference>",
        relocate::CAPSULE_ROOT
    );
    let mut out = String::with_capacity(csproj.len());
    let mut rest = csproj;
    let mut replaced = false;
    while let Some(start) = rest.find("<PackageReference") {
        let Some(len) = rest[start..].find("/>").map(|end| end + 2) else {
            break;
        };
        let element = &rest[start..start + len];
        out.push_str(&rest[..start]);
        if element.contains("Include=\"SharpFuzz\"") {
            out.push_str(&reference);
            replaced = true;
        } else {
            out.push_str(element);
        }
        rest = &rest[start + len..];
    }
    out.push_str(rest);
    if !replaced {
        out = out.replacen("</ItemGroup>", &format!("  {reference}\n  </ItemGroup>"), 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sharpfuzz_package_becomes_a_vendored_reference() {
        let csproj = "<Project>\n  <ItemGroup>\n    <Compile Include=\"Driver.cs;BhfEntry.cs\" />\n    \
                      <PackageReference Include=\"SharpFuzz\" Version=\"2.3.0\" />\n    \
                      <PackageReference Include=\"Widget.Codec\" Version=\"1.0.0\" />\n  </ItemGroup>\n</Project>\n";
        let out = reference_vendored_sharpfuzz(csproj);
        assert!(!out.contains("Include=\"SharpFuzz\""), "{out}");
        assert!(
            out.contains("<HintPath>@BHF_CAPSULE@/vendor/SharpFuzz.Common.dll</HintPath>"),
            "{out}"
        );
        assert!(
            out.contains("<PackageReference Include=\"Widget.Codec\" Version=\"1.0.0\" />"),
            "other packages stay: {out}"
        );
    }

    /// A package the restore resolved that the local cache does not hold is
    /// refused with its name: the capsule cannot restore it offline.
    #[test]
    fn a_package_missing_from_the_nuget_cache_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let tree = temp.path().join("tree");
        let dir = work.join("harnesses/H-S0001-00000001");
        std::fs::create_dir_all(dir.join("proj/obj")).unwrap();
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::create_dir_all(work.join("auto")).unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(
            work.join("auto/run.json"),
            json!({"source_root": tree}).to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.join("proj/obj/project.assets.json"),
            json!({"libraries": {
                "SharpFuzz/2.3.0": {"type": "package"},
                "Widget.Codec.Absent/9.9.9": {"type": "package"},
                "Widget": {"type": "project"},
            }})
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            resolved_packages(&dir).unwrap(),
            vec![("Widget.Codec.Absent".to_owned(), "9.9.9".to_owned())]
        );
        let harness = HarnessContext {
            work_dir: work,
            harness_id: "H-S0001-00000001".to_owned(),
            harness_dir: dir,
        };
        let error = match CSHARP_LANE.plan_capsule(&harness) {
            Err(error) => error,
            Ok(_) => panic!("an uncached package must be refused"),
        };
        let refusal = error.downcast_ref::<super::super::PlanRefusal>().unwrap();
        assert!(refusal.0.contains("Widget.Codec.Absent 9.9.9"), "{refusal}");
        assert!(refusal.0.contains("offline"), "{refusal}");
    }
}
