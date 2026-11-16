// SPDX-License-Identifier: Apache-2.0

//! The C# harness builds wrote `bin/` and `obj/` into the project's own tree,
//! and two harnesses of one project built at once raced on its `obj/`
//! (MSB4018 in GenerateDepsFile, CS2012). With the default `--jobs` (half the
//! cores) most targets of a project failed. Each harness build now gives every
//! project its own `obj/` and `bin/` under the harness: every target builds, at
//! the default `--jobs` and at `--jobs 2`, and the tree is left as it was.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
                      <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n</Project>\n";

/// Four fuzzable methods of one class in one project.
const PARSER_CS: &str = "namespace Widget\n{\n    public static class Parser\n    {\n        \
     public static int ParseRecord(byte[] data) { return data.Length > 0 && data[0] == 0x41 ? 1 : 0; }\n        \
     public static int ParseHeader(byte[] data) { return data.Length > 1 && data[1] == 0x42 ? 2 : 0; }\n        \
     public static int ParseTrailer(byte[] data) { return data.Length > 2 && data[2] == 0x43 ? 3 : 0; }\n        \
     public static int ParseBody(byte[] data) { return data.Length > 3 && data[3] == 0x44 ? 4 : 0; }\n    \
     }\n}\n";

/// Every path under `root`, relative to it.
fn tree(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            out.push(path.strip_prefix(root).unwrap().to_path_buf());
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    out.sort();
    out
}

fn sharpfuzz_package_cached() -> bool {
    let packages = std::env::var_os("NUGET_PACKAGES")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|home| PathBuf::from(home).join(".nuget/packages"))
        });
    packages.is_some_and(|dir| dir.join("sharpfuzz/2.3.0/.nupkg.metadata").is_file())
}

#[test]
fn every_target_of_one_project_builds_and_the_tree_is_unchanged() {
    if Command::new("dotnet").arg("--version").output().is_err() {
        eprintln!("skipping: no dotnet");
        return;
    }
    let sharpfuzz = which::which("sharpfuzz").is_ok()
        || std::env::var_os("HOME")
            .is_some_and(|home| Path::new(&home).join(".dotnet/tools/sharpfuzz").is_file());
    if !sharpfuzz || !sharpfuzz_package_cached() {
        eprintln!("skipping: needs the sharpfuzz tool and the SharpFuzz 2.3.0 NuGet package");
        return;
    }
    let root = TestDir::new("auto-csharp-isolation");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("Widget.csproj"), CSPROJ).unwrap();
    std::fs::write(src.join("Parser.cs"), PARSER_CS).unwrap();
    let before = tree(&src);
    for (label, jobs) in [("default", None), ("jobs-2", Some("2"))] {
        let work = root.join(format!("work-{label}"));
        let mut auto = support::bhf_cargo_command();
        auto.current_dir(root.path())
            .args(["auto", "--work-dir", work.to_str().unwrap()])
            .args(["--per-target-time", "1", "--run-untrusted"]);
        if let Some(jobs) = jobs {
            auto.args(["--jobs", jobs]);
        }
        let out = auto.arg(src.to_str().unwrap()).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || out.status.code() == Some(1),
            "{label}: {stderr}"
        );
        let run: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let targets = run["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 4, "{label}: {stderr}");
        for target in targets {
            assert_eq!(
                target["outcome"]["outcome"], "built_and_fuzzed",
                "{label}: {target:#}"
            );
        }
        assert_eq!(tree(&src), before, "{label}: the source tree changed");
    }
}
