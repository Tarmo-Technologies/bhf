// SPDX-License-Identifier: Apache-2.0

//! A C# finding names its `.cs` file and line (#212). SharpFuzz rewrites the
//! target assembly without its debug symbols, so the fuzzed build's frames
//! name none (`at Acme.Tlv.Parser.Pick(Byte[] data)`). bhf keeps the build as
//! it was before instrumentation and re-runs a finding's input through it for
//! the lines.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
                      <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n</Project>\n";

/// The out-of-range read is on line 7.
const PARSER_CS: &str = "namespace Acme.Tlv\n{\n    public static class Parser\n    {\n        \
     public static int Pick(byte[] data)\n        {\n            \
     return data.Length > 0 && data[0] == 0x7f ? data[data.Length + 1] : 0;\n        \
     }\n    }\n}\n";

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
fn a_csharp_finding_names_the_cs_file_and_line() {
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
    let root = TestDir::new("auto-csharp-lines");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("Tlv.csproj"), CSPROJ).unwrap();
    std::fs::write(src.join("Parser.cs"), PARSER_CS).unwrap();
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"\x7f\x01").unwrap();
    let work = root.join("work");
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--per-target-time", "6", "--run-untrusted", "--jobs", "1"])
        .arg("--seed-file")
        .arg(&seed)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    let findings: Vec<serde_json::Value> = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.path().join("finding.json")).ok()?).ok()
        })
        .collect();
    let finding = findings
        .iter()
        .find(|finding| finding.to_string().contains("IndexOutOfRange"))
        .unwrap_or_else(|| panic!("the out-of-range read is found: {findings:#?}\n{stderr}"));
    let top = &finding["exception"]["stack"][0];
    assert!(
        top["function"]
            .as_str()
            .is_some_and(|function| function.contains("Parser.Pick")),
        "{finding:#}"
    );
    assert!(
        top["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("Parser.cs")),
        "{finding:#}"
    );
    assert_eq!(top["line"], 7, "{finding:#}");
    let sarif = std::fs::read_to_string(work.join("results/findings.sarif")).unwrap();
    assert!(
        sarif.contains("Parser.cs"),
        "SARIF names the source: {sarif}"
    );
}
