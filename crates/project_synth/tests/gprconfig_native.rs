// SPDX-License-Identifier: Apache-2.0

//! The generated project must load in gprbuild with the toolchain settings
//! `bhf build --toolchain <prefix>` writes. A tool prefix written as
//! `Toolchain_Name` matches no compiler in gprconfig's knowledge base, so the
//! project has no Ada compiler; as `Target` it selects the matching GNAT. Run
//! against the host GNAT with the host triple as the prefix; skipped without
//! gprbuild.

use std::path::PathBuf;
use std::process::Command;

use ada_parser::ast::AdaStandard;
use project_synth::{write_project, ProjectSpec, SourceRoot, Switches};

fn host_triple() -> Option<String> {
    let output = Command::new("gcc").arg("-dumpmachine").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|triple| !triple.is_empty())
}

#[test]
fn a_native_tool_prefix_configures_gprbuild_for_the_host_gnat() {
    if Command::new("gprbuild").arg("--version").output().is_err() {
        eprintln!("skip: gprbuild unavailable");
        return;
    }
    let Some(triple) = host_triple() else {
        eprintln!("skip: no host gcc to name the native triple");
        return;
    };
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-gprconfig-native-{nonce}"));
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(dir.join("obj")).unwrap();
    std::fs::write(
        src.join("main.adb"),
        "procedure Main is\nbegin\n   null;\nend Main;\n",
    )
    .unwrap();
    let spec = ProjectSpec {
        project_name: "Bhf_Build".to_owned(),
        extends_project: None,
        source_roots: vec![SourceRoot {
            path: src.clone(),
            language: "Ada".to_owned(),
        }],
        object_dir: dir.join("obj"),
        exec_dir: None,
        main_adb: Some("main.adb".to_owned()),
        ada_standard: AdaStandard::Ada2012,
        target: None,
        runtime: None,
        toolchain: Some(triple.clone()),
        switches: Switches::default(),
        with_clauses: Vec::new(),
        executable_name: None,
        compile_c: false,
        excluded_source_files: Vec::new(),
    };
    let project: PathBuf = dir.join("bhf_build.gpr");
    write_project(&spec, &project).unwrap();
    let output = Command::new("gprbuild")
        .arg("-P")
        .arg(&project)
        .arg("-q")
        .output()
        .unwrap();
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "gprbuild must find the {triple} GNAT for the generated project:\n{text}\n{}",
        std::fs::read_to_string(&project).unwrap()
    );
    assert!(!text.contains("can't find"), "{text}");
    assert!(dir.join("obj/main").is_file() || dir.join("obj/main.exe").is_file());
    let _ = std::fs::remove_dir_all(&dir);
}
