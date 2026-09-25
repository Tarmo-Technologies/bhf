// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fs::{self, File};
    use std::io::Read;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn run_step(name: &str, root: &Path, args: Vec<OsString>, deadline: Duration) {
        let log_path = root.join(format!("{name}.log"));
        let log = File::create(&log_path).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .args(&args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let expires = Instant::now() + deadline;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= expires {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{name} exceeded {deadline:?}; see {}", log_path.display());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if !status.success() {
            let mut excerpt = String::new();
            File::open(&log_path)
                .unwrap()
                .take(64 * 1024)
                .read_to_string(&mut excerpt)
                .unwrap();
            panic!("{name} failed with {status}: {excerpt}");
        }
    }

    #[test]
    fn generated_c_build_uses_framed_protocol_coverage_and_reports_crash() {
        if which::which("clang").is_err() || which::which("make").is_err() {
            eprintln!("skipping C protocol integration: clang or make unavailable");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        let generated = work.join("generated_harnesses");
        let source = root.path().join("planted.c");
        fs::create_dir_all(&generated).unwrap();
        fs::write(
            &source,
            "#include <stddef.h>\n#include <stdlib.h>\n\
             int target_one_input(const unsigned char *data, size_t size) {\n\
             if (size && data[0] == 'X') {\n\
                 char *small = malloc(2);\n\
                 volatile size_t bad_index = 8;\n\
                 small[bad_index] = (char)data[0];\n\
                 free(small);\n\
                 return 1;\n\
             }\n\
             return 0;\n}\n",
        )
        .unwrap();
        let id = "H-MANUAL-PROTOCOL";
        run_step(
            "generate",
            root.path(),
            vec![
                "generate-harness".into(),
                source.into_os_string(),
                "--target".into(),
                "target_one_input".into(),
                "--output".into(),
                generated.clone().into_os_string(),
                "--id".into(),
                id.into(),
            ],
            Duration::from_secs(30),
        );
        let generated_source = generated.join(id).join("main.c");
        assert!(fs::read_to_string(&generated_source)
            .unwrap()
            .contains("BHF_FRAMED"));
        run_step(
            "build",
            root.path(),
            vec![
                "build".into(),
                work.clone().into_os_string(),
                "--harness".into(),
                id.into(),
            ],
            Duration::from_secs(90),
        );
        let built = work.join("build").join(id).join("main");
        assert!(built.is_file());
        assert!(!built.parent().unwrap().join("main.c").exists());
        run_step(
            "fuzz",
            root.path(),
            vec![
                "fuzz".into(),
                work.clone().into_os_string(),
                "--harness".into(),
                id.into(),
                "--iterations".into(),
                "4".into(),
                "--seed-input".into(),
                "X".into(),
                "--max-len".into(),
                "8".into(),
                "--len-control".into(),
                "0".into(),
                "--timeout".into(),
                "2s".into(),
                "--fork-server".into(),
                "--sandbox".into(),
                "none".into(),
            ],
            Duration::from_secs(20),
        );
        let summary: serde_json::Value = serde_json::from_slice(
            &fs::read(work.join("fuzz_runs").join(format!("{id}-latest.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(summary["harness_path"], built.to_string_lossy().as_ref());
        assert_eq!(summary["execution"]["harness_protocol"], "bhf_framed");
        assert_eq!(summary["execution"]["forkserver"], true);
        assert!(
            summary["coverage"]["edges"].as_u64().unwrap_or(0) > 0,
            "expected measured driver coverage: {summary}"
        );
        let findings = summary["findings"].as_array().unwrap();
        assert!(!findings.is_empty(), "expected planted crash: {summary}");
        let first = findings[0].as_str().unwrap();
        let finding: serde_json::Value = serde_json::from_slice(
            &fs::read(work.join("findings").join(first).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(finding["exception"]["sanitizer"], "asan");
        assert_eq!(
            fs::read(work.join("findings").join(first).join("testcase.bin")).unwrap(),
            b"X"
        );

        // Exercise the same generated binary without a persistent child. This
        // is also the path used to isolate an input after the framed child dies.
        let fallback_work = root.path().join("fallback");
        let fallback_build = fallback_work.join("build").join(id);
        let fallback_source = fallback_work.join("generated_harnesses").join(id);
        fs::create_dir_all(&fallback_build).unwrap();
        fs::create_dir_all(&fallback_source).unwrap();
        fs::copy(&built, fallback_build.join("main")).unwrap();
        fs::copy(&generated_source, fallback_source.join("main.c")).unwrap();
        run_step(
            "fuzz-no-fork",
            root.path(),
            vec![
                "fuzz".into(),
                fallback_work.clone().into_os_string(),
                "--harness".into(),
                id.into(),
                "--iterations".into(),
                "1".into(),
                "--seed-input".into(),
                "X".into(),
                "--no-fork-server".into(),
                "--sandbox".into(),
                "none".into(),
            ],
            Duration::from_secs(20),
        );
        let fallback: serde_json::Value = serde_json::from_slice(
            &fs::read(
                fallback_work
                    .join("fuzz_runs")
                    .join(format!("{id}-latest.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(fallback["execution"]["harness_protocol"], "bhf_framed");
        assert_eq!(fallback["execution"]["forkserver"], false);
        assert!(fallback["coverage"]["edges"].as_u64().unwrap_or(0) > 0);
        assert_eq!(fallback["findings"].as_array().unwrap().len(), 1);
    }
}
