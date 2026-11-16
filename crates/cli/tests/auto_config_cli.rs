// SPDX-License-Identifier: Apache-2.0
//
// `bhf auto` project config file. A `.bhf.toml` in the scanned tree is
// auto-loaded, but — because that tree is untrusted — its build-EXECUTING keys
// (build-command / run-untrusted / unsafe-search-and-run…) are ignored unless the
// config is passed explicitly with `--config`. Safe knobs apply either way. Uses
// `--dry-run` so the test is fast and never actually builds.

use std::path::PathBuf;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The `bhf` binary cargo built for these tests (`bhf.exe` on Windows).
fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

#[test]
fn auto_loaded_config_ignores_build_executing_keys_but_explicit_config_honors_them() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built");
        return;
    }
    let tmp = TestDir::new("config");
    let src = tmp.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("a.c"),
        "int process(const char *d, unsigned long n){ return n>0?d[0]:0; }\n",
    )
    .unwrap();
    // A safe knob plus a build-EXECUTING key.
    let cfg = src.join(".bhf.toml");
    std::fs::write(&cfg, "per-target-time = 1\nbuild-command = \"./x.sh\"\n").unwrap();

    let stderr = |extra: &[&str]| -> String {
        let mut args = vec!["auto", src.to_str().unwrap(), "--dry-run"];
        args.extend_from_slice(extra);
        let out = Command::new(&bin).args(args).output().expect("run auto");
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // Auto-loaded: config is loaded, but the build-command key is ignored (untrusted).
    let auto = stderr(&[]);
    assert!(
        auto.contains("loaded config from"),
        "config should load:\n{auto}"
    );
    assert!(
        auto.contains("ignoring build-executing keys"),
        "auto-loaded build-command must be ignored:\n{auto}"
    );

    // Explicit --config: the same file is trusted, so the key is honored (no warning).
    let explicit = stderr(&["--config", cfg.to_str().unwrap()]);
    assert!(
        explicit.contains("loaded config from"),
        "config should load:\n{explicit}"
    );
    assert!(
        !explicit.contains("ignoring build-executing keys"),
        "an explicit --config must honor build-command:\n{explicit}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// A config `jobs` key sets the job count whatever the host's default is, and
/// a `--jobs` the command line gives wins over it, even with that default's
/// value.
#[test]
fn config_jobs_applies_whatever_the_host_default() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("a.c"),
        "int process(const char *d, unsigned long n){ return n>0?d[0]:0; }\n",
    )
    .unwrap();
    let cfg = tmp.path().join("jobs.toml");
    std::fs::write(&cfg, "jobs = 1\n").unwrap();
    let jobs_of = |extra: &[&str]| -> (u64, String) {
        let work = tmp.path().join("w");
        let _ = std::fs::remove_dir_all(&work);
        let out = Command::new(&bin)
            .arg("auto")
            .arg(&src)
            .arg("--work-dir")
            .arg(&work)
            .arg("--config")
            .arg(&cfg)
            .arg("--dry-run")
            .args(extra)
            .env("BHF_DEFAULT_JOBS", "3")
            .output()
            .expect("run auto");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let context: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.join("auto/support-context.json"))
                .unwrap_or_else(|error| panic!("no support context ({error}):\n{stderr}")),
        )
        .unwrap();
        (context["jobs"].as_u64().expect("jobs"), stderr)
    };
    let (jobs, stderr) = jobs_of(&[]);
    assert_eq!(jobs, 1, "the config's jobs must apply:\n{stderr}");
    let (jobs, stderr) = jobs_of(&["--jobs", "3"]);
    assert_eq!(
        jobs, 3,
        "an explicit --jobs wins over the config:\n{stderr}"
    );
}
