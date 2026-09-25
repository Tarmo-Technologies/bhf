// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[test]
fn offline_dist_packager_advertises_binary_only_content_pack_flow() {
    let root = repo_root();
    let script = root.join("scripts/package-offline-dist.sh");

    assert!(script.is_file(), "missing {}", script.display());

    let output = Command::new("bash")
        .arg(&script)
        .arg("--help")
        .output()
        .expect("run package-offline-dist --help");

    assert_success(output, "package-offline-dist --help");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--help")
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    assert!(stdout.contains("--sbom-cve-db"));
    assert!(stdout.contains("--binary-cve-db"));
    assert!(stdout.contains("--seed-dir"));
    assert!(stdout.contains("--artifact-dir"));
    assert!(stdout.contains("dist/content-inputs/sbom-cves.json"));
    assert!(stdout.contains("dist/content-inputs/binary-cves.json"));
    assert!(stdout.contains("smoke"));
    assert!(stdout.contains("install.sh"));
    assert!(stdout.contains("INSTALL.md"));
    assert!(stdout.contains("LICENSE"));
    assert!(stdout.contains("README.md"));
    assert!(stdout.contains("RELEASE_NOTES.md"));
    assert!(stdout.contains("RUN-BHF.md"));
    assert!(stdout.contains("bhf-bug-report"));
    assert!(stdout.contains("does not include BHF source"));
}

#[test]
fn offline_dist_packager_generates_default_content_inputs_when_omitted() {
    let root = repo_root();
    let script = root.join("scripts/package-offline-dist.sh");
    let out_dir = temp_dir("dist-package-default-inputs");

    let output = Command::new("bash")
        .arg(&script)
        .arg("--dry-run")
        .arg("--skip-build")
        .arg("--legacy-integrity-only")
        .arg("--out")
        .arg(&out_dir)
        .arg("--version")
        .arg("test")
        .output()
        .expect("run package-offline-dist dry-run");

    assert_success(output, "package-offline-dist dry-run");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--dry-run")
            .arg("--skip-build")
            .arg("--legacy-integrity-only")
            .arg("--out")
            .arg(&out_dir)
            .arg("--version")
            .arg("test")
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    assert!(stdout.contains("content-inputs/sbom-cves.json"));
    assert!(stdout.contains("content-inputs/binary-cves.json"));
    assert!(stdout.contains("content-inputs/seeds"));
    assert!(!stdout.contains("missing --sbom-cve-db"));
    assert!(!stdout.contains("missing --binary-cve-db"));
}

#[test]
fn offline_dist_packager_rejects_dot_names_before_cleanup() {
    let root = repo_root();
    let output_dir = temp_dir("dist-unsafe-name");
    let sentinel = output_dir.join("keep.txt");
    fs::write(&sentinel, "keep").unwrap();
    for name in [".", "..", "!!!"] {
        let output = Command::new("bash")
            .arg(root.join("scripts/package-offline-dist.sh"))
            .args(["--name", name, "--out"])
            .arg(&output_dir)
            .args([
                "--dry-run",
                "--skip-build",
                "--legacy-integrity-only",
                "--version",
                "test",
            ])
            .output()
            .expect("run packager with unsafe name");
        assert!(!output.status.success(), "{name:?} was accepted");
        assert!(sentinel.is_file(), "{name:?} removed output contents");
    }
}

#[cfg(unix)]
#[test]
fn offline_dist_installer_keeps_existing_backup_on_timestamp_collision() {
    let bundle = temp_dir("dist-backup-collision");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let fake_bin = bundle.join("fake-bin");
    fs::create_dir(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("date"),
        "#!/bin/sh\nprintf '20260924000000\\n'\n",
    );
    let prefix = bundle.join("install");
    fs::create_dir_all(prefix.join("packs/user")).unwrap();
    fs::create_dir_all(prefix.join("corpora/user")).unwrap();
    fs::write(prefix.join("previous.txt"), "previous").unwrap();
    fs::write(prefix.join("packs/user/keep.txt"), "pack").unwrap();
    fs::write(prefix.join("corpora/user/keep.txt"), "corpus").unwrap();
    let bin_dir = bundle.join("bin");
    fs::create_dir(&bin_dir).unwrap();
    std::os::unix::fs::symlink(prefix.join("bhf"), bin_dir.join("bhf")).unwrap();
    let existing_backup = bundle.join("install.backup.20260924000000");
    fs::create_dir(&existing_backup).unwrap();
    fs::write(existing_backup.join("older.txt"), "older").unwrap();

    let output = installer_command_with_symlinks(&bundle, &prefix, &bin_dir)
        .arg("--allow-legacy-integrity-only")
        .arg("--no-smoke")
        .env(
            "PATH",
            format!("{}:{}", fake_bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .expect("install with colliding backup timestamp");
    assert_success(output, "install with colliding backup timestamp");
    assert_eq!(
        fs::read_to_string(existing_backup.join("older.txt")).unwrap(),
        "older"
    );
    assert_eq!(
        fs::read_to_string(bundle.join("install.backup.20260924000000.1/previous.txt")).unwrap(),
        "previous"
    );
    assert_eq!(
        fs::read_to_string(prefix.join("packs/user/keep.txt")).unwrap(),
        "pack"
    );
    assert_eq!(
        fs::read_to_string(prefix.join("corpora/user/keep.txt")).unwrap(),
        "corpus"
    );
    assert_eq!(
        fs::read_link(bin_dir.join("bhf")).unwrap(),
        prefix.join("bhf")
    );
}

#[cfg(unix)]
#[test]
fn offline_dist_installer_verifies_pack_before_replacing_prefix() {
    let bundle = temp_dir("dist-bad-pack");
    create_minimal_bundle(&bundle);
    write_executable(
        &bundle.join("tool/bhf"),
        "#!/bin/sh\nif [ \"$1 $2\" = 'pack verify' ]; then exit 42; fi\nexit 0\n",
    );
    let prefix = bundle.join("install");
    fs::create_dir(&prefix).unwrap();
    fs::write(prefix.join("previous.txt"), "previous").unwrap();
    let output = installer_command(&bundle, &prefix)
        .arg("--allow-legacy-integrity-only")
        .arg("--no-smoke")
        .output()
        .expect("install with invalid pack");
    assert!(!output.status.success(), "invalid pack was accepted");
    assert_eq!(
        fs::read_to_string(prefix.join("previous.txt")).unwrap(),
        "previous"
    );
}

#[cfg(unix)]
#[test]
fn offline_dist_installer_pack_install_failure_keeps_current_install() {
    let bundle = temp_dir("dist-pack-install-failure");
    create_minimal_bundle(&bundle);
    write_executable(
        &bundle.join("tool/bhf"),
        "#!/bin/sh\nif [ \"$1 $2\" = 'pack install' ]; then exit 42; fi\nexit 0\n",
    );
    let prefix = bundle.join("install");
    let existing_pack = prefix.join("packs/user/keep.txt");
    let existing_corpus = prefix.join("corpora/user/keep.txt");
    fs::create_dir_all(existing_pack.parent().unwrap()).unwrap();
    fs::create_dir_all(existing_corpus.parent().unwrap()).unwrap();
    fs::write(&existing_pack, "pack").unwrap();
    fs::write(&existing_corpus, "corpus").unwrap();
    fs::write(prefix.join("bhf"), "previous binary").unwrap();
    let bin_dir = bundle.join("bin");
    fs::create_dir(&bin_dir).unwrap();
    std::os::unix::fs::symlink(prefix.join("bhf"), bin_dir.join("bhf")).unwrap();

    let output = installer_command_with_symlinks(&bundle, &prefix, &bin_dir)
        .arg("--allow-legacy-integrity-only")
        .arg("--no-smoke")
        .output()
        .expect("install with failing content-pack install");
    assert!(!output.status.success(), "pack install failure was ignored");
    assert_eq!(
        fs::read_to_string(prefix.join("bhf")).unwrap(),
        "previous binary"
    );
    assert_eq!(fs::read_to_string(&existing_pack).unwrap(), "pack");
    assert_eq!(fs::read_to_string(&existing_corpus).unwrap(), "corpus");
    assert_eq!(
        fs::read_link(bin_dir.join("bhf")).unwrap(),
        prefix.join("bhf")
    );
}

#[cfg(unix)]
#[test]
fn offline_dist_installer_smoke_failure_keeps_current_install() {
    let bundle = temp_dir("dist-smoke-failure");
    create_minimal_bundle(&bundle);
    write_executable(
        &bundle.join("tool/bhf"),
        "#!/bin/sh\nif [ \"$1\" = auto ]; then exit 43; fi\nexit 0\n",
    );
    let fake_bin = bundle.join("fake-bin");
    fs::create_dir(&fake_bin).unwrap();
    write_executable(&fake_bin.join("clang"), "#!/bin/sh\nexit 0\n");
    write_executable(&fake_bin.join("make"), "#!/bin/sh\nexit 0\n");
    let prefix = bundle.join("install");
    fs::create_dir(&prefix).unwrap();
    fs::write(prefix.join("bhf"), "previous binary").unwrap();
    let bin_dir = bundle.join("bin");
    fs::create_dir(&bin_dir).unwrap();
    std::os::unix::fs::symlink(prefix.join("bhf"), bin_dir.join("bhf")).unwrap();

    let output = installer_command_with_symlinks(&bundle, &prefix, &bin_dir)
        .arg("--no-content")
        .env(
            "PATH",
            format!("{}:{}", fake_bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .expect("install with failing smoke test");
    assert!(!output.status.success(), "smoke failure was ignored");
    assert_eq!(
        fs::read_to_string(prefix.join("bhf")).unwrap(),
        "previous binary"
    );
    assert_eq!(
        fs::read_link(bin_dir.join("bhf")).unwrap(),
        prefix.join("bhf")
    );
}

#[cfg(unix)]
#[test]
fn installer_rejects_fifo_and_symlink_seed_members_before_activation() {
    let bundle = temp_dir("unsafe-seeds");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let prefix = bundle.join("install");
    fs::create_dir(&prefix).unwrap();
    fs::write(prefix.join("previous.txt"), b"previous").unwrap();
    let outside = bundle.join("outside-sentinel");
    fs::write(&outside, b"outside").unwrap();
    let seed_source = bundle.join("seed-source");
    fs::create_dir(&seed_source).unwrap();
    let seed_tar = bundle.join("content/packs/current/corpus/seeds.tar.gz");
    fs::create_dir_all(seed_tar.parent().unwrap()).unwrap();
    assert_success(
        Command::new("mkfifo")
            .arg(seed_source.join("seed.pipe"))
            .output()
            .unwrap(),
        "create FIFO fixture",
    );
    assert_success(
        Command::new("tar")
            .arg("-C")
            .arg(&seed_source)
            .arg("-czf")
            .arg(&seed_tar)
            .arg(".")
            .output()
            .unwrap(),
        "archive FIFO fixture",
    );
    let install = || {
        installer_command(&bundle, &prefix)
            .args([
                "--allow-legacy-integrity-only",
                "--install-seeds",
                "--no-smoke",
            ])
            .output()
            .unwrap()
    };
    assert!(!install().status.success(), "FIFO seed member was accepted");
    fs::remove_file(seed_source.join("seed.pipe")).unwrap();
    std::os::unix::fs::symlink("../../../outside-sentinel", seed_source.join("escape-link"))
        .unwrap();
    assert_success(
        Command::new("tar")
            .arg("-C")
            .arg(&seed_source)
            .arg("-czf")
            .arg(&seed_tar)
            .arg(".")
            .output()
            .unwrap(),
        "archive symlink fixture",
    );
    assert!(
        !install().status.success(),
        "symlink seed member was accepted"
    );
    assert_eq!(fs::read(prefix.join("previous.txt")).unwrap(), b"previous");
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert!(!prefix.join("corpora").exists());
}

#[cfg(unix)]
#[test]
fn installer_rejects_oversized_compressed_seed_archive_before_activation() {
    let bundle = temp_dir("large-seeds");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let seed_tar = bundle.join("content/packs/current/corpus/seeds.tar.gz");
    fs::create_dir_all(seed_tar.parent().unwrap()).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&seed_tar)
        .unwrap()
        .set_len(2 * 1024 * 1024 * 1024 + 1)
        .unwrap();
    let prefix = bundle.join("install");
    fs::create_dir(&prefix).unwrap();
    fs::write(prefix.join("previous.txt"), b"previous").unwrap();
    let output = installer_command(&bundle, &prefix)
        .args([
            "--allow-legacy-integrity-only",
            "--install-seeds",
            "--no-smoke",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("2 GiB compressed"));
    assert_eq!(fs::read(prefix.join("previous.txt")).unwrap(), b"previous");
}

#[cfg(unix)]
#[test]
fn installer_stages_valid_seeds_and_retains_previous_seed_directory() {
    let bundle = temp_dir("safe-seeds");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let source = bundle.join("seed-source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("new-seed"), b"new").unwrap();
    let seed_tar = bundle.join("content/packs/current/corpus/seeds.tar.gz");
    fs::create_dir_all(seed_tar.parent().unwrap()).unwrap();
    assert_success(
        Command::new("tar")
            .arg("-C")
            .arg(&source)
            .arg("-czf")
            .arg(&seed_tar)
            .arg(".")
            .output()
            .unwrap(),
        "archive safe seeds",
    );
    let prefix = bundle.join("install");
    fs::create_dir_all(prefix.join("corpora/seeds")).unwrap();
    fs::write(prefix.join("corpora/seeds/old-seed"), b"old").unwrap();
    assert_success(
        installer_command(&bundle, &prefix)
            .args([
                "--allow-legacy-integrity-only",
                "--install-seeds",
                "--no-smoke",
            ])
            .output()
            .unwrap(),
        "install safe seeds",
    );
    assert_eq!(
        fs::read(prefix.join("corpora/seeds/new-seed")).unwrap(),
        b"new"
    );
    let previous = fs::read_dir(prefix.join("corpora"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("seeds.previous.")
        })
        .expect("previous seeds retained");
    assert_eq!(fs::read(previous.join("old-seed")).unwrap(), b"old");
}

#[cfg(unix)]
#[test]
fn installer_extracts_installed_seed_copy_if_bundle_changes_after_pack_install() {
    let bundle = temp_dir("seed-pack-snapshot");
    create_minimal_bundle(&bundle);
    let binary = bundle.join("tool/bhf");
    let original_script = fs::read_to_string(&binary).unwrap();
    // The fake pack command copies into the staged install, then changes the
    // original archive. The installer must extract the staged copy.
    let script = original_script.replacen(
        "printf '{\"valid\":true,\"pack_id\":\"test-pack\"}\\n' > \"$output\"\n",
        "printf '{\"valid\":true,\"pack_id\":\"test-pack\"}\\n' > \"$output\"\n: > \"$pack_root/corpus/seeds.tar.gz\"\n",
        1,
    );
    assert_ne!(
        script, original_script,
        "fake pack mutation hook was absent"
    );
    fs::write(&binary, script).unwrap();
    make_executable(&binary);
    let source = bundle.join("seed-source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("trusted-seed"), b"trusted").unwrap();
    let seed_tar = bundle.join("content/packs/current/corpus/seeds.tar.gz");
    fs::create_dir_all(seed_tar.parent().unwrap()).unwrap();
    assert_success(
        Command::new("tar")
            .arg("-C")
            .arg(&source)
            .arg("-czf")
            .arg(&seed_tar)
            .arg(".")
            .output()
            .unwrap(),
        "archive trusted seed",
    );
    let prefix = bundle.join("install");
    assert_success(
        installer_command(&bundle, &prefix)
            .args([
                "--allow-legacy-integrity-only",
                "--install-seeds",
                "--no-smoke",
            ])
            .output()
            .unwrap(),
        "install seed from pack snapshot",
    );
    assert_eq!(
        fs::read(prefix.join("corpora/seeds/trusted-seed")).unwrap(),
        b"trusted"
    );
    assert_eq!(fs::metadata(seed_tar).unwrap().len(), 0);
}

#[cfg(unix)]
#[test]
fn installer_seed_dry_run_does_not_read_nonexistent_install_result() {
    let bundle = temp_dir("seed-dry-run");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let seed_tar = bundle.join("content/packs/current/corpus/seeds.tar.gz");
    fs::create_dir_all(seed_tar.parent().unwrap()).unwrap();
    fs::write(&seed_tar, b"dry-run placeholder").unwrap();
    let prefix = bundle.join("install");
    let output = installer_command(&bundle, &prefix)
        .args([
            "--allow-legacy-integrity-only",
            "--install-seeds",
            "--dry-run",
            "--no-smoke",
        ])
        .output()
        .unwrap();
    assert_success(output, "dry run with seeds");
    assert!(!prefix.exists());
}

#[cfg(unix)]
#[test]
fn offline_dist_installer_restores_previous_prefix_if_activation_move_fails() {
    let bundle = temp_dir("dist-activation-failure");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let fake_bin = bundle.join("fake-bin");
    fs::create_dir(&fake_bin).unwrap();
    write_executable(
        &fake_bin.join("mv"),
        "#!/bin/sh\ncase \"$2\" in *.new.*) exit 71 ;; esac\nexec /bin/mv \"$@\"\n",
    );
    let prefix = bundle.join("install");
    fs::create_dir(&prefix).unwrap();
    fs::write(prefix.join("bhf"), "previous binary").unwrap();
    let output = installer_command(&bundle, &prefix)
        .args(["--no-content", "--no-smoke"])
        .env(
            "PATH",
            format!("{}:{}", fake_bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .expect("install with failing activation move");
    assert!(
        !output.status.success(),
        "activation move failure was ignored"
    );
    assert_eq!(
        fs::read_to_string(prefix.join("bhf")).unwrap(),
        "previous binary"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("previous install restored"));
}

#[cfg(unix)]
#[test]
fn offline_dist_installer_preserves_explicit_smoke_work_directory() {
    let bundle = temp_dir("dist-smoke-preserve");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let fake_bin = bundle.join("fake-bin");
    fs::create_dir(&fake_bin).unwrap();
    write_executable(&fake_bin.join("clang"), "#!/bin/sh\nexit 0\n");
    write_executable(&fake_bin.join("make"), "#!/bin/sh\nexit 0\n");
    let smoke = bundle.join("smoke-work");
    fs::create_dir(&smoke).unwrap();
    fs::write(smoke.join("keep.txt"), "keep").unwrap();
    let prefix = bundle.join("install");
    let output = installer_command(&bundle, &prefix)
        .args(["--no-content", "--smoke-work-dir"])
        .arg(&smoke)
        .env(
            "PATH",
            format!("{}:{}", fake_bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .expect("install with explicit smoke work directory");
    assert_success(output, "install with explicit smoke work directory");
    assert_eq!(fs::read_to_string(smoke.join("keep.txt")).unwrap(), "keep");
}

#[cfg(unix)]
#[test]
fn offline_dist_installer_rejects_bundle_root_as_install_prefix() {
    let bundle = temp_dir("dist-unsafe-prefix");
    create_minimal_bundle(&bundle);
    make_executable(&bundle.join("tool/bhf"));
    let sentinel = bundle.join("keep.txt");
    fs::write(&sentinel, "keep").unwrap();
    let output = installer_command(&bundle, &bundle)
        .args(["--no-content", "--no-smoke"])
        .output()
        .expect("install with unsafe prefix");
    assert!(
        !output.status.success(),
        "bundle root was accepted as prefix"
    );
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep");
    assert!(bundle.join("tool/bhf").is_file());
}

#[test]
fn offline_dist_readme_documents_install_options_without_source_tree_note() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();
    let readme = extract_readme_dist_template(&script);

    for expected in [
        "--prefix DIR",
        "--bin-dir DIR",
        "--non-interactive",
        "--languages LIST",
        "c,cpp,rust,java,python,perl,go,ada,cobol,",
        "fortran,csharp,javascript,typescript,ruby,lua,php,all,none",
        "--targets LIST",
        "native,windows,aarch64,all,none",
        "--fuzzers LIST",
        "builtin,afl,all,none",
        "--extras LIST",
        "build-recovery,sandbox,archives,all,none",
        "--install-seeds",
        "--package-manager NAME",
        "--no-system-packages",
        "--no-apt",
        "--no-rustup",
        "--no-content",
        "--no-symlink",
        "--no-smoke",
        "--smoke-work-dir DIR",
        "--dry-run",
        "-h, --help",
        "./install.sh --non-interactive",
        "--languages c,cpp,rust",
        "--targets native,aarch64",
        "--fuzzers builtin,afl",
        "--extras build-recovery,archives",
        "--languages all",
        "--targets all",
        "--fuzzers all",
        "--extras all",
        "all-in-one Linux package",
        "both Linux preload shims",
        "INSTALL.md",
        "LICENSE",
        "README.md",
        "RELEASE_NOTES.md",
        "manually co-locate",
        "bhf-bug-report",
    ] {
        assert!(
            readme.contains(expected),
            "README-DIST template missing {expected:?}:\n{readme}"
        );
    }
    // The binary-only dist README must not carry a build-from-source install
    // instruction (it may still discuss operating bhf ON a source tree, and
    // note that the dist "does not include BHF source").
    let lower = readme.to_lowercase();
    assert!(!lower.contains("build from source"));
    assert!(!lower.contains("git clone"));
    assert!(!lower.contains("cargo build"));
}

#[test]
fn offline_dist_run_guide_is_packaged_and_documents_core_workflows() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();
    let readme = extract_readme_dist_template(&script);
    let run_guide = extract_run_guide_template(&script);

    assert!(
        script.contains("cat >\"$STAGE_ROOT/RUN-BHF.md\" <<"),
        "packager must write RUN-BHF.md into the staged tarball root"
    );
    assert!(
        readme.contains("RUN-BHF.md"),
        "README-DIST should point installed operators at the run guide:\n{readme}"
    );
    assert!(
        readme.contains("AUTO-OFFLINE-RUNBOOK.md"),
        "README-DIST should point operators at the offline auto runbook:\n{readme}"
    );
    assert!(
        script.contains(
            "cp \"$REPO_ROOT/docs/site/offline-auto-runbook.md\" \"$STAGE_ROOT/AUTO-OFFLINE-RUNBOOK.md\""
        ),
        "packager must put the offline auto runbook in the distribution root"
    );
    assert!(
        script.contains(
            "cp \"$REPO_ROOT/docs/site/offline-auto-runbook.md\" \"$TOOL_DIR/docs/AUTO-OFFLINE-RUNBOOK.md\""
        ),
        "packager must install the offline auto runbook under the tool prefix"
    );
    assert!(
        run_guide.contains("AUTO-OFFLINE-RUNBOOK.md"),
        "RUN-BHF should point operators at the detailed offline auto runbook"
    );

    for expected in [
        "bhf --help",
        "VERSION",
        "bhf auto",
        "--work-dir",
        "--per-target-time",
        "30 seconds",
        "auto/run.md",
        "auto/run.json",
        "bhf report",
        "--findings bhf_work/findings",
        "--csv",
        "reports/last.csv",
        "bhf fuzz",
        "10 minutes",
        "bhf replay",
        "bhf sbom",
        "--emit sbom,cyclonedx,vulnerabilities,openvex,csv",
        "sbom/sbom.csv",
        "sbom/vulnerabilities.csv",
        "bhf-daemon",
        "BHF_RUNTRACE_SHIM",
        "/opt/bhf",
        "A content pack is an offline bundle of BHF data with SHA-256 payload checks",
        "Seeds are example input files",
        "bhf-bug-report /path/to/bhf_work",
    ] {
        assert!(
            run_guide.contains(expected),
            "RUN-BHF template missing {expected:?}:\n{run_guide}"
        );
    }
}

#[test]
fn offline_auto_runbook_documents_trusted_and_forced_recovery_flows() {
    let runbook = fs::read_to_string(repo_root().join("docs/site/offline-auto-runbook.md"))
        .expect("read offline auto runbook");

    for expected in [
        "Known Build Command",
        "Unknown Build Command",
        "--run-untrusted",
        "--build-command",
        "--unsafe-search-and-run-build-commands",
        "--extra-include",
        "--extra-source",
        "--ada-deps",
        "IDL and Generated Source",
        "--force",
        "different work directory",
        "Do not use `--install-deps`",
        "positive coverage",
        "Compact Scrubbed Support Report",
        "bhf-bug-report /results/bhf-real",
    ] {
        assert!(
            runbook.contains(expected),
            "offline auto runbook missing {expected:?}:\n{runbook}"
        );
    }
}

#[test]
fn offline_dist_checksum_sidecar_uses_archive_basename() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();

    assert!(
        script.contains("sha256sum \"${NAME}.tar.gz\""),
        "checksum sidecar should record the archive basename so sha256sum -c works after transfer"
    );
    assert!(
        !script.contains("sha256sum \"$TARBALL\" >\"${TARBALL}.sha256\""),
        "checksum sidecar must not record the build host's absolute tarball path"
    );
}

#[test]
fn offline_dist_installer_supports_interactive_and_noninteractive_profiles() {
    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");

    assert!(script.is_file(), "missing {}", script.display());

    let help = Command::new("bash")
        .arg(&script)
        .arg("--help")
        .output()
        .expect("run install-dist --help");
    assert_success(help, "install-dist --help");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--help")
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    assert!(stdout.contains("--non-interactive"));
    assert!(stdout.contains("--languages"));
    assert!(stdout.contains("--targets"));
    assert!(stdout.contains("--fuzzers"));
    assert!(stdout.contains("--package-manager"));
    assert!(stdout.contains("--no-system-packages"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--no-smoke"));
    assert!(stdout.contains("arrow-key checklist"));
    assert!(stdout.contains("Esc/Cancel"));
    assert!(!stdout.to_lowercase().contains("offline"));
}

#[test]
fn offline_dist_installer_maps_rhel_dependencies_to_dnf_packages() {
    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");
    let bundle = temp_dir("dist-installer-rhel-dry-run");
    create_minimal_bundle(&bundle);

    let output = Command::new("bash")
        .arg(&script)
        .arg("--non-interactive")
        .arg("--dry-run")
        .arg("--package-manager")
        .arg("dnf")
        .arg("--no-rustup")
        .arg("--no-content")
        .arg("--no-symlink")
        .arg("--no-smoke")
        .arg("--prefix")
        .arg(bundle.join("install"))
        .arg("--languages")
        .arg("all")
        .arg("--targets")
        .arg("native,windows,aarch64")
        .arg("--fuzzers")
        .arg("builtin,afl")
        .arg("--extras")
        .arg("build-recovery,sandbox,archives")
        .current_dir(&bundle)
        .output()
        .expect("run RHEL installer dry-run");

    assert_success(output.clone(), "RHEL installer dry-run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dnf -y makecache"), "{stdout}");
    assert!(stdout.contains("dnf install -y"), "{stdout}");
    for package in [
        "gcc-c++",
        "gcc-gnat",
        "java-17-openjdk-devel",
        "golang",
        "gcc-gfortran",
        "lua",
        "aflplusplus",
        "pkgconf-pkg-config",
        "xz",
    ] {
        assert!(
            stdout.contains(package),
            "RHEL dry-run did not mention {package}: {stdout}"
        );
    }
    for debian_only in ["default-jdk", "golang-go", "lua5.4", "xz-utils"] {
        assert!(
            !stdout.contains(debian_only),
            "RHEL dry-run used Debian package {debian_only}: {stdout}"
        );
    }
}

#[test]
fn offline_dist_installer_dry_run_maps_choices_to_dependency_groups() {
    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");
    let bundle = temp_dir("dist-installer-dry-run");
    create_minimal_bundle(&bundle);

    let output = Command::new("bash")
        .arg(&script)
        .arg("--non-interactive")
        .arg("--dry-run")
        .arg("--allow-legacy-integrity-only")
        .arg("--package-manager")
        .arg("apt-get")
        .arg("--prefix")
        .arg(bundle.join("install").to_str().unwrap())
        .arg("--languages")
        .arg("all")
        .arg("--targets")
        .arg("native,windows,aarch64")
        .arg("--fuzzers")
        .arg("builtin,afl")
        .arg("--extras")
        .arg("build-recovery,sandbox,archives")
        .current_dir(&bundle)
        .output()
        .expect("run installer dry-run");

    assert_success(output, "installer dry-run");
    let stdout = String::from_utf8_lossy(
        &Command::new("bash")
            .arg(&script)
            .arg("--non-interactive")
            .arg("--dry-run")
            .arg("--allow-legacy-integrity-only")
            .arg("--package-manager")
            .arg("apt-get")
            .arg("--prefix")
            .arg(bundle.join("install").to_str().unwrap())
            .arg("--languages")
            .arg("all")
            .arg("--targets")
            .arg("native,windows,aarch64")
            .arg("--fuzzers")
            .arg("builtin,afl")
            .arg("--extras")
            .arg("build-recovery,sandbox,archives")
            .current_dir(&bundle)
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    for pkg in [
        "clang",
        "gprbuild",
        "default-jdk",
        "golang-go",
        "gnucobol",
        "gfortran",
        "nodejs",
        "ruby",
        "lua5.4",
        "php-cli",
        "afl++",
        "wine64",
        "qemu-user",
        "bubblewrap",
    ] {
        assert!(
            stdout.contains(pkg),
            "dry-run did not mention {pkg}: {stdout}"
        );
    }
    assert!(stdout.contains("rustup toolchain install nightly"));
    assert!(stdout.contains("SharpFuzz.CommandLine"));
    assert!(stdout.contains("esbuild"));
    assert!(stdout.contains("pack verify"));
    assert!(stdout.contains("bhf-smoke"));
    assert!(stdout.contains("auto"));
}

#[test]
fn offline_dist_packager_stages_every_external_harness_runtime() {
    let script = fs::read_to_string(repo_root().join("scripts/package-offline-dist.sh")).unwrap();

    for runtime in [
        "c_runtime",
        "ada_runtime",
        "java_runtime",
        "python_runtime",
        "perl_runtime",
        "crates/rust_runtime",
        "csharp_runtime",
        "js_runtime",
        "ruby_runtime",
        "lua_runtime",
        "php_runtime",
    ] {
        assert!(
            script.contains(&format!("$REPO_ROOT/{runtime}")),
            "packager does not stage {runtime}"
        );
    }

    assert!(
        script.contains("libbhf_cc_intercept.so"),
        "all-in-one packager must stage the compiler-interception shim"
    );
    assert!(
        script.contains("cp \"$REPO_ROOT/INSTALL.md\" \"$STAGE_ROOT/INSTALL.md\""),
        "all-in-one package must carry the dual-path installation guide"
    );
    for document in ["LICENSE", "README.md", "RELEASE_NOTES.md"] {
        assert!(
            script.contains(&format!(
                "cp \"$REPO_ROOT/{document}\" \"$STAGE_ROOT/{document}\""
            )),
            "all-in-one package must carry {document}"
        );
    }
    assert!(
        script.contains("cp \"$SCRIPT_DIR/bhf-bug-report.sh\" \"$TOOL_DIR/bhf-bug-report\""),
        "all-in-one package must stage the scrubbed support-report wrapper"
    );
}

#[test]
fn release_matrix_keeps_windows_apps_and_linux_only_shims_separate() {
    let root = repo_root();
    let workspace = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let cli = fs::read_to_string(root.join("crates/cli/Cargo.toml")).unwrap();
    let daemon = fs::read_to_string(root.join("crates/daemon/Cargo.toml")).unwrap();
    let runtrace = fs::read_to_string(root.join("crates/bhf_runtrace_shim/Cargo.toml")).unwrap();
    let intercept = fs::read_to_string(root.join("crates/bhf_cc_intercept/Cargo.toml")).unwrap();
    let workflow = fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();

    assert!(workspace.contains("installers = [\"shell\", \"powershell\"]"));
    for manifest in [&workspace, &cli, &daemon] {
        assert!(manifest.contains("x86_64-unknown-linux-gnu"));
        assert!(manifest.contains("x86_64-pc-windows-msvc"));
    }
    for manifest in [&runtrace, &intercept] {
        assert!(manifest.contains("targets = [\"x86_64-unknown-linux-gnu\"]"));
        assert!(!manifest.contains("x86_64-pc-windows-msvc"));
    }
    for manifest in [&cli, &daemon, &runtrace, &intercept] {
        assert!(
            manifest.contains("../../INSTALL.md"),
            "every release component archive must include INSTALL.md"
        );
    }
    assert!(workflow.contains("if: runner.os == 'Linux'"));
    assert!(workflow.contains("if: runner.os == 'Windows'"));
    assert!(workflow.contains("scripts/check-linux-release-abi.sh"));
    assert!(workflow.contains("scripts/package-offline-dist.sh"));
    assert!(workflow.contains("bhf-dist-*.tar.gz.sha256"));
    assert!(workflow.contains("INSTALL.md LICENSE README.md RELEASE_NOTES.md"));
    assert!(workflow.contains("entries=$(tar -tf \"$archive\")"));
    assert!(workflow.contains("grep -Eq '(^|/)INSTALL\\.md$' <<<\"$entries\""));
    assert!(
        !workflow.contains("tar -tf \"$archive\" | grep -Eq"),
        "pipefail turns grep -q's successful early exit into a false tar failure"
    );
    assert!(workflow.contains("libbhf_cc_intercept.so"));
    assert!(cli.contains("../../scripts/bhf-bug-report.sh"));
    assert!(workflow.contains("bhf-bug-report.sh"));
}

#[test]
fn release_archive_install_guide_documents_both_linux_layouts() {
    let guide = fs::read_to_string(repo_root().join("INSTALL.md")).unwrap();

    for expected in [
        "all-in-one `install.sh` bundle",
        "./install.sh",
        "--non-interactive",
        "manually co-locate component archives",
        "libbhf_runtrace_shim.so",
        "libbhf_cc_intercept.so",
        "BHF_RUNTRACE_SHIM",
        "BHF_CC_INTERCEPT",
        "bhf-daemon",
        "bhf-bug-report",
    ] {
        assert!(
            guide.contains(expected),
            "INSTALL.md missing {expected:?}:\n{guide}"
        );
    }
}

#[test]
fn offline_dist_installer_interactive_prompt_accepts_down_arrow_to_ok() {
    // The arrow-key checklist needs a real interactive terminal. Under a headless
    // CI pty the installer detects no controlling TTY and falls back to text-input
    // mode, so the simulated Down-arrow escape sequences become garbage input and
    // the flow is untestable there. The non-interactive installer paths (the
    // `--non-interactive` tests) are what CI exercises; skip this one cleanly.
    if std::env::var_os("CI").is_some() {
        eprintln!("skip: interactive arrow-key TUI needs a real terminal (headless CI)");
        return;
    }
    if Command::new("script").arg("--version").output().is_err()
        || Command::new("timeout").arg("--version").output().is_err()
    {
        return;
    }

    let root = repo_root();
    let script = root.join("scripts/install-dist.sh");
    let bundle = temp_dir("dist-installer-arrow-ok");
    create_minimal_bundle(&bundle);

    let mut keys = String::new();
    keys.push_str(&down_arrow(16));
    keys.push('\n');
    keys.push_str(&down_arrow(3));
    keys.push('\n');
    keys.push_str(&down_arrow(2));
    keys.push('\n');
    keys.push_str(&down_arrow(3));
    keys.push('\n');

    // Force the built-in arrow-key checklist (not the whiptail/dialog popup) so the
    // simulated Down-arrow + Enter keystrokes drive a deterministic fallback UI.
    // `script` supplies the PTY; override an inherited `TERM=dumb` so the
    // installer does not switch to its numbered text prompt and read the escape
    // sequences as literal selection tags.
    let command = format!(
        "cd {} && TERM=xterm BHF_INSTALL_NO_GUI=1 bash {} --dry-run --no-apt --no-rustup --no-content --no-symlink --no-smoke --prefix {} --bin-dir {}",
        shell_quote(&bundle),
        shell_quote(&script),
        shell_quote(&bundle.join("install")),
        shell_quote(&bundle.join("bin")),
    );
    let mut child = Command::new("timeout")
        .arg("10")
        .arg("script")
        .arg("-qec")
        .arg(command)
        .arg("/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn installer pty");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(keys.as_bytes())
        .expect("write installer keys");
    let output = child.wait_with_output().expect("wait for installer pty");

    assert_success(output, "interactive installer down-arrow OK flow");
}

#[test]
fn offline_deployment_doc_uses_copy_pasteable_generated_content_paths() {
    // The offline binary-only packaging instructions moved out of README into the
    // dedicated offline deployment guide during the README slim-down. Wherever
    // they live, they must show real copy-pasteable generated paths, not
    // `/path/to/...` placeholders.
    let doc = fs::read_to_string(repo_root().join("docs/site/offline-deployment.md")).unwrap();

    assert!(!doc.contains("/path/to/bhf-sbom-cves.json"));
    assert!(!doc.contains("/path/to/bhf-binary-cves.json"));
    assert!(!doc.contains("/path/to/seed-corpus"));
    assert!(doc.contains("scripts/package-offline-dist.sh"));
    assert!(doc.contains("dist/content-inputs/sbom-cves.json"));
    assert!(doc.contains("dist/content-inputs/binary-cves.json"));
    assert!(doc.contains("dist/content-inputs/seeds"));
}

#[cfg(unix)]
#[test]
fn signed_offline_package_install_and_tamper_rejection_with_external_trust() {
    // The artifacts other than `bhf` are fixture stand-ins, not a release build.
    // This exercises the real packager, manifest signer/verifier, and installer.
    let work = temp_dir("signed-dist-e1");
    let artifacts = work.join("artifacts");
    let out = work.join("output");
    let seeds = work.join("seeds");
    fs::create_dir_all(&artifacts).unwrap();
    fs::create_dir_all(&seeds).unwrap();
    fs::write(seeds.join("seed"), b"seed").unwrap();
    fs::copy(env!("CARGO_BIN_EXE_bhf"), artifacts.join("bhf")).unwrap();
    write_executable(&artifacts.join("bhf-daemon"), "#!/bin/sh\nexit 0\n");
    fs::write(artifacts.join("libbhf_runtrace.so"), b"fixture").unwrap();
    fs::write(artifacts.join("libbhf_cc_intercept.so"), b"fixture").unwrap();
    let sbom_db = work.join("sbom-cves.json");
    let binary_db = work.join("binary-cves.json");
    fs::write(
        &sbom_db,
        b"{\"schema_version\":\"bhf.cve_db.v1\",\"vulnerabilities\":[]}",
    )
    .unwrap();
    fs::write(
        &binary_db,
        b"{\"schema_version\":\"bhf.binary.cves.v1\",\"components\":[]}",
    )
    .unwrap();
    let private = work.join("signing-key.der");
    let public = work.join("signing-key.pub");
    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bhf"))
            .args(["pack", "keygen", "--private-key"])
            .arg(&private)
            .arg("--public-key")
            .arg(&public)
            .output()
            .unwrap(),
        "fixture keygen",
    );
    let public_hex = fs::read_to_string(&public).unwrap();
    let external_policy = work.join("operator-policy.json");
    fs::write(
        &external_policy,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "bhf.policy.v1",
            "policy_id": "fixture-operator",
            "update_packs": {"require_signature": true,
                "trusted_public_keys": {"publisher-v1": public_hex.trim()},
                "revoked_keys": []}
        }))
        .unwrap(),
    )
    .unwrap();

    let package_output = Command::new("bash")
        .arg(repo_root().join("scripts/package-offline-dist.sh"))
        .arg("--artifact-dir")
        .arg(&artifacts)
        .arg("--out")
        .arg(&out)
        .args([
            "--name",
            "signed-fixture",
            "--version",
            "fixture",
            "--target-triple",
            "x86_64-unknown-linux-gnu",
        ])
        .arg("--sbom-cve-db")
        .arg(&sbom_db)
        .arg("--binary-cve-db")
        .arg(&binary_db)
        .arg("--seed-dir")
        .arg(&seeds)
        .arg("--signing-key")
        .arg(&private)
        .args(["--key-id", "publisher-v1"])
        .arg("--trusted-public-key")
        .arg(&public)
        .output()
        .unwrap();
    assert_success(package_output, "signed fixture packager");
    let bundle = out.join("signed-fixture");
    let manifest = bundle.join("content/packs/current/update-pack.json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&manifest).unwrap()).unwrap()
            ["signature"]["algorithm"],
        "ed25519-json-v1"
    );
    assert!(!bundle.join("signing-key.der").exists());
    let tar_listing = Command::new("tar")
        .arg("-tzf")
        .arg(out.join("signed-fixture.tar.gz"))
        .output()
        .unwrap();
    assert_success(tar_listing.clone(), "list signed fixture archive");
    assert!(!String::from_utf8_lossy(&tar_listing.stdout).contains("signing-key.der"));
    let archive = out.join("signed-fixture.tar.gz");
    let signature = out.join("signed-fixture.tar.gz.sig");
    let signature_sidecar = out.join("signed-fixture.tar.gz.sig.sha256");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 64);
    assert_success(
        Command::new("sha256sum")
            .arg("-c")
            .arg(signature_sidecar.file_name().unwrap())
            .current_dir(&out)
            .output()
            .unwrap(),
        "detached signature provenance hash",
    );
    let verifier = repo_root().join("scripts/verify-offline-dist.sh");
    let verify_archive = |archive: &Path, signature: &Path, public: &Path| {
        Command::new("bash")
            .arg(&verifier)
            .arg("--archive")
            .arg(archive)
            .arg("--signature")
            .arg(signature)
            .arg("--trusted-public-key")
            .arg(public)
            .output()
            .unwrap()
    };
    assert_success(
        verify_archive(&archive, &signature, &public),
        "independent OpenSSL archive verification",
    );

    let prefix = work.join("installed");
    let bin_dir = work.join("bin");
    fs::create_dir_all(&prefix).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(prefix.join("previous.txt"), b"previous").unwrap();
    std::os::unix::fs::symlink(prefix.join("bhf"), bin_dir.join("bhf")).unwrap();
    let install = || {
        installer_command_with_symlinks(&bundle, &prefix, &bin_dir)
            .arg("--trust-policy")
            .arg(&external_policy)
            .arg("--no-smoke")
            .output()
            .unwrap()
    };
    assert_success(install(), "signed fixture install");
    let pack_id = "bhf-content-fixture";
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(prefix.join("packs").join(pack_id).join("install.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["publisher_authentication"]["authenticated"], true);
    assert_eq!(
        receipt["install_dir"],
        prefix.join("packs").join(pack_id).to_str().unwrap()
    );
    assert!(!receipt["install_dir"].as_str().unwrap().contains(".new."));
    let active_binary = fs::read(prefix.join("bhf")).unwrap();
    let active_link = fs::read_link(bin_dir.join("bhf")).unwrap();
    let rule_path = bundle.join("content/packs/current/rules/static.json");
    let original_rules = fs::read(&rule_path).unwrap();
    fs::write(&rule_path, b"tampered payload").unwrap();
    assert!(!install().status.success());
    fs::write(&rule_path, original_rules).unwrap();
    let original_manifest = fs::read(&manifest).unwrap();
    let mut metadata: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
    metadata["version"] = serde_json::json!("forged");
    fs::write(&manifest, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert!(!install().status.success());
    fs::write(&manifest, &original_manifest).unwrap();
    let mut unsigned: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
    unsigned.as_object_mut().unwrap().remove("signature");
    fs::write(&manifest, serde_json::to_vec(&unsigned).unwrap()).unwrap();
    fs::write(
        &external_policy,
        b"{\"update_packs\":{\"require_signature\":false}}",
    )
    .unwrap();
    assert!(
        !install().status.success(),
        "weak policy must not downgrade authenticated installation"
    );
    fs::write(&manifest, &original_manifest).unwrap();
    assert!(
        !installer_command_with_symlinks(&bundle, &prefix, &bin_dir)
            .arg("--trust-policy")
            .arg(bundle.join("content/bhf-policy.json"))
            .arg("--no-smoke")
            .output()
            .unwrap()
            .status
            .success(),
        "bundled policy cannot be trust anchor"
    );
    assert_eq!(fs::read(prefix.join("bhf")).unwrap(), active_binary);
    assert_eq!(fs::read_link(bin_dir.join("bhf")).unwrap(), active_link);
    assert!(!prefix.join("previous.txt").exists());

    let wrong_private = work.join("wrong-key.der");
    let wrong_public = work.join("wrong-key.pub");
    assert_success(
        Command::new(env!("CARGO_BIN_EXE_bhf"))
            .args(["pack", "keygen", "--private-key"])
            .arg(&wrong_private)
            .arg("--public-key")
            .arg(&wrong_public)
            .output()
            .unwrap(),
        "wrong-key fixture",
    );
    assert!(!verify_archive(&archive, &signature, &wrong_public)
        .status
        .success());
    let bad_signature = work.join("bad.sig");
    let mut signature_bytes = fs::read(&signature).unwrap();
    signature_bytes[0] ^= 1;
    fs::write(&bad_signature, signature_bytes).unwrap();
    assert!(!verify_archive(&archive, &bad_signature, &public)
        .status
        .success());
    let bad_archive = work.join("bad.tar.gz");
    fs::copy(&archive, &bad_archive).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&bad_archive)
        .unwrap()
        .write_all(b"tamper")
        .unwrap();
    assert!(!verify_archive(&bad_archive, &signature, &public)
        .status
        .success());
}

#[test]
fn release_workflow_keeps_signing_in_protected_tag_job_and_publishes_signature_assets() {
    let workflow = fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    assert!(workflow.contains("sign-linux-bundle:"));
    assert!(workflow.contains("environment: production-release"));
    assert!(workflow.contains(
        "needs.plan.outputs.publishing == 'true' && needs.build-local-artifacts.result == 'success'"
    ));
    assert!(workflow.contains("secrets.BHF_RELEASE_SIGNING_KEY_PKCS8_B64"));
    assert!(workflow.contains("vars.BHF_RELEASE_PUBLIC_KEY_HEX"));
    assert!(workflow.contains("scripts/verify-offline-dist.sh --archive"));
    assert!(workflow.contains("--trust-policy \"$signing_dir/policy.json\""));
    assert!(workflow.contains("target/distrib/bhf-dist-*.tar.gz.sig.sha256"));
    assert!(!workflow.contains("--legacy-integrity-only"));
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_success(output: std::process::Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn temp_dir(prefix: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-{prefix}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn create_minimal_bundle(root: &Path) {
    fs::create_dir_all(root.join("tool")).unwrap();
    fs::create_dir_all(root.join("content/packs/current")).unwrap();
    fs::create_dir_all(root.join("smoke/c")).unwrap();
    fs::write(
        root.join("tool/bhf"),
        b"#!/usr/bin/env bash\n\
if [[ \"$1 $2\" == 'pack install' ]]; then\n\
  shift 2\n\
  shift\n\
  while [[ $# -gt 0 ]]; do\n\
    case \"$1\" in\n\
      --root) pack_root=\"$2\"; shift 2 ;;\n\
      --install-dir) install_dir=\"$2\"; shift 2 ;;\n\
      --out) output=\"$2\"; shift 2 ;;\n\
      *) shift ;;\n\
    esac\n\
  done\n\
  mkdir -p \"$install_dir/test-pack\"\n\
  cp -a \"$pack_root/.\" \"$install_dir/test-pack/\"\n\
  printf '{\"valid\":true,\"pack_id\":\"test-pack\"}\\n' > \"$output\"\n\
fi\n\
exit 0\n",
    )
    .unwrap();
    fs::write(root.join("content/packs/current/update-pack.json"), b"{}\n").unwrap();
    fs::write(
        root.join("smoke/c/bhf_smoke.c"),
        b"#include <stddef.h>\nint bhf_smoke_parse(const unsigned char *data, size_t len) { return len && data[0] == 'G'; }\n",
    )
    .unwrap();
}

#[cfg(unix)]
fn installer_command(bundle: &Path, prefix: &Path) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join("scripts/install-dist.sh"))
        .args([
            "--non-interactive",
            "--no-system-packages",
            "--no-rustup",
            "--no-symlink",
        ])
        .args([
            "--languages",
            "none",
            "--targets",
            "none",
            "--fuzzers",
            "none",
            "--extras",
            "none",
        ])
        .arg("--prefix")
        .arg(prefix)
        .current_dir(bundle);
    command
}

#[cfg(unix)]
fn installer_command_with_symlinks(bundle: &Path, prefix: &Path, bin_dir: &Path) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join("scripts/install-dist.sh"))
        .args(["--non-interactive", "--no-system-packages", "--no-rustup"])
        .args([
            "--languages",
            "none",
            "--targets",
            "none",
            "--fuzzers",
            "none",
            "--extras",
            "none",
        ])
        .arg("--prefix")
        .arg(prefix)
        .arg("--bin-dir")
        .arg(bin_dir)
        .current_dir(bundle);
    command
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    make_executable(path);
}

fn down_arrow(count: usize) -> String {
    "\x1b[B".repeat(count)
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn extract_readme_dist_template(script: &str) -> &str {
    let marker = "cat >\"$STAGE_ROOT/README-DIST.md\" <<";
    let marker_start = script.find(marker).expect("README-DIST heredoc marker");
    let after_marker = &script[marker_start..];
    let content_start = after_marker.find('\n').unwrap() + 1;
    let content = &after_marker[content_start..];
    let end = content
        .find("\nEOF")
        .expect("README-DIST heredoc terminator");
    &content[..end]
}

fn extract_run_guide_template(script: &str) -> &str {
    let marker = "cat >\"$STAGE_ROOT/RUN-BHF.md\" <<";
    let marker_start = script.find(marker).expect("RUN-BHF heredoc marker");
    let after_marker = &script[marker_start..];
    let content_start = after_marker.find('\n').unwrap() + 1;
    let content = &after_marker[content_start..];
    let end = content.find("\nEOF").expect("RUN-BHF heredoc terminator");
    &content[..end]
}
