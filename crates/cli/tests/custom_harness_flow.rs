// SPDX-License-Identifier: Apache-2.0

//! The custom-harness workflow from docs/site/custom-harness.md, end to end on
//! a small multi-file C++ library: target a namespaced class method by its
//! `Class::method` suffix, build it (first without, then with, the sibling
//! source it needs), fuzz from a byte-exact seed file, and replay the finding.
//! A second flow wraps the project's own `LLVMFuzzerTestOneInput`.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::time::{Duration, Instant};

    /// Run bhf with captured output, bounded by `deadline`.
    fn bhf(args: &[OsString], envs: &[(&str, OsString)], deadline: Duration) -> Output {
        let root = tempfile::tempdir().unwrap();
        let out_path = root.path().join("stdout");
        let err_path = root.path().join("stderr");
        let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
        command
            .args(args)
            .env_remove("CC")
            .env_remove("CXX")
            .env_remove("AUTO_EXTRA_SOURCES")
            .env_remove("AUTO_EXTRA_INCLUDES")
            .env_remove("AUTO_EXTRA_LDFLAGS")
            .env_remove("CXX_STD")
            .env_remove("C_STD")
            .stdin(Stdio::null())
            .stdout(fs::File::create(&out_path).unwrap())
            .stderr(fs::File::create(&err_path).unwrap());
        for (key, value) in envs {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        let expires = Instant::now() + deadline;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= expires {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "bhf {args:?} exceeded {deadline:?}; stderr:\n{}",
                    fs::read_to_string(&err_path).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Output {
            status,
            stdout: fs::read(&out_path).unwrap(),
            stderr: fs::read(&err_path).unwrap(),
        }
    }

    fn args(items: &[&dyn AsRef<std::ffi::OsStr>]) -> Vec<OsString> {
        items.iter().map(|item| item.as_ref().to_owned()).collect()
    }

    fn text(output: &Output) -> String {
        format!(
            "status={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn cpp_toolchain() -> bool {
        let ok = |program: &str| {
            Command::new(program)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        };
        ok("clang++") && ok("make")
    }

    /// A two-file C++ library: `widgets::Codec::decode` (codec.cpp) calls
    /// `widgets::Table::store` (table.cpp), which overflows a heap buffer on a
    /// `W!` record longer than eight bytes.
    fn write_library(root: &Path) -> PathBuf {
        let lib = root.join("lib");
        fs::create_dir_all(lib.join("include/widgets")).unwrap();
        fs::create_dir_all(lib.join("src")).unwrap();
        fs::write(
            lib.join("include/widgets/codec.h"),
            "#pragma once\n#include <cstddef>\n\
             namespace widgets {\n\
             class Codec {\n\
             public:\n\
             \x20   int decode(const unsigned char *data, size_t size);\n\
             };\n\
             }\n",
        )
        .unwrap();
        fs::write(
            lib.join("src/table.h"),
            "#pragma once\n#include <cstddef>\n\
             namespace widgets {\n\
             class Table {\n\
             public:\n\
             \x20   static int store(const unsigned char *data, size_t size);\n\
             };\n\
             }\n",
        )
        .unwrap();
        fs::write(
            lib.join("src/codec.cpp"),
            "#include \"widgets/codec.h\"\n#include \"table.h\"\n\
             namespace widgets {\n\
             int Codec::decode(const unsigned char *data, size_t size) {\n\
             \x20   if (size < 2 || data[0] != 'W') return 0;\n\
             \x20   return Table::store(data + 1, size - 1);\n\
             }\n\
             }\n",
        )
        .unwrap();
        fs::write(
            lib.join("src/table.cpp"),
            "#include \"table.h\"\n#include <cstring>\n\
             namespace widgets {\n\
             int Table::store(const unsigned char *data, size_t size) {\n\
             \x20   if (data[0] != '!') return 0;\n\
             \x20   char *slot = new char[8];\n\
             \x20   std::memcpy(slot, data, size);\n\
             \x20   int first = slot[0];\n\
             \x20   delete[] slot;\n\
             \x20   return first;\n\
             }\n\
             }\n",
        )
        .unwrap();
        lib
    }

    const CRASHING_SEED: &[u8] = b"W!overflowing-the-eight-byte-slot\x00\xff";

    /// Fuzz from the crashing seed and return the finding directory.
    fn fuzz_to_finding(work: &Path, id: &str, seed: &Path) -> PathBuf {
        let fuzz = bhf(
            &args(&[
                &"fuzz",
                &work,
                &"--harness",
                &id,
                &"--seed-file",
                &seed,
                &"--iterations",
                &"64",
                &"--timeout",
                &"5s",
                &"--sandbox",
                &"none",
            ]),
            &[],
            Duration::from_secs(180),
        );
        assert!(fuzz.status.success(), "fuzz failed: {}", text(&fuzz));
        let summary: serde_json::Value = serde_json::from_slice(
            &fs::read(work.join("fuzz_runs").join(format!("{id}-latest.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            summary["execution"]["harness_protocol"], "bhf_framed",
            "{summary}"
        );
        let findings = summary["findings"].as_array().cloned().unwrap_or_default();
        let first = findings
            .first()
            .and_then(|finding| finding.as_str())
            .unwrap_or_else(|| panic!("the seed must crash: {summary}"));
        let finding_dir = work.join("results").join("findings").join(first);
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["exception"]["sanitizer"], "asan", "{finding}");
        assert_eq!(
            fs::read(finding_dir.join("testcase.bin")).unwrap(),
            CRASHING_SEED,
            "--seed-file must reach the harness byte for byte"
        );
        finding_dir
    }

    fn replay_matches(finding_dir: &Path, harness_binary: &Path) {
        let replay = bhf(
            &args(&[
                &"replay",
                &"--finding",
                &finding_dir,
                &"--harness",
                &harness_binary,
                &"--sandbox",
                &"none",
            ]),
            &[],
            Duration::from_secs(60),
        );
        assert!(replay.status.success(), "replay failed: {}", text(&replay));
        assert!(
            String::from_utf8_lossy(&replay.stdout).contains("MATCH"),
            "{}",
            text(&replay)
        );
    }

    #[test]
    fn documented_class_method_flow_generates_builds_fuzzes_and_replays() {
        if !cpp_toolchain() {
            eprintln!("skipping custom-harness flow: clang++ or make unavailable");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let lib = write_library(root.path());
        let work = root.path().join("bhf_work");
        let harnesses = work.join("harnesses");
        let codec = lib.join("src/codec.cpp");
        let table = lib.join("src/table.cpp");
        let include = lib.join("include");
        let id = "H-WIDGET-DECODE";

        // A misspelled target names the closest definition and the spellings.
        let miss = bhf(
            &args(&[
                &"generate-harness",
                &codec,
                &"--target",
                &"Codec::decod",
                &"--output",
                &harnesses,
            ]),
            &[],
            Duration::from_secs(60),
        );
        assert!(!miss.status.success());
        let miss_text = text(&miss);
        assert!(
            miss_text.contains("closest definitions: widgets::Codec::decode"),
            "{miss_text}"
        );

        // `Codec::decode` (no namespace) selects `widgets::Codec::decode`.
        let generate = |extra_source: Option<&Path>| {
            let mut command = args(&[
                &"generate-harness",
                &codec,
                &"--target",
                &"Codec::decode",
                &"--id",
                &id,
                &"--output",
                &harnesses,
                &"--extra-include",
                &include,
            ]);
            if let Some(source) = extra_source {
                command.push("--extra-source".into());
                command.push(source.into());
            }
            let output = bhf(&command, &[], Duration::from_secs(60));
            assert!(
                output.status.success(),
                "generate failed: {}",
                text(&output)
            );
        };
        generate(None);
        let main_cpp = fs::read_to_string(harnesses.join(id).join("main.cpp")).unwrap();
        assert!(main_cpp.contains(".decode("), "{main_cpp}");

        // Without table.cpp the link fails; bhf build names the source that
        // defines the missing symbol and the exact ways to add it.
        let failed = bhf(
            &args(&[&"build", &work, &"--harness", &id]),
            &[],
            Duration::from_secs(300),
        );
        let failed_text = text(&failed);
        assert_eq!(failed.status.code(), Some(1), "{failed_text}");
        let table_display = table.display().to_string();
        assert!(
            failed_text.contains(&format!("--extra-source {table_display}")),
            "{failed_text}"
        );
        assert!(
            failed_text.contains(&format!("AUTO_EXTRA_SOURCES={table_display} bhf build"))
                || failed_text.contains(&format!("AUTO_EXTRA_SOURCES='{table_display}' bhf build")),
            "{failed_text}"
        );

        // The suggested environment variable builds it without regenerating.
        let via_env = bhf(
            &args(&[&"build", &work, &"--harness", &id]),
            &[("AUTO_EXTRA_SOURCES", table.clone().into_os_string())],
            Duration::from_secs(300),
        );
        assert!(
            via_env.status.success(),
            "env build failed: {}",
            text(&via_env)
        );

        // So does regenerating with --extra-source, the documented route.
        generate(Some(&table));
        let built = bhf(
            &args(&[&"build", &work, &"--harness", &id]),
            &[],
            Duration::from_secs(300),
        );
        assert!(built.status.success(), "build failed: {}", text(&built));
        assert!(work.join("build").join(id).join("main").is_file());

        let seed = root.path().join("crash.bin");
        fs::write(&seed, CRASHING_SEED).unwrap();
        let finding_dir = fuzz_to_finding(&work, id, &seed);
        replay_matches(&finding_dir, &harnesses.join(id).join("main"));

        // `--harness` is optional for minimize too: it runs the finding's own
        // harness, resolved in the work dir, and says which one.
        let minimized = bhf(
            &args(&[&"minimize", &"--finding", &finding_dir]),
            &[],
            Duration::from_secs(300),
        );
        assert!(minimized.status.success(), "{}", text(&minimized));
        let minimized_text = text(&minimized);
        assert!(
            String::from_utf8_lossy(&minimized.stdout).contains("MINIMIZED "),
            "{minimized_text}"
        );
        assert!(
            minimized_text.contains(&format!("{id}/main")),
            "the resolved harness is named: {minimized_text}"
        );
        assert!(finding_dir.join("min_testcase.bin").is_file());

        // With a second harness in the work dir, a bare `bhf build` reports the
        // real lookup problem and lists both ids.
        let second = bhf(
            &args(&[
                &"generate-harness",
                &table,
                &"--target",
                &"Table::store",
                &"--id",
                &"H-WIDGET-STORE",
                &"--output",
                &harnesses,
            ]),
            &[],
            Duration::from_secs(60),
        );
        assert!(second.status.success(), "{}", text(&second));
        let ambiguous = bhf(&args(&[&"build", &work]), &[], Duration::from_secs(60));
        let ambiguous_text = text(&ambiguous);
        assert_eq!(ambiguous.status.code(), Some(3), "{ambiguous_text}");
        assert!(
            ambiguous_text.contains("2 harnesses found (H-WIDGET-DECODE, H-WIDGET-STORE)"),
            "{ambiguous_text}"
        );
        assert!(
            !ambiguous_text.contains("src_instrumented"),
            "{ambiguous_text}"
        );
    }

    /// The same flow with `CXX=g++`: the Makefile takes gcc's flags, and the
    /// gcc-built harness fuzzes to the same AddressSanitizer finding.
    #[test]
    fn documented_flow_builds_and_fuzzes_with_gcc() {
        let gxx = Command::new("g++")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !gxx || !cpp_toolchain() {
            eprintln!("skipping gcc custom-harness flow: g++, clang++ or make unavailable");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let lib = write_library(root.path());
        let work = root.path().join("bhf_work");
        let harnesses = work.join("harnesses");
        let id = "H-WIDGET-GCC";
        let generate = bhf(
            &args(&[
                &"generate-harness",
                &lib.join("src/codec.cpp"),
                &"--target",
                &"Codec::decode",
                &"--id",
                &id,
                &"--output",
                &harnesses,
                &"--extra-include",
                &lib.join("include"),
                &"--extra-source",
                &lib.join("src/table.cpp"),
            ]),
            &[],
            Duration::from_secs(60),
        );
        assert!(generate.status.success(), "{}", text(&generate));
        let built = bhf(
            &args(&[&"build", &work, &"--harness", &id]),
            &[("CXX", "g++".into())],
            Duration::from_secs(300),
        );
        assert!(built.status.success(), "gcc build failed: {}", text(&built));
        let seed = root.path().join("crash.bin");
        fs::write(&seed, CRASHING_SEED).unwrap();
        let finding_dir = fuzz_to_finding(&work, id, &seed);
        replay_matches(&finding_dir, &harnesses.join(id).join("main"));
    }

    /// The guide no longer says gcc does not work, and the C/C++ page no
    /// longer says `bhf auto` leaves the C++ compatibility flag to be set by hand.
    #[test]
    fn the_guides_do_not_repeat_retired_claims() {
        let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site");
        let flat = |name: &str| {
            fs::read_to_string(docs.join(name))
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let guide = flat("custom-harness.md");
        assert!(
            !guide.contains("Leave `CC`/`CXX` unset, or set them to `clang`/`clang++`"),
            "custom-harness.md still says only clang works"
        );
        assert!(
            guide.contains("c-cpp.md"),
            "the pitfall points at the compiler contract"
        );
        assert!(
            !guide.contains("`bhf minimize` from the finding"),
            "custom-harness.md still says bhf minimize finds the harness from the finding"
        );
        assert!(
            guide.contains("`bhf minimize` takes it as `--harness`"),
            "custom-harness.md says bhf minimize takes the harness as --harness"
        );
        assert!(
            !guide.contains("records no build recipe"),
            "custom-harness.md still says bhf build records no build recipe"
        );
        let c_cpp = flat("c-cpp.md");
        assert!(
            !c_cpp.contains("but does not add it itself"),
            "c-cpp.md still says auto does not add the compatibility flag"
        );
    }

    #[test]
    fn documented_passthrough_driver_flow_builds_fuzzes_and_replays() {
        if !cpp_toolchain() {
            eprintln!("skipping passthrough flow: clang++ or make unavailable");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let lib = write_library(root.path());
        let driver_dir = root.path().join("harness");
        fs::create_dir_all(&driver_dir).unwrap();
        let driver = driver_dir.join("drive_codec.cpp");
        fs::write(
            &driver,
            "#include <cstddef>\n#include <cstdint>\n#include \"widgets/codec.h\"\n\
             extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
             \x20   widgets::Codec codec;\n\
             \x20   codec.decode(data, size);\n\
             \x20   return 0;\n\
             }\n",
        )
        .unwrap();
        let work = root.path().join("bhf_work");
        let harnesses = work.join("harnesses");
        let id = "H-DRIVE-CODEC";
        let generate = bhf(
            &args(&[
                &"generate-harness",
                &driver,
                &"--target",
                &"LLVMFuzzerTestOneInput",
                &"--id",
                &id,
                &"--output",
                &harnesses,
                &"--extra-source",
                &lib.join("src/codec.cpp"),
                &"--extra-source",
                &lib.join("src/table.cpp"),
                &"--extra-include",
                &lib.join("include"),
                &"--extra-include",
                &lib.join("src"),
            ]),
            &[],
            Duration::from_secs(60),
        );
        assert!(generate.status.success(), "{}", text(&generate));
        let harness_dir = harnesses.join(id);
        assert!(!harness_dir.join("bhf_libfuzzer.c").exists());

        // The harness directory itself is accepted as the build argument.
        let built = bhf(
            &args(&[&"build", &harness_dir]),
            &[],
            Duration::from_secs(300),
        );
        assert!(built.status.success(), "build failed: {}", text(&built));
        assert!(work.join("build").join(id).join("main").is_file());

        let seed = root.path().join("crash.bin");
        fs::write(&seed, CRASHING_SEED).unwrap();
        let finding_dir = fuzz_to_finding(&work, id, &seed);
        replay_matches(&finding_dir, &harness_dir.join("main"));

        // PORTABILITY.md's libFuzzer build links the project's own entry point.
        let libfuzzer = Command::new("make")
            .arg("libfuzzer")
            .current_dir(&harness_dir)
            .env_remove("CC")
            .env_remove("CXX")
            .output()
            .unwrap();
        let probe = Command::new("clang++")
            .args(["-fsanitize=fuzzer", "-x", "c++", "-", "-o"])
            .arg(root.path().join("probe"))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(
                    b"#include <cstddef>\n#include <cstdint>\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*, size_t){return 0;}\n",
                )?;
                child.wait()
            })
            .is_ok_and(|status| status.success());
        if probe {
            assert!(
                libfuzzer.status.success(),
                "make libfuzzer failed:\n{}\n{}",
                String::from_utf8_lossy(&libfuzzer.stdout),
                String::from_utf8_lossy(&libfuzzer.stderr)
            );
            let run = Command::new(harness_dir.join("main_libfuzzer"))
                .arg(&seed)
                .output()
                .unwrap();
            assert!(!run.status.success(), "the seed must crash under libFuzzer");
            assert!(String::from_utf8_lossy(&run.stderr).contains("AddressSanitizer"));
        }
    }

    #[test]
    fn auto_target_selection_accepts_suffixes_and_explicit_fuzz_drivers() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        write_library(&tree);
        fs::create_dir_all(tree.join("harness")).unwrap();
        fs::write(
            tree.join("harness/drive_codec.cpp"),
            "#include <cstddef>\n#include <cstdint>\n#include \"widgets/codec.h\"\n\
             extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
             \x20   widgets::Codec codec;\n\
             \x20   return codec.decode(data, size);\n\
             }\n",
        )
        .unwrap();
        let list = |work: &str, target: Option<&str>| {
            let mut command = args(&[
                &"auto",
                &tree,
                &"--work-dir",
                &root.path().join(work),
                &"--list-targets",
            ]);
            if let Some(target) = target {
                command.push("--target".into());
                command.push(target.into());
            }
            let output = bhf(&command, &[], Duration::from_secs(120));
            assert!(output.status.success(), "{}", text(&output));
            output
        };

        // Without a selection the driver is shadowed by the library, with a note.
        let plain = text(&list("w-plain", None));
        assert!(plain.contains("widgets::Codec::decode"), "{plain}");
        assert!(!plain.contains("  LLVMFuzzerTestOneInput"), "{plain}");
        assert!(plain.contains("ignored 1 project fuzz driver"), "{plain}");

        // Naming the driver keeps it.
        let driver = text(&list("w-driver", Some("LLVMFuzzerTestOneInput")));
        assert!(driver.contains("1 ranked target(s)"), "{driver}");
        assert!(driver.contains("LLVMFuzzerTestOneInput"), "{driver}");

        // A class-qualified suffix selects the namespaced method.
        let suffix = text(&list("w-suffix", Some("Codec::decode")));
        assert!(suffix.contains("1 ranked target(s)"), "{suffix}");
        assert!(suffix.contains("widgets::Codec::decode"), "{suffix}");

        // A miss names the closest discovered target.
        let miss = text(&list("w-miss", Some("Codec::decod")));
        assert!(miss.contains("0 ranked target(s)"), "{miss}");
        assert!(miss.contains("closest: widgets::Codec::decode"), "{miss}");
    }

    /// Split `VAR=value VAR='a b' bhf build <work> --harness <id>` into its
    /// assignments and the words after them (single quotes only).
    fn split_suggested_command(line: &str) -> (Vec<(String, String)>, Vec<String>) {
        let mut words = Vec::new();
        let mut current = String::new();
        let mut quoted = false;
        for ch in line.chars() {
            match ch {
                '\'' => quoted = !quoted,
                c if c.is_whitespace() && !quoted => {
                    if !current.is_empty() {
                        words.push(std::mem::take(&mut current));
                    }
                }
                c => current.push(c),
            }
        }
        if !current.is_empty() {
            words.push(current);
        }
        let mut envs = Vec::new();
        let mut rest = words.into_iter().peekable();
        while let Some(word) = rest.next_if(|word| {
            word.split_once('=')
                .is_some_and(|(name, _)| name.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        }) {
            let (name, value) = word.split_once('=').unwrap();
            envs.push((name.to_owned(), value.to_owned()));
        }
        (envs, rest.collect())
    }

    #[test]
    fn failed_build_hints_combine_into_one_working_command() {
        if !cpp_toolchain() {
            eprintln!("skipping build-hint flow: clang++ or make unavailable");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("lib/src");
        fs::create_dir_all(&src).unwrap();
        // A legacy library: a member declared with its class qualification, and a
        // sibling source that uses `cerr` without including <iostream>.
        fs::write(
            src.join("widget.h"),
            "#pragma once\n#include <cstddef>\n\
             class Widget {\n\
             public:\n\
             \x20   int Widget::parse_record(const unsigned char *data, size_t size);\n\
             };\n",
        )
        .unwrap();
        fs::write(
            src.join("widget.cpp"),
            "#include \"widget.h\"\n\
             void log_line(const char *text);\n\
             int Widget::parse_record(const unsigned char *data, size_t size) {\n\
             \x20   log_line(\"parse\");\n\
             \x20   return size > 0 ? data[0] : 0;\n\
             }\n",
        )
        .unwrap();
        let log = src.join("log.cpp");
        fs::write(
            &log,
            "#include <ostream>\nusing namespace std;\n\
             void log_line(const char *text) { cerr << text << endl; }\n",
        )
        .unwrap();
        let work = root.path().join("bhf_work");
        let id = "H-XWIDGET";
        let generated = bhf(
            &args(&[
                &"generate-harness",
                &src.join("widget.cpp"),
                &"--target",
                &"Widget::parse_record",
                &"--id",
                &id,
                &"--output",
                &work.join("harnesses"),
            ]),
            &[],
            Duration::from_secs(60),
        );
        assert!(generated.status.success(), "{}", text(&generated));

        // The operator already passes the sibling source and a standard.
        let inherited = [
            ("AUTO_EXTRA_SOURCES", log.clone().into_os_string()),
            ("CXX_STD", OsString::from("gnu++14")),
        ];
        let failed = bhf(
            &args(&[&"build", &work, &"--harness", &id]),
            &inherited,
            Duration::from_secs(300),
        );
        let failed_text = text(&failed);
        assert_eq!(failed.status.code(), Some(1), "{failed_text}");
        let stderr = String::from_utf8_lossy(&failed.stderr).into_owned();
        let hint_lines: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("hint:") && line.contains("bhf build"))
            .collect();
        assert!(hint_lines.len() >= 3, "{failed_text}");
        // Every suggested command carries what the build already had.
        for line in &hint_lines {
            assert!(
                line.contains(&format!("AUTO_EXTRA_SOURCES={}", log.display()))
                    && line.contains("CXX_STD=gnu++14"),
                "{failed_text}"
            );
        }
        let combined = hint_lines
            .iter()
            .find_map(|line| line.split_once("every suggestion above at once: "))
            .map(|(_, command)| command)
            .unwrap_or_else(|| panic!("no combined command: {failed_text}"));
        let (envs, words) = split_suggested_command(combined);
        assert_eq!(&words[..2], ["bhf", "build"], "{combined}");
        let includes = envs
            .iter()
            .find(|(name, _)| name == "AUTO_EXTRA_INCLUDES")
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        assert!(includes.contains("-include iostream"), "{combined}");
        assert!(includes.contains("-fms-extensions"), "{combined}");

        // Running the combined command as printed builds the harness.
        let envs: Vec<(&str, OsString)> = envs
            .iter()
            .map(|(name, value)| (name.as_str(), OsString::from(value)))
            .collect();
        let rebuild_args: Vec<OsString> = words[1..].iter().map(OsString::from).collect();
        let built = bhf(&rebuild_args, &envs, Duration::from_secs(300));
        assert!(
            built.status.success(),
            "combined command failed: {}",
            text(&built)
        );
        assert!(work.join("build").join(id).join("main").is_file());
    }

    #[test]
    fn auto_target_exact_spelling_beats_a_suffix_match() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        fs::create_dir_all(tree.join("src")).unwrap();
        fs::write(
            tree.join("src/a.cpp"),
            "#include <cstddef>\n\
             class Codec {\n\
             public:\n\
             \x20   int decode(const unsigned char *data, size_t size) { return size ? data[0] : 0; }\n\
             };\n",
        )
        .unwrap();
        fs::write(
            tree.join("src/b.cpp"),
            "#include <cstddef>\n\
             namespace widgets {\n\
             class Codec {\n\
             public:\n\
             \x20   int decode(const unsigned char *data, size_t size) { return size > 1 ? data[1] : 0; }\n\
             };\n\
             class Table {\n\
             public:\n\
             \x20   int store(const unsigned char *data, size_t size) { return size > 2 ? data[2] : 0; }\n\
             };\n\
             }\n",
        )
        .unwrap();
        let list = |work: &str, target: &str| {
            let output = bhf(
                &args(&[
                    &"auto",
                    &tree,
                    &"--work-dir",
                    &root.path().join(work),
                    &"--list-targets",
                    &"--target",
                    &target,
                ]),
                &[],
                Duration::from_secs(120),
            );
            assert!(output.status.success(), "{}", text(&output));
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        let lines = |listing: &str, needle: &str| {
            listing.lines().filter(|line| line.contains(needle)).count()
        };

        let global = list("w-global", "Codec::decode");
        assert!(global.contains("1 ranked target(s)"), "{global}");
        assert!(global.contains("src/a.cpp"), "{global}");
        assert!(!global.contains("widgets::Codec::decode"), "{global}");

        let namespaced = list("w-namespaced", "widgets::Codec::decode");
        assert!(namespaced.contains("1 ranked target(s)"), "{namespaced}");
        assert_eq!(
            lines(&namespaced, "widgets::Codec::decode"),
            1,
            "{namespaced}"
        );

        let suffix = list("w-suffix", "Table::store");
        assert!(suffix.contains("1 ranked target(s)"), "{suffix}");
        assert!(suffix.contains("widgets::Table::store"), "{suffix}");
    }

    /// The library of [`write_library`] with `table.cpp` needing what only
    /// the build supplies: a define, a force-included config header, and
    /// `<iostream>` for the `std::cerr` it never includes.
    fn write_library_needing_build_inputs(root: &Path) -> PathBuf {
        let lib = write_library(root);
        fs::write(
            lib.join("include/widgets/config.h"),
            "#pragma once\n#define WIDGETS_SLOT_SIZE 8\n",
        )
        .unwrap();
        fs::write(
            lib.join("src/table.cpp"),
            "#include \"table.h\"\n#include <cstring>\n\
             #ifndef WIDGETS_LEGACY\n#error WIDGETS_LEGACY comes from the build\n#endif\n\
             namespace widgets {\n\
             int Table::store(const unsigned char *data, size_t size) {\n\
             \x20   if (data[0] != '!') {\n\
             \x20       std::cerr << \"not a table record\\n\";\n\
             \x20       return 0;\n\
             \x20   }\n\
             \x20   char *slot = new char[WIDGETS_SLOT_SIZE];\n\
             \x20   std::memcpy(slot, data, size);\n\
             \x20   int first = slot[0];\n\
             \x20   delete[] slot;\n\
             \x20   return first;\n\
             }\n\
             }\n",
        )
        .unwrap();
        lib
    }

    /// Package `finding` and verify the capsule from a clean copy with the
    /// library and the work dir moved away.
    fn capsule_round_trip(work: &Path, lib: &Path, finding: &str) {
        let packaged = bhf(
            &args(&[
                &"capsule",
                &"--work-dir",
                &work,
                &"--finding-id",
                &finding,
                &"--verbose",
            ]),
            &[],
            Duration::from_secs(600),
        );
        let packaged_text = text(&packaged);
        assert!(
            packaged.status.success()
                && packaged_text.contains(&format!("capsule_{finding}  (✓)"))
                && packaged_text.contains("1 verified to reproduce"),
            "{packaged_text}"
        );
        let capsule = work.join("capsules").join(format!("capsule_{finding}"));
        let clean = tempfile::tempdir().unwrap();
        let copy = clean.path().join("capsule");
        let copied = Command::new("cp")
            .arg("-r")
            .arg(&capsule)
            .arg(&copy)
            .status()
            .unwrap();
        assert!(copied.success());
        let hidden = [lib.to_path_buf(), work.to_path_buf()];
        for dir in &hidden {
            fs::rename(dir, dir.with_extension("hidden")).unwrap();
        }
        let verified = bhf(
            &args(&[&"verify-poc", &copy]),
            &[],
            Duration::from_secs(600),
        );
        for dir in &hidden {
            fs::rename(dir.with_extension("hidden"), dir).unwrap();
        }
        let verified_text = text(&verified);
        assert!(
            verified.status.success() && verified_text.contains("verify-poc: PASS"),
            "{verified_text}"
        );
    }

    /// A harness `bhf build` built with `AUTO_EXTRA_SOURCES` and
    /// `AUTO_EXTRA_INCLUDES` set (`-include iostream` among them, a header
    /// the compiler finds itself) records them in its build recipe, so its
    /// finding packages into a capsule that rebuilds offline without them in
    /// the environment; so does one regenerated with `--extra-source`.
    #[test]
    fn a_harness_built_with_extra_build_inputs_packages_into_a_verified_capsule() {
        if !cpp_toolchain() {
            eprintln!("skipping custom-harness capsule flow: clang++ or make unavailable");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let lib = write_library_needing_build_inputs(root.path());
        let work = root.path().join("bhf_work");
        let harnesses = work.join("harnesses");
        let codec = lib.join("src/codec.cpp");
        let table = lib.join("src/table.cpp");
        let config = lib.join("include/widgets/config.h");
        let id = "H-WIDGET-CAPSULE";
        let generate = |extra_source: Option<&Path>| {
            let mut command = args(&[
                &"generate-harness",
                &codec,
                &"--target",
                &"Codec::decode",
                &"--id",
                &id,
                &"--output",
                &harnesses,
                &"--extra-include",
                &lib.join("include"),
            ]);
            if let Some(source) = extra_source {
                command.push("--extra-source".into());
                command.push(source.into());
            }
            let output = bhf(&command, &[], Duration::from_secs(60));
            assert!(output.status.success(), "{}", text(&output));
        };
        generate(None);
        let includes = format!(
            "-DWIDGETS_LEGACY=1 -include {} -include iostream",
            config.display()
        );
        let built = bhf(
            &args(&[&"build", &work, &"--harness", &id]),
            &[
                ("AUTO_EXTRA_SOURCES", table.clone().into_os_string()),
                ("AUTO_EXTRA_INCLUDES", includes.clone().into()),
            ],
            Duration::from_secs(300),
        );
        assert!(built.status.success(), "build failed: {}", text(&built));
        let recipe: serde_json::Value = serde_json::from_slice(
            &fs::read(harnesses.join(id).join("coverage-build-recipe.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(recipe["schema_version"], 2, "{recipe}");
        assert_eq!(recipe["recorded_by"], "build", "{recipe}");
        assert_eq!(
            recipe["extra_sources"][0],
            table.display().to_string(),
            "{recipe}"
        );
        assert_eq!(
            recipe["extra_compile_flags"],
            serde_json::json!([
                "-DWIDGETS_LEGACY=1",
                "-include",
                config.display().to_string(),
                "-include",
                "iostream"
            ]),
            "{recipe}"
        );

        let seed = root.path().join("crash.bin");
        fs::write(&seed, CRASHING_SEED).unwrap();
        let finding_dir = fuzz_to_finding(&work, id, &seed);
        let finding = finding_dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        capsule_round_trip(&work, &lib, &finding);

        // Regenerated with --extra-source, the sibling is in the Makefile and
        // only the compile flags come from the environment.
        generate(Some(&table));
        let rebuilt = bhf(
            &args(&[&"build", &work, &"--harness", &id]),
            &[("AUTO_EXTRA_INCLUDES", includes.into())],
            Duration::from_secs(300),
        );
        assert!(rebuilt.status.success(), "build failed: {}", text(&rebuilt));
        capsule_round_trip(&work, &lib, &finding);
    }
}
