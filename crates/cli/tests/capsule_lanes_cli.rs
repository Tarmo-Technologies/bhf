// SPDX-License-Identifier: Apache-2.0
//! `bhf capsule` + `bhf verify-poc` round trips for every harness language
//! beyond C and C++ (those are in capsule_cli.rs).
//!
//! Each test writes a tiny crashing target, runs `bhf auto` on it with a
//! seconds-scale budget, packages the finding, copies the capsule to a clean
//! dir, moves the scanned tree and the work dir out of the way (so nothing the
//! capsule did not ship can be reached), and asserts that `bhf verify-poc`
//! rebuilds it there and reproduces the recorded crash. A test whose
//! toolchain is not installed skips with a message saying which.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

/// Whether `program <args>` runs successfully here.
fn runs(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// A scratch root holding `src/` (the scanned tree) and `work/`.
struct Run {
    scratch: tempfile::TempDir,
    src: PathBuf,
    work: PathBuf,
    /// Variables every bhf command of the run gets (a local package source).
    env: Vec<(String, std::ffi::OsString)>,
    /// Dirs besides the tree and the work dir that the clean rebuild must not
    /// reach (a local package source or cache).
    hidden: Vec<PathBuf>,
}

impl Run {
    fn new(files: &[(&str, &str)]) -> Self {
        let root = tempfile::Builder::new()
            .prefix("bhf-capsule-lane-")
            .tempdir()
            .unwrap();
        let src = root.path().join("src");
        for (name, text) in files {
            let path = src.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let work = root.path().join("work");
        Run {
            scratch: root,
            src,
            work,
            env: Vec::new(),
            hidden: Vec::new(),
        }
    }

    /// The scratch root the tree and the work dir are in.
    fn root(&self) -> &Path {
        self.scratch.path()
    }

    /// `program` with the run's environment.
    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.envs(self.env.iter().map(|(key, value)| (key, value)));
        command
    }

    /// `bhf` with the run's environment.
    fn bhf(&self) -> Command {
        self.command(env!("CARGO_BIN_EXE_bhf"))
    }

    /// `bhf auto` on the tree for `language`, then the first runtime crash
    /// finding it recorded.
    fn auto(&self, language: &str, seconds: u32, extra: &[&str]) -> Option<String> {
        let out = self
            .bhf()
            .arg("auto")
            .arg(&self.src)
            .arg("--work-dir")
            .arg(&self.work)
            .args(["--languages", language, "--max-targets", "1", "--jobs", "1"])
            .args([
                "--per-target-time",
                &seconds.to_string(),
                "--no-discovery-cache",
            ])
            .args(extra)
            .output()
            .expect("run bhf auto");
        let finding = crash_finding(&self.work);
        if finding.is_none() {
            eprintln!(
                "bhf auto found no runtime crash for {language}:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        finding
    }

    /// Package `id`, verify the capsule from a clean copy with the tree and
    /// the work dir gone, and return the capsule's manifest.
    fn round_trip(&self, id: &str, lang: &str) -> serde_json::Value {
        self.package(id, lang);
        self.verify_packaged(id, lang)
    }

    /// Package `id` and assert the capsule reproduced when it was packaged.
    fn package(&self, id: &str, lang: &str) {
        let packaged = self
            .bhf()
            .arg("capsule")
            .arg("--work-dir")
            .arg(&self.work)
            .args(["--finding-id", id, "--verbose"])
            .output()
            .expect("run bhf capsule");
        let stdout = String::from_utf8_lossy(&packaged.stdout);
        let stderr = String::from_utf8_lossy(&packaged.stderr);
        assert!(
            packaged.status.success() && stdout.contains("1 verified to reproduce"),
            "the {lang} capsule must reproduce when packaged; stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Verify the packaged capsule of `id` from a clean copy, with the tree,
    /// the work dir and the run's hidden dirs gone, and return its manifest.
    fn verify_packaged(&self, id: &str, lang: &str) -> serde_json::Value {
        let capsule = self.work.join("capsules").join(format!("capsule_{id}"));
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(capsule.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["lang"], lang, "{manifest}");
        assert!(
            manifest["requires"]
                .as_array()
                .is_some_and(|requires| !requires.is_empty()),
            "the manifest names the toolchain it needs: {manifest}"
        );
        // The COBOL and Fortran lanes ship a C capsule, whose `cobc -C`
        // translation keeps the source path in comments and messages; every
        // other lane relocates what it ships.
        if !matches!(lang, "cobol" | "fortran") {
            let naming = files_naming(&capsule, &[&self.src, &self.work]);
            assert!(
                naming.is_empty(),
                "a shipped {lang} file still names the scanned tree or the work dir: {naming:?}"
            );
        }
        let clean = tempfile::Builder::new()
            .prefix("bhf-capsule-clean-")
            .tempdir()
            .unwrap();
        std::fs::create_dir(clean.path().join("copies")).unwrap();
        let relative = Path::new("copies").join(format!("capsule_{id}"));
        let copy = clean.path().join(&relative);
        assert!(Command::new("cp")
            .arg("-r")
            .arg(&capsule)
            .arg(&copy)
            .status()
            .unwrap()
            .success());
        // Nothing the capsule did not ship may be reachable from the rebuild.
        let hidden: Vec<(PathBuf, PathBuf)> = [&self.src, &self.work]
            .into_iter()
            .chain(&self.hidden)
            .map(|dir| (dir.clone(), dir.with_extension("moved")))
            .collect();
        for (dir, moved) in &hidden {
            std::fs::rename(dir, moved).unwrap();
        }
        // The capsule path is relative to the current dir, as `bhf explain`
        // prints it.
        let verified = self
            .bhf()
            .arg("verify-poc")
            .arg(&relative)
            .current_dir(clean.path())
            .output();
        for (dir, moved) in &hidden {
            std::fs::rename(moved, dir).unwrap();
        }
        let verified = verified.expect("run bhf verify-poc");
        let verify_out = String::from_utf8_lossy(&verified.stdout);
        assert!(
            verified.status.success() && verify_out.contains("PASS"),
            "verify-poc must rebuild the {lang} capsule offline in a clean dir and reproduce; \
             stdout:\n{verify_out}\nstderr:\n{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert!(
            !copy.join("poc").exists() && !copy.join("build").exists(),
            "verify-poc leaves the capsule as it found it"
        );
        manifest
    }
}

/// Whether `text` names `path` as an absolute path (not inside a longer or a
/// relative one, such as a transpiler's `// ../../tmp/x/src/a.ts` comment).
fn names_absolute(text: &str, path: &str) -> bool {
    text.match_indices(path).any(|(at, _)| {
        text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '.' | '/' | '_' | '-')))
    })
}

/// The files under `dir` (but its manifest, which records where the finding
/// came from) whose text names one of `paths`.
fn files_naming(dir: &Path, paths: &[&Path]) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
                continue;
            }
            if path == dir.join("manifest.json") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            if let Some(named) = paths
                .iter()
                .find(|named| names_absolute(&text, &named.to_string_lossy()))
            {
                out.push(format!("{} names {}", path.display(), named.display()));
            }
        }
    }
    out.sort();
    out
}

/// The first runtime crash finding (`unhandled`, with a crash input) under `work`.
fn crash_finding(work: &Path) -> Option<String> {
    let mut ids: Vec<String> = std::fs::read_dir(work.join("results").join("findings"))
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let raw: serde_json::Value =
                serde_json::from_slice(&std::fs::read(entry.path().join("finding.json")).ok()?)
                    .ok()?;
            (raw["classification"] == "unhandled" && entry.path().join("testcase.bin").is_file())
                .then(|| raw["id"].as_str().map(str::to_owned))
                .flatten()
        })
        .collect();
    ids.sort();
    ids.into_iter().next()
}

macro_rules! skip_unless {
    ($cond:expr, $why:expr) => {
        if !$cond {
            eprintln!("skipping: {}", $why);
            return;
        }
    };
}

const PYTHON_TARGET: &str = "\
def parse_record(data: bytes):
    if len(data) < 1:
        raise ValueError(\"empty record\")
    if data[0] == 0x41:
        return _walk(data, 1)
    return len(data)


def _walk(data, depth):
    return _walk(data, depth + 1)
";

/// A Python capsule round-trips; verify-poc names the interpreter it needs
/// when that is missing.
#[test]
fn python_finding_round_trips_and_names_a_missing_interpreter() {
    skip_unless!(runs("python3", &["--version"]), "python3 not installed");
    let run = Run::new(&[("record_parser.py", PYTHON_TARGET)]);
    let Some(id) = run.auto("python", 6, &[]) else {
        panic!("bhf auto must find the Python crash");
    };
    let manifest = run.round_trip(&id, "python");
    assert_eq!(manifest["requires"][0]["program"], "python3", "{manifest}");
    assert!(
        manifest["requires"][0]["version"]
            .as_str()
            .is_some_and(|version| version.starts_with("Python 3")),
        "the interpreter version is recorded: {manifest}"
    );

    let capsule = run.work.join("capsules").join(format!("capsule_{id}"));
    let missing = bhf()
        .arg("verify-poc")
        .arg(&capsule)
        .env("PYTHON", "bhf-no-such-python")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&missing.stdout);
    assert!(!missing.status.success(), "{stdout}");
    assert!(
        stdout.contains("cannot rebuild the Python capsule here")
            && stdout.contains("bhf-no-such-python")
            && stdout.contains("PYTHON"),
        "verify-poc names the toolchain it needs: {stdout}"
    );
}

#[test]
fn javascript_finding_round_trips() {
    skip_unless!(runs("node", &["--version"]), "node not installed");
    let run = Run::new(&[(
        "parser.js",
        "function parseRecord(data) {\n  if (data.length > 0 && data[0] === 0x41) {\n    \
         throw new Error(\"corrupt record header\");\n  }\n  return data.length;\n}\n\
         module.exports = { parseRecord };\n",
    )]);
    let id = run
        .auto("javascript", 6, &[])
        .expect("bhf auto must find the crash");
    run.round_trip(&id, "javascript");
}

#[test]
fn typescript_finding_round_trips() {
    skip_unless!(runs("node", &["--version"]), "node not installed");
    let run = Run::new(&[(
        "parser.ts",
        "export function parseRecord(data: Uint8Array): number {\n  \
         if (data.length > 0 && data[0] === 0x41) {\n    \
         throw new Error(\"corrupt record header\");\n  }\n  return data.length;\n}\n",
    )]);
    let Some(id) = run.auto("typescript", 6, &[]) else {
        panic!("bhf auto must find the TypeScript crash");
    };
    run.round_trip(&id, "typescript");
}

#[test]
fn ruby_finding_round_trips() {
    skip_unless!(runs("ruby", &["--version"]), "ruby not installed");
    let run = Run::new(&[(
        "record_parser.rb",
        "module RecordParser\n  def self.parse_record(text)\n    \
         digits = text.count(\"0-9\")\n    1000 / digits\n  end\nend\n",
    )]);
    let id = run
        .auto("ruby", 6, &[])
        .expect("bhf auto must find the crash");
    run.round_trip(&id, "ruby");
}

#[test]
fn perl_finding_round_trips() {
    skip_unless!(runs("perl", &["-v"]), "perl not installed");
    let run = Run::new(&[(
        "RecordParser.pm",
        "package RecordParser;\nuse strict;\nuse warnings;\n\
         sub parse_record {\n    my ($text) = @_;\n    my $digits = () = $text =~ /[0-9]/g;\n    \
         return 1000 / $digits;\n}\n1;\n",
    )]);
    let id = run
        .auto("perl", 6, &[])
        .expect("bhf auto must find the crash");
    run.round_trip(&id, "perl");
}

#[test]
fn php_finding_round_trips() {
    skip_unless!(runs("php", &["--version"]), "php not installed");
    let run = Run::new(&[(
        "parser.php",
        "<?php\nnamespace Widget;\n\nfunction parse_record(string $text): int {\n    \
         $digits = preg_match_all('/[0-9]/', $text);\n    return intdiv(1000, $digits);\n}\n",
    )]);
    let id = run
        .auto("php", 6, &[])
        .expect("bhf auto must find the crash");
    run.round_trip(&id, "php");
}

#[test]
fn lua_finding_round_trips() {
    let lua = ["lua", "lua5.4", "lua5.3"]
        .iter()
        .any(|lua| runs(lua, &["-e", "return 1"]));
    skip_unless!(lua, "lua not installed");
    let run = Run::new(&[(
        "record_parser.lua",
        "local M = {}\nfunction M.parse_record(text)\n  local digits = 0\n  \
         for _ in text:gmatch(\"[0-9]\") do digits = digits + 1 end\n  \
         return 1000 // digits\nend\nreturn M\n",
    )]);
    let id = run
        .auto("lua", 6, &[])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "lua");

    // build.sh takes any of the Lua interpreter names, so verify-poc must too:
    // on a PATH without the interpreter the capsule was packaged with, but
    // with another Lua, the capsule still verifies.
    let recorded = manifest["requires"][0]["program"]
        .as_str()
        .expect("the recorded interpreter")
        .to_owned();
    let recorded_path = which::which(&recorded).expect("the recorded interpreter is installed");
    let bin = tempfile::Builder::new()
        .prefix("bhf-lua-path-")
        .tempdir()
        .unwrap();
    for entry in std::fs::read_dir("/usr/bin").unwrap().flatten() {
        let name = entry.file_name();
        if name.to_string_lossy() != recorded {
            let _ = std::os::unix::fs::symlink(entry.path(), bin.path().join(&name));
        }
    }
    let other = ["lua", "lua5.4", "lua5.3", "luajit"]
        .into_iter()
        .find(|name| *name != recorded)
        .unwrap();
    if !bin.path().join(other).exists() {
        let _ = std::fs::remove_file(bin.path().join(other));
        std::os::unix::fs::symlink(&recorded_path, bin.path().join(other)).unwrap();
    }
    let capsule = run.work.join("capsules").join(format!("capsule_{id}"));
    let verified = bhf()
        .arg("verify-poc")
        .arg(&capsule)
        .env("PATH", bin.path())
        .env_remove("LUA")
        .output()
        .expect("run bhf verify-poc");
    let verify_out = String::from_utf8_lossy(&verified.stdout);
    assert!(
        verified.status.success() && verify_out.contains("PASS"),
        "verify-poc must take another Lua interpreter when {recorded} is not on PATH; \
         stdout:\n{verify_out}\nstderr:\n{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn go_finding_round_trips() {
    skip_unless!(runs("go", &["version"]), "go not installed");
    let run = Run::new(&[
        ("go.mod", "module example.com/widget\n\ngo 1.21\n"),
        (
            "recordparser/parser.go",
            "package recordparser\n\nfunc ParseRecord(data []byte) int {\n\t\
             if len(data) == 0 {\n\t\treturn 0\n\t}\n\tif data[0] == 'A' {\n\t\t\
             return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4]) + int(data[5])\n\t}\n\t\
             return len(data)\n}\n",
        ),
    ]);
    let id = run
        .auto("go", 10, &[])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "go");
    assert_eq!(manifest["build_recipe"]["vendored"], false, "{manifest}");
}

/// A Go target whose module requires a module from outside the scanned tree:
/// the capsule vendors it from the local module cache (`go mod vendor`) and
/// rebuilds with `-mod=vendor`, with no module cache or proxy reachable. The
/// module comes from a `file://` module proxy of the test's own, so the cache
/// fills without the network.
#[test]
fn go_finding_with_a_cached_module_dependency_round_trips_vendored() {
    skip_unless!(runs("go", &["version"]), "go not installed");
    let mut run = Run::new(&[
        (
            "go.mod",
            "module example.com/widget\n\ngo 1.21\n\nrequire example.com/slots v1.0.0\n",
        ),
        (
            "recordparser/parser.go",
            "package recordparser\n\nimport \"example.com/slots\"\n\n\
             func ParseRecord(data []byte) int {\n\tif len(data) > 0 && data[0] == 'A' {\n\t\t\
             return slots.Pick(data)\n\t}\n\treturn len(data)\n}\n",
        ),
    ]);
    let proxy = run.root().join("proxy");
    write_module_proxy(
        &proxy,
        "example.com/slots",
        "v1.0.0",
        &[
            ("go.mod", "module example.com/slots\n\ngo 1.21\n"),
            (
                "slots.go",
                "package slots\n\n// Pick reads past the end of a two-slot table.\n\
                 func Pick(data []byte) int {\n\ttable := []int{1, 2}\n\t\
                 return table[len(data)+2]\n}\n",
            ),
        ],
    );
    let cache = run.root().join("modcache");
    let empty_cache = run.root().join("empty-modcache");
    std::fs::create_dir_all(&empty_cache).unwrap();
    run.env = vec![
        (
            "GOPROXY".into(),
            format!("file://{}", proxy.display()).into(),
        ),
        ("GOMODCACHE".into(), cache.clone().into()),
        ("GOSUMDB".into(), "off".into()),
        ("GOTOOLCHAIN".into(), "local".into()),
    ];
    let id = run.auto("go", 10, &[]);
    // The module cache is read-only, as Go leaves it: make it removable.
    let _cleanup = WritableOnDrop(cache.clone());
    let id = id.expect("bhf auto must find the crash");
    let capsule = run.work.join("capsules").join(format!("capsule_{id}"));
    // Packaging vendors from the cache that holds the module (with the
    // proxy switched off); the rebuild gets an empty cache and can reach
    // neither the proxy nor the cache that filled it.
    run.env[0].1 = "off".into();
    run.package(&id, "go");
    run.env[1].1 = empty_cache.clone().into();
    run.hidden = vec![proxy.clone(), cache.clone()];
    let manifest = run.verify_packaged(&id, "go");
    assert_eq!(manifest["build_recipe"]["vendored"], true, "{manifest}");
    assert_eq!(
        manifest["build_recipe"]["module_mode"], "vendor",
        "{manifest}"
    );
    assert!(
        capsule
            .join("harness/vendor/example.com/slots/slots.go")
            .is_file(),
        "the dependency ships in harness/vendor/"
    );
    assert!(capsule.join("harness/vendor/modules.txt").is_file());
}

/// Makes a dir tree writable again when dropped, so a read-only Go module
/// cache inside a scratch dir can be removed.
struct WritableOnDrop(PathBuf);

impl Drop for WritableOnDrop {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .arg("-R")
            .arg("u+w")
            .arg(&self.0)
            .status();
    }
}

/// A `file://` Go module proxy (`go help goproxy`) serving one version of
/// `module`: its `@v/list`, `.info`, `.mod` and module zip.
fn write_module_proxy(proxy: &Path, module: &str, version: &str, files: &[(&str, &str)]) {
    let dir = proxy.join(module).join("@v");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("list"), format!("{version}\n")).unwrap();
    std::fs::write(
        dir.join(format!("{version}.info")),
        format!("{{\"Version\":\"{version}\",\"Time\":\"2024-01-01T00:00:00Z\"}}"),
    )
    .unwrap();
    let go_mod = files
        .iter()
        .find(|(name, _)| *name == "go.mod")
        .map(|(_, text)| *text)
        .expect("a module zip holds its go.mod");
    std::fs::write(dir.join(format!("{version}.mod")), go_mod).unwrap();
    let entries: Vec<(String, &[u8])> = files
        .iter()
        .map(|(name, text)| (format!("{module}@{version}/{name}"), text.as_bytes()))
        .collect();
    std::fs::write(dir.join(format!("{version}.zip")), stored_zip(&entries)).unwrap();
}

/// A zip archive holding `entries` uncompressed (method 0, "stored").
fn stored_zip(entries: &[(String, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    // 1980-01-01, the earliest date a zip entry can carry.
    let (time, date) = (0u16, 0x21u16);
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let size = data.len() as u32;
        let name_len = name.len() as u16;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        for field in [20u16, 0, 0, time, date] {
            out.extend_from_slice(&field.to_le_bytes());
        }
        for field in [crc, size, size] {
            out.extend_from_slice(&field.to_le_bytes());
        }
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        for field in [20u16, 20, 0, 0, time, date] {
            central.extend_from_slice(&field.to_le_bytes());
        }
        for field in [crc, size, size] {
            central.extend_from_slice(&field.to_le_bytes());
        }
        for field in [name_len, 0, 0, 0, 0] {
            central.extend_from_slice(&field.to_le_bytes());
        }
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    let count = entries.len() as u16;
    for field in [0u16, 0, count, count] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// CRC-32 (IEEE 802.3), as a zip entry records it.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[test]
fn rust_finding_round_trips() {
    skip_unless!(
        runs("cargo", &["+nightly", "--version"]),
        "cargo with a rustup nightly toolchain not installed"
    );
    skip_unless!(runs("clang", &["--version"]), "clang not installed");
    let run = Run::new(&[
        (
            "Cargo.toml",
            "[package]\nname = \"widget\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [lib]\npath = \"src/lib.rs\"\n\n[workspace]\n",
        ),
        (
            "src/lib.rs",
            "pub fn parse_record(data: &[u8]) -> u8 {\n    \
             if !data.is_empty() && data[0] == b'A' {\n        return data[data.len() + 3];\n    }\n    0\n}\n",
        ),
    ]);
    let id = run
        .auto("rust", 10, &["--run-untrusted"])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "rust");
    assert!(
        manifest["expected_signature"]
            .as_str()
            .is_some_and(|signature| signature.contains("rust-panic")),
        "the Rust panic is the oracle, not ASan's abort report: {manifest}"
    );
}

/// Whether the local cargo cache holds a downloaded `name` crate.
fn cargo_crate_cached(name: &str) -> bool {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let Some(cache) = home.map(|home| home.join("registry").join("cache")) else {
        return false;
    };
    std::fs::read_dir(cache)
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|registry| {
            std::fs::read_dir(registry.path())
                .into_iter()
                .flatten()
                .flatten()
        })
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .strip_prefix(&format!("{name}-"))
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
}

/// A Rust target depending on a crates.io package ships it vendored, and the
/// capsule rebuilds offline from the vendored copy.
#[test]
fn rust_finding_with_a_registry_dependency_round_trips_vendored() {
    skip_unless!(
        runs("cargo", &["+nightly", "--version"]),
        "cargo with a rustup nightly toolchain not installed"
    );
    skip_unless!(runs("clang", &["--version"]), "clang not installed");
    skip_unless!(
        cargo_crate_cached("cfg-if"),
        "the cfg-if crate is not in the local cargo cache"
    );
    let run = Run::new(&[
        (
            "Cargo.toml",
            "[package]\nname = \"widget\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [lib]\npath = \"src/lib.rs\"\n\n[dependencies]\ncfg-if = \"1\"\n\n[workspace]\n",
        ),
        (
            "src/lib.rs",
            "cfg_if::cfg_if! {\n    if #[cfg(unix)] {\n        fn header_len() -> usize { 3 }\n    \
             } else {\n        fn header_len() -> usize { 4 }\n    }\n}\n\n\
             pub fn parse_record(data: &[u8]) -> u8 {\n    \
             if !data.is_empty() && data[0] == b'A' {\n        \
             return data[data.len() + header_len()];\n    }\n    0\n}\n",
        ),
    ]);
    let id = run
        .auto("rust", 10, &["--run-untrusted"])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "rust");
    assert_eq!(manifest["build_recipe"]["vendored"], true, "{manifest}");
    let capsule = run.work.join("capsules").join(format!("capsule_{id}"));
    let config = std::fs::read_to_string(capsule.join(".cargo/config.toml")).unwrap();
    assert!(
        config.contains("vendored-sources") && !config.contains(&*run.work.to_string_lossy()),
        "the shipped cargo config points at the capsule's vendor/: {config}"
    );
    assert!(
        std::fs::read_dir(capsule.join("vendor"))
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("cfg-if-")),
        "cfg-if ships in vendor/"
    );
}

#[test]
fn java_finding_round_trips() {
    skip_unless!(
        runs("javac", &["-version"]) && runs("java", &["-version"]),
        "a JDK (javac, java) is not installed"
    );
    let run = Run::new(&[(
        "src/com/acme/Magic.java",
        "package com.acme;\n\npublic class Magic {\n    public static void parse(byte[] data) {\n        \
         if (data.length < 2) {\n            return;\n        }\n        if (data[0] == 'G') {\n            \
         int[] tiny = new int[1];\n            int value = tiny[data.length];\n            \
         if (value == 0) {\n                return;\n            }\n        }\n    }\n}\n",
    )]);
    let id = run
        .auto("java", 12, &[])
        .expect("bhf auto must find the crash");
    run.round_trip(&id, "java");
}

fn have_gnat() -> bool {
    runs("gprbuild", &["--version"]) && runs("gnatmake", &["--version"])
}

const ADA_SPEC: &str = "\
package Record_Parser is
   function Parse_Record (Data : String) return Natural;
end Record_Parser;
";

const ADA_BODY: &str = "\
package body Record_Parser is
   function Parse_Record (Data : String) return Natural is
      type Slot_Array is array (1 .. 4) of Natural;
      Slots : constant Slot_Array := (others => 0);
   begin
      if Data'Length > 0 and then Data (Data'First) = 'A' then
         return Slots (Data'Length + 4);
      end if;
      return Data'Length;
   end Parse_Record;
end Record_Parser;
";

/// An Ada finding round-trips: the capsule rebuilds the generated project
/// with gprbuild and replays through the stdin event-log protocol.
#[test]
fn ada_finding_round_trips_through_the_event_log() {
    skip_unless!(have_gnat(), "GNAT with gprbuild not installed");
    let run = Run::new(&[
        ("record_parser.ads", ADA_SPEC),
        ("record_parser.adb", ADA_BODY),
    ]);
    let id = run
        .auto("ada", 6, &[])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "ada");
    assert_eq!(manifest["protocol"], "stdin event log", "{manifest}");
    assert_eq!(
        manifest["expected_signature"], "ada:CONSTRAINT_ERROR",
        "{manifest}"
    );
    assert_eq!(
        manifest["finding_signature"], manifest["expected_signature"],
        "the replay raises the exception the finding recorded: {manifest}"
    );
    assert!(
        manifest["run"]
            .as_str()
            .is_some_and(|run| run.contains("BHF_EVENTS_PATH") && run.starts_with("cat ")),
        "{manifest}"
    );
    let recipe = &manifest["build_recipe"];
    assert!(
        recipe["switches"]
            .as_array()
            .is_some_and(|switches| switches.iter().any(|s| s == "-gnata")),
        "the switches are recorded: {manifest}"
    );
    assert!(recipe["gnat_version"].as_str().is_some(), "{manifest}");

    // A rebuilt PoC raising another exception than the finding recorded
    // reproduces a crash, but not this finding's: the capsule says so, and
    // verify-poc checks the replay against the finding's exception.
    let finding_path = run
        .work
        .join("results")
        .join("findings")
        .join(&id)
        .join("finding.json");
    let mut finding: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&finding_path).unwrap()).unwrap();
    finding["exception"]["name"] = serde_json::json!("Program_Error");
    std::fs::write(&finding_path, serde_json::to_vec_pretty(&finding).unwrap()).unwrap();
    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&run.work)
        .args(["--finding-id", &id])
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    let stderr = String::from_utf8_lossy(&packaged.stderr);
    assert!(
        !packaged.status.success()
            && stdout.contains("0 verified to reproduce")
            && stdout.contains("ada:PROGRAM_ERROR"),
        "a replay raising another exception is not this finding's crash; stdout:\n{stdout}\n\
         stderr:\n{stderr}"
    );
    let capsule = run.work.join("capsules").join(format!("capsule_{id}"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(capsule.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["finding_signature"], "ada:PROGRAM_ERROR",
        "{manifest}"
    );
    assert_eq!(
        manifest["expected_signature"], "ada:CONSTRAINT_ERROR",
        "{manifest}"
    );
    assert_eq!(manifest["reproduced_other_crash"], true, "{manifest}");
    let verified = bhf()
        .arg("verify-poc")
        .arg(&capsule)
        .output()
        .expect("run bhf verify-poc");
    let verify_out = String::from_utf8_lossy(&verified.stdout);
    assert!(
        !verified.status.success()
            && verify_out.contains("MISMATCH")
            && verify_out.contains("expected: ada:PROGRAM_ERROR"),
        "verify-poc checks the finding's exception; stdout:\n{verify_out}"
    );
}

/// An Ada harness whose generated project extends the operator's own `.gpr`
/// ships that project and the sources it names.
#[test]
fn ada_finding_extending_the_operator_project_round_trips() {
    skip_unless!(have_gnat(), "GNAT with gprbuild not installed");
    let run = Run::new(&[
        (
            "widget.gpr",
            "project Widget is\n   for Source_Dirs use (\"src\");\n   for Object_Dir use \"obj\";\nend Widget;\n",
        ),
        ("src/record_parser.ads", ADA_SPEC),
        ("src/record_parser.adb", ADA_BODY),
    ]);
    let id = run
        .auto("ada", 6, &[])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "ada");
    assert_eq!(
        manifest["build_recipe"]["extends"], "sources/widget.gpr",
        "{manifest}"
    );
}

#[test]
fn cobol_finding_round_trips() {
    skip_unless!(
        runs("cobc", &["--version"]) && runs("clang", &["--version"]),
        "cobc (GnuCOBOL) and clang not installed"
    );
    let run = Run::new(&[(
        "parseit.cob",
        "       IDENTIFICATION DIVISION.\n       PROGRAM-ID. PARSEIT.\n       DATA DIVISION.\n       \
         WORKING-STORAGE SECTION.\n       01 IDX PIC 9(4).\n       LINKAGE SECTION.\n       \
         01 BUF PIC X(8).\n       PROCEDURE DIVISION USING BUF.\n           IF BUF(1:1) = \"Z\"\n               \
         MOVE 200 TO IDX\n               DISPLAY BUF(IDX:1)\n           END-IF\n           GOBACK.\n",
    )]);
    // The COBOL lane looks for copybooks from the tree's project root (the
    // nearest dir with `.git`, else five levels up): mark the scratch root so
    // the search stays inside it.
    std::fs::create_dir_all(run.src.parent().unwrap().join(".git")).unwrap();
    let seeds = run.src.parent().unwrap().join("seeds");
    std::fs::create_dir_all(&seeds).unwrap();
    std::fs::write(seeds.join("z.bin"), b"Z").unwrap();
    let id = run
        .auto("cobol", 6, &["--seed-dir", &seeds.to_string_lossy()])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "cobol");
    assert!(
        manifest["expected_signature"]
            .as_str()
            .is_some_and(|signature| signature.starts_with("COBOL:")),
        "libcob's runtime check is the oracle: {manifest}"
    );
}

#[test]
fn fortran_finding_round_trips_from_source() {
    skip_unless!(
        runs("gfortran", &["--version"]) && runs("clang", &["--version"]),
        "gfortran and clang not installed"
    );
    let run = Run::new(&[(
        "parse.f90",
        "subroutine parse_record(data)\n  implicit none\n  character(len=*), intent(in) :: data\n  \
         integer, allocatable :: slots(:)\n  integer :: i\n  allocate(slots(4))\n  slots = 0\n  \
         if (len(data) > 0) then\n    if (data(1:1) == 'A') then\n      i = len(data) + 4\n      \
         slots(i) = 7\n      print *, slots(i)\n    end if\n  end if\n  deallocate(slots)\n\
         end subroutine parse_record\n",
    )]);
    let id = run
        .auto("fortran", 6, &[])
        .expect("bhf auto must find the crash");
    let manifest = run.round_trip(&id, "fortran");
    assert_eq!(
        manifest["build_recipe"]["fortran_objects"], 1,
        "the Fortran object is compiled from the shipped source: {manifest}"
    );
}

/// The C# lane: `bhf auto` builds C# harnesses against the SharpFuzz NuGet
/// package. When the local package cache holds it, the finding comes from
/// `bhf auto`; an offline host without it cannot build a C# harness at all, so
/// the test then lays out the harness exactly as the C# lane writes it (the
/// harness project, bhf's .NET driver, the entry, the build output's
/// SharpFuzz.Common.dll and the launcher) from the SharpFuzz command-line
/// tool's own copy of the assembly.
#[test]
fn csharp_harness_round_trips() {
    skip_unless!(
        runs("dotnet", &["--version"]),
        "the .NET SDK is not installed"
    );
    if sharpfuzz_package_cached() {
        let run = Run::new(&[
            ("Widget.csproj", WIDGET_CSPROJ),
            ("Parser.cs", WIDGET_PARSER_CS),
        ]);
        let id = run
            .auto("csharp", 10, &["--run-untrusted"])
            .expect("bhf auto must find the crash");
        run.round_trip(&id, "csharp");
        return;
    }
    let Some(sharpfuzz_common) = sharpfuzz_common_dll() else {
        eprintln!(
            "skipping: no SharpFuzz.Common.dll (install the sharpfuzz tool: dotnet tool install \
             --global SharpFuzz.CommandLine)"
        );
        return;
    };
    let run = Run::new(&[
        ("Widget.csproj", WIDGET_CSPROJ),
        ("Parser.cs", WIDGET_PARSER_CS),
    ]);
    let id = lay_out_csharp_harness(&run, &sharpfuzz_common, None);
    let manifest = run.round_trip(&id, "csharp");
    assert_eq!(
        manifest["expected_signature"], "BHF-201:csharp-index-out-of-bounds",
        "{manifest}"
    );
}

/// A C# target that references a NuGet package: the capsule vendors the
/// package from the local NuGet package cache into `vendor/nuget` and restores
/// from that feed alone, with no other feed or cache reachable. The package is
/// packed by the test into a local feed dir, which fills a package cache of
/// the test's own without the network.
#[test]
fn csharp_finding_with_a_cached_package_round_trips_vendored() {
    skip_unless!(
        runs("dotnet", &["--version"]),
        "the .NET SDK is not installed"
    );
    let Some(sharpfuzz_common) = sharpfuzz_common_dll() else {
        eprintln!(
            "skipping: no SharpFuzz.Common.dll (install the sharpfuzz tool: dotnet tool install \
             --global SharpFuzz.CommandLine)"
        );
        return;
    };
    let mut run = Run::new(&[
        ("Widget.csproj", WIDGET_CODEC_CSPROJ),
        ("Parser.cs", WIDGET_CODEC_PARSER_CS),
    ]);
    let codec = run.root().join("codec");
    let feed = run.root().join("feed");
    let cache = run.root().join("nuget-cache");
    let empty_cache = run.root().join("empty-nuget-cache");
    std::fs::create_dir_all(&codec).unwrap();
    std::fs::create_dir_all(&feed).unwrap();
    std::fs::create_dir_all(&empty_cache).unwrap();
    std::fs::write(codec.join("Widget.Codec.csproj"), CODEC_CSPROJ).unwrap();
    std::fs::write(codec.join("Slots.cs"), CODEC_SLOTS_CS).unwrap();
    run.env = vec![
        ("NUGET_PACKAGES".into(), cache.clone().into()),
        ("DOTNET_CLI_TELEMETRY_OPTOUT".into(), "1".into()),
        ("DOTNET_NOLOGO".into(), "1".into()),
    ];
    let packed = run
        .command("dotnet")
        .arg("pack")
        .arg(codec.join("Widget.Codec.csproj"))
        .args(["-c", "Release", "--nologo", "-o"])
        .arg(&feed)
        .arg(format!("-p:RestoreSources={}", feed.display()))
        .output()
        .expect("run dotnet pack");
    assert!(
        packed.status.success() && feed.join("Widget.Codec.1.0.0.nupkg").is_file(),
        "dotnet pack must write the package into the local feed:\n{}\n{}",
        String::from_utf8_lossy(&packed.stdout),
        String::from_utf8_lossy(&packed.stderr)
    );
    let id = lay_out_csharp_harness(&run, &sharpfuzz_common, Some(&feed));
    assert!(
        cache
            .join("widget.codec/1.0.0/widget.codec.1.0.0.nupkg")
            .is_file(),
        "the harness restore put the package in the cache"
    );
    run.package(&id, "csharp");
    // The rebuild gets an empty package cache and reaches neither the feed,
    // the cache that holds the package, nor the package's project.
    run.env[0].1 = empty_cache.clone().into();
    run.hidden = vec![codec, feed, cache];
    let manifest = run.verify_packaged(&id, "csharp");
    assert_eq!(
        manifest["build_recipe"]["vendored_packages"],
        serde_json::json!(["Widget.Codec 1.0.0"]),
        "{manifest}"
    );
    assert_eq!(
        manifest["expected_signature"], "BHF-201:csharp-index-out-of-bounds",
        "{manifest}"
    );
    let capsule = run.work.join("capsules").join(format!("capsule_{id}"));
    assert!(capsule
        .join("vendor/nuget/widget.codec.1.0.0.nupkg")
        .is_file());
}

/// Lay out a C# harness for `Widget.Parser.ParseRecord` exactly as the C# lane
/// writes it (the harness project, bhf's .NET driver, the entry, the build
/// output's SharpFuzz.Common.dll and the launcher), plus a recorded finding,
/// and return the finding id. With `feed`, the harness project's packages are
/// restored from that local feed, as the lane's own build restores them: the
/// restore resolves them into the run's package cache and records them in
/// `proj/obj/project.assets.json` (SharpFuzz, which no local feed holds, is
/// left out of that restore).
fn lay_out_csharp_harness(run: &Run, sharpfuzz_common: &Path, feed: Option<&Path>) -> String {
    let harness_id = "H-S0001-0000C0DE";
    let id = "F-0000-0000c0de";
    let harness = run.work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(harness.join("proj")).unwrap();
    std::fs::create_dir_all(harness.join("out")).unwrap();
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../csharp_runtime/Driver.cs");
    std::fs::copy(runtime, harness.join("proj/Driver.cs")).unwrap();
    std::fs::copy(sharpfuzz_common, harness.join("out/SharpFuzz.Common.dll")).unwrap();
    std::fs::write(
        harness.join("proj/BhfEntry.cs"),
        "namespace Bhfgen {\n  public static class BhfEntry {\n    public static void Run(byte[] data) {\n      \
         var bhfArg0 = data;\n      global::Widget.Parser.ParseRecord(bhfArg0);\n    }\n  }\n}\n",
    )
    .unwrap();
    let csproj = |sharpfuzz: &str| {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    \
             <TargetFramework>net8.0</TargetFramework>\n    <LangVersion>latest</LangVersion>\n    \
             <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n    \
             <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <Nullable>disable</Nullable>\n    \
             <AssemblyName>bhf_harness</AssemblyName>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    \
             <ImplicitUsings>disable</ImplicitUsings>\n  </PropertyGroup>\n  <ItemGroup>\n    \
             <Compile Include=\"Driver.cs;BhfEntry.cs\" />\n    {sharpfuzz}\n    \
             <ProjectReference Include=\"{}\" SetTargetFramework=\"TargetFramework=net8.0\" />\n  \
             </ItemGroup>\n</Project>\n",
            run.src.join("Widget.csproj").display()
        )
    };
    let project = harness.join("proj/bhf_harness.csproj");
    if let Some(feed) = feed {
        std::fs::write(
            &project,
            csproj(&format!(
                "<Reference Include=\"SharpFuzz.Common\"><HintPath>{}</HintPath></Reference>",
                harness.join("out/SharpFuzz.Common.dll").display()
            )),
        )
        .unwrap();
        let restored = run
            .command("dotnet")
            .arg("restore")
            .arg(&project)
            .arg("--nologo")
            .arg(format!("-p:RestoreSources={}", feed.display()))
            .output()
            .expect("run dotnet restore");
        assert!(
            restored.status.success() && harness.join("proj/obj/project.assets.json").is_file(),
            "the harness project must restore from the local feed:\n{}\n{}",
            String::from_utf8_lossy(&restored.stdout),
            String::from_utf8_lossy(&restored.stderr)
        );
    }
    std::fs::write(
        &project,
        csproj("<PackageReference Include=\"SharpFuzz\" Version=\"2.3.0\" />"),
    )
    .unwrap();
    let launcher = harness.join("main");
    std::fs::write(
        &launcher,
        format!(
            "#!/bin/sh\n# BHF_FRAMED BHF_CS_LAUNCHER bhf .NET driver launcher (native C# lane).\n\
             BHF_CS_NAMESPACE=\"Widget\" \\\nBHF_EXPECTED_EXCEPTIONS=\"\" \\\n\
             DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_ROLL_FORWARD=Major \\\n\
             exec dotnet \"{}\" \"$@\"\n",
            harness.join("out/bhf_harness.dll").display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::create_dir_all(run.work.join("auto")).unwrap();
    std::fs::write(
        run.work.join("auto/run.json"),
        serde_json::json!({"source_root": run.src}).to_string(),
    )
    .unwrap();
    let finding = run.work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding).unwrap();
    std::fs::write(finding.join("testcase.bin"), b"A").unwrap();
    std::fs::write(
        finding.join("finding.json"),
        serde_json::json!({
            "id": id, "classification": "unhandled", "harness_id": harness_id,
            "rule_id": "BHF-201",
        })
        .to_string(),
    )
    .unwrap();
    id.to_owned()
}

const WIDGET_CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
     <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n</Project>\n";

const WIDGET_PARSER_CS: &str = "namespace Widget\n{\n    public static class Parser\n    {\n        \
     public static int ParseRecord(byte[] data)\n        {\n            \
     if (data.Length > 0 && data[0] == 0x41)\n            {\n                \
     int[] slots = new int[2];\n                return slots[data.Length + 4];\n            }\n            \
     return data.Length;\n        }\n    }\n}\n";

/// The target project of the vendored-package test: it references the
/// `Widget.Codec` package, whose index runs past the two slots.
const WIDGET_CODEC_CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
     <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n  <ItemGroup>\n    \
     <PackageReference Include=\"Widget.Codec\" Version=\"1.0.0\" />\n  </ItemGroup>\n</Project>\n";

const WIDGET_CODEC_PARSER_CS: &str = "namespace Widget\n{\n    public static class Parser\n    {\n        \
     public static int ParseRecord(byte[] data)\n        {\n            \
     if (data.Length > 0 && data[0] == 0x41)\n            {\n                \
     int[] slots = new int[2];\n                return slots[Widget.Codec.Slots.Index(data)];\n            }\n            \
     return data.Length;\n        }\n    }\n}\n";

const CODEC_CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
     <TargetFramework>net8.0</TargetFramework>\n    <PackageId>Widget.Codec</PackageId>\n    \
     <Version>1.0.0</Version>\n  </PropertyGroup>\n</Project>\n";

const CODEC_SLOTS_CS: &str =
    "namespace Widget.Codec\n{\n    public static class Slots\n    {\n        \
     public static int Index(byte[] data) => data.Length + 4;\n    }\n}\n";

/// Whether the local NuGet package cache holds the SharpFuzz package the C#
/// lane's fuzz build references.
fn sharpfuzz_package_cached() -> bool {
    let cache = std::env::var_os("NUGET_PACKAGES")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".nuget/packages"))
        });
    cache.is_some_and(|cache| cache.join("sharpfuzz").is_dir())
}

/// The SharpFuzz.Common.dll the sharpfuzz global tool ships, when installed.
fn sharpfuzz_common_dll() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let store = home.join(".dotnet/tools/.store/sharpfuzz.commandline");
    let mut stack = vec![store];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .is_some_and(|name| name == "SharpFuzz.Common.dll")
                && path.to_string_lossy().contains("net8.0")
            {
                return Some(path);
            }
        }
    }
    None
}

/// A Go harness whose module needs a dependency the local module cache does
/// not hold is refused with that reason, and nothing is packaged.
#[test]
fn a_go_dependency_that_cannot_be_vendored_offline_is_refused() {
    skip_unless!(runs("go", &["version"]), "go not installed");
    let run = Run::new(&[
        (
            "go.mod",
            "module example.com/widget\n\ngo 1.21\n\nrequire example.invalid/absent v1.0.0\n",
        ),
        ("widget.go", "package widget\n"),
    ]);
    let harness_id = "H-G0001-0000BEEF";
    let id = "F-0000-0000beef";
    let harness = run.work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(
        harness.join("go.mod"),
        format!(
            "module example.com/widget/bhfharness\n\ngo 1.21\n\n\
             require example.com/widget v0.0.0-incompatible\n\nreplace example.com/widget => {}\n",
            serde_json::to_string(&run.src.to_string_lossy()).unwrap()
        ),
    )
    .unwrap();
    std::fs::write(
        harness.join("bhf_harness.go"),
        "package main\n\nimport _ \"example.com/widget\"\n\nfunc main() {}\n",
    )
    .unwrap();
    std::fs::create_dir_all(run.work.join("auto")).unwrap();
    std::fs::write(
        run.work.join("auto/run.json"),
        serde_json::json!({"source_root": run.src}).to_string(),
    )
    .unwrap();
    let finding = run.work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding).unwrap();
    std::fs::write(finding.join("testcase.bin"), b"A").unwrap();
    std::fs::write(
        finding.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();
    let out = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&run.work)
        .args(["--finding-id", id])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("cannot package {id}"))
            && stderr.contains("Go harness")
            && stderr.contains("cannot be vendored for an offline rebuild")
            && stderr.contains("example.invalid/absent"),
        "the refusal names the dependency that cannot be vendored:\n{stderr}"
    );
    assert!(!run.work.join("capsules").exists(), "{stderr}");
}

/// An Ada harness whose generated project extends a project outside the
/// scanned tree is refused with the path, and explain does not offer capsule.
#[test]
fn an_ada_project_outside_the_scanned_tree_is_refused() {
    let run = Run::new(&[("record_parser.ads", ADA_SPEC)]);
    let elsewhere = run.src.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("base.gpr"), "project Base is\nend Base;\n").unwrap();
    let harness_id = "H-A0001-0000ADA0";
    let id = "F-0000-0000ada0";
    let build = run.work.join("build").join(harness_id);
    std::fs::create_dir_all(&build).unwrap();
    std::fs::write(
        build.join("bhf_build.gpr"),
        format!(
            "with \"adafuzz_runtime.gpr\";\n\nproject Bhf_Build extends \"{}\" is\n\n   \
             for Source_Dirs use (\"{}\");\n   for Main use (\"main.adb\");\nend Bhf_Build;\n",
            elsewhere.join("base.gpr").display(),
            run.src.display()
        ),
    )
    .unwrap();
    let harness = run.work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"ada"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(run.work.join("auto")).unwrap();
    std::fs::write(
        run.work.join("auto/run.json"),
        serde_json::json!({"source_root": run.src}).to_string(),
    )
    .unwrap();
    let finding = run.work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding).unwrap();
    std::fs::write(finding.join("testcase.bin"), b"A").unwrap();
    std::fs::write(
        finding.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();
    let out = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&run.work)
        .args(["--finding-id", id])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("Ada harness")
            && stderr.contains("outside the scanned tree")
            && stderr.contains(&elsewhere.join("base.gpr").display().to_string()),
        "{stderr}"
    );
    let explain = bhf()
        .arg("explain")
        .arg("--work-dir")
        .arg(&run.work)
        .args(["--finding-id", id])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&explain.stdout);
    let reproduce = text.split("REPRODUCE OFFLINE").nth(1).unwrap_or_default();
    assert!(!reproduce.contains("bhf verify-poc"), "{reproduce}");
    assert!(
        reproduce.contains("bhf capsule is not available for this finding"),
        "{reproduce}"
    );
}
