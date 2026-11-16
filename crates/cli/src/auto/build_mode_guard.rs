// SPDX-License-Identifier: Apache-2.0

//! Whether a finding's crash path depends on what
//! `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` changes. Every C/C++ lane
//! defines the macro, so a check under `#ifndef` (a signature, a checksum) is
//! compiled out and code under `#ifdef` is compiled in. A crash reached past
//! the first, or inside the second, may not reproduce on a production build;
//! [`guard_note`] says so.

use std::collections::HashMap;
use std::path::Path;

use harness_gen::fuzzing_build_mode::MACRO;

/// A region of a source file the macro switches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    /// The code is compiled only when the macro is defined (a fuzz build).
    fuzz_only: bool,
    /// 1-based line of the directive that opens the branch.
    start: u32,
    /// 1-based line of the directive that closes it.
    end: u32,
}

/// How a conditional directive tests the macro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Test {
    Defined,
    NotDefined,
    Other,
}

fn directive(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim_start().strip_prefix('#')?.trim_start();
    let name_len = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    Some((&rest[..name_len], rest[name_len..].trim()))
}

fn test_of(name: &str, operand: &str) -> Test {
    let operand: String = operand.split_whitespace().collect();
    let defined = [
        MACRO.to_owned(),
        format!("defined({MACRO})"),
        format!("defined{MACRO}"),
    ];
    match name {
        "ifdef" if operand == MACRO => Test::Defined,
        "ifndef" if operand == MACRO => Test::NotDefined,
        "if" if defined.contains(&operand) => Test::Defined,
        "if" if operand
            .strip_prefix('!')
            .is_some_and(|rest| defined.iter().any(|form| form == rest)) =>
        {
            Test::NotDefined
        }
        _ => Test::Other,
    }
}

/// The regions of `source` that the macro switches on or off.
fn regions(source: &str) -> Vec<Region> {
    // Open conditionals: the test and where its current branch started.
    let mut open: Vec<(Test, u32)> = Vec::new();
    let mut out = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let Some((name, operand)) = directive(line) else {
            continue;
        };
        match name {
            "if" | "ifdef" | "ifndef" => open.push((test_of(name, operand), number)),
            "else" | "elif" | "endif" => {
                let Some((test, start)) = open.pop() else {
                    continue;
                };
                if test != Test::Other {
                    out.push(Region {
                        fuzz_only: test == Test::Defined,
                        start,
                        end: number,
                    });
                }
                // The other branch of a plain test is the opposite region; an
                // `#elif` tests something else.
                let next = match (name, test) {
                    ("else", Test::Defined) => Some(Test::NotDefined),
                    ("else", Test::NotDefined) => Some(Test::Defined),
                    ("endif", _) => None,
                    _ => Some(Test::Other),
                };
                if let Some(next) = next {
                    open.push((next, number));
                }
            }
            _ => {}
        }
    }
    out
}

/// The line `function`'s definition starts on, at or before `line`: the
/// nearest line that starts in column 0 and names `function(`.
fn function_start(source: &str, function: &str, line: u32) -> Option<u32> {
    let call = format!("{function}(");
    let lines: Vec<&str> = source.lines().collect();
    let last = usize::try_from(line).ok()?.min(lines.len());
    (0..last).rev().find_map(|index| {
        let text = lines[index];
        let starts_in_column_0 = text
            .chars()
            .next()
            .is_some_and(|c| !c.is_whitespace() && c != '#' && c != '}' && c != '/');
        (starts_in_column_0 && text.contains(&call) && !text.trim_end().ends_with(';'))
            .then(|| u32::try_from(index + 1).unwrap_or(u32::MAX))
    })
}

/// One place on the crash path: a source file, a line, the function there.
struct Site<'a> {
    file: &'a str,
    line: u32,
    function: Option<&'a str>,
}

fn sites(raw: &serde_json::Value) -> Vec<Site<'_>> {
    let mut out: Vec<Site<'_>> = raw
        .pointer("/exception/stack")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|frame| {
            Some(Site {
                file: frame.get("file")?.as_str()?,
                line: u32::try_from(frame.get("line")?.as_u64()?).ok()?,
                function: frame.get("function").and_then(serde_json::Value::as_str),
            })
        })
        .collect();
    // A finding without a crash frame (an oracle) runs the fuzzed target.
    if out.is_empty() {
        if let (Some(file), Some(line)) = (
            raw.pointer("/target/source_path")
                .and_then(serde_json::Value::as_str),
            raw.pointer("/target/line")
                .and_then(serde_json::Value::as_u64),
        ) {
            out.push(Site {
                file,
                line: u32::try_from(line).unwrap_or(u32::MAX),
                function: raw
                    .pointer("/target/subprogram")
                    .and_then(serde_json::Value::as_str),
            });
        }
    }
    out
}

/// The note for a finding whose crash path depends on the macro, naming the
/// region (`file` shown relative to `root`), or `None`.
pub(crate) fn guard_note(raw: &serde_json::Value, root: Option<&Path>) -> Option<String> {
    let mut sources: HashMap<&str, Option<String>> = HashMap::new();
    for site in sites(raw) {
        let Some(source) = sources
            .entry(site.file)
            .or_insert_with(|| std::fs::read_to_string(site.file).ok())
            .as_deref()
        else {
            continue;
        };
        if !source.contains(MACRO) {
            continue;
        }
        let shown = root
            .and_then(|root| Path::new(site.file).strip_prefix(root).ok())
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| site.file.to_owned());
        let function_start = site
            .function
            .and_then(|function| function_start(source, function, site.line));
        for region in regions(source) {
            let inside = region.start < site.line && site.line < region.end;
            if region.fuzz_only && inside {
                return Some(format!(
                    "reachable only with {MACRO} defined: the crash path runs code \
                     under it at {shown}:{}, which a production build leaves out",
                    region.start
                ));
            }
            let passed =
                function_start.is_some_and(|start| start < region.start) && region.end < site.line;
            if !region.fuzz_only && passed {
                return Some(format!(
                    "reachable only with the check under `#ifndef {MACRO}` at \
                     {shown}:{} disabled; a production build runs it",
                    region.start
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUARDED: &str = "\
#include <string.h>
static int signature_ok(const unsigned char *b, size_t n) { return n > 8 && b[0] == 7; }

int fw_update_parse(const unsigned char *buf, size_t len)
{
  unsigned char hdr[8];
  if (len < 2) return 0;
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  if (!signature_ok(buf, len)) return -1;
#endif
  memcpy(hdr, buf + 1, buf[0]);
  return hdr[0];
}

int debug_hook(const unsigned char *buf, size_t len)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
  return buf[len];
#else
  return 0;
#endif
}

int plain(const unsigned char *buf, size_t len)
{
  return buf[len];
}
";

    fn finding(file: &Path, function: &str, line: u32) -> serde_json::Value {
        serde_json::json!({
            "exception": { "stack": [
                { "function": "__asan_memcpy" },
                { "function": function, "file": file, "line": line },
            ] }
        })
    }

    fn guarded_file() -> (crate::test_support::TestDir, std::path::PathBuf) {
        let dir = crate::test_support::TestDir::new("build-mode-guard");
        let file = dir.join("upd.c");
        std::fs::write(&file, GUARDED).unwrap();
        (dir, file)
    }

    #[test]
    fn regions_pair_each_branch_with_what_the_macro_does_to_it() {
        assert_eq!(
            regions(GUARDED),
            vec![
                Region {
                    fuzz_only: false,
                    start: 8,
                    end: 10
                },
                Region {
                    fuzz_only: true,
                    start: 17,
                    end: 19
                },
                Region {
                    fuzz_only: false,
                    start: 19,
                    end: 21
                },
            ]
        );
        assert!(regions("#if FOO\n#ifdef BAR\n#endif\n#endif\n").is_empty());
    }

    #[test]
    fn a_crash_past_a_compiled_out_check_is_noted_with_the_check() {
        let (dir, file) = guarded_file();
        let note = guard_note(&finding(&file, "fw_update_parse", 11), Some(&dir)).unwrap();
        assert_eq!(
            note,
            "reachable only with the check under `#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` \
             at upd.c:8 disabled; a production build runs it"
        );
    }

    #[test]
    fn a_crash_in_fuzz_only_code_is_noted() {
        let (dir, file) = guarded_file();
        let note = guard_note(&finding(&file, "debug_hook", 18), Some(&dir)).unwrap();
        assert!(
            note.contains("upd.c:17, which a production build leaves out"),
            "{note}"
        );
    }

    #[test]
    fn an_unguarded_crash_has_no_note() {
        let (dir, file) = guarded_file();
        assert_eq!(guard_note(&finding(&file, "plain", 26), Some(&dir)), None);
        // A crash before the guarded check did not need it compiled out.
        assert_eq!(
            guard_note(&finding(&file, "fw_update_parse", 7), Some(&dir)),
            None
        );
        // Nor does one in a source that never names the macro.
        let other = dir.join("other.c");
        std::fs::write(&other, "int f(int x)\n{\n  return 1 / x;\n}\n").unwrap();
        assert_eq!(guard_note(&finding(&other, "f", 3), Some(&dir)), None);
    }
}
