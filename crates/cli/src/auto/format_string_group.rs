// SPDX-License-Identifier: Apache-2.0

//! One format-string bug, one finding group. An input-controlled `snprintf`
//! format crashes inside the C library in several ways (a `%n` write through a
//! small pointer, a `%s` read of a garbage argument), each its own sanitizer
//! finding with a NULL-dereference or wild-access CWE, beside the runtime
//! oracle's CWE-134 finding. A crash whose faulting frames are printf
//! internals, called from a site whose format argument is not a string literal
//! (or in a harness the format-string oracle fired for), is the format-string
//! bug: it becomes BHF-408 (CWE-134) and shares one cluster key with the
//! harness's other format-string findings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The format-string rule.
const RULE: &str = "BHF-408";

/// printf-family entry points, with the argument index of the format.
const APIS: &[(&str, usize)] = &[
    ("printf", 0),
    ("vprintf", 0),
    ("fprintf", 1),
    ("vfprintf", 1),
    ("dprintf", 1),
    ("vdprintf", 1),
    ("sprintf", 1),
    ("vsprintf", 1),
    ("asprintf", 1),
    ("vasprintf", 1),
    ("snprintf", 2),
    ("vsnprintf", 2),
    ("syslog", 1),
    ("vsyslog", 1),
];

/// Frames above the call site that may sit inside the C library's formatter.
const MAX_LIBRARY_FRAMES: usize = 16;

/// The printf-family API a frame's function is, without interceptor and
/// fortify spellings (`__interceptor_snprintf`, `__snprintf_chk`).
fn api_of(function: &str) -> Option<&'static str> {
    let bare = function
        .trim_start_matches("___interceptor_")
        .trim_start_matches("__interceptor_")
        .trim_start_matches("__")
        .trim_end_matches("_chk")
        .trim_end_matches("_internal");
    APIS.iter().map(|(api, _)| *api).find(|api| *api == bare)
}

/// Where a printf-family call that crashed was made.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallSite {
    api: &'static str,
    file: String,
    line: u64,
    function: Option<String>,
}

/// The call site of a crash inside a printf-family call: the first frame with
/// a source line below the innermost frames, when one of them is the API.
fn call_site(raw: &Value) -> Option<CallSite> {
    let frames = raw.pointer("/exception/stack")?.as_array()?;
    let mut api = None;
    for frame in frames.iter().take(MAX_LIBRARY_FRAMES) {
        let function = frame.get("function").and_then(Value::as_str).unwrap_or("");
        if let Some(name) = api_of(function) {
            api = Some(name);
            continue;
        }
        let Some(api) = api else {
            continue;
        };
        let file = frame.get("file").and_then(Value::as_str)?;
        let line = frame.get("line").and_then(Value::as_u64)?;
        return Some(CallSite {
            api,
            file: file.to_owned(),
            line,
            function: (!function.is_empty()).then(|| function.to_owned()),
        });
    }
    None
}

/// The arguments of the first `api(` call in `text`, split at top-level
/// commas.
fn call_arguments<'a>(text: &'a str, api: &str) -> Option<Vec<&'a str>> {
    let bytes = text.as_bytes();
    let mut search = 0;
    let open = loop {
        let at = search + text[search..].find(api)?;
        let before = at.checked_sub(1).map(|i| bytes[i]);
        let after = text[at + api.len()..].trim_start();
        if !before.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_') && after.starts_with('(')
        {
            break at + api.len() + (text[at + api.len()..].len() - after.len());
        }
        search = at + api.len();
    };
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut start = open + 1;
    let mut args = Vec::new();
    let mut i = open + 1;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 1;
                } else if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'(' | b'[' | b'{' => depth += 1,
                b')' if depth == 0 => {
                    args.push(text[start..i].trim());
                    return Some(args);
                }
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => {
                    args.push(text[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            },
        }
        i += 1;
    }
    None
}

/// Whether the `api` call at `file:line` passes a format that is not a string
/// literal. `false` when the source or the call cannot be read.
fn format_is_nonliteral(site: &CallSite) -> bool {
    let Ok(source) = std::fs::read_to_string(&site.file) else {
        return false;
    };
    let Some(index) = usize::try_from(site.line)
        .ok()
        .and_then(|l| l.checked_sub(1))
    else {
        return false;
    };
    // A call may continue onto the next lines.
    let text: String = source
        .lines()
        .skip(index)
        .take(4)
        .collect::<Vec<_>>()
        .join(" ");
    let position = APIS
        .iter()
        .find(|(api, _)| *api == site.api)
        .map(|(_, position)| *position);
    let Some(arguments) = position.and_then(|_| call_arguments(&text, site.api)) else {
        return false;
    };
    arguments
        .get(position.unwrap_or_default())
        .is_some_and(|format| !format.is_empty() && !format.starts_with('"'))
}

fn is_format_oracle(raw: &Value) -> bool {
    raw.get("rule_id").and_then(Value::as_str) == Some(RULE) && raw.get("oracle").is_some()
}

/// A capability finding for the input-controlled format itself.
fn is_format_capability(raw: &Value) -> bool {
    raw.pointer("/capability/kind").and_then(Value::as_str) == Some("format-string")
}

/// The cluster key every format-string finding of `harness_id` shares.
fn shared_cluster(harness_id: &str) -> corpus::cluster::ClusterKey {
    corpus::cluster::cluster_key_from_frames(&[
        "format-string".to_owned(),
        corpus::cluster::crash_scope(harness_id, None),
    ])
}

/// Rewrite each format-string crash of a harness as the format-string bug and
/// group it with that harness's format-string oracle finding. Best-effort:
/// an unreadable or malformed `finding.json` is left alone.
pub(crate) fn group_format_string_findings(work_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(corpus::layout::findings_dir(work_dir)) else {
        return;
    };
    let mut by_harness: BTreeMap<String, Vec<(PathBuf, Value)>> = BTreeMap::new();
    for entry in entries.flatten() {
        let path = entry.path().join("finding.json");
        let Some(raw) = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        else {
            continue;
        };
        let Some(harness) = raw.get("harness_id").and_then(Value::as_str) else {
            continue;
        };
        by_harness
            .entry(harness.to_owned())
            .or_default()
            .push((path, raw));
    }
    for (harness, findings) in by_harness {
        let oracle_fired = findings.iter().any(|(_, raw)| is_format_oracle(raw));
        let sites: Vec<Option<CallSite>> = findings
            .iter()
            .map(|(_, raw)| {
                call_site(raw).filter(|site| oracle_fired || format_is_nonliteral(site))
            })
            .collect();
        // The oracle saw the format, not where it was passed; a crash says.
        let first_site = sites.iter().flatten().next().cloned();
        let cluster = shared_cluster(&harness);
        for ((path, mut raw), site) in findings.into_iter().zip(sites) {
            let oracle = is_format_oracle(&raw);
            if site.is_none() && !oracle && !is_format_capability(&raw) {
                continue;
            }
            let before = raw.clone();
            if let Some(site) = &site {
                reclassify(&mut raw, site, oracle_fired, &path);
            }
            if let (true, Some(site), Some(target)) = (
                oracle,
                &first_site,
                raw.get_mut("target").and_then(Value::as_object_mut),
            ) {
                target.insert(
                    "location".to_owned(),
                    serde_json::json!({ "path": site.file, "line": site.line }),
                );
            }
            let Some(obj) = raw.as_object_mut() else {
                continue;
            };
            obj.insert(
                "cluster_key".to_owned(),
                Value::String(cluster.short.clone()),
            );
            obj.insert(
                "cluster_key_full".to_owned(),
                Value::String(cluster.full.clone()),
            );
            obj.insert(
                "cluster_normalized_frames".to_owned(),
                serde_json::json!(cluster.frames),
            );
            obj.insert("cluster_fallback".to_owned(), Value::Bool(false));
            if raw == before {
                continue;
            }
            corpus::finding::append_history(
                &mut raw,
                "auto",
                &[
                    "rule_id",
                    "format_string",
                    "target.location",
                    "cluster_key",
                    "actionability",
                ],
            );
            if let Ok(bytes) = serde_json::to_vec_pretty(&raw) {
                if let Err(error) = std::fs::write(&path, bytes) {
                    bhfeprintln!(
                        "bhf auto: warning: group format-string finding {}: {error}",
                        path.display()
                    );
                }
            }
        }
    }
}

/// Make a crash finding the format-string bug: rule BHF-408 (CWE-134) at its
/// call site, keeping the crash's own severity when that is higher, with the
/// actionability recomputed for the new rule.
fn reclassify(raw: &mut Value, site: &CallSite, oracle_fired: bool, path: &Path) {
    let previous = raw
        .get("rule_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if previous.as_deref() == Some(RULE) {
        return;
    }
    let severity = raw
        .get("severity")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            previous
                .as_deref()
                .and_then(finding_rules::by_id)
                .map(|rule| rule.default_severity.as_str().to_owned())
        });
    let mode = raw
        .pointer("/actionability/mode")
        .cloned()
        .and_then(|mode| serde_json::from_value::<actionability::RunMode>(mode).ok())
        .unwrap_or_default();
    let Some(obj) = raw.as_object_mut() else {
        return;
    };
    obj.insert("rule_id".to_owned(), Value::String(RULE.to_owned()));
    if let Some(severity) = severity {
        obj.insert("severity".to_owned(), Value::String(severity));
    }
    obj.insert(
        "format_string".to_owned(),
        serde_json::json!({
            "api": site.api,
            "call_site": { "file": site.file, "line": site.line, "function": site.function },
            "crash_rule_id": previous,
            "evidence": if oracle_fired { "format_string_oracle" } else { "nonliteral_format_argument" },
        }),
    );
    obj.remove("actionability");
    let mut recomputed = actionability::value_for_finding(mode, raw, Some(path));
    // The crash's own memory-safety CWE stays as the secondary one.
    let crash_cwe = recomputed
        .pointer("/cwe/0")
        .and_then(Value::as_str)
        .filter(|cwe| *cwe != "CWE-134")
        .map(str::to_owned);
    if let Some(record) = recomputed.as_object_mut() {
        let mut cwe = vec![Value::String("CWE-134".to_owned())];
        cwe.extend(crash_cwe.map(Value::String));
        record.insert("cwe".to_owned(), Value::Array(cwe));
        record.insert(
            "cwe_name".to_owned(),
            Value::String("Use of Externally-Controlled Format String".to_owned()),
        );
        let caller = site.function.as_deref().unwrap_or("the target");
        record.insert(
            "explanation".to_owned(),
            Value::String(format!(
                "`{caller}` passes input-controlled bytes to `{api}` as its format \
                 ({file}:{line}), and the C library faulted while reading the \
                 conversions in them. An attacker who controls a format string can \
                 read memory with `%s`/`%x` and write it with `%n`; pass the data as \
                 an argument to a literal format such as \"%s\" instead.",
                api = site.api,
                file = site.file,
                line = site.line,
            )),
        );
    }
    if let Some(obj) = raw.as_object_mut() {
        obj.insert("actionability".to_owned(), recomputed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printf_crash(file: &Path, line: u64) -> Value {
        serde_json::json!({
            "id": "F-0001-aaaa",
            "harness_id": "H-C0001",
            "rule_id": "BHF-206",
            "classification": "ASAN_SEGV",
            "exception": {
                "name": "ASAN_SEGV",
                "stack": [
                    { "function": "printf_positional", "file": "stdio-common/vfprintf-internal.c", "line": 1800 },
                    { "function": "__vsnprintf_internal", "file": "libio/vsnprintf.c", "line": 96 },
                    { "function": "snprintf", "file": "stdio-common/snprintf.c", "line": 31 },
                    { "function": "log_message", "file": file, "line": line },
                    { "function": "bhf_run_one", "file": "main.c", "line": 92 },
                ]
            }
        })
    }

    #[test]
    fn printf_internal_fault_with_nonliteral_format_is_cwe_134() {
        let dir = crate::test_support::TestDir::new("format-string-group");
        let source = dir.join("fmt.c");
        std::fs::write(
            &source,
            "#include <stdio.h>\nint log_message(const char *msg) {\n  char buf[64];\n  \
             snprintf(buf, sizeof buf, \"%s\", msg);\n  snprintf(buf,\n           sizeof buf, msg);\n  \
             return 0;\n}\n",
        )
        .unwrap();
        let nonliteral = call_site(&printf_crash(&source, 5)).unwrap();
        assert_eq!(nonliteral.api, "snprintf");
        assert_eq!(nonliteral.function.as_deref(), Some("log_message"));
        assert!(format_is_nonliteral(&nonliteral));
        let literal = call_site(&printf_crash(&source, 4)).unwrap();
        assert!(!format_is_nonliteral(&literal));

        let path = dir.join("finding.json");
        let mut raw = printf_crash(&source, 5);
        reclassify(&mut raw, &nonliteral, false, &path);
        assert_eq!(raw["rule_id"], "BHF-408");
        // The crash keeps its own severity, not the static rule's default.
        assert_eq!(
            raw["severity"],
            finding_rules::by_id("BHF-206")
                .unwrap()
                .default_severity
                .as_str()
        );
        assert_eq!(raw["format_string"]["crash_rule_id"], "BHF-206");
        assert_eq!(raw["format_string"]["call_site"]["line"], 5);
        assert_eq!(raw["actionability"]["cwe"][0], "CWE-134");
        assert!(raw["actionability"]["explanation"]
            .as_str()
            .unwrap()
            .contains("`log_message` passes input-controlled bytes to `snprintf`"));
    }

    #[test]
    fn a_crash_outside_a_printf_call_is_not_a_format_string_bug() {
        let raw = serde_json::json!({
            "exception": { "stack": [
                { "function": "__asan_memcpy" },
                { "function": "parse", "file": "/src/p.c", "line": 3 },
            ] }
        });
        assert_eq!(call_site(&raw), None);
        assert_eq!(api_of("__interceptor_vsnprintf"), Some("vsnprintf"));
        assert_eq!(api_of("__snprintf_chk"), Some("snprintf"));
        assert_eq!(api_of("snprintf_like"), None);
    }

    #[test]
    fn call_arguments_split_at_top_level_commas_only() {
        assert_eq!(
            call_arguments(r#"x = snprintf(b, f(1, 2), "a,b", m);"#, "snprintf"),
            Some(vec!["b", "f(1, 2)", r#""a,b""#, "m"])
        );
        assert_eq!(call_arguments("my_snprintf(a, b, c)", "snprintf"), None);
    }
}
