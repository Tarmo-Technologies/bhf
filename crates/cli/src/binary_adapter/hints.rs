// SPDX-License-Identifier: Apache-2.0

//! What `bhf binary fuzz` and `bhf binary scan` take from a binary adapter's
//! report (`--adapter-report`, #267): the strings the code uses, as
//! dictionary tokens, and the binary's own functions ranked as fuzz entry
//! points, the first of which is the candidate persistent address.

use super::{ADAPTER_SCHEMA_VERSION, MAX_OUTPUT_BYTES};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

/// The most dictionary tokens taken from a report.
const MAX_TOKENS: usize = 256;
/// The longest token, in bytes; longer strings are messages, not keywords.
const MAX_TOKEN_BYTES: usize = 64;
/// How many ranked functions a run's output names.
pub(crate) const RANKING_SHOWN: usize = 10;

/// Sections whose strings are the toolchain's, not the program's.
fn toolchain_section(section: &str) -> bool {
    matches!(
        section,
        ".interp" | ".comment" | ".eh_frame" | ".eh_frame_hdr"
    ) || section.starts_with(".note")
        || section.starts_with(".gnu")
}

/// Functions the C runtime and the linker add to every binary.
const RUNTIME_FUNCTIONS: &[&str] = &[
    "_init",
    "_fini",
    "_start",
    "entry0",
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
    "__libc_csu_init",
    "__libc_csu_fini",
];

/// Imports through which a function handles its input: parsing,
/// comparing, copying and reading. A call to one is a reason to fuzz it.
const INPUT_IMPORTS: &[&str] = &[
    "memcmp",
    "strcmp",
    "strncmp",
    "strcasecmp",
    "strncasecmp",
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "sprintf",
    "snprintf",
    "sscanf",
    "scanf",
    "fscanf",
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
    "atoi",
    "atol",
    "strtok",
    "strchr",
    "strrchr",
    "strstr",
    "memchr",
    "read",
    "recv",
    "recvfrom",
    "fread",
    "fgets",
    "gets",
    "getline",
];

/// A function ranked as a fuzz entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RankedFunction {
    pub name: String,
    pub address: String,
    pub score: u32,
    /// Why it ranks: `calls strncmp`, `references "LEGACY/1.0"`, ...
    pub reasons: Vec<String>,
}

/// The dictionary tokens and the function ranking a report gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterHints {
    /// The adapter that wrote the report: `rizin`, `ghidra`, `angr`, `mock`.
    pub adapter: String,
    /// The strings the code references first, then the binary's other data
    /// strings; at most [`MAX_TOKENS`].
    pub tokens: Vec<Vec<u8>>,
    /// The binary's own functions, best first.
    pub ranking: Vec<RankedFunction>,
}

impl AdapterHints {
    /// The hints a run's output records: the report, the token count, the
    /// top of the ranking and the candidate persistent address.
    pub(crate) fn provenance(&self, report: &Path) -> Value {
        let ranked: Vec<Value> = self
            .ranking
            .iter()
            .take(RANKING_SHOWN)
            .map(|function| {
                json!({
                    "name": function.name,
                    "address": function.address,
                    "score": function.score,
                    "reasons": function.reasons
                })
            })
            .collect();
        json!({
            "path": report,
            "adapter": self.adapter,
            "dictionary_tokens": self.tokens.len(),
            "ranking": ranked,
            "persistent_candidate": self.ranking.first().map(|function| json!({
                "name": function.name,
                "address": function.address
            }))
        })
    }
}

/// Read an adapter report and derive its hints. A report that is not an
/// `ok` `bhf.binary.adapter.v1` one is refused: an empty or failed analysis
/// would seed nothing while the run said it used one.
pub(crate) fn load(path: &Path) -> Result<AdapterHints, String> {
    let size = std::fs::metadata(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?
        .len();
    if size > MAX_OUTPUT_BYTES as u64 {
        return Err(format!("{} is {size} bytes", path.display()));
    }
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let report: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if report["schema_version"] != ADAPTER_SCHEMA_VERSION {
        return Err(format!(
            "{} is not a {ADAPTER_SCHEMA_VERSION} report",
            path.display()
        ));
    }
    if report["status"] != "ok" {
        return Err(format!(
            "{}: the adapter's analysis is {}, not ok",
            path.display(),
            report["status"]
        ));
    }
    Ok(hints(&report))
}

fn array<'a>(report: &'a Value, key: &str) -> &'a [Value] {
    report[key]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn address(value: &Value, key: &str) -> Option<u64> {
    super::int_at(value, key)
}

/// The hints of a loaded `ok` report.
fn hints(report: &Value) -> AdapterHints {
    let strings = array(report, "strings");
    let xrefs = array(report, "xrefs");
    let functions = array(report, "functions");

    // Each string's value by address, and which code references it.
    let string_at: HashMap<u64, &str> = strings
        .iter()
        .filter_map(|string| Some((address(string, "address")?, string["value"].as_str()?)))
        .collect();
    let referenced: HashSet<u64> = xrefs
        .iter()
        .filter_map(|xref| address(xref, "to"))
        .filter(|to| string_at.contains_key(to))
        .collect();

    let mut tokens = Vec::new();
    let mut seen = BTreeSet::new();
    for pass_referenced in [true, false] {
        for string in strings {
            let (Some(at), Some(value)) = (address(string, "address"), string["value"].as_str())
            else {
                continue;
            };
            if referenced.contains(&at) != pass_referenced
                || string["section"].as_str().is_some_and(toolchain_section)
                || !(2..=MAX_TOKEN_BYTES).contains(&value.len())
                || value.chars().any(|c| c.is_control() && c != '\t')
            {
                continue;
            }
            if tokens.len() < MAX_TOKENS && seen.insert(value.as_bytes().to_vec()) {
                tokens.push(value.as_bytes().to_vec());
            }
        }
    }

    // The xrefs and calls out of each function, by its address range.
    let mut own: Vec<(u64, u64, &str)> = functions
        .iter()
        .filter(|function| function["imported"] != true)
        .filter_map(|function| {
            let name = function["name"].as_str()?;
            let start = address(function, "address")?;
            let size = address(function, "size").unwrap_or(1).max(1);
            Some((start, start.saturating_add(size), name))
        })
        .collect();
    own.sort();
    let containing = |at: u64| -> Option<&str> {
        let index = own
            .partition_point(|(start, _, _)| *start <= at)
            .checked_sub(1)?;
        let (_, end, name) = own[index];
        (at < end).then_some(name)
    };
    let mut reasons: HashMap<&str, (u32, Vec<String>)> = HashMap::new();
    for xref in xrefs {
        let (Some(from), Some(to)) = (address(xref, "from"), address(xref, "to")) else {
            continue;
        };
        if let (Some(function), Some(value)) = (containing(from), string_at.get(&to)) {
            let entry = reasons.entry(function).or_default();
            let reason = format!("references {value:?}");
            if !entry.1.contains(&reason) {
                entry.0 += 2;
                entry.1.push(reason);
            }
        }
    }
    let own_names: HashSet<&str> = own.iter().map(|(_, _, name)| *name).collect();
    for edge in array(report, "call_graph") {
        let (Some(caller), Some(callee)) = (edge["caller"].as_str(), edge["callee"].as_str())
        else {
            continue;
        };
        if !own_names.contains(caller) {
            continue;
        }
        let entry = reasons.entry(caller).or_default();
        if INPUT_IMPORTS.contains(&callee) {
            entry.0 += 3;
            entry.1.push(format!("calls {callee}"));
        } else if own_names.contains(callee) {
            entry.0 += 1;
            entry.1.push(format!("calls {callee}"));
        }
    }

    let mut ranking: Vec<RankedFunction> = own
        .iter()
        .filter(|(_, _, name)| !RUNTIME_FUNCTIONS.contains(name))
        .filter_map(|(start, _, name)| {
            let (score, reasons) = reasons.get(name)?.clone();
            (score > 0).then(|| RankedFunction {
                name: (*name).to_owned(),
                address: super::hex(*start),
                score,
                reasons,
            })
        })
        .collect();
    ranking.sort_by(|a, b| b.score.cmp(&a.score).then(a.address.cmp(&b.address)));

    AdapterHints {
        adapter: report["adapter"]["kind"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned(),
        tokens,
        ranking,
    }
}

/// `tokens` as an AFL++ dictionary file: one `"..."` entry a line, with `\`,
/// `"` and every byte outside printable ASCII escaped as `\xNN`.
pub(crate) fn afl_dictionary(tokens: &[Vec<u8>]) -> String {
    let mut text = String::new();
    for (index, token) in tokens.iter().enumerate() {
        text.push_str(&format!("adapter_{index}=\""));
        for &byte in token {
            match byte {
                b'"' | b'\\' => text.push_str(&format!("\\x{byte:02x}")),
                0x20..=0x7e => text.push(byte as char),
                _ => text.push_str(&format!("\\x{byte:02x}")),
            }
        }
        text.push_str("\"\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report `bhf binary adapter --adapter rizin` wrote for
    /// `tests/fixtures/binary_adapter/legacy.c`.
    const RECORDED: &str =
        include_str!("../../../../tests/fixtures/binary_adapter/legacy-rizin-report.json");

    #[test]
    fn a_recorded_report_gives_the_strings_the_code_uses_and_ranks_the_parser_first() {
        let hints = hints(&serde_json::from_str(RECORDED).unwrap());
        assert_eq!(hints.adapter, "rizin");
        assert_eq!(
            hints.tokens,
            [b"LEGACY/1.0".to_vec(), b"usage: legacy".to_vec()],
            "the referenced strings, without the .interp path"
        );
        let names: Vec<&str> = hints.ranking.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["parse_header", "handle", "main"]);
        let parser = &hints.ranking[0];
        assert_eq!(parser.address, "0x1169");
        assert!(
            parser.reasons.contains(&"calls strncmp".to_owned()),
            "{parser:?}"
        );
        assert!(
            parser
                .reasons
                .contains(&"references \"LEGACY/1.0\"".to_owned()),
            "{parser:?}"
        );
        let provenance = hints.provenance(Path::new("report.json"));
        assert_eq!(provenance["dictionary_tokens"], 2);
        assert_eq!(provenance["persistent_candidate"]["name"], "parse_header");
        assert_eq!(provenance["persistent_candidate"]["address"], "0x1169");
    }

    #[test]
    fn only_an_ok_adapter_report_is_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let mut report: Value = serde_json::from_str(RECORDED).unwrap();
        report["status"] = json!("error");
        std::fs::write(&path, report.to_string()).unwrap();
        assert!(load(&path).unwrap_err().contains("not ok"));
        std::fs::write(&path, r#"{"schema_version": "other"}"#).unwrap();
        assert!(load(&path).unwrap_err().contains("bhf.binary.adapter.v1"));
        std::fs::write(&path, RECORDED).unwrap();
        assert_eq!(load(&path).unwrap().tokens.len(), 2);
    }

    #[test]
    fn afl_dictionary_entries_escape_quotes_and_unprintable_bytes() {
        let text = afl_dictionary(&[b"LEGACY/1.0".to_vec(), b"a\"b\\\x01".to_vec()]);
        assert_eq!(
            text,
            "adapter_0=\"LEGACY/1.0\"\nadapter_1=\"a\\x22b\\x5c\\x01\"\n"
        );
    }
}
