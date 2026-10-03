// SPDX-License-Identifier: Apache-2.0
//! `results/findings.sarif`: ONE run (GitHub code scanning rejects several
//! runs with the same tool+category in one file). Fuzz/runtime/binary/
//! differential results come from the `report` emitter, static results from
//! `static/static-report.sarif`; SCA results are excluded (CycloneDX/OpenVEX
//! in `sbom/` is their channel).

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Keyed by both finding id and `fingerprint.primary`, so a fuzz result
/// (indexed by `bhfFindingId`) and a static result (indexed by
/// `bhfStaticFingerprint`) can share one lookup: finding id or fingerprint ->
/// (unified severity, fingerprint.primary, finding id).
pub type SeverityIndex = HashMap<String, (String, String, String)>;

/// `folded`: static fingerprints whose static-scan result was folded into an
/// auto static finding (already present in `fuzz`), so they are skipped here.
pub fn merge(
    mut fuzz: Value,
    static_sarif: Option<&Value>,
    index: &SeverityIndex,
    folded: &HashSet<String>,
) -> Value {
    let Some(run) = fuzz.pointer_mut("/runs/0") else {
        return fuzz;
    };
    for result in run["results"].as_array_mut().into_iter().flatten() {
        let Some(id) = result
            .pointer("/properties/bhfFindingId")
            .and_then(Value::as_str)
        else {
            continue;
        };
        if let Some((severity, primary, _)) = index.get(id).cloned() {
            result["level"] = json!(level_for(&severity));
            result["partialFingerprints"]["bhfPrimary"] = json!(primary);
        }
    }
    run["properties"]["bhfFindingsSchemaVersion"] = json!(crate::model::FINDINGS_SCHEMA_VERSION);

    let Some(static_run) = static_sarif.and_then(|s| s.pointer("/runs/0")) else {
        return fuzz;
    };
    let base_root = run.pointer("/originalUriBaseIds/SRCROOT/uri").cloned();
    let static_root = static_run
        .pointer("/originalUriBaseIds/SRCROOT/uri")
        .cloned();
    let rebase = matches!((&base_root, &static_root), (Some(a), Some(b)) if a != b);
    if base_root.is_none() {
        if let Some(entry) = static_run.pointer("/originalUriBaseIds/SRCROOT") {
            run["originalUriBaseIds"]["SRCROOT"] = entry.clone();
        }
    }
    if rebase {
        run["originalUriBaseIds"]["STATICROOT"] =
            static_run["originalUriBaseIds"]["SRCROOT"].clone();
    }

    let mut known: HashSet<String> = run["tool"]["driver"]["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["id"].as_str().map(str::to_owned))
        .collect();
    for rule in static_run
        .pointer("/tool/driver/rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(id) = rule["id"].as_str() {
            if known.insert(id.to_owned()) {
                push(&mut run["tool"]["driver"]["rules"], rule.clone());
            }
        }
    }
    for raw in static_run
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !raw.is_object() {
            continue;
        }
        let fingerprint = raw
            .pointer("/partialFingerprints/bhfStaticFingerprint")
            .and_then(Value::as_str);
        if fingerprint.is_some_and(|fp| folded.contains(fp)) {
            continue;
        }
        let mut result = raw.clone();
        if let Some(obj) = result.as_object_mut() {
            obj.remove("ruleIndex"); // indices are per source run
        }
        if let Some(fp) = fingerprint {
            let primary = match index.get(fp) {
                Some((severity, primary, id)) => {
                    result["level"] = json!(level_for(severity));
                    // static-scan's own SARIF has no finding id; this links
                    // the result to its findings.json entry.
                    if !result["properties"].is_object() {
                        result["properties"] = json!({});
                    }
                    result["properties"]["bhfFindingId"] = json!(id);
                    primary.clone()
                }
                None => fp.to_owned(),
            };
            result["partialFingerprints"]["bhfPrimary"] = json!(primary);
        }
        if rebase {
            rebase_uri_base_ids(&mut result);
        }
        push(&mut run["results"], result);
    }
    fuzz
}

fn push(target: &mut Value, item: Value) {
    if !target.is_array() {
        *target = json!([]);
    }
    target.as_array_mut().expect("array").push(item);
}

fn rebase_uri_base_ids(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.get("uriBaseId").and_then(Value::as_str) == Some("SRCROOT") {
                map.insert("uriBaseId".to_owned(), json!("STATICROOT"));
            }
            map.values_mut().for_each(rebase_uri_base_ids);
        }
        Value::Array(items) => items.iter_mut().for_each(rebase_uri_base_ids),
        _ => {}
    }
}

/// The one severity->SARIF-level mapping, shared via `severity::sarif_level`;
/// an unparseable severity string falls back to the least alarming level.
fn level_for(severity: &str) -> &'static str {
    crate::severity::parse(severity)
        .map(crate::severity::sarif_level)
        .unwrap_or("note")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fuzz_run() -> Value {
        json!({"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "BHF", "rules": [{"id": "BHF-201"}]}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/demo/"}},
            "results": [{"ruleId": "BHF-201", "level": "warning", "message": {"text": "m"},
                         "locations": [], "partialFingerprints": {"bhfIssueKey": "k"},
                         "properties": {"bhfFindingId": "F-0000-1a2b3c4d"}}],
            "properties": {}
        }]})
    }

    fn static_run(root: &str) -> Value {
        json!({"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "BHF", "rules": [{"id": "BHF-201"}, {"id": "BHF-S-120"}]}},
            "originalUriBaseIds": {"SRCROOT": {"uri": root}},
            "results": [{"ruleId": "BHF-S-120", "level": "error", "message": {"text": "s"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "weak.c", "uriBaseId": "SRCROOT"}}}],
                         "partialFingerprints": {"bhfStaticFingerprint": "fp"}}],
            "properties": {"bhfStaticSchemaVersion": "bhf.static.v1"}
        }]})
    }

    #[test]
    fn merges_into_one_run_with_unified_levels() {
        let severities = [(
            "F-0000-1a2b3c4d".to_owned(),
            (
                "high".to_owned(),
                "c0ffee".to_owned(),
                "F-0000-1a2b3c4d".to_owned(),
            ),
        )]
        .into_iter()
        .collect();
        let merged = merge(
            fuzz_run(),
            Some(&static_run("file:///src/demo/")),
            &severities,
            &HashSet::new(),
        );
        let runs = merged["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        let rule_ids: Vec<_> = run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(rule_ids, ["BHF-201", "BHF-S-120"]);
        assert_eq!(run["results"].as_array().unwrap().len(), 2);
        assert_eq!(
            run["results"][0]["level"], "error",
            "fuzz level from unified severity"
        );
        assert_eq!(
            run["results"][0]["partialFingerprints"]["bhfPrimary"],
            "c0ffee"
        );
        assert_eq!(run["results"][1]["partialFingerprints"]["bhfPrimary"], "fp");
        assert_eq!(
            run["properties"]["bhfFindingsSchemaVersion"],
            "bhf.findings.v1"
        );
        assert!(run["originalUriBaseIds"].get("STATICROOT").is_none());
    }

    #[test]
    fn rebases_static_results_when_roots_differ() {
        let merged = merge(
            fuzz_run(),
            Some(&static_run("file:///elsewhere/")),
            &Default::default(),
            &HashSet::new(),
        );
        let run = &merged["runs"][0];
        assert_eq!(
            run["originalUriBaseIds"]["STATICROOT"]["uri"],
            "file:///elsewhere/"
        );
        assert_eq!(
            run["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"],
            "STATICROOT"
        );
    }

    #[test]
    fn no_static_run_is_identity_plus_properties() {
        let merged = merge(fuzz_run(), None, &Default::default(), &HashSet::new());
        assert_eq!(merged["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn folded_static_results_are_skipped() {
        let folded: HashSet<String> = ["fp".to_owned()].into_iter().collect();
        let merged = merge(
            fuzz_run(),
            Some(&static_run("file:///src/demo/")),
            &Default::default(),
            &folded,
        );
        assert_eq!(merged["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn static_result_severity_from_index_sets_sarif_level() {
        let severities: SeverityIndex = [(
            "fp".to_owned(),
            (
                "low".to_owned(),
                "primaryfp".to_owned(),
                "S-0001".to_owned(),
            ),
        )]
        .into_iter()
        .collect();
        let merged = merge(
            fuzz_run(),
            Some(&static_run("file:///src/demo/")),
            &severities,
            &HashSet::new(),
        );
        assert_eq!(merged["runs"][0]["results"][1]["level"], "note");
        assert_eq!(
            merged["runs"][0]["results"][1]["partialFingerprints"]["bhfPrimary"],
            "primaryfp"
        );
    }

    #[test]
    fn static_results_carry_their_finding_id() {
        let severities: SeverityIndex = [(
            "fp".to_owned(),
            (
                "high".to_owned(),
                "primaryfp".to_owned(),
                "S-0001".to_owned(),
            ),
        )]
        .into_iter()
        .collect();
        // static_run's result has no `properties`: it is created.
        let merged = merge(
            fuzz_run(),
            Some(&static_run("file:///src/demo/")),
            &severities,
            &HashSet::new(),
        );
        let result = &merged["runs"][0]["results"][1];
        assert_eq!(result["properties"]["bhfFindingId"], "S-0001");

        // A non-object `properties` is replaced, never indexed into.
        let mut hostile = static_run("file:///src/demo/");
        hostile["runs"][0]["results"][0]["properties"] = json!("nope");
        let merged = merge(fuzz_run(), Some(&hostile), &severities, &HashSet::new());
        assert_eq!(
            merged["runs"][0]["results"][1]["properties"]["bhfFindingId"],
            "S-0001"
        );

        // Kept alongside existing properties; unknown fingerprints get no id.
        let mut with_props = static_run("file:///src/demo/");
        with_props["runs"][0]["results"][0]["properties"] = json!({"findingKind": "static"});
        let merged = merge(fuzz_run(), Some(&with_props), &severities, &HashSet::new());
        let props = &merged["runs"][0]["results"][1]["properties"];
        assert_eq!(props["findingKind"], "static");
        assert_eq!(props["bhfFindingId"], "S-0001");
        let merged = merge(
            fuzz_run(),
            Some(&static_run("file:///src/demo/")),
            &Default::default(),
            &HashSet::new(),
        );
        assert!(merged["runs"][0]["results"][1]
            .pointer("/properties/bhfFindingId")
            .is_none());
    }

    #[test]
    fn malformed_fuzz_input_without_runs_returns_input_unchanged() {
        let fuzz = json!({"not": "sarif"});
        let merged = merge(fuzz.clone(), None, &Default::default(), &HashSet::new());
        assert_eq!(merged, fuzz);
    }

    #[test]
    fn malformed_static_results_are_skipped() {
        let static_sarif = json!({"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "BHF", "rules": []}},
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/demo/"}},
            "results": ["not-an-object", 42, null],
            "properties": {}
        }]});
        let merged = merge(
            fuzz_run(),
            Some(&static_sarif),
            &Default::default(),
            &HashSet::new(),
        );
        assert_eq!(merged["runs"][0]["results"].as_array().unwrap().len(), 1);
    }
}
