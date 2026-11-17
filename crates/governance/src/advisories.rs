// SPDX-License-Identifier: Apache-2.0

//! The advisory database `bhf sbom --vuln-db` reads, and the importers that
//! build one from public feeds (#223).
//!
//! A database is `{"vulnerabilities": [record, ...]}`. A record names a
//! package (`package.ecosystem` and `package.name`, or `package.purl`, or
//! `package.cpe`) and the versions it affects: `affected_versions` lists exact
//! versions (`"*"` is every version), and `affected_ranges` lists ranges, each
//! an object of optional bounds `start_including`, `start_excluding`,
//! `end_including` and `end_excluding` (an empty object is every version).
//! `bhf pack import-osv` maps OSV records onto that format, and
//! `bhf pack import-nvd` NVD CVE records (#387).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::GovernanceError;

/// The bound keys of an `affected_ranges` entry.
pub const RANGE_BOUNDS: [&str; 4] = [
    "start_including",
    "start_excluding",
    "end_including",
    "end_excluding",
];

/// Compare two versions the way package managers order them: release
/// segments split on `.`, `-`, `_` and `+` compare numerically where both
/// start with digits (`1.10` after `1.9`), then by the letters after the
/// digits (`1.0.2` before `1.0.2a` before `1.0.2u`); a semver pre-release
/// (`1.0.0-rc1`) comes before its release. Build metadata (`+...`) is ignored.
pub fn compare_versions(left: &str, right: &str) -> Ordering {
    let split = |version: &str| -> (Vec<String>, Option<String>) {
        let version = version.trim().trim_start_matches(['v', 'V']);
        let version = version.split('+').next().unwrap_or(version);
        // A `-` before a letter starts a pre-release only when the release
        // part is dotted numbers (`1.2.3-beta`), not a Debian-style revision.
        match version.split_once('-') {
            Some((release, pre))
                if release
                    .split('.')
                    .all(|part| part.chars().all(|c| c.is_ascii_digit()))
                    && pre.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) =>
            {
                (segments(release), Some(pre.to_ascii_lowercase()))
            }
            _ => (segments(version), None),
        }
    };
    let (left_release, left_pre) = split(left);
    let (right_release, right_pre) = split(right);
    let len = left_release.len().max(right_release.len());
    for index in 0..len {
        let ordering = compare_segment(
            left_release.get(index).map_or("0", String::as_str),
            right_release.get(index).map_or("0", String::as_str),
        );
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    match (left_pre, right_pre) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(left), Some(right)) => compare_versions(&left, &right),
    }
}

fn segments(version: &str) -> Vec<String> {
    version
        .split(['.', '-', '_'])
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn compare_segment(left: &str, right: &str) -> Ordering {
    let digits = |part: &str| -> (Option<u128>, String) {
        let end = part
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(part.len());
        (part[..end].parse().ok(), part[end..].to_owned())
    };
    match (digits(left), digits(right)) {
        ((Some(left_number), left_rest), (Some(right_number), right_rest)) => left_number
            .cmp(&right_number)
            .then_with(|| left_rest.cmp(&right_rest)),
        // A number sorts after a word (`1.0.0` after `1.0.beta`).
        ((Some(_), _), (None, _)) => Ordering::Greater,
        ((None, _), (Some(_), _)) => Ordering::Less,
        _ => left.cmp(right),
    }
}

/// Whether `version` lies in an `affected_ranges` entry.
pub fn range_contains(range: &Map<String, Value>, version: &str) -> bool {
    let bound = |key: &str| range.get(key).and_then(Value::as_str);
    bound("start_including").is_none_or(|start| compare_versions(version, start).is_ge())
        && bound("start_excluding").is_none_or(|start| compare_versions(version, start).is_gt())
        && bound("end_including").is_none_or(|end| compare_versions(version, end).is_le())
        && bound("end_excluding").is_none_or(|end| compare_versions(version, end).is_lt())
}

/// Why a record's `affected_ranges` is not an array of range objects whose
/// bounds are nonempty strings, or `None` when it is (or is absent).
pub fn invalid_ranges(ranges: Option<&Value>) -> Option<String> {
    let ranges = match ranges {
        None | Some(Value::Null) => return None,
        Some(Value::Array(ranges)) => ranges,
        Some(_) => return Some("affected_ranges is not an array".to_owned()),
    };
    for range in ranges {
        let Some(range) = range.as_object() else {
            return Some("an affected_ranges entry is not an object".to_owned());
        };
        for (key, value) in range {
            if !RANGE_BOUNDS.contains(&key.as_str()) {
                return Some(format!("affected_ranges has an unknown bound `{key}`"));
            }
            if value.as_str().is_none_or(|text| text.trim().is_empty()) {
                return Some(format!("affected_ranges bound `{key}` is not a version"));
            }
        }
    }
    None
}

/// The CVSS v3 base score of a `CVSS:3.x/...` vector, per the FIRST
/// specification, or `None` for a vector that is not one.
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut metrics: BTreeMap<&str, &str> = BTreeMap::new();
    let mut parts = vector.trim().split('/');
    if !parts.next()?.starts_with("CVSS:3") {
        return None;
    }
    for part in parts {
        let (key, value) = part.split_once(':')?;
        metrics.insert(key, value);
    }
    let changed = match *metrics.get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match *metrics.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *metrics.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*metrics.get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *metrics.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |key: &str| -> Option<f64> {
        match *metrics.get(key)? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(round_up(raw))
}

/// CVSS v3.1's Roundup: the smallest one-decimal number not below `value`.
fn round_up(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) + 1) as f64 / 10.0
    }
}

/// The qualitative rating of a CVSS score.
pub fn severity_of_score(score: f64) -> &'static str {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        s if s > 0.0 => "low",
        _ => "none",
    }
}

/// The records an importer read, and the ones it reported and skipped.
#[derive(Debug, Default)]
pub struct AdvisoryImport {
    /// The feed's format (`osv`, `nvd`).
    pub format: &'static str,
    /// Database records, one per affected package.
    pub records: Vec<Value>,
    /// Source files read.
    pub files: usize,
    /// Feed records read.
    pub feed_records: usize,
    /// `(source, reason)` of each record or file that was skipped as
    /// malformed.
    pub malformed: Vec<(String, String)>,
    /// Affected packages left out because their ecosystem has no bhf
    /// cataloger, by the feed's ecosystem name.
    pub unsupported_ecosystems: BTreeMap<String, usize>,
    /// Affected packages left out because they name no version (a git
    /// commit range only).
    pub without_versions: usize,
}

/// The bhf ecosystem of an OSV ecosystem name (the part before any `:`,
/// as in `Debian:11`), when bhf catalogs it.
pub fn bhf_ecosystem_of_osv(ecosystem: &str) -> Option<&'static str> {
    Some(match ecosystem.split(':').next().unwrap_or(ecosystem) {
        "crates.io" => "cargo",
        "npm" => "npm",
        "PyPI" => "pypi",
        "Go" => "golang",
        "Maven" => "maven",
        "NuGet" => "nuget",
        "RubyGems" => "gem",
        "Packagist" => "composer",
        "ConanCenter" => "conan",
        _ => return None,
    })
}

/// The `.json` files `inputs` name: each file, and every file under each
/// directory, in path order.
fn json_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, GovernanceError> {
    let mut out = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let mut stack = vec![input.clone()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir)? {
                    let path = entry?.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().is_some_and(|ext| ext == "json") {
                        out.push(path);
                    }
                }
            }
        } else if input.is_file() {
            out.push(input.clone());
        } else {
            return Err(GovernanceError::InvalidInput {
                message: format!("{}: no such file or directory", input.display()),
            });
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Read the OSV records in `inputs` (OSV JSON files, one record or an array
/// of records each, or directories of them, as an OSV ecosystem export
/// unzips) into database records.
pub fn import_osv(inputs: &[PathBuf]) -> Result<AdvisoryImport, GovernanceError> {
    let mut import = AdvisoryImport {
        format: "osv",
        ..AdvisoryImport::default()
    };
    for path in json_files(inputs)? {
        import.files += 1;
        let source = path.display().to_string();
        let value: Value = match std::fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
        {
            Ok(value) => value,
            Err(error) => {
                import
                    .malformed
                    .push((source, format!("not JSON: {error}")));
                continue;
            }
        };
        let records = match value {
            Value::Array(records) => records,
            record => vec![record],
        };
        for record in records {
            import.feed_records += 1;
            osv_record(&record, &source, &mut import);
        }
    }
    import.records.sort_by(record_order);
    Ok(import)
}

fn record_order(left: &Value, right: &Value) -> Ordering {
    let key = |record: &Value| {
        (
            record["id"].as_str().unwrap_or_default().to_owned(),
            record["package"].to_string(),
        )
    };
    key(left).cmp(&key(right))
}

/// Map one OSV record onto database records, one per affected package.
fn osv_record(record: &Value, source: &str, import: &mut AdvisoryImport) {
    let Some(id) = record
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
    else {
        import
            .malformed
            .push((source.to_owned(), "an OSV record without an id".to_owned()));
        return;
    };
    let at = format!("{source} ({id})");
    let Some(affected) = record.get("affected").and_then(Value::as_array) else {
        if record.get("withdrawn").is_none() {
            import.malformed.push((at, "no affected array".to_owned()));
        }
        return;
    };
    let severity = osv_severity(record);
    let aliases: Vec<Value> = record
        .get("aliases")
        .and_then(Value::as_array)
        .map(|aliases| {
            aliases
                .iter()
                .filter(|alias| alias.is_string())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let summary = record
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| {
            record
                .get("details")
                .and_then(Value::as_str)
                .and_then(|details| details.lines().next())
        })
        .unwrap_or_default();
    for (index, entry) in affected.iter().enumerate() {
        let package = entry.get("package").unwrap_or(&Value::Null);
        let (Some(ecosystem), Some(name)) = (
            package.get("ecosystem").and_then(Value::as_str),
            package.get("name").and_then(Value::as_str),
        ) else {
            import.malformed.push((
                at.clone(),
                format!("affected[{index}] names no package ecosystem and name"),
            ));
            continue;
        };
        let purl = package.get("purl").and_then(Value::as_str);
        let Some(bhf_ecosystem) = bhf_ecosystem_of_osv(ecosystem) else {
            *import
                .unsupported_ecosystems
                .entry(ecosystem.split(':').next().unwrap_or(ecosystem).to_owned())
                .or_default() += 1;
            continue;
        };
        let versions = match entry.get("versions") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(versions)) if versions.iter().all(Value::is_string) => {
                versions.clone()
            }
            Some(_) => {
                import.malformed.push((
                    at.clone(),
                    format!("affected[{index}].versions is not an array of strings"),
                ));
                continue;
            }
        };
        let ranges = match osv_ranges(entry.get("ranges")) {
            Ok(ranges) => ranges,
            Err(reason) => {
                import
                    .malformed
                    .push((at.clone(), format!("affected[{index}]: {reason}")));
                continue;
            }
        };
        if versions.is_empty() && ranges.is_empty() {
            import.without_versions += 1;
            continue;
        }
        let mut out_package = json!({ "ecosystem": bhf_ecosystem, "name": name });
        let purl = purl.map(str::to_owned).or_else(|| {
            (bhf_ecosystem == "maven")
                .then(|| name.split_once(':'))
                .flatten()
                .map(|(group, artifact)| format!("pkg:maven/{group}/{artifact}"))
        });
        if let Some(purl) = purl {
            out_package["purl"] = Value::String(purl);
        }
        let mut out = json!({
            "id": id,
            "source": "osv",
            "package": out_package,
            "affected_versions": versions,
            "affected_ranges": ranges,
            "severity": severity,
        });
        if !aliases.is_empty() {
            out["aliases"] = Value::Array(aliases.clone());
        }
        if !summary.is_empty() {
            out["summary"] = Value::String(summary.to_owned());
        }
        import.records.push(out);
    }
}

/// An OSV affected entry's `SEMVER` and `ECOSYSTEM` ranges as
/// `affected_ranges` entries: each `introduced` event opens one (`"0"` from
/// the first version), and `fixed` or `limit` closes it before, or
/// `last_affected` at, a version. A `GIT` range names commits, not versions,
/// and is left out.
fn osv_ranges(ranges: Option<&Value>) -> Result<Vec<Value>, String> {
    let ranges = match ranges {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(ranges)) => ranges,
        Some(_) => return Err("ranges is not an array".to_owned()),
    };
    let mut out = Vec::new();
    for range in ranges {
        let kind = range
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kind == "GIT" {
            continue;
        }
        if !matches!(kind, "SEMVER" | "ECOSYSTEM") {
            return Err(format!(
                "range type `{kind}` is not SEMVER, ECOSYSTEM or GIT"
            ));
        }
        let events = range
            .get("events")
            .and_then(Value::as_array)
            .ok_or("a range without events")?;
        let mut open: Option<Map<String, Value>> = None;
        for event in events {
            let event = event.as_object().ok_or("a range event is not an object")?;
            let (key, version) = event
                .iter()
                .next()
                .and_then(|(key, value)| Some((key.as_str(), value.as_str()?)))
                .ok_or("a range event without a version")?;
            match key {
                "introduced" => {
                    if let Some(range) = open.take() {
                        out.push(Value::Object(range));
                    }
                    let mut range = Map::new();
                    if version != "0" {
                        range.insert("start_including".to_owned(), json!(version));
                    }
                    open = Some(range);
                }
                "fixed" | "limit" | "last_affected" => {
                    let mut range = open.take().unwrap_or_default();
                    let bound = if key == "last_affected" {
                        "end_including"
                    } else {
                        "end_excluding"
                    };
                    range.insert(bound.to_owned(), json!(version));
                    out.push(Value::Object(range));
                }
                other => return Err(format!("unknown range event `{other}`")),
            }
        }
        if let Some(range) = open {
            out.push(Value::Object(range));
        }
    }
    Ok(out)
}

/// An OSV record's severity: the GitHub advisory rating it carries in
/// `database_specific.severity` (`MODERATE` is medium), else the rating of
/// its highest CVSS v3 score, else `unknown`.
fn osv_severity(record: &Value) -> String {
    if let Some(rating) = record
        .pointer("/database_specific/severity")
        .and_then(Value::as_str)
    {
        let rating = rating.to_ascii_lowercase();
        return if rating == "moderate" {
            "medium".to_owned()
        } else {
            rating
        };
    }
    record
        .get("severity")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with("CVSS_V3"))
        })
        .filter_map(|entry| cvss3_base_score(entry.get("score")?.as_str()?))
        .max_by(f64::total_cmp)
        .map_or_else(
            || "unknown".to_owned(),
            |score| severity_of_score(score).to_owned(),
        )
}

/// Read the NVD CVE records in `inputs` (NVD CVE JSON 2.0: feed files or
/// API responses, `{"vulnerabilities": [{"cve": ...}, ...]}`, or
/// directories of them) into database records: one per vulnerable CPE
/// match of a CVE's configurations, identified by its CPE and affecting the
/// version its CPE names or the versions its bounds take.
pub fn import_nvd(inputs: &[PathBuf]) -> Result<AdvisoryImport, GovernanceError> {
    let mut import = AdvisoryImport {
        format: "nvd",
        ..AdvisoryImport::default()
    };
    for path in json_files(inputs)? {
        import.files += 1;
        let source = path.display().to_string();
        let value: Value = match std::fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
        {
            Ok(value) => value,
            Err(error) => {
                import
                    .malformed
                    .push((source, format!("not JSON: {error}")));
                continue;
            }
        };
        let Some(items) = value.get("vulnerabilities").and_then(Value::as_array) else {
            import.malformed.push((
                source,
                "no vulnerabilities array: not an NVD CVE JSON 2.0 file".to_owned(),
            ));
            continue;
        };
        for item in items {
            import.feed_records += 1;
            nvd_record(item.get("cve").unwrap_or(item), &source, &mut import);
        }
    }
    import.records.sort_by(record_order);
    Ok(import)
}

/// Map one NVD CVE onto database records.
fn nvd_record(cve: &Value, source: &str, import: &mut AdvisoryImport) {
    let Some(id) = cve
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
    else {
        import
            .malformed
            .push((source.to_owned(), "a CVE record without an id".to_owned()));
        return;
    };
    let at = format!("{source} ({id})");
    if cve.get("vulnStatus").and_then(Value::as_str) == Some("Rejected") {
        return;
    }
    let configurations = match cve.get("configurations") {
        None | Some(Value::Null) => {
            import.without_versions += 1;
            return;
        }
        Some(Value::Array(configurations)) => configurations,
        Some(_) => {
            import
                .malformed
                .push((at, "configurations is not an array".to_owned()));
            return;
        }
    };
    let summary = cve
        .get("descriptions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|description| description.get("lang").and_then(Value::as_str) == Some("en"))
        .and_then(|description| description.get("value").and_then(Value::as_str))
        .unwrap_or_default();
    let severity = nvd_severity(cve);
    let (mut matched, mut malformed) = (0usize, 0usize);
    for (config_index, configuration) in configurations.iter().enumerate() {
        let nodes = configuration
            .get("nodes")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for node in nodes {
            if node.get("negate").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let matches = node
                .get("cpeMatch")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            for cpe_match in matches {
                if cpe_match.get("vulnerable").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                match nvd_cpe_record(id, cpe_match, &severity, summary) {
                    Ok(record) => {
                        matched += 1;
                        import.records.push(record);
                    }
                    Err(reason) => {
                        malformed += 1;
                        import.malformed.push((
                            at.clone(),
                            format!("configurations[{config_index}]: {reason}"),
                        ));
                    }
                }
            }
        }
    }
    if matched == 0 && malformed == 0 {
        import.without_versions += 1;
    }
}

/// The database record of one vulnerable NVD CPE match.
fn nvd_cpe_record(
    id: &str,
    cpe_match: &Value,
    severity: &str,
    summary: &str,
) -> Result<Value, String> {
    let criteria = cpe_match
        .get("criteria")
        .and_then(Value::as_str)
        .ok_or("a CPE match without criteria")?;
    let fields: Vec<&str> = criteria
        .strip_prefix("cpe:2.3:")
        .ok_or_else(|| format!("criteria `{criteria}` is not a CPE 2.3 string"))?
        .split(':')
        .collect();
    if fields.len() < 4 {
        return Err(format!(
            "criteria `{criteria}` names no product and version"
        ));
    }
    let mut range = Map::new();
    for (nvd_key, bound) in [
        ("versionStartIncluding", "start_including"),
        ("versionStartExcluding", "start_excluding"),
        ("versionEndIncluding", "end_including"),
        ("versionEndExcluding", "end_excluding"),
    ] {
        match cpe_match.get(nvd_key) {
            None | Some(Value::Null) => {}
            Some(Value::String(version)) if !version.trim().is_empty() => {
                range.insert(bound.to_owned(), json!(version));
            }
            Some(_) => return Err(format!("{nvd_key} is not a version")),
        }
    }
    // The CPE's own version field: a version, or `*` (any) / `-` (none).
    let version = fields[3];
    let (affected_versions, affected_ranges) = if !range.is_empty() {
        (Vec::new(), vec![Value::Object(range)])
    } else if version == "*" || version == "-" {
        (vec![json!("*")], Vec::new())
    } else {
        (vec![json!(version.replace('\\', ""))], Vec::new())
    };
    let mut record = json!({
        "id": id,
        "source": "nvd",
        "package": { "cpe": criteria },
        "affected_versions": affected_versions,
        "affected_ranges": affected_ranges,
        "severity": severity,
    });
    if !summary.is_empty() {
        record["summary"] = json!(summary);
    }
    Ok(record)
}

/// A CVE's NVD severity: the base severity of its CVSS v4.0, v3.1, v3.0 or
/// v2 metric, the first that has one (the NVD's own primary score first),
/// else `unknown`.
fn nvd_severity(cve: &Value) -> String {
    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ] {
        let Some(metrics) = cve
            .pointer(&format!("/metrics/{key}"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        let primary = metrics
            .iter()
            .find(|metric| metric.get("type").and_then(Value::as_str) == Some("Primary"))
            .or_else(|| metrics.first());
        let severity = primary.and_then(|metric| {
            metric
                .pointer("/cvssData/baseSeverity")
                .or_else(|| metric.get("baseSeverity"))
                .and_then(Value::as_str)
        });
        if let Some(severity) = severity {
            return severity.to_ascii_lowercase();
        }
    }
    "unknown".to_owned()
}

/// Write `import`'s records as an advisory database at `out`, with what was
/// read, and return the summary `bhf pack` prints.
pub fn write_advisory_db(
    import: &AdvisoryImport,
    inputs: &[PathBuf],
    out: &Path,
) -> Result<Value, GovernanceError> {
    let db = json!({
        "schema_version": "bhf.cve_db.v1",
        "generated_by": format!("bhf pack import-{}", import.format),
        "sources": inputs.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "vulnerabilities": import.records,
    });
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, format!("{}\n", serde_json::to_string_pretty(&db)?))?;
    Ok(json!({
        "format": import.format,
        "out": out.display().to_string(),
        "files": import.files,
        "feed_records": import.feed_records,
        "records_written": import.records.len(),
        "malformed": import.malformed.iter().map(|(source, reason)| json!({
            "source": source,
            "reason": reason,
        })).collect::<Vec<_>>(),
        "unsupported_ecosystems": import.unsupported_ecosystems,
        "without_versions": import.without_versions,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_as_package_managers_order_them() {
        let ascending = [
            "0.9",
            "0.10.0",
            "0.10.2",
            "1.0.0-alpha",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.2",
            "1.0.2a",
            "1.0.2u",
            "1.0.10",
            "2",
        ];
        for pair in ascending.windows(2) {
            assert_eq!(
                compare_versions(pair[0], pair[1]),
                Ordering::Less,
                "{pair:?}"
            );
            assert_eq!(
                compare_versions(pair[1], pair[0]),
                Ordering::Greater,
                "{pair:?}"
            );
        }
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("v1.2.3", "1.2.3+build.5"), Ordering::Equal);
    }

    #[test]
    fn a_range_holds_the_versions_between_its_bounds() {
        let range = |value: Value| value.as_object().unwrap().clone();
        let fixed = range(json!({"start_including": "0.10.0", "end_excluding": "0.10.38"}));
        assert!(range_contains(&fixed, "0.10.0"));
        assert!(range_contains(&fixed, "0.10.37"));
        assert!(!range_contains(&fixed, "0.10.38"));
        assert!(!range_contains(&fixed, "0.9.9"));
        let last = range(json!({"start_excluding": "1.0", "end_including": "1.2"}));
        assert!(!range_contains(&last, "1.0"));
        assert!(range_contains(&last, "1.2"));
        assert!(range_contains(&range(json!({})), "42"));
    }

    #[test]
    fn cvss3_vectors_score_as_the_specification_does() {
        let score = |vector: &str| cvss3_base_score(vector).unwrap();
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 7.5);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
        assert_eq!(score("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"), 1.8);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
        assert_eq!(cvss3_base_score("CVSS:2.0/AV:N"), None);
        assert_eq!(cvss3_base_score("CVSS:3.1/AV:X/AC:L"), None);
        assert_eq!(severity_of_score(9.8), "critical");
        assert_eq!(severity_of_score(6.1), "medium");
    }

    #[test]
    fn an_nvd_cpe_match_takes_its_bounds_or_its_cpe_version() {
        let ranged = nvd_cpe_record(
            "CVE-2026-1",
            &json!({"vulnerable": true,
                    "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "1.0.2", "versionEndExcluding": "1.0.2u"}),
            "high",
            "",
        )
        .unwrap();
        assert_eq!(
            ranged["package"]["cpe"],
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
        );
        assert_eq!(
            ranged["affected_ranges"],
            json!([{"start_including": "1.0.2", "end_excluding": "1.0.2u"}])
        );
        let pinned = nvd_cpe_record(
            "CVE-2026-2",
            &json!({"vulnerable": true, "criteria": "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"}),
            "medium",
            "",
        )
        .unwrap();
        assert_eq!(pinned["affected_versions"], json!(["1.2.11"]));
        let any = nvd_cpe_record(
            "CVE-2026-3",
            &json!({"vulnerable": true, "criteria": "cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"}),
            "low",
            "",
        )
        .unwrap();
        assert_eq!(any["affected_versions"], json!(["*"]));
        assert!(nvd_cpe_record("X", &json!({"criteria": "openssl"}), "low", "").is_err());
        assert!(nvd_cpe_record(
            "X",
            &json!({"criteria": "cpe:2.3:a:o:o:*:*:*:*:*:*:*:*", "versionEndExcluding": 3}),
            "low",
            ""
        )
        .is_err());
    }

    #[test]
    fn osv_events_become_ranges() {
        let ranges = osv_ranges(Some(&json!([
            {"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "0.10.38"},
                {"introduced": "1.0.0"}, {"last_affected": "1.0.4"},
                {"introduced": "2.0.0"}
            ]},
            {"type": "GIT", "events": [{"introduced": "abc123"}]}
        ])))
        .unwrap();
        assert_eq!(
            ranges,
            [
                json!({"end_excluding": "0.10.38"}),
                json!({"start_including": "1.0.0", "end_including": "1.0.4"}),
                json!({"start_including": "2.0.0"}),
            ]
        );
        assert!(osv_ranges(Some(
            &json!([{"type": "SEMVER", "events": [{"broke": "1"}]}])
        ))
        .is_err());
        assert!(osv_ranges(Some(&json!([{"type": "SEMVER"}]))).is_err());
    }
}
