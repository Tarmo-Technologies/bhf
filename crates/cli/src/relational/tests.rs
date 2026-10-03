// SPDX-License-Identifier: Apache-2.0
//! Unit tests for the relational driver's pure helpers and its persistence path.
//! The campaign/predicate/replay/minimize logic is covered by the `relational`
//! crate's own tests; here we exercise the CLI-side executor mappers, secret
//! resolution/redaction, coverage reading, and the results-layout writer — using
//! the crate's in-process mock executor for the pure persistence coverage.

use super::*;

use relational::{EffectEvent, EffectKind, FnExecutor, ProfileStatus};
use runtime_collector::{CollectorEvent, EventKind, EventPhase};

const SUBSET_CFG: &str = r#"
schema = "bhf.relational.v1"
[[profiles]]
name = "viewer"
allowlist = ["viewer-helper"]
collector = "runtrace"
[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
"#;

struct Fixed(Vec<u8>);
impl TestcaseBytes for Fixed {
    fn testcase_for(&self, _sha: &str) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

#[test]
fn runtrace_process_exec_maps_to_process_effect() {
    let event = RuntraceEvent::ProcessExec {
        api: "execve".into(),
        program: "administrator-helper".into(),
        taint_offset: None,
    };
    let effect = runtrace_event_to_effect(&event).expect("mapped");
    assert_eq!(effect.kind, EffectKind::ProcessExec);
    assert_eq!(effect.target, "administrator-helper");
    assert_eq!(effect.api, "execve");
}

#[test]
fn runtrace_command_and_net_and_lib_map_but_file_ops_do_not() {
    let cmd = RuntraceEvent::CommandExecuted {
        api: "system".into(),
        command: "sh -c id".into(),
        taint_offset: None,
    };
    assert_eq!(
        runtrace_event_to_effect(&cmd).map(|e| (e.kind, e.target)),
        Some((EffectKind::CommandExec, "sh -c id".to_string()))
    );
    let net = RuntraceEvent::NetworkEgress {
        api: "connect".into(),
        address: "10.0.0.1:443".into(),
        taint_offset: None,
    };
    assert_eq!(
        runtrace_event_to_effect(&net).map(|e| e.kind),
        Some(EffectKind::NetworkEgress)
    );
    // A file-open event is not an effect the relational model tracks.
    let open = RuntraceEvent::FileOpened {
        syscall: "open".into(),
        fd: 3,
        path: "/etc/passwd".into(),
        taint_offset: None,
    };
    assert!(runtrace_event_to_effect(&open).is_none());
}

#[test]
fn collector_event_maps_process_and_shell_and_network() {
    let mut proc = CollectorEvent::new("tc", 0, 0, EventPhase::Event, EventKind::ProcessCreate);
    proc.process.image = Some("administrator-helper".into());
    proc.args = vec!["--role".into(), "admin".into()];
    let effect = collector_event_to_effect(&proc).expect("mapped");
    assert_eq!(effect.kind, EffectKind::ProcessExec);
    assert_eq!(effect.target, "administrator-helper --role admin");

    let mut net = CollectorEvent::new("tc", 0, 1, EventPhase::Event, EventKind::Network);
    net.address = Some("203.0.113.5:80".into());
    assert_eq!(
        collector_event_to_effect(&net).map(|e| (e.kind, e.target)),
        Some((EffectKind::NetworkEgress, "203.0.113.5:80".to_string()))
    );

    // Begin/End phases are session markers, not effects.
    let begin = CollectorEvent::new("tc", 0, 2, EventPhase::Begin, EventKind::ProcessCreate);
    assert!(collector_event_to_effect(&begin).is_none());
    // A file event is not a tracked effect kind.
    let file = CollectorEvent::new("tc", 0, 3, EventPhase::Event, EventKind::FileOpen);
    assert!(collector_event_to_effect(&file).is_none());
}

#[test]
fn collector_events_parses_jsonl_log() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("collector.jsonl");
    let mut ev = CollectorEvent::new("tc", 0, 0, EventPhase::Event, EventKind::ProcessCreate);
    ev.process.image = Some("administrator-helper".into());
    let line = ev.to_jsonl_line();
    std::fs::write(&log, format!("{line}\nnot-json\n")).unwrap();
    let effects = collector_events(&log);
    assert_eq!(effects.len(), 1, "one valid line parses, junk is skipped");
    assert_eq!(effects[0].target, "administrator-helper");
    // A missing log yields no events (not an error).
    assert!(collector_events(&tmp.path().join("absent.jsonl")).is_empty());
}

#[test]
fn oracle_hit_maps_to_finding_semantic_hit() {
    let hit = finding_rules::oracle_sdk::OracleHit {
        oracle_name: "command-exec".into(),
        rule_id: "BHF-431".into(),
        category: "command".into(),
        api: "system".into(),
        message: "tainted command execution".into(),
        evidence: Vec::new(),
    };
    let semantic = oracle_hit_to_semantic(&hit);
    assert_eq!(semantic.rule, "BHF-431");
    assert_eq!(semantic.verdict, SemanticVerdict::Finding);
    assert_eq!(semantic.detail, "tainted command execution");
}

#[test]
fn resolve_secret_reads_env_with_name_transform() {
    let key = "BHF_SECRET_RELATIONAL_UNIT_TOKEN";
    std::env::set_var(key, "s3cr3t");
    // "lab:relational-unit-token" -> BHF_SECRET_RELATIONAL_UNIT_TOKEN
    assert_eq!(
        resolve_secret("lab:relational-unit-token", "lab:"),
        Some("s3cr3t".to_string())
    );
    std::env::remove_var(key);
    assert_eq!(resolve_secret("lab:relational-unit-token", "lab:"), None);
    // An empty value is treated as unresolved.
    std::env::set_var(key, "");
    assert_eq!(resolve_secret("lab:relational-unit-token", "lab:"), None);
    std::env::remove_var(key);
}

#[test]
fn coverage_shm_arms_zeroed_and_reads_back_popcount() {
    let tmp = tempfile::tempdir().unwrap();
    let shm = tmp.path().join("cov.shm");
    arm_cov_shm(&shm).unwrap();
    let zeroed = read_cov_shm(&shm);
    assert_eq!(zeroed.len(), COV_BITS);
    assert_eq!(relational::popcount(&zeroed), 0);
    // Simulate an instrumented harness setting three edges.
    let mut bytes = vec![0u8; COV_BITS];
    bytes[0] = 1;
    bytes[7] = 1;
    bytes[9] = 42;
    std::fs::write(&shm, &bytes).unwrap();
    assert_eq!(relational::popcount(&read_cov_shm(&shm)), 3);
    // A missing shm reads as empty (no coverage collected).
    assert!(read_cov_shm(&tmp.path().join("absent")).is_empty());
}

#[test]
fn build_command_prefers_runner_then_first_arg() {
    let with_runner = Profile {
        name: "r".into(),
        runner: Some("/bin/sh".into()),
        args: vec!["launch.sh".into()],
        env: Default::default(),
        allowlist: Vec::new(),
        collector: CollectorKind::Runtrace,
    };
    assert!(build_command(&with_runner).is_some());
    let no_runner = Profile {
        name: "r".into(),
        runner: None,
        args: vec!["/usr/bin/true".into()],
        env: Default::default(),
        allowlist: Vec::new(),
        collector: CollectorKind::Runtrace,
    };
    assert!(build_command(&no_runner).is_some());
    let nothing = Profile {
        name: "r".into(),
        runner: None,
        args: Vec::new(),
        env: Default::default(),
        allowlist: Vec::new(),
        collector: CollectorKind::Runtrace,
    };
    assert!(build_command(&nothing).is_none());
}

/// Acceptance #9 at the CLI persistence boundary, using the crate's mock
/// executor: a finding whose evidence carries a resolved secret value is written
/// into the results layout with the value scrubbed and the reference id intact.
#[test]
fn persist_scrubs_resolved_secret_and_writes_results_layout() {
    let config = RelationalConfig::parse(SUBSET_CFG).unwrap();
    let mut exec = FnExecutor::new(|p: &Profile, input: &[u8]| {
        let escaping = p.name == "viewer" && input.contains(&0xAA);
        let mut events = vec![EffectEvent::process_exec("execve", "viewer-helper")];
        if escaping {
            events.push(EffectEvent::process_exec("execve", "administrator-helper"));
            events.push(EffectEvent {
                api: "system".into(),
                kind: EffectKind::CommandExec,
                target: "login --token s3cr3t".into(),
            });
        }
        ProfileRun::ready(p.name.clone(), 0).with_events(events)
    });
    let opts = CampaignOptions {
        max_execs: 1,
        max_len: 4,
        seed: 1,
        max_findings: 8,
    };
    let report = run_campaign(&config, &[vec![0xAAu8]], &mut exec, &opts).unwrap();
    assert_eq!(
        report.findings.len(),
        1,
        "exactly one allowlist-escape finding"
    );

    let tmp = tempfile::tempdir().unwrap();
    let mut resolution = SecretResolution::new();
    resolution.insert("lab:viewer-token", "s3cr3t");
    let written =
        persist_findings(tmp.path(), report.findings, &resolution, &Fixed(vec![0xAA])).unwrap();
    assert_eq!(written, 1);

    let findings = tmp.path().join("results/findings");
    let dir = std::fs::read_dir(&findings)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(dir.join("testcase.bin").is_file());
    let text = std::fs::read_to_string(dir.join("finding.json")).unwrap();
    assert!(!text.contains("s3cr3t"), "resolved secret leaked: {text}");
    assert!(text.contains("administrator-helper"));
    assert!(
        text.contains("<secret:lab:viewer-token>"),
        "redaction placeholder with the stable reference id must remain"
    );
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["rule_id"], "BHF-309");
    assert_eq!(value["classification"], "relational_violation");
    assert_eq!(value["finding_kind"], "differential");
    assert_eq!(value["schema_version"], "bhf.finding.v1");
    assert!(value["id"].as_str().unwrap().starts_with("F-REL-"));
}

/// A status observation sanity check: the crate's status mapping drives the
/// response-digest/status seam the executor fills. Kept minimal (the crate owns
/// the deeper coverage) but asserts real behaviour, not a type shape.
#[test]
fn ready_observation_keeps_profile_status() {
    let obs = relational::Observation::ready("viewer", ProfileStatus::Denied);
    assert_eq!(obs.status, ProfileStatus::Denied);
}
