// SPDX-License-Identifier: Apache-2.0
use super::*;

fn finding(id: &str, key: &str, severity: &str) -> Value {
    json!({"id":id,"severity":severity,"cluster_key_full":key,"rule_id":"BHF-0001",
        "classification":"memory_error","target":{"qualified_name":"parse"}})
}
fn snapshot(run: &str, findings: Vec<Value>) -> Snapshot {
    parse_snapshot(&serde_json::to_vec(&json!({"schema_version":"bhf.report.v2",
        "run":{"id":run,"source_root":"/src"},"counts":{"findings":findings.len()},"findings":findings})).unwrap()).unwrap()
}
fn decision(key: &str, status: ReviewStatus) -> BTreeMap<String, Decision> {
    BTreeMap::from([(key.to_owned(), Decision { issue_key:key.to_owned(), status,
        owner:"reviewer".to_owned(), reason:"ticket 42".to_owned() })])
}
fn one() -> Snapshot { snapshot("first", vec![finding("f1", "stack-a", "high")]) }

#[test]
fn classifies_new_persistent_and_not_observed() {
    let a = snapshot("a", vec![finding("a1","same","high"),finding("a2","old","low")]);
    let b = snapshot("b", vec![finding("b1","same","high"),finding("b2","new","medium")]);
    let report=compare(&a,&b,&BTreeMap::new());
    for state in ["new","persistent","not_observed"] { assert_eq!(report.counts[state],1); }
    assert_eq!(report.counts["review_needed"],2);
    assert!(report.notice.contains("not fixed"));
}
#[test]
fn cluster_matching_does_not_depend_on_run_or_finding_id() {
    let a=one(); let b=snapshot("b",vec![finding("different","stack-a","high")]);
    assert_eq!(compare(&a,&b,&BTreeMap::new()).counts["persistent"],1);
}
#[test]
fn collapses_members_and_keeps_all_ids_sorted() {
    let a=snapshot("a",vec![]);
    let b=snapshot("b",vec![finding("z","stack","low"),finding("a","stack","critical")]);
    let report=compare(&a,&b,&BTreeMap::new());
    assert_eq!(report.issues.len(),1);
    let issue=report.issues[0].current.as_ref().unwrap();
    assert_eq!(issue.finding_ids,vec!["a","z"]); assert_eq!(issue.severity,"critical");
}
#[test]
fn signatures_match_when_full_cluster_unavailable() {
    let mut f=finding("a","","low"); f["signature"]=json!("stable signature");
    let a=snapshot("a",vec![f.clone()]); f["id"]=json!("b");
    let report=compare(&a,&snapshot("b",vec![f]),&BTreeMap::new());
    assert_eq!(report.counts["persistent"],1);
    assert_eq!(report.issues[0].current.as_ref().unwrap().identity_kind,"signature");
}
#[test]
fn fallback_cluster_without_signature_never_matches_local_ids() {
    let mut f=finding("same-id","untrusted-fallback","low"); f["cluster_fallback"]=json!(true);
    let a=snapshot("last",vec![f.clone()]); let b=snapshot("last",vec![f]);
    let report=compare(&a,&b,&BTreeMap::new());
    assert_eq!(report.counts["persistent"],0); assert_eq!(report.counts["new"],1);
    assert!(report.warnings.iter().any(|s| s.contains("intentionally not matched")));
}
#[test]
fn rule_classification_and_target_partition_identity() {
    for field in ["rule_id","classification","target"] {
        let a=one(); let mut f=finding("f2","stack-a","high");
        f[field]=if field=="target" {json!({"qualified_name":"other"})} else {json!("other")};
        let report=compare(&a,&snapshot("b",vec![f]),&BTreeMap::new());
        assert_eq!(report.counts["persistent"],0, "{field}");
    }
}
#[test]
fn tracks_severity_escalation_and_reopens_review() {
    let a=one(); let b=snapshot("b",vec![finding("f2","stack-a","critical")]);
    let key=group(&a,"baseline").into_keys().next().unwrap();
    let report=compare(&a,&b,&decision(&key,ReviewStatus::AcceptedRisk));
    assert_eq!(report.counts["severity_increased"],1); assert!(report.issues[0].review_needed);
    assert_eq!(report.issues[0].review_status,"accepted_risk");
    assert_eq!(report.issues[0].decision.as_ref().unwrap().reason,"ticket 42");
}
#[test]
fn previously_fixed_but_observed_is_reopened_not_suppressed() {
    let a=one(); let key=group(&a,"baseline").into_keys().next().unwrap();
    let report=compare(&a,&a,&decision(&key,ReviewStatus::Fixed));
    assert_eq!(report.counts["reopened"],1); assert_eq!(report.issues.len(),1);
    assert_eq!(report.issues[0].review_status,"reopened"); assert!(report.issues[0].review_needed);
}
#[test]
fn disappearance_never_changes_recorded_review_to_fixed() {
    let a=one(); let key=group(&a,"baseline").into_keys().next().unwrap();
    let report=compare(&a,&snapshot("b",vec![]),&decision(&key,ReviewStatus::Investigating));
    assert_eq!(report.issues[0].state,"not_observed");
    assert_eq!(report.issues[0].review_status,"investigating");
    assert!(!report.issues[0].review_needed);
}
#[test]
fn unchanged_review_is_carried_without_new_review_flag() {
    let a=one(); let key=group(&a,"baseline").into_keys().next().unwrap();
    let report=compare(&a,&a,&decision(&key,ReviewStatus::FalsePositive));
    assert!(!report.issues[0].review_needed); assert_eq!(report.issues[0].review_status,"false_positive");
}
#[test]
fn unknown_severity_change_is_not_claimed_improvement() {
    let a=one(); let key=group(&a,"baseline").into_keys().next().unwrap();
    let b=snapshot("b",vec![finding("f2","stack-a","custom")]);
    let report=compare(&a,&b,&decision(&key,ReviewStatus::AcceptedRisk));
    assert_eq!(report.issues[0].severity_increased,None); assert!(report.issues[0].review_needed);
}
#[test]
fn stale_triage_keys_are_explicit() {
    let a=one(); let key=format!("bhf-issue-v1:{}","a".repeat(64));
    let report=compare(&a,&a,&decision(&key,ReviewStatus::Open));
    assert_eq!(report.unmatched_triage_keys,vec![key]);
}
#[test]
fn ordering_is_independent_of_input_finding_order() {
    let a=one(); let f=vec![finding("b","b","low"),finding("a","a","high")];
    let mut reverse=f.clone(); reverse.reverse();
    assert_eq!(serde_json::to_value(compare(&a,&snapshot("b",f),&BTreeMap::new())).unwrap(),
        serde_json::to_value(compare(&a,&snapshot("b",reverse),&BTreeMap::new())).unwrap());
}
#[test]
fn rejects_bad_schema_counts_duplicate_ids_and_empty_fields() {
    let valid=json!({"schema_version":"bhf.report.v2","run":{"id":"a"},"counts":{"findings":1},"findings":[finding("f","a","high")]});
    let mut cases=vec![json!({}), json!([])];
    let mut x=valid.clone();x["schema_version"]=json!("other");cases.push(x);
    let mut x=valid.clone();x["counts"]["findings"]=json!(2);cases.push(x);
    let mut x=valid.clone();x["findings"][0]["id"]=json!("");cases.push(x);
    let mut x=valid.clone();x["findings"][0]["severity"]=json!("");cases.push(x);
    let mut x=valid.clone();x["run"]["id"]=json!("");cases.push(x);
    let mut x=valid;x["findings"]=json!([finding("f","a","high"),finding("f","b","low")]);x["counts"]["findings"]=json!(2);cases.push(x);
    for x in cases {assert!(parse_snapshot(&serde_json::to_vec(&x).unwrap()).is_err());}
}
#[test]
fn rejects_duplicate_known_json_fields() {
    assert!(parse_snapshot(br#"{"schema_version":"bhf.report.v2","schema_version":"bhf.report.v2","run":{"id":"a"},"counts":{"findings":0},"findings":[]}"#).is_err());
}
#[test]
fn triage_requires_valid_keys_owner_reason_unique_decisions_and_known_fields() {
    let tmp=tempfile::tempdir().unwrap();let path=tmp.path().join("triage.json");
    let key=group(&one(),"baseline").into_keys().next().unwrap();
    let good=serde_json::to_value(decision(&key,ReviewStatus::Open).into_values().next().unwrap()).unwrap();
    let mut cases=vec![json!([good.clone(),good.clone()])];
    for (field,value) in [("issue_key",json!("bad")),("owner",json!(" ")),("reason",json!("")),("status",json!("approved")),("extra",json!(true))] {
        let mut bad=good.clone();bad[field]=value;cases.push(json!([bad]));
    }
    for decisions in cases {
        fs::write(&path,json!({"schema_version":"bhf.triage.v1","decisions":decisions}).to_string()).unwrap();
        assert!(load_triage(Some(&path)).is_err());
    }
    fs::write(&path,json!({"schema_version":"bhf.triage.v1","decisions":[good]}).to_string()).unwrap();
    assert_eq!(load_triage(Some(&path)).unwrap().len(),1);
}
#[test]
fn reports_differing_or_missing_source_roots() {
    let a=one();let mut b=one();b.run.source_root=None;
    assert!(compare(&a,&b,&BTreeMap::new()).warnings.iter().any(|s|s.contains("Source roots")));
}
#[test]
fn html_escapes_untrusted_strings_and_loads_no_scripts() {
    let mut f=finding("<b>id</b>","a","high");f["target"]=json!("<script>alert(1)</script>");
    let report=compare(&snapshot("old",vec![]),&snapshot("<img src=x>",vec![f]),&BTreeMap::new());
    let rendered=html(&report);
    assert!(!rendered.contains("<script>"));assert!(!rendered.contains("<img src=x>"));
    assert!(rendered.contains("&lt;script&gt;"));assert!(rendered.contains("default-src 'none'"));
}
#[test]
fn markdown_escapes_table_delimiters_and_controls() {
    assert_eq!(md("a|b`\n<"),"a&#124;b&#96; &lt;");
}
#[test]
fn writes_three_reports_without_modifying_snapshot() {
    let tmp=tempfile::tempdir().unwrap();let current=tmp.path().join("last.json");
    fs::write(&current,"original").unwrap();let report=compare(&one(),&one(),&BTreeMap::new());
    let paths=write(&report,&current).unwrap();assert_eq!(paths.len(),3);
    assert!(paths.iter().all(|p|p.is_file()));assert_eq!(fs::read_to_string(current).unwrap(),"original");
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(),4);
}
#[test]
fn empty_comparisons_are_valid_and_have_zero_counts() {
    let a=snapshot("a",vec![]);let report=compare(&a,&a,&BTreeMap::new());
    assert!(report.counts.values().all(|n|*n==0));assert!(report.issues.is_empty());
}
#[cfg(unix)]
#[test]
fn rejects_symlink_inputs() {
    let tmp=tempfile::tempdir().unwrap();let file=tmp.path().join("file");let link=tmp.path().join("link");
    fs::write(&file,"{}").unwrap();std::os::unix::fs::symlink(&file,&link).unwrap();
    assert!(load_snapshot(&link).is_err());
}

#[test]
fn aliases_have_canonical_severity_and_order_independent_grouping() {
    let a=snapshot("a",vec![]);
    let f=vec![finding("a","same","INFO"),finding("b","same","informational")];
    let mut reverse=f.clone(); reverse.reverse();
    let first=compare(&a,&snapshot("b",f),&BTreeMap::new());
    let second=compare(&a,&snapshot("b",reverse),&BTreeMap::new());
    assert_eq!(first.issues[0].current.as_ref().unwrap().severity,"info");
    assert_eq!(serde_json::to_value(first).unwrap(),serde_json::to_value(second).unwrap());
}
#[test]
fn local_counter_triage_cannot_reassure_a_different_last_run() {
    let mut f=finding("local-id","","low"); f["cluster_fallback"]=json!(true);
    let a=snapshot("last",vec![f]);
    let key=group(&a,"current").into_keys().next().unwrap();
    let report=compare(&a,&a,&decision(&key,ReviewStatus::AcceptedRisk));
    let new=report.issues.iter().find(|i|i.state=="new").unwrap();
    assert_eq!(new.review_status,"unreviewed"); assert!(new.review_needed);
    assert_eq!(report.unmatched_triage_keys,vec![key]);
}
#[test]
fn open_or_investigating_current_issues_remain_in_work_queue() {
    let a=one();let key=group(&a,"baseline").into_keys().next().unwrap();
    for status in [ReviewStatus::Open,ReviewStatus::Investigating] {
        assert!(compare(&a,&a,&decision(&key,status)).issues[0].review_needed);
    }
}
#[test]
fn markdown_cannot_turn_target_text_into_remote_images() {
    assert_eq!(md("![remote](https://example.invalid/pixel)"),
        "&#33;&#91;remote&#93;(https://example.invalid/pixel)");
}
