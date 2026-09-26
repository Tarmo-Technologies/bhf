// SPDX-License-Identifier: Apache-2.0
//! Exercise the shipped command with actual BHF report generation, not a mock.
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn cli(findings: &Path, out: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("report").arg("--findings").arg(findings).arg("--out").arg(out)
        .args(args).output().expect("run native bhf report")
}
fn succeeds(output: &Output) {
    assert!(output.status.success(), "status={}\nstdout={}\nstderr={}",
        output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
fn raw(findings: &Path, id: &str, signature: &str, severity: &str) {
    let dir=findings.join(id); fs::create_dir_all(&dir).unwrap();
    let finding=json!({"id":id,"severity":severity,"signature":signature,
        "classification":"fixture_report","target":{"qualified_name":"fixture::decode","language":"c"},
        "exception":{"name":"FixtureError","message":"test-only report record"},
        "input":{"hex":"00"}});
    fs::write(dir.join("finding.json"),serde_json::to_vec(&finding).unwrap()).unwrap();
}
fn report_json(out: &Path) -> PathBuf {
    let files:Vec<_>=fs::read_dir(out).unwrap().map(|e|e.unwrap().path())
        .filter(|p|p.extension().is_some_and(|s|s=="json")
            && !p.file_name().unwrap().to_string_lossy().contains(".comparison.")).collect();
    assert_eq!(files.len(),1,"expected one native report JSON: {files:?}");files[0].clone()
}
fn read(path: &Path) -> Value { serde_json::from_slice(&fs::read(path).unwrap()).unwrap() }
fn comparison(out: &Path) -> Value { read(&report_json(out).with_extension("comparison.json")) }
fn baseline(root: &Path) -> (PathBuf, PathBuf) {
    let findings=root.join("findings");fs::create_dir_all(&findings).unwrap();
    raw(&findings,"before","stable-fixture-signature","high");
    let out=root.join("baseline-report");succeeds(&cli(&findings,&out,&[]));
    (findings,report_json(&out))
}
fn triage(path:&Path,key:&str,status:&str) {
    fs::write(path,json!({"schema_version":"bhf.triage.v1","decisions":[{
        "issue_key":key,"status":status,"owner":"review-team","reason":"review ticket 42"
    }]}).to_string()).unwrap();
}

#[test]
fn command_help_exposes_comparison_without_changing_plain_reports() {
    let result=Command::new(env!("CARGO_BIN_EXE_bhf")).args(["report","--help"]).output().unwrap();
    succeeds(&result);let help=String::from_utf8_lossy(&result.stdout);
    assert!(help.contains("--baseline"));assert!(help.contains("--triage"));
    let temp=tempfile::tempdir().unwrap();let (_,path)=baseline(temp.path());
    assert_eq!(read(&path)["schema_version"],"bhf.report.v2");
    assert!(!path.with_extension("comparison.json").exists());
}
#[test]
fn compares_generated_reports_and_emits_all_three_views() {
    let temp=tempfile::tempdir().unwrap();let (findings,old)=baseline(temp.path());
    fs::rename(findings.join("before"),findings.join("renamed-directory")).unwrap();
    raw(&findings,"additional","different-fixture-signature","low");
    let out=temp.path().join("current-report");
    succeeds(&cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str()]));
    let report=comparison(&out);assert_eq!(report["counts"]["persistent"],1);
    assert_eq!(report["counts"]["new"],1);assert_eq!(report["counts"]["not_observed"],0);
    for ext in ["comparison.json","comparison.md","comparison.html"] {
        assert!(report_json(&out).with_extension(ext).is_file());
    }
    assert_eq!(read(&report_json(&out))["counts"]["findings"],2);
}
#[test]
fn accepted_risk_is_carried_and_never_removes_underlying_findings() {
    let temp=tempfile::tempdir().unwrap();let (findings,old)=baseline(temp.path());
    let out=temp.path().join("current-report");
    succeeds(&cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str()]));
    let report=comparison(&out);let key=report["issues"][0]["issue_key"].as_str().unwrap();
    let review=temp.path().join("triage.json");triage(&review,key,"accepted_risk");
    succeeds(&cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str(),"--triage".as_ref(),review.as_os_str()]));
    let report=comparison(&out);assert_eq!(report["issues"][0]["review_status"],"accepted_risk");
    assert_eq!(report["issues"][0]["decision"]["owner"],"review-team");
    assert_eq!(report["counts"]["review_needed"],0);
    assert_eq!(read(&report_json(&out))["counts"]["findings"],1);
}
#[test]
fn recurrence_of_operator_fixed_issue_requires_review() {
    let temp=tempfile::tempdir().unwrap();let (findings,old)=baseline(temp.path());
    let out=temp.path().join("current-report");
    succeeds(&cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str()]));
    let report=comparison(&out);let key=report["issues"][0]["issue_key"].as_str().unwrap();
    let review=temp.path().join("triage.json");triage(&review,key,"fixed");
    succeeds(&cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str(),"--triage".as_ref(),review.as_os_str()]));
    let report=comparison(&out);assert_eq!(report["counts"]["reopened"],1);
    assert_eq!(report["issues"][0]["review_status"],"reopened");
    assert_eq!(report["issues"][0]["decision"]["status"],"fixed");
}
#[test]
fn disappeared_finding_is_not_observed_not_automatically_fixed() {
    let temp=tempfile::tempdir().unwrap();let (findings,old)=baseline(temp.path());
    fs::remove_dir_all(findings.join("before")).unwrap();
    let out=temp.path().join("current-report");
    succeeds(&cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str()]));
    let report=comparison(&out);assert_eq!(report["counts"]["not_observed"],1);
    assert_eq!(report["issues"][0]["state"],"not_observed");
    assert_eq!(report["issues"][0]["review_status"],"unreviewed");
    assert!(report["notice"].as_str().unwrap().contains("not fixed"));
}
#[test]
fn invalid_baseline_fails_before_writing_current_reports() {
    let temp=tempfile::tempdir().unwrap();let (findings,_)=baseline(temp.path());
    let bad=temp.path().join("bad.json");fs::write(&bad,"{}").unwrap();
    let out=temp.path().join("must-not-exist");
    assert!(!cli(&findings,&out,&["--baseline".as_ref(),bad.as_os_str()]).status.success());
    assert!(!out.exists());
}
#[test]
fn invalid_triage_fails_before_writing_current_reports() {
    let temp=tempfile::tempdir().unwrap();let (findings,old)=baseline(temp.path());
    let bad=temp.path().join("bad.json");fs::write(&bad,"{}").unwrap();
    let out=temp.path().join("must-not-exist");
    assert!(!cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str(),"--triage".as_ref(),bad.as_os_str()]).status.success());
    assert!(!out.exists());
}
#[test]
fn triage_without_baseline_is_rejected_by_native_cli() {
    let temp=tempfile::tempdir().unwrap();let (findings,_)=baseline(temp.path());
    let out=temp.path().join("must-not-exist");
    assert!(!cli(&findings,&out,&["--triage".as_ref(),"unused.json".as_ref()]).status.success());
    assert!(!out.exists());
}
#[test]
fn rolling_baseline_is_loaded_before_the_current_json_is_replaced() {
    let temp=tempfile::tempdir().unwrap();let (findings,old)=baseline(temp.path());
    fs::remove_dir_all(findings.join("before")).unwrap();
    let out=old.parent().unwrap();
    succeeds(&cli(&findings,out,&["--baseline".as_ref(),old.as_os_str()]));
    let report=comparison(out);assert_eq!(report["counts"]["not_observed"],1);
    assert_eq!(read(&old)["counts"]["findings"],0);
}
#[test]
fn baseline_option_preserves_sarif_csv_and_junit_exports() {
    let temp=tempfile::tempdir().unwrap();let (findings,old)=baseline(temp.path());
    let out=temp.path().join("current-report");
    succeeds(&cli(&findings,&out,&["--baseline".as_ref(),old.as_os_str(),"--sarif".as_ref(),"--junit".as_ref(),"--csv".as_ref()]));
    let path=report_json(&out);
    for ext in ["sarif","csv","junit.xml","comparison.json"] {assert!(path.with_extension(ext).is_file(),"{ext}");}
}
