use chrono::{DateTime, Duration, Utc};
use packweir::{
    assemblyline::{
        AssemblylineDenyRule, AssemblylinePolicy, AssemblylineServicePin, MAX_REPORT_BYTES,
        normalize_at,
    },
    model::{Outcome, sha256},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn now() -> DateTime<Utc> {
    "2026-11-11T12:00:00Z".parse().unwrap()
}
fn sid() -> &'static str {
    "fixture-submission-unique-id"
}
fn root() -> String {
    sha256(b"original package bytes")
}
fn child() -> String {
    sha256(b"extracted bytes never executed")
}
fn policy() -> AssemblylinePolicy {
    AssemblylinePolicy {
        required_services: BTreeMap::from([(
            "StaticFixture".into(),
            AssemblylineServicePin {
                version: "4.7.4.11".into(),
                tool_version: Some("fixture-rules-2026-11".into()),
                configuration_key: "PinnedFixture1".into(),
            },
        )]),
        deny_rules: vec![],
        max_result_age_seconds: 86400,
    }
}
fn key(sha: &str) -> String {
    format!("{sha}.StaticFixture.v4_7_4_11.cPinnedFixture1")
}
fn node(sha: &str, children: Value) -> Value {
    json!({"name":["fixture.bin"],"type":"unknown","sha256":sha,"size":12,
        "children":children,"truncated":false,"score":0})
}
fn service_result(sha: &str) -> Value {
    json!({"sha256":sha,"classification":"U","created":"2026-11-11T11:59:00Z",
        "expiry_ts":null,"partial":false,"drop_file":false,
        "response":{"service_name":"StaticFixture","service_version":"4.7.4.11",
            "service_tool_version":"fixture-rules-2026-11",
            "milestones":{"service_started":"2026-11-11T11:58:00Z","service_completed":"2026-11-11T11:59:00Z"},
            "extracted":[],"supplementary":[]},
        "result":{"score":0,"sections":[]}})
}
fn fixture() -> (Value, Value) {
    let sha = root();
    let tree = json!({"tree":{sha.clone():node(&sha,json!({}))},"partial":false,"filtered":false,
        "supplementary":[],"classification":"U"});
    let report = json!({"sid":sid(),"state":"completed","files":[{"name":"fixture.bin","sha256":sha,"size":12}],
        "file_count":1,"max_score":0,"error_count":0,"errors":{},"results":{key(&sha):service_result(&sha)},
        "params":{"ignore_cache":false,"services":{"selected":["StaticFixture"],"excluded":[],"rescan":[],"resubmit":[]},"service_spec":{}},
        "file_tree":tree["tree"],"file_infos":{sha.clone():{"sha256":sha,"size":12,"type":"unknown"}},
        "missing_result_keys":[],"missing_error_keys":[],"missing_file_keys":[]});
    (report, tree)
}
fn normalize(
    report: &Value,
    tree: &Value,
    policy: &AssemblylinePolicy,
) -> packweir::scanner::ScannerOutput {
    normalize_at(&root(), sid(), report, tree, policy, now()).unwrap()
}
fn finding(report: &mut Value) {
    report["results"][key(&root())]["result"] = json!({"score":0,"sections":[{
        "title_text":"Fixture heuristic with zero platform score", "body":"observation only", "depth":0,
        "heuristic":{"heur_id":"STATIC_FIXTURE_7","name":"Fixture behavior","score":0,
            "signature":[{"name":"fixture.signature","frequency":1,"safe":false}],"attack":[]},"tags":{}}]});
}
fn deny_policy() -> AssemblylinePolicy {
    let mut policy = policy();
    policy.deny_rules.push(AssemblylineDenyRule {
        service: "StaticFixture".into(),
        heuristic_id: "STATIC_FIXTURE_7".into(),
        signature: Some("fixture.signature".into()),
    });
    policy
}
fn add_child(report: &mut Value, tree: &mut Value, analyze_child: bool) {
    let child = child();
    report["results"][key(&root())]["response"]["extracted"] = json!([{
        "sha256":child,"name":"payload.bin","description":"fixture extracted payload","classification":"U","parent_relation":"EXTRACTED"}]);
    tree["tree"][root()]["children"][child.clone()] = node(&child, json!({}));
    report["file_tree"] = tree["tree"].clone();
    report["file_infos"][child.clone()] = json!({"sha256":child,"size":12,"type":"unknown"});
    if analyze_child {
        report["results"][key(&child)] = service_result(&child);
    }
}

#[test]
fn complete_pinned_service_results_pass_with_attributable_raw_evidence() {
    let (report, tree) = fixture();
    let output = normalize(&report, &tree, &policy());
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(output.details["subject"], root());
    assert_eq!(output.details["submission_id"], sid());
    assert_eq!(output.details["raw_report"], report);
    assert_eq!(
        output.details["raw_report_sha256"],
        sha256(&serde_json::to_vec(&report).unwrap())
    );
    assert_eq!(output.details["coverage"][0]["status"], "complete");
    assert_eq!(
        output.valid_until,
        Some(now() - Duration::seconds(60) + Duration::days(1))
    );
}

#[test]
fn score_alone_cannot_approve_missing_analysis_or_heuristics() {
    let (mut report, tree) = fixture();
    report["results"] = json!({});
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let (mut report, tree) = fixture();
    finding(&mut report);
    let output = normalize(&report, &tree, &policy());
    assert_eq!(output.outcome, Outcome::Inconclusive);
    assert_eq!(
        output.details["findings"][0]["heuristic"]["heur_id"],
        "STATIC_FIXTURE_7"
    );
    report["results"][key(&root())]["result"] = json!({"score":1,"sections":[]});
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let (mut report, tree) = fixture();
    report["max_score"] = json!(1000);
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn only_exact_operator_deny_mapping_fails_and_uncertainty_takes_precedence() {
    let (mut report, tree) = fixture();
    finding(&mut report);
    assert_eq!(
        normalize(&report, &tree, &deny_policy()).outcome,
        Outcome::Fail
    );
    let mut other_signature = deny_policy();
    other_signature.deny_rules[0].signature = Some("different.signature".into());
    assert_eq!(
        normalize(&report, &tree, &other_signature).outcome,
        Outcome::Inconclusive
    );
    report["results"][key(&root())]["partial"] = json!(true);
    assert_eq!(
        normalize(&report, &tree, &deny_policy()).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn all_extracted_descendants_require_their_own_pinned_coverage() {
    let (mut report, mut tree) = fixture();
    add_child(&mut report, &mut tree, false);
    let output = normalize(&report, &tree, &policy());
    assert_eq!(output.outcome, Outcome::Inconclusive);
    assert_eq!(output.details["extracted"][0]["parent_sha256"], root());
    assert_eq!(output.details["extracted"][0]["child_sha256"], child());
    report["results"][key(&child())] = service_result(&child());
    assert_eq!(normalize(&report, &tree, &policy()).outcome, Outcome::Pass);
}

#[test]
fn supplementary_evidence_is_preserved_without_treating_it_as_analyzed_children() {
    let (mut report, tree) = fixture();
    report["results"][key(&root())]["response"]["supplementary"] = json!([{
        "sha256":child(),"name":"decompiler-output.txt","description":"fixture only","classification":"U","parent_relation":"INFORMATION"}]);
    let output = normalize(&report, &tree, &policy());
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(
        output.details["supplementary"][0]["file"]["sha256"],
        child()
    );
    assert!(output.details["extracted"].as_array().unwrap().is_empty());
}

#[test]
fn missing_records_errors_partial_filtering_and_truncation_cannot_pass() {
    let (base, base_tree) = fixture();
    for field in [
        "missing_result_keys",
        "missing_error_keys",
        "missing_file_keys",
    ] {
        let mut report = base.clone();
        report[field] = json!(["missing-key"]);
        assert_eq!(
            normalize(&report, &base_tree, &policy()).outcome,
            Outcome::Inconclusive
        );
    }
    for field in ["partial", "filtered"] {
        let mut tree = base_tree.clone();
        tree[field] = json!(true);
        assert_eq!(
            normalize(&base, &tree, &policy()).outcome,
            Outcome::Inconclusive
        );
    }
    let mut report = base.clone();
    let mut tree = base_tree.clone();
    tree["tree"][root()]["truncated"] = json!(true);
    report["file_tree"] = tree["tree"].clone();
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let mut report = base.clone();
    report["error_count"] = json!(1);
    report["errors"] = json!({format!("{}.StaticFixture.v4_7_4_11.cPinnedFixture1.e12",root()):{
        "sha256":root(),"type":"MAX RETRY REACHED","severity":"error","response":{"service_name":"StaticFixture",
            "service_version":"4.7.4.11","service_tool_version":"fixture-rules-2026-11","status":"FAIL_RECOVERABLE","message":"service timeout"}}});
    assert_eq!(
        normalize(&report, &base_tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let mut report = base.clone();
    report["state"] = json!("submitted");
    assert_eq!(
        normalize(&report, &base_tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let mut report = base;
    report["results"][key(&root())]["drop_file"] = json!(true);
    assert_eq!(
        normalize(&report, &base_tree, &policy()).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn pins_bind_service_tool_and_actual_configuration_key() {
    let (report, tree) = fixture();
    for field in ["version", "tool_version", "configuration_key"] {
        let mut value = serde_json::to_value(policy()).unwrap();
        value["required_services"]["StaticFixture"][field] = json!("different");
        let policy = serde_json::from_value(value).unwrap();
        assert_eq!(
            normalize(&report, &tree, &policy).outcome,
            Outcome::Inconclusive
        );
    }
    let mut policy = policy();
    policy
        .required_services
        .get_mut("StaticFixture")
        .unwrap()
        .tool_version = None;
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn stale_future_or_expired_results_cannot_pass_and_upstream_expiry_caps_evidence() {
    let (base, tree) = fixture();
    for date in ["2026-11-10T11:00:00Z", "2026-11-11T12:00:01Z"] {
        let mut report = base.clone();
        report["results"][key(&root())]["created"] = json!(date);
        assert_eq!(
            normalize(&report, &tree, &policy()).outcome,
            Outcome::Inconclusive
        );
    }
    let mut report = base.clone();
    report["results"][key(&root())]["expiry_ts"] = json!("2026-11-11T11:59:59Z");
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    report["results"][key(&root())]["expiry_ts"] = json!("2026-11-11T12:30:00Z");
    let output = normalize(&report, &tree, &policy());
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(
        output.valid_until,
        Some("2026-11-11T12:30:00Z".parse().unwrap())
    );
}

#[test]
fn synthesized_empty_cache_results_cannot_prove_fresh_pinned_service_execution() {
    let (mut report, tree) = fixture();
    let mut result = report["results"]
        .as_object_mut()
        .unwrap()
        .remove(&key(&root()))
        .unwrap();
    result["response"]["service_version"] = json!("4_7_4_11");
    result["response"]["service_tool_version"] = Value::Null;
    result["created"] = json!("2026-11-11T12:00:00Z");
    report["results"][format!("{}.e", key(&root()))] = result;
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn unrelated_results_changed_submission_and_inconsistent_graphs_are_rejected() {
    let (base, tree) = fixture();
    let mut report = base.clone();
    report["sid"] = json!("different-submission");
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
    let mut report = base.clone();
    report["files"][0]["sha256"] = json!(child());
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
    let mut report = base.clone();
    report["results"][key(&child())] = service_result(&child());
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
    let mut report = base.clone();
    report["results"][key(&root())]["response"]["extracted"] = json!([{"sha256":child()}]);
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
    let mut tree = tree;
    tree["tree"][root()]["score"] = json!(1);
    assert!(normalize_at(&root(), sid(), &base, &tree, &policy(), now()).is_err());
}

#[test]
fn malformed_keys_and_missing_required_schema_cannot_approve() {
    let (mut report, tree) = fixture();
    let result = report["results"]
        .as_object_mut()
        .unwrap()
        .remove(&key(&root()))
        .unwrap();
    report["results"][format!("{}.OtherService.v4_7_4_11.cPinnedFixture1", root())] = result;
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
    let (mut report, tree) = fixture();
    report
        .as_object_mut()
        .unwrap()
        .remove("missing_result_keys");
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
    let (report, mut tree) = fixture();
    tree.as_object_mut().unwrap().remove("partial");
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
}

#[test]
fn policy_and_output_bounds_reject_unbounded_or_unpinned_configuration() {
    let mut invalid = policy();
    invalid.required_services.clear();
    assert!(invalid.validate().is_err());
    let mut invalid = policy();
    invalid.max_result_age_seconds = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = policy();
    invalid
        .required_services
        .get_mut("StaticFixture")
        .unwrap()
        .configuration_key
        .clear();
    assert!(invalid.validate().is_err());
    let mut invalid = deny_policy();
    invalid.deny_rules[0].service = "Ghidra".into();
    assert!(invalid.validate().is_err());
    let (mut report, tree) = fixture();
    report["metadata"] = json!({"large":"x".repeat(MAX_REPORT_BYTES)});
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
}

#[test]
fn actual_pinned_upstream_odm_shapes_normalize_complete_errors_and_synthetic_empty() {
    let manifest: Value =
        serde_json::from_str(include_str!("assemblyline/fixtures/manifest.json")).unwrap();
    let full: Value = serde_json::from_str(include_str!(
        "assemblyline/fixtures/submission.full.completed.json"
    ))
    .unwrap();
    let tree: Value = serde_json::from_str(include_str!(
        "assemblyline/fixtures/submission.tree.completed.json"
    ))
    .unwrap();
    let subject = manifest["subject_sha256"].as_str().unwrap();
    let sid = manifest["submission_id"].as_str().unwrap();
    let service = manifest["service"].as_str().unwrap();
    let policy = AssemblylinePolicy {
        required_services: BTreeMap::from([(
            service.into(),
            AssemblylineServicePin {
                version: manifest["service_version"].as_str().unwrap().into(),
                tool_version: manifest["service_tool_version"].as_str().map(Into::into),
                configuration_key: manifest["configuration_key"]
                    .as_str()
                    .unwrap()
                    .strip_prefix('c')
                    .unwrap()
                    .into(),
            },
        )]),
        deny_rules: vec![],
        max_result_age_seconds: 86400,
    };
    let at = manifest["now"].as_str().unwrap().parse().unwrap();
    let output = normalize_at(
        subject,
        sid,
        &full["api_response"],
        &tree["api_response"],
        &policy,
        at,
    )
    .unwrap();
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(output.details["files"].as_array().unwrap().len(), 2);
    let errors: Value = serde_json::from_str(include_str!(
        "assemblyline/fixtures/submission.full.service_error.json"
    ))
    .unwrap();
    let output = normalize_at(
        subject,
        sid,
        &errors["api_response"],
        &tree["api_response"],
        &policy,
        at,
    )
    .unwrap();
    assert_eq!(output.outcome, Outcome::Inconclusive);
    assert_eq!(
        output.details["service_errors"].as_array().unwrap().len(),
        1
    );
    let empty: Value = serde_json::from_str(include_str!(
        "assemblyline/fixtures/submission.full.synthetic_empty.json"
    ))
    .unwrap();
    let output = normalize_at(
        subject,
        sid,
        &empty["api_response"],
        &tree["api_response"],
        &policy,
        at,
    )
    .unwrap();
    assert_eq!(output.outcome, Outcome::Inconclusive);
}

#[test]
fn selected_configuration_and_service_milestones_are_required() {
    let (base, tree) = fixture();
    let mut report = base.clone();
    report["params"]["ignore_cache"] = json!(true);
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let mut report = base.clone();
    report["params"]["services"]["selected"] = json!(["Static Analysis"]);
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let mut report = base.clone();
    report["params"]["services"]["excluded"] = json!(["StaticFixture"]);
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    let mut report = base;
    report["results"][key(&root())]["response"]["milestones"]["service_completed"] =
        json!("2026-11-11T12:01:00Z");
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
}
