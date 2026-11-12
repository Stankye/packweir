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
                applies_to: vec![],
            },
        )]),
        deny_rules: vec![],
        informational_rules: vec![],
        allow_empty_files: false,
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

fn add_empty_child(report: &mut Value, tree: &mut Value) {
    let empty = sha256(b"");
    report["results"][key(&root())]["response"]["extracted"].as_array_mut().unwrap().push(json!({
        "sha256":empty,"name":"__init__.py","description":"empty fixture","classification":"U","parent_relation":"EXTRACTED"}));
    let mut empty_node = node(&empty, json!({}));
    empty_node["size"] = json!(0);
    empty_node["type"] = json!("empty");
    tree["tree"][root()]["children"][empty.clone()] = empty_node;
    report["file_tree"] = tree["tree"].clone();
    report["file_infos"][empty.clone()] = json!({"sha256":empty,"size":0,"type":"empty"});
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
fn new_record_creation_cannot_refresh_old_execution_and_completion_caps_validity() {
    let (mut report, tree) = fixture();
    report["results"][key(&root())]["response"]["milestones"] = json!({
        "service_started":"2026-11-09T10:00:00Z","service_completed":"2026-11-09T11:00:00Z"});
    assert_eq!(
        normalize(&report, &tree, &policy()).outcome,
        Outcome::Inconclusive
    );
    report["results"][key(&root())]["response"]["milestones"] = json!({
        "service_started":"2026-11-11T11:20:00Z","service_completed":"2026-11-11T11:30:00Z"});
    let output = normalize(&report, &tree, &policy());
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(
        output.valid_until,
        Some("2026-11-12T11:30:00Z".parse().unwrap())
    );
    report["results"][key(&root())]["expiry_ts"] = json!("2026-11-11T12:30:00Z");
    assert_eq!(
        normalize(&report, &tree, &policy()).valid_until,
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
                applies_to: vec![],
            },
        )]),
        deny_rules: vec![],
        informational_rules: vec![],
        allow_empty_files: false,
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

#[test]
fn explicit_applicability_preserves_skips_and_requires_other_coverage() {
    let (mut report, mut tree) = fixture();
    add_child(&mut report, &mut tree, false);
    report["file_infos"][root()]["type"] = json!("archive/zip");
    report["file_infos"][child()]["type"] = json!("text/plain");
    let mut policy = policy();
    policy
        .required_services
        .get_mut("StaticFixture")
        .unwrap()
        .applies_to = vec!["archive/zip".into()];
    let uncovered = normalize(&report, &tree, &policy);
    assert_eq!(uncovered.outcome, Outcome::Inconclusive);
    assert!(
        uncovered.details["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["sha256"] == child() && row["status"] == "not_applicable" })
    );
    let mut text_pin = policy.required_services["StaticFixture"].clone();
    text_pin.applies_to = vec!["text/".into()];
    policy
        .required_services
        .insert("TextFixture".into(), text_pin);
    report["params"]["services"]["selected"] = json!(["StaticFixture", "TextFixture"]);
    let mut result = service_result(&child());
    result["response"]["service_name"] = json!("TextFixture");
    report["results"][format!("{}.TextFixture.v4_7_4_11.cPinnedFixture1", child())] = result;
    assert_eq!(normalize(&report, &tree, &policy).outcome, Outcome::Pass);

    for missing_type in [Value::Null, json!(""), json!(17)] {
        let mut report = report.clone();
        report["file_infos"][child()]["type"] = missing_type;
        assert_eq!(
            normalize(&report, &tree, &policy).outcome,
            Outcome::Inconclusive
        );
    }
    report["file_infos"]
        .as_object_mut()
        .unwrap()
        .remove(&child());
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn legacy_all_files_scope_does_not_depend_on_new_type_metadata() {
    let (mut report, tree) = fixture();
    report["file_infos"][root()]
        .as_object_mut()
        .unwrap()
        .remove("type");
    assert_eq!(normalize(&report, &tree, &policy()).outcome, Outcome::Pass);
    let mut scoped = policy();
    scoped
        .required_services
        .get_mut("StaticFixture")
        .unwrap()
        .applies_to = vec!["archive/".into()];
    assert_eq!(
        normalize(&report, &tree, &scoped).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn nonapplicable_empty_cache_is_visible_without_fabricating_fresh_coverage() {
    let (mut report, tree) = fixture();
    report["file_infos"][root()]["type"] = json!("text/plain");
    let mut policy = policy();
    let mut pin = policy.required_services["StaticFixture"].clone();
    pin.applies_to = vec!["archive/zip".into()];
    policy
        .required_services
        .insert("ExtractFixture".into(), pin);
    report["params"]["services"]["selected"] = json!(["StaticFixture", "ExtractFixture"]);
    let mut empty = service_result(&root());
    empty["response"]["service_name"] = json!("ExtractFixture");
    empty["response"]["service_version"] = json!("4_7_4_11");
    empty["response"]["service_tool_version"] = Value::Null;
    empty["created"] = json!("2026-11-09T00:00:00Z");
    report["results"][format!("{}.ExtractFixture.v4_7_4_11.cPinnedFixture1.e", root())] = empty;
    let output = normalize(&report, &tree, &policy);
    assert_eq!(output.outcome, Outcome::Pass);
    let scope = output.details["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["service"] == "ExtractFixture")
        .unwrap();
    assert_eq!(scope["status"], "not_applicable");
    assert_eq!(scope["results"][0]["fresh"], false);
    policy
        .required_services
        .get_mut("ExtractFixture")
        .unwrap()
        .applies_to
        .clear();
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn only_explicit_zero_score_observations_can_be_informational_and_denials_win() {
    let (mut report, tree) = fixture();
    finding(&mut report);
    let mut policy = policy();
    policy.informational_rules = deny_policy().deny_rules;
    let output = normalize(&report, &tree, &policy);
    assert_eq!(output.outcome, Outcome::Pass);
    assert_eq!(
        output.details["findings"][0]["disposition"],
        "informational"
    );
    assert_eq!(
        output.details["findings"][0]["informational_rule_indices"],
        json!([0])
    );
    for score in [1, -1, 500] {
        let mut report = report.clone();
        report["results"][key(&root())]["result"]["sections"][0]["heuristic"]["score"] =
            json!(score);
        assert_eq!(
            normalize(&report, &tree, &policy).outcome,
            Outcome::Inconclusive
        );
    }
    for field in ["result", "platform"] {
        let mut report = report.clone();
        if field == "result" {
            report["results"][key(&root())]["result"]["score"] = json!(100);
        } else {
            report["max_score"] = json!(100);
        }
        assert_eq!(
            normalize(&report, &tree, &policy).outcome,
            Outcome::Inconclusive
        );
    }
    report["results"][key(&root())]["result"]["sections"][0]["heuristic"]["signature"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"unacknowledged", "safe":false, "frequency":1}));
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
    policy.informational_rules[0].signature = None;
    assert_eq!(normalize(&report, &tree, &policy).outcome, Outcome::Pass);
    policy.deny_rules = deny_policy().deny_rules;
    let denied = normalize(&report, &tree, &policy);
    assert_eq!(denied.outcome, Outcome::Fail);
    assert_eq!(denied.details["findings"][0]["disposition"], "deny");
    report["results"][key(&root())]["partial"] = json!(true);
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn applicability_selectors_are_bounded_plain_types_and_prefixes() {
    for selector in [
        ".*",
        "archive/*",
        "/",
        "archive|text",
        "text/plain\n",
        "TEXT/plain",
        "archive//zip",
    ] {
        let mut policy = policy();
        policy
            .required_services
            .get_mut("StaticFixture")
            .unwrap()
            .applies_to = vec![selector.into()];
        assert!(policy.validate().is_err(), "{selector:?}");
    }
    let mut policy = policy();
    policy
        .required_services
        .get_mut("StaticFixture")
        .unwrap()
        .applies_to = vec!["archive/".into(), "archive/".into()];
    assert!(policy.validate().is_err());
}

#[test]
fn omitted_optional_service_selection_lists_use_upstream_defaults_only() {
    let (mut report, tree) = fixture();
    for field in ["excluded", "rescan", "resubmit"] {
        report["params"]["services"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    assert_eq!(normalize(&report, &tree, &policy()).outcome, Outcome::Pass);
    for invalid in [Value::Null, json!("StaticFixture"), json!({}), json!(false)] {
        let mut invalid_report = report.clone();
        invalid_report["params"]["services"]["excluded"] = invalid;
        assert!(normalize_at(&root(), sid(), &invalid_report, &tree, &policy(), now()).is_err());
    }
    report["params"]["services"]
        .as_object_mut()
        .unwrap()
        .remove("selected");
    assert!(normalize_at(&root(), sid(), &report, &tree, &policy(), now()).is_err());
}

#[test]
fn exact_empty_content_requires_explicit_policy_and_never_claims_service_execution() {
    let (mut report, mut tree) = fixture();
    add_empty_child(&mut report, &mut tree);
    let mut policy = policy();
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
    let mut omitted = serde_json::to_value(&policy).unwrap();
    omitted.as_object_mut().unwrap().remove("allow_empty_files");
    assert!(
        !serde_json::from_value::<AssemblylinePolicy>(omitted)
            .unwrap()
            .allow_empty_files
    );
    policy.allow_empty_files = true;
    let output = normalize(&report, &tree, &policy);
    assert_eq!(output.outcome, Outcome::Pass);
    let empty = sha256(b"");
    let record = output.details["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["sha256"] == empty)
        .unwrap();
    assert_eq!(record["status"], "known_empty_content");
    assert!(record["service"].is_null());
    assert_eq!(record["service_execution_required"], false);
    assert_eq!(output.details["known_empty_content"], json!([empty]));
    assert_eq!(
        output.valid_until,
        normalize(&fixture().0, &fixture().1, &policy).valid_until
    );
}

#[test]
fn empty_content_exception_requires_consistent_tree_and_file_metadata() {
    let (mut report, mut tree) = fixture();
    add_empty_child(&mut report, &mut tree);
    let mut policy = policy();
    policy.allow_empty_files = true;
    let empty = sha256(b"");
    for field in ["size", "type", "sha256"] {
        let mut report = report.clone();
        report["file_infos"][&empty]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert_eq!(
            normalize(&report, &tree, &policy).outcome,
            Outcome::Inconclusive
        );
    }
    for (field, invalid) in [
        ("size", json!(1)),
        ("size", Value::Null),
        ("type", json!("unknown")),
    ] {
        let mut report = report.clone();
        let mut tree = tree.clone();
        tree["tree"][root()]["children"][&empty][field] = invalid;
        report["file_tree"] = tree["tree"].clone();
        assert_eq!(
            normalize(&report, &tree, &policy).outcome,
            Outcome::Inconclusive
        );
    }
    // Merely labelling different bytes empty cannot obtain the exception.
    let (mut report, mut tree) = fixture();
    add_child(&mut report, &mut tree, false);
    report["file_infos"][child()]["size"] = json!(0);
    report["file_infos"][child()]["type"] = json!("empty");
    tree["tree"][root()]["children"][child()]["size"] = json!(0);
    tree["tree"][root()]["children"][child()]["type"] = json!("empty");
    report["file_tree"] = tree["tree"].clone();
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn allowing_known_empty_content_never_waives_nonempty_service_coverage() {
    let (mut report, mut tree) = fixture();
    add_child(&mut report, &mut tree, false);
    add_empty_child(&mut report, &mut tree);
    let mut policy = policy();
    policy.allow_empty_files = true;
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
    let mut stale = service_result(&child());
    stale["created"] = json!("2026-11-09T00:00:00Z");
    report["results"][key(&child())] = stale;
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
    report["results"]
        .as_object_mut()
        .unwrap()
        .remove(&key(&child()));
    let mut empty_cached = service_result(&child());
    empty_cached["response"]["service_version"] = json!("4_7_4_11");
    empty_cached["response"]["service_tool_version"] = Value::Null;
    report["results"][format!("{}.e", key(&child()))] = empty_cached;
    assert_eq!(
        normalize(&report, &tree, &policy).outcome,
        Outcome::Inconclusive
    );
    report["results"]
        .as_object_mut()
        .unwrap()
        .remove(&format!("{}.e", key(&child())));
    report["results"][key(&child())] = service_result(&child());
    assert_eq!(normalize(&report, &tree, &policy).outcome, Outcome::Pass);
}
