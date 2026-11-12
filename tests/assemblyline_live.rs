//! Replay authenticated captures from the opt-in, real Assemblyline deployment.
//! This test cannot substitute generated fixtures for successful live execution.
use chrono::{DateTime, Utc};
use packweir::{
    assemblyline::{AssemblylinePolicy, normalize_at},
    model::Outcome,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn body(path: &Path) -> Value {
    let value = read(path);
    assert_eq!(value["api_error_message"], "");
    assert_eq!(value["api_status_code"], 200);
    value["api_response"].clone()
}

fn cannot_pass(
    subject: &str,
    sid: &str,
    report: &Value,
    tree: &Value,
    policy: &AssemblylinePolicy,
    now: DateTime<Utc>,
) {
    if let Ok(output) = normalize_at(subject, sid, report, tree, policy, now) {
        assert_ne!(output.outcome, Outcome::Pass);
    }
}

#[test]
#[ignore = "requires authenticated captures from tests/assemblyline/live/run.py"]
fn real_assemblyline_captures_and_tamper_replay() {
    let manifest_path = std::env::var_os("PACKWEIR_ASSEMBLYLINE_LIVE_MANIFEST")
        .expect("set PACKWEIR_ASSEMBLYLINE_LIVE_MANIFEST to the live capture manifest");
    let manifest_path = Path::new(&manifest_path);
    let directory = manifest_path.parent().unwrap();
    let manifest = read(manifest_path);
    assert_eq!(manifest["provenance"], "authenticated_real_assemblyline_v4");
    let cases = manifest["cases"].as_array().unwrap();
    let names: BTreeSet<_> = cases
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect();
    assert!(names.contains("benign"));
    assert!(names.contains("harmless-finding"));
    assert!(names.contains("archive-child"));
    for case in cases {
        let subject = case["subject"].as_str().unwrap();
        let sid = case["submission_id"].as_str().unwrap();
        let now: DateTime<Utc> = case["captured_at"].as_str().unwrap().parse().unwrap();
        let report = body(&directory.join(case["report_file"].as_str().unwrap()));
        let tree = body(&directory.join(case["tree_file"].as_str().unwrap()));
        let policy: AssemblylinePolicy =
            serde_json::from_value(read(&directory.join(case["policy_file"].as_str().unwrap())))
                .unwrap();
        let output = normalize_at(subject, sid, &report, &tree, &policy, now).unwrap();
        let expected = match case["name"].as_str().unwrap() {
            "benign" => Outcome::Pass,
            "harmless-finding" | "archive-child" => Outcome::Fail,
            "official-empty-cache" => Outcome::Inconclusive,
            name => panic!("unknown mandatory live case {name}"),
        };
        assert_eq!(
            output.outcome, expected,
            "{}: {}",
            case["name"], output.details
        );
        if case["name"] == "archive-child" {
            assert!(!output.details["extracted"].as_array().unwrap().is_empty());
            assert!(
                output.details["coverage"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|coverage| coverage["sha256"] != subject
                        && coverage["status"] == "complete")
            );
            let child_key = output.details["coverage"]
                .as_array()
                .unwrap()
                .iter()
                .find(|coverage| coverage["sha256"] != subject && coverage["status"] == "complete")
                .unwrap()["results"][0]["result_key"]
                .as_str()
                .unwrap();
            let mut incomplete = report.clone();
            incomplete["results"]
                .as_object_mut()
                .unwrap()
                .remove(child_key);
            assert_eq!(
                normalize_at(subject, sid, &incomplete, &tree, &policy, now)
                    .unwrap()
                    .outcome,
                Outcome::Inconclusive,
                "missing actual child coverage must take precedence over a denial"
            );
        }
        if case["name"] != "benign" {
            continue;
        }
        // Mutate copies only: each original HTTP response remains byte-for-byte
        // available under the live run. These are explicitly replay checks.
        let mut tampered = report.clone();
        tampered["files"][0]["sha256"] = json!("0".repeat(64));
        cannot_pass(subject, sid, &tampered, &tree, &policy, now);
        let mut tampered = tree.clone();
        tampered["filtered"] = json!(true);
        cannot_pass(subject, sid, &report, &tampered, &policy, now);
        let mut tampered = tree.clone();
        tampered["partial"] = json!(true);
        cannot_pass(subject, sid, &report, &tampered, &policy, now);
        for field in [
            "missing_result_keys",
            "missing_file_keys",
            "missing_error_keys",
        ] {
            let mut tampered = report.clone();
            tampered[field] = json!(["qualification-removed-record"]);
            cannot_pass(subject, sid, &tampered, &tree, &policy, now);
        }
        let mut tampered = report.clone();
        tampered["state"] = json!("submitted");
        cannot_pass(subject, sid, &tampered, &tree, &policy, now);
        let mut tampered = report.clone();
        tampered["results"] = json!({});
        cannot_pass(subject, sid, &tampered, &tree, &policy, now);
        for field in ["version", "tool_version", "configuration_key"] {
            let mut changed = serde_json::to_value(&policy).unwrap();
            let service = output.details["coverage"]
                .as_array()
                .unwrap()
                .iter()
                .find(|coverage| coverage["status"] == "complete")
                .unwrap()["service"]
                .as_str()
                .unwrap();
            changed["required_services"][service][field] = json!("tampered");
            let changed: AssemblylinePolicy = serde_json::from_value(changed).unwrap();
            cannot_pass(subject, sid, &report, &tree, &changed, now);
        }
    }
}
